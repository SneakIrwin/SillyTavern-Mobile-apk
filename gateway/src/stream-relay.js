import crypto from 'node:crypto';
import http from 'node:http';
import https from 'node:https';

export const RELAY_ID_HEADER = 'x-st-mobile-relay-id';
export const RELAY_OFFSET_HEADER = 'x-st-mobile-relay-offset';
export const RELAY_CLIENT_PATH = '/__mobile/stream-relay-client.js';

const DEFAULT_LIMITS = Object.freeze({
  maxRequestBytes: 16 * 1024 * 1024,
  maxRelayBytes: 16 * 1024 * 1024,
  maxTotalBytes: 64 * 1024 * 1024,
  maxRelays: 32,
  maxActiveRelays: 8,
  maxRelaysPerOwner: 2,
  maxSubscriberQueueBytes: 256 * 1024,
  completedTtlMs: 90 * 60_000,
  failedTtlMs: 10 * 60_000,
  maxActiveMs: 90 * 60_000,
  cancelTombstoneTtlMs: 100 * 60_000,
  maxCancelTombstones: 2_048,
});

const RELAY_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const STREAMING_PATHS = new Set([
  '/api/backends/chat-completions/generate',
  '/api/backends/text-completions/generate',
  '/api/backends/kobold/generate',
  '/api/novelai/generate',
]);
const HOP_BY_HOP_RESPONSE_HEADERS = new Set([
  'accept-ranges',
  'connection',
  'content-encoding',
  'content-length',
  'content-md5',
  'digest',
  'etag',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

function sendText(res, statusCode, message, headers = {}) {
  if (res.destroyed) {
    return;
  }
  res.writeHead(statusCode, {
    'content-type': 'text/plain; charset=utf-8',
    'cache-control': 'no-store',
    ...headers,
  });
  res.end(`${message}\n`);
}

function singleHeader(req, name) {
  const value = req.headers[name];
  return typeof value === 'string' ? value : null;
}

function parseRelayOffset(req) {
  const value = singleHeader(req, RELAY_OFFSET_HEADER);
  if (value === null || !/^(0|[1-9]\d*)$/.test(value)) {
    return null;
  }
  const offset = Number(value);
  return Number.isSafeInteger(offset) ? offset : null;
}

function requestSignature(req, body) {
  return crypto.createHash('sha256')
    .update(req.method)
    .update('\0')
    .update(req.url)
    .update('\0')
    .update(body)
    .digest('hex');
}

function responseHeaders(upstreamHeaders, relayId, state) {
  const headers = {};
  for (const [name, value] of Object.entries(upstreamHeaders)) {
    if (!HOP_BY_HOP_RESPONSE_HEADERS.has(name.toLowerCase()) && value !== undefined) {
      headers[name] = value;
    }
  }
  headers['cache-control'] = 'no-store';
  headers[RELAY_ID_HEADER] = relayId;
  headers['x-st-mobile-relay-state'] = state;
  return headers;
}

function readRequestBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    let settled = false;
    const fail = (error) => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    };
    req.on('data', (chunk) => {
      if (settled) {
        return;
      }
      length += chunk.length;
      if (length > maxBytes) {
        fail(Object.assign(new Error('Relay request body exceeds the configured limit'), { statusCode: 413 }));
        chunks.length = 0;
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (!settled) {
        settled = true;
        resolve(Buffer.concat(chunks, length));
      }
    });
    req.on('aborted', () => fail(new Error('Relay request upload was aborted')));
    req.on('error', fail);
  });
}

function bodyRequestsStreaming(pathname, body) {
  try {
    const parsed = JSON.parse(body.toString('utf8'));
    if (pathname === '/api/backends/chat-completions/generate'
        || pathname === '/api/backends/text-completions/generate') {
      return parsed?.stream === true;
    }
    if (pathname === '/api/backends/kobold/generate'
        || pathname === '/api/novelai/generate') {
      return parsed?.streaming === true;
    }
    return false;
  } catch {
    return false;
  }
}

function relayUrl(req) {
  try {
    return new URL(req.url, 'http://localhost');
  } catch {
    return null;
  }
}

export function isRelayCandidateRequest(req) {
  const relayId = singleHeader(req, RELAY_ID_HEADER);
  const parsed = relayUrl(req);
  return req.method === 'POST'
    && req.url.startsWith('/')
    && !req.url.startsWith('//')
    && relayId !== null
    && parsed !== null
    && parsed.search === ''
    && STREAMING_PATHS.has(parsed.pathname);
}

export function relayCancelId(req) {
  if (req.method !== 'DELETE' || !req.url.startsWith('/') || req.url.startsWith('//')) {
    return null;
  }
  const pathname = relayUrl(req)?.pathname ?? '';
  const match = pathname.match(/^\/__mobile\/stream-relay\/([0-9a-f-]+)$/);
  return match && RELAY_ID_PATTERN.test(match[1]) ? match[1] : null;
}

export function createStreamRelayManager(options) {
  const targetUrl = options.targetUrl instanceof URL ? options.targetUrl : new URL(options.targetUrl);
  const buildUpstreamHeaders = options.buildUpstreamHeaders;
  const onEvent = typeof options.onEvent === 'function' ? options.onEvent : null;
  const limits = { ...DEFAULT_LIMITS, ...(options.limits ?? {}) };
  const relays = new Map();
  const cancelTombstones = new Map();
  let totalBytes = 0;

  function emit(type, relay, details = {}) {
    if (!onEvent) {
      return;
    }
    try {
      onEvent({
        type,
        at: new Date().toISOString(),
        relayId: relay?.id ?? details.relayId ?? null,
        state: relay?.state ?? details.state ?? null,
        bufferedBytes: relay?.length ?? 0,
        ...details,
      });
    } catch {
      // Observability must never change relay behavior.
    }
  }

  function recordTombstone(id, ownerTokenHash) {
    if (cancelTombstones.size >= limits.maxCancelTombstones) {
      const oldest = [...cancelTombstones.entries()]
        .sort((a, b) => a[1].expiresAt - b[1].expiresAt)[0];
      if (oldest) {
        cancelTombstones.delete(oldest[0]);
      }
    }
    cancelTombstones.set(id, {
      ownerTokenHash,
      expiresAt: Date.now() + limits.cancelTombstoneTtlMs,
    });
  }

  function removeRelay(relay, { preserveId = true, reason = 'removed' } = {}) {
    if (relays.get(relay.id) !== relay) {
      return;
    }
    relays.delete(relay.id);
    totalBytes -= relay.length;
    emit('removed', relay, { reason });
    if (preserveId) {
      recordTombstone(relay.id, relay.ownerTokenHash);
    }
  }

  function endSubscribers(relay, destroy = false) {
    for (const subscriber of relay.subscribers) {
      if (destroy) {
        subscriber.res.destroy();
      } else if (!subscriber.res.destroyed) {
        subscriber.res.end();
      }
    }
    relay.subscribers.clear();
  }

  function finishRelay(relay, state, error = null) {
    if (!['pending', 'streaming'].includes(relay.state)) {
      return;
    }
    relay.state = state;
    relay.error = error;
    relay.finishedAt = Date.now();
    relay.expiresAt = relay.finishedAt + (state === 'complete' ? limits.completedTtlMs : limits.failedTtlMs);
    relay.resolveHeaders?.();
    relay.resolveHeaders = null;
    endSubscribers(relay, state !== 'complete');
    emit('terminal', relay, {
      reason: state === 'complete' ? 'upstream-complete' : 'upstream-ended-with-error',
    });
  }

  function cancelRelay(relay, reason = 'Relay canceled') {
    if (['pending', 'streaming'].includes(relay.state)) {
      relay.upstreamRequest?.destroy(new Error(reason));
      relay.upstreamResponse?.destroy(new Error(reason));
      finishRelay(relay, 'canceled', new Error(reason));
    }
    emit('canceled', relay, { reason });
    removeRelay(relay, { reason: 'canceled' });
  }

  function evictOldestTerminalRelay() {
    const relay = [...relays.values()]
      .filter((candidate) => !['pending', 'streaming'].includes(candidate.state))
      .sort((a, b) => (a.finishedAt ?? a.createdAt) - (b.finishedAt ?? b.createdAt))[0];
    if (!relay) {
      return false;
    }
    emit('capacity-evicted', relay, { reason: 'terminal-replay-buffer-capacity' });
    removeRelay(relay, { reason: 'capacity-evicted' });
    return true;
  }

  function cleanExpired(now = Date.now()) {
    for (const relay of relays.values()) {
      if (['pending', 'streaming'].includes(relay.state) && now - relay.createdAt > limits.maxActiveMs) {
        cancelRelay(relay, 'Relay exceeded the maximum active duration');
      } else if (!['pending', 'streaming'].includes(relay.state) && relay.expiresAt <= now) {
        emit('expired', relay, { reason: 'retention-horizon-ended' });
        removeRelay(relay, { reason: 'expired' });
      }
    }
    for (const [id, tombstone] of cancelTombstones) {
      if (tombstone.expiresAt <= now) {
        cancelTombstones.delete(id);
      }
    }
  }

  const cleanupTimer = setInterval(() => cleanExpired(), 30_000);
  cleanupTimer.unref?.();

  function appendChunk(relay, chunk) {
    while (totalBytes + chunk.length > limits.maxTotalBytes && evictOldestTerminalRelay()) {
      // Prefer evicting old completed replay buffers over failing a live generation.
    }
    if (relay.length + chunk.length > limits.maxRelayBytes
        || totalBytes + chunk.length > limits.maxTotalBytes) {
      cancelRelay(relay, 'Relay response exceeded the configured buffer limit');
      return false;
    }
    const copy = Buffer.from(chunk);
    const start = relay.length;
    relay.chunks.push({ start, data: copy });
    relay.length += copy.length;
    totalBytes += copy.length;

    for (const subscriber of [...relay.subscribers]) {
      if (subscriber.offset !== start || subscriber.res.destroyed) {
        subscriber.res.destroy();
        relay.subscribers.delete(subscriber);
        continue;
      }
      subscriber.res.write(copy);
      subscriber.offset += copy.length;
      if (subscriber.res.writableLength > limits.maxSubscriberQueueBytes) {
        subscriber.res.destroy();
        relay.subscribers.delete(subscriber);
      }
    }
    return true;
  }

  function startUpstream(relay, req, body) {
    const client = targetUrl.protocol === 'https:' ? https : http;
    const upstream = client.request({
      protocol: targetUrl.protocol,
      hostname: targetUrl.hostname,
      port: targetUrl.port || (targetUrl.protocol === 'https:' ? 443 : 80),
      method: req.method,
      path: req.url,
      headers: buildUpstreamHeaders(req, body.length),
    });
    relay.upstreamRequest = upstream;
    upstream.on('response', (upstreamRes) => {
      relay.upstreamResponse = upstreamRes;
      const contentEncoding = String(upstreamRes.headers['content-encoding'] ?? 'identity').toLowerCase();
      if (contentEncoding !== 'identity') {
        upstreamRes.resume();
        finishRelay(relay, 'failed', new Error('Encoded upstream stream is not safe for byte replay'));
        return;
      }
      relay.statusCode = upstreamRes.statusCode ?? 502;
      relay.statusMessage = upstreamRes.statusMessage;
      relay.headers = responseHeaders(upstreamRes.headers, relay.id, 'streaming');
      relay.state = 'streaming';
      emit('upstream-response', relay, { statusCode: relay.statusCode });
      relay.resolveHeaders?.();
      relay.resolveHeaders = null;
      upstreamRes.on('data', (chunk) => appendChunk(relay, chunk));
      upstreamRes.on('end', () => finishRelay(relay, 'complete'));
      upstreamRes.on('aborted', () => finishRelay(relay, 'failed', new Error('Upstream response aborted')));
      upstreamRes.on('error', (error) => finishRelay(relay, 'failed', error));
    });
    upstream.on('error', (error) => finishRelay(relay, 'failed', error));
    upstream.end(body);
  }

  function createRelay(req, device, body, id, signature) {
    cleanExpired();
    while (relays.size >= limits.maxRelays && evictOldestTerminalRelay()) {
      // Terminal relay IDs remain protected by compact tombstones.
    }
    const activeRelays = [...relays.values()]
      .filter((relay) => ['pending', 'streaming'].includes(relay.state));
    const ownerActiveRelayCount = activeRelays
      .filter((relay) => relay.ownerTokenHash === device.tokenHash).length;
    if (relays.size >= limits.maxRelays
        || activeRelays.length >= limits.maxActiveRelays
        || ownerActiveRelayCount >= limits.maxRelaysPerOwner) {
      return null;
    }
    let resolveHeaders;
    const headersReady = new Promise((resolve) => { resolveHeaders = resolve; });
    const relay = {
      id,
      ownerTokenHash: device.tokenHash,
      requestSignature: signature,
      createdAt: Date.now(),
      expiresAt: Number.POSITIVE_INFINITY,
      state: 'pending',
      error: null,
      statusCode: null,
      statusMessage: null,
      headers: null,
      chunks: [],
      length: 0,
      subscribers: new Set(),
      headersReady,
      resolveHeaders,
      upstreamRequest: null,
      upstreamResponse: null,
    };
    relays.set(id, relay);
    emit('created', relay);
    startUpstream(relay, req, body);
    return relay;
  }

  function attach(relay, res, offset) {
    if (res.destroyed || res.closed || res.writableEnded || !res.socket || res.socket.destroyed) {
      emit('attachment-dropped', relay, { offset, reason: 'client-transport-closed-before-headers' });
      return;
    }
    if (offset > relay.length) {
      sendText(res, 416, 'Relay offset is beyond the buffered response');
      return;
    }
    if (relay.state === 'failed') {
      sendText(res, 502, `Relayed upstream failed: ${relay.error?.message ?? 'unknown error'}`);
      return;
    }
    if (relay.state === 'canceled') {
      sendText(res, 409, 'Relay was canceled');
      return;
    }
    res.writeHead(relay.statusCode, relay.statusMessage, {
      ...relay.headers,
      'x-st-mobile-relay-state': relay.state,
    });
    const subscriber = { res, offset };
    emit('attached', relay, { offset });
    for (const chunk of relay.chunks) {
      const end = chunk.start + chunk.data.length;
      if (end <= subscriber.offset) {
        continue;
      }
      const slice = subscriber.offset > chunk.start
        ? chunk.data.subarray(subscriber.offset - chunk.start)
        : chunk.data;
      res.write(slice);
      subscriber.offset += slice.length;
      if (res.writableLength > limits.maxSubscriberQueueBytes) {
        res.destroy();
        return;
      }
    }
    if (relay.state === 'complete') {
      res.end();
      return;
    }
    relay.subscribers.add(subscriber);
    res.once('close', () => {
      relay.subscribers.delete(subscriber);
      emit('detached', relay, { offset: subscriber.offset, reason: 'client-transport-closed' });
    });
  }

  async function handle(req, res, device) {
    const id = singleHeader(req, RELAY_ID_HEADER);
    const offset = parseRelayOffset(req);
    if (!id || !RELAY_ID_PATTERN.test(id) || offset === null) {
      sendText(res, 400, 'Relay headers are malformed');
      return;
    }
    let body;
    try {
      body = await readRequestBody(req, limits.maxRequestBytes);
    } catch (error) {
      if (!res.destroyed) {
        sendText(res, error.statusCode ?? 400, error.message);
      }
      return;
    }
    const pathname = relayUrl(req)?.pathname ?? '';
    if (!bodyRequestsStreaming(pathname, body)) {
      sendText(res, 400, 'Relay request is not a recognized streaming generation');
      return;
    }
    const signature = requestSignature(req, body);
    let relay = relays.get(id);
    if (relay) {
      if (relay.ownerTokenHash !== device.tokenHash) {
        sendText(res, 404, 'Relay not found');
        return;
      }
      if (relay.requestSignature !== signature) {
        sendText(res, 409, 'Relay request does not match its original generation');
        return;
      }
    } else {
      const tombstone = cancelTombstones.get(id);
      if (tombstone) {
        sendText(res, tombstone.ownerTokenHash === device.tokenHash ? 409 : 404,
          tombstone.ownerTokenHash === device.tokenHash ? 'Relay was canceled' : 'Relay not found');
        return;
      }
      if (offset !== 0) {
        sendText(res, 404, 'Relay not found');
        return;
      }
      relay = createRelay(req, device, body, id, signature);
      if (!relay) {
        sendText(res, 503, 'Relay capacity is exhausted');
        return;
      }
    }
    await relay.headersReady;
    attach(relay, res, offset);
  }

  function cancel(id, device) {
    const relay = relays.get(id);
    if (relay && relay.ownerTokenHash !== device.tokenHash) {
      return false;
    }
    if (!relay) {
      cleanExpired();
      recordTombstone(id, device.tokenHash);
      return true;
    }
    cancelRelay(relay, 'Canceled by the generating device');
    recordTombstone(id, device.tokenHash);
    return true;
  }

  function cancelOwner(ownerTokenHash) {
    for (const relay of [...relays.values()]) {
      if (relay.ownerTokenHash === ownerTokenHash) {
        cancelRelay(relay, 'Generating device was revoked');
      }
    }
  }

  function ownerSnapshot(ownerTokenHash) {
    let activeRelayCount = 0;
    let bufferedRelayBytes = 0;
    for (const relay of relays.values()) {
      if (relay.ownerTokenHash === ownerTokenHash) {
        if (['pending', 'streaming'].includes(relay.state)) {
          activeRelayCount += 1;
        }
        bufferedRelayBytes += relay.length;
      }
    }
    return { activeRelayCount, bufferedRelayBytes };
  }

  function ownerTokenHashes() {
    return new Set([...relays.values()].map((relay) => relay.ownerTokenHash));
  }

  function close() {
    clearInterval(cleanupTimer);
    for (const relay of [...relays.values()]) {
      cancelRelay(relay, 'Gateway is shutting down');
    }
    cancelTombstones.clear();
  }

  return {
    handle,
    cancel,
    cancelOwner,
    ownerSnapshot,
    ownerTokenHashes,
    close,
    limits: Object.freeze({ ...limits }),
  };
}
