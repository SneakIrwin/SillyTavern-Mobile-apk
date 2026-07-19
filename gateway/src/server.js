import http from 'node:http';
import https from 'node:https';
import { readFileSync } from 'node:fs';
import net from 'node:net';
import { URL } from 'node:url';

import { COOKIE_NAME, consumePairingNonce, parseCookies, validateRequestSession } from './auth.js';
import { ensureCertificates } from './certs.js';
import { createAuthHubServer } from './hub.js';
import {
  createStreamRelayManager,
  isRelayCandidateRequest,
  RELAY_CLIENT_PATH,
  RELAY_ID_HEADER,
  RELAY_OFFSET_HEADER,
  relayCancelId,
} from './stream-relay.js';

const STREAM_RELAY_CLIENT_SOURCE = readFileSync(
  new URL('../public/stream-relay-client.js', import.meta.url),
  'utf8',
);
const STREAM_RELAY_SCRIPT_TAG = `<script src="${RELAY_CLIENT_PATH}" data-st-mobile-stream-relay="v1"></script>`;
const MAX_INJECTED_HTML_BYTES = 4 * 1024 * 1024;

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

function sendForbidden(resOrSocket) {
  if ('writeHead' in resOrSocket) {
    resOrSocket.writeHead(403, {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
    });
    resOrSocket.end('Forbidden\n');
    return;
  }

  resOrSocket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 10\r\n\r\nForbidden\n');
  resOrSocket.destroy();
}

function setPairingCookie(res, token) {
  res.setHeader('set-cookie', [
    `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Lax`,
  ]);
}

function pairNonceFromUrl(req) {
  const parsed = new URL(req.url, 'http://localhost');
  const match = parsed.pathname.match(/^\/__mobile\/pair\/([A-Za-z0-9_-]+)$/);
  return match ? match[1] : null;
}

function shouldAllowHealth(req) {
  const parsed = new URL(req.url, 'http://localhost');
  return parsed.pathname === '/__mobile/health';
}

function stripGatewayCookie(cookieHeader) {
  const kept = String(cookieHeader ?? '')
    .split(';')
    .map((part) => part.trim())
    .filter(Boolean)
    .filter((part) => !part.startsWith(`${COOKIE_NAME}=`));
  return kept.join('; ');
}

function proxyHeaders(req, {
  forUpgrade = false,
  forceIdentityEncoding = false,
  stripRepresentationConditions = false,
} = {}) {
  const headers = {};
  for (const [key, value] of Object.entries(req.headers)) {
    const lower = key.toLowerCase();
    if (!forUpgrade && HOP_BY_HOP_HEADERS.has(lower)) {
      continue;
    }
    if (forUpgrade && ['proxy-authenticate', 'proxy-authorization'].includes(lower)) {
      continue;
    }
    if (lower === RELAY_ID_HEADER || lower === RELAY_OFFSET_HEADER) {
      continue;
    }
    if (stripRepresentationConditions
        && ['if-match', 'if-modified-since', 'if-none-match', 'if-range', 'if-unmodified-since', 'range'].includes(lower)) {
      continue;
    }
    headers[key] = value;
  }

  const strippedCookie = stripGatewayCookie(req.headers.cookie);
  if (strippedCookie) {
    headers.cookie = strippedCookie;
  } else {
    delete headers.cookie;
  }

  if (forUpgrade) {
    headers.connection = 'Upgrade';
    headers.upgrade = req.headers.upgrade ?? 'websocket';
  }
  if (forceIdentityEncoding) {
    headers['accept-encoding'] = 'identity';
  }

  return headers;
}

function writeHeaderLines(socket, method, url, httpVersion, headers) {
  socket.write(`${method} ${url} HTTP/${httpVersion}\r\n`);
  for (const [key, value] of Object.entries(headers)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        socket.write(`${key}: ${item}\r\n`);
      }
    } else if (value !== undefined) {
      socket.write(`${key}: ${value}\r\n`);
    }
  }
  socket.write('\r\n');
}

function shouldInjectStreamRelayClient(req) {
  if (req.method !== 'GET') {
    return false;
  }
  let parsed;
  try {
    parsed = new URL(req.url, 'http://localhost');
  } catch {
    return false;
  }
  if (parsed.pathname !== '/') {
    return false;
  }
  const destination = String(req.headers['sec-fetch-dest'] ?? '').toLowerCase();
  const accept = String(req.headers.accept ?? '').toLowerCase();
  return destination === 'document' || accept.includes('text/html');
}

function injectedHtmlHeaders(upstreamHeaders, bodyLength) {
  const headers = { ...upstreamHeaders };
  for (const name of [
    'content-encoding',
    'content-length',
    'content-md5',
    'digest',
    'etag',
    'accept-ranges',
    'transfer-encoding',
  ]) {
    delete headers[name];
  }
  headers['content-length'] = String(bodyLength);
  headers['cache-control'] = 'no-store';
  headers['x-st-mobile-stream-relay'] = 'v1';
  return headers;
}

function injectStreamRelayClient(body) {
  if (body.includes(STREAM_RELAY_SCRIPT_TAG)) {
    return body;
  }
  const lower = body.toLowerCase();
  const headStart = lower.indexOf('<head');
  const headEnd = headStart < 0 ? -1 : lower.indexOf('>', headStart);
  if (headEnd < 0) {
    throw new Error('HTML document has no injectable head element');
  }
  return `${body.slice(0, headEnd + 1)}${STREAM_RELAY_SCRIPT_TAG}${body.slice(headEnd + 1)}`;
}

function proxyHttp(targetUrl, req, res, { injectRelayClient = false } = {}) {
  const client = targetUrl.protocol === 'https:' ? https : http;
  const upstream = client.request({
    protocol: targetUrl.protocol,
    hostname: targetUrl.hostname,
    port: targetUrl.port || (targetUrl.protocol === 'https:' ? 443 : 80),
    method: req.method,
    path: req.url,
    headers: proxyHeaders(req, {
      forceIdentityEncoding: injectRelayClient,
      stripRepresentationConditions: injectRelayClient,
    }),
  }, (upstreamRes) => {
    const contentType = String(upstreamRes.headers['content-type'] ?? '').toLowerCase();
    if (injectRelayClient && upstreamRes.statusCode === 200 && contentType.includes('text/html')) {
      const contentEncoding = String(upstreamRes.headers['content-encoding'] ?? 'identity').toLowerCase();
      if (contentEncoding !== 'identity') {
        upstreamRes.resume();
        res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
        res.end('Gateway HTML injection refused an encoded upstream document\n');
        return;
      }
      const chunks = [];
      let length = 0;
      upstreamRes.on('data', (chunk) => {
        length += chunk.length;
        if (length > MAX_INJECTED_HTML_BYTES) {
          upstreamRes.destroy(new Error('SillyTavern HTML exceeds the mobile relay injection limit'));
          return;
        }
        chunks.push(chunk);
      });
      upstreamRes.on('end', () => {
        if (res.destroyed) {
          return;
        }
        try {
          const injected = Buffer.from(injectStreamRelayClient(Buffer.concat(chunks, length).toString('utf8')), 'utf8');
          res.writeHead(
            upstreamRes.statusCode ?? 502,
            upstreamRes.statusMessage,
            injectedHtmlHeaders(upstreamRes.headers, injected.length),
          );
          res.end(injected);
        } catch (error) {
          res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
          res.end(`Gateway HTML injection error: ${error.message}\n`);
        }
      });
      upstreamRes.on('error', (error) => {
        if (!res.headersSent && !res.destroyed) {
          res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
          res.end(`Gateway HTML injection error: ${error.message}\n`);
        }
      });
      return;
    }
    res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.statusMessage, upstreamRes.headers);
    upstreamRes.pipe(res);
  });

  upstream.on('error', (error) => {
    if (!res.headersSent) {
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
    }
    if (!res.destroyed) {
      res.end(`Gateway proxy error: ${error.message}\n`);
    }
  });

  req.pipe(upstream);
}

function proxyUpgrade(targetUrl, req, socket, head) {
  const upstream = net.connect(Number(targetUrl.port || 80), targetUrl.hostname);
  upstream.once('connect', () => {
    writeHeaderLines(upstream, req.method, req.url, req.httpVersion, proxyHeaders(req, { forUpgrade: true }));
    if (head?.length) {
      upstream.write(head);
    }
    upstream.pipe(socket);
    socket.pipe(upstream);
  });
  upstream.once('error', () => {
    if (!socket.destroyed) {
      socket.write('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 12\r\n\r\nBad Gateway\n');
      socket.destroy();
    }
  });
}

export async function createGatewayServer(options) {
  const target = options.target ?? 'http://127.0.0.1:3000';
  const targetUrl = new URL(target);
  const store = options.store;
  if (!store) {
    throw new Error('store is required');
  }

  const activeSockets = new Map();
  const trackedSockets = new WeakSet();
  const relayManager = createStreamRelayManager({
    targetUrl,
    limits: options.relayLimits,
    onEvent: options.onRelayEvent,
    buildUpstreamHeaders: (req, bodyLength) => ({
      ...proxyHeaders(req, { forceIdentityEncoding: true }),
      'content-length': String(bodyLength),
    }),
  });

  function logLastSeenTouchError(error) {
    console.warn(`[st-mobile-gateway] lastSeenAt update skipped: ${error.message}`);
  }

  function trackSocket(device, socket) {
    if (!device?.tokenHash || !socket) {
      return;
    }
    if (trackedSockets.has(socket)) {
      return;
    }
    trackedSockets.add(socket);
    if (!activeSockets.has(device.tokenHash)) {
      activeSockets.set(device.tokenHash, new Set());
    }
    activeSockets.get(device.tokenHash).add(socket);
    socket.once('close', () => {
      activeSockets.get(device.tokenHash)?.delete(socket);
      if (activeSockets.get(device.tokenHash)?.size === 0) {
        activeSockets.delete(device.tokenHash);
      }
    });
  }

  function getConnectionSnapshot() {
    const snapshot = new Map();
    for (const [tokenHash, sockets] of activeSockets) {
      snapshot.set(tokenHash, { connectionCount: sockets.size });
    }
    return snapshot;
  }

  async function closeRevokedSockets() {
    const state = await store.load();
    const validTokenHashes = new Set(Object.values(state.devices)
      .filter((device) => !device.revokedAt)
      .map((device) => device.tokenHash));
    for (const ownerTokenHash of relayManager.ownerTokenHashes()) {
      if (!validTokenHashes.has(ownerTokenHash)) {
        relayManager.cancelOwner(ownerTokenHash);
      }
    }
    for (const [tokenHash, sockets] of activeSockets) {
      const device = Object.values(state.devices).find((candidate) => candidate.tokenHash === tokenHash);
      if (!device || device.revokedAt) {
        relayManager.cancelOwner(tokenHash);
        for (const socket of sockets) {
          socket.destroy();
        }
        activeSockets.delete(tokenHash);
      }
    }
  }

  const revokeTimer = setInterval(() => {
    closeRevokedSockets().catch(() => {});
  }, 2_000);
  revokeTimer.unref?.();

  const handler = async (req, res) => {
    try {
      if (shouldAllowHealth(req)) {
        res.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store',
        });
        res.end(JSON.stringify({ ok: true }));
        return;
      }

      const nonce = pairNonceFromUrl(req);
      if (nonce) {
        const session = await consumePairingNonce(store, nonce, {
          userAgent: req.headers['user-agent'] ?? '',
          remoteAddress: req.socket.remoteAddress ?? '',
        });
        if (!session) {
          sendForbidden(res);
          return;
        }
        setPairingCookie(res, session.token);
        res.writeHead(302, {
          location: '/',
          'cache-control': 'no-store',
        });
        res.end();
        return;
      }

      const device = await validateRequestSession(store, req, COOKIE_NAME, { onTouchError: logLastSeenTouchError });
      if (!device) {
        sendForbidden(res);
        return;
      }

      trackSocket(device, req.socket);
      const pathname = new URL(req.url, 'http://localhost').pathname;
      if (pathname === RELAY_CLIENT_PATH) {
        if (req.method !== 'GET') {
          res.writeHead(405, { allow: 'GET', 'cache-control': 'no-store' });
          res.end();
          return;
        }
        res.writeHead(200, {
          'content-type': 'text/javascript; charset=utf-8',
          'content-length': Buffer.byteLength(STREAM_RELAY_CLIENT_SOURCE),
          'cache-control': 'no-store',
          'x-content-type-options': 'nosniff',
        });
        res.end(STREAM_RELAY_CLIENT_SOURCE);
        return;
      }

      if (pathname.startsWith('/__mobile/stream-relay/')) {
        const cancelId = relayCancelId(req);
        if (!cancelId) {
          res.writeHead(req.method === 'DELETE' ? 400 : 405, {
            allow: 'DELETE',
            'cache-control': 'no-store',
          });
          res.end();
          return;
        }
        if (!relayManager.cancel(cancelId, device)) {
          res.writeHead(404, { 'cache-control': 'no-store' });
          res.end();
          return;
        }
        res.writeHead(204, { 'cache-control': 'no-store' });
        res.end();
        return;
      }

      if (isRelayCandidateRequest(req)) {
        await relayManager.handle(req, res, device);
        return;
      }
      if (req.headers[RELAY_ID_HEADER] !== undefined || req.headers[RELAY_OFFSET_HEADER] !== undefined) {
        res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
        res.end('Relay headers are not valid for this request\n');
        return;
      }

      proxyHttp(targetUrl, req, res, { injectRelayClient: shouldInjectStreamRelayClient(req) });
    } catch (error) {
      console.error(`[st-mobile-gateway] ${req.method} ${req.url} failed: ${error.stack || error.message}`);
      if (!res.headersSent) {
        res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
      }
      res.end(`Gateway error: ${error.message}\n`);
    }
  };

  let serverOptions = {};
  if (options.tls !== false) {
    const certificates = options.certificates ?? await ensureCertificates({
      certDir: options.certDir,
      hostnames: [options.publicHost, options.listenHost].filter(Boolean),
    });
    serverOptions = {
      key: certificates.serverKeyPem,
      cert: certificates.serverCertPem,
    };
  }

  const server = options.tls === false
    ? http.createServer(handler)
    : https.createServer(serverOptions, handler);

  server.on('upgrade', async (req, socket, head) => {
    try {
      const cookies = parseCookies(req.headers.cookie);
      const device = await validateRequestSession(store, { headers: { cookie: `${COOKIE_NAME}=${cookies[COOKIE_NAME] ?? ''}` } }, COOKIE_NAME, { onTouchError: logLastSeenTouchError });
      if (!device) {
        sendForbidden(socket);
        return;
      }
      trackSocket(device, socket);
      proxyUpgrade(targetUrl, req, socket, head);
    } catch {
      sendForbidden(socket);
    }
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.listenPort ?? 38443, options.listenHost ?? '0.0.0.0', () => {
      server.off('error', reject);
      resolve();
    });
  });

  const boundAddress = server.address();
  const gatewayPort = typeof boundAddress === 'object' && boundAddress ? boundAddress.port : (options.listenPort ?? 38443);
  let hub = null;
  try {
    hub = options.hubPort === undefined ? null : await createAuthHubServer({
      store,
      publicHost: options.publicHost,
      gatewayPort,
      gatewayScheme: options.tls === false ? 'http' : 'https',
      listenHost: options.hubHost ?? '127.0.0.1',
      listenPort: options.hubPort,
      getConnectionSnapshot,
      closeRevokedSockets,
    });
  } catch (error) {
    clearInterval(revokeTimer);
    await new Promise((resolve) => server.close(resolve));
    throw error;
  }

  return {
    server,
    hub,
    close: async () => {
      clearInterval(revokeTimer);
      relayManager.close();
      if (hub) {
        await hub.close();
      }
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
