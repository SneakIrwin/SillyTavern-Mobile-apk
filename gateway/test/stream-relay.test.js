import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { consumePairingNonce, createPairingNonce, revokeDevice } from '../src/auth.js';
import { createGatewayServer } from '../src/server.js';
import { createStateStore } from '../src/state.js';

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve(server.address());
    });
  });
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

async function pairedSession(store, label = 'relay test') {
  const issued = await createPairingNonce(store, { ttlMs: 60_000, label });
  const session = await consumePairingNonce(store, issued.nonce, { userAgent: 'node-test' });
  return { ...session, cookie: `stmg=${session.token}` };
}

async function startGateway(target, relayLimits = {}) {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'st-mobile-stream-relay-'));
  const store = createStateStore({ stateDir });
  const gateway = await createGatewayServer({
    target,
    store,
    tls: false,
    listenHost: '127.0.0.1',
    listenPort: 0,
    relayLimits,
  });
  const address = gateway.server.address();
  return {
    url: `http://127.0.0.1:${address.port}`,
    store,
    close: async () => {
      await gateway.close();
      await rm(stateDir, { recursive: true, force: true });
    },
  };
}

function relayHeaders(id, offset) {
  return {
    'content-type': 'application/json',
    'x-st-mobile-relay-id': id,
    'x-st-mobile-relay-offset': String(offset),
  };
}

async function startControlledStreamServer() {
  const requests = [];
  const pending = [];
  const waiters = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const record = {
        req,
        res,
        body: Buffer.concat(chunks),
        headers: { ...req.headers },
      };
      requests.push(record);
      res.writeHead(200, {
        'content-type': 'text/event-stream; charset=utf-8',
        'cache-control': 'no-cache',
        etag: 'must-not-survive-relay',
        digest: 'sha-256=must-not-survive-relay',
      });
      const waiter = waiters.shift();
      if (waiter) waiter(record); else pending.push(record);
    });
  });
  const address = await listen(server);
  return {
    target: `http://127.0.0.1:${address.port}`,
    requests,
    nextRequest: () => pending.length
      ? Promise.resolve(pending.shift())
      : new Promise((resolve) => waiters.push(resolve)),
    close: () => close(server),
  };
}

test('authenticated root injects the blocking relay client once and serves it only to paired devices', async () => {
  let acceptEncoding = '';
  let conditionalHeaders = null;
  const upstream = http.createServer((req, res) => {
    acceptEncoding = String(req.headers['accept-encoding'] ?? '');
    conditionalHeaders = {
      etag: req.headers['if-none-match'],
      modified: req.headers['if-modified-since'],
      range: req.headers.range,
    };
    if (Object.values(conditionalHeaders).some(Boolean)) {
      res.writeHead(304);
      res.end();
      return;
    }
    const html = '<!doctype html><html><head><title>ST</title></head><body><script src="/st.js"></script></body></html>';
    res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'content-length': Buffer.byteLength(html),
      etag: 'stale-etag',
      digest: 'stale-digest',
      'content-md5': 'stale-md5',
      'accept-ranges': 'bytes',
    });
    res.end(html);
  });
  const address = await listen(upstream);
  const gateway = await startGateway(`http://127.0.0.1:${address.port}`);
  try {
    const session = await pairedSession(gateway.store);
    const denied = await fetch(`${gateway.url}/__mobile/stream-relay-client.js`);
    assert.equal(denied.status, 403);

    const response = await fetch(`${gateway.url}/?oauth=callback`, {
      headers: {
        cookie: session.cookie,
        accept: 'text/html',
        'if-none-match': 'cached-root',
        'if-modified-since': new Date(0).toUTCString(),
        range: 'bytes=0-100',
      },
    });
    const body = await response.text();
    const marker = '<script src="/__mobile/stream-relay-client.js" data-st-mobile-stream-relay="v1"></script>';
    assert.equal(response.status, 200);
    assert.equal(body.split(marker).length - 1, 1);
    assert.ok(body.indexOf(marker) < body.indexOf('/st.js'));
    assert.equal(acceptEncoding, 'identity');
    assert.deepEqual(conditionalHeaders, { etag: undefined, modified: undefined, range: undefined });
    assert.equal(response.headers.get('etag'), null);
    assert.equal(response.headers.get('digest'), null);
    assert.equal(response.headers.get('content-md5'), null);
    assert.equal(response.headers.get('accept-ranges'), null);
    assert.equal(Number(response.headers.get('content-length')), Buffer.byteLength(body));

    const script = await fetch(`${gateway.url}/__mobile/stream-relay-client.js`, {
      headers: { cookie: session.cookie },
    });
    assert.equal(script.status, 200);
    assert.match(await script.text(), /stMobileResumableFetch/);
  } finally {
    await gateway.close();
    await close(upstream);
  }
});

test('encoded root HTML is refused instead of being decoded as corrupt markup', async () => {
  const upstream = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html', 'content-encoding': 'gzip' });
    res.end('<html><head></head></html>');
  });
  const address = await listen(upstream);
  const gateway = await startGateway(`http://127.0.0.1:${address.port}`);
  try {
    const session = await pairedSession(gateway.store);
    const response = await fetch(`${gateway.url}/`, {
      headers: { cookie: session.cookie, accept: 'text/html' },
    });
    assert.equal(response.status, 502);
    assert.match(await response.text(), /refused an encoded upstream document/);
  } finally {
    await gateway.close();
    await close(upstream);
  }
});

test('relay keeps one upstream generation alive and replays exact SSE bytes from a reconnect offset', async () => {
  const upstream = await startControlledStreamServer();
  const gateway = await startGateway(upstream.target);
  try {
    const session = await pairedSession(gateway.store);
    const id = crypto.randomUUID();
    const body = JSON.stringify({ stream: true, prompt: 'resume me' });
    const firstFetch = fetch(`${gateway.url}/api/backends/chat-completions/generate`, {
      method: 'POST',
      headers: { ...relayHeaders(id, 0), cookie: `${session.cookie}; theme=dark` },
      body,
    });
    const upstreamRequest = await upstream.nextRequest();
    const firstChunk = Buffer.from('data: {"token":"α"}\n\n', 'utf8');
    const remaining = Buffer.from('data: {"token":"β"}\n\ndata: [DONE]\n\n', 'utf8');
    upstreamRequest.res.write(firstChunk);

    const firstResponse = await firstFetch;
    const firstReader = firstResponse.body.getReader();
    const firstRead = await firstReader.read();
    assert.deepEqual(Buffer.from(firstRead.value), firstChunk);
    await firstReader.cancel();

    upstreamRequest.res.end(remaining);
    await new Promise((resolve) => setTimeout(resolve, 30));
    const resumed = await fetch(`${gateway.url}/api/backends/chat-completions/generate`, {
      method: 'POST',
      headers: { ...relayHeaders(id, firstChunk.length), cookie: session.cookie },
      body,
    });
    assert.equal(resumed.status, 200);
    assert.deepEqual(Buffer.from(await resumed.arrayBuffer()), remaining);
    assert.equal(upstream.requests.length, 1);
    assert.equal(upstreamRequest.body.toString('utf8'), body);
    assert.equal(upstreamRequest.headers['accept-encoding'], 'identity');
    assert.equal(upstreamRequest.headers['x-st-mobile-relay-id'], undefined);
    assert.equal(upstreamRequest.headers['x-st-mobile-relay-offset'], undefined);
    assert.equal(upstreamRequest.headers.cookie, 'theme=dark');
    assert.equal(resumed.headers.get('etag'), null);
    assert.equal(resumed.headers.get('digest'), null);
  } finally {
    await gateway.close();
    await upstream.close();
  }
});

test('relay refuses encoded upstream streams rather than replaying corrupt bytes', async () => {
  const upstream = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      res.writeHead(200, {
        'content-type': 'text/event-stream',
        'content-encoding': 'gzip',
      });
      res.end(Buffer.from('not-really-gzip'));
    });
  });
  const address = await listen(upstream);
  const gateway = await startGateway(`http://127.0.0.1:${address.port}`);
  try {
    const session = await pairedSession(gateway.store);
    const response = await fetch(`${gateway.url}/api/backends/chat-completions/generate`, {
      method: 'POST',
      headers: { ...relayHeaders(crypto.randomUUID(), 0), cookie: session.cookie },
      body: JSON.stringify({ stream: true }),
    });
    assert.equal(response.status, 502);
    assert.match(await response.text(), /Encoded upstream stream is not safe for byte replay/);
  } finally {
    await gateway.close();
    await close(upstream);
  }
});

test('terminal relay eviction preserves its UUID tombstone and frees creation capacity', async () => {
  const upstream = await startControlledStreamServer();
  const gateway = await startGateway(upstream.target, { maxRelays: 1 });
  try {
    const owner = await pairedSession(gateway.store);
    const body = JSON.stringify({ stream: true, prompt: 'capacity' });
    const firstId = crypto.randomUUID();
    const firstFetch = fetch(`${gateway.url}/api/backends/chat-completions/generate`, {
      method: 'POST', headers: { ...relayHeaders(firstId, 0), cookie: owner.cookie }, body,
    });
    const firstUpstream = await upstream.nextRequest();
    firstUpstream.res.end('data: [DONE]\n\n');
    const firstResponse = await firstFetch;
    assert.equal(firstResponse.status, 200);
    await firstResponse.arrayBuffer();

    const secondId = crypto.randomUUID();
    const secondFetch = fetch(`${gateway.url}/api/backends/chat-completions/generate`, {
      method: 'POST', headers: { ...relayHeaders(secondId, 0), cookie: owner.cookie }, body,
    });
    const secondUpstream = await upstream.nextRequest();
    secondUpstream.res.end('data: [DONE]\n\n');
    const secondResponse = await secondFetch;
    assert.equal(secondResponse.status, 200);
    await secondResponse.arrayBuffer();

    const duplicate = await fetch(`${gateway.url}/api/backends/chat-completions/generate`, {
      method: 'POST', headers: { ...relayHeaders(firstId, 0), cookie: owner.cookie }, body,
    });
    assert.equal(duplicate.status, 409);
    assert.equal(upstream.requests.length, 2);
  } finally {
    await gateway.close();
    await upstream.close();
  }
});

test('relay IDs are device-bound and idempotent while explicit cancellation is race-safe', async () => {
  const upstream = await startControlledStreamServer();
  const gateway = await startGateway(upstream.target);
  try {
    const owner = await pairedSession(gateway.store, 'owner');
    const stranger = await pairedSession(gateway.store, 'stranger');
    const id = crypto.randomUUID();
    const body = JSON.stringify({ stream: true, prompt: 'owned' });
    const firstFetch = fetch(`${gateway.url}/api/backends/chat-completions/generate`, {
      method: 'POST', headers: { ...relayHeaders(id, 0), cookie: owner.cookie }, body,
    });
    const controlled = await upstream.nextRequest();
    controlled.res.write(Buffer.from('data: {"token":"one"}\n\n'));
    const first = await firstFetch;

    const changed = await fetch(`${gateway.url}/api/backends/chat-completions/generate`, {
      method: 'POST', headers: { ...relayHeaders(id, 0), cookie: owner.cookie },
      body: JSON.stringify({ stream: true, prompt: 'different' }),
    });
    assert.equal(changed.status, 409);

    const hidden = await fetch(`${gateway.url}/api/backends/chat-completions/generate`, {
      method: 'POST', headers: { ...relayHeaders(id, 0), cookie: stranger.cookie }, body,
    });
    assert.equal(hidden.status, 404);
    const strangerCancel = await fetch(`${gateway.url}/__mobile/stream-relay/${id}`, {
      method: 'DELETE', headers: { cookie: stranger.cookie },
    });
    assert.equal(strangerCancel.status, 404);

    await first.body.cancel();
    const canceled = await fetch(`${gateway.url}/__mobile/stream-relay/${id}`, {
      method: 'DELETE', headers: { cookie: owner.cookie },
    });
    assert.equal(canceled.status, 204);
    const canceledAgain = await fetch(`${gateway.url}/__mobile/stream-relay/${id}`, {
      method: 'DELETE', headers: { cookie: owner.cookie },
    });
    assert.equal(canceledAgain.status, 204);

    const tombstonedId = crypto.randomUUID();
    const preCanceled = await fetch(`${gateway.url}/__mobile/stream-relay/${tombstonedId}`, {
      method: 'DELETE', headers: { cookie: owner.cookie },
    });
    assert.equal(preCanceled.status, 204);
    const lateStart = await fetch(`${gateway.url}/api/backends/chat-completions/generate`, {
      method: 'POST', headers: { ...relayHeaders(tombstonedId, 0), cookie: owner.cookie }, body,
    });
    assert.equal(lateStart.status, 409);
    assert.equal(upstream.requests.length, 1);
  } finally {
    await gateway.close();
    await upstream.close();
  }
});

test('relay rejects malformed scope and oversized uploads before reaching SillyTavern', async () => {
  let hits = 0;
  const upstream = http.createServer((req, res) => { hits += 1; res.end('unexpected'); });
  const address = await listen(upstream);
  const gateway = await startGateway(`http://127.0.0.1:${address.port}`, { maxRequestBytes: 48 });
  try {
    const session = await pairedSession(gateway.store);
    const wrongFlag = await fetch(`${gateway.url}/api/backends/kobold/generate`, {
      method: 'POST', headers: { ...relayHeaders(crypto.randomUUID(), 0), cookie: session.cookie },
      body: JSON.stringify({ stream: true }),
    });
    assert.equal(wrongFlag.status, 400);
    const query = await fetch(`${gateway.url}/api/backends/chat-completions/generate?smuggled=1`, {
      method: 'POST', headers: { ...relayHeaders(crypto.randomUUID(), 0), cookie: session.cookie },
      body: JSON.stringify({ stream: true }),
    });
    assert.equal(query.status, 400);
    const oversized = await fetch(`${gateway.url}/api/backends/chat-completions/generate`, {
      method: 'POST', headers: { ...relayHeaders(crypto.randomUUID(), 0), cookie: session.cookie },
      body: JSON.stringify({ stream: true, prompt: 'x'.repeat(100) }),
    });
    assert.equal(oversized.status, 413);
    assert.equal(hits, 0);
  } finally {
    await gateway.close();
    await close(upstream);
  }
});

test('revoking a device aborts its detached upstream relay with zero subscribers', async () => {
  const upstream = await startControlledStreamServer();
  const gateway = await startGateway(upstream.target);
  try {
    const owner = await pairedSession(gateway.store);
    const id = crypto.randomUUID();
    const body = JSON.stringify({ stream: true, prompt: 'revoke me' });
    const initialFetch = fetch(`${gateway.url}/api/backends/chat-completions/generate`, {
      method: 'POST', headers: { ...relayHeaders(id, 0), cookie: owner.cookie }, body,
    });
    const controlled = await upstream.nextRequest();
    const closed = new Promise((resolve) => controlled.res.once('close', resolve));
    controlled.res.write(Buffer.from('data: {"token":"started"}\n\n'));
    const initial = await initialFetch;
    const reader = initial.body.getReader();
    await reader.read();
    await reader.cancel();
    await revokeDevice(gateway.store, owner.deviceId);
    await Promise.race([
      closed,
      new Promise((_, reject) => setTimeout(() => reject(new Error('revocation did not abort detached relay')), 4_000)),
    ]);
  } finally {
    await gateway.close();
    await upstream.close();
  }
});

test('relay client shim is narrowly scoped and retries with byte offsets without forbidden encoding headers', async () => {
  const source = await readFile(new URL('../public/stream-relay-client.js', import.meta.url), 'utf8');
  assert.match(source, /url\.search !== ''/);
  assert.match(source, /parsed\?\.stream === true/);
  assert.match(source, /parsed\?\.streaming === true/);
  assert.match(source, /headers\.set\('x-st-mobile-relay-offset', String\(offset\)\)/);
  assert.match(source, /controller\.enqueue\(value\);\s*offset \+= value\.byteLength/);
  assert.match(source, /details\.signal\?\.addEventListener\('abort'/);
  assert.match(source, /localStorage\.setItem\(pendingAbortStorageKey/);
  assert.match(source, /while \(true\)/);
  assert.match(source, /relayRetryLifetimeMs = 80 \* 60_000/);
  assert.match(source, /relayRetryDeadline = relayStartedAt \+ relayRetryLifetimeMs/);
  assert.match(source, /activeTransport\?\.abort\(retryLifetimeError\(\)\)/);
  assert.match(source, /Math\.max\(0, relayRetryDeadline - Date\.now\(\)\)/);
  assert.match(source, /retryLifetimeExpired\(\)/);
  assert.match(source, /window\.addEventListener\('online', resumePendingAborts\)/);
  assert.doesNotMatch(source, /headers\.set\(['"]accept-encoding/i);
});
