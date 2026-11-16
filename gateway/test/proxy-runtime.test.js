import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';
import { sha256 } from '../src/auth.js';
import { createGatewayServer } from '../src/server.js';

async function fixture(handler) {
  const upstream = http.createServer(handler);
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const token = 'proxy-runtime-test';
  const store = {
    load: async () => ({ devices: { test: { tokenHash: sha256(token), lastSeenAt: new Date().toISOString() } } }),
    update: async () => {},
  };
  const gateway = await createGatewayServer({ target: `http://127.0.0.1:${upstream.address().port}`, store, tls: false, listenHost: '127.0.0.1', listenPort: 0 });
  return {
    url: `http://127.0.0.1:${gateway.server.address().port}`,
    headers: { cookie: `stmg=${token}` },
    close: async () => {
      await gateway.close();
      upstream.closeAllConnections();
      await new Promise((resolve) => upstream.close(resolve));
    },
  };
}

test('ordinary proxy fails a truncated upstream body promptly instead of hanging or appending text', { timeout: 5000 }, async () => {
  const f = await fixture((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.write('partial response');
    setTimeout(() => res.destroy(), 30);
  });
  try {
    const response = await fetch(`${f.url}/ordinary`, { headers: f.headers, signal: AbortSignal.timeout(2000) });
    assert.equal(response.status, 200);
    await assert.rejects(response.text(), (error) => error.name !== 'TimeoutError');
  } finally { await f.close(); }
});

test('ordinary proxy client cancellation closes the upstream response', { timeout: 5000 }, async () => {
  let closed;
  const closedPromise = new Promise((resolve) => { closed = resolve; });
  const f = await fixture((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.write('live response');
    res.once('close', closed);
  });
  try {
    const response = await fetch(`${f.url}/ordinary`, { headers: f.headers, signal: AbortSignal.timeout(2000) });
    const reader = response.body.getReader();
    await reader.read();
    await reader.cancel();
    let timeout;
    try {
      await Promise.race([closedPromise, new Promise((_resolve, reject) => { timeout = setTimeout(() => reject(new Error('upstream leaked')), 1500); })]);
    } finally { clearTimeout(timeout); }
  } finally { await f.close(); }
});

test('truncated HTML injection returns a gateway error before headers are committed', { timeout: 5000 }, async () => {
  const f = await fixture((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.write('<html><head>');
    setTimeout(() => res.destroy(), 30);
  });
  try {
    const response = await fetch(`${f.url}/`, { headers: { ...f.headers, accept: 'text/html' }, signal: AbortSignal.timeout(2000) });
    assert.equal(response.status, 502);
    assert.match(await response.text(), /Gateway proxy error/);
  } finally { await f.close(); }
});

test('revocation follows the current device after keep-alive HTTP authenticates a different WebSocket owner', { timeout: 8000 }, async () => {
  const upstreamSockets = new Set();
  let upgradedUpstreamSocket;
  let markUpstreamClosed;
  const upstreamClosed = new Promise((resolve) => { markUpstreamClosed = resolve; });
  const upstream = http.createServer((_req, res) => res.end('ordinary response'));
  upstream.on('connection', (socket) => {
    upstreamSockets.add(socket);
    socket.once('close', () => upstreamSockets.delete(socket));
  });
  upstream.on('upgrade', (_req, socket) => {
    upgradedUpstreamSocket = socket;
    socket.once('close', markUpstreamClosed);
    // A WebSocket peer consumes frames; a paused raw test socket would not
    // observe the remote FIN and could falsely look like a leaked connection.
    socket.resume();
    // HTTP upgrade sockets allow half-open TCP connections. Acknowledge the
    // gateway's EOF so this test peer can finish closing its own write side.
    socket.once('end', () => socket.end());
    socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n');
  });
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const now = new Date().toISOString();
  const state = { devices: {
    a: { tokenHash: sha256('runtime-owner-a'), lastSeenAt: now },
    b: { tokenHash: sha256('runtime-owner-b'), lastSeenAt: now },
  } };
  const store = { load: async () => state, update: async (mutate) => mutate(state) };
  const gateway = await createGatewayServer({
    target: `http://127.0.0.1:${upstream.address().port}`, store, tls: false,
    listenHost: '127.0.0.1', listenPort: 0,
  });
  const port = gateway.server.address().port;
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  let firstSocket;
  let upgradedSocket;
  try {
    await new Promise((resolve, reject) => {
      const req = http.get({ host: '127.0.0.1', port, path: '/ordinary', agent,
        headers: { cookie: 'stmg=runtime-owner-a' } }, (res) => {
        firstSocket = req.socket;
        res.resume();
        res.once('end', resolve);
        res.once('error', reject);
      });
      req.once('error', reject);
    });
    upgradedSocket = await new Promise((resolve, reject) => {
      const req = http.get({ host: '127.0.0.1', port, path: '/websocket', agent,
        headers: { cookie: 'stmg=runtime-owner-b', connection: 'Upgrade', upgrade: 'websocket' } });
      req.once('error', reject);
      req.once('response', (res) => {
        res.resume();
        reject(new Error(`Expected WebSocket upgrade, got HTTP ${res.statusCode}`));
      });
      req.once('upgrade', (_res, socket) => resolve(socket));
    });
    assert.equal(upgradedSocket, firstSocket, 'Regression requires reuse of the exact authenticated TCP connection');
    const closed = new Promise((resolve) => upgradedSocket.once('close', resolve));
    state.devices.b.revokedAt = new Date().toISOString();
    let timer;
    try {
      await Promise.race([
        Promise.all([closed, upstreamClosed]),
        new Promise((_resolve, reject) => { timer = setTimeout(() => reject(new Error('Revoked current WebSocket owner or its upstream stayed connected')), 3500); }),
      ]);
    } finally { clearTimeout(timer); }
    assert.equal(upgradedSocket.destroyed, true);
    assert.equal(upgradedUpstreamSocket.readableEnded, true);
    assert.equal(upgradedUpstreamSocket.destroyed, true);
    assert.equal(state.devices.a.revokedAt, undefined, 'The original owner remains valid and must not mask the revocation');
  } finally {
    upgradedSocket?.destroy();
    agent.destroy();
    for (const socket of upstreamSockets) socket.destroy();
    await gateway.close();
    await new Promise((resolve) => upstream.close(resolve));
  }
});

test('gateway close terminates a live upgraded client and its upstream without hanging', { timeout: 5000 }, async () => {
  const upstreamSockets = new Set();
  let upgradedUpstreamSocket;
  let markUpstreamClosed;
  const upstreamClosed = new Promise((resolve) => { markUpstreamClosed = resolve; });
  const upstream = http.createServer((_req, res) => res.end('ordinary response'));
  upstream.on('connection', (socket) => {
    upstreamSockets.add(socket);
    socket.once('close', () => upstreamSockets.delete(socket));
  });
  upstream.on('upgrade', (_req, socket) => {
    upgradedUpstreamSocket = socket;
    socket.once('close', markUpstreamClosed);
    socket.resume();
    socket.once('end', () => socket.end());
    socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n');
  });
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const store = {
    load: async () => ({ devices: { owner: {
      tokenHash: sha256('shutdown-upgrade-owner'), lastSeenAt: new Date().toISOString(),
    } } }),
    update: async () => {},
  };
  const gateway = await createGatewayServer({
    target: `http://127.0.0.1:${upstream.address().port}`, store, tls: false,
    listenHost: '127.0.0.1', listenPort: 0,
  });
  let client;
  let timer;
  try {
    client = await new Promise((resolve, reject) => {
      const req = http.get({ host: '127.0.0.1', port: gateway.server.address().port,
        path: '/websocket', agent: false,
        headers: { cookie: 'stmg=shutdown-upgrade-owner', connection: 'Upgrade', upgrade: 'websocket' } });
      req.once('error', reject);
      req.once('response', (res) => {
        res.resume();
        reject(new Error(`Expected WebSocket upgrade, got HTTP ${res.statusCode}`));
      });
      req.once('upgrade', (_res, socket) => resolve(socket));
    });
    const clientClosed = new Promise((resolve) => client.once('close', resolve));
    await Promise.race([
      Promise.all([gateway.close(), clientClosed, upstreamClosed]),
      new Promise((_resolve, reject) => { timer = setTimeout(() => reject(new Error('Gateway shutdown leaked a live upgrade')), 1500); }),
    ]);
    assert.equal(client.destroyed, true);
    assert.equal(upgradedUpstreamSocket.readableEnded, true);
    assert.equal(upgradedUpstreamSocket.destroyed, true);
    assert.equal(gateway.server.listening, false);
  } finally {
    clearTimeout(timer);
    client?.destroy();
    for (const socket of upstreamSockets) socket.destroy();
    if (gateway.server.listening) await gateway.close();
    await new Promise((resolve) => upstream.close(resolve));
  }
});
