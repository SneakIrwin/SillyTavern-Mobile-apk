import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createPairingNonce, consumePairingNonce } from '../src/auth.js';
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

async function startFakeSillyTavern() {
  let httpHits = 0;
  let upgradeHits = 0;
  let lastCookie = '';
  let lastUpgradeCookie = '';
  const server = http.createServer((req, res) => {
    httpHits += 1;
    lastCookie = req.headers.cookie ?? '';
    res.setHeader('content-type', 'text/plain');
    res.end(`st ok ${req.url}`);
  });
  server.on('upgrade', (req, socket) => {
    upgradeHits += 1;
    lastUpgradeCookie = req.headers.cookie ?? '';
    socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n');
    socket.end();
  });
  const address = await listen(server);
  return {
    target: `http://127.0.0.1:${address.port}`,
    hits: () => ({ httpHits, upgradeHits }),
    cookies: () => ({ lastCookie, lastUpgradeCookie }),
    close: () => close(server),
  };
}

async function startGateway(target) {
  const dir = await mkdtemp(path.join(tmpdir(), 'st-mobile-gateway-'));
  const store = createStateStore({ stateDir: dir });
  const gateway = await createGatewayServer({
    target,
    store,
    tls: false,
    listenHost: '127.0.0.1',
    listenPort: 0,
  });
  const address = gateway.server.address();
  return {
    url: `http://127.0.0.1:${address.port}`,
    store,
    close: async () => {
      await gateway.close();
      await rm(dir, { recursive: true, force: true });
    },
  };
}

async function pairedCookie(store) {
  const issued = await createPairingNonce(store, { ttlMs: 60_000, label: 'test' });
  const session = await consumePairingNonce(store, issued.nonce, { userAgent: 'node-test' });
  return `stmg=${session.token}`;
}

function rawUpgrade(port, cookie = '') {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1');
    let data = '';
    socket.setTimeout(2_000);
    socket.on('connect', () => {
      const lines = [
        'GET /socket.io/?EIO=4&transport=websocket HTTP/1.1',
        'Host: 127.0.0.1',
        'Upgrade: websocket',
        'Connection: Upgrade',
        'Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==',
        'Sec-WebSocket-Version: 13',
        cookie ? `Cookie: ${cookie}` : '',
      ].filter((line) => line !== '');
      socket.write(`${lines.join('\r\n')}\r\n\r\n`);
    });
    socket.on('data', (chunk) => {
      data += chunk.toString('utf8');
      if (data.includes('\r\n\r\n')) {
        socket.destroy();
      }
    });
    socket.on('timeout', () => {
      socket.destroy(new Error('upgrade timed out'));
    });
    socket.on('error', reject);
    socket.on('close', () => resolve(data));
  });
}

test('unauthenticated HTTP requests are denied before reaching SillyTavern', async () => {
  const st = await startFakeSillyTavern();
  const gateway = await startGateway(st.target);
  try {
    const response = await fetch(`${gateway.url}/`);
    assert.equal(response.status, 403);
    assert.deepEqual(st.hits(), { httpHits: 0, upgradeHits: 0 });
  } finally {
    await gateway.close();
    await st.close();
  }
});

test('malformed session cookies fail closed without proxying', async () => {
  const st = await startFakeSillyTavern();
  const gateway = await startGateway(st.target);
  try {
    const response = await fetch(`${gateway.url}/`, {
      headers: { cookie: 'stmg=%ZZ' },
    });
    assert.equal(response.status, 403);
    assert.equal(await response.text(), 'Forbidden\n');
    assert.deepEqual(st.hits(), { httpHits: 0, upgradeHits: 0 });
  } finally {
    await gateway.close();
    await st.close();
  }
});

test('authenticated HTTP requests proxy to SillyTavern', async () => {
  const st = await startFakeSillyTavern();
  const gateway = await startGateway(st.target);
  try {
    const response = await fetch(`${gateway.url}/characters`, {
      headers: { cookie: await pairedCookie(gateway.store) },
    });
    assert.equal(response.status, 200);
    assert.equal(await response.text(), 'st ok /characters');
    assert.deepEqual(st.hits(), { httpHits: 1, upgradeHits: 0 });
  } finally {
    await gateway.close();
    await st.close();
  }
});

test('concurrent authenticated HTTP fan-out does not produce gateway state-write failures', async () => {
  const st = await startFakeSillyTavern();
  const gateway = await startGateway(st.target);
  try {
    const cookie = await pairedCookie(gateway.store);
    const responses = await Promise.all(Array.from({ length: 40 }, (_, index) => (
      fetch(`${gateway.url}/fanout-${index}`, { headers: { cookie } })
    )));
    const statuses = responses.map((response) => response.status);
    assert.deepEqual([...new Set(statuses)], [200]);
  } finally {
    await gateway.close();
    await st.close();
  }
});

test('gateway session cookie is stripped before proxying to SillyTavern', async () => {
  const st = await startFakeSillyTavern();
  const gateway = await startGateway(st.target);
  try {
    const cookie = `${await pairedCookie(gateway.store)}; theme=dark`;
    const response = await fetch(`${gateway.url}/`, { headers: { cookie } });
    assert.equal(response.status, 200);
    assert.equal(st.cookies().lastCookie, 'theme=dark');
  } finally {
    await gateway.close();
    await st.close();
  }
});

test('one-time pairing URL sets secure cookie and refuses reuse', async () => {
  const st = await startFakeSillyTavern();
  const gateway = await startGateway(st.target);
  try {
    const issued = await createPairingNonce(gateway.store, { ttlMs: 60_000, label: 'qr' });
    const first = await fetch(`${gateway.url}/__mobile/pair/${issued.nonce}`, { redirect: 'manual' });
    assert.equal(first.status, 302);
    assert.match(first.headers.get('set-cookie'), /stmg=.*HttpOnly.*SameSite=Lax/i);
    assert.match(first.headers.get('set-cookie'), /Secure/i);

    const second = await fetch(`${gateway.url}/__mobile/pair/${issued.nonce}`, { redirect: 'manual' });
    assert.equal(second.status, 403);
  } finally {
    await gateway.close();
    await st.close();
  }
});

test('WebSocket upgrades are denied without a session and proxied with one', async () => {
  const st = await startFakeSillyTavern();
  const gateway = await startGateway(st.target);
  try {
    const port = new URL(gateway.url).port;
    const denied = await rawUpgrade(Number(port));
    assert.match(denied, /^HTTP\/1\.1 403 Forbidden/);
    assert.deepEqual(st.hits(), { httpHits: 0, upgradeHits: 0 });

    const accepted = await rawUpgrade(Number(port), await pairedCookie(gateway.store));
    assert.match(accepted, /^HTTP\/1\.1 101 Switching Protocols/);
    assert.deepEqual(st.hits(), { httpHits: 0, upgradeHits: 1 });
  } finally {
    await gateway.close();
    await st.close();
  }
});
