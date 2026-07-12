import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

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
  const upgradeSockets = new Set();
  const server = http.createServer((req, res) => {
    res.setHeader('content-type', 'text/html; charset=utf-8');
    res.end('<title>SillyTavern</title><div id="top-settings-holder"></div>');
  });
  server.on('upgrade', (req, socket) => {
    upgradeSockets.add(socket);
    socket.once('close', () => upgradeSockets.delete(socket));
    socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n');
  });
  const address = await listen(server);
  return {
    target: `http://127.0.0.1:${address.port}`,
    close: async () => {
      for (const socket of upgradeSockets) {
        socket.destroy();
      }
      await close(server);
    },
  };
}

async function startGateway(target, extra = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), 'st-mobile-hub-'));
  const store = createStateStore({ stateDir: dir });
  try {
    const gateway = await createGatewayServer({
      target,
      store,
      tls: false,
      listenHost: '127.0.0.1',
      listenPort: 0,
      publicHost: '127.0.0.1',
      hubPort: 0,
      ...extra,
    });
    const address = gateway.server.address();
    return {
      url: `http://127.0.0.1:${address.port}`,
      hubUrl: gateway.hub.url.replace(/\/$/, ''),
      store,
      close: async () => {
        await gateway.close();
        await rm(dir, { recursive: true, force: true });
      },
    };
  } catch (error) {
    await rm(dir, { recursive: true, force: true });
    throw error;
  }
}

async function postJson(url, body, headers = {}) {
  return fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

function cookieToken(setCookie) {
  return String(setCookie).match(/stmg=([^;]+)/)?.[1] ?? '';
}

function rawUpgradeHold(port, cookie) {
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
        `Cookie: ${cookie}`,
      ];
      socket.write(`${lines.join('\r\n')}\r\n\r\n`);
    });
    socket.on('data', (chunk) => {
      data += chunk.toString('utf8');
      if (data.includes('\r\n\r\n')) {
        resolve({ socket, data });
      }
    });
    socket.on('timeout', () => {
      socket.destroy(new Error('upgrade timed out'));
    });
    socket.on('error', reject);
  });
}

function requestWithHeaders(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const req = http.request({
      hostname: parsed.hostname,
      port: parsed.port,
      method: 'GET',
      path: `${parsed.pathname}${parsed.search}`,
      headers,
    }, (res) => {
      res.resume();
      res.on('end', () => resolve(res));
    });
    req.on('error', reject);
    req.end();
  });
}

function getTextWithHeaders(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const req = http.request({
      hostname: parsed.hostname,
      port: parsed.port,
      method: 'GET',
      path: `${parsed.pathname}${parsed.search}`,
      headers,
      agent: false,
    }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        body += chunk;
      });
      res.on('end', () => resolve({ statusCode: res.statusCode, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

async function eventually(predicate, timeoutMs = 1500) {
  const deadline = Date.now() + timeoutMs;
  let lastValue;
  while (Date.now() < deadline) {
    lastValue = await predicate();
    if (lastValue) {
      return lastValue;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return lastValue;
}

test('auth hub is loopback-only', async () => {
  const st = await startFakeSillyTavern();
  await assert.rejects(
    () => startGateway(st.target, { hubHost: '0.0.0.0' }),
    /auth hub must bind to loopback only/,
  );
  await st.close();
});

test('auth hub generates pairing QR, tracks connected devices, and revokes live sockets', async () => {
  const st = await startFakeSillyTavern();
  const gateway = await startGateway(st.target);
  let heldUpgrade;
  try {
    const html = await fetch(`${gateway.hubUrl}/`).then((response) => response.text());
    assert.match(html, /SillyTavern Mobile Auth Hub/);
    assert.match(html, /Attribution/);

    const rebindingHost = await requestWithHeaders(`${gateway.hubUrl}/api/devices`, { Host: 'evil.example.test:38444' });
    assert.equal(rebindingHost.statusCode, 403);

    const rejected = await postJson(`${gateway.hubUrl}/api/pair`, { label: 'S24 Ultra' });
    assert.equal(rejected.status, 403);

    const rejectedOrigin = await postJson(
      `${gateway.hubUrl}/api/pair`,
      { label: 'S24 Ultra' },
      { 'x-st-mobile-hub': '1', Origin: 'http://evil.example.test' },
    );
    assert.equal(rejectedOrigin.status, 403);

    const pairResponse = await postJson(`${gateway.hubUrl}/api/pair`, { label: 'S24 Ultra' }, { 'x-st-mobile-hub': '1' });
    assert.equal(pairResponse.status, 200);
    const pair = await pairResponse.json();
    assert.equal(pair.label, 'S24 Ultra');
    assert.match(pair.deepLink, /^stmobile:\/\/pair\?url=/);
    assert.match(pair.qrDataUrl, /^data:image\/png;base64,/);
    assert.match(pair.pairUrl, new RegExp(`^${gateway.url.replaceAll('.', '\\.')}\\/__mobile\\/pair\\/`));

    const identityResponse = await fetch(`${gateway.hubUrl}/api/devices`);
    assert.equal(identityResponse.headers.get('x-st-mobile-hub'), '1');
    let devices = await identityResponse.json();
    assert.equal(devices.service, 'sillytavern-mobile-auth-hub');
    assert.equal(devices.schemaVersion, 1);
    assert.equal(devices.pendingPairings.length, 1);
    assert.equal(devices.devices.length, 0);

    const pairing = await fetch(pair.pairUrl, { redirect: 'manual' });
    assert.equal(pairing.status, 302);
    const setCookie = pairing.headers.get('set-cookie');
    assert.match(setCookie, /Max-Age=31536000/);
    const cookie = `stmg=${cookieToken(setCookie)}`;

    const page = await getTextWithHeaders(`${gateway.url}/`, { Cookie: cookie, Connection: 'close' });
    assert.equal(page.statusCode, 200);
    assert.match(page.body, /<title>SillyTavern<\/title>/);
    assert.match(page.body, /top-settings-holder/);

    devices = await eventually(async () => {
      const snapshot = await fetch(`${gateway.hubUrl}/api/devices`).then((response) => response.json());
      return snapshot.devices[0]?.status === 'disconnected' ? snapshot : null;
    });
    assert.equal(devices.pendingPairings.length, 0);
    assert.equal(devices.devices.length, 1);
    assert.equal(devices.devices[0].status, 'disconnected');
    assert.equal(devices.devices[0].authorized, true);

    const gatewayPort = Number(new URL(gateway.url).port);
    heldUpgrade = await rawUpgradeHold(gatewayPort, cookie);
    assert.match(heldUpgrade.data, /101 Switching Protocols/);

    const connected = await eventually(async () => {
      const snapshot = await fetch(`${gateway.hubUrl}/api/devices`).then((response) => response.json());
      return snapshot.devices[0]?.connected ? snapshot : null;
    });
    assert.equal(connected.devices[0].status, 'connected');
    assert.equal(connected.devices[0].connectionCount, 1);

    const revoke = await postJson(
      `${gateway.hubUrl}/api/revoke`,
      { deviceId: connected.devices[0].deviceId },
      { 'x-st-mobile-hub': '1' },
    );
    assert.equal(revoke.status, 200);

    const revoked = await eventually(async () => {
      const snapshot = await fetch(`${gateway.hubUrl}/api/devices`).then((response) => response.json());
      return snapshot.devices[0]?.status === 'revoked' ? snapshot : null;
    });
    assert.equal(revoked.devices[0].authorized, false);
    assert.equal(revoked.devices[0].connected, false);
  } finally {
    heldUpgrade?.socket.destroy();
    await gateway.close();
    await st.close();
  }
});
