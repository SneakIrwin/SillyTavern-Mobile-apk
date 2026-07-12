import http from 'node:http';
import { URL } from 'node:url';

import QRCode from 'qrcode';

import { createPairingNonce, revokeDevice } from './auth.js';

const HUB_MUTATION_HEADER = 'x-st-mobile-hub';
const HUB_IDENTITY_HEADER = 'x-st-mobile-hub';
const HUB_SERVICE_ID = 'sillytavern-mobile-auth-hub';
const HUB_SCHEMA_VERSION = 1;
const MAX_JSON_BODY_BYTES = 16 * 1024;

function isLoopbackHost(host) {
  const normalized = String(host ?? '').toLowerCase().replace(/^\[|\]$/g, '');
  return normalized === '127.0.0.1' || normalized === '::1' || normalized === 'localhost';
}

function hostnameFromHostHeader(hostHeader) {
  const value = String(hostHeader ?? '').trim();
  if (!value) {
    return '';
  }
  try {
    return new URL(`http://${value}`).hostname;
  } catch {
    return '';
  }
}

function isAllowedHubHost(req) {
  return isLoopbackHost(hostnameFromHostHeader(req.headers.host));
}

function isAllowedHubOrigin(req) {
  const origin = String(req.headers.origin ?? '').trim();
  if (!origin) {
    return true;
  }
  try {
    return isLoopbackHost(new URL(origin).hostname);
  } catch {
    return false;
  }
}

function sendJson(res, status, value) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    [HUB_IDENTITY_HEADER]: '1',
  });
  res.end(`${JSON.stringify(value)}\n`);
}

function sendText(res, status, body, contentType = 'text/plain; charset=utf-8') {
  res.writeHead(status, {
    'content-type': contentType,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'x-frame-options': 'DENY',
    [HUB_IDENTITY_HEADER]: '1',
  });
  res.end(body);
}

function requireHubMutationHeader(req) {
  if (!isAllowedHubOrigin(req)) {
    const error = new Error('Forbidden hub origin');
    error.statusCode = 403;
    throw error;
  }
  if (req.headers[HUB_MUTATION_HEADER] !== '1') {
    const error = new Error('Missing hub mutation header');
    error.statusCode = 403;
    throw error;
  }
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_JSON_BODY_BYTES) {
        reject(Object.assign(new Error('Request body too large'), { statusCode: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (chunks.length === 0) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(Object.assign(new Error('Invalid JSON body'), { statusCode: 400 }));
      }
    });
    req.on('error', reject);
  });
}

function normalizeLabel(value) {
  const label = String(value ?? '').trim();
  return label ? label.slice(0, 80) : 'Android device';
}

function pendingPairings(state, now = Date.now()) {
  return Object.values(state.pendingNonces)
    .filter((pending) => !pending.consumedAt && Date.parse(pending.expiresAt) > now)
    .map((pending) => ({
      label: pending.label,
      createdAt: pending.createdAt,
      expiresAt: pending.expiresAt,
    }))
    .sort((a, b) => String(a.expiresAt).localeCompare(String(b.expiresAt)));
}

function summarizeDevice(device, connections) {
  const connectionCount = Number(connections.get(device.tokenHash)?.connectionCount ?? 0);
  const revoked = Boolean(device.revokedAt);
  const connected = !revoked && connectionCount > 0;
  return {
    deviceId: device.deviceId,
    label: device.label,
    userAgent: device.userAgent,
    remoteAddress: device.remoteAddress,
    createdAt: device.createdAt,
    lastSeenAt: device.lastSeenAt,
    revokedAt: device.revokedAt,
    authorized: !revoked,
    connected,
    connectionCount: revoked ? 0 : connectionCount,
    status: revoked ? 'revoked' : connected ? 'connected' : 'disconnected',
  };
}

function renderHubHtml() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SillyTavern Mobile Auth Hub</title>
  <style>
    :root { color-scheme: dark; --bg: #101214; --panel: #171b1f; --line: #2b333b; --text: #eef3f7; --muted: #aab6c2; --accent: #e0445e; --ok: #54d17a; --warn: #e5b84d; font-family: Inter, Segoe UI, system-ui, sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--bg); color: var(--text); }
    header { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 16px 20px; border-bottom: 1px solid var(--line); }
    h1 { font-size: 20px; margin: 0; }
    main { display: grid; grid-template-columns: minmax(280px, 380px) 1fr; min-height: calc(100vh - 65px); }
    section { padding: 18px 20px; border-right: 1px solid var(--line); }
    section:last-child { border-right: 0; }
    label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 6px; }
    input { width: 100%; border: 1px solid var(--line); border-radius: 6px; background: #0d0f11; color: var(--text); padding: 10px 12px; font: inherit; }
    button { border: 1px solid var(--line); border-radius: 6px; background: #222932; color: var(--text); padding: 9px 12px; font: inherit; cursor: pointer; }
    button.primary { background: var(--accent); border-color: var(--accent); color: white; }
    button:disabled { opacity: .55; cursor: default; }
    .row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .stack { display: grid; gap: 12px; }
    .qr { width: min(100%, 280px); aspect-ratio: 1; background: white; border-radius: 6px; padding: 8px; display: none; }
    .linkbox { word-break: break-all; color: var(--muted); font-size: 13px; line-height: 1.4; }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; border-bottom: 1px solid var(--line); padding: 10px 8px; vertical-align: top; font-size: 13px; }
    th { color: var(--muted); font-weight: 600; }
    .status { display: inline-flex; align-items: center; gap: 6px; }
    .dot { width: 8px; height: 8px; border-radius: 999px; background: var(--muted); display: inline-block; }
    .connected .dot { background: var(--ok); }
    .revoked .dot { background: var(--warn); }
    .muted { color: var(--muted); }
    .error { color: #ff8d9f; min-height: 20px; }
    .tabs { display: flex; gap: 8px; margin-bottom: 14px; }
    .tab-panel[hidden] { display: none; }
    @media (max-width: 840px) { main { grid-template-columns: 1fr; } section { border-right: 0; border-bottom: 1px solid var(--line); } }
  </style>
</head>
<body>
  <header><h1>SillyTavern Mobile Auth Hub</h1><div class="row"><span class="muted" id="gateway"></span><button id="refresh">Refresh</button></div></header>
  <main>
    <section class="stack">
      <div><label for="label">Pairing label</label><input id="label" value="S24 Ultra" maxlength="80"></div>
      <button id="pair" class="primary">Generate QR</button>
      <img id="qr" class="qr" alt="Pairing QR code">
      <div class="linkbox" id="deepLink"></div>
      <div class="linkbox" id="manualUrl"></div>
      <div class="muted" id="expires"></div>
      <div class="error" id="error"></div>
    </section>
    <section>
      <div class="tabs"><button class="tab" data-tab="devices">Devices</button><button class="tab" data-tab="desktop">Desktop</button><button class="tab" data-tab="attribution">Attribution</button></div>
      <div id="devices" class="tab-panel">
        <table><thead><tr><th>Status</th><th>Label</th><th>Last Seen</th><th>Device ID</th><th></th></tr></thead><tbody id="deviceRows"></tbody></table>
      </div>
      <div id="desktop" class="tab-panel" hidden>
        <div class="stack">
          <h2>Background tray host</h2>
          <p>The ST Launcher home-menu option 1, <strong>Update &amp; Start SillyTavern</strong>, starts the authentication hub tray automatically without opening another window.</p>
          <p>Right-click the SillyTavern Mobile icon under the taskbar hidden icons and toggle <strong>Start with Windows</strong> to opt in or out. At Windows login the tray waits quietly for SillyTavern; it does not launch SillyTavern by itself.</p>
          <p class="muted">The tray host and every automatic child run hidden/no-focus at Windows Idle priority. Double-click the tray icon to return here.</p>
        </div>
      </div>
      <div id="attribution" class="tab-panel" hidden>
        <div class="stack">
          <p>This project is an independent mobile wrapper and secure LAN gateway for a local SillyTavern instance.</p>
          <p>SillyTavern is AGPL-3.0 licensed. Its public credits also identify Original TavernAI 1.2.8 by Humi under the MIT License. Credits: https://docs.sillytavern.app/licensecredits/</p>
          <p>SillyTavern Launcher is MIT licensed. Its copyright and license notice is preserved in this repository.</p>
          <p>The Android launcher icon is derived from / intended to match SillyTavern Launcher's red network/brain visual identity. Icon source inspected: https://github.com/SillyTavern/SillyTavern-Launcher/blob/main/st-launcher.ico</p>
          <p>Source and notices: https://github.com/SneakIrwin/SillyTavern-Mobile-apk</p>
          <p class="muted">No official affiliation or endorsement is claimed.</p>
        </div>
      </div>
    </section>
  </main>
  <script>
    const hubHeader = { 'content-type': 'application/json', 'x-st-mobile-hub': '1' };
    const els = {
      label: document.getElementById('label'), pair: document.getElementById('pair'), qr: document.getElementById('qr'),
      deepLink: document.getElementById('deepLink'), manualUrl: document.getElementById('manualUrl'), expires: document.getElementById('expires'),
      error: document.getElementById('error'), rows: document.getElementById('deviceRows'), refresh: document.getElementById('refresh'), gateway: document.getElementById('gateway'),
    };
    function setError(message) { els.error.textContent = message || ''; }
    function fmt(value) { if (!value) return ''; const date = new Date(value); return Number.isNaN(date.getTime()) ? value : date.toLocaleString(); }
    function tab(name) { for (const panel of document.querySelectorAll('.tab-panel')) panel.hidden = panel.id !== name; }
    async function jsonFetch(url, options = {}) { const response = await fetch(url, options); const body = await response.json().catch(() => ({})); if (!response.ok) throw new Error(body.error || response.statusText); return body; }
    async function refresh() {
      const data = await jsonFetch('/api/devices'); els.gateway.textContent = data.gatewayUrl; els.rows.replaceChildren();
      for (const device of data.devices) {
        const row = document.createElement('tr');
        const status = document.createElement('td');
        const statusWrap = document.createElement('span'); statusWrap.className = 'status ' + device.status;
        const dot = document.createElement('span'); dot.className = 'dot';
        statusWrap.append(dot, document.createTextNode(device.status)); status.append(statusWrap);
        const label = document.createElement('td'); label.textContent = device.label || '';
        const lastSeen = document.createElement('td'); lastSeen.textContent = fmt(device.lastSeenAt);
        const id = document.createElement('td'); id.textContent = device.deviceId;
        const actions = document.createElement('td'); const button = document.createElement('button'); button.textContent = 'Revoke'; button.disabled = Boolean(device.revokedAt);
        button.addEventListener('click', async () => { button.disabled = true; await jsonFetch('/api/revoke', { method: 'POST', headers: hubHeader, body: JSON.stringify({ deviceId: device.deviceId }) }); await refresh(); });
        actions.append(button); row.append(status, label, lastSeen, id, actions); els.rows.append(row);
      }
    }
    async function pair() {
      setError(''); els.pair.disabled = true;
      try {
        const data = await jsonFetch('/api/pair', { method: 'POST', headers: hubHeader, body: JSON.stringify({ label: els.label.value }) });
        els.qr.src = data.qrDataUrl; els.qr.style.display = 'block'; els.deepLink.textContent = data.deepLink; els.manualUrl.textContent = data.pairUrl; els.expires.textContent = 'Expires ' + fmt(data.expiresAt); await refresh();
      } catch (error) { setError(error.message); } finally { els.pair.disabled = false; }
    }
    document.querySelectorAll('.tab').forEach((button) => button.addEventListener('click', () => tab(button.dataset.tab)));
    els.pair.addEventListener('click', pair); els.refresh.addEventListener('click', () => refresh().catch((error) => setError(error.message)));
    tab('devices'); refresh().catch((error) => setError(error.message)); setInterval(() => refresh().catch(() => {}), 2000);
  </script>
</body>
</html>`;
}

export async function createAuthHubServer(options) {
  const listenHost = options.listenHost ?? '127.0.0.1';
  if (!isLoopbackHost(listenHost)) {
    throw new Error('auth hub must bind to loopback only');
  }
  if (!options.publicHost) {
    throw new Error('auth hub requires publicHost');
  }

  const gatewayScheme = options.gatewayScheme ?? 'https';
  const gatewayUrl = `${gatewayScheme}://${options.publicHost}:${options.gatewayPort}`;

  async function listDevices() {
    const state = await options.store.load();
    const connections = options.getConnectionSnapshot?.() ?? new Map();
    return {
      service: HUB_SERVICE_ID,
      schemaVersion: HUB_SCHEMA_VERSION,
      gatewayUrl,
      devices: Object.values(state.devices)
        .map((device) => summarizeDevice(device, connections))
        .sort((a, b) => String(b.lastSeenAt).localeCompare(String(a.lastSeenAt))),
      pendingPairings: pendingPairings(state),
    };
  }

  const server = http.createServer(async (req, res) => {
    try {
      if (!isAllowedHubHost(req)) {
        sendJson(res, 403, { error: 'forbidden hub host' });
        return;
      }
      const url = new URL(req.url, `http://${listenHost}`);
      if (req.method === 'GET' && url.pathname === '/') {
        sendText(res, 200, renderHubHtml(), 'text/html; charset=utf-8');
        return;
      }
      if (req.method === 'GET' && url.pathname === '/api/devices') {
        sendJson(res, 200, await listDevices());
        return;
      }
      if (req.method === 'POST' && url.pathname === '/api/pair') {
        requireHubMutationHeader(req);
        const body = await readJsonBody(req);
        const label = normalizeLabel(body.label);
        const issued = await createPairingNonce(options.store, { ttlMs: 5 * 60_000, label });
        const pairUrl = `${gatewayUrl}/__mobile/pair/${issued.nonce}`;
        const deepLink = `stmobile://pair?url=${encodeURIComponent(pairUrl)}`;
        const qrDataUrl = await QRCode.toDataURL(deepLink, { errorCorrectionLevel: 'M', margin: 2, width: 360 });
        sendJson(res, 200, { label, pairUrl, deepLink, qrDataUrl, expiresAt: issued.expiresAt });
        return;
      }
      if (req.method === 'POST' && url.pathname === '/api/revoke') {
        requireHubMutationHeader(req);
        const body = await readJsonBody(req);
        const deviceId = String(body.deviceId ?? '').trim();
        if (!deviceId) {
          sendJson(res, 400, { error: 'deviceId is required' });
          return;
        }
        const revoked = await revokeDevice(options.store, deviceId);
        if (!revoked) {
          sendJson(res, 404, { error: 'device not found' });
          return;
        }
        await options.closeRevokedSockets?.();
        sendJson(res, 200, { revoked: true, deviceId });
        return;
      }
      sendJson(res, 404, { error: 'not found' });
    } catch (error) {
      sendJson(res, error.statusCode ?? 500, { error: error.message });
    }
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.listenPort ?? 38444, listenHost, () => {
      server.off('error', reject);
      resolve();
    });
  });

  const address = server.address();
  const host = address.address === '::1' ? '[::1]' : address.address;
  return {
    server,
    url: `http://${host}:${address.port}/`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
