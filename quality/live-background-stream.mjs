import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import http from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createPairingNonce } from '../gateway/src/auth.js';
import { ensureCertificates } from '../gateway/src/certs.js';
import { createGatewayServer } from '../gateway/src/server.js';
import { createStateStore } from '../gateway/src/state.js';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const adbPath = path.join(projectRoot, '.tools', 'android-sdk', 'platform-tools', 'adb.exe');
const gatewayPort = 38443;
const gatewayHost = '192.168.1.215';
const packageName = 'app.sillytavern.securemobile';
const activityName = `${packageName}/.MainActivity`;

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

function adb(...args) {
  return execFileSync(adbPath, args, { encoding: 'utf8', timeout: 30_000 }).trim();
}

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

async function waitFor(predicate, timeoutMs, message) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = predicate();
    if (value) {
      return value;
    }
    await delay(100);
  }
  throw new Error(message);
}

const chunks = Array.from({ length: 120 }, (_, index) => (
  Buffer.from(`data: {"index":${index},"token":"αβ${index}"}\n\n`, 'utf8')
));
chunks.push(Buffer.from('data: [DONE]\n\n', 'utf8'));
const expected = Buffer.concat(chunks);

let generationHits = 0;
let resolveResult;
let rejectResult;
const resultPromise = new Promise((resolve, reject) => {
  resolveResult = resolve;
  rejectResult = reject;
});

const page = `<!doctype html><html><head><meta charset="utf-8"><title>Relay live test</title></head><body>
<p id="status">waiting</p><script>
(() => {
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  async function report(payload) {
    while (true) {
      try {
        const response = await fetch('/__test/result', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(payload),
          cache: 'no-store',
        });
        if (response.ok) return;
      } catch {}
      await sleep(250);
    }
  }
  (async () => {
    await sleep(750);
    document.querySelector('#status').textContent = 'streaming';
    try {
      const response = await fetch('/api/backends/chat-completions/generate', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ stream: true, prompt: 'live background relay test' }),
      });
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const bytes = new Uint8Array(await response.arrayBuffer());
      let binary = '';
      for (const byte of bytes) binary += String.fromCharCode(byte);
      await report({ ok: true, base64: btoa(binary), visibility: document.visibilityState });
      document.querySelector('#status').textContent = 'complete';
    } catch (error) {
      await report({ ok: false, error: String(error && error.stack || error), visibility: document.visibilityState });
    }
  })();
})();
</script></body></html>`;

const upstream = http.createServer((req, res) => {
  if (req.method === 'GET' && new URL(req.url, 'http://localhost').pathname === '/') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(page);
    return;
  }
  if (req.method === 'POST' && req.url === '/api/backends/chat-completions/generate') {
    generationHits += 1;
    req.resume();
    req.once('end', () => {
      res.writeHead(200, {
        'content-type': 'text/event-stream; charset=utf-8',
        'cache-control': 'no-cache',
      });
      let index = 0;
      const timer = setInterval(() => {
        if (index >= chunks.length) {
          clearInterval(timer);
          res.end();
          return;
        }
        res.write(chunks[index]);
        index += 1;
      }, 100);
      res.once('close', () => clearInterval(timer));
    });
    return;
  }
  if (req.method === 'POST' && req.url === '/__test/result') {
    const body = [];
    req.on('data', (chunk) => body.push(chunk));
    req.on('end', () => {
      try {
        resolveResult(JSON.parse(Buffer.concat(body).toString('utf8')));
        res.writeHead(204);
        res.end();
      } catch (error) {
        rejectResult(error);
        res.writeHead(400);
        res.end();
      }
    });
    return;
  }
  res.writeHead(404);
  res.end();
});

let gateway;
let stateDir;
try {
  const upstreamAddress = await listen(upstream);
  stateDir = await mkdtemp(path.join(tmpdir(), 'st-mobile-live-background-'));
  const store = createStateStore({ stateDir });
  const certificates = await ensureCertificates({
    certDir: path.join(projectRoot, 'state', 'certs'),
    hostnames: ['localhost'],
  });
  gateway = await createGatewayServer({
    target: `http://127.0.0.1:${upstreamAddress.port}`,
    store,
    certificates,
    listenHost: '0.0.0.0',
    listenPort: gatewayPort,
  });
  const issued = await createPairingNonce(store, { ttlMs: 60_000, label: 'Headless background test' });
  const pairingUrl = `https://${gatewayHost}:${gatewayPort}/__mobile/pair/${issued.nonce}`;
  const deepLink = `stmobile://pair?url=${encodeURIComponent(pairingUrl)}`;

  adb('shell', 'pm', 'clear', packageName);
  adb('shell', 'am', 'start', '-W', '-a', 'android.intent.action.VIEW', '-d', deepLink);
  await waitFor(() => generationHits === 1, 15_000, 'The Android WebView never started the relayed generation');

  adb('shell', 'input', 'keyevent', 'KEYCODE_HOME');
  const backgroundedAt = Date.now();
  await delay(2_000);
  gateway.server.closeAllConnections();
  await delay(15_000);
  const backgroundDurationMs = Date.now() - backgroundedAt;

  adb('shell', 'am', 'start', '-W', '-n', activityName);
  const result = await Promise.race([
    resultPromise,
    delay(30_000).then(() => { throw new Error('The WebView did not finish after returning from the background'); }),
  ]);
  assert.equal(result.ok, true, result.error ?? 'WebView stream failed');
  assert.deepEqual(Buffer.from(result.base64, 'base64'), expected);
  assert.equal(generationHits, 1, 'Reconnect started a duplicate upstream generation');
  assert.ok(backgroundDurationMs >= 15_000, `App was backgrounded for only ${backgroundDurationMs} ms`);

  const packageDump = adb('shell', 'dumpsys', 'package', packageName);
  assert.doesNotMatch(packageDump, /supportsPictureInPicture=true/);
  console.log(JSON.stringify({
    ok: true,
    version: packageDump.match(/versionName=([^\s]+)/)?.[1] ?? null,
    backgroundDurationMs,
    forcedMobileConnectionDrop: true,
    upstreamGenerationHits: generationHits,
    exactBytes: expected.length,
    completionVisibility: result.visibility,
  }, null, 2));
} finally {
  if (gateway) await gateway.close();
  await close(upstream).catch(() => {});
  if (stateDir) await rm(stateDir, { recursive: true, force: true });
}
