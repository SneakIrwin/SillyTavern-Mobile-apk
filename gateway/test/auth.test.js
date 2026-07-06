import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readdir, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createPairingNonce, consumePairingNonce, parseCookies, revokeDevice, validateSessionToken } from '../src/auth.js';
import { createStateStore } from '../src/state.js';

const stateModuleUrl = new URL('../src/state.js', import.meta.url).href;
const authModuleUrl = new URL('../src/auth.js', import.meta.url).href;

async function withStore(fn) {
  const dir = await mkdtemp(path.join(tmpdir(), 'st-mobile-auth-'));
  try {
    const store = createStateStore({ stateDir: dir });
    await fn(store, dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

function waitForChild(child) {
  let stderr = '';
  child.stderr.on('data', (chunk) => {
    stderr += chunk.toString('utf8');
  });
  return new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('exit', (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`child exited ${code}: ${stderr}`));
    });
  });
}

function waitForStdout(child, marker) {
  return new Promise((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => reject(new Error(`timed out waiting for ${marker}`)), 5_000);
    child.stdout.on('data', (chunk) => {
      output += chunk.toString('utf8');
      if (output.includes(marker)) {
        clearTimeout(timer);
        resolve();
      }
    });
    child.on('exit', (code) => {
      if (!output.includes(marker)) {
        clearTimeout(timer);
        reject(new Error(`child exited ${code} before ${marker}`));
      }
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

function spawnModule(script, env) {
  return spawn(process.execPath, ['--input-type=module', '-e', script], {
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

test('pairing nonce is high entropy and can be consumed exactly once', async () => {
  await withStore(async (store) => {
    const now = new Date('2026-07-03T20:00:00.000Z');
    const issued = await createPairingNonce(store, { now, ttlMs: 60_000, label: 'S24 Ultra' });

    assert.match(issued.nonce, /^[A-Za-z0-9_-]{43,}$/);

    const first = await consumePairingNonce(store, issued.nonce, {
      now: new Date('2026-07-03T20:00:30.000Z'),
      userAgent: 'Android WebView',
    });

    assert.match(first.deviceId, /^[A-Za-z0-9_-]{16,}$/);
    assert.match(first.token, /^[A-Za-z0-9_-]{43,}$/);
    assert.equal(first.tokenHash.length, 64);

    const second = await consumePairingNonce(store, issued.nonce, {
      now: new Date('2026-07-03T20:00:31.000Z'),
      userAgent: 'Android WebView',
    });

    assert.equal(second, null);
  });
});

test('expired pairing nonce fails without creating a device session', async () => {
  await withStore(async (store) => {
    const issued = await createPairingNonce(store, {
      now: new Date('2026-07-03T20:00:00.000Z'),
      ttlMs: 1_000,
      label: 'Manual fallback',
    });

    const consumed = await consumePairingNonce(store, issued.nonce, {
      now: new Date('2026-07-03T20:00:02.001Z'),
      userAgent: 'Android WebView',
    });

    assert.equal(consumed, null);
    assert.deepEqual((await store.load()).devices, {});
  });
});

test('durable state stores hashed session tokens only', async () => {
  await withStore(async (store, dir) => {
    const issued = await createPairingNonce(store, {
      now: new Date('2026-07-03T20:00:00.000Z'),
      ttlMs: 60_000,
      label: 'Hash check',
    });
    const session = await consumePairingNonce(store, issued.nonce, {
      now: new Date('2026-07-03T20:00:01.000Z'),
      userAgent: 'Android WebView',
    });

    const rawState = await readFile(path.join(dir, 'state.json'), 'utf8');
    assert.equal(rawState.includes(session.token), false);
    assert.equal(rawState.includes(session.tokenHash), true);

    const valid = await validateSessionToken(store, session.token, { touch: 'blocking' });
    assert.equal(valid.deviceId, session.deviceId);
  });
});

test('concurrent pairing attempts can consume a nonce only once', async () => {
  await withStore(async (store) => {
    const issued = await createPairingNonce(store, {
      now: new Date('2026-07-03T20:00:00.000Z'),
      ttlMs: 60_000,
      label: 'Concurrent pair',
    });

    const attempts = await Promise.all(Array.from({ length: 12 }, (_, index) => (
      consumePairingNonce(store, issued.nonce, {
        now: new Date(`2026-07-03T20:00:${String(index + 1).padStart(2, '0')}.000Z`),
        userAgent: `Android WebView ${index}`,
      })
    )));

    const successes = attempts.filter(Boolean);
    assert.equal(successes.length, 1);
    assert.equal(Object.keys((await store.load()).devices).length, 1);
  });
});

test('concurrent validation cannot erase a revocation', async () => {
  await withStore(async (store) => {
    const issued = await createPairingNonce(store, { ttlMs: 60_000, label: 'Revocation race' });
    const session = await consumePairingNonce(store, issued.nonce, { userAgent: 'Android WebView' });

    await Promise.all([
      ...Array.from({ length: 32 }, () => validateSessionToken(store, session.token, { touch: 'blocking' })),
      revokeDevice(store, session.deviceId),
    ]);

    const state = await store.load();
    assert.match(state.devices[session.deviceId].revokedAt, /^20/);
  });
});

test('cross-process updates preserve both writers', async () => {
  await withStore(async (store, dir) => {
    const slowWriter = spawnModule(`
      import { createStateStore } from ${JSON.stringify(stateModuleUrl)};
      const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
      const store = createStateStore({ stateDir: process.env.ST_STATE_DIR });
      await store.update(async (state) => {
        state.devices.deviceA = {
          deviceId: 'deviceA',
          tokenHash: 'a'.repeat(64),
          label: 'slow writer',
          userAgent: '',
          remoteAddress: '',
          createdAt: '2026-07-03T20:00:00.000Z',
          lastSeenAt: '2026-07-03T20:00:00.000Z',
          revokedAt: null,
        };
        console.log('entered');
        await sleep(600);
      });
    `, { ST_STATE_DIR: dir });

    await waitForStdout(slowWriter, 'entered');

    const nonceWriter = spawnModule(`
      import { createStateStore } from ${JSON.stringify(stateModuleUrl)};
      import { createPairingNonce } from ${JSON.stringify(authModuleUrl)};
      const store = createStateStore({ stateDir: process.env.ST_STATE_DIR });
      await createPairingNonce(store, { ttlMs: 60_000, label: 'parallel nonce' });
    `, { ST_STATE_DIR: dir });

    await Promise.all([waitForChild(slowWriter), waitForChild(nonceWriter)]);

    const state = await store.load();
    assert.equal(Boolean(state.devices.deviceA), true);
    assert.equal(Object.keys(state.pendingNonces).length, 1);
  });
});

test('cross-process revocation cannot be overwritten by a stale writer', async () => {
  await withStore(async (store, dir) => {
    const issued = await createPairingNonce(store, { ttlMs: 60_000, label: 'cross process revoke' });
    const session = await consumePairingNonce(store, issued.nonce, { userAgent: 'node-test' });

    const slowSeenWriter = spawnModule(`
      import { createStateStore } from ${JSON.stringify(stateModuleUrl)};
      const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
      const store = createStateStore({ stateDir: process.env.ST_STATE_DIR });
      await store.update(async (state) => {
        const device = state.devices[process.env.DEVICE_ID];
        if (device && !device.revokedAt) {
          device.lastSeenAt = '2026-07-03T20:01:00.000Z';
          console.log('entered');
          await sleep(600);
        }
      });
    `, { ST_STATE_DIR: dir, DEVICE_ID: session.deviceId });

    await waitForStdout(slowSeenWriter, 'entered');

    const revoker = spawnModule(`
      import { createStateStore } from ${JSON.stringify(stateModuleUrl)};
      import { revokeDevice } from ${JSON.stringify(authModuleUrl)};
      const store = createStateStore({ stateDir: process.env.ST_STATE_DIR });
      await revokeDevice(store, process.env.DEVICE_ID, { now: new Date('2026-07-03T20:02:00.000Z') });
    `, { ST_STATE_DIR: dir, DEVICE_ID: session.deviceId });

    await Promise.all([waitForChild(slowSeenWriter), waitForChild(revoker)]);

    const state = await store.load();
    assert.equal(state.devices[session.deviceId].revokedAt, '2026-07-03T20:02:00.000Z');
  });
});

test('fresh ownerless state lock is not stolen', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'st-mobile-ownerless-lock-'));
  try {
    const store = createStateStore({ stateDir: dir, lockTimeoutMs: 150, lockStaleMs: 5_000 });
    await mkdir(store.lockDir);

    await assert.rejects(
      store.update((state) => {
        state.certs.shouldNotWrite = true;
      }),
      /Timed out waiting for state lock/,
    );

    await stat(store.lockDir);
    assert.deepEqual((await store.load()).certs, {});
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('stale ownerless state lock is reaped', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'st-mobile-stale-ownerless-lock-'));
  try {
    const store = createStateStore({ stateDir: dir, lockTimeoutMs: 1_000, lockStaleMs: 20 });
    await mkdir(store.lockDir);
    await sleep(60);

    await store.update((state) => {
      state.certs.recovered = true;
    });

    assert.equal((await store.load()).certs.recovered, true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('malformed cookies are ignored instead of throwing', () => {
  assert.deepEqual(parseCookies('stmg=%; theme=dark'), { theme: 'dark' });
  assert.deepEqual(parseCookies('stmg=%ZZ'), {});
});

test('invalid session tokens do not rewrite durable state or leave temp files', async () => {
  await withStore(async (store, dir) => {
    const issued = await createPairingNonce(store, { ttlMs: 60_000, label: 'invalid token no-write' });
    await consumePairingNonce(store, issued.nonce, { userAgent: 'node-test' });

    const before = await readFile(path.join(dir, 'state.json'), 'utf8');
    assert.equal(await validateSessionToken(store, 'not-a-real-token'), null);
    const after = await readFile(path.join(dir, 'state.json'), 'utf8');
    const temps = (await readdir(dir)).filter((name) => name.startsWith('state.json.') && name.endsWith('.tmp'));

    assert.equal(after, before);
    assert.deepEqual(temps, []);
  });
});
