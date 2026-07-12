import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { mkdir, mkdtemp, readdir, readFile, rename, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';

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

test('stale ownerless legacy lock is safely reclaimed and released by the Windows broker', {
  skip: process.platform !== 'win32',
}, async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'st-mobile-stale-ownerless-lock-'));
  try {
    const store = createStateStore({ stateDir: dir, lockTimeoutMs: 1_000, lockStaleMs: 20 });
    await mkdir(store.lockDir);
    await sleep(60);

    await store.update((state) => {
      state.certs.recovered = true;
    });

    assert.equal((await store.load()).certs.recovered, true);
    await assert.rejects(stat(store.lockDir), { code: 'ENOENT' });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('stale legacy owner generation cannot be replaced after the Windows broker pins it', {
  skip: process.platform !== 'win32',
}, async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'st-mobile-stale-owner-generation-'));
  const lockDir = path.join(dir, 'state.json.lock');
  const ownerFile = path.join(lockDir, 'owner.json');
  const displacedOwner = path.join(lockDir, 'displaced-owner.json');
  const replacementOwner = path.join(dir, 'attacker-owner.json');
  try {
    await mkdir(lockDir);
    await writeFile(ownerFile, JSON.stringify({
      pid: 999_999_999,
      ownerToken: 'stale-generation',
      createdAt: '2000-01-01T00:00:00.000Z',
      stateFile: path.join(dir, 'state.json'),
      lockProtocol: 'windows-mutex-plus-legacy-directory-v1',
      padding: 'x'.repeat(7 * 1024 * 1024),
    }));
    await writeFile(replacementOwner, 'attacker replacement must survive\n');

    const reclaimer = spawnModule(`
      import { createStateStore } from ${JSON.stringify(stateModuleUrl)};
      const store = createStateStore({ stateDir: process.env.ST_STATE_DIR, lockTimeoutMs: 5000, lockStaleMs: 20 });
      await store.update((state) => { state.certs.reclaimedPinnedGeneration = true; });
    `, { ST_STATE_DIR: dir });
    const reclaimerDone = waitForChild(reclaimer);
    void reclaimerDone.catch(() => {});

    let observedPinnedGeneration = false;
    const deadline = Date.now() + 5_000;
    while (Date.now() < deadline && reclaimer.exitCode === null) {
      try {
        await rename(ownerFile, displacedOwner);
        await rename(displacedOwner, ownerFile);
      } catch (error) {
        if (['EPERM', 'EACCES', 'EBUSY'].includes(error.code)) {
          observedPinnedGeneration = true;
          break;
        }
        if (error.code !== 'ENOENT') throw error;
      }
      await sleep(1);
    }

    assert.equal(observedPinnedGeneration, true);
    await assert.rejects(
      rm(ownerFile, { force: false }),
      (error) => ['EPERM', 'EACCES', 'EBUSY'].includes(error.code),
    );
    await reclaimerDone;

    assert.equal(await readFile(replacementOwner, 'utf8'), 'attacker replacement must survive\n');
    assert.equal((await createStateStore({ stateDir: dir }).load()).certs.reclaimedPinnedGeneration, true);
    await assert.rejects(stat(lockDir), { code: 'ENOENT' });
    await assert.rejects(stat(displacedOwner), { code: 'ENOENT' });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('reparse-point legacy lock is refused without touching its target', {
  skip: process.platform !== 'win32',
}, async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'st-mobile-lock-reparse-'));
  const stateDir = path.join(root, 'state');
  const externalTarget = path.join(root, 'external-target');
  const lockJunction = path.join(stateDir, 'state.json.lock');
  const ownerFile = path.join(externalTarget, 'owner.json');
  try {
    await mkdir(stateDir);
    await mkdir(externalTarget);
    const ownerText = JSON.stringify({
      pid: 999_999_999,
      createdAt: '2000-01-01T00:00:00.000Z',
      stateFile: path.join(stateDir, 'state.json'),
    });
    await writeFile(ownerFile, ownerText);
    await symlink(externalTarget, lockJunction, 'junction');

    const store = createStateStore({ stateDir, lockTimeoutMs: 500, lockStaleMs: 20 });
    await assert.rejects(
      store.update((state) => { state.certs.mustNotWrite = true; }),
      /non-ordinary|reparse-point/,
    );

    await stat(lockJunction);
    await stat(externalTarget);
    assert.equal(await readFile(ownerFile, 'utf8'), ownerText);
    assert.deepEqual((await store.load()).certs, {});
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('simultaneous stale legacy observers cannot compromise a new Windows lock owner', {
  skip: process.platform !== 'win32',
}, async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'st-mobile-stale-mutex-race-'));
  try {
    const store = createStateStore({ stateDir: dir, lockTimeoutMs: 5_000, lockStaleMs: 20 });
    await mkdir(store.lockDir);
    await sleep(60);

    const slowOwner = spawnModule(`
      import { createStateStore } from ${JSON.stringify(stateModuleUrl)};
      const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
      const store = createStateStore({ stateDir: process.env.ST_STATE_DIR, lockTimeoutMs: 5000, lockStaleMs: 20 });
      await store.update(async (state) => {
        state.certs.slowOwner = true;
        console.log('mutex-held');
        await sleep(600);
      });
    `, { ST_STATE_DIR: dir });
    await waitForStdout(slowOwner, 'mutex-held');

    const waitingOwner = spawnModule(`
      import { createStateStore } from ${JSON.stringify(stateModuleUrl)};
      const store = createStateStore({ stateDir: process.env.ST_STATE_DIR, lockTimeoutMs: 5000, lockStaleMs: 20 });
      await store.update((state) => { state.certs.waitingOwner = true; });
    `, { ST_STATE_DIR: dir });

    await Promise.all([waitForChild(slowOwner), waitForChild(waitingOwner)]);
    const state = await store.load();
    assert.equal(state.certs.slowOwner, true);
    assert.equal(state.certs.waitingOwner, true);
    await assert.rejects(stat(store.lockDir), { code: 'ENOENT' });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('normal Windows broker release removes only its pinned owner and preserves foreign lock children', {
  skip: process.platform !== 'win32',
}, async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'st-mobile-lock-foreign-child-'));
  const lockDir = path.join(dir, 'state.json.lock');
  const ownerFile = path.join(lockDir, 'owner.json');
  const movedOwner = path.join(lockDir, 'moved-owner.json');
  const foreignFile = path.join(lockDir, 'foreign.txt');
  try {
    const owner = spawnModule(`
      import { createStateStore } from ${JSON.stringify(stateModuleUrl)};
      const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
      const store = createStateStore({ stateDir: process.env.ST_STATE_DIR, lockTimeoutMs: 5000 });
      try {
        await store.update(async (state) => {
          state.certs.mustNotCommit = true;
          console.log('mutex-held');
          await sleep(700);
        });
        process.exitCode = 2;
      } catch {
        console.log('release-rejected');
      }
    `, { ST_STATE_DIR: dir });
    await waitForStdout(owner, 'mutex-held');

    await assert.rejects(
      rename(ownerFile, movedOwner),
      (error) => ['EPERM', 'EACCES', 'EBUSY'].includes(error.code),
    );
    await writeFile(foreignFile, 'foreign-child-must-survive\n');

    await waitForStdout(owner, 'release-rejected');
    await waitForChild(owner);
    assert.equal(await readFile(foreignFile, 'utf8'), 'foreign-child-must-survive\n');
    await stat(lockDir);
    await assert.rejects(stat(ownerFile), { code: 'ENOENT' });
    await assert.rejects(stat(movedOwner), { code: 'ENOENT' });
    assert.equal((await createStateStore({ stateDir: dir }).load()).certs.mustNotCommit, undefined);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('late foreign lock child is restored to the canonical generation after exact retirement', {
  skip: process.platform !== 'win32',
  timeout: 20_000,
}, async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'st-mobile-lock-late-child-'));
  const dir = path.join(root, 'state');
  const harnessPath = path.join(root, 'state-retirement-harness.mjs');
  const lockDir = path.join(dir, 'state.json.lock');
  try {
    await mkdir(dir);
    const productionSource = await readFile(new URL('../src/state.js', import.meta.url), 'utf8');
    const anchor = '  # TEST-HARNESS-AFTER-LEGACY-RETIREMENT';
    assert.equal(productionSource.split(anchor).length - 1, 1);
    await writeFile(
      harnessPath,
      productionSource.replace(anchor, '  Start-Sleep -Milliseconds 500\n' + anchor),
    );
    const harnessUrl = pathToFileURL(harnessPath).href;
    const owner = spawnModule(`
      import { createStateStore } from ${JSON.stringify(harnessUrl)};
      const store = createStateStore({ stateDir: process.env.ST_STATE_DIR, lockTimeoutMs: 5000 });
      await store.update((state) => {
        state.certs.lateForeignChildCommit = true;
        console.log('mutator-finished');
      });
    `, { ST_STATE_DIR: dir });
    await waitForStdout(owner, 'mutator-finished');

    let retiredPath = null;
    const deadline = Date.now() + 5_000;
    while (Date.now() < deadline && retiredPath === null) {
      const retiredName = (await readdir(dir))
        .find((name) => name.startsWith('state.json.lock.retired-'));
      if (retiredName) retiredPath = path.join(dir, retiredName);
      else await sleep(5);
    }
    assert.ok(retiredPath, 'copied harness did not expose the exact post-retirement test window');
    await writeFile(path.join(retiredPath, 'late-foreign.txt'), 'late foreign child must survive\n');
    await waitForChild(owner);

    assert.equal(
      await readFile(path.join(lockDir, 'late-foreign.txt'), 'utf8'),
      'late foreign child must survive\n',
    );
    assert.equal((await createStateStore({ stateDir: dir }).load()).certs.lateForeignChildCommit, true);
    assert.deepEqual(
      (await readdir(dir)).filter((name) => name.startsWith('state.json.lock.retired-')),
      [],
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('blocked late-child restore preserves and reports the exact retired generation', {
  skip: process.platform !== 'win32',
  timeout: 20_000,
}, async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'st-mobile-lock-late-child-blocked-'));
  const dir = path.join(root, 'state');
  const harnessPath = path.join(root, 'state-retirement-harness.mjs');
  const lockDir = path.join(dir, 'state.json.lock');
  try {
    await mkdir(dir);
    const productionSource = await readFile(new URL('../src/state.js', import.meta.url), 'utf8');
    const anchor = '  # TEST-HARNESS-AFTER-LEGACY-RETIREMENT';
    assert.equal(productionSource.split(anchor).length - 1, 1);
    await writeFile(
      harnessPath,
      productionSource.replace(anchor, '  Start-Sleep -Milliseconds 500\n' + anchor),
    );
    const harnessUrl = pathToFileURL(harnessPath).href;
    const owner = spawnModule(`
      import { createStateStore } from ${JSON.stringify(harnessUrl)};
      const store = createStateStore({ stateDir: process.env.ST_STATE_DIR, lockTimeoutMs: 5000 });
      await store.update((state) => {
        state.certs.blockedRestoreCommit = true;
        console.log('mutator-finished');
      });
    `, { ST_STATE_DIR: dir });
    let stderr = '';
    owner.stderr.setEncoding('utf8');
    owner.stderr.on('data', (chunk) => { stderr += chunk; });
    await waitForStdout(owner, 'mutator-finished');

    let retiredPath = null;
    const deadline = Date.now() + 5_000;
    while (Date.now() < deadline && retiredPath === null) {
      const retiredName = (await readdir(dir))
        .find((name) => name.startsWith('state.json.lock.retired-'));
      if (retiredName) retiredPath = path.join(dir, retiredName);
      else await sleep(5);
    }
    assert.ok(retiredPath, 'copied harness did not expose the blocked-restore test window');
    await mkdir(lockDir);
    await writeFile(path.join(retiredPath, 'late-foreign.txt'), 'preserve retired generation\n');
    await waitForChild(owner);

    assert.equal(await readFile(path.join(retiredPath, 'late-foreign.txt'), 'utf8'), 'preserve retired generation\n');
    await stat(lockDir);
    assert.match(stderr, /POST_COMMIT_LOCK_CLEANUP_PRESERVED/);
    assert.match(stderr, /changed generation is preserved/);
    assert.ok(stderr.includes(retiredPath), `exact retirement path missing from blocker: ${stderr}`);
    assert.match(stderr, /Canonical restore blocker/);
    assert.equal((await createStateStore({ stateDir: dir }).load()).certs.blockedRestoreCommit, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('live Windows lock-directory generation cannot be swapped before handle-based release', {
  skip: process.platform !== 'win32',
}, async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'st-mobile-lock-generation-'));
  const lockDir = path.join(dir, 'state.json.lock');
  const displacedLockDir = path.join(dir, 'displaced-state.json.lock');
  try {
    const owner = spawnModule(`
      import { createStateStore } from ${JSON.stringify(stateModuleUrl)};
      const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
      const store = createStateStore({ stateDir: process.env.ST_STATE_DIR, lockTimeoutMs: 5000 });
      await store.update(async () => {
        console.log('mutex-held');
        await sleep(700);
      });
    `, { ST_STATE_DIR: dir });
    await waitForStdout(owner, 'mutex-held');

    await assert.rejects(
      rename(lockDir, displacedLockDir),
      (error) => ['EPERM', 'EACCES', 'EBUSY'].includes(error.code),
    );

    await waitForChild(owner);
    await assert.rejects(stat(lockDir), { code: 'ENOENT' });
    await assert.rejects(stat(displacedLockDir), { code: 'ENOENT' });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('pre-mutex legacy writer is serialized by the broker legacy-directory claim', {
  skip: process.platform !== 'win32',
}, async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'st-mobile-legacy-coexistence-'));
  try {
    const currentWriter = spawnModule(`
      import { createStateStore } from ${JSON.stringify(stateModuleUrl)};
      const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
      const store = createStateStore({ stateDir: process.env.ST_STATE_DIR, lockTimeoutMs: 5000, lockStaleMs: 20 });
      await store.update(async (state) => {
        state.certs.currentWriter = true;
        console.log('current-entered');
        await sleep(600);
      });
    `, { ST_STATE_DIR: dir });
    await waitForStdout(currentWriter, 'current-entered');

    const legacyWriter = spawnModule(`
      import { mkdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
      import path from 'node:path';
      const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
      const stateFile = path.join(process.env.ST_STATE_DIR, 'state.json');
      const lockDir = path.join(process.env.ST_STATE_DIR, 'state.json.lock');
      while (true) {
        try {
          await mkdir(lockDir);
          await writeFile(path.join(lockDir, 'owner.json'), JSON.stringify({
            pid: process.pid,
            createdAt: new Date().toISOString(),
            stateFile,
          }));
          break;
        } catch (error) {
          if (error.code !== 'EEXIST') throw error;
        }
        let metadata = null;
        try { metadata = JSON.parse(await readFile(path.join(lockDir, 'owner.json'), 'utf8')); } catch {}
        let age = 0;
        try {
          const info = await stat(lockDir);
          const created = Date.parse(metadata?.createdAt ?? '');
          age = Date.now() - (Number.isFinite(created) ? created : info.mtimeMs);
        } catch (error) {
          if (error.code === 'ENOENT') continue;
          throw error;
        }
        let alive = false;
        try { process.kill(Number(metadata?.pid), 0); alive = true; } catch (error) { alive = error.code === 'EPERM'; }
        if (age > 20 && !alive) {
          await rm(lockDir, { recursive: true, force: true });
          continue;
        }
        await sleep(20);
      }
      try {
        let state;
        try { state = JSON.parse(await readFile(stateFile, 'utf8')); }
        catch (error) { if (error.code !== 'ENOENT') throw error; state = { certs: {} }; }
        state.certs ??= {};
        state.certs.legacyWriter = true;
        const temporary = stateFile + '.' + process.pid + '.legacy.tmp';
        await writeFile(temporary, JSON.stringify(state));
        await rename(temporary, stateFile);
      } finally {
        await rm(lockDir, { recursive: true, force: true });
      }
    `, { ST_STATE_DIR: dir });

    await Promise.all([waitForChild(currentWriter), waitForChild(legacyWriter)]);
    const state = await createStateStore({ stateDir: dir }).load();
    assert.equal(state.certs.currentWriter, true);
    assert.equal(state.certs.legacyWriter, true);
    assert.deepEqual(
      (await readdir(dir)).filter((name) => name.startsWith('state.json.lock.retired-')),
      [],
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('parent process death releases the Windows mutex for the next owner', {
  skip: process.platform !== 'win32',
}, async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'st-mobile-abandoned-mutex-'));
  try {
    const abandonedOwner = spawnModule(`
      import { createStateStore } from ${JSON.stringify(stateModuleUrl)};
      const store = createStateStore({ stateDir: process.env.ST_STATE_DIR, lockTimeoutMs: 5000 });
      await store.update(async (state) => {
        state.certs.abandonedWrite = true;
        console.log('mutex-held');
        await new Promise(() => {});
      });
    `, { ST_STATE_DIR: dir });
    await waitForStdout(abandonedOwner, 'mutex-held');
    abandonedOwner.kill();
    await new Promise((resolve) => abandonedOwner.once('exit', resolve));

    const store = createStateStore({ stateDir: dir, lockTimeoutMs: 3_000 });
    await store.update((state) => {
      state.certs.recoveredAfterParentDeath = true;
    });
    assert.equal((await store.load()).certs.recoveredAfterParentDeath, true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('killing the mutex helper prevents its stale Node mutator from committing', {
  skip: process.platform !== 'win32',
}, async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'st-mobile-killed-helper-'));
  try {
    const slowWriter = spawnModule(`
      import { createStateStore } from ${JSON.stringify(stateModuleUrl)};
      const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
      const store = createStateStore({ stateDir: process.env.ST_STATE_DIR, lockTimeoutMs: 5000 });
      await store.update(async (state) => {
        state.certs.staleWriter = true;
        console.log('mutex-held');
        await sleep(1200);
      });
    `, { ST_STATE_DIR: dir });
    const slowWriterDone = waitForChild(slowWriter);
    void slowWriterDone.catch(() => {});
    await waitForStdout(slowWriter, 'mutex-held');

    const helperInfo = JSON.parse(execFileSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-Command',
      `$p=Get-CimInstance Win32_Process -Filter "ParentProcessId=${slowWriter.pid}" | Where-Object Name -eq 'powershell.exe' | Select-Object -First 1; if(-not $p){throw 'mutex helper missing'}; $g=Get-Process -Id $p.ProcessId; [pscustomobject]@{pid=$p.ProcessId;priority=[string]$g.PriorityClass;window=[int64]$g.MainWindowHandle}|ConvertTo-Json -Compress`,
    ], { encoding: 'utf8', windowsHide: true }));
    assert.equal(helperInfo.priority, 'Idle');
    assert.equal(helperInfo.window, 0);
    process.kill(helperInfo.pid);
    await sleep(150);

    const winningWriter = spawnModule(`
      import { createStateStore } from ${JSON.stringify(stateModuleUrl)};
      const store = createStateStore({ stateDir: process.env.ST_STATE_DIR, lockTimeoutMs: 5000 });
      await store.update((state) => { state.certs.winningWriter = true; });
    `, { ST_STATE_DIR: dir });

    await waitForChild(winningWriter);
    await assert.rejects(slowWriterDone, /mutex helper exited|already finished/);
    const state = await createStateStore({ stateDir: dir }).load();
    assert.equal(state.certs.winningWriter, true);
    assert.equal(state.certs.staleWriter, undefined);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('locked stale temp cleanup cannot turn a durable Windows commit into a reported failure', {
  skip: process.platform !== 'win32',
}, async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'st-mobile-locked-stale-temp-'));
  const lockedTemp = path.join(dir, 'state.json.locked-stale.tmp');
  try {
    const escapedTemp = lockedTemp.replaceAll("'", "''");
    const lockerScript = `
$ErrorActionPreference = 'Stop'
$process = [System.Diagnostics.Process]::GetCurrentProcess()
$process.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle
$stream = [System.IO.File]::Open('${escapedTemp}', [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::Read)
try {
  [Console]::Out.WriteLine('READY')
  [Console]::Out.Flush()
  $null = [Console]::In.ReadLine()
} finally {
  $stream.Dispose()
}`;
    const locker = spawn('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden',
      '-ExecutionPolicy', 'Bypass', '-EncodedCommand', Buffer.from(lockerScript, 'utf16le').toString('base64'),
    ], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    const lockerDone = waitForChild(locker);
    void lockerDone.catch(() => {});
    await waitForStdout(locker, 'READY');

    const store = createStateStore({ stateDir: dir });
    await store.update((state) => { state.certs.committedWithLockedStaleTemp = true; });
    assert.equal((await store.load()).certs.committedWithLockedStaleTemp, true);

    locker.stdin.end('RELEASE\n');
    await lockerDone;
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('junction aliases share one physical Windows mutex domain', {
  skip: process.platform !== 'win32',
}, async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'st-mobile-junction-mutex-'));
  const realDir = path.join(root, 'real-state');
  const aliasDir = path.join(root, 'junction-state');
  try {
    await mkdir(realDir);
    await symlink(realDir, aliasDir, 'junction');
    const slowWriter = spawnModule(`
      import { createStateStore } from ${JSON.stringify(stateModuleUrl)};
      const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
      const store = createStateStore({ stateDir: process.env.ST_STATE_DIR, lockTimeoutMs: 5000 });
      await store.update(async (state) => {
        state.certs.realPathWriter = true;
        console.log('mutex-held');
        await sleep(600);
      });
    `, { ST_STATE_DIR: realDir });
    await waitForStdout(slowWriter, 'mutex-held');

    const aliasWriter = spawnModule(`
      import { createStateStore } from ${JSON.stringify(stateModuleUrl)};
      const store = createStateStore({ stateDir: process.env.ST_STATE_DIR, lockTimeoutMs: 5000 });
      await store.update((state) => { state.certs.aliasPathWriter = true; });
    `, { ST_STATE_DIR: aliasDir });

    await Promise.all([waitForChild(slowWriter), waitForChild(aliasWriter)]);
    const state = await createStateStore({ stateDir: realDir }).load();
    assert.equal(state.certs.realPathWriter, true);
    assert.equal(state.certs.aliasPathWriter, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('junction retargeting cannot move a commit outside its pinned Windows lock domain', {
  skip: process.platform !== 'win32',
}, async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'st-mobile-junction-retarget-'));
  const realA = path.join(root, 'real-a');
  const realB = path.join(root, 'real-b');
  const aliasDir = path.join(root, 'junction-state');
  try {
    await mkdir(realA);
    await mkdir(realB);
    await createStateStore({ stateDir: realA }).save({ certs: { originA: true } });
    await createStateStore({ stateDir: realB }).save({ certs: { originB: true } });
    await symlink(realA, aliasDir, 'junction');

    const slowAliasWriter = spawnModule(`
      import { createStateStore } from ${JSON.stringify(stateModuleUrl)};
      const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
      const store = createStateStore({ stateDir: process.env.ST_STATE_DIR, lockTimeoutMs: 5000 });
      await store.update(async (state) => {
        state.certs.slowA = true;
        console.log('mutex-held');
        await sleep(800);
      });
    `, { ST_STATE_DIR: aliasDir });
    const slowAliasDone = waitForChild(slowAliasWriter);
    void slowAliasDone.catch(() => {});
    await waitForStdout(slowAliasWriter, 'mutex-held');

    await rm(aliasDir, { recursive: true, force: true });
    await symlink(realB, aliasDir, 'junction');

    const realBWriter = spawnModule(`
      import { createStateStore } from ${JSON.stringify(stateModuleUrl)};
      const store = createStateStore({ stateDir: process.env.ST_STATE_DIR, lockTimeoutMs: 5000 });
      await store.update((state) => {
        state.certs.winningB = true;
        state.certs.revokedAt = 'REVOKED';
      });
    `, { ST_STATE_DIR: realB });

    await Promise.all([slowAliasDone, waitForChild(realBWriter)]);
    const stateA = await createStateStore({ stateDir: realA }).load();
    const stateB = await createStateStore({ stateDir: realB }).load();
    assert.equal(stateA.certs.originA, true);
    assert.equal(stateA.certs.slowA, true);
    assert.equal(stateA.certs.originB, undefined);
    assert.equal(stateA.certs.winningB, undefined);
    assert.equal(stateB.certs.originB, true);
    assert.equal(stateB.certs.winningB, true);
    assert.equal(stateB.certs.revokedAt, 'REVOKED');
    assert.equal(stateB.certs.originA, undefined);
    assert.equal(stateB.certs.slowA, undefined);
  } finally {
    await rm(root, { recursive: true, force: true });
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
