import { mkdir, readFile, readdir, rename, rm, stat, unlink, writeFile } from 'node:fs/promises';
import crypto from 'node:crypto';
import path from 'node:path';

const LOCK_TIMEOUT_MS = 30_000;
const LOCK_STALE_MS = 60_000;

function freshState() {
  const now = new Date().toISOString();
  return {
    version: 1,
    createdAt: now,
    updatedAt: now,
    pendingNonces: {},
    devices: {},
    certs: {},
  };
}

function normalizeState(value) {
  const state = value && typeof value === 'object' ? value : {};
  return {
    ...freshState(),
    ...state,
    pendingNonces: state.pendingNonces && typeof state.pendingNonces === 'object' ? state.pendingNonces : {},
    devices: state.devices && typeof state.devices === 'object' ? state.devices : {},
    certs: state.certs && typeof state.certs === 'object' ? state.certs : {},
  };
}

export function createStateStore({ stateDir, lockTimeoutMs = LOCK_TIMEOUT_MS, lockStaleMs = LOCK_STALE_MS }) {
  if (!stateDir) {
    throw new Error('stateDir is required');
  }

  const stateFile = path.join(stateDir, 'state.json');
  const lockDir = path.join(stateDir, 'state.json.lock');
  let updateQueue = Promise.resolve();

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async function renameWithRetry(source, destination) {
    const transientCodes = new Set(['EPERM', 'EACCES', 'EBUSY']);
    for (let attempt = 0; attempt < 12; attempt += 1) {
      try {
        await rename(source, destination);
        return;
      } catch (error) {
        if (!transientCodes.has(error.code) || attempt === 11) {
          throw error;
        }
        await sleep(Math.min(500, 20 * (attempt + 1)));
      }
    }
  }

  function processIsAlive(pid) {
    if (!Number.isInteger(pid) || pid <= 0) {
      return false;
    }
    try {
      process.kill(pid, 0);
      return true;
    } catch (error) {
      return error.code === 'EPERM';
    }
  }

  async function ensureDir() {
    await mkdir(stateDir, { recursive: true });
  }

  async function readStateFile() {
    await ensureDir();
    try {
      return normalizeState(JSON.parse(await readFile(stateFile, 'utf8')));
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
      return freshState();
    }
  }

  async function removeStaleTempFiles() {
    const stateName = path.basename(stateFile);
    let entries = [];
    try {
      entries = await readdir(stateDir, { withFileTypes: true });
    } catch (error) {
      if (error.code === 'ENOENT') {
        return;
      }
      throw error;
    }

    await Promise.all(entries
      .filter((entry) => entry.isFile() && entry.name.startsWith(`${stateName}.`) && entry.name.endsWith('.tmp'))
      .map(async (entry) => {
        try {
          await unlink(path.join(stateDir, entry.name));
        } catch (error) {
          if (error.code !== 'ENOENT') {
            throw error;
          }
        }
      }));
  }

  async function saveUnlocked(state) {
    await ensureDir();
    const next = normalizeState(state);
    next.updatedAt = new Date().toISOString();
    const tmpFile = `${stateFile}.${process.pid}.${Date.now()}.${crypto.randomUUID()}.tmp`;
    await writeFile(tmpFile, `${JSON.stringify(next, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    await renameWithRetry(tmpFile, stateFile);
    await removeStaleTempFiles();
    return next;
  }

  async function readLockMetadata() {
    try {
      return JSON.parse(await readFile(path.join(lockDir, 'owner.json'), 'utf8'));
    } catch {
      return null;
    }
  }

  async function lockDirectoryAgeMs() {
    try {
      const info = await stat(lockDir);
      return Date.now() - info.mtimeMs;
    } catch (error) {
      if (error.code === 'ENOENT') {
        return 0;
      }
      throw error;
    }
  }

  async function acquireLock() {
    await ensureDir();
    const startedAt = Date.now();
    let attempts = 0;

    while (true) {
      try {
        await mkdir(lockDir, { mode: 0o700 });
        try {
          await writeFile(path.join(lockDir, 'owner.json'), `${JSON.stringify({
            pid: process.pid,
            createdAt: new Date().toISOString(),
            stateFile,
          }, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
        } catch (error) {
          await rm(lockDir, { recursive: true, force: true });
          if (error.code === 'ENOENT') {
            continue;
          }
          throw error;
        }
        return async () => {
          await rm(lockDir, { recursive: true, force: true });
        };
      } catch (error) {
        if (error.code !== 'EEXIST') {
          throw error;
        }
      }

      const metadata = await readLockMetadata();
      const dirAgeMs = await lockDirectoryAgeMs();
      const metadataCreatedAtMs = Date.parse(metadata?.createdAt ?? '');
      const lockAgeMs = Number.isFinite(metadataCreatedAtMs) ? Date.now() - metadataCreatedAtMs : dirAgeMs;
      const ownerAlive = metadata?.pid ? processIsAlive(Number(metadata.pid)) : false;
      if (lockAgeMs > lockStaleMs && !ownerAlive) {
        await rm(lockDir, { recursive: true, force: true });
        continue;
      }

      if (Date.now() - startedAt > lockTimeoutMs) {
        throw new Error(`Timed out waiting for state lock: ${lockDir}`);
      }

      attempts += 1;
      await sleep(Math.min(250, 20 + attempts * 10));
    }
  }

  async function withLock(fn) {
    const release = await acquireLock();
    try {
      return await fn();
    } finally {
      await release();
    }
  }

  async function load() {
    return readStateFile();
  }

  async function save(state) {
    return withLock(() => saveUnlocked(state));
  }

  async function update(mutator) {
    const run = async () => {
      return withLock(async () => {
        const state = await readStateFile();
        const before = JSON.stringify(normalizeState(state));
        const result = await mutator(state);
        const after = JSON.stringify(normalizeState(state));
        if (after !== before) {
          await saveUnlocked(state);
        }
        return result;
      });
    };
    const next = updateQueue.then(run, run);
    updateQueue = next.catch(() => {});
    return next;
  }

  return {
    stateDir,
    stateFile,
    lockDir,
    load,
    save,
    update,
  };
}
