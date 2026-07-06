import crypto from 'node:crypto';

export const COOKIE_NAME = 'stmg';
const DEFAULT_LAST_SEEN_TOUCH_INTERVAL_MS = 30_000;
const lastSeenTouchReservations = new Map();

function toDate(value) {
  return value instanceof Date ? value : new Date(value ?? Date.now());
}

function iso(value) {
  return toDate(value).toISOString();
}

function randomBase64Url(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function shouldTouchLastSeen(device, now, minIntervalMs) {
  const previous = Date.parse(device?.lastSeenAt ?? '');
  return !Number.isFinite(previous) || now.getTime() - previous >= minIntervalMs;
}

function reserveLastSeenTouch(tokenHash, now, minIntervalMs) {
  const previous = lastSeenTouchReservations.get(tokenHash) ?? 0;
  if (now.getTime() - previous < minIntervalMs) {
    return false;
  }
  lastSeenTouchReservations.set(tokenHash, now.getTime());
  return true;
}

export function parseCookies(header) {
  const cookies = {};
  for (const part of String(header ?? '').split(';')) {
    const index = part.indexOf('=');
    if (index < 1) {
      continue;
    }
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (key) {
      try {
        cookies[key] = decodeURIComponent(value);
      } catch {
        // Malformed cookie encoding is treated like an absent cookie.
      }
    }
  }
  return cookies;
}

export async function createPairingNonce(store, options = {}) {
  const now = toDate(options.now);
  const ttlMs = Number(options.ttlMs ?? 5 * 60_000);
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new Error('ttlMs must be a positive number');
  }

  const nonce = randomBase64Url(32);
  const nonceHash = sha256(nonce);
  const expiresAt = new Date(now.getTime() + ttlMs);

  await store.update((state) => {
    state.pendingNonces[nonceHash] = {
      nonceHash,
      label: String(options.label ?? 'Android device'),
      createdAt: iso(now),
      expiresAt: iso(expiresAt),
      consumedAt: null,
    };
  });

  return {
    nonce,
    nonceHash,
    expiresAt: iso(expiresAt),
  };
}

export async function consumePairingNonce(store, nonce, options = {}) {
  if (!nonce || typeof nonce !== 'string') {
    return null;
  }

  const now = toDate(options.now);
  const nonceHash = sha256(nonce);
  let createdSession = null;

  await store.update((state) => {
    const pending = state.pendingNonces[nonceHash];
    if (!pending || pending.consumedAt || new Date(pending.expiresAt).getTime() < now.getTime()) {
      return;
    }

    const deviceId = randomBase64Url(12);
    const token = randomBase64Url(32);
    const tokenHash = sha256(token);

    pending.consumedAt = iso(now);
    state.devices[deviceId] = {
      deviceId,
      tokenHash,
      label: pending.label,
      userAgent: String(options.userAgent ?? ''),
      remoteAddress: String(options.remoteAddress ?? ''),
      createdAt: iso(now),
      lastSeenAt: iso(now),
      revokedAt: null,
    };

    createdSession = {
      deviceId,
      token,
      tokenHash,
    };
  });

  return createdSession;
}

export async function validateSessionToken(store, token, options = {}) {
  if (!token || typeof token !== 'string') {
    return null;
  }

  const tokenHash = sha256(token);
  const now = toDate(options.now);
  const minTouchIntervalMs = Number(options.minTouchIntervalMs ?? DEFAULT_LAST_SEEN_TOUCH_INTERVAL_MS);

  const currentState = await store.load();
  const validDevice = Object.values(currentState.devices).find((device) => device.tokenHash === tokenHash && !device.revokedAt);
  if (!validDevice) {
    return null;
  }

  if (
    options.touch !== false
    && shouldTouchLastSeen(validDevice, now, minTouchIntervalMs)
    && reserveLastSeenTouch(tokenHash, now, minTouchIntervalMs)
  ) {
    const touch = store.update((state) => {
      for (const device of Object.values(state.devices)) {
        if (device.tokenHash === tokenHash && !device.revokedAt && shouldTouchLastSeen(device, now, minTouchIntervalMs)) {
          device.lastSeenAt = iso(now);
          return;
        }
      }
    }).catch((error) => {
      if (typeof options.onTouchError === 'function') {
        options.onTouchError(error);
      }
    });
    if (options.touch === 'blocking') {
      await touch;
    }
  }

  return { ...validDevice };
}

export async function revokeDevice(store, deviceId, options = {}) {
  const now = toDate(options.now);
  let revoked = null;
  await store.update((state) => {
    const device = state.devices[deviceId];
    if (!device) {
      return;
    }
    device.revokedAt = device.revokedAt ?? iso(now);
    revoked = { ...device };
  });
  return revoked;
}

export async function validateRequestSession(store, request, cookieName = COOKIE_NAME, options = {}) {
  if (cookieName && typeof cookieName === 'object') {
    options = cookieName;
    cookieName = COOKIE_NAME;
  }
  const token = parseCookies(request.headers.cookie)[cookieName];
  return validateSessionToken(store, token, options);
}
