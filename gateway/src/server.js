import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { URL } from 'node:url';

import { COOKIE_NAME, consumePairingNonce, parseCookies, validateRequestSession } from './auth.js';
import { ensureCertificates } from './certs.js';
import { createAuthHubServer } from './hub.js';

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

function sendForbidden(resOrSocket) {
  if ('writeHead' in resOrSocket) {
    resOrSocket.writeHead(403, {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
    });
    resOrSocket.end('Forbidden\n');
    return;
  }

  resOrSocket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 10\r\n\r\nForbidden\n');
  resOrSocket.destroy();
}

function setPairingCookie(res, token) {
  res.setHeader('set-cookie', [
    `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Lax`,
  ]);
}

function pairNonceFromUrl(req) {
  const parsed = new URL(req.url, 'http://localhost');
  const match = parsed.pathname.match(/^\/__mobile\/pair\/([A-Za-z0-9_-]+)$/);
  return match ? match[1] : null;
}

function shouldAllowHealth(req) {
  const parsed = new URL(req.url, 'http://localhost');
  return parsed.pathname === '/__mobile/health';
}

function stripGatewayCookie(cookieHeader) {
  const kept = String(cookieHeader ?? '')
    .split(';')
    .map((part) => part.trim())
    .filter(Boolean)
    .filter((part) => !part.startsWith(`${COOKIE_NAME}=`));
  return kept.join('; ');
}

function proxyHeaders(req, { forUpgrade = false } = {}) {
  const headers = {};
  for (const [key, value] of Object.entries(req.headers)) {
    const lower = key.toLowerCase();
    if (!forUpgrade && HOP_BY_HOP_HEADERS.has(lower)) {
      continue;
    }
    if (forUpgrade && ['proxy-authenticate', 'proxy-authorization'].includes(lower)) {
      continue;
    }
    headers[key] = value;
  }

  const strippedCookie = stripGatewayCookie(req.headers.cookie);
  if (strippedCookie) {
    headers.cookie = strippedCookie;
  } else {
    delete headers.cookie;
  }

  if (forUpgrade) {
    headers.connection = 'Upgrade';
    headers.upgrade = req.headers.upgrade ?? 'websocket';
  }

  return headers;
}

function writeHeaderLines(socket, method, url, httpVersion, headers) {
  socket.write(`${method} ${url} HTTP/${httpVersion}\r\n`);
  for (const [key, value] of Object.entries(headers)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        socket.write(`${key}: ${item}\r\n`);
      }
    } else if (value !== undefined) {
      socket.write(`${key}: ${value}\r\n`);
    }
  }
  socket.write('\r\n');
}

function proxyHttp(targetUrl, req, res) {
  const client = targetUrl.protocol === 'https:' ? https : http;
  const upstream = client.request({
    protocol: targetUrl.protocol,
    hostname: targetUrl.hostname,
    port: targetUrl.port || (targetUrl.protocol === 'https:' ? 443 : 80),
    method: req.method,
    path: req.url,
    headers: proxyHeaders(req),
  }, (upstreamRes) => {
    res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.statusMessage, upstreamRes.headers);
    upstreamRes.pipe(res);
  });

  upstream.on('error', (error) => {
    if (!res.headersSent) {
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
    }
    if (!res.destroyed) {
      res.end(`Gateway proxy error: ${error.message}\n`);
    }
  });

  req.pipe(upstream);
}

function proxyUpgrade(targetUrl, req, socket, head) {
  const upstream = net.connect(Number(targetUrl.port || 80), targetUrl.hostname);
  upstream.once('connect', () => {
    writeHeaderLines(upstream, req.method, req.url, req.httpVersion, proxyHeaders(req, { forUpgrade: true }));
    if (head?.length) {
      upstream.write(head);
    }
    upstream.pipe(socket);
    socket.pipe(upstream);
  });
  upstream.once('error', () => {
    if (!socket.destroyed) {
      socket.write('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 12\r\n\r\nBad Gateway\n');
      socket.destroy();
    }
  });
}

export async function createGatewayServer(options) {
  const target = options.target ?? 'http://127.0.0.1:3000';
  const targetUrl = new URL(target);
  const store = options.store;
  if (!store) {
    throw new Error('store is required');
  }

  const activeSockets = new Map();
  const trackedSockets = new WeakSet();

  function logLastSeenTouchError(error) {
    console.warn(`[st-mobile-gateway] lastSeenAt update skipped: ${error.message}`);
  }

  function trackSocket(device, socket) {
    if (!device?.tokenHash || !socket) {
      return;
    }
    if (trackedSockets.has(socket)) {
      return;
    }
    trackedSockets.add(socket);
    if (!activeSockets.has(device.tokenHash)) {
      activeSockets.set(device.tokenHash, new Set());
    }
    activeSockets.get(device.tokenHash).add(socket);
    socket.once('close', () => {
      activeSockets.get(device.tokenHash)?.delete(socket);
      if (activeSockets.get(device.tokenHash)?.size === 0) {
        activeSockets.delete(device.tokenHash);
      }
    });
  }

  function getConnectionSnapshot() {
    const snapshot = new Map();
    for (const [tokenHash, sockets] of activeSockets) {
      snapshot.set(tokenHash, { connectionCount: sockets.size });
    }
    return snapshot;
  }

  async function closeRevokedSockets() {
    const state = await store.load();
    for (const [tokenHash, sockets] of activeSockets) {
      const device = Object.values(state.devices).find((candidate) => candidate.tokenHash === tokenHash);
      if (!device || device.revokedAt) {
        for (const socket of sockets) {
          socket.destroy();
        }
        activeSockets.delete(tokenHash);
      }
    }
  }

  const revokeTimer = setInterval(() => {
    closeRevokedSockets().catch(() => {});
  }, 2_000);
  revokeTimer.unref?.();

  const handler = async (req, res) => {
    try {
      if (shouldAllowHealth(req)) {
        res.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store',
        });
        res.end(JSON.stringify({ ok: true }));
        return;
      }

      const nonce = pairNonceFromUrl(req);
      if (nonce) {
        const session = await consumePairingNonce(store, nonce, {
          userAgent: req.headers['user-agent'] ?? '',
          remoteAddress: req.socket.remoteAddress ?? '',
        });
        if (!session) {
          sendForbidden(res);
          return;
        }
        setPairingCookie(res, session.token);
        res.writeHead(302, {
          location: '/',
          'cache-control': 'no-store',
        });
        res.end();
        return;
      }

      const device = await validateRequestSession(store, req, COOKIE_NAME, { onTouchError: logLastSeenTouchError });
      if (!device) {
        sendForbidden(res);
        return;
      }

      trackSocket(device, req.socket);
      proxyHttp(targetUrl, req, res);
    } catch (error) {
      console.error(`[st-mobile-gateway] ${req.method} ${req.url} failed: ${error.stack || error.message}`);
      if (!res.headersSent) {
        res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
      }
      res.end(`Gateway error: ${error.message}\n`);
    }
  };

  let serverOptions = {};
  if (options.tls !== false) {
    const certificates = options.certificates ?? await ensureCertificates({
      certDir: options.certDir,
      hostnames: [options.publicHost, options.listenHost].filter(Boolean),
    });
    serverOptions = {
      key: certificates.serverKeyPem,
      cert: certificates.serverCertPem,
    };
  }

  const server = options.tls === false
    ? http.createServer(handler)
    : https.createServer(serverOptions, handler);

  server.on('upgrade', async (req, socket, head) => {
    try {
      const cookies = parseCookies(req.headers.cookie);
      const device = await validateRequestSession(store, { headers: { cookie: `${COOKIE_NAME}=${cookies[COOKIE_NAME] ?? ''}` } }, COOKIE_NAME, { onTouchError: logLastSeenTouchError });
      if (!device) {
        sendForbidden(socket);
        return;
      }
      trackSocket(device, socket);
      proxyUpgrade(targetUrl, req, socket, head);
    } catch {
      sendForbidden(socket);
    }
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.listenPort ?? 38443, options.listenHost ?? '0.0.0.0', () => {
      server.off('error', reject);
      resolve();
    });
  });

  const boundAddress = server.address();
  const gatewayPort = typeof boundAddress === 'object' && boundAddress ? boundAddress.port : (options.listenPort ?? 38443);
  let hub = null;
  try {
    hub = options.hubPort === undefined ? null : await createAuthHubServer({
      store,
      publicHost: options.publicHost,
      gatewayPort,
      gatewayScheme: options.tls === false ? 'http' : 'https',
      listenHost: options.hubHost ?? '127.0.0.1',
      listenPort: options.hubPort,
      getConnectionSnapshot,
      closeRevokedSockets,
    });
  } catch (error) {
    clearInterval(revokeTimer);
    await new Promise((resolve) => server.close(resolve));
    throw error;
  }

  return {
    server,
    hub,
    close: async () => {
      clearInterval(revokeTimer);
      if (hub) {
        await hub.close();
      }
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
