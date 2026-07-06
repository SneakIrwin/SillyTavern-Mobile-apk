#!/usr/bin/env node
import { mkdir, copyFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import QRCode from 'qrcode';

import { createPairingNonce, revokeDevice } from './auth.js';
import { ensureCertificates } from './certs.js';
import { resolveConfig } from './config.js';
import { assertGatewayReadyToAdvertise, assertTargetReady } from './preflight.js';
import { createGatewayServer } from './server.js';
import { createStateStore } from './state.js';
import { protectWindowsPrivatePathAcls } from './windows-acls.js';

function argValue(args, name, fallback = undefined) {
  const index = args.indexOf(name);
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback;
}

function parsePort(value, name) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${name} must be an integer TCP port from 1 to 65535`);
  }
  return port;
}

function parseConfig(args) {
  return resolveConfig({
    publicHost: argValue(args, '--host'),
    listenHost: argValue(args, '--listen-host'),
    port: argValue(args, '--port'),
    target: argValue(args, '--target'),
    stateDir: argValue(args, '--state-dir'),
  });
}

async function prepare(config) {
  await protectWindowsPrivatePathAcls([config.stateDir]);
  const store = createStateStore({ stateDir: config.stateDir });
  const certificates = await ensureCertificates({
    certDir: config.certDir,
    hostnames: [config.publicHost],
  });
  await protectWindowsPrivatePathAcls([config.stateDir]);
  return { store, certificates };
}

async function prepareStateOnly(config) {
  await protectWindowsPrivatePathAcls([config.stateDir]);
  return createStateStore({ stateDir: config.stateDir });
}

function printUsage() {
  console.log(`Usage:
  node gateway/src/cli.js serve [--host 192.168.1.x] [--port 38443]
  node gateway/src/cli.js serve [--host 192.168.1.x] [--port 38443] [--hub-port 38444]
  node gateway/src/cli.js pair [--host 192.168.1.x] [--port 38443] [--label "S24 Ultra"]
  node gateway/src/cli.js ready [--port 38443]
  node gateway/src/cli.js list
  node gateway/src/cli.js revoke <deviceId>
  node gateway/src/cli.js info
`);
}

async function commandServe(args) {
  const config = parseConfig(args);
  const { store, certificates } = await prepare(config);
  const hubPort = args.includes('--no-hub') ? undefined : parsePort(argValue(args, '--hub-port', 38444), '--hub-port');
  await assertTargetReady(config);
  const gateway = await createGatewayServer({
    target: config.target,
    store,
    certificates,
    listenHost: config.listenHost,
    listenPort: config.port,
    publicHost: config.publicHost,
    hubPort,
  });

  console.log(`ST Mobile Gateway listening at https://${config.publicHost}:${config.port}`);
  if (gateway.hub?.url) {
    console.log(`Auth hub: ${gateway.hub.url}`);
  }
  console.log(`Proxy target: ${config.target}`);
  console.log(`State: ${config.stateDir}`);
}

async function commandPair(args) {
  const config = parseConfig(args);
  const { store, certificates } = await prepare(config);
  await assertGatewayReadyToAdvertise(config, { store, certificates });
  const label = argValue(args, '--label', 'Android device');

  await mkdir(config.pairingDir, { recursive: true });
  await protectWindowsPrivatePathAcls([config.stateDir, config.pairingDir]);

  const issued = await createPairingNonce(store, { ttlMs: 5 * 60_000, label });
  const pairUrl = `https://${config.publicHost}:${config.port}/__mobile/pair/${issued.nonce}`;
  const deepLink = `stmobile://pair?url=${encodeURIComponent(pairUrl)}`;

  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const qrPath = path.join(config.pairingDir, `st-mobile-pair-${stamp}.png`);
  await QRCode.toFile(qrPath, deepLink, {
    errorCorrectionLevel: 'M',
    margin: 2,
    width: 512,
  });

  console.log(`Pairing QR: ${qrPath}`);
  console.log(`Deep link: ${deepLink}`);
  console.log(`Manual pairing URL: ${pairUrl}`);
  console.log(`Expires: ${issued.expiresAt}`);
  console.log(`CA certificate: ${certificates.caCertPath}`);
}

async function commandReady(args) {
  const config = parseConfig(args);
  const { store, certificates } = await prepare(config);
  await assertGatewayReadyToAdvertise(config, { store, certificates });
  console.log(JSON.stringify({ ready: true, gatewayUrl: `https://${config.publicHost}:${config.port}` }, null, 2));
}

async function commandList(args) {
  const config = parseConfig(args);
  const store = await prepareStateOnly(config);
  const state = await store.load();
  const devices = Object.values(state.devices).map((device) => ({
    deviceId: device.deviceId,
    label: device.label,
    userAgent: device.userAgent,
    createdAt: device.createdAt,
    lastSeenAt: device.lastSeenAt,
    revokedAt: device.revokedAt,
  }));
  console.log(JSON.stringify(devices, null, 2));
}

async function commandRevoke(args) {
  const config = parseConfig(args);
  const deviceId = args.find((arg) => !arg.startsWith('--') && arg !== 'revoke');
  if (!deviceId) {
    throw new Error('revoke requires a deviceId');
  }
  const store = await prepareStateOnly(config);
  const revoked = await revokeDevice(store, deviceId);
  if (!revoked) {
    throw new Error(`No device found for ${deviceId}`);
  }
  console.log(JSON.stringify({ revoked: true, deviceId }, null, 2));
}

async function commandInfo(args) {
  const config = parseConfig(args);
  const { certificates } = await prepare(config);
  const androidCaPath = path.join(config.projectRoot, 'android', 'app', 'src', 'main', 'res', 'raw', 'st_mobile_ca.crt');
  await mkdir(path.dirname(androidCaPath), { recursive: true });
  await copyFile(certificates.caCertPath, androidCaPath);
  console.log(JSON.stringify({
    gatewayUrl: `https://${config.publicHost}:${config.port}`,
    target: config.target,
    stateDir: config.stateDir,
    caCertPath: certificates.caCertPath,
    androidCaPath,
  }, null, 2));
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (!command || command === '--help' || command === '-h') {
    printUsage();
    return;
  }

  if (command === 'serve') {
    await commandServe(args);
  } else if (command === 'pair') {
    await commandPair(args);
  } else if (command === 'ready') {
    await commandReady(args);
  } else if (command === 'list') {
    await commandList(args);
  } else if (command === 'revoke') {
    await commandRevoke([command, ...args]);
  } else if (command === 'info') {
    await commandInfo(args);
  } else {
    throw new Error(`Unknown command: ${command}`);
  }
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
