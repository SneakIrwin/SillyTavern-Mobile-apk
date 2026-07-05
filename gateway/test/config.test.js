import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';

import { resolveConfig, selectBestPrivateIPv4 } from '../src/config.js';

test('private host selection prefers default-route LAN over virtual adapters', () => {
  const candidates = [
    { name: 'vEthernet (WSL)', address: '172.22.160.1' },
    { name: 'vEthernet (Default Switch)', address: '172.27.192.1' },
    { name: 'Wi-Fi', address: '192.168.1.215' },
  ];

  assert.equal(selectBestPrivateIPv4(candidates, '192.168.1.215'), '192.168.1.215');
});

test('private host selection de-prioritizes virtual adapters without route data', () => {
  const candidates = [
    { name: 'vEthernet (WSL)', address: '172.22.160.1' },
    { name: 'Wi-Fi', address: '192.168.1.215' },
  ];

  assert.equal(selectBestPrivateIPv4(candidates), '192.168.1.215');
});

test('private host selection does not let virtual default route outrank Wi-Fi', () => {
  const candidates = [
    { name: 'vEthernet (WSL)', address: '172.22.160.1' },
    { name: 'Wi-Fi', address: '192.168.1.215' },
  ];

  assert.equal(selectBestPrivateIPv4(candidates, '172.22.160.1'), '192.168.1.215');
});

test('pairing QR output resolves under the private state tree', () => {
  const config = resolveConfig({
    stateDir: path.join('C:', 'secure-state'),
    publicHost: '192.168.1.215',
    port: 38443,
  });

  assert.equal(config.pairingDir, path.join(config.stateDir, 'pairing'));
  assert.equal(path.relative(config.stateDir, config.pairingDir), 'pairing');
  assert.notEqual(path.dirname(config.pairingDir), config.projectRoot);
});
