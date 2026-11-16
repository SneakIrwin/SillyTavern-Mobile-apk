import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, readFile, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { ensureCertificates } from '../src/certs.js';
import { createStateStore } from '../src/state.js';
import { protectWindowsPrivatePathAcls } from '../src/windows-acls.js';

test('certificate repair preserves the CA and refuses partial trust identities', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'st-mobile-cert-repair-'));
  try {
    const original = await ensureCertificates({ certDir: dir });
    const ca = await readFile(original.caCertPath);
    await writeFile(original.serverCertPath, 'damaged server certificate');
    await ensureCertificates({ certDir: dir });
    assert.deepEqual(await readFile(original.caCertPath), ca);
    assert.match(await readFile(original.serverCertPath, 'utf8'), /BEGIN CERTIFICATE/);
    await unlink(original.caKeyPath);
    await assert.rejects(ensureCertificates({ certDir: dir }), /Incomplete gateway CA identity/);
    assert.deepEqual(await readFile(original.caCertPath), ca);
    await unlink(original.caCertPath);
    await assert.rejects(ensureCertificates({ certDir: dir }), /server identity exists without its CA/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

function execFileText(file, args) {
  return new Promise((resolve, reject) => {
    execFile(file, args, { windowsHide: true }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(stderr || stdout || error.message));
        return;
      }
      resolve(stdout);
    });
  });
}

test('direct certificate generation protects Windows private-key ACLs', { skip: process.platform !== 'win32' }, async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'st-mobile-certs-'));
  try {
    const certDir = path.join(dir, 'certs');
    const certs = await ensureCertificates({ certDir, hostnames: ['127.0.0.1'] });

    const keyAcl = await execFileText('icacls.exe', [certs.caKeyPath]);
    const dirAcl = await execFileText('icacls.exe', [certDir]);

    assert.doesNotMatch(keyAcl, /CodexSandboxUsers|CodexSandboxOnline|CodexSandboxOffline/);
    assert.doesNotMatch(dirAcl, /CodexSandboxUsers|CodexSandboxOnline|CodexSandboxOffline/);
    assert.match(keyAcl, /NT AUTHORITY\\SYSTEM/);
    assert.match(keyAcl, /BUILTIN\\Administrators/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('state storage ACLs exclude sandbox modifier principals', { skip: process.platform !== 'win32' }, async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'st-mobile-state-acls-'));
  try {
    const stateDir = path.join(dir, 'state');
    const store = createStateStore({ stateDir });
    await store.save({ version: 1, pendingNonces: {}, devices: {}, certs: {} });
    await protectWindowsPrivatePathAcls([stateDir]);

    const stateAcl = await execFileText('icacls.exe', [stateDir]);
    const fileAcl = await execFileText('icacls.exe', [store.stateFile]);

    assert.doesNotMatch(stateAcl, /CodexSandboxUsers|CodexSandboxOnline|CodexSandboxOffline/);
    assert.doesNotMatch(fileAcl, /CodexSandboxUsers|CodexSandboxOnline|CodexSandboxOffline/);
    assert.match(fileAcl, /NT AUTHORITY\\SYSTEM/);
    assert.match(fileAcl, /BUILTIN\\Administrators/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
