import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import forge from 'node-forge';

import { protectWindowsPrivatePathAcls } from './windows-acls.js';

function serialNumber() {
  return forge.util.bytesToHex(forge.random.getBytesSync(16));
}

function subject(commonName) {
  return [
    { name: 'commonName', value: commonName },
    { name: 'organizationName', value: 'SillyTavern Secure Mobile' },
  ];
}

function isIpAddress(value) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) || String(value).includes(':');
}

function pemPath(certDir, name) {
  return path.join(certDir, name);
}

async function fileExists(file) {
  try {
    await readFile(file);
    return true;
  } catch (error) {
    if (error.code === 'ENOENT') {
      return false;
    }
    throw error;
  }
}

function createCaCertificate() {
  const keys = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = serialNumber();
  cert.validity.notBefore = new Date(Date.now() - 24 * 60 * 60 * 1000);
  cert.validity.notAfter = new Date(Date.now() + 10 * 365 * 24 * 60 * 60 * 1000);
  cert.setSubject(subject('SillyTavern Secure Mobile Local CA'));
  cert.setIssuer(cert.subject.attributes);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, digitalSignature: true },
    { name: 'subjectKeyIdentifier' },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return { cert, privateKey: keys.privateKey };
}

function createServerCertificate(ca, names) {
  const keys = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = serialNumber();
  cert.validity.notBefore = new Date(Date.now() - 24 * 60 * 60 * 1000);
  cert.validity.notAfter = new Date(Date.now() + 825 * 24 * 60 * 60 * 1000);

  const primaryName = names[0] ?? 'localhost';
  cert.setSubject(subject(primaryName));
  cert.setIssuer(ca.cert.subject.attributes);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', serverAuth: true },
    {
      name: 'subjectAltName',
      altNames: names.map((name) => ({
        type: isIpAddress(name) ? 7 : 2,
        ip: isIpAddress(name) ? name : undefined,
        value: isIpAddress(name) ? undefined : name,
      })),
    },
  ]);
  cert.sign(ca.privateKey, forge.md.sha256.create());
  return { cert, privateKey: keys.privateKey };
}

export async function ensureCertificates({ certDir, hostnames = [] }) {
  await mkdir(certDir, { recursive: true });
  await protectWindowsPrivatePathAcls([certDir]);

  const caCertPath = pemPath(certDir, 'st-mobile-ca.crt');
  const caKeyPath = pemPath(certDir, 'st-mobile-ca.key.pem');
  const serverCertPath = pemPath(certDir, 'st-mobile-server.crt');
  const serverKeyPath = pemPath(certDir, 'st-mobile-server.key.pem');
  const metadataPath = pemPath(certDir, 'metadata.json');

  if (!(await fileExists(caCertPath)) || !(await fileExists(caKeyPath))) {
    const ca = createCaCertificate();
    await writeFile(caCertPath, forge.pki.certificateToPem(ca.cert), { encoding: 'utf8', mode: 0o600 });
    await writeFile(caKeyPath, forge.pki.privateKeyToPem(ca.privateKey), { encoding: 'utf8', mode: 0o600 });
    await protectWindowsPrivatePathAcls([certDir]);
  }

  const names = [...new Set(['localhost', '127.0.0.1', ...hostnames.filter(Boolean)])];
  let regenerateServer = !(await fileExists(serverCertPath)) || !(await fileExists(serverKeyPath));

  try {
    const metadata = JSON.parse(await readFile(metadataPath, 'utf8'));
    const oldNames = Array.isArray(metadata.hostnames) ? metadata.hostnames : [];
    regenerateServer = regenerateServer || names.some((name) => !oldNames.includes(name));
  } catch (error) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
    regenerateServer = true;
  }

  if (regenerateServer) {
    const ca = {
      cert: forge.pki.certificateFromPem(await readFile(caCertPath, 'utf8')),
      privateKey: forge.pki.privateKeyFromPem(await readFile(caKeyPath, 'utf8')),
    };
    const server = createServerCertificate(ca, names);
    await writeFile(serverCertPath, forge.pki.certificateToPem(server.cert), { encoding: 'utf8', mode: 0o600 });
    await writeFile(serverKeyPath, forge.pki.privateKeyToPem(server.privateKey), { encoding: 'utf8', mode: 0o600 });
    await writeFile(metadataPath, `${JSON.stringify({ hostnames: names, updatedAt: new Date().toISOString() }, null, 2)}\n`, 'utf8');
    await protectWindowsPrivatePathAcls([certDir]);
  }

  return {
    caCertPath,
    caKeyPath,
    serverCertPath,
    serverKeyPath,
    caCertPem: await readFile(caCertPath, 'utf8'),
    serverCertPem: await readFile(serverCertPath, 'utf8'),
    serverKeyPem: await readFile(serverKeyPath, 'utf8'),
  };
}
