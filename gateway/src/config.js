import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const gatewayRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const projectRoot = path.resolve(gatewayRoot, '..');

function isPrivateIPv4(address) {
  return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(address);
}

function detectWindowsDefaultRouteIPv4() {
  if (process.platform !== 'win32') {
    return null;
  }
  const script = `
$ErrorActionPreference = 'Stop'
try { [System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle } catch {}
$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' |
  Sort-Object RouteMetric, InterfaceMetric |
  Select-Object -First 1
if (-not $route) { exit 1 }
$ip = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex |
  Where-Object { $_.IPAddress -match '^(10\\.|172\\.(1[6-9]|2\\d|3[01])\\.|192\\.168\\.)' } |
  Select-Object -First 1
if (-not $ip) { exit 1 }
$ip.IPAddress
`;
  try {
    const output = execFileSync('powershell.exe', ['-NoProfile', '-Command', script], {
      encoding: 'utf8',
      windowsHide: true,
      timeout: 5_000,
    }).trim();
    return output || null;
  } catch {
    return null;
  }
}

function scoreCandidate(candidate, routeAddress) {
  let score = 0;
  const isPreferredPhysical = /^(wi-?fi|wlan|ethernet|local area connection)$/i.test(candidate.name);
  const isVirtual = /(hyper-v|vEthernet|wsl|docker|virtualbox|vmware|npcap|loopback|bluetooth|vpn|tap|tun|tailscale|zerotier)/i.test(candidate.name);
  if (candidate.address === routeAddress) {
    score += isVirtual ? 40 : 1000;
  }
  if (isPreferredPhysical) {
    score += 100;
  }
  if (/192\.168\./.test(candidate.address)) {
    score += 30;
  } else if (/^10\./.test(candidate.address)) {
    score += 20;
  }
  if (isVirtual) {
    score -= 200;
  }
  return score;
}

export function selectBestPrivateIPv4(candidates, routeAddress = null) {
  const eligible = candidates.filter((candidate) => isPrivateIPv4(candidate.address));
  if (eligible.length === 0) {
    return null;
  }
  return eligible
    .map((candidate) => ({ candidate, score: scoreCandidate(candidate, routeAddress) }))
    .sort((a, b) => b.score - a.score || a.candidate.address.localeCompare(b.candidate.address))[0]
    .candidate.address;
}

export function detectPrivateIPv4() {
  const candidates = [];
  for (const [name, iface] of Object.entries(os.networkInterfaces())) {
    for (const address of iface ?? []) {
      if (address.family !== 'IPv4' || address.internal) {
        continue;
      }
      if (isPrivateIPv4(address.address)) {
        candidates.push({ name, address: address.address });
      }
    }
  }
  return selectBestPrivateIPv4(candidates, detectWindowsDefaultRouteIPv4()) ?? '127.0.0.1';
}

export function resolveConfig(overrides = {}) {
  const stateDir = path.resolve(overrides.stateDir ?? process.env.ST_MOBILE_STATE_DIR ?? path.join(projectRoot, 'state'));
  const publicHost = overrides.publicHost ?? process.env.ST_MOBILE_HOST ?? detectPrivateIPv4();
  const port = Number(overrides.port ?? process.env.ST_MOBILE_PORT ?? 38443);
  return {
    projectRoot,
    gatewayRoot,
    stateDir,
    certDir: path.join(stateDir, 'certs'),
    pairingDir: path.join(stateDir, 'pairing'),
    publicHost,
    listenHost: overrides.listenHost ?? process.env.ST_MOBILE_LISTEN_HOST ?? '0.0.0.0',
    port,
    target: overrides.target ?? process.env.ST_MOBILE_TARGET ?? 'http://127.0.0.1:3000',
  };
}
