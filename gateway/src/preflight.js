import http from 'node:http';
import https from 'node:https';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { URL } from 'node:url';

import { COOKIE_NAME, createPairingNonce, parseCookies, sha256 } from './auth.js';

const REQUIRED_SILLYTAVERN_ANCHORS = [
  /<title>\s*SillyTavern\s*<\/title>/i,
  /href=["']manifest\.json["']/i,
  /href=["']css\/st-tailwind\.css["']/i,
  /id=["']top-settings-holder["']/i,
  /id=["']ai-config-button["']/i,
];

function isExpectedSillyTavernHtml(body) {
  const text = String(body ?? '');
  return REQUIRED_SILLYTAVERN_ANCHORS.every((pattern) => pattern.test(text));
}

function assertExpectedTarget(target) {
  const parsed = new URL(target);
  if (parsed.protocol !== 'http:' || parsed.hostname !== '127.0.0.1' || parsed.port !== '3000') {
    throw new Error(`Refusing to advertise gateway for unexpected target: ${target}`);
  }
}

function assertPrivateLanPublicHost(publicHost) {
  if (!/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(publicHost)) {
    throw new Error(`Refusing to advertise non-private-LAN gateway host: ${publicHost}`);
  }
}

function ruleProfileAllows(ruleProfile, networkCategory) {
  return String(ruleProfile)
    .split(',')
    .map((part) => part.trim())
    .some((part) => part === 'Any' || part === networkCategory);
}

function ruleProfileExactly(ruleProfile, networkCategory) {
  const parts = String(ruleProfile)
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);
  return parts.length === 1 && parts[0] === networkCategory;
}

function isExactLocalSubnet(value) {
  return String(value).trim().toLowerCase() === 'localsubnet';
}

export function firewallLocalPortIncludes(localPort, port) {
  const text = String(localPort ?? '').trim();
  if (!text) {
    return false;
  }
  if (text.toLowerCase() === 'any') {
    return true;
  }
  const target = Number(port);
  if (!Number.isInteger(target)) {
    return false;
  }
  return text
    .replace(/\s*-\s*/g, '-')
    .split(/[,\s]+/)
    .filter(Boolean)
    .some((part) => {
      if (/^\d+$/.test(part)) {
        return Number(part) === target;
      }
      const range = part.match(/^(\d+)-(\d+)$/);
      if (!range) {
        return false;
      }
      const start = Number(range[1]);
      const end = Number(range[2]);
      return target >= Math.min(start, end) && target <= Math.max(start, end);
    });
}

function firewallLocalPortExplicitlyIncludes(localPort, port) {
  return String(localPort ?? '').trim().toLowerCase() !== 'any' && firewallLocalPortIncludes(localPort, port);
}

function firewallLocalPortExactly(localPort, port) {
  return String(localPort ?? '').trim() === String(port);
}

function firewallProgramAppliesToGateway(program, execPath) {
  const text = String(program ?? '').trim();
  return !text || text.toLowerCase() === 'any' || text.toLowerCase() === String(execPath).toLowerCase();
}

function firewallNamedProgramAppliesToGateway(program, execPath) {
  const text = String(program ?? '').trim().toLowerCase();
  return !text || text === 'any' || text === String(execPath).toLowerCase();
}

function firewallRuleHasExactGatewayScope(rule, port) {
  return (
    rule.Protocol === 'TCP' &&
    firewallLocalPortExactly(rule.LocalPort, port) &&
    isExactLocalSubnet(rule.RemoteIP)
  );
}

export function firewallRuleShadowsGatewayScope(rule, port, execPath) {
  return (
    rule.Enabled === 'Yes' &&
    rule.Direction === 'In' &&
    rule.Action === 'Allow' &&
    (rule.Protocol === 'TCP' || rule.Protocol === 'Any') &&
    firewallLocalPortIncludes(rule.LocalPort, port) &&
    firewallProgramAppliesToGateway(rule.Program, execPath) &&
    !firewallRuleHasExactGatewayScope(rule, port)
  );
}

function parseNetshRules(output) {
  const rules = [];
  let current = null;
  for (const line of String(output).split(/\r?\n/)) {
    const ruleName = line.match(/^Rule Name:\s*(.+?)\s*$/);
    if (ruleName) {
      current = { DisplayName: ruleName[1].trim() };
      rules.push(current);
      continue;
    }
    if (!current) {
      continue;
    }
    const pair = line.match(/^([A-Za-z ]+):\s*(.*?)\s*$/);
    if (pair) {
      current[pair[1].trim().replace(/\s+/g, '')] = pair[2].trim();
    }
  }
  return rules;
}

function netshRules(name, runCommand = execFileSync) {
  const output = runCommand('netsh.exe', ['advfirewall', 'firewall', 'show', 'rule', `name=${name}`, 'verbose'], {
    encoding: 'utf8',
    windowsHide: true,
    timeout: 10_000,
    maxBuffer: 16 * 1024 * 1024,
  });
  return parseNetshRules(output);
}

export function firewallProfileEnabled(value) {
  return value === true || String(value ?? '').trim().toLowerCase() === 'true' || String(value ?? '').trim() === '1';
}

function firewallDefaultInboundBlocked(value) {
  const text = String(value ?? '').trim().toLowerCase();
  return text === 'block' || text === '0';
}

export function assertWindowsGatewayFirewallScope(publicHost, port, {
  platform = process.platform,
  runCommand = execFileSync,
  execPath = process.execPath,
} = {}) {
  if (platform !== 'win32') {
    return;
  }
  const profileScript = `
$ErrorActionPreference = 'Stop'
try { [System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle } catch {}
$ip = Get-NetIPAddress -AddressFamily IPv4 -IPAddress '${publicHost}' -ErrorAction Stop | Select-Object -First 1
$profile = Get-NetConnectionProfile -InterfaceIndex $ip.InterfaceIndex -ErrorAction Stop | Select-Object -First 1
$firewallProfile = Get-NetFirewallProfile -Profile $profile.NetworkCategory -PolicyStore ActiveStore -ErrorAction Stop | Select-Object -First 1
[pscustomobject]@{
  InterfaceAlias = $profile.InterfaceAlias
  InterfaceIndex = $profile.InterfaceIndex
  NetworkCategory = [string]$profile.NetworkCategory
  IPv4Connectivity = [string]$profile.IPv4Connectivity
  FirewallProfile = [string]$firewallProfile.Name
  FirewallEnabled = $firewallProfile.Enabled
  FirewallDefaultInboundAction = [string]$firewallProfile.DefaultInboundAction
} | ConvertTo-Json -Compress
`;
  let profile;
  try {
    profile = JSON.parse(runCommand('powershell.exe', ['-NoProfile', '-Command', profileScript], {
      encoding: 'utf8',
      windowsHide: true,
      timeout: 5_000,
    }));
  } catch (error) {
    throw new Error(`Could not verify Windows network profile for ${publicHost}: ${error.message}`);
  }
  if (!firewallProfileEnabled(profile.FirewallEnabled)) {
    throw new Error(
      `Refusing to advertise ${publicHost} on ${profile.InterfaceAlias} (${profile.NetworkCategory}); ` +
      `Windows Firewall is disabled for the active profile.`,
    );
  }
  if (!firewallDefaultInboundBlocked(profile.FirewallDefaultInboundAction)) {
    throw new Error(
      `Refusing to advertise ${publicHost} on ${profile.InterfaceAlias} (${profile.NetworkCategory}); ` +
      `Windows Firewall default inbound action must be Block for the active profile.`,
    );
  }
  const gatewayRules = netshRules('SillyTavern Secure Mobile Gateway', runCommand);
  const namedRules = gatewayRules.filter((rule) => rule.DisplayName === 'SillyTavern Secure Mobile Gateway');
  const activeNamedRules = namedRules.filter((rule) => rule.Enabled === 'Yes' && ruleProfileAllows(rule.Profiles, profile.NetworkCategory));
  const exactNamedRules = activeNamedRules.filter((rule) => (
    rule.Direction === 'In' &&
    rule.Action === 'Allow' &&
    rule.Protocol === 'TCP' &&
    rule.LocalPort === String(port) &&
    isExactLocalSubnet(rule.RemoteIP) &&
    ruleProfileExactly(rule.Profiles, profile.NetworkCategory) &&
    firewallNamedProgramAppliesToGateway(rule.Program, execPath)
  ));
  if (activeNamedRules.length !== 1 || exactNamedRules.length !== 1) {
    throw new Error(
      `Refusing to advertise ${publicHost} on ${profile.InterfaceAlias} (${profile.NetworkCategory}); ` +
      `exactly one active firewall rule must allow only Program Any or the gateway executable, TCP ${port} from LocalSubnet on the active profile.`,
    );
  }
  const broadRules = netshRules('all', runCommand).filter((rule) => (
    ruleProfileAllows(rule.Profiles, profile.NetworkCategory) &&
    firewallRuleShadowsGatewayScope(rule, port, execPath)
  ));
  if (broadRules.length > 0) {
    const names = broadRules.map((rule) => rule.DisplayName).join(', ');
    throw new Error(`Refusing to advertise ${publicHost}; broad inbound allow rule(s) shadow gateway scope: ${names}`);
  }
}

function requestText(url, { ca, cookie, timeoutMs = 5_000 } = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const client = parsed.protocol === 'https:' ? https : http;
    const req = client.request({
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port,
      path: `${parsed.pathname}${parsed.search}`,
      method: 'GET',
      ca,
      rejectUnauthorized: parsed.protocol === 'https:',
      headers: cookie ? { cookie } : {},
      timeout: timeoutMs,
    }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        body += chunk;
      });
      res.on('end', () => {
        resolve({ status: res.statusCode, headers: res.headers, body });
      });
    });
    req.on('timeout', () => req.destroy(new Error(`Timed out requesting ${url}`)));
    req.on('error', reject);
    req.end();
  });
}

async function assertLoopbackSillyTavernIdentity(target) {
  assertExpectedTarget(target);
  const response = await requestText(target);
  if (response.status !== 200 || !isExpectedSillyTavernHtml(response.body)) {
    throw new Error('Loopback target did not return the expected SillyTavern fingerprint.');
  }
}

async function cleanupProbeState(store, nonceHash, token) {
  const tokenHash = token ? sha256(token) : null;
  await store.update((state) => {
    if (nonceHash) {
      delete state.pendingNonces[nonceHash];
    }
    if (tokenHash) {
      for (const [deviceId, device] of Object.entries(state.devices)) {
        if (device.tokenHash === tokenHash) {
          delete state.devices[deviceId];
        }
      }
    }
  });
}

async function assertGatewayOriginReady(gatewayBase, { store, ca }) {
  const health = await requestText(`${gatewayBase}/__mobile/health`, { ca });
  if (health.status !== 200) {
    throw new Error(`Gateway health probe failed for ${gatewayBase} with status ${health.status}`);
  }

  const issued = await createPairingNonce(store, { ttlMs: 60_000, label: 'Readiness probe' });
  let token = null;
  try {
    const pair = await requestText(`${gatewayBase}/__mobile/pair/${issued.nonce}`, { ca });
    const setCookie = Array.isArray(pair.headers['set-cookie']) ? pair.headers['set-cookie'][0] : pair.headers['set-cookie'];
    token = parseCookies(setCookie)[COOKIE_NAME];
    if (pair.status !== 302 || !token) {
      throw new Error(`Gateway pairing readiness probe failed for ${gatewayBase} with status ${pair.status}`);
    }

    const root = await requestText(`${gatewayBase}/`, { ca, cookie: `${COOKIE_NAME}=${encodeURIComponent(token)}` });
    if (root.status !== 200 || !isExpectedSillyTavernHtml(root.body)) {
      throw new Error(`Authenticated gateway probe for ${gatewayBase} did not return the expected SillyTavern fingerprint.`);
    }
  } finally {
    await cleanupProbeState(store, issued.nonceHash, token);
  }
}

export async function assertGatewayReadyToAdvertise(config, { store, certificates }) {
  await assertLoopbackSillyTavernIdentity(config.target);
  assertPrivateLanPublicHost(config.publicHost);
  assertWindowsGatewayFirewallScope(config.publicHost, config.port);

  const ca = certificates?.caCertPem ?? await readFile(`${config.certDir}/st-mobile-ca.crt`, 'utf8');
  await assertGatewayOriginReady(`https://127.0.0.1:${config.port}`, { store, ca });
  await assertGatewayOriginReady(`https://${config.publicHost}:${config.port}`, { store, ca });
}

export async function assertTargetReady(config) {
  await assertLoopbackSillyTavernIdentity(config.target);
}
