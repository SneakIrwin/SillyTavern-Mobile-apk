import assert from 'node:assert/strict';
import test from 'node:test';

import { assertWindowsGatewayFirewallScope, firewallLocalPortIncludes, firewallRuleShadowsGatewayScope } from '../src/preflight.js';

test('firewall LocalPort parser detects gateway port in Any, lists, and ranges', () => {
  assert.equal(firewallLocalPortIncludes('Any', 38443), true);
  assert.equal(firewallLocalPortIncludes('38443', 38443), true);
  assert.equal(firewallLocalPortIncludes('80, 38443', 38443), true);
  assert.equal(firewallLocalPortIncludes('80 38443', 38443), true);
  assert.equal(firewallLocalPortIncludes('38400-38500', 38443), true);
  assert.equal(firewallLocalPortIncludes('38400 - 38500', 38443), true);
  assert.equal(firewallLocalPortIncludes('38500-38600', 38443), false);
  assert.equal(firewallLocalPortIncludes('RPC Endpoint Mapper', 38443), false);
});

const scopedGatewayRule = `
Rule Name:                            SillyTavern Secure Mobile Gateway
Enabled:                              Yes
Direction:                            In
Profiles:                             Public
Action:                               Allow
Program:                              Any
Protocol:                             TCP
LocalPort:                            38443
RemoteIP:                             LocalSubnet
`;

const broadLocalSubnetNodeRule = `
Rule Name:                            Node.js JavaScript Runtime
Enabled:                              Yes
Direction:                            In
Profiles:                             Public
Action:                               Allow
Program:                              C:\\Program Files\\nodejs\\node.exe
Protocol:                             TCP
LocalPort:                            Any
RemoteIP:                             LocalSubnet
`;

const wrongProgramGatewayRule = scopedGatewayRule.replace('Program:                              Any', 'Program:                              C:\\Other\\not-gateway.exe');
const blankProgramGatewayRule = scopedGatewayRule.replace('Program:                              Any\n', '');
const anyProfileGatewayRule = scopedGatewayRule.replace('Profiles:                             Public', 'Profiles:                             Any');
const multiProfileGatewayRule = scopedGatewayRule.replace('Profiles:                             Public', 'Profiles:                             Private, Public');

function mockedFirewallCommand({
  firewallEnabled = true,
  defaultInboundAction = 'Block',
  gatewayRule = scopedGatewayRule,
  allRules = scopedGatewayRule,
} = {}) {
  return (file, args) => {
    if (file === 'powershell.exe') {
      return JSON.stringify({
        InterfaceAlias: 'Wi-Fi',
        InterfaceIndex: 19,
        NetworkCategory: 'Public',
        IPv4Connectivity: 'Internet',
        FirewallProfile: 'Public',
        FirewallEnabled: firewallEnabled,
        FirewallDefaultInboundAction: defaultInboundAction,
      });
    }
    if (file === 'netsh.exe' && args.includes('name=SillyTavern Secure Mobile Gateway')) {
      return gatewayRule;
    }
    if (file === 'netsh.exe' && args.includes('name=all')) {
      return allRules;
    }
    throw new Error(`unexpected command: ${file} ${args.join(' ')}`);
  };
}

test('windows gateway firewall scope accepts a closed active firewall profile', () => {
  assert.doesNotThrow(() => assertWindowsGatewayFirewallScope('192.168.1.215', 38443, {
    platform: 'win32',
    runCommand: mockedFirewallCommand(),
    execPath: 'C:\\Program Files\\nodejs\\node.exe',
  }));
});

test('windows gateway firewall scope accepts netsh omitted Program as Program Any', () => {
  assert.doesNotThrow(() => assertWindowsGatewayFirewallScope('192.168.1.215', 38443, {
    platform: 'win32',
    runCommand: mockedFirewallCommand({ gatewayRule: blankProgramGatewayRule }),
    execPath: 'C:\\Program Files\\nodejs\\node.exe',
  }));
});

test('windows gateway firewall scope fails closed when the active firewall profile is disabled', () => {
  assert.throws(() => assertWindowsGatewayFirewallScope('192.168.1.215', 38443, {
    platform: 'win32',
    runCommand: mockedFirewallCommand({ firewallEnabled: false }),
    execPath: 'C:\\Program Files\\nodejs\\node.exe',
  }), /Windows Firewall is disabled for the active profile/);
});

test('windows gateway firewall scope fails closed when default inbound is not blocked', () => {
  assert.throws(() => assertWindowsGatewayFirewallScope('192.168.1.215', 38443, {
    platform: 'win32',
    runCommand: mockedFirewallCommand({ defaultInboundAction: 'Allow' }),
    execPath: 'C:\\Program Files\\nodejs\\node.exe',
  }), /default inbound action must be Block/);
});

test('windows gateway firewall scope rejects a named gateway rule for the wrong executable', () => {
  assert.throws(() => assertWindowsGatewayFirewallScope('192.168.1.215', 38443, {
    platform: 'win32',
    runCommand: mockedFirewallCommand({ gatewayRule: wrongProgramGatewayRule }),
    execPath: 'C:\\Program Files\\nodejs\\node.exe',
  }), /firewall rule must allow only Program Any or the gateway executable/);
});

test('windows gateway firewall scope rejects named gateway rules with broad profiles', () => {
  assert.throws(() => assertWindowsGatewayFirewallScope('192.168.1.215', 38443, {
    platform: 'win32',
    runCommand: mockedFirewallCommand({ gatewayRule: anyProfileGatewayRule }),
    execPath: 'C:\\Program Files\\nodejs\\node.exe',
  }), /firewall rule must allow only Program Any or the gateway executable/);
  assert.throws(() => assertWindowsGatewayFirewallScope('192.168.1.215', 38443, {
    platform: 'win32',
    runCommand: mockedFirewallCommand({ gatewayRule: multiProfileGatewayRule }),
    execPath: 'C:\\Program Files\\nodejs\\node.exe',
  }), /firewall rule must allow only Program Any or the gateway executable/);
});

test('windows gateway firewall scope rejects mixed duplicate named gateway rules', () => {
  assert.throws(() => assertWindowsGatewayFirewallScope('192.168.1.215', 38443, {
    platform: 'win32',
    runCommand: mockedFirewallCommand({ gatewayRule: `${scopedGatewayRule}\n${wrongProgramGatewayRule}` }),
    execPath: 'C:\\Program Files\\nodejs\\node.exe',
  }), /exactly one active firewall rule must allow only Program Any or the gateway executable/);
  assert.throws(() => assertWindowsGatewayFirewallScope('192.168.1.215', 38443, {
    platform: 'win32',
    runCommand: mockedFirewallCommand({ gatewayRule: `${scopedGatewayRule}\n${multiProfileGatewayRule}` }),
    execPath: 'C:\\Program Files\\nodejs\\node.exe',
  }), /exactly one active firewall rule must allow only Program Any or the gateway executable/);
});

test('firewall shadow predicate rejects broader LocalSubnet rules for the gateway executable', () => {
  assert.equal(firewallRuleShadowsGatewayScope({
    Enabled: 'Yes',
    Direction: 'In',
    Action: 'Allow',
    Program: 'Any',
    Protocol: 'TCP',
    LocalPort: '38443',
    RemoteIP: 'LocalSubnet',
  }, 38443, 'C:\\Program Files\\nodejs\\node.exe'), false);
  assert.equal(firewallRuleShadowsGatewayScope({
    Enabled: 'Yes',
    Direction: 'In',
    Action: 'Allow',
    Program: 'C:\\Program Files\\nodejs\\node.exe',
    Protocol: 'TCP',
    LocalPort: 'Any',
    RemoteIP: 'LocalSubnet',
  }, 38443, 'C:\\Program Files\\nodejs\\node.exe'), true);
  assert.equal(firewallRuleShadowsGatewayScope({
    Enabled: 'Yes',
    Direction: 'In',
    Action: 'Allow',
    Program: 'Any',
    Protocol: 'TCP',
    LocalPort: '80, 38443',
    RemoteIP: 'LocalSubnet',
  }, 38443, 'C:\\Program Files\\nodejs\\node.exe'), true);
  assert.equal(firewallRuleShadowsGatewayScope({
    Enabled: 'Yes',
    Direction: 'In',
    Action: 'Allow',
    Program: 'Any',
    Protocol: 'TCP',
    LocalPort: '38400-38500',
    RemoteIP: 'LocalSubnet',
  }, 38443, 'C:\\Program Files\\nodejs\\node.exe'), true);
  assert.equal(firewallRuleShadowsGatewayScope({
    Enabled: 'Yes',
    Direction: 'In',
    Action: 'Allow',
    Program: 'Any',
    Protocol: 'Any',
    LocalPort: '38443',
    RemoteIP: 'LocalSubnet',
  }, 38443, 'C:\\Program Files\\nodejs\\node.exe'), true);
  assert.equal(firewallRuleShadowsGatewayScope({
    Enabled: 'Yes',
    Direction: 'In',
    Action: 'Allow',
    Program: 'C:\\Other\\node.exe',
    Protocol: 'TCP',
    LocalPort: 'Any',
    RemoteIP: 'LocalSubnet',
  }, 38443, 'C:\\Program Files\\nodejs\\node.exe'), false);
});

test('windows gateway firewall scope fails on a broader same-LocalSubnet Node rule', () => {
  assert.throws(() => assertWindowsGatewayFirewallScope('192.168.1.215', 38443, {
    platform: 'win32',
    runCommand: mockedFirewallCommand({ allRules: `${scopedGatewayRule}\n${broadLocalSubnetNodeRule}` }),
    execPath: 'C:\\Program Files\\nodejs\\node.exe',
  }), /broad inbound allow rule\(s\) shadow gateway scope: Node\.js JavaScript Runtime/);
});
