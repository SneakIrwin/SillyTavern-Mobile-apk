import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const root = path.resolve(import.meta.dirname, '..');

async function text(relativePath) {
  return readFile(path.join(root, relativePath), 'utf8');
}

test('desktop launcher fails closed on unsafe ST and gateway listeners', async () => {
  const source = await text('scripts/Start-StMobile.ps1');
  assert.match(source, /Assert-SillyTavernPortSafe/);
  assert.match(source, /Assert-SillyTavernIdentity/);
  assert.match(source, /Assert-GatewayListenerExpected/);
  assert.match(source, /Assert-GatewaySecurityProbes/);
  assert.match(source, /Assert-GatewayReadyThroughCli/);
  assert.match(source, /Assert-PublicHostNetworkReady/);
  assert.match(source, /Get-DefaultPrivateIPv4/);
  assert.match(source, /__mobile\/health/);
  assert.match(source, /bad-cookie/);
  assert.match(source, /\$expectedCli = \(Resolve-Path \$GatewayCli\)\.Path/);
  assert.match(source, /\$commandLine\.Contains\(\$expectedCli\)/);
  assert.doesNotMatch(source, /expectedCliFragment/);
  assert.match(source, /throw "Unsafe SillyTavern listener/);
  assert.match(source, /SillyTavern page fingerprint/);
  assert.match(source, /<title>\\s\*SillyTavern\\s\*<\/title>/);
  assert.match(source, /throw "Gateway port .*unexpected process/);
  assert.match(source, /--target/);
  assert.match(source, /--listen-host/);
  assert.match(source, /--host \$PublicHost/);
  assert.match(source, /LocalSubnet/);
  assert.match(source, /active \$\(\$profile\.NetworkCategory\) profile/);
  assert.match(source, /Get-NetFirewallProfile -Profile \$profile\.NetworkCategory -PolicyStore ActiveStore/);
  assert.match(source, /Assert-ActiveFirewallProfileClosed/);
  assert.match(source, /Windows Firewall is disabled for active/);
  assert.match(source, /Test-FirewallNamedProgramAppliesToGateway/);
  assert.match(source, /Test-FirewallProfilesExactly/);
  assert.match(source, /Test-ActiveNamedGatewayRulesExactly/);
  assert.match(source, /Test-FirewallRuleShadowsGatewayScope/);
  assert.match(source, /Broad inbound firewall allow rule/);
  assert.match(source, /hostMatches\.Count -ne 1/);
  assert.match(source, /GatewayPidFile/);
  assert.match(source, /PriorityClass.*Idle/s);
});

test('desktop scripts protect certificate ACLs and pin build downloads', async () => {
  const start = await text('scripts/Start-StMobile.ps1');
  const build = await text('scripts/Build-Android.ps1');
  const protect = await text('scripts/Protect-CertAcls.ps1');
  const sdkManifest = await text('quality/android-sdk-package-hashes.tsv');

  assert.match(start, /Protect-CertAcls\.ps1/);
  assert.match(start, /-PrivatePath \$StateRoot/);
  assert.match(build, /Protect-CertAcls\.ps1/);
  assert.match(build, /-PrivatePath \$stateRoot/);
  const certs = await text('gateway/src/certs.js');
  const aclModule = await text('gateway/src/windows-acls.js');
  assert.match(aclModule, /Protect-CertAcls\.ps1/);
  assert.match(certs, /protectWindowsPrivatePathAcls/);
  const cli = await text('gateway/src/cli.js');
  const preflight = await text('gateway/src/preflight.js');
  const config = await text('gateway/src/config.js');
  assert.match(cli, /assertGatewayReadyToAdvertise/);
  assert.match(cli, /commandReady/);
  assert.match(cli, /https:\/\/\$\{config\.publicHost\}:\$\{config\.port\}/);
  assert.match(preflight, /Readiness probe/);
  assert.match(preflight, /assertPrivateLanPublicHost/);
  assert.match(preflight, /assertWindowsGatewayFirewallScope/);
  assert.match(preflight, /Get-NetFirewallProfile -Profile \$profile\.NetworkCategory -PolicyStore ActiveStore/);
  assert.match(preflight, /FirewallEnabled = \$firewallProfile\.Enabled/);
  assert.match(preflight, /Windows Firewall is disabled for the active profile/);
  assert.match(preflight, /firewallNamedProgramAppliesToGateway/);
  assert.match(preflight, /ruleProfileExactly/);
  assert.match(preflight, /firewallRuleShadowsGatewayScope/);
  assert.match(preflight, /firewall rule must allow only Program Any or the gateway executable, TCP \$\{port\} from LocalSubnet/);
  assert.match(preflight, /netshRules\('all', runCommand\)/);
  assert.match(preflight, /broad inbound allow rule\(s\) shadow gateway scope/);
  assert.match(preflight, /https:\/\/\$\{config\.publicHost\}:\$\{config\.port\}/);
  assert.match(preflight, /Authenticated gateway probe for \$\{gatewayBase\} did not return the expected SillyTavern fingerprint/);
  assert.match(config, /detectWindowsDefaultRouteIPv4/);
  assert.match(config, /selectBestPrivateIPv4/);
  assert.match(config, /vEthernet\|wsl\|docker/i);
  assert.match(build, /JdkSha256/);
  assert.match(build, /CommandLineToolsSha256/);
  assert.match(build, /Ensure-Archive/);
  assert.match(build, /Assert-AndroidSdkPackageHashes/);
  assert.match(build, /Assert-GradleDependencyVerification/);
  assert.match(build, /--dependency-verification strict/);
  assert.match(build, /Remove-UnderTools \$GradleRoot/);
  assert.match(build, /Remove-UnderTools \$JdkRoot/);
  assert.match(build, /quality\\android-sdk-package-hashes\.tsv/);
  assert.doesNotMatch(build, /binary\/latest\/21\/ga/);
  assert.match(protect, /SetAccessRuleProtection\(\$true, \$false\)/);
  assert.match(protect, /GetCurrentProcess\(\)\.PriorityClass/);
  assert.match(protect, /S-1-5-18/);
  assert.match(protect, /S-1-5-32-544/);
  assert.match(sdkManifest, /\.tools\/android-sdk\/build-tools\/36\.0\.0\/aapt2\.exe\t[0-9a-f]{64}\t/);
  assert.match(sdkManifest, /\.tools\/android-sdk\/platforms\/android-36\/android\.jar\t[0-9a-f]{64}\t/);
  assert.match(await text('android/gradle/verification-metadata.xml'), /com\.android\.application\.gradle\.plugin/);
});

test('admin relay processed request records omit live nonce material', async () => {
  const broker = await text('scripts/AdminRelay-Broker.ps1');

  assert.match(broker, /function Write-ProcessedRequestFile/);
  assert.match(broker, /nonce_omitted = \$true/);
  assert.match(broker, /Write-ProcessedRequestFile -Path \$processedPath -RequestId \$requestId -Request \$request/);
  assert.match(broker, /Remove-Item -LiteralPath \$file\.FullName -Force/);
  assert.doesNotMatch(broker, /Move-Item -LiteralPath \$file\.FullName -Destination \$processedPath/);
});

test('pairing QR output stays under protected state ACLs', async () => {
  const config = await text('gateway/src/config.js');
  const cli = await text('gateway/src/cli.js');

  assert.match(config, /pairingDir: path\.join\(stateDir, 'pairing'\)/);
  assert.doesNotMatch(config, /pairingDir: path\.join\(projectRoot, 'pairing'\)/);
  assert.match(cli, /await mkdir\(config\.pairingDir, \{ recursive: true \}\);/);
  assert.match(cli, /await protectWindowsPrivatePathAcls\(\[config\.stateDir, config\.pairingDir\]\);/);
  assert.match(cli, /QRCode\.toFile\(qrPath, deepLink/);
  assert.ok(
    cli.indexOf('await protectWindowsPrivatePathAcls([config.stateDir, config.pairingDir]);')
      < cli.indexOf('const issued = await createPairingNonce'),
    'pairing directory must be ACL-protected before nonce creation',
  );
  assert.ok(
    cli.indexOf('await protectWindowsPrivatePathAcls([config.stateDir, config.pairingDir]);')
      < cli.indexOf('await QRCode.toFile(qrPath, deepLink'),
    'pairing directory must be ACL-protected before QR write',
  );
});

test('desktop firewall port parser detects gateway port in lists and ranges', () => {
  const startScript = path.join(root, 'scripts', 'Start-StMobile.ps1').replaceAll("'", "''");
  const script = `
$ErrorActionPreference = 'Stop'
$source = Get-Content -Raw -LiteralPath '${startScript}'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw ($errors | Out-String) }
foreach ($name in @('Test-FirewallLocalPortIncludes', 'Test-FirewallLocalPortExplicitlyIncludes')) {
  $function = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
  if (-not $function) { throw "Missing function $name" }
  Invoke-Expression $function.Extent.Text
}
[pscustomobject]@{
  Any = Test-FirewallLocalPortIncludes 'Any' 38443
  Exact = Test-FirewallLocalPortIncludes '38443' 38443
  List = Test-FirewallLocalPortIncludes '80, 38443' 38443
  WhitespaceList = Test-FirewallLocalPortIncludes '80 38443' 38443
  Range = Test-FirewallLocalPortIncludes '38400-38500' 38443
  SpacedRange = Test-FirewallLocalPortIncludes '38400 - 38500' 38443
  OutOfRange = Test-FirewallLocalPortIncludes '38500-38600' 38443
  ExplicitAny = Test-FirewallLocalPortExplicitlyIncludes 'Any' 38443
  ExplicitRange = Test-FirewallLocalPortExplicitlyIncludes '38400-38500' 38443
} | ConvertTo-Json -Compress
`;
  const result = JSON.parse(execFileSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script], {
    encoding: 'utf8',
    windowsHide: true,
  }));

  assert.deepEqual(result, {
    Any: true,
    Exact: true,
    List: true,
    WhitespaceList: true,
    Range: true,
    SpacedRange: true,
    OutOfRange: false,
    ExplicitAny: false,
    ExplicitRange: true,
  });
});

test('desktop launcher firewall profile helper fails closed on disabled active profile', () => {
  const startScript = path.join(root, 'scripts', 'Start-StMobile.ps1').replaceAll("'", "''");
  const script = `
$ErrorActionPreference = 'Stop'
$source = Get-Content -Raw -LiteralPath '${startScript}'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw ($errors | Out-String) }
foreach ($name in @('Test-WindowsFirewallProfileEnabled', 'Test-WindowsFirewallDefaultInboundBlocked', 'Assert-ActiveFirewallProfileClosed')) {
  $function = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
  if (-not $function) { throw "Missing function $name" }
  Invoke-Expression $function.Extent.Text
}
$connection = [pscustomobject]@{ NetworkCategory = 'Public'; InterfaceAlias = 'Wi-Fi' }
$disabledMessage = $null
try {
  Assert-ActiveFirewallProfileClosed ([pscustomobject]@{ Name = 'Public'; Enabled = $false; DefaultInboundAction = 'Block' }) $connection
  $disabledMessage = 'NO_THROW'
} catch {
  $disabledMessage = $_.Exception.Message
}
$allowMessage = $null
try {
  Assert-ActiveFirewallProfileClosed ([pscustomobject]@{ Name = 'Public'; Enabled = $true; DefaultInboundAction = 'Allow' }) $connection
  $allowMessage = 'NO_THROW'
} catch {
  $allowMessage = $_.Exception.Message
}
[pscustomobject]@{
  EnabledTrue = Test-WindowsFirewallProfileEnabled $true
  EnabledFalse = Test-WindowsFirewallProfileEnabled $false
  InboundBlock = Test-WindowsFirewallDefaultInboundBlocked 'Block'
  InboundAllow = Test-WindowsFirewallDefaultInboundBlocked 'Allow'
  DisabledMessage = $disabledMessage
  AllowMessage = $allowMessage
} | ConvertTo-Json -Compress
`;
  const result = JSON.parse(execFileSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script], {
    encoding: 'utf8',
    windowsHide: true,
  }));

  assert.equal(result.EnabledTrue, true);
  assert.equal(result.EnabledFalse, false);
  assert.equal(result.InboundBlock, true);
  assert.equal(result.InboundAllow, false);
  assert.match(result.DisabledMessage, /Windows Firewall is disabled for active Public profile/);
  assert.match(result.AllowMessage, /default inbound action is Allow, not Block/);
});

test('desktop launcher firewall shadow helper rejects broader LocalSubnet gateway executable rules', () => {
  const startScript = path.join(root, 'scripts', 'Start-StMobile.ps1').replaceAll("'", "''");
  const script = `
$ErrorActionPreference = 'Stop'
$source = Get-Content -Raw -LiteralPath '${startScript}'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw ($errors | Out-String) }
foreach ($name in @('Test-FirewallLocalPortIncludes', 'Test-FirewallLocalPortExactly', 'Test-FirewallProgramAppliesToGateway', 'Test-FirewallRuleHasExactGatewayScope', 'Test-FirewallRuleShadowsGatewayScope')) {
  $function = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
  if (-not $function) { throw "Missing function $name" }
  Invoke-Expression $function.Extent.Text
}
$nodePath = 'C:\\Program Files\\nodejs\\node.exe'
$exactGateway = [pscustomobject]@{ Enabled = 'Yes'; Direction = 'In'; Action = 'Allow'; Program = 'Any'; Protocol = 'TCP'; LocalPort = '38443'; RemoteIP = 'LocalSubnet' }
$broadLocalSubnetNode = [pscustomobject]@{ Enabled = 'Yes'; Direction = 'In'; Action = 'Allow'; Program = 'C:\\Program Files\\nodejs\\node.exe'; Protocol = 'TCP'; LocalPort = 'Any'; RemoteIP = 'LocalSubnet' }
$broadListProgramAny = [pscustomobject]@{ Enabled = 'Yes'; Direction = 'In'; Action = 'Allow'; Program = 'Any'; Protocol = 'TCP'; LocalPort = '80, 38443'; RemoteIP = 'LocalSubnet' }
$broadRangeProgramAny = [pscustomobject]@{ Enabled = 'Yes'; Direction = 'In'; Action = 'Allow'; Program = 'Any'; Protocol = 'TCP'; LocalPort = '38400-38500'; RemoteIP = 'LocalSubnet' }
$protocolAnyExactPort = [pscustomobject]@{ Enabled = 'Yes'; Direction = 'In'; Action = 'Allow'; Program = 'Any'; Protocol = 'Any'; LocalPort = '38443'; RemoteIP = 'LocalSubnet' }
$otherProgram = [pscustomobject]@{ Enabled = 'Yes'; Direction = 'In'; Action = 'Allow'; Program = 'C:\\Other\\node.exe'; Protocol = 'TCP'; LocalPort = 'Any'; RemoteIP = 'LocalSubnet' }
[pscustomobject]@{
  ExactGateway = Test-FirewallRuleShadowsGatewayScope $exactGateway 38443 $nodePath
  BroadLocalSubnetNode = Test-FirewallRuleShadowsGatewayScope $broadLocalSubnetNode 38443 $nodePath
  BroadListProgramAny = Test-FirewallRuleShadowsGatewayScope $broadListProgramAny 38443 $nodePath
  BroadRangeProgramAny = Test-FirewallRuleShadowsGatewayScope $broadRangeProgramAny 38443 $nodePath
  ProtocolAnyExactPort = Test-FirewallRuleShadowsGatewayScope $protocolAnyExactPort 38443 $nodePath
  OtherProgram = Test-FirewallRuleShadowsGatewayScope $otherProgram 38443 $nodePath
} | ConvertTo-Json -Compress
`;
  const result = JSON.parse(execFileSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script], {
    encoding: 'utf8',
    windowsHide: true,
  }));

  assert.deepEqual(result, {
    ExactGateway: false,
    BroadLocalSubnetNode: true,
    BroadListProgramAny: true,
    BroadRangeProgramAny: true,
    ProtocolAnyExactPort: true,
    OtherProgram: false,
  });
});

test('desktop launcher named gateway rule helper rejects wrong program and broad profiles', () => {
  const startScript = path.join(root, 'scripts', 'Start-StMobile.ps1').replaceAll("'", "''");
  const script = `
$ErrorActionPreference = 'Stop'
$source = Get-Content -Raw -LiteralPath '${startScript}'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw ($errors | Out-String) }
foreach ($name in @('Test-FirewallNamedProgramAppliesToGateway', 'Test-FirewallProfilesExactly')) {
  $function = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
  if (-not $function) { throw "Missing function $name" }
  Invoke-Expression $function.Extent.Text
}
$nodePath = 'C:\\Program Files\\nodejs\\node.exe'
[pscustomobject]@{
  ProgramAny = Test-FirewallNamedProgramAppliesToGateway 'Any' $nodePath
  ProgramExact = Test-FirewallNamedProgramAppliesToGateway 'C:\\Program Files\\nodejs\\node.exe' $nodePath
  ProgramWrong = Test-FirewallNamedProgramAppliesToGateway 'C:\\Other\\not-gateway.exe' $nodePath
  ProgramBlankAsNetshAny = Test-FirewallNamedProgramAppliesToGateway '' $nodePath
  ProfilePublic = Test-FirewallProfilesExactly 'Public' 'Public'
  ProfileAny = Test-FirewallProfilesExactly 'Any' 'Public'
  ProfileMulti = Test-FirewallProfilesExactly 'Private, Public' 'Public'
} | ConvertTo-Json -Compress
`;
  const result = JSON.parse(execFileSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script], {
    encoding: 'utf8',
    windowsHide: true,
  }));

  assert.deepEqual(result, {
    ProgramAny: true,
    ProgramExact: true,
    ProgramWrong: false,
    ProgramBlankAsNetshAny: true,
    ProfilePublic: true,
    ProfileAny: false,
    ProfileMulti: false,
  });
});

test('desktop launcher named gateway rule helper rejects duplicate active same-named rules', () => {
  const startScript = path.join(root, 'scripts', 'Start-StMobile.ps1').replaceAll("'", "''");
  const script = `
$ErrorActionPreference = 'Stop'
$source = Get-Content -Raw -LiteralPath '${startScript}'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw ($errors | Out-String) }
foreach ($name in @('Test-FirewallNamedProgramAppliesToGateway', 'Test-FirewallProfilesExactly', 'Test-ActiveNamedGatewayRulesExactly')) {
  $function = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
  if (-not $function) { throw "Missing function $name" }
  Invoke-Expression $function.Extent.Text
}
$nodePath = 'C:\\Program Files\\nodejs\\node.exe'
$exact = [pscustomobject]@{ Enabled = 'Yes'; Direction = 'In'; Action = 'Allow'; Profiles = 'Public'; Program = ''; Protocol = 'TCP'; LocalPort = '38443'; RemoteIP = 'LocalSubnet' }
$wrongProgram = [pscustomobject]@{ Enabled = 'Yes'; Direction = 'In'; Action = 'Allow'; Profiles = 'Public'; Program = 'C:\\Other\\not-gateway.exe'; Protocol = 'TCP'; LocalPort = '38443'; RemoteIP = 'LocalSubnet' }
$broadProfile = [pscustomobject]@{ Enabled = 'Yes'; Direction = 'In'; Action = 'Allow'; Profiles = 'Private, Public'; Program = ''; Protocol = 'TCP'; LocalPort = '38443'; RemoteIP = 'LocalSubnet' }
$disabledWrong = [pscustomobject]@{ Enabled = 'No'; Direction = 'In'; Action = 'Allow'; Profiles = 'Public'; Program = 'C:\\Other\\not-gateway.exe'; Protocol = 'TCP'; LocalPort = '38443'; RemoteIP = 'LocalSubnet' }
[pscustomobject]@{
  SingleExact = Test-ActiveNamedGatewayRulesExactly @($exact) 38443 'Public' $nodePath
  ExactPlusWrong = Test-ActiveNamedGatewayRulesExactly @($exact, $wrongProgram) 38443 'Public' $nodePath
  ExactPlusBroadProfile = Test-ActiveNamedGatewayRulesExactly @($exact, $broadProfile) 38443 'Public' $nodePath
  ExactPlusDisabledWrong = Test-ActiveNamedGatewayRulesExactly @($exact, $disabledWrong) 38443 'Public' $nodePath
} | ConvertTo-Json -Compress
`;
  const result = JSON.parse(execFileSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script], {
    encoding: 'utf8',
    windowsHide: true,
  }));

  assert.deepEqual(result, {
    SingleExact: true,
    ExactPlusWrong: false,
    ExactPlusBroadProfile: false,
    ExactPlusDisabledWrong: true,
  });
});
