import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { link, mkdir, mkdtemp, open, readFile, readdir, rename, rm, stat, symlink, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
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

test('desktop auth hub is loopback-only and launched with the gateway', async () => {
  const start = await text('scripts/Start-StMobile.ps1');
  const stop = await text('scripts/Stop-StMobile.ps1');
  const cli = await text('gateway/src/cli.js');
  const server = await text('gateway/src/server.js');
  const hub = await text('gateway/src/hub.js');

  assert.match(start, /\[int\]\$HubPort = 38444/);
  assert.match(start, /\$HubUrlFile = Join-Path \$StateRoot 'auth-hub\.url'/);
  assert.match(start, /\$GatewayProcessRecord = Join-Path \$StateRoot 'gateway-process\.json'/);
  assert.match(start, /\$SillyTavernProcessRecord = Join-Path \$StateRoot 'sillytavern-process\.json'/);
  assert.match(start, /schema = 'st-mobile-gateway-process\/v1'/);
  assert.match(start, /Get-StMobileGatewayOwnershipState/);
  assert.match(start, /'OwnedLive'|'OwnedStale'|'Conflict'/);
  assert.match(start, /Get-SillyTavernSession/);
  assert.match(start, /Start it through ST Launcher option 1/);
  assert.match(start, /Clear-StaleGatewayOwnershipForLaunch/);
  assert.match(start, /ServerScriptPath = \$serverScript/);
  assert.match(start, /--hub-port', "\$HubPort"/);
  assert.match(start, /is not running the auth hub on expected loopback port \$HubPort/);
  assert.match(start, /explicitly disabled the auth hub/);
  assert.match(start, /function Assert-AuthHubReady/);
  assert.match(start, /http:\/\/127\.0\.0\.1:\$HubPort\/api\/devices/);
  assert.match(start, /Auth hub readiness probe returned unexpected gatewayUrl/);
  assert.match(start, /Publish-StMobileAuthHubUrlRecord/);
  assert.match(start, /verifiedGatewayForHubRecord/);
  assert.doesNotMatch(start, /Set-Content -LiteralPath \$HubUrlFile/);
  assert.match(stop, /Publish-StMobileAuthHubUrlRecord/);
  assert.doesNotMatch(stop, /Remove-Item -LiteralPath \$HubUrlFile/);
  assert.match(stop, /Get-StMobileGatewayOwnershipState/);
  assert.match(stop, /TerminatePinnedProcess/);
  assert.match(stop, /\$SillyTavernProcessRecord/);
  assert.match(stop, /PID, start time, executable, exact argv, and ownership record agree/);
  assert.doesNotMatch(stop, /function Stop-FromPidFile/);
  assert.match(cli, /--hub-port 38444/);
  assert.match(cli, /parsePort\(argValue\(args, '--hub-port', 38444\), '--hub-port'\)/);
  assert.match(cli, /Auth hub: \$\{gateway\.hub\.url\}/);
  assert.match(server, /hubPort/);
  assert.match(server, /createAuthHubServer/);
  assert.match(hub, /auth hub must bind to loopback only/);
  assert.match(hub, /isAllowedHubHost/);
  assert.match(hub, /isAllowedHubOrigin/);
  assert.match(hub, /Forbidden hub origin/);
  assert.match(hub, /HUB_MUTATION_HEADER = 'x-st-mobile-hub'/);
  assert.match(hub, /HUB_SERVICE_ID = 'sillytavern-mobile-auth-hub'/);
  assert.match(hub, /HUB_SCHEMA_VERSION = 1/);
  assert.match(hub, /QRCode\.toDataURL/);
  assert.match(hub, /pendingPairings/);
  assert.match(hub, /getConnectionSnapshot/);
  assert.match(hub, /closeRevokedSockets/);
  assert.match(hub, /Attribution/);
  assert.match(hub, /Background tray host/);
  assert.match(hub, /Start with Windows/);
  assert.match(hub, /Update &amp; Start SillyTavern/);
  assert.match(hub, /docs\.sillytavern\.app\/licensecredits\//);
  assert.doesNotMatch(hub, /innerHTML/);
});

test('desktop hub tray is single-instance, hidden, Idle, and opt-in at Windows startup', async () => {
  const tray = await text('scripts/Start-StMobileTray.ps1');
  const launch = await text('scripts/Launch-StMobileTray.ps1');
  const stop = await text('scripts/Stop-StMobileTray.ps1');
  const common = await text('scripts/StMobileTrayCommon.ps1');

  assert.match(tray, /System\.Windows\.Forms\.NotifyIcon/);
  assert.match(tray, /Local\\SillyTavernMobileAuthHubTray/);
  assert.match(tray, /Start with Windows/);
  assert.match(tray, /SpecialFolder\]::Startup/);
  assert.match(tray, /Refusing to remove modified or unrecognized startup shortcut/);
  assert.match(tray, /'-WindowStyle', 'Hidden'/);
  assert.match(tray, /CreateNoWindow = \$true/);
  assert.match(tray, /ProcessWindowStyle\]::Hidden/);
  assert.match(tray, /ProcessPriorityClass\]::Idle/);
  assert.match(tray, /-NoStartSillyTavern/);
  assert.match(tray, /AutoStartSuppressed/);
  assert.match(tray, /AddSeconds\(30\)/);
  assert.match(tray, /\$MaxAutoStartAttempts = 3/);
  assert.match(tray, /st-mobile-gateway-retry\/v1/);
  assert.match(tray, /RETRY_STATE_RESTORED/);
  assert.match(tray, /st-mobile-gateway-suppression\/v1/);
  assert.match(tray, /sillytavern-mobile-auth-hub/);
  assert.match(tray, /Open SillyTavern on Desktop/);
  assert.match(tray, /Open-VerifiedSillyTavernDesktop/);
  assert.match(tray, /Get-SillyTavernSession[\s\S]*-ThrowOnInvalid[\s\S]*Start-Process -FilePath "http:\/\/127\.0\.0\.1:\$Port\/"/);
  assert.match(tray, /\$openSillyTavernItem\.Enabled = \$stReady/);
  assert.match(tray, /schema = 'st-mobile-tray-process\/v2'/);
  assert.match(tray, /stopCapability = \[guid\]::NewGuid\(\)\.ToString\('D'\)/);
  assert.match(common, /CommandLineToArgvW/);
  assert.match(common, /record\.stopCapability -cne \[string\]\$TrayRecord\.stopCapability/);
  assert.match(common, /Get-StMobileWindowsPowerShellExecutable/);
  assert.match(common, /Test-StMobileExactTrayArguments/);
  assert.match(common, /Test-StMobileExactGatewayArguments/);
  assert.match(common, /Get-VerifiedStMobileGatewayProcess/);
  assert.match(common, /Get-StMobileSillyTavernCandidateSession/);
  assert.match(common, /Write-StMobileSillyTavernRecord/);
  assert.match(common, /st-mobile-sillytavern-process\/v1/);
  assert.match(common, /Test-SillyTavernHttpIdentity/);
  assert.match(common, /arguments\.Count -ne 2/);
  assert.doesNotMatch(tray, /EfficiencyMode|EcoQoS|PowerThrottling/);

  assert.match(launch, /-STA/);
  assert.match(launch, /-WindowStyle', 'Hidden/);
  assert.match(launch, /CreateNoWindow = \$true/);
  assert.match(launch, /ProcessPriorityClass\]::Idle/);
  assert.match(launch, /MainWindowHandle -ne 0/);
  assert.match(launch, /Get-VerifiedTrayProcess/);
  assert.match(launch, /-ExpectedHubPort \$HubPort/);
  assert.match(launch, /-ExpectedSillyTavernPort \$SillyTavernPort/);
  assert.match(launch, /-ExpectedSillyTavernRoot \$SillyTavernRoot/);
  assert.match(launch, /-ExpectedLauncherIconPath \$LauncherIconPath/);
  assert.match(stop, /tray\.stop\.request/);
  assert.match(stop, /New-StMobileTrayStopRequestBytes/);
  assert.match(stop, /Write-StMobileBytesCreateNew \$TrayStopFile \$stopRequestBytes/);
  assert.match(stop, /Get-StMobileOwnedTrayStopRequest/);
  assert.doesNotMatch(stop, /Set-Content -LiteralPath \$TrayStopFile/);
  assert.match(tray, /Get-StMobileOwnedTrayStopRequest/);
  assert.match(tray, /accepted=false preserved=true/);
  assert.doesNotMatch(tray, /Remove-Item -LiteralPath \$TrayStopFile -Force/);
  assert.match(tray, /PinnedFileOperations\]::PinParent/);
  assert.match(tray, /ShellLinkSerializer\]::SerializeAndValidate/);
  assert.match(tray, /publishedIdentity = \[StMobile\.PinnedFileOperations\]::CreateNew/);
  assert.match(tray, /\$shortcutBytes/);
  assert.match(tray, /publishedIdentity\.FileToken/);
  const startupSetter = tray.slice(
    tray.indexOf('function Set-StartupShortcut'),
    tray.indexOf('function Test-TcpListener'));
  assert.doesNotMatch(startupSetter, /temporaryShortcutPath|\.Save\(\)|Move-Item|Remove-Item/);
  assert.match(stop, /Get-VerifiedTrayProcess/);
  assert.match(stop, /Assert-StMobilePinnedProcessIdentity/);
  assert.match(stop, /TerminatePinnedProcess/);
  assert.match(stop, /PriorityClass = \[System\.Diagnostics\.ProcessPriorityClass\]::Idle/);
});

test('tray desktop-open action revalidates the exact ST session before opening loopback', async () => {
  const tray = await text('scripts/Start-StMobileTray.ps1');
  const start = tray.indexOf('function Open-VerifiedSillyTavernDesktop');
  const end = tray.indexOf('$context = New-Object System.Windows.Forms.ApplicationContext', start);
  assert.ok(start >= 0 && end > start);
  const helperSource = tray.slice(start, end);
  assert.doesNotMatch(helperSource, /Start-GatewayAttempt|Start-HiddenIdlePowerShell|Start-StMobile\.ps1/);
  const helper = helperSource.replaceAll("'", "''");
  const result = JSON.parse(execFileSync('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-Command', `
$ErrorActionPreference='Stop'
$script:failVerification=$false
$script:opened=$null
$script:verification=$null
function Get-SillyTavernSession {
  param([int]$Port,[string]$SillyTavernRoot,[string]$RecordPath,[switch]$ThrowOnInvalid)
  $script:verification=[pscustomobject]@{port=$Port;root=$SillyTavernRoot;record=$RecordPath;throwOnInvalid=$ThrowOnInvalid.IsPresent}
  if($script:failVerification){return $null}
  return [pscustomobject]@{Key='verified-session'}
}
function Start-Process { param([string]$FilePath);$script:opened=$FilePath }
Invoke-Expression '${helper}'
Open-VerifiedSillyTavernDesktop -Port 3000 -Root 'C:\\VerifiedST' -RecordPath 'C:\\State\\sillytavern-process.json'
$success=[pscustomobject]@{opened=$script:opened;verification=$script:verification}
$script:opened=$null
$script:failVerification=$true
$blocked=$false
try{Open-VerifiedSillyTavernDesktop -Port 3000 -Root 'C:\\VerifiedST' -RecordPath 'C:\\State\\sillytavern-process.json'}catch{$blocked=$_.Exception.Message -like '*No live root-verified*'}
[pscustomobject]@{success=$success;blocked=$blocked;openedAfterFailure=$script:opened}|ConvertTo-Json -Depth 5 -Compress
`,
  ], { encoding: 'utf8', windowsHide: true }));
  assert.deepEqual(result, {
    success: {
      opened: 'http://127.0.0.1:3000/',
      verification: {
        port: 3000,
        root: 'C:\\VerifiedST',
        record: 'C:\\State\\sillytavern-process.json',
        throwOnInvalid: true,
      },
    },
    blocked: true,
    openedAfterFailure: null,
  });
});

test('auth-hub URL and tray-stop control records are canonical, instance-bound, and reparse-safe', async () => {
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'st-mobile-control-records-'));
  const realRoot = path.join(temporaryRoot, 'real');
  const aliasRoot = path.join(temporaryRoot, 'alias');
  await mkdir(realRoot, { recursive: true });
  const common = path.join(root, 'scripts', 'StMobileTrayCommon.ps1').replaceAll("'", "''");
  const escapedTemporaryRoot = temporaryRoot.replaceAll("'", "''");
  const escapedRealRoot = realRoot.replaceAll("'", "''");
  const escapedAliasRoot = aliasRoot.replaceAll("'", "''");
  try {
    const script = `
$ErrorActionPreference = 'Stop'
. '${common}'
New-Item -ItemType Junction -Path '${escapedAliasRoot}' -Target '${escapedRealRoot}' | Out-Null
$gateway = [pscustomobject][ordered]@{
  instanceId='00000000-0000-0000-0000-000000000101'; pid=[int]101
  processStartTimeUtc='2026-07-11T12:00:00.000Z'; hubPort=[int]38444
}
$tray = [pscustomobject][ordered]@{
  instanceId='00000000-0000-0000-0000-000000000202'; pid=[int]202
  processStartTimeUtc='2026-07-11T12:00:01.000Z'
  stopCapability='00000000-0000-0000-0000-000000000212'
}
$hubPath = Join-Path '${escapedTemporaryRoot}' 'auth-hub.url'
$publishedHub = Publish-StMobileAuthHubUrlRecord $hubPath $gateway
$readHub = Get-StMobileOwnedAuthHubUrlRecord $hubPath $gateway
$hubExact = Test-BytesEqual $publishedHub.Bytes $readHub.Bytes
$hubIdempotent = Test-BytesEqual (Publish-StMobileAuthHubUrlRecord $hubPath $gateway).Bytes $publishedHub.Bytes
$legacyHubPath = Join-Path '${escapedTemporaryRoot}' 'legacy-auth-hub.url'
$legacyHubBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes('http://127.0.0.1:38444/' + [Environment]::NewLine)
[System.IO.File]::WriteAllBytes($legacyHubPath, $legacyHubBytes)
$migratedHub = Publish-StMobileAuthHubUrlRecord $legacyHubPath $gateway -AllowLegacyUrlCas
$legacyCasExact = Test-BytesEqual $migratedHub.Bytes (New-StMobileAuthHubUrlRecordBytes $gateway)
$legacyCasArtifactsClean = @(Get-ChildItem -LiteralPath '${escapedTemporaryRoot}' -Force | Where-Object Name -Like 'legacy-auth-hub.url.st-mobile-legacy-*').Count -eq 0
$foreignHubPath = Join-Path '${escapedTemporaryRoot}' 'foreign-auth-hub.url'
$foreignHubBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes('foreign hub bytes')
[System.IO.File]::WriteAllBytes($foreignHubPath, $foreignHubBytes)
$foreignHubRejected = $false
try { [void](Publish-StMobileAuthHubUrlRecord $foreignHubPath $gateway) } catch { $foreignHubRejected = $true }
$foreignHubPreserved = Test-BytesEqual ([System.IO.File]::ReadAllBytes($foreignHubPath)) $foreignHubBytes
$reparseHubPath = Join-Path '${escapedAliasRoot}' 'auth-hub.url'
$reparseHubRejected = $false
try { [void](Publish-StMobileAuthHubUrlRecord $reparseHubPath $gateway) } catch { $reparseHubRejected = $true }
$reparseHubTargetAbsent = -not (Test-Path -LiteralPath (Join-Path '${escapedRealRoot}' 'auth-hub.url'))
$requestPath = Join-Path '${escapedTemporaryRoot}' 'tray.stop.request'
$nonce = '00000000-0000-0000-0000-000000000303'
$requestBytes = New-StMobileTrayStopRequestBytes $tray $nonce
Write-StMobileBytesCreateNew $requestPath $requestBytes
$request = Get-StMobileOwnedTrayStopRequest $requestPath $tray
$requestExact = (Test-BytesEqual $request.Bytes $requestBytes) -and $request.Record.requestNonce -ceq $nonce -and $request.Record.stopCapability -ceq $tray.stopCapability
$wrongTray = $tray.PSObject.Copy(); $wrongTray.instanceId='00000000-0000-0000-0000-000000000404'
$wrongInstanceRejected = $false
try { [void](Get-StMobileOwnedTrayStopRequest $requestPath $wrongTray) } catch { $wrongInstanceRejected = $true }
$requestPreserved = Test-BytesEqual ([System.IO.File]::ReadAllBytes($requestPath)) $requestBytes
$forgedRequestPath = Join-Path '${escapedTemporaryRoot}' 'forged.stop.request'
$forgedTray = $tray.PSObject.Copy(); $forgedTray.stopCapability='00000000-0000-0000-0000-000000000505'
$forgedRequestBytes = New-StMobileTrayStopRequestBytes $forgedTray '00000000-0000-0000-0000-000000000506'
Write-StMobileBytesCreateNew $forgedRequestPath $forgedRequestBytes
$arbitraryCapabilityRejected = $false
try { [void](Get-StMobileOwnedTrayStopRequest $forgedRequestPath $tray) } catch { $arbitraryCapabilityRejected = $true }
$forgedRequestPreserved = Test-BytesEqual ([System.IO.File]::ReadAllBytes($forgedRequestPath)) $forgedRequestBytes
$foreignRequestPath = Join-Path '${escapedTemporaryRoot}' 'foreign.stop.request'
$foreignRequestBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes('foreign stop bytes')
[System.IO.File]::WriteAllBytes($foreignRequestPath, $foreignRequestBytes)
$foreignRequestCreateNewRejected = $false
try { Write-StMobileBytesCreateNew $foreignRequestPath $requestBytes } catch { $foreignRequestCreateNewRejected = $true }
$foreignRequestRejected = $false
try { [void](Get-StMobileOwnedTrayStopRequest $foreignRequestPath $tray) } catch { $foreignRequestRejected = $true }
$foreignRequestPreserved = Test-BytesEqual ([System.IO.File]::ReadAllBytes($foreignRequestPath)) $foreignRequestBytes
$reparseRequestTarget = Join-Path '${escapedRealRoot}' 'tray.stop.request'
[System.IO.File]::WriteAllBytes($reparseRequestTarget, $requestBytes)
$reparseRequestRejected = $false
try { [void](Get-StMobileOwnedTrayStopRequest (Join-Path '${escapedAliasRoot}' 'tray.stop.request') $tray) } catch { $reparseRequestRejected = $true }
$reparseRequestCleanupRejected = $false
try { Remove-StMobileFileIfUnchanged (Join-Path '${escapedAliasRoot}' 'tray.stop.request') $requestBytes 'test reparse request' } catch { $reparseRequestCleanupRejected = $true }
$reparseRequestPreserved = Test-BytesEqual ([System.IO.File]::ReadAllBytes($reparseRequestTarget)) $requestBytes
[pscustomobject]@{
  hubExact=$hubExact; hubIdempotent=$hubIdempotent
  legacyCasExact=$legacyCasExact; legacyCasArtifactsClean=$legacyCasArtifactsClean
  foreignHubRejected=$foreignHubRejected; foreignHubPreserved=$foreignHubPreserved
  reparseHubRejected=$reparseHubRejected; reparseHubTargetAbsent=$reparseHubTargetAbsent
  requestExact=$requestExact; wrongInstanceRejected=$wrongInstanceRejected; requestPreserved=$requestPreserved
  arbitraryCapabilityRejected=$arbitraryCapabilityRejected; forgedRequestPreserved=$forgedRequestPreserved
  foreignRequestCreateNewRejected=$foreignRequestCreateNewRejected
  foreignRequestRejected=$foreignRequestRejected; foreignRequestPreserved=$foreignRequestPreserved
  reparseRequestRejected=$reparseRequestRejected; reparseRequestCleanupRejected=$reparseRequestCleanupRejected
  reparseRequestPreserved=$reparseRequestPreserved
} | ConvertTo-Json -Compress
`;
    const result = JSON.parse(execFileSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script,
    ], { encoding: 'utf8', windowsHide: true }));
    assert.deepEqual(result, {
      hubExact: true,
      hubIdempotent: true,
      legacyCasExact: true,
      legacyCasArtifactsClean: true,
      foreignHubRejected: true,
      foreignHubPreserved: true,
      reparseHubRejected: true,
      reparseHubTargetAbsent: true,
      requestExact: true,
      wrongInstanceRejected: true,
      requestPreserved: true,
      arbitraryCapabilityRejected: true,
      forgedRequestPreserved: true,
      foreignRequestCreateNewRejected: true,
      foreignRequestRejected: true,
      foreignRequestPreserved: true,
      reparseRequestRejected: true,
      reparseRequestCleanupRejected: true,
      reparseRequestPreserved: true,
    });
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test('hidden child launch returns its committed process despite post-start logging failure', async () => {
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'st-mobile-post-start-'));
  const common = path.join(root, 'scripts', 'StMobileTrayCommon.ps1').replaceAll("'", "''");
  const trayScript = path.join(root, 'scripts', 'Start-StMobileTray.ps1').replaceAll("'", "''");
  const childScript = path.join(temporaryRoot, 'child.ps1');
  await writeFile(childScript, 'Start-Sleep -Milliseconds 100\r\n', 'utf8');
  try {
    const result = JSON.parse(execFileSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-Command', `
$ErrorActionPreference='Stop';. '${common}'
$tokens=$null;$errors=$null;$ast=[System.Management.Automation.Language.Parser]::ParseFile('${trayScript}',[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n)$n -is [System.Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq'Start-HiddenIdlePowerShell'},$true)
$functionText=$node.Extent.Text;. ([scriptblock]::Create($functionText));$PowerShellExe=(Get-Command powershell.exe).Source;$ProjectRoot='${temporaryRoot.replaceAll("'", "''")}'
function Write-TrayLog { throw 'post-start-log-sentinel' }
$process=Start-HiddenIdlePowerShell '${childScript.replaceAll("'", "''")}' @() 'post_start_test'
$returned=$null-ne$process;$pidValue=$process.Id;$priority=[string]$process.PriorityClass
$process.WaitForExit(5000)|Out-Null;$exited=$process.HasExited;$process.Dispose()
$priorityFailureText=$functionText.Replace('$process.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle',"throw 'post-start-priority-sentinel'")
. ([scriptblock]::Create($priorityFailureText));$priorityFailureProcess=Start-HiddenIdlePowerShell '${childScript.replaceAll("'", "''")}' @() 'priority_failure_test'
$priorityFailureReturned=$null-ne$priorityFailureProcess;$priorityFailureProcess.WaitForExit(5000)|Out-Null;$priorityFailureExited=$priorityFailureProcess.HasExited;$priorityFailureProcess.Dispose()
[pscustomobject]@{returned=$returned;pidPositive=$pidValue-gt0;priority=$priority;exited=$exited;priorityFailureReturned=$priorityFailureReturned;priorityFailureExited=$priorityFailureExited}|ConvertTo-Json -Compress
`,
    ], { encoding: 'utf8', windowsHide: true }));
    assert.deepEqual(result, { returned: true, pidPositive: true, priority: 'Idle', exited: true, priorityFailureReturned: true, priorityFailureExited: true });
  } finally { await rm(temporaryRoot, { recursive: true, force: true }); }
});

test('pinned create and exact-generation delete block between-check junction retargets', { timeout: 30_000 }, async () => {
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'st-mobile-pinned-race-'));
  const common = path.join(root, 'scripts', 'StMobileTrayCommon.ps1').replaceAll("'", "''");

  async function waitForPath(target, worker) {
    const deadline = Date.now() + 8_000;
    while (Date.now() < deadline) {
      try {
        await stat(target);
        return;
      } catch {}
      if (worker.exitCode !== null) throw new Error(`pinned worker exited before marker: ${worker.exitCode}`);
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    throw new Error(`timed out waiting for pinned-operation marker: ${target}`);
  }

  async function runRace(operation) {
    const caseRoot = path.join(temporaryRoot, operation);
    const active = path.join(caseRoot, 'active');
    const saved = path.join(caseRoot, 'saved');
    const foreign = path.join(caseRoot, 'foreign');
    const marker = path.join(caseRoot, 'pinned.marker');
    const continuation = path.join(caseRoot, 'continue.marker');
    const ownedPath = path.join(active, 'control.bin');
    const foreignPath = path.join(foreign, 'control.bin');
    await mkdir(active, { recursive: true });
    await mkdir(foreign, { recursive: true });
    if (operation === 'move' || operation === 'delete') await writeFile(ownedPath, Buffer.from('owned-delete', 'utf8'));
    await writeFile(foreignPath, Buffer.from('foreign-preserve', 'utf8'));

    const workerScript = `
$ErrorActionPreference = 'Stop'
[System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle
. '${common}'
$binding = [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static
$type = [StMobile.PinnedFileOperations]
$type.GetMethod('ConfigurePinnedInterlock', $binding).Invoke($null, @(
  $env:ST_MOBILE_TEST_PINNED_OPERATION,
  $env:ST_MOBILE_TEST_PINNED_MARKER,
  $env:ST_MOBILE_TEST_PINNED_CONTINUE)) | Out-Null
$bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes('${operation === 'create' ? 'owned-create' : 'owned-delete'}')
$snapshot = if ('${operation}' -ne 'create') { [StMobile.PinnedFileOperations]::ReadSnapshot('${ownedPath.replaceAll("'", "''")}', '') } else { $null }
${operation === 'create'
    ? `Write-StMobileBytesCreateNew '${ownedPath.replaceAll("'", "''")}' $bytes`
    : operation === 'move'
      ? `Remove-StMobileFileIfUnchanged '${ownedPath.replaceAll("'", "''")}' $bytes 'junction-race fixture' $snapshot.ParentToken $snapshot.FileToken`
      : `[StMobile.PinnedFileOperations]::DeleteExact('${ownedPath.replaceAll("'", "''")}', $bytes, $snapshot.ParentToken, $snapshot.FileToken)`}
`;
    const worker = spawn('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass',
      '-Command', workerScript,
    ], {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      env: {
        ...process.env,
        ST_MOBILE_TEST_PINNED_OPERATION: operation,
        ST_MOBILE_TEST_PINNED_MARKER: marker,
        ST_MOBILE_TEST_PINNED_CONTINUE: continuation,
      },
    });
    const stderr = [];
    worker.stderr.on('data', (chunk) => stderr.push(chunk));
    await waitForPath(marker, worker);

    let retargetBlocked = false;
    let retargetSucceeded = false;
    let inPlaceWriteBlocked = operation === 'create';
    try {
      await rename(active, saved);
      await symlink(foreign, active, 'junction');
      retargetSucceeded = true;
    } catch {
      retargetBlocked = true;
    } finally {
      if (operation === 'move' || operation === 'delete') {
        try {
          await writeFile(ownedPath, Buffer.from('foreign-in-place-write', 'utf8'));
        } catch {
          inPlaceWriteBlocked = true;
        }
      }
      await writeFile(continuation, 'continue', 'utf8');
    }
    const [exitCode] = await once(worker, 'exit');
    if (retargetSucceeded) {
      await rm(active, { force: true });
      await rename(saved, active);
    }
    assert.equal(exitCode, 0, Buffer.concat(stderr).toString('utf8'));
    assert.equal(retargetBlocked, true, `${operation} parent retarget unexpectedly succeeded while pinned`);
    assert.equal(inPlaceWriteBlocked, true, `${operation} allowed an in-place write after exact-byte validation`);
    assert.deepEqual(await readFile(foreignPath), Buffer.from('foreign-preserve', 'utf8'));
    if (operation === 'create') {
      assert.deepEqual(await readFile(ownedPath), Buffer.from('owned-create', 'utf8'));
    } else {
      await assert.rejects(readFile(ownedPath), /ENOENT/);
    }
  }

  try {
    await runRace('create');
    await runRace('move');
    await runRace('delete');
    const generationRoot = path.join(temporaryRoot, 'same-bytes-generation');
    await mkdir(generationRoot, { recursive: true });
    const source = path.join(generationRoot, 'source.bin').replaceAll("'", "''");
    const destination = path.join(generationRoot, 'destination.bin').replaceAll("'", "''");
    const generationScript = `
$ErrorActionPreference = 'Stop'
. '${common}'
$bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes('same bytes, different generation')
Write-StMobileBytesCreateNew '${source}' $bytes
$old = [StMobile.PinnedFileOperations]::InspectExact('${source}', $bytes, '', '')
[StMobile.PinnedFileOperations]::DeleteExact('${source}', $bytes, $old.ParentToken, $old.FileToken)
Write-StMobileBytesCreateNew '${source}' $bytes
$new = [StMobile.PinnedFileOperations]::InspectExact('${source}', $bytes, '', '')
$blocked = $false
$deleteBlocked = $false
try {
  [void][StMobile.PinnedFileOperations]::MoveExact('${source}', '${destination}', $bytes, $old.ParentToken, $old.FileToken)
} catch { $blocked = $true }
try {
  [StMobile.PinnedFileOperations]::DeleteExact('${source}', $bytes, $old.ParentToken, $old.FileToken)
} catch { $deleteBlocked = $true }
[pscustomobject]@{
  generationChanged = $old.FileToken -cne $new.FileToken
  staleTokenBlocked = $blocked
  staleDeleteTokenBlocked = $deleteBlocked
  sourcePreserved = Test-Path -LiteralPath '${source}'
  destinationAbsent = -not (Test-Path -LiteralPath '${destination}')
} | ConvertTo-Json -Compress
`;
    const generationResult = JSON.parse(execFileSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass',
      '-Command', generationScript,
    ], { encoding: 'utf8', windowsHide: true }));
    assert.deepEqual(generationResult, {
      generationChanged: true,
      staleTokenBlocked: true,
      staleDeleteTokenBlocked: true,
      sourcePreserved: true,
      destinationAbsent: true,
    });

    const snapshotPath = path.join(generationRoot, 'snapshot.bin');
    const snapshotBytes = Buffer.from('stable pinned snapshot bytes', 'utf8');
    await writeFile(snapshotPath, snapshotBytes);
    const writer = await open(snapshotPath, 'r+');
    try {
      const blockedSnapshot = spawnSync('powershell.exe', [
        '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass',
        '-Command', `[Diagnostics.Process]::GetCurrentProcess().PriorityClass=[Diagnostics.ProcessPriorityClass]::Idle;. '${common}'; [void][StMobile.PinnedFileOperations]::ReadSnapshot('${snapshotPath.replaceAll("'", "''")}', '')`,
      ], { encoding: 'utf8', windowsHide: true });
      assert.notEqual(blockedSnapshot.status, 0, 'ReadSnapshot must reject an already-open writer');
      assert.deepEqual(await readFile(snapshotPath), snapshotBytes, 'rejected snapshot must preserve writer-owned bytes');
    } finally {
      await writer.close();
    }
    const stableSnapshot = JSON.parse(execFileSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass',
      '-Command', [
        '[Diagnostics.Process]::GetCurrentProcess().PriorityClass=[Diagnostics.ProcessPriorityClass]::Idle',
        `. '${common}'`,
        `$snapshot=[StMobile.PinnedFileOperations]::ReadSnapshot('${snapshotPath.replaceAll("'", "''")}', '')`,
        '[pscustomobject]@{bytes=[Convert]::ToBase64String($snapshot.Bytes);parent=$snapshot.ParentToken;file=$snapshot.FileToken}|ConvertTo-Json -Compress',
      ].join(';'),
    ], { encoding: 'utf8', windowsHide: true }));
    assert.deepEqual(Buffer.from(stableSnapshot.bytes, 'base64'), snapshotBytes);
    assert.match(stableSnapshot.parent, /^[0-9a-f]{8}:[0-9a-f]{8}:[0-9a-f]{8}$/);
    assert.match(stableSnapshot.file, /^[0-9a-f]{8}:[0-9a-f]{8}:[0-9a-f]{8}$/);

    const linkedSource = path.join(generationRoot, 'ordinary-linked.bin');
    const linkedAlias = path.join(generationRoot, 'ordinary-linked-alias.bin');
    await writeFile(linkedSource, Buffer.from('ordinary linked bytes', 'utf8'));
    await link(linkedSource, linkedAlias);
    const linkedSnapshot = spawnSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-Command',
      `. '${common}';[void][StMobile.PinnedFileOperations]::ReadSnapshot('${linkedSource.replaceAll("'", "''")}', '')`,
    ], { encoding: 'utf8', windowsHide: true });
    assert.notEqual(linkedSnapshot.status, 0, 'ordinary snapshot must reject a pre-existing hardlink');
    assert.deepEqual(await readFile(linkedSource), Buffer.from('ordinary linked bytes', 'utf8'));

    const linkedRaceSource = path.join(generationRoot, 'ordinary-link-race.bin');
    const linkedRaceAlias = path.join(generationRoot, 'ordinary-link-race-alias.bin');
    const linkedRaceMarker = path.join(generationRoot, 'ordinary-link-race.marker');
    const linkedRaceContinue = path.join(generationRoot, 'ordinary-link-race.continue');
    await writeFile(linkedRaceSource, Buffer.from('ordinary link race', 'utf8'));
    const linkedRaceWorker = spawn('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-Command', `
$ErrorActionPreference='Stop';. '${common}';$snapshot=[StMobile.PinnedFileOperations]::ReadSnapshot('${linkedRaceSource.replaceAll("'", "''")}','')
$binding=[Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static
[StMobile.PinnedFileOperations].GetMethod('ConfigurePinnedInterlock',$binding).Invoke($null,@('delete','${linkedRaceMarker.replaceAll("'", "''")}','${linkedRaceContinue.replaceAll("'", "''")}'))|Out-Null
[StMobile.PinnedFileOperations]::DeleteExact('${linkedRaceSource.replaceAll("'", "''")}', $snapshot.Bytes, $snapshot.ParentToken, $snapshot.FileToken)
`,
    ], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    await waitForPath(linkedRaceMarker, linkedRaceWorker);
    let ordinaryLinkBlocked = false;
    try { await link(linkedRaceSource, linkedRaceAlias); } catch { ordinaryLinkBlocked = true; }
    await writeFile(linkedRaceContinue, 'continue', 'utf8');
    const [linkedRaceExit] = await once(linkedRaceWorker, 'exit');
    assert.ok(ordinaryLinkBlocked || linkedRaceExit !== 0, 'ordinary mutator neither blocked nor detected a raced hardlink');
    if (!ordinaryLinkBlocked) {
      assert.notEqual(linkedRaceExit, 0, 'ordinary delete must reject a hardlink added after snapshot');
      assert.deepEqual(await readFile(linkedRaceSource), Buffer.from('ordinary link race', 'utf8'));
    }

    const reserveRoot = path.join(temporaryRoot, 'reserve-link-race');
    await mkdir(reserveRoot, { recursive: true });
    const reservePath = path.join(reserveRoot, 'reservation.bin');
    const hardlinkPath = path.join(reserveRoot, 'foreign-hardlink.bin');
    const reserveMarker = path.join(reserveRoot, 'reserve.marker');
    const reserveContinue = path.join(reserveRoot, 'reserve.continue');
    const reserveWorker = spawn('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-Command', `
$ErrorActionPreference='Stop';[Diagnostics.Process]::GetCurrentProcess().PriorityClass=[Diagnostics.ProcessPriorityClass]::Idle;. '${common}'
$binding=[Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static
[StMobile.PinnedFileOperations].GetMethod('ConfigurePinnedInterlock',$binding).Invoke($null,@('reserve','${reserveMarker.replaceAll("'", "''")}','${reserveContinue.replaceAll("'", "''")}'))|Out-Null
$bytes=(New-Object Text.UTF8Encoding($false)).GetBytes('reserve-link-race')
$lease=[StMobile.PinnedFileOperations]::ReserveNew('${reservePath.replaceAll("'", "''")}',$bytes,'')
$lease.Retire()
`,
    ], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    const reserveErrors = [];
    reserveWorker.stderr.on('data', (chunk) => reserveErrors.push(chunk));
    await waitForPath(reserveMarker, reserveWorker);
    let hardlinkBlocked = false;
    let hardlinkCreated = false;
    try {
      await link(reservePath, hardlinkPath);
      hardlinkCreated = true;
    } catch {
      hardlinkBlocked = true;
    } finally {
      await writeFile(reserveContinue, 'continue', 'utf8');
    }
    const [reserveExit] = await once(reserveWorker, 'exit');
    assert.ok(hardlinkBlocked || reserveExit !== 0, 'concurrent hardlink was neither blocked nor detected');
    if (hardlinkCreated) assert.notEqual(reserveExit, 0, 'post-interlock link-count validation must reject a created hardlink');
    if (reserveExit === 0) assert.equal(Buffer.concat(reserveErrors).toString('utf8'), '');
    await assert.rejects(readFile(reservePath), /ENOENT/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test('tray loop delegates bounded loopback probes to a hidden Idle worker', { timeout: 20_000 }, async () => {
  const tray = await text('scripts/Start-StMobileTray.ps1');
  const probe = await text('scripts/Probe-StMobileTrayState.ps1');
  const updateStart = tray.indexOf('function Update-TrayState');
  const timerStart = tray.indexOf('$timer = New-Object System.Windows.Forms.Timer');
  assert.ok(updateStart >= 0 && timerStart > updateStart);
  const uiLoop = tray.slice(updateStart, timerStart);
  assert.match(uiLoop, /Complete-TrayProbe/);
  assert.match(uiLoop, /Start-TrayProbe/);
  assert.doesNotMatch(uiLoop, /Test-HubReady|Get-SillyTavernSession|HttpWebRequest|ReadToEnd/);
  assert.match(probe, /PriorityClass\s*=\s*\[System\.Diagnostics\.ProcessPriorityClass\]::Idle/);
  assert.match(probe, /ReadWriteTimeout = 800/);
  assert.match(probe, /MaxCharacters 65536/);
  assert.match(probe, /Write-StMobileBytesCreateNew \$ResultPath \$resultBytes/);
  assert.doesNotMatch(probe, /Move-Item .*ResultPath.*-Force/);
  assert.match(tray, /Read-TrayProbeResultSnapshot/);
  assert.match(tray, /Remove-StMobileFileIfUnchanged/);
  assert.match(tray, /probe nested session did not match a fresh exact SillyTavern verification/);

  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'st-mobile-probe-timeout-'));
  const resultPath = path.join(temporaryRoot, 'probe.json');
  const recordPath = path.join(temporaryRoot, 'missing-record.json');
  await mkdir(path.join(temporaryRoot, 'public'), { recursive: true });
  await writeFile(path.join(temporaryRoot, 'server.js'), '// fixture\n', 'utf8');
  const hungServer = spawn(process.execPath, ['-e', [
    "const net=require('net');",
    "const s=net.createServer(()=>{});",
    "s.listen(0,'127.0.0.1',()=>process.stdout.write(String(s.address().port)+'\\n'));",
    'setInterval(()=>{},1000);',
  ].join('')], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  try {
    const [portChunk] = await once(hungServer.stdout, 'data');
    const port = Number(String(portChunk).trim());
    assert.ok(Number.isInteger(port) && port > 0);
    const startedAt = Date.now();
    const result = spawnSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass',
      '-File', path.join(root, 'scripts', 'Probe-StMobileTrayState.ps1'),
      '-HubPort', String(port), '-SillyTavernPort', String(port),
      '-SillyTavernRoot', temporaryRoot, '-SillyTavernProcessRecord', recordPath,
      '-ResultPath', resultPath, '-ProbeId', randomUUID(),
    ], { encoding: 'utf8', windowsHide: true, timeout: 8_000 });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.ok(Date.now() - startedAt < 8_000, 'bounded probe exceeded its process timeout');
    const payload = JSON.parse(await readFile(resultPath, 'utf8'));
    assert.equal(payload.hubReady, false);
    assert.equal(payload.listenerReady, false);
    await unlink(resultPath);
    const foreignBytes = Buffer.from('foreign probe collision\r\n', 'utf8');
    await writeFile(resultPath, foreignBytes);
    const collision = spawnSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass',
      '-File', path.join(root, 'scripts', 'Probe-StMobileTrayState.ps1'),
      '-HubPort', String(port), '-SillyTavernPort', String(port),
      '-SillyTavernRoot', temporaryRoot, '-SillyTavernProcessRecord', recordPath,
      '-ResultPath', resultPath, '-ProbeId', randomUUID(),
    ], { encoding: 'utf8', windowsHide: true, timeout: 8_000 });
    assert.notEqual(collision.status, 0, 'probe publication must refuse a preexisting result path');
    assert.deepEqual(await readFile(resultPath), foreignBytes);
  } finally {
    hungServer.kill();
    await once(hungServer, 'exit').catch(() => {});
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test('Start with Windows toggle creates and removes only its verified hidden shortcut', async () => {
  const temporaryStartup = await mkdtemp(path.join(tmpdir(), 'st-mobile-startup-'));
  const trayScript = path.join(root, 'scripts', 'Start-StMobileTray.ps1');
  const common = [
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', trayScript,
    '-StartupDirectory', temporaryStartup,
  ];
  try {
    const enabled = JSON.parse(execFileSync('powershell.exe', [...common, '-Mode', 'EnableStartup'], {
      encoding: 'utf8',
      windowsHide: true,
    }));
    assert.equal(enabled.startupEnabled, true);
    const status = JSON.parse(execFileSync('powershell.exe', [...common, '-Mode', 'Status'], {
      encoding: 'utf8',
      windowsHide: true,
    }));
    assert.equal(status.startupEnabled, true);
    assert.equal(typeof status.trayRunning, 'boolean');
    const disabled = JSON.parse(execFileSync('powershell.exe', [...common, '-Mode', 'DisableStartup'], {
      encoding: 'utf8',
      windowsHide: true,
    }));
    assert.equal(disabled.startupEnabled, false);
  } finally {
    await rm(temporaryStartup, { recursive: true, force: true });
  }
});

test('Start with Windows refuses a reparse Startup ancestor without touching its target', async () => {
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'st-mobile-startup-reparse-'));
  const realStartup = path.join(temporaryRoot, 'real-startup');
  const aliasStartup = path.join(temporaryRoot, 'startup-alias');
  const sentinel = path.join(realStartup, 'foreign-sentinel.bin');
  await mkdir(realStartup, { recursive: true });
  await writeFile(sentinel, Buffer.from('preserve startup target', 'utf8'));
  await symlink(realStartup, aliasStartup, 'junction');
  const trayScript = path.join(root, 'scripts', 'Start-StMobileTray.ps1');
  try {
    const result = spawnSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass',
      '-File', trayScript, '-StartupDirectory', aliasStartup, '-Mode', 'EnableStartup',
    ], { encoding: 'utf8', windowsHide: true });
    assert.notEqual(result.status, 0, 'reparse Startup directory must be rejected');
    assert.match(`${result.stdout}\n${result.stderr}`, /reparse point|Pinned path/i);
    assert.deepEqual(await readFile(sentinel), Buffer.from('preserve startup target', 'utf8'));
    assert.deepEqual(await readdir(realStartup), ['foreign-sentinel.bin']);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test('Start with Windows preserves hardlink and reparse leaf collisions', async () => {
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'st-mobile-startup-leaf-collision-'));
  const startup = path.join(temporaryRoot, 'startup');
  const shortcutPath = path.join(startup, 'SillyTavern Mobile Auth Hub.lnk');
  const hardlinkTarget = path.join(temporaryRoot, 'hardlink-target.bin');
  const reparseTarget = path.join(temporaryRoot, 'reparse-target');
  const reparseSentinel = path.join(reparseTarget, 'sentinel.bin');
  const hardlinkBytes = Buffer.from('foreign hardlink target must survive', 'utf8');
  await mkdir(startup, { recursive: true });
  await mkdir(reparseTarget, { recursive: true });
  await writeFile(hardlinkTarget, hardlinkBytes);
  await writeFile(reparseSentinel, Buffer.from('foreign reparse target must survive', 'utf8'));
  const trayScript = path.join(root, 'scripts', 'Start-StMobileTray.ps1');
  const runEnable = () => spawnSync('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass',
    '-File', trayScript, '-StartupDirectory', startup, '-Mode', 'EnableStartup',
  ], { encoding: 'utf8', windowsHide: true });
  try {
    await link(hardlinkTarget, shortcutPath);
    const hardlinkResult = runEnable();
    assert.notEqual(hardlinkResult.status, 0, 'hardlink destination collision must fail closed');
    assert.deepEqual(await readFile(hardlinkTarget), hardlinkBytes);
    assert.deepEqual(await readFile(shortcutPath), hardlinkBytes);
    await unlink(shortcutPath);

    await symlink(reparseTarget, shortcutPath, 'junction');
    const reparseResult = runEnable();
    assert.notEqual(reparseResult.status, 0, 'reparse destination collision must fail closed');
    assert.match(`${reparseResult.stdout}\n${reparseResult.stderr}`, /modified or unrecognized|reparse point/i);
    assert.deepEqual(await readFile(reparseSentinel), Buffer.from('foreign reparse target must survive', 'utf8'));
    assert.deepEqual(await readdir(reparseTarget), ['sentinel.bin']);
    assert.deepEqual((await readdir(startup)).sort(), ['SillyTavern Mobile Auth Hub.lnk']);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test('pathless shell-link serialization round-trips under both PowerShell COM runtimes', () => {
  const common = path.join(root, 'scripts', 'StMobileTrayCommon.ps1').replaceAll("'", "''");
  for (const executable of ['powershell.exe', 'pwsh.exe']) {
    const script = `
. '${common}'
$target = (Get-Command powershell.exe).Source
$bytes = [StMobile.ShellLinkSerializer]::SerializeAndValidate(
  $target, '-NoProfile -NonInteractive', '${root.replaceAll("'", "''")}',
  'ST Mobile pathless serializer test', 7, $target, 0)
[pscustomobject]@{
  length=$bytes.Length
  header=(($bytes[0..3] | ForEach-Object { $_.ToString('x2') }) -join '')
} | ConvertTo-Json -Compress
`;
    const result = JSON.parse(execFileSync(executable, [
      '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass',
      '-Command', script,
    ], { encoding: 'utf8', windowsHide: true }));
    assert.ok(result.length > 100, `${executable} serialized an implausibly short shell link`);
    assert.equal(result.header, '4c000000');
  }
});

test('Windows argument quoting round-trips trailing slashes and rejects extra tray arguments', () => {
  const commonScript = path.join(root, 'scripts', 'StMobileTrayCommon.ps1').replaceAll("'", "''");
  const values = ['', 'plain', 'two words', 'C:\\path with space\\', 'say "hello"', 'slashes\\\\\\"quote\\'];
  const encodedValues = Buffer.from(JSON.stringify(values), 'utf8').toString('base64');
  const script = `
$ErrorActionPreference = 'Stop'
. '${commonScript}'
$json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encodedValues}'))
$decoded = $json | ConvertFrom-Json
[string[]]$values = foreach ($value in $decoded) { [string]$value }
$joined = Join-WindowsCommandLineArguments $values
$parsed = @([StMobile.NativeCommandLine]::Split('program.exe ' + $joined) | Select-Object -Skip 1)
$record = [pscustomobject]@{
  scriptPath = 'C:\\test root\\Start-StMobileTray.ps1'
  hubPort = 38444
  sillyTavernPort = 3000
  sillyTavernRoot = 'C:\\ST Root\\'
  launcherIconPath = 'C:\\Launcher Root\\icon.ico'
}
    $expected = @(
  '-NoProfile', '-STA', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass',
  '-File', $record.scriptPath, '-Mode', 'Tray', '-HubPort', '38444',
      '-SillyTavernPort', '3000', '-SillyTavernRoot', $record.sillyTavernRoot,
      '-LauncherIconPath', $record.launcherIconPath)
    $gatewayRecord = [pscustomobject]@{
      cliPath = 'C:\gateway root\cli.js'
      publicHost = '192.168.1.2'
      port = 38443
      hubPort = 38444
    }
    $gatewayExpected = @(
      $gatewayRecord.cliPath, 'serve', '--host', $gatewayRecord.publicHost,
      '--port', '38443', '--hub-port', '38444')
    [pscustomobject]@{
      parsed = $parsed
      exactAccepted = Test-StMobileExactTrayArguments $expected $record
      extraRejected = -not (Test-StMobileExactTrayArguments @($expected + '-Command') $record)
      gatewayExactAccepted = Test-StMobileExactGatewayArguments $gatewayExpected $gatewayRecord
      gatewayExtraRejected = -not (Test-StMobileExactGatewayArguments @($gatewayExpected + '--no-hub') $gatewayRecord)
    } | ConvertTo-Json -Compress
`;
  const result = JSON.parse(execFileSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script], {
    encoding: 'utf8',
    windowsHide: true,
  }));

  assert.deepEqual(result.parsed, values);
  assert.equal(result.exactAccepted, true);
  assert.equal(result.extraRejected, true);
  assert.equal(result.gatewayExactAccepted, true);
  assert.equal(result.gatewayExtraRejected, true);

  const resolvedWindowsPowerShell = execFileSync('pwsh.exe', [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command',
    `. '${commonScript.replaceAll("'", "''")}'; Get-StMobileWindowsPowerShellExecutable`,
  ], { encoding: 'utf8', windowsHide: true }).trim();
  assert.match(resolvedWindowsPowerShell, /WindowsPowerShell\\v1\.0\\powershell\.exe$/i);
});

test('trusted SillyTavern record writer refuses to overwrite a foreign record', async () => {
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'st-mobile-st-record-'));
  const recordPath = path.join(temporaryRoot, 'sillytavern-process.json');
  const foreign = Buffer.from('{"schema":"foreign","sentinel":"preserve"}\n', 'utf8');
  const commonScript = path.join(root, 'scripts', 'StMobileTrayCommon.ps1').replaceAll("'", "''");
  const serverPath = path.join(root, 'package.json').replaceAll("'", "''");
  const escapedRecord = recordPath.replaceAll("'", "''");
  try {
    await writeFile(recordPath, foreign);
    const script = `
$ErrorActionPreference = 'Stop'
. '${commonScript}'
$process = Get-Process -Id $PID
$session = [pscustomobject]@{
  Pid = $PID
  ProcessStartTimeUtc = Get-StMobileProcessStartIdentity $process
  ExecutablePath = $process.MainModule.FileName
  SillyTavernRoot = '${root.replaceAll("'", "''")}'
  ServerScriptPath = '${serverPath}'
  RootProofMethod = 'absolute-server-argv-v1'
  RootProofAtUtc = [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
}
try {
  Write-StMobileSillyTavernRecord -Session $session -RecordPath '${escapedRecord}' -Provenance 'st-launcher-option-1' | Out-Null
  Write-Output 'foreign record was overwritten'
  exit 2
} catch {
  Write-Output $_.Exception.Message
  exit 0
}
`;
    const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], {
      encoding: 'utf8', windowsHide: true,
    });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /foreign or modified; refusing overwrite/);
    assert.deepEqual(await readFile(recordPath), foreign);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test('exact same-session SillyTavern v1 provenance upgrades to root-proven v2', async () => {
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'st-mobile-st-upgrade-'));
  const recordPath = path.join(temporaryRoot, 'sillytavern-process.json');
  const serverPath = path.join(root, 'package.json');
  const common = path.join(root, 'scripts', 'StMobileTrayCommon.ps1').replaceAll("'", "''");
  try {
    const script = `
. '${common}'
$process = Get-Process -Id $PID
$session = [pscustomobject]@{
  Pid=$PID; ProcessStartTimeUtc=Get-StMobileProcessStartIdentity $process
  ExecutablePath=$process.MainModule.FileName; SillyTavernRoot='${root.replaceAll("'", "''")}'
  ServerScriptPath='${serverPath.replaceAll("'", "''")}'
  RootProofMethod='served-random-challenge-v1'
  RootProofAtUtc=[DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
}
$legacy = [ordered]@{
  schema='st-mobile-sillytavern-process/v1'; pid=$PID; processStartTimeUtc=$session.ProcessStartTimeUtc
  executablePath=$session.ExecutablePath; sillyTavernRoot=$session.SillyTavernRoot; serverScriptPath=$session.ServerScriptPath
  provenance='st-launcher-option-1'; instanceId=[guid]::NewGuid().ToString('D')
}
[System.IO.File]::WriteAllText('${recordPath.replaceAll("'", "''")}', ($legacy | ConvertTo-Json) + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))
$upgraded = Write-StMobileSillyTavernRecord -Session $session -RecordPath '${recordPath.replaceAll("'", "''")}' -Provenance 'st-launcher-option-1'
$upgraded | ConvertTo-Json -Compress
`;
    const upgraded = JSON.parse(execFileSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script,
    ], { encoding: 'utf8', windowsHide: true }));
    assert.equal(upgraded.schema, 'st-mobile-sillytavern-process/v2');
    assert.equal(upgraded.rootProofMethod, 'served-random-challenge-v1');
    assert.match(upgraded.rootProofAtUtc, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test('process records reject PID reuse, malformed canonical fields, extras, and unsafe cleanup', async () => {
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'st-mobile-process-record-'));
  const recordPath = path.join(temporaryRoot, 'tray.json');
  const common = path.join(root, 'scripts', 'StMobileTrayCommon.ps1').replaceAll("'", "''");
  const trayScript = path.join(root, 'scripts', 'Start-StMobileTray.ps1').replaceAll("'", "''");
  const escapedRecord = recordPath.replaceAll("'", "''");
  try {
    const script = `
. '${common}'
$process = Get-Process -Id $PID
$exe = $process.MainModule.FileName
$actualStart = Get-StMobileProcessStartIdentity $process
$parsed = [datetime]::ParseExact($actualStart, "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal)
$staleStart = $parsed.AddSeconds(1).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
$record = [ordered]@{
  schema='st-mobile-tray-process/v2'; pid=$PID; processStartTimeUtc=$staleStart
  executablePath=$exe; scriptPath='${trayScript}'; mode='Tray'; hubPort=38444; sillyTavernPort=3000
  sillyTavernRoot='${temporaryRoot.replaceAll("'", "''")}'; launcherIconPath='${path.join(temporaryRoot, 'icon.ico').replaceAll("'", "''")}'
  instanceId='abcdefab-cdef-abcd-efab-cdefabcdefab'; stopCapability='12345678-1234-1234-1234-123456789abc'
}
[System.IO.File]::WriteAllText('${escapedRecord}', ($record | ConvertTo-Json) + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))
$stale = Get-VerifiedStMobileTrayProcess -RecordPath '${escapedRecord}' -PowerShellExe $exe -TrayScriptPath '${trayScript}'
$staleState = Get-StMobileTrayOwnershipState -RecordPath '${escapedRecord}' -PowerShellExe $exe -TrayScriptPath '${trayScript}'
$wrongPortState = Get-StMobileTrayOwnershipState -RecordPath '${escapedRecord}' -PowerShellExe $exe -TrayScriptPath '${trayScript}' -ExpectedHubPort 39999 -ExpectedSillyTavernPort 3000 -ExpectedSillyTavernRoot '${temporaryRoot.replaceAll("'", "''")}' -ExpectedLauncherIconPath '${path.join(temporaryRoot, 'icon.ico').replaceAll("'", "''")}'
$wrongRootState = Get-StMobileTrayOwnershipState -RecordPath '${escapedRecord}' -PowerShellExe $exe -TrayScriptPath '${trayScript}' -ExpectedHubPort 38444 -ExpectedSillyTavernPort 3000 -ExpectedSillyTavernRoot '${path.join(temporaryRoot, 'other-root').replaceAll("'", "''")}' -ExpectedLauncherIconPath '${path.join(temporaryRoot, 'icon.ico').replaceAll("'", "''")}'
$extra = [pscustomobject]$record; $extra | Add-Member foreign 1
$extra | ConvertTo-Json | Set-Content -LiteralPath '${escapedRecord}' -Encoding UTF8
$conflictState = Get-StMobileTrayOwnershipState -RecordPath '${escapedRecord}' -PowerShellExe $exe -TrayScriptPath '${trayScript}'
$baseJson = $record | ConvertTo-Json -Compress
$stringPid = $baseJson | ConvertFrom-Json; $stringPid.pid = [string]$PID
$stringPid | ConvertTo-Json | Set-Content -LiteralPath '${escapedRecord}' -Encoding UTF8
$stringPidState = Get-StMobileTrayOwnershipState -RecordPath '${escapedRecord}' -PowerShellExe $exe -TrayScriptPath '${trayScript}'
$stringPort = $baseJson | ConvertFrom-Json; $stringPort.hubPort = '38444'
$stringPort | ConvertTo-Json | Set-Content -LiteralPath '${escapedRecord}' -Encoding UTF8
$stringPortState = Get-StMobileTrayOwnershipState -RecordPath '${escapedRecord}' -PowerShellExe $exe -TrayScriptPath '${trayScript}'
$caseSchema = $baseJson | ConvertFrom-Json; $caseSchema.schema = 'ST-MOBILE-TRAY-PROCESS/V2'
$caseSchema | ConvertTo-Json | Set-Content -LiteralPath '${escapedRecord}' -Encoding UTF8
$caseSchemaState = Get-StMobileTrayOwnershipState -RecordPath '${escapedRecord}' -PowerShellExe $exe -TrayScriptPath '${trayScript}'
$caseMode = $baseJson | ConvertFrom-Json; $caseMode.mode = 'tray'
$caseMode | ConvertTo-Json | Set-Content -LiteralPath '${escapedRecord}' -Encoding UTF8
$caseModeState = Get-StMobileTrayOwnershipState -RecordPath '${escapedRecord}' -PowerShellExe $exe -TrayScriptPath '${trayScript}'
$relativePath = $baseJson | ConvertFrom-Json; $relativePath.scriptPath = '.\\Start-StMobileTray.ps1'
$relativePath | ConvertTo-Json | Set-Content -LiteralPath '${escapedRecord}' -Encoding UTF8
$relativePathState = Get-StMobileTrayOwnershipState -RecordPath '${escapedRecord}' -PowerShellExe $exe -TrayScriptPath '${trayScript}'
$casePath = $baseJson | ConvertFrom-Json; $casePath.scriptPath = ([string]$casePath.scriptPath).ToUpperInvariant()
$casePath | ConvertTo-Json | Set-Content -LiteralPath '${escapedRecord}' -Encoding UTF8
$casePathState = Get-StMobileTrayOwnershipState -RecordPath '${escapedRecord}' -PowerShellExe $exe -TrayScriptPath '${trayScript}'
$caseGuid = $baseJson | ConvertFrom-Json; $caseGuid.instanceId = ([string]$caseGuid.instanceId).ToUpperInvariant()
$caseGuid | ConvertTo-Json | Set-Content -LiteralPath '${escapedRecord}' -Encoding UTF8
$caseGuidState = Get-StMobileTrayOwnershipState -RecordPath '${escapedRecord}' -PowerShellExe $exe -TrayScriptPath '${trayScript}'
$caseCapability = $baseJson | ConvertFrom-Json; $caseCapability.stopCapability = ([string]$caseCapability.stopCapability).ToUpperInvariant()
$caseCapability | ConvertTo-Json | Set-Content -LiteralPath '${escapedRecord}' -Encoding UTF8
$caseCapabilityState = Get-StMobileTrayOwnershipState -RecordPath '${escapedRecord}' -PowerShellExe $exe -TrayScriptPath '${trayScript}'
[pscustomobject]@{
  pidReuseRejected = -not [bool]$stale
  staleClassified = $staleState.State -ceq 'OwnedStale'
  wrongPortConflict = $wrongPortState.State -ceq 'Conflict'
  wrongRootConflict = $wrongRootState.State -ceq 'Conflict'
  conflictClassified = $conflictState.State -ceq 'Conflict'
  stringPidConflict = $stringPidState.State -ceq 'Conflict'
  stringPortConflict = $stringPortState.State -ceq 'Conflict'
  caseSchemaConflict = $caseSchemaState.State -ceq 'Conflict'
  caseModeConflict = $caseModeState.State -ceq 'Conflict'
  relativePathConflict = $relativePathState.State -ceq 'Conflict'
  casePathConflict = $casePathState.State -ceq 'Conflict'
  caseGuidConflict = $caseGuidState.State -ceq 'Conflict'
  caseCapabilityConflict = $caseCapabilityState.State -ceq 'Conflict'
  malformedTimestampRejected = -not (Test-StMobileCanonicalProcessStartIdentity '2026-07-11T12:00:00Z')
  malformedGuidRejected = -not (Test-StMobileCanonicalGuid 'NOT-A-GUID')
  uppercaseGuidRejected = -not (Test-StMobileCanonicalGuid ([guid]::NewGuid().ToString('D').ToUpperInvariant()))
  extraPropertyRejected = -not (Test-StMobileExactPropertySet $extra @('schema','pid','processStartTimeUtc','executablePath','scriptPath','mode','hubPort','sillyTavernPort','sillyTavernRoot','launcherIconPath','instanceId','stopCapability'))
} | ConvertTo-Json -Compress
`;
    const result = JSON.parse(execFileSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script,
    ], { encoding: 'utf8', windowsHide: true }));
    assert.deepEqual(result, {
      pidReuseRejected: true,
      staleClassified: true,
      wrongPortConflict: true,
      wrongRootConflict: true,
      conflictClassified: true,
      stringPidConflict: true,
      stringPortConflict: true,
      caseSchemaConflict: true,
      caseModeConflict: true,
      relativePathConflict: true,
      casePathConflict: true,
      caseGuidConflict: true,
      caseCapabilityConflict: true,
      malformedTimestampRejected: true,
      malformedGuidRejected: true,
      uppercaseGuidRejected: true,
      extraPropertyRejected: true,
    });
    const stopTray = await text('scripts/Stop-StMobileTray.ps1');
    const stopMobile = await text('scripts/Stop-StMobile.ps1');
    assert.match(stopTray, /Test-BytesEqual \$trayRecordBytesBeforeStop \$trayRecordBytesAfterStop/);
    assert.match(stopMobile, /Test-BytesEqual \$gatewayRecordBytesBeforeStop \(\[System\.IO\.File\]::ReadAllBytes\(\$GatewayProcessRecord\)\)/);
    assert.match(stopMobile, /Test-BytesEqual \$stRecordBytesBeforeStop \(\[System\.IO\.File\]::ReadAllBytes\(\$SillyTavernProcessRecord\)\)/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test('process-stop verifiers reject same-byte and different-byte record generation swaps', async () => {
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'st-mobile-stop-generation-'));
  const common = path.join(root, 'scripts', 'StMobileTrayCommon.ps1').replaceAll("'", "''");
  const escapedRoot = temporaryRoot.replaceAll("'", "''");
  try {
    const result = JSON.parse(execFileSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-Command', `
$ErrorActionPreference='Stop';. '${common}';$utf8=New-Object Text.UTF8Encoding($false)
function Test-Swap([string]$Name,[bool]$Different){
  $path=Join-Path '${escapedRoot}' ($Name+'.json');$saved=$path+'.saved';$original=$utf8.GetBytes('{"fixture":"original"}')
  $created=[StMobile.PinnedFileOperations]::CreateNew($path,$original,'');$snapshot=[StMobile.PinnedFileOperations]::ReadSnapshot($path,$created.ParentToken)
  [void][StMobile.PinnedFileOperations]::MoveExact($path,$saved,$original,$snapshot.ParentToken,$snapshot.FileToken)
  $replacement=if($Different){$utf8.GetBytes('{"fixture":"replacement"}')}else{$original}
  [void][StMobile.PinnedFileOperations]::CreateNew($path,$replacement,$snapshot.ParentToken)
  $trayBlocked=$false;$gatewayBlocked=$false;$stBlocked=$false
  try{[void](Get-VerifiedStMobileTrayProcess -RecordPath $path -RecordSnapshot $snapshot -PowerShellExe 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' -TrayScriptPath 'C:\\fixture.ps1' -ThrowOnInvalid)}catch{$trayBlocked=$true}
  try{[void](Get-VerifiedStMobileGatewayProcess -RecordPath $path -RecordSnapshot $snapshot -NodeExe 'C:\\Program Files\\nodejs\\node.exe' -GatewayCli 'C:\\fixture.js' -PublicHost '192.0.2.10' -Port 38443 -HubPort 38444 -ThrowOnInvalid)}catch{$gatewayBlocked=$true}
  try{[void](Get-SillyTavernSession -Port 3000 -SillyTavernRoot '${escapedRoot}' -RecordPath $path -RecordSnapshot $snapshot -ThrowOnInvalid)}catch{$stBlocked=$true}
  [pscustomobject]@{tray=$trayBlocked;gateway=$gatewayBlocked;st=$stBlocked;replacementPreserved=(Test-BytesEqual([IO.File]::ReadAllBytes($path))$replacement)}
}
[pscustomobject]@{same=Test-Swap 'same' $false;different=Test-Swap 'different' $true}|ConvertTo-Json -Depth 4 -Compress
`,
    ], { encoding: 'utf8', windowsHide: true }));
    assert.deepEqual(result, {
      same: { tray: true, gateway: true, st: true, replacementPreserved: true },
      different: { tray: true, gateway: true, st: true, replacementPreserved: true },
    });

    const stop = await text('scripts/Stop-StMobile.ps1');
    const stopTray = await text('scripts/Stop-StMobileTray.ps1');
    const gatewayBody = stop.slice(stop.indexOf('function Stop-VerifiedGateway'), stop.indexOf('function Stop-VerifiedSillyTavern'));
    const stBody = stop.slice(stop.indexOf('function Stop-VerifiedSillyTavern'));
    for (const [name, body] of [['gateway', gatewayBody], ['SillyTavern', stBody]]) {
      const capture = body.indexOf('ReadSnapshot');
      const boundVerify = body.indexOf('-RecordSnapshot');
      const exactRecheck = body.indexOf('::InspectExact', boundVerify);
      const processRecheck = body.indexOf('Assert-StMobilePinnedProcessIdentity', exactRecheck);
      const terminate = body.indexOf('::TerminatePinnedProcess', processRecheck);
      assert.ok(capture >= 0 && boundVerify > capture && exactRecheck > boundVerify && processRecheck > exactRecheck && terminate > processRecheck,
        `${name} stop must capture, verify, file-recheck, process-handle-recheck, then terminate in that order`);
      assert.doesNotMatch(body, /Stop-Process\s+-Id/);
    }
    const trayCapture = stopTray.indexOf('ReadSnapshot');
    const trayBoundVerify = stopTray.indexOf('-RecordSnapshot');
    const trayExactRecheck = stopTray.indexOf('::InspectExact', trayBoundVerify);
    const trayRequest = stopTray.indexOf('Write-StMobileBytesCreateNew', trayExactRecheck);
    assert.ok(trayCapture >= 0 && trayBoundVerify > trayCapture && trayExactRecheck > trayBoundVerify && trayRequest > trayExactRecheck,
      'tray stop must capture, verify, exact-recheck, then publish its capability request');
    assert.match(stopTray, /Assert-StMobilePinnedProcessIdentity[\s\S]*TerminatePinnedProcess/);
    assert.doesNotMatch(stopTray, /Stop-Process\s+-Id/);
  } finally { await rm(temporaryRoot, { recursive: true, force: true }); }
});

test('pinned process capability fails closed after target exit and never touches a bystander', async () => {
  const start = await text('scripts/Start-StMobile.ps1');
  const launchHelper = start.slice(start.indexOf('function Start-HiddenIdleProcess'), start.indexOf('function Stop-JustLaunchedProcessAndConfirm'));
  const rollback = start.slice(start.indexOf('function Stop-JustLaunchedProcessAndConfirm'), start.indexOf('function Test-LoopbackSillyTavern'));
  assert.match(start, /PinProcess\(\$process\)/);
  assert.match(launchHelper, /\$startIdentity = Get-StMobileProcessStartIdentity \$process/);
  assert.match(launchHelper, /TerminatePinnedProcess\(\$process, 1\)/);
  assert.match(launchHelper, /Process = \$process[\s\S]*ExpectedStartIdentity = \$startIdentity/);
  assert.match(start, /\$stProcess = \$stLaunch\.Process[\s\S]*\$stProcessStartIdentity = \$stLaunch\.ExpectedStartIdentity/);
  assert.match(start, /\$gatewayProcess = \$gatewayLaunch\.Process[\s\S]*\$gatewayProcessStartIdentity = \$gatewayLaunch\.ExpectedStartIdentity/);
  assert.doesNotMatch(start, /\$stProcessStartIdentity = Get-StMobileProcessStartIdentity \$stProcess|\$gatewayProcessStartIdentity = Get-StMobileProcessStartIdentity \$gatewayProcess/);
  assert.match(rollback, /Assert-StMobilePinnedProcessIdentity[\s\S]*-ExpectedProcessStartTimeUtc \$ExpectedStartIdentity[\s\S]*-OwnershipName \$Name/);
  assert.match(rollback, /TerminatePinnedProcess/);
  assert.doesNotMatch(rollback, /Get-Process\s+-Id|Stop-Process\s+-Id/);
  const common = path.join(root, 'scripts', 'StMobileTrayCommon.ps1').replaceAll("'", "''");
  const rollbackDefinition = rollback.replaceAll("'", "''");
  const result = JSON.parse(execFileSync('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-Command', `
$ErrorActionPreference='Stop';. '${common}';Invoke-Expression '${rollbackDefinition}';$exe=(Get-Command powershell.exe).Source
function Start-Sleeper {
  $info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=$exe;$info.Arguments='-NoProfile -NonInteractive -WindowStyle Hidden -Command "Start-Sleep -Seconds 30"';$info.UseShellExecute=$false;$info.CreateNoWindow=$true
  [Diagnostics.Process]::Start($info)
}
$target=Start-Sleeper;$bystander=Start-Sleeper;$exact=Start-Sleeper;$rollbackLive=Start-Sleeper;$rollbackExited=Start-Sleeper
try {
  [void][StMobile.PinnedFileOperations]::PinProcess($target);$targetStart=Get-StMobileProcessStartIdentity $target
  $target.Kill();$target.WaitForExit(5000)|Out-Null
  $exitedBlocked=$false;try{Assert-StMobilePinnedProcessIdentity $target $targetStart 'exited target'}catch{$exitedBlocked=$true}
  [void][StMobile.PinnedFileOperations]::PinProcess($exact);$exactStart=Get-StMobileProcessStartIdentity $exact
  Assert-StMobilePinnedProcessIdentity $exact $exactStart 'exact target';[StMobile.PinnedFileOperations]::TerminatePinnedProcess($exact,1);$exact.WaitForExit(5000)|Out-Null
  [void][StMobile.PinnedFileOperations]::PinProcess($rollbackLive);$rollbackLiveStart=Get-StMobileProcessStartIdentity $rollbackLive
  Stop-JustLaunchedProcessAndConfirm $rollbackLive $rollbackLiveStart 'live rollback'
  [void][StMobile.PinnedFileOperations]::PinProcess($rollbackExited);$rollbackExitedStart=Get-StMobileProcessStartIdentity $rollbackExited
  $rollbackExited.Kill();$rollbackExited.WaitForExit(5000)|Out-Null
  Stop-JustLaunchedProcessAndConfirm $rollbackExited $rollbackExitedStart 'exited rollback'
  [pscustomobject]@{exitedBlocked=$exitedBlocked;exactExited=$exact.HasExited;rollbackLiveExited=$rollbackLive.HasExited;rollbackExitedClean=$rollbackExited.HasExited;bystanderAlive=-not$bystander.HasExited}|ConvertTo-Json -Compress
} finally {
  foreach($p in @($target,$exact,$rollbackLive,$rollbackExited,$bystander)){if($p -and -not $p.HasExited){$p.Kill();$p.WaitForExit(5000)|Out-Null};if($p){$p.Dispose()}}
}
`,
  ], { encoding: 'utf8', windowsHide: true }));
  assert.deepEqual(result, { exitedBlocked: true, exactExited: true, rollbackLiveExited: true, rollbackExitedClean: true, bystanderAlive: true });
  const listenerGuard = start.slice(start.indexOf('function Assert-GatewayListenerExpected'), start.indexOf('function Clear-StaleGatewayOwnershipForLaunch'));
  assert.match(listenerGuard, /-not \$process -or \[string\]::IsNullOrWhiteSpace/);
  assert.match(listenerGuard, /\$gatewayProcess = \$gatewayOwnership\.Verified\.Process/);
  assert.match(listenerGuard, /Assert-StMobilePinnedProcessIdentity[\s\S]*Set-IdlePriority[\s\S]*Assert-StMobilePinnedProcessIdentity/);
  assert.doesNotMatch(listenerGuard, /Get-Process\s+-Id/);
});

test('post-start identity capture failure exact-cleans both launch roles and preserves a bystander', async () => {
  const start = await text('scripts/Start-StMobile.ps1');
  const launchHelper = start.slice(start.indexOf('function Start-HiddenIdleProcess'), start.indexOf('function Stop-JustLaunchedProcessAndConfirm'));
  const common = path.join(root, 'scripts', 'StMobileTrayCommon.ps1').replaceAll("'", "''");
  const escapedHelper = launchHelper.replaceAll("'", "''");
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'st-mobile-launch-identity-failure-'));
  const escapedRoot = temporaryRoot.replaceAll("'", "''");
  try {
    const result = JSON.parse(execFileSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-Command', `
$ErrorActionPreference='Stop';. '${common}';Invoke-Expression '${escapedHelper}'
function Set-IdlePriority { param($Process,$Name) }
function Get-StMobileProcessStartIdentity { param($Process);Start-Sleep -Milliseconds 700;throw 'forced identity capture failure' }
$sleeper=Join-Path '${escapedRoot}' 'sleeper.ps1';[IO.File]::WriteAllText($sleeper,'param([string]$PidPath);[IO.File]::WriteAllText($PidPath,[string]$PID);Start-Sleep -Seconds 30')
$exe=(Get-Command powershell.exe).Source
$bystander=[Diagnostics.Process]::Start($exe,'-NoProfile -NonInteractive -WindowStyle Hidden -Command "Start-Sleep -Seconds 30"')
$roles=@('SillyTavern','ST Mobile Gateway');$out=@()
try {
  foreach($role in $roles){
    $slug=$role.Replace(' ','-');$pidPath=Join-Path '${escapedRoot}' ($slug+'.pid');$stdout=Join-Path '${escapedRoot}' ($slug+'.out');$stderr=Join-Path '${escapedRoot}' ($slug+'.err');$blocked=$false
    try{Start-HiddenIdleProcess -FilePath $exe -ArgumentList @('-NoProfile','-NonInteractive','-File',$sleeper,$pidPath) -WorkingDirectory '${escapedRoot}' -Name $role -OutLog $stdout -ErrLog $stderr}catch{$blocked=$_.Exception.Message -like '*forced identity capture failure*'}
    $childPid=[int][IO.File]::ReadAllText($pidPath);$alive=[bool](Get-Process -Id $childPid -ErrorAction SilentlyContinue);$out += [pscustomobject]@{role=$role;blocked=$blocked;childAlive=$alive}
  }
  [pscustomobject]@{roles=$out;bystanderAlive=-not $bystander.HasExited}|ConvertTo-Json -Depth 4 -Compress
} finally {if(-not $bystander.HasExited){$bystander.Kill();$bystander.WaitForExit(5000)|Out-Null};$bystander.Dispose()}
`,
    ], { encoding: 'utf8', windowsHide: true }));
    assert.deepEqual(result, {
      roles: [
        { role: 'SillyTavern', blocked: true, childAlive: false },
        { role: 'ST Mobile Gateway', blocked: true, childAlive: false },
      ],
      bystanderAlive: true,
    });
  } finally { await rm(temporaryRoot, { recursive: true, force: true }); }
});

test('admin relay drains redirected output concurrently before waiting for child exit', async () => {
  const broker = await text('scripts/AdminRelay-Broker.ps1');
  const start = broker.indexOf('[void]$process.Start()');
  const wait = broker.indexOf('$process.WaitForExit($timeoutMs)', start);
  const stdoutRead = broker.indexOf('$process.StandardOutput.ReadToEndAsync()', start);
  const stderrRead = broker.indexOf('$process.StandardError.ReadToEndAsync()', start);
  assert.ok(start >= 0 && stdoutRead > start && stderrRead > start);
  assert.ok(stdoutRead < wait && stderrRead < wait);
  assert.match(broker, /\$stdoutTask\.GetAwaiter\(\)\.GetResult\(\)/);
  assert.match(broker, /\$stderrTask\.GetAwaiter\(\)\.GetResult\(\)/);
});

test('Desktop AI Tools shortcut is a hidden one-click full-stack bootstrap', async () => {
  const open = await text('scripts/Open-StMobileAuthHub.ps1');
  const install = await text('scripts/Install-DesktopAiToolsShortcut.ps1');
  assert.match(open, /PriorityClass\s*=\s*\[System\.Diagnostics\.ProcessPriorityClass\]::Idle/);
  assert.match(open, /Test-AuthHubReady/);
  assert.match(open, /& \$StartScript[\s\S]*Test-AuthHubReady[\s\S]*& \$LaunchTrayScript[\s\S]*Start-Process \$HubUrl/);
  assert.match(open, /independent lifetimes[\s\S]*Always ensure the tray/);
  assert.match(open, /X-ST-Mobile-Hub/);
  assert.match(install, /SillyTavern Mobile Auth Hub\.lnk/);
  assert.match(install, /-WindowStyle Hidden -File/);
  assert.match(install, /Open-StMobileAuthHub\.ps1/);
  assert.match(install, /Refusing to overwrite an unrecognized AI Tools shortcut/);
  assert.match(install, /Staged one-click shortcut failed exact readback/);
});

test('owned file-set cleanup quarantines exact bytes and preserves the whole set on conflict', async () => {
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'st-mobile-owned-set-'));
  const common = path.join(root, 'scripts', 'StMobileTrayCommon.ps1').replaceAll("'", "''");
  const escapedRoot = temporaryRoot.replaceAll("'", "''");
  try {
    const script = `
. '${common}'
$a = Join-Path '${escapedRoot}' 'a.bin'; $b = Join-Path '${escapedRoot}' 'b.bin'
$c = Join-Path '${escapedRoot}' 'c.bin'; $d = Join-Path '${escapedRoot}' 'd.bin'
$e = Join-Path '${escapedRoot}' 'e.bin'; $f = Join-Path '${escapedRoot}' 'f.bin'
[System.IO.File]::WriteAllBytes($a, [byte[]](1,2)); [System.IO.File]::WriteAllBytes($b, [byte[]](3,4))
[System.IO.File]::WriteAllBytes($c, [byte[]](5,6)); [System.IO.File]::WriteAllBytes($d, [byte[]](7,8))
[System.IO.File]::WriteAllBytes($e, [byte[]](10,11)); [System.IO.File]::WriteAllBytes($f, [byte[]](12,13))
$aId=[StMobile.PinnedFileOperations]::ReadSnapshot($a,'');$bId=[StMobile.PinnedFileOperations]::ReadSnapshot($b,'')
$cId=[StMobile.PinnedFileOperations]::ReadSnapshot($c,'');$dId=[StMobile.PinnedFileOperations]::ReadSnapshot($d,'')
$eId=[StMobile.PinnedFileOperations]::ReadSnapshot($e,'');$fId=[StMobile.PinnedFileOperations]::ReadSnapshot($f,'')
$cExpected = $cId.Bytes; $dExpected = $dId.Bytes
[System.IO.File]::WriteAllBytes($d, [byte[]](9,9))
$blocked = $false
try {
  Remove-StMobileFileSetIfUnchanged -OwnershipName 'test conflict set' -Entries @(
    [pscustomobject]@{Path=$c;Bytes=$cExpected;ParentToken=$cId.ParentToken;FileToken=$cId.FileToken},
    [pscustomobject]@{Path=$d;Bytes=$dExpected;ParentToken=$dId.ParentToken;FileToken=$dId.FileToken})
} catch { $blocked = $true }
Remove-StMobileFileSetIfUnchanged -OwnershipName 'test exact set' -Entries @(
  [pscustomobject]@{Path=$a;Bytes=$aId.Bytes;ParentToken=$aId.ParentToken;FileToken=$aId.FileToken},
  [pscustomobject]@{Path=$b;Bytes=$bId.Bytes;ParentToken=$bId.ParentToken;FileToken=$bId.FileToken})
$rollbackBlocked = $false
$env:ST_MOBILE_TEST_FAIL_OWNED_SET_DELETE_AFTER = '1'
try {
  Remove-StMobileFileSetIfUnchanged -OwnershipName 'test injected rollback set' -Entries @(
    [pscustomobject]@{Path=$e;Bytes=$eId.Bytes;ParentToken=$eId.ParentToken;FileToken=$eId.FileToken},
    [pscustomobject]@{Path=$f;Bytes=$fId.Bytes;ParentToken=$fId.ParentToken;FileToken=$fId.FileToken})
} catch { $rollbackBlocked = $true }
Remove-Item Env:ST_MOBILE_TEST_FAIL_OWNED_SET_DELETE_AFTER -ErrorAction SilentlyContinue
$restoreArtifacts = @(Get-ChildItem -LiteralPath '${escapedRoot}' -Force | Where-Object { $_.Name -match '\\.(st-mobile-delete|restore)-' })
[pscustomobject]@{
  conflictBlocked=$blocked; conflictAExists=Test-Path $c; conflictBExists=Test-Path $d
  exactADeleted=-not (Test-Path $a); exactBDeleted=-not (Test-Path $b)
  rollbackBlocked=$rollbackBlocked
  rollbackAExact=(Test-Path $e) -and (Test-BytesEqual ([System.IO.File]::ReadAllBytes($e)) ([byte[]](10,11)))
  rollbackBExact=(Test-Path $f) -and (Test-BytesEqual ([System.IO.File]::ReadAllBytes($f)) ([byte[]](12,13)))
  rollbackArtifactsClean=$restoreArtifacts.Count -eq 0
} | ConvertTo-Json -Compress
`;
    const result = JSON.parse(execFileSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script,
    ], { encoding: 'utf8', windowsHide: true }));
    assert.deepEqual(result, {
      conflictBlocked: true,
      conflictAExists: true,
      conflictBExists: true,
      exactADeleted: true,
      exactBDeleted: true,
      rollbackBlocked: true,
      rollbackAExact: true,
      rollbackBExact: true,
      rollbackArtifactsClean: true,
    });
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test('gateway and SillyTavern ownership records reject coerced scalars and altered canonical strings', async () => {
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'st-mobile-other-records-'));
  const recordPath = path.join(temporaryRoot, 'gateway.json');
  const common = path.join(root, 'scripts', 'StMobileTrayCommon.ps1').replaceAll("'", "''");
  const escapedRoot = temporaryRoot.replaceAll("'", "''");
  const escapedRecord = recordPath.replaceAll("'", "''");
  try {
    const script = `
. '${common}'
$process = Get-Process -Id $PID
$exe = [System.IO.Path]::GetFullPath($process.MainModule.FileName)
$actualStart = Get-StMobileProcessStartIdentity $process
$parsed = [datetime]::ParseExact($actualStart, "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal)
$staleStart = $parsed.AddSeconds(1).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
$cli = [System.IO.Path]::GetFullPath((Join-Path '${escapedRoot}' 'cli.js'))
$gateway = [ordered]@{
  schema='st-mobile-gateway-process/v1'; pid=$PID; processStartTimeUtc=$staleStart
  executablePath=$exe; cliPath=$cli; publicHost='192.0.2.10'; port=38443; hubPort=38444
  instanceId=[guid]::NewGuid().ToString('D')
}
$gatewayJson = $gateway | ConvertTo-Json -Compress
function Get-GatewayState([object]$value) {
  [System.IO.File]::WriteAllText('${escapedRecord}', ($value | ConvertTo-Json) + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))
  return (Get-StMobileGatewayOwnershipState -RecordPath '${escapedRecord}' -NodeExe $exe -GatewayCli $cli -PublicHost '192.0.2.10' -Port 38443 -HubPort 38444).State
}
$gatewayStale = Get-GatewayState ($gatewayJson | ConvertFrom-Json)
$gatewayStringPid = $gatewayJson | ConvertFrom-Json; $gatewayStringPid.pid = [string]$PID
$gatewayStringPort = $gatewayJson | ConvertFrom-Json; $gatewayStringPort.port = '38443'
$gatewayCaseSchema = $gatewayJson | ConvertFrom-Json; $gatewayCaseSchema.schema = 'ST-MOBILE-GATEWAY-PROCESS/V1'
$gatewayCasePath = $gatewayJson | ConvertFrom-Json; $gatewayCasePath.cliPath = ([string]$gatewayCasePath.cliPath).ToUpperInvariant()
$gatewayCaseGuid = $gatewayJson | ConvertFrom-Json; $gatewayCaseGuid.instanceId = ([string]$gatewayCaseGuid.instanceId).ToUpperInvariant()
$server = [System.IO.Path]::GetFullPath((Join-Path '${escapedRoot}' 'server.js'))
$st = [pscustomobject][ordered]@{
  schema='st-mobile-sillytavern-process/v2'; pid=[int]42
  processStartTimeUtc='2026-07-11T12:00:00.000Z'; executablePath=$exe
  sillyTavernRoot=[System.IO.Path]::GetFullPath('${escapedRoot}'); serverScriptPath=$server
  provenance='st-launcher-option-1'; instanceId='abcdefab-cdef-abcd-efab-cdefabcdefab'
  rootProofMethod='served-random-challenge-v1'; rootProofAtUtc='2026-07-11T12:00:01.000Z'
}
$stValid = Test-StMobileSillyTavernRecordStructure $st '${escapedRoot}' $server $exe
$stStringPid = $st.PSObject.Copy(); $stStringPid.pid = '42'
$stCaseProvenance = $st.PSObject.Copy(); $stCaseProvenance.provenance = 'ST-LAUNCHER-OPTION-1'
$stCaseRoot = $st.PSObject.Copy(); $stCaseRoot.sillyTavernRoot = ([string]$stCaseRoot.sillyTavernRoot).ToUpperInvariant()
$stRelativeServer = $st.PSObject.Copy(); $stRelativeServer.serverScriptPath = '.\\server.js'
$stCaseGuid = $st.PSObject.Copy(); $stCaseGuid.instanceId = ([string]$stCaseGuid.instanceId).ToUpperInvariant()
$validPidBytes = (New-Object System.Text.ASCIIEncoding).GetBytes('42' + [Environment]::NewLine)
$leadingSpaceRejected = $false; $extraNewlineRejected = $false; $bomRejected = $false
try { [void](Read-StMobileCanonicalPositivePidBytes ((New-Object System.Text.ASCIIEncoding).GetBytes(' 42' + [Environment]::NewLine)) 'test') } catch { $leadingSpaceRejected = $true }
try { [void](Read-StMobileCanonicalPositivePidBytes ((New-Object System.Text.ASCIIEncoding).GetBytes('42' + [Environment]::NewLine + [Environment]::NewLine)) 'test') } catch { $extraNewlineRejected = $true }
try { [void](Read-StMobileCanonicalPositivePidBytes ([byte[]](0xEF,0xBB,0xBF,0x34,0x32,0x0D,0x0A)) 'test') } catch { $bomRejected = $true }
[pscustomobject]@{
  gatewayStale=$gatewayStale -ceq 'OwnedStale'
  gatewayStringPid=(Get-GatewayState $gatewayStringPid) -ceq 'Conflict'
  gatewayStringPort=(Get-GatewayState $gatewayStringPort) -ceq 'Conflict'
  gatewayCaseSchema=(Get-GatewayState $gatewayCaseSchema) -ceq 'Conflict'
  gatewayCasePath=(Get-GatewayState $gatewayCasePath) -ceq 'Conflict'
  gatewayCaseGuid=(Get-GatewayState $gatewayCaseGuid) -ceq 'Conflict'
  stValid=$stValid
  stStringPid=-not (Test-StMobileSillyTavernRecordStructure $stStringPid '${escapedRoot}' $server $exe)
  stCaseProvenance=-not (Test-StMobileSillyTavernRecordStructure $stCaseProvenance '${escapedRoot}' $server $exe)
  stCaseRoot=-not (Test-StMobileSillyTavernRecordStructure $stCaseRoot '${escapedRoot}' $server $exe)
  stRelativeServer=-not (Test-StMobileSillyTavernRecordStructure $stRelativeServer '${escapedRoot}' $server $exe)
  stCaseGuid=-not (Test-StMobileSillyTavernRecordStructure $stCaseGuid '${escapedRoot}' $server $exe)
  canonicalPid=(Read-StMobileCanonicalPositivePidBytes $validPidBytes 'test') -eq 42
  leadingSpaceRejected=$leadingSpaceRejected
  extraNewlineRejected=$extraNewlineRejected
  bomRejected=$bomRejected
} | ConvertTo-Json -Compress
`;
    const result = JSON.parse(execFileSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script,
    ], { encoding: 'utf8', windowsHide: true }));
    assert.deepEqual(result, {
      gatewayStale: true,
      gatewayStringPid: true,
      gatewayStringPort: true,
      gatewayCaseSchema: true,
      gatewayCasePath: true,
      gatewayCaseGuid: true,
      stValid: true,
      stStringPid: true,
      stCaseProvenance: true,
      stCaseRoot: true,
      stRelativeServer: true,
      stCaseGuid: true,
      canonicalPid: true,
      leadingSpaceRejected: true,
      extraNewlineRejected: true,
      bomRejected: true,
    });
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test('retry and suppression records fail closed on malformed or type-coerced state', async () => {
  const common = path.join(root, 'scripts', 'StMobileTrayCommon.ps1').replaceAll("'", "''");
  const script = `
. '${common}'
$retry = '{"schema":"st-mobile-gateway-retry/v1","stSessionKey":"42|2026-07-11T12:00:00.000Z","stPid":42,"stProcessStartTimeUtc":"2026-07-11T12:00:00.000Z","attempts":3,"exhausted":true,"updatedAtUtc":"2026-07-11T12:01:00.000Z"}' | ConvertFrom-Json
$suppression = '{"schema":"st-mobile-gateway-suppression/v1","stSessionKey":"42|2026-07-11T12:00:00.000Z","stPid":42,"stProcessStartTimeUtc":"2026-07-11T12:00:00.000Z","suppressedAtUtc":"2026-07-11T12:01:00.000Z"}' | ConvertFrom-Json
$retryExtra = $retry | Select-Object *, @{n='foreign';e={1}}
$retryString = $retry.PSObject.Copy(); $retryString.attempts = '3'
$retryBadTime = $retry.PSObject.Copy(); $retryBadTime.updatedAtUtc = 'tomorrow'
$retryMismatch = $retry.PSObject.Copy(); $retryMismatch.exhausted = $false
$suppressionBadTime = $suppression.PSObject.Copy(); $suppressionBadTime.suppressedAtUtc = 'tomorrow'
[pscustomobject]@{
  validRetry = Test-StMobileGatewayRetryStateRecord $retry 3
  validSuppression = Test-StMobileGatewaySuppressionStateRecord $suppression
  extraRejected = -not (Test-StMobileGatewayRetryStateRecord $retryExtra 3)
  stringRejected = -not (Test-StMobileGatewayRetryStateRecord $retryString 3)
  badTimeRejected = -not (Test-StMobileGatewayRetryStateRecord $retryBadTime 3)
  mismatchRejected = -not (Test-StMobileGatewayRetryStateRecord $retryMismatch 3)
  suppressionBadTimeRejected = -not (Test-StMobileGatewaySuppressionStateRecord $suppressionBadTime)
} | ConvertTo-Json -Compress
`;
  const result = JSON.parse(execFileSync('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script,
  ], { encoding: 'utf8', windowsHide: true }));
  assert.deepEqual(result, {
    validRetry: true,
    validSuppression: true,
    extraRejected: true,
    stringRejected: true,
    badTimeRejected: true,
    mismatchRejected: true,
    suppressionBadTimeRejected: true,
  });
  const tray = await text('scripts/Start-StMobileTray.ps1');
  const increment = tray.indexOf('$script:AutoStartAttempts++');
  const exhaust = tray.indexOf('$script:AutoRetryExhausted = $script:AutoStartAttempts -ge $MaxAutoStartAttempts', increment);
  const persist = tray.indexOf('Write-RetryStateRecord $sessionState.Session', exhaust);
  assert.ok(increment >= 0 && exhaust > increment && persist > exhaust,
    'the final allowed attempt must be marked exhausted before its retry record is persisted');
  assert.match(tray, /function Write-TrayStateRecordCas/);
  assert.match(tray, /update would violate its monotonic state transition/);
  assert.match(tray, /\[int\]\$new\.attempts -ge \[int\]\$old\.attempts/);
  const casStart = tray.indexOf('function Write-TrayStateRecordCas');
  const casEnd = tray.indexOf('function Get-RetryStateRecord', casStart);
  const cas = tray.slice(casStart, casEnd);
  assert.match(cas, /PinnedFileOperations\]::InspectExact/);
  assert.match(cas, /PinnedFileOperations\]::MoveExact/);
  assert.match(cas, /PinnedFileOperations\]::CreateNew/);
  assert.match(cas, /PinnedFileOperations\]::DeleteExact/);
  assert.match(cas, /oldIdentity\.FileToken/);
  assert.match(cas, /priorIdentity\.ParentToken/);
  assert.doesNotMatch(cas, /Move-Item|Remove-Item/);
});

test('tray retry CAS preserves foreign and reparse generations', async () => {
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'st-mobile-tray-cas-'));
  const common = path.join(root, 'scripts', 'StMobileTrayCommon.ps1').replaceAll("'", "''");
  const trayScript = path.join(root, 'scripts', 'Start-StMobileTray.ps1').replaceAll("'", "''");
  const escapedRoot = temporaryRoot.replaceAll("'", "''");
  try {
    const script = `
$ErrorActionPreference = 'Stop'
. '${common}'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile('${trayScript}', [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'tray script parse failed' }
$functionAst = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Write-TrayStateRecordCas' }, $true)
if (-not $functionAst) { throw 'Write-TrayStateRecordCas not found' }
. ([scriptblock]::Create($functionAst.Extent.Text))
function Write-TrayLog { param([string]$Message) }
$validator = { param($record) Test-StMobileGatewayRetryStateRecord $record 3 }
$transition = { param($old,$new) [int]$new.attempts -ge [int]$old.attempts }
function New-Record([int]$attempts) {
  [ordered]@{
    schema='st-mobile-gateway-retry/v1'; stSessionKey='42|2026-07-11T12:00:00.000Z'
    stPid=[int]42; stProcessStartTimeUtc='2026-07-11T12:00:00.000Z'
    attempts=[int]$attempts; exhausted=[bool]($attempts -ge 3)
    updatedAtUtc=('2026-07-11T12:0' + $attempts + ':00.000Z')
  }
}
$statePath = Join-Path '${escapedRoot}' 'retry.json'
$initial = New-Record 1
$initialBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes(($initial | ConvertTo-Json) + [Environment]::NewLine)
Write-StMobileBytesCreateNew $statePath $initialBytes
Write-TrayStateRecordCas $statePath (New-Record 2) $validator $transition 'test retry state'
$updated = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
$normalUpdated = [int]$updated.attempts -eq 2
$priorClean = @(Get-ChildItem -LiteralPath '${escapedRoot}' -Force | Where-Object Name -Like 'retry.json.st-mobile-prior-*').Count -eq 0
$foreignPath = Join-Path '${escapedRoot}' 'foreign.json'
$foreignBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes('foreign retry bytes')
[System.IO.File]::WriteAllBytes($foreignPath, $foreignBytes)
$foreignRejected = $false
try { Write-TrayStateRecordCas $foreignPath (New-Record 2) $validator $transition 'foreign retry state' } catch { $foreignRejected = $true }
$foreignPreserved = Test-BytesEqual ([System.IO.File]::ReadAllBytes($foreignPath)) $foreignBytes
$realRoot = Join-Path '${escapedRoot}' 'real'; $aliasRoot = Join-Path '${escapedRoot}' 'alias'
New-Item -ItemType Directory -Path $realRoot | Out-Null
New-Item -ItemType Junction -Path $aliasRoot -Target $realRoot | Out-Null
$reparseTarget = Join-Path $realRoot 'retry.json'
[System.IO.File]::WriteAllBytes($reparseTarget, $initialBytes)
$reparseRejected = $false
try { Write-TrayStateRecordCas (Join-Path $aliasRoot 'retry.json') (New-Record 2) $validator $transition 'reparse retry state' } catch { $reparseRejected = $true }
$reparsePreserved = Test-BytesEqual ([System.IO.File]::ReadAllBytes($reparseTarget)) $initialBytes
[pscustomobject]@{
  normalUpdated=$normalUpdated; priorClean=$priorClean
  foreignRejected=$foreignRejected; foreignPreserved=$foreignPreserved
  reparseRejected=$reparseRejected; reparsePreserved=$reparsePreserved
} | ConvertTo-Json -Compress
`;
    const result = JSON.parse(execFileSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass',
      '-Command', script,
    ], { encoding: 'utf8', windowsHide: true }));
    assert.deepEqual(result, {
      normalUpdated: true,
      priorClean: true,
      foreignRejected: true,
      foreignPreserved: true,
      reparseRejected: true,
      reparsePreserved: true,
    });
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test('manual-rearm quarantine retains classified generations and rolls back the conflict set', async () => {
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'st-mobile-manual-rearm-'));
  const common = path.join(root, 'scripts', 'StMobileTrayCommon.ps1').replaceAll("'", "''");
  const trayScript = path.join(root, 'scripts', 'Start-StMobileTray.ps1').replaceAll("'", "''");
  const escapedRoot = temporaryRoot.replaceAll("'", "''");
  try {
    const script = `
$ErrorActionPreference = 'Stop'
. '${common}'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile('${trayScript}', [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'tray script parse failed' }
foreach ($name in @('Set-FrozenStateRecordConflict','Get-RetryStateRecord','Get-SuppressionRecord','Quarantine-StateRecordConflictsForManualRearm','Start-GatewayAttempt')) {
  $node = $ast.Find({ param($candidate) $candidate -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $candidate.Name -ceq $name }, $true)
  if (-not $node) { throw "missing tray function $name" }
  Set-Variable -Name ($name + 'Text') -Value $node.Extent.Text
  . ([scriptblock]::Create($node.Extent.Text))
}
$quarantineText = Get-Variable -Name 'Quarantine-StateRecordConflictsForManualRearmText' -ValueOnly
$anchor = '# TEST-HARNESS-ANCHOR: after-state-record-conflict-preflight'
if (($quarantineText.Split(@($anchor), [System.StringSplitOptions]::None).Count - 1) -ne 1) { throw 'manual-rearm test anchor is not unique' }
function Write-TrayLog { param([string]$Message) }
$utf8 = New-Object System.Text.UTF8Encoding($false)
$MaxAutoStartAttempts = 3
function Reset-ConflictState {
  $script:StateRecordConflict = $false; $script:StateRecordConflictReason = ''
  $script:StateRecordConflictSnapshots = [ordered]@{ Retry=$null; Suppression=$null }
}

# Only the classified invalid record is quarantined; a valid companion is preserved byte-for-byte.
Reset-ConflictState
$normalRoot = Join-Path '${escapedRoot}' 'normal'; New-Item -ItemType Directory -Path $normalRoot | Out-Null
$RetryStateFile = Join-Path $normalRoot 'retry.json'; $SuppressionFile = Join-Path $normalRoot 'suppression.json'
$invalidRetryBytes = $utf8.GetBytes('invalid retry')
$validSuppressionBytes = $utf8.GetBytes('{"schema":"st-mobile-gateway-suppression/v1","stSessionKey":"42|2026-07-11T12:00:00.000Z","stPid":42,"stProcessStartTimeUtc":"2026-07-11T12:00:00.000Z","suppressedAtUtc":"2026-07-11T12:01:00.000Z"}')
[System.IO.File]::WriteAllBytes($RetryStateFile,$invalidRetryBytes); [System.IO.File]::WriteAllBytes($SuppressionFile,$validSuppressionBytes)
[void](Get-RetryStateRecord); $validCompanion = Get-SuppressionRecord
Quarantine-StateRecordConflictsForManualRearm
$normalQuarantine = @(Get-ChildItem $normalRoot -Filter 'retry.json.*.conflict')
$normalExact = $normalQuarantine.Count -eq 1 -and (Test-BytesEqual ([System.IO.File]::ReadAllBytes($normalQuarantine[0].FullName)) $invalidRetryBytes) -and
  (Test-BytesEqual ([System.IO.File]::ReadAllBytes($SuppressionFile)) $validSuppressionBytes) -and $validCompanion -and -not $script:StateRecordConflict

# A reparse ancestor cannot produce a trusted frozen generation and remains fail-closed.
Reset-ConflictState
$realRoot=Join-Path '${escapedRoot}' 'real';$aliasRoot=Join-Path '${escapedRoot}' 'alias';New-Item -ItemType Directory $realRoot|Out-Null;New-Item -ItemType Junction -Path $aliasRoot -Target $realRoot|Out-Null
$reparseTarget=Join-Path $realRoot 'retry.json';$reparseBytes=$utf8.GetBytes('invalid through reparse');[System.IO.File]::WriteAllBytes($reparseTarget,$reparseBytes)
$RetryStateFile=Join-Path $aliasRoot 'retry.json';$SuppressionFile=Join-Path $aliasRoot 'suppression.json';[void](Get-RetryStateRecord)
$reparseRejected=$false;try{Quarantine-StateRecordConflictsForManualRearm}catch{$reparseRejected=$true}
$reparsePreserved=(Test-BytesEqual ([System.IO.File]::ReadAllBytes($reparseTarget)) $reparseBytes)-and $script:StateRecordConflict

# Replacement before manual rearm is not adopted as the conflict generation.
Reset-ConflictState
$beforeRoot=Join-Path '${escapedRoot}' 'before';New-Item -ItemType Directory $beforeRoot|Out-Null
$RetryStateFile=Join-Path $beforeRoot 'retry.json';$SuppressionFile=Join-Path $beforeRoot 'suppression.json'
$beforeOriginal=$utf8.GetBytes('classified original');$beforeForeign=$utf8.GetBytes('foreign before manual');$beforeSaved=Join-Path $beforeRoot 'classified.saved'
[System.IO.File]::WriteAllBytes($RetryStateFile,$beforeOriginal);[void](Get-RetryStateRecord)
$frozen=$script:StateRecordConflictSnapshots.Retry
[void][StMobile.PinnedFileOperations]::MoveExact($RetryStateFile,$beforeSaved,$frozen.Bytes,$frozen.ParentToken,$frozen.FileToken)
[void][StMobile.PinnedFileOperations]::CreateNew($RetryStateFile,$beforeForeign,$frozen.ParentToken)
$beforeRejected=$false;try{Quarantine-StateRecordConflictsForManualRearm}catch{$beforeRejected=$true}
$beforePreserved=(Test-BytesEqual ([System.IO.File]::ReadAllBytes($RetryStateFile)) $beforeForeign)-and(Test-BytesEqual ([System.IO.File]::ReadAllBytes($beforeSaved)) $beforeOriginal)-and $script:StateRecordConflict

# Replacement after transaction preflight is rejected by the retained token.
Reset-ConflictState
$afterRoot=Join-Path '${escapedRoot}' 'after';New-Item -ItemType Directory $afterRoot|Out-Null
$RetryStateFile=Join-Path $afterRoot 'retry.json';$SuppressionFile=Join-Path $afterRoot 'suppression.json'
$afterOriginal=$utf8.GetBytes('classified after');$afterForeign=$utf8.GetBytes('foreign after preflight');$afterSaved=Join-Path $afterRoot 'classified.saved'
[System.IO.File]::WriteAllBytes($RetryStateFile,$afterOriginal);[void](Get-RetryStateRecord)
$afterInjection='$snapshot=$script:StateRecordConflictSnapshots.Retry; [void][StMobile.PinnedFileOperations]::MoveExact($snapshot.Path,$afterSaved,$snapshot.Bytes,$snapshot.ParentToken,$snapshot.FileToken); [void][StMobile.PinnedFileOperations]::CreateNew($snapshot.Path,$afterForeign,$snapshot.ParentToken)'
. ([scriptblock]::Create($quarantineText.Replace($anchor,$anchor+[Environment]::NewLine+$afterInjection)))
$afterRejected=$false;try{Quarantine-StateRecordConflictsForManualRearm}catch{$afterRejected=$true}
$afterPreserved=(Test-BytesEqual ([System.IO.File]::ReadAllBytes($RetryStateFile)) $afterForeign)-and(Test-BytesEqual ([System.IO.File]::ReadAllBytes($afterSaved)) $afterOriginal)-and $script:StateRecordConflict

# If the second conflicting record collides, the first staged move is restored exactly.
. ([scriptblock]::Create($quarantineText));Reset-ConflictState
$txRoot=Join-Path '${escapedRoot}' 'transaction';New-Item -ItemType Directory $txRoot|Out-Null
$RetryStateFile=Join-Path $txRoot 'retry.json';$SuppressionFile=Join-Path $txRoot 'suppression.json'
$txRetry=$utf8.GetBytes('invalid retry tx');$txSuppression=$utf8.GetBytes('invalid suppression tx');$txCollision=$utf8.GetBytes('foreign destination')
[System.IO.File]::WriteAllBytes($RetryStateFile,$txRetry);[System.IO.File]::WriteAllBytes($SuppressionFile,$txSuppression);[void](Get-RetryStateRecord);[void](Get-SuppressionRecord)
$txInjection='$collision="$SuppressionFile.$suffix"; [void][StMobile.PinnedFileOperations]::CreateNew($collision,$txCollision,$script:StateRecordConflictSnapshots.Suppression.ParentToken)'
. ([scriptblock]::Create($quarantineText.Replace($anchor,$anchor+[Environment]::NewLine+$txInjection)))
$txRejected=$false;try{Quarantine-StateRecordConflictsForManualRearm}catch{$txRejected=$true}
$txForeign=@(Get-ChildItem $txRoot -Filter 'suppression.json.*.conflict')
$txRestored=(Test-BytesEqual ([System.IO.File]::ReadAllBytes($RetryStateFile)) $txRetry)-and(Test-BytesEqual ([System.IO.File]::ReadAllBytes($SuppressionFile)) $txSuppression)-and
  $txForeign.Count -eq 1 -and(Test-BytesEqual ([System.IO.File]::ReadAllBytes($txForeign[0].FullName)) $txCollision)-and $script:StateRecordConflict -and
  $script:StateRecordConflictSnapshots.Retry -and $script:StateRecordConflictSnapshots.Suppression

# Forced reset contains the full quarantine/rollback failure and cannot reach process start.
$forceLogs=New-Object 'System.Collections.Generic.List[string]';$script:StartAttempt=$null;$script:StateRecordConflict=$false;$script:AutoStartSuppressed=$false;$script:AutoRetryExhausted=$false
function Write-TrayLog { param([string]$Message) $forceLogs.Add($Message) }
function Get-CachedSillyTavernSessionState { [pscustomobject]@{Session=[pscustomobject]@{Key='fixture'};ListenerReady=$true} }
function New-ForceResetStateTransaction { throw 'rollback-detail-sentinel' }
function Remove-SuppressionRecord { throw 'remove must not run' };function Remove-RetryStateRecord { throw 'remove must not run' }
function Start-HiddenIdlePowerShell { $script:ForceStartReached=$true;[pscustomobject]@{HasExited=$true} }
$script:ForceStartReached=$false;$forceContained=$true
try { Start-GatewayAttempt $true } catch { $forceContained=$false }
$forceBlocked = $forceContained -and -not $script:ForceStartReached -and $script:StateRecordConflict -and
  $script:AutoStartSuppressed -and $script:AutoRetryExhausted -and
  $script:StateRecordConflictReason.Contains('rollback-detail-sentinel') -and
  @($forceLogs | Where-Object { $_ -ceq 'GATEWAY_FORCE_RESET_BLOCKED error=rollback-detail-sentinel' }).Count -eq 1

[pscustomobject]@{normalExact=$normalExact;reparseRejected=$reparseRejected;reparsePreserved=$reparsePreserved;beforeRejected=$beforeRejected;beforePreserved=$beforePreserved;afterRejected=$afterRejected;afterPreserved=$afterPreserved;txRejected=$txRejected;txRestored=$txRestored;forceBlocked=$forceBlocked}|ConvertTo-Json -Compress
`;
    const result = JSON.parse(execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-Command', script], { encoding: 'utf8', windowsHide: true }));
    assert.deepEqual(result, { normalExact: true, reparseRejected: true, reparsePreserved: true, beforeRejected: true, beforePreserved: true, afterRejected: true, afterPreserved: true, txRejected: true, txRestored: true, forceBlocked: true });
    const tray = await text('scripts/Start-StMobileTray.ps1');
    const start = tray.indexOf('function Quarantine-StateRecordConflictsForManualRearm');
    const quarantine = tray.slice(start, tray.indexOf('function Set-CurrentSillyTavernSession', start));
    assert.match(tray, /StateRecordConflictSnapshots/);
    assert.match(quarantine, /PinnedFileOperations\]::InspectExact/);
    assert.match(quarantine, /PinnedFileOperations\]::MoveExact/);
    assert.match(quarantine, /Exact-generation rollback also failed/);
    assert.doesNotMatch(quarantine, /Move-Item/);
    const forceStart = tray.indexOf('function Start-GatewayAttempt');
    const forceBody = tray.slice(forceStart, tray.indexOf('function Stop-GatewayFromTray', forceStart));
    const stateStage = forceBody.indexOf('New-ForceResetStateTransaction');
    const reservations = forceBody.indexOf('New-ForceResetNamespaceReservations', stateStage);
    const processStart = forceBody.indexOf('Start-HiddenIdlePowerShell', reservations);
    const reservationRetire = forceBody.indexOf('Remove-ForceResetNamespaceReservations', processStart);
    assert.ok(stateStage >= 0 && reservations > stateStage && processStart > reservations && reservationRetire > processStart,
      'forced reset must stage state and hold both namespace reservations through child launch commitment');
    assert.match(forceBody, /catch \{/);
    assert.match(forceBody, /GATEWAY_FORCE_RESET_BLOCKED error=\$forceResetFailure/);
    const clickStart = tray.indexOf('$startGatewayItem.add_Click');
    const clickBody = tray.slice(clickStart, tray.indexOf('$stopGatewayItem.add_Click', clickStart));
    assert.doesNotMatch(clickBody, /Quarantine-StateRecordConflictsForManualRearm/);
    assert.match(clickBody, /Start-GatewayAttempt \$true/);
  } finally { await rm(temporaryRoot, { recursive: true, force: true }); }
});

test('force reset reserves both state names through child launch commitment', async () => {
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'st-mobile-force-reset-'));
  const common = path.join(root, 'scripts', 'StMobileTrayCommon.ps1').replaceAll("'", "''");
  const trayScript = path.join(root, 'scripts', 'Start-StMobileTray.ps1').replaceAll("'", "''");
  const escapedRoot = temporaryRoot.replaceAll("'", "''");
  try {
    const script = `
$ErrorActionPreference='Stop';. '${common}'
$tokens=$null;$errors=$null;$ast=[System.Management.Automation.Language.Parser]::ParseFile('${trayScript}',[ref]$tokens,[ref]$errors);if($errors.Count){throw 'tray parse failed'}
foreach($name in @('Set-FrozenStateRecordConflict','Remove-RetryStateRecord','Write-RetryStateRecord','Remove-SuppressionRecord','Write-SuppressionRecord','Set-CurrentSillyTavernSession','Complete-TrayProbe','Stop-GatewayFromTray','Update-TrayState','New-ForceResetStateTransaction','Restore-ForceResetStateTransaction','Complete-ForceResetStateTransaction','New-ForceResetNamespaceReservations','Remove-ForceResetNamespaceReservations','Start-GatewayAttempt')){
 $node=$ast.Find({param($n)$n -is [System.Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq$name},$true);if(-not$node){throw "missing $name"};Set-Variable ($name+'Text') $node.Extent.Text;. ([scriptblock]::Create($node.Extent.Text))
}
$utf8=New-Object System.Text.UTF8Encoding($false);$MaxAutoStartAttempts=3;$ForceResetReservationBytes=$utf8.GetBytes('st-mobile-force-reset-reservation/v1'+[Environment]::NewLine)
$validRetry=$utf8.GetBytes('{"schema":"st-mobile-gateway-retry/v1","stSessionKey":"42|2026-07-11T12:00:00.000Z","stPid":42,"stProcessStartTimeUtc":"2026-07-11T12:00:00.000Z","attempts":1,"exhausted":false,"updatedAtUtc":"2026-07-11T12:01:00.000Z"}')
$validSuppression=$utf8.GetBytes('{"schema":"st-mobile-gateway-suppression/v1","stSessionKey":"42|2026-07-11T12:00:00.000Z","stPid":42,"stProcessStartTimeUtc":"2026-07-11T12:00:00.000Z","suppressedAtUtc":"2026-07-11T12:01:00.000Z"}')
function Write-TrayLog{param([string]$Message)$script:Logs.Add($Message)};function Get-CachedSillyTavernSessionState{[pscustomobject]@{Session=[pscustomobject]@{Key='fixture'};ListenerReady=$true}};function Quarantine-StateRecordConflictsForManualRearm{}
$StartScript='fixture';$HubPort=38444;$SillyTavernRoot='fixture'
function Reset-Force([string]$Name){$dir=Join-Path '${escapedRoot}' $Name;New-Item -ItemType Directory -Force $dir|Out-Null;$script:RetryStateFile=Join-Path $dir 'retry.json';$script:SuppressionFile=Join-Path $dir 'suppression.json';$script:StateRecordConflict=$false;$script:StateRecordConflictReason='';$script:StateRecordConflictSnapshots=[ordered]@{Retry=$null;Suppression=$null};$script:AutoStartSuppressed=$false;$script:AutoRetryExhausted=$false;$script:AutoStartAttempts=0;$script:NextStartAttemptUtc=[datetime]::MinValue;$script:StartAttempt=$null;$script:ForceResetTransactionActive=$false;$script:Started=$false;$script:HeldAtStart=$false;$script:Logs=New-Object 'System.Collections.Generic.List[string]';return $dir}
function Start-HiddenIdlePowerShell{$script:Started=$true;$retryBlocked=$false;$suppressionBlocked=$false;try{[void][StMobile.PinnedFileOperations]::ReadSnapshot($RetryStateFile,'')}catch{$retryBlocked=$true};try{[void][StMobile.PinnedFileOperations]::ReadSnapshot($SuppressionFile,'')}catch{$suppressionBlocked=$true};$script:HeldAtStart=$retryBlocked-and$suppressionBlocked;[pscustomobject]@{HasExited=$true}}

# Cleanup must retain the originally captured IDs, not recapture same-byte replacements.
$sameDir=Reset-Force 'same-id';[System.IO.File]::WriteAllBytes($RetryStateFile,$validRetry)
$retryText=Get-Variable 'Remove-RetryStateRecordText' -ValueOnly;$retryAnchor='# TEST-HARNESS-ANCHOR: before-retry-state-exact-cleanup';$retrySaved="$RetryStateFile.saved"
$retryInjection='[void][StMobile.PinnedFileOperations]::MoveExact($RetryStateFile,$retrySaved,$bytes,$identity.ParentToken,$identity.FileToken);[void][StMobile.PinnedFileOperations]::CreateNew($RetryStateFile,$bytes,$identity.ParentToken)'
. ([scriptblock]::Create($retryText.Replace($retryAnchor,$retryAnchor+[Environment]::NewLine+$retryInjection)));$retrySwapRejected=$false;try{Remove-RetryStateRecord}catch{$retrySwapRejected=$true};$retrySwapPreserved=$retrySwapRejected-and(Test-BytesEqual([IO.File]::ReadAllBytes($RetryStateFile))$validRetry)-and(Test-BytesEqual([IO.File]::ReadAllBytes($retrySaved))$validRetry)
[System.IO.File]::WriteAllBytes($SuppressionFile,$validSuppression);$suppText=Get-Variable 'Remove-SuppressionRecordText' -ValueOnly;$suppAnchor='# TEST-HARNESS-ANCHOR: before-suppression-state-exact-cleanup';$suppSaved="$SuppressionFile.saved"
$suppInjection='[void][StMobile.PinnedFileOperations]::MoveExact($SuppressionFile,$suppSaved,$bytes,$identity.ParentToken,$identity.FileToken);[void][StMobile.PinnedFileOperations]::CreateNew($SuppressionFile,$bytes,$identity.ParentToken)'
. ([scriptblock]::Create($suppText.Replace($suppAnchor,$suppAnchor+[Environment]::NewLine+$suppInjection)));$suppSwapRejected=$false;try{Remove-SuppressionRecord}catch{$suppSwapRejected=$true};$suppSwapPreserved=$suppSwapRejected-and(Test-BytesEqual([IO.File]::ReadAllBytes($SuppressionFile))$validSuppression)-and(Test-BytesEqual([IO.File]::ReadAllBytes($suppSaved))$validSuppression)

# Restore production removal functions for force-reset scenarios.
. ([scriptblock]::Create($retryText));. ([scriptblock]::Create($suppText));$startText=Get-Variable 'Start-GatewayAttemptText' -ValueOnly
$arrival=$utf8.GetBytes('foreign arrival')
$stateText=Get-Variable 'New-ForceResetStateTransactionText' -ValueOnly;$stateAnchor='# TEST-HARNESS-ANCHOR: after-force-state-stage-move'
$dir=Reset-Force 'after-first-stage';[IO.File]::WriteAllBytes($RetryStateFile,$validRetry);[IO.File]::WriteAllBytes($SuppressionFile,$validSuppression)
$stageInjection='if($entry.Kind -eq ''Retry''){[IO.File]::WriteAllBytes($SuppressionFile,$arrival)}';. ([scriptblock]::Create($stateText.Replace($stateAnchor,$stateAnchor+[Environment]::NewLine+$stageInjection)));. ([scriptblock]::Create($startText));Start-GatewayAttempt $true
$afterFirstStage=(-not$script:Started)-and(Test-BytesEqual([IO.File]::ReadAllBytes($RetryStateFile))$validRetry)-and(Test-BytesEqual([IO.File]::ReadAllBytes($SuppressionFile))$arrival)
. ([scriptblock]::Create($stateText))
$reserveText=Get-Variable 'New-ForceResetNamespaceReservationsText' -ValueOnly;$reserveAnchor='# TEST-HARNESS-ANCHOR: after-force-retry-reservation';$reserveInjection='$leases[0].Bytes[0]=$leases[0].Bytes[0]-bxor 1'
. ([scriptblock]::Create($reserveText.Replace($reserveAnchor,$reserveAnchor+[Environment]::NewLine+$reserveInjection)))
$dir=Reset-Force 'after-suppression';$injection='[IO.File]::WriteAllBytes($SuppressionFile,$arrival)';. ([scriptblock]::Create($startText.Replace('# TEST-HARNESS-ANCHOR: after-force-suppression-removal','# TEST-HARNESS-ANCHOR: after-force-suppression-removal'+[Environment]::NewLine+$injection)));Start-GatewayAttempt $true
$afterSuppression=(-not$script:Started)-and$script:StateRecordConflict-and(Test-BytesEqual([IO.File]::ReadAllBytes($SuppressionFile))$arrival)-and-not(Test-Path $RetryStateFile)-and(@($script:Logs|Where-Object{$_ -match 'parent_token=.*file_token=.*retire_validation=.*emergency_dispose='}).Count -eq 1)
. ([scriptblock]::Create($reserveText))
$dir=Reset-Force 'after-retry';$injection='[IO.File]::WriteAllBytes($RetryStateFile,$arrival)';. ([scriptblock]::Create($startText.Replace('# TEST-HARNESS-ANCHOR: after-force-retry-removal','# TEST-HARNESS-ANCHOR: after-force-retry-removal'+[Environment]::NewLine+$injection)));Start-GatewayAttempt $true
$afterRetry=(-not$script:Started)-and$script:StateRecordConflict-and(Test-BytesEqual([IO.File]::ReadAllBytes($RetryStateFile))$arrival)-and-not(Test-Path $SuppressionFile)
$dir=Reset-Force 'before-launch';$injection='Write-RetryStateRecord $null;Write-SuppressionRecord $null;Remove-RetryStateRecord;Remove-SuppressionRecord;Set-CurrentSillyTavernSession $null;Complete-TrayProbe;Stop-GatewayFromTray;Update-TrayState;[IO.File]::WriteAllBytes($RetryStateFile,$arrival)';. ([scriptblock]::Create($startText.Replace('# TEST-HARNESS-ANCHOR: before-force-child-launch','# TEST-HARNESS-ANCHOR: before-force-child-launch'+[Environment]::NewLine+$injection)));Start-GatewayAttempt $true
$beforeLaunch=(-not$script:Started)-and$script:StateRecordConflict-and-not(Test-Path $RetryStateFile)-and-not(Test-Path $SuppressionFile)
$dir=Reset-Force 'normal';. ([scriptblock]::Create($startText));Start-GatewayAttempt $true
$normal=$script:Started-and$script:HeldAtStart-and-not$script:StateRecordConflict-and-not$script:ForceResetTransactionActive-and-not(Test-Path $RetryStateFile)-and-not(Test-Path $SuppressionFile)
$dir=Reset-Force 'partial-finalization';[IO.File]::WriteAllBytes($RetryStateFile,$validRetry);[IO.File]::WriteAllBytes($SuppressionFile,$validSuppression)
$completeText=Get-Variable 'Complete-ForceResetStateTransactionText' -ValueOnly;$completeAnchor='# TEST-HARNESS-ANCHOR: after-force-state-finalization-entry';$completeInjection='if($entry.Kind -eq ''Retry''){throw ''second-finalization-sentinel''}'
. ([scriptblock]::Create($completeText.Replace($completeAnchor,$completeAnchor+[Environment]::NewLine+$completeInjection)));. ([scriptblock]::Create($startText));Start-GatewayAttempt $true
$partialStages=@(Get-ChildItem $dir -Filter '*.st-mobile-force-stage-*');$partialFinalization=$script:Started-and$script:StateRecordConflict-and$script:AutoStartSuppressed-and$partialStages.Count -eq 1-and-not(Test-Path $RetryStateFile)-and-not(Test-Path $SuppressionFile)-and(@($script:Logs|Where-Object{$_ -match 'GATEWAY_FORCE_RESET_COMMITTED_CLEANUP_BLOCKED.*second-finalization-sentinel'}).Count -eq 1)
. ([scriptblock]::Create($completeText))
$dir=Reset-Force 'crash-residue';[IO.File]::WriteAllBytes($RetryStateFile,$ForceResetReservationBytes);. ([scriptblock]::Create($startText));Start-GatewayAttempt $true
$crashResidue=(-not$script:Started)-and$script:StateRecordConflict-and(Test-BytesEqual([IO.File]::ReadAllBytes($RetryStateFile))$ForceResetReservationBytes)
$dir=Reset-Force 'stage-crash-residue';$stageResidue="$RetryStateFile.st-mobile-force-stage-crash";[IO.File]::WriteAllBytes($stageResidue,$validRetry);. ([scriptblock]::Create($startText));Start-GatewayAttempt $true
$stageCrashResidue=(-not$script:Started)-and$script:StateRecordConflict-and(Test-BytesEqual([IO.File]::ReadAllBytes($stageResidue))$validRetry)
[pscustomobject]@{retrySwapPreserved=$retrySwapPreserved;suppSwapPreserved=$suppSwapPreserved;afterFirstStage=$afterFirstStage;afterSuppression=$afterSuppression;afterRetry=$afterRetry;beforeLaunch=$beforeLaunch;normal=$normal;partialFinalization=$partialFinalization;crashResidue=$crashResidue;stageCrashResidue=$stageCrashResidue}|ConvertTo-Json -Compress
`;
    const result = JSON.parse(execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-Command', script], { encoding: 'utf8', windowsHide: true }));
    assert.deepEqual(result, { retrySwapPreserved: true, suppSwapPreserved: true, afterFirstStage: true, afterSuppression: true, afterRetry: true, beforeLaunch: true, normal: true, partialFinalization: true, crashResidue: true, stageCrashResidue: true });
    const validationPath = path.join(temporaryRoot, 'retire-validation.bin').replaceAll("'", "''");
    const retirementValidation = JSON.parse(execFileSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-Command', `
$ErrorActionPreference='Stop';[Diagnostics.Process]::GetCurrentProcess().PriorityClass=[Diagnostics.ProcessPriorityClass]::Idle;. '${common}'
$bytes=(New-Object Text.UTF8Encoding($false)).GetBytes('retire-validation')
$lease=[StMobile.PinnedFileOperations]::ReserveNew('${validationPath}',$bytes,'')
$lease.Bytes[0]=$lease.Bytes[0]-bxor 1
$blocked=$false;$message=''
try{$lease.Retire()}catch{$blocked=$true;$message=$_.Exception.Message}
$replacement=(New-Object Text.UTF8Encoding($false)).GetBytes('replacement')
$created=[StMobile.PinnedFileOperations]::CreateNew('${validationPath}',$replacement,'')
[StMobile.PinnedFileOperations]::DeleteExact('${validationPath}',$replacement,$created.ParentToken,$created.FileToken)
[pscustomobject]@{blocked=$blocked;pathReported=$message.Contains('${validationPath}');createNewAfterFailure=$true}|ConvertTo-Json -Compress
`,
    ], { encoding: 'utf8', windowsHide: true }));
    assert.deepEqual(retirementValidation, { blocked: true, pathReported: true, createNewAfterFailure: true });
    const hardKillPath = path.join(temporaryRoot, 'hard-kill-reservation').replaceAll("'", "''");
    const worker = spawn('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-Command', `
. '${common}'
$current=[Diagnostics.Process]::GetCurrentProcess();$current.PriorityClass=[Diagnostics.ProcessPriorityClass]::Idle
if($current.PriorityClass -ne [Diagnostics.ProcessPriorityClass]::Idle){throw 'reservation worker priority is not Idle'}
$bytes=(New-Object System.Text.UTF8Encoding($false)).GetBytes('reservation')
$lease=[StMobile.PinnedFileOperations]::ReserveNew('${hardKillPath}',$bytes,'')
[Console]::Out.WriteLine('READY');[Console]::Out.Flush()
Start-Sleep -Seconds 30
`,
    ], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    const [ready] = await Promise.race([
      once(worker.stdout, 'data'),
      new Promise((_, reject) => setTimeout(() => reject(new Error('reservation worker readiness timeout')), 8_000)),
    ]);
    assert.match(String(ready), /READY/);
    const collision = spawnSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-Command',
      `[Diagnostics.Process]::GetCurrentProcess().PriorityClass=[Diagnostics.ProcessPriorityClass]::Idle;. '${common}';$b=(New-Object System.Text.UTF8Encoding($false)).GetBytes('foreign');[void][StMobile.PinnedFileOperations]::ReserveNew('${hardKillPath}',$b,'')`,
    ], { encoding: 'utf8', windowsHide: true });
    assert.notEqual(collision.status, 0, 'held reservation must block a second create-new lease');
    worker.kill();
    await once(worker, 'exit');
    const postKill = spawnSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-Command',
      `[Diagnostics.Process]::GetCurrentProcess().PriorityClass=[Diagnostics.ProcessPriorityClass]::Idle;. '${common}';$b=(New-Object System.Text.UTF8Encoding($false)).GetBytes('post-kill');$i=[StMobile.PinnedFileOperations]::CreateNew('${hardKillPath}',$b,'');[StMobile.PinnedFileOperations]::DeleteExact('${hardKillPath}',$b,$i.ParentToken,$i.FileToken)`,
    ], { encoding: 'utf8', windowsHide: true });
    assert.equal(postKill.status, 0, postKill.stderr);
  } finally { await rm(temporaryRoot, { recursive: true, force: true }); }
});

test('direct launch preflights stale ownership and stop paths prove final termination', async () => {
  const start = await text('scripts/Start-StMobile.ps1');
  const stop = await text('scripts/Stop-StMobile.ps1');
  const stopTray = await text('scripts/Stop-StMobileTray.ps1');
  const direct = start.indexOf('if (-not $NoStartSillyTavern -and -not (Test-LoopbackSillyTavern))');
  const preflight = start.indexOf('Clear-StaleSillyTavernOwnershipForLaunch', direct);
  const launch = start.indexOf('Start-HiddenIdleProcess', preflight);
  assert.ok(direct >= 0 && preflight > direct && launch > preflight,
    'direct launch must resolve the complete existing PID/JSON ownership set before spawning ST');
  assert.match(start, /Write-StMobileBytesCreateNew \$SillyTavernPidFile \$stPidBytesWritten/);
  assert.match(start, /Write-StMobileBytesCreateNew \$GatewayProcessRecord \$gatewayRecordBytesWritten/);
  assert.match(start, /function Stop-JustLaunchedProcessAndConfirm/);
  assert.match(start, /PinProcess\(\$process\)/);
  assert.match(start, /Assert-StMobilePinnedProcessIdentity[\s\S]*-ExpectedProcessStartTimeUtc \$ExpectedStartIdentity[\s\S]*-OwnershipName \$Name/);
  assert.match(start, /TerminatePinnedProcess\(\$Process, 1\)/);
  assert.doesNotMatch(start, /Stop-Process\s+-Id/);
  assert.match(start, /WaitForExit\(10000\)/);
  assert.match(start, /Ownership files were preserved/);
  const tray = await text('scripts/Start-StMobileTray.ps1');
  assert.match(tray, /Write-StMobileBytesCreateNew \$TrayProcessRecord \$processRecordBytes/);
  assert.doesNotMatch(tray, /processRecordTemp|Move-Item .*TrayProcessRecord.*-Force/);
  assert.match(stop, /SillyTavern PID .* remained alive after pinned-handle termination/);
  assert.match(stop, /Gateway PID .* remained alive after pinned-handle termination/);
  assert.match(stopTray, /Tray PID .* remained alive after pinned-handle termination/);
  assert.match(stop, /TerminatePinnedProcess/);
  assert.match(stopTray, /TerminatePinnedProcess/);
  assert.match(stop, /WaitForExit\(10000\)/);
  assert.match(stopTray, /WaitForExit\(10000\)/);
});

test('relative server.js provenance is accepted only for the root actually served', { timeout: 20_000 }, async () => {
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'st-mobile-root-proof-'));
  const servedRoot = path.join(temporaryRoot, 'served');
  const foreignRoot = path.join(temporaryRoot, 'foreign');
  await mkdir(path.join(servedRoot, 'public'), { recursive: true });
  await mkdir(path.join(foreignRoot, 'public'), { recursive: true });
  const server = spawn(process.execPath, ['-e', [
    "const http=require('http'),fs=require('fs'),path=require('path');",
    "const root=process.env.ST_PROOF_ROOT;",
    "const s=http.createServer((q,r)=>{const n=path.basename(q.url);const p=path.join(root,'public',n);fs.readFile(p,(e,b)=>{if(e){r.statusCode=404;r.end('no');}else{r.end(b);}})});",
    "s.listen(0,'127.0.0.1',()=>process.stdout.write(String(s.address().port)+'\\n'));",
  ].join('')], {
    stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
    env: { ...process.env, ST_PROOF_ROOT: servedRoot },
  });
  try {
    const [portChunk] = await once(server.stdout, 'data');
    const port = Number(String(portChunk).trim());
    const common = path.join(root, 'scripts', 'StMobileTrayCommon.ps1').replaceAll("'", "''");
    const script = `
. '${common}'
[pscustomobject]@{
  served = Test-StMobileServedRootChallenge -Port ${port} -SillyTavernRoot '${servedRoot.replaceAll("'", "''")}'
  foreign = Test-StMobileServedRootChallenge -Port ${port} -SillyTavernRoot '${foreignRoot.replaceAll("'", "''")}'
} | ConvertTo-Json -Compress
`;
    const result = JSON.parse(execFileSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script,
    ], { encoding: 'utf8', windowsHide: true }));
    assert.equal(result.served, true);
    assert.equal(result.foreign, false);
    assert.deepEqual(await readdir(path.join(servedRoot, 'public')), []);
    assert.deepEqual(await readdir(path.join(foreignRoot, 'public')), []);
  } finally {
    server.kill();
    await once(server, 'exit').catch(() => {});
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test('absolute server argv reuses its trusted proof timestamp across later identity checks', async () => {
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'st-mobile-absolute-proof-'));
  const common = path.join(root, 'scripts', 'StMobileTrayCommon.ps1').replaceAll("'", "''");
  const escapedRoot = temporaryRoot.replaceAll("'", "''");
  try {
    const script = `
. '${common}'
$script:fakePid = 4242
$script:fakeStart = '2026-07-11T12:00:00.000Z'
$script:fakeExe = [System.IO.Path]::GetFullPath((Join-Path '${escapedRoot}' 'node.exe'))
$script:fakeServer = [System.IO.Path]::GetFullPath((Join-Path '${escapedRoot}' 'server.js'))
[System.IO.File]::WriteAllText($script:fakeServer, '// fixture')
function Get-NetTCPConnection { param($State,$LocalPort,$ErrorAction) [pscustomobject]@{LocalAddress='127.0.0.1';OwningProcess=$script:fakePid} }
function Get-Process { param([int]$Id,$ErrorAction) if($Id -eq $script:fakePid){[pscustomobject]@{Id=$script:fakePid;ProcessName='node';Path=$script:fakeExe;StartTime=[datetime]::Parse('2026-07-11T12:00:00Z').ToUniversalTime()}} }
function Get-CimInstance { param($ClassName,$Filter,$ErrorAction) [pscustomobject]@{ExecutablePath=$script:fakeExe;CommandLine=('"' + $script:fakeExe + '" "' + $script:fakeServer + '"')} }
function Get-StMobileProcessStartIdentity { param([object]$Process) return $script:fakeStart }
function Test-SillyTavernHttpIdentity { param([int]$Port) return $true }
$trusted = [pscustomobject][ordered]@{
  schema='st-mobile-sillytavern-process/v2'; pid=[int]$script:fakePid
  processStartTimeUtc=$script:fakeStart; executablePath=$script:fakeExe
  sillyTavernRoot=[System.IO.Path]::GetFullPath('${escapedRoot}'); serverScriptPath=$script:fakeServer
  provenance='start-st-mobile'; instanceId='00000000-0000-0000-0000-000000000001'
  rootProofMethod='absolute-server-argv-v1'; rootProofAtUtc='2026-07-11T12:00:01.000Z'
}
$first = Get-StMobileSillyTavernCandidateSession -Port 3000 -SillyTavernRoot '${escapedRoot}' -TrustedRecord $trusted
Start-Sleep -Milliseconds 20
$second = Get-StMobileSillyTavernCandidateSession -Port 3000 -SillyTavernRoot '${escapedRoot}' -TrustedRecord $trusted
$wrongProof = $trusted.PSObject.Copy(); $wrongProof.rootProofMethod='served-random-challenge-v1'
$rejected = Get-StMobileSillyTavernCandidateSession -Port 3000 -SillyTavernRoot '${escapedRoot}' -TrustedRecord $wrongProof
[pscustomobject]@{
  firstExact=$first.RootProofAtUtc -ceq $trusted.rootProofAtUtc
  secondExact=$second.RootProofAtUtc -ceq $trusted.rootProofAtUtc
  stable=$first.RootProofAtUtc -ceq $second.RootProofAtUtc
  mismatchedMethodRejected=$null -eq $rejected
} | ConvertTo-Json -Compress
`;
    const result = JSON.parse(execFileSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script,
    ], { encoding: 'utf8', windowsHide: true }));
    assert.deepEqual(result, {
      firstExact: true,
      secondExact: true,
      stable: true,
      mismatchedMethodRejected: true,
    });
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test('Start with Windows refuses same-name foreign and modified shortcuts without changing them', async () => {
  const temporaryStartup = await mkdtemp(path.join(tmpdir(), 'st-mobile-startup-collision-'));
  const shortcutPath = path.join(temporaryStartup, 'SillyTavern Mobile Auth Hub.lnk');
  const trayScript = path.join(root, 'scripts', 'Start-StMobileTray.ps1');
  const runTray = (mode) => spawnSync('powershell.exe', [
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', trayScript,
    '-StartupDirectory', temporaryStartup, '-Mode', mode,
  ], { encoding: 'utf8', windowsHide: true });
  const runShortcutMutation = (command) => execFileSync('powershell.exe', [
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command,
  ], {
    encoding: 'utf8',
    windowsHide: true,
    env: { ...process.env, ST_TEST_SHORTCUT: shortcutPath },
  });

  try {
    runShortcutMutation(`
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($env:ST_TEST_SHORTCUT)
$shortcut.TargetPath = Join-Path $env:SystemRoot 'System32\\notepad.exe'
$shortcut.Arguments = '--foreign-owner'
$shortcut.WorkingDirectory = $env:SystemRoot
$shortcut.Description = 'Foreign same-name shortcut'
$shortcut.WindowStyle = 1
$shortcut.IconLocation = (Join-Path $env:SystemRoot 'System32\\notepad.exe') + ',0'
$shortcut.Hotkey = 'CTRL+ALT+F12'
$shortcut.Save()
`);
    const foreignBytes = await readFile(shortcutPath);
    const refusedOverwrite = runTray('EnableStartup');
    assert.notEqual(refusedOverwrite.status, 0);
    assert.match(`${refusedOverwrite.stdout}\n${refusedOverwrite.stderr}`, /Refusing to overwrite modified or unrecognized startup shortcut/);
    assert.deepEqual(await readFile(shortcutPath), foreignBytes);

    await unlink(shortcutPath);
    const enabled = runTray('EnableStartup');
    assert.equal(enabled.status, 0, enabled.stderr);

    runShortcutMutation(`
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($env:ST_TEST_SHORTCUT)
$shortcut.Arguments = $shortcut.Arguments + ' -Injected'
$shortcut.IconLocation = (Join-Path $env:SystemRoot 'System32\\notepad.exe') + ',0'
$shortcut.Save()
`);
    const modifiedBytes = await readFile(shortcutPath);
    const refusedRemoval = runTray('DisableStartup');
    assert.notEqual(refusedRemoval.status, 0);
    assert.match(`${refusedRemoval.stdout}\n${refusedRemoval.stderr}`, /Refusing to remove modified or unrecognized startup shortcut/);
    assert.deepEqual(await readFile(shortcutPath), modifiedBytes);
  } finally {
    await rm(temporaryStartup, { recursive: true, force: true });
  }
});

test('ST Launcher option-1 filter is reversible and fails closed around the exact launch anchor', async () => {
  const filterScript = path.join(root, 'scripts', 'StLauncherIntegrationFilter.ps1');
  const installer = await text('scripts/Install-StLauncherIntegration.ps1');
  const fixture = [
    '@echo off',
    'if "%sslPathsFound%"=="true" (',
    '    start "" cmd /k "launch"',
    ') else (',
    '    start "" cmd /k "launch"',
    ')',
    '',
    'if %ps_errorlevel% equ 0 (',
    '    exit /b 0',
    ')',
    '',
    'REM Clear the old log file if it exists',
    'echo done',
    '',
  ].join('\r\n');
  const smudged = execFileSync('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', filterScript, '-Mode', 'Smudge',
  ], { input: fixture, encoding: 'utf8', windowsHide: true });
  assert.match(smudged, /REM >>> ST MOBILE AUTH HUB INTEGRATION \(managed\)/);
  assert.match(smudged, /Launch-StMobileTray\.ps1/);
  assert.match(smudged, /-WindowStyle Hidden/);
  assert.match(smudged, /-SillyTavernRoot "%st_install_path%"/);
  assert.match(smudged, /REM Clear the old log file if it exists/);

  const cleaned = execFileSync('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', filterScript, '-Mode', 'Clean',
  ], { input: smudged, encoding: 'utf8', windowsHide: true });
  assert.equal(cleaned.replaceAll('\r\n', '\n'), fixture.replaceAll('\r\n', '\n'));

  for (const exactFixture of [
    fixture.replace('echo done', 'echo café 日本語'),
    fixture.replace('echo done\r\n', 'echo no-final-newline').replace(/\r\n$/, ''),
  ]) {
    const originalBuffer = Buffer.from(exactFixture, 'utf8');
    const exactSmudged = execFileSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-File', filterScript, '-Mode', 'Smudge',
    ], { input: originalBuffer, windowsHide: true });
    const exactCleaned = execFileSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-File', filterScript, '-Mode', 'Clean',
    ], { input: exactSmudged, windowsHide: true });
    assert.deepEqual(exactCleaned, originalBuffer);
  }

  const filterArgs = [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', filterScript, '-Mode', 'Clean',
  ];
  const modifiedBlock = spawnSync('powershell.exe', filterArgs, {
    input: smudged.replace('-WindowStyle Hidden', '-WindowStyle Normal'),
    encoding: 'utf8',
    windowsHide: true,
  });
  assert.notEqual(modifiedBlock.status, 0);
  assert.match(`${modifiedBlock.stdout}\n${modifiedBlock.stderr}`, /integration block was modified or duplicated/);

  const duplicateMarker = spawnSync('powershell.exe', filterArgs, {
    input: smudged.replace(
      'REM >>> ST MOBILE AUTH HUB INTEGRATION (managed)',
      'REM >>> ST MOBILE AUTH HUB INTEGRATION (managed)\r\nREM >>> ST MOBILE AUTH HUB INTEGRATION (managed)',
    ),
    encoding: 'utf8',
    windowsHide: true,
  });
  assert.notEqual(duplicateMarker.status, 0);
  assert.match(`${duplicateMarker.stdout}\n${duplicateMarker.stderr}`, /markers are missing or duplicated/);

  const canonicalBlock = smudged.match(/REM >>> ST MOBILE AUTH HUB INTEGRATION \(managed\)[\s\S]*?REM <<< ST MOBILE AUTH HUB INTEGRATION \(managed\)\r?\n/)[0];
  const movedBlock = spawnSync('powershell.exe', filterArgs, {
    input: canonicalBlock + smudged.replace(canonicalBlock, ''),
    encoding: 'utf8',
    windowsHide: true,
  });
  assert.notEqual(movedBlock.status, 0);
  assert.match(`${movedBlock.stdout}\n${movedBlock.stderr}`, /exact canonical anchor position/);
  assert.match(installer, /stmobileauthhubv1/);
  assert.match(installer, /"filter\.\$FilterName\.clean"/);
  assert.match(installer, /"filter\.\$FilterName\.smudge"/);
  assert.match(installer, /"filter\.\$FilterName\.required"/);
  assert.match(installer, /targetGitClean/);
  assert.match(installer, /non-managed Git blob changes/);
  assert.match(installer, /hash-object/);
});

test('ST Launcher integration survives a clean Git checkout without dirtying upstream option 1', async () => {
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'st-mobile-launcher-repo-'));
  const launcherRoot = path.join(temporaryRoot, 'launcher');
  const backupBase = path.join(temporaryRoot, 'backups');
  const targetRelative = 'bin/functions/Toolbox/App_Launcher/Core_Utilities/update_start_st.bat';
  const target = path.join(launcherRoot, ...targetRelative.split('/'));
  const installerScript = path.join(root, 'scripts', 'Install-StLauncherIntegration.ps1');
  const fixture = [
    '@echo off',
    'if "%sslPathsFound%"=="true" (',
    '    start "" cmd /k "launch"',
    ') else (',
    '    start "" cmd /k "launch"',
    ')',
    '',
    'if %ps_errorlevel% equ 0 (',
    '    exit /b 0',
    ')',
    '',
    'REM Clear the old log file if it exists',
    'echo done',
    '',
  ].join('\r\n');
  const runGit = (...args) => execFileSync('git', ['-C', launcherRoot, ...args], {
    encoding: 'utf8',
    windowsHide: true,
  });
  const runInstallerWith = (executable, mode) => JSON.parse(execFileSync(executable, [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', installerScript,
    '-Mode', mode,
    '-LauncherRoot', launcherRoot,
    '-BackupBase', backupBase,
  ], { encoding: 'utf8', windowsHide: true }));
  const runInstaller = (mode) => runInstallerWith('powershell.exe', mode);

  try {
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, fixture, 'utf8');
    const originalBytes = await readFile(target);
    runGit('init');
    runGit('config', 'user.name', 'ST Mobile Test');
    runGit('config', 'user.email', 'st-mobile-test@example.invalid');
    runGit('config', 'core.autocrlf', 'true');
    runGit('add', '--', targetRelative);
    runGit('commit', '-m', 'fixture');

    const installed = runInstaller('Install');
    assert.equal(installed.markerPresent, true);
    assert.equal(installed.targetGitClean, true);
    assert.equal(installed.filterName, 'stmobileauthhubv1');
    assert.equal(runGit('status', '--porcelain', '--', targetRelative), '');
    assert.match(await readFile(target, 'utf8'), /Launch-StMobileTray\.ps1/);
    assert.match(runGit('config', '--local', '--get', 'filter.stmobileauthhubv1.clean'), /-WindowStyle Hidden/);

    const pwshStatus = runInstallerWith('pwsh.exe', 'Status');
    assert.equal(pwshStatus.state, 'current');
    assert.equal(pwshStatus.targetGitClean, true);
    assert.deepEqual(pwshStatus.managedConfig['filter.stmobile.clean'], []);
    assert.deepEqual(pwshStatus.managedConfig['filter.stmobile.smudge'], []);
    assert.deepEqual(pwshStatus.managedConfig['filter.stmobile.required'], []);
    assert.deepEqual(pwshStatus.managedConfig['filter.stmobileauthhubv1.required'], ['true']);
    assert.deepEqual(pwshStatus.managedConfig['filter.stmobileauthhubv1.clean'], [
      runGit('config', '--local', '--get', 'filter.stmobileauthhubv1.clean').trim(),
    ]);
    assert.deepEqual(pwshStatus.managedConfig['filter.stmobileauthhubv1.smudge'], [
      runGit('config', '--local', '--get', 'filter.stmobileauthhubv1.smudge').trim(),
    ]);
    assert.equal(pwshStatus.effectiveFilter, `${targetRelative}: filter: stmobileauthhubv1`);
    assert.match(pwshStatus.headBlobId, /^[0-9a-f]{40,64}$/);
    assert.equal(pwshStatus.cleanBlobId, pwshStatus.headBlobId);
    assert.equal(pwshStatus.roundTripBlobId, pwshStatus.headBlobId);

    const currentClean = runGit('config', '--local', '--get', 'filter.stmobileauthhubv1.clean').trim();
    const currentSmudge = runGit('config', '--local', '--get', 'filter.stmobileauthhubv1.smudge').trim();
    const legacyLaunchScript = path.join(root, 'scripts', 'Launch-StMobileTray.ps1');
    const legacyBlock = [
      'REM >>> ST MOBILE AUTH HUB INTEGRATION (managed)',
      `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "${legacyLaunchScript}" -SillyTavernRoot "%st_install_path%" -LauncherIconPath "%~dp0..\\..\\..\\..\\..\\st-launcher.ico"`,
      'REM <<< ST MOBILE AUTH HUB INTEGRATION (managed)',
      '',
      '',
    ].join('\r\n');
    await writeFile(target, fixture.replace('REM Clear the old log file if it exists', `${legacyBlock}REM Clear the old log file if it exists`), 'utf8');
    const attributesPath = path.join(launcherRoot, '.git', 'info', 'attributes');
    await writeFile(attributesPath, (await readFile(attributesPath, 'utf8')).replace('filter=stmobileauthhubv1', 'filter=stmobile'), 'utf8');
    const configPath = path.join(launcherRoot, '.git', 'config');
    const currentConfigText = await readFile(configPath, 'utf8');
    const legacyConfigText = currentConfigText.replace(
      /^# >>> ST MOBILE AUTH HUB FILTER CONFIG \(managed\)\r?\n[\s\S]*?^# <<< ST MOBILE AUTH HUB FILTER CONFIG \(managed\)\r?\n/m,
      '',
    );
    assert.notEqual(legacyConfigText, currentConfigText, 'legacy migration fixture must remove the current managed config block');
    await writeFile(configPath, legacyConfigText, 'utf8');
    runGit('config', '--local', 'filter.stmobile.clean', currentClean.replace(' -WindowStyle Hidden', ''));
    runGit('config', '--local', 'filter.stmobile.smudge', currentSmudge.replace(' -WindowStyle Hidden', ''));
    runGit('config', '--local', 'filter.stmobile.required', 'true');
    runGit('add', '--', targetRelative);
    const legacy = runInstaller('Status');
    assert.equal(legacy.state, 'migration');
    assert.equal(legacy.markerState, 'migration-legacy');
    assert.equal(legacy.targetGitClean, true);

    const migrated = runInstaller('Install');
    assert.equal(migrated.state, 'current');
    assert.equal(migrated.targetGitClean, true);
    assert.match(await readFile(target, 'utf8'), /-WindowStyle Hidden/);
    const removedLegacyConfig = spawnSync('git', ['-C', launcherRoot, 'config', '--local', '--get-all', 'filter.stmobile.clean'], {
      encoding: 'utf8', windowsHide: true,
    });
    assert.equal(removedLegacyConfig.status, 1);
    assert.equal(removedLegacyConfig.stdout, '');

    await unlink(target);
    runGit('checkout-index', '--force', '--', targetRelative);
    assert.match(await readFile(target, 'utf8'), /Launch-StMobileTray\.ps1/);
    assert.equal(runGit('status', '--porcelain', '--', targetRelative), '');

    const removed = runInstaller('Remove');
    assert.equal(removed.markerPresent, false);
    assert.equal(removed.attributePresent, false);
    assert.equal(removed.targetGitClean, true);
    assert.doesNotMatch(await readFile(target, 'utf8'), /ST MOBILE AUTH HUB INTEGRATION/);
    assert.deepEqual(await readFile(target), originalBytes);
    assert.equal(runGit('status', '--porcelain', '--', targetRelative), '');
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test('ST Launcher installer fails closed on collisions and rolls back every mutated surface', { timeout: 180_000 }, async () => {
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'st-mobile-launcher-adversarial-'));
  const installerScript = path.join(root, 'scripts', 'Install-StLauncherIntegration.ps1');
  const installerSource = await readFile(installerScript, 'utf8');
  const targetRelative = 'bin/functions/Toolbox/App_Launcher/Core_Utilities/update_start_st.bat';
  const fixture = [
    '@echo off',
    'if "%sslPathsFound%"=="true" (',
    '    start "" cmd /k "launch"',
    ') else (',
    '    start "" cmd /k "launch"',
    ')',
    '',
    'if %ps_errorlevel% equ 0 (',
    '    exit /b 0',
    ')',
    '',
    'REM Clear the old log file if it exists',
    'echo done',
    '',
  ].join('\r\n');
  const exists = async (file) => stat(file).then(() => true, () => false);
  const runGit = (launcherRoot, ...args) => execFileSync('git', ['-C', launcherRoot, ...args], {
    encoding: 'utf8',
    windowsHide: true,
  });
  const createRepo = async (name, contents = fixture) => {
    const launcherRoot = path.join(temporaryRoot, name);
    const target = path.join(launcherRoot, ...targetRelative.split('/'));
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, contents, 'utf8');
    runGit(launcherRoot, 'init');
    runGit(launcherRoot, 'config', 'user.name', 'ST Mobile Test');
    runGit(launcherRoot, 'config', 'user.email', 'st-mobile-test@example.invalid');
    runGit(launcherRoot, 'config', 'core.autocrlf', 'false');
    runGit(launcherRoot, 'add', '--', targetRelative);
    runGit(launcherRoot, 'commit', '-m', 'fixture');
    return {
      launcherRoot,
      target,
      attributes: path.join(launcherRoot, '.git', 'info', 'attributes'),
      config: path.join(launcherRoot, '.git', 'config'),
      index: path.join(launcherRoot, '.git', 'index'),
    };
  };
  const runInstaller = (repo, mode, extraEnv = {}, scriptPath = installerScript) => spawnSync('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', scriptPath, '-Mode', mode,
    '-LauncherRoot', repo.launcherRoot,
    '-BackupBase', path.join(temporaryRoot, 'backups'),
  ], {
    encoding: 'utf8', windowsHide: true, maxBuffer: 4 * 1024 * 1024,
    env: { ...process.env, ...extraEnv },
  });
  const snapshot = async (repo) => ({
    target: await readFile(repo.target),
    attributes: await exists(repo.attributes) ? await readFile(repo.attributes) : null,
    config: await readFile(repo.config),
    index: await readFile(repo.index),
    indexEntries: runGit(repo.launcherRoot, 'ls-files', '--stage'),
  });
  const rawSnapshot = async (repo) => ({
    target: await readFile(repo.target),
    attributes: await exists(repo.attributes) ? await readFile(repo.attributes) : null,
    config: await readFile(repo.config),
    index: await readFile(repo.index),
  });
  const casResidue = async (repo) => {
    const entries = [];
    for (const directory of [path.join(repo.launcherRoot, '.git'), path.dirname(repo.target)]) {
      for (const entry of await readdir(directory, { recursive: true })) {
        if (/\.st-mobile-(?:cas|rollback)-/i.test(entry)) entries.push(path.join(directory, entry));
      }
    }
    return entries;
  };
  const createHarness = async (name, anchorOrInjections, injectedPowerShell = '') => {
    const scriptsRoot = path.join(root, 'scripts').replaceAll("'", "''");
    let instrumented = installerSource.replaceAll('$PSScriptRoot', `'${scriptsRoot}'`);
    const injections = typeof anchorOrInjections === 'string'
      ? [[anchorOrInjections, injectedPowerShell]]
      : Object.entries(anchorOrInjections);
    for (const [anchor, injection] of injections) {
      const marker = `# TEST-HARNESS-ANCHOR: ${anchor}`;
      assert.equal(instrumented.split(marker).length - 1, 1, `missing unique harness anchor ${anchor}`);
      instrumented = instrumented.replace(marker, `${marker}\r\n${injection}`);
    }
    const harnessPath = path.join(temporaryRoot, `installer-harness-${name}.ps1`);
    await writeFile(harnessPath, instrumented, 'utf8');
    return harnessPath;
  };

  try {
    const foreign = await createRepo('foreign-filter');
    runGit(foreign.launcherRoot, 'config', '--local', 'filter.stmobileauthhubv1.clean', 'foreign-command');
    const foreignBefore = await snapshot(foreign);
    const foreignResult = runInstaller(foreign, 'Install');
    assert.notEqual(foreignResult.status, 0);
    assert.match(`${foreignResult.stdout}\n${foreignResult.stderr}`, /ownership state is mixed or modified/);
    assert.deepEqual(await snapshot(foreign), foreignBefore);

    const noAnchorFixture = '@echo off\r\necho unsupported upstream shape\r\n';
    const noAnchor = await createRepo('no-anchor', noAnchorFixture);
    const noAnchorBefore = await snapshot(noAnchor);
    const noAnchorResult = runInstaller(noAnchor, 'Install');
    assert.notEqual(noAnchorResult.status, 0);
    assert.match(`${noAnchorResult.stdout}\n${noAnchorResult.stderr}`, /must contain exactly one supported injection anchor/);
    assert.deepEqual(await snapshot(noAnchor), noAnchorBefore);

    const rollback = await createRepo('rollback');
    const unrelated = path.join(rollback.launcherRoot, 'unrelated.txt');
    await writeFile(unrelated, 'unrelated staged sentinel\n', 'utf8');
    runGit(rollback.launcherRoot, 'add', '--', 'unrelated.txt');
    runGit(rollback.launcherRoot, 'config', '--local', 'test.unrelated-sentinel', 'preserve-me');
    const rollbackTargetBefore = await readFile(rollback.target);
    const rollbackCachedBefore = runGit(rollback.launcherRoot, 'diff', '--cached', '--binary');
    const rollbackHarness = await createHarness(
      'rollback-final-readback',
      'after-effective-attributes',
      "throw 'Injected copied-harness final-readback failure'",
    );
    const rollbackResult = runInstaller(rollback, 'Install', {}, rollbackHarness);
    assert.notEqual(rollbackResult.status, 0);
    assert.match(`${rollbackResult.stdout}\n${rollbackResult.stderr}`, /failed and owned state was rolled back/);
    assert.deepEqual(await readFile(rollback.target), rollbackTargetBefore);
    assert.equal(await exists(rollback.attributes), false);
    assert.equal(runGit(rollback.launcherRoot, 'diff', '--cached', '--binary'), rollbackCachedBefore);
    for (const suffix of ['clean', 'smudge', 'required']) {
      const owned = spawnSync('git', ['-C', rollback.launcherRoot, 'config', '--local', '--get-all', `filter.stmobileauthhubv1.${suffix}`], {
        encoding: 'utf8', windowsHide: true,
      });
      assert.equal(owned.status, 1);
    }
    assert.equal(runGit(rollback.launcherRoot, 'config', '--local', '--get', 'test.unrelated-sentinel').trim(), 'preserve-me');
    assert.match(runGit(rollback.launcherRoot, 'status', '--porcelain'), /A  unrelated\.txt/);

    const afterSnapshotInjection = {
      target: '[System.IO.File]::WriteAllBytes($TargetPath, $StrictUtf8.GetBytes("@echo off`r`necho foreign target after snapshot`r`n"))',
      attributes: 'New-Item -ItemType Directory -Force -Path (Split-Path -Parent $InfoAttributes) | Out-Null\r\n[System.IO.File]::WriteAllBytes($InfoAttributes, $StrictUtf8.GetBytes("# foreign attributes after snapshot`r`n"))',
      config: '[void](Invoke-Git @(\'config\', \'--local\', "filter.$FilterName.clean", \'foreign-after-snapshot\'))',
      index: '[void](Invoke-Git @(\'update-index\', \'--add\', \'--cacheinfo\', \'100644\', $headBlobId, \'st-mobile-after-snapshot-index-collision.txt\'))',
    };
    for (const surface of Object.keys(afterSnapshotInjection)) {
      const collision = await createRepo(`after-snapshot-${surface}`);
      const before = await snapshot(collision);
      const harness = await createHarness(`after-snapshot-${surface}`, 'after-snapshots', afterSnapshotInjection[surface]);
      const result = runInstaller(collision, 'Install', {}, harness);
      assert.notEqual(result.status, 0, `after-snapshot ${surface} collision must fail closed`);
      assert.match(`${result.stdout}\n${result.stderr}`, /generation changed after snapshot/);
      const after = await snapshot(collision);
      if (surface !== 'target') assert.deepEqual(after.target, before.target);
      if (surface !== 'attributes') assert.deepEqual(after.attributes, before.attributes);
      if (surface !== 'config') assert.deepEqual(after.config, before.config);
      if (surface !== 'index') assert.equal(after.indexEntries, before.indexEntries);
      if (surface === 'target') {
        assert.match(after.target.toString('utf8'), /foreign target after snapshot/);
      } else if (surface === 'attributes') {
        assert.match(after.attributes.toString('utf8'), /foreign attributes after snapshot/);
      } else if (surface === 'config') {
        assert.equal(runGit(collision.launcherRoot, 'config', '--local', '--get', 'filter.stmobileauthhubv1.clean').trim(), 'foreign-after-snapshot');
      } else {
        assert.match(runGit(collision.launcherRoot, 'ls-files', '--stage', '--', 'st-mobile-after-snapshot-index-collision.txt'), /st-mobile-after-snapshot-index-collision\.txt/);
      }
      assert.deepEqual(await casResidue(collision), []);
    }

    const afterSnapshotEffective = await createRepo('after-snapshot-effective-attributes');
    const afterSnapshotEffectiveBefore = await snapshot(afterSnapshotEffective);
    const afterSnapshotEffectiveHarness = await createHarness(
      'after-snapshot-effective-attributes',
      'after-snapshots',
      '[System.IO.File]::WriteAllBytes((Join-Path $LauncherRoot \'.gitattributes\'), $StrictUtf8.GetBytes("$TargetRelative filter=foreign`n"))',
    );
    const afterSnapshotEffectiveResult = runInstaller(afterSnapshotEffective, 'Install', {}, afterSnapshotEffectiveHarness);
    assert.notEqual(afterSnapshotEffectiveResult.status, 0);
    assert.match(`${afterSnapshotEffectiveResult.stdout}\n${afterSnapshotEffectiveResult.stderr}`, /Effective Git filter/);
    assert.deepEqual(await snapshot(afterSnapshotEffective), afterSnapshotEffectiveBefore);
    assert.equal(await readFile(path.join(afterSnapshotEffective.launcherRoot, '.gitattributes'), 'utf8'), `${targetRelative} filter=foreign\n`);
    assert.deepEqual(await casResidue(afterSnapshotEffective), []);

    const afterSnapshotUnrelatedConfig = await createRepo('after-snapshot-unrelated-config');
    const afterSnapshotUnrelatedBefore = await snapshot(afterSnapshotUnrelatedConfig);
    const afterSnapshotUnrelatedHarness = await createHarness(
      'after-snapshot-unrelated-config',
      'after-snapshots',
      '[void](Invoke-Git @(\'config\', \'--local\', \'test.concurrent-after-snapshot\', \'preserve-after-snapshot\'))',
    );
    const afterSnapshotUnrelatedResult = runInstaller(afterSnapshotUnrelatedConfig, 'Install', {}, afterSnapshotUnrelatedHarness);
    assert.notEqual(afterSnapshotUnrelatedResult.status, 0);
    assert.match(`${afterSnapshotUnrelatedResult.stdout}\n${afterSnapshotUnrelatedResult.stderr}`, /Git config generation changed after snapshot/);
    assert.deepEqual(await readFile(afterSnapshotUnrelatedConfig.target), afterSnapshotUnrelatedBefore.target);
    assert.equal(await exists(afterSnapshotUnrelatedConfig.attributes), false);
    assert.equal(runGit(afterSnapshotUnrelatedConfig.launcherRoot, 'ls-files', '--stage'), afterSnapshotUnrelatedBefore.indexEntries);
    assert.equal(runGit(afterSnapshotUnrelatedConfig.launcherRoot, 'config', '--local', '--get', 'test.concurrent-after-snapshot').trim(), 'preserve-after-snapshot');
    assert.deepEqual(await casResidue(afterSnapshotUnrelatedConfig), []);

    const sameBytesNewGeneration = await createRepo('after-snapshot-same-bytes-new-generation');
    const sameBytesNewGenerationBefore = await snapshot(sameBytesNewGeneration);
    const sameBytesNewGenerationHarness = await createHarness(
      'after-snapshot-same-bytes-new-generation',
      'after-snapshots',
      '$oldGeneration = $TargetPath + \'.same-bytes-prior\'\r\n[void][StMobile.PinnedFileOperations]::MoveExact($TargetPath, $oldGeneration, $originalTarget.Bytes, $targetIdentity.ParentToken, $targetIdentity.FileToken)\r\n[void][StMobile.PinnedFileOperations]::CreateNew($TargetPath, $originalTarget.Bytes, $targetIdentity.ParentToken)',
    );
    const sameBytesNewGenerationResult = runInstaller(sameBytesNewGeneration, 'Install', {}, sameBytesNewGenerationHarness);
    assert.notEqual(sameBytesNewGenerationResult.status, 0);
    assert.match(`${sameBytesNewGenerationResult.stdout}\n${sameBytesNewGenerationResult.stderr}`, /target generation changed after snapshot/);
    assert.deepEqual(await snapshot(sameBytesNewGeneration), sameBytesNewGenerationBefore, 'same bytes must not conceal a changed file ID');
    assert.deepEqual(await readFile(`${sameBytesNewGeneration.target}.same-bytes-prior`), sameBytesNewGenerationBefore.target);
    assert.deepEqual(await casResidue(sameBytesNewGeneration), []);

    const reparseParent = await createRepo('after-snapshot-reparse-parent');
    const reparseParentBefore = await snapshot(reparseParent);
    const reparseParentHarness = await createHarness(
      'after-snapshot-reparse-parent',
      'after-snapshots',
      '$targetParent = Split-Path -Parent $TargetPath\r\n$realParent = $targetParent + \'.real-parent\'\r\nMove-Item -LiteralPath $targetParent -Destination $realParent\r\nNew-Item -ItemType Junction -Path $targetParent -Target $realParent | Out-Null',
    );
    const reparseParentResult = runInstaller(reparseParent, 'Install', {}, reparseParentHarness);
    assert.notEqual(reparseParentResult.status, 0);
    assert.match(`${reparseParentResult.stdout}\n${reparseParentResult.stderr}`, /target generation changed after snapshot/);
    assert.deepEqual(await snapshot(reparseParent), reparseParentBefore);
    assert.deepEqual(await casResidue(reparseParent), []);

    const postMoveFailure = await createRepo('post-move-publication-failure');
    const postMoveBefore = await snapshot(postMoveFailure);
    const postMoveHarness = await createHarness(
      'post-move-publication-failure',
      'after-live-generation-moved',
      "throw 'Injected failure after live generation move'",
    );
    const postMoveResult = runInstaller(postMoveFailure, 'Install', {}, postMoveHarness);
    assert.notEqual(postMoveResult.status, 0);
    assert.match(`${postMoveResult.stdout}\n${postMoveResult.stderr}`, /could not quarantine the exact live generation/);
    assert.deepEqual(await snapshot(postMoveFailure), postMoveBefore);
    assert.deepEqual(await casResidue(postMoveFailure), []);

    const postMoveTamper = await createRepo('post-move-quarantine-tamper');
    const postMoveTamperBefore = await snapshot(postMoveTamper);
    const postMoveTamperHarness = await createHarness(
      'post-move-quarantine-tamper',
      'after-live-generation-moved',
      '[System.IO.File]::WriteAllBytes($quarantine, $StrictUtf8.GetBytes("foreign post-move quarantine bytes"))\r\nthrow \'Injected post-move quarantine tamper\'',
    );
    const postMoveTamperResult = runInstaller(postMoveTamper, 'Install', {}, postMoveTamperHarness);
    assert.notEqual(postMoveTamperResult.status, 0);
    assert.match(`${postMoveTamperResult.stdout}\n${postMoveTamperResult.stderr}`, /exact frozen prior generation was recreated from immutable bytes/);
    assert.match(`${postMoveTamperResult.stdout}\n${postMoveTamperResult.stderr}`, /tampered or unreadable quarantine preserved at/);
    assert.deepEqual(await snapshot(postMoveTamper), postMoveTamperBefore);
    const postMoveTamperResidue = await casResidue(postMoveTamper);
    assert.equal(postMoveTamperResidue.length, 1, 'the foreign quarantine must be preserved and reported, not republished or silently deleted');
    assert.equal(await readFile(postMoveTamperResidue[0], 'utf8'), 'foreign post-move quarantine bytes');

    const postMoveTamperExactLive = await createRepo('post-move-quarantine-tamper-exact-live');
    const postMoveTamperExactLiveBefore = await snapshot(postMoveTamperExactLive);
    const postMoveTamperExactLiveHarness = await createHarness(
      'post-move-quarantine-tamper-exact-live',
      'after-live-generation-moved',
      '[void][StMobile.PinnedFileOperations]::MoveExact($quarantine, $Path, $priorBytes, $priorIdentity.ParentToken, $priorIdentity.FileToken)\r\n[void][StMobile.PinnedFileOperations]::CreateNew($quarantine, $StrictUtf8.GetBytes("foreign exact-live quarantine bytes"), $priorIdentity.ParentToken)\r\nthrow \'Injected exact-live post-move quarantine tamper\'',
    );
    const postMoveTamperExactLiveResult = runInstaller(postMoveTamperExactLive, 'Install', {}, postMoveTamperExactLiveHarness);
    assert.notEqual(postMoveTamperExactLiveResult.status, 0);
    const postMoveTamperExactLiveMessage = `${postMoveTamperExactLiveResult.stdout}\n${postMoveTamperExactLiveResult.stderr}`;
    assert.match(postMoveTamperExactLiveMessage, /exact frozen prior generation was already live/);
    assert.match(postMoveTamperExactLiveMessage, /tampered or blocked quarantine preserved at/);
    assert.match(postMoveTamperExactLiveMessage, /quarantine blocker:/);
    assert.deepEqual(await snapshot(postMoveTamperExactLive), postMoveTamperExactLiveBefore);
    const postMoveTamperExactLiveResidue = await casResidue(postMoveTamperExactLive);
    assert.equal(postMoveTamperExactLiveResidue.length, 1, 'the exact-live branch must preserve and report its foreign quarantine');
    assert.equal(await readFile(postMoveTamperExactLiveResidue[0], 'utf8'), 'foreign exact-live quarantine bytes');
    assert.ok(
      postMoveTamperExactLiveMessage.replaceAll(/\s/g, '').includes(postMoveTamperExactLiveResidue[0].replaceAll(/\s/g, '')),
      'the blocker must identify the exact preserved quarantine path even when PowerShell wraps the error text',
    );

    const betweenPublications = [
      {
        name: 'attributes-after-target',
        anchor: 'after-target-publication',
        injection: 'New-Item -ItemType Directory -Force -Path (Split-Path -Parent $InfoAttributes) | Out-Null\r\n[System.IO.File]::WriteAllBytes($InfoAttributes, $StrictUtf8.GetBytes("# foreign attributes between publications`r`n"))',
        verify: async (repo, before) => {
          assert.deepEqual(await readFile(repo.target), before.target);
          assert.match((await readFile(repo.attributes, 'utf8')), /foreign attributes between publications/);
          assert.deepEqual(await readFile(repo.config), before.config);
          assert.equal(runGit(repo.launcherRoot, 'ls-files', '--stage'), before.indexEntries);
        },
      },
      {
        name: 'config-after-attributes',
        anchor: 'after-attributes-publication',
        injection: '[void](Invoke-Git @(\'config\', \'--local\', "filter.$FilterName.clean", \'foreign-between-publications\'))',
        verify: async (repo, before) => {
          assert.deepEqual(await readFile(repo.target), before.target);
          assert.equal(await exists(repo.attributes), false);
          assert.equal(runGit(repo.launcherRoot, 'config', '--local', '--get', 'filter.stmobileauthhubv1.clean').trim(), 'foreign-between-publications');
          assert.equal(runGit(repo.launcherRoot, 'ls-files', '--stage'), before.indexEntries);
        },
      },
    ];
    for (const scenario of betweenPublications) {
      const collision = await createRepo(`between-${scenario.name}`);
      const before = await snapshot(collision);
      const harness = await createHarness(`between-${scenario.name}`, scenario.anchor, scenario.injection);
      const result = runInstaller(collision, 'Install', {}, harness);
      assert.notEqual(result.status, 0, `${scenario.name} must fail closed`);
      assert.match(`${result.stdout}\n${result.stderr}`, /failed and owned state was rolled back|Compare-and-swap rollback also failed/);
      await scenario.verify(collision, before);
      assert.deepEqual(await casResidue(collision), []);
    }

    const indexAfterConfig = await createRepo('index-after-config');
    const indexAfterConfigHarness = await createHarness(
      'index-after-config',
      'after-config-publication',
      '[void](Invoke-Git @(\'update-index\', \'--add\', \'--cacheinfo\', \'100644\', $headBlobId, \'st-mobile-between-publications-index.txt\'))',
    );
    const indexAfterConfigResult = runInstaller(indexAfterConfig, 'Install', {}, indexAfterConfigHarness);
    assert.equal(indexAfterConfigResult.status, 0, indexAfterConfigResult.stderr);
    assert.match(runGit(indexAfterConfig.launcherRoot, 'ls-files', '--stage', '--', 'st-mobile-between-publications-index.txt'), /st-mobile-between-publications-index\.txt/);
    assert.equal(runGit(indexAfterConfig.launcherRoot, 'status', '--porcelain', '--', targetRelative), '');
    assert.deepEqual(await casResidue(indexAfterConfig), []);

    const effectiveAttributes = await createRepo('effective-attributes-collision');
    const effectiveBefore = await snapshot(effectiveAttributes);
    const effectiveHarness = await createHarness(
      'effective-attributes',
      'after-index-publication',
      '[System.IO.File]::WriteAllBytes($InfoAttributes, $StrictUtf8.GetBytes("$TargetRelative filter=foreign`r`n"))',
    );
    const effectiveResult = runInstaller(effectiveAttributes, 'Install', {}, effectiveHarness);
    assert.notEqual(effectiveResult.status, 0);
    assert.match(`${effectiveResult.stdout}\n${effectiveResult.stderr}`, /Effective Git filter/);
    assert.match(`${effectiveResult.stdout}\n${effectiveResult.stderr}`, /Compare-and-swap rollback also failed/);
    assert.deepEqual(await readFile(effectiveAttributes.target), effectiveBefore.target);
    assert.equal(await readFile(effectiveAttributes.attributes, 'utf8'), `${targetRelative} filter=foreign\r\n`);
    assert.deepEqual(await readFile(effectiveAttributes.config), effectiveBefore.config);
    assert.equal(runGit(effectiveAttributes.launcherRoot, 'ls-files', '--stage'), effectiveBefore.indexEntries);
    assert.deepEqual(await casResidue(effectiveAttributes), []);

    const unrelatedAfterEffective = await createRepo('unrelated-config-after-effective-attributes');
    const unrelatedAfterEffectiveHarness = await createHarness(
      'unrelated-config-after-effective-attributes',
      'after-effective-attributes',
      '[void](Invoke-Git @(\'config\', \'--local\', \'test.concurrent-after-effective\', \'preserve-after-effective\'))',
    );
    const unrelatedAfterEffectiveResult = runInstaller(unrelatedAfterEffective, 'Install', {}, unrelatedAfterEffectiveHarness);
    assert.equal(unrelatedAfterEffectiveResult.status, 0, unrelatedAfterEffectiveResult.stderr);
    assert.equal(runGit(unrelatedAfterEffective.launcherRoot, 'config', '--local', '--get', 'test.concurrent-after-effective').trim(), 'preserve-after-effective');
    assert.equal(runGit(unrelatedAfterEffective.launcherRoot, 'status', '--porcelain', '--', targetRelative), '');
    assert.deepEqual(await casResidue(unrelatedAfterEffective), []);
    const unrelatedAfterEffectiveRemove = runInstaller(unrelatedAfterEffective, 'Remove');
    assert.equal(unrelatedAfterEffectiveRemove.status, 0, unrelatedAfterEffectiveRemove.stderr);
    assert.equal(runGit(unrelatedAfterEffective.launcherRoot, 'config', '--local', '--get', 'test.concurrent-after-effective').trim(), 'preserve-after-effective');
    assert.deepEqual(await casResidue(unrelatedAfterEffective), []);

    const rollbackInjection = {
      target: '[System.IO.File]::WriteAllBytes($TargetPath, $StrictUtf8.GetBytes("@echo off`r`necho foreign target during rollback`r`n"))\r\nthrow \'Injected rollback collision\'',
      attributes: '[System.IO.File]::WriteAllBytes($InfoAttributes, $StrictUtf8.GetBytes("# foreign attributes during rollback`r`n"))\r\nthrow \'Injected rollback collision\'',
      config: '[void](Invoke-Git @(\'config\', \'--local\', "filter.$FilterName.clean", \'foreign-during-rollback\'))\r\nthrow \'Injected rollback collision\'',
    };
    for (const surface of Object.keys(rollbackInjection)) {
      const collision = await createRepo(`rollback-collision-${surface}`);
      const before = await snapshot(collision);
      const harness = await createHarness(`rollback-${surface}`, 'after-index-publication', rollbackInjection[surface]);
      const result = runInstaller(collision, 'Install', {}, harness);
      assert.notEqual(result.status, 0, `rollback ${surface} collision must be reported`);
      assert.match(`${result.stdout}\n${result.stderr}`, /Compare-and-swap rollback also failed/);
      const after = await snapshot(collision);
      if (surface !== 'target') assert.deepEqual(after.target, before.target);
      if (surface !== 'attributes') assert.deepEqual(after.attributes, before.attributes);
      if (surface !== 'config') assert.deepEqual(after.config, before.config);
      assert.equal(after.indexEntries, before.indexEntries);
      if (surface === 'target') {
        assert.match(after.target.toString('utf8'), /foreign target during rollback/);
      } else if (surface === 'attributes') {
        assert.match(after.attributes.toString('utf8'), /foreign attributes during rollback/);
      } else if (surface === 'config') {
        assert.equal(runGit(collision.launcherRoot, 'config', '--local', '--get', 'filter.stmobileauthhubv1.clean').trim(), 'foreign-during-rollback');
      } else {
        assert.match(runGit(collision.launcherRoot, 'ls-files', '--stage', '--', 'st-mobile-rollback-index-collision.txt'), /st-mobile-rollback-index-collision\.txt/);
      }
      assert.deepEqual(await casResidue(collision), []);
    }


    const rollbackIndex = await createRepo('rollback-index-preservation');
    const rollbackIndexBefore = await snapshot(rollbackIndex);
    const rollbackIndexHarness = await createHarness(
      'rollback-index-preservation',
      'after-index-publication',
      '[void](Invoke-Git @(\'update-index\', \'--add\', \'--cacheinfo\', \'100644\', $headBlobId, \'st-mobile-rollback-index-collision.txt\'))\r\nthrow \'Injected rollback after unrelated index update\'',
    );
    const rollbackIndexResult = runInstaller(rollbackIndex, 'Install', {}, rollbackIndexHarness);
    assert.notEqual(rollbackIndexResult.status, 0);
    assert.match(`${rollbackIndexResult.stdout}\n${rollbackIndexResult.stderr}`, /failed and owned state was rolled back/);
    assert.deepEqual(await readFile(rollbackIndex.target), rollbackIndexBefore.target);
    assert.equal(await exists(rollbackIndex.attributes), false);
    assert.deepEqual(await readFile(rollbackIndex.config), rollbackIndexBefore.config);
    assert.match(runGit(rollbackIndex.launcherRoot, 'ls-files', '--stage', '--', 'st-mobile-rollback-index-collision.txt'), /st-mobile-rollback-index-collision\.txt/);
    assert.deepEqual(await casResidue(rollbackIndex), []);

    const changedPriorQuarantine = await createRepo('changed-prior-quarantine');
    const changedPriorBefore = await snapshot(changedPriorQuarantine);
    const changedPriorHarness = await createHarness('changed-prior-quarantine', {
      'after-index-publication': "throw 'Trigger rollback for changed prior quarantine'",
      'before-original-quarantine-restore': 'if ($Token.Surface -eq \'target\') { [System.IO.File]::WriteAllBytes($Token.OriginalQuarantine, $StrictUtf8.GetBytes("foreign quarantine bytes")) }',
    });
    const changedPriorResult = runInstaller(changedPriorQuarantine, 'Install', {}, changedPriorHarness);
    assert.notEqual(changedPriorResult.status, 0);
    assert.match(`${changedPriorResult.stdout}\n${changedPriorResult.stderr}`, /Pinned file bytes changed; refusing mutation/);
    assert.match(`${changedPriorResult.stdout}\n${changedPriorResult.stderr}`, /Compare-and-swap rollback also failed/);
    assert.match(await readFile(changedPriorQuarantine.target, 'utf8'), /ST MOBILE AUTH HUB INTEGRATION/);
    assert.doesNotMatch(await readFile(changedPriorQuarantine.target, 'utf8'), /foreign quarantine bytes/);
    assert.equal(await exists(changedPriorQuarantine.attributes), false);
    assert.deepEqual(await readFile(changedPriorQuarantine.config), changedPriorBefore.config);
    assert.equal(runGit(changedPriorQuarantine.launcherRoot, 'ls-files', '--stage'), changedPriorBefore.indexEntries);
    const changedPriorResidue = await casResidue(changedPriorQuarantine);
    assert.equal(changedPriorResidue.length, 1, 'changed prior quarantine must be preserved when pinned delete refuses it');
    assert.equal(await readFile(changedPriorResidue[0], 'utf8'), 'foreign quarantine bytes');

    const concurrentUnrelatedConfig = await createRepo('rollback-concurrent-unrelated-config');
    const concurrentUnrelatedBefore = await snapshot(concurrentUnrelatedConfig);
    const concurrentUnrelatedHarness = await createHarness(
      'rollback-concurrent-unrelated-config',
      'after-index-publication',
      '[void](Invoke-Git @(\'config\', \'--local\', \'test.concurrent-unrelated\', \'preserve-concurrent\'))\r\nthrow \'Injected unrelated config rollback\'',
    );
    const concurrentUnrelatedResult = runInstaller(concurrentUnrelatedConfig, 'Install', {}, concurrentUnrelatedHarness);
    assert.notEqual(concurrentUnrelatedResult.status, 0);
    assert.match(`${concurrentUnrelatedResult.stdout}\n${concurrentUnrelatedResult.stderr}`, /failed and owned state was rolled back/);
    assert.deepEqual(await readFile(concurrentUnrelatedConfig.target), concurrentUnrelatedBefore.target);
    assert.equal(await exists(concurrentUnrelatedConfig.attributes), false);
    assert.equal(runGit(concurrentUnrelatedConfig.launcherRoot, 'ls-files', '--stage'), concurrentUnrelatedBefore.indexEntries);
    assert.equal(runGit(concurrentUnrelatedConfig.launcherRoot, 'config', '--local', '--get', 'test.concurrent-unrelated').trim(), 'preserve-concurrent');
    for (const suffix of ['clean', 'smudge', 'required']) {
      const owned = spawnSync('git', ['-C', concurrentUnrelatedConfig.launcherRoot, 'config', '--local', '--get-all', `filter.stmobileauthhubv1.${suffix}`], {
        encoding: 'utf8', windowsHide: true,
      });
      assert.equal(owned.status, 1);
    }
    assert.deepEqual(await casResidue(concurrentUnrelatedConfig), []);

    const targetTamper = await createRepo('target-tamper');
    const installedTarget = runInstaller(targetTamper, 'Install');
    assert.equal(installedTarget.status, 0, installedTarget.stderr);
    const tamperedTargetText = (await readFile(targetTamper.target, 'utf8')).replace('-WindowStyle Hidden', '-WindowStyle Normal');
    await writeFile(targetTamper.target, tamperedTargetText, 'utf8');
    const targetTamperBefore = await snapshot(targetTamper);
    const targetTamperResult = runInstaller(targetTamper, 'Remove');
    assert.notEqual(targetTamperResult.status, 0);
    assert.match(`${targetTamperResult.stdout}\n${targetTamperResult.stderr}`, /integration block was modified or duplicated/);
    assert.deepEqual(await snapshot(targetTamper), targetTamperBefore);

    const attributesTamper = await createRepo('attributes-tamper');
    const installedAttributes = runInstaller(attributesTamper, 'Install');
    assert.equal(installedAttributes.status, 0, installedAttributes.stderr);
    const tamperedAttributesText = (await readFile(attributesTamper.attributes, 'utf8'))
      .replace('filter=stmobileauthhubv1', 'filter=stmobileauthhubv1 # modified');
    await writeFile(attributesTamper.attributes, tamperedAttributesText, 'utf8');
    const attributesTamperBefore = await snapshot(attributesTamper);
    const attributesTamperResult = runInstaller(attributesTamper, 'Remove');
    assert.notEqual(attributesTamperResult.status, 0);
    assert.match(`${attributesTamperResult.stdout}\n${attributesTamperResult.stderr}`, /attributes block was modified or duplicated/);
    assert.deepEqual(await snapshot(attributesTamper), attributesTamperBefore);

    const extraConfig = await createRepo('extra-config');
    const installedExtraConfig = runInstaller(extraConfig, 'Install');
    assert.equal(installedExtraConfig.status, 0, installedExtraConfig.stderr);
    runGit(extraConfig.launcherRoot, 'config', '--local', 'filter.stmobileauthhubv1.process', 'foreign-process-filter');
    const extraConfigBefore = await snapshot(extraConfig);
    const extraConfigResult = runInstaller(extraConfig, 'Remove');
    assert.notEqual(extraConfigResult.status, 0);
    assert.match(`${extraConfigResult.stdout}\n${extraConfigResult.stderr}`.replaceAll(/\s+/g, ' '), /Managed Git config block/);
    assert.deepEqual(await snapshot(extraConfig), extraConfigBefore);

    const canonicalConfig = await createRepo('canonical-config-byte-preservation');
    await writeFile(canonicalConfig.config, Buffer.concat([
      await readFile(canonicalConfig.config),
      Buffer.from('# unrelated config byte sentinel\n', 'utf8'),
    ]));
    const canonicalConfigBefore = await readFile(canonicalConfig.config);
    const canonicalInstall = runInstaller(canonicalConfig, 'Install');
    assert.equal(canonicalInstall.status, 0, canonicalInstall.stderr);
    const canonicalInstalledText = await readFile(canonicalConfig.config, 'utf8');
    assert.equal((canonicalInstalledText.match(/^# >>> ST MOBILE AUTH HUB FILTER CONFIG \(managed\)\r?$/gm) || []).length, 1);
    assert.equal((canonicalInstalledText.match(/^# <<< ST MOBILE AUTH HUB FILTER CONFIG \(managed\)\r?$/gm) || []).length, 1);
    const canonicalRemove = runInstaller(canonicalConfig, 'Remove');
    assert.equal(canonicalRemove.status, 0, canonicalRemove.stderr);
    assert.deepEqual(await readFile(canonicalConfig.config), canonicalConfigBefore, 'canonical remove must preserve all unrelated config bytes');
    assert.deepEqual(await casResidue(canonicalConfig), []);

    const beginConfigMarker = '# >>> ST MOBILE AUTH HUB FILTER CONFIG (managed)';
    const endConfigMarker = '# <<< ST MOBILE AUTH HUB FILTER CONFIG (managed)';
    const configMarkerMutations = [
      {
        name: 'foreign-inside',
        mutate: (text) => text.replace(endConfigMarker, `# foreign bytes inside managed block\r\n${endConfigMarker}`),
      },
      {
        name: 'duplicate',
        mutate: (text) => {
          const begin = text.indexOf(beginConfigMarker);
          const end = text.indexOf(`${endConfigMarker}\r\n`, begin);
          assert.ok(begin >= 0 && end >= 0, 'installed canonical block must be extractable');
          const block = text.slice(begin, end + endConfigMarker.length + 2);
          return text + block;
        },
      },
      {
        name: 'nested',
        mutate: (text) => text.replace(endConfigMarker, `${beginConfigMarker}\r\n${endConfigMarker}`),
      },
      {
        name: 'partial',
        mutate: (text) => text.replace(`${endConfigMarker}\r\n`, ''),
      },
      {
        name: 'leading-marker-text',
        mutate: (text) => text.replace(beginConfigMarker, ` foreign-prefix ${beginConfigMarker}`),
      },
      {
        name: 'trailing-marker-text',
        mutate: (text) => text.replace(beginConfigMarker, `${beginConfigMarker} foreign-suffix`),
      },
      {
        name: 'inline-marker',
        mutate: (text) => text.replace(beginConfigMarker, `[test "inline"] ${beginConfigMarker}`),
      },
      {
        name: 'extra-comment-only-section',
        mutate: (text) => `${text}[filter "stmobileauthhubv1"]\r\n\t# foreign comment-only section\r\n`,
      },
    ];
    for (const scenario of configMarkerMutations) {
      const collision = await createRepo(`config-marker-${scenario.name}`);
      const installed = runInstaller(collision, 'Install');
      assert.equal(installed.status, 0, installed.stderr);
      const installedText = await readFile(collision.config, 'utf8');
      const mutatedText = scenario.mutate(installedText);
      assert.notEqual(mutatedText, installedText, `${scenario.name} mutation must alter the managed config block`);
      await writeFile(collision.config, mutatedText, 'utf8');
      const before = await rawSnapshot(collision);
      const result = runInstaller(collision, 'Remove');
      assert.notEqual(result.status, 0, `${scenario.name} managed-marker corruption must fail closed`);
      assert.match(`${result.stdout}\n${result.stderr}`, /managed Git config|Managed Git config|Reserved Git config/);
      assert.deepEqual(await rawSnapshot(collision), before);
      assert.deepEqual(await casResidue(collision), []);
    }

    const preMarkerCommentOnly = await createRepo('pre-marker-comment-only-section');
    await writeFile(
      preMarkerCommentOnly.config,
      Buffer.concat([
        await readFile(preMarkerCommentOnly.config),
        Buffer.from('[filter "stmobileauthhubv1"]\n\t# foreign comment-only section\n', 'utf8'),
      ]),
    );
    const preMarkerCommentOnlyBefore = await snapshot(preMarkerCommentOnly);
    const preMarkerCommentOnlyResult = runInstaller(preMarkerCommentOnly, 'Install');
    assert.notEqual(preMarkerCommentOnlyResult.status, 0);
    assert.match(`${preMarkerCommentOnlyResult.stdout}\n${preMarkerCommentOnlyResult.stderr}`, /empty, comment-only, or otherwise unowned section/);
    assert.deepEqual(await snapshot(preMarkerCommentOnly), preMarkerCommentOnlyBefore);
    assert.deepEqual(await casResidue(preMarkerCommentOnly), []);

    const movedAttributes = await createRepo('moved-attributes');
    const installedMovedAttributes = runInstaller(movedAttributes, 'Install');
    assert.equal(installedMovedAttributes.status, 0, installedMovedAttributes.stderr);
    const managedAttributes = await readFile(movedAttributes.attributes, 'utf8');
    await writeFile(movedAttributes.attributes, `# unrelated preface\r\n${managedAttributes}# unrelated tail\r\n`, 'utf8');
    const movedAttributesBefore = await snapshot(movedAttributes);
    const movedAttributesResult = runInstaller(movedAttributes, 'Remove');
    assert.notEqual(movedAttributesResult.status, 0);
    assert.match(`${movedAttributesResult.stdout}\n${movedAttributesResult.stderr}`, /exact canonical end-of-file position/);
    assert.deepEqual(await snapshot(movedAttributes), movedAttributesBefore);

    const outOfBlockAttributes = await createRepo('out-of-block-attributes');
    await mkdir(path.dirname(outOfBlockAttributes.attributes), { recursive: true });
    await writeFile(
      outOfBlockAttributes.attributes,
      `${targetRelative} filter=foreign\r\n`,
      'utf8',
    );
    const outOfBlockBefore = await snapshot(outOfBlockAttributes);
    const outOfBlockResult = runInstaller(outOfBlockAttributes, 'Install');
    assert.notEqual(outOfBlockResult.status, 0);
    assert.match(`${outOfBlockResult.stdout}\n${outOfBlockResult.stderr}`, /out-of-block attributes mapping/);
    assert.deepEqual(await snapshot(outOfBlockAttributes), outOfBlockBefore);

    const wildcardAttributes = await createRepo('wildcard-attributes');
    await writeFile(path.join(wildcardAttributes.launcherRoot, '.gitattributes'), '*.bat filter=foreign\n', 'utf8');
    runGit(wildcardAttributes.launcherRoot, 'add', '--', '.gitattributes');
    runGit(wildcardAttributes.launcherRoot, 'commit', '-m', 'foreign wildcard attributes');
    runGit(wildcardAttributes.launcherRoot, 'config', '--local', 'filter.foreign.clean', 'definitely-missing-st-mobile-filter-command');
    runGit(wildcardAttributes.launcherRoot, 'config', '--local', 'filter.foreign.smudge', 'cat');
    runGit(wildcardAttributes.launcherRoot, 'config', '--local', 'filter.foreign.required', 'true');
    const wildcardBefore = await snapshot(wildcardAttributes);
    const wildcardResult = runInstaller(wildcardAttributes, 'Install');
    assert.notEqual(wildcardResult.status, 0);
    assert.match(`${wildcardResult.stdout}\n${wildcardResult.stderr}`, /Effective Git filter .* is not exact-owned/);
    assert.doesNotMatch(`${wildcardResult.stdout}\n${wildcardResult.stderr}`, /definitely-missing-st-mobile-filter-command.*failed/);
    assert.deepEqual(await snapshot(wildcardAttributes), wildcardBefore);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
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
