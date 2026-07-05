import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const root = path.resolve(import.meta.dirname, '..');

async function text(relativePath) {
  return readFile(path.join(root, relativePath), 'utf8');
}

test('manifest has only expected permissions and declares local CA config', async () => {
  const manifest = await text('android/app/src/main/AndroidManifest.xml');
  assert.match(manifest, /android\.permission\.INTERNET/);
  assert.match(manifest, /android\.permission\.REQUEST_INSTALL_PACKAGES/);
  assert.doesNotMatch(manifest, /READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|MANAGE_EXTERNAL_STORAGE/);
  assert.doesNotMatch(manifest, /android\.permission\.(?:BIND_DEVICE_ADMIN|MANAGE_DEVICE_POLICY|INSTALL_PACKAGES|DELETE_PACKAGES|UPDATE_PACKAGES_WITHOUT_USER_ACTION)/);
  assert.doesNotMatch(manifest, /DeviceAdminReceiver|android\.app\.device_admin|accessibilityservice|VpnService|SYSTEM_ALERT_WINDOW/);
  assert.match(manifest, /android:networkSecurityConfig="@xml\/network_security_config"/);
  assert.match(manifest, /android:scheme="stmobile"/);
});

test('network security config fails closed, trusts gateway CA, and scopes GitHub system trust', async () => {
  const config = await text('android/app/src/main/res/xml/network_security_config.xml');
  assert.match(config, /cleartextTrafficPermitted="false"/);
  assert.match(config, /@raw\/st_mobile_ca/);
  assert.match(config, /<domain includeSubdomains="false">raw\.githubusercontent\.com<\/domain>/);
  assert.match(config, /<certificates src="system" \/>/);
  assert.doesNotMatch(config, /includeSubdomains="true"/);

  const ca = await text('android/app/src/main/res/raw/st_mobile_ca.crt');
  assert.match(ca, /BEGIN CERTIFICATE/);
  assert.match(ca, /END CERTIFICATE/);
});

test('WebView wrapper has origin lock and no unsafe bridge or SSL bypass', async () => {
  const source = await text('android/app/src/main/java/app/sillytavern/securemobile/MainActivity.java');
  assert.doesNotMatch(source, /addJavascriptInterface/);
  assert.doesNotMatch(source, /handler\.proceed\s*\(/);
  assert.match(source, /handler\.cancel\s*\(/);
  assert.match(source, /setAllowFileAccess\(false\)/);
  assert.match(source, /setAllowFileAccessFromFileURLs\(false\)/);
  assert.match(source, /setAllowUniversalAccessFromFileURLs\(false\)/);
  assert.match(source, /isAllowedGatewayUri/);
  assert.match(source, /ACTION_OPEN_DOCUMENT/);
  assert.match(source, /setWebContentsDebuggingEnabled\(false\)/);
});

test('launch updater is normal user-approved PackageInstaller flow only', async () => {
  const manifest = await text('android/app/src/main/AndroidManifest.xml');
  const source = await text('android/app/src/main/java/app/sillytavern/securemobile/MainActivity.java');
  assert.match(manifest, /android\.permission\.REQUEST_INSTALL_PACKAGES/);
  assert.match(source, /UPDATE_MANIFEST_URL/);
  assert.match(source, /raw\.githubusercontent\.com/);
  assert.match(source, /UPDATE_RAW_PATH_PREFIX\s*=\s*"\/SneakIrwin\/SillyTavern-Mobile-apk\/main\/update\//);
  assert.match(source, /setInstanceFollowRedirects\(false\)/);
  assert.match(source, /PackageInstaller\.SessionParams/);
  assert.match(source, /USER_ACTION_REQUIRED/);
  assert.match(source, /STATUS_PENDING_USER_ACTION/);
  assert.match(source, /Intent\.EXTRA_INTENT/);
  assert.match(source, /startActivity\(confirmationIntent\)/);
  assert.match(source, /FLAG_MUTABLE/);
  assert.doesNotMatch(source, /USER_ACTION_NOT_REQUIRED/);
  assert.doesNotMatch(source, /FLAG_IMMUTABLE/);
  assert.doesNotMatch(source, /Runtime\.getRuntime|ProcessBuilder|exec\s*\(|\bsu\b|pm install|DevicePolicyManager|DeviceAdminReceiver/);
});

test('update downloads are hash checked and package identity checked before install prompt', async () => {
  const source = await text('android/app/src/main/java/app/sillytavern/securemobile/MainActivity.java');
  assert.match(source, /sha256Hex\(apkFile\)/);
  assert.match(source, /actualSha256\.equals\(manifest\.sha256\)/);
  assert.match(source, /getPackageArchiveInfo/);
  assert.match(source, /getPackageName\(\)\.equals\(packageInfo\.packageName\)/);
  assert.match(source, /getVersionCode\(packageInfo\) == manifest\.versionCode/);
  assert.match(source, /manifest\.versionCode <= getCurrentVersionCode\(\)/);

  const installPromptIndex = source.indexOf('promptInstallVerifiedUpdate(apkFile, manifest)');
  const identityCheckIndex = source.indexOf('isDownloadedPackageExpected(apkFile, manifest)');
  assert.ok(identityCheckIndex >= 0 && installPromptIndex > identityCheckIndex);
});

test('pairing admission rejects public origins and waits to persist until success', async () => {
  const source = await text('android/app/src/main/java/app/sillytavern/securemobile/MainActivity.java');
  assert.match(source, /EXPECTED_GATEWAY_PORT\s*=\s*38443/);
  assert.match(source, /isPrivateLanHost/);
  assert.match(source, /pendingGatewayOrigin/);
  assert.match(source, /pendingMainFrameError/);
  assert.match(source, /commitPendingPairingIfReady/);

  const openPairingUrl = source.match(/private void openPairingUrl\(String url\) \{[\s\S]*?\n    \}/)?.[0] ?? '';
  assert.doesNotMatch(openPairingUrl, /saveGatewayOrigin/);
  assert.match(openPairingUrl, /pendingGatewayOrigin\s*=/);

  const isValidPairingUri = source.match(/private boolean isValidPairingUri\(Uri uri\) \{[\s\S]*?\n    \}/)?.[0] ?? '';
  assert.match(isValidPairingUri, /uri\.getPort\(\) == EXPECTED_GATEWAY_PORT/);
  assert.match(isValidPairingUri, /isPrivateLanHost\(uri\.getHost\(\)\)/);

  const commitPendingPairingIfReady = source.match(/private void commitPendingPairingIfReady\(Uri uri\) \{[\s\S]*?\n    \}/)?.[0] ?? '';
  assert.match(commitPendingPairingIfReady, /pendingMainFrameError/);
  assert.match(commitPendingPairingIfReady, /return/);
});

test('failed redirected pairing loads clear pending state instead of persisting origin', async () => {
  const source = await text('android/app/src/main/java/app/sillytavern/securemobile/MainActivity.java');
  const httpErrorBlock = source.match(/public void onReceivedHttpError\(WebView view, WebResourceRequest request, WebResourceResponse errorResponse\) \{[\s\S]*?\n            \}/)?.[0] ?? '';
  assert.match(httpErrorBlock, /request\.isForMainFrame\(\)/);
  assert.match(httpErrorBlock, /isPendingGatewayOrigin\(request\.getUrl\(\)\)/);
  assert.match(httpErrorBlock, /pendingMainFrameError\s*=\s*true/);
  assert.match(httpErrorBlock, /clearPendingPairing\(\)/);
});

test('standalone Android build syncs active gateway CA before packaging', async () => {
  const source = await text('scripts/Build-Android.ps1');
  assert.match(source, /Sync-GatewayCa/);
  assert.match(source, /st-mobile-ca\.crt/);
  assert.match(source, /st_mobile_ca\.crt/);
  assert.match(source, /Get-FileHash/);
  assert.match(source, /Embedded Android CA does not match active gateway CA/);
});

test('standalone Android build publishes GitHub raw update manifest and APK artifact', async () => {
  const source = await text('scripts/Build-Android.ps1');
  assert.match(source, /Write-UpdateManifest/);
  assert.match(source, /SillyTavern-Mobile-debug\.apk/);
  assert.match(source, /latest\.json/);
  assert.match(source, /raw\.githubusercontent\.com\/SneakIrwin\/SillyTavern-Mobile-apk\/main\/update/);
  assert.match(source, /Get-FileHash -Algorithm SHA256/);
  assert.match(source, /packageName = 'app\.sillytavern\.securemobile'/);
});
