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
  assert.match(manifest, /android:windowSoftInputMode="adjustResize"/);
});

test('network security config fails closed and trusts gateway plus normal HTTPS CAs', async () => {
  const config = await text('android/app/src/main/res/xml/network_security_config.xml');
  assert.match(config, /cleartextTrafficPermitted="false"/);
  assert.match(config, /@raw\/st_mobile_ca/);
  assert.match(config, /<base-config cleartextTrafficPermitted="false">[\s\S]*<certificates src="system" \/>[\s\S]*<certificates src="@raw\/st_mobile_ca" \/>[\s\S]*<\/base-config>/);
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
  assert.match(source, /SOFT_INPUT_ADJUST_RESIZE/);
  assert.match(source, /addOnGlobalLayoutListener\(this::applyKeyboardInset\)/);
  assert.match(source, /getWindowVisibleDisplayFrame/);
  assert.match(source, /uriFromSslError/);
  assert.match(source, /isPendingGatewayOrigin\(errorUri\)/);
  assert.doesNotMatch(source, /pendingGatewayOrigin != null\) \{\s*clearPendingPairing/);
});

test('native wrapper does not consume live SillyTavern viewport space', async () => {
  const source = await text('android/app/src/main/java/app/sillytavern/securemobile/MainActivity.java');
  assert.match(source, /private Button forgetButton/);
  assert.match(source, /forgetButton\.setVisibility\(View\.GONE\)/);

  const showWebView = source.match(/private void showWebView\(\) \{[\s\S]*?\n    \}/)?.[0] ?? '';
  assert.match(showWebView, /webView\.setVisibility\(View\.VISIBLE\)/);
  assert.match(showWebView, /forgetButton\.setVisibility\(View\.GONE\)/);

  const showGatewayLoadFailed = source.match(/private void showGatewayLoadFailed\(\) \{[\s\S]*?\n    \}/)?.[0] ?? '';
  assert.match(showGatewayLoadFailed, /showWebView\(\)/);
  assert.match(showGatewayLoadFailed, /forgetButton\.setVisibility\(View\.VISIBLE\)/);
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

test('pairing state and session cookies survive normal same-package updates', async () => {
  const manifest = await text('android/app/src/main/AndroidManifest.xml');
  const build = await text('android/app/build.gradle');
  const source = await text('android/app/src/main/java/app/sillytavern/securemobile/MainActivity.java');
  const updateManifest = await text('update/latest.json');

  assert.match(build, /applicationId 'app\.sillytavern\.securemobile'/);
  assert.match(updateManifest, /"packageName":\s+"app\.sillytavern\.securemobile"/);
  assert.match(source, /private static final String PREFS = "st_mobile"/);
  assert.match(source, /private static final String KEY_GATEWAY_ORIGIN = "gateway_origin"/);
  assert.match(source, /getSharedPreferences\(PREFS, Context\.MODE_PRIVATE\)/);
  assert.match(source, /saveGatewayOrigin\(pendingGatewayOrigin\)/);
  assert.match(source, /CookieManager\.getInstance\(\)\.flush\(\)/);
  assert.match(source, /PackageInstaller\.SessionParams\.MODE_FULL_INSTALL/);
  assert.doesNotMatch(manifest, /android:allowBackup="true"/);
  assert.doesNotMatch(source, /removeAllCookies|removeSessionCookies|clearCache\(true\)|clearFormData|deleteDatabase|clearApplicationUserData/);
});

test('pairing admission rejects public origins and waits to persist until success', async () => {
  const source = await text('android/app/src/main/java/app/sillytavern/securemobile/MainActivity.java');
  assert.match(source, /EXPECTED_GATEWAY_PORT\s*=\s*38443/);
  assert.match(source, /isPrivateLanHost/);
  assert.match(source, /pendingGatewayOrigin/);
  assert.match(source, /pendingMainFrameError/);
  assert.match(source, /commitPendingPairingIfReady/);

  const openPairingUrl = source.match(/private boolean openPairingUrl\(String url\) \{[\s\S]*?\n    \}/)?.[0] ?? '';
  assert.doesNotMatch(openPairingUrl, /saveGatewayOrigin/);
  assert.match(openPairingUrl, /pendingGatewayOrigin\s*=/);
  assert.match(openPairingUrl, /webView\.loadUrl\(uri\.toString\(\)\)/);
  assert.match(openPairingUrl, /return true/);

  const isValidPairingUri = source.match(/private boolean isValidPairingUri\(Uri uri\) \{[\s\S]*?\n    \}/)?.[0] ?? '';
  assert.match(isValidPairingUri, /uri\.getPort\(\) == EXPECTED_GATEWAY_PORT/);
  assert.match(isValidPairingUri, /isPrivateLanHost\(uri\.getHost\(\)\)/);

  const commitPendingPairingIfReady = source.match(/private void commitPendingPairingIfReady\(Uri uri\) \{[\s\S]*?\n    \}/)?.[0] ?? '';
  assert.match(commitPendingPairingIfReady, /pendingMainFrameError/);
  assert.match(commitPendingPairingIfReady, /saveGatewayOrigin\(pendingGatewayOrigin\)/);
  assert.match(commitPendingPairingIfReady, /CookieManager\.getInstance\(\)\.flush\(\)/);
  assert.ok(commitPendingPairingIfReady.indexOf('saveGatewayOrigin(pendingGatewayOrigin)') < commitPendingPairingIfReady.indexOf('CookieManager.getInstance().flush()'));
  assert.match(commitPendingPairingIfReady, /return/);
});

test('startup pairing intent remains visible while asynchronous WebView pairing finishes', async () => {
  const source = await text('android/app/src/main/java/app/sillytavern/securemobile/MainActivity.java');
  const onCreate = source.match(/protected void onCreate\(Bundle savedInstanceState\) \{[\s\S]*?\n    \}/)?.[0] ?? '';
  assert.match(onCreate, /boolean startedPairing = handleIntent\(getIntent\(\)\)/);
  assert.match(onCreate, /String gatewayOrigin = getGatewayOrigin\(\)/);
  assert.match(onCreate, /if \(startedPairing\) \{[\s\S]*return;[\s\S]*\}/);
  assert.match(onCreate, /if \(gatewayOrigin == null\) \{[\s\S]*showPairingPanel\(\);[\s\S]*\} else if \(webView\.getUrl\(\) == null\) \{/);
  assert.match(onCreate, /webView\.loadUrl\(gatewayOrigin \+ "\/"\)/);
  assert.doesNotMatch(onCreate, /webView\.loadUrl\(getGatewayOrigin\(\) \+ "\/"\)/);
  assert.doesNotMatch(onCreate, /getGatewayOrigin\(\) == null && !startedPairing/);
  assert.doesNotMatch(onCreate, /handleIntent\(getIntent\(\)\);\s*checkForUpdateOnLaunch\(\);\s*if \(getGatewayOrigin\(\) == null\)/);

  const handleIntent = source.match(/private boolean handleIntent\(Intent intent\) \{[\s\S]*?\n    \}/)?.[0] ?? '';
  assert.match(handleIntent, /return false/);
  assert.match(handleIntent, /boolean opened = openPairingUrl\(data\.getQueryParameter\("url"\)\)/);
  assert.match(handleIntent, /return opened/);
  assert.doesNotMatch(handleIntent, /openPairingUrl\(data\.getQueryParameter\("url"\)\);\s*return true/);
});

test('invalid pairing deep links do not suppress the native pairing panel or load null gateway', async () => {
  const source = await text('android/app/src/main/java/app/sillytavern/securemobile/MainActivity.java');
  const handleIntent = source.match(/private boolean handleIntent\(Intent intent\) \{[\s\S]*?\n    \}/)?.[0] ?? '';
  assert.match(handleIntent, /if \(!opened && getGatewayOrigin\(\) == null\) \{[\s\S]*showPairingPanel\(\);[\s\S]*\}/);
  assert.match(handleIntent, /return opened/);

  const openPairingUrl = source.match(/private boolean openPairingUrl\(String url\) \{[\s\S]*?\n    \}/)?.[0] ?? '';
  const emptyUrlReturn = openPairingUrl.indexOf('if (url == null || url.isEmpty())');
  const validUriCheck = openPairingUrl.indexOf('if (!isValidPairingUri(uri))');
  const loadUrl = openPairingUrl.indexOf('webView.loadUrl(uri.toString())');
  assert.ok(emptyUrlReturn >= 0 && emptyUrlReturn < loadUrl);
  assert.ok(validUriCheck >= 0 && validUriCheck < loadUrl);
  assert.match(openPairingUrl, /showInvalidPairingLink\(\);\s*return false;/);
  assert.doesNotMatch(openPairingUrl, /webView\.loadUrl\(getGatewayOrigin\(\) \+ "\/"\)/);
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
