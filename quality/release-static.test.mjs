import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { verifyApkSigner } from './verify-apk-signer.mjs';

test('signer identity comparison tolerates tool rendering, not a different or missing certificate', () => {
  const digest = 'e19a30327cb2b6500429ef6ad54f296f21dd4968842744b6340545d895f31456';
  assert.equal(verifyApkSigner(`Signer #1 certificate SHA-256 digest: ${digest.toUpperCase()}\r\n`, digest), digest);
  // Captured from the actual hosted build-tools 37.0.0 job, not an assumed format.
  assert.equal(verifyApkSigner(`V2 Signer: certificate SHA-256 digest: ${digest}\n`, digest), digest);
  assert.equal(verifyApkSigner(`V2 Signer: certificate SHA-256 digest: ${digest}\nV3.1 Signer: certificate SHA-256 digest: ${digest}\n`, digest), digest);
  assert.throws(() => verifyApkSigner(`Source Stamp Signer certificate SHA-256 digest: ${digest}\n`, digest), /mismatch/);
  assert.throws(() => verifyApkSigner('', digest), /mismatch/);
  assert.throws(() => verifyApkSigner(`Signer #1 certificate SHA-256 digest: ${'0'.repeat(64)}\n`, digest), /mismatch/);
  assert.throws(() => verifyApkSigner(`Signer #1 certificate SHA-256 digest: ${digest}\nSigner #2 certificate SHA-256 digest: ${'0'.repeat(64)}\n`, digest), /mismatch/);
});

const source = (name) => readFile(new URL(`../${name}`, import.meta.url), 'utf8');

test('publication builds a non-debuggable release with the pinned upgrade signer before replacing updater files', async () => {
  const build = await source('scripts/Build-Android.ps1');
  const gradle = await source('android/app/build.gradle');
  const policy = JSON.parse(await source('quality/release-signing.json'));
  assert.match(gradle, /release \{[\s\S]*signingConfig signingConfigs\.existingIdentity[\s\S]*debuggable false/);
  assert.match(build, /:app:assembleRelease/);
  assert.match(build, /apksigner\.bat/);
  assert.match(build, /application-debuggable/);
  assert.match(build, /raw\/st_mobile_ca/);
  assert.match(build, /\$toolsPrefix = \$resolvedTools\.TrimEnd/);
  assert.match(build, /Assert-ApkCaMatchesGateway\s+Assert-ReleaseApk\s+Write-UpdateManifest/);
  assert.equal(policy.certificateSha256, 'e19a30327cb2b6500429ef6ad54f296f21dd4968842744b6340545d895f31456');
});

test('installed SDK verification precedes any SDK manager mutation and platform tools archive is pinned', async () => {
  const build = await source('scripts/Build-Android.ps1');
  const start = build.indexOf('function Ensure-AndroidSdk');
  const end = build.indexOf('function Ensure-Gradle');
  const sdk = build.slice(start, end);
  assert.ok(sdk.indexOf('Assert-AndroidSdkPackageHashes') < sdk.indexOf('Ensure-Archive'));
  assert.doesNotMatch(sdk, /--licenses/);
  assert.match(sdk, /platform-tools_r\$PlatformToolsVersion-win\.zip/);
  assert.match(sdk, /\$PlatformToolsSha256/);
});

test('one-click hub readiness uses the common bounded response reader', async () => {
  const sourceText = await source('scripts/Open-StMobileAuthHub.ps1');
  assert.match(sourceText, /Read-StMobileBoundedResponseText -Response \$response -MaxCharacters 65536 -ReadTimeoutMilliseconds 1000/);
  assert.doesNotMatch(sourceText, /ReadToEnd\(\)/);
});
