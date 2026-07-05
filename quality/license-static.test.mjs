import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const root = path.resolve(import.meta.dirname, '..');

async function text(relativePath) {
  return readFile(path.join(root, relativePath), 'utf8');
}

test('root project license matches SillyTavern AGPL-3.0', async () => {
  const license = await text('LICENSE');
  assert.match(license, /GNU AFFERO GENERAL PUBLIC LICENSE/);
  assert.match(license, /Version 3, 19 November 2007/);
});

test('SillyTavern Launcher MIT license notice is preserved', async () => {
  const launcherLicense = await text('LICENSES/SillyTavern-Launcher-MIT.txt');
  assert.match(launcherLicense, /MIT License/);
  assert.match(launcherLicense, /Copyright \(c\) 2023 SillyTavern/);
});

test('notice names upstream licenses and source location', async () => {
  const notice = await text('NOTICE.md');
  assert.match(notice, /GNU Affero General Public License v3\.0/);
  assert.match(notice, /SillyTavern-Launcher is licensed under the MIT License/);
  assert.match(notice, /https:\/\/github\.com\/SneakIrwin\/SillyTavern-Mobile-apk/);
  assert.match(notice, /not an official SillyTavern or SillyTavern-Launcher release/);
});
