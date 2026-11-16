import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { requireDisposableEmulator } from './android-harness-safety.mjs';

test('device preflight requires explicit matching emulator consent before any ADB probe', () => {
  for (const [serial, consent] of [[undefined, undefined], ['device-123', 'device-123'], ['emulator-5554', 'yes'], ['emulator-5554', 'emulator-5556']]) {
    const calls = [];
    assert.throws(() => requireDisposableEmulator({ serial, consent, probe: (...args) => calls.push(args) }));
    assert.deepEqual(calls, []);
  }
});

test('device preflight rejects offline, non-emulator and nameless targets using read-only probes', () => {
  for (const responses of [['offline'], ['device', '0'], ['device', '1', 'OK']]) {
    const calls = [];
    assert.throws(() => requireDisposableEmulator({
      serial: 'emulator-5554', consent: 'emulator-5554',
      probe: (...args) => { calls.push(args); return responses[calls.length - 1]; },
    }));
    for (const call of calls) {
      assert.ok(['get-state', 'shell', 'emu'].includes(call[0]));
      assert.notDeepEqual(call.slice(0, 3), ['shell', 'pm', 'clear']);
    }
  }
});

test('device preflight accepts the explicitly named ready disposable emulator', () => {
  const responses = ['device', '1', 'Disposable_AVD\nOK'];
  const calls = [];
  requireDisposableEmulator({ serial: 'emulator-5554', consent: 'emulator-5554',
    probe: (...args) => { calls.push(args); return responses[calls.length - 1]; } });
  assert.deepEqual(calls, [['get-state'], ['shell', 'getprop', 'ro.kernel.qemu'], ['emu', 'avd', 'name']]);
});

test('live harness scopes all ADB commands and checks isolated fixtures before clearing app data', async () => {
  const source = await readFile(new URL('./live-background-stream.mjs', import.meta.url), 'utf8');
  assert.match(source, /execFileSync\(adbPath, \['-s', serial, \.\.\.args\]/);
  const clearIndex = source.indexOf("adb('shell', 'pm', 'clear', packageName)");
  assert.ok(clearIndex > source.indexOf('requireDisposableEmulator({ serial'));
  assert.ok(clearIndex > source.indexOf('Test CA fixture must be outside the project'));
  assert.ok(clearIndex > source.indexOf('Test CA fixture files must resolve inside'));
  assert.ok(clearIndex > source.indexOf("const certDir = path.join(stateDir, 'certs')"));
  assert.doesNotMatch(source, /certDir: path\.join\(projectRoot, 'state', 'certs'\)/);
});
