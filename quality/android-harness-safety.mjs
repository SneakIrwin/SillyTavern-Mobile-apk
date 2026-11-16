// The caller supplies only read-only, serial-scoped ADB probes here.
export function requireDisposableEmulator({ serial, consent, probe }) {
  if (!/^emulator-\d+$/.test(serial ?? '') || consent !== serial) {
    throw new Error('Set ST_MOBILE_TEST_SERIAL and ST_MOBILE_DISPOSABLE_EMULATOR to the same disposable emulator serial; its app data will be erased.');
  }
  if (probe('get-state').trim() !== 'device'
      || probe('shell', 'getprop', 'ro.kernel.qemu').trim() !== '1'
      || !probe('emu', 'avd', 'name').trim().replace(/\s*OK\s*$/, '').trim()) {
    throw new Error('Selected target is not a ready Android emulator with an AVD name.');
  }
}
