# Android Safe-Area Live Smoke — exact final APK — 2026-07-12

This validation exercised the exact final repaired `0.1.5` (`versionCode 6`)
APK on real API 36 and API 29 Android emulators without opening an emulator
window or using host desktop input.

## Exact artifact and environment

- Candidate and published APK: `update/SillyTavern-Mobile-debug.apk`
- APK SHA-256: `112f50324c5a2086c3351e8e677f12cdae6793964b2653844a0ff3818ae0a58d`
- Installed metadata on both devices: `versionCode=6`, `versionName=0.1.5`, `targetSdk=36`
- Android 16 / API 36 Google APIs x86_64: `emulator-5554`, `1080x2400`
- Android 10 / API 29 Google APIs x86_64: temporary `emulator-5556`, `1080x1920`
- Gateway: `https://192.168.1.215:38443`
- Isolated UiAutomator test APK SHA-256: `f3654f299b4590c151cfb71ae93ab04463721939515a88eba2d3237a23496dcb`

The UiAutomator helper existed only under `scratch/mobile-smoke-helper`, was
installed as a separate package, and did not alter or rebuild the candidate
APK. It selected the visible edit control through Android accessibility and
proved the IME was actually shown. Raw coordinate injection was not accepted
as evidence.

## API 36 results

- The exact APK installed as an in-place update; the saved device session
  survived and the authenticated SillyTavern WebView loaded.
- Portrait, IME closed: WebView `[0,128][1080,2337]`, exactly below the
  128px status/cutout inset and above the 63px gesture inset.
- Portrait, IME shown: `mInputShown=true`, WebView
  `[0,128][1080,1517]`, focused `send_textarea`
  `[99,1332][981,1432]`.
- Landscape, IME closed: WebView `[128,63][2400,1017]`, with the cutout on
  the 128px left inset and 63px status/gesture insets.
- Landscape, IME shown: WebView `[128,63][2400,394]`, focused
  `send_textarea` `[327,317][2293,397]`.

## API 29 results

- The exact APK paired successfully to the live gateway; the old WebView
  rendered inside `[0,63][1080,1794]`, exactly between the 63px status bar
  and 126px navigation bar.
- The legacy WebView cannot execute every current SillyTavern frontend
  feature, so the native pairing input isolated the platform IME branch.
- Portrait native controls with IME closed occupied `y=775..1082`; with
  `mInputShown=true` they occupied `y=404..711`. The single 371px upward
  shift is the platform `adjustResize`; no second manual keyboard padding
  was present.
- Landscape paired WebView bounds were `[0,63][1794,1080]`, ending before
  the 126px right-side navigation bar.
- With the native landscape input focused, Android used its fullscreen IME.
  The app configuration remained byte-for-byte equivalent at
  `mBounds=Rect(0,0-1920,1080)` and `mAppBounds=Rect(0,0-1794,1080)` before
  and after IME display, proving the wrapper did not claim a second inset.

## Cleanup and host behavior

- No app crash or fatal WebView error appeared during installation, pairing,
  orientation changes, accessibility inspection, or IME inspection.
- ADB, both emulator parents, and the API 29 QEMU child had zero host window
  handles and Windows `Idle` priority (`ProcessPriorityClass` value 64).
- Both temporary API 29 device sessions were revoked.
- The UiAutomator helper was uninstalled from the persistent API 36 device.
- The temporary API 29 emulator was stopped, both host processes exited, and
  AVD `st_mobile_api29_v24` was deleted. Only `st_mobile_api36` remains.
- API 36 was restored to rotation `0` and its original
  `show_ime_with_hard_keyboard=0` setting.
- Accessibility dumps were deleted after extracting bounds because they can
  include the user's live SillyTavern session text. No screenshot was taken.

The published artifact remains debug-signed by design until a deliberate
long-lived release-key migration is chosen; that signing decision does not
change the exact-binary safe-area evidence above.
