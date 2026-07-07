# Android Emulator Live Smoke - 2026-07-06

This smoke test was run against a real Android emulator after the WebView wrapper fixes for pairing, viewport, and input forwarding.

## Environment

- Host gateway hub: `http://127.0.0.1:38444`
- Gateway origin used by the app: `https://192.168.1.215:38443`
- Android target: API 36 Google APIs x86_64 emulator, `st_mobile_api36`
- Emulator serial: `emulator-5554`
- Display: `1080x2400`
- APK: `android/app/build/outputs/apk/debug/app-debug.apk`
- Published update artifact: `update/SillyTavern-Mobile-debug.apk`
- Published update version: `0.1.4` / `versionCode 5`
- Published artifact SHA-256: `49a7b2033a511e42f062c64f870f691c5d367782d996de10f15b5c0d00acf155`

## Live Flow Results

- Clean-installed the debug APK on the emulator.
- Launched an invalid `stmobile://pair` deep link on a clean install and confirmed it stayed on the native pairing UI instead of loading a `null/` gateway.
- Created a one-time pair link from the desktop auth hub and launched it through the `stmobile://pair` deep link.
- Confirmed the app reached the live SillyTavern WebView instead of returning to the native pairing screen.
- Confirmed valid pairing no longer falls through into the saved-origin reload branch before the gateway origin is persisted.
- Confirmed the normal live WebView no longer shows the native `Forget` button over or below SillyTavern.
- Opened the Android keyboard by tapping the SillyTavern composer. The composer and send control stayed visible above the keyboard.
- Waited for the live `send_textarea` composer before typing, then typed `/help` into the composer and tapped SillyTavern's send button.
- Confirmed logcat contained SillyTavern's own console receipt of `User Input -- /help`.
- Confirmed SillyTavern rendered its help response in the chat UI.
- Tapped the visible top chat-selector arrow and confirmed the chat list opened.
- Relaunched into an independent foreground session, tapped the bottom-left SillyTavern menu, and confirmed the action menu opened.
- Relaunched into an independent foreground session for command forwarding so Android Back/popup state could not contaminate the result.
- Force-stopped the Android app, relaunched it without a new pairing link, and confirmed it reopened SillyTavern from persisted auth rather than showing `Not paired`.

Screenshots and raw UI dumps from this run were intentionally kept as temporary local artifacts only because they include the user's live SillyTavern session content.

## Automated Verification

Commands run after the live smoke:

```powershell
npm test
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\Build-Android.ps1
```

Results:

- Gateway tests: 37 passed.
- Android static tests: 13 passed.
- Desktop static tests: 10 passed.
- License and attribution tests: 4 passed.
- Gradle debug build: passed.
- Git-backed update manifest advertises `versionCode 5`, which is higher than the previous broken `versionCode 4` build.
