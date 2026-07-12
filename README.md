# SillyTavern Secure Mobile

This project builds a debug Android APK that opens your desktop SillyTavern UI through a local HTTPS gateway.

## Security Shape

- SillyTavern stays on loopback: `127.0.0.1:3000` / `::1:3000`.
- The LAN-facing port is the gateway: `https://192.168.1.215:38443`.
- The Android app embeds this project's generated local CA certificate.
- Pairing uses a short-lived, one-time, high-entropy URL wrapped in a `stmobile://pair?...` QR deep link.
- Pairing refuses to advertise unless the selected LAN host has an enabled Windows Firewall rule for only TCP `38443` from `LocalSubnet` on the active network profile, and the exact advertised HTTPS origin passes authenticated readiness probes.
- Gateway session tokens are stored as hashes on the PC and are stripped before requests reach SillyTavern.
- Gateway state writes use a cross-process lock so CLI pairing/revocation cannot race the running server.
- Malformed or invalid session cookies fail closed as `403` and do not rewrite `state/state.json`.
- The CA private key is generated under a restricted ACL for Sneak, SYSTEM, and Administrators.
- The Android WebView has no JavaScript bridge, does not bypass SSL errors, disables file URL access, and only allows navigation inside the paired gateway origin.
- On Android 11 and newer, the wrapper applies status-bar, display-cutout, gesture-navigation, and IME insets to the native root. Android 8-10 retain the platform's fitted decor plus `adjustResize`, avoiding double keyboard compensation.
- The PC auth hub binds to loopback only at `http://127.0.0.1:38444/`; it generates QR/deep links, lists authorized devices, and shows active connected/disconnected state from the running gateway.
- A single-instance Windows tray host keeps the hub in the taskbar hidden-icons area, starts automatically only after ST Launcher option 1 reports successful upstream readiness, and offers an opt-in `Start with Windows` toggle without opening a console or browser on login. Option 1 publishes exact ST PID/start/root provenance; relative `server.js` launches must answer a random file challenge from that configured root before the gateway can expose them.
- Tray network health checks run in short-lived hidden `Idle` workers with bounded connect/read/body limits, so a slow loopback endpoint cannot block the notification-area UI thread.
- The build script pins Gradle, Temurin JDK 21.0.11+10, Android command-line tools 15641748, Gradle-resolved dependencies, and installed Android SDK package files by SHA-256.
- On launch, the APK checks the GitHub raw update manifest, downloads only from this repo's `update/` path, verifies SHA-256 plus package identity/version, and then uses Android's normal user-confirmed package installer prompt. It does not root the phone, become a device owner/admin, install silently, or use system updater privileges.

## Paths

- APK: `android/app/build/outputs/apk/debug/app-debug.apk`
- GitHub update APK: `update/SillyTavern-Mobile-debug.apk`
- GitHub update manifest: `update/latest.json`
- Gateway state: `state/state.json`
- CA certificate: `state/certs/st-mobile-ca.crt`
- Pairing QR folder: `state/pairing/` with private Windows ACLs
- Auth hub URL file: `state/auth-hub.url`
- Verified tray identity: `state/tray-process.json`
- Verified gateway identity: `state/gateway-process.json` plus the compatibility PID file `state/gateway.pid`
- Trusted ST Launcher identity: `state/sillytavern-process.json` v2 (PID, normalized process start, node executable, configured root, absolute `server.js`, provenance, instance ID, root-proof method, and proof time)
- Per-SillyTavern-session pause/retry state: `state/tray-gateway-suppression.json` and `state/tray-gateway-retry.json` (present only while needed)
- Gateway logs: `logs/gateway.out.log` and `logs/gateway.err.log`

## Commands

Start the desktop gateway:

```powershell
.\scripts\Start-StMobile.ps1 -Port 38443
```

Open the PC-side auth hub after startup:

```powershell
Start-Process http://127.0.0.1:38444/
```

Install or refresh the genuinely one-click **Desktop → AI Tools → SillyTavern Mobile Auth Hub** shortcut. It starts or reuses SillyTavern, the secure gateway, authentication hub, and hidden tray before opening the verified hub URL:

```powershell
.\scripts\Install-DesktopAiToolsShortcut.ps1 -Mode Install
.\scripts\Install-DesktopAiToolsShortcut.ps1 -Mode Status
```

Start the hidden desktop tray host (normally launched for you by ST Launcher option 1):

```powershell
.\scripts\Launch-StMobileTray.ps1
```

Right-click its taskbar hidden icon to open the hub, start/stop the gateway for the current ST session, or toggle `Start with Windows`. Logon startup is opt-in and only starts the tray watcher; it waits for SillyTavern rather than launching SillyTavern on its own. Gateway auto-start requires the trusted ST record published by ST Launcher option 1 (or by `Start-StMobile.ps1` when that script itself launches ST), so a lookalike `node server.js` process from another root is refused.

Automatic gateway startup is capped at three attempts for one verified SillyTavern PID/start-time session, and that exhaustion state survives tray restarts. A manual **Start Gateway Now** clears the cap. **Stop Gateway for This ST Session** persists its pause through transient listener loss and tray restarts, then clears automatically when that SillyTavern process ends or changes.

Install or verify the update-resilient local integration with ST Launcher option 1:

```powershell
.\scripts\Install-StLauncherIntegration.ps1 -Mode Install
.\scripts\Install-StLauncherIntegration.ps1 -Mode Status
```

Stop the tray without stopping the already-running gateway, or fully disable/remove its persistent startup behavior:

```powershell
.\scripts\Stop-StMobileTray.ps1
.\scripts\Stop-StMobileTray.ps1 -DisableStartup -StopGateway
.\scripts\Install-StLauncherIntegration.ps1 -Mode Remove
```

Rank Audit for this desktop integration:

- Rank 4: automatic/background tray and child processes stay hidden/no-focus at Windows `Idle` priority; Windows startup remains opt-in; option-1 integration runs only after successful upstream readiness; network probes stay bounded and off the UI thread; launch/reuse/stop/removal touches only exact ST Mobile-owned shortcut, filter, PID/start/executable/argv/root-proof, and process-record state.
- Rank 3: while active, the tray watches a root-proven loopback SillyTavern session and starts the authenticated gateway with 30-second backoff, at most three automatic attempts per PID/start-time session; manual start or a new trusted SillyTavern session rearms it. The current short-lived probe-worker and repository-local Git-filter implementations may be replaced by equally verified mechanisms without weakening Rank 4 behavior.

Generate a fresh pairing QR:

```powershell
node .\gateway\src\cli.js pair --host 192.168.1.215 --port 38443 --label "S24 Ultra"
```

List or revoke paired devices:

```powershell
node .\gateway\src\cli.js list
node .\gateway\src\cli.js revoke <deviceId>
```

Stop the gateway:

```powershell
.\scripts\Stop-StMobile.ps1
```

Build the APK:

```powershell
.\scripts\Build-Android.ps1
```

The build also refreshes the Git-backed update files:

```text
update/latest.json
update/SillyTavern-Mobile-debug.apk
```

When the app sees a higher `versionCode` in `latest.json`, Android will still ask before installing. If Android has not allowed this app to install unknown apps yet, the app opens the standard settings page and retries on the next launch.

The GitHub repository must remain public for this no-credentials update channel. The APK does not embed a GitHub token.

## License

This project is licensed under the GNU Affero General Public License v3.0 to match SillyTavern. See `LICENSE`.

SillyTavern-Launcher is MIT licensed; its notice is preserved in `LICENSES/SillyTavern-Launcher-MIT.txt`. See `NOTICE.md` and `ATTRIBUTION.md` for upstream attribution, source-location notes, and the honest breakdown of what this project uses.

Run tests:

```powershell
npm test
```

Configure the firewall rule if it is ever removed:

```powershell
.\scripts\Configure-Firewall.ps1 -Port 38443
```

That script must be run elevated. By default it opens only TCP `38443` on the Public profile from `LocalSubnet`; it does not open SillyTavern port `3000`.

```powershell
.\scripts\Configure-Firewall.ps1 -Port 38443 -Profile Public
```
