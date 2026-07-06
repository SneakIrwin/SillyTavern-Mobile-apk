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
- The PC auth hub binds to loopback only at `http://127.0.0.1:38444/`; it generates QR/deep links, lists authorized devices, and shows active connected/disconnected state from the running gateway.
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
