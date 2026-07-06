# Attribution

This repository is an unofficial Android WebView wrapper and secure local-network gateway for a user-run SillyTavern instance.

## Project Source

- Project: SillyTavern Mobile APK
- Source: https://github.com/SneakIrwin/SillyTavern-Mobile-apk
- License: GNU Affero General Public License v3.0, matching SillyTavern's license family.

## Upstream Projects

### SillyTavern

- Upstream: https://github.com/SillyTavern/SillyTavern
- Documentation: https://docs.sillytavern.app/
- License and credits: https://docs.sillytavern.app/licensecredits/
- License: GNU Affero General Public License v3.0.
- Credit notes: SillyTavern's public license/credits page also credits Original TavernAI 1.2.8 by Humi under the MIT License.
- Use in this project: this project does not bundle SillyTavern. It proxies a locally running SillyTavern instance on the user's PC through a locked-down LAN gateway.

### SillyTavern Launcher

- Upstream: https://github.com/SillyTavern/SillyTavern-Launcher
- Icon source inspected: https://github.com/SillyTavern/SillyTavern-Launcher/blob/main/st-launcher.ico
- License: MIT License.
- Preserved license notice: `LICENSES/SillyTavern-Launcher-MIT.txt`.
- Use in this project: desktop setup assumptions and visual identity are aligned with the user's local SillyTavern Launcher install. The Android launcher icon is derived from / intended to match the SillyTavern Launcher visual identity, including the red network/brain launcher icon style.

## Non-Affiliation

This project is not an official SillyTavern or SillyTavern Launcher release. No endorsement by upstream maintainers is claimed.

## Practical Compliance Notes

- The AGPL-3.0 license text is included as `LICENSE`.
- The public source location is listed in `README.md`, `NOTICE.md`, and this file.
- The MIT notice for SillyTavern Launcher is preserved in `LICENSES/SillyTavern-Launcher-MIT.txt`.
- The PC auth hub includes an Attribution tab with the upstream breakdown and source/license pointers.
