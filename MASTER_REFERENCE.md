# Master Reference

References owned by this working directory. Other directories and global references remain at their recorded owners.

**Catalog updated:** 2026-11-16T22:03:43.8428729Z.

This page is generated from [registry.json](<C:/Users/Sneak/Documents/Codex/Misc/sillytavern-secure-mobile/MasterReference/registry.json>). Current approved source rules remain at their recorded owners. A catalog entry does not grant authority, establish authentication, override a current user instruction, or prove runtime adoption.

## Read and use

- Start with this working directory's sheet. Follow a directory or global reference when relevant, and read the current owning rule before consequential work or credential use.
- Separate saved defaults, scoped user rules, temporary experiments and verified runtime. A general default does not overwrite an approved scoped exception.
- Use a targeted lookup for routine work; no prior chat-history search is required to discover these records.
- After an authorized durable change, update its owning local or global catalog record, source checks and dependency list, record the user authorization, run the checker and regenerate that owner's page. A changed source is reported as drift until reconciled; never silently adopt a new authority from a file.
- Rank S changes still require the exact direct-user approval specified by Rule 1S. Their original wording and owner files remain in place.
- Secret records contain locators only. Use the existing provider resolver and authorized task scope; do not put secret values in this catalog, prompts, journals or logs.

## Quick lookup

```powershell
python "D:\Agent_Sync\MasterReference\reference.py" --registry "C:\Users\Sneak\Documents\Codex\Misc\sillytavern-secure-mobile\MasterReference\registry.json" lookup
python "D:\Agent_Sync\MasterReference\reference.py" --registry "C:\Users\Sneak\Documents\Codex\Misc\sillytavern-secure-mobile\MasterReference\registry.json" check
python "D:\Agent_Sync\MasterReference\reference.py" --registry "C:\Users\Sneak\Documents\Codex\Misc\sillytavern-secure-mobile\MasterReference\registry.json" render
```

Add `--id <record-id>` or `--scope <scope>` to lookup/check for a targeted read; impact accepts `--id <record-id>`. `lookup --workspace <absolute-working-directory>` prefers its exact local registry, then the nearest ancestor registry, then the supplied shared registry.

The checker reads selected registered rule sections and allowlisted config fields, and checks credential-path existence without opening credentials. It reports drift; it never changes a model, automation, authority, order or credential.

## Project operation

| Reference | Scope | Current value or rule | State | Owning source |
| --- | --- | --- | --- | --- |
| **App and relay boundaries** (`st-mobile.architecture`) | sillytavern-secure-mobile | Android WebView uses native system/IME insets and authenticated HTTPS LAN gateway; ST stays loopback. Gateway owns bounded in-memory replay, not durable page/process reconstruction. | Source audited 2026-11-16; exact checks and limits in audit report | [README.md](<C:/Users/Sneak/Documents/Codex/Misc/sillytavern-secure-mobile/README.md>), [audit-2026-11-16.md](<C:/Users/Sneak/Documents/Codex/Misc/sillytavern-secure-mobile/docs/audit-2026-11-16.md>) |
| **Desktop tray and launch ownership** (`st-mobile.desktop`) | sillytavern-secure-mobile/desktop | ST Launcher option 1 and Desktop AI Tools one-click integration start/reuse verified ST/gateway/tray. Startup is opt-in. All automatic launches hidden/no-focus at Idle; exact owned identities govern stop/removal. | Saved launch paths retained; 2026-11-16 baseline startup absent and ST/hub/tray stopped, not changed by audit | [Start-StMobileTray.ps1](<C:/Users/Sneak/Documents/Codex/Misc/sillytavern-secure-mobile/scripts/Start-StMobileTray.ps1>), [Open-StMobileAuthHub.ps1](<C:/Users/Sneak/Documents/Codex/Misc/sillytavern-secure-mobile/scripts/Open-StMobileAuthHub.ps1>) |

- **st-mobile.architecture:** Preserve paired origin/cookies and original CA. Credential locators only: state/state.json and state/certs. No JavaScript bridge, PiP, overlay, wake lock or foreground service. Project-scoped latest request does not authorize desktop control.
- **st-mobile.desktop:** Runtime must be re-read, never inferred from historical PIDs. Commands and exact disable/remove instructions remain in README and durable background-process registry. No new persistent trigger is introduced.

## Release

| Reference | Scope | Current value or rule | State | Owning source |
| --- | --- | --- | --- | --- |
| **Build and publication contract** (`st-mobile.release`) | sillytavern-secure-mobile/release | v0.1.9 / versionCode 10; non-debuggable release signed with the existing upgrade-compatible certificate. Keep Git, updater APK/manifest, tag and GitHub Release in parity. | Local signed release built and checked; publication/readback recorded in audit report | [release-signing.json](<C:/Users/Sneak/Documents/Codex/Misc/sillytavern-secure-mobile/quality/release-signing.json>), [latest.json](<C:/Users/Sneak/Documents/Codex/Misc/sillytavern-secure-mobile/update/latest.json>) |

- **st-mobile.release:** Signing-key locator: %USERPROFILE%/.android/debug.keystore or ST_MOBILE_SIGNING_STORE; secret values are never cataloged. Legacy updater asset filename remains SillyTavern-Mobile-debug.apk, but its bytes are release. Installed SDK is verified before mutation; platform-tools archive is versioned and pinned. Full checks: npm test and scripts/Build-Android.ps1.

## References owned elsewhere

| Directory or reference | Scope | Page | Owning registry |
| --- | --- | --- | --- |
| Shared index and global rule references | global | [MASTER_REFERENCE.md](<D:/Agent_Sync/MASTER_REFERENCE.md>) | [registry.json](<D:/Agent_Sync/MasterReference/registry.json>) |
| Portable bootstrap and global owner instructions | global | [WORKSPACE_BOOTSTRAP.md](<D:/Agent_Sync/MasterReference/WORKSPACE_BOOTSTRAP.md>) | [registry.json](<D:/Agent_Sync/MasterReference/registry.json>) |

Other-host, WSL and cloud work need an accessible copy or shared mount and [WORKSPACE_BOOTSTRAP.md](<D:/Agent_Sync/MasterReference/WORKSPACE_BOOTSTRAP.md>); a catalog does not make private local paths accessible.

## Maintenance and coverage

Maintain records in the directory that owns them. Register cross-directory dependencies as links or routing records; do not copy project values into the shared index. Use current source readback to resolve drift. Missing or unavailable sources remain explicit unknowns.

**Registry:** [registry.json](<C:/Users/Sneak/Documents/Codex/Misc/sillytavern-secure-mobile/MasterReference/registry.json>). **Portable entry instructions:** [WORKSPACE_BOOTSTRAP.md](<D:/Agent_Sync/MasterReference/WORKSPACE_BOOTSTRAP.md>). **Change history:** [CHANGELOG.jsonl](<C:/Users/Sneak/Documents/Codex/Misc/sillytavern-secure-mobile/MasterReference/CHANGELOG.jsonl>).
