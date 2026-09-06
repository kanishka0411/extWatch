# ExtWatch v1 plan

Written 2026-09-05. Target: v1 in 5 weeks. Source idea: `~/Desktop/openSource/PROJECT_IDEAS.md`, pick 1.

ExtWatch is a desktop tray app that snapshots every extension installed in Chrome-family browsers, catches the silent version swap with a file watcher, and shows a prettified manifest and code diff that highlights new host permissions, new fetch domains and remote-payload loaders. It keeps a local archive of every version it has seen and can produce a shareable, reproducible report. It never phones home.

## Status (2026-09-06, after review)

The sections below are the original design. This table is the truth about what the code does
today; where they disagree, the table wins.

| Capability | Status | Notes |
| --- | --- | --- |
| Discovery of Chrome-family browsers and profiles | Done | Built-in components are filtered by location, known ID and browser install path |
| Startup, periodic and watcher-triggered rescans | Done | Watcher armed from discovery at startup; a change during a scan queues a rescan |
| Content-addressed archive | Done | Blobs are hashed while copied and refused if the file changed meanwhile; 0600/0700 permissions |
| Atomic snapshots | Done | Blobs first, then version and file rows in one transaction; no snapshot without its blobs |
| Version stability gate | Done | Files newer than 3 s or a tree that changed while hashing are retried, up to twice |
| Fingerprint reuse | Done | Unchanged trees (files, bytes, newest mtime) are not re-hashed |
| Event kinds | Done | baseline, updated, modified_in_place (same version, different bytes), pending_version (also on first scan), enabled, disabled, removed |
| Database migrations | Done | `schema_version` with ordered migrations; refuses newer databases; schema 2 today |
| Crash recovery | Done | Events left without findings are analyzed on the next scan |
| Behavior signatures | Done | tree-sitter facts, prettified line numbers, per-file parallel analysis on a bounded low-priority pool |
| Rules | Done | 51 rules; sink identity is (kind, file); content scripts compared per declaration; DNR header operations, redirects and allowAllRequests; `world: MAIN`, `match_origin_as_fallback`, `externally_connectable.ids` |
| Evasions handled | Partial | `(0, eval)`, `globalThis["eval"]`, `Function(x)()`, `browser.*`, named period constants, `chrome.alarms`; no taint or control-flow analysis |
| Incomplete analysis is reported | Done | Files above 48 MiB, nesting above 400 levels, refused archive entries, parse errors produce `analysis.incomplete` |
| Package limits | Done | 512 MiB archive, 20,000 entries, 128 MiB per entry, 1 GiB total, 200x ratio; non-code entries are never inflated |
| WebAssembly, invisible characters | Done | Listed and flagged; wasm contents not analyzed |
| Side-by-side diff | Done | Line hashes are verified, never trusted alone |
| Quarantine and restore | Done | Recorded per browser profile with a random id; verified moves; restore goes to the original path only |
| Companion one-click Disable | Done | Targets one browser profile (browser kind plus inventory); origin validated; no uninstall command |
| Single instance | Done | Lock file per archive |
| Web Store publisher tracking | Done (opt-in) | Scraped labels, treated as a sensor; `parser_version` recorded |
| `doctor` | Done | SQLite check, blob presence and optional re-hash, orphan count, quarantines, companion integrity, permissions |
| Snapshot addressing in the CLI | Done | `1.2.0`, `1.2.0@<hash prefix>`, `@<hash prefix>` |
| Supply chain | Done | Dependencies and actions pinned to commits, linuxdeploy pinned with checksums, releases gated on the test matrix, `SHA256SUMS` attached |
| Signing and notarization | Needs certificates | Wired in the workflow |
| CRX signature verification, Web Store `verified_contents` check | Planned | Would prove local files are the store's files |
| Separate analyzer process | Planned | Today the analyzer runs in-process with limits |
| Per-blob analysis cache, taint analysis, effective-permission events, Firefox | Planned | |

## 1. What "v1 done" means

The hero demo, recorded as a GIF for the README and Show HN:

1. An extension silently updates in the background (in the demo: a fixture extension served from a local update server, so the swap is real and repeatable).
2. Within seconds a tray notification reads: "Screenshot Tool 4.1 → 4.2: +host permission <all_urls>, +fetch to cdn-example.invalid every 5 min, +remote code loader".
3. Clicking it opens ExtWatch on the change: findings list at the top, manifest diff, then a side-by-side prettified JavaScript diff with the new lines highlighted and each finding linked to its line.
4. A Disable button neutralizes the extension. An Export button writes a self-contained HTML report.

v1 ships when all of this works on macOS, Windows and Linux for Chrome, Chromium, Edge and Brave, with a `--json` CLI, signed or clearly documented unsigned builds, and a README that explains the behavior-signature rules.

Scope guard from the shortlist: v1 is Chrome-family only with manifest, permission and fetch-domain diff plus the remote-loader signatures. Firefox, publisher tracking and deeper analysis come after v1. Nothing in v1 uses an LLM.

## 2. Tech stack

Decision: **C++20 with Qt 6 Widgets**, one binary that runs as the tray GUI or as a CLI.

| Concern | Choice | Why |
|---|---|---|
| Language / UI | C++20, Qt 6 Widgets (min 6.5, dev on the local 6.10.2, CI on 6.8 LTS) | Matches Kanishka's Tiled experience and the shortlist's stated stack. Tray, notifications, file watching, SQLite and networking are all in Qt. Reusable for Portalkeeper, PhoneCheckup and QtReplay later. |
| Build | CMake 3.28+, Ninja, presets, clang-format | Already installed locally. Same toolchain as Tiled. |
| JS analysis | tree-sitter core + tree-sitter-javascript, vendored via FetchContent | Error-tolerant, fast on multi-MB minified bundles, plain C, MIT. Gives a concrete syntax tree for both signature extraction and the structural prettifier. |
| Diff | dtl (header-only Myers diff, BSD) | Small, tested, no deps. Wrapped so it can be swapped for patience diff later. |
| Storage | SQLite through Qt SQL, blobs on disk content-addressed by SHA-256 | Snapshots and events in SQLite, file contents deduplicated across versions on disk. |
| Zip | miniz (single-file, MIT) | Only for exporting versions and reading `.crx`/`.zip` in `analyze`. |
| Tests | Qt Test, fixture extensions and fixture profiles under `fixtures/` | Golden `--json` outputs keep the CLI contract stable. |
| CI / packaging | GitHub Actions matrix (macOS arm64+x86_64, Windows MSVC, Ubuntu 22.04), aqtinstall, macdeployqt / windeployqt / linuxdeploy AppImage | Kanishka has done this matrix for Qt before. |
| Optional companion | MV3 extension (plain JS) + native messaging | Only for the Disable button and instant update events. See section 5. |
| License | MIT for ExtWatch, Qt used under LGPLv3 with dynamic linking | Standard for tray tools; keeps the rules JSON reusable by researchers. |

No web view. The diff viewer is a native widget (two synchronized `QPlainTextEdit` panes with gutters and hunk shading), which handles 50k-line documents better than a webview would and avoids QtWebEngine's 150 MB.

Alternative considered: Tauri 2 with a Rust core (`notify`, `rusqlite`, `oxc` parser, `similar` diff) and a Monaco diff editor in the webview. It gives a nicer diff UI in fewer days and smaller binaries, but adds a new language to a 5-week budget and breaks the Qt portfolio thread. Switch to it only if the native diff widget is not usable by the end of week 4.

Repository layout:

```
exWatch/
  CMakeLists.txt, CMakePresets.json, cmake/deps.cmake
  src/core/        library: discovery, prefs, snapshot, archive, db, watcher, analysis, rules, diff, report
  src/cli/         extwatch subcommands, links core
  src/app/         Qt Widgets GUI and tray, links core
  companion/       optional MV3 extension (manifest.json, sw.js) + native host manifest templates
  rules/           rules.v1.json, domain-allowlist.json (the published signature database seed)
  fixtures/        synthetic profiles and extension versions used by tests and the demo
  tests/           Qt Test executables + golden JSON
  packaging/       Info.plist, LaunchAgent template, Inno Setup script, AppImage recipe
  docs/            PLAN.md, ARCHITECTURE.md, signature-schema.md
  .github/workflows/
```

## 3. Facts the design rests on

Verified on this Mac on 2026-09-05 (Chrome with two profiles, Brave with three) and from Chromium source or published research:

- **Install layout.** `<UserData>/<Profile>/Extensions/<32-char id>/<version>_<n>/`. Old version directories linger until Chrome garbage-collects them (Google Docs Offline had three version dirs at once), so a new version directory, not the removal of the old one, is the update signal.
- **Unpacked manifests carry the signing key.** Chrome writes the CRX public key into `manifest.json` as `key` on unpack (24 of 24 local manifests). `id = a..p encoding of the first 16 bytes of SHA-256(DER public key)`, so ExtWatch can verify the ID derivation offline and flag mismatches.
- **Web Store signature material is on disk.** Every store-installed version has `_metadata/verified_contents.json` (signed by the Web Store) and `computed_hashes.json`. v1 records their presence; signature verification is v2.
- **Prefs.** Extension records live in `Secure Preferences` under `extensions.settings.<id>` with `path`, `location`, `from_webstore`, `manifest`, `first_install_time`, `last_update_time`, `disable_reasons`, `active_permissions`, `granted_permissions`. Newer Chrome and Brave omit `state` and use `disable_reasons` (empty list = enabled); older profiles still have `state: 1`. Handle both. Timestamps are microseconds since 1601-01-01. `location` 5 (component) and 10 (external component) are browser-internal and must be filtered out; 1 = user install, 4 = unpacked, 6/7/9 = external or policy.
- **Secure Preferences is HMAC-protected on macOS and Windows** (`protection.macs`, `super_mac`, seeded from the browser binary and a machine ID). Writing to it is out of scope for v1. Linux does not enforce the MACs (Chalmers 2020 paper), which leaves a door open for a Linux-only rollback experiment later.
- **`chrome://` URLs cannot be opened from the command line.** Chromium's `ValidateLaunchUrlWebUnsafe` only accepts web-safe schemes, `file://`, `about:blank` and the exact settings-reset page. So "open the extension's details page" is not available to an external app; ExtWatch opens the Web Store listing instead and copies `chrome://extensions/?id=<id>` to the clipboard.
- **Policies on macOS require Managed Preferences** (a configuration profile or `/Library/Managed Preferences`, admin). `defaults write com.google.Chrome ExtensionInstallBlocklist` is loaded as "recommended" and ignored for extension policies. On Windows, Chrome reads `HKCU\Software\Policies\Google\Chrome`, which needs no admin; behavior for `ExtensionInstallBlocklist` from HKCU must be confirmed in the week-1 spike (it also makes Chrome show "managed by your organization").
- **The QuickLens technique** (Feb 2026): kept original features, stripped `X-Frame-Options`/CSP from responses, polled a server every five minutes for JavaScript, stored it in local storage and executed it on every page load via a hidden 1×1 `<img>` whose `onload` attribute was set to the string. ShotBird added fake Chrome-update prompts leading to host malware. These define the v1 remote-loader signatures.
- **Prior art to cite.** `ading2210/ext-watcher` (Python, 11 stars, AGPL) downloads CRXs from the store by ID, deobfuscates with webcrack and posts diffs to Discord. It watches the store for IDs you list; it does not see what is installed on a machine, has no archive, GUI or profile awareness. Extension Monitor is an enterprise agent plus SaaS dashboard. crx-analyzer is a one-shot CLI. None diff the local install version over version.

## 4. Architecture

```
 discovery ──> inventory ──> snapshot ──> archive (blobs + sqlite)
    ^              │             │
    │              │             └──> analysis ──> signature.json ──┐
 watcher ──────────┘                                                ├──> rules ──> findings ──> events
 (fs events, catch-up scan, timer)                                  │
                                                     diff (manifest semantic + prettified code) 
                                                                    │
                     tray + notifications <──── events              └──> report (HTML / JSON)
                     main window (timeline, findings, manifest diff, code diff, actions)
                     cli (scan / analyze / diff / watch / export / history)
```

Modules in `src/core` (all headless, all unit-testable):

- **discovery**: known user-data dirs per OS and browser (Chrome stable/beta/canary, Chromium, Edge, Brave, plus Vivaldi, Opera and Arc as config-only entries; Flatpak and Snap paths on Linux; `--user-data-dir` overrides from settings). Profiles from `Local State` → `profile.info_cache`, fallback to any subdir containing `Secure Preferences`.
- **prefs**: read-only parser for `Local State`, `Preferences`, `Secure Preferences`. Produces `ExtensionRecord{id, location, enabled, disable_reasons, from_webstore, path, install/update times, granted/active permissions, cached manifest}`.
- **inventory**: joins prefs with the `Extensions/` directory. Distinguishes: active version (prefs `path`), pending version dirs (downloaded, not yet activated because the extension was busy), stale dirs (awaiting garbage collection), unpacked dev extensions (absolute `path`), records without files and files without records.
- **snapshot**: hashes every file (SHA-256), stores blobs content-addressed under `<AppData>/ExtWatch/blobs/aa/<sha256>`, computes a Merkle tree hash over sorted `(path, hash)` as the version identity, resolves `__MSG_*__` names through `_locales/<default_locale>/messages.json`, extracts icons, verifies `key` → ID.
- **watcher**: `QFileSystemWatcher` (FSEvents on macOS, inotify on Linux, ReadDirectoryChangesW on Windows) on each profile's `Extensions/` dir, each `Extensions/<id>/` dir and `Secure Preferences`. Debounce 3 s; a new version dir counts as ready when `manifest.json` parses and `_metadata/computed_hashes.json` exists or the tree is unchanged across two polls. Safety nets: full rescan at startup (catches updates that happened while ExtWatch was closed), every 15 minutes, and on wake from sleep. The database is the source of truth; the watcher only decides when to look.
- **analysis**: per version, produces `signature.json` (section 6). Manifest facts from JSON; code facts from tree-sitter over every `.js` file and inline scripts in `.html`; static `declarative_net_request` rulesets parsed from their JSON files.
- **rules**: `rules/rules.v1.json` maps signature deltas to findings with severity and a plain-English explanation. Versioned so a report can say which rules produced it.
- **diff**: semantic manifest diff (key-sorted, per-field for permission arrays, content-script matches, externally_connectable, CSP), file-tree diff (added, removed, modified with sizes), and line diff of prettified sources with a work cap that falls back to "file rewritten" plus the signature delta.
- **prettify**: deterministic structural formatter driven by the tree-sitter CST: one statement per line, indentation by block depth, objects and arrays broken when long, strings and comments untouched. Same input always gives the same output, so diffs of two prettified versions only show real changes. JSON is key-sorted and indented. CSS and HTML are diffed as-is.
- **report**: self-contained HTML (inline CSS, no scripts, hunk size caps) and JSON. Includes both tree hashes, the ExtWatch and rules versions, browser and profile, so anyone with the same two versions can reproduce it with `extwatch diff`.
- **db**: schema in section 7, migrations versioned from day one.

`src/app` is the tray (`QSystemTrayIcon`, menu: recent changes, pause, rescan now, open, quit), notifications (`showMessage`; on macOS this needs a real `.app` bundle with `LSUIElement` so there is no Dock icon), the main window and settings. `src/cli` is `QCoreApplication` only; `main()` inspects argv before constructing either application object.

## 5. Handling the hard parts

**Catching the swap, including while closed.** Watcher for immediacy, startup and periodic rescans for correctness, tree hash as identity so a "new" directory with identical content is not reported as a change. Pending-but-not-activated versions are shown as "downloaded, activates when the extension is idle" so the user hears about a suspicious update before it even runs.

**Readable diffs of minified bundles.** Prettify both sides identically, diff lines, show hunks only, link findings to lines. The findings list is the primary view; the code diff is evidence. Performance targets: prettify a 5 MB file under 2 s, diff under 1 s, UI stays responsive by running analysis in a worker thread.

**The QuickLens trick.** Signatures for: fetch or XHR whose response feeds `chrome.storage`; `setAttribute("onload"|"onerror", ...)` with non-literal or long string values; `eval`, `new Function`, `setTimeout`/`setInterval` with string bodies, `importScripts` with remote URLs; `<script src>` pointing off-extension or built from variables; `location = "javascript:..."`; timers with periods of one minute or more that sit near a network call; `declarativeNetRequest` static or dynamic rules and `webRequest.onHeadersReceived` handlers that remove or rewrite `content-security-policy`, `x-frame-options` or `set-cookie`; country or UA fingerprinting calls near the poller (`navigator.language`, `Intl.DateTimeFormat().resolvedOptions().timeZone`, IP-lookup domains). The malicious payload is never in the files, so ExtWatch flags the loader and the header stripping, which are.

**Disable.** Because prefs are HMAC-protected and `chrome://` deep links are blocked, the Disable button is tiered and always tells the user which tier it used:

1. Companion extension (recommended for v1 if week 4 is on schedule, otherwise v1.1): a ~100-line MV3 extension with the `management` permission that connects to ExtWatch through native messaging (host manifest registered per browser in the user's own directory, no admin). ExtWatch sends `setEnabled(id, false)`; the companion also forwards `management.onInstalled` events, which gives instant update detection independent of the file watcher. Installed by "load unpacked" for v1, Web Store listing later. The monitoring stays outside the browser; only the actuator is inside.
2. Quarantine: move the version directory into the archive. Chrome's content verification marks the extension corrupted and disables it. Blunt, but works today on every OS with no privileges; labelled experimental and reversible (restore moves it back).
3. Windows per-user policy: add the ID to `HKCU\Software\Policies\Google\Chrome\ExtensionInstallBlocklist` (and the Edge/Brave equivalents). Confirmed in the week-1 spike before it ships.
4. Guide: open the Web Store listing, copy `chrome://extensions/?id=<id>` to the clipboard and show a one-line instruction.

**Rollback.** v1 archives every version and can export one as a loadable unpacked directory or zip. "Roll back" in the UI means: export the chosen version, disable the store copy (tiers above), then the user loads the export unpacked. In-place rollback by editing prefs is not attempted in v1; on Linux, where the MACs are not enforced, it is a documented experiment for later. The store would re-update a pinned old version within hours anyway unless the store copy is disabled, so this flow is the honest one.

**Publisher and signer tracking.** Not in v1. The `key` → ID check and `verified_contents.json` presence are recorded now; Web Store metadata (developer name, email, website) via the store page and the Omaha update-check XML is an opt-in v1.1 feature, because it sends the user's installed IDs to Google.

**Privacy.** No network calls in v1. No telemetry. Only the current user's home directory is read.

## 6. Signature and findings

`signature.json` per version (schema documented in `docs/signature-schema.md`):

```json
{
  "schema": 1, "id": "abcd...", "version": "4.2.0", "tree_hash": "sha256:...",
  "manifest": {
    "manifest_version": 3,
    "permissions": [...], "optional_permissions": [...],
    "host_permissions": [...], "optional_host_permissions": [...],
    "content_scripts": [{"matches": [...], "js": [...], "run_at": "...", "all_frames": true}],
    "background": {"service_worker": "sw.js"},
    "externally_connectable": {"matches": [...], "ids": [...]},
    "web_accessible_resources": [...], "content_security_policy": {...},
    "update_url": "...", "key_matches_id": true,
    "dnr_rulesets": [{"path": "rules.json", "rules": 12, "modify_headers": ["content-security-policy"]}]
  },
  "code": {
    "files": [{"path": "sw.js", "bytes": 812331, "sha256": "..."}],
    "domains": [{"host": "cdn-example.invalid", "refs": [{"file": "sw.js", "line": 4123}]}],
    "chrome_apis": ["chrome.storage.local.set", "chrome.declarativeNetRequest.updateDynamicRules"],
    "sinks": [{"kind": "onload-attribute-exec", "file": "content.js", "line": 88}],
    "timers": [{"kind": "setInterval", "ms": 300000, "file": "sw.js", "line": 4100}],
    "listeners": ["keydown", "input"],
    "obfuscation": {"long_base64_literals": 3, "from_char_code": 0, "atob": 2}
  }
}
```

Findings come from diffing two signatures through `rules.v1.json`. Initial severities:

| Severity | Trigger |
|---|---|
| High | new `<all_urls>` or `*://*/*` host access; new remote-code sink (eval, new Function, onload-attribute exec, remote `<script>` or `importScripts`); new header stripping of CSP or X-Frame-Options; new non-allowlisted domain together with a periodic timer; `key` no longer matches the ID; `update_url` changed; `externally_connectable` widened to all sites |
| Medium | new sensitive API permission (cookies, history, webRequest, tabs, scripting, declarativeNetRequest, management, nativeMessaging, debugger, proxy, identity, downloads, clipboardRead); content-script matches broadened; new non-allowlisted fetch domain; new keyboard or input listeners in a content script; CSP loosened |
| Low | new domains on the allowlist (googleapis, gstatic, the extension's own homepage host); new files; large size change |
| Info | version bump, name or description change, icon change |

The first snapshot of an extension is the baseline and produces no findings; only deltas notify. Notification default: every update, coloured by highest severity; users can raise the threshold.

## 7. Data model and on-disk layout

`<AppData>/ExtWatch/extwatch.sqlite` (macOS `~/Library/Application Support/ExtWatch`, Linux `~/.local/share/extwatch`, Windows `%LOCALAPPDATA%\ExtWatch`):

```
browsers   (id, kind, user_data_dir, first_seen, last_seen)
profiles   (id, browser_id, dir_name, display_name, last_seen)
extensions (id, profile_id, ext_id, name, first_seen, last_seen, current_version_id, key_sha256)
versions   (id, extension_id, version, dir_name, tree_hash, seen_at, activated_at, manifest_json, signature_json, file_count, bytes)
files      (version_id, path, sha256, size)
events     (id, extension_id, kind, from_version_id, to_version_id, at, max_severity, findings_json, acknowledged)
settings   (key, value)
```

Blobs: `blobs/<first two hex>/<sha256>`, deduplicated across versions and extensions (most updates change a handful of files). Retention setting: keep all versions by default, with a per-extension cap available. Reports: `reports/<ext_id>/<from>_<to>.html`.

## 8. CLI

```
extwatch scan [--json] [--browser chrome|brave|edge|chromium] [--profile NAME]   inventory + signatures
extwatch analyze <dir|zip|crx> [--json]                                           analyze any extension package
extwatch diff <ext_id> <vA> <vB> [--json] [--html out.html]                        exit 2 if any High finding
extwatch history <ext_id>                                                          versions and events
extwatch export <ext_id> <version> <out.zip|out_dir>                               for rollback or sharing
extwatch watch --headless [--jsonl]                                                daemon mode for servers and CI
```

`analyze` reads CRX3 by skipping the header (magic `Cr24`, version 3, header length at bytes 8-12, zip follows), no signature verification in v1. Exit codes and JSON shapes are golden-tested.

## 9. Week-by-week

Assumes roughly 30 to 40 hours per week. Each week ends with a demo checkpoint; if a checkpoint slips, cut from the "stretch" column, never from the checkpoint.

| Week | Build | Checkpoint | Stretch |
|---|---|---|---|
| 0 (2 days) | Repo scaffold: CMake presets, core/cli/app targets, FetchContent for tree-sitter and dtl, vendored miniz, clang-format, CI that builds an empty tray app on three OSes, fixture generator that writes a fake profile with two versions of a fixture extension | Green CI, tray icon appears on macOS | Decide name and license |
| 1 | discovery, prefs, inventory, snapshot, db; `extwatch scan --json`. Spikes (2 days max): Windows HKCU blocklist behaviour, native messaging host registration for Chrome/Brave/Edge on macOS, tree-sitter parse time on the largest local bundle | `scan --json` lists every extension in every Chrome and Brave profile on this Mac with correct enabled state and pending versions | Edge and Chromium paths tested in a VM |
| 2 | watcher with debounce and readiness check, catch-up rescan, archive blobs, events table, tray menu, notifications, autostart (LaunchAgent, Run key, XDG autostart), settings file | Bump the fixture extension's version through a local update server; a notification appears within 10 s and the version is archived. Quit ExtWatch, update again, relaunch: the missed update is detected | Wake-from-sleep rescan |
| 3 | tree-sitter signature extraction, prettifier, dtl line diff with caps, semantic manifest diff, rules.v1.json, findings, `analyze` and `diff` CLI, HTML/JSON report | `analyze` flags the QuickLens-style fixture as High with correct file:line; `diff` on all local extensions produces no crash and no High false positives | CRX3 input for `analyze` |
| 4 | Main window: tree of browsers/profiles/extensions, timeline, findings panel, manifest diff view, side-by-side code diff widget with hunk navigation and finding links, actions (store page, copy URL, quarantine, export report, export version), settings dialog. Companion extension + native messaging Disable if on schedule | The full hero flow on macOS, recorded as a GIF | Windows HKCU policy Disable |
| 5 | Windows and Linux passes, packaging (dmg, zip or Inno Setup, AppImage), unsigned-build instructions, README with GIF and prior-art section, `docs/signature-schema.md`, publish `rules/rules.v1.json`, perf pass on 5 MB bundles, Show HN draft | Tagged v1.0.0 with three platform builds | Homebrew cask formula |

## 10. Testing

- Unit: ID derivation from `key`; prefs parsing against redacted real `Secure Preferences` fixtures from Chrome and Brave (both `state` and `disable_reasons` shapes); manifest semantic diff; each signature kind on a small JS fixture; prettifier determinism and idempotence (`prettify(prettify(x)) == prettify(x)`); diff correctness; snapshot and archive round-trip.
- Fixtures: a benign fixture extension in versions 1.0 and 1.1; a "turned malicious" 1.2 that adds `<all_urls>`, a 5-minute poller into `chrome.storage`, an `onload`-attribute executor pointing at `*.invalid` hosts, and a DNR rule stripping CSP. Nothing in the fixtures contacts a real host.
- Integration: watcher test against a temp fake profile (create `<id>/2.0_0`, expect one event); CLI golden JSON.
- Performance: prettify and diff a real 3 to 5 MB vendor bundle inside the targets; run `scan` over 100 fixture extensions under 5 s.
- Manual matrix before release: Chrome, Brave and Edge on each OS, at least one real store update observed end to end.

## 11. Packaging and distribution

- macOS: `.app` in a `.dmg` via macdeployqt, universal binary, `LSUIElement` agent app. Notarization needs the paid Apple Developer account; until then the README documents `xattr -d com.apple.quarantine`.
- Windows: windeployqt into a zip plus an Inno Setup installer; unsigned builds trigger SmartScreen, documented.
- Linux: AppImage; tray requires a StatusNotifier host (KDE, or GNOME with the AppIndicator extension), documented.
- Show HN post with the GIF, replies in the existing HN threads on extension hijacks, r/privacy and r/browsers, Privacy Guides and awesome-privacy listings. Cite ext-watcher and crx-analyzer as prior art in the README.

## 12. Risks

| Risk | Mitigation |
|---|---|
| Disable is weaker than the hero GIF implies on macOS | Tiered Disable; companion extension is the reliable path and is scheduled for week 4 with v1.1 as fallback. Never claim more than the tier that ran. |
| Noisy findings make people uninstall | Baseline produces nothing; only deltas notify; allowlist for common CDNs; severity threshold setting; ship rules as data so they can be tuned without a release. |
| Prettifier or diff chokes on giant bundles | Work caps with an honest "file rewritten" fallback; analysis in a worker thread; perf test in CI. |
| Watcher misses events (sleep, network drives, inotify limits) | Startup, periodic and wake rescans; the database is the truth. |
| Chrome changes prefs shape again | Prefs parser tolerates both known shapes and logs unknown ones; fixtures from real files. |
| Name collision with ading2210/ext-watcher | Decide in week 0 (section 13). |
| Packaging and signing eat week 5 | CI produces artifacts from week 0; signing is optional for v1. |

## 13. Decisions for Kanishka

1. Stack: Qt/C++ as above (recommended) or Tauri/Rust.
2. Companion extension in v1 (recommended if week 4 stays on schedule) or deferred to v1.1 with Quarantine as the only one-click Disable.
3. Name: keep ExtWatch (distinct enough from ext-watcher, a low-star script) or pick something more searchable before the repo goes public.
4. License: MIT (recommended) or GPL-3.
5. Notification default: every update (recommended) or only Medium and above.

## 14. After v1

v1.1: companion extension if deferred; opt-in Web Store publisher tracking (store page and Omaha update-check XML, rate-limited, with "publisher changed" findings); Windows policy Disable; Homebrew cask and winget.
v2: Firefox (`profiles.ini`, `extensions.json`, XPI archives); `verified_contents.json` signature verification; optional deobfuscation pass through an external tool when Node is present; a store-side harness for the "500 popular extensions for 30 days" study; team mode that merges `scan --json` from many machines; Linux in-place rollback experiment.

## Sources

- Local inspection of Chrome and Brave profiles on this machine, 2026-09-05.
- Chromium source: `chrome/browser/ui/startup/url_util.cc` (`ValidateLaunchUrlWebUnsafe`), `startup_tab_provider.cc`.
- Picazo-Sanchez et al., "HMAC and Secure Preferences: Revisiting Chromium-based Browsers Security", CANS 2020: https://www.cse.chalmers.se/~andrei/cans20.pdf
- Google, "Set Chrome app and extension policies (Mac)": https://support.google.com/chrome/a/answer/7517624
- The Hacker News, "Chrome Extension Turns Malicious After Ownership Transfer" (QuickLens, ShotBird, March 2026): https://thehackernews.com/2026/03/chrome-extension-turns-malicious-after.html
- monxresearch ShotBird report: https://monxresearch-sec.github.io/shotbird-extension-malware-report/
- ading2210/ext-watcher: https://github.com/ading2210/ext-watcher
- Extension Monitor: https://extensionmonitor.com/
