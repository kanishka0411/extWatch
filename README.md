# ExtWatch

**A local watchdog that diffs your browser extensions on every silent update.**

ExtWatch is a small tray app (macOS, Windows, Linux) that snapshots every extension installed in
Chrome, Chromium, Edge and Brave, across all profiles. When an extension updates in the background,
ExtWatch catches the new version, archives it, prettifies the code, diffs it against the previous
version and tells you what actually changed: new host access, new permissions, new domains it talks
to, header stripping, and the loader patterns used by extensions that turned malicious after being
sold (fetch JavaScript on a timer, cache it in storage, run it through an `onload` attribute).

Nothing leaves your machine. There is no account, no server, no telemetry.

```
Screenshot Tool 1.1.0 → 1.2.0
+host access <all_urls>, polls cdn-updates.example.invalid every 5 min,
executes code through an event-handler attribute
```

## What it does

- **Finds every install.** Chrome (stable/beta/dev/canary), Chromium, Edge, Brave, Vivaldi, Opera
  and Arc user data directories, every profile, including unpacked developer extensions. Reads the
  browser's own preferences for enabled state, install source and the active version.
- **Archives every version.** Files are stored content-addressed (SHA-256), so a hundred versions of
  a 5 MB extension cost a few MB. Export any version as a zip to load unpacked, or keep it as evidence.
- **Catches silent updates.** A file-system watcher on each profile plus periodic and startup rescans;
  a version that was downloaded but not yet activated is reported before it runs.
- **Explains the change.** A semantic manifest diff and a behavior signature extracted from the code
  with tree-sitter: network domains, `chrome.*` APIs, `eval`/`new Function`/timer-string execution,
  `setAttribute('onload', …)`, `importScripts`, storage-to-exec chains, `declarativeNetRequest`
  rules that strip `Content-Security-Policy` or `X-Frame-Options`, keystroke listeners in content
  scripts, fingerprinting reads, obfuscation indicators. Forty rules turn the delta into findings
  with a severity and a plain-English explanation. Each finding links to a line of the prettified code.
- **Shows the diff.** Side-by-side, prettified, syntax-highlighted, with change navigation.
  Minified 20k-line bundles are formatted deterministically so only real changes show.
- **Lets you act.** One-click **Disable** through the companion extension (below), open the Web
  Store listing, copy the `chrome://extensions` URL, export the version, export a self-contained
  HTML report to share, or quarantine the installed files so the browser disables the extension
  (reversible).
- **Watches the publisher (opt-in).** Once a day it can read the Web Store listing of each
  store-installed extension and raise a High finding when "Offered by" changes or the listing
  disappears. Off by default; it is the only network access ExtWatch ever makes.
- **Works headless.** `extwatch scan --json`, `extwatch analyze <dir|zip|crx>` and
  `extwatch diff` return machine-readable output and exit code 3 on a High finding, for CI and blog posts.

## Install

Release builds are produced by `.github/workflows/release.yml` on every `v*` tag: a macOS `.dmg`
(signed and notarized when the repository secrets are set), a Windows installer and portable zip,
and a Linux AppImage. The same scripts run locally:

```bash
packaging/macos/build-dmg.sh            # ExtWatch.app + dist/ExtWatch-<version>-macos.dmg
packaging/linux/build-appimage.sh       # dist/ExtWatch-<version>-x86_64.AppImage
packaging/linux/docker-build.sh         # build + tests + AppImage inside Debian trixie
powershell packaging/windows/build-installer.ps1   # Inno Setup installer + portable zip
```

A dmg built against Homebrew's Qt is for local testing only (Homebrew's Qt frameworks target the
newest macOS); release dmgs come from the workflow, which uses the official Qt installer.
Unsigned builds work but macOS Gatekeeper and Windows SmartScreen will warn; see the scripts for
the `CODESIGN_IDENTITY`, `NOTARY_PROFILE` and `SIGNTOOL_CERT_THUMBPRINT` variables. For the
command line on macOS: `ln -s /Applications/ExtWatch.app/Contents/MacOS/ExtWatch /usr/local/bin/extwatch`.

To build from source:

Requirements: CMake 3.24+, Ninja, a C++20 compiler, Qt 6.5+ (Core, Gui, Widgets, Sql, Concurrent, Network, Svg, Test).
tree-sitter, its JavaScript grammar and dtl are fetched at configure time; miniz is vendored.

```bash
cmake --preset dev-mac      # or dev-linux; see CMakePresets.json for CI presets
cmake --build --preset dev-mac
ctest --preset dev-mac
```

macOS: `brew install qt cmake ninja`. Linux: your distribution's Qt 6 development packages.
Windows: the Qt online installer with MSVC 2022, then the `ci-windows` preset.

## Use

Start `extwatch` without arguments for the tray app. The first scan records every extension as a
baseline and shows its risk profile; from then on you are notified about changes only.

```bash
extwatch scan                      # inventory of every profile, archives new versions, prints events
extwatch scan --json               # the same, machine-readable (manifest facts and findings included)
extwatch history <extension-id>    # archived versions and events for one extension
extwatch events                    # recent events across all extensions
extwatch diff <id> <vA> <vB>       # findings, manifest and code diff between two archived versions
extwatch diff <id> <vA> <vB> --html report.html
extwatch report <event-id> --html report.html
extwatch analyze <dir|zip|crx>     # behavior signature and risk profile of any extension package
extwatch export <id> <version> out.zip
extwatch rules                     # the rules behind the findings
extwatch store <extension-id>      # Web Store listing: publisher, version, rating (uses the network)
extwatch paths                     # where ExtWatch looks for browsers on this machine
```

Troubleshooting: `EXTWATCH_DEBUG=1` makes the tray app log watcher activity and rescans to stderr.

Data lives in the per-user data directory (macOS `~/Library/Application Support/ExtWatch`, Linux
`~/.local/share/extwatch`, Windows `%LOCALAPPDATA%\ExtWatch`), overridable with `EXTWATCH_DATA_DIR`
or `--data-dir`. Unusual browser locations: `EXTWATCH_USER_DATA_DIRS="chrome=/path/User Data;brave=/other"`
or the Settings dialog.

## One-click Disable: the companion extension

Browsers refuse `chrome://` links from other programs and protect their preference files, so a
desktop app cannot flip an extension off by itself. ExtWatch ships a companion extension
(`companion/`, about 150 lines, `management` and `nativeMessaging` permissions only, no network,
no page access) that gives the app a real **Disable** button and instant install/update events.

Setup takes a minute: **Settings → Set up companion extension** registers the native messaging
host for every browser on the machine (user level, no admin) and opens the folder to load
unpacked from `chrome://extensions` with Developer mode on. Monitoring keeps running outside the
browser; only the switch lives inside it. Without the companion, **Quarantine** remains available.

## Try the demo

The repository ships a fixture extension in three versions: 1.0.0 and 1.1.0 are benign, 1.2.0 is a
faithful re-creation of the QuickLens pattern (all hosts, CSP stripping, a five-minute poller and an
`onload` executor, pointing at reserved `.invalid` hosts so nothing ever connects).

```bash
tools/make_fixture_profile.py fixtures/generated/user-data --version 1.1.0
export EXTWATCH_DATA_DIR=$PWD/fixtures/generated/data
export EXTWATCH_USER_DATA_DIRS="chrome=$PWD/fixtures/generated/user-data" EXTWATCH_USER_DATA_DIRS_ONLY=1
./build/dev-mac/src/extwatch                                        # tray app records the baseline
tools/make_fixture_profile.py fixtures/generated/user-data --update 1.2.0   # the silent update lands
```

Within a few seconds the tray reports the update with its findings; click it to see the diff.

## How the hard parts work

- **Where extensions live.** `<User Data>/<Profile>/Extensions/<id>/<version>_<n>/`. Chrome writes the
  signing key into the unpacked `manifest.json`, so ExtWatch verifies that the key derives to the
  extension ID. Enabled state and the active version come from `Secure Preferences`, which is
  HMAC-protected on macOS and Windows and therefore never written.
- **Readable diffs of minified code.** A structural formatter driven by the tree-sitter syntax tree
  (one statement per line, blocks indented, long literals broken) is deterministic, so two formatted
  versions diff cleanly. Analysis runs on the original bytes and maps offsets to formatted lines.
- **The QuickLens trick.** The malicious payload is never in the package, so the rules flag the
  loader instead: a timer plus a network call to a new domain in the same file, storage reads next to
  string execution, `on*` attributes set from variables, and header-stripping rules.
- **Disable.** Browsers reject `chrome://` URLs from other programs and protect their preferences, so
  the one-click path is the companion extension over native messaging; the fallbacks are copying the
  extensions-page URL and quarantining the files so the browser disables the extension as corrupted.
- **Publisher tracking.** The Web Store has no API. The listing page is server-rendered with stable
  labels ("Offered by", "Version", "Updated"), which the parser keys on; unknown IDs redirect to the
  store front page, which is treated as "listing gone".

The full plan, decisions and roadmap are in [docs/PLAN.md](docs/PLAN.md).

## Prior art

[ading2210/ext-watcher](https://github.com/ading2210/ext-watcher) watches the Web Store for extension
IDs you list and posts diffs to Discord. crx-analyzer analyzes one package at a time. Chrome itself
re-prompts on permission increases but shows no code. ExtWatch watches what is actually installed on
your machine, across browsers and profiles, keeps every version, and explains the code change.

## License

MIT. Qt is used under the LGPLv3 with dynamic linking. tree-sitter (MIT), dtl (BSD), miniz (MIT).
