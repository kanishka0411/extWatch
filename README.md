<div align="center">
  <img src="docs/images/logo.png" alt="ExtWatch logo" width="110">
  <h1>ExtWatch</h1>
  <p>
    <strong>Your browser extensions update themselves at night. ExtWatch reads the diff so you don't have to.</strong>
  </p>
  <p>
    <a href="#why-extwatch">Why</a> &middot;
    <a href="#how-it-works">How it works</a> &middot;
    <a href="#what-it-catches">What it catches</a> &middot;
    <a href="#quick-start">Quick start</a> &middot;
    <a href="#security-model">Security</a>
  </p>
</div>

---

## Why ExtWatch?

An extension you installed years ago is not the extension running today. Extensions get sold,
developer accounts get phished, and the next silent update turns a screenshot tool into
spyware. QuickLens did exactly that in 2026: kept its features, added a five-minute poll to a
server for JavaScript to run on every page. The Great Suspender, Nano Adblocker, Stylish and the
35 extensions of the Cyberhaven wave went the same way. The browser shows nothing, because
nothing about the update looks wrong to the browser.

ExtWatch is a small tray app for macOS, Windows and Linux that watches what your extensions
actually do, version after version, on your own machine.

- **Sees every install** - Chrome, Chromium, Edge, Brave, Vivaldi, Opera and Arc, every profile,
  read straight from the browser's own files.
- **Keeps every version** - content-addressed archive, so a hundred versions of a 5 MB extension
  cost a few MB. Export any of them as a zip.
- **Catches silent updates in seconds** - a file watcher per profile, plus rescans on start and
  every 15 minutes. Versions that are downloaded but not yet running are reported first.
- **Explains the change** - the code is parsed, reduced to a behavior signature, and diffed against
  the previous version. Forty rules turn the difference into findings a normal person can read.
- **Shows the code** - side by side, prettified, highlighted, with each finding linked to its line.
- **Lets you act** - one-click Disable, quarantine, export, share a report.
- **Local only** - no account, no server, no telemetry. The one optional network feature is off
  by default.

## How It Works

<div align="center">
  <img src="docs/images/architecture.svg" alt="ExtWatch architecture" width="900">
</div>

1. **Discover** - find every user data directory and profile, list the extensions and read
   `Secure Preferences` for the active version and enabled state.
2. **Snapshot** - hash every file, store new blobs in the archive, record the version and its
   manifest in SQLite. The first snapshot of an extension is its baseline.
3. **Watch** - a file-system watcher on each profile notices the new `Extensions/<id>/<version>/`
   directory the moment the browser writes it.
4. **Analyze** - both versions are parsed with tree-sitter: domains it talks to, `chrome.*` APIs,
   code run from strings, storage read next to `eval`, header-stripping rules, keystroke listeners,
   fingerprinting reads, obfuscation.
5. **Explain** - the rules compare the two signatures and produce findings with a severity, a
   sentence, and a `file:line`.
6. **Show** - a tray notification with the one-line summary, and a window with the findings, the
   manifest diff and the code diff.

## What It Catches

<div align="center">
  <img src="docs/images/changes.png" alt="A silent update caught by ExtWatch" width="900">
</div>

The notification for the update above reads:

```
Screenshot Tool 1.1.0 → 1.2.0
+host access <all_urls>, polls cdn-updates.example.invalid every 5 min,
executes code through an event-handler attribute
```

The malicious payload is never in the package, so the rules look for the loader instead:

- a timer plus a network call to a new domain in the same file
- `chrome.storage` reads next to `eval`, `new Function` or a string timer
- an `on*` attribute set from a variable, the QuickLens trick
- `declarativeNetRequest` rules or `webRequest` listeners that strip `Content-Security-Policy`
  or `X-Frame-Options` from every page
- new `<all_urls>` access, new sensitive permissions, widened `externally_connectable`
- a changed signing key or update URL, keystroke listeners in content scripts, obfuscation

Every finding opens the code at the exact line, prettified so a 20,000-line minified bundle
diffs like source:

<div align="center">
  <img src="docs/images/code-diff.png" alt="Side-by-side code diff" width="900">
</div>

## Tech Stack

| Layer     | Technology                                                    |
| --------- | ------------------------------------------------------------- |
| App       | C++20, Qt 6 Widgets (tray, window, diff viewer)               |
| Analysis  | tree-sitter + tree-sitter-javascript, custom structural formatter |
| Diff      | dtl (Myers)                                                   |
| Storage   | SQLite via Qt SQL, content-addressed blob store               |
| Packages  | miniz (zip, CRX2/CRX3)                                        |
| Companion | Manifest V3 extension, native messaging                        |
| Build     | CMake, Ninja, GitHub Actions (macOS, Windows, Linux)           |

## Security Model

ExtWatch is a read-only observer of your browser's files. It never writes to browser
preferences and never sends data anywhere.

### Protected Today

- **Everything is local** - the archive, the database and the reports live in your user data
  directory. The only network access, Web Store publisher tracking, is opt-in.
- **Tamper check** - Chrome writes the signing key into every unpacked `manifest.json`; ExtWatch
  verifies that it derives to the extension ID.
- **Reproducible findings** - every version has a tree hash and every report names the rules
  version, so two machines with the same files get the same result.
- **Small companion** - the optional extension has only `management` and `nativeMessaging`
  permissions, no page access, no network, about 150 lines you can read in a minute.

### Known Limits

| Limit                | Details                                                                                                                       |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Static analysis      | ExtWatch reads code, it does not run it. Heavily obfuscated loaders can hide; the obfuscation itself is flagged.               |
| Disable needs help   | Browsers refuse `chrome://` links from other apps and protect their preferences, so one-click Disable goes through the companion extension. Without it, Quarantine moves the files so the browser refuses to run them. |
| Unsigned builds      | Until certificates are added, Gatekeeper and SmartScreen warn once. Signing and notarization are wired into the release workflow. |
| First scan cost      | The first run analyzes every extension once. With a 44 MB wallet extension installed that takes about 40 seconds in the background; later scans take about a second. |

## Quick Start

```bash
git clone https://github.com/kanishka0411/extWatch.git
cd extWatch
cmake --preset dev-mac          # dev-linux on Linux, ci-windows on Windows
cmake --build --preset dev-mac
ctest --preset dev-mac
./build/dev-mac/src/extwatch --show
```

Requirements: CMake 3.24+, Ninja, a C++20 compiler and Qt 6.5+ (Core, Gui, Widgets, Sql,
Concurrent, Network, Svg, Test). On a Mac, `brew install qt cmake ninja` covers it. tree-sitter,
its JavaScript grammar and dtl are fetched at configure time; miniz is vendored.

### See it catch something

The repo ships a fixture extension in three versions. 1.0.0 and 1.1.0 are harmless; 1.2.0 is a
faithful copy of the QuickLens loader, pointed at `.invalid` domains so it can never connect.

```bash
tools/make_fixture_profile.py fixtures/generated/user-data --version 1.1.0
export EXTWATCH_DATA_DIR=$PWD/fixtures/generated/data
export EXTWATCH_USER_DATA_DIRS="chrome=$PWD/fixtures/generated/user-data" EXTWATCH_USER_DATA_DIRS_ONLY=1
./build/dev-mac/src/extwatch --show
```

In a second terminal, let the update land, then watch the notification:

```bash
tools/make_fixture_profile.py fixtures/generated/user-data --update 1.2.0
```

### Packages

Every `v*` tag builds a macOS dmg, a Windows installer plus portable zip and a Linux AppImage on
GitHub Actions and attaches them to the release. The same scripts run locally:

```bash
packaging/macos/build-dmg.sh
packaging/linux/build-appimage.sh
packaging/linux/docker-build.sh                    # build, test and package inside Debian trixie
powershell packaging/windows/build-installer.ps1
```

## Command Line

Everything the window does, for scripts and CI. `--json` everywhere; exit code 3 when a finding
is High.

| Command                                | What it does                                              |
| -------------------------------------- | --------------------------------------------------------- |
| `extwatch scan`                        | Inventory every profile, archive new versions, print events |
| `extwatch history <id>`                | Versions and events recorded for one extension            |
| `extwatch events`                      | Recent events across all extensions                       |
| `extwatch diff <id> <old> <new>`       | Findings, manifest and code diff between two versions     |
| `extwatch report <event-id> --html f`  | Self-contained HTML report for one event                  |
| `extwatch analyze <dir\|zip\|crx>`      | Risk profile of any package, nothing installed            |
| `extwatch export <id> <version> out.zip` | Restore an archived version                             |
| `extwatch store <id>`                  | Who offers it on the Web Store right now                  |
| `extwatch rules`                       | The forty rules and their explanations                    |
| `extwatch paths`                       | Where it looks for browsers on this machine               |

Data lives in `~/Library/Application Support/ExtWatch` (macOS), `~/.local/share/extwatch`
(Linux) or `%LOCALAPPDATA%\ExtWatch` (Windows). Browsers in unusual places:
`EXTWATCH_USER_DATA_DIRS="chrome=/path/User Data;brave=/other"`. `EXTWATCH_DEBUG=1` logs what
the watcher sees.

## Companion Extension

A desktop app cannot switch an extension off by itself, so ExtWatch ships a companion. It lives
in `companion/`, connects to ExtWatch through native messaging, and does one thing: enable or
disable an extension when you press the button. It also reports installs and updates instantly.

Settings → **Set up companion extension** registers the native messaging host for every browser
on the machine (no admin) and opens the folder. Load it unpacked from `chrome://extensions` with
Developer mode on. Monitoring stays outside the browser; only the switch lives inside it.

## License

MIT. See [LICENSE](LICENSE); third-party components are listed in [THIRD_PARTY.md](THIRD_PARTY.md).
