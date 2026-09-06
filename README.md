<div align="center">
  <img src="docs/images/logo.png" alt="ExtWatch logo" width="110">
  <h1>ExtWatch</h1>
  <p>
    <strong>Your browser extensions update themselves at night. ExtWatch reads the diff so you don't have to.</strong>
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
  the previous version. Fifty-one rules turn the difference into findings a normal person can read,
  and anything the analyzer could not inspect is reported rather than passed off as clean.
- **Shows the code** - side by side, prettified, highlighted, with each finding linked to its line.
- **Lets you act** - one-click Disable through a tiny companion extension, quarantine, export,
  share a report.
- **Local only** - no account, no server, no telemetry. The one optional network feature is off
  by default.

## How It Works

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

## How to start it

You need CMake, Ninja, a C++20 compiler and Qt 6. On a Mac, `brew install qt cmake ninja` is enough.

```bash
git clone https://github.com/kanishka0411/extWatch.git
cd extWatch
cmake --preset dev-mac          # dev-linux on Linux, ci-windows on Windows
cmake --build --preset dev-mac
./build/dev-mac/src/extwatch --show
```

It sits in the tray. The first scan records every extension as a baseline; after that you only
hear about changes. The same binary is the command line: `extwatch --help`.

## License

MIT
