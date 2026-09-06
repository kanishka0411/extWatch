# Threat model

ExtWatch runs as the user, reads the browser's profile directories, keeps copies of every
extension version and analyzes their code. This is what it defends against and what it does not.

| Threat | In scope | Notes |
| --- | --- | --- |
| A store extension turns malicious in an update | Yes | The core case: silent update, new loader, new permissions. Detected by diffing snapshots. |
| A publisher account is phished or the extension is sold | Yes | Same as above; publisher tracking (opt-in) adds the "Offered by" change as evidence. |
| A sideloaded or unpacked extension | Yes | Listed and analyzed like any other; the key check tells tampered files from store files. |
| Files of an installed version change without a version bump | Yes | Reported as "modified in place" with its own event kind. |
| A malicious package given to `extwatch analyze` | Yes | Archives are size, entry and ratio limited; single files above 48 MiB and nesting beyond 800 levels are skipped and reported as incomplete. |
| Code written to evade the rules | Partly | Static analysis only. Aliased `eval`, `browser.*`, computed periods and `chrome.alarms` are handled; heavy obfuscation is flagged rather than understood. |
| Another process running as the same user | Partly | It can read the archive (kept 0700/0600) and connect to the companion socket. The socket accepts only relays that carry the companion's origin, but a same-user process is trusted by the OS. |
| A second ExtWatch instance | Yes | An instance lock per archive prevents socket takeover. |
| Root, administrator or kernel compromise | No | Nothing user-level can defend against this. |
| Tampering with the ExtWatch binary or its release | No, except | Releases are built by CI from a tagged commit with pinned actions and tools and ship `SHA256SUMS`; signing depends on certificates. |
| Network attacks on publisher tracking | Limited | HTTPS to the Web Store; the page is treated as an unreliable sensor, never as proof. |

## Trust boundaries

- **Browser files are untrusted input.** Preferences, manifests and code are parsed defensively.
- **The archive is evidence.** Blobs are verified while copied and named by their hash; snapshots
  are recorded only once every blob is stored. `extwatch doctor --verify-blobs` re-checks them.
- **Actions are explicit and scoped.** Disable, Quarantine and Restore act on one browser profile,
  identified by its database row, never by extension ID alone.
- **The companion is small and checkable.** About 150 lines, two permissions, no network; the
  extracted copy is compared with the embedded one.
- **Rescans trust per-file metadata, sweeps re-hash.** Between full hashes an unchanged version
  directory is recognised by a fingerprint over every file's path, size and mtime. A rewrite that
  preserves all three for a file would pass; the first scan after the app launches, every fourth
  persisted scan (a counter in the database, shared by the app and `extwatch scan`), and
  `extwatch scan --verify` hash every file again.
- **Ambiguity fails closed.** A Disable request that could reach two profiles with identical
  extension inventories is refused, and a `version@hash` reference that matches more than one
  snapshot is an error, rather than a guess.
