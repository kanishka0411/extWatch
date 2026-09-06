# Security policy

ExtWatch analyzes untrusted browser extension packages and stores copies of them. Bugs that let a
malicious package crash, exhaust or escape the analyzer, corrupt the archive, or make a finding
disappear are security bugs.

## Reporting

Please do not open a public issue for a vulnerability. Email kanishka0411k@gmail.com with:

- the ExtWatch version or commit
- a package, fixture or script that reproduces the problem
- what you expected to see

You will get an acknowledgement within a week. Fixes ship as a normal release with credit to you
unless you prefer otherwise.

## Scope

In scope: the scanner, the archive and its database, the JavaScript and package analyzers, the
rules, the companion extension and its native messaging host, the quarantine and restore actions,
and the release pipeline.

Out of scope: attacks that require root or administrator rights on the machine, physical access,
or modifying the ExtWatch binary itself. The threat model is in `docs/THREAT_MODEL.md`.

## Supported versions

Only the latest release receives fixes.
