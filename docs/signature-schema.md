# Behavior signature and findings

`extwatch analyze <package> --json` and `extwatch scan --json` emit a **signature** per extension
version and, for events, a list of **findings**. Both are stable JSON meant to be consumed by scripts,
CI and write-ups. Schema version 1.

## Signature (`signature`)

| Field | Meaning |
|---|---|
| `schema` | Always `1`. |
| `version` | Manifest version string. |
| `key_matches_id` | Whether the `key` in `manifest.json` derives to the extension ID (SHA-256 of the DER public key, first 16 bytes, a-p encoding). `false` means tampered or sideloaded files. |
| `manifest` | Normalized manifest facts: `manifest_version`, `name`, `description`, `permissions` (API permissions only), `host_permissions` (host patterns, including MV2 patterns moved out of `permissions`), `optional_*`, `content_scripts[]` (each with `matches`, `exclude_matches`, `include_globs`, `exclude_globs`, `js`, `css`, `run_at`, `world`, `all_frames`, `match_origin_as_fallback`; compared per declaration, keyed by its script files), `background`, `externally_connectable` (`matches` and `ids`, where `*` means any extension), `web_accessible_resources`, `content_security_policy`, `dnr_rule_resources`, `update_url`, `key`, `raw` (the manifest as shipped). |
| `dnr_header_mods[]` | Static declarativeNetRequest rules that modify security-relevant headers: `ruleset`, `rule_id`, `header` (lower-case), `operation` (`remove`, `set`, `append`). Findings distinguish a removal (High) from a set or append (Medium). |
| `dnr_redirects[]` | Static redirect rules: `ruleset`, `rule_id`, `target` (URL, regex substitution or transform summary). |
| `dnr_allow_all_requests` | Number of `allowAllRequests` rules. |
| `dnr_rule_count` | Number of static rules. |
| `wasm_files[]` | `.wasm` modules in the package (their contents are not analyzed). |
| `analysis_warnings[]` | `file: reason` for every place the analysis was incomplete: files above 48 MiB, nesting deeper than 400 levels, entries a package loader refused to inflate, parse errors. A signature with warnings yields an `analysis.incomplete` finding. |
| `files[]` | `path`, `bytes`, `analyzed`, `lines` (prettified line count), `parse_error`. |
| `total_bytes` | Sum of file sizes. |
| `content_script_files[]` | JavaScript files injected into web pages. |
| `remote_script_sources[]` | `<script src="https://...">` targets found in extension pages. |
| `domains[]` | Hosts of absolute `http(s)`/`ws(s)` URLs in string literals: `host`, `refs[] {file, line}`. |
| `chrome_apis[]` | `chrome.<namespace>.<member>` expressions seen in code (storage areas collapse to `chrome.storage.local` etc.). |
| `sinks[]` | Calls and assignments that execute code, move data or rewrite traffic: `kind`, `file`, `line`, `evidence`. Kinds: `eval` (also `(0, eval)`, `globalThis["eval"]`, `window.eval`), `new_function` (also `Function(x)()`), `timer_string`, `attribute_exec`, `import_scripts_remote`, `import_scripts_dynamic`, `import_scripts_local`, `script_element`, `iframe_element`, `src_assignment`, `src_remote_literal`, `inner_html`, `javascript_url`, `fetch`, `xhr`, `websocket`, `beacon`, `event_source`, `native_messaging`, `storage_get`, `dnr_dynamic_rules`, `webrequest_headers`, `execute_script`, `register_content_scripts`, `wasm_instantiate`. The `browser.*` namespace is normalized to `chrome.*`. A sink is "new" in a comparison when the previous version had no sink of that kind in the same file. |
| `timers[]` | `setTimeout`, `setInterval` and `chrome.alarms.create` calls: `kind` (`setTimeout`, `setInterval`, `alarm`), `ms` (literal, product like `5 * 60 * 1000`, a file-level constant such as `const FIVE_MINUTES = 300000`, or `periodInMinutes` converted; 0 when unresolved), `string_body`, `file`, `line`. |
| `listeners[]` | `addEventListener` for `keydown`, `keypress`, `keyup`, `input`, `paste`, `submit`, `change`, `copy`, `beforeunload`. |
| `fingerprinting[]` | Device fingerprint reads (`navigator.language`, time zone, user agent, screen size, ...), with `fingerprinting_files[]`. |
| `security_header_literals[]` | Header names such as `content-security-policy` appearing as string literals, with `security_header_files[]`. |
| `dynamic_urls` | A template literal builds a URL whose host is computed at runtime. |
| `obfuscation` | Counters: `long_base64_literals`, `hex_escaped_strings`, `atob_calls`, `from_char_code_calls`, `obfuscator_identifiers` (`_0x...` names), `invisible_chars` (bidirectional overrides and isolates, zero-width characters, byte-order marks inside the file). |

Line numbers refer to the **prettified** text (`extwatch` formats every JavaScript file deterministically
before showing it), so `file:line` from a finding points at the line you see in the diff viewer or
the HTML report.

## Findings

A finding is produced by comparing two signatures (`before` and `after`). For a baseline, `before`
is empty and the findings describe the extension's risk profile.

```json
{ "rule": "network.poller", "severity": "high",
  "title": "Polls a server on a timer",
  "detail": "Contacts cdn-updates.example.invalid every 5 min (sw.js:17).",
  "file": "sw.js", "line": 17 }
```

Severities: `high`, `medium`, `low`, `info`. The rule list with explanations is in
[`rules/rules.v1.json`](../rules/rules.v1.json) and printed by `extwatch rules`.

Findings are sorted by severity, then by rule order. `findings_summary` (in scan events) is a
one-line digest of the top findings, used for notifications:

```
+host access <all_urls>, polls cdn-updates.example.invalid every 5 min, Executes code through an event-handler attribute
```

## Reproducibility

Every version is identified by a tree hash: SHA-256 over `path \0 sha256hex \n` lines of all files,
sorted by path. Two machines with the same installed files compute the same hash, and
`extwatch diff <id> <vA> <vB>` on either produces the same findings for the same rules version.
