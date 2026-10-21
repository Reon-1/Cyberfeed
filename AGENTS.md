# CyberFeed — Engineering Instructions

## Purpose and working style

CyberFeed is a local-first defensive investigation TUI. It inspects files as data, extracts indicators, performs passive lookups against optional public providers, and stores evidence for later review. Never execute suspicious files, visit extracted URLs, upload file contents, or claim an artifact is safe from a no-match result. Prefer focused, tested changes and explain important Rust concepts briefly for the learner.

Before editing, inspect `git status --short` and the relevant diff. Preserve all working-tree changes. Never reset, discard, commit, or push unless explicitly requested. Keep dependencies, report formats, and user workflows stable unless a verified defect justifies a change.

## Architecture

- `src/main.rs` loads configuration, builds the blocking HTTP client, and starts the app.
- `src/config.rs` loads optional credentials and performs the confirmed `.env` edit flow.
- `src/app/` owns menus and workflows: file inspection, lookup scheduling, provider views, threat feeds, log hunting, and saved-report browsing.
- `src/app/indicator_list.rs` performs bounded, local-only import/comparison of one-indicator-per-line lists. Its preview provenance currently lives only for the active workflow; individual follow-up Value Searches are recorded through the existing session/report path.
- `src/tui/` owns Ratatui rendering, shared styles/components, Crossterm terminal lifecycle, and test rendering. Keep provider and evidence decisions out of drawing code.
- `src/file.rs`, `src/indicator.rs`, and `src/investigation.rs` own local inspection, indicator classification, and in-memory evidence.
- `src/providers/` owns provider-specific HTTP and response parsing. Normalize results at the workflow boundary.
- `src/report/` owns file/session report models, serialization, persistence, Markdown rendering, and STIX export.

Keep modules focused and errors explicit. Do not introduce an async runtime, database, provider framework, or cache without a concrete need.

## Evidence and security invariants

- Preserve distinctions between `FOUND`, `NOT FOUND`, `ERROR`, `INVALID`, `UNSUPPORTED`, `NOT CONFIGURED`, and `SKIPPED`. A provider failure is never a negative result.
- A provider match applies to the queried indicator; it is not by itself a verdict on a local file. Preserve source, queried value, timestamps, and available metadata.
- MalwareBazaar, ThreatFox, and URLhaus support different indicator types. URLhaus exact-URL checks preserve full URL paths and queries; URLhaus does not support SHA-1 payload lookup. Cloudflare Radar is a feed, not an IOC lookup provider.
- Batch file checks and log hunting are local-only. Log occurrence provenance is optional for older reports and must deserialize with its default.
- Preserve supported legacy file reports and the distinction between file and session reports. Paired report writes must retain atomic-write/error guarantees. Do not silently replace historical evidence.
- Bound file, log, provider-response, and saved-report reads. File inspection and its sequential provider lookups share a 60-second analysis budget, with each provider request capped at 15 seconds. Keep these limits explicit and test changes to them; blocking OS file reads cannot be interrupted mid-call.
- Indicator-list import is bounded to 8 MiB per source, 4,096 bytes per line, 100,000 candidates per import, and 1,000 URLs. Preserve the accepted prefix and disclose when a limit truncates input; do not treat list preview as provider coverage.
- Credentials may come from externally supplied environment variables or `.env`; external values take precedence. Never reveal secrets in UI, errors, tests, logs, or reports. Credential edits must be hidden, confirmed, and preserve unrelated `.env` entries. Setup must not make authentication requests.
- Sanitize untrusted terminal strings. Restore raw mode, alternate screen, and cursor state on ordinary errors and panic paths.

## Tests and verification

Use deterministic tests with temporary files and dummy credentials; never call live providers in automated tests. Prefer focused unit tests beside private implementation and Ratatui `TestBackend` checks for visible UI behavior. Add regression tests for confirmed defects and retain legacy report compatibility coverage.

For normal changes, run:

```sh
cargo fmt --check
cargo check --all-targets
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo doc --no-deps
git diff --check
```

Report only checks and platforms that actually passed. Review the final status and diff; do not commit.
