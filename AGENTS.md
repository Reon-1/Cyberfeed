# CyberFeed — Codex Project Instructions

## Purpose
CyberFeed is a Rust CLI for local file inspection, indicator extraction, passive threat-intelligence lookups, investigation evidence, and JSON/Markdown reports. Treat it as real security-related software: preserve evidence accurately, distinguish missing results from errors, and do not claim an artifact is safe merely because a provider returns no match.

## Working style
- The developer is learning Rust. Make good engineering decisions, but explain important changes in plain language and briefly. Prefer a concise summary of the key Rust concepts over a long tutorial unless asked.
- Be token-efficient: inspect relevant files first, avoid dumping entire files or repeating this document, keep plans and final reports concise, and do not explain routine syntax unless it helps understanding.
- Do the task, not just an audit or a list of suggestions. Ask questions only when a genuine ambiguity blocks safe progress.
- Prefer small, coherent diffs. Broad refactoring is allowed when justified, but avoid speculative frameworks and unrelated cleanup.

## Protect the repository
- Before edits, run `git status --short` and inspect the current diff. Treat all existing modifications as user work; preserve them.
- Never run destructive cleanup/reset/checkout commands, commit, push, or rewrite history unless explicitly requested.
- Do not change dependencies, report schemas, or documented behavior without a concrete reason. If serialized data changes, preserve older report compatibility with tests.
- Never put API keys, secrets, or sensitive local data in source, tests, logs, reports, or documentation.
- Review and update `AGENTS.md` when architecture, module locations, workflows, or engineering conventions change. Review `README.md` when user-visible behavior, capabilities, configuration, limits, or project structure change.

## Current architecture (verify against code before relying on this)
- `src/main.rs`: application entry point.
- `src/config.rs`: credential presence/loading and the narrow, confirmed `.env` editor; never expose credential values.
- `src/app/`: terminal menus and application workflows.
- `src/app/file_workflow.rs`: interactive file-investigation flow.
- `src/app/file_workflow/lookups.rs`: provider lookup scheduling, limits, deduplication, and result normalization.
- `src/indicator.rs`: indicator types and classification.
- `src/file.rs`: local file hashing and text indicator extraction; never execute inspected files or visit extracted URLs.
- `src/log_hunt.rs`: bounded streaming text/JSONL extraction with per-occurrence source locations.
- `src/investigation.rs`: investigation/session evidence.
- `src/providers/malwarebazaar.rs`, `src/providers/threatfox.rs`, `src/providers/urlhaus.rs`: provider-specific API behavior.
- `src/providers/cloudflare.rs`: Cloudflare Radar/feed behavior; do not assume it supports the same lookup operations as the IOC providers.
- `src/providers/mod.rs`: external API client module declarations.
- `src/report/`: report models, summary calculation, rendering, and persistence.
- `src/report/stix.rs`: STIX 2.1 bundle construction and separate local export.
- `src/app/saved_reports/`: saved-report browsing and comparison.

Keep domain/evidence logic separate from terminal presentation and provider-specific JSON where practical. Add abstractions only when they reduce real coupling or make behavior testable; do not add a trait, plugin framework, async runtime, database, or caching layer speculatively.
Batch local triage and log hunting are local-only today; do not represent absent provider lookups as negative findings. Log occurrence provenance is an optional schema-v4 field; deserialize older reports with the serde default and retain compatibility tests.

Credential changes must preserve unrelated `.env` entries, require confirmation, keep input hidden, and never include values in errors or reports. Treat externally supplied environment variables as higher priority than `.env`; do not make authentication requests during setup. Automated tests must use dummy credentials and temporary directories. The CI matrix targets stable Rust on Linux, macOS, and Windows; report only platforms that actually passed.

Terminal input is event-driven through Crossterm. Handle resize events by redrawing the active screen, preserving prompt contents and navigation state, and restoring raw mode/cursor visibility on every exit path. Terminal screens should use current dimensions, compact layouts for small windows, sanitized untrusted text, and shared outcome styling. Explain outcomes in plain language without replacing evidence or implying safety. Report comparisons must distinguish same-file identity from different contents and treat missing, unsupported, skipped, unconfigured, or failed evidence as inconclusive where appropriate.

## Provider and evidence rules
- MalwareBazaar, ThreatFox, and URLhaus have different capabilities. Route only supported indicator types to each provider; represent unsupported operations explicitly rather than issuing invalid requests.
- URLhaus supports exact URL, host (IP/domain), and MD5/SHA-256 payload lookups. It does not support SHA-1 payload lookup. URLhaus uses the existing shared `ABUSECH_AUTH_KEY` configuration if that remains true in code.
- URL exact-match lookups and host lookups are different observations. Preserve URL paths and query strings; do not collapse distinct URLs by lowercasing the whole URL.
- Never fetch, resolve, or navigate to URLs extracted from files. Only submit indicator values to documented passive lookup APIs.
- Keep provider provenance and useful evidence. `FOUND`, `NOT FOUND`, `ERROR`, `UNSUPPORTED`, and `SKIPPED` must remain meaningfully distinct. A provider failure is never a negative result. Offline URLhaus records can still be historical evidence.
- Counts must state what they count: unique indicators, distinct indicators with at least one positive result, or provider/lookup outcomes. Do not count duplicate provider hits as separate unique indicators.
- Keep request budgets, response-size caps, timeouts, and bounded file/report reads. If changing a limit or scheduling policy, explain the trade-off and add deterministic tests.

## Rust quality and testing
- Prefer clear, idiomatic Rust over clever abstractions. Use `Result` for fallible operations, `Option` for absent values, and enums when they make states explicit. Avoid panics on user input, files, network responses, and deserialized data.
- Keep provider HTTP/JSON details inside provider adapters and normalize results at the boundary.
- Automated tests must be deterministic and must not depend on live third-party APIs. Use fixtures or mocked/local HTTP responses for provider behavior.
- Keep private unit tests beside their implementation; use `tests/` for public or multi-component integration behavior. Prefer observable rendering/layout decisions over brittle full-screen snapshots.
- Add regression tests for bug fixes, failure cases, malformed input, compatibility, limits, and deduplication where relevant.
- Do not fabricate live API results. State clearly when live API behavior was not tested.

## Verification
Run the checks relevant to the change. For a normal code change, run:

```bash
cargo fmt --check
cargo check --all-targets
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo doc --no-deps
 git diff --check
```

Report only commands actually run and their real outcomes. Separate regressions from pre-existing/environmental failures. Review `git status --short` and the final diff. Do not commit.

## Documentation
- Review `README.md` whenever user-visible behavior, capabilities, configuration, limits, or project structure change.
- Review and update `AGENTS.md` where appropriate whenever architecture, module locations, development workflow, or engineering conventions change.
- Refresh README screenshots when a meaningful UI change warrants new captures. Capture to a temporary path, inspect the actual image and dimensions, then replace the documentation asset; verify every README image path before finishing.
Update `README.md` only when behavior, setup, supported providers, limits, or user-facing instructions change. Keep documentation factual and aligned with implementation. Do not document unimplemented future features.

## Final response format
Keep the handoff concise:
1. What changed and why.
2. Tests/checks actually run and results.
3. Remaining risks or unverified behavior.
4. A brief beginner-friendly explanation of the main concept(s).

Do not repeat the entire plan or generate a lengthy architecture essay unless requested.
