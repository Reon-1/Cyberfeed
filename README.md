# CyberFeed

CyberFeed is a local-first Rust terminal tool for examining suspicious files, checking indicators against free public threat-intelligence sources, and keeping investigation evidence in readable reports.

It helps you collect and review evidence. It is not antivirus software and does not decide that a file is safe or malicious. CyberFeed never executes inspected files or visits URLs found in evidence.

## What you can do

- **Check a file:** calculate its SHA-256 locally, extract supported hashes, IP addresses, domains, and HTTP/HTTPS URLs from readable content, and optionally check supported values with configured providers. The file itself is not uploaded.
- **Search an indicator:** check a hash, IP address, domain, or full HTTP/HTTPS URL and review provider-specific evidence.
- **Compare indicator lists:** in **Current Session**, add two or more line-oriented text files for a local overlap preview, then pivot a selected value into Value Search. Use one indicator per line; blank lines and lines beginning with `#` are ignored. Each file is limited to 8 MiB, lines to 4,096 bytes, the import to 100,000 candidates, and URLs to 1,000. The preview retains source lines while open; it does not upload files.
- **Search a log:** extract indicators from local UTF-8 text or JSONL while preserving line and context provenance. Log hunting is local-only.
- **Save and revisit evidence:** store file and session investigations as JSON/Markdown pairs, browse them offline, compare reports, and export eligible indicators as STIX 2.1.
- **Use local tools:** try the offline demo, inspect setup, or batch-check up to 100 files without provider lookups.
- **Browse public feeds:** view MalwareBazaar samples and Cloudflare Radar attack trends. Cloudflare country rows show a flag when the ISO code is recognized, with the country name and code retained as text.

Provider results describe the queried value, not necessarily the file it came from. `NOT FOUND` means that source returned no record at lookup time; it does not establish safety. Errors, unsupported checks, missing credentials, and skipped requests remain distinct from a no-match.

## Quick start

Install stable Rust with Cargo, then run from a checkout:

```sh
git clone https://github.com/Reon-1/Cyberfeed.git
cd Cyberfeed
cargo run
```

No credentials are needed for local file inspection, logs, the offline demo, or saved-report browsing. The main menu offers file investigation, the current session, log search, saved reports, and **More Tools**. Navigate with arrows or `j`/`k`, choose with Enter or a number, and use Esc to go back. In Saved Reports, `N`/`P` changes pages.

## Provider setup

Threat lookups and live feeds are optional. Configure credentials in **More Tools → Configure Providers**, or provide environment variables:

| Variable | Used by |
| --- | --- |
| `ABUSECH_AUTH_KEY` | MalwareBazaar, ThreatFox, and URLhaus |
| `CLOUDFLARE_API_TOKEN` | Cloudflare Radar |

Credential entry is hidden. CyberFeed reports whether a credential is present but does not authenticate it during setup. The `.env` file stores saved credentials as plaintext; keep it private. Environment variables take precedence over `.env`; restart CyberFeed after changing credentials. `.env.example` contains placeholders only.

CyberFeed routes only supported indicator types to each provider. URLhaus checks exact URLs, IP/domain hosts, and MD5/SHA-256 payload hashes; MalwareBazaar and ThreatFox have different supported types. Provider coverage and availability vary. No paid account is required by CyberFeed, though providers may apply their own access limits.

## Example workflows

1. Choose **Check a File**, enter a local path, review the file hash and extracted indicators, then open recorded provider details or save the report.
2. Choose **Current Session → Check a Value** to examine a hash, address, domain, or full web address. CyberFeed shows provider coverage first; press `D` for technical evidence, then `0` to continue to the optional individual-check save prompt. Completed checks can also be saved together as a session report.
3. Choose **Current Session → Compare Indicator Lists** to compare local lists and choose an indicator for a fresh provider lookup. This workflow does not persist the import queue or source-line provenance in a report; save the resulting value checks as ordinary session evidence.
4. Choose **Search Logs** and enter a local text or JSONL path. The scan is bounded to 64 MiB total, 16 KiB per line, 1,000 unique indicators, and 10,000 occurrences. Results include source line and context; they do not trigger provider requests.
5. Open **Saved Reports** to review file and session reports offline. File comparison requires matching file identity to compare the same contents; missing or failed provider coverage is inconclusive. A saved report can export eligible indicators as STIX 2.1.

File investigation performs local extraction before bounded provider lookups. The inspection and sequential provider checks share a 60-second analysis budget; each provider request is also capped at 15 seconds. If the budget expires, completed evidence is retained and unfinished checks are marked as timed out or skipped. Cloudflare Radar displays a request-in-progress state and each complete endpoint response when available; the endpoint does not stream individual rows.

## Reports and privacy

Reports are written under `reports/` in the current working directory. File reports and session reports remain separate: a file report records one file investigation, while a session report collects completed file and individual-value checks. Reports can contain sensitive paths, hashes, and indicators, so protect the directory. Report loading is bounded and reports are read locally; malformed or unsupported files are surfaced as unavailable rather than treated as findings.

## Project map

- `src/app/` — menus and investigation workflows.
- `src/tui/` — Ratatui rendering, shared styles, components, and Crossterm terminal lifecycle.
- `src/file.rs`, `src/indicator.rs`, `src/investigation.rs` — local inspection and evidence models.
- `src/providers/` — provider-specific HTTP requests and response parsing.
- `src/report/` — report models, rendering, persistence, and STIX export.

## Development

Automated tests use local data and do not require credentials or live providers. Run the project checks with:

```sh
cargo fmt --check
cargo check --all-targets
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo doc --no-deps
git diff --check
```

The GitHub Actions workflow runs formatting, compilation, tests, and Clippy on stable Rust for Linux, macOS, and Windows. Only platforms actually exercised should be considered verified.
