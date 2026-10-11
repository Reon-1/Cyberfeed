# CyberFeed

CyberFeed is a Rust-based defensive threat-intelligence investigation CLI. It starts with a local file or an indicator, gathers related evidence from local inspection and selected public intelligence sources, and keeps the results available for review without treating them as an automatic malware verdict.

## Screenshots

**Main menu**

![CyberFeed main menu](docs/screenshots/main-menu.png)

**File input**

![Local file input prompt with the file handling notice](docs/screenshots/file-input.png)

**Completed investigation**

![Completed file investigation overview](docs/screenshots/investigation-overview.png)

**Indicator evidence**

![Detailed provider evidence for an indicator](docs/screenshots/indicator-details.png)

**Saved reports**

![Saved reports browser](docs/screenshots/saved-reports.png)

*The report browser reads saved JSON reports locally and can compare two reports offline.*

## Features

- Inspect a local file as data, calculate its SHA-256 with streamed reads, and extract unique hashes, IP addresses, and domains from readable text.
- Query MalwareBazaar for hashes and ThreatFox for supported hashes, IP addresses, and domains. Duplicate indicators do not cause duplicate requests.
- Browse MalwareBazaar recent-sample feeds with optional country filtering, or view Cloudflare Radar Layer 7 attack telemetry.
- Follow live file-lookup progress, review provider outcomes, page through indicators, and open detailed recorded evidence.
- Save paired Markdown and JSON file-investigation reports, browse reports, and compare saved investigations offline when they refer to the same file SHA-256.

## How an investigation works

1. Choose **Check a File** and enter, paste, or drag in a path. CyberFeed reads the file locally, hashes it, and scans readable text for supported indicators; it never executes the file.
2. Review the original file hash separately from indicators extracted from its contents. When configured, the relevant provider receives the hash or supported indicator value for lookup; file contents are not uploaded.
3. Inspect provider outcomes and available match metadata, then optionally save the evidence as a report.

`NOT FOUND` means that a provider returned no record for that query; it is not proof of safety. Provider errors, unsupported values, missing configuration, and skipped lookups remain distinct outcomes. A match describes the queried indicator and does not by itself establish that the source file is malicious.

## Requirements and installation

Install Rust and Cargo with support for the Rust 2024 edition. From a checkout, build and start CyberFeed with:

```sh
git clone https://github.com/Reon-1/Cyberfeed.git
cd Cyberfeed
cargo run
```

No provider credentials are required for local inspection or offline report browsing.

## Configuration

CyberFeed reads optional credentials from environment variables or a local `.env` file. The repository's `.env.example` contains placeholders; keep real values in your private `.env`, which is ignored by Git.

| Variable | Provider |
| --- | --- |
| `ABUSECH_AUTH_KEY` | Shared by MalwareBazaar and ThreatFox |
| `CLOUDFLARE_API_TOKEN` | Cloudflare Radar, configured independently |

If a provider's credential is absent, its lookup is recorded as not configured. See the official [MalwareBazaar API](https://bazaar.abuse.ch/api/), [ThreatFox API](https://threatfox.abuse.ch/api/), and [Cloudflare Radar API](https://developers.cloudflare.com/radar/) documentation.

## Using the menus

- **Check a File** starts local inspection and provider lookups. Use the displayed number to open indicator evidence, `N`/`P` to change overview pages, `F` for the original file's hash result, and `0` to continue to the report-saving prompt.
- **Investigation** lets you add a hash, IP address, or domain and review evidence collected in the current session.
- **Threat Intelligence** opens the provider-specific feed and telemetry views.
- **Saved Reports** browses local report snapshots and offers **Compare Reports** when at least two valid reports are available.

## Reports, privacy, and limits

Choosing to save a file investigation writes a JSON and a Markdown report under `reports/` relative to the current working directory. Reports contain the file's name, size, SHA-256, extracted indicators, and recorded provider evidence. File evidence stays in the current session unless that file report is saved. Saved reports can be browsed and compared offline; manually added session indicators are not automatically included in file reports. Reports can contain sensitive indicators and hashes, so keep them private.

The file itself is not sent to providers. Configured lookups send the original file SHA-256 and supported extracted indicator values to the relevant API. MalwareBazaar checks hashes; ThreatFox accepts MD5 and SHA-256 hashes, IP addresses, and domains (SHA-1 is unsupported there). MalwareBazaar and ThreatFox each have a ten-unique-lookup automatic cap per file; the original file hash uses one slot, duplicate queries are suppressed, and unqueried values are reported as skipped rather than not found. Local extraction is capped at 10,000 unique indicators. Provider availability and public-data coverage vary, and an API failure is not a no-match result.

## Project structure

- `src/app/` coordinates menus, file investigations, provider views, and saved-report navigation.
- `src/file.rs`, `src/indicator.rs`, and `src/investigation.rs` handle local inspection, classification, and collected evidence.
- `src/malwarebazaar.rs`, `src/threatfox.rs`, and `src/cloudflare.rs` own provider requests and response parsing.
- `src/report/` models, renders, and stores reports; `src/ui.rs` and `src/app/terminal.rs` provide terminal presentation and input.

## Development

```sh
cargo fmt --check
cargo check --all-targets
cargo test
cargo build
cargo clippy --all-targets --all-features -- -D warnings
git diff --check
```

Tests use deterministic local data and do not require credentials or live provider requests.
