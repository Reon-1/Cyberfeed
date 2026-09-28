# CyberFeed

CyberFeed is a Rust-based terminal cybersecurity investigation tool built as a practical Rust learning project.

It collects local evidence, extracts security indicators, and enriches supported indicators with free public threat-intelligence sources. The project is designed to gradually evolve from a small terminal tool into a lightweight, local-first defensive investigation workflow.

> **CyberFeed is a learning project.**
>
> The goal is not only to make the tool work, but to understand how a real Rust application is structured, tested, and extended incrementally.

---

## What CyberFeed Is Becoming

The long-term idea is simple:

> **Give CyberFeed something suspicious, and let it gather the surrounding evidence.**

The intended investigation flow is:

```text
Local evidence
      ↓
Collect evidence
      ↓
Extract indicators
      ↓
Enrich indicators with threat intelligence
      ↓
Correlate evidence
      ↓
Help the investigator understand what happened
```

The current implementation is intentionally much smaller than that vision. Today, a local file can act as the starting point for an investigation:

```text
Suspicious file
      ↓
Inspect file
      ↓
Calculate SHA-256
      ↓
Extract Hash / IP / Domain indicators
      ↓
Store indicators in an Investigation
      ↓
Query supported threat-intelligence sources
      ↓
Display the evidence and lookup results
```

The project is being developed one capability at a time rather than attempting to build a complete security platform up front.

---

## Current Capabilities

### Local File Investigation

CyberFeed can inspect a local file and collect basic evidence such as:

- file name
- file size
- SHA-256 hash
- supported indicators found in readable content

The file is read as data for inspection and hashing. **CyberFeed does not execute the file.**

A file investigation can currently:

1. Calculate the file's SHA-256.
2. Check the hash against MalwareBazaar.
3. Extract supported Hash, IP, and Domain indicators from readable content.
4. Store those indicators in the current investigation.
5. Display enrichment results for supported indicator types.

### Indicators

CyberFeed uses a common `Indicator` model for security-relevant values.

Each indicator contains a value and a type:

```text
Indicator
├── value
└── indicator_type
```

Current indicator types are:

```text
Hash
IP
Domain
```

For example:

```text
44d88612...      → Hash
185.220.101.1   → IP
example.com     → Domain
```

This common model allows evidence from different sources to move through the investigation system without every source needing its own representation.

Not every indicator type currently has a connected enrichment source. Hash lookups are currently supported through MalwareBazaar; additional IP/domain sources are future work.

### MalwareBazaar

CyberFeed integrates with [MalwareBazaar](https://bazaar.abuse.ch/) for malware-sample intelligence and SHA-256 lookups.

The recent-sample feed can display information such as:

- file name
- file type
- origin country
- first-seen time
- SHA-256 hash
- malware signature
- optional country filtering

For a specific hash, CyberFeed now keeps the source result explicit:

```text
FOUND
NOT FOUND
INVALID
API ERROR
```

A `NOT FOUND` result means that **MalwareBazaar did not return a record for the queried hash**. It is not treated as proof that a file is safe or benign.

The lookup path also distinguishes request, HTTP, and JSON/response errors from a legitimate `NOT FOUND` result.

### Cloudflare Radar

CyberFeed also integrates with [Cloudflare Radar](https://radar.cloudflare.com/) for Layer 7 attack telemetry, including:

- top attack origins
- top attack targets
- top origin → target attack pairs
- attack percentages
- country flags
- configurable refresh intervals

Cloudflare Radar currently functions primarily as a threat-intelligence data source rather than as local evidence from an investigation.

### Investigations

CyberFeed groups collected indicators into an `Investigation`.

Conceptually:

```text
Investigation
├── Hash
├── Hash
├── IP
├── IP
├── Domain
└── Hash
```

The current investigation exists **in memory for the running session**. Persistent investigation history is not implemented yet.

The investigation model is currently the foundation for future enrichment, correlation, and evidence-management features.

---

## Example Investigation

A simple text file can be used as a safe test artifact.

For example, a file might contain:

```text
Suspicious sample

44d88612fea8a8f36de82e1278abb02f
185.220.101.1
example.com
```

CyberFeed can process that file as:

```text
File
 │
 ├── SHA-256 of the file
 │
 ├── Hash indicator
 │
 ├── IP indicator
 │
 └── Domain indicator
```

The extracted values are stored using the common `Indicator` model and become part of the current investigation.

This test setup is deliberately simple and safe. It allows the investigation pipeline to be developed without executing live malware.

---

## Project Architecture

CyberFeed is divided into modules based on responsibility:

```text
CyberFeed
│
├── main.rs
│   └── Application entry point
│
├── app.rs
│   └── Application flow and orchestration
│
├── file.rs
│   └── Local file inspection, hashing, and indicator extraction
│
├── indicator.rs
│   └── Common indicator model and indicator classification
│
├── investigation.rs
│   └── Investigation state and collected evidence
│
├── cloudflare.rs
│   └── Cloudflare Radar integration
│
├── malwarebazaar.rs
│   └── MalwareBazaar integration and hash lookups
│
└── ui.rs
    └── Reusable terminal UI and formatting helpers
```

The separation is intentional:

- **`main.rs`** — starts the application and loads configuration.
- **`app.rs`** — coordinates menus, user actions, and the application flow.
- **`file.rs`** — handles local file inspection, hashing, and extraction of supported indicators.
- **`indicator.rs`** — defines the common indicator model.
- **`investigation.rs`** — stores and presents evidence collected during an investigation.
- **`cloudflare.rs`** — handles Cloudflare Radar requests and response data.
- **`malwarebazaar.rs`** — handles MalwareBazaar requests, response parsing, and hash lookup states.
- **`ui.rs`** — contains reusable terminal presentation helpers so screens follow a consistent layout.

The goal is to keep presentation, application flow, investigation state, and source-specific API logic separated so future features can be added without repeatedly rewriting existing functionality.

---

## Data Flow

The current architecture can be simplified to:

```text
                         CyberFeed
                             │
                             ▼
                           app.rs
                             │
                 ┌───────────┴───────────┐
                 ▼                       ▼
              file.rs              threat sources
                 │                 ┌──────┴──────┐
                 ▼                 ▼             ▼
             Indicators      MalwareBazaar  Cloudflare
                 │
                 ▼
        investigation.rs
                 │
                 ▼
           Investigation
```

The important design idea is that the investigation system does not need to know how every external source works.

For example:

```text
file.rs
  ↓
Indicator
  ↓
Investigation
  ↓
source-specific enrichment
```

The source module handles the external API details while the investigation system works with CyberFeed's common evidence model.

---

## Data Sources

### Currently Integrated

- [Cloudflare Radar](https://radar.cloudflare.com/)
- [MalwareBazaar](https://bazaar.abuse.ch/)

### Potential Future Sources

The project may eventually integrate additional free public sources such as:

- [URLhaus](https://urlhaus.abuse.ch/)
- [ThreatFox](https://threatfox.abuse.ch/)
- [NVD](https://nvd.nist.gov/)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

These are roadmap ideas, not current CyberFeed capabilities.

---

## Roadmap Direction

The long-term project may expand from file-centered investigations into broader local evidence and correlation.

Possible future capabilities include:

```text
Local evidence
├── files
├── processes
├── logs
├── network activity
└── other system artifacts
```

combined with:

```text
Threat intelligence
├── hashes
├── IPs
├── domains / URLs
├── CVEs
└── other security-relevant data
```

A future investigation could eventually connect those pieces into relationships such as:

```text
Process
  │
  ├── launched → File
  │                │
  │                └── SHA-256
  │                       │
  │                       └── Threat intelligence
  │
  └── connected → IP
                       │
                       └── Threat intelligence
```

Persistence, databases, richer correlation, and evidence graphs are future possibilities. They are intentionally not part of the current implementation.

---

## Learning Goals

CyberFeed is primarily a **Rust learning project built around a real application**.

Instead of learning Rust only through isolated exercises, the project is used to understand how Rust works inside a growing program.

Current learning areas include:

- modules and visibility
- structs and enums
- ownership and borrowing
- references
- `Option` and `Result`
- collections such as `Vec`
- iterators and filtering
- generics
- HTTP requests
- JSON deserialization
- error handling
- environment variables
- file I/O
- hashing
- terminal application development
- application architecture
- Git and incremental development

A major goal is understanding **why the code is structured the way it is**, not simply getting code that compiles.

---

## Development Philosophy

CyberFeed is intentionally developed incrementally:

```text
Build something small
        ↓
Understand it
        ↓
Test it
        ↓
Fix and improve it
        ↓
Protect existing behavior
        ↓
Add the next capability
```

The project is not trying to become a complete security platform immediately. Each new capability should have a clear reason to exist and should fit the existing architecture without unnecessarily breaking older functionality.

---

## Requirements

- Rust
- Cargo
- Cloudflare Radar API token
- MalwareBazaar API key

---

## Setup

Clone the repository and create a `.env` file based on `.env.example`.

```env
CLOUDFLARE_API_TOKEN=your_cloudflare_api_token
MALWAREBAZAAR_AUTH_KEY=your_malwarebazaar_auth_key
```

Then run:

```bash
cargo run
```

### Security

Never commit `.env` or expose API credentials.

Keep secrets in environment variables and make sure `.env` is included in `.gitignore`.

---

## Testing

Before committing changes, the project should be checked with:

```bash
cargo fmt
cargo test
cargo build
cargo clippy --all-targets --all-features -- -D warnings
```

The project uses focused tests for stable behavior, including API response parsing and result-state handling.

Manual testing is also important for terminal input and UI behavior because some interactive behavior cannot be fully captured by unit tests.

---

## Project Status

**Active work in progress.**

CyberFeed has moved beyond a simple threat-intelligence feed viewer and now has the foundation of a local defensive investigation workflow:

```text
Local Evidence
      ↓
File Inspection
      ↓
Indicators
      ↓
Investigation
      ↓
Threat Intelligence
      ↓
Enrichment
      ↓
Future Correlation
```

The current implementation can already:

- inspect local files
- calculate file SHA-256 hashes
- extract hashes, IPs, and domains from readable file content
- store indicators in an investigation
- investigate supported hashes through MalwareBazaar
- display threat-intelligence results in the terminal
- browse Cloudflare Radar telemetry

What is not implemented yet includes persistent investigation history, broader local system telemetry, multiple additional enrichment sources, and richer correlation.

The project will continue to evolve one feature at a time while the underlying Rust concepts are learned and understood.

---

## Disclaimer

CyberFeed is intended for educational, research, and defensive cybersecurity purposes.

Threat-intelligence information is provided by external services and may be incomplete, inaccurate, delayed, unavailable, or subject to change.

CyberFeed should not be treated as a definitive source of security conclusions. Investigation results should be interpreted in context and, where appropriate, validated using additional evidence and trusted sources.
