# CyberFeed

CyberFeed is a Rust-based terminal cybersecurity intelligence CLI built as a practical Rust learning project.

It collects information from free public threat-intelligence sources, analyzes local evidence such as files, extracts security indicators, and uses available intelligence sources to help investigate suspicious activity from the terminal.

The project started as a simple threat-intelligence feed viewer and is gradually evolving into a lightweight, local-first defensive investigation tool.

> **CyberFeed is a learning project.**
>
> The goal is not only to make the tool work, but to understand how a real Rust application is designed, structured, and developed incrementally.

---

## What CyberFeed Is Becoming

The long-term goal is to make CyberFeed useful when investigating something suspicious on a local system.

The general workflow is:

```text
Collect evidence
      ↓
Extract indicators
      ↓
Enrich indicators with threat intelligence
      ↓
Correlate information
      ↓
Understand what happened
```

A current file investigation can follow this process:

```text
Suspicious file
      ↓
Inspect file
      ↓
Calculate SHA-256
      ↓
Check file hash
      ↓
Extract indicators
      ↓
Create Indicator objects
      ↓
Store indicators in an Investigation
      ↓
Query supported threat-intelligence sources
      ↓
Display results
```

The architecture is being developed incrementally rather than attempting to build a complete security platform all at once.

---

## Current Features

### Cloudflare Radar

CyberFeed can retrieve and display Layer 7 attack telemetry from Cloudflare Radar, including:

- Top attack origins
- Top attack targets
- Top origin → target attack pairs
- Attack percentages
- Country flags
- Configurable refresh intervals

Cloudflare Radar currently serves primarily as a **threat-intelligence data source** within CyberFeed.

### MalwareBazaar

CyberFeed can retrieve recent malware samples from MalwareBazaar, including:

- File name
- File type
- Origin country
- First-seen time
- SHA-256 hash
- Malware signature
- Optional country filtering

CyberFeed can also perform a specific SHA-256 lookup.

A known malware hash can be converted into CyberFeed's common `Indicator` model, allowing threat-intelligence results to become part of an investigation.

### Local File Investigation

CyberFeed can inspect a local file and collect basic evidence such as:

- File name
- File size
- SHA-256 hash

The file is read as data for inspection and hashing. **CyberFeed does not execute the file.**

CyberFeed can then:

1. Calculate the file's SHA-256.
2. Check the file hash against MalwareBazaar.
3. Extract supported indicators from readable file content.
4. Store extracted indicators in the current investigation.
5. Enrich supported indicators using connected threat-intelligence sources.

### Indicator Extraction

CyberFeed can currently recognize three indicator types:

```text
Hash
IP
Domain
```

For example:

```text
abc123...       → Hash

192.168.1.10    → IP

example.com     → Domain
```

Extracted indicators are converted into CyberFeed's common `Indicator` model.

Not every indicator type currently has a connected intelligence source. Hashes can be investigated through MalwareBazaar, while IP and domain enrichment is planned for future integrations.

### Indicators

CyberFeed uses a common internal `Indicator` model to represent pieces of security-relevant evidence.

An indicator contains:

```text
Value
+
Indicator Type
```

For example:

```text
abc123...       → Hash
192.168.1.10    → IP
example.com     → Domain
```

This common representation allows different data sources and investigation features to work with the same basic evidence model.

### Investigations

CyberFeed can organize collected indicators into an investigation.

An investigation can contain multiple indicators gathered from local evidence and other sources.

For example:

```text
Investigation
├── Hash
├── Hash
├── IP
├── IP
├── Domain
└── Hash
```

The current investigation is stored in memory for the running session.

The investigation system is currently the foundation for future correlation and enrichment features rather than a finished investigation engine.

---

## Example Investigation

A simple text file containing suspicious indicators can be investigated by CyberFeed.

For example:

```text
Suspicious file
      ↓
Calculate file SHA-256
      ↓
Check file hash
      ↓
Extract hashes, IPs, and domains
      ↓
Store indicators
      ↓
Look up supported hashes
      ↓
Display threat-intelligence results
```

This allows a single local file to become the starting point for a larger investigation.

For example, a file may contain:

```text
Hash
87.106.48.217
example.com
```

CyberFeed represents these as different indicator types rather than treating every value as the same kind of data.

---

## Project Architecture

CyberFeed is separated into modules based on responsibility.

```text
CyberFeed
│
├── main.rs
│   └── Application entry point
│
├── app.rs
│   └── Application flow and coordination
│
├── file.rs
│   └── Local file inspection, hashing, and extraction
│
├── indicator.rs
│   └── Common indicator model
│
├── investigation.rs
│   └── Investigation and collected evidence
│
├── cloudflare.rs
│   └── Cloudflare Radar integration
│
├── malwarebazaar.rs
│   └── MalwareBazaar integration
│
└── ui.rs
    └── Reusable terminal UI helpers
```

The modules deliberately have different responsibilities.

### `main.rs`

The entry point of the application.

It initializes the application and required configuration before handing control to the application layer.

### `app.rs`

Coordinates the application.

It handles the user-facing application flow and connects the different parts of CyberFeed together.

### `file.rs`

Handles local file inspection.

It is responsible for collecting basic file information, calculating SHA-256 hashes, and extracting supported indicators from readable file content.

### `indicator.rs`

Defines the common indicator model used throughout CyberFeed.

Currently supported types are:

```rust
Hash
IP
Domain
```

### `investigation.rs`

Represents an investigation and stores indicators collected during that investigation.

It provides the internal place where evidence gathered during a session can be organized.

### `cloudflare.rs`

Handles Cloudflare Radar API requests, response structures, and attack telemetry.

### `malwarebazaar.rs`

Handles MalwareBazaar API requests, malware sample data, and SHA-256 hash lookups.

### `ui.rs`

Contains reusable terminal UI components used to keep the application's interface consistent.

---

## Data Flow

The current investigation architecture can be simplified to:

```text
                    CyberFeed
                       │
                       ▼
                     app.rs
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
          file.rs          threat sources
             │             ┌──────┴──────┐
             ▼             ▼             ▼
         Indicators   MalwareBazaar  Cloudflare
             │
             ▼
     investigation.rs
             │
             ▼
       Investigation
```

The important idea is that the investigation system does not need to know how every external source works.

For example:

```text
file.rs
   ↓
Indicator
   ↓
Investigation
   ↓
malwarebazaar.rs
```

Each module has its own responsibility.

---

## Data Sources

### Currently Used

- [Cloudflare Radar](https://radar.cloudflare.com/)
- [MalwareBazaar](https://bazaar.abuse.ch/)

### Potential Future Sources

The project may eventually integrate additional free public sources such as:

- URLhaus
- ThreatFox
- NVD / CVE data
- CISA Known Exploited Vulnerabilities (KEV)

Future integrations will be added only as the investigation architecture develops.

---

## Learning Goals

CyberFeed is primarily a **Rust learning project built around a real application**.

Instead of learning Rust only through isolated exercises, the project is being used to understand how the language is applied in a larger program.

Areas currently being learned include:

- Rust modules
- Structs and enums
- Ownership and borrowing
- References
- `Option` and `Result`
- `Vec` and other collections
- Iterators and filtering
- Generics
- HTTP requests
- JSON deserialization
- Error handling
- Environment variables
- File I/O
- Hashing
- Terminal application development
- Application architecture
- Git and incremental development

A major goal is understanding **why the code is structured the way it is**, not simply getting code that works.

---

## Development Philosophy

CyberFeed is being developed incrementally.

The project deliberately avoids trying to implement every cybersecurity feature at once.

The general approach is:

```text
Build something small
      ↓
Understand it
      ↓
Test it
      ↓
Improve the architecture
      ↓
Add the next capability
```

The project is also intended to document the process of learning Rust through a real-world application, including the parts that are difficult, confusing, or require architectural changes.

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

Never commit your `.env` file or expose API credentials.

Keep secrets in environment variables and make sure `.env` is included in `.gitignore`.

---

## Project Status

CyberFeed is an **active work in progress**.

The project has now moved beyond being only a threat-intelligence feed viewer. It has the foundation of a local defensive investigation workflow:

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

The current investigation system is intentionally small.

It can already:

- Inspect local files
- Calculate file SHA-256 hashes
- Extract hashes, IPs, and domains from readable file content
- Store indicators in an investigation
- Check supported hashes against MalwareBazaar
- Display enrichment results in the terminal

Many parts of the long-term investigation workflow are not implemented yet.

The project will continue to evolve one feature at a time while the underlying Rust concepts are learned and understood.

---

## Disclaimer

CyberFeed is intended for educational, research, and defensive cybersecurity purposes.

Threat-intelligence information is provided by external services and may be incomplete, inaccurate, delayed, unavailable, or subject to change.

CyberFeed should not be treated as a definitive source of security conclusions. Any investigation or security decision should be validated using appropriate additional evidence and trusted sources.
