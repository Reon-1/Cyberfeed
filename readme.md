# CyberFeed

CyberFeed is a Rust-based terminal cybersecurity intelligence CLI built as a practical Rust learning project.

It collects information from free public threat-intelligence sources, analyzes local evidence such as files, and provides a foundation for investigating suspicious activity from the terminal.

The project started as a simple threat-intelligence feed viewer and is gradually evolving into a lightweight, local-first defensive investigation tool.

> **CyberFeed is a learning project.**
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

For example, a future investigation could start with a suspicious file:

```text
Suspicious file
      ↓
Calculate SHA-256
      ↓
Create an Indicator
      ↓
Query threat-intelligence sources
      ↓
Collect results
      ↓
Build an investigation
```

This architecture is being developed incrementally rather than attempting to build a complete security platform all at once.

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

CyberFeed can also use a SHA-256 hash to perform a specific MalwareBazaar lookup.

Malware hashes can be converted into CyberFeed's common `Indicator` model, allowing threat-intelligence data to become part of an investigation.

### Local File Investigation

CyberFeed can inspect a local file and collect basic evidence such as:

- File name
- File size
- SHA-256 hash

The file is read as data for hashing; CyberFeed does not execute the file.

The resulting SHA-256 can then be represented as a `Hash` indicator and investigated through supported threat-intelligence sources.

### Indicators

CyberFeed uses a common internal `Indicator` model to represent pieces of security-relevant evidence.

Currently supported indicator types are:

```text
Hash
IP
Domain
```

An indicator consists of:

```text
Value
+
Indicator Type
```

For example:

```text
abc123...       → Hash
192.168.1.10   → IP
example.com    → Domain
```

This common model is the foundation for the project's investigation and correlation architecture.

### Investigations

CyberFeed is beginning to organize collected indicators into an investigation.

An investigation can contain multiple indicators gathered from different sources.

For example:

```text
Investigation
├── Hash
├── IP
├── Domain
└── Hash
```

The investigation system is currently a foundation for future correlation and enrichment features rather than a finished investigation engine.

---

## Project Architecture

CyberFeed is intentionally separated into modules based on responsibility.

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
│   └── Local file inspection and hashing
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

The modules have deliberately different responsibilities.

### `main.rs`

The entry point of the application.

It initializes the application and its required configuration before handing control to the application layer.

### `app.rs`

Coordinates the application.

It handles the user-facing application flow and connects the different parts of CyberFeed together.

### `file.rs`

Handles local file inspection.

It is responsible for collecting basic file information and calculating SHA-256 hashes.

### `indicator.rs`

Defines the common indicator model used throughout CyberFeed.

Currently:

```rust
Hash
IP
Domain
```

### `investigation.rs`

Represents an investigation and stores indicators collected during that investigation.

### `cloudflare.rs`

Handles Cloudflare Radar API requests, response structures, and attack telemetry.

### `malwarebazaar.rs`

Handles MalwareBazaar API requests, malware sample data, and hash lookups.

### `ui.rs`

Contains reusable terminal UI components used to keep the application's interface consistent.

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

The project is currently transitioning from a threat-intelligence feed viewer into the foundation of a small defensive investigation tool.

The current architectural focus is:

```text
Local Evidence
      ↓
Indicators
      ↓
Investigation
      ↓
Threat Intelligence
      ↓
Enrichment & Correlation
```

Many parts of the long-term investigation workflow are not implemented yet.

The project will continue to evolve one feature at a time while the underlying Rust concepts are learned and understood.

---

## Disclaimer

CyberFeed is intended for educational, research, and defensive cybersecurity purposes.

Threat-intelligence information is provided by external services and may be incomplete, inaccurate, delayed, unavailable, or subject to change.

CyberFeed should not be treated as a definitive source of security conclusions. Any investigation or security decision should be validated using appropriate additional evidence and trusted sources.
