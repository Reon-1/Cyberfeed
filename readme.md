# CyberFeed

CyberFeed is a Rust-based terminal cybersecurity intelligence CLI.

It collects threat-intelligence data from free public sources and presents it in a simple terminal interface. The project is also a practical way for me to learn Rust by building a real application instead of following isolated tutorials.

## Current Features

### Cloudflare Radar

Displays Layer 7 attack telemetry, including:

- Top attack origins
- Top attack targets
- Top origin → target attack pairs
- Attack percentages
- Country flags
- Configurable refresh intervals

### MalwareBazaar

Displays recent malware samples, including:

- File name
- File type
- Origin country
- First-seen time
- SHA-256 hash
- Malware signature
- Optional country filtering

CyberFeed also converts malware hashes into a common internal `Indicator` model, which is the beginning of the project's investigation architecture.

## Project Direction

CyberFeed is gradually moving beyond simply displaying threat-intelligence feeds.

The long-term goal is to build a lightweight defensive investigation tool that can:

```text
Collect evidence
      ↓
Extract indicators
      ↓
Enrich indicators with threat intelligence
      ↓
Correlate information
      ↓
Help investigate what happened
```

The project is being developed incrementally, one piece at a time.

## Data Sources

Currently:

- [Cloudflare Radar](https://radar.cloudflare.com/)
- [MalwareBazaar](https://bazaar.abuse.ch/)

Possible future sources include:

- URLhaus
- ThreatFox
- NVD / CVE data
- CISA KEV

## Project Structure

```text
Cyberfeed/
├── src/
│   ├── main.rs
│   ├── cloudflare.rs
│   ├── malwarebazaar.rs
│   ├── indicator.rs
│   └── ui.rs
│
├── .env.example
├── Cargo.toml
├── Cargo.lock
└── README.md
```

### Modules

**`main.rs`**
Application entry point and coordinator.

**`cloudflare.rs`**
Handles Cloudflare Radar requests and attack telemetry.

**`malwarebazaar.rs`**
Handles MalwareBazaar requests and malware sample data.

**`indicator.rs`**
Defines CyberFeed's common indicator model for hashes, IP addresses, and domains.

**`ui.rs`**
Contains reusable terminal UI helpers.

## Requirements

- Rust
- Cargo
- Cloudflare Radar API token
- MalwareBazaar API key

## Setup

Create a `.env` file based on `.env.example`:

```env
CLOUDFLARE_API_TOKEN=your_cloudflare_api_token
MALWAREBAZAAR_AUTH_KEY=your_malwarebazaar_auth_key
```

Then run:

```bash
cargo run
```

Never commit your `.env` file or expose your API credentials.

## Learning Goals

CyberFeed is primarily a Rust learning project.

Through the project, I am learning how to work with:

- Rust modules
- Structs and enums
- Ownership and borrowing
- `Option` and `Result`
- Collections such as `Vec`
- Iterators and filtering
- HTTP APIs
- JSON deserialization
- Error handling
- Environment variables
- Terminal applications
- Project architecture
- Git and incremental development

The goal is not just to make CyberFeed work, but to understand how the parts of a real Rust application fit together.

## Status

CyberFeed is an active work in progress.

The current focus is building the foundation for a small, local-first defensive investigation tool while continuing to learn Rust through practical development.

## Disclaimer

CyberFeed is intended for educational, research, and defensive cybersecurity purposes.

Threat-intelligence data comes from external providers and may be incomplete, delayed, unavailable, or change without notice.
