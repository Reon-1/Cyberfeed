# CyberFeed

CyberFeed is a Rust-based terminal cybersecurity intelligence CLI that collects and displays data from free threat-intelligence sources.

The project is being developed as a practical way to learn Rust through a real application, while working with HTTP APIs, JSON deserialization, error handling, data filtering, modular application design, and terminal-based user interfaces.

## Features

### Cloudflare Radar

Displays Layer 7 attack telemetry from Cloudflare Radar, including:

- Top attack origin countries
- Top target countries
- Top origin → target attack pairs
- Attack percentages
- Country flags and percentage visualizations
- Configurable data refresh intervals

### MalwareBazaar

Displays recent malware samples from MalwareBazaar, including available:

- File name
- File type
- Origin country
- First-seen timestamp
- SHA-256 hash
- Malware signature
- Optional country filtering

The application also indicates whether the feed is currently online or returned an error.

## Requirements

- Rust and Cargo
- A Cloudflare API token with access to Cloudflare Radar
- A MalwareBazaar API Auth-Key

## Setup

### 1. Clone the repository

```bash
git clone git@github.com:Reon-1/Cyberfeed.git
cd Cyberfeed
```

### 2. Configure environment variables

Copy the example environment file:

**Linux / macOS / Git Bash**

```bash
cp .env.example .env
```

**Windows Command Prompt**

```cmd
copy .env.example .env
```

**Windows PowerShell**

```powershell
Copy-Item .env.example .env
```

### 3. Add API credentials

Open `.env` and add your credentials:

```ini
CLOUDFLARE_API_TOKEN=your_cloudflare_api_token
MALWAREBAZAAR_AUTH_KEY=your_malwarebazaar_auth_key
```

#### Cloudflare

Create an API token through your Cloudflare Dashboard with the permissions required to access Cloudflare Radar data.

#### MalwareBazaar

Obtain an API Auth-Key through MalwareBazaar and add it to the `MALWAREBAZAAR_AUTH_KEY` variable.

> **Never commit your `.env` file or expose your API credentials publicly.**

The `.env` file should remain local and should not be committed to Git.

### 4. Build and run

With Rust installed, launch CyberFeed with:

```bash
cargo run
```

## Usage

After launching, CyberFeed presents the main menu:

```text
[1] Cloudflare Radar
[2] MalwareBazaar
[0] Exit
```

### Cloudflare Radar

The Cloudflare Radar menu provides:

```text
[1] Top attack origins
[2] Top attack targets
[3] Top attack pairs
[0] Back
```

For live feeds, you can select a refresh interval:

- 5 seconds
- 10 seconds
- 30 seconds
- 1 minute
- 5 minutes

CyberFeed refreshes the selected feed multiple times before returning to the menu.

### MalwareBazaar

The MalwareBazaar feed retrieves recent malware samples and displays available metadata such as:

- File information
- File type
- Origin country
- First-seen timestamp
- SHA-256 hash
- Malware signature

A country filter can also be used to narrow the displayed samples.

## Project Structure

```text
Cyberfeed/
│
├── src/
│   ├── main.rs
│   ├── cloudflare.rs
│   ├── malwarebazaar.rs
│   └── ui.rs
│
├── .env.example
├── Cargo.toml
├── Cargo.lock
└── README.md
```

### Module responsibilities

**`main.rs`**

Acts as the main entry point and coordinates the application flow, menus, configuration, and API client.

**`cloudflare.rs`**

Handles requests to the Cloudflare Radar API, deserializes the responses, processes attack telemetry, and prepares the data for display.

**`malwarebazaar.rs`**

Handles communication with the MalwareBazaar API, deserializes malware sample data, applies filtering, and prepares results for display.

**`ui.rs`**

Contains reusable terminal UI helpers such as menus, boxes, text formatting, input handling, screen clearing, and refresh-related display utilities.

## Data Sources

CyberFeed currently integrates:

- [Cloudflare Radar](https://radar.cloudflare.com/)
- [MalwareBazaar](https://bazaar.abuse.ch/)

These services provide cybersecurity and threat-intelligence data through their respective APIs.

## Project Status

CyberFeed is an ongoing learning project and an experimental terminal-based threat-intelligence platform written in Rust.

The project is intentionally being developed incrementally: new data sources and functionality are added as the application and the developer's understanding of Rust evolve.

Potential future integrations include:

- URLhaus
- ThreatFox
- NVD / CVE data
- CISA Known Exploited Vulnerabilities (KEV)

Future development may also include improvements to error handling, data organization, testing, configuration, and the terminal interface as the project grows.

## Learning Goals

CyberFeed is also being used to explore practical Rust development concepts, including:

- Rust modules and project organization
- Structs and enums
- `Option` and `Result`
- Ownership and borrowing
- Collections such as `Vec`
- Iterators and filtering
- HTTP requests with `reqwest`
- JSON deserialization with `serde`
- Environment variables and configuration
- Error handling
- Terminal application design
- Git and incremental software development

The goal is not simply to build a working CLI, but to understand how the pieces of a real Rust application fit together.

## Disclaimer

CyberFeed is intended for educational, research, and defensive cybersecurity purposes.

The data displayed by CyberFeed comes from external threat-intelligence providers and may be delayed, incomplete, unavailable, or subject to changes in their APIs.

CyberFeed does not guarantee the accuracy or completeness of information provided by external sources.

## License

This project is currently intended for educational, learning, and research purposes.
