# CyberFeed

CyberFeed is a Rust-based terminal cybersecurity intelligence CLI that collects and displays data from free threat-intelligence sources.

The project is built as a learning project while exploring Rust, APIs, JSON deserialization, HTTP requests, and terminal-based applications.

## Features

### Cloudflare Radar

Displays live Layer 7 attack telemetry:

- Top attack origin countries
- Top target countries
- Top origin → target attack pairs
- Configurable refresh intervals
- Percentage-based attack visualization

### MalwareBazaar

Displays recent malware samples:

- File name
- File type
- Origin country
- First seen time
- SHA-256 hash
- Malware signature when available

## Requirements

- Rust and Cargo
- A Cloudflare API Token with access to Cloudflare Radar
- A MalwareBazaar API Auth-Key

## 🚀 Setup & API Configuration

### 1. Clone the project

```bash
git clone git@github.com:Reon-1/Cyberfeed.git
cd Cyberfeed
```

### 2. Configure Environment Variables

Copy the provided template file to create your local `.env` file.

**Linux / macOS / Git Bash:**

```bash
cp .env.example .env
```

**Windows (Command Prompt):**

```cmd
copy .env.example .env
```

**Windows (PowerShell):**

```powershell
Copy-Item .env.example .env
```

### 3. Add Your API Credentials

Open the newly created `.env` file and add your API credentials:

```ini
CLOUDFLARE_API_TOKEN=your_cloudflare_api_token
MALWAREBAZAAR_AUTH_KEY=your_malwarebazaar_auth_key
```

#### Cloudflare

Create an API Token through your Cloudflare Dashboard with the required permissions to access Cloudflare Radar data.

#### MalwareBazaar

Create an API Auth-Key through MalwareBazaar and add it to the `MALWAREBAZAAR_AUTH_KEY` variable.

> **Never commit your `.env` file or expose your API credentials publicly.**

### 4. Build and Run

Make sure Rust is installed, then launch CyberFeed:

```bash
cargo run
```

## Usage

After launching CyberFeed, the main menu provides access to the available threat-intelligence feeds:

```text
[1] Cloudflare Radar
[2] MalwareBazaar
[0] Exit
```

### Cloudflare Radar

Choose a feed to view:

```text
[1] Top attack origins
[2] Top attack targets
[3] Top attack pairs
[0] Back
```

You can choose how frequently the live data refreshes:

- 5 seconds
- 10 seconds
- 30 seconds
- 1 minute
- 5 minutes

CyberFeed refreshes the selected feed multiple times before returning to the menu.

### MalwareBazaar

The MalwareBazaar feed displays recent malware samples returned by the API, including available metadata such as:

- File information
- Malware type
- Origin country
- First-seen timestamp
- SHA-256 hash
- Malware signature

## Project Structure

```text
Cyberfeed/
├── src/
│   ├── main.rs
│   ├── cloudflare.rs
│   └── malwarebazzar.rs
├── .env.example
├── Cargo.toml
└── README.md
```

## Data Sources

CyberFeed currently uses:

- [Cloudflare Radar](https://radar.cloudflare.com/)
- [MalwareBazaar](https://bazaar.abuse.ch/)

Both provide cybersecurity data through publicly accessible APIs.

## Project Status

CyberFeed is an ongoing learning project focused on building a terminal-based threat-intelligence platform in Rust.

The project will gradually integrate additional free cybersecurity data sources as development continues.

Potential future integrations include:

- URLhaus
- ThreatFox
- NVD
- CISA Known Exploited Vulnerabilities (KEV)

## Disclaimer

CyberFeed is intended for educational, research, and defensive cybersecurity purposes.

The data displayed by CyberFeed comes from external threat-intelligence providers and may be delayed, incomplete, or subject to changes in their APIs.

## License

This project is for educational, learning and research purposes.
