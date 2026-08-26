## 🚀 Setup & API Configuration

This Rust CLI tool requires a Cloudflare API Token to pull live Layer 7 attack information. Follow these steps to configure it on your machine:

### 1. Clone the project
```bash
git clone git@github.com:Reon-1/Cyberfeed.git
cd Cyberfeed
```

### 2. Configure Environment Variables
Copy the provided template file to create your own local `.env` configuration file:
```bash
cp .env.example .env
```

### 3. Add Your Token
Open the newly created `.env` file in your text editor and change `your_cloudflare_api_token_here` to your real token:
```ini
CLOUDFLARE_API_TOKEN=your_actual_token_value
```
*(Note: You can generate an API Token with read access to Cloudflare Radar from your Cloudflare Dashboard).*

### 4. Build and Run
Make sure you have Rust installed, then launch the program:
```bash
cargo run
```
