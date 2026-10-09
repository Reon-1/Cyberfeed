mod app;
mod cloudflare;
mod config;
mod file;
mod indicator;
mod investigation;
mod malwarebazaar;
mod report;
mod ui;

use dotenvy::dotenv;
use reqwest::blocking::Client;
use std::time::Duration;

fn main() {
    let _ = dotenv();
    let config = config::Config::from_lookup(|key| std::env::var(key).ok());

    let client = match Client::builder().timeout(Duration::from_secs(30)).build() {
        Ok(client) => client,
        Err(error) => {
            eprintln!("Could not initialize the HTTP client: {error}");
            std::process::exit(1);
        }
    };

    app::run(&client, &config);
}
