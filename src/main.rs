mod app;
mod config;
mod file;
mod http_response;
mod indicator;
mod investigation;
mod log_hunt;
mod providers;
mod report;
mod tui;

use dotenvy::dotenv;
use reqwest::blocking::Client;
use std::time::Duration;

fn main() {
    let _ = dotenv();
    let config = config::Config::from_lookup(|key| std::env::var(key).ok());

    let client = match Client::builder()
        .user_agent(concat!("Cyberfeed/", env!("CARGO_PKG_VERSION")))
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            eprintln!("Could not initialize the HTTP client: {error}");
            std::process::exit(1);
        }
    };

    app::run(&client, &config);
}
