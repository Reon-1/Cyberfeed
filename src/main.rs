mod app;
mod cloudflare;
mod file;
mod indicator;
mod investigation;
mod malwarebazaar;
mod ui;

use dotenvy::dotenv;
use reqwest::blocking::Client;
use std::env;
use std::time::Duration;

fn main() {
    dotenv().ok();

    let cloudflare_token = match env::var("CLOUDFLARE_API_TOKEN") {
        Ok(value) => value,
        Err(_) => {
            eprintln!("CLOUDFLARE_API_TOKEN is missing from the environment or .env file.");
            return;
        }
    };
    let malwarebazaar_auth_key = match env::var("MALWAREBAZAAR_AUTH_KEY") {
        Ok(value) => value,
        Err(_) => {
            eprintln!("MALWAREBAZAAR_AUTH_KEY is missing from the environment or .env file.");
            return;
        }
    };

    let client = match Client::builder().timeout(Duration::from_secs(30)).build() {
        Ok(client) => client,
        Err(error) => {
            eprintln!("Could not initialize the HTTP client: {error}");
            return;
        }
    };

    app::run(&client, &cloudflare_token, &malwarebazaar_auth_key);
}
