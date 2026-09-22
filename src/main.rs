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

fn main() {
    dotenv().ok();

    let client = Client::new();
    let cloudflare_token =
        env::var("CLOUDFLARE_API_TOKEN").expect("CLOUDFLARE_API_TOKEN is missing from .env");
    let malwarebazaar_auth_key =
        env::var("MALWAREBAZAAR_AUTH_KEY").expect("MALWAREBAZAAR_AUTH_KEY is missing from .env");

    app::run(&client, &cloudflare_token, &malwarebazaar_auth_key);
}
