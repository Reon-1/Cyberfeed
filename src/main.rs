mod attack;
mod data;

use crate::attack::{Attack, Severity};
use crate::data::load_attacks;

use reqwest::blocking::Client;
use serde::Deserialize;
use std::io::{self, Write};

#[derive(Deserialize)]
struct OriginCountry {
    // Cloudflare uses camelCase, so we tell Serde which JSON field to use.
    #[serde(rename = "originCountryAlpha2")]
    origin_country_alpha2: String,

    #[serde(rename = "originCountryName")]
    origin_country_name: String,

    // Cloudflare sends this number as a String, so we convert it to f64.
    #[serde(deserialize_with = "parse_f64_from_string")]
    value: f64,

    rank: usize,
}

// Holds the list of countries returned by Cloudflare.
#[derive(Deserialize)]
struct TopOrigins {
    top_0: Vec<OriginCountry>,
}

// Represents the main Cloudflare response.
#[derive(Deserialize)]
struct CloudflareResponse {
    success: bool,
    result: TopOrigins,
}

// Converts a number like "22.425573" from a JSON String into an f64.
fn parse_f64_from_string<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;

    value.parse().map_err(serde::de::Error::custom)
}

fn main() {
    dotenvy::dotenv().ok();

    let client = Client::new();

    let token = std::env::var("CLOUDFLARE_API_TOKEN").expect("CLOUDFLARE_API_TOKEN is not set");

    let response = client
        .get("https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/origin?dateRange=1d")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .expect("Failed to send request");

    println!("{}", response.status());

    // Turn Cloudflare's JSON into our Rust structs.
    let data: CloudflareResponse = response
        .json()
        .expect("Failed to parse Cloudflare response");

    println!("API request successful: {}", data.success);

    // Get all attacks when the program starts.
    let attack_list: Vec<Attack> = load_attacks();

    loop {
        println!("====================");
        println!("      CYBERFEED");
        println!("====================");

        attack_feed();

        print!("Select One Option: ");

        // Make sure the prompt appears before waiting for input.
        io::stdout().flush().expect("Failed to flush stdout");

        let mut input = String::new();

        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");

        // Remove whitespace and the newline from the input.
        let user_input = input.trim();

        println!("You chose option {}", user_input);
        println!("-----------------------------");

        if user_input == "1" {
            let attack_count = attack_list.len();

            println!("{} : Attacks Detected", attack_count);
            println!("-----------------------------");

            display_all_attacks(&attack_list);

            println!("Press Enter to Continue");

            input.clear();

            io::stdin()
                .read_line(&mut input)
                .expect("Press Enter to Continue");
        } else if user_input == "2" {
            let high_severity_count = display_high_severity_attacks(&attack_list);

            println!("{} High Severity Attacks Detected", high_severity_count);

            println!("Press Enter to Continue");

            input.clear();

            io::stdin()
                .read_line(&mut input)
                .expect("Press Enter to Continue");
        } else if user_input == "3" {
            print!("Enter target country: ");

            io::stdout().flush().expect("Failed to flush stdout");

            let mut country_choice = String::new();

            io::stdin()
                .read_line(&mut country_choice)
                .expect("Enter target country");

            let country_choice = country_choice.trim().to_string();

            display_attack_country(&attack_list, &country_choice);

            println!("Press Enter to Continue");

            input.clear();

            io::stdin()
                .read_line(&mut input)
                .expect("Press Enter to Continue");
        } else if user_input == "4" {
            // Display the live Cloudflare data.
            display_top_origins(&data.result.top_0);

            println!("Press Enter to Continue");

            input.clear();

            io::stdin()
                .read_line(&mut input)
                .expect("Press Enter to Continue");
        } else if user_input == "5" {
            println!("Exit!");
            break;
        } else {
            println!("Invalid Choice!");
        }
    }
}

fn attack_feed() {
    println!("1. View all attacks");
    println!("2. View high severity attacks");
    println!("3. View attacks targeting a specific country");
    println!("4. View top attack origins");
    println!("5. Exit");
}

pub fn display_attack(current_attack: &Attack) {
    println!("Source: {}", current_attack.source_country);
    println!("Target: {}", current_attack.target_country);
    println!("Type: {}", current_attack.attack_type);
    println!("Time: {}", current_attack.timestamp);

    match current_attack.severity {
        Severity::Low => println!("Severity: Low"),
        Severity::Medium => println!("Severity: Medium"),
        Severity::High => println!("Severity: High"),
    }

    println!("-----------------------------");
}

pub fn display_all_attacks(attack_list: &[Attack]) {
    // Go through every attack in the list.
    for current_attack in attack_list {
        display_attack(current_attack);
    }
}

pub fn display_high_severity_attacks(attack_list: &[Attack]) -> usize {
    let mut high_severity_count: usize = 0;

    // Keep only attacks whose severity is High.
    for current_attack in attack_list.iter().filter(|attack| match attack.severity {
        Severity::High => true,
        _ => false,
    }) {
        high_severity_count += 1;

        display_attack(current_attack);
    }

    high_severity_count
}

pub fn display_attack_country(attack_list: &[Attack], country: &str) {
    // Keep only attacks targeting the country entered by the user.
    for current_attack in attack_list.iter().filter(|current_attack| {
        current_attack.target_country.to_lowercase() == country.to_lowercase()
    }) {
        display_attack(current_attack);
    }
}

// Display the countries Cloudflare currently reports as the
// top sources of Layer 7 attacks.
fn display_top_origins(origins: &[OriginCountry]) {
    println!("\nTOP ATTACK ORIGINS");
    println!("-----------------------------");

    // Go through each country in Cloudflare's list.
    for country in origins {
        println!(
            "{}. {} {} ({}) - {:.2}%",
            country.rank,
            country_flag(&country.origin_country_alpha2),
            country.origin_country_name,
            country.origin_country_alpha2,
            country.value
        );
    }
}

// Turn a two-letter country code like "US" into 🇺🇸.
fn country_flag(code: &str) -> String {
    code.chars()
        .filter_map(|letter| {
            let letter = letter.to_ascii_uppercase();

            if letter.is_ascii_uppercase() {
                char::from_u32(0x1F1E6 + (letter as u32 - 'A' as u32))
            } else {
                None
            }
        })
        .collect()
}
