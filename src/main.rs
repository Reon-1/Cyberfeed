mod attack;
mod data;

use serde::Deserialize;

use crate::attack::{Attack, Severity};
use crate::data::load_attacks;
use std::io::{self, Write};

// Allows Serde to deserialize JSON data into this struct.
#[derive(Deserialize)]
struct OriginCountry {
    // Cloudflare uses camelCase in its JSON.
    // `rename` maps the JSON field to our Rust snake_case field.
    #[serde(rename = "originCountryAlpha2")]
    origin_country_alpha2: String,

    // Maps Cloudflare's JSON field to our Rust field.
    #[serde(rename = "originCountryName")]
    origin_country_name: String,

    // Cloudflare sends this value as a string,
    #[serde(deserialize_with = "parse_f64_from_string")]
    value: f64,

    // Position of the country in Cloudflare's ranking.
    rank: usize,
}

// recieves JSON string and parses it into an f64
fn parse_f64_from_string<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    value.parse().map_err(serde::de::Error::custom)
}

fn main() {
    // Get all attacks when the program starts
    let attack_list: Vec<Attack> = load_attacks();

    loop {
        println!("====================");
        println!("      CYBERFEED");
        println!("====================");

        // Display the available menu options
        attack_feed();

        print!("Select One Option: ");

        // Make sure the prompt appears before waiting for input
        io::stdout().flush().expect("Failed to flush stdout");

        let mut input = String::new();

        // Read the user's input
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");

        // Remove whitespace and the newline from the input
        let user_input = input.trim();

        println!("You chose option {}", user_input);
        println!("-----------------------------");

        // Handle user choice
        if user_input == "1" {
            // Get the number of attacks in the list
            let attack_count = attack_list.len();

            println!("{} : Attacks Detected", attack_count);
            println!("-----------------------------");

            // Display every attack
            display_all_attacks(&attack_list);

            println!("Press Enter to Continue");

            input.clear();

            io::stdin()
                .read_line(&mut input)
                .expect("Press Enter to Continue");
        } else if user_input == "2" {
            // Find and display only High severity attacks
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

            //ask user for country
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
            // Exit the program
            println!("Exit!");
            break;
        } else {
            // Handle anything other than 1, 2, or 3
            println!("Invalid Choice!");
        }
    }
}

fn attack_feed() {
    // Display the available options
    println!("1. View all attacks");
    println!("2. View high severity attacks");
    println!("3. View attacks targeting a specefic country");
    println!("4. Exit");
}

pub fn display_attack(current_attack: &Attack) {
    // Display information about one attack
    println!("Source: {}", current_attack.source_country);
    println!("Target: {}", current_attack.target_country);
    println!("Type: {}", current_attack.attack_type);
    println!("Time: {}", current_attack.timestamp);

    // Display the severity of the attack
    match current_attack.severity {
        Severity::Low => println!("Severity: Low"),
        Severity::Medium => println!("Severity: Medium"),
        Severity::High => println!("Severity: High"),
    }

    println!("-----------------------------");
}

pub fn display_all_attacks(attack_list: &[Attack]) {
    // Go through every attack in the list
    for current_attack in attack_list {
        // Display the current attack
        display_attack(current_attack);
    }
}

pub fn display_high_severity_attacks(attack_list: &[Attack]) -> usize {
    // Keep track of how many High severity attacks we find
    let mut high_severity_count: usize = 0;

    // Go through only High severity attacks
    for current_attack in attack_list.iter().filter(|attack| {
        // Check the severity of each attack
        match attack.severity {
            // Keep High severity attacks
            Severity::High => true,

            // Reject Low and Medium attacks
            _ => false,
        }
    }) {
        // Now outside the filter.
        // Anything here is already High severity.
        high_severity_count += 1;

        display_attack(current_attack);
    }

    // Return the number of High severity attacks
    high_severity_count
}

pub fn display_attack_country(attack_list: &[Attack], country: &str) {
    for current_attack in attack_list.iter().filter(|current_attack| {
        current_attack.target_country.to_lowercase() == country.to_lowercase()
    }) {
        display_attack(current_attack);
    }
}
