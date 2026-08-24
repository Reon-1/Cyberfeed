mod attack;
mod cloudflare;
mod data;

use crate::attack::{Attack, Severity};
use crate::cloudflare::{display_top_origins, fetch_cloudflare_data};
use crate::data::load_attacks;

use reqwest::blocking::Client;

use std::io::{self, Write};
use std::thread::sleep;
use std::time::Duration;

fn main() {
    dotenvy::dotenv().ok();

    let client = Client::new();

    let token = std::env::var("CLOUDFLARE_API_TOKEN").expect("CLOUDFLARE_API_TOKEN is not set");

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
            println!("Choose refresh interval:");
            println!("1. Every 5 seconds");
            println!("2. Every 10 seconds");
            println!("3. Every 30 seconds");
            println!("4. Every 1 minute");
            println!("5. Every 5 minutes");

            print!("Select: ");

            io::stdout().flush().expect("Failed to flush stdout");

            let mut interval_input = String::new();

            io::stdin()
                .read_line(&mut interval_input)
                .expect("Failed to read interval");

            // Remove the newline from the user's input.
            let interval_input = interval_input.trim();

            // Convert the user's choice into a Duration.
            let refresh_interval = match interval_input {
                "1" => Duration::from_secs(5),
                "2" => Duration::from_secs(10),
                "3" => Duration::from_secs(30),
                "4" => Duration::from_secs(60),
                "5" => Duration::from_secs(300),

                // If the user enters something invalid,
                // use 10 seconds as the default.
                _ => Duration::from_secs(10),
            };

            // Keep track of how many times we have refreshed.
            let mut refresh_count = 0;

            // Display the live Cloudflare data updating.
            loop {
                let data = fetch_cloudflare_data(&client, &token);

                display_top_origins(&data.result.top_0);

                // Increase the refresh count by one.
                refresh_count += 1;

                // Stop the loop after 5 refreshes.
                if refresh_count == 5 {
                    break;
                }

                // Wait for the amount of time chosen by the user.
                println!("\nRefreshing...");
                sleep(refresh_interval);
            }
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
    println!("4. View Live attack origins");
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
    for current_attack in attack_list.iter() {
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
