mod cloudflare;

use crate::cloudflare::{
    display_top_attack_pairs, display_top_origins, display_top_targets,
    fetch_cloudflare_attack_pairs, fetch_cloudflare_data, fetch_cloudflare_targets,
};

use reqwest::blocking::Client;
use std::io::{self, Write};
use std::thread::sleep;
use std::time::Duration;

fn main() {
    dotenvy::dotenv().ok();

    let client = Client::new();

    let token = std::env::var("CLOUDFLARE_API_TOKEN").expect("CLOUDFLARE_API_TOKEN is not set");

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
            println!("LIVE ATTACK DATA");
            println!("-----------------------------");

            println!("1. Top attack origins");
            println!("2. Top attack targets");
            println!("3. Top attack pairs");
            println!("4. Back");

            print!("Select: ");

            io::stdout().flush().expect("Failed to flush stdout");

            let mut live_input = String::new();

            io::stdin()
                .read_line(&mut live_input)
                .expect("Failed to read live data choice");

            let live_choice = live_input.trim();

            if live_choice == "4" {
                continue;
            }

            if live_choice != "1" && live_choice != "2" && live_choice != "3" {
                println!("Invalid Choice!");
                continue;
            }

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
                if live_choice == "1" {
                    let data = fetch_cloudflare_data(&client, &token);

                    display_top_origins(&data.result.top_0);
                } else if live_choice == "2" {
                    let data = fetch_cloudflare_targets(&client, &token);

                    display_top_targets(&data.result.top_0);
                } else {
                    let data = fetch_cloudflare_attack_pairs(&client, &token);

                    display_top_attack_pairs(&data.result.top_0);
                }

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
        } else if user_input == "2" {
            println!("Exit!");
            break;
        } else {
            println!("Invalid Choice!");
        }
    }
}

fn attack_feed() {
    println!("1. Cloudflare Live Attack Data");
    println!("2. Exit");
}
