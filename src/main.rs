mod cloudflare;
mod malwarebazaar;
mod ui;

use cloudflare::{
    display_top_attack_pairs, display_top_origins, display_top_targets,
    fetch_cloudflare_attack_pairs, fetch_cloudflare_data, fetch_cloudflare_targets,
};
use dotenvy::dotenv;
use malwarebazaar::{display_malware_data, fetch_malware_data};
use reqwest::blocking::Client;
use std::env;
use std::io::{self, Write};
use std::thread::sleep;
use std::time::Duration;

fn main() {
    // Load the variables from the .env file
    dotenv().ok();

    let client = Client::new();

    // Get the API keys from the environment
    let cloudflare_token =
        env::var("CLOUDFLARE_API_TOKEN").expect("CLOUDFLARE_API_TOKEN is missing from .env");

    let malwarebazaar_auth_key =
        env::var("MALWAREBAZAAR_AUTH_KEY").expect("MALWAREBAZAAR_AUTH_KEY is missing from .env");

    loop {
        // Show the main menu
        clear_screen();

        println!("╔══════════════════════════════════════════════════════════════╗");
        box_text("CYBERFEED");
        box_text("THREAT INTELLIGENCE TERMINAL");
        println!("╠══════════════════════════════════════════════════════════════╣");
        ui::box_line("");
        box_menu("[1] Cloudflare Radar    Layer 7 attack activity");
        box_menu("[2] MalwareBazaar       Recent malware samples");
        ui::box_line("");
        box_menu("[0] Exit");
        ui::box_line("");
        println!("╚══════════════════════════════════════════════════════════════╝");

        print!("\n  Select an option: ");
        flush();

        let choice = read_input();

        match choice.as_str() {
            "1" => cloudflare_menu(&client, &cloudflare_token),
            "2" => malwarebazaar_menu(&client, &malwarebazaar_auth_key),
            "0" => {
                clear_screen();
                println!("Goodbye.");
                break;
            }
            _ => {
                println!("\n  Invalid option.");
                pause();
            }
        }
    }
}

fn cloudflare_menu(client: &Client, token: &str) {
    loop {
        // Show the Cloudflare menu
        clear_screen();

        println!("╔══════════════════════════════════════════════════════════════╗");
        box_text("CLOUDFLARE RADAR");
        box_text("LIVE LAYER 7 ATTACK DATA");
        println!("╠══════════════════════════════════════════════════════════════╣");
        ui::box_line("");
        box_menu("[1] Top attack origins");
        box_menu("[2] Top attack targets");
        box_menu("[3] Top attack pairs");
        ui::box_line("");
        box_menu("[0] Back");
        ui::box_line("");
        println!("╚══════════════════════════════════════════════════════════════╝");

        print!("\n  Select an option: ");
        flush();

        let choice = read_input();

        match choice.as_str() {
            "1" => run_cloudflare_feed(client, token, 1),
            "2" => run_cloudflare_feed(client, token, 2),
            "3" => run_cloudflare_feed(client, token, 3),
            "0" => break,
            _ => {
                println!("\n  Invalid option.");
                pause();
            }
        }
    }
}

fn run_cloudflare_feed(client: &Client, token: &str, feed: u8) {
    // Ask how often the live data should refresh
    let interval = choose_refresh_interval();

    let Some(interval) = interval else {
        return;
    };

    // Limit the number of refreshes so the user can return to the menu
    const MAX_REFRESHES: usize = 5;

    for refresh in 0..MAX_REFRESHES {
        // Clear the previous results before showing the new data
        clear_screen();

        println!("╔══════════════════════════════════════════════════════════════╗");
        box_text("CLOUDFLARE RADAR");
        box_text("LIVE LAYER 7 ATTACK DATA");
        println!("╠══════════════════════════════════════════════════════════════╣");
        ui::box_line("");

        match feed {
            1 => {
                // Fetch the top attack origins
                let data = fetch_cloudflare_data(client, token);

                if data.success {
                    display_top_origins(&data.result);
                } else {
                    println!("  Cloudflare API returned an unsuccessful response.");
                }
            }
            2 => {
                // Fetch the top attack targets
                let data = fetch_cloudflare_targets(client, token);

                if data.success {
                    display_top_targets(&data.result);
                } else {
                    println!("  Cloudflare API returned an unsuccessful response.");
                }
            }
            3 => {
                // Fetch the top origin to target attack pairs
                let data = fetch_cloudflare_attack_pairs(client, token);

                if data.success {
                    display_top_attack_pairs(&data.result);
                } else {
                    println!("  Cloudflare API returned an unsuccessful response.");
                }
            }
            _ => {}
        }

        ui::box_line("");
        println!("╠══════════════════════════════════════════════════════════════╣");

        let current = refresh + 1;

        if current < MAX_REFRESHES {
            box_text(&format!(
                "Refresh {}/{} • Next update in {}",
                current,
                MAX_REFRESHES,
                format_duration(interval)
            ));

            println!("╚══════════════════════════════════════════════════════════════╝");

            // Wait before fetching the next update
            sleep(interval);
        } else {
            box_text("Refresh limit reached");
            println!("╚══════════════════════════════════════════════════════════════╝");

            pause();
        }
    }
}

fn choose_refresh_interval() -> Option<Duration> {
    loop {
        // Show the refresh interval options
        clear_screen();

        println!("╔══════════════════════════════════════════════════════════════╗");
        box_text("REFRESH INTERVAL");
        box_text("CLOUDFLARE LIVE FEED");
        println!("╠══════════════════════════════════════════════════════════════╣");
        ui::box_line("");
        box_menu("[1] 5 seconds");
        box_menu("[2] 10 seconds");
        box_menu("[3] 30 seconds");
        box_menu("[4] 1 minute");
        box_menu("[5] 5 minutes");
        ui::box_line("");
        box_menu("[0] Back");
        ui::box_line("");
        println!("╚══════════════════════════════════════════════════════════════╝");

        print!("\n  Select an option: ");
        flush();

        match read_input().as_str() {
            "1" => return Some(Duration::from_secs(5)),
            "2" => return Some(Duration::from_secs(10)),
            "3" => return Some(Duration::from_secs(30)),
            "4" => return Some(Duration::from_secs(60)),
            "5" => return Some(Duration::from_secs(300)),
            "0" => return None,
            _ => {
                println!("\n  Invalid option.");
                pause();
            }
        }
    }
}

fn malwarebazaar_menu(client: &Client, auth_key: &str) {
    // Fetch and display the latest MalwareBazaar samples
    clear_screen();

    let data = fetch_malware_data(client, auth_key);

    display_malware_data(&data);

    pause();
}

fn box_text(text: &str) {
    // Center text inside the 62-character box interior.
    ui::centered_box_line(text);
}

fn box_menu(text: &str) {
    // Keep menu options aligned inside the box
    ui::box_line(&format!("  {text}"));
}

fn clear_screen() {
    // Clear the screen and move the cursor back to the top
    print!("\x1B[2J\x1B[3J\x1B[H");
    flush();
}

fn read_input() -> String {
    let mut input = String::new();

    // Read the user's menu choice
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");

    input.trim().to_string()
}

fn pause() {
    // Wait for the user before returning to the menu
    print!("\n  Press Enter to continue...");
    flush();

    let mut input = String::new();

    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");
}

fn flush() {
    // Make sure printed text appears immediately
    io::stdout().flush().expect("Failed to flush stdout");
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();

    // Display minutes when the interval is one minute or longer
    if seconds >= 60 {
        let minutes = seconds / 60;
        format!("{} minute(s)", minutes)
    } else {
        format!("{} second(s)", seconds)
    }
}
