mod cloudflare;
mod indicator;
mod investigation;
mod malwarebazaar;
mod ui;

use cloudflare::{
    display_top_attack_pairs, display_top_origins, display_top_targets,
    fetch_cloudflare_attack_pairs, fetch_cloudflare_data, fetch_cloudflare_targets,
};
use dotenvy::dotenv;
use indicator::IndicatorType;
use investigation::Investigation;
use malwarebazaar::{
    display_hash_lookup, display_malware_data, fetch_malware_data, lookup_malware_hash,
};
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

    let mut investigation = Investigation::new();

    loop {
        // Show the main menu
        clear_screen();

        ui::header("CYBERFEED", "Defensive Cybersecurity Investigation");
        ui::box_line("");
        box_menu_with_description(
            "1",
            "Investigation",
            "Collect and investigate suspicious indicators",
        );
        box_menu_with_description(
            "2",
            "Threat Intelligence",
            "Browse external threat intelligence sources",
        );
        ui::box_line("");
        box_menu("[0] Exit");
        ui::box_line("");
        close_box();

        print!("\n  Select an option: ");
        flush();

        let choice = read_input();

        match choice.as_str() {
            "1" => investigation_menu(&client, &malwarebazaar_auth_key, &mut investigation),
            "2" => threat_intelligence_menu(
                &client,
                &cloudflare_token,
                &malwarebazaar_auth_key,
                &mut investigation,
            ),
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

fn threat_intelligence_menu(
    client: &Client,
    cloudflare_token: &str,
    malwarebazaar_auth_key: &str,
    investigation: &mut Investigation,
) {
    loop {
        clear_screen();

        ui::header("THREAT INTELLIGENCE", "Browse external data sources");
        ui::box_line("");
        box_menu("[1] MalwareBazaar");
        box_menu("[2] Cloudflare Radar");
        ui::box_line("");
        box_menu("[0] Back");
        ui::box_line("");
        close_box();

        print!("\n  Select an option: ");
        flush();

        match read_input().as_str() {
            "1" => malwarebazaar_menu(client, malwarebazaar_auth_key, investigation),
            "2" => cloudflare_menu(client, cloudflare_token),
            "0" => break,
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

        ui::header("CLOUDFLARE RADAR", "Live Layer 7 attack telemetry");
        ui::box_line("");
        box_menu_with_description("1", "Top attack origins", "Countries where attacks begin");
        box_menu_with_description("2", "Top attack targets", "Countries receiving attacks");
        box_menu_with_description("3", "Top attack pairs", "Origin to target activity");
        ui::box_line("");
        box_menu("[0] Back");
        ui::box_line("");
        close_box();

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

        ui::header("CLOUDFLARE RADAR", "Live Layer 7 attack telemetry");
        ui::box_line("");

        match feed {
            1 => {
                // Fetch the top attack origins
                let data = fetch_cloudflare_data(client, token);

                if data.success {
                    display_top_origins(&data.result);
                } else {
                    ui::box_line("  ERROR  Cloudflare returned an unsuccessful response.");
                }
            }
            2 => {
                // Fetch the top attack targets
                let data = fetch_cloudflare_targets(client, token);

                if data.success {
                    display_top_targets(&data.result);
                } else {
                    ui::box_line("  ERROR  Cloudflare returned an unsuccessful response.");
                }
            }
            3 => {
                // Fetch the top origin to target attack pairs
                let data = fetch_cloudflare_attack_pairs(client, token);

                if data.success {
                    display_top_attack_pairs(&data.result);
                } else {
                    ui::box_line("  ERROR  Cloudflare returned an unsuccessful response.");
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

        ui::header("REFRESH INTERVAL", "Choose how often data refreshes");
        ui::box_line("");
        box_menu("[1] 5 seconds");
        box_menu("[2] 10 seconds");
        box_menu("[3] 30 seconds");
        box_menu("[4] 1 minute");
        box_menu("[5] 5 minutes");
        ui::box_line("");
        box_menu("[0] Back");
        ui::box_line("");
        close_box();

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

fn malwarebazaar_menu(client: &Client, auth_key: &str, investigation: &mut Investigation) {
    loop {
        clear_screen();

        ui::header("MALWAREBAZAAR", "Recent malware sample intelligence");
        ui::box_line("");
        box_menu("[1] Recent malware samples");
        box_menu("[2] Filter samples by country");
        ui::box_line("");
        box_menu("[0] Back");
        ui::box_line("");
        close_box();

        print!("\n  Select an option: ");
        flush();

        match read_input().as_str() {
            "1" => match fetch_malware_data(client, auth_key) {
                Ok(data) => {
                    clear_screen();
                    let indicators = display_malware_data(&data, None);
                    investigation.add_indicators(indicators);
                    pause();
                }
                Err(error) => show_source_error(&error),
            },
            "2" => {
                print!("\n  Enter a two-letter country code (for example, NP): ");
                flush();
                let country = read_input().to_uppercase();

                if country.len() != 2
                    || !country
                        .chars()
                        .all(|character| character.is_ascii_alphabetic())
                {
                    println!("\n  Please enter a valid two-letter country code.");
                    pause();
                    continue;
                }

                match fetch_malware_data(client, auth_key) {
                    Ok(data) => {
                        clear_screen();
                        let indicators = display_malware_data(&data, Some(&country));
                        investigation.add_indicators(indicators);
                        pause();
                    }
                    Err(error) => show_source_error(&error),
                }
            }
            "0" => break,
            _ => {
                println!("\n  Invalid option.");
                pause();
            }
        }
    }
}

fn investigation_menu(client: &Client, auth_key: &str, investigation: &mut Investigation) {
    loop {
        clear_screen();

        ui::header(
            "INVESTIGATION",
            "Collect and investigate suspicious indicators",
        );
        ui::box_line("");
        box_menu("[1] Add indicator");
        box_menu("[2] View collected indicators");
        box_menu("[3] Investigate indicator");
        ui::box_line("");
        box_menu("[0] Back");
        ui::box_line("");
        close_box();

        print!("\n  Select an option: ");
        flush();

        match read_input().as_str() {
            "1" => add_indicator_menu(investigation),
            "2" => view_indicators(investigation),
            "3" => investigate_indicator_menu(client, auth_key, investigation),
            "0" => break,
            _ => {
                println!("\n  Invalid option.");
                pause();
            }
        }
    }
}

fn add_indicator_menu(investigation: &mut Investigation) {
    clear_screen();

    ui::header("ADD INDICATOR", "Add evidence to this investigation");
    ui::box_line("");

    println!("  What are you investigating?");
    println!("\n  [1] Hash");
    println!("  [2] IP address");
    println!("  [3] Domain");
    println!("  [0] Cancel");
    print!("\n  Select a type: ");
    flush();

    let indicator_type = match read_input().as_str() {
        "1" => IndicatorType::Hash,
        "2" => IndicatorType::IP,
        "3" => IndicatorType::Domain,
        "0" => return,
        _ => {
            println!("\n  Please choose one of the listed types.");
            pause();
            return;
        }
    };

    print!("\n  Enter the indicator value: ");
    flush();
    let value = read_input();

    if value.is_empty() {
        println!("\n  Indicator value cannot be empty.");
        pause();
        return;
    }

    let type_name = indicator_type.as_str().to_string();
    let display_value = value.clone();
    investigation.add_indicator(value, indicator_type);
    println!("\n  SUCCESS  Indicator added");
    println!("  Type:    {type_name}");
    println!("  Value:   {display_value}");
    pause();
}

fn view_indicators(investigation: &Investigation) {
    clear_screen();

    ui::header(
        "COLLECTED INDICATORS",
        "Evidence currently in this investigation",
    );
    investigation.display_indicators();
    close_box();
    pause();
}

fn investigate_indicator_menu(client: &Client, auth_key: &str, investigation: &Investigation) {
    clear_screen();

    ui::header(
        "INVESTIGATE INDICATOR",
        "Select evidence to check with MalwareBazaar",
    );

    if investigation.indicators().is_empty() {
        ui::box_line("  No indicators collected yet.");
        ui::box_line("  Add a suspicious hash, IP, or domain first.");
        close_box();
        pause();
        return;
    }

    ui::box_line("");
    ui::box_line("  Choose an indicator:");
    for (index, indicator) in investigation.indicators().iter().enumerate() {
        ui::box_line(&format!(
            "  [{}] {} ({})",
            index + 1,
            indicator.value,
            indicator.indicator_type.as_str()
        ));
    }

    print!("\n  Select an indicator: ");
    flush();
    let selection = match read_input().parse::<usize>() {
        Ok(selection) if selection > 0 => selection - 1,
        _ => {
            println!("\n  Invalid selection.");
            pause();
            return;
        }
    };

    let Some(indicator) = investigation.indicators().get(selection) else {
        println!("\n  Invalid selection.");
        pause();
        return;
    };

    if !matches!(&indicator.indicator_type, IndicatorType::Hash) {
        println!("\n  MalwareBazaar lookup currently supports hashes only.");
        pause();
        return;
    }

    clear_screen();
    ui::header("INDICATOR INVESTIGATION", "Checking the selected evidence");
    ui::box_line("");
    ui::box_line("  INDICATOR");
    ui::box_line(&format!("  Type:   {}", indicator.indicator_type.as_str()));
    ui::box_line(&format!("  Value:  {}", indicator.value));
    ui::box_line("");
    ui::box_line("  SOURCE");
    ui::box_line("  MalwareBazaar");
    ui::box_line("  STATUS  Looking up...");
    ui::box_line("");

    match lookup_malware_hash(client, auth_key, &indicator.value) {
        Ok(sample) => display_hash_lookup(indicator, sample.as_ref()),
        Err(error) => {
            ui::box_line("  ERROR  MalwareBazaar could not be reached.");
            ui::box_line(&format!("  Details: {error}"));
        }
    }

    close_box();
    pause();
}

fn show_source_error(error: &str) {
    clear_screen();
    ui::header("THREAT INTELLIGENCE", "The data source could not be loaded");
    ui::box_line("  ERROR  Request failed.");
    ui::box_line(&format!("  Details: {error}"));
    close_box();
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

fn box_menu_with_description(number: &str, title: &str, description: &str) {
    ui::box_line(&format!("  [{number}] {title}"));
    ui::box_line(&format!("      {description}"));
}

fn close_box() {
    println!("╚══════════════════════════════════════════════════════════════╝");
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
