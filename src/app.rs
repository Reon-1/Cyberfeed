use crate::cloudflare::{
    display_top_attack_pairs, display_top_origins, display_top_targets,
    fetch_cloudflare_attack_pairs, fetch_cloudflare_data, fetch_cloudflare_targets,
};
use crate::file::{FileInfo, format_size, inspect_file};
use crate::indicator::IndicatorType;
use crate::investigation::Investigation;
use crate::malwarebazaar::{
    display_hash_lookup, display_malware_data, fetch_malware_data, lookup_malware_hash,
};
use crate::ui;
use reqwest::blocking::Client;
use std::io::{self, Write};
use std::thread::sleep;
use std::time::Duration;

pub fn run(client: &Client, cloudflare_token: &str, malwarebazaar_auth_key: &str) {
    let mut investigation = Investigation::new();

    loop {
        clear_screen();
        ui::header("CYBERFEED", "Defensive Cybersecurity Investigation");
        ui::box_line("");
        menu_item("1", "Investigate File", "Analyze a suspicious local file");
        menu_item(
            "2",
            "Investigation",
            "View evidence collected in this session",
        );
        menu_item(
            "3",
            "Threat Intelligence",
            "Browse external intelligence sources",
        );
        ui::box_line("");
        menu_item("0", "Exit", "Close CyberFeed");
        ui::box_line("");
        close_box();

        print!("\n  Select an option: ");
        flush();

        match read_input().as_str() {
            "1" => investigate_file(client, malwarebazaar_auth_key, &mut investigation),
            "2" => investigation_menu(client, malwarebazaar_auth_key, &mut investigation),
            "3" => threat_intelligence_menu(
                client,
                cloudflare_token,
                malwarebazaar_auth_key,
                &mut investigation,
            ),
            "0" => {
                clear_screen();
                println!("Goodbye.");
                break;
            }
            _ => invalid_choice(),
        }
    }
}

fn investigation_menu(client: &Client, auth_key: &str, investigation: &mut Investigation) {
    loop {
        clear_screen();
        ui::header("INVESTIGATION", "Collect and investigate evidence");
        ui::box_line("");
        menu_item("1", "Investigate File", "Hash a suspicious local file");
        menu_item("2", "Add Indicator", "Manually add a hash, IP, or domain");
        menu_item("3", "View Indicators", "Review evidence in this session");
        menu_item("4", "Investigate Indicator", "Check a collected hash");
        ui::box_line("");
        menu_item("0", "Back", "Return to the main menu");
        ui::box_line("");
        close_box();

        print!("\n  Select an option: ");
        flush();

        match read_input().as_str() {
            "1" => investigate_file(client, auth_key, investigation),
            "2" => add_indicator(investigation),
            "3" => view_indicators(investigation),
            "4" => investigate_indicator(client, auth_key, investigation),
            "0" => break,
            _ => invalid_choice(),
        }
    }
}

fn investigate_file(client: &Client, auth_key: &str, investigation: &mut Investigation) {
    clear_screen();
    ui::header("FILE INVESTIGATION", "Analyze a suspicious local file");
    ui::box_line("");
    ui::box_line("  The file will be read only to calculate its SHA-256.");
    ui::box_line("  CyberFeed will not execute or upload the file.");
    ui::box_line("");

    print!("  File path: ");
    flush();
    let path = read_input();

    if path.is_empty() {
        show_error("A file path is required.");
        return;
    }

    let file = match inspect_file(&path) {
        Ok(file) => file,
        Err(error) => {
            show_error(&error);
            return;
        }
    };

    investigation.add_indicator(file.sha256.clone(), IndicatorType::Hash);
    let indicator = investigation
        .indicators()
        .last()
        .expect("file indicator was just added");

    clear_screen();
    ui::header("FILE INVESTIGATION", "SHA-256 threat-intelligence lookup");
    display_file_info(&file);
    ui::box_line("");
    ui::box_line("  THREAT INTELLIGENCE");
    ui::box_line("  Source:  MalwareBazaar");
    ui::box_line("  Status:  Checking hash...");
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

fn display_file_info(file: &FileInfo) {
    ui::box_line("  FILE");
    ui::box_line("  ──────────────────────────────────────────────────────────");
    ui::box_line(&format!("  Name:    {}", file.name));
    ui::box_line(&format!("  Size:    {}", format_size(file.size)));
    ui::box_line(&format!("  SHA-256: {}", file.sha256));
}

fn add_indicator(investigation: &mut Investigation) {
    clear_screen();
    ui::header("ADD INDICATOR", "Manual evidence entry");
    ui::box_line("");
    ui::box_line("  This is an advanced path for non-file evidence.");
    ui::box_line("");
    ui::box_line("  What are you investigating?");
    ui::box_line("");
    ui::box_line("  [1] Hash");
    ui::box_line("  [2] IP address");
    ui::box_line("  [3] Domain");
    ui::box_line("  [0] Cancel");

    print!("\n  Select a type: ");
    flush();

    let indicator_type = match read_input().as_str() {
        "1" => IndicatorType::Hash,
        "2" => IndicatorType::IP,
        "3" => IndicatorType::Domain,
        "0" => return,
        _ => {
            show_error("Please choose one of the listed indicator types.");
            return;
        }
    };

    print!("\n  Enter the indicator value: ");
    flush();
    let value = read_input();

    if value.is_empty() {
        show_error("The indicator value cannot be empty.");
        return;
    }

    let type_name = indicator_type.as_str().to_string();
    investigation.add_indicator(value.clone(), indicator_type);

    clear_screen();
    ui::header("INDICATOR ADDED", "Evidence saved to this session");
    ui::box_line("");
    ui::box_line("  SUCCESS  Indicator added");
    ui::box_line(&format!("  Type:     {type_name}"));
    ui::box_line(&format!("  Value:    {value}"));
    close_box();
    pause();
}

fn view_indicators(investigation: &Investigation) {
    clear_screen();
    ui::header("COLLECTED INDICATORS", "Evidence in this investigation");
    investigation.display_indicators();
    close_box();
    pause();
}

fn investigate_indicator(client: &Client, auth_key: &str, investigation: &Investigation) {
    clear_screen();
    ui::header(
        "INVESTIGATE INDICATOR",
        "Check collected evidence with MalwareBazaar",
    );

    if investigation.indicators().is_empty() {
        ui::box_line("");
        ui::box_line("  No indicators collected yet.");
        ui::box_line("  Investigate a file or add an indicator first.");
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
            show_error("Please enter a valid indicator number.");
            return;
        }
    };

    let Some(indicator) = investigation.indicators().get(selection) else {
        show_error("That indicator number does not exist.");
        return;
    };

    if !matches!(&indicator.indicator_type, IndicatorType::Hash) {
        show_info("MalwareBazaar lookup currently supports hashes only.");
        return;
    }

    clear_screen();
    ui::header("INDICATOR INVESTIGATION", "Checking the selected hash");
    ui::box_line("");
    ui::box_line("  INDICATOR");
    ui::box_line(&format!("  Type:   {}", indicator.indicator_type.as_str()));
    ui::box_line(&format!("  Value:  {}", indicator.value));
    ui::box_line("");
    ui::box_line("  SOURCE");
    ui::box_line("  MalwareBazaar");
    ui::box_line("  STATUS  Checking...");
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

fn threat_intelligence_menu(
    client: &Client,
    cloudflare_token: &str,
    auth_key: &str,
    investigation: &mut Investigation,
) {
    loop {
        clear_screen();
        ui::header(
            "THREAT INTELLIGENCE",
            "Browse external intelligence sources",
        );
        ui::box_line("");
        menu_item("1", "MalwareBazaar", "Recent malware samples");
        menu_item("2", "Cloudflare Radar", "Live Layer 7 attack telemetry");
        ui::box_line("");
        menu_item("0", "Back", "Return to the main menu");
        ui::box_line("");
        close_box();

        print!("\n  Select an option: ");
        flush();

        match read_input().as_str() {
            "1" => malwarebazaar_menu(client, auth_key, investigation),
            "2" => cloudflare_menu(client, cloudflare_token),
            "0" => break,
            _ => invalid_choice(),
        }
    }
}

fn malwarebazaar_menu(client: &Client, auth_key: &str, investigation: &mut Investigation) {
    loop {
        clear_screen();
        ui::header("MALWAREBAZAAR", "Recent malware sample intelligence");
        ui::box_line("");
        menu_item(
            "1",
            "Recent Samples",
            "View the latest MalwareBazaar samples",
        );
        menu_item("2", "Filter by Country", "View samples from one country");
        ui::box_line("");
        menu_item("0", "Back", "Return to Threat Intelligence");
        ui::box_line("");
        close_box();

        print!("\n  Select an option: ");
        flush();

        match read_input().as_str() {
            "1" => match fetch_malware_data(client, auth_key) {
                Ok(data) => {
                    clear_screen();
                    investigation.add_indicators(display_malware_data(&data, None));
                    pause();
                }
                Err(error) => show_source_error(&error),
            },
            "2" => filter_malware_samples(client, auth_key, investigation),
            "0" => break,
            _ => invalid_choice(),
        }
    }
}

fn filter_malware_samples(client: &Client, auth_key: &str, investigation: &mut Investigation) {
    print!("\n  Enter a two-letter country code (for example, NP): ");
    flush();
    let country = read_input().to_uppercase();

    if country.len() != 2
        || !country
            .chars()
            .all(|character| character.is_ascii_alphabetic())
    {
        show_error("Please enter a valid two-letter country code.");
        return;
    }

    match fetch_malware_data(client, auth_key) {
        Ok(data) => {
            clear_screen();
            investigation.add_indicators(display_malware_data(&data, Some(&country)));
            pause();
        }
        Err(error) => show_source_error(&error),
    }
}

fn cloudflare_menu(client: &Client, token: &str) {
    loop {
        clear_screen();
        ui::header("CLOUDFLARE RADAR", "Live Layer 7 attack telemetry");
        ui::box_line("");
        menu_item("1", "Top Attack Origins", "Countries where attacks begin");
        menu_item("2", "Top Attack Targets", "Countries receiving attacks");
        menu_item("3", "Top Attack Pairs", "Origin to target activity");
        ui::box_line("");
        menu_item("0", "Back", "Return to Threat Intelligence");
        ui::box_line("");
        close_box();

        print!("\n  Select an option: ");
        flush();

        match read_input().as_str() {
            "1" => run_cloudflare_feed(client, token, 1),
            "2" => run_cloudflare_feed(client, token, 2),
            "3" => run_cloudflare_feed(client, token, 3),
            "0" => break,
            _ => invalid_choice(),
        }
    }
}

fn run_cloudflare_feed(client: &Client, token: &str, feed: u8) {
    let Some(interval) = choose_refresh_interval() else {
        return;
    };

    const MAX_REFRESHES: usize = 5;

    for refresh in 0..MAX_REFRESHES {
        clear_screen();
        ui::header("CLOUDFLARE RADAR", "Live Layer 7 attack telemetry");
        ui::box_line("");

        match feed {
            1 => {
                let data = fetch_cloudflare_data(client, token);
                if data.success {
                    display_top_origins(&data.result);
                } else {
                    ui::box_line("  ERROR  Cloudflare returned an unsuccessful response.");
                }
            }
            2 => {
                let data = fetch_cloudflare_targets(client, token);
                if data.success {
                    display_top_targets(&data.result);
                } else {
                    ui::box_line("  ERROR  Cloudflare returned an unsuccessful response.");
                }
            }
            3 => {
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
            ui::centered_box_line(&format!(
                "Refresh {current}/{MAX_REFRESHES} • Next update in {}",
                format_duration(interval)
            ));
            println!("╚══════════════════════════════════════════════════════════════╝");
            sleep(interval);
        } else {
            ui::centered_box_line("Refresh limit reached");
            close_box();
            pause();
        }
    }
}

fn choose_refresh_interval() -> Option<Duration> {
    loop {
        clear_screen();
        ui::header(
            "REFRESH INTERVAL",
            "Choose how often Cloudflare data refreshes",
        );
        ui::box_line("");
        menu_item("1", "5 seconds", "Fast refresh");
        menu_item("2", "10 seconds", "Short refresh");
        menu_item("3", "30 seconds", "Moderate refresh");
        menu_item("4", "1 minute", "Long refresh");
        menu_item("5", "5 minutes", "Slow refresh");
        ui::box_line("");
        menu_item("0", "Back", "Return to Cloudflare Radar");
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
            _ => invalid_choice(),
        }
    }
}

fn menu_item(number: &str, title: &str, description: &str) {
    ui::box_line(&format!("  [{number}] {title}"));
    ui::box_line(&format!("      {description}"));
}

fn close_box() {
    println!("╚══════════════════════════════════════════════════════════════╝");
}

fn invalid_choice() {
    show_error("Please choose one of the listed options.");
}

fn show_error(message: &str) {
    clear_screen();
    ui::header("ERROR", "The requested action could not be completed");
    ui::box_line(&format!("  {message}"));
    close_box();
    pause();
}

fn show_info(message: &str) {
    clear_screen();
    ui::header("INFORMATION", "No lookup was performed");
    ui::box_line(&format!("  {message}"));
    close_box();
    pause();
}

fn show_source_error(error: &str) {
    clear_screen();
    ui::header("THREAT INTELLIGENCE", "The source could not be loaded");
    ui::box_line("  ERROR  Request failed.");
    ui::box_line(&format!("  Details: {error}"));
    close_box();
    pause();
}

fn clear_screen() {
    print!("\x1B[2J\x1B[3J\x1B[H");
    flush();
}

fn read_input() -> String {
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");
    input.trim().to_string()
}

fn pause() {
    print!("\n  Press Enter to continue...");
    flush();

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");
}

fn flush() {
    io::stdout().flush().expect("Failed to flush stdout");
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds >= 60 {
        format!("{} minute(s)", seconds / 60)
    } else {
        format!("{} second(s)", seconds)
    }
}
