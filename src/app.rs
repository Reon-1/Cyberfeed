use crate::cloudflare::{
    display_top_attack_pairs, display_top_origins, display_top_targets,
    fetch_cloudflare_attack_pairs, fetch_cloudflare_data, fetch_cloudflare_targets,
};
use crate::file::{FileInfo, extract_text_indicators, format_size, inspect_file};
use crate::indicator::IndicatorType;
use crate::investigation::Investigation;
use crate::malwarebazaar::{
    display_hash_lookup, display_malware_data, fetch_malware_data, lookup_malware_hash,
};
use crate::ui;
use reqwest::blocking::Client;
use std::io::{self, Write};
use std::net::IpAddr;
use std::thread::sleep;
use std::time::Duration;

pub fn run(client: &Client, cloudflare_token: &str, malwarebazaar_auth_key: &str) {
    let mut investigation = Investigation::new();

    loop {
        clear_screen();
        ui::header("CYBERFEED", "Defensive Cybersecurity Investigation");
        ui::box_line("");
        menu_item("1", "Check a File", "Analyze a file on this computer");
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
        menu_item("1", "Check a File", "Analyze a file on this computer");
        menu_item(
            "2",
            "Check an Indicator",
            "Check a hash, IP address, or domain",
        );
        menu_item("3", "Investigation", "View collected evidence");
        ui::box_line("");
        menu_item("0", "Back", "Return to the main menu");
        ui::box_line("");
        close_box();

        print!("\n  Select an option: ");
        flush();

        match read_input().as_str() {
            "1" => investigate_file(client, auth_key, investigation),
            "2" => check_indicator(client, auth_key, investigation),
            "3" => view_indicators(investigation),
            "0" => break,
            _ => invalid_choice(),
        }
    }
}

fn investigate_file(client: &Client, auth_key: &str, investigation: &mut Investigation) {
    clear_screen();
    ui::header("FILE INVESTIGATION", "Analyze a suspicious local file");
    ui::box_line("");
    ui::box_line("  The file will be read only as data for hashing and text inspection.");
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
    ui::section("THREAT INTELLIGENCE");
    ui::field("Source", "MalwareBazaar");
    ui::status("STATUS", "Checking hash...", ui::Status::Neutral);

    match lookup_malware_hash(client, auth_key, &indicator.value) {
        Ok(sample) => {
            ui::section("FILE RESULT");
            ui::field("Type", indicator.indicator_type.as_str());
            ui::field("Value", &indicator.value);
            display_hash_lookup(indicator, sample.as_ref());
        }
        Err(error) => {
            ui::section("LOOKUP FAILED");
            ui::error("MalwareBazaar lookup failed.");
            ui::field("Details", error);
        }
    }

    match extract_text_indicators(&path) {
        Ok(indicators) if !indicators.is_empty() => {
            ui::section("EXTRACTED INDICATORS");
            for (index, extracted) in indicators.into_iter().enumerate() {
                let is_hash = matches!(&extracted.indicator_type, IndicatorType::Hash);
                investigation.add_indicators(vec![extracted]);
                let extracted = investigation
                    .indicators()
                    .last()
                    .expect("extracted indicator was just added");

                ui::indicator(
                    index + 1,
                    extracted.indicator_type.as_str(),
                    &extracted.value,
                );

                if is_hash {
                    ui::field("Source", "MalwareBazaar");
                    match lookup_malware_hash(client, auth_key, &extracted.value) {
                        Ok(sample) => display_hash_lookup(extracted, sample.as_ref()),
                        Err(error) => {
                            ui::section("LOOKUP FAILED");
                            ui::error("MalwareBazaar lookup failed.");
                            ui::field("Details", error);
                        }
                    }
                } else {
                    ui::field("Lookup", "No connected source is available yet.");
                }
            }
        }
        Ok(_) => ui::box_line("  No indicators found in readable text content."),
        Err(error) => {
            ui::section("CONTENT INSPECTION SKIPPED");
            ui::field("Details", error);
        }
    }

    close_box();
    pause();
}

fn display_file_info(file: &FileInfo) {
    ui::section("FILE");
    ui::field("Name", &file.name);
    ui::field("Size", format_size(file.size));
    ui::field("SHA-256", &file.sha256);
}

fn check_indicator(client: &Client, auth_key: &str, investigation: &mut Investigation) {
    clear_screen();
    ui::header("CHECK AN INDICATOR", "Check a hash, IP address, or domain");
    ui::box_line("");
    ui::box_line("  Enter a hash, IP address, or domain.");
    ui::box_line("  CyberFeed will identify the type automatically.");
    ui::box_line("");

    print!("  Value: ");
    flush();
    let value = read_input();

    if value.is_empty() {
        show_error("A hash, IP address, or domain is required.");
        return;
    }

    let Some(indicator_type) = infer_indicator_type(&value) else {
        show_error("CyberFeed could not identify that value as a hash, IP address, or domain.");
        return;
    };

    let type_name = indicator_type.as_str().to_string();
    investigation.add_indicator(value.clone(), indicator_type);

    let indicator = investigation
        .indicators()
        .last()
        .expect("indicator was just added");

    if !matches!(&indicator.indicator_type, IndicatorType::Hash) {
        clear_screen();
        ui::header("INDICATOR CHECK", "Evidence saved to this investigation");
        ui::section("INDICATOR");
        ui::field("Type", &type_name);
        ui::field("Value", &value);
        ui::section("LOOKUP STATUS");
        ui::status("LOOKUP", "NOT AVAILABLE", ui::Status::Warning);
        ui::warning("No threat-intelligence source is connected for this type yet.");
        ui::box_line("  The indicator has been saved for this investigation.");
        close_box();
        pause();
        return;
    }

    clear_screen();
    ui::header("INDICATOR CHECK", "Checking this hash with MalwareBazaar");
    ui::section("INDICATOR");
    ui::field("Type", &type_name);
    ui::field("Value", &value);
    ui::section("THREAT INTELLIGENCE");
    ui::field("Source", "MalwareBazaar");
    ui::status("STATUS", "Checking...", ui::Status::Neutral);

    match lookup_malware_hash(client, auth_key, &indicator.value) {
        Ok(sample) => display_hash_lookup(indicator, sample.as_ref()),
        Err(error) => {
            ui::section("LOOKUP FAILED");
            ui::error("MalwareBazaar lookup failed.");
            ui::field("Details", error);
        }
    }

    close_box();
    pause();
}

fn infer_indicator_type(value: &str) -> Option<IndicatorType> {
    if value.parse::<IpAddr>().is_ok() {
        return Some(IndicatorType::IP);
    }

    let is_hash = matches!(value.len(), 32 | 40 | 64)
        && value.chars().all(|character| character.is_ascii_hexdigit());
    if is_hash {
        return Some(IndicatorType::Hash);
    }

    let is_domain = value.contains('.')
        && !value.chars().any(char::is_whitespace)
        && value.split('.').all(|label| {
            !label.is_empty()
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        });
    is_domain.then_some(IndicatorType::Domain)
}

fn view_indicators(investigation: &Investigation) {
    clear_screen();
    ui::header("COLLECTED INDICATORS", "Evidence in this investigation");
    investigation.display_indicators();
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
                    ui::error("Cloudflare returned an unsuccessful response.");
                }
            }
            2 => {
                let data = fetch_cloudflare_targets(client, token);
                if data.success {
                    display_top_targets(&data.result);
                } else {
                    ui::error("Cloudflare returned an unsuccessful response.");
                }
            }
            3 => {
                let data = fetch_cloudflare_attack_pairs(client, token);
                if data.success {
                    display_top_attack_pairs(&data.result);
                } else {
                    ui::error("Cloudflare returned an unsuccessful response.");
                }
            }
            _ => {}
        }

        ui::box_line("");
        ui::divider();

        let current = refresh + 1;
        if current < MAX_REFRESHES {
            ui::centered_box_line(&format!(
                "Refresh {current}/{MAX_REFRESHES} • Next update in {}",
                format_duration(interval)
            ));
            ui::close_box();
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
    ui::menu_item(number, title, description);
}

fn close_box() {
    ui::close_box();
}

fn invalid_choice() {
    show_error("Please choose one of the listed options.");
}

fn show_error(message: &str) {
    clear_screen();
    ui::header("ERROR", "The requested action could not be completed");
    ui::section("MESSAGE");
    ui::error(message);
    close_box();
    pause();
}

fn show_source_error(error: &str) {
    clear_screen();
    ui::header("THREAT INTELLIGENCE", "The source could not be loaded");
    ui::section("REQUEST FAILED");
    ui::error("The intelligence source returned an error.");
    ui::field("Details", error);
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
