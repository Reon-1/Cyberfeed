use crate::cloudflare::{
    display_top_attack_pairs, display_top_origins, display_top_targets,
    fetch_cloudflare_attack_pairs, fetch_cloudflare_data, fetch_cloudflare_targets,
};
use crate::file::{FileInfo, extract_text_indicators, format_size, inspect_file};
use crate::indicator::{IndicatorType, MANUAL_HASH_LENGTHS, classify};
use crate::investigation::Investigation;
use crate::malwarebazaar::{
    display_hash_lookup, display_malware_data, fetch_malware_data, lookup_malware_hash,
};
use crate::ui;
use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use reqwest::blocking::Client;
use rustyline::completion::FilenameCompleter;
use rustyline::error::ReadlineError;
use rustyline::highlight::MatchingBracketHighlighter;
use rustyline::hint::HistoryHinter;
use rustyline::history::DefaultHistory;
use rustyline::validate::MatchingBracketValidator;
use rustyline::{Completer, Config, Editor, Helper, Highlighter, Hinter, Validator};
use std::collections::HashSet;
use std::io::{self, Write};
use std::thread::sleep;
use std::time::Duration;

#[derive(Completer, Helper, Highlighter, Hinter, Validator)]
struct PathHelper {
    #[rustyline(Completer)]
    completer: FilenameCompleter,
    #[rustyline(Highlighter)]
    highlighter: MatchingBracketHighlighter,
    #[rustyline(Hinter)]
    hinter: HistoryHinter,
    #[rustyline(Validator)]
    validator: MatchingBracketValidator,
}

type InputEditor = Editor<PathHelper, DefaultHistory>;

const MAX_AUTOMATIC_MALWAREBAZAAR_LOOKUPS: usize = 10;

#[derive(Clone, Copy)]
enum Feed {
    Origins,
    Targets,
    Pairs,
}

pub fn run(client: &Client, cloudflare_token: &str, malwarebazaar_auth_key: &str) {
    let config = Config::builder().history_ignore_space(true).build();
    let mut editor = match InputEditor::with_config(config) {
        Ok(editor) => editor,
        Err(error) => {
            eprintln!("Input error: {error}");
            return;
        }
    };
    let mut investigation = Investigation::new();

    loop {
        clear_screen();
        ui::header("CYBERFEED", "Defensive Cybersecurity Investigation");
        ui::box_line("");
        ui::menu_item("1", "Check a File", "Analyze a file on this computer");
        ui::menu_item(
            "2",
            "Investigation",
            "View evidence collected in this session",
        );
        ui::menu_item(
            "3",
            "Threat Intelligence",
            "Browse external intelligence sources",
        );
        ui::box_line("");
        ui::menu_item("0", "Exit", "Close CyberFeed");
        ui::box_line("");
        ui::close_box();

        match read_input(&mut editor, "\n  Select an option: ", false).as_str() {
            "1" => investigate_file(
                &mut editor,
                client,
                malwarebazaar_auth_key,
                &mut investigation,
            ),
            "2" => investigation_menu(
                &mut editor,
                client,
                malwarebazaar_auth_key,
                &mut investigation,
            ),
            "3" => threat_intelligence_menu(
                &mut editor,
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

fn investigation_menu(
    editor: &mut InputEditor,
    client: &Client,
    auth_key: &str,
    investigation: &mut Investigation,
) {
    loop {
        clear_screen();
        ui::header("INVESTIGATION", "Collect and investigate evidence");
        ui::box_line("");
        ui::menu_item("1", "Check a File", "Analyze a file on this computer");
        ui::menu_item(
            "2",
            "Check an Indicator",
            "Check a hash, IP address, or domain",
        );
        ui::menu_item("3", "Investigation", "View collected evidence");
        ui::box_line("");
        ui::menu_item("0", "Back", "Return to the main menu");
        ui::box_line("");
        ui::close_box();

        match read_input(editor, "\n  Select an option: ", false).as_str() {
            "1" => investigate_file(editor, client, auth_key, investigation),
            "2" => check_indicator(editor, client, auth_key, investigation),
            "3" => view_indicators(investigation),
            "0" => break,
            _ => invalid_choice(),
        }
    }
}

fn investigate_file(
    editor: &mut InputEditor,
    client: &Client,
    auth_key: &str,
    investigation: &mut Investigation,
) {
    clear_screen();
    ui::header("FILE INVESTIGATION", "Analyze a suspicious local file");
    ui::box_line("");
    ui::box_line("  The file will be read only as data for hashing and text inspection.");
    ui::box_line("  CyberFeed will not execute or upload the file.");
    ui::navigation_footer("0", "Back / cancel");
    ui::close_box();

    let path = read_input(editor, "  File path: ", true);

    if path == "0" {
        return;
    }

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

    let file_hash = file.sha256.clone();
    investigation.add_indicator(file_hash.as_str(), IndicatorType::Hash);
    let mut automatic_hash_lookups = HashSet::new();

    clear_screen();
    ui::header("FILE INVESTIGATION", "SHA-256 threat-intelligence lookup");
    display_file_info(&file);
    ui::section("THREAT INTELLIGENCE");
    ui::field("Source", "MalwareBazaar");
    ui::status("STATUS", "Checking hash...", ui::Status::Neutral);

    if should_lookup_hash(&mut automatic_hash_lookups, &file_hash) {
        match lookup_malware_hash(client, auth_key, &file_hash) {
            Ok(result) => {
                ui::section("FILE RESULT");
                ui::indicator_details(IndicatorType::Hash.as_str(), &file_hash);
                display_hash_lookup(&result);
            }
            Err(error) => {
                display_lookup_failure(error);
            }
        }
    }

    match extract_text_indicators(&path) {
        Ok(indicators) if !indicators.is_empty() => {
            ui::section("EXTRACTED INDICATORS");
            for (index, extracted) in indicators.into_iter().enumerate() {
                let is_hash = matches!(extracted.indicator_type, IndicatorType::Hash);
                ui::indicator_row(
                    index + 1,
                    extracted.indicator_type.as_str(),
                    &extracted.value,
                );
                ui::box_line("");

                if is_hash {
                    if should_lookup_hash(&mut automatic_hash_lookups, &extracted.value) {
                        ui::field("Source", "MalwareBazaar");
                        match lookup_malware_hash(client, auth_key, &extracted.value) {
                            Ok(result) => display_hash_lookup(&result),
                            Err(error) => display_lookup_failure(error),
                        }
                    } else if automatic_hash_lookups.contains(&extracted.value) {
                        ui::field("Lookup", "Duplicate hash; lookup already performed.");
                    } else if automatic_hash_lookups.len() >= MAX_AUTOMATIC_MALWAREBAZAAR_LOOKUPS {
                        ui::field(
                            "Lookup",
                            "Automatic MalwareBazaar lookup cap reached; hash was collected only.",
                        );
                    }
                } else {
                    ui::field("Lookup", "No connected source is available yet.");
                }

                investigation.add_indicator(extracted.value, extracted.indicator_type);
                ui::box_line("");
            }
        }
        Ok(_) => ui::box_line("  No indicators found in readable text content."),
        Err(error) => {
            ui::section("CONTENT INSPECTION SKIPPED");
            ui::field("Details", error);
        }
    }

    ui::close_box();
    pause();
}

fn should_lookup_hash(looked_up: &mut HashSet<String>, hash: &str) -> bool {
    looked_up.len() < MAX_AUTOMATIC_MALWAREBAZAAR_LOOKUPS && looked_up.insert(hash.to_string())
}

fn display_lookup_failure(error: impl std::fmt::Display) {
    ui::section("LOOKUP FAILED");
    ui::error("MalwareBazaar lookup failed.");
    ui::field("Details", error);
}

fn display_file_info(file: &FileInfo) {
    ui::section("FILE");
    ui::field("Name", &file.name);
    ui::field("Size", format_size(file.size));
    ui::field("SHA-256", &file.sha256);
}

fn check_indicator(
    editor: &mut InputEditor,
    client: &Client,
    auth_key: &str,
    investigation: &mut Investigation,
) {
    clear_screen();
    ui::header("CHECK AN INDICATOR", "Check a hash, IP address, or domain");
    ui::box_line("");
    ui::box_line("  Enter a hash, IP address, or domain.");
    ui::box_line("  CyberFeed will identify the type automatically.");
    ui::navigation_footer("0", "Back / cancel");
    ui::close_box();

    let value = read_input(editor, "  Value: ", false);

    if value == "0" {
        return;
    }

    if value.is_empty() {
        show_error("A hash, IP address, or domain is required.");
        return;
    }

    let Some(indicator_type) = classify(&value, MANUAL_HASH_LENGTHS) else {
        show_error("CyberFeed could not identify that value as a hash, IP address, or domain.");
        return;
    };

    let type_name = indicator_type.as_str();
    investigation.add_indicator(value.as_str(), indicator_type);

    if !matches!(indicator_type, IndicatorType::Hash) {
        clear_screen();
        ui::header("INDICATOR CHECK", "Evidence saved to this investigation");
        ui::section("INDICATOR");
        ui::indicator_details(type_name, &value);
        ui::section("LOOKUP STATUS");
        ui::status("LOOKUP", "NOT AVAILABLE", ui::Status::Warning);
        ui::warning("No threat-intelligence source is connected for this type yet.");
        ui::box_line("  The indicator has been saved for this investigation.");
        ui::close_box();
        pause();
        return;
    }

    clear_screen();
    ui::header("INDICATOR CHECK", "Checking this hash with MalwareBazaar");
    ui::section("INDICATOR");
    ui::indicator_details(type_name, &value);
    ui::section("THREAT INTELLIGENCE");
    ui::field("Source", "MalwareBazaar");
    ui::status("STATUS", "Checking...", ui::Status::Neutral);

    match lookup_malware_hash(client, auth_key, &value) {
        Ok(result) => display_hash_lookup(&result),
        Err(error) => display_lookup_failure(error),
    }

    ui::close_box();
    pause();
}

fn view_indicators(investigation: &Investigation) {
    clear_screen();
    ui::header("COLLECTED INDICATORS", "Evidence in this investigation");
    investigation.display_indicators();
    ui::close_box();
    pause();
}

fn threat_intelligence_menu(
    editor: &mut InputEditor,
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
        ui::menu_item("1", "MalwareBazaar", "Recent malware samples");
        ui::menu_item("2", "Cloudflare Radar", "Live Layer 7 attack telemetry");
        ui::box_line("");
        ui::menu_item("0", "Back", "Return to the main menu");
        ui::box_line("");
        ui::close_box();

        match read_input(editor, "\n  Select an option: ", false).as_str() {
            "1" => malwarebazaar_menu(editor, client, auth_key, investigation),
            "2" => cloudflare_menu(editor, client, cloudflare_token),
            "0" => break,
            _ => invalid_choice(),
        }
    }
}

fn malwarebazaar_menu(
    editor: &mut InputEditor,
    client: &Client,
    auth_key: &str,
    investigation: &mut Investigation,
) {
    loop {
        clear_screen();
        ui::header("MALWAREBAZAAR", "Recent malware sample intelligence");
        ui::box_line("");
        ui::menu_item(
            "1",
            "Recent Samples",
            "View the latest MalwareBazaar samples",
        );
        ui::menu_item("2", "Filter by Country", "View samples from one country");
        ui::box_line("");
        ui::menu_item("0", "Back", "Return to Threat Intelligence");
        ui::box_line("");
        ui::close_box();

        match read_input(editor, "\n  Select an option: ", false).as_str() {
            "1" => match fetch_malware_data(client, auth_key) {
                Ok(data) => {
                    clear_screen();
                    investigation.add_indicators(display_malware_data(&data, None));
                    pause();
                }
                Err(error) => show_source_error(&error.to_string()),
            },
            "2" => filter_malware_samples(editor, client, auth_key, investigation),
            "0" => break,
            _ => invalid_choice(),
        }
    }
}

fn filter_malware_samples(
    editor: &mut InputEditor,
    client: &Client,
    auth_key: &str,
    investigation: &mut Investigation,
) {
    clear_screen();
    ui::header("MALWAREBAZAAR", "Filter recent samples by origin country");
    ui::box_line("  Enter a two-letter country code (for example, NP).");
    ui::navigation_footer("0", "Back / cancel");
    ui::close_box();

    let country = read_input(editor, "\n  Country code: ", false).to_uppercase();

    if country == "0" {
        return;
    }

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
        Err(error) => show_source_error(&error.to_string()),
    }
}

fn cloudflare_menu(editor: &mut InputEditor, client: &Client, token: &str) {
    loop {
        clear_screen();
        ui::header("CLOUDFLARE RADAR", "Live Layer 7 attack telemetry");
        ui::box_line("");
        ui::menu_item("1", "Top Attack Origins", "Countries where attacks begin");
        ui::menu_item("2", "Top Attack Targets", "Countries receiving attacks");
        ui::menu_item("3", "Top Attack Pairs", "Origin to target activity");
        ui::box_line("");
        ui::menu_item("0", "Back", "Return to Threat Intelligence");
        ui::box_line("");
        ui::close_box();

        match read_input(editor, "\n  Select an option: ", false).as_str() {
            "1" => run_cloudflare_feed(editor, client, token, Feed::Origins),
            "2" => run_cloudflare_feed(editor, client, token, Feed::Targets),
            "3" => run_cloudflare_feed(editor, client, token, Feed::Pairs),
            "0" => break,
            _ => invalid_choice(),
        }
    }
}

fn run_cloudflare_feed(editor: &mut InputEditor, client: &Client, token: &str, feed: Feed) {
    let Some(interval) = choose_refresh_interval(editor) else {
        return;
    };

    const MAX_REFRESHES: usize = 5;

    for refresh in 0..MAX_REFRESHES {
        clear_screen();
        ui::header("CLOUDFLARE RADAR", "Live Layer 7 attack telemetry");
        ui::box_line("");

        match feed {
            Feed::Origins => match fetch_cloudflare_data(client, token) {
                Ok(data) if data.success => display_top_origins(&data.result),
                Ok(_) => ui::error("Cloudflare returned an unsuccessful response."),
                Err(error) => {
                    ui::error("Cloudflare request failed.");
                    ui::field("Details", error);
                }
            },
            Feed::Targets => match fetch_cloudflare_targets(client, token) {
                Ok(data) if data.success => display_top_targets(&data.result),
                Ok(_) => ui::error("Cloudflare returned an unsuccessful response."),
                Err(error) => {
                    ui::error("Cloudflare request failed.");
                    ui::field("Details", error);
                }
            },
            Feed::Pairs => match fetch_cloudflare_attack_pairs(client, token) {
                Ok(data) if data.success => display_top_attack_pairs(&data.result),
                Ok(_) => ui::error("Cloudflare returned an unsuccessful response."),
                Err(error) => {
                    ui::error("Cloudflare request failed.");
                    ui::field("Details", error);
                }
            },
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

            if wait_for_cloudflare_refresh(interval) {
                return;
            }
        } else {
            ui::centered_box_line("Refresh limit reached");
            ui::close_box();
            pause();
        }
    }
}

fn wait_for_cloudflare_refresh(interval: Duration) -> bool {
    if enable_raw_mode().is_err() {
        sleep(interval);
        return false;
    }

    let start = std::time::Instant::now();
    let cancelled = loop {
        let Some(remaining) = interval.checked_sub(start.elapsed()) else {
            break false;
        };

        let poll_duration = remaining.min(Duration::from_millis(100));
        match event::poll(poll_duration) {
            Ok(true) => match event::read() {
                Ok(Event::Key(key))
                    if matches!(key.code, KeyCode::Esc | KeyCode::Char('q' | 'Q')) =>
                {
                    break true;
                }
                Ok(_) => {}
                Err(_) => break false,
            },
            Ok(false) => {}
            Err(_) => break false,
        }
    };

    let _ = disable_raw_mode();
    cancelled
}

fn choose_refresh_interval(editor: &mut InputEditor) -> Option<Duration> {
    loop {
        clear_screen();
        ui::header(
            "REFRESH INTERVAL",
            "Choose how often Cloudflare data refreshes",
        );
        ui::box_line("");
        ui::menu_item("1", "5 seconds", "Fast refresh");
        ui::menu_item("2", "10 seconds", "Short refresh");
        ui::menu_item("3", "30 seconds", "Moderate refresh");
        ui::menu_item("4", "1 minute", "Long refresh");
        ui::menu_item("5", "5 minutes", "Slow refresh");
        ui::box_line("");
        ui::menu_item("0", "Back", "Return to Cloudflare Radar");
        ui::box_line("");
        ui::close_box();

        match read_input(editor, "\n  Select an option: ", false).as_str() {
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

fn invalid_choice() {
    show_error("Please choose one of the listed options.");
}

fn show_error(message: &str) {
    clear_screen();
    ui::header("ERROR", "The requested action could not be completed");
    ui::section("MESSAGE");
    ui::error(message);
    ui::close_box();
    pause();
}

fn show_source_error(error: &str) {
    clear_screen();
    ui::header("THREAT INTELLIGENCE", "The source could not be loaded");
    ui::section("REQUEST FAILED");
    ui::error("The intelligence source returned an error.");
    ui::field("Details", error);
    ui::close_box();
    pause();
}

fn clear_screen() {
    print!("\x1B[2J\x1B[3J\x1B[H");
    flush();
}

fn read_input(editor: &mut InputEditor, prompt: &str, path_completion: bool) -> String {
    if path_completion {
        editor.set_helper(Some(PathHelper {
            completer: FilenameCompleter::new(),
            highlighter: MatchingBracketHighlighter::new(),
            hinter: HistoryHinter::new(),
            validator: MatchingBracketValidator::new(),
        }));
    } else {
        editor.set_helper(None);
    }

    match editor.readline(prompt) {
        Ok(input) => {
            let input = input.trim().to_string();
            if !input.is_empty() {
                let _ = editor.add_history_entry(input.as_str());
            }
            input
        }
        Err(ReadlineError::Interrupted | ReadlineError::Eof) => String::from("0"),
        Err(error) => {
            eprintln!("Input error: {error}");
            String::from("0")
        }
    }
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

#[cfg(test)]
mod tests {
    use super::{MAX_AUTOMATIC_MALWAREBAZAAR_LOOKUPS, should_lookup_hash};
    use std::collections::HashSet;

    #[test]
    fn automatic_hash_lookups_are_capped_and_deduplicated() {
        let mut looked_up = HashSet::new();

        assert!(should_lookup_hash(&mut looked_up, "a"));
        assert!(!should_lookup_hash(&mut looked_up, "a"));

        for index in 1..MAX_AUTOMATIC_MALWAREBAZAAR_LOOKUPS {
            assert!(should_lookup_hash(&mut looked_up, &index.to_string()));
        }

        assert_eq!(looked_up.len(), MAX_AUTOMATIC_MALWAREBAZAAR_LOOKUPS);
        assert!(!should_lookup_hash(&mut looked_up, "new-hash"));
    }
}
