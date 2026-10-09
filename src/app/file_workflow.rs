use super::terminal::{self, InputEditor};
use crate::file::{FileInfo, format_size, inspect_file};
use crate::indicator::{IndicatorType, MANUAL_HASH_LENGTHS, classify};
use crate::investigation::Investigation;
use crate::malwarebazaar::{display_hash_lookup, lookup_malware_hash};
use crate::ui;
use reqwest::blocking::Client;
use std::collections::HashSet;

const MAX_AUTOMATIC_MALWAREBAZAAR_LOOKUPS: usize = 10;

pub(super) fn investigate_file(
    editor: &mut InputEditor,
    client: &Client,
    auth_key: &str,
    investigation: &mut Investigation,
) {
    clear_file_prompt();
    let path = terminal::read_input(editor, "  File path: ", true);

    if path == "0" {
        return;
    }
    if path.is_empty() {
        terminal::show_error("A file path is required.");
        return;
    }

    let inspection = match inspect_file(&path) {
        Ok(inspection) => inspection,
        Err(error) => {
            terminal::show_error(&error);
            return;
        }
    };

    let file = inspection.info;
    let text_indicators = inspection.text_indicators;
    let file_hash = file.sha256.clone();
    investigation.add_indicator(file_hash.as_str(), IndicatorType::Hash);
    let mut automatic_hash_lookups = HashSet::new();

    terminal::clear_screen();
    ui::header("FILE INVESTIGATION", "SHA-256 threat-intelligence lookup");
    display_file_info(&file);
    ui::section("THREAT INTELLIGENCE");
    ui::field("Source", "MalwareBazaar");
    if auth_key.trim().is_empty() {
        ui::status("STATUS", "NOT CONFIGURED", ui::Status::Warning);
        ui::warning("Set MALWAREBAZAAR_AUTH_KEY to enable hash lookups.");
    } else {
        ui::status("STATUS", "Checking hash...", ui::Status::Neutral);
        lookup_hash(client, auth_key, &file_hash);
        automatic_hash_lookups.insert(file_hash.to_ascii_lowercase());
    }

    match text_indicators {
        Some(text) if !text.indicators.is_empty() => {
            ui::section("EXTRACTED INDICATORS");
            for (index, extracted) in text.indicators.into_iter().enumerate() {
                let is_hash = matches!(extracted.indicator_type, IndicatorType::Hash);
                ui::indicator_row(
                    index + 1,
                    extracted.indicator_type.as_str(),
                    &extracted.value,
                );
                ui::box_line("");

                if is_hash {
                    show_hash_lookup(
                        client,
                        auth_key,
                        &extracted.value,
                        &mut automatic_hash_lookups,
                    );
                } else {
                    ui::field("Lookup", "No connected source is available yet.");
                }

                investigation.add_indicator(extracted.value, extracted.indicator_type);
                ui::box_line("");
            }
            if text.limit_reached {
                ui::warning(
                    "Extraction stopped after 10,000 unique indicators; later file content was not scanned for indicators.",
                );
            }
        }
        Some(_) => ui::box_line("  No indicators found in readable text content."),
        None => ui::box_line("  Text-indicator extraction skipped for binary/non-text content."),
    }

    ui::close_box();
    terminal::pause();
}

fn clear_file_prompt() {
    terminal::clear_screen();
    ui::header("FILE INVESTIGATION", "Analyze a suspicious local file");
    ui::box_line("");
    ui::box_line("  The file will be read only as data for hashing and text inspection.");
    ui::box_line("  CyberFeed will not execute or upload the file.");
    ui::navigation_footer("0", "Back / cancel");
    ui::close_box();
}

fn show_hash_lookup(client: &Client, auth_key: &str, hash: &str, looked_up: &mut HashSet<String>) {
    if auth_key.trim().is_empty() {
        ui::field(
            "Lookup",
            "Set MALWAREBAZAAR_AUTH_KEY to enable hash lookups.",
        );
    } else if should_lookup_hash(looked_up, hash) {
        ui::field("Source", "MalwareBazaar");
        lookup_hash(client, auth_key, hash);
    } else if looked_up.contains(&hash.to_ascii_lowercase()) {
        ui::field("Lookup", "Duplicate hash; lookup already performed.");
    } else {
        ui::field(
            "Lookup",
            "Automatic MalwareBazaar lookup cap reached; hash was collected only.",
        );
    }
}

fn lookup_hash(client: &Client, auth_key: &str, hash: &str) {
    match lookup_malware_hash(client, auth_key, hash) {
        Ok(result) => display_hash_lookup(&result),
        Err(error) => {
            ui::section("LOOKUP FAILED");
            ui::error("MalwareBazaar lookup failed.");
            ui::field("Details", error);
        }
    }
}

fn should_lookup_hash(looked_up: &mut HashSet<String>, hash: &str) -> bool {
    looked_up.len() < MAX_AUTOMATIC_MALWAREBAZAAR_LOOKUPS
        && looked_up.insert(hash.to_ascii_lowercase())
}

fn display_file_info(file: &FileInfo) {
    ui::section("FILE");
    ui::field("Name", &file.name);
    ui::field("Size", format_size(file.size));
    ui::field("SHA-256", &file.sha256);
}

pub(super) fn check_indicator(
    editor: &mut InputEditor,
    client: &Client,
    auth_key: &str,
    investigation: &mut Investigation,
) {
    terminal::clear_screen();
    ui::header("CHECK AN INDICATOR", "Check a hash, IP address, or domain");
    ui::box_line("");
    ui::box_line("  Enter a hash, IP address, or domain.");
    ui::box_line("  CyberFeed will identify the type automatically.");
    ui::navigation_footer("0", "Back / cancel");
    ui::close_box();

    let value = terminal::read_input(editor, "  Value: ", false);
    if value == "0" {
        return;
    }
    if value.is_empty() {
        terminal::show_error("A hash, IP address, or domain is required.");
        return;
    }

    let Some(indicator_type) = classify(&value, MANUAL_HASH_LENGTHS) else {
        terminal::show_error(
            "CyberFeed could not identify that value as a hash, IP address, or domain.",
        );
        return;
    };

    investigation.add_indicator(value.as_str(), indicator_type);
    if !matches!(indicator_type, IndicatorType::Hash) {
        terminal::clear_screen();
        ui::header("INDICATOR CHECK", "Evidence saved to this investigation");
        ui::section("INDICATOR");
        ui::indicator_details(indicator_type.as_str(), &value);
        ui::section("LOOKUP STATUS");
        ui::status("LOOKUP", "NOT AVAILABLE", ui::Status::Warning);
        ui::warning("No threat-intelligence source is connected for this type yet.");
        ui::box_line("  The indicator has been saved for this investigation.");
        ui::close_box();
        terminal::pause();
        return;
    }

    terminal::clear_screen();
    ui::header("INDICATOR CHECK", "Checking this hash with MalwareBazaar");
    ui::section("INDICATOR");
    ui::indicator_details(indicator_type.as_str(), &value);
    ui::section("THREAT INTELLIGENCE");
    ui::field("Source", "MalwareBazaar");
    if auth_key.trim().is_empty() {
        terminal::show_error(
            "Set MALWAREBAZAAR_AUTH_KEY in the environment or .env to check hashes.",
        );
        return;
    }

    lookup_hash(client, auth_key, &value);
    ui::close_box();
    terminal::pause();
}

pub(super) fn view_indicators(investigation: &Investigation) {
    terminal::clear_screen();
    ui::header("COLLECTED INDICATORS", "Evidence in this investigation");
    investigation.display_indicators();
    ui::close_box();
    terminal::pause();
}

#[cfg(test)]
mod tests {
    use super::{MAX_AUTOMATIC_MALWAREBAZAAR_LOOKUPS, should_lookup_hash};
    use std::collections::HashSet;

    #[test]
    fn automatic_hash_lookups_are_capped_and_case_insensitively_deduplicated() {
        let mut looked_up = HashSet::new();

        assert!(should_lookup_hash(&mut looked_up, "A"));
        assert!(!should_lookup_hash(&mut looked_up, "a"));
        for index in 1..MAX_AUTOMATIC_MALWAREBAZAAR_LOOKUPS {
            assert!(should_lookup_hash(&mut looked_up, &index.to_string()));
        }
        assert_eq!(looked_up.len(), MAX_AUTOMATIC_MALWAREBAZAAR_LOOKUPS);
        assert!(!should_lookup_hash(&mut looked_up, "new-hash"));
    }
}
