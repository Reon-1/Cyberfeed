use super::terminal::{self, InputEditor};
use crate::file::{FileInfo, format_size, inspect_file, normalize_user_path};
use crate::indicator::{IndicatorType, MANUAL_HASH_LENGTHS, classify};
use crate::investigation::Investigation;
use crate::malwarebazaar::{display_hash_lookup, lookup_malware_hash};
use crate::report::{
    self, InvestigationReport, LookupOutcome, LookupSubject, ProviderLookup, outcome_from_result,
};
use crate::ui;
use reqwest::blocking::Client;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_AUTOMATIC_MALWAREBAZAAR_LOOKUPS: usize = 10;

pub(super) fn investigate_file(
    editor: &mut InputEditor,
    client: &Client,
    auth_key: &str,
    investigation: &mut Investigation,
) {
    let inspection = loop {
        clear_file_prompt();
        let input = terminal::read_input(editor, "  File path: ", true);
        if input == "0" {
            return;
        }
        let path = match normalize_user_path(&input) {
            Ok(Some(path)) => path,
            Ok(None) => {
                terminal::show_error("Enter a file path, or enter 0 to cancel.");
                continue;
            }
            Err(message) => {
                terminal::show_error(message);
                continue;
            }
        };
        match inspect_file(&path) {
            Ok(inspection) => break inspection,
            Err(error) => {
                terminal::show_error(&format!(
                    "{error}\nCheck the path and permissions, then try again or enter 0 to cancel."
                ));
            }
        }
    };

    let file = inspection.info;
    let text_indicators = inspection.text_indicators;
    let file_hash = file.sha256.clone();
    investigation.add_indicator(file_hash.as_str(), IndicatorType::Hash);
    let mut automatic_hash_lookups = HashSet::new();
    let mut lookups = Vec::new();

    terminal::clear_screen();
    ui::header("FILE INVESTIGATION", "SHA-256 threat-intelligence lookup");
    display_file_info(&file);
    ui::section("THREAT INTELLIGENCE");
    ui::field("Source", "MalwareBazaar");
    if auth_key.trim().is_empty() {
        ui::status("STATUS", "NOT CONFIGURED", ui::Status::Warning);
        ui::warning("Set MALWAREBAZAAR_AUTH_KEY to enable hash lookups.");
        lookups.push(provider_record(
            &file_hash,
            LookupSubject::OriginalFileSha256,
            None,
            LookupOutcome::NotConfigured,
        ));
    } else {
        ui::status("STATUS", "Checking hash...", ui::Status::Neutral);
        let outcome = lookup_hash_record(client, auth_key, &file_hash);
        lookups.push(provider_record(
            &file_hash,
            LookupSubject::OriginalFileSha256,
            Some(now_seconds()),
            outcome,
        ));
        automatic_hash_lookups.insert(file_hash.to_ascii_lowercase());
    }

    match &text_indicators {
        Some(text) if !text.indicators.is_empty() => {
            ui::section("EXTRACTED INDICATORS");
            for (index, extracted) in text.indicators.iter().enumerate() {
                let is_hash = matches!(extracted.indicator_type, IndicatorType::Hash);
                ui::indicator_row(
                    index + 1,
                    extracted.indicator_type.as_str(),
                    &extracted.value,
                );
                ui::box_line("");

                if is_hash {
                    lookups.push(show_hash_lookup(
                        client,
                        auth_key,
                        &extracted.value,
                        &mut automatic_hash_lookups,
                    ));
                } else {
                    ui::field("Lookup", "No connected source is available yet.");
                }

                investigation.add_indicator(extracted.value.clone(), extracted.indicator_type);
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

    terminal::clear_screen();
    ui::header(
        "SAVE INVESTIGATION REPORT",
        "Create Markdown and JSON copies",
    );
    ui::box_line(
        "  Save both report files in the local reports/ directory? They may contain sensitive indicators.",
    );
    ui::navigation_footer("0", "Skip / return");
    ui::close_box();
    let answer = terminal::read_input(editor, "  Save report? [y/N]: ", false);
    if matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes") {
        let extraction = inspection_extraction_state(&text_indicators);
        let indicators = text_indicators
            .as_ref()
            .map(|text| text.indicators.clone())
            .unwrap_or_default();
        let report = InvestigationReport::new(&file, indicators, extraction, lookups);
        match report::save_report(&report, std::path::Path::new("reports")) {
            Ok((json, markdown)) => {
                println!(
                    "Reports saved successfully:\n  JSON: {}\n  Markdown: {}",
                    json.display(),
                    markdown.display()
                );
                terminal::pause();
            }
            Err(error) => {
                terminal::show_error(&format!("Could not save both report files: {error}"))
            }
        }
    }
}

fn clear_file_prompt() {
    terminal::clear_screen();
    ui::header("FILE INVESTIGATION", "Analyze a suspicious local file");
    ui::box_line("");
    ui::box_line("  The file will be read only as data for hashing and text inspection.");
    ui::box_line("  CyberFeed will not execute or upload the file.");
    ui::box_line(
        "  If configured, MalwareBazaar receives the file SHA-256 and extracted SHA-256 values for lookup.",
    );
    ui::navigation_footer("0", "Back / cancel");
    ui::close_box();
}

fn show_hash_lookup(
    client: &Client,
    auth_key: &str,
    hash: &str,
    looked_up: &mut HashSet<String>,
) -> ProviderLookup {
    if auth_key.trim().is_empty() {
        ui::field(
            "Lookup",
            "Set MALWAREBAZAAR_AUTH_KEY to enable hash lookups.",
        );
        provider_record(
            hash,
            LookupSubject::ExtractedIndicatorSha256,
            None,
            LookupOutcome::NotConfigured,
        )
    } else if should_lookup_hash(looked_up, hash) {
        ui::field("Source", "MalwareBazaar");
        let outcome = lookup_hash_record(client, auth_key, hash);
        provider_record(
            hash,
            LookupSubject::ExtractedIndicatorSha256,
            Some(now_seconds()),
            outcome,
        )
    } else if looked_up.contains(&hash.to_ascii_lowercase()) {
        ui::field("Lookup", "Duplicate hash; lookup already performed.");
        provider_record(
            hash,
            LookupSubject::ExtractedIndicatorSha256,
            None,
            LookupOutcome::SkippedDuplicate {
                references_hash: hash.to_ascii_lowercase(),
            },
        )
    } else {
        ui::field(
            "Lookup",
            "Automatic MalwareBazaar lookup cap reached; hash was collected only.",
        );
        provider_record(
            hash,
            LookupSubject::ExtractedIndicatorSha256,
            None,
            LookupOutcome::SkippedLookupLimit,
        )
    }
}

fn lookup_hash(client: &Client, auth_key: &str, hash: &str) {
    let _ = lookup_hash_record(client, auth_key, hash);
}

fn lookup_hash_record(client: &Client, auth_key: &str, hash: &str) -> LookupOutcome {
    let result = lookup_malware_hash(client, auth_key, hash);
    match &result {
        Ok(result) => display_hash_lookup(result),
        Err(error) => {
            ui::section("LOOKUP FAILED");
            ui::error("MalwareBazaar lookup failed.");
            ui::field("Details", error);
        }
    }
    outcome_from_result(result)
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn provider_record(
    hash: &str,
    subject: LookupSubject,
    retrieved: Option<u64>,
    outcome: LookupOutcome,
) -> ProviderLookup {
    ProviderLookup {
        provider: "MalwareBazaar".into(),
        subject,
        queried_hash: hash.into(),
        retrieved_at_unix_seconds: retrieved,
        outcome,
    }
}
fn inspection_extraction_state(text: &Option<crate::file::TextIndicators>) -> Option<bool> {
    text.as_ref().map(|t| t.limit_reached)
}

fn should_lookup_hash(looked_up: &mut HashSet<String>, hash: &str) -> bool {
    // The file's own hash is inserted first, so it counts toward this cap.
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

    #[test]
    fn original_file_hash_counts_as_one_of_ten_automatic_lookups() {
        let mut looked_up = HashSet::from(["original-file-hash".to_string()]);
        for index in 0..MAX_AUTOMATIC_MALWAREBAZAAR_LOOKUPS - 1 {
            assert!(should_lookup_hash(
                &mut looked_up,
                &format!("embedded-{index}")
            ));
        }
        assert_eq!(looked_up.len(), MAX_AUTOMATIC_MALWAREBAZAAR_LOOKUPS);
        assert!(!should_lookup_hash(&mut looked_up, "one-too-many"));
    }
}
