//! Terminal presentation for provider data; request and parsing code stays in provider modules.
use crate::indicator::{Indicator, IndicatorType};
use crate::providers::cloudflare::{TopAttackPairs, TopOrigins, TopTargets};
use crate::providers::malwarebazaar::{MalwareResponse, MalwareSample};
use crate::report::{LookupOutcome, MatchDetails};
use crate::ui;

pub(crate) fn display_lookup(provider: &str, indicator: &str, outcome: &LookupOutcome) {
    let status = outcome.status();
    ui::status(provider, status, status_kind(outcome));
    ui::field("Meaning", ui::outcome_explanation(outcome));
    ui::field("Indicator", indicator);
    match outcome {
        LookupOutcome::Found(details) => display_malwarebazaar_match(details),
        LookupOutcome::ThreatFoxFound { findings } => {
            for finding in findings {
                ui::field("IOC", format!("{} ({})", finding.ioc, finding.ioc_type));
                ui::field(
                    "IOC type info",
                    finding
                        .ioc_type_description
                        .as_deref()
                        .unwrap_or("Not provided"),
                );
                ui::field(
                    "Threat type",
                    finding.threat_type.as_deref().unwrap_or("Not provided"),
                );
                ui::field(
                    "Threat info",
                    finding
                        .threat_type_description
                        .as_deref()
                        .unwrap_or("Not provided"),
                );
                ui::field(
                    "Malware family",
                    finding.malware.as_deref().unwrap_or("Not provided"),
                );
                ui::field(
                    "Malware name",
                    finding
                        .malware_printable
                        .as_deref()
                        .unwrap_or("Not provided"),
                );
                ui::field(
                    "Confidence",
                    finding
                        .confidence_level
                        .map_or_else(|| "Not provided".into(), |value| format!("{value}%")),
                );
                ui::field(
                    "First seen",
                    finding.first_seen.as_deref().unwrap_or("Not provided"),
                );
                ui::field(
                    "Last seen",
                    finding.last_seen.as_deref().unwrap_or("Not provided"),
                );
                ui::field(
                    "Reference",
                    finding.reference.as_deref().unwrap_or("Not provided"),
                );
                ui::field(
                    "Reporter",
                    finding.reporter.as_deref().unwrap_or("Not provided"),
                );
                ui::field(
                    "Tags",
                    if finding.tags.is_empty() {
                        "Not provided".to_owned()
                    } else {
                        finding.tags.join(", ")
                    },
                );
                ui::field(
                    "Record ID",
                    finding
                        .source_record_id
                        .as_deref()
                        .unwrap_or("Not provided"),
                );
            }
        }
        LookupOutcome::UrlhausFound { details } => display_urlhaus_details(details),
        LookupOutcome::NotFound => {}
        LookupOutcome::Invalid { explanation }
        | LookupOutcome::ApiError { explanation }
        | LookupOutcome::RequestError { explanation }
        | LookupOutcome::Unsupported { explanation } => ui::field("Details", explanation),
        LookupOutcome::NotConfigured => {
            ui::field(
                "Details",
                "ABUSECH_AUTH_KEY is not configured; no request was made.",
            );
        }
        LookupOutcome::SkippedDuplicate { references_hash } => {
            ui::field(
                "Details",
                format!("Reuses earlier lookup for {references_hash}."),
            );
        }
        LookupOutcome::SkippedLookupLimit => {
            ui::field(
                "Details",
                "No request was made because the automatic lookup limit was reached.",
            );
        }
    }
}

/// Render provider evidence without repeating the selected indicator value.
/// The detail screen already shows that value once, so only a distinct match
/// identifier is shown below when the provider returned one.
pub(crate) fn display_lookup_details(
    provider: &str,
    selected_indicator: &str,
    outcome: &LookupOutcome,
) {
    ui::section(provider);
    ui::status("Outcome", outcome.status(), status_kind(outcome));
    ui::field("Meaning", ui::outcome_explanation(outcome));
    match outcome {
        LookupOutcome::Found(details) => {
            if details.matched_sha256 != selected_indicator {
                ui::field("Matched SHA-256", &details.matched_sha256);
            }
            present_field("First seen", Some(&details.first_seen));
            present_field("File type", Some(&details.file_type));
            present_field("Sample file", details.sample_filename.as_deref());
            present_field("Signature", details.signature.as_deref());
        }
        LookupOutcome::ThreatFoxFound { findings } => {
            for (index, finding) in findings.iter().enumerate() {
                if findings.len() > 1 {
                    ui::field("Finding", index + 1);
                }
                if finding.ioc != selected_indicator {
                    ui::field(
                        "Matched IOC",
                        format!("{} ({})", finding.ioc, finding.ioc_type),
                    );
                }
                present_field("IOC type", Some(&finding.ioc_type));
                present_field("Type info", finding.ioc_type_description.as_deref());
                present_field("Threat type", finding.threat_type.as_deref());
                present_field("Threat info", finding.threat_type_description.as_deref());
                present_field("Malware family", finding.malware.as_deref());
                present_field("Malware name", finding.malware_printable.as_deref());
                if let Some(confidence) = finding.confidence_level {
                    ui::field("Confidence", format!("{confidence}%"));
                }
                present_field("First seen", finding.first_seen.as_deref());
                present_field("Last seen", finding.last_seen.as_deref());
                present_field("Record ID", finding.source_record_id.as_deref());
                present_field("Reference", finding.reference.as_deref());
                present_field("Reporter", finding.reporter.as_deref());
                if !finding.tags.is_empty() {
                    ui::field("Tags", finding.tags.join(", "));
                }
            }
        }
        LookupOutcome::UrlhausFound { details } => display_urlhaus_details(details),
        LookupOutcome::NotFound => {}
        LookupOutcome::Invalid { explanation }
        | LookupOutcome::ApiError { explanation }
        | LookupOutcome::RequestError { explanation }
        | LookupOutcome::Unsupported { explanation } => ui::field("Details", explanation),
        LookupOutcome::NotConfigured => {
            ui::field(
                "Details",
                "ABUSECH_AUTH_KEY is not configured; no request was made.",
            );
        }
        LookupOutcome::SkippedDuplicate { references_hash } => {
            if !references_hash.eq_ignore_ascii_case(selected_indicator) {
                ui::field("Reuses lookup", references_hash);
            } else {
                ui::field("Details", "This value was already looked up once.");
            }
        }
        LookupOutcome::SkippedLookupLimit => {
            ui::field(
                "Details",
                "No request was made because the lookup limit was reached.",
            );
        }
    }
}

fn present_field(label: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        ui::field(label, value);
    }
}

fn display_urlhaus_details(details: &crate::report::UrlhausLookupDetails) {
    present_field("URLhaus reference", details.reference.as_deref());
    present_field("Queried host", details.queried_host.as_deref());
    present_field("Payload MD5", details.md5_hash.as_deref());
    present_field("Payload SHA-256", details.sha256_hash.as_deref());
    present_field("File type", details.file_type.as_deref());
    present_field("First seen", details.first_seen.as_deref());
    present_field("Last seen", details.last_seen.as_deref());
    for (index, record) in details.associated_urls.iter().enumerate() {
        ui::field("Associated URL", format!("{}. {}", index + 1, record.url));
        present_field("URL status", record.status.as_deref());
        present_field("URLhaus reference", record.reference.as_deref());
        present_field("Host", record.host.as_deref());
        present_field("Threat", record.threat.as_deref());
        if !record.tags.is_empty() {
            ui::field("Tags", record.tags.join(", "));
        }
    }
    if details.associated_urls.is_empty()
        && let Some(count) = details.associated_url_count
    {
        ui::field("Associated URL records", count);
    }
}

fn display_malwarebazaar_match(details: &MatchDetails) {
    ui::field("Matched SHA-256", &details.matched_sha256);
    ui::field("First seen", &details.first_seen);
    ui::field("File type", &details.file_type);
    ui::field(
        "Sample file",
        details.sample_filename.as_deref().unwrap_or("Not provided"),
    );
    ui::field(
        "Signature",
        details.signature.as_deref().unwrap_or("Not provided"),
    );
}

pub(crate) fn status_kind(outcome: &LookupOutcome) -> ui::Status {
    ui::outcome_style(outcome)
}

// Display the malware data in the terminal.
pub(super) fn display_malware_data(
    data: &MalwareResponse,
    country: Option<&str>,
) -> Vec<Indicator> {
    ui::header("MALWAREBAZAAR", "Recent malware sample intelligence");

    ui::section("FEED STATUS");
    ui::field("Provider", "MalwareBazaar");

    if data.query_status == "ok" {
        ui::status("STATUS", "ONLINE", ui::Status::Success);
        ui::field("Results", format!("{} recent samples", data.data.len()));
    } else {
        ui::status("STATUS", "ERROR", ui::Status::Error);
        ui::field("Results", "No samples returned");
    }

    ui::section("RECENT SAMPLES");

    // If a country was provided, only keep samples from that country.
    // Otherwise, keep all samples.
    let samples: Vec<&MalwareSample> = match country {
        Some(country) => data
            .data
            .iter()
            .filter(|sample| sample.origin_country.as_deref() == Some(country))
            .collect(),

        None => data.data.iter().collect(),
    };

    let mut indicators: Vec<Indicator> = Vec::new();

    if samples.is_empty() {
        match country {
            Some(country) => ui::box_line(&format!("  No malware samples found for {country}.")),
            None => ui::box_line("  No malware samples were returned."),
        }
    } else {
        // Go through each malware sample one at a time.
        for (index, sample) in samples.iter().enumerate() {
            // Convert the MalwareBazaar sample into our common Indicator type.
            indicators.push(Indicator::new(&sample.sha256_hash, IndicatorType::Hash));

            display_sample(sample, index + 1);
        }
    }

    ui::close_box();
    println!();

    indicators
}

// Display one malware sample as a card.
fn display_sample(sample: &MalwareSample, number: usize) {
    let country_code = sample
        .origin_country
        .as_deref()
        .unwrap_or("")
        .to_uppercase();

    // Convert the country code into a flag and readable country name.
    let flag = ui::country_flag(&country_code);
    let country = country_name(&country_code);
    let origin = if country_code.is_empty() {
        format!("{flag} {country}")
    } else {
        format!("{flag} {country} ({country_code})")
    };

    ui::section(&format!("MALWARE SAMPLE #{number}"));
    ui::field("File", &sample.file_name);
    ui::field("Type", &sample.file_type);
    ui::field("Origin", origin);
    ui::field("First seen", &sample.first_seen);
    ui::field("SHA-256", &sample.sha256_hash);
    ui::field(
        "Signature",
        sample.signature.as_deref().unwrap_or("Unknown"),
    );
    ui::box_line("");
}

// Convert an ISO country code into a readable country name.
fn country_name(code: &str) -> &str {
    match code {
        "AU" => "Australia",
        "AT" => "Austria",
        "BE" => "Belgium",
        "BR" => "Brazil",
        "CA" => "Canada",
        "CH" => "Switzerland",
        "CN" => "China",
        "CZ" => "Czech Republic",
        "DE" => "Germany",
        "DK" => "Denmark",
        "ES" => "Spain",
        "FI" => "Finland",
        "FR" => "France",
        "GB" => "United Kingdom",
        "GR" => "Greece",
        "HK" => "Hong Kong",
        "HU" => "Hungary",
        "ID" => "Indonesia",
        "IE" => "Ireland",
        "IN" => "India",
        "IT" => "Italy",
        "JP" => "Japan",
        "KR" => "South Korea",
        "MX" => "Mexico",
        "MY" => "Malaysia",
        "NL" => "Netherlands",
        "NO" => "Norway",
        "NP" => "Nepal",
        "NZ" => "New Zealand",
        "PL" => "Poland",
        "PT" => "Portugal",
        "RO" => "Romania",
        "RU" => "Russia",
        "SE" => "Sweden",
        "SG" => "Singapore",
        "TH" => "Thailand",
        "TR" => "Turkey",
        "TW" => "Taiwan",
        "UA" => "Ukraine",
        "US" => "United States",
        "VN" => "Vietnam",
        "ZA" => "South Africa",
        _ => "Unknown",
    }
}

pub(super) fn display_top_origins(data: &TopOrigins) {
    ui::section("SOURCE COUNTRIES");

    // Display each country returned by Cloudflare
    for country in &data.top_0 {
        let flag = ui::country_flag(&country.origin_country_alpha2);
        let bar = percentage_bar(country.value);

        ui::field(
            &format!("#{}", country.rank),
            format!(
                "{flag} {} · {:.2}%",
                country.origin_country_name, country.value
            ),
        );
        ui::box_line(&format!("      {bar}"));
    }
}

pub(super) fn display_top_targets(data: &TopTargets) {
    ui::section("TARGET COUNTRIES");

    // Display each target country returned by Cloudflare
    for country in &data.top_0 {
        let flag = ui::country_flag(&country.target_country_alpha2);
        let bar = percentage_bar(country.value);

        ui::field(
            &format!("#{}", country.rank),
            format!(
                "{flag} {} · {:.2}%",
                country.target_country_name, country.value
            ),
        );
        ui::box_line(&format!("      {bar}"));
    }
}

pub(super) fn display_top_attack_pairs(data: &TopAttackPairs) {
    ui::section("ORIGIN → TARGET ATTACK PAIRS");

    // Display where the attacks are coming from and where they are going
    for pair in &data.top_0 {
        let origin_flag = ui::country_flag(&pair.origin_country_alpha2);
        let target_flag = ui::country_flag(&pair.target_country_alpha2);
        let bar = percentage_bar(pair.value);

        ui::field(
            &format!("#{}", pair.rank),
            format!(
                "{origin_flag} {} → {target_flag} {} · {:.2}%",
                pair.origin_country_name, pair.target_country_name, pair.value
            ),
        );
        ui::box_line(&format!("      {bar}"));
    }
}

fn percentage_bar(value: f64) -> String {
    // Turn the percentage into a 20-character progress bar
    let filled = ((value / 5.0) * 20.0).round() as usize;

    // Don't allow the bar to become longer than 20 characters
    let filled = filled.min(20);

    format!("[{}{}]", "█".repeat(filled), "░".repeat(20 - filled))
}

#[cfg(test)]
mod tests {
    use super::{display_lookup_details, status_kind};
    use crate::report::LookupOutcome;
    use crate::ui::Status;

    #[test]
    fn provider_status_colors_preserve_result_meaning() {
        assert!(matches!(
            status_kind(&LookupOutcome::Found(crate::report::MatchDetails {
                matched_sha256: "hash".into(),
                first_seen: "today".into(),
                file_type: "bin".into(),
                sample_filename: None,
                signature: None,
            })),
            Status::Warning
        ));
        assert!(matches!(
            status_kind(&LookupOutcome::NotFound),
            Status::Neutral
        ));
        assert!(matches!(
            status_kind(&LookupOutcome::NotConfigured),
            Status::Warning
        ));
        assert!(matches!(
            status_kind(&LookupOutcome::SkippedLookupLimit),
            Status::Neutral
        ));
        assert!(matches!(
            status_kind(&LookupOutcome::RequestError {
                explanation: "offline".into()
            }),
            Status::Error
        ));
    }

    #[test]
    fn provider_detail_has_one_plain_meaning_and_technical_error_details() {
        for outcome in [
            LookupOutcome::NotFound,
            LookupOutcome::RequestError {
                explanation: "connection closed before message completed".into(),
            },
            LookupOutcome::NotConfigured,
            LookupOutcome::SkippedLookupLimit,
            LookupOutcome::Unsupported {
                explanation: "SHA-1 is not supported".into(),
            },
        ] {
            crate::ui::reset_screen();
            display_lookup_details("URLhaus", "example", &outcome);
            let lines = crate::ui::recorded_line_texts();
            assert_eq!(
                lines.iter().filter(|line| line.contains("Meaning")).count(),
                1,
                "outcome {outcome:?} should have one explanation"
            );
            assert!(
                !lines
                    .iter()
                    .any(|line| line.contains("No record returned at lookup time"))
            );
            if matches!(outcome, LookupOutcome::RequestError { .. }) {
                assert!(lines.iter().any(|line| line.contains("Details")));
            }
        }
    }
}
