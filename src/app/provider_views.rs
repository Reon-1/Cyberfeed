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
            if findings.is_empty() {
                ui::field(
                    "Details",
                    "The stored result is marked FOUND but contains no IOC records.",
                );
            }
            for (index, finding) in findings.iter().enumerate() {
                if findings.len() > 1 {
                    ui::field("Finding", index + 1);
                }
                if finding.ioc != indicator {
                    field_or_not_provided("Matched indicator", Some(&finding.ioc));
                }
                field_or_not_provided("Indicator type", Some(&finding.ioc_type));
                field_or_not_provided("Type info", finding.ioc_type_description.as_deref());
                field_or_not_provided("Threat type", finding.threat_type.as_deref());
                field_or_not_provided("Threat info", finding.threat_type_description.as_deref());
                field_or_not_provided("Malware family", finding.malware.as_deref());
                field_or_not_provided("Malware name", finding.malware_printable.as_deref());
                field_or_not_provided(
                    "Confidence",
                    finding
                        .confidence_level
                        .map(|confidence| format!("{confidence}%"))
                        .as_deref(),
                );
                field_or_not_provided("First seen", finding.first_seen.as_deref());
                field_or_not_provided("Last seen", finding.last_seen.as_deref());
                field_or_not_provided("Reference", finding.reference.as_deref());
                field_or_not_provided("Reporter", finding.reporter.as_deref());
                display_tags(&finding.tags);
                field_or_not_provided("Record ID", finding.source_record_id.as_deref());
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
    ui::divider();
    ui::spacer();
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
            field_or_not_provided("Sample file", details.sample_filename.as_deref());
            field_or_not_provided("Signature", details.signature.as_deref());
        }
        LookupOutcome::ThreatFoxFound { findings } => {
            if findings.is_empty() {
                ui::field(
                    "Details",
                    "The stored result is marked FOUND but contains no IOC records.",
                );
            }
            for (index, finding) in findings.iter().enumerate() {
                if findings.len() > 1 {
                    ui::field("Finding", index + 1);
                }
                if finding.ioc != selected_indicator {
                    field_or_not_provided("Matched indicator", Some(&finding.ioc));
                }
                field_or_not_provided("Indicator type", Some(&finding.ioc_type));
                field_or_not_provided("Type info", finding.ioc_type_description.as_deref());
                field_or_not_provided("Threat type", finding.threat_type.as_deref());
                field_or_not_provided("Threat info", finding.threat_type_description.as_deref());
                field_or_not_provided("Malware family", finding.malware.as_deref());
                field_or_not_provided("Malware name", finding.malware_printable.as_deref());
                field_or_not_provided(
                    "Confidence",
                    finding
                        .confidence_level
                        .map(|confidence| format!("{confidence}%"))
                        .as_deref(),
                );
                field_or_not_provided("First seen", finding.first_seen.as_deref());
                field_or_not_provided("Last seen", finding.last_seen.as_deref());
                field_or_not_provided("Record ID", finding.source_record_id.as_deref());
                field_or_not_provided("Reference", finding.reference.as_deref());
                field_or_not_provided("Reporter", finding.reporter.as_deref());
                display_tags(&finding.tags);
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
    // Close each provider block so consecutive results remain visually distinct.
    ui::divider();
    ui::spacer();
}

fn present_field(label: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        ui::field(label, value);
    }
}

fn field_or_not_provided(label: &str, value: Option<&str>) {
    let value = value
        .map(str::trim)
        .filter(|value| !value.is_empty() && !value.eq_ignore_ascii_case("Not provided"))
        .unwrap_or("Not provided");
    ui::field(label, value);
}

fn display_tags(tags: &[String]) {
    let tags = tags
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .collect::<Vec<_>>();
    if tags.is_empty() {
        field_or_not_provided("Tags", None);
    } else {
        field_or_not_provided("Tags", Some(&tags.join(", ")));
    }
}

fn display_urlhaus_details(details: &crate::report::UrlhausLookupDetails) {
    field_or_not_provided("URLhaus reference", details.reference.as_deref());
    field_or_not_provided("Queried host", details.queried_host.as_deref());
    field_or_not_provided("Payload MD5", details.md5_hash.as_deref());
    field_or_not_provided("Payload SHA-256", details.sha256_hash.as_deref());
    field_or_not_provided("File type", details.file_type.as_deref());
    field_or_not_provided("First seen", details.first_seen.as_deref());
    field_or_not_provided("Last seen", details.last_seen.as_deref());
    for (index, record) in details.associated_urls.iter().enumerate() {
        let url = if record.url.trim().is_empty() {
            "Not provided"
        } else {
            &record.url
        };
        ui::field("Associated URL", format!("{}. {}", index + 1, url));
        field_or_not_provided("URL status", record.status.as_deref());
        field_or_not_provided("URLhaus reference", record.reference.as_deref());
        field_or_not_provided("Host", record.host.as_deref());
        field_or_not_provided("Threat", record.threat.as_deref());
        field_or_not_provided("Date added", record.date_added.as_deref());
        field_or_not_provided("First seen", record.first_seen.as_deref());
        field_or_not_provided("Last seen", record.last_seen.as_deref());
        display_tags(&record.tags);
    }
    if details.associated_urls.is_empty()
        && let Some(count) = details.associated_url_count
    {
        ui::field("Associated URL records", count);
    }
}

fn display_malwarebazaar_match(details: &MatchDetails) {
    field_or_not_provided("Matched SHA-256", Some(&details.matched_sha256));
    field_or_not_provided("First seen", Some(&details.first_seen));
    field_or_not_provided("File type", Some(&details.file_type));
    field_or_not_provided("Sample file", details.sample_filename.as_deref());
    field_or_not_provided("Signature", details.signature.as_deref());
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
    use super::{display_lookup, display_lookup_details, status_kind};
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

    #[test]
    fn provider_details_are_separated_and_keep_status_and_evidence() {
        crate::ui::reset_screen();
        display_lookup_details(
            "MalwareBazaar",
            "selected",
            &LookupOutcome::Found(crate::report::MatchDetails {
                matched_sha256: "matched-hash".into(),
                first_seen: "2026-10-14".into(),
                file_type: "PE32".into(),
                sample_filename: None,
                signature: None,
            }),
        );
        display_lookup_details("ThreatFox", "selected", &LookupOutcome::NotFound);
        display_lookup_details("URLhaus", "selected", &LookupOutcome::NotFound);

        let lines = crate::ui::recorded_rendered_lines(80);
        let malware = lines
            .iter()
            .position(|line| line.contains("MalwareBazaar"))
            .unwrap();
        let threatfox = lines
            .iter()
            .position(|line| line.contains("ThreatFox"))
            .unwrap();
        let urlhaus = lines
            .iter()
            .position(|line| line.contains("URLhaus"))
            .unwrap();
        assert!(malware < threatfox);
        assert!(threatfox < urlhaus);
        for (start, end) in [(malware, threatfox), (threatfox, urlhaus)] {
            assert!(
                lines[start + 1..end].iter().any(|line| {
                    line.strip_prefix('║')
                        .and_then(|interior| interior.strip_suffix('║'))
                        .is_some_and(|interior| interior.chars().all(char::is_whitespace))
                }),
                "provider sections must have a blank framed row between them"
            );
        }
        assert!(
            lines
                .iter()
                .all(|line| crate::ui::visible_width(line) <= 80)
        );
        assert!(lines.iter().any(|line| line.contains("FOUND")));
        assert!(lines.iter().any(|line| line.contains("NOT FOUND")));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Matched SHA-256") && line.contains("matched-hash"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Sample file") && line.contains("Not provided"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Signature") && line.contains("Not provided"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("does not prove the item"))
        );
        assert!(lines.iter().any(|line| line.contains("is safe.")));
    }

    #[test]
    fn value_search_provider_results_have_framed_spacing() {
        crate::ui::reset_screen();
        display_lookup(
            "MalwareBazaar",
            "selected",
            &LookupOutcome::Found(crate::report::MatchDetails {
                matched_sha256: "matched-hash".into(),
                first_seen: "today".into(),
                file_type: "PE32".into(),
                sample_filename: None,
                signature: None,
            }),
        );
        display_lookup("ThreatFox", "selected", &LookupOutcome::NotFound);
        display_lookup("URLhaus", "selected", &LookupOutcome::NotFound);

        let lines = crate::ui::recorded_rendered_lines(80);
        let malware = lines
            .iter()
            .position(|line| line.contains("MalwareBazaar") && line.contains("FOUND"))
            .unwrap();
        let threatfox = lines
            .iter()
            .position(|line| line.contains("ThreatFox") && line.contains("NOT FOUND"))
            .unwrap();
        let urlhaus = lines
            .iter()
            .position(|line| line.contains("URLhaus") && line.contains("NOT FOUND"))
            .unwrap();

        for (start, end) in [(malware, threatfox), (threatfox, urlhaus)] {
            assert!(
                lines[start + 1..end].iter().any(|line| {
                    line.strip_prefix('║')
                        .and_then(|interior| interior.strip_suffix('║'))
                        .is_some_and(|interior| interior.chars().all(char::is_whitespace))
                }),
                "Value Search results must have an empty framed row between providers"
            );
        }
        assert!(
            lines
                .iter()
                .all(|line| crate::ui::visible_width(line) <= 80)
        );
        assert!(lines.iter().any(|line| line.contains("Matched SHA-256")));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("does not prove the item"))
        );
    }

    #[test]
    fn value_search_groups_multiple_threatfox_findings_and_normalizes_missing_fields() {
        crate::ui::reset_screen();
        let finding = crate::report::ThreatFoxFinding {
            source_record_id: None,
            ioc: "selected.example".into(),
            ioc_type: "domain".into(),
            ioc_type_description: Some(String::new()),
            threat_type: None,
            threat_type_description: Some("  ".into()),
            malware: None,
            malware_printable: Some("Not provided".into()),
            confidence_level: None,
            first_seen: None,
            last_seen: Some(String::new()),
            reference: None,
            reporter: None,
            tags: vec![String::new()],
        };
        let mut second = finding.clone();
        second.ioc = "other.example".into();
        second.malware_printable = Some("Different family".into());
        display_lookup(
            "ThreatFox",
            "selected.example",
            &LookupOutcome::ThreatFoxFound {
                findings: vec![finding, second],
            },
        );

        let lines = crate::ui::recorded_line_texts();
        assert!(lines.iter().any(|line| line == "Finding: 1"));
        assert!(lines.iter().any(|line| line == "Finding: 2"));
        assert!(
            lines
                .iter()
                .any(|line| line == "Matched indicator: other.example")
        );
        assert!(lines.iter().any(|line| line == "Type info: Not provided"));
        assert!(lines.iter().any(|line| line == "Tags: Not provided"));
        assert!(
            lines
                .iter()
                .any(|line| line == "Malware name: Different family")
        );
        assert!(!lines.iter().any(|line| line.ends_with(": ")));
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.as_str() == "Indicator: selected.example")
                .count(),
            1,
            "the selected IOC should not be repeated for a matching finding"
        );
    }

    #[test]
    fn value_search_explains_empty_threatfox_match_data() {
        crate::ui::reset_screen();
        display_lookup(
            "ThreatFox",
            "selected.example",
            &LookupOutcome::ThreatFoxFound { findings: vec![] },
        );

        let lines = crate::ui::recorded_line_texts();
        assert!(lines.iter().any(|line| line.contains("FOUND")));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("contains no IOC records"))
        );
    }

    #[test]
    fn missing_and_empty_metadata_render_once_as_not_provided() {
        crate::ui::reset_screen();
        let threatfox = crate::report::ThreatFoxFinding {
            source_record_id: None,
            ioc: "indicator.example".into(),
            ioc_type: "domain".into(),
            ioc_type_description: Some(String::new()),
            threat_type: None,
            threat_type_description: Some("  ".into()),
            malware: None,
            malware_printable: Some("Not provided".into()),
            confidence_level: None,
            first_seen: None,
            last_seen: Some(String::new()),
            reference: Some("   ".into()),
            reporter: None,
            tags: vec![String::new(), "  ".into()],
        };
        display_lookup_details(
            "ThreatFox",
            "selected",
            &LookupOutcome::ThreatFoxFound {
                findings: vec![threatfox],
            },
        );

        let urlhaus = crate::report::UrlhausLookupDetails {
            reference: None,
            queried_host: Some(String::new()),
            associated_url_count: Some(1),
            md5_hash: None,
            sha256_hash: None,
            file_type: None,
            first_seen: None,
            last_seen: Some(" ".into()),
            signature: None,
            associated_urls: vec![crate::report::UrlhausUrlRecord {
                reference: None,
                url: "https://indicator.example/path".into(),
                status: Some(String::new()),
                host: None,
                date_added: Some("2026-01-02".into()),
                first_seen: Some("2026-01-03".into()),
                last_seen: Some("2026-01-04".into()),
                threat: Some("Not provided".into()),
                tags: vec![" ".into()],
            }],
        };
        display_lookup_details(
            "URLhaus",
            "selected",
            &LookupOutcome::UrlhausFound { details: urlhaus },
        );

        let lines = crate::ui::recorded_line_texts();
        assert!(lines.iter().any(|line| line == "Date added: 2026-01-02"));
        assert!(lines.iter().any(|line| line == "First seen: 2026-01-03"));
        assert!(lines.iter().any(|line| line == "Last seen: 2026-01-04"));
        for label in [
            "Type info",
            "Threat type",
            "Threat info",
            "Malware family",
            "Malware name",
            "First seen",
            "Last seen",
            "Record ID",
            "Reference",
            "Reporter",
            "Tags",
            "URLhaus reference",
            "Queried host",
            "Payload MD5",
            "Payload SHA-256",
            "File type",
            "URL status",
            "Host",
            "Threat",
        ] {
            assert!(
                lines
                    .iter()
                    .any(|line| line.contains(label) && line.contains("Not provided")),
                "{label} should show the missing-value placeholder"
            );
            assert!(
                !lines
                    .iter()
                    .any(|line| line.ends_with(&format!("{label}: "))),
                "{label} must not produce a blank row"
            );
        }
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.contains("Not provided"))
                .count(),
            24,
            "an existing placeholder must not be duplicated"
        );
    }
}
