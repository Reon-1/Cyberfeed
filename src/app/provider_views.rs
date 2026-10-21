//! Terminal presentation for provider data; request and parsing code stays in provider modules.
use crate::indicator::{Indicator, IndicatorType};
use crate::providers::cloudflare::{TopAttackPairs, TopOrigins, TopTargets};
use crate::providers::malwarebazaar::{MalwareResponse, MalwareSample};
use crate::report::{LookupOutcome, MatchDetails};
use crate::tui;

pub(crate) fn display_lookup(provider: &str, indicator: &str, outcome: &LookupOutcome) {
    let status = outcome.status();
    tui::status(provider, status, status_kind(outcome));
    tui::field("Meaning", tui::outcome_explanation(outcome));
    tui::field("Indicator", indicator);
    match outcome {
        LookupOutcome::Found(details) => display_malwarebazaar_match(details),
        LookupOutcome::ThreatFoxFound { findings } => {
            if findings.is_empty() {
                tui::field(
                    "Details",
                    "The stored result is marked FOUND but contains no IOC records.",
                );
            }
            for (index, finding) in findings.iter().enumerate() {
                if findings.len() > 1 {
                    tui::field("Finding", index + 1);
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
        | LookupOutcome::TimedOut { explanation }
        | LookupOutcome::SkippedDeadline { explanation }
        | LookupOutcome::Unsupported { explanation } => tui::field("Details", explanation),
        LookupOutcome::NotConfigured => {
            tui::field(
                "Details",
                "ABUSECH_AUTH_KEY is not configured; no request was made.",
            );
        }
        LookupOutcome::SkippedDuplicate { references_hash } => {
            tui::field(
                "Details",
                format!("Reuses earlier lookup for {references_hash}."),
            );
        }
        LookupOutcome::SkippedLookupLimit => {
            tui::field(
                "Details",
                "No request was made because the automatic lookup limit was reached.",
            );
        }
    }
    tui::divider();
    tui::spacer();
}

/// Render provider evidence without repeating the selected indicator value.
/// The detail screen already shows that value once, so only a distinct match
/// identifier is shown below when the provider returned one.
pub(crate) fn display_lookup_details(
    provider: &str,
    selected_indicator: &str,
    outcome: &LookupOutcome,
) {
    display_lookup_details_inner(provider, selected_indicator, outcome, true);
}

/// Render provider details when the parent screen already explains the shared
/// meaning of no-match and unavailable outcomes.
pub(crate) fn display_value_lookup_details(
    provider: &str,
    selected_indicator: &str,
    outcome: &LookupOutcome,
) {
    display_lookup_details_inner(provider, selected_indicator, outcome, false);
}

fn display_lookup_details_inner(
    provider: &str,
    selected_indicator: &str,
    outcome: &LookupOutcome,
    include_meaning: bool,
) {
    tui::section(provider);
    tui::status("Outcome", outcome.status(), status_kind(outcome));
    if include_meaning {
        tui::field("Meaning", tui::outcome_explanation(outcome));
    }
    match outcome {
        LookupOutcome::Found(details) => {
            if details.matched_sha256 != selected_indicator {
                tui::field("Matched SHA-256", &details.matched_sha256);
            }
            present_field("First seen", Some(&details.first_seen));
            present_field("File type", Some(&details.file_type));
            field_or_not_provided("Sample file", details.sample_filename.as_deref());
            field_or_not_provided("Signature", details.signature.as_deref());
        }
        LookupOutcome::ThreatFoxFound { findings } => {
            if findings.is_empty() {
                tui::field(
                    "Details",
                    "The stored result is marked FOUND but contains no IOC records.",
                );
            }
            for (index, finding) in findings.iter().enumerate() {
                if findings.len() > 1 {
                    tui::field("Finding", index + 1);
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
        | LookupOutcome::TimedOut { explanation }
        | LookupOutcome::SkippedDeadline { explanation }
        | LookupOutcome::Unsupported { explanation } => tui::field("Details", explanation),
        LookupOutcome::NotConfigured => {
            tui::field(
                "Details",
                "ABUSECH_AUTH_KEY is not configured; no request was made.",
            );
        }
        LookupOutcome::SkippedDuplicate { references_hash } => {
            if !references_hash.eq_ignore_ascii_case(selected_indicator) {
                tui::field("Reuses lookup", references_hash);
            } else {
                tui::field("Details", "This value was already looked up once.");
            }
        }
        LookupOutcome::SkippedLookupLimit => {
            tui::field(
                "Details",
                "No request was made because the lookup limit was reached.",
            );
        }
    }
    // Close each provider block so consecutive results remain visually distinct.
    if include_meaning {
        tui::divider();
    }
    tui::spacer();
}

fn present_field(label: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        tui::field(label, value);
    }
}

fn field_or_not_provided(label: &str, value: Option<&str>) {
    let value = value
        .map(str::trim)
        .filter(|value| !value.is_empty() && !value.eq_ignore_ascii_case("Not provided"))
        .unwrap_or("Not provided");
    tui::field(label, value);
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
        tui::field("Associated URL", format!("{}. {}", index + 1, url));
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
        tui::field("Associated URL records", count);
    }
}

fn display_malwarebazaar_match(details: &MatchDetails) {
    field_or_not_provided("Matched SHA-256", Some(&details.matched_sha256));
    field_or_not_provided("First seen", Some(&details.first_seen));
    field_or_not_provided("File type", Some(&details.file_type));
    field_or_not_provided("Sample file", details.sample_filename.as_deref());
    field_or_not_provided("Signature", details.signature.as_deref());
}

pub(crate) fn status_kind(outcome: &LookupOutcome) -> tui::Status {
    tui::outcome_style(outcome)
}

// Display the malware data in the terminal.
pub(super) fn display_malware_data(
    data: &MalwareResponse,
    country: Option<&str>,
) -> Vec<Indicator> {
    tui::header("MALWAREBAZAAR", "Recent malware sample intelligence");

    tui::section("FEED STATUS");
    tui::field("Provider", "MalwareBazaar");

    if data.query_status == "ok" {
        tui::status("STATUS", "ONLINE", tui::Status::Success);
        tui::field("Results", format!("{} recent samples", data.data.len()));
    } else {
        tui::status("STATUS", "ERROR", tui::Status::Error);
        tui::field("Results", "No samples returned");
    }

    tui::section("RECENT SAMPLES");

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
            Some(country) => tui::box_line(&format!("  No malware samples found for {country}.")),
            None => tui::box_line("  No malware samples were returned."),
        }
    } else {
        // Go through each malware sample one at a time.
        for (index, sample) in samples.iter().enumerate() {
            // Convert the MalwareBazaar sample into our common Indicator type.
            indicators.push(Indicator::new(&sample.sha256_hash, IndicatorType::Hash));

            display_sample(sample, index + 1);
        }
    }

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

    let country = country_name(&country_code);
    let origin = tui::country_label(&country_code, country);

    tui::section(&format!("MALWARE SAMPLE #{number}"));
    tui::field("File", &sample.file_name);
    tui::field("Type", &sample.file_type);
    tui::field("Origin", origin);
    tui::field("First seen", &sample.first_seen);
    tui::field("SHA-256", &sample.sha256_hash);
    tui::field(
        "Signature",
        sample.signature.as_deref().unwrap_or("Unknown"),
    );
    tui::box_line("");
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
    tui::section("SOURCE COUNTRIES");

    // Display each country returned by Cloudflare
    for country in &data.top_0 {
        let bar = percentage_bar(country.value);

        tui::field(
            &format!("#{}", country.rank),
            format!(
                "{} · {:.2}%",
                tui::country_label(&country.origin_country_alpha2, &country.origin_country_name),
                country.value
            ),
        );
        tui::box_line(&format!("      {bar}"));
    }
}

pub(super) fn display_top_targets(data: &TopTargets) {
    tui::section("TARGET COUNTRIES");

    // Display each target country returned by Cloudflare
    for country in &data.top_0 {
        let bar = percentage_bar(country.value);

        tui::field(
            &format!("#{}", country.rank),
            format!(
                "{} · {:.2}%",
                tui::country_label(&country.target_country_alpha2, &country.target_country_name),
                country.value
            ),
        );
        tui::box_line(&format!("      {bar}"));
    }
}

pub(super) fn display_top_attack_pairs(data: &TopAttackPairs) {
    tui::section("ORIGIN → TARGET ATTACK PAIRS");

    // Display where the attacks are coming from and where they are going
    for pair in &data.top_0 {
        let bar = percentage_bar(pair.value);

        tui::field(
            &format!("#{}", pair.rank),
            format!(
                "{} → {} · {:.2}%",
                tui::country_label(&pair.origin_country_alpha2, &pair.origin_country_name),
                tui::country_label(&pair.target_country_alpha2, &pair.target_country_name),
                pair.value
            ),
        );
        tui::box_line(&format!("      {bar}"));
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
    use super::{display_lookup, display_lookup_details, display_top_origins, status_kind};
    use crate::providers::cloudflare::{OriginCountry, TopOrigins};
    use crate::report::LookupOutcome;
    use crate::tui::Status;

    #[test]
    fn cloudflare_country_rows_keep_flag_and_text_fallback_together() {
        crate::tui::reset_screen();
        display_top_origins(&TopOrigins {
            top_0: vec![
                OriginCountry {
                    origin_country_alpha2: "NP".into(),
                    origin_country_name: "Nepal".into(),
                    value: 12.5,
                    rank: 1,
                },
                OriginCountry {
                    origin_country_alpha2: "ZZ".into(),
                    origin_country_name: "Unknown region".into(),
                    value: 2.0,
                    rank: 2,
                },
            ],
        });
        let rows = crate::tui::test_rendered_lines(120, 30);
        let output = rows.join("\n");
        assert!(output.contains("🇳🇵"));
        assert!(output.contains("Nepal (NP)"));
        assert!(output.contains("Unknown region (ZZ)"), "{output}");
    }

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
            crate::tui::reset_screen();
            display_lookup_details("URLhaus", "example", &outcome);
            let lines = crate::tui::test_rendered_lines(160, 512);
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
        crate::tui::reset_screen();
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

        let lines = crate::tui::test_rendered_lines(80, 512);
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
                lines[start + 1..end].iter().any(|line| line
                    .chars()
                    .all(|character| character.is_whitespace() || character == '│')),
                "provider sections must have a blank row between them"
            );
        }
        assert!(
            lines
                .iter()
                .all(|line| crate::tui::visible_width(line) <= 80)
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
        assert!(lines.iter().any(|line| line.contains("does not establish")));
        assert!(lines.iter().any(|line| line.contains("is safe.")));
    }

    #[test]
    fn not_found_status_and_queried_indicator_render_on_separate_lines() {
        crate::tui::reset_screen();
        display_lookup("URLhaus", "example.test", &LookupOutcome::NotFound);
        let lines = crate::tui::test_rendered_lines(80, 32);
        let status_line = lines
            .iter()
            .find(|line| line.contains("URLhaus") && line.contains("NOT FOUND"))
            .expect("provider status is visible");
        let indicator_line = lines
            .iter()
            .find(|line| line.contains("Indicator") && line.contains("example.test"))
            .expect("queried indicator is visible");
        assert!(!status_line.contains("example.test"));
        assert!(!indicator_line.contains("NOT FOUND"));
        assert!(lines.iter().any(|line| line.contains("does not establish")));
        assert!(lines.iter().any(|line| line.contains("safe.")));
    }

    #[test]
    fn value_search_provider_results_have_framed_spacing() {
        crate::tui::reset_screen();
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

        let lines = crate::tui::test_rendered_lines(80, 512);
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
                lines[start + 1..end].iter().any(|line| line
                    .chars()
                    .all(|character| character.is_whitespace() || character == '│')),
                "Value Search results must have an empty row between providers"
            );
        }
        assert!(
            lines
                .iter()
                .all(|line| crate::tui::visible_width(line) <= 80)
        );
        assert!(lines.iter().any(|line| line.contains("Matched SHA-256")));
        assert!(lines.iter().any(|line| line.contains("does not establish")));
    }

    #[test]
    fn value_search_groups_multiple_threatfox_findings_and_normalizes_missing_fields() {
        crate::tui::reset_screen();
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

        let lines = crate::tui::test_rendered_lines(160, 512);
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Finding") && line.contains('1'))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Finding") && line.contains('2'))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Matched indicator") && line.contains("other.example"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Type info") && line.contains("Not provided"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Tags") && line.contains("Not provided"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Malware name") && line.contains("Different family"))
        );
        assert!(!lines.iter().any(|line| line.ends_with(": ")));
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.contains("Indicator") && line.contains("selected.example"))
                .count(),
            1,
            "the selected IOC should not be repeated for a matching finding"
        );
    }

    #[test]
    fn value_search_explains_empty_threatfox_match_data() {
        crate::tui::reset_screen();
        display_lookup(
            "ThreatFox",
            "selected.example",
            &LookupOutcome::ThreatFoxFound { findings: vec![] },
        );

        let lines = crate::tui::test_rendered_lines(160, 512);
        assert!(lines.iter().any(|line| line.contains("FOUND")));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("contains no IOC records"))
        );
    }

    #[test]
    fn missing_and_empty_metadata_render_once_as_not_provided() {
        crate::tui::reset_screen();
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

        let lines = crate::tui::test_rendered_lines(160, 512);
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Date added") && line.contains("2026-01-02"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("First seen") && line.contains("2026-01-03"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Last seen") && line.contains("2026-01-04"))
        );
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
