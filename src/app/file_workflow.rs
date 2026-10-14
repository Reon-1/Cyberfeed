use super::provider_views;
use super::terminal::{self, InputEditor};
use crate::file::{inspect_file, normalize_user_path};
use crate::indicator::{Indicator, IndicatorType, MANUAL_HASH_LENGTHS};
use crate::investigation::Investigation;
use crate::report::{self, InvestigationReport, LookupOutcome, LookupSubject};
use crate::ui;
use reqwest::blocking::Client;
use std::collections::HashSet;

mod lookups;
mod results;

use lookups::{
    UrlhausRequestState, allocate_threatfox_indicators, allocate_urlhaus_requests,
    hash_request_available, host_from_url, inspection_extraction_state, lookup_hash_record,
    now_seconds, provider_record, should_query_threatfox, show_hash_lookup,
    threatfox_indicator_key, threatfox_lookup_record, urlhaus_lookup_record,
};

pub(super) fn investigate_file(
    editor: &mut InputEditor,
    client: &Client,
    auth_key: &str,
    investigation: &mut Investigation,
) {
    let (inspection, mut progress) = loop {
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
        terminal::clear_screen();
        let progress = results::LiveProgress::new();
        progress.phase("Inspecting file, hashing and extracting indicators in one pass…");
        match inspect_file(&path) {
            Ok(inspection) => break (inspection, progress),
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
    progress.phase(&format!(
        "Inspection complete: {} · {} bytes",
        file.name, file.size
    ));
    progress.finding(
        text_indicators
            .as_ref()
            .map_or(0, |text| text.indicators.len()),
    );
    investigation.add_indicator(file_hash.as_str(), IndicatorType::Hash);
    let mut automatic_hash_lookups = HashSet::new();
    let mut lookups = Vec::new();
    let mut threatfox_queries = HashSet::new();
    let mut urlhaus_state = UrlhausRequestState::default();
    let threatfox_allocation = allocate_threatfox_indicators(
        text_indicators
            .as_ref()
            .map(|text| text.indicators.as_slice())
            .unwrap_or_default(),
        &file_hash,
    );
    let urlhaus_allocation = allocate_urlhaus_requests(
        text_indicators
            .as_ref()
            .map(|text| text.indicators.as_slice())
            .unwrap_or_default(),
        &file_hash,
    );
    let lookup_total = 3 + text_indicators.as_ref().map_or(0, |text| {
        text.indicators
            .iter()
            .map(|i| {
                if i.indicator_type == IndicatorType::Url && host_from_url(&i.value).is_some() {
                    4
                } else {
                    3
                }
            })
            .sum()
    });
    progress.begin_lookups(lookup_total);

    if auth_key.trim().is_empty() {
        let lookup = provider_record(
            &file_hash,
            LookupSubject::OriginalFileSha256,
            None,
            LookupOutcome::NotConfigured,
        );
        progress.completed("MalwareBazaar", &file_hash, &lookup.outcome);
        lookups.push(lookup);
    } else {
        progress.checking("MalwareBazaar", &file_hash);
        let outcome = lookup_hash_record(client, auth_key, &file_hash);
        let lookup = provider_record(
            &file_hash,
            LookupSubject::OriginalFileSha256,
            Some(now_seconds()),
            outcome,
        );
        progress.completed("MalwareBazaar", &file_hash, &lookup.outcome);
        lookups.push(lookup);
        automatic_hash_lookups.insert(file_hash.to_ascii_lowercase());
    }
    let file_indicator = Indicator::new(&file_hash, IndicatorType::Hash);
    if should_query_threatfox(auth_key, &file_indicator, &threatfox_queries, true) {
        progress.checking("ThreatFox", &file_hash);
    }
    let threatfox_file_lookup = threatfox_lookup_record(
        client,
        auth_key,
        &file_hash,
        IndicatorType::Hash,
        LookupSubject::OriginalFileSha256,
        &mut threatfox_queries,
        true,
    );
    progress.completed("ThreatFox", &file_hash, &threatfox_file_lookup.outcome);
    lookups.push(threatfox_file_lookup);
    progress.checking("URLhaus", &file_hash);
    let urlhaus_file_lookup = urlhaus_lookup_record(
        client,
        auth_key,
        &file_hash,
        IndicatorType::Hash,
        LookupSubject::OriginalFileSha256,
        &mut urlhaus_state,
        true,
    );
    progress.completed("URLhaus", &file_hash, &urlhaus_file_lookup.outcome);
    lookups.push(urlhaus_file_lookup);

    match &text_indicators {
        Some(text) if !text.indicators.is_empty() => {
            for extracted in &text.indicators {
                let is_hash = matches!(extracted.indicator_type, IndicatorType::Hash);
                if is_hash {
                    if hash_request_available(auth_key, &automatic_hash_lookups, &extracted.value) {
                        progress.checking("MalwareBazaar", &extracted.value);
                    }
                    let lookup = show_hash_lookup(
                        client,
                        auth_key,
                        &extracted.value,
                        &mut automatic_hash_lookups,
                    );
                    progress.completed("MalwareBazaar", &extracted.value, &lookup.outcome);
                    lookups.push(lookup);
                } else {
                    let lookup = provider_record(
                        &extracted.value,
                        LookupSubject::ExtractedIndicator,
                        None,
                        LookupOutcome::Unsupported {
                            explanation:
                                "MalwareBazaar hash lookups do not support IP/domain indicators."
                                    .into(),
                        },
                    );
                    progress.completed("MalwareBazaar", &extracted.value, &lookup.outcome);
                    lookups.push(lookup);
                }

                let indicator = Indicator::new(&extracted.value, extracted.indicator_type);
                if should_query_threatfox(
                    auth_key,
                    &indicator,
                    &threatfox_queries,
                    threatfox_allocation.contains(&threatfox_indicator_key(
                        extracted.indicator_type,
                        &extracted.value,
                    )),
                ) {
                    progress.checking("ThreatFox", &extracted.value);
                }
                let threatfox_lookup = threatfox_lookup_record(
                    client,
                    auth_key,
                    &extracted.value,
                    extracted.indicator_type,
                    LookupSubject::ExtractedIndicator,
                    &mut threatfox_queries,
                    threatfox_allocation.contains(&threatfox_indicator_key(
                        extracted.indicator_type,
                        &extracted.value,
                    )),
                );
                progress.completed("ThreatFox", &extracted.value, &threatfox_lookup.outcome);
                lookups.push(threatfox_lookup);

                let urlhaus_lookup = urlhaus_lookup_record(
                    client,
                    auth_key,
                    &extracted.value,
                    extracted.indicator_type,
                    LookupSubject::ExtractedIndicator,
                    &mut urlhaus_state,
                    crate::providers::urlhaus::request_key(&indicator)
                        .is_some_and(|key| urlhaus_allocation.contains(&key)),
                );
                progress.completed("URLhaus", &extracted.value, &urlhaus_lookup.outcome);
                lookups.push(urlhaus_lookup);
                if extracted.indicator_type == IndicatorType::Url
                    && let Some((host, host_type)) = host_from_url(&extracted.value)
                {
                    let host_lookup = urlhaus_lookup_record(
                        client,
                        auth_key,
                        &host,
                        host_type,
                        LookupSubject::ExtractedIndicator,
                        &mut urlhaus_state,
                        crate::providers::urlhaus::request_key(&Indicator::new(&host, host_type))
                            .is_some_and(|key| urlhaus_allocation.contains(&key)),
                    );
                    progress.completed("URLhaus host", &host, &host_lookup.outcome);
                    lookups.push(host_lookup);
                }

                investigation.add_indicator(extracted.value.clone(), extracted.indicator_type);
            }
        }
        _ => {}
    }

    progress.finish();
    let extraction = inspection_extraction_state(&text_indicators);
    let indicators = text_indicators
        .as_ref()
        .map(|text| text.indicators.clone())
        .unwrap_or_default();
    // Keep the file-scoped snapshot intact for its existing save prompt, and
    // also retain it as one entry in the application-wide session.
    let report_snapshot = InvestigationReport::new(&file, indicators, extraction, lookups.clone());
    investigation.add_file_investigation(&report_snapshot);
    results::review(editor, &file, text_indicators.as_ref(), &lookups);

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
        match report::save_report(&report_snapshot, std::path::Path::new("reports")) {
            Ok((json, markdown)) => {
                terminal::clear_screen();
                ui::header("REPORTS SAVED", "Investigation evidence stored locally");
                ui::field("JSON report", json.display());
                ui::field("Markdown report", markdown.display());
                ui::navigation_footer("Enter", "Return to the main menu");
                ui::close_box();
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
    ui::box_line("  CyberFeed will not execute or upload the file contents.");
    ui::box_line(
        "  Configured providers receive the file SHA-256 and supported extracted indicators for lookup.",
    );
    ui::navigation_footer("0", "Back / cancel");
    ui::close_box();
}

pub(super) fn check_indicator(
    editor: &mut InputEditor,
    client: &Client,
    auth_key: &str,
    investigation: &mut Investigation,
) {
    terminal::clear_screen();
    ui::header(
        "CHECK A VALUE",
        "Search a hash, IP address, domain, or web address",
    );
    ui::box_line("");
    ui::box_line("  Enter a hash, IP address, domain, or HTTP/HTTPS URL.");
    ui::box_line("  CyberFeed will identify the type automatically.");
    ui::box_line("  Configured providers receive this indicator value for lookup.");
    ui::navigation_footer("0", "Back / cancel");
    ui::close_box();

    let value = terminal::read_input(editor, "  Value: ", false);
    if value == "0" {
        return;
    }
    if value.is_empty() {
        terminal::show_error("A hash, IP address, domain, or URL is required.");
        return;
    }

    let indicator_type = match crate::indicator::classify_with_feedback(&value, MANUAL_HASH_LENGTHS)
    {
        crate::indicator::ClassificationFeedback::Valid(kind) => kind,
        crate::indicator::ClassificationFeedback::EndpointWithPort { ip, port } => {
            terminal::show_error(&format!(
                "'{value}' is an IP endpoint with port {port}. Threat intelligence providers look up bare IP addresses, not specific ports. To check this host IP, enter '{ip}'."
            ));
            return;
        }
        crate::indicator::ClassificationFeedback::InvalidHashLength { len, expected } => {
            let expected_str = expected
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            terminal::show_error(&format!(
                "'{value}' has {len} hexadecimal characters, but supported hash lengths are {expected_str} (MD5: 32, SHA-1: 40, SHA-256: 64)."
            ));
            return;
        }
        crate::indicator::ClassificationFeedback::MalformedUrl(reason) => {
            terminal::show_error(&format!(
                "'{value}' appears to be a URL, but is invalid: {reason}."
            ));
            return;
        }
        crate::indicator::ClassificationFeedback::MalformedDomain(reason) => {
            terminal::show_error(&format!(
                "'{value}' appears to be a domain name, but {reason}."
            ));
            return;
        }
        crate::indicator::ClassificationFeedback::Unrecognized => {
            terminal::show_error(
                "CyberFeed could not identify that value as a hash, IP address, domain, or HTTP/HTTPS URL.",
            );
            return;
        }
    };

    let lookups = lookup_indicator_value(client, auth_key, &value, indicator_type);

    investigation.add_indicator_lookup(Indicator::new(value.clone(), indicator_type), &lookups);

    terminal::clear_screen();
    ui::header(
        "VALUE SEARCH",
        "Results from the providers that were checked",
    );
    ui::section("SUMMARY");
    if lookups.iter().any(|lookup| {
        matches!(
            lookup.outcome,
            LookupOutcome::Found(_)
                | LookupOutcome::ThreatFoxFound { .. }
                | LookupOutcome::UrlhausFound { .. }
        )
    }) {
        ui::box_line(
            "At least one provider returned a matching record. Review its evidence below; this is not a verdict about a file.",
        );
    } else if lookups.iter().any(|lookup| {
        matches!(
            lookup.outcome,
            LookupOutcome::ApiError { .. }
                | LookupOutcome::RequestError { .. }
                | LookupOutcome::Invalid { .. }
        )
    }) {
        ui::box_line(
            "One or more checks failed, so results are incomplete. See provider details below.",
        );
    } else if lookups.iter().any(|lookup| {
        matches!(
            lookup.outcome,
            LookupOutcome::NotConfigured
                | LookupOutcome::SkippedLookupLimit
                | LookupOutcome::Unsupported { .. }
        )
    }) {
        ui::box_line("Some providers could not check this value. Review which checks ran below.");
    } else {
        ui::box_line(
            "No matching record was returned by the checks performed. This does not prove safety.",
        );
    }
    ui::section("VALUE");
    ui::indicator_details(indicator_type.as_str(), &value);
    ui::section("PROVIDER RESULTS");
    for record in &lookups {
        provider_views::display_lookup(&record.provider, &record.queried_hash, &record.outcome);
    }
    if lookups
        .iter()
        .any(|record| record.outcome == LookupOutcome::NotFound)
    {
        ui::warning("NOT FOUND is a provider response at lookup time, not a safety verdict.");
    }
    ui::close_box();
    save_indicator_check_prompt(editor, &value, indicator_type, &lookups);
}

fn save_indicator_check_prompt(
    editor: &mut InputEditor,
    value: &str,
    indicator_type: IndicatorType,
    lookups: &[report::ProviderLookup],
) {
    terminal::clear_screen();
    ui::header("SAVE INDICATOR CHECK", "Save this lookup for Saved Reports");
    ui::indicator_details(indicator_type.as_str(), value);
    ui::box_line("The report contains this indicator and its recorded provider outcomes.");
    ui::warning("Reports may contain sensitive indicators and provider evidence.");
    ui::navigation_footer("Enter", "Skip saving and return to Current Session");
    ui::close_box();
    let answer = terminal::read_input(editor, "  Save this indicator check? [y/N]: ", false);
    if !matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes") {
        return;
    }

    let indicator = Indicator::new(value.to_owned(), indicator_type);
    match report::save_indicator_report(&indicator, lookups, std::path::Path::new("reports")) {
        Ok((json, markdown)) => {
            terminal::clear_screen();
            ui::header("INDICATOR CHECK SAVED", "Available in Saved Reports");
            ui::field("JSON report", json.display());
            ui::field("Markdown report", markdown.display());
            ui::navigation_footer("Enter", "Return to Current Session");
            ui::close_box();
            terminal::pause();
        }
        Err(error) => terminal::show_error(&format!("Could not save indicator report: {error}")),
    }
}

pub(super) fn view_indicators(investigation: &Investigation) {
    terminal::clear_screen();
    render_current_session(investigation);
    terminal::pause();
}

fn render_current_session(investigation: &Investigation) {
    ui::header(
        "CURRENT SESSION",
        "Values checked and results recorded so far",
    );
    investigation.display_indicators();
    if !investigation.provider_lookups().is_empty() {
        ui::section("PROVIDER OBSERVATIONS");
        for lookup in investigation.provider_lookups() {
            provider_views::display_lookup(&lookup.provider, &lookup.queried_hash, &lookup.outcome);
        }
        if investigation
            .provider_lookups()
            .iter()
            .any(|lookup| lookup.outcome == LookupOutcome::NotFound)
        {
            ui::warning("NOT FOUND is a provider response at lookup time, not a safety verdict.");
        }
    }
    ui::close_box();
}

fn lookup_indicator_value(
    client: &Client,
    auth_key: &str,
    value: &str,
    indicator_type: IndicatorType,
) -> Vec<report::ProviderLookup> {
    let mut lookups = Vec::new();
    let is_hash = matches!(indicator_type, IndicatorType::Hash);
    let malwarebazaar_configured = is_hash && !auth_key.trim().is_empty();
    let mb_outcome = if is_hash {
        if !malwarebazaar_configured {
            LookupOutcome::NotConfigured
        } else {
            lookup_hash_record(client, auth_key, value)
        }
    } else {
        LookupOutcome::Unsupported {
            explanation: "MalwareBazaar hash lookups do not support IP/domain indicators.".into(),
        }
    };
    lookups.push(provider_record(
        value,
        LookupSubject::ExtractedIndicator,
        malwarebazaar_configured.then(now_seconds),
        mb_outcome,
    ));
    let mut queries = HashSet::new();
    lookups.push(threatfox_lookup_record(
        client,
        auth_key,
        value,
        indicator_type,
        LookupSubject::ExtractedIndicator,
        &mut queries,
        true,
    ));
    let mut urlhaus_state = UrlhausRequestState::default();
    lookups.push(urlhaus_lookup_record(
        client,
        auth_key,
        value,
        indicator_type,
        LookupSubject::ExtractedIndicator,
        &mut urlhaus_state,
        true,
    ));
    if indicator_type == IndicatorType::Url
        && let Some((host, host_type)) = host_from_url(value)
    {
        lookups.push(urlhaus_lookup_record(
            client,
            auth_key,
            &host,
            host_type,
            LookupSubject::ExtractedIndicator,
            &mut urlhaus_state,
            true,
        ));
    }
    lookups
}

#[cfg(test)]
mod tests {
    use super::lookups::{
        AutomaticLookup, MAX_AUTOMATIC_MALWAREBAZAAR_LOOKUPS, MAX_AUTOMATIC_THREATFOX_LOOKUPS,
        UrlhausRequestState, allocate_threatfox_indicators, allocate_urlhaus_requests,
        claim_threatfox_lookup, outcome_from_malwarebazaar_result, redact_secret,
        should_lookup_hash, threatfox_error_outcome, threatfox_indicator_key,
        threatfox_lookup_record, threatfox_outcome, urlhaus_lookup_record,
    };
    use crate::file::inspect_file;
    use crate::indicator::{Indicator, IndicatorType};
    use crate::investigation::Investigation;
    use crate::providers::malwarebazaar::{MalwareLookupError, MalwareLookupResult, MalwareSample};
    use crate::providers::threatfox::{ThreatFoxError, ThreatFoxLookupResult};
    use crate::report::{InvestigationReport, LookupOutcome, LookupSubject, ProviderLookup};
    use std::collections::HashSet;

    #[test]
    fn individual_hash_ip_and_domain_checks_run_without_credentials() {
        let client = reqwest::blocking::Client::new();
        let checks = [
            ("a".repeat(64), IndicatorType::Hash),
            ("192.0.2.4".to_owned(), IndicatorType::IP),
            ("example.test".to_owned(), IndicatorType::Domain),
        ];

        for (value, indicator_type) in checks {
            let lookups = super::lookup_indicator_value(&client, "", &value, indicator_type);
            assert_eq!(lookups.len(), 3);
            assert!(lookups.iter().all(|lookup| matches!(
                lookup.outcome,
                LookupOutcome::NotConfigured | LookupOutcome::Unsupported { .. }
            )));
            if indicator_type == IndicatorType::Hash {
                assert_eq!(lookups[0].outcome, LookupOutcome::NotConfigured);
            } else {
                assert!(matches!(
                    lookups[0].outcome,
                    LookupOutcome::Unsupported { .. }
                ));
            }
        }
    }

    #[test]
    fn current_session_review_renders_accumulated_file_and_value_results() {
        let file = crate::file::FileInfo {
            name: "sample.bin".into(),
            size: 12,
            sha256: "file-sha256".into(),
        };
        let file_report = InvestigationReport::new(
            &file,
            vec![Indicator::new("file-domain.test", IndicatorType::Domain)],
            Some(false),
            vec![ProviderLookup {
                provider: "MalwareBazaar".into(),
                subject: LookupSubject::OriginalFileSha256,
                queried_hash: "file-sha256".into(),
                retrieved_at_unix_seconds: None,
                outcome: LookupOutcome::NotConfigured,
            }],
        );
        let mut investigation = Investigation::new();
        investigation.add_file_investigation(&file_report);
        investigation.add_indicator_lookup(
            Indicator::new("198.51.100.8", IndicatorType::IP),
            &[ProviderLookup {
                provider: "ThreatFox".into(),
                subject: LookupSubject::ExtractedIndicator,
                queried_hash: "198.51.100.8".into(),
                retrieved_at_unix_seconds: Some(1),
                outcome: LookupOutcome::NotFound,
            }],
        );

        crate::ui::reset_screen();
        super::render_current_session(&investigation);
        let rendered = crate::ui::recorded_line_texts().join("\n");

        assert!(rendered.contains("file-domain.test"));
        assert!(rendered.contains("198.51.100.8"));
        assert!(rendered.contains("MalwareBazaar"));
        assert!(rendered.contains("NOT CONFIGURED"));
        assert!(rendered.contains("ThreatFox"));
        assert!(rendered.contains("NOT FOUND"));
    }

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

    #[test]
    fn urlhaus_scheduler_is_deterministic_fair_and_caps_mixed_requests() {
        let indicators = vec![
            Indicator::new("a".repeat(32), IndicatorType::Hash),
            Indicator::new("b".repeat(64), IndicatorType::Hash),
            Indicator::new("192.0.2.5", IndicatorType::IP),
            Indicator::new("203.0.113.9", IndicatorType::IP),
            Indicator::new("example.test", IndicatorType::Domain),
            Indicator::new("https://example.test/A", IndicatorType::Url),
            Indicator::new("https://example.test/a", IndicatorType::Url),
            Indicator::new("https://other.test/drop", IndicatorType::Url),
            Indicator::new("https://third.test/last", IndicatorType::Url),
            Indicator::new("https://example.test/A", IndicatorType::Url),
        ];
        let first = allocate_urlhaus_requests(&indicators, &"f".repeat(64));
        let second = allocate_urlhaus_requests(&indicators, &"f".repeat(64));
        assert_eq!(first, second);
        assert_eq!(first.len(), 10);
        assert!(first.iter().any(|key| key.starts_with("Url:https://")));
        assert!(first.iter().any(|key| key.starts_with("Host:")));
        assert!(first.iter().any(|key| key.starts_with("Md5:")));
        assert!(first.iter().any(|key| key.starts_with("Sha256:")));
        assert!(first.contains("Url:https://example.test/A"));
        assert!(first.contains("Url:https://example.test/a"));
        assert!(first.contains("Host:other.test"));
        assert_eq!(
            first.iter().filter(|key| key.starts_with("Host:")).count(),
            5
        );
        assert!(!first.contains("Url:https://third.test/last"));
    }

    #[test]
    fn unallocated_urlhaus_request_is_reported_skipped_then_deduplicated_without_network() {
        let client = reqwest::blocking::Client::new();
        let mut state = UrlhausRequestState::default();
        let first = urlhaus_lookup_record(
            &client,
            "test-key",
            "https://example.test/a",
            IndicatorType::Url,
            crate::report::LookupSubject::ExtractedIndicator,
            &mut state,
            false,
        );
        let duplicate = urlhaus_lookup_record(
            &client,
            "test-key",
            "https://example.test/a",
            IndicatorType::Url,
            crate::report::LookupSubject::ExtractedIndicator,
            &mut state,
            false,
        );
        assert_eq!(first.outcome, LookupOutcome::SkippedLookupLimit);
        assert!(matches!(
            duplicate.outcome,
            LookupOutcome::SkippedDuplicate { .. }
        ));
        assert!(state.queried.is_empty());
        assert_eq!(state.seen.len(), 1);
    }

    #[test]
    fn provider_adapter_preserves_success_and_failure_categories() {
        let sample = MalwareSample {
            sha256_hash: "sha256".into(),
            first_seen: "2026-01-01".into(),
            file_name: "sample.bin".into(),
            file_type: "exe".into(),
            origin_country: None,
            signature: Some("Example".into()),
        };
        assert!(matches!(
            outcome_from_malwarebazaar_result(Ok(MalwareLookupResult::Found(sample)), "test-key"),
            LookupOutcome::Found(details)
                if details.matched_sha256 == "sha256" && details.sample_filename.as_deref() == Some("sample.bin")
        ));
        assert_eq!(
            outcome_from_malwarebazaar_result(Ok(MalwareLookupResult::NotFound), "test-key"),
            LookupOutcome::NotFound
        );
        assert!(matches!(
            outcome_from_malwarebazaar_result(
                Err(MalwareLookupError::Request("timeout".into())),
                "test-key"
            ),
            LookupOutcome::RequestError { .. }
        ));
        assert!(matches!(
            outcome_from_malwarebazaar_result(Err(MalwareLookupError::Http {
                status: 429,
                body: "detail".into(),
            }), "test-key"),
            LookupOutcome::ApiError { explanation } if explanation.contains("429")
        ));
        assert!(matches!(
            outcome_from_malwarebazaar_result(
                Err(MalwareLookupError::AuthenticationRejected { status: 403 }),
                "never-print-this-secret"
            ),
            LookupOutcome::ApiError { explanation }
                if explanation.contains("check ABUSECH_AUTH_KEY") && !explanation.contains("never-print-this-secret")
        ));
        assert_eq!(
            redact_secret("provider echoed secret", "secret"),
            "provider echoed [redacted]"
        );
    }

    #[test]
    fn threatfox_automatic_queries_are_deduplicated_and_capped() {
        let mut queried = HashSet::new();
        assert_eq!(
            claim_threatfox_lookup(&mut queried, "IP:192.0.2.1"),
            AutomaticLookup::Proceed
        );
        assert_eq!(
            claim_threatfox_lookup(&mut queried, "IP:192.0.2.1"),
            AutomaticLookup::Duplicate
        );
        for index in 1..MAX_AUTOMATIC_THREATFOX_LOOKUPS {
            assert_eq!(
                claim_threatfox_lookup(&mut queried, &format!("D:{index}")),
                AutomaticLookup::Proceed
            );
        }
        assert_eq!(queried.len(), MAX_AUTOMATIC_THREATFOX_LOOKUPS);
        assert_eq!(
            claim_threatfox_lookup(&mut queried, "D:overflow"),
            AutomaticLookup::Limit
        );
    }

    #[test]
    fn threatfox_allocation_round_robins_supported_types_after_original_hash() {
        let indicators = (0..20)
            .map(|index| Indicator::new(format!("{index:064x}"), IndicatorType::Hash))
            .chain([
                Indicator::new("192.0.2.10", IndicatorType::IP),
                Indicator::new("example.test", IndicatorType::Domain),
                Indicator::new("192.0.2.10", IndicatorType::IP),
            ])
            .collect::<Vec<_>>();
        let original = "f".repeat(64);
        let allocation = allocate_threatfox_indicators(&indicators, &original);

        assert_eq!(allocation.len(), MAX_AUTOMATIC_THREATFOX_LOOKUPS - 1);
        assert!(!allocation.contains(&threatfox_indicator_key(IndicatorType::Hash, &original)));
        assert!(allocation.contains(&threatfox_indicator_key(IndicatorType::IP, "192.0.2.10")));
        assert!(allocation.contains(&threatfox_indicator_key(
            IndicatorType::Domain,
            "example.test"
        )));
        assert_eq!(
            allocation
                .iter()
                .filter(|key| key.starts_with("Hash:"))
                .count(),
            7
        );
        assert_eq!(
            allocation,
            allocate_threatfox_indicators(&indicators, &original),
            "allocation is deterministic for the same extraction order"
        );
    }

    #[test]
    fn threatfox_failures_remain_explicit_instead_of_becoming_negative_results() {
        assert!(matches!(
            threatfox_error_outcome(ThreatFoxError::Request("timeout".into()), "secret"),
            LookupOutcome::RequestError { .. }
        ));
        assert!(matches!(
            threatfox_error_outcome(
                ThreatFoxError::Http {
                    status: 429,
                    body: "detail".into()
                },
                "secret"
            ),
            LookupOutcome::ApiError { explanation } if explanation.contains("429")
        ));
        assert!(matches!(
            threatfox_outcome(ThreatFoxLookupResult::Unsupported(
                "SHA-1 unsupported".into()
            )),
            LookupOutcome::Unsupported { .. }
        ));
    }

    #[test]
    fn pipeline_reads_current_file_and_generates_distinct_requests_without_leakage() {
        let temp_dir = std::env::temp_dir();
        let path1 = temp_dir.join(format!("cyberfeed-test-pipe1-{}.txt", std::process::id()));
        let path2 = temp_dir.join(format!("cyberfeed-test-pipe2-{}.txt", std::process::id()));

        let hash1 = "11".repeat(16);
        let ip1 = "198.51.100.1";
        let domain1 = "alpha-threat.test";
        std::fs::write(&path1, format!("{hash1}\n{ip1}\n{domain1}\n")).unwrap();

        let hash2 = "22".repeat(16);
        let ip2 = "203.0.113.2";
        let domain2 = "beta-threat.test";
        std::fs::write(&path2, format!("{hash2}\n{ip2}\n{domain2}\n")).unwrap();

        let insp1 = inspect_file(&path1).expect("file 1 inspection");
        let inds1 = insp1.text_indicators.expect("file 1 text").indicators;
        assert_eq!(inds1.len(), 3);
        assert_eq!(inds1[0].value, hash1);
        assert_eq!(inds1[1].value, ip1);
        assert_eq!(inds1[2].value, domain1);

        let client = reqwest::blocking::Client::new();
        let tf_req1 = crate::providers::threatfox::request_for_indicator(&inds1[1]).unwrap();
        let _ = crate::providers::threatfox::build_lookup_request(&client, "auth-key", &tf_req1)
            .unwrap();
        let tf_body1 = format!("{:?}", tf_req1);
        assert!(tf_body1.contains(ip1));
        assert!(!tf_body1.contains(ip2));

        let mb_built1 =
            crate::providers::malwarebazaar::build_hash_lookup_request(&client, "auth-key", &hash1)
                .unwrap();
        let mb_body1 =
            String::from_utf8_lossy(mb_built1.body().unwrap().as_bytes().unwrap()).into_owned();
        assert!(mb_body1.contains(&hash1));
        assert!(!mb_body1.contains(&hash2));

        let insp2 = inspect_file(&path2).expect("file 2 inspection");
        let inds2 = insp2.text_indicators.expect("file 2 text").indicators;
        assert_eq!(inds2.len(), 3);
        assert_eq!(inds2[0].value, hash2);
        assert_eq!(inds2[1].value, ip2);
        assert_eq!(inds2[2].value, domain2);

        assert_ne!(insp1.info.sha256, insp2.info.sha256);
        assert!(
            !inds2
                .iter()
                .any(|i| i.value == hash1 || i.value == ip1 || i.value == domain1)
        );

        let tf_req2 = crate::providers::threatfox::request_for_indicator(&inds2[1]).unwrap();
        let tf_body2 = format!("{:?}", tf_req2);
        assert!(tf_body2.contains(ip2));
        assert!(!tf_body2.contains(ip1));

        let mb_built2 =
            crate::providers::malwarebazaar::build_hash_lookup_request(&client, "auth-key", &hash2)
                .unwrap();
        let mb_body2 =
            String::from_utf8_lossy(mb_built2.body().unwrap().as_bytes().unwrap()).into_owned();
        assert!(mb_body2.contains(&hash2));
        assert!(!mb_body2.contains(&hash1));

        let _ = std::fs::remove_file(path1);
        let _ = std::fs::remove_file(path2);
    }

    #[test]
    fn different_indicators_remain_distinct_and_independent_records() {
        let client = reqwest::blocking::Client::new();
        let ind1 = "198.51.100.1";
        let ind2 = "203.0.113.2";

        let mut queries = HashSet::new();
        let rec1 = threatfox_lookup_record(
            &client,
            "",
            ind1,
            IndicatorType::IP,
            LookupSubject::ExtractedIndicator,
            &mut queries,
            true,
        );
        let rec2 = threatfox_lookup_record(
            &client,
            "",
            ind2,
            IndicatorType::IP,
            LookupSubject::ExtractedIndicator,
            &mut queries,
            true,
        );

        assert_eq!(rec1.queried_hash, ind1);
        assert_eq!(rec2.queried_hash, ind2);
        assert_ne!(rec1.queried_hash, rec2.queried_hash);
    }
}
