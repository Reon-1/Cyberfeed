use super::provider_views;
use super::terminal::{self, InputEditor};
use crate::file::{inspect_file, normalize_user_path};
use crate::indicator::{Indicator, IndicatorType, MANUAL_HASH_LENGTHS, classify};
use crate::investigation::Investigation;
use crate::malwarebazaar::{
    MalwareLookupError, MalwareLookupResult, MalwareSample, lookup_malware_hash,
};
use crate::report::{
    self, InvestigationReport, LookupOutcome, LookupSubject, MatchDetails, ProviderLookup,
    ThreatFoxFinding,
};
use crate::threatfox::{self, ThreatFoxError, ThreatFoxLookupResult};
use crate::ui;
use reqwest::blocking::Client;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

mod results;

const MAX_AUTOMATIC_MALWAREBAZAAR_LOOKUPS: usize = 10;
const MAX_AUTOMATIC_THREATFOX_LOOKUPS: usize = 10;

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
    let threatfox_allocation = allocate_threatfox_indicators(
        text_indicators
            .as_ref()
            .map(|text| text.indicators.as_slice())
            .unwrap_or_default(),
        &file_hash,
    );
    let lookup_total = 2 + text_indicators
        .as_ref()
        .map_or(0, |text| text.indicators.len() * 2);
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

                investigation.add_indicator(extracted.value.clone(), extracted.indicator_type);
            }
        }
        _ => {}
    }

    progress.finish();
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
        let extraction = inspection_extraction_state(&text_indicators);
        let indicators = text_indicators
            .as_ref()
            .map(|text| text.indicators.clone())
            .unwrap_or_default();
        // Build the export snapshot from this file's findings and lookups. The
        // session collection is separate and may also contain unrelated inputs.
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
    ui::box_line("  CyberFeed will not execute or upload the file contents.");
    ui::box_line(
        "  Configured providers receive the file SHA-256 and supported extracted indicators for lookup.",
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
        provider_record(
            hash,
            LookupSubject::ExtractedIndicatorSha256,
            None,
            LookupOutcome::NotConfigured,
        )
    } else if should_lookup_hash(looked_up, hash) {
        let outcome = lookup_hash_record(client, auth_key, hash);
        provider_record(
            hash,
            LookupSubject::ExtractedIndicatorSha256,
            Some(now_seconds()),
            outcome,
        )
    } else if looked_up.contains(&hash.to_ascii_lowercase()) {
        provider_record(
            hash,
            LookupSubject::ExtractedIndicatorSha256,
            None,
            LookupOutcome::SkippedDuplicate {
                references_hash: hash.to_ascii_lowercase(),
            },
        )
    } else {
        provider_record(
            hash,
            LookupSubject::ExtractedIndicatorSha256,
            None,
            LookupOutcome::SkippedLookupLimit,
        )
    }
}

fn threatfox_lookup_record(
    client: &Client,
    auth_key: &str,
    value: &str,
    indicator_type: IndicatorType,
    subject: LookupSubject,
    queried: &mut HashSet<String>,
    allow_query: bool,
) -> ProviderLookup {
    let indicator = crate::indicator::Indicator::new(value, indicator_type);
    let key = threatfox_indicator_key(indicator_type, value);
    let outcome = if let Err(result) = threatfox::request_for_indicator(&indicator) {
        threatfox_outcome(result)
    } else if auth_key.trim().is_empty() {
        LookupOutcome::NotConfigured
    } else if queried.contains(&key) {
        LookupOutcome::SkippedDuplicate {
            references_hash: value.to_ascii_lowercase(),
        }
    } else if !allow_query {
        LookupOutcome::SkippedLookupLimit
    } else {
        match claim_threatfox_lookup(queried, &key) {
            AutomaticLookup::Duplicate => LookupOutcome::SkippedDuplicate {
                references_hash: value.to_ascii_lowercase(),
            },
            AutomaticLookup::Limit => LookupOutcome::SkippedLookupLimit,
            AutomaticLookup::Proceed => {
                match threatfox::lookup_indicator(client, Some(auth_key), &indicator) {
                    Ok(result) => threatfox_outcome(result),
                    Err(error) => threatfox_error_outcome(error),
                }
            }
        }
    };
    let requested = !matches!(
        outcome,
        LookupOutcome::NotConfigured
            | LookupOutcome::Unsupported { .. }
            | LookupOutcome::Invalid { .. }
            | LookupOutcome::SkippedDuplicate { .. }
            | LookupOutcome::SkippedLookupLimit
    );
    ProviderLookup {
        provider: "ThreatFox".into(),
        subject,
        queried_hash: value.into(),
        retrieved_at_unix_seconds: requested.then(now_seconds),
        outcome,
    }
}

fn threatfox_indicator_key(indicator_type: IndicatorType, value: &str) -> String {
    format!("{indicator_type:?}:{}", value.to_ascii_lowercase())
}

/// Reserve the original file hash first, then rotate through hash, IP, and
/// domain queues so a large hash list cannot starve the other supported types.
fn allocate_threatfox_indicators(
    indicators: &[Indicator],
    original_file_hash: &str,
) -> HashSet<String> {
    let mut seen = HashSet::from([threatfox_indicator_key(
        IndicatorType::Hash,
        original_file_hash,
    )]);
    let mut queues: [Vec<String>; 3] = std::array::from_fn(|_| Vec::new());
    for indicator in indicators {
        let key = threatfox_indicator_key(indicator.indicator_type, &indicator.value);
        if seen.insert(key.clone()) && threatfox::request_for_indicator(indicator).is_ok() {
            queues[indicator_queue_index(indicator.indicator_type)].push(key);
        }
    }

    let mut selected = HashSet::new();
    let mut cursors = [0; 3];
    let mut next_type = 0;
    while selected.len() < MAX_AUTOMATIC_THREATFOX_LOOKUPS.saturating_sub(1) {
        let Some(queue_index) = (0..3)
            .map(|offset| (next_type + offset) % 3)
            .find(|index| cursors[*index] < queues[*index].len())
        else {
            break;
        };
        selected.insert(queues[queue_index][cursors[queue_index]].clone());
        cursors[queue_index] += 1;
        next_type = (queue_index + 1) % 3;
    }
    selected
}

fn indicator_queue_index(indicator_type: IndicatorType) -> usize {
    match indicator_type {
        IndicatorType::Hash => 0,
        IndicatorType::IP => 1,
        IndicatorType::Domain => 2,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum AutomaticLookup {
    Proceed,
    Duplicate,
    Limit,
}

fn claim_threatfox_lookup(queried: &mut HashSet<String>, key: &str) -> AutomaticLookup {
    if queried.contains(key) {
        return AutomaticLookup::Duplicate;
    }
    if queried.len() >= MAX_AUTOMATIC_THREATFOX_LOOKUPS {
        return AutomaticLookup::Limit;
    }
    queried.insert(key.to_owned());
    AutomaticLookup::Proceed
}

fn should_query_threatfox(
    auth_key: &str,
    indicator: &Indicator,
    queried: &HashSet<String>,
    allow_query: bool,
) -> bool {
    let key = threatfox_indicator_key(indicator.indicator_type, &indicator.value);
    !auth_key.trim().is_empty()
        && allow_query
        && !queried.contains(&key)
        && queried.len() < MAX_AUTOMATIC_THREATFOX_LOOKUPS
        && threatfox::request_for_indicator(indicator).is_ok()
}

fn threatfox_outcome(result: ThreatFoxLookupResult) -> LookupOutcome {
    match result {
        ThreatFoxLookupResult::Found(findings) => LookupOutcome::ThreatFoxFound {
            findings: findings
                .into_iter()
                .map(|finding| ThreatFoxFinding {
                    source_record_id: finding.id,
                    ioc: finding.ioc,
                    ioc_type: finding.ioc_type,
                    ioc_type_description: finding.ioc_type_desc,
                    threat_type: finding.threat_type,
                    threat_type_description: finding.threat_type_desc,
                    malware: finding.malware,
                    malware_printable: finding.malware_printable,
                    confidence_level: finding.confidence_level,
                    first_seen: finding.first_seen,
                    last_seen: finding.last_seen,
                    reference: finding.reference,
                    reporter: finding.reporter,
                    tags: finding.tags.unwrap_or_default(),
                })
                .collect(),
        },
        ThreatFoxLookupResult::NotFound => LookupOutcome::NotFound,
        ThreatFoxLookupResult::InvalidInput(explanation) => LookupOutcome::Invalid { explanation },
        ThreatFoxLookupResult::Unsupported(explanation) => {
            LookupOutcome::Unsupported { explanation }
        }
        ThreatFoxLookupResult::NotConfigured => LookupOutcome::NotConfigured,
        ThreatFoxLookupResult::ProviderError(explanation) => {
            LookupOutcome::ApiError { explanation }
        }
    }
}

fn threatfox_error_outcome(error: ThreatFoxError) -> LookupOutcome {
    match error {
        ThreatFoxError::Request(explanation) => LookupOutcome::RequestError { explanation },
        ThreatFoxError::Http { status, .. } => LookupOutcome::ApiError {
            explanation: format!("ThreatFox returned HTTP {status}."),
        },
        ThreatFoxError::Parse(explanation) => LookupOutcome::ApiError {
            explanation: format!("ThreatFox response could not be parsed: {explanation}"),
        },
    }
}

fn lookup_hash_record(client: &Client, auth_key: &str, hash: &str) -> LookupOutcome {
    let result = lookup_malware_hash(client, auth_key, hash);
    outcome_from_malwarebazaar_result(result, auth_key)
}

fn redact_secret(message: &str, secret: &str) -> String {
    if secret.is_empty() {
        message.to_owned()
    } else {
        message.replace(secret, "[redacted]")
    }
}

/// Adapt the provider's response types into the shared evidence model at the
/// workflow boundary, keeping report serialization independent of the client.
fn outcome_from_malwarebazaar_result(
    result: Result<MalwareLookupResult, MalwareLookupError>,
    auth_key: &str,
) -> LookupOutcome {
    match result {
        Ok(MalwareLookupResult::Found(sample)) => {
            LookupOutcome::Found(malware_sample_details(sample))
        }
        Ok(MalwareLookupResult::NotFound) => LookupOutcome::NotFound,
        Ok(MalwareLookupResult::InvalidHash(explanation)) => LookupOutcome::Invalid { explanation },
        Ok(MalwareLookupResult::ApiError(explanation)) => LookupOutcome::ApiError { explanation },
        Err(MalwareLookupError::Request(message)) => LookupOutcome::RequestError {
            explanation: redact_secret(&message.replace(['\n', '\r'], " "), auth_key),
        },
        Err(MalwareLookupError::AuthenticationRejected { status }) => LookupOutcome::ApiError {
            explanation: format!(
                "MalwareBazaar rejected the configured Auth-Key (HTTP {status}); check ABUSECH_AUTH_KEY."
            ),
        },
        Err(MalwareLookupError::Http { status, .. }) => LookupOutcome::ApiError {
            explanation: format!("MalwareBazaar returned HTTP {status}."),
        },
        Err(MalwareLookupError::Parse(message)) => LookupOutcome::ApiError {
            explanation: redact_secret(
                &format!("Could not parse MalwareBazaar response: {message}"),
                auth_key,
            ),
        },
    }
}

fn malware_sample_details(sample: MalwareSample) -> MatchDetails {
    MatchDetails {
        matched_sha256: sample.sha256_hash,
        first_seen: sample.first_seen,
        file_type: sample.file_type,
        sample_filename: (!sample.file_name.is_empty()).then_some(sample.file_name),
        signature: sample.signature,
    }
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

fn hash_request_available(auth_key: &str, looked_up: &HashSet<String>, hash: &str) -> bool {
    !auth_key.trim().is_empty()
        && looked_up.len() < MAX_AUTOMATIC_MALWAREBAZAAR_LOOKUPS
        && !looked_up.contains(&hash.to_ascii_lowercase())
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
    ui::box_line("  Configured providers receive this indicator value for lookup.");
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
    let mut lookups = Vec::new();
    if matches!(indicator_type, IndicatorType::Hash) {
        let mb_outcome = if auth_key.trim().is_empty() {
            LookupOutcome::NotConfigured
        } else {
            lookup_hash_record(client, auth_key, &value)
        };
        lookups.push(provider_record(
            &value,
            LookupSubject::ExtractedIndicatorSha256,
            None,
            mb_outcome,
        ));
    } else {
        lookups.push(provider_record(
            &value,
            LookupSubject::ExtractedIndicator,
            None,
            LookupOutcome::Unsupported {
                explanation: "MalwareBazaar hash lookups do not support IP/domain indicators."
                    .into(),
            },
        ));
    }
    let mut queries = HashSet::new();
    let lookup = threatfox_lookup_record(
        client,
        auth_key,
        &value,
        indicator_type,
        LookupSubject::ExtractedIndicator,
        &mut queries,
        true,
    );
    lookups.push(lookup);

    terminal::clear_screen();
    ui::header("INDICATOR CHECK", "Completed provider observations");
    ui::section("INDICATOR");
    ui::indicator_details(indicator_type.as_str(), &value);
    ui::section("PROVIDER RESULTS");
    for record in lookups {
        provider_views::display_lookup(&record.provider, &record.queried_hash, &record.outcome);
        investigation.add_provider_lookup(record);
    }
    if investigation
        .provider_lookups()
        .iter()
        .any(|record| record.outcome == LookupOutcome::NotFound)
    {
        ui::warning("NOT FOUND is a provider response at lookup time, not a safety verdict.");
    }
    ui::close_box();
    terminal::pause();
}

pub(super) fn view_indicators(investigation: &Investigation) {
    terminal::clear_screen();
    ui::header("COLLECTED INDICATORS", "Evidence in this investigation");
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
    terminal::pause();
}

#[cfg(test)]
mod tests {
    use super::{
        AutomaticLookup, MAX_AUTOMATIC_MALWAREBAZAAR_LOOKUPS, MAX_AUTOMATIC_THREATFOX_LOOKUPS,
        allocate_threatfox_indicators, claim_threatfox_lookup, outcome_from_malwarebazaar_result,
        redact_secret, should_lookup_hash, threatfox_error_outcome, threatfox_indicator_key,
        threatfox_outcome,
    };
    use crate::indicator::{Indicator, IndicatorType};
    use crate::malwarebazaar::{MalwareLookupError, MalwareLookupResult, MalwareSample};
    use crate::report::LookupOutcome;
    use crate::threatfox::{ThreatFoxError, ThreatFoxLookupResult};
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
            threatfox_error_outcome(ThreatFoxError::Request("timeout".into())),
            LookupOutcome::RequestError { .. }
        ));
        assert!(matches!(
            threatfox_error_outcome(ThreatFoxError::Http { status: 429, body: "detail".into() }),
            LookupOutcome::ApiError { explanation } if explanation.contains("429")
        ));
        assert!(matches!(
            threatfox_outcome(ThreatFoxLookupResult::Unsupported(
                "SHA-1 unsupported".into()
            )),
            LookupOutcome::Unsupported { .. }
        ));
    }
}
