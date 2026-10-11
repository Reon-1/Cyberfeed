use super::{
    IndicatorEntry, LiveProgress, OutcomeCounts, Selection, extracted_outcome_counts,
    matched_indicator_count, overview_value, page_capacity, page_count, parse_selection,
    provider_summary,
};
use crate::indicator::IndicatorType;
use crate::report::{LookupOutcome, LookupSubject, MatchDetails, ProviderLookup, ThreatFoxFinding};

fn record(outcome: LookupOutcome) -> ProviderLookup {
    ProviderLookup {
        provider: "ThreatFox".into(),
        subject: LookupSubject::ExtractedIndicator,
        queried_hash: "192.0.2.1".into(),
        retrieved_at_unix_seconds: Some(1),
        outcome,
    }
}

#[test]
fn live_progress_advances_once_for_each_recorded_provider_outcome() {
    let mut progress = LiveProgress {
        total: 2,
        completed: 0,
    };
    progress.completed("ThreatFox", "example.test", &LookupOutcome::NotFound);
    assert_eq!(progress.completed, 1);
    progress.completed("MalwareBazaar", "abcd", &LookupOutcome::NotConfigured);
    assert_eq!(progress.completed, progress.total);
}

#[test]
fn provider_summary_counts_each_recorded_outcome_once_by_category() {
    let mut counts = OutcomeCounts::default();
    for outcome in [
        LookupOutcome::NotFound,
        LookupOutcome::Found(crate::report::MatchDetails {
            matched_sha256: "hash".into(),
            first_seen: "today".into(),
            file_type: "PE32".into(),
            sample_filename: None,
            signature: None,
        }),
        LookupOutcome::ThreatFoxFound { findings: vec![] },
        LookupOutcome::Invalid {
            explanation: "invalid".into(),
        },
        LookupOutcome::NotConfigured,
        LookupOutcome::Unsupported {
            explanation: "unsupported".into(),
        },
        LookupOutcome::SkippedLookupLimit,
        LookupOutcome::SkippedDuplicate {
            references_hash: "prior".into(),
        },
        LookupOutcome::ApiError {
            explanation: "failure".into(),
        },
        LookupOutcome::RequestError {
            explanation: "offline".into(),
        },
    ] {
        counts.record(&outcome);
    }
    assert_eq!(counts.not_found, 1);
    assert_eq!(counts.found, 2);
    assert_eq!(counts.errors, 3);
    assert_eq!(counts.unconfigured, 1);
    assert_eq!(counts.unsupported, 1);
    assert_eq!(counts.skipped, 2);
    assert_eq!(
        counts.summary(),
        "FOUND 2 · NOT FOUND 1 · ERROR 3 · UNSUPPORTED 1 · NOT CONFIGURED 1 · SKIPPED 2"
    );
}

#[test]
fn overview_finding_labels_use_provider_fields_and_fallback_to_record_found() {
    let malware = ProviderLookup {
        provider: "MalwareBazaar".into(),
        ..record(LookupOutcome::Found(MatchDetails {
            matched_sha256: "queried".into(),
            first_seen: "today".into(),
            file_type: "PE32".into(),
            sample_filename: None,
            signature: Some("Formbook".into()),
        }))
    };
    let threatfox = ProviderLookup {
        provider: "ThreatFox".into(),
        outcome: LookupOutcome::ThreatFoxFound {
            findings: vec![ThreatFoxFinding {
                source_record_id: Some("7".into()),
                ioc: "192.0.2.1".into(),
                ioc_type: "ip:port".into(),
                ioc_type_description: None,
                threat_type: None,
                threat_type_description: Some("botnet C&C".into()),
                malware: None,
                malware_printable: None,
                confidence_level: None,
                first_seen: None,
                last_seen: None,
                reference: None,
                reporter: None,
                tags: vec![],
            }],
        },
        ..record(LookupOutcome::NotFound)
    };
    let entry = IndicatorEntry {
        value: "192.0.2.1",
        indicator_type: IndicatorType::IP,
        lookups: vec![&malware, &threatfox],
    };
    assert_eq!(provider_summary(&entry, "MalwareBazaar"), "FOUND: Formbook");
    assert_eq!(provider_summary(&entry, "ThreatFox"), "FOUND: botnet C&C");

    let no_name = ProviderLookup {
        provider: "MalwareBazaar".into(),
        ..record(LookupOutcome::Found(MatchDetails {
            matched_sha256: "queried".into(),
            first_seen: "today".into(),
            file_type: "".into(),
            sample_filename: None,
            signature: None,
        }))
    };
    let entry = IndicatorEntry {
        value: "hash",
        indicator_type: IndicatorType::Hash,
        lookups: vec![&no_name],
    };
    assert_eq!(provider_summary(&entry, "ThreatFox"), "—");
    assert_eq!(
        provider_summary(&entry, "MalwareBazaar"),
        "FOUND: Record found"
    );
}

#[test]
fn matched_indicator_count_counts_each_extracted_entry_only_when_a_record_exists() {
    let found = record(LookupOutcome::NotFound);
    let match_record = ProviderLookup {
        provider: "ThreatFox".into(),
        outcome: LookupOutcome::ThreatFoxFound { findings: vec![] },
        ..record(LookupOutcome::NotFound)
    };
    let entries = [
        IndicatorEntry {
            value: "one",
            indicator_type: IndicatorType::Domain,
            lookups: vec![&found],
        },
        IndicatorEntry {
            value: "two",
            indicator_type: IndicatorType::IP,
            lookups: vec![&match_record],
        },
    ];
    assert_eq!(matched_indicator_count(&entries), 1);
}

#[test]
fn extracted_provider_summary_does_not_count_the_separate_file_hash_observation() {
    let extracted = record(LookupOutcome::NotFound);
    let original = ProviderLookup {
        subject: LookupSubject::OriginalFileSha256,
        ..record(LookupOutcome::Found(crate::report::MatchDetails {
            matched_sha256: "filehash".into(),
            first_seen: "today".into(),
            file_type: "PE32".into(),
            sample_filename: None,
            signature: None,
        }))
    };
    let counts = extracted_outcome_counts(&[original, extracted], "ThreatFox");
    assert_eq!(counts.found, 0);
    assert_eq!(counts.not_found, 1);
}

#[test]
fn indicator_row_uses_provider_records_without_inventing_missing_states() {
    let lookup = record(LookupOutcome::NotFound);
    let entry = super::IndicatorEntry {
        value: "192.0.2.1",
        indicator_type: IndicatorType::IP,
        lookups: vec![&lookup],
    };
    assert_eq!(provider_summary(&entry, "ThreatFox"), "NOT FOUND");
    assert_eq!(provider_summary(&entry, "MalwareBazaar"), "—");
}

#[test]
fn selection_navigation_rejects_invalid_numbers_and_returns_to_save_on_zero() {
    assert_eq!(parse_selection("2", 0, 3), Selection::Open(1));
    assert_eq!(parse_selection("0", 0, 3), Selection::Continue);
    assert_eq!(parse_selection("4", 0, 3), Selection::Invalid);
    assert_eq!(parse_selection("n", 0, 3), Selection::Next);
    assert_eq!(parse_selection("p", 0, 3), Selection::Previous);
    assert_eq!(parse_selection("f", 0, 3), Selection::Original);
    assert_eq!(parse_selection("4", 3, 5), Selection::Open(3));
}

#[test]
fn page_capacity_adapts_to_terminal_dimensions_and_page_count_handles_edges() {
    assert_eq!(page_capacity(20, (80, 24)), 1);
    assert_eq!(page_capacity(20, (120, 40)), 4);
    assert_eq!(page_capacity(20, (40, 10)), 1);
    assert_eq!(page_count(0, 4), 0);
    assert_eq!(page_count(3, 4), 1);
    assert_eq!(page_count(9, 4), 3);
}

#[test]
fn overview_shortens_hash_visibly_while_details_keep_full_value() {
    let hash = "0123456789abcdef".repeat(4);
    let overview = overview_value(&hash, IndicatorType::Hash);
    assert!(overview.contains('…'));
    assert!(overview.starts_with(&hash[..12]));
    assert!(overview.ends_with(&hash[hash.len() - 8..]));
    assert_eq!(hash.len(), 64);
}
