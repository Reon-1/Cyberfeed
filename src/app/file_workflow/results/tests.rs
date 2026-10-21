use super::{
    IndicatorEntry, LiveProgress, OutcomeCounts, Selection, TABLE_PROVIDER_WIDTH,
    extracted_outcome_counts, fit_indicator, fit_text, indicator_entries, indicator_line_count,
    is_positive_match, matched_indicator_count, matched_type_counts, overview_layout,
    overview_value, page_capacity, page_count, page_for_indicator, parse_selection,
    provider_summary, table_widths,
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
        LookupOutcome::UrlhausFound {
            details: crate::report::UrlhausLookupDetails {
                reference: None,
                queried_host: Some("example.test".into()),
                associated_url_count: Some(1),
                md5_hash: None,
                sha256_hash: None,
                file_type: None,
                first_seen: None,
                last_seen: None,
                signature: None,
                associated_urls: vec![],
            },
        },
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
    assert_eq!(counts.found, 3);
    assert_eq!(counts.errors, 2);
    assert_eq!(counts.invalid, 1);
    assert_eq!(counts.unconfigured, 1);
    assert_eq!(counts.unsupported, 1);
    assert_eq!(counts.skipped_duplicate, 1);
    assert_eq!(counts.skipped_limit, 1);
    assert_eq!(
        counts.summary(),
        "FOUND 3 · NOT FOUND 1 · ERROR 2 · INVALID 1 · UNSUPPORTED 1 · NOT CONFIGURED 1 · SKIPPED DUPLICATE 1 · SKIPPED LIMIT 1"
    );
}

#[test]
fn positive_findings_are_summarized_by_indicator_type_without_counting_no_match_or_error() {
    let lookups = [
        record(LookupOutcome::NotFound),
        record(LookupOutcome::Found(MatchDetails {
            matched_sha256: "file-hash".into(),
            first_seen: "today".into(),
            file_type: "PE32".into(),
            sample_filename: None,
            signature: None,
        })),
        record(LookupOutcome::ApiError {
            explanation: "unavailable".into(),
        }),
        record(LookupOutcome::ThreatFoxFound { findings: vec![] }),
    ];
    let hash = "a".repeat(32);
    let entries = [
        IndicatorEntry {
            value: &hash,
            indicator_type: IndicatorType::Hash,
            lookups: vec![&lookups[0]],
        },
        IndicatorEntry {
            value: "192.0.2.1",
            indicator_type: IndicatorType::IP,
            lookups: vec![&lookups[1]],
        },
        IndicatorEntry {
            value: "example.test",
            indicator_type: IndicatorType::Domain,
            lookups: vec![&lookups[2]],
        },
        IndicatorEntry {
            value: "https://example.test/path",
            indicator_type: IndicatorType::Url,
            lookups: vec![&lookups[3]],
        },
    ];

    assert_eq!(matched_type_counts(&entries), [0, 1, 0, 1]);
}

#[test]
fn quick_summary_treats_only_provider_matches_as_positive_findings() {
    assert!(is_positive_match(&LookupOutcome::Found(MatchDetails {
        matched_sha256: "a".repeat(64),
        first_seen: "today".into(),
        file_type: "text".into(),
        sample_filename: None,
        signature: None,
    })));
    for outcome in [
        LookupOutcome::NotFound,
        LookupOutcome::NotConfigured,
        LookupOutcome::RequestError {
            explanation: "offline".into(),
        },
        LookupOutcome::Unsupported {
            explanation: "not supported".into(),
        },
        LookupOutcome::SkippedLookupLimit,
    ] {
        assert!(!is_positive_match(&outcome));
    }
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
    assert_eq!(
        provider_summary(&entry, "MalwareBazaar"),
        "FOUND · Formbook"
    );
    assert_eq!(provider_summary(&entry, "ThreatFox"), "FOUND · botnet C&C");

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
        "FOUND · Record found"
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
fn urlhaus_only_match_counts_once_even_when_exact_url_and_host_both_match() {
    let host = ProviderLookup {
        provider: "URLhaus".into(),
        subject: LookupSubject::ExtractedIndicator,
        queried_hash: "example.test".into(),
        retrieved_at_unix_seconds: Some(1),
        outcome: LookupOutcome::UrlhausFound {
            details: crate::report::UrlhausLookupDetails {
                reference: Some("https://urlhaus.abuse.ch/url/1/".into()),
                queried_host: None,
                associated_url_count: None,
                md5_hash: None,
                sha256_hash: None,
                file_type: None,
                first_seen: None,
                last_seen: None,
                signature: None,
                associated_urls: vec![],
            },
        },
    };
    let exact = ProviderLookup {
        provider: "URLhaus".into(),
        subject: LookupSubject::ExtractedIndicator,
        queried_hash: "https://example.test/dropper".into(),
        retrieved_at_unix_seconds: None,
        outcome: LookupOutcome::SkippedLookupLimit,
    };
    let not_found = record(LookupOutcome::NotFound);
    let entry = IndicatorEntry {
        value: "https://example.test/dropper",
        indicator_type: IndicatorType::Url,
        lookups: vec![&exact, &host, &not_found],
    };
    assert_eq!(matched_indicator_count(std::slice::from_ref(&entry)), 1);
    assert_eq!(provider_summary(&entry, "URLhaus"), "FOUND");
}

#[test]
fn urlhaus_table_labels_use_recorded_count_or_status_and_handle_missing_fields() {
    let details =
        |associated_url_count, status: Option<&str>| crate::report::UrlhausLookupDetails {
            reference: Some("https://urlhaus.abuse.ch/host/example.test/".into()),
            queried_host: Some("example.test".into()),
            associated_url_count,
            md5_hash: None,
            sha256_hash: None,
            file_type: None,
            first_seen: None,
            last_seen: None,
            signature: None,
            associated_urls: status
                .map(|status| {
                    vec![crate::report::UrlhausUrlRecord {
                        reference: None,
                        url: "https://example.test/dropper".into(),
                        status: Some(status.into()),
                        host: None,
                        date_added: None,
                        first_seen: None,
                        last_seen: None,
                        threat: None,
                        tags: vec![],
                    }]
                })
                .unwrap_or_default(),
        };
    let summary = |details| {
        let lookup = ProviderLookup {
            provider: "URLhaus".into(),
            outcome: LookupOutcome::UrlhausFound { details },
            ..record(LookupOutcome::NotFound)
        };
        let entry = super::IndicatorEntry {
            value: "example.test",
            indicator_type: IndicatorType::Domain,
            lookups: vec![&lookup],
        };
        provider_summary(&entry, "URLhaus")
    };

    assert_eq!(summary(details(Some(3), Some("online"))), "FOUND · 3 URLs");
    assert_eq!(summary(details(None, Some("offline"))), "FOUND · Offline");
    assert_eq!(summary(details(None, None)), "FOUND");
}

#[test]
fn provider_summary_cell_truncates_only_the_display_value_at_narrow_widths() {
    let lookup = ProviderLookup {
        provider: "MalwareBazaar".into(),
        outcome: LookupOutcome::Found(MatchDetails {
            matched_sha256: "queried".into(),
            first_seen: "today".into(),
            file_type: "PE32".into(),
            sample_filename: None,
            signature: Some("A very long malware family name".into()),
        }),
        ..record(LookupOutcome::NotFound)
    };
    let entry = super::IndicatorEntry {
        value: "hash",
        indicator_type: IndicatorType::Hash,
        lookups: vec![&lookup],
    };
    let display = super::provider_summary_cell(&entry, "MalwareBazaar", 8);
    assert!(display.contains("FOUND ·…"));
    assert!(!display.contains("A very long malware family name"));
    assert_eq!(lookup.queried_hash, "192.0.2.1");
}

#[test]
fn multiple_providers_matching_one_indicator_count_once_and_failures_are_not_matches() {
    let mb = ProviderLookup {
        provider: "MalwareBazaar".into(),
        outcome: LookupOutcome::Found(MatchDetails {
            matched_sha256: "x".into(),
            first_seen: "today".into(),
            file_type: "exe".into(),
            sample_filename: None,
            signature: None,
        }),
        ..record(LookupOutcome::NotFound)
    };
    let urlhaus = ProviderLookup {
        provider: "URLhaus".into(),
        outcome: LookupOutcome::UrlhausFound {
            details: crate::report::UrlhausLookupDetails {
                reference: None,
                queried_host: None,
                associated_url_count: None,
                md5_hash: None,
                sha256_hash: None,
                file_type: None,
                first_seen: None,
                last_seen: None,
                signature: None,
                associated_urls: vec![],
            },
        },
        ..record(LookupOutcome::NotFound)
    };
    let failure = record(LookupOutcome::RequestError {
        explanation: "timeout".into(),
    });
    let skipped = ProviderLookup {
        outcome: LookupOutcome::SkippedLookupLimit,
        ..record(LookupOutcome::NotFound)
    };
    let found_entry = IndicatorEntry {
        value: "hash",
        indicator_type: IndicatorType::Hash,
        lookups: vec![&mb, &urlhaus],
    };
    let failed_entry = IndicatorEntry {
        value: "failed",
        indicator_type: IndicatorType::Domain,
        lookups: vec![&failure, &skipped],
    };
    assert_eq!(matched_indicator_count(&[found_entry, failed_entry]), 1);
}

#[test]
fn original_file_positive_lookup_is_not_an_extracted_indicator_match() {
    let original = ProviderLookup {
        provider: "URLhaus".into(),
        subject: LookupSubject::OriginalFileSha256,
        queried_hash: "f".repeat(64),
        retrieved_at_unix_seconds: Some(1),
        outcome: LookupOutcome::UrlhausFound {
            details: crate::report::UrlhausLookupDetails {
                reference: None,
                queried_host: None,
                associated_url_count: None,
                md5_hash: None,
                sha256_hash: None,
                file_type: None,
                first_seen: None,
                last_seen: None,
                signature: None,
                associated_urls: vec![],
            },
        },
    };
    let extraction = crate::file::TextIndicators {
        indicators: vec![crate::indicator::Indicator::new(
            "192.0.2.8",
            IndicatorType::IP,
        )],
        limit_reached: false,
    };
    let original_lookups = [original];
    let entries = indicator_entries(Some(&extraction), &original_lookups);
    assert_eq!(matched_indicator_count(&entries), 0);
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
    assert_eq!(page_capacity(20, (80, 32)), 2);
    assert_eq!(page_capacity(20, (112, 40)), 2);
    assert_eq!(page_capacity(20, (80, 40)), 1);
    assert_eq!(page_capacity(20, (40, 10)), 1);
    assert_eq!(page_capacity(20, (18, 24)), 1);
    assert_eq!(page_count(0, 4), 0);
    assert_eq!(page_count(3, 4), 1);
    assert_eq!(page_count(9, 4), 3);
    assert_eq!(
        overview_layout(20, (80, 24)),
        super::OverviewLayout {
            compact: true,
            table: false,
            capacity: 1
        }
    );
    assert_eq!(
        overview_layout(20, (80, 32)),
        super::OverviewLayout {
            compact: true,
            table: false,
            capacity: 2
        }
    );
    assert_eq!(
        overview_layout(20, (112, 40)),
        super::OverviewLayout {
            compact: false,
            table: true,
            capacity: 2
        }
    );
    assert_eq!(
        overview_layout(20, (30, 24)),
        super::OverviewLayout {
            compact: true,
            table: false,
            capacity: 1
        }
    );
}

#[test]
fn table_widths_fit_common_and_maximum_panels_without_overflow() {
    assert!(!table_widths(72).table);
    assert!(!table_widths(78).table);
    let common = table_widths(96);
    assert!(common.table);
    assert_eq!(common.indicator, 26);
    assert_eq!(common.indicator + 70, 96);
    let wide = table_widths(112);
    assert!(wide.table);
    assert_eq!(wide.indicator + 70, 112);
    let long_url = "https://example.test/a/very/long/path?query=long";
    let clipped = fit_indicator(long_url, IndicatorType::Url, common.indicator);
    assert!(clipped.starts_with("https://example.test"));
    assert!(clipped.ends_with("=long"));
    assert_ne!(
        clipped,
        fit_indicator(
            "https://example.test/a/very/long/path?query=other",
            IndicatorType::Url,
            common.indicator
        )
    );
    let hash = "0123456789abcdef".repeat(4);
    let compact_hash = fit_indicator(&hash, IndicatorType::Hash, 14);
    assert_eq!(compact_hash.chars().count(), 14);
    assert!(compact_hash.starts_with("0123456"));
    assert!(compact_hash.ends_with("abcdef"));
    assert_eq!(
        fit_text("NOT CONFIGURED", TABLE_PROVIDER_WIDTH),
        "NOT CONFIGURED"
    );
    assert_eq!(
        fit_text("FOUND · Offline", TABLE_PROVIDER_WIDTH),
        "FOUND · Offline"
    );
    assert_eq!(
        fit_text("FOUND · Online", TABLE_PROVIDER_WIDTH),
        "FOUND · Online"
    );
    assert_eq!(
        fit_text("FOUND · 100 URLs", TABLE_PROVIDER_WIDTH),
        "FOUND · 100 URLs"
    );
    for label in ["ERROR", "NOT FOUND", "SKIP LIMIT", "SKIP DUPLICATE"] {
        assert_eq!(fit_text(label, TABLE_PROVIDER_WIDTH), label);
    }
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

#[test]
fn page_capacity_at_representative_sizes_matches_actual_available_rows() {
    // Compact stacked mode uses four rendered lines per indicator.
    // 80×24 leaves too little room for one complete four-line result.
    assert_eq!(page_capacity(21, (80, 24)), 1);
    // 80×30: (30-22)/4 = 2
    assert_eq!(page_capacity(21, (80, 30)), 2);
    // 80×34: (34-22)/4 = 3
    assert_eq!(page_capacity(21, (80, 34)), 3);

    // Regular stacked mode (rows >= 36, cols < 88): reserved=38, lines=4.
    // 80×40: (40-38)/4 = 0 → max(1) = 1
    assert_eq!(page_capacity(21, (80, 40)), 1);
    // 80×50: (50-38)/4 = 3
    assert_eq!(page_capacity(21, (80, 50)), 3);
    // 80×60: (60-38)/4 = 5
    assert_eq!(page_capacity(21, (80, 60)), 5);

    // Wide compact mode now renders table rows, matching its one-line capacity.
    assert_eq!(page_capacity(21, (112, 24)), 2);
    assert_eq!(page_capacity(21, (112, 30)), 8);
    // Regular table mode (rows >= 36, cols >= 88): one rendered line per row.
    // 112×40: (40-38)/1 = 2
    assert_eq!(page_capacity(21, (112, 40)), 2);
    // 120×50: (50-38)/1 = 12
    assert_eq!(page_capacity(21, (120, 50)), 12);
    // 120×70: (70-38)/1 = 32, capped at min(21)
    assert_eq!(page_capacity(21, (120, 70)), 21);

    // Page counts for a 21-indicator investigation at two representative sizes.
    // 80×40 stacked → 1/page → 21 pages (correct for a very constrained terminal).
    assert_eq!(page_count(21, page_capacity(21, (80, 40))), 21);
    // 112×40 table → 2/page → 11 pages.
    assert_eq!(page_count(21, page_capacity(21, (112, 40))), 11);
}

#[test]
fn selected_layout_matches_indicator_rendered_line_count_at_switch_boundaries() {
    for dimensions in [(80, 24), (80, 40), (112, 24), (112, 30), (112, 40)] {
        let layout = overview_layout(21, dimensions);
        assert_eq!(
            indicator_line_count(layout),
            if layout.table { 1 } else { 4 },
            "layout and renderer disagree for {dimensions:?}"
        );
    }
    assert!(!overview_layout(21, (87, 40)).table);
    assert!(overview_layout(21, (88, 40)).table);
    assert!(overview_layout(21, (112, 35)).compact);
    assert!(!overview_layout(21, (112, 36)).compact);
}

#[test]
fn resize_keeps_the_current_first_indicator_as_close_as_new_pages_allow() {
    let anchor = 8usize;
    let smaller_capacity = page_capacity(21, (112, 40));
    let page = page_for_indicator(anchor, smaller_capacity);
    assert_eq!(page * smaller_capacity, anchor);

    let larger_capacity = page_capacity(21, (112, 30));
    let page = page_for_indicator(anchor, larger_capacity);
    assert!(page * larger_capacity <= anchor);
    assert!(anchor < (page + 1) * larger_capacity);
}

#[test]
fn provider_summary_preserves_full_malware_name_and_all_outcome_labels_are_distinct() {
    // Full malware family name is preserved in provider_summary (the value that
    // goes on to the details screen). The table-cell truncation happens only in
    // provider_summary_cell, not in the underlying evidence record.
    let mountlocker = ProviderLookup {
        provider: "ThreatFox".into(),
        outcome: LookupOutcome::ThreatFoxFound {
            findings: vec![ThreatFoxFinding {
                source_record_id: None,
                ioc: "192.0.2.1".into(),
                ioc_type: "ip:port".into(),
                ioc_type_description: None,
                threat_type: None,
                threat_type_description: None,
                malware: None,
                malware_printable: Some("MountLocker".into()),
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
        lookups: vec![&mountlocker],
    };
    // Full name accessible for details rendering.
    let full = provider_summary(&entry, "ThreatFox");
    assert_eq!(full, "FOUND · MountLocker");
    assert!(
        full.contains("MountLocker"),
        "full malware name in provider_summary"
    );

    // Compact table cell truncates at TABLE_PROVIDER_WIDTH (16); full name is
    // not lost — it is reachable from the details screen.
    let cell = super::provider_summary_cell(&entry, "ThreatFox", TABLE_PROVIDER_WIDTH);
    assert!(
        cell.contains("FOUND"),
        "FOUND label survives cell truncation"
    );
    assert!(
        !cell.contains("MountLocker"),
        "name longer than TABLE_PROVIDER_WIDTH is truncated in the overview table cell"
    );

    // All non-match outcome labels are distinct; none collapses to another.
    let make = |outcome: LookupOutcome| ProviderLookup {
        provider: "ThreatFox".into(),
        subject: LookupSubject::ExtractedIndicator,
        queried_hash: "example.test".into(),
        retrieved_at_unix_seconds: None,
        outcome,
    };
    let check = |outcome: LookupOutcome, expected: &str| {
        let lookup = make(outcome);
        let e = IndicatorEntry {
            value: "example.test",
            indicator_type: IndicatorType::Domain,
            lookups: vec![&lookup],
        };
        assert_eq!(provider_summary(&e, "ThreatFox"), expected);
    };

    check(LookupOutcome::NotFound, "NOT FOUND");
    check(
        LookupOutcome::ApiError {
            explanation: "server error".into(),
        },
        "ERROR",
    );
    check(
        LookupOutcome::RequestError {
            explanation: "timed out".into(),
        },
        "ERROR",
    );
    check(
        LookupOutcome::Unsupported {
            explanation: "hash only".into(),
        },
        "UNSUPPORTED",
    );
    check(LookupOutcome::NotConfigured, "NOT CONFIGURED");
    check(
        LookupOutcome::SkippedDuplicate {
            references_hash: "prior".into(),
        },
        "SKIP DUPLICATE",
    );
    check(LookupOutcome::SkippedLookupLimit, "SKIP LIMIT");

    // ERROR and NOT FOUND must not be interchangeable — a provider failure is
    // not a negative result.
    assert_ne!(
        {
            let l = make(LookupOutcome::ApiError {
                explanation: "e".into(),
            });
            let e = IndicatorEntry {
                value: "x",
                indicator_type: IndicatorType::IP,
                lookups: vec![&l],
            };
            provider_summary(&e, "ThreatFox")
        },
        {
            let l = make(LookupOutcome::NotFound);
            let e = IndicatorEntry {
                value: "x",
                indicator_type: IndicatorType::IP,
                lookups: vec![&l],
            };
            provider_summary(&e, "ThreatFox")
        },
    );
}
