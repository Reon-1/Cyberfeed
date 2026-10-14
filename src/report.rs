//! Versioned investigation report model, rendering, and local persistence.
mod model;
mod render;
mod stix;
mod storage;

pub use model::*;
pub use stix::{save_stix_bundle, stix_indicator_count};
pub use storage::{save_indicator_report, save_report, save_session_report};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::FileInfo;
    use crate::indicator::{Indicator, IndicatorType};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_PATH: AtomicU64 = AtomicU64::new(0);

    fn unique_test_path(label: &str) -> std::path::PathBuf {
        let id = NEXT_TEST_PATH.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("cyberfeed-{label}-{}-{id}", std::process::id()))
    }
    #[test]
    fn report_round_trips_and_has_versioned_metadata() {
        let f = FileInfo {
            name: "x".into(),
            size: 1,
            sha256: "abc".into(),
        };
        let r = InvestigationReport::new(&f, vec![], Some(false), vec![]);
        let j = serde_json::to_string(&r).unwrap();
        let back: InvestigationReport = serde_json::from_str(&j).unwrap();
        assert_eq!(back.schema_version, SCHEMA_VERSION);
        assert_eq!(back.file.filename, "x");
        assert!(back.file.inspected_locally_not_executed_or_uploaded);
    }
    #[test]
    fn markdown_escapes_untrusted_values() {
        let f = FileInfo {
            name: "evil|`\nname.txt".into(),
            size: 1,
            sha256: "x".into(),
        };
        let r = InvestigationReport::new(
            &f,
            vec![Indicator::new("x|y\n`", IndicatorType::Domain)],
            Some(false),
            vec![],
        );
        let md = r.to_markdown();
        assert!(!md.contains("evil|`\n"));
        assert!(md.contains("x\\|y"));
    }
    #[test]
    fn saves_both_files_without_overwrite() {
        let dir = unique_test_path("report");
        let f = FileInfo {
            name: "sample.bin".into(),
            size: 0,
            sha256: "abc".into(),
        };
        let r = InvestigationReport::new(&f, vec![], None, vec![]);
        let a = save_report(&r, &dir).unwrap();
        let b = save_report(&r, &dir).unwrap();
        assert_ne!(a, b);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&a.0).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&a.1).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let json: InvestigationReport = serde_json::from_slice(&fs::read(&a.0).unwrap()).unwrap();
        assert_eq!(json.schema_version, SCHEMA_VERSION);
        let markdown = fs::read_to_string(&a.1).unwrap();
        assert!(markdown.starts_with("# CyberFeed Investigation Report"));
        assert!(markdown.contains("## Investigation summary"));
        let original_json = fs::read(&a.0).unwrap();
        let _second = save_report(&r, &dir).unwrap();
        assert_eq!(fs::read(&a.0).unwrap(), original_json);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn output_directory_failure_preserves_the_existing_file() {
        let path = unique_test_path("report-output-file");
        fs::write(&path, b"keep me").unwrap();
        let file = FileInfo {
            name: "sample".into(),
            size: 0,
            sha256: "abc".into(),
        };
        let report = InvestigationReport::new(&file, vec![], None, vec![]);
        assert!(save_report(&report, &path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"keep me");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn existing_markdown_collision_is_preserved_and_pair_uses_next_name() {
        let directory = unique_test_path("report-md-collision");
        fs::create_dir(&directory).unwrap();
        let file = FileInfo {
            name: "sample.bin".into(),
            size: 0,
            sha256: "abc".into(),
        };
        let mut report = InvestigationReport::new(&file, vec![], None, vec![]);
        report.generated_at_unix_seconds = 123;
        let existing_markdown = directory.join("cyberfeed-sample-123.md");
        fs::write(&existing_markdown, b"preserve this file").unwrap();

        let (json, markdown) = save_report(&report, &directory).unwrap();
        assert_eq!(json.file_name().unwrap(), "cyberfeed-sample-123-1.json");
        assert_eq!(markdown.file_name().unwrap(), "cyberfeed-sample-123-1.md");
        assert_eq!(fs::read(existing_markdown).unwrap(), b"preserve this file");
        assert!(serde_json::from_slice::<InvestigationReport>(&fs::read(json).unwrap()).is_ok());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn summary_separates_original_file_from_extracted_hash_lookup_counts() {
        let file = FileInfo {
            name: "sample.bin".into(),
            size: 10,
            sha256: "file-hash".into(),
        };
        let indicators = vec![
            Indicator::new("embedded-hash", IndicatorType::Hash),
            Indicator::new("192.0.2.1", IndicatorType::IP),
            Indicator::new("example.test", IndicatorType::Domain),
        ];
        let lookups = vec![
            ProviderLookup {
                provider: "MalwareBazaar".into(),
                subject: LookupSubject::OriginalFileSha256,
                queried_hash: "file-hash".into(),
                retrieved_at_unix_seconds: Some(1),
                outcome: LookupOutcome::NotFound,
            },
            ProviderLookup {
                provider: "MalwareBazaar".into(),
                subject: LookupSubject::ExtractedIndicatorSha256,
                queried_hash: "embedded-hash".into(),
                retrieved_at_unix_seconds: Some(1),
                outcome: LookupOutcome::Found(MatchDetails {
                    matched_sha256: "embedded-hash".into(),
                    first_seen: "today".into(),
                    file_type: "exe".into(),
                    sample_filename: None,
                    signature: None,
                }),
            },
            ProviderLookup {
                provider: "MalwareBazaar".into(),
                subject: LookupSubject::ExtractedIndicatorSha256,
                queried_hash: "another-hash".into(),
                retrieved_at_unix_seconds: None,
                outcome: LookupOutcome::SkippedLookupLimit,
            },
        ];
        let report = InvestigationReport::new(&file, indicators, Some(true), lookups);
        assert_eq!(
            report.summary.original_file_lookup_status.as_deref(),
            Some("NOT FOUND")
        );
        assert_eq!(report.summary.extracted_indicator_counts.hashes, 1);
        assert_eq!(report.summary.extracted_indicator_counts.ip_addresses, 1);
        assert_eq!(report.summary.extracted_indicator_counts.domains, 1);
        assert_eq!(report.summary.extracted_hash_lookup_counts.found, 1);
        assert_eq!(report.summary.extracted_hash_lookup_counts.not_found, 0);
        assert_eq!(
            report
                .summary
                .extracted_hash_lookup_counts
                .skipped_or_unavailable,
            1
        );
        assert!(
            report
                .to_markdown()
                .contains("Original file lookup: NOT FOUND")
        );
        assert!(report.to_markdown().contains("1 found, 0 not found"));
    }

    #[test]
    fn summaries_count_both_providers_per_extracted_hash_and_exclude_other_indicators() {
        let file = FileInfo {
            name: "sample".into(),
            size: 1,
            sha256: "file".into(),
        };
        let lookup = |provider: &str, subject, queried_hash: &str, outcome| ProviderLookup {
            provider: provider.into(),
            subject,
            queried_hash: queried_hash.into(),
            retrieved_at_unix_seconds: None,
            outcome,
        };
        let report = InvestigationReport::new(
            &file,
            vec![],
            None,
            vec![
                lookup(
                    "MalwareBazaar",
                    LookupSubject::ExtractedIndicatorSha256,
                    &"a".repeat(64),
                    LookupOutcome::NotFound,
                ),
                lookup(
                    "ThreatFox",
                    LookupSubject::ExtractedIndicator,
                    &"a".repeat(64),
                    LookupOutcome::ThreatFoxFound { findings: vec![] },
                ),
                lookup(
                    "URLhaus",
                    LookupSubject::ExtractedIndicator,
                    &"b".repeat(32),
                    LookupOutcome::NotFound,
                ),
                lookup(
                    "URLhaus",
                    LookupSubject::ExtractedIndicator,
                    &"c".repeat(40),
                    LookupOutcome::Unsupported {
                        explanation: "SHA-1 unsupported".into(),
                    },
                ),
                lookup(
                    "ThreatFox",
                    LookupSubject::ExtractedIndicator,
                    "192.0.2.1",
                    LookupOutcome::Found(MatchDetails {
                        matched_sha256: "x".into(),
                        first_seen: "now".into(),
                        file_type: "x".into(),
                        sample_filename: None,
                        signature: None,
                    }),
                ),
                lookup(
                    "ThreatFox",
                    LookupSubject::ExtractedIndicator,
                    "example.test",
                    LookupOutcome::NotFound,
                ),
            ],
        );
        assert_eq!(
            report.summary.extracted_hash_lookup_counts,
            LookupCounts {
                found: 1,
                not_found: 2,
                failures: 0,
                skipped_or_unavailable: 1
            }
        );
        assert!(
            report
                .to_markdown()
                .contains("Extracted hash provider outcomes: 1 found, 2 not found")
        );
    }

    #[test]
    fn original_file_summary_prefers_positive_and_marks_disagreement_incomplete() {
        let file = FileInfo {
            name: "sample".into(),
            size: 1,
            sha256: "file".into(),
        };
        let lookup = |provider: &str, outcome| ProviderLookup {
            provider: provider.into(),
            subject: LookupSubject::OriginalFileSha256,
            queried_hash: "file".into(),
            retrieved_at_unix_seconds: None,
            outcome,
        };
        let positive = InvestigationReport::new(
            &file,
            vec![],
            None,
            vec![
                lookup("MalwareBazaar", LookupOutcome::NotFound),
                lookup(
                    "ThreatFox",
                    LookupOutcome::ThreatFoxFound { findings: vec![] },
                ),
            ],
        );
        assert_eq!(
            positive.summary.original_file_lookup_status.as_deref(),
            Some("FOUND")
        );
        let mixed = InvestigationReport::new(
            &file,
            vec![],
            None,
            vec![
                lookup("MalwareBazaar", LookupOutcome::NotConfigured),
                lookup("ThreatFox", LookupOutcome::NotFound),
            ],
        );
        assert_eq!(
            mixed.summary.original_file_lookup_status.as_deref(),
            Some("INCOMPLETE")
        );
        let same = InvestigationReport::new(
            &file,
            vec![],
            None,
            vec![
                lookup("MalwareBazaar", LookupOutcome::NotConfigured),
                lookup("ThreatFox", LookupOutcome::NotConfigured),
            ],
        );
        assert_eq!(
            same.summary.original_file_lookup_status.as_deref(),
            Some("NOT CONFIGURED")
        );
        let none = InvestigationReport::new(&file, vec![], None, vec![]);
        assert_eq!(none.summary.original_file_lookup_status, None);
    }

    #[test]
    fn extracted_hash_counts_include_failures_and_skipped_threatfox_outcomes() {
        let file = FileInfo {
            name: "sample".into(),
            size: 1,
            sha256: "file".into(),
        };
        let lookups = [
            LookupOutcome::ApiError {
                explanation: "error".into(),
            },
            LookupOutcome::SkippedLookupLimit,
            LookupOutcome::Unsupported {
                explanation: "not supported".into(),
            },
        ]
        .into_iter()
        .map(|outcome| ProviderLookup {
            provider: "ThreatFox".into(),
            subject: LookupSubject::ExtractedIndicator,
            queried_hash: "a".repeat(64),
            retrieved_at_unix_seconds: None,
            outcome,
        })
        .collect();
        let report = InvestigationReport::new(&file, vec![], None, lookups);
        assert_eq!(report.summary.extracted_hash_lookup_counts.failures, 1);
        assert_eq!(
            report
                .summary
                .extracted_hash_lookup_counts
                .skipped_or_unavailable,
            2
        );
    }

    #[test]
    fn every_lookup_state_has_a_stable_markdown_label() {
        let outcomes = [
            LookupOutcome::Found(MatchDetails {
                matched_sha256: "abc".into(),
                first_seen: "today".into(),
                file_type: "exe".into(),
                sample_filename: None,
                signature: None,
            }),
            LookupOutcome::NotFound,
            LookupOutcome::Invalid {
                explanation: "invalid".into(),
            },
            LookupOutcome::ApiError {
                explanation: "api".into(),
            },
            LookupOutcome::RequestError {
                explanation: "request".into(),
            },
            LookupOutcome::NotConfigured,
            LookupOutcome::SkippedDuplicate {
                references_hash: "abc".into(),
            },
            LookupOutcome::SkippedLookupLimit,
        ];
        let expected = [
            "FOUND",
            "NOT FOUND",
            "INVALID",
            "API ERROR",
            "REQUEST ERROR",
            "NOT CONFIGURED",
            "SKIPPED: DUPLICATE",
            "SKIPPED: LOOKUP LIMIT",
        ];
        for (outcome, label) in outcomes.into_iter().zip(expected) {
            assert_eq!(outcome.status(), label);
            let f = FileInfo {
                name: "sample".into(),
                size: 0,
                sha256: "abc".into(),
            };
            let lookup = ProviderLookup {
                provider: "MalwareBazaar".into(),
                subject: LookupSubject::ExtractedIndicatorSha256,
                queried_hash: "abc".into(),
                retrieved_at_unix_seconds: None,
                outcome,
            };
            let report = InvestigationReport::new(&f, vec![], None, vec![lookup]);
            assert!(report.to_markdown().contains(label));
        }
    }

    #[test]
    fn reports_do_not_include_authentication_material() {
        let f = FileInfo {
            name: "sample".into(),
            size: 0,
            sha256: "abc".into(),
        };
        let r = InvestigationReport::new(
            &f,
            vec![],
            None,
            vec![ProviderLookup {
                provider: "MalwareBazaar".into(),
                subject: LookupSubject::OriginalFileSha256,
                queried_hash: "abc".into(),
                retrieved_at_unix_seconds: None,
                outcome: LookupOutcome::NotConfigured,
            }],
        );
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("auth_key"));
        assert!(!json.contains("Auth-Key"));
        assert!(!json.contains("MALWAREBAZAAR_AUTH_KEY"));
        assert!(!json.contains("ABUSECH_AUTH_KEY"));
    }

    #[test]
    fn threatfox_findings_round_trip_and_render_provider_fields() {
        let file = FileInfo {
            name: "evidence".into(),
            size: 1,
            sha256: "subject".into(),
        };
        let report = InvestigationReport::new(
            &file,
            vec![],
            None,
            vec![ProviderLookup {
                provider: "ThreatFox".into(),
                subject: LookupSubject::ExtractedIndicator,
                queried_hash: "example.test".into(),
                retrieved_at_unix_seconds: Some(5),
                outcome: LookupOutcome::ThreatFoxFound {
                    findings: vec![ThreatFoxFinding {
                        source_record_id: Some("42".into()),
                        ioc: "example.test".into(),
                        ioc_type: "domain".into(),
                        ioc_type_description: None,
                        threat_type: Some("botnet_cc".into()),
                        threat_type_description: Some("C2".into()),
                        malware: None,
                        malware_printable: Some("Example family".into()),
                        confidence_level: Some(90),
                        first_seen: Some("2026-01-01".into()),
                        last_seen: None,
                        reference: None,
                        reporter: Some("researcher".into()),
                        tags: vec!["tag".into()],
                    }],
                },
            }],
        );
        let serialized = serde_json::to_vec(&report).unwrap();
        let loaded: InvestigationReport = serde_json::from_slice(&serialized).unwrap();
        assert!(
            matches!(&loaded.provider_lookups[0].outcome, LookupOutcome::ThreatFoxFound { findings } if findings[0].confidence_level == Some(90) && findings[0].source_record_id.as_deref() == Some("42"))
        );
        let markdown = loaded.to_markdown();
        assert!(markdown.contains("Example family"));
        assert!(markdown.contains("ThreatFox returned matching IOC records"));
    }

    #[test]
    fn markdown_keeps_urlhaus_associated_evidence_and_omits_empty_metadata() {
        let file = FileInfo {
            name: "evidence".into(),
            size: 1,
            sha256: "subject".into(),
        };
        let report = InvestigationReport::new(
            &file,
            vec![],
            None,
            vec![ProviderLookup {
                provider: "URLhaus".into(),
                subject: LookupSubject::ExtractedIndicator,
                queried_hash: "example.test".into(),
                retrieved_at_unix_seconds: Some(5),
                outcome: LookupOutcome::UrlhausFound {
                    details: UrlhausLookupDetails {
                        reference: Some("  ".into()),
                        queried_host: None,
                        associated_url_count: None,
                        md5_hash: None,
                        sha256_hash: None,
                        file_type: None,
                        first_seen: None,
                        last_seen: None,
                        signature: None,
                        associated_urls: vec![UrlhausUrlRecord {
                            reference: None,
                            url: "https://example.test/path".into(),
                            status: Some("online".into()),
                            host: Some("example.test".into()),
                            date_added: Some("2026-01-02".into()),
                            first_seen: Some("2026-01-03".into()),
                            last_seen: Some("2026-01-04".into()),
                            threat: Some("malware_download".into()),
                            tags: vec!["".into(), "  ".into()],
                        }],
                    },
                },
            }],
        );

        let markdown = report.to_markdown();
        assert!(markdown.contains("Associated URL records: 1"));
        assert!(markdown.contains("Host: example.test"));
        assert!(markdown.contains("Threat: malware\\_download"));
        assert!(markdown.contains("Date added: 2026-01-02"));
        assert_eq!(markdown.matches("Date added: 2026-01-02").count(), 1);
        assert!(markdown.contains("First seen: 2026-01-03"));
        assert!(markdown.contains("Last seen: 2026-01-04"));
        assert!(!markdown.contains("Tags:"));
        assert!(!markdown.contains("URLhaus reference: \n"));
    }
}
