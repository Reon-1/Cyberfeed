//! Pure comparison of the structured findings stored in two reports.
use crate::indicator::{Indicator, IndicatorType, classify};
use crate::report::{InvestigationReport, LookupOutcome, ProviderLookup, TextExtraction};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct ReportComparison {
    pub(super) same_subject: bool,
    pub(super) unchanged_indicators: usize,
    pub(super) added_indicators: Vec<Indicator>,
    pub(super) removed_indicators: Vec<Indicator>,
    pub(super) provider_changes: Vec<String>,
    pub(super) unchanged_provider_results: usize,
    pub(super) unavailable_provider_results: Vec<String>,
    pub(super) metadata_changes: Vec<String>,
    pub(super) indicator_absence_inconclusive: bool,
    pub(super) interpretations: Vec<String>,
    pub(super) worth_checking: Vec<String>,
}

/// A SHA-256 mismatch blocks result comparison because the reports describe
/// different subjects. Provider matching stays generic across provider names.
pub(super) fn compare(
    older: &InvestigationReport,
    newer: &InvestigationReport,
) -> ReportComparison {
    let same_subject = older.file.sha256.eq_ignore_ascii_case(&newer.file.sha256);
    let mut result = ReportComparison {
        same_subject,
        unchanged_indicators: 0,
        added_indicators: Vec::new(),
        removed_indicators: Vec::new(),
        provider_changes: Vec::new(),
        unchanged_provider_results: 0,
        unavailable_provider_results: Vec::new(),
        metadata_changes: Vec::new(),
        indicator_absence_inconclusive: false,
        interpretations: Vec::new(),
        worth_checking: Vec::new(),
    };
    if !same_subject {
        return result;
    }

    compare_metadata(older, newer, &mut result);
    compare_indicators(older, newer, &mut result);
    compare_provider_results(older, newer, &mut result);
    result
}

fn compare_metadata(
    older: &InvestigationReport,
    newer: &InvestigationReport,
    result: &mut ReportComparison,
) {
    if older.file.filename != newer.file.filename {
        result.metadata_changes.push(format!(
            "Filename: {} → {}",
            older.file.filename, newer.file.filename
        ));
    }
    if older.file.size_bytes != newer.file.size_bytes {
        result.metadata_changes.push(format!(
            "Recorded size: {} → {} bytes",
            older.file.size_bytes, newer.file.size_bytes
        ));
    }
    if older.file.inspected_locally_not_executed_or_uploaded
        != newer.file.inspected_locally_not_executed_or_uploaded
    {
        result
            .metadata_changes
            .push("Local inspection handling flag changed".into());
    }
    let extraction = |value: &TextExtraction| match value {
        TextExtraction::Performed { limit_reached } => {
            format!("performed (limit reached: {limit_reached})")
        }
        TextExtraction::SkippedBinaryOrNonText => "skipped (binary or non-text)".into(),
    };
    if extraction(&older.local_inspection.text_extraction)
        != extraction(&newer.local_inspection.text_extraction)
    {
        result.metadata_changes.push(format!(
            "Text extraction: {} → {}",
            extraction(&older.local_inspection.text_extraction),
            extraction(&newer.local_inspection.text_extraction)
        ));
    }
    if older.summary.extraction_limit_reached != newer.summary.extraction_limit_reached {
        result.metadata_changes.push(format!(
            "Extraction limit reached: {} → {}",
            older.summary.extraction_limit_reached, newer.summary.extraction_limit_reached
        ));
    }
    if older.summary.original_file_lookup_status != newer.summary.original_file_lookup_status {
        result.metadata_changes.push(format!(
            "Summary original-file lookup status: {:?} → {:?}",
            older.summary.original_file_lookup_status, newer.summary.original_file_lookup_status
        ));
    }
    if older.summary.extracted_indicator_counts != newer.summary.extracted_indicator_counts {
        result.metadata_changes.push(format!(
            "Summary extracted-indicator counts changed: {:?} → {:?}",
            older.summary.extracted_indicator_counts, newer.summary.extracted_indicator_counts
        ));
    }
    if older.summary.extracted_hash_lookup_counts != newer.summary.extracted_hash_lookup_counts {
        result.metadata_changes.push(format!(
            "Summary extracted-hash lookup counts changed: {:?} → {:?}",
            older.summary.extracted_hash_lookup_counts, newer.summary.extracted_hash_lookup_counts
        ));
    }
    if older.interpretation != newer.interpretation {
        result
            .metadata_changes
            .push("Interpretation notes differ".into());
    }
}

fn compare_indicators(
    older: &InvestigationReport,
    newer: &InvestigationReport,
    result: &mut ReportComparison,
) {
    let full_extraction = |report: &InvestigationReport| {
        matches!(
            report.local_inspection.text_extraction,
            TextExtraction::Performed {
                limit_reached: false
            }
        )
    };
    result.indicator_absence_inconclusive = !(full_extraction(older) && full_extraction(newer));
    let old: BTreeMap<_, _> = older
        .local_inspection
        .indicators
        .iter()
        .map(|indicator| {
            (
                (
                    indicator.indicator_type,
                    indicator_key(indicator.indicator_type, &indicator.value),
                ),
                indicator,
            )
        })
        .collect();
    let new: BTreeMap<_, _> = newer
        .local_inspection
        .indicators
        .iter()
        .map(|indicator| {
            (
                (
                    indicator.indicator_type,
                    indicator_key(indicator.indicator_type, &indicator.value),
                ),
                indicator,
            )
        })
        .collect();
    result.unchanged_indicators = old.keys().filter(|key| new.contains_key(*key)).count();
    if !result.indicator_absence_inconclusive {
        result.removed_indicators = old
            .iter()
            .filter(|(key, _)| !new.contains_key(*key))
            .map(|(_, value)| (*value).clone())
            .collect();
    }
    result.added_indicators = new
        .iter()
        .filter(|(key, _)| !old.contains_key(*key))
        .map(|(_, value)| (*value).clone())
        .collect();
}

fn indicator_key(indicator_type: IndicatorType, value: &str) -> String {
    if indicator_type == IndicatorType::Url {
        value.to_owned()
    } else {
        value.to_ascii_lowercase()
    }
}

fn compare_provider_results(
    older: &InvestigationReport,
    newer: &InvestigationReport,
    result: &mut ReportComparison,
) {
    let old = lookup_map(&older.provider_lookups);
    let new = lookup_map(&newer.provider_lookups);
    let keys: BTreeSet<_> = old.keys().chain(new.keys()).cloned().collect();
    for key in keys {
        let label = format!("{} {} {} {}", key.0, key.1, key.2, key.3);
        let old_result = old.get(&key).copied();
        let new_result = new.get(&key).copied();
        match (old_result, new_result) {
            (Some(before), Some(after)) => {
                if outcomes_equivalent(&before.outcome, &after.outcome) {
                    result.unchanged_provider_results += 1;
                } else {
                    result.provider_changes.push(format!(
                        "{label}: {} → {}",
                        outcome_description(&before.outcome),
                        outcome_description(&after.outcome)
                    ));
                    result
                        .interpretations
                        .push(change_interpretation(&before.outcome, &after.outcome));
                    result.worth_checking.push(label.clone());
                }
            }
            (Some(before), None) => {
                result.provider_changes.push(format!(
                    "{label}: {} → no lookup recorded",
                    outcome_description(&before.outcome)
                ));
                result.interpretations.push(format!(
                    "Coverage differs for {label}; no newer lookup was recorded, so this is not a negative result."
                ));
                result.worth_checking.push(label.clone());
            }
            (None, Some(after)) => {
                result.provider_changes.push(format!(
                    "{label}: no lookup recorded → {}",
                    outcome_description(&after.outcome)
                ));
                result.interpretations.push(format!(
                    "Coverage differs for {label}; the earlier report contains no result to compare."
                ));
                result.worth_checking.push(label.clone());
            }
            (None, None) => {}
        }
        for lookup in [old_result, new_result].into_iter().flatten() {
            if outcome_is_unavailable(&lookup.outcome) {
                let unavailable = format!("{label}: {}", outcome_description(&lookup.outcome));
                // Identical unavailable records in both snapshots are one fact,
                // while different errors or skipped states remain distinct.
                if !result.unavailable_provider_results.contains(&unavailable) {
                    result.unavailable_provider_results.push(unavailable);
                }
            }
        }
    }
}

fn change_interpretation(before: &LookupOutcome, after: &LookupOutcome) -> String {
    if outcome_is_unavailable(before) || outcome_is_unavailable(after) {
        return "At least one check was unavailable, skipped, unsupported, or failed; the change is inconclusive.".into();
    }
    if is_positive(after) && !is_positive(before) {
        return "A matching record is present in the newer report. This is newly recorded evidence; it does not show when the threat appeared.".into();
    }
    if is_positive(before) && matches!(after, LookupOutcome::NotFound) {
        return "The newer check returned no match. The earlier record remains historical evidence; this does not prove the threat disappeared or the item is safe.".into();
    }
    "Provider evidence or metadata changed; inspect the technical details to see which fields differ.".into()
}

fn is_positive(outcome: &LookupOutcome) -> bool {
    matches!(
        outcome,
        LookupOutcome::Found(_)
            | LookupOutcome::ThreatFoxFound { .. }
            | LookupOutcome::UrlhausFound { .. }
    )
}

fn outcomes_equivalent(older: &LookupOutcome, newer: &LookupOutcome) -> bool {
    match (older, newer) {
        (
            LookupOutcome::ThreatFoxFound { findings: older },
            LookupOutcome::ThreatFoxFound { findings: newer },
        ) => {
            let mut older = older.clone();
            let mut newer = newer.clone();
            older.sort();
            newer.sort();
            older == newer
        }
        (
            LookupOutcome::UrlhausFound { details: older },
            LookupOutcome::UrlhausFound { details: newer },
        ) => {
            let mut older = older.clone();
            let mut newer = newer.clone();
            older.associated_urls.sort();
            newer.associated_urls.sort();
            older == newer
        }
        _ => older == newer,
    }
}

fn lookup_map(
    lookups: &[ProviderLookup],
) -> BTreeMap<(String, String, String, String), &ProviderLookup> {
    lookups
        .iter()
        .map(|lookup| {
            (
                (
                    lookup.provider.clone(),
                    format!("{:?}", lookup.subject),
                    format!("{:?}", lookup_indicator_type(lookup)),
                    indicator_key(lookup_indicator_type(lookup), &lookup.queried_hash),
                ),
                lookup,
            )
        })
        .collect()
}

fn lookup_indicator_type(lookup: &ProviderLookup) -> IndicatorType {
    if lookup.subject == crate::report::LookupSubject::OriginalFileSha256 {
        IndicatorType::Hash
    } else {
        classify(
            &lookup.queried_hash,
            crate::indicator::EXTRACTED_HASH_LENGTHS,
        )
        .unwrap_or(IndicatorType::Domain)
    }
}

fn outcome_is_unavailable(outcome: &LookupOutcome) -> bool {
    matches!(
        outcome,
        LookupOutcome::Invalid { .. }
            | LookupOutcome::ApiError { .. }
            | LookupOutcome::RequestError { .. }
            | LookupOutcome::NotConfigured
            | LookupOutcome::SkippedDuplicate { .. }
            | LookupOutcome::SkippedLookupLimit
            | LookupOutcome::Unsupported { .. }
    )
}

fn outcome_description(outcome: &LookupOutcome) -> String {
    match outcome {
        LookupOutcome::Found(details) => format!(
            "FOUND (matched SHA-256 {}; first seen {}; type {}; sample {}; signature {})",
            details.matched_sha256,
            details.first_seen,
            details.file_type,
            details.sample_filename.as_deref().unwrap_or("not provided"),
            details.signature.as_deref().unwrap_or("not provided")
        ),
        LookupOutcome::NotFound => {
            "NOT FOUND (no provider record at lookup time; not a safety verdict)".into()
        }
        LookupOutcome::Invalid { explanation } => format!("INVALID: {explanation}"),
        LookupOutcome::ApiError { explanation } => format!("API ERROR: {explanation}"),
        LookupOutcome::RequestError { explanation } => format!("REQUEST ERROR: {explanation}"),
        LookupOutcome::NotConfigured => "NOT CONFIGURED (lookup not made)".into(),
        LookupOutcome::SkippedDuplicate { references_hash } => {
            format!("SKIPPED DUPLICATE (reuses {references_hash})")
        }
        LookupOutcome::SkippedLookupLimit => "SKIPPED LOOKUP LIMIT".into(),
        LookupOutcome::Unsupported { explanation } => format!("UNSUPPORTED: {explanation}"),
        LookupOutcome::ThreatFoxFound { findings } => {
            let details = findings
                .iter()
                .map(threatfox_finding_description)
                .collect::<Vec<_>>()
                .join("; ");
            format!("THREATFOX FOUND ({details})")
        }
        LookupOutcome::UrlhausFound { details } => format!(
            "URLHAUS FOUND: {} associated URL(s), reference {}",
            details
                .associated_url_count
                .map_or_else(|| "unknown".into(), |count| count.to_string()),
            details.reference.as_deref().unwrap_or("not provided")
        ),
    }
}

fn threatfox_finding_description(finding: &crate::report::ThreatFoxFinding) -> String {
    format!(
        "IOC {} ({}; {}); threat {} ({}); malware {} ({}); confidence {}; first seen {}; last seen {}; reference {}; reporter {}; tags [{}]; record {}",
        finding.ioc,
        finding.ioc_type,
        finding
            .ioc_type_description
            .as_deref()
            .unwrap_or("type description unavailable"),
        finding.threat_type.as_deref().unwrap_or("unavailable"),
        finding
            .threat_type_description
            .as_deref()
            .unwrap_or("description unavailable"),
        finding.malware.as_deref().unwrap_or("unavailable"),
        finding
            .malware_printable
            .as_deref()
            .unwrap_or("printable name unavailable"),
        finding
            .confidence_level
            .map_or_else(|| "unavailable".into(), |value| value.to_string()),
        finding.first_seen.as_deref().unwrap_or("unavailable"),
        finding.last_seen.as_deref().unwrap_or("unavailable"),
        finding.reference.as_deref().unwrap_or("unavailable"),
        finding.reporter.as_deref().unwrap_or("unavailable"),
        finding.tags.join(", "),
        finding.source_record_id.as_deref().unwrap_or("unavailable"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::FileInfo;
    use crate::indicator::{Indicator, IndicatorType};
    use crate::report::{LookupSubject, MatchDetails, ProviderLookup};

    fn report() -> InvestigationReport {
        let file = FileInfo {
            name: "evidence.bin".into(),
            size: 42,
            sha256: "file-sha".into(),
        };
        InvestigationReport::new(
            &file,
            vec![Indicator::new("example.test", IndicatorType::Domain)],
            Some(false),
            vec![ProviderLookup {
                provider: "ExampleProvider".into(),
                subject: LookupSubject::OriginalFileSha256,
                queried_hash: "file-sha".into(),
                retrieved_at_unix_seconds: Some(9),
                outcome: LookupOutcome::NotFound,
            }],
        )
    }

    fn found() -> LookupOutcome {
        LookupOutcome::Found(MatchDetails {
            matched_sha256: "file-sha".into(),
            first_seen: "today".into(),
            file_type: "bin".into(),
            sample_filename: None,
            signature: None,
        })
    }

    #[test]
    fn unchanged_provider_result_and_indicators_are_counted() {
        let comparison = compare(&report(), &report());
        assert!(comparison.same_subject);
        assert_eq!(comparison.unchanged_indicators, 1);
        assert_eq!(comparison.unchanged_provider_results, 1);
        assert!(comparison.provider_changes.is_empty());
    }

    #[test]
    fn added_and_removed_indicators_are_reported() {
        let mut older = report();
        older
            .local_inspection
            .indicators
            .push(Indicator::new("old.test", IndicatorType::Domain));
        let mut newer = report();
        newer
            .local_inspection
            .indicators
            .push(Indicator::new("new.test", IndicatorType::Domain));
        let comparison = compare(&older, &newer);
        assert_eq!(comparison.unchanged_indicators, 1);
        assert_eq!(comparison.added_indicators[0].value, "new.test");
        assert_eq!(comparison.removed_indicators[0].value, "old.test");
    }

    #[test]
    fn url_paths_keep_case_when_comparing_extracted_indicators() {
        let mut older = report();
        older.local_inspection.indicators =
            vec![Indicator::new("https://example.test/A", IndicatorType::Url)];
        let mut newer = report();
        newer.local_inspection.indicators =
            vec![Indicator::new("https://example.test/a", IndicatorType::Url)];
        let comparison = compare(&older, &newer);
        assert_eq!(
            comparison.added_indicators[0].value,
            "https://example.test/a"
        );
        assert_eq!(
            comparison.removed_indicators[0].value,
            "https://example.test/A"
        );
    }

    #[test]
    fn incomplete_extraction_does_not_claim_an_indicator_was_removed() {
        let mut older = report();
        older
            .local_inspection
            .indicators
            .push(Indicator::new("old.example.test", IndicatorType::Domain));
        let mut newer = report();
        newer.local_inspection.text_extraction = TextExtraction::SkippedBinaryOrNonText;
        let comparison = compare(&older, &newer);
        assert!(comparison.removed_indicators.is_empty());
        assert!(comparison.indicator_absence_inconclusive);
    }

    #[test]
    fn newly_recorded_matches_and_provider_errors_are_interpreted_cautiously() {
        let mut older = report();
        let mut newer = report();
        older.provider_lookups[0].outcome = LookupOutcome::NotFound;
        newer.provider_lookups[0].outcome = found();
        let comparison = compare(&older, &newer);
        assert!(comparison.interpretations[0].contains("newly recorded evidence"));

        older.provider_lookups[0].outcome = LookupOutcome::RequestError {
            explanation: "offline".into(),
        };
        let comparison = compare(&older, &newer);
        assert!(comparison.interpretations[0].contains("inconclusive"));
    }

    #[test]
    fn provider_transition_preserves_recorded_error_and_success() {
        let mut older = report();
        older.provider_lookups[0].outcome = LookupOutcome::ApiError {
            explanation: "timeout".into(),
        };
        let mut newer = report();
        newer.provider_lookups[0].outcome = found();
        let comparison = compare(&older, &newer);
        assert!(comparison.provider_changes[0].contains("API ERROR: timeout → FOUND"));
        assert_eq!(comparison.unavailable_provider_results.len(), 1);
    }

    #[test]
    fn found_outcomes_compare_all_structured_match_details() {
        let mut older = report();
        older.provider_lookups[0].outcome = found();
        let mut equivalent = older.clone();
        let comparison = compare(&older, &equivalent);
        assert_eq!(comparison.unchanged_provider_results, 1);
        assert!(comparison.provider_changes.is_empty());

        let LookupOutcome::Found(details) = &mut equivalent.provider_lookups[0].outcome else {
            unreachable!();
        };
        details.signature = Some("different signature".into());
        let comparison = compare(&older, &equivalent);
        assert_eq!(comparison.unchanged_provider_results, 0);
        assert_eq!(comparison.provider_changes.len(), 1);
        assert!(comparison.provider_changes[0].contains("signature not provided"));
        assert!(comparison.provider_changes[0].contains("different signature"));
    }

    #[test]
    fn provider_outcome_variants_remain_distinct() {
        let mut older = report();
        older.provider_lookups[0].outcome = LookupOutcome::NotFound;
        let mut newer = report();
        newer.provider_lookups[0].outcome = LookupOutcome::NotConfigured;
        let comparison = compare(&older, &newer);
        assert_eq!(comparison.unchanged_provider_results, 0);
        assert!(comparison.provider_changes[0].contains("NOT FOUND"));
        assert!(comparison.provider_changes[0].contains("NOT CONFIGURED"));
    }

    #[test]
    fn identical_unavailable_outcomes_are_deduplicated() {
        let mut older = report();
        older.provider_lookups[0].outcome = LookupOutcome::SkippedLookupLimit;
        let newer = older.clone();
        let comparison = compare(&older, &newer);
        assert_eq!(comparison.unchanged_provider_results, 1);
        assert!(comparison.provider_changes.is_empty());
        assert_eq!(comparison.unavailable_provider_results.len(), 1);
    }

    #[test]
    fn distinct_unavailable_outcomes_remain_visible() {
        let mut older = report();
        older.provider_lookups[0].outcome = LookupOutcome::ApiError {
            explanation: "timeout".into(),
        };
        let mut newer = report();
        newer.provider_lookups[0].outcome = LookupOutcome::RequestError {
            explanation: "reset".into(),
        };
        let comparison = compare(&older, &newer);
        assert_eq!(comparison.unavailable_provider_results.len(), 2);
        assert!(
            comparison.provider_changes[0].contains("API ERROR: timeout → REQUEST ERROR: reset")
        );
    }

    #[test]
    fn different_subjects_do_not_compare_findings_or_provider_results() {
        let older = report();
        let mut newer = report();
        newer.file.sha256 = "other-file".into();
        let comparison = compare(&older, &newer);
        assert!(!comparison.same_subject);
        assert!(comparison.added_indicators.is_empty());
        assert!(comparison.provider_changes.is_empty());
    }

    #[test]
    fn threatfox_records_compare_structured_fields_and_equivalent_records_stay_unchanged() {
        use crate::report::ThreatFoxFinding;
        let finding = ThreatFoxFinding {
            source_record_id: Some("17".into()),
            ioc: "example.test".into(),
            ioc_type: "domain".into(),
            ioc_type_description: None,
            threat_type: Some("botnet_cc".into()),
            threat_type_description: None,
            malware: None,
            malware_printable: Some("Family".into()),
            confidence_level: Some(80),
            first_seen: None,
            last_seen: None,
            reference: None,
            reporter: None,
            tags: vec![],
        };
        let set = |finding| LookupOutcome::ThreatFoxFound {
            findings: vec![finding],
        };
        let mut older = report();
        older.provider_lookups[0].provider = "ThreatFox".into();
        older.provider_lookups[0].outcome = set(finding.clone());
        let mut second_finding = finding.clone();
        second_finding.ioc = "other.example".into();
        if let LookupOutcome::ThreatFoxFound { findings } = &mut older.provider_lookups[0].outcome {
            findings.push(second_finding);
        }
        let mut same = older.clone();
        if let LookupOutcome::ThreatFoxFound { findings } = &mut same.provider_lookups[0].outcome {
            findings.reverse();
        }
        assert_eq!(compare(&older, &same).unchanged_provider_results, 1);
        same = older.clone();
        let LookupOutcome::ThreatFoxFound { findings } = &mut same.provider_lookups[0].outcome
        else {
            panic!()
        };
        findings[0].confidence_level = Some(95);
        let changed = compare(&older, &same);
        assert_eq!(changed.unchanged_provider_results, 0);
        assert!(changed.provider_changes[0].contains("confidence 80"));
        assert!(changed.provider_changes[0].contains("confidence 95"));
    }
}
