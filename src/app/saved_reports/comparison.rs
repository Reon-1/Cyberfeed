//! Pure comparison of the structured findings stored in two reports.
use crate::indicator::Indicator;
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
    let old: BTreeMap<_, _> = older
        .local_inspection
        .indicators
        .iter()
        .map(|indicator| {
            (
                (indicator.indicator_type, indicator.value.to_lowercase()),
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
                (indicator.indicator_type, indicator.value.to_lowercase()),
                indicator,
            )
        })
        .collect();
    result.unchanged_indicators = old.keys().filter(|key| new.contains_key(*key)).count();
    result.removed_indicators = old
        .iter()
        .filter(|(key, _)| !new.contains_key(*key))
        .map(|(_, value)| (*value).clone())
        .collect();
    result.added_indicators = new
        .iter()
        .filter(|(key, _)| !old.contains_key(*key))
        .map(|(_, value)| (*value).clone())
        .collect();
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
        let label = format!("{} {} {}", key.0, key.1, key.2);
        let old_result = old.get(&key).copied();
        let new_result = new.get(&key).copied();
        match (old_result, new_result) {
            (Some(before), Some(after)) => {
                if before.outcome == after.outcome {
                    result.unchanged_provider_results += 1;
                } else {
                    result.provider_changes.push(format!(
                        "{label}: {} → {}",
                        outcome_description(&before.outcome),
                        outcome_description(&after.outcome)
                    ));
                }
            }
            (Some(before), None) => result.provider_changes.push(format!(
                "{label}: {} → no lookup recorded",
                outcome_description(&before.outcome)
            )),
            (None, Some(after)) => result.provider_changes.push(format!(
                "{label}: no lookup recorded → {}",
                outcome_description(&after.outcome)
            )),
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

fn lookup_map(lookups: &[ProviderLookup]) -> BTreeMap<(String, String, String), &ProviderLookup> {
    lookups
        .iter()
        .map(|lookup| {
            (
                (
                    lookup.provider.clone(),
                    format!("{:?}", lookup.subject),
                    lookup.queried_hash.to_lowercase(),
                ),
                lookup,
            )
        })
        .collect()
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
    }
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
            Some(true),
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
}
