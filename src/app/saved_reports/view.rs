//! Terminal rendering and display formatting for saved report data.
use super::comparison::{self, ReportComparison};
use super::report_files::{ReportCollection, SavedReport, SavedReportContents};
use crate::report::{
    InvestigationReport, LookupOutcome, LookupSubject, SessionCheck, SessionReport,
};
use crate::tui;

pub(super) fn report_page_capacity(rows: usize) -> usize {
    rows.saturating_sub(16).checked_div(2).unwrap_or(0).max(1)
}

pub(super) fn report_list(collection: &ReportCollection, start: usize, page_size: usize) {
    tui::menu_item(
        "C",
        "Compare Same-File Reports",
        "Compare repeated investigations with the same file SHA-256",
    );
    tui::menu_item(
        "I",
        "Compare Indicator Checks",
        "Compare recorded hash, IP, or domain lookups offline",
    );
    if collection.reports.is_empty() {
        tui::section("NO VALID REPORTS");
        tui::box_line("No readable JSON investigation reports were found in reports/.");
    } else {
        let pages = collection.reports.len().div_ceil(page_size.max(1));
        let page = start / page_size.max(1) + 1;
        tui::section(&format!(
            "AVAILABLE REPORTS · PAGE {page}/{pages} · NEWEST FIRST"
        ));
        for (index, saved) in collection
            .reports
            .iter()
            .enumerate()
            .skip(start)
            .take(page_size)
        {
            let name = saved
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("(unprintable filename)");
            match &saved.contents {
                SavedReportContents::File(report) => {
                    tui::menu_item(
                        &(index - start + 1).to_string(),
                        &format!("File · {}", terminal_safe(&report.file.filename)),
                        &terminal_safe(&format!(
                            "{} · {}",
                            format_timestamp(report.generated_at_unix_seconds),
                            file_report_status_summary(report)
                        )),
                    );
                }
                SavedReportContents::Session(report) => {
                    tui::menu_item(
                        &(index - start + 1).to_string(),
                        &format!("Session · {}", terminal_safe(name)),
                        &terminal_safe(&format!(
                            "{} completed check(s) · {}",
                            report.checks.len(),
                            format_timestamp(report.generated_at_unix_seconds)
                        )),
                    );
                }
            }
        }
    }
    if !collection.unavailable.is_empty() {
        tui::warning(&format!(
            "{} JSON file(s) could not be loaded (malformed, unreadable, or unsupported schema); valid reports remain available.",
            collection.unavailable.len()
        ));
        for issue in collection.unavailable.iter().take(3) {
            tui::field("Skipped", terminal_safe(issue));
        }
        if collection.unavailable.len() > 3 {
            tui::note(&format!(
                "{} additional report errors were omitted from this list.",
                collection.unavailable.len() - 3
            ));
        }
    }
    tui::navigation_footer("0", "Return to the main menu");
}

fn file_report_status_summary(report: &InvestigationReport) -> String {
    if report.provider_lookups.is_empty() {
        return "Local inspection only · no provider checks recorded".into();
    }

    let mut parts = vec![format!(
        "File hash {}",
        report
            .summary
            .original_file_lookup_status
            .as_deref()
            .unwrap_or("not checked")
    )];

    let matched_indicators = report
        .local_inspection
        .indicators
        .iter()
        .filter(|indicator| {
            report.provider_lookups.iter().any(|lookup| {
                lookup.subject != LookupSubject::OriginalFileSha256
                    && lookup.queried_hash == indicator.value
                    && matches!(
                        lookup.outcome,
                        LookupOutcome::Found(_)
                            | LookupOutcome::ThreatFoxFound { .. }
                            | LookupOutcome::UrlhausFound { .. }
                    )
            })
        })
        .map(|indicator| indicator.value.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len();
    if matched_indicators > 0 {
        parts.push(format!(
            "{matched_indicators} extracted indicator match(es)"
        ));
    } else {
        parts.push("no extracted matches in recorded checks".into());
    }

    let incomplete = report
        .provider_lookups
        .iter()
        .filter(|lookup| {
            matches!(
                lookup.outcome,
                LookupOutcome::Invalid { .. }
                    | LookupOutcome::ApiError { .. }
                    | LookupOutcome::RequestError { .. }
                    | LookupOutcome::TimedOut { .. }
                    | LookupOutcome::SkippedDeadline { .. }
                    | LookupOutcome::SkippedLookupLimit
                    | LookupOutcome::NotConfigured
                    | LookupOutcome::Unsupported { .. }
            )
        })
        .count();
    if incomplete > 0 {
        parts.push(format!(
            "coverage incomplete · {incomplete} skipped/unavailable/failed"
        ));
    }
    parts.join(" · ")
}

pub(super) struct IndicatorCheck<'a> {
    pub(super) value: &'a str,
    pub(super) source: &'a str,
    pub(super) time: u64,
    pub(super) lookups: &'a [crate::report::ProviderLookup],
}

pub(super) fn indicator_comparison_screen(
    indicator_type: &str,
    older: IndicatorCheck<'_>,
    newer: IndicatorCheck<'_>,
) {
    tui::header(
        "INDICATOR COMPARISON",
        "Recorded results · offline · read-only",
    );
    tui::field("Type", indicator_type);
    tui::field("Older value", terminal_safe(older.value));
    tui::field("Newer value", terminal_safe(newer.value));
    tui::section("SAVED CHECKS");
    tui::field(
        "Older",
        format!(
            "{} · {}",
            terminal_safe(older.source),
            format_timestamp(older.time)
        ),
    );
    tui::field(
        "Newer",
        format!(
            "{} · {}",
            terminal_safe(newer.source),
            format_timestamp(newer.time)
        ),
    );
    if older.value.eq_ignore_ascii_case(newer.value) {
        tui::section("PROVIDER OUTCOME COMPARISON");
        let mut seen = Vec::<(String, String)>::new();
        for lookup in older.lookups.iter().chain(newer.lookups) {
            let key = (
                lookup.provider.clone(),
                lookup.queried_hash.to_ascii_lowercase(),
            );
            if seen.contains(&key) {
                continue;
            }
            seen.push(key.clone());
            let old = older.lookups.iter().find(|item| {
                item.provider == key.0 && item.queried_hash.eq_ignore_ascii_case(&key.1)
            });
            let new = newer.lookups.iter().find(|item| {
                item.provider == key.0 && item.queried_hash.eq_ignore_ascii_case(&key.1)
            });
            let old_status = old.map(|item| item.outcome.status());
            let new_status = new.map(|item| item.outcome.status());
            let outcome = match (old_status, new_status) {
                (Some(old), Some(new)) if old == new => format!("{old} · unchanged"),
                (Some(old), Some(new)) => format!("{old} → {new} · CHANGED"),
                (Some(old), None) => format!("{old} → NOT RECORDED in newer report"),
                (None, Some(new)) => format!("NOT RECORDED in older report → {new}"),
                (None, None) => continue,
            };
            tui::field(
                &format!("{} · {}", terminal_safe(&key.0), terminal_safe(&key.1)),
                outcome,
            );
        }
        if older.lookups.is_empty() && newer.lookups.is_empty() {
            tui::field("Providers", "No outcomes were recorded for either check");
        }
    } else {
        tui::section("OLDER INDICATOR OUTCOMES");
        render_indicator_outcomes(older.lookups);
        tui::section("NEWER INDICATOR OUTCOMES");
        render_indicator_outcomes(newer.lookups);
    }
    tui::note("NOT FOUND means no matching record was returned; it is not a safety verdict.");
    tui::navigation_footer("Enter", "Return to Saved Reports");
}

fn render_indicator_outcomes(outcomes: &[crate::report::ProviderLookup]) {
    if outcomes.is_empty() {
        tui::field("Providers", "No outcomes were recorded for this indicator");
        return;
    }
    for outcome in outcomes {
        tui::field(
            &format!(
                "{} · {}",
                terminal_safe(&outcome.provider),
                terminal_safe(&outcome.queried_hash)
            ),
            outcome.outcome.status(),
        );
    }
}

pub(super) fn report_screen(saved: &SavedReport) {
    if let SavedReportContents::Session(report) = &saved.contents {
        session_check_screen(report, 0);
        return;
    }
    tui::header(
        "SAVED REPORT",
        &terminal_safe(
            saved
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("Investigation report"),
        ),
    );
    // Markdown is the report model's canonical renderer and already escapes
    // untrusted report values; box_line wraps each rendered line to the panel.
    for line in saved.contents.to_markdown().lines() {
        tui::box_line(line);
    }
    tui::navigation_footer("S / Enter", "Export STIX / return to the report list");
}

pub(super) fn session_check_screen(report: &SessionReport, check_index: usize) {
    let total = report.checks.len();
    tui::header(
        "SAVED SESSION REPORT",
        &format!(
            "Check {} of {total}",
            check_index.saturating_add(1).min(total)
        ),
    );
    let Some(check) = report.checks.get(check_index) else {
        tui::section("NO COMPLETED CHECKS");
        tui::navigation_footer("Enter", "Return to Saved Reports");
        return;
    };
    match check {
        SessionCheck::FileInvestigation { report } => {
            tui::section("FILE INVESTIGATION");
            tui::field("Filename", terminal_safe(&report.file.filename));
            tui::field("SHA-256", &report.file.sha256);
            render_provider_outcomes(&report.provider_lookups);
        }
        SessionCheck::IndicatorLookup {
            indicator,
            provider_lookups,
        } => {
            tui::section("INDICATOR LOOKUP");
            tui::field("Type", indicator.indicator_type.as_str());
            tui::field("Value", terminal_safe(&indicator.value));
            render_provider_outcomes(provider_lookups);
        }
    }
    tui::note("NOT FOUND means no matching record was returned; it is not a safety verdict.");
    tui::navigation_footer(
        "N / P / Enter",
        "Next check / previous check / return to Saved Reports",
    );
}

fn render_provider_outcomes(lookups: &[crate::report::ProviderLookup]) {
    if lookups.is_empty() {
        tui::field("Providers", "No provider outcomes recorded");
        return;
    }
    let outcomes = lookups
        .iter()
        .map(|lookup| {
            format!(
                "{}: {}",
                terminal_safe(&lookup.provider),
                lookup.outcome.status()
            )
        })
        .collect::<Vec<_>>()
        .join(" · ");
    tui::field("Outcomes", outcomes);
}

pub(super) fn comparison_screen(older: &InvestigationReport, newer: &InvestigationReport) {
    let (_, rows) = tui::terminal_dimensions();
    comparison_screen_at_height(older, newer, rows);
}

fn comparison_screen_at_height(
    older: &InvestigationReport,
    newer: &InvestigationReport,
    rows: usize,
) {
    let comparison = comparison::compare(older, newer);
    // The input redraw reserves a row for its prompt and compacts long screens.
    // Keep a useful comparison summary on ordinary terminal heights instead of
    // allowing that compaction to remove every comparison row.
    if rows < 48 || older.provider_lookups.len() + newer.provider_lookups.len() > 4 {
        compact_comparison_screen(older, newer, &comparison);
        return;
    }

    tui::header(
        "REPORT COMPARISON",
        "Recorded results · offline · read-only",
    );
    tui::section("COMPARISON SUMMARY");
    tui::field("Older report", terminal_safe(&older.file.filename));
    tui::field(
        "Older saved",
        format_timestamp(older.generated_at_unix_seconds),
    );
    tui::field("Newer report", terminal_safe(&newer.file.filename));
    tui::field(
        "Newer saved",
        format_timestamp(newer.generated_at_unix_seconds),
    );
    hash_field("Older SHA-256", &older.file.sha256);
    hash_field("Newer SHA-256", &newer.file.sha256);
    if !comparison.same_subject {
        tui::status(
            "File identity",
            "Different file contents — findings not compared",
            tui::Status::Neutral,
        );
        tui::section("WHAT IT MEANS");
        comparison_line(
            "The SHA-256 hashes differ, so these reports describe different file contents. The timestamps do not establish that one is a later version of the other.",
        );
    } else {
        tui::status(
            "File identity",
            "Same SHA-256 — recorded evidence can be compared",
            tui::Status::Neutral,
        );
        render_same_subject_comparison(&comparison);
    }
    technical_details_section("OLDER REPORT EVIDENCE", older);
    technical_details_section("NEWER REPORT EVIDENCE", newer);
    tui::navigation_footer("Enter", "Return to Saved Reports");
}

fn compact_comparison_screen(
    older: &InvestigationReport,
    newer: &InvestigationReport,
    comparison: &ReportComparison,
) {
    tui::header(
        "REPORT COMPARISON",
        "Recorded results · offline · read-only",
    );
    tui::field(
        "Older report",
        format!(
            "{} · {}",
            terminal_safe(&older.file.filename),
            format_timestamp(older.generated_at_unix_seconds)
        ),
    );
    tui::field(
        "Newer report",
        format!(
            "{} · {}",
            terminal_safe(&newer.file.filename),
            format_timestamp(newer.generated_at_unix_seconds)
        ),
    );
    hash_field("Older SHA-256", &older.file.sha256);
    hash_field("Newer SHA-256", &newer.file.sha256);
    if comparison.same_subject {
        tui::status(
            "File identity",
            "Same SHA-256 — recorded evidence can be compared",
            tui::Status::Neutral,
        );
        comparison_line(&format!(
            "Indicators: {} added · {} removed · {} unchanged",
            comparison.added_indicators.len(),
            comparison.removed_indicators.len(),
            comparison.unchanged_indicators
        ));
        comparison_line(&format!(
            "Provider observations changed: {}",
            comparison.provider_changes.len()
        ));
        for change in &comparison.provider_changes {
            comparison_line(change);
        }
        for change in &comparison.metadata_changes {
            comparison_line(change);
        }
    } else {
        tui::status(
            "File identity",
            "Different file contents — findings not compared",
            tui::Status::Neutral,
        );
        comparison_line(
            "The SHA-256 hashes differ, so findings cannot be compared. Timestamps do not establish that one is a later version.",
        );
    }
    tui::note("Compact view: open either saved report for complete provider evidence.");
    tui::navigation_footer("Enter", "Return to Saved Reports");
}

fn render_same_subject_comparison(comparison: &ReportComparison) {
    tui::section("WHAT CHANGED");
    comparison_line(&format!(
        "Indicators first recorded in newer report: {}",
        comparison.added_indicators.len()
    ));
    comparison_line(&format!(
        "Indicators absent from a complete newer scan: {}",
        comparison.removed_indicators.len()
    ));
    comparison_line(&format!(
        "Indicators present in both reports: {}",
        comparison.unchanged_indicators
    ));
    if comparison.indicator_absence_inconclusive {
        tui::box_line(
            "At least one extraction was skipped or incomplete; absence cannot be interpreted as removal.",
        );
    }
    for indicator in &comparison.added_indicators {
        comparison_line(&format!(
            "First recorded in newer report: {} {}",
            indicator.indicator_type.as_str(),
            indicator.value
        ));
    }
    for indicator in &comparison.removed_indicators {
        comparison_line(&format!(
            "Not found in the newer complete extraction: {} {}",
            indicator.indicator_type.as_str(),
            indicator.value
        ));
    }

    comparison_line(&format!(
        "Provider observations changed: {}",
        comparison.provider_changes.len()
    ));
    for change in &comparison.provider_changes {
        comparison_line(change);
    }

    tui::section("WHAT IT MEANS");
    if comparison.provider_changes.is_empty()
        && comparison.metadata_changes.is_empty()
        && comparison.added_indicators.is_empty()
        && comparison.removed_indicators.is_empty()
    {
        tui::box_line(
            "No meaningful differences were detected in the saved evidence. This does not establish that the file is safe.",
        );
    }
    if comparison.interpretations.is_empty() && !comparison.indicator_absence_inconclusive {
        tui::box_line("No changed provider results need interpretation.");
    }
    for meaning in &comparison.interpretations {
        comparison_line(meaning);
    }
    for change in &comparison.metadata_changes {
        comparison_line(change);
    }

    tui::section("WORTH CHECKING");
    if comparison.worth_checking.is_empty() && comparison.added_indicators.is_empty() {
        tui::box_line("No specific changed indicator or provider result was identified.");
    }
    for item in comparison.worth_checking.iter().take(12) {
        comparison_line(item);
    }
    for indicator in comparison.added_indicators.iter().take(12) {
        comparison_line(&format!(
            "{} {}",
            indicator.indicator_type.as_str(),
            indicator.value
        ));
    }
    tui::section("PROVIDER OUTCOME COUNTS");
    comparison_line(&format!(
        "Unchanged observations: {}",
        comparison.unchanged_provider_results
    ));
    comparison_line(&format!(
        "Unavailable/error/skipped observations: {}",
        comparison.unavailable_provider_results.len()
    ));
}

fn report_details_section(title: &str, report: &InvestigationReport) {
    tui::section(title);
    tui::field("Filename", terminal_safe(&report.file.filename));
    tui::field(
        "Generated",
        format_timestamp(report.generated_at_unix_seconds),
    );
    hash_field("SHA-256", &report.file.sha256);
}

fn technical_details_section(title: &str, report: &InvestigationReport) {
    report_details_section(title, report);
    for lookup in &report.provider_lookups {
        comparison_line(&format!(
            "{} · {:?} · {}",
            terminal_safe(&lookup.provider),
            lookup.subject,
            terminal_safe(lookup.outcome.status())
        ));
        super::super::provider_views::display_lookup_details(
            &lookup.provider,
            &lookup.queried_hash,
            &lookup.outcome,
        );
        if let Some(timestamp) = lookup.retrieved_at_unix_seconds {
            comparison_line(&format!("Checked: {}", format_timestamp(timestamp)));
        }
    }
}

fn hash_field(label: &str, hash: &str) {
    comparison_line(label);
    for line in hash_continuation_lines(hash, tui::content_width()) {
        tui::box_line(&line);
    }
}

fn hash_continuation_lines(hash: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let indentation = 4.min(width.saturating_sub(1));
    let value_width = width.saturating_sub(indentation).max(1);
    tui::wrap_text(&terminal_safe(hash), value_width)
        .into_iter()
        .map(|part| format!("{}{part}", " ".repeat(indentation)))
        .collect()
}

fn comparison_line(text: &str) {
    for line in wrap_comparison_text(text, tui::content_width()) {
        tui::box_line(&line);
    }
}

fn wrap_comparison_text(text: &str, width: usize) -> Vec<String> {
    tui::wrap_text(&terminal_safe(text), width)
}

fn terminal_safe(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

pub(super) fn format_timestamp(seconds: u64) -> String {
    let Ok(seconds) = i64::try_from(seconds) else {
        return format!("{seconds} (Unix seconds)");
    };
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    // Gregorian civil-date conversion, using UTC days from the Unix epoch.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        day_seconds / 3600,
        (day_seconds % 3600) / 60,
        day_seconds % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::FileInfo;
    use crate::indicator::{Indicator, IndicatorType};
    use crate::report::{InvestigationReport, LookupOutcome, LookupSubject, ProviderLookup};
    use std::path::PathBuf;

    #[test]
    fn saved_report_list_is_compact_and_uses_responsive_pages() {
        assert_eq!(report_page_capacity(12), 1);
        assert_eq!(report_page_capacity(24), 4);
        assert_eq!(report_page_capacity(40), 12);

        let collection = ReportCollection {
            reports: (1..=3)
                .map(|index| SavedReport {
                    path: PathBuf::from(format!("reports/session-{index}.json")),
                    contents: SavedReportContents::Session(SessionReport::new(Vec::new())),
                })
                .collect(),
            unavailable: Vec::new(),
        };
        crate::tui::reset_screen();
        crate::tui::header("SAVED REPORTS", "Review prior evidence");
        report_list(&collection, 2, 2);
        let rendered = crate::tui::test_rendered_lines(80, 32).join("\n");
        assert!(rendered.contains("PAGE 2/2"));
        assert!(rendered.contains("Session · session-3.json"));
        assert!(!rendered.contains("Session · session-1.json"));
        assert!(rendered.contains("Return to the main menu"));
        assert!(rendered.contains("Compare Same-File Reports"));
    }

    fn report_with_lookups(lookups: Vec<ProviderLookup>) -> InvestigationReport {
        let file = FileInfo {
            name: "new_test.txt".into(),
            size: 123,
            sha256: "file-sha256".into(),
        };
        InvestigationReport::new(
            &file,
            vec![Indicator::new("example.test", IndicatorType::Domain)],
            Some(false),
            lookups,
        )
    }

    fn file_lookup(subject: LookupSubject, value: &str, outcome: LookupOutcome) -> ProviderLookup {
        ProviderLookup {
            provider: "ThreatFox".into(),
            subject,
            queried_hash: value.into(),
            retrieved_at_unix_seconds: Some(1),
            outcome,
        }
    }

    fn positive_match() -> LookupOutcome {
        LookupOutcome::ThreatFoxFound {
            findings: vec![crate::report::ThreatFoxFinding {
                source_record_id: Some("offline-fixture".into()),
                ioc: "example.test".into(),
                ioc_type: "domain".into(),
                ioc_type_description: None,
                threat_type: None,
                threat_type_description: None,
                malware: None,
                malware_printable: None,
                confidence_level: None,
                first_seen: None,
                last_seen: None,
                reference: None,
                reporter: None,
                tags: Vec::new(),
            }],
        }
    }

    #[test]
    fn saved_file_report_summary_separates_file_hash_and_extracted_evidence() {
        let original_not_found = file_lookup(
            LookupSubject::OriginalFileSha256,
            "file-sha256",
            LookupOutcome::NotFound,
        );
        let extracted_match = file_lookup(
            LookupSubject::ExtractedIndicator,
            "example.test",
            positive_match(),
        );
        let report = report_with_lookups(vec![original_not_found.clone(), extracted_match]);
        let summary = file_report_status_summary(&report);
        assert!(summary.contains("File hash NOT FOUND"));
        assert!(summary.contains("1 extracted indicator match"));

        let report = report_with_lookups(vec![
            original_not_found,
            file_lookup(
                LookupSubject::ExtractedIndicator,
                "example.test",
                LookupOutcome::NotFound,
            ),
        ]);
        let summary = file_report_status_summary(&report);
        assert!(summary.contains("File hash NOT FOUND"));
        assert!(summary.contains("no extracted matches"));
        assert!(!summary.contains("safe"));
    }

    #[test]
    fn saved_file_report_summary_labels_local_only_and_incomplete_coverage() {
        let local_only = report_with_lookups(Vec::new());
        assert_eq!(
            file_report_status_summary(&local_only),
            "Local inspection only · no provider checks recorded"
        );

        let incomplete = report_with_lookups(vec![
            file_lookup(
                LookupSubject::OriginalFileSha256,
                "file-sha256",
                LookupOutcome::NotFound,
            ),
            file_lookup(
                LookupSubject::ExtractedIndicator,
                "example.test",
                LookupOutcome::SkippedLookupLimit,
            ),
        ]);
        let summary = file_report_status_summary(&incomplete);
        assert!(summary.contains("coverage incomplete"));
        assert!(summary.contains("1 skipped/unavailable/failed"));
        assert!(summary.contains("File hash NOT FOUND"));
    }

    #[test]
    fn saved_file_report_summary_preserves_positive_original_file_status() {
        let report = report_with_lookups(vec![file_lookup(
            LookupSubject::OriginalFileSha256,
            "file-sha256",
            positive_match(),
        )]);
        assert!(file_report_status_summary(&report).contains("File hash FOUND"));
    }

    fn session_lookup(provider: &str, value: &str, outcome: LookupOutcome) -> ProviderLookup {
        ProviderLookup {
            provider: provider.into(),
            subject: LookupSubject::ExtractedIndicator,
            queried_hash: value.into(),
            retrieved_at_unix_seconds: None,
            outcome,
        }
    }

    fn comparison_fixture(
        filename: &str,
        generated_at: u64,
        provider_outcome: LookupOutcome,
        indicator_value: &str,
    ) -> InvestigationReport {
        let file = FileInfo {
            name: filename.into(),
            size: 42,
            sha256: "same-file-sha256".into(),
        };
        let mut report = InvestigationReport::new(
            &file,
            vec![Indicator::new(indicator_value, IndicatorType::Domain)],
            Some(false),
            vec![ProviderLookup {
                provider: "ThreatFox".into(),
                subject: LookupSubject::ExtractedIndicator,
                queried_hash: indicator_value.into(),
                retrieved_at_unix_seconds: Some(generated_at),
                outcome: provider_outcome,
            }],
        );
        report.generated_at_unix_seconds = generated_at;
        report
    }

    #[test]
    fn short_terminal_comparison_renders_selected_report_differences() {
        let older = comparison_fixture(
            "older-evidence.bin",
            100,
            LookupOutcome::NotFound,
            "old.example.test",
        );
        let newer = comparison_fixture(
            "newer-evidence.bin",
            200,
            LookupOutcome::ApiError {
                explanation: "temporary provider failure".into(),
            },
            "old.example.test",
        );

        crate::tui::reset_screen();
        comparison_screen_at_height(&older, &newer, 24);
        let rendered = crate::tui::test_rendered_lines_for_rows(80, 23).join("\n");

        assert!(rendered.contains("REPORT COMPARISON"));
        assert!(rendered.contains("older-evidence.bin"));
        assert!(rendered.contains("newer-evidence.bin"));
        assert!(rendered.contains("00:01:40 UTC"));
        assert!(rendered.contains("00:03:20 UTC"));
        assert!(rendered.contains("Same SHA-256"));
        assert!(rendered.contains("Indicators:"));
        assert!(rendered.contains("Provider observations changed: 1"));
        assert!(rendered.contains("NOT FOUND"));
        assert!(rendered.contains("API ERROR"));
    }

    #[test]
    fn different_file_hashes_explain_same_file_comparison_and_return_path() {
        let older =
            comparison_fixture("test.txt", 100, LookupOutcome::NotFound, "old.example.test");
        let mut newer = comparison_fixture(
            "new_test.txt",
            200,
            LookupOutcome::NotFound,
            "old.example.test",
        );
        newer.file.sha256 = "different-file-content".into();

        let rendered = crate::tui::with_test_terminal_dimensions(80, 23, || {
            crate::tui::reset_screen();
            comparison_screen_at_height(&older, &newer, 24);
            crate::tui::test_rendered_lines_for_rows(80, 23).join("\n")
        });
        let rendered_without_line_breaks = rendered.lines().collect::<Vec<_>>().join(" ");
        assert!(rendered.contains("Different file contents"));
        assert!(rendered.contains("SHA-256 hashes differ"));
        assert!(rendered.contains("Timestamps do not"));
        assert!(
            rendered_without_line_breaks.contains("establish that one is a later version."),
            "complete comparison warning missing from rendered screen:\n{rendered}"
        );
        assert!(rendered.contains("Return to Saved Reports"));
        assert!(!rendered.contains("Indicators: 0 added"));
    }

    #[test]
    fn session_report_pages_render_each_check_and_its_recorded_provider_outcomes() {
        let file = FileInfo {
            name: "checked-file.bin".into(),
            size: 7,
            sha256: "file-sha".into(),
        };
        let checks = vec![
            SessionCheck::FileInvestigation {
                report: Box::new(InvestigationReport::new(
                    &file,
                    Vec::new(),
                    Some(false),
                    vec![session_lookup(
                        "MalwareBazaar",
                        "file-sha",
                        LookupOutcome::NotConfigured,
                    )],
                )),
            },
            SessionCheck::IndicatorLookup {
                indicator: Indicator::new("0123456789abcdef", IndicatorType::Hash),
                provider_lookups: vec![session_lookup(
                    "ThreatFox",
                    "0123456789abcdef",
                    LookupOutcome::NotFound,
                )],
            },
            SessionCheck::IndicatorLookup {
                indicator: Indicator::new("192.0.2.8", IndicatorType::IP),
                provider_lookups: vec![session_lookup(
                    "URLhaus",
                    "192.0.2.8",
                    LookupOutcome::Unsupported {
                        explanation: "unsupported test lookup".into(),
                    },
                )],
            },
            SessionCheck::IndicatorLookup {
                indicator: Indicator::new("example.test", IndicatorType::Domain),
                provider_lookups: vec![session_lookup(
                    "ThreatFox",
                    "example.test",
                    LookupOutcome::ApiError {
                        explanation: "temporary failure".into(),
                    },
                )],
            },
        ];
        let report = SessionReport::new(checks);
        let mut rendered_pages = Vec::new();

        for index in 0..report.checks.len() {
            crate::tui::reset_screen();
            session_check_screen(&report, index);
            rendered_pages.push(crate::tui::test_rendered_lines(160, 512).join("\n"));
        }

        let rendered = rendered_pages.join("\n");
        for expected in [
            "FILE INVESTIGATION",
            "checked-file.bin",
            "MalwareBazaar: NOT CONFIGURED",
            "HASH",
            "0123456789abcdef",
            "ThreatFox: NOT FOUND",
            "IP",
            "192.0.2.8",
            "URLhaus: UNSUPPORTED",
            "DOMAIN",
            "example.test",
            "ThreatFox: API ERROR",
        ] {
            assert!(
                rendered.contains(expected),
                "missing {expected} in {rendered}"
            );
        }
    }

    #[test]
    fn same_hash_comparison_highlights_genuine_provider_status_changes() {
        let older = vec![session_lookup(
            "ThreatFox",
            "same-hash",
            LookupOutcome::NotFound,
        )];
        let newer = vec![session_lookup(
            "ThreatFox",
            "SAME-HASH",
            LookupOutcome::ApiError {
                explanation: "offline".into(),
            },
        )];
        crate::tui::reset_screen();
        indicator_comparison_screen(
            "HASH",
            IndicatorCheck {
                value: "same-hash",
                source: "cyberfeed-session-1.json",
                time: 100,
                lookups: &older,
            },
            IndicatorCheck {
                value: "SAME-HASH",
                source: "cyberfeed-indicator-HASH-example-200.json",
                time: 200,
                lookups: &newer,
            },
        );
        let rendered = crate::tui::test_rendered_lines_for_rows(100, 30).join("\n");
        assert!(rendered.contains("INDICATOR COMPARISON"));
        assert!(rendered.contains("same-hash"));
        assert!(rendered.contains("NOT FOUND → API ERROR · CHANGED"));
        assert!(rendered.contains("cyberfeed-session-1.json"));
        assert!(rendered.contains("cyberfeed-indicator-HASH-example-200.json"));
        assert!(rendered.contains("offline · read-only"));
    }

    #[test]
    fn different_hashes_render_separate_outcomes_without_status_change_claims() {
        let older = vec![session_lookup(
            "ThreatFox",
            "older-hash",
            LookupOutcome::NotFound,
        )];
        let newer = vec![session_lookup(
            "ThreatFox",
            "newer-hash",
            LookupOutcome::NotConfigured,
        )];
        crate::tui::reset_screen();
        indicator_comparison_screen(
            "HASH",
            IndicatorCheck {
                value: "older-hash",
                source: "cyberfeed-session-1.json",
                time: 100,
                lookups: &older,
            },
            IndicatorCheck {
                value: "newer-hash",
                source: "cyberfeed-indicator-HASH-newer-200.json",
                time: 200,
                lookups: &newer,
            },
        );
        let rendered = crate::tui::test_rendered_lines_for_rows(100, 32).join("\n");
        assert!(rendered.contains("Older value") && rendered.contains("older-hash"));
        assert!(rendered.contains("Newer value") && rendered.contains("newer-hash"));
        assert!(rendered.contains("OLDER INDICATOR OUTCOMES"));
        assert!(rendered.contains("NEWER INDICATOR OUTCOMES"));
        assert!(rendered.contains("ThreatFox · older-hash") && rendered.contains("NOT FOUND"));
        assert!(rendered.contains("ThreatFox · newer-hash") && rendered.contains("NOT CONFIGURED"));
        assert!(!rendered.contains("CHANGED"));
        assert!(!rendered.contains("NOT RECORDED"));
    }

    #[test]
    fn formats_utc_timestamps() {
        assert_eq!(format_timestamp(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_timestamp(1_700_000_000), "2023-11-14 22:13:20 UTC");
    }

    #[test]
    fn wraps_sentences_hashes_and_narrow_terminal_text_without_loss() {
        let sentence = "Different file SHA-256 values mean findings cannot be compared reliably.";
        let lines = wrap_comparison_text(sentence, 20);
        assert!(lines.iter().all(|line| line.len() <= 20));
        assert_eq!(
            lines.join(" ").split_whitespace().collect::<Vec<_>>(),
            sentence.split_whitespace().collect::<Vec<_>>()
        );
        let hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let lines = wrap_comparison_text(hash, 12);
        assert!(lines.iter().all(|line| line.len() <= 12));
        assert_eq!(lines.concat(), hash);
        for width in [1, 10, 30, 80] {
            let hash_lines = hash_continuation_lines(hash, width);
            assert!(hash_lines.iter().all(|line| line.len() <= width.max(1)));
            assert_eq!(
                hash_lines
                    .iter()
                    .map(|line| line.trim_start())
                    .collect::<Vec<_>>()
                    .concat(),
                hash
            );
            if width >= 10 {
                assert!(hash_lines.iter().all(|line| line.starts_with("    ")));
            }
        }
        assert!(
            wrap_comparison_text("narrow terminal text", 1)
                .iter()
                .all(|line| line.len() <= 1)
        );
    }
}
