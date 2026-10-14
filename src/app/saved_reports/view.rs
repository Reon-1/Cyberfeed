//! Terminal rendering and display formatting for saved report data.
use super::comparison::{self, ReportComparison};
use super::report_files::{ReportCollection, SavedReport, SavedReportContents};
use crate::report::{InvestigationReport, SessionCheck, SessionReport};
use crate::ui;

pub(super) fn report_list(collection: &ReportCollection) {
    ui::menu_item(
        "C",
        "Compare File Reports",
        "Compare two file investigations offline",
    );
    ui::menu_item(
        "I",
        "Compare Indicator Checks",
        "Compare recorded hash, IP, or domain lookups offline",
    );
    if collection.reports.is_empty() {
        ui::section("NO VALID REPORTS");
        ui::box_line("No readable JSON investigation reports were found in reports/.");
    } else {
        ui::section("AVAILABLE REPORTS — NEWEST FIRST");
        for (index, saved) in collection.reports.iter().enumerate() {
            let name = saved
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("(unprintable filename)");
            match &saved.contents {
                SavedReportContents::File(report) => {
                    ui::menu_item(
                        &(index + 1).to_string(),
                        &terminal_safe(name),
                        &terminal_safe(&format!(
                            "{} bytes · {} · {}",
                            report.file.size_bytes,
                            format_timestamp(report.generated_at_unix_seconds),
                            report
                                .summary
                                .original_file_lookup_status
                                .as_deref()
                                .unwrap_or("lookup not recorded")
                        )),
                    );
                    ui::field("Report type", "File investigation");
                    ui::field("File", terminal_safe(&report.file.filename));
                    ui::field(
                        "Generated",
                        format_timestamp(report.generated_at_unix_seconds),
                    );
                    ui::field("SHA-256", abbreviated_sha256(&report.file.sha256));
                    ui::field(
                        "Original lookup",
                        terminal_safe(
                            report
                                .summary
                                .original_file_lookup_status
                                .as_deref()
                                .unwrap_or("not recorded"),
                        ),
                    );
                }
                SavedReportContents::Session(report) => {
                    ui::menu_item(
                        &(index + 1).to_string(),
                        &terminal_safe(name),
                        &terminal_safe(&format!(
                            "Session · {} completed check(s) · {}",
                            report.checks.len(),
                            format_timestamp(report.generated_at_unix_seconds)
                        )),
                    );
                    ui::field("Report type", "Current session");
                    ui::field("Completed checks", report.checks.len());
                    ui::field(
                        "Generated",
                        format_timestamp(report.generated_at_unix_seconds),
                    );
                }
            }
            ui::box_line("");
        }
    }
    if !collection.unavailable.is_empty() {
        ui::warning(&format!(
            "{} JSON file(s) could not be loaded (malformed, unreadable, or unsupported schema); valid reports remain available.",
            collection.unavailable.len()
        ));
        for issue in &collection.unavailable {
            ui::field("Skipped", terminal_safe(issue));
        }
    }
    ui::navigation_footer("0", "Return to the main menu");
    ui::close_box();
}

pub(super) fn indicator_comparison_screen(
    indicator_type: &str,
    older_value: &str,
    newer_value: &str,
    older_source: &str,
    older_time: u64,
    older: &[crate::report::ProviderLookup],
    newer_source: &str,
    newer_time: u64,
    newer: &[crate::report::ProviderLookup],
) {
    ui::header(
        "INDICATOR COMPARISON",
        "Recorded results · offline · read-only",
    );
    ui::field("Type", indicator_type);
    ui::field("Older value", terminal_safe(older_value));
    ui::field("Newer value", terminal_safe(newer_value));
    ui::section("SAVED CHECKS");
    ui::field(
        "Older",
        format!(
            "{} · {}",
            terminal_safe(older_source),
            format_timestamp(older_time)
        ),
    );
    ui::field(
        "Newer",
        format!(
            "{} · {}",
            terminal_safe(newer_source),
            format_timestamp(newer_time)
        ),
    );
    if older_value.eq_ignore_ascii_case(newer_value) {
        ui::section("PROVIDER OUTCOME COMPARISON");
        let mut seen = Vec::<(String, String)>::new();
        for lookup in older.iter().chain(newer) {
            let key = (
                lookup.provider.clone(),
                lookup.queried_hash.to_ascii_lowercase(),
            );
            if seen.contains(&key) {
                continue;
            }
            seen.push(key.clone());
            let old = older.iter().find(|item| {
                item.provider == key.0 && item.queried_hash.eq_ignore_ascii_case(&key.1)
            });
            let new = newer.iter().find(|item| {
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
            ui::field(
                &format!("{} · {}", terminal_safe(&key.0), terminal_safe(&key.1)),
                outcome,
            );
        }
        if older.is_empty() && newer.is_empty() {
            ui::field("Providers", "No outcomes were recorded for either check");
        }
    } else {
        ui::section("OLDER INDICATOR OUTCOMES");
        render_indicator_outcomes(older);
        ui::section("NEWER INDICATOR OUTCOMES");
        render_indicator_outcomes(newer);
    }
    ui::note("NOT FOUND means no matching record was returned; it is not a safety verdict.");
    ui::navigation_footer("Enter", "Return to Saved Reports");
    ui::close_box();
}

fn render_indicator_outcomes(outcomes: &[crate::report::ProviderLookup]) {
    if outcomes.is_empty() {
        ui::field("Providers", "No outcomes were recorded for this indicator");
        return;
    }
    for outcome in outcomes {
        ui::field(
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
    ui::header(
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
        ui::box_line(line);
    }
    ui::navigation_footer("S / Enter", "Export STIX / return to the report list");
    ui::close_box();
}

pub(super) fn session_check_screen(report: &SessionReport, check_index: usize) {
    let total = report.checks.len();
    ui::header(
        "SAVED SESSION REPORT",
        &format!(
            "Check {} of {total}",
            check_index.saturating_add(1).min(total)
        ),
    );
    let Some(check) = report.checks.get(check_index) else {
        ui::section("NO COMPLETED CHECKS");
        ui::navigation_footer("Enter", "Return to Saved Reports");
        ui::close_box();
        return;
    };
    match check {
        SessionCheck::FileInvestigation { report } => {
            ui::section("FILE INVESTIGATION");
            ui::field("Filename", terminal_safe(&report.file.filename));
            ui::field("SHA-256", &report.file.sha256);
            render_provider_outcomes(&report.provider_lookups);
        }
        SessionCheck::IndicatorLookup {
            indicator,
            provider_lookups,
        } => {
            ui::section("INDICATOR LOOKUP");
            ui::field("Type", indicator.indicator_type.as_str());
            ui::field("Value", terminal_safe(&indicator.value));
            render_provider_outcomes(provider_lookups);
        }
    }
    ui::note("NOT FOUND means no matching record was returned; it is not a safety verdict.");
    ui::navigation_footer(
        "N / P / Enter",
        "Next check / previous check / return to Saved Reports",
    );
    ui::close_box();
}

fn render_provider_outcomes(lookups: &[crate::report::ProviderLookup]) {
    if lookups.is_empty() {
        ui::field("Providers", "No provider outcomes recorded");
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
    ui::field("Outcomes", outcomes);
}

pub(super) fn comparison_screen(older: &InvestigationReport, newer: &InvestigationReport) {
    let (_, rows) = ui::terminal_dimensions();
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

    ui::header(
        "REPORT COMPARISON",
        "Recorded results · offline · read-only",
    );
    ui::section("COMPARISON SUMMARY");
    ui::field("Older report", terminal_safe(&older.file.filename));
    ui::field(
        "Older saved",
        format_timestamp(older.generated_at_unix_seconds),
    );
    ui::field("Newer report", terminal_safe(&newer.file.filename));
    ui::field(
        "Newer saved",
        format_timestamp(newer.generated_at_unix_seconds),
    );
    hash_field("Older SHA-256", &older.file.sha256);
    hash_field("Newer SHA-256", &newer.file.sha256);
    if !comparison.same_subject {
        ui::status(
            "File identity",
            "Different file contents — findings not compared",
            ui::Status::Neutral,
        );
        ui::section("WHAT IT MEANS");
        comparison_line(
            "The SHA-256 hashes differ, so these reports describe different file contents. The timestamps do not establish that one is a later version of the other.",
        );
    } else {
        ui::status(
            "File identity",
            "Same SHA-256 — recorded evidence can be compared",
            ui::Status::Neutral,
        );
        render_same_subject_comparison(&comparison);
    }
    technical_details_section("OLDER REPORT EVIDENCE", older);
    technical_details_section("NEWER REPORT EVIDENCE", newer);
    ui::navigation_footer("Enter", "Return to Saved Reports");
    ui::close_box();
}

fn compact_comparison_screen(
    older: &InvestigationReport,
    newer: &InvestigationReport,
    comparison: &ReportComparison,
) {
    ui::header(
        "REPORT COMPARISON",
        "Recorded results · offline · read-only",
    );
    ui::field(
        "Older report",
        format!(
            "{} · {}",
            terminal_safe(&older.file.filename),
            format_timestamp(older.generated_at_unix_seconds)
        ),
    );
    ui::field(
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
        ui::status(
            "File identity",
            "Same SHA-256 — recorded evidence can be compared",
            ui::Status::Neutral,
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
        ui::status(
            "File identity",
            "Different file contents — findings not compared",
            ui::Status::Neutral,
        );
        comparison_line(
            "The SHA-256 hashes differ, so findings cannot be compared. Timestamps do not establish that one is a later version.",
        );
    }
    ui::note("Compact view: open either saved report for complete provider evidence.");
    ui::navigation_footer("Enter", "Return to Saved Reports");
    ui::close_box();
}

fn render_same_subject_comparison(comparison: &ReportComparison) {
    ui::section("WHAT CHANGED");
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
        ui::box_line(
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

    ui::section("WHAT IT MEANS");
    if comparison.provider_changes.is_empty()
        && comparison.metadata_changes.is_empty()
        && comparison.added_indicators.is_empty()
        && comparison.removed_indicators.is_empty()
    {
        ui::box_line(
            "No meaningful differences were detected in the saved evidence. This does not establish that the file is safe.",
        );
    }
    if comparison.interpretations.is_empty() && !comparison.indicator_absence_inconclusive {
        ui::box_line("No changed provider results need interpretation.");
    }
    for meaning in &comparison.interpretations {
        comparison_line(meaning);
    }
    for change in &comparison.metadata_changes {
        comparison_line(change);
    }

    ui::section("WORTH CHECKING");
    if comparison.worth_checking.is_empty() && comparison.added_indicators.is_empty() {
        ui::box_line("No specific changed indicator or provider result was identified.");
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
    ui::section("PROVIDER OUTCOME COUNTS");
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
    ui::section(title);
    ui::field("Filename", terminal_safe(&report.file.filename));
    ui::field(
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
    for line in hash_continuation_lines(hash, ui::content_width()) {
        ui::box_line(&line);
    }
}

fn hash_continuation_lines(hash: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let indentation = 4.min(width.saturating_sub(1));
    let value_width = width.saturating_sub(indentation).max(1);
    ui::wrap_text(&terminal_safe(hash), value_width)
        .into_iter()
        .map(|part| format!("{}{part}", " ".repeat(indentation)))
        .collect()
}

fn comparison_line(text: &str) {
    for line in wrap_comparison_text(text, ui::content_width()) {
        ui::box_line(&line);
    }
}

fn wrap_comparison_text(text: &str, width: usize) -> Vec<String> {
    ui::wrap_text(&terminal_safe(text), width)
}

fn abbreviated_sha256(hash: &str) -> String {
    const DISPLAY_LENGTH: usize = 18;
    let hash = terminal_safe(hash);
    if hash.chars().count() <= DISPLAY_LENGTH {
        return hash;
    }
    format!("{}…", hash.chars().take(DISPLAY_LENGTH).collect::<String>())
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

        crate::ui::reset_screen();
        comparison_screen_at_height(&older, &newer, 24);
        let rendered = crate::ui::recorded_rendered_lines_for_rows(80, 23).join("\n");

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
            crate::ui::reset_screen();
            session_check_screen(&report, index);
            rendered_pages.push(crate::ui::recorded_line_texts().join("\n"));
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
        crate::ui::reset_screen();
        indicator_comparison_screen(
            "HASH",
            "same-hash",
            "SAME-HASH",
            "cyberfeed-session-1.json",
            100,
            &older,
            "cyberfeed-indicator-HASH-example-200.json",
            200,
            &newer,
        );
        let rendered = crate::ui::recorded_rendered_lines_for_rows(100, 30).join("\n");
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
        crate::ui::reset_screen();
        indicator_comparison_screen(
            "HASH",
            "older-hash",
            "newer-hash",
            "cyberfeed-session-1.json",
            100,
            &older,
            "cyberfeed-indicator-HASH-newer-200.json",
            200,
            &newer,
        );
        let rendered = crate::ui::recorded_rendered_lines_for_rows(100, 32).join("\n");
        assert!(rendered.contains("Older value : older-hash"));
        assert!(rendered.contains("Newer value : newer-hash"));
        assert!(rendered.contains("OLDER INDICATOR OUTCOMES"));
        assert!(rendered.contains("NEWER INDICATOR OUTCOMES"));
        assert!(rendered.contains("ThreatFox · older-hash : NOT FOUND"));
        assert!(rendered.contains("ThreatFox · newer-hash : NOT CONFIGURED"));
        assert!(!rendered.contains("CHANGED"));
        assert!(!rendered.contains("NOT RECORDED"));
    }

    #[test]
    fn formats_utc_timestamps_and_abbreviates_list_hashes() {
        assert_eq!(format_timestamp(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_timestamp(1_700_000_000), "2023-11-14 22:13:20 UTC");
        assert_eq!(abbreviated_sha256("short"), "short");
        assert_eq!(
            abbreviated_sha256("0123456789abcdef0123456789abcdef"),
            "0123456789abcdef01…"
        );
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
