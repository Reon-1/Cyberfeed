//! Terminal rendering and display formatting for saved report data.
use super::comparison::{self, ReportComparison};
use super::report_files::{ReportCollection, SavedReport};
use crate::report::InvestigationReport;
use crate::ui;

pub(super) fn report_list(collection: &ReportCollection) {
    ui::menu_item("C", "Compare Reports", "Compare two saved reports offline");
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
            ui::menu_item(
                &(index + 1).to_string(),
                &terminal_safe(name),
                &terminal_safe(&format!(
                    "{} bytes · {} · {}",
                    saved.report.file.size_bytes,
                    format_timestamp(saved.report.generated_at_unix_seconds),
                    saved
                        .report
                        .summary
                        .original_file_lookup_status
                        .as_deref()
                        .unwrap_or("lookup not recorded")
                )),
            );
            ui::field("File", terminal_safe(&saved.report.file.filename));
            ui::field(
                "Generated",
                format_timestamp(saved.report.generated_at_unix_seconds),
            );
            ui::field("SHA-256", abbreviated_sha256(&saved.report.file.sha256));
            ui::field(
                "Original lookup",
                terminal_safe(
                    saved
                        .report
                        .summary
                        .original_file_lookup_status
                        .as_deref()
                        .unwrap_or("not recorded"),
                ),
            );
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

pub(super) fn report_screen(saved: &SavedReport) {
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
    for line in saved.report.to_markdown().lines() {
        ui::box_line(line);
    }
    ui::navigation_footer("Enter", "Return to the report list");
    ui::close_box();
}

pub(super) fn comparison_screen(older: &InvestigationReport, newer: &InvestigationReport) {
    let comparison = comparison::compare(older, newer);
    ui::header(
        "REPORT COMPARISON",
        "Recorded results · offline · read-only",
    );
    report_details_section("OLDER REPORT", older);
    report_details_section("NEWER REPORT", newer);
    if !comparison.same_subject {
        ui::status(
            "RESULT",
            "DIFFERENT SUBJECTS — FINDINGS NOT COMPARED",
            ui::Status::Warning,
        );
        ui::section("WHY NO COMPARISON?");
        comparison_line(
            "The file SHA-256 values differ, so these reports describe different file subjects. A historical findings comparison would be unreliable.",
        );
    } else {
        render_same_subject_comparison(&comparison);
    }
    ui::navigation_footer("Enter", "Return to Saved Reports");
    ui::close_box();
}

fn render_same_subject_comparison(comparison: &ReportComparison) {
    ui::status(
        "RESULT",
        "SAME FILE SUBJECT — RECORDED RESULTS COMPARED",
        ui::Status::Success,
    );
    ui::section("INVESTIGATION METADATA");
    if comparison.metadata_changes.is_empty() {
        ui::box_line("No recorded metadata differences.");
    }
    for change in &comparison.metadata_changes {
        comparison_line(&format!("• {change}"));
    }

    ui::section("INDICATOR CHANGES");
    comparison_line(&format!("Added: {}", comparison.added_indicators.len()));
    comparison_line(&format!("Removed: {}", comparison.removed_indicators.len()));
    comparison_line(&format!("Unchanged: {}", comparison.unchanged_indicators));
    if comparison.added_indicators.is_empty() && comparison.removed_indicators.is_empty() {
        ui::box_line("No indicator additions or removals.");
    }
    for indicator in &comparison.added_indicators {
        comparison_line(&format!(
            "Added in newer report: {} {}",
            indicator.indicator_type.as_str(),
            indicator.value
        ));
    }
    for indicator in &comparison.removed_indicators {
        comparison_line(&format!(
            "Absent from newer report: {} {}",
            indicator.indicator_type.as_str(),
            indicator.value
        ));
    }

    ui::section("PROVIDER RESULTS");
    comparison_line(&format!("Changed: {}", comparison.provider_changes.len()));
    comparison_line(&format!(
        "Unchanged: {}",
        comparison.unchanged_provider_results
    ));
    comparison_line(&format!(
        "Unavailable/error/skipped: {}",
        comparison.unavailable_provider_results.len()
    ));
    for change in &comparison.provider_changes {
        comparison_line(&format!("Changed outcome: {change}"));
    }
    for unavailable in &comparison.unavailable_provider_results {
        comparison_line(&format!("Unavailable or skipped: {unavailable}"));
    }
    if comparison.provider_changes.is_empty() && comparison.unavailable_provider_results.is_empty()
    {
        ui::box_line("No provider result differences or unavailable outcomes.");
    }
    comparison_line(
        "These are saved outcome changes only. NOT FOUND is not proof of safety; an error followed by success does not establish that a threat appeared.",
    );
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

fn format_timestamp(seconds: u64) -> String {
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
