//! Menu orchestration for browsing and comparing saved investigation reports.
mod comparison;
mod report_files;
mod view;

use super::terminal::{self, InputEditor};
use crate::indicator::{Indicator, IndicatorType};
use crate::report::{InvestigationReport, ProviderLookup, SessionCheck, SessionReport};
use crate::ui;
use std::io;
use std::path::Path;

struct FileReportCandidate<'a> {
    report: &'a InvestigationReport,
    title: String,
    description: String,
}

struct IndicatorReportCandidate {
    indicator: Indicator,
    provider_lookups: Vec<ProviderLookup>,
    generated_at: u64,
    source: String,
    description: String,
}

pub(super) fn menu(editor: &mut InputEditor) {
    loop {
        terminal::clear_screen();
        ui::header("SAVED REPORTS", "Your saved investigations · newest first");
        let collection = match report_files::discover(Path::new("reports")) {
            Ok(collection) => collection,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                ui::section("NO REPORT DIRECTORY");
                ui::field("Location", "reports/ in the current working directory");
                ui::box_line("Save a file or current-session report to create this directory.");
                return_to_parent();
                terminal::pause();
                break;
            }
            Err(error) => {
                ui::section("COULD NOT READ REPORT DIRECTORY");
                ui::field("Details", error);
                return_to_parent();
                terminal::pause();
                break;
            }
        };

        view::report_list(&collection);
        let selection = terminal::read_input(
            editor,
            "\n  Choose a report, C compare files, I compare indicators, or 0 to go back: ",
            false,
        );
        if selection == "0" {
            break;
        }
        if selection.eq_ignore_ascii_case("c") {
            compare_reports(editor, &collection.reports);
            continue;
        }
        if selection.eq_ignore_ascii_case("i") {
            compare_indicator_checks(editor, &collection.reports);
            continue;
        }
        match selected_index(&selection, collection.reports.len()) {
            Some(index) => {
                let saved = &collection.reports[index];
                if let report_files::SavedReportContents::Session(report) = &saved.contents {
                    browse_session_report(editor, report);
                } else {
                    terminal::clear_screen();
                    view::report_screen(saved);
                    let Some(report) = saved.contents.file_report() else {
                        unreachable!("session reports are opened in the session viewer")
                    };
                    let action = terminal::read_input(
                        editor,
                        "\n  Enter to return, or S to export STIX 2.1: ",
                        false,
                    );
                    if action.eq_ignore_ascii_case("s") {
                        if crate::report::stix_indicator_count(report) == 0 {
                            terminal::show_error(
                                "This report contains no supported indicators to export.",
                            );
                            continue;
                        }
                        match crate::report::save_stix_bundle(report, Path::new("reports/stix")) {
                            Ok(path) => terminal::show_error(&format!(
                                "STIX bundle saved: {}",
                                path.display()
                            )),
                            Err(error) => terminal::show_error(&format!(
                                "Could not save STIX bundle: {error}"
                            )),
                        }
                    }
                }
            }
            None => terminal::invalid_choice(),
        }
    }
}

fn browse_session_report(editor: &mut InputEditor, report: &SessionReport) {
    if report.checks.is_empty() {
        terminal::clear_screen();
        ui::header("SAVED SESSION REPORT", "No completed checks were recorded");
        ui::navigation_footer("Enter", "Return to Saved Reports");
        ui::close_box();
        let _ = terminal::read_input(editor, "\n  Press Enter to return: ", false);
        return;
    }

    let mut index = 0;
    loop {
        terminal::clear_screen();
        view::session_check_screen(report, index);
        match terminal::read_input(
            editor,
            "\n  N next check · P previous check · Enter return: ",
            false,
        )
        .to_ascii_lowercase()
        .as_str()
        {
            "n" if index + 1 < report.checks.len() => index += 1,
            "p" if index > 0 => index -= 1,
            "" | "0" => break,
            _ => terminal::invalid_choice(),
        }
    }
}

fn file_comparison_candidates(
    reports: &[report_files::SavedReport],
) -> Vec<FileReportCandidate<'_>> {
    let mut candidates = Vec::new();
    for saved in reports {
        let source_name = saved
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("saved report");
        match &saved.contents {
            report_files::SavedReportContents::File(report) => {
                candidates.push(file_candidate(
                    report,
                    format!(
                        "Standalone · SHA-256 {} · {}",
                        report.file.sha256,
                        view::format_timestamp(report.generated_at_unix_seconds)
                    ),
                ));
            }
            report_files::SavedReportContents::Session(session) => {
                let total_file_checks = session
                    .checks
                    .iter()
                    .filter(|check| matches!(check, SessionCheck::FileInvestigation { .. }))
                    .count();
                let mut file_check_number = 0;
                for (check_index, check) in session.checks.iter().enumerate() {
                    if let SessionCheck::FileInvestigation { report } = check {
                        file_check_number += 1;
                        candidates.push(file_candidate(
                            report,
                            format!(
                                "Session {source_name} · file check {file_check_number} of {total_file_checks} (session check {}) · SHA-256 {} · {}",
                                check_index + 1,
                                report.file.sha256,
                                view::format_timestamp(report.generated_at_unix_seconds)
                            ),
                        ));
                    }
                }
            }
        }
    }
    candidates
}

fn file_candidate<'a>(
    report: &'a InvestigationReport,
    description: String,
) -> FileReportCandidate<'a> {
    FileReportCandidate {
        report,
        title: report.file.filename.clone(),
        description,
    }
}

fn compare_reports(editor: &mut InputEditor, reports: &[report_files::SavedReport]) {
    let candidates = file_comparison_candidates(reports);
    if candidates.len() < 2 {
        terminal::show_error("At least two valid file reports are required for comparison.");
        return;
    }
    terminal::clear_screen();
    ui::header(
        "COMPARE FILE REPORTS",
        "Session reports are not file comparisons",
    );
    for (index, candidate) in candidates.iter().enumerate() {
        ui::menu_item(
            &(index + 1).to_string(),
            &candidate.title,
            &candidate.description,
        );
    }
    ui::navigation_footer("0", "Cancel comparison");
    ui::close_box();
    let Some(first) = prompt_report_index(
        editor,
        candidates.len(),
        "First file report number (0 to cancel): ",
    ) else {
        return;
    };
    let Some(second) = prompt_report_index(
        editor,
        candidates.len(),
        "Second file report number (0 to cancel): ",
    ) else {
        return;
    };
    if first == second {
        terminal::show_error("Choose two different saved reports.");
        return;
    }
    let first = candidates[first].report;
    let second = candidates[second].report;
    let (older, newer) = if first.generated_at_unix_seconds <= second.generated_at_unix_seconds {
        (first, second)
    } else {
        (second, first)
    };
    terminal::clear_screen();
    view::comparison_screen(older, newer);
    let _ = terminal::read_input(editor, "\n  Press Enter to continue: ", false);
}

fn indicator_comparison_candidates(
    reports: &[report_files::SavedReport],
    indicator_type: IndicatorType,
) -> Vec<IndicatorReportCandidate> {
    let mut candidates = Vec::new();
    for saved in reports {
        let source_name = saved
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("saved report");
        if !matches!(
            indicator_type,
            IndicatorType::Hash | IndicatorType::IP | IndicatorType::Domain
        ) {
            continue;
        }
        match &saved.contents {
            report_files::SavedReportContents::File(report) => {
                let report_time = report.generated_at_unix_seconds;
                let file_hash = Indicator::new(report.file.sha256.clone(), IndicatorType::Hash);
                let original_lookups = report
                    .provider_lookups
                    .iter()
                    .filter(|lookup| {
                        lookup.subject == crate::report::LookupSubject::OriginalFileSha256
                            && lookup
                                .queried_hash
                                .eq_ignore_ascii_case(&report.file.sha256)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                if indicator_type == IndicatorType::Hash && !original_lookups.is_empty() {
                    candidates.push(indicator_candidate(
                        file_hash,
                        original_lookups,
                        report_time,
                        format!("Standalone · {source_name}"),
                    ));
                }
                let mut seen = std::collections::HashSet::new();
                for indicator in &report.local_inspection.indicators {
                    if indicator.indicator_type != indicator_type
                        || !seen.insert(indicator.value.as_str())
                    {
                        continue;
                    }
                    let lookups = report
                        .provider_lookups
                        .iter()
                        .filter(|lookup| {
                            lookup.subject != crate::report::LookupSubject::OriginalFileSha256
                                && lookup.queried_hash == indicator.value
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    if !lookups.is_empty() {
                        candidates.push(indicator_candidate(
                            indicator.clone(),
                            lookups,
                            report_time,
                            format!("Standalone · {source_name}"),
                        ));
                    }
                }
            }
            report_files::SavedReportContents::Session(session) => {
                let report_time = session.generated_at_unix_seconds;
                for (index, check) in session.checks.iter().enumerate() {
                    if let SessionCheck::IndicatorLookup {
                        indicator,
                        provider_lookups,
                    } = check
                        && indicator.indicator_type == indicator_type
                    {
                        candidates.push(indicator_candidate(
                            indicator.clone(),
                            provider_lookups.clone(),
                            report_time,
                            format!("{} · check {}", source_name, index + 1),
                        ));
                    }
                }
            }
        }
    }
    candidates
}

fn indicator_candidate(
    indicator: Indicator,
    provider_lookups: Vec<ProviderLookup>,
    generated_at: u64,
    origin: String,
) -> IndicatorReportCandidate {
    IndicatorReportCandidate {
        indicator,
        provider_lookups,
        generated_at,
        source: origin.clone(),
        description: format!("{origin} · {}", view::format_timestamp(generated_at)),
    }
}

fn compare_indicator_checks(editor: &mut InputEditor, reports: &[report_files::SavedReport]) {
    let types = [
        IndicatorType::Hash,
        IndicatorType::IP,
        IndicatorType::Domain,
    ]
    .into_iter()
    .filter(|kind| indicator_comparison_candidates(reports, *kind).len() >= 2)
    .collect::<Vec<_>>();
    if types.is_empty() {
        terminal::show_error(
            "At least two saved checks of the same hash, IP, or domain type are required.",
        );
        return;
    }
    terminal::clear_screen();
    ui::header(
        "COMPARE INDICATOR CHECKS",
        "Choose a matching indicator type",
    );
    for (index, kind) in types.iter().enumerate() {
        ui::menu_item(
            &(index + 1).to_string(),
            kind.as_str(),
            "Compare two recorded checks; no lookups are performed",
        );
    }
    ui::navigation_footer("0", "Cancel comparison");
    ui::close_box();
    let Some(type_index) =
        prompt_report_index(editor, types.len(), "Indicator type number (0 to cancel): ")
    else {
        return;
    };
    let candidates = indicator_comparison_candidates(reports, types[type_index]);
    terminal::clear_screen();
    ui::header(
        "COMPARE INDICATOR CHECKS",
        "Select two saved checks of the same type",
    );
    for (index, candidate) in candidates.iter().enumerate() {
        ui::menu_item(
            &(index + 1).to_string(),
            &candidate.indicator.value,
            &candidate.description,
        );
    }
    ui::navigation_footer("0", "Cancel comparison");
    ui::close_box();
    let Some(first) = prompt_report_index(
        editor,
        candidates.len(),
        "First check number (0 to cancel): ",
    ) else {
        return;
    };
    let Some(second) = prompt_report_index(
        editor,
        candidates.len(),
        "Second check number (0 to cancel): ",
    ) else {
        return;
    };
    if first == second {
        terminal::show_error("Choose two different saved checks.");
        return;
    }
    let older = &candidates[first];
    let newer = &candidates[second];
    let (older, newer) = if older.generated_at <= newer.generated_at {
        (older, newer)
    } else {
        (newer, older)
    };
    terminal::clear_screen();
    view::indicator_comparison_screen(
        types[type_index].as_str(),
        view::IndicatorCheck {
            value: &older.indicator.value,
            source: &older.source,
            time: older.generated_at,
            lookups: &older.provider_lookups,
        },
        view::IndicatorCheck {
            value: &newer.indicator.value,
            source: &newer.source,
            time: newer.generated_at,
            lookups: &newer.provider_lookups,
        },
    );
    let _ = terminal::read_input(editor, "\n  Press Enter to continue: ", false);
}

fn prompt_report_index(editor: &mut InputEditor, count: usize, prompt: &str) -> Option<usize> {
    loop {
        let input = terminal::read_input(editor, prompt, false);
        if input == "0" {
            return None;
        }
        match selected_index(&input, count) {
            Some(index) => return Some(index),
            None => terminal::invalid_choice(),
        }
    }
}

fn selected_index(input: &str, count: usize) -> Option<usize> {
    input
        .parse::<usize>()
        .ok()?
        .checked_sub(1)
        .filter(|index| *index < count)
}

fn return_to_parent() {
    ui::navigation_footer("0", "Return to the main menu");
    ui::close_box();
}

#[cfg(test)]
mod tests {
    use super::{file_comparison_candidates, indicator_comparison_candidates, selected_index};
    use crate::app::saved_reports::report_files::{SavedReport, SavedReportContents};
    use crate::file::FileInfo;
    use crate::indicator::{Indicator, IndicatorType};
    use crate::report::{
        InvestigationReport, LookupOutcome, LookupSubject, ProviderLookup, SessionCheck,
        SessionReport,
    };
    use std::path::PathBuf;

    fn file_report(filename: &str, sha256: &str, generated_at: u64) -> InvestigationReport {
        let file = FileInfo {
            name: filename.into(),
            size: 10,
            sha256: sha256.into(),
        };
        let mut report = InvestigationReport::new(&file, Vec::new(), Some(false), Vec::new());
        report.generated_at_unix_seconds = generated_at;
        report
    }

    fn saved_session(checks: Vec<SessionCheck>, path: &str) -> SavedReport {
        SavedReport {
            path: PathBuf::from(path),
            contents: SavedReportContents::Session(SessionReport::new(checks)),
        }
    }

    #[test]
    fn report_selection_rejects_invalid_and_out_of_range_numbers() {
        assert_eq!(selected_index("1", 2), Some(0));
        assert_eq!(selected_index("2", 2), Some(1));
        assert_eq!(selected_index("0", 2), None);
        assert_eq!(selected_index("3", 2), None);
        assert_eq!(selected_index("abc", 2), None);
    }

    #[test]
    fn session_file_checks_are_comparison_candidates_with_readable_origins() {
        let session = saved_session(
            vec![
                SessionCheck::FileInvestigation {
                    report: Box::new(file_report("sample.bin", "same-sha", 11)),
                },
                SessionCheck::IndicatorLookup {
                    indicator: Indicator::new("example.test", IndicatorType::Domain),
                    provider_lookups: vec![],
                },
                SessionCheck::FileInvestigation {
                    report: Box::new(file_report("sample.bin", "other-sha", 12)),
                },
            ],
            "cyberfeed-session.json",
        );
        let standalone = SavedReport {
            path: PathBuf::from("cyberfeed-standalone.json"),
            contents: SavedReportContents::File(Box::new(file_report(
                "standalone.bin",
                "same-sha",
                13,
            ))),
        };

        let reports = [session, standalone];
        let candidates = file_comparison_candidates(&reports);

        assert_eq!(candidates.len(), 3);
        assert!(
            candidates[0]
                .description
                .contains("Session cyberfeed-session.json")
        );
        assert!(
            candidates[0]
                .description
                .contains("file check 1 of 2 (session check 1)")
        );
        assert!(
            candidates[1]
                .description
                .contains("file check 2 of 2 (session check 3)")
        );
        assert!(candidates[2].description.contains("Standalone"));
        assert!(
            candidates
                .iter()
                .all(|candidate| { candidate.description.contains("1970-01-01") })
        );
        assert!(
            candidates[0]
                .description
                .contains("1970-01-01 00:00:11 UTC")
        );
        assert!(
            candidates[2]
                .description
                .contains("1970-01-01 00:00:13 UTC")
        );

        let comparison = super::comparison::compare(candidates[0].report, candidates[2].report);
        assert!(comparison.same_subject);
    }

    #[test]
    fn indicator_only_session_checks_are_not_file_comparison_candidates() {
        let report = saved_session(
            vec![SessionCheck::IndicatorLookup {
                indicator: Indicator::new("198.51.100.7", IndicatorType::IP),
                provider_lookups: vec![],
            }],
            "indicators-only.json",
        );

        assert!(file_comparison_candidates(&[report]).is_empty());
    }

    #[test]
    fn indicator_comparison_candidates_include_saved_individuals_and_session_checks_only() {
        let lookup = |value: &str| ProviderLookup {
            provider: "ThreatFox".into(),
            subject: LookupSubject::ExtractedIndicator,
            queried_hash: value.into(),
            retrieved_at_unix_seconds: None,
            outcome: LookupOutcome::NotFound,
        };
        let aggregate = saved_session(
            vec![
                SessionCheck::FileInvestigation {
                    report: Box::new(file_report("file", "sha", 1)),
                },
                SessionCheck::IndicatorLookup {
                    indicator: Indicator::new("example.test", IndicatorType::Domain),
                    provider_lookups: vec![lookup("example.test")],
                },
                SessionCheck::IndicatorLookup {
                    indicator: Indicator::new("198.51.100.1", IndicatorType::IP),
                    provider_lookups: vec![lookup("198.51.100.1")],
                },
            ],
            "cyberfeed-session-1.json",
        );
        let individual = saved_session(
            vec![SessionCheck::IndicatorLookup {
                indicator: Indicator::new("other.test", IndicatorType::Domain),
                provider_lookups: vec![lookup("other.test")],
            }],
            "cyberfeed-indicator-DOMAIN-other-2.json",
        );
        let reports = [aggregate, individual];
        let candidates = indicator_comparison_candidates(&reports, IndicatorType::Domain);
        assert_eq!(candidates.len(), 2);
        assert!(candidates[0].source.starts_with("cyberfeed-session-"));
        assert!(candidates[1].source.starts_with("cyberfeed-indicator-"));
        assert_eq!(
            indicator_comparison_candidates(&reports, IndicatorType::IP).len(),
            1
        );
        assert!(indicator_comparison_candidates(&reports, IndicatorType::Hash).is_empty());
    }

    #[test]
    fn standalone_file_hash_compares_with_individual_hash_and_keeps_recorded_statuses() {
        let mut file = file_report("sample.bin", "file-sha256", 100);
        file.provider_lookups.push(ProviderLookup {
            provider: "ThreatFox".into(),
            subject: LookupSubject::OriginalFileSha256,
            queried_hash: "file-sha256".into(),
            retrieved_at_unix_seconds: Some(100),
            outcome: LookupOutcome::NotFound,
        });
        file.local_inspection
            .indicators
            .push(Indicator::new("unlooked-up.example", IndicatorType::Domain));
        let standalone = SavedReport {
            path: PathBuf::from("cyberfeed-sample-100.json"),
            contents: SavedReportContents::File(Box::new(file)),
        };
        let individual = saved_session(
            vec![SessionCheck::IndicatorLookup {
                indicator: Indicator::new("file-sha256", IndicatorType::Hash),
                provider_lookups: vec![ProviderLookup {
                    provider: "ThreatFox".into(),
                    subject: LookupSubject::ExtractedIndicator,
                    queried_hash: "file-sha256".into(),
                    retrieved_at_unix_seconds: Some(200),
                    outcome: LookupOutcome::NotConfigured,
                }],
            }],
            "cyberfeed-indicator-HASH-file-sha256-200.json",
        );

        let reports = [standalone, individual];
        let candidates = indicator_comparison_candidates(&reports, IndicatorType::Hash);
        assert_eq!(candidates.len(), 2);
        assert!(candidates[0].source.starts_with("Standalone ·"));
        assert!(candidates[1].source.starts_with("cyberfeed-indicator-"));
        assert_eq!(candidates[0].indicator.value, "file-sha256");
        assert_eq!(
            candidates[0].provider_lookups[0].outcome.status(),
            "NOT FOUND"
        );
        assert_eq!(
            candidates[1].provider_lookups[0].outcome.status(),
            "NOT CONFIGURED"
        );
        assert!(indicator_comparison_candidates(&reports, IndicatorType::Domain).is_empty());
    }

    #[test]
    fn standalone_file_reports_remain_comparable() {
        let older = SavedReport {
            path: PathBuf::from("older.json"),
            contents: SavedReportContents::File(Box::new(file_report("sample.bin", "same", 1))),
        };
        let newer = SavedReport {
            path: PathBuf::from("newer.json"),
            contents: SavedReportContents::File(Box::new(file_report("sample.bin", "same", 2))),
        };

        let reports = [older, newer];
        let candidates = file_comparison_candidates(&reports);

        assert_eq!(candidates.len(), 2);
        assert!(
            super::comparison::compare(candidates[0].report, candidates[1].report).same_subject
        );
    }
}
