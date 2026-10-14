//! Menu orchestration for browsing and comparing saved investigation reports.
mod comparison;
mod report_files;
mod view;

use super::terminal::{self, InputEditor};
use crate::ui;
use std::io;
use std::path::Path;

pub(super) fn menu(editor: &mut InputEditor) {
    loop {
        terminal::clear_screen();
        ui::header("SAVED REPORTS", "Your saved investigations · newest first");
        let collection = match report_files::discover(Path::new("reports")) {
            Ok(collection) => collection,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                ui::section("NO REPORT DIRECTORY");
                ui::field("Location", "reports/ in the current working directory");
                ui::box_line("Save a file investigation report to create this directory.");
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
            "\n  Choose a report, C to compare, or 0 to go back: ",
            false,
        );
        if selection == "0" {
            break;
        }
        if selection.eq_ignore_ascii_case("c") {
            compare_reports(editor, &collection.reports);
            continue;
        }
        match selected_index(&selection, collection.reports.len()) {
            Some(index) => {
                terminal::clear_screen();
                view::report_screen(&collection.reports[index]);
                let action = terminal::read_input(
                    editor,
                    "\n  Enter to return, or S to export STIX 2.1: ",
                    false,
                );
                if action.eq_ignore_ascii_case("s") {
                    if crate::report::stix_indicator_count(&collection.reports[index].report) == 0 {
                        terminal::show_error(
                            "This report contains no supported indicators to export.",
                        );
                        continue;
                    }
                    match crate::report::save_stix_bundle(
                        &collection.reports[index].report,
                        Path::new("reports/stix"),
                    ) {
                        Ok(path) => {
                            terminal::show_error(&format!("STIX bundle saved: {}", path.display()))
                        }
                        Err(error) => {
                            terminal::show_error(&format!("Could not save STIX bundle: {error}"))
                        }
                    }
                }
            }
            None => terminal::invalid_choice(),
        }
    }
}

fn compare_reports(editor: &mut InputEditor, reports: &[report_files::SavedReport]) {
    if reports.len() < 2 {
        terminal::show_error("At least two valid saved reports are required for comparison.");
        return;
    }
    let Some(first) =
        prompt_report_index(editor, reports.len(), "First report number (0 to cancel): ")
    else {
        return;
    };
    let Some(second) = prompt_report_index(
        editor,
        reports.len(),
        "Second report number (0 to cancel): ",
    ) else {
        return;
    };
    if first == second {
        terminal::show_error("Choose two different saved reports.");
        return;
    }
    let first = &reports[first].report;
    let second = &reports[second].report;
    let (older, newer) = if first.generated_at_unix_seconds <= second.generated_at_unix_seconds {
        (first, second)
    } else {
        (second, first)
    };
    terminal::clear_screen();
    view::comparison_screen(older, newer);
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
    use super::selected_index;

    #[test]
    fn report_selection_rejects_invalid_and_out_of_range_numbers() {
        assert_eq!(selected_index("1", 2), Some(0));
        assert_eq!(selected_index("2", 2), Some(1));
        assert_eq!(selected_index("0", 2), None);
        assert_eq!(selected_index("3", 2), None);
        assert_eq!(selected_index("abc", 2), None);
    }
}
