use crate::ui;
use crossterm::event::{Event, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use rustyline::completion::FilenameCompleter;
use rustyline::error::ReadlineError;
use rustyline::highlight::MatchingBracketHighlighter;
use rustyline::hint::HistoryHinter;
use rustyline::history::DefaultHistory;
use rustyline::validate::MatchingBracketValidator;
use rustyline::{Completer, Config, Editor, Helper, Highlighter, Hinter, Validator};
use std::io::{self, Write};
use std::thread::sleep;
use std::time::{Duration, Instant};

#[derive(Completer, Helper, Highlighter, Hinter, Validator)]
pub(super) struct PathHelper {
    #[rustyline(Completer)]
    completer: FilenameCompleter,
    #[rustyline(Highlighter)]
    highlighter: MatchingBracketHighlighter,
    #[rustyline(Hinter)]
    hinter: HistoryHinter,
    #[rustyline(Validator)]
    validator: MatchingBracketValidator,
}

pub(super) type InputEditor = Editor<PathHelper, DefaultHistory>;

pub(super) fn new_editor() -> Result<InputEditor, ReadlineError> {
    let config = Config::builder().history_ignore_space(true).build();
    InputEditor::with_config(config)
}

pub(super) fn read_input(editor: &mut InputEditor, prompt: &str, path_completion: bool) -> String {
    if path_completion {
        editor.set_helper(Some(PathHelper {
            completer: FilenameCompleter::new(),
            highlighter: MatchingBracketHighlighter::new(),
            hinter: HistoryHinter::new(),
            validator: MatchingBracketValidator::new(),
        }));
    } else {
        editor.set_helper(None);
    }

    let prompt = ui::align_prompt(prompt);
    match editor.readline(&prompt) {
        Ok(input) => {
            let input = input.trim().to_string();
            if !input.is_empty() {
                let _ = editor.add_history_entry(input.as_str());
            }
            input
        }
        Err(ReadlineError::Interrupted | ReadlineError::Eof) => String::from("0"),
        Err(error) => {
            eprintln!("Input error: {error}");
            String::from("\0")
        }
    }
}

pub(super) fn clear_screen() {
    print!("\x1B[2J\x1B[3J\x1B[H");
    flush();
}

pub(super) fn pause() {
    print!("\n{}  Press Enter to continue...", ui::horizontal_margin());
    flush();

    let mut input = String::new();
    if let Err(error) = io::stdin().read_line(&mut input) {
        eprintln!("Input error: {error}");
    }
}

pub(super) fn invalid_choice() {
    show_error("Please choose one of the listed options.");
}

pub(super) fn show_error(message: &str) {
    clear_screen();
    ui::header("ERROR", "The requested action could not be completed");
    ui::section("MESSAGE");
    ui::error(message);
    ui::close_box();
    pause();
}

pub(super) fn show_source_error(error: &str) {
    clear_screen();
    ui::header("THREAT INTELLIGENCE", "The source could not be loaded");
    ui::section("REQUEST FAILED");
    ui::error("The intelligence source returned an error.");
    ui::field("Details", error);
    ui::close_box();
    pause();
}

pub(super) fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds >= 60 {
        format!("{} minute(s)", seconds / 60)
    } else {
        format!("{} second(s)", seconds)
    }
}

pub(super) fn wait_for_refresh(interval: Duration) -> bool {
    if let Err(error) = enable_raw_mode() {
        eprintln!("Could not enable terminal refresh controls: {error}");
        sleep(interval);
        return false;
    }

    let start = Instant::now();
    let cancelled = loop {
        let Some(remaining) = interval.checked_sub(start.elapsed()) else {
            break false;
        };

        match crossterm::event::poll(remaining.min(Duration::from_millis(100))) {
            Ok(true) => match crossterm::event::read() {
                Ok(Event::Key(key))
                    if matches!(key.code, KeyCode::Esc | KeyCode::Char('q' | 'Q')) =>
                {
                    break true;
                }
                Ok(_) => {}
                Err(error) => {
                    eprintln!("Could not read refresh key: {error}");
                    break false;
                }
            },
            Ok(false) => {}
            Err(error) => {
                eprintln!("Could not wait for refresh key: {error}");
                break false;
            }
        }
    };

    if let Err(error) = disable_raw_mode() {
        eprintln!("Could not restore terminal input mode: {error}");
    }
    cancelled
}

fn flush() {
    if let Err(error) = io::stdout().flush() {
        eprintln!("Output error: {error}");
    }
}
