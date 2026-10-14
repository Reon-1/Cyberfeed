use crate::ui;
use crossterm::cursor;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{Clear, ClearType, disable_raw_mode, enable_raw_mode};
use rustyline::completion::FilenameCompleter;
use std::io::{self, Write};
use std::thread::sleep;
use std::time::{Duration, Instant};

pub(super) struct InputEditor {
    history: Vec<String>,
    history_index: Option<usize>,
    saved_input: String,
    completer: FilenameCompleter,
}

impl Default for InputEditor {
    fn default() -> Self {
        Self {
            history: Vec::new(),
            history_index: None,
            saved_input: String::new(),
            completer: FilenameCompleter::new(),
        }
    }
}

struct RawMode;

impl RawMode {
    fn enable() -> io::Result<Self> {
        enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, cursor::Show);
        let _ = stdout.flush();
    }
}

pub(super) fn new_editor() -> io::Result<InputEditor> {
    Ok(InputEditor::default())
}

/// Read a credential without echoing characters, storing them in input history,
/// or placing them in terminal redraw buffers. Escape and Ctrl+C cancel.
pub(super) fn read_secret(prompt: &str) -> Option<String> {
    let _raw_mode = match RawMode::enable() {
        Ok(raw_mode) => raw_mode,
        Err(_) => return None,
    };
    print!("{}", ui::sanitize_terminal_text(prompt));
    if io::stdout().flush().is_err() {
        return None;
    }
    let mut secret = String::new();
    loop {
        match event::read() {
            Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Enter => {
                    println!();
                    return Some(secret);
                }
                KeyCode::Esc | KeyCode::Char('c')
                    if key.code == KeyCode::Esc
                        || key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    println!();
                    return None;
                }
                KeyCode::Backspace => {
                    secret.pop();
                }
                KeyCode::Char(character)
                    if !character.is_control()
                        && !key.modifiers.intersects(
                            KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER,
                        ) =>
                {
                    secret.push(character);
                }
                _ => {}
            },
            Ok(Event::Resize(_, _)) => {}
            Ok(_) => {}
            Err(_) => {
                println!();
                secret.clear();
                return None;
            }
        }
    }
}

pub(super) fn read_input(editor: &mut InputEditor, prompt: &str, path_completion: bool) -> String {
    let _raw_mode = match RawMode::enable() {
        Ok(raw_mode) => raw_mode,
        Err(error) => {
            eprintln!("Could not enable terminal input: {error}");
            return String::from("\0");
        }
    };
    let prompt = prompt.to_owned();
    let mut input = String::new();
    let mut cursor_index = 0usize;
    let mut completion_choices = Vec::new();
    let mut pending_event = None;
    editor.history_index = None;
    redraw_screen(&prompt, &input, cursor_index, &completion_choices);

    loop {
        let event = if let Some(event) = pending_event.take() {
            Some(event)
        } else {
            match event::read() {
                Ok(event) => Some(event),
                Err(error) => {
                    eprintln!("Input error: {error}");
                    return String::from("\0");
                }
            }
        };
        match event {
            Some(Event::Resize(_, _)) => {
                if let Some(event) = coalesce_resize_events() {
                    pending_event = Some(event);
                }
                redraw_screen(&prompt, &input, cursor_index, &completion_choices);
            }
            Some(Event::Key(key))
                if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) =>
            {
                let had_completion_choices = !completion_choices.is_empty();
                match key.code {
                    KeyCode::Enter => {
                        let input = clean_editor_input(input, path_completion);
                        if !input.is_empty() && editor.history.last() != Some(&input) {
                            editor.history.push(input.clone());
                        }
                        editor.history_index = None;
                        return input;
                    }
                    KeyCode::Esc => {}
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return String::from("0");
                    }
                    KeyCode::Char('d')
                        if key.modifiers.contains(KeyModifiers::CONTROL) && input.is_empty() =>
                    {
                        return String::from("0");
                    }
                    KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        cursor_index = 0
                    }
                    KeyCode::Char('e') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        cursor_index = input.chars().count()
                    }
                    KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        input.clear();
                        cursor_index = 0;
                    }
                    KeyCode::Char('w') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        let mut chars = input.chars().collect::<Vec<_>>();
                        let end = cursor_index.min(chars.len());
                        let mut start = end;
                        while start > 0 && chars[start - 1].is_whitespace() {
                            start -= 1;
                        }
                        while start > 0 && !chars[start - 1].is_whitespace() {
                            start -= 1;
                        }
                        chars.drain(start..end);
                        input = chars.into_iter().collect();
                        cursor_index = start;
                    }
                    KeyCode::Tab if path_completion => {
                        completion_choices.clear();
                        let cursor_byte =
                            input.chars().take(cursor_index).map(char::len_utf8).sum();
                        if let Ok((start, candidates)) =
                            editor.completer.complete_path(&input, cursor_byte)
                        {
                            if candidates.len() == 1 {
                                let end = cursor_byte;
                                input.replace_range(start..end, &candidates[0].replacement);
                                cursor_index = input.chars().count();
                            } else {
                                completion_choices = candidates
                                    .into_iter()
                                    .map(|candidate| ui::sanitize_terminal_text(&candidate.display))
                                    .collect();
                            }
                        }
                    }
                    KeyCode::Char(character)
                        if !key.modifiers.intersects(
                            KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER,
                        ) =>
                    {
                        let byte = input
                            .char_indices()
                            .nth(cursor_index)
                            .map_or(input.len(), |(index, _)| index);
                        input.insert(byte, character);
                        cursor_index += 1;
                    }
                    KeyCode::Backspace if cursor_index > 0 => {
                        let mut chars = input.chars().collect::<Vec<_>>();
                        chars.remove(cursor_index - 1);
                        input = chars.into_iter().collect();
                        cursor_index -= 1;
                    }
                    KeyCode::Delete => {
                        let mut chars = input.chars().collect::<Vec<_>>();
                        if cursor_index < chars.len() {
                            chars.remove(cursor_index);
                        }
                        input = chars.into_iter().collect();
                    }
                    KeyCode::Left => cursor_index = cursor_index.saturating_sub(1),
                    KeyCode::Right => cursor_index = (cursor_index + 1).min(input.chars().count()),
                    KeyCode::Home => cursor_index = 0,
                    KeyCode::End => cursor_index = input.chars().count(),
                    KeyCode::Up => history_move(editor, -1, &mut input, &mut cursor_index),
                    KeyCode::Down => history_move(editor, 1, &mut input, &mut cursor_index),
                    _ => {}
                }
                if !matches!(key.code, KeyCode::Tab) {
                    completion_choices.clear();
                }
                redraw_prompt(
                    &prompt,
                    &input,
                    cursor_index,
                    &completion_choices,
                    should_clear_completion_row(
                        had_completion_choices,
                        !completion_choices.is_empty(),
                    ),
                );
            }
            Some(_) => {}
            None => return String::from("\0"),
        }
    }
}

fn history_move(
    editor: &mut InputEditor,
    direction: isize,
    input: &mut String,
    cursor: &mut usize,
) {
    if editor.history.is_empty() {
        return;
    }
    let next = match (editor.history_index, direction) {
        (None, -1) => Some(editor.history.len() - 1),
        (Some(index), -1) => index.checked_sub(1),
        (Some(index), 1) if index + 1 < editor.history.len() => Some(index + 1),
        (Some(_), 1) => None,
        _ => editor.history_index,
    };
    if editor.history_index.is_none() && next.is_some() {
        editor.saved_input = input.clone();
    }
    editor.history_index = next;
    *input = next.map_or_else(
        || editor.saved_input.clone(),
        |index| editor.history[index].clone(),
    );
    *cursor = input.chars().count();
}

fn redraw_screen(prompt: &str, input: &str, cursor_index: usize, completion_choices: &[String]) {
    let mut stdout = io::stdout();
    let _ = execute!(stdout, Clear(ClearType::All), cursor::MoveTo(0, 0));
    let (columns, rows) = ui::terminal_dimensions();
    if ui::terminal_too_small((columns, rows)) {
        for (row, message) in [
            "Terminal too small to show the complete screen. Resize to at least 20×6.",
            "The current input is preserved. Enter submits; Ctrl+C returns.",
        ]
        .iter()
        .enumerate()
        {
            let _ = execute!(
                stdout,
                cursor::MoveTo(0, row as u16),
                Clear(ClearType::CurrentLine)
            );
            let _ = write!(stdout, "{}", ui::sanitize_terminal_text(message));
        }
        ui::set_rendered_rows(2);
        let _ = stdout.flush();
    } else {
        ui::redraw_current_screen_with_prompt();
    }
    redraw_prompt(prompt, input, cursor_index, completion_choices, false);
}

fn redraw_prompt(
    prompt: &str,
    input: &str,
    cursor_index: usize,
    completion_choices: &[String],
    clear_completion_row: bool,
) {
    let mut stdout = io::stdout();
    let (columns, rows) = ui::terminal_dimensions();
    let columns = columns.max(1);
    let row = prompt_row(ui::rendered_rows(), rows).min(u16::MAX as usize) as u16;
    if !completion_choices.is_empty() && rows > 1 {
        let choice_row = row.saturating_sub(1);
        let _ = execute!(
            stdout,
            cursor::MoveTo(0, choice_row),
            Clear(ClearType::CurrentLine)
        );
        let choice_text = completion_choices.join("  ");
        print!(
            "{}",
            ui::wrap_text(&choice_text, columns)
                .first()
                .cloned()
                .unwrap_or_default()
        );
    } else if clear_completion_row && rows > 1 {
        let _ = execute!(
            stdout,
            cursor::MoveTo(0, row.saturating_sub(1)),
            Clear(ClearType::CurrentLine)
        );
    }
    let prompt = ui::align_prompt(prompt);
    let prompt = prompt.rsplit('\n').next().unwrap_or(&prompt);
    let prompt_width = ui::visible_width(prompt).min(columns.saturating_sub(1));
    let available = columns.saturating_sub(prompt_width);
    let (shown, cursor_offset) = input_window(input, cursor_index, available);
    let _ = execute!(
        stdout,
        cursor::MoveTo(0, row),
        Clear(ClearType::CurrentLine)
    );
    print!("{prompt}{shown}");
    let _ = execute!(stdout, cursor::MoveTo(prompt_width as u16, row));
    if cursor_offset > 0 {
        let _ = execute!(
            stdout,
            cursor::MoveRight(cursor_offset.min(u16::MAX as usize) as u16)
        );
    }
    let _ = stdout.flush();
}

fn should_clear_completion_row(previously_shown: bool, currently_shown: bool) -> bool {
    previously_shown && !currently_shown
}

fn prompt_row(screen_rows: usize, terminal_rows: usize) -> usize {
    screen_rows.min(terminal_rows.saturating_sub(1))
}

fn input_window(input: &str, cursor_index: usize, width: usize) -> (String, usize) {
    let chars = input.chars().collect::<Vec<_>>();
    let cursor_index = cursor_index.min(chars.len());
    if width == 0 {
        return (String::new(), 0);
    }
    let mut start = cursor_index;
    let mut left_width = 0;
    while start > 0 {
        let next = ui::display_width(chars[start - 1]);
        if left_width + next > width {
            break;
        }
        start -= 1;
        left_width += next;
    }
    let mut end = cursor_index;
    let mut used = left_width;
    while end < chars.len() {
        let next = ui::display_width(chars[end]);
        if used + next > width {
            break;
        }
        used += next;
        end += 1;
    }
    (chars[start..end].iter().collect(), left_width)
}

fn coalesce_resize_events() -> Option<Event> {
    let start = Instant::now();
    let max_wait = Duration::from_millis(100);
    let quiet = Duration::from_millis(35);
    let mut last_resize = start;
    loop {
        let elapsed = start.elapsed();
        let remaining = max_wait
            .saturating_sub(elapsed)
            .min(quiet.saturating_sub(last_resize.elapsed()));
        if remaining.is_zero() {
            return None;
        }
        match event::poll(remaining) {
            Ok(true) => match event::read() {
                Ok(Event::Resize(_, _)) => last_resize = Instant::now(),
                Ok(event) => return Some(event),
                Err(_) => return None,
            },
            Ok(false) => return None,
            Err(_) => return None,
        }
    }
}

fn clean_editor_input(input: String, path_completion: bool) -> String {
    if path_completion {
        // Preserve meaningful edge spaces in an existing filename; the path
        // normalizer separately removes terminal-added surrounding whitespace.
        input.trim_matches(['\r', '\n']).to_owned()
    } else {
        input.trim().to_owned()
    }
}

pub(super) fn clear_screen() {
    ui::reset_screen();
    print!("\x1B[2J\x1B[3J\x1B[H");
    flush();
}

pub(super) fn pause() {
    let mut editor = InputEditor::default();
    let _ = read_input(&mut editor, "\n  Press Enter to continue...", false);
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
    ui::header("THREAT FEEDS", "The live data source could not be loaded");
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
    let _raw_mode = match RawMode::enable() {
        Ok(raw_mode) => raw_mode,
        Err(error) => {
            eprintln!("Could not enable terminal refresh controls: {error}");
            sleep(interval);
            return false;
        }
    };

    let start = Instant::now();
    loop {
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
                Ok(Event::Resize(_, _)) => {
                    let mut stdout = io::stdout();
                    let _ = execute!(stdout, Clear(ClearType::All), cursor::MoveTo(0, 0));
                    ui::redraw_current_screen();
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
    }
}

fn flush() {
    if let Err(error) = io::stdout().flush() {
        eprintln!("Output error: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InputEditor, clean_editor_input, history_move, input_window, prompt_row,
        should_clear_completion_row,
    };

    #[test]
    fn path_input_keeps_spaces_but_removes_terminal_line_endings() {
        assert_eq!(
            clean_editor_input(" /tmp/a b \r\n".into(), true),
            " /tmp/a b "
        );
        assert_eq!(clean_editor_input("  next  ".into(), false), "next");
    }

    #[test]
    fn editor_history_preserves_the_current_draft_and_cursor_state() {
        let mut editor = InputEditor {
            history: vec!["first".into(), "second".into()],
            ..InputEditor::default()
        };
        let mut input = "unfinished draft".to_owned();
        let mut cursor = input.chars().count();

        history_move(&mut editor, -1, &mut input, &mut cursor);
        assert_eq!(input, "second");
        history_move(&mut editor, -1, &mut input, &mut cursor);
        assert_eq!(input, "first");
        history_move(&mut editor, 1, &mut input, &mut cursor);
        assert_eq!(input, "second");
        history_move(&mut editor, 1, &mut input, &mut cursor);
        assert_eq!(input, "unfinished draft");
        assert_eq!(cursor, input.chars().count());
    }

    #[test]
    fn prompt_follows_the_screen_until_the_bottom_row_is_needed() {
        assert_eq!(prompt_row(18, 24), 18);
        assert_eq!(prompt_row(23, 24), 23);
        assert_eq!(prompt_row(40, 24), 23);
        assert_eq!(prompt_row(2, 0), 0);
    }

    #[test]
    fn input_resize_window_keeps_the_cursor_context_and_typed_value() {
        let input = "prefix-0123456789-suffix";
        let cursor = 16;
        let (narrow, narrow_cursor) = input_window(input, cursor, 8);
        let (wide, wide_cursor) = input_window(input, cursor, 32);
        assert!(narrow.contains("12345678"));
        assert!(wide.contains(input));
        assert!(narrow_cursor <= 8);
        assert_eq!(wide_cursor, cursor);
    }

    #[test]
    fn prompt_redraw_only_clears_a_completion_row_that_was_previously_shown() {
        assert!(!should_clear_completion_row(false, false));
        assert!(!should_clear_completion_row(false, true));
        assert!(!should_clear_completion_row(true, true));
        assert!(should_clear_completion_row(true, false));
    }
}
