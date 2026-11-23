use crate::tui;
use crossterm::cursor;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{Clear, ClearType, disable_raw_mode, enable_raw_mode};
use rustyline::completion::FilenameCompleter;
use std::io::{self, Write};
use std::time::{Duration, Instant};
use unicode_segmentation::UnicodeSegmentation;

pub(super) struct InputEditor {
    history: Vec<String>,
    history_index: Option<usize>,
    saved_input: String,
    completer: FilenameCompleter,
}

#[derive(Debug, PartialEq, Eq)]
enum InputAction {
    Submit,
    Cancel,
}

fn input_action(key: KeyCode) -> Option<InputAction> {
    match key {
        KeyCode::Enter => Some(InputAction::Submit),
        KeyCode::Esc => Some(InputAction::Cancel),
        _ => None,
    }
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
    print!("{}", tui::sanitize_terminal_text(prompt));
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

pub(super) fn read_input(
    editor: &mut InputEditor,
    prompt: &str,
    path_completion: bool,
) -> Option<String> {
    read_input_inner(editor, prompt, path_completion, None)
}

pub(super) fn read_evidence(editor: &mut InputEditor, prompt: &str) -> Option<String> {
    read_input_inner(
        editor,
        prompt,
        false,
        Some(tui::terminal::EvidenceScroll::default()),
    )
}

pub(super) fn pause_evidence() {
    let _ = read_evidence(&mut InputEditor::default(), "Enter to return: ");
}

fn read_input_inner(
    editor: &mut InputEditor,
    prompt: &str,
    path_completion: bool,
    mut scroll: Option<tui::terminal::EvidenceScroll>,
) -> Option<String> {
    let _raw_mode = match RawMode::enable() {
        Ok(raw_mode) => raw_mode,
        Err(error) => {
            eprintln!("Could not enable terminal input: {error}");
            return None;
        }
    };
    let prompt = prompt.to_owned();
    let mut input = String::new();
    let mut cursor_index = 0usize;
    let mut completion_choices = Vec::new();
    let mut pending_event = None;
    editor.history_index = None;
    redraw_screen(
        &prompt,
        &input,
        cursor_index,
        &completion_choices,
        scroll.as_mut(),
    );

    loop {
        let event = if let Some(event) = pending_event.take() {
            Some(event)
        } else {
            match event::read() {
                Ok(event) => Some(event),
                Err(error) => {
                    eprintln!("Input error: {error}");
                    return None;
                }
            }
        };
        match event {
            Some(Event::Resize(_, _)) => {
                if let Some(event) = coalesce_resize_events() {
                    pending_event = Some(event);
                }
                redraw_screen(
                    &prompt,
                    &input,
                    cursor_index,
                    &completion_choices,
                    scroll.as_mut(),
                );
            }
            Some(Event::Key(key))
                if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) =>
            {
                match input_action(key.code) {
                    Some(InputAction::Submit) => {
                        let input = clean_editor_input(input, path_completion);
                        if !input.is_empty() && editor.history.last() != Some(&input) {
                            editor.history.push(input.clone());
                        }
                        editor.history_index = None;
                        return Some(input);
                    }
                    Some(InputAction::Cancel) => return None,
                    None => {}
                }
                let had_completion_choices = !completion_choices.is_empty();
                match key.code {
                    KeyCode::PageUp | KeyCode::PageDown if scroll.is_some() => {
                        if let Some(scroll) = scroll.as_mut() {
                            scroll.move_page(key.code == KeyCode::PageDown);
                            tui::redraw_evidence(scroll, true);
                        }
                    }
                    KeyCode::Enter | KeyCode::Esc => unreachable!("handled above"),
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return None;
                    }
                    KeyCode::Char('d')
                        if key.modifiers.contains(KeyModifiers::CONTROL) && input.is_empty() =>
                    {
                        return None;
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
                                    .map(|candidate| {
                                        tui::sanitize_terminal_text(&candidate.display)
                                    })
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
                        let start = grapheme_cursor(&input, cursor_index, false);
                        remove_input_range(&mut input, start, cursor_index);
                        cursor_index = start;
                    }
                    KeyCode::Delete => {
                        let end = grapheme_cursor(&input, cursor_index, true);
                        remove_input_range(&mut input, cursor_index, end);
                    }
                    KeyCode::Left => cursor_index = grapheme_cursor(&input, cursor_index, false),
                    KeyCode::Right => cursor_index = grapheme_cursor(&input, cursor_index, true),
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
            None => return None,
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

fn redraw_screen(
    prompt: &str,
    input: &str,
    cursor_index: usize,
    completion_choices: &[String],
    scroll: Option<&mut tui::terminal::EvidenceScroll>,
) {
    tui::clear_terminal();
    if let Some(scroll) = scroll {
        tui::redraw_evidence(scroll, true);
    } else {
        tui::redraw_current_screen_with_prompt();
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
    let (columns, rows) = tui::terminal_dimensions();
    let columns = columns.max(1);
    let row = prompt_row(rows).min(u16::MAX as usize) as u16;
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
            tui::wrap_text(&choice_text, columns)
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
    let (prompt, shown, prompt_width, cursor_offset) =
        prompt_window(prompt, input, cursor_index, columns);
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

fn prompt_row(terminal_rows: usize) -> usize {
    terminal_rows.saturating_sub(1)
}

fn prompt_window(
    prompt: &str,
    input: &str,
    cursor: usize,
    columns: usize,
) -> (String, String, usize, usize) {
    let prompt = tui::align_prompt(prompt);
    let prompt = prompt.rsplit('\n').next().unwrap_or(&prompt);
    let usable = columns.saturating_sub(1);
    let input_reserve = (usable / 3).clamp(1, 8);
    let (label, _) = input_window(prompt, 0, usable.saturating_sub(input_reserve));
    let label_width = tui::visible_width(&label);
    let (shown, cursor_offset) = input_window(input, cursor, usable.saturating_sub(label_width));
    (label, shown, label_width, cursor_offset)
}

fn input_byte(input: &str, cursor: usize) -> usize {
    input
        .char_indices()
        .nth(cursor)
        .map_or(input.len(), |(byte, _)| byte)
}

fn remove_input_range(input: &mut String, start: usize, end: usize) {
    input.replace_range(input_byte(input, start)..input_byte(input, end), "");
}

fn grapheme_cursor(input: &str, cursor: usize, forward: bool) -> usize {
    let mut position = 0;
    for grapheme in input.graphemes(true) {
        let next = position + grapheme.chars().count();
        if cursor < next || (!forward && cursor == next) {
            return if forward { next } else { position };
        }
        position = next;
    }
    position
}

fn input_window(input: &str, cursor_index: usize, width: usize) -> (String, usize) {
    if width == 0 {
        return (String::new(), 0);
    }
    let safe: String = input
        .chars()
        .map(|c| if c.is_control() { '�' } else { c })
        .collect();
    let cursor_byte = input_byte(&safe, cursor_index);
    // If insertion joined adjacent graphemes, place the visible cursor at
    // the next cluster boundary.
    let cells: Vec<_> = safe
        .grapheme_indices(true)
        .map(|(index, cluster)| (index, tui::visible_width(cluster)))
        .collect();
    let cursor = cells.partition_point(|&(index, _)| index < cursor_byte);
    let mut start = cursor;
    let mut used = 0;
    while start > 0 && used + cells[start - 1].1 <= width {
        start -= 1;
        used += cells[start].1;
    }
    let left_width = used;
    let mut end = cursor;
    while end < cells.len() && used + cells[end].1 <= width {
        used += cells[end].1;
        end += 1;
    }
    let byte = |index| cells.get(index).map_or(safe.len(), |&(byte, _)| byte);
    (safe[byte(start)..byte(end)].to_owned(), left_width)
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
    tui::reset_screen();
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
    tui::header("ERROR", "The requested action could not be completed");
    tui::section("MESSAGE");
    tui::error(message);
    pause();
}

pub(super) fn show_source_error(error: &str) {
    clear_screen();
    tui::header("THREAT FEEDS", "The live data source could not be loaded");
    tui::section("REQUEST FAILED");
    tui::error("The intelligence source returned an error.");
    tui::field("Details", error);
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
            return true;
        }
    };

    let start = Instant::now();
    let mut scroll = tui::terminal::EvidenceScroll::default();
    tui::redraw_evidence(&mut scroll, false);
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
                Ok(Event::Key(key)) if matches!(key.code, KeyCode::PageUp | KeyCode::PageDown) => {
                    scroll.move_page(key.code == KeyCode::PageDown);
                    tui::redraw_evidence(&mut scroll, false);
                }
                Ok(Event::Resize(_, _)) => {
                    let mut stdout = io::stdout();
                    let _ = execute!(stdout, Clear(ClearType::All), cursor::MoveTo(0, 0));
                    tui::redraw_evidence(&mut scroll, false);
                }
                Ok(_) => {}
                Err(error) => {
                    eprintln!("Could not read refresh key: {error}");
                    break true;
                }
            },
            Ok(false) => {}
            Err(error) => {
                eprintln!("Could not wait for refresh key: {error}");
                break true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InputAction, InputEditor, clean_editor_input, history_move, input_action, input_window,
        prompt_row, should_clear_completion_row,
    };
    use crossterm::event::KeyCode;

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
    fn prompt_uses_the_reserved_bottom_row_at_each_terminal_size() {
        assert_eq!(prompt_row(24), 23);
        assert_eq!(prompt_row(12), 11);
        assert_eq!(prompt_row(0), 0);
    }

    #[test]
    fn input_enter_submits_and_escape_cancels() {
        assert_eq!(input_action(KeyCode::Enter), Some(InputAction::Submit));
        assert_eq!(input_action(KeyCode::Esc), Some(InputAction::Cancel));
        assert_eq!(input_action(KeyCode::Char('x')), None);
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
    fn prompt_shows_control_placeholders_without_changing_path() {
        let path = "界é\u{7}\nname";
        let (displayed, width) = input_window(path, 5, 20);
        assert_eq!(displayed, "界é��name");
        assert_eq!(width, 5);
        assert_eq!(path, "界é\u{7}\nname");
        assert!(displayed.chars().all(|c| !c.is_control()));
        let emoji = "a👩‍💻z";
        assert_eq!(input_window(emoji, 4, 3), ("a👩‍💻".into(), 3));
        assert_eq!(super::grapheme_cursor(emoji, 4, false), 1);
        assert_eq!(super::grapheme_cursor(emoji, 1, true), 4);
    }

    #[test]
    fn long_prompt_leaves_room_for_input_at_narrow_width() {
        let (label, shown, label_width, cursor) =
            super::prompt_window("S export STIX · Enter return: ", "s", 1, 20);
        assert!(label.starts_with("S export STIX"));
        assert_eq!(shown, "s");
        assert_eq!(cursor, 1);
        assert!(label_width + cursor < 20);
    }

    #[test]
    fn prompt_redraw_only_clears_a_completion_row_that_was_previously_shown() {
        assert!(!should_clear_completion_row(false, false));
        assert!(!should_clear_completion_row(false, true));
        assert!(!should_clear_completion_row(true, true));
        assert!(should_clear_completion_row(true, false));
    }
}
