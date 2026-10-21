//! Shared Ratatui screen content and semantic presentation helpers.
//!
//! Workflows decide which evidence to show. This module turns that evidence
//! into Ratatui text widgets; terminal ownership and interactive lists live in
//! `terminal`, and shared colors live in `theme`.

mod components;
pub(crate) mod terminal;
pub(crate) mod theme;

use crate::report::LookupOutcome;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use std::cell::RefCell;
use std::fmt::Display;

pub(crate) use terminal::TerminalSession;
pub use theme::Status;

pub const INNER_WIDTH: usize = 96;

#[derive(Default)]
struct Screen {
    title: String,
    lines: Vec<Line<'static>>,
}

thread_local! {
    static SCREEN: RefCell<Screen> = RefCell::new(Screen::default());
}

fn add_line(line: Line<'static>) {
    SCREEN.with(|screen| screen.borrow_mut().lines.push(line));
}

pub fn header(title: &str, subtitle: &str) {
    let title = sanitize_terminal_text(title);
    SCREEN.with(|screen| {
        let mut screen = screen.borrow_mut();
        screen.title = if title.eq_ignore_ascii_case("CYBERFEED") {
            "CyberFeed".into()
        } else {
            format!("CyberFeed · {title}")
        };
        screen.lines.clear();
        screen.lines.push(Line::styled(
            sanitize_terminal_text(subtitle),
            Style::default().fg(Color::Gray),
        ));
    });
    redraw_current_screen();
}

pub fn divider() {
    add_line(Line::styled(
        "────────────────────────────────────────".to_owned(),
        Style::default().fg(Color::DarkGray),
    ));
}

pub fn spacer() {
    add_line(Line::default());
}

pub fn box_line(text: &str) {
    let clean = strip_ansi_sgr(&sanitize_terminal_text(text));
    let style = components::style_from_embedded_color(text);
    add_line(Line::styled(clean, style));
}

pub fn note(text: &str) {
    add_line(Line::styled(
        sanitize_terminal_text(text),
        Style::default().fg(Color::Gray),
    ));
}

pub fn menu_item(number: &str, title: &str, description: &str) {
    add_line(Line::styled(
        format!("[{number}] {}", sanitize_terminal_text(title)),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ));
    add_line(Line::styled(
        format!("  {}", sanitize_terminal_text(description)),
        Style::default().fg(Color::Gray),
    ));
}

pub fn section(title: &str) {
    add_line(Line::default());
    add_line(Line::styled(
        sanitize_terminal_text(title),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ));
}

pub fn field(label: &str, value: impl Display) {
    let label = sanitize_terminal_text(label);
    let value = sanitize_terminal_text(&value.to_string());
    add_line(Line::from(vec![
        Span::styled(format!("{label:<14}"), Style::default().fg(Color::Gray)),
        Span::raw("  "),
        Span::raw(value),
    ]));
}

pub fn indicator_header() {
    add_line(Line::styled(
        "#    TYPE     VALUE",
        Style::default()
            .fg(Color::Gray)
            .add_modifier(Modifier::BOLD),
    ));
}

pub fn indicator_row(index: usize, indicator_type: &str, indicator_value: &str) {
    add_line(Line::from(vec![
        Span::styled(format!("{index:<4}"), Style::default().fg(Color::Gray)),
        Span::styled(
            format!("{indicator_type:<8}"),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw(sanitize_terminal_text(indicator_value)),
    ]));
}

pub fn indicator_details(indicator_type: &str, indicator_value: &str) {
    field("Type", indicator_type);
    field("Value", indicator_value);
}

pub fn navigation_footer(key: &str, action: &str) {
    add_line(Line::default());
    add_line(Line::from(vec![
        Span::styled(
            format!("[{key}] "),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            sanitize_terminal_text(action),
            Style::default().fg(Color::Gray),
        ),
    ]));
}

pub fn align_prompt(prompt: &str) -> String {
    sanitize_terminal_text(prompt)
}

pub fn status(label: &str, value: &str, kind: Status) {
    let style = theme::status_style(kind);
    add_line(Line::from(vec![
        Span::styled("● ", style),
        Span::styled(format!("{label:<14}"), Style::default().fg(Color::Gray)),
        Span::styled(sanitize_terminal_text(value), style),
    ]));
}

pub fn styled_status(value: &str, kind: Status) -> String {
    let _ = kind;
    sanitize_terminal_text(value)
}

pub fn warning(message: &str) {
    add_line(Line::from(vec![
        Span::styled("! ", theme::status_style(Status::Warning)),
        Span::styled(
            sanitize_terminal_text(message),
            theme::status_style(Status::Warning),
        ),
    ]));
}

pub fn error(message: &str) {
    add_line(Line::from(vec![
        Span::styled("× ", theme::status_style(Status::Error)),
        Span::styled(
            sanitize_terminal_text(message),
            theme::status_style(Status::Error),
        ),
    ]));
}

pub fn progress_line(message: &str, kind: Status) {
    status("Progress", message, kind);
    redraw_current_screen();
}

pub fn country_flag(code: &str) -> String {
    // Regional-indicator symbols look like flags for any two letters, including
    // made-up codes. Restrict them to assigned ISO 3166-1 alpha-2 codes.
    const ISO_ALPHA2: &str = "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW";
    let code = code.to_ascii_uppercase();
    if !ISO_ALPHA2
        .split_ascii_whitespace()
        .any(|valid| valid == code)
    {
        return String::new();
    }
    code.chars()
        .filter_map(|letter| {
            let scalar = 0x1F1E6 + (letter as u32).checked_sub('A' as u32)?;
            char::from_u32(scalar)
        })
        .collect()
}

pub fn country_label(code: &str, name: &str) -> String {
    let code = sanitize_terminal_text(code.trim()).to_ascii_uppercase();
    let name = sanitize_terminal_text(name.trim());
    let name = if name.is_empty() {
        "Unknown country"
    } else {
        &name
    };
    let code_label = if code.is_empty() {
        String::new()
    } else {
        format!(" ({code})")
    };
    let flag = country_flag(&code);
    if flag.is_empty() {
        format!("{name}{code_label}")
    } else {
        format!("{flag} {name}{code_label}")
    }
}

pub fn outcome_style(outcome: &LookupOutcome) -> Status {
    match outcome {
        LookupOutcome::Found(_)
        | LookupOutcome::ThreatFoxFound { .. }
        | LookupOutcome::UrlhausFound { .. } => Status::Warning,
        LookupOutcome::NotFound
        | LookupOutcome::SkippedDuplicate { .. }
        | LookupOutcome::SkippedLookupLimit
        | LookupOutcome::SkippedDeadline { .. }
        | LookupOutcome::Unsupported { .. } => Status::Neutral,
        LookupOutcome::Invalid { .. } | LookupOutcome::NotConfigured => Status::Warning,
        LookupOutcome::ApiError { .. }
        | LookupOutcome::RequestError { .. }
        | LookupOutcome::TimedOut { .. } => Status::Error,
    }
}

pub fn outcome_explanation(outcome: &LookupOutcome) -> &'static str {
    match outcome {
        LookupOutcome::Found(_)
        | LookupOutcome::ThreatFoxFound { .. }
        | LookupOutcome::UrlhausFound { .. } => theme::outcome_explanation("FOUND"),
        LookupOutcome::NotFound => theme::outcome_explanation("NOT FOUND"),
        LookupOutcome::Invalid { .. } => theme::outcome_explanation("INVALID"),
        LookupOutcome::NotConfigured => theme::outcome_explanation("NOT CONFIGURED"),
        LookupOutcome::SkippedDuplicate { .. } => {
            "A duplicate value reused the result of its original lookup."
        }
        LookupOutcome::SkippedLookupLimit => theme::outcome_explanation("SKIPPED"),
        LookupOutcome::SkippedDeadline { .. } => {
            "This check was skipped because the investigation time budget expired."
        }
        LookupOutcome::TimedOut { .. } => {
            "The investigation time budget expired during this provider request."
        }
        LookupOutcome::Unsupported { .. } => theme::outcome_explanation("UNSUPPORTED"),
        LookupOutcome::ApiError { .. } | LookupOutcome::RequestError { .. } => {
            theme::outcome_explanation("API ERROR")
        }
    }
}

pub fn sanitize_terminal_text(text: &str) -> String {
    text.chars()
        .map(|character| match character {
            '\n' => character,
            '\t' => ' ',
            character if character.is_control() => ' ',
            character => character,
        })
        .collect()
}

fn strip_ansi_sgr(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            for next in chars.by_ref() {
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
        } else {
            output.push(character);
        }
    }
    output
}

pub fn reset_screen() {
    SCREEN.with(|screen| *screen.borrow_mut() = Screen::default());
    terminal::clear();
}

pub fn redraw_current_screen() {
    SCREEN.with(|screen| {
        let screen = screen.borrow();
        terminal::draw_content(&screen.title, &screen.lines, false);
    });
}

pub fn redraw_current_screen_with_prompt() {
    SCREEN.with(|screen| {
        let screen = screen.borrow();
        terminal::draw_content(&screen.title, &screen.lines, true);
    });
}

pub(crate) fn clear_terminal() {
    terminal::clear();
}

pub fn terminal_dimensions() -> (usize, usize) {
    crossterm::terminal::size()
        .map(|(columns, rows)| (usize::from(columns), usize::from(rows)))
        .unwrap_or((INNER_WIDTH + 2, 24))
}

pub fn content_width() -> usize {
    terminal_dimensions().0.min(INNER_WIDTH)
}

pub fn wrap_text(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![text.to_owned()];
    }
    let mut output = Vec::new();
    for paragraph in text.split('\n') {
        if paragraph.is_empty() {
            output.push(String::new());
            continue;
        }
        let indent = paragraph.len() - paragraph.trim_start().len();
        let prefix = &paragraph[..indent];
        let mut line = prefix.to_owned();
        for word in paragraph[indent..].split_whitespace() {
            let separator = usize::from(line.len() > prefix.len());
            if visible_width(&line) + separator + visible_width(word) > width
                && line.len() > prefix.len()
            {
                output.push(line);
                line = prefix.to_owned();
            }
            if line.len() > prefix.len() {
                line.push(' ');
            }
            for character in word.chars() {
                if visible_width(&line) + display_width(character) > width
                    && line.len() > prefix.len()
                {
                    output.push(line);
                    line = prefix.to_owned();
                }
                line.push(character);
            }
        }
        output.push(line);
    }
    output
}

pub(crate) fn visible_width(text: &str) -> usize {
    strip_ansi_sgr(text).chars().map(display_width).sum()
}

pub fn display_width(character: char) -> usize {
    let code = character as u32;
    if matches!(code,
        0x1100..=0x115f | 0x2329..=0x232a | 0x2e80..=0xa4cf | 0xac00..=0xd7a3 |
        0xf900..=0xfaff | 0xfe10..=0xfe19 | 0xfe30..=0xfe6f | 0xff00..=0xff60 |
        0xffe0..=0xffe6 | 0x1f1e6..=0x1f1ff | 0x1f300..=0x1faff | 0x20000..=0x3fffd
    ) {
        2
    } else {
        1
    }
}

#[cfg(test)]
pub(crate) fn test_rendered_lines(columns: usize, rows: usize) -> Vec<String> {
    SCREEN.with(|screen| {
        let screen = screen.borrow();
        terminal::render_to_test_backend(
            columns.min(u16::MAX as usize) as u16,
            rows.min(u16::MAX as usize) as u16,
            &screen.title,
            &screen.lines,
        )
    })
}

#[cfg(test)]
pub(crate) fn test_rendered_lines_for_rows(columns: usize, max_rows: usize) -> Vec<String> {
    test_rendered_lines(columns, max_rows)
}

#[cfg(test)]
mod tests;
