use std::fmt::Display;

pub const INNER_WIDTH: usize = 80;
const FIELD_LABEL_WIDTH: usize = 11;
const FIELD_PREFIX_WIDTH: usize = 2;
const FIELD_SEPARATOR_WIDTH: usize = 3;
const STATUS_LABEL_WIDTH: usize = 12;
const MENU_KEY_WIDTH: usize = 4;
const INDICATOR_INDEX_WIDTH: usize = 4;
const INDICATOR_TYPE_WIDTH: usize = 8;
const INDICATOR_PREFIX_WIDTH: usize = 16;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const MUTED: &str = "\x1b[37m";
const ACCENT: &str = "\x1b[1;36m";
const SECONDARY: &str = "\x1b[1;94m";
const SUCCESS: &str = "\x1b[1;32m";
const WARNING: &str = "\x1b[1;33m";
const ERROR: &str = "\x1b[1;31m";
const BORDER: &str = "\x1b[90m";

#[derive(Clone, Copy)]
pub enum Status {
    Success,
    Warning,
    Error,
    Neutral,
}

pub fn header(title: &str, subtitle: &str) {
    open_box();
    if title == "CYBERFEED" {
        centered_box_line(&format!("{ACCENT}>_{RESET} {BOLD}CYBERFEED{RESET}"));
    } else {
        centered_box_line(&format!("{ACCENT}>_{RESET} {MUTED}CYBERFEED{RESET}"));
        centered_box_line(&format!("{BOLD}{ACCENT}{title}{RESET}"));
    }
    centered_box_line(&format!("{MUTED}{subtitle}{RESET}"));
    divider();
}

pub fn open_box() {
    let (width, margin) = frame_geometry();
    if width == 0 {
        return;
    }
    println!(
        "{}{BORDER}╔{}╗{RESET}",
        " ".repeat(margin),
        "═".repeat(width)
    );
}

pub fn close_box() {
    let (width, margin) = frame_geometry();
    if width == 0 {
        return;
    }
    println!(
        "{}{BORDER}╚{}╝{RESET}",
        " ".repeat(margin),
        "═".repeat(width)
    );
}

pub fn divider() {
    let (width, margin) = frame_geometry();
    if width == 0 {
        return;
    }
    println!(
        "{}{BORDER}╠{}╣{RESET}",
        " ".repeat(margin),
        "═".repeat(width)
    );
}

pub fn box_line(text: &str) {
    let (width, margin) = frame_geometry();
    for line in wrap_text(text, width.max(1)) {
        if width == 0 {
            println!("{line}");
            continue;
        }
        let padding = width.saturating_sub(visible_width(&line));
        println!(
            "{}{BORDER}║{RESET}{line}{:width$}{BORDER}║{RESET}",
            " ".repeat(margin),
            "",
            width = padding
        );
    }
}

pub fn centered_box_line(text: &str) {
    let (width, margin) = frame_geometry();
    for line in wrap_text(text, width.max(1)) {
        if width == 0 {
            println!("{line}");
            continue;
        }
        let padding = width.saturating_sub(visible_width(&line));
        let left_padding = padding / 2;
        let right_padding = padding - left_padding;

        println!(
            "{}{BORDER}║{RESET}{}{}{}{BORDER}║{RESET}",
            " ".repeat(margin),
            " ".repeat(left_padding),
            line,
            " ".repeat(right_padding)
        );
    }
}

pub fn section(title: &str) {
    box_line("");
    box_line(&format!("  {SECONDARY}▸{RESET} {BOLD}{title}{RESET}"));
    divider();
}

pub fn menu_item(number: &str, title: &str, description: &str) {
    box_line(&format!("  {} {BOLD}{title}{RESET}", menu_key(number)));
    let indent = "      ";
    let description_width = content_width().saturating_sub(indent.len()).max(1);
    for line in wrap_text(description, description_width) {
        box_line(&format!("{indent}{MUTED}{line}{RESET}"));
    }
}

fn menu_key(number: &str) -> String {
    let key = format!("[{number}]");
    let padding = MENU_KEY_WIDTH.saturating_sub(visible_width(&key));
    format!("{ACCENT}{key}{RESET}{}", " ".repeat(padding))
}

pub fn country_flag(code: &str) -> String {
    if code.len() != 2 {
        return "🏳️".to_string();
    }

    let mut flag = String::new();
    for character in code.to_uppercase().chars() {
        if !character.is_ascii_uppercase() {
            return "🏳️".to_string();
        }
        if let Some(regional_indicator) = char::from_u32(0x1F1E6 + (character as u32 - 'A' as u32))
        {
            flag.push(regional_indicator);
        }
    }
    flag
}

pub fn field(label: &str, value: impl Display) {
    let value = value.to_string();
    let value_width = content_width()
        .saturating_sub(FIELD_PREFIX_WIDTH + FIELD_LABEL_WIDTH + FIELD_SEPARATOR_WIDTH)
        .max(1);
    let lines = wrap_text(&value, value_width);

    for (index, line) in lines.iter().enumerate() {
        if index == 0 {
            box_line(&format!("  {label:<FIELD_LABEL_WIDTH$} : {line}"));
        } else {
            box_line(&format!("  {:<FIELD_LABEL_WIDTH$}   {line}", ""));
        }
    }
}

pub fn indicator_header() {
    box_line(&format!(
        "  {:<INDICATOR_INDEX_WIDTH$} {:<INDICATOR_TYPE_WIDTH$} VALUE",
        "#", "TYPE"
    ));
}

pub fn indicator_row(index: usize, indicator_type: &str, indicator_value: &str) {
    let value_width = content_width()
        .saturating_sub(INDICATOR_PREFIX_WIDTH)
        .max(1);
    let lines = wrap_text(indicator_value, value_width);

    for (line_index, line) in lines.iter().enumerate() {
        if line_index == 0 {
            box_line(&format!(
                "  {index:<INDICATOR_INDEX_WIDTH$} {indicator_type:<INDICATOR_TYPE_WIDTH$} {line}"
            ));
        } else {
            box_line(&format!("{}{line}", " ".repeat(INDICATOR_PREFIX_WIDTH)));
        }
    }
}

pub fn indicator_details(indicator_type: &str, indicator_value: &str) {
    field("Type", indicator_type);
    field("Value", indicator_value);
}

pub fn navigation_footer(key: &str, action: &str) {
    box_line("");
    divider();
    box_line(&format!("  {ACCENT}[{key}]{RESET}  {MUTED}{action}{RESET}"));
}

pub fn align_prompt(prompt: &str) -> String {
    let margin = " ".repeat(frame_geometry().1);
    if margin.is_empty() {
        return prompt.to_string();
    }
    if prompt.contains('\n') {
        prompt.replace('\n', &format!("\n{margin}"))
    } else {
        format!("{margin}{prompt}")
    }
}

pub fn horizontal_margin() -> String {
    " ".repeat(frame_geometry().1)
}

pub fn status(label: &str, value: &str, kind: Status) {
    let (symbol, color) = match kind {
        Status::Success => ("✓", SUCCESS),
        Status::Warning => ("!", WARNING),
        Status::Error => ("×", ERROR),
        Status::Neutral => ("•", MUTED),
    };

    let prefix = format!("  {color}{symbol}{RESET} {BOLD}{label:<STATUS_LABEL_WIDTH$}{RESET} : ");
    let value_width = content_width()
        .saturating_sub(visible_width(&prefix))
        .max(1);
    for (index, line) in wrap_text(value, value_width).iter().enumerate() {
        if index == 0 {
            box_line(&format!("{prefix}{line}"));
        } else {
            box_line(&format!("{}{line}", " ".repeat(visible_width(&prefix))));
        }
    }
}

pub fn warning(message: &str) {
    box_line(&format!("{WARNING}!{RESET}  {message}"));
}

pub fn error(message: &str) {
    box_line(&format!("{ERROR}×{RESET}  {message}"));
}

fn content_width() -> usize {
    frame_geometry().0
}

fn frame_geometry() -> (usize, usize) {
    crossterm::terminal::size()
        .map(|(columns, _)| geometry_for_columns(columns))
        .unwrap_or((INNER_WIDTH, 0))
}

fn geometry_for_columns(columns: u16) -> (usize, usize) {
    if columns < 3 {
        return (0, 0);
    }
    let width = width_for_columns(columns);
    let frame_width = width.saturating_add(2);
    let margin = usize::from(columns).saturating_sub(frame_width) / 2;
    (width, margin)
}

fn width_for_columns(columns: u16) -> usize {
    usize::from(columns).saturating_sub(2).clamp(1, INNER_WIDTH)
}

pub fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();

    for paragraph in text.split('\n') {
        if visible_width(paragraph) <= width {
            lines.push(paragraph.to_string());
            continue;
        }

        let indent_length = paragraph
            .char_indices()
            .find(|(_, character)| !character.is_whitespace())
            .map(|(index, _)| index)
            .unwrap_or(paragraph.len());
        let indent = &paragraph[..indent_length];
        let words: Vec<&str> = paragraph.split_whitespace().collect();
        if words.is_empty() {
            lines.push(indent.to_string());
            continue;
        }

        let paragraph_start = lines.len();
        let mut current = String::new();
        for word in words {
            if visible_width(word) > width {
                if !current.is_empty() {
                    lines.push(current);
                    current = String::new();
                }

                let mut remaining = word;
                while visible_width(remaining) > width {
                    let (head, tail) = split_visible(remaining, width);
                    lines.push(head);
                    remaining = tail;
                }
                current.push_str(remaining);
            } else if current.is_empty() {
                current.push_str(word);
            } else if visible_width(&current) + 1 + visible_width(word) <= width {
                current.push(' ');
                current.push_str(word);
            } else {
                lines.push(current);
                current = word.to_string();
            }
        }

        if !current.is_empty() {
            lines.push(current);
        }

        if let Some(first_line) = lines.get_mut(paragraph_start) {
            first_line.insert_str(0, indent);
        }
    }

    lines
}

fn split_visible(text: &str, width: usize) -> (String, &str) {
    let mut visible = 0;
    let mut end = text.len();
    let mut escape = false;
    let mut split = false;

    for (index, character) in text.char_indices() {
        if escape {
            if character.is_ascii_alphabetic() {
                escape = false;
            }
            continue;
        }
        if character == '\x1b' {
            escape = true;
            continue;
        }
        let character_width = display_width(character);
        if visible > 0 && visible + character_width > width {
            end = index;
            split = true;
            break;
        }
        visible += character_width;
    }

    if !split {
        return (text.to_string(), "");
    }

    let (head, tail) = text.split_at(end);
    (head.to_string(), tail)
}

fn visible_width(text: &str) -> usize {
    let mut width = 0;
    let mut escape = false;

    for character in text.chars() {
        if escape {
            if character.is_ascii_alphabetic() {
                escape = false;
            }
        } else if character == '\x1b' {
            escape = true;
        } else {
            width += display_width(character);
        }
    }

    width
}

fn display_width(character: char) -> usize {
    let code = character as u32;
    if matches!(
        code,
        0x0300..=0x036f
            | 0x0483..=0x0489
            | 0x0591..=0x05bd
            | 0x05bf
            | 0x05c1..=0x05c2
            | 0x0610..=0x061a
            | 0x064b..=0x065f
            | 0x1ab0..=0x1aff
            | 0x1dc0..=0x1dff
            | 0x20d0..=0x20ff
            | 0xfe00..=0xfe0f
            | 0xfe20..=0xfe2f
    ) {
        0
    } else if matches!(
        code,
        0x1100..=0x115f
            | 0x2329..=0x232a
            | 0x2e80..=0xa4cf
            | 0xac00..=0xd7a3
            | 0xf900..=0xfaff
            | 0xfe10..=0xfe19
            | 0xfe30..=0xfe6f
            | 0xff00..=0xff60
            | 0xffe0..=0xffe6
            | 0x1f1e6..=0x1f1ff
            | 0x1f300..=0x1faff
            | 0x20000..=0x3fffd
    ) {
        2
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MENU_KEY_WIDTH, geometry_for_columns, menu_key, visible_width, width_for_columns, wrap_text,
    };

    #[test]
    fn wraps_long_words_without_dropping_content() {
        let text = "abcdef1234567890";
        let lines = wrap_text(text, 5);

        assert_eq!(lines, ["abcde", "f1234", "56789", "0"]);
        assert_eq!(lines.concat(), text);
    }

    #[test]
    fn ignores_ansi_sequences_when_measuring() {
        assert_eq!(visible_width("\x1b[31mERROR\x1b[0m"), 5);
        assert_eq!(wrap_text("\x1b[31mERROR\x1b[0m details", 12).len(), 2);
    }

    #[test]
    fn preserves_padding_when_line_fits() {
        assert_eq!(
            wrap_text("  Name       : test.txt", 80),
            ["  Name       : test.txt"]
        );
    }

    #[test]
    fn keeps_a_sha256_value_on_one_line_when_the_value_column_allows_it() {
        let hash = "226a723ffb4a91d9950a8b266167c5b354ab0db1dc225578494917fe53867ef2";

        assert_eq!(wrap_text(hash, 64), [hash]);
        assert_eq!(wrap_text(hash, 32).concat(), hash);
    }

    #[test]
    fn counts_wide_unicode_characters_by_terminal_columns() {
        assert_eq!(visible_width("中"), 2);
        assert_eq!(visible_width("🇳🇵"), 4);
        assert_eq!(wrap_text("中中", 3), ["中", "中"]);
    }

    #[test]
    fn frame_width_fits_narrow_terminals_and_stays_at_eighty_columns_maximum() {
        assert_eq!(width_for_columns(41), 39);
        assert_eq!(width_for_columns(82), 80);
        assert_eq!(width_for_columns(160), 80);
        assert_eq!(width_for_columns(1), 1);
    }

    #[test]
    fn frame_centers_in_wide_terminals_and_expands_to_available_width() {
        assert_eq!(geometry_for_columns(120), (80, 19));
        assert_eq!(geometry_for_columns(42), (40, 0));
        assert_eq!(geometry_for_columns(1), (0, 0));
    }

    #[test]
    fn menu_keys_keep_compact_brackets_and_a_consistent_title_column() {
        let one = menu_key("1");
        let two = menu_key("2");
        let back = menu_key("0");

        assert!(one.contains("[1]"));
        assert!(two.contains("[2]"));
        assert!(back.contains("[0]"));
        assert_eq!(visible_width(&one), MENU_KEY_WIDTH);
        assert_eq!(visible_width(&two), MENU_KEY_WIDTH);
        assert_eq!(visible_width(&back), MENU_KEY_WIDTH);
    }
}
