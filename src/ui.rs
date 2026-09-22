use std::fmt::Display;

pub const INNER_WIDTH: usize = 62;
const FIELD_LABEL_WIDTH: usize = 11;
const FIELD_PREFIX_WIDTH: usize = 2;
const FIELD_SEPARATOR_WIDTH: usize = 1;
const STATUS_LABEL_WIDTH: usize = 12;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const MUTED: &str = "\x1b[2;37m";
const ACCENT: &str = "\x1b[1;36m";
const SUCCESS: &str = "\x1b[1;32m";
const WARNING: &str = "\x1b[1;33m";
const ERROR: &str = "\x1b[1;31m";
const BORDER: &str = "\x1b[36m";

#[derive(Clone, Copy)]
pub enum Status {
    Success,
    Warning,
    Error,
    Neutral,
}

pub fn header(title: &str, subtitle: &str) {
    open_box();
    centered_box_line(&format!("{BOLD}{ACCENT}{title}{RESET}"));
    centered_box_line(&format!("{MUTED}{subtitle}{RESET}"));
    divider();
}

pub fn open_box() {
    println!("{BORDER}╔{}╗{RESET}", "═".repeat(INNER_WIDTH));
}

pub fn close_box() {
    println!("{BORDER}╚{}╝{RESET}", "═".repeat(INNER_WIDTH));
}

pub fn divider() {
    println!("{BORDER}╠{}╣{RESET}", "═".repeat(INNER_WIDTH));
}

pub fn box_line(text: &str) {
    for line in wrap_text(text, INNER_WIDTH) {
        let padding = INNER_WIDTH.saturating_sub(visible_width(&line));
        println!(
            "{BORDER}║{RESET}{}{BORDER}║{RESET}",
            format!("{}{}", line, " ".repeat(padding))
        );
    }
}

pub fn centered_box_line(text: &str) {
    for line in wrap_text(text, INNER_WIDTH) {
        let padding = INNER_WIDTH.saturating_sub(visible_width(&line));
        let left_padding = padding / 2;
        let right_padding = padding - left_padding;

        println!(
            "{BORDER}║{RESET}{}{}{}{BORDER}║{RESET}",
            " ".repeat(left_padding),
            line,
            " ".repeat(right_padding)
        );
    }
}

pub fn section(title: &str) {
    box_line("");
    box_line(&format!("{ACCENT}{BOLD}  {title}{RESET}"));
    divider();
}

pub fn menu_item(number: &str, title: &str, description: &str) {
    box_line(&format!("  {ACCENT}[{number}]{RESET} {BOLD}{title}{RESET}"));
    box_line(&format!("      {MUTED}{description}{RESET}"));
    box_line("");
}

pub fn field(label: &str, value: impl Display) {
    let value = value.to_string();
    let value_width = INNER_WIDTH
        .saturating_sub(FIELD_PREFIX_WIDTH + FIELD_LABEL_WIDTH + FIELD_SEPARATOR_WIDTH)
        .max(1);
    let lines = wrap_text(&value, value_width);

    for (index, line) in lines.iter().enumerate() {
        if index == 0 {
            box_line(&format!("  {label:<FIELD_LABEL_WIDTH$} {line}"));
        } else {
            box_line(&format!("  {:<FIELD_LABEL_WIDTH$} {line}", ""));
        }
    }
}

pub fn value(value: impl Display) {
    let value = value.to_string();
    let value_width = INNER_WIDTH.saturating_sub(FIELD_PREFIX_WIDTH).max(1);

    for line in wrap_text(&value, value_width) {
        box_line(&format!("  {line}"));
    }
}

pub fn status(label: &str, value: &str, kind: Status) {
    let (symbol, color) = match kind {
        Status::Success => ("●", SUCCESS),
        Status::Warning => ("▲", WARNING),
        Status::Error => ("●", ERROR),
        Status::Neutral => ("•", MUTED),
    };

    box_line(&format!(
        "  {color}{symbol}{RESET} {BOLD}{label:<STATUS_LABEL_WIDTH$}{RESET} {value}"
    ));
}

pub fn indicator(index: usize, indicator_type: &str, indicator_value: &str) {
    box_line("");
    box_line(&format!("  [{index}] {indicator_type}"));
    value(indicator_value);
}

pub fn warning(message: &str) {
    box_line(&format!("{WARNING}  !  {message}{RESET}"));
}

pub fn error(message: &str) {
    box_line(&format!("{ERROR}  ✖  {message}{RESET}"));
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
        if visible == width {
            end = index;
            break;
        }
        visible += 1;
    }

    if visible < width {
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
            width += 1;
        }
    }

    width
}

#[cfg(test)]
mod tests {
    use super::{visible_width, wrap_text};

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
            wrap_text("  Name       test.txt", 62),
            ["  Name       test.txt"]
        );
    }
}
