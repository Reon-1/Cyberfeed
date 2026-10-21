use ratatui::style::{Color, Style};

pub(super) fn style_from_embedded_color(text: &str) -> Style {
    if text.contains("\x1b[31m") {
        Style::default().fg(Color::Red)
    } else if text.contains("\x1b[32m") {
        Style::default().fg(Color::Green)
    } else if text.contains("\x1b[33m") {
        Style::default().fg(Color::Yellow)
    } else if text.contains("\x1b[36m") {
        Style::default().fg(Color::Cyan)
    } else if text.contains("\x1b[90m") {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default()
    }
}
