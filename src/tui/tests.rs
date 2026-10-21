use super::{Status, outcome_explanation, sanitize_terminal_text, theme};
use crate::report::LookupOutcome;
use ratatui::style::Color;
use ratatui::text::Line;

#[test]
fn test_backend_renders_content_and_wraps_long_indicators() {
    let value = "https://example.invalid/a/very/long/path?token=redacted#section";
    let rows = super::terminal::render_to_test_backend(
        40,
        12,
        "CyberFeed · Value Search",
        &[Line::raw(format!("Checked: {value}"))],
    );
    let output = rows.join("\n");
    assert!(output.contains("CyberFeed"));
    assert!(output.contains("Checked:"));
    assert!(output.contains("example.invalid"));
    assert!(rows.iter().all(|row| row.chars().count() <= 40));
}

#[test]
fn narrow_terminal_gets_actionable_fallback() {
    let rows = super::terminal::render_to_test_backend(18, 5, "Title", &[]);
    assert!(rows.join("\n").contains("Terminal too small"));
}

#[test]
fn responsive_content_renders_at_common_terminal_sizes() {
    for (width, height) in [(40, 12), (80, 24), (120, 40)] {
        let rows = super::terminal::render_to_test_backend(
            width,
            height,
            "CyberFeed · File Investigation",
            &[
                Line::raw("SHA-256  0123456789abcdef"),
                Line::raw("NOT FOUND does not establish safety"),
            ],
        );
        assert_eq!(rows.len(), usize::from(height));
        assert!(rows.join("\n").contains("NOT FOUND"));
        assert!(
            rows.iter()
                .all(|row| row.chars().count() <= usize::from(width))
        );
    }
}

#[test]
fn outcome_language_preserves_inconclusive_states() {
    assert!(outcome_explanation(&LookupOutcome::NotFound).contains("does not establish"));
    assert!(
        outcome_explanation(&LookupOutcome::RequestError {
            explanation: "timeout".into()
        })
        .contains("unknown")
    );
    assert!(outcome_explanation(&LookupOutcome::SkippedLookupLimit).contains("not attempted"));
    assert_eq!(
        theme::status_style(super::outcome_style(&LookupOutcome::RequestError {
            explanation: "failed".into()
        }))
        .fg,
        Some(Color::Red)
    );
    assert_eq!(
        theme::status_style(super::outcome_style(&LookupOutcome::NotFound)).fg,
        Some(Color::Gray)
    );
    assert_eq!(theme::status_style(Status::Success).fg, Some(Color::Green));
}

#[test]
fn untrusted_controls_are_displayed_as_plain_text() {
    assert_eq!(
        sanitize_terminal_text("name\x1b[31m\r\tvalue"),
        "name [31m  value"
    );
}

#[test]
fn country_flag_uses_known_iso_codes_and_keeps_readable_fallbacks() {
    assert_eq!(super::country_flag("np"), "🇳🇵");
    assert!(super::country_flag("ZZ").is_empty());
    assert!(super::country_flag("?").is_empty());
    assert_eq!(super::country_label("NP", "Nepal"), "🇳🇵 Nepal (NP)");
    assert_eq!(
        super::country_label("ZZ", "Example Region"),
        "Example Region (ZZ)"
    );
    assert_eq!(super::country_label("", ""), "Unknown country");
}
