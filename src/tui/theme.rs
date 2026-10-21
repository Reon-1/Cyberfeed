use ratatui::style::{Color, Style};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Success,
    Warning,
    Error,
    Neutral,
}

pub fn status_style(status: Status) -> Style {
    Style::default().fg(match status {
        Status::Success => Color::Green,
        Status::Warning => Color::Yellow,
        Status::Error => Color::Red,
        Status::Neutral => Color::Gray,
    })
}

pub fn outcome_explanation(outcome: &str) -> &'static str {
    match outcome.to_ascii_uppercase().as_str() {
        "FOUND" => "A source returned a matching record; review its evidence and context.",
        "NOT FOUND" => {
            "No matching record was returned. This does not establish that the value is safe."
        }
        "INVALID" => "The value did not pass local format validation, so no lookup was made.",
        "NOT CONFIGURED" => "This source needs configuration before it can be queried.",
        "UNSUPPORTED" => "This source does not support lookups for this value type.",
        "SKIPPED" | "LOOKUP LIMIT" => "This check was not attempted; no result is available.",
        "TIMEOUT" => "The request exceeded its time limit; no negative result can be inferred.",
        "CANCELLED" => "The check was cancelled before a result was available.",
        "ERROR" | "API ERROR" | "HTTP ERROR" | "NETWORK ERROR" => {
            "The source could not be checked successfully; its result is unknown."
        }
        _ => "Review the source status and evidence before drawing conclusions.",
    }
}
