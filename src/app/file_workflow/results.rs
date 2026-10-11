//! Overview and on-demand details for completed file investigations.
//!
//! This module only presents recorded lookups. Returning from a detail screen
//! reuses the same records, so navigating never repeats provider requests.

use super::super::provider_views;
use super::super::terminal::{self, InputEditor};
use crate::file::{FileInfo, TextIndicators, format_size};
use crate::indicator::IndicatorType;
use crate::report::{LookupOutcome, LookupSubject, ProviderLookup};
use crate::ui;
use std::collections::BTreeMap;

const MALWAREBAZAAR: &str = "MalwareBazaar";
const THREATFOX: &str = "ThreatFox";

pub(super) struct LiveProgress {
    total: usize,
    completed: usize,
}

impl LiveProgress {
    pub(super) fn new() -> Self {
        ui::header("FILE INVESTIGATION", "Live analysis progress");
        Self {
            total: 0,
            completed: 0,
        }
    }

    pub(super) fn phase(&self, message: &str) {
        ui::progress_line(message, ui::Status::Warning);
    }

    pub(super) fn begin_lookups(&mut self, total: usize) {
        self.total = total;
        self.phase(&format!("Provider lookups: 0 of {total} recorded"));
    }

    pub(super) fn checking(&self, provider: &str, value: &str) {
        ui::progress_line(
            &format!("{provider}: checking {}…", progress_value(value)),
            ui::Status::Warning,
        );
    }

    pub(super) fn finding(&self, indicator_count: usize) {
        ui::progress_line(
            &format!("Extracted {indicator_count} distinct indicators."),
            ui::Status::Success,
        );
    }

    pub(super) fn completed(&mut self, provider: &str, value: &str, outcome: &LookupOutcome) {
        self.completed += 1;
        ui::progress_line(
            &format!(
                "{provider}: {} — {} ({}/{})",
                outcome.status(),
                progress_value(value),
                self.completed,
                self.total
            ),
            provider_views::status_kind(outcome),
        );
    }

    pub(super) fn finish(&self) {
        ui::progress_line(
            "Investigation complete; opening recorded results.",
            ui::Status::Success,
        );
        ui::close_box();
    }
}

fn progress_value(value: &str) -> String {
    let chars = value.chars().collect::<Vec<_>>();
    if chars.len() > 26 {
        format!(
            "{}…{}",
            chars[..12].iter().collect::<String>(),
            chars[chars.len() - 8..].iter().collect::<String>()
        )
    } else {
        value.to_owned()
    }
}

struct IndicatorEntry<'a> {
    value: &'a str,
    indicator_type: IndicatorType,
    lookups: Vec<&'a ProviderLookup>,
}

#[derive(Clone, Copy)]
struct PageView {
    first: usize,
    end: usize,
    page: usize,
    pages: usize,
}

#[derive(Default, Debug, PartialEq, Eq)]
struct OutcomeCounts {
    found: usize,
    not_found: usize,
    errors: usize,
    unsupported: usize,
    unconfigured: usize,
    skipped: usize,
}

impl OutcomeCounts {
    fn record(&mut self, outcome: &LookupOutcome) {
        match outcome {
            LookupOutcome::Found(_) | LookupOutcome::ThreatFoxFound { .. } => self.found += 1,
            LookupOutcome::NotFound => self.not_found += 1,
            LookupOutcome::Invalid { .. }
            | LookupOutcome::ApiError { .. }
            | LookupOutcome::RequestError { .. } => self.errors += 1,
            LookupOutcome::Unsupported { .. } => self.unsupported += 1,
            LookupOutcome::NotConfigured => self.unconfigured += 1,
            LookupOutcome::SkippedDuplicate { .. } | LookupOutcome::SkippedLookupLimit => {
                self.skipped += 1;
            }
        }
    }

    fn summary(&self) -> String {
        [
            ("FOUND", self.found),
            ("NOT FOUND", self.not_found),
            ("ERROR", self.errors),
            ("UNSUPPORTED", self.unsupported),
            ("NOT CONFIGURED", self.unconfigured),
            ("SKIPPED", self.skipped),
        ]
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .map(|(label, count)| format!("{label} {count}"))
        .collect::<Vec<_>>()
        .join(" · ")
    }
}

fn indicator_entries<'a>(
    extraction: Option<&'a TextIndicators>,
    lookups: &'a [ProviderLookup],
) -> Vec<IndicatorEntry<'a>> {
    let mut entries = Vec::new();
    if let Some(extraction) = extraction {
        entries.extend(extraction.indicators.iter().map(|indicator| {
            IndicatorEntry {
                value: &indicator.value,
                indicator_type: indicator.indicator_type,
                lookups: lookups
                    .iter()
                    .filter(|lookup| {
                        lookup.subject != LookupSubject::OriginalFileSha256
                            && lookup.queried_hash == indicator.value
                    })
                    .collect(),
            }
        }));
    }
    entries
}

/// Let users inspect individual recorded outcomes before the existing save prompt.
pub(super) fn review(
    editor: &mut InputEditor,
    file: &FileInfo,
    extraction: Option<&TextIndicators>,
    lookups: &[ProviderLookup],
) {
    let entries = indicator_entries(extraction, lookups);
    let mut page = 0usize;
    loop {
        terminal::clear_screen();
        let dimensions = ui::terminal_dimensions();
        let small_terminal = dimensions.1 < 36;
        let capacity = page_capacity(entries.len(), dimensions);
        let pages = page_count(entries.len(), capacity);
        page = page.min(pages.saturating_sub(1));
        let first = page * capacity;
        let end = (first + capacity).min(entries.len());
        render_overview(
            file,
            extraction,
            lookups,
            &entries,
            PageView {
                first,
                end,
                page,
                pages,
            },
        );
        if !small_terminal && pages > 1 {
            ui::navigation_footer("N / P", "Next / previous page");
        }
        if !small_terminal {
            ui::navigation_footer("number", "Open indicator details");
            ui::navigation_footer("F", "Original file hash evidence");
        }
        ui::navigation_footer("0", "Continue to report saving");
        ui::close_box();

        let input = terminal::read_input(editor, "  Selection: ", false);
        let selection = if small_terminal && input != "0" {
            Selection::Invalid
        } else {
            parse_selection(&input, first, end)
        };
        match selection {
            Selection::Continue => return,
            Selection::Next => page = (page + 1).min(pages.saturating_sub(1)),
            Selection::Previous => page = page.saturating_sub(1),
            Selection::Open(index) => {
                terminal::clear_screen();
                render_details(&entries[index]);
                ui::navigation_footer("Enter", "Return to investigation overview");
                ui::close_box();
                // Any completed input returns to the already-built overview; no lookup is rerun.
                let _ = terminal::read_input(editor, "  Press Enter to return: ", false);
            }
            Selection::Original => {
                terminal::clear_screen();
                render_original_details(file, lookups);
                ui::navigation_footer("Enter", "Return to investigation overview");
                ui::close_box();
                let _ = terminal::read_input(editor, "  Press Enter to return: ", false);
            }
            Selection::Invalid => terminal::invalid_choice(),
        }
    }
}

fn render_overview(
    file: &FileInfo,
    extraction: Option<&TextIndicators>,
    lookups: &[ProviderLookup],
    entries: &[IndicatorEntry<'_>],
    view: PageView,
) {
    if ui::terminal_dimensions().1 < 36 {
        ui::header("FILE INVESTIGATION", "Terminal size limits the overview");
        ui::section("FILE SUMMARY");
        ui::field("Filename", &file.name);
        ui::field("Size", format_size(file.size));
        ui::field("SHA-256", overview_value(&file.sha256, IndicatorType::Hash));
        ui::warning("Resize the terminal to review provider summaries and indicators.");
        return;
    }
    let PageView {
        first,
        end,
        page,
        pages,
    } = view;
    ui::header("FILE INVESTIGATION", "Completed findings · offline review");
    ui::section("FILE SUMMARY");
    ui::field("Filename", &file.name);
    ui::field("Size", format_size(file.size));
    ui::field("SHA-256", overview_value(&file.sha256, IndicatorType::Hash));
    let counts = extraction.map(|data| {
        let mut counts = [0usize; 3];
        for indicator in &data.indicators {
            counts[type_index(indicator.indicator_type)] += 1;
        }
        counts
    });
    match counts {
        Some([hashes, ips, domains]) => ui::field(
            "Extracted",
            format!(
                "{} indicators ({} hashes, {} IPs, {} domains)",
                hashes + ips + domains,
                hashes,
                ips,
                domains
            ),
        ),
        None => ui::field("Extracted", "Skipped (binary or non-text content)"),
    }
    ui::field(
        "Matches",
        format!(
            "{} extracted indicators with a provider record",
            matched_indicator_count(entries)
        ),
    );

    ui::section("EXTRACTED INDICATOR PROVIDER SUMMARY");
    for provider in [MALWAREBAZAAR, THREATFOX] {
        let counts = extracted_outcome_counts(lookups, provider);
        ui::field(
            provider,
            if counts == OutcomeCounts::default() {
                "No recorded outcomes".to_owned()
            } else {
                counts.summary()
            },
        );
    }

    ui::section("ORIGINAL FILE HASH LOOKUP");
    for provider in [MALWAREBAZAAR, THREATFOX] {
        if let Some(lookup) = lookups.iter().find(|lookup| {
            lookup.subject == LookupSubject::OriginalFileSha256 && lookup.provider == provider
        }) {
            ui::status(
                provider,
                lookup.outcome.status(),
                provider_views::status_kind(&lookup.outcome),
            );
        }
    }

    ui::section("INDICATOR RESULTS");
    if entries.is_empty() {
        ui::box_line("No extracted indicators to review.");
    } else if ui::terminal_dimensions().0 >= 96 {
        ui::box_line(
            " No.  Type    Indicator                                      MalwareBazaar                    ThreatFox",
        );
        ui::divider();
        for (index, entry) in entries.iter().enumerate().take(end).skip(first) {
            ui::box_line(&format!(
                " {:02}   {:<6}  {:<40}  {:<30}  {}",
                index + 1,
                entry.indicator_type.as_str(),
                overview_value(entry.value, entry.indicator_type),
                provider_summary(entry, MALWAREBAZAAR),
                provider_summary(entry, THREATFOX)
            ));
        }
    } else {
        for (index, entry) in entries.iter().enumerate().take(end).skip(first) {
            ui::box_line(&format!(
                "[{:02}] {}  {}  |  MB {}  |  TF {}",
                index + 1,
                entry.indicator_type.as_str(),
                overview_value(entry.value, entry.indicator_type),
                provider_summary(entry, MALWAREBAZAAR),
                provider_summary(entry, THREATFOX)
            ));
        }
    }
    if pages > 1 {
        ui::box_line(&format!(
            "Page {} of {} · indicators {}–{}",
            page + 1,
            pages,
            first + 1,
            end
        ));
    }
    if entries.is_empty() && extraction.is_some_and(|data| data.indicators.is_empty()) {
        ui::box_line("No indicators were extracted from readable text.");
    }
    if extraction.is_some_and(|data| data.limit_reached) {
        ui::warning(
            "Indicator extraction reached its limit; remaining file content was not scanned.",
        );
    }
    ui::box_line(
        "Provider matches apply to queried indicators, not automatically to this file. NOT FOUND is not proof of safety; ThreatFox may omit older IOCs.",
    );
}

fn extracted_outcome_counts(lookups: &[ProviderLookup], provider: &str) -> OutcomeCounts {
    let mut counts = OutcomeCounts::default();
    for lookup in lookups.iter().filter(|lookup| {
        lookup.provider == provider && lookup.subject != LookupSubject::OriginalFileSha256
    }) {
        counts.record(&lookup.outcome);
    }
    counts
}

fn provider_summary(entry: &IndicatorEntry<'_>, provider: &str) -> String {
    let Some(lookup) = entry
        .lookups
        .iter()
        .find(|lookup| lookup.provider == provider)
    else {
        return "—".to_owned();
    };
    if matches!(
        &lookup.outcome,
        LookupOutcome::Found(_) | LookupOutcome::ThreatFoxFound { .. }
    ) {
        format!("FOUND: {}", finding_name(&lookup.outcome))
    } else {
        lookup.outcome.status().to_owned()
    }
}

fn finding_name(outcome: &LookupOutcome) -> &str {
    match outcome {
        LookupOutcome::Found(details) => details
            .signature
            .as_deref()
            .filter(|name| !name.trim().is_empty())
            .or_else(|| {
                (!details.file_type.trim().is_empty()).then_some(details.file_type.as_str())
            })
            .unwrap_or("Record found"),
        LookupOutcome::ThreatFoxFound { findings } => findings
            .iter()
            .find_map(|finding| {
                finding
                    .malware_printable
                    .as_deref()
                    .filter(|name| !name.trim().is_empty())
                    .or_else(|| {
                        finding
                            .malware
                            .as_deref()
                            .filter(|name| !name.trim().is_empty())
                    })
                    .or_else(|| {
                        finding
                            .threat_type_description
                            .as_deref()
                            .filter(|name| !name.trim().is_empty())
                    })
                    .or_else(|| {
                        finding
                            .threat_type
                            .as_deref()
                            .filter(|name| !name.trim().is_empty())
                    })
            })
            .unwrap_or("Record found"),
        _ => "",
    }
}

fn matched_indicator_count(entries: &[IndicatorEntry<'_>]) -> usize {
    entries
        .iter()
        .filter(|entry| {
            entry.lookups.iter().any(|lookup| {
                matches!(
                    &lookup.outcome,
                    LookupOutcome::Found(_) | LookupOutcome::ThreatFoxFound { .. }
                )
            })
        })
        .count()
}

fn page_capacity(count: usize, (columns, rows): (usize, usize)) -> usize {
    if count == 0 {
        return 1;
    }
    // Reserve the fixed summary and footer height; stacked rows use two lines per indicator.
    let lines_per_entry = if columns >= 96 { 1 } else { 2 };
    rows.saturating_sub(36)
        .checked_div(lines_per_entry)
        .unwrap_or(0)
        .max(1)
        .min(count)
}

fn page_count(count: usize, capacity: usize) -> usize {
    count.saturating_add(capacity.max(1) - 1) / capacity.max(1)
}

fn render_details(entry: &IndicatorEntry<'_>) {
    ui::header("INDICATOR DETAILS", "Recorded provider evidence");
    ui::section("SELECTED INDICATOR");
    ui::indicator_details(entry.indicator_type.as_str(), entry.value);
    ui::field("Subject", "Extracted from file contents");

    let mut by_provider: BTreeMap<&str, Vec<&ProviderLookup>> = BTreeMap::new();
    for lookup in &entry.lookups {
        by_provider
            .entry(lookup.provider.as_str())
            .or_default()
            .push(lookup);
    }
    for (provider, records) in by_provider {
        for record in records {
            provider_views::display_lookup_details(provider, entry.value, &record.outcome);
        }
    }
    if entry.lookups.is_empty() {
        ui::warning("No provider outcomes were recorded for this indicator.");
    }
}

fn render_original_details(file: &FileInfo, lookups: &[ProviderLookup]) {
    ui::header("ORIGINAL FILE HASH", "Recorded file-hash provider evidence");
    ui::section("ORIGINAL FILE SHA-256");
    ui::indicator_details(IndicatorType::Hash.as_str(), &file.sha256);
    for provider in [MALWAREBAZAAR, THREATFOX] {
        for lookup in lookups.iter().filter(|lookup| {
            lookup.subject == LookupSubject::OriginalFileSha256 && lookup.provider == provider
        }) {
            provider_views::display_lookup_details(provider, &file.sha256, &lookup.outcome);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Selection {
    Continue,
    Next,
    Previous,
    Original,
    Open(usize),
    Invalid,
}

fn parse_selection(input: &str, first: usize, end: usize) -> Selection {
    if input == "0" {
        return Selection::Continue;
    }
    if input.eq_ignore_ascii_case("n") {
        return Selection::Next;
    }
    if input.eq_ignore_ascii_case("p") {
        return Selection::Previous;
    }
    if input.eq_ignore_ascii_case("f") {
        return Selection::Original;
    }
    input
        .parse::<usize>()
        .ok()
        .filter(|number| (first + 1..=end).contains(number))
        .map_or(Selection::Invalid, |number| Selection::Open(number - 1))
}

fn overview_value(value: &str, indicator_type: IndicatorType) -> String {
    if indicator_type == IndicatorType::Hash && value.len() > 28 {
        format!("{}…{}", &value[..12], &value[value.len() - 8..])
    } else {
        value.to_owned()
    }
}

fn type_index(indicator_type: IndicatorType) -> usize {
    match indicator_type {
        IndicatorType::Hash => 0,
        IndicatorType::IP => 1,
        IndicatorType::Domain => 2,
    }
}

#[cfg(test)]
mod tests;
