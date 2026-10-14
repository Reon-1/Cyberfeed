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
const URLHAUS: &str = "URLhaus";
const TABLE_PROVIDER_WIDTH: usize = 16;

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
    compact: bool,
    table: bool,
}

#[derive(Default, Debug, PartialEq, Eq)]
struct OutcomeCounts {
    found: usize,
    not_found: usize,
    errors: usize,
    invalid: usize,
    unsupported: usize,
    unconfigured: usize,
    skipped_duplicate: usize,
    skipped_limit: usize,
}

impl OutcomeCounts {
    fn record(&mut self, outcome: &LookupOutcome) {
        match outcome {
            LookupOutcome::Found(_)
            | LookupOutcome::ThreatFoxFound { .. }
            | LookupOutcome::UrlhausFound { .. } => self.found += 1,
            LookupOutcome::NotFound => self.not_found += 1,
            LookupOutcome::ApiError { .. } | LookupOutcome::RequestError { .. } => self.errors += 1,
            LookupOutcome::Invalid { .. } => self.invalid += 1,
            LookupOutcome::Unsupported { .. } => self.unsupported += 1,
            LookupOutcome::NotConfigured => self.unconfigured += 1,
            LookupOutcome::SkippedDuplicate { .. } => self.skipped_duplicate += 1,
            LookupOutcome::SkippedLookupLimit => self.skipped_limit += 1,
        }
    }

    fn summary(&self) -> String {
        [
            ("FOUND", self.found),
            ("NOT FOUND", self.not_found),
            ("ERROR", self.errors),
            ("INVALID", self.invalid),
            ("UNSUPPORTED", self.unsupported),
            ("NOT CONFIGURED", self.unconfigured),
            ("SKIPPED DUPLICATE", self.skipped_duplicate),
            ("SKIPPED LIMIT", self.skipped_limit),
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
                            && (lookup.queried_hash == indicator.value
                                || (indicator.indicator_type == IndicatorType::Url
                                    && super::lookups::host_from_url(&indicator.value)
                                        .is_some_and(|(host, _)| {
                                            lookup.provider == "URLhaus"
                                                && lookup.queried_hash == host
                                        })))
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
    loop {
        terminal::clear_screen();
        ui::header(
            "QUICK SUMMARY",
            "File inspection and recorded provider outcomes",
        );
        ui::section("INSPECTED FILE");
        ui::field("Filename", &file.name);
        ui::field("Size", format_size(file.size));
        ui::field(
            "Local analysis",
            "SHA-256 calculated; file contents were not uploaded",
        );
        match extraction {
            Some(data) => {
                ui::field("Extracted values", data.indicators.len());
                if data.limit_reached {
                    ui::warning(
                        "The local extraction limit was reached; results may be incomplete.",
                    );
                }
            }
            None => ui::field("Text analysis", "Not available for this file"),
        }
        ui::section("PROVIDER CHECKS");
        let attempted = lookups
            .iter()
            .filter(|lookup| lookup.retrieved_at_unix_seconds.is_some())
            .count();
        ui::field("Requests attempted", attempted);
        if lookups.is_empty() {
            ui::field("Results", "No provider checks were recorded");
        } else {
            for provider in [MALWAREBAZAAR, THREATFOX, URLHAUS] {
                let counts = all_outcome_counts(lookups, provider);
                if counts != OutcomeCounts::default() {
                    ui::field(provider, counts.summary());
                }
            }
        }
        let original_file_matches = lookups
            .iter()
            .filter(|lookup| {
                lookup.subject == LookupSubject::OriginalFileSha256
                    && is_positive_match(&lookup.outcome)
            })
            .count();
        if original_file_matches > 0 {
            ui::status(
                "File hash",
                &format!("Matching record from {original_file_matches} provider(s)"),
                ui::Status::Warning,
            );
        } else if lookups
            .iter()
            .any(|lookup| lookup.subject == LookupSubject::OriginalFileSha256)
        {
            ui::field(
                "File hash",
                "No positive match recorded; review check status",
            );
        } else {
            ui::field("File hash", "No provider check was recorded");
        }
        let matched = matched_indicator_count(&entries);
        if matched > 0 {
            ui::status(
                "Provider matches",
                &format!("{matched} extracted value(s) had a matching record; review evidence"),
                ui::Status::Warning,
            );
        } else {
            ui::note(
                "No extracted value match was recorded. This does not establish that a file is safe.",
            );
        }
        let errors = lookups
            .iter()
            .filter(|lookup| {
                matches!(
                    lookup.outcome,
                    LookupOutcome::ApiError { .. } | LookupOutcome::RequestError { .. }
                )
            })
            .count();
        if errors > 0 {
            ui::warning(&format!(
                "{errors} provider check(s) failed; their results are unknown."
            ));
        }
        if lookups
            .iter()
            .any(|lookup| matches!(lookup.outcome, LookupOutcome::Invalid { .. }))
        {
            ui::note("One or more values could not be checked because their format was invalid.");
        }
        if lookups.iter().any(|lookup| {
            matches!(
                lookup.outcome,
                LookupOutcome::NotConfigured
                    | LookupOutcome::Unsupported { .. }
                    | LookupOutcome::SkippedLookupLimit
            )
        }) {
            ui::note(
                "Some checks were unavailable, unsupported, or skipped; see detailed evidence.",
            );
        }
        ui::note(
            "Choose D for detailed evidence. A save-report prompt follows; reports are stored in reports/.",
        );
        ui::navigation_footer("D / 0", "Detailed evidence / continue to save prompt");
        ui::close_box();
        match terminal::read_input(editor, "  Choose D or 0: ", false)
            .to_ascii_lowercase()
            .as_str()
        {
            "d" => review_details(editor, file, extraction, lookups),
            "0" => return,
            _ => terminal::invalid_choice(),
        }
    }
}

fn all_outcome_counts(lookups: &[ProviderLookup], provider: &str) -> OutcomeCounts {
    let mut counts = OutcomeCounts::default();
    for lookup in lookups.iter().filter(|lookup| lookup.provider == provider) {
        counts.record(&lookup.outcome);
    }
    counts
}

/// Detailed view of the same recorded observations used in the quick summary.
fn review_details(
    editor: &mut InputEditor,
    file: &FileInfo,
    extraction: Option<&TextIndicators>,
    lookups: &[ProviderLookup],
) {
    let entries = indicator_entries(extraction, lookups);
    let mut page = 0usize;
    let mut previous_capacity = None;
    loop {
        terminal::clear_screen();
        let dimensions = ui::terminal_dimensions();
        let layout = overview_layout(entries.len(), dimensions);
        let capacity = layout.capacity;
        if let Some(old_capacity) = previous_capacity
            && old_capacity != capacity
        {
            let current_indicator = page.saturating_mul(old_capacity);
            page = page_for_indicator(current_indicator, capacity);
        }
        previous_capacity = Some(capacity);
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
                compact: layout.compact,
                table: layout.table,
            },
        );
        let navigation = if pages > 1 {
            "N/P page · number details · F file hash · 0 summary"
        } else {
            "number details · F file hash · 0 summary"
        };
        ui::box_line("");
        ui::divider();
        ui::box_line(&format!("  {navigation}"));
        ui::close_box();

        let input = terminal::read_input(editor, "  Selection: ", false);
        let selection = parse_selection(&input, first, end);
        match selection {
            Selection::Continue => return,
            Selection::Next => page = (page + 1).min(pages.saturating_sub(1)),
            Selection::Previous => page = page.saturating_sub(1),
            Selection::Open(index) => {
                terminal::clear_screen();
                render_details(&entries[index]);
                ui::navigation_footer("Enter", "Return to quick summary");
                ui::close_box();
                // Any completed input returns to the already-built overview; no lookup is rerun.
                let _ = terminal::read_input(editor, "  Press Enter to return: ", false);
            }
            Selection::Original => {
                terminal::clear_screen();
                render_original_details(file, lookups);
                ui::navigation_footer("Enter", "Return to quick summary");
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
    if view.compact {
        render_compact_overview(file, extraction, entries, view);
        return;
    }
    let PageView {
        first,
        end,
        page,
        pages,
        ..
    } = view;
    ui::header(
        "FILE INVESTIGATION",
        "Completed investigation · review results",
    );
    ui::section("FILE SUMMARY");
    ui::field("Filename", &file.name);
    ui::field("Size", format_size(file.size));
    ui::field("SHA-256", overview_value(&file.sha256, IndicatorType::Hash));
    let counts = extraction.map(|data| {
        let mut counts = [0usize; 4];
        for indicator in &data.indicators {
            counts[type_index(indicator.indicator_type)] += 1;
        }
        counts
    });
    match counts {
        Some([hashes, ips, domains, urls]) => ui::field(
            "Extracted",
            format!(
                "{} indicators ({} hashes, {} IPs, {} domains, {} URLs)",
                hashes + ips + domains + urls,
                hashes,
                ips,
                domains,
                urls
            ),
        ),
        None => ui::field("Extracted", "Skipped (binary or non-text content)"),
    }
    ui::field(
        "Matches",
        format!(
            "{} unique extracted values matched a provider record",
            matched_indicator_count(entries)
        ),
    );
    ui::note("A provider match is evidence about that value, not a verdict on the whole file.");

    ui::section("PROVIDER LOOKUP OUTCOMES");
    ui::box_line(
        "  Counts are outcomes, not indicators; one URL may produce exact-URL and host results.",
    );
    for provider in [MALWAREBAZAAR, THREATFOX, URLHAUS] {
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
    for provider in [MALWAREBAZAAR, THREATFOX, URLHAUS] {
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
    } else if view.table {
        let widths = table_widths(ui::content_width());
        ui::box_line(&format!(
            "  {:>2}  {:<6}  {:<width$}  {:<TABLE_PROVIDER_WIDTH$}  {:<TABLE_PROVIDER_WIDTH$}  {:<TABLE_PROVIDER_WIDTH$}",
            "#",
            "TYPE",
            "INDICATOR",
            "MalwareBazaar",
            "ThreatFox",
            "URLhaus",
            width = widths.indicator
        ));
        ui::divider();
        for (index, entry) in entries.iter().enumerate().take(end).skip(first) {
            let indicator = fit_indicator(entry.value, entry.indicator_type, widths.indicator);
            let mb = provider_summary_cell(entry, MALWAREBAZAAR, TABLE_PROVIDER_WIDTH);
            let tf = provider_summary_cell(entry, THREATFOX, TABLE_PROVIDER_WIDTH);
            let uh = provider_summary_cell(entry, URLHAUS, TABLE_PROVIDER_WIDTH);
            ui::box_line(&format!(
                "  {:>2}  {:<6}  {:<width$}  {:<TABLE_PROVIDER_WIDTH$}  {:<TABLE_PROVIDER_WIDTH$}  {:<TABLE_PROVIDER_WIDTH$}",
                index + 1,
                entry.indicator_type.as_str(),
                indicator,
                mb,
                tf,
                uh,
                width = widths.indicator
            ));
        }
    } else {
        for (index, entry) in entries.iter().enumerate().take(end).skip(first) {
            ui::box_line(&format!(
                "[{:02}] {} {}",
                index + 1,
                entry.indicator_type.as_str(),
                fit_indicator(
                    entry.value,
                    entry.indicator_type,
                    ui::content_width().saturating_sub(18)
                )
            ));
            for provider in [MALWAREBAZAAR, THREATFOX, URLHAUS] {
                ui::box_line(&format!(
                    "    {provider:<13} {}",
                    provider_summary_cell(entry, provider, ui::content_width().saturating_sub(20))
                ));
            }
        }
    }
    if pages > 0 {
        ui::box_line(&format!(
            "Page {} of {} · indicators {}–{} of {}",
            page + 1,
            pages,
            first + 1,
            end,
            entries.len()
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
    let mut provider_lookups = entry
        .lookups
        .iter()
        .filter(|lookup| lookup.provider == provider);
    let first = provider_lookups.next();
    let Some(lookup) = first else {
        return "—".to_owned();
    };
    let lookup = if is_positive_match(&lookup.outcome) {
        lookup
    } else {
        entry
            .lookups
            .iter()
            .find(|candidate| {
                candidate.provider == provider && is_positive_match(&candidate.outcome)
            })
            .unwrap_or(lookup)
    };
    if is_positive_match(&lookup.outcome) {
        match &lookup.outcome {
            LookupOutcome::UrlhausFound { details } => urlhaus_summary(details),
            _ => format!("FOUND · {}", finding_name(&lookup.outcome)),
        }
    } else {
        table_outcome_label(&lookup.outcome).to_owned()
    }
}

fn urlhaus_summary(details: &crate::report::UrlhausLookupDetails) -> String {
    if let Some(count) = details.associated_url_count {
        return format!("FOUND · {count} URLs");
    }

    let mut statuses = details
        .associated_urls
        .iter()
        .filter_map(|record| record.status.as_deref())
        .map(str::trim)
        .filter(|status| !status.is_empty());
    if let Some(status) = statuses.next()
        && statuses.next().is_none()
    {
        match status.to_ascii_lowercase().as_str() {
            "offline" => return "FOUND · Offline".to_owned(),
            "online" => return "FOUND · Online".to_owned(),
            _ => {}
        }
    }
    if !details.associated_urls.is_empty() {
        return format!("FOUND · {} URLs", details.associated_urls.len());
    }
    "FOUND".to_owned()
}

fn table_outcome_label(outcome: &LookupOutcome) -> &'static str {
    match outcome {
        LookupOutcome::NotFound => "NOT FOUND",
        LookupOutcome::Invalid { .. }
        | LookupOutcome::ApiError { .. }
        | LookupOutcome::RequestError { .. } => "ERROR",
        LookupOutcome::Unsupported { .. } => "UNSUPPORTED",
        LookupOutcome::NotConfigured => "NOT CONFIGURED",
        LookupOutcome::SkippedDuplicate { .. } => "SKIP DUPLICATE",
        LookupOutcome::SkippedLookupLimit => "SKIP LIMIT",
        LookupOutcome::Found(_)
        | LookupOutcome::ThreatFoxFound { .. }
        | LookupOutcome::UrlhausFound { .. } => "FOUND",
    }
}

fn is_positive_match(outcome: &LookupOutcome) -> bool {
    matches!(
        outcome,
        LookupOutcome::Found(_)
            | LookupOutcome::ThreatFoxFound { .. }
            | LookupOutcome::UrlhausFound { .. }
    )
}

fn provider_summary_cell(entry: &IndicatorEntry<'_>, provider: &str, width: usize) -> String {
    let summary = provider_summary(entry, provider);
    let outcome = entry
        .lookups
        .iter()
        .find(|lookup| lookup.provider == provider && is_positive_match(&lookup.outcome))
        .or_else(|| {
            entry
                .lookups
                .iter()
                .find(|lookup| lookup.provider == provider)
        })
        .map(|lookup| &lookup.outcome);
    let kind = outcome.map_or(ui::Status::Warning, provider_views::status_kind);
    ui::styled_status(&fit_text(&summary, width), kind)
}

#[derive(Debug, PartialEq, Eq)]
struct TableWidths {
    indicator: usize,
    table: bool,
}

fn table_widths(available_width: usize) -> TableWidths {
    // Provider cells retain room for NOT CONFIGURED and SKIP DUPLICATE;
    // below 14 indicator columns the stacked layout is easier to read.
    TableWidths {
        indicator: available_width.saturating_sub(70).max(1),
        table: available_width >= 84,
    }
}

fn fit_indicator(value: &str, indicator_type: IndicatorType, width: usize) -> String {
    if indicator_type == IndicatorType::Url && value.chars().count() > width && width >= 3 {
        if let Some(authority_end) = value.find("://").and_then(|scheme_end| {
            value[scheme_end + 3..]
                .find(['/', '?', '#'])
                .map(|offset| scheme_end + 3 + offset)
        }) {
            let prefix = &value[..authority_end];
            let prefix_chars = prefix.chars().count();
            if prefix_chars + 2 < width {
                let suffix_width = width - prefix_chars - 1;
                let suffix = value.chars().rev().take(suffix_width).collect::<String>();
                return format!("{prefix}…{}", suffix.chars().rev().collect::<String>());
            }
        }
        fit_text(value, width)
    } else if indicator_type == IndicatorType::Hash && value.chars().count() > width && width >= 3 {
        let prefix = width.div_ceil(2);
        let suffix = width - prefix - 1;
        let chars = value.chars().collect::<Vec<_>>();
        format!(
            "{}…{}",
            chars[..prefix].iter().collect::<String>(),
            chars[chars.len() - suffix..].iter().collect::<String>()
        )
    } else {
        fit_text(value, width)
    }
}

fn fit_text(value: &str, width: usize) -> String {
    let width = width.max(1);
    let chars = value.chars().collect::<Vec<_>>();
    if chars.len() <= width {
        return value.to_owned();
    }
    if width == 1 {
        return "…".into();
    }
    chars[..width - 1].iter().collect::<String>() + "…"
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
        LookupOutcome::UrlhausFound { .. } => "URL record found",
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
                    LookupOutcome::Found(_)
                        | LookupOutcome::ThreatFoxFound { .. }
                        | LookupOutcome::UrlhausFound { .. }
                )
            })
        })
        .count()
}

fn page_capacity(count: usize, (columns, rows): (usize, usize)) -> usize {
    if count == 0 {
        return 1;
    }
    // Regular layout overhead (rows >= 36): header(5) + FILE SUMMARY section and
    // fields(9) + PROVIDER OUTCOMES section, note, and fields(7) + HASH LOOKUP
    // section and status rows(6) + INDICATOR RESULTS section(3) + post-indicator
    // lines(3) + four navigation footers(12) + close(1) = 46 raw rows.
    // render_screen_lines_for_rows removes ~8 blank lines (section spacers, footer
    // spacers), netting ~38 rows of chrome. Using 35 was 3 rows too low and caused
    // page_capacity to over-promise capacity that the clipping system then silently
    // reclaimed.
    //
    // Compact layout overhead (rows < 36): header(5) + summary fields(3) +
    // INDICATORS section(3) + navigation footers(10) + close(1) = 22 raw rows,
    // netting ~20 after blank-line stripping.
    let layout = overview_layout_without_capacity(columns, rows);
    let lines_per_entry = indicator_line_count(layout);
    let reserved_rows = if rows < 36 { 22 } else { 38 };
    rows.saturating_sub(reserved_rows)
        .checked_div(lines_per_entry)
        .unwrap_or(0)
        .max(1)
        .min(count)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OverviewLayout {
    compact: bool,
    table: bool,
    capacity: usize,
}

fn overview_layout(count: usize, (columns, rows): (usize, usize)) -> OverviewLayout {
    OverviewLayout {
        capacity: page_capacity(count, (columns, rows)),
        ..overview_layout_without_capacity(columns, rows)
    }
}

fn overview_layout_without_capacity(columns: usize, rows: usize) -> OverviewLayout {
    OverviewLayout {
        compact: rows < 36,
        table: table_widths(columns.saturating_sub(4)).table,
        capacity: 1,
    }
}

fn indicator_line_count(layout: OverviewLayout) -> usize {
    if layout.table { 1 } else { 4 }
}

fn render_compact_overview(
    file: &FileInfo,
    extraction: Option<&TextIndicators>,
    entries: &[IndicatorEntry<'_>],
    view: PageView,
) {
    ui::header("FILE INVESTIGATION", "Compact results");
    ui::box_line(&format!(
        "File: {} · {}",
        fit_text(
            &ui::sanitize_terminal_text(&file.name),
            ui::content_width().saturating_sub(20)
        ),
        format_size(file.size)
    ));
    ui::box_line(&format!(
        "SHA-256: {}",
        overview_value(&file.sha256, IndicatorType::Hash)
    ));
    ui::box_line(&format!(
        "Extracted: {} · positive indicators: {}",
        entries.len(),
        matched_indicator_count(entries)
    ));
    if entries.is_empty() {
        ui::box_line(if extraction.is_some() {
            "No indicators extracted from readable text."
        } else {
            "Indicator extraction skipped for binary or non-text content."
        });
    }
    ui::section("INDICATORS");
    if view.table {
        let widths = table_widths(ui::content_width());
        ui::box_line(&format!(
            "  {:>2}  {:<6}  {:<width$}  {:<TABLE_PROVIDER_WIDTH$}  {:<TABLE_PROVIDER_WIDTH$}  {:<TABLE_PROVIDER_WIDTH$}",
            "#",
            "TYPE",
            "INDICATOR",
            "MalwareBazaar",
            "ThreatFox",
            "URLhaus",
            width = widths.indicator
        ));
        ui::divider();
        for (index, entry) in entries.iter().enumerate().take(view.end).skip(view.first) {
            ui::box_line(&format!(
                "  {:>2}  {:<6}  {:<width$}  {:<TABLE_PROVIDER_WIDTH$}  {:<TABLE_PROVIDER_WIDTH$}  {:<TABLE_PROVIDER_WIDTH$}",
                index + 1,
                entry.indicator_type.as_str(),
                fit_indicator(entry.value, entry.indicator_type, widths.indicator),
                provider_summary_cell(entry, MALWAREBAZAAR, TABLE_PROVIDER_WIDTH),
                provider_summary_cell(entry, THREATFOX, TABLE_PROVIDER_WIDTH),
                provider_summary_cell(entry, URLHAUS, TABLE_PROVIDER_WIDTH),
                width = widths.indicator
            ));
        }
    } else {
        for (index, entry) in entries.iter().enumerate().take(view.end).skip(view.first) {
            ui::box_line(&format!(
                "[{}] {} {}",
                index + 1,
                entry.indicator_type.as_str(),
                fit_indicator(
                    entry.value,
                    entry.indicator_type,
                    ui::content_width().saturating_sub(18)
                )
            ));
            for provider in [MALWAREBAZAAR, THREATFOX, URLHAUS] {
                ui::box_line(&format!(
                    "  {provider}: {}",
                    provider_summary_cell(entry, provider, ui::content_width().saturating_sub(16))
                ));
            }
        }
    }
    if view.pages > 1 {
        ui::box_line(&format!(
            "Page {} of {} · {}–{} / {}",
            view.page + 1,
            view.pages,
            view.first + 1,
            view.end,
            entries.len()
        ));
    }
}

fn page_count(count: usize, capacity: usize) -> usize {
    count.saturating_add(capacity.max(1) - 1) / capacity.max(1)
}

fn page_for_indicator(indicator: usize, capacity: usize) -> usize {
    indicator / capacity.max(1)
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
    for provider in [MALWAREBAZAAR, THREATFOX, URLHAUS] {
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
        IndicatorType::Url => 3,
    }
}

#[cfg(test)]
mod tests;
