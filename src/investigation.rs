use crate::indicator::{Indicator, IndicatorType};
use crate::report::{InvestigationReport, ProviderLookup, SessionCheck, SessionReport};
use crate::tui;
use std::collections::HashSet;

/// Indicators, provider observations, and completed checks from this CLI run.
/// File reports remain scoped to one file; session reports retain each
/// completed file or independent indicator check as a separate entry.
pub struct Investigation {
    indicators: Vec<Indicator>,
    seen: HashSet<Indicator>,
    provider_lookups: Vec<ProviderLookup>,
    checks: Vec<SessionCheck>,
}

impl Investigation {
    /// Starts an empty, in-memory investigation session.
    pub fn new() -> Self {
        Self {
            indicators: Vec::new(),
            seen: HashSet::new(),
            provider_lookups: Vec::new(),
            checks: Vec::new(),
        }
    }

    pub fn add_indicators(&mut self, indicators: Vec<Indicator>) {
        for indicator in indicators {
            self.add_indicator(indicator.value, indicator.indicator_type);
        }
    }

    pub fn add_indicator(&mut self, value: impl Into<String>, indicator_type: IndicatorType) {
        let indicator = Indicator::new(value, indicator_type);
        let key = normalized_key(&indicator);
        // Keep the user's first spelling and insertion order for display.
        // Hashes/domains are case-insensitive; URL paths and queries are not.
        if self.seen.insert(Indicator::new(key, indicator_type)) {
            self.indicators.push(indicator);
        }
    }

    pub fn display_indicators(&self) {
        if self.indicators.is_empty() {
            tui::box_line("  No indicators collected yet.");
            tui::box_line("  Add a suspicious hash, IP, or domain to begin.");
            return;
        }

        tui::indicator_header();
        tui::divider();

        for (index, indicator) in self.indicators.iter().enumerate() {
            tui::indicator_row(
                index + 1,
                indicator.indicator_type.as_str(),
                &indicator.value,
            );
        }
    }

    pub fn provider_lookups(&self) -> &[ProviderLookup] {
        &self.provider_lookups
    }

    pub fn add_file_investigation(&mut self, report: &InvestigationReport) {
        self.add_indicator(report.file.sha256.clone(), IndicatorType::Hash);
        self.add_indicators(report.local_inspection.indicators.clone());
        self.provider_lookups
            .extend(report.provider_lookups.iter().cloned());
        self.checks.push(SessionCheck::FileInvestigation {
            report: Box::new(report.clone()),
        });
    }

    pub fn add_indicator_lookup(
        &mut self,
        indicator: Indicator,
        provider_lookups: &[ProviderLookup],
    ) {
        self.add_indicator(indicator.value.clone(), indicator.indicator_type);
        self.provider_lookups
            .extend(provider_lookups.iter().cloned());
        self.checks.push(SessionCheck::IndicatorLookup {
            indicator,
            provider_lookups: provider_lookups.to_vec(),
        });
    }

    pub fn session_report(&self) -> SessionReport {
        SessionReport::new(self.checks.clone())
    }

    pub fn has_completed_checks(&self) -> bool {
        !self.checks.is_empty()
    }
}

fn normalized_key(indicator: &Indicator) -> String {
    match indicator.indicator_type {
        IndicatorType::Hash | IndicatorType::Domain => indicator.value.to_ascii_lowercase(),
        IndicatorType::IP => indicator.value.clone(),
        IndicatorType::Url => indicator.value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::Investigation;
    use crate::indicator::IndicatorType;

    #[test]
    fn duplicate_indicators_are_stored_once_in_insertion_order() {
        let mut investigation = Investigation::new();
        investigation.add_indicator("example.com", IndicatorType::Domain);
        investigation.add_indicator("example.com", IndicatorType::Domain);
        investigation.add_indicator("192.0.2.1", IndicatorType::IP);

        assert_eq!(investigation.indicators.len(), 2);
        assert_eq!(investigation.indicators[0].value, "example.com");
        assert_eq!(investigation.indicators[1].value, "192.0.2.1");
    }

    #[test]
    fn case_variants_of_hashes_and_domains_keep_the_first_value() {
        let mut investigation = Investigation::new();
        investigation.add_indicator("ABCDEF", IndicatorType::Hash);
        investigation.add_indicator("abcdef", IndicatorType::Hash);
        investigation.add_indicator("Example.COM", IndicatorType::Domain);
        investigation.add_indicator("example.com", IndicatorType::Domain);

        assert_eq!(investigation.indicators.len(), 2);
        assert_eq!(investigation.indicators[0].value, "ABCDEF");
        assert_eq!(investigation.indicators[1].value, "Example.COM");
    }
}
