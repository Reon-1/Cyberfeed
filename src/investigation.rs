use crate::indicator::{Indicator, IndicatorType};
use crate::ui;
use std::collections::HashSet;

pub struct Investigation {
    indicators: Vec<Indicator>,
    seen: HashSet<Indicator>,
}

impl Investigation {
    pub fn new() -> Self {
        Self {
            indicators: Vec::new(),
            seen: HashSet::new(),
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
        if self.seen.insert(Indicator::new(key, indicator_type)) {
            self.indicators.push(indicator);
        }
    }

    pub fn display_indicators(&self) {
        if self.indicators.is_empty() {
            ui::box_line("  No indicators collected yet.");
            ui::box_line("  Add a suspicious hash, IP, or domain to begin.");
            return;
        }

        ui::indicator_header();
        ui::divider();

        for (index, indicator) in self.indicators.iter().enumerate() {
            ui::indicator_row(
                index + 1,
                indicator.indicator_type.as_str(),
                &indicator.value,
            );
        }
    }
}

fn normalized_key(indicator: &Indicator) -> String {
    match indicator.indicator_type {
        IndicatorType::Hash | IndicatorType::Domain => indicator.value.to_ascii_lowercase(),
        IndicatorType::IP => indicator.value.clone(),
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
