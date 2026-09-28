use crate::indicator::{Indicator, IndicatorType};
use crate::ui;

pub struct Investigation {
    indicators: Vec<Indicator>,
}

impl Investigation {
    pub fn new() -> Self {
        Self {
            indicators: Vec::new(),
        }
    }

    pub fn add_indicators(&mut self, indicators: Vec<Indicator>) {
        self.indicators.extend(indicators);
    }

    pub fn add_indicator(&mut self, value: String, indicator_type: IndicatorType) {
        self.indicators.push(Indicator {
            value,
            indicator_type,
        });
    }

    pub fn indicators(&self) -> &[Indicator] {
        &self.indicators
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
