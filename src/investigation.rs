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

        ui::box_line("  #   TYPE       VALUE");
        ui::box_line("  ──────────────────────────────────────────────────────────");

        for (index, indicator) in self.indicators.iter().enumerate() {
            ui::box_line(&format!(
                "  {:<3} {:<10} {}",
                index + 1,
                indicator.indicator_type.as_str(),
                indicator.value
            ));
        }
    }
}
