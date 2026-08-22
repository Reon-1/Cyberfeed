use serde::Deserialize;

#[derive(Deserialize)]
pub struct Attack {
    pub source_country: String,
    pub target_country: String,
    pub attack_type: String,
    pub timestamp: String,
    pub severity: Severity,
}

#[derive(Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
}

