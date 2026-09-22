pub struct Indicator {
    pub value: String,
    pub indicator_type: IndicatorType,
}

pub enum IndicatorType {
    Hash,
    IP,
    Domain,
}

impl IndicatorType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Hash => "Hash",
            Self::IP => "IP",
            Self::Domain => "Domain",
        }
    }
}
