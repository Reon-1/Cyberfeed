pub struct Indicator {
    pub value: String,
    pub indicator_type: IndicatorType,
}

pub enum IndicatorType {
    Hash,
    IP,
    Domain,
}
