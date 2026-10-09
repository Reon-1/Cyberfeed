use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Indicator {
    pub value: String,
    pub indicator_type: IndicatorType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IndicatorType {
    Hash,
    IP,
    Domain,
}

impl IndicatorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hash => "HASH",
            Self::IP => "IP",
            Self::Domain => "DOMAIN",
        }
    }
}

impl Indicator {
    pub fn new(value: impl Into<String>, indicator_type: IndicatorType) -> Self {
        Self {
            value: value.into(),
            indicator_type,
        }
    }
}

/// Classify a value using the rules for its input source.
///
/// Manual input accepts MD5, SHA-1, and SHA-256 lengths. Text extraction
/// intentionally passes only `64`, preserving its existing behavior.
pub fn classify(value: &str, accepted_hash_lengths: &[usize]) -> Option<IndicatorType> {
    if value.parse::<IpAddr>().is_ok() {
        return Some(IndicatorType::IP);
    }

    if accepted_hash_lengths.contains(&value.len())
        && value.chars().all(|character| character.is_ascii_hexdigit())
    {
        return Some(IndicatorType::Hash);
    }

    let labels: Vec<&str> = value.split('.').collect();
    let is_domain = labels.len() >= 2
        && value.len() <= 253
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
        && labels.last().is_some_and(|label| {
            label.len() >= 2 && label.chars().all(|c| c.is_ascii_alphabetic())
        });

    is_domain.then_some(IndicatorType::Domain)
}

pub const MANUAL_HASH_LENGTHS: &[usize] = &[32, 40, 64];
pub const EXTRACTED_HASH_LENGTHS: &[usize] = &[64];

#[cfg(test)]
mod tests {
    use super::{EXTRACTED_HASH_LENGTHS, IndicatorType, MANUAL_HASH_LENGTHS, classify};

    #[test]
    fn classifies_manual_hash_lengths() {
        for length in MANUAL_HASH_LENGTHS {
            let hash = "a".repeat(*length);
            assert_eq!(
                classify(&hash, MANUAL_HASH_LENGTHS),
                Some(IndicatorType::Hash)
            );
        }
    }

    #[test]
    fn text_extraction_keeps_sha256_only_behavior() {
        assert_eq!(classify(&"a".repeat(32), EXTRACTED_HASH_LENGTHS), None);
        assert_eq!(
            classify(&"a".repeat(64), EXTRACTED_HASH_LENGTHS),
            Some(IndicatorType::Hash)
        );
    }

    #[test]
    fn classifies_ip_and_domain() {
        assert_eq!(
            classify("192.0.2.1", MANUAL_HASH_LENGTHS),
            Some(IndicatorType::IP)
        );
        assert_eq!(
            classify("example.test", MANUAL_HASH_LENGTHS),
            Some(IndicatorType::Domain)
        );
        assert_eq!(classify("not an indicator", MANUAL_HASH_LENGTHS), None);
    }

    #[test]
    fn rejects_obvious_false_positive_domains() {
        for value in [
            ".example",
            "example.",
            "example.-com",
            "example.com-",
            "example.c",
        ] {
            assert_eq!(classify(value, MANUAL_HASH_LENGTHS), None, "{value}");
        }
    }
}
