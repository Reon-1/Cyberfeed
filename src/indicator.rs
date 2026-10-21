use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Indicator {
    pub value: String,
    pub indicator_type: IndicatorType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IndicatorType {
    Hash,
    IP,
    Domain,
    Url,
}

impl IndicatorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hash => "HASH",
            Self::IP => "IP",
            Self::Domain => "DOMAIN",
            Self::Url => "URL",
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClassificationFeedback {
    Valid(IndicatorType),
    EndpointWithPort { ip: String, port: u16 },
    InvalidHashLength { len: usize, expected: Vec<usize> },
    MalformedUrl(String),
    MalformedDomain(String),
    Unrecognized,
}

/// Classify a value and provide explanatory diagnostic feedback if rejected.
pub fn classify_with_feedback(
    value: &str,
    accepted_hash_lengths: &[usize],
) -> ClassificationFeedback {
    let trimmed = value.trim();
    if trimmed.parse::<IpAddr>().is_ok() {
        return ClassificationFeedback::Valid(IndicatorType::IP);
    }

    if let Ok(socket) = trimmed.parse::<std::net::SocketAddr>() {
        return ClassificationFeedback::EndpointWithPort {
            ip: socket.ip().to_string(),
            port: socket.port(),
        };
    }

    if !trimmed.is_empty()
        && trimmed
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        if accepted_hash_lengths.contains(&trimmed.len()) {
            return ClassificationFeedback::Valid(IndicatorType::Hash);
        } else {
            return ClassificationFeedback::InvalidHashLength {
                len: trimmed.len(),
                expected: accepted_hash_lengths.to_vec(),
            };
        }
    }

    if is_http_url(trimmed) {
        return ClassificationFeedback::Valid(IndicatorType::Url);
    }

    if trimmed
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("http://"))
        || trimmed
            .get(..8)
            .is_some_and(|p| p.eq_ignore_ascii_case("https://"))
        || trimmed.contains("://")
    {
        let reason = if let Some(scheme_end) = trimmed.find("://") {
            let scheme = &trimmed[..scheme_end];
            if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
                format!("unsupported scheme '{scheme}', only http:// and https:// are supported")
            } else {
                let authority = &trimmed[scheme_end + 3..];
                if authority.is_empty() || authority.starts_with('/') {
                    "missing host in URL".into()
                } else {
                    match reqwest::Url::parse(trimmed) {
                        Ok(url) if url.host_str().is_none_or(|h| h.is_empty()) => {
                            "missing host in URL".into()
                        }
                        Ok(_) => "invalid URL structure".into(),
                        Err(err) => err.to_string(),
                    }
                }
            }
        } else {
            "malformed URL syntax".into()
        };
        return ClassificationFeedback::MalformedUrl(reason);
    }

    let labels: Vec<&str> = trimmed.split('.').collect();
    if labels.len() > 1 && labels.iter().all(|l| !l.is_empty()) {
        let last_label = labels.last().copied().unwrap_or_default();
        if trimmed.len() > 253 {
            return ClassificationFeedback::MalformedDomain("domain exceeds 253 characters".into());
        }
        if let Some(bad_label) = labels.iter().find(|l| l.len() > 63) {
            return ClassificationFeedback::MalformedDomain(format!(
                "label '{bad_label}' exceeds 63 characters"
            ));
        }
        if let Some(bad_label) = labels
            .iter()
            .find(|l| l.starts_with('-') || l.ends_with('-'))
        {
            return ClassificationFeedback::MalformedDomain(format!(
                "label '{bad_label}' begins or ends with a hyphen"
            ));
        }
        if let Some(bad_label) = labels
            .iter()
            .find(|l| !l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        {
            return ClassificationFeedback::MalformedDomain(format!(
                "label '{bad_label}' contains invalid characters"
            ));
        }
        if last_label.len() < 2 || !last_label.chars().all(|c| c.is_ascii_alphabetic()) {
            return ClassificationFeedback::MalformedDomain(
                "top-level domain must be at least two alphabetic characters".into(),
            );
        }
        return ClassificationFeedback::Valid(IndicatorType::Domain);
    }

    ClassificationFeedback::Unrecognized
}

/// Classify a value using the rules for its input source.
///
/// Manual input accepts MD5, SHA-1, and SHA-256 lengths. Text extraction
/// recognizes all three common hash widths in file text.
pub fn classify(value: &str, accepted_hash_lengths: &[usize]) -> Option<IndicatorType> {
    match classify_with_feedback(value, accepted_hash_lengths) {
        ClassificationFeedback::Valid(kind) => Some(kind),
        _ => None,
    }
}

pub const MANUAL_HASH_LENGTHS: &[usize] = &[32, 40, 64];
pub const EXTRACTED_HASH_LENGTHS: &[usize] = &[32, 40, 64];

/// Recognize HTTP(S) indicators without resolving or requesting them.
pub fn is_http_url(value: &str) -> bool {
    if value.len() > 2_048 {
        return false;
    }
    let authority = value
        .get(..7)
        .filter(|prefix| prefix.eq_ignore_ascii_case("http://"))
        .map(|_| &value[7..])
        .or_else(|| {
            value
                .get(..8)
                .filter(|prefix| prefix.eq_ignore_ascii_case("https://"))
                .map(|_| &value[8..])
        });
    let Some(authority) = authority else {
        return false;
    };
    let authority = authority.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return false;
    }
    if has_ambiguous_numeric_ipv4_host(authority) {
        return false;
    }
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https") && url.host_str().is_some_and(|host| !host.is_empty())
}

/// WHATWG URL parsing accepts shortened, hexadecimal, and octal IPv4 forms
/// and canonicalizes them. Reject numeric-only hosts unless they are already
/// a canonical four-octet decimal address, so lookup never changes the target.
fn has_ambiguous_numeric_ipv4_host(authority: &str) -> bool {
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if authority.starts_with('[') {
        // Bracketed IPv6 has colons and is validated by the URL parser below.
        return false;
    }
    let host = authority.split(':').next().unwrap_or_default();
    if host.is_empty() {
        return false;
    }
    let parts = host.strip_suffix('.').unwrap_or(host).split('.');
    let parts = parts.collect::<Vec<_>>();
    let numeric_form = !parts.is_empty()
        && parts.iter().all(|part| {
            !part.is_empty()
                && (part.bytes().all(|byte| byte.is_ascii_digit())
                    || part == &"0x"
                    || part == &"0X"
                    || part
                        .strip_prefix("0x")
                        .or_else(|| part.strip_prefix("0X"))
                        .is_some_and(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit())))
        });
    if !numeric_form {
        return false;
    }
    let Ok(address) = host.parse::<std::net::Ipv4Addr>() else {
        return true;
    };
    address.to_string() != host
}

#[cfg(test)]
mod tests;
