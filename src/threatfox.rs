//! ThreatFox Community API client and typed response parsing.
use crate::http_response::{BoundedReadError, read_bounded};
use crate::indicator::{Indicator, IndicatorType, classify};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::Read;
use std::time::Duration;

pub const ENDPOINT: &str = "https://threatfox-api.abuse.ch/api/v1/";
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ThreatFoxRequest {
    Ioc(SearchIoc),
    Hash(SearchHash),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SearchIoc {
    pub query: &'static str,
    pub search_term: String,
    pub exact_match: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SearchHash {
    pub query: &'static str,
    pub hash: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ApiFinding {
    #[serde(default, deserialize_with = "optional_string")]
    pub id: Option<String>,
    pub ioc: String,
    pub ioc_type: String,
    #[serde(default)]
    pub ioc_type_desc: Option<String>,
    #[serde(default)]
    pub threat_type: Option<String>,
    #[serde(default)]
    pub threat_type_desc: Option<String>,
    #[serde(default)]
    pub malware: Option<String>,
    #[serde(default)]
    pub malware_printable: Option<String>,
    #[serde(default)]
    pub confidence_level: Option<u32>,
    #[serde(default)]
    pub first_seen: Option<String>,
    #[serde(default)]
    pub last_seen: Option<String>,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub reporter: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

fn optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(
        Option::<serde_json::Value>::deserialize(deserializer)?.map(|value| match value {
            serde_json::Value::String(value) => value,
            other => other.to_string(),
        }),
    )
}

#[derive(Debug, Deserialize)]
struct ApiResponse {
    query_status: String,
    #[serde(default)]
    data: Option<serde_json::Value>,
}

const NO_RESULT_MESSAGE: &str = "Your search did not yield any results";

#[derive(Debug, PartialEq, Eq)]
pub enum ThreatFoxLookupResult {
    Found(Vec<ApiFinding>),
    NotFound,
    InvalidInput(String),
    Unsupported(String),
    NotConfigured,
    ProviderError(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ThreatFoxError {
    Request(String),
    Http { status: u16, body: String },
    Parse(String),
}

impl fmt::Display for ThreatFoxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(message) => write!(f, "ThreatFox request failed: {message}"),
            Self::Http { status, body } => write!(f, "ThreatFox returned HTTP {status}: {body}"),
            Self::Parse(message) => write!(f, "Could not parse ThreatFox response: {message}"),
        }
    }
}

pub fn request_for_indicator(
    indicator: &Indicator,
) -> Result<ThreatFoxRequest, ThreatFoxLookupResult> {
    match indicator.indicator_type {
        IndicatorType::IP | IndicatorType::Domain => {
            if classify(&indicator.value, &[]) != Some(indicator.indicator_type) {
                return Err(ThreatFoxLookupResult::InvalidInput(
                    "value does not match its indicator type".into(),
                ));
            }
            Ok(ThreatFoxRequest::Ioc(SearchIoc {
                query: "search_ioc",
                search_term: indicator.value.clone(),
                exact_match: true,
            }))
        }
        IndicatorType::Hash => {
            let value = indicator.value.trim();
            if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(ThreatFoxLookupResult::InvalidInput(
                    "hash must contain only hexadecimal characters".into(),
                ));
            }
            match value.len() {
                32 | 64 => Ok(ThreatFoxRequest::Hash(SearchHash {
                    query: "search_hash",
                    hash: value.to_ascii_lowercase(),
                })),
                40 => Err(ThreatFoxLookupResult::Unsupported(
                    "ThreatFox hash search documents MD5 and SHA-256, not SHA-1.".into(),
                )),
                _ => Err(ThreatFoxLookupResult::InvalidInput(
                    "ThreatFox hash search accepts MD5 or SHA-256 values".into(),
                )),
            }
        }
    }
}

pub fn lookup_indicator(
    client: &Client,
    auth_key: Option<&str>,
    indicator: &Indicator,
) -> Result<ThreatFoxLookupResult, ThreatFoxError> {
    let request = match request_for_indicator(indicator) {
        Ok(request) => request,
        Err(result) => return Ok(result),
    };
    let Some(auth_key) = auth_key.filter(|key| !key.trim().is_empty()) else {
        return Ok(ThreatFoxLookupResult::NotConfigured);
    };
    let request = build_lookup_request(client, auth_key, &request)
        .map_err(|error| ThreatFoxError::Request(error.to_string()))?;
    let response = client
        .execute(request)
        .map_err(|error| ThreatFoxError::Request(error.to_string()))?;
    let status = response.status();
    if !status.is_success() {
        return Err(ThreatFoxError::Http {
            status: status.as_u16(),
            body: read_error_body(response),
        });
    }
    let bytes = read_bounded(response, MAX_RESPONSE_BYTES).map_err(|error| match error {
        BoundedReadError::Read(error) => ThreatFoxError::Request(error.to_string()),
        BoundedReadError::TooLarge { limit } => {
            ThreatFoxError::Parse(format!("response exceeded the {limit}-byte size limit"))
        }
    })?;
    let body =
        String::from_utf8(bytes).map_err(|error| ThreatFoxError::Parse(error.to_string()))?;
    parse_response(&body)
}

/// Build a lookup request without sending it, allowing header wiring to be
/// tested using dummy credentials and no network connection.
pub(crate) fn build_lookup_request(
    client: &Client,
    auth_key: &str,
    request: &ThreatFoxRequest,
) -> Result<reqwest::blocking::Request, reqwest::Error> {
    client
        .post(ENDPOINT)
        .timeout(LOOKUP_TIMEOUT)
        .header("Auth-Key", auth_key)
        .json(&request)
        .build()
}

fn read_error_body(response: reqwest::blocking::Response) -> String {
    const MAX_BYTES: u64 = 2048;
    let mut limited = response.take(MAX_BYTES + 1);
    let mut bytes = Vec::new();
    if let Err(error) = limited.read_to_end(&mut bytes) {
        return format!("could not read response body: {error}");
    }
    let truncated = bytes.len() as u64 > MAX_BYTES;
    bytes.truncate(MAX_BYTES as usize);
    let mut body = String::from_utf8_lossy(&bytes).into_owned();
    if truncated {
        body.push_str("… [truncated]");
    }
    body
}

pub fn parse_response(body: &str) -> Result<ThreatFoxLookupResult, ThreatFoxError> {
    let response: ApiResponse =
        serde_json::from_str(body).map_err(|error| ThreatFoxError::Parse(error.to_string()))?;
    // ThreatFox uses different `data` shapes by query status. Check the status
    // first, and accept only its documented no-result message for that status.
    match response.query_status.as_str() {
        "ok" => {
            let data = response.data.ok_or_else(|| {
                ThreatFoxError::Parse("successful response did not contain IOC records".into())
            })?;
            let records: Vec<ApiFinding> = serde_json::from_value(data).map_err(|error| {
                ThreatFoxError::Parse(format!(
                    "successful response data was not an IOC array: {error}"
                ))
            })?;
            if records.is_empty() {
                return Err(ThreatFoxError::Parse(
                    "successful response contained an empty IOC array".into(),
                ));
            }
            Ok(ThreatFoxLookupResult::Found(records))
        }
        "no_result" => match response.data {
            Some(serde_json::Value::String(message)) if message.trim() == NO_RESULT_MESSAGE => {
                Ok(ThreatFoxLookupResult::NotFound)
            }
            Some(serde_json::Value::Array(records)) if records.is_empty() => {
                Ok(ThreatFoxLookupResult::NotFound)
            }
            None => Ok(ThreatFoxLookupResult::ProviderError(
                "no_result response omitted its result message".into(),
            )),
            Some(other) => Ok(ThreatFoxLookupResult::ProviderError(format!(
                "no_result response contained unexpected data: {}",
                bounded_value_description(&other)
            ))),
        },
        "illegal_search_term" | "no_search_term" => {
            Ok(ThreatFoxLookupResult::InvalidInput(response.query_status))
        }
        status => Ok(ThreatFoxLookupResult::ProviderError(status.to_string())),
    }
}

fn bounded_value_description(value: &serde_json::Value) -> String {
    let description = match value {
        serde_json::Value::String(message) => message.as_str(),
        _ => "unexpected non-string value",
    };
    description.chars().take(160).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indicator::IndicatorType;

    const FIXTURE: &str = r#"{"query_status":"ok","data":[{"id":"123","ioc":"192.0.2.1","ioc_type":"ip:port","ioc_type_desc":"IPv4 address","threat_type":"botnet_cc","threat_type_desc":"C&C","malware":"family","malware_printable":"Family Name","confidence_level":90,"first_seen":"2026-01-01","last_seen":null,"reference":null,"reporter":"analyst","tags":["tag"]},{"id":124,"ioc":"example.test","ioc_type":"domain","confidence_level":50}]}"#;
    const NO_RESULT_FIXTURE: &str =
        r#"{"query_status":"no_result","data":"Your search did not yield any results"}"#;

    #[test]
    fn parses_multiple_findings_and_nullable_fields() {
        let ThreatFoxLookupResult::Found(findings) = parse_response(FIXTURE).unwrap() else {
            panic!()
        };
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].id.as_deref(), Some("123"));
        assert_eq!(findings[0].last_seen, None);
        assert_eq!(findings[1].reporter, None);
        assert_eq!(findings[1].id.as_deref(), Some("124"));
    }

    #[test]
    fn statuses_and_malformed_responses_are_distinct() {
        assert_eq!(
            parse_response(r#"{"query_status":"no_result","data":[]}"#).unwrap(),
            ThreatFoxLookupResult::NotFound
        );
        assert!(matches!(
            parse_response(r#"{"query_status":"queued"}"#).unwrap(),
            ThreatFoxLookupResult::ProviderError(_)
        ));
        assert!(matches!(
            parse_response("{}"),
            Err(ThreatFoxError::Parse(_))
        ));
        assert!(matches!(
            parse_response("no json"),
            Err(ThreatFoxError::Parse(_))
        ));
        assert!(matches!(
            parse_response(r#"{"query_status":"ok","data":[]}"#),
            Err(ThreatFoxError::Parse(_))
        ));
        assert!(matches!(
            parse_response(
                r#"{"query_status":"ok","data":"Your search did not yield any results"}"#
            ),
            Err(ThreatFoxError::Parse(_))
        ));
        assert!(matches!(
            parse_response(r#"{"query_status":"no_result","data":"Unexpected provider message"}"#).unwrap(),
            ThreatFoxLookupResult::ProviderError(message) if message.contains("Unexpected provider message")
        ));
        assert!(matches!(
            parse_response(r#"{"query_status":"no_result","data":null}"#).unwrap(),
            ThreatFoxLookupResult::ProviderError(_)
        ));
        assert!(matches!(
            parse_response(r#"{"query_status":"unknown_auth_key","data":"Your search did not yield any results"}"#).unwrap(),
            ThreatFoxLookupResult::ProviderError(status) if status == "unknown_auth_key"
        ));
    }

    #[test]
    fn observed_no_result_message_is_not_parsed_as_findings() {
        assert_eq!(
            parse_response(NO_RESULT_FIXTURE).unwrap(),
            ThreatFoxLookupResult::NotFound
        );
    }

    #[test]
    fn requests_are_exact_and_sha1_is_explicitly_unsupported() {
        let ip = Indicator::new("192.0.2.1", IndicatorType::IP);
        assert_eq!(
            serde_json::to_value(request_for_indicator(&ip).unwrap()).unwrap(),
            serde_json::json!({"query":"search_ioc","search_term":"192.0.2.1","exact_match":true})
        );
        let hash = Indicator::new("a".repeat(64), IndicatorType::Hash);
        assert_eq!(
            serde_json::to_value(request_for_indicator(&hash).unwrap()).unwrap(),
            serde_json::json!({"query":"search_hash","hash":"a".repeat(64)})
        );
        let sha1 = Indicator::new("a".repeat(40), IndicatorType::Hash);
        assert!(matches!(
            request_for_indicator(&sha1),
            Err(ThreatFoxLookupResult::Unsupported(_))
        ));
    }

    #[test]
    fn missing_key_does_not_attempt_network_and_is_explicit() {
        let client = Client::new();
        let ip = Indicator::new("192.0.2.1", IndicatorType::IP);
        assert_eq!(
            lookup_indicator(&client, None, &ip).unwrap(),
            ThreatFoxLookupResult::NotConfigured
        );
    }
}
