//! URLhaus v1 lookups for exact URLs, hosts, and malware payload hashes.
use crate::http_response::{BoundedReadError, read_bounded};
use crate::indicator::{Indicator, IndicatorType, classify, is_http_url};
use crate::report::{UrlhausLookupDetails, UrlhausUrlRecord};
use reqwest::blocking::{Client, Request, Response};
use serde::Deserialize;
use std::error::Error as StdError;
use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;

const URL_ENDPOINT: &str = "https://urlhaus-api.abuse.ch/v1/url/";
const HOST_ENDPOINT: &str = "https://urlhaus-api.abuse.ch/v1/host/";
const PAYLOAD_ENDPOINT: &str = "https://urlhaus-api.abuse.ch/v1/payload/";
#[cfg(test)]
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);
// Ten automatic calls at this per-response ceiling remain comfortably below
// the 32 MiB saved-report limit even before normal JSON overhead.
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAX_ASSOCIATED_URLS: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryKind {
    Url,
    Host,
    Md5,
    Sha256,
}

impl QueryKind {
    fn endpoint_and_field(self) -> (&'static str, &'static str) {
        match self {
            Self::Url => (URL_ENDPOINT, "url"),
            Self::Host => (HOST_ENDPOINT, "host"),
            Self::Md5 => (PAYLOAD_ENDPOINT, "md5_hash"),
            Self::Sha256 => (PAYLOAD_ENDPOINT, "sha256_hash"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum UrlhausLookupResult {
    Found(Box<UrlhausLookupDetails>),
    NotFound,
    InvalidInput(String),
    Unsupported(String),
    NotConfigured,
    ApiError(String),
}

pub fn outcome(
    result: Result<UrlhausLookupResult, UrlhausError>,
    auth_key: &str,
) -> crate::report::LookupOutcome {
    use crate::report::LookupOutcome;
    match result {
        Ok(UrlhausLookupResult::Found(details)) => {
            LookupOutcome::UrlhausFound { details: *details }
        }
        Ok(UrlhausLookupResult::NotFound) => LookupOutcome::NotFound,
        Ok(UrlhausLookupResult::InvalidInput(explanation)) => {
            LookupOutcome::Invalid { explanation }
        }
        Ok(UrlhausLookupResult::Unsupported(explanation)) => {
            LookupOutcome::Unsupported { explanation }
        }
        Ok(UrlhausLookupResult::NotConfigured) => LookupOutcome::NotConfigured,
        Ok(UrlhausLookupResult::ApiError(explanation)) => LookupOutcome::ApiError { explanation },
        Err(error) => {
            let explanation = if auth_key.is_empty() {
                error.to_string()
            } else {
                error.to_string().replace(auth_key, "[redacted]")
            };
            match error {
                UrlhausError::Timeout(_) | UrlhausError::Request(_) | UrlhausError::BodyRead(_) => {
                    LookupOutcome::RequestError { explanation }
                }
                _ => LookupOutcome::ApiError { explanation },
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum UrlhausError {
    Timeout(String),
    Request(String),
    BodyRead(String),
    AuthenticationRejected { status: u16 },
    RateLimited { retry_after: Option<String> },
    Http { status: u16 },
    Parse(String),
}

impl fmt::Display for UrlhausError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout(message) => write!(f, "URLhaus request timed out: {message}"),
            Self::Request(message) => write!(f, "URLhaus request send failed: {message}"),
            Self::BodyRead(message) => write!(f, "URLhaus response body read failed: {message}"),
            Self::AuthenticationRejected { status } => {
                write!(
                    f,
                    "URLhaus rejected the configured Auth-Key (HTTP {status})"
                )
            }
            Self::RateLimited {
                retry_after: Some(value),
            } => {
                write!(
                    f,
                    "URLhaus rate limited the request (HTTP 429; retry after {value})"
                )
            }
            Self::RateLimited { retry_after: None } => {
                write!(f, "URLhaus rate limited the request (HTTP 429)")
            }
            Self::Http { status } => write!(f, "URLhaus returned HTTP {status}"),
            Self::Parse(message) => write!(f, "Could not parse URLhaus response: {message}"),
        }
    }
}

/// Validate and choose the documented URLhaus query for one indicator.
pub fn query_for_indicator(
    indicator: &Indicator,
) -> Result<(QueryKind, &str), UrlhausLookupResult> {
    match indicator.indicator_type {
        IndicatorType::Url if is_http_url(&indicator.value) => {
            Ok((QueryKind::Url, &indicator.value))
        }
        IndicatorType::Url => Err(UrlhausLookupResult::InvalidInput(
            "URL must be a complete HTTP or HTTPS URL with a host".into(),
        )),
        IndicatorType::IP if indicator.value.parse::<Ipv4Addr>().is_ok() => {
            Ok((QueryKind::Host, &indicator.value))
        }
        IndicatorType::IP => Err(UrlhausLookupResult::Unsupported(
            "URLhaus host lookups support IPv4 addresses, not IPv6 addresses".into(),
        )),
        IndicatorType::Domain if is_supported_host(&indicator.value) => {
            Ok((QueryKind::Host, &indicator.value))
        }
        IndicatorType::Domain => Err(UrlhausLookupResult::InvalidInput(
            "value does not match a valid domain or hostname".into(),
        )),
        IndicatorType::Hash => {
            let value = indicator.value.trim();
            if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(UrlhausLookupResult::InvalidInput(
                    "hash must contain only hexadecimal characters".into(),
                ));
            }
            match value.len() {
                32 => Ok((QueryKind::Md5, value)),
                64 => Ok((QueryKind::Sha256, value)),
                40 => Err(UrlhausLookupResult::Unsupported(
                    "URLhaus payload lookup supports MD5 and SHA-256, not SHA-1".into(),
                )),
                _ => Err(UrlhausLookupResult::InvalidInput(
                    "URLhaus payload lookup accepts MD5 or SHA-256 values".into(),
                )),
            }
        }
    }
}

/// Stable key for deduplicating requests according to URLhaus operation and
/// its input's case semantics (URL paths remain case-sensitive).
pub fn request_key(indicator: &Indicator) -> Option<String> {
    let (kind, value) = query_for_indicator(indicator).ok()?;
    let value = if kind == QueryKind::Url {
        value.to_owned()
    } else {
        value.to_ascii_lowercase()
    };
    Some(format!("{kind:?}:{value}"))
}

fn is_supported_host(host: &str) -> bool {
    classify(host, &[]) == Some(IndicatorType::Domain)
        || (!host.is_empty()
            && host.len() <= 63
            && !host.starts_with('-')
            && !host.ends_with('-')
            && host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'))
}

/// Perform one passive lookup. Missing credentials are handled before any
/// request is built or sent; the local file or URL is never fetched/uploaded.
#[cfg(test)]
pub fn lookup_indicator(
    client: &Client,
    auth_key: Option<&str>,
    indicator: &Indicator,
) -> Result<UrlhausLookupResult, UrlhausError> {
    lookup_indicator_with_timeout(client, auth_key, indicator, LOOKUP_TIMEOUT)
}

pub(crate) fn lookup_indicator_with_timeout(
    client: &Client,
    auth_key: Option<&str>,
    indicator: &Indicator,
    timeout: Duration,
) -> Result<UrlhausLookupResult, UrlhausError> {
    let (kind, value) = match query_for_indicator(indicator) {
        Ok(query) => query,
        Err(result) => return Ok(result),
    };
    let Some(auth_key) = auth_key.filter(|key| !key.trim().is_empty()) else {
        return Ok(UrlhausLookupResult::NotConfigured);
    };
    let request = build_request_with_timeout(client, auth_key, kind, value, timeout)
        .map_err(|error| UrlhausError::Request(format!("could not build request: {error}")))?;
    let response = client.execute(request).map_err(|error| {
        let timed_out = error.is_timeout();
        let explanation = reqwest_error_chain(error.without_url(), auth_key);
        request_error(timed_out, explanation)
    })?;
    let status = response.status();
    if !status.is_success() {
        return Err(http_error(response));
    }
    let bytes = read_bounded(response, MAX_RESPONSE_BYTES).map_err(|error| match error {
        BoundedReadError::Read(error) if error.kind() == std::io::ErrorKind::TimedOut => {
            UrlhausError::Timeout(format!("response body read timed out: {error}"))
        }
        BoundedReadError::Read(error) => UrlhausError::BodyRead(error.to_string()),
        BoundedReadError::TooLarge { limit } => {
            UrlhausError::Parse(format!("response exceeded the {limit}-byte size limit"))
        }
    })?;
    parse_response(&bytes, kind)
}

fn reqwest_error_chain(error: reqwest::Error, auth_key: &str) -> String {
    let mut messages = Vec::new();
    let mut cause: Option<&dyn StdError> = Some(&error);
    while let Some(current) = cause {
        let message = current.to_string().replace(auth_key, "[redacted]");
        if !messages.contains(&message) {
            messages.push(message);
        }
        cause = current.source();
    }
    messages.join(": ")
}

fn request_error(is_timeout: bool, explanation: String) -> UrlhausError {
    if is_timeout {
        UrlhausError::Timeout(explanation)
    } else {
        UrlhausError::Request(explanation)
    }
}

#[cfg(test)]
fn build_request(
    client: &Client,
    auth_key: &str,
    kind: QueryKind,
    value: &str,
) -> Result<Request, reqwest::Error> {
    build_request_with_timeout(client, auth_key, kind, value, LOOKUP_TIMEOUT)
}

fn build_request_with_timeout(
    client: &Client,
    auth_key: &str,
    kind: QueryKind,
    value: &str,
    timeout: Duration,
) -> Result<Request, reqwest::Error> {
    let (endpoint, field) = kind.endpoint_and_field();
    client
        .post(endpoint)
        .timeout(timeout)
        .header("Auth-Key", auth_key)
        .header(reqwest::header::CONNECTION, "close")
        .form(&[(field, value)])
        .build()
}

fn http_error(response: Response) -> UrlhausError {
    let status = response.status();
    let retry_after = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    http_error_status(status.as_u16(), retry_after)
}

fn http_error_status(status: u16, retry_after: Option<String>) -> UrlhausError {
    match status {
        401 | 403 => UrlhausError::AuthenticationRejected { status },
        429 => UrlhausError::RateLimited { retry_after },
        _ => UrlhausError::Http { status },
    }
}

#[derive(Debug, Deserialize)]
struct ApiResponse {
    query_status: String,
    #[serde(default, deserialize_with = "optional_string")]
    urlhaus_reference: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    url: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    host: Option<String>,
    #[serde(default, deserialize_with = "optional_usize")]
    url_count: Option<usize>,
    #[serde(default, deserialize_with = "optional_string")]
    md5_hash: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    sha256_hash: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    file_type: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    firstseen: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    lastseen: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    date_added: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    url_status: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    threat: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    signature: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    urls: Option<Vec<ApiUrlRecord>>,
}

#[derive(Debug, Deserialize)]
struct ApiUrlRecord {
    #[serde(default, deserialize_with = "optional_string")]
    urlhaus_reference: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    url: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    url_status: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    host: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    date_added: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    firstseen: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    lastseen: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    threat: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}

fn optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.and_then(|value| value.as_str().map(str::to_owned)))
}

fn optional_usize<'de, D>(deserializer: D) -> Result<Option<usize>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.and_then(|value| {
        value
            .as_u64()
            .and_then(|number| usize::try_from(number).ok())
            .or_else(|| value.as_str()?.parse().ok())
    }))
}

fn parse_response(body: &[u8], kind: QueryKind) -> Result<UrlhausLookupResult, UrlhausError> {
    let response: ApiResponse =
        serde_json::from_slice(body).map_err(|error| UrlhausError::Parse(error.to_string()))?;
    match response.query_status.as_str() {
        "no_results" => Ok(UrlhausLookupResult::NotFound),
        "invalid_url" | "invalid_host" | "invalid_md5" | "invalid_sha256" => {
            Ok(UrlhausLookupResult::InvalidInput(response.query_status))
        }
        "ok" => {
            let mut associated_urls = response
                .urls
                .unwrap_or_default()
                .into_iter()
                .filter_map(api_url_record)
                .collect::<Vec<_>>();
            if kind == QueryKind::Url {
                let url = response.url.clone().ok_or_else(|| {
                    UrlhausError::Parse("successful URL response omitted its URL".into())
                })?;
                associated_urls.insert(
                    0,
                    UrlhausUrlRecord {
                        reference: response.urlhaus_reference.clone(),
                        url,
                        status: response.url_status.clone(),
                        host: response.host.clone(),
                        date_added: response.date_added.clone(),
                        first_seen: response.firstseen.clone(),
                        last_seen: response.lastseen.clone(),
                        threat: response.threat.clone(),
                        tags: response.tags.clone().unwrap_or_default(),
                    },
                );
            }
            associated_urls.truncate(MAX_ASSOCIATED_URLS);
            Ok(UrlhausLookupResult::Found(Box::new(UrlhausLookupDetails {
                reference: response.urlhaus_reference,
                queried_host: response.host,
                associated_url_count: response.url_count,
                md5_hash: response.md5_hash,
                sha256_hash: response.sha256_hash,
                file_type: response.file_type,
                first_seen: response.firstseen,
                last_seen: response.lastseen,
                signature: response.signature,
                associated_urls,
            })))
        }
        "http_post_expected" => Ok(UrlhausLookupResult::ApiError(
            "URLhaus expected an HTTP POST request".into(),
        )),
        other => Ok(UrlhausLookupResult::ApiError(format!(
            "URLhaus returned unexpected query status '{other}'"
        ))),
    }
}

fn api_url_record(record: ApiUrlRecord) -> Option<UrlhausUrlRecord> {
    Some(UrlhausUrlRecord {
        reference: record.urlhaus_reference,
        url: record.url?,
        status: record.url_status,
        host: record.host,
        date_added: record.date_added,
        first_seen: record.firstseen,
        last_seen: record.lastseen,
        threat: record.threat,
        tags: record.tags.unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        HOST_ENDPOINT, MAX_ASSOCIATED_URLS, PAYLOAD_ENDPOINT, QueryKind, URL_ENDPOINT,
        UrlhausError, UrlhausLookupResult, build_request, http_error_status, lookup_indicator,
        parse_response, query_for_indicator, request_error,
    };
    use crate::indicator::{Indicator, IndicatorType};
    use crate::report::UrlhausLookupDetails;
    use reqwest::blocking::Client;

    #[test]
    fn creates_encoded_post_requests_with_correct_fields_and_authentication() {
        let client = Client::new();
        let cases = [
            (
                QueryKind::Url,
                "https://example.test/a path?q=a&b=c",
                URL_ENDPOINT,
                "url",
            ),
            (QueryKind::Host, "example.test", HOST_ENDPOINT, "host"),
            (
                QueryKind::Md5,
                &"a".repeat(32),
                PAYLOAD_ENDPOINT,
                "md5_hash",
            ),
            (
                QueryKind::Sha256,
                &"b".repeat(64),
                PAYLOAD_ENDPOINT,
                "sha256_hash",
            ),
        ];
        for (kind, value, endpoint, field) in cases {
            let request = build_request(&client, "test-auth-key", kind, value).unwrap();
            assert_eq!(request.method(), reqwest::Method::POST);
            assert_eq!(request.url().as_str(), endpoint);
            assert_eq!(request.headers()["Auth-Key"], "test-auth-key");
            assert_eq!(request.headers()[reqwest::header::CONNECTION], "close");
            let body = request.body().unwrap().as_bytes().unwrap();
            let body = String::from_utf8_lossy(body);
            if kind == QueryKind::Md5 {
                assert_eq!(body, format!("md5_hash={value}"));
            }
            assert!(body.starts_with(&format!("{field}=")));
            assert!(
                body.contains("%2F")
                    || kind == QueryKind::Host
                    || kind == QueryKind::Md5
                    || kind == QueryKind::Sha256
            );
        }
    }

    #[test]
    fn routes_supported_indicator_types_and_rejects_unsupported_hashes() {
        for (value, indicator_type, kind) in [
            ("https://example.test/a", IndicatorType::Url, QueryKind::Url),
            ("192.0.2.1", IndicatorType::IP, QueryKind::Host),
            ("example.test", IndicatorType::Domain, QueryKind::Host),
            (&"a".repeat(32), IndicatorType::Hash, QueryKind::Md5),
            (&"b".repeat(64), IndicatorType::Hash, QueryKind::Sha256),
        ] {
            assert_eq!(
                query_for_indicator(&Indicator::new(value, indicator_type)).unwrap(),
                (kind, value)
            );
        }
        assert!(matches!(
            query_for_indicator(&Indicator::new("a".repeat(40), IndicatorType::Hash)),
            Err(UrlhausLookupResult::Unsupported(_))
        ));
        assert!(matches!(
            query_for_indicator(&Indicator::new("2001:db8::1", IndicatorType::IP)),
            Err(UrlhausLookupResult::Unsupported(_))
        ));
    }

    #[test]
    fn missing_credentials_return_without_network_access() {
        let result = lookup_indicator(
            &Client::new(),
            None,
            &Indicator::new("example.test", IndicatorType::Domain),
        )
        .unwrap();
        assert_eq!(result, UrlhausLookupResult::NotConfigured);
    }

    #[test]
    fn http_status_categories_preserve_authentication_rate_limit_and_server_errors() {
        assert_eq!(
            http_error_status(403, None),
            UrlhausError::AuthenticationRejected { status: 403 }
        );
        assert_eq!(
            http_error_status(429, Some("60".into())),
            UrlhausError::RateLimited {
                retry_after: Some("60".into())
            }
        );
        assert_eq!(
            http_error_status(502, None),
            UrlhausError::Http { status: 502 }
        );
    }

    #[test]
    fn transport_and_timeout_errors_remain_distinct() {
        assert_eq!(
            request_error(true, "deadline".into()),
            UrlhausError::Timeout("deadline".into())
        );
        assert_eq!(
            request_error(false, "connection refused".into()),
            UrlhausError::Request("connection refused".into())
        );
        assert!(
            UrlhausError::BodyRead("connection closed".into())
                .to_string()
                .contains("response body read failed")
        );
        assert!(matches!(
            super::outcome(
                Err(UrlhausError::BodyRead("connection closed".into())),
                ""
            ),
            crate::report::LookupOutcome::RequestError { explanation }
                if explanation.contains("response body read failed")
        ));
    }

    #[test]
    fn parses_exact_url_and_offline_results_as_positive_evidence() {
        let result = parse_response(
            br#"{"query_status":"ok","urlhaus_reference":"https://urlhaus.abuse.ch/url/7/","url":"https://example.test/a?q=1","url_status":"offline","host":"example.test","date_added":"2025-01-02 UTC","tags":["sample"]}"#,
            QueryKind::Url,
        )
        .unwrap();
        let UrlhausLookupResult::Found(details) = result else {
            panic!("expected URL evidence")
        };
        assert_eq!(details.associated_urls.len(), 1);
        assert_eq!(
            details.associated_urls[0].status.as_deref(),
            Some("offline")
        );
        assert_eq!(details.associated_urls[0].tags, ["sample"]);
    }

    #[test]
    fn parses_multiple_host_records_and_bounds_the_result_list() {
        let body = format!(
            "{{\"query_status\":\"ok\",\"urlhaus_reference\":\"https://urlhaus.abuse.ch/host/example.test/\",\"host\":\"example.test\",\"url_count\":\"{}\",\"urls\":[{}]}}",
            MAX_ASSOCIATED_URLS + 2,
            (0..MAX_ASSOCIATED_URLS + 2)
                .map(|n| format!(
                    "{{\"url\":\"https://example.test/{n}\",\"url_status\":\"offline\"}}"
                ))
                .collect::<Vec<_>>()
                .join(",")
        );
        let UrlhausLookupResult::Found(details) =
            parse_response(body.as_bytes(), QueryKind::Host).unwrap()
        else {
            panic!("expected host evidence")
        };
        assert_eq!(details.associated_url_count, Some(MAX_ASSOCIATED_URLS + 2));
        assert_eq!(details.associated_urls.len(), MAX_ASSOCIATED_URLS);
        assert_eq!(
            details.reference.as_deref(),
            Some("https://urlhaus.abuse.ch/host/example.test/")
        );
    }

    #[test]
    fn parses_payload_matches_and_optional_fields() {
        let result = parse_response(
            br#"{"query_status":"ok","md5_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sha256_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","file_type":"exe","firstseen":"today","signature":null}"#,
            QueryKind::Md5,
        )
        .unwrap();
        let UrlhausLookupResult::Found(details) = result else {
            panic!("expected payload evidence")
        };
        assert_eq!(
            details.md5_hash.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(details.signature, None);
        assert!(details.associated_urls.is_empty());
    }

    #[test]
    fn parses_no_results_invalid_and_unexpected_statuses_distinctly() {
        let no_payload_results =
            parse_response(br#"{"query_status":"no_results"}"#, QueryKind::Md5).unwrap();
        assert_eq!(no_payload_results, UrlhausLookupResult::NotFound);
        assert_eq!(
            super::outcome(Ok(no_payload_results), "secret-key"),
            crate::report::LookupOutcome::NotFound
        );
        assert_eq!(
            super::outcome(
                Err(UrlhausError::Request(
                    "DNS resolution failed secret-key".into(),
                )),
                "secret-key"
            ),
            crate::report::LookupOutcome::RequestError {
                explanation: "URLhaus request send failed: DNS resolution failed [redacted]".into()
            }
        );
        for (status, kind) in [
            ("invalid_url", QueryKind::Url),
            ("invalid_host", QueryKind::Host),
            ("invalid_md5", QueryKind::Md5),
            ("invalid_sha256", QueryKind::Sha256),
        ] {
            assert_eq!(
                parse_response(format!(r#"{{"query_status":"{status}"}}"#).as_bytes(), kind)
                    .unwrap(),
                UrlhausLookupResult::InvalidInput(status.into())
            );
        }
        assert!(matches!(
            parse_response(br#"{"query_status":"new_provider_state"}"#, QueryKind::Host).unwrap(),
            UrlhausLookupResult::ApiError(_)
        ));
        assert!(parse_response(b"{", QueryKind::Url).is_err());
        assert!(parse_response(br#"{"query_status":"ok"}"#, QueryKind::Url).is_err());
    }

    #[test]
    fn fixture_mapping_retains_only_bounded_report_fields() {
        let result = parse_response(
            br#"{"query_status":"ok","urlhaus_reference":"https://urlhaus.abuse.ch/host/example.test/","host":"example.test","url_count":1,"urls":[{"url":"https://example.test/a","urlhaus_reference":"https://urlhaus.abuse.ch/url/9/","url_status":"online","date_added":"today","tags":["tag"]}]}"#,
            QueryKind::Host,
        )
        .unwrap();
        let UrlhausLookupResult::Found(details) = result else {
            panic!("expected evidence")
        };
        let serialized = serde_json::to_value(details).unwrap();
        assert_eq!(
            serialized["associated_urls"][0]["url"],
            "https://example.test/a"
        );
        assert_eq!(serialized["associated_urls"][0]["tags"][0], "tag");
        let _: UrlhausLookupDetails = serde_json::from_value(serialized).unwrap();
    }
}
