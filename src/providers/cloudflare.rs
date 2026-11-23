use reqwest::blocking::Client;
use serde::Deserialize;
use serde::de::{self, Deserializer};
use std::fmt;
use std::time::Duration;

use crate::http_response::{BoundedReadError, read_bounded};

const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Deserialize)]
pub struct OriginCountry {
    #[serde(rename = "originCountryAlpha2")]
    #[serde(default)]
    pub origin_country_alpha2: String,

    #[serde(rename = "originCountryName")]
    #[serde(default)]
    pub origin_country_name: String,

    // Cloudflare sends the percentage as a string, so convert it to f64
    #[serde(deserialize_with = "parse_f64_from_string")]
    pub value: f64,

    pub rank: usize,
}

#[derive(Deserialize)]
pub struct TopOrigins {
    pub top_0: Vec<OriginCountry>,
}

#[derive(Deserialize)]
pub struct TargetCountry {
    #[serde(rename = "targetCountryAlpha2")]
    #[serde(default)]
    pub target_country_alpha2: String,

    #[serde(rename = "targetCountryName")]
    #[serde(default)]
    pub target_country_name: String,

    // Convert the percentage string into a number
    #[serde(deserialize_with = "parse_f64_from_string")]
    pub value: f64,

    pub rank: usize,
}

#[derive(Deserialize)]
pub struct TopTargets {
    pub top_0: Vec<TargetCountry>,
}

#[derive(Deserialize)]
pub struct AttackPair {
    #[serde(rename = "originCountryAlpha2")]
    #[serde(default)]
    pub origin_country_alpha2: String,

    #[serde(rename = "originCountryName")]
    #[serde(default)]
    pub origin_country_name: String,

    #[serde(rename = "targetCountryAlpha2")]
    #[serde(default)]
    pub target_country_alpha2: String,

    #[serde(rename = "targetCountryName")]
    #[serde(default)]
    pub target_country_name: String,

    // Convert the percentage string into a number
    #[serde(deserialize_with = "parse_f64_from_string")]
    pub value: f64,

    pub rank: usize,
}

#[derive(Deserialize)]
pub struct TopAttackPairs {
    pub top_0: Vec<AttackPair>,
}

#[derive(Deserialize)]
pub struct CloudflareResponse<T> {
    pub result: T,
}

#[derive(Debug)]
pub enum CloudflareError {
    Request(String),
    Http {
        status: u16,
        retry_after_seconds: Option<u64>,
    },
    Rejected,
    Parse(String),
}

impl fmt::Display for CloudflareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(message) => write!(formatter, "Cloudflare request failed: {message}"),
            Self::Http {
                status: 401 | 403, ..
            } => write!(
                formatter,
                "Cloudflare rejected the credential or its permissions."
            ),
            Self::Http {
                status: 429,
                retry_after_seconds,
            } => {
                write!(formatter, "Cloudflare rate limited the request (HTTP 429).")?;
                if let Some(seconds) = retry_after_seconds {
                    write!(
                        formatter,
                        " Wait at least {seconds} seconds before retrying."
                    )
                } else {
                    write!(formatter, " Wait before retrying.")
                }
            }
            Self::Http { status, .. } => write!(formatter, "Cloudflare returned HTTP {status}."),
            Self::Rejected => write!(formatter, "Cloudflare rejected the feed query."),
            Self::Parse(message) => {
                write!(formatter, "Could not parse Cloudflare response: {message}")
            }
        }
    }
}

fn parse_f64_from_string<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: Deserializer<'de>,
{
    // Get the value from the API as a String
    let value = String::deserialize(deserializer)?;

    // Convert the String into a floating-point number
    let parsed = value
        .parse::<f64>()
        .map_err(|error| de::Error::custom(error.to_string()))?;
    if !parsed.is_finite() {
        return Err(de::Error::custom("percentage must be a finite number"));
    }
    Ok(parsed)
}

pub fn fetch_cloudflare_data(
    client: &Client,
    token: &str,
) -> Result<CloudflareResponse<TopOrigins>, CloudflareError> {
    let url = "https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/origin?dateRange=1d";
    fetch_json(client, url, token)
}

pub fn fetch_cloudflare_targets(
    client: &Client,
    token: &str,
) -> Result<CloudflareResponse<TopTargets>, CloudflareError> {
    let url = "https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/target?dateRange=1d";
    fetch_json(client, url, token)
}

pub fn fetch_cloudflare_attack_pairs(
    client: &Client,
    token: &str,
) -> Result<CloudflareResponse<TopAttackPairs>, CloudflareError> {
    let url = "https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/attacks?limit=5&dateRange=1d&format=json";
    fetch_json(client, url, token)
}

fn fetch_json<T: for<'de> serde::Deserialize<'de>>(
    client: &Client,
    url: &str,
    token: &str,
) -> Result<CloudflareResponse<T>, CloudflareError> {
    let response = client
        .get(url)
        .timeout(REQUEST_TIMEOUT)
        .bearer_auth(token)
        .send()
        .map_err(|error| {
            let timed_out = error.is_timeout();
            let message = redact(&error.without_url().to_string(), token);
            CloudflareError::Request(if timed_out {
                format!("request timed out: {message}")
            } else {
                message
            })
        })?;
    let status = response.status();
    if !status.is_success() {
        let retry_after_seconds = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|text| text.parse().ok());
        return Err(CloudflareError::Http {
            status: status.as_u16(),
            retry_after_seconds,
        });
    }

    let bytes = read_bounded(response, MAX_RESPONSE_BYTES).map_err(|error| match error {
        BoundedReadError::Read(error) if error.kind() == std::io::ErrorKind::TimedOut => {
            CloudflareError::Request(format!("response body read timed out: {error}"))
        }
        BoundedReadError::Read(error) => CloudflareError::Request(error.to_string()),
        BoundedReadError::TooLarge { limit } => {
            CloudflareError::Parse(format!("response exceeded the {limit}-byte size limit"))
        }
    })?;
    parse_feed_response(&bytes)
}

fn parse_feed_response<T: for<'de> serde::Deserialize<'de>>(
    bytes: &[u8],
) -> Result<CloudflareResponse<T>, CloudflareError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| CloudflareError::Parse("invalid response JSON".into()))?;
    match value.get("success").and_then(serde_json::Value::as_bool) {
        Some(false) => Err(CloudflareError::Rejected),
        Some(true) => serde_json::from_value(value)
            .map_err(|_| CloudflareError::Parse("invalid feed result".into())),
        None => Err(CloudflareError::Parse(
            "missing or invalid success flag".into(),
        )),
    }
}

fn redact(message: &str, token: &str) -> String {
    if token.is_empty() {
        message.to_owned()
    } else {
        message.replace(token, "[redacted]")
    }
}

#[cfg(test)]
mod tests {
    use super::{CloudflareResponse, TopAttackPairs, TopOrigins, TopTargets, redact};

    #[test]
    fn provider_errors_redact_bearer_tokens() {
        assert_eq!(
            redact("remote echoed private-token", "private-token"),
            "remote echoed [redacted]"
        );
    }

    #[test]
    fn mock_http_rate_limit_keeps_retry_guidance_without_echoing_body() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("local mock could not accept request: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.extend_from_slice(&byte);
            }
            let body = "dummy-token";
            write!(stream, "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 42\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
        });
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .build()
            .unwrap();
        let result =
            super::fetch_json::<TopOrigins>(&client, &format!("http://{address}"), "dummy-token");
        server.join().unwrap();
        let Err(error) = result else {
            panic!("expected HTTP error")
        };
        assert!(matches!(
            error,
            super::CloudflareError::Http {
                status: 429,
                retry_after_seconds: Some(42)
            }
        ));
        assert!(error.to_string().contains("42 seconds"));
        assert!(!error.to_string().contains("dummy-token"));
    }

    #[test]
    fn radar_distinguishes_rejected_missing_and_empty_payloads() {
        assert!(matches!(
            super::parse_feed_response::<TopOrigins>(br#"{"success":false,"result":{"top_0":[]}}"#),
            Err(super::CloudflareError::Rejected)
        ));
        assert!(matches!(
            super::parse_feed_response::<TopOrigins>(br#"{"success":true}"#),
            Err(super::CloudflareError::Parse(_))
        ));
        assert!(
            super::parse_feed_response::<TopOrigins>(br#"{"success":true,"result":{"top_0":[]}}"#)
                .unwrap()
                .result
                .top_0
                .is_empty()
        );
    }

    #[test]
    fn parses_all_radar_feed_shapes() {
        let origins: CloudflareResponse<TopOrigins> = serde_json::from_str(
            r#"{"success":true,"result":{"top_0":[{"originCountryAlpha2":"NP","originCountryName":"Nepal","value":"12.5","rank":1}]}}"#,
        )
        .expect("origin response should parse");
        assert_eq!(origins.result.top_0[0].value, 12.5);

        let targets: CloudflareResponse<TopTargets> =
            serde_json::from_str(r#"{"success":true,"result":{"top_0":[]}}"#)
                .expect("target response should parse");
        assert!(targets.result.top_0.is_empty());

        let pairs: CloudflareResponse<TopAttackPairs> =
            serde_json::from_str(r#"{"success":true,"result":{"top_0":[]}}"#)
                .expect("attack pair response should parse");
        assert!(pairs.result.top_0.is_empty());
    }

    #[test]
    fn rejects_non_finite_percentage_values() {
        let response: Result<CloudflareResponse<TopOrigins>, _> = serde_json::from_str(
            r#"{"success":true,"result":{"top_0":[{"originCountryAlpha2":"NP","originCountryName":"Nepal","value":"NaN","rank":1}]}}"#,
        );
        assert!(response.is_err());
    }

    #[test]
    fn country_metadata_may_be_missing_without_losing_the_record() {
        let response: CloudflareResponse<TopOrigins> = serde_json::from_str(
            r#"{"success":true,"result":{"top_0":[{"value":"12.5","rank":1}]}}"#,
        )
        .expect("optional location metadata should not discard a valid row");
        let country = &response.result.top_0[0];
        assert!(country.origin_country_alpha2.is_empty());
        assert!(country.origin_country_name.is_empty());
        assert_eq!(country.value, 12.5);
    }
}
