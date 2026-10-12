use reqwest::blocking::Client;
use serde::Deserialize;
use serde::de::{self, Deserializer};
use std::fmt;
use std::io::Read;
use std::time::Duration;

use crate::http_response::{BoundedReadError, read_bounded};

const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Deserialize)]
pub struct OriginCountry {
    #[serde(rename = "originCountryAlpha2")]
    pub origin_country_alpha2: String,

    #[serde(rename = "originCountryName")]
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
    pub target_country_alpha2: String,

    #[serde(rename = "targetCountryName")]
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
    pub origin_country_alpha2: String,

    #[serde(rename = "originCountryName")]
    pub origin_country_name: String,

    #[serde(rename = "targetCountryAlpha2")]
    pub target_country_alpha2: String,

    #[serde(rename = "targetCountryName")]
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
    pub success: bool,
    pub result: T,
}

#[derive(Debug)]
pub enum CloudflareError {
    Request(String),
    Http { status: u16, body: String },
    Parse(String),
}

impl fmt::Display for CloudflareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(message) => write!(formatter, "Cloudflare request failed: {message}"),
            Self::Http { status, body } => {
                write!(formatter, "Cloudflare returned HTTP {status}: {body}")
            }
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
        let body = redact(&read_error_body(response), token);
        return Err(CloudflareError::Http {
            status: status.as_u16(),
            body,
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
    serde_json::from_slice(&bytes).map_err(|error| CloudflareError::Parse(error.to_string()))
}

fn redact(message: &str, token: &str) -> String {
    if token.is_empty() {
        message.to_owned()
    } else {
        message.replace(token, "[redacted]")
    }
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
    let mut result = String::from_utf8_lossy(&bytes).into_owned();
    if truncated {
        result.push_str("… [truncated]");
    }
    result
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
}
