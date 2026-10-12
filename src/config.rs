/// Optional credentials; the abuse.ch key is shared by MalwareBazaar, ThreatFox, and URLhaus.
pub struct Config {
    pub cloudflare_token: Option<String>,
    pub abusech_auth_key: Option<String>,
}

impl Config {
    pub fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Self {
        Self {
            cloudflare_token: non_blank(lookup("CLOUDFLARE_API_TOKEN")),
            abusech_auth_key: non_blank(lookup("ABUSECH_AUTH_KEY")),
        }
    }
}

fn non_blank(value: Option<String>) -> Option<String> {
    value.and_then(|value| (!value.trim().is_empty()).then_some(value.trim().to_owned()))
}

#[cfg(test)]
mod tests {
    use super::Config;
    use crate::indicator::{Indicator, IndicatorType};
    use crate::providers::malwarebazaar::build_hash_lookup_request;
    use crate::providers::threatfox::{build_lookup_request, request_for_indicator};
    use reqwest::blocking::Client;

    #[test]
    fn credentials_are_independent_and_blank_values_are_missing() {
        let cloudflare = Config::from_lookup(|key| match key {
            "CLOUDFLARE_API_TOKEN" => Some("  token  ".into()),
            _ => Some(" \t ".into()),
        });
        assert_eq!(cloudflare.cloudflare_token.as_deref(), Some("token"));
        assert_eq!(cloudflare.abusech_auth_key, None);

        let abusech = Config::from_lookup(|key| match key {
            "ABUSECH_AUTH_KEY" => Some("shared-key".into()),
            "CLOUDFLARE_API_TOKEN" => Some("radar-token".into()),
            _ => None,
        });
        assert_eq!(abusech.cloudflare_token.as_deref(), Some("radar-token"));
        assert_eq!(abusech.abusech_auth_key.as_deref(), Some("shared-key"));
    }

    #[test]
    fn both_credentials_may_be_absent() {
        let config = Config::from_lookup(|_| None);
        assert!(config.cloudflare_token.is_none());
        assert!(config.abusech_auth_key.is_none());
    }

    #[test]
    fn whitespace_only_credentials_are_missing_for_both_integrations() {
        let config = Config::from_lookup(|_| Some(" \n\t ".into()));
        assert!(config.cloudflare_token.is_none());
        assert!(config.abusech_auth_key.is_none());
    }

    #[test]
    fn both_abusech_providers_use_shared_key_and_cloudflare_stays_independent() {
        const ABUSECH_TEST_KEY: &str = "dummy-shared-abusech-key";
        const CLOUDFLARE_TEST_TOKEN: &str = "dummy-cloudflare-token";
        let config = Config::from_lookup(|name| match name {
            "ABUSECH_AUTH_KEY" => Some(ABUSECH_TEST_KEY.into()),
            "CLOUDFLARE_API_TOKEN" => Some(CLOUDFLARE_TEST_TOKEN.into()),
            _ => None,
        });
        let client = Client::new();

        let malwarebazaar_request = build_hash_lookup_request(
            &client,
            config.abusech_auth_key.as_deref().unwrap_or_default(),
            &"a".repeat(64),
        )
        .expect("dummy MalwareBazaar request should build");
        let threatfox_indicator = Indicator::new("192.0.2.1", IndicatorType::IP);
        let threatfox_payload = request_for_indicator(&threatfox_indicator)
            .expect("test IP should produce a ThreatFox request");
        let threatfox_request = build_lookup_request(
            &client,
            config.abusech_auth_key.as_deref().unwrap_or_default(),
            &threatfox_payload,
        )
        .expect("dummy ThreatFox request should build");

        assert_eq!(
            malwarebazaar_request
                .headers()
                .get("Auth-Key")
                .and_then(|value| value.to_str().ok()),
            Some(ABUSECH_TEST_KEY)
        );
        assert_eq!(
            threatfox_request
                .headers()
                .get("Auth-Key")
                .and_then(|value| value.to_str().ok()),
            Some(ABUSECH_TEST_KEY)
        );
        assert_eq!(
            config.cloudflare_token.as_deref(),
            Some(CLOUDFLARE_TEST_TOKEN)
        );
    }
}
