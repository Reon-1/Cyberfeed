/// Optional credentials for independent threat-intelligence integrations.
pub struct Config {
    pub cloudflare_token: Option<String>,
    pub malwarebazaar_auth_key: Option<String>,
}

impl Config {
    pub fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Self {
        Self {
            cloudflare_token: non_blank(lookup("CLOUDFLARE_API_TOKEN")),
            malwarebazaar_auth_key: non_blank(lookup("MALWAREBAZAAR_AUTH_KEY")),
        }
    }
}

fn non_blank(value: Option<String>) -> Option<String> {
    value.and_then(|value| (!value.trim().is_empty()).then_some(value.trim().to_owned()))
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn credentials_are_independent_and_blank_values_are_missing() {
        let cloudflare = Config::from_lookup(|key| match key {
            "CLOUDFLARE_API_TOKEN" => Some("  token  ".into()),
            _ => Some(" \t ".into()),
        });
        assert_eq!(cloudflare.cloudflare_token.as_deref(), Some("token"));
        assert_eq!(cloudflare.malwarebazaar_auth_key, None);

        let malwarebazaar = Config::from_lookup(|key| match key {
            "MALWAREBAZAAR_AUTH_KEY" => Some("key".into()),
            _ => None,
        });
        assert_eq!(malwarebazaar.cloudflare_token, None);
        assert_eq!(malwarebazaar.malwarebazaar_auth_key.as_deref(), Some("key"));
    }

    #[test]
    fn both_credentials_may_be_absent() {
        let config = Config::from_lookup(|_| None);
        assert!(config.cloudflare_token.is_none());
        assert!(config.malwarebazaar_auth_key.is_none());
    }

    #[test]
    fn whitespace_only_credentials_are_missing_for_both_integrations() {
        let config = Config::from_lookup(|_| Some(" \n\t ".into()));
        assert!(config.cloudflare_token.is_none());
        assert!(config.malwarebazaar_auth_key.is_none());
    }
}
