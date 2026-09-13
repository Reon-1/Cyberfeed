use reqwest::blocking::Client;
use serde::Deserialize;
use serde::de::{self, Deserializer};

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

fn parse_f64_from_string<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: Deserializer<'de>,
{
    // Get the value from the API as a String
    let value = String::deserialize(deserializer)?;

    // Convert the String into a floating-point number
    value
        .parse::<f64>()
        .map_err(|error| de::Error::custom(error.to_string()))
}

pub fn fetch_cloudflare_data(client: &Client, token: &str) -> CloudflareResponse<TopOrigins> {
    let url = "https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/origin?dateRange=1d";

    // Send the request with the Cloudflare API token
    client
        .get(url)
        .bearer_auth(token)
        .send()
        .expect("Failed to request Cloudflare origin data")
        .json()
        .expect("Failed to parse Cloudflare origin response")
}

pub fn fetch_cloudflare_targets(client: &Client, token: &str) -> CloudflareResponse<TopTargets> {
    let url = "https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/target?dateRange=1d";

    // Send the request with the Cloudflare API token
    client
        .get(url)
        .bearer_auth(token)
        .send()
        .expect("Failed to request Cloudflare target data")
        .json()
        .expect("Failed to parse Cloudflare target response")
}

pub fn fetch_cloudflare_attack_pairs(
    client: &Client,
    token: &str,
) -> CloudflareResponse<TopAttackPairs> {
    let url = "https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/attacks?limit=5&dateRange=1d&format=json";

    // Send the request with the Cloudflare API token
    client
        .get(url)
        .bearer_auth(token)
        .send()
        .expect("Failed to request Cloudflare attack pair data")
        .json()
        .expect("Failed to parse Cloudflare attack pair response")
}

pub fn display_top_origins(data: &TopOrigins) {
    println!("║  SOURCE COUNTRIES                                         ║");
    println!("║                                                            ║");

    // Display each country returned by Cloudflare
    for country in &data.top_0 {
        let flag = country_flag(&country.origin_country_alpha2);
        let bar = percentage_bar(country.value);

        println!(
            "║  #{:<2} {} {:<18} {:>6.2}%                         ║",
            country.rank,
            flag,
            shorten(&country.origin_country_name, 18),
            country.value
        );

        println!("║      {}                                    ║", bar);
    }
}

pub fn display_top_targets(data: &TopTargets) {
    println!("║  TARGET COUNTRIES                                         ║");
    println!("║                                                            ║");

    // Display each target country returned by Cloudflare
    for country in &data.top_0 {
        let flag = country_flag(&country.target_country_alpha2);
        let bar = percentage_bar(country.value);

        println!(
            "║  #{:<2} {} {:<18} {:>6.2}%                         ║",
            country.rank,
            flag,
            shorten(&country.target_country_name, 18),
            country.value
        );

        println!("║      {}                                    ║", bar);
    }
}

pub fn display_top_attack_pairs(data: &TopAttackPairs) {
    println!("║  ORIGIN → TARGET ATTACK PAIRS                              ║");
    println!("║                                                            ║");

    // Display where the attacks are coming from and where they are going
    for pair in &data.top_0 {
        let origin_flag = country_flag(&pair.origin_country_alpha2);
        let target_flag = country_flag(&pair.target_country_alpha2);
        let bar = percentage_bar(pair.value);

        println!(
            "║  #{:<2} {} {} → {} {:<16} {:>6.2}%              ║",
            pair.rank,
            origin_flag,
            shorten(&pair.origin_country_name, 12),
            target_flag,
            shorten(&pair.target_country_name, 16),
            pair.value
        );

        println!("║      {}                                    ║", bar);
    }
}

fn percentage_bar(value: f64) -> String {
    // Turn the percentage into a 20-character progress bar
    let filled = ((value / 5.0) * 20.0).round() as usize;

    // Don't allow the bar to become longer than 20 characters
    let filled = filled.min(20);

    format!("[{}{}]", "█".repeat(filled), "░".repeat(20 - filled))
}

fn country_flag(code: &str) -> String {
    // Country flags are made from two regional indicator characters
    if code.len() != 2 {
        return "🏳️".to_string();
    }

    let mut flag = String::new();

    for character in code.to_uppercase().chars() {
        if !character.is_ascii_uppercase() {
            return "🏳️".to_string();
        }

        let regional_indicator = char::from_u32(0x1F1E6 + (character as u32 - 'A' as u32));

        if let Some(regional_indicator) = regional_indicator {
            flag.push(regional_indicator);
        }
    }

    flag
}

fn shorten(text: &str, max_length: usize) -> String {
    // Shorten long country names so they don't break the terminal layout
    if text.chars().count() <= max_length {
        return text.to_string();
    }

    let shortened: String = text.chars().take(max_length.saturating_sub(3)).collect();

    format!("{}...", shortened)
}
