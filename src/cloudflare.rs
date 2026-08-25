use reqwest::blocking::Client;
use serde::Deserialize;

// Represents one country returned by Cloudflare as an attack origin.
#[derive(Deserialize)]
pub struct OriginCountry {
    // Cloudflare uses camelCase field names.
    #[serde(rename = "originCountryAlpha2")]
    pub origin_country_alpha2: String,

    #[serde(rename = "originCountryName")]
    pub origin_country_name: String,

    // Cloudflare sends the percentage as a JSON String.
    #[serde(deserialize_with = "parse_f64_from_string")]
    pub value: f64,

    pub rank: usize,
}

// Holds the list of top origin countries returned by Cloudflare.
#[derive(Deserialize)]
pub struct TopOrigins {
    pub top_0: Vec<OriginCountry>,
}

// Represents one country returned by Cloudflare as an attack target.
#[derive(Deserialize)]
pub struct TargetCountry {
    #[serde(rename = "targetCountryAlpha2")]
    pub target_country_alpha2: String,

    #[serde(rename = "targetCountryName")]
    pub target_country_name: String,

    #[serde(deserialize_with = "parse_f64_from_string")]
    pub value: f64,

    pub rank: usize,
}

// Holds the list of top target countries returned by Cloudflare.
#[derive(Deserialize)]
pub struct TopTargets {
    pub top_0: Vec<TargetCountry>,
}

// Represents one origin -> target attack pair returned by Cloudflare.
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

    #[serde(deserialize_with = "parse_f64_from_string")]
    pub value: f64,

    pub rank: usize,
}

// Holds the list of top origin -> target attack pairs.
#[derive(Deserialize)]
pub struct TopAttackPairs {
    pub top_0: Vec<AttackPair>,
}

// Represents the common structure of a Cloudflare API response.
//
// T allows the same response type to be reused for origins,
// targets, and attack pairs.
#[derive(Deserialize)]
pub struct CloudflareResponse<T> {
    pub success: bool,
    pub result: T,
}

// Converts a number such as "12.291670" from a JSON String into an f64.
fn parse_f64_from_string<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;

    value.parse().map_err(serde::de::Error::custom)
}

// Fetch the top origin countries from Cloudflare.
pub fn fetch_cloudflare_data(client: &Client, token: &str) -> CloudflareResponse<TopOrigins> {
    let response = client
        .get(
            "https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/origin?dateRange=1d",
        )
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .expect("Failed to send request");

    println!("{}", response.status());

    let data: CloudflareResponse<TopOrigins> = response
        .json()
        .expect("Failed to parse Cloudflare response");

    println!("API request successful: {}", data.success);

    data
}

// Fetch the top target countries from Cloudflare.
pub fn fetch_cloudflare_targets(client: &Client, token: &str) -> CloudflareResponse<TopTargets> {
    let response = client
        .get(
            "https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/target?dateRange=1d",
        )
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .expect("Failed to send request");

    println!("{}", response.status());

    let data: CloudflareResponse<TopTargets> = response
        .json()
        .expect("Failed to parse Cloudflare response");

    println!("API request successful: {}", data.success);

    data
}

// Fetch the top origin -> target attack pairs from Cloudflare.
pub fn fetch_cloudflare_attack_pairs(
    client: &Client,
    token: &str,
) -> CloudflareResponse<TopAttackPairs> {
    let response = client
        .get(
            "https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/attacks?limit=5&dateRange=1d&format=json",
        )
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .expect("Failed to send request");

    println!("{}", response.status());

    let data: CloudflareResponse<TopAttackPairs> = response
        .json()
        .expect("Failed to parse Cloudflare response");

    println!("API request successful: {}", data.success);

    data
}

// Display the countries Cloudflare currently reports as the
// top sources of Layer 7 attacks.
pub fn display_top_origins(origins: &[OriginCountry]) {
    println!("\nTOP ATTACK ORIGINS");
    println!("-----------------------------");

    for country in origins {
        println!(
            "{}. {} {} ({}) - {:.2}%",
            country.rank,
            country_flag(&country.origin_country_alpha2),
            country.origin_country_name,
            country.origin_country_alpha2,
            country.value
        );
    }
}

// Display the countries Cloudflare currently reports as the
// top targets of Layer 7 attacks.
pub fn display_top_targets(targets: &[TargetCountry]) {
    println!("\nTOP ATTACK TARGETS");
    println!("-----------------------------");

    for country in targets {
        println!(
            "{}. {} {} ({}) - {:.2}%",
            country.rank,
            country_flag(&country.target_country_alpha2),
            country.target_country_name,
            country.target_country_alpha2,
            country.value
        );
    }
}

// Display the top origin -> target attack pairs.
//
// The percentage represents the share of attack requests
// associated with that particular origin -> target pair.
pub fn display_top_attack_pairs(pairs: &[AttackPair]) {
    println!("\nTOP ATTACK PAIRS");
    println!("-----------------------------");

    for pair in pairs {
        println!(
            "{}. {} {} ({}) -> {} {} ({})",
            pair.rank,
            country_flag(&pair.origin_country_alpha2),
            pair.origin_country_name,
            pair.origin_country_alpha2,
            country_flag(&pair.target_country_alpha2),
            pair.target_country_name,
            pair.target_country_alpha2
        );

        println!("   {:.2}% of attack requests", pair.value);
    }
}

// Convert a two-letter country code such as "US" into 🇺🇸.
fn country_flag(code: &str) -> String {
    code.chars()
        .filter_map(|letter| {
            let letter = letter.to_ascii_uppercase();

            if letter.is_ascii_uppercase() {
                char::from_u32(0x1F1E6 + (letter as u32 - 'A' as u32))
            } else {
                None
            }
        })
        .collect()
}
