use reqwest::blocking::Client;
use serde::Deserialize;

// Represents one country returned by Cloudflare.
#[derive(Deserialize)]
pub struct OriginCountry {
    // Cloudflare uses camelCase, so we tell Serde which JSON field to use.
    #[serde(rename = "originCountryAlpha2")]
    pub origin_country_alpha2: String,

    #[serde(rename = "originCountryName")]
    pub origin_country_name: String,

    // Cloudflare sends this number as a String, so we convert it to f64.
    #[serde(deserialize_with = "parse_f64_from_string")]
    pub value: f64,

    pub rank: usize,
}

// Holds the list of countries returned by Cloudflare.
#[derive(Deserialize)]
pub struct TopOrigins {
    pub top_0: Vec<OriginCountry>,
}

// Represents the main Cloudflare response.
#[derive(Deserialize)]
pub struct CloudflareResponse {
    pub success: bool,
    pub result: TopOrigins,
}

// Converts a number like "22.425573" from a JSON String into an f64.
fn parse_f64_from_string<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;

    value.parse().map_err(serde::de::Error::custom)
}

// Fetch data from Cloudflare.
pub fn fetch_cloudflare_data(client: &Client, token: &str) -> CloudflareResponse {
    let response = client
        .get("https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/origin?dateRange=1d")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .expect("Failed to send request");

    println!("{}", response.status());

    // Turn Cloudflare's JSON into our Rust structs.
    let data: CloudflareResponse = response
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

    // Go through each country in Cloudflare's list.
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

// Turn a two-letter country code like "US" into 🇺🇸.
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
