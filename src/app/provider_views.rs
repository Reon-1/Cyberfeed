//! Terminal presentation for provider data; request and parsing code stays in provider modules.
use crate::cloudflare::{TopAttackPairs, TopOrigins, TopTargets};
use crate::indicator::{Indicator, IndicatorType};
use crate::malwarebazaar::{MalwareLookupResult, MalwareResponse, MalwareSample};
use crate::ui;

// Display the result of a hash lookup without adding it to the sample feed UI.
pub(super) fn display_hash_lookup(result: &MalwareLookupResult) {
    match result {
        MalwareLookupResult::Found(sample) => {
            ui::status("MalwareBazaar", "FOUND", ui::Status::Success);
            ui::box_line("  MalwareBazaar returned a record for this hash.");
            ui::field("First seen", &sample.first_seen);
            ui::field("File type", &sample.file_type);
            ui::field(
                "Signature",
                sample.signature.as_deref().unwrap_or("Unknown"),
            );
        }
        MalwareLookupResult::NotFound => {
            ui::status("MalwareBazaar", "NOT FOUND", ui::Status::Warning);
            ui::box_line("  No record for this hash was returned by MalwareBazaar.");
            ui::warning("This does not determine whether the file is malicious or safe.");
        }
        MalwareLookupResult::InvalidHash(status) => {
            ui::status("MalwareBazaar", "INVALID", ui::Status::Error);
            ui::box_line("  MalwareBazaar could not use the submitted hash value.");
            ui::field("Provider detail", status);
        }
        MalwareLookupResult::ApiError(status) => {
            ui::status("MalwareBazaar", "API ERROR", ui::Status::Error);
            ui::box_line("  MalwareBazaar did not return a usable lookup result.");
            ui::field("Provider detail", status);
        }
    }
}

// Display the malware data in the terminal.
pub(super) fn display_malware_data(
    data: &MalwareResponse,
    country: Option<&str>,
) -> Vec<Indicator> {
    ui::header("MALWAREBAZAAR", "Recent malware sample intelligence");

    ui::section("FEED STATUS");
    ui::field("Provider", "MalwareBazaar");

    if data.query_status == "ok" {
        ui::status("STATUS", "ONLINE", ui::Status::Success);
        ui::field("Results", format!("{} recent samples", data.data.len()));
    } else {
        ui::status("STATUS", "ERROR", ui::Status::Error);
        ui::field("Results", "No samples returned");
    }

    ui::section("RECENT SAMPLES");

    // If a country was provided, only keep samples from that country.
    // Otherwise, keep all samples.
    let samples: Vec<&MalwareSample> = match country {
        Some(country) => data
            .data
            .iter()
            .filter(|sample| sample.origin_country.as_deref() == Some(country))
            .collect(),

        None => data.data.iter().collect(),
    };

    let mut indicators: Vec<Indicator> = Vec::new();

    if samples.is_empty() {
        match country {
            Some(country) => ui::box_line(&format!("  No malware samples found for {country}.")),
            None => ui::box_line("  No malware samples were returned."),
        }
    } else {
        // Go through each malware sample one at a time.
        for (index, sample) in samples.iter().enumerate() {
            // Convert the MalwareBazaar sample into our common Indicator type.
            indicators.push(Indicator::new(&sample.sha256_hash, IndicatorType::Hash));

            display_sample(sample, index + 1);
        }
    }

    ui::close_box();
    println!();

    indicators
}

// Display one malware sample as a card.
fn display_sample(sample: &MalwareSample, number: usize) {
    let country_code = sample
        .origin_country
        .as_deref()
        .unwrap_or("")
        .to_uppercase();

    // Convert the country code into a flag and readable country name.
    let flag = ui::country_flag(&country_code);
    let country = country_name(&country_code);
    let origin = if country_code.is_empty() {
        format!("{flag} {country}")
    } else {
        format!("{flag} {country} ({country_code})")
    };

    ui::section(&format!("MALWARE SAMPLE #{number}"));
    ui::field("File", &sample.file_name);
    ui::field("Type", &sample.file_type);
    ui::field("Origin", origin);
    ui::field("First seen", &sample.first_seen);
    ui::field("SHA-256", &sample.sha256_hash);
    ui::field(
        "Signature",
        sample.signature.as_deref().unwrap_or("Unknown"),
    );
    ui::box_line("");
}

// Convert an ISO country code into a readable country name.
fn country_name(code: &str) -> &str {
    match code {
        "AU" => "Australia",
        "AT" => "Austria",
        "BE" => "Belgium",
        "BR" => "Brazil",
        "CA" => "Canada",
        "CH" => "Switzerland",
        "CN" => "China",
        "CZ" => "Czech Republic",
        "DE" => "Germany",
        "DK" => "Denmark",
        "ES" => "Spain",
        "FI" => "Finland",
        "FR" => "France",
        "GB" => "United Kingdom",
        "GR" => "Greece",
        "HK" => "Hong Kong",
        "HU" => "Hungary",
        "ID" => "Indonesia",
        "IE" => "Ireland",
        "IN" => "India",
        "IT" => "Italy",
        "JP" => "Japan",
        "KR" => "South Korea",
        "MX" => "Mexico",
        "MY" => "Malaysia",
        "NL" => "Netherlands",
        "NO" => "Norway",
        "NP" => "Nepal",
        "NZ" => "New Zealand",
        "PL" => "Poland",
        "PT" => "Portugal",
        "RO" => "Romania",
        "RU" => "Russia",
        "SE" => "Sweden",
        "SG" => "Singapore",
        "TH" => "Thailand",
        "TR" => "Turkey",
        "TW" => "Taiwan",
        "UA" => "Ukraine",
        "US" => "United States",
        "VN" => "Vietnam",
        "ZA" => "South Africa",
        _ => "Unknown",
    }
}

pub(super) fn display_top_origins(data: &TopOrigins) {
    ui::section("SOURCE COUNTRIES");

    // Display each country returned by Cloudflare
    for country in &data.top_0 {
        let flag = ui::country_flag(&country.origin_country_alpha2);
        let bar = percentage_bar(country.value);

        ui::box_line(&format!(
            "  #{:<2} {} {:<18} {:>6.2}%",
            country.rank,
            flag,
            shorten(&country.origin_country_name, 18),
            country.value
        ));

        ui::box_line(&format!("      {bar}"));
    }
}

pub(super) fn display_top_targets(data: &TopTargets) {
    ui::section("TARGET COUNTRIES");

    // Display each target country returned by Cloudflare
    for country in &data.top_0 {
        let flag = ui::country_flag(&country.target_country_alpha2);
        let bar = percentage_bar(country.value);

        ui::box_line(&format!(
            "  #{:<2} {} {:<18} {:>6.2}%",
            country.rank,
            flag,
            shorten(&country.target_country_name, 18),
            country.value
        ));

        ui::box_line(&format!("      {bar}"));
    }
}

pub(super) fn display_top_attack_pairs(data: &TopAttackPairs) {
    ui::section("ORIGIN → TARGET ATTACK PAIRS");

    // Display where the attacks are coming from and where they are going
    for pair in &data.top_0 {
        let origin_flag = ui::country_flag(&pair.origin_country_alpha2);
        let target_flag = ui::country_flag(&pair.target_country_alpha2);
        let bar = percentage_bar(pair.value);

        ui::box_line(&format!(
            "  #{:<2} {} {} → {} {:<16} {:>6.2}%",
            pair.rank,
            origin_flag,
            shorten(&pair.origin_country_name, 12),
            target_flag,
            shorten(&pair.target_country_name, 16),
            pair.value
        ));

        ui::box_line(&format!("      {bar}"));
    }
}

fn percentage_bar(value: f64) -> String {
    // Turn the percentage into a 20-character progress bar
    let filled = ((value / 5.0) * 20.0).round() as usize;

    // Don't allow the bar to become longer than 20 characters
    let filled = filled.min(20);

    format!("[{}{}]", "█".repeat(filled), "░".repeat(20 - filled))
}

fn shorten(text: &str, max_length: usize) -> String {
    // Shorten long country names so they don't break the terminal layout
    if text.chars().count() <= max_length {
        return text.to_string();
    }

    let shortened: String = text.chars().take(max_length.saturating_sub(3)).collect();

    format!("{}...", shortened)
}
