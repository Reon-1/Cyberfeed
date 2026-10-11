use crate::file::FileInfo;
use crate::indicator::{Indicator, IndicatorType};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCHEMA_VERSION: u32 = 1;
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Exportable evidence for one local file inspection.
///
/// This is a report snapshot, not the application-wide session investigation:
/// it carries file context and provider outcomes, but not manually collected
/// indicators from elsewhere in the session.
pub struct InvestigationReport {
    pub schema_version: u32,
    /// Seconds since the Unix epoch in UTC.
    pub generated_at_unix_seconds: u64,
    pub file: ReportFile,
    pub local_inspection: LocalInspection,
    pub provider_lookups: Vec<ProviderLookup>,
    pub summary: ReportSummary,
    pub interpretation: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportFile {
    pub filename: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub inspected_locally_not_executed_or_uploaded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalInspection {
    pub text_extraction: TextExtraction,
    pub indicators: Vec<Indicator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TextExtraction {
    Performed { limit_reached: bool },
    SkippedBinaryOrNonText,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// One provider lookup, including its subject and the time CyberFeed recorded it.
pub struct ProviderLookup {
    pub provider: String,
    pub subject: LookupSubject,
    pub queried_hash: String,
    pub retrieved_at_unix_seconds: Option<u64>,
    pub outcome: LookupOutcome,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LookupSubject {
    OriginalFileSha256,
    ExtractedIndicatorSha256,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportSummary {
    pub original_file_lookup_status: Option<String>,
    pub extracted_indicator_counts: IndicatorCounts,
    pub extracted_hash_lookup_counts: LookupCounts,
    pub extraction_limit_reached: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndicatorCounts {
    pub hashes: usize,
    pub ip_addresses: usize,
    pub domains: usize,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LookupCounts {
    pub found: usize,
    pub not_found: usize,
    pub failures: usize,
    pub skipped_or_unavailable: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "status",
    content = "details",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
/// A lookup result with distinct success, negative, failure, and skipped states.
/// `NotFound` means only that the provider returned no record at lookup time.
pub enum LookupOutcome {
    Found(MatchDetails),
    NotFound,
    Invalid { explanation: String },
    ApiError { explanation: String },
    RequestError { explanation: String },
    NotConfigured,
    SkippedDuplicate { references_hash: String },
    SkippedLookupLimit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatchDetails {
    pub matched_sha256: String,
    pub first_seen: String,
    pub file_type: String,
    pub sample_filename: Option<String>,
    pub signature: Option<String>,
}

impl InvestigationReport {
    pub fn new(
        file: &FileInfo,
        indicators: Vec<Indicator>,
        extraction: Option<bool>,
        lookups: Vec<ProviderLookup>,
    ) -> Self {
        let summary = derive_summary(&indicators, extraction, &lookups);
        Self {
            schema_version: SCHEMA_VERSION,
            generated_at_unix_seconds: now_seconds(),
            file: ReportFile { filename: file.name.clone(), size_bytes: file.size, sha256: file.sha256.clone(), inspected_locally_not_executed_or_uploaded: true },
            local_inspection: LocalInspection {
                text_extraction: extraction.map_or(TextExtraction::SkippedBinaryOrNonText, |limit_reached| TextExtraction::Performed { limit_reached }),
                indicators,
            },
            provider_lookups: lookups,
            summary,
            interpretation: vec![
                "FOUND means the provider returned a matching record; NOT FOUND means it returned no matching record.".into(),
                "No matching record does not establish that a file is safe, and successful local inspection does not establish that it is benign.".into(),
                "A match for a hash extracted from file contents applies to that hash; it does not by itself establish that the original file is malicious.".into(),
                "Extracted IP addresses and domains are investigation leads, not proof of malicious activity.".into(),
                "General network telemetry is not evidence about an individual file.".into(),
            ],
        }
    }
}

fn derive_summary(
    indicators: &[Indicator],
    extraction: Option<bool>,
    lookups: &[ProviderLookup],
) -> ReportSummary {
    let mut indicator_counts = IndicatorCounts::default();
    for indicator in indicators {
        match indicator.indicator_type {
            IndicatorType::Hash => indicator_counts.hashes += 1,
            IndicatorType::IP => indicator_counts.ip_addresses += 1,
            IndicatorType::Domain => indicator_counts.domains += 1,
        }
    }
    let original_file_lookup_status = lookups
        .iter()
        .find(|lookup| lookup.subject == LookupSubject::OriginalFileSha256)
        .map(|lookup| lookup.outcome.status().to_string());
    let mut lookup_counts = LookupCounts::default();
    for lookup in lookups
        .iter()
        .filter(|lookup| lookup.subject == LookupSubject::ExtractedIndicatorSha256)
    {
        match lookup.outcome {
            LookupOutcome::Found(_) => lookup_counts.found += 1,
            LookupOutcome::NotFound => lookup_counts.not_found += 1,
            LookupOutcome::Invalid { .. }
            | LookupOutcome::ApiError { .. }
            | LookupOutcome::RequestError { .. } => lookup_counts.failures += 1,
            LookupOutcome::NotConfigured
            | LookupOutcome::SkippedDuplicate { .. }
            | LookupOutcome::SkippedLookupLimit => lookup_counts.skipped_or_unavailable += 1,
        }
    }
    ReportSummary {
        original_file_lookup_status,
        extracted_indicator_counts: indicator_counts,
        extracted_hash_lookup_counts: lookup_counts,
        extraction_limit_reached: extraction.unwrap_or(false),
    }
}

impl LookupOutcome {
    pub fn status(&self) -> &'static str {
        match self {
            Self::Found(_) => "FOUND",
            Self::NotFound => "NOT FOUND",
            Self::Invalid { .. } => "INVALID",
            Self::ApiError { .. } => "API ERROR",
            Self::RequestError { .. } => "REQUEST ERROR",
            Self::NotConfigured => "NOT CONFIGURED",
            Self::SkippedDuplicate { .. } => "SKIPPED: DUPLICATE",
            Self::SkippedLookupLimit => "SKIPPED: LOOKUP LIMIT",
        }
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
