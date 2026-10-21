use crate::file::FileInfo;
use crate::indicator::{Indicator, IndicatorType};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCHEMA_VERSION: u32 = 5;
pub const SESSION_REPORT_TYPE: &str = "SESSION";
/// Saved JSON reports are bounded to this size when written and reopened.
pub const MAX_SAVED_REPORT_BYTES: u64 = 32 * 1024 * 1024;
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

/// A snapshot of all completed checks in one application session.
///
/// File checks retain their existing file-scoped report as one entry, while
/// manual indicator checks retain their own indicator and provider outcomes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReport {
    pub schema_version: u32,
    pub report_type: String,
    pub generated_at_unix_seconds: u64,
    pub checks: Vec<SessionCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "check_type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionCheck {
    FileInvestigation {
        report: Box<InvestigationReport>,
    },
    IndicatorLookup {
        indicator: Indicator,
        provider_lookups: Vec<ProviderLookup>,
    },
}

impl SessionReport {
    pub fn new(checks: Vec<SessionCheck>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            report_type: SESSION_REPORT_TYPE.into(),
            generated_at_unix_seconds: now_seconds(),
            checks,
        }
    }
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
    /// Optional per-line provenance, present for log-hunt reports (schema v4).
    #[serde(default)]
    pub source_occurrences: Vec<SourceOccurrence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceOccurrence {
    pub source_filename: String,
    pub line_number: u64,
    pub indicator: Indicator,
    pub original_value: String,
    pub context: String,
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
    /// Queried hash or other indicator value. The JSON key stays `queried_hash`
    /// for compatibility with existing schema-version-1 report consumers.
    pub queried_hash: String,
    pub retrieved_at_unix_seconds: Option<u64>,
    pub outcome: LookupOutcome,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LookupSubject {
    OriginalFileSha256,
    ExtractedIndicatorSha256,
    ExtractedIndicator,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportSummary {
    /// Aggregate status across recorded original-file provider outcomes.
    pub original_file_lookup_status: Option<String>,
    pub extracted_indicator_counts: IndicatorCounts,
    /// Counts provider outcomes for extracted hashes only (MD5, SHA-1, and SHA-256).
    pub extracted_hash_lookup_counts: LookupCounts,
    pub extraction_limit_reached: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndicatorCounts {
    pub hashes: usize,
    pub ip_addresses: usize,
    pub domains: usize,
    /// Added in schema version 3; older reports deserialize this as zero.
    #[serde(default)]
    pub urls: usize,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Provider outcomes for extracted hashes. Unsupported, unconfigured, duplicate,
/// and limit-skipped queries share the unavailable/skipped bucket.
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
    TimedOut { explanation: String },
    SkippedDeadline { explanation: String },
    ThreatFoxFound { findings: Vec<ThreatFoxFinding> },
    UrlhausFound { details: UrlhausLookupDetails },
    Unsupported { explanation: String },
}

/// Bounded, provider-specific evidence returned by a URLhaus URL, host, or
/// payload lookup. Raw response JSON and download URLs are not retained.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UrlhausLookupDetails {
    pub reference: Option<String>,
    pub queried_host: Option<String>,
    pub associated_url_count: Option<usize>,
    pub md5_hash: Option<String>,
    pub sha256_hash: Option<String>,
    pub file_type: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub signature: Option<String>,
    pub associated_urls: Vec<UrlhausUrlRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct UrlhausUrlRecord {
    pub reference: Option<String>,
    pub url: String,
    pub status: Option<String>,
    pub host: Option<String>,
    pub date_added: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub threat: Option<String>,
    pub tags: Vec<String>,
}

/// Provider-neutral report data copied from ThreatFox's response at the workflow boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ThreatFoxFinding {
    pub source_record_id: Option<String>,
    pub ioc: String,
    pub ioc_type: String,
    pub ioc_type_description: Option<String>,
    pub threat_type: Option<String>,
    pub threat_type_description: Option<String>,
    pub malware: Option<String>,
    pub malware_printable: Option<String>,
    pub confidence_level: Option<u32>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub reference: Option<String>,
    pub reporter: Option<String>,
    pub tags: Vec<String>,
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
                source_occurrences: Vec::new(),
            },
            provider_lookups: lookups,
            summary,
            interpretation: vec![
                "FOUND means the provider returned a matching record; NOT FOUND means it returned no matching record.".into(),
                "The original-file lookup summary is FOUND if any provider finds a match, NOT FOUND only if every recorded provider reports no match, the shared status if all providers agree, and INCOMPLETE when non-positive provider statuses differ.".into(),
                "Extracted hash lookup counts count each provider outcome for extracted hashes; IP address and domain lookups are excluded.".into(),
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
            IndicatorType::Url => indicator_counts.urls += 1,
        }
    }
    let original_lookups = lookups
        .iter()
        .filter(|lookup| lookup.subject == LookupSubject::OriginalFileSha256)
        .collect::<Vec<_>>();
    let original_file_lookup_status = if original_lookups.is_empty() {
        None
    } else if original_lookups.iter().any(|lookup| {
        matches!(
            lookup.outcome,
            LookupOutcome::Found(_)
                | LookupOutcome::ThreatFoxFound { .. }
                | LookupOutcome::UrlhausFound { .. }
        )
    }) {
        Some("FOUND".into())
    } else if original_lookups
        .iter()
        .all(|lookup| matches!(lookup.outcome, LookupOutcome::NotFound))
    {
        Some("NOT FOUND".into())
    } else {
        let first_status = original_lookups[0].outcome.status();
        if original_lookups
            .iter()
            .all(|lookup| lookup.outcome.status() == first_status)
        {
            Some(first_status.to_string())
        } else {
            Some("INCOMPLETE".into())
        }
    };
    let mut lookup_counts = LookupCounts::default();
    for lookup in lookups.iter().filter(|lookup| match lookup.subject {
        LookupSubject::ExtractedIndicatorSha256 => true,
        LookupSubject::ExtractedIndicator => {
            crate::indicator::classify(
                &lookup.queried_hash,
                crate::indicator::EXTRACTED_HASH_LENGTHS,
            ) == Some(IndicatorType::Hash)
        }
        LookupSubject::OriginalFileSha256 => false,
    }) {
        match lookup.outcome {
            LookupOutcome::Found(_) => lookup_counts.found += 1,
            LookupOutcome::NotFound => lookup_counts.not_found += 1,
            LookupOutcome::Invalid { .. }
            | LookupOutcome::ApiError { .. }
            | LookupOutcome::RequestError { .. }
            | LookupOutcome::TimedOut { .. } => lookup_counts.failures += 1,
            LookupOutcome::NotConfigured
            | LookupOutcome::SkippedDuplicate { .. }
            | LookupOutcome::SkippedLookupLimit
            | LookupOutcome::SkippedDeadline { .. }
            | LookupOutcome::Unsupported { .. } => lookup_counts.skipped_or_unavailable += 1,
            LookupOutcome::ThreatFoxFound { .. } | LookupOutcome::UrlhausFound { .. } => {
                lookup_counts.found += 1
            }
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
            Self::TimedOut { .. } => "TIMED OUT",
            Self::SkippedDeadline { .. } => "SKIPPED: DEADLINE",
            Self::ThreatFoxFound { .. } => "FOUND",
            Self::UrlhausFound { .. } => "FOUND",
            Self::Unsupported { .. } => "UNSUPPORTED",
        }
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
