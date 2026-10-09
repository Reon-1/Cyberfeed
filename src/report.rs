use crate::file::FileInfo;
use crate::indicator::{Indicator, IndicatorType};
use crate::malwarebazaar::{MalwareLookupError, MalwareLookupResult, MalwareSample};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCHEMA_VERSION: u32 = 1;
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "status",
    content = "details",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
                "Cloudflare Radar statistics concern general network telemetry and are not evidence about an individual file.".into(),
            ],
        }
    }

    pub fn to_markdown(&self) -> String {
        let mut out =
            String::from("# CyberFeed Investigation Report\n\n## Investigation summary\n\n");
        out.push_str(&format!("- File: `{}` ({} bytes)\n- Original file SHA-256: `{}`\n- Original file lookup: {}\n- Extracted indicators: {} hashes, {} IP addresses, {} domains\n- Extracted hash lookups: {} found, {} not found, {} failed, {} skipped or unavailable\n- Extraction limit reached: {}\n- Generated at: {} seconds since the Unix epoch (UTC)\n\nCyberFeed read the file locally as data; it did not execute or upload it.\n\n", md_code(&self.file.filename), self.file.size_bytes, md_code(&self.file.sha256), self.summary.original_file_lookup_status.as_deref().unwrap_or("not recorded"), self.summary.extracted_indicator_counts.hashes, self.summary.extracted_indicator_counts.ip_addresses, self.summary.extracted_indicator_counts.domains, self.summary.extracted_hash_lookup_counts.found, self.summary.extracted_hash_lookup_counts.not_found, self.summary.extracted_hash_lookup_counts.failures, self.summary.extracted_hash_lookup_counts.skipped_or_unavailable, self.summary.extraction_limit_reached, self.generated_at_unix_seconds));
        out.push_str("## File details\n\n");
        out.push_str(&format!(
            "- Size: {} bytes\n\n## Local inspection findings\n\n",
            self.file.size_bytes
        ));
        match self.local_inspection.text_extraction {
            TextExtraction::Performed { limit_reached } => out.push_str(&format!("Readable-text extraction was performed. Extraction limit reached: **{}**.\n\n", limit_reached)),
            TextExtraction::SkippedBinaryOrNonText => out.push_str("Readable-text extraction was skipped because the content was binary or non-text.\n\n"),
        }
        out.push_str("## Extracted indicators\n\n");
        if self.local_inspection.indicators.is_empty() {
            out.push_str("No indicators were extracted.\n\n");
        } else {
            out.push_str("| Type | Value |\n|---|---|\n");
            for i in &self.local_inspection.indicators {
                out.push_str(&format!(
                    "| {} | `{}` |\n",
                    i.indicator_type.as_str(),
                    md_code(&i.value)
                ));
            }
            out.push('\n');
        }
        out.push_str("## Original file hash lookup\n\n");
        let originals = self
            .provider_lookups
            .iter()
            .filter(|lookup| lookup.subject == LookupSubject::OriginalFileSha256)
            .collect::<Vec<_>>();
        if originals.is_empty() {
            out.push_str("No provider lookup was recorded for the original file SHA-256.\n\n");
        }
        for lookup in originals {
            render_lookup(&mut out, lookup);
        }

        out.push_str("## Extracted indicator hash lookups\n\n");
        let extracted = self
            .provider_lookups
            .iter()
            .filter(|lookup| lookup.subject == LookupSubject::ExtractedIndicatorSha256)
            .collect::<Vec<_>>();
        if extracted.is_empty() {
            out.push_str("No extracted SHA-256 indicators were queried. Extracted IP addresses and domains are not enriched by a connected provider.\n\n");
        }
        for lookup in extracted {
            render_lookup(&mut out, lookup);
        }
        out.push_str("## Interpretation and limitations\n\n");
        for line in &self.interpretation {
            out.push_str(&format!("- {}\n", md_plain(line)));
        }
        out
    }
}

fn render_lookup(out: &mut String, lookup: &ProviderLookup) {
    out.push_str(&format!(
        "### {} — {}\n\nQueried hash: `{}`\n\n",
        md_plain(&lookup.provider),
        lookup.outcome.status(),
        md_code(&lookup.queried_hash)
    ));
    if let Some(timestamp) = lookup.retrieved_at_unix_seconds {
        out.push_str(&format!(
            "Retrieved at: {} seconds since the Unix epoch (UTC).\n\n",
            timestamp
        ));
    }
    match &lookup.outcome {
            LookupOutcome::Found(m) => out.push_str(&format!("- Matched SHA-256: `{}`\n- First seen: {}\n- File type: {}\n- Sample filename: {}\n- Signature: {}\n\n", md_code(&m.matched_sha256), md_plain(&m.first_seen), md_plain(&m.file_type), m.sample_filename.as_deref().map(md_plain).unwrap_or_else(|| "Not provided".into()), m.signature.as_deref().map(md_plain).unwrap_or_else(|| "Not provided".into()))),
            LookupOutcome::Invalid { explanation } | LookupOutcome::ApiError { explanation } | LookupOutcome::RequestError { explanation } => out.push_str(&format!("{}\n\n", md_plain(explanation))),
            LookupOutcome::SkippedDuplicate { references_hash } => out.push_str(&format!("Reuses the earlier result for `{}`; no second request was made.\n\n", md_code(references_hash))),
                LookupOutcome::NotFound => out.push_str("MalwareBazaar returned no matching record. This does not establish that the file is safe.\n\n"),
                LookupOutcome::NotConfigured => out.push_str("The MalwareBazaar credential is not configured, so no request was made.\n\n"),
                LookupOutcome::SkippedLookupLimit => out.push_str("No request was made because the automatic lookup limit was reached.\n\n"),
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

pub fn outcome_from_result(
    result: Result<MalwareLookupResult, MalwareLookupError>,
) -> LookupOutcome {
    match result {
        Ok(MalwareLookupResult::Found(sample)) => LookupOutcome::Found(sample_details(sample)),
        Ok(MalwareLookupResult::NotFound) => LookupOutcome::NotFound,
        Ok(MalwareLookupResult::InvalidHash(s)) => LookupOutcome::Invalid { explanation: s },
        Ok(MalwareLookupResult::ApiError(s)) => LookupOutcome::ApiError { explanation: s },
        Err(MalwareLookupError::Request(s)) => LookupOutcome::RequestError {
            explanation: sanitize_error(s),
        },
        Err(MalwareLookupError::Http { status, .. }) => LookupOutcome::ApiError {
            explanation: format!("MalwareBazaar returned HTTP {status}."),
        },
        Err(MalwareLookupError::Parse(s)) => LookupOutcome::ApiError {
            explanation: format!("Could not parse MalwareBazaar response: {s}"),
        },
    }
}
fn sample_details(s: MalwareSample) -> MatchDetails {
    MatchDetails {
        matched_sha256: s.sha256_hash,
        first_seen: s.first_seen,
        file_type: s.file_type,
        sample_filename: (!s.file_name.is_empty()).then_some(s.file_name),
        signature: s.signature,
    }
}
fn sanitize_error(s: String) -> String {
    s.replace(['\n', '\r'], " ")
}
fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn md_code(s: &str) -> String {
    let mut safe = String::new();
    for c in s.chars() {
        match c {
            c if c.is_control() => safe.push(' '),
            '`' => safe.push('\''),
            '|' => safe.push_str("\\|"),
            _ => safe.push(c),
        }
    }
    safe
}
fn md_plain(s: &str) -> String {
    let mut safe = String::new();
    for c in s.chars() {
        if c.is_control() {
            safe.push(' ');
        } else {
            if matches!(c, '\\' | '#' | '*' | '_' | '[' | ']' | '>' | '`') {
                safe.push('\\');
            }
            safe.push(c);
        }
    }
    safe
}

pub fn save_report(
    report: &InvestigationReport,
    directory: &Path,
) -> std::io::Result<(PathBuf, PathBuf)> {
    fs::create_dir_all(directory)?;
    let stem = safe_stem(&report.file.filename);
    for suffix in 0u32.. {
        let extra = if suffix == 0 {
            String::new()
        } else {
            format!("-{suffix}")
        };
        let base = format!(
            "cyberfeed-{stem}-{}{}",
            report.generated_at_unix_seconds, extra
        );
        let json = directory.join(format!("{base}.json"));
        let md = directory.join(format!("{base}.md"));
        let jf = match exclusive(&json) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        let mf = match exclusive(&md) {
            Ok(file) => file,
            Err(error) => {
                drop(jf);
                let _ = fs::remove_file(&json);
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    continue;
                }
                return Err(error);
            }
        };
        let (json_tmp, json_temp_file) = match create_temp_file(directory, &base, "json") {
            Ok(temp) => temp,
            Err(error) => {
                let _ = fs::remove_file(&json);
                let _ = fs::remove_file(&md);
                return Err(error);
            }
        };
        let (md_tmp, md_temp_file) = match create_temp_file(directory, &base, "md") {
            Ok(temp) => temp,
            Err(error) => {
                drop(json_temp_file);
                let _ = fs::remove_file(&json_tmp);
                let _ = fs::remove_file(&json);
                let _ = fs::remove_file(&md);
                return Err(error);
            }
        };
        let result = write_pair(
            report,
            (json_tmp.clone(), json_temp_file),
            (md_tmp.clone(), md_temp_file),
            ((json.clone(), jf), (md.clone(), mf)),
        );
        if let Err(error) = result {
            let _ = fs::remove_file(&json);
            let _ = fs::remove_file(&md);
            let _ = fs::remove_file(&json_tmp);
            let _ = fs::remove_file(&md_tmp);
            return Err(error);
        }
        return Ok((json, md));
    }
    unreachable!()
}
fn exclusive(path: &Path) -> std::io::Result<fs::File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}
fn create_temp_file(
    directory: &Path,
    base: &str,
    extension: &str,
) -> std::io::Result<(PathBuf, fs::File)> {
    loop {
        let id = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(
            ".{base}-{}-{id}.{extension}.tmp",
            std::process::id()
        ));
        match exclusive(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
}
fn write_pair(
    report: &InvestigationReport,
    (json_tmp, mut jf): (PathBuf, fs::File),
    (md_tmp, mut mf): (PathBuf, fs::File),
    ((json_path, _json_reservation), (md_path, _md_reservation)): (
        (PathBuf, fs::File),
        (PathBuf, fs::File),
    ),
) -> std::io::Result<()> {
    serde_json::to_writer_pretty(&mut jf, report).map_err(std::io::Error::other)?;
    jf.write_all(b"\n")?;
    mf.write_all(report.to_markdown().as_bytes())?;
    jf.sync_all()?;
    mf.sync_all()?;
    drop(jf);
    drop(mf);
    fs::rename(json_tmp, json_path)?;
    fs::rename(md_tmp, md_path)
}
fn safe_stem(filename: &str) -> String {
    let stem = Path::new(filename)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let s: String = stem
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(48)
        .collect();
    if s.is_empty() { "file".into() } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indicator::IndicatorType;
    #[test]
    fn report_round_trips_and_has_versioned_metadata() {
        let f = FileInfo {
            name: "x".into(),
            size: 1,
            sha256: "abc".into(),
        };
        let r = InvestigationReport::new(&f, vec![], Some(false), vec![]);
        let j = serde_json::to_string(&r).unwrap();
        let back: InvestigationReport = serde_json::from_str(&j).unwrap();
        assert_eq!(back.schema_version, 1);
        assert_eq!(back.file.filename, "x");
        assert!(back.file.inspected_locally_not_executed_or_uploaded);
    }
    #[test]
    fn markdown_escapes_untrusted_values() {
        let f = FileInfo {
            name: "evil|`\nname.txt".into(),
            size: 1,
            sha256: "x".into(),
        };
        let r = InvestigationReport::new(
            &f,
            vec![Indicator::new("x|y\n`", IndicatorType::Domain)],
            Some(false),
            vec![],
        );
        let md = r.to_markdown();
        assert!(!md.contains("evil|`\n"));
        assert!(md.contains("x\\|y"));
    }
    #[test]
    fn saves_both_files_without_overwrite() {
        let dir = std::env::temp_dir().join(format!("cyberfeed-report-{}", std::process::id()));
        let f = FileInfo {
            name: "sample.bin".into(),
            size: 0,
            sha256: "abc".into(),
        };
        let r = InvestigationReport::new(&f, vec![], None, vec![]);
        let a = save_report(&r, &dir).unwrap();
        let b = save_report(&r, &dir).unwrap();
        assert_ne!(a, b);
        let json: InvestigationReport = serde_json::from_slice(&fs::read(&a.0).unwrap()).unwrap();
        assert_eq!(json.schema_version, SCHEMA_VERSION);
        let markdown = fs::read_to_string(&a.1).unwrap();
        assert!(markdown.starts_with("# CyberFeed Investigation Report"));
        assert!(markdown.contains("## Investigation summary"));
        let original_json = fs::read(&a.0).unwrap();
        let _second = save_report(&r, &dir).unwrap();
        assert_eq!(fs::read(&a.0).unwrap(), original_json);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn output_directory_failure_preserves_the_existing_file() {
        let path = std::env::temp_dir().join(format!(
            "cyberfeed-report-output-file-{}",
            std::process::id()
        ));
        fs::write(&path, b"keep me").unwrap();
        let file = FileInfo {
            name: "sample".into(),
            size: 0,
            sha256: "abc".into(),
        };
        let report = InvestigationReport::new(&file, vec![], None, vec![]);
        assert!(save_report(&report, &path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"keep me");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn summary_separates_original_file_from_extracted_hash_lookup_counts() {
        let file = FileInfo {
            name: "sample.bin".into(),
            size: 10,
            sha256: "file-hash".into(),
        };
        let indicators = vec![
            Indicator::new("embedded-hash", IndicatorType::Hash),
            Indicator::new("192.0.2.1", IndicatorType::IP),
            Indicator::new("example.test", IndicatorType::Domain),
        ];
        let lookups = vec![
            ProviderLookup {
                provider: "MalwareBazaar".into(),
                subject: LookupSubject::OriginalFileSha256,
                queried_hash: "file-hash".into(),
                retrieved_at_unix_seconds: Some(1),
                outcome: LookupOutcome::NotFound,
            },
            ProviderLookup {
                provider: "MalwareBazaar".into(),
                subject: LookupSubject::ExtractedIndicatorSha256,
                queried_hash: "embedded-hash".into(),
                retrieved_at_unix_seconds: Some(1),
                outcome: LookupOutcome::Found(MatchDetails {
                    matched_sha256: "embedded-hash".into(),
                    first_seen: "today".into(),
                    file_type: "exe".into(),
                    sample_filename: None,
                    signature: None,
                }),
            },
            ProviderLookup {
                provider: "MalwareBazaar".into(),
                subject: LookupSubject::ExtractedIndicatorSha256,
                queried_hash: "another-hash".into(),
                retrieved_at_unix_seconds: None,
                outcome: LookupOutcome::SkippedLookupLimit,
            },
        ];
        let report = InvestigationReport::new(&file, indicators, Some(true), lookups);
        assert_eq!(
            report.summary.original_file_lookup_status.as_deref(),
            Some("NOT FOUND")
        );
        assert_eq!(report.summary.extracted_indicator_counts.hashes, 1);
        assert_eq!(report.summary.extracted_indicator_counts.ip_addresses, 1);
        assert_eq!(report.summary.extracted_indicator_counts.domains, 1);
        assert_eq!(report.summary.extracted_hash_lookup_counts.found, 1);
        assert_eq!(report.summary.extracted_hash_lookup_counts.not_found, 0);
        assert_eq!(
            report
                .summary
                .extracted_hash_lookup_counts
                .skipped_or_unavailable,
            1
        );
        assert!(
            report
                .to_markdown()
                .contains("Original file lookup: NOT FOUND")
        );
        assert!(report.to_markdown().contains("1 found, 0 not found"));
    }

    #[test]
    fn every_lookup_state_has_a_stable_markdown_label() {
        let outcomes = [
            LookupOutcome::Found(MatchDetails {
                matched_sha256: "abc".into(),
                first_seen: "today".into(),
                file_type: "exe".into(),
                sample_filename: None,
                signature: None,
            }),
            LookupOutcome::NotFound,
            LookupOutcome::Invalid {
                explanation: "invalid".into(),
            },
            LookupOutcome::ApiError {
                explanation: "api".into(),
            },
            LookupOutcome::RequestError {
                explanation: "request".into(),
            },
            LookupOutcome::NotConfigured,
            LookupOutcome::SkippedDuplicate {
                references_hash: "abc".into(),
            },
            LookupOutcome::SkippedLookupLimit,
        ];
        let expected = [
            "FOUND",
            "NOT FOUND",
            "INVALID",
            "API ERROR",
            "REQUEST ERROR",
            "NOT CONFIGURED",
            "SKIPPED: DUPLICATE",
            "SKIPPED: LOOKUP LIMIT",
        ];
        for (outcome, label) in outcomes.into_iter().zip(expected) {
            assert_eq!(outcome.status(), label);
            let f = FileInfo {
                name: "sample".into(),
                size: 0,
                sha256: "abc".into(),
            };
            let lookup = ProviderLookup {
                provider: "MalwareBazaar".into(),
                subject: LookupSubject::ExtractedIndicatorSha256,
                queried_hash: "abc".into(),
                retrieved_at_unix_seconds: None,
                outcome,
            };
            let report = InvestigationReport::new(&f, vec![], None, vec![lookup]);
            assert!(report.to_markdown().contains(label));
        }
    }

    #[test]
    fn reports_do_not_include_authentication_material() {
        let f = FileInfo {
            name: "sample".into(),
            size: 0,
            sha256: "abc".into(),
        };
        let r = InvestigationReport::new(
            &f,
            vec![],
            None,
            vec![ProviderLookup {
                provider: "MalwareBazaar".into(),
                subject: LookupSubject::OriginalFileSha256,
                queried_hash: "abc".into(),
                retrieved_at_unix_seconds: None,
                outcome: LookupOutcome::NotConfigured,
            }],
        );
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("auth_key"));
        assert!(!json.contains("Auth-Key"));
        assert!(!json.contains("MALWAREBAZAAR_AUTH_KEY"));
    }
}
