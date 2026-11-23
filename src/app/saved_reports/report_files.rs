//! Read-only discovery and schema validation for saved JSON reports.
use crate::report::{
    InvestigationReport, MAX_SAVED_REPORT_BYTES, SCHEMA_VERSION, SESSION_REPORT_TYPE, SessionCheck,
    SessionReport,
};
use serde_json::Value;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

pub(super) struct SavedReport {
    pub(super) path: PathBuf,
    pub(super) contents: SavedReportContents,
}

pub(super) enum SavedReportContents {
    File(Box<InvestigationReport>),
    Session(SessionReport),
}

impl SavedReportContents {
    pub(super) fn generated_at_unix_seconds(&self) -> u64 {
        match self {
            Self::File(report) => report.generated_at_unix_seconds,
            Self::Session(report) => report.generated_at_unix_seconds,
        }
    }

    pub(super) fn file_report(&self) -> Option<&InvestigationReport> {
        match self {
            Self::File(report) => Some(report.as_ref()),
            Self::Session(_) => None,
        }
    }

    pub(super) fn to_markdown(&self) -> String {
        match self {
            Self::File(report) => report.to_markdown(),
            Self::Session(report) => report.to_markdown(),
        }
    }
}

pub(super) struct ReportCollection<T> {
    pub(super) reports: Vec<T>,
    pub(super) unavailable: Vec<String>,
}

pub(super) struct ReportIndexEntry {
    pub(super) path: PathBuf,
    pub(super) timestamp: u64,
    pub(super) title: String,
    pub(super) description: String,
}

const MAX_DIRECTORY_ENTRIES: usize = 4096;
const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;

pub(super) fn index(directory: &Path) -> io::Result<ReportCollection<ReportIndexEntry>> {
    discover_with(
        directory,
        |saved| {
            let timestamp = saved.contents.generated_at_unix_seconds();
            let (title, description) = super::view::report_list_labels(&saved);
            ReportIndexEntry {
                path: saved.path,
                timestamp,
                title,
                description,
            }
        },
        |entry| entry.timestamp,
    )
}

pub(super) fn open_report(path: &Path) -> Result<SavedReport, String> {
    Ok(SavedReport {
        path: path.to_owned(),
        contents: load_one(path)?,
    })
}

impl ReportCollection<ReportIndexEntry> {
    pub(super) fn comparison_reports(&self) -> ReportCollection<SavedReport> {
        let mut bytes_left = MAX_ARCHIVE_BYTES;
        let mut collection = ReportCollection {
            reports: Vec::new(),
            unavailable: Vec::new(),
        };
        for entry in &self.reports {
            match load_with_budget(&entry.path, &mut bytes_left) {
                Ok(contents) => collection.reports.push(SavedReport {
                    path: entry.path.clone(),
                    contents,
                }),
                Err(error) => collection
                    .unavailable
                    .push(format!("{}: {error}", entry.path.display())),
            }
        }
        collection
    }
}

#[cfg(test)]
pub(super) fn discover(directory: &Path) -> io::Result<ReportCollection<SavedReport>> {
    discover_with(
        directory,
        |saved| saved,
        |saved| saved.contents.generated_at_unix_seconds(),
    )
}

/// Directory errors are separate from per-file errors so one damaged report
/// does not prevent valid neighboring reports from loading.
fn discover_with<T>(
    directory: &Path,
    project: impl Fn(SavedReport) -> T,
    timestamp: impl Fn(&T) -> u64,
) -> io::Result<ReportCollection<T>> {
    let entries = fs::read_dir(directory)?;
    let mut collection = ReportCollection {
        reports: Vec::new(),
        unavailable: Vec::new(),
    };
    let mut bytes_left = MAX_ARCHIVE_BYTES;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_DIRECTORY_ENTRIES || bytes_left == 0 {
            collection.unavailable.push("Archive scan limit reached. Move older reports to another directory to browse them.".into());
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                collection.unavailable.push(error.to_string());
                continue;
            }
        };
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        match entry.file_type() {
            Ok(file_type) if file_type.is_file() => {}
            Ok(_) => continue,
            Err(error) => {
                collection
                    .unavailable
                    .push(format!("{}: {error}", path.display()));
                continue;
            }
        }
        match load_with_budget(&path, &mut bytes_left) {
            Ok(contents) => collection
                .reports
                .push(project(SavedReport { path, contents })),
            Err(error) => collection
                .unavailable
                .push(format!("{}: {error}", path.display())),
        }
    }
    collection
        .reports
        .sort_by_key(|report| std::cmp::Reverse(timestamp(report)));
    Ok(collection)
}

fn load_one(path: &Path) -> Result<SavedReportContents, String> {
    load_with_budget(path, &mut (MAX_SAVED_REPORT_BYTES + 1))
}

fn load_with_budget(path: &Path, bytes_left: &mut u64) -> Result<SavedReportContents, String> {
    let (mut file, metadata) =
        crate::file::open_regular_file(path).map_err(|error| error.to_string())?;
    if metadata.len() > MAX_SAVED_REPORT_BYTES {
        return Err("report exceeds the 32 MiB saved-report size limit".into());
    }
    // Read one byte past the cap so growth after metadata() is detected while
    // allocation remains bounded.
    let limit = *bytes_left;
    if metadata.len() > limit {
        return Err("report exceeds the remaining archive scan budget".into());
    }
    let mut bytes = Vec::new();
    let read_result = file
        .by_ref()
        .take((MAX_SAVED_REPORT_BYTES + 1).min(limit.saturating_add(1)))
        .read_to_end(&mut bytes);
    *bytes_left = bytes_left.saturating_sub(bytes.len() as u64);
    read_result.map_err(|error| error.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("report exceeds the remaining archive scan budget".into());
    }
    let after = file.metadata().map_err(|error| error.to_string())?;
    crate::file::check_file_snapshot(&metadata, &after, bytes.len() as u64)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_SAVED_REPORT_BYTES {
        return Err("report exceeds the 32 MiB saved-report size limit".into());
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let version = value
        .get("schema_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing or invalid schema_version".to_string())?;
    if !(1..=u64::from(SCHEMA_VERSION)).contains(&version) {
        return Err(format!(
            "unsupported schema version {version}; this application supports {SCHEMA_VERSION}"
        ));
    }
    let is_session = value.get("report_type").and_then(Value::as_str) == Some(SESSION_REPORT_TYPE);
    if is_session {
        let mut report: SessionReport =
            serde_json::from_value(value).map_err(|error| error.to_string())?;
        if report.checks.is_empty() {
            return Err("session report contains no completed checks".into());
        }
        for check in &mut report.checks {
            if let SessionCheck::FileInvestigation { report } = check {
                if !(1..=SCHEMA_VERSION).contains(&report.schema_version) {
                    return Err("unsupported nested file report schema version".into());
                }
                report.upgrade_legacy();
            }
        }
        report.schema_version = SCHEMA_VERSION;
        return Ok(SavedReportContents::Session(report));
    }
    let mut report: InvestigationReport =
        serde_json::from_value(value).map_err(|error| error.to_string())?;
    // Earlier report schemas remain readable; the in-memory model uses the
    // current version while preserving the fields those versions contained.
    report.upgrade_legacy();
    Ok(SavedReportContents::File(Box::new(report)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::FileInfo;
    use crate::indicator::Indicator;
    use crate::investigation::Investigation;
    use crate::report::{LookupOutcome, LookupSubject, ProviderLookup, SessionCheck};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let id = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cyberfeed-report-files-{}-{id}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn report() -> InvestigationReport {
        let file = FileInfo {
            name: "evidence.bin".into(),
            size: 42,
            sha256: "file-sha".into(),
        };
        InvestigationReport::new(
            &file,
            vec![Indicator::new(
                "example.test",
                crate::indicator::IndicatorType::Domain,
            )],
            Some(true),
            vec![ProviderLookup {
                provider: "ExampleProvider".into(),
                subject: LookupSubject::OriginalFileSha256,
                queried_hash: "file-sha".into(),
                retrieved_at_unix_seconds: Some(9),
                outcome: LookupOutcome::NotFound,
            }],
        )
    }

    fn write_report(directory: &Path, name: &str, timestamp: u64) {
        let mut report = report();
        report.generated_at_unix_seconds = timestamp;
        fs::write(directory.join(name), serde_json::to_vec(&report).unwrap()).unwrap();
    }

    #[test]
    fn empty_and_missing_directories_are_handled() {
        let directory = TestDir::new();
        assert!(discover(&directory.0).unwrap().reports.is_empty());
        let missing = discover(&directory.0.join("missing"));
        assert!(matches!(missing, Err(error) if error.kind() == io::ErrorKind::NotFound));
    }

    #[test]
    fn loads_valid_report_and_preserves_findings() {
        let directory = TestDir::new();
        write_report(&directory.0, "report.json", 123);
        let collection = discover(&directory.0).unwrap();
        let loaded = collection.reports[0].contents.file_report().unwrap();
        assert_eq!(loaded.file.filename, "evidence.bin");
        assert_eq!(loaded.file.size_bytes, 42);
        assert_eq!(loaded.file.sha256, "file-sha");
        assert_eq!(loaded.local_inspection.indicators[0].value, "example.test");
        assert_eq!(
            loaded.summary.original_file_lookup_status.as_deref(),
            Some("NOT FOUND")
        );
    }

    #[test]
    fn report_saved_by_the_file_workflow_is_discoverable_with_its_evidence() {
        let directory = TestDir::new();
        let report = report();

        let (json_path, markdown_path) = crate::report::save_report(&report, &directory.0).unwrap();
        assert!(json_path.is_file());
        assert!(markdown_path.is_file());

        let collection = discover(&directory.0).unwrap();
        assert_eq!(collection.reports.len(), 1);
        assert!(collection.unavailable.is_empty());
        let reopened = collection.reports[0].contents.file_report().unwrap();
        assert_eq!(reopened.file.filename, "evidence.bin");
        assert_eq!(
            reopened.local_inspection.indicators[0].value,
            "example.test"
        );
        assert_eq!(reopened.provider_lookups.len(), 1);
        assert_eq!(reopened.provider_lookups[0].provider, "ExampleProvider");
        assert_eq!(
            reopened.provider_lookups[0].outcome,
            LookupOutcome::NotFound
        );
    }

    #[test]
    fn saved_session_report_reopens_with_file_and_independent_value_checks() {
        let directory = TestDir::new();
        let file_report = report();
        let mut investigation = Investigation::new();
        investigation.add_file_investigation(&file_report);
        investigation.add_indicator_lookup(
            Indicator::new("198.51.100.22", crate::indicator::IndicatorType::IP),
            &[
                ProviderLookup {
                    provider: "MalwareBazaar".into(),
                    subject: LookupSubject::ExtractedIndicator,
                    queried_hash: "198.51.100.22".into(),
                    retrieved_at_unix_seconds: None,
                    outcome: LookupOutcome::Unsupported {
                        explanation: "hash lookups only".into(),
                    },
                },
                ProviderLookup {
                    provider: "ThreatFox".into(),
                    subject: LookupSubject::ExtractedIndicator,
                    queried_hash: "198.51.100.22".into(),
                    retrieved_at_unix_seconds: Some(10),
                    outcome: LookupOutcome::ApiError {
                        explanation: "temporary test failure".into(),
                    },
                },
            ],
        );
        let session = investigation.session_report();

        let report_dir = directory.0.join("reports");
        let (json_path, markdown_path) =
            crate::report::save_session_report(&session, &report_dir).unwrap();
        let duplicate = crate::report::save_session_report(&session, &report_dir).unwrap();
        assert_ne!(json_path, duplicate.0);
        assert_ne!(markdown_path, duplicate.1);
        assert!(json_path.is_file());
        let markdown = fs::read_to_string(markdown_path).unwrap();
        assert!(markdown.contains("File investigation: `evidence.bin`"));
        assert!(markdown.contains("Indicator lookup"));
        assert!(markdown.contains("UNSUPPORTED"));
        assert!(markdown.contains("ERROR"));

        let collection = discover(&report_dir).unwrap();
        assert_eq!(collection.reports.len(), 2);
        assert!(collection.unavailable.is_empty());
        let SavedReportContents::Session(reopened) = &collection.reports[0].contents else {
            panic!("session JSON must be discovered as a session report");
        };
        assert_eq!(reopened.checks.len(), 2);
        assert!(matches!(
            &reopened.checks[0],
            SessionCheck::FileInvestigation { report }
                if report.file.sha256 == "file-sha"
                    && report.provider_lookups[0].outcome == LookupOutcome::NotFound
        ));
        assert!(matches!(
            &reopened.checks[1],
            SessionCheck::IndicatorLookup { indicator, provider_lookups }
                if indicator.value == "198.51.100.22"
                    && provider_lookups[0].outcome.status() == "UNSUPPORTED"
                    && provider_lookups[1].outcome.status() == "API ERROR"
        ));
    }

    #[test]
    fn individually_saved_indicator_check_is_discovered_and_reopened_with_outcomes() {
        let directory = TestDir::new();
        let indicator = Indicator::new("198.51.100.44", crate::indicator::IndicatorType::IP);
        let lookups = vec![
            ProviderLookup {
                provider: "MalwareBazaar".into(),
                subject: LookupSubject::ExtractedIndicator,
                queried_hash: indicator.value.clone(),
                retrieved_at_unix_seconds: None,
                outcome: LookupOutcome::Unsupported {
                    explanation: "IP lookups are unsupported".into(),
                },
            },
            ProviderLookup {
                provider: "ThreatFox".into(),
                subject: LookupSubject::ExtractedIndicator,
                queried_hash: indicator.value.clone(),
                retrieved_at_unix_seconds: None,
                outcome: LookupOutcome::NotConfigured,
            },
            ProviderLookup {
                provider: "URLhaus".into(),
                subject: LookupSubject::ExtractedIndicator,
                queried_hash: indicator.value.clone(),
                retrieved_at_unix_seconds: Some(11),
                outcome: LookupOutcome::ApiError {
                    explanation: "temporary provider error".into(),
                },
            },
            ProviderLookup {
                provider: "ExampleSource".into(),
                subject: LookupSubject::ExtractedIndicator,
                queried_hash: indicator.value.clone(),
                retrieved_at_unix_seconds: Some(12),
                outcome: LookupOutcome::NotFound,
            },
        ];
        let aggregate = crate::report::SessionReport::new(vec![
            SessionCheck::IndicatorLookup {
                indicator: indicator.clone(),
                provider_lookups: lookups.clone(),
            },
            SessionCheck::IndicatorLookup {
                indicator: Indicator::new("example.test", crate::indicator::IndicatorType::Domain),
                provider_lookups: vec![],
            },
            SessionCheck::IndicatorLookup {
                indicator: Indicator::new(
                    "another.example",
                    crate::indicator::IndicatorType::Domain,
                ),
                provider_lookups: vec![],
            },
        ]);
        crate::report::save_session_report(&aggregate, &directory.0).unwrap();
        let (individual_json, _) =
            crate::report::save_indicator_report(&indicator, &lookups, &directory.0).unwrap();
        assert!(
            individual_json
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("cyberfeed-indicator-IP-198_51_100_44-")
        );

        let found = discover(&directory.0).unwrap();

        assert_eq!(found.reports.len(), 2);
        assert!(found.unavailable.is_empty());
        let individual = found
            .reports
            .iter()
            .find(|saved| saved.path == individual_json)
            .expect("the individual report must be its own Saved Reports entry");
        let SavedReportContents::Session(reopened) = &individual.contents else {
            panic!("the saved indicator check must be recognized as a session report");
        };
        assert_eq!(reopened.checks.len(), 1);
        assert!(matches!(
            &reopened.checks[0],
            SessionCheck::IndicatorLookup { indicator, provider_lookups }
                if indicator.value == "198.51.100.44"
                    && provider_lookups[0].outcome.status() == "UNSUPPORTED"
                    && provider_lookups[1].outcome.status() == "NOT CONFIGURED"
                    && provider_lookups[2].outcome.status() == "API ERROR"
                    && provider_lookups[3].outcome.status() == "NOT FOUND"
        ));
    }

    #[test]
    fn empty_session_report_is_rejected_without_creating_report_files() {
        let directory = TestDir::new();
        let empty = crate::report::SessionReport::new(Vec::new());

        let error = crate::report::save_session_report(&empty, &directory.0).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);
    }

    #[test]
    fn session_report_write_failure_is_returned_without_replacing_the_target() {
        let directory = TestDir::new();
        let target = directory.0.join("reports-is-a-file");
        fs::write(&target, b"preserve this file").unwrap();
        let mut investigation = Investigation::new();
        investigation.add_indicator_lookup(
            Indicator::new("example.test", crate::indicator::IndicatorType::Domain),
            &[],
        );
        let session = investigation.session_report();

        assert!(crate::report::save_session_report(&session, &target).is_err());
        assert_eq!(fs::read(target).unwrap(), b"preserve this file");
    }

    #[test]
    fn sorts_valid_reports_by_generation_time() {
        let directory = TestDir::new();
        write_report(&directory.0, "z-old.json", 1);
        write_report(&directory.0, "a-new.json", 20);
        let collection = discover(&directory.0).unwrap();
        assert_eq!(
            collection.reports[0].contents.generated_at_unix_seconds(),
            20
        );
        assert_eq!(
            collection.reports[1].contents.generated_at_unix_seconds(),
            1
        );
    }

    #[test]
    fn skips_malformed_and_unsupported_reports_but_keeps_valid_reports() {
        let directory = TestDir::new();
        write_report(&directory.0, "good.json", 1);
        fs::write(directory.0.join("bad.json"), b"{").unwrap();
        let mut unsupported = report();
        unsupported.schema_version += 1;
        fs::write(
            directory.0.join("future.json"),
            serde_json::to_vec(&unsupported).unwrap(),
        )
        .unwrap();
        let collection = discover(&directory.0).unwrap();
        assert_eq!(collection.reports.len(), 1);
        assert_eq!(collection.unavailable.len(), 2);
        assert!(
            collection
                .unavailable
                .iter()
                .any(|error| error.contains("unsupported schema version"))
        );
    }

    #[test]
    fn ignores_non_json_files() {
        let directory = TestDir::new();
        write_report(&directory.0, "report.json", 1);
        fs::write(directory.0.join("report.md"), "not JSON").unwrap();
        let collection = discover(&directory.0).unwrap();
        assert_eq!(collection.reports.len(), 1);
        assert!(collection.unavailable.is_empty());
    }

    #[test]
    fn genuine_version_one_report_loads_and_upgrades_in_memory() {
        let directory = TestDir::new();
        // This fixture uses the v1 enums from the historical model: no generic
        // extracted-indicator subject and no ThreatFox-specific outcomes.
        let legacy = r#"{
          "schema_version": 1,
          "generated_at_unix_seconds": 77,
          "file": {"filename":"legacy.bin","size_bytes":12,"sha256":"legacy-sha","inspected_locally_not_executed_or_uploaded":true},
          "local_inspection": {"text_extraction":{"status":"PERFORMED","limit_reached":false},"indicators":[{"value":"legacy.test","indicator_type":"DOMAIN"}]},
          "provider_lookups": [{"provider":"MalwareBazaar","subject":"ORIGINAL_FILE_SHA256","queried_hash":"legacy-sha","retrieved_at_unix_seconds":7,"outcome":{"status":"NOT_FOUND"}}],
          "summary": {"original_file_lookup_status":"NOT FOUND","extracted_indicator_counts":{"hashes":0,"ip_addresses":0,"domains":1},"extracted_hash_lookup_counts":{"found":0,"not_found":0,"failures":0,"skipped_or_unavailable":0},"extraction_limit_reached":false},
          "interpretation": ["legacy note"]
        }"#;
        fs::write(directory.0.join("legacy.json"), legacy).unwrap();
        let loaded = discover(&directory.0).unwrap();
        assert_eq!(loaded.reports.len(), 1);
        let report = loaded.reports[0].contents.file_report().unwrap();
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.generated_at_unix_seconds, 77);
        assert_eq!(report.file.sha256, "legacy-sha");
        assert_eq!(report.local_inspection.indicators[0].value, "legacy.test");
        assert_eq!(report.interpretation, ["legacy note"]);
    }

    #[test]
    fn version_two_report_shape_loads_and_adds_default_url_count_in_memory() {
        let directory = TestDir::new();
        let mut legacy = serde_json::to_value(report()).unwrap();
        legacy["schema_version"] = serde_json::json!(2);
        legacy["summary"]["extracted_indicator_counts"]
            .as_object_mut()
            .unwrap()
            .remove("urls");
        fs::write(
            directory.0.join("v2.json"),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        let loaded = discover(&directory.0).unwrap();
        assert_eq!(loaded.reports.len(), 1);
        let report = loaded.reports[0].contents.file_report().unwrap();
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.file.sha256, "file-sha");
        assert_eq!(report.summary.extracted_indicator_counts.urls, 0);
    }

    #[test]
    fn version_four_report_loads_after_deadline_outcomes_are_added() {
        let directory = TestDir::new();
        let mut legacy = serde_json::to_value(report()).unwrap();
        legacy["schema_version"] = serde_json::json!(4);
        fs::write(
            directory.0.join("v4.json"),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        let loaded = discover(&directory.0).unwrap();
        assert_eq!(loaded.reports.len(), 1);
        let report = loaded.reports[0].contents.file_report().unwrap();
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.file.sha256, "file-sha");
    }

    #[test]
    fn legacy_truncated_identity_survives_schema_upgrade_and_blocks_export() {
        let dir = TestDir::new();
        let mut old = report();
        old.schema_version = 5;
        old.provider_lookups.clear();
        fs::write(
            dir.0.join("legacy-log.json"),
            serde_json::to_vec(&old).unwrap(),
        )
        .unwrap();
        let saved = open_report(&dir.0.join("legacy-log.json")).unwrap();
        let loaded = saved.contents.file_report().unwrap();
        assert_eq!(loaded.schema_version, SCHEMA_VERSION);
        assert!(loaded.identity_incomplete());
        assert!(loaded.to_markdown().contains("incomplete file identity"));
        assert_eq!(crate::report::stix_indicator_count(loaded), 0);
        assert!(crate::report::save_stix_bundle(loaded, &dir.0.join("stix")).is_err());
        assert!(!super::super::comparison::compare(loaded, loaded).same_subject);
        old.schema_version = SCHEMA_VERSION;
        assert!(!old.identity_incomplete());
    }

    #[test]
    fn index_keeps_metadata_and_only_reopens_selected_report() {
        let dir = TestDir::new();
        write_report(&dir.0, "older.json", 1);
        write_report(&dir.0, "newer.json", 2);
        fs::write(dir.0.join("broken.json"), b"{").unwrap();
        let indexed = index(&dir.0).unwrap();
        assert_eq!(indexed.reports.len(), 2);
        assert_eq!(indexed.unavailable.len(), 1);
        assert_eq!(indexed.reports[0].timestamp, 2);
        fs::remove_file(&indexed.reports[1].path).unwrap();
        assert_eq!(indexed.reports[1].timestamp, 1);
        assert!(open_report(&indexed.reports[0].path).is_ok());
        let loaded = indexed.comparison_reports();
        assert_eq!(loaded.reports.len(), 1);
        assert_eq!(loaded.unavailable.len(), 1);
        let mut tiny_budget = 1;
        assert!(load_with_budget(&indexed.reports[0].path, &mut tiny_budget).is_err());
        assert_eq!(tiny_budget, 1);
    }

    #[test]
    fn rejects_oversized_report_but_keeps_valid_neighbor() {
        let directory = TestDir::new();
        write_report(&directory.0, "valid.json", 1);
        fs::write(
            directory.0.join("large.json"),
            vec![b' '; MAX_SAVED_REPORT_BYTES as usize + 1],
        )
        .unwrap();
        let collection = discover(&directory.0).unwrap();
        assert_eq!(collection.reports.len(), 1);
        assert_eq!(
            collection.reports[0].contents.generated_at_unix_seconds(),
            1
        );
        assert!(
            collection
                .unavailable
                .iter()
                .any(|error| error.contains("32 MiB saved-report size limit"))
        );
    }
}
