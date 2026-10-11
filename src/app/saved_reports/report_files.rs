//! Read-only discovery and schema validation for saved JSON reports.
use crate::report::{InvestigationReport, SCHEMA_VERSION};
use serde_json::Value;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub(super) struct SavedReport {
    pub(super) path: PathBuf,
    pub(super) report: InvestigationReport,
}

pub(super) struct ReportCollection {
    pub(super) reports: Vec<SavedReport>,
    pub(super) unavailable: Vec<String>,
}

/// Directory errors are separate from per-file errors so one damaged report
/// does not prevent valid neighboring reports from loading.
pub(super) fn discover(directory: &Path) -> io::Result<ReportCollection> {
    let entries = fs::read_dir(directory)?;
    let mut collection = ReportCollection {
        reports: Vec::new(),
        unavailable: Vec::new(),
    };
    for entry in entries {
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
        match load_one(&path) {
            Ok(report) => collection.reports.push(SavedReport { path, report }),
            Err(error) => collection
                .unavailable
                .push(format!("{}: {error}", path.display())),
        }
    }
    collection.reports.sort_by(|left, right| {
        right
            .report
            .generated_at_unix_seconds
            .cmp(&left.report.generated_at_unix_seconds)
    });
    Ok(collection)
}

fn load_one(path: &Path) -> Result<InvestigationReport, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let version = value
        .get("schema_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing or invalid schema_version".to_string())?;
    if version != 1 && version != u64::from(SCHEMA_VERSION) {
        return Err(format!(
            "unsupported schema version {version}; this application supports {SCHEMA_VERSION}"
        ));
    }
    let mut report: InvestigationReport =
        serde_json::from_value(value).map_err(|error| error.to_string())?;
    // Version 2 adds typed provider outcomes and subjects; version-1 fields
    // retain their meaning, so upgrade only the in-memory snapshot on load.
    if version == 1 {
        report.schema_version = SCHEMA_VERSION;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::FileInfo;
    use crate::indicator::Indicator;
    use crate::report::{LookupOutcome, LookupSubject, ProviderLookup};
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
        let loaded = &collection.reports[0].report;
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
    fn sorts_valid_reports_by_generation_time() {
        let directory = TestDir::new();
        write_report(&directory.0, "z-old.json", 1);
        write_report(&directory.0, "a-new.json", 20);
        let collection = discover(&directory.0).unwrap();
        assert_eq!(collection.reports[0].report.generated_at_unix_seconds, 20);
        assert_eq!(collection.reports[1].report.generated_at_unix_seconds, 1);
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
    fn version_one_reports_load_and_upgrade_in_memory() {
        let directory = TestDir::new();
        let mut old = report();
        old.schema_version = 1;
        fs::write(
            directory.0.join("legacy.json"),
            serde_json::to_vec(&old).unwrap(),
        )
        .unwrap();
        let loaded = discover(&directory.0).unwrap();
        assert_eq!(loaded.reports.len(), 1);
        assert_eq!(loaded.reports[0].report.schema_version, SCHEMA_VERSION);
    }
}
