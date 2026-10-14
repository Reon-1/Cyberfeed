use super::model::InvestigationReport;
use crate::indicator::{Indicator, IndicatorType};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);
const MAX_STIX_UNIX_SECONDS: u64 = 253_402_300_799; // 9999-12-31T23:59:59Z

/// Build a STIX 2.1 bundle of locally observed supported indicators.
/// Provider descriptions are deliberately excluded: a report indicator is not
/// itself a claim that a file is malicious.
pub fn stix_bundle(report: &InvestigationReport) -> Value {
    let objects: Vec<Value> = report
        .local_inspection
        .indicators
        .iter()
        .filter_map(|indicator| {
            stix_indicator(
                indicator,
                report.generated_at_unix_seconds,
                &report.file.sha256,
            )
        })
        .collect();
    json!({"type":"bundle", "id": format!("bundle--{}", Uuid::new_v4()), "objects":objects})
}

pub fn stix_indicator_count(report: &InvestigationReport) -> usize {
    report
        .local_inspection
        .indicators
        .iter()
        .filter(|indicator| {
            stix_indicator(
                indicator,
                report.generated_at_unix_seconds,
                &report.file.sha256,
            )
            .is_some()
        })
        .count()
}

fn stix_indicator(indicator: &Indicator, timestamp: u64, report_sha256: &str) -> Option<Value> {
    if crate::indicator::classify(&indicator.value, crate::indicator::MANUAL_HASH_LENGTHS)
        != Some(indicator.indicator_type)
    {
        return None;
    }
    let (pattern, kind) = match indicator.indicator_type {
        IndicatorType::IP if indicator.value.parse::<std::net::Ipv4Addr>().is_ok() => (
            format!("[ipv4-addr:value = '{}']", escape(&indicator.value)),
            "ipv4-addr",
        ),
        IndicatorType::IP if indicator.value.parse::<std::net::Ipv6Addr>().is_ok() => (
            format!("[ipv6-addr:value = '{}']", escape(&indicator.value)),
            "ipv6-addr",
        ),
        IndicatorType::Domain => (
            format!("[domain-name:value = '{}']", escape(&indicator.value)),
            "domain-name",
        ),
        IndicatorType::Url => (
            format!("[url:value = '{}']", escape(&indicator.value)),
            "url",
        ),
        IndicatorType::Hash => match indicator.value.len() {
            32 => (
                format!("[file:hashes.'MD5' = '{}']", escape(&indicator.value)),
                "file",
            ),
            40 => (
                format!("[file:hashes.'SHA-1' = '{}']", escape(&indicator.value)),
                "file",
            ),
            64 => (
                format!("[file:hashes.'SHA-256' = '{}']", escape(&indicator.value)),
                "file",
            ),
            _ => return None,
        },
        IndicatorType::IP => return None,
    };
    let timestamp = format_timestamp(timestamp);
    Some(
        json!({"type":"indicator", "spec_version":"2.1", "id":format!("indicator--{}", Uuid::new_v4()), "created":timestamp, "modified":timestamp, "name":format!("CyberFeed observed {kind} indicator"), "description":"Indicator extracted locally from an investigated artifact. This is not a verdict about that artifact.", "indicator_types":["unknown"], "pattern":pattern, "pattern_type":"stix", "valid_from":timestamp, "external_references":[{"source_name":"CyberFeed local investigation", "external_id":report_sha256, "description":"Source report SHA-256 identifier; this indicator is an observation, not a file verdict."}]}),
    )
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}
fn format_timestamp(seconds: u64) -> String {
    // STIX requires RFC3339. UTC conversion without another dependency.
    let days = seconds / 86400;
    let day_seconds = seconds % 86400;
    let (year, month, day) = civil_from_days(days as i64);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        day_seconds / 3600,
        (day_seconds % 3600) / 60,
        day_seconds % 60
    )
}
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    if m <= 2 {
        y += 1;
    }
    (y, m, d)
}

pub fn save_stix_bundle(
    report: &InvestigationReport,
    directory: &Path,
) -> std::io::Result<PathBuf> {
    if report.generated_at_unix_seconds > MAX_STIX_UNIX_SECONDS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "report timestamp is outside the STIX RFC3339 date range",
        ));
    }
    fs::create_dir_all(directory)?;
    let base = format!(
        "cyberfeed-{}-{}.stix.json",
        safe(&report.file.filename),
        report.generated_at_unix_seconds
    );
    let (temp_path, mut file) = create_temp_file(directory, &base)?;
    let write_result = serde_json::to_writer_pretty(&mut file, &stix_bundle(report))
        .map_err(std::io::Error::other)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = write_result {
        return Err(cleanup_temp(error, &temp_path));
    }

    let mut suffix = 0u64;
    loop {
        let extra = if suffix == 0 {
            String::new()
        } else {
            format!("-{suffix}")
        };
        let path = directory.join(format!(
            "cyberfeed-{}-{}{extra}.stix.json",
            safe(&report.file.filename),
            report.generated_at_unix_seconds
        ));
        match fs::hard_link(&temp_path, &path) {
            Ok(()) => {
                if let Err(error) = fs::remove_file(&temp_path) {
                    eprintln!(
                        "STIX bundle saved to '{}', but temporary file '{}' could not be removed: {error}",
                        path.display(),
                        temp_path.display()
                    );
                }
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                suffix = suffix.checked_add(1).ok_or_else(|| {
                    cleanup_temp(
                        std::io::Error::other("STIX export filename suffix space exhausted"),
                        &temp_path,
                    )
                })?;
            }
            Err(error) => return Err(cleanup_temp(error, &temp_path)),
        }
    }
}

fn create_temp_file(directory: &Path, base: &str) -> std::io::Result<(PathBuf, File)> {
    loop {
        let id = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(".{base}-{}-{id}.stix.tmp", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
}

fn cleanup_temp(error: std::io::Error, path: &Path) -> std::io::Error {
    match fs::remove_file(path) {
        Ok(()) => error,
        Err(cleanup) if cleanup.kind() == std::io::ErrorKind::NotFound => error,
        Err(cleanup) => std::io::Error::new(
            error.kind(),
            format!(
                "{error}; temporary STIX file '{}' could not be removed: {cleanup}",
                path.display()
            ),
        ),
    }
}
fn safe(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(48)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{file::FileInfo, indicator::Indicator};
    use std::sync::atomic::AtomicU64;

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("cyberfeed-stix-test-{}-{id}", std::process::id()));
            fs::create_dir(&path).expect("test directory should be created");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn stix_bundle_uses_supported_patterns_and_escapes_literals() {
        let report = InvestigationReport::new(
            &FileInfo {
                name: "x".into(),
                size: 0,
                sha256: "sha".into(),
            },
            vec![
                Indicator::new("192.0.2.1", IndicatorType::IP),
                Indicator::new("example.test", IndicatorType::Domain),
                Indicator::new("https://x.test/a'\\b", IndicatorType::Url),
                Indicator::new("bad", IndicatorType::Hash),
            ],
            Some(true),
            vec![],
        );
        let bundle = stix_bundle(&report);
        assert_eq!(bundle["type"], "bundle");
        assert_eq!(bundle["objects"].as_array().unwrap().len(), 3);
        assert!(bundle.to_string().contains("ipv4-addr:value"));
        assert!(bundle.to_string().contains("\\'"));
        assert!(bundle.to_string().contains("\\\\"));
    }

    #[test]
    fn exports_supported_types_with_stix_fields_provenance_and_uuid_v4_ids() {
        let file = FileInfo {
            name: "x".into(),
            size: 0,
            sha256: "report-sha".into(),
        };
        let mut report = InvestigationReport::new(
            &file,
            vec![
                Indicator::new("a".repeat(32), IndicatorType::Hash),
                Indicator::new("b".repeat(40), IndicatorType::Hash),
                Indicator::new("c".repeat(64), IndicatorType::Hash),
                Indicator::new("192.0.2.2", IndicatorType::IP),
                Indicator::new("2001:db8::2", IndicatorType::IP),
                Indicator::new("example.test", IndicatorType::Domain),
                Indicator::new("https://example.test/A?q=1", IndicatorType::Url),
            ],
            Some(false),
            vec![],
        );
        report.generated_at_unix_seconds = 1_700_000_000;
        let bundle = stix_bundle(&report);
        let objects = bundle["objects"].as_array().unwrap();
        assert_eq!(objects.len(), 7);
        assert_eq!(
            objects[0]["pattern"],
            format!("[file:hashes.'MD5' = '{}']", "a".repeat(32))
        );
        assert_eq!(
            objects[1]["pattern"],
            format!("[file:hashes.'SHA-1' = '{}']", "b".repeat(40))
        );
        assert_eq!(
            objects[2]["pattern"],
            format!("[file:hashes.'SHA-256' = '{}']", "c".repeat(64))
        );
        assert_eq!(objects[3]["pattern"], "[ipv4-addr:value = '192.0.2.2']");
        assert_eq!(objects[4]["pattern"], "[ipv6-addr:value = '2001:db8::2']");
        assert_eq!(
            objects[5]["pattern"],
            "[domain-name:value = 'example.test']"
        );
        assert_eq!(
            objects[6]["pattern"],
            "[url:value = 'https://example.test/A?q=1']"
        );
        assert_eq!(objects[6]["indicator_types"][0], "unknown");
        assert_eq!(
            objects[0]["external_references"][0]["external_id"],
            "report-sha"
        );
        assert_eq!(objects[0]["created"], "2023-11-14T22:13:20Z");
        let bundle_uuid = bundle["id"]
            .as_str()
            .unwrap()
            .strip_prefix("bundle--")
            .unwrap();
        let parsed_bundle_uuid = Uuid::parse_str(bundle_uuid).unwrap();
        assert_eq!(parsed_bundle_uuid.get_version_num(), 4);
        assert_eq!(parsed_bundle_uuid.get_variant(), uuid::Variant::RFC4122);
        let mut identifiers = std::collections::HashSet::from([bundle_uuid.to_owned()]);
        for object in objects {
            let id = object["id"].as_str().unwrap();
            let uuid = id.strip_prefix("indicator--").unwrap();
            let parsed = Uuid::parse_str(uuid).unwrap();
            assert_eq!(parsed.get_version_num(), 4);
            assert_eq!(parsed.get_variant(), uuid::Variant::RFC4122);
            assert!(
                identifiers.insert(uuid.to_owned()),
                "duplicate STIX ID: {id}"
            );
            assert_eq!(object["pattern_type"], "stix");
        }
    }

    #[test]
    fn empty_and_unsupported_reports_produce_empty_valid_bundles() {
        let file = FileInfo {
            name: "empty".into(),
            size: 0,
            sha256: "x".into(),
        };
        for indicators in [
            vec![],
            vec![
                Indicator::new("not-an-ip", IndicatorType::IP),
                Indicator::new("short", IndicatorType::Hash),
            ],
        ] {
            let report = InvestigationReport::new(&file, indicators, Some(false), vec![]);
            assert_eq!(stix_indicator_count(&report), 0);
            assert_eq!(stix_bundle(&report)["objects"].as_array().unwrap().len(), 0);
        }
    }

    #[test]
    fn saved_export_does_not_replace_existing_files_and_publishes_complete_json() {
        let directory = TestDirectory::new();
        let file = FileInfo {
            name: "sample.bin".into(),
            size: 1,
            sha256: "report-sha".into(),
        };
        let mut report = InvestigationReport::new(
            &file,
            vec![Indicator::new("example.test", IndicatorType::Domain)],
            Some(true),
            vec![],
        );
        report.generated_at_unix_seconds = 1_700_000_000;
        let existing = directory
            .0
            .join("cyberfeed-sample_bin-1700000000.stix.json");
        fs::write(&existing, "keep existing data").unwrap();

        let saved = save_stix_bundle(&report, &directory.0).unwrap();

        assert_eq!(fs::read(&existing).unwrap(), b"keep existing data");
        assert!(saved.ends_with("cyberfeed-sample_bin-1700000000-1.stix.json"));
        let parsed: Value = serde_json::from_slice(&fs::read(saved).unwrap()).unwrap();
        assert_eq!(parsed["type"], "bundle");
        assert_eq!(parsed["objects"].as_array().unwrap().len(), 1);
        assert_eq!(
            fs::read_dir(&directory.0)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                .count(),
            0
        );
    }

    #[test]
    fn invalid_report_timestamp_is_rejected_before_creating_export_files() {
        let directory = TestDirectory::new();
        let file = FileInfo {
            name: "sample.bin".into(),
            size: 1,
            sha256: "report-sha".into(),
        };
        let mut report = InvestigationReport::new(
            &file,
            vec![Indicator::new("example.test", IndicatorType::Domain)],
            Some(true),
            vec![],
        );
        report.generated_at_unix_seconds = u64::MAX;

        let error = save_stix_bundle(&report, &directory.0).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);
    }
}
