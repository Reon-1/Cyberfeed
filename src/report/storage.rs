//! Local persistence for paired JSON and Markdown report exports.
use super::model::{
    InvestigationReport, MAX_SAVED_REPORT_BYTES, ProviderLookup, SessionCheck, SessionReport,
};
use crate::indicator::Indicator;
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Writes a JSON/Markdown report pair without replacing existing destination files.
///
/// Each completed file is published with a same-directory hard link, which
/// atomically fails if its destination already exists. The two links cannot be
/// committed as one filesystem transaction, so a failed second publication
/// removes the first and reports any cleanup failure.
pub fn save_report(
    report: &InvestigationReport,
    directory: &Path,
) -> std::io::Result<(PathBuf, PathBuf)> {
    save_document(
        report,
        &report.file.filename,
        report.generated_at_unix_seconds,
        &report.to_markdown(),
        directory,
    )
}

/// Writes a non-empty current-session report using the same paired-file
/// persistence and collision handling as file-scoped reports.
pub fn save_session_report(
    report: &SessionReport,
    directory: &Path,
) -> std::io::Result<(PathBuf, PathBuf)> {
    if report.checks.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cannot save an empty session report",
        ));
    }
    save_document(
        report,
        "session",
        report.generated_at_unix_seconds,
        &report.to_markdown(),
        directory,
    )
}

/// Saves one indicator lookup as a separate, discoverable report entry.
pub fn save_indicator_report(
    indicator: &Indicator,
    provider_lookups: &[ProviderLookup],
    directory: &Path,
) -> std::io::Result<(PathBuf, PathBuf)> {
    let report = SessionReport::new(vec![SessionCheck::IndicatorLookup {
        indicator: indicator.clone(),
        provider_lookups: provider_lookups.to_vec(),
    }]);
    let stem = format!(
        "indicator-{}-{}",
        indicator.indicator_type.as_str(),
        safe_label(&indicator.value.replace('.', "_"))
    );
    save_document(
        &report,
        &stem,
        report.generated_at_unix_seconds,
        &report.to_markdown(),
        directory,
    )
}

fn save_document<T: Serialize>(
    report: &T,
    filename: &str,
    generated_at_unix_seconds: u64,
    markdown_content: &str,
    directory: &Path,
) -> std::io::Result<(PathBuf, PathBuf)> {
    fs::create_dir_all(directory)
        .map_err(|error| contextual(error, "create report directory", directory))?;
    let stem = safe_stem(filename);
    let mut suffix = 0u64;

    loop {
        let extra = if suffix == 0 {
            String::new()
        } else {
            format!("-{suffix}")
        };
        let base = format!("cyberfeed-{stem}-{}{extra}", generated_at_unix_seconds);
        let json = directory.join(format!("{base}.json"));
        let markdown_path = directory.join(format!("{base}.md"));
        let (json_temp, json_file) = create_temp_file(directory, &base, "json")
            .map_err(|error| contextual(error, "create staged JSON report in", directory))?;
        let (markdown_temp, markdown_file) = match create_temp_file(directory, &base, "md") {
            Ok(temp) => temp,
            Err(error) => {
                drop(json_file);
                return Err(with_cleanup(
                    contextual(error, "create staged Markdown report in", directory),
                    &[json_temp],
                ));
            }
        };

        if let Err(error) = write_pair(report, markdown_content, json_file, markdown_file) {
            return Err(with_cleanup(
                contextual(error, "write staged report files in", directory),
                &[json_temp, markdown_temp],
            ));
        }

        match fs::hard_link(&json_temp, &json) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                cleanup_or_error(&[json_temp, markdown_temp])?;
                suffix = suffix.checked_add(1).ok_or_else(|| {
                    std::io::Error::other("report filename suffix space exhausted")
                })?;
                continue;
            }
            Err(error) => {
                return Err(with_cleanup(
                    contextual(error, "publish JSON report to", &json),
                    &[json_temp, markdown_temp],
                ));
            }
        }

        match fs::hard_link(&markdown_temp, &markdown_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let cleanup_error =
                    cleanup_paths(&[json.clone(), json_temp.clone(), markdown_temp.clone()]);
                if let Some(message) = cleanup_error {
                    return Err(std::io::Error::new(
                        error.kind(),
                        format!("{}; {message}", error),
                    ));
                }
                suffix = suffix.checked_add(1).ok_or_else(|| {
                    std::io::Error::other("report filename suffix space exhausted")
                })?;
                continue;
            }
            Err(error) => {
                return Err(with_cleanup(
                    contextual(error, "publish Markdown report to", &markdown_path),
                    &[json.clone(), json_temp, markdown_temp],
                ));
            }
        }

        if let Some(message) = cleanup_paths(&[json_temp, markdown_temp]) {
            // Both reports are published; retain success but make the leftover staging files visible.
            eprintln!(
                "Reports saved to '{}' and '{}', but {message}",
                json.display(),
                markdown_path.display()
            );
        }
        return Ok((json, markdown_path));
    }
}

fn contextual(error: std::io::Error, operation: &str, path: &Path) -> std::io::Error {
    std::io::Error::new(
        error.kind(),
        format!("could not {operation} '{}': {error}", path.display()),
    )
}

fn write_pair(
    report: &impl Serialize,
    markdown: &str,
    json_file: File,
    mut markdown_file: File,
) -> std::io::Result<()> {
    let mut bounded_json = BoundedReportWriter {
        file: json_file,
        bytes_written: 0,
    };
    serde_json::to_writer_pretty(&mut bounded_json, report).map_err(std::io::Error::other)?;
    bounded_json.write_all(b"\n")?;
    let json_file = bounded_json.file;
    markdown_file.write_all(markdown.as_bytes())?;
    json_file.sync_all()?;
    markdown_file.sync_all()
}

struct BoundedReportWriter {
    file: File,
    bytes_written: u64,
}

impl Write for BoundedReportWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if self.bytes_written.saturating_add(buffer.len() as u64) > MAX_SAVED_REPORT_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "serialized report exceeds the 32 MiB Saved Reports limit",
            ));
        }
        let written = self.file.write(buffer)?;
        self.bytes_written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

fn create_temp_file(
    directory: &Path,
    base: &str,
    extension: &str,
) -> std::io::Result<(PathBuf, File)> {
    loop {
        let id = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(
            ".{base}-{}-{id}.{extension}.tmp",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        // Reports contain hashes and extracted indicators. Keep them private
        // to the creating user on Unix instead of inheriting a readable mode.
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
}

fn cleanup_or_error(paths: &[PathBuf]) -> std::io::Result<()> {
    match cleanup_paths(paths) {
        Some(message) => Err(std::io::Error::other(message)),
        None => Ok(()),
    }
}

fn with_cleanup(error: std::io::Error, paths: &[PathBuf]) -> std::io::Error {
    match cleanup_paths(paths) {
        Some(message) => std::io::Error::new(error.kind(), format!("{error}; {message}")),
        None => error,
    }
}

fn cleanup_paths(paths: &[PathBuf]) -> Option<String> {
    let mut failures = Vec::new();
    for path in paths {
        if let Err(error) = fs::remove_file(path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            failures.push(format!("could not remove '{}': {error}", path.display()));
        }
    }
    (!failures.is_empty()).then(|| failures.join("; "))
}

fn safe_stem(filename: &str) -> String {
    let stem = Path::new(filename)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    safe_label(stem)
}

// Indicator values are labels, never paths. Sanitize the complete value
// before passing a derived label to `save_document`.
fn safe_label(label: &str) -> String {
    let s: String = label
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
    use super::{safe_label, safe_stem, save_indicator_report};
    use crate::indicator::{Indicator, IndicatorType};
    use std::fs;
    use std::path::PathBuf;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "cyberfeed-storage-{}-{}",
                std::process::id(),
                crate::report::storage::TEMP_FILE_COUNTER
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn indicator_filenames_sanitize_the_whole_value_without_path_semantics() {
        for (value, expected) in [
            ("example.test", "example_test"),
            ("192.0.2.1", "192_0_2_1"),
            ("2001:db8::1", "2001_db8__1"),
            (
                "https://example.test/a?q=x#frag",
                "https___example_test_a_q_x_frag",
            ),
        ] {
            assert_eq!(safe_label(value), expected);
        }
        for (value, expected_len) in [
            ("a".repeat(32), 32),
            ("b".repeat(40), 40),
            ("c".repeat(64), 48),
        ] {
            assert_eq!(safe_stem(&value).len(), expected_len);
        }
        assert!(!safe_stem("../目录\\CON:*?").contains('/'));
        assert!(!safe_stem("../目录\\CON:*?").contains('\\'));
        assert_eq!(safe_stem(""), "file");
    }

    #[test]
    fn indicator_report_keeps_identity_and_collision_suffixes_distinct_values() {
        let directory = TestDirectory::new();
        let values = [
            "https://example.test/a?q=x#frag",
            "https://example.test/a?q?x#frag",
        ];
        let mut paths = Vec::new();
        for value in values {
            let indicator = Indicator::new(value, IndicatorType::Url);
            let (json, markdown) = save_indicator_report(&indicator, &[], &directory.0).unwrap();
            assert_eq!(json.parent(), Some(directory.0.as_path()));
            assert_eq!(markdown.parent(), Some(directory.0.as_path()));
            assert!(json.file_name().unwrap().to_string_lossy().len() < 100);
            let content = fs::read_to_string(&json).unwrap();
            assert!(content.contains(value));
            paths.push(json);
        }
        assert_ne!(paths[0], paths[1]);
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 4);
    }
}
