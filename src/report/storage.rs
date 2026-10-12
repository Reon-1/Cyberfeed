//! Local persistence for paired JSON and Markdown report exports.
use super::model::InvestigationReport;
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
    fs::create_dir_all(directory)
        .map_err(|error| contextual(error, "create report directory", directory))?;
    let stem = safe_stem(&report.file.filename);
    let mut suffix = 0u64;

    loop {
        let extra = if suffix == 0 {
            String::new()
        } else {
            format!("-{suffix}")
        };
        let base = format!(
            "cyberfeed-{stem}-{}{extra}",
            report.generated_at_unix_seconds
        );
        let json = directory.join(format!("{base}.json"));
        let markdown = directory.join(format!("{base}.md"));
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

        if let Err(error) = write_pair(report, json_file, markdown_file) {
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

        match fs::hard_link(&markdown_temp, &markdown) {
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
                    contextual(error, "publish Markdown report to", &markdown),
                    &[json.clone(), json_temp, markdown_temp],
                ));
            }
        }

        if let Some(message) = cleanup_paths(&[json_temp, markdown_temp]) {
            // Both reports are published; retain success but make the leftover staging files visible.
            eprintln!(
                "Reports saved to '{}' and '{}', but {message}",
                json.display(),
                markdown.display()
            );
        }
        return Ok((json, markdown));
    }
}

fn contextual(error: std::io::Error, operation: &str, path: &Path) -> std::io::Error {
    std::io::Error::new(
        error.kind(),
        format!("could not {operation} '{}': {error}", path.display()),
    )
}

fn write_pair(
    report: &InvestigationReport,
    mut json_file: File,
    mut markdown_file: File,
) -> std::io::Result<()> {
    serde_json::to_writer_pretty(&mut json_file, report).map_err(std::io::Error::other)?;
    json_file.write_all(b"\n")?;
    markdown_file.write_all(report.to_markdown().as_bytes())?;
    json_file.sync_all()?;
    markdown_file.sync_all()
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
