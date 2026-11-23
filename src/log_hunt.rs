//! Bounded streaming extraction for ordinary text and JSON Lines logs.
use crate::file::{check_file_snapshot, open_regular_file};
use crate::indicator::{EXTRACTED_HASH_LENGTHS, Indicator, IndicatorType, classify};
use crate::report::SourceOccurrence;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;
use std::time::{Duration, Instant};

pub const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_LINE_BYTES: usize = 16 * 1024;
pub const MAX_UNIQUE_INDICATORS: usize = 1_000;
pub const MAX_OCCURRENCES: usize = 10_000;
const MAX_CONTEXT_CHARS: usize = 240;

pub struct LogHunt {
    pub sha256: String,
    pub size_bytes: u64,
    pub indicators: Vec<Indicator>,
    pub occurrences: Vec<SourceOccurrence>,
    pub limit_reached: bool,
}

pub fn inspect_log(path: &Path) -> Result<LogHunt, String> {
    inspect_log_with_limit(path, MAX_LOG_BYTES)
}

fn inspect_log_with_limit(path: &Path, max_bytes: u64) -> Result<LogHunt, String> {
    let deadline = Instant::now() + Duration::from_secs(60);
    let (file, metadata) =
        open_regular_file(path).map_err(|e| format!("Could not open '{}': {e}", path.display()))?;
    if metadata.len() > max_bytes {
        return Err(format!(
            "'{}' exceeds the 64 MiB log limit.",
            path.display()
        ));
    }
    let mut reader = BufReader::new(file.take(max_bytes + 1));
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut line_number = 0u64;
    let mut line = Vec::with_capacity(4096);
    let mut indicators = Vec::new();
    let mut seen = HashSet::new();
    let mut occurrences = Vec::new();
    let mut limit_reached = false;
    let mut collecting = true;
    let source_filename = path
        .file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned();
    loop {
        line.clear();
        let (line_bytes, oversized, ended) = read_limited_line(
            &mut reader,
            &mut line,
            if collecting { MAX_LINE_BYTES } else { 0 },
            &mut hasher,
            deadline,
        )
        .map_err(|e| format!("Could not read '{}': {e}", path.display()))?;
        if line_bytes == 0 && ended {
            break;
        }
        total = total.saturating_add(line_bytes as u64);
        line_number += 1;
        if total > max_bytes {
            return Err("Log exceeded the 64 MiB limit; no file identity was saved.".into());
        }
        if !collecting {
            continue;
        }
        if oversized {
            limit_reached = true;
            continue;
        }
        let Ok(text) = std::str::from_utf8(&line) else {
            limit_reached = true;
            continue;
        };
        let context = bounded_context(text);
        for (value, kind) in candidates(text) {
            // Keep every reported indicator tied to at least one saved source
            // occurrence. Do not add a new unique value after provenance is full.
            if occurrences.len() >= MAX_OCCURRENCES {
                limit_reached = true;
                collecting = false;
                break;
            }
            let indicator = Indicator::new(value.clone(), kind);
            let key = match kind {
                IndicatorType::Hash | IndicatorType::Domain => value.to_ascii_lowercase(),
                _ => value.clone(),
            };
            if !seen.contains(&(kind, key.clone())) {
                if seen.len() >= MAX_UNIQUE_INDICATORS {
                    limit_reached = true;
                    collecting = false;
                    break;
                }
                seen.insert((kind, key));
                indicators.push(indicator.clone());
            }
            occurrences.push(SourceOccurrence {
                source_filename: source_filename.clone(),
                line_number,
                indicator: indicator.clone(),
                original_value: value,
                context: context.clone(),
            });
        }
    }
    let after = reader
        .get_ref()
        .get_ref()
        .metadata()
        .map_err(|e| e.to_string())?;
    check_file_snapshot(&metadata, &after, total).map_err(|e| e.to_string())?;
    Ok(LogHunt {
        sha256: format!("{:x}", hasher.finalize()),
        size_bytes: total,
        indicators,
        occurrences,
        limit_reached,
    })
}

/// Reads at most one configured line chunk into memory while consuming an
/// oversized line safely. The underlying reader enforces the total byte budget.
fn read_limited_line<R: BufRead>(
    reader: &mut R,
    line: &mut Vec<u8>,
    cap: usize,
    hasher: &mut Sha256,
    deadline: Instant,
) -> io::Result<(usize, bool, bool)> {
    let mut consumed = 0usize;
    let mut oversized = false;
    let mut ended = false;
    loop {
        let check_deadline = || {
            if Instant::now() >= deadline {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "log inspection exceeded its time budget",
                ))
            } else {
                Ok(())
            }
        };
        check_deadline()?;
        let buffer = reader.fill_buf()?;
        check_deadline()?;
        if buffer.is_empty() {
            ended = true;
            break;
        }
        let take = buffer
            .iter()
            .position(|b| *b == b'\n')
            .map_or(buffer.len(), |i| i + 1);
        hasher.update(&buffer[..take]);
        let allowed = cap.saturating_add(1).saturating_sub(line.len());
        if allowed > 0 {
            line.extend_from_slice(&buffer[..take.min(allowed)]);
        }
        if line.len() > cap {
            oversized = true;
        }
        consumed += take;
        let has_newline = buffer.get(take.saturating_sub(1)) == Some(&b'\n');
        reader.consume(take);
        if has_newline {
            break;
        }
    }
    Ok((consumed, oversized, ended))
}

fn candidates(line: &str) -> Vec<(String, IndicatorType)> {
    let mut output = Vec::new();
    let mut add = |value: &str| {
        let value = value.trim_matches(|c: char| {
            matches!(
                c,
                '\'' | '"' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '='
            )
        });
        if let Some(kind) = classify(value, EXTRACTED_HASH_LENGTHS) {
            output.push((value.to_owned(), kind));
        }
    };
    // Extract full URLs first so punctuation in the scheme and query remains intact.
    for (start, _) in line
        .match_indices("http://")
        .chain(line.match_indices("https://"))
    {
        let tail = &line[start..];
        let end = tail
            .find(|c: char| c.is_whitespace() || matches!(c, '\'' | '"' | '<' | '>' | ',' | ']'))
            .unwrap_or(tail.len());
        add(tail[..end].trim_end_matches(['.', ')', ';']));
    }
    for token in line.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-')))
    {
        if !token.is_empty() {
            add(token);
        }
    }
    let mut unique = HashSet::new();
    output.retain(|(value, kind)| unique.insert((*kind, value.clone())));
    output
}

fn bounded_context(line: &str) -> String {
    let sanitized = line
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>();
    let mut value = sanitized
        .chars()
        .take(MAX_CONTEXT_CHARS)
        .collect::<String>();
    if sanitized.chars().count() > MAX_CONTEXT_CHARS {
        value.push('…');
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    #[test]
    fn jsonl_hunt_deduplicates_indicators_and_keeps_each_location() {
        let path = std::env::temp_dir().join(format!(
            "cyberfeed-log-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(
            &path,
            "{\"src_ip\":\"192.0.2.10\",\"url\":\"https://demo.invalid/A\"}\npeer=192.0.2.10\n",
        )
        .unwrap();
        let hunt = inspect_log(&path).unwrap();
        assert_eq!(
            hunt.occurrences
                .iter()
                .filter(|o| o.indicator.value == "192.0.2.10")
                .count(),
            2
        );
        assert_eq!(hunt.occurrences[0].line_number, 1);
        assert_eq!(
            hunt.indicators
                .iter()
                .filter(|i| i.indicator_type == IndicatorType::IP)
                .count(),
            1
        );
        fs::remove_file(path).unwrap();
    }

    fn inspect_fixture(bytes: &[u8], budget: u64) -> Result<LogHunt, String> {
        let path = std::env::temp_dir().join(format!("cyberfeed-log-{}", uuid::Uuid::new_v4()));
        fs::write(&path, bytes).unwrap();
        let result = inspect_log_with_limit(&path, budget);
        fs::remove_file(path).unwrap();
        result
    }

    #[test]
    fn tails_after_the_occurrence_limit_still_contribute_to_identity() {
        let prefix = b"peer=192.0.2.10\n".repeat(MAX_OCCURRENCES + 1);
        let mut digests = Vec::new();
        for tail in [b"tail A", b"tail B"] {
            let bytes = [prefix.as_slice(), tail].concat();
            let hunt = inspect_fixture(&bytes, bytes.len() as u64).unwrap();
            assert!(hunt.limit_reached);
            assert_eq!(hunt.size_bytes, bytes.len() as u64);
            assert_eq!(hunt.sha256, format!("{:x}", Sha256::digest(&bytes)));
            digests.push(hunt.sha256);
        }
        assert_ne!(digests[0], digests[1]);
    }

    #[test]
    fn skipped_lines_keep_later_provenance_and_full_hash_at_byte_boundary() {
        let mut bytes = vec![b'x'; MAX_LINE_BYTES + 1];
        bytes.extend_from_slice(b"\n\xff\npeer=example.test");
        let size = bytes.len() as u64;
        let hunt = inspect_fixture(&bytes, size).unwrap();
        assert!(hunt.limit_reached);
        assert_eq!(hunt.occurrences.len(), 1);
        assert_eq!(hunt.occurrences[0].line_number, 3);
        assert_eq!(hunt.sha256, format!("{:x}", Sha256::digest(&bytes)));
        assert!(inspect_fixture(&bytes, size - 1).is_err());
        assert!(!inspect_fixture(b"", 0).unwrap().limit_reached);
    }

    #[test]
    fn occurrence_limit_does_not_add_indicators_without_source_locations() {
        let path = std::env::temp_dir().join(format!(
            "cyberfeed-log-limit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut contents = "address=192.0.2.10\n".repeat(MAX_OCCURRENCES);
        contents.push_str("domain=example.test\n");
        fs::write(&path, contents).unwrap();

        let hunt = inspect_log(&path).unwrap();

        assert!(hunt.limit_reached);
        assert_eq!(hunt.occurrences.len(), MAX_OCCURRENCES);
        assert!(
            !hunt
                .indicators
                .iter()
                .any(|indicator| indicator.value == "example.test")
        );
        fs::remove_file(path).unwrap();
    }
}
