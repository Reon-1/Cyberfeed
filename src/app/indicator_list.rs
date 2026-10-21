//! Bounded, local-only import and comparison of line-oriented IOC lists.
use crate::indicator::{
    ClassificationFeedback, Indicator, IndicatorType, MANUAL_HASH_LENGTHS, classify_with_feedback,
};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

pub(super) const MAX_LIST_BYTES: u64 = 8 * 1024 * 1024;
pub(super) const MAX_TOTAL_LINES: usize = 100_000;
pub(super) const MAX_URLS: usize = 1_000;
const MAX_LINE_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Occurrence {
    pub source: String,
    pub line: usize,
    pub original: String,
    pub indicator: Indicator,
}

#[derive(Debug, Default)]
pub(super) struct Import {
    pub occurrences: Vec<Occurrence>,
    pub invalid: Vec<(String, usize, String)>,
    pub files: Vec<(String, usize)>,
    pub duplicates: usize,
    pub limited: bool,
    identities: HashSet<(IndicatorType, String)>,
    url_count: usize,
}

impl Import {
    pub fn unique(&self) -> Vec<Indicator> {
        let mut seen = HashSet::new();
        self.occurrences
            .iter()
            .filter(|occ| seen.insert(identity(&occ.indicator)))
            .map(|occ| occ.indicator.clone())
            .collect()
    }

    pub fn comparisons(&self) -> (usize, usize, usize) {
        let Some((left, right)) = self.files.first().zip(self.files.get(1)) else {
            return (0, self.unique().len(), 0);
        };
        let values_for = |source: &str| {
            self.occurrences
                .iter()
                .filter(|occ| occ.source == source)
                .map(|occ| identity(&occ.indicator))
                .collect::<HashSet<_>>()
        };
        let a = values_for(&left.0);
        let b = values_for(&right.0);
        let common = a.intersection(&b).count();
        (
            common,
            a.len().saturating_sub(common),
            b.len().saturating_sub(common),
        )
    }
}

pub(super) fn import_path(path: &Path, result: &mut Import) -> std::io::Result<()> {
    let display = path.display().to_string();
    let file = File::open(path)?;
    if file.metadata()?.len() > MAX_LIST_BYTES {
        result.limited = true;
        result.files.push((display, 0));
        return Ok(());
    }
    let mut reader = BufReader::new(file.take(MAX_LIST_BYTES + 1));
    let mut line = Vec::new();
    let mut line_number = 0;
    loop {
        line.clear();
        let oversized_line = read_bounded_line(&mut reader, &mut line)?;
        if line.is_empty() && !oversized_line {
            break;
        }
        line_number += 1;
        if result.occurrences.len() + result.invalid.len() >= MAX_TOTAL_LINES || oversized_line {
            result.limited = true;
            break;
        }
        let raw = String::from_utf8_lossy(&line);
        let value = raw.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        let normalized = value.trim_end_matches('\r').trim();
        match classify_with_feedback(normalized, MANUAL_HASH_LENGTHS) {
            ClassificationFeedback::Valid(kind) => {
                if kind == IndicatorType::Url && result.url_count >= MAX_URLS {
                    result.limited = true;
                    break;
                }
                let indicator = Indicator::new(normalized, kind);
                let key = identity(&indicator);
                if !result.identities.insert(key) {
                    result.duplicates += 1;
                }
                result.occurrences.push(Occurrence {
                    source: display.clone(),
                    line: line_number,
                    original: normalized.to_owned(),
                    indicator,
                });
                if kind == IndicatorType::Url {
                    result.url_count += 1;
                }
            }
            _ => result
                .invalid
                .push((display.clone(), line_number, normalized.to_owned())),
        }
    }
    result.files.push((display, line_number));
    if reader.get_ref().limit() == 0 {
        result.limited = true;
    }
    Ok(())
}

/// Reads one line while storing at most `MAX_LINE_BYTES + 1`, draining an
/// oversized line without allocating in proportion to untrusted input size.
fn read_bounded_line(
    reader: &mut BufReader<std::io::Take<File>>,
    output: &mut Vec<u8>,
) -> std::io::Result<bool> {
    let mut oversized = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(oversized);
        }
        let consumed = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        let room = MAX_LINE_BYTES + 1 - output.len().min(MAX_LINE_BYTES + 1);
        output.extend_from_slice(&available[..consumed.min(room)]);
        if output.len() > MAX_LINE_BYTES {
            oversized = true;
            output.truncate(MAX_LINE_BYTES + 1);
        }
        let ended = available.get(consumed.saturating_sub(1)) == Some(&b'\n');
        reader.consume(consumed);
        if ended {
            return Ok(oversized);
        }
    }
}

fn identity(indicator: &Indicator) -> (IndicatorType, String) {
    let value = match indicator.indicator_type {
        IndicatorType::Hash | IndicatorType::Domain => indicator.value.to_ascii_lowercase(),
        IndicatorType::IP | IndicatorType::Url => indicator.value.clone(),
    };
    (indicator.indicator_type, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp(name: &str, content: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("cyberfeed-list-{}-{name}", uuid::Uuid::new_v4()));
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn imports_two_lists_preserving_occurrence_provenance_and_comparison() {
        let a = temp(
            "a",
            "# IOCs\r\nexample.com\r\n192.0.2.1\r\nexample.com\r\nnot an IOC\r\n\n",
        );
        let b = temp("b", "example.com\nhttps://example.test/a\n");
        let mut imported = Import::default();
        import_path(&a, &mut imported).unwrap();
        import_path(&b, &mut imported).unwrap();
        assert_eq!(imported.occurrences[0].line, 2);
        assert_eq!(imported.duplicates, 2);
        assert_eq!(imported.invalid.len(), 1);
        assert_eq!(imported.unique().len(), 3);
        assert_eq!(imported.comparisons(), (1, 1, 1));
        let _ = fs::remove_file(a);
        let _ = fs::remove_file(b);
    }

    #[test]
    fn deduplication_preserves_first_seen_order_and_url_identity() {
        let path = temp(
            "ids",
            "Example.com\nexample.com\nhttps://example.test/A\nhttps://example.test/a\n",
        );
        let mut imported = Import::default();
        import_path(&path, &mut imported).unwrap();
        assert_eq!(imported.unique().len(), 3);
        assert_eq!(imported.unique()[0].value, "Example.com");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn lists_larger_than_the_old_automatic_lookup_cap_are_retained() {
        let content = (0..10_005)
            .map(|index| format!("host{index}.test\n"))
            .collect::<String>();
        let path = temp("many", &content);
        let mut imported = Import::default();
        import_path(&path, &mut imported).unwrap();
        assert!(!imported.limited);
        assert_eq!(imported.unique().len(), 10_005);
        assert_eq!(imported.occurrences.len(), 10_005);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn list_sizes_below_at_and_above_ten_are_not_special_cased() {
        for count in [9, 10, 11] {
            let content = (0..count)
                .map(|index| format!("ioc{index}.test\n"))
                .collect::<String>();
            let path = temp("boundary", &content);
            let mut imported = Import::default();
            import_path(&path, &mut imported).unwrap();
            assert_eq!(imported.unique().len(), count);
            assert!(!imported.limited);
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn import_limit_is_reported_without_discarding_the_accepted_prefix() {
        let content = (0..MAX_TOTAL_LINES + 1)
            .map(|index| format!("host{index}.test\n"))
            .collect::<String>();
        let path = temp("limit", &content);
        let mut imported = Import::default();
        import_path(&path, &mut imported).unwrap();
        assert!(imported.limited);
        assert_eq!(imported.occurrences.len(), MAX_TOTAL_LINES);
        let _ = fs::remove_file(path);
    }
}
