use crate::indicator::{EXTRACTED_HASH_LENGTHS, Indicator, classify};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;

pub struct FileInfo {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

pub struct FileInspection {
    pub info: FileInfo,
    pub text_indicators: Option<TextIndicators>,
}

pub struct TextIndicators {
    pub indicators: Vec<Indicator>,
    pub limit_reached: bool,
}

const MAX_EXTRACTED_INDICATORS: usize = 10_000;

// Hash and scan the same read-only byte stream so the evidence corresponds to
// the bytes that produced the file hash.
pub fn inspect_file(path_text: &str) -> Result<FileInspection, String> {
    let path = Path::new(path_text);
    let metadata = fs::metadata(path)
        .map_err(|error| format!("Could not access '{}': {error}", path.display()))?;

    if !metadata.is_file() {
        return Err(format!("'{}' is not a regular file.", path.display()));
    }

    let file = File::open(path)
        .map_err(|error| format!("Could not read '{}': {error}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut scanner = TextScanner::default();

    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .map_err(|error| format!("Could not read '{}': {error}", path.display()))?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
        scanner.push_bytes(&buffer[..bytes_read]);
    }

    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path_text)
        .to_string();

    Ok(FileInspection {
        info: FileInfo {
            name,
            size: metadata.len(),
            sha256: format!("{:x}", hasher.finalize()),
        },
        text_indicators: scanner.finish(),
    })
}

pub fn format_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;

    if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

struct TextScanner {
    token: String,
    carry: Vec<u8>,
    started: bool,
    trailing_punctuation: bool,
    invalid_token: bool,
    is_text: bool,
    limit_reached: bool,
    indicators: Vec<Indicator>,
    seen: HashSet<String>,
}

impl Default for TextScanner {
    fn default() -> Self {
        Self {
            token: String::new(),
            carry: Vec::new(),
            started: false,
            trailing_punctuation: false,
            invalid_token: false,
            is_text: true,
            limit_reached: false,
            indicators: Vec::new(),
            seen: HashSet::new(),
        }
    }
}

impl TextScanner {
    fn push_bytes(&mut self, bytes: &[u8]) {
        if !self.is_text {
            return;
        }
        if bytes.contains(&0) {
            self.mark_non_text();
            return;
        }

        let mut chunk = std::mem::take(&mut self.carry);
        chunk.extend_from_slice(bytes);
        match std::str::from_utf8(&chunk) {
            Ok(text) if !self.limit_reached => self.push_text(text),
            Ok(_) => {}
            Err(error) if error.error_len().is_some() => self.mark_non_text(),
            Err(error) => {
                let valid_end = error.valid_up_to();
                let Ok(text) = std::str::from_utf8(&chunk[..valid_end]) else {
                    self.mark_non_text();
                    return;
                };
                if !self.limit_reached {
                    self.push_text(text);
                }
                self.carry.extend_from_slice(&chunk[valid_end..]);
            }
        }
    }

    fn push_text(&mut self, text: &str) {
        for character in text.chars() {
            if self.limit_reached {
                break;
            }
            if character.is_whitespace() {
                self.finish_token();
            } else if !self.invalid_token
                && (character.is_ascii_alphanumeric() || matches!(character, '.' | '-'))
            {
                if self.trailing_punctuation {
                    self.invalid_token = true;
                    continue;
                }
                self.started = true;
                if self.token.len() < 253 {
                    self.token.push(character);
                } else {
                    self.invalid_token = true;
                }
            } else if self.started {
                self.trailing_punctuation = true;
            }
        }
    }

    fn mark_non_text(&mut self) {
        self.is_text = false;
        self.carry.clear();
        self.token.clear();
        self.indicators.clear();
        self.seen.clear();
    }

    fn finish(mut self) -> Option<TextIndicators> {
        if !self.is_text || !self.carry.is_empty() {
            return None;
        }
        self.finish_token();
        Some(TextIndicators {
            indicators: self.indicators,
            limit_reached: self.limit_reached,
        })
    }

    fn finish_token(&mut self) {
        if self.started
            && !self.invalid_token
            && let Some(indicator_type) = classify(&self.token, EXTRACTED_HASH_LENGTHS)
        {
            let key = match indicator_type {
                crate::indicator::IndicatorType::Hash | crate::indicator::IndicatorType::Domain => {
                    self.token.to_ascii_lowercase()
                }
                crate::indicator::IndicatorType::IP => self.token.clone(),
            };
            if !self.seen.contains(&key) && self.indicators.len() == MAX_EXTRACTED_INDICATORS {
                self.limit_reached = true;
            } else if self.seen.insert(key) {
                self.indicators
                    .push(Indicator::new(self.token.clone(), indicator_type));
            }
        }
        self.token.clear();
        self.started = false;
        self.trailing_punctuation = false;
        self.invalid_token = false;
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_EXTRACTED_INDICATORS, TextScanner, inspect_file};
    use crate::indicator::IndicatorType;
    use std::fs;

    #[test]
    fn extracts_hash_ip_and_domain_from_text_file() {
        let path = std::env::temp_dir().join(format!(
            "cyberfeed-indicators-{}-{}.txt",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        fs::write(
            &path,
            "226a723ffb4a91d9950a8b266167c5b354ab0db1dc225578494917fe53867ef2\nsecurity-malware.com\n185.244.150.174\n",
        )
        .expect("test file should be writable");

        let analysis = inspect_file(path.to_str().expect("valid test path"))
            .expect("file inspection should succeed");
        let indicators = analysis
            .text_indicators
            .expect("text file should be recognized")
            .indicators;

        assert_eq!(indicators.len(), 3);
        assert!(matches!(indicators[0].indicator_type, IndicatorType::Hash));
        assert!(matches!(
            indicators[1].indicator_type,
            IndicatorType::Domain
        ));
        assert!(matches!(indicators[2].indicator_type, IndicatorType::IP));
        assert_eq!(
            indicators[0].value,
            "226a723ffb4a91d9950a8b266167c5b354ab0db1dc225578494917fe53867ef2"
        );

        fs::remove_file(path).expect("test file should be removable");
    }

    #[test]
    fn skips_non_text_file_contents() {
        let path = std::env::temp_dir().join(format!(
            "cyberfeed-binary-{}-{}.bin",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        fs::write(&path, [0xff, 0xfe, 0xfd]).expect("test file should be writable");

        let analysis = inspect_file(path.to_str().expect("valid test path"))
            .expect("binary file should still be hashed");
        assert!(analysis.text_indicators.is_none());
        fs::remove_file(path).expect("test file should be removable");
    }

    #[test]
    fn a_very_long_token_does_not_hide_later_indicators_or_grow_unbounded() {
        let mut scanner = TextScanner::default();
        scanner.push_text(&format!("{} example.com", "a".repeat(100_000)));
        scanner.finish_token();

        assert!(scanner.token.is_empty());
        assert_eq!(scanner.indicators.len(), 1);
        assert_eq!(scanner.indicators[0].value, "example.com");
    }

    #[test]
    fn scanner_deduplicates_case_variants_but_keeps_first_spelling() {
        let mut scanner = TextScanner::default();
        scanner.push_text("Example.COM example.com");
        scanner.finish_token();

        assert_eq!(scanner.indicators.len(), 1);
        assert_eq!(scanner.indicators[0].value, "Example.COM");
    }

    #[test]
    fn extraction_stops_at_the_explicit_unique_indicator_cap() {
        let mut scanner = TextScanner::default();
        let content = (0..=MAX_EXTRACTED_INDICATORS)
            .map(|number| format!("host{number}.example "))
            .collect::<String>();
        scanner.push_text(&content);
        assert_eq!(scanner.seen.len(), MAX_EXTRACTED_INDICATORS);
        let result = scanner.finish().expect("content should be text");

        assert_eq!(result.indicators.len(), MAX_EXTRACTED_INDICATORS);
        assert!(result.limit_reached);
    }

    #[test]
    fn utf8_sequences_split_across_read_chunks_are_preserved() {
        let mut scanner = TextScanner::default();
        scanner.push_bytes(b" ");
        scanner.push_bytes(&[0xe2]);
        scanner.push_bytes(&[0x80]);
        scanner.push_bytes(&[0x83]);
        scanner.push_bytes(b"example.com");
        let result = scanner.finish().expect("valid UTF-8 should stay text");

        assert_eq!(result.indicators.len(), 1);
        assert_eq!(result.indicators[0].value, "example.com");
    }

    #[test]
    fn binary_bytes_after_the_extraction_cap_still_reject_text_extraction() {
        let mut scanner = TextScanner::default();
        let content = (0..=MAX_EXTRACTED_INDICATORS)
            .map(|number| format!("host{number}.example "))
            .collect::<String>();
        scanner.push_text(&content);
        scanner.push_bytes(&[0]);

        assert!(scanner.finish().is_none());
    }
}
