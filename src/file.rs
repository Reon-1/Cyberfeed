use crate::indicator::{EXTRACTED_HASH_LENGTHS, Indicator, classify};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

pub struct FileInfo {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

pub struct FileInspection {
    pub info: FileInfo,
    pub text_indicators: Option<TextIndicators>,
}

#[derive(Clone)]
pub struct TextIndicators {
    pub indicators: Vec<Indicator>,
    pub limit_reached: bool,
}

const MAX_EXTRACTED_INDICATORS: usize = 10_000;

// Hash and scan the same read-only byte stream so the evidence corresponds to
// the bytes that produced the file hash.
pub fn normalize_user_path(input: &str) -> Result<Option<PathBuf>, &'static str> {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed == "0" {
        return Ok(None);
    }
    if !input.trim().is_empty() && Path::new(input).exists() {
        return Ok(Some(PathBuf::from(input)));
    }
    let input = trimmed;

    let unquoted = strip_matching_outer_quotes(input)?;
    let exact = PathBuf::from(unquoted);
    // An existing literal filename wins over terminal escape decoding. This
    // keeps valid backslashes intact while still accepting drag-in `\ ` paths.
    if exact.exists() {
        return Ok(Some(exact));
    }
    if let Some(uri_path) = decode_file_uri(unquoted)
        && uri_path.exists()
    {
        return Ok(Some(uri_path));
    }
    let decoded = decode_terminal_escapes(unquoted);
    if decoded != unquoted && Path::new(&decoded).exists() {
        return Ok(Some(PathBuf::from(decoded)));
    }
    Ok(Some(exact))
}

fn strip_matching_outer_quotes(input: &str) -> Result<&str, &'static str> {
    let first = input.chars().next().expect("non-empty input");
    let last = input.chars().next_back().expect("non-empty input");
    if first == '\'' || first == '"' {
        if input.len() < 2 || last != first {
            return Err(
                "The path has an unmatched outer quote. Add the matching quote or remove it.",
            );
        }
        return Ok(&input[first.len_utf8()..input.len() - last.len_utf8()]);
    }
    if last == '\'' || last == '"' {
        return Err("The path has an unmatched outer quote. Add the matching quote or remove it.");
    }
    Ok(input)
}

fn decode_terminal_escapes(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\\'
            && chars.peek().is_some_and(|next| {
                next.is_whitespace() || matches!(next, '\\' | '\'' | '"' | '(' | ')' | '[' | ']')
            })
        {
            output.push(chars.next().expect("peeked character exists"));
        } else {
            output.push(character);
        }
    }
    output
}

fn decode_file_uri(input: &str) -> Option<PathBuf> {
    let path = input.strip_prefix("file://")?;
    // A local file URI may include an explicit localhost authority.
    let path = path
        .strip_prefix("localhost/")
        .map_or_else(|| path.to_owned(), |rest| format!("/{rest}"));
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok()?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok().map(PathBuf::from)
}

pub fn inspect_file(path: &Path) -> Result<FileInspection, String> {
    let file = File::open(path)
        .map_err(|error| format!("Could not open '{}': {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("Could not inspect '{}': {error}", path.display()))?;

    if !metadata.is_file() {
        return Err(format!("'{}' is not a regular file.", path.display()));
    }

    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut scanner = TextScanner::default();
    let mut size = 0u64;

    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .map_err(|error| format!("Could not read '{}': {error}", path.display()))?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
        scanner.push_bytes(&buffer[..bytes_read]);
        size += bytes_read as u64;
    }

    let name = path
        .file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned();

    Ok(FileInspection {
        info: FileInfo {
            name,
            size,
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
                && (character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | ':'))
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
        let token = self.token.strip_suffix(':').unwrap_or(&self.token);
        let classified = classify(&self.token, EXTRACTED_HASH_LENGTHS)
            .or_else(|| classify(token, EXTRACTED_HASH_LENGTHS));
        if self.started
            && !self.invalid_token
            && let Some(indicator_type) = classified
        {
            let key = match indicator_type {
                crate::indicator::IndicatorType::Hash | crate::indicator::IndicatorType::Domain => {
                    token.to_ascii_lowercase()
                }
                crate::indicator::IndicatorType::IP => token.to_string(),
            };
            if !self.seen.contains(&key) && self.indicators.len() == MAX_EXTRACTED_INDICATORS {
                self.limit_reached = true;
            } else if self.seen.insert(key) {
                self.indicators.push(Indicator::new(token, indicator_type));
            }
        }
        self.token.clear();
        self.started = false;
        self.trailing_punctuation = false;
        self.invalid_token = false;
    }
}

#[cfg(test)]
mod tests;
