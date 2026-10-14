use crate::indicator::{Indicator, MANUAL_HASH_LENGTHS, classify};
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
const MAX_URL_INDICATOR_BYTES: usize = 2_048;
/// Keep the worst-case repeated URL evidence compatible with the saved-report
/// reader's 32 MiB cap alongside the 10,000-item general extraction limit.
const MAX_EXTRACTED_URLS: usize = 1_000;

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
    // Accept the slash-rooted local form and localhost authority everywhere.
    // Windows drag-and-drop also emits `file://C:\\...`, so accept that
    // explicit drive form only on Windows. Other authorities stay rejected.
    #[cfg(windows)]
    let path = {
        let bytes = path.as_bytes();
        let is_drive_path = bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'/' | b'\\');
        if is_drive_path {
            path.to_owned()
        } else if let Some(rest) = path.strip_prefix("localhost/") {
            format!("/{rest}")
        } else if path.starts_with('/') {
            path.to_owned()
        } else {
            return None;
        }
    };
    #[cfg(not(windows))]
    let path = if let Some(rest) = path.strip_prefix("localhost/") {
        format!("/{rest}")
    } else if path.starts_with('/') {
        path.to_owned()
    } else {
        return None;
    };
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return None;
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok()?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    let path = String::from_utf8(decoded).ok()?;
    #[cfg(windows)]
    let path = {
        let path = path.replace('\\', "/");
        path.strip_prefix('/')
            .filter(|path| {
                let bytes = path.as_bytes();
                bytes.len() >= 3
                    && bytes[0].is_ascii_alphabetic()
                    && bytes[1] == b':'
                    && bytes[2] == b'/'
            })
            .unwrap_or(&path)
            .to_owned()
    };
    Some(PathBuf::from(path))
}

pub fn inspect_file(path: &Path) -> Result<FileInspection, String> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("Could not open '{}': {error}", path.display()))?;

    if !metadata.is_file() {
        return Err(format!("'{}' is not a regular file.", path.display()));
    }

    let file = File::open(path)
        .map_err(|error| format!("Could not open '{}': {error}", path.display()))?;

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
    url_count: usize,
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
            url_count: 0,
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
            } else if !self.invalid_token && is_indicator_character(character, &self.token) {
                if self.trailing_punctuation {
                    self.invalid_token = true;
                    continue;
                }
                self.started = true;
                let maximum = if is_url_candidate(&self.token) {
                    MAX_URL_INDICATOR_BYTES
                } else {
                    253
                };
                if self.token.len() + character.len_utf8() <= maximum {
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
        self.url_count = 0;
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
        let url_token = trim_url_punctuation(&self.token);
        let token = self.token.strip_suffix(':').unwrap_or(&self.token);
        let unbracketed = token
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(token);

        let (value, classified) = if classify(url_token, MANUAL_HASH_LENGTHS)
            == Some(crate::indicator::IndicatorType::Url)
        {
            (
                url_token.to_string(),
                Some(crate::indicator::IndicatorType::Url),
            )
        } else if let Some(classified) = classify(&self.token, MANUAL_HASH_LENGTHS)
            .or_else(|| classify(token, MANUAL_HASH_LENGTHS))
            .or_else(|| classify(unbracketed, MANUAL_HASH_LENGTHS))
        {
            (unbracketed.to_string(), Some(classified))
        } else if let Ok(socket) = token.parse::<std::net::SocketAddr>() {
            // When an IP endpoint with a port (e.g. 185.112.146.10:8080 or [2001:db8::1]:8080)
            // is found in inspected text, extract the bare host IP address. Threat intelligence
            // lookups index IP addresses, not transport ports; CyberFeed records the queried IP indicator.
            (
                socket.ip().to_string(),
                Some(crate::indicator::IndicatorType::IP),
            )
        } else {
            (token.to_string(), None)
        };

        if self.started
            && !self.invalid_token
            && let Some(indicator_type) = classified
        {
            let key = match indicator_type {
                crate::indicator::IndicatorType::Hash | crate::indicator::IndicatorType::Domain => {
                    value.to_ascii_lowercase()
                }
                crate::indicator::IndicatorType::IP => value.clone(),
                crate::indicator::IndicatorType::Url => value.clone(),
            };
            if !self.seen.contains(&key)
                && (self.indicators.len() == MAX_EXTRACTED_INDICATORS
                    || (indicator_type == crate::indicator::IndicatorType::Url
                        && self.url_count == MAX_EXTRACTED_URLS))
            {
                self.limit_reached = true;
            } else if self.seen.insert(key) {
                if indicator_type == crate::indicator::IndicatorType::Url {
                    self.url_count += 1;
                }
                self.indicators.push(Indicator::new(value, indicator_type));
            }
        }
        self.token.clear();
        self.started = false;
        self.trailing_punctuation = false;
        self.invalid_token = false;
    }
}

fn is_indicator_character(character: char, token: &str) -> bool {
    if character.is_ascii_alphanumeric() || matches!(character, '.' | '-') {
        return true;
    }
    if character == ':' {
        return true;
    }
    if character == '[' && token.is_empty() {
        return true;
    }
    if character == ']' && token.starts_with('[') && !token.contains(']') {
        return true;
    }
    if url_scheme_prefix(token) {
        return character.is_ascii_graphic() && !matches!(character, '<' | '>' | '"' | '\'');
    }
    false
}

fn url_scheme_prefix(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let token = token.to_ascii_lowercase();
    "http://".starts_with(&token) || "https://".starts_with(&token) || is_url_candidate(&token)
}

fn is_url_candidate(token: &str) -> bool {
    token
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
        || token
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
}

fn trim_url_punctuation(token: &str) -> &str {
    token.trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '}'])
}

#[cfg(test)]
mod tests;
