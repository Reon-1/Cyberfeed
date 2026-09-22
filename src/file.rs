use crate::indicator::{Indicator, IndicatorType};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::net::IpAddr;
use std::path::Path;

pub struct FileInfo {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

// Read basic metadata and calculate a SHA-256 without modifying the file.
pub fn inspect_file(path_text: &str) -> Result<FileInfo, String> {
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

    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .map_err(|error| format!("Could not read '{}': {error}", path.display()))?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path_text)
        .to_string();

    Ok(FileInfo {
        name,
        size: metadata.len(),
        sha256: format!("{:x}", hasher.finalize()),
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

// Read indicators only from content that is safely recognizable as text.
pub fn extract_text_indicators(path_text: &str) -> Result<Vec<Indicator>, String> {
    let path = Path::new(path_text);
    let contents =
        fs::read(path).map_err(|error| format!("Could not read '{}': {error}", path.display()))?;

    let Ok(text) = std::str::from_utf8(&contents) else {
        return Ok(Vec::new());
    };

    if text.contains('\0') {
        return Ok(Vec::new());
    }

    Ok(text
        .split_whitespace()
        .filter_map(|token| {
            Some(token.trim_matches(|character: char| {
                !character.is_ascii_alphanumeric() && !matches!(character, '.' | '-')
            }))
        })
        .filter_map(indicator_from_token)
        .collect())
}

fn indicator_from_token(token: &str) -> Option<Indicator> {
    if token.len() == 64 && token.chars().all(|character| character.is_ascii_hexdigit()) {
        return Some(Indicator {
            value: token.to_string(),
            indicator_type: IndicatorType::Hash,
        });
    }

    if token.parse::<IpAddr>().is_ok() {
        return Some(Indicator {
            value: token.to_string(),
            indicator_type: IndicatorType::IP,
        });
    }

    let is_domain = token.contains('.')
        && token.split('.').all(|label| {
            !label.is_empty()
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        });

    is_domain.then(|| Indicator {
        value: token.to_string(),
        indicator_type: IndicatorType::Domain,
    })
}

#[cfg(test)]
mod tests {
    use super::extract_text_indicators;
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

        let indicators = extract_text_indicators(path.to_str().expect("valid test path"))
            .expect("text extraction should succeed");

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

        let indicators = extract_text_indicators(path.to_str().expect("valid test path"))
            .expect("binary content should be skipped");

        assert!(indicators.is_empty());
        fs::remove_file(path).expect("test file should be removable");
    }
}
