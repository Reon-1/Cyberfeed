use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufReader, Read};
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
