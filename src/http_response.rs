//! Small shared helpers for bounding provider response bodies.
use std::io::{self, Read};

#[derive(Debug)]
pub enum BoundedReadError {
    Read(io::Error),
    TooLarge { limit: u64 },
}

pub fn read_bounded(reader: impl Read, limit: u64) -> Result<Vec<u8>, BoundedReadError> {
    let mut bytes = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(BoundedReadError::Read)?;
    if bytes.len() as u64 > limit {
        return Err(BoundedReadError::TooLarge { limit });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{BoundedReadError, read_bounded};
    use std::io::Cursor;

    #[test]
    fn reads_within_the_limit_and_rejects_oversized_bodies() {
        assert_eq!(read_bounded(Cursor::new(b"1234"), 4).unwrap(), b"1234");
        assert!(matches!(
            read_bounded(Cursor::new(b"12345"), 4),
            Err(BoundedReadError::TooLarge { limit: 4 })
        ));
    }
}
