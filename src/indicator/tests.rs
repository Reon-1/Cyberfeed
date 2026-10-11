use super::{EXTRACTED_HASH_LENGTHS, IndicatorType, MANUAL_HASH_LENGTHS, classify};

#[test]
fn classifies_manual_hash_lengths() {
    for length in MANUAL_HASH_LENGTHS {
        let hash = "a".repeat(*length);
        assert_eq!(
            classify(&hash, MANUAL_HASH_LENGTHS),
            Some(IndicatorType::Hash)
        );
    }
}

#[test]
fn text_extraction_keeps_sha256_only_behavior() {
    assert_eq!(classify(&"a".repeat(32), EXTRACTED_HASH_LENGTHS), None);
    assert_eq!(
        classify(&"a".repeat(64), EXTRACTED_HASH_LENGTHS),
        Some(IndicatorType::Hash)
    );
}

#[test]
fn classifies_ip_and_domain() {
    assert_eq!(
        classify("192.0.2.1", MANUAL_HASH_LENGTHS),
        Some(IndicatorType::IP)
    );
    assert_eq!(
        classify("example.test", MANUAL_HASH_LENGTHS),
        Some(IndicatorType::Domain)
    );
    assert_eq!(classify("not an indicator", MANUAL_HASH_LENGTHS), None);
}

#[test]
fn rejects_obvious_false_positive_domains() {
    for value in [
        ".example",
        "example.",
        "example.-com",
        "example.com-",
        "example.c",
    ] {
        assert_eq!(classify(value, MANUAL_HASH_LENGTHS), None, "{value}");
    }
}
