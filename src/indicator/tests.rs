use super::{IndicatorType, MANUAL_HASH_LENGTHS, classify};

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
fn extracted_hash_classification_accepts_md5_sha1_and_sha256() {
    for length in [32, 40, 64] {
        assert_eq!(
            classify(&"a".repeat(length), MANUAL_HASH_LENGTHS),
            Some(IndicatorType::Hash)
        );
    }
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
fn classifies_only_well_formed_http_urls_as_url_indicators() {
    for value in [
        "https://example.test/download?id=1",
        "http://192.0.2.1/a.exe",
        "HTTPS://Example.test/Path",
    ] {
        assert_eq!(
            classify(value, MANUAL_HASH_LENGTHS),
            Some(IndicatorType::Url)
        );
    }
    for value in [
        "ftp://example.test/file",
        "http:///missing-host",
        "https://",
    ] {
        assert_ne!(
            classify(value, MANUAL_HASH_LENGTHS),
            Some(IndicatorType::Url)
        );
    }
}

#[test]
fn url_indicator_keeps_the_uppercase_serialized_type_name() {
    assert_eq!(
        serde_json::to_string(&IndicatorType::Url).unwrap(),
        "\"URL\""
    );
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

#[test]
fn provides_detailed_classification_feedback() {
    use super::{ClassificationFeedback, classify_with_feedback};

    assert_eq!(
        classify_with_feedback("185.112.146.10:8080", MANUAL_HASH_LENGTHS),
        ClassificationFeedback::EndpointWithPort {
            ip: "185.112.146.10".into(),
            port: 8080,
        }
    );
    assert_eq!(
        classify_with_feedback("[2001:db8::1]:8443", MANUAL_HASH_LENGTHS),
        ClassificationFeedback::EndpointWithPort {
            ip: "2001:db8::1".into(),
            port: 8443,
        }
    );
    assert_eq!(
        classify_with_feedback(&"a".repeat(38), MANUAL_HASH_LENGTHS),
        ClassificationFeedback::InvalidHashLength {
            len: 38,
            expected: vec![32, 40, 64],
        }
    );
    assert_eq!(
        classify_with_feedback(&"a".repeat(32), MANUAL_HASH_LENGTHS),
        ClassificationFeedback::Valid(IndicatorType::Hash)
    );
    assert_eq!(
        classify_with_feedback("192.0.2.1", MANUAL_HASH_LENGTHS),
        ClassificationFeedback::Valid(IndicatorType::IP)
    );
    assert_eq!(
        classify_with_feedback("2001:db8::1", MANUAL_HASH_LENGTHS),
        ClassificationFeedback::Valid(IndicatorType::IP)
    );
    assert!(matches!(
        classify_with_feedback("ftp://example.test/file", MANUAL_HASH_LENGTHS),
        ClassificationFeedback::MalformedUrl(_)
    ));
    assert!(matches!(
        classify_with_feedback("example.-com", MANUAL_HASH_LENGTHS),
        ClassificationFeedback::MalformedDomain(_)
    ));
    assert_eq!(
        classify_with_feedback("not an indicator", MANUAL_HASH_LENGTHS),
        ClassificationFeedback::Unrecognized
    );
}
