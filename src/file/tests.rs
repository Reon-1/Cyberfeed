use super::{
    MAX_EXTRACTED_INDICATORS, TextScanner, decode_file_uri, inspect_file, normalize_user_path,
};
use crate::indicator::IndicatorType;
use std::fs;
use std::path::PathBuf;

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

    let analysis = inspect_file(&path).expect("file inspection should succeed");
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
fn extracts_url_and_all_payload_hash_lengths_without_losing_url_path_or_query() {
    let mut single = TextScanner::default();
    single.push_text("(https://Example.test/a/path?key=value&next=1),");
    assert_eq!(
        single.finish().unwrap().indicators[0].value,
        "https://Example.test/a/path?key=value&next=1"
    );
    let mut scanner = TextScanner::default();
    scanner.push_text(&format!(
        "{} {} {} (https://Example.test/a/path?key=value&next=1), example.test 192.0.2.5",
        "a".repeat(32),
        "b".repeat(40),
        "c".repeat(64),
    ));
    let indicators = scanner.finish().expect("input should be text").indicators;
    assert_eq!(indicators.len(), 6);
    assert_eq!(indicators[0].indicator_type, IndicatorType::Hash);
    assert_eq!(indicators[0].value.len(), 32);
    assert_eq!(indicators[1].value.len(), 40);
    assert_eq!(indicators[2].value.len(), 64);
    assert_eq!(indicators[3].indicator_type, IndicatorType::Url);
    assert_eq!(
        indicators[3].value,
        "https://Example.test/a/path?key=value&next=1"
    );
    assert_eq!(indicators[4].indicator_type, IndicatorType::Domain);
    assert_eq!(indicators[5].indicator_type, IndicatorType::IP);
}

#[test]
fn exact_url_deduplication_preserves_case_sensitive_path_distinctions() {
    let mut scanner = TextScanner::default();
    scanner.push_text("https://example.test/A https://example.test/a https://example.test/A");
    let indicators = scanner.finish().expect("input should be text").indicators;
    assert_eq!(indicators.len(), 2);
    assert_eq!(indicators[0].value, "https://example.test/A");
    assert_eq!(indicators[1].value, "https://example.test/a");
}

#[test]
fn extracted_urls_have_a_documented_per_type_cap() {
    let mut scanner = TextScanner::default();
    for index in 0..1_002 {
        scanner.push_text(&format!("https://example.test/{index} "));
    }
    let extracted = scanner.finish().expect("URL text should be recognized");
    assert_eq!(extracted.indicators.len(), 1_000);
    assert!(extracted.limit_reached);
}

#[test]
fn extracted_ipv6_uses_the_same_classifier_as_manual_input() {
    let mut scanner = TextScanner::default();
    scanner.push_text("2001:db8::1 example.test:");
    scanner.finish_token();
    let extracted = scanner.finish().expect("input should be text");
    assert_eq!(extracted.indicators.len(), 2);
    assert_eq!(extracted.indicators[0].value, "2001:db8::1");
    assert_eq!(extracted.indicators[0].indicator_type, IndicatorType::IP);
    assert_eq!(extracted.indicators[1].value, "example.test");
    assert_eq!(
        extracted.indicators[1].indicator_type,
        IndicatorType::Domain
    );
}

#[test]
fn skips_non_text_file_contents() {
    let path = std::env::temp_dir().join(format!(
        "cyberfeed-binary-{}-{}.bin",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    fs::write(&path, [0xff, 0xfe, 0xfd]).expect("test file should be writable");

    let analysis = inspect_file(&path).expect("binary file should still be hashed");
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

#[test]
fn normalizes_typed_and_dragged_paths_without_shell_processing() {
    for (input, expected) in [
        ("/tmp/a.txt", "/tmp/a.txt"),
        (" '/tmp/my file.txt' ", "/tmp/my file.txt"),
        ("\"/tmp/my file.txt\"", "/tmp/my file.txt"),
        ("/tmp/a'b.txt", "/tmp/a'b.txt"),
        ("/tmp/é file.txt", "/tmp/é file.txt"),
    ] {
        assert_eq!(
            normalize_user_path(input).unwrap().unwrap(),
            PathBuf::from(expected)
        );
    }
}

#[test]
fn file_uri_decoder_rejects_remote_authorities() {
    assert!(decode_file_uri("file://example.test/tmp/evidence").is_none());
    assert_eq!(
        decode_file_uri("file:///tmp/evidence"),
        Some(std::path::PathBuf::from("/tmp/evidence"))
    );
    assert_eq!(
        decode_file_uri("file://localhost/tmp/evidence"),
        Some(std::path::PathBuf::from("/tmp/evidence"))
    );
}

#[test]
fn normalizes_shell_escaped_and_file_uri_drag_paths_only_when_target_exists() {
    let directory = std::env::temp_dir();
    let filename = format!("cyberfeed drag {}.txt", std::process::id());
    let target = directory.join(&filename);
    std::fs::write(&target, b"test").unwrap();
    let escaped = target.to_string_lossy().replace(' ', "\\ ");
    let uri = format!("file://{}", target.to_string_lossy().replace(' ', "%20"));
    assert_eq!(normalize_user_path(&escaped).unwrap(), Some(target.clone()));
    assert_eq!(normalize_user_path(&uri).unwrap(), Some(target.clone()));
    std::fs::remove_file(target).unwrap();

    let invalid = directory.join(format!("cyberfeed\\ missing {}.txt", std::process::id()));
    assert_eq!(
        normalize_user_path(invalid.to_str().unwrap()).unwrap(),
        Some(invalid)
    );
}

#[test]
fn preserves_an_existing_filename_with_edge_spaces_before_trimming() {
    let path = std::env::temp_dir().join(format!(" cyberfeed-edge-{} ", std::process::id()));
    std::fs::write(&path, b"evidence").unwrap();
    let input = path.to_string_lossy().to_string();
    assert_eq!(normalize_user_path(&input).unwrap(), Some(path.clone()));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn rejects_empty_and_mismatched_paths_without_rewriting_them() {
    assert!(normalize_user_path("  ").unwrap().is_none());
    assert!(normalize_user_path("0").unwrap().is_none());
    assert!(normalize_user_path("'missing").is_err());
    assert!(normalize_user_path("missing\"").is_err());
}

#[test]
fn inspection_rejects_missing_files_and_directories_cleanly() {
    let missing = std::env::temp_dir().join(format!("cyberfeed-missing-{}", std::process::id()));
    assert!(
        inspect_file(&missing)
            .err()
            .unwrap()
            .contains("Could not open")
    );
    let directory = std::env::temp_dir();
    assert!(
        inspect_file(&directory)
            .err()
            .unwrap()
            .contains("not a regular file")
    );
}

#[test]
fn extracts_bare_host_ip_from_endpoints_with_ports_and_deduplicates() {
    let mut scanner = TextScanner::default();
    scanner.push_text("185.112.146.10:8080 185.112.146.10 [2001:db8::1]:8443 [2001:db8::1]");
    let indicators = scanner.finish().expect("input should be text").indicators;

    assert_eq!(indicators.len(), 2);
    assert_eq!(indicators[0].value, "185.112.146.10");
    assert_eq!(indicators[0].indicator_type, IndicatorType::IP);
    assert_eq!(indicators[1].value, "2001:db8::1");
    assert_eq!(indicators[1].indicator_type, IndicatorType::IP);
}

#[test]
fn rejects_invalid_length_hex_strings_from_file_extraction() {
    let mut scanner = TextScanner::default();
    // 30-char hex, 38-char hex, 65-char hex
    scanner.push_text(&format!(
        "{} {} {} {}",
        "a".repeat(30),
        "b".repeat(38),
        "c".repeat(65),
        "d".repeat(64),
    ));
    let indicators = scanner.finish().expect("input should be text").indicators;

    assert_eq!(indicators.len(), 1);
    assert_eq!(indicators[0].value, "d".repeat(64));
    assert_eq!(indicators[0].indicator_type, IndicatorType::Hash);
}
