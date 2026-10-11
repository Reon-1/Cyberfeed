use super::{
    MENU_KEY_WIDTH, geometry_for_columns, menu_key, sanitize_terminal_text, visible_width,
    width_for_columns, wrap_text,
};

#[test]
fn wraps_long_words_without_dropping_content() {
    let text = "abcdef1234567890";
    let lines = wrap_text(text, 5);

    assert_eq!(lines, ["abcde", "f1234", "56789", "0"]);
    assert_eq!(lines.concat(), text);
}

#[test]
fn wrapped_continuation_lines_keep_the_original_indentation() {
    assert_eq!(
        wrap_text("  alpha beta gamma", 9),
        ["  alpha", "  beta", "  gamma"]
    );
}

#[test]
fn terminal_text_replaces_control_characters_without_losing_newlines() {
    assert_eq!(
        sanitize_terminal_text("filename\u{1b}[2J\r\u{7} end\nnext"),
        "filename [2J   end\nnext"
    );
}

#[test]
fn ignores_ansi_sequences_when_measuring() {
    assert_eq!(visible_width("\x1b[31mERROR\x1b[0m"), 5);
    assert_eq!(wrap_text("\x1b[31mERROR\x1b[0m details", 12).len(), 2);
}

#[test]
fn preserves_padding_when_line_fits() {
    assert_eq!(
        wrap_text("  Name       : test.txt", 80),
        ["  Name       : test.txt"]
    );
}

#[test]
fn keeps_a_sha256_value_on_one_line_when_the_value_column_allows_it() {
    let hash = "226a723ffb4a91d9950a8b266167c5b354ab0db1dc225578494917fe53867ef2";

    assert_eq!(wrap_text(hash, 64), [hash]);
    assert_eq!(wrap_text(hash, 32).concat(), hash);
}

#[test]
fn counts_wide_unicode_characters_by_terminal_columns() {
    assert_eq!(visible_width("中"), 2);
    assert_eq!(visible_width("🇳🇵"), 4);
    assert_eq!(wrap_text("中中", 3), ["中", "中"]);
}

#[test]
fn frame_width_fits_narrow_terminals_and_stays_at_a_sensible_maximum() {
    assert_eq!(width_for_columns(41), 39);
    assert_eq!(width_for_columns(82), 80);
    assert_eq!(width_for_columns(160), 112);
    assert_eq!(width_for_columns(1), 1);
}

#[test]
fn frame_centers_in_wide_terminals_and_expands_to_available_width() {
    assert_eq!(geometry_for_columns(120), (112, 3));
    assert_eq!(geometry_for_columns(160), (112, 23));
    assert_eq!(geometry_for_columns(42), (40, 0));
    assert_eq!(geometry_for_columns(1), (0, 0));
}

#[test]
fn menu_keys_keep_compact_brackets_and_a_consistent_title_column() {
    let one = menu_key("1");
    let two = menu_key("2");
    let back = menu_key("0");

    assert!(one.contains("[1]"));
    assert!(two.contains("[2]"));
    assert!(back.contains("[0]"));
    assert_eq!(visible_width(&one), MENU_KEY_WIDTH);
    assert_eq!(visible_width(&two), MENU_KEY_WIDTH);
    assert_eq!(visible_width(&back), MENU_KEY_WIDTH);
}
