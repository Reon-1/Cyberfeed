use super::{
    DrawOp, INNER_WIDTH, MENU_KEY_WIDTH, MUTED, Status, colors_enabled_for, geometry_for_columns,
    menu_key, outcome_style, render_op_lines, render_screen_lines_for_rows, sanitize_terminal_text,
    strip_ansi_sgr, terminal_too_small, visible_width, width_for_columns, wrap_text,
    write_lines_to,
};
use crate::report::{LookupOutcome, MatchDetails};

#[test]
fn provider_outcomes_share_cautionary_neutral_and_error_styles() {
    assert_eq!(
        outcome_style(&LookupOutcome::Found(MatchDetails {
            matched_sha256: "hash".into(),
            first_seen: "today".into(),
            file_type: "bin".into(),
            sample_filename: None,
            signature: None,
        })),
        Status::Warning
    );
    assert_eq!(outcome_style(&LookupOutcome::NotFound), Status::Neutral);
    assert_eq!(
        outcome_style(&LookupOutcome::NotConfigured),
        Status::Warning
    );
    assert_eq!(
        outcome_style(&LookupOutcome::RequestError {
            explanation: "offline".into()
        }),
        Status::Error
    );
    assert_eq!(
        outcome_style(&LookupOutcome::Unsupported {
            explanation: "unsupported".into()
        }),
        Status::Neutral
    );
}

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
fn fields_with_long_labels_wrap_values_within_the_frame_and_keep_alignment() {
    let op = DrawOp::Field(
        "Indicator type".into(),
        "https://example.test/a/very/long/path/that/needs/to/wrap/without/loss".into(),
    );
    let lines = render_op_lines(&op, 80)
        .iter()
        .map(|line| strip_ansi_sgr(line))
        .collect::<Vec<_>>();

    assert!(lines.len() > 1);
    assert!(lines.iter().all(|line| visible_width(line) <= 80));
    let first_value_byte = lines[0].find("https://").unwrap();
    let first_value_column = lines[0][..first_value_byte].chars().count();
    let continuation_value_byte = lines[1]
        .char_indices()
        .find(|(_, character)| *character != '║' && !character.is_whitespace())
        .map(|(index, _)| index)
        .unwrap();
    let continuation_value_column = lines[1][..continuation_value_byte].chars().count();
    assert_eq!(first_value_column, continuation_value_column);
    let rendered_value = lines
        .iter()
        .map(|line| {
            line.chars()
                .skip(first_value_column)
                .take_while(|character| *character != '║')
                .collect::<String>()
                .trim_end()
                .to_owned()
        })
        .collect::<String>();
    assert_eq!(
        rendered_value, "https://example.test/a/very/long/path/that/needs/to/wrap/without/loss",
        "rendered lines: {lines:?}"
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
fn no_color_and_dumb_terminal_modes_disable_sgr_without_touching_other_text() {
    assert!(!colors_enabled_for(true, Some("xterm-256color")));
    assert!(!colors_enabled_for(false, Some("dumb")));
    assert!(colors_enabled_for(false, Some("xterm-256color")));
    assert_eq!(
        strip_ansi_sgr("\x1b[1;36mCYBERFEED\x1b[0m \x1b[2J"),
        "CYBERFEED \x1b[2J"
    );
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
    assert_eq!(width_for_columns(160), INNER_WIDTH);
    assert_eq!(width_for_columns(1), 1);
}

#[test]
fn frame_centers_in_wide_terminals_and_expands_to_available_width() {
    assert_eq!(geometry_for_columns(120), (INNER_WIDTH, 11));
    assert_eq!(geometry_for_columns(160), (INNER_WIDTH, 31));
    assert_eq!(geometry_for_columns(42), (40, 0));
    assert_eq!(geometry_for_columns(1), (0, 0));
}

#[test]
fn panels_keep_the_terminal_background_and_use_readable_secondary_text() {
    let rendered = render_op_lines(
        &DrawOp::MenuItem(
            "1".into(),
            "Check a File".into(),
            "Analyze a file on this computer".into(),
        ),
        80,
    )
    .join("\n");

    assert!(!rendered.contains("\x1b[48;"));
    assert_eq!(MUTED, "\x1b[37m");
    assert!(!rendered.contains("\x1b[0m\x1b[48;"));
}

#[test]
fn retained_screen_operations_reflow_without_overflow_at_representative_widths() {
    let operations = [
        DrawOp::Open,
        DrawOp::Center("CYBERFEED · Investigation".into()),
        DrawOp::Line(
            "A long URL https://example.test/Case/Sensitive?query=long and useful evidence".into(),
        ),
        DrawOp::Divider,
        DrawOp::Close,
    ];
    for columns in [80, 112, 20, 12, 4] {
        let rendered = operations
            .iter()
            .flat_map(|operation| render_op_lines(operation, columns))
            .collect::<Vec<_>>();
        assert!(rendered.iter().all(|line| visible_width(line) <= columns));
    }
}

#[test]
fn menu_descriptions_align_under_labels_and_notes_reflow_with_terminal_width() {
    let menu = DrawOp::MenuItem(
        "1".into(),
        "Check".into(),
        "Analyze this very long local file path without uploading any contents".into(),
    );
    let note = DrawOp::Note(
        "Local file checks work without credentials; live provider searches need optional credentials.".into(),
    );
    for columns in [80, 40, 20] {
        let menu_lines = render_op_lines(&menu, columns);
        let label = menu_lines
            .iter()
            .find(|line| line.contains("Check"))
            .unwrap();
        let description = menu_lines
            .iter()
            .find(|line| line.contains("Analyze"))
            .unwrap();
        let plain = |line: &str| {
            let mut result = String::new();
            let mut in_escape = false;
            for character in line.chars() {
                if in_escape {
                    if character.is_ascii_alphabetic() {
                        in_escape = false;
                    }
                } else if character == '\x1b' {
                    in_escape = true;
                } else {
                    result.push(character);
                }
            }
            result
        };
        let label_column = plain(label).find("Check").unwrap();
        let description_column = plain(description).find("Analyze").unwrap();
        assert_eq!(label_column, description_column);

        let note_lines = render_op_lines(&note, columns);
        assert!(note_lines.len() > 1);
        assert!(note_lines.iter().all(|line| visible_width(line) <= columns));
        assert!(
            note_lines
                .iter()
                .any(|line| plain(line).contains("credentials"))
        );
    }
}

#[test]
fn replayed_menu_remains_grouped_inside_a_centered_connected_panel() {
    let operations = [
        DrawOp::Open,
        DrawOp::Center(">_ CYBERFEED".into()),
        DrawOp::Center("Check files, search logs, and review evidence".into()),
        DrawOp::Divider,
        DrawOp::Line("".into()),
        DrawOp::MenuItem(
            "1".into(),
            "Check a File".into(),
            "Analyze a file on this computer".into(),
        ),
        DrawOp::MenuItem(
            "2".into(),
            "Current Session".into(),
            "Check a value or review results from this session".into(),
        ),
        DrawOp::MenuItem(
            "3".into(),
            "Search Logs".into(),
            "Find IPs, domains, URLs, and hashes in a local text or JSONL log".into(),
        ),
        DrawOp::MenuItem(
            "4".into(),
            "Saved Reports".into(),
            "Review past file and log investigations".into(),
        ),
        DrawOp::Line("".into()),
        DrawOp::MenuItem(
            "5".into(),
            "More Tools".into(),
            "Offline demo, setup check, batch files, and live threat feeds".into(),
        ),
        DrawOp::Note(
            "File checks, log searches, and saved reports work without provider credentials."
                .into(),
        ),
        DrawOp::Line("".into()),
        DrawOp::Divider,
        DrawOp::Footer("0".into(), "Exit · choose 1–5 above".into()),
        DrawOp::Close,
    ];

    for columns in [80, 112, 160, 240] {
        let lines = operations
            .iter()
            .flat_map(|operation| render_op_lines(operation, columns))
            .collect::<Vec<_>>();
        let widths = lines
            .iter()
            .map(|line| visible_width(line))
            .collect::<Vec<_>>();
        assert!(widths.iter().all(|width| *width <= columns));
        let panel_width = geometry_for_columns(columns as u16).0 + 2;
        let margin = (columns - panel_width) / 2;
        assert!(lines[0].starts_with(&" ".repeat(margin)));
        assert!(lines[0].contains('╔') && lines[0].contains('╗'));
        assert!(lines.last().unwrap().contains('╚') && lines.last().unwrap().contains('╝'));
        assert!(lines.iter().all(|line| line.contains('║')
            || line.contains('╔')
            || line.contains('╚')
            || line.contains('╠')));

        let positions = ["[1]", "[2]", "[3]", "[4]", "[5]", "[0]"]
            .map(|label| lines.iter().position(|line| line.contains(label)).unwrap());
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        for (position, title) in positions.iter().zip([
            "Check a File",
            "Current Session",
            "Search Logs",
            "Saved Reports",
            "More Tools",
            "Exit",
        ]) {
            assert!(lines[*position].contains(title));
        }
        for (position, description) in positions[..5].iter().zip([
            "Analyze a file on this computer",
            "Check a value or review results from this session",
            "Find IPs, domains, URLs, and hashes",
            "Review past file and log investigations",
            "Offline demo, setup check, batch files, and live threat feeds",
        ]) {
            let next = lines[*position + 1..]
                .iter()
                .position(|line| line.contains(description));
            assert!(next.is_some(), "description for menu row is retained");
            assert!(
                next.unwrap() <= 2,
                "description stays grouped with its option"
            );
        }
        assert!(lines[positions[5]].contains("choose 1–5 above"));
    }

    // A short terminal drops spacing and the optional note while keeping the
    // exit hint, closing border, and room for the prompt.
    let compact = render_screen_lines_for_rows(&operations, 80, 17);
    assert!(compact.len() <= 17);
    assert!(compact.last().unwrap().contains('╚'));
    assert!(
        compact
            .iter()
            .any(|line| line.contains("[0]") && line.contains("Exit"))
    );

    let narrow = operations
        .iter()
        .flat_map(|operation| render_op_lines(operation, 40))
        .collect::<Vec<_>>();
    let wide = operations
        .iter()
        .flat_map(|operation| render_op_lines(operation, 112))
        .collect::<Vec<_>>();
    assert!(narrow.len() > wide.len());
    assert!(wide.iter().any(|line| line.contains("investigations")));
}

#[test]
fn replay_positions_and_clears_each_row_without_newline_dependent_cursor_motion() {
    let mut output = Vec::new();
    write_lines_to(
        &mut output,
        &["menu row".into(), "description".into(), "prompt".into()],
        3,
        5,
    )
    .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("\u{1b}[4;1H\u{1b}[2Kmenu row"));
    assert!(output.contains("\u{1b}[5;1H\u{1b}[2Kdescription"));
    assert!(!output.contains("prompt"));
    assert!(!output.contains('\n'));
}

#[test]
fn very_small_terminal_fallback_keeps_normal_sizes_usable() {
    assert!(!terminal_too_small((80, 24)));
    assert!(!terminal_too_small((80, 32)));
    assert!(!terminal_too_small((112, 40)));
    assert!(terminal_too_small((12, 24)));
    assert!(terminal_too_small((80, 5)));
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
