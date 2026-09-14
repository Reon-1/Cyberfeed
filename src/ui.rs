pub const INNER_WIDTH: usize = 62;

pub fn box_line(text: &str) {
    println!("║{:width$}║", truncate(text), width = INNER_WIDTH);
}

pub fn centered_box_line(text: &str) {
    let text = truncate(text);
    let padding = INNER_WIDTH.saturating_sub(text.chars().count());
    let left_padding = padding / 2;
    let right_padding = padding - left_padding;

    println!(
        "║{}{}{}║",
        " ".repeat(left_padding),
        text,
        " ".repeat(right_padding)
    );
}

fn truncate(text: &str) -> String {
    if text.chars().count() <= INNER_WIDTH {
        return text.to_string();
    }

    let shortened: String = text.chars().take(INNER_WIDTH - 3).collect();
    format!("{shortened}...")
}
