use super::file_workflow;
use super::terminal::{self, InputEditor};
use super::threat_menu;
use crate::config::Config;
use crate::investigation::Investigation;
use crate::ui;
use reqwest::blocking::Client;

const INVESTIGATION_MENU_OPTIONS: [(&str, &str, &str); 3] = [
    (
        "1",
        "Check an Indicator",
        "Add a hash, IP address, or domain to this investigation",
    ),
    (
        "2",
        "Review Collected Evidence",
        "Open the evidence collected in this session",
    ),
    ("0", "Back", "Return to the main menu"),
];

pub(super) fn run(client: &Client, config: &Config) {
    let mut editor = match terminal::new_editor() {
        Ok(editor) => editor,
        Err(error) => {
            eprintln!("Input error: {error}");
            return;
        }
    };
    let mut investigation = Investigation::new();
    let cloudflare_token = config.cloudflare_token.as_deref().unwrap_or("");
    let malwarebazaar_auth_key = config.malwarebazaar_auth_key.as_deref().unwrap_or("");

    loop {
        terminal::clear_screen();
        ui::header("CYBERFEED", "Defensive Cybersecurity Investigation");
        ui::box_line("");
        ui::menu_item("1", "Check a File", "Analyze a file on this computer");
        ui::menu_item(
            "2",
            "Investigation",
            "Continue and review this session's evidence",
        );
        ui::menu_item(
            "3",
            "Threat Intelligence",
            "Browse external intelligence sources",
        );
        ui::box_line("");
        ui::menu_item("0", "Exit", "Close CyberFeed");
        ui::box_line("");
        ui::close_box();

        match terminal::read_input(&mut editor, "\n  Select an option: ", false).as_str() {
            "1" => file_workflow::investigate_file(
                &mut editor,
                client,
                malwarebazaar_auth_key,
                &mut investigation,
            ),
            "2" => investigation_menu(
                &mut editor,
                client,
                malwarebazaar_auth_key,
                &mut investigation,
            ),
            "3" => threat_menu::menu(
                &mut editor,
                client,
                cloudflare_token,
                malwarebazaar_auth_key,
                &mut investigation,
            ),
            "0" => {
                terminal::clear_screen();
                println!("Goodbye.");
                break;
            }
            _ => terminal::invalid_choice(),
        }
    }
}

fn investigation_menu(
    editor: &mut InputEditor,
    client: &Client,
    auth_key: &str,
    investigation: &mut Investigation,
) {
    loop {
        terminal::clear_screen();
        ui::header("INVESTIGATION", "Continue working with collected evidence");
        ui::box_line("");
        for (key, label, description) in INVESTIGATION_MENU_OPTIONS {
            ui::menu_item(key, label, description);
        }
        ui::box_line("");
        ui::close_box();

        match terminal::read_input(editor, "\n  Select an option: ", false).as_str() {
            "1" => file_workflow::check_indicator(editor, client, auth_key, investigation),
            "2" => file_workflow::view_indicators(investigation),
            "0" => break,
            _ => terminal::invalid_choice(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::INVESTIGATION_MENU_OPTIONS;

    #[test]
    fn investigation_menu_has_review_and_indicator_actions_without_duplicate_file_check() {
        let labels: Vec<&str> = INVESTIGATION_MENU_OPTIONS
            .iter()
            .map(|(_, label, _)| *label)
            .collect();

        assert_eq!(
            labels,
            ["Check an Indicator", "Review Collected Evidence", "Back"]
        );
        assert!(!labels.contains(&"Check a File"));
    }
}
