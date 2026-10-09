use super::terminal::{self, InputEditor};
use crate::cloudflare::{
    display_top_attack_pairs, display_top_origins, display_top_targets,
    fetch_cloudflare_attack_pairs, fetch_cloudflare_data, fetch_cloudflare_targets,
};
use crate::investigation::Investigation;
use crate::malwarebazaar::{display_malware_data, fetch_malware_data};
use crate::ui;
use reqwest::blocking::Client;
use std::time::Duration;

#[derive(Clone, Copy)]
enum Feed {
    Origins,
    Targets,
    Pairs,
}

pub(super) fn menu(
    editor: &mut InputEditor,
    client: &Client,
    cloudflare_token: &str,
    auth_key: &str,
    investigation: &mut Investigation,
) {
    loop {
        terminal::clear_screen();
        ui::header(
            "THREAT INTELLIGENCE",
            "Browse external intelligence sources",
        );
        ui::box_line("");
        ui::menu_item("1", "MalwareBazaar", "Recent malware samples");
        ui::menu_item("2", "Cloudflare Radar", "Live Layer 7 attack telemetry");
        ui::box_line("");
        ui::menu_item("0", "Back", "Return to the main menu");
        ui::box_line("");
        ui::close_box();

        match terminal::read_input(editor, "\n  Select an option: ", false).as_str() {
            "1" => malwarebazaar_menu(editor, client, auth_key, investigation),
            "2" => cloudflare_menu(editor, client, cloudflare_token),
            "0" => break,
            _ => terminal::invalid_choice(),
        }
    }
}

fn malwarebazaar_menu(
    editor: &mut InputEditor,
    client: &Client,
    auth_key: &str,
    investigation: &mut Investigation,
) {
    loop {
        terminal::clear_screen();
        ui::header("MALWAREBAZAAR", "Recent malware sample intelligence");
        ui::box_line("");
        ui::menu_item(
            "1",
            "Recent Samples",
            "View the latest MalwareBazaar samples",
        );
        ui::menu_item("2", "Filter by Country", "View samples from one country");
        ui::box_line("");
        ui::menu_item("0", "Back", "Return to Threat Intelligence");
        ui::box_line("");
        ui::close_box();

        match terminal::read_input(editor, "\n  Select an option: ", false).as_str() {
            "1" if auth_key.trim().is_empty() => terminal::show_error(
                "Set MALWAREBAZAAR_AUTH_KEY in the environment or .env to use MalwareBazaar.",
            ),
            "1" => match fetch_malware_data(client, auth_key) {
                Ok(data) => {
                    terminal::clear_screen();
                    investigation.add_indicators(display_malware_data(&data, None));
                    terminal::pause();
                }
                Err(error) => terminal::show_source_error(&error.to_string()),
            },
            "2" if auth_key.trim().is_empty() => terminal::show_error(
                "Set MALWAREBAZAAR_AUTH_KEY in the environment or .env to use MalwareBazaar.",
            ),
            "2" => filter_malware_samples(editor, client, auth_key, investigation),
            "0" => break,
            _ => terminal::invalid_choice(),
        }
    }
}

fn filter_malware_samples(
    editor: &mut InputEditor,
    client: &Client,
    auth_key: &str,
    investigation: &mut Investigation,
) {
    terminal::clear_screen();
    ui::header("MALWAREBAZAAR", "Filter recent samples by origin country");
    ui::box_line("  Enter a two-letter country code (for example, NP).");
    ui::navigation_footer("0", "Back / cancel");
    ui::close_box();

    let country = terminal::read_input(editor, "\n  Country code: ", false).to_uppercase();
    if country == "0" {
        return;
    }
    if country.len() != 2
        || !country
            .chars()
            .all(|character| character.is_ascii_alphabetic())
    {
        terminal::show_error("Please enter a valid two-letter country code.");
        return;
    }

    match fetch_malware_data(client, auth_key) {
        Ok(data) => {
            terminal::clear_screen();
            investigation.add_indicators(display_malware_data(&data, Some(&country)));
            terminal::pause();
        }
        Err(error) => terminal::show_source_error(&error.to_string()),
    }
}

fn cloudflare_menu(editor: &mut InputEditor, client: &Client, token: &str) {
    loop {
        terminal::clear_screen();
        ui::header("CLOUDFLARE RADAR", "Live Layer 7 attack telemetry");
        ui::box_line("");
        ui::menu_item("1", "Top Attack Origins", "Countries where attacks begin");
        ui::menu_item("2", "Top Attack Targets", "Countries receiving attacks");
        ui::menu_item("3", "Top Attack Pairs", "Origin to target activity");
        ui::box_line("");
        ui::menu_item("0", "Back", "Return to Threat Intelligence");
        ui::box_line("");
        ui::close_box();

        match terminal::read_input(editor, "\n  Select an option: ", false).as_str() {
            "1" if token.trim().is_empty() => terminal::show_error(
                "Set CLOUDFLARE_API_TOKEN in the environment or .env to use Cloudflare Radar.",
            ),
            "1" => run_cloudflare_feed(editor, client, token, Feed::Origins),
            "2" if token.trim().is_empty() => terminal::show_error(
                "Set CLOUDFLARE_API_TOKEN in the environment or .env to use Cloudflare Radar.",
            ),
            "2" => run_cloudflare_feed(editor, client, token, Feed::Targets),
            "3" if token.trim().is_empty() => terminal::show_error(
                "Set CLOUDFLARE_API_TOKEN in the environment or .env to use Cloudflare Radar.",
            ),
            "3" => run_cloudflare_feed(editor, client, token, Feed::Pairs),
            "0" => break,
            _ => terminal::invalid_choice(),
        }
    }
}

fn run_cloudflare_feed(editor: &mut InputEditor, client: &Client, token: &str, feed: Feed) {
    let Some(interval) = choose_refresh_interval(editor) else {
        return;
    };

    const MAX_REFRESHES: usize = 5;
    for refresh in 0..MAX_REFRESHES {
        terminal::clear_screen();
        ui::header("CLOUDFLARE RADAR", "Live Layer 7 attack telemetry");
        ui::box_line("");

        match feed {
            Feed::Origins => match fetch_cloudflare_data(client, token) {
                Ok(data) if data.success => display_top_origins(&data.result),
                Ok(_) => ui::error("Cloudflare returned an unsuccessful response."),
                Err(error) => {
                    ui::error("Cloudflare request failed.");
                    ui::field("Details", error);
                }
            },
            Feed::Targets => match fetch_cloudflare_targets(client, token) {
                Ok(data) if data.success => display_top_targets(&data.result),
                Ok(_) => ui::error("Cloudflare returned an unsuccessful response."),
                Err(error) => {
                    ui::error("Cloudflare request failed.");
                    ui::field("Details", error);
                }
            },
            Feed::Pairs => match fetch_cloudflare_attack_pairs(client, token) {
                Ok(data) if data.success => display_top_attack_pairs(&data.result),
                Ok(_) => ui::error("Cloudflare returned an unsuccessful response."),
                Err(error) => {
                    ui::error("Cloudflare request failed.");
                    ui::field("Details", error);
                }
            },
        }

        ui::box_line("");
        ui::divider();
        let current = refresh + 1;
        if current < MAX_REFRESHES {
            ui::centered_box_line(&format!(
                "Refresh {current}/{MAX_REFRESHES} • Next update in {}",
                terminal::format_duration(interval)
            ));
            ui::centered_box_line("Esc / q: Stop live refresh and return to Cloudflare Radar");
            ui::close_box();
            if terminal::wait_for_refresh(interval) {
                return;
            }
        } else {
            ui::centered_box_line("Refresh limit reached");
            ui::close_box();
            terminal::pause();
        }
    }
}

fn choose_refresh_interval(editor: &mut InputEditor) -> Option<Duration> {
    loop {
        terminal::clear_screen();
        ui::header(
            "REFRESH INTERVAL",
            "Choose how often Cloudflare data refreshes",
        );
        ui::box_line("");
        ui::menu_item("1", "5 seconds", "Fast refresh");
        ui::menu_item("2", "10 seconds", "Short refresh");
        ui::menu_item("3", "30 seconds", "Moderate refresh");
        ui::menu_item("4", "1 minute", "Long refresh");
        ui::menu_item("5", "5 minutes", "Slow refresh");
        ui::box_line("");
        ui::menu_item("0", "Back", "Return to Cloudflare Radar");
        ui::box_line("");
        ui::close_box();

        match terminal::read_input(editor, "\n  Select an option: ", false).as_str() {
            "1" => return Some(Duration::from_secs(5)),
            "2" => return Some(Duration::from_secs(10)),
            "3" => return Some(Duration::from_secs(30)),
            "4" => return Some(Duration::from_secs(60)),
            "5" => return Some(Duration::from_secs(300)),
            "0" => return None,
            _ => terminal::invalid_choice(),
        }
    }
}
