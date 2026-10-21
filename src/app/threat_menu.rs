use super::provider_views::{
    display_malware_data, display_top_attack_pairs, display_top_origins, display_top_targets,
};
use super::terminal::{self, InputEditor};
use crate::investigation::Investigation;
use crate::providers::cloudflare::{
    fetch_cloudflare_attack_pairs, fetch_cloudflare_data, fetch_cloudflare_targets,
};
use crate::providers::malwarebazaar::fetch_malware_data;
use crate::tui;
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
        tui::header("THREAT FEEDS", "Browse optional, live public data");
        tui::box_line("");
        tui::menu_item(
            "1",
            "MalwareBazaar",
            "Browse recently reported malware samples",
        );
        tui::menu_item("2", "Cloudflare Radar", "View broad internet attack trends");
        tui::box_line("");
        tui::menu_item("0", "Back", "Return to the main menu");
        tui::box_line("");

        let Some(selection) = terminal::read_input(editor, "\n  Select an option: ", false) else {
            break;
        };
        match selection.as_str() {
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
        tui::header("MALWAREBAZAAR", "Recently reported malware samples");
        tui::box_line("");
        tui::menu_item(
            "1",
            "Recent Samples",
            "View the latest MalwareBazaar samples",
        );
        tui::menu_item("2", "Choose a Country", "Narrow the sample list by country");
        tui::box_line("");
        tui::menu_item("0", "Back", "Return to Threat Intelligence");
        tui::box_line("");

        let Some(selection) = terminal::read_input(editor, "\n  Select an option: ", false) else {
            break;
        };
        match selection.as_str() {
            "1" if auth_key.trim().is_empty() => terminal::show_error(
                "Set ABUSECH_AUTH_KEY in the environment or .env to use MalwareBazaar.",
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
                "Set ABUSECH_AUTH_KEY in the environment or .env to use MalwareBazaar.",
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
    tui::header("MALWAREBAZAAR", "Filter recent samples by origin country");
    tui::box_line("  Enter a two-letter country code (for example, NP).");
    tui::navigation_footer("0", "Back / cancel");

    let Some(country) = terminal::read_input(editor, "\n  Country code: ", false) else {
        return;
    };
    let country = country.to_uppercase();
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
        tui::header("CLOUDFLARE RADAR", "Live internet attack trends");
        tui::box_line("");
        tui::menu_item("1", "Top Attack Origins", "Countries where attacks begin");
        tui::menu_item("2", "Top Attack Targets", "Countries receiving attacks");
        tui::menu_item("3", "Top Attack Pairs", "Origin to target activity");
        tui::box_line("");
        tui::menu_item("0", "Back", "Return to Threat Intelligence");
        tui::box_line("");

        let Some(selection) = terminal::read_input(editor, "\n  Select an option: ", false) else {
            break;
        };
        match selection.as_str() {
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
        tui::header("CLOUDFLARE RADAR", "Live internet attack trends");
        show_refresh_progress(feed, refresh + 1, MAX_REFRESHES);

        let succeeded = match feed {
            Feed::Origins => match fetch_cloudflare_data(client, token) {
                Ok(data) if data.success => {
                    display_top_origins(&data.result);
                    true
                }
                Ok(_) => {
                    tui::error("Cloudflare returned an unsuccessful response.");
                    false
                }
                Err(error) => {
                    tui::error("Cloudflare request failed.");
                    tui::field("Details", error);
                    false
                }
            },
            Feed::Targets => match fetch_cloudflare_targets(client, token) {
                Ok(data) if data.success => {
                    display_top_targets(&data.result);
                    true
                }
                Ok(_) => {
                    tui::error("Cloudflare returned an unsuccessful response.");
                    false
                }
                Err(error) => {
                    tui::error("Cloudflare request failed.");
                    tui::field("Details", error);
                    false
                }
            },
            Feed::Pairs => match fetch_cloudflare_attack_pairs(client, token) {
                Ok(data) if data.success => {
                    display_top_attack_pairs(&data.result);
                    true
                }
                Ok(_) => {
                    tui::error("Cloudflare returned an unsuccessful response.");
                    false
                }
                Err(error) => {
                    tui::error("Cloudflare request failed.");
                    tui::field("Details", error);
                    false
                }
            },
        };
        tui::status(
            "Refresh",
            if succeeded {
                "Complete"
            } else {
                "Failed · see details"
            },
            if succeeded {
                tui::Status::Success
            } else {
                tui::Status::Error
            },
        );
        tui::redraw_current_screen();

        tui::box_line("");
        tui::divider();
        let current = refresh + 1;
        if current < MAX_REFRESHES {
            tui::box_line(&format!(
                "Refresh {current}/{MAX_REFRESHES} • Next update in {}",
                terminal::format_duration(interval)
            ));
            tui::box_line("Esc / q stops automatic refresh after this response completes");
            tui::redraw_current_screen();
            if terminal::wait_for_refresh(interval) {
                return;
            }
        } else {
            tui::box_line("Refresh limit reached");
            terminal::pause();
        }
    }
}

fn show_refresh_progress(feed: Feed, current: usize, total: usize) {
    let label = match feed {
        Feed::Origins => "attack origins",
        Feed::Targets => "attack targets",
        Feed::Pairs => "origin-to-target pairs",
    };
    tui::progress_line(
        &format!("Request {current}/{total}: fetching {label} from Cloudflare Radar…"),
        tui::Status::Warning,
    );
    tui::note("This feed arrives as one response; results appear when that response is parsed.");
    tui::redraw_current_screen();
}

fn choose_refresh_interval(editor: &mut InputEditor) -> Option<Duration> {
    loop {
        terminal::clear_screen();
        tui::header(
            "REFRESH INTERVAL",
            "Choose how often Cloudflare data refreshes",
        );
        tui::box_line("");
        tui::menu_item("1", "5 seconds", "Fast refresh");
        tui::menu_item("2", "10 seconds", "Short refresh");
        tui::menu_item("3", "30 seconds", "Moderate refresh");
        tui::menu_item("4", "1 minute", "Long refresh");
        tui::menu_item("5", "5 minutes", "Slow refresh");
        tui::box_line("");
        tui::menu_item("0", "Back", "Return to Cloudflare Radar");
        tui::box_line("");

        let selection = terminal::read_input(editor, "\n  Select an option: ", false)?;
        match selection.as_str() {
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

#[cfg(test)]
mod tests {
    use super::{Feed, show_refresh_progress};

    #[test]
    fn cloudflare_refresh_progress_is_visible_before_the_single_response_arrives() {
        crate::tui::reset_screen();
        crate::tui::header("CLOUDFLARE RADAR", "Live internet attack trends");
        show_refresh_progress(Feed::Targets, 2, 5);
        let rendered = crate::tui::test_rendered_lines(80, 12).join("\n");
        assert!(rendered.contains("Request 2/5"));
        assert!(rendered.contains("fetching attack targets"));
        assert!(rendered.contains("one response"));
        assert!(rendered.contains("CLOUDFLARE RADAR"));
    }
}
