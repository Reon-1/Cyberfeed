mod file_workflow;
mod indicator_list;
mod menu;
pub(crate) mod provider_views;
mod saved_reports;
mod terminal;
mod threat_menu;

use crate::config::Config;
use reqwest::blocking::Client;

pub fn run(client: &Client, config: &Config) {
    let _terminal = match crate::tui::TerminalSession::new() {
        Ok(terminal) => terminal,
        Err(error) => {
            eprintln!("Could not initialize the terminal UI: {error}");
            return;
        }
    };
    menu::run(client, config);
}
