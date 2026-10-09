mod file_workflow;
mod menu;
mod terminal;
mod threat_menu;

use crate::config::Config;
use reqwest::blocking::Client;

pub fn run(client: &Client, config: &Config) {
    menu::run(client, config);
}
