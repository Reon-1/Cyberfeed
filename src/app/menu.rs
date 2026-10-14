use super::file_workflow;
use super::saved_reports;
use super::terminal::{self, InputEditor};
use super::threat_menu;
use crate::config::Config;
use crate::investigation::Investigation;
use crate::ui;
use reqwest::blocking::Client;

const INVESTIGATION_MENU_OPTIONS: [(&str, &str, &str); 3] = [
    (
        "1",
        "Check a Value",
        "Search a hash, IP address, domain, or web address",
    ),
    (
        "2",
        "Review This Session",
        "See the values checked and results recorded so far",
    ),
    ("0", "Back", "Return to the main menu"),
];

const MORE_MENU_OPTIONS: [(&str, &str, &str); 6] = [
    (
        "1",
        "Offline Demo",
        "Try a simulated example; no internet or credentials needed",
    ),
    (
        "2",
        "Check Setup",
        "See whether local reports and provider credentials are configured",
    ),
    (
        "3",
        "Configure Providers",
        "Add, replace, or remove saved credentials",
    ),
    (
        "4",
        "Batch Check Files",
        "Inspect up to 100 local files without provider lookups",
    ),
    (
        "5",
        "Threat Feeds",
        "Browse live MalwareBazaar and Cloudflare Radar data",
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
    let abusech_auth_key = config.abusech_auth_key.as_deref().unwrap_or("");

    loop {
        terminal::clear_screen();
        ui::header("CYBERFEED", "Check files, search logs, and review evidence");
        ui::box_line("");
        ui::menu_item("1", "Check a File", "Analyze a file on this computer");
        ui::menu_item(
            "2",
            "Current Session",
            "Check a value or review results from this session",
        );
        ui::menu_item(
            "3",
            "Search Logs",
            "Find IPs, domains, URLs, and hashes in a local text or JSONL log",
        );
        ui::menu_item(
            "4",
            "Saved Reports",
            "Review past file and log investigations",
        );
        ui::box_line("");
        ui::menu_item(
            "5",
            "More Tools",
            "Offline demo, setup check, batch files, and live threat feeds",
        );
        ui::note("File checks, log searches, and saved reports work without provider credentials.");
        ui::navigation_footer("0", "Exit · choose 1–5 above");
        ui::close_box();

        match terminal::read_input(&mut editor, "\n  Choose an option (0 to exit): ", false)
            .as_str()
        {
            "1" => file_workflow::investigate_file(
                &mut editor,
                client,
                abusech_auth_key,
                &mut investigation,
            ),
            "2" => investigation_menu(&mut editor, client, abusech_auth_key, &mut investigation),
            "3" => log_hunt(&mut editor),
            "4" => saved_reports::menu(&mut editor),
            "5" => more_menu(
                &mut editor,
                client,
                config,
                cloudflare_token,
                abusech_auth_key,
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

fn more_menu(
    editor: &mut InputEditor,
    client: &Client,
    config: &Config,
    cloudflare_token: &str,
    abusech_auth_key: &str,
    investigation: &mut Investigation,
) {
    loop {
        terminal::clear_screen();
        ui::header("MORE TOOLS", "Optional setup and external threat feeds");
        ui::note(
            "The demo is offline; configure credentials here. Threat feeds make live requests.",
        );
        for (key, label, description) in MORE_MENU_OPTIONS {
            ui::menu_item(key, label, description);
        }
        ui::navigation_footer("0", "Back to the main menu");
        ui::close_box();
        match terminal::read_input(editor, "\n  Choose an option (0 to go back): ", false).as_str()
        {
            "1" => offline_demo(),
            "2" => setup_diagnostics(config),
            "3" => configure_providers(editor, config),
            "4" => batch_triage(editor),
            "5" => threat_menu::menu(
                editor,
                client,
                cloudflare_token,
                abusech_auth_key,
                investigation,
            ),
            "0" => break,
            _ => terminal::invalid_choice(),
        }
    }
}

fn configure_providers(editor: &mut InputEditor, config: &Config) {
    use std::path::Path;

    loop {
        terminal::clear_screen();
        ui::header(
            "CONFIGURE PROVIDERS",
            "Credentials are optional and never tested here",
        );
        ui::note("MalwareBazaar, ThreatFox, and URLhaus share ABUSECH_AUTH_KEY.");
        ui::note("Cloudflare Radar uses CLOUDFLARE_API_TOKEN.");
        ui::status(
            "abuse.ch key",
            if config.abusech_auth_key.is_some() {
                "Present · authentication not verified"
            } else {
                "Not configured"
            },
            ui::Status::Neutral,
        );
        ui::status(
            "Cloudflare token",
            if config.cloudflare_token.is_some() {
                "Present · authentication not verified"
            } else {
                "Not configured"
            },
            ui::Status::Neutral,
        );
        ui::note(
            "Saved values go in .env as plaintext. Existing environment variables take precedence over .env.",
        );
        ui::note(
            "Changes are read at startup; restart CyberFeed after saving or removing a value.",
        );
        ui::menu_item("1", "abuse.ch Services", "Set or remove the shared key");
        ui::menu_item("2", "Cloudflare Radar", "Set or remove the Radar token");
        ui::navigation_footer("0", "Back");
        ui::close_box();
        match terminal::read_input(editor, "  Choose a provider (0 to go back): ", false).as_str() {
            "1" => edit_credential(editor, "ABUSECH_AUTH_KEY", "abuse.ch"),
            "2" => edit_credential(editor, "CLOUDFLARE_API_TOKEN", "Cloudflare Radar"),
            "0" => break,
            _ => terminal::invalid_choice(),
        }
    }

    fn edit_credential(editor: &mut InputEditor, key: &str, provider: &str) {
        use crate::config::{CredentialChange, apply_credential_change};

        terminal::clear_screen();
        ui::header("UPDATE CREDENTIAL", provider);
        ui::note("The value is hidden while you type and is never tested automatically.");
        ui::warning("The .env file stores credentials as plaintext. Keep it private.");
        ui::menu_item("1", "Add or Replace", "Enter a new credential");
        ui::menu_item("2", "Remove Saved Value", "Delete this key from .env");
        ui::navigation_footer("0", "Cancel");
        ui::close_box();
        let action = terminal::read_input(editor, "  Choose an action (0 to cancel): ", false);
        let result = match action.as_str() {
            "1" => {
                let Some(secret) = terminal::read_secret("  New credential (hidden): ") else {
                    return;
                };
                if secret.is_empty()
                    || !terminal::read_input(
                        editor,
                        "  Save this value to .env as plaintext? [y/N]: ",
                        false,
                    )
                    .eq_ignore_ascii_case("y")
                {
                    return;
                }
                apply_credential_change(Path::new(".env"), key, CredentialChange::Set(&secret))
            }
            "2" => {
                if !terminal::read_input(editor, "  Remove this key from .env? [y/N]: ", false)
                    .eq_ignore_ascii_case("y")
                {
                    return;
                }
                apply_credential_change(Path::new(".env"), key, CredentialChange::Remove)
            }
            "0" => apply_credential_change(Path::new(".env"), key, CredentialChange::Cancel),
            _ => return,
        };
        match result {
            Ok(true) => {
                terminal::clear_screen();
                ui::header(
                    "CONFIGURATION UPDATED",
                    "Restart CyberFeed to apply the change",
                );
                ui::status(
                    "Credential",
                    "Saved without displaying its value",
                    ui::Status::Success,
                );
                ui::navigation_footer("Enter", "Return");
                ui::close_box();
                terminal::pause();
            }
            Ok(false) => {}
            Err(_) => terminal::show_error(
                "The .env update or cleanup reported a filesystem problem. No credential value was displayed; review .env and any temporary files before retrying.",
            ),
        }
    }
}

fn batch_triage(editor: &mut InputEditor) {
    use crate::file::inspect_file;
    use crate::report::InvestigationReport;
    use std::{
        fs,
        path::{Path, PathBuf},
    };
    terminal::clear_screen();
    ui::header(
        "BATCH LOCAL TRIAGE",
        "Bounded local inspection · no provider requests",
    );
    ui::note(
        "Enter semicolon-separated file paths or one directory. Directories are scanned one level only.",
    );
    ui::note(
        "Maximum 100 files; extracted indicators are capped at 10,000 per file by the inspection pipeline.",
    );
    ui::navigation_footer("0", "Cancel");
    ui::close_box();
    let input = terminal::read_input(editor, "  Paths: ", true);
    if input == "0" || input.trim().is_empty() {
        return;
    }
    let mut paths = Vec::<PathBuf>::new();
    let mut errors = Vec::new();
    let pieces = input
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    for piece in pieces {
        let path = PathBuf::from(piece);
        if path.is_dir() {
            match fs::read_dir(&path) {
                Ok(entries) => {
                    for entry in entries.take(100usize.saturating_sub(paths.len())) {
                        match entry {
                            Ok(entry) if entry.file_type().is_ok_and(|ty| ty.is_file()) => {
                                paths.push(entry.path())
                            }
                            Ok(_) => {}
                            Err(error) => errors.push(format!(
                                "{}: could not read directory entry: {error}",
                                path.display()
                            )),
                        }
                    }
                }
                Err(e) => errors.push(format!("Could not scan '{}': {e}", path.display())),
            }
        } else {
            paths.push(path);
        }
        if paths.len() >= 100 {
            break;
        }
    }
    let mut processed = 0usize;
    let mut saved = Vec::new();
    for path in paths {
        match inspect_file(&path) {
            Ok(inspection) => {
                processed += 1;
                let indicators = inspection
                    .text_indicators
                    .as_ref()
                    .map(|t| t.indicators.clone())
                    .unwrap_or_default();
                let extraction = inspection.text_indicators.as_ref().map(|t| t.limit_reached);
                let report =
                    InvestigationReport::new(&inspection.info, indicators, extraction, vec![]);
                match crate::report::save_report(&report, Path::new("reports")) {
                    Ok((json, _)) => saved.push(json),
                    Err(error) => {
                        errors.push(format!("{}: report save failed: {error}", path.display()))
                    }
                }
            }
            Err(error) => errors.push(error),
        }
    }
    terminal::clear_screen();
    ui::header("BATCH TRIAGE SUMMARY", "Local inspection results");
    ui::field("Processed files", processed);
    ui::field("Errors", errors.len());
    ui::field("Saved JSON reports", saved.len());
    for path in saved {
        ui::field("Report", path.display());
    }
    for error in errors {
        ui::field("File error", error);
    }
    ui::warning(
        "Batch mode performed local extraction only. No provider outcomes were requested or inferred.",
    );
    ui::navigation_footer("Enter", "Return");
    ui::close_box();
    terminal::pause();
}

fn log_hunt(editor: &mut InputEditor) {
    use crate::{file::FileInfo, log_hunt::inspect_log, report::InvestigationReport};
    use std::path::Path;
    terminal::clear_screen();
    ui::header(
        "LOCAL LOG HUNT",
        "Text and JSONL · streamed · no content uploads",
    );
    ui::note(
        "Supported input: ordinary UTF-8 text and one JSON object per .jsonl line. No vendor-specific schemas are assumed.",
    );
    ui::note(
        "Limits: 64 MiB per file, 16 KiB per line, 1,000 unique indicators, 10,000 occurrences.",
    );
    ui::note("This mode extracts locally and does not enrich through providers.");
    ui::navigation_footer("0", "Cancel");
    ui::close_box();
    let input = terminal::read_input(editor, "  Log path: ", true);
    if input == "0" || input.trim().is_empty() {
        return;
    }
    match inspect_log(Path::new(input.trim())) {
        Err(error) => terminal::show_error(&error),
        Ok(hunt) => {
            let path = Path::new(input.trim());
            let filename = path
                .file_name()
                .unwrap_or(path.as_os_str())
                .to_string_lossy()
                .into_owned();
            let mut report = InvestigationReport::new(
                &FileInfo {
                    name: filename,
                    size: hunt.size_bytes,
                    sha256: hunt.sha256,
                },
                hunt.indicators,
                Some(hunt.limit_reached),
                vec![],
            );
            report.local_inspection.source_occurrences = hunt.occurrences;
            terminal::clear_screen();
            ui::header(
                "LOG HUNT RESULTS",
                "Locally observed values · no provider intelligence",
            );
            ui::field(
                "Unique indicators",
                report.local_inspection.indicators.len(),
            );
            ui::field(
                "Occurrences with locations",
                report.local_inspection.source_occurrences.len(),
            );
            ui::field("Input limit reached", hunt.limit_reached);
            for occurrence in report.local_inspection.source_occurrences.iter().take(15) {
                ui::field(
                    "Occurrence",
                    format!(
                        "{}:{} · {} · {}",
                        occurrence.source_filename,
                        occurrence.line_number,
                        occurrence.indicator.indicator_type.as_str(),
                        occurrence.original_value
                    ),
                );
                ui::field("Context", &occurrence.context);
            }
            ui::warning(
                "Observed log values are leads, not provider findings or proof of malicious activity.",
            );
            match crate::report::save_report(&report, Path::new("reports")) {
                Ok((json, markdown)) => {
                    ui::field("JSON report", json.display());
                    ui::field("Markdown report", markdown.display());
                }
                Err(error) => ui::field("Report save error", error),
            }
            ui::navigation_footer("Enter", "Return");
            ui::close_box();
            terminal::pause();
        }
    }
}

fn setup_diagnostics(config: &Config) {
    terminal::clear_screen();
    ui::header(
        "SETUP DIAGNOSTICS",
        "Local checks only · no network requests",
    );
    ui::section("PROVIDER CONFIGURATION");
    ui::field(
        "MalwareBazaar",
        if config.abusech_auth_key.is_some() {
            "Credential present · authentication not checked"
        } else {
            "Not configured · local features remain available"
        },
    );
    ui::field(
        "ThreatFox",
        if config.abusech_auth_key.is_some() {
            "Credential present · authentication not checked"
        } else {
            "Not configured · local features remain available"
        },
    );
    ui::field(
        "URLhaus",
        if config.abusech_auth_key.is_some() {
            "Credential present · authentication not checked"
        } else {
            "Not configured · local features remain available"
        },
    );
    ui::field(
        "Cloudflare Radar",
        if config.cloudflare_token.is_some() {
            "Token present · authentication not checked"
        } else {
            "Not configured"
        },
    );
    let report_dir = std::path::Path::new("reports");
    let writable = std::fs::create_dir_all(report_dir)
        .and_then(|_| {
            let probe = report_dir.join(format!(".cyberfeed-diagnostic-{}", std::process::id()));
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&probe)
                .and_then(|f| {
                    drop(f);
                    std::fs::remove_file(probe)
                })
        })
        .is_ok();
    ui::section("LOCAL PREREQUISITES");
    ui::field(
        "Report directory",
        if writable {
            "reports/ accessible and writable"
        } else {
            "reports/ unavailable or not writable"
        },
    );
    ui::field("Network check", "Not performed");
    ui::navigation_footer("Enter", "Return");
    ui::close_box();
    terminal::pause();
}

fn offline_demo() {
    use crate::file::FileInfo;
    use crate::indicator::{Indicator, IndicatorType};
    use crate::report::{
        InvestigationReport, LookupOutcome, LookupSubject, MatchDetails, ProviderLookup,
    };
    terminal::clear_screen();
    ui::header(
        "OFFLINE DEMO",
        "DEMO DATA · simulated provider responses · no requests",
    );
    ui::warning("Every finding on this screen is synthetic training data, not live intelligence.");
    ui::section("SAMPLE INVESTIGATION");
    ui::field("Artifact", "training-sample.txt · read locally as data");
    ui::field(
        "SHA-256",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    ui::field("Extracted indicator", "https://demo.invalid/payload.exe");
    ui::section("SIMULATED PROVIDER OUTCOMES");
    ui::field("MalwareBazaar", "DEMO FOUND · synthetic hash record");
    ui::field("ThreatFox", "DEMO NOT FOUND · synthetic response");
    ui::field("URLhaus", "DEMO NOT CONFIGURED · no request made");
    ui::section("EVIDENCE AND REPORT PREVIEW");
    let file = FileInfo {
        name: "training-sample.txt".into(),
        size: 64,
        sha256: "a".repeat(64),
    };
    let mut demo = InvestigationReport::new(
        &file,
        vec![Indicator::new(
            "https://demo.invalid/payload.exe",
            IndicatorType::Url,
        )],
        Some(false),
        vec![
            ProviderLookup {
                provider: "DEMO MalwareBazaar".into(),
                subject: LookupSubject::OriginalFileSha256,
                queried_hash: file.sha256.clone(),
                retrieved_at_unix_seconds: Some(1_700_000_000),
                outcome: LookupOutcome::Found(MatchDetails {
                    matched_sha256: file.sha256.clone(),
                    first_seen: "DEMO 2025-01-01".into(),
                    file_type: "DEMO TEXT".into(),
                    sample_filename: Some("demo-only.txt".into()),
                    signature: Some("SIMULATED TRAINING RECORD".into()),
                }),
            },
            ProviderLookup {
                provider: "DEMO ThreatFox".into(),
                subject: LookupSubject::ExtractedIndicator,
                queried_hash: "https://demo.invalid/payload.exe".into(),
                retrieved_at_unix_seconds: Some(1_700_000_001),
                outcome: LookupOutcome::NotFound,
            },
            ProviderLookup {
                provider: "DEMO URLhaus".into(),
                subject: LookupSubject::ExtractedIndicator,
                queried_hash: "https://demo.invalid/payload.exe".into(),
                retrieved_at_unix_seconds: None,
                outcome: LookupOutcome::NotConfigured,
            },
        ],
    );
    demo.summary.original_file_lookup_status = Some("DEMO FOUND (SYNTHETIC)".into());
    for line in demo.to_markdown().lines().take(14) {
        ui::box_line(line);
    }
    ui::box_line("DEMO: no provider requests were made; no report was saved.");
    ui::navigation_footer("Enter", "Return");
    ui::close_box();
    terminal::pause();
}

fn investigation_menu(
    editor: &mut InputEditor,
    client: &Client,
    auth_key: &str,
    investigation: &mut Investigation,
) {
    loop {
        terminal::clear_screen();
        ui::header("CURRENT SESSION", "Check a value or review results");
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
    use super::{INVESTIGATION_MENU_OPTIONS, MORE_MENU_OPTIONS};

    #[test]
    fn investigation_menu_has_review_and_indicator_actions_without_duplicate_file_check() {
        let labels: Vec<&str> = INVESTIGATION_MENU_OPTIONS
            .iter()
            .map(|(_, label, _)| *label)
            .collect();

        assert_eq!(labels, ["Check a Value", "Review This Session", "Back"]);
        assert!(!labels.contains(&"Check a File"));
    }

    #[test]
    fn more_tools_groups_optional_actions_and_uses_zero_to_go_back() {
        let labels: Vec<&str> = MORE_MENU_OPTIONS
            .iter()
            .map(|(_, label, _)| *label)
            .collect();
        assert_eq!(
            labels,
            [
                "Offline Demo",
                "Check Setup",
                "Configure Providers",
                "Batch Check Files",
                "Threat Feeds",
                "Back"
            ]
        );
    }
}
