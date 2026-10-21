use super::file_workflow;
use super::saved_reports;
use super::terminal::{self, InputEditor};
use super::threat_menu;
use crate::config::Config;
use crate::investigation::Investigation;
use crate::tui;
use reqwest::blocking::Client;

const MAIN_MENU_OPTIONS: [(&str, &str, &str); 6] = [
    ("1", "Check a File", "Analyze a file on this computer"),
    (
        "2",
        "Current Session",
        "Check a value, review results, or save this session",
    ),
    (
        "3",
        "Search Logs",
        "Find IPs, domains, URLs, and hashes in a local text or JSONL log",
    ),
    (
        "4",
        "Saved Reports",
        "Review past file, session, and log investigations",
    ),
    (
        "5",
        "More Tools",
        "Offline demo, setup check, batch files, and live threat feeds",
    ),
    ("0", "Exit", "Leave CyberFeed and restore the terminal"),
];

const INVESTIGATION_MENU_OPTIONS: [(&str, &str, &str); 5] = [
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
    (
        "3",
        "Compare Indicator Lists",
        "Preview and compare indicators from two or more text files locally",
    ),
    (
        "4",
        "Save This Session",
        "Save all completed file and value checks as one report",
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

#[derive(Debug, PartialEq, Eq)]
enum MainMenuAction {
    CheckFile,
    CurrentSession,
    SearchLogs,
    SavedReports,
    MoreTools,
    Exit,
}

fn main_menu_action(selection: &str) -> Option<MainMenuAction> {
    Some(match selection {
        "1" => MainMenuAction::CheckFile,
        "2" => MainMenuAction::CurrentSession,
        "3" => MainMenuAction::SearchLogs,
        "4" => MainMenuAction::SavedReports,
        "5" => MainMenuAction::MoreTools,
        "0" => MainMenuAction::Exit,
        _ => return None,
    })
}

#[derive(Debug, PartialEq, Eq)]
enum SessionMenuAction {
    CheckValue,
    Review,
    CompareLists,
    Save,
    Back,
}

fn session_menu_action(selection: &str) -> Option<SessionMenuAction> {
    Some(match selection {
        "1" => SessionMenuAction::CheckValue,
        "2" => SessionMenuAction::Review,
        "3" => SessionMenuAction::CompareLists,
        "4" => SessionMenuAction::Save,
        "0" => SessionMenuAction::Back,
        _ => return None,
    })
}

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
        let selection = tui::terminal::select_menu(
            "CyberFeed",
            "Check files, search logs, and review evidence. Local workflows need no credentials.",
            &MAIN_MENU_OPTIONS,
        );
        match main_menu_action(&selection) {
            Some(MainMenuAction::CheckFile) => file_workflow::investigate_file(
                &mut editor,
                client,
                abusech_auth_key,
                &mut investigation,
            ),
            Some(MainMenuAction::CurrentSession) => {
                investigation_menu(&mut editor, client, abusech_auth_key, &mut investigation)
            }
            Some(MainMenuAction::SearchLogs) => log_hunt(&mut editor),
            Some(MainMenuAction::SavedReports) => saved_reports::menu(&mut editor),
            Some(MainMenuAction::MoreTools) => more_menu(
                &mut editor,
                client,
                config,
                cloudflare_token,
                abusech_auth_key,
                &mut investigation,
            ),
            Some(MainMenuAction::Exit) => {
                terminal::clear_screen();
                println!("Goodbye.");
                break;
            }
            None => terminal::invalid_choice(),
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
        match tui::terminal::select_menu(
            "More Tools",
            "Offline demo needs no network. Threat feeds make live requests.",
            &MORE_MENU_OPTIONS,
        )
        .as_str()
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
        tui::header(
            "CONFIGURE PROVIDERS",
            "Credentials are optional and never tested here",
        );
        tui::note("MalwareBazaar, ThreatFox, and URLhaus share ABUSECH_AUTH_KEY.");
        tui::note("Cloudflare Radar uses CLOUDFLARE_API_TOKEN.");
        tui::status(
            "abuse.ch key",
            if config.abusech_auth_key.is_some() {
                "Present · authentication not verified"
            } else {
                "Not configured"
            },
            tui::Status::Neutral,
        );
        tui::status(
            "Cloudflare token",
            if config.cloudflare_token.is_some() {
                "Present · authentication not verified"
            } else {
                "Not configured"
            },
            tui::Status::Neutral,
        );
        tui::note(
            "Saved values go in .env as plaintext. Existing environment variables take precedence over .env.",
        );
        tui::note(
            "Changes are read at startup; restart CyberFeed after saving or removing a value.",
        );
        let providers = [
            ("1", "abuse.ch Services", "Set or remove the shared key"),
            ("2", "Cloudflare Radar", "Set or remove the Radar token"),
            ("0", "Back", "Return to More Tools"),
        ];
        match tui::terminal::select_menu(
            "Configure Providers",
            "Credentials remain hidden and are never tested during setup.",
            &providers,
        )
        .as_str()
        {
            "1" => edit_credential(editor, "ABUSECH_AUTH_KEY", "abuse.ch"),
            "2" => edit_credential(editor, "CLOUDFLARE_API_TOKEN", "Cloudflare Radar"),
            "0" => break,
            _ => terminal::invalid_choice(),
        }
    }

    fn edit_credential(editor: &mut InputEditor, key: &str, provider: &str) {
        use crate::config::{CredentialChange, apply_credential_change};

        terminal::clear_screen();
        tui::header("UPDATE CREDENTIAL", provider);
        tui::note("The value is hidden while you type and is never tested automatically.");
        tui::warning("The .env file stores credentials as plaintext. Keep it private.");
        let actions = [
            ("1", "Add or Replace", "Enter a new credential"),
            ("2", "Remove Saved Value", "Delete this key from .env"),
            ("0", "Cancel", "Return without changing configuration"),
        ];
        let action = tui::terminal::select_menu("Update Credential", provider, &actions);
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
                    .is_some_and(|answer| answer.eq_ignore_ascii_case("y"))
                {
                    return;
                }
                apply_credential_change(Path::new(".env"), key, CredentialChange::Set(&secret))
            }
            "2" => {
                if !terminal::read_input(editor, "  Remove this key from .env? [y/N]: ", false)
                    .is_some_and(|answer| answer.eq_ignore_ascii_case("y"))
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
                tui::header(
                    "CONFIGURATION UPDATED",
                    "Restart CyberFeed to apply the change",
                );
                tui::status(
                    "Credential",
                    "Saved without displaying its value",
                    tui::Status::Success,
                );
                tui::navigation_footer("Enter", "Return");
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
    tui::header(
        "BATCH LOCAL TRIAGE",
        "Bounded local inspection · no provider requests",
    );
    tui::note(
        "Enter semicolon-separated file paths or one directory. Directories are scanned one level only.",
    );
    tui::note(
        "Maximum 100 files; extracted indicators are capped at 10,000 per file by the inspection pipeline.",
    );
    tui::navigation_footer("0", "Cancel");
    let Some(input) = terminal::read_input(editor, "  Paths: ", true) else {
        return;
    };
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
    tui::header("BATCH TRIAGE SUMMARY", "Local inspection results");
    tui::field("Processed files", processed);
    tui::field("Errors", errors.len());
    tui::field("Saved JSON reports", saved.len());
    for path in saved {
        tui::field("Report", path.display());
    }
    for error in errors {
        tui::field("File error", error);
    }
    tui::warning(
        "Batch mode performed local extraction only. No provider outcomes were requested or inferred.",
    );
    tui::navigation_footer("Enter", "Return");
    terminal::pause();
}

fn log_hunt(editor: &mut InputEditor) {
    use crate::{file::FileInfo, log_hunt::inspect_log, report::InvestigationReport};
    use std::path::Path;
    terminal::clear_screen();
    tui::header(
        "LOCAL LOG HUNT",
        "Text and JSONL · streamed · no content uploads",
    );
    tui::note(
        "Supported input: ordinary UTF-8 text and one JSON object per .jsonl line. No vendor-specific schemas are assumed.",
    );
    tui::note(
        "Limits: 64 MiB per file, 16 KiB per line, 1,000 unique indicators, 10,000 occurrences.",
    );
    tui::note("This mode extracts locally and does not enrich through providers.");
    tui::navigation_footer("0", "Cancel");
    let Some(input) = terminal::read_input(editor, "  Log path: ", true) else {
        return;
    };
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
            tui::header(
                "LOG HUNT RESULTS",
                "Locally observed values · no provider intelligence",
            );
            tui::field(
                "Unique indicators",
                report.local_inspection.indicators.len(),
            );
            tui::field(
                "Occurrences with locations",
                report.local_inspection.source_occurrences.len(),
            );
            tui::field("Input limit reached", hunt.limit_reached);
            for occurrence in report.local_inspection.source_occurrences.iter().take(15) {
                tui::field(
                    "Occurrence",
                    format!(
                        "{}:{} · {} · {}",
                        occurrence.source_filename,
                        occurrence.line_number,
                        occurrence.indicator.indicator_type.as_str(),
                        occurrence.original_value
                    ),
                );
                tui::field("Context", &occurrence.context);
            }
            tui::warning(
                "Observed log values are leads, not provider findings or proof of malicious activity.",
            );
            match crate::report::save_report(&report, Path::new("reports")) {
                Ok((json, markdown)) => {
                    tui::field("JSON report", json.display());
                    tui::field("Markdown report", markdown.display());
                }
                Err(error) => tui::field("Report save error", error),
            }
            tui::navigation_footer("Enter", "Return");
            terminal::pause();
        }
    }
}

fn setup_diagnostics(config: &Config) {
    terminal::clear_screen();
    tui::header(
        "SETUP DIAGNOSTICS",
        "Local checks only · no network requests",
    );
    tui::section("PROVIDER CONFIGURATION");
    tui::field(
        "MalwareBazaar",
        if config.abusech_auth_key.is_some() {
            "Credential present · authentication not checked"
        } else {
            "Not configured · local features remain available"
        },
    );
    tui::field(
        "ThreatFox",
        if config.abusech_auth_key.is_some() {
            "Credential present · authentication not checked"
        } else {
            "Not configured · local features remain available"
        },
    );
    tui::field(
        "URLhaus",
        if config.abusech_auth_key.is_some() {
            "Credential present · authentication not checked"
        } else {
            "Not configured · local features remain available"
        },
    );
    tui::field(
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
    tui::section("LOCAL PREREQUISITES");
    tui::field(
        "Report directory",
        if writable {
            "reports/ accessible and writable"
        } else {
            "reports/ unavailable or not writable"
        },
    );
    tui::field("Network check", "Not performed");
    tui::navigation_footer("Enter", "Return");
    terminal::pause();
}

fn offline_demo() {
    use crate::file::FileInfo;
    use crate::indicator::{Indicator, IndicatorType};
    use crate::report::{
        InvestigationReport, LookupOutcome, LookupSubject, MatchDetails, ProviderLookup,
    };
    terminal::clear_screen();
    tui::header(
        "OFFLINE DEMO",
        "DEMO DATA · simulated provider responses · no requests",
    );
    tui::warning("Every finding on this screen is synthetic training data, not live intelligence.");
    tui::section("SAMPLE INVESTIGATION");
    tui::field("Artifact", "training-sample.txt · read locally as data");
    tui::field(
        "SHA-256",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    tui::field("Extracted indicator", "https://demo.invalid/payload.exe");
    tui::section("SIMULATED PROVIDER OUTCOMES");
    tui::field("MalwareBazaar", "DEMO FOUND · synthetic hash record");
    tui::field("ThreatFox", "DEMO NOT FOUND · synthetic response");
    tui::field("URLhaus", "DEMO NOT CONFIGURED · no request made");
    tui::section("EVIDENCE AND REPORT PREVIEW");
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
        tui::box_line(line);
    }
    tui::box_line("DEMO: no provider requests were made; no report was saved.");
    tui::navigation_footer("Enter", "Return");
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
        let selection = tui::terminal::select_menu(
            "Current Session",
            "Review independent checks collected during this run.",
            &INVESTIGATION_MENU_OPTIONS,
        );
        match session_menu_action(&selection) {
            Some(SessionMenuAction::CheckValue) => {
                file_workflow::check_indicator(editor, client, auth_key, investigation)
            }
            Some(SessionMenuAction::Review) => file_workflow::view_indicators(investigation),
            Some(SessionMenuAction::CompareLists) => {
                compare_indicator_lists(editor, client, auth_key, investigation)
            }
            Some(SessionMenuAction::Save) => save_session_report(editor, investigation),
            Some(SessionMenuAction::Back) => break,
            None => terminal::invalid_choice(),
        }
    }
}

fn compare_indicator_lists(
    editor: &mut InputEditor,
    client: &Client,
    auth_key: &str,
    investigation: &mut Investigation,
) {
    use crate::app::indicator_list::{Import, import_path};
    use std::path::Path;

    let mut imported = Import::default();
    loop {
        terminal::clear_screen();
        tui::header(
            "COMPARE INDICATOR LISTS",
            "Local preview only; files are not uploaded",
        );
        tui::note("Add at least two text files, one hash, IP, domain, or HTTP(S) URL per line.");
        tui::note(
            "Blank lines and lines beginning with # are ignored. Surrounding whitespace is trimmed.",
        );
        tui::note(
            "Limits: 8 MiB per file, 4,096 bytes per line, 100,000 candidates, and 1,000 URLs.",
        );
        tui::field("Files added", imported.files.len());
        tui::navigation_footer("Esc", "Cancel before any provider lookup");
        let Some(path) = terminal::read_input(editor, "  Indicator-list path: ", true) else {
            return;
        };
        if path.is_empty() {
            terminal::show_error("Enter a file path, or press Escape to cancel.");
            continue;
        }
        match import_path(Path::new(&path), &mut imported) {
            Ok(()) => {}
            Err(error) => {
                terminal::show_error(&format!("Could not read this list: {error}"));
                continue;
            }
        }
        let options = [
            (
                "1",
                "Add another file",
                "Import another list for comparison",
            ),
            ("2", "Review preview", "Continue to the local comparison"),
            ("0", "Cancel", "Return without running provider lookups"),
        ];
        let selection = tui::terminal::select_menu(
            "Indicator Lists",
            "Keep adding files, or review the local preview.",
            &options,
        );
        match selection.as_str() {
            "1" => continue,
            "2" => break,
            _ => return,
        }
    }
    if imported.files.len() < 2 {
        terminal::show_error("At least two readable list files are needed for a comparison.");
        return;
    }
    let unique = imported.unique();
    loop {
        terminal::clear_screen();
        tui::header(
            "INDICATOR LIST PREVIEW",
            "Local classification and overlap; no network requests made",
        );
        tui::section("SOURCES");
        for (path, lines) in imported.files.iter().take(5) {
            tui::field(path, format!("{lines} lines read"));
        }
        if imported.files.len() > 5 {
            tui::note(&format!(
                "{} additional sources were imported.",
                imported.files.len() - 5
            ));
        }
        tui::section("COLLECTED INDICATORS");
        tui::field("Unique valid", unique.len());
        for kind in [
            crate::indicator::IndicatorType::Hash,
            crate::indicator::IndicatorType::IP,
            crate::indicator::IndicatorType::Domain,
            crate::indicator::IndicatorType::Url,
        ] {
            let count = unique
                .iter()
                .filter(|indicator| indicator.indicator_type == kind)
                .count();
            if count > 0 {
                tui::field(kind.as_str(), count);
            }
        }
        let (common, left_only, right_only) = imported.comparisons();
        tui::field("Common to first two", common);
        tui::field("Only in first", left_only);
        tui::field("Only in second", right_only);
        tui::field("Duplicate occurrences", imported.duplicates);
        tui::field("Invalid candidates", imported.invalid.len());
        let provider_state = if auth_key.trim().is_empty() {
            "Not configured"
        } else {
            "Configured"
        };
        tui::field("abuse.ch providers", provider_state);
        if imported.limited {
            tui::warning("A documented input limit was reached; this preview is incomplete.");
        }
        tui::note("Provider matches describe an indicator; NOT FOUND does not establish safety.");
        tui::note("Each valid occurrence retains its source path and line during this preview.");
        tui::navigation_footer("Enter", "Review indicator examples and invalid lines");
        terminal::pause();

        terminal::clear_screen();
        tui::header(
            "LIST EVIDENCE",
            "Example values retain source file and line",
        );
        tui::section("PROVIDER ROUTING");
        tui::field("MalwareBazaar", format!("{provider_state} · hashes only"));
        tui::field(
            "ThreatFox",
            format!("{provider_state} · supported hash, IP, domain, and URL types"),
        );
        tui::field(
            "URLhaus",
            format!("{provider_state} · URL, host, MD5, and SHA-256"),
        );
        tui::section("VALID VALUES (FIRST 8)");
        for indicator in unique.iter().take(8) {
            let first = imported
                .occurrences
                .iter()
                .find(|occ| occ.indicator == *indicator);
            if let Some(occ) = first {
                tui::field(
                    &format!(
                        "{} · {}:{}",
                        indicator.indicator_type.as_str(),
                        occ.source,
                        occ.line
                    ),
                    &indicator.value,
                );
            }
        }
        if unique.len() > 8 {
            tui::note(
                "Showing the first 8 values; use the follow-up menu to select from the first 30.",
            );
        }
        if !imported.invalid.is_empty() {
            tui::section("INVALID LINES (FIRST 5)");
            for (source, line, value) in imported.invalid.iter().take(5) {
                tui::field(&format!("{source}:{line}"), value);
            }
            if imported.invalid.len() > 5 {
                tui::note(&format!(
                    "{} more invalid candidates are omitted from this screen.",
                    imported.invalid.len() - 5
                ));
            }
        }
        tui::note("Invalid lines were not sent to providers. No prose extraction is performed.");
        tui::navigation_footer("Enter", "Choose an optional provider lookup");
        terminal::pause();

        terminal::clear_screen();
        let mut options = vec![(
            "0".to_owned(),
            "Return".to_owned(),
            "Back to Current Session".to_owned(),
        )];
        for (index, indicator) in unique.iter().take(30).enumerate() {
            let source = imported
                .occurrences
                .iter()
                .find(|occ| occ.indicator == *indicator)
                .map(|occ| format!("{}:{}", occ.source, occ.line))
                .unwrap_or_default();
            options.push((
                (index + 1).to_string(),
                format!("Check {}", indicator.value),
                format!(
                    "{} · {source} · fresh provider lookup",
                    indicator.indicator_type.as_str()
                ),
            ));
        }
        if unique.len() > 30 {
            tui::note(
                "Only the first 30 values are directly selectable here; use Value Search for others.",
            );
        }
        tui::note(
            "A lookup sends only the selected indicator to configured providers. List files are never uploaded.",
        );
        let refs = options
            .iter()
            .map(|(key, title, description)| (key.as_str(), title.as_str(), description.as_str()))
            .collect::<Vec<_>>();
        let selection =
            tui::terminal::select_menu("Follow Up", "Choose a value to look up, or return.", &refs);
        if selection == "0" {
            return;
        }
        if let Ok(number) = selection.parse::<usize>()
            && let Some(indicator) = unique.get(number.saturating_sub(1))
        {
            file_workflow::check_indicator_value(
                editor,
                client,
                auth_key,
                investigation,
                indicator.value.clone(),
            );
        }
    }
}

fn save_session_report(editor: &mut InputEditor, investigation: &Investigation) {
    if !investigation.has_completed_checks() {
        terminal::show_error("There are no completed checks to save in this session yet.");
        return;
    }

    terminal::clear_screen();
    tui::header("SAVE CURRENT SESSION", "Create Markdown and JSON copies");
    tui::box_line("The report includes every completed file and value check in this session.");
    tui::warning("Reports may contain sensitive indicators and provider evidence.");
    tui::navigation_footer("0", "Cancel");
    let answer =
        terminal::read_input(editor, "  Save session report? [y/N]: ", false).unwrap_or_default();
    if !matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes") {
        return;
    }

    let report = investigation.session_report();
    match crate::report::save_session_report(&report, std::path::Path::new("reports")) {
        Ok((json, markdown)) => {
            terminal::clear_screen();
            tui::header(
                "SESSION REPORTS SAVED",
                "Current session evidence stored locally",
            );
            tui::field("JSON report", json.display());
            tui::field("Markdown report", markdown.display());
            tui::navigation_footer("Enter", "Return to Current Session");
            terminal::pause();
        }
        Err(error) => terminal::show_error(&format!("Could not save session report: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        INVESTIGATION_MENU_OPTIONS, MAIN_MENU_OPTIONS, MORE_MENU_OPTIONS, MainMenuAction,
        SessionMenuAction, main_menu_action, session_menu_action,
    };

    #[test]
    fn investigation_menu_has_review_and_indicator_actions_without_duplicate_file_check() {
        let labels: Vec<&str> = INVESTIGATION_MENU_OPTIONS
            .iter()
            .map(|(_, label, _)| *label)
            .collect();

        assert_eq!(
            labels,
            [
                "Check a Value",
                "Review This Session",
                "Compare Indicator Lists",
                "Save This Session",
                "Back"
            ]
        );
        assert!(!labels.contains(&"Check a File"));
    }

    #[test]
    fn main_menu_reaches_file_checks_current_session_and_saved_reports() {
        assert_eq!(
            MAIN_MENU_OPTIONS
                .iter()
                .map(|(_, label, _)| *label)
                .collect::<Vec<_>>(),
            [
                "Check a File",
                "Current Session",
                "Search Logs",
                "Saved Reports",
                "More Tools",
                "Exit"
            ]
        );
        assert_eq!(main_menu_action("1"), Some(MainMenuAction::CheckFile));
        assert_eq!(main_menu_action("2"), Some(MainMenuAction::CurrentSession));
        assert_eq!(main_menu_action("4"), Some(MainMenuAction::SavedReports));
        assert_eq!(main_menu_action("0"), Some(MainMenuAction::Exit));
        assert_eq!(main_menu_action("invalid"), None);
    }

    #[test]
    fn current_session_actions_route_check_review_save_and_back() {
        assert_eq!(
            session_menu_action("1"),
            Some(SessionMenuAction::CheckValue)
        );
        assert_eq!(session_menu_action("2"), Some(SessionMenuAction::Review));
        assert_eq!(
            session_menu_action("3"),
            Some(SessionMenuAction::CompareLists)
        );
        assert_eq!(session_menu_action("4"), Some(SessionMenuAction::Save));
        assert_eq!(session_menu_action("0"), Some(SessionMenuAction::Back));
        assert_eq!(session_menu_action("invalid"), None);
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
