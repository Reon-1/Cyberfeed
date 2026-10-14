/// Optional credentials; the abuse.ch key is shared by MalwareBazaar, ThreatFox, and URLhaus.
pub struct Config {
    pub cloudflare_token: Option<String>,
    pub abusech_auth_key: Option<String>,
}

impl Config {
    pub fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Self {
        Self {
            cloudflare_token: non_blank(lookup("CLOUDFLARE_API_TOKEN")),
            abusech_auth_key: non_blank(lookup("ABUSECH_AUTH_KEY")),
        }
    }
}

fn non_blank(value: Option<String>) -> Option<String> {
    value.and_then(|value| (!value.trim().is_empty()).then_some(value.trim().to_owned()))
}

#[cfg(test)]
mod tests {
    use super::Config;
    use crate::indicator::{Indicator, IndicatorType};
    use crate::providers::malwarebazaar::build_hash_lookup_request;
    use crate::providers::threatfox::{build_lookup_request, request_for_indicator};
    use reqwest::blocking::Client;

    #[test]
    fn credentials_are_independent_and_blank_values_are_missing() {
        let cloudflare = Config::from_lookup(|key| match key {
            "CLOUDFLARE_API_TOKEN" => Some("  token  ".into()),
            _ => Some(" \t ".into()),
        });
        assert_eq!(cloudflare.cloudflare_token.as_deref(), Some("token"));
        assert_eq!(cloudflare.abusech_auth_key, None);

        let abusech = Config::from_lookup(|key| match key {
            "ABUSECH_AUTH_KEY" => Some("shared-key".into()),
            "CLOUDFLARE_API_TOKEN" => Some("radar-token".into()),
            _ => None,
        });
        assert_eq!(abusech.cloudflare_token.as_deref(), Some("radar-token"));
        assert_eq!(abusech.abusech_auth_key.as_deref(), Some("shared-key"));
    }

    #[test]
    fn both_credentials_may_be_absent() {
        let config = Config::from_lookup(|_| None);
        assert!(config.cloudflare_token.is_none());
        assert!(config.abusech_auth_key.is_none());
    }

    #[test]
    fn whitespace_only_credentials_are_missing_for_both_integrations() {
        let config = Config::from_lookup(|_| Some(" \n\t ".into()));
        assert!(config.cloudflare_token.is_none());
        assert!(config.abusech_auth_key.is_none());
    }

    #[test]
    fn both_abusech_providers_use_shared_key_and_cloudflare_stays_independent() {
        const ABUSECH_TEST_KEY: &str = "dummy-shared-abusech-key";
        const CLOUDFLARE_TEST_TOKEN: &str = "dummy-cloudflare-token";
        let config = Config::from_lookup(|name| match name {
            "ABUSECH_AUTH_KEY" => Some(ABUSECH_TEST_KEY.into()),
            "CLOUDFLARE_API_TOKEN" => Some(CLOUDFLARE_TEST_TOKEN.into()),
            _ => None,
        });
        let client = Client::new();

        let malwarebazaar_request = build_hash_lookup_request(
            &client,
            config.abusech_auth_key.as_deref().unwrap_or_default(),
            &"a".repeat(64),
        )
        .expect("dummy MalwareBazaar request should build");
        let threatfox_indicator = Indicator::new("192.0.2.1", IndicatorType::IP);
        let threatfox_payload = request_for_indicator(&threatfox_indicator)
            .expect("test IP should produce a ThreatFox request");
        let threatfox_request = build_lookup_request(
            &client,
            config.abusech_auth_key.as_deref().unwrap_or_default(),
            &threatfox_payload,
        )
        .expect("dummy ThreatFox request should build");

        assert_eq!(
            malwarebazaar_request
                .headers()
                .get("Auth-Key")
                .and_then(|value| value.to_str().ok()),
            Some(ABUSECH_TEST_KEY)
        );
        assert_eq!(
            threatfox_request
                .headers()
                .get("Auth-Key")
                .and_then(|value| value.to_str().ok()),
            Some(ABUSECH_TEST_KEY)
        );
        assert_eq!(
            config.cloudflare_token.as_deref(),
            Some(CLOUDFLARE_TEST_TOKEN)
        );
    }
}

const ABUSECH_KEY: &str = "ABUSECH_AUTH_KEY";
const CLOUDFLARE_KEY: &str = "CLOUDFLARE_API_TOKEN";

/// A user-confirmed edit to one of CyberFeed's supported credential entries.
pub(crate) enum CredentialChange<'a> {
    Set(&'a str),
    Remove,
    Cancel,
}

/// Apply one supported credential change while preserving other .env content.
/// Credentials are written only to the selected file and never included in errors.
pub(crate) fn apply_credential_change(
    path: &std::path::Path,
    key: &str,
    change: CredentialChange<'_>,
) -> std::io::Result<bool> {
    if !matches!(key, ABUSECH_KEY | CLOUDFLARE_KEY) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unsupported credential setting",
        ));
    }
    match change {
        CredentialChange::Set(value) => {
            let value = value.trim();
            if value.is_empty() || value.contains(['\r', '\n']) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "credential must be non-empty and fit on one line",
                ));
            }
            update_env_file(path, key, Some(value)).map(|()| true)
        }
        CredentialChange::Remove => update_env_file(path, key, None).map(|()| true),
        CredentialChange::Cancel => Ok(false),
    }
}

fn update_env_file(path: &std::path::Path, key: &str, value: Option<&str>) -> std::io::Result<()> {
    use std::fs;
    let existing = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error),
    };
    let newline = if existing.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let had_trailing_newline = existing.ends_with('\n');
    let mut lines = Vec::new();
    let mut inserted = false;
    for line in existing.lines() {
        if env_assignment_key(line) == Some(key) {
            if !inserted {
                if let Some(value) = value {
                    lines.push(quoted_assignment(key, value));
                }
                inserted = true;
            }
        } else {
            lines.push(line.to_owned());
        }
    }
    if !inserted && value.is_none() {
        return Ok(());
    }
    if !inserted && let Some(value) = value {
        lines.push(quoted_assignment(key, value));
    }
    let mut updated = lines.join(newline);
    if had_trailing_newline || !updated.is_empty() {
        updated.push_str(newline);
    }
    replace_file_safely(path, updated.as_bytes())
}

fn env_assignment_key(line: &str) -> Option<&str> {
    let line = line.trim_start();
    let line = line.strip_prefix("export ").unwrap_or(line);
    let (name, _) = line.split_once('=')?;
    Some(name.trim())
}

fn quoted_assignment(key: &str, value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "\\$");
    format!("{key}=\"{escaped}\"")
}

fn replace_file_safely(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static TEMP_ID: AtomicU64 = AtomicU64::new(0);

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let (temp_path, mut file) = loop {
        let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), id));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(file) => break (candidate, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    };
    let result = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(&temp_path);
        return Err(error);
    }

    #[cfg(not(windows))]
    let replace_result = fs::rename(&temp_path, path);

    // Windows does not replace an existing destination with std::fs::rename.
    // Move the old file aside, publish the complete staged file, and restore
    // the original if publication fails. No partially written .env is exposed.
    #[cfg(windows)]
    let replace_result = {
        let backup = parent.join(format!(".{name}.{}.backup", std::process::id()));
        let had_original = path.exists();
        let result = if had_original {
            fs::rename(path, &backup).and_then(|()| fs::rename(&temp_path, path))
        } else {
            fs::rename(&temp_path, path)
        };
        match result {
            Ok(()) if had_original => fs::remove_file(&backup).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "configuration was updated, but the old temporary copy '{}' could not be removed: {error}",
                        backup.display()
                    ),
                )
            }),
            Ok(()) => Ok(()),
            Err(error) if had_original => match fs::rename(&backup, path) {
                Ok(()) => Err(error),
                Err(restore_error) => Err(std::io::Error::new(
                    error.kind(),
                    format!(
                        "configuration update failed ({error}); the original file could not be restored from '{}': {restore_error}",
                        backup.display()
                    ),
                )),
            },
            Err(error) => Err(error),
        }
    };
    match replace_result {
        Ok(()) => Ok(()),
        Err(error) => match fs::remove_file(&temp_path) {
            Ok(()) => Err(error),
            Err(cleanup) if cleanup.kind() == std::io::ErrorKind::NotFound => Err(error),
            Err(cleanup) => Err(std::io::Error::new(
                error.kind(),
                format!(
                    "{error}; staged configuration file '{}' could not be removed: {cleanup}",
                    temp_path.display()
                ),
            )),
        },
    }
}

#[cfg(test)]
mod credential_file_tests {
    use super::{CredentialChange, apply_credential_change};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("cyberfeed-config-test-{}-{id}", std::process::id()));
            std::fs::create_dir(&path).expect("test directory should be created");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn updates_only_the_selected_value_and_preserves_comments_and_other_entries() {
        let dir = TestDirectory::new();
        let path = dir.0.join(".env");
        std::fs::write(
            &path,
            "# keep this comment\nOTHER_SETTING=unchanged\nABUSECH_AUTH_KEY=old\nCLOUDFLARE_API_TOKEN=keep\n",
        )
        .unwrap();

        apply_credential_change(
            &path,
            "ABUSECH_AUTH_KEY",
            CredentialChange::Set("  new value  "),
        )
        .unwrap();
        let contents = std::fs::read_to_string(path).unwrap();
        assert!(contents.starts_with("# keep this comment\nOTHER_SETTING=unchanged\n"));
        assert!(contents.contains("ABUSECH_AUTH_KEY=\"new value\"\n"));
        assert!(contents.contains("CLOUDFLARE_API_TOKEN=keep\n"));
        assert!(!contents.contains("ABUSECH_AUTH_KEY=old"));
    }

    #[test]
    fn quotes_and_backslashes_are_escaped_without_leaking_the_secret_in_errors() {
        let dir = TestDirectory::new();
        let path = dir.0.join(".env");
        let secret = "a \"quote\" and \\slash # $value";
        apply_credential_change(&path, "CLOUDFLARE_API_TOKEN", CredentialChange::Set(secret))
            .unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed = dotenvy::from_read_iter(std::io::Cursor::new(content))
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            parsed.get("CLOUDFLARE_API_TOKEN").map(String::as_str),
            Some(secret)
        );

        let error = apply_credential_change(
            &dir.0.join("missing-parent/.env"),
            "CLOUDFLARE_API_TOKEN",
            CredentialChange::Set(secret),
        )
        .unwrap_err();
        assert!(!error.to_string().contains(secret));
    }

    #[test]
    fn cancellation_leaves_the_file_unchanged_and_remove_keeps_unrelated_values() {
        let dir = TestDirectory::new();
        let path = dir.0.join(".env");
        std::fs::write(&path, "# comment\nOTHER=value\nABUSECH_AUTH_KEY=old\n").unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(
            !apply_credential_change(&path, "ABUSECH_AUTH_KEY", CredentialChange::Cancel).unwrap()
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);

        apply_credential_change(&path, "ABUSECH_AUTH_KEY", CredentialChange::Remove).unwrap();
        let after = std::fs::read_to_string(path).unwrap();
        assert!(after.contains("# comment"));
        assert!(after.contains("OTHER=value"));
        assert!(!after.contains("ABUSECH_AUTH_KEY"));
    }

    #[test]
    fn blank_and_multiline_values_are_rejected_without_writing() {
        let dir = TestDirectory::new();
        let path = dir.0.join(".env");
        for value in ["  ", "one\ntwo"] {
            assert!(
                apply_credential_change(&path, "ABUSECH_AUTH_KEY", CredentialChange::Set(value))
                    .is_err()
            );
        }
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn created_credential_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDirectory::new();
        let path = dir.0.join(".env");
        apply_credential_change(
            &path,
            "ABUSECH_AUTH_KEY",
            CredentialChange::Set("dummy-test-value"),
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
