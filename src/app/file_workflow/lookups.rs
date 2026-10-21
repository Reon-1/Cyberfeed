//! Provider request scheduling and normalization for file investigations.
use crate::indicator::{Indicator, IndicatorType};
use crate::providers::malwarebazaar::{MalwareLookupError, MalwareLookupResult, MalwareSample};
use crate::providers::threatfox::{self, ThreatFoxError, ThreatFoxLookupResult};
use crate::providers::urlhaus;
use crate::report::{LookupOutcome, LookupSubject, MatchDetails, ProviderLookup, ThreatFoxFinding};
use reqwest::blocking::Client;
use std::collections::HashSet;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(super) const INVESTIGATION_BUDGET: Duration = Duration::from_secs(60);
const PROVIDER_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy)]
pub(super) struct LookupDeadline(Instant);

impl LookupDeadline {
    pub(super) fn at(instant: Instant) -> Self {
        Self(instant)
    }

    fn remaining(self) -> Option<Duration> {
        self.0
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
    }

    fn timeout(self) -> Option<Duration> {
        self.remaining()
            .map(|remaining| remaining.min(PROVIDER_REQUEST_TIMEOUT))
    }
}

#[derive(Clone, Copy)]
pub(super) struct LookupPolicy {
    subject: LookupSubject,
    allow_query: bool,
    deadline: Option<LookupDeadline>,
}

impl LookupPolicy {
    pub(super) fn new(
        subject: LookupSubject,
        allow_query: bool,
        deadline: Option<LookupDeadline>,
    ) -> Self {
        Self {
            subject,
            allow_query,
            deadline,
        }
    }
}

fn deadline_skip() -> LookupOutcome {
    LookupOutcome::SkippedDeadline {
        explanation:
            "The overall investigation deadline elapsed before this request; no request was sent."
                .into(),
    }
}

fn deadline_timeout() -> LookupOutcome {
    LookupOutcome::TimedOut {
        explanation: "The overall investigation deadline elapsed during this request; later checks were skipped.".into(),
    }
}

pub(super) const MAX_AUTOMATIC_MALWAREBAZAAR_LOOKUPS: usize = 10;
pub(super) const MAX_AUTOMATIC_THREATFOX_LOOKUPS: usize = 10;
pub(super) const MAX_AUTOMATIC_URLHAUS_LOOKUPS: usize = 10;

#[derive(Default)]
pub(super) struct UrlhausRequestState {
    pub(super) queried: HashSet<String>,
    pub(super) seen: HashSet<String>,
}

pub(super) fn show_hash_lookup_before(
    client: &Client,
    auth_key: &str,
    hash: &str,
    looked_up: &mut HashSet<String>,
    deadline: Option<LookupDeadline>,
) -> ProviderLookup {
    let subject = if hash.len() == 64 {
        LookupSubject::ExtractedIndicatorSha256
    } else {
        LookupSubject::ExtractedIndicator
    };
    if auth_key.trim().is_empty() {
        provider_record(hash, subject, None, LookupOutcome::NotConfigured)
    } else if deadline.is_some_and(|deadline| deadline.timeout().is_none()) {
        provider_record(hash, subject, None, deadline_skip())
    } else if should_lookup_hash(looked_up, hash) {
        let Some(timeout) =
            deadline.map_or(Some(PROVIDER_REQUEST_TIMEOUT), LookupDeadline::timeout)
        else {
            return provider_record(hash, subject, None, deadline_skip());
        };
        let outcome = lookup_hash_record_with_timeout(client, auth_key, hash, timeout, deadline);
        provider_record(hash, subject, Some(now_seconds()), outcome)
    } else if looked_up.contains(&hash.to_ascii_lowercase()) {
        provider_record(
            hash,
            subject,
            None,
            LookupOutcome::SkippedDuplicate {
                references_hash: hash.to_ascii_lowercase(),
            },
        )
    } else {
        provider_record(hash, subject, None, LookupOutcome::SkippedLookupLimit)
    }
}

pub(super) fn threatfox_lookup_record_before(
    client: &Client,
    auth_key: &str,
    value: &str,
    indicator_type: IndicatorType,
    queried: &mut HashSet<String>,
    policy: LookupPolicy,
) -> ProviderLookup {
    let LookupPolicy {
        subject,
        allow_query,
        deadline,
    } = policy;
    let indicator = crate::indicator::Indicator::new(value, indicator_type);
    let key = threatfox_indicator_key(indicator_type, value);
    let outcome = if let Err(result) = threatfox::request_for_indicator(&indicator) {
        threatfox_outcome(result)
    } else if auth_key.trim().is_empty() {
        LookupOutcome::NotConfigured
    } else if queried.contains(&key) {
        LookupOutcome::SkippedDuplicate {
            references_hash: value.to_ascii_lowercase(),
        }
    } else if !allow_query {
        LookupOutcome::SkippedLookupLimit
    } else if deadline.is_some_and(|deadline| deadline.timeout().is_none()) {
        deadline_skip()
    } else {
        match claim_threatfox_lookup(queried, &key) {
            AutomaticLookup::Duplicate => LookupOutcome::SkippedDuplicate {
                references_hash: value.to_ascii_lowercase(),
            },
            AutomaticLookup::Limit => LookupOutcome::SkippedLookupLimit,
            AutomaticLookup::Proceed => {
                let Some(timeout) =
                    deadline.map_or(Some(PROVIDER_REQUEST_TIMEOUT), LookupDeadline::timeout)
                else {
                    return provider_named_record(
                        "ThreatFox",
                        value,
                        subject,
                        None,
                        deadline_skip(),
                    );
                };
                match threatfox::lookup_indicator_with_timeout(
                    client,
                    Some(auth_key),
                    &indicator,
                    timeout,
                ) {
                    Ok(result) => threatfox_outcome(result),
                    Err(_error)
                        if deadline.is_some_and(|deadline| deadline.remaining().is_none()) =>
                    {
                        deadline_timeout()
                    }
                    Err(error) => threatfox_error_outcome(error, auth_key),
                }
            }
        }
    };
    let requested = !matches!(
        outcome,
        LookupOutcome::NotConfigured
            | LookupOutcome::Unsupported { .. }
            | LookupOutcome::Invalid { .. }
            | LookupOutcome::SkippedDuplicate { .. }
            | LookupOutcome::SkippedLookupLimit
            | LookupOutcome::SkippedDeadline { .. }
    );
    ProviderLookup {
        provider: "ThreatFox".into(),
        subject,
        queried_hash: value.into(),
        retrieved_at_unix_seconds: requested.then(now_seconds),
        outcome,
    }
}

pub(super) fn threatfox_indicator_key(indicator_type: IndicatorType, value: &str) -> String {
    let normalized = match indicator_type {
        // URL paths and queries may be case-sensitive; preserve the full IOC.
        IndicatorType::Url => value.to_owned(),
        IndicatorType::Hash | IndicatorType::IP | IndicatorType::Domain => {
            value.to_ascii_lowercase()
        }
    };
    format!("{indicator_type:?}:{normalized}")
}

pub(super) fn urlhaus_lookup_record_before(
    client: &Client,
    auth_key: &str,
    value: &str,
    indicator_type: IndicatorType,
    state: &mut UrlhausRequestState,
    policy: LookupPolicy,
) -> ProviderLookup {
    let LookupPolicy {
        subject,
        allow_query,
        deadline,
    } = policy;
    let indicator = Indicator::new(value, indicator_type);
    let key =
        urlhaus::request_key(&indicator).unwrap_or_else(|| format!("{indicator_type:?}:{value}"));
    let outcome = if let Err(result) = urlhaus::query_for_indicator(&indicator) {
        urlhaus::outcome(Ok(result), auth_key)
    } else if auth_key.trim().is_empty() {
        LookupOutcome::NotConfigured
    } else if state.seen.contains(&key) {
        LookupOutcome::SkippedDuplicate {
            references_hash: value.into(),
        }
    } else {
        if !allow_query || state.queried.len() >= MAX_AUTOMATIC_URLHAUS_LOOKUPS {
            state.seen.insert(key);
            LookupOutcome::SkippedLookupLimit
        } else if deadline.is_some_and(|deadline| deadline.timeout().is_none()) {
            deadline_skip()
        } else {
            state.seen.insert(key.clone());
            state.queried.insert(key);
            let Some(timeout) =
                deadline.map_or(Some(PROVIDER_REQUEST_TIMEOUT), LookupDeadline::timeout)
            else {
                return provider_named_record("URLhaus", value, subject, None, deadline_skip());
            };
            match urlhaus::lookup_indicator_with_timeout(
                client,
                Some(auth_key),
                &indicator,
                timeout,
            ) {
                Err(_error) if deadline.is_some_and(|deadline| deadline.remaining().is_none()) => {
                    deadline_timeout()
                }
                result => urlhaus::outcome(result, auth_key),
            }
        }
    };
    let requested = !matches!(
        outcome,
        LookupOutcome::NotConfigured
            | LookupOutcome::Unsupported { .. }
            | LookupOutcome::Invalid { .. }
            | LookupOutcome::SkippedDuplicate { .. }
            | LookupOutcome::SkippedLookupLimit
            | LookupOutcome::SkippedDeadline { .. }
    );
    ProviderLookup {
        provider: "URLhaus".into(),
        subject,
        queried_hash: value.into(),
        retrieved_at_unix_seconds: requested.then(now_seconds),
        outcome,
    }
}

/// Reserve the original file hash, then fairly rotate through payload hashes,
/// explicit host indicators, exact URLs, and URL-derived hosts. The total
/// remains capped at ten URLhaus requests per file. Categories are independent
/// so domains cannot consume IP capacity. Slots rotate through every category
/// with remaining candidates; when categories are empty, active queues reuse
/// the available budget instead of leaving reserved slots idle.
pub(super) fn allocate_urlhaus_requests(
    indicators: &[Indicator],
    original_file_hash: &str,
) -> HashSet<String> {
    let original = Indicator::new(original_file_hash, IndicatorType::Hash);
    let original_key =
        urlhaus::request_key(&original).expect("SHA-256 is a supported payload query");
    let mut seen = HashSet::from([original_key.clone()]);
    let mut queues: [Vec<String>; 5] = std::array::from_fn(|_| Vec::new());
    let mut candidates: [Vec<Indicator>; 5] = std::array::from_fn(|_| Vec::new());

    for indicator in indicators {
        match indicator.indicator_type {
            IndicatorType::Hash => candidates[0].push(indicator.clone()),
            IndicatorType::IP => candidates[1].push(indicator.clone()),
            IndicatorType::Domain => candidates[2].push(indicator.clone()),
            IndicatorType::Url => {
                candidates[3].push(indicator.clone());
                if let Some((host, kind)) = host_from_url(&indicator.value) {
                    candidates[4].push(Indicator::new(host, kind));
                }
            }
        }
    }

    // A literal extracted host gets priority over the same host derived from a
    // URL; the same API request is never scheduled twice.
    for (category, indicators) in candidates.iter().enumerate() {
        for indicator in indicators {
            let Some(key) = urlhaus::request_key(indicator) else {
                continue;
            };
            if seen.insert(key.clone()) {
                queues[category].push(key);
            }
        }
    }

    let mut selected = HashSet::from([original_key]);
    let mut cursors = [0; 5];
    let mut next_category = 0;
    while selected.len() < MAX_AUTOMATIC_URLHAUS_LOOKUPS {
        let Some(category) = (0..queues.len())
            .map(|offset| (next_category + offset) % queues.len())
            .find(|&index| cursors[index] < queues[index].len())
        else {
            break;
        };
        selected.insert(queues[category][cursors[category]].clone());
        cursors[category] += 1;
        next_category = (category + 1) % queues.len();
    }
    selected
}

pub(super) fn host_from_url(value: &str) -> Option<(String, IndicatorType)> {
    if !crate::indicator::is_http_url(value) {
        return None;
    }
    let url = reqwest::Url::parse(value).ok()?;
    let host = url.host_str()?.to_owned();
    let kind = if host.parse::<std::net::Ipv4Addr>().is_ok() {
        IndicatorType::IP
    } else if crate::indicator::classify(&host, &[]) == Some(IndicatorType::Domain)
        || (!host.is_empty()
            && host.len() <= 63
            && !host.starts_with('-')
            && !host.ends_with('-')
            && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
    {
        IndicatorType::Domain
    } else {
        return None;
    };
    Some((host, kind))
}

/// Reserve the original file hash first, then rotate through hash, IP, and
/// domain queues so a large hash list cannot starve the other supported types.
pub(super) fn allocate_threatfox_indicators(
    indicators: &[Indicator],
    original_file_hash: &str,
) -> HashSet<String> {
    let mut seen = HashSet::from([threatfox_indicator_key(
        IndicatorType::Hash,
        original_file_hash,
    )]);
    let mut queues: [Vec<String>; 4] = std::array::from_fn(|_| Vec::new());
    for indicator in indicators {
        let key = threatfox_indicator_key(indicator.indicator_type, &indicator.value);
        if seen.insert(key.clone()) && threatfox::request_for_indicator(indicator).is_ok() {
            queues[indicator_queue_index(indicator.indicator_type)].push(key);
        }
    }

    let mut selected = HashSet::new();
    let mut cursors = [0; 4];
    let mut next_type = 0;
    while selected.len() < MAX_AUTOMATIC_THREATFOX_LOOKUPS.saturating_sub(1) {
        let Some(queue_index) = (0..4)
            .map(|offset| (next_type + offset) % 4)
            .find(|index| cursors[*index] < queues[*index].len())
        else {
            break;
        };
        selected.insert(queues[queue_index][cursors[queue_index]].clone());
        cursors[queue_index] += 1;
        next_type = (queue_index + 1) % 4;
    }
    selected
}

pub(super) fn indicator_queue_index(indicator_type: IndicatorType) -> usize {
    match indicator_type {
        IndicatorType::Hash => 0,
        IndicatorType::IP => 1,
        IndicatorType::Domain => 2,
        IndicatorType::Url => 3,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum AutomaticLookup {
    Proceed,
    Duplicate,
    Limit,
}

pub(super) fn claim_threatfox_lookup(queried: &mut HashSet<String>, key: &str) -> AutomaticLookup {
    if queried.contains(key) {
        return AutomaticLookup::Duplicate;
    }
    if queried.len() >= MAX_AUTOMATIC_THREATFOX_LOOKUPS {
        return AutomaticLookup::Limit;
    }
    queried.insert(key.to_owned());
    AutomaticLookup::Proceed
}

pub(super) fn should_query_threatfox(
    auth_key: &str,
    indicator: &Indicator,
    queried: &HashSet<String>,
    allow_query: bool,
) -> bool {
    let key = threatfox_indicator_key(indicator.indicator_type, &indicator.value);
    !auth_key.trim().is_empty()
        && allow_query
        && !queried.contains(&key)
        && queried.len() < MAX_AUTOMATIC_THREATFOX_LOOKUPS
        && threatfox::request_for_indicator(indicator).is_ok()
}

pub(super) fn threatfox_outcome(result: ThreatFoxLookupResult) -> LookupOutcome {
    match result {
        ThreatFoxLookupResult::Found(findings) => LookupOutcome::ThreatFoxFound {
            findings: findings
                .into_iter()
                .map(|finding| ThreatFoxFinding {
                    source_record_id: finding.id,
                    ioc: finding.ioc,
                    ioc_type: finding.ioc_type,
                    ioc_type_description: finding.ioc_type_desc,
                    threat_type: finding.threat_type,
                    threat_type_description: finding.threat_type_desc,
                    malware: finding.malware,
                    malware_printable: finding.malware_printable,
                    confidence_level: finding.confidence_level,
                    first_seen: finding.first_seen,
                    last_seen: finding.last_seen,
                    reference: finding.reference,
                    reporter: finding.reporter,
                    tags: finding.tags.unwrap_or_default(),
                })
                .collect(),
        },
        ThreatFoxLookupResult::NotFound => LookupOutcome::NotFound,
        ThreatFoxLookupResult::InvalidInput(explanation) => LookupOutcome::Invalid { explanation },
        ThreatFoxLookupResult::Unsupported(explanation) => {
            LookupOutcome::Unsupported { explanation }
        }
        ThreatFoxLookupResult::NotConfigured => LookupOutcome::NotConfigured,
        ThreatFoxLookupResult::ProviderError(explanation) => {
            LookupOutcome::ApiError { explanation }
        }
    }
}

pub(super) fn threatfox_error_outcome(error: ThreatFoxError, auth_key: &str) -> LookupOutcome {
    match error {
        ThreatFoxError::Request(explanation) => LookupOutcome::RequestError {
            explanation: redact_secret(&explanation, auth_key),
        },
        ThreatFoxError::Http { status, .. } => LookupOutcome::ApiError {
            explanation: format!("ThreatFox returned HTTP {status}."),
        },
        ThreatFoxError::Parse(explanation) => LookupOutcome::ApiError {
            explanation: redact_secret(
                &format!("ThreatFox response could not be parsed: {explanation}"),
                auth_key,
            ),
        },
    }
}

pub(super) fn lookup_hash_record_before(
    client: &Client,
    auth_key: &str,
    hash: &str,
    deadline: LookupDeadline,
) -> LookupOutcome {
    let Some(timeout) = deadline.timeout() else {
        return deadline_skip();
    };
    lookup_hash_record_with_timeout(client, auth_key, hash, timeout, Some(deadline))
}

pub(super) fn lookup_hash_record_with_timeout(
    client: &Client,
    auth_key: &str,
    hash: &str,
    timeout: Duration,
    deadline: Option<LookupDeadline>,
) -> LookupOutcome {
    let result = crate::providers::malwarebazaar::lookup_malware_hash_with_timeout(
        client, auth_key, hash, timeout,
    );
    match result {
        Err(MalwareLookupError::Request(_))
            if deadline.is_some_and(|deadline| deadline.remaining().is_none()) =>
        {
            deadline_timeout()
        }
        result => outcome_from_malwarebazaar_result(result, auth_key),
    }
}

pub(super) fn redact_secret(message: &str, secret: &str) -> String {
    if secret.is_empty() {
        message.to_owned()
    } else {
        message.replace(secret, "[redacted]")
    }
}

/// Adapt the provider's response types into the shared evidence model at the
/// workflow boundary, keeping report serialization independent of the client.
pub(super) fn outcome_from_malwarebazaar_result(
    result: Result<MalwareLookupResult, MalwareLookupError>,
    auth_key: &str,
) -> LookupOutcome {
    match result {
        Ok(MalwareLookupResult::Found(sample)) => {
            LookupOutcome::Found(malware_sample_details(sample))
        }
        Ok(MalwareLookupResult::NotFound) => LookupOutcome::NotFound,
        Ok(MalwareLookupResult::InvalidHash(explanation)) => LookupOutcome::Invalid { explanation },
        Ok(MalwareLookupResult::ApiError(explanation)) => LookupOutcome::ApiError { explanation },
        Err(MalwareLookupError::Request(message)) => LookupOutcome::RequestError {
            explanation: redact_secret(&message.replace(['\n', '\r'], " "), auth_key),
        },
        Err(MalwareLookupError::AuthenticationRejected { status }) => LookupOutcome::ApiError {
            explanation: format!(
                "MalwareBazaar rejected the configured Auth-Key (HTTP {status}); check ABUSECH_AUTH_KEY."
            ),
        },
        Err(MalwareLookupError::Http { status, .. }) => LookupOutcome::ApiError {
            explanation: format!("MalwareBazaar returned HTTP {status}."),
        },
        Err(MalwareLookupError::Parse(message)) => LookupOutcome::ApiError {
            explanation: redact_secret(
                &format!("Could not parse MalwareBazaar response: {message}"),
                auth_key,
            ),
        },
    }
}

pub(super) fn malware_sample_details(sample: MalwareSample) -> MatchDetails {
    MatchDetails {
        matched_sha256: sample.sha256_hash,
        first_seen: sample.first_seen,
        file_type: sample.file_type,
        sample_filename: (!sample.file_name.is_empty()).then_some(sample.file_name),
        signature: sample.signature,
    }
}

pub(super) fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(super) fn provider_record(
    hash: &str,
    subject: LookupSubject,
    retrieved: Option<u64>,
    outcome: LookupOutcome,
) -> ProviderLookup {
    ProviderLookup {
        provider: "MalwareBazaar".into(),
        subject,
        queried_hash: hash.into(),
        retrieved_at_unix_seconds: retrieved,
        outcome,
    }
}

fn provider_named_record(
    provider: &str,
    value: &str,
    subject: LookupSubject,
    retrieved: Option<u64>,
    outcome: LookupOutcome,
) -> ProviderLookup {
    ProviderLookup {
        provider: provider.into(),
        subject,
        queried_hash: value.into(),
        retrieved_at_unix_seconds: retrieved,
        outcome,
    }
}
pub(super) fn inspection_extraction_state(
    text: &Option<crate::file::TextIndicators>,
) -> Option<bool> {
    text.as_ref().map(|t| t.limit_reached)
}

pub(super) fn should_lookup_hash(looked_up: &mut HashSet<String>, hash: &str) -> bool {
    // The file's own hash is inserted first, so it counts toward this cap.
    looked_up.len() < MAX_AUTOMATIC_MALWAREBAZAAR_LOOKUPS
        && looked_up.insert(hash.to_ascii_lowercase())
}

pub(super) fn hash_request_available(
    auth_key: &str,
    looked_up: &HashSet<String>,
    hash: &str,
) -> bool {
    !auth_key.trim().is_empty()
        && looked_up.len() < MAX_AUTOMATIC_MALWAREBAZAAR_LOOKUPS
        && !looked_up.contains(&hash.to_ascii_lowercase())
}

#[cfg(test)]
mod key_tests {
    use super::{
        INVESTIGATION_BUDGET, LookupDeadline, LookupPolicy, UrlhausRequestState,
        threatfox_indicator_key, threatfox_lookup_record_before, urlhaus_lookup_record_before,
    };
    use crate::indicator::IndicatorType;
    use crate::report::{LookupOutcome, LookupSubject};
    use std::collections::HashSet;
    use std::time::Instant;

    #[test]
    fn threatfox_url_keys_keep_path_case_but_normalize_host_only_indicators() {
        let upper_path = "https://example.test/A";
        let lower_path = "https://example.test/a";
        assert_ne!(
            threatfox_indicator_key(IndicatorType::Url, upper_path),
            threatfox_indicator_key(IndicatorType::Url, lower_path)
        );
        assert_ne!(
            threatfox_indicator_key(IndicatorType::Url, upper_path),
            threatfox_indicator_key(IndicatorType::Url, "https://example.test/A/")
        );
        assert_eq!(
            threatfox_indicator_key(IndicatorType::Domain, "EXAMPLE.TEST"),
            threatfox_indicator_key(IndicatorType::Domain, "example.test")
        );
        assert_eq!(
            threatfox_indicator_key(IndicatorType::Hash, &"A".repeat(64)),
            threatfox_indicator_key(IndicatorType::Hash, &"a".repeat(64))
        );
    }

    #[test]
    fn expired_deadline_skips_configured_requests_without_claiming_no_match() {
        assert_eq!(INVESTIGATION_BUDGET.as_secs(), 60);
        let client = reqwest::blocking::Client::new();
        let deadline = LookupDeadline::at(Instant::now());
        let mut threatfox_seen = HashSet::new();
        let threatfox = threatfox_lookup_record_before(
            &client,
            "dummy-key",
            "example.test",
            IndicatorType::Domain,
            &mut threatfox_seen,
            LookupPolicy::new(LookupSubject::ExtractedIndicator, true, Some(deadline)),
        );
        assert!(matches!(
            threatfox.outcome,
            LookupOutcome::SkippedDeadline { .. }
        ));
        assert!(threatfox.retrieved_at_unix_seconds.is_none());
        assert!(threatfox_seen.is_empty());

        let mut urlhaus_state = UrlhausRequestState::default();
        let urlhaus = urlhaus_lookup_record_before(
            &client,
            "dummy-key",
            "example.test",
            IndicatorType::Domain,
            &mut urlhaus_state,
            LookupPolicy::new(LookupSubject::ExtractedIndicator, true, Some(deadline)),
        );
        assert!(matches!(
            urlhaus.outcome,
            LookupOutcome::SkippedDeadline { .. }
        ));
        assert!(urlhaus.retrieved_at_unix_seconds.is_none());
        assert_eq!(urlhaus.outcome.status(), "SKIPPED: DEADLINE");
        assert!(urlhaus_state.queried.is_empty());
        assert!(urlhaus_state.seen.is_empty());
    }
}
