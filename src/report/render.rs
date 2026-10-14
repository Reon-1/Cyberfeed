use super::model::{
    InvestigationReport, LookupOutcome, LookupSubject, ProviderLookup, SessionCheck, SessionReport,
    TextExtraction,
};

impl SessionReport {
    pub fn to_markdown(&self) -> String {
        let mut out = format!(
            "# CyberFeed Session Report\n\n- Completed checks: {}\n- Generated at: {} seconds since the Unix epoch (UTC)\n\n",
            self.checks.len(),
            self.generated_at_unix_seconds
        );
        out.push_str("`FOUND` means a provider returned a matching record. `NOT FOUND` means that provider returned no match at lookup time; it is not a safety verdict. Errors, unsupported checks, and missing configuration remain distinct.\n\n");
        for (index, check) in self.checks.iter().enumerate() {
            match check {
                SessionCheck::FileInvestigation { report } => {
                    out.push_str(&format!(
                        "## Check {} — File investigation: `{}`\n\n",
                        index + 1,
                        md_code(&report.file.filename)
                    ));
                    let markdown = report.to_markdown();
                    let body = markdown
                        .strip_prefix("# CyberFeed Investigation Report\n\n")
                        .unwrap_or(&markdown);
                    for line in body.lines() {
                        if line.starts_with('#') {
                            out.push_str("##");
                        }
                        out.push_str(line);
                        out.push('\n');
                    }
                    out.push('\n');
                }
                SessionCheck::IndicatorLookup {
                    indicator,
                    provider_lookups,
                } => {
                    out.push_str(&format!(
                        "## Check {} — Indicator lookup\n\n- Type: {}\n- Value: `{}`\n\n",
                        index + 1,
                        indicator.indicator_type.as_str(),
                        md_code(&indicator.value)
                    ));
                    if provider_lookups.is_empty() {
                        out.push_str("No provider outcomes were recorded for this check.\n\n");
                    }
                    for lookup in provider_lookups {
                        render_lookup(&mut out, lookup);
                    }
                    out.push_str("This lookup describes the submitted indicator and does not establish that a file or related system is safe or malicious.\n\n");
                }
            }
        }
        out
    }
}

impl InvestigationReport {
    pub fn to_markdown(&self) -> String {
        let mut out =
            String::from("# CyberFeed Investigation Report\n\n## Investigation summary\n\n");
        out.push_str(&format!("- File: `{}` ({} bytes)\n- Original file SHA-256: `{}`\n- Original file lookup: {}\n- Extracted indicators: {} hashes, {} IP addresses, {} domains, {} URLs\n- Extracted hash provider outcomes: {} found, {} not found, {} failed, {} skipped or unavailable\n- Extraction limit reached: {}\n- Generated at: {} seconds since the Unix epoch (UTC)\n\nCyberFeed read the file locally as data; it did not execute or upload it.\n\n", md_code(&self.file.filename), self.file.size_bytes, md_code(&self.file.sha256), self.summary.original_file_lookup_status.as_deref().unwrap_or("not recorded"), self.summary.extracted_indicator_counts.hashes, self.summary.extracted_indicator_counts.ip_addresses, self.summary.extracted_indicator_counts.domains, self.summary.extracted_indicator_counts.urls, self.summary.extracted_hash_lookup_counts.found, self.summary.extracted_hash_lookup_counts.not_found, self.summary.extracted_hash_lookup_counts.failures, self.summary.extracted_hash_lookup_counts.skipped_or_unavailable, self.summary.extraction_limit_reached, self.generated_at_unix_seconds));
        out.push_str("## File details\n\n");
        out.push_str(&format!(
            "- Size: {} bytes\n\n## Local inspection findings\n\n",
            self.file.size_bytes
        ));
        match self.local_inspection.text_extraction {
            TextExtraction::Performed { limit_reached } => out.push_str(&format!("Readable-text extraction was performed. Extraction limit reached: **{}**.\n\n", limit_reached)),
            TextExtraction::SkippedBinaryOrNonText => out.push_str("Readable-text extraction was skipped because the content was binary or non-text.\n\n"),
        }
        out.push_str("## Extracted indicators\n\n");
        if self.local_inspection.indicators.is_empty() {
            out.push_str("No indicators were extracted.\n\n");
        } else {
            out.push_str("| Type | Value |\n|---|---|\n");
            for i in &self.local_inspection.indicators {
                out.push_str(&format!(
                    "| {} | `{}` |\n",
                    i.indicator_type.as_str(),
                    md_code(&i.value)
                ));
            }
            out.push('\n');
        }
        if !self.local_inspection.source_occurrences.is_empty() {
            out.push_str("## Local source occurrences\n\n| Source | Line | Type | Original value | Context |\n|---|---:|---|---|---|\n");
            for occurrence in &self.local_inspection.source_occurrences {
                out.push_str(&format!(
                    "| `{}` | {} | {} | `{}` | {} |\n",
                    md_code(&occurrence.source_filename),
                    occurrence.line_number,
                    occurrence.indicator.indicator_type.as_str(),
                    md_code(&occurrence.original_value),
                    md_plain(&occurrence.context)
                ));
            }
            out.push_str("\nThese are locally observed log values. They are separate from provider lookup evidence.\n\n");
        }
        out.push_str("## Original file hash lookup\n\n");
        let originals = self
            .provider_lookups
            .iter()
            .filter(|lookup| lookup.subject == LookupSubject::OriginalFileSha256)
            .collect::<Vec<_>>();
        if originals.is_empty() {
            out.push_str("No provider lookup was recorded for the original file SHA-256.\n\n");
        }
        for lookup in originals {
            render_lookup(&mut out, lookup);
        }

        out.push_str("## Extracted indicator lookups\n\n");
        let extracted = self
            .provider_lookups
            .iter()
            .filter(|lookup| {
                matches!(
                    lookup.subject,
                    LookupSubject::ExtractedIndicatorSha256 | LookupSubject::ExtractedIndicator
                )
            })
            .collect::<Vec<_>>();
        if extracted.is_empty() {
            out.push_str("No extracted indicators were queried.\n\n");
        }
        for lookup in extracted {
            render_lookup(&mut out, lookup);
        }
        out.push_str("## Interpretation and limitations\n\n");
        for line in &self.interpretation {
            out.push_str(&format!("- {}\n", md_plain(line)));
        }
        out
    }
}

fn render_lookup(out: &mut String, lookup: &ProviderLookup) {
    out.push_str(&format!(
        "### {} — {}\n\nQueried indicator: `{}`\n\n",
        md_plain(&lookup.provider),
        lookup.outcome.status(),
        md_code(&lookup.queried_hash)
    ));
    if let Some(timestamp) = lookup.retrieved_at_unix_seconds {
        out.push_str(&format!(
            "Retrieved at: {} seconds since the Unix epoch (UTC).\n\n",
            timestamp
        ));
    }
    match &lookup.outcome {
            LookupOutcome::Found(m) => out.push_str(&format!("- Matched SHA-256: `{}`\n- First seen: {}\n- File type: {}\n- Sample filename: {}\n- Signature: {}\n\n", md_code(&m.matched_sha256), md_plain(&m.first_seen), md_plain(&m.file_type), optional_display(m.sample_filename.as_deref()), optional_display(m.signature.as_deref()))),
            LookupOutcome::Invalid { explanation } | LookupOutcome::ApiError { explanation } | LookupOutcome::RequestError { explanation } => out.push_str(&format!("{}\n\n", md_plain(explanation))),
            LookupOutcome::SkippedDuplicate { references_hash } => out.push_str(&format!("Reuses the earlier result for `{}`; no second request was made.\n\n", md_code(references_hash))),
                LookupOutcome::NotFound => {
                    out.push_str(&format!("{} returned no matching record at lookup time. This does not establish that the subject is safe.", md_plain(&lookup.provider)));
                    if lookup.provider == "ThreatFox" { out.push_str(" ThreatFox may omit IOCs that have expired from its API dataset."); }
                    out.push_str("\n\n");
                }
                LookupOutcome::NotConfigured => out.push_str(&format!("{} configuration is missing, so no request was made.\n\n", md_plain(&lookup.provider))),
                LookupOutcome::SkippedLookupLimit => out.push_str("No request was made because the automatic lookup limit was reached.\n\n"),
            LookupOutcome::Unsupported { explanation } => out.push_str(&format!("Lookup unsupported: {}\n\n", md_plain(explanation))),
            LookupOutcome::ThreatFoxFound { findings } => {
                out.push_str("ThreatFox returned matching IOC records. A record is an observation, not a verdict about the original file.\n\n");
                if findings.is_empty() {
                    out.push_str("No IOC record details were recorded for this result.\n\n");
                }
                for finding in findings {
                    out.push_str(&format!("#### IOC `{}` ({})\n\n", md_code(&finding.ioc), md_plain(&finding.ioc_type)));
                    let confidence = finding.confidence_level.map(|value| value.to_string());
                    for (label, value) in [
                        ("IOC type description", finding.ioc_type_description.as_deref()),
                        ("Threat type", finding.threat_type.as_deref()),
                        ("Threat description", finding.threat_type_description.as_deref()),
                        ("Malware", finding.malware.as_deref()),
                        ("Malware name", finding.malware_printable.as_deref()),
                        ("Confidence", confidence.as_deref()),
                        ("First seen", finding.first_seen.as_deref()),
                        ("Last seen", finding.last_seen.as_deref()),
                        ("Reference", finding.reference.as_deref()),
                        ("Reporter", finding.reporter.as_deref()),
                        ("Source record ID", finding.source_record_id.as_deref()),
                    ] {
                        if let Some(value) = nonempty(value) { out.push_str(&format!("- {}: {}\n", label, md_plain(value.trim()))); }
                    }
                    let tags = finding.tags.iter().map(|tag| tag.trim()).filter(|tag| !tag.is_empty()).map(md_plain).collect::<Vec<_>>();
                    if !tags.is_empty() { out.push_str(&format!("- Tags: {}\n", tags.join(", "))); }
                    out.push('\n');
                }
            }
            LookupOutcome::UrlhausFound { details } => {
                let reference = nonempty(details.reference.as_deref())
                    .map(|value| md_plain(value.trim()))
                    .unwrap_or_else(|| "Not provided".into());
                let associated_count = details.associated_url_count.or_else(|| {
                    (!details.associated_urls.is_empty()).then_some(details.associated_urls.len())
                });
                out.push_str(&format!("URLhaus reference: {reference}\nAssociated URL records: {}\n", associated_count.map_or_else(|| "Not provided".into(), |count| count.to_string())));
                for (label, value) in [
                    ("Queried host", details.queried_host.as_deref()),
                    ("Payload MD5", details.md5_hash.as_deref()),
                    ("Payload SHA-256", details.sha256_hash.as_deref()),
                    ("File type", details.file_type.as_deref()),
                    ("First seen", details.first_seen.as_deref()),
                    ("Last seen", details.last_seen.as_deref()),
                    ("Signature", details.signature.as_deref()),
                ] {
                    if let Some(value) = nonempty(value) { out.push_str(&format!("- {label}: {}\n", md_plain(value.trim()))); }
                }
                for record in &details.associated_urls {
                    let url = nonempty(Some(&record.url)).map(str::trim).unwrap_or("Not provided");
                    let status = optional_display(record.status.as_deref());
                    let reference = optional_display(record.reference.as_deref());
                    out.push_str(&format!("- URL: `{}` · status: {status} · reference: {reference}\n", md_code(url)));
                    for (label, value) in [
                        ("Host", record.host.as_deref()),
                        ("Threat", record.threat.as_deref()),
                        ("Date added", record.date_added.as_deref()),
                        ("First seen", record.first_seen.as_deref()),
                        ("Last seen", record.last_seen.as_deref()),
                    ] {
                        if let Some(value) = nonempty(value) { out.push_str(&format!("  - {label}: {}\n", md_plain(value.trim()))); }
                    }
                    let tags = record.tags.iter().map(|tag| tag.trim()).filter(|tag| !tag.is_empty()).map(md_plain).collect::<Vec<_>>();
                    if !tags.is_empty() { out.push_str(&format!("  - Tags: {}\n", tags.join(", "))); }
                }
                out.push('\n');
            }
        }
}

fn nonempty(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.trim().is_empty())
}

fn optional_display(value: Option<&str>) -> String {
    nonempty(value)
        .map(|value| md_plain(value.trim()))
        .unwrap_or_else(|| "Not provided".into())
}

fn md_code(s: &str) -> String {
    let mut safe = String::new();
    for c in s.chars() {
        match c {
            c if c.is_control() => safe.push(' '),
            '`' => safe.push('\''),
            '|' => safe.push_str("\\|"),
            _ => safe.push(c),
        }
    }
    safe
}
fn md_plain(s: &str) -> String {
    let mut safe = String::new();
    for c in s.chars() {
        if c.is_control() {
            safe.push(' ');
        } else {
            if matches!(c, '\\' | '#' | '*' | '_' | '[' | ']' | '>' | '`' | '|') {
                safe.push('\\');
            }
            safe.push(c);
        }
    }
    safe
}
