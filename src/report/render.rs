use super::model::{
    InvestigationReport, LookupOutcome, LookupSubject, ProviderLookup, TextExtraction,
};

impl InvestigationReport {
    pub fn to_markdown(&self) -> String {
        let mut out =
            String::from("# CyberFeed Investigation Report\n\n## Investigation summary\n\n");
        out.push_str(&format!("- File: `{}` ({} bytes)\n- Original file SHA-256: `{}`\n- Original file lookup: {}\n- Extracted indicators: {} hashes, {} IP addresses, {} domains\n- Extracted hash lookups: {} found, {} not found, {} failed, {} skipped or unavailable\n- Extraction limit reached: {}\n- Generated at: {} seconds since the Unix epoch (UTC)\n\nCyberFeed read the file locally as data; it did not execute or upload it.\n\n", md_code(&self.file.filename), self.file.size_bytes, md_code(&self.file.sha256), self.summary.original_file_lookup_status.as_deref().unwrap_or("not recorded"), self.summary.extracted_indicator_counts.hashes, self.summary.extracted_indicator_counts.ip_addresses, self.summary.extracted_indicator_counts.domains, self.summary.extracted_hash_lookup_counts.found, self.summary.extracted_hash_lookup_counts.not_found, self.summary.extracted_hash_lookup_counts.failures, self.summary.extracted_hash_lookup_counts.skipped_or_unavailable, self.summary.extraction_limit_reached, self.generated_at_unix_seconds));
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

        out.push_str("## Extracted indicator hash lookups\n\n");
        let extracted = self
            .provider_lookups
            .iter()
            .filter(|lookup| lookup.subject == LookupSubject::ExtractedIndicatorSha256)
            .collect::<Vec<_>>();
        if extracted.is_empty() {
            out.push_str("No extracted SHA-256 indicators were queried. Extracted IP addresses and domains are not enriched by a connected provider.\n\n");
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
        "### {} — {}\n\nQueried hash: `{}`\n\n",
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
            LookupOutcome::Found(m) => out.push_str(&format!("- Matched SHA-256: `{}`\n- First seen: {}\n- File type: {}\n- Sample filename: {}\n- Signature: {}\n\n", md_code(&m.matched_sha256), md_plain(&m.first_seen), md_plain(&m.file_type), m.sample_filename.as_deref().map(md_plain).unwrap_or_else(|| "Not provided".into()), m.signature.as_deref().map(md_plain).unwrap_or_else(|| "Not provided".into()))),
            LookupOutcome::Invalid { explanation } | LookupOutcome::ApiError { explanation } | LookupOutcome::RequestError { explanation } => out.push_str(&format!("{}\n\n", md_plain(explanation))),
            LookupOutcome::SkippedDuplicate { references_hash } => out.push_str(&format!("Reuses the earlier result for `{}`; no second request was made.\n\n", md_code(references_hash))),
                LookupOutcome::NotFound => out.push_str(&format!("{} returned no matching record. This does not establish that the subject is safe.\n\n", md_plain(&lookup.provider))),
                LookupOutcome::NotConfigured => out.push_str(&format!("{} configuration is missing, so no request was made.\n\n", md_plain(&lookup.provider))),
                LookupOutcome::SkippedLookupLimit => out.push_str("No request was made because the automatic lookup limit was reached.\n\n"),
        }
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
            if matches!(c, '\\' | '#' | '*' | '_' | '[' | ']' | '>' | '`') {
                safe.push('\\');
            }
            safe.push(c);
        }
    }
    safe
}
