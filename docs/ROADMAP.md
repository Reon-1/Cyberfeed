# Roadmap

- Recheck saved report indicators with a separate snapshot and typed comparison. Today `src/app/file_workflow/lookups.rs` owns scheduling state inside the interactive file workflow and exposes provider-specific helpers rather than a reusable investigation-level scheduler. Extracting that shared bounded pipeline should precede recheck or enrichment so limits and deduplication cannot drift.
- Offer opt-in batch/log enrichment only after the same shared scheduler is available; local-only behavior remains the default.
- Add vendor-specific log parsers only when their schemas and field provenance can be tested with public or synthetic fixtures. Current hunting supports plain text and JSONL token extraction.

These are deferred capabilities; the current UI does not advertise them as implemented.
