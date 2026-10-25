# Evaluation Report

## Public sample results

Evaluation uses only the participant-facing 32-row public sample and its supplied reference output. It does not use hidden answers.

- Case-level deletion-status accuracy: 32/32 = 100.0%.
- Exact step match (multiset precision / recall): 124/173 = 71.7% precision; 124/193 = 64.2% recall.
- Field-level positional accuracy over the seven required step fields: 1040/1358 = 76.6%.
- Exact ordered sequence accuracy (status and complete ordered JSON array): 13/32 = 40.6%.

The public sample status result is 32/32, while exact ordered step matching remains lower. Some public expected references are unsupported or ambiguous in the supplied evidence, as reported in challenge issue #19 (https://github.com/interviewstreet/hackerrank-orchestrate-october26/issues/19). The runner does not guess those resource IDs. Audit-retention records with their own pre-cutoff event timestamps are preserved even when a containing bundle was published later.

## Additional team-authored evaluation cases

1. **Non-deletion intent:** Request says “Please stop marketing email; do not delete my account.” Expected `NOT_APPLICABLE` and `[]`. The intent gate must stop evidence search and produce no deletion actions.
2. **Compliant tombstone:** A deleted account tombstone retains only stable `user_id`; name, email, phone, and email hash are null. Expected `COMPLETE`, with a cited `VERIFY_RECORD_REDACTED` for the tombstone and any required retained-record checks.
3. **Restorable backup:** A subject-linked backup has `restore_allowed=true` at the audit cutoff. Expected `INCOMPLETE`, with `REPORT_RESTORE_RISK`, `BLOCK_RESTORE`, then `VERIFY_RESTORE_BLOCKED`, all sorted with other steps by the contract.

## Failures found and improvements made

- Initial intent matching missed paraphrases such as “remove the search result” and “close it”; added broader multilingual deletion cues while preserving common non-deletion gates.
- Substring matching of stable user IDs could associate `user_15` with `user_150`; changed identifier matching to token boundaries.
- Evidence nested in SQL JSON payloads was not being associated with its source system/category; the extractor now reads embedded JSON and propagates service names.
- Per-file capture cutoffs are applied in addition to record timestamps so post-cutoff files do not affect a case.
- Operational log lines are correlated by trace ID, PDF text is extracted when `pdfplumber` is installed, and tombstones with null direct identifiers are treated separately from user-linked analytics.
- Remaining limitations: screenshots (`.png`) have no OCR dependency in the deterministic runner; sparse readback traces can omit records from other evidence sources; evidence-to-resource links that are absent from participant data cannot be inferred safely. This is reflected in step-level and sequence accuracy.
