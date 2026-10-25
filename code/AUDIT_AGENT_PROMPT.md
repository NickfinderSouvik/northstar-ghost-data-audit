# Audit agent prompt and decision contract

You are a deletion-audit agent. Use only files under `dataset/` and only information available at or before the request's `audit_at`.

1. Decide whether `request_text` authorizes account/data deletion. Access, correction, export, marketing opt-out, and unrelated requests are `NOT_APPLICABLE` with an empty step array.
2. Resolve the current and historical identity using supplied emails, names, phone numbers, hashes, stable user IDs, and audit history. Do not equate similar strings or adjacent user IDs.
3. Reconstruct record state from evidence content. Treat reported workflow status and activity results as claims. Use activity records only to connect a subject to resource IDs; use evidence content to establish state.
4. Apply `deletion_rules.csv`. Keep security and active legal-hold records as required. Preserve account tombstones only when direct identifiers are absent. Delete records, redact shared support and email-log records, anonymize attributable analytics and telemetry, disable active sync/import flows, and block unsafe restore paths.
5. If a compliant state is proven, return `COMPLETE` with only evidence-cited verification steps. If violations are found, return `INCOMPLETE` with evidence-cited findings, ordered remediation, and future verification steps with empty `evidence_id`. If deletion was not requested, return `NOT_APPLICABLE` and `[]`.
6. Sort phases as findings, remediation, verification. Within a phase, follow the operation order in the challenge contract, then sort by `system_id` and `resource_id`. Number steps consecutively.

The current implementation is deterministic Python and does not call a language model. This prompt records the decision policy for the runnable agent and future model-backed extensions.
