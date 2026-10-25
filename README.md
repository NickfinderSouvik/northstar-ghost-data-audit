# Ghost Data Still Exists — Deletion Audit Agent

An evidence-grounded, deterministic deletion-audit solution for the Northstar Shop challenge. It reviews deletion requests, resolves current and historical identifiers, checks the supplied evidence at each request's audit time, applies the deletion policy, and writes an ordered audit plan.

## Requirements

- Python 3.10 or later
- The challenge's participant-facing `dataset/` directory at the repository root. It is intentionally not included in this project archive; obtain it from the official challenge repository.
- `pdfplumber` is optional. Install it with `python -m pip install -r code/requirements.txt` to extract selectable text from PDF evidence.

The runner uses no external model provider, API key, or network connection. It makes no model calls when generating predictions.

## Run

From the repository root, generate predictions for all requests:

```text
python code/main.py
```

The runner reads `dataset/deletion_requests.csv` and writes `output.csv` in the repository root. To use a different request file or output location:

```text
python code/main.py --requests dataset/sample_deletion_requests.csv --output sample_predictions.csv
```

Or use the built-in public-sample shortcut:

```text
python code/main.py --sample
```

## Validate and evaluate

Check the full output's row count, columns, JSON structure, step numbering, operation/state combinations, citations, and order:

```text
python code/evaluation/main.py --output output.csv
```

Compare `sample_predictions.csv` with the 32-case public reference and refresh the evaluation report:

```text
python code/evaluation/evaluate.py
```

The evaluation uses the provided public sample only; it does not use hidden answers.

## How it works

1. **Resolve identity:** combines the request email with current and historical email, name, phone, user ID, and email-hash values.
2. **Collect evidence:** reads the evidence manifest and indexes supported SQL snapshots, JSON records, logs, text records, and optional PDF text. Structured log events can inherit a subject key from events sharing a trace ID.
3. **Apply time and identity links:** checks file and record timestamps against `audit_at`, follows explicit identity/resource links, and uses activity only to connect a subject to a resource handle. Activity results do not prove the resource's state.
4. **Apply policy:** creates findings and remediation steps for remaining personal data, active sync paths, restorable backups, and records that must be retained. It orders findings, remediation, and verification steps according to the challenge contract.
5. **Write output:** emits one sorted CSV row per request with the required `case_id,deletion_status,steps_json` header.

## Public sample results

Current results against the supplied 32-row sample:

- Deletion-status accuracy: **32/32**.
- Exact ordered step-sequence accuracy: **13/32**.
- Exact step matches: **124/193** reference steps.

The step score is lower because some expected resource references are absent or ambiguous in the participant evidence. Challenge [issue #19](https://github.com/interviewstreet/hackerrank-orchestrate-october26/issues/19) reports missing expected audit records for cases 18 and 20 and an ambiguous account reference for case 23. The implementation does not guess unsupported resource IDs. See `code/evaluation/evaluation_report.md` for detailed metrics and known limitations.

## Project files

- `code/main.py` — deterministic audit runner.
- `code/AUDIT_AGENT_PROMPT.md` — reusable audit decision contract.
- `code/evaluation/evaluate.py` — public sample comparison and report generator.
- `code/evaluation/main.py` — output validator.
- `code/evaluation/evaluation_report.md` — sample metrics, extra evaluation cases, failures, and fixes.
- `code/evaluation/usage_report.md` — final run model-call and token-cost accounting.

## Development environment

Developed with OpenAI Codex desktop. This describes the development tool; the submitted runner is local Python code and does not call Codex or another model at runtime.
