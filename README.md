# Ghost Data Still Exists - runnable audit solution

## Run

Place this `code/` directory and this README at the repository root beside the supplied `dataset/` directory. Use Python 3.10 or later.

```powershell
python code/main.py
```

The runner reads the participant-facing CSVs and evidence from `dataset/` and writes `output.csv` at the repository root. Use `python code/main.py --sample` to create `sample_predictions.csv` for comparison with the public 32-case sample.

Install `pdfplumber` to extract selectable PDF text:

```powershell
python -m pip install -r code/requirements.txt
```

Image OCR is not implemented in this baseline. No external model provider, API key, or network access is required.

## Design

The runner resolves current and historical emails, names, phone numbers, and email hashes, then searches JSON snapshots, SQLite-compatible SQL exports, logs, text records, and PDFs. Evidence is filtered by file capture time and record time relative to each case’s `audit_at`; retained security audit records use their own event timestamp if the containing bundle is published later. System activity is used only to connect identity references to resource IDs; evidence content establishes state. A deterministic policy mapper creates findings, remediation actions, and verification steps in the required phase and operation order. Reported workflow status is not used as proof.

The reusable audit decision contract is in `code/AUDIT_AGENT_PROMPT.md`. The public sample evaluator is available at `code/evaluation/evaluate.py`. Evaluation and token reports are in `code/evaluation/`.

## Limitations

The baseline does not OCR screenshots and cannot resolve relationships absent from the supplied evidence. Exact step sequence accuracy on the public sample is reported in `code/evaluation/evaluation_report.md`; status accuracy alone does not establish complete evidence recall.
## Development environment

Development tool: OpenAI Codex desktop. The submitted runner is a deterministic local Python program and makes no model calls during prediction generation.
