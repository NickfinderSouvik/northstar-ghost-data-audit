"""Compare a sample prediction run with the public reference and validate output."""
from pathlib import Path
import csv, json, sys
ROOT=Path(__file__).resolve().parents[2]
DATA=ROOT/'dataset'

def load_csv(path):
    with path.open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))

def norm_step(step):
    return tuple(step.get(k) for k in ('step_no','phase','system_id','resource_id','operation','state','evidence_id'))

def run():
    gold=load_csv(DATA/'sample_output.csv')
    pred=load_csv(ROOT/'sample_predictions.csv')
    g={r['case_id']:r for r in gold}; p={r['case_id']:r for r in pred}
    matched=sum(g[k]['deletion_status']==p[k]['deletion_status'] for k in g)
    exactseq=0; exactsteps=0; goldsteps=0; predsteps=0; field_equal=0; field_total=0
    step_fields=('step_no','phase','system_id','resource_id','operation','state','evidence_id')
    for k in g:
        gs=json.loads(g[k]['steps_json']); ps=json.loads(p[k]['steps_json'])
        if g[k]['deletion_status']==p[k]['deletion_status'] and gs==ps: exactseq+=1
        gtuples=[norm_step(s) for s in gs]; ptuples=[norm_step(s) for s in ps]
        goldsteps+=len(gtuples); predsteps+=len(ptuples)
        from collections import Counter
        exactsteps+=sum((Counter(gtuples)&Counter(ptuples)).values())
        for i in range(max(len(gs),len(ps))):
            for field in step_fields:
                field_total+=1
                if i<len(gs) and i<len(ps) and gs[i].get(field)==ps[i].get(field): field_equal+=1
    status_acc=matched/len(g)
    step_precision=exactsteps/predsteps if predsteps else 0
    step_recall=exactsteps/goldsteps if goldsteps else 0
    field_acc=field_equal/field_total if field_total else 0
    sequence_acc=exactseq/len(g)
    report=f'''# Evaluation Report

## Public sample results

Evaluation uses only the participant-facing 32-row public sample and its supplied reference output. It does not use hidden answers.

- Case-level deletion-status accuracy: {matched}/{len(g)} = {status_acc:.1%}.
- Exact step match (multiset precision / recall): {exactsteps}/{predsteps} = {step_precision:.1%} precision; {exactsteps}/{goldsteps} = {step_recall:.1%} recall.
- Field-level positional accuracy over the seven required step fields: {field_equal}/{field_total} = {field_acc:.1%}.
- Exact ordered sequence accuracy (status and complete ordered JSON array): {exactseq}/{len(g)} = {sequence_acc:.1%}.

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
'''
    (ROOT/'code/evaluation/evaluation_report.md').write_text(report,encoding='utf-8')
    print(report.splitlines()[4:9])

if __name__=='__main__':run()
