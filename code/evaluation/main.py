"""Validate a generated deletion-audit output against the submission contract."""
from __future__ import annotations
import argparse, csv, json, re
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
DATA=ROOT/"dataset"
COLUMNS=("case_id","deletion_status","steps_json")
PHASE_ORDER={"FINDING":0,"REMEDIATION":1,"VERIFICATION":2}
OP_ORDER={
 "REPORT_REMAINING_RECORD":0,"REPORT_EXPOSED_PII":1,"REPORT_ACTIVE_DATA_FLOW":2,"REPORT_RESTORE_RISK":3,
 "DISABLE_DATA_FLOW":0,"BLOCK_RESTORE":1,"DELETE_RECORD":2,"REDACT_RECORD":3,"ANONYMIZE_RECORD":4,
 "VERIFY_RECORD_ABSENT":0,"VERIFY_RECORD_PRESENT":1,"VERIFY_RECORD_REDACTED":2,
 "VERIFY_RECORD_ANONYMIZED":3,"VERIFY_DATA_FLOW_DISABLED":4,"VERIFY_RESTORE_BLOCKED":5,
}
OP_STATE={
 "REPORT_REMAINING_RECORD":"PRESENT","REPORT_EXPOSED_PII":"PRESENT","REPORT_ACTIVE_DATA_FLOW":"ACTIVE","REPORT_RESTORE_RISK":"ACTIVE",
 "DISABLE_DATA_FLOW":"DISABLED","BLOCK_RESTORE":"BLOCKED","DELETE_RECORD":"ABSENT","REDACT_RECORD":"REDACTED","ANONYMIZE_RECORD":"ANONYMIZED",
 "VERIFY_RECORD_ABSENT":"ABSENT","VERIFY_RECORD_PRESENT":"PRESENT","VERIFY_RECORD_REDACTED":"REDACTED",
 "VERIFY_RECORD_ANONYMIZED":"ANONYMIZED","VERIFY_DATA_FLOW_DISABLED":"DISABLED","VERIFY_RESTORE_BLOCKED":"BLOCKED",
}
STEP_FIELDS={"step_no","phase","system_id","resource_id","operation","state","evidence_id"}

def load(path:Path):
 with path.open(encoding="utf-8-sig",newline="") as f:return list(csv.DictReader(f))

def validate(path:Path):
 requests=load(DATA/"deletion_requests.csv")
 rows=load(path)
 expected=[r["case_id"] for r in requests]
 actual=[r["case_id"] for r in rows]
 assert rows and tuple(rows[0])==COLUMNS, f"Expected columns {COLUMNS}"
 assert len(rows)==len(expected),f"Expected {len(expected)} rows, got {len(rows)}"
 assert actual==sorted(expected),"Rows must contain each expected case exactly once, sorted by case_id"
 valid_evidence={r["file_id"] for r in load(DATA/"evidence_files.csv")}
 valid_evidence.update(r["activity_id"] for r in load(DATA/"system_activity.csv"))
 valid_evidence.update(r["audit_id"] for r in load(DATA/"user_audit_log.csv"))
 for row in rows:
  case=row["case_id"]; status=row["deletion_status"]
  assert status in {"COMPLETE","INCOMPLETE","NOT_APPLICABLE"},f"{case}: invalid status {status}"
  steps=json.loads(row["steps_json"])
  assert isinstance(steps,list),f"{case}: steps_json must be an array"
  assert [s.get("step_no") for s in steps]==list(range(1,len(steps)+1)),f"{case}: step numbers not consecutive"
  assert all(set(s)==STEP_FIELDS for s in steps),f"{case}: incorrect step keys"
  assert all(s["phase"] in PHASE_ORDER for s in steps),f"{case}: invalid phase"
  assert all(s["operation"] in OP_ORDER for s in steps),f"{case}: invalid operation"
  assert all(s["state"]==OP_STATE[s["operation"]] for s in steps),f"{case}: invalid operation/state pair"
  assert all(s["system_id"] and s["resource_id"] for s in steps),f"{case}: system/resource must be populated"
  keys=[(PHASE_ORDER[s["phase"]],OP_ORDER[s["operation"]],s["system_id"],s["resource_id"]) for s in steps]
  assert keys==sorted(keys),f"{case}: steps violate phase/operation/system/resource order"
  if status=="NOT_APPLICABLE": assert steps==[],f"{case}: NOT_APPLICABLE must have no steps"
  for s in steps:
   citation=s["evidence_id"]
   if s["phase"]=="FINDING" or (status=="COMPLETE" and s["phase"]=="VERIFICATION"):
    assert citation in valid_evidence,f"{case}: missing or invalid evidence citation {citation!r}"
   if status=="INCOMPLETE" and s["phase"]=="VERIFICATION":
    assert citation=="",f"{case}: future verification must have empty evidence_id"
 print(f"Validated {len(rows)} rows in {path}")

if __name__=="__main__":
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument("--output",type=Path,default=ROOT/"output.csv")
 args=parser.parse_args()
 validate(args.output)
