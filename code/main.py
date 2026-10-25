"""Deterministic evidence-grounded deletion audit runner (standard library only)."""
from __future__ import annotations
import argparse, csv, datetime as dt, hashlib, json, re, sqlite3, sys
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "dataset"
OUT = ROOT / "output.csv"
FILE_PATHS = {}
RULE_ACTIONS = {}

OP_ORDER = {"REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1, "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3,
            "DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2, "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4,
            "VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1, "VERIFY_RECORD_REDACTED": 2,
            "VERIFY_RECORD_ANONYMIZED": 3, "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5}


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as f: return list(csv.DictReader(f))

def parse_time(v):
    if not v: return None
    try: return dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError: return None

def norm(s): return str(s).strip().casefold()
def flatten(obj):
    if isinstance(obj, dict):
        out=[]
        for k,v in obj.items(): out.extend([str(k), *flatten(v)])
        return out
    if isinstance(obj, list):
        out=[]
        for v in obj: out.extend(flatten(v))
        return out
    if obj is None: return []
    return [str(obj)]
def hash_email(s): return hashlib.sha256(norm(s).encode()).hexdigest()
def sys_from(s):
    x=norm(s)
    if "account" in x or "profile" in x: return "account_service"
    if "search" in x or "index" in x: return "search_service"
    if "support" in x or "attachment" in x: return "support_platform"
    if "analytics" in x or "telemetry" in x: return "analytics_platform"
    if "export" in x: return "export_service"
    if "marketing" in x: return "marketing_service"
    if "email" in x or "notification" in x: return "messaging_service"
    if "security" in x or "audit" in x: return "security_service"
    if "legal" in x: return "legal_service"
    if "backup" in x or "restore" in x: return "backup_service"
    if "integration" in x or "connector" in x or "flow" in x or "sync" in x: return "integration_service"
    return ""

class Evidence:
    def __init__(self): self.items=[]; self.current_file_time=None; self.by_key=defaultdict(list); self.snapshots=[]
    def add(self, fid, captured, sysid, rid, category, values, state="PRESENT", direct=False, text=""):
        self.items.append(dict(fid=fid, file_time=self.current_file_time, time=parse_time(captured), system=str(sysid or "").strip(), rid=str(rid or "").strip(), category=str(category or "").strip(),
                               values=[norm(x) for x in values if x], state=state.upper(), direct=direct, text=norm(text)))

def load_evidence():
    manifest=read_csv(DATA/"evidence_files.csv"); ev=Evidence()
    FILE_PATHS.update({m["file_id"]:m["file_path"] for m in manifest})
    for m in manifest:
        p=DATA/m["file_path"]
        if not p.exists(): continue
        fid, cap=m["file_id"],m["captured_at"]
        ev.current_file_time=parse_time(cap)
        ext=p.suffix.lower()
        if ext==".json":
            try: data=json.loads(p.read_text(encoding="utf-8"))
            except Exception: continue
            def walk(x, parent_sys="", parent_cat="", cap0=cap):
                if isinstance(x,dict):
                    sc=x.get("data_store") or x.get("system") or x.get("system_id") or x.get("service") or parent_sys
                    cat=x.get("record_type") or x.get("data_category") or x.get("category") or x.get("collection") or parent_cat
                    if str(cat).casefold()=="deleted_customer_references": cat="ACCOUNT_TOMBSTONE"
                    if sys_from(sc)=="analytics_platform" and str(cat).casefold() in ("profiles","analytics_profiles"): cat="ANALYTICS_PROFILE"
                    if sys_from(sc)=="search_service" and str(cat).casefold() in ("profiles","documents"): cat="SEARCH_INDEX_ENTRY"
                    if sys_from(sc)=="support_platform" and "attachment" in str(cat).casefold(): cat="SUPPORT_ATTACHMENT"
                    if sys_from(sc)=="support_platform" and str(cat).casefold() in ("messages","conversations","records"): cat="SUPPORT_MESSAGE"
                    when=x.get("captured_at") or x.get("observed_at") or x.get("recorded_at") or x.get("event_time") or cap0
                    rid=x.get("resource_id") or x.get("record_id") or x.get("id")
                    vals=flatten(x)
                    if rid:
                        state="PRESENT"
                        status_values=[str(v).casefold() for k,v in x.items() if k.casefold() in ("result","status","state","record_status","lookup_result","operation_status") and v is not None]
                        status=" ".join(status_values)
                        if str(x.get("status_code",""))=="404": state="ABSENT"
                        if any(k in status for k in ["not_found", "absent"]): state="ABSENT"
                        if "anonymized" in status: state="ANONYMIZED"
                        if "redacted" in status: state="REDACTED"
                        if "blocked" in status: state="BLOCKED"
                        if "active" in status: state="ACTIVE"
                        if x.get("restore_allowed") is False: state="BLOCKED"
                        if x.get("enabled") is False: state="DISABLED"
                        if x.get("deletion_block") is True: state="BLOCKED"
                        ev.add(fid,when,sys_from(sc) or sc,rid,cat,vals,state=state,direct=True,text=" ".join(vals))
                    for k,v in x.items():
                        child_sys=sys_from(k) or sc
                        child_cat=cat or k
                        if str(cat).casefold() in ("service_exports","exports"):
                            child_cat={"account_service":"USER_PROFILE","search_service":"SEARCH_INDEX_ENTRY","analytics_platform":"ANALYTICS_PROFILE","support_platform":"SUPPORT_MESSAGE","export_service":"USER_EXPORT","backup_service":"BACKUP_ARCHIVE","integration_service":"DATA_FLOW","security_service":"SECURITY_AUDIT_LOG"}.get(child_sys,child_cat)
                        walk(v,child_sys,child_cat,when)
                elif isinstance(x,list):
                    for v in x: walk(v,parent_sys,parent_cat,cap0)
            walk(data)
        elif ext==".sql":
            # Execute participant-facing SQLite-compatible snapshots read-only in memory.
            try:
                con=sqlite3.connect(":memory:"); con.executescript(p.read_text(encoding="utf-8",errors="replace"))
                for (table,) in con.execute("select name from sqlite_master where type='table'"):
                    cur=con.execute(f'SELECT * FROM "{table}"'); cols=[d[0] for d in cur.description]
                    table_rows=cur.fetchall(); table_resources=set()
                    for row in table_rows:
                        rec=dict(zip(cols,row)); vals=flatten(rec); rid=next((v for k,v in rec.items() if k.lower() in ("resource_id","record_id","id")),"")
                        if rid: table_resources.add(str(rid))
                        nested={}
                        for value in rec.values():
                            if isinstance(value,str) and value.startswith("{"):
                                try: nested=json.loads(value); break
                                except Exception: pass
                        sysid=rec.get("origin_system") or rec.get("system") or sys_from(table) or sys_from(p.name)
                        cat=rec.get("table_name") or rec.get("record_type") or table
                        state="PRESENT"
                        if "enabled" in rec and str(rec["enabled"]).casefold() in ("0","false","no"): state="DISABLED"
                        if "restore_allowed" in rec and str(rec["restore_allowed"]).casefold() in ("0","false","no"): state="BLOCKED"
                        if nested:
                            vals.extend(flatten(nested))
                            if "ACCOUNT_TOMBSTONE" in str(nested.get("data_category","")): cat="ACCOUNT_TOMBSTONE"
                        if rid: ev.add(fid,cap,sysid,rid,cat,vals,state=state,text=" ".join(vals))
                    table_key=table.casefold()
                    if "customer_profile" in table_key and "resource_id" in [c.casefold() for c in cols]:
                        ev.snapshots.append({"fid":fid,"file_time":parse_time(cap),"system":"account_service","category":"USER_PROFILE","resources":table_resources})
                con.close()
            except Exception: pass
        elif ext in (".txt",".log"):
            lines=p.read_text(encoding="utf-8",errors="replace").splitlines()
            trace_keys={}
            for line in lines:
                tr=re.search(r"trace_id=([\w-]+)",line)
                key=re.search(r"(?:lookup_key|subject_key|correlation_key|matched_value|subject_ref)=\"?([^\" ]+)\"?",line)
                if tr and key: trace_keys[tr.group(1)]=key.group(1)
                # Structured exports often embed one JSON event after the timestamp.
                try:
                    obj=json.loads(line.split(" ",1)[1])
                    tr_id=obj.get("trace_id")
                    alias=next((obj.get(k) for k in ("lookup_key","subject_key","correlation_key","matched_value","subject_ref","match_key","owner_key") if obj.get(k)),None)
                    if tr_id and alias: trace_keys[str(tr_id)]=str(alias)
                except (ValueError, IndexError, TypeError):
                    pass
            for line in lines:
                # Handover format: timestamp | system | resource | category | result | subject
                m2=re.search(r"(20\d\d-\d\d-\d\dT[^ |]+)\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*(.*)",line)
                if m2:
                    when,sy,rid,cat,state,subject=m2.groups(); ev.add(fid,when,sys_from(sy),rid,cat,[subject,rid,cat,state],state=state,direct=True,text=line); continue
                # Structured JSON service events preserve exact field boundaries and
                # allow the record to inherit its subject key from a sibling event
                # sharing the same trace ID.
                try:
                    obj=json.loads(line.split(" ",1)[1])
                except (ValueError, IndexError, TypeError):
                    obj=None
                if isinstance(obj,dict) and obj.get("resource_id"):
                    rid=str(obj["resource_id"])
                    service=str(obj.get("service") or obj.get("logger") or "")
                    event=str(obj.get("event") or "LOG_EVENT")
                    trace=str(obj.get("trace_id") or "")
                    key=next((obj.get(k) for k in ("lookup_key","subject_key","correlation_key","matched_value","subject_ref","match_key","owner_key") if obj.get(k)),None)
                    alias=str(key or trace_keys.get(trace,""))
                    raw_state=" ".join(str(obj.get(k,"")) for k in ("http_status","rows","result","enabled","restore_allowed","deletion_block","scheduler_registered","decision"))
                    state="ABSENT" if str(obj.get("http_status"))=="404" or str(obj.get("rows"))=="0" or str(obj.get("result","")).casefold() in ("not_found","absent") else "DISABLED" if str(obj.get("enabled")).casefold()=="false" or str(obj.get("scheduler_registered")).casefold()=="false" else "BLOCKED" if str(obj.get("deletion_block")).casefold()=="true" or str(obj.get("decision","")).casefold()=="deny" else "ACTIVE" if str(obj.get("enabled")).casefold()=="true" or str(obj.get("restore_allowed")).casefold()=="true" else "PRESENT"
                    if "support" in service.casefold():
                        if "attachment" in event.casefold(): event="SUPPORT_ATTACHMENT"
                        elif "message" in event.casefold(): event="SUPPORT_MESSAGE"
                    if "analytics" in service.casefold() and "profile" in event.casefold(): event="ANALYTICS_PROFILE"
                    if "search" in service.casefold() and "index" in event.casefold(): event="SEARCH_INDEX_ENTRY"
                    if "account" in service.casefold() and "profile" in event.casefold(): event="USER_PROFILE"
                    if "backup" in service.casefold(): event="BACKUP_ARCHIVE"
                    if "integration" in service.casefold() or "connector" in event.casefold(): event="DATA_FLOW"
                    if "audit_record" in event.casefold(): event="SECURITY_AUDIT_LOG"
                    ev.add(fid,line[:20],sys_from(service),rid,event,[rid,alias,line],state=state,direct=bool(key or alias),text=line)
                    continue
                # Key-value structured service traces and operational records
                ridm=re.search(r"resource_id=([\w-]+)",line)
                if ridm:
                    rid=ridm.group(1); svc=re.search(r"service=([\w-]+)",line); event=re.search(r"event=([\w-]+)",line)
                    key=re.search(r"(?:lookup_key|subject_key|correlation_key|matched_value|subject_ref)=\"?([^\" ]+)\"?",line)
                    tr=re.search(r"trace_id=([\w-]+)",line)
                    alias=key.group(1) if key else trace_keys.get(tr.group(1),"") if tr else ""
                    vals=[rid, alias, line]
                    state="ABSENT" if "http_status=404" in line or "rows=0" in line else "DISABLED" if "enabled=false" in line or "scheduler_registered=false" in line else "BLOCKED" if "deletion_block=true" in line else "ACTIVE" if "enabled=true" in line or "restore_allowed=true" in line or "restore_candidate_evaluated eligible=true" in line else "PRESENT"
                    event_name=event.group(1) if event else "LOG_EVENT"
                    if "support" in (svc.group(1) if svc else ""):
                        if "attachment" in event_name: event_name="SUPPORT_ATTACHMENT"
                        elif "message" in event_name: event_name="SUPPORT_MESSAGE"
                    if "analytics" in (svc.group(1) if svc else "") and "profile" in event_name: event_name="ANALYTICS_PROFILE"
                    if "search" in (svc.group(1) if svc else "") and "index" in event_name: event_name="SEARCH_INDEX_ENTRY"
                    if "account" in (svc.group(1) if svc else "") and "profile" in event_name: event_name="USER_PROFILE"
                    if "backup" in (svc.group(1) if svc else ""): event_name="BACKUP_ARCHIVE"
                    if "integration" in (svc.group(1) if svc else "") or "connector" in event_name: event_name="DATA_FLOW"
                    if "audit_record" in event_name: event_name="SECURITY_AUDIT_LOG"
                    ev.add(fid,line[:20],sys_from(svc.group(1)) if svc else "",rid,event_name,vals,state=state,direct=bool(key or alias),text=line)
        elif ext==".pdf":
            try:
                import pdfplumber
                text="\n".join(page.extract_text() or "" for page in pdfplumber.open(p).pages)
            except Exception:
                text=""
            ids=re.findall(r"\b(?:account|search|support|analytics|export|backup|data_flow|audit_record|tombstone)_\d+\b",text,re.I)
            cat=("SUPPORT_ATTACHMENT" if "support" in p.name.lower() or "attachment" in p.name.lower() else
                 "SECURITY_AUDIT_LOG" if "security" in p.name.lower() or "retention" in p.name.lower() else "BUSINESS_DOCUMENT")
            system=sys_from(p.name) or ("support_platform" if cat=="SUPPORT_ATTACHMENT" else "security_service" if cat=="SECURITY_AUDIT_LOG" else "")
            for rid in sorted(set(ids)):
                context=text if len(set(ids))==1 else " ".join(line for line in text.splitlines() if rid.casefold() in line.casefold())
                ev.add(fid,cap,system,rid,cat,[context],state="PRESENT",direct=True,text=context)
        # Image OCR is optional; images without extracted text are not treated as proof.
    # Inverted exact-identifier index avoids rescanning every artifact for every case.
    email_re=re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}")
    id_re=re.compile(r"\buser_\d+\b",re.I)
    hash_re=re.compile(r"\b[a-fA-F0-9]{64}\b")
    for item in ev.items:
        keys=set(item["values"])
        source=" ".join(item["values"]+[item["text"]])
        keys.update(norm(x) for x in email_re.findall(source))
        keys.update(norm(x) for x in id_re.findall(source))
        keys.update(norm(x) for x in hash_re.findall(source))
        for key in keys:
            if key: ev.by_key[key].append(item)
    return ev

def build_identities():
    users={}
    for r in read_csv(DATA/"user_identities.csv"):
        users[r["user_id"]]={k:[r[k]] for k in ("name","email","phone","email_hash") if r.get(k)}
    audits=read_csv(DATA/"user_audit_log.csv")
    for a in audits:
        u=users.setdefault(a["user_id"],defaultdict(list))
        if a.get("field_name") in ("name","email","phone","email_hash"):
            if a.get("old_value"): u[a["field_name"]].append(a["old_value"])
            if a.get("new_value"): u[a["field_name"]].append(a["new_value"])
    for u, fields in users.items():
        vals=set()
        for v in fields.values(): vals.update(norm(x) for x in v if x)
        for email in list(fields.get("email",[])): vals.add(hash_email(email))
        users[u]["_all"]=sorted(vals)
    return users,audits

def deletion_intent(text):
    t=norm(text)
    # English plus common challenge languages; negate opt-out/access/export/correction unless delete verbs present.
    nondelete=["do not delete","don't delete","not requesting deletion","access my data","export my data","correct my","update my","unsubscribe","opt out","stop marketing","no deletion"]
    if any(x in t for x in nondelete): return False
    keys=["delet", "eras", "close my account", "close this account", "close the account", "remove my account", "remove the profile", "remove the personal details", "remove that search result", "remove records linked", "remove records under", "clean my personal details out", "would like it closed", "close it", "close the account completely", "profile is gone", "account and identifiable analytics data", "confirm the result once the verification is complete", "confirm when the review is complete", "erase", "erased", "erase the account", "confirm that the profile is gone", "confirm the result after completing", "disconnect my account", "suppression of my account", "supprimer", "suppression", "eliminar", "eliminación", "borrar", "löschen", "lösche", "entfernen", "eliminare", "cancellare", "hapus", "menghapus", "xóa", "xoá", "удал", "删除", "消除", "削除", "계정 삭제", "verwijder", "slet", "poistaa"]
    return any(k in t for k in keys)


def related(item, user_id, aliases):
    hay=" ".join(item["values"]+[item["text"]])
    if user_id and re.search(r"(?<![a-z0-9])"+re.escape(norm(user_id))+r"(?![a-z0-9])",hay): return True
    # match token boundary to avoid substrings in IDs or unrelated addresses
    return any(re.search(r"(?<![a-z0-9])"+re.escape(a)+r"(?![a-z0-9])",hay) for a in aliases if len(a)>2)

def canonical_category(system, resource, category, text):
    c=str(category or "").upper()
    # Resource namespace disambiguates records inside mixed-system exports.
    prefix_system={"account_":"account_service","search_":"search_service","support_":"support_platform",
                   "analytics_":"analytics_platform","export_":"export_service","backup_":"backup_service",
                   "data_flow_":"integration_service","audit_record_":"security_service","tombstone_":"identity_service"}
    for prefix, inferred in prefix_system.items():
        if str(resource).startswith(prefix):
            system=inferred
            break
    if "TOMBSTONE" in c or str(resource).startswith("tombstone_"): return "ACCOUNT_TOMBSTONE"
    if "ATTACHMENT" in c: return "SUPPORT_ATTACHMENT"
    if "SUPPORT" in c or system=="support_platform": return "SUPPORT_MESSAGE"
    if "ANALYTICS" in c or system=="analytics_platform": return "ANALYTICS_PROFILE"
    if "TELEMETRY" in c: return "PRODUCT_TELEMETRY"
    if "SEARCH" in c or system=="search_service": return "SEARCH_INDEX_ENTRY"
    if "USER_PROFILE" in c or "CUSTOMER_PROFILE" in c or system=="account_service": return "USER_PROFILE"
    if "EXPORT" in c or system=="export_service": return "USER_EXPORT"
    if "MARKETING" in c or system=="marketing_service": return "MARKETING_PROFILE"
    if "EMAIL_DELIVERY" in c or system=="messaging_service": return "EMAIL_DELIVERY_LOG"
    if "SECURITY_AUDIT" in c or system=="security_service": return "SECURITY_AUDIT_LOG"
    if "LEGAL_HOLD" in c or system=="legal_service": return "LEGAL_HOLD_RECORD"
    if "BACKUP" in c or system=="backup_service": return "BACKUP_ARCHIVE"
    if "FLOW" in c or "CONNECTOR" in c or system=="integration_service": return "DATA_FLOW"
    return c

def category_action(cat, text):
    c=norm(cat).upper(); t=text.casefold()
    aliases={"CUSTOMER_PROFILES":"USER_PROFILE","CUSTOMER_SEARCH_DOCUMENTS":"SEARCH_INDEX_ENTRY","CUSTOMER_ANALYTICS_PROFILES":"ANALYTICS_PROFILE","CUSTOMER_ANALYTICS_REPORTS":"ANALYTICS_PROFILE","SUPPORT_RECORDS":"SUPPORT_MESSAGE","SUPPORT_CONVERSATIONS":"SUPPORT_MESSAGE","CUSTOMER_EXPORTS":"USER_EXPORT","CONNECTOR_SUBSCRIPTIONS":"PRODUCT_TELEMETRY","BACKUP_RESTORE_ENTRIES":"BACKUP_ARCHIVE","SECURITY_AUDIT_RECORDS":"SECURITY_AUDIT_LOG","DELETED_CUSTOMER_REFERENCES":"ACCOUNT_TOMBSTONE"}
    c=aliases.get(c,c)
    if c in RULE_ACTIONS: return RULE_ACTIONS[c]
    if "USER_PROFILE" in c or "CUSTOMER_PROFILE" in c or "SECONDARY_IDENTIFIER" in c or "SEARCH_INDEX" in c or "CACHE_ENTRY" in c or "USER_EXPORT" in c or "CUSTOMER_EXPORT" in c or "MARKETING_PROFILE" in c: return "DELETE"
    if "SUPPORT_ATTACHMENT" in c: return "DELETE"
    if "SUPPORT_MESSAGE" in c or "SUPPORT_RECORD" in c or "EMAIL_DELIVERY_LOG" in c or "ACCOUNT_TOMBSTONE" in c or "TOMBSTONE" in c: return "REDACT"
    if "ANALYTICS" in c or "TELEMETRY" in c: return "ANONYMIZE"
    if "SECURITY_AUDIT" in c: return "RETAIN"
    if "LEGAL_HOLD" in c: return "RETAIN"
    if "BACKUP_ARCHIVE" in c: return "RETAIN"
    return "DELETE"

def correlate_activity_to_requests(requests, activities, account_window_seconds=600, analytics_window_seconds=1800):
    """Link one unique worker resource to a request using its report timestamp.

    Only account deletion and analytics anonymization actions qualify. The
    activity result is never taken as state evidence; it supplies a resource
    handle only, which must be independently checked against evidence.
    """
    eligible=[]
    for req in requests:
        if not deletion_intent(req.get("request_text","")): continue
        reported=parse_time(req.get("reported_at",""))
        audit=parse_time(req.get("audit_at",""))
        if reported: eligible.append((req,reported,audit))
    assignments=defaultdict(list)
    for act in activities:
        if act.get("source_system")!="deletion_worker" or not act.get("resource_id"): continue
        event_key=(act.get("event_type"),act.get("target_system"))
        if event_key not in {("DELETE_RECORD","account_service"),("ANONYMIZE_RECORD","analytics_platform")}: continue
        at=parse_time(act.get("event_time",""))
        if not at: continue
        candidates=[]
        for req,reported,audit in eligible:
            if audit and at>audit: continue
            delta=abs((at-reported).total_seconds())
            window=(account_window_seconds if event_key[1]=="account_service" else analytics_window_seconds)
            if delta<=window: candidates.append((delta,req))
        if not candidates: continue
        candidates.sort(key=lambda x:x[0]); best=candidates[0][0]
        winners=[r for d,r in candidates if d==best]
        if len(winners)==1: assignments[winners[0]["case_id"]].append(act)
    linked=defaultdict(list)
    for case, events in assignments.items():
        grouped=defaultdict(list)
        for act in events: grouped[(act["event_type"],act["target_system"])].append(act)
        # If multiple same-purpose resource IDs are equally plausible, leave the
        # linkage unresolved instead of guessing between global activity rows.
        for group in grouped.values():
            if len(group)==1: linked[case].extend(group)
    return linked

def main():
    parser=argparse.ArgumentParser(description="Run a deterministic deletion audit.")
    parser.add_argument("--sample",action="store_true",help="Use the public 32-case sample.")
    parser.add_argument("--requests",type=Path,help="Override the request CSV path.")
    parser.add_argument("--output",type=Path,help="Override the output CSV path.")
    args=parser.parse_args()
    sample_mode=args.sample
    request_path=args.requests or DATA/("sample_deletion_requests.csv" if sample_mode else "deletion_requests.csv")
    requests=read_csv(request_path); identities,audits=build_identities(); ev=load_evidence(); activities=read_csv(DATA/"system_activity.csv")
    time_linked_activity=correlate_activity_to_requests(requests,activities)
    activity_by_key=defaultdict(list)
    email_re=re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}")
    user_re=re.compile(r"\buser_\d+\b",re.I)
    for act in activities:
        details=norm(act.get("details","")); keys=set(email_re.findall(details))|set(user_re.findall(details))
        for key in keys: activity_by_key[key].append(act)
    # Request email aliases link to a current or historical identity.
    email_to_user={}
    for uid,u in identities.items():
        for email in u.get("email",[]): email_to_user[norm(email)]=uid
    for a in audits:
        if a.get("field_name")=="email":
            for value in (a.get("old_value"),a.get("new_value")):
                if value: email_to_user[norm(value)]=a["user_id"]
    # Map hash aliases after identity values are resolved.
    for uid,u in identities.items():
        for email in u.get("email",[]): u["_all"].append(hash_email(email))
        u["_all"]=sorted(set(u["_all"]))
    global RULE_ACTIONS
    rules=read_csv(DATA/"deletion_rules.csv")
    RULE_ACTIONS={r["data_category"].upper():r["required_action"].upper() for r in rules}
    results=[]
    for req in requests:
        case=req["case_id"]; cutoff=parse_time(req["audit_at"]); email=norm(req["email"]); uid=email_to_user.get(email)
        if not deletion_intent(req["request_text"]):
            results.append((case,"NOT_APPLICABLE",[])); continue
        # Unknown identity still gets a conservative incomplete plan only if evidence directly matches supplied address.
        aliases=set([email,hash_email(email)])
        if uid:
            aliases.update(identities[uid]["_all"])
            for a in audits:
                if a["user_id"]==uid and a.get("old_value"): aliases.add(norm(a["old_value"]))
        if uid: aliases.add(norm(uid))
        aliases=sorted(x for x in aliases if x)
        candidate_items=[]; seen_items=set()
        for key in aliases:
            for item in ev.by_key.get(key,[]):
                ident=id(item)
                if ident not in seen_items: seen_items.add(ident); candidate_items.append(item)
        rel=[e for e in candidate_items if (not e["file_time"] or not cutoff or e["file_time"]<=cutoff) and (not e["time"] or not cutoff or e["time"]<=cutoff)]
        # Use global activity only to join a subject to resource IDs; evidence files must establish state.
        linked_ids=set(); related_activity=[]; seen_activity=set()
        for key in aliases:
            for act in activity_by_key.get(key,[]):
                ident=act.get("activity_id",id(act))
                if ident not in seen_activity: seen_activity.add(ident); related_activity.append(act)
        direct_systems={e["system"] for e in candidate_items if e.get("system") and e.get("rid")}
        for act in time_linked_activity.get(case,[]):
            if act.get("target_system") in direct_systems: continue
            ident=act.get("activity_id",id(act))
            if ident not in seen_activity: seen_activity.add(ident); related_activity.append(act)
        for act in related_activity:
            at=parse_time(act.get("event_time"))
            if cutoff and at and at>cutoff: continue
            if act.get("resource_id"): linked_ids.add(act["resource_id"])
        # Follow resource references found in already linked records, then materialize matching evidence.
        resource_re=re.compile(r"\b(?:account|search|support|analytics|export|backup|data_flow|audit_record|tombstone)_\d+\b",re.I)
        for _ in range(2):
            for item in candidate_items:
                linked_ids.update(resource_re.findall(" ".join(item["values"]+[item["text"]])))
            if not linked_ids: break
            for item in ev.items:
                if item["rid"] in linked_ids and (not item["file_time"] or not cutoff or item["file_time"]<=cutoff) and (not item["time"] or not cutoff or item["time"]<=cutoff) and id(item) not in seen_items:
                    seen_items.add(id(item)); candidate_items.append(item)
        if linked_ids:
            rel=[e for e in candidate_items if (not e["file_time"] or not cutoff or e["file_time"]<=cutoff) and (not e["time"] or not cutoff or e["time"]<=cutoff)]
            # A missing row in one replica is not enough if any supplied snapshot
            # still contains that resource; preserve the positive evidence.
            known_account_resources={e["rid"] for e in ev.items if e["system"]=="account_service" and e["rid"]}
            for snapshot in ev.snapshots:
                if cutoff and snapshot["file_time"] and snapshot["file_time"]>cutoff: continue
                for rid in linked_ids:
                    if sys_from(rid)!="account_service" or rid in known_account_resources: continue
                    if rid not in snapshot["resources"]:
                        item=dict(fid=snapshot["fid"],file_time=snapshot["file_time"],time=snapshot["file_time"],system=snapshot["system"],rid=rid,category=snapshot["category"],values=[],state="ABSENT",direct=False,text="resource absent from complete customer profile snapshot")
                        if id(item) not in seen_items: seen_items.add(id(item)); candidate_items.append(item)
            rel=[e for e in candidate_items if (not e["file_time"] or not cutoff or e["file_time"]<=cutoff) and (not e["time"] or not cutoff or e["time"]<=cutoff)]
        # A timestamped shift handover is a consolidated readback for the subjects it names.
        # Use its per-resource states as the current state and avoid reviving older snapshots.
        if rel:
            handovers=[e for e in rel if "handover" in FILE_PATHS.get(e["fid"],"")]
            exports=[e for e in rel if "service_resource_export" in FILE_PATHS.get(e["fid"],"")]
            bundles=[e for e in rel if "customer_data_snapshot_bundle" in FILE_PATHS.get(e["fid"],"")]
            selected=handovers or exports or bundles
            if selected:
                newest=max(e["file_time"] or e["time"] for e in selected if e["file_time"] or e["time"])
                rel=[e for e in selected if (e["file_time"] or e["time"])==newest]
                # A service readback can supersede customer-state snapshots, but
                # it cannot replace separately retained security audit evidence.
                # Keep subject-linked audit records from every eligible source.
                retained_audits=[e for e in candidate_items
                                 if e.get("system")=="security_service"
                                 and e.get("rid", "").startswith("audit_record_")
                                 # Retained records carry an event timestamp. It can
                                 # be valid even when the containing bundle is published later.
                                 and (not e["time"] or not cutoff or e["time"]<=cutoff)]
                # Preserve individually subject-linked readbacks too. The selected
                # aggregate is a fallback for sparse coverage, not a replacement
                # for a newer, identity-keyed result from another service file.
                linked_readbacks=[e for e in candidate_items
                                  if e.get("rid") and related(e,uid,aliases)
                                  and (not e["file_time"] or not cutoff or e["file_time"]<=cutoff)
                                  and (not e["time"] or not cutoff or e["time"]<=cutoff)]
                known={(e["fid"],e["rid"]) for e in rel}
                rel.extend(e for e in retained_audits+linked_readbacks if (e["fid"],e["rid"]) not in known)
        # Normalize system/category before de-duplicating: aggregate JSON exports can
        # emit both a parent-container observation and a nested resource observation.
        for e in rel:
            inferred=sys_from(e["rid"])
            if inferred: e["system"]=inferred
            elif e["rid"].startswith("tombstone_"): e["system"]="identity_service"
            e["category"]=canonical_category(e["system"] or sys_from(e["category"]),e["rid"],e["category"],e["text"])
        # Select the latest observation per normalized system/resource pair.
        byres={}
        for e in rel:
            key=(e["system"],e["rid"])
            prev=byres.get(key)
            if prev is None or (e["time"] or dt.datetime.min.replace(tzinfo=dt.timezone.utc)) >= (prev["time"] or dt.datetime.min.replace(tzinfo=dt.timezone.utc)):
                byres[key]=e
        rel=list(byres.values())
        # Keep the latest observed absent primary-account handle; older aliases are
        # already proven absent and should not become duplicate future checks.
        account_absent=[e for e in rel if e["system"]=="account_service" and e["state"] in ("ABSENT","NOT_FOUND","DELETED","404")]
        if len(account_absent)>1:
            latest=max(account_absent,key=lambda e:(e["time"] or e["file_time"] or dt.datetime.min.replace(tzinfo=dt.timezone.utc)))
            rel=[e for e in rel if e not in account_absent or e is latest]
        # Evidence can mention request address; for identity records keyed only by user_id, include all resources tied to that ID.
        findings=[]; remed=[]; verify=[]
        for e in rel:
            resource=e["rid"]
            # Records in aggregate exports can carry a misleading parent system.
            # Prefer their namespaced resource ID for emitted system attribution.
            system=(sys_from(resource) or ("identity_service" if resource.startswith("tombstone_") else "") or e["system"] or sys_from(e["category"]))
            cat=canonical_category(system,resource,e["category"],e["text"])
            action=category_action(cat,e["text"]); state=e["state"]
            if not resource or not system: continue
            # Special flow and restore conditions.
            flow=("FLOW" in cat or "CONNECTOR" in cat or "SYNC" in cat or system=="integration_service")
            restore=("BACKUP" in cat or system=="backup_service")
            if flow:
                if state not in ("DISABLED","NOT_FOUND","ABSENT"):
                    findings.append(("REPORT_ACTIVE_DATA_FLOW","ACTIVE",system,resource,e["fid"])); remed.append(("DISABLE_DATA_FLOW","DISABLED",system,resource,"")); verify.append(("VERIFY_DATA_FLOW_DISABLED","DISABLED",system,resource,""))
                else: verify.append(("VERIFY_DATA_FLOW_DISABLED","DISABLED",system,resource,e["fid"]))
                continue
            if restore:
                if state not in ("BLOCKED","NOT_FOUND","ABSENT"):
                    findings.append(("REPORT_RESTORE_RISK","ACTIVE",system,resource,e["fid"])); remed.append(("BLOCK_RESTORE","BLOCKED",system,resource,"")); verify.append(("VERIFY_RESTORE_BLOCKED","BLOCKED",system,resource,""))
                else: verify.append(("VERIFY_RESTORE_BLOCKED","BLOCKED",system,resource,e["fid"]))
                continue
            if "SECURITY_AUDIT" in cat or system=="security_service":
                if state not in ("ABSENT","NOT_FOUND"): verify.append(("VERIFY_RECORD_PRESENT","PRESENT",system,resource,e["fid"]))
                continue
            if "LEGAL_HOLD" in cat:
                if state not in ("ABSENT","NOT_FOUND"): verify.append(("VERIFY_RECORD_PRESENT","PRESENT",system,resource,e["fid"]))
                continue
            # Determine if identifiers remain in record. Text contains all recursively flattened values.
            hay=" ".join(e["values"]+[e["text"]]); pii=any(re.search(r"(?<![a-z0-9])"+re.escape(a)+r"(?![a-z0-9])",hay) for a in aliases if len(a)>3 and a!=norm(uid))
            absent=state in ("ABSENT","NOT_FOUND","DELETED","404") or "not_found" in e["text"] or "status_code 404" in e["text"]
            sanitized=state in ("REDACTED","ANONYMIZED","BLOCKED")
            if action=="RETAIN":
                if not absent: verify.append(("VERIFY_RECORD_PRESENT","PRESENT",system,resource,e["fid"]))
            elif absent:
                verify.append(("VERIFY_RECORD_ABSENT","ABSENT",system,resource,e["fid"]))
            elif action=="DELETE":
                findings.append(("REPORT_REMAINING_RECORD","PRESENT",system,resource,e["fid"]))
                remed.append(("DELETE_RECORD","ABSENT",system,resource,"")); verify.append(("VERIFY_RECORD_ABSENT","ABSENT",system,resource,""))
            elif action=="REDACT":
                if pii:
                    findings.append(("REPORT_EXPOSED_PII","PRESENT",system,resource,e["fid"]))
                    remed.append(("REDACT_RECORD","REDACTED",system,resource,"")); verify.append(("VERIFY_RECORD_REDACTED","REDACTED",system,resource,""))
                else: verify.append(("VERIFY_RECORD_REDACTED","REDACTED",system,resource,e["fid"]))
            elif action=="ANONYMIZE":
                linked=bool(uid and norm(uid) in hay)
                if pii or linked:
                    findings.append(("REPORT_EXPOSED_PII","PRESENT",system,resource,e["fid"]))
                    remed.append(("ANONYMIZE_RECORD","ANONYMIZED",system,resource,"")); verify.append(("VERIFY_RECORD_ANONYMIZED","ANONYMIZED",system,resource,""))
                else: verify.append(("VERIFY_RECORD_ANONYMIZED","ANONYMIZED",system,resource,e["fid"]))
        # Ensure primary account state is represented, as it is central to every authorized deletion.
        acct=[x for x in rel if x["system"]=="account_service" and x["rid"]]
        if not any(x[2]=="account_service" for x in verify) and not any(x[2]=="account_service" for x in findings):
            # An account lookup showing absence is evidence; otherwise conservative planned check.
            missing=next((e for e in rel if e["system"]=="account_service"),None)
            if missing and missing["state"] in ("ABSENT","NOT_FOUND"):
                verify.append(("VERIFY_RECORD_ABSENT","ABSENT","account_service",missing["rid"],missing["fid"]))
            elif missing:
                findings.append(("REPORT_REMAINING_RECORD","PRESENT","account_service",missing["rid"],missing["fid"]))
                remed.append(("DELETE_RECORD","ABSENT","account_service",missing["rid"],"")); verify.append(("VERIFY_RECORD_ABSENT","ABSENT","account_service",missing["rid"],""))
        # Deterministic phase ordering per challenge contract.
        sortf=lambda x:(OP_ORDER.get(x[0],99),x[2],x[3])
        findings.sort(key=sortf); remed.sort(key=sortf); verify.sort(key=sortf)
        status="INCOMPLETE" if findings else "COMPLETE"
        if status=="COMPLETE" and not verify:
            # No evidence-backed check means completion cannot be asserted. Plan a primary lookup by stable subject reference.
            status="INCOMPLETE"
            verify=[("VERIFY_RECORD_ABSENT","ABSENT","account_service",uid or email,"")]
            verify.sort(key=sortf)
        entries=[]
        chosen=([("FINDING",x) for x in findings]+[("REMEDIATION",x) for x in remed]+[("VERIFICATION",x) for x in verify]) if status=="INCOMPLETE" else [("VERIFICATION",x) for x in verify]
        # Drop any contradictory same resource verification, keep latest single action.
        for i,(phase,x) in enumerate(chosen,1):
            op,state,system,resource,evidence=x
            if status=="INCOMPLETE" and phase=="VERIFICATION": evidence=""
            entries.append(dict(step_no=i,phase=phase,system_id=system,resource_id=resource,operation=op,state=state,evidence_id=evidence))
        results.append((case,status,entries))
    results.sort(key=lambda x:x[0])
    dest=args.output or ((ROOT / "sample_predictions.csv") if sample_mode else OUT)
    with dest.open("w",encoding="utf-8",newline="") as f:
        w=csv.writer(f,lineterminator="\n"); w.writerow(["case_id","deletion_status","steps_json"])
        for case,status,steps in results: w.writerow([case,status,json.dumps(steps,ensure_ascii=False,separators=(",",":"))])
    print(f"Wrote {len(results)} rows to {dest}")

if __name__=="__main__": main()











