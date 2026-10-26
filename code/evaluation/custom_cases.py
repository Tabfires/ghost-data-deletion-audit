"""Custom evaluation cases (written by the team, not taken from the dataset).

Each case builds a tiny self-contained dataset in a temporary directory (identities, audit log,
activity, rules, evidence manifest + evidence files), runs the real agent on it and compares the
output with a hand-written expected answer using the same scorer as the main evaluation.

Run:  python code/evaluation/custom_cases.py
"""
from __future__ import annotations

import csv
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CODE = os.path.dirname(HERE)
ROOT = os.path.dirname(CODE)
sys.path.insert(0, CODE)
sys.path.insert(0, HERE)

RULES = os.path.join(ROOT, "dataset", "deletion_rules.csv")


def write_csv(path, header, rows):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def step(n, phase, system, rid, op, state, ev=""):
    return {"step_no": n, "phase": phase, "system_id": system, "resource_id": rid, "operation": op,
            "state": state, "evidence_id": ev}


IDENTITIES = [
    ("user_901", "Ana Test", "ana.new@example.com", "+351 912 000 001",
     "0" * 63 + "1", "2026-05-01T00:00:00Z"),
    ("user_902", "Ben Probe", "ben.probe@example.com", "+44 7700 900002", "0" * 63 + "2", "2026-01-01T00:00:00Z"),
    ("user_903", "Cleo Sample", "cleo.sample@example.com", "+61 400 000 003", "0" * 63 + "3", "2026-01-01T00:00:00Z"),
    ("user_904", "Dev Fixture", "dev.fixture@example.com", "+91 90000 00004", "0" * 63 + "4", "2026-01-01T00:00:00Z"),
]
AUDIT = [("audit_901", "user_901", "2026-05-01T00:00:00Z", "email", "ana.old@example.com", "ana.new@example.com")]

CASES = []


def case(fn):
    CASES.append(fn)
    return fn


@case
def negated_deletion_language():
    """A request that mentions deletion only to say it is NOT a deletion request -> NOT_APPLICABLE."""
    req = ("case_c1", "ben.probe@example.com", "2026-09-01T10:00:00Z", "NOT_STARTED", "2026-09-02T10:00:00Z",
           "2026-09-05T10:00:00Z",
           "Please send me a copy of my data. I am not asking for deletion and do not close the account.")
    return dict(requests=[req], activity=[], files={}, expected=("NOT_APPLICABLE", []))


@case
def historical_email_and_replica_drift():
    """Request uses the OLD email. The primary table no longer has the profile but a read replica still
    does (replication drift); the search document only carries the new email. Evidence captured after
    audit_at shows everything clean and must be ignored."""
    sql = """-- Captured at: 2026-09-10T08:00:00Z
BEGIN TRANSACTION;
CREATE TABLE customer_data_primary (resource_id TEXT PRIMARY KEY, origin_system TEXT, collection_name TEXT, record_json TEXT, updated_at TEXT);
CREATE TABLE customer_data_read_replica (resource_id TEXT PRIMARY KEY, origin_system TEXT, collection_name TEXT, record_json TEXT, updated_at TEXT);
INSERT INTO customer_data_primary VALUES('search_9001','search_service','customer_search_documents','{"resource_id":"search_9001","document":{"display_name":"Ana Test","email":"ana.new@example.com","customer_reference":"user_901"}}','2026-09-10T08:00:00Z');
INSERT INTO customer_data_primary VALUES('audit_record_9001','security_service','security_audit_events','{"resource_id":"audit_record_9001","subject_reference":"user_901","event_name":"account_deletion_reviewed"}','2026-09-10T08:00:00Z');
INSERT INTO customer_data_read_replica VALUES('account_9001','account_service','customer_profiles','{"resource_id":"account_9001","customer_reference":"user_901","full_name":"Ana Test","email":"ana.old@example.com","account_status":"ACTIVE"}','2026-09-10T08:00:00Z');
COMMIT;
"""
    later = """2026-09-20T08:00:00Z level=INFO service=account_service trace_id=t1 event=profile_lookup_started lookup_key=ana.new@example.com
2026-09-20T08:00:01Z level=INFO service=account_service trace_id=t1 event=profile_lookup_completed resource_id=account_9001 rows=0 http_status=404
2026-09-20T08:00:02Z level=INFO service=search_service trace_id=t2 event=index_query_started lookup_key=ana.new@example.com
2026-09-20T08:00:03Z level=INFO service=search_service trace_id=t2 event=index_query_completed resource_id=search_9001 result=miss total_hits=0
"""
    req = ("case_c2", "ana.old@example.com", "2026-09-05T10:00:00Z", "COMPLETE", "2026-09-06T10:00:00Z",
           "2026-09-12T10:00:00Z", "Please delete my account. I changed my email, please check the old address too.")
    expected = ("INCOMPLETE", [
        step(1, "FINDING", "account_service", "account_9001", "REPORT_REMAINING_RECORD", "PRESENT", "evidence_c2a"),
        step(2, "FINDING", "search_service", "search_9001", "REPORT_REMAINING_RECORD", "PRESENT", "evidence_c2a"),
        step(3, "REMEDIATION", "account_service", "account_9001", "DELETE_RECORD", "ABSENT"),
        step(4, "REMEDIATION", "search_service", "search_9001", "DELETE_RECORD", "ABSENT"),
        step(5, "VERIFICATION", "account_service", "account_9001", "VERIFY_RECORD_ABSENT", "ABSENT"),
        step(6, "VERIFICATION", "search_service", "search_9001", "VERIFY_RECORD_ABSENT", "ABSENT"),
        step(7, "VERIFICATION", "security_service", "audit_record_9001", "VERIFY_RECORD_PRESENT", "PRESENT"),
    ])
    return dict(requests=[req], activity=[],
                files={"evidence_c2a": ("databases/c2_replica.sql", "2026-09-10T08:00:00Z", sql),
                       "evidence_c2b": ("logs/c2_later.log", "2026-09-20T08:00:05Z", later)},
                expected=expected)


@case
def tombstone_flow_and_remediation_order():
    """Account gone, but the tombstone still carries PII, a connector is still enabled and a support
    conversation (shared order context) still shows the email. Remediation must disable the flow
    first, then redact; verification follows the operation table order."""
    handover = """CUSTOMER PLATFORM - SHIFT HANDOVER
- 2026-09-10T12:00:00Z | account_service | account_9003 | USER_PROFILE | NOT_FOUND | cleo.sample@example.com
- 2026-09-10T12:00:00Z | identity_service | tombstone_9003 | ACCOUNT_TOMBSTONE | IDENTIFIABLE | cleo.sample@example.com
- 2026-09-10T12:00:00Z | integration_service | data_flow_9003 | DATA_FLOW | ACTIVE | cleo.sample@example.com
- 2026-09-10T12:00:00Z | support_platform | support_9003 | SUPPORT_MESSAGE | IDENTIFIABLE | cleo.sample@example.com
- 2026-09-10T12:00:00Z | security_service | audit_record_9003 | SECURITY_AUDIT_LOG | FOUND | user_903
"""
    req = ("case_c3", "cleo.sample@example.com", "2026-09-01T10:00:00Z", "COMPLETE", "2026-09-02T10:00:00Z",
           "2026-09-11T10:00:00Z", "Je demande la suppression définitive du compte associé à cette adresse e-mail.")
    E = "evidence_c3"
    expected = ("INCOMPLETE", [
        step(1, "FINDING", "identity_service", "tombstone_9003", "REPORT_EXPOSED_PII", "PRESENT", E),
        step(2, "FINDING", "support_platform", "support_9003", "REPORT_EXPOSED_PII", "PRESENT", E),
        step(3, "FINDING", "integration_service", "data_flow_9003", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", E),
        step(4, "REMEDIATION", "integration_service", "data_flow_9003", "DISABLE_DATA_FLOW", "DISABLED"),
        step(5, "REMEDIATION", "identity_service", "tombstone_9003", "REDACT_RECORD", "REDACTED"),
        step(6, "REMEDIATION", "support_platform", "support_9003", "REDACT_RECORD", "REDACTED"),
        step(7, "VERIFICATION", "account_service", "account_9003", "VERIFY_RECORD_ABSENT", "ABSENT"),
        step(8, "VERIFICATION", "security_service", "audit_record_9003", "VERIFY_RECORD_PRESENT", "PRESENT"),
        step(9, "VERIFICATION", "identity_service", "tombstone_9003", "VERIFY_RECORD_REDACTED", "REDACTED"),
        step(10, "VERIFICATION", "support_platform", "support_9003", "VERIFY_RECORD_REDACTED", "REDACTED"),
        step(11, "VERIFICATION", "integration_service", "data_flow_9003", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
    ])
    return dict(requests=[req], activity=[], files={E: ("records/c3_handover.txt", "2026-09-10T12:00:00Z", handover)},
                expected=expected)


@case
def workflow_linked_anonymised_records_complete():
    """COMPLETE case where the deleted account and the anonymised analytics profile no longer carry any
    identifier. They are tied to the request only through the deletion worker's burst: the account
    delete is the only one in the window, and the anonymisation sits on the request's timing chain
    (449 s before the redaction of the subject's support message)."""
    export = {"exported_at": "2026-09-12T11:00:00Z", "service_exports": {
        "account_service": {"profile_lookups": [
            {"observed_at": "2026-09-12T09:00:00Z", "profile": None, "resource_id": "account_9004", "status_code": 404}]},
        "analytics_platform": {"profiles": [
            {"observed_at": "2026-09-12T09:10:00Z", "resource_id": "analytics_9004", "customer_reference": None,
             "email": None, "phone": None, "email_hash": None, "audience_cohort": "general"}]},
        "support_platform": {"tickets": [
            {"observed_at": "2026-09-12T09:20:00Z", "resource_id": "support_9004", "customer_reference": "user_904",
             "requester_email": None, "requester_name": None, "requester_phone": None,
             "message_excerpt": "Customer asked about an order."}]},
        "security_service": {"audit_records": [
            {"observed_at": "2026-09-12T09:30:00Z", "resource_id": "audit_record_9004", "subject_reference": "user_904",
             "event_code": "ACCOUNT_DELETION_RECORDED", "retention_until": "2031-12-31T23:59:59Z"}]}}}
    activity = [
        ("activity_c4a", "2026-09-03T10:50:00Z", "DELETE_RECORD", "deletion_worker", "account_service", "account_9004",
         "SUCCESS", "Deletion worker submitted primary profile account_9004 to account_service."),
        ("activity_c4b", "2026-09-03T11:31:10Z", "ANONYMIZE_RECORD", "deletion_worker", "analytics_platform",
         "analytics_9004", "SUCCESS", "Policy action completed for analytics_9004."),
        ("activity_c4c", "2026-09-03T11:38:39Z", "REDACT_RECORD", "deletion_worker", "support_platform",
         "support_9004", "SUCCESS", "Policy action completed for support_9004."),
    ]
    req = ("case_c4", "dev.fixture@example.com", "2026-09-02T12:00:00Z", "COMPLETE", "2026-09-03T12:00:00Z",
           "2026-09-12T12:00:00Z", "Please erase the account linked to this email address.")
    E = "evidence_c4"
    expected = ("COMPLETE", [
        step(1, "VERIFICATION", "account_service", "account_9004", "VERIFY_RECORD_ABSENT", "ABSENT", E),
        step(2, "VERIFICATION", "security_service", "audit_record_9004", "VERIFY_RECORD_PRESENT", "PRESENT", E),
        step(3, "VERIFICATION", "support_platform", "support_9004", "VERIFY_RECORD_REDACTED", "REDACTED", E),
        step(4, "VERIFICATION", "analytics_platform", "analytics_9004", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", E),
    ])
    return dict(requests=[req], activity=activity,
                files={E: ("records/c4_export.json", "2026-09-12T11:00:00Z", json.dumps(export))},
                expected=expected)


def build_fixture(spec: dict) -> str:
    d = tempfile.mkdtemp(prefix="ghost_custom_")
    for sub in ("databases", "documents", "images", "logs", "records"):
        os.makedirs(os.path.join(d, "evidence", sub))
    write_csv(os.path.join(d, "user_identities.csv"),
              ["user_id", "name", "email", "phone", "email_hash", "updated_at"], IDENTITIES)
    write_csv(os.path.join(d, "user_audit_log.csv"),
              ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"], AUDIT)
    write_csv(os.path.join(d, "system_activity.csv"),
              ["activity_id", "event_time", "event_type", "source_system", "target_system", "resource_id",
               "reported_result", "details"], spec["activity"])
    shutil.copy(RULES, os.path.join(d, "deletion_rules.csv"))
    manifest = []
    for fid, (rel, cap, content) in spec["files"].items():
        with open(os.path.join(d, "evidence", rel), "w", encoding="utf-8") as fh:
            fh.write(content)
        manifest.append((fid, "evidence/" + rel, "custom_fixture", cap))
    write_csv(os.path.join(d, "evidence_files.csv"), ["file_id", "file_path", "origin", "captured_at"], manifest)
    write_csv(os.path.join(d, "deletion_requests.csv"),
              ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"],
              spec["requests"])
    return d


def run_custom(verbose: bool = True) -> list[dict]:
    score = _load("eval_scorer", os.path.join(HERE, "main.py")).score
    os.environ.setdefault("INTENT_LLM", "off")
    results = []
    for fn in CASES:
        spec = fn()
        d = build_fixture(spec)
        out = os.path.join(d, "pred.csv")
        agent_main = _load("agent_main", os.path.join(CODE, "main.py"))
        agent_main.main(["--dataset", d, "--out", out, "--cache", os.path.join(d, ".cache")])
        cid = spec["requests"][0][0]
        gold = {cid: spec["expected"]}
        with open(out, encoding="utf-8") as fh:
            pred = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(fh)}
        res = score(pred, gold, verbose=False)
        ok = res["exact_case_match"] == 1.0
        results.append({"case": fn.__name__, "doc": (fn.__doc__ or "").strip().split("\n")[0], "pass": ok,
                        "status": pred[cid][0], "step_f1": res["step_f1"], "diffs": res["diffs"]})
        if verbose:
            print(f"[{'PASS' if ok else 'FAIL'}] {fn.__name__}: status={pred[cid][0]} step_f1={res['step_f1']:.3f}")
            for _, gs, ps, missing, extra in res["diffs"]:
                for k in missing:
                    print("      missing", k)
                for k in extra:
                    print("      extra  ", k)
        shutil.rmtree(d, ignore_errors=True)
    return results


def _load(name: str, path: str):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


if __name__ == "__main__":
    run_custom()
