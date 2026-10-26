"""Evidence extractors: every supported file format -> Observations (+ coverage).

Formats handled
  * logs   - key=value, JSON-line, syslog, pipe, bracket and cloud-runtime layouts;
             multi-line traces are stitched by trace id so a lookup key on the
             "started" line is linked to the outcome on the "completed" line.
  * sql    - SQLite-compatible snapshot exports, executed in an in-memory DB
             (inventory tables, primary/replica record_json tables, hand-made dumps).
  * json   - snapshot bundles, service exports, explicit lookup ledgers, job lists.
  * txt    - shift handover style "ts | system | resource | type | result | subject".
  * pdf/png- text is extracted (pypdf / OCR, see media.py) and resource ids mentioned
             in the artifact are recorded as present.
"""
from __future__ import annotations

import csv
import json
import os
import re
import sqlite3
from collections import defaultdict

from .interpret import flatten, interpret_record
from .model import (PRESENT, RESOURCE_RE, Coverage, Observation, norm_token, system_of, tokens_in_text)

KV_RE = re.compile(r'([A-Za-z_][\w.]*)=("((?:[^"\\]|\\.)*)"|(\S+))')
TRACE_KEY_FIELDS = ("lookup_key", "match_key", "subject_key", "scan_key", "subject_ref", "owner_key", "correlation_key")
NOISE_EVENTS = {"connection_acquired", "cache_lookup", "dependency_retry", "dependency_recovered"}
LOG_SERVICE_SYSTEM = {"profile_service": "account_service", "support_replica": "support_platform"}


# --------------------------------------------------------------------------- logs
def parse_log_line(line: str) -> dict | None:
    line = line.rstrip("\n")
    m = re.match(r"(\d{4}-\d\d-\d\dT[\d:]+Z)\s*(.*)", line)
    if not m:
        return None
    ts, rest = m.groups()
    d: dict = {"ts": ts}
    if rest.startswith("{"):
        try:
            d.update(json.loads(rest))
        except json.JSONDecodeError:
            return None
        d.setdefault("service", d.get("logger"))
        return d
    if rest.startswith("requestId="):
        rest = rest.replace('\\"', '"')
    m2 = re.match(r"<\d+>1 (\S+) (\S+) (\S+) - - (.*)", rest)
    if m2:
        d["service"], d["trace_id"], rest = m2.group(2), m2.group(3), m2.group(4)
    m3 = re.match(r"(\w+) \| (\S+) \| (\S+) \| (\S+) \| (.*)", rest)
    if m3:
        d["level"], d["service"], d["trace_id"], d["event"], rest = m3.groups()
    m4 = re.match(r"\[(\w+)\] \[(\S+)\] \[(\S+)\] (\S+): (.*)", rest)
    if m4:
        d["level"], d["service"], d["trace_id"], d["event"], rest = m4.groups()
    for k, _, quoted, bare in KV_RE.findall(rest):
        if k not in d:
            d[k] = quoted if quoted or bare == "" else bare
    if "service" not in d:
        d["service"] = d.get("function") or d.get("logger")
    if "trace_id" not in d and "requestId" in d:
        d["trace_id"] = d["requestId"]
    return d


def extract_log(file_id: str, path: str, captured_at: str):
    rows = [d for d in (parse_log_line(l) for l in open(path, encoding="utf-8")) if d]
    trace_keys: dict[str, set[str]] = defaultdict(set)
    for d in rows:
        tid = d.get("trace_id")
        if not tid:
            continue
        for f in TRACE_KEY_FIELDS:
            tok = norm_token(d.get(f))
            if tok:
                trace_keys[tid].add(tok)
    out = []
    for d in rows:
        rid = d.get("resource_id")
        event = str(d.get("event") or "")
        if not rid or not RESOURCE_RE.fullmatch(rid) or event in NOISE_EVENTS:
            continue
        if event.endswith("_started") or event == "thumbnail_failed":
            continue
        system = d.get("system") or system_of(rid)
        fields = {k: v for k, v in d.items() if k not in {
            "ts", "service", "event", "trace_id", "level", "severity", "logger", "function", "requestId",
            "instance", "pod", "region", "attempt", "seq", "system", "record_type", "result"}}
        explicit = None
        if event == "record_lookup":
            explicit = d.get("result")
            if d.get("subject_reference"):
                fields["subject_reference"] = d["subject_reference"]
        if event.endswith("pii_scan") or event.endswith("identity_scan"):
            # a detector matched a direct identifier inside the record
            mv = d.get("matched_value")
            tok = norm_token(mv)
            kind = (tok or "email:").split(":")[0]
            fields[{"email": "email", "phone": "phone", "hash": "email_hash"}.get(kind, "email")] = mv
            fields.pop("matched_value", None)
        if event.startswith("index_query") and "result" in d:
            fields["result"] = d["result"]
        state, category, ids, pii = interpret_record(system, rid, fields, result=explicit,
                                                     record_type=d.get("record_type"))
        if d.get("service") == "support_replica":
            # a row in a legacy contact index replica: a secondary copy of the identifier
            state, category = PRESENT, "SECONDARY_IDENTIFIER"
        ids |= trace_keys.get(d.get("trace_id"), set())
        out.append(Observation(file_id, d["ts"], system, rid, state, category, ids, pii, source=f"log:{event}"))
    return out, []


# --------------------------------------------------------------------------- sql
SQL_TABLE_SYSTEM = {
    "customer_profiles": "account_service",
    "customer_search_documents": "search_service",
    "customer_analytics_profiles": "analytics_platform",
    "support_records": "support_platform",
    "customer_exports": "export_service",
    "connector_subscriptions": "integration_service",
    "backup_restore_entries": "backup_service",
    "security_audit_records": "security_service",
}


def extract_sql(file_id: str, path: str, captured_at: str):
    text = open(path, encoding="utf-8").read()
    m = re.search(r"Captured at:\s*(\S+)", text) or re.search(r"snapshot_completed_at=(\S+)", text)
    snap_at = m.group(1) if m else captured_at
    db = sqlite3.connect(":memory:")
    db.executescript(text)
    tables = [r[0] for r in db.execute("select name from sqlite_master where type='table'")]
    obs, cover = [], defaultdict(set)
    scope_systems = set()
    if "snapshot_scope" in tables:
        scope_systems = {r[0] for r in db.execute("select origin_system from snapshot_scope")}
    for t in tables:
        if t == "snapshot_scope":
            continue
        cur = db.execute(f'select * from "{t}"')
        cols = [c[0] for c in cur.description]
        for row in cur.fetchall():
            rec = dict(zip(cols, row))
            rid = rec.get("resource_id")
            if not rid:
                continue
            if "record_json" in rec:
                fields = json.loads(rec["record_json"])
                system = rec.get("origin_system") or system_of(rid)
            else:
                fields = {k: v for k, v in rec.items() if k not in {"resource_id", "updated_at", "account_status"}}
                system = SQL_TABLE_SYSTEM.get(t) or system_of(rid)
            if system == "integration_service" and "enabled" in fields:
                fields["enabled"] = bool(fields["enabled"]) if isinstance(fields["enabled"], int) else fields["enabled"]
            if system == "backup_service" and isinstance(fields.get("restore_allowed"), int):
                fields["restore_allowed"] = bool(fields["restore_allowed"])
            state, category, ids, pii = interpret_record(system, rid, fields)
            obs.append(Observation(file_id, snap_at, system, rid, state, category, ids, pii, source=f"sql:{t}"))
            cover[system].add(rid)
    systems = scope_systems or set(cover)
    coverage = [Coverage(file_id, snap_at, s, cover.get(s, set()), source="sql") for s in systems]
    return obs, coverage


# --------------------------------------------------------------------------- json
def _explicit_records(file_id, records, default_at):
    out = []
    for r in records:
        rid = r.get("resource_id")
        if not rid:
            continue
        system = r.get("system") or system_of(rid)
        fields = {"subject_reference": r.get("subject_reference") or r.get("lookup_value")}
        state, category, ids, pii = interpret_record(system, rid, fields, result=r.get("result"),
                                                     record_type=r.get("record_type"))
        out.append(Observation(file_id, r.get("recorded_at") or default_at, system, rid, state, category,
                               ids, pii, source="json:ledger"))
    return out


def extract_json(file_id: str, path: str, captured_at: str):
    d = json.load(open(path, encoding="utf-8"))
    obs, coverage = [], []
    at = d.get("exported_at") or d.get("captured_at") or captured_at
    if "snapshots" in d:
        for snap in d["snapshots"]:
            s_at = snap.get("captured_at") or at
            store = snap.get("data_store")
            recs = snap.get("records", [])
            if recs and "result" in recs[0] and "system" in recs[0]:
                obs += _explicit_records(file_id, recs, s_at)
                continue
            ids_seen = set()
            for r in recs:
                rid = r.get("resource_id")
                system = system_of(rid) or store
                state, category, ids, pii = interpret_record(system, rid, r)
                if snap.get("collection") == "ticket_attachments":
                    category = "SUPPORT_ATTACHMENT"
                obs.append(Observation(file_id, s_at, system, rid, state, category, ids, pii,
                                       source=f"json:{snap.get('collection')}"))
                ids_seen.add(rid)
            if store and store not in {"backup_restore_service", "privacy_treatment_service", "support_storage_service"}:
                coverage.append(Coverage(file_id, s_at, store, ids_seen, source="json:snapshot"))
    elif "service_exports" in d:
        for svc, colls in d["service_exports"].items():
            for coll, recs in colls.items():
                for r in recs:
                    rid = r.get("resource_id")
                    if not rid:
                        continue
                    fields = {k: v for k, v in r.items() if k not in {"observed_at", "resource_id"}}
                    state, category, ids, pii = interpret_record(svc, rid, fields)
                    obs.append(Observation(file_id, r.get("observed_at") or at, svc, rid, state, category, ids, pii,
                                           source=f"json:{coll}"))
    elif isinstance(d.get("records"), list):
        recs = d["records"]
        if recs and "result" in recs[0]:
            obs += _explicit_records(file_id, recs, at)
        else:
            for r in recs:
                rid = r.get("resource_id")
                system = system_of(rid)
                state, category, ids, pii = interpret_record(system, rid, r)
                obs.append(Observation(file_id, at, system, rid, state, category, ids, pii,
                                       source=f"json:{d.get('collection')}"))
    return obs, coverage


# --------------------------------------------------------------------------- txt
def extract_txt(file_id: str, path: str, captured_at: str):
    obs = []
    for line in open(path, encoding="utf-8"):
        parts = [p.strip() for p in line.strip().lstrip("-").split("|")]
        if len(parts) >= 6 and RESOURCE_RE.fullmatch(parts[2]):
            ts, system, rid, rtype, result, subject = parts[:6]
            state, category, ids, pii = interpret_record(system, rid, {"subject_reference": subject},
                                                         result=result, record_type=rtype)
            obs.append(Observation(file_id, ts, system, rid, state, category, ids, pii, source="txt:handover"))
    return obs, []


# --------------------------------------------------------------------------- media
def extract_media_text(file_id: str, text: str, captured_at: str, aliases: dict[str, str] | None = None,
                       is_document: bool = False):
    """Business artifacts (screens, PDFs): every resource shown in the artifact exists at capture time.

    Resources are found by id or by a catalog alias (statement number, file name, customer key).
    Which person a displayed resource belongs to comes from the data catalog / other evidence,
    not from whatever emails happen to be printed on a multi-record screen; the artifact only
    tells us the resource's state (does it still show identifiers, is a connector running, ...).
    """
    obs = []
    tokens = tokens_in_text(text)
    shows_identifier = any(t.startswith(("email:", "phone:")) for t in tokens)
    emails = {t for t in tokens if t.startswith("email:")}
    # a document (PDF) addressed to exactly one person is about that person's records;
    # application screens list many records and are linked through the catalog instead
    link_tokens = tokens if (is_document and len(emails) == 1) else set()
    found = set(RESOURCE_RE.findall(text))
    for alias, rid in (aliases or {}).items():
        if alias != rid and re.search(r"(?<![\w.])" + re.escape(alias) + r"(?![\w])", text):
            found.add(rid)
    low = text.lower()
    for rid in sorted(found):
        system = system_of(rid)
        state, category, _, _ = interpret_record(system, rid, {})
        if system in ("support_platform", "object_storage") and re.search(r"attachment|\.pdf\b|upload", low):
            category = "SUPPORT_ATTACHMENT"
            state = PRESENT
        elif system == "support_platform":
            category, state = "SUPPORT_MESSAGE", ("IDENTIFIABLE" if shows_identifier else "REDACTED")
        elif system == "analytics_platform":
            state = "IDENTIFIABLE" if shows_identifier or re.search(r"user_\d+", low) else "ANONYMIZED"
        elif system == "identity_service":
            state = "IDENTIFIABLE" if shows_identifier else "REDACTED"
        elif system == "integration_service":
            state = "DISABLED" if re.search(r"\b(disabled|paused|stopped)\b", low) and not re.search(
                r"continuous|healthy", low) else "ACTIVE"
        elif system == "backup_service":
            state = "BLOCKED" if re.search(r"restore (blocked|denied|disabled)", low) else "ACTIVE"
        obs.append(Observation(file_id, captured_at, system, rid, state, category, set(link_tokens), set(),
                               source="media"))
    return obs, []


def load_manifest(dataset_dir: str) -> list[dict]:
    return list(csv.DictReader(open(os.path.join(dataset_dir, "evidence_files.csv"), encoding="utf-8")))


def extract_file(dataset_dir: str, row: dict, media_text: dict[str, str], aliases: dict[str, str] | None = None):
    path = os.path.join(dataset_dir, row["file_path"])
    ext = os.path.splitext(path)[1].lower()
    fid, cap = row["file_id"], row["captured_at"]
    if ext == ".log":
        return extract_log(fid, path, cap)
    if ext == ".sql":
        return extract_sql(fid, path, cap)
    if ext == ".json":
        return extract_json(fid, path, cap)
    if ext == ".txt":
        return extract_txt(fid, path, cap)
    if ext in {".png", ".jpg", ".jpeg", ".pdf"}:
        return extract_media_text(fid, media_text.get(row["file_path"], ""), cap, aliases, is_document=ext == ".pdf")
    return [], []
