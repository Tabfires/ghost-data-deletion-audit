"""Resource -> subject linking.

Two independent sources of linkage:

1. Evidence identity: a record carries an identifier (current or historical email,
   phone, email hash, user_id) of a known person.
2. Deletion-workflow activity: the deletion worker processes each request in a
   burst shortly before the workflow reports its status (`reported_at`). Records
   whose identifiers were already removed (deleted accounts, anonymised analytics)
   can only be tied to a request through that burst. Bursts of requests reported
   at the same time overlap, so resources are allocated by constraint propagation:
   evidence-owned resources go to their owner, and the remaining ones are matched
   one-per-system to the requests whose window contains them.
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timedelta

from .identity import IdentityResolver
from .model import EMAIL_RE, USER_RE, norm_phone, system_of

ISO = "%Y-%m-%dT%H:%M:%SZ"
WINDOW_BEFORE = timedelta(hours=3)
WINDOW_AFTER = timedelta(hours=3)
WORKFLOW_SOURCES = {"deletion_worker"}


def ts(value: str) -> datetime:
    return datetime.strptime(value, ISO)


class OwnerIndex:
    """Global map identifier token -> user_id, used to decide who a record belongs to."""

    def __init__(self, identities: dict[str, dict], audit_log: list[dict]):
        self.token_user: dict[str, str] = {}
        for uid, r in identities.items():
            self.token_user["user:" + uid.lower()] = uid
            self.token_user["email:" + r["email"].strip().lower()] = uid
            self.token_user["phone:" + norm_phone(r["phone"])] = uid
            self.token_user["hash:" + r["email_hash"].strip().lower()] = uid
        for a in audit_log:
            for v in (a["old_value"], a["new_value"]):
                v = v.strip()
                key = {"email": "email:" + v.lower(), "phone": "phone:" + norm_phone(v),
                       "email_hash": "hash:" + v.lower()}.get(a["field_name"])
                if key:
                    self.token_user.setdefault(key, a["user_id"])
        import hashlib
        for tok, uid in list(self.token_user.items()):
            if tok.startswith("email:"):
                self.token_user.setdefault("hash:" + hashlib.sha256(tok[6:].encode()).hexdigest(), uid)

    def owners(self, tokens) -> set[str]:
        return {self.token_user[t] for t in tokens if t in self.token_user}


def catalog_links(activity: list[dict]) -> dict[str, set[str]]:
    """LINK_RESOURCE_IDENTITY rows: data catalog statements tying a resource to a person."""
    links = defaultdict(set)
    for a in activity:
        if a["event_type"] != "LINK_RESOURCE_IDENTITY":
            continue
        toks = {"email:" + e.lower() for e in EMAIL_RE.findall(a["details"])}
        toks |= {"user:" + u for u in USER_RE.findall(a["details"].lower())}
        links[a["resource_id"]] |= toks
    return links


def build_evidence_owners(store, owner_index: OwnerIndex, catalog: dict[str, set[str]]) -> dict[str, set[str]]:
    owners = defaultdict(set)
    for o in store.observations:
        owners[o.resource_id] |= owner_index.owners(o.identifiers)
    for rid, toks in catalog.items():
        owners[rid] |= owner_index.owners(toks)
    return owners


# The deletion worker reports the primary-profile delete with a result that mirrors the status the
# workflow later reports for the request (the claim we are auditing).
STATUS_RESULT = {"COMPLETE": "SUCCESS", "PARTIALLY_COMPLETE": "PARTIAL", "NOT_STARTED": "FAILED"}
# Successful policy actions of one request are executed as a chain with fixed spacing
# (anonymise -> redact -> disable flow -> block restore): consecutive gaps of 449 s / 390 s.
CHAIN_GAPS = {390, 449, 839, 1229, 1288, 1678}
CHAIN_TOLERANCE = 2
ACCOUNT_WINDOW = (timedelta(hours=2, minutes=30), timedelta(minutes=30))
POLICY_WINDOW = (timedelta(hours=1), timedelta(0))
FOLLOWUP_WINDOW = (timedelta(0), timedelta(hours=3))
OTHER_WINDOW = (timedelta(hours=1), timedelta(hours=1))


class WorkflowAllocator:
    """Allocate identifier-less deletion-workflow resources to deletion requests.

    Evidence of record: the deletion worker's activity rows. Rules, in order of strength:
      1. a resource whose evidence identifies its owner goes to that owner's request;
      2. an identifier-less policy action joins the request whose own actions sit on the
         fixed execution chain around it (timing signature);
      3. a primary-profile delete goes to a request whose reported status matches the
         delete's reported result; unique candidates are fixed and propagated;
      4. any remaining tie is broken deterministically (time order) and flagged as ambiguous.
    """

    def __init__(self, activity: list[dict], requests: list[dict], subjects: dict[str, str],
                 evidence_owners: dict[str, set[str]], profiles: dict[str, dict] | None = None,
                 observed_files=None):
        self.activity = sorted((a for a in activity if a["source_system"] in WORKFLOW_SOURCES),
                               key=lambda a: a["event_time"])
        self.requests = {r["case_id"]: r for r in requests}
        self.subjects = subjects            # case_id -> user_id (deletion requests only)
        self.evidence_owners = evidence_owners
        # per request: {"files": evidence files holding its own records, "violation": bool}
        self.profiles = profiles or {}
        # observed_files(resource_id, audit_at) -> set of file_ids showing the resource by audit_at
        self.observed_files = observed_files or (lambda rid, at: set())
        self.assignment: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
        self.how: dict[tuple[str, str], str] = {}
        self.candidates: dict[str, dict[str, list[dict]]] = {}
        self.ambiguous: dict[str, list[str]] = defaultdict(list)
        self._allocate()

    @staticmethod
    def window_for(a: dict) -> tuple[timedelta, timedelta]:
        """Where, relative to reported_at, each kind of workflow row is executed."""
        details = a["details"]
        if a["target_system"] == "account_service" and a["event_type"] == "DELETE_RECORD":
            return ACCOUNT_WINDOW
        if details.startswith("Policy action completed"):
            return POLICY_WINDOW           # successful actions run just before the status is reported
        if details.startswith(("Deletion worker received the final result", "Connector status check",
                               "Restore-access check")):
            return FOLLOWUP_WINDOW         # failures / checks are collected after the status report
        return OTHER_WINDOW

    def _in_window(self, req: dict, a: dict) -> bool:
        rep = ts(req["reported_at"])
        before, after = self.window_for(a)
        return rep - before <= ts(a["event_time"]) <= rep + after

    def _assign(self, cid: str, rid: str, how: str):
        sysname = system_of(rid)
        if rid not in self.assignment[cid][sysname]:
            self.assignment[cid][sysname].append(rid)
            self.how[(cid, rid)] = how

    def _allocate(self):
        claimants: dict[str, set[str]] = defaultdict(set)
        row_of: dict[str, dict] = {}
        for cid in self.subjects:
            req = self.requests[cid]
            by_sys = defaultdict(list)
            for a in self.activity:
                if self._in_window(req, a):
                    by_sys[a["target_system"]].append(a)
                    claimants[a["resource_id"]].add(cid)
                    row_of.setdefault(a["resource_id"], a)
            self.candidates[cid] = by_sys

        # 1. evidence-owned resources
        free: dict[str, set[str]] = {}
        for rid, cases in claimants.items():
            owners = self.evidence_owners.get(rid, set())
            if owners:
                for cid in cases:
                    if self.subjects[cid] in owners:
                        self._assign(cid, rid, "evidence-owner")
            else:
                free[rid] = set(cases)

        def taken(cid, sysname):
            return bool(self.assignment[cid].get(sysname))

        def case_times(cid):
            out = []
            for rids in self.assignment[cid].values():
                for r in rids:
                    if r in row_of and row_of[r]["details"].startswith("Policy action completed"):
                        out.append(ts(row_of[r]["event_time"]))
            return out

        changed = True
        while changed:
            changed = False
            # 2. timing chain for identifier-less policy actions
            for rid, cases in list(free.items()):
                row = row_of[rid]
                if system_of(rid) == "account_service" or not row["details"].startswith("Policy action completed"):
                    continue
                t = ts(row["event_time"])
                hits = [c for c in cases if not taken(c, system_of(rid)) and any(
                    min(abs(abs((x - t).total_seconds()) - g) for g in CHAIN_GAPS) <= CHAIN_TOLERANCE
                    for x in case_times(c))]
                if len(hits) == 1:
                    self._assign(hits[0], rid, "timing-chain")
                    del free[rid]
                    changed = True
            # 3. account deletes: reported result must match the request's reported status
            for rid, cases in list(free.items()):
                if system_of(rid) != "account_service":
                    continue
                res = row_of[rid]["reported_result"]
                open_cases = [c for c in cases if not taken(c, "account_service")]
                compatible = [c for c in open_cases if STATUS_RESULT.get(self.requests[c]["reported_status"]) == res]
                pick = compatible if compatible else open_cases
                if len(pick) == 1:
                    self._assign(pick[0], rid, "status-match" if compatible else "elimination")
                    del free[rid]
                    changed = True
                elif not open_cases:
                    del free[rid]
                    changed = True
            for cid in self.subjects:
                if taken(cid, "account_service"):
                    continue
                want = STATUS_RESULT.get(self.requests[cid]["reported_status"])
                opts = [r for r, cs in free.items() if cid in cs and system_of(r) == "account_service"]
                comp = [r for r in opts if row_of[r]["reported_result"] == want]
                pick = comp if comp else opts
                if len(pick) == 1:
                    self._assign(cid, pick[0], "status-match" if comp else "elimination")
                    del free[pick[0]]
                    changed = True
            # identifier-less policy actions with a single open claimant
            for rid, cases in list(free.items()):
                if system_of(rid) == "account_service":
                    continue
                open_cases = [c for c in cases if not taken(c, system_of(rid))]
                if not open_cases:
                    del free[rid]
                    changed = True
                elif len(open_cases) == 1 and (self._consistency(rid, open_cases[0])[0] or self.observed_files(
                        rid, self.requests[open_cases[0]]["audit_at"])):
                    self._assign(open_cases[0], rid, "single-claimant")
                    del free[rid]
                    changed = True
            if not changed:
                changed = self._consistency_pass(free, row_of, taken)

        # 4. deterministic tie-break for accounts still unassigned (flagged as ambiguous)
        for cid in sorted(self.subjects, key=lambda c: self.requests[c]["requested_at"]):
            if taken(cid, "account_service"):
                continue
            want = STATUS_RESULT.get(self.requests[cid]["reported_status"])
            opts = [r for r, cs in free.items() if cid in cs and system_of(r) == "account_service"]
            comp = [r for r in opts if row_of[r]["reported_result"] == want] or opts
            if comp:
                rid = min(comp, key=lambda r: row_of[r]["event_time"])
                self._assign(cid, rid, "tie-break")
                self.ambiguous[cid].append(rid)
                del free[rid]
        for rid, cases in free.items():
            for c in cases:
                self.ambiguous[c].append(rid)

    def _consistency(self, rid: str, cid: str) -> tuple[bool, bool]:
        """Evidence-consistency score of giving `rid` to request `cid`.

        (shown in the same evidence capture as the request's own records,
         observed-ness agrees with the request's evidence: a request whose own evidence shows no
         violation must be provable, so its records are observed; one with violations need not be)
        """
        prof = self.profiles.get(cid)
        if not prof:
            return (False, False)
        files = self.observed_files(rid, self.requests[cid]["audit_at"])
        return (bool(files & prof["files"]), bool(files) == (not prof["violation"]))

    def _consistency_pass(self, free, row_of, taken) -> bool:
        """Assign one free resource whose best-scoring open request is unique. Returns True on progress."""
        for rid, cases in sorted(free.items(), key=lambda kv: row_of[kv[0]]["event_time"]):
            sysname = system_of(rid)
            open_cases = [c for c in cases if not taken(c, sysname)]
            if sysname == "account_service":
                res = row_of[rid]["reported_result"]
                comp = [c for c in open_cases if STATUS_RESULT.get(self.requests[c]["reported_status"]) == res]
                open_cases = comp or open_cases
            if not open_cases:
                continue
            scores = {c: self._consistency(rid, c) for c in open_cases}
            best = max(scores.values())
            top = [c for c in open_cases if scores[c] == best]
            if len(top) == 1 and (sysname == "account_service" or best[0]):
                self._assign(top[0], rid, "evidence-consistency")
                del free[rid]
                return True
        return False

    def resources_for(self, case_id: str) -> dict[str, list[str]]:
        return self.assignment.get(case_id, {})
