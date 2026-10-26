"""Case auditor: subject -> relevant resources -> state at audit_at -> policy -> ordered steps."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .identity import IdentityResolver, Subject
from datetime import timedelta

from .linking import ISO, OwnerIndex, WorkflowAllocator, build_evidence_owners, catalog_links, ts

# Retained security records are immutable; a capture shortly after the audit still identifies
# which retained record must remain available (used for future verification only).
SECURITY_LOOKAHEAD = timedelta(days=14)
from .model import ABSENT, Observation, system_of
from .policy import FINDING_ORDER, OP_STATE, REMEDIATION_ORDER, VERIFICATION_ORDER, Policy


@dataclass
class ResourceAssessment:
    system: str
    resource_id: str
    category: str | None
    state: str | None
    evidence_id: str
    link: str                       # how the resource was tied to the subject
    finding: str | None = None
    remediation: str | None = None
    verification: str | None = None


@dataclass
class CaseResult:
    case_id: str
    status: str
    steps: list[dict]
    subject: Subject | None = None
    intent: dict = field(default_factory=dict)
    resources: list[ResourceAssessment] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class Auditor:
    def __init__(self, ds, intent_classifier, universe_requests: list[dict]):
        self.ds = ds
        self.intent = intent_classifier
        self.resolver = IdentityResolver(ds.identities, ds.audit_log)
        self.policy = Policy(ds.rules)
        self.store = ds.evidence
        self.manifest_at = {fid: r["captured_at"] for fid, r in self.store.manifest.items()}
        self.owner_index = OwnerIndex(ds.identities, ds.audit_log)
        self.catalog = catalog_links(ds.activity)
        self.evidence_owners = build_evidence_owners(self.store, self.owner_index, self.catalog)
        # resources per owner (evidence identity)
        self.owned = defaultdict(set)
        for rid, owners in self.evidence_owners.items():
            for u in owners:
                self.owned[u].add(rid)
        # deletion-workflow allocation across every known request
        subjects, profiles = {}, {}
        for req in universe_requests:
            s = self.resolver.resolve(req["email"])
            if s and self.intent.is_deletion(req):
                subjects[req["case_id"]] = s.user_id
                profiles[req["case_id"]] = self.evidence_profile(req, s)
        self.allocator = WorkflowAllocator(ds.activity, universe_requests, subjects, self.evidence_owners,
                                           profiles, self.observed_files)

    def observed_files(self, rid: str, audit_at: str) -> set[str]:
        return {o.file_id for o in self.store.by_resource.get(rid, []) if self.visible(o, audit_at)}

    def evidence_profile(self, req: dict, subject: Subject) -> dict:
        """What the subject's own (identifier-linked) evidence says, before workflow allocation."""
        links = {rid: "evidence-identity" for rid in self.owned.get(subject.user_id, ())}
        links = {rid: how for rid, how in links.items() if self.relevant(rid, req, how)}
        files, violation = set(), False
        for rid in links:
            obs = self.state_at(rid, req["audit_at"])
            if obs is None:
                continue
            files |= self.observed_files(rid, req["audit_at"])
            category = self.category_of(rid) or obs.category
            f, _, _ = self.policy.decide(category, obs.state)
            violation |= f is not None
        return {"files": files, "violation": violation}

    # ------------------------------------------------------------------ state
    def visible(self, o: Observation, audit_at: str) -> bool:
        return self.manifest_at[o.file_id] <= audit_at and o.observed_at <= audit_at

    def state_at(self, rid: str, audit_at: str, subject_rids: set[str] = frozenset()) -> Observation | None:
        """State of a resource at audit_at: the latest explicit observation from evidence captured
        at or before audit_at; for account profiles, a snapshot that enumerates the account store
        without the profile is accepted as proof of absence when nothing explicit exists."""
        best = None
        for o in self.store.by_resource.get(rid, []):
            if not self.visible(o, audit_at):
                continue
            key = (o.observed_at, self.manifest_at[o.file_id])
            if best is None or key >= best[0]:
                best = (key, o)
        if best:
            return best[1]
        if system_of(rid) == "account_service":
            cov = self.coverage_absence(rid, audit_at, subject_rids)
            if cov:
                return Observation(cov.file_id, cov.observed_at, cov.system, rid, ABSENT, "USER_PROFILE",
                                   set(), set(), source="coverage")
        return None

    def coverage_absence(self, rid: str, audit_at: str, subject_rids: set[str]):
        """Best snapshot proving absence: prefer one that also captured the subject's other records,
        then the most specific (fewest systems) and most recent."""
        system = system_of(rid)
        n_systems = defaultdict(int)
        for c in self.store.coverage:
            n_systems[c.file_id] += 1
        best, best_key = None, None
        for c in self.store.coverage:
            if c.system != system or self.manifest_at[c.file_id] > audit_at or rid in c.resource_ids:
                continue
            about_subject = any(o.file_id == c.file_id for r in subject_rids for o in self.store.by_resource.get(r, []))
            key = (about_subject, -n_systems[c.file_id], c.observed_at)
            if best_key is None or key > best_key:
                best, best_key = c, key
        return best

    def relevant(self, rid: str, req: dict, how: str) -> bool:
        """Is an evidence-linked resource part of this request's scope?

        Evidence about the subject observed between the request and the audit cut-off is in scope;
        older sightings belong to earlier history (e.g. an earlier request by the same person).
        Security audit records are retained artefacts and are identified from any capture.
        """
        if how != "evidence-identity":
            return True
        if system_of(rid) == "security_service":
            horizon = (ts(req["audit_at"]) + SECURITY_LOOKAHEAD).strftime(ISO)
            return any(self.visible(o, req["audit_at"]) or o.observed_at <= horizon
                       for o in self.store.by_resource.get(rid, []))
        for o in self.store.by_resource.get(rid, []):
            if req["requested_at"] <= o.observed_at and self.visible(o, req["audit_at"]):
                return True
        return False

    def category_of(self, rid: str) -> str | None:
        cats = [o.category for o in self.store.by_resource.get(rid, []) if o.category]
        if not cats:
            return None
        # a specific category reported by any source wins over the generic system default
        for special in ("SUPPORT_ATTACHMENT", "SECONDARY_IDENTIFIER"):
            if special in cats:
                return special
        return cats[-1]

    # ------------------------------------------------------------------ audit
    def audit(self, req: dict) -> CaseResult:
        intent = self.intent.classify(req)
        if not intent["deletion"]:
            return CaseResult(req["case_id"], "NOT_APPLICABLE", [], intent=intent)
        subject = self.resolver.resolve(req["email"])
        result = CaseResult(req["case_id"], "COMPLETE", [], subject=subject, intent=intent)
        if subject is None:
            result.notes.append("request email does not resolve to a known subject")
            return result
        audit_at = req["audit_at"]

        links: dict[str, str] = {}
        for rid in self.owned.get(subject.user_id, ()):
            links[rid] = "evidence-identity"
        for sysname, rids in self.allocator.resources_for(req["case_id"]).items():
            for rid in rids:
                # processed by this request's own deletion workflow: in scope regardless of when seen
                links[rid] = "workflow-activity"

        links = {rid: how for rid, how in links.items() if self.relevant(rid, req, how)}
        # one primary profile per request: prefer the workflow-linked account, else the latest seen
        accounts = [r for r in links if system_of(r) == "account_service"]
        if len(accounts) > 1:
            wf = [r for r in accounts if links[r] == "workflow-activity"]
            keep = wf[0] if wf else max(accounts, key=lambda r: max(o.observed_at for o in self.store.by_resource[r]))
            for r in accounts:
                if r != keep:
                    links.pop(r)
        subject_rids = set(links)

        assessments = []
        for rid, how in sorted(links.items()):
            system = system_of(rid)
            if system is None:
                continue
            obs = self.state_at(rid, audit_at, subject_rids)
            category = self.category_of(rid) or (obs.category if obs else None)
            if category is None:
                from .model import SYSTEM_CATEGORY
                category = SYSTEM_CATEGORY.get(system)
            if obs is None:
                if system == "account_service":
                    # deletion submitted but no participant-visible observation: verify absence afterwards
                    assessments.append(ResourceAssessment(system, rid, category, None, "", how,
                                                          verification="VERIFY_RECORD_ABSENT"))
                elif system == "security_service" and how == "evidence-identity":
                    assessments.append(ResourceAssessment(system, rid, category, None, "", how,
                                                          verification="VERIFY_RECORD_PRESENT"))
                continue
            f, r, v = self.policy.decide(category, obs.state)
            if system != "account_service" and f is None and v == "VERIFY_RECORD_ABSENT":
                v = None  # an already-absent copy needs no proof beyond the account itself
            assessments.append(ResourceAssessment(system, rid, category, obs.state, obs.file_id, how, f, r, v))

        result.resources = assessments
        result.status = "INCOMPLETE" if any(a.finding for a in assessments) else "COMPLETE"
        result.steps = self.plan(result.status, assessments)
        return result

    # ------------------------------------------------------------------ plan
    @staticmethod
    def plan(status: str, items: list[ResourceAssessment]) -> list[dict]:
        def order(op_list, op):
            return op_list.index(op)

        steps = []
        if status == "INCOMPLETE":
            for a in sorted((a for a in items if a.finding), key=lambda a: (order(FINDING_ORDER, a.finding), a.system, a.resource_id)):
                steps.append(("FINDING", a.system, a.resource_id, a.finding, a.evidence_id))
            for a in sorted((a for a in items if a.remediation), key=lambda a: (order(REMEDIATION_ORDER, a.remediation), a.system, a.resource_id)):
                steps.append(("REMEDIATION", a.system, a.resource_id, a.remediation, ""))
            for a in sorted((a for a in items if a.verification), key=lambda a: (order(VERIFICATION_ORDER, a.verification), a.system, a.resource_id)):
                steps.append(("VERIFICATION", a.system, a.resource_id, a.verification, ""))
        else:
            # a COMPLETE verdict lists only checks that existing evidence already proves
            for a in sorted((a for a in items if a.verification and a.evidence_id), key=lambda a: (order(VERIFICATION_ORDER, a.verification), a.system, a.resource_id)):
                steps.append(("VERIFICATION", a.system, a.resource_id, a.verification, a.evidence_id))
        return [{"step_no": i, "phase": ph, "system_id": sysid, "resource_id": rid, "operation": op,
                 "state": OP_STATE[op], "evidence_id": ev}
                for i, (ph, sysid, rid, op, ev) in enumerate(steps, 1)]
