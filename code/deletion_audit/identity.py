"""Identity resolution: request email -> subject and all current + historical identifiers."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .model import norm_name, norm_phone


@dataclass
class Subject:
    user_id: str
    name: str
    emails: set[str] = field(default_factory=set)
    phones: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)
    audit_ids: list[str] = field(default_factory=list)   # audit_log rows used (historical identifiers)

    @property
    def tokens(self) -> set[str]:
        toks = {"user:" + self.user_id.lower()}
        toks |= {"email:" + e for e in self.emails}
        toks |= {"phone:" + p for p in self.phones if p}
        toks |= {"hash:" + h for h in self.hashes}
        return toks

    @property
    def name_key(self) -> str:
        return norm_name(self.name)


class IdentityResolver:
    def __init__(self, identities: dict[str, dict], audit_log: list[dict]):
        self.identities = identities
        self.audit = sorted(audit_log, key=lambda r: r["event_time"])
        self.email_index: dict[str, str] = {}
        for uid, r in identities.items():
            self.email_index[r["email"].strip().lower()] = uid
        for a in self.audit:
            if a["field_name"] == "email":
                for v in (a["old_value"], a["new_value"]):
                    self.email_index.setdefault(v.strip().lower(), a["user_id"])

    def resolve(self, email: str) -> Subject | None:
        uid = self.email_index.get((email or "").strip().lower())
        if not uid:
            return None
        r = self.identities[uid]
        s = Subject(uid, r["name"])
        s.emails.add(r["email"].strip().lower())
        s.phones.add(norm_phone(r["phone"]))
        s.hashes.add(r["email_hash"].strip().lower())
        for a in self.audit:
            if a["user_id"] != uid:
                continue
            s.audit_ids.append(a["audit_id"])
            for v in (a["old_value"], a["new_value"]):
                v = v.strip()
                if a["field_name"] == "email":
                    s.emails.add(v.lower())
                elif a["field_name"] == "phone":
                    s.phones.add(norm_phone(v))
                elif a["field_name"] == "email_hash":
                    s.hashes.add(v.lower())
        # hashes of every known email (sha256 of the lower-cased address, as used by the platform)
        for e in list(s.emails):
            s.hashes.add(hashlib.sha256(e.encode()).hexdigest())
        return s
