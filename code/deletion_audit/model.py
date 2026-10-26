"""Core data model shared by the extractors, the reasoner and the planner."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# Resource-id prefix -> owning system. Evidence sometimes names a system
# explicitly; the prefix is the fallback and is also used to sanity check it.
PREFIX_SYSTEM = [
    ("audit_record_", "security_service"),
    ("data_flow_", "integration_service"),
    ("email_delivery_", "email_delivery_service"),
    ("tombstone_", "identity_service"),
    ("analytics_", "analytics_platform"),
    ("marketing_", "marketing_platform"),
    ("account_", "account_service"),
    ("support_", "support_platform"),
    ("search_", "search_service"),
    ("export_", "export_service"),
    ("backup_", "backup_service"),
    ("legal_", "legal_service"),
    ("object_", "object_storage"),
    ("cache_", "cache_service"),
]

SYSTEM_CATEGORY = {
    "account_service": "USER_PROFILE",
    "search_service": "SEARCH_INDEX_ENTRY",
    "analytics_platform": "ANALYTICS_PROFILE",
    "support_platform": "SUPPORT_MESSAGE",
    "export_service": "USER_EXPORT",
    "integration_service": "DATA_FLOW",
    "backup_service": "BACKUP_ARCHIVE",
    "security_service": "SECURITY_AUDIT_LOG",
    "identity_service": "ACCOUNT_TOMBSTONE",
    "marketing_platform": "MARKETING_PROFILE",
    "email_delivery_service": "EMAIL_DELIVERY_LOG",
    "cache_service": "CACHE_ENTRY",
    "legal_service": "LEGAL_HOLD_RECORD",
    "object_storage": "SUPPORT_ATTACHMENT",
}

RESOURCE_RE = re.compile(
    r"\b(?:audit_record|data_flow|email_delivery|tombstone|analytics|marketing|account|support|search|export|backup|legal|object|cache)_\d+\b"
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
USER_RE = re.compile(r"\buser_\d+\b")
HASH_RE = re.compile(r"\b[0-9a-f]{64}\b")


def system_of(resource_id: str) -> str | None:
    for prefix, system in PREFIX_SYSTEM:
        if resource_id.startswith(prefix):
            return system
    return None


def norm_phone(value: str) -> str:
    return re.sub(r"\D", "", value or "")


def norm_name(value: str) -> str:
    value = unicodedata.normalize("NFKD", value or "")
    value = "".join(c for c in value if not unicodedata.combining(c))
    return re.sub(r"[^a-z]+", " ", value.lower()).strip()


def norm_token(value) -> str | None:
    """Normalise one identifier-looking value into a comparable key."""
    if value is None:
        return None
    value = str(value).strip().strip('"')
    if not value or value.lower() in {"null", "none", "[redacted]", "redacted"}:
        return None
    if "@" in value and EMAIL_RE.fullmatch(value):
        return "email:" + value.lower()
    if USER_RE.fullmatch(value.lower()):
        return "user:" + value.lower()
    if HASH_RE.fullmatch(value.lower()):
        return "hash:" + value.lower()
    digits = norm_phone(value)
    if value.startswith("+") and len(digits) >= 8:
        return "phone:" + digits
    return None


def tokens_in_text(text: str) -> set[str]:
    """Pull every identifier-looking token out of free text."""
    found = set()
    for m in EMAIL_RE.findall(text or ""):
        found.add("email:" + m.lower().rstrip("."))
    for m in USER_RE.findall((text or "").lower()):
        found.add("user:" + m)
    for m in HASH_RE.findall((text or "").lower()):
        found.add("hash:" + m)
    for m in re.findall(r"\+\d[\d ()-]{6,}\d", text or ""):
        found.add("phone:" + norm_phone(m))
    return found


# Observation states (what a piece of evidence says about a resource).
PRESENT = "PRESENT"            # record exists (and, if relevant, carries identifiers)
ABSENT = "ABSENT"              # record does not exist
IDENTIFIABLE = "IDENTIFIABLE"  # record exists and still carries direct identifiers
ANONYMIZED = "ANONYMIZED"      # record exists with no direct identifiers
REDACTED = "REDACTED"          # record exists, identifiers removed, stable reference kept
ACTIVE = "ACTIVE"              # data flow enabled / restore allowed
DISABLED = "DISABLED"          # data flow disabled
BLOCKED = "BLOCKED"            # restore blocked


@dataclass
class Observation:
    file_id: str
    observed_at: str
    system: str
    resource_id: str
    state: str
    category: str | None = None
    identifiers: set[str] = field(default_factory=set)   # tokens linking the record to a subject
    pii: set[str] = field(default_factory=set)           # direct identifier fields still present
    source: str = ""                                     # extractor tag, for debugging
    note: str = ""

    def __repr__(self) -> str:  # compact for debugging
        ids = ",".join(sorted(self.identifiers))
        return (f"Obs({self.file_id}@{self.observed_at} {self.system}/{self.resource_id} "
                f"{self.category}:{self.state} ids=[{ids}] pii={sorted(self.pii)} {self.source})")


@dataclass
class Coverage:
    """A snapshot that enumerates every record of a system/collection at a time.

    A resource missing from a covering snapshot is evidence that it is absent.
    """
    file_id: str
    observed_at: str
    system: str
    resource_ids: set[str]
    source: str = ""
