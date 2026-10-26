"""Turn a raw evidence record (a dict of fields) into an Observation state.

Every extractor funnels its records through `interpret_record`, so the
semantics of "what does this record say about the resource" live in one place.
"""
from __future__ import annotations

from .model import (ABSENT, ACTIVE, ANONYMIZED, BLOCKED, DISABLED, IDENTIFIABLE, PRESENT, REDACTED,
                    SYSTEM_CATEGORY, norm_token, system_of, tokens_in_text)

# Fields that carry a direct identifier (policy says these must be removed).
DIRECT_FIELDS = {
    "email": "email", "customer_email": "email", "owner_email": "email", "requester_email": "email",
    "phone": "phone", "owner_phone": "phone", "requester_phone": "phone",
    "email_hash": "email_hash",
    "full_name": "name", "name": "name", "display_name": "name", "requester_name": "name",
}
# Fields that carry the stable internal reference (allowed on tombstones / retained records).
REFERENCE_FIELDS = {"customer_reference", "subject_reference", "user_id", "subject_ref"}
# Fields that only link the record to a subject (lookup keys, selectors, scan matches).
LINK_FIELDS = {"subject_selector", "matched_value", "lookup_value", "correlation_key", "lookup_key",
               "match_key", "subject_key", "scan_key", "owner_key", "query", "selector"}

RESULT_STATE = {
    "FOUND": PRESENT, "PRESENT": PRESENT, "EXISTS": PRESENT, "HIT": PRESENT,
    "NOT_FOUND": ABSENT, "ABSENT": ABSENT, "DELETED": ABSENT, "MISSING": ABSENT, "MISS": ABSENT,
    "IDENTIFIABLE": IDENTIFIABLE, "ANONYMIZED": ANONYMIZED, "REDACTED": REDACTED,
    "ACTIVE": ACTIVE, "ENABLED": ACTIVE, "DISABLED": DISABLED, "STOPPED": DISABLED,
    "BLOCKED": BLOCKED, "RESTORABLE": ACTIVE,
}

TRUE = {"true", "1", "yes", "y"}
FALSE = {"false", "0", "no", "n"}


def truthy(value) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    v = str(value).strip().strip('"').lower()
    if v in TRUE:
        return True
    if v in FALSE:
        return False
    return None


def is_null(value) -> bool:
    return value is None or str(value).strip().strip('"').lower() in {"", "null", "none", "[redacted]"}


def flatten(fields: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in (fields or {}).items():
        if isinstance(v, dict):
            out.update(flatten(v, prefix))
        elif isinstance(v, list):
            if v and all(isinstance(x, dict) for x in v):
                for x in v:
                    for kk, vv in flatten(x, prefix).items():
                        out.setdefault(kk, vv)
            else:
                out[prefix + k] = v
        else:
            out[prefix + k] = v
    return out


def identifiers_and_pii(fields: dict) -> tuple[set[str], set[str]]:
    """Return (identifier tokens, direct-identifier kinds still present)."""
    ids, pii = set(), set()
    for k, v in fields.items():
        if is_null(v):
            continue
        key = k.lower()
        if key in DIRECT_FIELDS:
            kind = DIRECT_FIELDS[key]
            pii.add(kind)
            tok = norm_token(v)
            if tok:
                ids.add(tok)
            elif kind == "name":
                ids.add("name:" + str(v).strip().lower())
        elif key in REFERENCE_FIELDS or key in LINK_FIELDS:
            tok = norm_token(v)
            if tok:
                ids.add(tok)
        elif key in {"message_text", "message_excerpt", "message", "details", "detail"}:
            found = tokens_in_text(str(v))
            if found:
                ids |= found
                pii.add("message_identifier")
    return ids, pii


def interpret_record(system: str | None, resource_id: str, fields: dict, *,
                     result: str | None = None, record_type: str | None = None) -> tuple[str, str, set[str], set[str]]:
    """Return (state, category, identifiers, pii) for one record."""
    system = system or system_of(resource_id)
    flat = flatten(fields)
    ids, pii = identifiers_and_pii(flat)
    category = record_type or SYSTEM_CATEGORY.get(system or "", None)

    if result:
        state = RESULT_STATE.get(str(result).upper().strip('"'))
        if state:
            return state, category, ids, pii

    has_ref = any(not is_null(flat.get(f)) for f in REFERENCE_FIELDS)
    if system == "integration_service":
        enabled = truthy(flat.get("enabled"))
        if enabled is None:
            enabled = truthy(flat.get("scheduler_registered"))
        if enabled is None and str(flat.get("mode", "")).lower().startswith("continuous"):
            enabled = True
        return (ACTIVE if enabled or enabled is None else DISABLED), "DATA_FLOW", ids, pii
    if system == "backup_service":
        allowed = truthy(flat.get("restore_allowed"))
        if allowed is None and "eligible" in flat:
            allowed = truthy(flat.get("eligible")) and not truthy(flat.get("deletion_block"))
        if allowed is None and "decision" in flat:
            allowed = str(flat.get("decision")).lower() not in {"deny", "denied", "blocked"}
        if allowed is None and "archive_present" in flat and not truthy(flat.get("archive_present")):
            return ABSENT, "BACKUP_ARCHIVE", ids, pii
        return (ACTIVE if allowed or allowed is None else BLOCKED), "BACKUP_ARCHIVE", ids, pii
    if system == "export_service":
        avail = truthy(flat.get("download_available", flat.get("available")))
        return (ABSENT if avail is False else PRESENT), "USER_EXPORT", ids, pii
    if system == "account_service":
        if not lookup_found(flat):
            return ABSENT, category, ids, pii
        return PRESENT, category, ids, pii
    if system == "search_service":
        if not lookup_found(flat):
            return ABSENT, category, ids, pii
        return PRESENT, category, ids, pii
    if system in {"analytics_platform"}:
        if not lookup_found(flat):
            return ABSENT, category, ids, pii
        if truthy(flat.get("email_opt_in")) is not None:
            # a marketing contact entry keyed by an identifier: a secondary identifier copy
            return PRESENT, "SECONDARY_IDENTIFIER", ids, pii
        if pii or has_ref or truthy_count(flat.get("direct_identifiers")):
            return IDENTIFIABLE, category, ids, pii
        return ANONYMIZED, category, ids, pii
    if system == "identity_service":
        if not lookup_found(flat):
            return ABSENT, category, ids, pii
        return (IDENTIFIABLE if pii else REDACTED), "ACCOUNT_TOMBSTONE", ids, pii
    if system == "support_platform":
        if not lookup_found(flat):
            return ABSENT, category, ids, pii
        if record_type == "SUPPORT_ATTACHMENT" or "file" in flat or "file_name" in flat or "uploaded_by" in flat:
            return PRESENT, "SUPPORT_ATTACHMENT", ids, pii
        if pii:
            return IDENTIFIABLE, "SUPPORT_MESSAGE", ids, pii
        return REDACTED, "SUPPORT_MESSAGE", ids, pii
    if system == "security_service":
        if not lookup_found(flat):
            return ABSENT, category, ids, pii
        return PRESENT, "SECURITY_AUDIT_LOG", ids, pii
    if system == "legal_service":
        return PRESENT, "LEGAL_HOLD_RECORD", ids, pii
    if system == "marketing_platform":
        return PRESENT, "MARKETING_PROFILE", ids, pii
    if not lookup_found(flat):
        return ABSENT, category, ids, pii
    return PRESENT, category, ids, pii


def truthy_count(value) -> bool:
    try:
        return int(str(value).strip('"')) > 0
    except (TypeError, ValueError):
        return False


def lookup_found(flat: dict) -> bool:
    """Interpret lookup-style result fields (rows, http status, hits)."""
    for key in ("rows", "total_hits", "total"):
        if key in flat and not is_null(flat[key]):
            try:
                if int(str(flat[key]).strip('"')) == 0:
                    return False
            except ValueError:
                pass
    for key in ("http_status", "status_code"):
        if key in flat and str(flat[key]).strip('"') == "404":
            return False
    res = str(flat.get("result", "")).lower().strip('"')
    if res in {"miss", "not_found", "none"}:
        return False
    if "profile" in flat and flat["profile"] is None:
        return False
    if "marker_found" in flat:
        # a replica row is still present; marker_found only says whether a deletion marker exists
        return True
    return True
