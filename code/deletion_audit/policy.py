"""Policy: map a data category + observed state to findings, remediation and verification.

The required end-state per category comes from dataset/deletion_rules.csv
(DELETE / REDACT / ANONYMIZE / RETAIN); data flows and restore paths are the
recreation risks that must be switched off.
"""
from __future__ import annotations

from .model import ABSENT, ACTIVE, ANONYMIZED, BLOCKED, DISABLED, IDENTIFIABLE, PRESENT, REDACTED

# Phase-internal operation order (problem statement, "Allowed Operations" table).
FINDING_ORDER = ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"]
REMEDIATION_ORDER = ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"]
VERIFICATION_ORDER = ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
                      "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"]
OP_STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE", "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED", "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT", "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}

ACTION_VERIFY = {"DELETE": "VERIFY_RECORD_ABSENT", "REDACT": "VERIFY_RECORD_REDACTED",
                 "ANONYMIZE": "VERIFY_RECORD_ANONYMIZED", "RETAIN": "VERIFY_RECORD_PRESENT"}


class Policy:
    def __init__(self, rules: list[dict]):
        self.action = {r["data_category"]: r["required_action"] for r in rules}
        self.rule_id = {r["data_category"]: r["rule_id"] for r in rules}

    def required_action(self, category: str) -> str:
        if category == "DATA_FLOW":
            return "DISABLE"
        return self.action.get(category, "DELETE")

    def decide(self, category: str, state: str) -> tuple[str | None, str | None, str | None]:
        """Return (finding op, remediation op, verification op) for one resource.

        finding/remediation are None when the resource already complies.
        verification is None when nothing needs to be proven for the resource.
        """
        if category == "DATA_FLOW":
            if state == ACTIVE:
                return "REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"
            return None, None, "VERIFY_DATA_FLOW_DISABLED"
        if category == "BACKUP_ARCHIVE":
            if state == ACTIVE:
                return "REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"
            if state == ABSENT:
                return None, None, None
            return None, None, "VERIFY_RESTORE_BLOCKED"
        action = self.required_action(category)
        if action == "RETAIN":
            return (None, None, "VERIFY_RECORD_PRESENT") if state != ABSENT else (None, None, None)
        if action == "DELETE":
            if state == ABSENT:
                return None, None, "VERIFY_RECORD_ABSENT"
            return "REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"
        if action == "REDACT":
            if state == ABSENT:
                return None, None, None
            if state in (IDENTIFIABLE, PRESENT):
                return "REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"
            return None, None, "VERIFY_RECORD_REDACTED"
        if action == "ANONYMIZE":
            if state == ABSENT:
                return None, None, None
            if state in (IDENTIFIABLE, PRESENT):
                return "REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"
            return None, None, "VERIFY_RECORD_ANONYMIZED"
        return None, None, None
