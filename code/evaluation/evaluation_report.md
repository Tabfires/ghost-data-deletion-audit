# Evaluation Report — Ghost Data Still Exists

Workflow: `python code/evaluation/main.py` runs the agent on `dataset/sample_deletion_requests.csv`
and scores it against `dataset/sample_output.csv`. `python code/evaluation/custom_cases.py` runs the
custom fixture cases. Both use the scorer in `code/evaluation/main.py`.

Metric definitions:
* **Status accuracy:** the fraction of cases whose `deletion_status` matches.
* **Step-level precision / recall / F1:** a step counts as correct only when all six fields match
  (`phase, system_id, resource_id, operation, state, evidence_id`). The comparison is a multiset
  per case.
* **Positional field accuracy:** step *i* of the prediction is compared with step *i* of the gold
  answer, one field at a time. Missing or extra steps count as errors.
* **Matched field accuracy:** for steps that share `(phase, system_id, resource_id)`, the share
  whose `operation` / `state` / `evidence_id` agree.
* **Sequence accuracy:**
  * *exact case match*: the whole `steps_json` array is identical;
  * *LCS ratio*: the longest common subsequence of steps divided by the longer sequence;
  * *shared-step order accuracy*: steps present in both arrays appear in the same relative order.

## 1. Final results on the 32 public samples

Final configuration: local `qwen3:14b` intent judge, rules override it only on an explicit cue,
and the full evidence and allocation pipeline.

| Metric | Value |
| --- | --- |
| Case-level status accuracy | **1.000** (32/32) |
| Step precision | **0.995** |
| Step recall | **0.979** |
| Step F1 | **0.987** |
| Exact case match (sequence) | **0.875** (28/32) |
| LCS sequence ratio | 0.979 |
| Shared-step order accuracy | **1.000** |

Status confusion: COMPLETE→COMPLETE 10, INCOMPLETE→INCOMPLETE 22.

Positional field accuracy:

| phase | system_id | resource_id | operation | state | evidence_id | step_no |
| --- | --- | --- | --- | --- | --- | --- |
| 0.984 | 0.959 | 0.953 | 0.959 | 0.959 | 0.979 | 0.984 |

Matched field accuracy (same phase, system and resource): operation 1.000, state 1.000,
evidence_id 1.000. When the agent finds the right resource, the policy decision and the cited
evidence are always right; every remaining error is a missing or misidentified resource.

The rules-only configuration (`INTENT_LLM=off`) scores the same on the samples.

### Remaining sample errors (4 cases, 5 steps)

| Case | Error | Why it remains |
| --- | --- | --- |
| case_04 | missing `account_004` VERIFY_RECORD_ABSENT | `account_004` does not appear in any participant file (evidence or activity). It cannot be derived without guessing an id pattern. |
| case_18 | missing `audit_record_6645` VERIFY_RECORD_PRESENT | The id appears nowhere in participant data. |
| case_20 | missing `audit_record_5569` VERIFY_RECORD_PRESENT | Same as case_18. |
| case_23 | `account_7015` instead of `account_410` | A true tie. Three identifier-less FAILED account deletes (`7015`, `410`, `9155`) fall in the same burst as three NOT_STARTED requests (23, 547, 548). No participant-visible signal separates them, so the deterministic tie-break picked the wrong one. |

## 2. Custom evaluation cases (written by us)

`code/evaluation/custom_cases.py` builds four self-contained mini datasets: identities, audit log,
activity, rules, an evidence manifest and real evidence files. Each one targets one failure mode,
runs the real agent on it, and scores the output against a hand-written expected answer.

| # | Case | What it checks | Result |
| --- | --- | --- | --- |
| C1 | `negated_deletion_language` | The text says "send me a copy… I am not asking for deletion and do not close the account". The answer must be NOT_APPLICABLE with `[]`, even though it contains the word "deletion". | PASS |
| C2 | `historical_email_and_replica_drift` | The request uses the **old** email. The primary DB is clean but a **read replica** still holds the profile, which counts as a remaining record. The search document carries only the **new** email. A log captured **after `audit_at`** shows everything deleted and must be ignored. 7 expected steps, including the retained security record. | PASS |
| C3 | `tombstone_flow_and_remediation_order` | A French request. The tombstone still has PII, a connector is active, and a support conversation still exposes the email. Checks the operation order: DISABLE before REDACT, then verification ordered ABSENT → PRESENT → REDACTED → DISABLED. 11 expected steps. | PASS |
| C4 | `workflow_linked_anonymised_records_complete` | A COMPLETE case where the deleted account and the anonymised analytics profile carry **no identifier**. They must be linked through the deletion worker's burst: the account by status match, the analytics profile by the +449 s timing chain to the subject's redaction. Every verification step must cite the evidence file. | PASS |

All four pass (step F1 1.000). Honest caveat: these fixtures were written after the
corresponding logic, so they work as regression tests that pin behaviour down, not as blind
tests. The failures that drove the design came from the sample-set error analysis below.

## 3. Failures found and improvements made

Each row is one iteration on the 32 samples, with metrics measured after the change.

| # | Change | Failure it fixed | Status acc | Step F1 | Exact |
| --- | --- | --- | --- | --- | --- |
| 1 | First end-to-end pipeline: extractors, identity, policy, ordering | — | 0.969 | 0.925 | 0.44 |
| 2 | Snapshot "absence by omission" restricted to account profiles and used only as a fallback. Resources first seen *before* the request count as earlier history. Screenshots stop linking every printed email to every resource. More intent cues. | Partial snapshot bundles made retained security records look deleted. A 6-month-old lookup of the same person's earlier account was pulled into a later case (case_17). A multi-person connector console linked another user's flow (case_15). | 0.969 | 0.925→0.955 | 0.66 |
| 3 | Workflow-burst allocator: account delete `reported_result` ↔ request `reported_status`, plus the policy-action **timing chain** (gaps of exactly 449 s / 390 s) | Deleted accounts and anonymised analytics have no identifiers; at first they were simply missing. | 0.969 | 0.955 | 0.66 |
| 4 | Evidence-consistency tie-break. An observed identifier-less record goes to a request whose own evidence comes from the same capture and shows no violation; an unobserved one goes to a request that already has findings. Explicit `copy of` cue fixed for C1-style texts. | Ties between requests in the same burst (cases 25/26/27/28/31/32). | **1.000** | 0.982 | 0.84 |
| 5 | Workflow-allocated resources are always in scope, whenever they were last seen | case_09's account was dropped by the relevance filter. | 1.000 | 0.984 | 0.84 |
| 6 | Screenshot handling: catalog **aliases** (`NST-2026-0718-1842` → `export_1842`, `user_17` → `tombstone_17`, `delivery_confirmation_19.pdf` → `object_19`). State is read from the artifact. Single-person PDFs link to their subject. | The hand-crafted screenshot/PDF test cases had no findings, and case_07's PDF attachment was briefly lost (regression to F1 0.971, then fixed). | 1.000 | 0.984 | 0.84 |
| 7 | Per-activity-kind windows: successful policy actions in [rep−1h, rep]; failures and checks in [rep, rep+3h]; account deletes in [rep−2.5h, rep+30m] | An unrelated burst claimed case_04's analytics record. | 1.000 | **0.987** | **0.875** |
| 8 | LLM intent judge (qwen3:14b) added, with rule override on an explicit cue | The LLM alone misread case_25 ("tell me whether … have already been removed") as non-deletion. The rule cue keeps it a deletion check. | 1.000 | 0.987 | 0.875 |

## 4. Full-dataset run (518 requests): what to expect

Statuses: **353 INCOMPLETE, 155 COMPLETE, 10 NOT_APPLICABLE**; 3,187 steps in total. All 10
non-deletion requests (phone correction, marketing opt-out, export or access, password reset,
name or email change) were flagged by both the rule classifier and the LLM, with zero
disagreements on the test set.

How deletion-workflow resources were linked to test requests:

| Link method | Accounts | Other resources |
| --- | --- | --- |
| Evidence identity (identifier or data catalog) | 223 | 726 |
| Account result ↔ reported status (unique) | 153 | — |
| Policy-action timing chain | — | 33 |
| Single claimant in the burst | — | 17 |
| Evidence consistency | 18 | 48 |
| **Deterministic tie-break (ambiguous)** | **102** | — |

The 102 tie-broken accounts are the main known risk. Each one affects a single
`VERIFY_RECORD_ABSENT` step. With 2–3 candidates per tie, about half of them are expected to be
wrong. Twelve hand-crafted screenshot/PDF requests have no workflow activity at all, so their
primary-profile id cannot be recovered and no account step is emitted for them.

## 5. Determinism

Output is deterministic. Ordering is fixed, JSON uses compact separators, and tie-breaks follow
time order. LLM answers are cached (temperature 0, fixed seed) and OCR text is cached as well.
Rows are written sorted by `case_id`.
