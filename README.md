# Ghost Data Still Exists — Deletion Audit Agent

HackerRank Orchestrate, October 2026. This agent checks whether a person's data was really
deleted. It does not trust the workflow's claim. It rebuilds the true state at `audit_at`
from the supplied evidence and writes an ordered plan of findings, remediation and verification
steps.

> **Competition entry.** Built and submitted for
> [HackerRank Orchestrate (October 2026) — Ghost Data Still Exists](https://wwww.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists),
> a timed AI-agent engineering challenge. This repo contains the full solution, evaluation
> reports and the coding-agent transcript (`log.txt`) as submitted.

```
dataset/ ──► extract ──► link ──► reconstruct ──► apply policy ──► plan ──► output.csv
            (all formats)  (who?)   (state @ audit)  (rules.csv)     (ordering)
```

## Quick start

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r code/requirements.txt

python code/main.py                     # dataset/deletion_requests.csv -> ./output.csv
python code/evaluation/main.py          # run on the 32 public samples and score vs sample_output.csv
python code/evaluation/custom_cases.py  # 4 hand-written fixture cases
```

Optional flags: `--requests <csv>`, `--out <csv>`, `--trace traces.jsonl` (per-case reasoning),
`--usage-json usage.json`.

### Models (optional; the pipeline also runs fully offline)

| Purpose | Default | Alternatives |
| --- | --- | --- |
| Request intent (does the text authorise deletion?) | local `qwen3:14b` via Ollama (`http://localhost:11434`) | `INTENT_LLM=anthropic` + `ANTHROPIC_API_KEY` (`ANTHROPIC_MODEL`, default `claude-haiku-5-5`); `INTENT_LLM=off` uses the multilingual rule classifier only |
| Screenshot text | RapidOCR (ONNX, offline) | — |
| PDF text | pypdf | — |

LLM answers and OCR text are cached in `.cache/`, so a rerun is deterministic and makes no
model calls. The cache lives outside `code/` and is not part of the submission. No secrets are
read from anywhere except environment variables.

## How it works

`code/deletion_audit/`

| Module | Role |
| --- | --- |
| `evidence.py` | Parses every evidence format into normalised `Observation`s (system, resource, state, identifiers, time, file_id). Covers 6 log layouts (multi-line traces are stitched by trace id, so a lookup key on the `*_started` line is linked to the outcome on `*_completed`), SQLite snapshots executed in memory (inventory tables, primary vs read/regional/reporting/failover replicas), JSON bundles / service exports / lookup ledgers, handover text, and PDFs / screenshots. |
| `media.py` | PDF text extraction (pypdf) and screenshot OCR (RapidOCR), with a cache. |
| `interpret.py` | One place that decides what a record says: present / absent / identifiable / anonymised / redacted / active / disabled / blocked, and which direct identifiers it still exposes. |
| `identity.py` | Resolves the request email (current or historical) to the subject, plus every identifier: current and historical emails, phones, email hashes (sha256 of each known email), and `user_id`. |
| `linking.py` | Ties resources to the subject. **(1) Evidence identity:** a record carries one of the subject's identifiers, or the data catalog (`LINK_RESOURCE_IDENTITY`) names its owner. **(2) Deletion-workflow bursts:** deleted accounts and anonymised analytics carry no identifier, so they are allocated from the deletion worker's activity around the request's `reported_at`. Constraint propagation uses: evidence-owned rows → the timing chain of each request's policy actions (+449 s / +390 s) → account delete result ↔ reported status → evidence consistency → a deterministic tie-break (flagged). |
| `auditor.py` | Keeps the resources in scope. Rebuilds each one's state from evidence captured at or before `audit_at` (the manifest's `captured_at` gates citations). Applies policy and builds the plan. |
| `policy.py` | `deletion_rules.csv` → finding / remediation / verification per category and state. Holds the operation order tables. |
| `intent.py` | Rule classifier (multilingual, negation-aware) plus an LLM judge with a JSON contract. |
| `usage.py` | Token and cost accounting for the usage report. |

Key decisions:

* **Reported statuses and activity results are claims.** State always comes from evidence. When
  the evidence says nothing, a primary-profile delete is still checked by a future
  `VERIFY_RECORD_ABSENT`.
* **Time discipline.** Only files whose manifest `captured_at` ≤ `audit_at` are used for state and
  citations. Records first seen before the request belong to earlier history and are out of scope.
  Retained security records may be identified from a capture up to 14 days after the audit; they
  are used only in future-verification steps, which carry no evidence id.
* **Replica drift.** A row present in any replica counts as a remaining copy, even when the primary
  is clean.
* **Policy.** Delete: profiles, secondary identifiers, search, cache, exports, marketing, sole-owner
  attachments. Redact: support conversations, email logs, tombstones (keep `user_id`). Anonymise:
  analytics and telemetry. Retain and verify present: security audit and legal hold records. Data
  flows are disabled and backup restores are blocked.
* **Ordering.** Findings → remediation → verification. Inside each phase, steps follow the operation
  table order, then `system_id`, then `resource_id`. COMPLETE cases list only evidence-backed
  verification steps. INCOMPLETE remediation and verification steps use `evidence_id=""`.

Evaluation results, custom cases and the improvement log are in
[`code/evaluation/evaluation_report.md`](code/evaluation/evaluation_report.md); token usage and
cost are in [`code/evaluation/usage_report.md`](code/evaluation/usage_report.md).
