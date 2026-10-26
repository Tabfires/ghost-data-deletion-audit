"""Ghost Data Still Exists - deletion audit agent.

Usage (from the repository root):
    python code/main.py                                   # dataset/deletion_requests.csv -> output.csv
    python code/main.py --requests dataset/sample_deletion_requests.csv --out sample_pred.csv
    python code/main.py --trace traces.jsonl              # also dump per-case reasoning
Environment:
    INTENT_LLM=ollama|anthropic|off   (default ollama; falls back to rules when unreachable)
    OLLAMA_MODEL=qwen3:14b, ANTHROPIC_API_KEY / ANTHROPIC_MODEL for the hosted option
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from deletion_audit.auditor import Auditor  # noqa: E402
from deletion_audit.data import load_dataset, read_csv  # noqa: E402
from deletion_audit.intent import IntentClassifier, LLMIntent  # noqa: E402
from deletion_audit.usage import Usage  # noqa: E402


def build_auditor(dataset_dir: str, requests_path: str, cache_dir: str):
    ds = load_dataset(dataset_dir, requests_path, cache_dir)
    usage = Usage()
    llm = LLMIntent(os.path.join(cache_dir, "intent_llm.json"), usage)
    intent = IntentClassifier(llm if llm.provider != "off" else None)
    # every participant-visible request takes part in the workflow-burst allocation
    universe = {r["case_id"]: r for r in ds.requests}
    for name in ("deletion_requests.csv", "sample_deletion_requests.csv"):
        p = os.path.join(dataset_dir, name)
        if os.path.exists(p):
            for r in read_csv(p):
                universe.setdefault(r["case_id"], r)
    auditor = Auditor(ds, intent, list(universe.values()))
    return ds, auditor, usage, llm, intent


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=os.path.join(ROOT, "dataset"))
    ap.add_argument("--requests", default=None)
    ap.add_argument("--out", default=os.path.join(ROOT, "output.csv"))
    ap.add_argument("--cache", default=os.path.join(ROOT, ".cache"))
    ap.add_argument("--trace", default=None, help="optional JSONL with per-case reasoning")
    ap.add_argument("--usage-json", default=None)
    args = ap.parse_args(argv)
    requests_path = args.requests or os.path.join(args.dataset, "deletion_requests.csv")

    t0 = time.time()
    ds, auditor, usage, llm, intent = build_auditor(args.dataset, requests_path, args.cache)
    results = [auditor.audit(r) for r in ds.requests]
    llm.save()
    results.sort(key=lambda r: case_sort_key(r.case_id))

    with open(args.out, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["case_id", "deletion_status", "steps_json"])
        for r in results:
            w.writerow([r.case_id, r.status, json.dumps(r.steps, separators=(",", ":"))])
    if args.trace:
        with open(args.trace, "w", encoding="utf-8") as fh:
            for r in results:
                fh.write(json.dumps({
                    "case_id": r.case_id, "status": r.status, "intent": r.intent,
                    "subject": r.subject.user_id if r.subject else None,
                    "resources": [a.__dict__ for a in r.resources], "notes": r.notes,
                }, default=list) + "\n")
    summary = {"requests": len(results), "seconds": round(time.time() - t0, 1), "usage": usage.summary(),
               "intent_disagreements": intent.disagreements}
    if args.usage_json:
        json.dump(summary, open(args.usage_json, "w", encoding="utf-8"), indent=1)
    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    print(f"wrote {len(results)} rows to {args.out} in {summary['seconds']}s  {counts}")
    print("model usage:", json.dumps(summary["usage"]))
    return results


def case_sort_key(case_id: str):
    # "sorted by case_id": plain lexical order, as in the provided templates
    return case_id


if __name__ == "__main__":
    main()
