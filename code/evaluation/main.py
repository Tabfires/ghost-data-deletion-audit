"""Evaluation workflow.

Scores a predictions CSV against an expected CSV (default: the agent's run on the public
sample requests vs dataset/sample_output.csv) and reports:
  * case-level deletion_status accuracy (+ confusion matrix)
  * step-level precision / recall / F1 (a step = phase, system, resource, operation, state, evidence)
  * field-level accuracy over position-aligned steps and over matched (system, resource, phase) keys
  * sequence accuracy (exact steps_json match, and order agreement of the shared steps)
  * per-case diffs to drive error analysis

Usage (repository root):
    python code/evaluation/main.py                      # run agent on samples, then score
    python code/evaluation/main.py --pred p.csv --gold g.csv
    python code/evaluation/main.py --custom             # also run the hand-written custom cases
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
CODE = os.path.dirname(HERE)
ROOT = os.path.dirname(CODE)
sys.path.insert(0, CODE)

FIELDS = ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]


def load(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(fh)}


def step_key(s):
    return tuple(s[f] for f in FIELDS)


def lcs(a, b):
    m = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a)):
        for j in range(len(b)):
            m[i + 1][j + 1] = m[i][j] + 1 if a[i] == b[j] else max(m[i][j + 1], m[i + 1][j])
    return m[-1][-1]


def score(pred: dict, gold: dict, verbose: bool = True) -> dict:
    cases = sorted(gold)
    status_ok = sum(pred.get(c, ("MISSING", []))[0] == gold[c][0] for c in cases)
    confusion = Counter((gold[c][0], pred.get(c, ("MISSING", []))[0]) for c in cases)
    tp = fp = fn = 0
    pos_total = pos_match = Counter()
    pos_total, pos_match = Counter(), Counter()
    key_total, key_match = Counter(), Counter()
    exact = order_ok = order_n = 0
    lcs_sum = len_sum = 0
    diffs = []
    for c in cases:
        gs, gsteps = gold[c]
        ps, psteps = pred.get(c, ("MISSING", []))
        gk = [step_key(s) for s in gsteps]
        pk = [step_key(s) for s in psteps]
        gset, pset = Counter(gk), Counter(pk)
        inter = sum((gset & pset).values())
        tp += inter
        fp += sum(pset.values()) - inter
        fn += sum(gset.values()) - inter
        # position-aligned field accuracy
        for i in range(max(len(gsteps), len(psteps))):
            for f in FIELDS + ["step_no"]:
                pos_total[f] += 1
                if i < len(gsteps) and i < len(psteps) and gsteps[i][f] == psteps[i][f]:
                    pos_match[f] += 1
        # key-matched field accuracy (same phase/system/resource)
        gmap = {(s["phase"], s["system_id"], s["resource_id"]): s for s in gsteps}
        pmap = {(s["phase"], s["system_id"], s["resource_id"]): s for s in psteps}
        for k, gsx in gmap.items():
            if k in pmap:
                for f in ("operation", "state", "evidence_id"):
                    key_total[f] += 1
                    key_match[f] += gsx[f] == pmap[k][f]
        same = gs == ps and gk == pk
        exact += same
        # order agreement among shared steps
        shared = [k for k in pk if k in set(gk)]
        if len(shared) > 1:
            order_n += 1
            order_ok += shared == [k for k in gk if k in set(pk)]
        lcs_sum += lcs(gk, pk)
        len_sum += max(len(gk), len(pk))
        if not same:
            diffs.append((c, gs, ps, [k for k in gk if k not in set(pk)], [k for k in pk if k not in set(gk)]))
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    res = {
        "cases": len(cases),
        "status_accuracy": status_ok / len(cases),
        "step_precision": prec, "step_recall": rec, "step_f1": f1,
        "exact_case_match": exact / len(cases),
        "sequence_lcs_ratio": lcs_sum / len_sum if len_sum else 1.0,
        "shared_step_order_accuracy": order_ok / order_n if order_n else 1.0,
        "field_accuracy_positional": {f: pos_match[f] / pos_total[f] for f in pos_total},
        "field_accuracy_matched": {f: key_match[f] / key_total[f] for f in key_total},
        "confusion": {f"{g}->{p}": n for (g, p), n in sorted(confusion.items())},
    }
    if verbose:
        print(json.dumps(res, indent=1))
        for c, gs, ps, missing, extra in diffs:
            print(f"--- {c}: gold={gs} pred={ps}")
            for k in missing:
                print("   missing", k)
            for k in extra:
                print("   extra  ", k)
    res["diffs"] = diffs
    return res


def run_agent(requests, out, extra_args=()):
    import main as agent
    return agent.main(["--requests", requests, "--out", out, *extra_args])


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--pred")
    ap.add_argument("--gold", default=os.path.join(ROOT, "dataset", "sample_output.csv"))
    ap.add_argument("--requests", default=os.path.join(ROOT, "dataset", "sample_deletion_requests.csv"))
    ap.add_argument("--custom", action="store_true", help="also score the custom evaluation cases")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)
    pred_path = args.pred
    if not pred_path:
        pred_path = os.path.join(ROOT, ".cache", "sample_predictions.csv")
        os.makedirs(os.path.dirname(pred_path), exist_ok=True)
        run_agent(args.requests, pred_path)
    res = score(load(pred_path), load(args.gold), verbose=not args.quiet)
    if args.custom:
        from custom_cases import run_custom
        run_custom()
    return res


if __name__ == "__main__":
    main()
