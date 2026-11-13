#!/usr/bin/env python3
"""Score a PII detector against the Sangop India-PII synthetic benchmark.

    # score Sangop itself (needs `pip install -e .` of this repo)
    python score.py --detector sangop

    # score any other detector: give it a predictions file
    python score.py --pred my_predictions.jsonl

Predictions file: one JSON object per line
    {"id": "<example id>", "spans": [{"start": 0, "end": 12, "kind": "AADHAAR"}]}
Kinds must be one of: AADHAAR PAN GSTIN PHONE_IN EMAIL CARD IFSC UPI SECRET
(map your tool's labels to these first). The gold file format is described in README.md next to this file.

Matching rules (stated so results are reproducible and fair):
* STRICT : a prediction is correct only if kind AND exact (start, end) match a gold span.
* LENIENT: same kind and the spans overlap by at least 50% of the shorter span.
* A prediction that matches no gold span is a false positive for ITS kind.
  A gold span that no prediction matched is a false negative for ITS kind.
  (A wrong-kind prediction on a gold span therefore costs one FP and one FN.)
* Hard negatives ("decoys") are never in gold; any prediction overlapping a
  decoy is also counted in the separate decoy table.
* PROTECTION VIEW (added with Sangop 0.1.3, shown as a second table): a gold span counts as "covered" if ANY
  prediction of ANY kind fully contains it. This is what matters to a privacy tool: was the sensitive text
  masked at all, even under a wider span or a different label (for example a label for an ambiguous number)? It is a
  supplementary view, never a replacement for the strict numbers.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List

HERE = Path(__file__).resolve().parent
KINDS = ["AADHAAR", "PAN", "GSTIN", "PHONE_IN", "EMAIL", "CARD", "IFSC", "UPI", "SECRET"]


def require_dataset(path: Path) -> None:
    """The project's own benchmark sets are private and are not shipped (their sha256 files are, see README.md).
    Point --data at a JSONL file in the documented format."""
    if not path.exists():
        raise SystemExit(f"{path} not found. Pass --data with a JSONL gold file in the format described in "
                         "bench/india_pii/README.md.")


def load_jsonl(path: Path) -> List[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _overlap(a: dict, b: dict) -> int:
    return max(0, min(a["end"], b["end"]) - max(a["start"], b["start"]))


def _match(g: dict, p: dict, mode: str) -> bool:
    if g["kind"] != p["kind"]:
        return False
    if mode == "strict":
        return g["start"] == p["start"] and g["end"] == p["end"]
    ov = _overlap(g, p)
    shorter = min(g["end"] - g["start"], p["end"] - p["start"])
    return shorter > 0 and ov * 2 >= shorter


def score(gold_rows: List[dict], preds: Dict[str, List[dict]], mode: str = "strict") -> dict:
    tp, fp, fn = Counter(), Counter(), Counter()
    covered = Counter()
    decoy_total, decoy_hit = Counter(), Counter()
    for row in gold_rows:
        gold = row["spans"]
        pred = preds.get(row["id"], [])
        used = set()
        for g in gold:
            if any(p["start"] <= g["start"] and p["end"] >= g["end"] for p in pred):
                covered[g["kind"]] += 1
            hit = None
            for j, p in enumerate(pred):
                if j not in used and _match(g, p, mode):
                    hit = j
                    break
            if hit is None:
                fn[g["kind"]] += 1
            else:
                used.add(hit)
                tp[g["kind"]] += 1
        for j, p in enumerate(pred):
            if j not in used:
                fp[p["kind"]] += 1
        for d in row.get("decoys", []):
            decoy_total[d["like"]] += 1
            if any(_overlap(d, p) > 0 for p in pred):
                decoy_hit[d["like"]] += 1
    kinds = sorted(set(KINDS) | set(tp) | set(fp) | set(fn), key=lambda k: (k not in KINDS, k))
    per = {}
    for k in kinds:
        t, f_p, f_n = tp[k], fp[k], fn[k]
        pr = t / (t + f_p) if t + f_p else 0.0
        rc = t / (t + f_n) if t + f_n else 0.0
        f1 = 2 * pr * rc / (pr + rc) if pr + rc else 0.0
        per[k] = {"tp": t, "fp": f_p, "fn": f_n, "precision": pr, "recall": rc, "f1": f1,
                  "covered": covered[k], "cover_recall": covered[k] / (t + f_n) if t + f_n else 0.0}
    T, FP, FN = sum(tp.values()), sum(fp.values()), sum(fn.values())
    pr = T / (T + FP) if T + FP else 0.0
    rc = T / (T + FN) if T + FN else 0.0
    f1 = 2 * pr * rc / (pr + rc) if pr + rc else 0.0
    cov = sum(covered.values())
    return {"mode": mode, "per_kind": per,
            "overall": {"tp": T, "fp": FP, "fn": FN, "precision": pr, "recall": rc, "f1": f1,
                        "covered": cov, "cover_recall": cov / (T + FN) if T + FN else 0.0},
            "decoys": {k: {"total": decoy_total[k], "hit": decoy_hit[k]} for k in sorted(decoy_total)}}


def markdown(name: str, res: dict) -> str:
    out = [f"### {name} - {res['mode']} matching", "",
           "| Kind | TP | FP | FN | Precision | Recall | F1 |", "|---|---:|---:|---:|---:|---:|---:|"]
    for k, v in res["per_kind"].items():
        if v["tp"] + v["fp"] + v["fn"] == 0:
            continue
        out.append(f"| {k} | {v['tp']} | {v['fp']} | {v['fn']} | {v['precision']:.3f} | {v['recall']:.3f} | {v['f1']:.3f} |")
    o = res["overall"]
    out.append(f"| **ALL (micro)** | {o['tp']} | {o['fp']} | {o['fn']} | {o['precision']:.3f} | {o['recall']:.3f} | {o['f1']:.3f} |")
    out += ["", "Protection view (gold span fully inside ANY prediction, any kind or span width):", "",
            "| Kind | Gold | Covered | Cover recall |", "|---|---:|---:|---:|"]
    for k, v in res["per_kind"].items():
        gold = v["tp"] + v["fn"]
        if gold:
            out.append(f"| {k} | {gold} | {v['covered']} | {v['cover_recall']:.3f} |")
    out.append(f"| **ALL** | {o['tp'] + o['fn']} | {o['covered']} | {o['cover_recall']:.3f} |")
    out += ["", "Hard-negative look-alikes wrongly flagged (lower is better):", "",
            "| Look-alike of | Decoys | Flagged | Rate |", "|---|---:|---:|---:|"]
    for k, v in res["decoys"].items():
        rate = v["hit"] / v["total"] if v["total"] else 0.0
        out.append(f"| {k} | {v['total']} | {v['hit']} | {rate:.1%} |")
    return "\n".join(out) + "\n"


def sangop_predictions(rows: Iterable[dict]) -> Dict[str, List[dict]]:
    from sangop import find_all  # imported lazily so score.py works without sangop

    out: Dict[str, List[dict]] = {}
    for row in rows:
        spans = []
        for f in find_all(row["text"]):
            kind = "SECRET" if f.kind.startswith("SECRET") else f.kind
            spans.append({"start": f.start, "end": f.end, "kind": kind})
        out[row["id"]] = spans
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", type=Path, default=HERE / "dataset_v0_1.jsonl")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--detector", choices=["sangop"], help="run a built-in adapter")
    g.add_argument("--pred", type=Path, help="predictions jsonl produced by another tool")
    ap.add_argument("--name", default=None)
    ap.add_argument("--style", default=None, help="score only rows whose \"style\" field equals this (a slice of a set)")
    ap.add_argument("--json", type=Path, default=None, help="also write raw numbers here")
    a = ap.parse_args(argv)
    require_dataset(a.data)
    rows = load_jsonl(a.data)
    if a.style:
        rows = [r for r in rows if r.get("style") == a.style]
    t0 = time.perf_counter()
    if a.detector == "sangop":
        preds = sangop_predictions(rows)
    else:
        preds = {r["id"]: r.get("spans", []) for r in load_jsonl(a.pred)}
    secs = time.perf_counter() - t0
    name = a.name or a.detector or a.pred.stem
    results = {m: score(rows, preds, m) for m in ("strict", "lenient")}
    for m in ("strict", "lenient"):
        print(markdown(name, results[m]))
    print(f"_Examples: {len(rows)}; detector wall time {secs:.2f}s ({secs / max(len(rows), 1) * 1000:.3f} ms/example, includes I/O of this script)._")
    if a.json:
        a.json.write_text(json.dumps({"name": name, "seconds": secs, "results": results}, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
