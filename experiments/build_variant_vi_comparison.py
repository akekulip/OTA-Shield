"""Build comparison.json for E10 variant (vi) = Suricata permissive + RAT.

Mirrors the TP/TN/FP/FN contract used by `experiments/suricata_baseline.py`
(and therefore by `extract_paper_numbers.py`'s `_emit_baseline_block`), but
instead of deciding purely from Suricata alerts, decides from the decisions
log emitted by `experiments/suricata_rat_arbiter.py`.

Per-event contract
------------------
For each ground-truth event:
  predicted = "attack" if ANY decision record for this 5-tuple has
              decision != "PASS" (i.e., RAT did NOT demote the alert).
  predicted = "legit"  if no such retained-alert record exists (either
              Suricata did not alert, or RAT demoted every alert).

Inputs
------
  --decisions   suricata_rat_decisions.json (written by suricata_rat_arbiter.py)
  --ground-truth runs/baseline_suricata/ground_truth.json
  --out          runs/baseline_suricata_stateful_permissive/suricata_rat_perm_comparison.json

The decisions file may be JSON-array or JSON-lines (the arbiter supports
both). We autodetect.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_decisions(path: Path) -> list[dict]:
    txt = path.read_text().strip()
    if not txt:
        return []
    if txt.startswith("["):
        return json.loads(txt)
    out: list[dict] = []
    for line in txt.splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--decisions", required=True, type=Path)
    ap.add_argument("--ground-truth", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--ruleset-label",
                    default="experiments/rules/ota_shield_stateful_permissive.rules",
                    help="String for provenance only.")
    args = ap.parse_args()

    gt = json.loads(args.ground_truth.read_text())
    gt_events = gt["events"]

    dec = load_decisions(args.decisions)

    # Build set of 5-tuples where Suricata fired AND RAT kept the alert.
    retained: set[tuple] = set()
    for d in dec:
        if d.get("decision") == "PASS":
            continue  # demoted by RAT
        key = (d.get("suricata_src_ip"),
               d.get("suricata_dst_ip"),
               int(d.get("src_port", 0) or 0))
        retained.add(key)

    tp = tn = fp = fn = 0
    for ev in gt_events:
        key = (ev["src_ip"], ev["dst_ip"], int(ev["src_port"]))
        predicted = "attack" if key in retained else "legit"
        truth = "attack" if ev["label"] == "ATTACK" else "legit"
        if   truth == "attack" and predicted == "attack": tp += 1
        elif truth == "legit"  and predicted == "legit":  tn += 1
        elif truth == "legit"  and predicted == "attack": fp += 1
        else:                                              fn += 1

    n = tp + tn + fp + fn
    out = {
        "n_decisions": n,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": tp / (tp + fp) if (tp + fp) else None,
        "recall":    tp / (tp + fn) if (tp + fn) else None,
        "accuracy":  (tp + tn) / n if n else None,
        "latency_seconds": None,
        "suricata_processing_time_s": None,
        "ruleset_path": args.ruleset_label,
        "notes": [
            "Variant (vi): post-processes variant (iii) stateful-permissive "
            "Suricata alerts through the same RAT arbiter the controller runs "
            "in-band (experiments/suricata_rat_arbiter.py).",
            "Per-event predicted='attack' iff at least one alert for the "
            "event's 5-tuple survived RAT demotion (decision != PASS).",
            "Addresses reviewer Minor 4: pairs the fairest-rule Suricata "
            "variant with RAT rather than the zero-alert minimal variant (i).",
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2))
    print(f"Wrote {args.out}")
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
