"""Correlate Zeek notice.log against E1 ground_truth.json for E10 baseline."""
from __future__ import annotations
import argparse, json
from pathlib import Path


def parse_notice(path: Path) -> list[dict]:
    rows = []
    with path.open() as f:
        header = None
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                header = line.split("\t")[1:]
                continue
            if line.startswith("#") or not line.strip():
                continue
            if header is None:
                continue
            parts = line.split("\t")
            rec = dict(zip(header, parts))
            rows.append(rec)
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--notice", required=True, type=Path)
    ap.add_argument("--ground-truth", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()

    notices = parse_notice(args.notice)
    gt = json.loads(args.ground_truth.read_text())
    gt_events = gt["events"]

    # index notices by 5-tuple (src_ip, dst_ip, src_port)
    alerted: dict[tuple, list[str]] = {}
    for n in notices:
        key = (n.get("id.orig_h", ""),
               n.get("id.resp_h", ""),
               int(n.get("id.orig_p", "0") or 0))
        alerted.setdefault(key, []).append(n.get("note", ""))

    tp = tn = fp = fn = 0
    decisions = []
    for ev in gt_events:
        key = (ev["src_ip"], ev["dst_ip"], int(ev["src_port"]))
        hits = alerted.get(key, [])
        predicted = "attack" if hits else "legit"
        truth = "attack" if ev["label"] == "ATTACK" else "legit"
        if   truth == "attack" and predicted == "attack": tp += 1
        elif truth == "legit"  and predicted == "legit":  tn += 1
        elif truth == "legit"  and predicted == "attack": fp += 1
        else:                                              fn += 1
        decisions.append({
            "src_ip": ev["src_ip"], "dst_ip": ev["dst_ip"],
            "src_port": ev["src_port"], "truth": truth,
            "zeek_predicted": predicted,
            "zeek_notes": hits,
        })

    n = tp + tn + fp + fn
    out = {
        "n_decisions": n,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": tp / (tp + fp) if (tp + fp) else None,
        "recall":    tp / (tp + fn) if (tp + fn) else None,
        "accuracy":  (tp + tn) / n if n else None,
        "notice_count_by_type": {
            nt: sum(1 for n in notices if n.get("note") == nt)
            for nt in sorted({n.get("note", "") for n in notices})
        },
    }
    args.out.write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
