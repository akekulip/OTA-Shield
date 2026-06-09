"""Shaped-adversary F1 — pools E1/E8 clean attacks with E17 mimicry
events so a reviewer sees one number that reflects both naive and
shaped adversaries.

Reads per-trial TP/TN/FP/FN from E1 and E17 aggregates, sums them,
and computes precision/recall/F1 over the pool with a bootstrap CI.

Writes runs/experiments/_agg/shaped_adversary.json with:
  { "tp": ..., "fp": ..., "fn": ..., "precision": ..., "recall": ...,
    "f1": ..., "f1_ci_lo": ..., "f1_ci_hi": ..., "n_events": ... }
"""
from __future__ import annotations
import argparse, json, random, statistics
from pathlib import Path


def load_gt(trial_dir: Path) -> list[dict]:
    p = trial_dir / "ground_truth.json"
    if not p.exists():
        return []
    return json.loads(p.read_text()).get("events", [])


def load_decisions(trial_dir: Path) -> list[dict]:
    for name in ("controller_decisions.jsonl", "decisions.jsonl"):
        p = trial_dir / name
        if p.exists():
            out = []
            for line in p.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            if out:
                return out
    return []


def int_to_ip(x) -> str:
    if isinstance(x, str):
        return x
    x = int(x)
    return ".".join(str((x >> (8 * (3 - i))) & 0xff) for i in range(4))


def per_event_label(ev: dict, dec: dict | None) -> str:
    """Return 'TP','FP','FN','TN' for a single event given its
    ground-truth label and controller decision (None => no decision)."""
    true_attack = ev.get("label") == "ATTACK"
    if dec is None:
        # No decision: classify-pass-through. Treat as PASS.
        predicted_attack = False
    else:
        predicted_attack = (dec.get("decision") or "").upper() == "DROP"
    if true_attack and predicted_attack: return "TP"
    if true_attack and not predicted_attack: return "FN"
    if not true_attack and predicted_attack: return "FP"
    return "TN"


def pool_events(dirs: list[Path]) -> list[str]:
    """Return list of per-event labels from the given trial dirs."""
    labels: list[str] = []
    for exp in dirs:
        if not exp.exists():
            continue
        for t in sorted(p for p in exp.iterdir() if p.is_dir()):
            gt = load_gt(t)
            decs = load_decisions(t)
            by_key = {}
            for d in decs:
                k = (int_to_ip(d.get("src_ip", 0)),
                     int_to_ip(d.get("dst_ip", 0)),
                     int(d.get("src_port", 0)))
                by_key[k] = d
            for ev in gt:
                k = (ev["src_ip"], ev["dst_ip"], int(ev["src_port"]))
                labels.append(per_event_label(ev, by_key.get(k)))
    return labels


def metrics(labels: list[str]) -> dict:
    tp = labels.count("TP"); fp = labels.count("FP")
    fn = labels.count("FN"); tn = labels.count("TN")
    prec = tp / (tp + fp) if (tp + fp) > 0 else float("nan")
    rec  = tp / (tp + fn) if (tp + fn) > 0 else float("nan")
    f1   = (2 * prec * rec / (prec + rec)
            if prec == prec and rec == rec and (prec + rec) > 0
            else float("nan"))
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": prec, "recall": rec, "f1": f1,
            "n_events": len(labels)}


def bootstrap_ci(labels: list[str], n_iter: int = 2000,
                  seed: int = 0) -> tuple[float, float]:
    rng = random.Random(seed)
    f1s = []
    for _ in range(n_iter):
        sample = [rng.choice(labels) for _ in range(len(labels))]
        m = metrics(sample)
        if m["f1"] == m["f1"]:
            f1s.append(m["f1"])
    f1s.sort()
    return (f1s[int(0.025 * len(f1s))],
            f1s[int(0.975 * len(f1s))]) if f1s else (float("nan"), float("nan"))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp-dirs", nargs="+", default=[
        "runs/experiments/E1_attack_detection",
        "runs/experiments/E17_mimicry",
    ], type=Path)
    ap.add_argument("--out",
                    default="runs/experiments/_agg/shaped_adversary.json",
                    type=Path)
    args = ap.parse_args()

    labels = pool_events(args.exp_dirs)
    m = metrics(labels)
    lo, hi = bootstrap_ci(labels)
    m["f1_ci_lo"] = lo; m["f1_ci_hi"] = hi
    m["pooled_dirs"] = [str(p) for p in args.exp_dirs]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(m, indent=2))

    print("=== shaped-adversary F1 (E1 clean attacks + E17 mimicry) ===")
    print(f"N events: {m['n_events']}")
    print(f"TP={m['tp']}  FP={m['fp']}  FN={m['fn']}  TN={m['tn']}")
    print(f"precision={m['precision']:.3f}")
    print(f"recall   ={m['recall']:.3f}")
    print(f"F1       ={m['f1']:.3f}  [95% CI {lo:.3f}, {hi:.3f}]")
    print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
