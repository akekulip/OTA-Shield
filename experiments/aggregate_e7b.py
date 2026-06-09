"""E7b aggregator — R1 false-trigger rate + R2/R4/R5/R6 attack metrics.

Reads one trial directory produced by `run_e7b.py`:

    <trial_dir>/
        ground_truth.json              # emitted by run_e7b.py
        decisions.jsonl                # switch digest slice (optional)
        controller_decisions.jsonl     # authoritative controller log

Emits two groups of numbers that feed the IJCIP-revision macros
`\\EsevenbIntervalPzeroOne` and `\\EsevenbRoneFPRate`:

1. Benign segment (R1 should be silent)
    * `r1_fp_count`   — benign events for which R1 bit was set
    * `r1_fp_rate`    — r1_fp_count / n_benign_events
    * `benign_interval_p0_1` — P0.1 of realized per-BMS intervals (s)

2. Attack segment (R2/R4/R5/R6 should catch everything)
    * per-rule hit counts restricted to attack events
    * precision / recall / F1 over PASS/DROP decisions

The script is intentionally decoupled from `aggregate.py` so the E7b
pipeline can run without touching the main experiment aggregator
(which scans every `runs/experiments/*` directory).
"""
from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter
from pathlib import Path


def ipv4_to_int(ip: str) -> int:
    """Pack a dotted-quad IP string into a 32-bit integer (matches the
    controller's on-wire endianness, same convention as aggregate.py)."""
    p = ip.split(".")
    return (int(p[0]) << 24) | (int(p[1]) << 16) | (int(p[2]) << 8) | int(p[3])


def _percentile(vals: list[float], q: float) -> float:
    """Numpy-free percentile helper (keeps this script dependency-light
    so it can also run on the switch host if needed)."""
    if not vals:
        return float("nan")
    s = sorted(vals)
    if len(s) == 1:
        return float(s[0])
    k = (len(s) - 1) * (q / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    frac = k - lo
    return s[lo] * (1 - frac) + s[hi] * frac


def _load_controller_decisions(trial_dir: Path) -> dict:
    """Key controller decisions by full 5-tuple, same convention as
    `aggregate.load_trial`."""
    path = trial_dir / "controller_decisions.jsonl"
    out: dict = {}
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "_marker" in d:
            continue
        key = (int(d["src_ip"]), int(d["dst_ip"]),
               int(d["src_port"]),
               int(d.get("dst_port", 1883)))
        out[key] = d
    return out


def _load_digest_decisions(trial_dir: Path) -> dict:
    """Same contract as `aggregate._dec_index` — keyed by 5-tuple, with
    hold_digest preferred over mqtt/classify digests if both appeared."""
    out: dict = {}
    for name in ("decisions.jsonl", "decisions_digest.jsonl"):
        p = trial_dir / name
        if not p.exists():
            continue
        for line in p.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            key = (int(d.get("src_ip", 0)),
                   int(d.get("dst_ip", 0)),
                   int(d.get("src_port", 0)),
                   int(d.get("dst_port", 1883)))
            prev = out.get(key)
            if (prev is None or
                    (d.get("_type") == "hold_digest"
                     and prev.get("_type") != "hold_digest")):
                out[key] = d
    return out


def _rules_for_event(ev: dict,
                     ctrl_index: dict,
                     dig_index: dict) -> tuple[list[str], str, str]:
    """Return ``(rules_fired, action, source)`` for one ground-truth
    event, mirroring the strict-mode logic in `aggregate.load_trial`.

    ``source`` is informational (``controller_log``, ``pipeline_no_fire``,
    or ``NO_DECISION``).
    """
    key = (ipv4_to_int(ev["src_ip"]),
           ipv4_to_int(ev["dst_ip"]),
           int(ev["src_port"]),
           int(ev.get("dst_port", 1883)))
    ctrl = ctrl_index.get(key)
    dig = dig_index.get(key)
    if ctrl is not None:
        return (list(ctrl.get("rules_fired", [])),
                str(ctrl.get("decision", "PASS")),
                "controller_log")
    if dig is None:
        return ([], "NO_DECISION", "NO_DECISION")
    # Digest present, no controller log.
    if dig.get("_type") == "hold_digest":
        # hold_digest without controller log is treated as NO_DECISION
        # (controller_log is authoritative for DROP/PASS).
        return ([], "NO_DECISION", "NO_DECISION")
    if ev["label"] == "ATTACK":
        # Attack events with only mqtt/classify digest are ambiguous —
        # match aggregate.py's conservative stance.
        return ([], "NO_DECISION", "NO_DECISION")
    return ([], "PASS", "pipeline_no_fire")


def _per_bms_intervals(benign_events: list[dict]) -> list[float]:
    """Realized per-BMS inter-update intervals in wall-clock seconds."""
    by_bms: dict[str, list[float]] = {}
    for ev in benign_events:
        by_bms.setdefault(ev["dst_ip"], []).append(float(ev["t_send"]))
    out: list[float] = []
    for lst in by_bms.values():
        lst.sort()
        for a, b in zip(lst[:-1], lst[1:]):
            out.append(b - a)
    return out


def aggregate_trial(trial_dir: Path) -> dict:
    """Compute the full E7b metric bundle for one trial directory."""
    gt_path = trial_dir / "ground_truth.json"
    if not gt_path.exists():
        raise FileNotFoundError(gt_path)
    gt = json.loads(gt_path.read_text())

    ctrl_index = _load_controller_decisions(trial_dir)
    dig_index = _load_digest_decisions(trial_dir)

    events: list[dict] = gt.get("events", [])
    benign = [e for e in events if e["label"] == "LEGIT"]
    attacks = [e for e in events if e["label"] == "ATTACK"]

    # ---- Benign segment: R1 false-trigger + interval distribution ----
    r1_fp = 0
    benign_rule_counter: Counter[str] = Counter()
    benign_no_decision = 0
    for ev in benign:
        rules, action, source = _rules_for_event(ev, ctrl_index, dig_index)
        if source == "NO_DECISION":
            benign_no_decision += 1
            continue
        for r in rules:
            benign_rule_counter[r] += 1
        if "R1" in rules:
            r1_fp += 1

    intervals = _per_bms_intervals(benign)

    # ---- Attack segment: per-rule coverage + precision/recall/F1 ----
    tp = fp = fn = tn = 0
    attack_rule_counter: Counter[str] = Counter()
    attack_no_decision = 0
    per_rule_catches: Counter[str] = Counter()
    for ev in attacks:
        rules, action, source = _rules_for_event(ev, ctrl_index, dig_index)
        if source == "NO_DECISION":
            attack_no_decision += 1
            continue
        for r in rules:
            attack_rule_counter[r] += 1
        if action == "DROP":
            tp += 1
            for r in rules:
                per_rule_catches[r] += 1
        else:
            fn += 1

    # Benign PASS/DROP → TN/FP for full-trial P/R/F1.
    for ev in benign:
        rules, action, source = _rules_for_event(ev, ctrl_index, dig_index)
        if source == "NO_DECISION":
            continue
        if action == "DROP":
            fp += 1
        else:
            tn += 1

    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = (2 * prec * rec / (prec + rec)
          if (prec + rec) and not (prec != prec or rec != rec)
          else float("nan"))

    n_benign_obs = len(benign) - benign_no_decision
    r1_fp_rate = r1_fp / n_benign_obs if n_benign_obs else float("nan")

    return {
        "trial_id": gt.get("trial_id"),
        "trial_dir": str(trial_dir),
        "n_events_total": len(events),
        "benign": {
            "n_total": len(benign),
            "n_observed": n_benign_obs,
            "n_no_decision": benign_no_decision,
            "r1_fp_count": r1_fp,
            "r1_fp_rate": r1_fp_rate,
            "rule_hits": dict(benign_rule_counter),
            "interval_s": {
                "n": len(intervals),
                "min": min(intervals) if intervals else float("nan"),
                "p0_1": _percentile(intervals, 0.1),
                "p1": _percentile(intervals, 1.0),
                "median": (statistics.median(intervals)
                           if intervals else float("nan")),
                "max": max(intervals) if intervals else float("nan"),
            },
        },
        "attack": {
            "n_total": len(attacks),
            "n_observed": len(attacks) - attack_no_decision,
            "n_no_decision": attack_no_decision,
            "tp": tp, "fn": fn,
            "rule_hits": dict(attack_rule_counter),
            "per_rule_catches": dict(per_rule_catches),
        },
        "overall": {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": prec, "recall": rec, "f1": f1,
        },
        "paper_macros_suggested": {
            # Paper macro is in seconds with one decimal place; the
            # authoring script renders the final formatting.
            "EsevenbIntervalPzeroOne": _percentile(intervals, 0.1),
            "EsevenbRoneFPRate": r1_fp_rate,
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--trial-dir", type=Path, required=True,
                    help="Trial directory with ground_truth.json + "
                         "controller_decisions.jsonl.")
    ap.add_argument("--out-json", type=Path,
                    default=None,
                    help="Output JSON path (default: "
                         "<trial-dir>/aggregate_e7b.json).")
    args = ap.parse_args()

    out = aggregate_trial(args.trial_dir)
    out_path = args.out_json or (args.trial_dir / "aggregate_e7b.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2))
    print(f"[E7b] wrote {out_path}")
    b = out["benign"]
    a = out["attack"]
    o = out["overall"]
    print(f"  R1 FP: {b['r1_fp_count']}/{b['n_observed']} "
          f"({b['r1_fp_rate']:.4f})")
    print(f"  benign interval P0.1 = "
          f"{b['interval_s']['p0_1']:.1f}s (tau_R1=14400s)")
    print(f"  attack TP={a['tp']} FN={a['fn']} "
          f"per-rule catches={a['per_rule_catches']}")
    print(f"  overall P={o['precision']:.3f} R={o['recall']:.3f} "
          f"F1={o['f1']:.3f}")


if __name__ == "__main__":
    main()
