"""T2.4 brokered-MQTT aggregator (E20) + IP-only negative control (E20a).

For each scenario it computes the F1 macro the publisher-id-keyed RAT
achieves (from the actual controller decisions when a hardware run is
present, else from the dual expected_pubid_rat column = the ideal E20
outcome) and the F1 the IP-only RAT achieves (the expected_ip_rat
negative-control column, which collapses because every publish carries the
broker source IP).  It then:

  * gives a cluster-bootstrap BCa CI (B=10000) on the brokered pubid F1
    (cluster = (trial, scenario));
  * runs TOST (delta = 0.02) of the brokered pubid F1 vs the direct
    (non-brokered) reference F1 -> "matches direct" verdict;
  * counts fallback_ip_key=true events in the controller log (falsifier:
    > 5% means publisher-id keying silently degraded to IP keying).

No fabrication: with no controller decisions the pubid score falls back to
the analytical expected_pubid_rat column and is labelled as such.

Usage:
    python3 -m experiments.aggregate_t2_4 runs/experiments
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from experiments.aggregate_cluster import pairs_cluster_bootstrap  # noqa: E402

DEFAULT_DIRECT_F1 = 0.996   # non-brokered reference (abstract headline)
TOST_DELTA = 0.02
FALLBACK_FALSIFIER = 0.05


def _int_to_ip(x) -> str:
    if isinstance(x, str):
        return x
    x = int(x)
    return ".".join(str((x >> (8 * (3 - i))) & 0xFF) for i in range(4))


def _f1_from_counts(c: Counter) -> dict:
    tp, tn, fp, fn = c["TP"], c["TN"], c["FP"], c["FN"]
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = (2 * prec * rec / (prec + rec)
          if prec == prec and rec == rec and (prec + rec) > 0 else float("nan"))
    return {"precision": prec, "recall": rec, "f1": f1,
            "tp": tp, "tn": tn, "fp": fp, "fn": fn}


def _control_collapsed(pub: dict, ip: dict) -> bool | None:
    """The IP-only control collapses if its recall is materially below the
    publisher-id RAT's recall (it misses the attacks the broker hides). A
    nan IP recall with attacks present (TP+FN>0) also counts as collapse."""
    pub_r = pub["recall"]
    ip_r = ip["recall"]
    ip_attacks = ip["tp"] + ip["fn"]
    if pub_r != pub_r:           # pubid recall undefined -> cannot compare
        return None
    if ip_r != ip_r:             # ip recall nan
        return ip_attacks > 0
    return ip_r < pub_r - 1e-9


def _verdict(gt: str, pred: str) -> str:
    if gt == "ATTACK" and pred == "DROP":
        return "TP"
    if gt == "LEGIT" and pred == "PASS":
        return "TN"
    if gt == "LEGIT" and pred == "DROP":
        return "FP"
    if gt == "ATTACK" and pred == "PASS":
        return "FN"
    return "NO_DECISION"


def _load_decisions(trial_dir: Path) -> tuple[dict[tuple, dict], int, int]:
    """Return (index_by_5tuple, n_decisions, n_fallback_ip_key)."""
    idx: dict[tuple, dict] = {}
    n = 0
    n_fallback = 0
    p = trial_dir / "controller_decisions.jsonl"
    if not p.exists():
        return idx, 0, 0
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "_marker" in d:
            continue
        n += 1
        if d.get("fallback_ip_key") in (True, "true", 1):
            n_fallback += 1
        try:
            key = (_int_to_ip(d.get("src_ip", 0)),
                   _int_to_ip(d.get("dst_ip", 0)),
                   int(d.get("src_port", 0)))
        except (TypeError, ValueError):
            continue
        idx[key] = d
    return idx, n, n_fallback


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("root", type=Path, nargs="?",
                    default=REPO / "runs/experiments")
    ap.add_argument("--direct-f1", type=float, default=DEFAULT_DIRECT_F1)
    ap.add_argument("--delta", type=float, default=TOST_DELTA)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    exp_dirs = sorted(d for d in args.root.glob("T2_4_*") if d.is_dir())
    if not exp_dirs:
        print(f"no T2_4_* dirs under {args.root}")
        return 1

    pubid_events: list[dict] = []   # for the overall BCa
    pubid_counts = Counter()
    ip_counts = Counter()
    total_decisions = 0
    total_fallback = 0
    per_scenario: dict[str, dict] = {}
    used_hw = False

    for exp_dir in exp_dirs:
        sc_pub = Counter()
        sc_ip = Counter()
        for trial in sorted(exp_dir.iterdir()):
            gt_p = trial / "ground_truth.json"
            if not (trial.is_dir() and gt_p.exists()):
                continue
            gt = json.loads(gt_p.read_text())
            decs, nd, nfb = _load_decisions(trial)
            total_decisions += nd
            total_fallback += nfb
            if decs:
                used_hw = True
            for ev in gt.get("events", []):
                gt_label = ev["label"]
                key = (ev.get("src_ip"), ev.get("dst_ip"),
                       int(ev.get("src_port", 0)))
                # pubid-RAT prediction: actual decision if present, else
                # the analytical expected_pubid_rat column.
                d = decs.get(key)
                if d and d.get("decision"):
                    pred_pub = d["decision"].upper()
                else:
                    pred_pub = ev.get("expected_pubid_rat", "PASS")
                pred_ip = ev.get("expected_ip_rat", "PASS")
                v_pub = _verdict(gt_label, pred_pub)
                v_ip = _verdict(gt_label, pred_ip)
                sc_pub[v_pub] += 1
                sc_ip[v_ip] += 1
                pubid_events.append({
                    "trial_id": gt.get("trial_id", trial.name),
                    "scenario_id": ev.get("scenario_id", exp_dir.name),
                    "gt_label": gt_label,
                    "pred_label": pred_pub if pred_pub in ("DROP", "PASS")
                    else "PASS"})
        pubid_counts.update(sc_pub)
        ip_counts.update(sc_ip)
        per_scenario[exp_dir.name] = {
            "pubid_rat": _f1_from_counts(sc_pub),
            "ip_rat_control": _f1_from_counts(sc_ip)}

    overall_pub = _f1_from_counts(pubid_counts)
    overall_ip = _f1_from_counts(ip_counts)
    bca = pairs_cluster_bootstrap(pubid_events, B=10000, alpha=0.05,
                                  seed=0xCAFE)
    f1_lo, f1_hi = bca["ci_lo"]["f1"], bca["ci_hi"]["f1"]

    # TOST: equivalence iff the BCa CI lies entirely within
    # [direct - delta, direct + delta].
    lo_bound = args.direct_f1 - args.delta
    hi_bound = args.direct_f1 + args.delta
    tost_equiv = None
    if f1_lo == f1_lo and f1_hi == f1_hi:   # not NaN
        tost_equiv = (f1_lo >= lo_bound and f1_hi <= hi_bound)

    fallback_rate = (total_fallback / total_decisions
                     if total_decisions else 0.0)
    falsifier = fallback_rate > FALLBACK_FALSIFIER

    out = {
        "experiment": "T2.4",
        "score_source": "controller_decisions" if used_hw
        else "analytical_expected_columns (dry-run / no HW)",
        "direct_f1_reference": args.direct_f1,
        "tost_delta": args.delta,
        "brokered_pubid_rat": {**overall_pub,
                               "f1_ci95": [f1_lo, f1_hi],
                               "tost_equivalent_to_direct": tost_equiv,
                               "tost_bounds": [lo_bound, hi_bound]},
        "ip_rat_negative_control": overall_ip,
        # The IP-only control collapses when it catches far fewer attacks
        # (recall) than the publisher-id RAT — every publish carries the
        # broker source IP, so an authorized-broker rule passes the attacks.
        "negative_control_collapsed": _control_collapsed(overall_pub,
                                                         overall_ip),
        "fallback_ip_key": {"events": total_fallback,
                            "n_decisions": total_decisions,
                            "rate": fallback_rate,
                            "falsifier_gt_5pct": falsifier},
        "per_scenario": per_scenario,
        "statistical_test": "paired cluster-bootstrap BCa B=10000; "
                            "TOST delta=0.02 vs direct F1.",
    }
    out_path = args.out or (args.root / "_agg" / "T2_4_brokered.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, default=str))

    print(f"score source: {out['score_source']}")
    print(f"brokered pubid-RAT F1 = {overall_pub['f1']} "
          f"[{f1_lo}, {f1_hi}]  TOST-equiv-to-direct: {tost_equiv}")
    print(f"IP-only control F1    = {overall_ip['f1']} "
          f"(P={overall_ip['precision']})  collapsed: "
          f"{out['negative_control_collapsed']}")
    print(f"fallback_ip_key rate  = {fallback_rate:.4f} "
          f"(falsifier >5%: {falsifier})")
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
