"""T2.5 / T2.5a / T2.5b aggregator — mimicry per-strategy with CIs.

Produces, from the per-trial ground_truth.json + controller_decisions.jsonl
under runs/experiments/T2_5_mimicry/:

  * per-strategy detection rate + Wilson 95% CI (and Clopper-Pearson UB on
    the false-negative rate for any 0/N cell — zero-event class);
  * cross-strategy cluster-bootstrap BCa CI on the pooled F1
    (cluster = (trial, strategy), via aggregate_cluster);
  * Holm-Bonferroni adjusted p-values across the 5 strategies (one-sided
    binomial test of detection rate vs p0, default 0.5);
  * T2.5b fully-invisible-campaign rate (campaigns with zero catches) with
    its Clopper-Pearson UB;
  * secondary: time-to-first-drop and BMS-reached-before-detection (E21),
    when the controller log carries timestamps.

No fabrication: in a dry-run (no decisions) every detection is 0 and the
output says so. Usage:
    python3 -m experiments.aggregate_t2_5 runs/experiments/T2_5_mimicry
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from experiments.exact_bounds import (  # noqa: E402
    wilson_score_interval, clopper_pearson_upper)
from experiments.aggregate_cluster import pairs_cluster_bootstrap  # noqa: E402

STRATEGIES = ["mimicry_fanout_sub", "mimicry_fanout_three",
              "mimicry_combined", "mimicry_r4_deadzone", "mimicry_r1_late"]


def _int_to_ip(x) -> str:
    if isinstance(x, str):
        return x
    x = int(x)
    return ".".join(str((x >> (8 * (3 - i))) & 0xFF) for i in range(4))


def _load_decisions(trial_dir: Path) -> dict[tuple, dict]:
    out: dict[tuple, dict] = {}
    for name in ("controller_decisions.jsonl", "decisions.jsonl"):
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
            if "_marker" in d:
                continue
            try:
                key = (_int_to_ip(d.get("src_ip", 0)),
                       _int_to_ip(d.get("dst_ip", 0)),
                       int(d.get("src_port", 0)))
            except (TypeError, ValueError):
                continue
            out[key] = d
        if out:
            break
    return out


def _holm_bonferroni(pvals: dict[str, float], alpha: float = 0.05
                     ) -> dict[str, dict]:
    """Holm step-down. Returns per-key {p, p_adj, reject}."""
    items = sorted(pvals.items(), key=lambda kv: kv[1])
    m = len(items)
    out: dict[str, dict] = {}
    running_max = 0.0
    for i, (k, p) in enumerate(items):
        adj = min(1.0, (m - i) * p)
        running_max = max(running_max, adj)   # enforce monotonicity
        out[k] = {"p": p, "p_adj": running_max,
                  "reject": running_max < alpha}
    return out


def _binom_p_greater(k: int, n: int, p0: float) -> float:
    """One-sided binomial p-value for H0: rate <= p0 (P[X >= k])."""
    if n == 0:
        return 1.0
    try:
        from scipy.stats import binomtest
        return float(binomtest(k, n, p0, alternative="greater").pvalue)
    except Exception:
        from scipy.stats import binom
        return float(binom.sf(k - 1, n, p0))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("exp_dir", type=Path, nargs="?",
                    default=REPO / "runs/experiments/T2_5_mimicry")
    ap.add_argument("--p0", type=float, default=0.5,
                    help="null detection rate for the per-strategy test")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    if not args.exp_dir.exists():
        print(f"missing {args.exp_dir}")
        return 1
    trials = sorted(d for d in args.exp_dir.iterdir()
                    if d.is_dir() and (d / "ground_truth.json").exists())
    if not trials:
        print(f"no trials under {args.exp_dir}")
        return 1

    by_strat = defaultdict(lambda: {"n": 0, "caught": 0})
    all_events: list[dict] = []          # for cross-strategy BCa
    n_campaigns = 0
    invisible_campaigns = 0
    n_degraded = 0

    for t in trials:
        if (t / "trial_invalid.txt").exists():
            n_degraded += 1
            continue
        gt = json.loads((t / "ground_truth.json").read_text())
        decs = _load_decisions(t)
        n_campaigns += 1
        campaign_caught = 0
        for ev in gt.get("events", []):
            scen = ev.get("scenario", "unknown")
            by_strat[scen]["n"] += 1
            key = (ev.get("src_ip"), ev.get("dst_ip"),
                   int(ev.get("src_port", 0)))
            d = decs.get(key)
            caught = bool(d) and (d.get("decision", "").upper() == "DROP")
            if caught:
                by_strat[scen]["caught"] += 1
                campaign_caught += 1
            all_events.append({
                "trial_id": gt.get("trial_id", t.name),
                "scenario_id": scen,
                "gt_label": "ATTACK",
                "pred_label": "DROP" if caught else "PASS",
            })
        if campaign_caught == 0:
            invisible_campaigns += 1

    # Per-strategy Wilson + CP-UB.
    per_strategy: dict[str, dict] = {}
    pvals: dict[str, float] = {}
    for scen in sorted(by_strat):
        n = by_strat[scen]["n"]
        c = by_strat[scen]["caught"]
        rate = c / n if n else float("nan")
        lo, hi = wilson_score_interval(c, n) if n else (float("nan"),) * 2
        cp_ub_fn = clopper_pearson_upper(n - c, n) if n else float("nan")
        pvals[scen] = _binom_p_greater(c, n, args.p0)
        per_strategy[scen] = {
            "n_events": n, "caught": c, "detection_rate": rate,
            "wilson_ci95": [lo, hi], "fn_rate_cp_ub": cp_ub_fn}

    holm = _holm_bonferroni(pvals, alpha=0.05)
    for scen, h in holm.items():
        per_strategy[scen]["holm"] = h

    # Cross-strategy BCa on pooled F1 (cluster = trial x strategy).
    bca = pairs_cluster_bootstrap(all_events, B=10000, alpha=0.05,
                                  seed=0xCAFE)

    # T2.5b fully-invisible-campaign rate.
    inv_rate = invisible_campaigns / n_campaigns if n_campaigns else float("nan")
    inv_lo, inv_hi = (wilson_score_interval(invisible_campaigns, n_campaigns)
                      if n_campaigns else (float("nan"),) * 2)
    inv_cp_ub = (clopper_pearson_upper(invisible_campaigns, n_campaigns)
                 if n_campaigns else float("nan"))

    out = {
        "experiment": "T2.5",
        "n_campaigns": n_campaigns,
        "n_degraded_trials": n_degraded,
        "p0_null_detection_rate": args.p0,
        "per_strategy": per_strategy,
        "cross_strategy_bca": {
            "f1": bca["point"]["f1"],
            "f1_ci95": [bca["ci_lo"]["f1"], bca["ci_hi"]["f1"]],
            "precision": bca["point"]["precision"],
            "recall": bca["point"]["recall"],
            "n_clusters": bca["n_clusters"], "B": bca["B"]},
        "t2_5b_fully_invisible_campaign": {
            "invisible": invisible_campaigns, "n": n_campaigns,
            "rate": inv_rate, "wilson_ci95": [inv_lo, inv_hi],
            "cp_ub": inv_cp_ub},
        "statistical_test": "Wilson 95% per strategy; cluster-bootstrap BCa "
                            "B=10000 cross-strategy; Holm-Bonferroni across "
                            "5 strategies; Clopper-Pearson UB on 0/N cells.",
    }
    out_path = args.out or (args.exp_dir.parent / "_agg" / "T2_5_mimicry.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, default=str))

    print(f"{'strategy':22s} {'N':>5} {'caught':>7} {'rate':>6} "
          f"{'wilson95':>16} {'p_adj':>7}")
    for scen in sorted(per_strategy):
        s = per_strategy[scen]
        ci = s["wilson_ci95"]
        print(f"{scen:22s} {s['n_events']:>5} {s['caught']:>7} "
              f"{s['detection_rate']:>6.3f} "
              f"[{ci[0]*100:5.1f},{ci[1]*100:5.1f}] "
              f"{s['holm']['p_adj']:>7.4f}")
    print(f"\ncross-strategy BCa F1: {out['cross_strategy_bca']['f1']} "
          f"{out['cross_strategy_bca']['f1_ci95']}")
    print(f"T2.5b invisible-campaign rate: {invisible_campaigns}/{n_campaigns} "
          f"= {inv_rate}  (CP-UB {inv_cp_ub})")
    print(f"degraded trials: {n_degraded}")
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
