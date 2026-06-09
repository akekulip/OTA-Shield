"""T2.8 TCP-evasion aggregator — predicted-vs-observed detection heatmap.

For each of the 25 (evasion, rule) cells it computes the observed
detection rate (DROP / trials) with a Wilson 95% CI, compares it to the
predicted heatmap (traffic_gen.tcp_evasion.PREDICTED), runs a two-sided
binomial test of observed vs predicted with Benjamini-Hochberg FDR control
across the 25 cells, and evaluates the falsifier (any cell where the
threat model predicted EVADED (0) but the system detected the attack via
an unexpected rule).

No fabrication: in a dry-run (no controller decision slices) observed
detection is 0 for every cell and the output says so.

Usage:
    python3 -m experiments.aggregate_t2_8 runs/experiments
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from experiments.exact_bounds import (  # noqa: E402
    wilson_score_interval, clopper_pearson_upper)
from traffic_gen.tcp_evasion import EVASIONS, RULES, PREDICTED  # noqa: E402


def _int_to_ip(x) -> str:
    if isinstance(x, str):
        return x
    x = int(x)
    return ".".join(str((x >> (8 * (3 - i))) & 0xFF) for i in range(4))


def _load_decision_index(root: Path) -> dict[tuple, dict]:
    """Index every controller decision slice by (src_ip, dst_ip, src_port)."""
    idx: dict[tuple, dict] = {}
    slice_dir = root / "T2_8_slices"
    if not slice_dir.exists():
        return idx
    for p in sorted(slice_dir.glob("*.jsonl")):
        for line in p.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            try:
                key = (_int_to_ip(d.get("src_ip", 0)),
                       _int_to_ip(d.get("dst_ip", 0)),
                       int(d.get("src_port", 0)))
            except (TypeError, ValueError):
                continue
            idx[key] = d
    return idx


def _binom_two_sided(k: int, n: int, p0: float) -> float:
    if n == 0:
        return 1.0
    p0 = min(max(p0, 0.01), 0.99)
    try:
        from scipy.stats import binomtest
        return float(binomtest(k, n, p0, alternative="two-sided").pvalue)
    except Exception:
        from scipy.stats import binom
        # symmetric tail approximation
        from math import isclose
        mean = n * p0
        if k >= mean:
            return float(min(1.0, 2 * binom.sf(k - 1, n, p0)))
        return float(min(1.0, 2 * binom.cdf(k, n, p0)))


def _bh_fdr(pvals: dict[tuple, float], alpha: float = 0.05) -> dict[tuple, dict]:
    items = sorted(pvals.items(), key=lambda kv: kv[1])
    m = len(items)
    out: dict[tuple, dict] = {}
    # BH adjusted q-values (monotone from the largest down).
    prev_q = 1.0
    for rank in range(m, 0, -1):
        k, p = items[rank - 1]
        q = min(prev_q, p * m / rank)
        prev_q = q
        out[k] = {"p": p, "q": q, "reject": q < alpha}
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("root", type=Path, nargs="?",
                    default=REPO / "runs/experiments")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    dec_idx = _load_decision_index(args.root)
    cells: dict[str, dict] = {}
    pvals: dict[tuple, float] = {}
    falsifier_hits: list[str] = []

    for ev in EVASIONS:
        for rule in RULES:
            exp_dir = args.root / f"T2_8_{ev}_{rule}"
            n = caught = 0
            if exp_dir.exists():
                for trial in sorted(exp_dir.iterdir()):
                    gt_p = trial / "ground_truth.json"
                    if not (trial.is_dir() and gt_p.exists()):
                        continue
                    gt = json.loads(gt_p.read_text())
                    evs = gt.get("events", [])
                    if not evs:
                        continue
                    e0 = evs[0]
                    n += 1
                    key = (e0.get("src_ip"), e0.get("dst_ip"),
                           int(e0.get("src_port", 0)))
                    d = dec_idx.get(key)
                    if d and d.get("decision", "").upper() == "DROP":
                        caught += 1
            pred = PREDICTED[ev][rule]
            rate = caught / n if n else float("nan")
            lo, hi = wilson_score_interval(caught, n) if n else (float("nan"),) * 2
            cp_ub = clopper_pearson_upper(caught, n) if n else float("nan")
            ckey = (ev, rule)
            pvals[ckey] = _binom_two_sided(caught, n, float(pred))
            cell = {"evasion": ev, "rule": rule, "n_trials": n,
                    "caught": caught, "observed_detect_rate": rate,
                    "wilson_ci95": [lo, hi], "cp_ub": cp_ub,
                    "predicted_detect": pred}
            # Falsifier: predicted EVADED (0) but observed detection > 0.
            if pred == 0 and caught > 0:
                falsifier_hits.append(f"{ev} x {rule} ({caught}/{n})")
            cells[f"{ev}|{rule}"] = cell

    bh = _bh_fdr(pvals)
    for ckey, info in bh.items():
        cells[f"{ckey[0]}|{ckey[1]}"]["bh"] = info

    out = {
        "experiment": "T2.8",
        "n_cells": len(cells),
        "predicted_heatmap": PREDICTED,
        "cells": cells,
        "falsifier_triggered": bool(falsifier_hits),
        "falsifier_hits": falsifier_hits,
        "statistical_test": "Wilson 95% per cell; two-sided binomial vs "
                            "predicted with BH-FDR across 25 cells; "
                            "Clopper-Pearson UB on zero-event cells.",
    }
    out_path = args.out or (args.root / "_agg" / "T2_8_tcp_evasion.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, default=str))

    # Print the observed heatmap (and predicted alongside).
    print("observed detection rate (predicted in parens):")
    print("           " + " ".join(f"{r:>10}" for r in RULES))
    for ev in EVASIONS:
        row = []
        for r in RULES:
            c = cells[f"{ev}|{r}"]
            rate = c["observed_detect_rate"]
            rate_s = "nan" if rate != rate else f"{rate:.2f}"
            row.append(f"{rate_s}({c['predicted_detect']})")
        print(f"  {ev:<18} " + " ".join(f"{x:>10}" for x in row))
    print(f"\nfalsifier_triggered: {out['falsifier_triggered']} "
          f"{out['falsifier_hits']}")
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
