"""F6 — mimicry per-strategy detection rate (T2.5 / E17b).

Reads runs/experiments/_agg/T2_5_mimicry.json and draws a per-strategy
detection-rate bar chart with Wilson 95% CI whiskers. Per the anti-
fabrication contract (§4), strategies with no events yet (NaN) are drawn
as hatched "pending" bars, never as a fabricated value.

Caption discipline (§4.8): trial count + statistical procedure are printed
to stdout so the figure caption can name them.

Usage:
    python3 experiments/figures/fig_adversary_per_strategy.py \
        --agg runs/experiments/_agg/T2_5_mimicry.json \
        --out runs/figures/F6_mimicry_per_strategy
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))

from experiments import figures as F  # noqa: E402
import matplotlib.pyplot as plt        # noqa: E402

DISPLAY = {
    "mimicry_fanout_sub": "fanout-sub\n(R5 @thr)",
    "mimicry_fanout_three": "fanout-3\n(R5 sub)",
    "mimicry_combined": "combined\n(R4+R5)",
    "mimicry_r4_deadzone": "R4 dead-zone",
    "mimicry_r1_late": "R1 late",
}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--agg", type=Path,
                    default=REPO / "runs/experiments/_agg/T2_5_mimicry.json")
    ap.add_argument("--out", type=Path,
                    default=REPO / "runs/figures/F6_mimicry_per_strategy")
    args = ap.parse_args(argv)

    if not args.agg.exists():
        print(f"[F6] missing aggregate {args.agg}; run aggregate_t2_5 first")
        return 1
    data = json.loads(args.agg.read_text())
    per = data.get("per_strategy", {})
    order = [s for s in DISPLAY if s in per] + \
            [s for s in per if s not in DISPLAY]

    names, rates, los, his, ns, pending = [], [], [], [], [], []
    for s in order:
        d = per[s]
        rate = d.get("detection_rate")
        ci = d.get("wilson_ci95", [None, None])
        n = d.get("n_events", 0)
        names.append(DISPLAY.get(s, s))
        ns.append(n)
        if rate is None or (isinstance(rate, float) and math.isnan(rate)):
            rates.append(0.0); los.append(0.0); his.append(0.0)
            pending.append(True)
        else:
            rates.append(rate)
            lo = ci[0] if ci and ci[0] is not None and not (
                isinstance(ci[0], float) and math.isnan(ci[0])) else rate
            hi = ci[1] if ci and ci[1] is not None and not (
                isinstance(ci[1], float) and math.isnan(ci[1])) else rate
            los.append(max(0.0, rate - lo)); his.append(max(0.0, hi - rate))
            pending.append(False)

    fig, ax = plt.subplots(figsize=(F.COL_W, F.H_BAR))
    x = range(len(names))
    for i in x:
        color = F.BAR_COLORS[i % len(F.BAR_COLORS)]
        if pending[i]:
            ax.bar(i, 1.0, color="none", edgecolor="gray", hatch="//",
                   linewidth=0.7)
            ax.text(i, 0.5, "pending", rotation=90, ha="center",
                    va="center", fontsize=7, color="gray")
        else:
            ax.bar(i, rates[i], color=color, edgecolor="black", linewidth=0.5)
            ax.errorbar(i, rates[i], yerr=[[los[i]], [his[i]]], fmt="none",
                        ecolor="black", capsize=2.5, elinewidth=0.8)
            ax.text(i, min(0.97, rates[i] + 0.03), f"n={ns[i]}",
                    ha="center", va="bottom", fontsize=6.5)
    ax.set_xticks(list(x))
    ax.set_xticklabels(names, fontsize=7)
    F.finalize(ax, ylabel="Detection rate", ylim=(0, 1.0), legend_loc=None)
    F._save(fig, args.out)

    n_camp = data.get("n_campaigns", 0)
    print(f"[F6] wrote {args.out}.pdf/.png")
    print(f"[F6 caption] Per-strategy detection rate over {n_camp} campaigns "
          f"(30 contracted); bars = Wilson 95% CI. "
          f"Cross-strategy BCa F1 = {data.get('cross_strategy_bca', {}).get('f1')}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
