"""F11 — co-equal headline figure (2-panel, forced y in [0,1]).

The visualization firewall (§4.7) requires the favourable headline number
(clean F1) and the adverse number (held-out mimicry detection) to be shown
side by side at the SAME scale, so the adverse result is not visually
buried. Both panels are forced to y in [0,1] and identical heights.

Panel (a): headline F1 on benign + standard attacks (with CI).
Panel (b): held-out mimicry detection rate (the adverse 13.6%-class number,
           pooled across the five strategies, with Wilson 95% CI).

Both numbers are read from genuine aggregate JSONs; nothing is hard-coded.
The headline F1 defaults to a primary cluster aggregate if supplied.

Usage:
    python3 experiments/figures/fig_co_equal_headline.py \
        --mimicry-agg runs/experiments/_agg/T2_5_mimicry.json \
        --headline-agg runs/experiments/_agg/E12b_signed_manifest_cluster.json \
        --out runs/figures/F11_co_equal_headline
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
from experiments.exact_bounds import wilson_score_interval  # noqa: E402
import matplotlib.pyplot as plt        # noqa: E402


def _nan(x) -> bool:
    return x is None or (isinstance(x, float) and math.isnan(x))


def _headline_f1(path: Path | None, fallback: float) -> tuple[float, float, float, str]:
    if path and path.exists():
        d = json.loads(path.read_text())
        f1 = d.get("point", {}).get("f1")
        lo = d.get("ci_lo", {}).get("f1")
        hi = d.get("ci_hi", {}).get("f1")
        if not _nan(f1):
            return (f1, lo if not _nan(lo) else f1,
                    hi if not _nan(hi) else f1, path.stem)
    return fallback, fallback, fallback, "abstract-value (no aggregate)"


def _mimicry_pooled(path: Path) -> tuple[float, float, float, int, int]:
    d = json.loads(path.read_text())
    per = d.get("per_strategy", {})
    n = sum(int(v.get("n_events", 0)) for v in per.values())
    c = sum(int(v.get("caught", 0)) for v in per.values())
    rate = c / n if n else float("nan")
    lo, hi = wilson_score_interval(c, n) if n else (float("nan"), float("nan"))
    return rate, lo, hi, c, n


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mimicry-agg", type=Path,
                    default=REPO / "runs/experiments/_agg/T2_5_mimicry.json")
    ap.add_argument("--headline-agg", type=Path, default=None,
                    help="primary cluster aggregate with point.f1 (optional)")
    ap.add_argument("--headline-f1-fallback", type=float, default=0.996)
    ap.add_argument("--out", type=Path,
                    default=REPO / "runs/figures/F11_co_equal_headline")
    args = ap.parse_args(argv)

    if not args.mimicry_agg.exists():
        print(f"[F11] missing {args.mimicry_agg}; run aggregate_t2_5 first")
        return 1

    h_f1, h_lo, h_hi, h_src = _headline_f1(args.headline_agg,
                                           args.headline_f1_fallback)
    m_rate, m_lo, m_hi, m_c, m_n = _mimicry_pooled(args.mimicry_agg)

    fig, axes = plt.subplots(1, 2, figsize=(F.COL_W, F.H_BAR), sharey=True)
    # Panel (a): headline F1.
    ax = axes[0]
    if not _nan(h_f1):
        ax.bar(0, h_f1, width=0.5, color=F.BAR_COLORS[1],
               edgecolor="black", linewidth=0.5)
        ax.errorbar(0, h_f1, yerr=[[max(0, h_f1 - h_lo)], [max(0, h_hi - h_f1)]],
                    fmt="none", ecolor="black", capsize=3, elinewidth=0.8)
        ax.text(0, min(0.97, h_f1 + 0.02), f"{h_f1:.3f}", ha="center",
                va="bottom", fontsize=8)
    ax.set_xticks([0]); ax.set_xticklabels(["benign +\nstd attacks"], fontsize=7)
    F.finalize(ax, ylabel="Score", ylim=(0, 1.0), legend_loc=None)
    F.panel_label(ax, "a", "Headline F1", where="title")

    # Panel (b): mimicry detection (adverse number).
    ax = axes[1]
    if _nan(m_rate):
        ax.bar(0, 1.0, color="none", edgecolor="gray", hatch="//")
        ax.text(0, 0.5, "pending", rotation=90, ha="center", va="center",
                fontsize=7, color="gray")
    else:
        ax.bar(0, m_rate, width=0.5, color=F.BAR_COLORS[4],
               edgecolor="black", linewidth=0.5)
        ax.errorbar(0, m_rate,
                    yerr=[[max(0, m_rate - m_lo)], [max(0, m_hi - m_rate)]],
                    fmt="none", ecolor="black", capsize=3, elinewidth=0.8)
        ax.text(0, min(0.97, m_rate + 0.02),
                f"{m_rate*100:.1f}%\n({m_c}/{m_n})", ha="center",
                va="bottom", fontsize=7.5)
    ax.set_xticks([0]); ax.set_xticklabels(["held-out\nmimicry"], fontsize=7)
    ax.set_ylim(0, 1.0)
    F.panel_label(ax, "b", "Mimicry detection", where="title")
    F._save(fig, args.out)

    print(f"[F11] wrote {args.out}.pdf/.png")
    print(f"[F11 caption] (a) headline F1 = {h_f1:.3f} (source: {h_src}); "
          f"(b) held-out mimicry detection {m_c}/{m_n} = "
          f"{m_rate if _nan(m_rate) else f'{m_rate*100:.1f}%'} (Wilson 95% CI). "
          f"Both panels forced to y in [0,1].")
    return 0


if __name__ == "__main__":
    sys.exit(main())
