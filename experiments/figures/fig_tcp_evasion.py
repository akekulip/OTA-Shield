"""F15 — TCP-evasion 5x5 detection heatmap (T2.8, Table 9).

Reads runs/experiments/_agg/T2_8_tcp_evasion.json and draws the observed
per-(evasion, rule) detection-rate heatmap. Each cell is annotated with the
observed rate and the predicted value in parentheses, so the figure doubles
as the predicted-vs-observed comparison the falsifier checks. Cells without
hardware data yet are drawn hatched ("pending"), never fabricated.

Usage:
    python3 experiments/figures/fig_tcp_evasion.py \
        --agg runs/experiments/_agg/T2_8_tcp_evasion.json \
        --out runs/figures/F15_tcp_evasion
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
import numpy as np                     # noqa: E402

EVASIONS = ["split_mqtt_fh", "split_topic", "split_ota_hdr",
            "retransmit_dup_ota", "out_of_order"]
RULES = ["R1", "R2", "R4", "R5", "R6"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--agg", type=Path,
                    default=REPO / "runs/experiments/_agg/T2_8_tcp_evasion.json")
    ap.add_argument("--out", type=Path,
                    default=REPO / "runs/figures/F15_tcp_evasion")
    args = ap.parse_args(argv)

    if not args.agg.exists():
        print(f"[F15] missing {args.agg}; run aggregate_t2_8 first")
        return 1
    data = json.loads(args.agg.read_text())
    cells = data.get("cells", {})

    obs = np.full((len(EVASIONS), len(RULES)), np.nan)
    pred = np.zeros((len(EVASIONS), len(RULES)))
    pending = np.zeros((len(EVASIONS), len(RULES)), dtype=bool)
    n_any = 0
    for i, ev in enumerate(EVASIONS):
        for j, r in enumerate(RULES):
            c = cells.get(f"{ev}|{r}", {})
            pred[i, j] = c.get("predicted_detect", 0)
            rate = c.get("observed_detect_rate")
            if rate is None or (isinstance(rate, float) and math.isnan(rate)) \
                    or c.get("n_trials", 0) == 0:
                pending[i, j] = True
            else:
                obs[i, j] = rate
                n_any += 1

    fig, ax = plt.subplots(figsize=(F.COL_W + 0.6, F.H_HIST))
    # Plot observed where available; mask NaN.
    masked = np.ma.masked_invalid(obs)
    im = ax.imshow(masked, cmap="viridis", vmin=0.0, vmax=1.0, aspect="auto")
    for i in range(len(EVASIONS)):
        for j in range(len(RULES)):
            if pending[i, j]:
                ax.add_patch(plt.Rectangle((j - 0.5, i - 0.5), 1, 1,
                             fill=True, facecolor="#dddddd", hatch="//",
                             edgecolor="white"))
                txt = f"·\n(p{int(pred[i, j])})"
                color = "gray"
            else:
                txt = f"{obs[i, j]:.2f}\n(p{int(pred[i, j])})"
                color = "white" if obs[i, j] < 0.55 else "black"
            ax.text(j, i, txt, ha="center", va="center", fontsize=6.5,
                    color=color)
    ax.set_xticks(range(len(RULES))); ax.set_xticklabels(RULES)
    ax.set_yticks(range(len(EVASIONS)))
    ax.set_yticklabels([e.replace("_", "\n") for e in EVASIONS], fontsize=7)
    ax.set_xlabel("Target rule"); ax.set_ylabel("Evasion")
    cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.set_label("Observed detection rate", fontsize=8)
    F._save(fig, args.out)

    print(f"[F15] wrote {args.out}.pdf/.png  ({n_any}/25 cells have HW data)")
    print(f"[F15 caption] TCP-evasion 5x5 detection heatmap (10 trials/cell, "
          f"250 total). Cell text: observed rate (predicted in parens). "
          f"Wilson 95% per cell, BH-FDR across 25 cells. "
          f"Falsifier triggered: {data.get('falsifier_triggered')}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
