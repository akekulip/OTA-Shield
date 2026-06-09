"""F13 — brokered MQTT: publisher-id keying vs IP-only collapse (T2.4).

Reads runs/experiments/_agg/T2_4_brokered.json and draws grouped bars of
precision / recall / F1 for the publisher-id-keyed RAT (E20) vs the IP-only
RAT negative control (E20a), which collapses because the broker hides the
true source IP. y is forced to [0,1].

Usage:
    python3 experiments/figures/fig_brokered_mqtt.py \
        --agg runs/experiments/_agg/T2_4_brokered.json \
        --out runs/figures/F13_brokered_mqtt
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


def _g(d: dict, k: str) -> float:
    v = d.get(k)
    return 0.0 if v is None or (isinstance(v, float) and math.isnan(v)) else v


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--agg", type=Path,
                    default=REPO / "runs/experiments/_agg/T2_4_brokered.json")
    ap.add_argument("--out", type=Path,
                    default=REPO / "runs/figures/F13_brokered_mqtt")
    args = ap.parse_args(argv)

    if not args.agg.exists():
        print(f"[F13] missing {args.agg}; run aggregate_t2_4 first")
        return 1
    data = json.loads(args.agg.read_text())
    pub = data.get("brokered_pubid_rat", {})
    ip = data.get("ip_rat_negative_control", {})

    metrics = ["precision", "recall", "f1"]
    pub_vals = [_g(pub, m) for m in metrics]
    ip_vals = [_g(ip, m) for m in metrics]

    fig, ax = plt.subplots(figsize=(F.COL_W, F.H_BAR))
    x = np.arange(len(metrics))
    w = 0.38
    ax.bar(x - w / 2, pub_vals, w, label="publisher-id RAT (E20)",
           color=F.BAR_COLORS[1], edgecolor="black", linewidth=0.5)
    ax.bar(x + w / 2, ip_vals, w, label="IP-only RAT (E20a control)",
           color=F.BAR_COLORS[4], edgecolor="black", linewidth=0.5)
    for i, v in enumerate(pub_vals):
        ax.text(i - w / 2, min(0.97, v + 0.02), f"{v:.2f}", ha="center",
                va="bottom", fontsize=6.5)
    for i, v in enumerate(ip_vals):
        ax.text(i + w / 2, min(0.97, v + 0.02), f"{v:.2f}", ha="center",
                va="bottom", fontsize=6.5)
    ax.set_xticks(x)
    ax.set_xticklabels(["Precision", "Recall", "F1"])
    F.finalize(ax, ylabel="Score", ylim=(0, 1.0), legend_loc="lower left")
    F._save(fig, args.out)

    tost = pub.get("tost_equivalent_to_direct")
    collapsed = data.get("negative_control_collapsed")
    print(f"[F13] wrote {args.out}.pdf/.png")
    print(f"[F13 caption] Brokered MQTT under publisher-id keying (E20) vs "
          f"IP-only control (E20a). pubid F1={pub.get('f1')} "
          f"CI={pub.get('f1_ci95')} TOST-eq-direct={tost}; control "
          f"collapsed={collapsed}. Source: {data.get('score_source')}. "
          f"paired cluster-bootstrap BCa B=10000.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
