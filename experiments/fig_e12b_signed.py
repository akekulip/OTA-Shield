"""Generator for fig_e12b_stale_rat.pdf (signed-manifest fail-safe edition).

E12b semantics after the 2026-04-20 signed-manifest redesign:
  * 21 trials = 1 validation warm-up + 20 scored trials.
  * Phase A (valid signed RAT):   150 benign events / trial -> 3150 total.
  * Phase B (sig tamper -> LKG):    8 events / trial       ->  168 total.
  * All events PASS; 0 FP, 0 DROP, 0 NO_DECISION.
Reads only from the aggregate JSON so numbers cannot drift from data.
Writes into paper/figures/ (both PDF + PNG, for parity with figures.py).

Usage:
    python3 experiments/fig_e12b_signed.py \
        --in runs/experiments/_agg/E12b_signed_manifest.json \
        --out paper/figures/fig_e12b_stale_rat.pdf
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np


# ---------- Publication style (cloned from experiments/figures.py) ----------
STYLE = {
    "font.family":           "serif",
    "font.serif":            ["Times New Roman", "Nimbus Roman No9 L",
                              "Liberation Serif", "DejaVu Serif"],
    "mathtext.fontset":      "stix",
    "font.size":             10,
    "axes.labelsize":        10,
    "axes.titlesize":        10,
    "xtick.labelsize":        9,
    "ytick.labelsize":        9,
    "legend.fontsize":        9,
    "legend.frameon":         True,
    "legend.framealpha":      1.0,
    "legend.edgecolor":       "gray",
    "legend.facecolor":       "white",
    "legend.fancybox":        False,
    "legend.borderpad":       0.3,
    "legend.handlelength":    1.6,
    "legend.handletextpad":   0.5,
    "legend.borderaxespad":   0.4,
    "axes.grid":              True,
    "grid.alpha":             0.3,
    "grid.linestyle":         ":",
    "grid.linewidth":         0.4,
    "axes.linewidth":         0.7,
    "xtick.major.width":      0.7,
    "ytick.major.width":      0.7,
    "xtick.minor.width":      0.5,
    "ytick.minor.width":      0.5,
    "xtick.direction":        "in",
    "ytick.direction":        "in",
    "xtick.top":              True,
    "ytick.right":            True,
    "lines.linewidth":        1.0,
    "lines.markersize":       4.5,
    "lines.markeredgewidth":  0.9,
    "figure.dpi":             200,
    "savefig.dpi":            600,
    "savefig.bbox":           "tight",
    "savefig.pad_inches":     0.02,
    "pdf.fonttype":           42,
    "ps.fonttype":            42,
    "axes.spines.top":        True,
    "axes.spines.right":      True,
    "axes.spines.left":       True,
    "axes.spines.bottom":     True,
}
mpl.rcParams.update(STYLE)

COL_W = 3.5      # single-column width (in)
H_BAR = 2.2      # slightly taller for annotation room

# PASS / DROP / NO_DECISION palette aligned with figures.py BAR_COLORS
#   PASS        = #59a14f (green, "good path")
#   DROP        = #d95f02 (orange, "attention")
#   NO_DECISION = #b07aa1 (mauve, "indeterminate")
DECISION_COLORS = {
    "PASS":         "#59a14f",
    "DROP":         "#d95f02",
    "NO_DECISION":  "#b07aa1",
}


def _load(agg_path: Path) -> dict:
    with agg_path.open() as f:
        return json.load(f)


def _extract_phase_totals(agg: dict) -> dict:
    """Re-derive Phase A / Phase B totals directly from `per_trial` so the
    figure is defensible against any top-level summary drift."""
    a_pass = a_drop = a_nd = 0
    b_pass = b_drop = b_nd = 0
    n_trials = 0
    for tr in agg.get("per_trial", []):
        pt = tr.get("phase_totals", {})
        A  = pt.get("A", {})
        B  = pt.get("B_lastgood", {})
        a_pass += int(A.get("pass", 0))
        a_drop += int(A.get("drop", 0)) + int(A.get("fp", 0))
        a_nd   += int(A.get("no_decision", 0))
        b_pass += int(B.get("pass", 0))
        b_drop += int(B.get("drop", 0)) + int(B.get("fp", 0))
        b_nd   += int(B.get("no_decision", 0))
        n_trials += 1
    return {
        "n_trials": n_trials,
        "A": {"pass": a_pass, "drop": a_drop, "no_decision": a_nd,
              "total": a_pass + a_drop + a_nd},
        "B": {"pass": b_pass, "drop": b_drop, "no_decision": b_nd,
              "total": b_pass + b_drop + b_nd},
    }


def _fmt_pct(n: int, total: int) -> str:
    if total == 0:
        return "0%"
    pct = 100.0 * n / total
    if pct == 100.0 or pct == 0.0:
        return f"{pct:.0f}%"
    return f"{pct:.1f}%"


def make_figure(totals: dict, out_pdf: Path) -> None:
    phases = [("A", "Phase A\nvalid signed RAT"),
              ("B", "Phase B\nsig tamper -> LKG")]
    decisions = ["PASS", "DROP", "NO_DECISION"]
    labels    = {"PASS": "PASS", "DROP": "DROP",
                 "NO_DECISION": "NO\\_DECISION"}

    fig, ax = plt.subplots(figsize=(COL_W, H_BAR))

    x = np.arange(len(phases))
    width = 0.55

    # Build a stacked bar per phase, normalized to 100% for shape; we
    # overlay absolute counts so the reader sees both forms.
    for i, (key, _lbl) in enumerate(phases):
        pdata = totals["A"] if key == "A" else totals["B"]
        tot = max(1, pdata["total"])
        bottom = 0.0
        for dkey in decisions:
            # map dict key
            if dkey == "PASS":
                n = pdata["pass"]
            elif dkey == "DROP":
                n = pdata["drop"]
            else:
                n = pdata["no_decision"]
            frac = 100.0 * n / tot
            if frac <= 0:
                continue
            ax.bar(x[i], frac, width,
                   bottom=bottom,
                   color=DECISION_COLORS[dkey],
                   edgecolor="black", linewidth=0.6,
                   label=labels[dkey] if i == 0 else None)
            # centre-label only for non-trivial slice
            if frac >= 6.0:
                ax.text(x[i], bottom + frac / 2.0,
                        f"{n}\n({_fmt_pct(n, tot)})",
                        ha="center", va="center", fontsize=7,
                        color="white" if dkey != "NO_DECISION" else "black")
            bottom += frac

        # N= annotation above each bar
        ax.text(x[i], 102.0, f"N={pdata['total']}",
                ha="center", va="bottom", fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels([lbl for _, lbl in phases])
    ax.set_ylabel("Share of events (%)")
    ax.set_ylim(0, 112)
    ax.set_yticks([0, 25, 50, 75, 100])

    # Subtle n_trials annotation (reproducibility anchor)
    ax.text(0.99, 0.02,
            f"{totals['n_trials']} trials",
            transform=ax.transAxes,
            ha="right", va="bottom", fontsize=7, color="#444444")

    # Legend above axes, horizontal
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.02),
              ncol=3, handlelength=1.2, frameon=False,
              borderaxespad=0.2)

    fig.tight_layout()
    out_pdf.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_pdf.with_suffix(".pdf"))
    fig.savefig(out_pdf.with_suffix(".png"))
    plt.close(fig)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--in", dest="agg_json",
                   default="runs/experiments/_agg/E12b_signed_manifest.json",
                   type=Path)
    p.add_argument("--out", dest="out",
                   default="paper/figures/fig_e12b_stale_rat.pdf",
                   type=Path)
    args = p.parse_args()

    agg = _load(args.agg_json)
    totals = _extract_phase_totals(agg)

    # Sanity: the newly computed totals must match the top-level summary.
    top_A = agg.get("phaseA", {})
    top_B = agg.get("phaseB_lastgood", {})
    assert totals["A"]["pass"] == top_A.get("pass", totals["A"]["pass"]), \
        "Phase A pass mismatch vs top-level summary"
    assert totals["B"]["pass"] == top_B.get("pass", totals["B"]["pass"]), \
        "Phase B pass mismatch vs top-level summary"

    print(f"[e12b fig] trials     = {totals['n_trials']}")
    print(f"[e12b fig] phase A    = {totals['A']}")
    print(f"[e12b fig] phase B    = {totals['B']}")
    print(f"[e12b fig] writing    -> {args.out}")

    make_figure(totals, args.out)
    print("[e12b fig] done.")


if __name__ == "__main__":
    main()
