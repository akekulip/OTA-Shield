"""Regenerate fig_suricata_vs_ours with a 4th symmetric-comparison panel.

Panel layout (4 columns, 1 row):
  (a) Precision  — 7 systems on E1 PCAP, 90 events (asymmetric)
  (b) Recall     — same
  (c) Accuracy   — same
  (d) Symmetric  — Suricata-perm vs OTA-Shield on E8 1800 events:
                   3 metric groups (P / R / F1), 2 bars each

Data sources (all genuine, on-disk):
  runs/baseline_suricata/comparison.json              — Suricata minimal (variant i)
  runs/baseline_suricata_stateful/comparison.json     — Suricata stateful
  runs/baseline_suricata_stateful_permissive/...      — Suricata perm (best recall)
  runs/baseline_zeek/comparison.json                  — Zeek domain-aware
  runs/baseline_suricata/suricata_rat_comparison.json — Suricata+RAT (M7)
  runs/baseline_suricata_stateful_permissive/suricata_rat_perm_comparison.json
  runs/experiments/_agg/E1_attack_detection.json      — OTA-Shield (E1, asymmetric panels)
  runs/experiments/_agg/E8_stochastic.json            — OTA-Shield (E8, symmetric panel)
  runs/baseline_suricata_symmetric_2026-06-06/aggregate.json  — Suricata perm on E8 population
"""
from __future__ import annotations
import json, math, sys
from pathlib import Path

# ── paths ──────────────────────────────────────────────────────────────────
REPO = Path("/home/philip/Projects/OTA-Shield/OTA/ota_shield")
sys.path.insert(0, str(REPO / "experiments"))

from figures import (
    STYLE, COL2_W, H_BAR, BAR_COLORS, LINE_STYLES,
    panel_label, _save,
)
import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
mpl.rcParams.update(STYLE)

OUT_DIR = REPO / "paper" / "figures"
OUT_NAME = OUT_DIR / "fig_suricata_vs_ours"

# ── load all data ───────────────────────────────────────────────────────────
def _load(p: Path) -> dict | None:
    if p.exists():
        return json.loads(p.read_text())
    print(f"[WARN] missing: {p}", file=sys.stderr)
    return None

runs = REPO / "runs"
sur_min        = _load(runs / "baseline_suricata" / "comparison.json")
sur_stat       = _load(runs / "baseline_suricata_stateful" / "comparison.json")
sur_perm       = _load(runs / "baseline_suricata_stateful_permissive" / "comparison.json")
zeek           = _load(runs / "baseline_zeek" / "comparison.json")
sur_rat        = _load(runs / "baseline_suricata" / "suricata_rat_comparison.json")
sur_perm_rat   = _load(runs / "baseline_suricata_stateful_permissive"
                           / "suricata_rat_perm_comparison.json")
e1_agg_raw     = _load(runs / "experiments" / "_agg" / "E1_attack_detection.json")
e8_agg_raw     = _load(runs / "experiments" / "_agg" / "E8_stochastic.json")
sym_sur        = _load(runs / "baseline_suricata_symmetric_2026-06-06" / "aggregate.json")

# OTA-Shield E1 mean stats (asymmetric panels a/b/c)
def _mean(agg: dict, key: str) -> float:
    v = agg.get("aggregate", {}).get(key, {}).get("mean", float("nan"))
    return float(v)

our_e1_p = _mean(e1_agg_raw, "precision")
our_e1_r = _mean(e1_agg_raw, "recall")
our_e1_a = _mean(e1_agg_raw, "accuracy")

# OTA-Shield E8 mean stats (symmetric panel d)
our_e8_p = _mean(e8_agg_raw, "precision")    # 1.000
our_e8_r = _mean(e8_agg_raw, "recall")       # 0.992
our_e8_f = _mean(e8_agg_raw, "f1")           # 0.996

# Suricata-perm symmetric stats (panel d)
def _sym_val(key: str) -> float:
    ap = sym_sur.get("aggregate_pooled", {})
    return float(ap.get(key, float("nan")))

sym_p  = _sym_val("precision")   # 0.6667
sym_r  = _sym_val("recall")      # 1.000
sym_f  = _sym_val("f1")          # 0.800

# ── helper ──────────────────────────────────────────────────────────────────
def _pr(d: dict | None, key: str) -> float:
    if d is None:
        return float("nan")
    v = d.get(key)
    return float(v) if v is not None else float("nan")

def _nan_to_zero(v: float) -> float:
    return 0.0 if math.isnan(v) else v

# ── asymmetric rows (panels a/b/c) ─────────────────────────────────────────
rows: list[tuple[str, float, float, float]] = [
    ("OTA-Shield",           our_e1_r,          our_e1_p,          our_e1_a),
    ("Suricata min",         _pr(sur_min,  "recall"), _pr(sur_min,  "precision"), _pr(sur_min,  "accuracy")),
    ("Suricata stateful",    _pr(sur_stat, "recall"), _pr(sur_stat, "precision"), _pr(sur_stat, "accuracy")),
    ("Suricata perm",        _pr(sur_perm, "recall"), _pr(sur_perm, "precision"), _pr(sur_perm, "accuracy")),
    ("Zeek domain-aware",    _pr(zeek,     "recall"), _pr(zeek,     "precision"), _pr(zeek,     "accuracy")),
    ("Suricata +RAT",        _pr(sur_rat,     "recall"), _pr(sur_rat,     "precision"), _pr(sur_rat,     "accuracy")),
    ("Suricata perm+RAT",    _pr(sur_perm_rat,"recall"), _pr(sur_perm_rat,"precision"), _pr(sur_perm_rat,"accuracy")),
]

labels   = [r[0] for r in rows]
rec_vals = [r[1] for r in rows]
pre_vals = [r[2] for r in rows]
acc_vals = [r[3] for r in rows]

n = len(labels)
x = np.arange(n)
palette = [BAR_COLORS[i % len(BAR_COLORS)] for i in range(n)]

# ── figure layout ───────────────────────────────────────────────────────────
# 4 panels; panel d is narrower (only 2 systems, 3 metric groups)
fig, axes = plt.subplots(
    1, 4,
    figsize=(COL2_W * 1.35, H_BAR + 1.35),
    gridspec_kw={"width_ratios": [1.5, 1.5, 1.5, 1.1], "wspace": 0.26},
)
ax_p, ax_r, ax_a, ax_d = axes

# ── panels a/b/c: asymmetric 7-system comparison ────────────────────────────
def _draw_asymm(ax, vals, panel_letter, panel_title):
    plot_vals = [_nan_to_zero(v) for v in vals]
    ax.bar(x, plot_vals, width=0.62, color=palette, edgecolor="black", linewidth=0.6)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=35, ha="right", fontsize=6)
    for i, v in enumerate(vals):
        txt = "n/a" if math.isnan(v) else f"{v:.2f}"
        ypos = _nan_to_zero(v) + 0.02
        ax.text(i, ypos, txt, ha="center", va="bottom", fontsize=5.8)
    panel_label(ax, panel_letter, panel_title, where="xlabel")
    ax.set_ylim(0, 1.18)
    ax.grid(axis="y", alpha=0.3, linestyle=":", linewidth=0.4)
    ax.grid(axis="x", visible=False)

_draw_asymm(ax_p, pre_vals, "a", "Precision")
_draw_asymm(ax_r, rec_vals, "b", "Recall")
_draw_asymm(ax_a, acc_vals, "c", "Accuracy")
ax_p.set_ylabel("Score")

# ── panel d: symmetric comparison (E8, n=1,800) ─────────────────────────────
sym_metrics = ["P", "R", "F1"]
sym_ours    = [our_e8_p, our_e8_r, our_e8_f]
sym_sur_v   = [sym_p,    sym_r,    sym_f]

x_d   = np.arange(len(sym_metrics))
width = 0.35
c_ours  = BAR_COLORS[0]   # blue — OTA-Shield
c_suri  = BAR_COLORS[4]   # orange-red — Suricata perm

bars1 = ax_d.bar(x_d - width / 2, sym_ours,  width, color=c_ours,
                 edgecolor="black", linewidth=0.6, label="OTA-Shield (E8)")
bars2 = ax_d.bar(x_d + width / 2, sym_sur_v, width, color=c_suri,
                 edgecolor="black", linewidth=0.6, label="Suricata perm")

for bar, v in zip(list(bars1) + list(bars2),
                  sym_ours + sym_sur_v):
    ax_d.text(bar.get_x() + bar.get_width() / 2.0,
              v + 0.02, f"{v:.3f}",
              ha="center", va="bottom", fontsize=5.8)

ax_d.set_xticks(x_d)
ax_d.set_xticklabels(sym_metrics, fontsize=8)
ax_d.set_ylim(0, 1.18)
ax_d.set_ylabel("Score")
ax_d.legend(loc="lower left", fontsize=5.5, frameon=True,
            handlelength=1.2, borderpad=0.4)
ax_d.grid(axis="y", alpha=0.3, linestyle=":", linewidth=0.4)
ax_d.grid(axis="x", visible=False)

# Annotate "n=1,800" and "symmetric" label
ax_d.text(0.5, 1.09, "Symmetric (n=1,800)",
          transform=ax_d.transAxes,
          ha="center", va="bottom", fontsize=6.5,
          bbox=dict(boxstyle="round,pad=0.25", fc="#f0f0f0",
                    ec="#999999", linewidth=0.5))
panel_label(ax_d, "d", "P / R / F$_1$", where="xlabel")

fig.tight_layout()
_save(fig, OUT_NAME)
print(f"Wrote {OUT_NAME}.pdf and {OUT_NAME}.png")

# ── verification summary ─────────────────────────────────────────────────────
print()
print("=== Verification: panel d data vs paper macros ===")
print(f"OTA-Shield E8: P={our_e8_p:.3f} R={our_e8_r:.3f} F1={our_e8_f:.3f}")
print(f"Suricata perm (symmetric 1800): P={sym_p:.4f} R={sym_r:.4f} F1={sym_f:.4f}")
print("Paper macros (numbers_supplement.tex):")
print("  \\EtenSymPrecision 0.667  \\EtenSymRecall 1.000  \\EtenSymFOne 0.800")
print("  \\EEightstochasticPrecisionMean 1.000  \\EEightstochasticRecallMean 0.992  \\EEightstochasticFOneMean 0.996")
print()
print("=== Verification: panels a/b/c data ===")
print(f"OTA-Shield E1: P={our_e1_p:.3f} R={our_e1_r:.3f} Acc={our_e1_a:.3f}")
for lbl, r, p, a in rows[1:]:
    ps = f"{p:.3f}" if not math.isnan(p) else "N/A"
    rs = f"{r:.3f}" if not math.isnan(r) else "N/A"
    as_ = f"{a:.3f}" if not math.isnan(a) else "N/A"
    print(f"  {lbl}: P={ps} R={rs} Acc={as_}")
