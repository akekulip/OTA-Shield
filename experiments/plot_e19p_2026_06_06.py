"""Generate figures for the 2026-06-06 E19p stochastic 10-trial HW run.

Produces:
  runs/figures/E19p_2026-06-06_per_trial_f1.{pdf,png}
  runs/figures/E19p_2026-06-06_latency_cdf.{pdf,png}
  runs/figures/E19p_2026-06-06_confusion_per_trial.{pdf,png}
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np

# -- Style (mirrors figures.py publication settings) --------------------------
STYLE = {
    "font.family":      "serif",
    "font.serif":       ["Times New Roman", "Liberation Serif", "DejaVu Serif"],
    "mathtext.fontset": "stix",
    "font.size":        10,
    "axes.labelsize":   10,
    "axes.titlesize":   10,
    "xtick.labelsize":   9,
    "ytick.labelsize":   9,
    "legend.fontsize":   9,
    "legend.frameon":    True,
    "legend.framealpha": 1.0,
    "legend.edgecolor":  "gray",
    "legend.facecolor":  "white",
    "legend.fancybox":   False,
    "axes.grid":         True,
    "grid.alpha":        0.3,
    "grid.linestyle":    ":",
    "grid.linewidth":    0.4,
    "axes.linewidth":    0.7,
    "xtick.direction":   "in",
    "ytick.direction":   "in",
    "xtick.top":         True,
    "ytick.right":       True,
    "lines.linewidth":   1.0,
    "lines.markersize":  4.5,
    "figure.dpi":        150,
    "savefig.dpi":       300,
    "savefig.bbox":      "tight",
    "savefig.pad_inches": 0.02,
    "pdf.fonttype":      42,
    "ps.fonttype":       42,
}
mpl.rcParams.update(STYLE)

COL_W  = 3.5
COL2_W = 7.16

# -- Colors (ColorBrewer Set1) ------------------------------------------------
C_TP   = "#1b9e77"   # green
C_TN   = "#7570b3"   # purple
C_FP   = "#d95f02"   # orange
C_FN   = "#e7298a"   # pink
C_ND   = "#bdbdbd"   # gray


def save(fig: plt.Figure, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path.with_suffix(".pdf"))
    fig.savefig(path.with_suffix(".png"))
    plt.close(fig)
    print(f"  wrote {path.with_suffix('.pdf')} + .png")


# -------------------------------------------------------------------------
# Figure 1: per-trial F1 bar chart with precision/recall
# -------------------------------------------------------------------------
def fig_per_trial_f1(agg: dict, out: Path) -> None:
    ptr = agg["per_trial_raw"]
    n = len(ptr)
    trials = [f"t{i:02d}" for i in range(n)]
    x = np.arange(n)
    width = 0.25

    # Compute per-trial P, R, F1 from raw TP/FP/FN
    prec_list, rec_list, f1_list = [], [], []
    for t in ptr:
        tp = t.get("tp", 0); fp = t.get("fp", 0); fn = t.get("fn", 0)
        p  = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        r  = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f  = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        prec_list.append(p)
        rec_list.append(r)
        f1_list.append(f)

    fig, ax = plt.subplots(figsize=(COL2_W, 2.4))
    ax.bar(x - width, prec_list, width, label="Precision",
           color=C_TP, edgecolor="black", linewidth=0.4)
    ax.bar(x,         rec_list,  width, label="Recall",
           color=C_TN, edgecolor="black", linewidth=0.4)
    ax.bar(x + width, f1_list,   width, label="F1",
           color=C_FP, edgecolor="black", linewidth=0.4)

    # Mean F1 line
    mean_f1 = agg["aggregate"]["f1"]["mean"]
    ax.axhline(mean_f1, color="black", linestyle="--", linewidth=0.8,
               label=f"mean F1 = {mean_f1:.3f}")

    # CI band
    ci_lo = agg["aggregate"]["f1"]["ci_lo"]
    ci_hi = agg["aggregate"]["f1"]["ci_hi"]
    ax.axhspan(ci_lo, ci_hi, alpha=0.08, color="black",
               label=f"95% CI [{ci_lo:.3f}, {ci_hi:.3f}]")

    ax.set_xticks(x)
    ax.set_xticklabels(trials, fontsize=8)
    ax.set_xlabel("Trial")
    ax.set_ylabel("Score")
    ax.set_ylim(0.0, 1.08)
    ax.set_title("E19p Stochastic Rollback — per-trial Precision / Recall / F1\n"
                 "(n = 10 trials, Tofino HW, 2026-06-06)")
    ax.legend(loc="lower left", fontsize=7, ncol=2)
    fig.tight_layout()
    save(fig, out)


# -------------------------------------------------------------------------
# Figure 2: detection latency CDF
# -------------------------------------------------------------------------
def fig_latency_cdf(agg: dict, out: Path) -> None:
    lat = agg.get("latency_seconds", {})
    if not lat:
        print("  no latency data — skipping latency CDF")
        return

    # Reconstruct an approximate distribution from known percentiles
    # Real per-event latencies are not stored in the aggregate JSON;
    # we use the summary statistics to annotate a synthetic CDF derived
    # from all per-trial decisions.jsonl files if available.
    raw_latencies: list[float] = []
    exp_dir = Path("runs/experiments/E19p_stochastic_2026-06-06")
    for trial_dir in sorted(exp_dir.glob("t*")):
        gt_path = trial_dir / "ground_truth.json"
        dec_path = trial_dir / "decisions.jsonl"
        if not (gt_path.exists() and dec_path.exists()):
            continue
        gt = json.loads(gt_path.read_text())
        events = {(e["src_ip"], e["dst_ip"], int(e["src_port"])): e
                  for e in gt.get("events", [])}
        decisions = [json.loads(l) for l in dec_path.read_text().splitlines() if l.strip()]
        # t_recv for each hold_digest → latency = t_recv - matching ground truth send time.
        # Filter to ATTACK-labeled events only: FP events (LEGIT packets that triggered
        # hold_digest via the hold_armed_reg cascade) must be excluded so that the latency
        # CDF reflects genuine detection latency, not cascade DROP latency.
        # Review P3 / Fix 3 (review_rigor_2026-06-06.md): figure previously included all 227
        # hold_digest events; correct count is n=216 (ATTACK-only), matching aggregate JSON.
        for d in decisions:
            if d.get("_type") != "hold_digest":
                continue
            import socket, struct
            src_ip_str = socket.inet_ntoa(struct.pack(">I", int(d["src_ip"])))
            dst_ip_str = socket.inet_ntoa(struct.pack(">I", int(d["dst_ip"])))
            sp = int(d.get("src_port", 0))
            ev_key = (src_ip_str, dst_ip_str, sp)
            ev = events.get(ev_key)
            if ev is None:
                continue
            # Exclude FP events (LEGIT events that triggered hold_digest cascade).
            if ev.get("label") != "ATTACK":
                continue
            send_t = ev.get("t_send")
            if send_t is None:
                continue
            raw_latencies.append(d["_t_recv"] - send_t)

    if not raw_latencies:
        # Fall back: draw from summary stats only as a single-marker chart
        print("  per-event latencies unavailable — drawing from summary stats")
        fig, ax = plt.subplots(figsize=(COL_W, 2.2))
        stats = lat
        labels = ["min", "median", "mean", "p95", "max"]
        vals   = [stats.get(k, 0) * 1000 for k in labels]
        ax.barh(labels, vals, color=C_TP, edgecolor="black", linewidth=0.4)
        ax.set_xlabel("Latency (ms)")
        ax.set_title("E19p HW detection latency (hold_digest)")
        ax.axvline(stats.get("median", 0) * 1000, color="red",
                   linestyle="--", linewidth=0.8, label=f"median {stats['median']*1000:.1f} ms")
        ax.legend(fontsize=7)
        fig.tight_layout()
        save(fig, out)
        return

    raw_ms = sorted(l * 1000 for l in raw_latencies)
    cdf_y  = np.arange(1, len(raw_ms) + 1) / len(raw_ms)

    fig, ax = plt.subplots(figsize=(COL_W, 2.4))
    ax.plot(raw_ms, cdf_y, color=C_TP, linewidth=1.0, label="Empirical CDF")

    med_ms = lat.get("median", 0) * 1000
    p95_ms = lat.get("p95",    0) * 1000
    ax.axvline(med_ms, color="black", linestyle="--", linewidth=0.8,
               label=f"median {med_ms:.1f} ms")
    ax.axvline(p95_ms, color="#d95f02", linestyle=":", linewidth=0.8,
               label=f"p95 {p95_ms:.1f} ms")

    ax.set_xlabel("Detection latency (ms)")
    ax.set_ylabel("CDF")
    ax.set_ylim(0, 1.05)
    ax.set_title(f"Hold-digest detection latency\n"
                 f"(n = {len(raw_ms)} events, Tofino HW, 2026-06-06)")
    ax.legend(fontsize=7)
    fig.tight_layout()
    save(fig, out)


# -------------------------------------------------------------------------
# Figure 3: stacked TP/FP/TN/ND per trial
# -------------------------------------------------------------------------
def fig_confusion_per_trial(agg: dict, out: Path) -> None:
    ptr = agg["per_trial_raw"]
    n = len(ptr)
    trials = [f"t{i:02d}" for i in range(n)]

    tp_vals = [t.get("tp", 0) for t in ptr]
    fp_vals = [t.get("fp", 0) for t in ptr]
    tn_vals = [t.get("tn", 0) for t in ptr]
    fn_vals = [t.get("fn", 0) for t in ptr]
    nd_vals = [t.get("no_decision", 0) for t in ptr]

    x = np.arange(n)
    w = 0.6

    fig, ax = plt.subplots(figsize=(COL2_W, 2.2))
    b1 = ax.bar(x, tp_vals, w, label="TP",         color=C_TP, edgecolor="black", linewidth=0.3)
    b2 = ax.bar(x, tn_vals, w, bottom=tp_vals,     label="TN",
                color=C_TN, edgecolor="black", linewidth=0.3)
    bottom2 = [a + b for a, b in zip(tp_vals, tn_vals)]
    b3 = ax.bar(x, fp_vals, w, bottom=bottom2,     label="FP",
                color=C_FP, edgecolor="black", linewidth=0.3)
    bottom3 = [a + b for a, b in zip(bottom2, fp_vals)]
    b4 = ax.bar(x, fn_vals, w, bottom=bottom3,     label="FN",
                color=C_FN, edgecolor="black", linewidth=0.3)
    bottom4 = [a + b for a, b in zip(bottom3, fn_vals)]
    b5 = ax.bar(x, nd_vals, w, bottom=bottom4,     label="NO_DECISION",
                color=C_ND, edgecolor="black", linewidth=0.3)

    ax.set_xticks(x)
    ax.set_xticklabels(trials, fontsize=8)
    ax.set_xlabel("Trial")
    ax.set_ylabel("Event count")
    ax.set_title("E19p Stochastic Rollback — per-trial decision breakdown\n"
                 "(n_events = 40 per trial, 20 legit + 20 attack)")
    ax.legend(loc="upper right", fontsize=7, ncol=5)
    fig.tight_layout()
    save(fig, out)


# -------------------------------------------------------------------------
# Main
# -------------------------------------------------------------------------
def main() -> None:
    agg_path = Path("runs/experiments/_agg/E19p_stochastic_2026-06-06.json")
    if not agg_path.exists():
        sys.exit(f"Aggregate file not found: {agg_path}")
    agg = json.loads(agg_path.read_text())

    out_base = Path("runs/figures/E19p_2026-06-06")
    print("Generating E19p 2026-06-06 figures...")

    fig_per_trial_f1(agg, out_base.parent / "E19p_2026-06-06_per_trial_f1")
    fig_latency_cdf(agg, out_base.parent / "E19p_2026-06-06_latency_cdf")
    fig_confusion_per_trial(agg, out_base.parent / "E19p_2026-06-06_confusion_per_trial")

    print("Done.")


if __name__ == "__main__":
    main()
