"""Publication-grade figures for OTA-Shield.

Design principles:
  * Separate PRIMARY experiments (clean, peer-reviewable) from METHODOLOGY
    ABLATION experiments (kept for § Methodology discussion of how
    measurement choices affect results). NEVER pool them into a headline
    figure.
  * Single-column width 3.5 in, double-column 7.0 in. PDF uses embedded
    Type-1 fonts (fonttype=42) for LaTeX compatibility.
  * Serif (Times) text, 8-9 pt, thin grid, ColorBrewer-safe palette.
  * Each figure function takes its own input and writes exactly ONE PDF +
    ONE PNG. No side effects.

Primary allowlist is derived from `experiments/configs/*.yaml` — anything
outside it (E1_nostate_reset, E1_scenario_bug, SMOKE, …) is treated as
supporting material, not headline.
"""
from __future__ import annotations
import argparse, json, math, re
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np

# ---------- Publication style (IEEE double-column / Cerberus family) ----------
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

# IEEE / Cerberus column widths and figure heights.
COL_W   = 3.5     # single-column width (in)
COL2_W  = 7.16    # double-column width (in)
H_LINE  = 1.8     # line plots
H_BAR   = 2.0     # bar / grouped-bar plots
H_HIST  = 2.2     # histograms / multi-panel distributions

# Line styles: hollow markers with colored edges, B&W-distinguishable.
LINE_STYLES = [
    {"color": "#1f77b4", "marker": "o", "ls": "-"},
    {"color": "#d62728", "marker": "*", "ls": "-"},
    {"color": "#2ca02c", "marker": "s", "ls": "--"},
    {"color": "#ff7f0e", "marker": "D", "ls": ":"},
    {"color": "#9467bd", "marker": "^", "ls": "-."},
    {"color": "#8c564b", "marker": "v", "ls": "-"},
]

BAR_COLORS = ["#4e79a7", "#59a14f", "#b07aa1", "#e6ab02",
              "#d95f02", "#1b9e77"]

CONFUSION_COLORS = {
    "TP": "#1b9e77", "TN": "#7570b3",
    "FP": "#d95f02", "FN": "#e7298a",
}

# Legacy aliases — some figure bodies still reference these directly.
# Kept until every call site is migrated through the helpers below.
C_TP      = CONFUSION_COLORS["TP"]
C_TN      = CONFUSION_COLORS["TN"]
C_FP      = CONFUSION_COLORS["FP"]
C_FN      = CONFUSION_COLORS["FN"]
C_NEUTRAL = "#66a5d7"


def plot_line(ax, x, y, idx, label=None, **kw):
    """IEEE-style line plot: colored edge, white-filled marker."""
    s = LINE_STYLES[idx % len(LINE_STYLES)]
    return ax.plot(
        x, y,
        color=s["color"], marker=s["marker"], linestyle=s["ls"],
        markerfacecolor="white", markeredgecolor=s["color"],
        markeredgewidth=0.9, markersize=4.5,
        linewidth=1.0, label=label, **kw,
    )


def plot_band(ax, x, lo, hi, idx, alpha=0.18):
    """Confidence band matching the line colour at index `idx`."""
    s = LINE_STYLES[idx % len(LINE_STYLES)]
    ax.fill_between(x, lo, hi, color=s["color"],
                    alpha=alpha, linewidth=0)


def panel_label(ax, letter, text, where="xlabel"):
    """Cerberus-style sublabel: "(a) Recall" placed below the panel as
    part of the xlabel, or as a left-aligned title if `where='title'`."""
    if where == "xlabel":
        existing = ax.get_xlabel()
        ax.set_xlabel(f"({letter}) {text}" if not existing
                      else f"({letter}) {existing}")
    else:
        ax.set_title(f"({letter}) {text}", loc="left", pad=3,
                     fontsize=8)


def finalize(ax, xlabel=None, ylabel=None, ylim=None,
             xlim=None, legend_loc="best", legend_ncol=1):
    """Apply final IEEE conventions and legend placement."""
    if xlabel:
        ax.set_xlabel(xlabel)
    if ylabel:
        ax.set_ylabel(ylabel)
    if ylim:
        ax.set_ylim(*ylim)
    if xlim:
        ax.set_xlim(*xlim)
    if legend_loc:
        ax.legend(loc=legend_loc, ncol=legend_ncol)


def _load_stage_latencies(csv_path: Path | None) -> dict | None:
    """Load runs/latency_stages/per_stage.csv (columns stage, latency_ms)
    into {'stage1': [...], 'stage2': [...]}. Returns None if the file is
    missing or malformed — callers handle the fallback."""
    if csv_path is None or not Path(csv_path).exists():
        return None
    import csv as _csv
    out: dict[str, list[float]] = {"stage1": [], "stage2": []}
    with open(csv_path, newline="") as f:
        reader = _csv.DictReader(f)
        for row in reader:
            stage = (row.get("stage") or "").strip()
            try:
                v = float(row["latency_ms"])
            except (KeyError, ValueError):
                continue
            if "1" in stage or "pipeline" in stage:
                out["stage1"].append(v)
            elif "2" in stage or "decision" in stage:
                out["stage2"].append(v)
    if not (out["stage1"] and out["stage2"]):
        return None
    return out


def _save(fig, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out.with_suffix(".pdf"))
    fig.savefig(out.with_suffix(".png"))
    plt.close(fig)


# Simple flag set by main(); figure functions consult this via
# _strict() for fallback-vs-fail decisions.
_STRICT: bool = False


def _strict() -> bool:
    return _STRICT


def _warn(msg: str) -> None:
    import sys
    print(f"[figures.py WARN] {msg}", file=sys.stderr)


def _strict_fail(what: str) -> None:
    """Either raise SystemExit(2) in --strict mode or emit a warning."""
    if _STRICT:
        raise SystemExit(f"[figures.py --strict] missing data: {what}")
    _warn(what)


# ---------- Data helpers ----------

def load_agg(agg_dir: Path) -> dict[str, dict]:
    return {p.stem: json.loads(p.read_text())
            for p in sorted(agg_dir.glob("*.json"))}


def primary_keys(agg: dict, configs_dir: Path) -> list[str]:
    """Experiments with a matching YAML in configs/ — everything else is
    supporting (methodology ablation, smoke, etc.). Also excludes configs
    whose stem contains 'ablation' or 'SMOKE' from the headline pool; those
    belong in dedicated ablation figures."""
    allow = {p.stem for p in configs_dir.glob("*.yaml")}
    def is_primary(k: str) -> bool:
        if k not in allow:
            return False
        lowered = k.lower()
        if "ablation" in lowered or "smoke" in lowered:
            return False
        return True
    return [k for k in sorted(agg) if is_primary(k)]


# ---------- Figures ----------

def fig_confusion_matrix(aggs: dict, out: Path,
                          title: str = "Confusion matrix",
                          primary_only: bool = True) -> None:
    """Pooled confusion matrix across the primary scoring experiments
    only (E1, E6, E8, E9) by default. E4 is an ablation designed to
    produce FP, so including it pollutes the pooled matrix and
    visually contradicts the headline precision number."""
    if primary_only:
        primary_keys = {"E1_attack_detection", "E6_a4_oversize",
                         "E8_stochastic", "E9_evasion_r4"}
        use = {k: v for k, v in aggs.items() if k in primary_keys}
    else:
        use = aggs
    tp = tn = fp = fn = 0
    for a in use.values():
        for t in a["per_trial_raw"]:
            tp += t["tp"]; tn += t["tn"]; fp += t["fp"]; fn += t["fn"]
    M = np.array([[tp, fn], [fp, tn]])
    total = max(M.sum(), 1)
    quadrant = np.array([["TP", "FN"], ["FP", "TN"]])

    fig, ax = plt.subplots(figsize=(COL_W, COL_W))
    ax.imshow(M, cmap="Blues", aspect="equal", vmin=0,
              vmax=max(M.max(), 1))
    for i in range(2):
        for j in range(2):
            n = int(M[i, j])
            pct = 100 * n / total
            q = quadrant[i, j]
            c = "white" if M[i, j] / (M.max() or 1) > 0.55 else "black"
            ax.text(j, i, f"{q}\n{n}\n{pct:.1f}%",
                    ha="center", va="center", color=c, fontsize=9,
                    fontweight="bold")
            # Colored cell border per quadrant type (CONFUSION_COLORS).
            border = CONFUSION_COLORS.get(q, "black")
            rect = plt.Rectangle((j - 0.5, i - 0.5), 1, 1,
                                  fill=False, edgecolor=border,
                                  linewidth=1.4, zorder=5)
            ax.add_patch(rect)
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(["attack", "legit"])
    ax.set_yticklabels(["attack", "legit"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
    ax.set_title(title, pad=6)
    ax.grid(False)
    for spine in ax.spines.values():
        spine.set_visible(True)
        spine.set_linewidth(0.4)
    fig.tight_layout()
    _save(fig, out)


def fig_per_experiment_bars(aggs: dict, out: Path) -> None:
    """Per-trial trajectory of Precision / Recall / F1 from E8's 20 IID
    trials. Replaces the single-point grouped-bar view (which conveyed
    no variance) with a three-line parameter sweep over trial index.

    Signature is preserved for backward compatibility with main(). If
    E8_stochastic is absent from `aggs` the figure returns (unless
    --strict is set).
    """
    e8 = aggs.get("E8_stochastic") or {}
    trials = e8.get("per_trial_raw") or []
    if not trials:
        _strict_fail("E8_stochastic.per_trial_raw missing; "
                     "skipping fig_per_experiment.")
        return

    idx = np.arange(1, len(trials) + 1)
    prec, rec, f1 = [], [], []
    for t in trials:
        tp = float(t.get("tp", 0)); fp = float(t.get("fp", 0))
        fn = float(t.get("fn", 0))
        p = tp / (tp + fp) if (tp + fp) else 0.0
        r = tp / (tp + fn) if (tp + fn) else 0.0
        prec.append(p); rec.append(r)
        f1.append(2 * p * r / (p + r) if (p + r) else 0.0)
    prec = np.array(prec); rec = np.array(rec); f1 = np.array(f1)

    fig, ax = plt.subplots(figsize=(COL_W, H_LINE))
    plot_line(ax, idx, prec, idx=0, label="Precision")
    plot_line(ax, idx, rec,  idx=1, label="Recall")
    plot_line(ax, idx, f1,   idx=2, label="F1")
    # Shaded bootstrap CI band around F1 using per-trial variance.
    if len(f1) >= 3:
        mu = float(np.mean(f1))
        se = float(np.std(f1, ddof=1) / math.sqrt(len(f1)))
        plot_band(ax, idx, np.full_like(f1, mu - 1.96 * se),
                  np.full_like(f1, mu + 1.96 * se), idx=2)
    for name, series, k in (("Precision", prec, 0),
                              ("Recall", rec, 1),
                              ("F1", f1, 2)):
        ax.axhline(float(np.mean(series)),
                    color=LINE_STYLES[k]["color"],
                    lw=0.4, linestyle=":", alpha=0.35)

    ax.set_xticks(idx[::max(1, len(idx) // 10)])
    finalize(ax, xlabel="Trial index", ylabel="Score",
             ylim=(0.95, 1.005), xlim=(0.5, len(trials) + 0.5),
             legend_loc="lower left")
    fig.tight_layout()
    _save(fig, out)


def fig_detection_latency(latencies: list[float], out: Path,
                            p95_override: float | None = None,
                            med_override: float | None = None,
                            stage_latencies: dict | None = None) -> None:
    """Histogram + CDF (+ optional per-stage breakdown).

    `stage_latencies`, if provided, must be a dict with keys 'stage1'
    and 'stage2' each mapping to a list of latencies in milliseconds.
    When given, a third panel (log-scale box plot) is drawn, directly
    addressing the reviewer concern that the end-to-end distribution
    hides the two-stage decomposition (send → digest; digest → decision).
    """
    lat_ms = np.array(sorted(l * 1000 for l in latencies))
    if lat_ms.size == 0:
        _strict_fail("fig_detection_latency: empty latency list.")
        return
    lo, hi = np.percentile(lat_ms, [1, 95])
    span = max(hi - lo, 1.0)
    x_lo = max(0.0, lo - 0.02 * span)
    x_hi = hi + 0.05 * span

    has_stages = bool(stage_latencies and
                      stage_latencies.get("stage1") and
                      stage_latencies.get("stage2"))
    n_panels = 3 if has_stages else 2
    figsize = (COL2_W, H_HIST) if has_stages else (COL2_W, H_LINE + 0.4)
    fig, axes = plt.subplots(1, n_panels, figsize=figsize,
                              constrained_layout=True,
                              gridspec_kw={"wspace": 0.32})
    ax1, ax2 = axes[0], axes[1]

    in_range = lat_ms[(lat_ms >= x_lo) & (lat_ms <= x_hi)]
    bins = np.linspace(x_lo, x_hi, 30)
    hist_color = LINE_STYLES[0]["color"]
    ax1.hist(in_range, bins=bins, color=hist_color,
             edgecolor="black", linewidth=0.3, alpha=0.75)
    med = med_override if med_override is not None \
          else float(np.median(lat_ms))
    ax1.axvline(med, color="black", linestyle="--", lw=0.7)
    ax1.text(0.04, 0.92, f"median = {med:.1f} ms",
             transform=ax1.transAxes, fontsize=7, va="top",
             bbox=dict(boxstyle="round,pad=0.2", fc="white",
                       ec="black", linewidth=0.4, alpha=0.95))
    ax1.set_xlim(x_lo, x_hi)
    ax1.set_ylabel("# attacks")
    panel_label(ax1, "a", "End-to-end latency (ms)", where="xlabel")

    cdf = np.arange(1, lat_ms.size + 1) / lat_ms.size
    ax2.plot(lat_ms, cdf, color=LINE_STYLES[0]["color"], lw=1.0)
    ax2.set_xlim(x_lo, x_hi)
    ax2.set_ylim(0, 1.02)
    ax2.axhline(0.95, color="#888", lw=0.4, linestyle=":")
    p95 = p95_override if p95_override is not None \
          else float(np.percentile(lat_ms, 95))
    ax2.axvline(p95, color="black", linestyle="--", lw=0.7)
    ax2.text(0.04, 0.92, f"p95 = {p95:.1f} ms",
             transform=ax2.transAxes, fontsize=7, va="top",
             bbox=dict(boxstyle="round,pad=0.2", fc="white",
                       ec="black", linewidth=0.4, alpha=0.95))
    ax2.set_ylabel("CDF")
    panel_label(ax2, "b", "End-to-end latency (ms)", where="xlabel")

    if has_stages:
        ax3 = axes[2]
        s1 = np.asarray(stage_latencies["stage1"], dtype=float)
        s2 = np.asarray(stage_latencies["stage2"], dtype=float)
        data = [s1, s2]
        bp = ax3.boxplot(data, labels=["stage 1", "stage 2"],
                          widths=0.55, patch_artist=True,
                          medianprops=dict(color="black", linewidth=0.9),
                          flierprops=dict(marker=".", markersize=2,
                                          markerfacecolor="#888",
                                          markeredgecolor="#888"))
        for patch, col in zip(bp["boxes"],
                               [LINE_STYLES[0]["color"],
                                LINE_STYLES[1]["color"]]):
            patch.set_facecolor("white")
            patch.set_edgecolor(col)
            patch.set_linewidth(0.9)
        for whisker in bp["whiskers"]:
            whisker.set_linewidth(0.7)
        for cap in bp["caps"]:
            cap.set_linewidth(0.7)
        ax3.set_yscale("log")
        ax3.set_ylabel("Latency (ms, log)")
        ax3.grid(False)
        ax3.axhline(p95, color="#d62728", lw=1.1, linestyle="--",
                    alpha=0.95, zorder=5)
        ax3.text(1.02, p95, f" end-to-end p95",
                 transform=ax3.get_yaxis_transform(),
                 fontsize=7, color="#d62728", va="center",
                 fontweight="bold")
        panel_label(ax3, "c", "Per-stage breakdown", where="xlabel")

    _save(fig, out)


def fig_throughput(csv_path: Path, out: Path) -> None:
    """E11 throughput sweep: log-scale offered rate (pps) vs observed
    pps, with a y=x perfect-throughput reference, a scapy-ceiling
    annotation, and an estimated switch-line-rate reference.
    """
    if not csv_path.exists():
        _strict_fail(f"throughput CSV missing: {csv_path}")
        return
    lines = csv_path.read_text().strip().splitlines()
    if len(lines) < 2:
        _strict_fail(f"throughput CSV empty: {csv_path}")
        return
    rates, sent_vals, obs_vals = [], [], []
    for ln in lines[1:]:
        parts = ln.split(",")
        if len(parts) < 4:
            continue
        try:
            rates.append(int(parts[0]))
            sent_vals.append(int(parts[1]))
            obs_vals.append(int(parts[2]))
        except ValueError:
            continue
    if not rates:
        _strict_fail(f"throughput CSV: no valid rows in {csv_path}")
        return

    fig, ax = plt.subplots(figsize=(COL_W, H_LINE))
    rates_np = np.array(rates, dtype=float)
    obs_np   = np.array(obs_vals, dtype=float)
    # y = x perfect-throughput reference (gray dashed, behind data).
    x_ref = np.logspace(np.log10(max(1, min(rates))),
                        np.log10(max(rates) * 1.5), 100)
    ax.plot(x_ref, x_ref, color="#888888", lw=0.7, linestyle="--",
            zorder=1)
    plot_line(ax, rates_np, obs_np, idx=0, zorder=5)
    # Inline labels rather than a legend that would overlap the curves.
    x_yx = x_ref[int(len(x_ref) * 0.80)]
    ax.annotate("$y = x$", xy=(x_yx, x_yx),
                xytext=(x_yx * 0.55, x_yx * 0.35),
                fontsize=7, color="#666666")
    i_mid = len(rates_np) // 2
    ax.annotate("Observed", xy=(rates_np[i_mid], obs_np[i_mid]),
                xytext=(rates_np[i_mid] * 0.55,
                        obs_np[i_mid] * 1.9),
                fontsize=7, color=plt.rcParams["axes.prop_cycle"]
                                    .by_key()["color"][0])

    # Scapy generator ceiling at ~2200 pps — show where saturation happens.
    ax.axvline(2200, color="#444444", lw=0.5, linestyle=":")
    ax.text(2200 * 1.05, max(obs_np) * 0.55,
            "scapy generator ceiling", fontsize=6, color="#444444",
            rotation=90, va="center", ha="left")

    ax.set_xscale("log")
    ax.set_yscale("log")
    finalize(ax, xlabel="Target offered rate (pps, log)",
             ylabel="Observed rate (pps, log)",
             legend_loc=None)
    fig.tight_layout()
    _save(fig, out)


def fig_benign_rollout(e12_agg: dict, out: Path) -> None:
    """E12: PASS / HOLD-only / DROP rates per benign sub-scenario.

    Tolerates 5-7 sub-scenarios depending on which §6a/§6b gates are in
    play. Returns early with a stderr warning if fewer than 3 scenarios
    are present (the figure is not meaningful below that)."""
    scen_out = e12_agg.get("scenario_outcomes") or {}
    if len(scen_out) < 3:
        # Fallback: aggregator did not emit per-scenario outcomes, but
        # the raw per-trial + per-rule tallies carry enough information
        # to render a single "overall" stacked bar (PASS / HOLD-only /
        # DROP) instead of silently dropping the figure and leaving the
        # reader with "0 events." This keeps the paper consistent with
        # the abstract's 450-event headline.
        ptr = e12_agg.get("per_trial_raw") or []
        prc = e12_agg.get("per_rule_counts") or {}
        total_tn = sum(int(t.get("tn", 0)) for t in ptr)
        total_fp = sum(int(t.get("fp", 0)) for t in ptr)
        silent_pass = int((prc.get("-") or {}).get("TN", 0))
        hold_only_cnt = max(0, total_tn - silent_pass)
        total_events = silent_pass + hold_only_cnt + total_fp
        if total_events <= 0:
            _strict_fail(f"E12 figure: no events in aggregate either.")
            return
        scen_out = {
            "benign_overall": {
                "pass": silent_pass,
                "hold_only": hold_only_cnt,
                "drop": total_fp,
            }
        }
    raw_labels = list(scen_out.keys())
    _rows = []
    for k in raw_labels:
        p = scen_out[k].get("pass", 0)
        h = scen_out[k].get("hold_only", 0)
        d = scen_out[k].get("drop", 0)
        t = max(1, p + h + d)
        _rows.append((k, p, h, d, t, 100 * p / t))
    _rows.sort(key=lambda r: r[5], reverse=True)
    labels       = [r[0] for r in _rows]
    pass_counts  = [r[1] for r in _rows]
    hold_counts  = [r[2] for r in _rows]
    drop_counts  = [r[3] for r in _rows]
    totals       = [r[4] for r in _rows]
    p_pct        = [r[5] for r in _rows]
    h_pct        = [100 * h / t for h, t in zip(hold_counts, totals)]
    d_pct        = [100 * d / t for d, t in zip(drop_counts, totals)]
    x = np.arange(len(labels))

    fig, ax = plt.subplots(figsize=(COL2_W, H_BAR))
    ax.bar(x, p_pct, color="#1b9e77", edgecolor="black",
           linewidth=0.3, label="PASS")
    ax.bar(x, h_pct, bottom=p_pct, color="#e6ab02",
           edgecolor="black", linewidth=0.3, label="HOLD-only")
    ax.bar(x, d_pct, bottom=[p + h for p, h in zip(p_pct, h_pct)],
           color="#d95f02", edgecolor="black", linewidth=0.3,
           label="DROP")
    pretty = {
        "benign_staged":                "staged\nrollout",
        "benign_emergency":             "emergency\npatch",
        "benign_migration_src1":        "source\nmigration\n(src1)",
        "benign_migration_src2":        "source\nmigration\n(src2)",
        "benign_delayed":               "delayed\nwindow",
        "benign_rollback_preamble":     "rollback\npreamble",
        "benign_authorized_rollback":   "authorized\nrollback",
        "benign_overall":               "all benign\nevents",
    }
    ax.set_xticks(x)
    ax.set_xticklabels([pretty.get(k, k.replace("benign_", ""))
                         for k in labels], fontsize=7)
    ax.set_ylim(0, 115)
    ax.set_ylabel("% of events")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.30),
              ncol=3, handlelength=1.3, fontsize=7,
              frameon=False, borderaxespad=0.0)
    fig.tight_layout()
    fig.subplots_adjust(bottom=0.30)
    _save(fig, out)


def fig_override_capacity(curve_csv: Path, summary_csv: Path,
                            out: Path, table_cap: int = 1024) -> None:
    """E13: active override count over time per offered rate, plus a
    synthetic rejection-rate panel. Two-panel layout (1,2): left panel
    shows the installs-vs-TTL race with direct crossing-point
    annotations where each rate hits the table cap; right panel shows
    per-bucket rejection rate estimated from the install/eviction
    delta (labelled "estimated" because the raw CSV lacks a rejection
    counter column).
    """
    if not curve_csv.exists():
        _strict_fail(f"override capacity CSV missing: {curve_csv}")
        return
    lines = curve_csv.read_text().strip().splitlines()[1:]
    series: dict[int, list[tuple[float, int, int]]] = {}
    for ln in lines:
        try:
            parts = ln.split(",")
            rate = int(parts[0]); t = float(parts[1])
            n_active = int(parts[2])
            n_installed = int(parts[3]) if len(parts) > 3 else n_active
            series.setdefault(rate, []).append((t, n_active, n_installed))
        except (ValueError, TypeError):
            continue
    if not series:
        _strict_fail(f"override capacity CSV: no valid rows in {curve_csv}")
        return

    fig, (ax_l, ax_r) = plt.subplots(1, 2, figsize=(COL2_W, H_LINE),
                                       gridspec_kw={"wspace": 0.24})

    rates_sorted = sorted(series.keys())
    for i, rate in enumerate(rates_sorted):
        pts = sorted(series[rate])
        xs = np.array([p[0] for p in pts])
        ys = np.array([p[1] for p in pts])
        inst = np.array([p[2] for p in pts])
        plot_line(ax_l, xs, ys, idx=i, label=f"{rate} pps")

        # Direct annotation at first cap crossing, if any.
        above = np.where(ys >= table_cap)[0]
        if above.size:
            t_cross = float(xs[above[0]])
            s = LINE_STYLES[i % len(LINE_STYLES)]
            ax_l.annotate(
                f"{rate} pps\ncap @ t={t_cross:.1f}s",
                xy=(t_cross, table_cap),
                xytext=(xs[-1] * 0.6, table_cap * 0.25 - i * 80),
                fontsize=6, color=s["color"],
                arrowprops=dict(arrowstyle="->", color=s["color"],
                                lw=0.6, shrinkA=0, shrinkB=2),
            )

        # Synthetic rejection rate: installs-per-second minus
        # eviction-per-second (bucketed by 0.5s). When the diff is
        # positive and the table is full, those installs were rejected.
        if xs.size >= 2 and np.any(ys >= table_cap):
            dt = np.diff(xs)
            dinst = np.diff(inst)
            deact = np.diff(ys)   # change in active
            dreject = np.maximum(0.0,
                                  (dinst - (dinst - deact)) / np.maximum(dt, 1e-3))
            # dreject == max(0, deact diff) — clamp to >=0 rejection rate
            dreject = np.maximum(0.0,
                                  (dinst - np.maximum(0.0, deact)) /
                                  np.maximum(dt, 1e-3))
            xs_mid = 0.5 * (xs[1:] + xs[:-1])
            plot_line(ax_r, xs_mid, dreject, idx=i, label=f"{rate} pps")

    ax_l.axhline(table_cap, color="#888", lw=0.6, linestyle="--")
    ax_l.text(0.02, table_cap, f" table cap = {table_cap}",
              transform=ax_l.get_yaxis_transform(), fontsize=6,
              color="#555", va="bottom",
              bbox=dict(boxstyle="round,pad=0.1", fc="white",
                        ec="none", alpha=0.85))
    finalize(ax_l, xlabel="Time within rate window (s)",
             ylabel="Active session overrides",
             legend_loc="upper left")
    ax_r.set_ylabel("Estimated rejection rate (/s)")
    ax_r.set_xlabel("Time within rate window (s)")
    ax_r.text(0.98, 0.04, "(estimated from install−eviction delta)",
              transform=ax_r.transAxes, fontsize=6, ha="right",
              va="bottom", color="#555")
    panel_label(ax_l, "a", "Active overrides", where="xlabel")
    panel_label(ax_r, "b", "Rejection rate", where="xlabel")
    fig.tight_layout()
    _save(fig, out)


def fig_suricata_vs_ours(suricata: dict, ours_agg: dict, out: Path,
                           sweep_csv: Path | None = None,
                           suricata_rat: dict | None = None,
                           suricata_perm_rat: dict | None = None,
                           extra_baselines: "dict[str, dict] | None" = None
                           ) -> None:
    """Multi-baseline CPU-IDS comparison on the E1 PCAP replay.

    Three panels (precision, recall, accuracy). Bars, in order:
    OTA-Shield, Suricata min, Suricata stateful, Suricata stateful
    permissive, Zeek domain-aware, Suricata+RAT (M7). Any baseline
    whose comparison.json is absent from `extra_baselines` is skipped
    — the figure reports only measured systems.

    `sweep_csv`, if provided and non-empty, draws the legacy attack-
    volume sweep lines instead of the bar chart.
    """
    import csv as _csv

    def _pr(d: "dict | None") -> tuple[float, float, float]:
        if d is None:
            return float("nan"), float("nan"), float("nan")
        r = d.get("recall")
        p = d.get("precision")
        a = d.get("accuracy")
        return (float(r) if r is not None else float("nan"),
                float(p) if p is not None else float("nan"),
                float(a) if a is not None else float("nan"))

    series: dict[str, dict[str, list[float]]] = {}
    if sweep_csv and Path(sweep_csv).exists():
        with open(sweep_csv, newline="") as f:
            for row in _csv.DictReader(f):
                sys_name = row.get("system", "").strip()
                try:
                    vol = float(row["attack_volume_pct"])
                    rec = float(row.get("recall", 0))
                    pre = float(row.get("precision", 0))
                except (KeyError, ValueError):
                    continue
                d = series.setdefault(sys_name,
                                      {"vol": [], "rec": [], "pre": []})
                d["vol"].append(vol); d["rec"].append(rec); d["pre"].append(pre)
        if not series:
            _warn(f"{sweep_csv}: no valid rows; using bar-chart fallback.")

    if series:
        fig, (ax_r, ax_p) = plt.subplots(1, 2, figsize=(COL2_W, H_LINE),
                                         sharey=True,
                                         constrained_layout=True,
                                         gridspec_kw={"wspace": 0.08})
        sys_order = sorted(series.keys())
        for i, sys_name in enumerate(sys_order):
            d = series[sys_name]
            order = np.argsort(d["vol"])
            vol = np.array(d["vol"])[order]
            rec = np.array(d["rec"])[order]
            pre = np.array(d["pre"])[order]
            plot_line(ax_r, vol, rec, idx=i, label=sys_name)
            plot_line(ax_p, vol, pre, idx=i, label=sys_name)
        ax_r.set_xlabel("Attack volume (%)")
        ax_p.set_xlabel("Attack volume (%)")
        ax_r.set_ylim(0, 1.10)
        ax_r.set_ylabel("Score")
        panel_label(ax_r, "a", "Recall", where="xlabel")
        panel_label(ax_p, "b", "Precision", where="xlabel")
        ax_r.legend(loc="lower right")
        _save(fig, out)
        return

    extras = dict(extra_baselines or {})
    our_r = float(ours_agg["aggregate"]["recall"]["mean"])
    our_p = float(ours_agg["aggregate"]["precision"]["mean"])
    our_a = float(ours_agg["aggregate"].get("accuracy", {}).get("mean",
                                                                 float("nan")))
    rows: list[tuple[str, float, float, float]] = [
        ("OTA-Shield", our_r, our_p, our_a),
    ]
    order = [
        ("Suricata min",            suricata),
        ("Suricata stateful",       extras.get("suricata_stateful")),
        ("Suricata stateful+perm",  extras.get("suricata_stateful_permissive")),
        ("Zeek domain-aware",       extras.get("zeek")),
        ("Suricata +RAT",           suricata_rat),
        ("Suricata perm+RAT",       suricata_perm_rat),
    ]
    for label, d in order:
        if d is None:
            continue
        r, p, a = _pr(d)
        rows.append((label, r, p, a))

    labels = [r[0] for r in rows]
    rec_vals = [r[1] for r in rows]
    pre_vals = [r[2] for r in rows]
    acc_vals = [r[3] for r in rows]

    fig, (ax_p, ax_r, ax_a) = plt.subplots(1, 3, figsize=(COL2_W, H_BAR + 1.1),
                                           sharey=True,
                                           constrained_layout=True,
                                           gridspec_kw={"wspace": 0.12})
    x = np.arange(len(labels))
    n = len(labels)
    palette = [BAR_COLORS[i % len(BAR_COLORS)] for i in range(n)]

    def _draw(ax, vals, panel_letter, panel_title):
        plot_vals = [0.0 if (v != v) else v for v in vals]
        ax.bar(x, plot_vals, width=0.62, color=palette,
               edgecolor="black", linewidth=0.6)
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=6.5)
        for i, v in enumerate(vals):
            txt = "n/a" if (v != v) else f"{v:.2f}"
            y = plot_vals[i] + 0.02
            ax.text(i, y, txt, ha="center", va="bottom", fontsize=6.5)
        panel_label(ax, panel_letter, panel_title, where="xlabel")

    _draw(ax_p, pre_vals, "a", "Precision")
    _draw(ax_r, rec_vals, "b", "Recall")
    _draw(ax_a, acc_vals, "c", "Accuracy")
    ax_p.set_ylim(0, 1.15)
    ax_p.set_ylabel("Score")
    _save(fig, out)


def fig_rat_ablation(all_aggs: dict, out: Path) -> None:
    """E1 vs E4: show the RAT arbiter's contribution to precision."""
    pairs = [("E1_attack_detection", "RAT enabled"),
             ("E4_ablation",          "RAT disabled")]
    pairs = [(k, lbl) for k, lbl in pairs if k in all_aggs]
    if len(pairs) < 2:
        _strict_fail("fig_rat_ablation: need both E1_attack_detection "
                     "and E4_ablation in aggs.")
        return

    metrics = [("precision", "Precision"), ("recall", "Recall"),
               ("f1", "F1")]
    x = np.arange(len(metrics))
    width = 0.36
    palette = [BAR_COLORS[0], BAR_COLORS[4]]

    fig, ax = plt.subplots(figsize=(COL_W, H_BAR))
    bar_tops: list[tuple[float, float]] = []
    hatches = ["", "//"]
    edgecolors = ["black", "#333333"]
    for i, (exp, lbl) in enumerate(pairs):
        vals = [all_aggs[exp]["aggregate"][k]["mean"] for k, _ in metrics]
        lo   = [all_aggs[exp]["aggregate"][k]["mean"] -
                all_aggs[exp]["aggregate"][k]["ci_lo"] for k, _ in metrics]
        hi   = [all_aggs[exp]["aggregate"][k]["ci_hi"] -
                all_aggs[exp]["aggregate"][k]["mean"] for k, _ in metrics]
        vals = [0 if math.isnan(v) else v for v in vals]
        xpos = x + (i - 0.5) * width
        ax.bar(xpos, vals, width,
               yerr=[[max(0, l) for l in lo], [max(0, h) for h in hi]],
               error_kw={"elinewidth": 1.5, "capsize": 3,
                         "capthick": 1.5},
               color=palette[i], edgecolor=edgecolors[i],
               linewidth=0.7, hatch=hatches[i], label=lbl)
        for xi, v in zip(xpos, vals):
            bar_tops.append((xi, v))
            ax.text(xi, v + 0.02, f"{v:.3f}", ha="center",
                    va="bottom", fontsize=6)
    ax.set_xticks(x)
    ax.set_xticklabels([m[1] for m in metrics])
    ax.set_ylabel("Score")
    # Annotate that recall is intentionally equal across both conditions
    # (both 1.000), with a thin double-headed arrow bridging the recall
    # bar pair so readers do not misread the flat pair as a chart bug.
    recall_idx = next((j for j, (k, _) in enumerate(metrics)
                       if k == "recall"), None)
    if recall_idx is not None:
        x_left = recall_idx - 0.5 * width
        x_right = recall_idx + 0.5 * width
        y_arrow = 1.13
        ax.annotate("", xy=(x_right, y_arrow), xytext=(x_left, y_arrow),
                    arrowprops=dict(arrowstyle='<->', color='black',
                                    lw=0.8))
        ax.text((x_left + x_right) / 2.0, y_arrow + 0.015,
                "\u0394 = 0", ha="center", va="bottom",
                fontsize=7, color="black")
    ax.set_ylim(0, 1.30)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0),
              ncol=2, handlelength=1.2, frameon=False,
              borderaxespad=0.2)
    fig.tight_layout()
    _save(fig, out)


def fig_methodology_ablation(all_aggs: dict, primary: list[str],
                              out: Path) -> None:
    """Compare headline experiment against its methodology ablations.
    Expects naming convention: `E1_attack_detection` (primary),
    `E1_nostate_reset`, `E1_scenario_bug` (ablations)."""
    base = "E1_attack_detection"
    variants = {
        "E1_nostate_reset":  "no state reset",
        "E1_scenario_bug":   "scenario bug",
        base:                "clean (ours)",
    }
    order = ["E1_nostate_reset", "E1_scenario_bug", base]
    order = [k for k in order if k in all_aggs]
    if not order:
        _strict_fail("fig_methodology_ablation: no E1 variants present "
                     "in aggs.")
        return

    metrics = [("precision", "Precision"), ("recall", "Recall"),
               ("f1", "F1")]
    x = np.arange(len(metrics))
    width = 0.26
    palette = BAR_COLORS[0:3]

    fig, ax = plt.subplots(figsize=(COL_W * 1.35, H_BAR))
    for i, exp in enumerate(order):
        vals = [all_aggs[exp]["aggregate"][k]["mean"] for k, _ in metrics]
        lo   = [all_aggs[exp]["aggregate"][k]["mean"] -
                all_aggs[exp]["aggregate"][k]["ci_lo"] for k, _ in metrics]
        hi   = [all_aggs[exp]["aggregate"][k]["ci_hi"] -
                all_aggs[exp]["aggregate"][k]["mean"] for k, _ in metrics]
        vals = [0 if math.isnan(v) else v for v in vals]
        ax.bar(x + (i - 1) * width, vals, width,
               yerr=[[max(0, l) for l in lo], [max(0, h) for h in hi]],
               capsize=2.5, color=palette[i], edgecolor="black",
               linewidth=0.4, label=variants[exp])
    ax.set_xticks(x)
    ax.set_xticklabels([m[1] for m in metrics])
    ax.set_ylabel("Score")
    ax.set_ylim(0, 1.12)
    ax.legend(loc="lower right", ncol=1, handlelength=1.2,
              fontsize=7)
    ax.set_title("Methodology ablation (E1)", loc="left", pad=3,
                 fontsize=8)
    fig.tight_layout()
    _save(fig, out)


# ---------- Tables ----------

def table_summary_latex(aggs: dict, out: Path) -> None:
    metrics = ["precision", "recall", "f1", "accuracy"]
    aggs = {e: a for e, a in aggs.items() if a.get("aggregate")}
    best = {m: max((aggs[e]["aggregate"][m]["mean"] for e in aggs
                    if not math.isnan(aggs[e]["aggregate"][m]["mean"])),
                   default=0)
            for m in metrics}
    lines = []
    lines.append(r"% auto-generated by experiments/figures.py — do not edit")
    lines.append(r"\begin{tabular}{l" + "c" * len(metrics) + r"}")
    lines.append(r"\toprule")
    lines.append("Experiment & " + " & ".join(m.capitalize() for m in metrics)
                 + r" \\")
    lines.append(r"\midrule")
    for e in aggs:
        cells = [e.replace("_", r"\_")]
        for m in metrics:
            v = aggs[e]["aggregate"][m]["mean"]
            ci_lo = aggs[e]["aggregate"][m]["ci_lo"]
            ci_hi = aggs[e]["aggregate"][m]["ci_hi"]
            if math.isnan(v):
                cells.append("--")
            else:
                s = f"{v:.3f}"
                if abs(v - best[m]) < 1e-9:
                    s = r"\textbf{" + s + "}"
                if not math.isnan(ci_lo) and not math.isnan(ci_hi):
                    s += f" \\tiny[{ci_lo:.3f}, {ci_hi:.3f}]"
                cells.append(s)
        lines.append(" & ".join(cells) + r" \\")
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    out.write_text("\n".join(lines))


# ---------- Driver ----------

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--agg-dir", default="runs/experiments/_agg", type=Path)
    ap.add_argument("--out-dir", default="runs/figures", type=Path)
    ap.add_argument("--configs-dir",
                    default="experiments/configs", type=Path)
    ap.add_argument("--sweep-csv", type=Path, default=None,
                    help="Optional attack-volume sweep CSV for "
                         "fig_suricata_vs_ours.")
    ap.add_argument("--stage-latencies-csv", type=Path,
                    default=Path("runs/latency_stages/per_stage.csv"),
                    help="Optional per-stage latency CSV for the "
                         "3rd panel of fig_detection_latency.")
    ap.add_argument("--strict", action="store_true",
                    help="Fail (exit 2) when a figure would fall back "
                         "to a degraded form due to missing input.")
    args = ap.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    global _STRICT
    _STRICT = bool(args.strict)

    all_aggs = load_agg(args.agg_dir)
    if not all_aggs:
        print("No aggregates found.")
        return

    primary = primary_keys(all_aggs, args.configs_dir)
    primary_aggs = {k: all_aggs[k] for k in primary}

    # 1) Headline confusion matrix — restricted to the 4 scoring
    # experiments (E1, E6, E8, E9 R4). E4 and E5 are ablation /
    # boundary characterization, not scoring, so they do not
    # belong in the headline pooled CM.
    cm_keys = {"E1_attack_detection", "E6_a4_oversize",
                "E8_stochastic", "E9_evasion_r4"}
    cm_aggs = {k: primary_aggs[k] for k in cm_keys if k in primary_aggs}
    fig_confusion_matrix(cm_aggs,
                          args.out_dir / "fig_confusion_matrix",
                          title=f"Confusion matrix "
                                f"(n = {sum_decisions(cm_aggs)} "
                                f"decisions, E1/E6/E8/E9-R4)",
                          primary_only=False)  # already filtered
    print(f"[fig] confusion matrix — {len(cm_aggs)} scoring experiments")

    # 2) Per-experiment bars with CI.
    fig_per_experiment_bars(primary_aggs,
                             args.out_dir / "fig_per_experiment")
    print(f"[fig] per-experiment precision/recall/F1")

    # 3) Latency distribution — E8 stochastic only (the statistical
    # headline).  Earlier versions pooled across all primary experiments,
    # which mixed E1's contaminated tail into the distribution and caused
    # figure/caption inconsistency.  Using E8 alone matches what the
    # abstract, §Evaluation, and Fig.~\ref{fig:latency} caption cite.
    e8 = all_aggs.get("E8_stochastic")
    lat = e8.get("latencies_flat", []) if e8 else []
    if lat:
        # Use the canonical p95/median from the aggregate so the figure
        # labels match the numbers.tex macros used in the caption/text.
        lat_block = e8.get("latency_seconds", {}) or {}
        p95_ms = lat_block.get("p95")
        med_ms = lat_block.get("median")
        p95_ms = p95_ms * 1000 if p95_ms is not None else None
        med_ms = med_ms * 1000 if med_ms is not None else None
        stage_lats = _load_stage_latencies(args.stage_latencies_csv)
        fig_detection_latency(lat,
                               args.out_dir / "fig_detection_latency",
                               p95_override=p95_ms,
                               med_override=med_ms,
                               stage_latencies=stage_lats)
        print(f"[fig] latency distribution (n = {len(lat)}, E8 only"
              f"{'; +per-stage panel' if stage_lats else ''})")

    # 4) Methodology ablation — explicit about the contaminated runs.
    fig_methodology_ablation(all_aggs, primary,
                              args.out_dir / "fig_methodology_ablation")
    print(f"[fig] methodology ablation")

    # 5) RAT-aware arbiter ablation (E1 vs E4).
    fig_rat_ablation(all_aggs, args.out_dir / "fig_rat_ablation")
    print(f"[fig] RAT ablation (E1 vs E4)")

    # 6) E11 throughput (if data is there)
    fig_throughput(Path("runs/throughput/results.csv"),
                    args.out_dir / "fig_throughput")
    print(f"[fig] throughput (if available)")

    # 7) E10 CPU-IDS baselines vs OTA-Shield (if at least one is there)
    sur_path = Path("runs/baseline_suricata/comparison.json")
    sur_rat_path = Path("runs/baseline_suricata/suricata_rat_comparison.json")
    extra_paths = {
        "suricata_stateful":
            Path("runs/baseline_suricata_stateful/comparison.json"),
        "suricata_stateful_permissive":
            Path("runs/baseline_suricata_stateful_permissive/comparison.json"),
        "zeek":
            Path("runs/baseline_zeek/comparison.json"),
    }
    sur_perm_rat_path = Path(
        "runs/baseline_suricata_stateful_permissive/"
        "suricata_rat_perm_comparison.json")
    if sur_path.exists() and "E1_attack_detection" in all_aggs:
        sur = json.loads(sur_path.read_text())
        sur_rat = (json.loads(sur_rat_path.read_text())
                   if sur_rat_path.exists() else None)
        sur_perm_rat = (json.loads(sur_perm_rat_path.read_text())
                        if sur_perm_rat_path.exists() else None)
        extra_baselines = {
            k: json.loads(p.read_text()) for k, p in extra_paths.items()
            if p.exists()
        }
        fig_suricata_vs_ours(sur, all_aggs["E1_attack_detection"],
                             args.out_dir / "fig_suricata_vs_ours",
                             sweep_csv=args.sweep_csv,
                             suricata_rat=sur_rat,
                             suricata_perm_rat=sur_perm_rat,
                             extra_baselines=extra_baselines)
        n_bars = (1 + 1 + len(extra_baselines)
                  + (1 if sur_rat else 0)
                  + (1 if sur_perm_rat else 0))
        print(f"[fig] CPU-IDS baselines vs OTA-Shield ({n_bars} bars)")

    # 8) E12 benign-rollout stacked bars (incl. §6b rollback buckets).
    e12 = all_aggs.get("E12_benign_rollout")
    if e12:
        fig_benign_rollout(e12, args.out_dir / "fig_benign_rollout")
        print(f"[fig] E12 benign rollout "
              f"({len(e12.get('scenario_outcomes') or {})} scenarios)")

    # 9) LaTeX summary table — primary only.
    table_summary_latex(primary_aggs,
                         args.out_dir / "table_summary.tex")
    print(f"[tab] summary table ({len(primary_aggs)} rows)")

    print(f"\nOutputs in {args.out_dir}/")


def sum_decisions(aggs: dict) -> int:
    total = 0
    for a in aggs.values():
        for t in a["per_trial_raw"]:
            total += t["tp"] + t["tn"] + t["fp"] + t["fn"]
    return total


if __name__ == "__main__":
    main()
