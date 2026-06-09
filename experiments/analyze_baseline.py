"""E7 baseline-trace analyzer — derives empirically grounded thresholds
from a long legitimate-traffic run.

Reads `runs/experiments/E7_long_baseline/t*/ground_truth.json` and the
matching controller `decisions.jsonl` slices, then computes:

  - Distribution of distinct-BMS-count per 60 s window  (justifies R5)
  - Per-BMS inter-rollout interval distribution         (justifies R1)
  - Firmware-size distribution                          (justifies R4)

Outputs JSON + CSV at `runs/baseline_thresholds.{json,csv}` and IEEE-style
PDF figures at `runs/figures/fig_threshold_derivation.{pdf,png}`.

These outputs are paper artefacts: the R5/R1/R4 threshold sentences in §4
should cite numbers from the JSON, not assert them a priori.
"""
from __future__ import annotations
import argparse, json, statistics
from collections import defaultdict
from pathlib import Path

import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt

import figures  # for STYLE


def load_events(exp_dir: Path) -> list[dict]:
    out = []
    for tdir in sorted(exp_dir.glob("t*")):
        gt_path = tdir / "ground_truth.json"
        if not gt_path.exists():
            continue
        d = json.loads(gt_path.read_text())
        out.extend(d.get("events", []))
    out.sort(key=lambda e: e["t_send"])
    return out


def percentile(values: list[float], q: float) -> float:
    if not values:
        return float("nan")
    return float(np.percentile(values, q))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp-dir",
                    default="runs/experiments/E7_long_baseline", type=Path)
    ap.add_argument("--out-json",
                    default="runs/baseline_thresholds.json", type=Path)
    ap.add_argument("--out-fig",
                    default="runs/figures/fig_threshold_derivation",
                    type=Path)
    ap.add_argument("--window-s", type=int, default=60)
    args = ap.parse_args()

    events = load_events(args.exp_dir)
    if not events:
        print(f"No baseline events in {args.exp_dir} — run E7 first.")
        return

    # ---- Distinct-BMS-count per W-second sliding window (R5 metric) ----
    times = [e["t_send"] for e in events]
    dsts  = [e["dst_ip"]  for e in events]
    counts: list[int] = []
    # Step the window in 1-second hops; count distinct BMSes seen in
    # [t-W, t). This matches Bloom-window semantics (60s clear).
    t0, tN = times[0], times[-1]
    cur = t0 + args.window_s
    j = 0
    bms_in_win: dict[str, float] = {}
    while cur <= tN:
        # Advance left edge
        while j < len(times) and times[j] < cur - args.window_s:
            j += 1
        # Recount distinct BMSes in [cur - W, cur)
        seen = {dsts[k] for k in range(j, len(times)) if times[k] < cur}
        counts.append(len(seen))
        cur += 1.0   # 1-Hz sampling

    # ---- Per-BMS inter-rollout intervals (R1 metric) ----
    last_seen: dict[str, float] = {}
    intervals: list[float] = []
    for e in events:
        prev = last_seen.get(e["dst_ip"])
        if prev is not None:
            intervals.append(e["t_send"] - prev)
        last_seen[e["dst_ip"]] = e["t_send"]

    # ---- Firmware sizes (R4 metric) ----
    sizes = [int(e["ota_size"]) for e in events]

    summary = {
        "n_events":   len(events),
        "duration_s": tN - t0,
        "window_s":   args.window_s,
        "distinct_bms_per_window": {
            "n_windows": len(counts),
            "mean":   statistics.mean(counts) if counts else float("nan"),
            "median": statistics.median(counts) if counts else float("nan"),
            "max":    max(counts) if counts else 0,
            "p99":    percentile(counts, 99),
            "p99_9":  percentile(counts, 99.9),
            "p99_99": percentile(counts, 99.99),
        },
        "per_bms_interval_s": {
            "n":       len(intervals),
            "mean":    statistics.mean(intervals) if intervals else float("nan"),
            "median":  statistics.median(intervals) if intervals else float("nan"),
            "min":     min(intervals) if intervals else float("nan"),
            "p1":      percentile(intervals, 1),
            "p0_1":    percentile(intervals, 0.1),
        },
        "firmware_size_bytes": {
            "n":      len(sizes),
            "mean":   statistics.mean(sizes) if sizes else float("nan"),
            "max":    max(sizes) if sizes else 0,
            "p99":    percentile(sizes, 99),
            "p99_9":  percentile(sizes, 99.9),
        },
        "threshold_recommendations": {
            "R5_count":   max(int(percentile(counts, 99.9)) + 1, 4),
            "R1_min_s":   max(int(percentile(intervals, 0.1)) - 1, 1),
            "R4_max_B":   int(max(sizes) * 1.05) if sizes else None,
        },
    }
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(summary, indent=2))
    print(f"Wrote {args.out_json}")
    print(f"  R5 P99.9 distinct-BMS = {summary['distinct_bms_per_window']['p99_9']:.1f}")
    print(f"  R1 P0.1 interval (s)   = {summary['per_bms_interval_s']['p0_1']:.1f}")
    print(f"  R4 P99.9 size (B)      = {summary['firmware_size_bytes']['p99_9']:.0f}")

    # ---- Figure: 3-panel threshold derivation ----
    fig, axes = plt.subplots(1, 3, figsize=(figures.COL2_W, 2.2),
                              gridspec_kw={"wspace": 0.35})

    if counts:
        axes[0].hist(counts, bins=range(0, max(counts) + 2),
                     color="#1f77b4", edgecolor="black", linewidth=0.3)
        axes[0].axvline(summary["threshold_recommendations"]["R5_count"],
                        color="black", linestyle="--", lw=0.7)
        axes[0].set_xlabel("Distinct BMSes / 60 s window")
        axes[0].set_ylabel("Count")
        axes[0].set_title("(a) R5 baseline", loc="left", pad=4)

    if intervals:
        # Log-scale x because intervals span seconds to hours
        log_iv = [max(i, 0.01) for i in intervals]
        axes[1].hist(log_iv, bins=np.geomspace(0.01,
                          max(log_iv) + 1, 30),
                     color="#2ca02c", edgecolor="black", linewidth=0.3)
        axes[1].set_xscale("log")
        axes[1].set_xlabel("Per-BMS interval (s, log)")
        axes[1].set_ylabel("Count")
        axes[1].set_title("(b) R1 baseline", loc="left", pad=4)

    if sizes:
        axes[2].hist([s / 1024 for s in sizes], bins=30,
                     color="#d62728", edgecolor="black", linewidth=0.3)
        axes[2].set_xlabel("Firmware size (KiB)")
        axes[2].set_ylabel("Count")
        axes[2].set_title("(c) R4 baseline", loc="left", pad=4)

    out_pdf = args.out_fig.with_suffix(".pdf")
    out_png = args.out_fig.with_suffix(".png")
    out_pdf.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_pdf, bbox_inches="tight", pad_inches=0.02)
    fig.savefig(out_png, bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)
    print(f"Wrote {out_pdf} / {out_png}")


if __name__ == "__main__":
    main()
