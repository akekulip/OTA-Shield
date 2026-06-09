"""E5 analysis — R5 decision-boundary characterization.

E5 is a controlled sweep of fanout size N ∈ {3,4,5,6,7}. For each N:
  ground_truth.json has N events with scenario="a1_fleet_fanout" and
  the `note` field encodes position (fanout i/N). We compute:

    P(R5 fires | fanout size = N) = fraction of events in that fanout
                                     whose hold_digest shows r5_fired = 1

Because the ground truth for ALL E5 events is label="LEGIT" (authorized
source, authorized BMSes, size in RAT range), R5 firing is NOT an error;
it is the detector's sensitivity. Paired with the RAT arbiter it still
resolves to PASS — so we also report fraction PASS per fanout.

Produces a figure: fanout_size (x) vs P(R5 fire) and P(PASS) (y).
"""
from __future__ import annotations
import argparse, json, re
from collections import defaultdict
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np

import figures  # reuse STYLE from figures.py
_ = figures  # keep linter happy; mpl rcParams already applied on import


def load_trial(tdir: Path) -> tuple[list[dict], dict[tuple, dict], dict[tuple, dict]]:
    gt = json.loads((tdir / "ground_truth.json").read_text())
    digests = {}
    for p in [tdir / "decisions.jsonl"]:
        if not p.exists():
            continue
        for line in p.read_text().splitlines():
            if not line.strip():
                continue
            d = json.loads(line)
            key = (int(d.get("src_ip", 0)),
                   int(d.get("dst_ip", 0)),
                   int(d.get("src_port", 0)))
            if d.get("_type") == "hold_digest":
                digests[key] = d
            elif key not in digests:
                digests[key] = d
    ctrl = {}
    cp = tdir / "controller_decisions.jsonl"
    if cp.exists():
        for line in cp.read_text().splitlines():
            if not line.strip():
                continue
            d = json.loads(line)
            # Skip barrier/reset markers and any record that isn't a
            # per-flow decision.
            if "_marker" in d or "src_ip" not in d:
                continue
            key = (int(d["src_ip"]), int(d["dst_ip"]), int(d["src_port"]))
            ctrl[key] = d
    return gt["events"], digests, ctrl


def ip_int(ip: str) -> int:
    p = ip.split(".")
    return (int(p[0]) << 24) | (int(p[1]) << 16) | (int(p[2]) << 8) | int(p[3])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp-dir",
                    default="runs/experiments/E5_adversarial", type=Path)
    ap.add_argument("--out",
                    default="runs/figures/fig_r5_boundary", type=Path)
    args = ap.parse_args()

    # Aggregate per-fanout-size counts across trials.
    per_fanout = defaultdict(lambda: {"n": 0, "r5_fires": 0, "pass": 0,
                                       "drop": 0, "no_decision": 0})
    pat = re.compile(r"fanout (\d+)/(\d+)")

    for tdir in sorted(args.exp_dir.glob("t*")):
        events, digests, ctrl = load_trial(tdir)
        for ev in events:
            m = pat.search(ev.get("note", ""))
            if not m:
                continue
            fanout_total = int(m.group(2))
            key = (ip_int(ev["src_ip"]), ip_int(ev["dst_ip"]),
                   int(ev["src_port"]))
            bucket = per_fanout[fanout_total]
            bucket["n"] += 1
            d = digests.get(key)
            if d is None:
                bucket["no_decision"] += 1
                continue
            if int(d.get("r5_fired", 0)) == 1:
                bucket["r5_fires"] += 1
            c = ctrl.get(key)
            if c is None:
                # no rule fired → forwarded → PASS (real data-plane obs)
                bucket["pass"] += 1
            else:
                if c["decision"] == "PASS":
                    bucket["pass"] += 1
                else:
                    bucket["drop"] += 1

    if not per_fanout:
        print(f"No E5 data in {args.exp_dir}")
        return

    sizes = sorted(per_fanout)
    n_vals  = np.array([per_fanout[s]["n"] for s in sizes])
    r5_vals = np.array([per_fanout[s]["r5_fires"] for s in sizes])
    pass_vals = np.array([per_fanout[s]["pass"] for s in sizes])
    drop_vals = np.array([per_fanout[s]["drop"] for s in sizes])

    p_r5   = r5_vals / np.maximum(n_vals, 1)
    p_pass = pass_vals / np.maximum(n_vals, 1)

    fig, ax = plt.subplots(figsize=(figures.COL_W, 2.4))
    ax.plot(sizes, p_r5, "o-", color="#d95f02", lw=1.1, ms=4,
            label=r"P(R5 fires)")
    ax.plot(sizes, p_pass, "s--", color="#1b9e77", lw=1.0, ms=4,
            label=r"P(controller PASS)")
    ax.axvline(4, color="#888", lw=0.6, linestyle=":")
    ax.text(4.05, 0.05, "R5\nthreshold", fontsize=7, color="#444")
    ax.set_xlabel("fanout n (total events in window)")
    ax.set_ylabel("Probability")
    # Two-line tick labels: bottom = fanout n, top = total events.
    ax.set_xticks(sizes)
    ax.set_xticklabels([f"{s}\n({n})" for s, n in zip(sizes, n_vals)],
                        fontsize=9)
    ax.set_ylim(-0.03, 1.05)
    ax.legend(loc="center right")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.out.with_suffix(".pdf"),
                bbox_inches="tight", pad_inches=0.02)
    fig.savefig(args.out.with_suffix(".png"),
                bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)

    # Dump CSV for reproducibility / paper prose.
    csv_path = args.out.with_suffix(".csv")
    with csv_path.open("w") as f:
        f.write("fanout_size,n,r5_fires,p_r5_fire,passes,drops,p_pass\n")
        for s in sizes:
            b = per_fanout[s]
            f.write(f"{s},{b['n']},{b['r5_fires']},"
                    f"{b['r5_fires']/max(b['n'],1):.4f},"
                    f"{b['pass']},{b['drop']},"
                    f"{b['pass']/max(b['n'],1):.4f}\n")
    print(f"Wrote {args.out}.pdf / .png and {csv_path}")


if __name__ == "__main__":
    main()
