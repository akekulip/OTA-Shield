"""E13 post-processor — reconstruct active override count over time
from the controller decision log, then align with the install-rate
windows in stamps.jsonl.

Each PASS or DROP decision in decisions.jsonl corresponds to exactly
one override install. With TTL=5s, an entry installed at time `t`
contributes to the active count during [t, t+TTL_S).

Outputs:
  runs/override_capacity/active_over_time.csv
    rate_pps_target, t_rel_s, n_active, n_installed, window_id
  runs/override_capacity/summary.csv
    rate_pps_target, peak_active, total_installs, time_to_saturation_s

The 1024-entry table limit is the saturation boundary. The plot
shows the active-count trajectory per offered-rate curve.
"""
from __future__ import annotations
import argparse, json
from pathlib import Path

TTL_S = 5.0
TABLE_CAP = 1024


def load_jsonl(p: Path) -> list[dict]:
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stamps",
                    default="runs/override_capacity/stamps.jsonl",
                    type=Path)
    ap.add_argument("--decisions",
                    default="runs/override_capacity/decisions.jsonl",
                    type=Path)
    ap.add_argument("--out-dir",
                    default="runs/override_capacity", type=Path)
    ap.add_argument("--ttl-s", type=float, default=TTL_S)
    ap.add_argument("--bin-ms", type=int, default=100,
                    help="time resolution (ms) for active-count curve")
    args = ap.parse_args()

    stamps = load_jsonl(args.stamps)
    decisions = load_jsonl(args.decisions)
    if not stamps:
        print(f"No stamps in {args.stamps}")
        return
    if not decisions:
        print(f"No decisions in {args.decisions}; did you scp the "
               "controller log?")
        return

    # install times sorted
    install_ts = sorted(float(d["t"]) for d in decisions
                        if d.get("decision") in ("PASS", "DROP"))
    bin_s = args.bin_ms / 1000.0

    args.out_dir.mkdir(parents=True, exist_ok=True)
    curve_rows = ["rate_pps_target,t_rel_s,n_active,n_installed,window_id"]
    summary_rows = ["rate_pps_target,peak_active,total_installs,"
                     "time_to_saturation_s"]

    for wid, w in enumerate(stamps):
        t0 = float(w["t_start"])
        t1 = float(w["t_end"])
        window_end_obs = t1 + args.ttl_s  # let TTLs fully expire
        # Filter installs inside this window (+ a short pre-roll to
        # catch late-arriving digests from the prior rest).
        wins_installs = [t for t in install_ts
                         if t0 - 1.0 <= t <= window_end_obs]
        # Active count = number of installs whose [install_t, install_t+TTL]
        # interval covers the bin midpoint.
        if not wins_installs:
            peak = 0; total = 0; sat_t = -1.0
        else:
            peak = 0; sat_t = -1.0
            t_cur = t0
            cumulative = 0
            while t_cur <= window_end_obs:
                active = sum(1 for it in wins_installs
                             if it <= t_cur <= it + args.ttl_s)
                cumulative = sum(1 for it in wins_installs if it <= t_cur)
                curve_rows.append(
                    f"{w['rate_pps_target']},"
                    f"{t_cur - t0:.3f},"
                    f"{active},"
                    f"{cumulative},"
                    f"{wid}")
                if active > peak:
                    peak = active
                if active >= TABLE_CAP and sat_t < 0:
                    sat_t = t_cur - t0
                t_cur += bin_s
            total = len(wins_installs)
        summary_rows.append(
            f"{w['rate_pps_target']},{peak},{total},"
            f"{sat_t if sat_t >= 0 else 'never'}")
        print(f"rate={w['rate_pps_target']}pps  peak_active={peak}  "
              f"total_installs={total}  "
              f"sat={sat_t if sat_t >= 0 else 'never'}s")

    (args.out_dir / "active_over_time.csv").write_text(
        "\n".join(curve_rows) + "\n")
    (args.out_dir / "summary.csv").write_text(
        "\n".join(summary_rows) + "\n")
    print(f"Wrote {args.out_dir}/active_over_time.csv and summary.csv")


if __name__ == "__main__":
    main()
