"""Post-process throughput stamps + switch controller log into a results
CSV. Runs on laptop after scp'ing both files back.

Honest counting: for each (t_start, t_end) window we count controller log
lines whose `_t_recv` timestamp falls within the window. No per-rate SSH,
no password prompts, no rate-dependent measurement artefact.

Usage:
    python3 experiments/throughput_correlate.py \
        --stamps runs/throughput/stamps.jsonl \
        --controller-log runs/throughput/controller.jsonl \
        --out runs/throughput/results.csv
"""
from __future__ import annotations
import argparse, json
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stamps", required=True, type=Path)
    ap.add_argument("--controller-log", required=True, type=Path)
    ap.add_argument("--out", default="runs/throughput/results.csv",
                    type=Path)
    args = ap.parse_args()

    # Load all digests with _t_recv timestamps.
    digests = []
    for line in args.controller_log.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Count any non-rule digest with a receive timestamp. Throughput
        # traffic to 10.0.2.200 classifies as mqtt_digest (because the
        # packet carries an OTA header with has_ota_hdr=1) rather than
        # classify_digest, so we accept both.
        if d.get("_type") in ("classify_digest", "mqtt_digest") and d.get("_t_recv"):
            digests.append(float(d["_t_recv"]))
    digests.sort()
    print(f"Loaded {len(digests)} classify_digests from controller log")
    if digests:
        print(f"  Controller log t range: {digests[0]:.1f} .. {digests[-1]:.1f}")
    # Load stamps and report clock skew
    stamp_times = []
    for line in args.stamps.read_text().splitlines():
        if line.strip():
            s = json.loads(line)
            stamp_times.append(s["t_start"])
    if stamp_times:
        print(f"  Vision stamp t range:  {min(stamp_times):.1f} .. {max(stamp_times):.1f}")
        if digests:
            skew = digests[0] - min(stamp_times)
            print(f"  Approx clock offset (switch - vision): {skew:+.1f} s")

    # Process each stamp window.
    args.out.parent.mkdir(parents=True, exist_ok=True)
    rows = ["offered_pps,duration_s,sent_packets,observed_digests,"
            "loss_pct,realised_pps,observed_rate_pps"]
    # Auto-align by matching the END of the controller log to the END of
    # the stamp series. The controller log may contain days of older
    # history; our throughput test is always at the tail.
    offset = 0.0
    if digests and stamp_times:
        offset = digests[-1] - max(stamp_times)
        print(f"  Auto-applying offset {offset:+.1f}s to all stamp windows "
              "(aligned on log tail)")

    for line in args.stamps.read_text().splitlines():
        if not line.strip():
            continue
        s = json.loads(line)
        # Wider padding (30s) + apply the measured clock offset.
        lo = s["t_start"] + offset - 5.0
        hi = s["t_end"]   + offset + 30.0
        observed = sum(1 for t in digests if lo <= t <= hi)
        sent = s["sent"]
        dur = s["duration_s"]
        realised = sent / (s["t_end"] - s["t_start"]) if s["t_end"] > s["t_start"] else 0
        loss_pct = (1 - observed / sent) * 100 if sent else 0
        obs_rate = observed / (hi - lo) if (hi - lo) else 0
        rows.append(f"{s['rate_pps_target']},{dur},{sent},{observed},"
                    f"{loss_pct:.2f},{realised:.0f},{obs_rate:.0f}")
        print(f"  target={s['rate_pps_target']}pps "
              f"sent={sent} realised={realised:.0f}pps "
              f"observed={observed} loss={loss_pct:.2f}%")

    args.out.write_text("\n".join(rows) + "\n")
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
