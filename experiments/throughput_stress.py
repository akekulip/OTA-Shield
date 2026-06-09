"""E11 — Controller throughput stress test.

Generates a controlled-rate stream of OTA PUBLISHes from vision and
measures the controller's digest-handling rate. Honest measurements only:
report the offered load, the realised digest rate at the controller, and
the gap (digest loss).

Output: runs/throughput/results.csv with columns
  offered_pps,duration_s,sent_packets,observed_digests,loss_pct,p95_latency_ms

Honest limits:
  - Realised pps capped by scapy/Linux raw socket throughput on vision.
    For true line-rate (25 Gb/s) testing, swap scapy for pktgen-DPDK and
    re-run; this harness is the SCAPY-LIMITED ceiling and we report it
    as such in the paper §5.5.
  - "Observed digests" counts entries the controller wrote to its log
    during the run window. Tofino digest-quanta loss IS counted as loss.
"""
from __future__ import annotations
import argparse, json, struct, subprocess, time
from pathlib import Path

from scapy.all import Ether, IP, TCP, Raw, sendp


IFACE   = "enp59s0f0np0"
SRC_IP  = "10.0.1.10"
SRC_MAC = "00:00:00:00:10:10"
DST_MAC = "00:00:00:00:20:ff"


def _varint(n: int) -> bytes:
    o = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        o.append(b)
        if not n: break
    return bytes(o)


def _publish(topic: str) -> bytes:
    t = topic.encode().ljust(32, b"\x00")
    pl = b"OTAS" + struct.pack(">II", 48, 1024) + b"\x00" * 8
    var = struct.pack(">H", 32) + t + struct.pack(">H", 1) + pl
    return bytes([0x32]) + _varint(len(var)) + var


def burst(target_pps: int, duration_s: int) -> int:
    """Throughput measurement: all packets target the SAME BMS so R5 does
    NOT fire (no override installs). This isolates pipeline + digest-
    transport throughput from the override-table capacity limit, which
    is measured separately in the session-override-capacity experiment."""
    n = target_pps * duration_s
    pkts = []
    # Destination is OUTSIDE the authorized BMS fleet (10.0.2.10..59). The
    # bms_ip_to_idx lookup misses → bms_known=0, so R1/R4/R5 all skip
    # (each gates on bms_known==1). Authorized source means R2 doesn't
    # fire either. The pipeline classifies each packet (classify_digest)
    # without installing any override, isolating pipeline + digest-
    # transport throughput from the override-table capacity limit.
    dst = "10.0.2.200"
    topic = "/monitor/probe/00"   # also outside /ota/bms/ prefix
    for i in range(n):
        pkts.append((Ether(src=SRC_MAC, dst=DST_MAC) /
                     IP(src=SRC_IP, dst=dst) /
                     TCP(sport=49152 + (i % 16000), dport=1883,
                         flags="PA", seq=1, ack=1) /
                     Raw(_publish(topic))))
    t0 = time.time()
    # Send in batches to amortize syscall overhead; report wall-clock.
    BATCH = 200
    sent = 0
    for i in range(0, n, BATCH):
        sendp(pkts[i:i+BATCH], iface=IFACE, verbose=False)
        sent += min(BATCH, n - i)
    elapsed = time.time() - t0
    print(f"target={target_pps}pps  sent={sent} in {elapsed:.2f}s "
          f"(realised={sent/elapsed:.0f}pps)")
    return sent


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rates", nargs="+", type=int,
                    default=[100, 500, 1000, 5000, 10000])
    ap.add_argument("--duration", type=int, default=10)
    ap.add_argument("--out-csv", default="runs/throughput/results.csv",
                    type=Path)
    ap.add_argument("--switch-host", default="decps@10.10.54.15")
    ap.add_argument("--controller-log",
                    default="/home/decps/my_program/ota/runs/phase6_digests.jsonl")
    args = ap.parse_args()

    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    rows = ["offered_pps,duration_s,sent_packets,observed_digests,loss_pct"]

    # Stamp markers locally into a file on Vision. The switch's controller
    # log is the ground truth for what arrived; we pull it ONCE at the end
    # via scp. No per-rate SSH round-trips, no password prompts.
    stamp_path = Path("/tmp/throughput_stamps.jsonl")
    if stamp_path.exists():
        stamp_path.unlink()

    for rate in args.rates:
        t_start = time.time()
        sent = burst(rate, args.duration)
        t_end = time.time()
        time.sleep(args.duration + 5)   # let digests drain to switch
        # Local stamp of this rate window
        with stamp_path.open("a") as f:
            f.write(json.dumps({
                "rate_pps_target": rate,
                "sent": sent,
                "t_start": t_start,
                "t_end": t_end,
                "duration_s": args.duration,
            }) + "\n")
        print(f"target={rate}pps sent={sent} "
              f"in {t_end - t_start:.2f}s (local only; "
              f"post-hoc match via switch log timestamps)")
        time.sleep(60)  # let R5 window clear

    # Write a placeholder CSV that the post-processor will fill once the
    # switch log is pulled.
    rows.append("# Raw stamps at /tmp/throughput_stamps.jsonl")
    rows.append("# Run throughput_correlate.py on laptop after scp'ing the")
    rows.append("# switch's controller log to produce the final CSV.")
    for line in stamp_path.read_text().splitlines():
        rec = json.loads(line)
        rows.append(f"{rec['rate_pps_target']},"
                    f"{rec['duration_s']},"
                    f"{rec['sent']},"
                    f"pending,"
                    f"pending")

    args.out_csv.write_text("\n".join(rows) + "\n")
    print(f"Wrote {args.out_csv}")


if __name__ == "__main__":
    main()
