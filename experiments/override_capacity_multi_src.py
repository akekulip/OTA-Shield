"""E13 multi-source sweep — measures the P4-level src-IP-keyed
session_action_override table cap by varying source-IP cardinality.

Traffic: each packet cycles through N_SRC distinct source IPs in
10.0.1.10..10.0.1.(10+N_SRC-1), each targeting distinct BMS IPs so
R5's distinct-BMS counter fires. Expect peak active overrides to
equal min(N_SRC, 64) — the table size.

Output: runs/override_capacity_e13_src_sweep/stamps.jsonl
"""
from __future__ import annotations
import argparse, json, struct, time
from pathlib import Path

from scapy.all import Ether, IP, TCP, Raw, sendp


IFACE   = "enp59s0f0np0"
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


def _publish(topic: str, size: int = 1024) -> bytes:
    t = topic.encode().ljust(32, b"\x00")
    pl = b"OTAS" + struct.pack(">II", 48, size) + b"\x00" * 8
    var = struct.pack(">H", 32) + t + struct.pack(">H", 1) + pl
    return bytes([0x32]) + _varint(len(var)) + var


def install_burst(target_pps: int, duration_s: int,
                   n_src: int, n_bms: int = 50,
                   sport_start: int = 40000) -> int:
    n = target_pps * duration_s
    pkts = []
    for i in range(n):
        src_ip = f"10.0.1.{10 + (i % n_src)}"
        bms = 10 + (i % n_bms)
        dst = f"10.0.2.{bms}"
        topic = f"/ota/bms/{(i % n_bms):02d}"
        sport = sport_start + (i % 5000)
        pkts.append((Ether(src=SRC_MAC, dst=DST_MAC) /
                     IP(src=src_ip, dst=dst) /
                     TCP(sport=sport, dport=1883,
                         flags="PA", seq=1, ack=1) /
                     Raw(_publish(topic))))
    t0 = time.time()
    sendp(pkts, iface=IFACE, verbose=False)
    elapsed = max(time.time() - t0, 0.001)
    print(f"target={target_pps}pps sent={n} in {elapsed:.2f}s "
          f"(realised={n/elapsed:.0f}pps) n_src={n_src}")
    return n


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src-counts", nargs="+", type=int,
                    default=[1, 10, 32, 64, 100, 200])
    ap.add_argument("--rate", type=int, default=500,
                    help="offered pps per window")
    ap.add_argument("--duration", type=int, default=10)
    ap.add_argument("--rest", type=int, default=30)
    ap.add_argument("--out-dir",
                    default="runs/override_capacity_e13_src_sweep",
                    type=Path)
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    stamp_path = args.out_dir / "stamps.jsonl"
    if stamp_path.exists():
        stamp_path.unlink()

    for n_src in args.src_counts:
        t_start = time.time()
        sent = install_burst(args.rate, args.duration, n_src=n_src)
        t_end = time.time()
        with stamp_path.open("a") as f:
            f.write(json.dumps({
                "rate_pps_target": args.rate,
                "n_src": n_src,
                "sent": sent,
                "t_start": t_start,
                "t_end": t_end,
                "duration_s": args.duration,
            }) + "\n")
        print(f"rest {args.rest}s...")
        time.sleep(args.rest)

    print(f"Wrote {stamp_path}")


if __name__ == "__main__":
    main()
