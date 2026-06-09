"""E13 — session-override table capacity experiment.

Drives the override-install rate by sending distinct-5-tuple packets
to many distinct BMSes so each R5 fire produces a unique
session_override entry. Measures active override count over time
(reconstructed from the controller log) until the 1024-entry table
saturates.

Design:
  - Target the AUTHORIZED BMS range 10.0.2.10--59 so bms_known=1 and
    R5's distinct-BMS counter is active.
  - Sweep through many distinct source ports so each packet is a new
    5-tuple; every R5 fire yields a unique session_override install.
  - Multiple offered rates; each run writes a local stamp so the
    post-processor can align installs with windows.

Output: runs/override_capacity/stamps.jsonl  (one row per rate)
Post-processor: override_capacity_correlate.py converts the
controller log into an `active_overrides_over_time.csv` per window.

Honest limits:
  - Scapy ceiling (~2200 pps) still applies on this host.
  - Controller TTL is compile-time-fixed at 5 s in this run; for a
    real TTL sweep restart the controller with the intended TTL
    between windows.
"""
from __future__ import annotations
import argparse, json, struct, time
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


def _publish(topic: str, size: int = 1024) -> bytes:
    t = topic.encode().ljust(32, b"\x00")
    pl = b"OTAS" + struct.pack(">II", 48, size) + b"\x00" * 8
    var = struct.pack(">H", 32) + t + struct.pack(">H", 1) + pl
    return bytes([0x32]) + _varint(len(var)) + var


def install_burst(target_pps: int, duration_s: int,
                   n_bms: int = 50, sport_start: int = 40000,
                   sport_cycle: int = 5000) -> int:
    """Send at `target_pps` for `duration_s`, cycling through
    `n_bms` distinct BMSes with fresh source ports so each packet is
    a unique 5-tuple. Once R5's 60s-window count exceeds 4, every
    additional distinct BMS triggers a HOLD → override install.
    """
    n = target_pps * duration_s
    pkts = []
    for i in range(n):
        bms = 10 + (i % n_bms)
        dst = f"10.0.2.{bms}"
        topic = f"/ota/bms/{(i % n_bms):02d}"
        # Each packet gets a unique sport so its 5-tuple is distinct.
        sport = sport_start + (i % sport_cycle)
        # Offset into a 2nd port range if cycle wraps within a run to
        # avoid 5-tuple reuse.
        if (i // sport_cycle) % 2:
            sport += sport_cycle
        pkts.append((Ether(src=SRC_MAC, dst=DST_MAC) /
                     IP(src=SRC_IP, dst=dst) /
                     TCP(sport=sport, dport=1883,
                         flags="PA", seq=1, ack=1) /
                     Raw(_publish(topic))))
    t0 = time.time()
    BATCH = 200
    sent = 0
    for i in range(0, n, BATCH):
        sendp(pkts[i:i+BATCH], iface=IFACE, verbose=False)
        sent += min(BATCH, n - i)
    elapsed = time.time() - t0
    print(f"target={target_pps}pps sent={sent} in {elapsed:.2f}s "
          f"(realised={sent/elapsed:.0f}pps)")
    return sent


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rates", nargs="+", type=int,
                    default=[100, 250, 500, 1000])
    ap.add_argument("--duration", type=int, default=10,
                    help="seconds per rate window")
    ap.add_argument("--rest", type=int, default=60,
                    help="seconds between rates to let TTL expire")
    ap.add_argument("--out-dir", default="runs/override_capacity",
                    type=Path)
    ap.add_argument("--n-bms", type=int, default=50)
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    stamp_path = args.out_dir / "stamps.jsonl"
    if stamp_path.exists():
        stamp_path.unlink()

    for rate in args.rates:
        t_start = time.time()
        sent = install_burst(rate, args.duration, n_bms=args.n_bms)
        t_end = time.time()
        with stamp_path.open("a") as f:
            f.write(json.dumps({
                "rate_pps_target": rate,
                "sent": sent,
                "t_start": t_start,
                "t_end": t_end,
                "duration_s": args.duration,
                "n_bms": args.n_bms,
            }) + "\n")
        print(f"rest {args.rest}s to let TTL expire...")
        time.sleep(args.rest)

    print(f"Wrote {stamp_path}")
    print("Next: scp controller log to laptop and run "
           "override_capacity_correlate.py")


if __name__ == "__main__":
    main()
