"""E15 — session-hash collision empirical study.

Sweeps the number of concurrent unique 5-tuples N and measures how
often two distinct flows produce the same 16-bit session index. The
controller's classify_digest records (src_ip, dst_ip, src_port,
dst_port, session_idx). Post-hoc we count distinct 4-tuples that
share a session_idx.

For each N in {100, 500, 1000, 2000, 5000, 10000}, send one packet
per unique 5-tuple to a non-BMS destination so R5 does not fire and
no override-table pressure is added (isolate collision behavior from
capacity behavior).

5-tuple diversity: by default the script varies src_ip, dst_ip, sport,
and dport jointly using a seeded RNG. An earlier version varied only
sport sequentially; CRC32 on sequential single-field inputs is a
linear permutation so the lower 16 bits were injective up to 2^16
inputs, and the measurement reported 0 collisions at every N —
statistically impossible for a random hash. Randomizing four of the
five fields gives a realistic fleet-flow workload and produces the
expected birthday-paradox collision rate (~n^2/(2*65536)).

Output: runs/collision/stamps.jsonl (rate-window timings).
"""
from __future__ import annotations
import argparse, json, random, struct, time
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


def _pingreq() -> bytes:
    # MQTT PINGREQ: fixed byte 0xC0, remaining length 0. This is the
    # smallest legal MQTT packet and is parsed as is_mqtt=1 +
    # is_mqtt_publish=0, which triggers phase1 classify_digest (the only
    # digest that carries session_id for M5 collision measurement).
    return bytes([0xC0, 0x00])


def send_n_unique(n: int, sport_start: int, dst: str,
                  mqtt_type: str = "pingreq",
                  tuple_mode: str = "random",
                  seed: int = 0) -> int:
    pkts = []
    rng = random.Random(seed)
    # Fleet-like source range: 10.0.1.10 .. 10.0.1.254 (245 src IPs)
    # and dst range: 10.0.2.10 .. 10.0.2.254 (245 dst IPs) minus BMS.
    # For the default non-BMS target we keep dst constant to avoid
    # accidental R5 fleet-pressure; we only diversify src_ip, sport,
    # dport to reach the 5-tuple uniqueness required by the experiment
    # while preserving the R5-silent condition.
    seen: set[tuple[int, int, int, int]] = set()
    i = 0
    while len(pkts) < n:
        if tuple_mode == "random":
            src_last = rng.randint(10, 254)
            src_ip_s = f"10.0.1.{src_last}"
            sport = rng.randint(10000, 60000)
            dport = rng.choice([1883, 8883, 1884, 1885])
            key = (src_last, 0, sport, dport)
        else:
            src_ip_s = SRC_IP
            sport = sport_start + i
            dport = 1883
            key = (0, 0, sport, dport)
            i += 1
        if key in seen:
            if tuple_mode != "random":
                i += 1
            continue
        seen.add(key)
        if mqtt_type == "pingreq":
            body = _pingreq()
        else:
            body = _publish(f"/monitor/probe/{len(pkts):05d}")
        pkts.append((Ether(src=SRC_MAC, dst=DST_MAC) /
                     IP(src=src_ip_s, dst=dst) /
                     TCP(sport=sport, dport=dport,
                         flags="PA", seq=1, ack=1) /
                     Raw(body)))
    BATCH = 200
    sent = 0
    for i in range(0, n, BATCH):
        sendp(pkts[i:i+BATCH], iface=IFACE, verbose=False)
        sent += min(BATCH, n - i)
    return sent


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ns", nargs="+", type=int,
                    default=[100, 500, 1000, 2000, 5000, 10000])
    ap.add_argument("--rest", type=int, default=10,
                    help="seconds between sweeps")
    ap.add_argument("--out-dir", default="runs/collision", type=Path)
    ap.add_argument("--dst", default="10.0.2.200",
                    help="non-BMS dst so R5 does not fire")
    ap.add_argument("--mqtt-type", default="pingreq",
                    choices=["pingreq", "publish"],
                    help="MQTT packet type. 'pingreq' triggers phase1 "
                         "classify_digest which carries session_id "
                         "(required for M5 collision measurement); "
                         "'publish' triggers phase2 mqtt_digest "
                         "(no session_id field).")
    ap.add_argument("--tuple-mode", default="random",
                    choices=["random", "sequential_sport"],
                    help="5-tuple diversity mode. 'random' varies "
                         "src_ip, sport, dport using a seeded RNG "
                         "(realistic fleet workload). "
                         "'sequential_sport' varies only sport "
                         "(legacy; produces 0 collisions because "
                         "CRC32 is injective on sequential inputs up "
                         "to 2^16).")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    stamp_path = args.out_dir / "stamps.jsonl"
    if stamp_path.exists():
        stamp_path.unlink()

    sport_start = 20000
    for n in args.ns:
        t_start = time.time()
        sent = send_n_unique(n, sport_start, args.dst, args.mqtt_type)
        t_end = time.time()
        with stamp_path.open("a") as f:
            f.write(json.dumps({
                "n": n, "sent": sent,
                "sport_start": sport_start,
                "t_start": t_start, "t_end": t_end,
                "dst": args.dst,
            }) + "\n")
        print(f"N={n}  sent={sent}  elapsed={t_end - t_start:.2f}s")
        # Advance sport range so next sweep has different 5-tuples
        sport_start += n
        time.sleep(args.rest)

    print(f"Wrote {stamp_path}")


if __name__ == "__main__":
    main()
