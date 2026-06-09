"""E18 — reference-channel portability.

Sends a small number of MQTT PUBLISHes with variations on the
reference channel assumptions (topic length, QoS level, retain flag,
extra properties) and observes whether the P4 parser recognises each
variant as a valid OTA flow.

For each variant we send one packet and classify the outcome by
inspecting the controller's classify_digest log:
  - PARSED  : a classify_digest with has_ota_hdr=1
  - PARSER_MISS: classify_digest with has_ota_hdr=0
  - DROPPED : no classify_digest (pipeline dropped the packet)

Output: runs/portability/e18_results.csv
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


def make_publish(topic: bytes, qos: int, retain: bool,
                  pkt_id: int, size: int = 1024) -> bytes:
    """Build an MQTT PUBLISH with explicit topic bytes, QoS, retain.
    Packet identifier field is present only for QoS>0."""
    pl = b"OTAS" + struct.pack(">II", 48, size) + b"\x00" * 8
    var = struct.pack(">H", len(topic)) + topic
    if qos > 0:
        var += struct.pack(">H", pkt_id)
    var += pl
    flags = 0x30 | (qos << 1) | (1 if retain else 0)
    return bytes([flags]) + _varint(len(var)) + var


def send_one(sport: int, dst: str, pub: bytes) -> None:
    pkt = (Ether(src=SRC_MAC, dst=DST_MAC) /
           IP(src=SRC_IP, dst=dst) /
           TCP(sport=sport, dport=1883, flags="PA", seq=1, ack=1) /
           Raw(pub))
    sendp(pkt, iface=IFACE, verbose=False)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-csv",
                    default="runs/portability/e18_results.csv",
                    type=Path)
    args = ap.parse_args()

    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    sport = 45000
    # dst within the authorized fleet so bms_known=1 (to reach R5 path)
    dst = "10.0.2.10"
    rows = ["variant,topic_len,qos,retain,expected,notes"]

    cases = [
        # (name, topic_len_bytes, qos, retain, expected, note)
        ("baseline_32_q1",      32, 1, False, "PARSED",
            "reference channel: 32B topic, QoS=1"),
        ("short_16_q1",         16, 1, False, "PARSER_MISS",
            "topic shorter than the 32B null-padded assumption"),
        ("long_64_q1",          64, 1, False, "PARSER_MISS",
            "topic longer than the parser's fixed 32B slot"),
        ("qos0",                32, 0, False, "PARSER_MISS",
            "QoS=0: packet identifier absent → OTA header misaligned"),
        ("qos2",                32, 2, False, "PARSED",
            "QoS=2: packet identifier still present (same offset)"),
        ("retain",              32, 1, True,  "PARSED",
            "retain flag set; does not affect OTA header offset"),
    ]

    for name, tlen, qos, retain, expected, note in cases:
        topic = ("/ota/bms/00".ljust(tlen, "\x00")).encode()[:tlen]
        pub = make_publish(topic, qos, retain, pkt_id=1, size=1024)
        send_one(sport, dst, pub)
        sport += 1
        rows.append(f"{name},{tlen},{qos},{int(retain)},{expected},{note}")
        time.sleep(0.2)

    args.out_csv.write_text("\n".join(rows) + "\n")
    print(f"Sent {len(cases)} variants to {dst}")
    print(f"Wrote expected-outcomes sheet to {args.out_csv}")
    print("Scp the controller's phase6_digests.jsonl and run "
           "portability_e18_correlate.py to produce the final table.")


if __name__ == "__main__":
    main()
