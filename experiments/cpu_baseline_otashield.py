"""T2.3 — CPU-side reference detector with the same R1..R6 semantics
as OTA-Shield, used to isolate "in-network vs CPU" from "rule
expressiveness".

The Suricata baseline (`runs/baseline_suricata/`) already shows that
Suricata's rule language cannot express R1 (4-hour replay window),
R5 (distinct-BMS fanout) or R4 (cumulative session bytes) without
custom Lua, so it produces F1=0 on the reference pcap. That answers
"can you reproduce OTA-Shield's detection in a stock CPU IDS?" —
no. But it does NOT isolate the in-network performance advantage
from the rule expressiveness advantage. This module supplies the
missing comparison: a Python CPU detector that runs the exact same
R1..R6 logic as the data-plane binary, producing comparable F1 so
the CPU-vs-HW gap reduces to throughput / latency / resource cost
rather than detection quality.

Detection rules (mirror `p4src/`):
  R1  Same (src,bms_idx) within R1_INTERVAL → replay attack
  R2  src not in RAT.authorized_sources → unauthorized source
  R4  Cumulative session bytes for (5-tuple) > R4_THRESHOLD
  R5  Distinct (bms_idx) count in 60s window from unauthorized sources > R5_THRESHOLD
  R6  ota_version < per-bms max_seen_version → rollback
       (max_seen_version only advanced for r2_fired==0 packets)

Inputs:
  --pcap         input packet capture
  --rat          RAT JSON (authorized_sources + target_bms_list)
  --gt           ground_truth.json from the matching trial (5-tuple → label)
  --out          output JSON with per-packet decisions + summary metrics

Output: decisions list aligned with ground truth + (P, R, F1, throughput).
"""
from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Compile-time thresholds (mirror p4src constants).
R1_INTERVAL_S = 14400  # 4 h
R4_THRESHOLD_BYTES = 2 * 1024 * 1024  # 2 MiB
R5_THRESHOLD = 4
R5_WINDOW_S = 60


@dataclass
class CpuDecision:
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    rules_fired: list[str] = field(default_factory=list)
    pred_label: str = "PASS"  # PASS | HOLD | DROP


@dataclass
class CpuDetector:
    authorized_sources: set[str]
    bms_to_idx: dict[str, int]
    r1_last_seen: dict[int, float] = field(default_factory=dict)
    r6_max_version: dict[int, int] = field(default_factory=dict)
    session_bytes: dict[tuple, int] = field(default_factory=dict)
    r5_seen_unauth_bms: set[int] = field(default_factory=set)
    r5_window_start: float | None = None

    def reset_r5_window_if_needed(self, now: float) -> None:
        if self.r5_window_start is None:
            self.r5_window_start = now
            return
        if now - self.r5_window_start >= R5_WINDOW_S:
            self.r5_seen_unauth_bms.clear()
            self.r5_window_start = now

    def process(self, pkt: dict) -> CpuDecision:
        d = CpuDecision(ts=pkt["ts"], src_ip=pkt["src_ip"],
                        dst_ip=pkt["dst_ip"], src_port=pkt["src_port"],
                        dst_port=pkt["dst_port"])
        self.reset_r5_window_if_needed(pkt["ts"])

        if not pkt.get("is_ota_publish", False):
            return d  # pass-through for non-OTA traffic

        # R2 — RAT membership.
        r2_fired = pkt["src_ip"] not in self.authorized_sources
        if r2_fired:
            d.rules_fired.append("R2")

        # bms_idx lookup (from dst_ip).
        bms_idx = self.bms_to_idx.get(pkt["dst_ip"])
        if bms_idx is None:
            # Unknown BMS — none of R1/R5/R6 can fire.
            d.pred_label = "DROP" if r2_fired else "PASS"
            return d

        # R1 — replay window. Only authorized writes update the state
        # (mirrors D1 architectural fix: r1_delta_commit gated on r2==0).
        prev = self.r1_last_seen.get(bms_idx)
        if prev is not None:
            dt = pkt["ts"] - prev
            if dt < R1_INTERVAL_S:
                d.rules_fired.append("R1")
        if not r2_fired:
            self.r1_last_seen[bms_idx] = pkt["ts"]

        # R4 — cumulative session bytes (5-tuple keyed).
        five_tuple = (pkt["src_ip"], pkt["dst_ip"], pkt["src_port"],
                      pkt["dst_port"], "tcp")
        new_bytes = self.session_bytes.get(five_tuple, 0) + pkt.get("size", 0)
        self.session_bytes[five_tuple] = new_bytes
        if new_bytes > R4_THRESHOLD_BYTES:
            d.rules_fired.append("R4")

        # R5 — distinct BMSes in 60s window from UNAUTHORIZED sources only
        # (mirrors D3 architectural fix: BF gated on r2_fired==1).
        if r2_fired:
            self.r5_seen_unauth_bms.add(bms_idx)
            if len(self.r5_seen_unauth_bms) > R5_THRESHOLD:
                d.rules_fired.append("R5")

        # R6 — rollback. Probe always; commit only when r2==0
        # (mirrors D2: simplified gate; SALU's internal >= clause inhibits
        # rollback writes; commit emits the rollback flag).
        cur_max = self.r6_max_version.get(bms_idx, 0)
        if pkt.get("ota_version", 0) < cur_max:
            d.rules_fired.append("R6")
        if not r2_fired and pkt.get("ota_version", 0) >= cur_max:
            self.r6_max_version[bms_idx] = pkt["ota_version"]

        # Policy: R2 → DROP; R1/R4/R5/R6 → HOLD; else PASS.
        if "R2" in d.rules_fired:
            d.pred_label = "DROP"
        elif d.rules_fired:
            d.pred_label = "HOLD"
        else:
            d.pred_label = "PASS"
        return d


def load_pcap_packets(pcap_path: Path) -> list[dict]:
    """Parse a pcap into the packet dict shape the detector expects.

    Uses scapy. Filters to TCP/MQTT-PUBLISH-with-OTAS-magic only — those
    are the only packets the data plane treats as is_ota_publish=1.
    """
    from scapy.all import rdpcap, IP, TCP, Raw
    pkts = rdpcap(str(pcap_path))
    out: list[dict] = []
    for p in pkts:
        if not p.haslayer(IP) or not p.haslayer(TCP):
            continue
        ip = p[IP]
        tcp = p[TCP]
        is_ota = False
        ota_version = 0
        if tcp.dport == 1883 and p.haslayer(Raw):
            payload = bytes(p[Raw].load)
            # Scan for "OTAS" magic in the first 512 B (covers MQTT
            # PUBLISH header + OTA-header offset variation).
            magic_idx = payload.find(b"OTAS")
            if magic_idx >= 0 and magic_idx + 8 <= len(payload):
                is_ota = True
                ota_version = int.from_bytes(
                    payload[magic_idx + 4: magic_idx + 8], "big")
        out.append({
            "ts": float(p.time),
            "src_ip": ip.src, "dst_ip": ip.dst,
            "src_port": int(tcp.sport), "dst_port": int(tcp.dport),
            "size": len(p),
            "is_ota_publish": is_ota,
            "ota_version": ota_version,
        })
    return out


def load_rat(rat_path: Path) -> tuple[set[str], dict[str, int]]:
    """Accept either the legacy flat schema (authorized_sources +
    target_bms_list at top level) or the v2 schema with a list of
    authorized_rollouts each carrying authorized_source_ips +
    target_bms_list. We union across all rollouts."""
    rat = json.loads(rat_path.read_text())
    authorized: set[str] = set(rat.get("authorized_sources", []))
    bms_to_idx: dict[str, int] = {}
    for ip in rat.get("target_bms_list", []):
        bms_to_idx.setdefault(ip, len(bms_to_idx))
    for rollout in rat.get("authorized_rollouts", []) or []:
        for ip in rollout.get("authorized_source_ips", []) or []:
            authorized.add(ip)
        for ip in rollout.get("target_bms_list", []) or []:
            bms_to_idx.setdefault(ip, len(bms_to_idx))
    return authorized, bms_to_idx


def load_gt(gt_path: Path) -> dict[tuple, str]:
    """ground_truth.json may be either a list of records or a top-level
    dict with an "events" key. Each record needs at least src_ip,
    dst_ip, src_port (dst_port defaults to 1883 — MQTT — if absent),
    plus a gt_label or label."""
    raw = json.loads(gt_path.read_text())
    if isinstance(raw, dict):
        records = raw.get("events", raw.get("records", []))
    else:
        records = raw
    gt: dict[tuple, str] = {}
    for r in records:
        try:
            key = (r["src_ip"], r["dst_ip"], int(r["src_port"]),
                   int(r.get("dst_port", 1883)), "tcp")
        except (KeyError, TypeError, ValueError):
            continue
        label = r.get("gt_label") or r.get("label") or "UNKNOWN"
        gt[key] = "ATTACK" if label.upper().startswith("ATTACK") else "LEGIT"
    return gt


def score(decisions: list[CpuDecision], gt: dict[tuple, str]
          ) -> dict[str, float | int]:
    tp = fp = tn = fn = 0
    matched = 0
    for d in decisions:
        key = (d.src_ip, d.dst_ip, d.src_port, d.dst_port, "tcp")
        label = gt.get(key)
        if label is None:
            continue
        matched += 1
        pred_attack = d.pred_label in ("HOLD", "DROP")
        if label == "ATTACK" and pred_attack:
            tp += 1
        elif label == "ATTACK" and not pred_attack:
            fn += 1
        elif label == "LEGIT" and pred_attack:
            fp += 1
        else:
            tn += 1
    p = tp / (tp + fp) if (tp + fp) else None
    r = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * p * r / (p + r)) if (p and r) else None
    return {
        "matched": matched, "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": p, "recall": r, "f1": f1,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", type=Path, required=True)
    ap.add_argument("--rat", type=Path, required=True)
    ap.add_argument("--gt", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    print(f"[cpu-baseline] loading pcap {args.pcap}...")
    t0 = time.time()
    pkts = load_pcap_packets(args.pcap)
    t_load = time.time() - t0
    print(f"  {len(pkts)} TCP packets loaded ({t_load:.3f} s)")

    authorized, bms_to_idx = load_rat(args.rat)
    print(f"  RAT: {len(authorized)} authorized src(s), "
          f"{len(bms_to_idx)} BMSes")

    gt = load_gt(args.gt)
    print(f"  GT: {len(gt)} 5-tuples labelled")

    det = CpuDetector(authorized_sources=authorized, bms_to_idx=bms_to_idx)
    decisions: list[CpuDecision] = []
    t_proc_start = time.time()
    for pkt in pkts:
        decisions.append(det.process(pkt))
    t_proc = time.time() - t_proc_start

    pps = len(pkts) / t_proc if t_proc > 0 else float("inf")
    metrics = score(decisions, gt)

    out = {
        "input": {"pcap": str(args.pcap), "rat": str(args.rat),
                  "gt": str(args.gt)},
        "n_packets_total": len(pkts),
        "n_packets_ota": sum(1 for p in pkts if p["is_ota_publish"]),
        "throughput_pps": pps,
        "processing_time_s": t_proc,
        "metrics": metrics,
        "thresholds": {
            "R1_INTERVAL_S": R1_INTERVAL_S,
            "R4_THRESHOLD_BYTES": R4_THRESHOLD_BYTES,
            "R5_THRESHOLD": R5_THRESHOLD,
            "R5_WINDOW_S": R5_WINDOW_S,
        },
        "decisions": [
            {"ts": d.ts, "src_ip": d.src_ip, "dst_ip": d.dst_ip,
             "src_port": d.src_port, "dst_port": d.dst_port,
             "rules_fired": d.rules_fired, "pred_label": d.pred_label}
            for d in decisions
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2, default=str))
    print(f"\n[cpu-baseline] result -> {args.out}")
    print(f"  throughput: {pps:,.0f} pkt/s "
          f"({len(pkts)} pkts in {t_proc*1000:.1f} ms)")
    print(f"  matched {metrics['matched']} GT 5-tuples; "
          f"tp={metrics['tp']} fp={metrics['fp']} "
          f"tn={metrics['tn']} fn={metrics['fn']}")
    p, r, f = metrics["precision"], metrics["recall"], metrics["f1"]
    print(f"  precision={p}, recall={r}, F1={f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
