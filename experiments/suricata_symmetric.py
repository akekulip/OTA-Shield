"""E1-symmetric — Run Suricata on reconstructed E8-stochastic PCAPs.

The original E10 baseline comparison (runs/baseline_suricata_stateful/) ran
Suricata on the 90-event E1 PCAP (single deterministic trial).  OTA-Shield's
headline result (E8) used 20 stochastic trials x 90 events = 1800 events.
The methodology reviewer flagged this as asymmetric.

This script:
  1. Reconstructs a per-trial PCAP from each E8 ground_truth.json (same
     packet format as the original hardware runs -- scapy PA-only, no
     handshake, matching scenarios.py's _publish() format).
  2. Runs Suricata stateful-permissive on each PCAP.
  3. Correlates alerts with ground truth by 5-tuple.
  4. Computes per-trial and aggregate (bootstrap) P/R/F1.

Output written to runs/baseline_suricata_symmetric_2026-06-06/.

NOTE: PCAP reconstruction is faithful to the ground_truth parameters
(timestamps, IPs, ports, topic, version, size).  No fabrication; if a trial
PCAP already exists it is reused.  The resulting comparison is genuinely
symmetric: both Suricata and OTA-Shield are evaluated on the same 20 x 90
event population.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# MQTT PUBLISH packet builder (mirrors scenarios.py exactly)
# ---------------------------------------------------------------------------

def _varint(n: int) -> bytes:
    o = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            b |= 0x80
        o.append(b)
        if not n:
            break
    return bytes(o)


def _publish_payload(topic: str, ver: int, sz: int,
                     on_wire_max: int = 1300) -> bytes:
    """Build MQTT PUBLISH carrying the OTAS OTA header.
    Mirrors scenarios.py:_publish() exactly."""
    t = topic.encode().ljust(32, b"\x00")
    on_wire_fw = max(0, min(sz - 20, on_wire_max - 20))
    fw = b"\x00" * on_wire_fw
    pl = b"OTAS" + struct.pack(">II", ver, sz) + b"\x00" * 8 + fw
    var = struct.pack(">H", 32) + t + struct.pack(">H", 1) + pl
    return bytes([0x32]) + _varint(len(var)) + var


def build_pcap_from_gt(gt_events: list[dict], out_pcap: Path) -> None:
    """Write a PCAP from a ground_truth events list.

    Uses scapy to build PA-only TCP packets (same as original testbed captures).
    No TCP handshake is included -- matches the e1.pcap format exactly.
    """
    from scapy.all import Ether, IP, TCP, Raw, wrpcap

    pkts = []
    for ev in gt_events:
        payload = _publish_payload(
            ev["topic"], ev["ota_version"], ev["ota_size"]
        )
        pkt = (
            Ether(src="00:00:00:00:10:10", dst="00:00:00:00:20:ff")
            / IP(src=ev["src_ip"], dst=ev["dst_ip"])
            / TCP(
                sport=ev["src_port"],
                dport=1883,
                flags="PA",
                seq=1,
                ack=1,
            )
            / Raw(payload)
        )
        # Embed the ground-truth timestamp so Suricata uses it.
        pkt.time = ev["t_send"]
        pkts.append(pkt)

    wrpcap(str(out_pcap), pkts)


# ---------------------------------------------------------------------------
# Suricata runner
# ---------------------------------------------------------------------------

def run_suricata(pcap: Path, rules: Path, out_dir: Path,
                 suricata_conf: Path | None) -> list[dict]:
    """Run Suricata in offline mode; return parsed alert records."""
    out_dir.mkdir(parents=True, exist_ok=True)
    eve = out_dir / "eve.json"
    if eve.exists():
        eve.unlink()

    cmd = [
        "suricata",
        "-r", str(pcap),
        "-S", str(rules),
        "-l", str(out_dir),
        "--runmode=single",
        "-k", "none",
    ]
    if suricata_conf and suricata_conf.exists():
        cmd += ["-c", str(suricata_conf)]

    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        # Suricata returns non-zero on warnings sometimes; log but continue.
        sys.stderr.write(f"[suricata] rc={res.returncode}: {res.stderr[:400]}\n")

    alerts: list[dict] = []
    if eve.exists():
        for line in eve.read_text().splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("event_type") == "alert":
                alerts.append(rec)
    return alerts


# ---------------------------------------------------------------------------
# Correlation logic
# ---------------------------------------------------------------------------

def correlate(gt_events: list[dict], alerts: list[dict]) -> dict:
    """Correlate Suricata alerts with ground-truth events by 5-tuple."""
    # Build alert key: (src_ip, dst_ip, src_port) -> first alert
    alert_keys: dict[tuple, dict] = {}
    for a in alerts:
        key = (
            a.get("src_ip", ""),
            a.get("dest_ip", ""),
            int(a.get("src_port", 0)),
        )
        alert_keys.setdefault(key, a)

    tp = tn = fp = fn = 0
    decisions = []
    for ev in gt_events:
        key = (ev["src_ip"], ev["dst_ip"], int(ev["src_port"]))
        a = alert_keys.get(key)
        predicted = "attack" if a else "legit"
        truth = "attack" if ev["label"] == "ATTACK" else "legit"
        if truth == "attack" and predicted == "attack":
            tp += 1
        elif truth == "legit" and predicted == "legit":
            tn += 1
        elif truth == "legit" and predicted == "attack":
            fp += 1
        else:
            fn += 1
        decisions.append({
            "src_ip": ev["src_ip"],
            "dst_ip": ev["dst_ip"],
            "src_port": ev["src_port"],
            "scenario": ev.get("scenario", ""),
            "truth": truth,
            "suricata_predicted": predicted,
        })

    n = tp + tn + fp + fn
    prec = tp / (tp + fp) if (tp + fp) else None
    rec = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * prec * rec / (prec + rec)
          if (prec is not None and rec is not None and (prec + rec) > 0)
          else None)
    return {
        "n": n,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "decisions": decisions,
    }


# ---------------------------------------------------------------------------
# Bootstrap CI
# ---------------------------------------------------------------------------

def bootstrap_ci(values: list[float], n_boot: int = 2000,
                 alpha: float = 0.05) -> tuple[float, float]:
    """Trial-level percentile bootstrap (matches aggregate.py convention)."""
    rng = random.Random(42)
    n = len(values)
    resamples = []
    for _ in range(n_boot):
        sample = [rng.choice(values) for _ in range(n)]
        resamples.append(sum(sample) / len(sample))
    resamples.sort()
    lo = resamples[int(alpha / 2 * n_boot)]
    hi = resamples[int((1 - alpha / 2) * n_boot)]
    return lo, hi


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Symmetric Suricata baseline over E8 stochastic trials"
    )
    ap.add_argument(
        "--e8-dir",
        default="runs/experiments/E8_stochastic",
        type=Path,
        help="Directory with E8 trial sub-dirs (t00, t01, ...)",
    )
    ap.add_argument(
        "--rules",
        default="experiments/rules/ota_shield_stateful_permissive.rules",
        type=Path,
        help="Suricata rules file to use for comparison",
    )
    ap.add_argument(
        "--suricata-conf",
        default="experiments/suricata_conf/suricata.yaml",
        type=Path,
    )
    ap.add_argument(
        "--out-dir",
        default="runs/baseline_suricata_symmetric_2026-06-06",
        type=Path,
    )
    ap.add_argument(
        "--n-trials", type=int, default=None,
        help="Limit number of trials (default: all)",
    )
    args = ap.parse_args()

    if not shutil.which("suricata"):
        print("suricata not installed. Cannot run symmetric baseline.")
        sys.exit(1)

    # Resolve paths relative to project root if not absolute.
    proj = Path(__file__).parent.parent
    e8_dir = args.e8_dir if args.e8_dir.is_absolute() else proj / args.e8_dir
    rules = args.rules if args.rules.is_absolute() else proj / args.rules
    suricata_conf = (
        args.suricata_conf
        if args.suricata_conf.is_absolute()
        else proj / args.suricata_conf
    )
    out_dir = args.out_dir if args.out_dir.is_absolute() else proj / args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    trial_dirs = sorted(e8_dir.glob("t*"))
    if args.n_trials:
        trial_dirs = trial_dirs[: args.n_trials]

    print(f"[symmetric] Processing {len(trial_dirs)} E8 trials")
    print(f"[symmetric] Rules: {rules}")
    print(f"[symmetric] Output: {out_dir}")

    per_trial: list[dict] = []

    for trial_dir in trial_dirs:
        gt_path = trial_dir / "ground_truth.json"
        if not gt_path.exists():
            print(f"  [skip] {trial_dir.name}: no ground_truth.json")
            continue

        with open(gt_path) as f:
            gt = json.load(f)
        gt_events = gt["events"]
        trial_id = gt.get("trial_id", trial_dir.name)

        trial_out = out_dir / trial_dir.name
        trial_out.mkdir(parents=True, exist_ok=True)

        # Build PCAP from ground truth (reuse if already exists).
        pcap_path = trial_out / "trial.pcap"
        if not pcap_path.exists():
            print(f"  [build-pcap] {trial_id} ({len(gt_events)} events) ...")
            build_pcap_from_gt(gt_events, pcap_path)
        else:
            print(f"  [pcap-exists] {trial_id}")

        # Run Suricata.
        print(f"  [suricata] {trial_id} ...", end=" ", flush=True)
        t0 = time.time()
        alerts = run_suricata(pcap_path, rules, trial_out, suricata_conf)
        elapsed = time.time() - t0
        print(f"{len(alerts)} alerts in {elapsed:.2f}s")

        # Correlate.
        metrics = correlate(gt_events, alerts)

        trial_result = {
            "trial_id": trial_id,
            "n_events": len(gt_events),
            "n_alerts": len(alerts),
            "tp": metrics["tp"],
            "tn": metrics["tn"],
            "fp": metrics["fp"],
            "fn": metrics["fn"],
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1"],
            "suricata_elapsed_s": elapsed,
        }
        # Save per-trial JSON.
        (trial_out / "comparison.json").write_text(
            json.dumps(trial_result, indent=2)
        )
        per_trial.append(trial_result)

    if not per_trial:
        print("[symmetric] No trials processed.")
        sys.exit(1)

    # Aggregate.
    total_tp = sum(t["tp"] for t in per_trial)
    total_tn = sum(t["tn"] for t in per_trial)
    total_fp = sum(t["fp"] for t in per_trial)
    total_fn = sum(t["fn"] for t in per_trial)
    total_n = total_tp + total_tn + total_fp + total_fn

    agg_prec = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else None
    agg_rec = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else None
    agg_f1 = (
        2 * agg_prec * agg_rec / (agg_prec + agg_rec)
        if (agg_prec and agg_rec and (agg_prec + agg_rec) > 0)
        else None
    )

    # Per-trial lists for bootstrap.
    precs = [t["precision"] for t in per_trial if t["precision"] is not None]
    recs = [t["recall"] for t in per_trial if t["recall"] is not None]
    f1s = [t["f1"] for t in per_trial if t["f1"] is not None]

    prec_ci = bootstrap_ci(precs) if len(precs) >= 2 else (None, None)
    rec_ci = bootstrap_ci(recs) if len(recs) >= 2 else (None, None)
    f1_ci = bootstrap_ci(f1s) if len(f1s) >= 2 else (None, None)

    # Also compute trial-level mean.
    def mean(lst: list[float]) -> float | None:
        return sum(lst) / len(lst) if lst else None

    aggregate = {
        "description": (
            "Suricata stateful-permissive on E8-stochastic PCAPs "
            "(symmetric comparison to OTA-Shield E8 headline result). "
            "PCAPs reconstructed from ground_truth.json; same logical "
            "scenarios as E1 but stochastic (20 independent trials)."
        ),
        "rules": str(rules),
        "n_trials": len(per_trial),
        "n_events_per_trial": per_trial[0]["n_events"] if per_trial else None,
        "n_events_total": total_n,
        "aggregate_pooled": {
            "tp": total_tp, "tn": total_tn, "fp": total_fp, "fn": total_fn,
            "precision": round(agg_prec, 4) if agg_prec is not None else None,
            "recall": round(agg_rec, 4) if agg_rec is not None else None,
            "f1": round(agg_f1, 4) if agg_f1 is not None else None,
        },
        "trial_level_mean": {
            "precision": round(mean(precs), 4) if mean(precs) else None,
            "recall": round(mean(recs), 4) if mean(recs) else None,
            "f1": round(mean(f1s), 4) if mean(f1s) else None,
        },
        "bootstrap_95ci": {
            "precision": [round(prec_ci[0], 4), round(prec_ci[1], 4)] if prec_ci[0] else None,
            "recall": [round(rec_ci[0], 4), round(rec_ci[1], 4)] if rec_ci[0] else None,
            "f1": [round(f1_ci[0], 4), round(f1_ci[1], 4)] if f1_ci[0] else None,
        },
        "per_trial": per_trial,
        "ota_shield_e8_reference": {
            "source": "runs/experiments/E8_stochastic/ + paper/numbers.tex macros",
            "note": (
                "OTA-Shield E8 20-trial aggregate: P=1.000, R=0.992, F1=0.996 "
                "(FP=0/600 benign; FN=~10/1200 attacks due to digest-channel loss). "
                "Comparison is now symmetric: both systems evaluated on same "
                "20 x 90 = 1800 event population."
            ),
        },
    }

    out_json = out_dir / "aggregate.json"
    out_json.write_text(json.dumps(aggregate, indent=2))
    print(f"\n[symmetric] Wrote {out_json}")

    print("\n=== SYMMETRIC COMPARISON RESULTS ===")
    print(f"Trials: {len(per_trial)} x {per_trial[0]['n_events']} events = {total_n} total")
    print(f"Suricata stateful-permissive (pooled):")
    print(f"  P = {agg_prec:.4f}  R = {agg_rec:.4f}  F1 = {agg_f1:.4f}")
    print(f"  TP={total_tp}  TN={total_tn}  FP={total_fp}  FN={total_fn}")
    print(f"Trial-level mean:  P={mean(precs):.4f}  R={mean(recs):.4f}  F1={mean(f1s):.4f}")
    print(f"Bootstrap 95% CI:  P={prec_ci}  R={rec_ci}  F1={f1_ci}")
    print()
    print("OTA-Shield E8 reference: P=1.000  R=0.992  F1=0.996 (FP=0/600 benign; FN~10/1200 attacks)")


if __name__ == "__main__":
    main()
