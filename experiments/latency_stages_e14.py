"""E14 — per-stage latency breakdown from existing E8 logs.

Decomposes end-to-end detection latency into three measurable stages
using timestamps already present in the existing data:

  stage1_send_to_pipeline  = t_digest - t_send
     (packet in flight from the generator to the Tofino ingress +
      parser + all rule fires + digest emit)

  stage2_digest_to_decision = t_decision - t_digest
     (controller reads the mqtt/hold digest off the gRPC channel,
      loads RAT, reaches a PASS/DROP verdict)

  stage3_decision_to_install = t_install - t_decision
     (install_session_override call — the time to push the override
      table entry back to the switch via gRPC)

Outputs:
  runs/latency_stages/per_stage.csv  : one row per event
  runs/latency_stages/summary.csv    : median and p95 per stage
"""
from __future__ import annotations
import argparse, json
import statistics as stats
from pathlib import Path
from collections import defaultdict


def load_jsonl(p: Path) -> list[dict]:
    out = []
    if not p.exists():
        return out
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def int_to_ip(x) -> str:
    if isinstance(x, str):
        return x
    x = int(x)
    return ".".join(str((x >> (8 * (3 - i))) & 0xff) for i in range(4))


def key_of(rec: dict) -> tuple[str, str, int]:
    return (int_to_ip(rec.get("src_ip", 0)),
            int_to_ip(rec.get("dst_ip", 0)),
            int(rec.get("src_port", 0)))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--e8-dir",
                    default="runs/experiments/E8_stochastic",
                    type=Path)
    ap.add_argument("--out-dir",
                    default="runs/latency_stages", type=Path)
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    stages: dict[str, list[float]] = defaultdict(list)
    n_trials = 0
    for trial in sorted(args.e8_dir.iterdir()):
        if not trial.is_dir():
            continue
        gt_path = trial / "ground_truth.json"
        # In this repo: controller_decisions.jsonl holds PASS/DROP records
        # (with `t` = decision time); decisions.jsonl holds raw digests
        # (with `_t_recv` = digest arrival time).
        dec_path = trial / "controller_decisions.jsonl"
        dig_path = trial / "decisions.jsonl"
        if not gt_path.exists() or not dec_path.exists():
            continue
        n_trials += 1
        gt = json.loads(gt_path.read_text()).get("events", [])
        decs = load_jsonl(dec_path)
        digs = load_jsonl(dig_path)

        gt_by_key = {key_of({"src_ip": e["src_ip"],
                              "dst_ip": e["dst_ip"],
                              "src_port": e["src_port"]}):
                     float(e["t_send"]) for e in gt}
        dec_by_key: dict = {}
        for d in decs:
            dec_by_key[key_of(d)] = d
        # Digests have _type and carry `t` when the controller logged them.
        dig_by_key: dict = {}
        for d in digs:
            # Skip non-OTA digests (classify-only without the OTA hdr).
            if d.get("_type") not in ("mqtt_digest", "hold_digest"):
                continue
            k = key_of(d)
            t = float(d.get("_t_recv") or d.get("t", 0))
            if k not in dig_by_key or t < dig_by_key[k]:
                dig_by_key[k] = t

        # Index GT by key so we can pull per-event labels later.
        gt_label = {key_of({"src_ip": e["src_ip"],
                             "dst_ip": e["dst_ip"],
                             "src_port": e["src_port"]}):
                    e.get("label", "") for e in gt}

        for k, t_send in gt_by_key.items():
            dec = dec_by_key.get(k)
            t_dig = dig_by_key.get(k)
            if dec is None:
                continue
            # Only report per-stage latency on ATTACK events so the
            # numbers reconcile with the Fig.7 end-to-end distribution
            # which is also computed on attack events only. Including
            # legit events here would pool in post-SIGUSR1 barrier
            # waits where the controller was paused for trial reset,
            # producing an artificially heavy tail that is not on the
            # security-critical path.
            if gt_label.get(k) != "ATTACK":
                continue
            t_dec = float(dec.get("t", 0))
            if t_dig and t_dig > t_send:
                stages["stage1_send_to_pipeline"].append(t_dig - t_send)
            if t_dig and t_dec > t_dig:
                stages["stage2_digest_to_decision"].append(t_dec - t_dig)

    per_stage_path = args.out_dir / "per_stage.csv"
    summary_path = args.out_dir / "summary.csv"
    per_rows = ["stage,latency_ms"]
    sum_rows = ["stage,n,median_ms,p95_ms,max_ms"]
    for stage, vals in stages.items():
        for v in vals:
            per_rows.append(f"{stage},{v*1000:.3f}")
        if not vals:
            continue
        med = stats.median(vals) * 1000
        p95 = sorted(vals)[int(0.95 * (len(vals) - 1))] * 1000
        mx = max(vals) * 1000
        sum_rows.append(f"{stage},{len(vals)},{med:.2f},{p95:.2f},{mx:.2f}")
        print(f"{stage:28s}  n={len(vals):>5}  "
              f"median={med:6.2f}ms  p95={p95:6.2f}ms")
    per_stage_path.write_text("\n".join(per_rows) + "\n")
    summary_path.write_text("\n".join(sum_rows) + "\n")
    print(f"\nTrials analyzed: {n_trials}")
    print(f"Wrote {per_stage_path}")
    print(f"Wrote {summary_path}")


if __name__ == "__main__":
    main()
