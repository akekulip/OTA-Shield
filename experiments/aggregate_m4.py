"""M4 aggregator — read M4 trial outputs and emit paper-macro JSON.

Reads the three M4 scenarios' outputs and produces a single JSON
blob the paper build can inject as LaTeX macros:

    runs/m4/<scenario>/
        labels.json                 # from scenarios_m4.py
        manifest.json               # from scenarios_m4.py
        (optional) trial_*/
            controller_decisions.jsonl
            phase6_digests.jsonl
            classify_digests.jsonl  # legacy name
        (optional) qos0_binary.txt  # one of {"old_parser","new_parser"}
                                    #   selects which expected_* column
                                    #   to compare against.

If trial_* directories are present, the aggregator correlates labels to
observed decisions; if not, it only reports the honest-framing block
(axes, rate model, extrapolation disclosures) so the paper can still
document what WILL be measured. This mirrors the M4 strategy: emit data
now, fold in real observations after the recompile / HW slot.

Output:
    runs/m4/m4_aggregate.json

The JSON shape is stable across invocations so the paper macros bind to
fixed keys:

    {
      "E18_qos0": {
         "binary": "old_parser"|"new_parser"|null,
         "rows": [
             {"variant": "baseline_32_q1", "expected": "PARSED",
              "observed": "PARSED", "verdict": "OK"}, ...
         ],
         "summary": {"n": 8, "n_ok": 7, "n_diff": 1}
      },
      "E1_200bms": {
         "axes": {...}, "rate_model": {...},
         "measured_vs_extrapolated": {...},
         "trials": [{"trial_id": ..., "metrics": {...}}, ...],
         "metrics": {"precision": ..., "recall": ..., "f1": ...}
      },
      "E8_200bms": { ... same shape ... }
    }
"""
from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional


# ---------- Small IO helpers ----------

def _load_jsonl(p: Path) -> list[dict]:
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


def _load_json(p: Path) -> Optional[dict | list]:
    if not p.exists():
        return None
    return json.loads(p.read_text())


# ---------- E18 QoS=0 summary ----------

def aggregate_e18(scenario_dir: Path) -> dict:
    """Aggregate the E18 QoS=0 portability rerun.

    Picks the expected-column to compare against based on
    ``scenario_dir/qos0_binary.txt`` (contents: ``old_parser`` or
    ``new_parser``).  Default: ``old_parser`` so the paper does not
    silently claim the new binary before it is deployed.
    """
    labels = _load_json(scenario_dir / "labels.json") or []
    binary_hint = (scenario_dir / "qos0_binary.txt")
    binary = (binary_hint.read_text().strip()
              if binary_hint.exists() else "old_parser")
    if binary not in ("old_parser", "new_parser"):
        raise ValueError(f"unknown qos0_binary contents: {binary!r}")

    # Index any observed digests by src_port.  Digest format reuses the
    # existing portability_e18_correlate convention so this script stays
    # interchangeable with the original E18 analysis.
    observed_by_sport: dict[int, dict] = {}
    # Deep-stage sports: any frame that reached rule/hold digest has
    # definitively PARSED past the OTA header — stronger evidence than
    # an mqtt_digest with has_ota_hdr=1.
    deep_parsed_sports: set[int] = set()
    for d in _load_jsonl(scenario_dir / "phase6_digests.jsonl"):
        t = d.get("_type")
        sp = int(d.get("src_port") or d.get("sport") or 0)
        if t in ("classify_digest", "mqtt_digest"):
            observed_by_sport[sp] = d
        elif t in ("rule_digest", "hold_digest"):
            deep_parsed_sports.add(sp)

    rows = []
    for row in labels:
        sport = int(row["src_port"])
        exp_col = "expected_new_parser" if binary == "new_parser" \
            else "expected_old_parser"
        expected = row.get(exp_col) or row.get("expected_old_parser")
        d = observed_by_sport.get(sport)
        if sport in deep_parsed_sports:
            observed = "PARSED"  # reached rule/hold digest => parsed
        elif d is None and not observed_by_sport and not deep_parsed_sports:
            observed = None  # no HW observation yet
        elif d is None:
            observed = "DROPPED"
        else:
            observed = "PARSED" if int(d.get("has_ota_hdr", 0)) else "PARSER_MISS"
        verdict = None if observed is None \
            else ("OK" if observed == expected else "DIFF")
        rows.append({
            "variant": row["scenario"].replace("e18_qos0_", ""),
            "topic_len": len(row["topic"]),
            "qos": row["qos"],
            "src_port": sport,
            "expected": expected,
            "observed": observed,
            "verdict": verdict,
            "note": row.get("note", ""),
        })

    n = len(rows)
    observed_rows = [r for r in rows if r["verdict"] is not None]
    n_ok = sum(1 for r in observed_rows if r["verdict"] == "OK")
    n_diff = sum(1 for r in observed_rows if r["verdict"] == "DIFF")
    return {
        "binary": binary,
        "rows": rows,
        "summary": {"n": n, "n_observed": len(observed_rows),
                    "n_ok": n_ok, "n_diff": n_diff},
    }


# ---------- 200-BMS E1 / E8 correlator ----------

def _ipv4_to_int(ip: str) -> int:
    p = ip.split(".")
    return (int(p[0]) << 24) | (int(p[1]) << 16) | (int(p[2]) << 8) | int(p[3])


def _score_trial(labels: list[dict], trial_dir: Path) -> dict:
    """Return per-trial verdict counts and latency samples."""
    ctrl_decisions = {}
    for d in _load_jsonl(trial_dir / "controller_decisions.jsonl"):
        if "_marker" in d:
            continue
        try:
            key = (int(d["src_ip"]), int(d["dst_ip"]),
                   int(d["src_port"]), int(d.get("dst_port", 1883)))
        except (KeyError, TypeError, ValueError):
            continue
        ctrl_decisions[key] = d

    # dec_index: prefer hold_digest if multiple decisions for same key
    dec_index: dict[tuple, dict] = {}
    for d in _load_jsonl(trial_dir / "decisions.jsonl"):
        try:
            key = (int(d.get("src_ip", 0)),
                   int(d.get("dst_ip", 0)),
                   int(d.get("src_port", 0)),
                   int(d.get("dst_port", 1883)))
        except (TypeError, ValueError):
            continue
        existing = dec_index.get(key)
        if (existing is None
                or (d.get("_type") == "hold_digest"
                    and existing.get("_type") != "hold_digest")):
            dec_index[key] = d

    verdicts = []
    latencies = []
    for ev in labels:
        key = (_ipv4_to_int(ev["src_ip"]), _ipv4_to_int(ev["dst_ip"]),
               int(ev["src_port"]), int(ev["dst_port"]))
        ctrl = ctrl_decisions.get(key)
        d = dec_index.get(key)
        if d is None:
            verdicts.append("NO_DECISION")
            continue
        dtype = d.get("_type", "")
        if dtype == "hold_digest":
            if ctrl is None:
                verdicts.append("NO_DECISION")
                continue
            action = ctrl["decision"]
        else:
            if ev["label"] == "ATTACK":
                if ctrl is None:
                    verdicts.append("NO_DECISION")
                    continue
                action = ctrl["decision"]
            else:
                action = "PASS"
        if ev["label"] == "ATTACK" and action == "DROP":
            verdicts.append("TP")
        elif ev["label"] == "LEGIT" and action == "PASS":
            verdicts.append("TN")
        elif ev["label"] == "LEGIT" and action == "DROP":
            verdicts.append("FP")
        else:
            verdicts.append("FN")
        if ev["label"] == "ATTACK" and d.get("_t_recv"):
            latencies.append(float(d["_t_recv"]) - float(ev["t_offset_s"]))
    return {"verdicts": verdicts, "latencies": latencies}


def _metrics_from_verdicts(verdicts: list[str]) -> dict:
    c = Counter(verdicts)
    tp, tn, fp, fn = c["TP"], c["TN"], c["FP"], c["FN"]
    nd = c["NO_DECISION"]
    total = tp + tn + fp + fn + nd
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = (2 * prec * rec / (prec + rec)
          if (prec + rec and prec == prec and rec == rec) else float("nan"))
    acc = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else float("nan")
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn, "no_decision": nd,
            "total": total, "precision": prec, "recall": rec,
            "f1": f1, "accuracy": acc,
            "digest_loss_rate": nd / total if total else float("nan")}


def aggregate_scaled(scenario_dir: Path) -> dict:
    """Aggregate an extrapolation scenario (E1_200bms or E8_200bms).

    Returns the extrapolation disclosures from the manifest PLUS any
    trial metrics found under ``<scenario_dir>/trial_*/``.  The trial
    block is empty if no real run has happened yet — the paper still
    gets the honest framing that way.
    """
    manifest = _load_json(scenario_dir / "manifest.json") or {}
    labels = _load_json(scenario_dir / "labels.json") or []
    trial_dirs = sorted(p for p in scenario_dir.glob("trial_*") if p.is_dir())

    per_trial = []
    all_verdicts: list[str] = []
    all_latencies: list[float] = []
    for td in trial_dirs:
        scored = _score_trial(labels, td)
        per_trial.append({"trial_id": td.name,
                          "metrics": _metrics_from_verdicts(scored["verdicts"]),
                          "n_latency_samples": len(scored["latencies"])})
        all_verdicts.extend(scored["verdicts"])
        all_latencies.extend(scored["latencies"])

    pooled = _metrics_from_verdicts(all_verdicts) if all_verdicts else {}
    if all_latencies:
        pooled["latency_median_s"] = statistics.median(all_latencies)
        pooled["latency_p95_s"] = sorted(all_latencies)[
            max(0, int(0.95 * len(all_latencies)) - 1)]

    return {
        "axes": manifest.get("axes", {}),
        "rate_model": manifest.get("rate_model", {}),
        "measured_vs_extrapolated":
            manifest.get("measured_vs_extrapolated", {}),
        "n_intended_events": len(labels),
        "trials": per_trial,
        "metrics": pooled,
    }


# ---------- CLI ----------

def _main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default="runs/m4", type=Path,
                    help="Parent directory containing the three M4 "
                         "scenario subdirs.")
    ap.add_argument("--out", default=None, type=Path,
                    help="Output JSON path. Defaults to "
                         "<root>/m4_aggregate.json.")
    args = ap.parse_args()

    out_path = args.out or (args.root / "m4_aggregate.json")
    if not args.root.exists():
        raise SystemExit(f"[m4-aggregate] missing root directory {args.root}")

    agg = {
        "E18_qos0": aggregate_e18(args.root / "E18_qos0_portability")
                    if (args.root / "E18_qos0_portability").exists() else None,
        "E1_200bms": aggregate_scaled(args.root / "E1_200bms")
                     if (args.root / "E1_200bms").exists() else None,
        "E8_200bms": aggregate_scaled(args.root / "E8_200bms")
                     if (args.root / "E8_200bms").exists() else None,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(agg, indent=2))
    print(f"[m4-aggregate] wrote {out_path}")

    # Compact human summary
    for key, blob in agg.items():
        if blob is None:
            print(f"  {key:12s}: (not produced yet)")
        elif key == "E18_qos0":
            s = blob["summary"]
            print(f"  {key:12s}: binary={blob['binary']} n={s['n']} "
                  f"observed={s['n_observed']} ok={s['n_ok']} "
                  f"diff={s['n_diff']}")
        else:
            m = blob.get("metrics") or {}
            n_trials = len(blob.get("trials") or [])
            print(f"  {key:12s}: n_events_intended={blob['n_intended_events']} "
                  f"trials={n_trials} "
                  f"f1={m.get('f1', float('nan')):.3f} "
                  f"digest_loss={m.get('digest_loss_rate', float('nan')):.3f}")


if __name__ == "__main__":
    _main()
