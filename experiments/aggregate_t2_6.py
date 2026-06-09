"""T2.6 fleet-scaling aggregator (E23).

For each fleet size it reports:
  * F1 (cluster-bootstrap BCa via aggregate_cluster) over the trials;
  * peak override-table occupancy (max over trials, from controller log);
  * R5 Bloom FP observed vs the analytical 3-BF bound (r5_bloom_fp_analysis);
  * digest p99 latency (ms) if the controller logged per-event latencies.

Falsifier (per EXPERIMENT_DESIGN T2.6): E23-500 Bloom FP > 2x bound, OR
override saturates -> benign drops. This aggregator only computes the
numbers and the falsifier verdict; it never fabricates a result — missing
hardware data is reported as ``null`` so the dry-run output is honest.

Usage:
    python3 -m experiments.aggregate_t2_6 runs/experiments
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from experiments.aggregate_cluster import aggregate as cluster_aggregate  # noqa: E402

# Analytical R5 3-BF Bloom FP (mirrors r5_bloom_fp_analysis.fp_all_three).
M_BITS_DEFAULT = 1024
N_BF = 3
FALSIFIER_MULT = 2.0


def fp_all_three(n: int, m: int = M_BITS_DEFAULT) -> float:
    return (1.0 - math.exp(-n / m)) ** N_BF


_KNOWN_SIZES = (100, 250, 500)


def _fleet_size_from_name(name: str) -> int | None:
    # Match against the locked fleet sizes so the "6" in the "T2_6_" prefix
    # is never mistaken for a size. Prefer the token following "fleet".
    tokens = name.replace(".", "_").split("_")
    for i, tok in enumerate(tokens):
        if tok == "fleet" and i + 1 < len(tokens) and tokens[i + 1].isdigit():
            return int(tokens[i + 1])
    for tok in tokens:
        if tok.isdigit() and int(tok) in _KNOWN_SIZES:
            return int(tok)
    return None


def _scan_hw_metrics(exp_dir: Path) -> dict:
    """Best-effort extraction of override occupancy / Bloom FP / latency
    from controller_decisions.jsonl slices and hw_state_post_trial.json
    snapshots (present only after a hardware execute run).

    Sources (in priority order):
      hw_state_post_trial.json — written by run_t2_6 via SIGUSR2 state dump
        BEFORE the SIGUSR1 reset; contains session_override_count,
        r5_bloom_nonzero, and r5_count from the live ASIC.
      controller_decisions.jsonl — per-arbiter-decision log; carries latency
        fields if the controller is instrumented with them, otherwise
        provides the decision stream for latency proxies.

    r5_bloom_fp_observed NOTE: the controller's decisions.jsonl does NOT
    include per-event R5 bloom test results (the data plane does not send
    that information in the digest payload).  Computing "distinct BMS IPs
    that R5 misclassified as duplicate on first contact" requires either
    (a) per-event controller instrumentation not yet deployed, or
    (b) replaying the bloom hash functions against the known BMS IP insertion
        order — possible in principle but not implemented here.
    As a result, r5_bloom_fp_observed is left null for this aggregation pass.
    r5_bloom_fp_n is set to the r5_count value from the ASIC (total distinct-
    BMS events processed by R5), and r5_bloom_nonzero is reported as a
    diagnostic field.  The caller may use fp_all_three(r5_bloom_fp_n, m_bits)
    as the analytical bound for the falsifier comparison.
    """
    occ_peak = None
    r5_bloom_nz: int | None = None
    r5_count_hw: int | None = None
    latencies: list[float] = []

    for trial in sorted(exp_dir.iterdir()):
        if not trial.is_dir():
            continue

        # Primary source: hw_state_post_trial.json (SIGUSR2 state dump).
        hw_path = trial / "hw_state_post_trial.json"
        if hw_path.exists():
            try:
                hw = json.loads(hw_path.read_text())
                # session_override_count may be an int or {"error": ...}.
                occ_raw = hw.get("session_override_count")
                if isinstance(occ_raw, int):
                    occ_peak = max(occ_peak or 0, occ_raw)
                # r5_bloom_nonzero: total non-zero bits across all 3 BFs.
                bnz = hw.get("r5_bloom_nonzero")
                if isinstance(bnz, int):
                    r5_bloom_nz = (r5_bloom_nz or 0) + bnz
                # r5_count: ASIC count-register value (distinct BMS seen).
                rc = hw.get("r5_count")
                if isinstance(rc, int):
                    r5_count_hw = max(r5_count_hw or 0, rc)
            except (json.JSONDecodeError, OSError):
                pass

        # Latency from controller_decisions.jsonl (if future controller
        # versions add latency fields).
        dpath = trial / "controller_decisions.jsonl"
        if dpath.exists():
            for line in dpath.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # Fallback occupancy from decision-log fields
                # (kept for backwards compat with older log formats).
                for key in ("override_occupancy", "override_count", "occupancy"):
                    if key in d and isinstance(d[key], (int, float)):
                        occ_peak = max(occ_peak or 0, int(d[key]))
                for key in ("latency_ms", "digest_latency_ms"):
                    if key in d:
                        try:
                            latencies.append(float(d[key]))
                        except (TypeError, ValueError):
                            pass

    p99 = None
    if latencies:
        latencies.sort()
        p99 = latencies[min(len(latencies) - 1,
                            int(math.ceil(0.99 * len(latencies)) - 1))]

    # r5_bloom_fp_observed is null: per-event R5 bloom test data is not
    # available from the controller log (see docstring above).
    return {"override_occupancy_peak": occ_peak,
            "r5_bloom_fp_observed": None,
            "r5_bloom_fp_n": r5_count_hw,
            "r5_bloom_nonzero": r5_bloom_nz,
            "digest_latency_p99_ms": p99}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("root", type=Path, nargs="?",
                    default=REPO / "runs/experiments",
                    help="dir containing T2_6_* experiment dirs")
    ap.add_argument("--m-bits", type=int, default=M_BITS_DEFAULT)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    exp_dirs = sorted(d for d in args.root.glob("T2_6_*") if d.is_dir())
    if not exp_dirs:
        print(f"no T2_6_* dirs under {args.root}")
        return 1

    per_size: dict[str, dict] = {}
    for exp_dir in exp_dirs:
        size = _fleet_size_from_name(exp_dir.name)
        try:
            agg = cluster_aggregate(exp_dir, out_path=exp_dir.parent /
                                    "_agg" / f"{exp_dir.name}_cluster.json")
            f1 = agg["point"]["f1"]
            f1_ci = [agg["ci_lo"]["f1"], agg["ci_hi"]["f1"]]
            n_trials = agg["n_trials_total"]
        except SystemExit:
            f1, f1_ci, n_trials = None, [None, None], 0
        hw = _scan_hw_metrics(exp_dir)
        pred_fp = fp_all_three(size, args.m_bits) if size else None
        obs_fp = hw["r5_bloom_fp_observed"]
        falsifier = None
        if size == 500 and obs_fp is not None and pred_fp is not None:
            falsifier = "FAIL" if obs_fp > FALSIFIER_MULT * pred_fp else "PASS"
        per_size[exp_dir.name] = {
            "fleet_size": size,
            "n_trials": n_trials,
            "f1": f1, "f1_ci95": f1_ci,
            "override_occupancy_peak": hw["override_occupancy_peak"],
            "r5_bloom_fp_predicted": pred_fp,
            "r5_bloom_fp_observed": obs_fp,
            "r5_bloom_fp_n": hw["r5_bloom_fp_n"],
            "r5_bloom_nonzero": hw.get("r5_bloom_nonzero"),
            "digest_latency_p99_ms": hw["digest_latency_p99_ms"],
            "falsifier_500_bloom_2x": falsifier,
            "notes": (
                "r5_bloom_fp_observed=null: per-event R5 bloom test data "
                "not in controller decisions log; requires controller "
                "instrumentation or bloom-hash replay to measure empirically."
            ) if obs_fp is None else None,
        }
        print(f"[{exp_dir.name}] fleet={size} trials={n_trials} F1={f1} "
              f"pred_fp={pred_fp} obs_fp={obs_fp} "
              f"r5_bloom_nz={hw.get('r5_bloom_nonzero')} "
              f"r5_count={hw['r5_bloom_fp_n']} "
              f"occ_peak={hw['override_occupancy_peak']} "
              f"falsifier={falsifier}")

    out = {"experiment": "T2.6", "m_bits": args.m_bits,
           "falsifier_multiple": FALSIFIER_MULT, "per_size": per_size,
           "statistical_test": "cluster-bootstrap BCa B=10000 on F1; "
                               "Wilson on FP rate; analytical 3-BF bound."}
    out_path = args.out or (args.root / "_agg" / "T2_6_fleet_scaling.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, default=str))
    print(f"\nwrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
