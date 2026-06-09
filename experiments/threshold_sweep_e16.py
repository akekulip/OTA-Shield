"""E16 — threshold robustness (1D R1 interval sweep).

R5's distinct-BMS threshold is baked in at P4-compile time (a range
match), so a full 2D heatmap would require recompiling for each R5
value. R1's minimum-interval threshold is a controller-side constant
(see `--r1-threshold-s`), so we can sweep it without recompiling.

This script drives a sequence of short E1-style trials under
different R1 threshold values and aggregates precision / recall / F1
per threshold. The paper presents the resulting F1-vs-R1-threshold
curve as a robustness plot: a stable plateau says the detector
tolerates threshold drift.

Because each run needs a controller restart with a different flag,
this is a user-in-the-loop driver rather than fully automated. It
prints the exact restart command before each window and waits for
the human to launch the controller.
"""
from __future__ import annotations
import argparse, json, time
from pathlib import Path


E1_CONFIG = "experiments/configs/E1_attack_detection.yaml"
LOCAL_OUT = "runs/threshold_sweep_e16"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--r1-values-s", nargs="+", type=int,
                    default=[300, 1800, 3600, 14400, 86400])
    ap.add_argument("--trials", type=int, default=2)
    ap.add_argument("--vision", required=True)
    ap.add_argument("--switch", required=True)
    ap.add_argument("--controller-log", required=True,
                    help="absolute path to phase6_digests.jsonl on switch")
    args = ap.parse_args()

    out = Path(LOCAL_OUT)
    out.mkdir(parents=True, exist_ok=True)

    for r1 in args.r1_values_s:
        print("=" * 70)
        print(f"R1 threshold window: {r1} s")
        print("=" * 70)
        print()
        print("On the SWITCH, stop the current controller (Ctrl-C) and")
        print("relaunch with the sweep threshold:")
        print()
        print(f"  python3.8 controller/ota_shield_controller.py \\")
        print(f"    --grpc-addr 127.0.0.1:50052 --p4-name ota_shield \\")
        print(f"    --rat controller/rat.json \\")
        print(f"    --log runs/phase6_digests.jsonl \\")
        print(f"    --r1-threshold-s {r1}")
        print()
        input("Press ENTER once the controller reports "
              "'Streaming digests...' ")

        cmd = (
            f"python3 experiments/sweep.py "
            f"--configs {E1_CONFIG} "
            f"--vision {args.vision} --switch {args.switch} "
            f"--controller-log {args.controller_log} "
            f"--trials {args.trials} "
            f"--local-out {LOCAL_OUT}/r1_{r1}s "
            f"--reset-between-trials 1 "
        )
        print(f"Running: {cmd}")
        import subprocess
        subprocess.run(cmd, shell=True, check=False)
        print()

    print("All R1-threshold windows complete. Aggregate each with:")
    print(f"  python3 experiments/aggregate.py "
          f"--runs-dir {LOCAL_OUT}/<r1_NNNs> "
          f"--out-dir {LOCAL_OUT}/_agg")


if __name__ == "__main__":
    main()
