"""Experiment sweep orchestrator.

Runs one or more experiment configs × N repetitions. For each trial:
  1. On switch: timestamp a "trial start" marker in the controller log path.
  2. On Vision: invoke run_trial.py with the config; emits ground-truth JSON.
  3. Wait `post_wait_s` seconds for digests to propagate.
  4. On switch: timestamp a "trial end" marker and slice out the log segment.
  5. Pull the log slice + ground-truth JSON to `runs/experiments/E<id>/<trial>/`.

Assumes the controller is already running on the switch with an append-mode
log at --controller-log. If a trial requires a different RAT config or
controller restart (e.g. E7 RAT variance), sweep calls the --pre-hook.

Usage:
    python3 experiments/sweep.py \\
        --configs experiments/configs/E1_attack_detection.yaml \\
        --trials 5 \\
        --vision decps@10.10.54.19 \\
        --switch decps@10.10.54.15 \\
        --controller-log /home/decps/my_program/ota/runs/phase6_digests.jsonl \\
        --remote-workdir /home/decps/my_program/ota/experiments
"""
from __future__ import annotations
import os
import argparse, json, shlex, subprocess, sys, time
from pathlib import Path


SSHPASS = os.environ.get("OTA_SSHPASS", "")
if not SSHPASS:
    raise RuntimeError("OTA_SSHPASS env var not set; refuse to fall back to a literal credential")


def sh(cmd: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, check=check,
                          capture_output=capture, text=True)


def ssh(host: str, remote_cmd: str, check: bool = True,
        capture: bool = False) -> subprocess.CompletedProcess:
    # Use sshpass for environments without passwordless SSH/sudo.
    return sh(
        f"sshpass -p {shlex.quote(SSHPASS)} ssh -o StrictHostKeyChecking=no "
        f"{host} {shlex.quote(remote_cmd)}",
        check=check, capture=capture)


def scp(src: str, dst: str) -> None:
    sh(f"sshpass -p {shlex.quote(SSHPASS)} scp -q "
       f"-o StrictHostKeyChecking=no {src} {dst}")


def run_trial(*, config_path: Path, trial_id: str, vision: str, switch: str,
              controller_log: str, remote_workdir: str,
              local_out_dir: Path, post_wait_s: float,
              seed_override: int | None = None) -> None:
    local_out_dir.mkdir(parents=True, exist_ok=True)

    # Push config + scenarios.py + run_trial.py to Vision's tmp workdir.
    vision_workdir = "/tmp/ota_experiments"
    ssh(vision, f"mkdir -p {vision_workdir}")
    scp(f"{Path(__file__).parent / 'scenarios.py'}", f"{vision}:{vision_workdir}/")
    scp(f"{Path(__file__).parent / 'run_trial.py'}", f"{vision}:{vision_workdir}/")

    # If seed_override is set, materialise a per-trial config with the
    # patched seed so stochastic scenarios produce independent trials.
    if seed_override is not None:
        import yaml
        cfg = yaml.safe_load(config_path.read_text())
        cfg.setdefault("params", {})["seed"] = int(seed_override)
        patched = local_out_dir / "cfg.yaml"
        patched.write_text(yaml.safe_dump(cfg))
        scp(str(patched), f"{vision}:{vision_workdir}/cfg.yaml")
    else:
        scp(str(config_path), f"{vision}:{vision_workdir}/cfg.yaml")

    # Mark start byte-offsets on switch for both the digest log and the
    # controller decisions log (real, not inferred — written by the
    # controller's evaluate_hold arbiter).
    decisions_log = str(Path(controller_log).parent / "decisions.jsonl")
    t0 = ssh(switch, f"stat -c %s {controller_log} 2>/dev/null || echo 0",
             capture=True).stdout.strip()
    t0_d = ssh(switch,
               f"stat -c %s {decisions_log} 2>/dev/null || echo 0",
               capture=True).stdout.strip()
    try:
        start_offset = int(t0)
    except ValueError:
        start_offset = 0
    try:
        start_offset_dec = int(t0_d)
    except ValueError:
        start_offset_dec = 0

    # Run the trial on Vision.
    # sudo -S reads the password from stdin (Vision is not NOPASSWD).
    gt_remote = f"{vision_workdir}/ground_truth_{trial_id}.json"
    ssh(vision,
        f"cd {vision_workdir} && echo {shlex.quote(SSHPASS)} | "
        f"sudo -S -p '' python3 run_trial.py "
        f"--config cfg.yaml --out-json {gt_remote} --trial-id {trial_id}")

    # Let the controller drain digests.
    time.sleep(post_wait_s)

    # Slice the switch logs for this trial.
    digest_slice = f"{remote_workdir}/trial_{trial_id}_digests.jsonl"
    ctrl_slice   = f"{remote_workdir}/trial_{trial_id}_controller.jsonl"
    ssh(switch, f"mkdir -p {remote_workdir}")
    # M2 fix (code review): guard against silent truncation if the
    # controller log was rotated mid-trial. Verify current size >=
    # start_offset before slicing; otherwise the trial is invalid.
    cur_size = ssh(switch,
                   f"stat -c %s {controller_log} 2>/dev/null || echo 0",
                   capture=True).stdout.strip()
    try:
        cur_size_i = int(cur_size)
    except ValueError:
        cur_size_i = 0
    if cur_size_i < start_offset:
        # File rotated/shrunk under us — record an explicit error.
        with open(local_out_dir / "trial_invalid.txt", "w") as f:
            f.write(f"controller_log shrank during trial: "
                    f"start={start_offset} now={cur_size_i}\n")
        print(f"  [WARN] {trial_id}: controller_log rotated mid-trial; "
              "marking trial INVALID.")
    ssh(switch,
        f"tail -c +{start_offset + 1} {controller_log} > {digest_slice}")
    ssh(switch,
        f"if [ -f {decisions_log} ]; then "
        f"  tail -c +{start_offset_dec + 1} {decisions_log} > {ctrl_slice}; "
        f"else : > {ctrl_slice}; fi")

    # Pull artefacts back to workstation.
    scp(f"{vision}:{gt_remote}",    f"{local_out_dir}/ground_truth.json")
    scp(f"{switch}:{digest_slice}", f"{local_out_dir}/decisions.jsonl")
    scp(f"{switch}:{ctrl_slice}",   f"{local_out_dir}/controller_decisions.jsonl")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--configs", nargs="+", required=True, type=Path)
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--vision", required=True)
    ap.add_argument("--switch", required=True)
    ap.add_argument("--controller-log", required=True)
    ap.add_argument("--remote-workdir", default="/home/decps/my_program/ota/experiments")
    ap.add_argument("--local-out", default="runs/experiments", type=Path)
    ap.add_argument("--post-wait", type=float, default=10.0)
    ap.add_argument("--inter-trial-wait", type=float, default=70.0,
                    help="Seconds between trials (default 70 to clear R5 window)")
    ap.add_argument("--reset-between-trials", type=int, default=1,
                    help="1=reset detector state (IID trials) via SIGUSR1; "
                         "0=leave state as-is (operational carryover mode)")
    ap.add_argument("--seed-per-trial", type=int, default=1,
                    help="If 1, override the YAML's params.seed with the "
                         "trial index for each trial. Use for stochastic "
                         "scenarios so trials are independent draws.")
    args = ap.parse_args()

    for cfg_path in args.configs:
        exp_id = cfg_path.stem
        for trial in range(args.trials):
            trial_id = f"{exp_id}_t{trial:02d}"
            print(f"\n=== Trial {trial_id} ===")
            # Reset detector state BEFORE each trial so trials are IID.
            # We signal the running controller via SIGUSR1 (handle_reset).
            if args.reset_between_trials:
                # Resolve the python controller PID explicitly (the bash
                # launcher's cmdline also contains the path string, so a
                # pkill -f match would target the wrong process). Then
                # SIGUSR1 via sudo -S since the controller runs as root.
                reset_cmd = (
                    "PID=$(ps -eo pid,comm,cmd --no-headers | "
                    "awk '$2 ~ /^python/ && $0 ~ "
                    "/controller\\/ota_shield_controller\\.py/ "
                    "{print $1; exit}'); "
                    f"if [ -n \"$PID\" ]; then echo {shlex.quote(SSHPASS)} "
                    "| sudo -S -p '' kill -USR1 $PID; "
                    "echo \"sent SIGUSR1 to $PID\"; "
                    "else echo no-controller; fi"
                )
                ssh(args.switch, reset_cmd, check=False)
                # Measured duration of handle_reset(): ~10s (R1 reseed +
                # R5 bloom clear × 1024 + R6 clear × 256 + session_bytes
                # clear × 64 batches + logged barrier). The previous 2s
                # sleep caused E12 benign_staged wave-1 packets to race
                # with the controller's reset-completion, producing
                # 12/50 no-decision events per trial. 15s gives ~5s
                # headroom.
                time.sleep(15)
            seed = trial if args.seed_per_trial else None
            run_trial(
                config_path=cfg_path, trial_id=trial_id,
                vision=args.vision, switch=args.switch,
                controller_log=args.controller_log,
                remote_workdir=args.remote_workdir,
                local_out_dir=args.local_out / exp_id / f"t{trial:02d}",
                post_wait_s=args.post_wait,
                seed_override=seed,
            )
            if trial < args.trials - 1:
                print(f"[sweep] Waiting {args.inter_trial_wait}s "
                      "for R5 window clear...")
                time.sleep(args.inter_trial_wait)


if __name__ == "__main__":
    main()
