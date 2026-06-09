"""E12b (signed-manifest) HW driver.

Orchestrates a full E12b trial sweep against the physical bench:
    workstation --ssh--> vision (packet source)
    workstation --ssh--> switch (controller host, RAT manifest)

For each trial:
  1. Verify the controller is running with `--require-signed-rat` by
     tailing its log for "RAT loaded: N entries, signed=True". Abort
     if signed=False or if the log line is missing.
  2. Snapshot controller/rat_e12.json.sig so we can restore it later.
  3. Launch Vision's run_trial.py with E12b_signed_manifest.yaml. This
     uses scenarios_e12b.pack_benign_rollout_signed, which emits a
     marker GroundTruthEvent just before the Phase-B injection window.
  4. When the Phase-B marker fires (detected by polling Vision's
     in-progress ground_truth_*.json), SSH to the switch and flip one
     byte of rat_e12.json.sig (then flip it back a few seconds later).
     This MUST trigger the controller's inotify watcher, cause a
     SignatureError, and log "RAT reload REJECTED".
  5. After the trial finishes, restore the original .sig byte, pull
     the controller log slice, and leave the bench clean.

This script does NOT execute HW on your behalf — it only provides the
orchestration. `--dry-run` (default OFF) prints the commands it would
run without touching the bench. For the actual HW replay the reviewer
asked for, a bench operator invokes:

    python3 experiments/run_e12b.py \\
        --vision decps@10.10.54.19 \\
        --switch decps@10.10.54.15 \\
        --controller-log /home/decps/my_program/ota/runs/phase6_digests.jsonl \\
        --rat-sig /home/decps/my_program/ota/controller/rat_e12.json.sig \\
        --trials 20

and then runs aggregate_e12b.py on the pulled artifacts.
"""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
import time
from pathlib import Path


# --------------------------------------------------------------------- shell


def _run(cmd: str, *, check: bool = True, capture: bool = False,
         dry_run: bool = False) -> subprocess.CompletedProcess | None:
    if dry_run:
        print(f"[dry-run] {cmd}")
        return None
    return subprocess.run(cmd, shell=True, check=check,
                          capture_output=capture, text=True)


def _ssh(host: str, remote_cmd: str, *, check: bool = True,
         capture: bool = False,
         dry_run: bool = False) -> subprocess.CompletedProcess | None:
    return _run(
        f"ssh -o StrictHostKeyChecking=no {host} {shlex.quote(remote_cmd)}",
        check=check, capture=capture, dry_run=dry_run)


def _scp(src: str, dst: str, *, dry_run: bool = False) -> None:
    _run(f"scp -q -o StrictHostKeyChecking=no {src} {dst}", dry_run=dry_run)


# --------------------------------------------------------------------- checks


def assert_signed_at_startup(switch: str, controller_log: str,
                             *, dry_run: bool) -> None:
    """Tail the controller log and confirm the most recent `RAT loaded:`
    line is signed=True. Raises SystemExit otherwise so a misconfigured
    bench cannot silently produce a "passes because unsigned fallback"
    result that would corrupt the paper's M6 claim.
    """
    cmd = (f"grep 'RAT loaded:' {shlex.quote(controller_log)} "
           "| tail -n 1 || true")
    if dry_run:
        print(f"[dry-run] ssh {switch} {cmd}")
        return
    res = _ssh(switch, cmd, capture=True)
    line = (res.stdout or "").strip() if res else ""
    if not line:
        raise SystemExit(
            f"ERROR: no 'RAT loaded:' line in {controller_log}. "
            "Start the controller with --rat-sig/--rat-pub/"
            "--require-signed-rat before running E12b.")
    if "signed=True" not in line:
        raise SystemExit(
            f"ERROR: controller is NOT in signed-manifest mode.\n"
            f"  last load line: {line}\n"
            "Aborting so the E12b numbers don't mis-represent the "
            "signed path. Restart controller with --require-signed-rat.")
    print(f"[ok] controller in signed mode: {line}")


# --------------------------------------------------------------------- sig op


def snapshot_sig(switch: str, sig_path: str, *, dry_run: bool) -> str:
    """Copy the sig file to a timestamped backup and return the remote
    backup path. Used to restore the bench after each trial."""
    backup = f"{sig_path}.e12b.bak.{int(time.time())}"
    _ssh(switch, f"cp {shlex.quote(sig_path)} {shlex.quote(backup)}",
         dry_run=dry_run)
    return backup


def corrupt_sig(switch: str, sig_path: str, *, dry_run: bool) -> None:
    """Flip a single byte of the .sig file. One bit is enough for
    ed25519 to reject, and using dd means we don't need pynacl on the
    switch host."""
    # Read byte 0, XOR with 0xff, write back. `printf | dd` avoids
    # having to ship a helper script to the switch.
    cmd = (
        f"python3 - <<'PY'\n"
        f"from pathlib import Path\n"
        f"p = Path({sig_path!r})\n"
        f"b = bytearray(p.read_bytes())\n"
        f"b[0] ^= 0xff\n"
        f"p.write_bytes(bytes(b))\n"
        f"print('corrupted', p)\n"
        f"PY"
    )
    _ssh(switch, cmd, dry_run=dry_run)


def restore_sig(switch: str, sig_path: str, backup: str,
                *, dry_run: bool) -> None:
    _ssh(switch, f"mv {shlex.quote(backup)} {shlex.quote(sig_path)}",
         dry_run=dry_run)


# --------------------------------------------------------------------- trial


def run_one_trial(*, vision: str, switch: str, trial_id: str,
                  controller_log: str, startup_log: str, sig_path: str,
                  config_path: Path, remote_workdir: str,
                  local_out_dir: Path, post_wait_s: float,
                  controller_pid: int | None,
                  dry_run: bool) -> None:
    local_out_dir.mkdir(parents=True, exist_ok=True)

    # Pre-flight: signed mode (greps controller startup stdout/stderr).
    assert_signed_at_startup(switch, startup_log, dry_run=dry_run)

    # Pre-trial state reset. SIGUSR1 fires the controller's handle_reset
    # which clears R6_MAX_VERSION_REGISTER (256 slots), R5 count + bloom,
    # session_bytes / session_first_ts, and pending session overrides.
    # Without this, P4-ASIC register state from a prior experiment leaks
    # into trial 1 and every benign packet at version N < max_seen trips
    # R6 -> DROP via session-override bleed (observed 2026-04-20 dry-run).
    if controller_pid is not None:
        _ssh(switch, f"kill -USR1 {controller_pid}", dry_run=dry_run)
        if not dry_run:
            time.sleep(4.0)  # let handle_reset finish (256+R5 bloom clears)
        print(f"[ok] sent SIGUSR1 to controller pid={controller_pid}")
    else:
        print("[warn] no --controller-pid-hint; skipping pre-trial SIGUSR1. "
              "Trial may inherit R6 baseline from prior experiment.")

    # Stage code on Vision.
    here = Path(__file__).parent
    vision_workdir = "/tmp/ota_experiments"
    _ssh(vision, f"mkdir -p {vision_workdir}", dry_run=dry_run)
    for f in ("scenarios.py", "scenarios_e12b.py", "run_trial.py"):
        _scp(str(here / f), f"{vision}:{vision_workdir}/", dry_run=dry_run)
    _scp(str(config_path), f"{vision}:{vision_workdir}/cfg.yaml",
         dry_run=dry_run)

    # Start-offset markers on the switch log for later slicing.
    if not dry_run:
        res = _ssh(switch,
                   f"stat -c %s {controller_log} 2>/dev/null || echo 0",
                   capture=True)
        start_offset = int((res.stdout or "0").strip() or 0)
    else:
        start_offset = 0
        print(f"[dry-run] (pretending start_offset=0)")

    # Back up the sig so we can always restore it.
    backup = snapshot_sig(switch, sig_path, dry_run=dry_run)

    # Kick off the trial on Vision in the background so we can poll its
    # ground-truth file for the Phase-B marker and inject the sig
    # corruption on time.
    gt_remote = f"{vision_workdir}/ground_truth_{trial_id}.json"
    trial_cmd = (
        f"cd {vision_workdir} && sudo python3 run_trial.py "
        f"--config cfg.yaml --out-json {gt_remote} --trial-id {trial_id}"
    )
    trial_pid_file = f"{vision_workdir}/trial_{trial_id}.pid"
    launch = (
        f"nohup bash -c {shlex.quote(trial_cmd)} "
        f"> {vision_workdir}/trial_{trial_id}.out 2>&1 & "
        f"echo $! > {trial_pid_file}"
    )
    _ssh(vision, launch, dry_run=dry_run)

    # Poll for the Phase-B marker. run_trial.py writes ground_truth
    # incrementally? Currently it writes only at the end, so we instead
    # time-synchronise: the marker fires ~ (3 + 5*(50 + 70) + 70 + 70 +
    # 70 + 70) seconds into the scenario given the sleeps in
    # pack_benign_rollout_signed. That is brittle; a safer approach is
    # to have the operator supply --phase-b-delay-s which defaults to
    # a generous lower bound.
    #
    # For the HW rerun the reviewer asked for, we use the default delay
    # below and cross-check with the controller log after the fact.
    # --dry-run just prints the would-be timeline.
    phase_b_delay_s = 3.0 + 5 * (50 + 70) + 70 + 70 + 70 + 70
    print(f"[info] waiting {phase_b_delay_s:.0f}s for Phase B marker")
    if not dry_run:
        time.sleep(phase_b_delay_s)

    # Corrupt the sig. Controller's inotify watcher must observe this,
    # fail verify, and log "RAT reload REJECTED".
    print("[info] corrupting rat_e12.json.sig (one byte flip)")
    corrupt_sig(switch, sig_path, dry_run=dry_run)

    # Give the controller ~5s to log the REJECT, then restore so the
    # next trial starts with a valid sig. The scenario's last-known-
    # good probe burst runs during this restore window; that is fine
    # because the controller kept the old cache regardless.
    if not dry_run:
        time.sleep(5.0)
    restore_sig(switch, sig_path, backup, dry_run=dry_run)

    # Wait for Vision's trial to finish (indicated by the
    # ground-truth file appearing).
    if not dry_run:
        for _ in range(120):  # up to 2 min extra
            res = _ssh(vision, f"test -s {gt_remote} && echo ok || echo no",
                       capture=True, check=False)
            if res and (res.stdout or "").strip() == "ok":
                break
            time.sleep(5.0)
    time.sleep(post_wait_s)

    # Slice the controller log for this trial and pull artifacts.
    ctrl_slice = f"{remote_workdir}/trial_{trial_id}_controller.log"
    _ssh(switch, f"mkdir -p {remote_workdir}", dry_run=dry_run)
    _ssh(switch,
         f"tail -c +{start_offset + 1} {controller_log} > {ctrl_slice}",
         dry_run=dry_run)
    _scp(f"{vision}:{gt_remote}",
         f"{local_out_dir}/ground_truth.json", dry_run=dry_run)
    _scp(f"{switch}:{ctrl_slice}",
         f"{local_out_dir}/controller.log", dry_run=dry_run)

    print(f"[ok] trial {trial_id} artifacts in {local_out_dir}")


# --------------------------------------------------------------------- main


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--vision", required=True,
                    help="ssh target for the packet source (e.g. "
                         "decps@10.10.54.19)")
    ap.add_argument("--switch", required=True,
                    help="ssh target for the controller host")
    ap.add_argument("--controller-log", required=True,
                    help="absolute path to the controller DECISIONS log "
                         "(jsonl) on the switch host; byte-offset sliced "
                         "per trial")
    ap.add_argument("--startup-log",
                    default="/tmp/controller.log",
                    help="absolute path to the controller STARTUP log "
                         "(stderr/stdout) on the switch host; greppped "
                         "for 'RAT loaded:' signed=True assertion")
    ap.add_argument("--rat-sig", required=True,
                    help="absolute path to controller/rat_e12.json.sig "
                         "on the switch host")
    ap.add_argument("--config",
                    default=Path(__file__).parent / "configs" /
                    "E12b_signed_manifest.yaml", type=Path)
    ap.add_argument("--trials", type=int, default=20)
    ap.add_argument("--remote-workdir",
                    default="/home/decps/my_program/ota/experiments")
    ap.add_argument("--local-out",
                    default=Path("runs/experiments/E12b_signed_manifest"),
                    type=Path)
    ap.add_argument("--post-wait", type=float, default=10.0)
    ap.add_argument("--inter-trial-wait", type=float, default=70.0)
    ap.add_argument("--dry-run", action="store_true",
                    help="print the commands that would run; do NOT "
                         "touch the bench")
    ap.add_argument("--safe", action="store_true",
                    help="pass --safe through to preflight (skip "
                         "destructive negative reload test)")
    ap.add_argument("--skip-preflight", action="store_true",
                    help="bypass the preflight verifier (USE WITH CARE)")
    ap.add_argument("--controller-pid-hint", type=int, default=None,
                    help="forward to preflight as a hint for /proc lookup")
    args = ap.parse_args()

    if not args.config.exists():
        print(f"ERROR: config {args.config} missing", file=sys.stderr)
        return 1

    # Preflight is the kill switch. We refuse to touch the bench unless
    # every check is green.
    if not args.dry_run:
        try:
            from experiments.preflight_e12b import main as _preflight
        except ImportError:
            sys.path.insert(0, str(Path(__file__).parent))
            from preflight_e12b import main as _preflight  # type: ignore
        pf_argv = ["--vision", args.vision, "--switch", args.switch]
        if args.safe:
            pf_argv.append("--safe")
        if args.skip_preflight:
            pf_argv.append("--skip-preflight")
        if args.controller_pid_hint is not None:
            pf_argv += ["--controller-pid-hint", str(args.controller_pid_hint)]
        rc = _preflight(pf_argv)
        if rc != 0:
            print(f"ERROR: preflight failed (rc={rc}); aborting E12b.",
                  file=sys.stderr)
            return rc

    for i in range(args.trials):
        trial_id = f"E12b_signed_t{i:02d}"
        print(f"\n=== Trial {trial_id} ===")
        try:
            run_one_trial(
                vision=args.vision, switch=args.switch, trial_id=trial_id,
                controller_log=args.controller_log,
                startup_log=args.startup_log,
                sig_path=args.rat_sig,
                config_path=args.config,
                remote_workdir=args.remote_workdir,
                local_out_dir=args.local_out / f"t{i:02d}",
                post_wait_s=args.post_wait,
                controller_pid=args.controller_pid_hint,
                dry_run=args.dry_run,
            )
        except SystemExit:
            raise
        except Exception as exc:  # noqa: BLE001
            print(f"[warn] trial {trial_id} failed: {exc}")
        if i < args.trials - 1:
            print(f"[sweep] waiting {args.inter_trial_wait}s "
                  "for R5 window clear")
            if not args.dry_run:
                time.sleep(args.inter_trial_wait)

    print("\nDone. Next step: "
          "python3 experiments/aggregate_e12b.py "
          f"--exp-dir {args.local_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
