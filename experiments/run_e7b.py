"""E7b 8-hour overnight driver with resume-on-disconnect and heartbeats.

This script executes the deterministic plan produced by
`scenarios_e7b.pack_e7b_slow_cadence`. Unlike the existing scenario
packs (which loop inline around `time.sleep(...)`), E7b has to survive
an 8-hour overnight run:

* every planned event is checkpointed to disk *before* its packet goes
  out, so a driver crash / SSH drop can resume on the next launch;
* a heartbeat line is appended to the log every 15 minutes so a human
  monitoring the overnight run can see progress at a glance;
* start and end wall-clock timestamps are written as discrete events
  so the switch controller's decisions log can be sliced offline.

Usage
-----
Typical invocation on the Vision host::

    sudo python3 run_e7b.py \\
        --config experiments/configs/E7b_slow_cadence.yaml \\
        --trial-id E7b_slow_cadence_t00 \\
        --out-dir runs/experiments/E7b_slow_cadence/t00

If the script is re-launched with the same `--out-dir`, it detects
existing `checkpoint.json` and `ground_truth.partial.jsonl`, recovers
the cursor, and resumes sending at the correct wall-clock offset.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import signal
import sys
import time
from pathlib import Path
from typing import Optional

# Local imports — scenarios_e7b is dependency-light; scapy is only
# required inside `_send` from the primary scenarios module.
import scenarios_e7b


HEARTBEAT_INTERVAL_S: float = 15 * 60  # 15 minutes


# ----------------------- plan / checkpoint I/O -----------------------


def load_yaml(path: Path) -> dict:
    """Minimal YAML loader. Imports PyYAML lazily so this file can still
    be imported on hosts without PyYAML for plan-inspection tasks."""
    import yaml
    return yaml.safe_load(path.read_text())


def build_plan(cfg: dict) -> list[scenarios_e7b.E7bPlannedEvent]:
    """Translate a parsed YAML config into a plan list."""
    params = cfg.get("params", {})
    scenario = cfg.get("scenario", "pack_e7b_slow_cadence")
    if scenario != "pack_e7b_slow_cadence":
        raise SystemExit(f"run_e7b.py only accepts scenario "
                         f"'pack_e7b_slow_cadence' (got '{scenario}')")
    return scenarios_e7b.pack_e7b_slow_cadence(**params)


def write_plan(plan: list[scenarios_e7b.E7bPlannedEvent],
               out_dir: Path) -> Path:
    """Persist the plan to disk for reproducibility + resume."""
    path = out_dir / "plan.jsonl"
    with path.open("w") as f:
        for ev in plan:
            f.write(json.dumps(dataclasses.asdict(ev)) + "\n")
    return path


def read_checkpoint(out_dir: Path) -> Optional[dict]:
    """Return the persisted checkpoint dict (or None on first launch)."""
    path = out_dir / "checkpoint.json"
    if not path.exists():
        return None
    return json.loads(path.read_text())


def write_checkpoint(out_dir: Path, state: dict) -> None:
    """Atomic-rewrite checkpoint so resume is crash-safe."""
    path = out_dir / "checkpoint.json"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(path)


# --------------------------- heartbeat log ---------------------------


def heartbeat(out_dir: Path, msg: dict) -> None:
    """Append a heartbeat record to `heartbeat.jsonl`. Safe to call
    from a signal handler: one write(), no buffering surprises."""
    line = json.dumps({"t_wall": time.time(), **msg}) + "\n"
    with (out_dir / "heartbeat.jsonl").open("a") as f:
        f.write(line)
    # Also mirror to stdout so the overnight tmux/tail -f shows it.
    sys.stdout.write(line)
    sys.stdout.flush()


# ----------------------------- sender -------------------------------


def _send_packet(src_ip: str, dst_ip: str, sport: int,
                 topic: str, version: int, size: int,
                 vision: str = "decps@10.10.54.19",
                 vision_pw: Optional[str] = None,
                 iface: str = "enp59s0f0np0") -> None:
    """Send one packet by invoking a pre-staged scapy helper on Vision
    over ssh. The laptop does not own the data-plane NIC, so local
    scapy.sendp cannot reach the switch; mirror E22's ssh-to-Vision
    pattern. The helper at /tmp/_e7b_send_one.py on Vision must be
    pre-staged once per run (handled by preflight / launcher)."""
    import shlex
    import subprocess
    # SSH password read from environment — never hardcode; set via source ~/.lab_env
    if vision_pw is None:
        vision_pw = os.environ.get("OTA_SSHPASS", "")
        if not vision_pw:
            raise RuntimeError("OTA_SSHPASS env var not set; source ~/.lab_env first")
    args = [src_ip, dst_ip, str(sport), topic, str(version),
            str(size), iface]
    remote = ("sudo -n python3 /tmp/_e7b_send_one.py "
              + " ".join(shlex.quote(a) for a in args))
    # Use `sshpass -e` (password from the SSHPASS env var) rather than
    # `-p <pw>` so the secret never appears in argv / CalledProcessError
    # logs over a long unattended run (security.md: no secrets in logs).
    cmd = ["sshpass", "-e", "ssh",
           "-o", "StrictHostKeyChecking=no",
           "-o", "ConnectTimeout=10",
           vision, remote]
    env = {**os.environ, "SSHPASS": vision_pw}
    subprocess.run(cmd, check=True, capture_output=True, timeout=20,
                   env=env)


# ----------------------------- driver --------------------------------


def _append_gt_line(out_dir: Path, record: dict) -> None:
    """Append one ground-truth record as JSONL. We write a line-per-event
    file for crash safety, then collapse into the standard
    ground_truth.json at the end of the run."""
    with (out_dir / "ground_truth.partial.jsonl").open("a") as f:
        f.write(json.dumps(record) + "\n")


def _collapse_partial(out_dir: Path,
                      trial_id: str,
                      cfg: dict,
                      t_start: float,
                      t_end: float) -> Path:
    """Fold the crash-safe partial JSONL into the canonical
    ground_truth.json contract expected by `aggregate.py` / `aggregate_e7b.py`.

    Fields intentionally mirror `run_trial.py`'s schema so downstream
    code can treat E7b identically to every other experiment."""
    partial = out_dir / "ground_truth.partial.jsonl"
    events: list[dict] = []
    if partial.exists():
        for line in partial.read_text().splitlines():
            line = line.strip()
            if line:
                events.append(json.loads(line))
    out = {
        "trial_id": trial_id,
        "config": cfg,
        "t_start": t_start,
        "t_end": t_end,
        "n_events": len(events),
        "events": events,
    }
    path = out_dir / "ground_truth.json"
    path.write_text(json.dumps(out, indent=2))
    return path


def run(cfg_path: Path, out_dir: Path, trial_id: str,
        dry_run: bool = False) -> None:
    """Execute the E7b plan with resume + heartbeats."""
    out_dir.mkdir(parents=True, exist_ok=True)
    cfg = load_yaml(cfg_path)

    # Load-or-build the plan. We persist it on first launch and re-load
    # it on resume to guarantee byte-identical replay (seed alone is
    # not enough if the YAML was edited mid-run).
    plan_path = out_dir / "plan.jsonl"
    if plan_path.exists():
        plan: list[scenarios_e7b.E7bPlannedEvent] = []
        for line in plan_path.read_text().splitlines():
            if not line.strip():
                continue
            d = json.loads(line)
            plan.append(scenarios_e7b.E7bPlannedEvent(**d))
        print(f"[E7b] resumed plan with {len(plan)} events from {plan_path}")
    else:
        plan = build_plan(cfg)
        write_plan(plan, out_dir)
        print(f"[E7b] wrote plan with {len(plan)} events to {plan_path}")

    summary = scenarios_e7b.summarize_plan(plan)
    print(f"[E7b] plan summary: {json.dumps(summary)}")

    # Resume state.
    ckpt = read_checkpoint(out_dir)
    if ckpt is not None:
        run_start_wall: float = float(ckpt["run_start_wall"])
        next_idx: int = int(ckpt["next_idx"])
        print(f"[E7b] resuming at idx={next_idx}/{len(plan)}; "
              f"run_start_wall={run_start_wall}")
    else:
        run_start_wall = time.time()
        next_idx = 0
        write_checkpoint(out_dir, {
            "run_start_wall": run_start_wall,
            "next_idx": 0,
            "trial_id": trial_id,
            "config_path": str(cfg_path),
            "plan_size": len(plan),
        })

    # Header event: records a start marker the aggregator uses to slice
    # the controller log. Emitted only on the initial launch.
    if ckpt is None:
        heartbeat(out_dir, {
            "event": "run_start",
            "trial_id": trial_id,
            "plan_size": len(plan),
            "plan_summary": summary,
        })

    # Graceful shutdown: persist checkpoint on SIGTERM/SIGINT so the
    # next resume starts at the right cursor.
    shutting_down = {"flag": False}

    def _handle_sig(signum, _frame):
        shutting_down["flag"] = True
        heartbeat(out_dir, {
            "event": "signal",
            "signum": int(signum),
            "next_idx_snapshot": next_idx,
        })

    signal.signal(signal.SIGTERM, _handle_sig)
    signal.signal(signal.SIGINT, _handle_sig)

    next_heartbeat = time.time() + HEARTBEAT_INTERVAL_S

    # Main loop.
    for i in range(next_idx, len(plan)):
        if shutting_down["flag"]:
            break
        ev = plan[i]
        target_wall = run_start_wall + ev.planned_offset_s
        now = time.time()
        # Emit a heartbeat at least every 15 minutes even during long
        # idle gaps between benign updates.
        while now < target_wall:
            remaining = target_wall - now
            sleep_for = min(remaining, max(0.0, next_heartbeat - now))
            if sleep_for > 0:
                time.sleep(sleep_for)
            now = time.time()
            if now >= next_heartbeat:
                heartbeat(out_dir, {
                    "event": "heartbeat",
                    "next_idx": i,
                    "elapsed_s": now - run_start_wall,
                    "remaining_events": len(plan) - i,
                })
                next_heartbeat = now + HEARTBEAT_INTERVAL_S
            if shutting_down["flag"]:
                break
        if shutting_down["flag"]:
            break

        # Send the packet (unless --dry-run). We call the sender first
        # and the ground-truth record reflects the actual wall-clock time
        # of transmission, matching the `GroundTruthEvent.t_send`
        # convention used by `scenarios.py`.
        t_send = time.time()
        if not dry_run:
            try:
                _send_packet(ev.src_ip, ev.dst_ip, ev.sport,
                             ev.topic, ev.ota_version, ev.ota_size)
            except Exception as exc:
                # Log but do not abort — an 8-hour run should not die on
                # one flaky sendp(); we record the failure and keep going.
                heartbeat(out_dir, {
                    "event": "send_error",
                    "idx": i,
                    "error": repr(exc),
                })
                continue

        # Record ground-truth event + advance cursor atomically.
        _append_gt_line(out_dir, {
            "t_send": t_send,
            "scenario": "e7b_slow_cadence",
            "label": ev.label,
            "src_ip": ev.src_ip,
            "dst_ip": ev.dst_ip,
            "src_port": ev.sport,
            "topic": ev.topic,
            "ota_size": ev.ota_size,
            "ota_version": ev.ota_version,
            "note": ev.note,
            "kind": ev.kind,
            "plan_idx": ev.idx,
            "planned_offset_s": ev.planned_offset_s,
        })
        write_checkpoint(out_dir, {
            "run_start_wall": run_start_wall,
            "next_idx": i + 1,
            "trial_id": trial_id,
            "config_path": str(cfg_path),
            "plan_size": len(plan),
        })

        # Heartbeat cadence also catches short inter-event gaps where
        # the while-loop above didn't sleep.
        if time.time() >= next_heartbeat:
            heartbeat(out_dir, {
                "event": "heartbeat",
                "next_idx": i + 1,
                "elapsed_s": time.time() - run_start_wall,
                "remaining_events": len(plan) - (i + 1),
            })
            next_heartbeat = time.time() + HEARTBEAT_INTERVAL_S

    # Final heartbeat + collapse partial into the canonical ground_truth.
    t_end = time.time()
    ckpt_now = read_checkpoint(out_dir) or {}
    reached = int(ckpt_now.get("next_idx", 0))
    if shutting_down["flag"] and reached < len(plan):
        heartbeat(out_dir, {
            "event": "run_suspended",
            "trial_id": trial_id,
            "next_idx": reached,
            "plan_size": len(plan),
        })
        print(f"[E7b] suspended at idx={reached}/{len(plan)}; "
              "rerun with the same --out-dir to resume.")
        return

    heartbeat(out_dir, {
        "event": "run_end",
        "trial_id": trial_id,
        "n_events": reached,
        "duration_s": t_end - run_start_wall,
    })
    gt_path = _collapse_partial(out_dir, trial_id, cfg,
                                 run_start_wall, t_end)
    print(f"[E7b] wrote {gt_path} ({reached} events, "
          f"{t_end - run_start_wall:.1f}s)")


# -------------------------- argparse shim ---------------------------


def _run_preflight(cfg_path: Path,
                   vision: str, switch: str,
                   controller_log: str,
                   require_fresh_controller: bool) -> None:
    """Invoke preflight_e7b.py as a subprocess. Aborts on non-zero exit.

    Importing preflight_e7b directly would work, but running it as a
    subprocess keeps its argparse contract identical to the CLI version
    a human would run and makes the failure mode a clean process
    boundary (no partially-initialized driver state)."""
    import subprocess  # stdlib import isolated to this helper
    here = Path(__file__).resolve().parent
    preflight = here / "preflight_e7b.py"
    if not preflight.exists():
        print(f"[E7b] preflight script missing at {preflight}; "
              "refusing to launch 8h run without preflight. "
              "Pass --skip-preflight at your own risk.", file=sys.stderr)
        sys.exit(2)
    cmd = [
        sys.executable, str(preflight),
        "--vision", vision,
        "--switch", switch,
        "--config-path", str(cfg_path),
        "--controller-log", controller_log,
    ]
    if require_fresh_controller:
        cmd.append("--require-fresh-controller")
    print(f"[E7b] running preflight: {' '.join(cmd)}")
    rc = subprocess.call(cmd)
    if rc != 0:
        print(f"[E7b] preflight FAILED (rc={rc}); "
              "fix the reported issues or rerun with --skip-preflight "
              "if you truly understand the risk.", file=sys.stderr)
        sys.exit(rc)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", type=Path, required=True,
                    help="YAML config (e.g. configs/E7b_slow_cadence.yaml)")
    ap.add_argument("--out-dir", type=Path, required=True,
                    help="Trial output directory (created if absent). "
                         "Re-using the same path triggers resume.")
    ap.add_argument("--trial-id", type=str,
                    default="E7b_slow_cadence_t00",
                    help="Trial identifier; recorded in ground_truth.json.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Execute the full schedule WITHOUT sending "
                         "packets (useful for plan validation).")
    # Preflight wiring.
    ap.add_argument("--skip-preflight", action="store_true",
                    help="Skip preflight_e7b.py. DO NOT use for real "
                         "overnight runs.")
    ap.add_argument("--vision", default="decps@10.10.54.19",
                    help="SSH target for the Vision traffic generator.")
    ap.add_argument("--switch", default="decps@10.10.54.15",
                    help="SSH target for the switch/controller host.")
    ap.add_argument("--controller-log", default="/tmp/controller.log",
                    help="Remote controller log tailed by preflight.")
    ap.add_argument("--require-fresh-controller", action="store_true",
                    help="Forward to preflight: fail if controller "
                         "uptime >= 1h.")
    args = ap.parse_args()

    if not args.skip_preflight:
        _run_preflight(cfg_path=args.config,
                       vision=args.vision, switch=args.switch,
                       controller_log=args.controller_log,
                       require_fresh_controller=args.require_fresh_controller)
    else:
        print("[E7b] WARNING: --skip-preflight set; proceeding without "
              "state verification.", file=sys.stderr)

    run(cfg_path=args.config, out_dir=args.out_dir,
        trial_id=args.trial_id, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
