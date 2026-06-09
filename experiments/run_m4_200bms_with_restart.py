"""M4 200-BMS hardware replay with controller restart.

Extends the canonical RAT to cover BMSes 10.0.2.10..209, restarts the
Python controller so it installs the data-plane BMS index table for
the extended fleet, replays the E1' and E8' pcaps, and restores the
canonical RAT plus a controller restart at the end so the system is
left in its prior state.

The controller is logged to `runs/controller_smoke.log` and started
with the same environment block as the in-place process. We never
restart `bf_switchd`; only the Python process.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import logging
import shlex
import subprocess
import time
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_m4_200bms import (  # noqa: E402  (sibling module reuse)
    SWITCH_HOST, SWITCH_OTA, SWITCH_RAT, SWITCH_SIG, SWITCH_LOG,
    SWITCH_DECISIONS, SWITCH_KEY, SSH_PASS,
    _ssh, _scp_from, _scp_to,
    snapshot_canonical_rat, build_extended_rat, push_and_sign,
    wait_for_reload, get_decisions_offset, slice_decisions, replay_pcap,
    restore_canonical, REPO_ROOT,
)

logger = logging.getLogger(__name__)

CONTROLLER_LAUNCH_CMD = (
    f"cd {SWITCH_OTA} && "
    f"echo {shlex.quote(SSH_PASS)} | sudo -SE setsid env "
    "SDE=/home/decps/Downloads/bf-sde-9.13.2 "
    "SDE_INSTALL=/home/decps/Downloads/bf-sde-9.13.2/install "
    "LD_LIBRARY_PATH=/home/decps/Downloads/bf-sde-9.13.2/install/lib "
    "PYTHONPATH=/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/"
    "site-packages/tofino:/home/decps/Downloads/bf-sde-9.13.2/install/lib/"
    "python3.8/site-packages "
    "python3 controller/ota_shield_controller.py --require-signed-rat "
    f">> runs/controller_smoke.log 2>&1 < /dev/null &"
)

STARTUP_TIMEOUT_S = 60.0


def find_controller_pid() -> int | None:
    out = _ssh(SWITCH_HOST, "pgrep -f 'ota_shield_controller.py' | head -1")
    out = out.strip()
    if not out:
        return None
    try:
        return int(out)
    except ValueError:
        return None


def stop_controller(grace_s: float = 10.0) -> None:
    pid = find_controller_pid()
    if pid is None:
        logger.info("no controller running")
        return
    logger.info("stopping controller pid=%d", pid)
    _ssh(SWITCH_HOST,
         f"echo {shlex.quote(SSH_PASS)} | sudo -S kill -INT {pid} 2>/dev/null || true")
    deadline = time.time() + grace_s
    while time.time() < deadline:
        if find_controller_pid() is None:
            return
        time.sleep(0.5)
    logger.warning("controller did not exit on SIGINT; sending SIGTERM")
    _ssh(SWITCH_HOST,
         f"echo {shlex.quote(SSH_PASS)} | sudo -S kill -TERM {pid} 2>/dev/null || true")
    time.sleep(2.0)


def start_controller_and_wait(min_t: float) -> dict:
    """Launch the controller and confirm it has loaded the RAT plus run
    its startup state reset before any traffic is replayed. Detection
    uses byte-offset growth on `controller_smoke.log` rather than
    timezone-sensitive timestamp parsing: we capture the log size right
    before launch and grep only the new tail for the two markers.
    """
    pre_size = int(_ssh(SWITCH_HOST,
                        f"stat -c %s {shlex.quote(SWITCH_LOG)}").strip())
    _ssh(SWITCH_HOST, CONTROLLER_LAUNCH_CMD, capture=False)
    deadline = time.time() + STARTUP_TIMEOUT_S
    saw_rat = False
    saw_reset = False
    while time.time() < deadline:
        try:
            tail = _ssh(
                SWITCH_HOST,
                f"tail -c +{pre_size + 1} {shlex.quote(SWITCH_LOG)} | "
                f"grep -E 'RAT loaded:|Startup state reset|install_bms_index' "
                f"|| true",
            )
        except RuntimeError:
            time.sleep(1.0)
            continue
        if tail:
            saw_rat = saw_rat or ("RAT loaded" in tail)
            saw_reset = saw_reset or ("Startup state reset" in tail)
            if saw_rat and saw_reset:
                return {"rat_line": _first_match(tail, "RAT loaded"),
                        "startup_line": _first_match(tail, "Startup state reset")}
        time.sleep(1.0)
    raise RuntimeError(
        f"controller did not finish startup within {STARTUP_TIMEOUT_S}s "
        f"(rat_seen={saw_rat} reset_seen={saw_reset})"
    )


def _first_match(text: str, needle: str) -> str:
    for line in text.splitlines():
        if needle in line:
            return line.strip()
    return ""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--work-dir", type=Path,
                    default=Path("runs/m4/_m4_200bms_session_state_restart"))
    ap.add_argument("--drain-after-replay-s", type=float, default=30.0)
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if not args.execute:
        logger.info("dry run; pass --execute to actually run")
        return 0

    work_dir = args.work_dir
    work_dir.mkdir(parents=True, exist_ok=True)

    snapshot = None
    session: dict = {"started_at": _dt.datetime.now().isoformat(timespec="seconds"),
                     "scenarios": []}

    try:
        logger.info("snapshotting canonical RAT")
        snapshot = snapshot_canonical_rat(work_dir)

        extended_json = work_dir / f"rat.json.extended.{snapshot['stamp']}"
        build_extended_rat(snapshot["canonical_json"], extended_json)
        push_and_sign(extended_json)
        logger.info("extended RAT pushed and signed: %s", extended_json)

        stop_controller()
        restart_t = time.time()
        startup = start_controller_and_wait(restart_t - 5)
        logger.info("controller restarted: %s", startup)
        session["restart_with_extended"] = startup

        time.sleep(2.0)  # let BMS-index installs settle

        for scenario in ("E1_200bms", "E8_200bms"):
            scenario_dir = REPO_ROOT / "runs" / "m4" / scenario
            local_pcap = scenario_dir / "traffic.pcap"
            offset_start = get_decisions_offset()
            replay_meta = replay_pcap(local_pcap, scenario)
            logger.info("%s replay: %s", scenario, replay_meta)
            time.sleep(args.drain_after_replay_s)
            offset_end = get_decisions_offset()

            trial_dir = scenario_dir / "trial_01_restart"
            trial_dir.mkdir(parents=True, exist_ok=True)
            slice_path = trial_dir / "controller_decisions.jsonl"
            slice_decisions(offset_start, offset_end, slice_path)

            scenario_record = {
                "scenario": scenario,
                "trial_dir": str(trial_dir),
                "offset_start": offset_start,
                "offset_end": offset_end,
                "bytes_captured": offset_end - offset_start,
                **replay_meta,
            }
            (trial_dir / "m4_200bms_replay_meta.json").write_text(
                json.dumps(scenario_record, indent=2)
            )
            session["scenarios"].append(scenario_record)
            logger.info(
                "%s captured: %d bytes -> %s",
                scenario, scenario_record["bytes_captured"], slice_path,
            )
    finally:
        if snapshot is not None:
            try:
                logger.info("restoring canonical RAT and restarting controller")
                restore_canonical(snapshot)
                stop_controller()
                restart_t2 = time.time()
                startup2 = start_controller_and_wait(restart_t2 - 5)
                session["restart_canonical"] = startup2
                logger.info("controller restarted on canonical RAT: %s", startup2)
            except Exception as exc:
                logger.error("restore-canonical failed: %s", exc)
                session["restore_error"] = str(exc)

    session["finished_at"] = _dt.datetime.now().isoformat(timespec="seconds")
    session_path = work_dir / f"session_{snapshot['stamp']}.json"
    session_path.write_text(json.dumps(session, indent=2, default=str))
    logger.info("session record: %s", session_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
