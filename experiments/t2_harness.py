"""Shared hardware-orchestration helpers for the Tier-2 reruns.

Factors out the SSH / controller-reset / decision-slicing / manifest
plumbing common to ``run_t2_4.py``, ``run_t2_5.py``, ``run_t2_6.py`` and
``run_t2_8.py`` so each runner stays small and the contract details
(EXPERIMENT_DESIGN §3 manifest, §4 trial counts, controller SIGUSR1
reset per CLAUDE.md) live in exactly one place.

Nothing here touches hardware on import. All SSH calls require
``OTA_SSHPASS`` in the environment (security.md — never hardcode the
credential).  Runners pass ``execute=False`` (the default) to skip every
remote call so the harness is fully exercisable on the laptop.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from experiments.manifest import (  # noqa: E402
    TrialManifest, write_manifest, compute_file_sha, compute_p4_binary_sha,
)
from experiments.seed_schedule import derive_trial_seed  # noqa: E402

SWITCH = "decps@10.10.54.15"
VISION = "decps@10.10.54.19"   # eno1 mgmt IP (was .71 in old notes — run_t1_5 corrected)
SWITCH_OTA = "/home/decps/my_program/ota"
SWITCH_DECISIONS = f"{SWITCH_OTA}/runs/decisions.jsonl"
SWITCH_CONTROLLER_LOG = f"{SWITCH_OTA}/runs/controller_smoke.log"
SWITCH_P4_CONF = ("/home/decps/Downloads/bf-sde-9.13.2/build/ota_shield/"
                  "ota_shield.conf")
RAT_LIFECYCLE_LOCAL = REPO_ROOT / "controller" / "rat_lifecycle.py"


def _sshpass() -> str:
    pw = os.environ.get("OTA_SSHPASS", "")
    if not pw:
        raise RuntimeError(
            "OTA_SSHPASS env var not set; refuse to fall back to a literal "
            "credential (security.md). Source ~/.lab_env first.")
    return pw


def ssh(host: str, cmd: str, timeout: int = 60) -> tuple[int, str]:
    """Run a remote command via sshpass+ssh. Returns (rc, stdout+stderr)."""
    full = ["sshpass", "-p", _sshpass(), "ssh",
            "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
            host, cmd]
    p = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


def scp_to(host: str, local: Path, remote: str) -> None:
    full = ["sshpass", "-p", _sshpass(), "scp",
            "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
            str(local), f"{host}:{remote}"]
    subprocess.run(full, check=True, capture_output=True, text=True)


def scp_from(host: str, remote: str, local: Path) -> None:
    full = ["sshpass", "-p", _sshpass(), "scp",
            "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
            f"{host}:{remote}", str(local)]
    subprocess.run(full, check=True, capture_output=True, text=True)


def reset_controller_state(wait_s: float = 10.0) -> str:
    """Send SIGUSR1 to the controller (clears hold_armed_reg, R5 Bloom,
    session state — per CLAUDE.md takes ~9 s for the 256-slot write)."""
    pw = shlex.quote(_sshpass())
    cmd = (
        "PID=$(ps -eo pid,comm,cmd --no-headers | "
        "awk '$2 ~ /^python/ && $0 ~ "
        "/controller\\/ota_shield_controller\\.py/ {print $1; exit}'); "
        f"if [ -n \"$PID\" ]; then echo {pw} | sudo -S -p '' kill -USR1 $PID; "
        "echo \"sent SIGUSR1 to $PID\"; else echo no-controller; fi"
    )
    _, out = ssh(SWITCH, cmd, timeout=15)
    time.sleep(wait_s)
    return out.strip()


def dump_controller_state(wait_s: float = 2.0) -> str:
    """Send SIGUSR2 to the controller to trigger a state dump.

    The controller writes r5_count, r5_bloom_nonzero, session_override_count,
    and r6_max_version to /tmp/ota_controller_state.json (atomic write).
    Returns the raw SIGUSR2-send output.  Does NOT reset any registers.
    """
    pw = shlex.quote(_sshpass())
    cmd = (
        "PID=$(ps -eo pid,comm,cmd --no-headers | "
        "awk '$2 ~ /^python/ && $0 ~ "
        "/controller\\/ota_shield_controller\\.py/ {print $1; exit}'); "
        f"if [ -n \"$PID\" ]; then echo {pw} | sudo -S -p '' kill -USR2 $PID; "
        "echo \"sent SIGUSR2 to $PID\"; else echo no-controller; fi"
    )
    _, out = ssh(SWITCH, cmd, timeout=15)
    time.sleep(wait_s)
    return out.strip()


CONTROLLER_STATE_DUMP = "/tmp/ota_controller_state.json"


def get_decisions_offset() -> int:
    """Current byte size of the cumulative controller decisions log."""
    rc, out = ssh(SWITCH, f"stat -c %s {shlex.quote(SWITCH_DECISIONS)}",
                  timeout=15)
    return int(out.strip()) if rc == 0 and out.strip().isdigit() else -1


def slice_decisions(start: int, end: int, out_path: Path) -> None:
    """Pull byte range [start, end) of the cumulative decisions log."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    length = end - start
    if length <= 0:
        out_path.write_text("")
        return
    cmd = (f"dd if={shlex.quote(SWITCH_DECISIONS)} bs=1 skip={start} "
           f"count={length} 2>/dev/null")
    full = ["sshpass", "-p", _sshpass(), "ssh",
            "-o", "StrictHostKeyChecking=no", SWITCH, cmd]
    with out_path.open("wb") as fh:
        subprocess.run(full, check=True, stdout=fh)


def _controller_git_rev() -> str:
    try:
        p = subprocess.run(["git", "-C", str(REPO_ROOT), "rev-parse",
                            "--short", "HEAD"],
                           capture_output=True, text=True, timeout=8)
        return p.stdout.strip() if p.returncode == 0 else ""
    except Exception:
        return ""


def write_trial_manifest(trial_dir: Path, *, exp_id: str, trial_id: str,
                         scenario_id: str, declared_duration_s: float,
                         actual_duration_s: float, master_seed: str,
                         preflight: dict[str, str] | None = None,
                         postflight: dict[str, str] | None = None,
                         notes: str = "", execute: bool = False) -> Path:
    """Write the §3 reproducibility manifest for one trial.

    When ``execute`` is False the P4-binary sha is computed locally only if
    the file happens to exist; the live sha-over-SSH is left blank so the
    laptop dry-run never reaches for hardware.
    """
    trial_seed = derive_trial_seed(exp_id, trial_id, master_seed)
    p4_sha = ""
    if execute:
        p4_sha = compute_p4_binary_sha(SWITCH_P4_CONF, ssh_host=SWITCH)
    manifest = TrialManifest(
        exp_id=exp_id,
        trial_id=trial_id,
        scenario_id=scenario_id,
        declared_duration_s=declared_duration_s,
        actual_duration_s=actual_duration_s,
        master_seed=master_seed,
        trial_seed=trial_seed,
        p4_binary_sha256=p4_sha,
        controller_git_rev=_controller_git_rev(),
        rat_lifecycle_sha256=compute_file_sha(RAT_LIFECYCLE_LOCAL),
        preflight_integrity=preflight or {},
        postflight_integrity=postflight or {},
        notes=notes,
    )
    return write_manifest(trial_dir, manifest)


def now_iso() -> str:
    return _dt.datetime.now().isoformat(timespec="seconds")


def write_ground_truth(trial_dir: Path, trial_id: str, scenario_id: str,
                       events: list[dict]) -> Path:
    """Write ground_truth.json in the schema aggregate_cluster / aggregate_e17
    consume (``{"trial_id", "scenario", "events": [...]}``)."""
    trial_dir.mkdir(parents=True, exist_ok=True)
    gt = {"trial_id": trial_id, "scenario": scenario_id, "events": events}
    p = trial_dir / "ground_truth.json"
    p.write_text(json.dumps(gt, indent=2, default=str))
    return p


__all__ = [
    "REPO_ROOT", "SWITCH", "VISION", "SWITCH_OTA", "SWITCH_DECISIONS",
    "SWITCH_CONTROLLER_LOG", "CONTROLLER_STATE_DUMP",
    "ssh", "scp_to", "scp_from",
    "reset_controller_state", "dump_controller_state",
    "get_decisions_offset", "slice_decisions",
    "write_trial_manifest", "write_ground_truth", "now_iso",
    "derive_trial_seed",
]
