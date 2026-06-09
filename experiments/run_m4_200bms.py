"""M4 200-BMS hardware replay driver.

Replays `runs/m4/E1_200bms/traffic.pcap` and `runs/m4/E8_200bms/traffic.pcap`
against the live OTA-Shield controller on the switch and records the
controller decision log byte-offsets so the M4 aggregator can compute
per-trial precision, recall, and F1 against the labels.json shipped
with each pcap.

Order of operations:

  1. Snapshot the canonical RAT and signature on the switch.
  2. Build an extended RAT that adds destination BMSes 10.0.2.60..209
     to `e12-primary-source` and bumps `max_concurrent_targets` to 250.
  3. Atomically push the extended JSON, sign it on the switch with the
     existing ed25519 key, wait for the controller to reload it, and
     verify the load via `/tmp/controller.log`.
  4. Capture the byte-offset of `runs/E19p_stochastic.jsonl` on the
     switch.
  5. ship each pcap to Vision and replay it through `enp59s0f0np0`
     using a small scapy sender invoked via `sudo -n python3`.
  6. After both replays finish, capture the final byte-offset, slice
     the cumulative decision log into per-scenario JSONL files on the
     laptop, and store them under `runs/m4/<scenario>/trial_00/`.
  7. Restore the canonical RAT, re-sign, and verify the reload.

The driver is idempotent for restoration: even on early exit the
canonical RAT and signature are written back from the backup we took
in step 1.

The driver does NOT touch `bf_switchd`. The controller is
restart-safe: it polls the RAT file every five seconds, and its
inotify path is a best-effort optimization.

Usage:
    python3 experiments/run_m4_200bms.py --execute
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import logging
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNS_M4 = REPO_ROOT / "runs" / "m4"
SWITCH_HOST = "decps@10.10.54.15"
VISION_HOST = "decps@10.10.54.19"
VISION_IFACE = "enp59s0f0np0"
SWITCH_OTA = "/home/decps/my_program/ota"
SWITCH_RAT = f"{SWITCH_OTA}/controller/rat.json"
SWITCH_SIG = f"{SWITCH_RAT}.sig"
SWITCH_LOG = f"{SWITCH_OTA}/runs/controller_smoke.log"
SWITCH_DECISIONS = f"{SWITCH_OTA}/runs/decisions.jsonl"
SWITCH_KEY = "/home/decps/.ota_shield/rat_signing.key"
# SSH password read from environment — never hardcode; set via source ~/.lab_env
SSH_PASS = os.environ.get("OTA_SSHPASS", "")
if not SSH_PASS:
    raise RuntimeError("OTA_SSHPASS env var not set; source ~/.lab_env first")

POLL_RELOAD_SECONDS = 30.0
POLL_RELOAD_INTERVAL = 2.0


def _ssh(host: str, cmd: str, capture: bool = True) -> str:
    """Run a shell command on a remote host via sshpass+ssh."""
    full = [
        "sshpass", "-p", SSH_PASS,
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=30",
        host, cmd,
    ]
    proc = subprocess.run(full, capture_output=capture, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"ssh {host!r} {cmd!r} returned {proc.returncode}\n"
            f"stderr={proc.stderr.strip()}"
        )
    return proc.stdout if capture else ""


def _scp_to(host: str, local: Path, remote: str) -> None:
    full = [
        "sshpass", "-p", SSH_PASS,
        "scp",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        str(local), f"{host}:{remote}",
    ]
    subprocess.run(full, check=True)


def _scp_from(host: str, remote: str, local: Path) -> None:
    full = [
        "sshpass", "-p", SSH_PASS,
        "scp",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        f"{host}:{remote}", str(local),
    ]
    subprocess.run(full, check=True)


def _now_iso() -> str:
    return _dt.datetime.now().isoformat(timespec="seconds")


def snapshot_canonical_rat(work_dir: Path) -> dict:
    """Pull the canonical RAT and signature from the switch and stamp the
    backup with a UTC timestamp so we never overwrite an older backup.
    """
    work_dir.mkdir(parents=True, exist_ok=True)
    stamp = _dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    canonical_json = work_dir / f"rat_e12.json.canonical.{stamp}"
    canonical_sig = work_dir / f"rat_e12.json.sig.canonical.{stamp}"

    _scp_from(SWITCH_HOST, SWITCH_RAT, canonical_json)
    _scp_from(SWITCH_HOST, SWITCH_SIG, canonical_sig)

    bak_remote_json = f"{SWITCH_RAT}.m4_200bms_bak.{stamp}"
    bak_remote_sig = f"{SWITCH_SIG}.m4_200bms_bak.{stamp}"
    _ssh(SWITCH_HOST, f"cp {shlex.quote(SWITCH_RAT)} {shlex.quote(bak_remote_json)}")
    _ssh(SWITCH_HOST, f"cp {shlex.quote(SWITCH_SIG)} {shlex.quote(bak_remote_sig)}")

    return {
        "stamp": stamp,
        "canonical_json": canonical_json,
        "canonical_sig": canonical_sig,
        "switch_bak_json": bak_remote_json,
        "switch_bak_sig": bak_remote_sig,
    }


def build_extended_rat(canonical_json: Path, out_path: Path) -> None:
    """Extend the canonical rat.json so every rollout's `target_bms_list`
    covers BMSes 10.0.2.10..209 and `max_concurrent_targets` is large
    enough to not throttle a 200-BMS fleet replay. Source IPs and time
    windows are preserved.
    """
    rat = json.loads(canonical_json.read_text())
    extended = ["10.0.2." + str(i) for i in range(10, 210)]
    for r in rat["authorized_rollouts"]:
        r["target_bms_list"] = extended
        r["max_concurrent_targets"] = 250
    out_path.write_text(json.dumps(rat, indent=2))


def push_and_sign(extended_json: Path) -> None:
    """Atomically push the extended RAT to the switch and sign it with
    the existing ed25519 key. The order is intentional: we push the
    JSON first, then sign in-place on the switch so the .sig matches
    the bytes the controller actually reads.
    """
    _scp_to(SWITCH_HOST, extended_json, SWITCH_RAT)
    _ssh(
        SWITCH_HOST,
        f"cd {shlex.quote(SWITCH_OTA)} && python3 controller/sign_rat.py "
        f"{shlex.quote(SWITCH_RAT)} --priv {shlex.quote(SWITCH_KEY)}",
    )


def wait_for_reload(min_t: float, expect_signed: bool) -> dict:
    """Poll `/tmp/controller.log` for a `RAT loaded:` line newer than
    `min_t` (epoch seconds) and confirm `signed=True`. Returns the
    matched line and its parsed timestamp.
    """
    deadline = time.time() + POLL_RELOAD_SECONDS
    while time.time() < deadline:
        out = _ssh(
            SWITCH_HOST,
            f"awk '/RAT loaded:/' {shlex.quote(SWITCH_LOG)} | tail -5",
        )
        if out.strip():
            for line in out.strip().splitlines():
                ts = line.split()[0] + " " + line.split()[1]
                try:
                    epoch = _dt.datetime.strptime(
                        ts.split(",")[0], "%Y-%m-%d %H:%M:%S"
                    ).timestamp()
                except ValueError:
                    continue
                if epoch >= min_t:
                    signed_ok = "signed=True" in line
                    if expect_signed and not signed_ok:
                        raise RuntimeError(
                            f"RAT loaded but signed=False: {line!r}"
                        )
                    return {"line": line, "epoch": epoch}
        time.sleep(POLL_RELOAD_INTERVAL)
    raise RuntimeError(
        f"controller did not reload RAT within {POLL_RELOAD_SECONDS}s"
    )


def get_decisions_offset() -> int:
    """Return the current byte size of the cumulative decisions log."""
    out = _ssh(SWITCH_HOST, f"stat -c %s {shlex.quote(SWITCH_DECISIONS)}")
    return int(out.strip())


def slice_decisions(start: int, end: int, out_path: Path) -> None:
    """Pull the byte range [start, end) from the switch's cumulative
    decisions log and write it locally as a plain JSONL slice.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    length = end - start
    if length <= 0:
        out_path.write_text("")
        return
    cmd = (
        f"dd if={shlex.quote(SWITCH_DECISIONS)} "
        f"bs=1 skip={start} count={length} 2>/dev/null"
    )
    full = [
        "sshpass", "-p", SSH_PASS,
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        SWITCH_HOST, cmd,
    ]
    with out_path.open("wb") as fh:
        subprocess.run(full, check=True, stdout=fh)


def replay_pcap(local_pcap: Path, scenario: str) -> dict:
    """ship a pcap to Vision and replay it through the data-plane NIC
    using scapy under `sudo -n python3`. Returns wall-clock start and
    end timestamps.
    """
    remote_pcap = f"/tmp/m4_{scenario}.pcap"
    _scp_to(VISION_HOST, local_pcap, remote_pcap)

    replay_src = (
        "import sys, time\n"
        "from scapy.all import rdpcap, sendp\n"
        "pcap, iface = sys.argv[1], sys.argv[2]\n"
        "pkts = rdpcap(pcap)\n"
        "t0 = time.time()\n"
        "sendp(pkts, iface=iface, verbose=False)\n"
        "print(f'sent {len(pkts)} pkts in {time.time()-t0:.2f}s')\n"
    )
    import base64
    replay_b64 = base64.b64encode(replay_src.encode()).decode()
    cmd = (
        f"echo {replay_b64} | base64 -d > /tmp/_m4_replay.py && "
        f"sudo -n python3 /tmp/_m4_replay.py "
        f"{shlex.quote(remote_pcap)} {shlex.quote(VISION_IFACE)}"
    )
    t_start = time.time()
    out = _ssh(VISION_HOST, cmd)
    t_end = time.time()
    return {
        "scenario": scenario,
        "remote_pcap": remote_pcap,
        "t_start": t_start,
        "t_end": t_end,
        "elapsed_s": t_end - t_start,
        "replayer_stdout": out.strip(),
    }


def restore_canonical(snapshot: dict) -> None:
    """Restore the canonical RAT and signature, then wait for the
    controller to load them.
    """
    _scp_to(SWITCH_HOST, snapshot["canonical_json"], SWITCH_RAT)
    _scp_to(SWITCH_HOST, snapshot["canonical_sig"], SWITCH_SIG)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--execute", action="store_true",
                    help="run the full flow; default is dry run")
    ap.add_argument("--work-dir", type=Path,
                    default=Path("runs/m4/_m4_200bms_session_state"))
    ap.add_argument("--drain-after-replay-s", type=float, default=30.0,
                    help="how long to wait after each replay so the "
                         "controller flushes pending digests")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if not args.execute:
        logger.info("dry run; pass --execute to actually run")
        return 0

    work_dir = args.work_dir
    work_dir.mkdir(parents=True, exist_ok=True)

    session = {
        "started_at": _now_iso(),
        "scenarios": [],
    }

    snapshot = None
    try:
        logger.info("snapshotting canonical RAT")
        snapshot = snapshot_canonical_rat(work_dir)
        logger.info("canonical RAT snapshot: %s", snapshot)

        extended_json = work_dir / f"rat_e12.json.extended.{snapshot['stamp']}"
        build_extended_rat(snapshot["canonical_json"], extended_json)
        logger.info("built extended RAT: %s", extended_json)

        push_t0 = time.time()
        push_and_sign(extended_json)
        reload1 = wait_for_reload(push_t0 - 5, expect_signed=True)
        logger.info("controller reloaded extended RAT: %s", reload1["line"])
        session["extended_reload"] = reload1

        for scenario in ("E1_200bms", "E8_200bms"):
            scenario_dir = REPO_ROOT / "runs" / "m4" / scenario
            local_pcap = scenario_dir / "traffic.pcap"
            if not local_pcap.exists():
                raise FileNotFoundError(local_pcap)

            offset_start = get_decisions_offset()
            replay_meta = replay_pcap(local_pcap, scenario)
            logger.info("%s replay: %s", scenario, replay_meta)
            time.sleep(args.drain_after_replay_s)
            offset_end = get_decisions_offset()

            trial_dir = scenario_dir / "trial_00"
            trial_dir.mkdir(parents=True, exist_ok=True)
            slice_path = trial_dir / "controller_decisions.jsonl"
            slice_decisions(offset_start, offset_end, slice_path)

            scenario_record = {
                "scenario": scenario,
                "offset_start": offset_start,
                "offset_end": offset_end,
                "bytes_captured": offset_end - offset_start,
                "slice_path": str(slice_path),
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
                logger.info("restoring canonical RAT")
                push_t1 = time.time()
                restore_canonical(snapshot)
                reload2 = wait_for_reload(push_t1 - 5, expect_signed=True)
                logger.info("controller reloaded canonical RAT: %s",
                            reload2["line"])
                session["canonical_reload"] = reload2
            except Exception as exc:
                logger.error("restore-canonical failed: %s", exc)
                session["restore_error"] = str(exc)

    session["finished_at"] = _now_iso()
    session_path = work_dir / f"session_{snapshot['stamp']}.json"
    session_path.write_text(json.dumps(session, indent=2, default=str))
    logger.info("session record: %s", session_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
