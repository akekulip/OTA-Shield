"""T2.4 preflight — brokered-MQTT topology (E20 / E20a).

Asserts (Testbed §3 items incl. 12 + 13 + per-experiment guards):
  * ports 8/11 UP, bf_switchd + controller alive, RAT verified
  * all four broker scenarios' sanity_check() pass (src collapses to broker;
    IP-only control PASSes every attack; publisher-id recoverable)
  * controller is in publisher-id-keyed RAT mode (not IP-only) — checked via
    the controller log / cmdline
  * BROKER DEPENDENCY: a real mosquitto broker is reachable at the configured
    host:port (or paho-mqtt is importable on Vision for the relay). If
    NEITHER is available the preflight FAILS this check and clearly states
    the dependency rather than letting the run silently fall back to the
    reduced-fidelity scapy "minimal relay" (item 13: broker-relay flag).

Exit 0 = pass; non-zero = abort. --no-hardware runs only the local sanity.
"""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

SSH_PASS = os.environ.get("OTA_SSHPASS", "")
SSH_OPTS = ("-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            "-o LogLevel=ERROR -o ConnectTimeout=5")
GREEN = "\033[32m"; RED = "\033[31m"; YEL = "\033[33m"; RESET = "\033[0m"

_SDE_LDPATH = "/home/decps/Downloads/bf-sde-9.13.2/install/lib"
_BFSHELL    = "/home/decps/Downloads/bf-sde-9.13.2/install/bin/bfshell"


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str


def _ssh(host: str, remote: str, timeout: float = 10.0) -> tuple[int, str]:
    if not SSH_PASS:
        return 127, "OTA_SSHPASS unset"
    cmd = (f"sshpass -p {shlex.quote(SSH_PASS)} ssh {SSH_OPTS} "
           f"{shlex.quote(host)} {shlex.quote(remote)}")
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout:.1f}s"


def check_ports_up(switch: str) -> tuple[bool, str]:
    """Query port state via bfshell ucli pm show.

    Uses nohup + (printf cmds; sleep) | bfshell -i 1 to keep stdin open —
    bfshell exits on EOF before output is flushed (same issue/fix as
    run_t2_2.py _preseed_r1_on_switch).  Navigates ucli -> pm -> show.

    Checks dev_port 8 (Vision/15/0) and dev_port 9 (Hulk/15/1) as wired
    per tofino_25g_connectivity_map.md. dev_port 11 (15/3) is an empty
    breakout lane removed from the $PORT table.
    """
    ts = int(time.time())
    result_path = f"/tmp/preflight_pmshow_{ts}.txt"
    launch = (
        f"rm -f {result_path}; "
        f"nohup bash -c "
        f"'(printf \"ucli\\npm\\nshow\\nexit\\nexit\\n\"; sleep 20) | "
        f"LD_LIBRARY_PATH={_SDE_LDPATH} {_BFSHELL} -i 1 "
        f"> {result_path} 2>&1' "
        f"> /dev/null 2>&1 &"
    )
    _ssh(switch, launch, timeout=12)
    time.sleep(12)
    out = ""
    for _ in range(5):
        _, out = _ssh(switch, f"cat {result_path} 2>/dev/null", 8)
        if out.strip() and ("UP" in out or "DWN" in out):
            break
        time.sleep(3)
    if not out.strip():
        return False, f"pm show timeout (no output in {result_path})"
    up: list[int] = []
    for l in out.splitlines():
        parts = l.split("|")
        if len(parts) >= 11:
            try:
                dp = int(parts[2].strip())
                opr = parts[10].strip()
                if opr.upper().startswith("UP"):
                    up.append(dp)
            except (ValueError, IndexError):
                pass
    if not up:
        return False, f"no port lines parsed (first 300: {out[:300]!r})"
    return (8 in up and 9 in up), f"dev_ports UP: {sorted(up)}"


def check_proc(switch: str, name: str) -> tuple[bool, str]:
    rc, out = _ssh(switch, f"pgrep -af {shlex.quote(name)} | head -n 1", 5)
    return (rc == 0 and bool(out.strip())), out.strip()[:120] or f"{name} down"


def check_rat_verified(switch: str, log_path: str) -> tuple[bool, str]:
    # grep the full log for signed-RAT lines (tail -n 200 is unreliable:
    # the controller reloads the RAT every ~30 min and the last reload line
    # may be thousands of log lines before EOF).
    cmd = (f"grep -E 'RAT loaded.*signed=True|RAT verified' "
           f"{shlex.quote(log_path)} 2>/dev/null | tail -n 1")
    _, out = _ssh(switch, cmd, timeout=20)
    if not out.strip():
        return False, f"no signed-RAT line found in {log_path}"
    return True, out.strip()[:120]


def check_pubid_mode(switch: str) -> tuple[bool, str]:
    """Confirm the controller runs in publisher-id-keyed mode (E20), not
    the IP-only control (E20a) — otherwise the brokered run scores the
    wrong arm."""
    rc, out = _ssh(switch,
                   "pgrep -af ota_shield_controller.py | head -n 1", 6)
    if rc != 0 or not out.strip():
        return False, "controller not running"
    if "--ip-only-rat" in out:
        return False, "controller is in IP-ONLY mode (E20a); expected E20"
    return True, "controller in publisher-id-keyed mode (no --ip-only-rat)"


def check_broker(cfg: dict, vision: str) -> tuple[bool, str]:
    bk = cfg.get("broker", {})
    host = bk.get("host_ip", "10.0.1.50")
    port = int(bk.get("port", 1883))
    # 1. is a mosquitto broker listening?
    rc, out = _ssh(vision,
                   f"(nc -z -w2 {host} {port} && echo LISTEN) "
                   f"|| echo NOLISTEN", 8)
    if "LISTEN" in out:
        return True, f"mosquitto reachable at {host}:{port}"
    # 2. fall back: is paho-mqtt importable on Vision (for the relay)?
    rc, out = _ssh(vision, "python3 -c 'import paho.mqtt.publish' "
                           "&& echo PAHO || echo NOPAHO", 8)
    if "PAHO" in out and "NOPAHO" not in out:
        return False, (f"{YEL}DEPENDENCY{RESET}: no mosquitto at {host}:{port}; "
                       f"paho present but a REAL broker is required for a "
                       f"full-fidelity E20 run (install/start mosquitto)")
    return False, (f"DEPENDENCY MISSING: neither mosquitto at {host}:{port} "
                   f"nor paho-mqtt on Vision. Install mosquitto "
                   f"(apt install mosquitto, requires approval) before T2.4. "
                   f"Do NOT fall back to the scapy minimal relay for the "
                   f"headline run.")


def check_generator_sanity() -> tuple[bool, str]:
    cmd = [sys.executable, "-m",
           "traffic_gen.sanity_checks.check_broker_attack"]
    p = subprocess.run(cmd, cwd=str(REPO), capture_output=True, text=True,
                       timeout=20)
    ok = p.returncode == 0
    last = (p.stdout.strip().splitlines()[-1] if p.stdout.strip()
            else p.stderr.strip()[:200])
    return ok, ("all 4 broker scenarios sane" if ok else last)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="T2.4 preflight")
    ap.add_argument("--config", type=Path,
                    default=REPO / "experiments/configs/T2_4.yaml")
    ap.add_argument("--switch", default="decps@10.10.54.15")
    ap.add_argument("--vision", default="decps@10.10.54.19")
    ap.add_argument("--controller-log",
                    default="/home/decps/my_program/ota/runs/controller_campaign_2026-06-06.log")
    ap.add_argument("--no-hardware", action="store_true")
    args = ap.parse_args(argv)

    cfg = yaml.safe_load(args.config.read_text())
    print(f"\n=== T2.4 preflight ({cfg['experiment_id']}) ===\n")
    results = [CheckResult("broker-scenarios-sanity", *check_generator_sanity())]
    if not args.no_hardware:
        results += [
            CheckResult("ports-up", *check_ports_up(args.switch)),
            CheckResult("bf_switchd-alive", *check_proc(args.switch, "bf_switchd")),
            CheckResult("controller-alive",
                        *check_proc(args.switch, "ota_shield_controller.py")),
            CheckResult("pubid-rat-mode", *check_pubid_mode(args.switch)),
            CheckResult("rat-verified",
                        *check_rat_verified(args.switch, args.controller_log)),
            CheckResult("broker-dependency", *check_broker(cfg, args.vision)),
        ]
    for r in results:
        tag = f"{GREEN}  OK  {RESET}" if r.ok else f"{RED} FAIL {RESET}"
        print(f"[{tag}] {r.name:<24} {r.detail}")
    failed = [r for r in results if not r.ok]
    if failed:
        print(f"\n{RED}T2.4 PREFLIGHT FAILED{RESET}: {len(failed)} failed.")
        for r in failed:
            print(f"  - {r.name}: {r.detail}")
        return 1
    print(f"\n{GREEN}T2.4 PREFLIGHT OK{RESET}: all {len(results)} passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
