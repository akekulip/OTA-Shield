"""T2.8 preflight — TCP-evasion battery.

Asserts (Testbed §3 + per-experiment guards):
  * ports 8/11 UP, bf_switchd + controller alive, RAT verified
  * tcp_evasion battery sanity_check() passes (25 cells, header-split hides
    the parseable header, predicted matrix matches the threat model)
  * iptables NOTRACK rule present on Vision so the kernel does NOT reassemble
    the crafted TCP segments before they hit the wire (blocker per T2.8)

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


def check_notrack(vision: str) -> tuple[bool, str]:
    """The raw-table NOTRACK rule prevents kernel conntrack/GRO from
    reassembling the hand-crafted segments before egress."""
    rc, out = _ssh(vision,
                   "sudo -n iptables -t raw -S 2>/dev/null | grep -i NOTRACK "
                   "|| echo MISSING", 8)
    if "MISSING" in out or rc != 0:
        return False, ("no iptables raw NOTRACK rule on Vision (blocker: add "
                       "NOPASSWD iptables + a NOTRACK rule for the test 5-tuples)")
    return True, out.strip().splitlines()[0][:120]


def check_generator_sanity() -> tuple[bool, str]:
    cmd = [sys.executable, "-m",
           "traffic_gen.sanity_checks.check_tcp_evasion"]
    p = subprocess.run(cmd, cwd=str(REPO), capture_output=True, text=True,
                       timeout=20)
    last = (p.stdout.strip().splitlines()[-1] if p.stdout.strip()
            else p.stderr.strip()[:200])
    return p.returncode == 0, last


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="T2.8 preflight")
    ap.add_argument("--config", type=Path,
                    default=REPO / "experiments/configs/T2_8.yaml")
    ap.add_argument("--switch", default="decps@10.10.54.15")
    ap.add_argument("--vision", default="decps@10.10.54.19")
    ap.add_argument("--controller-log",
                    default="/home/decps/my_program/ota/runs/controller_campaign_2026-06-06.log")
    ap.add_argument("--no-hardware", action="store_true")
    args = ap.parse_args(argv)

    cfg = yaml.safe_load(args.config.read_text())
    print(f"\n=== T2.8 preflight ({cfg['experiment_id']}) ===\n")
    results = [CheckResult("tcp-evasion-sanity", *check_generator_sanity())]
    if not args.no_hardware:
        results += [
            CheckResult("ports-up", *check_ports_up(args.switch)),
            CheckResult("bf_switchd-alive", *check_proc(args.switch, "bf_switchd")),
            CheckResult("controller-alive",
                        *check_proc(args.switch, "ota_shield_controller.py")),
            CheckResult("rat-verified",
                        *check_rat_verified(args.switch, args.controller_log)),
            CheckResult("vision-notrack", *check_notrack(args.vision)),
        ]
    for r in results:
        tag = f"{GREEN}  OK  {RESET}" if r.ok else f"{RED} FAIL {RESET}"
        print(f"[{tag}] {r.name:<22} {r.detail}")
    failed = [r for r in results if not r.ok]
    if failed:
        print(f"\n{RED}T2.8 PREFLIGHT FAILED{RESET}: {len(failed)} failed.")
        return 1
    print(f"\n{GREEN}T2.8 PREFLIGHT OK{RESET}: all {len(results)} passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
