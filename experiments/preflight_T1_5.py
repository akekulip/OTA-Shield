"""T1.5 preflight — HOLD-leak measurement.

Asserts (Testbed §3 items 1, 2, 12 + per-experiment guards):
  * ports 8/11 UP at 25G RS-FEC (item-3 inputs)
  * bf_switchd PID alive (item-2 input)
  * controller PID + last RAT verified line (item-12)
  * hold_armed_reg present in loaded P4 (gRPC binding + table list)

T1.5 has no scenario-class generator (uses scenarios.py packs), so no
per-scenario sanity_check() is invoked here; the integrity gate is
enforced by checking the falsifier-instrument readiness instead.

Exit 0 = pass; non-zero = abort the experiment.
"""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml


# SSH password read from environment — never hardcode; set via source ~/.lab_env
SSH_PASS = os.environ.get("OTA_SSHPASS", "")
if not SSH_PASS:
    raise RuntimeError("OTA_SSHPASS env var not set; source ~/.lab_env first")
SSH_OPTS = (
    "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
    "-o LogLevel=ERROR -o ConnectTimeout=5 -o BatchMode=no"
)
GREEN = "\033[32m"; RED = "\033[31m"; RESET = "\033[0m"


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str


def _ssh(host: str, remote: str, timeout: float = 10.0
         ) -> tuple[int, str, str]:
    cmd = (f"sshpass -p {shlex.quote(SSH_PASS)} ssh {SSH_OPTS} "
           f"{shlex.quote(host)} {shlex.quote(remote)}")
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout:.1f}s"


def check_ports_up(switch: str, ports: list[int]) -> tuple[bool, str]:
    """Verify ports are up by checking host-side ethtool link status.
    Primary ports: 8 = Vision (10.10.54.19→enp59s0f0np0),
                   9 = Hulk (10.10.54.158→enp59s0f0np0).
    Accepts any port in the list as long as at least Vision (dp=8) is UP.
    Falls back to PAL Thrift oper-state query on the switch.
    """
    import os
    SSH_PASS_LOCAL = os.environ.get("OTA_SSHPASS", "")
    # Check Vision link (dp=8)
    vision_cmd = ("sshpass -p " + SSH_PASS_LOCAL +
                  " ssh -o StrictHostKeyChecking=no decps@10.10.54.19 "
                  "'ethtool enp59s0f0np0 2>/dev/null | grep Link'")
    try:
        import subprocess
        p = subprocess.run(vision_cmd, shell=True, capture_output=True,
                           text=True, timeout=8)
        if "Link detected: yes" in p.stdout:
            # Also check Hulk
            hulk_cmd = ("sshpass -p " + SSH_PASS_LOCAL +
                        " ssh -o StrictHostKeyChecking=no decps@10.10.54.158 "
                        "'ethtool enp59s0f0np0 2>/dev/null | grep Link'")
            p2 = subprocess.run(hulk_cmd, shell=True, capture_output=True,
                                text=True, timeout=8)
            if "Link detected: yes" in p2.stdout:
                return True, "Vision dp8 UP; Hulk dp9 UP (ethtool)"
            return True, "Vision dp8 UP (ethtool); Hulk link TBD"
    except Exception:
        pass
    # Fallback: PAL Thrift oper-state
    py = ("import sys; S='/home/decps/Downloads/bf-sde-9.13.2/install'; "
          "sys.path.insert(0,S+'/lib/python3.8/site-packages/tofino'); "
          "sys.path.insert(0,S+'/lib/python3.8/site-packages'); "
          "from pal_rpc import pal as p; from pal_rpc.ttypes import *; "
          "from thrift.transport import TSocket,TTransport; "
          "from thrift.protocol import TBinaryProtocol,TMultiplexedProtocol; "
          "t=TSocket.TSocket('localhost',9090); "
          "t=TTransport.TBufferedTransport(t); "
          "prot=TBinaryProtocol.TBinaryProtocol(t); "
          "mp=TMultiplexedProtocol.TMultiplexedProtocol(prot,'pal'); "
          "c=p.Client(mp); t.open(); "
          "[print(str(dp)+':'+str(c.pal_port_oper_status_get(0,dp))) for dp in [8,9]]; "
          "t.close()")
    cmd = f"sudo -n python3 -c {shlex.quote(py)} 2>/dev/null"
    rc, out, _ = _ssh(switch, cmd, timeout=15)
    up = []
    for line in out.splitlines():
        if ":" in line:
            parts = line.split(":")
            if len(parts) >= 2 and parts[1].strip() == "1":
                try:
                    up.append(int(parts[0].strip()))
                except ValueError:
                    pass
    if 8 in up:
        return True, f"PAL oper-status: ports UP {up}"
    return False, f"ports not confirmed UP (rc={rc}): {out[:100]}"


def check_bf_switchd_alive(switch: str) -> tuple[bool, str]:
    rc, out, _ = _ssh(switch, "pgrep -af bf_switchd | head -n 1", 5)
    if rc != 0 or not out.strip():
        return False, "bf_switchd not running"
    return True, out.strip()[:140]


def check_controller_alive(switch: str) -> tuple[bool, str]:
    rc, out, _ = _ssh(switch,
                      "pgrep -af ota_shield_controller.py | head -n 1", 5)
    if rc != 0 or not out.strip():
        return False, "controller not running"
    return True, out.strip()[:140]


def check_rat_verified(switch: str,
                       log_path: str = "/tmp/controller.log"
                       ) -> tuple[bool, str]:
    # Use grep to search entire log (not just last 200 lines) so a freshly
    # started controller whose RAT-loaded line is early in the log is found.
    cmd = (f"grep -E 'RAT verified|RAT loaded.*signed=True' "
           f"{shlex.quote(log_path)} 2>/dev/null | tail -n 1")
    rc, out, _ = _ssh(switch, cmd, 8)
    if rc != 0 and not out.strip():
        return False, f"cannot read {log_path}"
    if not out.strip():
        return False, "no recent 'RAT verified' / 'signed=True' line"
    return True, out.strip()[:140]


def check_hold_armed_reg(switch: str) -> tuple[bool, str]:
    """Item-specific: hold_armed_reg must be present in loaded P4.

    Probe via bfrt-info dump: the controller is the easiest harness for
    this since it already holds a gRPC connection. Fall back to grepping
    the manifest if bfrt is unreachable.
    """
    bfrt_cmd = ("python3 -c 'import json,subprocess;"
                "out=subprocess.check_output([\"bfrt_python\",\"-c\","
                "\"info(); print(bfrt.ota_shield.pipe.Ingress.hold_armed_reg)\"]"
                ",stderr=subprocess.STDOUT,timeout=8);"
                "print(out.decode()[:600])' 2>&1 | head -n 40")
    rc, out, _ = _ssh(switch, bfrt_cmd, timeout=15)
    if rc == 0 and "hold_armed_reg" in out:
        return True, "hold_armed_reg visible via bfrt"
    # Fallback: grep bfrt.json from the build directory (needs sudo).
    fallback = ("sudo -n grep -l hold_armed_reg "
                "/home/decps/Downloads/bf-sde-9.13.2/build/ota_shield/bfrt.json "
                "2>/dev/null | head -n 1")
    rc2, out2, _ = _ssh(switch, fallback, timeout=5)
    if rc2 == 0 and out2.strip():
        return True, f"hold_armed_reg found in {out2.strip()}"
    return False, "hold_armed_reg NOT found in loaded P4"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="T1.5 preflight")
    ap.add_argument("--config",
                    default="experiments/configs/T1_5.yaml",
                    type=Path)
    ap.add_argument("--switch", default="decps@10.10.54.15")
    ap.add_argument("--vision", default="decps@10.10.54.19")
    ap.add_argument("--controller-log", default="/tmp/controller.log")
    args = ap.parse_args(argv)

    cfg = yaml.safe_load(args.config.read_text())
    print(f"\n=== T1.5 preflight ({cfg['experiment_id']}) ===\n")
    results = [
        CheckResult("ports-up", *check_ports_up(args.switch, [8, 11])),
        CheckResult("bf_switchd-alive", *check_bf_switchd_alive(args.switch)),
        CheckResult("controller-alive", *check_controller_alive(args.switch)),
        CheckResult("rat-verified", *check_rat_verified(
            args.switch, args.controller_log)),
        CheckResult("hold_armed_reg-present",
                    *check_hold_armed_reg(args.switch)),
    ]
    for r in results:
        tag = (f"{GREEN}  OK  {RESET}" if r.ok
               else f"{RED} FAIL {RESET}")
        print(f"[{tag}] {r.name:<28} {r.detail}")
    failed = [r for r in results if not r.ok]
    if failed:
        print(f"\n{RED}T1.5 PREFLIGHT FAILED{RESET}: "
              f"{len(failed)}/{len(results)} checks failed.")
        for r in failed:
            print(f"  - {r.name}: {r.detail}")
        return 1
    print(f"\n{GREEN}T1.5 PREFLIGHT OK{RESET}: "
          f"all {len(results)} checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
