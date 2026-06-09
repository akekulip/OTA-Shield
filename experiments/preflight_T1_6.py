"""T1.6 preflight — R6 high-version-poisoning verification.

Asserts (Testbed §3 items 1, 2, 12 + per-experiment guards):
  * ports 8/11 UP at 25G RS-FEC (item-3 input)
  * bf_switchd PID alive (item-2 input)
  * controller PID + last RAT verified line (item-12)
  * r6_version_probe action exists in loaded P4 (bfrt info)
  * r6_version_commit action exists in loaded P4 (bfrt info)
  * traffic_gen.r6_poison sanity_check() passes (Adversary §7-1 binding)

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


def check_ports_up(switch: str) -> tuple[bool, str]:
    """Query bfrt_grpc via /tmp/check_ports.py (avoids shell `$` expansion).

    The probe script is installed on the switch by the testbed bring-up;
    if missing this check returns False with an actionable message.
    """
    cmd = (
        f"echo {shlex.quote(SSH_PASS)} | sudo -S env "
        "SDE_INSTALL=/home/decps/Downloads/bf-sde-9.13.2/install "
        "python3 /tmp/check_ports.py 2>/dev/null | tail -1"
    )
    rc, out, _ = _ssh(switch, cmd, timeout=20)
    if rc != 0 or not out.strip():
        return False, (f"port probe failed (rc={rc}); "
                       "ensure /tmp/check_ports.py exists on switch")
    up = []
    for entry in out.strip().split(';'):
        parts = entry.split(':')
        if len(parts) != 3:
            continue
        port, port_up, speed = parts
        if port_up.strip() == 'True' and 'BF_SPEED_25G' in speed:
            up.append(int(port))
    if 8 not in up or 11 not in up:
        return False, f"ports UP @ 25G: {sorted(up)} (need 8 and 11)"
    return True, f"ports {sorted(up)} UP @ 25G"


def check_bf_switchd(switch: str) -> tuple[bool, str]:
    rc, out, _ = _ssh(switch, "pgrep -af bf_switchd | head -n 1", 5)
    return ((rc == 0 and bool(out.strip())),
            out.strip()[:140] or "bf_switchd not running")


def check_controller(switch: str) -> tuple[bool, str]:
    rc, out, _ = _ssh(switch,
                      "pgrep -af ota_shield_controller.py | head -n 1", 5)
    return ((rc == 0 and bool(out.strip())),
            out.strip()[:140] or "controller not running")


def check_rat_verified(switch: str, log_path: str) -> tuple[bool, str]:
    rc, out, _ = _ssh(switch,
                      f"tail -n 200 {shlex.quote(log_path)} 2>/dev/null", 8)
    if rc != 0:
        return False, f"cannot read {log_path}"
    matches = [ln for ln in out.splitlines()
               if "RAT verified" in ln or
               ("RAT loaded" in ln and "signed=True" in ln)]
    if not matches:
        return False, "no recent 'RAT verified' / 'signed=True' line"
    return True, matches[-1].strip()[:140]


def check_r6_actions_in_p4(switch: str) -> tuple[bool, str]:
    """r6_version_probe + r6_version_commit must be in compiled BFA.

    Tofino RegisterAction names are NOT exposed in bfrt.json (they are
    P4 source-level constructs that the compiler lowers to SALU
    instruction slots). They appear in the .bfa assembly output. So we
    grep there.
    """
    cmd = (
        "grep -loE 'r6_version_(probe|commit)' "
        "/home/decps/Downloads/bf-sde-9.13.2/build/ota_shield/pipe/*.bfa "
        "2>/dev/null | head -1 && "
        "grep -oE 'r6_version_(probe|commit|update)' "
        "/home/decps/Downloads/bf-sde-9.13.2/build/ota_shield/pipe/*.bfa "
        "2>/dev/null | sort -u"
    )
    rc, out, _ = _ssh(switch, cmd, timeout=8)
    if rc != 0 or not out.strip():
        return False, f"could not grep .bfa (rc={rc})"
    found = set(line.strip() for line in out.splitlines()
                if line.strip().startswith("r6_version_"))
    needed = {"r6_version_probe", "r6_version_commit"}
    if not needed.issubset(found):
        missing = sorted(needed - found)
        return False, (f"missing in .bfa: {missing}; found: {sorted(found)}")
    if "r6_version_update" in found:
        return False, ("legacy r6_version_update still present in .bfa - "
                       "patch did not fully replace it")
    return True, f"compiled actions in BFA: {sorted(found)}"


def check_generator_sanity(cfg: dict) -> tuple[bool, str]:
    """Run the standalone sanity dispatcher for the generator."""
    gen_cfg = cfg.get("generator", {})
    params = gen_cfg.get("params", {})
    forwarded = [
        "--src-unauth", str(params.get("unauthorized_src_ip",
                                        "10.0.99.99")),
        "--src-legit", str(params.get("legitimate_src_ip", "10.0.1.10")),
        "--target", str(params.get("target_bms_ip", "10.0.2.10")),
        "--gap", str(params.get("gap_seconds", 60)),
        "--legit-version", str(params.get("legitimate_version", 49)),
        "--poison-version-hex",
        str(params.get("poison_version_hex", "DEADBEEF")),
    ]
    repo_root = Path(__file__).resolve().parent.parent
    cmd = ([sys.executable, "-m",
            "traffic_gen.sanity_checks.check_r6_poison"] + forwarded)
    p = subprocess.run(cmd, cwd=str(repo_root),
                       capture_output=True, text=True, timeout=15)
    detail = (p.stdout.strip().splitlines()[-1] if p.stdout.strip()
              else p.stderr.strip()[:200] or f"rc={p.returncode}")
    return p.returncode == 0, detail


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="T1.6 preflight")
    ap.add_argument("--config",
                    default="experiments/configs/T1_6.yaml",
                    type=Path)
    ap.add_argument("--switch", default="decps@10.10.54.15")
    ap.add_argument("--vision", default="decps@10.10.54.19")
    ap.add_argument("--controller-log", default="/tmp/controller.log")
    args = ap.parse_args(argv)

    cfg = yaml.safe_load(args.config.read_text())
    print(f"\n=== T1.6 preflight ({cfg['experiment_id']}) ===\n")
    results = [
        CheckResult("ports-up", *check_ports_up(args.switch)),
        CheckResult("bf_switchd-alive", *check_bf_switchd(args.switch)),
        CheckResult("controller-alive", *check_controller(args.switch)),
        CheckResult("rat-verified", *check_rat_verified(
            args.switch, args.controller_log)),
        CheckResult("r6-actions-in-p4",
                    *check_r6_actions_in_p4(args.switch)),
        CheckResult("r6_poison-sanity",
                    *check_generator_sanity(cfg)),
    ]
    for r in results:
        tag = (f"{GREEN}  OK  {RESET}" if r.ok
               else f"{RED} FAIL {RESET}")
        print(f"[{tag}] {r.name:<28} {r.detail}")
    failed = [r for r in results if not r.ok]
    if failed:
        print(f"\n{RED}T1.6 PREFLIGHT FAILED{RESET}: "
              f"{len(failed)}/{len(results)} checks failed.")
        for r in failed:
            print(f"  - {r.name}: {r.detail}")
        return 1
    print(f"\n{GREEN}T1.6 PREFLIGHT OK{RESET}: "
          f"all {len(results)} checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
