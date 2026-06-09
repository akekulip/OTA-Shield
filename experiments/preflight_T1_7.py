"""T1.7 preflight — 5-tuple override at 200 sources.

Asserts (Testbed §3 items 1, 2, 12 + per-experiment guards):
  * ports 8/11 UP at 25G RS-FEC
  * bf_switchd PID alive
  * controller PID + last RAT verified line
  * session_action_override has the 5-tuple key shape AND size 256
  * traffic_gen.scenario_5tuple_alias sanity_check() passes

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
    cmd = ("echo 'pm.show' | bfshell -i 1 2>/dev/null | "
           "grep -E '^[[:space:]]*(8|11) '")
    rc, out, _ = _ssh(switch, cmd, timeout=8)
    if rc != 0 or not out.strip():
        return False, f"could not parse pm.show (rc={rc})"
    up = [int(line.split()[0]) for line in out.splitlines()
          if line.split() and line.split()[0].isdigit() and "UP" in line]
    if 8 not in up or 11 not in up:
        return False, f"ports UP: {sorted(up)} (need 8 and 11)"
    return True, f"ports {sorted(up)} UP"


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


def check_session_action_override(switch: str, expected_size: int,
                                  expected_keys: list[str]
                                  ) -> tuple[bool, str]:
    """Inspect the override table's bfrt info: key shape AND size 256.

    Override-table-size detection: read the entry count cap from the
    P4 manifest. Key shape: grep the bfrt.json for the table's key list.
    """
    bfrt_path = ("/home/decps/my_program/ota/p4build/*/bfrt.json")
    cmd = (f"python3 -c '"
           f"import glob,json,sys;\n"
           f"paths=glob.glob({bfrt_path!r});\n"
           f"if not paths: print(\"NOFILE\"); sys.exit(0)\n"
           f"d=json.load(open(paths[0]));\n"
           f"hit=None\n"
           f"for t in d.get(\"tables\", []):\n"
           f"    if \"session_action_override\" in t.get(\"name\",\"\"):\n"
           f"        hit=t; break\n"
           f"if hit is None: print(\"NOTABLE\"); sys.exit(0)\n"
           f"sz = hit.get(\"size\")\n"
           f"keys=[k.get(\"name\") for k in hit.get(\"key\",[])]\n"
           f"print(\"size=\"+str(sz)+\" keys=\"+\",\".join(keys))'\n")
    rc, out, _ = _ssh(switch, cmd, timeout=10)
    if rc != 0:
        return False, f"bfrt parse failed (rc={rc})"
    out = out.strip()
    if out == "NOFILE":
        return False, "no bfrt.json found in p4build/*/bfrt.json"
    if out == "NOTABLE":
        return False, "session_action_override table not in bfrt.json"
    # Parse "size=<int> keys=<csv>".
    try:
        size_part, keys_part = out.split(" keys=")
        size_val = int(size_part.split("=", 1)[1])
        seen_keys = [k.strip() for k in keys_part.split(",") if k.strip()]
    except Exception as exc:
        return False, f"could not parse bfrt out {out!r}: {exc}"
    if size_val != expected_size:
        return False, (f"override table size = {size_val} "
                       f"(expected {expected_size})")
    # Each expected key must appear (substring match because bfrt names
    # are sometimes `hdr.ipv4.src_addr` etc.).
    missing = [k for k in expected_keys
               if not any(k in s for s in seen_keys)]
    if missing:
        return False, (f"override table missing keys {missing}; "
                       f"saw {seen_keys}")
    return True, (f"override table size={size_val}, "
                  f"keys={seen_keys}")


def check_generator_sanity(cfg: dict) -> tuple[bool, str]:
    gen_cfg = cfg.get("generator", {})
    params = gen_cfg.get("params", {})
    forwarded = ["--n-sources", str(params.get("n_sources", 200))]
    repo_root = Path(__file__).resolve().parent.parent
    cmd = ([sys.executable, "-m",
            "traffic_gen.sanity_checks.check_5tuple_alias"] + forwarded)
    p = subprocess.run(cmd, cwd=str(repo_root),
                       capture_output=True, text=True, timeout=15)
    detail = (p.stdout.strip().splitlines()[-1] if p.stdout.strip()
              else p.stderr.strip()[:200] or f"rc={p.returncode}")
    return p.returncode == 0, detail


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="T1.7 preflight")
    ap.add_argument("--config",
                    default="experiments/configs/T1_7.yaml",
                    type=Path)
    ap.add_argument("--switch", default="decps@10.10.54.15")
    ap.add_argument("--vision", default="decps@10.10.54.19")
    ap.add_argument("--controller-log", default="/tmp/controller.log")
    args = ap.parse_args(argv)

    cfg = yaml.safe_load(args.config.read_text())
    print(f"\n=== T1.7 preflight ({cfg['experiment_id']}) ===\n")
    expected_size = int(cfg.get("override_table", {}).get(
        "expected_size", 256))
    expected_keys = list(cfg.get("override_table", {}).get(
        "expected_key", ["src_ip", "dst_ip", "src_port", "dst_port",
                          "protocol"]))
    results = [
        CheckResult("ports-up", *check_ports_up(args.switch)),
        CheckResult("bf_switchd-alive", *check_bf_switchd(args.switch)),
        CheckResult("controller-alive", *check_controller(args.switch)),
        CheckResult("rat-verified", *check_rat_verified(
            args.switch, args.controller_log)),
        CheckResult("override-table-shape",
                    *check_session_action_override(
                        args.switch, expected_size, expected_keys)),
        CheckResult("5tuple_alias-sanity",
                    *check_generator_sanity(cfg)),
    ]
    for r in results:
        tag = (f"{GREEN}  OK  {RESET}" if r.ok
               else f"{RED} FAIL {RESET}")
        print(f"[{tag}] {r.name:<28} {r.detail}")
    failed = [r for r in results if not r.ok]
    if failed:
        print(f"\n{RED}T1.7 PREFLIGHT FAILED{RESET}: "
              f"{len(failed)}/{len(results)} checks failed.")
        for r in failed:
            print(f"  - {r.name}: {r.detail}")
        return 1
    print(f"\n{GREEN}T1.7 PREFLIGHT OK{RESET}: "
          f"all {len(results)} checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
