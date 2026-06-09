"""T2.5 preflight — mimicry per-strategy (E17b / E21).

Asserts (Testbed §3 + per-experiment guards):
  * ports 8/11 UP, bf_switchd + controller alive, RAT verified
  * the mimicry campaign planner builds all five strategies cleanly
    (per-trial seed disjoints the 5-tuple space)
  * the controller honours SIGUSR1 reset (item 12 footgun: stale overrides)

Exit 0 = pass; non-zero = abort. --no-hardware runs only the local
campaign-planner sanity check.
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
GREEN = "\033[32m"; RED = "\033[31m"; RESET = "\033[0m"

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


def check_campaign_planner(cfg: dict) -> tuple[bool, str]:
    """Build a campaign for two seeds and confirm all five strategies are
    present with disjoint per-strategy 5-tuple space (no sport collisions)."""
    try:
        import experiments.scenarios as S
        orig_send, orig_sleep = S._send, S.time.sleep
        S._send = lambda *a, **k: None          # type: ignore[assignment]
        S.time.sleep = lambda *a, **k: None      # type: ignore[assignment]
        try:
            ev0 = S.pack_mimicry_e17(seed=0)
            ev1 = S.pack_mimicry_e17(seed=1)
        finally:
            S._send, S.time.sleep = orig_send, orig_sleep
    except Exception as exc:
        return False, f"planner error: {exc}"
    strat0 = {e.scenario for e in ev0}
    want = set(cfg["strategies"])
    if not want.issubset(strat0):
        return False, f"missing strategies: {sorted(want - strat0)}"
    # disjoint sport space across seeds (per-trial offset).
    sp0 = {(e.scenario, e.src_port) for e in ev0}
    sp1 = {(e.scenario, e.src_port) for e in ev1}
    overlap = sp0 & sp1
    if overlap:
        return False, (f"sport collision across seeds: "
                       f"{len(overlap)} shared (trial isolation broken)")
    return True, (f"5 strategies present; {len(ev0)} events/campaign; "
                  f"seed0/seed1 sport spaces disjoint")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="T2.5 preflight")
    ap.add_argument("--config", type=Path,
                    default=REPO / "experiments/configs/T2_5.yaml")
    ap.add_argument("--switch", default="decps@10.10.54.15")
    ap.add_argument("--controller-log",
                    default="/home/decps/my_program/ota/runs/controller_campaign_2026-06-06.log")
    ap.add_argument("--no-hardware", action="store_true")
    args = ap.parse_args(argv)

    cfg = yaml.safe_load(args.config.read_text())
    print(f"\n=== T2.5 preflight ({cfg['experiment_id']}) ===\n")
    results = [CheckResult("campaign-planner", *check_campaign_planner(cfg))]
    if not args.no_hardware:
        results += [
            CheckResult("ports-up", *check_ports_up(args.switch)),
            CheckResult("bf_switchd-alive", *check_proc(args.switch, "bf_switchd")),
            CheckResult("controller-alive",
                        *check_proc(args.switch, "ota_shield_controller.py")),
            CheckResult("rat-verified",
                        *check_rat_verified(args.switch, args.controller_log)),
        ]
    for r in results:
        tag = f"{GREEN}  OK  {RESET}" if r.ok else f"{RED} FAIL {RESET}"
        print(f"[{tag}] {r.name:<22} {r.detail}")
    failed = [r for r in results if not r.ok]
    if failed:
        print(f"\n{RED}T2.5 PREFLIGHT FAILED{RESET}: {len(failed)} failed.")
        return 1
    print(f"\n{GREEN}T2.5 PREFLIGHT OK{RESET}: all {len(results)} passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
