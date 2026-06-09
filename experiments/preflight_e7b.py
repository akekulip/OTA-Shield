"""Preflight verifier for the E7b 8-hour slow-cadence overnight experiment.

E7b emits ~100 sparse benign MQTT PUBLISHes over 8h to verify
tau_R1=14400s fires zero times on benign events. Every check below
queries real state on laptop + switch + Vision. Any FAIL aborts.

Exit: 0 proceed, 1 abort (FAIL), 2 preflight crashed. Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Tuple

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
CheckResult = Tuple[bool, str, str]

# SSH password read from environment — never hardcode; set via source ~/.lab_env
SSH_PASSWORD = os.environ.get("OTA_SSHPASS", "")
if not SSH_PASSWORD:
    raise RuntimeError("OTA_SSHPASS env var not set; source ~/.lab_env first")
SSH_TIMEOUT_S = 5
DEFAULT_VISION = "decps@10.10.54.19"
DEFAULT_SWITCH = "decps@10.10.54.15"
# Standard E7b / pre-E22 baseline: exactly these 3 rollout_ids.
EXPECTED_ROLLOUT_IDS = {"e12-primary-source",
                        "e12-authorized-rollback",
                        "e12-secondary-source-migration"}
REMOTE_CONTROLLER_PY = ("/home/decps/my_program/ota/controller/"
                        "ota_shield_controller.py")
REMOTE_RAT = "/home/decps/my_program/ota/controller/rat_e12.json"
REMOTE_RAT_BAK = REMOTE_RAT + ".e22bak"
REMOTE_CONTROLLER_LOG_DEFAULT = "/tmp/controller.log"


def _ssh(host: str, cmd: str,
         timeout: int = SSH_TIMEOUT_S) -> subprocess.CompletedProcess:
    """sshpass-wrapped ssh; never raises."""
    full = ["sshpass", "-p", SSH_PASSWORD, "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", f"ConnectTimeout={timeout}",
            "-o", "LogLevel=ERROR", host, cmd]
    try:
        return subprocess.run(full, capture_output=True, text=True,
                              timeout=timeout + 3)
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(full, 124, e.stdout or "",
                                           "TIMEOUT")
    except FileNotFoundError:
        return subprocess.CompletedProcess(full, 127, "", "sshpass-missing")


def _have_sshpass() -> CheckResult:
    if shutil.which("sshpass") is None:
        return False, "sshpass binary missing on laptop", FAIL
    return True, "sshpass present", PASS


def chk_ssh(vision: str, switch: str) -> CheckResult:
    for h in (vision, switch):
        r = _ssh(h, "true")
        if r.returncode != 0:
            return (False,
                    f"{h} unreachable rc={r.returncode} "
                    f"{r.stderr.strip()[:120]}", FAIL)
    return True, f"ssh ok {vision} + {switch}", PASS


def _controller_pid_etime(switch: str):
    r = _ssh(switch, "pgrep -af ota_shield_controller.py || true")
    lines = [ln for ln in r.stdout.splitlines()
             if ln.strip() and "preflight" not in ln]
    if not lines:
        return None, None
    pid = lines[0].split()[0]
    r2 = _ssh(switch, f"ps -o etimes= -p {pid} 2>/dev/null || true")
    try:
        et = int(r2.stdout.strip().splitlines()[0])
    except (ValueError, IndexError):
        et = None
    return pid, et


def chk_controller_alive(switch: str) -> CheckResult:
    pid, et = _controller_pid_etime(switch)
    if pid is None:
        return False, "no ota_shield_controller.py process", FAIL
    if et is None:
        return True, f"controller pid={pid} (etime unknown)", WARN
    return True, f"controller alive pid={pid} etime={et}s", PASS


def chk_controller_uptime(switch: str, require_fresh: bool) -> CheckResult:
    pid, et = _controller_pid_etime(switch)
    if pid is None:
        return False, "controller not running", FAIL
    if et is None:
        return True, f"pid={pid} etime parse-fail; assume fresh", WARN
    if require_fresh and et >= 3600:
        return False, f"controller up {et}s >= 1h (--require-fresh)", FAIL
    if et < 3600:
        return True, f"controller uptime {et}s < 1h", PASS
    if et <= 4 * 3600:
        return True, f"controller uptime {et}s in (1h,4h]", WARN
    return True, f"controller up {et}s > 4h; R1 counters may be dirty", WARN


def chk_rat_current(switch: str) -> CheckResult:
    r = _ssh(switch,
             f"cat {REMOTE_RAT}; echo ===SEP===; "
             f"sha256sum {REMOTE_RAT} 2>/dev/null; "
             f"sha256sum {REMOTE_RAT_BAK} 2>/dev/null")
    parts = r.stdout.split("===SEP===") if r.returncode == 0 else []
    if len(parts) < 2:
        return False, f"cannot read {REMOTE_RAT}", FAIL
    try:
        rat = json.loads(parts[0])
    except json.JSONDecodeError as exc:
        return False, f"rat_e12.json not valid JSON: {exc}", FAIL
    ros = rat.get("authorized_rollouts", [])
    if len(ros) != 3:
        return (False, f"RAT has {len(ros)} rollouts, expected 3 "
                "(E22 fixture still installed?)", FAIL)
    got = {ro.get("rollout_id", "") for ro in ros}
    if got != EXPECTED_ROLLOUT_IDS:
        return (False, f"RAT rollout_ids mismatch; "
                f"extra={sorted(got-EXPECTED_ROLLOUT_IDS)} "
                f"missing={sorted(EXPECTED_ROLLOUT_IDS-got)}", FAIL)
    shas = [ln.split()[0] for ln in parts[1].strip().splitlines()
            if ln.strip()]
    if len(shas) < 2:
        return True, "3 standard rollouts; backup sha missing", WARN
    if shas[0] != shas[1]:
        return (False, f"rat sha {shas[0][:12]} != .e22bak "
                f"{shas[1][:12]} — E22 did not restore cleanly", FAIL)
    return True, f"RAT standard + sha matches .e22bak ({shas[0][:12]})", PASS


def chk_clock_skew(vision: str, switch: str) -> CheckResult:
    a = time.time()
    rs = _ssh(switch, "date +%s.%N")
    rv = _ssh(vision, "date +%s.%N")
    b = time.time()
    if rs.returncode or rv.returncode:
        return False, "clock query ssh failed", FAIL
    try:
        ts, tv = float(rs.stdout.strip()), float(rv.stdout.strip())
    except ValueError:
        return False, "could not parse remote date", FAIL
    tl = 0.5 * (a + b)
    skew = max(abs(ts - tl), abs(tv - tl), abs(ts - tv))
    if skew > 2.0:
        return (False,
                f"skew {skew:.2f}s > 2s (laptop={tl:.2f} sw={ts:.2f} "
                f"vi={tv:.2f})", FAIL)
    return True, f"clock skew max {skew:.2f}s", PASS


def _free_gb(host: str, path: str) -> float:
    r = _ssh(host, f"df -PB1 {path} | tail -1 | awk '{{print $4}}'")
    try:
        return int(r.stdout.strip()) / (1024 ** 3)
    except ValueError:
        return -1.0


def chk_disk(vision: str, switch: str) -> CheckResult:
    sw = _free_gb(switch, "/home")
    vi = _free_gb(vision, "/tmp")
    if sw < 0 or vi < 0:
        return False, f"df failed switch={sw} vision={vi}", FAIL
    if sw < 5.0:
        return False, f"switch /home {sw:.1f}GB < 5GB", FAIL
    if vi < 2.0:
        return False, f"vision /tmp {vi:.1f}GB < 2GB", FAIL
    return True, f"switch /home {sw:.1f}GB, vision /tmp {vi:.1f}GB", PASS


def chk_local_heartbeat_path() -> CheckResult:
    p = Path("runs/experiments/E7b")
    try:
        p.mkdir(parents=True, exist_ok=True)
        probe = p / ".preflight_probe"
        probe.write_text("ok")
        probe.unlink()
    except OSError as exc:
        return False, f"{p} not writable: {exc}", FAIL
    return True, f"{p} writable", PASS


def chk_scapy(vision: str) -> CheckResult:
    r = _ssh(vision,
             "sudo -n python3 -c 'from scapy.all import sendp' 2>&1; "
             "echo rc=$?", timeout=10)
    tail = r.stdout.strip().splitlines()
    if not tail or "rc=0" not in tail[-1]:
        return False, f"sudo -n scapy failed: {r.stdout[-200:]}", FAIL
    return True, "sudo -n + scapy.sendp ok on vision", PASS


def chk_vision_iface(vision: str, iface: str = "enp59s0f0np0") -> CheckResult:
    r = _ssh(vision, f"ip -o link show {iface} 2>/dev/null; "
             f"ethtool {iface} 2>/dev/null | grep -E 'Speed:' || true")
    if r.returncode or not r.stdout.strip():
        return False, f"iface {iface} not found", FAIL
    txt = r.stdout
    if "state UP" not in txt and ",UP," not in txt and "UP " not in txt:
        return False, f"iface {iface} not UP: {txt.strip()[:160]}", FAIL
    m = re.search(r"Speed:\s*(\d+)\s*Mb/s", txt)
    sp = int(m.group(1)) if m else 0
    if sp and sp < 1000:
        return False, f"iface {iface} speed {sp}Mb/s < 1Gb/s", FAIL
    return True, f"iface {iface} UP speed={sp or 'unknown'}Mb/s", PASS


def chk_no_competing(vision: str, switch: str) -> CheckResult:
    conflicts = []
    for h in (vision, switch):
        r = _ssh(h, "pgrep -af 'run_e22.py|run_e12b.py' | "
                    "grep -v preflight || true")
        hits = [ln for ln in r.stdout.splitlines() if ln.strip()]
        if hits:
            conflicts.append(f"{h}: {hits[0][:120]}")
    if conflicts:
        return False, "competing run: " + " | ".join(conflicts), FAIL
    return True, "no E22/E12b competitor", PASS


def chk_tau_r1(switch: str) -> CheckResult:
    r = _ssh(switch,
             f"grep -nE 'R1_MIN_INTERVAL_S|tau_r1|tau_R1|TAU_R1' "
             f"{REMOTE_CONTROLLER_PY} | head -5")
    if r.returncode or not r.stdout.strip():
        return False, f"cannot grep tau_R1 in {REMOTE_CONTROLLER_PY}", FAIL
    for line in r.stdout.splitlines():
        if "R1_MIN_INTERVAL_S" in line and "14400" in line:
            return True, "tau_R1 = 14400s in controller source", PASS
        if re.search(r"tau_r1\s*=\s*14400", line, re.I):
            return True, "tau_R1 = 14400s in controller source", PASS
    return (False,
            "tau_R1 != 14400: "
            + r.stdout.strip().replace("\n", " | ")[:240], FAIL)


def chk_duration_vs_cadence(cfg_path: Path) -> CheckResult:
    if not cfg_path.exists():
        return False, f"config not found: {cfg_path}", FAIL
    params: dict = {}
    in_p = False
    for raw in cfg_path.read_text().splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if line.startswith("params:"):
            in_p = True
            continue
        if in_p and line and not line.startswith((" ", "\t")):
            in_p = False
            continue
        if in_p:
            m = re.match(r"\s+([A-Za-z_][\w]*):\s*([-\d.]+)", line)
            if m:
                try:
                    params[m.group(1)] = float(m.group(2))
                except ValueError:
                    pass
    dur, n_bms, tau = (params.get("duration_sec"), params.get("n_bms"),
                       params.get("tau_r1_sec"))
    if None in (dur, n_bms, tau):
        return False, f"missing duration_sec/n_bms/tau_r1_sec: {params}", FAIL
    if dur > 8 * 3600 + 60:
        return False, f"duration_sec {dur} > 8h budget", FAIL
    # Uniform(18000,22000) per-BMS ≈ 1 event per 20000s per BMS.
    exp = n_bms * dur / 20000.0
    if not (40 <= exp <= 200):
        return False, f"expected benign events {exp:.0f} outside [40,200]", FAIL
    if tau != 14400:
        return False, f"config tau_r1_sec={tau} != 14400", FAIL
    return (True, f"dur={dur:.0f}s n_bms={n_bms:.0f} ~{exp:.0f} benign "
            f"events; tau_r1_sec={tau}", PASS)


def chk_ssh_keepalive() -> CheckResult:
    cfg = Path.home() / ".ssh" / "config"
    if cfg.exists() and "serveraliveinterval" in cfg.read_text().lower():
        return True, "~/.ssh/config has ServerAliveInterval", PASS
    return (True,
            "no ServerAliveInterval; run driver under tmux/nohup to "
            "survive overnight SSH drop", WARN)


def chk_heartbeat_writable(out_dir: Path,
                           interval_s: float) -> CheckResult:
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        probe = out_dir / ".preflight_probe_resume"
        probe.write_text("ok")
        probe.unlink()
    except OSError as exc:
        return False, f"resume dir {out_dir} not writable: {exc}", FAIL
    if interval_s < 60 or interval_s > 3600:
        return (False,
                f"heartbeat interval {interval_s}s outside [60s,1h]", FAIL)
    return (True,
            f"{out_dir} writable; heartbeat {interval_s:.0f}s", PASS)


# Step-0 (2026-04-20): ASIC-register readback. Closes state-bleed where
# R6/R5/override rows stayed dirty across controller restarts and silently
# produced DROPs at bms_idx=0 in E12b Phase A.
def chk_state_readback(switch: str) -> CheckResult:
    pid, _ = _controller_pid_etime(switch)
    if pid is None:
        return False, "no controller pid (cannot SIGUSR1/2)", FAIL
    script = Path(__file__).with_name("preflight_state_check.py")
    if not script.exists():
        return False, f"{script} missing", FAIL
    cmd = ["python3", str(script),
           "--switch", switch,
           "--controller-pid", str(pid),
           "--require-signed",
           "--expected-rat-entries", "3",
           "--expected-rollback-window-entries", "0",
           "--quiet"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return False, "preflight_state_check.py >30s", FAIL
    if r.returncode == 0:
        return True, f"R6/R5/override clean; RAT signed (pid {pid})", PASS
    tail = ((r.stderr or "") + (r.stdout or "")).strip().splitlines()
    detail = "; ".join(tail[-6:]) if tail else "unknown failure"
    return False, f"rc={r.returncode}: {detail[:400]}", FAIL


def chk_rat_reload_rejections(switch: str, log: str) -> CheckResult:
    r = _ssh(switch,
             f"tail -n 200 {log} 2>/dev/null | "
             "grep -c 'RAT reload REJECTED' || true")
    try:
        n = int(r.stdout.strip().splitlines()[-1]) if r.stdout.strip() else 0
    except (ValueError, IndexError):
        n = 0
    if n > 0:
        return False, f"{n} 'RAT reload REJECTED' in last 200 of {log}", FAIL
    return True, "no recent RAT reload rejections", PASS


@dataclass
class Check:
    name: str
    fn: Callable[[], CheckResult]


def build_checks(a: argparse.Namespace) -> List[Check]:
    out = Path("runs/experiments/E7b")
    return [
        Check("sshpass-binary", _have_sshpass),
        Check("ssh-reachability", lambda: chk_ssh(a.vision, a.switch)),
        Check("controller-alive", lambda: chk_controller_alive(a.switch)),
        Check("controller-uptime", lambda: chk_controller_uptime(
            a.switch, a.require_fresh_controller)),
        Check("rat-current", lambda: chk_rat_current(a.switch)),
        Check("clock-skew", lambda: chk_clock_skew(a.vision, a.switch)),
        Check("disk-headroom", lambda: chk_disk(a.vision, a.switch)),
        Check("local-heartbeat-path", chk_local_heartbeat_path),
        Check("scapy-on-vision", lambda: chk_scapy(a.vision)),
        Check("vision-iface", lambda: chk_vision_iface(a.vision)),
        Check("no-competing-run",
              lambda: chk_no_competing(a.vision, a.switch)),
        Check("tau-r1-source", lambda: chk_tau_r1(a.switch)),
        Check("duration-vs-cadence",
              lambda: chk_duration_vs_cadence(a.config_path)),
        Check("ssh-keepalive", chk_ssh_keepalive),
        Check("heartbeat-writable",
              lambda: chk_heartbeat_writable(out, 15 * 60)),
        Check("rat-reload-rejections",
              lambda: chk_rat_reload_rejections(a.switch, a.controller_log)),
        Check("asic-state-readback",
              lambda: chk_state_readback(a.switch)),
    ]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--vision", default=DEFAULT_VISION)
    ap.add_argument("--switch", default=DEFAULT_SWITCH)
    ap.add_argument("--config-path", type=Path,
                    default=Path("experiments/configs/E7b_slow_cadence.yaml"))
    ap.add_argument("--controller-log", default=REMOTE_CONTROLLER_LOG_DEFAULT)
    ap.add_argument("--require-fresh-controller", action="store_true",
                    help="Treat controller uptime >= 1h as FAIL.")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    n_fail = n_warn = n_pass = 0
    results = []
    print("=== preflight_e7b ===")
    for ch in build_checks(args):
        t0 = time.time()
        try:
            ok, detail, sev = ch.fn()
        except Exception as exc:
            ok, detail, sev = False, f"check crashed: {exc!r}", FAIL
        dt = time.time() - t0
        n_fail += sev == FAIL
        n_warn += sev == WARN
        n_pass += sev == PASS
        print(f"  [{sev}] {ch.name:<26} ({dt:4.1f}s) {detail}")
        results.append({"name": ch.name, "ok": ok, "severity": sev,
                        "detail": detail, "elapsed_s": dt})
    print(f"--- summary: {n_pass} PASS, {n_warn} WARN, {n_fail} FAIL ---")
    if args.json:
        print(json.dumps({"n_pass": n_pass, "n_warn": n_warn,
                          "n_fail": n_fail, "results": results}, indent=2))
    return 1 if n_fail else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(2)
