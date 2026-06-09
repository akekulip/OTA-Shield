"""Preflight verifier for the M4 QoS=0 portability reviewer wave.

Sub-experiments (--experiment REQUIRED; this IS the intent gate, #14):
- e18_qos0  : QoS=0 portability rerun. TWO AXES. (a) old-parser HW run
              reuses the currently loaded P4 and is safe. (b) new-parser
              HW run is GATED on a P4 recompile + bf_switchd restart,
              which the user has explicitly forbidden without approval.
- e1_200bms : 200-BMS per-rule extrapolation; old parser fine.
- e8_200bms : 200-BMS stochastic extrapolation; old parser fine.

Rules: never restart bf_switchd, never recompile P4, stdlib-only.
"""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Tuple

SEV_INFO, SEV_WARN, SEV_FAIL = "INFO", "WARN", "FAIL"
CheckResult = Tuple[bool, str, str]

REPO_ROOT = Path(__file__).resolve().parent.parent
CONF_DIR = REPO_ROOT / "experiments" / "configs"
EXTRAPOL_NOTES = REPO_ROOT / "experiments" / "m4_extrapolation_notes.md"
SCENARIOS_M4 = REPO_ROOT / "experiments" / "scenarios_m4.py"

SWITCH_P4INFO_CANDIDATES = [
    "/home/decps/my_program/ota/build/ota_shield/ota_shield.p4info.txt",
    "/home/decps/my_program/ota/build/ota_shield/p4info.txt",
    "/home/decps/my_program/ota/build/ota_shield/ota_shield.conf",
    "/home/decps/Downloads/bf-sde-9.13.2/build/ota_shield/ota_shield.p4info.txt",
    "/home/decps/Downloads/bf-sde-9.13.2/build/ota_shield/p4info.txt",
    "/home/decps/Downloads/bf-sde-9.13.2/build/ota_shield/ota_shield.conf",
]
SWITCH_CONTROLLER_RAT = "/home/decps/my_program/ota/controller/rat_e12.json"
SWITCH_CONTROLLER_LOG = "/home/decps/my_program/ota/runs/phase6_digests.jsonl"
SWITCH_DECISIONS_LOG = "/home/decps/my_program/ota/runs/decisions.jsonl"

# Recompile/restart hint, kept as a STRING — never executed here.
P4_RECOMPILE_HINT = (
    "# To flip to the new parser, the operator (NOT this script) runs:\n"
    "#   ssh decps@10.10.54.15 'cd ~/my_program/ota && make -C p4build clean"
    " && make -C p4build && sudo pkill -INT bf_switchd && sleep 5"
    " && sudo /home/decps/my_program/ota/run_switch.sh'\n"
    "# The user has explicitly forbidden this without approval.")

EXPECTED_BMS_COUNT = 200
def _run(cmd: str, timeout: float = 10.0) -> subprocess.CompletedProcess:
    """Run a shell command with a bounded timeout; never raises."""
    try:
        return subprocess.run(cmd, shell=True, capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(cmd, 124, exc.stdout or "",
                                           f"TIMEOUT after {timeout}s")
def _ssh(host: str, remote: str, timeout: float = 10.0
         ) -> subprocess.CompletedProcess:
    """ssh wrapper with short ConnectTimeout; read-only remotes only."""
    return _run("ssh -o StrictHostKeyChecking=no -o BatchMode=yes "
                f"-o ConnectTimeout=5 {host} {shlex.quote(remote)}",
                timeout=timeout)
def check_ssh_reachability(switch: str, vision: str) -> CheckResult:
    """Check 1: both hosts answer a trivial command within 5 s."""
    t0 = time.time()
    sr = _ssh(switch, "true", timeout=5.0)
    vr = _ssh(vision, "true", timeout=5.0)
    if sr.returncode != 0:
        return False, f"switch SSH rc={sr.returncode}: {sr.stderr}", SEV_FAIL
    if vr.returncode != 0:
        return False, f"vision SSH rc={vr.returncode}: {vr.stderr}", SEV_FAIL
    return True, f"switch+vision reachable in {time.time()-t0:.2f}s", SEV_INFO
def check_bf_switchd_alive(switch: str) -> CheckResult:
    """Check 3: pgrep bf_switchd returns a PID. Read-only."""
    r = _ssh(switch, "pgrep -af bf_switchd | head -1")
    if r.returncode != 0 or not r.stdout.strip():
        return (False, "bf_switchd NOT running. Do NOT start/restart it "
                       "from this script — escalate to user.", SEV_FAIL)
    return True, f"bf_switchd alive: {r.stdout.strip()}", SEV_INFO
def detect_parser(switch: str) -> dict:
    """Probe loaded parser: compare P4 artifact mtime to bf_switchd start
    time. If artifact is FRESHER than the process, bf_switchd is still
    executing the OLD parser — the hazard new-parser must reject."""
    info = {"artifact_path": None, "artifact_mtime": None,
            "bf_start_epoch": None, "program_name": None,
            "fresher_on_disk": None}
    for path in SWITCH_P4INFO_CANDIDATES:
        r = _ssh(switch, f"stat -c '%Y %n' {path} 2>/dev/null")
        if r.returncode == 0 and r.stdout.strip():
            parts = r.stdout.strip().split(None, 1)
            if len(parts) == 2:
                try:
                    info["artifact_mtime"] = int(parts[0])
                    info["artifact_path"] = parts[1]
                    break
                except ValueError:
                    pass
    r = _ssh(switch, "ps -o lstart=,pid=,cmd= -C bf_switchd | head -1")
    if r.returncode == 0 and r.stdout.strip():
        info["program_name"] = r.stdout.strip()
        r2 = _ssh(switch, "ps -o etimes= -C bf_switchd | head -1")
        if r2.returncode == 0 and r2.stdout.strip():
            try:
                info["bf_start_epoch"] = int(time.time()) - int(r2.stdout.strip())
            except ValueError:
                pass
    if info["artifact_mtime"] and info["bf_start_epoch"]:
        info["fresher_on_disk"] = info["artifact_mtime"] > info["bf_start_epoch"]
    return info
def check_parser_matches_intent(switch: str, experiment: str,
                                 want_new_parser: bool) -> CheckResult:
    """Checks 2 + 15: if new-parser is requested (e18_qos0 only), FAIL
    unless the disk artifact is fresher than bf_switchd AND restart is
    operator-approved. Old-parser intent always passes (with summary)."""
    p = detect_parser(switch)
    if p["artifact_path"] is None:
        return (False, "No P4 artifact at: "
                + ", ".join(SWITCH_P4INFO_CANDIDATES), SEV_FAIL)
    if p["bf_start_epoch"] is None:
        return (False, "bf_switchd elapsed-time probe failed — cannot "
                       "correlate artifact mtime to running binary.", SEV_FAIL)
    delta = (p["artifact_mtime"] or 0) - p["bf_start_epoch"]
    summary = (f"artifact={p['artifact_path']} mtime={p['artifact_mtime']} "
               f"bf_start={p['bf_start_epoch']} delta={delta}s "
               f"fresher_on_disk={p['fresher_on_disk']}")
    if not want_new_parser:
        return True, "OLD-parser intent OK — " + summary, SEV_INFO
    if p["fresher_on_disk"] is False:
        return (False, "NEW-parser requested but artifact is NOT fresher "
                "than bf_switchd — the QoS=0 row would silently measure "
                "the OLD parser.\n" + summary + "\n" + P4_RECOMPILE_HINT,
                SEV_FAIL)
    return (False, "NEW-parser requested: disk artifact IS fresher than "
            "bf_switchd. This preflight will NOT restart bf_switchd; "
            "operator must approve restart first.\n" + summary + "\n"
            + P4_RECOMPILE_HINT, SEV_FAIL)
def check_controller_rat(switch: str) -> CheckResult:
    """Check 4a: rat.json parses and has a sibling .sig (signed=True)."""
    r = _ssh(switch, f"cat {SWITCH_CONTROLLER_RAT}")
    if r.returncode != 0 or not r.stdout.strip():
        return False, f"rat.json unreadable: {r.stderr}", SEV_FAIL
    try:
        rat = json.loads(r.stdout)
    except json.JSONDecodeError as exc:
        return False, f"rat.json invalid JSON: {exc}", SEV_FAIL
    rollouts = rat.get("authorized_rollouts", [])
    if not rollouts:
        return False, "rat.json has no authorized_rollouts.", SEV_FAIL
    sig_r = _ssh(switch, f"ls -1 {SWITCH_CONTROLLER_RAT}.sig 2>/dev/null")
    if not sig_r.stdout.strip():
        return (False, f"No {SWITCH_CONTROLLER_RAT}.sig — signed=True "
                       "required for M4 runs.", SEV_FAIL)
    return True, f"rat.json has {len(rollouts)} rollout(s), signed=True", SEV_INFO
def check_controller_no_recent_reject(switch: str) -> CheckResult:
    """Check 4b: count REJECTED entries in tail of decisions.jsonl."""
    cmd = (f"tail -n 500 {SWITCH_DECISIONS_LOG} 2>/dev/null | "
           "grep -c REJECTED || true")
    r = _ssh(switch, cmd)
    raw = (r.stdout or "").strip().split()[0] if r.stdout.strip() else "0"
    try:
        n = int(raw)
    except ValueError:
        n = 0
    if n > 0:
        return True, f"{n} REJECTED in tail 500 of decisions.jsonl", SEV_WARN
    return True, "no recent REJECTED entries", SEV_INFO
def check_scenario_pcap_validity(experiment: str) -> CheckResult:
    """Check 5: build a tiny pcap with scenarios_m4 and verify with rdpcap.
    For e18_qos0, also confirm at least one QoS=0 PUBLISH frame is present."""
    import importlib.util
    import shutil
    import tempfile
    spec = importlib.util.spec_from_file_location("scenarios_m4", SCENARIOS_M4)
    if spec is None or spec.loader is None:
        return False, f"cannot import {SCENARIOS_M4}", SEV_FAIL
    try:
        mod = importlib.util.module_from_spec(spec)
        import sys as _sys
        _sys.modules[spec.name] = mod  # py3.8 dataclasses needs cls.__module__ resolvable
        spec.loader.exec_module(mod)
    except Exception as exc:
        return False, f"scenarios_m4 import failed: {exc!r}", SEV_FAIL
    tmp = Path(tempfile.mkdtemp(prefix="m4_preflight_"))
    try:
        if experiment == "e18_qos0":
            scenario_dir = mod.pack_e18_qos0_portability(tmp, seed=0)
        elif experiment == "e1_200bms":
            scenario_dir = mod.pack_e1_200bms_extrapolation(
                tmp, seed=0, n_bms=5, per_bms_rate_hz=0.5,
                duration_s=4.0, attack_fraction=0.2)
        else:
            scenario_dir = mod.pack_e8_200bms_extrapolation(
                tmp, seed=0, n_bms=5, per_bms_rate_hz=0.5,
                duration_s=4.0, attack_fraction=0.2)
        pcap_path = Path(scenario_dir) / "traffic.pcap"
        if not pcap_path.exists():
            return False, f"pcap not generated at {pcap_path}", SEV_FAIL
        try:
            from scapy.all import rdpcap
        except Exception as exc:
            return False, f"scapy rdpcap unavailable: {exc!r}", SEV_FAIL
        pkts = rdpcap(str(pcap_path))
        if len(pkts) == 0:
            return False, "pcap has zero frames", SEV_FAIL
        if experiment == "e18_qos0":
            saw_qos0 = False
            for p in pkts:
                raw = bytes(p.payload.payload.payload) if hasattr(p, "payload") else b""
                if raw and (raw[0] & 0xF0) == 0x30 and (raw[0] & 0x06) == 0:
                    saw_qos0 = True
                    break
            if not saw_qos0:
                return False, "no QoS=0 PUBLISH frame in E18 pcap", SEV_FAIL
        return True, f"pcap OK n={len(pkts)} at {pcap_path}", SEV_INFO
    except Exception as exc:
        return False, f"pcap build/probe failed: {exc!r}", SEV_FAIL
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
def check_extrapolation_notes(experiment: str) -> CheckResult:
    """Check 6: extrapolation notes exist and disclose measured-vs-extrapolated."""
    if not EXTRAPOL_NOTES.exists():
        return False, f"missing {EXTRAPOL_NOTES}", SEV_FAIL
    txt = EXTRAPOL_NOTES.read_text(errors="replace").lower()
    missing = [t for t in ("measured", "extrapolat") if t not in txt]
    if missing:
        return False, f"{EXTRAPOL_NOTES.name} missing tokens: {missing}", SEV_FAIL
    if experiment in {"e1_200bms", "e8_200bms"} and "200" not in txt:
        return False, "extrapolation notes missing 200-BMS framing", SEV_FAIL
    return True, f"{EXTRAPOL_NOTES.name} discloses axes", SEV_INFO
def check_output_dir_writable(experiment: str) -> CheckResult:
    """Check 7: per-sub-experiment dir under runs/experiments/M4 is writable."""
    out_root = REPO_ROOT / "runs" / "experiments" / "M4" / experiment
    try:
        out_root.mkdir(parents=True, exist_ok=True)
        probe = out_root / ".preflight_probe"
        probe.write_text("ok")
        probe.unlink()
    except OSError as exc:
        return False, f"cannot write {out_root}: {exc}", SEV_FAIL
    return True, f"output dir writable: {out_root}", SEV_INFO
def check_vision_iface_up(vision: str, iface: str) -> CheckResult:
    """Check 8: Vision iface is administratively up."""
    r = _ssh(vision, f"ip -br link show {shlex.quote(iface)}")
    if r.returncode != 0 or not r.stdout.strip():
        return False, f"iface {iface} missing: {r.stderr}", SEV_FAIL
    line = r.stdout.strip()
    if " UP " not in f" {line} ":
        return False, f"iface {iface} not UP: {line}", SEV_FAIL
    return True, f"Vision iface up: {line}", SEV_INFO
def check_vision_scapy_and_sudo(vision: str) -> CheckResult:
    """Check 9: scapy import under sudo -n python3 (NOPASSWD)."""
    r = _ssh(vision,
             "sudo -n python3 -c 'import scapy.all,sys;print(scapy.all.__name__)'",
             timeout=8.0)
    if r.returncode != 0:
        return (False, f"sudo -n python3 scapy probe failed: "
                f"rc={r.returncode} stderr={r.stderr.strip()}", SEV_FAIL)
    return True, "Vision scapy+NOPASSWD python3 OK", SEV_INFO
def check_no_competing_run() -> CheckResult:
    """Check 10: no run_e22|run_e7b|run_e12b|run_m4 pgrep match locally."""
    r = _run("pgrep -af 'run_e22|run_e7b|run_e12b|run_m4' | "
             "grep -v preflight_m4 || true")
    hits = [ln for ln in (r.stdout or "").splitlines() if ln.strip()]
    if hits:
        return False, "competing runner(s): " + " | ".join(hits), SEV_FAIL
    return True, "no competing run process", SEV_INFO
def check_config_knobs(experiment: str) -> CheckResult:
    """Check 11: config parses and matches paper-expected knobs.
    For e18_qos0 the QoS=0 axis must be declared; for the 200-BMS
    configs, n_bms must equal EXPECTED_BMS_COUNT."""
    def _load(path: Path) -> dict:
        txt = path.read_text(errors="replace")
        try:
            import yaml
            return yaml.safe_load(txt) or {}
        except Exception:
            flat: dict = {}
            for ln in txt.splitlines():
                s = ln.strip()
                if not s or s.startswith("#") or ":" not in s:
                    continue
                k, _, v = s.partition(":")
                flat[k.strip()] = v.strip().strip('"')
            return flat
    if experiment == "e18_qos0":
        cfg_path = CONF_DIR / "E18_qos0_portability.yaml"
        text = cfg_path.read_text().lower()
        if "qos" not in text or "0" not in text:
            return False, f"{cfg_path.name} missing QoS=0 axis", SEV_FAIL
        return True, f"{cfg_path.name} declares QoS=0 portability", SEV_INFO
    cfg_path = (CONF_DIR / "E1_200bms.yaml" if experiment == "e1_200bms"
                else CONF_DIR / "E8_200bms.yaml")
    cfg = _load(cfg_path)
    params = cfg.get("params", {}) if isinstance(cfg.get("params"), dict) else {}
    n_bms = params.get("n_bms") or cfg.get("n_bms")
    if str(n_bms) != str(EXPECTED_BMS_COUNT):
        return (False, f"{cfg_path.name} n_bms={n_bms!r}, expected "
                f"{EXPECTED_BMS_COUNT}", SEV_FAIL)
    return True, f"{cfg_path.name} n_bms={EXPECTED_BMS_COUNT}", SEV_INFO
def check_clock_skew(switch: str, vision: str) -> CheckResult:
    """Check 12: |local - switch|, |local - vision| both <2 s."""
    local = int(time.time())
    sr = _ssh(switch, "date +%s", timeout=5.0)
    vr = _ssh(vision, "date +%s", timeout=5.0)
    try:
        sw, vi = int(sr.stdout.strip()), int(vr.stdout.strip())
    except (ValueError, AttributeError):
        return False, "could not read remote clocks", SEV_FAIL
    ds, dv = abs(local - sw), abs(local - vi)
    if ds >= 2 or dv >= 2:
        return False, f"clock skew switch={ds}s vision={dv}s (>=2s)", SEV_FAIL
    return True, f"clock skew switch={ds}s vision={dv}s", SEV_INFO
def check_logs_readable(switch: str) -> CheckResult:
    """Check 13: decisions.jsonl + controller log readable on switch."""
    for p in (SWITCH_DECISIONS_LOG, SWITCH_CONTROLLER_LOG):
        r = _ssh(switch, f"test -r {p} && echo ok || echo missing:{p}")
        if r.returncode != 0 or "ok" not in (r.stdout or ""):
            return False, f"{p} unreadable: {r.stdout.strip()}", SEV_FAIL
    return True, "decisions.jsonl + phase6_digests.jsonl readable", SEV_INFO
def _print(sev: str, name: str, ok: bool, detail: str) -> None:
    """Stable one-line format for each check."""
    tag = {SEV_FAIL: "FAIL", SEV_WARN: "WARN", SEV_INFO: "OK  "}[sev]
    mark = "[v]" if ok else "[x]"
    print(f"{mark} {tag} {name:36s} :: {detail}")
def run_all(args: argparse.Namespace) -> int:
    """Run every check relevant to args.experiment; return exit code."""
    exp = args.experiment
    want_new_parser = bool(args.new_parser)
    checks: list[Tuple[str, Callable[[], CheckResult]]] = [
        ("14_intent_gate_echo", lambda: (
            True, f"experiment={exp} new_parser={want_new_parser}", SEV_INFO)),
        ("01_ssh_reachability",
            lambda: check_ssh_reachability(args.switch, args.vision)),
        ("03_bf_switchd_alive", lambda: check_bf_switchd_alive(args.switch)),
        ("02_15_parser_intent",
            lambda: check_parser_matches_intent(args.switch, exp, want_new_parser)),
        ("04a_rat_signed", lambda: check_controller_rat(args.switch)),
        ("04b_no_recent_reject",
            lambda: check_controller_no_recent_reject(args.switch)),
        ("05_scenario_pcap_valid", lambda: check_scenario_pcap_validity(exp)),
        ("06_extrapolation_notes", lambda: check_extrapolation_notes(exp)),
        ("07_output_dir_writable", lambda: check_output_dir_writable(exp)),
        ("08_vision_iface_up",
            lambda: check_vision_iface_up(args.vision, args.vision_iface)),
        ("09_vision_scapy_sudo",
            lambda: check_vision_scapy_and_sudo(args.vision)),
        ("10_no_competing_run", check_no_competing_run),
        ("11_config_knobs", lambda: check_config_knobs(exp)),
        ("12_clock_skew", lambda: check_clock_skew(args.switch, args.vision)),
        ("13_logs_readable", lambda: check_logs_readable(args.switch)),
    ]
    n_fail = n_warn = 0
    for name, fn in checks:
        try:
            ok, detail, sev = fn()
        except Exception as exc:
            ok, detail, sev = False, f"check raised: {exc!r}", SEV_FAIL
        _print(sev, name, ok, detail)
        if not ok and sev == SEV_FAIL:
            n_fail += 1
        elif sev == SEV_WARN:
            n_warn += 1
    print(f"\nSummary: fail={n_fail} warn={n_warn} "
          f"experiment={exp} new_parser={want_new_parser}")
    return 0 if n_fail == 0 else 2
def main() -> int:
    """CLI entry point."""
    ap = argparse.ArgumentParser(
        description="Preflight verifier for M4 QoS=0 portability "
                    "(E18_qos0, E1_200bms, E8_200bms). Read-only; "
                    "never restarts bf_switchd or recompiles P4.")
    ap.add_argument("--switch", default="decps@10.10.54.15")
    ap.add_argument("--vision", default="decps@10.10.54.19")
    ap.add_argument("--vision-iface", default="enp59s0f0np0")
    # Check 14: intent gate — no default, forcing explicit operator intent.
    ap.add_argument("--experiment", required=True,
                    choices=["e18_qos0", "e1_200bms", "e8_200bms"],
                    help="REQUIRED. M4 sub-experiments share this "
                         "preflight but have different preconditions.")
    ap.add_argument("--new-parser", action="store_true",
                    help="Only valid with --experiment e18_qos0. FAILS "
                         "unless the P4 artifact is fresher than "
                         "bf_switchd AND operator has approved restart. "
                         "This preflight NEVER performs a restart.")
    ap.add_argument("--skip-preflight", action="store_true",
                    help="Emit a WARN line and return 0. Never use for "
                         "a real HW wave.")
    args = ap.parse_args()
    if args.skip_preflight:
        print("[!] WARN preflight SKIPPED by --skip-preflight "
              f"(experiment={args.experiment})")
        return 0
    if args.new_parser and args.experiment != "e18_qos0":
        print(f"[x] FAIL --new-parser is only valid with "
              f"--experiment e18_qos0 (got {args.experiment}).")
        return 2
    return run_all(args)

if __name__ == "__main__":
    sys.exit(main())

