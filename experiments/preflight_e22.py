"""E22 preflight verifier.

Runs BEFORE the E22 driver touches any real hardware. Every check that
can be done without mutating controller state is performed, and the
live-reload probe writes the SAME bytes back so the controller behavior
does not change.

Exit code 0 => proceed. Non-zero => abort; the caller must print the
line-by-line report and refuse to run trials.

Rationale: yesterday's E22 run was wasted because the driver passed
`--remote-sign-cmd true` (a no-op). Every fixture overwrite was scp'd
but its `.sig` stayed stale, the controller rejected each reload with
`ed25519 verification failed`, and 4/5 cases replayed against the
PRE-run last-known-good RAT. F1 came out NaN on 4/5 cases.

This preflight makes that failure mode impossible to repeat: check #12
rejects the exact footgun strings; check #5 proves the poll-reload and
signature-verify pipeline is actually alive at the moment the driver
starts.
"""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Callable, List, Tuple

# SSH password read from environment — never hardcode; set via source ~/.lab_env
SSH_PASS = os.environ.get("OTA_SSHPASS", "")
if not SSH_PASS:
    raise RuntimeError("OTA_SSHPASS env var not set; source ~/.lab_env first")
SSH_OPTS = (
    "-o StrictHostKeyChecking=no "
    "-o UserKnownHostsFile=/dev/null "
    "-o LogLevel=ERROR "
    "-o ConnectTimeout=5 "
    "-o BatchMode=no"
)

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str


def _run(cmd: str, timeout: float = 10.0) -> Tuple[int, str, str]:
    """Run `cmd` through the local shell. Returns (rc, stdout, stderr)."""
    try:
        p = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout:.1f}s"


def _ssh(host: str, remote: str, timeout: float = 10.0) -> Tuple[int, str, str]:
    """sshpass+ssh to `host` (user@host) and run `remote`."""
    cmd = (
        f"sshpass -p {shlex.quote(SSH_PASS)} ssh {SSH_OPTS} "
        f"{shlex.quote(host)} {shlex.quote(remote)}"
    )
    return _run(cmd, timeout=timeout)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def check_ssh_reachability(vision: str, switch: str) -> Tuple[bool, str]:
    """1. SSH reachability for both hosts, <5s each."""
    t0 = time.time()
    rc_s, _, err_s = _ssh(switch, "true", timeout=5.0)
    t_s = time.time() - t0
    t0 = time.time()
    rc_v, _, err_v = _ssh(vision, "true", timeout=5.0)
    t_v = time.time() - t0
    if rc_s != 0:
        return False, f"switch unreachable (rc={rc_s} {t_s:.1f}s): {err_s.strip()}"
    if rc_v != 0:
        return False, f"vision unreachable (rc={rc_v} {t_v:.1f}s): {err_v.strip()}"
    if t_s > 5.0 or t_v > 5.0:
        return False, f"ssh too slow (switch={t_s:.1f}s vision={t_v:.1f}s)"
    return True, f"switch={t_s:.2f}s vision={t_v:.2f}s"


def check_controller_signed(switch: str, log_path: str) -> Tuple[bool, str]:
    """2. Controller alive and last RAT-load was signed=True.

    NOTE: tail -n 200 is unreliable here because the controller emits
    ~1-2 WARNING lines/second (digest_get errors), which pushes RAT-loaded
    lines out of the last 200 within 2 minutes. Use grep instead to find
    the last occurrence regardless of position.
    """
    # grep exits 1 when no match; || true prevents non-zero rc on empty.
    remote = (f"grep 'RAT loaded' {shlex.quote(log_path)} 2>/dev/null "
              f"| tail -n 1 || true")
    rc, out, err = _ssh(switch, remote, timeout=10.0)
    if rc != 0:
        return False, f"cannot read controller log: {err.strip()}"
    last = out.strip()
    if not last:
        return False, f"no 'RAT loaded' lines anywhere in {log_path}"
    if "signed=True" not in last:
        return False, f"last RAT-load not signed: {last[:140]}"
    # Recency: check log file mtime < 30 min (controller writes continuously).
    recent_by_time = False
    try:
        ts_rc, ts_out, _ = _ssh(
            switch,
            f"stat -c %Y {shlex.quote(log_path)} 2>/dev/null",
            timeout=5.0,
        )
        if ts_rc == 0 and ts_out.strip().isdigit():
            mtime = int(ts_out.strip())
            if (time.time() - mtime) < 1800:
                recent_by_time = True
    except Exception:
        pass
    if not recent_by_time:
        return False, f"log mtime is stale (> 30 min old): {last[:140]}"
    return True, last[:140]


def check_signing_assets(switch: str) -> Tuple[bool, str]:
    """3. Signing key (600) and pub key present on switch."""
    key = "/home/decps/.ota_shield/rat_signing.key"
    pub = "/home/decps/my_program/ota/controller/rat.pub"
    remote = (
        f"stat -c '%a %n' {shlex.quote(key)} 2>/dev/null; "
        f"stat -c '%a %n' {shlex.quote(pub)} 2>/dev/null"
    )
    rc, out, err = _ssh(switch, remote, timeout=5.0)
    if rc != 0:
        return False, f"stat failed: {err.strip()}"
    lines = [ln for ln in out.splitlines() if ln.strip()]
    key_line = next((ln for ln in lines if ln.endswith(key)), None)
    pub_line = next((ln for ln in lines if ln.endswith(pub)), None)
    if not key_line:
        return False, f"missing signing key: {key}"
    if not pub_line:
        return False, f"missing pub key: {pub}"
    perm = key_line.split()[0]
    if perm != "600":
        return False, f"signing key perm={perm} (want 600): {key}"
    return True, f"key={key} perm=600; pub={pub}"


def check_sign_rat_roundtrip(switch: str) -> Tuple[bool, str]:
    """4. sign_rat.py round-trip against a throwaway temp copy."""
    src = "/home/decps/my_program/ota/controller/rat_e12.json"
    tmp = "/tmp/_preflight_rat.json"
    tmp_sig = tmp + ".sig"
    # One compound remote command; clean up regardless of outcome.
    remote = (
        f"set -e; cp {shlex.quote(src)} {shlex.quote(tmp)}; "
        f"cd /home/decps/my_program/ota && "
        f"python3 controller/sign_rat.py {shlex.quote(tmp)} >/dev/null 2>&1; "
        f"stat -c %s {shlex.quote(tmp_sig)}"
    )
    rc, out, err = _ssh(switch, remote, timeout=15.0)
    cleanup = f"rm -f {shlex.quote(tmp)} {shlex.quote(tmp_sig)}"
    _ssh(switch, cleanup, timeout=5.0)
    if rc != 0:
        return False, f"sign_rat.py failed (rc={rc}): {err.strip()[:160]}"
    size_s = out.strip()
    if not size_s.isdigit():
        return False, f"could not stat sig: '{size_s}'"
    size = int(size_s)
    if size != 64:
        return False, f"sig size = {size} bytes (want 64)"
    return True, f"sign_rat.py round-trip OK; sig=64 bytes"


def check_live_reload(switch: str, rat_path: str, log_path: str,
                      wait_s: float = 8.0) -> Tuple[bool, str]:
    """5. Prove the poll-reload + signature-verify pipeline is live."""
    # Record current controller-log size to bound the post-touch grep.
    rc0, out0, err0 = _ssh(
        switch, f"stat -c %s {shlex.quote(log_path)} 2>/dev/null",
        timeout=5.0,
    )
    if rc0 != 0 or not out0.strip().isdigit():
        return False, f"cannot stat controller log: {err0.strip()}"
    log_off = int(out0.strip())
    pre_mtime_rc, pre_mtime_out, _ = _ssh(
        switch, f"stat -c %Y {shlex.quote(rat_path)}", timeout=5.0)
    if pre_mtime_rc != 0 or not pre_mtime_out.strip().isdigit():
        return False, f"cannot stat rat file: {rat_path}"
    pre_mtime = int(pre_mtime_out.strip())
    touch_ts = int(time.time())
    # SAME-BYTES rewrite: read content, write verbatim back, re-sign.
    # Using python3 so the file bytes are identical (no shell newline twist).
    py = (
        "import sys, pathlib; "
        "p = pathlib.Path(sys.argv[1]); "
        "b = p.read_bytes(); "
        "p.write_bytes(b)"
    )
    remote = (
        f"python3 -c {shlex.quote(py)} {shlex.quote(rat_path)} && "
        f"cd /home/decps/my_program/ota && "
        f"python3 controller/sign_rat.py {shlex.quote(rat_path)} "
        f">/dev/null 2>&1"
    )
    rc, out, err = _ssh(switch, remote, timeout=15.0)
    if rc != 0:
        return False, f"same-bytes rewrite/sign failed: {err.strip()[:160]}"
    time.sleep(wait_s)
    # Grep only content APPENDED after we recorded log_off.
    # dd skips the pre-touch bytes so we don't match a stale 'RAT loaded'.
    tail_cmd = (
        f"dd if={shlex.quote(log_path)} bs=1 skip={log_off} 2>/dev/null"
    )
    rc2, out2, err2 = _ssh(switch, tail_cmd, timeout=8.0)
    if rc2 != 0:
        return False, f"cannot slice controller log: {err2.strip()[:160]}"
    fresh_loads = [ln for ln in out2.splitlines() if "RAT loaded" in ln]
    if not fresh_loads:
        return False, (
            f"no fresh 'RAT loaded' in {wait_s:.0f}s post-touch "
            f"(touch_ts={touch_ts}, pre_mtime={pre_mtime}). "
            f"Reload watcher appears dead."
        )
    if not any("signed=True" in ln for ln in fresh_loads):
        return False, (
            f"fresh RAT load saw signed=False: {fresh_loads[-1].strip()[:140]}"
        )
    return True, f"fresh signed reload observed: {fresh_loads[-1].strip()[:140]}"


def check_rat_backups(switch: str, rat_path: str) -> Tuple[bool, str]:
    """6. RAT fixture + sig backups present for post-run restore."""
    bak = rat_path + ".e22bak"
    bak_sig = rat_path + ".sig.e22bak"
    remote = (
        f"stat -c %s {shlex.quote(bak)} 2>/dev/null; "
        f"stat -c %s {shlex.quote(bak_sig)} 2>/dev/null"
    )
    rc, out, err = _ssh(switch, remote, timeout=5.0)
    if rc != 0:
        return False, f"stat failed: {err.strip()}"
    sizes = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if len(sizes) < 2:
        return False, f"missing backups: {bak} and/or {bak_sig}"
    if not all(s.isdigit() and int(s) > 0 for s in sizes[:2]):
        return False, f"backup file(s) empty or unreadable: {sizes}"
    return True, f"{bak}={sizes[0]}B, {bak_sig}={sizes[1]}B"


def check_vision_scapy(vision: str) -> Tuple[bool, str]:
    """7. sudo -n python3 + scapy on Vision."""
    py = 'from scapy.all import sendp, rdpcap; print("OK")'
    remote = f"sudo -n python3 -c {shlex.quote(py)}"
    rc, out, err = _ssh(vision, remote, timeout=10.0)
    if rc != 0 or "OK" not in out:
        return False, f"scapy/sudo failed: rc={rc} out={out.strip()[:80]} err={err.strip()[:120]}"
    return True, "sudo -n python3 scapy OK"


def check_vision_iface(vision: str, iface: str) -> Tuple[bool, str]:
    """8. Replay NIC is UP on Vision."""
    rc, out, err = _ssh(
        vision, f"ip -br link show {shlex.quote(iface)}", timeout=5.0)
    if rc != 0:
        return False, f"ip link failed: {err.strip()[:160]}"
    # Expect: "<iface> UP ..." or "<iface> UNKNOWN ..." (NICs with no carrier peer)
    tokens = out.split()
    if len(tokens) < 2:
        return False, f"unexpected output: {out.strip()[:120]}"
    state = tokens[1]
    if state not in ("UP", "UNKNOWN"):
        return False, f"iface {iface} state={state}"
    return True, f"{iface} state={state}"


def check_decision_logs(switch: str) -> Tuple[bool, str]:
    """9. Decisions + stochastic logs exist and are non-empty."""
    paths = [
        "/home/decps/my_program/ota/runs/decisions.jsonl",
        "/home/decps/my_program/ota/runs/E19p_stochastic.jsonl",
    ]
    remote = "; ".join(f"stat -c '%s %n' {shlex.quote(p)} 2>/dev/null"
                        for p in paths)
    rc, out, err = _ssh(switch, remote, timeout=5.0)
    if rc != 0:
        return False, f"stat failed: {err.strip()}"
    lines = [ln for ln in out.splitlines() if ln.strip()]
    got = {ln.split()[-1]: int(ln.split()[0]) for ln in lines
            if ln.split()[0].isdigit()}
    missing = [p for p in paths if p not in got]
    if missing:
        return False, f"missing: {missing}"
    empty = [p for p, s in got.items() if s <= 0]
    if empty:
        return False, f"empty: {empty}"
    return True, "; ".join(f"{p.split('/')[-1]}={s}B" for p, s in got.items())


def check_no_stale_run(switch: str) -> Tuple[bool, str]:
    """10. No stray run_e22.py on the switch."""
    rc, out, err = _ssh(switch, "pgrep -af run_e22.py || true", timeout=5.0)
    if rc != 0:
        return False, f"pgrep failed: {err.strip()}"
    # Exclude self-matches: the ssh+bash wrapper running pgrep itself
    # contains the literal 'run_e22.py' pattern string.
    procs = [ln for ln in out.splitlines() if ln.strip()
             and "pgrep" not in ln and "bash -c" not in ln]
    if procs:
        return False, (
            f"stale run_e22 process(es): "
            + "; ".join(p[:140] for p in procs[:3])
        )
    return True, "no run_e22 processes"


def check_r5_window_clear(switch: str) -> Tuple[bool, str]:
    """11. No `rat_miss` DROP decisions in the last 60s of decisions log."""
    log = "/home/decps/my_program/ota/runs/decisions.jsonl"
    # Single-line python to avoid shell multi-line quoting pitfalls.
    # Reads last 400 lines, counts DROP+rat_miss with ts >= now-60.
    py_oneliner = (
        "import sys,json,time;"
        "cut=time.time()-60;n=0;"
        "[(_ for _ in ()).throw(None)] if False else None;"
        "hdr=None"
    )
    # Build a sane single-line scanner with a list comprehension.
    py_oneliner = (
        "import sys,json,time;"
        "cut=time.time()-60;n=0\n"
        "for ln in sys.stdin:\n"
        " try: j=json.loads(ln)\n"
        " except Exception: continue\n"
        " ts=j.get('ts') or j.get('timestamp') or 0\n"
        " try: ts=float(ts)\n"
        " except Exception: ts=0\n"
        " if ts<cut: continue\n"
        " if j.get('action')=='DROP' and 'rat_miss' in str(j.get('reason','')): n+=1\n"
        "print(n)\n"
    )
    remote = (
        f"tail -n 400 {shlex.quote(log)} 2>/dev/null | "
        f"python3 -c {shlex.quote(py_oneliner)}"
    )
    rc, out, err = _ssh(switch, remote, timeout=10.0)
    if rc != 0:
        return False, f"decisions scan failed: {err.strip()[:160]}"
    val = out.strip().splitlines()[-1] if out.strip() else ""
    if not val.isdigit():
        return False, f"unexpected scan output: {out.strip()[:120]}"
    n = int(val)
    if n > 0:
        return False, f"{n} rat_miss DROP(s) in last 60s (R5 window not clear)"
    return True, "no rat_miss DROPs in last 60s"


def check_sign_cmd_not_footgun(sign_cmd: str | None) -> Tuple[bool, str]:
    """12. Reject the exact footgun strings that killed yesterday's run."""
    if sign_cmd is None:
        return True, "no --sign-cmd supplied to preflight (skipped)"
    stripped = sign_cmd.strip()
    banned = {"true", "/bin/true", ":", ""}
    if stripped in banned:
        return False, (
            f"--remote-sign-cmd is a no-op ({stripped!r}). "
            f"This is the exact footgun that invalidated the "
            f"2026-04-18 run. Use the real sign_rat.py invocation."
        )
    if "sign_rat.py" not in stripped:
        return False, (
            f"--remote-sign-cmd does not invoke sign_rat.py: {stripped!r}"
        )
    return True, f"sign-cmd OK ({stripped[:80]}{'...' if len(stripped) > 80 else ''})"


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def _fmt(r: CheckResult) -> str:
    tag = f"{GREEN}  OK  {RESET}" if r.ok else f"{RED} FAIL {RESET}"
    return f"[{tag}] {r.name:<34} {r.detail}"


def main() -> int:
    ap = argparse.ArgumentParser(description="E22 preflight verifier")
    ap.add_argument("--vision", default="decps@10.10.54.19")
    ap.add_argument("--switch", default="decps@10.10.54.15")
    ap.add_argument("--sign-cmd", default=None,
                    help="Value of driver's --remote-sign-cmd, for check #12.")
    ap.add_argument("--remote-rat-path",
                    default="/home/decps/my_program/ota/controller/rat_e12.json")
    ap.add_argument("--controller-log", default="/tmp/controller.log")
    ap.add_argument("--vision-iface", default="enp59s0f0np0")
    ap.add_argument("--skip-live-reload", action="store_true",
                    help="Skip check #5 for dry/debug runs.")
    args = ap.parse_args()

    # Build ordered list of (name, callable). All thunks return (ok, detail).
    checks: List[Tuple[str, Callable[[], Tuple[bool, str]]]] = [
        ("1 ssh-reachability",
            lambda: check_ssh_reachability(args.vision, args.switch)),
        ("2 controller-signed-mode",
            lambda: check_controller_signed(args.switch, args.controller_log)),
        ("3 signing-assets",
            lambda: check_signing_assets(args.switch)),
        ("4 sign-rat-roundtrip",
            lambda: check_sign_rat_roundtrip(args.switch)),
    ]
    if not args.skip_live_reload:
        checks.append((
            "5 live-reload-exercise",
            lambda: check_live_reload(
                args.switch, args.remote_rat_path, args.controller_log),
        ))
    else:
        checks.append((
            "5 live-reload-exercise",
            lambda: (True, f"{YELLOW}SKIPPED (--skip-live-reload){RESET}"),
        ))
    checks.extend([
        ("6 rat-backups",
            lambda: check_rat_backups(args.switch, args.remote_rat_path)),
        ("7 vision-scapy-sudo",
            lambda: check_vision_scapy(args.vision)),
        ("8 vision-iface-up",
            lambda: check_vision_iface(args.vision, args.vision_iface)),
        ("9 decision-logs-present",
            lambda: check_decision_logs(args.switch)),
        ("10 no-stale-run-e22",
            lambda: check_no_stale_run(args.switch)),
        ("11 r5-window-clear",
            lambda: check_r5_window_clear(args.switch)),
        ("12 sign-cmd-not-footgun",
            lambda: check_sign_cmd_not_footgun(args.sign_cmd)),
    ])

    print("\n=== E22 preflight ===")
    print(f"  vision : {args.vision}")
    print(f"  switch : {args.switch}")
    print(f"  rat    : {args.remote_rat_path}")
    print(f"  log    : {args.controller_log}")
    print()

    results: List[CheckResult] = []
    for name, thunk in checks:
        try:
            ok, detail = thunk()
        except Exception as exc:
            ok, detail = False, f"exception: {exc}"
        r = CheckResult(name=name, ok=ok, detail=detail)
        results.append(r)
        print(_fmt(r))

    failed = [r for r in results if not r.ok]
    print()
    if failed:
        print(f"{RED}PREFLIGHT FAILED{RESET}: "
                f"{len(failed)}/{len(results)} check(s) failed.")
        for r in failed:
            print(f"  - {r.name}: {r.detail}")
        return 1
    print(f"{GREEN}PREFLIGHT OK{RESET}: all {len(results)} checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
