"""E12b preflight verifier.

Refuses to run the E12b signed-manifest rerun unless the bench is in a
state where the experiment measures something real. Core danger: if the
controller is running WITHOUT ``--require-signed-rat`` (i.e.
``allow_unsigned=True``, as observed on PID 496904 at the time this was
written), every trial trivially "passes" and the paper claim is false.

Exit 0 => proceed, non-zero => abort. Stdlib only. Each check returns
``(ok, detail)``. Run::

    python3 experiments/preflight_e12b.py --vision V --switch S

``--safe`` skips the destructive negative test (#8). ``--skip-preflight``
bypasses entirely (USE WITH CARE).
"""

from __future__ import annotations

import argparse
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, List, Tuple

CheckResult = Tuple[bool, str]
REPO_ROOT = Path(__file__).resolve().parent.parent
RESTART_CMD = (
    "python3 controller/ota_shield_controller.py "
    "--grpc-addr 127.0.0.1:50052 --p4-name ota_shield "
    "--rat controller/rat_e12.json --log runs/E19p_stochastic.jsonl "
    "--rat-pub controller/rat.pub --rat-sig controller/rat_e12.json.sig "
    "--require-signed-rat"
)


def _run(cmd: str, *, timeout: float = 10.0) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          timeout=timeout)


def _ssh(host: str, remote: str, *, timeout: float = 10.0
         ) -> subprocess.CompletedProcess:
    return _run(
        "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "
        f"-o BatchMode=yes {host} {shlex.quote(remote)}",
        timeout=timeout,
    )


def _pid(switch: str, hint: int | None) -> Tuple[int | None, str]:
    if hint:
        r = _ssh(switch, f"test -d /proc/{hint} && echo y || echo n")
        if "y" in (r.stdout or ""):
            return hint, f"hinted pid {hint}"
    r = _ssh(switch, "pgrep -af 'python3 .*ota_shield_controller.py' | head -1")
    line = (r.stdout or "").strip()
    if not line:
        return None, "no ota_shield_controller.py process"
    try:
        return int(line.split()[0]), f"found pid {line.split()[0]}"
    except Exception:
        return None, f"could not parse pid: {line}"


# 1
def c_ssh(vision: str, switch: str) -> CheckResult:
    try:
        r1 = _ssh(switch, "echo ok", timeout=5)
        r2 = _ssh(vision, "echo ok", timeout=5)
    except subprocess.TimeoutExpired:
        return False, "ssh >5s"
    if r1.returncode: return False, f"switch: {r1.stderr.strip()}"
    if r2.returncode: return False, f"vision: {r2.stderr.strip()}"
    return True, "switch + vision reachable"


# 2 - KILL SWITCH
def c_signed_mode(switch: str, hint: int | None) -> CheckResult:
    pid, _ = _pid(switch, hint)
    if pid is None: return False, "no controller pid"
    r = _ssh(switch, f"tr '\\0' ' ' < /proc/{pid}/cmdline; echo")
    if r.returncode:
        return False, f"/proc/{pid}/cmdline read failed"
    cmd = (r.stdout or "").strip()
    missing = [f for f in ("--require-signed-rat", "--rat-pub", "--rat-sig")
               if f not in cmd]
    if missing:
        return False, (
            f"pid {pid} MISSING {missing}. allow_unsigned=True - E12b "
            f"would be meaningless.\n  cmdline: {cmd[:180]}\n"
            f"  Restart with:\n    {RESTART_CMD}"
        )
    return True, f"pid {pid} has all three flags"


# 3
def c_m6_code(switch: str, hint: int | None) -> CheckResult:
    pid, _ = _pid(switch, hint)
    if pid is None: return False, "no controller pid"
    r = _ssh(switch, f"stat -c %Y /proc/{pid}")
    try: started = int((r.stdout or "0").strip())
    except ValueError: return False, f"cannot stat /proc/{pid}"
    r = _ssh(switch, f"readlink /proc/{pid}/cwd")
    cwd = (r.stdout or "").strip()
    if not cwd: return False, "cannot read controller cwd"
    lp = f"{cwd}/controller/rat_lifecycle.py"
    r = _ssh(switch, f"stat -c %Y {shlex.quote(lp)}")
    try: mtime = int((r.stdout or "0").strip())
    except ValueError: return False, f"cannot stat {lp}"
    if mtime > started:
        return False, (f"{lp} modified after controller start "
                       f"({mtime}>{started}); restart to load M6.")
    r = _ssh(switch,
             f"grep -cE 'def reload\\(|start_watcher' {shlex.quote(lp)}")
    try: n = int((r.stdout or "0").strip())
    except ValueError: n = 0
    if n < 2:
        return False, f"{lp} missing reload()/start_watcher (n={n}); not M6"
    return True, f"M6 code loaded (mtime {mtime} < start {started})"


# 4
def c_key(switch: str) -> CheckResult:
    key = "/home/decps/.ota_shield/rat_signing.key"
    r = _ssh(switch, f"stat -c '%a %U' {shlex.quote(key)}")
    if r.returncode: return False, f"{key} missing"
    parts = (r.stdout or "").strip().split()
    if not parts or parts[0] != "600":
        return False, f"{key} perms {parts}, expected 600"
    return True, f"{key} perm 600"


# 5
def c_rat_pub(repo: Path) -> CheckResult:
    pub = repo / "controller" / "rat.pub"
    if not pub.exists(): return False, f"{pub} missing"
    raw = pub.read_bytes()
    if len(raw) == 32: return True, f"{pub} 32 raw bytes"
    try:
        b = bytes.fromhex(raw.decode("ascii").strip())
    except (UnicodeDecodeError, ValueError):
        return False, f"{pub} {len(raw)}B, not 32 raw and not hex"
    if len(b) != 32:
        return False, f"{pub} hex decodes to {len(b)}B, expected 32"
    return True, f"{pub} valid (32B hex)"


# 6
def c_sig_verify(switch: str, hint: int | None) -> CheckResult:
    pid, _ = _pid(switch, hint)
    if pid is None: return False, "no controller pid"
    r = _ssh(switch, f"readlink /proc/{pid}/cwd")
    cwd = (r.stdout or "").strip() or "."
    py = (
        "from pathlib import Path\n"
        "try: from nacl.signing import VerifyKey\n"
        "except ImportError: print('NO_PYNACL'); raise SystemExit(2)\n"
        "p=Path('controller/rat.pub').read_bytes()\n"
        "if len(p)!=32:\n"
        " p=bytes.fromhex(p.decode().strip())\n"
        "s=Path('controller/rat_e12.json.sig').read_bytes()\n"
        "m=Path('controller/rat_e12.json').read_bytes()\n"
        "VerifyKey(p).verify(m,s); print('OK')\n"
    )
    r = _ssh(switch, f"cd {shlex.quote(cwd)} && python3 -c {shlex.quote(py)}",
             timeout=15)
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    if "OK" in out: return True, "rat_e12.json.sig verifies"
    if "NO_PYNACL" in out: return False, "pynacl not installed on switch"
    return False, f"sig verify failed: {out[-160:]}"


# 7
def c_signed_load_log(switch: str,
                      log: str = "/tmp/controller.log") -> CheckResult:
    r = _ssh(switch, f"grep 'RAT loaded:' {shlex.quote(log)} | tail -n 5")
    lines = [ln for ln in (r.stdout or "").splitlines() if ln.strip()]
    if not lines:
        return False, f"no 'RAT loaded:' line in {log}"
    last = lines[-1]
    if "signed=True" not in last:
        return False, f"last load shows signed=False: {last[:160]}"
    return True, f"startup signed=True: {last[-100:]}"


# 8
def c_negative(switch: str, safe: bool,
               log: str = "/tmp/controller.log") -> CheckResult:
    if safe:
        return True, ("SKIPPED (--safe); per-trial sig injection in "
                      "run_e12b is still the real test.")
    script = (
        "set -e\n"
        "cd /home/decps/my_program/ota\n"
        "ORIG=controller/rat_e12.json; SIG=controller/rat_e12.json.sig\n"
        "BK=/tmp/_pf_rat.bak; SBK=/tmp/_pf_sig.bak\n"
        "cp $ORIG $BK; cp $SIG $SBK\n"
        "OFFS=$(wc -c < /tmp/controller.log 2>/dev/null || echo 0)\n"
        "python3 -c \"import json,pathlib;p=pathlib.Path('$ORIG');"
        "d=json.loads(p.read_text());d['_pf_probe']=1;"
        "p.write_text(json.dumps(d))\"\n"
        # Poll-path cadence is 5s (inotify fallback); give a full cycle
        # + slack before restoring, else the reject window closes first.
        "sleep 8\n"
        "mv $BK $ORIG; mv $SBK $SIG\n"
        "sleep 6\n"
        "tail -c +$((OFFS+1)) /tmp/controller.log\n"
    )
    r = _ssh(switch, script, timeout=35)
    out = r.stdout or ""
    if "RAT reload REJECTED" not in out:
        return False, (
            "no 'RAT reload REJECTED' after tamper; sig not enforced.\n"
            f"  tail:\n{out[-400:]}"
        )
    return True, "tampered reload was rejected"


# 9
def c_dispatch(repo: Path) -> CheckResult:
    rt = repo / "experiments" / "run_trial.py"
    if not rt.exists(): return False, f"{rt} missing"
    if "pack_benign_rollout_signed" not in rt.read_text():
        return False, (f"{rt} has no pack_benign_rollout_signed; "
                       "dispatch fix missing")
    return True, "pack_benign_rollout_signed wired"


# 10
def c_numbers_tex(repo: Path) -> CheckResult:
    tex = repo / "paper" / "numbers.tex"
    if not tex.exists():
        return True, f"{tex} absent (aggregator creates fresh)"
    conflicts = [ln for ln in tex.read_text().splitlines()
                 if "\\newcommand" in ln and "EOneTwobsigned" in ln]
    if conflicts:
        return False, (f"{tex} has {len(conflicts)} EOneTwobsigned* "
                       f"macros; would collide. First: {conflicts[0][:100]}")
    return True, "no EOneTwobsigned* macros in numbers.tex"


# 11
def c_no_compete(switch: str) -> CheckResult:
    # Use ps and filter on the actual executable + first arg so we don't
    # self-match bash wrappers, CLI tools, or the orchestrator's own parent
    # shell. "Competing" means: a DIFFERENT python running run_e7b/22/12{b}.py
    # whose pid is not an ancestor of this preflight.
    me_ancestors = set()
    try:
        pid = Path("/proc/self").resolve().name
        while pid and pid != "0":
            me_ancestors.add(pid)
            stat = Path(f"/proc/{pid}/status").read_text().splitlines()
            ppid = next((ln.split()[1] for ln in stat
                         if ln.startswith("PPid:")), "0")
            pid = ppid if ppid != pid else "0"
    except OSError:
        pass
    pat = r'^\s*[0-9]+ python[0-9.]* \S*run_e(7b|22|12b|12)\.py'
    fmt = "ps -eo pid=,args= | awk '{print}'"
    local = _run(f"{fmt} | grep -E '{pat}' || true")
    rem = _ssh(switch, f"{fmt} | grep -E '{pat}' || true")
    busy: List[str] = []
    for src, is_local in ((local.stdout, True), (rem.stdout, False)):
        for ln in (src or "").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            pid0 = ln.split()[0]
            if is_local and pid0 in me_ancestors:
                continue
            busy.append(ln)
    if busy:
        return False, f"competing run: {busy[:2]}"
    return True, "no competing run_e7b/e22/e12 processes"


# 12
def c_decisions(switch: str) -> CheckResult:
    p = "runs/E19p_stochastic.jsonl"
    r = _ssh(switch, f"test -e {p} && test -w {p} && echo ok || echo no")
    if "ok" not in (r.stdout or ""):
        return False, f"{p} missing or not writable on switch"
    return True, f"{p} writable (offset-slice ok)"


# 13
def c_scapy_sudo(vision: str) -> CheckResult:
    r = _ssh(vision,
             "sudo -n python3 -c 'import scapy.all;print(\"OK\")' 2>&1",
             timeout=10)
    out = (r.stdout or "") + (r.stderr or "")
    if "OK" in out and "password" not in out.lower():
        return True, "sudo -n + scapy ok"
    return False, f"vision sudo/scapy failed: {out.strip()[:160]}"


# 14
def c_iface(vision: str) -> CheckResult:
    r = _ssh(vision,
             "ip -br link | awk '$2==\"UP\"{print $1}' | grep -v '^lo$' | head")
    ifs = [ln for ln in (r.stdout or "").splitlines() if ln.strip()]
    if not ifs: return False, "no non-lo iface UP"
    return True, f"iface UP: {','.join(ifs[:3])}"


# 15
def c_signop(repo: Path) -> CheckResult:
    sign = repo / "controller" / "sign_rat.py"
    rat = repo / "controller" / "rat_e12.json"
    if not sign.exists() or not rat.exists():
        return False, "sign_rat.py or rat_e12.json missing"
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        shutil.copy(rat, tdp / "rat.json")
        cmd = f"python3 {shlex.quote(str(sign))} {shlex.quote(str(tdp/'rat.json'))}"
        _run(cmd)
        src = tdp / "rat.json.sig"
        if not src.exists():
            return True, ("sign_rat.py not locally runnable (key on "
                          "switch only); idempotency unverified here.")
        b1 = src.read_bytes()
        src.unlink()
        _run(cmd)
        if not src.exists():
            return False, "second sign_rat.py run produced no .sig"
        b2 = src.read_bytes()
    if b1 != b2:
        return False, "sign_rat.py non-deterministic; ed25519 install broken"
    return True, f"sig identical across 2 runs ({len(b1)}B)"


# 16 - Step-0 (2026-04-20): ASIC-register readback. Closes the state-bleed
# pattern where handle_reset claimed success but R6/R5/override rows stayed
# dirty from prior experiments, silently producing DROPs at bms_idx=0.
def c_state_readback(switch: str, hint: int | None) -> CheckResult:
    pid, how = _pid(switch, hint)
    if pid is None:
        return False, "no controller pid (cannot SIGUSR1/2)"
    script = REPO_ROOT / "experiments" / "preflight_state_check.py"
    if not script.exists():
        return False, f"{script} missing"
    cmd = [
        "python3", str(script),
        "--switch", switch,
        "--controller-pid", str(pid),
        "--require-signed",
        "--expected-rat-entries", "3",
        "--expected-rollback-window-entries", "0",
        "--quiet",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return False, "preflight_state_check.py >30s"
    if r.returncode == 0:
        return True, f"R6/R5/override clean; RAT signed (pid {pid}, {how})"
    tail = ((r.stderr or "") + (r.stdout or "")).strip().splitlines()
    detail = "; ".join(tail[-6:]) if tail else "unknown failure"
    return False, f"rc={r.returncode}: {detail[:400]}"


def _row(name: str, ok: bool, detail: str) -> str:
    tag = "PASS" if ok else "FAIL"
    return f"  [{tag}] {name:<38}  {detail}"


def run_preflight(args: argparse.Namespace) -> int:
    checks: List[Tuple[str, Callable[[], CheckResult]]] = [
        ("1  ssh reachability", lambda: c_ssh(args.vision, args.switch)),
        ("2  --require-signed-rat in cmdline",
            lambda: c_signed_mode(args.switch, args.controller_pid_hint)),
        ("3  M6 rat_lifecycle.py loaded",
            lambda: c_m6_code(args.switch, args.controller_pid_hint)),
        ("4  signing key 600 on switch", lambda: c_key(args.switch)),
        ("5  rat.pub valid", lambda: c_rat_pub(REPO_ROOT)),
        ("6  rat sig verifies on switch",
            lambda: c_sig_verify(args.switch, args.controller_pid_hint)),
        ("7  startup signed=True in log",
            lambda: c_signed_load_log(args.switch)),
        ("8  tampered reload rejected",
            lambda: c_negative(args.switch, args.safe)),
        ("9  scenario dispatch wired", lambda: c_dispatch(REPO_ROOT)),
        ("10 numbers.tex namespace free", lambda: c_numbers_tex(REPO_ROOT)),
        ("11 no competing run_* process",
            lambda: c_no_compete(args.switch)),
        ("12 decisions baseline writable",
            lambda: c_decisions(args.switch)),
        ("13 vision scapy + NOPASSWD sudo",
            lambda: c_scapy_sudo(args.vision)),
        ("14 vision iface up", lambda: c_iface(args.vision)),
        ("15 sign_rat.py idempotent", lambda: c_signop(REPO_ROOT)),
        ("16 ASIC state clean (SIGUSR1+USR2 readback)",
            lambda: c_state_readback(args.switch, args.controller_pid_hint)),
    ]
    print("=" * 72)
    print(f"E12b preflight  vision={args.vision}  switch={args.switch}  "
          f"safe={args.safe}")
    print("-" * 72)
    results: List[Tuple[str, bool, str]] = []
    for name, fn in checks:
        try:
            ok, detail = fn()
        except subprocess.TimeoutExpired:
            ok, detail = False, "timed out"
        except Exception as exc:  # noqa: BLE001
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        results.append((name, ok, detail))
        print(_row(name, ok, detail))
    print("-" * 72)
    failed = [r for r in results if not r[1]]
    if failed:
        print(f"{len(failed)}/{len(results)} FAILED. E12b aborted.\n")
        for name, _, detail in failed:
            print(f"!! {name}")
            for ln in detail.splitlines():
                print(f"     {ln}")
        if any(n.startswith("2 ") and not ok for n, ok, _ in results):
            print("\nKILL-SWITCH: restart the controller in signed mode:\n")
            print(f"    {RESTART_CMD}\n")
        return 2
    print(f"All {len(results)} checks passed. Proceed with E12b.")
    return 0


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--vision", required=True)
    ap.add_argument("--switch", required=True)
    ap.add_argument("--controller-pid-hint", type=int, default=None)
    ap.add_argument("--safe", action="store_true",
                    help="skip destructive negative test (#8)")
    ap.add_argument("--skip-preflight", action="store_true",
                    help="bypass preflight entirely (USE WITH CARE)")
    args = ap.parse_args(argv)
    if args.skip_preflight:
        print("[preflight] skipped by --skip-preflight")
        return 0
    return run_preflight(args)


if __name__ == "__main__":
    sys.exit(main())
