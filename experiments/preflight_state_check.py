"""Step-0 preflight state-check (2026-04-20).

Verifies that the controller's post-reset invariants actually hold on
the switch ASIC before any trial launches traffic. This closes the
"handle_reset claimed success, registers dirty, downstream DROPs"
pattern that has cost multiple nights of wall-clock.

Contract
    1. ssh <switch> kill -USR1 <controller_pid>   # trigger reset
    2. sleep <reset_wait_s>                       # ~4 s for session regs
    3. ssh <switch> kill -USR2 <controller_pid>   # dump state to /tmp
    4. scp the dump back
    5. Assert invariants (R6==0, R5 count==0, R5 bloom==0, override
       table empty, _last_reset_errors empty, rat loaded+signed).
    6. Exit 0 if all green; non-zero with a mismatches JSON on stderr
       otherwise. Fail-closed.

Usage:
    python3 experiments/preflight_state_check.py \\
        --switch decps@10.10.54.15 \\
        --controller-pid 693288 \\
        [--remote-dump /tmp/ota_controller_state.json] \\
        [--require-signed] \\
        [--expected-rat-entries 3] \\
        [--expected-rollback-window-entries 0] \\
        [--reset-wait-s 4.0] [--dump-wait-s 2.0]

Exit codes:
    0  — all invariants hold
    2  — a reset step failed (controller-side)
    3  — a post-reset invariant is violated (ASIC state dirty)
    4  — RPC / SSH / file I/O failure
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def _ssh(host: str, cmd: str, *, check: bool = True,
         capture: bool = True) -> subprocess.CompletedProcess:
    full = f"ssh -o StrictHostKeyChecking=no {host} {shlex.quote(cmd)}"
    return subprocess.run(full, shell=True, check=check,
                          capture_output=capture, text=True)


def _scp(src: str, dst: str) -> None:
    subprocess.run(
        f"scp -q -o StrictHostKeyChecking=no {src} {dst}",
        shell=True, check=True, capture_output=True, text=True)


def check(switch: str, controller_pid: int, remote_dump: str,
          *, reset_wait_s: float, dump_wait_s: float,
          require_signed: bool,
          expected_rat_entries: int | None,
          expected_rollback_window_entries: int | None,
          skip_reset: bool = False) -> tuple[int, dict]:
    # 1. Trigger reset (unless caller is only verifying post-startup).
    if not skip_reset:
        try:
            _ssh(switch, f"sudo -n kill -USR1 {controller_pid}")
        except subprocess.CalledProcessError as exc:
            return 4, {"stage": "sigusr1", "err": str(exc)}
        time.sleep(reset_wait_s)
    # 2. Trigger dump.
    try:
        _ssh(switch, f"sudo -n kill -USR2 {controller_pid}")
    except subprocess.CalledProcessError as exc:
        return 4, {"stage": "sigusr2", "err": str(exc)}
    time.sleep(dump_wait_s)
    # 3. Pull dump.
    with tempfile.TemporaryDirectory() as td:
        local = Path(td) / "state.json"
        try:
            _scp(f"{switch}:{remote_dump}", str(local))
            dump = json.loads(local.read_text())
        except Exception as exc:  # noqa: BLE001
            return 4, {"stage": "scp", "err": repr(exc)}
    # 4. Assertions.
    violations: list[str] = []
    # 4a. Reset errors (hard fail).
    reset_errs = dump.get("reset_errors") or []
    if reset_errs:
        violations.append(f"reset_errors: {reset_errs}")
    # 4b. R6 must be all-zero.
    r6 = dump.get("r6_max_version") or {}
    if isinstance(r6, dict) and r6.get("error"):
        violations.append(f"r6_read_error: {r6['error']}")
    else:
        nz = r6.get("slots_nonzero", 0)
        if nz:
            violations.append(
                f"r6_slots_nonzero={nz} sample={r6.get('nonzero_sample')}")
    # 4c. R5 count must be zero.
    r5c = dump.get("r5_count")
    if isinstance(r5c, dict) and r5c.get("error"):
        violations.append(f"r5_count_read_error: {r5c['error']}")
    elif r5c not in (0, None):
        violations.append(f"r5_count={r5c}")
    # 4d. R5 bloom must be zero.
    bloom = dump.get("r5_bloom_nonzero", 0)
    if isinstance(bloom, dict) and bloom.get("error"):
        violations.append(f"r5_bloom_read_error: {bloom['error']}")
    elif bloom:
        violations.append(f"r5_bloom_nonzero={bloom}")
    # 4e. Override table must be empty.
    ov = dump.get("session_override_count", 0)
    if isinstance(ov, dict) and ov.get("error"):
        violations.append(f"override_read_error: {ov['error']}")
    elif ov:
        violations.append(f"session_override_count={ov}")
    # 4f. RAT invariants.
    rat = dump.get("rat") or {}
    if isinstance(rat, dict) and rat.get("error"):
        violations.append(f"rat_read_error: {rat['error']}")
    else:
        if require_signed and not rat.get("signed", False):
            violations.append(f"rat_signed={rat.get('signed')}")
        if expected_rat_entries is not None:
            actual = rat.get("entries")
            if actual != expected_rat_entries:
                violations.append(
                    f"rat_entries: got {actual}, want {expected_rat_entries}")
        if expected_rollback_window_entries is not None:
            actual = rat.get("rollback_window_entries")
            if actual != expected_rollback_window_entries:
                violations.append(
                    "rat_rollback_window_entries: "
                    f"got {actual}, want {expected_rollback_window_entries}")
    if reset_errs:
        return 2, {"violations": violations, "dump": dump}
    if violations:
        return 3, {"violations": violations, "dump": dump}
    return 0, {"dump": dump}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--switch", required=True,
                    help="ssh target for the switch (decps@10.10.54.15)")
    ap.add_argument("--controller-pid", type=int, required=True)
    ap.add_argument("--remote-dump",
                    default="/tmp/ota_controller_state.json")
    ap.add_argument("--reset-wait-s", type=float, default=4.0,
                    help="seconds to wait after SIGUSR1 before SIGUSR2 "
                         "(session_bytes clear is ~30s; tune per experiment)")
    ap.add_argument("--dump-wait-s", type=float, default=2.0)
    ap.add_argument("--require-signed", action="store_true",
                    help="fail if rat.signed != True")
    ap.add_argument("--expected-rat-entries", type=int, default=None)
    ap.add_argument("--expected-rollback-window-entries", type=int,
                    default=None)
    ap.add_argument("--skip-reset", action="store_true",
                    help="only dump + assert; useful right after a fresh "
                         "controller startup since startup already resets")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    rc, result = check(
        switch=args.switch,
        controller_pid=args.controller_pid,
        remote_dump=args.remote_dump,
        reset_wait_s=args.reset_wait_s,
        dump_wait_s=args.dump_wait_s,
        require_signed=args.require_signed,
        expected_rat_entries=args.expected_rat_entries,
        expected_rollback_window_entries=args.expected_rollback_window_entries,
        skip_reset=args.skip_reset,
    )
    if rc == 0:
        if not args.quiet:
            print("[preflight_state_check] OK:",
                  json.dumps(result["dump"], indent=2, default=str))
        return 0
    print(f"[preflight_state_check] FAIL rc={rc}", file=sys.stderr)
    print(json.dumps(result, indent=2, default=str), file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
