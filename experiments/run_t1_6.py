"""T1.6 R6-poisoning smoke driver — wires r6_poison.py on Vision into TrialRunner.

Reads experiments/configs/T1_6.yaml, deploys traffic_gen to Vision, runs the
generator from Vision via SSH for the trial duration, and uses TrialRunner
to bracket the trial with preflight + integrity + manifest.

The post-trial check inspects r6_bms_max_version_reg directly: post-fix the
malicious v=0xDEADBEEF MUST NOT be stored (gated by r2_fired); the legitimate
v=49 SHOULD be stored. If the register holds 0xDEADBEEF after the run, the
patch failed and the experiment is reported as falsifier-triggered.
"""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from experiments.trial_runner import TrialConfig, TrialRunner  # noqa: E402

SWITCH = "decps@10.10.54.15"
VISION = "decps@10.10.54.19"  # Vision management IP (eno1)
SSHPASS = os.environ.get("OTA_SSHPASS", "")
if not SSHPASS:
    raise RuntimeError("OTA_SSHPASS env var not set; refuse to fall back to a literal credential")
POISON_VAL = 0xDEADBEEF


def _ssh(host: str, cmd: str, timeout: int = 60) -> tuple[int, str]:
    """Run a command over SSH. Returns (returncode, stdout+stderr)."""
    full = ["sshpass", "-p", SSHPASS, "ssh",
            "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
            host, cmd]
    p = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


def deploy_to_vision() -> None:
    """rsync traffic_gen + a minimal launcher to Vision."""
    print("[deploy] copying traffic_gen to Vision...")
    cmd = ["sshpass", "-p", SSHPASS, "scp", "-o", "StrictHostKeyChecking=no",
           "-r", str(REPO / "traffic_gen"), f"{VISION}:/home/decps/"]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    print("[deploy] OK")


def dump_r6_register() -> dict[int, int]:
    """Read pipe.Ingress.r6.r6_bms_max_version_reg from the switch."""
    py = (
        'import os, sys; '
        'S="/home/decps/Downloads/bf-sde-9.13.2/install"; '
        'sys.path.insert(0, S+"/lib/python3.8/site-packages/tofino"); '
        'sys.path.insert(0, S+"/lib/python3.8/site-packages"); '
        'import bfrt_grpc.client as gc; '
        'i=gc.ClientInterface("localhost:50052",client_id=3,device_id=0); '
        'i.bind_pipeline_config("ota_shield"); '
        'b=i.bfrt_info_get("ota_shield"); t=gc.Target(device_id=0); '
        't_reg=b.table_get("pipe.Ingress.r6.r6_bms_max_version_reg"); '
        'DOL=chr(36); '
        'ks=[t_reg.make_key([gc.KeyTuple(DOL+"REGISTER_INDEX", j)]) for j in range(64)]; '
        'for j,(d,k) in enumerate(t_reg.entry_get(t,ks,{"from_hw":True})): '
        '    dd=d.to_dict(); '
        '    v=[v for kn,v in dd.items() if kn != DOL+"REGISTER_INDEX"][0]; '
        '    val = v[0] if isinstance(v,list) and v else (v if isinstance(v,int) else 0); '
        '    print(f"{j}:{val}"); '
        'i.tear_down_stream()'
    )
    cmd = (f"echo {shlex.quote(SSHPASS)} | sudo -S env "
           "SDE_INSTALL=/home/decps/Downloads/bf-sde-9.13.2/install "
           f"python3 -c {shlex.quote(py)} 2>/dev/null | tail -100")
    rc, out = _ssh(SWITCH, cmd, timeout=30)
    if rc != 0:
        print(f"[reg] dump failed (rc={rc}): {out[:200]}")
        return {}
    result = {}
    for line in out.strip().splitlines():
        if ":" in line and line.split(":")[0].strip().isdigit():
            idx_s, val_s = line.split(":", 1)
            try:
                result[int(idx_s)] = int(val_s)
            except ValueError:
                pass
    return result


def reset_controller_state() -> None:
    """SIGUSR1 the OTA controller to clear DP + override + R5/R6 registers.

    Resolves the python process explicitly (NOT a bash launcher whose
    cmdline merely contains the string 'ota_shield_controller.py'); a
    SIGUSR1 to the bash wrapper would be a no-op, leaving registers
    dirty across trials.
    """
    cmd = (
        "PID=$(ps -eo pid,comm,cmd --no-headers | "
        "awk '$2 ~ /^python/ && $0 ~ /controller\\/ota_shield_controller\\.py/ "
        "{print $1; exit}'); "
        "if [ -n \"$PID\" ]; then "
        f"echo {shlex.quote(SSHPASS)} | sudo -S -p '' kill -USR1 $PID; "
        "echo \"sent SIGUSR1 to $PID (python controller)\"; "
        "else echo no controller python process found; fi"
    )
    rc, out = _ssh(SWITCH, cmd, timeout=10)
    print(f"[reset] {out.strip()[:160]}")
    time.sleep(3)


def run_r6_poison_on_vision(params: dict[str, Any], duration_s: float,
                            trial_dir: Path) -> int:
    """Invoke r6_poison.py on Vision and pull back ground_truth.jsonl.

    F1 fix: full stdout+stderr is captured to {trial_dir}/r6_poison.stdout.log
    rather than truncated through `tail -8`. A fixed marker line lets the PI
    grep for an unambiguous success signal.
    F3 fix: pass --out-dir on Vision so r6_poison writes ground_truth.jsonl,
    then scp it back into trial_dir for the aggregator.
    """
    args = (
        f"--iface enp59s0f0np0 "
        f"--src-unauth {params.get('unauthorized_src_ip', '10.0.99.99')} "
        f"--src-legit {params.get('legitimate_src_ip', '10.0.1.10')} "
        f"--target {params.get('target_bms_ip', '10.0.2.10')} "
        f"--gap {params.get('gap_seconds', 60)} "
        f"--legit-version {params.get('legitimate_version', 49)} "
        f"--poison-version-hex {params.get('poison_version_hex', 'DEADBEEF')} "
        f"--out-dir /tmp/t1_6_gt"
    )
    remote_dir = "/tmp/t1_6_gt.$$"
    remote_log = "/tmp/r6_poison.$$.log"
    pw = shlex.quote(SSHPASS)
    cmd = (
        f"cd /home/decps; "
        f"echo {pw} | sudo -S -p '' rm -rf {remote_dir} >/dev/null 2>&1; "
        f"mkdir -p {remote_dir}; "
        f"(echo {pw} | sudo -S -p '' "
        f"python3 -m traffic_gen.r6_poison {args.replace('/tmp/t1_6_gt', remote_dir)}) "
        f">{remote_log} 2>&1; rc=$?; "
        f"echo MARKER_R6_POISON_DONE rc=$rc; "
        f"cat {remote_log} 2>/dev/null; "
        f"echo {pw} | sudo -S -p '' chmod 644 {remote_dir}/ground_truth.jsonl 2>/dev/null; "
        f"echo REMOTE_GT_PATH={remote_dir}/ground_truth.jsonl; "
        f"echo {pw} | sudo -S -p '' rm -f {remote_log} >/dev/null 2>&1; "
        f"exit $rc"
    )
    print(f"[vision] launching r6_poison: {args}")
    rc, out = _ssh(VISION, cmd, timeout=int(duration_s + 30))

    log_path = trial_dir / "r6_poison.stdout.log"
    log_path.write_text(out)
    if "MARKER_R6_POISON_DONE rc=0" in out:
        print(f"[vision] r6_poison rc={rc} (marker OK); full log -> {log_path}")
    else:
        print(f"[vision] r6_poison rc={rc} (NO success marker); "
              f"full log -> {log_path}")

    gt_remote = None
    for line in out.splitlines():
        if line.startswith("REMOTE_GT_PATH="):
            gt_remote = line.split("=", 1)[1].strip()
            break
    gt_local = trial_dir / "ground_truth.jsonl"
    if gt_remote:
        pull = ["sshpass", "-p", SSHPASS, "scp", "-o",
                "StrictHostKeyChecking=no",
                f"{VISION}:{gt_remote}", str(gt_local)]
        p = subprocess.run(pull, capture_output=True, text=True)
        if p.returncode == 0 and gt_local.exists():
            print(f"[vision] pulled ground_truth.jsonl -> {gt_local}")
        else:
            print(f"[vision] WARNING: ground_truth.jsonl pull failed: "
                  f"{p.stderr.strip()[:200]}")
    else:
        print(f"[vision] WARNING: REMOTE_GT_PATH marker not found in output")
    return rc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", type=Path,
                    default=REPO / "experiments/configs/T1_6.yaml")
    ap.add_argument("--exp-id", default="T1_6_smoke")
    ap.add_argument("--trial-id", default="t00")
    ap.add_argument("--output-dir", type=Path,
                    default=REPO / "runs/experiments/T1_6_smoke")
    args = ap.parse_args()

    cfg_dict = yaml.safe_load(args.config.read_text())
    duration = cfg_dict.get("declared_duration_s", 120)

    print(f"\n=== T1.6 smoke trial ===")
    print(f"config: {args.config}")
    print(f"declared_duration_s: {duration}")

    # 1. Pre-trial: deploy generator + reset controller state + read register
    deploy_to_vision()
    reset_controller_state()
    print("[register] pre-attack state:")
    pre = dump_r6_register()
    nonzero_pre = {k: v for k, v in pre.items() if v != 0}
    print(f"  non-zero slots: {nonzero_pre or '(all zero)'}")

    # 2. Build TrialRunner and exercise the FSM
    out_dir = args.output_dir / args.trial_id
    out_dir.mkdir(parents=True, exist_ok=True)
    config = TrialConfig(
        exp_id=args.exp_id,
        trial_id=args.trial_id,
        scenario_id=cfg_dict.get("scenarios", [{}])[0].get(
            "id", "bess.attack.r6_high_version_poison"),
        declared_duration_s=duration,
        output_dir=out_dir,
        switch_host=SWITCH,
        controller_log=Path(
            "/home/decps/my_program/ota/runs/controller_campaign_2026-06-06.log"),
        requires_signed_rat=True,
        duration_tolerance_pct=float(
            cfg_dict.get("duration_tolerance_pct", 2.0)),
        dry_run=False,
    )
    runner = TrialRunner(config)
    # run_trial() invokes setup() internally; do not call it here.

    # 3. Run the generator on Vision (this is the scenario_callable)
    gen_params = (cfg_dict.get("generator", {}) or {}).get("params", {})

    def scenario_callable(ctx: dict) -> dict:
        rc = run_r6_poison_on_vision(gen_params, duration, runner.trial_dir)
        if rc != 0:
            raise RuntimeError(
                f"r6_poison generator failed rc={rc}; see "
                f"{runner.trial_dir}/r6_poison.stdout.log"
            )
        return {"generator_rc": rc}

    status = runner.run_trial(scenario_callable)
    print(f"[trial] FSM status: {status}; dir: {runner.trial_dir}")

    # 4. Post-trial: dump register and compare
    print("[register] post-attack state:")
    post = dump_r6_register()
    nonzero_post = {k: v for k, v in post.items() if v != 0}
    print(f"  non-zero slots: {nonzero_post or '(all zero)'}")

    # 5. T1.6 falsifier check
    has_poison = any(v == POISON_VAL for v in post.values())
    has_legit = any(v == int(gen_params.get("legitimate_version", 49))
                    for v in post.values())

    print("\n=== T1.6 SMOKE RESULT ===")
    print(f"  poison value (0x{POISON_VAL:08x}) in register: "
          f"{'YES (FALSIFIER TRIGGERED — patch failed)' if has_poison else 'no (PASS)'}")
    print(f"  legit version  ({gen_params.get('legitimate_version', 49)}) in register: "
          f"{'yes' if has_legit else 'NO (legitimate update did not commit)'}")

    if has_poison:
        print("\nFAIL: post-fix should NEVER store 0xDEADBEEF; r2_fired gate did not fire.")
        return 1
    if not has_legit:
        print("\nDEGRADED: legitimate v=49 did not commit; either generator missed or "
              "the legit packet was filtered by an unrelated rule.")
        return 2
    print("\nPASS: T1.6 R6-poisoning falsifier check holds on the patched binary.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
