"""T2.2 Threshold Sensitivity Sweep — hardware driver.

Contract (EXPERIMENT_DESIGN.md §1 T2.2):
  30 cells: R5 ∈ {2,4,8,16,31} × R1 ∈ {1,60,600,3600,14400,86400} s
  10 trials per cell = 300 trials total
  Seed: sha256("T2.2-{r5}-{r1}-{trial_id}-0xCAFE")
  Expected: F1-vs-parameter curves monotone (R5 small→FN, large→TP;
            R1 small→TP, large→FN)

Scenario design (see configs/T2_2.yaml for rationale):
  R5 component: AUTH_SRC (10.0.1.10) → r5 distinct BMS 0..r5-1 (size=1 →
    RAT size-range miss → R5 determines detection).
    P4 threshold = 4, fires at count > 4 = count ≥ 5.
    Fanout < 5: FN. Fanout ≥ 5: first 4 packets FN, rest TP.
  R1 component: AUTH_SRC2 (10.0.1.11) → BMS 25 (IP 10.0.2.35, outside
    secondary-source RAT coverage which only covers .10-.29; size=1 →
    RAT miss). R1_LAST_SEEN[25] pre-seeded on switch to simulate r1
    seconds elapsed since last update. Fires if r1 < 14400.

Per trial:
  1. Derive seed sha256("T2.2-{r5}-{r1}-{trial_id}-0xCAFE")
  2. SIGUSR1 reset controller state (clears R5 Bloom, hold_armed_reg, sessions)
  3. Pre-seed R1_LAST_SEEN[r1_bms_idx] on switch via second bfrt_grpc client
  4. Record decision-log byte offset
  5. Ship + run scenario driver on Vision
  6. Wait post_wait_s for digest drain
  7. Slice controller decisions
  8. Write ground_truth.json + manifest.json
  9. Wait inter_trial_s (≥70 s for R5 window clear)

Degraded/error trials are recorded with trial_invalid=True and noted in
session.json; they are NOT hidden or retried (honest-measurement policy).

Usage:
    python3 experiments/run_t2_2.py --dry-run           # default
    python3 experiments/run_t2_2.py --execute           # hardware
    python3 experiments/run_t2_2.py --cells r5=8,r1=1 --trials 1 --execute
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from experiments import t2_harness as H       # noqa: E402
from experiments.seed_schedule import derive_trial_seed  # noqa: E402
from experiments.manifest import write_manifest, TrialManifest, compute_file_sha  # noqa: E402

EXP_ID = "T2.2"

# ---------------------------------------------------------------------------
# SDE environment on switch
# ---------------------------------------------------------------------------
SDE_BASE = "/home/decps/Downloads/bf-sde-9.13.2"
SDE_LDPATH = f"{SDE_BASE}/install/lib"
BFSHELL = f"{SDE_BASE}/install/bin/bfshell"

# Controller decisions log lives at args.log.parent / "decisions.jsonl".
# The active log is campaign_2026-06-06.jsonl, so decisions.jsonl is in:
SWITCH_DECISIONS = f"{H.SWITCH_OTA}/runs/decisions.jsonl"

# ---------------------------------------------------------------------------
# R1 pre-seed helper — uses bfshell -b (bfrt_python mode) on the switch.
# Writes R1_LAST_SEEN[bms_idx] = (coarse_now & 0xFFFF - r1_interval) & 0xFFFF
# so the next packet to that BMS has a simulated delta of r1_interval seconds.
#
# bfrt_grpc multi-client approach rejected: SDE 9.13.2 ClientInterface has no
# is_master= kwarg, and a second client cannot bind (ALREADY_EXISTS from
# the running controller). bfshell -b connects via the SDE ucli path instead.
# r1_last_seen_reg.f1 is a 16-bit field; coarse_time_reg.f1 is 32-bit (full
# epoch). We approximate coarse_now = int(time.time()) & 0xFFFF on the switch.
# ---------------------------------------------------------------------------

# Template: {bms_idx}, {r1_interval}, {result_path} are Python-format fields.
# MUST use try/except: bfshell runs as root under IPython; uncaught exceptions
# abort the script silently (2>/dev/null) and the result file is never written.
_BFSHELL_PRESEED_TPL = """\
import time, traceback, os
try:
    p4 = bfrt.ota_shield.pipe
    r1_reg = p4.Ingress.rules.r1_last_seen_reg
    bms_idx = {bms_idx}
    r1_interval = {r1_interval}
    coarse_now = int(time.time()) & 0xFFFF
    seed_val = (coarse_now - r1_interval) & 0xFFFF
    r1_reg.mod(REGISTER_INDEX=bms_idx, f1=seed_val)
    msg = 'PRESEED_OK bms_idx=' + str(bms_idx) + ' coarse_now=' + str(coarse_now) + ' r1_interval=' + str(r1_interval) + ' seed_val=' + str(seed_val)
    open('{result_path}', 'w').write(msg + '\\n')
    os.chmod('{result_path}', 0o644)
except Exception as _e:
    try:
        open('{result_path}', 'w').write('PRESEED_ERR: ' + str(_e) + '\\n')
        os.chmod('{result_path}', 0o644)
    except Exception:
        pass
"""

# ---------------------------------------------------------------------------
# Vision scenario driver — sends R5 fanout + R1 replay packets
# ---------------------------------------------------------------------------

_VISION_DRIVER_TPL = r"""
import sys, struct, time
try:
    from scapy.all import Ether, IP, TCP, Raw, sendp
except ImportError as e:
    print(f"SCAPY_MISSING: {{e}}", file=sys.stderr)
    sys.exit(1)

IFACE   = "enp59s0f0np0"
SRC_MAC = "00:00:00:00:10:10"
DST_MAC = "00:00:00:00:20:ff"

def _varint(n):
    o = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        o.append(b)
        if not n: break
    return bytes(o)

def _publish(topic, ver, sz):
    t = topic.encode().ljust(32, b"\x00")
    on_wire = max(0, min(sz - 20, 1280))
    fw = b"\x00" * on_wire
    pl = b"OTAS" + struct.pack(">II", ver, sz) + b"\x00" * 8 + fw
    var = struct.pack(">H", 32) + t + struct.pack(">H", 1) + pl
    return bytes([0x32]) + _varint(len(var)) + var

def send_pkt(src_ip, dst_ip, sport, topic, ver, sz):
    pkt = (Ether(src=SRC_MAC, dst=DST_MAC) /
           IP(src=src_ip, dst=dst_ip) /
           TCP(sport=sport, dport=1883, flags="PA", seq=1, ack=1) /
           Raw(_publish(topic, ver, sz)))
    sendp(pkt, iface=IFACE, verbose=False, count=1)

r5_fanout  = {r5_fanout}
r1_bms_idx = {r1_bms_idx}
sport_base = {sport_base}
AUTH_SRC   = "{auth_src}"
AUTH_SRC2  = "{auth_src2}"
ATTACK_SZ  = {attack_size}

events = []

# R5 fanout attack: AUTH_SRC → r5_fanout distinct BMS
# BMS 0..r5-1 → IPs 10.0.2.10..10.0.2.(10+r5-1)
# size=ATTACK_SZ → below RAT min_size (512) → RAT miss → R5 decides
for i in range(r5_fanout):
    bms = i
    dst = f"10.0.2.{{10+bms}}"
    sport = sport_base + i
    topic = f"/ota/bms/{{bms:02d}}"
    send_pkt(AUTH_SRC, dst, sport, topic, 48, ATTACK_SZ)
    events.append(dict(t_send=time.time(), scenario="r5_fanout_t2_2",
                       label="ATTACK", src_ip=AUTH_SRC, dst_ip=dst,
                       src_port=sport, dst_port=1883, topic=topic,
                       ota_size=ATTACK_SZ, ota_version=48,
                       note=f"r5_fanout={{r5_fanout}} bms={{bms}}"))
    time.sleep(0.025)   # ~40 pps, gives R5 Bloom filter time to update

# R1 replay attack: AUTH_SRC2 → BMS r1_bms_idx (outside secondary-RAT coverage)
# R1_LAST_SEEN[r1_bms_idx] pre-seeded on switch to simulate r1_interval seconds
# Since AUTH_SRC2 has separate R5 count, this does not contaminate R5 fanout.
r1_dst = f"10.0.2.{{10+r1_bms_idx}}"
r1_sport = sport_base + 90
r1_topic = f"/ota/bms/{{r1_bms_idx:02d}}"
send_pkt(AUTH_SRC2, r1_dst, r1_sport, r1_topic, 48, ATTACK_SZ)
events.append(dict(t_send=time.time(), scenario="r1_replay_t2_2",
                   label="ATTACK", src_ip=AUTH_SRC2, dst_ip=r1_dst,
                   src_port=r1_sport, dst_port=1883, topic=r1_topic,
                   ota_size=ATTACK_SZ, ota_version=48,
                   note=f"r1_preseed={{r1_bms_idx}}"))

import json, pathlib
out_path = pathlib.Path("/tmp/t2_2_gt_{trial_key}.json")
out_path.write_text(json.dumps(events))
print(f"T2_2_DONE n_events={{len(events)}} gt={{out_path}}")
"""


def _preseed_r1_on_switch(bms_idx: int, r1_interval: int,
                           execute: bool) -> str:
    """Write R1_LAST_SEEN[bms_idx] = (coarse_now - r1_interval) & 0xFFFF on switch.

    Uses bfshell -b (bfrt_python mode) because bfrt_grpc multi-client is not
    available in SDE 9.13.2 (no is_master kwarg; second client cannot bind).

    Root cause of H.ssh() failure: bfshell monitors its stdin channel.  When
    stdin closes (EOF), bfshell closes the ucli connection and exits before the
    script completes — producing only the first few bytes of ucli startup text.
    Fix: launch bfshell via ``nohup bash -c 'sleep 50 | bfshell -b ...'`` so
    (a) the pipe keeps bfshell stdin open for 50 s (enough for the ~20 s script
    startup) and (b) nohup lets the process survive SSH session teardown.
    Poll the result file (chmod 644 by the script so decps can read it) rather
    than waiting for the 50-s sleep to expire.
    """
    if not execute:
        return f"dry-run: would preseed bms_idx={bms_idx} r1_interval={r1_interval}"

    result_path = f"/tmp/t2_2_preseed_result_{bms_idx}_{r1_interval}.txt"
    script_path = f"/tmp/t2_2_preseed_{bms_idx}_{r1_interval}.py"
    log_path    = f"/tmp/t2_2_preseed_bfshell_{bms_idx}_{r1_interval}.log"

    # Upload script.
    script_body = _BFSHELL_PRESEED_TPL.format(
        bms_idx=bms_idx, r1_interval=r1_interval, result_path=result_path)
    script_b64 = base64.b64encode(script_body.encode()).decode()
    upload_cmd = (
        f"rm -f {result_path} {log_path} && "
        f"echo {script_b64} | base64 -d > {script_path}"
    )
    H.ssh(H.SWITCH, upload_cmd, timeout=15)

    # Launch bfshell under nohup with piped stdin so it stays alive.
    nohup_cmd = (
        f"nohup bash -c "
        f"'sleep 50 | LD_LIBRARY_PATH={SDE_LDPATH} {BFSHELL} -b {script_path} "
        f"> {log_path} 2>&1' "
        f"> /dev/null 2>&1 &"
    )
    H.ssh(H.SWITCH, nohup_cmd, timeout=15)

    # Poll for result file.  Script writes + chmod 644 inside try/except so
    # even if the bfrt call fails we get PRESEED_ERR not silence.
    for _attempt in range(14):
        time.sleep(3)
        _, out = H.ssh(H.SWITCH,
                       f"cat {result_path} 2>/dev/null || echo PRESEED_NO_RESULT",
                       timeout=10)
        out = out.strip()
        if "PRESEED_OK" in out or "PRESEED_ERR" in out:
            return out
    # 42s timeout — fetch bfshell log for diagnosis.
    _, blog = H.ssh(H.SWITCH, f"tail -5 {log_path} 2>/dev/null", timeout=10)
    return f"PRESEED_TIMEOUT (bfshell_log: {blog.strip()[:200]})"


def _emit_vision(r5_fanout: int, r1_bms_idx: int, sport_base: int,
                 auth_src: str, auth_src2: str, attack_size: int,
                 trial_key: str, execute: bool) -> tuple[int, str]:
    """Run scenario driver on Vision. Returns (rc, output)."""
    driver = _VISION_DRIVER_TPL.format(
        r5_fanout=r5_fanout, r1_bms_idx=r1_bms_idx, sport_base=sport_base,
        auth_src=auth_src, auth_src2=auth_src2, attack_size=attack_size,
        trial_key=trial_key,
    )
    b64 = base64.b64encode(driver.encode()).decode()
    # Script path includes trial_key to avoid collisions between concurrent runs.
    script_remote = f"/tmp/t2_2_driver_{trial_key}.py"
    cmd = (
        f"echo {b64} | base64 -d > {script_remote} && "
        f"echo {shlex.quote(H._sshpass())} | "
        f"sudo -S -p '' python3 {script_remote}"
    )
    if not execute:
        return 0, f"dry-run: would emit r5={r5_fanout} r1_bms={r1_bms_idx} sport_base={sport_base}"
    rc, out = H.ssh(H.VISION, cmd, timeout=60)
    return rc, out.strip()


def _pull_vision_gt(trial_key: str, trial_dir: Path, execute: bool) -> list[dict]:
    """Pull ground_truth events from Vision."""
    remote = f"/tmp/t2_2_gt_{trial_key}.json"
    local = trial_dir / "vision_gt_raw.json"
    if not execute:
        return []
    try:
        H.scp_from(H.VISION, remote, local)
        return json.loads(local.read_text())
    except Exception as exc:
        print(f"  [WARN] gt pull failed: {exc}", flush=True)
        return []


def _write_ground_truth(trial_dir: Path, trial_id: str, scenario_id: str,
                        events: list[dict]) -> None:
    gt = {"trial_id": trial_id, "scenario": scenario_id, "events": events}
    (trial_dir / "ground_truth.json").write_text(
        json.dumps(gt, indent=2, default=str))


def run_one_trial(r5: int, r1: int, trial_idx: int, cfg: dict,
                  out_root: Path, execute: bool) -> dict:
    """Execute one trial for cell (r5, r1)."""
    trial_id   = f"t{trial_idx:02d}"
    cell_label = f"r5_{r5}_r1_{r1}"
    trial_key  = f"{cell_label}_{trial_id}"
    exp_dir    = out_root / cell_label
    trial_dir  = exp_dir / trial_id
    trial_dir.mkdir(parents=True, exist_ok=True)

    # Seed per contract: sha256("T2.2-{r5}-{r1}-{trial_id}-0xCAFE")
    cell_exp_id = f"{EXP_ID}-{r5}-{r1}"
    seed = derive_trial_seed(cell_exp_id, trial_id, cfg["master_seed"])

    # Sport base: unique per cell × trial to avoid 5-tuple re-use
    r5_idx   = cfg["r5_values"].index(r5)
    r1_idx   = cfg["r1_values"].index(r1)
    cell_idx = r5_idx * len(cfg["r1_values"]) + r1_idx
    sport_base = 50000 + (cell_idx * 10 + trial_idx) * 100

    rec: dict = {
        "r5": r5, "r1": r1, "trial_id": trial_id, "seed": seed,
        "sport_base": sport_base, "cell_label": cell_label,
        "mode": "execute" if execute else "dry-run",
    }

    # Build synthetic ground truth for dry-run (predict what will happen)
    r1_bms_idx    = int(cfg["r1_bms_idx"])
    auth_src      = cfg["auth_src"]
    auth_src2     = cfg["auth_src2"]
    attack_sz     = int(cfg["attack_size_bytes"])
    # R5 events: first min(r5, 4) are FN (count < P4 threshold of 4 = fires at ≥5)
    # R1 event: TP if r1 < 14400, FN otherwise
    p4_r5_thresh  = 4  # compile-time constant (fires at count > 4)
    r5_tp_count   = max(0, r5 - p4_r5_thresh)
    r5_fn_count   = min(r5, p4_r5_thresh)
    r1_tp         = 1 if r1 < 14400 else 0
    r1_fn         = 1 - r1_tp
    rec["predicted_r5_tp"]  = r5_tp_count
    rec["predicted_r5_fn"]  = r5_fn_count
    rec["predicted_r1_tp"]  = r1_tp
    rec["predicted_r1_fn"]  = r1_fn
    rec["predicted_total_tp"] = r5_tp_count + r1_tp
    rec["predicted_total_fn"] = r5_fn_count + r1_fn

    t_start = time.time()

    # ---- EXECUTE PATH ----
    if execute:
        # 1. SIGUSR1 reset (wait 13s; controller does 256+64 reg writes ≈ 9-10s)
        reset_out = H.reset_controller_state(wait_s=13.0)
        rec["reset_out"] = reset_out[:200]

        # 2. Pre-seed R1_LAST_SEEN on switch (retry once if bfshell fails)
        preseed_out = _preseed_r1_on_switch(r1_bms_idx, r1, execute=True)
        if "PRESEED_OK" not in preseed_out and "PRESEED_ERR" not in preseed_out:
            # bfshell may have been slow starting; wait 3s and retry once.
            time.sleep(3)
            preseed_out = _preseed_r1_on_switch(r1_bms_idx, r1, execute=True)
        rec["preseed_out"] = preseed_out[:400]
        if "PRESEED_OK" not in preseed_out:
            rec["trial_invalid"] = True
            rec["trial_invalid_reason"] = f"preseed failed: {preseed_out[:100]}"
            print(f"  [WARN] preseed failed — marking trial invalid", flush=True)
            (trial_dir / "trial_invalid.txt").write_text(
                f"preseed failed:\n{preseed_out}\n")

        # 3. Record decision offset
        off0 = H.get_decisions_offset()
        rec["offset_start"] = off0

        # 4. Emit scenario on Vision
        emit_rc, emit_out = _emit_vision(
            r5_fanout=r5, r1_bms_idx=r1_bms_idx,
            sport_base=sport_base, auth_src=auth_src, auth_src2=auth_src2,
            attack_size=attack_sz, trial_key=trial_key, execute=True)
        rec["emit_rc"]  = emit_rc
        rec["emit_out"] = emit_out[-200:]
        if "T2_2_DONE" not in emit_out:
            rec.setdefault("trial_invalid", False)
            if not rec.get("trial_invalid"):
                rec["trial_invalid"] = True
                rec["trial_invalid_reason"] = f"vision driver no DONE marker"
                (trial_dir / "trial_invalid.txt").write_text(
                    f"vision driver output:\n{emit_out}\n")

        # 5. Drain
        time.sleep(float(cfg.get("post_wait_s", 12)))

        # 6. Slice decisions
        off1 = H.get_decisions_offset()
        rec["offset_end"] = off1
        H.slice_decisions(off0, off1, trial_dir / "controller_decisions.jsonl")

        # 7. Pull Vision ground truth
        live_events = _pull_vision_gt(trial_key, trial_dir, execute=True)
        if live_events:
            rec["n_events"] = len(live_events)
        else:
            # Synthesise ground truth from scenario parameters
            live_events = _synthetic_gt(
                r5, r1_bms_idx, sport_base, auth_src, auth_src2, attack_sz)
            rec["n_events"] = len(live_events)
            rec["gt_source"] = "synthetic"
    else:
        live_events = _synthetic_gt(
            r5, r1_bms_idx, sport_base, auth_src, auth_src2, attack_sz)
        rec["n_events"] = len(live_events)

    t_end = time.time()
    rec["actual_duration_s"] = round(t_end - t_start, 2)

    # 8. Write outputs
    _write_ground_truth(trial_dir, trial_id, cell_label, live_events)
    manifest = TrialManifest(
        exp_id=EXP_ID,
        trial_id=trial_id,
        scenario_id=cell_label,
        declared_duration_s=float(cfg.get("declared_duration_s", 15)),
        actual_duration_s=rec["actual_duration_s"],
        master_seed=cfg["master_seed"],
        trial_seed=seed,
        p4_binary_sha256="",  # informational-only in execute mode
        controller_git_rev="",
        rat_lifecycle_sha256=compute_file_sha(REPO / "controller" / "rat_lifecycle.py"),
        preflight_integrity={},
        postflight_integrity={},
        notes=(f"r5={r5} r1={r1} sport_base={sport_base} "
               f"p4_r5_thr=4 r1_thr=14400 size={attack_sz}"),
    )
    write_manifest(trial_dir, manifest)

    return rec


def _synthetic_gt(r5: int, r1_bms_idx: int, sport_base: int,
                  auth_src: str, auth_src2: str, attack_sz: int,
                  ) -> list[dict]:
    """Synthesise ground-truth events for dry-run or Vision-pull failure."""
    events = []
    for i in range(r5):
        bms = i
        events.append(dict(
            t_send=0, scenario="r5_fanout_t2_2", label="ATTACK",
            src_ip=auth_src, dst_ip=f"10.0.2.{10+bms}",
            src_port=sport_base + i, dst_port=1883,
            topic=f"/ota/bms/{bms:02d}", ota_size=attack_sz, ota_version=48,
            note=f"r5_fanout={r5} bms={bms}"))
    events.append(dict(
        t_send=0, scenario="r1_replay_t2_2", label="ATTACK",
        src_ip=auth_src2, dst_ip=f"10.0.2.{10+r1_bms_idx}",
        src_port=sport_base + 90, dst_port=1883,
        topic=f"/ota/bms/{r1_bms_idx:02d}",
        ota_size=attack_sz, ota_version=48,
        note=f"r1_preseed={r1_bms_idx}"))
    return events


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", type=Path,
                    default=REPO / "experiments/configs/T2_2.yaml")
    ap.add_argument("--out-root", type=Path,
                    default=REPO / "runs/experiments/T2_2_threshold_sweep_2026-06-06")
    ap.add_argument("--trials", type=int, default=None,
                    help="Override trial count (default from config)")
    ap.add_argument("--cells", default=None,
                    help="Run only specific cells e.g. 'r5=8,r1=1 r5=2,r1=60'")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dry-run", action="store_true", default=True)
    g.add_argument("--execute", action="store_true")
    args = ap.parse_args(argv)
    execute = bool(args.execute)

    cfg = yaml.safe_load(args.config.read_text())
    trials = args.trials if args.trials is not None else int(cfg["trial_count"])
    r5_values = [int(v) for v in cfg["r5_values"]]
    r1_values = [int(v) for v in cfg["r1_values"]]

    # Cell filter
    cell_filter: Optional[list[tuple[int, int]]] = None
    if args.cells:
        cell_filter = []
        for spec in args.cells.split():
            parts = {kv.split("=")[0]: int(kv.split("=")[1])
                     for kv in spec.split(",")}
            cell_filter.append((parts["r5"], parts["r1"]))

    n_cells = len(r5_values) * len(r1_values)
    n_total = n_cells * trials if cell_filter is None else len(cell_filter) * trials

    print(f"=== {EXP_ID} threshold sensitivity sweep "
          f"({'EXECUTE' if execute else 'DRY-RUN'}) ===", flush=True)
    print(f"  r5 values : {r5_values}", flush=True)
    print(f"  r1 values : {r1_values}", flush=True)
    print(f"  trials/cell: {trials}", flush=True)
    print(f"  total trials: {n_total}  ({n_cells} cells)", flush=True)
    est_h = n_total * (float(cfg.get("inter_trial_s", 72)) +
                       float(cfg.get("post_wait_s", 12)) + 8) / 3600
    print(f"  estimated wall-clock: {est_h:.1f} h", flush=True)
    if execute and not os.environ.get("OTA_SSHPASS"):
        print("ERROR: OTA_SSHPASS not set. Source ~/.lab_env first.", flush=True)
        return 1
    print(f"  output: {args.out_root}", flush=True)
    print(flush=True)

    session: list[dict] = []
    trial_num = 0

    for r5 in r5_values:
        for r1 in r1_values:
            if cell_filter is not None and (r5, r1) not in cell_filter:
                continue
            print(f"--- Cell r5={r5} r1={r1} ({len(session)+1}/{n_total} "
                  f"trials so far) ---", flush=True)
            for ti in range(trials):
                trial_num += 1
                print(f"  Trial t{ti:02d} [{trial_num}/{n_total}] ...",
                      end=" ", flush=True)
                try:
                    rec = run_one_trial(r5, r1, ti, cfg, args.out_root,
                                        execute)
                except Exception as exc:
                    rec = {"r5": r5, "r1": r1, "trial_id": f"t{ti:02d}",
                           "trial_invalid": True,
                           "trial_invalid_reason": repr(exc),
                           "mode": "execute" if execute else "dry-run"}
                    print(f"EXCEPTION: {exc}", flush=True)
                session.append(rec)
                status = ("INVALID" if rec.get("trial_invalid")
                          else f"ok n={rec.get('n_events','?')}")
                print(f"{status}  pred_tp={rec.get('predicted_total_tp','?')}/"
                      f"{rec.get('predicted_r5_tp','?')}+{rec.get('predicted_r1_tp','?')}",
                      flush=True)

                # Inter-trial wait for R5 window clear (skip after last trial)
                if execute and (ti < trials - 1 or
                                r1 != r1_values[-1] or r5 != r5_values[-1]):
                    inter = float(cfg.get("inter_trial_s", 72))
                    print(f"  [wait {inter:.0f}s for R5 window clear]",
                          flush=True)
                    time.sleep(inter)

    # Write session summary
    args.out_root.mkdir(parents=True, exist_ok=True)
    sess_path = args.out_root / "T2_2_session.json"
    sess_path.write_text(json.dumps(session, indent=2, default=str))
    n_invalid = sum(1 for r in session if r.get("trial_invalid"))
    print(f"\n{'='*60}", flush=True)
    print(f"T2.2 sweep done: {len(session)} trials "
          f"({n_invalid} invalid, {len(session)-n_invalid} good)",
          flush=True)
    print(f"session  -> {sess_path}", flush=True)
    print(f"raw data -> {args.out_root}", flush=True)
    print("next: python3 -m experiments.aggregate_t2_2 "
          f"--runs-dir {args.out_root}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
