"""T1.5 HOLD-leak measurement smoke (minimal, single-burst variant).

The full T1.5 (configs/T1_5.yaml) specifies a mixed scenario load
(staged_rollout_v48 60% + r5_fanout_clear 40%) over 10 × 120s trials and
correlates tcpdump pcap with the controller log to compute
bytes_leaked_per_hold_event (per-event p95 must be ≤ 1 MQTT PUBLISH frame).

This SMOKE simplifies to a single burst from one unauthorized source:
the falsifier signal is the same — packets emitted *between* the HOLD
digest at the controller and the moment the override-DROP entry lands at
the data plane. With panel-7 Option A (DP self-install), that window
should contain at most one PUBLISH frame.

Mechanics (controller log only — no tcpdump dependency for the smoke):
  1. Reset controller (SIGUSR1) so override table starts clean.
  2. Vision emits N=20 unauthorized OTA PUBLISHes back-to-back to a
     single dst BMS (one 5-tuple). Each packet is ~1.4 KB.
  3. Read the HOLD/DROP digest timestamp T_hold from the controller log.
  4. Read the "Session override DROP" timestamp T_install for the same
     5-tuple.
  5. Read the per-packet send-time list from ground_truth.jsonl on Vision.
  6. The leak window is [T_hold, T_install]. Count GT packets whose
     send-time falls inside that window — that is the bytes-leaked-
     per-HOLD-event proxy.

Limitations vs. full T1.5:
  * Single-source burst, not mixed staged_rollout + fanout.
  * Uses controller-log timestamps as proxy for override-install latency
    rather than tcpdump on PORT_HULK egress. This OVERESTIMATES leak
    (controller-log time > actual install time) — i.e. it is the
    conservative direction.
  * Single trial, not 10. No bootstrap / Wilson UB.
"""
from __future__ import annotations
import os

import argparse
import calendar
import json
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

SWITCH = "decps@10.10.54.15"
VISION = "decps@10.10.54.19"  # Vision management IP (eno1; was 10.10.54.19 in old notes)
SSHPASS = os.environ.get("OTA_SSHPASS", "")
if not SSHPASS:
    raise RuntimeError("OTA_SSHPASS env var not set; refuse to fall back to a literal credential")


def _ssh(host: str, cmd: str, timeout: int = 60) -> tuple[int, str]:
    full = ["sshpass", "-p", SSHPASS, "ssh",
            "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
            host, cmd]
    p = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


def reset_controller_state() -> None:
    cmd = (
        "PID=$(ps -eo pid,comm,cmd --no-headers | "
        "awk '$2 ~ /^python/ && $0 ~ "
        "/controller\\/ota_shield_controller\\.py/ {print $1; exit}'); "
        "if [ -n \"$PID\" ]; then "
        f"echo {shlex.quote(SSHPASS)} | sudo -S -p '' kill -USR1 $PID; "
        "echo \"sent SIGUSR1 to $PID\"; "
        "else echo no-controller; fi"
    )
    _, out = _ssh(SWITCH, cmd, timeout=10)
    print(f"[reset] {out.strip()[:160]}")
    time.sleep(3)


def deploy_burst_generator() -> None:
    """Deploy a tiny burst generator to Vision (inline, no module)."""
    src = """
import struct, sys, time, json
from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, sendp

IFACE = "enp59s0f0np0"
SRC_MAC = "00:00:00:00:10:10"
DST_MAC = "00:00:00:00:20:ff"
SRC_IP = "10.0.99.99"
DST_IP = "10.0.2.10"
DST_PORT = 1883
SPORT = 49500
N = int(sys.argv[1]) if len(sys.argv) > 1 else 20
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("/tmp/t1_5_gt")
OUT.mkdir(parents=True, exist_ok=True)

def varint(n):
    o = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        o.append(b)
        if not n: break
    return bytes(o)

def publish(topic, ver, sz):
    t = topic.encode().ljust(32, b"\\x00")
    pl = b"OTAS" + struct.pack(">II", ver, sz) + b"\\x00" * 8 + b"\\x00" * (1024 - 20)
    var = struct.pack(">H", 32) + t + struct.pack(">H", 1) + pl
    return bytes([0x32]) + varint(len(var)) + var

records = []
batch = []
t0 = time.time()
for i in range(N):
    pkt = (Ether(src=SRC_MAC, dst=DST_MAC) /
           IP(src=SRC_IP, dst=DST_IP) /
           TCP(sport=SPORT, dport=DST_PORT, flags="PA", seq=1+i*1500, ack=1) /
           Raw(publish("/ota/bms/00", 48, 1024)))
    batch.append(pkt)
    records.append({"seq": i, "ts_planned_offset_s": i * 0.001,
                    "src_ip": SRC_IP, "dst_ip": DST_IP,
                    "src_port": SPORT, "dst_port": DST_PORT})
sendp(batch, iface=IFACE, verbose=False)
t_end = time.time()
gt = OUT / "ground_truth.jsonl"
ts_send = OUT / "ts_send.json"
with gt.open("w") as f:
    for r in records:
        f.write(json.dumps(r) + "\\n")
ts_send.write_text(json.dumps({"t_send_start": t0, "t_send_end": t_end,
                                "n_packets": N}))
print(f"BURST_DONE n={N} duration_s={t_end-t0:.4f}")
"""
    Path("/tmp/t1_5_burst.py").write_text(src)
    pull = ["sshpass", "-p", SSHPASS, "scp", "-o", "StrictHostKeyChecking=no",
            "/tmp/t1_5_burst.py", f"{VISION}:/home/decps/t1_5_burst.py"]
    subprocess.run(pull, check=True, capture_output=True, text=True)
    print("[deploy] t1_5_burst.py copied to Vision")


def run_burst(n_packets: int, trial_dir: Path) -> tuple[int, dict]:
    """Run the burst generator on Vision; pull back ground_truth + ts_send."""
    remote_dir = "/tmp/t1_5_gt.$$"
    remote_log = "/tmp/t1_5_burst.$$.log"
    pw = shlex.quote(SSHPASS)
    cmd = (
        f"echo {pw} | sudo -S -p '' rm -rf {remote_dir} >/dev/null 2>&1; "
        f"mkdir -p {remote_dir}; "
        f"(echo {pw} | sudo -S -p '' python3 /home/decps/t1_5_burst.py "
        f"{n_packets} {remote_dir}) >{remote_log} 2>&1; "
        f"rc=$?; echo MARKER_BURST_DONE rc=$rc; "
        f"cat {remote_log}; "
        f"echo {pw} | sudo -S -p '' chmod 644 {remote_dir}/* 2>/dev/null; "
        f"echo REMOTE_DIR={remote_dir}; "
        f"echo {pw} | sudo -S -p '' rm -f {remote_log} >/dev/null 2>&1; "
        f"exit $rc"
    )
    rc, out = _ssh(VISION, cmd, timeout=60)
    log_path = trial_dir / "burst.stdout.log"
    log_path.write_text(out)
    print(f"[burst] rc={rc}; full log -> {log_path}")
    rdir = None
    for line in out.splitlines():
        if line.startswith("REMOTE_DIR="):
            rdir = line.split("=", 1)[1].strip()
            break
    if rdir is None:
        return rc, {}
    # Pull files individually — multi-source scp can silently drop a file if
    # one of the sources is missing; separate calls give each a clean rc.
    for fname in ("ground_truth.jsonl", "ts_send.json"):
        subprocess.run(
            ["sshpass", "-p", SSHPASS, "scp", "-o", "StrictHostKeyChecking=no",
             f"{VISION}:{rdir}/{fname}", str(trial_dir) + "/"],
            capture_output=True, text=True)
    ts_send = {}
    p = trial_dir / "ts_send.json"
    if p.exists():
        ts_send = json.loads(p.read_text())
    return rc, ts_send


def fetch_controller_log_window(t_start: float, t_end: float
                                 ) -> list[dict]:
    """Pull controller log lines between t_start and t_end (epoch s)."""
    log_remote = "/home/decps/my_program/ota/runs/controller_campaign_2026-06-06.log"
    cmd = f"tail -200 {log_remote}"
    _, out = _ssh(SWITCH, cmd, timeout=10)
    pattern = re.compile(
        r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+"
        r"(?P<level>WARNING|INFO)\s+(?P<msg>.*)")
    events = []
    for line in out.splitlines():
        m = pattern.match(line)
        if not m:
            continue
        try:
            # Switch logs are in UTC; parse as UTC to avoid TZ skew with
            # the host running this script (which uses time.time(),
            # always epoch).
            tm = calendar.timegm(time.strptime(
                m.group("ts").split(",")[0], "%Y-%m-%d %H:%M:%S"))
            tm += int(m.group("ts").split(",")[1]) / 1000.0
        except ValueError:
            continue
        if t_start - 5 <= tm <= t_end + 10:
            events.append({"ts": tm, "level": m.group("level"),
                           "msg": m.group("msg")})
    return events


def measure_leak(events: list[dict], target_5tuple: dict) -> dict:
    """Find HOLD/DROP for the target 5-tuple, then the matching session
    override DROP install. Return both timestamps + delta.

    For our smoke the target 5-tuple is: src=10.0.99.99 sport=49500
    dst=10.0.2.10 dport=1883. Controller logs use the form
    'Session override DROP: 10.0.99.99:49500 -> 10.0.2.10:1883'.
    """
    src = target_5tuple["src_ip"]; sport = target_5tuple["src_port"]
    dst = target_5tuple["dst_ip"]; dport = target_5tuple["dst_port"]
    sess_marker = f"{src}:{sport} -> {dst}:{dport}"
    t_hold = None
    t_install = None
    for e in events:
        msg = e["msg"]
        if t_hold is None and msg.startswith("HOLD/DROP") and "r2=1" in msg:
            t_hold = e["ts"]
        elif t_install is None and msg.startswith("Session override DROP") \
                and sess_marker in msg:
            t_install = e["ts"]
        if t_hold is not None and t_install is not None:
            break
    return {
        "t_hold": t_hold,
        "t_install": t_install,
        "install_latency_s": (t_install - t_hold)
                             if (t_hold and t_install) else None,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trial-id", default="t00")
    ap.add_argument("--n-packets", type=int, default=20)
    ap.add_argument("--output-dir", type=Path,
                    default=REPO / "runs/experiments/T1_5_smoke")
    args = ap.parse_args()

    trial_dir = args.output_dir / args.trial_id
    trial_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n=== T1.5 HOLD-leak smoke trial {args.trial_id} ===")

    # 1. Reset controller state.
    print("[1/4] reset controller state...")
    reset_controller_state()

    # 2. Deploy + run the burst.
    print("[2/4] deploy + run burst...")
    deploy_burst_generator()
    rc, ts_send = run_burst(args.n_packets, trial_dir)
    if rc != 0:
        print(f"  FAIL: burst rc={rc}")
        return 1
    print(f"  burst sent {ts_send.get('n_packets')} packets in "
          f"{ts_send.get('t_send_end',0)-ts_send.get('t_send_start',0):.4f}s")

    # 3. Wait for digest stream + override install.
    print("[3/4] wait 4s for controller to drain digests...")
    time.sleep(4)

    # 4. Correlate.
    events = fetch_controller_log_window(
        ts_send.get("t_send_start", time.time() - 30),
        ts_send.get("t_send_end", time.time())
    )
    target = {"src_ip": "10.0.99.99", "src_port": 49500,
              "dst_ip": "10.0.2.10", "dst_port": 1883}
    result = measure_leak(events, target)

    # Save raw events.
    (trial_dir / "events.json").write_text(
        json.dumps({"events": events, "result": result,
                    "ts_send": ts_send, "target": target},
                   indent=2, default=str))

    print("[4/4] T1.5 smoke result:")
    print(f"  T_hold       : {result['t_hold']}")
    print(f"  T_install    : {result['t_install']}")
    print(f"  install_lat_s: {result['install_latency_s']}")

    if result["t_hold"] is None:
        print("  DEGRADED: no HOLD/DROP r2=1 digest seen — burst may not "
              "have reached the data plane parser")
        return 2
    if result["t_install"] is None:
        print("  DEGRADED: HOLD seen but no Session override DROP install "
              "for the target 5-tuple")
        return 3

    # Per-event leak: count packets whose send-time falls inside
    # [T_hold, T_install]. With back-to-back send pacing inside ts_send,
    # packets with offset > (T_hold - T_send_start) and offset <=
    # (T_install - T_send_start) are leaked.
    t_send_start = ts_send.get("t_send_start", 0.0)
    t0 = result["t_hold"] - t_send_start
    t1 = result["t_install"] - t_send_start
    gt_path = trial_dir / "ground_truth.jsonl"
    leaked = 0
    if gt_path.exists():
        for line in gt_path.read_text().splitlines():
            r = json.loads(line)
            off = r.get("ts_planned_offset_s", 0)
            if t0 < off <= t1:
                leaked += 1
    print(f"  leaked_packets (in [T_hold, T_install] window): {leaked}")

    falsifier_pass = leaked <= 1
    print(f"\n=== T1.5 SMOKE FALSIFIER: "
          f"{'PASS' if falsifier_pass else 'FAIL'} ===")
    print(f"  bytes-leaked-per-HOLD-event proxy: {leaked} PUBLISH frames")
    print(f"  acceptance: <=1 PUBLISH frame")
    return 0 if falsifier_pass else 4


if __name__ == "__main__":
    sys.exit(main())
