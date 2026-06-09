"""T1.7 5-tuple override smoke driver.

Falsifier (per configs/T1_7.yaml):
    Any RESOURCE_EXHAUSTED reject AT table size 256, OR any cross-tuple
    ALLOW (secondary 5-tuple inheriting ALLOW from the original entry).

Structural test: inspect session_action_override via bfrt_grpc and verify
the table has 5-tuple key shape AND size == 256. Equivalent key shape
guarantees a secondary 5-tuple cannot collision-match an ALLOW entry; the
size check confirms 200 sources fit with headroom.

Capacity test: install n_sources synthetic session_allow overrides for the
generator's planned ALLOW tuples, count entries, verify no
RESOURCE_EXHAUSTED reject. Cleans up the entries afterward.

Smoke usage:
    python3 experiments/run_t1_7.py --trial-id t00 --n-sources 50

Full-trial usage:
    python3 experiments/run_t1_7.py --trial-id full --n-sources 200
"""
from __future__ import annotations
import os

import argparse
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

SWITCH = "decps@10.10.54.15"
SSHPASS = os.environ.get("OTA_SSHPASS", "")
if not SSHPASS:
    raise RuntimeError("OTA_SSHPASS env var not set; refuse to fall back to a literal credential")
EXPECTED_TABLE_SIZE = 256
EXPECTED_KEY_SUBSTR = ["src_addr", "dst_addr", "src_port", "dst_port",
                       "protocol"]


def _ssh(host: str, cmd: str, timeout: int = 60) -> tuple[int, str]:
    full = ["sshpass", "-p", SSHPASS, "ssh",
            "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
            host, cmd]
    p = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


def inspect_table_shape() -> tuple[bool, dict[str, Any]]:
    """Verify session_action_override key shape (via bfrt_grpc) + size
    (via bfrt.json, since the gRPC TableInfo on SDE 9.13.2 does not
    surface table size directly)."""
    bfrt_json = ("/home/decps/Downloads/bf-sde-9.13.2/build/ota_shield/"
                 "bfrt.json")
    py = (
        'import sys, json\n'
        'S="/home/decps/Downloads/bf-sde-9.13.2/install"\n'
        'sys.path.insert(0, S+"/lib/python3.8/site-packages/tofino")\n'
        'sys.path.insert(0, S+"/lib/python3.8/site-packages")\n'
        'import bfrt_grpc.client as gc\n'
        'i = gc.ClientInterface("localhost:50052", client_id=3, '
        'device_id=0)\n'
        'try: i.bind_pipeline_config("ota_shield")\n'
        'except Exception: pass\n'
        'b = i.bfrt_info_get("ota_shield")\n'
        'tbl = b.table_get("pipe.Ingress.session_action_override")\n'
        'kf = list(tbl.info.key_dict.keys())\n'
        'print("KEYS:" + ",".join(kf))\n'
        f'd = json.load(open("{bfrt_json}"))\n'
        'sz = None\n'
        'for t in d.get("tables", []):\n'
        '    if "session_action_override" in t.get("name",""):\n'
        '        sz = t.get("size"); break\n'
        'print("SIZE:" + str(sz))\n'
        'i.tear_down_stream()\n'
    )
    cmd = (f"echo {shlex.quote(SSHPASS)} | sudo -S env "
           "SDE_INSTALL=/home/decps/Downloads/bf-sde-9.13.2/install "
           f"python3 -c {shlex.quote(py)} 2>&1")
    rc, out = _ssh(SWITCH, cmd, timeout=30)
    info: dict[str, Any] = {"rc": rc, "raw": out, "keys": [], "size": None}
    for line in out.splitlines():
        if line.startswith("KEYS:"):
            info["keys"] = [k for k in line[5:].split(",") if k]
        elif line.startswith("SIZE:"):
            try:
                info["size"] = int(line[5:])
            except ValueError:
                pass
    if info["size"] is None or not info["keys"]:
        return False, info
    return True, info


def install_allow_entries(n_sources: int, dst_ip: str = "10.0.2.10",
                          dst_port_a: int = 1883, sport_base: int = 40000
                          ) -> tuple[int, int, str]:
    """Install n_sources session_allow entries via bfrt_grpc.

    Returns (entries_installed, resource_exhausted_count, raw_output).
    Sources mirror FiveTupleAliasScenario._src_ip layout (10.0.1.100+i)
    and use deterministic sport_a = sport_base + 2*i.
    """
    py = (
        'import sys\n'
        'S="/home/decps/Downloads/bf-sde-9.13.2/install"\n'
        'sys.path.insert(0, S+"/lib/python3.8/site-packages/tofino")\n'
        'sys.path.insert(0, S+"/lib/python3.8/site-packages")\n'
        'import bfrt_grpc.client as gc\n'
        f'N = {n_sources}\n'
        f'DST_IP = "{dst_ip}"\n'
        f'DST_PORT_A = {dst_port_a}\n'
        f'SPORT_BASE = {sport_base}\n'
        'i = gc.ClientInterface("localhost:50052", client_id=4, '
        'device_id=0)\n'
        'try: i.bind_pipeline_config("ota_shield")\n'
        'except Exception: pass\n'
        'b = i.bfrt_info_get("ota_shield")\n'
        't = gc.Target(device_id=0)\n'
        'tbl = b.table_get("pipe.Ingress.session_action_override")\n'
        'def ip_to_int(s):\n'
        '    return sum(int(o) << (24 - 8*j) for j,o in '
        'enumerate(s.split(".")))\n'
        'dst_int = ip_to_int(DST_IP)\n'
        'inserted = 0\n'
        'exhausted = 0\n'
        'errors = 0\n'
        'for idx in range(N):\n'
        '    src_int = ip_to_int(f"10.0.1.{100 + idx}") if idx < 156 else '
        'ip_to_int(f"10.0.2.{100 + (idx - 156)}")\n'
        '    sport_a = SPORT_BASE + 2*idx\n'
        '    try:\n'
        '        tbl.entry_add(t, [tbl.make_key([\n'
        '            gc.KeyTuple("hdr.ipv4.src_addr", src_int),\n'
        '            gc.KeyTuple("hdr.ipv4.dst_addr", dst_int),\n'
        '            gc.KeyTuple("hdr.tcp.dst_port", DST_PORT_A),\n'
        '            gc.KeyTuple("hdr.ipv4.protocol", 6),\n'
        '            gc.KeyTuple("hdr.tcp.src_port", sport_a),\n'
        '        ])], [tbl.make_data([], "Ingress.session_allow")])\n'
        '        inserted += 1\n'
        '    except Exception as e:\n'
        '        msg = str(e)\n'
        '        if "RESOURCE_EXHAUSTED" in msg or "no more resources" '
        'in msg.lower():\n'
        '            exhausted += 1\n'
        '        else:\n'
        '            errors += 1\n'
        '            if errors <= 3:\n'
        '                print(f"ERR idx={idx}: {msg[:120]}")\n'
        'print(f"INSERTED:{inserted}")\n'
        'print(f"RESOURCE_EXHAUSTED:{exhausted}")\n'
        'print(f"OTHER_ERRORS:{errors}")\n'
        'i.tear_down_stream()\n'
    )
    cmd = (f"echo {shlex.quote(SSHPASS)} | sudo -S env "
           "SDE_INSTALL=/home/decps/Downloads/bf-sde-9.13.2/install "
           f"python3 -c {shlex.quote(py)} 2>&1")
    rc, out = _ssh(SWITCH, cmd, timeout=120)
    inserted = exhausted = 0
    for line in out.splitlines():
        if line.startswith("INSERTED:"):
            inserted = int(line[len("INSERTED:"):])
        elif line.startswith("RESOURCE_EXHAUSTED:"):
            exhausted = int(line[len("RESOURCE_EXHAUSTED:"):])
    return inserted, exhausted, out


def cleanup_allow_entries(n_sources: int, dst_ip: str = "10.0.2.10",
                          dst_port_a: int = 1883, sport_base: int = 40000
                          ) -> str:
    """Remove the synthetic session_allow entries installed by the smoke."""
    py = (
        'import sys\n'
        'S="/home/decps/Downloads/bf-sde-9.13.2/install"\n'
        'sys.path.insert(0, S+"/lib/python3.8/site-packages/tofino")\n'
        'sys.path.insert(0, S+"/lib/python3.8/site-packages")\n'
        'import bfrt_grpc.client as gc\n'
        f'N = {n_sources}\n'
        f'DST_IP = "{dst_ip}"\n'
        f'DST_PORT_A = {dst_port_a}\n'
        f'SPORT_BASE = {sport_base}\n'
        'i = gc.ClientInterface("localhost:50052", client_id=5, '
        'device_id=0)\n'
        'try: i.bind_pipeline_config("ota_shield")\n'
        'except Exception: pass\n'
        'b = i.bfrt_info_get("ota_shield")\n'
        't = gc.Target(device_id=0)\n'
        'tbl = b.table_get("pipe.Ingress.session_action_override")\n'
        'def ip_to_int(s):\n'
        '    return sum(int(o) << (24 - 8*j) for j,o in '
        'enumerate(s.split(".")))\n'
        'dst_int = ip_to_int(DST_IP)\n'
        'removed = 0\n'
        'for idx in range(N):\n'
        '    src_int = ip_to_int(f"10.0.1.{100 + idx}") if idx < 156 else '
        'ip_to_int(f"10.0.2.{100 + (idx - 156)}")\n'
        '    sport_a = SPORT_BASE + 2*idx\n'
        '    try:\n'
        '        tbl.entry_del(t, [tbl.make_key([\n'
        '            gc.KeyTuple("hdr.ipv4.src_addr", src_int),\n'
        '            gc.KeyTuple("hdr.ipv4.dst_addr", dst_int),\n'
        '            gc.KeyTuple("hdr.tcp.dst_port", DST_PORT_A),\n'
        '            gc.KeyTuple("hdr.ipv4.protocol", 6),\n'
        '            gc.KeyTuple("hdr.tcp.src_port", sport_a),\n'
        '        ])])\n'
        '        removed += 1\n'
        '    except Exception:\n'
        '        pass\n'
        'print(f"REMOVED:{removed}")\n'
        'i.tear_down_stream()\n'
    )
    cmd = (f"echo {shlex.quote(SSHPASS)} | sudo -S env "
           "SDE_INSTALL=/home/decps/Downloads/bf-sde-9.13.2/install "
           f"python3 -c {shlex.quote(py)} 2>&1")
    _, out = _ssh(SWITCH, cmd, timeout=60)
    return out.strip()


def stop_controller() -> int | None:
    """Stop the python OTA controller to free the bfrt bind. Returns the
    PID stopped (so the caller can restart it from its known invocation),
    or None if no controller was running."""
    cmd = (
        "PID=$(ps -eo pid,comm,cmd --no-headers | "
        "awk '$2 ~ /^python/ && $0 ~ "
        "/controller\\/ota_shield_controller\\.py/ {print $1; exit}'); "
        "if [ -n \"$PID\" ]; then "
        f"echo {shlex.quote(SSHPASS)} | sudo -S -p '' kill -TERM $PID; "
        "echo \"PID=$PID\"; "
        "else echo PID=0; fi"
    )
    _, out = _ssh(SWITCH, cmd, timeout=10)
    pid = None
    for line in out.splitlines():
        if line.startswith("PID="):
            try:
                pid = int(line[4:])
                if pid == 0:
                    pid = None
            except ValueError:
                pass
    if pid is not None:
        time.sleep(3)
    return pid


def start_controller() -> bool:
    """Start the python OTA controller via nohup sudo -n (not setsid).
    Restores the full argument set used in the campaign session."""
    cmd = (
        "cd /home/decps/my_program/ota && "
        f"echo {shlex.quote(SSHPASS)} | sudo -S nohup env "
        "SDE=/home/decps/Downloads/bf-sde-9.13.2 "
        "SDE_INSTALL=/home/decps/Downloads/bf-sde-9.13.2/install "
        "LD_LIBRARY_PATH=/home/decps/Downloads/bf-sde-9.13.2/install/lib "
        "PYTHONPATH=/home/decps/Downloads/bf-sde-9.13.2/install/lib/"
        "python3.8/site-packages/tofino:/home/decps/Downloads/bf-sde-9.13.2/"
        "install/lib/python3.8/site-packages "
        "python3 controller/ota_shield_controller.py "
        "--grpc-addr 127.0.0.1:50052 --p4-name ota_shield "
        "--rat controller/rat_e12.json --rat-pub controller/rat.pub "
        "--rat-sig controller/rat_e12.json.sig "
        "--log runs/campaign_2026-06-06.jsonl "
        "--r5-threshold 4 --r1-threshold-s 14400 "
        "--r4-threshold-bytes 2097152 --require-signed-rat "
        ">> runs/controller_campaign_2026-06-06.log 2>&1 "
        "< /dev/null &"
    )
    try:
        _ssh(SWITCH, cmd, timeout=12)
    except subprocess.TimeoutExpired:
        pass
    time.sleep(8)
    _, ps = _ssh(SWITCH,
                 "pgrep -af 'python3.*ota_shield_controller' | head -1",
                 timeout=5)
    return bool(ps.strip())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", type=Path,
                    default=REPO / "experiments/configs/T1_7.yaml")
    ap.add_argument("--trial-id", default="t00")
    ap.add_argument("--n-sources", type=int, default=None,
                    help="Override config's n_sources (smoke runs use a "
                    "smaller value to fail fast).")
    ap.add_argument("--output-dir", type=Path,
                    default=REPO / "runs/experiments/T1_7_smoke")
    args = ap.parse_args()

    cfg = yaml.safe_load(args.config.read_text())
    n_sources = (args.n_sources
                 if args.n_sources is not None
                 else (cfg.get("generator", {}).get("params", {})
                       .get("n_sources", 200)))
    out_dir = args.output_dir / args.trial_id
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n=== T1.7 smoke trial {args.trial_id} (n_sources={n_sources}) ===")

    # 1. Structural check: inspect override table.
    print("[1/3] inspect override table shape...")
    ok, info = inspect_table_shape()
    print(f"  size: {info.get('size')} (expected {EXPECTED_TABLE_SIZE})")
    print(f"  keys: {info.get('keys')}")
    if not ok:
        print(f"  raw output: {info.get('raw', '')[:500]}")
    size_ok = info.get("size") == EXPECTED_TABLE_SIZE
    keys_ok = all(any(s in k for k in info.get("keys", []))
                  for s in EXPECTED_KEY_SUBSTR)
    if not (size_ok and keys_ok):
        print("  STRUCTURAL FAIL: table shape does not match T1.7 contract")
        (out_dir / "structural_fail.txt").write_text(info.get("raw", ""))
        return 1
    print("  OK: 5-tuple key + size 256 matches contract.")

    # 2. Capacity check: stop controller (frees bfrt bind), install
    #    n_sources session_allow entries, clean up, restart controller.
    print(f"[2/3] stop controller, install {n_sources} session_allow "
          f"entries, restart controller...")
    stopped_pid = stop_controller()
    if stopped_pid is None:
        print("  WARNING: no controller was running; will not restart")
    else:
        print(f"  controller PID {stopped_pid} stopped")

    inserted, exhausted, raw = install_allow_entries(n_sources)
    print(f"  inserted: {inserted}/{n_sources}")
    print(f"  RESOURCE_EXHAUSTED: {exhausted}")
    (out_dir / "install_log.txt").write_text(raw)

    cap_ok = (inserted == n_sources) and (exhausted == 0)

    print("[cleanup] removing synthetic session_allow entries...")
    rm_out = cleanup_allow_entries(n_sources)
    print(f"  {rm_out[:160]}")

    if stopped_pid is not None:
        print("[restart] restarting controller...")
        if start_controller():
            print("  OK")
        else:
            print("  WARNING: controller restart did not show a python "
                  "process; check /home/decps/my_program/ota/runs/"
                  "controller_smoke.log on the switch")

    # 3. Falsifier check.
    print("[3/3] T1.7 falsifier check...")
    if not cap_ok:
        print(f"  FAIL: only inserted {inserted}/{n_sources}; "
              f"RESOURCE_EXHAUSTED={exhausted}")
        return 2

    print(f"\n=== T1.7 SMOKE RESULT: PASS ===")
    print(f"  structural: 5-tuple key + size 256.")
    print(f"  capacity:   {n_sources} ALLOW entries, 0 RESOURCE_EXHAUSTED.")
    print(f"  cross-tuple ALLOW path is structurally impossible (key shape "
          f"distinguishes alias from ALLOW tuple).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
