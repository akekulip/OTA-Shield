"""T2.6 fleet-scaling driver (E23) — 100 / 250 / 500 BMS.

Generalizes the 200-BMS M4 harness (run_m4_200bms.py + scenarios_m4.py) to
the three locked fleet sizes.  For each (fleet_size, trial) it:

  1. derives the per-trial seed (sha256(T2.6-{size}-{trial}-0xCAFE));
  2. builds a fleet pcap + labels via scenarios_m4.pack_fleet_scaling;
  3. writes ground_truth.json + the §3 reproducibility manifest;
  4. (execute only) extends + signs the RAT for the fleet, SIGUSR1-resets
     the controller, replays the pcap on Vision, drains, and slices the
     controller decision log into the trial dir, then records the peak
     override-table occupancy and observed R5 Bloom FP for the aggregator.

The default mode is a dry run that does NOT touch hardware: it produces
every pcap / ground-truth / manifest artifact so the contract deliverables
exist and the aggregator can be exercised on synthetic structure.

Contracted trial counts: 5 trials per fleet size, 3 sizes -> 15 trials.

Usage:
    python3 experiments/run_t2_6.py --dry-run            # default
    python3 experiments/run_t2_6.py --execute            # hardware
    python3 experiments/run_t2_6.py --fleet-size 500 --execute
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from experiments import t2_harness as H            # noqa: E402
from experiments.scenarios_m4 import pack_fleet_scaling  # noqa: E402

EXP_ID = "T2.6"
DEFAULT_OUT = REPO / "runs" / "experiments"


def _labels_to_events(labels_path: Path) -> list[dict]:
    labels = json.loads(labels_path.read_text())
    events: list[dict] = []
    for r in labels:
        events.append({
            "t_send": r.get("t_offset_s"),
            "scenario": r.get("scenario"),
            "label": r.get("label"),
            "src_ip": r.get("src_ip"),
            "dst_ip": r.get("dst_ip"),
            "src_port": r.get("src_port"),
            "dst_port": r.get("dst_port", 1883),
            "ota_size": r.get("ota_size"),
            "ota_version": r.get("ota_version"),
        })
    return events


def run_one(scenario: dict, trial_idx: int, cfg: dict, out_root: Path,
            execute: bool) -> dict:
    sid = scenario["id"]
    fleet_size = int(scenario["fleet_size"])
    scaled = bool(scenario.get("scaled_iat", fleet_size >= 500))
    trial_id = f"t{trial_idx:02d}"
    seed = H.derive_trial_seed(f"{EXP_ID}-{fleet_size}", trial_id,
                               cfg["master_seed"])
    exp_dir = out_root / f"T2_6_{sid.replace('.', '_')}"
    trial_dir = exp_dir / trial_id
    trial_dir.mkdir(parents=True, exist_ok=True)

    # 1. Build the fleet pcap + labels (deterministic from the seed).
    pack_dir = pack_fleet_scaling(
        trial_dir, fleet_size=fleet_size, seed=seed,
        duration_s=float(cfg.get("declared_duration_s", 120)),
        attack_fraction=float(cfg["generator"]["params"]["attack_fraction"]),
        scaled_iat=scaled)
    labels_path = pack_dir / "labels.json"
    events = _labels_to_events(labels_path)
    H.write_ground_truth(trial_dir, trial_id, sid, events)

    # 2. Manifest.
    H.write_trial_manifest(
        trial_dir, exp_id=EXP_ID, trial_id=trial_id, scenario_id=sid,
        declared_duration_s=float(cfg.get("declared_duration_s", 120)),
        actual_duration_s=float(cfg.get("declared_duration_s", 120)),
        master_seed=cfg["master_seed"],
        notes=f"fleet_size={fleet_size} scaled_iat={scaled}",
        execute=execute)

    rec = {"scenario": sid, "trial_id": trial_id, "fleet_size": fleet_size,
           "seed": seed, "n_events": len(events),
           "pcap": str(pack_dir / "traffic.pcap")}

    if not execute:
        rec["mode"] = "dry-run"
        return rec

    # 3. Hardware path (only with --execute + OTA_SSHPASS + live switch).
    rec["mode"] = "execute"
    reset = H.reset_controller_state()
    rec["reset"] = reset
    off0 = H.get_decisions_offset()
    remote_pcap = f"/tmp/t2_6_{sid.replace('.', '_')}_{trial_id}.pcap"
    H.scp_to(H.VISION, pack_dir / "traffic.pcap", remote_pcap)
    # Replay through the data-plane NIC via tcpreplay (2.2 kpps cap for
    # fleet-500). pps cap is enforced by the config's scaled IAT model.
    rc, out = H.ssh(
        H.VISION,
        f"sudo -n tcpreplay -i enp59s0f0np0 --pps=2200 {remote_pcap} 2>&1 "
        f"|| sudo -n python3 -c \"from scapy.all import rdpcap,sendp; "
        f"sendp(rdpcap('{remote_pcap}'),iface='enp59s0f0np0',verbose=False)\"",
        timeout=600)
    rec["replay_rc"] = rc
    rec["replay_out"] = out.strip()[-400:]
    time.sleep(float(cfg.get("post_wait_s", 30)))
    off1 = H.get_decisions_offset()
    H.slice_decisions(off0, off1, trial_dir / "controller_decisions.jsonl")
    rec["offset_start"] = off0
    rec["offset_end"] = off1

    # 4. Capture post-trial hardware state BEFORE the next SIGUSR1 reset.
    #    SIGUSR2 triggers the controller's handle_dump_state which writes
    #    r5_count, r5_bloom_nonzero, session_override_count etc. to
    #    /tmp/ota_controller_state.json.  This is read by aggregate_t2_6 to
    #    populate override_occupancy_peak and r5 bloom diagnostics.
    dump_out = H.dump_controller_state(wait_s=2.0)
    rec["dump_state_out"] = dump_out
    hw_state_path = trial_dir / "hw_state_post_trial.json"
    try:
        H.scp_from(H.SWITCH, H.CONTROLLER_STATE_DUMP, hw_state_path)
        hw_state = json.loads(hw_state_path.read_text())
        rec["override_occupancy"] = hw_state.get("session_override_count")
        rec["r5_bloom_nonzero"] = hw_state.get("r5_bloom_nonzero")
        rec["r5_count"] = hw_state.get("r5_count")
    except Exception as exc:
        rec["hw_state_error"] = str(exc)

    return rec


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", type=Path,
                    default=REPO / "experiments/configs/T2_6.yaml")
    ap.add_argument("--out-root", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--fleet-size", type=int, default=None,
                    help="restrict to one fleet size")
    ap.add_argument("--trials", type=int, default=None,
                    help="override trial count (default: from config)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dry-run", action="store_true", default=True)
    g.add_argument("--execute", action="store_true")
    args = ap.parse_args(argv)
    execute = bool(args.execute)

    cfg = yaml.safe_load(args.config.read_text())
    trials = args.trials if args.trials is not None else int(cfg["trial_count"])
    scenarios = cfg["scenarios"]
    if args.fleet_size is not None:
        scenarios = [s for s in scenarios
                     if int(s["fleet_size"]) == args.fleet_size]
        if not scenarios:
            print(f"no scenario with fleet_size={args.fleet_size}")
            return 2

    print(f"=== {EXP_ID} fleet scaling ({'EXECUTE' if execute else 'DRY-RUN'}) ===")
    print(f"  scenarios: {[s['id'] for s in scenarios]}  trials/size: {trials}")
    print(f"  contracted total trials: {len(scenarios) * trials}")

    session: list[dict] = []
    for scen in scenarios:
        for ti in range(trials):
            rec = run_one(scen, ti, cfg, args.out_root, execute)
            session.append(rec)
            print(f"  [{scen['id']}] {rec['trial_id']}: "
                  f"n_events={rec['n_events']} seed={rec['seed']} "
                  f"({rec['mode']})")

    sess_path = args.out_root / "T2_6_session.json"
    sess_path.parent.mkdir(parents=True, exist_ok=True)
    sess_path.write_text(json.dumps(session, indent=2, default=str))
    print(f"\nsession -> {sess_path}")
    print(f"next: python3 -m experiments.aggregate_t2_6 {args.out_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
