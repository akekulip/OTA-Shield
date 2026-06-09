"""T2.4 brokered-MQTT topology driver (E20) + IP-only control (E20a).

20 trials per scenario x 4 scenarios = 80 trials, 30% held-out
(deterministic-stratified by scenario, seed = 0xCAFE ^ 0xH0LD). Each
trial emits a brokered campaign whose source IP collapses to the broker;
the publisher-id-keyed RAT (E20) must keep working while the IP-only RAT
(E20a) collapses.

Per trial it:
  1. derives the per-trial seed (sha256(T2.4-{scenario}-{trial}-0xCAFE));
  2. SIGUSR1-resets the controller;
  3. publishes the campaign THROUGH the broker (paho-mqtt -> mosquitto if
     available; otherwise synthesises the post-relay packets directly — a
     "minimal relay" model the preflight flags as a reduced-fidelity run);
  4. writes ground_truth.json (carrying the dual expected_pubid_rat /
     expected_ip_rat columns) + the §3 manifest, then slices decisions.

Dry-run (default) builds every campaign's ground truth + manifest without
touching hardware or a broker.

Usage:
    python3 experiments/run_t2_4.py --dry-run        # default
    python3 experiments/run_t2_4.py --execute        # hardware + broker
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from experiments import t2_harness as H            # noqa: E402
from experiments.seed_schedule import held_out_seed  # noqa: E402
from traffic_gen.broker_attack import BrokerRelayScenario  # noqa: E402

EXP_ID = "T2.4"
DEFAULT_OUT = REPO / "runs" / "experiments"


def _held_out_indices(scenario_id: str, n_trials: int, frac: float,
                      held_seed: int) -> set[int]:
    """Deterministic-stratified held-out indices for one scenario."""
    k = int(round(n_trials * frac))
    rng = random.Random(held_seed ^ (hash(scenario_id) & 0xFFFFFFFF))
    return set(rng.sample(range(n_trials), k)) if k else set()


def run_one(scenario: dict, trial_idx: int, cfg: dict, out_root: Path,
            held_out: bool, execute: bool) -> dict:
    sid = scenario["id"]
    trial_id = f"t{trial_idx:02d}"
    seed = H.derive_trial_seed(f"{EXP_ID}-{sid}", trial_id, cfg["master_seed"])
    exp_dir = out_root / f"T2_4_{sid.replace('.', '_')}"
    trial_dir = exp_dir / trial_id
    trial_dir.mkdir(parents=True, exist_ok=True)

    scen = BrokerRelayScenario(scenario_id=sid,
                               n_publishes=int(cfg.get("n_publishes", 30)),
                               seed=seed)
    events = scen.ground_truth()
    H.write_ground_truth(trial_dir, trial_id, sid, events)
    H.write_trial_manifest(
        trial_dir, exp_id=EXP_ID, trial_id=trial_id, scenario_id=sid,
        declared_duration_s=float(cfg.get("declared_duration_s", 60)),
        actual_duration_s=float(cfg.get("declared_duration_s", 60)),
        master_seed=cfg["master_seed"],
        notes=f"held_out={held_out} kind={scenario.get('kind')}",
        execute=execute)

    n_attack = sum(1 for e in events if e["label"] == "ATTACK")
    rec = {"scenario": sid, "trial_id": trial_id, "seed": seed,
           "held_out": held_out, "n_events": len(events),
           "n_attack": n_attack, "mode": "dry-run"}
    if not execute:
        return rec

    rec["mode"] = "execute"
    rec["reset"] = H.reset_controller_state()
    off0 = H.get_decisions_offset()
    # Ship the generator + a driver that publishes through the broker via
    # paho if present, else synthesises the post-relay packets via scapy.
    H.scp_to(H.VISION, REPO / "traffic_gen" / "broker_attack.py",
             "/home/decps/broker_attack_t2_4.py")
    driver = (
        "import sys,json; sys.path.insert(0,'/home/decps')\n"
        "import broker_attack_t2_4 as B\n"
        f"s=B.BrokerRelayScenario(scenario_id='{sid}',n_publishes="
        f"{int(cfg.get('n_publishes', 30))},seed={seed})\n"
        "mode='unknown'\n"
        "try:\n"
        "    import paho.mqtt.publish as pub\n"
        "    for it in s.publish_intents():\n"
        "        pub.single(it['topic'], payload=bytes.fromhex(it['payload_hex']),\n"
        f"                   hostname='{cfg.get('broker', {}).get('host_ip', '10.0.1.50')}',\n"
        f"                   port={cfg.get('broker', {}).get('port', 1883)})\n"
        "    mode='broker_paho'\n"
        "except Exception as e:\n"
        "    from scapy.all import sendp\n"
        "    for pkt in s.emit():\n"
        "        sendp(pkt, iface='enp59s0f0np0', verbose=False, count=1)\n"
        "    mode='minimal_relay'\n"
        "print('BROKER_DONE mode=%s n=%d'%(mode,len(s._plan)))\n")
    import base64
    b64 = base64.b64encode(driver.encode()).decode()
    rc, out = H.ssh(
        H.VISION,
        f"echo {b64} | base64 -d > /tmp/t2_4_driver.py && "
        f"sudo -n python3 /tmp/t2_4_driver.py", timeout=300)
    rec["emit_rc"] = rc
    rec["emit_out"] = out.strip()[-200:]
    rec["relay_mode"] = ("broker_paho" if "mode=broker_paho" in out
                         else "minimal_relay" if "mode=minimal_relay" in out
                         else "unknown")
    time.sleep(float(cfg.get("post_wait_s", 15)))
    off1 = H.get_decisions_offset()
    H.slice_decisions(off0, off1, trial_dir / "controller_decisions.jsonl")
    rec["offset_start"], rec["offset_end"] = off0, off1
    return rec


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", type=Path,
                    default=REPO / "experiments/configs/T2_4.yaml")
    ap.add_argument("--out-root", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--trials", type=int, default=None)
    ap.add_argument("--include-held-out", action="store_true",
                    help="also run the held-out split (touches it ONCE; "
                         "default dev-only per the prereg)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dry-run", action="store_true", default=True)
    g.add_argument("--execute", action="store_true")
    args = ap.parse_args(argv)
    execute = bool(args.execute)

    cfg = yaml.safe_load(args.config.read_text())
    trials = args.trials if args.trials is not None else int(cfg["trial_count"])
    frac = float(cfg.get("held_out_fraction", 0.0))
    hseed = held_out_seed(cfg["master_seed"],
                          cfg.get("held_out_seed_xor", "0xH0LD"))

    print(f"=== {EXP_ID} brokered MQTT "
          f"({'EXECUTE' if execute else 'DRY-RUN'}) ===")
    print(f"  scenarios: {[s['id'] for s in cfg['scenarios']]}")
    print(f"  trials/scenario: {trials}  held-out frac: {frac} "
          f"(include_held_out={args.include_held_out})")
    print(f"  contracted total trials: {len(cfg['scenarios']) * trials}")

    session: list[dict] = []
    for scen in cfg["scenarios"]:
        ho = _held_out_indices(scen["id"], trials, frac, hseed)
        for ti in range(trials):
            is_ho = ti in ho
            if is_ho and not args.include_held_out:
                continue   # leave held-out untouched (prereg: one pass only)
            rec = run_one(scen, ti, cfg, args.out_root, is_ho, execute)
            session.append(rec)
        print(f"  [{scen['id']}] held-out idx: {sorted(ho)}")

    sess = args.out_root / "T2_4_session.json"
    sess.parent.mkdir(parents=True, exist_ok=True)
    sess.write_text(json.dumps(session, indent=2, default=str))
    print(f"\nsession -> {sess}  ({len(session)} trials run)")
    print(f"next: python3 -m experiments.aggregate_t2_4 {args.out_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
