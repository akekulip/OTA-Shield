"""Runs a single experimental trial on Vision.

Called via SSH from the workstation's sweep.py. Reads a YAML config via
stdin or --config, invokes the right scenario pack from scenarios.py,
then dumps ground-truth events to --out-json.

The controller-side digest log is collected separately by sweep.py via
SSH to the switch; we pair ground-truth events here with decisions there
in aggregate.py by (src_ip, dst_ip, src_port) keys.
"""
from __future__ import annotations
import argparse, dataclasses, json, sys, time
from pathlib import Path

import scenarios


def load_config(path: Path) -> dict:
    if path.suffix in (".yaml", ".yml"):
        import yaml
        return yaml.safe_load(path.read_text())
    return json.loads(path.read_text())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, type=Path)
    ap.add_argument("--out-json", required=True, type=Path)
    ap.add_argument("--trial-id", required=True)
    args = ap.parse_args()

    cfg = load_config(args.config)
    scenario_name = cfg["scenario"]
    params = cfg.get("params", {})

    t_start = time.time()
    events: list[scenarios.GroundTruthEvent] = []
    if scenario_name == "legit_rollout":
        events = scenarios.legit_rollout(**params)
    elif scenario_name == "a5_replay":
        events = scenarios.a5_replay(**params)
    elif scenario_name == "a3_unauthorized":
        events = scenarios.a3_unauthorized(**params)
    elif scenario_name == "a4_oversize":
        events = scenarios.a4_oversize(**params)
    elif scenario_name == "a1_fleet_fanout":
        events = scenarios.a1_fleet_fanout(**params)
    elif scenario_name == "pack_attack_sweep":
        events = scenarios.pack_attack_sweep(**params)
    elif scenario_name == "pack_adversarial_near_threshold":
        events = scenarios.pack_adversarial_near_threshold()
    elif scenario_name == "pack_stochastic_e1":
        events = scenarios.pack_stochastic_e1(**params)
    elif scenario_name == "pack_evasion_r1":
        events = scenarios.pack_evasion_r1(**params)
    elif scenario_name == "pack_evasion_r4":
        events = scenarios.pack_evasion_r4(**params)
    elif scenario_name == "pack_evasion_r5":
        events = scenarios.pack_evasion_r5(**params)
    elif scenario_name == "pack_long_baseline":
        events = scenarios.pack_long_baseline(**params)
    elif scenario_name == "pack_benign_rollout_stress":
        events = scenarios.pack_benign_rollout_stress(**params)
    elif scenario_name == "pack_benign_rollout_signed":
        # E12b signed-manifest rerun (reviewer item M6). Lives in a
        # separate module so the signed-path two-phase logic and the
        # Phase-B inject marker don't bloat scenarios.py.
        import scenarios_e12b
        events = scenarios_e12b.pack_benign_rollout_signed(**params)
    elif scenario_name == "pack_mimicry_e17":
        events = scenarios.pack_mimicry_e17(**params)
    elif scenario_name == "pack_rollback_e19":
        events = scenarios.pack_rollback_e19(**params)
    elif scenario_name == "pack_rollback_e19_stochastic":
        # Inject trial_idx from trial-id suffix (e.g. "…_t07" → 7) so the
        # stochastic pack can derive a per-trial seed without sweep.py
        # having to know the scenario's internal parameter names.
        import re as _re
        m = _re.search(r"_t(\d+)$", args.trial_id)
        params.pop("seed", None)
        if m is not None and "trial_idx" not in params:
            params["trial_idx"] = int(m.group(1))
        events = scenarios.pack_rollback_e19_stochastic(**params)
    else:
        sys.exit(f"Unknown scenario {scenario_name}")
    t_end = time.time()

    out = {
        "trial_id": args.trial_id,
        "config": cfg,
        "t_start": t_start,
        "t_end": t_end,
        "n_events": len(events),
        "events": [dataclasses.asdict(e) for e in events],
    }
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(out, indent=2))
    print(f"[trial {args.trial_id}] {len(events)} events, "
          f"{t_end - t_start:.1f}s")


if __name__ == "__main__":
    main()
