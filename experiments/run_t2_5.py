"""T2.5 / T2.5a / T2.5b mimicry per-strategy driver (E17b / E21).

Runs 30 trials (locked) of the five-strategy mimicry campaign
(scenarios.pack_mimicry_e17). Each trial campaign exercises all five
strategies once, so the per-strategy detection rate is computed over
30 trial-instances per strategy and the fully-invisible-campaign rate
(T2.5b) is computed over the 30 campaigns.

Per trial it:
  1. derives the per-trial seed (sha256(T2.5-{trial}-0xCAFE)), which the
     mimicry generators use to disjoin their ephemeral 5-tuple space;
  2. SIGUSR1-resets the controller (clears override / hold_armed_reg) so a
     prior trial's overrides cannot leak into this one;
  3. emits the campaign on Vision and captures the controller decisions;
  4. writes ground_truth.json + the §3 reproducibility manifest.

Dry-run (default) builds the per-trial ground truth by invoking the
generators with packet-send and sleeps disabled, so the planned event
structure (per-strategy counts, 5-tuple layout, GT labels) and the
manifests exist without touching hardware.

Usage:
    python3 experiments/run_t2_5.py --dry-run            # default
    python3 experiments/run_t2_5.py --execute            # hardware
    python3 experiments/run_t2_5.py --trials 2 --dry-run # smoke
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

EXP_ID = "T2.5"
DEFAULT_OUT = REPO / "runs" / "experiments" / "T2_5_mimicry"

# Canonical strategy order (matches pack_mimicry_e17 execution order).
STRATEGIES_ORDERED = [
    "mimicry_fanout_sub",
    "mimicry_fanout_three",
    "mimicry_r4_deadzone",
    "mimicry_combined",
    "mimicry_r1_late",
]

# Per-strategy Vision SSH timeouts (s).
# fanout_* run 6 cycles × 65 s inter-cycle gap; combined 3 × 65 s.
_STRATEGY_TIMEOUT: dict[str, int] = {
    "mimicry_fanout_sub":   700,
    "mimicry_fanout_three": 700,
    "mimicry_r4_deadzone":   60,
    "mimicry_combined":     400,
    "mimicry_r1_late":       60,
}


def _plan_campaign(seed: int, only_strategy: str | None = None) -> list[dict]:
    """Build the planned per-trial ground truth WITHOUT emitting packets.

    Imports scenarios.py and neutralises packet send + sleeps, then runs
    pack_mimicry_e17(seed) (or a single strategy when ``only_strategy`` is
    set) to obtain the genuine GroundTruthEvent plan.
    """
    import experiments.scenarios as S
    orig_send = S._send
    orig_sleep = S.time.sleep
    S._send = lambda *a, **k: None          # type: ignore[assignment]
    S.time.sleep = lambda *a, **k: None      # type: ignore[assignment]
    try:
        if only_strategy:
            events = S.mimicry_single(only_strategy, seed=seed)
        else:
            events = S.pack_mimicry_e17(seed=seed)
    finally:
        S._send = orig_send                  # type: ignore[assignment]
        S.time.sleep = orig_sleep            # type: ignore[assignment]
    out: list[dict] = []
    for e in events:
        out.append({
            "t_send": e.t_send, "scenario": e.scenario, "label": e.label,
            "src_ip": e.src_ip, "dst_ip": e.dst_ip, "src_port": e.src_port,
            "dst_port": 1883, "topic": e.topic, "ota_size": e.ota_size,
            "ota_version": e.ota_version, "note": e.note,
        })
    return out


def _build_and_run_emit(emit_call: str, timeout: int) -> tuple[int, str]:
    """Build the base64-encoded remote driver and run it on VISION."""
    import base64
    driver = (
        "import json,sys; sys.path.insert(0,'/home/decps')\n"
        "import scenarios_t2_5 as S\n"
        f"evs={emit_call}\n"
        "out=[{'t_send':e.t_send,'scenario':e.scenario,'label':e.label,"
        "'src_ip':e.src_ip,'dst_ip':e.dst_ip,'src_port':e.src_port,"
        "'dst_port':1883,'topic':e.topic,'ota_size':e.ota_size,"
        "'ota_version':e.ota_version} for e in evs]\n"
        "open('/tmp/t2_5_gt.json','w').write(json.dumps(out))\n"
        "print('CAMPAIGN_DONE n=%d'%len(out))\n")
    b64 = base64.b64encode(driver.encode()).decode()
    return H.ssh(
        H.VISION,
        f"echo {b64} | base64 -d > /tmp/t2_5_driver.py && "
        f"sudo -n python3 /tmp/t2_5_driver.py",
        timeout=timeout)


def run_one(trial_idx: int, cfg: dict, out_dir: Path, execute: bool,
            only_strategy: str | None = None,
            per_strategy_reset: bool = True) -> dict:
    """Run one trial.

    When ``per_strategy_reset=True`` (default, T2.5a):
      Each of the 5 strategies is emitted in isolation with a SIGUSR1
      reset between them, so hold_armed_reg / Bloom / session state cannot
      cascade across strategies.  Per-strategy detection rates are cleanly
      attributable to each strategy's target rule.

    When ``per_strategy_reset=False`` (T2.5b / --no-per-strategy-reset):
      The continuous pack_mimicry_e17 campaign is emitted in one shot with
      no intra-campaign reset.  The T2.5b "fully-invisible-campaign" metric
      (campaigns with zero catches) is only meaningful in this mode.
    """
    trial_id = f"t{trial_idx:02d}"
    seed = H.derive_trial_seed(EXP_ID, trial_id, cfg["master_seed"])
    trial_dir = out_dir / trial_id
    trial_dir.mkdir(parents=True, exist_ok=True)

    planned = _plan_campaign(seed, only_strategy=only_strategy)
    H.write_ground_truth(trial_dir, trial_id, "mimicry_e17", planned)
    H.write_trial_manifest(
        trial_dir, exp_id=EXP_ID, trial_id=trial_id, scenario_id="mimicry_e17",
        declared_duration_s=float(cfg.get("declared_duration_s", 280)),
        actual_duration_s=float(cfg.get("declared_duration_s", 280)),
        master_seed=cfg["master_seed"], notes=f"seed={seed}", execute=execute)

    # per-strategy planned counts (for visibility).
    by_strat: dict[str, int] = {}
    for e in planned:
        by_strat[e["scenario"]] = by_strat.get(e["scenario"], 0) + 1

    rec = {"trial_id": trial_id, "seed": seed, "n_events": len(planned),
           "per_strategy": by_strat, "mode": "dry-run",
           "per_strategy_reset": per_strategy_reset}
    if not execute:
        return rec

    rec["mode"] = "execute"
    # Initial trial-level reset (always); clears hold_armed_reg, Bloom, session.
    rec["reset"] = H.reset_controller_state()
    H.scp_to(H.VISION, REPO / "experiments" / "scenarios.py",
             "/home/decps/scenarios_t2_5.py")

    if not per_strategy_reset:
        # ----------------------------------------------------------------
        # T2.5b / continuous-campaign path (no intra-campaign reset).
        # T2.5b "fully-invisible-campaign" metric is meaningful here only.
        # ----------------------------------------------------------------
        if only_strategy:
            emit_call = f"S.mimicry_single({only_strategy!r}, seed={seed})"
            emit_timeout = 600
        else:
            emit_call = f"S.pack_mimicry_e17(seed={seed})"
            emit_timeout = 1500
        off0 = H.get_decisions_offset()
        rc, sout = _build_and_run_emit(emit_call, emit_timeout)
        rec["emit_rc"] = rc
        rec["emit_out"] = sout.strip()[-200:]
        try:
            H.scp_from(H.VISION, "/tmp/t2_5_gt.json",
                       trial_dir / "vision_gt.json")
            live = json.loads((trial_dir / "vision_gt.json").read_text())
            H.write_ground_truth(trial_dir, trial_id, "mimicry_e17", live)
            rec["n_events"] = len(live)
        except Exception as exc:
            rec["gt_pull_error"] = str(exc)
        time.sleep(float(cfg.get("post_wait_s", 10)))
        off1 = H.get_decisions_offset()
        H.slice_decisions(off0, off1, trial_dir / "controller_decisions.jsonl")
        rec["offset_start"], rec["offset_end"] = off0, off1

    else:
        # ----------------------------------------------------------------
        # T2.5a / per-strategy-isolated path (--per-strategy-reset, default).
        # Each strategy emitted separately with a SIGUSR1 reset between them.
        # hold_armed_reg / Bloom / session cannot cascade across strategies,
        # so each strategy's caught count is attributable to its target rule.
        # NOTE: T2.5b "fully-invisible-campaign" is NOT meaningful in this
        # mode (each strategy sees a fresh state). Run with
        # --no-per-strategy-reset to score T2.5b.
        # ----------------------------------------------------------------
        strategies = ([only_strategy] if only_strategy else STRATEGIES_ORDERED)
        all_live_events: list[dict] = []
        all_dec_chunks: list[str] = []
        per_strat_resets: list[str] = []
        offsets_per_strat: list[tuple[int, int]] = []

        for i, strat in enumerate(strategies):
            if i > 0:
                # Reset between strategies: clears hold_armed_reg / Bloom.
                per_strat_resets.append(H.reset_controller_state())
            off_s = H.get_decisions_offset()
            emit_call = f"S.mimicry_single({strat!r}, seed={seed})"
            timeout = _STRATEGY_TIMEOUT.get(strat, 700)
            rc, sout = _build_and_run_emit(emit_call, timeout)
            rec.setdefault("emit_rc", {})[strat] = rc
            rec.setdefault("emit_out", {})[strat] = sout.strip()[-200:]
            try:
                dest = trial_dir / f"vision_gt_{strat}.json"
                H.scp_from(H.VISION, "/tmp/t2_5_gt.json", dest)
                strat_events = json.loads(dest.read_text())
                all_live_events.extend(strat_events)
            except Exception as exc:
                rec.setdefault("gt_pull_errors", {})[strat] = str(exc)
            time.sleep(float(cfg.get("post_wait_s", 10)))
            off_e = H.get_decisions_offset()
            offsets_per_strat.append((off_s, off_e))
            strat_dec = trial_dir / f"dec_{strat}.jsonl"
            H.slice_decisions(off_s, off_e, strat_dec)
            if strat_dec.exists():
                chunk = strat_dec.read_text()
                if chunk.strip():
                    all_dec_chunks.append(chunk)

        rec["per_strategy_resets"] = per_strat_resets
        rec["offsets_per_strategy"] = offsets_per_strat
        # Combine per-strategy decision slices; 5-tuple spaces are disjoint
        # (different sport_base per strategy), so concatenation is safe.
        (trial_dir / "controller_decisions.jsonl").write_text(
            "".join(all_dec_chunks))
        if all_live_events:
            H.write_ground_truth(trial_dir, trial_id, "mimicry_e17",
                                 all_live_events)
            rec["n_events"] = len(all_live_events)

    return rec


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", type=Path,
                    default=REPO / "experiments/configs/T2_5.yaml")
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--trials", type=int, default=None)
    ap.add_argument("--only-strategy", default=None,
                    help="emit ONLY this mimicry strategy per trial (smoke). "
                         "One of the config 'strategies' scenario names.")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dry-run", action="store_true", default=True)
    g.add_argument("--execute", action="store_true")
    # --per-strategy-reset (default ON) isolates each strategy for T2.5a.
    # Use --no-per-strategy-reset to run the continuous campaign for T2.5b.
    ap.add_argument("--per-strategy-reset", dest="per_strategy_reset",
                    action="store_true", default=True,
                    help="SIGUSR1 between strategies (T2.5a isolation, default).")
    ap.add_argument("--no-per-strategy-reset", dest="per_strategy_reset",
                    action="store_false",
                    help="Continuous campaign; T2.5b fully-invisible metric.")
    args = ap.parse_args(argv)
    execute = bool(args.execute)
    only_strategy = args.only_strategy
    per_strategy_reset = bool(args.per_strategy_reset)

    cfg = yaml.safe_load(args.config.read_text())
    if only_strategy and only_strategy not in cfg["strategies"]:
        print(f"--only-strategy {only_strategy!r} not in config strategies "
              f"{cfg['strategies']}")
        return 2
    trials = args.trials if args.trials is not None else int(cfg["trial_count"])
    reset_mode = ("per-strategy-reset (T2.5a)" if per_strategy_reset
                  else "no-per-strategy-reset (T2.5b continuous)")
    print(f"=== {EXP_ID} mimicry per-strategy "
          f"({'EXECUTE' if execute else 'DRY-RUN'}) | {reset_mode} ===")
    print(f"  strategies: {[only_strategy] if only_strategy else cfg['strategies']}")
    print(f"  trials (campaigns): {trials}  -> {trials} per strategy")
    if per_strategy_reset:
        print("  NOTE: T2.5b fully-invisible-campaign metric is NOT valid in "
              "this mode (each strategy sees fresh state). "
              "Run --no-per-strategy-reset for T2.5b.")

    session = []
    for ti in range(trials):
        rec = run_one(ti, cfg, args.out_dir, execute,
                      only_strategy=only_strategy,
                      per_strategy_reset=per_strategy_reset)
        session.append(rec)
        print(f"  {rec['trial_id']}: n_events={rec['n_events']} "
              f"seed={rec['seed']} strat_counts={rec['per_strategy']} "
              f"({rec['mode']})")

    sess = args.out_dir / "T2_5_session.json"
    sess.parent.mkdir(parents=True, exist_ok=True)
    sess.write_text(json.dumps(session, indent=2, default=str))
    print(f"\nsession -> {sess}")
    print(f"next: python3 -m experiments.aggregate_t2_5 {args.out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
