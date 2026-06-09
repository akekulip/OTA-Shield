"""T2.8 TCP-evasion battery driver.

5 evasions x 5 rules = 25 cells; 10 trials per cell = 250 trials. Each
trial of a cell emits the cell's evaded base-attack on a per-trial-unique
5-tuple and records whether the controller still DROPs it, so the
aggregator can build the predicted-vs-observed detection heatmap (Table 9
/ Fig F15).

Per trial it:
  1. derives the per-cell-per-trial seed
     (sha256(T2.8-{evasion}-{rule}-{trial}-0xCAFE));
  2. builds the cell's TCP segments (traffic_gen.tcp_evasion);
  3. writes ground_truth.json (one ATTACK event carrying the predicted
     detection) + the §3 manifest;
  4. (execute only) SIGUSR1-resets the controller, emits the cell's
     segments on Vision, drains, and slices the controller decisions.

Dry-run (default) builds every cell's ground truth + manifest without
touching hardware.

Usage:
    python3 experiments/run_t2_8.py --dry-run          # default
    python3 experiments/run_t2_8.py --execute          # hardware
    python3 experiments/run_t2_8.py --trials 1 --dry-run
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
from traffic_gen.tcp_evasion import (              # noqa: E402
    TcpEvasionBattery, EVASIONS, RULES)

EXP_ID = "T2.8"
DEFAULT_OUT = REPO / "runs" / "experiments"
VISION_MODULE = "/home/decps/tcp_evasion_t2_8.py"


def _emit_cell_on_vision(sport_base: int, seed: int, cell_index: int,
                         timeout: int) -> tuple[int, str]:
    """Emit ONE battery cell (by index) on VISION as root.

    Mirrors the T2.5 remote-driver pattern: scapy raw-socket emission needs
    root and must originate from the switch-attached host (Vision), not the
    controller host.  ``tcp_evasion.py`` must already be scp'd to
    ``VISION_MODULE`` (done once in ``main`` when ``--execute``).  The driver
    rebuilds the same deterministic battery (sport_base + seed) and sends only
    the requested cell's segments in emit order.

    Emitting one cell at a time lets the caller SIGUSR1-reset the controller
    *between* cells, which is mandatory here: ``hold_armed_reg`` is keyed by
    CRC16(src_ip) and most cells share AUTH_SRC, so without a per-cell reset a
    rule that fires on an earlier cell arms the source and cascades DROPs onto
    every later same-source cell — fabricating "detection" (the same cascade
    the T2.5 per-strategy reset eliminated).
    """
    import base64
    driver = (
        "import sys; sys.path.insert(0,'/home/decps')\n"
        "import tcp_evasion_t2_8 as T\n"
        "from scapy.all import sendp\n"
        f"b=T.TcpEvasionBattery(sport_base={sport_base}, seed={seed})\n"
        f"cell=b._plan[{cell_index}]\n"
        "n=0\n"
        "for pkt in b.emit_cell(cell):\n"
        "    sendp(pkt, iface=b.iface, verbose=False, count=1); n+=1\n"
        "print('T2_8_EMIT_DONE n=%d'%n)\n")
    b64 = base64.b64encode(driver.encode()).decode()
    return H.ssh(
        H.VISION,
        f"echo {b64} | base64 -d > /tmp/t2_8_driver.py && "
        f"sudo -n python3 /tmp/t2_8_driver.py",
        timeout=timeout)


def run_trial(trial_idx: int, cfg: dict, out_root: Path, execute: bool
              ) -> list[dict]:
    """Run all 25 cells for one trial index. Returns per-cell records."""
    # Per-trial battery with disjoint sport space (each trial's 25 cells
    # occupy [base, base+25)); base spaced by 200 across trials.
    battery = TcpEvasionBattery(sport_base=50000 + trial_idx * 200,
                                seed=trial_idx)
    gt_all = {(e["evasion"], e["rule"]): e for e in battery.ground_truth()}

    slice_dir = out_root / "T2_8_slices"
    if execute:
        slice_dir.mkdir(parents=True, exist_ok=True)

    recs: list[dict] = []
    for k, cell in enumerate(battery._plan):
        ev, rule = cell.evasion, cell.rule
        trial_id = f"t{trial_idx:02d}"
        seed = H.derive_trial_seed(f"{EXP_ID}-{ev}-{rule}", trial_id,
                                   cfg["master_seed"])
        exp_dir = out_root / f"T2_8_{ev}_{rule}"
        trial_dir = exp_dir / trial_id
        trial_dir.mkdir(parents=True, exist_ok=True)

        gt_ev = dict(gt_all[(ev, rule)])
        gt_ev["t_send"] = gt_ev.get("ts")
        H.write_ground_truth(trial_dir, trial_id, gt_ev["scenario_id"], [gt_ev])
        H.write_trial_manifest(
            trial_dir, exp_id=EXP_ID, trial_id=trial_id,
            scenario_id=gt_ev["scenario_id"],
            declared_duration_s=float(cfg.get("declared_duration_s", 30)),
            actual_duration_s=float(cfg.get("declared_duration_s", 30)),
            master_seed=cfg["master_seed"],
            notes=f"evasion={ev} rule={rule} predicted={cell.predicted_detect}",
            execute=execute)

        rec = {"evasion": ev, "rule": rule, "trial_id": trial_id,
               "seed": seed, "predicted_detect": cell.predicted_detect,
               "src_port": cell.src_port, "n_segments": len(cell.segments),
               "mode": "execute" if execute else "dry-run"}

        if execute:
            # Per-cell SIGUSR1 reset isolates hold_armed_reg so each cell's
            # observed detection is attributable to its OWN rule, not to a
            # cascade armed by an earlier same-source cell (T2.5 lesson).
            rec["reset"] = H.reset_controller_state()
            off0 = H.get_decisions_offset()
            emit_rc, emit_out = _emit_cell_on_vision(
                battery.sport_base, trial_idx, k,
                timeout=int(cfg.get("emit_timeout_s", 120)))
            time.sleep(float(cfg.get("post_wait_s", 5)))
            off1 = H.get_decisions_offset()
            # Per-cell slice; aggregator globs T2_8_slices/*.jsonl and keys by
            # the unique (src_ip,dst_ip,src_port) 5-tuple.
            H.slice_decisions(
                off0, off1,
                slice_dir / f"trial_{trial_idx:02d}_cell_{k:02d}.jsonl")
            rec["emit_rc"] = emit_rc
            rec["emit_out"] = emit_out.strip()[-200:]
            rec["offset_start"], rec["offset_end"] = off0, off1

        recs.append(rec)

    return recs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", type=Path,
                    default=REPO / "experiments/configs/T2_8.yaml")
    ap.add_argument("--out-root", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--trials", type=int, default=None)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dry-run", action="store_true", default=True)
    g.add_argument("--execute", action="store_true")
    args = ap.parse_args(argv)
    execute = bool(args.execute)

    cfg = yaml.safe_load(args.config.read_text())
    trials = args.trials if args.trials is not None else int(cfg["trial_count"])
    n_cells = len(EVASIONS) * len(RULES)
    print(f"=== {EXP_ID} TCP-evasion battery "
          f"({'EXECUTE' if execute else 'DRY-RUN'}) ===")
    print(f"  {len(EVASIONS)} evasions x {len(RULES)} rules = {n_cells} cells "
          f"x {trials} trials = {n_cells * trials} trials")

    if execute:
        # Ship the traffic module to Vision once so the per-trial remote
        # driver can rebuild the deterministic battery there.
        H.scp_to(H.VISION, REPO / "traffic_gen" / "tcp_evasion.py",
                 VISION_MODULE)

    session: list[dict] = []
    for ti in range(trials):
        session.extend(run_trial(ti, cfg, args.out_root, execute))
    print(f"  produced {len(session)} cell-trials")

    sess = args.out_root / "T2_8_session.json"
    sess.parent.mkdir(parents=True, exist_ok=True)
    sess.write_text(json.dumps(session, indent=2, default=str))
    print(f"\nsession -> {sess}")
    print(f"next: python3 -m experiments.aggregate_t2_8 {args.out_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
