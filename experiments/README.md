# OTA-Shield Experiment Matrix

Scaffold for reproducible, paper-grade evaluation. Each experiment is a YAML
config; the `sweep.py` driver runs N trials per config, captures ground
truth on Vision and controller digests on the switch, and
`aggregate.py` + `figures.py` turn the per-trial logs into metrics + IEEE-
style PDFs.

## Topology assumed
- **Workstation** — this repo; runs `sweep.py`, `aggregate.py`, `figures.py`.
- **Switch** `decps@10.10.54.15` — bf_switchd + controller running against
  an append-mode JSONL log.
- **Vision** `decps@10.10.54.19` — NIC `enp59s0f0np0` @ 10.0.1.10; runs
  `run_trial.py` via SSH-sudo for scapy injection.

Passwordless SSH must be set up from workstation to both hosts (see
`~/.ssh/config`). Sudo NOPASSWD on Vision for the `decps` user is
required for scapy raw-socket access.

## Experiments

| ID | Config | What it proves |
|---|---|---|
| E1 | `E1_attack_detection.yaml` | Per-rule TP/FP with bootstrap CI |
| E2 | `E2_fp_baseline.yaml` | Steady-state FP on legitimate rollouts |
| E5 | `E5_adversarial.yaml` | R5 detection boundary (fanout 3..7) |
| E6 | `E6_a4_oversize.yaml` | R4 oversize detection |
| E3* | `_threshold_sweep.yaml` | R5 threshold ROC — requires P4 recompile |
| E4* | `_ablation.yaml` | Ablation (disable R1/R5/RAT) — needs staged runs |
| E7* | `_rat_variance.yaml` | Robustness to RAT configuration |

(*) E3/E4/E7 require controller or P4-pipeline parameter changes between
trials. Current sweep.py doesn't automate the recompile loop — see §
"Manual experiments" below.

## Quick start

```bash
# One experiment:
make -C experiments e1

# Full automated matrix:
make -C experiments all

# Pull aggregate + figures:
cat runs/experiments/_agg/E1_attack_detection.json
ls runs/figures/
```

## Manual experiments (E3/E4/E7)

### E3 — R5 threshold ROC
1. Edit `p4src/fleet_monitor.p4` → set `R5_THRESHOLD_CONST` to each of
   `{2, 3, 4, 5, 6, 8, 10}`.
2. Recompile + reload bf_switchd (uses `ota_shield.sh`).
3. Relaunch controller, run `make e1 e5`.
4. Tag the output directory `runs/experiments/E3_T<threshold>/`.
5. After all threshold values done, merge into one aggregate and feed
   `figures.py fig_threshold_sensitivity`.

### E4 — Ablation
For each disabled component:
- **-R1**: set `R1_MIN_INTERVAL_SEC` to `0xFFFF` in `secondary_rules.p4`
  (threshold unreachable → R1 never fires). Recompile.
- **-R5**: set `R5_THRESHOLD_CONST` to `0xFFFF`. Recompile.
- **-RAT**: start the controller with `--rat /dev/null` so the RAT cache
  is empty → all HOLDs fall through to DROP.

### E7 — RAT variance
Prepare 5 variants of `controller/rat.json` (e.g. narrow size range, short
time window, half-fleet BMS list, version pinning, multi-rollout entries).
Restart controller per variant pointing at each file.

## Methodology: inter-trial state reset

Trials are treated as IID draws from the same experimental distribution —
the standard assumption behind bootstrap CIs and paired-statistics tests.
To maintain independence, the sweep driver resets detector state
(`r1_last_seen_reg`, `r5_count_reg`, Bloom filters) between trials by
sending the controller `SIGUSR1`. This is **test infrastructure only** —
in production the controller never resets state (R1's 4-hour "rapid
replay" window is a load-bearing invariant).

Without state reset, trials 1..N would measure "detector response after
trial 0's state leak", not the detector's per-trial performance. The
carryover is a real operational artefact (R1 *should* fire when the same
rollout re-hits a BMS within 4 h), but it is NOT a per-trial
measurement. Rationale documented here so the paper's §Methodology can
cite it.

Pass `--reset-between-trials 0` to `sweep.py` to measure the opposite
regime (operational carryover).

## Expected figure outputs

Under `runs/figures/`:
- `fig_confusion_matrix.pdf` — 2×2 heatmap, pooled across all experiments.
- `fig_per_rule_performance.pdf` — grouped-bar per-rule TP/TN/FP/FN.
- `fig_detection_latency.pdf` — histogram + CDF of attack-to-decision latency.
- `fig_threshold_sensitivity.pdf` — ROC across R5 thresholds (manual, E3).
- `fig_ablation.pdf` — F1 by configuration (manual, E4).
- `table_summary.tex` — booktabs-style LaTeX table.

All PDFs are embedded-font (pdf.fonttype=42), reusable inside a LaTeX
`\includegraphics`. Serif Times-like font, 9 pt axes, thin grid.
