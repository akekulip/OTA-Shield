VISION         ?= decps@10.10.54.19
SWITCH         ?= decps@10.10.54.15
CONTROLLER_LOG ?= /home/decps/my_program/ota/runs/phase6_digests.jsonl
TRIALS         ?= 5
WORKDIR        ?= /home/decps/my_program/ota/experiments
OUT            ?= ../runs/experiments
FIG_OUT        ?= ../runs/figures

PY ?= python3

SWEEP_CMD = $(PY) sweep.py \
	--vision $(VISION) --switch $(SWITCH) \
	--controller-log $(CONTROLLER_LOG) \
	--remote-workdir $(WORKDIR) \
	--local-out $(OUT) --trials $(TRIALS)

.PHONY: all e1 e2 e5 e6 e4 e7 e8 e9 e12 e17 e19 aggregate figures analyze-e5 analyze-e7 clean

all: e1 e2 e5 e6 e7 e8 e9 aggregate figures analyze-e5 analyze-e7

e1:
	$(SWEEP_CMD) --configs configs/E1_attack_detection.yaml

e2:
	$(SWEEP_CMD) --configs configs/E2_fp_baseline.yaml

e5:
	$(SWEEP_CMD) --configs configs/E5_adversarial.yaml --trials 3

e6:
	$(SWEEP_CMD) --configs configs/E6_a4_oversize.yaml --trials 3

e4: # ABLATION — same scenario as E1 but against controller run with --disable-rat
	@echo "E4 expects controller started with --disable-rat."
	@echo "On switch:"
	@echo "  python3.8 controller/ota_shield_controller.py ... --disable-rat"
	@echo "Then re-run this target."
	$(SWEEP_CMD) --configs configs/E4_ablation.yaml --trials 5

e7: # Long stochastic baseline → empirical thresholds (~30 min)
	$(SWEEP_CMD) --configs configs/E7_long_baseline.yaml --trials 3

e8: # Stochastic E1 with per-trial seed → real bootstrap CIs
	$(SWEEP_CMD) --configs configs/E8_stochastic.yaml \
		--trials 20 --seed-per-trial 1

e9: # Evasion sweeps R5/R4/R1-fast (parallel where possible)
	$(SWEEP_CMD) --configs configs/E9_evasion_r5.yaml --trials 3
	$(SWEEP_CMD) --configs configs/E9_evasion_r4.yaml --trials 3
	$(SWEEP_CMD) --configs configs/E9_evasion_r1_fast.yaml --trials 1

e12: # Benign operational rollout stress test — requires RAT manifest rat_e12.json
	$(SWEEP_CMD) --configs configs/E12_benign_rollout.yaml --trials 3

e17: # Held-out mimicry study (shaped adversary)
	$(SWEEP_CMD) --configs configs/E17_mimicry.yaml --trials 2

e19: # R6 rollback detection — requires rule_r6_rollback.p4 integrated + recompiled
	@echo "E19 requires rule_r6_rollback.p4 integrated into the pipeline."
	@echo "See plan/r6_integration_checklist.md before running."
	$(SWEEP_CMD) --configs configs/E19_rollback.yaml --trials 3

analyze-e5: aggregate
	$(PY) analyze_e5.py --exp-dir $(OUT)/E5_adversarial \
		--out $(FIG_OUT)/fig_r5_boundary

analyze-e7: aggregate
	$(PY) analyze_baseline.py \
		--exp-dir $(OUT)/E7_long_baseline \
		--out-json ../runs/baseline_thresholds.json \
		--out-fig $(FIG_OUT)/fig_threshold_derivation

aggregate:
	$(PY) aggregate.py --runs-dir $(OUT) --out-dir $(OUT)/_agg

figures: aggregate
	$(PY) figures.py --agg-dir $(OUT)/_agg --out-dir $(FIG_OUT) \
		--configs-dir configs

clean:
	rm -rf $(OUT)/_agg $(FIG_OUT)
