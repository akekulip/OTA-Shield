# OTA-Shield

A hardware-measured reference architecture (Intel Tofino / P4-TNA) for in-network OTA rollout admission and bounded firmware-attack detection on BESS site networks.

**What it is:** OTA-Shield parses a cleartext reference MQTT OTA channel in the data plane and uses a control-plane Rollout-Authorization Table (RAT) arbiter to admit authorized firmware rollouts and operator rollbacks while detecting a bounded family of OTA attacks (replay, unauthorized source, oversize, signed rollback). It is a reference design evaluated on a 50-unit emulated BMS testbed, not a universal OTA detector.

**Scope (honest):** detection requires a cleartext segment after TLS/VPN termination; the fleet-fanout rule (R5) counts only unauthorized-source fanout (r2-gated on the deployed build), so a stolen-credential attacker inside the rollout envelope is out of scope for R5; switch line-rate is not claimed. See the paper for the full threat model and the measured blind zones (adaptive mimicry, TCP segmentation, brokered MQTT).

## Project Structure

```
ota_shield/
├── definitions/          # Frozen architectural and methodological specifications
│   ├── 01_topology.md
│   ├── 02_observable_links.md
│   ├── 03_baseline_spec.md
│   ├── 04_rollout_distribution.md
│   ├── 05_attack_specs.md
│   ├── 06_heldout_variants.md
│   └── 07_statistics_plan.md
├── plans/                # Project management and code-level plans
│   ├── development_plan.md
│   └── coding_plan.md
├── p4src/                # [Phase 1+] P4 source
├── controller/           # [Phase 4+] P4Runtime controller
├── traffic_gen/          # [Phase 8+] Traffic generators
├── evaluation/           # [Phase 10+] Evaluation harness
└── Makefile              # [Phase 1+]
```

## Read First

1. `../OTA_Shield_Master_Document.md` — full project document
2. `../references/OTA_Shield_Addendum.md` — resolved architectural corrections
3. `definitions/` — read in order 01 → 07 before any coding begins
4. `plans/development_plan.md` — phases, gates, risks
5. `plans/coding_plan.md` — code-level structure and pseudocode

## Current Phase

**Scaffolding through Phase 5 complete. Hardware bring-up is next.**

Single-file walkthrough: **`HARDWARE_BRINGUP.md`** — covers compile,
tofino-model smoke (29 PTF tests), hardware load, controller startup, and
Gates 1c/4c/5c validation probes with a troubleshooting section.

Session checkpoint: `STATE.md` (read this first on resume).

Phases complete (scaffolded, not yet tested on hardware):
- 7 frozen definitions
- Skeleton (Phase 1), MQTT parser (Phase 2)
- OTA classifier + session manager (Phase 3, AF-001 fixes)
- R5 fleet monitor — Bloom-gated distinct counter (Phase 4, AF-002/003)
- R1/R2/R4 secondary rules (Phase 5, AF-004)

Per-phase runbooks: `PHASE{1,2,3,4,5}_CHECKLIST.md`
Agent policy: `plans/agent_orchestration.md`
Agent findings: `plans/agent_findings.md`

## Contact

Philip Akekudaga, CYPHER Lab, University of Rhode Island
