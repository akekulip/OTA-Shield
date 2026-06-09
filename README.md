# OTA-Shield

In-network detection of coordinated OTA firmware distribution campaigns for BESS site networks, using P4 programmable switches.

**Core claim:** OTA-Shield detects coordinated OTA distribution campaigns at an observable internal network choke point by monitoring fleet-level connection concurrency, timing, and session characteristics — providing detection capability that no endpoint or per-flow defense possesses.

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
