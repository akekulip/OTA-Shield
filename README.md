# OTA-Shield

A hardware-measured reference architecture (Intel Tofino 1 / P4-TNA) for
in-network OTA rollout admission and bounded firmware-attack detection on
BESS (battery energy storage system) site networks.

## What it is

OTA-Shield parses a cleartext reference MQTT OTA channel in the data plane and
uses a control-plane Rollout-Authorization Table (RAT) and two-stage arbiter
(Gate A, Gate B) to admit authorized firmware rollouts and operator rollbacks
while detecting a bounded family of OTA attacks: unauthorized source (R2),
oversize image (R4), signed version rollback (R6), and rapid replay (R1). A
fleet-fanout counter (R5) runs as telemetry behind the terminal R2 drop on the
deployed build. It is evaluated on a 50-unit emulated BMS testbed and reported
with its measured deployment boundaries. It is a reference design, not a
universal OTA detector.

## Scope and limitations (read this first)

- **Detection requires a cleartext MQTT segment** after TLS/VPN termination,
  evaluated as a single reference channel profile (MQTT over TCP/1883 with a
  20-byte application-level OTA header).
- **R5 is not an independent detector.** It counts only unauthorized-source
  fanout (r2-gated). An attacker holding a RAT-authorized source and version
  who stays inside the rollout envelope is out of scope for R5.
- **No switch line-rate claim.** Throughput is generator-limited (~2,000 pps,
  scapy) and reported as a controller digest-channel sustainable-rate lower
  bound, not a switch line-rate proof.
- **Not supported** on the deployed build: encrypted MQTT, brokered MQTT
  (source-IP collapse), TCP-segmented OTA headers, and generic vendor OTA
  formats. These are characterized as measured boundary cases (E18, E20, E23).

The paper's threat model, coverage matrix, and blind zones are authoritative.

## Repository contents

```
ota_shield/
├── p4src/                 # P4-16 / TNA data plane (ota_shield.p4 + includes)
│   ├── ota_shield.p4      #   top-level program
│   ├── parser.p4 headers.p4 deparser.p4
│   ├── ingress_control.p4 policy_engine.p4
│   ├── secondary_rules.p4 fleet_monitor.p4 rule_r6_rollback.p4
│   └── CONSTRAINTS.md     #   Tofino 1 constraint classes (read before editing .p4)
├── controller/            # P4Runtime / BfRt controller + RAT lifecycle
│   ├── ota_shield_controller.py
│   ├── rat_lifecycle.py   #   ed25519-signed manifest load, hot-reload, max_concurrent
│   ├── rat_arbiter.py     #   reusable Gate A / Gate B logic (also drives the IDS baseline)
│   ├── gen_rat_key.py sign_rat.py
│   └── rat_e12.json rat_e7b.json rat.pub   #   example manifests + public key
├── experiments/           # Result aggregators (aggregate_*.py) + experiments/README.md
├── definitions/           # Frozen architectural/methodological specs (01–07)
├── paper/                 # IJCIP manuscript (LaTeX source, figures, PDF)
├── p4build/Makefile       # bf-p4c build wrapper (delegated to by the top Makefile)
├── testing/smoke/         # tofino-model smoke test
└── Makefile               # top-level entry point (see `make help`)
```

## Prerequisites

- **Intel BF-SDE 9.13.2** (licensed) for P4 compilation and `bf_switchd`.
  P4 build and any hardware/tofino-model step require it; the SDE is not
  redistributable and is not included here.
- Python 3.8+ with the controller dependencies: `pip install -r controller/requirements.txt`
  (P4Runtime/BfRt bindings ship with the SDE; `pynacl` for ed25519).

## Build and run

```bash
make help                     # list targets
make build                    # compile P4 with bf-p4c (needs SDE; override SDE=<path>)
make resource                 # print MAU/SRAM/TCAM/hash utilisation report
make smoke                    # compile + tofino-model smoke test
make load                     # start bf_switchd on hardware (needs SDE + Tofino)
make controller               # start the P4Runtime controller
```

`make build` and `make smoke`/`make load` require the SDE; set `SDE=/path/to/bf-sde-9.13.2`
if it is not at the default location. The controller installs the R1/R2 tables
from a signed `rat.json` and arbitrates observed events against the rollout
schedule.

## Reproducing results

The `experiments/` directory holds the aggregators that turn raw run logs into
the reported metrics (e.g. `aggregate_e7b.py`, `aggregate_e12.py`,
`aggregate_m4.py`, `aggregate_t1.py`). The paper's macro values are produced by
these scripts from per-trial JSONL. See `experiments/README.md` for the
per-experiment mapping.

**Not included / not reproducible from this repo:** the raw multi-hour hardware
run logs, the RAT signing key, and the live testbed (Vision/Hulk hosts + Tofino)
are not redistributed. Hardware-bound experiments cannot be re-run without an
equivalent Tofino 1 + BF-SDE 9.13.2 deployment; the aggregators and example
manifests are provided so the analysis path can be inspected end-to-end.

## Citation

```bibtex
@article{akekudaga_otashield,
  title   = {OTA-Shield: A Hardware-Measured Reference Architecture for
             In-Network OTA Rollout Admission and Bounded Firmware-Attack
             Detection in Battery Energy Storage Systems},
  author  = {Akekudaga, Philip},
  journal = {International Journal of Critical Infrastructure Protection (under review)},
  year    = {2026}
}
```

## Contact

Philip Akekudaga, CYPHER Lab, University of Rhode Island.
