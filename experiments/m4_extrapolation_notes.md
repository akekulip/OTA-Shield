# M4 extrapolation model — 200-BMS E1 / E8 and QoS=0 E18

This note accompanies the IJCIP M4 reviewer-wave deliverables. It
exists so reviewers can distinguish cleanly between what was
**measured** on the hardware testbed and what was **extrapolated**
from that measurement.

The deliverables are:

- `experiments/scenarios_m4.py`
- `experiments/configs/E18_qos0_portability.yaml`
- `experiments/configs/E1_200bms.yaml`
- `experiments/configs/E8_200bms.yaml`
- `experiments/aggregate_m4.py`

and this file.

## 1. What the generator does (and does not) do

`scenarios_m4.pack_e1_200bms_extrapolation` and
`pack_e8_200bms_extrapolation` build a pcap + labels.json pair
describing a **200-BMS fleet**. They do not animate 200 physical
endpoints; the 50-host testbed is unchanged. The pcap can be replayed
on demand via `tcpreplay --topspeed` or the controller's own replayer
against the existing switch, and the aggregator correlates observed
switch decisions back to the intended labels using the same 5-tuple
scheme as the baseline E1/E8 aggregator.

`pack_e18_qos0_portability` is not an extrapolation — it is a real
eight-packet trace. It is grouped with the 200-BMS deliverables only
because the three pieces share the same M4 review item.

## 2. Rate and distribution model (200-BMS)

Given `n_bms` independent OTA sources, each emitting PUBLISHes as a
homogeneous Poisson process with per-BMS rate `λ` events/second, the
superposition is itself a Poisson process with rate
`Λ = n_bms * λ` events/second. Each arrival is tagged with its
originating BMS drawn uniformly at random from `{0, ..., n_bms-1}`.
This is the standard Poisson-superposition property; it is what makes
a 200-stream trace tractable without allocating 200 independent
queues.

The generator uses that model directly:

1. Draw inter-arrival `ΔT ~ Exp(Λ)` until the cumulative time exceeds
   `duration_s`.
2. For each arrival, pick a BMS index uniformly at random.
3. Tag the event as LEGIT, R1-replay ATTACK, or R2-unauthorized ATTACK
   according to the requested `attack_fraction`.

### What is MEASURED (taken from existing 50-host runs)

- Per-BMS OTA rate `λ` — default 0.2 events/s, matching the E7 long
  baseline steady state. Callers can override.
- Firmware size distribution — log-uniform over [256 KB, 2 MB],
  matching `pack_long_baseline` in `scenarios.py`.
- Version-monotonic rollout behaviour — v48 initial, per-event 0.02
  probability of `v += 1`, matches E7.
- The five per-rule detection probabilities at the single-flow level:
  taken from the hardware-green numbers for E1/E8 on the 50-host
  testbed (precision, recall, F1 per rule, NO_DECISION rate).
- The MQTT PUBLISH encoding (OTAS header layout, topic-padding
  convention, TCP 5-tuple shape).

### What is EXTRAPOLATED (assumed, not measured at 200-BMS scale)

- Fleet size — 200 instead of 50. The testbed cannot accommodate 200
  real hosts; the addresses `10.0.2.60..209` are synthetic.
- Arrival **independence** at 200-BMS scale. Real deployments can
  exhibit correlated rollouts (coordinated fleet waves, staged
  emergency patches). The Poisson-superposition model gives the
  *baseline* load; E12 scenarios already stress the correlated case.
- **Register-contention** behaviour at fleet scale. Each rule's
  per-BMS register slot remains isolated because R1 indexes by
  `dst_ip` and R6 by BMS index. The extrapolation assumes no new
  cross-BMS aliasing emerges at 200-BMS scale — true for the current
  register layout (`r1_last_seen_reg`, `r6_bms_max_version` both
  address by BMS index, and 200 < register width).
- **Ephemeral-port collision rate** at 200-BMS scale. The allocator
  in `scenarios_m4._fresh_sport_fn` draws from the Linux ephemeral
  range (49152..65535 = 16384 ports). For the default E1_200bms
  trace (~4800 events) collision probability inside a single trial
  is negligible; for E8_200bms (~7200 events) it starts to become
  observable. Any collisions are correctly flagged as `NO_DECISION`
  by `aggregate_m4.py`, not silently merged — this is the main mode
  of interest reviewers asked us to stress-test.

## 3. What the 200-BMS metric actually claims

The paper text should say (roughly):

> At a modelled 200-BMS fleet driven by a Poisson-superposition traffic
> model whose per-BMS rate, firmware size, and version cadence are
> taken from the 50-host testbed measurements, the controller's per-
> rule detection behaviour on individually replayable flows is
> unchanged from the 50-host run (F1 = ...). The fleet size is
> extrapolated; per-flow detection is measured.

It should NOT say:

> We ran 200 real BMSes.

The generator writes `manifest.json` per scenario with an explicit
`measured_vs_extrapolated` block that the aggregator copies into the
paper-macro JSON, so the claim text in the paper is bound to the
disclosure block at build time.

## 4. QoS=0 portability (E18)

The third deliverable is a real trace, not an extrapolation. It
re-runs the E18 reference-channel portability sheet with one extra
axis — MQTT QoS. The reviewer asked what the parser does at QoS=0,
where the packet identifier in the MQTT variable header is absent and
the OTAS firmware header offset shifts by two bytes.

M4 task #123 adds a QoS=0 branch to `p4src/ota_shield.p4`. The switch
has not been recompiled yet, so `labels.json` carries **both**
expected columns:

- `expected_old_parser` — the deployed binary ignores QoS=0; the
  `qos0_32` row should observe `PARSER_MISS`.
- `expected_new_parser` — the recompiled binary should observe
  `PARSED` on `qos0_32` while keeping `qos0_16` and `qos0_64` as
  `PARSER_MISS` (topic-length error dominates there).

`aggregate_m4.py` picks the column based on
`runs/m4/E18_qos0_portability/qos0_binary.txt` (contents: one of
`old_parser`, `new_parser`). Default is `old_parser` so the paper
does not claim the new behaviour before the recompile.

## 5. Reproducibility

Every RNG in `scenarios_m4.py` is explicit. Given the same
`(scenario, seed, n_bms, per_bms_rate_hz, duration_s,
attack_fraction)`, the generator produces a byte-identical pcap.
`manifest.json` records every axis and rate parameter. Reviewers can
reproduce the exact trace by running:

```bash
python -m experiments.scenarios_m4 --out-dir runs/m4 --seed 0
python -m experiments.aggregate_m4 --root runs/m4
```

No hardware access required to produce the trace or the aggregate
framing; hardware is only required to populate the `trial_*` blocks
under each scenario directory.

## 6. Why this framing matters

The M4 reviewer concern was specifically about whether the paper's
scaling claim is an empirical result or an extrapolation. The honest
answer is: **extrapolation, with a named model.** The deliverables in
this wave make that split legible. The paper text should not try to
smuggle the 200-BMS number into a claim that it was measured at
200-BMS — the disclosure block in `manifest.json` and `m4_aggregate
.json` is the artefact reviewers can cite against.
