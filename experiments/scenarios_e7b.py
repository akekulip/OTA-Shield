"""E7b: slow-cadence overnight trace for IJCIP reviewer M8.

Purpose
-------
M8 asked for an 8-hour trace where the per-BMS legitimate update cadence
is strictly *above* R1's threshold tau_R1 = 14400 s so that R1 must NOT
fire on any benign update. Any attack injected into that same trace must
still be caught by the remaining rules (R2 / R4 / R5 / R6). The run
produces the macros `\\EsevenbIntervalPzeroOne` and `\\EsevenbRoneFPRate`
(see `paper/plan/ijcip_revision_plan_v2.md`).

Scenario sketch
---------------
- Total wall-clock duration: `duration_sec` (default 8 h = 28800 s).
- Fleet: `n_bms` BMS targets addressed at `10.0.2.{10+bms}`.
- Benign layer: each BMS emits an authorized OTA PUBLISH with per-BMS
  inter-update interval drawn from `Uniform(18000, 22000)` s, always
  strictly greater than `tau_r1_sec = 14400`. At 20 000 s mean cadence
  each BMS typically fires 1-2 updates over an 8 h window. That keeps
  R1 idle on legitimate traffic by construction.
- Attack layer: `attack_count` rollback attacks (`ota_version` strictly
  below the per-BMS high-water mark) are interleaved at random epochs
  chosen *independently* from the benign schedule. Rollback attacks are
  picked because they specifically exercise R6 (and cannot be hidden by
  cadence control). R2/R4/R5 coverage is validated via the same event
  stream by the aggregator.

Design notes
------------
- This module never sleeps in wall-clock time to avoid blocking the
  8-hour driver; instead it returns a pre-computed, time-stamped event
  plan. `run_e7b.py` sleeps between events and calls `_send(...)` at
  the planned epoch — that makes heartbeats + resume easy.
- Version state is monotonic per BMS so benign updates never spuriously
  regress (paper-correct behaviour). Rollbacks are produced by decoding
  `rollback_delta` BELOW the current high-water version.
- The emitted plan is deterministic given `seed`.

Outputs
-------
`pack_e7b_slow_cadence(...)` returns `list[E7bPlannedEvent]`, each
carrying (planned_offset_s, kind, label, packet parameters) so the
driver can execute the plan deterministically and resume after a crash
by skipping already-sent entries in a checkpoint file.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Iterable


# Canonical addresses shared with scenarios.py so the controller sees
# the same ground-truth source semantics. We do NOT import scenarios.py
# at module scope because this file is meant to work even on the driver
# host where scapy may be absent; `_send` is imported lazily inside the
# driver.
AUTH_SRC = "10.0.1.10"
ATTACK_SRC = "10.0.1.99"


@dataclass
class E7bPlannedEvent:
    """One planned packet in the E7b trace plan.

    Attributes
    ----------
    idx:
        Monotonic 0-based index into the plan list. Also used as the
        resume cursor by the driver.
    planned_offset_s:
        Seconds from run start when this event must be transmitted.
    kind:
        Short label describing the event class (``benign_update`` or
        ``rollback_attack``) — useful for the aggregator.
    label:
        ``"LEGIT"`` or ``"ATTACK"`` (ground truth for the aggregator).
    src_ip, dst_ip, sport, topic, ota_version, ota_size:
        Packet parameters forwarded to `scenarios._send(...)`. Mirrored
        into the aggregator's `GroundTruthEvent` by the driver.
    note:
        Human-readable hint recorded alongside the event.
    """

    idx: int
    planned_offset_s: float
    kind: str
    label: str
    src_ip: str
    dst_ip: str
    sport: int
    topic: str
    ota_version: int
    ota_size: int
    note: str = ""


def _benign_schedule(duration_sec: int,
                     n_bms: int,
                     rng: random.Random,
                     interval_low_s: float = 18000.0,
                     interval_high_s: float = 22000.0,
                     start_jitter_s: float = 900.0,
                     ) -> list[tuple[float, int]]:
    """Plan benign per-BMS updates spanning `duration_sec`.

    Each BMS independently starts at a small uniform jitter epoch in
    ``[0, start_jitter_s]`` and then fires every
    ``Uniform(interval_low_s, interval_high_s)`` seconds until the
    trace ends. Returns a list of ``(offset_s, bms_idx)`` tuples,
    sorted by offset.

    The lower bound `interval_low_s = 18000` is a hard safety margin
    above ``tau_R1 = 14400`` — keep this gap >= 3600 s to absorb
    clock skew or late-send drift without accidentally tripping R1.
    """
    assert interval_low_s > 14400.0, \
        "E7b benign cadence must stay strictly above tau_R1=14400s"
    schedule: list[tuple[float, int]] = []
    for bms in range(n_bms):
        t = rng.uniform(0.0, start_jitter_s)
        while t < duration_sec:
            schedule.append((t, bms))
            t += rng.uniform(interval_low_s, interval_high_s)
    schedule.sort(key=lambda x: x[0])
    return schedule


def _attack_schedule(duration_sec: int,
                     attack_count: int,
                     n_bms: int,
                     rng: random.Random,
                     edge_margin_s: float = 60.0,
                     ) -> list[tuple[float, int]]:
    """Plan `attack_count` rollback attacks uniformly across the trace.

    Returns ``(offset_s, bms_idx)`` tuples sorted by offset. A small
    `edge_margin_s` keeps attacks away from the trace boundaries so
    they always post-date at least one benign update (needed so R6's
    high-water register is non-zero and the rollback is detectable).
    """
    lo = edge_margin_s
    hi = max(edge_margin_s + 1.0, float(duration_sec) - edge_margin_s)
    atks: list[tuple[float, int]] = []
    for _ in range(attack_count):
        t = rng.uniform(lo, hi)
        bms = rng.randrange(n_bms)
        atks.append((t, bms))
    atks.sort(key=lambda x: x[0])
    return atks


def pack_e7b_slow_cadence(duration_sec: int = 28800,
                           n_bms: int = 50,
                           tau_r1_sec: int = 14400,
                           attack_count: int = 100,
                           seed: int = 0,
                           baseline_version: int = 48,
                           rollback_delta_range: tuple[int, int] = (1, 6),
                           size_min: int = 512_000,
                           size_max: int = 1_800_000,
                           sport_base: int = 50000,
                           ) -> list[E7bPlannedEvent]:
    """Build the E7b slow-cadence plan for an 8-hour overnight trace.

    Parameters
    ----------
    duration_sec:
        Total trace wall-clock length. Default 28800 s (8 h).
    n_bms:
        Fleet size.
    tau_r1_sec:
        R1 cadence threshold (seconds). Purely informational here — the
        benign-update cadence is hard-coded above 14400 s. Supplied so
        the caller's YAML + logs explicitly record the policy under test.
    attack_count:
        Number of rollback attacks injected (default 100).
    seed:
        RNG seed for full plan determinism.
    baseline_version:
        Starting version for every BMS. Benign updates monotonically
        advance this with probability 1.0 (never regress). Attacks
        target a strictly lower version.
    rollback_delta_range:
        Inclusive ``(lo, hi)`` range for how many versions the attacker
        rolls back below the current per-BMS high-water mark.
    size_min, size_max:
        Firmware-size range for both benign and attack packets
        (uniform in bytes).
    sport_base:
        Starting ephemeral source port. Each event grabs a unique port
        by monotonic increment to keep the aggregator's 5-tuple key
        collision-free across an 8-hour run.

    Returns
    -------
    list[E7bPlannedEvent]
        Deterministic, offset-sorted plan. ``idx`` is 0..N-1 in planned
        send order; the driver uses it as a resume cursor.

    Notes
    -----
    Invariants enforced by construction:

    * Every consecutive pair of benign updates hitting the same BMS is
      separated by >= ``interval_low_s = 18000 s`` > tau_R1 = 14400 s,
      so R1 should fire on zero benign events.
    * Every rollback attack carries ``version < current BMS high-water``
      so R6 is the expected trigger.
    * Source IP for benign = ``AUTH_SRC`` (10.0.1.10), source IP for
      attacks = ``AUTH_SRC`` as well (rollback is a privileged-insider
      threat; see `pack_rollback_e19` in `scenarios.py`). R2 is *not*
      the target rule here — R2/R4/R5 coverage is a sanity-check side
      effect, not the primary pass/fail metric for E7b.
    """
    rng = random.Random(seed)
    benign_pairs = _benign_schedule(duration_sec=duration_sec,
                                    n_bms=n_bms, rng=rng)
    attack_pairs = _attack_schedule(duration_sec=duration_sec,
                                    attack_count=attack_count,
                                    n_bms=n_bms, rng=rng)

    # Per-BMS monotonic version state. Mirrors pack_long_baseline's
    # invariant: firmware only advances on legitimate operations.
    bms_version: dict[int, int] = {i: baseline_version for i in range(n_bms)}

    # Separate RNG stream for packet fields (sizes, rollback deltas) so
    # changing schedule parameters alone does not reshuffle packet sizes.
    pkt_rng = random.Random(seed ^ 0xBEEF)

    # Merge schedules tagged by kind, then re-sort by offset.
    merged: list[tuple[float, str, int]] = []
    for off, bms in benign_pairs:
        merged.append((off, "benign_update", bms))
    for off, bms in attack_pairs:
        merged.append((off, "rollback_attack", bms))
    merged.sort(key=lambda x: (x[0], 0 if x[1] == "benign_update" else 1))

    plan: list[E7bPlannedEvent] = []
    next_sport = sport_base
    for i, (off, kind, bms) in enumerate(merged):
        dst = f"10.0.2.{10 + bms}"
        topic = f"/ota/bms/{bms:02d}"
        size = int(pkt_rng.uniform(size_min, size_max))
        sport = next_sport
        next_sport += 1
        if kind == "benign_update":
            # Monotonic version advance on every benign touch — simple
            # and keeps R6 high-water strictly non-decreasing.
            bms_version[bms] += 1
            plan.append(E7bPlannedEvent(
                idx=i,
                planned_offset_s=off,
                kind=kind,
                label="LEGIT",
                src_ip=AUTH_SRC,
                dst_ip=dst,
                sport=sport,
                topic=topic,
                ota_version=bms_version[bms],
                ota_size=size,
                note=f"slow-cadence benign; tau_R1={tau_r1_sec}s",
            ))
        else:   # rollback_attack
            hwm = bms_version[bms]
            lo, hi = rollback_delta_range
            delta = pkt_rng.randint(lo, hi)
            # Clamp so ota_version stays >= 1 even if fewer benign
            # updates have landed for this BMS yet.
            victim_ver = max(1, hwm - delta)
            if victim_ver >= hwm:
                # Not a true rollback — skip (rare; happens only very
                # early in the trace before any benign update hit this
                # BMS). Preserve idx contiguity by still appending a
                # tagged no-op entry flagged via `note`.
                plan.append(E7bPlannedEvent(
                    idx=i,
                    planned_offset_s=off,
                    kind="rollback_attack_skipped",
                    label="ATTACK",
                    src_ip=AUTH_SRC,
                    dst_ip=dst,
                    sport=sport,
                    topic=topic,
                    ota_version=victim_ver,
                    ota_size=size,
                    note=("skipped: bms high-water not yet advanced "
                          "above 1 at injection time"),
                ))
                continue
            plan.append(E7bPlannedEvent(
                idx=i,
                planned_offset_s=off,
                kind=kind,
                label="ATTACK",
                src_ip=AUTH_SRC,
                dst_ip=dst,
                sport=sport,
                topic=topic,
                ota_version=victim_ver,
                ota_size=size,
                note=(f"rollback v{victim_ver} (hwm v{hwm}, "
                      f"delta={delta})"),
            ))
    return plan


def summarize_plan(plan: Iterable[E7bPlannedEvent]) -> dict:
    """Return a compact summary useful for driver start-up logs.

    Records counts per ``kind`` label and the realized inter-update
    min / median / max over the benign layer. The driver logs this at
    run start so humans can eyeball the plan before committing 8 h.
    """
    from statistics import median

    plan_list = list(plan)
    per_kind: dict[str, int] = {}
    for e in plan_list:
        per_kind[e.kind] = per_kind.get(e.kind, 0) + 1

    # Per-BMS benign intervals (sanity check that we really are above
    # tau_R1 by construction).
    by_bms: dict[str, list[float]] = {}
    for e in plan_list:
        if e.kind != "benign_update":
            continue
        by_bms.setdefault(e.dst_ip, []).append(e.planned_offset_s)
    intervals: list[float] = []
    for t_list in by_bms.values():
        t_list.sort()
        for a, b in zip(t_list[:-1], t_list[1:]):
            intervals.append(b - a)

    out: dict = {
        "n_events": len(plan_list),
        "per_kind": per_kind,
        "n_bms_with_any_benign": len(by_bms),
        "n_benign_intervals": len(intervals),
    }
    if intervals:
        out["benign_interval_s"] = {
            "min": min(intervals),
            "median": median(intervals),
            "max": max(intervals),
        }
    return out


__all__ = [
    "E7bPlannedEvent",
    "pack_e7b_slow_cadence",
    "summarize_plan",
    "AUTH_SRC",
    "ATTACK_SRC",
]
