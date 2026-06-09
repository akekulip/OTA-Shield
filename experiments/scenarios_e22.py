"""E22: RAT-manifest lifecycle matrix (IJCIP reviewer M6, E22).

The reviewer asked for a direct demonstration that the RAT manifest
arbiter behaves correctly across its full lifecycle, not just the
two states covered by E12 and E19'. This module produces five
laptop-side, pcap-first scenario packs — one per lifecycle phase —
each parametrised for 20 stochastic trials:

    1. pre_rollout       — attack arrives before valid_window_start
    2. active_authorized — attack matches an active manifest (PASS)
    3. active_unauthorized — active window but violates src / dst / size
    4. post_expiry       — attack arrives after valid_window_end
    5. max_concurrent    — (N + 1)-th concurrent target on a capped rollout

Each `pack_e22_*` function takes a per-trial seed, samples the stochastic
axes, builds a pcap of MQTT PUBLISHes identical in wire-shape to the
live-send scenarios in `scenarios.py`, and writes a ground-truth label
file. The pcap is later pushed to Vision (10.10.54.19) and replayed
with `tcpreplay` — no live packet send happens on the laptop.

Each function returns `(pcap_path, labels_jsonl_path, metadata)` as
required by `run_e22.py` and the reviewer-facing aggregate.

NOTE on the RAT fixture
-----------------------
These scenarios expect a dedicated E22 RAT manifest to be installed on
the controller for the duration of the experiment. The manifest is
NOT produced by this module (lives under `controller/rat_e22*.json`);
this module only *references* the expected windows / caps so the
generated pcaps align with those windows. The helper
`e22_rat_fixture()` returns the canonical fixture a driver can render
to disk and sign before each case.
"""
from __future__ import annotations

import json
import random
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from scapy.all import Ether, IP, TCP, Raw, wrpcap

# ---------------------------------------------------------------------------
# Wire-level constants — must match scenarios.py so the controller parser
# sees byte-identical MQTT PUBLISHes regardless of which scenario family
# produced the pcap.
# ---------------------------------------------------------------------------
IFACE_HINT: str = "enp59s0f0np0"   # for tcpreplay on Vision; not encoded
AUTH_SRC: str = "10.0.1.10"
ATTACK_SRC: str = "10.0.1.99"
SECONDARY_SRC: str = "10.0.1.11"     # used only by ablation / migration
SRC_MAC: str = "00:00:00:00:10:10"
DST_MAC: str = "00:00:00:00:20:ff"

# Default E22 RAT fixture timing anchors (epoch seconds resolved at run
# time by the driver; the pcap itself carries no absolute timestamps —
# tcpreplay decides when packets hit the wire).
E22_WINDOW_WIDTH_S: int = 3600           # 1 h active window per trial
E22_PRE_ROLLOUT_SKEW_S: int = 7200       # attack arrives 2 h BEFORE start
E22_POST_EXPIRY_SKEW_S: int = 7200       # attack arrives 2 h AFTER end
E22_MAX_CONCURRENT_TARGETS: int = 4      # small cap so N+1 is tractable

# RAT rollout_id strings referenced in metadata / driver.
E22_ACTIVE_ROLLOUT_ID: str = "e22-active"
E22_CAPPED_ROLLOUT_ID: str = "e22-capped"


@dataclass
class GroundTruthEvent:
    """Per-packet label the controller aggregator correlates against.

    Matches the shape of `scenarios.GroundTruthEvent` so existing
    aggregate code can read it without modification.

    Attributes:
        t_send: Intended send time offset from pcap t=0 (float seconds).
            The actual wall-clock send time is decided by tcpreplay on
            Vision; this value is the *relative* time inside the pcap
            that the driver can re-anchor to absolute time when needed.
        scenario: Sub-scenario tag (e.g. "e22_pre_rollout").
        label: "LEGIT" or "ATTACK".
        expected_decision: "PASS" or "DROP" — the correct controller
            action given the RAT fixture. This is the ground truth the
            aggregator compares against `decision` in the controller log.
        expected_reason: Optional expected value of the controller's
            `reason` field (rat_match, rat_miss, rat_rollback_match,
            rat_max_concurrent, terminal_fire). None means the
            aggregator only checks `decision`.
        src_ip, dst_ip, src_port: 5-tuple key for decision correlation.
        topic: MQTT topic — informational only.
        ota_size, ota_version: OTA header fields.
        note: Free-form diagnostic.
    """

    t_send: float
    scenario: str
    label: str
    expected_decision: str
    expected_reason: str | None
    src_ip: str
    dst_ip: str
    src_port: int
    topic: str
    ota_size: int
    ota_version: int
    note: str = ""


# ---------------------------------------------------------------------------
# MQTT/OTA wire helpers (copied from scenarios.py so this module is
# standalone and can run on a laptop without the Vision send stack).
# ---------------------------------------------------------------------------


def _varint(n: int) -> bytes:
    """Encode an integer as an MQTT variable-length integer."""
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            b |= 0x80
        out.append(b)
        if not n:
            break
    return bytes(out)


def _publish(topic: str, ver: int, sz: int,
             on_wire_max: int = 1300) -> bytes:
    """Build an MQTT PUBLISH carrying the OTAS OTA header.

    Matches `scenarios._publish` byte-for-byte so the parser on the
    switch treats replayed pcaps identically to live traffic.
    """
    t = topic.encode().ljust(32, b"\x00")
    on_wire_fw = max(0, min(sz - 20, on_wire_max - 20))
    fw = b"\x00" * on_wire_fw
    pl = b"OTAS" + struct.pack(">II", ver, sz) + b"\x00" * 8 + fw
    var = struct.pack(">H", 32) + t + struct.pack(">H", 1) + pl
    return bytes([0x32]) + _varint(len(var)) + var


def _build_packet(src_ip: str, dst_ip: str, sport: int,
                  topic: str, ver: int, sz: int):
    """Return a scapy packet object (not sent) suitable for wrpcap."""
    return (Ether(src=SRC_MAC, dst=DST_MAC) /
            IP(src=src_ip, dst=dst_ip) /
            TCP(sport=sport, dport=1883, flags="PA", seq=1, ack=1) /
            Raw(_publish(topic, ver, sz)))


# ---------------------------------------------------------------------------
# Per-case helpers
# ---------------------------------------------------------------------------


def _freshport_factory(rng: random.Random) -> Callable[[], int]:
    """Return a closure that yields unique ephemeral source ports.

    Matches the behaviour of `scenarios._send_with_jitter`-style trials
    so the 5-tuple keys used by the aggregator stay collision-free.
    """
    used: set[int] = set()

    def _fresh() -> int:
        while True:
            p = rng.randrange(49152, 65536)
            if p not in used:
                used.add(p)
                return p

    return _fresh


def _emit_pcap_and_labels(events: list[GroundTruthEvent],
                          packets: list,
                          pcap_path: Path,
                          labels_jsonl_path: Path,
                          metadata: dict,
                          metadata_path: Path | None = None) -> None:
    """Write pcap, JSONL labels, and an optional metadata sidecar."""
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    labels_jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(pcap_path), packets)
    with labels_jsonl_path.open("w") as fh:
        for ev in events:
            fh.write(json.dumps({
                "t_send": ev.t_send,
                "scenario": ev.scenario,
                "label": ev.label,
                "expected_decision": ev.expected_decision,
                "expected_reason": ev.expected_reason,
                "src_ip": ev.src_ip,
                "dst_ip": ev.dst_ip,
                "src_port": ev.src_port,
                "dst_port": 1883,
                "topic": ev.topic,
                "ota_size": ev.ota_size,
                "ota_version": ev.ota_version,
                "note": ev.note,
            }) + "\n")
    if metadata_path is not None:
        metadata_path.write_text(json.dumps(metadata, indent=2))


def e22_rat_fixture(*, now_s: float,
                     active_rollout_id: str = E22_ACTIVE_ROLLOUT_ID,
                     capped_rollout_id: str = E22_CAPPED_ROLLOUT_ID,
                     window_width_s: int = E22_WINDOW_WIDTH_S,
                     max_concurrent_targets: int = E22_MAX_CONCURRENT_TARGETS
                     ) -> dict:
    """Return the canonical E22 RAT fixture, centred on `now_s`.

    The driver renders this to disk (and signs it) before each case so
    every lifecycle phase tests against a known manifest. The two
    rollouts share the same target range; the `capped_rollout_id`
    exists solely to test the M6 concurrency enforcement path.
    """
    from datetime import datetime, timezone

    def _iso(t: float) -> str:
        return datetime.fromtimestamp(t, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")

    bms_list = [f"10.0.2.{10 + i}" for i in range(20)]
    return {
        "authorized_rollouts": [
            {
                "rollout_id": active_rollout_id,
                "authorized_source_ips": [AUTH_SRC],
                "expected_firmware_version": 48,
                "target_bms_list": bms_list,
                "valid_window_start": _iso(now_s - window_width_s / 2),
                "valid_window_end":   _iso(now_s + window_width_s / 2),
                "max_concurrent_targets": 50,
                "expected_payload_size_range": [512, 2_097_152],
            },
            {
                "rollout_id": capped_rollout_id,
                "authorized_source_ips": [AUTH_SRC],
                "expected_firmware_version": 48,
                "target_bms_list": bms_list,
                "valid_window_start": _iso(now_s - window_width_s / 2),
                "valid_window_end":   _iso(now_s + window_width_s / 2),
                "max_concurrent_targets": max_concurrent_targets,
                "expected_payload_size_range": [512, 2_097_152],
            },
        ],
    }


# ---------------------------------------------------------------------------
# CASE 1 — Pre-rollout: attack arrives BEFORE valid_window_start
# ---------------------------------------------------------------------------


def pack_e22_pre_rollout(pcap_path: Path,
                          labels_jsonl_path: Path,
                          metadata_path: Path | None = None,
                          *,
                          n_events: int = 8,
                          sport_base: int = 45000,
                          nominal_gap_s: float = 0.030,
                          jitter_std_s: float = 0.010,
                          jitter_min_s: float = 0.005,
                          jitter_max_s: float = 0.100,
                          base_seed: int = 0,
                          trial_idx: int = 0,
                          ) -> tuple[Path, Path, dict]:
    """Build a pcap of PUBLISHes from AUTH_SRC at otherwise-valid
    parameters. The driver is expected to install a RAT fixture whose
    `valid_window_start` is AHEAD of replay time by
    `E22_PRE_ROLLOUT_SKEW_S`, so the time-window predicate rejects
    every event regardless of src/dst/size/version.

    Ground truth: every event is ATTACK → DROP. The aggregator checks
    that the controller's `decision` is DROP. The likely `reason` is
    `rat_miss` (R5 fires on fanout, no active RAT entry covers it).

    Stochastic axes (seed = base_seed + trial_idx):
      * per-packet BMS index ∈ [0, 19]
      * inter-packet gap  ~ Normal(nominal_gap_s, jitter_std_s)
      * ephemeral source port drawn fresh per event
    """
    rng = random.Random(base_seed + trial_idx)
    fresh_sport = _freshport_factory(rng)

    events: list[GroundTruthEvent] = []
    packets: list = []
    base = time.time()
    t_cursor = 0.0

    for i in range(n_events):
        bms = rng.randrange(20)
        dst = f"10.0.2.{10 + bms}"
        sport = fresh_sport()
        version = 48
        size = 512 * 1024
        topic = f"/ota/bms/{bms:02d}"
        pkt = _build_packet(AUTH_SRC, dst, sport, topic, version, size)
        pkt.time = base + t_cursor
        packets.append(pkt)
        events.append(GroundTruthEvent(
            t_send=t_cursor,
            scenario="e22_pre_rollout",
            label="ATTACK",
            expected_decision="DROP",
            expected_reason="rat_miss",
            src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
            topic=topic, ota_size=size, ota_version=version,
            note=(f"pre_rollout {i+1}/{n_events} "
                  f"[trial={trial_idx}]"),
        ))
        gap = rng.gauss(nominal_gap_s, jitter_std_s)
        gap = max(jitter_min_s, min(jitter_max_s, gap))
        t_cursor += gap

    metadata = {
        "case_id": "case1_pre_rollout",
        "trial_idx": trial_idx,
        "seed": base_seed + trial_idx,
        "n_events": len(events),
        "expected_decision_dist": {"DROP": len(events)},
        "rat_fixture_note": (
            "driver must install rat_e22 with valid_window_start "
            f"≈ now + {E22_PRE_ROLLOUT_SKEW_S}s so every replayed "
            "packet falls strictly before the active window"),
        "pcap_duration_s": t_cursor,
    }
    _emit_pcap_and_labels(events, packets, pcap_path, labels_jsonl_path,
                          metadata, metadata_path)
    return pcap_path, labels_jsonl_path, metadata


# ---------------------------------------------------------------------------
# CASE 2 — Active-authorized: matches manifest; expected PASS.
# ---------------------------------------------------------------------------


def pack_e22_active_authorized(pcap_path: Path,
                                labels_jsonl_path: Path,
                                metadata_path: Path | None = None,
                                *,
                                n_events: int = 8,
                                sport_base: int = 46000,
                                nominal_gap_s: float = 0.030,
                                jitter_std_s: float = 0.010,
                                jitter_min_s: float = 0.005,
                                jitter_max_s: float = 0.100,
                                base_seed: int = 1000,
                                trial_idx: int = 0,
                                ) -> tuple[Path, Path, dict]:
    """Baseline-of-correctness case. Every event matches the ACTIVE
    rollout on src IP, target BMS, size, and firmware version. The
    fanout of n_events > 4 trips R5 so the HOLD path is exercised —
    arbiter must demote to PASS via `rat_match`.

    Ground truth: every event is LEGIT → PASS with reason=`rat_match`.

    Stochastic axes: BMS order permutation, inter-packet jitter, fresh
    ephemeral ports, and firmware size ~ LogUniform(512 KiB, 1.5 MiB)
    bounded inside the manifest's size range.
    """
    rng = random.Random(base_seed + trial_idx)
    fresh_sport = _freshport_factory(rng)

    events: list[GroundTruthEvent] = []
    packets: list = []
    base = time.time()
    t_cursor = 0.0
    order = list(range(20))
    rng.shuffle(order)

    for i in range(n_events):
        bms = order[i % 20]
        dst = f"10.0.2.{10 + bms}"
        sport = fresh_sport()
        version = 48
        size = int(rng.uniform(512 * 1024, 1_500_000))
        topic = f"/ota/bms/{bms:02d}"
        pkt = _build_packet(AUTH_SRC, dst, sport, topic, version, size)
        pkt.time = base + t_cursor
        packets.append(pkt)
        events.append(GroundTruthEvent(
            t_send=t_cursor,
            scenario="e22_active_authorized",
            label="LEGIT",
            expected_decision="PASS",
            expected_reason="rat_match",
            src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
            topic=topic, ota_size=size, ota_version=version,
            note=(f"active_authorized {i+1}/{n_events} "
                  f"[trial={trial_idx}]"),
        ))
        gap = rng.gauss(nominal_gap_s, jitter_std_s)
        gap = max(jitter_min_s, min(jitter_max_s, gap))
        t_cursor += gap

    metadata = {
        "case_id": "case2_active_authorized",
        "trial_idx": trial_idx,
        "seed": base_seed + trial_idx,
        "n_events": len(events),
        "expected_decision_dist": {"PASS": len(events)},
        "rat_fixture_note": (
            "driver must install rat_e22 with an ACTIVE window "
            "covering replay time, AUTH_SRC, and the .10-.29 BMS range"),
        "pcap_duration_s": t_cursor,
    }
    _emit_pcap_and_labels(events, packets, pcap_path, labels_jsonl_path,
                          metadata, metadata_path)
    return pcap_path, labels_jsonl_path, metadata


# ---------------------------------------------------------------------------
# CASE 3 — Active-unauthorized: active window but violates one axis.
# ---------------------------------------------------------------------------

# Violation modes sampled per event:
#   "src"     — packet from ATTACK_SRC (not in authorized_source_ips)
#   "dst"     — packet to BMS outside target_bms_list (.30..)
#   "size"    — oversized payload (> 2 MiB, outside expected_payload_size_range)
# Each violation is independent; we sample uniformly per event so every
# trial exercises multiple failure modes.
_VIOLATION_MODES: tuple[str, ...] = ("src", "dst", "size")


def pack_e22_active_unauthorized(pcap_path: Path,
                                  labels_jsonl_path: Path,
                                  metadata_path: Path | None = None,
                                  *,
                                  n_events: int = 9,
                                  sport_base: int = 47000,
                                  nominal_gap_s: float = 0.030,
                                  jitter_std_s: float = 0.010,
                                  jitter_min_s: float = 0.005,
                                  jitter_max_s: float = 0.100,
                                  base_seed: int = 2000,
                                  trial_idx: int = 0,
                                  ) -> tuple[Path, Path, dict]:
    """Active window, one-axis violation per event. Per-event mode
    sampled uniformly from {src, dst, size} so each trial covers all
    three failure modes in randomised order.

    Ground truth per event:
      * `src`   violation → ATTACK/DROP/`terminal_fire` (R2 fires).
      * `dst`   violation → ATTACK/DROP/`rat_miss`      (HOLD, RAT misses).
      * `size`  violation → ATTACK/DROP/`terminal_fire` (R4 fires).
    """
    rng = random.Random(base_seed + trial_idx)
    fresh_sport = _freshport_factory(rng)

    events: list[GroundTruthEvent] = []
    packets: list = []
    base = time.time()
    t_cursor = 0.0
    mode_counts: dict[str, int] = {m: 0 for m in _VIOLATION_MODES}

    for i in range(n_events):
        mode = rng.choice(_VIOLATION_MODES)
        mode_counts[mode] += 1
        sport = fresh_sport()
        topic = ""
        version = 48
        if mode == "src":
            # Attack source, otherwise well-formed → R2 terminal.
            bms = rng.randrange(20)
            dst = f"10.0.2.{10 + bms}"
            size = 512 * 1024
            src = ATTACK_SRC
            expected_reason = "terminal_fire"
        elif mode == "dst":
            # Authorized source but target BMS OUTSIDE manifest range.
            bms_off = rng.randrange(30, 50)
            dst = f"10.0.2.{bms_off + 10}"
            size = 512 * 1024
            src = AUTH_SRC
            expected_reason = "rat_miss"
        else:  # "size"
            # Authorized source + target, but payload > 2 MiB → R4 terminal.
            bms = rng.randrange(20)
            dst = f"10.0.2.{10 + bms}"
            size = int(rng.uniform(2_200_000, 3_000_000))
            src = AUTH_SRC
            expected_reason = "terminal_fire"
        topic = f"/ota/bms/attack_{mode}_{i:02d}"
        pkt = _build_packet(src, dst, sport, topic, version, size)
        pkt.time = base + t_cursor
        packets.append(pkt)
        events.append(GroundTruthEvent(
            t_send=t_cursor,
            scenario=f"e22_active_unauthorized_{mode}",
            label="ATTACK",
            expected_decision="DROP",
            expected_reason=expected_reason,
            src_ip=src, dst_ip=dst, src_port=sport,
            topic=topic, ota_size=size, ota_version=version,
            note=(f"active_unauthorized mode={mode} "
                  f"{i+1}/{n_events} [trial={trial_idx}]"),
        ))
        gap = rng.gauss(nominal_gap_s, jitter_std_s)
        gap = max(jitter_min_s, min(jitter_max_s, gap))
        t_cursor += gap

    metadata = {
        "case_id": "case3_active_unauthorized",
        "trial_idx": trial_idx,
        "seed": base_seed + trial_idx,
        "n_events": len(events),
        "expected_decision_dist": {"DROP": len(events)},
        "violation_mode_counts": mode_counts,
        "rat_fixture_note": (
            "driver installs rat_e22 ACTIVE window; each violation mode "
            "tests a distinct RAT axis (src/dst/size)"),
        "pcap_duration_s": t_cursor,
    }
    _emit_pcap_and_labels(events, packets, pcap_path, labels_jsonl_path,
                          metadata, metadata_path)
    return pcap_path, labels_jsonl_path, metadata


# ---------------------------------------------------------------------------
# CASE 4 — Post-expiry: attack after valid_window_end
# ---------------------------------------------------------------------------


def pack_e22_post_expiry(pcap_path: Path,
                          labels_jsonl_path: Path,
                          metadata_path: Path | None = None,
                          *,
                          n_events: int = 8,
                          sport_base: int = 48000,
                          nominal_gap_s: float = 0.030,
                          jitter_std_s: float = 0.010,
                          jitter_min_s: float = 0.005,
                          jitter_max_s: float = 0.100,
                          base_seed: int = 3000,
                          trial_idx: int = 0,
                          ) -> tuple[Path, Path, dict]:
    """Attack arrives AFTER valid_window_end. Parameters are
    otherwise-valid (matches src, dst, size, version). The driver
    installs a RAT fixture whose `valid_window_end` is in the PAST
    by `E22_POST_EXPIRY_SKEW_S`, so the time-window predicate rejects
    every event.

    Ground truth: every event is ATTACK → DROP with reason=`rat_miss`
    (R5 fires on fanout, time predicate filters the RAT entry).

    Semantics distinction from case 1: case 1 tests rejection of
    premature use; case 4 tests rejection of stale use. Both are
    time-axis failures but correspond to different operator errors.
    """
    rng = random.Random(base_seed + trial_idx)
    fresh_sport = _freshport_factory(rng)

    events: list[GroundTruthEvent] = []
    packets: list = []
    base = time.time()
    t_cursor = 0.0

    for i in range(n_events):
        bms = rng.randrange(20)
        dst = f"10.0.2.{10 + bms}"
        sport = fresh_sport()
        version = 48
        size = 512 * 1024
        topic = f"/ota/bms/{bms:02d}"
        pkt = _build_packet(AUTH_SRC, dst, sport, topic, version, size)
        pkt.time = base + t_cursor
        packets.append(pkt)
        events.append(GroundTruthEvent(
            t_send=t_cursor,
            scenario="e22_post_expiry",
            label="ATTACK",
            expected_decision="DROP",
            expected_reason="rat_miss",
            src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
            topic=topic, ota_size=size, ota_version=version,
            note=(f"post_expiry {i+1}/{n_events} "
                  f"[trial={trial_idx}]"),
        ))
        gap = rng.gauss(nominal_gap_s, jitter_std_s)
        gap = max(jitter_min_s, min(jitter_max_s, gap))
        t_cursor += gap

    metadata = {
        "case_id": "case4_post_expiry",
        "trial_idx": trial_idx,
        "seed": base_seed + trial_idx,
        "n_events": len(events),
        "expected_decision_dist": {"DROP": len(events)},
        "rat_fixture_note": (
            "driver installs rat_e22 with valid_window_end ≈ "
            f"now - {E22_POST_EXPIRY_SKEW_S}s so every replayed "
            "packet falls strictly after the active window"),
        "pcap_duration_s": t_cursor,
    }
    _emit_pcap_and_labels(events, packets, pcap_path, labels_jsonl_path,
                          metadata, metadata_path)
    return pcap_path, labels_jsonl_path, metadata


# ---------------------------------------------------------------------------
# CASE 5 — Max-concurrent-exceeded: (N+1)-th concurrent target.
# ---------------------------------------------------------------------------


def pack_e22_max_concurrent(pcap_path: Path,
                             labels_jsonl_path: Path,
                             metadata_path: Path | None = None,
                             *,
                             max_concurrent: int = E22_MAX_CONCURRENT_TARGETS,
                             sport_base: int = 49000,
                             nominal_gap_s: float = 0.030,
                             jitter_std_s: float = 0.010,
                             jitter_min_s: float = 0.005,
                             jitter_max_s: float = 0.100,
                             n_overflow: int = 3,
                             base_seed: int = 4000,
                             trial_idx: int = 0,
                             ) -> tuple[Path, Path, dict]:
    """First `max_concurrent` events fill the capped rollout's active
    slots; the following `n_overflow` events attempt admission and
    must be DENIED.

    Ground truth per event:
      * first max_concurrent  → LEGIT/PASS/`rat_match`.
      * following n_overflow  → ATTACK/DROP/`rat_max_concurrent`.

    Stochastic axes: per-event BMS index (disjoint across the
    max_concurrent prefix so R1 doesn't fire artefactually), fresh
    ephemeral ports, inter-packet jitter.

    Total n_events = max_concurrent + n_overflow. With defaults
    (4 + 3) that fits inside a single pcap < 1 s, well under the
    HOLD_OVERRIDE_TTL_S so the concurrency slots haven't pruned yet.
    """
    assert max_concurrent >= 1, "max_concurrent must be >= 1"
    assert n_overflow >= 1, "n_overflow must be >= 1"
    rng = random.Random(base_seed + trial_idx)
    fresh_sport = _freshport_factory(rng)

    n_events = max_concurrent + n_overflow
    # Disjoint BMS indices across all events so each event is a
    # distinct session (the M6 cap counts sessions, not packets).
    bms_pool = list(range(20))
    rng.shuffle(bms_pool)
    chosen_bms = bms_pool[:n_events]

    events: list[GroundTruthEvent] = []
    packets: list = []
    base = time.time()
    t_cursor = 0.0

    for i, bms in enumerate(chosen_bms):
        dst = f"10.0.2.{10 + bms}"
        sport = fresh_sport()
        version = 48
        size = 512 * 1024
        topic = f"/ota/bms/{bms:02d}"
        pkt = _build_packet(AUTH_SRC, dst, sport, topic, version, size)
        pkt.time = base + t_cursor
        packets.append(pkt)
        if i < max_concurrent:
            events.append(GroundTruthEvent(
                t_send=t_cursor,
                scenario="e22_max_concurrent_admitted",
                label="LEGIT",
                expected_decision="PASS",
                expected_reason="rat_match",
                src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
                topic=topic, ota_size=size, ota_version=version,
                note=(f"admit {i+1}/{max_concurrent} "
                      f"[trial={trial_idx}]"),
            ))
        else:
            overflow_idx = i - max_concurrent + 1
            events.append(GroundTruthEvent(
                t_send=t_cursor,
                scenario="e22_max_concurrent_overflow",
                label="ATTACK",
                expected_decision="DROP",
                expected_reason="rat_max_concurrent",
                src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
                topic=topic, ota_size=size, ota_version=version,
                note=(f"overflow {overflow_idx}/{n_overflow} "
                      f"[trial={trial_idx}]"),
            ))
        gap = rng.gauss(nominal_gap_s, jitter_std_s)
        gap = max(jitter_min_s, min(jitter_max_s, gap))
        t_cursor += gap

    metadata = {
        "case_id": "case5_max_concurrent",
        "trial_idx": trial_idx,
        "seed": base_seed + trial_idx,
        "n_events": n_events,
        "max_concurrent": max_concurrent,
        "n_overflow": n_overflow,
        "expected_decision_dist": {
            "PASS": max_concurrent, "DROP": n_overflow,
        },
        "rat_fixture_note": (
            "driver installs rat_e22 with the CAPPED rollout "
            f"max_concurrent_targets={max_concurrent} and a wide "
            "active window; total pcap duration stays below "
            "HOLD_OVERRIDE_TTL_S so slots have not been reclaimed "
            "when the overflow events arrive"),
        "pcap_duration_s": t_cursor,
    }
    _emit_pcap_and_labels(events, packets, pcap_path, labels_jsonl_path,
                          metadata, metadata_path)
    return pcap_path, labels_jsonl_path, metadata


# ---------------------------------------------------------------------------
# Dispatch table consumed by run_e22.py.
# ---------------------------------------------------------------------------


E22_CASE_BUILDERS: dict[str, Callable[..., tuple[Path, Path, dict]]] = {
    "case1_pre_rollout":       pack_e22_pre_rollout,
    "case2_active_authorized": pack_e22_active_authorized,
    "case3_active_unauthorized": pack_e22_active_unauthorized,
    "case4_post_expiry":       pack_e22_post_expiry,
    "case5_max_concurrent":    pack_e22_max_concurrent,
}
