"""M4 laptop-side scenario pack for the IJCIP reviewer wave.

This module is deliberately decoupled from `experiments/scenarios.py`:
- it is a *pcap builder*, not an inline packet sender, because the tasks
  it supports are either (a) held behind a P4 recompile (the QoS=0 parser
  variant for E18, tracked as M4 task #123) or (b) intentionally beyond
  the 50-host physical testbed (200-BMS E1 / E8 extrapolation),
- it emits `(pcap, labels.json)` pairs so a later lab session can replay
  them against the switch without re-running the generator,
- all randomness is driven by an explicit `seed` so any reviewer can
  reproduce the byte-identical trace.

Three public entry points:

- ``pack_e18_qos0_portability(out_dir, seed)``
    E18 portability rerun with the parser variant question flipped.
    Emits six MQTT PUBLISH variants *twice*: once at QoS=1 (the current
    reference channel) and once at QoS=0 (the variant produced by the
    new parser bundle). The labels file records both the expected
    outcome under the CURRENTLY-DEPLOYED binary (old parser, QoS=0 is
    a PARSER_MISS) and the expected outcome under the RECOMPILED binary
    (QoS=0 is PARSED).  The aggregator reads whichever column matches
    the binary actually running at replay time.

- ``pack_e1_200bms_extrapolation(out_dir, seed)``
    E1 (per-rule attack detection) extrapolated to a 200-BMS fleet.
    Each BMS is modelled as an independent Poisson arrival process
    whose per-BMS rate matches the measured single-BMS rate from the
    existing E1 50-host run; the 200 streams are then superposed on a
    single wire.  The generator writes a pcap so the pipeline can be
    replayed against the 50-host testbed *as if* 200 hosts were
    attached (the addresses are synthesised — see the extrapolation
    notes for the honest framing).

- ``pack_e8_200bms_extrapolation(out_dir, seed)``
    E8 (stochastic E1) at 200-BMS scale with the same Poisson-
    superposition model plus ephemeral source-port allocation and per-
    BMS version-monotonic rollouts — matches the shape of
    ``pack_stochastic_e1`` but at the larger fleet.

Output layout (per call):
    <out_dir>/<scenario_name>/
        traffic.pcap
        labels.json       # list[LabelRecord], one per intended event
        manifest.json     # seed, axes, rate model, honest-framing block

No scenario in this module blocks on wall-clock time.  Timestamps are
materialised into the pcap frame timestamps so a later replay tool
(``tcpreplay --topspeed`` or the controller's own replayer) reproduces
the original inter-arrival structure on demand.
"""
from __future__ import annotations

import json
import random
import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from scapy.all import Ether, IP, TCP, Raw, wrpcap


# ---------- Addressing constants (match scenarios.py where possible) ----------

IFACE_HINT = "enp59s0f0np0"   # informational; pcap replay picks the iface
AUTH_SRC   = "10.0.1.10"
ATTACK_SRC = "10.0.1.99"
SRC_MAC    = "00:00:00:00:10:10"
DST_MAC    = "00:00:00:00:20:ff"

# 200-BMS synthesised address range. The 50-host testbed uses
# 10.0.2.{10..59}; we extend the virtual fleet into 10.0.2.{10..209}.
# Addresses .60..209 do NOT correspond to real hosts on the lab wire,
# which is exactly why this is an extrapolation (see notes).
FLEET_BASE_V4   = "10.0.2."
FLEET_START_IDX = 10
FLEET_SIZE_200  = 200


# ---------- MQTT PUBLISH encoding (duplicated intentionally) ----------
#
# We duplicate the tiny encoding helpers from scenarios.py rather than
# import them, because scenarios.py sends packets at import time via
# scapy's L2 socket — which requires CAP_NET_RAW on the laptop. These
# helpers only *build* byte strings, so `scenarios_m4` stays importable
# in any CI or reviewer-reproduction environment.

def _varint(n: int) -> bytes:
    """Encode MQTT remaining-length as a varint (LSB first, 7-bit groups)."""
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


def _publish_bytes(topic: bytes, qos: int, retain: bool,
                   pkt_id: int, version: int, size: int,
                   on_wire_max: int = 1300) -> bytes:
    """Build one MQTT PUBLISH payload carrying the OTAS firmware header.

    Args:
        topic: raw topic bytes (caller controls length / padding).
        qos: 0, 1, or 2. Per MQTT v3.1.1 / v5 the *packet identifier* field
            in the variable header is present iff ``qos > 0``.  This is the
            exact offset the P4 parser keys on to locate the OTAS header.
        retain: sets MQTT retain flag in byte 1; independent of OTA header.
        pkt_id: used only when ``qos > 0``.
        version: OTA advertised firmware version (stored big-endian u32).
        size: OTA advertised firmware size bytes (stored big-endian u32).
        on_wire_max: cap for actual bytes carried in this single PUBLISH.

    Returns:
        Serialised MQTT PUBLISH fixed-header + variable-header + payload.
    """
    on_wire_fw = max(0, min(size - 20, on_wire_max - 20))
    fw = b"\x00" * on_wire_fw
    ota = b"OTAS" + struct.pack(">II", version, size) + b"\x00" * 8 + fw
    var = struct.pack(">H", len(topic)) + topic
    if qos > 0:
        var += struct.pack(">H", pkt_id)
    var += ota
    fixed_byte1 = 0x30 | ((qos & 0x3) << 1) | (1 if retain else 0)
    return bytes([fixed_byte1]) + _varint(len(var)) + var


def _frame(src_ip: str, dst_ip: str, sport: int, payload: bytes,
           seq: int = 1, ack: int = 1) -> Ether:
    """Wrap an MQTT PUBLISH in an Ether/IP/TCP frame matching the testbed."""
    return (Ether(src=SRC_MAC, dst=DST_MAC)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=sport, dport=1883, flags="PA", seq=seq, ack=ack)
            / Raw(payload))


# ---------- Label / manifest records ----------

@dataclass
class LabelRecord:
    """One intended event.  Written to labels.json alongside the pcap."""

    t_offset_s: float        # pcap-relative send time
    scenario:   str          # e.g. "e18_qos0_baseline_q0"
    label:      str          # "LEGIT" | "ATTACK"
    src_ip:     str
    dst_ip:     str
    src_port:   int
    dst_port:   int
    topic:      str          # decoded utf-8 best effort; may contain NULs
    qos:        int
    retain:     bool
    ota_size:   int
    ota_version: int
    # For E18 only — the aggregator reads whichever expected_* column
    # matches the switch binary running at replay time.
    expected_old_parser: Optional[str] = None   # pre-recompile (QoS=0 miss)
    expected_new_parser: Optional[str] = None   # post-recompile (QoS=0 parsed)
    note:       str = ""


@dataclass
class ScenarioManifest:
    """Per-scenario manifest capturing every knob so the trace is auditable."""

    name: str
    seed: int
    axes: dict = field(default_factory=dict)       # sampled axes and ranges
    rate_model: dict = field(default_factory=dict) # Poisson parameters etc.
    measured_vs_extrapolated: dict = field(default_factory=dict)
    total_events: int = 0
    generator: str = "experiments/scenarios_m4.py"


# ---------- Small IO helper ----------

def _write_scenario(out_dir: Path, name: str, frames: list,
                    timestamps: list[float],
                    labels: list[LabelRecord],
                    manifest: ScenarioManifest) -> Path:
    """Write ``traffic.pcap``, ``labels.json``, ``manifest.json``.

    Each frame is stamped with its corresponding ``timestamps[i]`` (wall-
    clock-relative seconds) so scapy records a monotonic pcap trace.

    Returns the scenario sub-directory.
    """
    assert len(frames) == len(timestamps) == len(labels), \
        "frames, timestamps, and labels must be the same length"
    scen_dir = out_dir / name
    scen_dir.mkdir(parents=True, exist_ok=True)

    # scapy's wrpcap takes a list of packets; we set `time` per-packet so
    # pcap-aware replayers reproduce the inter-arrival structure.
    base_epoch = 1_700_000_000.0   # stable, arbitrary epoch for the pcap
    for f, ts in zip(frames, timestamps):
        f.time = base_epoch + ts

    wrpcap(str(scen_dir / "traffic.pcap"), frames)
    (scen_dir / "labels.json").write_text(
        json.dumps([asdict(r) for r in labels], indent=2))
    manifest.total_events = len(labels)
    (scen_dir / "manifest.json").write_text(
        json.dumps(asdict(manifest), indent=2))
    return scen_dir


# =====================================================================
#  E18 — QoS=0 portability rerun
# =====================================================================

# The six reference-channel variants from the original E18 sheet, plus the
# QoS=0 column under both the old (currently-deployed) and new (post-M4)
# parser bundles. When the new binary is deployed, the aggregator flips
# to the ``expected_new_parser`` column; until then it compares against
# ``expected_old_parser`` and reports the baseline unchanged.
_E18_VARIANTS: list[tuple[str, int, int, bool, str, str, str]] = [
    # (name, topic_len, qos, retain, old_expected, new_expected, note)
    ("baseline_32_q1", 32, 1, False, "PARSED", "PARSED",
        "reference channel: 32B topic, QoS=1"),
    ("short_16_q1",    16, 1, False, "PARSER_MISS", "PARSER_MISS",
        "topic shorter than the 32B null-padded assumption"),
    ("long_64_q1",     64, 1, False, "PARSER_MISS", "PARSER_MISS",
        "topic longer than the parser's fixed 32B slot"),
    # The variant the reviewer actually asked about:
    ("qos0_32",        32, 0, False, "PARSER_MISS", "PARSED",
        "QoS=0, 32B topic: OLD parser misses (pkt_id absent misaligns "
        "OTA header); NEW parser (M4 #123) recognises the QoS=0 offset "
        "branch"),
    ("qos2_32",        32, 2, False, "PARSED", "PARSED",
        "QoS=2: packet identifier still present, same offset as QoS=1"),
    ("retain_32_q1",   32, 1, True,  "PARSED", "PARSED",
        "retain flag set; does not affect OTA header offset"),
    # Extra QoS=0 corner cases: short/long topics at QoS=0.  Both parsers
    # should still miss these because the topic-length mismatch is the
    # dominant error; we log them so the paper can report that the M4
    # parser fix is *specific* to QoS=0 with the reference topic length.
    ("qos0_16",        16, 0, False, "PARSER_MISS", "PARSER_MISS",
        "QoS=0 + short topic: still a miss (short-topic error dominates)"),
    ("qos0_64",        64, 0, False, "PARSER_MISS", "PARSER_MISS",
        "QoS=0 + long topic: still a miss (long-topic error dominates)"),
]


def pack_e18_qos0_portability(out_dir: Path, seed: int = 0,
                              dst_ip: str = "10.0.2.10",
                              inter_packet_s: float = 0.2,
                              ) -> Path:
    """Build the E18 portability rerun with an explicit QoS=0 column.

    Args:
        out_dir: parent directory; the scenario writes its own subdir.
        seed: reserved for future axes (topic-byte jitter, TCP seq roll).
            Currently only affects the pkt_id byte for QoS>0 variants so
            multiple invocations produce distinct pcaps.
        dst_ip: authorized BMS target; stays in the RAT manifest so
            ``bms_known=1`` and the parser's R5 path is reachable.
        inter_packet_s: gap between successive variants in the pcap.

    Returns:
        The scenario subdirectory containing ``traffic.pcap``,
        ``labels.json``, and ``manifest.json``.

    Notes:
        The labels file carries BOTH ``expected_old_parser`` and
        ``expected_new_parser`` columns. The analysis script selects
        whichever matches the binary actually loaded on the switch at
        replay time — the generator never assumes which binary will be
        exercised.
    """
    rng = random.Random(seed)
    frames: list = []
    timestamps: list[float] = []
    labels: list[LabelRecord] = []

    sport = 45000
    t = 0.0
    for name, tlen, qos, retain, old_exp, new_exp, note in _E18_VARIANTS:
        topic = "/ota/bms/00".ljust(tlen, "\x00").encode()[:tlen]
        pkt_id = rng.randrange(1, 0xFFFF) if qos > 0 else 0
        pub = _publish_bytes(topic=topic, qos=qos, retain=retain,
                             pkt_id=pkt_id, version=48, size=1024)
        frames.append(_frame(AUTH_SRC, dst_ip, sport, pub))
        timestamps.append(t)
        try:
            topic_str = topic.decode("utf-8", errors="replace")
        except Exception:   # pragma: no cover — decode always succeeds
            topic_str = repr(topic)
        labels.append(LabelRecord(
            t_offset_s=t, scenario=f"e18_qos0_{name}", label="LEGIT",
            src_ip=AUTH_SRC, dst_ip=dst_ip, src_port=sport, dst_port=1883,
            topic=topic_str, qos=qos, retain=retain,
            ota_size=1024, ota_version=48,
            expected_old_parser=old_exp, expected_new_parser=new_exp,
            note=note))
        sport += 1
        t += inter_packet_s

    manifest = ScenarioManifest(
        name="E18_qos0_portability",
        seed=seed,
        axes={"variants": [v[0] for v in _E18_VARIANTS],
              "topic_lengths": sorted({v[1] for v in _E18_VARIANTS}),
              "qos_levels": sorted({v[2] for v in _E18_VARIANTS})},
        rate_model={"inter_packet_s": inter_packet_s,
                    "model": "deterministic"},
        measured_vs_extrapolated={
            "measured": "PUBLISH encoding and topic-length axes (same "
                        "as deployed E18 driver).",
            "extrapolated": "None — this is a real 8-packet trace.",
            "parser_binary_dependency":
                "labels.json carries both expected_old_parser and "
                "expected_new_parser. The aggregator picks the column "
                "that matches the P4 binary running at replay. M4 task "
                "#123 adds the QoS=0 branch in p4src/ota_shield.p4; "
                "until the switch loads the recompiled bundle, the "
                "QoS=0 row will still read PARSER_MISS, which IS the "
                "correct outcome for the deployed binary."})
    return _write_scenario(out_dir, "E18_qos0_portability",
                           frames, timestamps, labels, manifest)


# =====================================================================
#  200-BMS extrapolation primitives
# =====================================================================

def _bms_ip(bms_idx: int) -> str:
    """Map a 0-based BMS index to its synthesised IPv4."""
    return FLEET_BASE_V4 + str(FLEET_START_IDX + bms_idx)


def _fresh_sport_fn(rng: random.Random):
    """Return a stateful allocator over the Linux ephemeral port range."""
    used: set[int] = set()

    def _fresh() -> int:
        while True:
            p = rng.randrange(49152, 65536)
            if p not in used:
                used.add(p)
                return p
    return _fresh


def _superposed_poisson_arrivals(n_streams: int, per_stream_rate_hz: float,
                                  duration_s: float, rng: random.Random
                                  ) -> list[tuple[float, int]]:
    """Simulate the superposition of ``n_streams`` independent Poisson
    processes, each with rate ``per_stream_rate_hz``, over ``duration_s``.

    Uses the well-known property that the superposition of independent
    Poisson processes is itself Poisson with rate
    ``n_streams * per_stream_rate_hz``, and the originating stream of each
    arrival is drawn uniformly at random from the n streams. This lets us
    generate a 200-stream trace in O(n_events) without allocating 200
    separate queues.

    Returns:
        Sorted ``[(t_offset_s, stream_idx), ...]`` — one tuple per event.
    """
    assert n_streams > 0 and per_stream_rate_hz > 0 and duration_s > 0
    agg_rate = n_streams * per_stream_rate_hz
    events: list[tuple[float, int]] = []
    t = 0.0
    while True:
        t += rng.expovariate(agg_rate)
        if t >= duration_s:
            break
        events.append((t, rng.randrange(n_streams)))
    return events


def pack_e1_200bms_extrapolation(out_dir: Path, seed: int = 0,
                                  n_bms: int = FLEET_SIZE_200,
                                  per_bms_rate_hz: float = 0.2,
                                  duration_s: float = 120.0,
                                  attack_fraction: float = 0.20,
                                  ) -> Path:
    """Build a 200-BMS E1 extrapolation trace.

    Event mix mirrors ``pack_attack_sweep`` but at fleet scale:
      - baseline authorized PUBLISHes (LEGIT), Poisson per BMS
      - R1 replay pulses (ATTACK) — authorized source hits the same BMS
        within 14400 s, here compressed to the trace duration
      - R2 unauthorized PUBLISHes (ATTACK) from ``ATTACK_SRC``

    Args:
        out_dir: parent directory.
        seed: RNG seed for reproducibility; every axis is derived from it.
        n_bms: fleet size (default 200 — the reviewer-requested scale).
        per_bms_rate_hz: measured single-BMS OTA rate from the 50-host
            E1 baseline.  Default 0.2 Hz matches the long-baseline E7
            steady-state.  Callers passing a value here should have it
            grounded in measurement — see the notes file.
        duration_s: trace length.  The product ``n_bms *
            per_bms_rate_hz * duration_s`` is the expected event count.
        attack_fraction: share of the event budget labelled ATTACK,
            split evenly between R1 replay and R2 unauthorized.

    Returns:
        Scenario subdirectory path.
    """
    assert 0 < attack_fraction < 1
    rng = random.Random(seed)
    fresh_sport = _fresh_sport_fn(rng)

    arrivals = _superposed_poisson_arrivals(
        n_streams=n_bms, per_stream_rate_hz=per_bms_rate_hz,
        duration_s=duration_s, rng=rng)
    n_total = len(arrivals)
    n_attack = int(round(n_total * attack_fraction))
    n_replay = n_attack // 2
    n_unauth = n_attack - n_replay

    # Pick which arrivals are attacks; the remainder are baseline LEGIT.
    attack_idx = set(rng.sample(range(n_total), n_attack)) if n_total else set()
    replay_idx = set(list(attack_idx)[:n_replay])
    unauth_idx = attack_idx - replay_idx

    # Track which BMSes have already seen a baseline so R1 replay lands
    # on an *existing* r1_last_seen_reg slot (matches the detector's
    # expected firing path — the same fix E1's non-200 pack took).
    seen_baseline_bms: set[int] = set()

    frames: list = []
    timestamps: list[float] = []
    labels: list[LabelRecord] = []

    for i, (t_off, bms_idx) in enumerate(arrivals):
        dst = _bms_ip(bms_idx)
        topic = f"/ota/bms/{bms_idx:03d}"   # 3-digit index for 200 fleet
        sport = fresh_sport()
        if i in replay_idx and bms_idx in seen_baseline_bms:
            scenario = "e1_200bms_replay"
            label = "ATTACK"
            src = AUTH_SRC
            note = "R1 replay (200-BMS extrapolation)"
        elif i in unauth_idx:
            scenario = "e1_200bms_unauthorized"
            label = "ATTACK"
            src = ATTACK_SRC
            note = "R2 unauthorized (200-BMS extrapolation)"
        else:
            scenario = "e1_200bms_baseline"
            label = "LEGIT"
            src = AUTH_SRC
            note = "baseline (200-BMS extrapolation)"
            seen_baseline_bms.add(bms_idx)

        pub = _publish_bytes(
            topic=topic.encode().ljust(32, b"\x00"),
            qos=1, retain=False, pkt_id=1,
            version=48, size=1024)
        frames.append(_frame(src, dst, sport, pub))
        timestamps.append(t_off)
        labels.append(LabelRecord(
            t_offset_s=t_off, scenario=scenario, label=label,
            src_ip=src, dst_ip=dst, src_port=sport, dst_port=1883,
            topic=topic, qos=1, retain=False,
            ota_size=1024, ota_version=48, note=note))

    manifest = ScenarioManifest(
        name="E1_200bms",
        seed=seed,
        axes={"n_bms": n_bms,
              "duration_s": duration_s,
              "attack_fraction": attack_fraction,
              "per_bms_rate_hz": per_bms_rate_hz},
        rate_model={"model": "superposed_poisson",
                    "per_stream_rate_hz": per_bms_rate_hz,
                    "aggregate_rate_hz": n_bms * per_bms_rate_hz,
                    "expected_events": n_bms * per_bms_rate_hz * duration_s,
                    "observed_events": n_total},
        measured_vs_extrapolated={
            "measured": "Per-BMS OTA rate from the 50-host testbed "
                        "(pack_attack_sweep + long_baseline).",
            "extrapolated": "Fleet size (200 vs 50) and the addresses "
                            "10.0.2.60..209, which are synthetic. No "
                            "physical endpoint answers these addresses; "
                            "we rely on the Poisson-superposition model "
                            "to state the expected load and the per-rule "
                            "detection rate. See m4_extrapolation_notes.md."})
    return _write_scenario(out_dir, "E1_200bms",
                           frames, timestamps, labels, manifest)


def pack_e8_200bms_extrapolation(out_dir: Path, seed: int = 0,
                                  n_bms: int = FLEET_SIZE_200,
                                  per_bms_rate_hz: float = 0.2,
                                  duration_s: float = 180.0,
                                  attack_fraction: float = 0.30,
                                  ) -> Path:
    """Build a 200-BMS E8 extrapolation trace.

    E8 is the stochastic version of E1; at 200-BMS scale we (a) keep the
    Poisson-superposition arrival model, (b) draw source ports from the
    Linux ephemeral range with the same allocator as
    ``pack_stochastic_e1``, and (c) use a per-BMS version-monotonic
    rollout (v48 initial, with a small per-event probability of a +1
    bump) so R6 does not fire on the LEGIT subset.

    Args: see ``pack_e1_200bms_extrapolation``.  The default duration
    is longer (180 s vs 120 s) so the aggregate event count supports
    a non-degenerate bootstrap CI even at tight attack fractions.
    """
    assert 0 < attack_fraction < 1
    rng = random.Random(seed)
    fresh_sport = _fresh_sport_fn(rng)

    arrivals = _superposed_poisson_arrivals(
        n_streams=n_bms, per_stream_rate_hz=per_bms_rate_hz,
        duration_s=duration_s, rng=rng)
    n_total = len(arrivals)
    n_attack = int(round(n_total * attack_fraction))
    n_replay = n_attack // 2
    n_unauth = n_attack - n_replay

    attack_idx = set(rng.sample(range(n_total), n_attack)) if n_total else set()
    replay_idx = set(list(attack_idx)[:n_replay])
    unauth_idx = attack_idx - replay_idx

    # Version-monotonic rollouts (mirrors pack_long_baseline).  ATTACK
    # events carry the current version so R6 is not spuriously tripped.
    bms_version: dict[int, int] = {b: 48 for b in range(n_bms)}
    seen_baseline_bms: set[int] = set()

    frames: list = []
    timestamps: list[float] = []
    labels: list[LabelRecord] = []

    for i, (t_off, bms_idx) in enumerate(arrivals):
        dst = _bms_ip(bms_idx)
        topic = f"/ota/bms/{bms_idx:03d}"
        sport = fresh_sport()

        # Realistic log-uniform firmware size (same shape as
        # pack_long_baseline), so the 200-BMS trace exercises R4.
        size = int(rng.uniform(256_000, 2_000_000))

        if rng.random() < 0.02:
            bms_version[bms_idx] += 1
        version = bms_version[bms_idx]

        if i in replay_idx and bms_idx in seen_baseline_bms:
            scenario = "e8_200bms_replay"
            label = "ATTACK"
            src = AUTH_SRC
            note = "R1 replay (200-BMS stochastic)"
        elif i in unauth_idx:
            scenario = "e8_200bms_unauthorized"
            label = "ATTACK"
            src = ATTACK_SRC
            note = "R2 unauthorized (200-BMS stochastic)"
        else:
            scenario = "e8_200bms_baseline"
            label = "LEGIT"
            src = AUTH_SRC
            note = "baseline (200-BMS stochastic)"
            seen_baseline_bms.add(bms_idx)

        pub = _publish_bytes(
            topic=topic.encode().ljust(32, b"\x00"),
            qos=1, retain=False, pkt_id=1,
            version=version, size=size)
        frames.append(_frame(src, dst, sport, pub))
        timestamps.append(t_off)
        labels.append(LabelRecord(
            t_offset_s=t_off, scenario=scenario, label=label,
            src_ip=src, dst_ip=dst, src_port=sport, dst_port=1883,
            topic=topic, qos=1, retain=False,
            ota_size=size, ota_version=version, note=note))

    manifest = ScenarioManifest(
        name="E8_200bms",
        seed=seed,
        axes={"n_bms": n_bms,
              "duration_s": duration_s,
              "attack_fraction": attack_fraction,
              "per_bms_rate_hz": per_bms_rate_hz,
              "version_bump_probability": 0.02,
              "size_distribution": "uniform[256KB, 2MB]"},
        rate_model={"model": "superposed_poisson_stochastic",
                    "per_stream_rate_hz": per_bms_rate_hz,
                    "aggregate_rate_hz": n_bms * per_bms_rate_hz,
                    "expected_events": n_bms * per_bms_rate_hz * duration_s,
                    "observed_events": n_total},
        measured_vs_extrapolated={
            "measured": "Per-BMS rate, size distribution, and version-"
                        "bump probability from the 50-host E7 long "
                        "baseline.",
            "extrapolated": "Fleet size (200) and synthetic addresses "
                            "10.0.2.60..209. Ephemeral-port contention "
                            "is also extrapolated: at 200-BMS scale "
                            "ephemeral-port reuse becomes more likely "
                            "inside a short window and the aggregator "
                            "flags any 5-tuple collisions as "
                            "NO_DECISION — this IS the mode we want to "
                            "stress-test for reviewers."})
    return _write_scenario(out_dir, "E8_200bms",
                           frames, timestamps, labels, manifest)


# =====================================================================
#  T2.6 — fleet scaling 100 / 250 / 500 (E23)
# =====================================================================

# Locked fleet sizes + the per-size arrival model (EXPERIMENT_DESIGN T2.6).
#   100 / 250 : native per-BMS Poisson at the measured 0.2 Hz steady-state.
#   500       : aggregate Poisson IAT scaled so the superposed rate fits
#               the 2.2 kpps replay cap.  mean aggregate IAT 0.00045 s ->
#               ~2222 pps aggregate.  Only the 500 fleet is rate-scaled;
#               this is recorded honestly in the scenario manifest.
FLEET_SIZES = [100, 250, 500]
# Nominal 0.45 ms aggregate IAT rounded up to 0.46 ms so the aggregate rate
# (~2174 pps) stays strictly under the 2.2 kpps (2200 pps) replay cap.
FLEET_500_AGG_IAT_MEAN_S = 0.00046   # 1/0.00046 ~= 2174 pps < 2200 cap
FLEET_NATIVE_PER_BMS_HZ = 0.2


def _scaled_aggregate_arrivals(n_streams: int, agg_iat_mean_s: float,
                               duration_s: float, rng: random.Random
                               ) -> list[tuple[float, int]]:
    """Aggregate Poisson arrivals at a fixed mean inter-arrival time, with
    the originating stream drawn uniformly. Used for fleet-500 where the
    native per-BMS rate would exceed the 2.2 kpps replay cap."""
    assert n_streams > 0 and agg_iat_mean_s > 0 and duration_s > 0
    events: list[tuple[float, int]] = []
    t = 0.0
    while True:
        t += rng.expovariate(1.0 / agg_iat_mean_s)
        if t >= duration_s:
            break
        events.append((t, rng.randrange(n_streams)))
    return events


def pack_fleet_scaling(out_dir: Path, fleet_size: int, seed: int = 0,
                       duration_s: float = 120.0,
                       attack_fraction: float = 0.20,
                       scaled_iat: Optional[bool] = None,
                       ) -> Path:
    """Build one T2.6 fleet-scaling trace at ``fleet_size`` BMSes.

    Mirrors ``pack_e1_200bms_extrapolation`` but parametrises the fleet
    size and the arrival model.  For 100/250 the arrivals are the native
    superposition of per-BMS Poisson processes at 0.2 Hz; for 500 (or when
    ``scaled_iat=True``) the aggregate Poisson IAT is fixed at
    ``FLEET_500_AGG_IAT_MEAN_S`` so the superposed rate fits the 2.2 kpps
    cap.  The event mix (LEGIT baseline + R1 replay + R2 unauthorized) is
    the same as the 200-BMS pack so the R5 fanout / override-occupancy /
    Bloom-FP behaviour is exercised at each scale.

    Scenario id: ``bess.fleet.{size}_native`` or
    ``bess.fleet.500_scaled_iat``.
    """
    assert 0 < attack_fraction < 1
    if scaled_iat is None:
        scaled_iat = (fleet_size >= 500)
    rng = random.Random(seed)
    fresh_sport = _fresh_sport_fn(rng)

    if scaled_iat:
        arrivals = _scaled_aggregate_arrivals(
            fleet_size, FLEET_500_AGG_IAT_MEAN_S, duration_s, rng)
        scenario_name = f"fleet_{fleet_size}_scaled_iat"
        scenario_id = f"bess.fleet.{fleet_size}_scaled_iat"
        rate_model = {
            "model": "scaled_aggregate_poisson",
            "aggregate_iat_mean_s": FLEET_500_AGG_IAT_MEAN_S,
            "aggregate_rate_pps": 1.0 / FLEET_500_AGG_IAT_MEAN_S,
            "cap_pps": 2200,
        }
    else:
        arrivals = _superposed_poisson_arrivals(
            fleet_size, FLEET_NATIVE_PER_BMS_HZ, duration_s, rng)
        scenario_name = f"fleet_{fleet_size}_native"
        scenario_id = f"bess.fleet.{fleet_size}_native"
        rate_model = {
            "model": "superposed_poisson",
            "per_stream_rate_hz": FLEET_NATIVE_PER_BMS_HZ,
            "aggregate_rate_hz": fleet_size * FLEET_NATIVE_PER_BMS_HZ,
        }

    n_total = len(arrivals)
    n_attack = int(round(n_total * attack_fraction))
    n_replay = n_attack // 2
    attack_idx = set(rng.sample(range(n_total), n_attack)) if n_total else set()
    replay_idx = set(list(attack_idx)[:n_replay])
    unauth_idx = attack_idx - replay_idx
    seen_baseline_bms: set[int] = set()

    # Fleet-safe address mapping: 10.0.2.10.. wraps into the third octet
    # once the fourth would exceed 254 so a 500-BMS fleet stays inside
    # valid IPv4 (10.0.{2+ot3}.{10+ot4}). The 200-BMS packs keep their own
    # 10.0.2.10..209 mapping via _bms_ip; this only affects T2.6.
    def _fleet_ip(idx: int) -> str:
        flat = FLEET_START_IDX + idx
        ot3 = 2 + (flat // 245)
        ot4 = 1 + (flat % 245)
        return f"10.0.{ot3}.{ot4}"

    frames: list = []
    timestamps: list[float] = []
    labels: list[LabelRecord] = []

    for i, (t_off, bms_idx) in enumerate(arrivals):
        dst = _fleet_ip(bms_idx)
        topic = f"/ota/bms/{bms_idx:03d}"
        sport = fresh_sport()
        if i in replay_idx and bms_idx in seen_baseline_bms:
            scen, label, src = f"{scenario_name}_replay", "ATTACK", AUTH_SRC
            note = "R1 replay"
        elif i in unauth_idx:
            scen, label, src = f"{scenario_name}_unauthorized", "ATTACK", ATTACK_SRC
            note = "R2 unauthorized"
        else:
            scen, label, src = f"{scenario_name}_baseline", "LEGIT", AUTH_SRC
            note = "baseline"
            seen_baseline_bms.add(bms_idx)
        pub = _publish_bytes(topic=topic.encode().ljust(32, b"\x00"),
                             qos=1, retain=False, pkt_id=1,
                             version=48, size=1024)
        frames.append(_frame(src, dst, sport, pub))
        timestamps.append(t_off)
        labels.append(LabelRecord(
            t_offset_s=t_off, scenario=scen, label=label,
            src_ip=src, dst_ip=dst, src_port=sport, dst_port=1883,
            topic=topic, qos=1, retain=False,
            ota_size=1024, ota_version=48, note=note))

    rate_model["expected_events"] = n_total
    rate_model["observed_events"] = n_total
    manifest = ScenarioManifest(
        name=scenario_name,
        seed=seed,
        axes={"fleet_size": fleet_size, "duration_s": duration_s,
              "attack_fraction": attack_fraction,
              "scenario_id": scenario_id,
              "scaled_iat": scaled_iat},
        rate_model=rate_model,
        measured_vs_extrapolated={
            "measured": "Per-BMS OTA rate, event mix, and rule behaviour "
                        "from the 50-host testbed.",
            "extrapolated": f"Fleet size ({fleet_size}) and synthetic "
                            f"addresses. Fleet-500 additionally rate-scales "
                            f"the aggregate IAT to {FLEET_500_AGG_IAT_MEAN_S}s "
                            f"to respect the 2.2 kpps replay cap — this is "
                            f"the ONLY rate adjustment and is recorded here."})
    return _write_scenario(out_dir, scenario_name,
                           frames, timestamps, labels, manifest)


# =====================================================================
#  CLI
# =====================================================================

def _main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out-dir", default="runs/m4", type=Path,
                    help="Parent directory for the three scenario packs.")
    ap.add_argument("--seed", default=0, type=int)
    ap.add_argument("--skip-e18", action="store_true")
    ap.add_argument("--skip-e1", action="store_true")
    ap.add_argument("--skip-e8", action="store_true")
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    produced: list[Path] = []
    if not args.skip_e18:
        produced.append(pack_e18_qos0_portability(args.out_dir, seed=args.seed))
    if not args.skip_e1:
        produced.append(pack_e1_200bms_extrapolation(args.out_dir, seed=args.seed))
    if not args.skip_e8:
        produced.append(pack_e8_200bms_extrapolation(args.out_dir, seed=args.seed))
    for p in produced:
        print(f"[m4] wrote {p}")


if __name__ == "__main__":
    _main()
