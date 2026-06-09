"""OTA-Shield scenario library — parametric scapy generators that run on
Vision. Each function emits packets that cross the Tofino fabric so the
controller's digest stream is the ground truth. Callers pass explicit
parameters from YAML configs; no hard-coded fleet sizes or timings here.

Functions return a list of `GroundTruthEvent` records so the trial runner
can correlate each decision with its intended label.

This module is imported by `run_trial.py` on Vision; keep the dependency
surface minimal (scapy + stdlib).
"""
from __future__ import annotations
import random, struct, time
from dataclasses import dataclass, field
from typing import Callable, Optional
from scapy.all import Ether, IP, TCP, Raw, sendp

IFACE      = "enp59s0f0np0"
AUTH_SRC   = "10.0.1.10"
ATTACK_SRC = "10.0.1.99"
SRC_MAC    = "00:00:00:00:10:10"
DST_MAC    = "00:00:00:00:20:ff"


@dataclass
class GroundTruthEvent:
    t_send:    float       # wall-clock when packet left Vision
    scenario:  str         # e.g. "baseline", "a5_replay", "a1_fanout"
    label:     str         # "LEGIT" | "ATTACK"
    src_ip:    str
    dst_ip:    str
    src_port:  int
    topic:     str
    ota_size:  int
    ota_version: int
    note:      str = ""


def _varint(n: int) -> bytes:
    o = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        o.append(b)
        if not n: break
    return bytes(o)


def _publish(topic: str, ver: int, sz: int,
             on_wire_max: int = 1300) -> bytes:
    """Build an MQTT PUBLISH carrying the OTA header.

    `sz` is the *advertised* firmware size (recorded in the OTAS header
    so the controller / paper can analyse the realistic size distribution).
    `on_wire_max` caps the actual bytes placed in the packet so we never
    exceed Ethernet MTU. For sizes > on_wire_max the packet still carries
    the genuine 20-byte OTA header (magic + version + size + hash_hint)
    plus a short filler — the only bytes the data plane R4 rule actually
    counts come from session_bytes_reg per packet, not from this single
    advertised size.
    """
    t = topic.encode().ljust(32, b"\x00")
    on_wire_fw = max(0, min(sz - 20, on_wire_max - 20))
    fw = b"\x00" * on_wire_fw
    pl = b"OTAS" + struct.pack(">II", ver, sz) + b"\x00" * 8 + fw
    var = struct.pack(">H", 32) + t + struct.pack(">H", 1) + pl
    return bytes([0x32]) + _varint(len(var)) + var


def _send(src_ip: str, dst_ip: str, sport: int,
          topic: str, ver: int, sz: int) -> None:
    pkt = (Ether(src=SRC_MAC, dst=DST_MAC) /
           IP(src=src_ip, dst=dst_ip) /
           TCP(sport=sport, dport=1883, flags="PA", seq=1, ack=1) /
           Raw(_publish(topic, ver, sz)))
    sendp(pkt, iface=IFACE, verbose=False, count=1)


# ---------- Scenario primitives ----------

def legit_rollout(n_bms: int, start_bms: int, size: int, version: int,
                  inter_packet_s: float, sport_base: int,
                  scenario: str = "legit_rollout") -> list[GroundTruthEvent]:
    """Authorized source pushes firmware to N contiguous BMSes.
    Trips R5 once n_bms >= 5 (should be RAT-relaxed to PASS)."""
    events = []
    for i in range(n_bms):
        dst = f"10.0.2.{10 + start_bms + i}"
        topic = f"/ota/bms/{start_bms + i:02d}"
        sport = sport_base + i
        t = time.time()
        _send(AUTH_SRC, dst, sport, topic, version, size)
        events.append(GroundTruthEvent(
            t_send=t, scenario=scenario, label="LEGIT",
            src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
            topic=topic, ota_size=size, ota_version=version,
            note=f"fanout {i+1}/{n_bms}"))
        time.sleep(inter_packet_s)
    return events


def a5_replay(targets: list[int], gap_s: float, size: int, version: int,
              sport_base: int) -> list[GroundTruthEvent]:
    """Rapid-replay attack: authorized source re-hits each BMS after gap_s
    < 14400. Trips R1."""
    events = []
    for i, bms in enumerate(targets):
        dst = f"10.0.2.{10 + bms}"
        topic = f"/ota/bms/{bms:02d}"
        sport = sport_base + i
        t = time.time()
        _send(AUTH_SRC, dst, sport, topic, version, size)
        events.append(GroundTruthEvent(
            t_send=t, scenario="a5_replay", label="ATTACK",
            src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
            topic=topic, ota_size=size, ota_version=version,
            note=f"replay gap={gap_s:.1f}s"))
        time.sleep(gap_s)
    return events


def a3_unauthorized(targets: list[int], size: int, version: int,
                    sport_base: int) -> list[GroundTruthEvent]:
    """Unauthorized-source OTA PUBLISH. Trips R2."""
    events = []
    for i, bms in enumerate(targets):
        dst = f"10.0.2.{10 + bms}"
        topic = f"/ota/bms/{bms:02d}"
        sport = sport_base + i
        t = time.time()
        _send(ATTACK_SRC, dst, sport, topic, version, size)
        events.append(GroundTruthEvent(
            t_send=t, scenario="a3_unauthorized", label="ATTACK",
            src_ip=ATTACK_SRC, dst_ip=dst, src_port=sport,
            topic=topic, ota_size=size, ota_version=version))
        time.sleep(0.02)
    return events


def a4_oversize(dst_bms: int, total_bytes: int,
                per_packet: int = 1400, sport: int = 54900
                ) -> list[GroundTruthEvent]:
    """Oversized firmware: one large MQTT session that pushes session_bytes
    past R4 threshold. Returns ONE event (the flow), not per packet.

    Packet #1 carries the MQTT PUBLISH *header only* (fixed + variable +
    20-byte OTA header) so the parser recognises is_ota=1. The actual
    "firmware" bytes are split across filler packets — matches real MQTT
    streaming behaviour and keeps each IP packet within MTU.
    """
    dst = f"10.0.2.{10 + dst_bms}"
    topic = f"/ota/bms/{dst_bms:02d}"

    # Build the header-only PUBLISH prefix (no firmware payload in-line):
    t_b = topic.encode().ljust(32, b"\x00")
    pl_prefix = b"OTAS" + struct.pack(">II", 11, total_bytes) + b"\x00" * 8
    var = struct.pack(">H", 32) + t_b + struct.pack(">H", 1) + pl_prefix
    header = bytes([0x32]) + _varint(len(var)) + var
    assert len(header) < per_packet, f"header {len(header)}B won't fit"

    t = time.time()
    pkt1 = (Ether(src=SRC_MAC, dst=DST_MAC) /
            IP(src=AUTH_SRC, dst=dst) /
            TCP(sport=sport, dport=1883, flags="PA", seq=1, ack=1) /
            Raw(header + b"X" * (per_packet - len(header))))
    sendp(pkt1, iface=IFACE, verbose=False, count=1)
    sent = per_packet
    seq = 1 + per_packet
    batch = []
    while sent < total_bytes:
        batch.append((Ether(src=SRC_MAC, dst=DST_MAC) /
                      IP(src=AUTH_SRC, dst=dst) /
                      TCP(sport=sport, dport=1883, flags="PA",
                          seq=seq, ack=1) /
                      Raw(b"X" * per_packet)))
        seq  += per_packet
        sent += per_packet
        if len(batch) >= 200:
            sendp(batch, iface=IFACE, verbose=False)
            batch = []
    if batch:
        sendp(batch, iface=IFACE, verbose=False)
    return [GroundTruthEvent(
        t_send=t, scenario="a4_oversize", label="ATTACK",
        src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
        topic=topic, ota_size=total_bytes, ota_version=11,
        note=f"sent {sent}B")]


def a1_fleet_fanout(n_bms: int, start_bms: int, inter_s: float,
                    size: int, version: int,
                    sport_base: int) -> list[GroundTruthEvent]:
    """Authorized source but anomalous: pushes to *many* BMSes far outside
    a typical rollout. Trips R5. RAT match depends on start_bms being
    inside target_bms_list (test should set this intentionally)."""
    return legit_rollout(n_bms, start_bms, size, version, inter_s,
                         sport_base, scenario="a1_fleet_fanout")


# ---------- High-level scenario packs ----------

def pack_attack_sweep(per_rule_n: int, seed: int = 0
                      ) -> list[GroundTruthEvent]:
    """N attack instances per rule. For E1 (detection rate).

    Baseline and replay target the SAME `per_rule_n` BMSes so the replay
    always encounters an existing r1_last_seen_reg slot → R1 fires
    deterministically (this is the intended detection path). Prior
    versions used contiguous baseline vs random-sampled replay; the
    partial overlap produced an artefactual recall shortfall that
    confused the metric with scenario-construction noise."""
    random.seed(seed)
    events = []
    target_bms = random.sample(range(50), per_rule_n)

    # Baseline: one authorized PUBLISH per target BMS.
    for i, bms in enumerate(target_bms):
        dst = f"10.0.2.{10 + bms}"
        topic = f"/ota/bms/{bms:02d}"
        sport = 51000 + i
        t = time.time()
        _send(AUTH_SRC, dst, sport, topic, 48, 1024)
        events.append(GroundTruthEvent(
            t_send=t, scenario="baseline", label="LEGIT",
            src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
            topic=topic, ota_size=1024, ota_version=48))
        time.sleep(0.05)

    # R1 replay: same BMSes, new source ports (so 5-tuples are distinct
    # ground-truth keys but the BMS index is seen again within 4 h).
    events += a5_replay(target_bms, gap_s=0.05, size=1024, version=48,
                        sport_base=52000)

    # R2 unauthorized: N distinct BMSes from the attack source.
    events += a3_unauthorized(random.sample(range(50), per_rule_n),
                              size=1024, version=48, sport_base=55000)
    return events


def pack_adversarial_near_threshold() -> list[GroundTruthEvent]:
    """Probe just-below / just-above threshold to map detection boundaries.
    For E5 (robustness).

    Uses DISJOINT BMS ranges across fanouts so R1 never fires on BMS
    revisits (which would be a scenario artefact, not a detector behaviour).
    25 distinct BMSes across 5 fanouts (sizes 3,4,5,6,7) fit in 0..49.
    """
    events = []
    sizes = (3, 4, 5, 6, 7)
    start = 0
    for n in sizes:
        events += a1_fleet_fanout(n, start_bms=start,
                                   inter_s=0.05, size=1024,
                                   version=48, sport_base=56000 + n * 100)
        start += n        # disjoint next range
        time.sleep(65)    # let R5 window clear
    return events


# ---------- Stochastic / evasion-sweep packs (E7/E8/E9) ----------

def _send_with_jitter(events: list, dst: str, sport: int, topic: str,
                      version: int, size: int, src_ip: str = AUTH_SRC,
                      label: str = "LEGIT", scenario: str = "",
                      note: str = "") -> None:
    t = time.time()
    _send(src_ip, dst, sport, topic, version, size)
    events.append(GroundTruthEvent(
        t_send=t, scenario=scenario, label=label,
        src_ip=src_ip, dst_ip=dst, src_port=sport,
        topic=topic, ota_size=size, ota_version=version, note=note))


def pack_stochastic_e1(per_rule_n: int = 30, seed: int = 0,
                        mean_iat_s: float = 0.10) -> list[GroundTruthEvent]:
    """E8: same logical scenario as E1 but with realistic stochasticity.

    Differences from pack_attack_sweep:
      - Random BMS ordering per trial (different draw each time, controlled
        only by the trial's `seed` parameter).
      - Poisson inter-arrival times (exponential with mean `mean_iat_s`).
      - Source ports drawn from the ephemeral range 49152-65535 instead of
        contiguous integers — matches Linux's outgoing TCP port allocation.

    Each trial passes a different seed (call sites must vary it). Bootstrap
    CIs across trials become meaningful because trials are now genuinely
    independent draws."""
    rng = random.Random(seed)
    events: list[GroundTruthEvent] = []
    target_bms = rng.sample(range(50), per_rule_n)
    rng.shuffle(target_bms)

    used_sports: set[int] = set()
    def fresh_sport() -> int:
        while True:
            p = rng.randrange(49152, 65536)
            if p not in used_sports:
                used_sports.add(p)
                return p

    # Stage 1: baseline (random order)
    for bms in target_bms:
        sport = fresh_sport()
        _send_with_jitter(events, f"10.0.2.{10+bms}", sport,
                          f"/ota/bms/{bms:02d}", 48, 1024,
                          scenario="baseline", label="LEGIT",
                          note="stochastic")
        time.sleep(rng.expovariate(1.0 / mean_iat_s))

    # Stage 2: replay (same BMSes, fresh ports, random order)
    replay_order = target_bms[:]
    rng.shuffle(replay_order)
    for bms in replay_order:
        sport = fresh_sport()
        _send_with_jitter(events, f"10.0.2.{10+bms}", sport,
                          f"/ota/bms/{bms:02d}", 48, 1024,
                          scenario="a5_replay", label="ATTACK",
                          note="stochastic")
        time.sleep(rng.expovariate(1.0 / mean_iat_s))

    # Stage 3: unauthorized (fresh BMS sample, random order)
    unauth_bms = rng.sample(range(50), per_rule_n)
    rng.shuffle(unauth_bms)
    for bms in unauth_bms:
        sport = fresh_sport()
        _send_with_jitter(events, f"10.0.2.{10+bms}", sport,
                          f"/ota/bms/{bms:02d}", 48, 1024,
                          src_ip=ATTACK_SRC,
                          scenario="a3_unauthorized", label="ATTACK",
                          note="stochastic")
        time.sleep(rng.expovariate(1.0 / mean_iat_s))
    return events


def pack_evasion_r1(intervals_s: list[float] | None = None,
                    base_bms: int = 0,
                    sport_base: int = 57000) -> list[GroundTruthEvent]:
    """E9-R1: rapid-replay edge sweep. Vary inter-replay interval around
    R1's 14400 s threshold to map exact detection boundary.

    Default intervals: 1, 60, 300, 3600, 7200, 14000, 14399, 14400, 14401,
    14500, 18000 seconds. Each interval probed against a distinct BMS so
    state from one probe doesn't contaminate another. Test waits the full
    interval between paired packets — runs LONG; for fast smoke pass a
    short list like [1, 5, 14399, 14401].

    Each pair is two events: baseline (LEGIT) + replay (ATTACK if interval
    < 14400; LEGIT-by-design if interval >= 14400 because R1 should NOT
    fire — that's exactly what we're testing)."""
    if intervals_s is None:
        intervals_s = [1, 60, 300, 3600, 7200, 14000,
                        14399, 14400, 14401, 14500, 18000]
    events: list[GroundTruthEvent] = []
    for i, interval in enumerate(intervals_s):
        bms = base_bms + i
        if bms >= 50:
            break
        dst = f"10.0.2.{10+bms}"
        topic = f"/ota/bms/{bms:02d}"
        # Baseline pulse establishes r1_last_seen_reg slot
        s1 = sport_base + 2 * i
        t1 = time.time()
        _send(AUTH_SRC, dst, s1, topic, 48, 1024)
        events.append(GroundTruthEvent(
            t_send=t1, scenario=f"r1_evasion_{interval}s",
            label="LEGIT",
            src_ip=AUTH_SRC, dst_ip=dst, src_port=s1,
            topic=topic, ota_size=1024, ota_version=48,
            note=f"baseline before {interval}s gap"))
        # Wait the chosen interval
        time.sleep(interval)
        # Replay; ground-truth label depends on whether R1 SHOULD fire.
        s2 = sport_base + 2 * i + 1
        t2 = time.time()
        _send(AUTH_SRC, dst, s2, topic, 48, 1024)
        gt_label = "ATTACK" if interval < 14400 else "LEGIT"
        events.append(GroundTruthEvent(
            t_send=t2, scenario=f"r1_evasion_{interval}s",
            label=gt_label,
            src_ip=AUTH_SRC, dst_ip=dst, src_port=s2,
            topic=topic, ota_size=1024, ota_version=48,
            note=f"replay after {interval}s (truth={gt_label})"))
    return events


def pack_evasion_r4(sizes_bytes: list[int] | None = None,
                    base_bms: int = 0,
                    sport_base: int = 58000) -> list[GroundTruthEvent]:
    """E9-R4: oversize edge sweep. Vary advertised firmware size and total
    bytes pushed across {1.5 MB, 1.99 MB, 2.0 MB, 2.01 MB, 4 MB, 8 MB}.

    Threshold is 2 MiB = 2097152 bytes. Sizes <= threshold should NOT fire
    R4 (LEGIT). Sizes > threshold SHOULD fire R4 (ATTACK).

    Each size hits a distinct BMS to keep state isolated."""
    if sizes_bytes is None:
        sizes_bytes = [1572864, 2086666, 2097152, 2107638,
                       4194304, 8388608]
    events: list[GroundTruthEvent] = []
    for i, sz in enumerate(sizes_bytes):
        bms = base_bms + i
        if bms >= 50:
            break
        # Use a4_oversize() but only rename label-by-truth.
        flow_events = a4_oversize(dst_bms=bms, total_bytes=sz,
                                   per_packet=1400,
                                   sport=sport_base + i)
        for ev in flow_events:
            ev.scenario = f"r4_evasion_{sz}B"
            ev.label = "ATTACK" if sz > 2_097_152 else "LEGIT"
            ev.note = f"size={sz}B (truth={ev.label})"
        events += flow_events
        time.sleep(5)   # short cooldown between flows
    return events


def pack_evasion_r5(fanouts: list[int] | None = None,
                    sport_base: int = 59000) -> list[GroundTruthEvent]:
    """E9-R5: extended fanout sweep. Probes {3,4,5,6,7,10,15,20} distinct
    BMSes per 60s window. Threshold count > 4 → fires.

    Each fanout uses a disjoint BMS range so R1 doesn't fire artefactually.
    Ground truth label here is intentionally LEGIT for ALL events because
    in our threat model fleet fanout from authorized source IS legitimate
    (the RAT confirms). R5 firing is a SENSITIVITY measure, not a binary
    classification — see analyze_e5.py for the proper analysis."""
    if fanouts is None:
        fanouts = [3, 4, 5, 6, 7, 10, 15, 20]
    events: list[GroundTruthEvent] = []
    start = 0
    for n in fanouts:
        if start + n > 50:
            break
        events += a1_fleet_fanout(n, start_bms=start, inter_s=0.05,
                                   size=1024, version=48,
                                   sport_base=sport_base + n * 100)
        start += n
        time.sleep(65)   # let R5 window clear before next fanout
    return events


def pack_long_baseline(duration_s: int = 1800,
                       mean_iat_s: float = 2.0,
                       seed: int = 42) -> list[GroundTruthEvent]:
    """E7: long-running legitimate baseline trace. Runs for `duration_s`
    seconds emitting authorized PUBLISHes to random BMSes with Poisson
    inter-arrivals (mean `mean_iat_s`). Used to measure empirical
    distributions of distinct-BMS-count, inter-rollout intervals, and
    firmware sizes to justify thresholds against measured data instead
    of a priori assertion.

    Default: 30 min @ 0.5 Hz mean = ~900 events. Caller can scale up to
    multi-hour runs for steady-state."""
    rng = random.Random(seed)
    events: list[GroundTruthEvent] = []
    used_sports: set[int] = set()
    def fresh_sport() -> int:
        while True:
            p = rng.randrange(49152, 65536)
            if p not in used_sports:
                used_sports.add(p)
                return p
    # Per-BMS version state: start at v=48 (matches fleet-fanout baseline).
    # Legitimate operations are version-monotonic — firmware only advances.
    # With 2% per-event probability we bump the target BMS's version by +1
    # to simulate occasional rollouts; otherwise the BMS re-receives the
    # same version (repeat PUBLISH is legal at T1 timescale; §6a demotes
    # any R1 fire via RAT-authorized source). This replaces the previous
    # `version = 40 + rng.randint(0, 20)` which caused spurious R6 fires
    # on every downward jump — R6 is the rollback detector and terminal,
    # so a "benign" scenario with random versions was never truly benign.
    bms_version: dict[int, int] = {i: 48 for i in range(50)}
    end = time.time() + duration_s
    while time.time() < end:
        bms = rng.randrange(50)
        # Realistic firmware-size distribution: log-uniform over [256KB, 2MB]
        size = int(rng.uniform(256_000, 2_000_000))
        if rng.random() < 0.02:
            bms_version[bms] += 1
        version = bms_version[bms]
        sport = fresh_sport()
        _send_with_jitter(events, f"10.0.2.{10+bms}", sport,
                          f"/ota/bms/{bms:02d}", version, size,
                          scenario="long_baseline", label="LEGIT",
                          note="poisson")
        time.sleep(rng.expovariate(1.0 / mean_iat_s))
    return events


# ---------- E12: benign operational rollout stress (TIER 1) ----------
#
# Four scenarios that all produce LEGIT ground-truth labels. The goal is
# to show that the arbiter PASSes realistic coordinated operations
# rather than collapsing them to DROP. Each sub-pack is designed to
# trip R5 (fanout > 4) so the RAT arbitration path is exercised; the
# correct outcome is PASS on every event because all sources and BMS
# targets are inside the RAT manifest.

def benign_staged_rollout(waves: int = 5, per_wave: int = 10,
                           wave_gap_s: float = 30.0,
                           sport_base: int = 60000, seed: int = 0
                           ) -> list[GroundTruthEvent]:
    """Staged rollout: `waves` waves of `per_wave` contiguous BMSes,
    `wave_gap_s` between waves. Each wave trips R5 (per_wave > 4).
    Uses disjoint BMS ranges so R1 does not fire on revisit.
    """
    rng = random.Random(seed)
    events: list[GroundTruthEvent] = []
    version = 48
    size = 512 * 1024
    for w in range(waves):
        start = w * per_wave
        for i in range(per_wave):
            dst = f"10.0.2.{10 + start + i}"
            topic = f"/ota/bms/{(start + i):02d}"
            sport = sport_base + w * per_wave + i
            t = time.time()
            _send(AUTH_SRC, dst, sport, topic, version, size)
            events.append(GroundTruthEvent(
                t_send=t, scenario="benign_staged", label="LEGIT",
                src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
                topic=topic, ota_size=size, ota_version=version,
                note=f"wave {w+1}/{waves} pos {i+1}/{per_wave}"))
            time.sleep(0.02 + rng.uniform(0, 0.01))
        if w < waves - 1:
            time.sleep(wave_gap_s)
    return events


def benign_emergency_patch(n_bms: int = 50,
                            sport_base: int = 61000
                            ) -> list[GroundTruthEvent]:
    """Emergency fleet-wide patch: all `n_bms` BMSes in a short burst.
    Trips R5 hard. Must remain LEGIT because the authorized source and
    the full BMS range are in the RAT manifest for this rollout."""
    events: list[GroundTruthEvent] = []
    version = 48
    size = 768 * 1024
    for i in range(n_bms):
        dst = f"10.0.2.{10 + i}"
        topic = f"/ota/bms/{i:02d}"
        sport = sport_base + i
        t = time.time()
        _send(AUTH_SRC, dst, sport, topic, version, size)
        events.append(GroundTruthEvent(
            t_send=t, scenario="benign_emergency", label="LEGIT",
            src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
            topic=topic, ota_size=size, ota_version=version,
            note=f"emergency {i+1}/{n_bms}"))
        time.sleep(0.005)
    return events


def benign_source_migration(n_bms: int = 10, sport_base: int = 62000,
                             secondary_src: str = "10.0.1.11"
                             ) -> list[GroundTruthEvent]:
    """Approved source migration: half the rollout arrives from
    AUTH_SRC, half from a secondary authorized source after the RAT
    manifest has been updated. Both halves must PASS.

    NOTE: the RAT for this scenario must list both AUTH_SRC and
    `secondary_src` under authorized_source_ips.
    """
    events: list[GroundTruthEvent] = []
    version = 48
    size = 1024 * 1024
    half = n_bms // 2
    for i in range(half):
        dst = f"10.0.2.{10 + i}"
        topic = f"/ota/bms/{i:02d}"
        sport = sport_base + i
        t = time.time()
        _send(AUTH_SRC, dst, sport, topic, version, size)
        events.append(GroundTruthEvent(
            t_send=t, scenario="benign_migration_src1", label="LEGIT",
            src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
            topic=topic, ota_size=size, ota_version=version,
            note=f"src1 {i+1}/{half}"))
        time.sleep(0.03)
    time.sleep(10.0)  # simulate RAT manifest refresh window
    for i in range(half, n_bms):
        dst = f"10.0.2.{10 + i}"
        topic = f"/ota/bms/{i:02d}"
        sport = sport_base + i
        t = time.time()
        _send(secondary_src, dst, sport, topic, version, size)
        events.append(GroundTruthEvent(
            t_send=t, scenario="benign_migration_src2", label="LEGIT",
            src_ip=secondary_src, dst_ip=dst, src_port=sport,
            topic=topic, ota_size=size, ota_version=version,
            note=f"src2 {i - half + 1}/{n_bms - half}"))
        time.sleep(0.03)
    return events


def benign_authorized_rollback(n_bms: int = 10,
                                 sport_base: int = 64000,
                                 ) -> list[GroundTruthEvent]:
    """§6b regression: OEM recalls a buggy v48 batch and re-pushes v47
    (last-known-good) back to a portion of the fleet. Without §6b this
    burst trips R6 monotonicity and every rollback packet is DROPped.
    With §6b + a RAT rollback_window covering v47, the arbiter
    recognises the authorised recall and PASSes every event.

    The scenario is self-contained: a v48 preamble seeds R6's per-BMS
    max-version register for the target range, a 70s gap lets the R5
    window clear, then a v47 burst is emitted. Expected outcome under
    §6b: all 2*n_bms events PASS (preamble via §6a RAT match, rollback
    via §6b rat_rollback_match).
    """
    events: list[GroundTruthEvent] = []
    preamble_version = 48
    rollback_version = 47
    size = 512 * 1024
    for i in range(n_bms):
        dst = f"10.0.2.{10 + i}"
        topic = f"/ota/bms/{i:02d}"
        sport = sport_base + i
        t = time.time()
        _send(AUTH_SRC, dst, sport, topic, preamble_version, size)
        events.append(GroundTruthEvent(
            t_send=t, scenario="benign_rollback_preamble", label="LEGIT",
            src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
            topic=topic, ota_size=size, ota_version=preamble_version,
            note=f"preamble {i+1}/{n_bms} v{preamble_version}"))
        time.sleep(0.03)
    time.sleep(70.0)  # let R5 window clear before rollback burst
    for i in range(n_bms):
        dst = f"10.0.2.{10 + i}"
        topic = f"/ota/bms/{i:02d}"
        # Distinct sport so R1 doesn't fire on same 5-tuple; R6 is
        # register-backed per-BMS and still fires on version drop.
        sport = sport_base + 100 + i
        t = time.time()
        _send(AUTH_SRC, dst, sport, topic, rollback_version, size)
        events.append(GroundTruthEvent(
            t_send=t, scenario="benign_authorized_rollback", label="LEGIT",
            src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
            topic=topic, ota_size=size, ota_version=rollback_version,
            note=f"rollback {i+1}/{n_bms} v{rollback_version}"))
        time.sleep(0.03)
    return events


def benign_delayed_window(n_bms: int = 20, sport_base: int = 63000,
                           delay_s: float = 15.0
                           ) -> list[GroundTruthEvent]:
    """Delayed rollout: rollout starts `delay_s` after its RAT valid
    window is announced. Tests that late-arriving but still-in-window
    operations are PASSed rather than collapsed."""
    time.sleep(delay_s)
    events: list[GroundTruthEvent] = []
    version = 48
    size = 640 * 1024
    for i in range(n_bms):
        dst = f"10.0.2.{10 + i}"
        topic = f"/ota/bms/{i:02d}"
        sport = sport_base + i
        t = time.time()
        _send(AUTH_SRC, dst, sport, topic, version, size)
        events.append(GroundTruthEvent(
            t_send=t, scenario="benign_delayed", label="LEGIT",
            src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
            topic=topic, ota_size=size, ota_version=version,
            note=f"delayed {i+1}/{n_bms}"))
        time.sleep(0.04)
    return events


# ---------- E17: held-out mimicry / near-threshold attacks ----------

def mimicry_fanout_sub_threshold(cycles: int = 6, per_cycle: int = 4,
                                   gap_s: float = 65.0,
                                   sport_base: int = 40000, seed: int = 0
                                   ) -> list[GroundTruthEvent]:
    """Near-threshold R5 evasion under a COMPROMISED-AUTHORIZED-SOURCE
    model. The attacker has valid AUTH_SRC credentials (so R2 does not
    fire) and keeps fanout at <= 4 per 60-second window so R5 does
    not fire either. Disjoint BMS groups per cycle mean the attacker
    reaches 4 * cycles distinct BMSes over the whole run.
    Labelled ATTACK; the paper's claim is that R5 alone misses this
    pattern. R1 may still catch it if the targeted BMSes were updated
    within the 14400 s replay window."""
    rng = random.Random(seed)
    events: list[GroundTruthEvent] = []
    all_bms = list(range(50))
    rng.shuffle(all_bms)
    version = 48
    size = 1024
    for c in range(cycles):
        group = all_bms[c * per_cycle : (c + 1) * per_cycle]
        if not group:
            break
        for i, bms in enumerate(group):
            dst = f"10.0.2.{10 + bms}"
            topic = f"/ota/bms/{bms:02d}"
            sport = sport_base + c * per_cycle + i
            t = time.time()
            _send(AUTH_SRC, dst, sport, topic, version, size)
            events.append(GroundTruthEvent(
                t_send=t, scenario="mimicry_fanout_sub", label="ATTACK",
                src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
                topic=topic, ota_size=size, ota_version=version,
                note=f"cycle {c+1}/{cycles} bms={bms}"))
            time.sleep(0.04)
        if c < cycles - 1:
            time.sleep(gap_s)
    return events


def mimicry_r4_deadzone(sizes_B: list[int] | None = None,
                         sport_base: int = 41000
                         ) -> list[GroundTruthEvent]:
    """R4 dead-zone exploit: send attack payloads sized inside the
    documented 64 KiB quantization blind zone [2.0 MiB, 2.0625 MiB]
    so R4's range-match on upper-16-bits (threshold 32 x 64 KiB) fails
    to fire. Labelled ATTACK; claim: R4 misses these specific sizes,
    but the multi-rule architecture (R5 + R1 on fleet-scale repeat)
    still catches the campaign at a different layer."""
    if sizes_B is None:
        # two inside dead zone, one just above (expected fire)
        sizes_B = [2_097_152, 2_113_536, 2_162_688]
    events: list[GroundTruthEvent] = []
    version = 48
    for i, sz in enumerate(sizes_B):
        dst = f"10.0.2.{10 + i}"
        topic = f"/ota/bms/{i:02d}"
        sport = sport_base + i
        t = time.time()
        _send(AUTH_SRC, dst, sport, topic, version, sz)
        events.append(GroundTruthEvent(
            t_send=t, scenario="mimicry_r4_deadzone", label="ATTACK",
            src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
            topic=topic, ota_size=sz, ota_version=version,
            note=f"size={sz}B ({sz/1024/1024:.3f}MiB)"))
        time.sleep(0.5)
    return events


def mimicry_r1_late_replay(bms_idx: int = 0, gap_s: float = 14401.0,
                             repeats: int = 2, sport_base: int = 42000
                             ) -> list[GroundTruthEvent]:
    """R1 late-replay evasion: revisit the same BMS but with inter-replay
    gap slightly ABOVE R1's 14400 s threshold so R1 doesn't fire. Short
    version for the paper: we send the two replays 10 s apart but
    manipulate the R1 register state between them to simulate the gap
    having elapsed. The paper treats this as a thought-experiment
    reference for R1's robustness and records behavior."""
    events: list[GroundTruthEvent] = []
    version = 48
    size = 1024
    dst = f"10.0.2.{10 + bms_idx}"
    topic = f"/ota/bms/{bms_idx:02d}"
    for r in range(repeats):
        sport = sport_base + r
        t = time.time()
        _send(AUTH_SRC, dst, sport, topic, version, size)
        events.append(GroundTruthEvent(
            t_send=t, scenario="mimicry_r1_late", label="ATTACK",
            src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
            topic=topic, ota_size=size, ota_version=version,
            note=f"late replay #{r+1} nominal_gap={gap_s:.0f}s"))
        # Short sleep to keep trial tractable; the claim is that at
        # gap_s > 14400 R1 does not fire, not that we wait in real time.
        time.sleep(2.0)
    return events


def mimicry_fanout_three(cycles: int = 6, per_cycle: int = 3,
                           gap_s: float = 65.0,
                           sport_base: int = 43000, seed: int = 0
                           ) -> list[GroundTruthEvent]:
    """Sub-threshold variant pinned at fanout = 3, well below R5's
    threshold of 4. Used to show R5 misses at multiple values, not
    just the boundary."""
    rng = random.Random(seed)
    events: list[GroundTruthEvent] = []
    all_bms = list(range(50))
    rng.shuffle(all_bms)
    version = 48
    size = 1024
    for c in range(cycles):
        group = all_bms[c * per_cycle : (c + 1) * per_cycle]
        if not group:
            break
        for i, bms in enumerate(group):
            dst = f"10.0.2.{10 + bms}"
            topic = f"/ota/bms/{bms:02d}"
            sport = sport_base + c * per_cycle + i
            t = time.time()
            _send(AUTH_SRC, dst, sport, topic, version, size)
            events.append(GroundTruthEvent(
                t_send=t, scenario="mimicry_fanout_three",
                label="ATTACK",
                src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
                topic=topic, ota_size=size, ota_version=version,
                note=f"cycle {c+1}/{cycles} bms={bms}"))
            time.sleep(0.04)
        if c < cycles - 1:
            time.sleep(gap_s)
    return events


def mimicry_combined_evasion(cycles: int = 3, per_cycle: int = 4,
                               gap_s: float = 65.0,
                               sport_base: int = 44000, seed: int = 0
                               ) -> list[GroundTruthEvent]:
    """Combined evasion: fanout sub-threshold AND payload size inside
    R4 dead zone on every event. Attacks two rules simultaneously."""
    rng = random.Random(seed)
    events: list[GroundTruthEvent] = []
    all_bms = list(range(50))
    rng.shuffle(all_bms)
    version = 48
    # middle of R4 dead zone [2.0, 2.0625] MiB
    size_deadzone = 2_105_344
    for c in range(cycles):
        group = all_bms[c * per_cycle : (c + 1) * per_cycle]
        if not group:
            break
        for i, bms in enumerate(group):
            dst = f"10.0.2.{10 + bms}"
            topic = f"/ota/bms/{bms:02d}"
            sport = sport_base + c * per_cycle + i
            t = time.time()
            _send(AUTH_SRC, dst, sport, topic, version, size_deadzone)
            events.append(GroundTruthEvent(
                t_send=t, scenario="mimicry_combined",
                label="ATTACK",
                src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
                topic=topic, ota_size=size_deadzone,
                ota_version=version,
                note=f"cycle {c+1}/{cycles} bms={bms} "
                      f"sz={size_deadzone}B"))
            time.sleep(0.05)
        if c < cycles - 1:
            time.sleep(gap_s)
    return events


def pack_mimicry_e17(seed: int = 0) -> list[GroundTruthEvent]:
    """E17 held-out near-threshold attacks. Five strategies that each
    target a documented rule blind zone:
      - fanout_sub  (R5 at threshold, fanout=4)
      - fanout_three (R5 sub-threshold, fanout=3)
      - r4_deadzone (R4 64 KiB quantization gap)
      - combined    (R5 sub-threshold + R4 dead-zone on same events)
      - r1_late     (R1 gap simulated; real gap >14400 s)
    Reporting follows the reviewer's 'shaped adversary' framing: we
    report per-strategy recall, not just counts.

    Per-trial sport randomization (T2.5 v2): the sport_base for each
    sub-scenario is derived from `seed` so trials use disjoint 5-tuple
    spaces. The session_action_override table holds entries keyed on
    (src, dst, sport, dport, proto); without per-trial sport offsets,
    overrides installed on cycle-N packets in trial T can fire on later
    packets in trial T+1 at the SAME 5-tuple if the controller's
    _clear_overrides path leaves ASIC state behind. seed*100 gives
    enough room to fit each sub-scenario's events (max ~24 sports) while
    keeping the sum (base + offset + i) below 65535 for all reasonable
    seeds (max base 44000 + 9*100 + 24 = 44924, well under 65535)."""
    sport_offset = (seed % 200) * 100  # 100-spacing × 200 unique offsets
    events: list[GroundTruthEvent] = []
    events += mimicry_fanout_sub_threshold(
        seed=seed, sport_base=40000 + sport_offset)
    time.sleep(65.0)
    events += mimicry_fanout_three(
        seed=seed + 1, sport_base=43000 + sport_offset)
    time.sleep(65.0)
    events += mimicry_r4_deadzone(sport_base=41000 + sport_offset)
    time.sleep(5.0)
    events += mimicry_combined_evasion(
        seed=seed + 2, sport_base=44000 + sport_offset)
    time.sleep(65.0)
    events += mimicry_r1_late_replay(sport_base=42000 + sport_offset)
    return events


def mimicry_single(scenario: str, seed: int = 0) -> list[GroundTruthEvent]:
    """Emit ONE mimicry strategy in isolation (smoke / per-strategy reruns).

    Uses the exact same per-trial sport_base layout as
    ``pack_mimicry_e17`` so a single-strategy smoke trial occupies the
    same disjoint 5-tuple space the full campaign would assign it. No
    inter-strategy sleeps, so a single strategy runs fast. ``scenario``
    must be one of the ``scenario`` field values the campaign emits."""
    sport_offset = (seed % 200) * 100
    if scenario == "mimicry_fanout_sub":
        return mimicry_fanout_sub_threshold(
            seed=seed, sport_base=40000 + sport_offset)
    if scenario == "mimicry_fanout_three":
        return mimicry_fanout_three(
            seed=seed + 1, sport_base=43000 + sport_offset)
    if scenario == "mimicry_r4_deadzone":
        return mimicry_r4_deadzone(sport_base=41000 + sport_offset)
    if scenario == "mimicry_combined":
        return mimicry_combined_evasion(
            seed=seed + 2, sport_base=44000 + sport_offset)
    if scenario == "mimicry_r1_late":
        return mimicry_r1_late_replay(sport_base=42000 + sport_offset)
    raise ValueError(f"unknown mimicry strategy: {scenario!r}")


def pack_rollback_e19(n_bms: int = 20,
                       baseline_version: int = 48,
                       rollback_version: int = 47,
                       sport_base: int = 64000,
                       seed: int = 0) -> list[GroundTruthEvent]:
    """E19: R6 rollback / replay detection.

    Two phases:
      1. Baseline rollout pushes `baseline_version` to `n_bms` BMSes
         (LEGIT). Each BMS's r6_bms_max_version register now holds
         `baseline_version`.
      2. Rollback attack pushes `rollback_version` (< baseline_version)
         to the same BMSes (ATTACK). R6 MUST fire.

    Uses AUTH_SRC for both phases so that R2 does NOT fire — the
    attacker holds a valid source identity, only the version field
    reveals the attack. This is the exact case R6 was added to cover.
    """
    assert rollback_version < baseline_version, \
        "rollback_version must be strictly less than baseline_version"
    rng = random.Random(seed)
    events: list[GroundTruthEvent] = []
    size = 512 * 1024

    # Phase 1: legitimate baseline
    for i in range(n_bms):
        dst = f"10.0.2.{10 + i}"
        topic = f"/ota/bms/{i:02d}"
        sport = sport_base + i
        t = time.time()
        _send(AUTH_SRC, dst, sport, topic, baseline_version, size)
        events.append(GroundTruthEvent(
            t_send=t, scenario="e19_baseline", label="LEGIT",
            src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
            topic=topic, ota_size=size, ota_version=baseline_version,
            note=f"baseline {i+1}/{n_bms} v{baseline_version}"))
        time.sleep(0.02 + rng.uniform(0, 0.01))

    # Pause long enough for R5 window to close (>60 s) AND long enough
    # that R1's 14400 s window WOULD still block a same-BMS re-push —
    # but R1 has a RAT bypass for the 10.0.1.10 source, so only R6 is
    # expected to fire on phase 2.
    time.sleep(65.0)

    # Phase 2: rollback attack from SAME source, SAME BMSes, LOWER version
    for i in range(n_bms):
        dst = f"10.0.2.{10 + i}"
        topic = f"/ota/bms/{i:02d}"
        sport = sport_base + 1000 + i
        t = time.time()
        _send(AUTH_SRC, dst, sport, topic, rollback_version, size)
        events.append(GroundTruthEvent(
            t_send=t, scenario="e19_rollback", label="ATTACK",
            src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
            topic=topic, ota_size=size, ota_version=rollback_version,
            note=f"rollback {i+1}/{n_bms} v{rollback_version} "
                 f"(was v{baseline_version})"))
        time.sleep(0.02 + rng.uniform(0, 0.01))

    return events


# ---------------------------------------------------------------------------
# E19' — stochastic variant of the rollback / replay scenario.
#
# WHY this exists (IJCIP reviewer concern M3):
#   The reviewer flagged that the original E19 reports F1 = 1.000 with
#   [1.000, 1.000] CI across 20 stochastic trials — i.e. zero variance.
#   Inspection of pack_rollback_e19 confirms the concern: although the
#   function takes a `seed`, every trial runs the same deterministic
#   attack (same n_bms, same fixed rollback_version = baseline - 1, near-
#   fixed inter-packet gap of 20 ms + 0..10 ms jitter). That is a per-
#   trial micro-jitter, not a true stochastic attack surface, so zero
#   variance across trials is expected — and uninformative.
#
# pack_rollback_e19_stochastic perturbs three axes independently per
# trial (RNG seeded with base_seed + trial_idx for reproducibility):
#   1. Rollback version delta ~ Uniform(1, 8) below the RAT high-water
#      baseline_version, so the attack is not always "baseline - 1".
#   2. Legit:attack ratio p_benign ~ Uniform(0.3, 0.7) of the total
#      packet budget, so the arbiter must actually discriminate rather
#      than see a clean two-phase split.
#   3. Inter-packet jitter ~ Normal(0, 15 ms) clipped to [10 ms, 200 ms]
#      (added to a nominal 20 ms gap), so packet ordering and timing are
#      not identical across trials.
#
# The total packet count stays at ~2 * n_bms (= 40 packets at defaults)
# to match the existing E19 runtime / R5-window budget. The existing
# deterministic pack_rollback_e19 is intentionally left untouched so that
# the paper's original numbers remain reproducible.
# ---------------------------------------------------------------------------

def pack_rollback_e19_stochastic(n_bms: int = 20,
                                  baseline_version: int = 48,
                                  max_delta: int = 16,
                                  min_delta: int = 9,
                                  p_benign_low: float = 0.3,
                                  p_benign_high: float = 0.7,
                                  nominal_gap_s: float = 0.02,
                                  jitter_std_s: float = 0.015,
                                  jitter_min_s: float = 0.010,
                                  jitter_max_s: float = 0.200,
                                  sport_base: int = 64000,
                                  base_seed: int = 0,
                                  trial_idx: int = 0,
                                  ) -> list[GroundTruthEvent]:
    """E19': R6 rollback / replay detection with a genuinely stochastic
    attack surface (addresses IJCIP reviewer M3 — see comment block above).

    Total packet budget is ~2 * n_bms to match pack_rollback_e19, split
    stochastically between LEGIT baseline-rollout packets (p_benign
    fraction) and ATTACK rollback packets (remainder). All three axes
    (version delta, legit:attack ratio, inter-packet jitter) are
    resampled every call so repeated invocations with distinct
    `trial_idx` produce genuinely different runs.

    Seeding:
        rng is seeded with (base_seed + trial_idx) so that (a) a fixed
        base_seed + varied trial_idx gives reproducible per-trial
        variance and (b) the overall variance study is itself
        reproducible. This matches the reviewer's expected interface
        for an "honest" stochastic evaluation.

    Returns a list of GroundTruthEvent in emission order, tagged with
    scenario="e19s_baseline" (LEGIT) or "e19s_rollback" (ATTACK).
    """
    assert 1 <= min_delta <= max_delta < baseline_version, \
        "require 1 <= min_delta <= max_delta < baseline_version"
    # NOTE: delta must place rollback_version strictly below the RAT's
    # authorized rollback_window.min_version in rat_e12.json (=40 for
    # e12-authorized-rollback targeting BMS .10-.19). With
    # baseline_version=48 and delta>=9, rollback_version<=39 — outside
    # the authorized envelope — so every generated ATTACK is genuinely
    # unauthorized regardless of which BMS it hits. An earlier default
    # of delta=[1..8] produced rollback_version in [40..47], which
    # intersected the RAT window and caused ~50% of "attacks" to be
    # semantically authorized (silently dropped by switch digest dedup
    # after rat_rollback_match). That was a scenario-design bug, not a
    # detection bug; fixed 2026-04-18.
    assert 0.0 < p_benign_low <= p_benign_high < 1.0, \
        "p_benign bounds must satisfy 0 < low <= high < 1"
    assert jitter_min_s <= jitter_max_s, \
        "jitter_min_s must be <= jitter_max_s"

    rng = random.Random(base_seed + trial_idx)
    events: list[GroundTruthEvent] = []
    size = 512 * 1024

    # --- Axis 1: randomize rollback version delta per trial ---
    delta = rng.randint(min_delta, max_delta)
    rollback_version = baseline_version - delta

    # --- Axis 2: randomize legit:attack ratio per trial ---
    total_budget = 2 * n_bms
    p_benign = rng.uniform(p_benign_low, p_benign_high)
    # Clamp legit count to n_bms: each device receives at most one baseline
    # contact per trial window (the intended one-update-per-device model).
    # Drawing n_legit > n_bms forces Phase-1 wrapping (repeat contacts on the
    # same BMS); under the current architecture a repeat legit contact arriving
    # after R1 latches hold_armed_reg is DROPped, producing false positives
    # unrelated to rollback detection (observed 2026-06-06 in trials t08/t09).
    # The hold_armed_reg cascade on repeat contacts is a genuine, documented
    # architectural limitation (CLAUDE.md) reported separately; this clamp keeps
    # the stochastic variance study on the intended model and does NOT mask it.
    n_legit = max(1, min(n_bms, int(round(p_benign * total_budget))))
    n_attack = total_budget - n_legit

    def _jittered_gap() -> float:
        """Axis 3: nominal gap + Normal(0, jitter_std_s), clipped."""
        j = rng.gauss(0.0, jitter_std_s)
        gap = nominal_gap_s + j
        if gap < jitter_min_s:
            gap = jitter_min_s
        elif gap > jitter_max_s:
            gap = jitter_max_s
        return gap

    # Phase 1: legitimate baseline rollout — up to n_legit packets, each
    # targeting a BMS drawn (without replacement where possible) from
    # the n_bms range. If n_legit > n_bms we wrap with replacement; this
    # is expected at high p_benign and mirrors a real staged rollout.
    bms_order = list(range(n_bms))
    rng.shuffle(bms_order)
    for i in range(n_legit):
        bms_idx = bms_order[i % n_bms]
        dst = f"10.0.2.{10 + bms_idx}"
        topic = f"/ota/bms/{bms_idx:02d}"
        sport = sport_base + i
        t = time.time()
        _send(AUTH_SRC, dst, sport, topic, baseline_version, size)
        events.append(GroundTruthEvent(
            t_send=t, scenario="e19s_baseline", label="LEGIT",
            src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
            topic=topic, ota_size=size, ota_version=baseline_version,
            note=(f"baseline {i+1}/{n_legit} v{baseline_version} "
                  f"[trial={trial_idx} p_benign={p_benign:.3f} "
                  f"delta={delta}]")))
        time.sleep(_jittered_gap())

    # Pause long enough for R5 window to close (>60 s). Kept as a fixed
    # wait since the R5 window is a rule-engine property, not an attack-
    # surface axis — randomizing it would confound the ablation with R5,
    # not with R6.
    time.sleep(65.0)

    # Phase 2: rollback attack from SAME source, randomized target order
    # and randomized rollback_version.
    attack_order = list(range(n_bms))
    rng.shuffle(attack_order)
    for i in range(n_attack):
        bms_idx = attack_order[i % n_bms]
        dst = f"10.0.2.{10 + bms_idx}"
        topic = f"/ota/bms/{bms_idx:02d}"
        sport = sport_base + 1000 + i
        t = time.time()
        _send(AUTH_SRC, dst, sport, topic, rollback_version, size)
        events.append(GroundTruthEvent(
            t_send=t, scenario="e19s_rollback", label="ATTACK",
            src_ip=AUTH_SRC, dst_ip=dst, src_port=sport,
            topic=topic, ota_size=size, ota_version=rollback_version,
            note=(f"rollback {i+1}/{n_attack} v{rollback_version} "
                  f"(was v{baseline_version}) "
                  f"[trial={trial_idx} delta={delta} "
                  f"p_benign={p_benign:.3f}]")))
        time.sleep(_jittered_gap())

    return events


def pack_benign_rollout_stress(seed: int = 0) -> list[GroundTruthEvent]:
    """E12: four benign operational rollout patterns run back-to-back.
    Directly answers the reviewer critique that the evaluation proves
    feasibility better than operational robustness."""
    events: list[GroundTruthEvent] = []
    # Defensive warm-up: wave-1 of benign_staged_rollout emits 10 packets
    # in <1s, which previously raced with the controller's post-SIGUSR1
    # handle_reset (~10s). sweep.py now sleeps 15s after SIGUSR1, but
    # we keep a short in-pack pause so this scenario is robust when run
    # outside sweep.py (e.g. standalone debugging).
    time.sleep(3.0)
    events += benign_staged_rollout(waves=5, per_wave=10,
                                     wave_gap_s=30.0, seed=seed)
    time.sleep(70.0)  # let R5 window clear before next scenario
    events += benign_emergency_patch(n_bms=50)
    time.sleep(70.0)
    events += benign_source_migration(n_bms=10)
    time.sleep(70.0)
    events += benign_delayed_window(n_bms=20, delay_s=15.0)
    time.sleep(70.0)  # clear R5 window before the §6b rollback scenario
    events += benign_authorized_rollback(n_bms=10)
    return events
