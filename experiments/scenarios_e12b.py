"""E12b (signed-manifest rerun) — two-phase benign rollout scenario.

Reviewer item M6 asked for a rerun of E12b under the new signed-manifest
infrastructure that landed in controller/rat_lifecycle.py:

  * ed25519 signature verification at every load
  * inotify (or poll-fallback) hot-reload on rat.json / rat.json.sig
  * max_concurrent_targets enforced by an active-session table

The old E12b (experiments/configs/E12b_stale_rat.yaml) exercised ONLY the
"what if the RAT window has lapsed?" failure mode. The new E12b must also
exercise the *signed* manifest path end-to-end, because the signed path
is the actual M6 contribution. That means two phases in one scenario:

  Phase A  (valid signed manifest)
      Same benign rollout workload as E12 (staged / emergency /
      migration / delayed / authorized-rollback). Every event is LEGIT.
      Expected outcome: 0 FP, identical to the E12 baseline, plus a
      controller log line stating `signed=True` at initial load.

  Phase B  (stale-manifest injection)
      While the trial is live, an on-switch helper flips one byte of
      rat_e12.json.sig. The inotify watcher reloads, the ed25519 verify
      fails, the manager logs "RAT reload REJECTED: ..." and keeps the
      previous (valid) cache. A handful of benign events are then fired
      to confirm the last-known-good cache is still serving requests.
      The .sig file is restored at the end so the bench is left clean.

The scenario pack itself only generates *packets*; the sig-corruption
action is driven by experiments/run_e12b.py (the HW driver) because it
runs on the switch host, not on Vision. The scenario function records
GroundTruthEvent entries tagged with scenario="e12b_phaseA_*" or
scenario="e12b_phaseB_lastgood" so aggregate_e12b.py can split them.

Honest framing:
    The new signed-manifest path makes the old stale-RAT numbers
    (macros \\EOneTwobstaler*) obsolete because the failure mode is no
    longer "controller silently accepts a stale file" but "controller
    refuses to reload and keeps last-known-good". The aggregator emits
    a new macro namespace `EOneTwobsigned*` and never touches the old
    one.
"""

from __future__ import annotations

import time

from scapy.all import sendp  # noqa: F401  (imported for parity with scenarios.py)

import scenarios
from scenarios import (
    AUTH_SRC,
    GroundTruthEvent,
    benign_authorized_rollback,
    benign_delayed_window,
    benign_emergency_patch,
    benign_source_migration,
    benign_staged_rollout,
)


# A short cooldown is needed after the sig corruption event so the
# controller has time to (a) observe the inotify event, (b) fail the
# verify, (c) log the REJECT. Empirically ~2 s is enough on Vision; we
# use 5 s for a margin consistent with the rest of the sweep.
SIG_REJECT_OBSERVE_WINDOW_S = 5.0

# Phase-B post-rejection benign burst: small enough to stay under the
# R5 fanout threshold so the last-known-good cache is exercised without
# needing another full R5-window drain. 8 BMSes × 1 packet each.
PHASE_B_LASTGOOD_N_BMS = 8


def _tag(events: list[GroundTruthEvent], tag: str) -> list[GroundTruthEvent]:
    """Replace the scenario label on a generated event list in place.

    scenarios.py emits sub-scenario tags like "benign_staged_rollout"; the
    aggregator wants them grouped under "e12b_phaseA_*" so Phase A and
    Phase B can be counted separately without re-implementing the packet
    generators.
    """
    for ev in events:
        ev.scenario = f"{tag}_{ev.scenario}"
    return events


def pack_benign_rollout_signed(n_trials: int = 20,
                               include_stale_injection: bool = True,
                               seed: int = 0) -> list[GroundTruthEvent]:
    """E12b signed-manifest rerun (two-phase).

    Args:
        n_trials: declared trial count for provenance only. The scenario
            pack itself emits ONE trial worth of packets; the sweep
            driver loops to accumulate n_trials runs.
        include_stale_injection: when True, emit a PHASE-B marker event
            and a small post-rejection burst. When False, only Phase A
            runs (useful for a signed-only sanity check without touching
            the .sig file).
        seed: forwarded to benign_staged_rollout for deterministic
            packet timing across trials.

    Returns:
        list[GroundTruthEvent] — all LEGIT events, tagged with
        "e12b_phaseA_*" or "e12b_phaseB_*" so the aggregator can report
        separate FP rates for the two phases.
    """
    events: list[GroundTruthEvent] = []

    # ------------------------------------------------------------------
    # Phase A — valid signed manifest. Re-uses the exact E12 workload.
    # ------------------------------------------------------------------
    # Defensive warm-up mirroring pack_benign_rollout_stress: wave-1 of
    # benign_staged_rollout emits 10 packets in <1s which previously
    # raced the controller's post-SIGUSR1 handle_reset on the switch.
    time.sleep(3.0)

    events += _tag(benign_staged_rollout(waves=5, per_wave=10,
                                          wave_gap_s=30.0, seed=seed),
                   "e12b_phaseA")
    time.sleep(70.0)  # let R5 window clear
    events += _tag(benign_emergency_patch(n_bms=50), "e12b_phaseA")
    time.sleep(70.0)
    events += _tag(benign_source_migration(n_bms=10), "e12b_phaseA")
    time.sleep(70.0)
    events += _tag(benign_delayed_window(n_bms=20, delay_s=15.0),
                   "e12b_phaseA")
    time.sleep(70.0)
    events += _tag(benign_authorized_rollback(n_bms=10), "e12b_phaseA")

    if not include_stale_injection:
        return events

    # ------------------------------------------------------------------
    # Phase B — stale-manifest injection.
    # ------------------------------------------------------------------
    # We record a marker GroundTruthEvent with scenario="e12b_phaseB_
    # inject_marker" and label="SIGFAIL_EXPECTED". This is NOT a packet
    # ground truth — it is a log anchor so the aggregator can correlate
    # the wall-clock of the .sig corruption with the controller's
    # "RAT reload REJECTED" line. run_e12b.py performs the actual
    # corruption on the switch host ~1s after this marker fires.
    time.sleep(70.0)  # clear R5 window before the injection window
    t_inject = time.time()
    events.append(GroundTruthEvent(
        t_send=t_inject,
        scenario="e12b_phaseB_inject_marker",
        label="SIGFAIL_EXPECTED",
        src_ip="0.0.0.0", dst_ip="0.0.0.0", src_port=0,
        topic="", ota_size=0, ota_version=0,
        note=("marker: run_e12b.py is corrupting rat_e12.json.sig "
              "on the switch now; controller reload MUST reject and "
              "retain last-known-good cache"),
    ))

    # Give the controller time to (a) notice the inotify event,
    # (b) fail verify, (c) log REJECT.
    time.sleep(SIG_REJECT_OBSERVE_WINDOW_S)

    # ------------------------------------------------------------------
    # Phase B last-known-good probe — a small benign burst AFTER the
    # rejection. Each packet SHOULD be PASSed because the manager kept
    # the old cache. We deliberately stay under the R5 fanout threshold
    # so this probe exercises Gate A rather than a fresh R5 fire.
    # ------------------------------------------------------------------
    events += _tag(benign_emergency_patch(n_bms=PHASE_B_LASTGOOD_N_BMS),
                   "e12b_phaseB_lastgood")

    return events


__all__ = [
    "pack_benign_rollout_signed",
    "SIG_REJECT_OBSERVE_WINDOW_S",
    "PHASE_B_LASTGOOD_N_BMS",
]
