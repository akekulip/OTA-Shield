"""Sanity tests for experiments/integrity_checker.py.

Focuses on the deterministic, no-subprocess checks. The PTP / chrony /
tshark-based checks are exercised only via their absence-handling
branches because the test rig has no PTP hardware.
"""
from __future__ import annotations

import json
from pathlib import Path

from experiments.integrity_checker import (
    check_broker_relay_flag,
    check_controller_log_clean,
    check_duration_bound,
    check_manifest_immutability,
    check_monotonic_timestamps,
    check_no_silent_nic_drops,
    check_p4_binary_sha,
    check_packet_conservation,
    check_register_zero_on_startup,
    check_sample_count,
    check_signed_rat_at_trial_start,
    check_sketch_counter_sanity,
    run_all,
)


def test_register_zero_passes_on_dict() -> None:
    name, ok, _ = check_register_zero_on_startup({"r1": 0, "r2": 0})
    assert ok
    assert name == "register_zero_on_startup"


def test_register_zero_fails_on_nonzero() -> None:
    _, ok, _ = check_register_zero_on_startup({"r1": 0, "r2": 7})
    assert not ok


def test_packet_conservation_pass_and_fail() -> None:
    _, ok, _ = check_packet_conservation(1000, 600, 350, 50)  # exact
    assert ok
    _, ok, _ = check_packet_conservation(1000, 600, 300, 50)  # off by 50
    assert not ok


def test_sample_count_pass_and_fail() -> None:
    _, ok, _ = check_sample_count(100, 100)
    assert ok
    # 999 / 1000 -> 0.1 % drift, well within 1 %.
    _, ok, _ = check_sample_count(999, 1000)
    assert ok
    _, ok, _ = check_sample_count(105, 100)
    assert not ok


def test_monotonic_timestamps_pass(tmp_path: Path) -> None:
    p = tmp_path / "decisions.jsonl"
    p.write_text("\n".join(json.dumps({"ts": t}) for t in (1.0, 1.1, 1.2)))
    _, ok, _ = check_monotonic_timestamps(p)
    assert ok


def test_monotonic_timestamps_inversion(tmp_path: Path) -> None:
    p = tmp_path / "decisions.jsonl"
    p.write_text("\n".join(json.dumps({"ts": t}) for t in (1.0, 1.2, 1.1)))
    _, ok, _ = check_monotonic_timestamps(p)
    assert not ok


def test_no_silent_nic_drops_pass() -> None:
    text = "rx_packets: 1000\nrx_missed_errors: 0\n"
    _, ok, _ = check_no_silent_nic_drops(text)
    assert ok


def test_no_silent_nic_drops_fail() -> None:
    text = "rx_missed_errors: 7\n"
    _, ok, _ = check_no_silent_nic_drops(text)
    assert not ok


def test_controller_log_clean(tmp_path: Path) -> None:
    p = tmp_path / "controller.log"
    p.write_text("INFO startup\nINFO RAT loaded: signed=True\n")
    _, ok, _ = check_controller_log_clean(p)
    assert ok
    p.write_text("INFO startup\nERROR something blew up\n")
    _, ok, _ = check_controller_log_clean(p)
    assert not ok


def test_duration_bound() -> None:
    _, ok, _ = check_duration_bound(60.0, 60.5)
    assert ok
    _, ok, _ = check_duration_bound(60.0, 65.0)
    assert not ok


def test_manifest_immutability_with_sidecar(tmp_path: Path) -> None:
    m = tmp_path / "manifest.yaml"
    m.write_text("p4_binary_sha256: deadbeef\n")
    import hashlib
    sha = hashlib.sha256(m.read_bytes()).hexdigest()
    (tmp_path / "manifest.yaml.sha256").write_text(sha + "\n")
    _, ok, _ = check_manifest_immutability(m)
    assert ok
    # Mutate file -> sha mismatch.
    m.write_text("p4_binary_sha256: cafebabe\n")
    _, ok, _ = check_manifest_immutability(m)
    assert not ok


def test_p4_binary_sha_present(tmp_path: Path) -> None:
    m = tmp_path / "manifest.yaml"
    m.write_text("p4_binary_sha256: deadbeef\n")
    _, ok, _ = check_p4_binary_sha(m)
    assert ok


def test_p4_binary_sha_missing(tmp_path: Path) -> None:
    m = tmp_path / "manifest.yaml"
    m.write_text("controller_git_rev: abcd123\n")
    _, ok, _ = check_p4_binary_sha(m)
    assert not ok


def test_sketch_counter_sanity_pass() -> None:
    _, ok, _ = check_sketch_counter_sanity(
        {"sketch": [0, 1, 2, 3], "accepted_total": 100}
    )
    assert ok


def test_sketch_counter_sanity_negative_fails() -> None:
    _, ok, _ = check_sketch_counter_sanity({"sketch": [0, -1, 2]})
    assert not ok


def test_signed_rat_at_trial_start(tmp_path: Path) -> None:
    p = tmp_path / "controller.log"
    p.write_text(
        "2026-04-29T10:00:00 INFO startup\n"
        "2026-04-29T10:00:01 INFO RAT loaded: signed=True\n"
    )
    _, ok, _ = check_signed_rat_at_trial_start(p)
    assert ok

    p.write_text(
        "2026-04-29T10:00:00 INFO startup\n"
        "2026-04-29T10:00:30 INFO RAT loaded: signed=True\n"
    )
    _, ok, _ = check_signed_rat_at_trial_start(p)
    assert not ok


def test_signed_rat_unsigned_fail(tmp_path: Path) -> None:
    p = tmp_path / "controller.log"
    p.write_text(
        "2026-04-29T10:00:00 INFO startup\n"
        "2026-04-29T10:00:01 INFO RAT loaded: signed=False\n"
    )
    _, ok, _ = check_signed_rat_at_trial_start(p)
    assert not ok


def test_broker_relay_flag_text_fixture(tmp_path: Path) -> None:
    p = tmp_path / "broker_capture.json"
    p.write_text('[{"meta":{"broker_relayed":1}}]')
    _, ok, _ = check_broker_relay_flag(p)
    assert ok
    p.write_text('[{"meta":{"broker_relayed":0}}]')
    _, ok, _ = check_broker_relay_flag(p)
    assert not ok


def test_run_all_skips_when_files_missing(tmp_path: Path) -> None:
    """All checks should return ``skip`` when their inputs are absent.

    With no evaluated items, ``valid`` must be False (run_all guards
    against an empty-evaluated trivial pass).
    """
    trial = tmp_path / "trial_X"
    trial.mkdir()
    report = run_all(trial)
    # 13 items reported.
    item_keys = [k for k in report if k.startswith(("0", "1"))
                 and k[:2].isdigit() and k[2] == "_"]
    assert len(item_keys) == 13
    assert report["valid"] is False  # no evidence -> not valid


def test_run_all_passes_with_minimal_fixture(tmp_path: Path) -> None:
    """A trial with all 13 inputs present and clean must report valid."""
    trial = tmp_path / "trial_Y"
    trial.mkdir()

    # registers_t0: zero
    (trial / "registers_t0.json").write_text(json.dumps({"r1": 0, "r2": 0}))

    # manifest with a known sha; sidecar locks it.
    manifest = trial / "manifest.yaml"
    manifest.write_text(
        "p4_binary_sha256: deadbeef\n"
        "declared_duration_s: 60\n"
        "actual_duration_s: 60.1\n"
        "offered: 1000\n"
        "rx_hulk: 600\n"
        "drop_switch: 350\n"
        "drop_nic: 50\n"
        "sample_count_actual: 1000\n"
        "sample_count_expected: 1000\n"
        "ptp_start_ns: 0\n"
        "ptp_end_ns: 50\n"
    )
    import hashlib
    sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
    (trial / "manifest.yaml.sha256").write_text(sha + "\n")

    # decisions.jsonl: monotonic
    (trial / "decisions.jsonl").write_text(
        "\n".join(json.dumps({"ts": t}) for t in (1.0, 1.1, 1.2))
    )

    # registers_post.json: non-negative sketch.
    (trial / "registers_post.json").write_text(
        json.dumps({"sketch": [0, 1, 2], "accepted_total": 1000})
    )

    # ethtool clean.
    (trial / "ethtool_post.txt").write_text("rx_missed_errors: 0\n")

    # controller.log: clean + signed=True early.
    (trial / "controller.log").write_text(
        "2026-04-29T10:00:00 INFO startup\n"
        "2026-04-29T10:00:01 INFO RAT loaded: signed=True\n"
        "2026-04-29T10:00:02 INFO trial begin\n"
    )

    report = run_all(trial)
    # The PTP step uses chrony fallback if its threshold is not met; for
    # the unit test we accept either pass or skip on item 6 but require
    # >90 % overall pass on the items we DO evaluate.
    assert report["n_evaluated"] >= 11
    assert report["pass_rate"] > 0.9
    assert report["valid"] is True
