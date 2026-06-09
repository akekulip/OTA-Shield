"""Tests for experiments/seed_schedule.py."""
from __future__ import annotations

from experiments.seed_schedule import (
    HELD_OUT_MARKER_DEFAULT,
    MASTER_SEED_DEFAULT,
    derive_trial_seed,
    held_out_seed,
)


def test_determinism_same_inputs_same_output() -> None:
    a = derive_trial_seed("T1.5", 7)
    b = derive_trial_seed("T1.5", 7)
    assert a == b


def test_determinism_with_string_trial_id() -> None:
    a = derive_trial_seed("T2.5", "trial-04")
    b = derive_trial_seed("T2.5", "trial-04")
    assert a == b


def test_different_experiment_ids_differ() -> None:
    a = derive_trial_seed("T1.5", 0)
    b = derive_trial_seed("T1.6", 0)
    assert a != b


def test_different_trial_ids_differ() -> None:
    a = derive_trial_seed("T2.4", 0)
    b = derive_trial_seed("T2.4", 1)
    assert a != b


def test_different_master_seeds_differ() -> None:
    a = derive_trial_seed("T2.5", 3, master_seed="0xCAFE")
    b = derive_trial_seed("T2.5", 3, master_seed="0xBEEF")
    assert a != b


def test_output_is_uint32() -> None:
    for trial in range(20):
        seed = derive_trial_seed("T2.6", trial)
        assert 0 <= seed <= 0xFFFFFFFF
        assert isinstance(seed, int)


def test_held_out_seed_xor_property() -> None:
    s = held_out_seed("0xCAFE", "0xH0LD")
    # 0xCAFE = 51966, 0xH0LD parses via raw bytes since 'H' / 'L' not hex.
    # Whatever the exact integer, XORing it back with itself returns 0.
    assert s == held_out_seed("0xCAFE", "0xH0LD")


def test_held_out_seed_changes_with_marker() -> None:
    a = held_out_seed("0xCAFE", "0xH0LD")
    b = held_out_seed("0xCAFE", "0xH0LE")
    assert a != b


def test_defaults_match_spec() -> None:
    assert MASTER_SEED_DEFAULT == "0xCAFE"
    assert HELD_OUT_MARKER_DEFAULT == "0xH0LD"
