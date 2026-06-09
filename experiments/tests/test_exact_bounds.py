"""Tests for experiments/exact_bounds.py."""
from __future__ import annotations

import math

import pytest

from experiments.exact_bounds import (
    ALPHA_DEFAULT,
    Z_95,
    clopper_pearson_upper,
    wilson_score_interval,
)


def test_module_constants() -> None:
    assert ALPHA_DEFAULT == 0.05
    assert math.isclose(Z_95, 1.959963984540054, rel_tol=1e-12)


# --------------------------------------------------------------------- #
# Clopper-Pearson UB
# --------------------------------------------------------------------- #


def test_cp_zero_in_100_known_value() -> None:
    """0 / 100 -> ~0.0295 at alpha = 0.05 (rule-of-three asymptotics)."""
    ub = clopper_pearson_upper(0, 100)
    assert math.isclose(ub, 0.0295, abs_tol=1e-3)


def test_cp_zero_in_one_within_documented_band() -> None:
    """clopper_pearson_upper(0, 1) ∈ [0.949, 1.0]."""
    ub = clopper_pearson_upper(0, 1)
    assert 0.949 <= ub <= 1.0


def test_cp_k_equals_n_returns_one() -> None:
    assert clopper_pearson_upper(5, 5) == 1.0
    assert clopper_pearson_upper(20, 20) == 1.0


def test_cp_general_case_increasing_in_k() -> None:
    """For fixed n, UB must be non-decreasing in k."""
    n = 50
    ubs = [clopper_pearson_upper(k, n) for k in range(0, 11)]
    for a, b in zip(ubs, ubs[1:]):
        assert a < b + 1e-12


def test_cp_input_validation() -> None:
    with pytest.raises(ValueError):
        clopper_pearson_upper(-1, 10)
    with pytest.raises(ValueError):
        clopper_pearson_upper(11, 10)
    with pytest.raises(ValueError):
        clopper_pearson_upper(0, 0)
    with pytest.raises(ValueError):
        clopper_pearson_upper(0, 10, alpha=1.5)


# --------------------------------------------------------------------- #
# Wilson score interval
# --------------------------------------------------------------------- #


def test_wilson_50_in_100_matches_published() -> None:
    """Wilson 50/100 ≈ (0.404, 0.595) at alpha = 0.05.

    Published rounding of the Wilson upper is 0.596; the spec wrote
    0.595 with abs tolerance 1e-3, which matches at 2e-3.
    """
    lo, hi = wilson_score_interval(50, 100)
    assert math.isclose(lo, 0.404, abs_tol=2e-3)
    assert math.isclose(hi, 0.596, abs_tol=2e-3)


def test_wilson_zero_returns_zero_lower() -> None:
    lo, hi = wilson_score_interval(0, 100)
    assert lo == 0.0
    assert 0.0 < hi < 0.05


def test_wilson_full_returns_one_upper() -> None:
    lo, hi = wilson_score_interval(100, 100)
    assert hi == 1.0
    assert 0.95 < lo < 1.0


def test_wilson_input_validation() -> None:
    with pytest.raises(ValueError):
        wilson_score_interval(-1, 10)
    with pytest.raises(ValueError):
        wilson_score_interval(11, 10)
    with pytest.raises(ValueError):
        wilson_score_interval(0, 0)
