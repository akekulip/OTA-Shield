"""Exact / closed-form binomial bounds for OTA-Shield IJCIP statistics.

Implements:
- Clopper-Pearson one-sided upper bound (used for zero-event cells and
  every "rare-failure" cell whose Wilson interval would collapse).
- Wilson score two-sided interval (single-population proportion default
  per panel-8 statistical contract).
- Module-level constants used elsewhere (alpha default + z_{0.975}).

Cross-references:
- agent-reports/panel-8-2026-04-29/02_statistical_design.md §6
- EXPERIMENT_DESIGN.md §5 (zero-event cells row)

CP-UB formula:
    k = 0:  UB = 1 - alpha^(1/n)              (closed form)
    k > 0:  UB = scipy.stats.beta.ppf(1-alpha, k+1, n-k)
    k = n:  UB = 1.0
"""
from __future__ import annotations

import math

from scipy.stats import beta as _beta

ALPHA_DEFAULT: float = 0.05
# z_{0.975} for the two-sided Wilson interval at alpha = 0.05.
Z_95: float = 1.959963984540054


def clopper_pearson_upper(k: int, n: int, alpha: float = ALPHA_DEFAULT) -> float:
    """Exact one-sided Clopper-Pearson upper bound on a binomial proportion.

    Parameters
    ----------
    k : int
        Observed failures (or successes — caller-defined). Must satisfy
        0 <= k <= n.
    n : int
        Trials. Must be > 0.
    alpha : float
        Significance level (default 0.05 -> 95 % one-sided UB).

    Returns
    -------
    float
        Upper bound on the underlying probability.
    """
    if n <= 0:
        raise ValueError(f"n must be positive, got {n}")
    if k < 0 or k > n:
        raise ValueError(f"k must be in [0, n], got k={k}, n={n}")
    if not (0.0 < alpha < 1.0):
        raise ValueError(f"alpha must be in (0, 1), got {alpha}")

    if k == 0:
        # 1 - alpha^(1/n).  Closed-form, no scipy round-trip.
        return 1.0 - alpha ** (1.0 / n)
    if k == n:
        return 1.0
    # Beta(k+1, n-k) inverse CDF at 1 - alpha.
    return float(_beta.ppf(1.0 - alpha, k + 1, n - k))


def wilson_score_interval(
    k: int, n: int, alpha: float = ALPHA_DEFAULT
) -> tuple[float, float]:
    """Two-sided Wilson score interval for a single binomial proportion.

    Returns
    -------
    tuple[float, float]
        (lower, upper) bounds, each in [0, 1].
    """
    if n <= 0:
        raise ValueError(f"n must be positive, got {n}")
    if k < 0 or k > n:
        raise ValueError(f"k must be in [0, n], got k={k}, n={n}")
    if not (0.0 < alpha < 1.0):
        raise ValueError(f"alpha must be in (0, 1), got {alpha}")

    # Use the canonical z for alpha=0.05; otherwise compute via scipy.
    if abs(alpha - 0.05) < 1e-12:
        z = Z_95
    else:
        from scipy.stats import norm as _norm
        z = float(_norm.ppf(1.0 - alpha / 2.0))

    p_hat = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p_hat + z2 / (2.0 * n)) / denom
    half = (z * math.sqrt(p_hat * (1.0 - p_hat) / n + z2 / (4.0 * n * n))) / denom
    lo = center - half
    hi = center + half
    # Clamp to [0, 1] and squash sub-epsilon noise.
    if lo < 1e-12:
        lo = 0.0
    if hi > 1.0 - 1e-12:
        hi = 1.0
    return (lo, hi)


__all__ = [
    "ALPHA_DEFAULT",
    "Z_95",
    "clopper_pearson_upper",
    "wilson_score_interval",
]
