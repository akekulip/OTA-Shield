"""Deterministic seed derivation for OTA-Shield IJCIP trials.

Per EXPERIMENT_DESIGN.md §1 + panel-8 02_statistical_design.md §3:
    seed = sha256(f"{exp_id}-{trial_id}-{master_seed}").digest()[:8]
masked to 32 bits so both numpy.random.default_rng and Python random
accept it without overflow.

The master seed is the locked string ``"0xCAFE"``. The held-out marker
is the locked string ``"0xH0LD"``.
"""
from __future__ import annotations

import hashlib

MASTER_SEED_DEFAULT: str = "0xCAFE"
HELD_OUT_MARKER_DEFAULT: str = "0xH0LD"

_UINT32_MASK: int = 0xFFFFFFFF


def _string_as_int(s: str) -> int:
    """Robust int interpretation of a master/held-out seed string.

    Accepts ``"0xCAFE"`` style hex literals as well as plain decimal
    strings; falls back to ``int.from_bytes(s.encode(), 'big')`` so
    any caller-defined label still produces a deterministic integer.
    """
    s = s.strip()
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s, 10)
    except ValueError:
        return int.from_bytes(s.encode("utf-8"), "big")


def derive_trial_seed(
    experiment_id: str,
    trial_id: int | str,
    master_seed: str = MASTER_SEED_DEFAULT,
) -> int:
    """Return the 32-bit unsigned seed for ``(experiment_id, trial_id)``.

    Same inputs always produce the same seed (determinism contract). The
    output is masked to 32 bits so both ``numpy.random.default_rng`` and
    the C-extension RNGs accept it without overflow.
    """
    payload = f"{experiment_id}-{trial_id}-{master_seed}".encode("utf-8")
    digest = hashlib.sha256(payload).digest()[:8]
    return int.from_bytes(digest, "big") & _UINT32_MASK


def held_out_seed(
    master_seed: str = MASTER_SEED_DEFAULT,
    held_out_marker: str = HELD_OUT_MARKER_DEFAULT,
) -> int:
    """Return the integer seed used for the held-out stratification.

    Per EXPERIMENT_DESIGN.md T2.4: ``seed = 0xCAFE ^ 0xH0LD``. We XOR the
    integer interpretations of both labels (hex if parseable, otherwise
    raw-bytes) and mask to 32 bits.
    """
    a = _string_as_int(master_seed)
    b = _string_as_int(held_out_marker)
    return (a ^ b) & _UINT32_MASK


__all__ = [
    "MASTER_SEED_DEFAULT",
    "HELD_OUT_MARKER_DEFAULT",
    "derive_trial_seed",
    "held_out_seed",
]
