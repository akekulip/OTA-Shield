"""Pure-Python RAT (Rollout Authorization Table) arbiter.

This module extracts the Gate A / Gate B arbitration logic from
`ota_shield_controller.py` so it can be reused off-switch (e.g. to
apply the same arbitration to a third-party IDS's alerts for a fair
apples-to-apples baseline).

The controller still owns the canonical implementation inside
`Controller.evaluate_hold` / `_rat_allows` / `_rat_allows_rollback` /
`_load_rat_cache`. This module mirrors those semantics **exactly** so
it can be invoked without instantiating a bfrt_grpc-backed controller.

Design contract
---------------
- Input: a RAT JSON file (same schema as `controller/rat.json`) plus
  per-alert records with (src_ip, dst_ip, timestamp, optional ota_size,
  optional ota_version, optional rules_fired).
- Output: a decision in {"PASS", "DROP"} and a human-readable reason
  string that matches the controller's `_log_decision` `reason` field.

Decision rules (verbatim from controller evaluate_hold):
  1. Explicit DROP (action_code == 2 OR R2 OR R4 OR R6): terminal DROP
     with reason="terminal_fire".
  2. R6 sole-terminal with rollback_window match  -> PASS ("rat_rollback_match").
  3. R1 terminal unless RAT allows               -> DROP ("terminal_fire").
  4. Otherwise (HOLD path), RAT match            -> PASS ("rat_match").
  5. Otherwise                                   -> DROP ("rat_miss").

When used against a tool like Suricata that does not expose R1..R6
directly, the caller can conservatively treat every alert as a "HOLD"
with an unknown rule set (rules_fired=[]) and (src, dst, ts, size) —
that is the intended M7 honest-baseline usage. Demotion then hinges
purely on Gate A (RAT coverage window + src/dst/size match).
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

__all__ = [
    "RatEntry",
    "RatArbiter",
    "ipv4_to_int",
    "load_rat_entries",
]

_LOG = logging.getLogger(__name__)


def ipv4_to_int(ip: str) -> int:
    """Duplicate of controller.ipv4_to_int — kept local so this module
    has zero runtime dependency on the bfrt-backed controller import
    chain. Any change in one must be mirrored in the other."""
    parts = [int(p) for p in ip.split(".")]
    assert len(parts) == 4 and all(0 <= p <= 255 for p in parts)
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


@dataclass(frozen=True)
class RatEntry:
    """Normalized RAT authorized_rollouts entry."""
    rollout_id: str
    t_start: float
    t_end: float
    src_ips: frozenset[int]
    bms_ips: frozenset[int]
    size_range: tuple[int, int]
    rollback_window: Optional[tuple[int, int]]


def _parse_window(value: str) -> float:
    """Convert an ISO-8601 timestamp (optionally Z-suffixed) to epoch
    seconds. Mirrors controller._load_rat_cache parsing."""
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def load_rat_entries(rat_path: Path) -> list[RatEntry]:
    """Load and normalize a `rat.json` file.

    Mirrors `Controller._load_rat_cache` line-for-line, including
    M12 size_range validation and the optional §6b rollback_window
    handling.
    """
    if not rat_path.exists():
        _LOG.warning("RAT file %s missing; arbitrer will deny all HOLDs.",
                     rat_path)
        return []

    data = json.loads(rat_path.read_text())
    entries: list[RatEntry] = []
    for entry in data.get("authorized_rollouts", []):
        rid = entry.get("rollout_id", "?")
        try:
            t_start = _parse_window(entry["valid_window_start"])
            t_end = _parse_window(entry["valid_window_end"])
        except Exception:  # noqa: BLE001
            # Match controller: degrade to a wide-open window rather
            # than dropping the whole entry.
            t_start, t_end = 0.0, 2**31 - 1

        sr = entry.get("expected_payload_size_range", [0, 2**31 - 1])
        if not (isinstance(sr, (list, tuple)) and len(sr) == 2):
            _LOG.warning(
                "RAT entry %s has invalid size_range %r — "
                "defaulting to [0, 2^31-1]", rid, sr,
            )
            sr = [0, 2**31 - 1]

        rw = entry.get("rollback_window")
        if isinstance(rw, dict):
            rollback_window: Optional[tuple[int, int]] = (
                int(rw.get("min_version", 0)),
                int(rw.get("max_version", 0)),
            )
        else:
            rollback_window = None

        entries.append(RatEntry(
            rollout_id=rid,
            t_start=t_start,
            t_end=t_end,
            src_ips=frozenset(ipv4_to_int(ip) for ip in
                              entry.get("authorized_source_ips", [])),
            bms_ips=frozenset(ipv4_to_int(ip) for ip in
                              entry.get("target_bms_list", [])),
            size_range=(int(sr[0]), int(sr[1])),
            rollback_window=rollback_window,
        ))

    _LOG.info("Loaded %d RAT entries.", len(entries))
    return entries


class RatArbiter:
    """Pure-Python equivalent of `Controller.evaluate_hold`.

    Stateless with respect to bfrt_grpc; usable from any experiment
    harness (off-switch, laptop-only).
    """

    def __init__(self, entries: Iterable[RatEntry]) -> None:
        self._entries: list[RatEntry] = list(entries)

    # -- Gate A (rollout coverage) ---------------------------------------
    def rat_allows(self, src: int, dst: int, size: int,
                   now: float) -> bool:
        """Mirror of `Controller._rat_allows`. Version is intentionally
        NOT enforced (staged rollouts may ship newer versions)."""
        for e in self._entries:
            if not (e.t_start <= now <= e.t_end):
                continue
            if src not in e.src_ips:
                continue
            if dst not in e.bms_ips:
                continue
            lo, hi = e.size_range
            if not (lo <= size <= hi):
                continue
            return True
        return False

    # -- Gate B (§6b rollback authorization) -----------------------------
    def rat_allows_rollback(self, src: int, dst: int, size: int,
                            version: int, now: float) -> bool:
        """Mirror of `Controller._rat_allows_rollback`."""
        for e in self._entries:
            if not (e.t_start <= now <= e.t_end):
                continue
            if src not in e.src_ips:
                continue
            if dst not in e.bms_ips:
                continue
            lo, hi = e.size_range
            if not (lo <= size <= hi):
                continue
            if e.rollback_window is None:
                continue
            rw_lo, rw_hi = e.rollback_window
            if rw_lo <= version <= rw_hi:
                return True
        return False

    # -- Full arbiter ----------------------------------------------------
    def arbitrate(self,
                  src: int, dst: int,
                  *,
                  ota_size: int = 0,
                  ota_version: int = 0,
                  action_code: int = 0,
                  r1: int = 0, r2: int = 0, r4: int = 0,
                  r5: int = 0, r6: int = 0,
                  now: float,
                  ) -> tuple[str, str]:
        """Return (decision, reason) mirroring `evaluate_hold`.

        decision in {"PASS", "DROP"}. Callers that want a HOLD-bucket
        should set action_code=1 (non-DROP) and set r1..r6 from their
        own detector output. If rule fires are unknown (e.g. a generic
        IDS alert), pass r1..r6 all zero AND action_code != 2; the
        arbiter will then exercise the HOLD path which is exactly what
        the M7 honest-baseline comparison needs.
        """
        # §6b R6 gate.
        if (r6 == 1 and r2 == 0 and r4 == 0 and action_code != 2
                and self.rat_allows_rollback(src, dst, ota_size,
                                             ota_version, now)):
            return ("PASS", "rat_rollback_match")

        # Terminal fires.
        if action_code == 2 or r2 == 1 or r4 == 1 or r6 == 1:
            return ("DROP", "terminal_fire")

        # R1 is terminal unless RAT covers the flow.
        if r1 == 1 and not self.rat_allows(src, dst, ota_size, now):
            return ("DROP", "terminal_fire")

        # HOLD path.
        if self.rat_allows(src, dst, ota_size, now):
            return ("PASS", "rat_match")
        return ("DROP", "rat_miss")
