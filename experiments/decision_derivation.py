"""Shared controller-decision derivation for OTA-Shield aggregators.

Why this module exists
----------------------
The per-trial files that the experiment drivers slice off the switch
(``controller_decisions.jsonl`` / ``decisions.jsonl``) are the controller's
RAW DIGEST log (the stream written by ``Controller.run`` at
``self.log_fh.write(...)``), NOT the arbiter's ``_log_decision`` output.
Those raw digests therefore carry ``action_name: null`` and have NO
``decision`` / ``reason`` strings; they only carry the genuine data-plane
fields:

    _type        : "mqtt_digest" | "hold_digest" | ...
    action_code  : 0=PASS, 1=HOLD, 2=DROP   (policy_engine.p4)
    r1..r6_fired : per-rule detection bits
    src_ip/dst_ip/src_port/dst_port (integers)
    ota_size / ota_version
    is_default_entry, session_id, bms_idx

Aggregators that score ``rec.get("decision")`` therefore see ``None`` for
every event and collapse to NaN. This helper reconstructs each event's
final decision/reason by mirroring ``Controller.evaluate_hold`` exactly,
so the genuine decision can be recovered from the logged fields.

Source of truth
---------------
The mapping below is transcribed line-for-line from
``controller/ota_shield_controller.py:Controller.evaluate_hold`` (the
canonical arbiter) and ``p4src/policy_engine.p4`` (the action_code
definition). The pure-Python RAT gate (``rat_allows`` /
``rat_allows_rollback``) is delegated to ``controller/rat_arbiter.py``,
which already mirrors the controller's Gate A / Gate B verbatim.

action_code -> action (policy_engine.p4 lines 27-29):
    0 = ACTION_PASS
    1 = ACTION_HOLD
    2 = ACTION_DROP

Note: ``ingress_control.p4`` may FORCE ``action_code = 2`` independently
of the rule bits when ``hold_armed_reg`` is armed for the source
(the documented hold-armed cascade). The logged ``action_code`` is the
post-cascade value, so this helper faithfully reflects what the data
plane actually told the controller.

evaluate_hold resolution order (verbatim):
    0. action_code == 0 (or no action_code / mqtt_digest): the data plane
       forwarded the trigger packet and the controller never enters
       evaluate_hold -> silent PASS ("silent_pass").
    1. §6b R6 gate: r6==1 and r2==0 and r4==0 and code!=2 and not
       disable_rat and rat_allows_rollback(...) -> PASS "rat_rollback_match".
    2. Terminal fire: code==2 or r2 or r4 or r6 -> DROP "terminal_fire".
    3. R1 terminal unless RAT covers the flow:
       r1==1 and (disable_rat or not rat_allows(...)) -> DROP "terminal_fire".
    4. disable_rat ablation -> DROP "rat_disabled_ablation".
    5. HOLD path, RAT match -> PASS "rat_match".
    6. otherwise -> DROP "rat_miss".

Off-switch limitation (documented, not hidden)
----------------------------------------------
The controller's ``rat_match`` and §6b branches additionally enforce
``max_concurrent_targets`` via the STATEFUL ``RatLifecycleManager.
check_and_record`` (reasons ``rat_max_concurrent`` /
``rat_rollback_max_concurrent``). That admission state cannot be replayed
purely from a digest stream, so this helper resolves only the admit==True
side of those branches. Callers that need the concurrency-cap reasons must
provide the recorded admission decisions. For datasets where every event
is terminal at code==2 (e.g. the 2026-06-06 E22 run, where the hold-armed
cascade forced code==2 on all 760 hold_digests), the RAT branches are
unreachable, so this limitation does not affect the recovered numbers.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional

try:
    from scipy.stats import beta as _beta  # type: ignore
    _HAVE_SCIPY = True
except Exception:  # noqa: BLE001 - scipy optional; CP degrades to NaN bounds
    _HAVE_SCIPY = False

# Reuse the canonical pure-Python arbiter for the RAT gates.
try:  # pragma: no cover - import shim for both package and script use
    from controller.rat_arbiter import RatArbiter  # type: ignore
except Exception:  # noqa: BLE001
    RatArbiter = None  # type: ignore

__all__ = [
    "ipv4_to_int",
    "int_to_ipv4",
    "DerivedDecision",
    "derive_decision",
    "clopper_pearson",
]

# action_code constants — verbatim from p4src/policy_engine.p4.
ACTION_PASS = 0
ACTION_HOLD = 1
ACTION_DROP = 2


def ipv4_to_int(ip: str) -> int:
    """Convert dotted-quad IPv4 to 32-bit int (controller convention)."""
    parts = ip.split(".")
    return ((int(parts[0]) << 24) | (int(parts[1]) << 16) |
            (int(parts[2]) << 8) | int(parts[3]))


def int_to_ipv4(x: int) -> str:
    """Inverse of ipv4_to_int (for diagnostics)."""
    return ".".join(str((x >> (8 * (3 - i))) & 0xFF) for i in range(4))


@dataclass(frozen=True)
class DerivedDecision:
    """Resolved controller decision for one logged digest record.

    Attributes:
        decision: "PASS" or "DROP" (controller-side, matches _log_decision).
        reason: Human-readable arbiter rationale, matching the controller's
            ``reason`` strings (e.g. "terminal_fire", "rat_miss",
            "rat_match", "silent_pass").
        action_code: The logged data-plane action_code (None for records
            that carry none, e.g. mqtt_digest).
        rules_fired: Rule labels that fired on this event (e.g. ["R1"]).
    """
    decision: str
    reason: str
    action_code: Optional[int]
    rules_fired: tuple[str, ...]


def derive_decision(rec: dict,
                    arbiter: "Optional[RatArbiter]" = None,
                    now: Optional[float] = None,
                    *,
                    disable_rat: bool = False,
                    disable_r6: bool = False) -> DerivedDecision:
    """Resolve a raw digest record into (decision, reason).

    Mirrors ``Controller.evaluate_hold`` exactly. See the module docstring
    for the verbatim resolution order and source references.

    Args:
        rec: One parsed digest record from the controller's raw digest log.
        arbiter: Optional pure-Python ``RatArbiter`` realising Gate A / B.
            If None, RAT coverage is treated as a miss (default-closed),
            which matches the controller when no RAT entry covers a flow.
        now: Epoch seconds for the RAT time-window check. Defaults to the
            record's ``_t_recv`` so the coverage window is evaluated at the
            same instant the controller saw the digest.
        disable_rat: ABLATION flag (E4): force every HOLD to DROP.
        disable_r6: ABLATION flag: treat R6 as absent (5-rule baseline).

    Returns:
        A ``DerivedDecision``.
    """
    rtype = rec.get("_type")
    code_raw = rec.get("action_code")
    if now is None:
        now = float(rec.get("_t_recv", 0.0) or 0.0)

    # Step 0: records with no action_code (mqtt_digest / OTA-header digest)
    # never enter evaluate_hold — the controller only calls it for
    # hold_digest. The data plane forwarded the trigger packet => silent
    # PASS. action_code == 0 (PASS override) is the same outcome.
    if code_raw is None or rtype == "mqtt_digest":
        return DerivedDecision("PASS", "silent_pass", None, ())
    code = int(code_raw)
    if code == ACTION_PASS:
        return DerivedDecision("PASS", "silent_pass", code, ())

    r1 = int(rec.get("r1_fired", 0) or 0)
    r2 = int(rec.get("r2_fired", 0) or 0)
    r4 = int(rec.get("r4_fired", 0) or 0)
    r5 = int(rec.get("r5_fired", 0) or 0)
    r6 = int(rec.get("r6_fired", 0) or 0)
    if disable_r6:
        r6 = 0
    rules_fired = tuple(n for n, v in
                        (("R1", r1), ("R2", r2), ("R4", r4),
                         ("R5", r5), ("R6", r6)) if v)

    src = int(rec.get("src_ip", 0) or 0)
    dst = int(rec.get("dst_ip", 0) or 0)
    size = int(rec.get("ota_size", 0) or 0)
    version = int(rec.get("ota_version", 0) or 0)

    def _rat_allows() -> bool:
        if arbiter is None:
            return False
        return arbiter.rat_allows(src, dst, size, now)

    def _rat_allows_rollback() -> bool:
        if arbiter is None:
            return False
        return arbiter.rat_allows_rollback(src, dst, size, version, now)

    # Step 1: §6b R6 RAT-gated rollback authorization.
    if (r6 == 1 and r2 == 0 and r4 == 0 and code != ACTION_DROP
            and not disable_rat and _rat_allows_rollback()):
        # NB: controller additionally enforces max_concurrent_targets here;
        # see module docstring. We resolve the admit==True side only.
        return DerivedDecision("PASS", "rat_rollback_match", code, rules_fired)

    # Step 2: terminal fires (no RAT override possible).
    if code == ACTION_DROP or r2 == 1 or r4 == 1 or r6 == 1:
        return DerivedDecision("DROP", "terminal_fire", code, rules_fired)

    # Step 3: R1 terminal unless an active RAT authorisation covers the flow.
    if r1 == 1 and (disable_rat or not _rat_allows()):
        return DerivedDecision("DROP", "terminal_fire", code, rules_fired)

    # Step 4: ablation — RAT disabled forces DROP.
    if disable_rat:
        return DerivedDecision("DROP", "rat_disabled_ablation", code,
                               rules_fired)

    # Step 5/6: HOLD path — RAT match -> PASS, else fail-closed DROP.
    if _rat_allows():
        return DerivedDecision("PASS", "rat_match", code, rules_fired)
    return DerivedDecision("DROP", "rat_miss", code, rules_fired)


def clopper_pearson(k: int, n: int,
                    alpha: float = 0.05) -> tuple[float, float, float]:
    """Exact Clopper-Pearson interval for a binomial proportion.

    Returns ``(point, lo, hi)``. Never returns ``[1.000, 1.000]``: when
    ``k == n`` the lower bound is strictly below 1; when ``k == 0`` the
    upper bound is strictly above 0. For ``n == 0`` the proportion is
    undefined and ``(nan, 0.0, 1.0)`` is returned.

    Falls back to NaN bounds if scipy is unavailable.
    """
    if n == 0:
        return (float("nan"), 0.0, 1.0)
    point = k / n
    if not _HAVE_SCIPY:
        return (point, float("nan"), float("nan"))
    lo = 0.0 if k == 0 else float(_beta.ppf(alpha / 2, k, n - k + 1))
    hi = 1.0 if k == n else float(_beta.ppf(1 - alpha / 2, k + 1, n - k))
    if math.isnan(lo):
        lo = 0.0
    if math.isnan(hi):
        hi = 1.0
    return (point, lo, hi)
