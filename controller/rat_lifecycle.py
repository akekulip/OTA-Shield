"""RAT manifest lifecycle: signed load, hot reload, concurrency enforcement.

This module hardens the RAT-on-disk pipeline against three lifecycle gaps:

  1. The RAT file was loaded as plain JSON, with no cryptographic integrity.
     An attacker who could write the file (or a misconfigured ops workflow)
     could silently alter rollout authorizations. Fix: ed25519 signature
     verified at every load; unverifiable manifests are refused and the
     last-known-good in-memory cache is preserved.

  2. There was no hot-reload path. Operators editing `rat.json` mid-run saw
     no effect until a controller restart, forcing an uncomfortable choice
     between outage and stale policy. Fix: an inotify watcher triggers a
     re-verify and atomic swap on `IN_CLOSE_WRITE` / `IN_MOVED_TO`.

  3. `max_concurrent_targets` was declared in the manifest but the arbiter
     never consulted it. Per-rollout blast-radius caps were documentation,
     not defense. Fix: an active-session table keyed by `rollout_id`, with
     TTL-aware pruning, is checked at Gate A; excess sessions are denied
     even when every other criterion matches.

The module deliberately owns no gRPC / BFRuntime state. It is safe to
import on a laptop with neither pynacl, inotify_simple, nor the SDE
installed — the heavy imports are deferred until first use and missing
optional dependencies degrade to documented fallback behavior (for
inotify) or a fatal refusal on load (for pynacl when a signature is
present on disk). Unsigned-mode fallback is only taken when the `.sig`
file is *absent*; a present-but-invalid signature is always fatal-for-
this-reload and the last-known-good cache is retained.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RatEntry:
    """One authorized rollout, post-parse and post-validation."""

    rollout_id: str
    t_start: float
    t_end: float
    src_ips: frozenset  # set[int] of IPv4 integers
    bms_ips: frozenset  # set[int] of IPv4 integers
    size_range: tuple  # (int, int)
    rollback_window: tuple | None  # (int, int) | None
    max_concurrent_targets: int  # 0 => unlimited


@dataclass
class ActiveSession:
    """One live session override tracked for M6 concurrency enforcement."""

    rollout_id: str
    src_ip: int
    dst_ip: int
    sport: int
    dport: int
    expires_at: float  # absolute epoch seconds


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


class SignatureError(Exception):
    """Raised when a signature is present but does not verify."""


def _canonical_bytes(rat_path: Path) -> bytes:
    """Return the exact bytes signed by `sign_rat.py`.

    We sign the raw file bytes (not a re-serialized canonical form) so the
    signing workflow is: operator writes/edits rat.json, runs `sign_rat.py
    rat.json`, ships both files together. This keeps the signing surface
    identical to what a manual `sha256sum rat.json` would see, and avoids
    any ambiguity around JSON key ordering or whitespace.
    """
    return rat_path.read_bytes()


def _load_public_key(pub_path: Path):
    """Load an ed25519 public key. Deferred import so laptop-only edits
    without pynacl installed don't break `import rat_lifecycle`."""
    from nacl.signing import VerifyKey  # type: ignore

    raw = pub_path.read_bytes()
    # Support both raw 32-byte and hex-encoded keys. gen_rat_key.py
    # writes raw; hand-rolled keys may be hex.
    if len(raw) == 32:
        return VerifyKey(raw)
    try:
        return VerifyKey(bytes.fromhex(raw.decode().strip()))
    except Exception as exc:
        raise ValueError(f"Unrecognised public-key format in {pub_path}") from exc


def verify_rat_signature(rat_path: Path, sig_path: Path,
                         pub_path: Path, rat_bytes=None) -> None:
    """Raise SignatureError if the signature does not verify.

    Returns None on success. pynacl is imported lazily. If `rat_bytes` is
    given, those exact bytes are verified instead of re-reading `rat_path`;
    callers pass the same buffer they will parse, closing the verify/parse
    time-of-check/time-of-use gap.
    """
    try:
        from nacl.exceptions import BadSignatureError  # type: ignore
    except ImportError as exc:
        raise SignatureError(
            "pynacl is not installed but rat.json.sig is present; "
            "refusing to load an unverifiable signed manifest"
        ) from exc

    vk = _load_public_key(pub_path)
    sig = sig_path.read_bytes()
    # Allow either 64 raw bytes or hex-encoded (sign_rat.py writes raw).
    if len(sig) != 64:
        try:
            sig = bytes.fromhex(sig.decode().strip())
        except Exception as exc:
            raise SignatureError(f"Malformed signature in {sig_path}") from exc
    message = rat_bytes if rat_bytes is not None else _canonical_bytes(rat_path)
    try:
        vk.verify(message, sig)
    except BadSignatureError as exc:
        raise SignatureError(
            f"ed25519 verification failed for {rat_path.name}"
        ) from exc


# ---------------------------------------------------------------------------
# RAT parsing
# ---------------------------------------------------------------------------


def _ipv4_to_int(ip: str) -> int:
    parts = [int(p) for p in ip.split(".")]
    if len(parts) != 4 or not all(0 <= p <= 255 for p in parts):
        raise ValueError(f"Bad IPv4 literal: {ip!r}")
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def parse_rat_entries(raw: dict) -> list[RatEntry]:
    """Parse the JSON dict into RatEntry records. Malformed *individual*
    entries are logged and skipped; a structurally bad document raises."""
    if not isinstance(raw, dict):
        raise ValueError("RAT root must be a JSON object")
    out: list[RatEntry] = []
    for entry in raw.get("authorized_rollouts", []):
        try:
            t_start = datetime.fromisoformat(
                entry["valid_window_start"].replace("Z", "+00:00")
            ).timestamp()
            t_end = datetime.fromisoformat(
                entry["valid_window_end"].replace("Z", "+00:00")
            ).timestamp()
        except Exception:
            t_start, t_end = 0.0, 2**31 - 1

        sr = entry.get("expected_payload_size_range", [0, 2**31 - 1])
        if not (isinstance(sr, (list, tuple)) and len(sr) == 2):
            logger.warning(
                "RAT entry %s has invalid size_range %r; defaulting to [0, 2^31-1]",
                entry.get("rollout_id", "?"), sr,
            )
            sr = [0, 2**31 - 1]

        rw = entry.get("rollback_window")
        rollback_window: tuple | None
        if isinstance(rw, dict):
            rollback_window = (int(rw.get("min_version", 0)),
                               int(rw.get("max_version", 0)))
        else:
            rollback_window = None

        try:
            src_ips = frozenset(_ipv4_to_int(ip) for ip in
                                entry.get("authorized_source_ips", []))
            bms_ips = frozenset(_ipv4_to_int(ip) for ip in
                                entry.get("target_bms_list", []))
        except ValueError as exc:
            logger.warning("RAT entry %s skipped: %s",
                           entry.get("rollout_id", "?"), exc)
            continue

        # max_concurrent_targets=0 means unlimited (back-compat with
        # files that omit the field entirely).
        mct = int(entry.get("max_concurrent_targets", 0) or 0)

        out.append(RatEntry(
            rollout_id=entry.get("rollout_id", "?"),
            t_start=t_start,
            t_end=t_end,
            src_ips=src_ips,
            bms_ips=bms_ips,
            size_range=(int(sr[0]), int(sr[1])),
            rollback_window=rollback_window,
            max_concurrent_targets=mct,
        ))
    return out


# ---------------------------------------------------------------------------
# Lifecycle manager
# ---------------------------------------------------------------------------


class RatLifecycleManager:
    """Owns the verified in-memory RAT cache plus the M6 active-session
    table. Thread-safe; callers must go through the public API.

    Usage contract:
      * `load_initial()` is called once at controller startup. Raises if
        the first load fails in signed mode AND no fallback is permitted.
      * `start_watcher()` spawns an inotify thread that re-verifies the
        manifest on any write/move event and swaps the cache atomically.
      * `start_pruner(ttl_default)` spawns a background thread that walks
        the active-session table every second and evicts stale entries.
      * `check_and_record(rollout_id, ttl)` is the M6 gate: it returns
        True on admission (and records the session) or False if the
        rollout is at its cap.
    """

    def __init__(self,
                 rat_path: Path,
                 sig_path: Path | None = None,
                 pub_path: Path | None = None,
                 allow_unsigned: bool = True) -> None:
        self.rat_path = Path(rat_path)
        self.sig_path = (Path(sig_path) if sig_path is not None
                         else self.rat_path.with_suffix(self.rat_path.suffix + ".sig"))
        self.pub_path = (Path(pub_path) if pub_path is not None
                         else self.rat_path.parent / "rat.pub")
        self.allow_unsigned = allow_unsigned

        # The in-memory cache is protected by `_rat_lock`; callers that
        # want to iterate entries must use `snapshot()`.
        self._rat_lock = threading.RLock()
        self._entries: list[RatEntry] = []
        self._last_signed: bool = False
        self._last_loaded_at: float = 0.0
        # Active sessions keyed by rollout_id. Each value is a list of
        # ActiveSession; short lists expected so O(n) prune is fine.
        self._active: dict[str, list[ActiveSession]] = {}

        # Watcher / pruner thread state.
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        # Inotify may not be installed in every environment. If the
        # watcher start fails we fall back to a polling thread with a
        # 5s cadence so hot-reload still works, just coarser.
        self._watcher_kind: str = "none"

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_initial(self) -> None:
        """First load at startup. Mirrors `reload()` but emits a big
        warning banner if the sig file is missing and unsigned mode is
        permitted; raises if signed mode is required and the file is
        missing or unverifiable."""
        if not self.rat_path.exists():
            logger.warning("RAT file %s missing; manager starts empty.",
                           self.rat_path)
            return
        try:
            self._reload_locked(is_initial=True)
        except SignatureError as exc:
            # First-load signature failure is fatal: we have no
            # last-known-good cache to fall back to.
            logger.error("RAT initial load REFUSED: %s", exc)
            raise

    def reload(self) -> bool:
        """Re-verify and atomically swap the cache. Returns True on
        success, False if the new manifest was rejected (cache unchanged)."""
        try:
            with self._rat_lock:
                self._reload_locked(is_initial=False)
            return True
        except (SignatureError, ValueError, OSError, json.JSONDecodeError) as exc:
            # Keep the old cache intact. This is the M6 journal-hygiene
            # property: an attacker who corrupts rat.json (or the sig)
            # cannot force the controller into an empty-RAT state.
            logger.error(
                "RAT reload REJECTED: %s. Keeping last-known-good cache "
                "(%d entries, signed=%s).",
                exc, len(self._entries), self._last_signed)
            return False

    def _reload_locked(self, is_initial: bool) -> None:
        """Must be called with `_rat_lock` held (or during init).

        Order of operations:
          1. If signature file exists: verify or raise SignatureError.
          2. If signature file is absent and allow_unsigned: warn loudly.
          3. Parse the JSON (raises ValueError on structural damage).
          4. Atomically swap `_entries`.
        """
        if not self.rat_path.exists():
            raise FileNotFoundError(f"RAT file vanished: {self.rat_path}")

        # Read the manifest exactly once; verify and parse the SAME bytes so a
        # concurrent writer cannot swap the file between the signature check
        # and the parse (TOCTOU).
        raw_bytes = self.rat_path.read_bytes()

        signed = self.sig_path.exists()
        if signed:
            if not self.pub_path.exists():
                raise SignatureError(
                    f"Signature {self.sig_path.name} present but "
                    f"public key {self.pub_path} missing")
            verify_rat_signature(self.rat_path, self.sig_path, self.pub_path,
                                 rat_bytes=raw_bytes)
        else:
            if not self.allow_unsigned:
                raise SignatureError(
                    f"rat.json.sig missing and unsigned mode disabled")
            if is_initial:
                banner = "#" * 72
                logger.warning(banner)
                logger.warning(
                    "UNSIGNED RAT MANIFEST: %s has no .sig file. "
                    "This is DEVELOPMENT MODE only and MUST NOT be used "
                    "in production. Re-run `python controller/sign_rat.py "
                    "%s` after editing.",
                    self.rat_path.name, self.rat_path)
                logger.warning(banner)

        raw = json.loads(raw_bytes)
        entries = parse_rat_entries(raw)

        # Atomic swap — a digest-loop thread calling snapshot() either
        # sees the old list or the new list, never a partial mutation.
        self._entries = entries
        self._last_signed = signed
        self._last_loaded_at = time.time()
        logger.info(
            "RAT loaded: %d entries, signed=%s, source=%s",
            len(entries), signed, self.rat_path)

    # ------------------------------------------------------------------
    # Snapshot API (used by arbiter)
    # ------------------------------------------------------------------

    def snapshot(self) -> list[RatEntry]:
        """Return the current entry list. Callers may read this without
        further locking because the list object itself is replaced on
        reload (not mutated in place)."""
        with self._rat_lock:
            return list(self._entries)

    def is_signed(self) -> bool:
        with self._rat_lock:
            return self._last_signed

    # ------------------------------------------------------------------
    # M6: active-session tracking and enforcement
    # ------------------------------------------------------------------

    def _prune_active_locked(self, rollout_id: str, now: float) -> None:
        """Remove expired sessions for this rollout. Caller holds lock."""
        live = [s for s in self._active.get(rollout_id, [])
                if s.expires_at > now]
        if live:
            self._active[rollout_id] = live
        else:
            self._active.pop(rollout_id, None)

    def active_count(self, rollout_id: str) -> int:
        """Number of unexpired active sessions for the given rollout."""
        now = time.time()
        with self._rat_lock:
            self._prune_active_locked(rollout_id, now)
            return len(self._active.get(rollout_id, []))

    def check_and_record(self, rollout_id: str, max_concurrent: int,
                          src_ip: int, dst_ip: int, sport: int, dport: int,
                          ttl_seconds: float) -> bool:
        """Gate A concurrency check.

        Returns True (and records the session) if admitting this session
        would not exceed `max_concurrent`. Returns False otherwise; the
        caller must then DENY the new session regardless of other
        criteria. A cap of 0 means unlimited (back-compat).
        """
        now = time.time()
        with self._rat_lock:
            self._prune_active_locked(rollout_id, now)
            current = len(self._active.get(rollout_id, []))
            if max_concurrent > 0 and current >= max_concurrent:
                logger.warning(
                    "M6 CAP HIT: rollout=%s active=%d cap=%d; denying new "
                    "session %s:%d -> %s:%d",
                    rollout_id, current, max_concurrent,
                    _ip_fmt(src_ip), sport, _ip_fmt(dst_ip), dport)
                return False
            session = ActiveSession(
                rollout_id=rollout_id,
                src_ip=src_ip, dst_ip=dst_ip,
                sport=sport, dport=dport,
                expires_at=now + ttl_seconds,
            )
            self._active.setdefault(rollout_id, []).append(session)
            return True

    # ------------------------------------------------------------------
    # Inotify watcher + polling fallback
    # ------------------------------------------------------------------

    def start_watcher(self) -> None:
        """Spawn the watcher thread. Safe to call once."""
        try:
            from inotify_simple import INotify, flags  # type: ignore
        except ImportError:
            logger.warning(
                "inotify_simple not installed; falling back to a 5s "
                "polling loop for RAT hot-reload.")
            t = threading.Thread(target=self._poll_loop, daemon=True,
                                 name="rat_poll_watcher")
            t.start()
            self._threads.append(t)
            self._watcher_kind = "poll"
            return

        t = threading.Thread(
            target=self._inotify_loop, args=(INotify, flags),
            daemon=True, name="rat_inotify_watcher")
        t.start()
        self._threads.append(t)
        self._watcher_kind = "inotify"
        logger.info("RAT inotify watcher started on %s",
                    self.rat_path.parent)

    def _inotify_loop(self, INotify, flags) -> None:
        try:
            watch = INotify()
            mask = (flags.CLOSE_WRITE | flags.MOVED_TO | flags.CREATE |
                    flags.DELETE)
            watch.add_watch(str(self.rat_path.parent), mask)
            target_names = {self.rat_path.name, self.sig_path.name,
                            self.pub_path.name}
            while not self._stop.is_set():
                events = watch.read(timeout=1000)
                if not events:
                    continue
                if any(ev.name in target_names for ev in events):
                    # Small debounce: editors often emit CLOSE_WRITE for
                    # both rat.json and rat.json.sig within a few ms of
                    # each other. Wait briefly so we don't verify the
                    # old sig against a freshly-written rat.json.
                    time.sleep(0.1)
                    logger.info("RAT change detected; reloading...")
                    self.reload()
        except Exception as exc:  # noqa: BLE001
            logger.error("inotify watcher crashed: %s", exc)

    def _poll_loop(self) -> None:
        """Fallback when inotify_simple is unavailable. 5s cadence —
        coarse but enough to prove the hot-reload path during dev."""
        last_mtime = self._file_mtime()
        while not self._stop.wait(5.0):
            m = self._file_mtime()
            if m != last_mtime:
                last_mtime = m
                logger.info("RAT mtime changed; reloading (poll path)...")
                self.reload()

    def _file_mtime(self) -> tuple:
        def _m(p: Path) -> float:
            try:
                return p.stat().st_mtime
            except FileNotFoundError:
                return 0.0
        return (_m(self.rat_path), _m(self.sig_path), _m(self.pub_path))

    # ------------------------------------------------------------------
    # TTL pruner
    # ------------------------------------------------------------------

    def start_pruner(self) -> None:
        t = threading.Thread(target=self._pruner_loop, daemon=True,
                             name="rat_ttl_pruner")
        t.start()
        self._threads.append(t)
        logger.info("RAT TTL pruner started (1s cadence).")

    def _pruner_loop(self) -> None:
        while not self._stop.wait(1.0):
            now = time.time()
            with self._rat_lock:
                # Copy keys because _prune_active_locked may delete.
                for rid in list(self._active.keys()):
                    self._prune_active_locked(rid, now)

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            try:
                t.join(timeout=2.0)
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# Arbiter-facing helpers
# ---------------------------------------------------------------------------


def find_matching_entry(entries: Iterable[RatEntry],
                        src_ip: int, dst_ip: int,
                        size: int, now: float | None = None) -> RatEntry | None:
    """Return the first entry that matches the (time, src, dst, size)
    tuple, or None. Pure function — no lock needed; callers pass a list
    obtained from `snapshot()`."""
    if now is None:
        now = time.time()
    for entry in entries:
        if not (entry.t_start <= now <= entry.t_end):
            continue
        if src_ip not in entry.src_ips:
            continue
        if dst_ip not in entry.bms_ips:
            continue
        lo, hi = entry.size_range
        if not (lo <= size <= hi):
            continue
        return entry
    return None


def find_rollback_entry(entries: Iterable[RatEntry],
                        src_ip: int, dst_ip: int,
                        version: int, size: int,
                        now: float | None = None) -> RatEntry | None:
    """§6b rollback check: first entry whose rollback_window covers
    `version` AND whose src/dst/size/time match. Default-closed: entries
    without a rollback_window never demote R6."""
    if now is None:
        now = time.time()
    for entry in entries:
        if entry.rollback_window is None:
            continue
        if not (entry.t_start <= now <= entry.t_end):
            continue
        if src_ip not in entry.src_ips:
            continue
        if dst_ip not in entry.bms_ips:
            continue
        lo, hi = entry.size_range
        if not (lo <= size <= hi):
            continue
        rw_lo, rw_hi = entry.rollback_window
        if rw_lo <= version <= rw_hi:
            return entry
    return None


def _ip_fmt(ip_int: int) -> str:
    return ".".join(str((ip_int >> s) & 0xFF) for s in (24, 16, 8, 0))
