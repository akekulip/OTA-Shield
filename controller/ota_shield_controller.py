#!/usr/bin/env python3
"""OTA-Shield controller — Phase 5 (cumulative through Phase 1).

Phase-5 additions (on top of Phase 4):
  * Install authorized sources (R2) and BMS IP→index (R1) tables from rat.json.
  * Set R1 and R4 thresholds at startup (defaults from Definition 3.5–3.8).
  * Background thread: write `coarse_time_reg[0]` every 1 s with current epoch
    seconds so the data plane's R1 rule has a long-scale time axis.
  * Subscribe to `phase5_rule_alert_digest_t` in addition to phases 1–4.

Usage:
    source $SDE/set_env.sh
    python3 ota_shield_controller.py \\
        --grpc-addr 10.10.54.15:50052 \\
        --p4-name ota_shield \\
        --rat controller/rat.json \\
        --log runs/phase5_digests.jsonl
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any

try:
    import bfrt_grpc.client as bfrt_client
except ImportError:  # pragma: no cover
    bfrt_client = None

# M6 (IJCIP reviewer major concern): signed-manifest + hot-reload +
# max_concurrent_targets enforcement live in a sibling module so the
# controller file stays focused on data-plane glue. See rat_lifecycle.py
# for the journal-hygiene rationale.
from rat_lifecycle import (
    RatLifecycleManager,
    find_matching_entry,
    find_rollback_entry,
)


DEFAULT_GRPC = "10.10.54.15:50052"
DEFAULT_P4_NAME = "ota_shield"
DEFAULT_CLIENT_ID = 0
DEFAULT_DEVICE_ID = 0

OTA_PREFIX = b"/ota/bms/"
TOPIC_SLOT_BYTES = 32

"""bf-p4c publishes learns by Digest *instance* name (defined in deparser.p4)
— `phase*_digest_t` is the type, not the learn name. We try a few qualifier
forms to stay robust across SDE conventions."""
DIGEST_INSTANCE_NAMES = (
    "classify_digest",
    "mqtt_digest",
    "session_digest",
    "r5_digest",
    "rule_digest",
    "hold_digest",
)

SESSION_OVERRIDE_TABLE = "Ingress.session_action_override"
HOLD_OVERRIDE_TTL_S    = 5.0   # fail-closed window per Phase 6 spec
DIGEST_NAME_PREFIXES = (
    "",                         # bare instance name
    "IngressDeparser.",         # control-scoped
    "pipe.IngressDeparser.",    # pipe-qualified
)

R5_BF_REGISTERS = (
    "Ingress.fleet.bf_r0",
    "Ingress.fleet.bf_r1",
    "Ingress.fleet.bf_r2",
)
R5_COUNT_REGISTER     = "Ingress.fleet.r5_count_reg"
R1_LAST_SEEN_REGISTER = "Ingress.rules.r1_last_seen_reg"
COARSE_TIME_REGISTER  = "Ingress.rules.coarse_time_reg"
SESSION_BYTES_REGISTER = "Ingress.sessions.session_bytes_reg"
SESSION_FIRST_TS_REGISTER = "Ingress.sessions.session_first_ts_reg"
R6_MAX_VERSION_REGISTER = "Ingress.r6.r6_bms_max_version_reg"
HOLD_ARMED_REGISTER   = "Ingress.hold_armed_reg"
R1_REGISTER_SLOTS     = 64        # only 0..63 used by bms_idx
R6_REGISTER_SLOTS     = 256       # p4src/rule_r6_rollback.p4 Register<.., bit<8>>(256)
HOLD_ARMED_SLOTS      = 256       # p4src/ingress_control.p4 Register<bit<8>,bit<8>>(256)
SESSION_TABLE_SIZE    = 65536     # mirrors p4src/headers.p4 SESSION_TABLE_SIZE

R5_WINDOW_SECONDS   = 60
COARSE_TIME_PERIOD  = 1.0            # write coarse_time every 1 s
R1_MIN_INTERVAL_S   = 14400          # 4 h; matches secondary_rules.p4 compile-time constant
R4_MAX_BYTES        = 2 * 1024 * 1024  # 2 MB


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="OTA-Shield controller (Phase 5)")
    p.add_argument("--grpc-addr", default=DEFAULT_GRPC)
    p.add_argument("--p4-name", default=DEFAULT_P4_NAME)
    p.add_argument("--client-id", type=int, default=DEFAULT_CLIENT_ID)
    p.add_argument("--device-id", type=int, default=DEFAULT_DEVICE_ID)
    p.add_argument("--log", type=Path, default=Path("runs/phase5_digests.jsonl"))
    p.add_argument("--rat", type=Path, default=Path("controller/rat.json"))
    p.add_argument("--r5-threshold", type=int, default=4)
    p.add_argument("--r1-threshold-s", type=int, default=R1_MIN_INTERVAL_S)
    p.add_argument("--r4-threshold-bytes", type=int, default=R4_MAX_BYTES)
    p.add_argument("--window-seconds", type=int, default=R5_WINDOW_SECONDS)
    p.add_argument("--coarse-time-period", type=float, default=COARSE_TIME_PERIOD)
    p.add_argument("--no-window-clear", action="store_true")
    p.add_argument("--no-coarse-time", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--disable-rat", action="store_true",
                   help="ABLATION: ignore RAT; every HOLD becomes DROP. "
                        "Use only for E4 ablation experiments.")
    p.add_argument("--disable-r6", action="store_true",
                   help="ABLATION: ignore r6_fired from digests. Use for "
                        "E19 baseline (5-rule vs 6-rule comparison). P4 "
                        "still evaluates R6 but controller masks it in "
                        "arbitration and rules_fired.")
    # M6: RAT manifest lifecycle controls.
    p.add_argument("--rat-pub", type=Path, default=None,
                   help="ed25519 verify key for the RAT manifest "
                        "(default: <rat-dir>/rat.pub).")
    p.add_argument("--rat-sig", type=Path, default=None,
                   help="ed25519 signature file for the RAT manifest "
                        "(default: <rat>.sig).")
    p.add_argument("--require-signed-rat", action="store_true",
                   help="Refuse to start if rat.json.sig is missing. "
                        "Production deployments should always set this; "
                        "dev workflows may omit it to iterate without "
                        "re-signing.")
    return p.parse_args()


def setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )


def build_topic_prefix_entry() -> tuple[bytearray, bytearray]:
    """bfrt_grpc KeyTuple rejects plain `bytes` — it wants `bytearray` (its
    internal ByteArray type) for wide key fields."""
    value = bytearray(OTA_PREFIX + b"\x00" * (TOPIC_SLOT_BYTES - len(OTA_PREFIX)))
    mask = bytearray(b"\xff" * len(OTA_PREFIX) + b"\x00" * (TOPIC_SLOT_BYTES - len(OTA_PREFIX)))
    return value, mask


def socket_fmt(ip_int: int) -> str:
    return ".".join(str((ip_int >> s) & 0xFF) for s in (24, 16, 8, 0))


def ipv4_to_int(ip: str) -> int:
    parts = [int(p) for p in ip.split(".")]
    assert len(parts) == 4 and all(0 <= p <= 255 for p in parts)
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


class Controller:
    def __init__(self, args: argparse.Namespace) -> None:
        if bfrt_client is None:
            raise RuntimeError("bfrt_grpc not importable. Source $SDE/set_env.sh first.")
        self.args = args
        self.args.log.parent.mkdir(parents=True, exist_ok=True)
        self.log_fh = open(self.args.log, "a", buffering=1)
        self.interface: Any = None
        self.bfrt_info: Any = None
        self.target: Any = None
        self.digest_learns: dict[str, Any] = {}
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

        # Integrity infrastructure ----------------------------------------
        # F1.3/F2.2/F4.2/F5.2 fixes: serialise all writes to the digest log
        # and the controller decision log so multi-thread interleaving
        # cannot corrupt JSONL lines.
        self._digest_log_lock = threading.Lock()
        self._decision_log_lock = threading.Lock()
        # Trial epoch — incremented by handle_reset (SIGUSR1). Embedded in
        # every digest and decision record so the aggregator can filter by
        # epoch instead of trusting byte offsets (F2.2/F7.1).
        self._trial_epoch = 0
        # Step-0 (2026-04-20): every per-step failure inside
        # _reset_detector_state() appends a "<register>: <reason>" string
        # here. handle_dump_state (SIGUSR2) exposes this to preflight so a
        # silent partial reset can no longer be consumed as "ready".
        self._last_reset_errors: list[str] = []
        # Path for SIGUSR2 state dump. /tmp is fine: preflight scps it back.
        self._state_dump_path: str = "/tmp/ota_controller_state.json"
        # F5.1 / F5.2 — single-thread expiry scheduler instead of a Timer
        # thread per override. heapq + Condition + bounded sleep.
        import heapq as _heapq
        self._expiry_heap: list[tuple[float, Any]] = []
        self._expiry_lock = threading.Lock()
        self._expiry_cv = threading.Condition(self._expiry_lock)
        self._heapq = _heapq
        # Shutdown signalling
        self._shutting_down = False

        # M6 RAT lifecycle manager. Constructed eagerly so the digest
        # loop can call `snapshot()` without a None guard; `load_initial`
        # is invoked from `run()` after logging is set up.
        self._rat_mgr = RatLifecycleManager(
            rat_path=self.args.rat,
            sig_path=getattr(self.args, "rat_sig", None),
            pub_path=getattr(self.args, "rat_pub", None),
            allow_unsigned=not getattr(self.args, "require_signed_rat", False),
        )

    # -- connection -------------------------------------------------------
    def connect(self) -> None:
        logging.info("Connecting to %s...", self.args.grpc_addr)
        self.interface = bfrt_client.ClientInterface(
            grpc_addr=self.args.grpc_addr,
            client_id=self.args.client_id,
            device_id=self.args.device_id,
        )
        self.interface.bind_pipeline_config(self.args.p4_name)
        self.bfrt_info = self.interface.bfrt_info_get(self.args.p4_name)
        self.target = bfrt_client.Target(device_id=self.args.device_id, pipe_id=0xFFFF)
        for inst in DIGEST_INSTANCE_NAMES:
            attached = False
            for prefix in DIGEST_NAME_PREFIXES:
                fq = f"{prefix}{inst}"
                try:
                    self.digest_learns[inst] = self.bfrt_info.learn_get(fq)
                    logging.info("Attached learn: %s", fq)
                    attached = True
                    break
                except Exception:  # noqa: BLE001
                    continue
            if not attached:
                logging.warning("learn_get failed for all name forms of %s", inst)
        logging.info("Connected; %d learn streams attached.", len(self.digest_learns))

    # -- register helpers -------------------------------------------------
    def _reg_write(self, reg_name: str, idx: int, val: int) -> None:
        reg = self.bfrt_info.table_get(reg_name)
        key = reg.make_key([bfrt_client.KeyTuple("$REGISTER_INDEX", idx)])
        field = f"{reg_name.split('.')[-1]}.f1"
        data = reg.make_data([bfrt_client.DataTuple(field, val)])
        try:
            reg.entry_mod(self.target, [key], [data])
        except Exception:
            reg.entry_add(self.target, [key], [data])

    def _reg_write_many(self, reg_name: str, items: list[tuple[int, int]]) -> None:
        """AF-003: batch register writes into a single RPC."""
        reg = self.bfrt_info.table_get(reg_name)
        keys, datas = [], []
        field = f"{reg_name.split('.')[-1]}.f1"
        for idx, val in items:
            keys.append(reg.make_key([bfrt_client.KeyTuple("$REGISTER_INDEX", idx)]))
            datas.append(reg.make_data([bfrt_client.DataTuple(field, val)]))
        try:
            reg.entry_mod(self.target, keys, datas)
        except Exception:
            reg.entry_add(self.target, keys, datas)

    # -- startup table installation ---------------------------------------
    def install_ota_prefix_entry(self) -> None:
        value, mask = build_topic_prefix_entry()
        table = self.bfrt_info.table_get("Ingress.ota_topic_prefix_match")
        key = table.make_key([
            bfrt_client.KeyTuple("hdr.mqtt_topic.bytes", value, mask)
        ])
        try:
            table.entry_del(self.target, [key])
        except bfrt_client.BfruntimeRpcException:
            pass
        data = table.make_data([], "Ingress.set_ota_flag")
        table.entry_add(self.target, [key], [data])
        logging.info("Installed OTA prefix entry: /ota/bms/ (ternary)")

    def install_authorized_sources(self, source_ips: list[str]) -> None:
        table = self.bfrt_info.table_get("Ingress.r2_authorized_sources")
        for ip in source_ips:
            key = table.make_key([
                bfrt_client.KeyTuple("hdr.ipv4.src_addr", ipv4_to_int(ip))
            ])
            data = table.make_data([], "NoAction")
            try:
                table.entry_del(self.target, [key])
            except bfrt_client.BfruntimeRpcException:
                pass
            table.entry_add(self.target, [key], [data])
        logging.info("Installed %d authorized source entries.", len(source_ips))

    def install_bms_index_table(self, bms_ips: list[str]) -> None:
        table = self.bfrt_info.table_get("Ingress.bms_ip_to_idx")
        for idx, ip in enumerate(bms_ips):
            if idx >= 64:
                logging.warning("BMS list has >64 entries; dropping beyond 64.")
                break
            key = table.make_key([
                bfrt_client.KeyTuple("hdr.ipv4.dst_addr", ipv4_to_int(ip))
            ])
            data = table.make_data(
                [bfrt_client.DataTuple("idx", idx)],
                "Ingress.set_bms_idx",
            )
            try:
                table.entry_del(self.target, [key])
            except bfrt_client.BfruntimeRpcException:
                pass
            table.entry_add(self.target, [key], [data])
        logging.info("Installed %d BMS index entries.", min(len(bms_ips), 64))

    # -- Phase 6: session-action override helpers ------------------------
    def install_session_override(self, src_ip: int, dst_ip: int,
                                  sport: int, dport: int,
                                  action: str,
                                  protocol: int = 6) -> None:
        """T1.7 (Panel-7) — install on the 5-tuple key (src_addr, dst_addr,
        dst_port, protocol, src_port) at size 256. Replaces the prior
        E13 src-IP-only aggregation: ALLOW for one 5-tuple no longer
        inadvertently authorizes unrelated traffic from the same src,
        and the 256-entry size accommodates 200 distinct sources × ~1.2
        concurrent flows without RESOURCE_EXHAUSTED rejects.

        protocol defaults to TCP (6); the override table is TCP-specific
        because hdr.tcp.{src,dst}_port are part of the key and the apply
        block guards on hdr.tcp.isValid(). Non-TCP HOLD verdicts cannot
        carry valid sport/dport into the data plane key, so callers
        should not invoke this for non-TCP flows; if they do, the entry
        will be installed but never matched."""
        table = self.bfrt_info.table_get(SESSION_OVERRIDE_TABLE)
        key = table.make_key([
            bfrt_client.KeyTuple("hdr.ipv4.src_addr", src_ip),
            bfrt_client.KeyTuple("hdr.ipv4.dst_addr", dst_ip),
            bfrt_client.KeyTuple("hdr.tcp.dst_port",  dport),
            bfrt_client.KeyTuple("hdr.ipv4.protocol", protocol),
            bfrt_client.KeyTuple("hdr.tcp.src_port",  sport),
        ])
        action_name = (
            "Ingress.session_deny" if action == "drop"
            else "Ingress.session_allow"
        )
        data = table.make_data([], action_name)
        try:
            table.entry_del(self.target, [key])
        except bfrt_client.BfruntimeRpcException:
            pass
        try:
            table.entry_add(self.target, [key], [data])
        except bfrt_client.BfruntimeRpcException as exc:
            # Table capacity exhausted (RESOURCE_EXHAUSTED) or similar.
            # Log-and-continue instead of crashing so the controller
            # keeps running and the capacity limit becomes a measurable
            # result rather than an outage.
            msg = str(exc)
            if "RESOURCE_EXHAUSTED" in msg or "Not enough space" in msg:
                self._override_capacity_rejects = (
                    getattr(self, "_override_capacity_rejects", 0) + 1)
                logging.error(
                    "session_action_override table FULL (%d rejects "
                    "this run): install skipped for %s:%d -> %s:%d",
                    self._override_capacity_rejects,
                    socket_fmt(src_ip), sport,
                    socket_fmt(dst_ip), dport)
                return
            raise
        logging.warning("Session override %s: %s:%d -> %s:%d",
                        action.upper(),
                        socket_fmt(src_ip), sport,
                        socket_fmt(dst_ip), dport)
        # F5.1 fix — schedule expiry on the SHARED heap-based scheduler
        # rather than spawning a Timer thread per override (which can
        # exhaust ulimit -u under sustained load and silently leak
        # never-expiring overrides).
        with self._expiry_cv:
            self._heapq.heappush(self._expiry_heap,
                                  (time.time() + HOLD_OVERRIDE_TTL_S, key))
            self._expiry_cv.notify()

    def _expiry_loop(self) -> None:
        """F5.1/F5.2 — single thread that pops the soonest-due override and
        deletes it. Wakes up via Condition when new overrides are pushed
        or on shutdown."""
        while not self._stop.is_set():
            with self._expiry_cv:
                if not self._expiry_heap:
                    self._expiry_cv.wait(timeout=1.0)
                    continue
                soonest_t, key = self._expiry_heap[0]
                wait = soonest_t - time.time()
                if wait > 0:
                    self._expiry_cv.wait(timeout=min(wait, 1.0))
                    continue
                self._heapq.heappop(self._expiry_heap)
            # Delete outside the lock to avoid blocking new pushes.
            try:
                table = self.bfrt_info.table_get(SESSION_OVERRIDE_TABLE)
                table.entry_del(self.target, [key])
            except Exception as exc:  # noqa: BLE001
                logging.debug("override delete ignored: %s", exc)

    def _log_decision(self, src: int, dst: int, sport: int, dport: int,
                      decision: str, rules: list[str], reason: str,
                      digest_rec: dict) -> None:
        """Append the controller's FINAL decision. F1.3+F2.2 fixes: lock-
        protected, includes trial_epoch + dst_port for correlation safety."""
        if self._shutting_down:
            return       # F5.2: don't write to a log we're closing.
        log_path = self.args.log.parent / "decisions.jsonl"
        entry = {
            "t": time.time(),
            "trial_epoch": self._trial_epoch,
            "src_ip": src, "dst_ip": dst,
            "src_port": sport, "dst_port": dport,
            "decision": decision,        # "PASS" | "DROP" (controller-side)
            "rules_fired": rules,
            "reason": reason,            # human-readable arbiter rationale
            "pipeline_action_code": int(digest_rec.get("action_code", 0)),
            "ota_size": int(digest_rec.get("ota_size", 0)),
            "ota_version": int(digest_rec.get("ota_version", 0)),
        }
        with self._decision_log_lock:
            try:
                with open(log_path, "a", buffering=1) as f:
                    f.write(json.dumps(entry) + "\n")
            except (OSError, ValueError) as exc:
                logging.error("Decision log write failed: %s", exc)

    def evaluate_hold(self, rec: dict) -> None:
        """Phase 6/7 RAT-aware policy arbiter.

        DROP (explicit) → always install drop override (R2 fired: source is
        not authorized, no RAT entry can override that).

        HOLD → consult the RAT:
          • If the 5-tuple matches an active authorised_rollouts entry AND
            the fired rules are behavioural-only (R1/R4/R5, NOT R2), allow
            the session — install an explicit PASS override so future
            packets on the same flow don't re-enter the expensive HOLD
            evaluation path.
          • Otherwise → install DROP (fail-closed).
        """
        src = int(rec.get("src_ip", 0))
        dst = int(rec.get("dst_ip", 0))
        sport = int(rec.get("src_port", 0))
        dport = int(rec.get("dst_port", 0))
        code = int(rec.get("action_code", 0))
        r2   = int(rec.get("r2_fired", 0))
        version = int(rec.get("ota_version", 0))
        size    = int(rec.get("ota_size", 0))
        if code == 0:
            return

        r1 = int(rec.get("r1_fired", 0))
        r4 = int(rec.get("r4_fired", 0))
        r5 = int(rec.get("r5_fired", 0))
        r6 = int(rec.get("r6_fired", 0))
        if getattr(self.args, "disable_r6", False):
            r6 = 0  # ABLATION: treat R6 as absent for 5-rule baseline.
        rules_fired = [n for n, v in
                       (("R1", r1), ("R2", r2), ("R4", r4),
                        ("R5", r5), ("R6", r6)) if v]

        # §6b: R6 RAT-gated rollback authorization. If R6 is the sole
        # terminal fire (no R2, no R4, and action_code != DROP) AND the
        # RAT has a rollback_window covering this (src, dst, version),
        # demote to PASS. Symmetric with §6a's R1 gate. This closes the
        # operational gap where authorized emergency rollbacks (e.g. OEM
        # recalls a buggy firmware batch) would otherwise trigger R6
        # monotonicity DROPs. Without a rollback_window declared in the
        # RAT, R6 remains terminal — default-closed.
        if (r6 == 1 and r2 == 0 and r4 == 0 and code != 2 and
                not getattr(self.args, "disable_rat", False)):
            rollback_entry = find_rollback_entry(
                self._rat_mgr.snapshot(), src, dst, version, size)
            if rollback_entry is not None:
                # M6: rollback admission counts against the same
                # per-rollout concurrency cap as ordinary pushes.
                admitted = self._rat_mgr.check_and_record(
                    rollout_id=rollback_entry.rollout_id,
                    max_concurrent=rollback_entry.max_concurrent_targets,
                    src_ip=src, dst_ip=dst, sport=sport, dport=dport,
                    ttl_seconds=HOLD_OVERRIDE_TTL_S,
                )
                if admitted:
                    logging.warning(
                        "§6b R6 GATE: authorized rollback %s -> %s v%d",
                        socket_fmt(src), socket_fmt(dst), version)
                    self.install_session_override(src, dst, sport, dport, "allow")
                    self._log_decision(src, dst, sport, dport, "PASS",
                                       rules_fired, "rat_rollback_match", rec)
                    return
                logging.warning(
                    "§6b R6 CAP: rollback DROP for %s -> %s v%d — "
                    "rollout %s at max_concurrent_targets=%d",
                    socket_fmt(src), socket_fmt(dst), version,
                    rollback_entry.rollout_id,
                    rollback_entry.max_concurrent_targets)
                self.install_session_override(src, dst, sport, dport, "drop")
                self._log_decision(src, dst, sport, dport, "DROP",
                                   rules_fired, "rat_rollback_max_concurrent",
                                   rec)
                return

        # Terminal fires — no RAT override possible:
        #   R2: unauthorized source (security boundary)
        #   R4: oversized firmware on one session (hard size contract)
        #   R6: per-BMS version monotonicity (rollback / replay defence)
        if code == 2 or r2 == 1 or r4 == 1 or r6 == 1:
            self.install_session_override(src, dst, sport, dport, "drop")
            self._log_decision(src, dst, sport, dport, "DROP", rules_fired,
                               "terminal_fire", rec)
            return

        # R1 (per-BMS rapid replay): terminal UNLESS the flow sits inside
        # an active RAT authorisation. RAT-covered same-BMS re-pushes are
        # a legitimate staged-rollout pattern (emergency re-push, revert).
        # Without this gate, E19 phase-2 rollbacks would be attributed to
        # R1 and the R6 contribution could not be proven.
        # Defensive: under --disable-rat (E4 ablation) R1 must stay
        # terminal regardless of RAT coverage.
        if r1 == 1 and (getattr(self.args, "disable_rat", False) or
                        not self._rat_allows(src, dst, version, size)):
            self.install_session_override(src, dst, sport, dport, "drop")
            self._log_decision(src, dst, sport, dport, "DROP", rules_fired,
                               "terminal_fire", rec)
            return

        # ABLATION: --disable-rat forces every HOLD to DROP without
        # consulting the RAT (used by E4 to show the RAT's contribution).
        if getattr(self.args, "disable_rat", False):
            self.install_session_override(src, dst, sport, dport, "drop")
            self._log_decision(src, dst, sport, dport, "DROP", rules_fired,
                               "rat_disabled_ablation", rec)
            return

        # HOLD path: only R5 (fleet fanout) can be a legitimate rollout.
        matched = self._rat_match(src, dst, size)
        if matched is not None:
            # M6: enforce max_concurrent_targets before admitting.
            # cap=0 means unlimited (legacy manifests). TTL matches the
            # HOLD override's fail-closed window; expiring overrides and
            # expiring concurrency slots stay in lockstep.
            admitted = self._rat_mgr.check_and_record(
                rollout_id=matched.rollout_id,
                max_concurrent=matched.max_concurrent_targets,
                src_ip=src, dst_ip=dst, sport=sport, dport=dport,
                ttl_seconds=HOLD_OVERRIDE_TTL_S,
            )
            if not admitted:
                logging.warning(
                    "RAT CAP: DROP override for %s -> %s (v%d, %dB) — "
                    "rollout %s at max_concurrent_targets=%d",
                    socket_fmt(src), socket_fmt(dst), version, size,
                    matched.rollout_id, matched.max_concurrent_targets)
                self.install_session_override(src, dst, sport, dport, "drop")
                self._log_decision(src, dst, sport, dport, "DROP",
                                   rules_fired, "rat_max_concurrent", rec)
                return
            logging.warning("RAT MATCH: PASS override for %s -> %s (v%d, %dB)",
                            socket_fmt(src), socket_fmt(dst), version, size)
            self.install_session_override(src, dst, sport, dport, "allow")
            self._log_decision(src, dst, sport, dport, "PASS", rules_fired,
                               "rat_match", rec)
        else:
            logging.warning("RAT MISS: DROP override for %s -> %s (v%d, %dB)",
                            socket_fmt(src), socket_fmt(dst), version, size)
            self.install_session_override(src, dst, sport, dport, "drop")
            self._log_decision(src, dst, sport, dport, "DROP", rules_fired,
                               "rat_miss", rec)

    def _rat_match(self, src: int, dst: int, size: int):
        """Return the matching RatEntry for Gate A, or None. Delegates
        into the lifecycle manager so every lookup sees the post-reload
        snapshot atomically."""
        return find_matching_entry(self._rat_mgr.snapshot(), src, dst, size)

    def _rat_allows(self, src: int, dst: int,
                    version: int, size: int) -> bool:
        """Back-compat wrapper kept for call sites that only need a bool.
        Note this intentionally does NOT enforce
        `expected_firmware_version` equality — a staged rollout may ship
        a newer version; we only flag wildly out-of-range sizes. M6
        concurrency enforcement happens separately in evaluate_hold so
        that lookup-only callers (e.g. §6b) never record phantom
        sessions."""
        return self._rat_match(src, dst, size) is not None

    def _rat_allows_rollback(self, src: int, dst: int,
                             version: int, size: int) -> bool:
        """§6b rollback admission. Default-closed: entries without a
        rollback_window never demote R6."""
        return find_rollback_entry(
            self._rat_mgr.snapshot(), src, dst, version, size
        ) is not None

    def init_r1_register(self) -> None:
        """Seed per-BMS R1 last-seen slots with `(coarse_lo + 32768) mod 65536`.

        Why: the data-plane RA has a `v == 0` sentinel branch that was meant
        to return 0xFFFF on never-seen slots, but it did not survive bf-p4c
        compilation on Tofino 1. The SALU returns `coarse_lo - 0 = coarse_lo`
        for fresh slots, which can drop below the 14400-second R1 threshold
        and fire a false-positive on the very first OTA packet to any BMS.
        Pre-seeding slots ensures the first-packet delta is ≥ 32768 for the
        next ~9 h after controller startup (32768 - coarse_lo wrap margin).
        """
        now = int(time.time())
        # Write coarse_time first so the data plane has a usable timebase.
        self._reg_write(COARSE_TIME_REGISTER, 0, now)
        seed = (now + 32768) & 0xFFFF
        self._reg_write_many(
            R1_LAST_SEEN_REGISTER,
            [(i, seed) for i in range(R1_REGISTER_SLOTS)],
        )
        logging.info("R1 register seeded: %d slots = 0x%04x (coarse+32768)",
                     R1_REGISTER_SLOTS, seed)

    def set_thresholds(self) -> None:
        # All rule thresholds (R1, R4, R5) are compile-time constants in the
        # P4 pipeline — Tofino 1's MAU predicates require one constant operand
        # per compare, so they can't be loaded from a runtime register and
        # compared against another runtime field in the same action.
        # CLI flags are accepted for logging/reproducibility only; to change
        # a threshold, recompile the pipeline with the new value.
        logging.info(
            "Compile-time thresholds in pipeline: R5=4 R1=14400s R4=2097152B. "
            "CLI values (R5=%d R1=%ds R4=%dB) are informational only.",
            self.args.r5_threshold,
            self.args.r1_threshold_s,
            self.args.r4_threshold_bytes,
        )

    # -- periodic background tasks ---------------------------------------
    def _window_loop(self) -> None:
        while not self._stop.wait(self.args.window_seconds):
            try:
                self._reg_write(R5_COUNT_REGISTER, 0, 0)
                for reg in R5_BF_REGISTERS:
                    self._reg_write_many(reg, [(i, 0) for i in range(1024)])
                logging.debug("R5 window cleared.")
            except Exception as exc:  # noqa: BLE001
                logging.warning("R5 window clear failed: %s", exc)

    def _r1_reseed_loop(self) -> None:
        """C1 fix (verification pass). The R1 seeding margin (32768 s
        worst-case at boot) decays at 1 s/s as `_coarse_time_loop`
        advances `coarse_time_reg`. Without periodic re-seeding the
        first packet to a previously-unseen BMS spuriously fires R1
        after ~5.1 h. Re-seed every hour so the margin stays bounded."""
        while not self._stop.wait(3600):
            try:
                self.init_r1_register()
                logging.info("R1 register periodic re-seed complete.")
            except Exception as exc:  # noqa: BLE001
                logging.warning("R1 periodic re-seed failed: %s", exc)

    def _coarse_time_loop(self) -> None:
        while not self._stop.wait(self.args.coarse_time_period):
            try:
                self._reg_write(COARSE_TIME_REGISTER, 0, int(time.time()))
            except Exception as exc:  # noqa: BLE001
                logging.warning("coarse_time write failed: %s", exc)

    # -- RAT loading ------------------------------------------------------
    def load_rat(self) -> tuple[list[str], list[str]]:
        """Return (authorized_source_ips, target_bms_ips) drawn from the
        lifecycle manager's verified snapshot. We deliberately do NOT
        re-read `rat.json` here — that would open a TOCTOU window where
        an attacker swaps the file between signature verification and
        this call, causing the startup R2 table to diverge from the
        arbiter's in-memory cache."""
        entries = self._rat_mgr.snapshot()
        src_ips: set[int] = set()
        bms_ips: list[int] = []
        seen_bms: set[int] = set()
        for entry in entries:
            src_ips.update(entry.src_ips)
            for bms in entry.bms_ips:
                if bms not in seen_bms:
                    seen_bms.add(bms)
                    bms_ips.append(bms)

        def _fmt(ip_int: int) -> str:
            return ".".join(str((ip_int >> s) & 0xFF)
                            for s in (24, 16, 8, 0))

        src_strs = sorted(_fmt(ip) for ip in src_ips)
        bms_strs = [_fmt(ip) for ip in bms_ips]

        if not bms_strs:
            # No RAT (or manager empty): fall back to the legacy default
            # 50-BMS fleet so devenv smoke tests still work.
            logging.warning(
                "RAT manager returned no entries; falling back to default "
                "10.0.2.10..59 fleet for BMS index install.")
            bms_strs = [f"10.0.2.{10 + i}" for i in range(50)]
        return src_strs, bms_strs

    # -- main loop --------------------------------------------------------
    def handle_stop(self, *_: Any) -> None:
        # F5.2: drain in-flight overrides from the data plane so a clean
        # restart doesn't leave dangling DROPs.
        self._shutting_down = True
        self._stop.set()
        with self._expiry_cv:
            pending = list(self._expiry_heap)
            self._expiry_heap.clear()
            self._expiry_cv.notify_all()
        for _, key in pending:
            try:
                table = self.bfrt_info.table_get(SESSION_OVERRIDE_TABLE)
                table.entry_del(self.target, [key])
            except Exception:  # noqa: BLE001
                pass
        logging.info("Shutdown requested; drained %d pending overrides.",
                     len(pending))
        # M6: stop the RAT watcher + pruner threads so the controller
        # process can exit cleanly. Safe to call multiple times.
        try:
            self._rat_mgr.stop()
        except Exception as exc:  # noqa: BLE001
            logging.debug("rat_mgr.stop ignored: %s", exc)

    # -- register read helpers (Step-0 preflight invariant check) ----------
    def _reg_read_many(self, reg_name: str,
                        indices: range | list[int]) -> dict[int, int]:
        """Batch-read a P4 register. Returns {idx: value}.

        Uses entry_get with from_hw=True so we read the actual ASIC state,
        not a cached copy. Raises on RPC failure — the caller decides how
        to surface that to preflight.
        """
        reg = self.bfrt_info.table_get(reg_name)
        field = f"{reg_name.split('.')[-1]}.f1"
        keys = [reg.make_key([bfrt_client.KeyTuple("$REGISTER_INDEX", i)])
                for i in indices]
        out: dict[int, int] = {}
        # entry_get on Tofino returns a list of (data, key) pairs in the
        # same order the keys were supplied when from_hw=True.
        results = list(reg.entry_get(self.target, keys,
                                      flags={"from_hw": True}))
        for (data, key) in results:
            key_dict = key.to_dict() if hasattr(key, "to_dict") else {}
            idx = key_dict.get("$REGISTER_INDEX", {}).get("value")
            data_dict = data.to_dict() if hasattr(data, "to_dict") else {}
            # Stateful ALUs return per-pipe arrays; f1 is either a scalar
            # or a list of per-pipe values. Reduce to max across pipes so a
            # non-zero on any pipe surfaces as "non-clean".
            val = data_dict.get(field, 0)
            if isinstance(val, list):
                val = max(val) if val else 0
            if idx is not None:
                out[int(idx)] = int(val)
        return out

    def _reset_detector_state(self, *, startup: bool = False) -> None:
        """The actual reset work. Called from both SIGUSR1 (inter-trial)
        and from run() at startup. Every step is wrapped in its own
        try/except that appends to self._last_reset_errors on failure.

        Step-0 (2026-04-20): silently-swallowed register-write failures
        used to produce "reset succeeded, registers dirty" states that
        poisoned downstream experiments. This method fails loud per step
        so preflight_state_check can refuse to launch traffic.
        """
        self._last_reset_errors = []

        if not startup:
            self._trial_epoch += 1

        def _step(name: str, fn):
            try:
                fn()
            except Exception as exc:  # noqa: BLE001
                msg = f"{name}: {exc!r}"
                logging.error("Reset step failed: %s", msg)
                self._last_reset_errors.append(msg)

        _step("init_r1_register", self.init_r1_register)
        _step("R5_COUNT",
              lambda: self._reg_write(R5_COUNT_REGISTER, 0, 0))
        for reg in R5_BF_REGISTERS:
            _step(f"R5_BLOOM[{reg}]",
                  lambda r=reg: self._reg_write_many(
                      r, [(i, 0) for i in range(1024)]))
        # R6 max-version: architectural must-clear between experiments.
        _step("R6_MAX_VERSION",
              lambda: self._reg_write_many(
                  R6_MAX_VERSION_REGISTER,
                  [(i, 0) for i in range(R6_REGISTER_SLOTS)]))
        # T1.5 HOLD-leak DP self-install: hold_armed_reg latches src-IP
        # CRC16 slots when any packet from that source receives a HOLD
        # verdict (action_code==1). The SALU only writes 1; it never
        # clears. Without this reset, an experiment that triggered a
        # HOLD anywhere keeps every subsequent packet from that source
        # DROPed at the data plane until controller restart, even when
        # the controller arbiter votes PASS. Clear all 256 slots so the
        # next trial starts with no source under suspicion.
        _step("HOLD_ARMED",
              lambda: self._reg_write_many(
                  HOLD_ARMED_REGISTER,
                  [(i, 0) for i in range(HOLD_ARMED_SLOTS)]))
        # Session state: 65 536 slots, batched to 1024 per RPC (~30 s).
        def _clear_session():
            for base in range(0, SESSION_TABLE_SIZE, 1024):
                self._reg_write_many(
                    SESSION_BYTES_REGISTER,
                    [(base + i, 0) for i in range(1024)
                     if (base + i) < SESSION_TABLE_SIZE])
                self._reg_write_many(
                    SESSION_FIRST_TS_REGISTER,
                    [(base + i, 0) for i in range(1024)
                     if (base + i) < SESSION_TABLE_SIZE])
        _step("SESSION_REGS", _clear_session)
        # Drop pending session overrides (both heap and ASIC table rows).
        def _clear_overrides():
            with self._expiry_cv:
                drained = list(self._expiry_heap)
                self._expiry_heap.clear()
            table = self.bfrt_info.table_get(SESSION_OVERRIDE_TABLE)
            for _, key in drained:
                try:
                    table.entry_del(self.target, [key])
                except Exception:  # noqa: BLE001
                    pass
            # Belt-and-braces: also wipe any ASIC rows not tracked in
            # our heap (crashed-controller residue).
            try:
                stale = list(table.entry_get(self.target,
                                              flags={"from_hw": True}))
                for (_d, k) in stale:
                    try:
                        table.entry_del(self.target, [k])
                    except Exception:  # noqa: BLE001
                        pass
            except Exception:  # noqa: BLE001
                pass
        _step("SESSION_OVERRIDE_TABLE", _clear_overrides)

        if self._last_reset_errors:
            logging.error("Reset completed with %d failed steps: %s",
                          len(self._last_reset_errors),
                          self._last_reset_errors)
        else:
            logging.warning("Reset complete (epoch=%d, startup=%s).",
                            self._trial_epoch, startup)

    def handle_reset(self, *_: Any) -> None:
        """SIGUSR1 entry point. Masks SIGUSR1, runs _reset_detector_state,
        writes barrier markers to both logs so sweep.py can locate trial
        boundaries by content rather than byte offsets (F7.1).
        """
        try:
            try:
                signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGUSR1])
            except Exception:
                pass
            logging.warning("SIGUSR1 received — resetting detector state.")
            self._reset_detector_state(startup=False)
            marker = json.dumps({
                "_marker": "trial_start",
                "trial_epoch": self._trial_epoch,
                "t": time.time(),
                "reset_errors": list(self._last_reset_errors),
            }) + "\n"
            try:
                with self._digest_log_lock:
                    self.log_fh.write(marker)
                    self.log_fh.flush()
            except Exception:
                pass
            try:
                with self._decision_log_lock:
                    with open(self.args.log.parent / "decisions.jsonl",
                              "a", buffering=1) as f:
                        f.write(marker)
            except Exception:
                pass
        except Exception as exc:  # noqa: BLE001
            logging.error("handle_reset failed: %s", exc)
        finally:
            try:
                signal.pthread_sigmask(signal.SIG_UNBLOCK, [signal.SIGUSR1])
            except Exception:
                pass

    def handle_dump_state(self, *_: Any) -> None:
        """SIGUSR2: snapshot controller + ASIC state to
        self._state_dump_path (atomic write via .tmp + rename).

        Step-0 preflight readback consumes this file. Every invariant
        the preflight needs must be represented here; if you add a new
        must-be-zero register, add it to both _reset_detector_state and
        to this dump.
        """
        snap: dict[str, Any] = {
            "t": time.time(),
            "trial_epoch": self._trial_epoch,
            "reset_errors": list(self._last_reset_errors),
        }
        try:
            r6 = self._reg_read_many(R6_MAX_VERSION_REGISTER,
                                      range(R6_REGISTER_SLOTS))
            nz = {i: v for i, v in r6.items() if v != 0}
            snap["r6_max_version"] = {
                "slots_total": R6_REGISTER_SLOTS,
                "slots_nonzero": len(nz),
                "sum": sum(r6.values()),
                "max": max(r6.values()) if r6 else 0,
                "nonzero_sample": dict(list(nz.items())[:16]),
            }
        except Exception as exc:  # noqa: BLE001
            snap["r6_max_version"] = {"error": repr(exc)}
        try:
            r5c = self._reg_read_many(R5_COUNT_REGISTER, [0])
            snap["r5_count"] = r5c.get(0, None)
        except Exception as exc:  # noqa: BLE001
            snap["r5_count"] = {"error": repr(exc)}
        bloom_nz = 0
        bloom_err = None
        for reg in R5_BF_REGISTERS:
            try:
                vals = self._reg_read_many(reg, range(1024))
                bloom_nz += sum(1 for v in vals.values() if v != 0)
            except Exception as exc:  # noqa: BLE001
                bloom_err = repr(exc)
                break
        snap["r5_bloom_nonzero"] = bloom_nz if bloom_err is None else {"error": bloom_err}
        try:
            t = self.bfrt_info.table_get(SESSION_OVERRIDE_TABLE)
            entries = list(t.entry_get(self.target, flags={"from_hw": True}))
            snap["session_override_count"] = len(entries)
        except Exception as exc:  # noqa: BLE001
            snap["session_override_count"] = {"error": repr(exc)}
        try:
            entries = self._rat_mgr.snapshot()
            snap["rat"] = {
                "entries": len(entries),
                "signed": bool(self._rat_mgr.is_signed()),
                "rollback_window_entries": sum(
                    1 for e in entries
                    if getattr(e, "rollback_window", None)
                ),
            }
        except Exception as exc:  # noqa: BLE001
            snap["rat"] = {"error": repr(exc)}
        # Atomic write: tmp + rename.
        try:
            tmp = self._state_dump_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(snap, f, indent=2, default=str)
            import os as _os
            _os.replace(tmp, self._state_dump_path)
            logging.warning("State dump written to %s "
                            "(r6_nz=%s, override=%s, reset_errors=%d)",
                            self._state_dump_path,
                            snap.get("r6_max_version", {}).get("slots_nonzero",
                                                               "?"),
                            snap.get("session_override_count", "?"),
                            len(self._last_reset_errors))
        except Exception as exc:  # noqa: BLE001
            logging.error("State dump failed: %s", exc)

    def run(self) -> None:
        signal.signal(signal.SIGINT, self.handle_stop)
        signal.signal(signal.SIGTERM, self.handle_stop)
        signal.signal(signal.SIGUSR1, self.handle_reset)
        signal.signal(signal.SIGUSR2, self.handle_dump_state)
        self.connect()
        # Flush any stale session_action_override entries left by a
        # previously crashed controller so the table starts empty.
        try:
            t = self.bfrt_info.table_get(SESSION_OVERRIDE_TABLE)
            # iterate-and-delete; bfrt_grpc raises if empty, ignore that
            stale = list(t.entry_get(self.target, flags={"from_hw": True}))
            for (data, key) in stale:
                try:
                    t.entry_del(self.target, [key])
                except bfrt_client.BfruntimeRpcException:
                    pass
            if stale:
                logging.warning(
                    "Flushed %d stale session_action_override entries "
                    "from previous run.", len(stale))
        except Exception as exc:  # noqa: BLE001
            logging.info("Override-table startup flush skipped: %s", exc)
        self.install_ota_prefix_entry()

        # M6: load the RAT manifest through the lifecycle manager FIRST,
        # so the arbiter sees a verified cache from the very first
        # digest. A missing-but-permitted unsigned manifest logs a
        # banner; a signature verification failure in --require-signed
        # mode aborts startup.
        self._rat_mgr.load_initial()

        src_ips, bms_ips = self.load_rat()
        self.install_authorized_sources(src_ips)
        self.install_bms_index_table(bms_ips)
        self.init_r1_register()
        self.set_thresholds()

        # Step-0 (2026-04-20): zero all stateful registers at startup so
        # ASIC state from a prior experiment cannot leak into trial 0.
        # Without this, R6_MAX_VERSION persists across controller restarts
        # (only bf_switchd restart clears it), causing benign packets at
        # version=N to appear as rollbacks if any prior experiment pushed
        # version>N. Observed in E12b dry-run 2026-04-20.
        # 2026-05-01: extended to also clear hold_armed_reg (T1.5 SALU),
        # which the SALU itself never clears. Without this, an inter-trial
        # SIGUSR1 still leaves prior-trial source-IPs auto-armed and the
        # data plane keeps DROPping subsequent packets from those sources.
        logging.info("Startup state reset — clearing R5/R6/session "
                     "registers + override table + hold_armed.")
        self._reset_detector_state(startup=True)
        if self._last_reset_errors:
            logging.error("Startup reset had %d failing steps; "
                          "preflight_state_check WILL fail-closed.",
                          len(self._last_reset_errors))

        # F5.1 single expiry-scheduler thread (replaces per-override Timers).
        t = threading.Thread(target=self._expiry_loop, daemon=True,
                              name="expiry_scheduler")
        t.start()
        self._threads.append(t)

        if not self.args.no_window_clear:
            t = threading.Thread(target=self._window_loop, daemon=True)
            t.start()
            self._threads.append(t)
            logging.info("R5 window clear thread started (%ds period).",
                         self.args.window_seconds)
        if not self.args.no_coarse_time:
            t = threading.Thread(target=self._coarse_time_loop, daemon=True)
            t.start()
            self._threads.append(t)
            logging.info("coarse_time thread started (%.1fs period).",
                         self.args.coarse_time_period)
        # C1 fix (verification pass): hourly R1 re-seed keeps the
        # first-packet false-positive margin bounded.
        t = threading.Thread(target=self._r1_reseed_loop, daemon=True,
                              name="r1_reseed")
        t.start()
        self._threads.append(t)
        logging.info("R1 hourly re-seed thread started.")

        # M6: inotify watcher + TTL pruner. Both are daemon threads
        # owned by the lifecycle manager; they are joined from
        # `handle_stop` via `self._rat_mgr.stop()`.
        self._rat_mgr.start_watcher()
        self._rat_mgr.start_pruner()

        logging.info("Streaming digests (Ctrl-C to stop)...")
        n = 0
        while not self._stop.is_set():
            try:
                digest = self.interface.digest_get(timeout=1)
            except Exception as exc:  # noqa: BLE001
                logging.warning("digest_get error: %s", exc)
                time.sleep(0.5)
                continue
            if digest is None:
                continue

            # BF-SDE 9.13 returns a DigestList protobuf with `digest_id` and
            # a `data` field. Match digest_id against each attached learn's
            # internal id. We memoise the id map on first use.
            if not hasattr(self, "_learn_by_id"):
                self._learn_by_id = {}
                for inst, lrn in self.digest_learns.items():
                    lid = None
                    for attr in ("id", "learn_id", "info"):
                        v = getattr(lrn, attr, None)
                        if v is None:
                            continue
                        if attr == "info":
                            # Object with id_get() method (bfrt_grpc convention)
                            try:
                                lid = v.id_get()
                            except Exception:  # noqa: BLE001
                                lid = getattr(v, "id", None)
                        else:
                            lid = v
                        if isinstance(lid, int):
                            break
                    if isinstance(lid, int):
                        self._learn_by_id[lid] = (inst, lrn)
                    else:
                        logging.warning("Could not resolve id for learn %s (attrs=%s)",
                                        inst, [a for a in dir(lrn) if not a.startswith("_")])
                logging.info("Learn id map: %s",
                             {k: v[0] for k, v in self._learn_by_id.items()})

            did = getattr(digest, "digest_id", None)
            match = self._learn_by_id.get(did) if did is not None else None
            if match is None:
                logging.warning("unknown digest_id=%s (known=%s)", did,
                                list(self._learn_by_id))
                continue
            digest_name, learn = match
            if learn is None:
                logging.warning("unknown digest: %s", digest_name)
                continue
            for data in learn.make_data_list(digest):
                rec = dict(data.to_dict())
                rec["_type"] = digest_name
                rec["_t_recv"] = time.time()
                rec["_trial_epoch"] = self._trial_epoch   # F2.2 fix
                with self._digest_log_lock:                # F1.3 fix
                    self.log_fh.write(json.dumps(rec, default=_json_default) + "\n")
                n += 1
                if digest_name == "hold_digest":
                    code = int(rec.get("action_code", 0))
                    label = {0: "PASS", 1: "HOLD", 2: "DROP"}.get(code, "?")
                    logging.warning(
                        "HOLD/DROP #%d: action=%s r1=%s r2=%s r4=%s r5=%s "
                        "r6=%s dst=%s bms_idx=%s",
                        n, label,
                        rec.get("r1_fired"), rec.get("r2_fired"),
                        rec.get("r4_fired"), rec.get("r5_fired"),
                        rec.get("r6_fired"),
                        rec.get("dst_ip"), rec.get("bms_idx"))
                    self.evaluate_hold(rec)
                elif digest_name == "r5_digest":
                    logging.warning("R5 FIRED #%d: count=%s thr=%s dst=%s",
                                    n, rec.get("r5_count"), rec.get("r5_threshold"),
                                    rec.get("dst_ip"))
                elif digest_name == "rule_digest":
                    logging.warning(
                        "RULE ALERT #%d: r1=%s r2=%s r4=%s dst=%s bms_idx=%s",
                        n, rec.get("r1_fired"), rec.get("r2_fired"),
                        rec.get("r4_fired"), rec.get("dst_ip"), rec.get("bms_idx"))
                else:
                    logging.info("digest #%d: %s", n, digest_name)

        self.log_fh.close()
        logging.info("Stopped after %d digests.", n)


def _json_default(obj: Any) -> Any:
    if isinstance(obj, (bytes, bytearray)):
        return obj.hex()
    if hasattr(obj, "__int__"):
        return int(obj)
    return str(obj)


def main() -> int:
    args = parse_args()
    setup_logging(args.verbose)
    try:
        Controller(args).run()
    except Exception:  # noqa: BLE001
        logging.exception("Controller failed")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
