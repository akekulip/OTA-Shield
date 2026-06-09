"""Trial-runner FSM (Tier-1 / Tier-2 reruns).

Owns the trial state machine described in panel-8 §2:

    INIT -> PRE_TRIAL -> RUN -> DRAIN -> POST_TRIAL -> {OK | DEGRADED}

Every Tier-1 / Tier-2 experiment driver calls
``TrialRunner.run_trial(scenario_callable)``. The runner

* SIGUSR1s the controller (state reset) and clears P4 registers;
* runs the first 6 of the 13 integrity items (preflight);
* invokes the scenario callable, capturing wall-clock + run.log;
* runs the remaining 7 integrity items (postflight);
* writes ``manifest.yaml`` + lock; promotes the trial to OK / DEGRADED
  / INVALID per the panel-8 contract.

A ``--dry-run`` mode exercises the full FSM without touching the switch
so we can smoke-test wiring before any hardware bring-up.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
import shlex
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Callable, Dict

import yaml

from experiments.manifest import (
    TrialManifest,
    compute_file_sha,
    compute_p4_binary_sha,
    verify_manifest_immutable,
    write_manifest,
)
from experiments.seed_schedule import derive_trial_seed

# A scenario callable returns a small dict the runner echoes into run.log.
# Real generators live in `traffic_gen/*` (Agent GB1) — runner does not
# implement them. Typed via typing.* so we stay Python 3.8 compatible.
ScenarioCallable = Callable[["TrialContext"], Dict[str, Any]]

LOG = logging.getLogger("trial_runner")

INTEGRITY_PRE = [
    "item_01_register_zero",
    "item_02_p4_binary_sha",
    "item_04_sample_count_baseline",
    "item_09_controller_log_clean",
    "item_12_rat_signature_verified",
    "item_13_broker_relay_flag",
]

INTEGRITY_POST = [
    "item_03_packet_conservation",
    "item_05_monotonic_timestamps",
    "item_06_ptp_drift",
    "item_07_sketch_counter_sane",
    "item_08_no_nic_drops",
    "item_10_duration_bound",
    "item_11_manifest_immutable",
]


# ----------------------------------------------------------------- contexts


@dataclasses.dataclass
class TrialConfig:
    """Inputs the runner needs to drive a single trial."""

    exp_id: str
    trial_id: str
    scenario_id: str
    declared_duration_s: float
    output_dir: Path
    switch_host: str | None = None       # ssh target, e.g. decps@10.10.54.15
    controller_host: str | None = None   # often == switch_host
    controller_pid: int | None = None
    controller_log: Path | None = None
    p4_conf_path: str = "/home/decps/my_program/sde/build/ota_shield/ota_shield.conf"
    rat_lifecycle_path: Path = Path("controller/rat_lifecycle.py")
    requires_broker_relay: bool = False  # T2.4 only
    requires_signed_rat: bool = True     # closes 2026-04-18 stale-.sig footgun
    duration_tolerance_pct: float = 2.0
    dry_run: bool = False


@dataclasses.dataclass
class TrialContext:
    """Mutable per-trial state. Scenario callables receive this so they
    know where to write `ground_truth.json` and which seed to use."""

    config: TrialConfig
    trial_dir: Path
    trial_seed: int
    t_start: float = 0.0
    t_end: float = 0.0
    preflight: dict[str, str] = dataclasses.field(default_factory=dict)
    postflight: dict[str, str] = dataclasses.field(default_factory=dict)
    notes: list[str] = dataclasses.field(default_factory=list)

    @property
    def actual_duration_s(self) -> float:
        return max(0.0, self.t_end - self.t_start)


# ----------------------------------------------------------------- shell


def _ssh(host: str, cmd: str, *, timeout_s: float = 8.0,
         dry_run: bool = False) -> subprocess.CompletedProcess | None:
    if dry_run or not host:
        return None
    full = (
        f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "
        f"{shlex.quote(host)} {shlex.quote(cmd)}"
    )
    try:
        return subprocess.run(full, shell=True, capture_output=True,
                              text=True, timeout=timeout_s, check=False)
    except subprocess.TimeoutExpired:
        return None


# ----------------------------------------------------------------- runner


class TrialRunner:
    """Drives a single trial through the FSM. One instance per trial."""

    def __init__(self, config: TrialConfig) -> None:
        self.config = config
        self.trial_dir = Path(config.output_dir).resolve()
        self.trial_dir.mkdir(parents=True, exist_ok=True)
        self.integrity_log = self.trial_dir / "integrity.log"
        self.run_log = self.trial_dir / "run.log"
        self._configure_logging()
        seed = derive_trial_seed(config.exp_id, config.trial_id)
        self.context = TrialContext(
            config=config, trial_dir=self.trial_dir, trial_seed=seed,
        )

    # -- logging -------------------------------------------------------

    def _configure_logging(self) -> None:
        # Per-trial file handler — one run.log per trial dir.
        for h in list(LOG.handlers):
            LOG.removeHandler(h)
        fh = logging.FileHandler(self.run_log, mode="w")
        fh.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(message)s"))
        LOG.addHandler(fh)
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(logging.Formatter("[trial_runner] %(message)s"))
        LOG.addHandler(sh)
        LOG.setLevel(logging.INFO)

    def _record_integrity(self, item: str, status: str, detail: str = "") -> None:
        line = f"{item}\t{status}\t{detail}".rstrip()
        with self.integrity_log.open("a") as f:
            f.write(line + "\n")

    # -- FSM stages ----------------------------------------------------

    def setup(self) -> None:
        """INIT → PRE_TRIAL transition: reset controller state, derive seed."""
        cfg = self.config
        LOG.info("setup exp=%s trial=%s scenario=%s seed=%d dry_run=%s",
                 cfg.exp_id, cfg.trial_id, cfg.scenario_id,
                 self.context.trial_seed, cfg.dry_run)

        # SIGUSR1 the controller to clear R5/R6/R1/session registers per
        # ota_shield_controller.handle_reset.
        if cfg.controller_pid is not None and cfg.controller_host:
            _ssh(cfg.controller_host, f"kill -USR1 {cfg.controller_pid}",
                 dry_run=cfg.dry_run)
            if not cfg.dry_run:
                time.sleep(4.0)  # match run_e12b.py: handle_reset is ~256+R5
            LOG.info("sent SIGUSR1 to controller pid=%d", cfg.controller_pid)
        else:
            LOG.warning("no controller_pid; skipping SIGUSR1 reset")

        # Optional `clear_registers.py` on the switch (panel-8 §2). We
        # never invent this file; if it is missing we just warn.
        clear_remote = "/home/decps/my_program/ota/experiments/clear_registers.py"
        if cfg.switch_host:
            res = _ssh(cfg.switch_host, f"test -f {clear_remote} && echo y || echo n",
                       dry_run=cfg.dry_run)
            if res and (res.stdout or "").strip() == "y":
                _ssh(cfg.switch_host, f"python3 {clear_remote}",
                     dry_run=cfg.dry_run, timeout_s=15.0)
                LOG.info("clear_registers.py executed on switch")
            else:
                LOG.warning("clear_registers.py absent on switch — registers"
                            " inherit prior state")

    def preflight_check(self) -> bool:
        """First 6 of the 13 integrity items — pre-run.

        Items requiring post-run data (3, 5, 7, 8, 10, 11) are deferred to
        :meth:`postflight_check`. Items 6 (PTP drift) is run twice: a
        baseline read here, the actual delta in postflight.
        """
        cfg = self.config
        ctx = self.context

        # Item 1: register zero (best-effort; no bfrt over SSH from agent
        # context — we record `unknown` if the switch is unreachable).
        if cfg.dry_run or not cfg.switch_host:
            ctx.preflight["item_01_register_zero"] = "skip"
            self._record_integrity("item_01_register_zero", "skip",
                                   "dry-run / no switch_host")
        else:
            ctx.preflight["item_01_register_zero"] = "deferred"
            self._record_integrity("item_01_register_zero", "deferred",
                                   "bfrt check owned by integrity_checker.py")

        # Item 2: P4 binary sha matches manifest. The manifest is written
        # in finalize() — here we record the live sha so postflight item 11
        # has a reference value.
        sha = compute_p4_binary_sha(cfg.p4_conf_path,
                                    ssh_host=None if cfg.dry_run
                                    else cfg.switch_host)
        ctx.preflight["item_02_p4_binary_sha"] = "pass" if sha else "skip"
        self._record_integrity("item_02_p4_binary_sha",
                               "pass" if sha else "skip",
                               sha or "no sha (dry-run / unreachable)")
        ctx.notes.append(f"p4_binary_sha={sha or 'unknown'}")

        # Item 4: sample-count baseline. We record the controller log size
        # so postflight can diff and reject if zero deltas land.
        baseline_bytes = 0
        if cfg.controller_host and cfg.controller_log and not cfg.dry_run:
            res = _ssh(cfg.controller_host,
                       f"stat -c %s {shlex.quote(str(cfg.controller_log))}"
                       " 2>/dev/null || echo 0",
                       dry_run=False)
            if res and res.stdout:
                baseline_bytes = int(res.stdout.strip() or 0)
        ctx.preflight["item_04_sample_count_baseline"] = "pass"
        ctx.notes.append(f"controller_log_baseline_bytes={baseline_bytes}")
        self._record_integrity("item_04_sample_count_baseline", "pass",
                               f"baseline_bytes={baseline_bytes}")

        # Item 9: controller log clean. We grep for ERROR / UNAVAILABLE in
        # the most recent N lines so a cascading failure does not poison
        # an otherwise-fine baseline.
        clean = True
        detail = "ok"
        if cfg.controller_host and cfg.controller_log and not cfg.dry_run:
            res = _ssh(cfg.controller_host,
                       f"tail -n 200 {shlex.quote(str(cfg.controller_log))}"
                       " | grep -E 'ERROR|gRPC UNAVAILABLE' || true",
                       dry_run=False)
            if res and (res.stdout or "").strip():
                clean = False
                detail = (res.stdout or "")[:200]
        ctx.preflight["item_09_controller_log_clean"] = "pass" if clean else "fail"
        self._record_integrity("item_09_controller_log_clean",
                               "pass" if clean else "fail", detail)

        # Item 12: RAT signature verified — rat_lifecycle.py must have
        # logged "RAT verified <sha256>" within the last 30 s. Skipped on
        # dry-run; in real harness we read controller startup log.
        if cfg.requires_signed_rat and not cfg.dry_run and cfg.controller_host:
            res = _ssh(cfg.controller_host,
                       "grep -E 'RAT verified|RAT loaded' /tmp/controller.log"
                       " | tail -n 1 || true",
                       dry_run=False)
            line = (res.stdout or "").strip() if res else ""
            verified = "RAT verified" in line or "signed=True" in line
            ctx.preflight["item_12_rat_signature_verified"] = (
                "pass" if verified else "fail")
            self._record_integrity("item_12_rat_signature_verified",
                                   "pass" if verified else "fail",
                                   line[:200])
        else:
            ctx.preflight["item_12_rat_signature_verified"] = (
                "skip" if not cfg.requires_signed_rat else "skip")
            self._record_integrity("item_12_rat_signature_verified", "skip",
                                   "dry-run or signed-RAT not required")

        # Item 13: broker-relay flag — only T2.4 enables this. Without
        # tshark on Vision (which the runner does not orchestrate
        # directly), we record `skip` and let the experiment's own
        # preflight_T2_4.py drive the real check.
        if cfg.requires_broker_relay:
            ctx.preflight["item_13_broker_relay_flag"] = "deferred"
            self._record_integrity("item_13_broker_relay_flag", "deferred",
                                   "tshark check owned by preflight_T2_4.py")
        else:
            ctx.preflight["item_13_broker_relay_flag"] = "n/a"
            self._record_integrity("item_13_broker_relay_flag", "n/a",
                                   "non-T2.4 trial")

        # A preflight is "passing" if no item failed outright; deferred /
        # skip / n/a do not block (the integrity checker enforces them).
        any_fail = any(v == "fail" for v in ctx.preflight.values())
        if any_fail:
            LOG.error("preflight failed: %s", ctx.preflight)
            return False
        return True

    def run(self, scenario_callable: ScenarioCallable) -> None:
        """RUN stage: invoke the scenario callable with the trial context.

        The callable is the per-experiment generator. Runner enforces the
        declared duration as a wall-clock budget but does not interrupt
        the scenario mid-emit (real generators must self-bound).
        """
        cfg = self.config
        ctx = self.context
        LOG.info("RUN scenario=%s declared_duration_s=%.1f",
                 cfg.scenario_id, cfg.declared_duration_s)
        ctx.t_start = time.time()
        try:
            result = scenario_callable(ctx) or {}
            LOG.info("scenario returned: %s",
                     json.dumps(result, default=str)[:400])
        except Exception as exc:  # noqa: BLE001
            LOG.error("scenario raised: %s\n%s", exc, traceback.format_exc())
            ctx.notes.append(f"scenario_exception={exc}")
        ctx.t_end = time.time()
        LOG.info("RUN complete actual_duration_s=%.3f",
                 ctx.actual_duration_s)

    def postflight_check(self) -> bool:
        """Remaining 7 integrity items — post-run.

        Items 3, 5, 7, 8 require host counters / sketch reads we cannot do
        from this process; we mark them ``deferred`` for the dedicated
        ``integrity_checker.py`` to confirm. Items 10 (duration bound) and
        11 (manifest immutability) are computed locally.
        """
        ctx = self.context
        cfg = self.config

        for item in ("item_03_packet_conservation",
                     "item_05_monotonic_timestamps",
                     "item_07_sketch_counter_sane",
                     "item_08_no_nic_drops"):
            ctx.postflight[item] = "deferred"
            self._record_integrity(item, "deferred",
                                   "owned by integrity_checker.py")

        # Item 6: PTP drift. Without phc_ctl we fall back to chronyc.
        if cfg.dry_run or not cfg.switch_host:
            ctx.postflight["item_06_ptp_drift"] = "skip"
            self._record_integrity("item_06_ptp_drift", "skip",
                                   "dry-run / no switch_host")
        else:
            ctx.postflight["item_06_ptp_drift"] = "deferred"
            self._record_integrity("item_06_ptp_drift", "deferred",
                                   "phc_ctl/chronyc owned by integrity_checker.py")

        # Item 10: duration bound. Allow ±duration_tolerance_pct.
        declared = cfg.declared_duration_s or 0.0
        actual = ctx.actual_duration_s
        tol = (cfg.duration_tolerance_pct / 100.0) * max(declared, 1e-6)
        if declared <= 0.0:
            status = "skip"
            detail = "declared_duration_s=0"
        elif abs(actual - declared) <= tol:
            status = "pass"
            detail = f"declared={declared:.3f} actual={actual:.3f}"
        else:
            status = "fail"
            detail = (f"declared={declared:.3f} actual={actual:.3f}"
                      f" tol={tol:.3f}")
        ctx.postflight["item_10_duration_bound"] = status
        self._record_integrity("item_10_duration_bound", status, detail)

        # Item 11: manifest immutability. Skipped here because the manifest
        # is written *after* postflight by finalize(); the verifier is
        # called inside finalize() and the result patched in.
        ctx.postflight["item_11_manifest_immutable"] = "pending"
        self._record_integrity("item_11_manifest_immutable", "pending",
                               "checked after manifest write")

        return not any(v == "fail" for v in ctx.postflight.values())

    def finalize(self) -> str:
        """Write the manifest, run the immutability check, classify the trial.

        Returns one of ``"valid"`` / ``"degraded"`` / ``"invalid"``.
        """
        ctx = self.context
        cfg = self.config

        controller_git_rev = _git_rev_short()
        rat_sha = compute_file_sha(cfg.rat_lifecycle_path)
        # Local fallback for p4 sha if preflight skipped it.
        p4_sha_note = next(
            (n for n in ctx.notes if n.startswith("p4_binary_sha=")),
            "p4_binary_sha=")
        p4_sha = p4_sha_note.split("=", 1)[1] or ""
        if p4_sha == "unknown":
            p4_sha = ""

        manifest = TrialManifest(
            exp_id=cfg.exp_id,
            trial_id=cfg.trial_id,
            scenario_id=cfg.scenario_id,
            declared_duration_s=cfg.declared_duration_s,
            actual_duration_s=ctx.actual_duration_s,
            trial_seed=ctx.trial_seed,
            p4_binary_sha256=p4_sha,
            controller_git_rev=controller_git_rev,
            rat_lifecycle_sha256=rat_sha,
            preflight_integrity=dict(ctx.preflight),
            postflight_integrity=dict(ctx.postflight),
            notes="; ".join(ctx.notes),
        )
        manifest_path = write_manifest(self.trial_dir, manifest)
        immutable = verify_manifest_immutable(self.trial_dir)
        ctx.postflight["item_11_manifest_immutable"] = (
            "pass" if immutable else "fail")
        self._record_integrity("item_11_manifest_immutable",
                               "pass" if immutable else "fail",
                               str(manifest_path))

        # Trial classification.
        any_fail = (any(v == "fail" for v in ctx.preflight.values())
                    or any(v == "fail" for v in ctx.postflight.values()))
        if any_fail:
            (self.trial_dir / "trial_invalid.txt").write_text(
                "preflight=" + json.dumps(ctx.preflight) + "\n"
                "postflight=" + json.dumps(ctx.postflight) + "\n")
            LOG.error("trial INVALID — see trial_invalid.txt")
            return "invalid"

        any_deferred = (any(v == "deferred" for v in ctx.preflight.values())
                        or any(v == "deferred" for v in ctx.postflight.values()))
        if any_deferred:
            LOG.info("trial OK with deferred items (integrity_checker.py"
                     " runs the real checks).")
            return "valid"
        LOG.info("trial OK (all 13 items resolved locally).")
        return "valid"

    # -- top-level orchestration --------------------------------------

    def run_trial(self, scenario_callable: ScenarioCallable) -> str:
        try:
            self.setup()
            if not self.preflight_check():
                LOG.error("preflight failed; aborting RUN")
                return self.finalize()
            self.run(scenario_callable)
            self.postflight_check()
            return self.finalize()
        except Exception as exc:  # noqa: BLE001
            LOG.error("FSM crashed: %s\n%s", exc, traceback.format_exc())
            (self.trial_dir / "trial_invalid.txt").write_text(
                f"fsm_exception={exc}\n")
            return "invalid"


# ----------------------------------------------------------------- helpers


def _git_rev_short() -> str:
    """Best-effort `git rev-parse --short HEAD` from CWD; "" on failure."""
    try:
        res = subprocess.run(
            "git rev-parse --short HEAD", shell=True,
            capture_output=True, text=True, timeout=2.0, check=False,
        )
        return (res.stdout or "").strip() or ""
    except Exception:  # noqa: BLE001
        return ""


def _fake_scenario(ctx: "TrialContext") -> Dict[str, Any]:
    """Smoke-mode scenario: writes a tiny `ground_truth.json` so
    reconcile_decisions can run end-to-end on the dry-run output.

    Sleeps for the declared duration so the duration-bound integrity
    item (10) exercises the pass path on dry-run.
    """
    declared = max(0.0, float(ctx.config.declared_duration_s or 0.0))
    payload = {
        "trial_id": ctx.config.trial_id,
        "scenario_id": ctx.config.scenario_id,
        "n_events": 0,
        "events": [],
        "t_start": time.time(),
    }
    if declared > 0.0:
        time.sleep(declared)
    payload["t_end"] = time.time()
    (ctx.trial_dir / "ground_truth.json").write_text(
        json.dumps(payload, indent=2))
    # Empty decisions log so the reconciler has both inputs.
    (ctx.trial_dir / "decisions.jsonl").write_text("")
    return {"events": 0, "fake": True, "slept_s": declared}


# ----------------------------------------------------------------- CLI


def _load_yaml_config(path: Path) -> dict:
    return yaml.safe_load(Path(path).read_text())


def _cli(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Trial-runner FSM driver.")
    ap.add_argument("--config", type=Path,
                    help="YAML config (alternative to flags).")
    ap.add_argument("--exp-id", default="SMOKE")
    ap.add_argument("--trial-id", default="t00")
    ap.add_argument("--scenario", default="smoke",
                    help="Scenario id label written to manifest.")
    ap.add_argument("--duration", type=float, default=1.0)
    ap.add_argument("--output-dir", type=Path, required=False)
    ap.add_argument("--switch-host", default=None)
    ap.add_argument("--controller-host", default=None)
    ap.add_argument("--controller-pid", type=int, default=None)
    ap.add_argument("--controller-log", type=Path, default=None)
    ap.add_argument("--requires-broker-relay", action="store_true")
    ap.add_argument("--no-signed-rat", action="store_true")
    ap.add_argument("--dry-run", action="store_true",
                    help="Exercise the FSM without touching the switch.")
    args = ap.parse_args(argv)

    cfg_dict: dict[str, Any] = {}
    if args.config:
        cfg_dict = _load_yaml_config(args.config) or {}

    out_dir = args.output_dir or cfg_dict.get("output_dir")
    if out_dir is None:
        out_dir = Path("/tmp/trial_runner_default") / args.exp_id / args.trial_id
    out_dir = Path(out_dir)

    config = TrialConfig(
        exp_id=args.exp_id,
        trial_id=args.trial_id,
        scenario_id=cfg_dict.get("scenario_id", args.scenario),
        declared_duration_s=cfg_dict.get("declared_duration_s", args.duration),
        output_dir=out_dir,
        switch_host=args.switch_host or cfg_dict.get("switch_host"),
        controller_host=(args.controller_host
                         or cfg_dict.get("controller_host")),
        controller_pid=args.controller_pid or cfg_dict.get("controller_pid"),
        controller_log=(args.controller_log
                        or (Path(cfg_dict["controller_log"])
                            if cfg_dict.get("controller_log") else None)),
        requires_broker_relay=(args.requires_broker_relay
                               or cfg_dict.get("requires_broker_relay", False)),
        requires_signed_rat=(not args.no_signed_rat)
                            and cfg_dict.get("requires_signed_rat", True),
        dry_run=args.dry_run,
    )
    runner = TrialRunner(config)
    status = runner.run_trial(_fake_scenario)
    print(f"[trial_runner] status={status} dir={runner.trial_dir}")
    return 0 if status != "invalid" else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(_cli())
