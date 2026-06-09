"""E22 driver — iterate the 5 cases x 20 trials RAT-lifecycle matrix.

For every case x trial this script:

  1. Builds a fresh stochastic pcap + ground-truth labels on the
     laptop via `scenarios_e22.E22_CASE_BUILDERS[...]`. Output paths:
         runs/experiments/E22_rat_lifecycle/<case_id>/t<NN>/
             trial.pcap
             labels.jsonl
             metadata.json
  2. Generates the per-case RAT fixture (JSON) with valid_window_start /
     valid_window_end resolved relative to `now`, signs it, and ships
     both files to the controller. The controller's inotify watcher
     (rat_lifecycle.py) picks up the change and hot-reloads.
  3. Ships the pcap to Vision (10.10.54.19 by default), records the
     switch's current controller-log offset, then replays the pcap on
     Vision with `tcpreplay` against the Tofino-connected NIC.
  4. Waits `post_wait_s` for digests to propagate and for the arbiter
     to emit decisions, then slices the controller decisions log from
     the recorded offset and scp's it back to the trial directory.
  5. (Between cases) signals the controller's detector-state reset via
     SIGUSR1 so R5/R6/override state doesn't carry over.

Per-event reset (--per-event-reset, default on)
------------------------------------------------
When --per-event-reset is active (the default for E22), each trial's
multi-event pcap is split into N single-packet per-event pcaps.
Between consecutive events the controller's SIGUSR1 reset is fired via
the existing `reset_detector_state()` helper, which zeros hold_armed_reg
(256 slots), R5 Bloom filters, session registers, and session overrides.
This prevents the hold_armed_reg cascade from short-circuiting the RAT
arbiter path and allows each event to be evaluated independently.

Honest-experiment note: the hold_armed_reg cascade is a genuine
architectural constraint of the current Tofino data-plane design.  Once
any packet from a source arms the register (action_code==1, HOLD), ALL
subsequent data-plane packets from that source are force-dropped before
the controller's RAT arbiter is reached.  Per-event reset isolates the
RAT-lifecycle test so the arbiter's correctness is observable; it does
NOT mask the limitation.  The cascade is reported separately as a
continuous-operation constraint (§6a) and can be reproduced by re-running
with --no-per-event-reset.  The 2026-06-06 baseline run (152/160 FP in
case2_active_authorized) is archived at
runs/experiments/_agg/E22_rat_lifecycle_2026-06-06_recovered.json.

DESIGN NOTE: This driver DOES NOT RUN THE HW. Invoking it on a laptop
prints the plan and produces the pcaps + labels on disk, then prints
the remote commands it would have executed. Pass --execute to actually
SSH/scp/replay. Keeping both modes lets us verify pcap generation and
metadata shape without touching the switch.

Honest-results policy: if any trial's pcap fails to generate, or if
the controller log slice is empty after replay, we write a
`trial_invalid.txt` marker and move on. aggregate_e22.py skips those
trials (but still reports them).
"""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# We sit next to scenarios_e22 so a relative import works.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import scenarios_e22  # noqa: E402


# ---------------------------------------------------------------------------
# Shell helpers — reuse the minimal ssh/scp pattern from sweep.py so a
# reviewer can cross-check one runner against the other.
# ---------------------------------------------------------------------------


def sh(cmd: str, check: bool = True, capture: bool = False
       ) -> subprocess.CompletedProcess:
    """Run a shell command with stable quoting."""
    return subprocess.run(cmd, shell=True, check=check,
                          capture_output=capture, text=True)


def ssh(host: str, remote_cmd: str, check: bool = True,
        capture: bool = False) -> subprocess.CompletedProcess:
    """SSH to `host` and run `remote_cmd`."""
    return sh(f"ssh -o StrictHostKeyChecking=no {host} "
              f"{shlex.quote(remote_cmd)}",
              check=check, capture=capture)


def scp(src: str, dst: str) -> None:
    """Copy a file over SSH."""
    sh(f"scp -q -o StrictHostKeyChecking=no {src} {dst}")


# ---------------------------------------------------------------------------
# RAT fixture materialisation
# ---------------------------------------------------------------------------


def _iso(t: float) -> str:
    """Format `t` (epoch seconds) as ISO-8601 UTC with `Z` suffix."""
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def build_case_fixture(case_cfg: dict, *, now_s: float,
                        active_rollout_id: str,
                        capped_rollout_id: str) -> dict:
    """Translate a case's `rat_fixture` YAML block into a RAT manifest.

    The two rollouts (`active`, `capped`) share timing but differ in
    `max_concurrent_targets`. Case 5 exercises the capped one; all
    other cases exercise the active one.
    """
    rat_cfg = case_cfg.get("rat_fixture", {})
    start_off_min = float(rat_cfg.get("valid_window_start_offset_min", -30))
    end_off_min = float(rat_cfg.get("valid_window_end_offset_min", 30))
    capped_cap = int(rat_cfg.get("max_concurrent_targets",
                                  scenarios_e22.E22_MAX_CONCURRENT_TARGETS))

    t_start = now_s + start_off_min * 60.0
    t_end = now_s + end_off_min * 60.0
    bms_list = [f"10.0.2.{10 + i}" for i in range(20)]
    return {
        "authorized_rollouts": [
            {
                "rollout_id": capped_rollout_id,
                "authorized_source_ips": [scenarios_e22.AUTH_SRC],
                "expected_firmware_version": 48,
                "target_bms_list": bms_list,
                "valid_window_start": _iso(t_start),
                "valid_window_end":   _iso(t_end),
                "max_concurrent_targets": capped_cap,
                "expected_payload_size_range": [512, 2_097_152],
            },
            {
                "rollout_id": active_rollout_id,
                "authorized_source_ips": [scenarios_e22.AUTH_SRC],
                "expected_firmware_version": 48,
                "target_bms_list": bms_list,
                "valid_window_start": _iso(t_start),
                "valid_window_end":   _iso(t_end),
                "max_concurrent_targets": 50,
                "expected_payload_size_range": [512, 2_097_152],
            },
        ],
    }


def install_rat(fixture: dict, *, switch: str,
                 remote_rat_path: str, remote_sig_path: str,
                 remote_sign_cmd: str, local_stage_dir: Path,
                 dry_run: bool) -> None:
    """Render fixture to disk, scp to switch, and trigger signing.

    We write the JSON locally first so the signed-manifest workflow
    mirrors what an operator would do by hand.
    """
    local_stage_dir.mkdir(parents=True, exist_ok=True)
    local_path = local_stage_dir / "rat_e22.json"
    local_path.write_text(json.dumps(fixture, indent=2))
    if dry_run:
        print(f"  [dry-run] would scp {local_path} -> {switch}:"
              f"{remote_rat_path} and sign via {remote_sign_cmd}")
        return
    scp(str(local_path), f"{switch}:{remote_rat_path}")
    # Signer is expected to produce rat_e22.json.sig alongside the json.
    # If the operator prefers raw (unsigned) mode, they pass
    # --skip-sign which leaves the .sig file absent and relies on the
    # controller's allow_unsigned=True fallback.
    if remote_sign_cmd:
        ssh(switch, remote_sign_cmd)


# ---------------------------------------------------------------------------
# Per-event pcap splitting (used by per_event_reset mode)
# ---------------------------------------------------------------------------


def _split_pcap_for_events(trial_pcap: Path, out_dir: Path) -> list[Path]:
    """Split *trial_pcap* into N single-packet per-event pcaps.

    Returns the list of Paths in packet order.  Requires scapy, which is
    already a dependency of scenarios_e22 (same experiments/ package).

    Each packet in the trial pcap corresponds to exactly one E22 event
    (scenarios_e22 generates one MQTT PUBLISH per event), so splitting
    by packet equals splitting by event.
    """
    from scapy.all import rdpcap, wrpcap  # noqa: PLC0415
    pkts = rdpcap(str(trial_pcap))
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for idx, pkt in enumerate(pkts):
        p = out_dir / f"event_{idx:03d}.pcap"
        wrpcap(str(p), [pkt])
        paths.append(p)
    return paths


# ---------------------------------------------------------------------------
# Trial orchestration
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> dict:
    """Load YAML via PyYAML (required)."""
    import yaml
    return yaml.safe_load(path.read_text())


def build_trial_artifacts(case_cfg: dict, trial_dir: Path,
                           trial_idx: int) -> dict:
    """Produce pcap + labels + metadata for one (case, trial). Returns
    the metadata dict."""
    builder_name = case_cfg["builder"]
    builder = scenarios_e22.E22_CASE_BUILDERS.get(
        case_cfg["case_id"])
    if builder is None:
        raise KeyError(f"Unknown E22 case_id: {case_cfg['case_id']!r}. "
                       f"Known: {list(scenarios_e22.E22_CASE_BUILDERS)}")
    if builder.__name__ != builder_name:
        # Non-fatal but loud — catches config typos during dev.
        print(f"  [WARN] YAML builder={builder_name} but dispatch "
              f"maps {case_cfg['case_id']} -> {builder.__name__}; "
              "using dispatch mapping.")
    trial_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = trial_dir / "trial.pcap"
    labels_path = trial_dir / "labels.jsonl"
    metadata_path = trial_dir / "metadata.json"
    params = dict(case_cfg.get("params", {}))
    params["trial_idx"] = trial_idx
    _, _, metadata = builder(pcap_path=pcap_path,
                              labels_jsonl_path=labels_path,
                              metadata_path=metadata_path,
                              **params)
    return metadata


def run_one_trial(*, case_cfg: dict, trial_idx: int, trial_dir: Path,
                  vision: str, switch: str, controller_log: str,
                  remote_workdir: str, vision_iface: str,
                  post_wait_s: float, dry_run: bool,
                  per_event_reset: bool = True,
                  per_event_settle_s: float = 5.0) -> None:
    """Generate pcap, replay on Vision, slice controller log.

    When *per_event_reset* is True (default for E22), the trial pcap is
    split into per-event single-packet chunks and each chunk is replayed
    separately.  Between consecutive events the controller's SIGUSR1 reset
    is triggered via reset_detector_state(), zeroing hold_armed_reg so the
    RAT arbiter is consulted independently for every event.

    Honest-experiment note
    ----------------------
    The hold_armed_reg cascade (once armed, all subsequent packets from the
    same source are force-dropped at the data plane before the RAT arbiter
    is reached) is a genuine architectural constraint reported in §6a.
    Per-event reset is an experimental-isolation fix only: it makes the RAT
    lifecycle measurable in isolation.  It does not change the cascade
    behaviour in real deployments.  Setting --no-per-event-reset reproduces
    the 2026-06-06 cascade-on baseline for direct comparison.

    Uses the existing SIGUSR1 mechanism (reset_detector_state) because no
    finer-grained hold_armed-only signal exists in the controller.  The
    full reset (~9 s for 65 k session-register writes) is heavier than
    strictly necessary but is the auditable existing path.  Each SIGUSR1
    also writes a _marker:trial_start record to both logs; aggregate_e22.py
    already skips _marker records (aggregate_e22.py line 126-127).
    """
    print(f"  -> trial t{trial_idx:02d} @ {trial_dir} "
          f"[per_event_reset={per_event_reset}]")
    metadata = build_trial_artifacts(case_cfg, trial_dir, trial_idx)
    n_events = int(metadata.get("n_events", 1))
    pcap_local = trial_dir / "trial.pcap"

    if dry_run:
        if per_event_reset:
            overhead_s = (per_event_settle_s + 15.0) * max(n_events - 1, 0)
            print(f"     [dry-run] per-event-reset ON: "
                  f"pcap={pcap_local} n_events={n_events} "
                  f"duration={metadata['pcap_duration_s']:.2f}s")
            print(f"     [dry-run] would replay {n_events} events with "
                  f"SIGUSR1 reset between each "
                  f"(~{per_event_settle_s + 15:.0f}s/gap x "
                  f"{max(n_events-1,0)} gaps = {overhead_s:.0f}s overhead)")
        else:
            print(f"     [dry-run] per-event-reset OFF (cascade-on): "
                  f"pcap={pcap_local} n_events={n_events} "
                  f"duration={metadata['pcap_duration_s']:.2f}s")
        return

    ssh(vision, "mkdir -p /tmp")

    # Snapshot byte offsets BEFORE the first event so the entire trial's
    # decisions land in one log slice regardless of per_event_reset mode.
    # Use controller_log for both slices to avoid picking up legacy files.
    decisions_log = controller_log
    t0 = ssh(switch,
             f"stat -c %s {controller_log} 2>/dev/null || echo 0",
             capture=True).stdout.strip()
    t0_dec = ssh(switch,
                 f"stat -c %s {decisions_log} 2>/dev/null || echo 0",
                 capture=True).stdout.strip()
    try:
        start_offset_digest = int(t0)
    except ValueError:
        start_offset_digest = 0
    try:
        start_offset_dec = int(t0_dec)
    except ValueError:
        start_offset_dec = 0

    # Install the scapy-based replay helper on Vision once (shared by
    # both per-event and single-shot modes).  The replayer preserves
    # inter-packet timing from scenarios_e22; for a single-packet per-
    # event pcap the timing loop is a no-op (prev is None on first
    # iteration).
    replay_py = (
        "import sys,time\n"
        "from scapy.all import rdpcap,sendp\n"
        "pkts=rdpcap(sys.argv[1])\n"
        "prev=None\n"
        "for p in pkts:\n"
        "    if prev is not None:\n"
        "        dt=float(p.time-prev)\n"
        "        if 0<dt<10: time.sleep(dt)\n"
        "    sendp(p,iface=sys.argv[2],verbose=False)\n"
        "    prev=p.time\n")
    import base64 as _b64
    replay_b64 = _b64.b64encode(replay_py.encode()).decode()
    ssh(vision, f"echo {replay_b64} | base64 -d > /tmp/_e22_replay.py")

    if per_event_reset:
        # -- Per-event replay with inter-event hold_armed_reg reset ----------
        # Split the trial pcap into N single-packet pcaps (one per event).
        event_pcaps = _split_pcap_for_events(
            pcap_local,
            trial_dir / "_event_pcaps",
        )
        for ev_idx, ev_pcap in enumerate(event_pcaps):
            remote_ev_pcap = (
                f"/tmp/e22_{case_cfg['case_id']}"
                f"_t{trial_idx:02d}_ev{ev_idx:03d}.pcap")
            scp(str(ev_pcap), f"{vision}:{remote_ev_pcap}")
            ssh(vision,
                f"sudo -n python3 /tmp/_e22_replay.py "
                f"{remote_ev_pcap} {vision_iface}")
            # Wait for the controller to receive the HOLD digest and
            # write a decision before resetting state for the next event.
            time.sleep(per_event_settle_s)
            if ev_idx < len(event_pcaps) - 1:
                print(f"       per-event reset after event "
                      f"{ev_idx + 1}/{n_events}...")
                # Sends SIGUSR1 to the controller and waits 15 s for
                # _reset_detector_state() to zero hold_armed_reg, R5 Bloom,
                # R6, session registers, and session overrides.
                reset_detector_state(switch, dry_run=False)
    else:
        # -- Original single-pcap replay (cascade-on, for comparison) -------
        remote_pcap = (
            f"/tmp/e22_{case_cfg['case_id']}_t{trial_idx:02d}.pcap")
        scp(str(pcap_local), f"{vision}:{remote_pcap}")
        ssh(vision,
            f"sudo -n python3 /tmp/_e22_replay.py "
            f"{remote_pcap} {vision_iface}")

    # Drain window.
    time.sleep(post_wait_s)

    # Slice controller_decisions.jsonl and digests log.
    ssh(switch, f"mkdir -p {remote_workdir}")
    digest_slice = (f"{remote_workdir}/e22_{case_cfg['case_id']}_"
                    f"t{trial_idx:02d}_digests.jsonl")
    ctrl_slice = (f"{remote_workdir}/e22_{case_cfg['case_id']}_"
                  f"t{trial_idx:02d}_controller.jsonl")

    # Guard against log rotation mid-trial (same check as sweep.py).
    cur_size = ssh(switch,
                   f"stat -c %s {controller_log} 2>/dev/null || echo 0",
                   capture=True).stdout.strip()
    try:
        cur_size_i = int(cur_size)
    except ValueError:
        cur_size_i = 0
    if cur_size_i < start_offset_digest:
        (trial_dir / "trial_invalid.txt").write_text(
            f"controller_log shrank during trial: "
            f"start={start_offset_digest} now={cur_size_i}\n")
        print(f"     [WARN] log rotated mid-trial; marking INVALID.")

    ssh(switch,
        f"tail -c +{start_offset_digest + 1} {controller_log} "
        f"> {digest_slice}")
    ssh(switch,
        f"if [ -f {decisions_log} ]; then "
        f"  tail -c +{start_offset_dec + 1} {decisions_log} > "
        f"{ctrl_slice}; "
        f"else : > {ctrl_slice}; fi")

    scp(f"{switch}:{digest_slice}", f"{trial_dir}/decisions.jsonl")
    scp(f"{switch}:{ctrl_slice}",
        f"{trial_dir}/controller_decisions.jsonl")

    # Empty controller_decisions is suspicious — mark (but keep data).
    if (trial_dir / "controller_decisions.jsonl").stat().st_size == 0:
        (trial_dir / "trial_warn_empty_decisions.txt").write_text(
            "controller_decisions.jsonl is empty; aggregator will "
            "report NO_DECISION for every event in this trial.\n")


def reset_detector_state(switch: str, dry_run: bool) -> None:
    """Send SIGUSR1 to the controller so detector state is zeroed
    between cases (matches sweep.py)."""
    if dry_run:
        print("  [dry-run] would send SIGUSR1 to controller")
        return
    # Controller runs as root (sudo); need sudo -n to send signals.
    ssh(switch,
        "sudo -n pkill -USR1 -x python3 2>/dev/null || "
        "sudo -n pkill -USR1 -f ota_shield_controller.py 2>/dev/null || true",
        check=False)
    time.sleep(15)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--config",
                    default="experiments/configs/E22_rat_lifecycle.yaml",
                    type=Path)
    ap.add_argument("--out-root",
                    default="runs/experiments/E22_rat_lifecycle",
                    type=Path)
    ap.add_argument("--vision", default="decps@10.10.54.19",
                    help="SSH target for the Vision traffic generator")
    ap.add_argument("--switch", default="decps@10.10.54.15",
                    help="SSH target for the switch/controller host")
    ap.add_argument("--controller-log",
                    default=("/home/decps/my_program/ota/runs/"
                             "phase6_digests.jsonl"))
    ap.add_argument("--controller-text-log",
                    default=("/home/decps/my_program/ota/runs/"
                             "controller_campaign_2026-06-06.log"),
                    help="Path to the Python logger text log on the switch "
                         "(where 'RAT loaded' lines appear). Used only by "
                         "preflight checks 2 and 5. Different from the "
                         "decisions JSONL log.")
    ap.add_argument("--remote-workdir",
                    default="/home/decps/my_program/ota/experiments")
    ap.add_argument("--remote-rat-path",
                    default="/home/decps/my_program/ota/"
                            "controller/rat.json",
                    help="Path the controller is watching.")
    ap.add_argument("--remote-sign-cmd",
                    default=("cd /home/decps/my_program/ota && "
                             "python3 controller/sign_rat.py "
                             "controller/rat.json"),
                    help="Remote command to (re-)sign the RAT file. "
                         "Empty string disables signing (unsigned mode).")
    ap.add_argument("--vision-iface", default="enp59s0f0np0")
    ap.add_argument("--post-wait-s", type=float, default=10.0)
    ap.add_argument("--trials-per-case", type=int, default=None,
                    help="Override YAML trials_per_case for debugging.")
    ap.add_argument("--only-case", default=None,
                    help="Run only this case_id (e.g. case2_active_authorized).")
    ap.add_argument("--execute", action="store_true",
                    help="Actually SSH/scp/replay. Default is DRY-RUN: "
                         "only build pcaps + labels + fixtures locally "
                         "and print the planned remote commands.")
    ap.add_argument("--skip-preflight", action="store_true",
                    help="Skip preflight_e22.py gate. Only for debug; "
                         "bypasses the checks that caught the "
                         "2026-04-18 --remote-sign-cmd=true footgun.")

    # Per-event reset flags (default ON — this is the corrected E22 mode).
    # Background: the 2026-06-06 run failed because hold_armed_reg was armed
    # by the first HOLD event and all subsequent events from the same source
    # were force-dropped at the data plane (action_code=2) without consulting
    # the RAT arbiter.  Per-event reset fires SIGUSR1 between events so each
    # event is evaluated independently.
    # --no-per-event-reset reproduces the 2026-06-06 cascade-on behaviour.
    ap.add_argument("--per-event-reset", dest="per_event_reset",
                    action="store_true", default=True,
                    help="(default ON) Split each trial into per-event "
                         "single-packet replays with a SIGUSR1 state reset "
                         "between consecutive events.  Isolates the RAT "
                         "lifecycle test from the hold_armed_reg cascade.")
    ap.add_argument("--no-per-event-reset", dest="per_event_reset",
                    action="store_false",
                    help="Disable per-event reset; reproduces the 2026-06-06 "
                         "cascade-on baseline where hold_armed_reg blocked "
                         "the RAT path after the first HOLD event.")
    ap.add_argument("--per-event-settle-s", type=float, default=5.0,
                    help="Seconds to wait after each event replay before "
                         "triggering the per-event SIGUSR1 reset, allowing "
                         "the controller to process the HOLD digest and log "
                         "a decision. (default: 5.0)")

    args = ap.parse_args()

    # Preflight gate — mandatory before any HW touches happen.
    # Runs only in EXECUTE mode (dry-run never reaches HW).
    if args.execute and not args.skip_preflight:
        preflight_script = Path(__file__).resolve().parent / "preflight_e22.py"
        preflight_cmd = [
            sys.executable, str(preflight_script),
            "--vision", args.vision,
            "--switch", args.switch,
            "--remote-rat-path", args.remote_rat_path,
            "--sign-cmd", args.remote_sign_cmd or "",
            # preflight_e22 needs the Python LOGGER log (where "RAT loaded"
            # lines appear), NOT the decisions log that the driver slices.
            # These are two different logs on the switch; do not conflate.
            "--controller-log", args.controller_text_log,
            "--vision-iface", args.vision_iface,
        ]
        print(f"\n[preflight] {' '.join(shlex.quote(p) for p in preflight_cmd)}")
        rc = subprocess.run(preflight_cmd).returncode
        if rc != 0:
            print(f"\nABORT: preflight_e22.py exited {rc}. "
                    f"Fix the failing check(s) above before re-running, "
                    f"or pass --skip-preflight to bypass (not recommended).")
            sys.exit(rc)
        print("[preflight] OK — proceeding with E22 trials.\n")

    cfg = _load_yaml(args.config)
    cases = cfg["cases"]
    trials_per_case = (args.trials_per_case if args.trials_per_case
                        is not None else cfg.get("trials_per_case", 20))
    post_wait_s = float(cfg.get("post_wait_s", args.post_wait_s))
    inter_trial_wait_s = float(cfg.get("inter_trial_wait_s", 70))
    inter_case_wait_s = float(cfg.get("inter_case_wait_s", 90))

    args.out_root.mkdir(parents=True, exist_ok=True)
    stage_dir = args.out_root / "_rat_stage"

    mode = "EXECUTE" if args.execute else "DRY-RUN (no HW touched)"
    print(f"\n=== E22 driver [{mode}] ===")
    print(f"  config           : {args.config}")
    print(f"  out-root         : {args.out_root}")
    print(f"  trials/case      : {trials_per_case}")
    print(f"  vision           : {args.vision} iface={args.vision_iface}")
    print(f"  switch           : {args.switch}")
    print(f"  rat path         : {args.remote_rat_path}")
    print(f"  per-event-reset  : {args.per_event_reset} "
          f"(settle={args.per_event_settle_s}s per event)")
    if not args.per_event_reset:
        print("  WARNING: per-event-reset is OFF — reproducing the "
              "2026-06-06 cascade-on baseline; expect high FP in "
              "case2_active_authorized.")
    print()

    for case_idx, case_cfg in enumerate(cases):
        case_id = case_cfg["case_id"]
        if args.only_case and case_id != args.only_case:
            continue
        case_out = args.out_root / case_id
        print(f"\n--- case {case_idx+1}/{len(cases)} {case_id} ---")

        # Render + install the per-case RAT fixture.
        fixture = build_case_fixture(
            case_cfg, now_s=time.time(),
            active_rollout_id=scenarios_e22.E22_ACTIVE_ROLLOUT_ID,
            capped_rollout_id=scenarios_e22.E22_CAPPED_ROLLOUT_ID,
        )
        install_rat(fixture, switch=args.switch,
                     remote_rat_path=args.remote_rat_path,
                     remote_sig_path=args.remote_rat_path + ".sig",
                     remote_sign_cmd=args.remote_sign_cmd,
                     local_stage_dir=stage_dir / case_id,
                     dry_run=not args.execute)

        # Wait for controller poll-reload (cadence ~5s). Without this the
        # first trial can race the reload and hit the old cache.
        if args.execute:
            print("     waiting 8s for controller RAT reload...")
            time.sleep(8)

        # Reset state so previous case can't leak R5 / override.
        if args.execute:
            reset_detector_state(args.switch, dry_run=False)

        for trial_idx in range(trials_per_case):
            trial_dir = case_out / f"t{trial_idx:02d}"
            run_one_trial(
                case_cfg=case_cfg,
                trial_idx=trial_idx,
                trial_dir=trial_dir,
                vision=args.vision,
                switch=args.switch,
                controller_log=args.controller_log,
                remote_workdir=args.remote_workdir,
                vision_iface=args.vision_iface,
                post_wait_s=post_wait_s,
                dry_run=not args.execute,
                per_event_reset=args.per_event_reset,
                per_event_settle_s=args.per_event_settle_s,
            )
            if trial_idx < trials_per_case - 1 and args.execute:
                print(f"     waiting {inter_trial_wait_s:.0f}s "
                      "(R5 window clear)...")
                time.sleep(inter_trial_wait_s)

        if case_idx < len(cases) - 1 and args.execute:
            print(f"  waiting {inter_case_wait_s:.0f}s before next case...")
            time.sleep(inter_case_wait_s)

    print("\nE22 driver done. "
          "Run: python3 experiments/aggregate_e22.py "
          f"--exp-dir {args.out_root}")


if __name__ == "__main__":
    main()
