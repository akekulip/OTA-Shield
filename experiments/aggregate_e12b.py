"""E12b (signed-manifest) post-processor.

Computes the three numbers the IJCIP reviewer asked for under M6:

  1. Phase-A FP rate under a valid signed manifest.
     Expected: 0 FP across all trials (identical to E12).

  2. Reload-reject detection rate on stale-manifest injection.
     Expected: 100 %. Every trial's controller log must contain
     "RAT reload REJECTED" within SIG_REJECT_OBSERVE_WINDOW_S of the
     Phase B marker event (scenario="e12b_phaseB_inject_marker") we
     wrote into ground_truth.json.

  3. Last-known-good fallback correctness.
     After the reject is logged, the probe burst tagged
     "e12b_phaseB_lastgood" must all resolve to PASS — i.e. the
     controller retained the old cache and Gate A still matched.

The script emits a JSON aggregate plus a numbers.tex fragment under a
NEW macro namespace `EOneTwobsigned*`. It deliberately never touches
the old `\\EOneTwobstaler*` macros; those come from the obsolete
stale-RAT experiment and the honest framing is that the new signed
pipeline supersedes them rather than patching their definitions in
place.

Usage
    python3 experiments/aggregate_e12b.py \\
        --exp-dir runs/experiments/E12b_signed_manifest \\
        --agg-json runs/experiments/_agg/E12b_signed_manifest.json \\
        --numbers-out paper/numbers_e12b_signed.tex
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


# Reload-reject log line written by RatLifecycleManager.reload(). We
# match the literal fragment rather than a full regex because the rest
# of the line carries the exception repr which can vary across Python
# versions.
RELOAD_REJECT_FRAGMENT = "RAT reload REJECTED"

# Matches the positive "loaded signed manifest" line so we can also
# report: "Phase-A actually ran signed=True". If any trial has
# signed=False at load time, the whole run is flagged NOT-SIGNED and
# the signed-path claim is not emitted.
SIGNED_TRUE_RE = re.compile(r"RAT loaded: \d+ entries, signed=True")
SIGNED_FALSE_RE = re.compile(r"RAT loaded: \d+ entries, signed=False")


# --------------------------------------------------------------------- I/O


def load_gt(trial_dir: Path) -> list[dict]:
    p = trial_dir / "ground_truth.json"
    if not p.exists():
        return []
    data = json.loads(p.read_text())
    if isinstance(data, list):
        return data
    return data.get("events", [])


def load_decisions(trial_dir: Path) -> list[dict]:
    for name in ("controller_decisions.jsonl", "decisions.jsonl"):
        p = trial_dir / name
        if not p.exists():
            continue
        out: list[dict] = []
        for line in p.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        if out:
            return out
    return []


def load_controller_log(trial_dir: Path) -> str:
    """Return the controller log text for this trial, empty string if
    none. sweep.py pulls the sliced controller log to either
    `controller.log` or `phase5_digests.jsonl`-style filenames; we try
    the common names in order.
    """
    for name in ("controller.log", "phase5_digests.jsonl",
                 "phase6_digests.jsonl", "trial_controller.log"):
        p = trial_dir / name
        if p.exists():
            try:
                return p.read_text(errors="replace")
            except OSError:
                return ""
    return ""


_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")


def _parse_log_ts_utc(line: str) -> float | None:
    """Parse the leading "YYYY-MM-DD HH:MM:SS" timestamp of a controller
    log line as UTC. Returns Unix epoch seconds, or None if the line has
    no parseable prefix. The controller writes UTC timestamps via
    logging's default %(asctime)s; we mirror that assumption here.
    """
    m = _TS_RE.match(line)
    if not m:
        return None
    try:
        dt = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc).timestamp()


def slice_stdout_for_trial(stdout_text: str, trial_dir: Path,
                           window_back_s: float,
                           window_fwd_s: float) -> str:
    """Return the controller-stdout slice covering this trial.

    The driver pulls per-trial artifacts immediately after restore_sig,
    so the trial directory's mtime brackets trial-end within a few
    seconds. We take a window of [end - window_back_s, end + fwd_s] in
    UTC epoch and return the matching log lines verbatim.

    This is the recovery path for runs where the per-trial captured
    "controller.log" was actually a decisions-jsonl slice rather than
    controller stdout (e.g. the driver was wired with --controller-log
    pointing at decisions.jsonl). It assumes the host clock and the
    controller log timestamps are both UTC, which matches the
    repository convention.
    """
    end_ts = trial_dir.stat().st_mtime
    lo = end_ts - window_back_s
    hi = end_ts + window_fwd_s
    out: list[str] = []
    for line in stdout_text.splitlines():
        ts = _parse_log_ts_utc(line)
        if ts is None:
            continue
        if lo <= ts <= hi:
            out.append(line)
    return "\n".join(out)


def int_to_ip(x: int) -> str:
    return ".".join(str((x >> (8 * (3 - i))) & 0xff) for i in range(4))


# --------------------------------------------------------------------- core


def classify_phase(scenario: str) -> str:
    """Map a ground-truth event's scenario label to a phase bucket."""
    if scenario.startswith("e12b_phaseA"):
        return "A"
    if scenario.startswith("e12b_phaseB_lastgood"):
        return "B_lastgood"
    if scenario == "e12b_phaseB_inject_marker":
        return "B_marker"
    return "unknown"


def count_trial(trial_dir: Path, *,
                stdout_slice_text: str | None = None) -> dict:
    gt = load_gt(trial_dir)
    decs = load_decisions(trial_dir)
    if stdout_slice_text is not None:
        log_text = stdout_slice_text
    else:
        log_text = load_controller_log(trial_dir)

    # Index decisions by (src_ip, dst_ip, src_port) for ground-truth
    # correlation, matching aggregate_e12.py's key.
    by_key: dict[tuple, dict] = {}
    for d in decs:
        src = d.get("src_ip")
        dst = d.get("dst_ip")
        sport = int(d.get("src_port", 0))
        if isinstance(src, int):
            src = int_to_ip(src)
        if isinstance(dst, int):
            dst = int_to_ip(dst)
        by_key[(src, dst, sport)] = d

    # Phase-A / Phase-B-lastgood outcome tallies.
    phase_totals = defaultdict(lambda: {"pass": 0, "fp": 0,
                                         "drop": 0, "no_decision": 0})
    marker_t: float | None = None

    for ev in gt:
        phase = classify_phase(ev.get("scenario", ""))
        if phase == "B_marker":
            marker_t = float(ev.get("t_send", 0.0))
            continue
        if phase == "unknown":
            continue
        # LEGIT-only scenario; any non-PASS is an FP.
        key = (ev.get("src_ip"), ev.get("dst_ip"),
               int(ev.get("src_port", 0)))
        d = by_key.get(key)
        if d is None:
            # Mirrors aggregate_e12.py: silent data-plane PASS is a
            # correct outcome for LEGIT events when no rule fired.
            phase_totals[phase]["pass"] += 1
            continue
        dec = (d.get("decision") or "").upper()
        if dec == "PASS":
            phase_totals[phase]["pass"] += 1
        elif dec == "DROP":
            phase_totals[phase]["fp"] += 1
            phase_totals[phase]["drop"] += 1
        else:
            phase_totals[phase]["no_decision"] += 1

    # Reload-reject detection: look for the fragment ANYWHERE in the
    # controller log during this trial's slice. sweep.py already
    # byte-sliced the log, so the whole file corresponds to this trial.
    reject_hits = log_text.count(RELOAD_REJECT_FRAGMENT)
    reject_detected = reject_hits > 0

    # Signed-at-load sanity: at least one "signed=True" and no
    # "signed=False" line in the trial slice.
    signed_true = bool(SIGNED_TRUE_RE.search(log_text))
    signed_false = bool(SIGNED_FALSE_RE.search(log_text))

    return {
        "trial": trial_dir.name,
        "phase_totals": {k: dict(v) for k, v in phase_totals.items()},
        "marker_t": marker_t,
        "reject_hits": reject_hits,
        "reject_detected": reject_detected,
        "signed_true_seen": signed_true,
        "signed_false_seen": signed_false,
    }


def aggregate(exp_dir: Path, *,
              controller_stdout_log: Path | None = None,
              window_back_s: float = 1500.0,
              window_fwd_s: float = 60.0) -> dict:
    if not exp_dir.exists():
        raise SystemExit(f"missing {exp_dir}")
    trials = sorted(
        p for p in exp_dir.iterdir()
        if p.is_dir() and not p.name.startswith("_"))
    stdout_text = (controller_stdout_log.read_text(errors="replace")
                   if controller_stdout_log is not None else None)
    per_trial = []
    for t in trials:
        slice_text = (
            slice_stdout_for_trial(stdout_text, t,
                                   window_back_s=window_back_s,
                                   window_fwd_s=window_fwd_s)
            if stdout_text is not None else None)
        per_trial.append(count_trial(t, stdout_slice_text=slice_text))
    n = len(per_trial)

    # Phase-A FP rate: total FP / total events across all trials.
    A_pass = sum(t["phase_totals"].get("A", {}).get("pass", 0)
                 for t in per_trial)
    A_fp = sum(t["phase_totals"].get("A", {}).get("fp", 0) for t in per_trial)
    A_nd = sum(t["phase_totals"].get("A", {}).get("no_decision", 0)
               for t in per_trial)
    A_total = A_pass + A_fp + A_nd
    A_fp_rate = A_fp / max(A_total, 1)

    # Phase-B last-known-good PASS rate.
    B_pass = sum(t["phase_totals"].get("B_lastgood", {}).get("pass", 0)
                 for t in per_trial)
    B_fp = sum(t["phase_totals"].get("B_lastgood", {}).get("fp", 0)
               for t in per_trial)
    B_nd = sum(t["phase_totals"].get("B_lastgood", {}).get("no_decision", 0)
               for t in per_trial)
    B_total = B_pass + B_fp + B_nd
    B_pass_rate = B_pass / max(B_total, 1)

    # Reload-reject detection rate: fraction of trials whose controller
    # log carries at least one "RAT reload REJECTED" line.
    rej_hits = sum(1 for t in per_trial if t["reject_detected"])
    rej_rate = rej_hits / max(n, 1)

    # Signed-at-load sanity: trials that saw signed=True and none that
    # saw signed=False.
    signed_ok = sum(
        1 for t in per_trial
        if t["signed_true_seen"] and not t["signed_false_seen"])
    signed_ok_rate = signed_ok / max(n, 1)

    summary = {
        "n_trials": n,
        "phaseA": {
            "pass": A_pass, "fp": A_fp, "no_decision": A_nd,
            "total": A_total, "fp_rate": A_fp_rate,
        },
        "phaseB_lastgood": {
            "pass": B_pass, "fp": B_fp, "no_decision": B_nd,
            "total": B_total, "pass_rate": B_pass_rate,
        },
        "reload_reject": {
            "trials_with_reject": rej_hits,
            "detection_rate": rej_rate,
        },
        "signed_mode": {
            "trials_signed_ok": signed_ok,
            "rate": signed_ok_rate,
        },
        "per_trial": per_trial,
    }
    return summary


# --------------------------------------------------------------------- LaTeX


def emit_numbers_tex(summary: dict, out: Path) -> None:
    """Emit a NEW macro namespace `EOneTwobsigned*`.

    This never touches `\\EOneTwobstaler*` macros — the old stale-RAT
    experiment is semantically distinct (it tested "start with stale
    JSON" which the signed-manifest pipeline no longer permits).
    """
    A = summary["phaseA"]
    B = summary["phaseB_lastgood"]
    R = summary["reload_reject"]
    S = summary["signed_mode"]
    lines = [
        "% Auto-generated by experiments/aggregate_e12b.py — DO NOT EDIT",
        "% Namespace: EOneTwobsigned* (E12b under the M6 signed-manifest",
        "% infrastructure). Replaces the obsolete EOneTwobstaler* macros;",
        "% do not reuse the old names — their experiment (plain-JSON stale",
        "% RAT) is no longer reachable in the signed pipeline.",
        f"\\newcommand{{\\EOneTwobsignedNTrials}}{{{summary['n_trials']}}}",
        f"\\newcommand{{\\EOneTwobsignedPhaseAEvents}}{{{A['total']}}}",
        f"\\newcommand{{\\EOneTwobsignedPhaseAFP}}{{{A['fp']}}}",
        (f"\\newcommand{{\\EOneTwobsignedPhaseAFPrate}}"
         f"{{{A['fp_rate']:.4f}}}"),
        f"\\newcommand{{\\EOneTwobsignedPhaseBEvents}}{{{B['total']}}}",
        f"\\newcommand{{\\EOneTwobsignedPhaseBPass}}{{{B['pass']}}}",
        (f"\\newcommand{{\\EOneTwobsignedPhaseBPassrate}}"
         f"{{{B['pass_rate']:.4f}}}"),
        (f"\\newcommand{{\\EOneTwobsignedRejectTrials}}"
         f"{{{R['trials_with_reject']}}}"),
        (f"\\newcommand{{\\EOneTwobsignedRejectRate}}"
         f"{{{R['detection_rate']:.4f}}}"),
        (f"\\newcommand{{\\EOneTwobsignedSignedOkTrials}}"
         f"{{{S['trials_signed_ok']}}}"),
        (f"\\newcommand{{\\EOneTwobsignedSignedOkRate}}"
         f"{{{S['rate']:.4f}}}"),
        "",
    ]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines))


# --------------------------------------------------------------------- main


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--exp-dir",
                    default="runs/experiments/E12b_signed_manifest",
                    type=Path)
    ap.add_argument("--agg-json",
                    default="runs/experiments/_agg/E12b_signed_manifest.json",
                    type=Path)
    ap.add_argument("--numbers-out",
                    default="paper/numbers_e12b_signed.tex",
                    type=Path,
                    help="LaTeX fragment with the EOneTwobsigned* macros.")
    ap.add_argument("--controller-stdout-log",
                    type=Path,
                    default=None,
                    help="Optional path to a captured slice of the "
                         "controller stdout log (controller_smoke.log "
                         "or equivalent). When provided, per-trial "
                         "reload-reject and signed-at-load detection "
                         "use a UTC time window around each trial's "
                         "directory mtime instead of the per-trial "
                         "captured file (which may carry a "
                         "decisions-jsonl slice if the driver was "
                         "wired with --controller-log pointing at "
                         "decisions.jsonl).")
    ap.add_argument("--window-back-s", type=float, default=1500.0,
                    help="Window backward from trial-end mtime (UTC "
                         "seconds) when slicing the controller stdout "
                         "log. Default 1500s covers the 883s Phase-B "
                         "wait plus prologue.")
    ap.add_argument("--window-fwd-s", type=float, default=60.0,
                    help="Window forward from trial-end mtime (UTC "
                         "seconds). Default 60s covers the post-restore "
                         "RAT-loaded line.")
    args = ap.parse_args()

    summary = aggregate(args.exp_dir,
                        controller_stdout_log=args.controller_stdout_log,
                        window_back_s=args.window_back_s,
                        window_fwd_s=args.window_fwd_s)

    args.agg_json.parent.mkdir(parents=True, exist_ok=True)
    args.agg_json.write_text(json.dumps(summary, indent=2))
    emit_numbers_tex(summary, args.numbers_out)

    A = summary["phaseA"]
    B = summary["phaseB_lastgood"]
    R = summary["reload_reject"]
    S = summary["signed_mode"]
    print(f"E12b signed-manifest aggregate ({summary['n_trials']} trials)")
    print(f"  Phase A (valid sig):        "
          f"events={A['total']}  FP={A['fp']}  "
          f"FP-rate={A['fp_rate']*100:.2f}%")
    print(f"  Phase B (last-known-good):  "
          f"events={B['total']}  PASS={B['pass']}  "
          f"pass-rate={B['pass_rate']*100:.2f}%")
    print(f"  Reload-reject detection:    "
          f"trials={R['trials_with_reject']}/{summary['n_trials']}  "
          f"rate={R['detection_rate']*100:.2f}%")
    print(f"  Signed=True at load:        "
          f"trials={S['trials_signed_ok']}/{summary['n_trials']}  "
          f"rate={S['rate']*100:.2f}%")
    print(f"\nWrote {args.agg_json}")
    print(f"Wrote {args.numbers_out}")


if __name__ == "__main__":
    main()
