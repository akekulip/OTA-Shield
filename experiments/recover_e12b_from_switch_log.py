"""E12b signed-mode recovery aggregator.

The original `aggregate_e12b.py` reads a per-trial `controller.log` from
each trial directory and searches for ``"RAT loaded: ... signed=True"``
and ``"RAT reload REJECTED"`` lines. In the 2026-04-20 20-trial run the
file under that name turned out to be a per-trial decisions JSONL slice,
not the human-readable controller log; the signed-mode and reject
signals live on the switch at ``/tmp/controller.log``. The original
`_agg/E12b_signed_manifest.json` therefore reports rate=0.0 for both,
which is a measurement-gap, not a science failure.

This script recovers those signals by cross-referencing each trial's
``marker_t`` (Phase B injection timestamp) against a copy of the switch
log pulled to the laptop. Output is a sidecar JSON; the original
aggregate file is left untouched for audit.

Usage:
    python3 experiments/recover_e12b_from_switch_log.py \\
        --orig-agg runs/experiments/_agg/E12b_signed_manifest.json \\
        --switch-log /home/philip/temp/e12b_recovery/switch_controller_2026-04-21.log \\
        --out-agg runs/experiments/_agg/E12b_signed_manifest_recovered.json \\
        --window-pre-s 60 --window-post-s 600
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
_LOADED_FRAG = "RAT loaded"
_REJECTED_FRAG = "RAT reload REJECTED"
_SIGNED_TRUE = "signed=True"
_SIGNED_FALSE = "signed=False"


def _parse_log(text: str) -> tuple[list[tuple[float, bool]], list[float]]:
    """Return (loaded_events, rejected_events).

    loaded_events is a list of (epoch_s, signed_true_bool).
    rejected_events is a list of epoch_s.
    """
    loaded: list[tuple[float, bool]] = []
    rejected: list[float] = []
    for line in text.splitlines():
        m = _TS_RE.match(line)
        if not m:
            continue
        try:
            epoch = _dt.datetime.strptime(
                m.group(1), "%Y-%m-%d %H:%M:%S"
            ).timestamp()
        except ValueError:
            continue
        if _LOADED_FRAG in line:
            loaded.append((epoch, _SIGNED_TRUE in line))
        if _REJECTED_FRAG in line:
            rejected.append(epoch)
    return loaded, rejected


def recover(orig_agg: dict,
            log_text: str,
            window_pre_s: float,
            window_post_s: float) -> dict:
    """Build a recovered aggregate dict. Trials whose marker_t precedes
    the log's first event are flagged ``coverage="MISSING"`` and their
    signed_true/reject fields stay None — never silently set to False.
    """
    loaded, rejected = _parse_log(log_text)
    if not loaded and not rejected:
        raise ValueError("switch log has no RAT events")

    log_first = min([e for e, _ in loaded] + rejected)
    log_last = max([e for e, _ in loaded] + rejected)

    per_trial_recovered = []
    for t in orig_agg.get("per_trial", []):
        mt = t.get("marker_t")
        if mt is None:
            per_trial_recovered.append({**t, "coverage": "NO_MARKER"})
            continue
        lo, hi = mt - window_pre_s, mt + window_post_s
        in_loaded = [(e, s) for e, s in loaded if lo <= e <= hi]
        in_rejected = [e for e in rejected if lo <= e <= hi]

        if mt + window_pre_s < log_first:
            coverage = "MISSING"
            signed_true_seen = None
            signed_false_seen = None
            reject_detected = None
        else:
            coverage = "COVERED"
            signed_true_seen = any(s for _, s in in_loaded)
            signed_false_seen = any((not s) for _, s in in_loaded)
            reject_detected = len(in_rejected) > 0

        per_trial_recovered.append({
            **t,
            "coverage": coverage,
            "recovered_signed_true_seen": signed_true_seen,
            "recovered_signed_false_seen": signed_false_seen,
            "recovered_reject_detected": reject_detected,
            "recovered_reject_hits": len(in_rejected),
            "recovered_loaded_in_window": len(in_loaded),
        })

    n_total = len(per_trial_recovered)
    covered = [r for r in per_trial_recovered if r.get("coverage") == "COVERED"]
    missing = [r for r in per_trial_recovered if r.get("coverage") == "MISSING"]

    if covered:
        signed_ok_among_covered = sum(
            1 for r in covered
            if r["recovered_signed_true_seen"] and not r["recovered_signed_false_seen"]
        )
        reject_det_among_covered = sum(
            1 for r in covered if r["recovered_reject_detected"]
        )
    else:
        signed_ok_among_covered = 0
        reject_det_among_covered = 0

    out = {
        **orig_agg,
        "recovery": {
            "switch_log_first_event_epoch": log_first,
            "switch_log_last_event_epoch": log_last,
            "switch_log_first_event_iso": _dt.datetime.fromtimestamp(log_first).isoformat(),
            "switch_log_last_event_iso": _dt.datetime.fromtimestamp(log_last).isoformat(),
            "window_pre_s": window_pre_s,
            "window_post_s": window_post_s,
            "n_trials_total": n_total,
            "n_covered": len(covered),
            "n_missing": len(missing),
            "signed_mode_recovered": {
                "signed_ok_among_covered": signed_ok_among_covered,
                "rate_among_covered": (
                    signed_ok_among_covered / max(len(covered), 1)
                ),
                "denominator_caveat": (
                    "Rate is over trials with controller-log coverage. "
                    f"{len(missing)} of {n_total} trials predate the log "
                    "due to a controller restart at "
                    f"{_dt.datetime.fromtimestamp(log_first).isoformat()}."
                ),
            },
            "reload_reject_recovered": {
                "detected_among_covered": reject_det_among_covered,
                "rate_among_covered": (
                    reject_det_among_covered / max(len(covered), 1)
                ),
            },
        },
        "per_trial": per_trial_recovered,
    }
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--orig-agg", required=True, type=Path)
    ap.add_argument("--switch-log", required=True, type=Path)
    ap.add_argument("--out-agg", required=True, type=Path)
    ap.add_argument("--window-pre-s", type=float, default=60.0)
    ap.add_argument("--window-post-s", type=float, default=600.0)
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    orig = json.loads(args.orig_agg.read_text())
    log_text = args.switch_log.read_text(errors="replace")
    out = recover(orig, log_text, args.window_pre_s, args.window_post_s)

    args.out_agg.parent.mkdir(parents=True, exist_ok=True)
    args.out_agg.write_text(json.dumps(out, indent=2))

    rec = out["recovery"]
    logger.info(
        "Recovered E12b: %d/%d covered; signed_ok %d/%d (%.3f); "
        "reject_detected %d/%d (%.3f). %d trials MISSING (pre-log).",
        rec["n_covered"], rec["n_trials_total"],
        rec["signed_mode_recovered"]["signed_ok_among_covered"],
        rec["n_covered"],
        rec["signed_mode_recovered"]["rate_among_covered"],
        rec["reload_reject_recovered"]["detected_among_covered"],
        rec["n_covered"],
        rec["reload_reject_recovered"]["rate_among_covered"],
        rec["n_missing"],
    )


if __name__ == "__main__":
    main()
