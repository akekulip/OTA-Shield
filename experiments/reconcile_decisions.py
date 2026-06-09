"""Ground-truth ↔ controller-decision reconciler.

Consumed by `aggregate_cluster.py` (Stats SB1). Per Testbed §4 we join
emit-time ground-truth events with the controller's `decisions.jsonl`
on a shared 5-tuple within a configurable timestamp window. The output
is a single ``reconciled.jsonl`` per trial, one JSON object per GT event
plus one per orphan decision.

Outcome semantics (per E12 / panel-8 §4):

    gt_label == LEGIT  + matched decision PASS  -> TN
    gt_label == LEGIT  + matched decision DROP  -> FP
    gt_label == LEGIT  + no decision found      -> TN  (silent pass; E12 §4)
    gt_label == ATTACK_*  + matched DROP        -> TP
    gt_label == ATTACK_*  + matched PASS        -> FN
    gt_label == ATTACK_*  + no decision found   -> FN
    gt_label == BROKER_RELAY                    -> ND  (excluded; T2.4 only)
    decision present, no matching GT            -> FP  (or ND if silent
                                                        controller pass)

CLI:
    python -m experiments.reconcile_decisions <trial_dir>
"""

from __future__ import annotations

import argparse
import bisect
import json
import sys
from pathlib import Path
from typing import Any, Iterable

# Default window in panel-8 §4 is ±2 ms; we expose 100 ms for unit tests
# but the real harness should tighten this. The aggregator does not look
# at the window — it only cares about the outcome label.
DEFAULT_WINDOW_MS = 100.0

ATTACK_PREFIXES = ("ATTACK_", "MIMICRY_")
NON_DECISION_LABELS = {"BROKER_RELAY"}


# ---------------------------------------------------------------- IP coercion


def _ip_to_int(value: Any) -> int:
    """Accept either dotted-quad ('10.0.1.10') or already-integer IP.
    Controller logs integers; ground truth logs dotted strings."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if s.isdigit():
            return int(s)
        try:
            parts = [int(p) for p in s.split(".")]
        except ValueError:
            return 0
        if len(parts) != 4:
            return 0
        a, b, c, d = parts
        return (a << 24) | (b << 16) | (c << 8) | d
    return 0


def _five_tuple(rec: dict) -> tuple[int, int, int, int]:
    return (
        _ip_to_int(rec.get("src_ip", 0)),
        _ip_to_int(rec.get("dst_ip", 0)),
        int(rec.get("src_port", 0) or 0),
        int(rec.get("dst_port", 0) or 0),
    )


# ---------------------------------------------------------------- loaders


def _read_json_or_jsonl(path: Path) -> list[dict]:
    """run_trial.py writes a single JSON dict with `events`; controller
    writes JSONL. Accept both so we don't fork the read path."""
    text = path.read_text().strip()
    if not text:
        return []

    # JSONL: every non-blank line parses as JSON (multi-line records
    # would not). A single-line JSONL file looks superficially like a
    # JSON document, so we try JSONL first and fall back to single-doc.
    lines = [ln for ln in text.splitlines() if ln.strip()]
    parsed_lines: list[dict] = []
    jsonl_ok = bool(lines)
    for line in lines:
        try:
            parsed_lines.append(json.loads(line))
        except json.JSONDecodeError:
            jsonl_ok = False
            break
    if jsonl_ok and parsed_lines:
        # If the JSONL detector landed on a single dict whose only
        # interesting field is `events`, treat it as the single-doc
        # variant so we always return the inner event list.
        if (len(parsed_lines) == 1 and isinstance(parsed_lines[0], dict)
                and "events" in parsed_lines[0]
                and isinstance(parsed_lines[0]["events"], list)):
            return list(parsed_lines[0]["events"])
        return parsed_lines

    # Pretty-printed multi-line single JSON document.
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(doc, dict) and isinstance(doc.get("events"), list):
        return list(doc["events"])
    if isinstance(doc, list):
        return doc
    return []


def load_ground_truth(trial_dir: Path) -> list[dict]:
    """Read ``ground_truth.json`` (or ``.jsonl``). Each emitted event is
    normalised to ``{ts, src_ip, dst_ip, src_port, dst_port, scenario_id,
    gt_label}`` so the matcher never has to think about file flavour."""
    trial_dir = Path(trial_dir)
    for name in ("ground_truth.jsonl", "ground_truth.json"):
        p = trial_dir / name
        if p.is_file():
            raw = _read_json_or_jsonl(p)
            break
    else:
        return []

    out: list[dict] = []
    for ev in raw:
        ts = float(ev.get("ts", ev.get("t_send", 0.0)) or 0.0)
        out.append({
            "ts": ts,
            "src_ip": _ip_to_int(ev.get("src_ip", 0)),
            "dst_ip": _ip_to_int(ev.get("dst_ip", 0)),
            "src_port": int(ev.get("src_port", 0) or 0),
            "dst_port": int(ev.get("dst_port", 1883) or 1883),
            "scenario_id": ev.get("scenario_id", ev.get("scenario", "")),
            "gt_label": ev.get("gt_label", ev.get("label", "LEGIT")),
        })
    return out


def load_decisions(trial_dir: Path) -> list[dict]:
    """Read controller `decisions.jsonl` — fields per the controller in
    `controller/ota_shield_controller.py:_log_decision`."""
    trial_dir = Path(trial_dir)
    for name in ("decisions.jsonl", "controller_decisions.jsonl"):
        p = trial_dir / name
        if p.is_file():
            raw = _read_json_or_jsonl(p)
            break
    else:
        return []
    out: list[dict] = []
    for rec in raw:
        # Controller-decisions only — skip raw mqtt_digest passthroughs the
        # E12 layout interleaves into `decisions.jsonl`.
        if "_type" in rec and rec.get("_type", "").endswith("_digest"):
            continue
        if "decision" not in rec:
            continue
        out.append({
            "ts": float(rec.get("t", rec.get("ts", 0.0)) or 0.0),
            "src_ip": _ip_to_int(rec.get("src_ip", 0)),
            "dst_ip": _ip_to_int(rec.get("dst_ip", 0)),
            "src_port": int(rec.get("src_port", 0) or 0),
            "dst_port": int(rec.get("dst_port", 1883) or 1883),
            "decision": rec.get("decision", "PASS"),
            "rules_fired": list(rec.get("rules_fired", []) or []),
            "action_code": int(rec.get("pipeline_action_code",
                                       rec.get("action_code", 0)) or 0),
            "reason": rec.get("reason", ""),
        })
    return out


# ---------------------------------------------------------------- matcher


def match_5tuple(gt_event: dict, dec_event: dict,
                 ts_window_ms: float = DEFAULT_WINDOW_MS) -> bool:
    """Same 5-tuple AND ts within ``ts_window_ms``."""
    if _five_tuple(gt_event) != _five_tuple(dec_event):
        return False
    return abs(gt_event["ts"] - dec_event["ts"]) * 1000.0 <= ts_window_ms


def _outcome_for_attack(decision: str | None) -> str:
    if decision is None:
        return "FN"  # silent pass on attack = miss
    return "TP" if decision == "DROP" else "FN"


def _outcome_for_legit(decision: str | None) -> str:
    if decision is None:
        return "TN"  # E12 4-events-no-digest pattern
    return "TN" if decision == "PASS" else "FP"


def _is_attack_label(label: str) -> bool:
    return any(label.startswith(p) for p in ATTACK_PREFIXES)


def reconcile(gt: list[dict], decisions: list[dict],
              ts_window_ms: float = DEFAULT_WINDOW_MS) -> list[dict]:
    """Join GT events to controller decisions; emit one outcome per GT
    event plus orphan decisions (FP) at the end."""
    used_decisions: set[int] = set()
    # Index decisions by 5-tuple for O(N log N) matching on ts.
    by_tuple: dict[tuple[int, int, int, int], list[tuple[float, int]]] = {}
    for idx, dec in enumerate(decisions):
        by_tuple.setdefault(_five_tuple(dec), []).append((dec["ts"], idx))
    for entries in by_tuple.values():
        entries.sort(key=lambda t: t[0])

    out: list[dict] = []
    for gt_ev in gt:
        gt_label = gt_ev["gt_label"]
        if gt_label in NON_DECISION_LABELS:
            out.append({
                "ts": gt_ev["ts"],
                "scenario_id": gt_ev["scenario_id"],
                "gt_label": gt_label,
                "pred_label": None,
                "outcome": "ND",
                "ts_lag_ms": None,
                "rules_fired": [],
            })
            continue

        candidates = by_tuple.get(_five_tuple(gt_ev), [])
        best_idx: int | None = None
        best_lag = float("inf")
        # bisect to the closest ts then walk +/- while inside the window.
        keys = [c[0] for c in candidates]
        pos = bisect.bisect_left(keys, gt_ev["ts"])
        for j in (pos - 1, pos):
            if 0 <= j < len(candidates):
                ts_d, idx_d = candidates[j]
                if idx_d in used_decisions:
                    continue
                lag_ms = abs(ts_d - gt_ev["ts"]) * 1000.0
                if lag_ms <= ts_window_ms and lag_ms < best_lag:
                    best_lag = lag_ms
                    best_idx = idx_d

        if best_idx is None:
            outcome = (_outcome_for_attack(None)
                       if _is_attack_label(gt_label)
                       else _outcome_for_legit(None))
            out.append({
                "ts": gt_ev["ts"],
                "scenario_id": gt_ev["scenario_id"],
                "gt_label": gt_label,
                "pred_label": "NO_DECISION",
                "outcome": outcome,
                "ts_lag_ms": None,
                "rules_fired": [],
            })
            continue

        used_decisions.add(best_idx)
        dec = decisions[best_idx]
        outcome = (_outcome_for_attack(dec["decision"])
                   if _is_attack_label(gt_label)
                   else _outcome_for_legit(dec["decision"]))
        out.append({
            "ts": gt_ev["ts"],
            "scenario_id": gt_ev["scenario_id"],
            "gt_label": gt_label,
            "pred_label": dec["decision"],
            "outcome": outcome,
            "ts_lag_ms": best_lag,
            "rules_fired": dec["rules_fired"],
        })

    # Orphan controller decisions (no matching GT) become FP unless the
    # decision was a silent PASS (then ND, by E12 semantics).
    for idx, dec in enumerate(decisions):
        if idx in used_decisions:
            continue
        outcome = "ND" if dec["decision"] == "PASS" else "FP"
        out.append({
            "ts": dec["ts"],
            "scenario_id": "",
            "gt_label": "UNMATCHED",
            "pred_label": dec["decision"],
            "outcome": outcome,
            "ts_lag_ms": None,
            "rules_fired": dec["rules_fired"],
        })
    return out


# ---------------------------------------------------------------- I/O


def write_reconciled(trial_dir: Path, rows: Iterable[dict]) -> Path:
    trial_dir = Path(trial_dir)
    out_path = trial_dir / "reconciled.jsonl"
    with out_path.open("w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    return out_path


def reconcile_trial(trial_dir: Path,
                    ts_window_ms: float = DEFAULT_WINDOW_MS) -> Path:
    gt = load_ground_truth(trial_dir)
    dec = load_decisions(trial_dir)
    rows = reconcile(gt, dec, ts_window_ms=ts_window_ms)
    return write_reconciled(trial_dir, rows)


def _cli(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="GT ↔ decision reconciler.")
    ap.add_argument("trial_dir", type=Path)
    ap.add_argument("--window-ms", type=float, default=DEFAULT_WINDOW_MS)
    args = ap.parse_args(argv)
    out_path = reconcile_trial(args.trial_dir, ts_window_ms=args.window_ms)
    print(f"[reconcile] wrote {out_path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(_cli())
