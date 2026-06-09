"""E22 post-processor — per-lifecycle-case confusion matrix.

Reads 5 cases x 20 trials from
    runs/experiments/E22_rat_lifecycle/<case_id>/t<NN>/
where each trial directory is written by `run_e22.py` and contains:
    labels.jsonl                 (ground truth produced by scenarios_e22)
    controller_decisions.jsonl   (arbiter decisions sliced from the switch)
    metadata.json                (per-case metadata; informational)

For each event we compare the ground-truth (`expected_decision`,
`expected_reason`) against the controller's (`decision`, `reason`) and
bucket into TP / TN / FP / FN / NO_DECISION. Precision / recall / F1 are
computed with ATTACK as the positive class, matching the convention in
the rest of the paper (aggregate.py).

Bootstrap 95 % CIs follow the `bootstrap_ci` implementation in
aggregate.py so figures share the same statistical machinery.

Writes:
    runs/experiments/_agg/E22_rat_lifecycle.json

Exit code is non-zero if any case has zero valid trials; reviewer-
facing null results still must be reported, but an empty directory is
a run-time error, not a null result.
"""
from __future__ import annotations

import argparse
import json
import math
import random
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Shared decision-derivation helper (see decision_derivation.py). The raw
# per-trial digest log carries no `decision`/`reason` string — only the
# genuine data-plane fields (action_code, r1..r6_fired, _type, ...). We
# reconstruct each event's controller decision by mirroring
# Controller.evaluate_hold, so this aggregator scores the real outcome.
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from decision_derivation import (  # noqa: E402
    clopper_pearson,
    derive_decision,
    int_to_ipv4,
    ipv4_to_int,
)

try:  # Optional: load the pure-Python RAT arbiter for RAT-gated branches.
    from controller.rat_arbiter import RatArbiter, load_rat_entries  # noqa: E402
except Exception:  # noqa: BLE001
    RatArbiter = None  # type: ignore
    load_rat_entries = None  # type: ignore


def bootstrap_ci(values: list[float], n_boot: int = 2000,
                 alpha: float = 0.05) -> tuple[float, float, float]:
    """Percentile bootstrap CI on the mean.

    Mirrors aggregate.py:bootstrap_ci so figures share one definition.
    Degenerate cases (n<3, all-equal) return NaN bounds.
    """
    if not values:
        return (float("nan"), float("nan"), float("nan"))
    if len(values) < 3:
        m = sum(values) / len(values)
        return (m, float("nan"), float("nan"))
    if max(values) - min(values) < 1e-12:
        m = sum(values) / len(values)
        return (m, float("nan"), float("nan"))
    rng = random.Random(0)
    mean = statistics.mean(values)
    reps = []
    for _ in range(n_boot):
        sample = [values[rng.randrange(len(values))] for _ in values]
        reps.append(statistics.mean(sample))
    reps.sort()
    lo = reps[int(n_boot * alpha / 2)]
    hi = reps[int(n_boot * (1 - alpha / 2))]
    return (mean, lo, hi)


# ---------------------------------------------------------------------------
# Per-trial correlation
# ---------------------------------------------------------------------------


def _load_labels(trial_dir: Path) -> list[dict]:
    """Load ground-truth labels written by scenarios_e22."""
    p = trial_dir / "labels.jsonl"
    if not p.exists():
        return []
    out: list[dict] = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _load_decisions(trial_dir: Path) -> dict:
    """Return controller decisions keyed by full 5-tuple of ints.

    We accept either `controller_decisions.jsonl` (produced by the
    sweep.py slicer) or `decisions.jsonl` (fallback for legacy runs).
    """
    for name in ("controller_decisions.jsonl", "decisions.jsonl"):
        p = trial_dir / name
        if not p.exists():
            continue
        decs: dict = {}
        for line in p.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "_marker" in d:
                continue
            src = d.get("src_ip")
            dst = d.get("dst_ip")
            if src is None or dst is None:
                continue
            if isinstance(src, str):
                src = ipv4_to_int(src)
            if isinstance(dst, str):
                dst = ipv4_to_int(dst)
            key = (int(src), int(dst),
                   int(d.get("src_port", 0)),
                   int(d.get("dst_port", 1883)))
            decs[key] = d
        if decs:
            return decs
    return {}


def _verdict(expected: str, observed: str, label: str) -> str:
    """Classify (expected_decision, observed_decision) into a verdict.

    ATTACK is the positive class (matches aggregate.py).
    """
    if observed is None:
        return "NO_DECISION"
    e = (expected or "").upper()
    o = (observed or "").upper()
    lab = (label or "").upper()
    if lab == "ATTACK":
        return "TP" if o == "DROP" else "FN"
    if lab == "LEGIT":
        return "TN" if o == "PASS" else "FP"
    # Shouldn't happen; treat as no-decision to surface upstream bug.
    return "NO_DECISION"


def _trial_metrics(trial_dir: Path,
                   arbiter: "RatArbiter | None" = None) -> dict | None:
    """Summarise one trial. Returns None if the trial is empty.

    Each label is matched to its raw digest record by 5-tuple (labels use
    string IPs, records use int IPs). The controller decision is then
    DERIVED from the record's genuine fields via ``derive_decision`` —
    the raw log has no ``decision``/``reason`` string.
    """
    labels = _load_labels(trial_dir)
    if not labels:
        return None
    decs = _load_decisions(trial_dir)

    verdicts: list[str] = []
    decision_match: list[int] = []  # 1 if derived decision == expected
    reason_match: list[int] = []    # 1 if derived reason == expected_reason
    reason_unmatch_rows: list[dict] = []
    per_reason = Counter()
    matched_keys: set[tuple] = set()
    labels_without_record = 0

    for ev in labels:
        key = (ipv4_to_int(ev["src_ip"]),
               ipv4_to_int(ev["dst_ip"]),
               int(ev["src_port"]),
               int(ev.get("dst_port", 1883)))
        d = decs.get(key)
        if d is None:
            # True coverage gap: GT event with no logged digest. Per the
            # E12 §4 / reconcile_decisions silent-pass convention, treat
            # an absent decision as a silent PASS (attack -> FN, legit ->
            # TN) and surface the count as a caveat.
            labels_without_record += 1
            observed, obs_reason = "PASS", "no_record"
        else:
            matched_keys.add(key)
            derived = derive_decision(d, arbiter=arbiter)
            observed, obs_reason = derived.decision, derived.reason

        v = _verdict(ev["expected_decision"], observed, ev["label"])
        verdicts.append(v)
        per_reason[obs_reason or "(none)"] += 1

        exp_dec = (ev.get("expected_decision") or "").upper()
        decision_match.append(1 if observed.upper() == exp_dec else 0)

        exp_reason = ev.get("expected_reason")
        if exp_reason is not None:
            if obs_reason == exp_reason:
                reason_match.append(1)
            else:
                reason_match.append(0)
                reason_unmatch_rows.append({
                    "scenario": ev.get("scenario"),
                    "src_ip": ev["src_ip"],
                    "dst_ip": ev["dst_ip"],
                    "expected_decision": exp_dec,
                    "observed_decision": observed,
                    "expected_reason": exp_reason,
                    "observed_reason": obs_reason,
                })

    # Orphan records: logged decisions with no matching GT label.
    orphan_records = sum(1 for k in decs if k not in matched_keys)

    c = Counter(verdicts)
    tp, tn, fp, fn, nd = c["TP"], c["TN"], c["FP"], c["FN"], c["NO_DECISION"]
    total = sum(c.values())
    obs = tp + tn + fp + fn
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec  = tp / (tp + fn) if (tp + fn) else float("nan")
    f1   = (2 * prec * rec / (prec + rec)
            if (prec + rec and not math.isnan(prec) and not math.isnan(rec))
            else float("nan"))
    acc  = (tp + tn) / obs if obs else float("nan")
    decision_acc = (sum(decision_match) / len(decision_match)
                    if decision_match else float("nan"))
    reason_acc = (sum(reason_match) / len(reason_match)
                  if reason_match else float("nan"))

    return {
        "trial_id": trial_dir.name,
        "n_events": total,
        "n_labels": len(labels),
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "no_decision": nd,
        "n_decision_correct": sum(decision_match),
        "n_decision_scored": len(decision_match),
        "n_reason_correct": sum(reason_match),
        "n_reason_scored": len(reason_match),
        "precision": prec, "recall": rec, "f1": f1, "accuracy": acc,
        "decision_accuracy": decision_acc,
        "reason_accuracy": reason_acc,
        "reason_counts": dict(per_reason),
        "reason_mismatches": reason_unmatch_rows,
        "labels_without_record": labels_without_record,
        "orphan_records": orphan_records,
        "digest_loss_rate": nd / total if total else 0.0,
    }


# ---------------------------------------------------------------------------
# Per-case aggregation
# ---------------------------------------------------------------------------


def _aggregate_case(case_dir: Path,
                    arbiter: "RatArbiter | None" = None) -> dict:
    """Aggregate all trials in one lifecycle case directory.

    E22 is a *deterministic-correctness* experiment (EXPERIMENT_DESIGN.md
    §"Reporting class"): point estimates are pooled across trials and
    zero-event cells use exact Clopper-Pearson UB at alpha=0.05 (never
    [1.000, 1.000]). The per-trial bootstrap CIs are retained for audit
    but are not the headline statistic for this class.
    """
    trials: list[dict] = []
    for trial_dir in sorted(case_dir.iterdir()):
        if not trial_dir.is_dir():
            continue
        m = _trial_metrics(trial_dir, arbiter=arbiter)
        if m is not None:
            trials.append(m)

    # Per-trial bootstrap CIs (audit only, stochastic-style).
    agg: dict[str, dict[str, float]] = {}
    for key in ("precision", "recall", "f1", "accuracy",
                "decision_accuracy", "reason_accuracy"):
        vals = [t[key] for t in trials
                if key in t and not math.isnan(t[key])]
        mean, lo, hi = (bootstrap_ci(vals) if vals
                        else (float("nan"),) * 3)
        agg[key] = {"mean": mean, "ci_lo": lo, "ci_hi": hi,
                    "per_trial": vals}

    # Global confusion counts summed across trials.
    tot = Counter()
    for t in trials:
        for k in ("tp", "tn", "fp", "fn", "no_decision", "n_events",
                  "n_labels", "n_decision_correct", "n_decision_scored",
                  "n_reason_correct", "n_reason_scored",
                  "labels_without_record", "orphan_records"):
            tot[k] += t[k]

    # Pooled point estimates + exact Clopper-Pearson intervals.
    tp, tn, fp, fn = tot["tp"], tot["tn"], tot["fp"], tot["fn"]
    pooled = {
        "precision": clopper_pearson(tp, tp + fp),
        "recall": clopper_pearson(tp, tp + fn),
        "accuracy": clopper_pearson(tp + tn, tp + tn + fp + fn),
        "decision_accuracy": clopper_pearson(
            tot["n_decision_correct"], tot["n_decision_scored"]),
        "reason_accuracy": clopper_pearson(
            tot["n_reason_correct"], tot["n_reason_scored"]),
    }
    p_pt, _, _ = pooled["precision"]
    r_pt, _, _ = pooled["recall"]
    f1_pt = (2 * p_pt * r_pt / (p_pt + r_pt)
             if (not math.isnan(p_pt) and not math.isnan(r_pt)
                 and (p_pt + r_pt) > 0) else float("nan"))
    pooled_out = {
        k: {"point": v[0], "cp_lo": v[1], "cp_hi": v[2]}
        for k, v in pooled.items()
    }
    pooled_out["f1"] = {"point": f1_pt, "cp_lo": float("nan"),
                        "cp_hi": float("nan")}

    # Reason-code histogram + mismatch rows across all trials (diagnostic).
    reason_hist: Counter = Counter()
    mismatches: list[dict] = []
    for t in trials:
        for r, n in t["reason_counts"].items():
            reason_hist[r] += n
        mismatches.extend(t["reason_mismatches"])

    coverage = {
        "labels_without_record": tot["labels_without_record"],
        "orphan_records": tot["orphan_records"],
        "n_labels": tot["n_labels"],
        "n_events_scored": tot["n_events"],
    }

    return {
        "case_id": case_dir.name,
        "n_trials": len(trials),
        "confusion_total": dict(tot),
        "pooled": pooled_out,
        "aggregate": agg,
        "coverage": coverage,
        "reason_histogram": dict(reason_hist),
        "reason_mismatches": mismatches,
        "per_trial_raw": trials,
    }


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp-dir",
                    default="runs/experiments/E22_rat_lifecycle",
                    type=Path)
    ap.add_argument("--agg-json",
                    default="runs/experiments/_agg/E22_rat_lifecycle.json",
                    type=Path)
    ap.add_argument("--rat-json", type=Path, default=None,
                    help="Optional RAT manifest for RAT-gated decision "
                         "branches. E22's terminal_fire path precedes RAT "
                         "consultation, so this does not change the 2026-06-06 "
                         "verdicts, but it is wired for general reuse.")
    args = ap.parse_args()

    if not args.exp_dir.exists():
        raise SystemExit(f"missing {args.exp_dir}")
    args.agg_json.parent.mkdir(parents=True, exist_ok=True)

    arbiter = None
    if args.rat_json is not None and RatArbiter is not None \
            and load_rat_entries is not None:
        arbiter = RatArbiter(load_rat_entries(args.rat_json))

    case_results: list[dict] = []
    empty_cases: list[str] = []
    for case_dir in sorted(p for p in args.exp_dir.iterdir()
                           if p.is_dir() and not p.name.startswith("_")):
        case = _aggregate_case(case_dir, arbiter=arbiter)
        if case["n_trials"] == 0:
            empty_cases.append(case_dir.name)
        case_results.append(case)

    summary = {
        "experiment": args.exp_dir.name,
        "n_cases": len(case_results),
        "reporting_class": "deterministic_correctness",
        "ci_method": "clopper_pearson_alpha0.05",
        "cases": case_results,
    }
    args.agg_json.write_text(json.dumps(summary, indent=2))

    # Console readout — honest values only, no mocking. Pooled point
    # estimates with exact Clopper-Pearson intervals (deterministic class).
    def _cp(d: dict) -> str:
        pt, lo, hi = d["point"], d["cp_lo"], d["cp_hi"]
        if math.isnan(pt):
            return "n/a (no scored cell)"
        if math.isnan(lo) or math.isnan(hi):
            return f"{pt:.3f}"
        return f"{pt:.3f} [{lo:.3f}, {hi:.3f}]"

    for c in case_results:
        p = c["pooled"]
        cm = c["confusion_total"]
        cov = c["coverage"]
        print(f"[E22 {c['case_id']:24s}] n_trials={c['n_trials']:2d} "
              f"TP={cm['tp']:3d} TN={cm['tn']:3d} FP={cm['fp']:3d} "
              f"FN={cm['fn']:3d}")
        print(f"        decision_acc={_cp(p['decision_accuracy'])}  "
              f"reason_acc={_cp(p['reason_accuracy'])}")
        print(f"        precision={_cp(p['precision'])}  "
              f"recall={_cp(p['recall'])}  F1={_cp(p['f1'])}")
        if cov["labels_without_record"] or cov["orphan_records"]:
            print(f"        COVERAGE CAVEAT: "
                  f"labels_without_record={cov['labels_without_record']} "
                  f"orphan_records={cov['orphan_records']} "
                  f"(of {cov['n_labels']} labels)")
        print(f"        reason_histogram={c['reason_histogram']}")
    print(f"\nWrote {args.agg_json}")
    if empty_cases:
        raise SystemExit(
            f"ERROR: {len(empty_cases)} case(s) had zero valid trials: "
            f"{empty_cases}")


if __name__ == "__main__":
    main()
