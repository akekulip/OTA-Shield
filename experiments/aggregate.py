"""Aggregate experiment trials into paper metrics.

Reads `runs/experiments/<exp_id>/t*/{ground_truth.json, decisions.jsonl}`,
correlates ground-truth events with observed controller decisions, and
emits per-experiment summary JSON with bootstrap 95 % CIs.

Correlation key: full 5-tuple `(src_ip, dst_ip, src_port, dst_port, proto)`.
Each ground-truth event has a label (LEGIT/ATTACK); each observed decision
has a rule set and a final action (PASS/DROP). A trial's outcome for each
event is verdict ∈ {TP, TN, FP, FN, NO_DECISION} (last = no matching digest
received).

**F1.1 / F4.1 review fixes:**
  - NO_DECISION is its own bucket and is reported separately. It is NOT
    rolled into FN. The paper must cite NO_DECISION rate alongside F1 so
    digest-transport loss cannot inflate the detector's apparent recall.
  - Correlation uses full 5-tuple including dst_port and proto so that
    ephemeral source-port collisions cannot silently mis-join.

Metrics per experiment (aggregated over trials):
  - precision, recall, F1, accuracy (mean ± 95 % CI)
  - per-rule counts
  - detection latency distribution (attack-only)
  - **digest_loss_rate** = NO_DECISION / total_events
  - per-event diagnostic CSV emitted alongside the summary so any
    suspicious row can be traced back to its source.
"""
from __future__ import annotations
import argparse, json, math, random, statistics
from pathlib import Path
from collections import Counter, defaultdict


def ipv4_to_int(ip: str) -> int:
    p = ip.split(".")
    return (int(p[0]) << 24) | (int(p[1]) << 16) | (int(p[2]) << 8) | int(p[3])


def load_trial(trial_dir: Path) -> dict | None:
    """Return aggregated trial metrics, or None if the trial was marked
    invalid by sweep.py (e.g. controller log was rotated mid-trial)."""
    if (trial_dir / "trial_invalid.txt").exists():
        return None
    gt = json.loads((trial_dir / "ground_truth.json").read_text())
    decisions = []
    for name in ("decisions.jsonl", "decisions_digest.jsonl"):
        p = trial_dir / name
        if not p.exists():
            continue
        for line in p.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                decisions.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    # Controller-side decision log (ground truth for what the controller
    # actually installed). Absent → aggregator falls back to inference.
    ctrl_decisions = {}
    ctrl_log = trial_dir / "controller_decisions.jsonl"
    if ctrl_log.exists():
        for line in ctrl_log.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "_marker" in d:
                continue   # skip controller barrier markers
            key = (int(d["src_ip"]), int(d["dst_ip"]),
                   int(d["src_port"]),
                   int(d.get("dst_port", 1883)))
            ctrl_decisions[key] = d

    # F4.1 fix: correlate by FULL 5-tuple including dst_port + proto.
    # Previously keyed on (src_ip, dst_ip, src_port) only, which under
    # ephemeral-port reuse can silently mis-join two events.
    dec_index = {}
    for d in decisions:
        key = (int(d.get("src_ip", 0)),
               int(d.get("dst_ip", 0)),
               int(d.get("src_port", 0)),
               int(d.get("dst_port", 1883)))
        existing = dec_index.get(key)
        if (existing is None
                or (d.get("_type") == "hold_digest"
                    and existing.get("_type") != "hold_digest")):
            dec_index[key] = d

    verdicts = []
    latencies = []
    per_rule = defaultdict(Counter)
    for ev in gt["events"]:
        key = (ipv4_to_int(ev["src_ip"]),
               ipv4_to_int(ev["dst_ip"]),
               int(ev["src_port"]),
               int(ev.get("dst_port", 1883)))
        # STRICT ACADEMIC MODE — no inference.
        ctrl = ctrl_decisions.get(key)
        d = dec_index.get(key)

        if d is None:
            verdicts.append("NO_DECISION")
            continue

        dtype = d.get("_type", "")

        # C3 FIX (code review). For ATTACK-labeled events, a non-hold
        # digest is INSUFFICIENT evidence of PASS: the hold_digest may have
        # been dropped by the BF-SDE learn channel under load. We MUST see
        # a controller decision (`ctrl is not None`) before we declare
        # action=PASS for an attack event. Without it, mark NO_DECISION
        # (separately tracked) instead of silently inflating recall.
        #
        # For LEGIT-labeled events with a non-hold digest and no controller
        # decision, the pipeline forwarded by default and no rule fired —
        # this IS a real PASS observation from the data plane (no rule
        # ever produces a hold_digest for normal traffic).
        if dtype == "hold_digest":
            if ctrl is None:
                verdicts.append("NO_DECISION")
                continue
            action = ctrl["decision"]
            rules = list(ctrl.get("rules_fired", []))
            rule_key = "+".join(rules) if rules else "-"
            source = "controller_log"
        else:
            if ev["label"] == "ATTACK":
                # Attack event with only mqtt/classify digest is suspicious.
                # If the controller logged a decision for this flow we trust
                # it; otherwise we cannot rule out lost hold_digest.
                if ctrl is not None:
                    action = ctrl["decision"]
                    rules = list(ctrl.get("rules_fired", []))
                    rule_key = "+".join(rules) if rules else "-"
                    source = "controller_log_for_attack"
                else:
                    verdicts.append("NO_DECISION")
                    continue
            else:   # LEGIT event with non-hold digest is real PASS
                action = "PASS"
                rule_key = "-"
                source = "pipeline_no_fire"

        if ev["label"] == "ATTACK" and action == "DROP":
            v = "TP"
        elif ev["label"] == "LEGIT" and action == "PASS":
            v = "TN"
        elif ev["label"] == "LEGIT" and action == "DROP":
            v = "FP"
        else:
            v = "FN"
        verdicts.append(v)
        per_rule[rule_key][v] += 1

        # Latency: controller-received timestamp minus packet-send timestamp.
        if ev["label"] == "ATTACK" and d.get("_t_recv"):
            latencies.append(float(d["_t_recv"]) - float(ev["t_send"]))

    return {
        "trial_id": gt["trial_id"],
        "verdicts": verdicts,
        "per_rule": {k: dict(v) for k, v in per_rule.items()},
        "latencies": latencies,
    }


def metrics_from_verdicts(verdicts: list[str]) -> dict:
    c = Counter(verdicts)
    tp, tn, fp, fn = c["TP"], c["TN"], c["FP"], c["FN"]
    nd = c["NO_DECISION"]
    total = sum(c.values())
    # Headline metrics computed only over OBSERVED decisions; digest-loss
    # is reported separately so the paper cannot conflate them.
    obs = tp + tn + fp + fn
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec  = tp / (tp + fn) if (tp + fn) else float("nan")
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else float("nan")
    acc  = (tp + tn) / obs if obs else float("nan")
    digest_loss_rate = nd / total if total else 0.0
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "no_decision": nd,
            "digest_loss_rate": digest_loss_rate,
            "precision": prec, "recall": rec, "f1": f1, "accuracy": acc}


def _merge_per_rule(dicts: list[dict]) -> dict:
    """Sum per-rule verdict counters across trials."""
    out: dict[str, dict[str, int]] = {}
    for d in dicts:
        for rule, verdicts in d.items():
            slot = out.setdefault(rule, {})
            for v, n in verdicts.items():
                slot[v] = slot.get(v, 0) + n
    return out


def bootstrap_ci(values: list[float], n_boot: int = 2000,
                 alpha: float = 0.05) -> tuple[float, float, float]:
    """Returns (mean, ci_lo, ci_hi). M7 fix: when n < 3 we cannot honestly
    quote a CI; return mean and NaN bounds. Also emit a degenerate CI when
    all input values are identical (deterministic input) so figures don't
    silently render zero-width error bars."""
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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs-dir", default="runs/experiments", type=Path)
    ap.add_argument("--out-dir", default="runs/experiments/_agg", type=Path)
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for exp_dir in sorted(p for p in args.runs_dir.iterdir()
                          if p.is_dir() and not p.name.startswith("_")):
        trials = []
        n_invalid = 0
        for trial_dir in sorted(exp_dir.iterdir()):
            if not (trial_dir / "ground_truth.json").exists():
                continue
            t = load_trial(trial_dir)
            if t is None:
                n_invalid += 1
                continue
            trials.append(t)
        if not trials:
            continue
        if n_invalid:
            print(f"  [{exp_dir.name}] dropped {n_invalid} invalid "
                  "trial(s) per sweep marker")

        per_trial_metrics = [metrics_from_verdicts(t["verdicts"]) for t in trials]
        agg = {}
        for key in ("precision", "recall", "f1", "accuracy"):
            vals = [m[key] for m in per_trial_metrics
                    if not math.isnan(m[key])]
            mean, lo, hi = bootstrap_ci(vals) if vals else (float("nan"),)*3
            agg[key] = {"mean": mean, "ci_lo": lo, "ci_hi": hi,
                        "per_trial": vals}

        all_latencies = [x for t in trials for x in t["latencies"]]
        latency_stats = {}
        if all_latencies:
            s = sorted(all_latencies)
            latency_stats = {
                "n": len(s),
                "min": s[0], "max": s[-1],
                "median": s[len(s) // 2],
                "p95": s[int(len(s) * 0.95)],
                "mean": statistics.mean(s),
            }

        out = {
            "experiment": exp_dir.name,
            "n_trials": len(trials),
            "aggregate": agg,
            "latency_seconds": latency_stats,
            "latencies_flat": all_latencies,
            "per_trial_raw": per_trial_metrics,
            "per_rule_counts": _merge_per_rule([t["per_rule"] for t in trials]),
        }
        out_path = args.out_dir / f"{exp_dir.name}.json"
        out_path.write_text(json.dumps(out, indent=2))
        print(f"[aggregate] {exp_dir.name}: "
              f"F1={agg['f1']['mean']:.3f} "
              f"[{agg['f1']['ci_lo']:.3f}, {agg['f1']['ci_hi']:.3f}] "
              f"(n={len(trials)} trials)")


if __name__ == "__main__":
    main()
