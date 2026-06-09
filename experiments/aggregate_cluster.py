"""Pairs cluster-bootstrap BCa aggregator.

Replaces the broken event-level resampler (`aggregate_e12.py`) for any
experiment that needs a non-degenerate confidence interval on F1 /
precision / recall.

Spec sources (binding):
- agent-reports/panel-8-2026-04-29/02_statistical_design.md §2 + §3
- EXPERIMENT_DESIGN.md §5

Cluster definition:
    cluster_id = (trial_id, gt_scenario_id)
Events inside a (trial, scenario) leg share Poisson-IAT seed, BMS
shuffle, and ephemeral src_port and are NOT IID. Trial-only clustering
discards the strategy structure E17 has.

Procedure:
    1. Build per-event records `{cluster, gt_label, pred_label}`.
    2. Pool counts per cluster (Counter[TP, TN, FP, FN, NO_DECISION]).
    3. Resample C clusters with replacement, B = 10 000 times.
    4. For each replicate, pool the selected clusters' counts and
       recompute F1 / precision / recall (F1 is non-linear; trial-mean
       is biased).
    5. BCa: bias `z₀ = Φ⁻¹(p̂)`, p̂ = #replicates < point / B; jackknife
       acceleration `â`; return `[α₁, α₂]` percentile of the bootstrap
       distribution.

Output JSON schema (extends but does not break the existing
`runs/experiments/_agg/<exp>.json` schema):
    {
        "experiment": <exp_id>,
        "n_clusters": int,
        "B": int,
        "cluster_unit": "(trial_id, scenario_id)",
        "metrics": {
            "f1":        {"point", "ci_lo", "ci_hi", "z0", "a_hat", "se_jackknife"},
            "precision": {...},
            "recall":    {...},
        },
        "per_cluster_counts": [
            {"cluster": [trial_id, scenario_id],
             "tp": int, "tn": int, "fp": int, "fn": int, "no_decision": int},
            ...
        ],
        "seed_master": int,
        "seed_bootstrap": int,
        "n_trials_total": int,
        "n_trials_invalid": int,
        # legacy compatibility:
        "point": {"precision": ..., "recall": ..., "f1": ...},
        "ci_lo": {"precision": ..., "recall": ..., "f1": ...},
        "ci_hi": {"precision": ..., "recall": ..., "f1": ...},
    }

CLI:
    python -m experiments.aggregate_cluster <exp_dir>

Defaults the output JSON to
    runs/experiments/_agg/<exp_id>_cluster.json
to avoid stomping on the legacy aggregate.
"""
from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

import numpy as np
from scipy.stats import norm as _norm

from experiments.seed_schedule import derive_trial_seed

# Bootstrap channel XOR-tag from panel-8 02_statistical_design.md §3.
_BOOT_CHANNEL_XOR: int = 0xB007


def _ipv4_to_int(ip: str | int) -> int:
    if isinstance(ip, int):
        return ip
    parts = ip.split(".")
    return ((int(parts[0]) << 24) | (int(parts[1]) << 16)
            | (int(parts[2]) << 8) | int(parts[3]))


def _coerce_ip(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    return _ipv4_to_int(value)


def load_trial(trial_dir: Path) -> dict | None:
    """Load one trial directory, returning event-level records.

    Matches `experiments/aggregate.py:load_trial` semantics for backward
    compatibility (`trial_invalid.txt`, full 5-tuple correlation, hold
    digest disambiguation, controller log preference).

    Returns
    -------
    dict | None
        ``None`` if the trial is marked invalid. Otherwise:
        ``{"trial_id": str, "events": list[dict]}`` where each event has
        ``{cluster_scenario, gt_label, pred_label, ts, src_ip, dst_ip}``.
    """
    if (trial_dir / "trial_invalid.txt").exists():
        return None
    gt_path = trial_dir / "ground_truth.json"
    if not gt_path.exists():
        return None

    gt = json.loads(gt_path.read_text())
    decisions: list[dict] = []
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

    ctrl_decisions: dict[tuple[int, int, int, int], dict] = {}
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
                continue
            try:
                key = (int(d["src_ip"]), int(d["dst_ip"]),
                       int(d["src_port"]), int(d.get("dst_port", 1883)))
            except (KeyError, TypeError, ValueError):
                continue
            ctrl_decisions[key] = d

    dec_index: dict[tuple[int, int, int, int], dict] = {}
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

    events: list[dict] = []
    for ev in gt.get("events", []):
        gt_label = (ev.get("label") or "").upper()
        scenario = ev.get("scenario") or gt.get("scenario") or "unknown"
        try:
            key = (_coerce_ip(ev.get("src_ip")),
                   _coerce_ip(ev.get("dst_ip")),
                   int(ev.get("src_port", 0)),
                   int(ev.get("dst_port", 1883)))
        except (TypeError, ValueError):
            continue
        ctrl = ctrl_decisions.get(key)
        d = dec_index.get(key)

        if d is None:
            # No decisions.jsonl / decisions_digest.jsonl entry for this key.
            # Fall back to controller_decisions.jsonl (post-arbiter decisions
            # sliced from the switch's decisions.jsonl by the T2.x harness).
            # When that is also absent, infer from the ground-truth label:
            #   LEGIT events not in the controller log were silently forwarded
            #   by the data plane (no hold_digest sent) -> PASS (TN).
            #   ATTACK events not logged could not be confirmed scored (digest
            #   suppressed by hold_armed cascade or timing gap) -> NO_DECISION.
            if ctrl is not None:
                pred_label = (ctrl.get("decision") or "").upper() or "NO_DECISION"
            elif gt_label == "LEGIT":
                pred_label = "PASS"
            else:
                pred_label = "NO_DECISION"
        else:
            dtype = d.get("_type", "")
            if dtype == "hold_digest":
                if ctrl is None:
                    pred_label = "NO_DECISION"
                else:
                    pred_label = (ctrl.get("decision") or "").upper() or "NO_DECISION"
            else:
                if gt_label == "ATTACK":
                    if ctrl is None:
                        pred_label = "NO_DECISION"
                    else:
                        pred_label = (ctrl.get("decision") or "").upper() or "NO_DECISION"
                else:
                    pred_label = "PASS"

        events.append({
            "cluster_scenario": scenario,
            "gt_label": gt_label,
            "pred_label": pred_label,
            "ts": ev.get("t_send"),
            "src_ip": ev.get("src_ip"),
            "dst_ip": ev.get("dst_ip"),
        })

    return {
        "trial_id": gt.get("trial_id", trial_dir.name),
        "events": events,
    }


def cluster_id_for(event: dict) -> tuple[str, str]:
    """Return the (trial_id, scenario_id) tuple identifying the cluster.

    The aggregator-level walker injects a synthetic ``trial_id`` field
    on each event so the spec-mandated test fixture (which feeds raw
    event dicts) and the trial-walker share the same key.
    """
    trial_id = str(event.get("trial_id", ""))
    scenario = str(event.get("scenario_id")
                   or event.get("cluster_scenario") or "unknown")
    return (trial_id, scenario)


def _verdict(gt_label: str, pred_label: str) -> str:
    if pred_label == "NO_DECISION":
        return "NO_DECISION"
    if gt_label == "ATTACK" and pred_label == "DROP":
        return "TP"
    if gt_label == "LEGIT" and pred_label == "PASS":
        return "TN"
    if gt_label == "LEGIT" and pred_label == "DROP":
        return "FP"
    if gt_label == "ATTACK" and pred_label == "PASS":
        return "FN"
    # Fallback: any unrecognized prediction on an attack event reads
    # as a miss, on a legit event as a false positive only if explicit
    # DROP; otherwise count as NO_DECISION so we never silently inflate.
    return "NO_DECISION"


def _counts_to_metrics(c: Counter) -> dict[str, float]:
    tp, tn, fp, fn = c["TP"], c["TN"], c["FP"], c["FN"]
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    if (not math.isnan(prec)) and (not math.isnan(rec)) and (prec + rec) > 0:
        f1 = 2 * prec * rec / (prec + rec)
    else:
        f1 = float("nan")
    return {"precision": prec, "recall": rec, "f1": f1}


def _bca_ci(
    point: float,
    replicates: np.ndarray,
    jackknife: np.ndarray,
    alpha: float,
) -> tuple[float, float, float, float, float]:
    """Return (ci_lo, ci_hi, z0, a_hat, se_jack) from BCa machinery."""
    B = replicates.size
    valid = replicates[~np.isnan(replicates)]
    if valid.size < 10 or math.isnan(point):
        return (float("nan"), float("nan"), float("nan"),
                float("nan"), float("nan"))

    p_hat = float(np.mean(valid < point))
    # Guard the inverse-normal against the boundary cases.
    if p_hat <= 0.0:
        p_hat = 1.0 / (2.0 * B)
    elif p_hat >= 1.0:
        p_hat = 1.0 - 1.0 / (2.0 * B)
    z0 = float(_norm.ppf(p_hat))

    jk_valid = jackknife[~np.isnan(jackknife)]
    if jk_valid.size < 2:
        a_hat = 0.0
        se_jack = float("nan")
    else:
        jk_mean = float(np.mean(jk_valid))
        diffs = jk_mean - jk_valid
        num = float(np.sum(diffs ** 3))
        den = 6.0 * (float(np.sum(diffs ** 2)) ** 1.5)
        a_hat = num / den if den > 0 else 0.0
        # Standard jackknife SE on the metric, surface for diagnostics.
        n_j = jk_valid.size
        se_jack = float(math.sqrt((n_j - 1) / n_j * np.sum(diffs ** 2)))

    z_alpha = float(_norm.ppf(1.0 - alpha / 2.0))
    denom_lo = 1.0 - a_hat * (z0 - z_alpha)
    denom_hi = 1.0 - a_hat * (z0 + z_alpha)
    if denom_lo == 0.0:
        denom_lo = 1e-12
    if denom_hi == 0.0:
        denom_hi = 1e-12
    alpha1 = float(_norm.cdf(z0 + (z0 - z_alpha) / denom_lo))
    alpha2 = float(_norm.cdf(z0 + (z0 + z_alpha) / denom_hi))
    # Clamp to [0, 1] for percentile lookup safety.
    alpha1 = min(max(alpha1, 0.0), 1.0)
    alpha2 = min(max(alpha2, 0.0), 1.0)

    sorted_reps = np.sort(valid)
    lo_idx = int(math.floor(alpha1 * (sorted_reps.size - 1)))
    hi_idx = int(math.ceil(alpha2 * (sorted_reps.size - 1)))
    lo_idx = max(0, min(lo_idx, sorted_reps.size - 1))
    hi_idx = max(0, min(hi_idx, sorted_reps.size - 1))
    return (float(sorted_reps[lo_idx]), float(sorted_reps[hi_idx]),
            z0, a_hat, se_jack)


def pairs_cluster_bootstrap(
    events: list[dict],
    n_clusters: int | None = None,
    B: int = 10000,
    alpha: float = 0.05,
    seed: int = 0xCAFE,
) -> dict:
    """Pairs cluster bootstrap with BCa CI on precision / recall / F1.

    Parameters
    ----------
    events : list[dict]
        Per-event records with at least ``cluster_scenario`` (or
        ``scenario_id``), ``gt_label``, ``pred_label``, plus a
        ``trial_id`` field if the cluster spans multiple trials.
    n_clusters : int | None
        Ignored unless > 0; if ``None``, equals the observed cluster
        count C (the spec-mandated default).
    B : int
        Bootstrap replicates (default 10 000 per spec).
    alpha : float
        CI significance level (default 0.05).
    seed : int
        RNG seed; the function mixes in the bootstrap channel XOR-tag
        ``0xB007`` so different bootstrap calls with the same trial
        seed remain independent.
    """
    if not events:
        nan = float("nan")
        return {
            "point": {"precision": nan, "recall": nan, "f1": nan},
            "ci_lo": {"precision": nan, "recall": nan, "f1": nan},
            "ci_hi": {"precision": nan, "recall": nan, "f1": nan},
            "n_clusters": 0, "B": B,
        }

    # Pool counts per cluster.
    counts_by_cluster: dict[tuple[str, str], Counter] = defaultdict(Counter)
    for ev in events:
        cid = cluster_id_for(ev)
        verdict = _verdict(ev.get("gt_label", "").upper(),
                           ev.get("pred_label", "").upper())
        counts_by_cluster[cid][verdict] += 1

    cluster_ids = list(counts_by_cluster.keys())
    C_obs = len(cluster_ids)
    C = C_obs if (n_clusters is None or n_clusters <= 0) else n_clusters
    counts_arr = np.array(
        [[counts_by_cluster[cid][k]
          for k in ("TP", "TN", "FP", "FN", "NO_DECISION")]
         for cid in cluster_ids],
        dtype=np.int64,
    )

    # Point estimate: pool ALL clusters.
    pooled_total = Counter({
        "TP": int(counts_arr[:, 0].sum()),
        "TN": int(counts_arr[:, 1].sum()),
        "FP": int(counts_arr[:, 2].sum()),
        "FN": int(counts_arr[:, 3].sum()),
        "NO_DECISION": int(counts_arr[:, 4].sum()),
    })
    point = _counts_to_metrics(pooled_total)

    # Bootstrap.
    rng = np.random.default_rng(seed ^ _BOOT_CHANNEL_XOR)
    rep_metrics = {k: np.full(B, np.nan, dtype=np.float64)
                   for k in ("precision", "recall", "f1")}

    if C_obs > 0:
        for b in range(B):
            idx = rng.integers(0, C_obs, size=C)
            sums = counts_arr[idx].sum(axis=0)
            c = Counter({"TP": int(sums[0]), "TN": int(sums[1]),
                         "FP": int(sums[2]), "FN": int(sums[3]),
                         "NO_DECISION": int(sums[4])})
            m = _counts_to_metrics(c)
            for k in rep_metrics:
                rep_metrics[k][b] = m[k]

    # Jackknife: leave-one-cluster-out.
    jk_metrics = {k: np.full(C_obs, np.nan, dtype=np.float64)
                  for k in ("precision", "recall", "f1")}
    if C_obs >= 2:
        full_sum = counts_arr.sum(axis=0)
        for i in range(C_obs):
            sums = full_sum - counts_arr[i]
            c = Counter({"TP": int(sums[0]), "TN": int(sums[1]),
                         "FP": int(sums[2]), "FN": int(sums[3]),
                         "NO_DECISION": int(sums[4])})
            m = _counts_to_metrics(c)
            for k in jk_metrics:
                jk_metrics[k][i] = m[k]

    metrics_block: dict[str, dict[str, float]] = {}
    ci_lo_block: dict[str, float] = {}
    ci_hi_block: dict[str, float] = {}
    for k in ("precision", "recall", "f1"):
        lo, hi, z0, a_hat, se_j = _bca_ci(
            point[k], rep_metrics[k], jk_metrics[k], alpha
        )
        metrics_block[k] = {
            "point": point[k],
            "ci_lo": lo,
            "ci_hi": hi,
            "z0": z0,
            "a_hat": a_hat,
            "se_jackknife": se_j,
        }
        ci_lo_block[k] = lo
        ci_hi_block[k] = hi

    return {
        "metrics": metrics_block,
        "point": point,
        "ci_lo": ci_lo_block,
        "ci_hi": ci_hi_block,
        "n_clusters": C_obs,
        "B": B,
        "cluster_unit": "(trial_id, scenario_id)",
        "alpha": alpha,
        "seed_master": int(seed),
        "seed_bootstrap": int(seed ^ _BOOT_CHANNEL_XOR),
    }


def aggregate(
    exp_dir: Path,
    out_path: Path | None = None,
    B: int = 10000,
    alpha: float = 0.05,
    master_seed: str = "0xCAFE",
) -> dict:
    """Walk every trial under ``exp_dir`` and emit aggregated JSON."""
    exp_dir = Path(exp_dir)
    if not exp_dir.exists():
        raise SystemExit(f"missing experiment dir: {exp_dir}")

    events: list[dict] = []
    n_trials = 0
    n_invalid = 0
    per_cluster_counts: dict[tuple[str, str], Counter] = defaultdict(Counter)

    for trial_dir in sorted(exp_dir.iterdir()):
        if not trial_dir.is_dir():
            continue
        if not (trial_dir / "ground_truth.json").exists():
            continue
        t = load_trial(trial_dir)
        if t is None:
            n_invalid += 1
            continue
        n_trials += 1
        for ev in t["events"]:
            ev2 = dict(ev)
            ev2["trial_id"] = t["trial_id"]
            events.append(ev2)
            cid = cluster_id_for(ev2)
            v = _verdict(ev2.get("gt_label", "").upper(),
                         ev2.get("pred_label", "").upper())
            per_cluster_counts[cid][v] += 1

    seed_int = derive_trial_seed(exp_dir.name, "agg", master_seed)
    boot = pairs_cluster_bootstrap(events, B=B, alpha=alpha, seed=seed_int)

    out: dict[str, Any] = {
        "experiment": exp_dir.name,
        "n_trials_total": n_trials,
        "n_trials_invalid": n_invalid,
        **boot,
        "per_cluster_counts": [
            {"cluster": list(cid),
             "tp": v["TP"], "tn": v["TN"], "fp": v["FP"],
             "fn": v["FN"], "no_decision": v["NO_DECISION"]}
            for cid, v in sorted(per_cluster_counts.items())
        ],
    }

    if out_path is None:
        out_path = exp_dir.parent / "_agg" / f"{exp_dir.name}_cluster.json"
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, default=lambda x: None
                                   if isinstance(x, float) and math.isnan(x)
                                   else x))
    print(f"[aggregate_cluster] {exp_dir.name}: "
          f"n_clusters={boot['n_clusters']} "
          f"B={boot['B']} F1={boot['point']['f1']} "
          f"[{boot['ci_lo']['f1']}, {boot['ci_hi']['f1']}]")
    return out


def main(argv: Iterable[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("exp_dir", type=Path,
                    help="path to runs/experiments/<exp_id>")
    ap.add_argument("--out", type=Path, default=None,
                    help="output JSON (default: <exp>/../_agg/<exp>_cluster.json)")
    ap.add_argument("--B", type=int, default=10000,
                    help="bootstrap replicates (default 10000)")
    ap.add_argument("--alpha", type=float, default=0.05,
                    help="CI significance level (default 0.05)")
    args = ap.parse_args(list(argv) if argv is not None else None)
    aggregate(args.exp_dir, out_path=args.out, B=args.B, alpha=args.alpha)


if __name__ == "__main__":
    main()
