"""Tests for experiments/aggregate_cluster.py.

Uses a synthetic 3-cluster fixture with known F1 = 0.8 and verifies:
- point F1 within 0.01 of 0.8
- BCa CI is non-degenerate (lo < point < hi)
- per_cluster_counts schema is preserved
- determinism: same seed -> same CI bounds
"""
from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from experiments.aggregate_cluster import (
    aggregate,
    cluster_id_for,
    load_trial,
    pairs_cluster_bootstrap,
)


def _build_cluster_events(
    trial_id: str, scenario: str, tp: int, fp: int, fn: int, tn: int = 0
) -> list[dict]:
    """Build event records with known TP / FP / FN / TN counts."""
    out: list[dict] = []
    for _ in range(tp):
        out.append({"trial_id": trial_id, "cluster_scenario": scenario,
                    "gt_label": "ATTACK", "pred_label": "DROP"})
    for _ in range(fp):
        out.append({"trial_id": trial_id, "cluster_scenario": scenario,
                    "gt_label": "LEGIT", "pred_label": "DROP"})
    for _ in range(fn):
        out.append({"trial_id": trial_id, "cluster_scenario": scenario,
                    "gt_label": "ATTACK", "pred_label": "PASS"})
    for _ in range(tn):
        out.append({"trial_id": trial_id, "cluster_scenario": scenario,
                    "gt_label": "LEGIT", "pred_label": "PASS"})
    return out


def test_cluster_id_for_uses_trial_and_scenario() -> None:
    ev = {"trial_id": "t01", "cluster_scenario": "scen-A"}
    assert cluster_id_for(ev) == ("t01", "scen-A")


def test_pairs_cluster_bootstrap_known_f1() -> None:
    """Three clusters, each with TP=8 FP=2 FN=2 -> per-cluster F1 = 0.8.

    Pooled counts: TP=24 FP=6 FN=6 -> P=R=F1=0.8.
    """
    events: list[dict] = []
    for tid in ("t01", "t02", "t03"):
        events += _build_cluster_events(tid, "scen-X", tp=8, fp=2, fn=2)

    out = pairs_cluster_bootstrap(events, B=1000, alpha=0.05, seed=0xCAFE)
    assert out["n_clusters"] == 3
    assert out["B"] == 1000
    assert math.isclose(out["point"]["f1"], 0.8, abs_tol=0.01)
    assert math.isclose(out["point"]["precision"], 0.8, abs_tol=1e-9)
    assert math.isclose(out["point"]["recall"], 0.8, abs_tol=1e-9)


def test_pairs_cluster_bootstrap_ci_nondegenerate() -> None:
    """When clusters genuinely vary, BCa lo < point < hi."""
    events: list[dict] = []
    # Three clusters with f1 ranging 0.7..0.9 so the bootstrap distribution
    # is non-degenerate.
    events += _build_cluster_events("t01", "scen-X", tp=7, fp=3, fn=3)
    events += _build_cluster_events("t02", "scen-X", tp=8, fp=2, fn=2)
    events += _build_cluster_events("t03", "scen-X", tp=9, fp=1, fn=1)

    out = pairs_cluster_bootstrap(events, B=1000, alpha=0.05, seed=0xCAFE)
    f1 = out["point"]["f1"]
    lo = out["ci_lo"]["f1"]
    hi = out["ci_hi"]["f1"]
    assert not math.isnan(lo)
    assert not math.isnan(hi)
    assert 0.0 <= lo <= f1 + 1e-9
    assert f1 - 1e-9 <= hi <= 1.0
    # Sanity on width: 3 clusters with 0.7/0.8/0.9 should not collapse to 0.
    assert hi - lo > 0.0


def test_pairs_cluster_bootstrap_deterministic() -> None:
    events: list[dict] = []
    for tid in ("t01", "t02", "t03"):
        events += _build_cluster_events(tid, "scen-X", tp=8, fp=2, fn=2)
    a = pairs_cluster_bootstrap(events, B=500, seed=12345)
    b = pairs_cluster_bootstrap(events, B=500, seed=12345)
    assert a["ci_lo"]["f1"] == b["ci_lo"]["f1"]
    assert a["ci_hi"]["f1"] == b["ci_hi"]["f1"]


def test_pairs_cluster_bootstrap_empty() -> None:
    out = pairs_cluster_bootstrap([], B=10)
    assert out["n_clusters"] == 0
    assert math.isnan(out["point"]["f1"])


def _write_trial(
    trial_dir: Path, trial_id: str, scenario: str,
    tp: int, fp: int, fn: int,
) -> None:
    trial_dir.mkdir(parents=True, exist_ok=True)
    events: list[dict] = []
    decisions: list[dict] = []
    src_port = 40000

    def _ev(label: str, action: str) -> None:
        nonlocal src_port
        src_port += 1
        ev = {
            "label": label,
            "scenario": scenario,
            "src_ip": "10.0.1.1",
            "dst_ip": "10.0.2.2",
            "src_port": src_port,
            "dst_port": 1883,
            "t_send": float(src_port),
        }
        events.append(ev)
        decisions.append({
            "_type": "hold_digest",
            "src_ip": (10 << 24) | (0 << 16) | (1 << 8) | 1,
            "dst_ip": (10 << 24) | (0 << 16) | (2 << 8) | 2,
            "src_port": src_port,
            "dst_port": 1883,
            "_t_recv": float(src_port) + 0.01,
        })

    for _ in range(tp):
        _ev("ATTACK", "DROP")
    for _ in range(fp):
        _ev("LEGIT", "DROP")
    for _ in range(fn):
        _ev("ATTACK", "PASS")

    (trial_dir / "ground_truth.json").write_text(
        json.dumps({"trial_id": trial_id, "events": events})
    )
    with (trial_dir / "decisions.jsonl").open("w") as f:
        for d in decisions:
            f.write(json.dumps(d) + "\n")
    # Mirror the controller decision log so load_trial trusts the verdict.
    with (trial_dir / "controller_decisions.jsonl").open("w") as f:
        for ev, d in zip(events, decisions):
            decision = "DROP" if (
                (ev["label"] == "ATTACK" and ev in events[:tp])
                or (ev["label"] == "LEGIT")
            ) else "PASS"
            f.write(json.dumps({
                "src_ip": d["src_ip"], "dst_ip": d["dst_ip"],
                "src_port": d["src_port"], "dst_port": d["dst_port"],
                "decision": decision,
                "rules_fired": ["R1"] if decision == "DROP" else [],
            }) + "\n")


def test_aggregate_walks_trials_and_writes_json(tmp_path: Path) -> None:
    """End-to-end: build 3 trial dirs, run aggregate, check the JSON."""
    exp_dir = tmp_path / "TX_synth"
    for i, tid in enumerate(("t01", "t02", "t03"), start=1):
        # Each trial == one cluster (scenario fixed) with TP=8 FP=2 FN=2.
        _write_trial(exp_dir / tid, tid, "scen-X", tp=8, fp=2, fn=2)

    # Force a cheaper B so the test stays under 1 s.
    out_path = tmp_path / "agg.json"
    out = aggregate(exp_dir, out_path=out_path, B=500)
    assert out_path.exists()
    blob = json.loads(out_path.read_text())
    assert blob["experiment"] == "TX_synth"
    assert blob["n_trials_total"] == 3
    assert blob["n_clusters"] == 3
    # F1 within 0.01 of 0.8.
    assert math.isclose(blob["point"]["f1"], 0.8, abs_tol=0.01)
    # per_cluster_counts schema check.
    assert isinstance(blob["per_cluster_counts"], list)
    assert len(blob["per_cluster_counts"]) == 3
    sample = blob["per_cluster_counts"][0]
    for k in ("cluster", "tp", "tn", "fp", "fn", "no_decision"):
        assert k in sample


def test_load_trial_skips_invalid_marker(tmp_path: Path) -> None:
    trial_dir = tmp_path / "t01"
    trial_dir.mkdir()
    (trial_dir / "trial_invalid.txt").write_text("test")
    (trial_dir / "ground_truth.json").write_text(
        json.dumps({"trial_id": "t01", "events": []})
    )
    assert load_trial(trial_dir) is None
