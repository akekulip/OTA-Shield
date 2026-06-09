"""Unit tests for `experiments.reconcile_decisions`.

Synthetic 5 GT events × 4 decisions, hand-computed expected outcomes
per the table in panel-8 §4.

Layout (per-event):
    e0 LEGIT      — matched PASS  -> TN
    e1 LEGIT      — matched DROP  -> FP
    e2 LEGIT      — no decision   -> TN  (silent pass)
    e3 ATTACK_R5  — matched DROP  -> TP
    e4 ATTACK_R5  — no decision   -> FN

Plus one orphan decision with no GT match -> FP.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments import reconcile_decisions as rd


def _make_trial_dir(tmp_path: Path) -> Path:
    trial = tmp_path / "trial"
    trial.mkdir()

    # 5 GT events. Timestamps in seconds; we keep them well outside the
    # default 100 ms window where we want "no match".
    gt = {
        "trial_id": "test_t00",
        "events": [
            {"t_send": 1000.000, "src_ip": "10.0.1.10", "dst_ip": "10.0.2.10",
             "src_port": 60000, "dst_port": 1883, "label": "LEGIT",
             "scenario": "test"},
            {"t_send": 1001.000, "src_ip": "10.0.1.10", "dst_ip": "10.0.2.11",
             "src_port": 60001, "dst_port": 1883, "label": "LEGIT",
             "scenario": "test"},
            {"t_send": 1002.000, "src_ip": "10.0.1.10", "dst_ip": "10.0.2.12",
             "src_port": 60002, "dst_port": 1883, "label": "LEGIT",
             "scenario": "test"},
            {"t_send": 1003.000, "src_ip": "10.0.1.99", "dst_ip": "10.0.2.13",
             "src_port": 60003, "dst_port": 1883, "label": "ATTACK_R5",
             "scenario": "test"},
            {"t_send": 1004.000, "src_ip": "10.0.1.99", "dst_ip": "10.0.2.14",
             "src_port": 60004, "dst_port": 1883, "label": "ATTACK_R5",
             "scenario": "test"},
        ],
    }
    (trial / "ground_truth.json").write_text(json.dumps(gt))

    # 4 decisions: e0, e1, e3 inside window; one orphan.
    def ip_int(s: str) -> int:
        a, b, c, d = (int(x) for x in s.split("."))
        return (a << 24) | (b << 16) | (c << 8) | d

    decisions = [
        {"t": 1000.010, "src_ip": ip_int("10.0.1.10"),
         "dst_ip": ip_int("10.0.2.10"), "src_port": 60000, "dst_port": 1883,
         "decision": "PASS", "rules_fired": [],
         "pipeline_action_code": 1, "reason": "rat_match"},
        {"t": 1001.005, "src_ip": ip_int("10.0.1.10"),
         "dst_ip": ip_int("10.0.2.11"), "src_port": 60001, "dst_port": 1883,
         "decision": "DROP", "rules_fired": ["R5"],
         "pipeline_action_code": 2, "reason": "spurious_drop"},
        {"t": 1003.020, "src_ip": ip_int("10.0.1.99"),
         "dst_ip": ip_int("10.0.2.13"), "src_port": 60003, "dst_port": 1883,
         "decision": "DROP", "rules_fired": ["R5"],
         "pipeline_action_code": 2, "reason": "rat_block"},
        # Orphan: no GT event matches this 5-tuple at all.
        {"t": 9999.000, "src_ip": ip_int("10.0.1.50"),
         "dst_ip": ip_int("10.0.2.99"), "src_port": 61000, "dst_port": 1883,
         "decision": "DROP", "rules_fired": ["R5"],
         "pipeline_action_code": 2, "reason": "rat_block"},
    ]
    with (trial / "decisions.jsonl").open("w") as f:
        for d in decisions:
            f.write(json.dumps(d) + "\n")
    return trial


def test_reconcile_synthetic(tmp_path: Path) -> None:
    trial = _make_trial_dir(tmp_path)
    gt = rd.load_ground_truth(trial)
    dec = rd.load_decisions(trial)
    assert len(gt) == 5
    assert len(dec) == 4

    rows = rd.reconcile(gt, dec, ts_window_ms=100.0)
    # 5 GT rows + 1 orphan row = 6 rows total.
    assert len(rows) == 6

    outcomes_by_label = [(r["gt_label"], r["outcome"]) for r in rows]
    assert outcomes_by_label[0] == ("LEGIT", "TN")
    assert outcomes_by_label[1] == ("LEGIT", "FP")
    assert outcomes_by_label[2] == ("LEGIT", "TN")  # silent pass
    assert outcomes_by_label[3] == ("ATTACK_R5", "TP")
    assert outcomes_by_label[4] == ("ATTACK_R5", "FN")
    assert outcomes_by_label[5] == ("UNMATCHED", "FP")

    counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "ND": 0}
    for r in rows:
        counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
    assert counts == {"TP": 1, "FP": 2, "TN": 2, "FN": 1, "ND": 0}


def test_reconcile_writes_jsonl(tmp_path: Path) -> None:
    trial = _make_trial_dir(tmp_path)
    out = rd.reconcile_trial(trial)
    assert out.exists()
    lines = out.read_text().splitlines()
    assert len(lines) == 6
    for line in lines:
        rec = json.loads(line)
        assert rec["outcome"] in {"TP", "FP", "TN", "FN", "ND"}


def test_match_5tuple_window() -> None:
    gt = {"ts": 1000.0, "src_ip": 1, "dst_ip": 2, "src_port": 3, "dst_port": 4}
    dec_in = {"ts": 1000.05, "src_ip": 1, "dst_ip": 2, "src_port": 3, "dst_port": 4}
    dec_out = {"ts": 1000.5, "src_ip": 1, "dst_ip": 2, "src_port": 3, "dst_port": 4}
    dec_wrong_tuple = {"ts": 1000.0, "src_ip": 9, "dst_ip": 2, "src_port": 3,
                       "dst_port": 4}
    assert rd.match_5tuple(gt, dec_in, ts_window_ms=100.0)
    assert not rd.match_5tuple(gt, dec_out, ts_window_ms=100.0)
    assert not rd.match_5tuple(gt, dec_wrong_tuple, ts_window_ms=100.0)


def test_broker_relay_label_excluded(tmp_path: Path) -> None:
    trial = tmp_path / "broker"
    trial.mkdir()
    (trial / "ground_truth.json").write_text(json.dumps({
        "events": [
            {"t_send": 1.0, "src_ip": "10.0.1.50", "dst_ip": "10.0.2.10",
             "src_port": 1883, "dst_port": 1883, "label": "BROKER_RELAY",
             "scenario": "broker"},
        ],
    }))
    (trial / "decisions.jsonl").write_text("")
    rows = rd.reconcile(rd.load_ground_truth(trial), rd.load_decisions(trial))
    assert len(rows) == 1
    assert rows[0]["outcome"] == "ND"


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
