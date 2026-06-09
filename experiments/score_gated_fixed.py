"""Emit paper-ready metrics for the two gated+RV-4 re-runs (E12, E19').

Reuses aggregate.load_trial so the 5-tuple correlation, NO_DECISION bucket,
and per-rule logic are identical to every other paper number. Adds the
strict/lenient recall split, first-contact (NO_DECISION) decomposition,
Wilson CIs on precision/recall, and a Clopper-Pearson 0-FP upper bound.
"""
from __future__ import annotations
import json, math
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))
import aggregate as agg

def wilson(k: int, n: int, z: float = 1.96):
    if n == 0:
        return (float("nan"), float("nan"), float("nan"))
    p = k / n
    d = 1 + z*z/n
    c = (p + z*z/(2*n)) / d
    h = z*math.sqrt(p*(1-p)/n + z*z/(4*n*n)) / d
    return (p, max(0.0, c-h), min(1.0, c+h))

def clopper_pearson_upper(k: int, n: int, alpha: float = 0.05):
    # upper one-sided bound for k failures in n trials (rule-of-three style)
    if k == 0:
        return 1 - (alpha) ** (1.0/n)
    from math import comb
    # bisection on Beta quantile via incomplete beta would be ideal; for k=0 the
    # closed form above suffices, which is our case.
    return float("nan")

def collect(runs_dir: Path):
    tp=fp=tn=fn=nd=0
    n_attack=n_legit=0
    per_rule = {}
    n_trials = 0
    lat = []
    for exp_dir in sorted(p for p in runs_dir.iterdir() if p.is_dir() and not p.name.startswith("_")):
        for trial_dir in sorted(exp_dir.iterdir()):
            if not (trial_dir / "ground_truth.json").exists():
                continue
            t = agg.load_trial(trial_dir)
            if t is None:
                continue
            n_trials += 1
            gt = json.loads((trial_dir / "ground_truth.json").read_text())
            for ev, verdict in zip(gt["events"], t["verdicts"]):
                label = ev.get("label")
                if label == "ATTACK": n_attack += 1
                elif label == "LEGIT": n_legit += 1
                if verdict == "TP": tp += 1
                elif verdict == "FP": fp += 1
                elif verdict == "TN": tn += 1
                elif verdict == "FN": fn += 1
                elif verdict == "NO_DECISION": nd += 1
            for combo, c in t["per_rule"].items():
                d = per_rule.setdefault(combo, {})
                for kk, vv in c.items():
                    d[kk] = d.get(kk, 0) + vv
            lat += t["latencies"]
    return dict(tp=tp,fp=fp,tn=tn,fn=fn,nd=nd,n_attack=n_attack,n_legit=n_legit,
                per_rule=per_rule,n_trials=n_trials,latencies=lat)

def metrics(c):
    tp,fp,fn,nd = c["tp"],c["fp"],c["fn"],c["nd"]
    out = dict(c); out.pop("latencies", None)
    prec = wilson(tp, tp+fp) if (tp+fp) else (float("nan"),)*3
    rec_len = wilson(tp, tp+fn) if (tp+fn) else (float("nan"),)*3   # lenient: ND excluded
    rec_str = wilson(tp, tp+fn+nd) if (tp+fn+nd) else (float("nan"),)*3  # strict: ND=miss
    out["precision"] = prec
    out["recall_lenient"] = rec_len
    out["recall_strict"] = rec_str
    if not math.isnan(prec[0]) and not math.isnan(rec_len[0]) and (prec[0]+rec_len[0])>0:
        out["f1_lenient"] = 2*prec[0]*rec_len[0]/(prec[0]+rec_len[0])
    out["first_contact_nd"] = nd
    out["total_missed"] = fn + nd
    if c["latencies"]:
        s = sorted(c["latencies"])
        out["latency_ms"] = dict(median=s[len(s)//2]*1e3, p95=s[int(len(s)*0.95)]*1e3, n=len(s))
    if fp == 0 and (c["n_legit"]>0):
        out["fp_upper_cp95"] = clopper_pearson_upper(0, c["n_legit"])
        out["n_benign_for_fp_bound"] = c["n_legit"]
    return out

for name, d in [("E19p", "runs/experiments/E19p_gated_fixed"),
                ("E12", "runs/experiments/E12_gated_fixed")]:
    c = collect(Path(d))
    m = metrics(c)
    outp = Path(d) / "_agg" / f"{name}_gated_metrics.json"
    outp.write_text(json.dumps(m, indent=2, default=str))
    print(f"=== {name} ===")
    print(json.dumps(m, indent=2, default=str))
