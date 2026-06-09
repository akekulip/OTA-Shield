"""E17 post-processor — per-strategy rule-fire breakdown with Wilson 95%
CIs on per-strategy detection rates (T3.5 input).

For each mimicry sub-scenario, count which rules fired on each event
and what the controller's final decision was. Emits per-strategy
detection rate (caught / n_events) with Wilson 95% CI; also emits the
Clopper-Pearson UB on the false-negative rate when caught == 0.
"""
from __future__ import annotations
import argparse, json, sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from exact_bounds import wilson_score_interval, clopper_pearson_upper


def load_gt(trial_dir: Path) -> list[dict]:
    p = trial_dir / "ground_truth.json"
    if not p.exists():
        return []
    return json.loads(p.read_text()).get("events", [])


def load_decisions(trial_dir: Path) -> list[dict]:
    for name in ("controller_decisions.jsonl", "decisions.jsonl"):
        p = trial_dir / name
        if p.exists():
            out = []
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


def int_to_ip(x) -> str:
    if isinstance(x, str):
        return x
    x = int(x)
    return ".".join(str((x >> (8 * (3 - i))) & 0xff) for i in range(4))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp-dir",
                    default="runs/experiments/E17_mimicry", type=Path)
    ap.add_argument("--agg-json",
                    default="runs/experiments/_agg/E17_mimicry.json",
                    type=Path)
    args = ap.parse_args()

    if not args.exp_dir.exists():
        raise SystemExit(f"missing {args.exp_dir}")
    trials = sorted(p for p in args.exp_dir.iterdir() if p.is_dir())

    # Per-strategy: count rule-fire counts and PASS/DROP verdicts
    by_strat: dict[str, dict] = defaultdict(
        lambda: {"n_events": 0, "r1_fired": 0, "r2_fired": 0,
                  "r4_fired": 0, "r5_fired": 0,
                  "caught": 0, "missed": 0})

    for t in trials:
        gt = load_gt(t)
        decs = load_decisions(t)
        dec_by_key = {}
        for d in decs:
            k = (int_to_ip(d.get("src_ip", 0)),
                 int_to_ip(d.get("dst_ip", 0)),
                 int(d.get("src_port", 0)))
            dec_by_key[k] = d

        for ev in gt:
            scen = ev["scenario"]
            by_strat[scen]["n_events"] += 1
            k = (ev["src_ip"], ev["dst_ip"], int(ev["src_port"]))
            dec = dec_by_key.get(k)
            if dec is None:
                by_strat[scen]["missed"] += 1
                continue
            rules = dec.get("rules_fired") or []
            decision = (dec.get("decision") or "").upper()
            for r, key in (("R1", "r1_fired"), ("R2", "r2_fired"),
                            ("R4", "r4_fired"), ("R5", "r5_fired")):
                if r in rules:
                    by_strat[scen][key] += 1
            if decision == "DROP":
                by_strat[scen]["caught"] += 1
            else:
                by_strat[scen]["missed"] += 1

    # Persist
    args.agg_json.parent.mkdir(parents=True, exist_ok=True)
    if args.agg_json.exists():
        existing = json.loads(args.agg_json.read_text())
    else:
        existing = {}
    existing["strategy_breakdown"] = dict(by_strat)
    args.agg_json.write_text(json.dumps(existing, indent=2))

    print(f"{'strategy':28s} {'N':>4} {'R1':>4} {'R2':>4} "
          f"{'R4':>4} {'R5':>4} {'caught':>7s} {'missed':>7s} "
          f"{'recall':>7s} {'CI95':>16s}")
    total_n = 0; total_caught = 0
    for scen, c in sorted(by_strat.items()):
        n = c["n_events"]; caught = c["caught"]
        total_n += n; total_caught += caught
        rec = caught / n if n > 0 else 0.0
        if n > 0:
            lo, hi = wilson_score_interval(caught, n)
            ci_str = f"[{lo*100:5.1f},{hi*100:5.1f}]"
        else:
            lo = hi = float("nan")
            ci_str = "[  N/A         ]"
        cp_ub_fn = (clopper_pearson_upper(n - caught, n) if n > 0
                    else float("nan"))
        print(f"{scen:28s} {n:>4} "
              f"{c['r1_fired']:>4} {c['r2_fired']:>4} "
              f"{c['r4_fired']:>4} {c['r5_fired']:>4} "
              f"{caught:>7d} {c['missed']:>7d} "
              f"{rec:>6.3f} {ci_str}")
        c["recall_on_attack"] = rec
        c["recall_ci95_lo"] = lo
        c["recall_ci95_hi"] = hi
        c["fn_rate_cp_ub"] = cp_ub_fn
    if total_n > 0:
        overall_recall = total_caught / total_n
        print(f"\nShaped-adversary recall (mimicry only): "
              f"{overall_recall:.3f} "
              f"({total_caught}/{total_n})")
        existing["shaped_recall_mimicry_only"] = overall_recall
        existing["shaped_n_events"]            = total_n
        existing["shaped_n_caught"]            = total_caught
        existing["strategy_breakdown"] = dict(by_strat)
        args.agg_json.write_text(json.dumps(existing, indent=2))
    print(f"\nWrote strategy_breakdown to {args.agg_json}")


if __name__ == "__main__":
    main()
