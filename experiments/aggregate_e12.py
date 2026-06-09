"""E12 post-processor — per-sub-scenario outcome breakdown.

E12 has only LEGIT events so precision/recall/F1 are undefined.
The useful metric is PASS / HOLD-only / DROP rates per sub-scenario
(staged, emergency, migration-src1, migration-src2, delayed).

Reads ground_truth.json (has per-event `scenario` label) and
controller_decisions.jsonl (has per-event PASS/DROP verdict + rules
fired) from each trial under runs/experiments/E12_benign_rollout/.
Writes a `scenario_outcomes` block into the E12 aggregate JSON.
"""
from __future__ import annotations
import argparse, json
from collections import defaultdict
from pathlib import Path


def load_gt(trial_dir: Path) -> list[dict]:
    p = trial_dir / "ground_truth.json"
    if not p.exists():
        return []
    data = json.loads(p.read_text())
    return data.get("events", [])


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


def int_to_ip(x: int) -> str:
    return ".".join(str((x >> (8 * (3 - i))) & 0xff) for i in range(4))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp-dir",
                    default="runs/experiments/E12_benign_rollout",
                    type=Path)
    ap.add_argument("--agg-json",
                    default="runs/experiments/_agg/E12_benign_rollout.json",
                    type=Path)
    args = ap.parse_args()

    if not args.exp_dir.exists():
        raise SystemExit(f"missing {args.exp_dir}")

    trials = sorted([p for p in args.exp_dir.iterdir() if p.is_dir()])
    agg: dict[str, dict[str, int]] = defaultdict(
        lambda: {"pass": 0, "hold_only": 0, "drop": 0, "no_decision": 0})

    for t in trials:
        gt = load_gt(t)
        decs = load_decisions(t)
        # index decisions by (src_ip, dst_ip, src_port) (dst_port=1883 always)
        by_key: dict[tuple[str, str, int], dict] = {}
        for d in decs:
            src = d.get("src_ip"); dst = d.get("dst_ip")
            sport = int(d.get("src_port", 0))
            if isinstance(src, int):
                src = int_to_ip(src)
            if isinstance(dst, int):
                dst = int_to_ip(dst)
            by_key[(src, dst, sport)] = d

        for ev in gt:
            scen = ev.get("scenario", "unknown")
            key = (ev.get("src_ip"), ev.get("dst_ip"),
                   int(ev.get("src_port", 0)))
            d = by_key.get(key)
            if d is None:
                # No digest reached the controller. For LEGIT events
                # this is the correct outcome — the data plane silently
                # PASSed the packet because no rule fired (e.g. first
                # 4 events of a wave are below R5's fanout threshold
                # with disjoint BMS ranges keeping R1 silent). Count as
                # "pass" rather than "no_decision" when the ground
                # truth is LEGIT, matching the operational semantics of
                # the digest-only-on-rule-fire pipeline.
                if (ev.get("label") or "").upper() == "LEGIT":
                    agg[scen]["pass"] += 1
                else:
                    agg[scen]["no_decision"] += 1
                continue
            dec = (d.get("decision") or "").upper()
            rules = d.get("rules_fired") or []
            if dec == "PASS":
                if rules:
                    # HOLD path cleared by RAT — still a PASS but we
                    # record HOLD-only as a distinct bucket for the
                    # PASS/HOLD/DROP stacked bar.
                    agg[scen]["hold_only"] += 1
                else:
                    agg[scen]["pass"] += 1
            elif dec == "DROP":
                agg[scen]["drop"] += 1
            else:
                agg[scen]["no_decision"] += 1

    # Load existing aggregate and merge
    if args.agg_json.exists():
        existing = json.loads(args.agg_json.read_text())
    else:
        existing = {}
    existing["scenario_outcomes"] = dict(agg)
    args.agg_json.write_text(json.dumps(existing, indent=2))

    for scen, counts in sorted(agg.items()):
        total = sum(counts.values())
        p = 100 * counts["pass"] / max(total, 1)
        h = 100 * counts["hold_only"] / max(total, 1)
        d = 100 * counts["drop"] / max(total, 1)
        nd = 100 * counts["no_decision"] / max(total, 1)
        print(f"{scen:32s} n={total:4d}  "
              f"PASS={p:5.1f}%  HOLD-only={h:5.1f}%  "
              f"DROP={d:5.1f}%  ND={nd:5.1f}%")
    print(f"\nWrote scenario_outcomes into {args.agg_json}")


if __name__ == "__main__":
    main()
