"""T1 per-experiment minimal aggregator.

Routes by --exp:
  T1.5 -> bytes-leaked-per-HOLD-event (median, p95) from tcpdump pcap +
          decisions.jsonl.
  T1.6 -> R6-fired count on legitimate v_{n+1} after malicious v_BIG;
          report rate with Clopper-Pearson UB at alpha=0.05.
  T1.7 -> RESOURCE_EXHAUSTED reject count + cross-tuple authorization
          rate with Clopper-Pearson UB.

Writes runs/experiments/_agg/T1_<n>.json (single JSON per experiment).

CLI:
  python -m experiments.aggregate_t1 --exp T1.5 \\
      --exp-dir runs/experiments/T1_5/

The expected --exp-dir layout is the canonical
`runs/experiments/<exp_id>/<trial_id>/{ground_truth.jsonl,
decisions.jsonl, pcaps/<file>.pcap}` per Testbed §2.

Implementation notes:
  * Only stdlib + scapy are used (scapy is already required by the
    generators); no pandas / numpy beyond `statistics` so this stays
    cheap to run on the Vision host.
  * exact_bounds.clopper_pearson_upper handles the zero-event case.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterator

# Repo-local import so this script runs as `python -m experiments.aggregate_t1`.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from exact_bounds import clopper_pearson_upper  # noqa: E402


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _iter_jsonl(path: Path) -> Iterator[dict]:
    if not path.exists() or path.stat().st_size == 0:
        return
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _list_trials(exp_dir: Path) -> list[Path]:
    """Return per-trial directories, ignoring stage/_agg/_meta dirs."""
    if not exp_dir.exists():
        raise FileNotFoundError(f"exp-dir {exp_dir} does not exist")
    return sorted(p for p in exp_dir.iterdir()
                  if p.is_dir() and not p.name.startswith("_"))


# ---------------------------------------------------------------------------
# T1.5 — bytes leaked per HOLD event
# ---------------------------------------------------------------------------


def _bytes_per_hold_event(trial_dir: Path) -> list[int]:
    """Compute bytes-leaked-per-HOLD-event for one trial.

    Strategy: every HOLD record in decisions.jsonl marks an event boundary;
    we count IP-payload bytes seen on the PORT_HULK pcap from the HOLD
    record's ts up to (HOLD ts + 100 ms) attributed to the same 5-tuple.
    The pcap path conventions follow Testbed §2 (`pcaps/*.pcap`).
    """
    decisions_path = trial_dir / "decisions.jsonl"
    pcap_dir = trial_dir / "pcaps"
    pcaps = sorted(pcap_dir.glob("*.pcap")) if pcap_dir.exists() else []
    holds = [d for d in _iter_jsonl(decisions_path)
             if str(d.get("action") or d.get("decision") or "").upper()
             == "HOLD"]
    if not holds:
        return []
    if not pcaps:
        # No pcap captured — treat as missing instrument; aggregator
        # surfaces it via a `missing_pcap_trials` counter.
        return []
    # Lazy scapy import — pcaps may not exist on every machine running
    # aggregate-only modes (e.g. CI smoke).
    from scapy.all import rdpcap, IP, TCP, Raw  # noqa: F401
    leaks: list[int] = []
    pkts = []
    for pcap in pcaps:
        try:
            pkts.extend(list(rdpcap(str(pcap))))
        except Exception:
            continue
    for ev in holds:
        try:
            t0 = float(ev.get("ts") or ev.get("timestamp") or 0.0)
        except (TypeError, ValueError):
            continue
        win_lo, win_hi = t0, t0 + 0.100
        ev_5tuple = (ev.get("src_ip"), ev.get("dst_ip"),
                     ev.get("src_port"), ev.get("dst_port"))
        leak = 0
        for p in pkts:
            try:
                pt = float(p.time)
            except Exception:
                continue
            if pt < win_lo or pt > win_hi:
                continue
            if not p.haslayer(IP) or not p.haslayer(TCP):
                continue
            ip = p[IP]
            tcp = p[TCP]
            tup = (ip.src, ip.dst, int(tcp.sport), int(tcp.dport))
            if ev_5tuple[0] is not None and tup != ev_5tuple:
                continue
            if p.haslayer(Raw):
                leak += len(bytes(p[Raw].load))
        leaks.append(leak)
    return leaks


def _aggregate_t1_5(exp_dir: Path) -> dict:
    trial_dirs = _list_trials(exp_dir)
    per_trial: list[dict] = []
    all_leaks: list[int] = []
    missing_pcap = 0
    zero_leak_events = 0
    total_events = 0
    for td in trial_dirs:
        leaks = _bytes_per_hold_event(td)
        if not leaks and not (td / "pcaps").exists():
            missing_pcap += 1
        per_trial.append({
            "trial": td.name,
            "n_hold_events": len(leaks),
            "median_bytes": (statistics.median(leaks) if leaks else None),
            "p95_bytes": (
                statistics.quantiles(leaks, n=20)[-1]
                if len(leaks) >= 2 else
                (leaks[0] if len(leaks) == 1 else None)
            ),
            "max_bytes": max(leaks) if leaks else None,
        })
        all_leaks.extend(leaks)
        zero_leak_events += sum(1 for x in leaks if x == 0)
        total_events += len(leaks)
    summary: dict = {
        "experiment_id": "T1.5",
        "metric": "bytes_leaked_per_hold_event",
        "n_trials": len(trial_dirs),
        "total_hold_events": total_events,
        "missing_pcap_trials": missing_pcap,
    }
    if all_leaks:
        summary["median_bytes_overall"] = statistics.median(all_leaks)
        summary["mean_bytes_overall"] = statistics.fmean(all_leaks)
        summary["max_bytes_overall"] = max(all_leaks)
        summary["p95_bytes_overall"] = (
            statistics.quantiles(all_leaks, n=20)[-1]
            if len(all_leaks) >= 2 else all_leaks[0]
        )
        if total_events > 0:
            non_zero = total_events - zero_leak_events
            # CP UB on the *non-zero leak* rate (the "fail" event).
            summary["nonzero_leak_rate"] = non_zero / total_events
            summary["cp_ub_nonzero_leak_rate_a05"] = clopper_pearson_upper(
                non_zero, total_events, alpha=0.05)
    summary["per_trial"] = per_trial
    return summary


# ---------------------------------------------------------------------------
# T1.6 — R6 false-rollback rate
# ---------------------------------------------------------------------------


def _trial_t1_6(trial_dir: Path) -> dict:
    gt_path = trial_dir / "ground_truth.jsonl"
    dec_path = trial_dir / "decisions.jsonl"
    gt_records = list(_iter_jsonl(gt_path))
    legits = [g for g in gt_records if g.get("gt_label") == "LEGIT"]
    poison_count = sum(1 for g in gt_records
                       if g.get("gt_label") == "ATTACK_R6_POISON")
    # Index decisions by 5-tuple (ts proximity is brittle for a single
    # trial; we rely on src+dst+sport since all sport values differ
    # per gt record).
    dec_by_key: dict[tuple, list[dict]] = defaultdict(list)
    for d in _iter_jsonl(dec_path):
        key = (d.get("src_ip"), d.get("dst_ip"),
               d.get("src_port"), d.get("dst_port"))
        dec_by_key[key].append(d)
    false_rollback = 0
    matched = 0
    for g in legits:
        key = (g.get("src_ip"), g.get("dst_ip"),
               g.get("src_port"), g.get("dst_port"))
        decs = dec_by_key.get(key, [])
        if not decs:
            continue
        matched += 1
        # Any decision flagged with R6 fire on a LEGIT event = false rollback.
        for d in decs:
            reasons = str(d.get("reason", "")).lower()
            rules_fired = d.get("rules_fired") or d.get("rules") or []
            rules_fired = [str(r).lower() for r in rules_fired]
            r6_fired = (
                "r6" in rules_fired or
                "rollback" in reasons or
                d.get("r6_fired") is True or
                d.get("r6") == 1
            )
            if r6_fired:
                false_rollback += 1
                break
    trial_failed = false_rollback > 0
    return {
        "trial": trial_dir.name,
        "n_legit_events": len(legits),
        "n_poison_events": poison_count,
        "n_matched_legit_decisions": matched,
        "false_rollback_events": false_rollback,
        "trial_failed_r6_falsifier": trial_failed,
    }


def _aggregate_t1_6(exp_dir: Path) -> dict:
    trial_dirs = _list_trials(exp_dir)
    per_trial = [_trial_t1_6(td) for td in trial_dirs]
    n_trials = len(trial_dirs)
    failing_trials = sum(1 for t in per_trial
                         if t["trial_failed_r6_falsifier"])
    cp_ub = (clopper_pearson_upper(failing_trials, n_trials, alpha=0.05)
             if n_trials > 0 else None)
    return {
        "experiment_id": "T1.6",
        "metric": "r6_false_rollback_rate",
        "n_trials": n_trials,
        "failing_trials": failing_trials,
        "false_rollback_rate": (failing_trials / n_trials
                                if n_trials else None),
        "cp_ub_false_rollback_rate_a05": cp_ub,
        "per_trial": per_trial,
    }


# ---------------------------------------------------------------------------
# T1.7 — RESOURCE_EXHAUSTED + cross-tuple authorization rate
# ---------------------------------------------------------------------------


def _trial_t1_7(trial_dir: Path) -> dict:
    gt_path = trial_dir / "ground_truth.jsonl"
    dec_path = trial_dir / "decisions.jsonl"
    ctrl_log = trial_dir / "controller_decisions.jsonl"
    gt_records = list(_iter_jsonl(gt_path))
    n_alias = sum(1 for g in gt_records
                  if g.get("gt_label") == "LEGIT_BUT_NOT_AUTHORIZED")
    n_allow = sum(1 for g in gt_records if g.get("gt_label") == "LEGIT")
    # Index decisions by 5-tuple.
    dec_by_key: dict[tuple, list[dict]] = defaultdict(list)
    for src in (dec_path, ctrl_log):
        for d in _iter_jsonl(src):
            key = (d.get("src_ip"), d.get("dst_ip"),
                   d.get("src_port"), d.get("dst_port"))
            dec_by_key[key].append(d)
    # RESOURCE_EXHAUSTED: scan all decisions for the action / reason marker.
    rsx = 0
    for decs in dec_by_key.values():
        for d in decs:
            reason = str(d.get("reason") or "").upper()
            action = str(d.get("action") or d.get("decision") or "").upper()
            if "RESOURCE_EXHAUSTED" in reason or \
                    "RESOURCE_EXHAUSTED" in action:
                rsx += 1
    # Cross-tuple authorization: alias 5-tuple records authorized as ALLOW.
    cross_alias_allow = 0
    matched_alias = 0
    for g in gt_records:
        if g.get("gt_label") != "LEGIT_BUT_NOT_AUTHORIZED":
            continue
        key = (g.get("src_ip"), g.get("dst_ip"),
               g.get("src_port"), g.get("dst_port"))
        decs = dec_by_key.get(key, [])
        if not decs:
            continue
        matched_alias += 1
        for d in decs:
            action = str(d.get("action") or d.get("decision")
                          or "").upper()
            reason = str(d.get("reason") or "").lower()
            if action == "ALLOW" or "override_allow" in reason:
                cross_alias_allow += 1
                break
    return {
        "trial": trial_dir.name,
        "n_allow_5tuple": n_allow,
        "n_alias_5tuple": n_alias,
        "matched_alias_decisions": matched_alias,
        "resource_exhausted_count": rsx,
        "cross_tuple_authorizations": cross_alias_allow,
    }


def _aggregate_t1_7(exp_dir: Path) -> dict:
    trial_dirs = _list_trials(exp_dir)
    per_trial = [_trial_t1_7(td) for td in trial_dirs]
    total_rsx = sum(t["resource_exhausted_count"] for t in per_trial)
    total_alias = sum(t["matched_alias_decisions"] for t in per_trial)
    total_cross = sum(t["cross_tuple_authorizations"]
                      for t in per_trial)
    cp_ub_cross = (clopper_pearson_upper(total_cross, total_alias,
                                          alpha=0.05)
                   if total_alias > 0 else None)
    # RESOURCE_EXHAUSTED denominator is total alias attempts (pessimistic).
    cp_ub_rsx = (clopper_pearson_upper(total_rsx, total_alias, alpha=0.05)
                 if total_alias > 0 else None)
    return {
        "experiment_id": "T1.7",
        "metric": ["resource_exhausted_count",
                    "cross_tuple_authorization_rate"],
        "n_trials": len(trial_dirs),
        "total_resource_exhausted": total_rsx,
        "total_alias_attempts": total_alias,
        "total_cross_tuple_authorizations": total_cross,
        "cross_tuple_authorization_rate": (
            total_cross / total_alias if total_alias else None),
        "cp_ub_cross_tuple_a05": cp_ub_cross,
        "cp_ub_resource_exhausted_a05": cp_ub_rsx,
        "per_trial": per_trial,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


_DISPATCH = {
    "T1.5": _aggregate_t1_5,
    "T1.6": _aggregate_t1_6,
    "T1.7": _aggregate_t1_7,
}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="T1 minimal aggregator")
    ap.add_argument("--exp", required=True, choices=sorted(_DISPATCH))
    ap.add_argument("--exp-dir", required=True, type=Path)
    ap.add_argument("--out-dir", type=Path,
                    default=Path("runs/experiments/_agg"))
    args = ap.parse_args(argv)

    fn = _DISPATCH[args.exp]
    summary = fn(args.exp_dir)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.out_dir / f"{args.exp.replace('.', '_')}.json"
    out_path.write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    print(f"\n[aggregate_t1] wrote {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
