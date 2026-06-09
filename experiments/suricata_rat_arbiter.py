"""Suricata + RAT arbiter — honest apples-to-apples baseline (M7).

Addresses IJCIP reviewer concern M7: the §5 comparison as submitted
measured `Suricata alone` vs `OTA-Shield + RAT`, which is unfair because
only OTA-Shield got the benefit of RAT-based demotion of benign fires.
This script post-processes Suricata's `eve.json` alerts with the SAME
RAT arbitration logic the controller runs in-band, and emits a
decision log in the same shape as `runs/<trial>/decisions.jsonl` so
`experiments/aggregate*.py` can ingest it as an additional comparison
bar.

Usage
-----
    python3 experiments/suricata_rat_arbiter.py \\
        --eve    runs/baseline_suricata/eve.json \\
        --config controller/rat.json \\
        --out    runs/baseline_suricata/suricata_rat_decisions.json

Design
------
The RAT arbiter logic is reused verbatim from the controller via
`controller/rat_arbiter.py` (extracted pure-python module — see its
docstring for why the extraction was needed). We do NOT re-implement
Gate A / Gate B here.

Suricata alerts do not carry ota_size / ota_version / r1..r6. We
therefore treat every alert as a "HOLD" bucket (action_code=1,
r1..r6 = 0) and let Gate A (RAT coverage on src+dst+time) decide:
  - If the alert's 5-tuple falls inside an active authorized_rollouts
    entry -> decision = PASS  (reason="rat_match").
  - Otherwise                                         -> DROP (reason="rat_miss").

Payload-size gating is advisory here: Suricata's alert record does
not reliably expose the OTA object size (only per-packet dsize), so
by default we pass size=0 to the arbiter and rely on the configured
RAT size_range to either accept 0 (if the range starts at 0) or
reject it. `--assume-size` lets the caller supply a representative
size when the RAT's size_range excludes 0.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

# Make the project root importable when run from either the repo root
# or from experiments/. Matches the pattern used in other E-scripts.
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from controller.rat_arbiter import (  # noqa: E402  (sys.path mutation above)
    RatArbiter,
    ipv4_to_int,
    load_rat_entries,
)

_LOG = logging.getLogger("suricata_rat_arbiter")


def parse_suricata_ts(ts: str) -> float:
    """Suricata emits timestamps like '2026-04-18T20:30:11.123456+0000'
    (no colon in the zone). Python's fromisoformat rejects that prior
    to 3.11, so we normalize first."""
    s = ts.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # '+0000' -> '+00:00', '-0500' -> '-05:00'
    if len(s) >= 5 and s[-5] in "+-" and s[-3] != ":":
        s = s[:-2] + ":" + s[-2:]
    return datetime.fromisoformat(s).timestamp()


def iter_suricata_alerts(eve_path: Path):
    """Yield only records where event_type == 'alert'."""
    with eve_path.open() as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                _LOG.warning("eve.json line %d not JSON: %s", line_no, exc)
                continue
            if rec.get("event_type") == "alert":
                yield rec


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--eve", required=True, type=Path,
                    help="Path to Suricata eve.json")
    ap.add_argument("--config", required=True, type=Path,
                    help="RAT file (same schema as controller/rat.json)")
    ap.add_argument("--out", required=True, type=Path,
                    help="Where to write the post-arbitration decision log "
                         "(JSON Lines unless --json-array is given).")
    ap.add_argument("--json-array", action="store_true",
                    help="Emit a single JSON array instead of JSON Lines. "
                         "Easier to diff; harder to tail.")
    ap.add_argument("--assume-size", type=int, default=0,
                    help="ota_size to pass to the arbiter when eve.json "
                         "does not carry it (default 0). Useful when the "
                         "RAT's size_range excludes 0.")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if not args.eve.exists():
        _LOG.error("eve.json not found: %s", args.eve)
        return 2
    if not args.config.exists():
        _LOG.error("RAT config not found: %s", args.config)
        return 2

    entries = load_rat_entries(args.config)
    arbiter = RatArbiter(entries)

    decisions: list[dict] = []
    n_total = n_pass = n_drop = n_skipped = 0

    for rec in iter_suricata_alerts(args.eve):
        n_total += 1
        src_str = rec.get("src_ip")
        dst_str = rec.get("dest_ip")
        ts_str = rec.get("timestamp")
        alert = rec.get("alert", {}) or {}
        sid = alert.get("signature_id")
        sig = alert.get("signature")

        if not (src_str and dst_str and ts_str):
            _LOG.debug("skip alert with incomplete 5-tuple/ts: %s", rec)
            n_skipped += 1
            continue

        try:
            src = ipv4_to_int(src_str)
            dst = ipv4_to_int(dst_str)
            now = parse_suricata_ts(ts_str)
        except Exception as exc:  # noqa: BLE001
            _LOG.warning("skip un-parseable alert: %s (%s)", rec, exc)
            n_skipped += 1
            continue

        # Honest apples-to-apples: Suricata does not expose OTA-Shield's
        # r1..r6, so we feed the arbiter a bare HOLD record. Gate A then
        # demotes iff (src, dst, time, size) is inside an active rollout.
        decision, reason = arbiter.arbitrate(
            src, dst,
            ota_size=args.assume_size,
            ota_version=0,
            action_code=1,
            r1=0, r2=0, r4=0, r5=0, r6=0,
            now=now,
        )

        if decision == "PASS":
            n_pass += 1
        else:
            n_drop += 1

        decisions.append({
            # Controller decisions.jsonl field names (so aggregate*.py
            # can ingest without branching).
            "t": now,
            "src_ip": src,
            "dst_ip": dst,
            "src_port": int(rec.get("src_port", 0) or 0),
            "dst_port": int(rec.get("dest_port", 0) or 0),
            "decision": decision,
            "rules_fired": [],          # Suricata does not map to R1..R6
            "reason": reason,
            "pipeline_action_code": 1,  # synthetic: always HOLD-bucket
            "ota_size": args.assume_size,
            "ota_version": 0,
            # Suricata-specific provenance (extra fields are ignored by
            # the OTA-Shield aggregator's dict.get calls).
            "suricata_sid": sid,
            "suricata_signature": sig,
            "suricata_src_ip": src_str,
            "suricata_dst_ip": dst_str,
            "suricata_timestamp": ts_str,
        })

    args.out.parent.mkdir(parents=True, exist_ok=True)
    if args.json_array:
        args.out.write_text(json.dumps(decisions, indent=2))
    else:
        with args.out.open("w") as f:
            for d in decisions:
                f.write(json.dumps(d) + "\n")

    _LOG.info(
        "Suricata+RAT arbitration: %d alerts -> %d PASS, %d DROP, %d skipped. "
        "Wrote %s",
        n_total, n_pass, n_drop, n_skipped, args.out,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
