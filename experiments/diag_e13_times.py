"""Diagnose E13 stamp vs decision time alignment."""
import json
from datetime import datetime
from pathlib import Path

base = Path("/home/philip/OTA/ota_shield/runs/override_capacity")

print("=== stamps.jsonl ===")
for i, line in enumerate(open(base / "stamps.jsonl")):
    r = json.loads(line)
    print(f"#{i}  rate={r['rate_pps_target']:>4} pps  "
          f"t_start={datetime.utcfromtimestamp(r['t_start']).isoformat()}  "
          f"t_end={datetime.utcfromtimestamp(r['t_end']).isoformat()}  "
          f"sent={r['sent']}")

print()
print("=== decisions.jsonl PASS/DROP timestamps ===")
ts = []
for line in open(base / "decisions.jsonl"):
    try:
        r = json.loads(line)
    except json.JSONDecodeError:
        continue
    if r.get("decision") in ("PASS", "DROP"):
        ts.append(r["t"])
ts.sort()
print(f"{len(ts)} decisions total")
if ts:
    print(f"first decision: {datetime.utcfromtimestamp(ts[0]).isoformat()}")
    print(f"last decision:  {datetime.utcfromtimestamp(ts[-1]).isoformat()}")

print()
print("=== overlap check ===")
with open(base / "stamps.jsonl") as f:
    for i, line in enumerate(f):
        r = json.loads(line)
        in_win = sum(1 for t in ts
                      if r["t_start"] <= t <= r["t_end"] + 5)
        print(f"stamp #{i} rate={r['rate_pps_target']}: "
              f"decisions in [t_start, t_end+5] = {in_win}")
