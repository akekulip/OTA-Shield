"""Diagnose E15 digest schema + time-window overlap."""
import json
from datetime import datetime
from pathlib import Path
from collections import Counter

base = Path("/home/philip/OTA/ota_shield/runs/collision")

print("=== stamps ===")
stamps = []
for line in open(base / "stamps.jsonl"):
    r = json.loads(line); stamps.append(r)
    print(f"N={r['n']:>5}  t_start={datetime.utcfromtimestamp(r['t_start']).isoformat()}  "
          f"t_end={datetime.utcfromtimestamp(r['t_end']).isoformat()}  "
          f"sport_start={r['sport_start']}")

print()
print("=== digest schema sample (first 3 records) ===")
n = 0
for line in open(base / "phase6_digests.jsonl"):
    try:
        r = json.loads(line)
    except:
        continue
    print(r)
    n += 1
    if n >= 3:
        break

print()
print("=== digest type distribution in last 60 s of file ===")
type_counter = Counter()
last_t = 0
for line in open(base / "phase6_digests.jsonl"):
    try:
        r = json.loads(line)
    except:
        continue
    t = float(r.get("t", 0))
    if t > last_t:
        last_t = t
for line in open(base / "phase6_digests.jsonl"):
    try:
        r = json.loads(line)
    except:
        continue
    t = float(r.get("t", 0))
    if t >= last_t - 60:
        tk = r.get("_type") or r.get("type") or r.get("kind") or "?"
        type_counter[tk] += 1
print(dict(type_counter))

print()
print("=== digests in each stamp window (any type) ===")
all_t = []
for line in open(base / "phase6_digests.jsonl"):
    try:
        r = json.loads(line)
    except:
        continue
    all_t.append((float(r.get("t", 0)), r))

for w in stamps:
    t0, t1 = w["t_start"], w["t_end"] + 1.0
    hits = [r for t, r in all_t if t0 <= t <= t1]
    print(f"N={w['n']:>5}  count={len(hits)}  sample keys: "
          f"{list(hits[0].keys()) if hits else 'none'}")
