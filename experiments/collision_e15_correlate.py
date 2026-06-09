"""E15 post-processor — count distinct 5-tuple collisions per N.

Reads the controller's classify/mqtt digests (which carry a
session_idx per packet) and, for each sweep window, counts how many
distinct 5-tuples landed on the same 16-bit session index.

Collision rate = (N - distinct_session_idx) / N.
"""
from __future__ import annotations
import argparse, json
from pathlib import Path
from collections import defaultdict


def load_jsonl(p: Path) -> list[dict]:
    out = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stamps",
                    default="runs/collision/stamps.jsonl", type=Path)
    ap.add_argument("--digests",
                    default="runs/collision/phase6_digests.jsonl",
                    type=Path)
    ap.add_argument("--out-csv",
                    default="runs/collision/results.csv", type=Path)
    args = ap.parse_args()

    stamps = load_jsonl(args.stamps)
    digs = load_jsonl(args.digests)

    rows = ["n,sent,observed,distinct_session_idx,collisions,collision_rate"]
    for w in stamps:
        t0, t1 = float(w["t_start"]), float(w["t_end"])
        in_win = [d for d in digs
                  if t0 - 0.5 <= float(d.get("_t_recv",
                                              d.get("t", 0))) <= t1 + 1.0]
        session_idx_seen: set[int] = set()
        for d in in_win:
            if d.get("_type") not in ("classify_digest", None):
                continue
            # Field is named session_id in P4; accept legacy session_idx too.
            idx = d.get("session_id", d.get("session_idx"))
            if idx is not None:
                session_idx_seen.add(int(idx))
        sent = int(w["sent"])
        observed = len(in_win)
        distinct = len(session_idx_seen)
        collisions = max(0, observed - distinct)
        rate = collisions / observed if observed > 0 else 0.0
        rows.append(f"{w['n']},{sent},{observed},{distinct},"
                     f"{collisions},{rate:.4f}")
        print(f"N={w['n']:>5}  sent={sent:>5}  obs={observed:>5}  "
              f"distinct_idx={distinct:>5}  coll={collisions:>5}  "
              f"rate={rate*100:5.2f}%")

    args.out_csv.write_text("\n".join(rows) + "\n")
    print(f"Wrote {args.out_csv}")


if __name__ == "__main__":
    main()
