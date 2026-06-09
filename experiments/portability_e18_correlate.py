"""E18 post-processor — compare expected outcomes vs observed."""
from __future__ import annotations
import argparse, json
from pathlib import Path


def load_jsonl(p: Path) -> list[dict]:
    out = []
    if not p.exists():
        return out
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
    ap.add_argument("--digests",
                    default="runs/portability/phase6_digests.jsonl",
                    type=Path)
    ap.add_argument("--expected",
                    default="runs/portability/e18_results.csv",
                    type=Path)
    ap.add_argument("--window-start", type=float, default=0,
                    help="epoch seconds; filter digests after this")
    args = ap.parse_args()

    digs = load_jsonl(args.digests)
    # Filter to recent digests only
    if args.window_start > 0:
        digs = [d for d in digs if d.get("t", 0) >= args.window_start]

    # Index classify_digests by src_port
    by_port = {}
    for d in digs:
        if d.get("_type") in ("classify_digest", "mqtt_digest"):
            sp = int(d.get("src_port") or d.get("sport") or 0)
            by_port[sp] = d

    # Read expected CSV
    lines = args.expected.read_text().strip().splitlines()
    header = lines[0]
    print("=== E18 portability observations ===")
    print(f"{'variant':24s} {'sent_sport':>10s} "
          f"{'has_ota':>7s} {'expected':>12s} {'verdict':>10s}")
    sport = 45000
    for ln in lines[1:]:
        parts = ln.split(",")
        name, tlen, qos, retain, expected = parts[:5]
        d = by_port.get(sport)
        if d is None:
            obs = "DROPPED"
        else:
            has_ota = int(d.get("has_ota_hdr", 0))
            obs = "PARSED" if has_ota else "PARSER_MISS"
        verdict = "OK" if obs == expected else "DIFF"
        print(f"{name:24s} {sport:>10d} "
              f"{obs:>7s} {expected:>12s} {verdict:>10s}")
        sport += 1


if __name__ == "__main__":
    main()
