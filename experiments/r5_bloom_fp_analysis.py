"""T2.7 — closed-form Bloom-filter FP analysis for R5 fanout detection.

The R5 detector (fleet_monitor.p4) uses three independent Bloom filters
of size m bits each, indexed by independent CRC-style hashes h0, h1, h2
of (dst_addr, salt). The 'duplicate-BMS' verdict is the AND of the three
test-and-set results — a packet is treated as a known BMS only when all
three BFs already had their corresponding bit set.

Standard analytical bound for the per-BF false-positive rate after n
distinct insertions into m bits with one hash function each:

    p_individual(n; m) = 1 - exp(-n / m)

(uniform-random hashing assumption; conservative for CRC-class hashes
when m and salts are well-chosen).

The R5 logic emits `r5_all_hit = 1` only when all three BFs report a
hit, so the FP probability for treating a NEW BMS as a duplicate is

    p_all_three(n; m) = (1 - exp(-n / m))^3

This is the per-packet false-negative-on-fanout rate (treating a new
BMS as duplicate, suppressing the count update). The resulting effect
on R5 detection is bounded above by p_all_three.

Falsifier (per MASTER_LEDGER §2 T2.7):
    Post-resize FP rate at n=500 still > 0.5%.

This script prints the analytical table (m=1024 vs m=4096, n in {50, 100,
200, 250, 500, 1000}) and emits a CSV the paper can reuse.
"""
from __future__ import annotations

import csv
import math
from pathlib import Path

# Single-BF size variants (bits).
M_VARIANTS = [(1024, "current"), (4096, "proposed")]

# Fanout levels (distinct BMSes inserted into the 60s window).
N_LEVELS = [50, 100, 200, 250, 500, 1000]

# Falsifier threshold.
FALSIFIER_FP_AT_N = (500, 0.005)


def fp_individual(n: int, m: int) -> float:
    """Per-BF FP rate after n insertions into m bits."""
    return 1.0 - math.exp(-n / m)


def fp_all_three(n: int, m: int) -> float:
    """3-BF AND FP rate."""
    p = fp_individual(n, m)
    return p ** 3


def break_even(target_p: float, m: int) -> int:
    """Largest n for which fp_all_three(n; m) <= target_p."""
    p_individual_target = target_p ** (1 / 3)
    n_continuous = -m * math.log(1.0 - p_individual_target)
    return int(math.floor(n_continuous))


def main() -> None:
    rows: list[dict[str, float | int | str]] = []
    print(f"\nR5 Bloom-filter analytical FP rates")
    print(f"3 independent BFs of size m bits each; 'duplicate BMS' verdict")
    print(f"is the AND of all three test-and-set results.\n")
    header = (
        "    n |  m=1024  per-BF |  m=1024  3-BF AND |"
        "  m=4096  per-BF |  m=4096  3-BF AND"
    )
    print(header)
    print("-" * len(header))
    for n in N_LEVELS:
        out = [f"{n:5d} |"]
        for m, label in M_VARIANTS:
            pi = fp_individual(n, m)
            p3 = fp_all_three(n, m)
            out.append(f"  {pi*100:7.4f} %       |  {p3*100:8.5f} %      |")
            rows.append({
                "n": n, "m": m, "m_label": label,
                "fp_individual_pct": pi * 100,
                "fp_all_three_pct": p3 * 100,
            })
        # Trim trailing pipe per row.
        line = " ".join(out)
        print(line.rstrip("|").rstrip())

    print()
    for m, label in M_VARIANTS:
        n_ber, p_ber = FALSIFIER_FP_AT_N
        p = fp_all_three(n_ber, m)
        verdict = "PASS" if p <= p_ber else "FAIL"
        print(f"  Falsifier @ n={n_ber}, m={m:5d} ({label:8s}): "
              f"3-BF FP = {p*100:7.4f} %   "
              f"(target ≤ {p_ber*100:.2f} %)  ->  {verdict}")

    print()
    for target in (0.005, 0.01, 0.05):
        for m, label in M_VARIANTS:
            n_ok = break_even(target, m)
            print(f"  Largest n s.t. 3-BF FP ≤ {target*100:.2f}% "
                  f"with m={m:5d} ({label:8s}): n = {n_ok}")
        print()

    out_csv = Path(__file__).parent.parent / "runs/_agg/r5_bloom_fp.csv"
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"\nWrote {out_csv}")


if __name__ == "__main__":
    main()
