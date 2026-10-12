#!/usr/bin/env python3
"""robustness_v005.py [--family M] [--delta 0.05] [--pairs A-B,A-C...] LABEL=RESULTS_CSV [...]

Sensitivity of the admission conditions to the way the bound is computed
(protocol_review_v005.txt, section 7; protocol_review2_v005.txt, section 7).
For every candidate of every series:

  status   three outcomes of the comparison with the margin delta, one-sided
           95% Student bounds of the paired contrast d = X(D) - (1-delta)*X(P0):
             NON_INFERIOR    lower bound > 0  (the admission condition)
             LOSS_EXCEEDS    upper bound < 0  (a loss larger than delta is shown)
             INCONCLUSIVE    neither
  Bonf     the same lower bound at the level 0.05 / M, where M is the number
           of restricted candidates of the service (--family, default: the
           candidates of the file); shows whether the admission survives a
           correction for the number of candidates compared with P0
  boot     percentile bootstrap bounds of the mean contrast (5% and 95%),
           20000 resamples of blocks, fixed seed; does not assume normality
  min d    the smallest margin delta at which the lower Student bound is
           positive, percent
  cost     one-sided 95% upper bound of the increase of CPU time per
           operation, and the same bound at the level 0.05 / M

--pairs gives direct paired contrasts between two restricted candidates in the
same series, e.g. "P1c-P5,P1c-P6": the mean of X(A) - X(B) per block and its
two-sided 95% confidence interval. This compares the cost of two protecting
profiles measured in one randomized series (review remark 12), without going
through P0.

The selection rule uses only the Student bounds at the level of the protocol;
everything else here is reported next to them. Python 3 standard library only;
must be located next to audit_benchmark_csv_v005.py.
"""
import argparse
import math
import random
import statistics as st
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_benchmark_csv_v005 import bounds, read, t_quantile  # noqa: E402

SEED = 20261011
RESAMPLES = 20000


def bootstrap(values, rng):
    n = len(values)
    means = sorted(sum(rng.choices(values, k=n)) / n for _ in range(RESAMPLES))
    return means[int(0.05 * RESAMPLES)], means[int(0.95 * RESAMPLES) - 1]


def min_margin(base, cand, t_one):
    lo, hi = 0.0, 1.0
    for _ in range(60):
        mid = (lo + hi) / 2
        _, _, lower, _ = bounds([y - (1 - mid) * x for x, y in zip(base, cand)], t_one)
        if lower > 0:
            hi = mid
        else:
            lo = mid
    return 100 * hi


def main():
    ap = argparse.ArgumentParser(description="Sensitivity of the admission conditions")
    ap.add_argument("--family", type=int, default=0)
    ap.add_argument("--delta", type=float, default=0.05)
    ap.add_argument("--pairs", default="", help="direct paired contrasts, e.g. P1c-P5,P1c-P6")
    ap.add_argument("series", nargs="+", metavar="LABEL=RESULTS_CSV")
    args = ap.parse_args()
    pairs = [tuple(p.split("-", 1)) for p in args.pairs.split(",") if "-" in p]

    for item in args.series:
        label, _, path = item.partition("=")
        _, blocks, col, _ = read(Path(path))
        numbers = sorted(blocks)
        profiles = sorted(set.intersection(*(set(blocks[b]) for b in numbers)) - {"P0"})
        n = len(numbers)
        family = args.family or len(profiles)
        t_one = t_quantile(0.95, n - 1)
        t_bonf = t_quantile(1 - 0.05 / family, n - 1)
        base = [blocks[b]["P0"]["value"] for b in numbers]
        rng = random.Random(SEED)
        print("=" * 118)
        print(f"SERIES {label}: {n} blocks, {col}, margin {100 * args.delta:g} %, family of {family} candidates, "
              f"mean P0 {st.mean(base):.1f}")
        print(f"  {'cand':<5}{'ratio':>7}{'mean d':>10}{'L95':>10}{'U95':>10}  {'status':<13}"
              f"{'Bonf L':>10} {'Bonf':<13}{'boot L':>10}{'boot U':>10}{'min d,%':>9}"
              f"{'cost':>8}{'cost U95':>10}{'cost Bonf':>11}")
        for p in profiles:
            cand = [blocks[b][p]["value"] for b in numbers]
            d = [y - (1 - args.delta) * x for x, y in zip(base, cand)]
            mean, _, lower, upper = bounds(d, t_one)
            _, _, lower_b, _ = bounds(d, t_bonf)
            status = "NON_INFERIOR" if lower > 0 else "LOSS_EXCEEDS" if upper < 0 else "INCONCLUSIVE"
            status_b = "NON_INFERIOR" if lower_b > 0 else "not shown"
            boot_l, boot_u = bootstrap(d, rng)
            logs = [math.log(blocks[b][p]["cost"] / blocks[b]["P0"]["cost"]) for b in numbers]
            cm, _, _, cu = bounds(logs, t_one)
            _, _, _, cu_b = bounds(logs, t_bonf)
            pct = lambda x: 100 * (math.exp(x) - 1)
            print(f"  {p:<5}{100 * st.mean(cand) / st.mean(base):>6.1f}%{mean:>10.1f}{lower:>10.1f}{upper:>10.1f}  "
                  f"{status:<13}{lower_b:>10.1f} {status_b:<13}{boot_l:>10.1f}{boot_u:>10.1f}"
                  f"{min_margin(base, cand, t_one):>9.1f}{pct(cm):>+7.1f}%{pct(cu):>+9.1f}%{pct(cu_b):>+10.1f}%")
        present = [(a, b) for a, b in pairs if a in profiles and b in profiles]
        if present:
            t_two = t_quantile(0.975, n - 1)
            print("  direct paired contrasts between protecting profiles (A - B per block):")
            for a, b in present:
                va = [blocks[k][a]["value"] for k in numbers]
                vb = [blocks[k][b]["value"] for k in numbers]
                diff = [x - y for x, y in zip(va, vb)]
                mean, _, low, high = bounds(diff, t_two)
                rel = 100 * mean / st.mean(vb)
                print(f"    {a}-{b}: mean {mean:+.1f} {col} ({rel:+.2f}% of {b}), "
                      f"two-sided 95% CI [{low:+.1f}, {high:+.1f}]")
    print()
    print("NOTE=L95 > 0 is the admission condition; L95 <= 0 alone does not show that the loss exceeds the margin.")
    print(f"NOTE=bootstrap: {RESAMPLES} resamples of blocks, seed {SEED}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
