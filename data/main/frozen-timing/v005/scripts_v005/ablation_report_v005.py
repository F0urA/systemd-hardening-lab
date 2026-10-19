#!/usr/bin/env python3
"""ablation_report_v005.py RESULTS_CSV

Cost hypothesis of protocol_ablation_v005.txt: the rise of CPU time per
request under P4 comes from the directives that install system-call filters.
The CSV must contain P0, P4s, P4n and P4 in every block (benchmark_v005.sh
nginx 20 P4 P4s P4n). Python 3 standard library only; must be located next to
audit_benchmark_csv_v005.py.

For every paired contrast the script prints the geometric mean increase of
CPU time per operation and its one-sided 95% lower and upper bounds (together
a two-sided 90% interval), then the verdict by the rule fixed in the protocol.
"""
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_benchmark_csv_v005 import bounds, read, t_quantile  # noqa: E402

CONTRASTS = [
    ("P4s", "P0", "filter group alone"),
    ("P4n", "P0", "all other directives alone"),
    ("P4", "P4n", "filter group on top of the others"),
    ("P4", "P0", "full profile"),
]


def pct(x):
    return 100 * (math.exp(x) - 1)


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 64
    _, blocks, unit, has_cost = read(Path(sys.argv[1]))
    numbers = sorted(blocks)
    needed = {"P0", "P4s", "P4n", "P4"}
    for b in numbers:
        if not needed.issubset(blocks[b]):
            raise SystemExit(f"Block {b} lacks: {' '.join(sorted(needed - set(blocks[b])))}")
    n = len(numbers)
    t_one = t_quantile(0.95, n - 1)

    print("===== COST ABLATION, CPU TIME PER OPERATION =====")
    print(f"PAIRS={n}  COST_SOURCE={'cpu_us_per_op' if has_cost else 'cpu_pct / ' + unit}")
    print(f"{'contrast':<12}{'meaning':<36}{'mean %':>9}{'lower %':>9}{'upper %':>9}")
    result = {}
    for cand, base, meaning in CONTRASTS:
        logs = [math.log(blocks[b][cand]["cost"] / blocks[b][base]["cost"]) for b in numbers]
        mean, _, lower, upper = bounds(logs, t_one)
        result[(cand, base)] = (mean, lower, upper)
        print(f"{cand + '/' + base:<12}{meaning:<36}{pct(mean):>+9.2f}{pct(lower):>+9.2f}{pct(upper):>+9.2f}")

    print()
    print("Throughput, mean " + unit + ": " + "  ".join(
        f"{p}={sum(blocks[b][p]['value'] for b in numbers) / n:.1f}" for p in ("P0", "P4s", "P4n", "P4")))

    s_mean, s_low, _ = result[("P4", "P4n")]
    r_mean, r_low, _ = result[("P4n", "P0")]
    print()
    if s_low > 0 and r_low <= 0:
        verdict = "SUPPORTED: the filter group accounts for the cost; the other directives show no increase"
    elif s_low <= 0 and r_low > 0:
        verdict = "NOT SUPPORTED: the cost comes from the other directives"
    elif s_low > 0 and r_low > 0:
        share = 100 * s_mean / (s_mean + r_mean)
        verdict = f"BOTH GROUPS CONTRIBUTE: filter group about {share:.0f}% of the increase (log scale)"
    else:
        verdict = "INCONCLUSIVE: neither contrast is separated from zero"
    print("VERDICT=" + verdict)
    print("NOTE=Bounds assume approximately normal, independent block contrasts.")
    print("NOTE=Exploratory series; it does not enter the selection rule.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
