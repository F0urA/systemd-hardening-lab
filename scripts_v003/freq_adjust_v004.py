#!/usr/bin/env python3
"""freq_adjust_v004.py HOST_ACTIVITY_CSV END_TIMES_TXT SERIES_DIR [SERIES_DIR ...]

Exploratory analysis, not part of the fixed protocol. The host log shows that
the frequency of the performance cores changed between measurements; this
script matches every measurement with the host samples taken while it ran and
reports

  * the correlation between frequency and throughput for every profile;
  * the coefficient of variation of P0 before and after dividing throughput
    by frequency;
  * paired contrasts of the frequency-adjusted cost  c* = CPU time per
    operation x relative frequency  (proportional to processor cycles per
    operation), with one-sided 95% bounds.

HOST_ACTIVITY_CSV  time,vm_pct_of_core,u0,f0,...,u15,f15 (2-second samples)
END_TIMES_TXT      "<epoch> <series-dir-name> <path of ab-B<n>-<profile>-a<k>-g1.txt>"
Python 3 standard library only; must be located next to
audit_benchmark_csv_v003.py.
"""
import csv
import math
import re
import statistics as st
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_benchmark_csv_v003 import bounds, t_quantile  # noqa: E402

P_CORES = [0, 1, 10, 11, 12, 13]
CLOCK_OFFSET = 1.7   # the guest clock was ahead of the host clock by about 1.7 s
DATE = "2026-10-11"


def corr(x, y):
    mx, my = st.mean(x), st.mean(y)
    num = sum((a - mx) * (b - my) for a, b in zip(x, y))
    return num / math.sqrt(sum((a - mx) ** 2 for a in x) * sum((b - my) ** 2 for b in y))


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 64
    host = []
    for r in csv.DictReader(open(sys.argv[1])):
        try:
            t = datetime.strptime(f"{DATE} {r['time']}", "%Y-%m-%d %H:%M:%S").timestamp()
            busy = [float(r[f"f{i}"]) for i in P_CORES if float(r[f"u{i}"]) > 50]
        except ValueError:
            continue
        if busy:
            host.append((t, st.mean(busy)))
    ends = {}
    for line in open(sys.argv[2]):
        ts, series, name = line.split()
        m = re.search(r"ab-B(\d+)-(\w+)-a(\d+)-g1", name)
        ends[(series, int(m.group(1)), m.group(2), int(m.group(3)))] = int(ts) - CLOCK_OFFSET

    for series_dir in sys.argv[3:]:
        d = Path(series_dir)
        rows = list(csv.DictReader(open(d / "results.csv")))
        data = {}
        for r in rows:
            end = ends[(d.name, int(r["block"]), r["profile"], int(r["attempt"]))]
            wall = int(r["wall_ns"]) / 1e9
            fs = [f for t, f in host if end - wall <= t <= end + 0.5]
            if not fs:
                continue
            data[(int(r["block"]), r["profile"])] = {
                "rps": float(r["rps"]), "cost": float(r["cpu_us_per_op"]), "freq": st.mean(fs)}
        profiles = sorted({p for _, p in data})
        blocks = sorted({b for b, _ in data})
        print("=" * 78)
        print(f"SERIES {d.name}: {len(data)} of {len(rows)} measurements matched with host samples")
        freqs = [v["freq"] for v in data.values()]
        print(f"frequency of the busy performance cores, percent of nominal: "
              f"mean {st.mean(freqs):.0f}, min {min(freqs):.0f}, max {max(freqs):.0f}")
        for p in profiles:
            q = [v for (b, pp), v in data.items() if pp == p]
            raw = [v["rps"] for v in q]
            adj = [v["rps"] / v["freq"] for v in q]
            print(f"  {p:<4} n={len(q):2d}  corr(frequency, throughput)={corr([v['freq'] for v in q], raw):+.2f}  "
                  f"CV raw {100 * st.stdev(raw) / st.mean(raw):5.1f} %  "
                  f"CV of throughput/frequency {100 * st.stdev(adj) / st.mean(adj):5.1f} %")

        pairs = [("P4", "P0"), ("P5", "P0"), ("P6", "P0"), ("P4s", "P0"), ("P4n", "P0"), ("P4", "P4n")]
        print(f"  {'contrast':<9}{'n':>3}  {'raw cost: mean':>15}{'lower':>8}{'upper':>8}   "
              f"{'adjusted cost: mean':>19}{'lower':>8}{'upper':>8}")
        for cand, base in pairs:
            common = [b for b in blocks if (b, cand) in data and (b, base) in data]
            if len(common) < 3:
                continue
            t_one = t_quantile(0.95, len(common) - 1)
            raw = [math.log(data[(b, cand)]["cost"] / data[(b, base)]["cost"]) for b in common]
            adj = [math.log(data[(b, cand)]["cost"] * data[(b, cand)]["freq"]
                            / (data[(b, base)]["cost"] * data[(b, base)]["freq"])) for b in common]
            rm, _, rl, ru = bounds(raw, t_one)
            am, _, al, au = bounds(adj, t_one)
            pc = lambda x: 100 * (math.exp(x) - 1)
            print(f"  {cand + '/' + base:<9}{len(common):>3}  {pc(rm):>+14.1f}%{pc(rl):>+7.1f}%{pc(ru):>+7.1f}%   "
                  f"{pc(am):>+18.1f}%{pc(al):>+7.1f}%{pc(au):>+7.1f}%")
    print()
    print("NOTE=Exploratory: the adjustment was chosen after seeing the data and is not in the protocol.")
    print("NOTE=Bounds are one-sided 95% (together a two-sided 90% interval).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
