#!/usr/bin/env python3
"""freq_adjust_v004.py --host HOST_CSV --ends END_TIMES_TXT [options] SERIES_DIR [SERIES_DIR ...]

Analysis with a correction for the frequency of the host processor. The host
log shows that the frequency of the performance cores changes between
measurements; this script matches every measurement with the host samples
taken while it ran and reports

  * the correlation between frequency and throughput for every profile;
  * the coefficient of variation of P0 before and after dividing throughput
    by frequency;
  * the non-inferiority contrast  d = X(D) - 0.95 * X(P0)  for the measured
    throughput and for the throughput normalized to the nominal frequency
    X* = X / f, with one-sided 95% bounds;
  * paired contrasts of the frequency-adjusted cost  c* = CPU time per
    operation x relative frequency  (proportional to processor cycles per
    operation), with one-sided 95% bounds.

For the series of 11.10.2026 this correction was chosen after seeing the data
and is exploratory. For the review series of v004 it is the secondary
analysis declared in protocol_review_v004.txt, section 6, before the run; the
selection rule uses the uncorrected bounds in both cases.

HOST_CSV       time,vm_pct_of_core,u0,f0,...  (2-second samples written by
               host_activity_v004.ps1). time is ISO date and time, or
               HH:MM:SS together with --date.
END_TIMES_TXT  "<epoch> <series-dir-name> <path of ab-B<n>-<profile>-a<k>-g1.txt>"
               (modification times of the generator outputs on the stand)
--clock-offset seconds by which the guest clock is ahead of the host clock
--cores        logical processors of the host the virtual machine is pinned to
--pairs        extra cost contrasts, e.g. "P4/P4n,P1c/P1r"; every profile is
               always compared with P0
Python 3 standard library only; must be located next to
audit_benchmark_csv_v004.py.
"""
import argparse
import csv
import math
import re
import statistics as st
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_benchmark_csv_v004 import bounds, t_quantile  # noqa: E402


def corr(x, y):
    mx, my = st.mean(x), st.mean(y)
    num = sum((a - mx) * (b - my) for a, b in zip(x, y))
    return num / math.sqrt(sum((a - mx) ** 2 for a in x) * sum((b - my) ** 2 for b in y))


def pc(x):
    return 100 * (math.exp(x) - 1)


def main():
    ap = argparse.ArgumentParser(description="Frequency-adjusted analysis of Nginx load series")
    ap.add_argument("--host", required=True)
    ap.add_argument("--ends", required=True)
    ap.add_argument("--date", help="date of the host log when its time column is HH:MM:SS")
    ap.add_argument("--clock-offset", type=float, default=0.0)
    ap.add_argument("--cores", default="0,1,10,11,12,13")
    ap.add_argument("--pairs", default="")
    ap.add_argument("series", nargs="+")
    args = ap.parse_args()
    cores = [int(c) for c in args.cores.split(",")]

    host = []
    for r in csv.DictReader(open(args.host, encoding="utf-8-sig")):
        try:
            stamp = r["time"] if "T" in r["time"] else f"{args.date}T{r['time']}"
            t = datetime.fromisoformat(stamp).timestamp()
            busy = [float(r[f"f{i}"]) for i in cores if float(r[f"u{i}"]) > 50]
        except (ValueError, TypeError):
            continue
        if busy:
            host.append((t, st.mean(busy)))
    ends = {}
    for line in open(args.ends):
        ts, series, name = line.split()
        m = re.search(r"ab-B(\d+)-(\w+)-a(\d+)-g1", name)
        ends[(series, int(m.group(1)), m.group(2), int(m.group(3)))] = float(ts) - args.clock_offset

    for series_dir in args.series:
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
        print("=" * 96)
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

        print("  NON-INFERIORITY CONTRAST d = X(D) - 0.95*X(P0), one-sided 95% bounds; "
              "X* = X * 100 / f (throughput at the nominal frequency)")
        print(f"  {'candidate':<10}{'n':>3}  {'measured: ratio':>16}{'L95':>9}{'U95':>9}   "
              f"{'normalized: ratio':>18}{'L95*':>9}{'U95*':>9}")
        for cand in [p for p in profiles if p != "P0"]:
            common = [b for b in blocks if (b, cand) in data and (b, "P0") in data]
            if len(common) < 3:
                continue
            t_one = t_quantile(0.95, len(common) - 1)
            x0 = [data[(b, "P0")]["rps"] for b in common]
            x1 = [data[(b, cand)]["rps"] for b in common]
            n0 = [data[(b, "P0")]["rps"] * 100 / data[(b, "P0")]["freq"] for b in common]
            n1 = [data[(b, cand)]["rps"] * 100 / data[(b, cand)]["freq"] for b in common]
            _, _, rl, ru = bounds([b - 0.95 * a for a, b in zip(x0, x1)], t_one)
            _, _, al, au = bounds([b - 0.95 * a for a, b in zip(n0, n1)], t_one)
            print(f"  {cand:<10}{len(common):>3}  {100 * st.mean(x1) / st.mean(x0):>15.1f}%{rl:>9.0f}{ru:>9.0f}   "
                  f"{100 * st.mean(n1) / st.mean(n0):>17.1f}%{al:>9.0f}{au:>9.0f}")

        pairs = [(p, "P0") for p in profiles if p != "P0"]
        pairs += [tuple(x.split("/")) for x in args.pairs.split(",") if x]
        print(f"  {'cost':<10}{'n':>3}  {'raw cost: mean':>15}{'lower':>8}{'upper':>8}   "
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
            print(f"  {cand + '/' + base:<10}{len(common):>3}  {pc(rm):>+14.1f}%{pc(rl):>+7.1f}%{pc(ru):>+7.1f}%   "
                  f"{pc(am):>+18.1f}%{pc(al):>+7.1f}%{pc(au):>+7.1f}%")
    print()
    print("NOTE=The selection rule uses the uncorrected bounds; the corrected ones are a sensitivity analysis.")
    print("NOTE=Bounds are one-sided 95% (together a two-sided 90% interval).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
