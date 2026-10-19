#!/usr/bin/env python3
"""Paired blocked-benchmark audit, v003. Python 3 standard library only.

Based on audit_benchmark_csv.py; the primary test is unchanged:
  D_b = throughput(candidate,b) - margin * throughput(baseline,b)
  one-sided 95% lower Student-t bound for mean(D_b) > 0.

Added in v003:
  * any number of paired blocks (the Student-t quantile is computed);
  * the cost criterion: CPU time per operation, c = CPU / operations.
    For every block r_b = c(candidate,b) / c(baseline,b); the one-sided 95%
    upper bound of the geometric mean ratio is compared with the budgets H;
  * the one-sided 95% upper bound of the CPU difference in percentage points.

All bounds assume approximately normal, independent block contrasts; block
and order effects are not modelled beyond pairing.
"""
import argparse
import csv
import hashlib
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path


def _betacf(a, b, x):
    tiny = 1e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c, d = 1.0, 1.0 - qab * x / qap
    d = 1.0 / (d if abs(d) > tiny else tiny)
    h = d
    for m in range(1, 400):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > tiny else tiny)
        c = 1.0 + aa / c
        c = c if abs(c) > tiny else tiny
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > tiny else tiny)
        c = 1.0 + aa / c
        c = c if abs(c) > tiny else tiny
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-15:
            break
    return h


def _betainc(a, b, x):
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    front = math.exp(math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
                     + a * math.log(x) + b * math.log(1.0 - x))
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - front * _betacf(b, a, 1.0 - x) / b


def t_cdf(t, df):
    x = df / (df + t * t)
    tail = 0.5 * _betainc(df / 2.0, 0.5, x)
    return 1.0 - tail if t >= 0 else tail


def t_quantile(p, df):
    lo, hi = 0.0, 1000.0
    for _ in range(200):
        mid = (lo + hi) / 2.0
        if t_cdf(mid, df) < p:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


def read(path):
    rows = list(csv.DictReader(path.open('r', encoding='utf-8-sig', newline='')))
    if not rows:
        raise ValueError('CSV is empty')
    necessary = {'block', 'order', 'profile', 'cpu_pct'}
    if not necessary.issubset(rows[0]):
        raise ValueError('Missing columns: ' + ', '.join(sorted(necessary - set(rows[0]))))
    col = 'rps' if 'rps' in rows[0] else 'tps' if 'tps' in rows[0] else None
    if col is None:
        raise ValueError('Neither rps nor tps column found')
    has_cost = 'cpu_us_per_op' in rows[0]
    blocks = defaultdict(dict)
    seen_orders = defaultdict(set)
    for lineno, row in enumerate(rows, start=2):
        b = int(row['block'])
        order = int(row['order'])
        profile = row['profile'].strip()
        if b <= 0 or order <= 0 or not profile:
            raise ValueError(f'Invalid identity on CSV line {lineno}')
        if profile in blocks[b]:
            raise ValueError(f'Duplicate profile {profile} in block {b}')
        if order in seen_orders[b]:
            raise ValueError(f'Duplicate order {order} in block {b}')
        seen_orders[b].add(order)
        value = float(row[col])
        cpu = float(row['cpu_pct'])
        if not (math.isfinite(value) and value > 0 and math.isfinite(cpu)):
            raise ValueError(f'Invalid value on CSV line {lineno}')
        if 'failed' in row and row['failed'] and int(float(row['failed'])) != 0:
            raise ValueError(f'Nonzero failed requests on CSV line {lineno}')
        # CPU per operation: measured directly when the column exists,
        # otherwise proportional to cpu_pct / throughput (same units cancel
        # in the paired ratio).
        cost = float(row['cpu_us_per_op']) if has_cost else cpu / value
        if not (math.isfinite(cost) and cost > 0):
            raise ValueError(f'Invalid CPU cost on CSV line {lineno}')
        blocks[b][profile] = {'value': value, 'cpu': cpu, 'cost': cost, 'order': order}
    return rows, blocks, col, has_cost


def bounds(values, tvalue):
    n = len(values)
    mean = statistics.mean(values)
    sd = statistics.stdev(values)
    half = tvalue * sd / math.sqrt(n)
    return mean, sd, mean - half, mean + half


def main():
    ap = argparse.ArgumentParser(description='Audit paired benchmark CSV (v003)')
    ap.add_argument('csv', type=Path)
    ap.add_argument('--baseline', default='P0')
    ap.add_argument('--candidate', default='P4')
    ap.add_argument('--margin', type=float, default=0.95)
    ap.add_argument('--budgets', default='2,5,10,15',
                    help='CPU-per-operation budgets H in percent, comma separated')
    args = ap.parse_args()
    if not (0 < args.margin < 1):
        ap.error('--margin must be between 0 and 1')
    if args.baseline == args.candidate:
        ap.error('Baseline and candidate must differ')
    if not args.csv.is_file():
        ap.error('CSV file not found: ' + str(args.csv))
    budgets = [float(x) for x in args.budgets.split(',') if x.strip()]

    print('===== BENCHMARK DATA AUDIT v003 =====')
    print('SOURCE=' + str(args.csv.resolve()))
    print('SHA256=' + hashlib.sha256(args.csv.read_bytes()).hexdigest())
    rows, blocks, unit, has_cost = read(args.csv)
    print('CSV_DATA_ROWS=' + str(len(rows)))
    print('ALL_PROFILES=' + str(dict(sorted(Counter(r['profile'] for r in rows).items()))))
    print('THROUGHPUT_COLUMN=' + unit)
    print('BASELINE=' + args.baseline + ' CANDIDATE=' + args.candidate)
    numbers = sorted(blocks)
    if numbers != list(range(1, len(numbers) + 1)):
        raise ValueError('Block numbers not consecutive from 1')
    for b in numbers:
        if args.baseline not in blocks[b] or args.candidate not in blocks[b]:
            raise ValueError(f'Missing pair in block {b}')
    n = len(numbers)
    if n < 3:
        raise ValueError('At least three paired blocks are required')
    df = n - 1
    t_one, t_two = t_quantile(0.95, df), t_quantile(0.975, df)

    base = [blocks[b][args.baseline] for b in numbers]
    cand = [blocks[b][args.candidate] for b in numbers]
    A = [x['value'] for x in base]
    B = [x['value'] for x in cand]
    contrasts = [y - args.margin * x for x, y in zip(A, B)]
    cpudiff = [y['cpu'] - x['cpu'] for x, y in zip(base, cand)]
    logs = [math.log(y / x) for x, y in zip(A, B)]
    costlogs = [math.log(y['cost'] / x['cost']) for x, y in zip(base, cand)]

    print('\n===== EACH PAIRED BLOCK =====')
    print(f"BLOCK ORDER_{args.baseline} ORDER_{args.candidate} {args.baseline}_{unit} "
          f"{args.candidate}_{unit} D={args.candidate}-{args.margin:.2f}*{args.baseline} "
          f"CPU_DELTA_PP CPU_PER_OP_RATIO")
    for b, x, y, d, cpu, cl in zip(numbers, base, cand, contrasts, cpudiff, costlogs):
        print(f"{b:5d} {x['order']:8d} {y['order']:8d} {x['value']:12.3f} {y['value']:12.3f} "
              f"{d:12.3f} {cpu:+12.3f} {math.exp(cl):16.4f}")

    mean0, mean1 = statistics.mean(A), statistics.mean(B)
    dmean, dsd, dlower, _ = bounds(contrasts, t_one)
    cpumean, _, cpu_low, cpu_high = bounds(cpudiff, t_two)
    _, _, _, cpu_upper_one = bounds(cpudiff, t_one)
    logmean, _, loglow, _ = bounds(logs, t_one)
    costmean, _, _, costupper = bounds(costlogs, t_one)

    print('\n===== VERIFIED SUMMARY =====')
    print('PAIRS=' + str(n))
    print(f'STUDENT_T_QUANTILES_DF_{df}=one_sided_95:{t_one:.6f} two_sided_95:{t_two:.6f}')
    print(f'MEAN_{args.baseline}_{unit}={mean0:.6f}')
    print(f'MEAN_{args.candidate}_{unit}={mean1:.6f}')
    print(f'RATIO_OF_ARITHMETIC_MEANS={mean1 / mean0:.9f} ({100 * mean1 / mean0:.5f}%)')
    print(f'PRIMARY_PAIRED_CONTRAST_MEAN={dmean:.6f} {unit}')
    print(f'PRIMARY_PAIRED_CONTRAST_SD={dsd:.6f} {unit}')
    print(f'STUDENT_T_ONE_SIDED_95_LOWER_FOR_CONTRAST={dlower:.6f} {unit}')
    print('PRIMARY_NONINFERIORITY_95=' + ('PASS_CONDITIONAL' if dlower > 0 else 'NOT_ESTABLISHED'))
    print(f'SENSITIVITY_GEOMETRIC_MEAN_PAIRED_RATIO={math.exp(logmean):.8f}')
    print(f'SENSITIVITY_GEOMETRIC_RATIO_ONE_SIDED_95_LOWER={math.exp(loglow):.8f}')
    print(f'CPU_MEAN_{args.baseline}={statistics.mean(x["cpu"] for x in base):.6f} %_one_core')
    print(f'CPU_MEAN_{args.candidate}={statistics.mean(x["cpu"] for x in cand):.6f} %_one_core')
    print(f'CPU_PAIRED_DELTA_MEAN={cpumean:+.6f} percentage_points')
    print(f'CPU_PAIRED_DELTA_TWO_SIDED_95_CI=[{cpu_low:+.6f},{cpu_high:+.6f}] percentage_points')
    print(f'CPU_PAIRED_DELTA_ONE_SIDED_95_UPPER={cpu_upper_one:+.6f} percentage_points')

    print('\n===== COST CRITERION: CPU TIME PER OPERATION =====')
    print('COST_SOURCE=' + ('cpu_us_per_op column' if has_cost else 'cpu_pct / ' + unit + ' (proportional)'))
    rel_mean = 100 * (math.exp(costmean) - 1)
    rel_upper = 100 * (math.exp(costupper) - 1)
    print(f'CPU_PER_OP_GEOMETRIC_MEAN_INCREASE={rel_mean:+.4f} %')
    print(f'CPU_PER_OP_ONE_SIDED_95_UPPER_INCREASE={rel_upper:+.4f} %')
    for h in budgets:
        verdict = 'PASS_CONDITIONAL' if rel_upper <= h else 'NOT_ESTABLISHED'
        print(f'CPU_BUDGET_H={h:g}%: {verdict}')
    print('NOTE=One-sided t inference assumes approximately normal, independent block contrasts.')
    print('NOTE=Do not replace source observations, including outliers, in the primary analysis.')


if __name__ == '__main__':
    main()
