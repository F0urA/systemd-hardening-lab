#!/usr/bin/env python3
"""pg_contrasts_v007.py RUN_DIR [--out-csv FILE] [--plot FILE]

PostgreSQL of the third stage (results_v005/run-20261012-v005): paired
block contrasts d_i = X(D, i) - 0.95 X(P0, i) and cost log ratios, their
distribution, and a distribution-free check of the t-bounds used for admission.

For every candidate the one-sided bounds are computed twice at the same level
alpha = 0.05 / (M * K), M = 5 candidates, K = 2 looks:
  t     -- Student bounds, as in build_criteria_v005.py (the admission rule);
  perm  -- exact sign-flip permutation bounds (all 2^n sign vectors), which
           assume only that the contrast is symmetric about its mean, not
           that it is normal.
The outcome (non-inferior / loss beyond the margin / no conclusion) and the
cost condition are reported for both, so that a reader can see whether the
admission decision depends on the normality assumption.

Series: R3 (10 blocks) for P1 and P1d; R3 + R3ext (20 blocks) for P2, P4, P6,
exactly as in the combined analysis. Needs numpy; matplotlib only for --plot.
"""
import argparse
import csv
import math
import statistics
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from audit_benchmark_csv_v005 import bounds, t_quantile  # noqa: E402

ALPHA = 0.05 / (5 * 2)
R3 = "postgresql/benchmark-v005/20261013-193448"
R3EXT = "postgresql/benchmark-v005/20261013-233151"
SOURCE = {"P1": (R3,), "P1d": (R3,), "P2": (R3, R3EXT), "P4": (R3, R3EXT), "P6": (R3, R3EXT)}
OUTCOME = {(True, False): "NON_INFERIOR", (False, True): "LOSS_EXCEEDS", (False, False): "INCONCLUSIVE"}


def blocks(run, series):
    out = []
    for s in series:
        rows = list(csv.DictReader(open(run / "raw-vm" / s / "results.csv", encoding="utf-8")))
        by = {}
        for r in rows:
            by.setdefault(int(r["block"]), {})[r["profile"]] = (float(r["tps"]), float(r["cpu_us_per_op"]))
        out += [by[b] for b in sorted(by)]
    return out


def signs(n):
    """All 2^n sign vectors as an (2^n, n) array of +-1."""
    idx = np.arange(2 ** n, dtype=np.int64)[:, None]
    return 1 - 2 * ((idx >> np.arange(n)) & 1).astype(np.int8)


def perm_p(x, theta, s, upper):
    """Exact sign-flip p-value of H0: mean = theta against mean > theta (or < theta if upper)."""
    y = np.asarray(x) - theta
    obs = y.mean()
    stats = (s @ y) / len(y)
    eps = 1e-9 * (abs(obs) + 1)
    return float(np.mean(stats <= obs + eps)) if upper else float(np.mean(stats >= obs - eps))


def perm_bound(x, alpha, s, upper):
    """One-sided bound: the boundary of the set of theta not rejected at alpha (bisection)."""
    span = max(x) - min(x) + 1e-12
    lo, hi = min(x) - span, max(x) + span
    # lower bound: largest theta still rejected (p <= alpha) against "mean > theta"
    for _ in range(60):
        mid = (lo + hi) / 2
        p = perm_p(x, mid, s, upper)
        rejected = p <= alpha
        if upper:   # rejected for theta above the bound
            hi, lo = (mid, lo) if rejected else (hi, mid)
        else:       # rejected for theta below the bound
            lo, hi = (mid, hi) if rejected else (lo, mid)
    return (lo + hi) / 2


def skewness(x):
    m, sd = statistics.mean(x), statistics.pstdev(x)
    return sum(((v - m) / sd) ** 3 for v in x) / len(x) if sd else 0.0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run", type=Path)
    ap.add_argument("--out-csv", type=Path)
    ap.add_argument("--plot", type=Path)
    a = ap.parse_args()
    rows, points = [], {}
    sign_cache = {}
    for prof, series in SOURCE.items():
        data = blocks(a.run, series)
        n = len(data)
        s = sign_cache.setdefault(n, signs(n))
        d = [b[prof][0] - 0.95 * b["P0"][0] for b in data]
        logs = [math.log(b[prof][1] / b["P0"][1]) for b in data]
        points[prof] = d
        t_one = t_quantile(1 - ALPHA, n - 1)
        _, _, t_l, t_u = bounds(d, t_one)
        _, _, _, t_c = bounds(logs, t_one)
        p_l = perm_bound(d, ALPHA, s, upper=False)
        p_u = perm_bound(d, ALPHA, s, upper=True)
        p_c = perm_bound(logs, ALPHA, s, upper=True)
        row = {
            "profile": prof, "series": "+".join(x.split("/")[-1] for x in series), "n": n,
            "mean_d": statistics.mean(d), "median_d": statistics.median(d),
            "sd_d": statistics.stdev(d), "skew_d": skewness(d),
            "min_d": min(d), "max_d": max(d), "negative_d": sum(v < 0 for v in d),
            "t_L": t_l, "t_U": t_u, "t_cost_upper_pct": 100 * (math.exp(t_c) - 1),
            "perm_L": p_l, "perm_U": p_u, "perm_cost_upper_pct": 100 * (math.exp(p_c) - 1),
        }
        row["t_outcome"] = OUTCOME[(t_l > 0, t_u < 0)]
        row["perm_outcome"] = OUTCOME[(p_l > 0, p_u < 0)]
        for h in (2, 5):
            row[f"t_admit_H{h}"] = int(t_l > 0 and row["t_cost_upper_pct"] <= h)
            row[f"perm_admit_H{h}"] = int(p_l > 0 and row["perm_cost_upper_pct"] <= h)
        rows.append(row)
    print(f"alpha per bound = {ALPHA:.4f} (M=5, K=2); exact sign-flip over all 2^n sign vectors")
    print(f"{'prof':5}{'n':>3} {'mean d':>8} {'median':>8} {'skew':>6} {'neg':>4} | "
          f"{'t L':>8} {'t U':>8} {'t cost':>7} {'t outcome':>13} | "
          f"{'perm L':>8} {'perm U':>8} {'p cost':>7} {'perm outcome':>13} | admit H2 H5 t/perm")
    for r in rows:
        print(f"{r['profile']:5}{r['n']:>3} {r['mean_d']:8.1f} {r['median_d']:8.1f} {r['skew_d']:6.2f} "
              f"{r['negative_d']:>4} | {r['t_L']:8.1f} {r['t_U']:8.1f} {r['t_cost_upper_pct']:6.2f}% "
              f"{r['t_outcome']:>13} | {r['perm_L']:8.1f} {r['perm_U']:8.1f} {r['perm_cost_upper_pct']:6.2f}% "
              f"{r['perm_outcome']:>13} | {r['t_admit_H2']}{r['perm_admit_H2']} {r['t_admit_H5']}{r['perm_admit_H5']}")
    same = all(r["t_outcome"] == r["perm_outcome"] and r["t_admit_H2"] == r["perm_admit_H2"]
               and r["t_admit_H5"] == r["perm_admit_H5"] for r in rows)
    print("ADMISSION_DECISIONS_AGREE" if same else "ADMISSION_DECISIONS_DIFFER")
    if a.out_csv:
        with open(a.out_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            for r in rows:
                w.writerow({k: (f"{v:.4f}" if isinstance(v, float) else v) for k, v in r.items()})
    if a.plot:
        plot(points, a.plot)


def plot(points, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    order = ["P1", "P1d", "P2", "P4", "P6"]
    fig, ax = plt.subplots(figsize=(6.4, 3.2), dpi=200)
    rng = np.random.default_rng(20261011)
    for i, p in enumerate(order):
        y = points[p]
        ax.scatter(i + rng.uniform(-0.12, 0.12, len(y)), y, s=18, color="#3d3d3d", alpha=0.8,
                   edgecolors="white", linewidths=0.5, zorder=3)
        ax.hlines(statistics.mean(y), i - 0.28, i + 0.28, color="#000000", linewidth=2, zorder=4)
    ax.hlines(0, -0.5, len(order) - 0.5, color="#7a7a7a", linewidth=0.9, linestyle="--", zorder=1)
    ax.set_xlim(-0.5, len(order) - 0.5 + 0.75)
    ax.text(len(order) - 0.45, 0, "d = 0:\nпорог\nδ = 5 %", va="center", ha="left", fontsize=7,
            color="#4a4a4a")
    ax.set_xticks(range(len(order)), [f"{p}\n(n = {len(points[p])})" for p in order])
    ax.set_ylabel("d = X(D) − 0,95·X(P0), транзакций/с")
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.grid(axis="y", color="#e3e3e3", linewidth=0.6, zorder=0)
    fig.tight_layout()
    fig.savefig(path)


if __name__ == "__main__":
    main()
