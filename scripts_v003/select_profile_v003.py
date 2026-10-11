#!/usr/bin/env python3
"""select_profile_v003.py CRITERIA_CSV [--budgets 2,5,10,15]

Applies the two selection rules of protocol_v003.txt to a table of measured
criteria and prints the chosen profile for every service and CPU budget H.
Python 3 standard library only.

CSV columns (one row per service and candidate):
  service, profile, F, L95, cost_upper, goals_blocked, emicro, exposure,
  n_directives
    F              1 if the functional contract passed, else 0
    L95            one-sided 95% lower bound of throughput(D) - 0.95*P0
    cost_upper     one-sided 95% upper bound of the cost increase over P0,
                   in the same unit as the budgets H (0 for P0)
    goals_blocked  number of attacker goals from G that the profile blocks
    emicro         share of baseline-allowed probes that the profile blocks
    exposure       systemd-analyze security, 0..10
    n_directives   number of settings in the drop-in

Rule A (reference): F = 1; minimal exposure; then fewer directives.
Rule B (proposed):  F = 1, L95 > 0, cost_upper <= H; then lexicographically
                    max goals_blocked, max emicro, min exposure, fewer
                    directives.
Remaining ties are reported, never resolved silently.
"""
import argparse
import csv
from collections import defaultdict


def pick(candidates, key):
    if not candidates:
        return "none"
    best = min(key(c) for c in candidates)
    winners = [c["profile"] for c in candidates if key(c) == best]
    return winners[0] if len(winners) == 1 else "TIE(" + "/".join(winners) + ")"


def rule_a(rows):
    return pick([r for r in rows if r["F"] == 1],
                lambda r: (r["exposure"], r["n_directives"]))


def admissible(rows, budget):
    return [r for r in rows if r["F"] == 1 and r["L95"] > 0 and r["cost_upper"] <= budget]


def rule_b(rows, budget):
    return pick(admissible(rows, budget),
                lambda r: (-r["goals_blocked"], -r["emicro"], r["exposure"], r["n_directives"]))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("csv")
    ap.add_argument("--budgets", default="2,5,10,15")
    args = ap.parse_args()
    budgets = [float(x) for x in args.budgets.split(",") if x.strip()]

    services = defaultdict(list)
    with open(args.csv, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(r for r in f if not r.startswith("#")):
            services[row["service"]].append({
                "profile": row["profile"],
                "F": int(row["F"]),
                "L95": float(row["L95"]),
                "cost_upper": float(row["cost_upper"]),
                "goals_blocked": int(row["goals_blocked"]),
                "emicro": float(row["emicro"]),
                "exposure": float(row["exposure"]),
                "n_directives": int(row["n_directives"]),
            })

    for service, rows in services.items():
        print("=" * 64)
        print(f"SERVICE {service}: candidates {' '.join(r['profile'] for r in rows)}")
        excluded = [r["profile"] for r in rows if r["F"] != 1]
        if excluded:
            print("  excluded by the functional gate: " + " ".join(excluded))
        failed = [r["profile"] for r in rows if r["F"] == 1 and r["L95"] <= 0]
        if failed:
            print("  throughput non-inferiority not established: " + " ".join(failed))
        print(f"  RULE A (min Exposure): {rule_a(rows)}")
        print(f"  {'H':>8}  {'admissible':<24} RULE B")
        for h in budgets:
            adm = " ".join(r["profile"] for r in admissible(rows, h)) or "-"
            print(f"  {h:>8g}  {adm:<24} {rule_b(rows, h)}")


if __name__ == "__main__":
    main()
