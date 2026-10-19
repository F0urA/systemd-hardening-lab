#!/usr/bin/env python3
"""select_profile_v004.py CRITERIA_CSV [--budgets 2,5,10,15]

Applies the selection rules of protocol_review_v004.txt to a table of measured
criteria and prints the outcome for every service and CPU budget H.
Python 3 standard library only.

CSV columns (one row per service and candidate):
  service, profile, F, L95, cost_upper, goals_blocked, cells_blocked, emicro,
  exposure, n_directives
    F              1 if the functional contract passed, else 0
    L95            one-sided 95% lower bound of throughput(D) - 0.95*P0
    cost_upper     one-sided 95% upper bound of the cost increase over P0,
                   in the same unit as the budgets H (0 for P0)
    goals_blocked  g(D): attacker goals blocked in every scenario cell in
                   which they are achievable under P0
    cells_blocked  s(D): scenario cells achievable under P0 and blocked under D
    emicro         share of baseline-allowed probes that the profile blocks
    exposure       systemd-analyze security, 0..10
    n_directives   number of settings in the drop-in

A candidate is admissible if F = 1, L95 > 0 and cost_upper <= H.

Rule A  (reference):  F = 1; minimal exposure; then fewer directives.
Rule A+ (reference):  admissible restricted candidates; minimal exposure;
                      then fewer directives. Same data as rule B, formal
                      score instead of the attacker goals.
Rule B  (proposed):   admissible restricted candidates; lexicographically
                      max goals_blocked, max cells_blocked, max emicro,
                      min exposure, fewer directives.
Rule B as fixed in protocol_v004.txt (series v003) is printed for comparison:
P0 is a candidate and the first criterion is cells_blocked.

P0 is not a restricted candidate. If no restricted candidate is admissible,
rules A+ and B report NONE: no admissible profile among those tested. This is
not a recommendation to run the service unrestricted.
Remaining ties are reported, never resolved silently.
"""
import argparse
import csv
from collections import defaultdict


def pick(candidates, key):
    if not candidates:
        return "NONE"
    best = min(key(c) for c in candidates)
    winners = [c["profile"] for c in candidates if key(c) == best]
    return winners[0] if len(winners) == 1 else "TIE(" + "/".join(winners) + ")"


def admissible(rows, budget):
    return [r for r in rows if r["F"] == 1 and r["L95"] > 0 and r["cost_upper"] <= budget]


def restricted(rows):
    return [r for r in rows if r["profile"] != "P0"]


def rule_a(rows):
    return pick([r for r in rows if r["F"] == 1],
                lambda r: (r["exposure"], r["n_directives"]))


def rule_a_plus(rows, budget):
    return pick(restricted(admissible(rows, budget)),
                lambda r: (r["exposure"], r["n_directives"]))


def rule_b(rows, budget):
    return pick(restricted(admissible(rows, budget)),
                lambda r: (-r["goals_blocked"], -r["cells_blocked"], -r["emicro"],
                           r["exposure"], r["n_directives"]))


def rule_b_v003(rows, budget):
    return pick(admissible(rows, budget),
                lambda r: (-r["cells_blocked"], -r["emicro"], r["exposure"], r["n_directives"]))


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
                "cells_blocked": int(row["cells_blocked"]),
                "emicro": float(row["emicro"]),
                "exposure": float(row["exposure"]),
                "n_directives": int(row["n_directives"]),
            })

    for service, rows in services.items():
        print("=" * 78)
        print(f"SERVICE {service}: candidates {' '.join(r['profile'] for r in rows)}")
        excluded = [r["profile"] for r in rows if r["F"] != 1]
        if excluded:
            print("  excluded by the functional gate: " + " ".join(excluded))
        failed = [r["profile"] for r in rows if r["F"] == 1 and r["L95"] <= 0]
        if failed:
            print("  throughput non-inferiority not established: " + " ".join(failed))
        print(f"  RULE A (min Exposure, no admission conditions): {rule_a(rows)}")
        print(f"  {'H':>6}  {'admissible restricted':<26}{'RULE A+':<16}{'RULE B':<16}RULE B (v003)")
        for h in budgets:
            adm = " ".join(r["profile"] for r in restricted(admissible(rows, h))) or "-"
            print(f"  {h:>6g}  {adm:<26}{rule_a_plus(rows, h):<16}{rule_b(rows, h):<16}{rule_b_v003(rows, h)}")
    print()
    print("NONE = no admissible restricted candidate among those tested.")


if __name__ == "__main__":
    main()
