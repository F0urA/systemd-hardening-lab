#!/usr/bin/env python3
"""select_profile_v005.py CRITERIA_CSV [--budgets 2,5,10,15] [--require SERVICE=GOAL[,GOAL...] ...]
                         [--policy s,emicro,exposure,n]

Applies the selection procedure of procedure_v005.txt to a table of measured
criteria and prints the outcome for every service and CPU budget H.
Python 3 standard library only.

CSV columns (one row per service and candidate):
  service, profile, F, L95, cost_upper, goals_blocked, cells_blocked, emicro,
  exposure, n_directives [, U95d, status, goals_full, pairs, source]
    F              1 if the functional contract passed, else 0
    L95            one-sided lower bound of throughput(D) - 0.95*P0
    cost_upper     one-sided upper bound of the cost increase over P0,
                   in the same unit as the budgets H (0 for P0)
    goals_blocked  g(D): attacker goals blocked in every scenario cell in
                   which they are achievable under P0
    cells_blocked  s(D): scenario cells achievable under P0 and blocked under D
    emicro         share of baseline-allowed probes that the profile blocks
    exposure       systemd-analyze security, 0..10
    n_directives   number of settings in the drop-in
    status         outcome of the throughput test (build_criteria_v005.py)
    goals_full     names of the goals counted in goals_blocked, ';' separated

Structure of the procedure (fixed):
  1. admission      F = 1, L95 > 0, cost_upper <= H and, when the operator
                    requires goals (--require), every required goal blocked;
  2. selection      among the admitted, the largest g(D);
  3. equal g(D)     all equal candidates are reported.
Policy of the operator (a parameter, not a part of the structure):
  --require         the goals that must be blocked for the service;
  --policy          the order of the diagnostic criteria that breaks a tie of
                    step 3. Default: s (max), emicro (max), exposure (min),
                    n (min) -- the order of the rule of revision v004.

Outcomes of rule B:
  a profile         selected;
  TIE(...)          equal candidates, all reported;
  NONE              no restricted candidate passes F, L95 and the cost budget;
  BELOW_REQUIRED    some candidates pass them, none blocks the required goals.
P0 is not a candidate. NONE and BELOW_REQUIRED are not recommendations to run
the service unrestricted.

Reference rules:
  A      F = 1; minimal exposure; then fewer directives.
  A+     candidates admitted by F, L95 and the budget; minimal exposure; then
         fewer directives. Same data as rule B, formal score instead of goals.
  B v003 the rule as fixed in protocol_v005.txt before the first series: P0 is
         a candidate and the first criterion is cells_blocked.
"""
import argparse
import csv
from collections import defaultdict

DIAGNOSTIC = {
    "g": lambda r: -r["goals_blocked"],
    "s": lambda r: -r["cells_blocked"],
    "emicro": lambda r: -r["emicro"],
    "exposure": lambda r: r["exposure"],
    "n": lambda r: r["n_directives"],
}


def pick(candidates, key):
    if not candidates:
        return "NONE"
    best = min(key(c) for c in candidates)
    winners = [c["profile"] for c in candidates if key(c) == best]
    return winners[0] if len(winners) == 1 else "TIE(" + "/".join(winners) + ")"


def lex(names):
    return lambda r: tuple(DIAGNOSTIC[n](r) for n in names)


def admissible(rows, budget):
    return [r for r in rows if r["F"] == 1 and r["L95"] > 0 and r["cost_upper"] <= budget]


def restricted(rows):
    return [r for r in rows if r["profile"] != "P0"]


def rule_a(rows):
    return pick([r for r in rows if r["F"] == 1], lex(["exposure", "n"]))


def rule_a_plus(rows, budget):
    return pick(restricted(admissible(rows, budget)), lex(["exposure", "n"]))


def rule_b(rows, budget, required, policy):
    """Returns (outcome of the structure, outcome with the tie-break policy)."""
    adm = restricted(admissible(rows, budget))
    if not adm:
        return "NONE", "NONE"
    adm = [r for r in adm if required <= r["goals_full"]]
    if not adm:
        return "BELOW_REQUIRED", "BELOW_REQUIRED"
    return pick(adm, lex(["g"])), pick(adm, lex(["g"] + policy))


def rule_b_v003(rows, budget):
    return pick(admissible(rows, budget), lex(["s", "emicro", "exposure", "n"]))


def read_criteria(path):
    services = defaultdict(list)
    with open(path, newline="", encoding="utf-8-sig") as f:
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
                "status": row.get("status") or "",
                "goals_full": {g for g in (row.get("goals_full") or "").split(";") if g},
            })
    return services


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("csv")
    ap.add_argument("--budgets", default="2,5,10,15")
    ap.add_argument("--require", action="append", default=[], metavar="SERVICE=GOAL[,GOAL...]")
    ap.add_argument("--policy", default="s,emicro,exposure,n")
    args = ap.parse_args()
    budgets = [float(x) for x in args.budgets.split(",") if x.strip()]
    policy = [x for x in args.policy.split(",") if x]
    for name in policy:
        if name not in DIAGNOSTIC or name == "g":
            ap.error(f"unknown diagnostic criterion in --policy: {name}")
    required = defaultdict(set)
    for item in args.require:
        service, _, names = item.partition("=")
        required[service] |= {g for g in names.split(",") if g}

    for service, rows in read_criteria(args.csv).items():
        print("=" * 100)
        print(f"SERVICE {service}: candidates {' '.join(r['profile'] for r in rows)}")
        excluded = [r["profile"] for r in rows if r["F"] != 1]
        if excluded:
            print("  excluded by the functional gate: " + " ".join(excluded))
        for status, text in (("LOSS_EXCEEDS", "loss larger than the margin is shown"),
                             ("NEEDS_MORE_DATA", "more measurements are required (planned extension)"),
                             ("INCONCLUSIVE", "no conclusion at the limit of observations"),
                             ("NOT_MEASURED", "not measured under load")):
            names = [r["profile"] for r in rows if r["F"] == 1 and r["status"] == status]
            if names:
                print(f"  {text}: " + " ".join(names))
        if not any(r["status"] for r in rows):
            failed = [r["profile"] for r in rows if r["F"] == 1 and r["L95"] <= 0]
            if failed:
                print("  throughput non-inferiority not established: " + " ".join(failed))
        if required[service]:
            print("  required goals: " + " ".join(sorted(required[service])))
        print(f"  RULE A (min Exposure, no admission conditions): {rule_a(rows)}")
        print(f"  {'H':>6}  {'admitted by F, L95, cost':<26}{'RULE A+':<16}{'RULE B':<18}"
              f"{'B + policy':<16}RULE B (v003)")
        for h in budgets:
            adm = " ".join(r["profile"] for r in restricted(admissible(rows, h))) or "-"
            b, b_policy = rule_b(rows, h, required[service], policy)
            print(f"  {h:>6g}  {adm:<26}{rule_a_plus(rows, h):<16}{b:<18}{b_policy:<16}{rule_b_v003(rows, h)}")
    print()
    print("NONE = no admitted restricted candidate among those tested.")
    print("BELOW_REQUIRED = admitted candidates exist, none blocks every required goal.")
    print(f"B + policy: ties of rule B broken by the operator's order {','.join(policy)}.")


if __name__ == "__main__":
    main()
