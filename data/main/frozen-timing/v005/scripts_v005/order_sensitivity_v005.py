#!/usr/bin/env python3
"""order_sensitivity_v005.py CRITERIA_CSV [--budgets 2,5,10,15]

How much does the selected profile depend on the order of the criteria?
For every service and CPU budget H the admitted candidates (F = 1, L95 > 0,
cost_upper <= H, P0 excluded) are ranked lexicographically under every
permutation of the five criteria

    g (max)  s (max)  emicro (max)  exposure (min)  n (min)

and the script prints how many of the 120 orders select each candidate, and
the selection for every choice of the first criterion. A candidate that wins
under every order does not depend on the policy of priorities at all; a
selection that changes with the first criterion is a decision of the
operator and not a property of the data.

The criteria table is the one written by build_criteria_v005.py. Python 3
standard library only; must be located next to select_profile_v005.py.
"""
import argparse
import itertools
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from select_profile_v005 import DIAGNOSTIC, admissible, lex, pick, read_criteria, restricted  # noqa: E402

NAMES = ["g", "s", "emicro", "exposure", "n"]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("csv")
    ap.add_argument("--budgets", default="2,5,10,15")
    args = ap.parse_args()
    budgets = [float(x) for x in args.budgets.split(",") if x.strip()]
    assert set(NAMES) == set(DIAGNOSTIC)
    orders = list(itertools.permutations(NAMES))

    for service, rows in read_criteria(args.csv).items():
        print("=" * 100)
        print(f"SERVICE {service}")
        for h in budgets:
            adm = restricted(admissible(rows, h))
            names = " ".join(r["profile"] for r in adm) or "-"
            print(f"  H = {h:g} %: admitted {names}")
            if len(adm) < 2:
                print("    fewer than two admitted candidates: the order of the criteria cannot matter")
                continue
            total = Counter(pick(adm, lex(list(o))) for o in orders)
            print("    selected under all 120 orders:  "
                  + ", ".join(f"{p} in {n}" for p, n in total.most_common()))
            for first in NAMES:
                by_first = Counter(pick(adm, lex(list(o))) for o in orders if o[0] == first)
                print(f"    first criterion {first:<9}: "
                      + ", ".join(f"{p} in {n} of 24" for p, n in by_first.most_common()))
            for name in NAMES:
                values = sorted({DIAGNOSTIC[name](r) for r in adm})
                if len(values) == 1:
                    print(f"    criterion {name} does not distinguish the admitted candidates")
    print()
    print("Rule B of the procedure uses g first; the remaining order is the operator's policy.")


if __name__ == "__main__":
    main()
