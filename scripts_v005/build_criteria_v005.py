#!/usr/bin/env python3
"""build_criteria_v005.py --probe DIR --scenarios DIR [--bench SERVICE=DIR[:P,P...] ...] [--conditional] [--out FILE]

Collects the measured criteria of every candidate into one table in the
format of select_profile_v005.py, so that the way from raw results to the
selected profile contains no manual steps. Python 3 standard library only;
must be located next to audit_benchmark_csv_v005.py.

Sources:
  F, exposure, n_directives  <scenarios>/candidates.csv
  goals_blocked g(D)         <scenarios>/goals.csv: goals whose every scenario
                             cell (goal, dac, context) that is ACHIEVED under
                             P0 is BLOCKED under D
  cells_blocked s(D)         the same file: number of such cells
  emicro                     <probe>/metrics.csv, column emicro_36; context
                             nginx-worker for Nginx (nginx-master is printed
                             for information)
  L95, cost_upper            <bench>/results.csv of the service: one-sided
                             95% bounds, as in audit_benchmark_csv_v005.py;
                             cost_upper is the increase of CPU time per
                             operation over P0, percent

--bench may be given several times for one service. "SERVICE=DIR:P1,P2" takes
only the listed candidates from that series, so that the source series of
every candidate is fixed on the command line (protocol_review_v005.txt,
section 5). Without a list the series supplies every candidate it contains
that an earlier --bench has not supplied.

--conditional: a functional candidate without load data is entered
as admissible (L95 = 1, cost_upper = 0) and marked in the notes. This is the
conditional application of rule B described in protocol_v005.txt, section 9.
Without the flag such candidates are not admissible.
"""
import argparse
import csv
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_benchmark_csv_v005 import bounds, read, t_quantile  # noqa: E402

CONTEXT = {"nginx": "nginx-worker", "redis": "redis", "postgresql": "postgresql"}
ORDER = ["nginx", "redis", "postgresql"]


def load(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def goals_blocked(rows, service):
    """profile -> (goals, cells, residual goals); cells achievable under P0; unexpected profiles."""
    cells = defaultdict(dict)
    for r in rows:
        if r["service"] == service and r["outcome"] in ("ACHIEVED", "BLOCKED", "UNEXPECTED"):
            cells[(r["goal"], r["dac"], r["context"])][r["profile"]] = r["outcome"]
    reachable = [c for c, by in cells.items() if by.get("P0") == "ACHIEVED"]
    goals = sorted({c[0] for c in reachable})
    profiles = {p for by in cells.values() for p in by}
    result = {}
    for p in profiles:
        blocked_cells = [c for c in reachable if cells[c].get(p) == "BLOCKED"]
        full = [g for g in goals if all(cells[c].get(p) == "BLOCKED" for c in reachable if c[0] == g)]
        result[p] = (len(full), len(blocked_cells), [g for g in goals if g not in full])
    unexpected = sorted({p for by in cells.values() for p, o in by.items() if o == "UNEXPECTED"})
    return result, len(goals), len(reachable), unexpected


def bench_bounds(path):
    """profile -> (L95, cost upper bound in percent, pairs); P0 is the baseline."""
    _, blocks, _, _ = read(path)
    numbers = sorted(blocks)
    t_one = t_quantile(0.95, len(numbers) - 1)
    out = {}
    profiles = set.intersection(*(set(blocks[b]) for b in numbers))
    if "P0" not in profiles:
        raise ValueError(f"{path}: P0 is missing in some block")
    base = [blocks[b]["P0"] for b in numbers]
    out["P0"] = (0.05 * statistics.mean(x["value"] for x in base), 0.0, len(numbers))
    for p in sorted(profiles - {"P0"}):
        cand = [blocks[b][p] for b in numbers]
        d = [y["value"] - 0.95 * x["value"] for x, y in zip(base, cand)]
        logs = [math.log(y["cost"] / x["cost"]) for x, y in zip(base, cand)]
        _, _, lower, _ = bounds(d, t_one)
        _, _, _, upper = bounds(logs, t_one)
        out[p] = (lower, 100 * (math.exp(upper) - 1), len(numbers))
    return out


def main():
    ap = argparse.ArgumentParser(description="Build the criteria table for select_profile_v005.py")
    ap.add_argument("--probe", required=True, type=Path)
    ap.add_argument("--scenarios", required=True, type=Path)
    ap.add_argument("--bench", action="append", default=[], metavar="SERVICE=DIR[:P,P...]")
    ap.add_argument("--conditional", action="store_true",
                    help="treat functional candidates without load data as admissible")
    ap.add_argument("--out", type=Path, default=Path("criteria_v005.csv"))
    args = ap.parse_args()

    metrics = {(r["context"], r["profile"]): r for r in load(args.probe / "metrics.csv")}
    candidates = load(args.scenarios / "candidates.csv")
    goals = load(args.scenarios / "goals.csv")
    bench, notes = defaultdict(dict), []
    for item in args.bench:
        service, _, rest = item.partition("=")
        directory, sep, only = rest.rpartition(":")
        if not sep or "/" in only or "\\" in only:
            directory, only = rest, ""
        series = bench_bounds(Path(directory) / "results.csv")
        wanted = [p for p in only.split(",") if p] or sorted(series)
        for p in wanted:
            if p not in series:
                raise SystemExit(f"{directory}: no complete data for {p}")
            if p not in bench[service]:
                bench[service][p] = series[p] + (Path(directory).name,)
        notes.append(f"{service}: series {Path(directory).name} supplies {' '.join(wanted)}"
                     + ("" if only else " (unless supplied by an earlier series)"))

    rows = []
    for service in ORDER:
        cands = [c for c in candidates if c["service"] == service]
        if not cands:
            continue
        blocked, n_goals, n_cells, unexpected = goals_blocked(goals, service)
        notes.append(f"{service}: {n_goals} goals in {n_cells} scenario cells are achievable under P0")
        if unexpected:
            notes.append(f"{service}: UNEXPECTED outcomes under {' '.join(unexpected)} -- resolve before use")
        for c in cands:
            p = c["profile"]
            functional = int(c["functional"])
            m = metrics.get((CONTEXT[service], p))
            if p == "P0":
                emicro = 0.0
            elif m and m["valid"] == "1":
                emicro = float(m["emicro_36"])
            else:
                emicro = 0.0
                if functional:
                    notes.append(f"{service} {p}: no valid probe run, emicro set to 0")
            if p in bench[service]:
                lower, cost, pairs, source = bench[service][p]
            else:
                lower, cost, pairs, source = -1.0, 0.0, 0, "-"
                if functional and args.conditional:
                    lower = 1.0
                    if p != "P0":
                        notes.append(f"{service} {p}: no load data, ASSUMED admissible (conditional rule B)")
                elif functional:
                    notes.append(f"{service} {p}: not benchmarked, L95 set to -1 (not admissible)")
            if service == "nginx":
                mm = metrics.get(("nginx-master", p))
                if mm and mm["valid"] == "1" and p != "P0":
                    notes.append(f"nginx {p}: master context emicro_36={float(mm['emicro_36']):.3f}, "
                                 f"required and still allowed: {mm['residual_required'] or '-'}")
            g, s, residual = blocked.get(p, (0, 0, []))
            if functional and p != "P0":
                notes.append(f"{service} {p}: goals not blocked in every cell: {' '.join(residual) or '-'}")
            rows.append({
                "service": service, "profile": p, "F": functional,
                "L95": f"{lower:.3f}", "cost_upper": f"{cost:.3f}",
                "goals_blocked": g, "cells_blocked": s, "emicro": f"{emicro:.3f}",
                "exposure": c["exposure"] if c["exposure"] not in ("", "NA") else "10",
                "n_directives": c["n_directives"], "pairs": pairs, "source": source,
            })

    fields = ["service", "profile", "F", "L95", "cost_upper", "goals_blocked", "cells_blocked", "emicro",
              "exposure", "n_directives"]
    with args.out.open("w", newline="", encoding="utf-8") as f:
        f.write("# built by build_criteria_v005.py; cost_upper: CPU time per operation, % over P0\n")
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    print(f"{'service':<11}{'profile':<8}{'F':>2}{'pairs':>6}{'L95':>11}{'cost_up%':>10}"
          f"{'g':>3}{'s':>3}{'emicro':>8}{'expos':>7}{'n':>4}  series")
    for r in rows:
        print(f"{r['service']:<11}{r['profile']:<8}{r['F']:>2}{r['pairs']:>6}{r['L95']:>11}"
              f"{r['cost_upper']:>10}{r['goals_blocked']:>3}{r['cells_blocked']:>3}{r['emicro']:>8}"
              f"{r['exposure']:>7}{r['n_directives']:>4}  {r['source']}")
    print()
    for n in notes:
        print("NOTE " + n)
    print(f"CSV={args.out}")
    print(f"NEXT: python3 select_profile_v005.py {args.out} --budgets 2,5,10,15")


if __name__ == "__main__":
    main()
