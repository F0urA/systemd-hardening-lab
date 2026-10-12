#!/usr/bin/env python3
"""build_criteria_v005.py --probe DIR --scenarios DIR [--bench SERVICE=DIR[+DIR...][:P,P...] ...]
                          [--level 0.05] [--family SERVICE=M ...] [--looks N] [--conditional] [--out FILE]

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
  goals_full                 the names of the goals counted in g(D)
  emicro                     <probe>/metrics.csv, column emicro_36; context
                             nginx-worker for Nginx (nginx-master is printed
                             for information)
  L95, U95d, cost_upper      <bench>/results.csv of the service: one-sided
                             bounds, as in audit_benchmark_csv_v005.py;
                             cost_upper is the increase of CPU time per
                             operation over P0, percent
  status                     NON_INFERIOR     L95 > 0 (the admission condition)
                             LOSS_EXCEEDS     U95d < 0
                             NEEDS_MORE_DATA  neither, and the planned
                                              extension has not been run
                             INCONCLUSIVE     neither, at the limit of looks
                             NOT_MEASURED     no load data

Level of the bounds (protocol_review2_v005.txt, section 7). Every bound is
computed at the level  --level / (M * --looks),  where M is the number of
restricted candidates of the service given by --family and --looks is the
planned number of analyses of a candidate (1 = no extension, 2 = one planned
extension). The defaults (--level 0.05, family 1, --looks 1) give the
uncorrected 95% bounds of the earlier revisions.

--bench may be given several times for one service. "SERVICE=DIR:P1,P2" takes
only the listed candidates from that series, so that the source series of
every candidate is fixed on the command line. Without a list the series
supplies every candidate it contains that an earlier --bench has not
supplied. "SERVICE=DIR1+DIR2" pools the blocks of an extension with the
first series (blocks are renumbered consecutively); such a candidate has
used two looks.

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

CONTEXT = {"nginx": "nginx-worker"}
ORDER = ["nginx", "redis", "postgresql"]


def load(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def goals_blocked(rows, service):
    """profile -> (fully blocked goals, blocked cells, residual goals); goals and cells achievable under P0."""
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
        result[p] = (full, len(blocked_cells), [g for g in goals if g not in full])
    unexpected = sorted({p for by in cells.values() for p, o in by.items() if o == "UNEXPECTED"})
    return result, len(goals), len(reachable), unexpected


def pooled_blocks(paths):
    """Blocks of one or several series, renumbered consecutively."""
    blocks = {}
    for path in paths:
        _, one, _, _ = read(path)
        offset = len(blocks)
        for b in sorted(one):
            blocks[offset + b] = one[b]
    return blocks


def bench_bounds(paths, alpha):
    """profile -> (L, U of the contrast, cost upper bound in percent, pairs); P0 is the baseline."""
    blocks = pooled_blocks(paths)
    numbers = sorted(blocks)
    t_one = t_quantile(1 - alpha, len(numbers) - 1)
    out = {}
    profiles = set.intersection(*(set(blocks[b]) for b in numbers))
    if "P0" not in profiles:
        raise ValueError(f"{paths[0]}: P0 is missing in some block")
    base = [blocks[b]["P0"] for b in numbers]
    margin = 0.05 * statistics.mean(x["value"] for x in base)
    out["P0"] = (margin, margin, 0.0, len(numbers))
    for p in sorted(profiles - {"P0"}):
        cand = [blocks[b][p] for b in numbers]
        d = [y["value"] - 0.95 * x["value"] for x, y in zip(base, cand)]
        logs = [math.log(y["cost"] / x["cost"]) for x, y in zip(base, cand)]
        _, _, lower, upper_d = bounds(d, t_one)
        _, _, _, upper = bounds(logs, t_one)
        out[p] = (lower, upper_d, 100 * (math.exp(upper) - 1), len(numbers))
    return out


def main():
    ap = argparse.ArgumentParser(description="Build the criteria table for select_profile_v005.py")
    ap.add_argument("--probe", required=True, type=Path)
    ap.add_argument("--scenarios", required=True, type=Path)
    ap.add_argument("--bench", action="append", default=[], metavar="SERVICE=DIR[+DIR...][:P,P...]")
    ap.add_argument("--level", type=float, default=0.05, help="family-wise level of a service")
    ap.add_argument("--family", action="append", default=[], metavar="SERVICE=M",
                    help="number of restricted candidates of the service (default 1)")
    ap.add_argument("--looks", type=int, default=1, help="planned number of analyses of a candidate")
    ap.add_argument("--conditional", action="store_true",
                    help="treat functional candidates without load data as admissible")
    ap.add_argument("--out", type=Path, default=Path("criteria_v005.csv"))
    args = ap.parse_args()

    metrics = {(r["context"], r["profile"]): r for r in load(args.probe / "metrics.csv")}
    candidates = load(args.scenarios / "candidates.csv")
    goals = load(args.scenarios / "goals.csv")
    family = defaultdict(lambda: 1)
    for item in args.family:
        service, _, m = item.partition("=")
        family[service] = int(m)
    bench, notes = defaultdict(dict), []
    for item in args.bench:
        service, _, rest = item.partition("=")
        directory, sep, only = rest.rpartition(":")
        if not sep or "/" in only or "\\" in only:
            directory, only = rest, ""
        parts = [Path(d) for d in directory.split("+")]
        alpha = args.level / (family[service] * args.looks)
        series = bench_bounds([d / "results.csv" for d in parts], alpha)
        name = "+".join(d.name for d in parts)
        wanted = [p for p in only.split(",") if p] or sorted(series)
        for p in wanted:
            if p not in series:
                raise SystemExit(f"{directory}: no complete data for {p}")
            if p not in bench[service]:
                bench[service][p] = series[p] + (name, len(parts))
        notes.append(f"{service}: series {name} supplies {' '.join(wanted)}"
                     + ("" if only else " (unless supplied by an earlier series)")
                     + f"; bounds at the level {alpha:g}")

    rows = []
    for service in ORDER + sorted({c["service"] for c in candidates} - set(ORDER)):
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
            m = metrics.get((CONTEXT.get(service, service), p))
            if p == "P0":
                emicro = 0.0
            elif m and m["valid"] == "1":
                emicro = float(m["emicro_36"])
            else:
                emicro = 0.0
                if functional:
                    notes.append(f"{service} {p}: no valid probe run, emicro set to 0")
            if p in bench[service]:
                lower, upper_d, cost, pairs, source, looks = bench[service][p]
                if lower > 0:
                    status = "NON_INFERIOR"
                elif upper_d < 0:
                    status = "LOSS_EXCEEDS"
                elif looks < args.looks:
                    status = "NEEDS_MORE_DATA"
                else:
                    status = "INCONCLUSIVE"
            else:
                lower, upper_d, cost, pairs, source, status = -1.0, -1.0, 0.0, 0, "-", "NOT_MEASURED"
                if functional and args.conditional:
                    lower = upper_d = 1.0
                    if p != "P0":
                        notes.append(f"{service} {p}: no load data, ASSUMED admissible (conditional rule B)")
                elif functional:
                    notes.append(f"{service} {p}: not benchmarked, L95 set to -1 (not admissible)")
            if service == "nginx":
                mm = metrics.get(("nginx-master", p))
                if mm and mm["valid"] == "1" and p != "P0":
                    notes.append(f"nginx {p}: master context emicro_36={float(mm['emicro_36']):.3f}, "
                                 f"required and still allowed: {mm['residual_required'] or '-'}")
            full, s, residual = blocked.get(p, ([], 0, []))
            if functional and p != "P0":
                notes.append(f"{service} {p}: goals not blocked in every cell: {' '.join(residual) or '-'}")
            rows.append({
                "service": service, "profile": p, "F": functional,
                "L95": f"{lower:.3f}", "cost_upper": f"{cost:.3f}",
                "goals_blocked": len(full), "cells_blocked": s, "emicro": f"{emicro:.3f}",
                "exposure": c["exposure"] if c["exposure"] not in ("", "NA") else "10",
                "n_directives": c["n_directives"], "U95d": f"{upper_d:.3f}",
                "status": "BASELINE" if p == "P0" else status, "goals_full": ";".join(full),
                "pairs": pairs, "source": source,
            })

    fields = ["service", "profile", "F", "L95", "cost_upper", "goals_blocked", "cells_blocked", "emicro",
              "exposure", "n_directives", "U95d", "status", "goals_full", "pairs", "source"]
    with args.out.open("w", newline="", encoding="utf-8") as f:
        f.write("# built by build_criteria_v005.py; cost_upper: CPU time per operation, % over P0\n")
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print(f"{'service':<11}{'profile':<8}{'F':>2}{'pairs':>6}{'L95':>11}{'U95d':>11}{'cost_up%':>10}"
          f"{'g':>3}{'s':>3}{'emicro':>8}{'expos':>7}{'n':>4}  {'status':<16}series")
    for r in rows:
        print(f"{r['service']:<11}{r['profile']:<8}{r['F']:>2}{r['pairs']:>6}{r['L95']:>11}{r['U95d']:>11}"
              f"{r['cost_upper']:>10}{r['goals_blocked']:>3}{r['cells_blocked']:>3}{r['emicro']:>8}"
              f"{r['exposure']:>7}{r['n_directives']:>4}  {r['status']:<16}{r['source']}")
    print()
    for n in notes:
        print("NOTE " + n)
    print(f"CSV={args.out}")
    print(f"NEXT: python3 select_profile_v005.py {args.out} --budgets 2,5,10,15")


if __name__ == "__main__":
    main()
