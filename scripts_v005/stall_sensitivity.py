#!/usr/bin/env python3
"""stall_sensitivity.py RUN_DIR [--out-csv FILE]

The measurements repeated because of a VM pause (invalid.csv of every series) and
how much the admission bounds depend on the rule that repeats them. Written after
the experiment; the admission rule itself (build_criteria_v005.py) is not changed.

Per service, for the series and profiles of the combined analysis (data/main or
data/rerun, by the name of RUN_DIR):

  attempts   accepted and repeated measurements per profile, longest pause;
  load       server CPU load, throughput against load (Pearson r over all
             accepted measurements), coefficient of variation of the throughput
             and of the CPU time per operation under P0;
  bounds     the lower bound L of the mean contrast X(D) - 0.95 X(P0) at the level
             of the combined analysis, alpha = 0.05 / (M * K), K = 2, computed
             three ways:
               accepted  -- the measurements of the analysis (the rule as run);
               first     -- the first attempt of every profile in every block,
                            stalled or not (invalid.csv has no CPU time, so only the
                            throughput condition is recomputed);
               clean     -- only the blocks in which no measurement was repeated.

"accepted" reproduces L of the combined criteria table; the other two show whether
the outcome NON_INFERIOR / LOSS_EXCEEDS / INCONCLUSIVE would change.
"""
import argparse
import csv
import math
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from audit_benchmark_csv_v005 import bounds, t_quantile  # noqa: E402

LOOKS = 2
SERIES = {
    "main": {
        "R1": "nginx/benchmark-v005/20261012-175912", "R1EXT": "nginx/benchmark-v005/20261013-221436",
        "R5": "nginx/benchmark-v005/20261013-204356", "R2": "redis/benchmark-v005/20261012-194224",
        "R3": "postgresql/benchmark-v005/20261013-193448", "R3EXT": "postgresql/benchmark-v005/20261013-233151"},
    "rerun": {
        "R1": "nginx/benchmark-v005/20261019-172537", "R1EXT": "nginx/benchmark-v005/20261019-222428",
        "R5": "nginx/benchmark-v005/20261019-211626", "R2": "redis/benchmark-v005/20261019-184311",
        "R3": "postgresql/benchmark-v005/20261019-194432", "R3EXT": "postgresql/benchmark-v005/20261019-230632"},
}
# service -> (M, {profile: series pooled for it}), as in the combined analysis
COMBINED = {
    "main": {
        "nginx": (7, {"P1": ("R5",), "P2": ("R5",), "P1r": ("R5",), "P1c": ("R1",),
                      "P4": ("R1", "R1EXT"), "P5": ("R1", "R1EXT"), "P6": ("R1", "R1EXT")}),
        "redis": (5, {p: ("R2",) for p in ("P1", "P2", "P1d", "P4", "P6")}),
        "postgresql": (5, {"P1": ("R3",), "P1d": ("R3",), "P2": ("R3", "R3EXT"),
                           "P4": ("R3", "R3EXT"), "P6": ("R3", "R3EXT")}),
    },
    "rerun": {
        "nginx": (7, {"P1": ("R5",), "P2": ("R5",), "P1r": ("R5",), "P1c": ("R1",), "P5": ("R1",),
                      "P4": ("R1", "R1EXT"), "P6": ("R1", "R1EXT")}),
        "redis": (5, {p: ("R2",) for p in ("P1", "P2", "P1d", "P4", "P6")}),
        "postgresql": (5, {p: ("R3", "R3EXT") for p in ("P1", "P2", "P1d", "P4", "P6")}),
    },
}
OUTCOME = {(True, False): "NON_INFERIOR", (False, True): "LOSS_EXCEEDS", (False, False): "INCONCLUSIVE"}


def read_series(run, path):
    """Accepted rows by (block, profile) and the first attempt of every repeated one."""
    raw = run / "raw-vm" / path
    rows = list(csv.DictReader(open(raw / "results.csv", encoding="utf-8")))
    col = "tps" if "tps" in rows[0] else "rps"
    accepted = {(int(r["block"]), r["profile"]): r for r in rows}
    for r in accepted.values():
        r["x"] = float(r[col])
    invalid = list(csv.DictReader(open(raw / "invalid.csv", encoding="utf-8")))
    first = {(int(r["block"]), r["profile"]): float(r["throughput"]) for r in invalid if r["attempt"] == "1"}
    return accepted, invalid, first


def lower(d, alpha):
    _, _, low, high = bounds(d, t_quantile(1 - alpha, len(d) - 1))
    return low, OUTCOME[(low > 0, high < 0)]


def service_report(run, series, service, family):
    m, profiles = family
    alpha = 0.05 / (m * LOOKS)
    data = {name: read_series(run, series[name]) for name in {s for v in profiles.values() for s in v}}
    out, rows = [], []
    accepted_all = [r for name in sorted(data) for r in data[name][0].values()]
    invalid_all = [r for name in sorted(data) for r in data[name][1]]
    x = [r["x"] for r in accepted_all]
    load = [float(r["cpu_pct"]) for r in accepted_all]
    p0 = [r for r in accepted_all if r["profile"] == "P0"]
    cv = lambda v: 100 * statistics.stdev(v) / statistics.mean(v)
    out.append(f"== {service}: M={m}, alpha={alpha:.5f}; series {', '.join(sorted(data))}")
    out.append(f"accepted {len(accepted_all)}, repeated {len(invalid_all)} "
               f"({100 * len(invalid_all) / (len(accepted_all) + len(invalid_all)):.1f} % of attempts), "
               f"longest pause {max([float(r['max_gap_ms']) for r in invalid_all] or [0]):.0f} ms")
    out.append(f"server CPU load {min(load):.1f}-{max(load):.1f} %, mean {statistics.mean(load):.1f} %; "
               f"r(throughput, load) = {statistics.correlation(x, load):.3f}; "
               f"P0: CV throughput {cv([r['x'] for r in p0]):.1f} %, "
               f"CV CPU per operation {cv([float(r['cpu_us_per_op']) for r in p0]):.1f} %")
    per = {}
    for r in invalid_all:
        per[r["profile"]] = per.get(r["profile"], 0) + 1
    out.append("repeated by profile: " + ", ".join(f"{p} {per.get(p, 0)}" for p in ["P0", *profiles]))
    out.append(f"{'profile':8}{'n':>4} {'L accepted':>11} {'outcome':>13} | {'n':>4} {'L first':>9} {'outcome':>13}"
               f" | {'n':>4} {'L clean':>9} {'outcome':>13}")
    for prof, names in profiles.items():
        acc, fst, cln = [], [], []
        for name in names:
            accepted, invalid, first = data[name]
            repeated = {int(r["block"]) for r in invalid}
            for block in sorted({b for b, _ in accepted}):
                if (block, prof) not in accepted:
                    continue
                a0, a1 = accepted[(block, "P0")]["x"], accepted[(block, prof)]["x"]
                acc.append(a1 - 0.95 * a0)
                fst.append(first.get((block, prof), a1) - 0.95 * first.get((block, "P0"), a0))
                if block not in repeated:
                    cln.append(a1 - 0.95 * a0)
        la, oa = lower(acc, alpha)
        lf, of = lower(fst, alpha)
        lc, oc = lower(cln, alpha) if len(cln) > 2 else (float("nan"), "TOO_FEW")
        out.append(f"{prof:8}{len(acc):>4} {la:11.1f} {oa:>13} | {len(fst):>4} {lf:9.1f} {of:>13}"
                   f" | {len(cln):>4} {lc:9.1f} {oc:>13}")
        rows.append({"service": service, "profile": prof, "M": m, "n_accepted": len(acc), "L_accepted": la,
                     "outcome_accepted": oa, "n_first": len(fst), "L_first": lf, "outcome_first": of,
                     "n_clean": len(cln), "L_clean": lc, "outcome_clean": oc, "repeated": per.get(prof, 0),
                     "repeated_P0": per.get("P0", 0)})
    changed = [r["profile"] for r in rows if len({r["outcome_accepted"], r["outcome_first"]} - {"TOO_FEW"}) > 1
               or r["outcome_clean"] not in (r["outcome_accepted"], "TOO_FEW")]
    out.append("OUTCOMES_ROBUST" if not changed else "OUTCOMES_DEPEND_ON_REPEATS: " + ", ".join(changed))
    return out, rows


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run", type=Path)
    ap.add_argument("--out-csv", type=Path)
    a = ap.parse_args()
    name = a.run.resolve().name
    lines, rows = [], []
    for service, family in COMBINED[name].items():
        text, r = service_report(a.run, SERIES[name], service, family)
        lines += text + [""]
        rows += r
    print("\n".join(lines).rstrip())
    if a.out_csv:
        with open(a.out_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            for r in rows:
                w.writerow({k: (f"{v:.4f}" if isinstance(v, float) else v) for k, v in r.items()})


if __name__ == "__main__":
    main()
