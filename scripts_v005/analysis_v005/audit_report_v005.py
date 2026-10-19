#!/usr/bin/env python3
"""Read-only verification of the already closed final outputs, not a new look.

Reads preserved evidence only. No VM access, series, exclusions, replanning,
or writes to frozen/source/raw/analysis paths. Optional output is a new audit.
"""
import argparse
import csv
import hashlib
import itertools
import json
import math
import statistics as st
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import analyze_v005 as frozen

RAW = ROOT / "raw-vm"
FINAL = ROOT / "analysis-final"


@lru_cache(None)
def t_critical(alpha, df):
    """Independent t quantile via density integration, not the frozen beta CDF."""
    norm = math.exp(math.lgamma((df + 1) / 2) - math.lgamma(df / 2)) / math.sqrt(df * math.pi)

    def density(x):
        return norm * math.exp(-(df + 1) / 2 * math.log1p(x * x / df))

    def integral(right):
        def refine(a, b, fa, fm, fb, whole, eps, depth):
            middle = (a + b) / 2
            fleft, fright = density((a + middle) / 2), density((middle + b) / 2)
            left = (middle - a) / 6 * (fa + 4 * fleft + fm)
            right_part = (b - middle) / 6 * (fm + 4 * fright + fb)
            error = left + right_part - whole
            if abs(error) <= 15 * eps:
                return left + right_part + error / 15
            require(depth > 0, "Independent density integration did not converge")
            return (refine(a, middle, fa, fleft, fm, left, eps / 2, depth - 1)
                    + refine(middle, b, fm, fright, fb, right_part, eps / 2, depth - 1))
        f0, fm, fr = density(0), density(right / 2), density(right)
        return refine(0, right, f0, fm, fr, right / 6 * (f0 + 4 * fm + fr), 2e-13, 24)

    lo, hi = 0.0, 16.0
    require(.5 + integral(hi) > 1 - alpha, "Independent quantile bracket")
    for _ in range(60):
        mid = (lo + hi) / 2
        if .5 + integral(mid) < 1 - alpha:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def read_csv(path):
    with Path(path).open(encoding="utf-8-sig", newline="") as file:
        return list(csv.DictReader(line for line in file if not line.startswith("#")))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def retry_history(directory):
    rows = read_csv(directory / "results.csv")
    invalid = read_csv(directory / "invalid.csv")
    by_cell = defaultdict(list)
    for row in invalid:
        require(row["reason"] == "stall" and float(row["max_gap_ms"]) > 500,
                f"Unexpected invalid reason: {directory}")
        by_cell[(row["block"], row["profile"])].append(int(row["attempt"]))
    for row in rows:
        key = row["block"], row["profile"]
        require(sorted(by_cell.pop(key, [])) == list(range(1, int(row["attempt"]))),
                f"Missing or extra retained attempts: {directory} {key}")
    require(not by_cell, f"Invalid rows without accepted successor: {directory}")
    return len(invalid)


def compact_series(directory, summary):
    data = read_csv(directory / "results.csv")
    proofs = summary["raw_count_audit"]
    return {
        "directory": directory.relative_to(RAW).as_posix(),
        "accepted": len(data),
        "invalid_stall_attempts": retry_history(directory),
        "csv_failed": sum(int(r["failed"]) for r in data),
        "results_sha256": sha(directory / "results.csv"),
        "profiles": summary["profiles"],
        "native_completed": sum(p["native_completed"] for p in proofs["measurements"])
                            if all("native_completed" in p for p in proofs["measurements"]) else None,
        "assigned_ops": sum(int(r["ops"]) for r in data),
        "count_limitations": proofs["limitations"],
    }


def pilots(ledger):
    result = {}
    for c in (1, 2, 4, 8, 16):
        entry = next(r for r in ledger if r["stage"] == f"R4-pilot-c{c}")
        directory = frozen.local_path(entry["result_directory"])
        rows = read_csv(directory / "results.csv")
        require(entry["exit_status"] == "0" and len(rows) == 6, "Pilot not closed")
        require({(int(r["block"]), r["profile"]) for r in rows} ==
                set(itertools.product(range(1, 4), ("P0", "P4"))), "Pilot matrix")
        for b in range(1, 4):
            require(sorted(int(r["order"]) for r in rows if int(r["block"]) == b) == [1, 2],
                    "Pilot orders")
        params = frozen.platform_parameters(directory)
        expected = {"SERVICE": "nginx", "BLOCKS": "3", "PIN": "1", "SERVER_CPU": "0",
                    "CLIENT_CPUS": "1-3", "KEEPALIVE": "0", "NGINX_N": "100000",
                    "NGINX_C": str(c), "STALL_MS": "500", "ELAPSED_CLOCK": "CLOCK_MONOTONIC_RAW"}
        require(all(params.get(k) == v for k, v in expected.items()), "Pilot parameter mismatch")
        for row in rows:
            require(all(math.isfinite(float(row[k])) for k in ("rps", "cpu_pct", "cpu_us_per_op", "max_gap_ms"))
                    and float(row["rps"]) > 0 and float(row["cpu_us_per_op"]) > 0
                    and int(row["failed"]) == 0 and 0 <= float(row["max_gap_ms"]) <= 500
                    and int(row["wall_ns"]) > 0 and 1 <= int(row["attempt"]) <= 5,
                    "Pilot accepted-row validity")
        require(sha(directory / "results.csv") == (directory / "sha256-results.txt").read_text().split()[0],
                "Pilot CSV hash")
        text = (directory / "run.log").read_text()
        require("===== BENCHMARK COMPLETE =====" in text and "RESTORE_P4 nginx=PASS" in text,
                "Pilot closure or restoration missing")
        proof = frozen.raw_count_audit("nginx", directory, rows, params)
        cpu = [float(r["cpu_pct"]) for r in rows if r["profile"] == "P0"]
        result[str(c)] = {"directory": directory.relative_to(RAW).as_posix(), "accepted": 6,
                          "invalid": retry_history(directory), "p0_cpu_pct": cpu,
                          "condition_met": all(40 <= v <= 70 for v in cpu),
                          "native_completed": sum(p["native_completed"] for p in proof["measurements"]),
                          "results_sha256": sha(directory / "results.csv")}
    require(not any(r["condition_met"] for r in result.values()), "R4 failure not justified")
    return result


def independent_bounds(directories, profile, family):
    d, costs = [], []
    for directory in directories:
        rows = read_csv(directory / "results.csv")
        blocks = defaultdict(dict)
        for row in rows:
            blocks[int(row["block"])][row["profile"]] = row
        for b in sorted(blocks):
            p0, candidate = blocks[b]["P0"], blocks[b][profile]
            metric = "tps" if "tps" in candidate else "rps"
            d.append(float(candidate[metric]) - .95 * float(p0[metric]))
            costs.append(math.log(float(candidate["cpu_us_per_op"]) / float(p0["cpu_us_per_op"])))
    alpha = .05 / (family * 2)
    critical = t_critical(alpha, len(d) - 1)
    se_d, se_cost = st.stdev(d) / math.sqrt(len(d)), st.stdev(costs) / math.sqrt(len(costs))
    return {"L": st.mean(d) - critical * se_d, "U": st.mean(d) + critical * se_d,
            "cost_upper": 100 * math.expm1(st.mean(costs) + critical * se_cost),
            "pairs": len(d), "M": family, "K": 2, "alpha": alpha}


def check_bounds(path, service_sources, families):
    checks = []
    for row in read_csv(path):
        if row["profile"] == "P0":
            continue
        service, profile = row["service"], row["profile"]
        sources = service_sources[(service, profile)]
        calc = independent_bounds(sources, profile, families[service])
        require(int(row["pairs"]) == calc["pairs"], "Wrong pair count")
        require(row["source"] == "+".join(p.name for p in sources), "Wrong source membership")
        # CSV is rounded to 0.001. Tolerance is solely the published rounding.
        for actual, label in (("L95", "L"), ("U95d", "U"), ("cost_upper", "cost_upper")):
            require(abs(float(row[actual]) - calc[label]) <= .000501, f"Bounds differ: {service} {profile} {actual}")
        status = "NON_INFERIOR" if calc["L"] > 0 else "LOSS_EXCEEDS" if calc["U"] < 0 else "INCONCLUSIVE"
        require(row["status"] == status, "Wrong terminal throughput status")
        checks.append({"service": service, "profile": profile, **calc})
    return checks


def pick(rows, order):
    signs = {"g": -1, "s": -1, "emicro": -1, "exposure": 1, "n": 1}
    columns = {"g": "goals_blocked", "s": "cells_blocked", "emicro": "emicro",
               "exposure": "exposure", "n": "n_directives"}
    if not rows:
        return "NONE"
    keys = [(tuple(signs[k] * float(r[columns[k]]) for k in order), r["profile"]) for r in rows]
    best = min(k for k, p in keys)
    winners = [p for k, p in keys if k == best]
    return winners[0] if len(winners) == 1 else "TIE(" + "/".join(winners) + ")"


def criteria_and_policies():
    table = read_csv(FINAL / "combined-criteria-INCOMPLETE_SCOPE.csv")
    contract = read_csv(RAW / "functional-v005/20261012-104934/contract.csv")
    gates = {(r["service"], r["profile"]): r["contract"] for r in contract}
    scenarios = read_csv(RAW / "scenarios-v005/20261012-110837/goals.csv")
    candidates = {(r["service"], r["profile"]): r for r in read_csv(RAW / "scenarios-v005/20261012-110837/candidates.csv")}
    metrics = {(r["context"], r["profile"]): r for r in read_csv(RAW / "probe-v005/20261012-110043/metrics.csv")}
    cells = defaultdict(dict)
    for r in scenarios:
        if r["outcome"] != "INFO":
            key = (r["service"], r["goal"], r["dac"], r["context"])
            require(r["profile"] not in cells[key], "Duplicate primary goal cell")
            cells[key][r["profile"]] = r["outcome"]
    for r in table:
        identity = r["service"], r["profile"]
        c = candidates[identity]
        expected_f = int(c["functional"] == "1" and gates.get(identity) == "PASS")
        require(int(r["F"]) == expected_f and r["contract"] == gates[identity], "F evidence mismatch")
        eligible = {k: v for k, v in cells.items() if k[0] == r["service"] and v.get("P0") == "ACHIEVED"}
        blocked = [k for k, v in eligible.items() if v.get(r["profile"]) == "BLOCKED"]
        goals = {k[1] for k in eligible}
        full = sorted(g for g in goals if all(v.get(r["profile"]) == "BLOCKED" for k, v in eligible.items() if k[1] == g))
        require(int(r["cells_blocked"]) == len(blocked) and int(r["goals_blocked"]) == len(full)
                and r["goals_full"] == ";".join(full), "Goal gate mismatch")
        ctx = "nginx-worker" if r["service"] == "nginx" else r["service"]
        m = metrics[(ctx, r["profile"])]
        require(m["valid"] == "1" and abs(float(r["emicro"]) - float(m["emicro_36"])) <= .000501,
                "Microprobe criterion mismatch")
        require(float(r["exposure"]) == float(c["exposure"]) and int(r["n_directives"]) == int(c["n_directives"]),
                "Exposure/directive criterion mismatch")
    actual = read_csv(FINAL / "policy24.csv")
    require(len(actual) == 288 and len({(r["service"], r["budget"], r["policy"]) for r in actual}) == 288,
            "Wrong policy24 size or duplicate")
    policies = set(itertools.permutations(("s", "emicro", "exposure", "n")))
    decisions, counts = [], defaultdict(Counter)
    for service in ("nginx", "redis", "postgresql"):
        rows = [r for r in table if r["service"] == service]
        for h in (2, 5, 10, 15):
            admitted = [r for r in rows if r["profile"] != "P0" and r["F"] == "1"
                        and float(r["L95"]) > 0 and float(r["cost_upper"]) <= h]
            subset = [r for r in actual if r["service"] == service and int(r["budget"]) == h]
            require({tuple(r["policy"].split(";")) for r in subset} == policies, "Incomplete policy matrix")
            for r in subset:
                require(r["outcome"] == pick(admitted, ["g", *r["policy"].split(";")]), "g-first policy mismatch")
                counts[f"{service}:H={h}"][r["outcome"]] += 1
            decisions.append({"service": service, "H": h, "admitted": [r["profile"] for r in admitted],
                              "A": pick([r for r in rows if r["F"] == "1"], ["exposure", "n"]),
                              "A+": pick(admitted, ["exposure", "n"]), "B": pick(admitted, ["g"]),
                              "B_default": pick(admitted, ["g", "s", "emicro", "exposure", "n"])})
    return {"criteria_rows_verified": len(table), "decisions": decisions,
            "policy_rows_verified": len(actual), "policy_counts": dict(counts)}


def supplemental():
    cap_dir = RAW / "scenarios-v005/20261014-002436"
    cap = read_csv(cap_dir / "goals.csv")
    profiles = {"P0", "P1r", "P1c", "P1cADMIN", "P1cPTRACE", "P1cDAC", "P1cCHROOT"}
    require(len(cap) == 70 and {r["profile"] for r in cap} == profiles, "Incomplete CAP scenario matrix")
    require(len({(r["profile"], r["goal"], r["dac"], r["context"]) for r in cap}) == 70, "Duplicate CAP cell")
    require(all(r["outcome"] in {"ACHIEVED", "BLOCKED"} for r in cap), "CAP unexpected result")
    contract = read_csv(RAW / "functional-v005/20261014-002104/contract.csv")
    require({r["profile"] for r in contract if r["service"] == "nginx"} == profiles
            and len(contract) == 9 and all(r["contract"] == "PASS" for r in contract), "CAP F/TLS matrix")
    fd = read_csv(RAW / "supplement-goals-v005/20261012-105904/goals.csv")
    require(len(fd) == 64 and len({(r["profile"], r["dac"], r["context"]) for r in fd}) == 64, "FD matrix")
    require(all(r["outcome"] in {"ACHIEVED", "BLOCKED"} and "http=200" in r["detail"] for r in fd), "FD verdict")
    mount = RAW / "mount-states-v005/20261014-002458-064fbb607ff2b76d"
    rows = read_csv(mount / "observations.csv")
    matrix = set(itertools.product(("late", "nested"), ("P0", "P1r", "P1c", "P5", "P6"),
                                   ("rootown", "labweb"), ("master", "worker")))
    require(len(rows) == 40 and {(r["mode"], r["profile"], r["dac"], r["context"]) for r in rows} == matrix,
            "Mount-state matrix")
    controls = {(r["mode"], r["dac"], r["context"]): r["provisional"] for r in rows if r["profile"] == "P0"}
    for r in rows:
        cell = "-".join(r[k] for k in ("mode", "profile", "dac", "context"))
        obs = json.loads((mount / "cells" / cell / "observation.json").read_text())
        require(obs["baseline_http"] == "200" and obs["final_http"] == "200" and obs["baseline_ok"], "Mount HTTP proof")
        baseline = controls[(r["mode"], r["dac"], r["context"])]
        require(r["eligible"] == str(int(baseline == "ACHIEVED")) and r["control_outcome"] == baseline,
                "Mount eligibility")
        expected = "NOT_REPRODUCED" if r["provisional"] == "BLOCKED" and baseline != "ACHIEVED" else r["provisional"]
        require(r["outcome"] == expected and "evidence_errors=[]" in r["detail"], "Mount classification/evidence")
        if r["outcome"] == "ACHIEVED":
            require(obs["model_result"]["result"] == "ALLOWED" and obs["model_result"]["state_reproduced"]
                    and bytes.fromhex(obs["final_body_hex"]) == b"G1_REPLACED_DOCUMENT\n", "Mount achieved proof")
    summary = json.loads((mount / "summary.json").read_text())
    counts = Counter(r["outcome"] for r in rows)
    require(all(summary["counts"][k] == counts[k] for k in summary["counts"]) and summary["complete_cells"]
            and not summary["selection_input"] and summary["status"] == "COMPLETE", "Mount summary mismatch")
    context = (RAW / "context-v005/20261012-105616/run.log").read_text()
    require(context.count("inservice_vs_transient=IDENTICAL (36 probes)") == 13, "Context status comparison")
    return {"CAP": {"functional_contracts": len(contract), "scenario_cells": len(cap),
                    "G1": [r for r in cap if r["goal"] == "G1-replace-document"]},
            "FD": {"cells": len(fd), "counts": dict(Counter(r["outcome"] for r in fd)),
                   "P1c_inherited": [r for r in fd if r["profile"] == "P1c" and r["context"].startswith("fd-")]},
            "mount_state": {"summary": summary, "observations": rows}, "context_status_matches": 13}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    series, coverage = frozen.completed_series()
    plan = frozen.saved_plan(ROOT / "extension-plan.json", series, coverage)
    extensions, ext_coverage = frozen.extension_map(plan)
    compact = {stage: compact_series(path, coverage[stage]["summary"]) for stage, path in series.items()}
    ext_compact = {stage: compact_series(path, ext_coverage[stage]["summary"]) for stage, path in extensions.items()}
    service_sources = {}
    for stage, directory in series.items():
        service, _, profiles, _ = frozen.SPEC[stage]
        selected = next((e["profiles"] for e in plan["extensions"] if e["stage"] == stage), [])
        for profile in profiles:
            service_sources[(service, profile)] = [directory] + ([extensions[stage]] if profile in selected else [])
    combined = check_bounds(FINAL / "combined-criteria-INCOMPLETE_SCOPE.csv", service_sources,
                            {"nginx": 7, "redis": 5, "postgresql": 5})
    standalone = {}
    for stage in series:
        family = 4 if stage == "R1-nginx" else 3 if stage == "R5-nginx-light" else 5
        standalone[stage] = check_bounds(FINAL / f"{stage}-criteria.csv", service_sources,
                                        {frozen.SPEC[stage][0]: family})
    excluded = {}
    for service, stamp in (("nginx", "20261012-110140"), ("nginx", "20261012-110940"),
                           ("postgresql", "20261012-210220")):
        directory = RAW / service / "benchmark-v005" / stamp
        excluded[f"{service}/{stamp}"] = {"accepted_csv_rows_not_pooled": len(read_csv(directory / "results.csv")),
                                           "retained_invalid_rows": len(read_csv(directory / "invalid.csv"))}
    totals = {"accepted_main_and_extensions": sum(r["accepted"] for r in (*compact.values(), *ext_compact.values())),
              "invalid_stall_attempts": sum(r["invalid_stall_attempts"] for r in (*compact.values(), *ext_compact.values()))}
    result = {"schema": "v005-final-report-audit-1", "utc": datetime.now(timezone.utc).isoformat(),
              "read_only_sources": True, "new_statistical_look": False,
              "validation": "PASS", "overall_scientific_scope": "INCOMPLETE_SCOPE",
              "primary_coverage": {n: r["status"] for n, r in coverage.items()},
              "extension_coverage": {n: r["status"] for n, r in ext_coverage.items()},
              "plan_sha256": sha(ROOT / "extension-plan.json"), "series": compact, "extensions": ext_compact,
              "R4_pilots": pilots(frozen.read_ledger(RAW / "driver/primary-corrected-ledger.csv")),
              "excluded_attempts": excluded, "totals": totals,
              "independent_combined_bounds": combined, "independent_standalone_bounds": standalone,
              "selection": criteria_and_policies(), "supplemental": supplemental()}
    if args.out:
        require(args.out.resolve().parent == ROOT and not args.out.exists(), "Audit destination must be new in results")
        args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("validation", "overall_scientific_scope", "totals", "excluded_attempts", "selection")},
                     indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
