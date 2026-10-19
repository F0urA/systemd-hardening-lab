#!/usr/bin/env python3
"""Apply the frozen, unchanged v005 rule to registered memcached observations."""
import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
SCRIPTS = ROOT / "frozen-timing" / "v005" / "scripts_v005"
sys.path.insert(0, str(SCRIPTS))
import build_criteria_v005 as criteria
from inspect_series_v005 import inspect


def run(arguments, destination):
    with destination.open("w", encoding="utf-8", newline="\n") as file:
        subprocess.run([sys.executable, *map(str, arguments)], stdout=file,
                       stderr=subprocess.STDOUT, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--functional", required=True, type=Path)
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument("--bench", required=True, type=Path)
    parser.add_argument("--extension", type=Path)
    args = parser.parse_args()
    destination = ROOT / ("memcached-analysis-final" if args.extension else "memcached-analysis-first-look")
    destination.mkdir(exist_ok=True)
    with (args.functional / "contract.csv").open(newline="", encoding="utf-8-sig") as file:
        contracts = list(csv.DictReader(file))
    expected_profiles = {"P0", "P1", "P2", "P4", "P6"}
    if len(contracts) != 5 or {row["profile"] for row in contracts} != expected_profiles:
        raise SystemExit("Incomplete or duplicate registered contract family.")
    if any(row["service"] != "memcached" or row["contract"] not in {"PASS", "FAIL"} for row in contracts):
        raise SystemExit("Unknown contract status or unexpected service.")
    admitted_f = {row["profile"] for row in contracts if row["contract"] == "PASS"}
    if "P0" not in admitted_f:
        raise SystemExit("P0 contract failed: no valid memcached performance reference.")
    if admitted_f == {"P0"}:
        (destination / "OUTCOME.txt").write_text("NONE: every restricted profile failed F; no load inference.\n", encoding="utf-8")
        print("NONE: no restricted profile passed F")
        return
    validation = json.loads((args.probe / "probe-validation.json").read_text(encoding="utf-8"))
    if validation["failed"]:
        raise SystemExit("Incomplete model probes: refusing to fabricate Emicro or a policy ranking.")
    sources = [args.bench]
    if args.extension:
        if args.extension.resolve() == args.bench.resolve():
            raise SystemExit("A benchmark cannot be pooled with itself.")
        sources.append(args.extension)
    summaries = []
    registered = json.loads((args.functional / "registration" / "parameters.json").read_text())
    for look, source in enumerate(sources, 1):
        if (source / "FAILED.txt").exists():
            raise SystemExit(f"{source}: explicitly failed attempt is not analysis data")
        if "BENCHMARK_COMPLETE memcached" not in (source / "run.log").read_text():
            raise SystemExit(f"{source}: completed-run evidence missing")
        if json.loads((source / "registration" / "parameters.json").read_text()) != registered:
            raise SystemExit(f"{source}: different registration; pooling forbidden")
        summary = inspect(source)
        if summary["platform_lines"].get("LOOK") != str(look):
            raise SystemExit(f"{source}: wrong statistical look order")
        if set(summary["profiles"]) != admitted_f:
            raise SystemExit(f"{source}: candidate set differs from the registered F gate")
        for profile, values in summary["profiles"].items():
            if values["blocks"] != list(range(1, 21)) or values["failed"] or values["max_gap_ms"] > 500:
                raise SystemExit(f"{source}/{profile}: incomplete or invalid accepted observations")
        summaries.append(summary)
    (destination / "series-summary.json").write_text(json.dumps(summaries, indent=2), encoding="utf-8")
    bench = "+".join(str(source) for source in sources)
    output = destination / "criteria.csv"
    run([SCRIPTS / "build_criteria_v005.py", "--probe", args.probe, "--scenarios", args.functional,
         "--contract", args.functional, "--bench", f"memcached={bench}", "--level", "0.05",
         "--family", "memcached=4", "--looks", "2", "--out", output], destination / "criteria.txt")
    run([SCRIPTS / "select_profile_v005.py", output], destination / "selection.txt")
    measured = criteria.bench_bounds([source / "results.csv" for source in sources], 0.05 / 8)
    unresolved = [profile for profile in sorted(admitted_f - {"P0"})
                  if measured[profile][0] <= 0 <= measured[profile][1]]
    decision = {"family": 4, "looks_allowed": 2, "looks_used": len(sources),
                "needs_extension": bool(unresolved) and len(sources) == 1,
                "unresolved": unresolved, "G": [],
                "note": "Empty file-path goals do not imply absence of security risk."}
    (destination / "extension-decision.json").write_text(json.dumps(decision, indent=2), encoding="utf-8")
    print(json.dumps(decision, ensure_ascii=False))
    print(f"Analysis directory: {destination}")


if __name__ == "__main__":
    main()
