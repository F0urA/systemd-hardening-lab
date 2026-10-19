#!/usr/bin/env python3
"""Read-only audit of a new series; no block removal or threshold adjustment."""
import argparse
import csv
import json
import statistics as st
from pathlib import Path


def inspect(directory):
    directory = Path(directory)
    with (directory / "results.csv").open(newline="", encoding="utf-8-sig") as file:
        rows = list(csv.DictReader(file))
    groups = {}
    for row in rows:
        groups.setdefault(row["profile"], []).append(row)
    profiles = {}
    for profile, data in sorted(groups.items()):
        metric = "rps" if "rps" in data[0] else "tps"
        values = [float(row[metric]) for row in data]
        mean = st.mean(values)
        profiles[profile] = {
            "n": len(data), "blocks": sorted(int(row["block"]) for row in data),
            "mean_throughput": mean, "cv_pct": 100 * st.stdev(values) / mean if len(values) > 1 else None,
            "mean_cpu_pct": st.mean(float(row["cpu_pct"]) for row in data),
            "min_cpu_pct": min(float(row["cpu_pct"]) for row in data),
            "max_cpu_pct": max(float(row["cpu_pct"]) for row in data),
            "mean_cpu_us_per_op": st.mean(float(row["cpu_us_per_op"]) for row in data),
            "max_gap_ms": max(float(row["max_gap_ms"]) for row in data),
            "failed": sum(int(row["failed"]) for row in data),
        }
    with (directory / "invalid.csv").open(newline="", encoding="utf-8-sig") as file:
        invalid = list(csv.DictReader(file))
    expected = {line.partition("=")[0]: line.partition("=")[2].strip()
                for line in (directory / "platform.txt").read_text().splitlines() if "=" in line}
    return {"directory": str(directory), "profiles": profiles, "invalid_count": len(invalid),
            "rows": len(rows), "platform_lines": expected}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    parser.add_argument("--expect-blocks", type=int)
    parser.add_argument("--expect-profiles")
    parser.add_argument("--pilot", action="store_true")
    args = parser.parse_args()
    result = inspect(args.directory)
    errors = []
    if args.expect_profiles and set(result["profiles"]) != set(args.expect_profiles.split(",")):
        errors.append("profile set differs from expected")
    if args.expect_blocks:
        for profile, data in result["profiles"].items():
            if data["blocks"] != list(range(1, args.expect_blocks + 1)):
                errors.append(f"{profile}: missing/duplicate blocks")
    for profile, data in result["profiles"].items():
        if data["failed"] or data["max_gap_ms"] > 500:
            errors.append(f"{profile}: invalid accepted measurement")
    if args.pilot:
        baseline = result["profiles"].get("P0", {})
        if baseline.get("n") != 10 or baseline.get("cv_pct") is None or baseline["cv_pct"] > 5:
            errors.append("pilot CV(P0)<=5% condition is not met")
    result["audit_errors"] = errors
    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(bool(errors))


if __name__ == "__main__":
    main()
