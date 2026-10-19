#!/usr/bin/env python3
"""Retrospective bounds only; immutable archive is never pooled with new data."""
import csv
import json
import math
import statistics
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
SCRIPTS = ROOT / "frozen-primary" / "v005" / "scripts_v005"
sys.path.insert(0, str(SCRIPTS))
from build_criteria_v005 import bench_bounds

REFERENCE = ROOT.parent / "experiment-work" / "reference" / "results_v005"
SERIES = [
    ("nginx", "20261011-192019", 20, 7, "old saturation 1"),
    ("nginx", "20261011-201906", 20, 3, "old CPU-group diagnostic 1"),
    ("nginx", "20261011-203853", 20, 7, "old saturation 2"),
    ("nginx", "20261011-204708", 20, 3, "old CPU-group diagnostic 2"),
    ("nginx", "20261012-090309", 60, 7, "old light-profile stage 2"),
    ("redis", "20261011-192829", 20, 5, "old Redis"),
    ("postgresql", "20261011-194534", 10, 5, "old PostgreSQL"),
]


def main():
    out = ROOT / "archive-retrospective"
    out.mkdir(exist_ok=True)
    rows = []
    for service, stamp, expected, family, note in SERIES:
        path = REFERENCE / service / "benchmark-v005" / stamp / "results.csv"
        with path.open(newline="", encoding="utf-8-sig") as stream:
            source = list(csv.DictReader(stream))
        profiles = {row["profile"] for row in source}
        blocks = {}
        for row in source:
            key = (int(row["block"]), row["profile"])
            if key in blocks or int(row["failed"]) or float(row["max_gap_ms"]) > 500:
                raise ValueError(f"{path}: invalid/duplicate accepted archive observation")
            blocks[key] = row
        if set(blocks) != {(block, profile) for block in range(1, expected + 1) for profile in profiles}:
            raise ValueError(f"{path}: incomplete archive blocks")
        metric = "rps" if "rps" in source[0] else "tps"
        bounds = bench_bounds([path], 0.05 / (family * 2))
        baseline = [blocks[block, "P0"] for block in range(1, expected + 1)]
        baseline_mean = statistics.mean(float(row[metric]) for row in baseline)
        for profile in sorted(profiles - {"P0"}):
            lower, upper, cost_upper, pairs = bounds[profile]
            candidate = [blocks[block, profile] for block in range(1, expected + 1)]
            mean = statistics.mean(float(row[metric]) for row in candidate)
            log_cost = [math.log(float(c["cpu_us_per_op"]) / float(b["cpu_us_per_op"]))
                        for b, c in zip(baseline, candidate)]
            status = "NON_INFERIOR" if lower > 0 else "INFERIOR" if upper < 0 else "UNRESOLVED_ARCHIVE"
            rows.append(dict(service=service, archive_series=stamp, diagnostic=note, profile=profile,
                             pairs=pairs, M=family, K=2, alpha=0.05 / (family * 2),
                             baseline_mean=baseline_mean, candidate_mean=mean, ratio=mean / baseline_mean,
                             L_contrast=lower, U_contrast=upper,
                             geometric_cost_increase_pct=100 * (math.exp(statistics.mean(log_cost)) - 1),
                             U_cost_pct=cost_upper, status=status))
    with (out / "bounds.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (out / "scope.json").write_text(json.dumps({
        "retrospective": True, "new_measurements": False, "pooled_with_new": False,
        "family_policy": "Current conservative Nginx=7, Redis/PG=5; old CPU-group diagnostic=3; K=2",
        "limitations": ["Archive renamed v004 data, not a new v005 stage",
                        "Archive timing/hardware cannot be independently validated now",
                        "No mandatory expanded F gate available in old criteria; no profile recommendation",
                        "UNRESOLVED_ARCHIVE is not a newly permitted additional look"],
        "series": len(SERIES), "contrasts": len(rows)
    }, indent=2), encoding="utf-8")
    print(f"Retrospective archive contrasts: {len(rows)}. No new/old pooling or selection.")


if __name__ == "__main__":
    main()
