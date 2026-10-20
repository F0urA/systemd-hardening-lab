#!/usr/bin/env python3
"""point_estimates_v005.py RUN_DIR

Descriptive point estimates for the accepted series of a stage-3 package
(data/main: the run of 2026-10-12..14; data/rerun: the repeat of 2026-10-19/20,
chosen by the name of RUN_DIR): mean throughput, ratio to P0, mean CPU,
geometric-mean cost increase per operation over P0 and CV of throughput.
Pooled rows join a primary series with its single registered extension,
pairing within blocks of each series. The admission bounds themselves come
from analysis-final/*-criteria.csv; this script only adds the point values
used in the text. Python 3 standard library only.
"""
import csv
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path

RUN = Path(sys.argv[1])
PACKAGES = {  # series directories relative to RUN_DIR
    "main": {
        "R1": "raw-vm/nginx/benchmark-v005/20261012-175912",
        "R1ext": "raw-vm/nginx/benchmark-v005/20261013-221436",
        "R5": "raw-vm/nginx/benchmark-v005/20261013-204356",
        "R2": "raw-vm/redis/benchmark-v005/20261012-194224",
        "R3": "raw-vm/postgresql/benchmark-v005/20261013-193448",
        "R3ext": "raw-vm/postgresql/benchmark-v005/20261013-233151",
    },
    "rerun": {
        "R1": "raw-vm/nginx/benchmark-v005/20261019-172537",
        "R1ext": "raw-vm/nginx/benchmark-v005/20261019-222428",
        "R5": "raw-vm/nginx/benchmark-v005/20261019-211626",
        "R2": "raw-vm/redis/benchmark-v005/20261019-184311",
        "R3": "raw-vm/postgresql/benchmark-v005/20261019-194432",
        "R3ext": "raw-vm/postgresql/benchmark-v005/20261019-230632",
        "MC": "memcached/results_v005/memcached/benchmark-v005/20261020T032709Z-138512",
    },
}
SERIES = PACKAGES[RUN.resolve().name]
POOLED = {"R1+R1ext": ("R1", "R1ext"), "R3+R3ext": ("R3", "R3ext")}


def load(name):
    rows = list(csv.DictReader(open(RUN / SERIES[name] / "results.csv", encoding="utf-8")))
    data = defaultdict(dict)
    for r in rows:
        x = float(r.get("rps") or r.get("tps"))
        data[(name, int(r["block"]))][r["profile"]] = (x, float(r["cpu_pct"]), float(r["cpu_us_per_op"]))
    return data


def summary(label, blocks):
    profiles = sorted({p for b in blocks.values() for p in b}, key=lambda p: (p != "P0", p))
    p0 = statistics.mean(b["P0"][0] for b in blocks.values() if "P0" in b)
    print(f"== {label}: blocks={len(blocks)} mean X(P0)={p0:.1f}")
    for p in profiles:
        xs = [b[p][0] for b in blocks.values() if p in b]
        cpu = statistics.mean(b[p][1] for b in blocks.values() if p in b)
        cv = 100 * statistics.stdev(xs) / statistics.mean(xs)
        if p == "P0":
            print(f"  {p:4s} X={statistics.mean(xs):10.1f} cpu={cpu:6.2f}% cv={cv:4.1f}%")
            continue
        ratio = 100 * statistics.mean(xs) / p0
        logs = [math.log(b[p][2] / b["P0"][2]) for b in blocks.values() if p in b and "P0" in b]
        cost = 100 * (math.exp(statistics.mean(logs)) - 1)
        print(f"  {p:4s} X={statistics.mean(xs):10.1f} toP0={ratio:6.1f}% cost={cost:+5.1f}% "
              f"cpu={cpu:6.2f}% cv={cv:4.1f}% n={len(xs)}")


loaded = {name: load(name) for name in SERIES}
for name, data in loaded.items():
    summary(name, data)
for label, parts in POOLED.items():
    joined = {}
    for part in parts:
        joined.update(loaded[part])
    summary(label, joined)
