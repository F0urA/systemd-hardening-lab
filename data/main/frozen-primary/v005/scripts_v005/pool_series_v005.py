#!/usr/bin/env python3
"""pool_series_v005.py OUT_CSV RESULTS_CSV RESULTS_CSV [...]

Concatenates the results of several series into one file with consecutive
block numbers, for the 40-block sensitivity calculation described in
protocol_load_repeat_v005.txt, section 4. The pooled file is then given to
audit_benchmark_csv_v005.py or ablation_report_v005.py. Standard library only.
"""
import csv
import sys


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 64
    out, sources = sys.argv[1], sys.argv[2:]
    rows, fields, offset = [], None, 0
    for src in sources:
        with open(src, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            fields = fields or reader.fieldnames
            part = list(reader)
        for r in part:
            r["block"] = str(int(r["block"]) + offset)
        offset = max(int(r["block"]) for r in part)
        rows.extend(part)
    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"{out}: {len(rows)} rows, {offset} blocks from {len(sources)} series")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
