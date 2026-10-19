#!/usr/bin/env python3
"""metric_summary_v004.py RESULT_DIR

Reads probe outputs named <context>__<profile>.txt (written by
probe_all_v004.sh or context_compare_v004.sh) and prints, for every context
and profile, the baseline-calibrated metrics. Python 3 standard library only.

Differences from metric_summary.py:
  * the baseline is <context>__P0.txt produced by the same launcher;
  * the extended probes X1..X4 are counted (Emicro over 36 probes);
  * operations required by the service are not silently dropped: they are
    listed as residual privileges, and Emicro is reported both with them
    excluded (comparable with the earlier text) and included;
  * every eligible operation that stays ALLOWED is listed by name.
"""
import csv
import re
import sys
from pathlib import Path

CATEGORIES = {
    "FS":   ["FS-1", "FS-2", "FS-3", "FS-4"],
    "DEV":  ["DEV-1", "DEV-2", "DEV-3", "DEV-4"],
    "KER":  ["KER-1", "KER-2", "KER-3", "KER-4"],
    "PROC": ["PROC-1", "PROC-2", "PROC-3", "PROC-4"],
    "PRIV": ["PRIV-1", "PRIV-2", "PRIV-3", "PRIV-4"],
    "NS":   ["NS-1", "NS-2", "NS-3", "NS-4"],
    "NET":  ["NET-1", "NET-2", "NET-3", "NET-4"],
    "ADV":  ["ADV-1", "ADV-2", "ADV-3", "ADV-4"],
}
BASIC = [t for tests in CATEGORIES.values() for t in tests]
EXTENDED = ["X1", "X2", "X3", "X4"]
# Operations the service itself needs; keyed by context-name suffix.
REQUIRED = {"nginx-master": {"PRIV-1", "PRIV-2"}}

LINE_RE = re.compile(r"^([A-Z]+-\d+|X\d)\s+(ALLOWED|BLOCKED|N/A|ERROR)\b")
PROFILE_ORDER = ["P0", "P1", "P1r", "P1c", "P2", "P3", "P4", "P5", "P6"]


def parse(path):
    result = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = LINE_RE.match(line.strip())
        if m:
            result[m.group(1)] = m.group(2)
    return result


def required_for(context):
    for suffix, ops in REQUIRED.items():
        if context.endswith(suffix):
            return set(ops)
    return set()


def ratio(blocked, eligible):
    return blocked / eligible if eligible else float("nan")


def evaluate(context, profile, baseline, current):
    required = required_for(context)
    eligible = [t for t in BASIC + EXTENDED if baseline.get(t) == "ALLOWED"]
    invalid = [(t, current.get(t)) for t in eligible
               if current.get(t) not in ("ALLOWED", "BLOCKED")]
    if invalid:
        return {"context": context, "profile": profile, "valid": 0,
                "note": "INVALID RUN: " + " ".join(f"{t}={s}" for t, s in invalid)}

    def blocked(tests):
        return sum(1 for t in tests if current[t] == "BLOCKED")

    basic = [t for t in eligible if t in BASIC]
    basic_excl = [t for t in basic if t not in required]
    scores = []
    for tests in CATEGORIES.values():
        cat = [t for t in tests if t in basic_excl]
        if cat:
            scores.append(blocked(cat) / len(cat))
    still_allowed = [t for t in eligible if current[t] == "ALLOWED"]
    return {
        "context": context, "profile": profile, "valid": 1,
        "eligible_36": len(eligible), "blocked_36": blocked(eligible),
        "emicro_36": ratio(blocked(eligible), len(eligible)),
        "eligible_32_excl": len(basic_excl), "blocked_32_excl": blocked(basic_excl),
        "emicro_32_excl": ratio(blocked(basic_excl), len(basic_excl)),
        "eiso_32_excl": sum(scores) / len(scores) if scores else float("nan"),
        "residual_required": " ".join(t for t in still_allowed if t in required),
        "residual_other": " ".join(t for t in still_allowed if t not in required),
        "note": "",
    }


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 64
    root = Path(sys.argv[1])
    files = {}
    for path in sorted(root.glob("*__*.txt")):
        context, profile = path.stem.split("__", 1)
        files.setdefault(context, {})[profile] = path
    if not files:
        print(f"No <context>__<profile>.txt files in {root}")
        return 1

    rows = []
    for context, profiles in files.items():
        print("=" * 72)
        print(f"CONTEXT {context}")
        if "P0" not in profiles:
            print("  MISSING BASELINE P0 -- context skipped")
            continue
        baseline = parse(profiles["P0"])
        missing = [t for t in BASIC + EXTENDED if t not in baseline]
        if missing:
            print("  BASELINE LACKS: " + " ".join(missing))
        required = required_for(context)
        if required:
            print("  required by the service (reported, not hidden): " + " ".join(sorted(required)))
        print(f"  {'PROF':<5}{'ELIG36':>7}{'BLK36':>6}{'Emicro36':>10}"
              f"{'ELIG32x':>9}{'BLK32x':>8}{'Emicro32x':>11}{'Eiso32x':>9}")
        ordered = sorted(profiles, key=lambda p: PROFILE_ORDER.index(p) if p in PROFILE_ORDER else 99)
        for profile in ordered:
            row = evaluate(context, profile, baseline, parse(profiles[profile]))
            rows.append(row)
            if not row["valid"]:
                print(f"  {profile:<5}{row['note']}")
                continue
            print(f"  {profile:<5}{row['eligible_36']:>7}{row['blocked_36']:>6}{row['emicro_36']:>10.3f}"
                  f"{row['eligible_32_excl']:>9}{row['blocked_32_excl']:>8}"
                  f"{row['emicro_32_excl']:>11.3f}{row['eiso_32_excl']:>9.3f}")
            if profile != "P0":
                print(f"       still ALLOWED, required: {row['residual_required'] or '-'}")
                print(f"       still ALLOWED, other:    {row['residual_other'] or '-'}")

    fields = ["context", "profile", "valid", "eligible_36", "blocked_36", "emicro_36",
              "eligible_32_excl", "blocked_32_excl", "emicro_32_excl", "eiso_32_excl",
              "residual_required", "residual_other", "note"]
    out = root / "metrics.csv"
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: (f"{v:.6f}" if isinstance(v, float) else v) for k, v in row.items()})
    print()
    print("Legend: 36 = 32 basic + 4 extended probes, nothing excluded;")
    print("        32x = 32 basic probes with service-required operations excluded")
    print("              (the definition used for Emicro/Eiso in the earlier text).")
    print(f"CSV={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
