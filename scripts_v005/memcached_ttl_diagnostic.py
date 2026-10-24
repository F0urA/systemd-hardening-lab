#!/usr/bin/env python3
"""memcached_ttl_diagnostic.py check|summarize ...

Helper of memcached_ttl_diagnostic.sh (protocol_memcached_ttl.md). Written after
the experiment to find out why P1 failed the expiration check of the memcached
contract once; it changes neither the contract nor the selection.

  check --expected-version V --out FILE
      the contract part before restart exactly as in the contract
      (memcached_client_v005.contract_before, expiration wait 3.2 s), then the time
      until a key stored with TTL 2 s disappears, polled every 50 ms for up to 10 s;
      one JSON object to FILE
  row --out FILE --round R --order O --profile P --gap MS
      one line of rows.csv from the JSON of a check and the longest pause during it
  summarize --dir DIR
      rows.csv of the run -> summary.txt with the classification of the protocol
"""
import argparse
import csv
import json
import statistics
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import memcached_client_v005 as client  # noqa: E402

HOST, PORT = "127.0.0.1", 11212
TTL, POLL, LIMIT = 2, 0.05, 10.0
PAUSE_MS = 1000          # a pause this long can consume the 1.2 s margin of the 3.2 s wait
QUIET_MS = 500           # the stall limit of the load series
EXPIRY_RANGE = (0.9, 2.3)  # one-second clock ticks: the key disappears 1-2 s after SET
PROFILES = ["P0", "P1", "P2", "P4", "P6"]


def time_to_expiry():
    key, value = b"v005-memcached-ttl-diagnostic", b"TTL_DIAGNOSTIC"
    with client.Connection(HOST, PORT) as connection:
        connection.set(key, value, expiration=TTL)
        start = client.elapsed_ns()
        client.expect(connection.get(key) == value, "expiring key was not initially present")
        while connection.get(key) is not None:
            if (client.elapsed_ns() - start) / 1e9 > LIMIT:
                return None
            time.sleep(POLL)
        return (client.elapsed_ns() - start) / 1e9


def check(expected_version, out):
    before = client.contract_before(HOST, PORT, expected_version)
    result = {c["check"]: c["result"] for c in before["checks"]}
    try:
        expiry = time_to_expiry()
        expiry_error = ""
    except (OSError, ValueError) as error:
        expiry, expiry_error = None, f"{type(error).__name__}: {error}"
    out.write_text(json.dumps({"contract_before": before, "expiration": result.get("expiration", "MISSING"),
                               "contract_before_pass": all(v == "PASS" for v in result.values()),
                               "time_to_expiry_s": expiry, "expiry_error": expiry_error},
                              sort_keys=True) + "\n", encoding="utf-8")
    return 0


FIELDS = ["round", "order", "profile", "expiration", "contract_before_pass", "time_to_expiry_s", "max_gap_ms"]


def row(out, rnd, order, profile, gap):
    result = json.loads(out.read_text(encoding="utf-8"))
    csv.writer(sys.stdout, lineterminator="\n").writerow(
        [rnd, order, profile, result["expiration"], int(result["contract_before_pass"]),
         result["time_to_expiry_s"], gap])
    return 0


def summarize(directory):
    with open(directory / "rows.csv", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    lines = [f"checks {len(rows)}; pause threshold {PAUSE_MS} ms, quiet below {QUIET_MS} ms",
             f"{'profile':8}{'checks':>7}{'fail':>6}{'fail quiet':>11}{'max gap ms':>11}"
             f"{'expiry min':>11}{'median':>8}{'max':>7}{'quiet out of range':>20}"]
    fails, quiet_fails, out_of_range = {}, {}, 0
    for p in PROFILES:
        mine = [r for r in rows if r["profile"] == p]
        if not mine:
            continue
        f = [r for r in mine if r["expiration"] != "PASS"]
        fq = [r for r in f if float(r["max_gap_ms"]) < PAUSE_MS]
        exp = [float(r["time_to_expiry_s"]) for r in mine if r["time_to_expiry_s"] not in ("", "None")]
        quiet = [float(r["time_to_expiry_s"]) for r in mine if float(r["max_gap_ms"]) < QUIET_MS
                 and r["time_to_expiry_s"] not in ("", "None")]
        bad = [v for v in quiet if not EXPIRY_RANGE[0] <= v <= EXPIRY_RANGE[1]]
        bad += [r for r in mine if r["time_to_expiry_s"] in ("", "None") and float(r["max_gap_ms"]) < QUIET_MS]
        fails[p], quiet_fails[p], out_of_range = len(f), len(fq), out_of_range + len(bad)
        lines.append(f"{p:8}{len(mine):>7}{len(f):>6}{len(fq):>11}{max(float(r['max_gap_ms']) for r in mine):>11.0f}"
                     + (f"{min(exp):>11.2f}{statistics.median(exp):>8.2f}{max(exp):>7.2f}" if exp else f"{'-':>26}")
                     + f"{len(bad):>20}")
    others_quiet = sum(v for p, v in quiet_fails.items() if p != "P1")
    if quiet_fails.get("P1", 0) >= 3 and others_quiet == 0:
        verdict = "PROFILE_EFFECT"
    elif sum(fails.values()) and not sum(quiet_fails.values()) and not out_of_range:
        verdict = "PAUSE_EFFECT"
    elif not sum(fails.values()) and not out_of_range:
        verdict = "NOT_REPRODUCED"
    else:
        verdict = "UNCLASSIFIED"
    lines.append(f"VERDICT={verdict}")
    (directory / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=["check", "row", "summarize"])
    ap.add_argument("--expected-version")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--dir", type=Path)
    ap.add_argument("--round")
    ap.add_argument("--order")
    ap.add_argument("--profile")
    ap.add_argument("--gap")
    a = ap.parse_args()
    if a.mode == "check":
        return check(a.expected_version, a.out)
    if a.mode == "row":
        return row(a.out, a.round, a.order, a.profile, a.gap)
    return summarize(a.dir)


if __name__ == "__main__":
    sys.exit(main())
