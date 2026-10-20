#!/usr/bin/env python3
"""Verify local report links, manually transcribed tables and F evidence."""
import csv
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RAW = ROOT / "raw-vm"
REPORT = ROOT / "report_v005.md"


def csv_rows(path):
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(line for line in stream if not line.startswith("#")))


def check(test, message):
    if not test:
        raise ValueError(message)


def number(value):
    return float(value.replace("−", "-").replace(",", "."))


text = REPORT.read_text(encoding="utf-8")
links = re.findall(r"\[[^\]]+\]\(([^)]+)\)", text)
check(all(Path(link).is_file() for link in links), "Missing report link")
criteria = {(r["service"], r["profile"]): r for r in
            csv_rows(ROOT / "analysis-final/combined-criteria-INCOMPLETE_SCOPE.csv")}
services = {"Nginx": "nginx", "Redis": "redis", "PostgreSQL": "postgresql"}
table_rows = [list(map(str.strip, line.strip("|").split("|"))) for line in text.splitlines() if line.startswith("| ")]
bound_rows = [r for r in table_rows if len(r) == 8 and r[0] in services and r[2] in {"5", "7"}]
check(len(bound_rows) == 17, "Wrong report bounds row count")
for r in bound_rows:
    source = criteria[(services[r[0]], r[1])]
    check(int(r[3]) == int(source["pairs"]), "Report pair count")
    check(all(number(r[i]) == float(source[key]) for i, key in ((4, "L95"), (5, "U95d"), (6, "cost_upper"))),
          "Report bound transcription")
    check(r[7] == {"NON_INFERIOR": "NI", "LOSS_EXCEEDS": "LOSS", "INCONCLUSIVE": "INC"}[source["status"]],
          "Report status transcription")

audit = json.loads((ROOT / "REPORT_AUDIT.json").read_text())
decisions = {(r["service"], str(r["H"])): r for r in audit["selection"]["decisions"]}
decision_rows = [r for r in table_rows if len(r) == 7 and r[0] in services and r[1] in {"2", "5", "10", "15"}]
check(len(decision_rows) == 12, "Wrong report decision row count")
for r in decision_rows:
    source = decisions[(services[r[0]], r[1])]
    check(r[2] == ", ".join(source["admitted"]) and r[3] == source["A"] and r[4] == source["A+"]
          and r[6] == source["B_default"], "Report selection transcription")
    raw_b = source["B"]
    expected_b = raw_b[4:-1] + ", равенство" if raw_b.startswith("TIE(") else raw_b
    check(r[5] == expected_b, "Report B tie transcription")

hash_rows = [r for r in table_rows if len(r) == 2 and re.fullmatch(r"[0-9a-f]{64}", r[1])]
check(len(hash_rows) == 6, "Wrong CSV hash table")
names = {"R1": audit["series"]["R1-nginx"], "R2": audit["series"]["R2-redis"],
         "R3 retry": audit["series"]["R3-postgresql"], "R5": audit["series"]["R5-nginx-light"],
         "R1 добор": audit["extensions"]["R1-nginx"], "R3 добор": audit["extensions"]["R3-postgresql"]}
check(all(names[r[0]]["results_sha256"] == r[1] for r in hash_rows), "Report CSV hash transcription")

expected_checks = {"nginx": {"start", "reopen-logs", "reload", "not-found-404", "restart", "crash-recovery"},
                   "redis": {"start", "bgsave", "bgrewriteaof", "restart-keeps-value"},
                   "postgresql": {"start", "checkpoint", "reload", "restart", "query-with-jit"},
                   "nginx-tls": {"tls-start", "https-proxy-response", "tls-reload"}}
functional_counts = []
for stamp in ("20261012-104934", "20261014-002104"):
    directory = RAW / "functional-v005" / stamp
    contract, rows = csv_rows(directory / "contract.csv"), csv_rows(directory / "functional.csv")
    for verdict in contract:
        checks = [r for r in rows if r["service"] == verdict["service"] and r["profile"] == verdict["profile"]]
        mandatory = [r for r in checks if r["mandatory"] == "1"]
        check({r["check"] for r in mandatory} == expected_checks[verdict["service"]]
              and len(mandatory) == len(expected_checks[verdict["service"]])
              and all(r["result"] == "PASS" for r in mandatory), "Incomplete mandatory F")
        optional = [r for r in checks if r["mandatory"] != "1"]
        check(all(r["mandatory"] == "0" and r["check"] == "crash-recovery" and r["result"] == "PASS"
                  for r in optional) and len(optional) == int(verdict["service"] in {"redis", "postgresql"}),
              "Unexpected optional F evidence")
    functional_counts.append({"directory": stamp, "contracts_pass": len(contract)})
for token in ("INCOMPLETE_SCOPE", "R4_FAILED", "NOT_RUN", "jit_used=no", "NOT_REPRODUCED",
              "73415", "23040", "CLOCK_MONOTONIC_RAW", "G=пусто", "минимального ослабления"):
    check(token in text, f"Required limit absent: {token}")

result = {"validation": "PASS", "report_sha256": hashlib.sha256(REPORT.read_bytes()).hexdigest(),
          "links_verified": len(links), "bounds_rows_verified": len(bound_rows),
          "decision_rows_verified": len(decision_rows), "csv_hash_rows_verified": len(hash_rows),
          "mandatory_functional_matrices_verified": functional_counts,
          "new_statistical_look": False, "scope": "INCOMPLETE_SCOPE"}
print(json.dumps(result, ensure_ascii=False, indent=2))
