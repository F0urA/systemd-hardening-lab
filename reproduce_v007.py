#!/usr/bin/env python3
"""reproduce_v007.py [--quick]

Recomputes the results of the third stage from the published package, without
the virtual machine, and compares them with the saved analysis.

  1. raw data      every file of data/main/raw-vm against
                   the closed manifest SHA256-CLOSED-RESULTS.txt (skipped by --quick)
     provenance    the frozen archives of the executed sources against the hashes
                   recorded before the measurements (for the archives whose local paths
                   were removed, through SANITIZATION_v007.md), and the executed copies
                   frozen-primary/, frozen-timing/ against the stand manifests
  2. criteria      build_criteria_v005.py with the same arguments the analyzer
                   used on the stand (analysis_v005/analyze_v005.py): the combined
                   table (Nginx M=7, Redis/PostgreSQL M=5, K=2 looks) and the four
                   separately registered families (R1 M=4, R5 M=3, R2 M=5, R3 M=5)
  3. selection     select_profile_v005.py, rules A, A+, B, for the combined table
  4. policies      the 24 g-first operator policies (policy24.csv)
  5. order         order_sensitivity_v005.py
  6. required      selection with required goal G2, then G1, for Nginx
  7. robustness    robustness_v005.py: direct contrasts P1c-P5, P1c-P6 of R1
  8. points        point_estimates_v005.py (point estimates quoted in the text)
  9. postgresql    pg_contrasts_v007.py: t-bounds against exact permutation bounds

Every step prints PASS or DIFF; the exit code is 0 only if all steps pass.
Needs Python 3.9+; step 9 also needs numpy.
"""
import csv
import hashlib
import itertools
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCRIPTS = ROOT / "scripts_v005"
RUN = ROOT / "data" / "main"
RAW = RUN / "raw-vm"
FINAL = RUN / "analysis-final"
SAVED = ROOT / "data" / "derived"
PROTOCOL = RUN / "protocol"
sys.path.insert(0, str(SCRIPTS))
from select_profile_v005 import read_criteria, admissible, restricted, lex, pick  # noqa: E402

NG = RAW / "nginx" / "benchmark-v005"
RD = RAW / "redis" / "benchmark-v005"
PG = RAW / "postgresql" / "benchmark-v005"
R1, R1EXT, R5 = NG / "20261012-175912", NG / "20261013-221436", NG / "20261013-204356"
R2 = RD / "20261012-194224"
R3, R3EXT = PG / "20261013-193448", PG / "20261013-233151"
BASE = ["--probe", RAW / "probe-v005" / "20261012-110043",
        "--contract", RAW / "functional-v005" / "20261012-104934", "--level", "0.05", "--looks", "2"]
SCENARIOS = RAW / "scenarios-v005" / "20261012-110837"
COMBINED = ["--family", "nginx=7", "--family", "redis=5", "--family", "postgresql=5",
            "--bench", f"nginx={R1}+{R1EXT}:P0,P4,P5,P6", "--bench", f"nginx={R1}:P0,P1c",
            "--bench", f"nginx={R5}:P0,P1,P2,P1r", "--bench", f"redis={R2}:P0,P1,P2,P1d,P4,P6",
            "--bench", f"postgresql={R3}+{R3EXT}:P0,P2,P4,P6", "--bench", f"postgresql={R3}:P0,P1,P1d"]
FAMILIES = {  # name -> (service, M, bench arguments)
    "R1-nginx": ("nginx", 4, ["--bench", f"nginx={R1}+{R1EXT}:P0,P4,P5,P6", "--bench", f"nginx={R1}"]),
    "R5-nginx-light": ("nginx", 3, ["--bench", f"nginx={R5}"]),
    "R2-redis": ("redis", 5, ["--bench", f"redis={R2}"]),
    "R3-postgresql": ("postgresql", 5, ["--bench", f"postgresql={R3}+{R3EXT}:P0,P2,P4,P6",
                                        "--bench", f"postgresql={R3}"]),
}
results = []


def run(args):
    out = subprocess.run([sys.executable, "-I", "-X", "utf8", *map(str, args)], capture_output=True, text=True,
                         encoding="utf-8", cwd=ROOT)
    if out.returncode:
        raise RuntimeError(f"{args[0]} failed:\n{out.stderr}")
    return out.stdout


def table(path):
    """CSV rows without the leading comment lines."""
    lines = [l for l in Path(path).read_text(encoding="utf-8-sig").splitlines() if not l.startswith("#")]
    return [tuple(r) for r in csv.reader(lines)]


def body(text):
    """Selection/sensitivity output from its first ==== rule on (saved files carry a scope header)."""
    lines = text.replace("\r\n", "\n").splitlines()
    start = next((i for i, l in enumerate(lines) if l.startswith("=====")), 0)
    return [l.rstrip() for l in lines[start:] if l.strip()]


def report(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'DIFF'}  {name}{('  ' + detail) if detail else ''}")


def step_raw():
    manifest = RAW / "SHA256-CLOSED-RESULTS.txt"
    bad, count = [], 0
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, name = line.split(maxsplit=1)
        path = RAW / name.lstrip("*").removeprefix("./")
        count += 1
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            bad.append(name)
    listed = {l.split(maxsplit=1)[1].lstrip("*").removeprefix("./")
              for l in manifest.read_text(encoding="utf-8").splitlines()}
    extra = [p for p in RAW.rglob("*") if p.is_file() and p != manifest
             and p.relative_to(RAW).as_posix() not in listed]
    report("raw data against SHA256-CLOSED-RESULTS.txt", not bad and not extra,
           f"{count} files, {len(bad)} missing or changed, {len(extra)} unlisted")


FREEZE_RECORDS = {  # archive of the executed sources -> record written before the measurements
    "v005-primary-frozen.zip": "PRIMARY_FREEZE.txt",
    "v005-timing-frozen.zip": "TIMING_FREEZE.txt",
    "v005-analysis-queue-frozen.zip": "ANALYSIS_QUEUE_FREEZE.txt",
    "v005-mount-states-frozen.zip": "MOUNT_STATE_FREEZE.txt",
    "v005-collector-frozen.zip": "COLLECTOR_FREEZE.md",
    "v005-resume-frozen.zip": "RESUME_FREEZE.txt",
}
SANITIZATION = ROOT / "docs" / "SANITIZATION_v007.md"


def sanitized():
    """SHA256 before and after the removal of local paths: archive -> pair, (archive, entry) -> pair."""
    text = SANITIZATION.read_text(encoding="utf-8") if SANITIZATION.is_file() else ""
    archives = {Path(p).name: (a, b) for p, a, b in re.findall(
        r"^\| `([^`]+\.zip)` \| ([0-9a-f]{64}) \| ([0-9a-f]{64}) \|", text, re.M)}
    entries = {(Path(p).name, e): (a, b) for p, e, a, b in re.findall(
        r"^\| `([^`]+\.zip)` → `([^`]+)` \| ([0-9a-f]{64}) \| ([0-9a-f]{64}) \|", text, re.M)}
    return archives, entries


def step_provenance():
    """The executed sources are the frozen archives and copies in the package, checked against
    the hashes recorded before the measurements. scripts_v005 is their portable edition."""
    archives, entries = sanitized()
    bad, cleaned = [], 0
    for archive, record in FREEZE_RECORDS.items():
        text = (PROTOCOL / record).read_text(encoding="utf-8")
        recorded = re.search(r"[0-9A-Fa-f]{64}", text[text.index(archive):]).group(0).lower()
        actual = hashlib.sha256((PROTOCOL / archive).read_bytes()).hexdigest()
        if actual == recorded:
            continue
        if archives.get(archive) != (recorded, actual):
            bad.append(archive)
            continue
        # local paths removed: every file the record names must still match it, or be listed in
        # SANITIZATION_v007.md with the recorded hash as its hash before the removal
        named = {n: h.lower() for n, h in re.findall(r"([\w.-]+\.(?:py|sh|ps1|json|md))[`:=\s]*([0-9A-Fa-f]{64})", text)}
        with zipfile.ZipFile(PROTOCOL / archive) as zf:
            for info in zf.infolist():
                name = Path(info.filename).name
                digest = hashlib.sha256(zf.read(info)).hexdigest()
                if name in named and digest != named[name] and entries.get((archive, info.filename)) != (named[name], digest):
                    bad.append(f"{archive}:{info.filename}")
        cleaned += 1
    report("frozen source archives against their freeze records", not bad,
           f"{len(FREEZE_RECORDS)} archives" + (f", {cleaned} with local paths removed (SANITIZATION_v007.md)" if cleaned else ""))
    for manifest in ("primary-source-sha256.txt", "timing-source-sha256.txt"):
        bad, count = [], 0
        for line in (RAW / "driver" / manifest).read_text(encoding="utf-8").splitlines():
            digest, name = line.split(maxsplit=1)
            path = RUN / name.lstrip("*")
            count += 1
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                bad.append(name)
        report(f"executed sources against {manifest}", not bad, f"{count} files")


def step_criteria(tmp):
    combined = tmp / "combined.csv"
    run([SCRIPTS / "build_criteria_v005.py", *BASE, "--scenarios", SCENARIOS, *COMBINED, "--out", combined])
    report("combined criteria (table 13)", table(combined) == table(FINAL / "combined-criteria-INCOMPLETE_SCOPE.csv"))
    for name, (service, family, bench) in FAMILIES.items():
        out = tmp / f"{name}.csv"
        run([SCRIPTS / "build_criteria_v005.py", *BASE, "--scenarios", FINAL / f"{name}-candidate-scope",
             "--family", f"{service}={family}", *bench, "--out", out])
        report(f"family {name}, M={family}", table(out) == table(FINAL / f"{name}-criteria.csv"))
    return combined


def step_selection(combined):
    text = run([SCRIPTS / "select_profile_v005.py", combined])
    report("selection, rules A / A+ / B (table 16)",
           body(text) == body((FINAL / "combined-selection-INCOMPLETE_SCOPE.txt").read_text(encoding="utf-8")))
    rows = []
    for service, crit in read_criteria(combined).items():
        for budget in [2, 5, 10, 15]:
            cands = restricted(admissible(crit, budget))
            for policy in itertools.permutations(["s", "emicro", "exposure", "n"]):
                rows.append((service, str(budget), ";".join(policy), pick(cands, lex(["g", *policy]))))
    report("24 operator policies (table 17)", [("service", "budget", "policy", "outcome"), *rows]
           == table(FINAL / "policy24.csv"))
    text = run([SCRIPTS / "order_sensitivity_v005.py", combined])
    report("order sensitivity", body(text) == body((FINAL / "order-sensitivity.txt").read_text(encoding="utf-8")))
    text = (run([SCRIPTS / "select_profile_v005.py", combined, "--require", "nginx=G2-read-app-secret"])
            + run([SCRIPTS / "select_profile_v005.py", combined, "--require", "nginx=G1-replace-document"]))
    saved = (SAVED / "selection_required_g2_v005.txt").read_text(encoding="utf-8")
    report("required goals G2 / G1 (section 6.9)",
           [l.rstrip() for l in text.splitlines() if l.strip()] == [l.rstrip() for l in saved.splitlines() if l.strip()])


def step_descriptive():
    text = run([SCRIPTS / "robustness_v005.py", "--family", "4", "--pairs", "P1c-P5,P1c-P6", f"R1={R1 / 'results.csv'}"])
    report("direct contrasts P1c-P5, P1c-P6 (section 6.7)",
           body(text) == body((FINAL / "R1-robustness-descriptive.txt").read_text(encoding="utf-8")))
    text = run([SCRIPTS / "point_estimates_v005.py", RUN])
    report("point estimates (table 13, sections 6.8, 6.10)",
           text.split() == (SAVED / "point_estimates_v005.txt").read_text(encoding="utf-8").split())


def step_postgresql(tmp):
    out = tmp / "pg.csv"
    run([SCRIPTS / "pg_contrasts_v007.py", RUN, "--out-csv", out])
    report("PostgreSQL t-bounds vs permutation bounds (table 14)",
           table(out) == table(SAVED / "pg_contrasts_v007.csv"))


def main():
    print(f"package: {RUN.relative_to(ROOT).as_posix()}")
    if "--quick" not in sys.argv:
        step_raw()
    step_provenance()
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        combined = step_criteria(tmp)
        step_selection(combined)
        step_descriptive()
        step_postgresql(tmp)
    print(f"{sum(results)}/{len(results)} checks passed")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
