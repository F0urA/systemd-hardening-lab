#!/usr/bin/env python3
"""reproduce.py [--quick] [main|rerun]

Recomputes the results of the third stage from the published package, without
the virtual machine, and compares them with the saved analysis. Two packages:

  main    data/main   the run of 2026-10-12..14 (AMD Ryzen 5 2600 host)
  rerun   data/rerun  the repeat of 2026-10-19/20 by run_stage3.sh (AMD Ryzen 5 3600
                      host), the data of the article; with memcached

Without an argument both are checked.

  1. raw data      every file against its closed manifest (skipped by --quick):
                   main  -- raw-vm/SHA256-CLOSED-RESULTS.txt;
                   rerun -- the same, the two memcached addenda, the TTL diagnostic
                   and the archives
     provenance    main  -- the frozen archives of the executed sources against the
                   hashes recorded before the measurements (for the archives whose local
                   paths were removed, through SANITIZATION.md), and the executed copies
                   frozen-primary/, frozen-timing/ against the stand manifests;
                   rerun -- every file deployed on the stand (vm-logs/deployed-sha256.txt)
                   against commit 6eb755e of this repository (needs git and the history),
                   the hashes of the queue drivers, and the corrected memcached copy
                   against the deployed scripts plus its two-line diff
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
  9. postgresql    pg_contrasts.py: t-bounds against exact permutation bounds
 10. memcached     rerun only: criteria and selection of analyze_memcached_v005.py
 11. repeats       stall_sensitivity.py: the measurements repeated after a VM pause and the
                   lower bounds with the first attempts or without the repeated blocks
 12. ttl           rerun only: the summary of the memcached TTL diagnostic (after the
                   experiment, scripts_v005/protocol_memcached_ttl.md) from its rows.csv

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
sys.path.insert(0, str(SCRIPTS))
from select_profile_v005 import read_criteria, admissible, restricted, lex, pick  # noqa: E402


class Package:
    """Where one package keeps its data and how its analyzer was called."""

    def __init__(self, name, run, saved, required, series, preflight, combined, families, manifests):
        self.name, self.run, self.saved, self.required = name, run, saved, required
        self.raw = run / "raw-vm"
        self.final = run / "analysis-final"
        self.series = {k: self.raw / v for k, v in series.items()}
        probe, contract, scenarios = preflight
        self.base = ["--probe", self.raw / probe, "--contract", self.raw / contract, "--level", "0.05", "--looks", "2"]
        self.scenarios = self.raw / scenarios
        s = self.series
        self.combined = ["--family", "nginx=7", "--family", "redis=5", "--family", "postgresql=5"]
        for service, spec in combined:
            self.combined += ["--bench", f"{service}={spec.format(**s)}"]
        self.families = {name: (service, family, [x for spec in specs for x in ("--bench", f"{service}={spec.format(**s)}")])
                         for name, (service, family, specs) in families.items()}
        self.manifests = [run / m for m in manifests]


MAIN = Package(
    "main", ROOT / "data" / "main", ROOT / "data" / "derived", "selection_required_g2_v005.txt",
    {"R1": "nginx/benchmark-v005/20261012-175912", "R1EXT": "nginx/benchmark-v005/20261013-221436",
     "R5": "nginx/benchmark-v005/20261013-204356", "R2": "redis/benchmark-v005/20261012-194224",
     "R3": "postgresql/benchmark-v005/20261013-193448", "R3EXT": "postgresql/benchmark-v005/20261013-233151"},
    ("probe-v005/20261012-110043", "functional-v005/20261012-104934", "scenarios-v005/20261012-110837"),
    [("nginx", "{R1}+{R1EXT}:P0,P4,P5,P6"), ("nginx", "{R1}:P0,P1c"), ("nginx", "{R5}:P0,P1,P2,P1r"),
     ("redis", "{R2}:P0,P1,P2,P1d,P4,P6"), ("postgresql", "{R3}+{R3EXT}:P0,P2,P4,P6"), ("postgresql", "{R3}:P0,P1,P1d")],
    {"R1-nginx": ("nginx", 4, ["{R1}+{R1EXT}:P0,P4,P5,P6", "{R1}"]),
     "R5-nginx-light": ("nginx", 3, ["{R5}"]),
     "R2-redis": ("redis", 5, ["{R2}"]),
     "R3-postgresql": ("postgresql", 5, ["{R3}+{R3EXT}:P0,P2,P4,P6", "{R3}"])},
    ["raw-vm/SHA256-CLOSED-RESULTS.txt"])

RERUN = Package(
    "rerun", ROOT / "data" / "rerun", ROOT / "data" / "rerun" / "derived", "selection_required.txt",
    {"R1": "nginx/benchmark-v005/20261019-172537", "R1EXT": "nginx/benchmark-v005/20261019-222428",
     "R5": "nginx/benchmark-v005/20261019-211626", "R2": "redis/benchmark-v005/20261019-184311",
     "R3": "postgresql/benchmark-v005/20261019-194432", "R3EXT": "postgresql/benchmark-v005/20261019-230632"},
    ("probe-v005/20261019-172028", "functional-v005/20261019-170059", "scenarios-v005/20261019-171608"),
    [("nginx", "{R1}+{R1EXT}:P0,P4,P6"), ("nginx", "{R1}:P0,P1c,P5"), ("redis", "{R2}:P0,P1,P2,P1d,P4,P6"),
     ("postgresql", "{R3}+{R3EXT}:P0,P1,P2,P1d,P4,P6"), ("nginx", "{R5}:P0,P1,P2,P1r")],
    {"R1-nginx": ("nginx", 4, ["{R1}+{R1EXT}:P0,P4,P6", "{R1}"]),
     "R5-nginx-light": ("nginx", 3, ["{R5}"]),
     "R2-redis": ("redis", 5, ["{R2}"]),
     "R3-postgresql": ("postgresql", 5, ["{R3}+{R3EXT}:P0,P1,P2,P1d,P4,P6", "{R3}"])},
    ["raw-vm/SHA256-CLOSED-RESULTS.txt", "memcached/results_v005/SHA256-ADDENDUM2-MEMCACHED.txt",
     "memcached-attempt1/results_v005/SHA256-ADDENDUM-MEMCACHED.txt",
     "memcached-ttl-diagnostic/20261024T163835Z/sha256-all.txt"])
PACKAGES = {"main": MAIN, "rerun": RERUN}

RERUN_COMMIT = "6eb755e48c43625964c5a202f8e5eaa59393cccc"   # cloned on the stand of the repeat
MEMCACHED = RERUN.run / "memcached"
MEMCACHED_RAW = MEMCACHED / "results_v005" / "memcached"
TTL_DIAGNOSTIC = RERUN.run / "memcached-ttl-diagnostic" / "20261024T163835Z"
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


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def step_raw(pkg):
    for manifest in pkg.manifests:
        root = manifest.parent
        text = manifest.read_text(encoding="utf-8").splitlines()
        bad = []
        for line in text:
            digest, name = line.split(maxsplit=1)
            path = root / name.lstrip("*").removeprefix("./")
            if not path.is_file() or sha256(path) != digest:
                bad.append(name)
        listed = {l.split(maxsplit=1)[1].lstrip("*").removeprefix("./") for l in text}
        extra = [p for p in root.rglob("*") if p.is_file() and p != manifest
                 and p.relative_to(root).as_posix() not in listed]
        report(f"raw data against {manifest.relative_to(pkg.run).as_posix()}", not bad and not extra,
               f"{len(text)} files, {len(bad)} missing or changed, {len(extra)} unlisted")
    if pkg is RERUN:
        archives = sorted((pkg.run / "archives").glob("*.sha256"))
        bad = [a.name for a in archives
               if sha256(a.with_suffix("")) != a.read_text(encoding="utf-8").split()[0]]
        report("archives of the stand against their SHA256", archives and not bad, f"{len(archives)} archives")


FREEZE_RECORDS = {  # archive of the executed sources -> record written before the measurements
    "v005-primary-frozen.zip": "PRIMARY_FREEZE.txt",
    "v005-timing-frozen.zip": "TIMING_FREEZE.txt",
    "v005-analysis-queue-frozen.zip": "ANALYSIS_QUEUE_FREEZE.txt",
    "v005-mount-states-frozen.zip": "MOUNT_STATE_FREEZE.txt",
    "v005-collector-frozen.zip": "COLLECTOR_FREEZE.md",
    "v005-resume-frozen.zip": "RESUME_FREEZE.txt",
}
SANITIZATION = ROOT / "docs" / "SANITIZATION.md"


def sanitized():
    """SHA256 before and after the removal of local paths: archive -> pair, (archive, entry) -> pair."""
    text = SANITIZATION.read_text(encoding="utf-8") if SANITIZATION.is_file() else ""
    archives = {Path(p).name: (a, b) for p, a, b in re.findall(
        r"^\| `([^`]+\.zip)` \| ([0-9a-f]{64}) \| ([0-9a-f]{64}) \|", text, re.M)}
    entries = {(Path(p).name, e): (a, b) for p, e, a, b in re.findall(
        r"^\| `([^`]+\.zip)` → `([^`]+)` \| ([0-9a-f]{64}) \| ([0-9a-f]{64}) \|", text, re.M)}
    return archives, entries


def step_provenance_main(pkg):
    """The executed sources are the frozen archives and copies in the package, checked against
    the hashes recorded before the measurements. scripts_v005 is their portable edition."""
    protocol = pkg.run / "protocol"
    archives, entries = sanitized()
    bad, cleaned = [], 0
    for archive, record in FREEZE_RECORDS.items():
        text = (protocol / record).read_text(encoding="utf-8")
        recorded = re.search(r"[0-9A-Fa-f]{64}", text[text.index(archive):]).group(0).lower()
        actual = sha256(protocol / archive)
        if actual == recorded:
            continue
        if archives.get(archive) != (recorded, actual):
            bad.append(archive)
            continue
        # local paths removed: every file the record names must still match it, or be listed in
        # SANITIZATION.md with the recorded hash as its hash before the removal
        named = {n: h.lower() for n, h in re.findall(r"([\w.-]+\.(?:py|sh|ps1|json|md))[`:=\s]*([0-9A-Fa-f]{64})", text)}
        with zipfile.ZipFile(protocol / archive) as zf:
            for info in zf.infolist():
                name = Path(info.filename).name
                digest = hashlib.sha256(zf.read(info)).hexdigest()
                if name in named and digest != named[name] and entries.get((archive, info.filename)) != (named[name], digest):
                    bad.append(f"{archive}:{info.filename}")
        cleaned += 1
    report("frozen source archives against their freeze records", not bad,
           f"{len(FREEZE_RECORDS)} archives" + (f", {cleaned} with local paths removed (SANITIZATION.md)" if cleaned else ""))
    for manifest in ("primary-source-sha256.txt", "timing-source-sha256.txt"):
        bad, count = [], 0
        for line in (pkg.raw / "driver" / manifest).read_text(encoding="utf-8").splitlines():
            digest, name = line.split(maxsplit=1)
            path = pkg.run / name.lstrip("*")
            count += 1
            if not path.is_file() or sha256(path) != digest:
                bad.append(name)
        report(f"executed sources against {manifest}", not bad, f"{count} files")


def deployed_source(path):
    """Repository path of a file that deploy_stage3.sh laid out on the stand."""
    path = path.removeprefix("./")
    for prefix in ("frozen-timing/v005/", "frozen-mount-states/", "post-analysis/frozen-primary/v005/",
                   "post-analysis/frozen-timing/v005/"):
        if path.startswith(prefix):
            return path[len(prefix):]
    if path in ("driver_extensions_v005.sh", "run_stage3.sh"):
        return f"scripts_v005/orchestration_v005/{path}"
    if path == "inspect_series_v005.py" or path.startswith("post-analysis/"):
        return f"scripts_v005/analysis_v005/{path.rsplit('/', 1)[-1]}"
    return None


def git_blobs(commit, paths):
    """Contents of PATHS at COMMIT, or None if git or the commit is not available."""
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "cat-file", "--batch"], input="".join(
            f"{commit}:{p}\n" for p in paths).encode(), capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    blobs, pos = [], 0
    for _ in paths:
        header_end = out.index(b"\n", pos)
        header = out[pos:header_end].split()
        if header[-1] == b"missing":
            return None
        size = int(header[2])
        blobs.append(out[header_end + 1:header_end + 1 + size])
        pos = header_end + 1 + size + 1
    return blobs


def step_provenance_rerun(pkg):
    """The repeat ran scripts_v005 and stand_v005 of commit 6eb755e, laid out by deploy_stage3.sh;
    memcached ran from a copy of them with two version patterns corrected."""
    logs = pkg.run / "vm-logs"
    deployed = {}
    for line in (logs / "deployed-sha256.txt").read_text(encoding="utf-8").splitlines():
        digest, name = line.split(maxsplit=1)
        if name != "./deployed-sha256.txt":
            deployed[name.removeprefix("./")] = digest
    commit = re.search(r"^COMMIT=(\w+)", (logs / "deployed-from.txt").read_text(encoding="utf-8"), re.M).group(1)
    sources = {name: deployed_source(name) for name in deployed}
    unknown = [n for n, s in sources.items() if s is None]
    blobs = git_blobs(commit, [s for s in sources.values() if s]) if not unknown else None
    if blobs is None:
        report(f"files deployed on the stand against commit {commit[:7]}", False,
               f"needs git and the history of the repository; unmapped: {unknown}" if unknown else
               "needs git and the history of the repository (a clone, not an archive of it)")
    else:
        bad = [n for (n, s), blob in zip([(n, s) for n, s in sources.items() if s], blobs)
               if hashlib.sha256(blob).hexdigest() != deployed[n]]
        report(f"files deployed on the stand against commit {commit[:7]}", commit == RERUN_COMMIT and not bad,
               f"{len(deployed)} files, {len(bad)} differ")
    bad, count = [], 0
    for record in (pkg.raw / "driver" / "primary-source-sha256.txt",
                   MEMCACHED / "results_v005" / "driver" / "addendum2-memcached-source-sha256.txt"):
        for line in record.read_text(encoding="utf-8").splitlines():
            digest, name = line.split(maxsplit=1)
            name = name.removeprefix("/root/systemd-hardening-lab/")
            count += 1
            if name in deployed:
                ok = deployed[name] == digest
            elif name == "memcached_addendum2.sh":
                ok = sha256(MEMCACHED / name) == digest
            elif name.startswith("frozen-memcached-addendum/"):
                ok = sha256(MEMCACHED / name) == digest
            elif name == "post-analysis/analyze_memcached_v005.py":
                ok = deployed["post-analysis/analyze_memcached_v005.py"] == digest
            else:
                ok = False
            if not ok:
                bad.append(name)
    report("queue drivers against the hashes recorded on the stand", not bad, f"{count} entries")
    # frozen-memcached-addendum = frozen-timing as deployed, except the two version patterns
    copy = MEMCACHED / "frozen-memcached-addendum" / "v005"
    bad, count = [], 0
    for path in sorted(p for p in copy.rglob("*") if p.is_file()):
        name = "frozen-timing/v005/" + path.relative_to(copy).as_posix()
        count += 1
        data = path.read_bytes()
        if name.endswith("/memcached_stage3_v005.sh"):
            original = git_blobs(commit, [deployed_source(name)])
            expected = original and re.sub(rb"\[a-zA-Z0-9\.-\]\*\$", b"[a-zA-Z0-9._-]*$", original[0])
            ok = expected == data and original[0] != data
        else:
            ok = deployed.get(name) == hashlib.sha256(data).hexdigest()
        if not ok:
            bad.append(name)
    missing = [n for n in deployed if n.startswith("frozen-timing/") and not (copy / n[len("frozen-timing/v005/"):]).is_file()]
    report("corrected memcached copy against the deployed scripts", not bad and not missing,
           f"{count} files, {len(bad)} differ, {len(missing)} missing; only the two version patterns changed")


def step_criteria(pkg, tmp):
    combined = tmp / "combined.csv"
    run([SCRIPTS / "build_criteria_v005.py", *pkg.base, "--scenarios", pkg.scenarios, *pkg.combined, "--out", combined])
    report("combined criteria (table 10)", table(combined) == table(pkg.final / "combined-criteria-INCOMPLETE_SCOPE.csv"))
    for name, (service, family, bench) in pkg.families.items():
        out = tmp / f"{name}.csv"
        run([SCRIPTS / "build_criteria_v005.py", *pkg.base, "--scenarios", pkg.final / f"{name}-candidate-scope",
             "--family", f"{service}={family}", *bench, "--out", out])
        report(f"family {name}, M={family}", table(out) == table(pkg.final / f"{name}-criteria.csv"))
    return combined


def step_selection(pkg, combined):
    text = run([SCRIPTS / "select_profile_v005.py", combined])
    report("selection, rules A / A+ / B (table 11)",
           body(text) == body((pkg.final / "combined-selection-INCOMPLETE_SCOPE.txt").read_text(encoding="utf-8")))
    rows = []
    for service, crit in read_criteria(combined).items():
        for budget in [2, 5, 10, 15]:
            cands = restricted(admissible(crit, budget))
            for policy in itertools.permutations(["s", "emicro", "exposure", "n"]):
                rows.append((service, str(budget), ";".join(policy), pick(cands, lex(["g", *policy]))))
    report("24 operator policies (table S6)", [("service", "budget", "policy", "outcome"), *rows]
           == table(pkg.final / "policy24.csv"))
    text = run([SCRIPTS / "order_sensitivity_v005.py", combined])
    report("order sensitivity", body(text) == body((pkg.final / "order-sensitivity.txt").read_text(encoding="utf-8")))
    text = (run([SCRIPTS / "select_profile_v005.py", combined, "--require", "nginx=G2-read-app-secret"])
            + run([SCRIPTS / "select_profile_v005.py", combined, "--require", "nginx=G1-replace-document"]))
    saved = (pkg.saved / pkg.required).read_text(encoding="utf-8")
    report("required goals G2 / G1 (section 6.9)",
           [l.rstrip() for l in text.splitlines() if l.strip()] == [l.rstrip() for l in saved.splitlines() if l.strip()])


def step_descriptive(pkg):
    text = run([SCRIPTS / "robustness_v005.py", "--family", "4", "--pairs", "P1c-P5,P1c-P6",
                f"R1={pkg.series['R1'] / 'results.csv'}"])
    report("direct contrasts P1c-P5, P1c-P6 (section 6.7)",
           body(text) == body((pkg.final / "R1-robustness-descriptive.txt").read_text(encoding="utf-8")))
    text = run([SCRIPTS / "point_estimates_v005.py", pkg.run])
    saved = "point_estimates_v005.txt" if pkg is MAIN else "point_estimates.txt"
    report("point estimates (table 10, sections 6.8, 6.10)",
           text.split() == (pkg.saved / saved).read_text(encoding="utf-8").split())


def step_postgresql(pkg, tmp):
    out = tmp / "pg.csv"
    run([SCRIPTS / "pg_contrasts.py", pkg.run, "--out-csv", out])
    report("PostgreSQL t-bounds vs permutation bounds (table S4)",
           table(out) == table(pkg.saved / "pg_contrasts.csv"))


def step_repeats(pkg, tmp):
    out = tmp / "stalls.csv"
    text = run([SCRIPTS / "stall_sensitivity.py", pkg.run, "--out-csv", out])
    saved = pkg.saved / "stall_sensitivity.txt"
    report("repeated measurements and their effect on the bounds",
           text.split() == saved.read_text(encoding="utf-8").split()
           and table(out) == table(pkg.saved / "stall_sensitivity.csv"))


def step_memcached(tmp):
    """The call of analyze_memcached_v005.py: contract and goals from the functional run."""
    functional = next((MEMCACHED_RAW / "functional-v005").iterdir())
    probe = next((MEMCACHED_RAW / "probe-v005").iterdir())
    bench = next((MEMCACHED_RAW / "benchmark-v005").iterdir())
    saved = MEMCACHED / "post-analysis" / "memcached-analysis-first-look"
    out = tmp / "memcached.csv"
    run([SCRIPTS / "build_criteria_v005.py", "--probe", probe, "--scenarios", functional, "--contract", functional,
         "--bench", f"memcached={bench}", "--level", "0.05", "--family", "memcached=4", "--looks", "2", "--out", out])
    report("memcached criteria (tables 5, 10)", table(out) == table(saved / "criteria.csv"))
    text = run([SCRIPTS / "select_profile_v005.py", out])
    report("memcached selection (table 11)", body(text) == body((saved / "selection.txt").read_text(encoding="utf-8")))


def step_ttl(tmp):
    """The verdict of memcached_ttl_diagnostic.py summarize, recomputed from the rows of the run."""
    (tmp / "rows.csv").write_bytes((TTL_DIAGNOSTIC / "rows.csv").read_bytes())
    run([SCRIPTS / "memcached_ttl_diagnostic.py", "summarize", "--dir", tmp])
    report("memcached TTL diagnostic summary",
           (tmp / "summary.txt").read_text(encoding="utf-8").split()
           == (TTL_DIAGNOSTIC / "summary.txt").read_text(encoding="utf-8").split())


def check(pkg, quick):
    print(f"package: {pkg.run.relative_to(ROOT).as_posix()}")
    if not quick:
        step_raw(pkg)
    (step_provenance_main if pkg is MAIN else step_provenance_rerun)(pkg)
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        combined = step_criteria(pkg, tmp)
        step_selection(pkg, combined)
        step_descriptive(pkg)
        step_postgresql(pkg, tmp)
        step_repeats(pkg, tmp)
        if pkg is RERUN:
            step_memcached(tmp)
            step_ttl(tmp)


def main():
    names = [a for a in sys.argv[1:] if not a.startswith("--")] or list(PACKAGES)
    for name in names:
        check(PACKAGES[name], "--quick" in sys.argv)
    print(f"{sum(results)}/{len(results)} checks passed")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
