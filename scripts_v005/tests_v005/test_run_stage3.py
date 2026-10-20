"""Offline test of run_stage3.sh: no VM, no systemd.

Stub measurement scripts replay the published series of data/main/raw-vm, so
the ledger and markers written by the new driver are checked by the unchanged
analyze_v005.py on real data (Bonferroni bounds, plan of the extension).
Needs bash (Git Bash on Windows) and the full repository with data/.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / 'scripts_v005'
RAW = REPO / 'data' / 'main' / 'raw-vm'
BASH = os.environ.get('SLAB_BASH') or shutil.which('bash')

# What the executed run measured for each call of benchmark_v005.sh.
SERIES = {
    ('nginx', '10', 'P4', '25'): 'nginx/benchmark-v005/20261012-175204',
    ('nginx', '60', 'P1c P4 P5 P6', '25'): 'nginx/benchmark-v005/20261012-175912',
    ('redis', '20', 'P1 P2 P1d P4 P6', '25'): 'redis/benchmark-v005/20261012-194224',
    ('postgresql', '10', 'P1 P2 P1d P4 P6', '25'): 'postgresql/benchmark-v005/20261013-193448',
    ('nginx', '60', 'P1 P2 P1r', '25'): 'nginx/benchmark-v005/20261013-204356',
    ('nginx', '3', 'P4', '1'): 'nginx/benchmark-v005/20261013-220413',
    ('nginx', '3', 'P4', '2'): 'nginx/benchmark-v005/20261013-220630',
    ('nginx', '3', 'P4', '4'): 'nginx/benchmark-v005/20261013-220836',
    ('nginx', '3', 'P4', '8'): 'nginx/benchmark-v005/20261013-221032',
    ('nginx', '3', 'P4', '16'): 'nginx/benchmark-v005/20261013-221223',
}
PREFLIGHT = {'functional_ext_v005.sh': 'functional-v005/20261012-104934',
             'scenarios_v005.sh': 'scenarios-v005/20261012-110837',
             'probe_all_v005.sh': 'probe-v005/20261012-110043'}

REPLAY = r'''#!/usr/bin/env bash
# Stub of benchmark_v005.sh: replays one published series under a new name.
set -euo pipefail
key="$1|$2|${*:3}|${NGINX_C:-25}"
source=$(awk -F'\t' -v k="$key" '$1==k {print $2}' "$SLAB_TEST_MAP")
[ -n "$source" ] || { echo "UNPLANNED CALL $key"; exit 2; }
echo "$key" >> "$SLAB_TEST_CALLS"
while :; do
    out="$SLAB_RESULTS_ROOT/$1/benchmark-v005/$(date +%Y%m%d-%H%M%S)"
    [ -e "$out" ] || break; sleep 1
done
mkdir -p "$(dirname "$out")"; cp -r "$SLAB_TEST_RAW/$source" "$out"
echo "RESULT_DIR=$out"
'''
PRE = r'''#!/usr/bin/env bash
set -euo pipefail
echo "$(basename "$0") ${*:-} PROFILES=${PROFILES:-}${REDIS_PROFILES:-}${PROBE_PROFILES:-}" >> "$SLAB_TEST_CALLS"
src=@SRC@
[ -z "$src" ] && exit 0
out="$SLAB_RESULTS_ROOT/$src"; mkdir -p "$(dirname "$out")"; cp -r "$SLAB_TEST_RAW/$src" "$out"
echo "RESULT_DIR=$out"
'''
COMMON = r'''ROOT=${SLAB_RESULTS_ROOT:?}
svc_profiles() { echo "$ROOT/$1/profiles"; }
require_rest_state() { echo "rest $*" >> "$SLAB_TEST_CALLS"; }
require_files() { local f; for f in "$@"; do [ -e "$f" ] || return 1; done; }
'''
SYSTEMCTL = r'''#!/usr/bin/env bash
echo "systemctl $*" >> "$SLAB_TEST_CALLS"
case "$1 ${*: -1}" in
    'show '*) echo not-found ;;
    'is-active memcached.service') exit 3 ;;
esac
exit 0
'''
APT_GET = r'''#!/usr/bin/env bash
echo "apt-get $*" >> "$SLAB_TEST_CALLS"
[ "$1" = -s ] && cat "$SLAB_TEST_APT_PLAN"
exit 0
'''
# The version patterns of the executed memcached_stage3_v005.sh, without '_'.
MEMCACHED_STAGE3 = r'''#!/usr/bin/env bash
    [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+[a-zA-Z0-9.-]*$ ]] || die 'invalid registered memcached version'
    VERSION=$("$BINARY" -V 2>&1 | awk '{print $NF}')
    [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+[a-zA-Z0-9.-]*$ ]] || die 'cannot identify installed memcached version'
'''


@unittest.skipUnless(BASH and RAW.is_dir(), 'bash and data/main/raw-vm are required')
class RunStage3Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='stage3-')
        tmp = Path(self.tmp.name)
        self.base = tmp / 'base'
        here = self.base / 'frozen-timing' / 'v005' / 'scripts_v005'
        here.mkdir(parents=True)
        (here / 'slab_common_v005.sh').write_text(COMMON, newline='\n')
        for name in ('benchmark_v005.sh', 'slab_heartbeat_v005.py'):
            (here / name).write_text(REPLAY, newline='\n')
        for name in ('functional_ext_v005.sh', 'context_compare_v005.sh', 'scenarios_v005.sh',
                     'supplement_goals_v005.sh', 'probe_all_v005.sh'):
            (here / name).write_text(PRE.replace('@SRC@', PREFLIGHT.get(name, '')), newline='\n')
        shutil.copy(SCRIPTS / 'orchestration_v005' / 'run_stage3.sh', self.base)
        shutil.copy(SCRIPTS / 'analysis_v005' / 'inspect_series_v005.py', self.base)
        self.root = self.base / 'results_v005'
        bin_dir = tmp / 'bin'
        bin_dir.mkdir()
        (bin_dir / 'id').write_text('#!/usr/bin/env bash\necho 0\n', newline='\n')
        (bin_dir / 'pgrep').write_text('#!/usr/bin/env bash\nexit 1\n', newline='\n')
        (bin_dir / 'rpm').write_text('#!/usr/bin/env bash\nexit 1\n', newline='\n')
        (bin_dir / 'ss').write_text('#!/usr/bin/env bash\nexit 0\n', newline='\n')
        (bin_dir / 'systemctl').write_text(SYSTEMCTL, newline='\n')
        (bin_dir / 'apt-get').write_text(APT_GET, newline='\n')
        (here / 'memcached_stage3_v005.sh').write_text(MEMCACHED_STAGE3, newline='\n')
        (self.base / 'frozen-timing' / 'v005' / 'stand_v005').mkdir()
        (bin_dir / 'chronyc').write_text(
            '#!/usr/bin/env bash\necho "System time     : 0.000012 seconds fast of NTP time"\n', newline='\n')
        (bin_dir / 'python3').write_text(f'#!/usr/bin/env bash\nexec "{Path(sys.executable).as_posix()}" "$@"\n',
                                         newline='\n')
        self.calls = tmp / 'calls.txt'
        self.ports = tmp / 'reserved-ports'
        self.ports.write_text('\n', newline='\n')
        series_map = tmp / 'map.tsv'
        series_map.write_text(''.join(f"{'|'.join(k)}\t{v}\n" for k, v in SERIES.items()), newline='\n')
        self.apt_plan = tmp / 'apt-plan.txt'
        self.env = dict(os.environ, SLAB_BASE=self.base.as_posix(), SLAB_TEST_CALLS=self.calls.as_posix(),
                        SLAB_TEST_APT_PLAN=self.apt_plan.as_posix(),
                        SLAB_TEST_RAW=RAW.as_posix(), SLAB_TEST_MAP=series_map.as_posix(),
                        SLAB_RESERVED_PORTS_FILE=self.ports.as_posix(),
                        PATH=bin_dir.as_posix() + os.pathsep + os.environ['PATH'])

    def tearDown(self):
        self.tmp.cleanup()

    def run_phase(self, phase):
        return subprocess.run([BASH, (self.base / 'run_stage3.sh').as_posix(), phase],
                              env=self.env, capture_output=True, text=True, encoding='utf-8')

    def call(self, function):
        """One function of run_stage3.sh, sourced without running a phase; called in a
        list, as run_logged calls it, so that set -e does not apply inside."""
        script = (self.base / 'run_stage3.sh').as_posix()
        return subprocess.run([BASH, '-c', f'. "{script}" library && {{ {function} || exit $?; }}'],
                              env=self.env, capture_output=True, text=True, encoding='utf-8')

    def analyzer(self):
        spec = importlib.util.spec_from_file_location('analyze_tested', SCRIPTS / 'analysis_v005' / 'analyze_v005.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.RAW = self.root
        module.REMOTE_PREFIX = self.root.as_posix() + '/'
        return module

    def test_queue_matches_protocol_and_analyzer(self):
        for phase in ('preflight', 'primary'):
            result = self.run_phase(phase)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls.read_text().splitlines()
        bench = [c for c in calls if c.count('|') == 3]
        self.assertEqual(bench, ['|'.join(k) for k in SERIES])  # protocol order, R4 pilots C=1..16
        self.assertEqual((self.root / 'driver' / 'R4-condition.txt').read_text().split(':')[0], 'R4=FAILED')
        self.assertEqual(self.ports.read_text().strip(), '')  # 55432 released after R3
        log = (self.root / 'driver' / 'pg-port-reservation.txt').read_text()
        self.assertIn('RESERVED 55432 R3', log)
        self.assertIn('RELEASED 55432 R3', log)

        analyze = self.analyzer()
        series, coverage = analyze.completed_series()
        self.assertEqual(sorted(series), ['R1-nginx', 'R2-redis', 'R3-postgresql', 'R5-nginx-light'])
        self.assertEqual(coverage['R4-nginx-nonsaturated']['status'], 'NO_VALID_PRIMARY')
        for stage in ('functional', 'microprobes', 'scenarios-diagnostic'):
            self.assertTrue(analyze.preflight_directory(stage).is_dir())
        # The first-look rule of analyze_v005.py gives the executed plan of the extension.
        planned = []
        for name, directory in series.items():
            service, blocks, profiles, family = analyze.SPEC[name]
            measured = analyze.criteria.bench_bounds([directory / 'results.csv'], 0.05 / (family * 2))
            needed = [p for p in profiles if measured[p][0] <= 0 <= measured[p][1]]
            if needed:
                planned.append({'stage': name, 'profiles': needed})
        published = json.loads((REPO / 'data' / 'main' / 'protocol' / 'extension-plan.json').read_text())
        self.assertEqual(planned, [{'stage': r['stage'], 'profiles': r['profiles']} for r in published['extensions']])

        # seal: the manifest is the one verify_raw_v005.py checks on the host.
        (self.root / 'driver' / 'post-primary-finished.txt').write_text('2026-10-19T00:00:00+00:00\n')
        final = self.base / 'post-analysis' / 'analysis-final'
        final.mkdir(parents=True)
        (final / 'combined-selection.txt').write_text('stub\n')
        result = self.run_phase('seal')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with tarfile.open(self.base / 'results_v005-closed.tar.gz') as archive:
            names = set(archive.getnames())
        self.assertIn('post-analysis/analysis-final/combined-selection.txt', names)
        self.assertIn('results_v005/SHA256-CLOSED-RESULTS.txt', names)
        spec = importlib.util.spec_from_file_location('verify_tested', SCRIPTS / 'analysis_v005' / 'verify_raw_v005.py')
        verify = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verify)
        checked = verify.verify(self.root, self.root / 'SHA256-CLOSED-RESULTS.txt')
        self.assertTrue(checked['verified'], checked)
        self.assertEqual(checked['unlisted_local_files'], [])

    def test_phases_run_once_and_in_order(self):
        result = self.run_phase('primary')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Preflight has not finished', result.stdout)
        self.assertEqual(self.run_phase('preflight').returncode, 0)
        again = self.run_phase('preflight')
        self.assertNotEqual(again.returncode, 0)
        self.assertIn('already started', again.stdout)

    def test_preflight_starts_process_targets(self):
        self.assertEqual(self.run_phase('preflight').returncode, 0)
        calls = self.calls.read_text().splitlines()
        for user in ('root', 'labweb', 'labredis', 'labpg'):
            self.assertIn(f'systemctl start lab-proc-target@{user}.service', calls)
        # the targets run before the first preflight stage
        self.assertLess(calls.index('systemctl start lab-proc-target@labpg.service'),
                        next(i for i, c in enumerate(calls) if c.startswith('functional_ext_v005.sh')))
        self.assertEqual(len((self.root / 'driver' / 'preflight-targets.txt').read_text().splitlines()), 4)

    def test_memcached_version_with_alt_suffix_is_accepted(self):
        plan = 'Inst memcached (1.6.42-alt1:p11+418735.100.1.1@1779279920 ALT p11:p11/branch [x86_64])\n'
        tail = '0 upgraded, 1 newly installed, 0 removed and 0 not upgraded.\n'
        self.apt_plan.write_text(plan + tail, newline='\n')
        result = self.call('install_memcached')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('apt-get -y install memcached', self.calls.read_text())
        self.apt_plan.write_text(plan.replace('1.6.42-alt1:', '1.6.43-alt1:') + tail, newline='\n')
        result = self.call('install_memcached')
        self.assertEqual(result.returncode, 2)
        self.assertIn('memcached 1.6.43-alt1 differs from 1.6.42-alt1', result.stdout)

    def test_memcached_copy_allows_underscore_in_version(self):
        result = self.call('memcached_copy')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        diff = (self.root / 'driver' / 'memcached-stage3.diff').read_text().splitlines()
        self.assertEqual([l[1:] for l in diff if l.startswith('+ ')],
                         [l[1:].replace('a-zA-Z0-9.-', 'a-zA-Z0-9._-') for l in diff if l.startswith('- ')])
        copy = self.base / 'frozen-memcached' / 'v005' / 'scripts_v005' / 'memcached_stage3_v005.sh'
        patterns = [l.split('=~ ')[1].split(' ]]')[0] for l in copy.read_text().splitlines() if '=~' in l]
        self.assertEqual(len(patterns), 2)
        for version in ('1.6.42_alt1', '1.6.42-alt1'):
            for pattern in patterns:
                check = subprocess.run([BASH, '-c', f'[[ "{version}" =~ {pattern} ]]'])
                self.assertEqual(check.returncode, 0, (version, pattern))
        # the sealed frozen-timing copy is not changed, a second copy is refused
        frozen = self.base / 'frozen-timing' / 'v005' / 'scripts_v005' / 'memcached_stage3_v005.sh'
        self.assertEqual(frozen.read_text(), MEMCACHED_STAGE3)
        self.assertEqual(self.call('memcached_copy').returncode, 2)

    def test_foreign_port_reservation_is_not_overwritten(self):
        self.assertEqual(self.run_phase('preflight').returncode, 0)
        self.ports.write_text('40000\n', newline='\n')
        result = self.run_phase('primary')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('not overwritten', result.stdout)
        self.assertEqual(self.ports.read_text().strip(), '40000')


if __name__ == '__main__':
    unittest.main()
