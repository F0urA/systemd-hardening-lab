"""Synthetic ledgers/CSV only. No real measurement data, network, or VM."""
import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import contextlib
import io
from unittest.mock import patch

sys.dont_write_bytecode = True
WORK = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('analysis_tested', WORK / 'results/analyze_v005.py')
a = importlib.util.module_from_spec(spec); spec.loader.exec_module(a)
BASH = Path('<OPERATOR_RUNTIME>/native/git/usr/bin/sh.exe')


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.raw = self.root / 'raw-vm'
        self.driver = self.raw / 'driver'; self.driver.mkdir(parents=True)
        self.short_spec = {name: (svc, 3, profiles, family)
                           for name, (svc, _, profiles, family) in a.SPEC.items()}
        self.patchers = [patch.object(a, 'ROOT', self.root), patch.object(a, 'RAW', self.raw),
                         patch.object(a, 'SPEC', self.short_spec)]
        for p in self.patchers: p.start()
        self.number = 0

    def tearDown(self):
        for p in reversed(self.patchers): p.stop()
        self.tmp.cleanup()

    def csv_write(self, path, fields, rows):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(rows)

    def bench(self, stage, profiles=None, concurrency='25', pilot=False):
        self.number += 1
        service, blocks, allowed, _ = self.short_spec[stage]
        profiles = ['P0', *(allowed if profiles is None else profiles)]
        suffix = f'{service}/benchmark-v005/20261013-12{self.number:04d}'
        directory = self.raw / suffix; directory.mkdir(parents=True)
        metric = 'tps' if service == 'postgresql' else 'rps'
        fields = ['block','order','profile',metric,'cpu_pct','cpu_us_per_op',
                  'ops','wall_ns','failed','max_gap_ms','attempt']
        rows = [{'block': b, 'order': i, 'profile': p, metric: 100 if p == 'P0' else 95,
                 'cpu_pct': 55, 'cpu_us_per_op': 550,
                 'ops': 200000 if service == 'nginx' else 3000000 if service == 'redis' else 1000,
                 'wall_ns': 1000000000,
                 'failed': 0, 'max_gap_ms': 1, 'attempt': 1}
                for b in range(1, blocks + 1) for i,p in enumerate(profiles, 1)]
        self.csv_write(directory/'results.csv', fields, rows)
        for row in rows:
            tag=f"B{row['block']}-{row['profile']}-a{row['attempt']}"
            if service == 'nginx':
                for gen in (1,2):
                    (directory/f'ab-{tag}-g{gen}.txt').write_text('Complete requests: 100000\nFailed requests: 0\n')
            elif service == 'redis':
                (directory/f'redis-{tag}.txt').write_text('GET: 1234.56 requests per second\n')
            else:
                (directory/f'pgbench-{tag}.txt').write_text('number of transactions actually processed: 1000\n'
                    'number of failed transactions: 0 (0.000%)\ntps = 1000.00 (without initial connection time)\n')
        self.csv_write(directory/'invalid.csv', ['block','order','profile','attempt','throughput','max_gap_ms','reason'], [])
        (directory/'platform.txt').write_text(
            f'SERVICE={service} BLOCKS={blocks} PIN=1 SERVER_CPU=0 CLIENT_CPUS=1-3\n'
            f'KEEPALIVE=0 NGINX_N=100000 NGINX_C={concurrency} REDIS_N=3000000 REDIS_THREADS=3 PG_T=60 STALL_MS=500\n'
            'ELAPSED_CLOCK=CLOCK_MONOTONIC_RAW (UTC only labels)\n')
        (directory/'run.log').write_text(f'===== BENCHMARK COMPLETE =====\nRESTORE_P4 {service}=PASS\n')
        self.rehash(directory)
        return a.REMOTE_PREFIX + suffix, directory

    def rehash(self, directory):
        (directory/'sha256-results.txt').write_text(a.digest(directory/'results.csv') + '  results.csv\n')

    def row(self, stage, remote='', rc=0):
        return dict(zip(a.LEDGER_FIELDS, [stage,'2026-10-13T12:00:00+00:00',
                    '2026-10-13T13:00:00+00:00',str(rc),remote]))

    def primary(self):
        rows = []
        for stage in self.short_spec:
            remote,_ = self.bench(stage, concurrency='1' if stage == 'R4-nginx-nonsaturated' else '25')
            rows.append(self.row(stage, remote))
        remote,_ = self.bench('R4-nginx-nonsaturated', ['P4'], concurrency='1', pilot=True)
        rows.append(self.row('R4-pilot-c1', remote))
        self.csv_write(self.driver/'primary-corrected-ledger.csv', a.LEDGER_FIELDS, rows)
        (self.driver/'primary-corrected-finished.txt').write_text('2026-10-13T14:00:00+00:00\n')
        (self.driver/'R4-condition.txt').write_text('R4_CHOSEN_C=1\n')
        return rows

    def plan(self, profiles=None):
        series,coverage = a.completed_series()
        plan = {'schema':'v005-first-look-plan-1','looks':2,'level':0.05,
                'trigger':'throughput_interval_contains_zero','primary':a.primary_fingerprint(series,coverage),
                'extensions':[{'stage':'R1-nginx','service':'nginx','blocks':3,
                               'profiles': profiles or ['P1c'],'family':7,'nginx_c':'25'}]}
        path = self.root/'extension-plan.json'; path.write_text(json.dumps(plan))
        record = self.root/'analysis-first-look'; record.mkdir(exist_ok=True)
        (record/'plan-record.json').write_text(json.dumps({'plan_sha256':a.digest(path)}))
        return plan,series,coverage

    def extension(self, plan, rows):
        self.csv_write(self.driver/'extension-ledger.csv',a.LEDGER_FIELDS,rows)
        (self.driver/'extensions-finished.txt').write_text('2026-10-13T14:00:00+00:00\n')
        (self.driver/'extension-plan.json').write_bytes((self.root/'extension-plan.json').read_bytes())

    def fake_analysis(self, final=False):
        """Exercise orchestration, not substitute a statistical calculation."""
        diagnostic=self.root/'diagnostic'; diagnostic.mkdir(exist_ok=True)
        self.csv_write(diagnostic/'candidates.csv',['service','profile'],
            [{'service':svc,'profile':p} for _,(svc,_,profiles,_) in self.short_spec.items() for p in ['P0',*profiles]])
        self.csv_write(diagnostic/'goals.csv',['service','profile'],[])
        calls=[]
        def command(args,out):
            args=list(map(str,args)); calls.append(args)
            out.write_text('synthetic subprocess output\n')
            if '--out' in args:
                Path(args[args.index('--out')+1]).write_text('service,profile\n')
        with patch.object(sys,'argv',['analyze_v005.py',*(['--final'] if final else [])]), \
                patch.object(a,'preflight_directory',return_value=diagnostic), \
                patch.object(a,'command',side_effect=command), patch.object(a,'read_criteria',return_value={}), \
                contextlib.redirect_stdout(io.StringIO()):
            a.main()
        return calls

    def test_no_marker_refuses_before_reading_any_benchmark(self):
        with patch.object(a,'validate') as validator:
            with self.assertRaisesRegex(ValueError,'has not finished'): a.completed_series()
            validator.assert_not_called()

    def test_duplicate_and_success_then_retry_ledgers_rejected(self):
        self.primary()
        rows = a.read_ledger(self.driver/'primary-corrected-ledger.csv')
        for extra in [rows[0], dict(rows[0],stage='R1-nginx-retry')]:
            with self.subTest(stage=extra['stage']):
                with self.assertRaises(ValueError): a.attempts(rows+[extra],set(self.short_spec)|a.PILOTS)

    def test_partial_duplicate_wrong_profile_and_wrong_order_csv(self):
        remote,directory = self.bench('R1-nginx')
        with (directory/'results.csv').open(newline='') as f:
            reader=csv.DictReader(f); fields=reader.fieldnames; original=list(reader)
        cases=[original[:-1],original+[original[0]],
               [dict(original[0],profile='P9')]+original[1:],
               [dict(original[0],order='2')]+original[1:]]
        for rows in cases:
            self.csv_write(directory/'results.csv',fields,rows); self.rehash(directory)
            with self.assertRaises(ValueError): a.validate('R1-nginx',directory)

    def test_old_clock_missing_footer_and_mismatched_hash_rejected(self):
        _,directory = self.bench('R1-nginx')
        platform=(directory/'platform.txt').read_text()
        (directory/'platform.txt').write_text(platform.replace('CLOCK_MONOTONIC_RAW','CLOCK_REALTIME'))
        with self.assertRaises(ValueError): a.validate('R1-nginx',directory)
        (directory/'platform.txt').write_text(platform)
        (directory/'sha256-results.txt').write_text('0'*64+'  results.csv\n')
        with self.assertRaises(ValueError): a.validate('R1-nginx',directory)
        self.rehash(directory); (directory/'run.log').write_text('incomplete')
        with self.assertRaises(ValueError): a.validate('R1-nginx',directory)

    def test_native_count_proof_and_quiet_redis_limitation(self):
        _,directory=self.bench('R1-nginx')
        proof=a.validate('R1-nginx',directory)['raw_count_audit']
        self.assertFalse(proof['limitations'])
        self.assertEqual(proof['measurements'][0]['native_completed'],200000)
        first=directory/'ab-B1-P0-a1-g1.txt'
        first.write_text('Complete requests: 99999\nFailed requests: 0\n')
        with self.assertRaisesRegex(ValueError,'Complete count'): a.validate('R1-nginx',directory)
        first.write_text('Complete requests: 100000\nFailed requests: 0\nNon-2xx responses: 1\n')
        with self.assertRaisesRegex(ValueError,'native counts'): a.validate('R1-nginx',directory)
        _,redis=self.bench('R2-redis')
        proof=a.validate('R2-redis',redis)['raw_count_audit']
        self.assertEqual(proof['limitations'],['COUNTS_NOT_EXPOSED_BY_QUIET_OUTPUT'])
        self.assertNotIn('native_completed',proof['measurements'][0])
        first=redis/'redis-B1-P0-a1.txt'
        first.write_text('  3000000 requests completed in 1.00 seconds\nGET: 1234.56 requests per second\n')
        proof=a.validate('R2-redis',redis)['raw_count_audit']
        self.assertEqual(proof['measurements'][0]['native_completed'],3000000)
        _,pg=self.bench('R3-postgresql')
        first=pg/'pgbench-B1-P0-a1.txt'
        first.write_text('number of transactions actually processed: 999\nnumber of failed transactions: 0\n')
        with self.assertRaisesRegex(ValueError,'native counts'): a.validate('R3-postgresql',pg)

    def test_missing_stage_and_failure_without_terminal_retry_rejected(self):
        rows=self.primary()
        self.csv_write(self.driver/'primary-corrected-ledger.csv',a.LEDGER_FIELDS,rows[1:])
        with self.assertRaisesRegex(ValueError,'missing required stages'): a.completed_series()
        rows[0]=dict(rows[0],exit_status='2')
        self.csv_write(self.driver/'primary-corrected-ledger.csv',a.LEDGER_FIELDS,rows)
        with self.assertRaisesRegex(ValueError,'terminal retry'): a.completed_series()

    def test_terminal_primary_failure_preserved_not_pooled(self):
        rows=self.primary(); rows[0]=dict(rows[0],exit_status='2')
        remote,_=self.bench('R1-nginx')
        rows.insert(1,self.row('R1-nginx-retry',remote,2))
        self.csv_write(self.driver/'primary-corrected-ledger.csv',a.LEDGER_FIELDS,rows)
        series,coverage=a.completed_series()
        self.assertNotIn('R1-nginx',series)
        self.assertEqual(coverage['R1-nginx']['status'],'NO_VALID_PRIMARY')
        self.assertIn('R2-redis',series)

    def test_plan_profiles_family_and_source_fingerprint_are_immutable(self):
        self.primary(); plan,series,coverage=self.plan()
        self.assertEqual(a.saved_plan(self.root/'extension-plan.json',series,coverage),plan)
        for changes in [dict(profiles=['P1c','P1c']),dict(profiles=['P9']),dict(family=4),dict(blocks=4)]:
            altered=json.loads(json.dumps(plan)); altered['extensions'][0].update(changes)
            with self.assertRaises(ValueError): a.validate_plan(altered)
        source=next(iter(series.values()))/'platform.txt'; source.write_text(source.read_text()+'NOTE=changed\n')
        with self.assertRaisesRegex(ValueError,'fingerprint'): a.saved_plan(self.root/'extension-plan.json',series,coverage)

    def test_extension_exact_set_and_blocks_against_plan(self):
        self.primary(); plan,_,_=self.plan()
        remote,_=self.bench('R1-nginx',['P4']) # Wrong but primary-compatible profile.
        self.extension(plan,[self.row('R1-nginx-extension',remote)])
        extensions,coverage=a.extension_map(plan)
        self.assertEqual(extensions,{})
        self.assertEqual(coverage['R1-nginx']['status'],'NO_VALID_EXTENSION')
        remote,directory=self.bench('R1-nginx',['P1c'])
        self.extension(plan,[self.row('R1-nginx-extension',remote)])
        extensions,_=a.extension_map(plan)
        self.assertEqual(extensions['R1-nginx'],directory)

    def test_unfinished_unplanned_duplicate_or_reused_extension_rejected(self):
        self.primary(); plan,_,_=self.plan()
        remote,_=self.bench('R1-nginx',['P1c'])
        row=self.row('R1-nginx-extension',remote)
        self.extension(plan,[row]); (self.driver/'extensions-finished.txt').unlink()
        with self.assertRaises(ValueError): a.extension_map(plan)
        for rows in [[row,row],[self.row('R2-redis-extension',remote)],
                     [self.row('R1-nginx-extension',plan['primary']['series']['R1-nginx']['directory'])]]:
            self.extension(plan,rows)
            with self.assertRaises(ValueError): a.extension_map(plan)

    def test_failed_planned_extension_is_terminal_and_visible(self):
        self.primary(); plan,_,_=self.plan()
        one,_=self.bench('R1-nginx',['P1c']); two,_=self.bench('R1-nginx',['P1c'])
        self.extension(plan,[self.row('R1-nginx-extension',one,2),self.row('R1-nginx-extension-retry',two,2)])
        extensions,coverage=a.extension_map(plan)
        self.assertFalse(extensions)
        self.assertTrue(coverage['R1-nginx']['attempt_limit_exhausted'])
        self.assertEqual(coverage['R1-nginx']['status'],'NO_VALID_EXTENSION')

    def test_first_look_M7_K2_no_heavy_robustness_and_one_plan(self):
        self.primary(); calls=self.fake_analysis()
        plan=json.loads((self.root/'extension-plan.json').read_text())
        self.assertEqual(plan['looks'],2)
        self.assertEqual(plan['trigger'],'throughput_interval_contains_zero')
        self.assertEqual({r['family'] for r in plan['extensions'] if r['service']=='nginx' and r['stage']!='R4-nginx-nonsaturated'},{7})
        combined=next(c for c in calls if 'combined-criteria.csv' in ' '.join(c))
        self.assertIn('nginx=7',combined)
        self.assertEqual(combined[combined.index('--looks')+1],'2')
        self.assertFalse(any('robustness_v005.py' in ' '.join(c) for c in calls))
        original=(self.root/'extension-plan.json').read_bytes()
        self.fake_analysis(); self.assertEqual((self.root/'extension-plan.json').read_bytes(),original)
        self.extension(plan,[])
        with self.assertRaisesRegex(ValueError,'refusing a new first-look'): self.fake_analysis()

    def test_failed_extension_final_is_named_incomplete_keeps_first_bounds(self):
        self.primary(); plan,series,_=self.plan()
        before=a.criteria.bench_bounds([series['R1-nginx']/'results.csv'],0.05/(7*2))
        one,_=self.bench('R1-nginx',['P1c']); two,_=self.bench('R1-nginx',['P1c'])
        self.extension(plan,[self.row('R1-nginx-extension',one,2),self.row('R1-nginx-extension-retry',two,2)])
        calls=self.fake_analysis(final=True)
        final=self.root/'analysis-final'
        self.assertFalse((final/'combined-selection.txt').exists())
        self.assertIn('INCOMPLETE_SCOPE',(final/'combined-selection-INCOMPLETE_SCOPE.txt').read_text())
        self.assertIn('NO_VALID_EXTENSION',(final/'R1-nginx-selection-INCOMPLETE_SCOPE.txt').read_text())
        self.assertEqual(json.loads((final/'analysis-status.json').read_text())['failed_extension'],['R1-nginx'])
        self.assertFalse(any('+' in value and ('benchmark-v005' in value) for c in calls for value in c))
        self.assertEqual(a.criteria.bench_bounds([series['R1-nginx']/'results.csv'],0.05/(7*2)),before)

    def test_all_failed_primary_saves_empty_plan_and_no_selection(self):
        rows=self.primary(); final_rows=[]
        for row in rows:
            if row['stage'] in self.short_spec:
                final_rows.append(dict(row,exit_status='2'))
                final_rows.append(self.row(row['stage']+'-retry','',2))
            else: final_rows.append(row)
        self.csv_write(self.driver/'primary-corrected-ledger.csv',a.LEDGER_FIELDS,final_rows)
        with patch.object(sys,'argv',['analyze_v005.py']), patch.object(a,'command') as command, \
                contextlib.redirect_stdout(io.StringIO()):
            a.main()
            command.assert_not_called()
        plan=json.loads((self.root/'extension-plan.json').read_text())
        self.assertEqual(plan['extensions'],[])
        self.assertEqual(plan['primary']['series'],{})
        self.assertTrue((self.root/'analysis-first-look/NO_VALID_PRIMARY.txt').exists())
        self.extension(plan,[])
        self.fake_analysis(final=True)
        self.assertFalse((self.root/'analysis-final/combined-selection.txt').exists())

    def test_driver_syntax_single_claim_and_validation_hooks(self):
        driver=WORK/'experiment-work/driver_extensions_v005.sh'
        if BASH.exists():
            done=subprocess.run([str(BASH),'--noprofile','--norc','-n',str(driver)],capture_output=True,text=True)
            self.assertEqual(done.returncode,0,done.stderr)
        source=driver.read_text()
        self.assertIn('extension-claim-v005',source)
        self.assertIn('--validate-extension-result',source)
        self.assertIn('status=$overall',source)
        self.assertNotIn('while true',source)


if __name__ == '__main__': unittest.main()
