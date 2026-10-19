"""Local owned fixtures/mocked shell helpers only. No VM, network, real data."""
import ast
import contextlib
import csv
import importlib.util
import io
import json
import os
import shutil
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest.mock import patch

sys.dont_write_bytecode = True
ORCH = Path(__file__).resolve().parents[1] / 'orchestration_v005'
FILES = [ORCH/name for name in
    ('driver_primary_resume_v005.sh','driver_post_primary_resume_v005.sh')]
spec=importlib.util.spec_from_file_location('resume_transport_tested',ORCH/'resume_transport_v005.py')
t=importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
BASH=Path(os.environ.get('SLAB_SH') or shutil.which('sh') or shutil.which('bash') or 'sh')

def embedded(source):
    return {match[1]:match[2] for match in re.finditer(r"<<'([A-Z_]+)'\n(.*?)\n\1(?:\n|$)",source,re.S)}

class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='resume-mock-')
        self.root=Path(self.tmp.name); self.driver=self.root/'driver'; self.driver.mkdir()
        self.registration=self.driver/'resume-transport-registration.json'
        self.registration.write_text(json.dumps({'prior_reserved_ports':'','reserved_ports':'55432','scopes':t.SCOPES}))
        self.reserved=self.root/'mock-reserved-ports'; self.reserved.write_text('55432\n')
        self.transport=t.Transport(self.root,self.reserved)

    def tearDown(self): self.tmp.cleanup()

    def plan(self, pg=True, mixed=False):
        names=(['R1-nginx'] if mixed or not pg else [])+(['R3-postgresql'] if pg else [])
        rows=[]
        for name in names:
            svc,blocks,profiles,family=t.SPEC[name]
            rows.append({'stage':name,'service':svc,'blocks':blocks,'profiles':profiles[:1],
                         'family':family,'nginx_c':'25'})
        value={'schema':'v005-first-look-plan-1','level':0.05,'looks':2,
               'trigger':'throughput_interval_contains_zero','primary':{'series':{name:{} for name in names}},
               'extensions':rows}
        path=self.root/'extension-plan.json'; path.write_text(json.dumps(value)); return path,value

    def test_primary_reserve_release_and_exit_idempotence(self):
        token=self.transport.primary_check()
        self.assertEqual(self.transport.primary_restore(token,'AFTER_R3'),'RESTORED')
        self.assertEqual(self.reserved.read_text(),'\n')
        self.assertEqual(self.transport.primary_restore(token,'EXIT'),'ALREADY_RESTORED')
        record=json.loads(self.transport.primary_record.read_text())
        self.assertEqual(record['phase'],'AFTER_R3')
        self.assertEqual(record['scope'],'R3-postgresql-retry-only')

    def test_foreign_reservation_not_overwritten(self):
        token=self.transport.primary_check(); self.reserved.write_text('55432,55555\n')
        with self.assertRaisesRegex(ValueError,'NOT OVERWRITTEN'): self.transport.primary_restore(token,'EXIT')
        self.assertEqual(self.reserved.read_text(),'55432,55555\n')
        self.assertEqual(json.loads(self.transport.primary_record.read_text())['status'],'ERROR')

    def test_released_scope_never_clears_later_actor_even_exact55432(self):
        token=self.transport.primary_check(); self.transport.primary_restore(token,'AFTER_R3')
        self.reserved.write_text('55432\n')
        with self.assertRaisesRegex(ValueError,'scope ended'): self.transport.primary_restore(token,'EXIT')
        self.assertEqual(self.reserved.read_text(),'55432\n')

    def test_registration_exact_and_pinned(self):
        token=self.transport.primary_check()
        data=json.loads(self.registration.read_text()); data['extra']='changed'
        self.registration.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,'registration changed'): self.transport.primary_restore(token,'EXIT')
        data['scopes']=['R3-postgresql-retry-only']; self.registration.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,'two exact'): self.transport.primary_check()

    def test_mixed_pg_extension_same_driver_scope_roundtrip(self):
        self.reserved.write_text('\n'); path,_=self.plan(mixed=True)
        token=self.transport.extension_start(path)
        self.assertRegex(token,r'^[0-9a-f]{32}$'); self.assertEqual(self.reserved.read_text(),'55432\n')
        self.assertEqual(self.transport.extension_restore(token,'AFTER_EXTENSIONS'),'RESTORED')
        self.assertEqual(self.transport.extension_restore(token,'EXIT'),'ALREADY_RESTORED')
        events=[json.loads(line) for line in self.transport.extension_log.read_text().splitlines()]
        self.assertEqual([v['status'] for v in events],['RESERVE_INTENT','RESERVED_BEFORE_LOAD','RESTORED'])
        self.assertEqual(events[1]['plan_sha256'],t.sha(path))

    def test_non_pg_never_reads_or_writes_sysctl(self):
        path,_=self.plan(pg=False)
        self.assertFalse(t.plan_has_pg(path))
        with patch.object(self.transport,'current',side_effect=AssertionError('sysctl was touched')):
            with self.assertRaisesRegex(ValueError,'non-PG'): self.transport.extension_start(path)
        self.assertFalse(self.transport.extension_log.exists())

    def test_extension_foreign_current_and_foreign_change(self):
        path,_=self.plan()
        with self.assertRaisesRegex(ValueError,'prior reserved ports EMPTY'): self.transport.extension_start(path)
        self.reserved.write_text('\n'); token=self.transport.extension_start(path)
        self.reserved.write_text('55555\n')
        with self.assertRaisesRegex(ValueError,'NOT OVERWRITTEN'): self.transport.extension_restore(token,'EXIT')
        self.assertEqual(self.reserved.read_text(),'55555\n')

    def test_plan_schema_profiles_service_and_family_are_not_guessed(self):
        path,plan=self.plan()
        cases=[dict(schema='old'),dict(looks=3),dict(trigger='CPU'),dict(level=0.10)]
        for change in cases:
            wrong=json.loads(json.dumps(plan)); wrong.update(change); path.write_text(json.dumps(wrong))
            with self.assertRaises(ValueError): t.plan_has_pg(path)
        for change in [dict(service='nginx'),dict(blocks=11),dict(family=7),dict(profiles=['P1','P1'])]:
            wrong=json.loads(json.dumps(plan)); wrong['extensions'][0].update(change); path.write_text(json.dumps(wrong))
            with self.assertRaises(ValueError): t.plan_has_pg(path)

    def test_shell_syntax_and_all_embedded_python_ast(self):
        for path in FILES:
            parsed=subprocess.run([str(BASH),'--noprofile','--norc','-n',str(path)],capture_output=True,text=True)
            self.assertEqual(parsed.returncode,0,parsed.stderr)
            for label,program in embedded(path.read_text()).items(): ast.parse(program,filename=path.name+':'+label)
        ast.parse((ORCH/'resume_transport_v005.py').read_text())

    def test_no_R1_R2_pilot_rerun_one_R3_retry_only(self):
        source=FILES[0].read_text()
        self.assertNotRegex(source,r'(?m)^run_(?:stage|attempt) R[12]-')
        self.assertNotIn('corrected-pilot-saturation.out',source)
        self.assertEqual(len(re.findall(r'(?m)^run_attempt R3-postgresql-retry ',source)),1)
        self.assertNotRegex(source,r'(?m)^run_stage R3-')
        self.assertIn('flock -n 9',source)
        self.assertIn('primary-resume-started.txt',source)
        self.assertIn("[('R1-nginx','0'),('R2-redis','0'),('R3-postgresql','2')]",source)
        self.assertIn('LAST_STAGE_DIRECTORY',source)
        self.assertNotIn("'$1==p && $4==0",source)

    def test_run_stage_at_most_one_retry_and_uses_retry_directory(self):
        source=FILES[0].read_text()
        function=re.search(r'(?m)^run_stage\(\) \{\n.*?\n\}',source,re.S).group()
        for statuses,expected in [([0],1),([2,0],2),([2,2],2)]:
            queue=' '.join(map(str,statuses))
            harness='set -euo pipefail\ncount=0\nstatuses=('+queue+')\nrun_attempt(){\n' \
                'echo "$1"; LAST_STAGE_RC=${statuses[$count]}; count=$((count+1)); LAST_STAGE_DIRECTORY="mock-$count";\n}\n' \
                +function+'\nrun_stage R4-pilot-c1 nginx 3 P4\necho "count=$count last=$LAST_STAGE_DIRECTORY rc=$LAST_STAGE_RC"\n'
            done=subprocess.run([str(BASH),'--noprofile','--norc','-c',harness],capture_output=True,text=True)
            self.assertEqual(done.returncode,0,done.stderr)
            self.assertIn(f'count={expected} last=mock-{expected}',done.stdout)
            self.assertEqual(done.stdout.count('R4-pilot-c1'),expected)

    def test_scientific_post_body_is_original_except_extension_wrapper(self):
        old=(ORCH/'driver_post_primary_v005.sh').read_text().split('first_rc=0\n',1)[1]
        new=FILES[1].read_text().split('first_rc=0\n',1)[1]
        expected=old.replace('run_logged extensions bash "$BASE/driver_extensions_v005.sh" "$ANALYSIS/extension-plan.json"',
                             'run_logged extensions run_extensions_guarded "$ANALYSIS/extension-plan.json"')
        self.assertEqual(new,expected)

    def test_post_wait_accepts_confirmed_zombie_and_rejects_reused_birth(self):
        program=embedded(FILES[1].read_text())['CONTROLLER_PY'].replace('from pathlib import Path','')
        model={'state':'S','start':123,'cwd':'/root/systemd-hardening-lab'}
        class FakePath:
            def __init__(self,value): self.value=str(value)
            def __truediv__(self,value): return FakePath(self.value+'/'+str(value))
            def __str__(self): return self.value
            def read_text(self): return '101 (bash) '+model['state']+' '+' '.join(['0']*18+[str(model['start'])])
            def read_bytes(self):
                return b'bash\0-c\0rc=0; bash driver_primary_resume_v005.sh > results_v005/out\0'
            def resolve(self,strict=False): return PurePosixPath(model['cwd'])
        def run(expected):
            out,err=io.StringIO(),io.StringIO(); code=0
            with patch.object(sys,'argv',['-',model['cwd'],'101',expected]),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                try: exec(compile(program,'mock-controller','exec'),{'Path':FakePath})
                except SystemExit as exc: code=exc.code
            return code,out.getvalue(),err.getvalue()
        self.assertEqual(run('')[:2],(0,'123\n'))
        model['state']='Z'; self.assertEqual(run('123')[:2],(0,'EXITED\n'))
        self.assertEqual(run('122')[0],2)

if __name__=='__main__': unittest.main()
