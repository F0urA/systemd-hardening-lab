#!/usr/bin/env python3
"""Reproducible orchestration of the frozen v005 analysis, not a new rule."""
import argparse
import csv
import hashlib
import importlib.util
import itertools
import json
import math
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
RAW = ROOT / "raw-vm"
SCRIPTS = ROOT / "frozen-primary" / "v005" / "scripts_v005"
sys.path.insert(0, str(SCRIPTS))
sys.path.append(str(ROOT))  # Also support import-based synthetic tests.
sys.path.append(str(ROOT.parent))  # VM: unchanged inspector may live in BASE.
import build_criteria_v005 as criteria
from inspect_series_v005 import inspect
from select_profile_v005 import read_criteria, admissible, restricted, lex, pick

SPEC = {
    "R1-nginx": ("nginx", 60, ["P1c", "P4", "P5", "P6"], 7),
    "R2-redis": ("redis", 20, ["P1", "P2", "P1d", "P4", "P6"], 5),
    "R3-postgresql": ("postgresql", 10, ["P1", "P2", "P1d", "P4", "P6"], 5),
    "R5-nginx-light": ("nginx", 60, ["P1", "P2", "P1r"], 7),
    "R4-nginx-nonsaturated": ("nginx", 60, ["P1c", "P4"], 2),
}
REMOTE_PREFIX = '/root/article-experiment/20261012-v005/results_v005/'
LEDGER_FIELDS = ['stage', 'start_guest_utc', 'end_guest_utc', 'exit_status', 'result_directory']
PILOTS = {f'R4-pilot-c{c}' for c in (1, 2, 4, 8, 16)}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def marker(path):
    if not path.is_file():
        raise ValueError(f'queue has not finished: missing {path.name}')
    value = path.read_text().strip()
    stamp = datetime.fromisoformat(value)
    if stamp.tzinfo is None:
        raise ValueError(f'{path}: completion timestamp has no timezone')
    return stamp


def local_path(remote):
    if not remote.startswith(REMOTE_PREFIX):
        raise ValueError(f"unexpected remote result path: {remote}")
    suffix = remote[len(REMOTE_PREFIX):]
    parts = PurePosixPath(suffix).parts
    if len(parts) != 3 or parts[0] not in {'nginx', 'redis', 'postgresql'} \
            or parts[1] != 'benchmark-v005' or not re.fullmatch(r'\d{8}-\d{6}', parts[2]) \
            or suffix != '/'.join(parts):
        raise ValueError(f'not a current benchmark directory: {remote}')
    path = RAW.joinpath(*parts)
    if not path.resolve().is_relative_to(RAW.resolve()):
        raise ValueError(f'result path escapes raw-vm: {remote}')
    return path


def preflight_directory(stage):
    text = (RAW / "driver" / f"{stage}.out").read_text(encoding="utf-8", errors="replace")
    paths = [line[len("RESULT_DIR="):] for line in text.splitlines() if line.startswith("RESULT_DIR=")]
    if not paths:
        raise ValueError(f"no result directory for {stage}")
    remote = paths[-1]
    if not remote.startswith(REMOTE_PREFIX):
        raise ValueError(f'foreign diagnostic directory: {remote}')
    suffix = PurePosixPath(remote[len(REMOTE_PREFIX):])
    if '..' in suffix.parts or suffix.is_absolute():
        raise ValueError('diagnostic path traversal')
    path = RAW.joinpath(*suffix.parts)
    if not path.resolve().is_relative_to(RAW.resolve()):
        raise ValueError('diagnostic directory escapes raw-vm')
    return path


def read_ledger(path):
    if not path.is_file():
        raise ValueError(f'missing ledger: {path}')
    with path.open(newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        if reader.fieldnames != LEDGER_FIELDS:
            raise ValueError(f'{path}: unexpected ledger header')
        rows = list(reader)
    for row in rows:
        if None in row or any(row.get(k) is None for k in LEDGER_FIELDS):
            raise ValueError(f'{path}: truncated or extra ledger fields')
        if not re.fullmatch(r'\d+', row['exit_status']):
            raise ValueError(f'{path}: invalid exit status')
        start = datetime.fromisoformat(row['start_guest_utc'])
        end = datetime.fromisoformat(row['end_guest_utc'])
        if start.tzinfo is None or end.tzinfo is None or end < start:
            raise ValueError(f'{path}: malformed attempt timestamps')
    return rows


def attempts(rows, allowed, extension=False):
    grouped, paths, names = {}, set(), set()
    for row in rows:
        label = row['stage']
        retry = label.endswith('-retry')
        stem = label.removesuffix('-retry')
        if extension:
            if not stem.endswith('-extension'):
                raise ValueError(f'not an extension ledger stage: {label}')
            stem = stem.removesuffix('-extension')
        if stem not in allowed or label in names:
            raise ValueError(f'unknown or duplicate ledger stage: {label}')
        names.add(label)
        group = grouped.setdefault(stem, [])
        if retry and (len(group) != 1 or group[0]['exit_status'] == '0'):
            raise ValueError(f'{label}: retry without exactly one failed attempt')
        if not retry and group:
            raise ValueError(f'{label}: duplicate primary attempt')
        group.append(row)
        if row['result_directory']:
            directory = local_path(row['result_directory'])
            if str(directory.resolve()) in paths:
                raise ValueError('one result directory is reused by multiple attempts')
            paths.add(str(directory.resolve()))
        elif row['exit_status'] == '0':
            raise ValueError(f'{label}: successful attempt has no result directory')
    return grouped


def terminal_attempt(group, name):
    if not group:
        raise ValueError(f'finished queue is missing required stage: {name}')
    if group[-1]['exit_status'] != '0' and len(group) != 2:
        raise ValueError(f'{name}: failed first attempt has no documented terminal retry')
    return group[-1]


def platform_parameters(directory):
    text = (directory / 'platform.txt').read_text()
    parameters = {}
    for match in re.finditer(r'(?:^|\s)([A-Z][A-Z0-9_]*)=(\S+)', text):
        key, value = match.groups()
        if key in parameters:
            raise ValueError(f'{directory}: duplicate platform setting {key}')
        parameters[key] = value
    return parameters


def command(args, output):
    with output.open("w", encoding="utf-8", newline="\n") as file:
        subprocess.run([sys.executable, *map(str, args)], check=True, stdout=file, stderr=subprocess.STDOUT)


def raw_count_audit(service, directory, rows, params):
    """Corroborate accepted CSV counts, without a new performance filter.

    Quiet Redis output may not expose a completed-count header. A successful
    producer exit and assigned REDIS_N are not proof of that missing count.
    """
    proofs, files, limitations = [], {}, set()

    def output(filename):
        path = directory / filename
        value = path.read_text(encoding='utf-8', errors='replace').replace('\r', '\n')
        files[filename] = digest(path)
        return value

    def count(text, pattern, filename, optional=False):
        found = re.findall(pattern, text, re.MULTILINE | re.IGNORECASE)
        if not found and optional:
            return None
        if len(found) != 1:
            raise ValueError(f'{filename}: missing/ambiguous native count')
        return int(found[0])

    for row in rows:
        tag = f"B{row['block']}-{row['profile']}-a{row['attempt']}"
        entry = {'tag': tag, 'csv_ops': int(row['ops']), 'csv_failed': int(row['failed'])}
        if service == 'nginx':
            completed, failed = 0, 0
            for generator in (1, 2):
                filename = f'ab-{tag}-g{generator}.txt'; text = output(filename)
                done = count(text, r'^Complete requests:\s*(\d+)\s*$', filename)
                bad = count(text, r'^Failed requests:\s*(\d+)\s*$', filename)
                non2xx = count(text, r'^Non-2xx responses:\s*(\d+)\s*$', filename, optional=True) or 0
                if done != int(params['NGINX_N']):
                    raise ValueError(f'{filename}: native Complete count differs from fixed NGINX_N')
                completed += done; failed += bad + non2xx
            entry.update(status='COUNTS_CONFIRMED', native_completed=completed, native_failed=failed)
        elif service == 'postgresql':
            filename = f'pgbench-{tag}.txt'; text = output(filename)
            completed = count(text, r'^number of transactions actually processed:\s*(\d+)\b.*$', filename)
            failed = count(text, r'^number of failed transactions:\s*(\d+)\b.*$', filename, optional=True)
            entry.update(status='COUNTS_CONFIRMED', native_completed=completed, native_failed=failed)
            if failed is None:
                limitations.add('PG_FAILED_COUNT_NOT_EXPOSED')
                entry['status'] = 'COMPLETED_COUNT_CONFIRMED_FAILED_COUNT_NOT_EXPOSED'
        else:
            filename = f'redis-{tag}.txt'; text = output(filename)
            if re.search(r'(^Error:|^ERR |server closed|connection refused)', text, re.MULTILINE | re.IGNORECASE):
                raise ValueError(f'{filename}: native Redis client reports an error')
            if 'requests per second' not in text:
                raise ValueError(f'{filename}: missing successful quiet benchmark summary')
            completed = count(text, r'^\s*(\d+)\s+requests completed in\b.*$', filename, optional=True)
            failed = None
            if completed is None:
                limitations.add('COUNTS_NOT_EXPOSED_BY_QUIET_OUTPUT')
                entry.update(status='COUNTS_NOT_EXPOSED_BY_QUIET_OUTPUT',
                             assigned_N=int(params['REDIS_N']),
                             evidence='recorded successful producer exit and quiet summary; not native count proof')
            else:
                if completed != int(params['REDIS_N']):
                    raise ValueError(f'{filename}: native completed count differs from fixed REDIS_N')
                entry.update(status='COMPLETED_COUNT_CONFIRMED', native_completed=completed,
                             native_failed=None)
            if int(row['ops']) != int(params['REDIS_N']):
                raise ValueError(f'{filename}: CSV assigned ops differs from fixed REDIS_N')
        if completed is not None and completed != int(row['ops']) \
                or failed is not None and failed != int(row['failed']):
            raise ValueError(f'{tag}: native counts differ from accepted CSV')
        proofs.append(entry)
    return {'measurements': proofs, 'files_sha256': files, 'limitations': sorted(limitations)}


def validate(name, directory, planned=None):
    service, blocks, profiles, _ = SPEC[name]
    directory = Path(directory)
    relative = directory.resolve().relative_to(RAW.resolve())
    if len(relative.parts) != 3 or relative.parts[:2] != (service, 'benchmark-v005'):
        raise ValueError(f'{name}: foreign service/directory role')
    profiles = planned['profiles'] if planned else profiles
    expected = {'P0', *profiles}
    params = platform_parameters(directory)
    required = {'SERVICE': service, 'BLOCKS': str(blocks), 'PIN': '1',
                'SERVER_CPU': '0', 'CLIENT_CPUS': '1-3', 'KEEPALIVE': '0',
                'NGINX_N': '100000', 'REDIS_N': '3000000', 'REDIS_THREADS': '3',
                'PG_T': '60', 'STALL_MS': '500', 'ELAPSED_CLOCK': 'CLOCK_MONOTONIC_RAW'}
    if any(params.get(k) != v for k, v in required.items()):
        raise ValueError(f'{name}: parameters differ from the timing-corrected fixed protocol')
    concurrency = params.get('NGINX_C')
    expected_c = planned['nginx_c'] if planned else '25' if name != 'R4-nginx-nonsaturated' else concurrency
    if concurrency != str(expected_c) or concurrency not in {'1', '2', '4', '8', '16', '25'}:
        raise ValueError(f'{name}: concurrency differs from the saved first-look plan')
    csv_path = directory / 'results.csv'
    metric = 'tps' if service == 'postgresql' else 'rps'
    with csv_path.open(newline='', encoding='utf-8-sig') as stream:
        reader = csv.DictReader(stream)
        fields = ['block', 'order', 'profile', metric, 'cpu_pct', 'cpu_us_per_op',
                  'ops', 'wall_ns', 'failed', 'max_gap_ms', 'attempt']
        if reader.fieldnames != fields:
            raise ValueError(f'{name}: unexpected benchmark schema')
        rows = list(reader)
    seen, orders = set(), {}
    for row in rows:
        if None in row or any(row.get(k) is None for k in fields):
            raise ValueError(f'{name}: truncated/extra CSV fields')
        block, order = int(row['block']), int(row['order'])
        key = (block, row['profile'])
        if row['profile'] not in expected or not 1 <= block <= blocks or key in seen:
            raise ValueError(f'{name}: duplicate, wrong-profile or out-of-range block')
        seen.add(key)
        orders.setdefault(block, []).append(order)
        numeric = {k: float(row[k]) for k in (metric, 'cpu_pct', 'cpu_us_per_op', 'max_gap_ms')}
        if any(not math.isfinite(v) for v in numeric.values()) \
                or numeric[metric] <= 0 or numeric['cpu_us_per_op'] <= 0 \
                or numeric['cpu_pct'] < 0 or not 0 <= numeric['max_gap_ms'] <= 500 \
                or int(row['failed']) != 0 or int(row['ops']) <= 0 \
                or int(row['wall_ns']) <= 0 or not 1 <= int(row['attempt']) <= 5:
            raise ValueError(f'{name}: invalid accepted measurement')
    if seen != {(b, p) for b in range(1, blocks + 1) for p in expected} \
            or any(sorted(values) != list(range(1, len(expected) + 1)) for values in orders.values()):
        raise ValueError(f'{name}: incomplete block/profile matrix or nonunique orders')
    footer = (directory / 'sha256-results.txt').read_text().strip().split()
    if len(footer) != 2 or footer[0] != digest(csv_path) \
            or PurePosixPath(footer[1]).name != 'results.csv':
        raise ValueError(f'{name}: missing/mismatched completed results hash')
    log = (directory / 'run.log').read_text(errors='replace')
    if '===== BENCHMARK COMPLETE =====' not in log or f'RESTORE_P4 {service}=PASS' not in log:
        raise ValueError(f'{name}: benchmark did not finish and restore normally')
    counts = raw_count_audit(service, directory, rows, params)
    data = inspect(directory)  # Summary only after exact raw validation.
    data['parameters'] = params
    data['results_sha256'] = digest(csv_path)
    data['raw_count_audit'] = counts
    return data


def completed_series():
    driver = RAW / 'driver'
    finished = marker(driver / 'primary-corrected-finished.txt')
    rows = read_ledger(driver / 'primary-corrected-ledger.csv')
    grouped = attempts(rows, set(SPEC) | PILOTS)
    if rows and finished < max(datetime.fromisoformat(r['end_guest_utc']) for r in rows):
        raise ValueError('primary completion marker predates the ledger')
    condition = (driver / 'R4-condition.txt').read_text().strip()
    failed_r4 = condition.startswith('R4=FAILED:')
    if failed_r4:
        if 'R4-nginx-nonsaturated' in grouped:
            raise ValueError('R4 failure condition conflicts with a recorded R4 series')
    elif not re.fullmatch(r'R4_CHOSEN_C=(1|2|4|8|16)', condition):
        raise ValueError('missing/unrecognized terminal R4 condition')
    pilot_order = [f'R4-pilot-c{c}' for c in (1, 2, 4, 8, 16)]
    expected_pilots = set(pilot_order if failed_r4 else
                          pilot_order[:pilot_order.index('R4-pilot-c' + condition.split('=')[1]) + 1])
    if set(grouped) & PILOTS != expected_pilots:
        raise ValueError(f'incomplete or unexpected R4 pilot stages: expected {sorted(expected_pilots)}')
    missing = [name for name in SPEC if name not in grouped and
               not (name == 'R4-nginx-nonsaturated' and failed_r4)]
    if missing:
        raise ValueError(f'finished primary queue is missing required stages: {missing}')
    result, coverage = {}, {}
    for name in SPEC:
        if name == 'R4-nginx-nonsaturated' and failed_r4:
            coverage[name] = {'status': 'NO_VALID_PRIMARY', 'reason': condition}
            continue
        row = terminal_attempt(grouped.get(name), name)
        entry = {'attempts': grouped[name], 'status': 'NO_VALID_PRIMARY'}
        if row['exit_status'] != '0':
            entry['reason'] = 'both complete technical attempts failed; partial data excluded'
        else:
            directory = local_path(row['result_directory'])
            try:
                summary = validate(name, directory)
                if name == 'R4-nginx-nonsaturated' and summary['parameters']['NGINX_C'] != condition.split('=')[1]:
                    raise ValueError('R4 concurrency differs from chosen condition')
                result[name] = directory
                entry.update(status='VALID_PRIMARY', summary=summary,
                             results_sha256=summary['results_sha256'])
            except (OSError, ValueError) as error:
                entry['reason'] = str(error)
        coverage[name] = entry
    # Pilot attempts are metadata, not primary selection or pooled blocks.
    for name, group in grouped.items():
        if name in PILOTS:
            terminal_attempt(group, name)
    if failed_r4:
        # The immutable producer's awk does not consult a successful -retry.
        # This audit reports that executor limitation, not a new pilot/choice.
        retry_checks = []
        for name, group in grouped.items():
            if name in PILOTS and len(group) == 2 and group[-1]['exit_status'] == '0':
                try:
                    pilot = inspect(local_path(group[-1]['result_directory']))
                    with (local_path(group[-1]['result_directory']) / 'results.csv').open(newline='') as f:
                        baseline = [r for r in csv.DictReader(f) if r['profile'] == 'P0']
                    reaches = (set(pilot['profiles']) == {'P0', 'P4'} and
                               all(v['blocks'] == [1, 2, 3] and not v['failed'] and
                                   v['max_gap_ms'] <= 500 for v in pilot['profiles'].values()) and
                               len(baseline) == 3 and all(40 <= float(r['cpu_pct']) <= 70 for r in baseline))
                    retry_checks.append({'stage': name, 'successful_retry': True,
                                         'matches_recorded_CPU_range': reaches})
                except (OSError, ValueError) as error:
                    retry_checks.append({'stage': name, 'audit_error': str(error)})
        coverage['R4-nginx-nonsaturated']['pilot_retry_audit'] = retry_checks
        if any(r.get('matches_recorded_CPU_range') for r in retry_checks):
            coverage['R4-nginx-nonsaturated']['executor_limitation'] = (
                'successful pilot retry matches the range but producer ignored retry name; '
                'FAILED is not evidence that no qualifying range existed; R4 is not retroactively run')
    return result, coverage


def primary_fingerprint(series, coverage):
    driver = RAW / 'driver'
    return {'ledger_sha256': digest(driver / 'primary-corrected-ledger.csv'),
            'finished_sha256': digest(driver / 'primary-corrected-finished.txt'),
            'r4_condition_sha256': digest(driver / 'R4-condition.txt'),
            'analyzer_sha256': digest(__file__),
            'statistics_sha256': {name: digest(SCRIPTS / name) for name in
                ('build_criteria_v005.py', 'audit_benchmark_csv_v005.py', 'select_profile_v005.py')},
            'series': {name: {'directory': coverage[name]['attempts'][-1]['result_directory'],
                              'results_sha256': digest(directory / 'results.csv'),
                              'platform_sha256': digest(directory / 'platform.txt'),
                              'accepted_native_outputs_sha256': coverage[name]['summary']['raw_count_audit']['files_sha256']}
                       for name, directory in series.items()}}


def validate_plan(plan):
    if not isinstance(plan, dict) or plan.get('schema') != 'v005-first-look-plan-1' \
            or plan.get('looks') != 2 or plan.get('level') != 0.05 \
            or plan.get('trigger') != 'throughput_interval_contains_zero':
        raise ValueError('unrecognized or altered first-look plan')
    seen = set()
    for row in plan['extensions']:
        name = row['stage']
        if name not in SPEC or name in seen:
            raise ValueError('duplicate/unknown planned extension stage')
        seen.add(name)
        service, blocks, allowed, family = SPEC[name]
        profiles = row['profiles']
        if row['service'] != service or row['blocks'] != blocks or row['family'] != family \
                or not profiles or len(profiles) != len(set(profiles)) \
                or profiles != [p for p in allowed if p in profiles] \
                or str(row['nginx_c']) not in {'1', '2', '4', '8', '16', '25'}:
            raise ValueError(f'{name}: altered family/blocks/profiles/concurrency')
        if name not in plan['primary']['series']:
            raise ValueError('extension of a primary series without valid complete data')
    return plan


def saved_plan(path, series, coverage):
    path = Path(path)
    plan = validate_plan(json.loads(path.read_text()))
    record = json.loads((ROOT / 'analysis-first-look' / 'plan-record.json').read_text())
    canonical = ROOT / 'extension-plan.json'
    if digest(path) != record['plan_sha256'] or digest(canonical) != record['plan_sha256'] \
            or plan['primary'] != primary_fingerprint(series, coverage):
        raise ValueError('plan/source fingerprint differs from the immutable first look')
    return plan


def extension_map(plan):
    driver = RAW / 'driver'
    finished = marker(driver / 'extensions-finished.txt')
    if digest(driver / 'extension-plan.json') != digest(ROOT / 'extension-plan.json'):
        raise ValueError('executed extension plan differs from saved first-look plan')
    rows = read_ledger(driver / 'extension-ledger.csv')
    planned = {r['stage']: r for r in plan['extensions']}
    grouped = attempts(rows, planned, extension=True)
    if rows and finished < max(datetime.fromisoformat(r['end_guest_utc']) for r in rows):
        raise ValueError('extension completion marker predates ledger')
    result, coverage = {}, {}
    used = {item['directory'] for item in plan['primary']['series'].values()}
    for name, requested in planned.items():
        row = terminal_attempt(grouped.get(name), name)
        entry = {'profiles': requested['profiles'], 'attempts': grouped[name],
                 'status': 'NO_VALID_EXTENSION', 'attempt_limit_exhausted': True}
        if row['exit_status'] != '0':
            entry['reason'] = 'both technical attempts failed; first-look bounds retained, no third look'
        else:
            if row['result_directory'] in used:
                raise ValueError('extension reuses a primary or another extension directory')
            used.add(row['result_directory'])
            directory = local_path(row['result_directory'])
            try:
                summary = validate(name, directory, requested)
                result[name] = directory
                entry.update(status='VALID_EXTENSION', summary=summary)
            except (OSError, ValueError) as error:
                entry['reason'] = str(error)
        coverage[name] = entry
    return result, coverage


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--final", action="store_true")
    parser.add_argument('--validate-extension-plan', type=Path)
    parser.add_argument('--emit-plan-tsv', type=Path)
    parser.add_argument('--validate-extension-result', choices=SPEC)
    parser.add_argument('--result-directory')
    args = parser.parse_args()
    series, primary_coverage = completed_series()  # No first look of an unfinished queue.
    if args.validate_extension_plan:
        plan = saved_plan(args.validate_extension_plan, series, primary_coverage)
        if args.validate_extension_result:
            requested = next((r for r in plan['extensions'] if r['stage'] == args.validate_extension_result), None)
            if requested is None or not args.result_directory:
                raise ValueError('unplanned extension result')
            if args.result_directory in {v['directory'] for v in plan['primary']['series'].values()}:
                raise ValueError('extension result is primary data')
            validate(args.validate_extension_result, local_path(args.result_directory), requested)
            print('VALID_COMPLETE_EXTENSION_RESULT (structural validation, no statistical look)')
        elif args.emit_plan_tsv:
            with args.emit_plan_tsv.open('x', encoding='utf-8', newline='\n') as file:
                for row in plan['extensions']:
                    file.write('\t'.join(map(str, (row['stage'], row['service'], row['blocks'],
                              row['nginx_c'], ' '.join(row['profiles'])))) + '\n')
            print('VALID_SAVED_FIRST_LOOK_PLAN')
        else:
            print('VALID_SAVED_FIRST_LOOK_PLAN')
        return
    if args.validate_extension_result or args.emit_plan_tsv:
        parser.error('--validate-extension-plan required for validation/TSV modes')
    destination = ROOT / ("analysis-final" if args.final else "analysis-first-look")
    destination.mkdir(exist_ok=True)
    (destination / 'primary-coverage.json').write_text(json.dumps(primary_coverage, indent=2, ensure_ascii=False), encoding='utf-8')
    summaries = {name: primary_coverage[name]['summary'] for name in series}
    (destination / "series-summary.json").write_text(json.dumps(summaries, indent=2, ensure_ascii=False), encoding="utf-8")
    extensions, extension_coverage = {}, {}
    if args.final:
        plan = saved_plan(ROOT / 'extension-plan.json', series, primary_coverage)
        extensions, extension_coverage = extension_map(plan)
        (destination / 'extension-coverage.json').write_text(json.dumps(extension_coverage, indent=2, ensure_ascii=False), encoding='utf-8')
    else:
        if (RAW / 'driver' / 'extension-ledger.csv').exists():
            raise ValueError('extension already attempted: refusing a new first-look plan')
        planned = []
        for name, directory in series.items():
            service, blocks, profiles, family = SPEC[name]
            measured = criteria.bench_bounds([directory / 'results.csv'], 0.05 / (family * 2))
            needed = [p for p in profiles if measured[p][0] <= 0 <= measured[p][1]]
            if needed:
                planned.append({'stage': name, 'service': service, 'blocks': blocks,
                                'profiles': needed, 'family': family,
                                'nginx_c': summaries[name]['parameters']['NGINX_C']})
        plan = {'schema': 'v005-first-look-plan-1', 'level': 0.05, 'looks': 2,
                'trigger': 'throughput_interval_contains_zero',
                'primary': primary_fingerprint(series, primary_coverage), 'extensions': planned}
        validate_plan(plan)
        text = json.dumps(plan, indent=2, ensure_ascii=False) + '\n'
        plan_path = ROOT / 'extension-plan.json'
        if plan_path.exists() and plan_path.read_text() != text:
            raise ValueError('immutable first-look plan already exists and differs; no replanning')
        if not plan_path.exists():
            plan_path.write_text(text, encoding='utf-8')
        (destination / 'plan-record.json').write_text(json.dumps({'plan_sha256': digest(plan_path)}, indent=2), encoding='utf-8')
    incomplete = any(v['status'] != 'VALID_PRIMARY' for v in primary_coverage.values()) \
        or any(v['status'] != 'VALID_EXTENSION' for v in extension_coverage.values())
    limits = {'scope': 'INCOMPLETE_SCOPE' if incomplete else 'COMPLETE_SCOPE',
              'looks_planned': 2, 'combined_nginx_family': 7,
              'failed_primary': [n for n, v in primary_coverage.items() if v['status'] != 'VALID_PRIMARY'],
              'failed_extension': [n for n, v in extension_coverage.items() if v['status'] != 'VALID_EXTENSION'],
              'native_count_limitations': {n: v['summary']['raw_count_audit']['limitations']
                  for n, v in primary_coverage.items() if v['status'] == 'VALID_PRIMARY' and
                  v['summary']['raw_count_audit']['limitations']},
              'third_look_permitted': False,
              'failed_extension_policy': 'retain first-look bounds/status; terminal NO_VALID_EXTENSION; affected inference unfinished'}
    (destination / 'analysis-status.json').write_text(json.dumps(limits, indent=2), encoding='utf-8')
    if incomplete and (destination / 'combined-selection.txt').exists():
        raise ValueError('stale ordinary combined-selection.txt exists; preserve it but do not present as current final output')
    if not series:
        # A terminal, fully recorded failed queue is not an unfinished queue.
        # Preserve coverage and an empty plan so orchestration can close the
        # sole continuation ledger without manufacturing a selection.
        (destination / 'NO_VALID_PRIMARY.txt').write_text(
            'No valid complete primary series. No statistical selection was computed.\n'
            'The recorded queue is terminal; partial attempts are excluded.\n', encoding='utf-8')
        print(f'NO_VALID_PRIMARY; coverage and empty continuation plan saved to {destination}')
        return
    probe = preflight_directory("microprobes")
    scenarios = preflight_directory("scenarios-diagnostic")
    contract = preflight_directory("functional")
    base_args = [SCRIPTS / "build_criteria_v005.py", "--probe", probe, "--scenarios", scenarios,
                 "--contract", contract, "--level", "0.05", "--looks", "2"]

    # Original protocol families, separately from a combined Nginx decision.
    for name, directory in series.items():
        service, _, profiles, union_family = SPEC[name]
        family = 4 if name == "R1-nginx" else 3 if name == "R5-nginx-light" else union_family
        # A/A+/B must use the same predeclared candidate family. This is a
        # derived view, never a rewrite of the raw scenarios or an outlier cut.
        scope = destination / f"{name}-candidate-scope"
        scope.mkdir(exist_ok=True)
        for filename in ["candidates.csv", "goals.csv"]:
            with (scenarios / filename).open(newline="", encoding="utf-8-sig") as file:
                reader = csv.DictReader(file)
                fieldnames = reader.fieldnames
                selected = [row for row in reader if row["service"] == service and
                            row["profile"] in {"P0", *profiles}]
            with (scope / filename).open("w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(selected)
        scoped_args = list(base_args)
        scoped_args[scoped_args.index("--scenarios") + 1] = scope
        csv_path = destination / f"{name}-criteria.csv"
        bench_args = []
        if name in extensions:
            extension = extensions[name]
            ext_profiles = next(r['profiles'] for r in plan['extensions'] if r['stage'] == name)
            bench_args = ["--bench", f"{service}={directory}+{extension}:P0,{','.join(ext_profiles)}"]
        command([*scoped_args, "--family", f"{service}={family}", *bench_args,
                 "--bench", f"{service}={directory}",
                 "--out", csv_path], destination / f"{name}-criteria.txt")
        suffix = '-INCOMPLETE_SCOPE' if name in extension_coverage and name not in extensions else ''
        selection_path = destination / f'{name}-selection{suffix}.txt'
        command([SCRIPTS / "select_profile_v005.py", csv_path], selection_path)
        if suffix:
            selection_path.write_text('NO_VALID_EXTENSION; first-look bounds/status retained. '
                'Planned attempt limit exhausted; inference unfinished, no third look.\n\n' +
                selection_path.read_text(), encoding='utf-8')

    combined_args = list(base_args)
    for service, family in (("nginx", 7), ("redis", 5), ("postgresql", 5)):
        combined_args += ["--family", f"{service}={family}"]
    for name, directory in series.items():
        if name == "R4-nginx-nonsaturated":
            continue
        service, _, profiles, _ = SPEC[name]
        remaining = list(profiles)
        if name in extensions:
            extension = extensions[name]
            ext_profiles = next(r['profiles'] for r in plan['extensions'] if r['stage'] == name)
            combined_args += ["--bench", f"{service}={directory}+{extension}:P0,{','.join(ext_profiles)}"]
            remaining = [profile for profile in remaining if profile not in ext_profiles]
        if remaining:
            combined_args += ["--bench", f"{service}={directory}:P0,{','.join(remaining)}"]
    scope_suffix = '-INCOMPLETE_SCOPE' if incomplete else ''
    combined = destination / f'combined-criteria{scope_suffix}.csv'
    command([*combined_args, "--out", combined], destination / f'combined-criteria{scope_suffix}.txt')
    selection_path = destination / f'combined-selection{scope_suffix}.txt'
    command([SCRIPTS / "select_profile_v005.py", combined], selection_path)
    if incomplete:
        selection_path.write_text('INCOMPLETE_SCOPE: conditional diagnostic, not a complete final selection.\n' +
            json.dumps(limits, ensure_ascii=False) + '\n\n' + selection_path.read_text(), encoding='utf-8')
    command([SCRIPTS / "order_sensitivity_v005.py", combined], destination / "order-sensitivity.txt")
    # The original 120-order diagnostic also moves g. That is not the operator
    # policy of procedure_v005 §5. Report its 24 legitimate g-first policies.
    policies = list(itertools.permutations(["s", "emicro", "exposure", "n"]))
    policy_rows = []
    for service, rows in read_criteria(combined).items():
        for budget in [2, 5, 10, 15]:
            candidates = restricted(admissible(rows, budget))
            for policy in policies:
                policy_rows.append({"service": service, "budget": budget, "policy": ";".join(policy),
                                    "outcome": pick(candidates, lex(["g", *policy]))})
    with (destination / "policy24.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["service", "budget", "policy", "outcome"])
        writer.writeheader()
        writer.writerows(policy_rows)
    if args.final and "R1-nginx" in series:
        command([SCRIPTS / "robustness_v005.py", "--family", "4", "--pairs", "P1c-P5,P1c-P6",
                 f"R1={series['R1-nginx'] / 'results.csv'}"], destination / "R1-robustness-descriptive.txt")
    print(f"Completed validated series: {', '.join(series)}")
    print(f"Planned extension cells: {json.dumps(plan['extensions'], ensure_ascii=False)}")
    print(f"Analysis scope: {limits['scope']}; limitations: {json.dumps(limits, ensure_ascii=False)}")
    print(f"Analysis directory: {destination}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        # No bounds from partial/invalid ledgers; failure is visible to serial wrapper.
        folder = ROOT / ('analysis-final' if '--final' in sys.argv else 'analysis-first-look')
        if '--validate-extension-plan' not in sys.argv:
            folder.mkdir(exist_ok=True)
            (folder / 'validation-error.json').write_text(json.dumps({'status': 'INVALID_OR_UNFINISHED_QUEUE',
                'error': str(error), 'third_look_permitted': False}, indent=2), encoding='utf-8')
        print(f'ANALYSIS_REFUSED: {error}', file=sys.stderr)
        raise SystemExit(2)
