#!/usr/bin/env python3
"""Exploratory v005 mount-state harness. No alternate attack or UID fallback.

The runner alone invokes host-bind. The model's mount syscalls are confined to
one fresh directory in a different, non-outward-propagating mount namespace.
Importing this module performs no mount, process launch, or network request.
"""
import argparse
import csv
import ctypes
import errno
import json
import os
from pathlib import Path
try:
    import pwd
except ImportError:  # Import-only synthetic tests on Windows; VM execution is Linux-only.
    pwd = None
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

SITE = Path('/var/lib/systemd-lab/nginx-www')
SOURCE_BASE = Path('/var/lib/systemd-lab/mountstate-v005')
CONTROL_PREFIX = '/run/slab-mountstate-v005-'
PROFILES = ('P0', 'P1r', 'P1c', 'P5', 'P6')
MODES = ('late', 'nested')
DACS = ('rootown', 'labweb')
CONTEXTS = ('master', 'worker')
ORIGINAL = b'G1_ORIGINAL_DOCUMENT\n'
REPLACED = b'G1_REPLACED_DOCUMENT\n'
DENIED_ERRNOS = {errno.EPERM, errno.EACCES, errno.EROFS}
MS_BIND, MS_REMOUNT = 4096, 32
REMOUNT_KEEP = {'nosuid': 2, 'nodev': 4, 'noexec': 8, 'noatime': 1024,
                'nodiratime': 2048, 'relatime': 1 << 21, 'strictatime': 1 << 24,
                'nosymfollow': 256}
CONTROL_FILES = {'spec.json', 'ready.json', 'trigger.json', 'result.json',
                 'nested.json', 'attempt-temp.json'}
PHASES = ('ready', 'after-state', 'after-bind', 'after-remount', 'before-exit', 'cleanup')
CONTROL_FILES.update(f'{phase}.{suffix}' for phase in PHASES
                     for suffix in ('mountinfo.txt', 'status.txt', 'process.json'))


class SafetyError(RuntimeError):
    pass


def cell_parts(cell):
    parts = cell.split('-')
    if len(parts) != 4 or parts[0] not in MODES or parts[1] not in PROFILES \
            or parts[2] not in DACS or parts[3] not in CONTEXTS:
        raise SafetyError('invalid cell identifier')
    return parts


def layout(token, cell=None):
    if not re.fullmatch(r'[0-9a-f]{16}', token):
        raise SafetyError('invalid run token')
    control_base = Path(CONTROL_PREFIX + token)
    result = {'source_base': SOURCE_BASE, 'control_base': control_base}
    if cell is not None:
        cell_parts(cell)
        result.update(source=SOURCE_BASE / cell,
                      target=SITE / f'mountstate-v005-{token}-{cell}',
                      control=control_base / cell)
    return result


def canonical(path, exists=True):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=exists) != path:
        raise SafetyError(f'noncanonical or symlink path: {path}')
    for component in (path, *path.parents):
        if component.is_symlink():
            raise SafetyError(f'symlink component: {component}')
    return path


def regular(path):
    path = canonical(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise SafetyError(f'not a regular file: {path}')
    return path


def identity(path):
    st = canonical(path).stat()
    return [st.st_dev, st.st_ino]


def write_bytes(path, data, mode=0o600):
    path = canonical(path, exists=False)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
    except BaseException:
        raise


def write_json(path, value):
    path = canonical(path, exists=False)
    # Publish only a complete file, without replacing an existing destination.
    # READY/trigger readers must never observe a half-written JSON document.
    pending = path.with_name(path.name + '.pending')
    write_bytes(pending, (json.dumps(value, sort_keys=True) + '\n').encode())
    try:
        os.link(pending, path, follow_symlinks=False)
    finally:
        regular(pending).unlink()


def read_json(path):
    return json.loads(regular(path).read_text(encoding='utf-8'))


def replace_json(path, value):
    path = regular(path)
    tmp = path.with_name(path.name + '.new')
    write_json(tmp, value)
    os.replace(tmp, path)


def mount_unescape(value):
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), value)


def parse_mountinfo(text):
    records = []
    for line in text.splitlines():
        left, right = line.split(' - ', 1)
        a, b = left.split(), right.split()
        if len(a) < 6 or len(b) < 3:
            raise SafetyError('malformed mountinfo record')
        records.append({'id': int(a[0]), 'parent': int(a[1]), 'device': a[2],
                        'root': mount_unescape(a[3]), 'target': mount_unescape(a[4]),
                        'options': a[5].split(','), 'optional': a[6:],
                        'fstype': b[0], 'source': mount_unescape(b[1]),
                        'super_options': b[2].split(','), 'line': line})
    return records


def exact_mounts(records, path):
    return [r for r in records if r['target'] == str(path)]


def below_mounts(records, path):
    path = Path(path)
    return [r for r in records if Path(r['target']).is_relative_to(path)]


def covering_mount(records, path):
    candidates = [r for r in records if Path(path).is_relative_to(Path(r['target']))]
    if not candidates:
        raise SafetyError(f'no covering mount: {path}')
    return max(candidates, key=lambda r: (len(Path(r['target']).parts), r['id']))


def nonshared(record):
    return not any(flag.startswith('shared:') for flag in record['optional'])


def error_result(exc, phase):
    number = exc.errno if isinstance(exc, OSError) else None
    return {'result': 'DENIED' if number in DENIED_ERRNOS else 'ERROR',
            'phase': phase, 'errno': number, 'message': str(exc)}


class Kernel:
    def namespace(self):
        return os.readlink('/proc/self/ns/mnt')

    def mountinfo_text(self):
        return Path('/proc/self/mountinfo').read_text()

    def records(self):
        return parse_mountinfo(self.mountinfo_text())

    def mount(self, source, target, flags):
        libc = ctypes.CDLL(None, use_errno=True)
        libc.mount.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                               ctypes.c_ulong, ctypes.c_void_p)
        libc.mount.restype = ctypes.c_int
        source_arg = os.fsencode(source) if source is not None else None
        if libc.mount(source_arg, os.fsencode(target), None, flags, None) != 0:
            number = ctypes.get_errno()
            raise OSError(number, os.strerror(number), str(target))

    def unmount(self, target):
        libc = ctypes.CDLL(None, use_errno=True)
        libc.umount2.argtypes = (ctypes.c_char_p, ctypes.c_int)
        libc.umount2.restype = ctypes.c_int
        if libc.umount2(os.fsencode(target), 0) != 0:
            number = ctypes.get_errno()
            raise OSError(number, os.strerror(number), str(target))

    def now(self):
        return time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)


def process_info(pid):
    base = Path('/proc') / str(pid)
    proc_stat = (base / 'stat').read_text()
    # comm may contain spaces/parentheses; starttime is field 22.
    tail = proc_stat[proc_stat.rfind(')') + 2:].split()
    return {'pid': int(pid), 'start_ticks': int(tail[19]),
            'namespace': os.readlink(base / 'ns/mnt')}


def snapshot(directory, name, pid=None, kernel=None):
    directory = canonical(directory)
    if not re.fullmatch(r'[A-Za-z0-9-]+', name):
        raise SafetyError('invalid snapshot name')
    if pid is None:
        kernel = kernel or Kernel()
        info = process_info(os.getpid())
        text = kernel.mountinfo_text()
        status = Path('/proc/self/status').read_text()
    else:
        info = process_info(pid)
        text = (Path('/proc') / str(pid) / 'mountinfo').read_text()
        status = (Path('/proc') / str(pid) / 'status').read_text()
    write_json(directory / f'{name}.process.json', info)
    write_bytes(directory / f'{name}.mountinfo.txt', text.encode())
    write_bytes(directory / f'{name}.status.txt', status.encode())
    return info


def atomic_replace(target, control):
    target = canonical(target)
    temp_path = None
    try:
        fd, temp_name = tempfile.mkstemp(prefix='.mountstate-replace-', dir=target)
        temp_path = Path(temp_name)
        with os.fdopen(fd, 'wb') as stream:
            try:
                write_json(control / 'attempt-temp.json', {'path': str(temp_path)})
            except (OSError, SafetyError) as exc:
                result = error_result(exc, 'evidence-publication')
                result['result'] = 'ERROR'  # A failed logger is not a denied G1 operation.
                return result
            stream.write(REPLACED)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
        os.replace(temp_path, target / 'document.txt')
        return {'result': 'ALLOWED', 'phase': 'replace', 'errno': None, 'message': ''}
    except (OSError, SafetyError) as exc:
        return error_result(exc, 'replace')
    finally:
        if temp_path is not None and temp_path.exists():
            if temp_path.parent != target or temp_path.is_symlink():
                raise SafetyError('unsafe atomic-temp cleanup')
            temp_path.unlink()


def verify_spec(spec, token, cell):
    loc = layout(token, cell)
    for key, value in zip(('mode', 'profile', 'dac', 'context'), cell_parts(cell)):
        if spec.get(key) != value:
            raise SafetyError(f'spec semantic mismatch: {key}')
    for key in ('source', 'target', 'control'):
        if spec.get(key) != str(loc[key]):
            raise SafetyError(f'spec path mismatch: {key}')
        canonical(loc[key])
    if spec.get('token') != token or spec.get('cell') != cell:
        raise SafetyError('spec token/cell mismatch')
    return loc


def late_attempt(spec, trigger, kernel):
    target = Path(spec['target'])
    records = kernel.records()
    mounts = exact_mounts(records, target)
    host_mount = trigger.get('host_mount', {})
    marker = regular(target / '.state-token').read_text()
    signature_matches = len(mounts) == 1 and all(
        mounts[0].get(k) == host_mount.get(k) for k in ('device', 'root', 'fstype'))
    appeared = signature_matches and marker == spec['source_marker'] \
        and identity(target) == trigger.get('source_identity')
    if not appeared:
        return {'result': 'NOT_REPRODUCED', 'phase': 'propagation', 'errno': None,
                'message': 'host bind not visible as the registered source in model namespace',
                'state_reproduced': False, 'exact_target_mounts': mounts,
                'observed_marker': marker}
    result = atomic_replace(target, Path(spec['control']))
    result.update(state_reproduced=True, exact_target_mounts=mounts,
                  observed_marker=marker)
    return result


def nested_attempt(spec, host_namespace, kernel, take_snapshot=snapshot):
    target, control = Path(spec['target']), Path(spec['control'])
    if kernel.namespace() == host_namespace:
        return {'result': 'NOT_REPRODUCED', 'phase': 'namespace-safety', 'errno': None,
                'message': 'model is in host mount namespace; no mount attempted',
                'state_reproduced': False}
    before = kernel.records()
    if not nonshared(covering_mount(before, control)) or not nonshared(covering_mount(before, target)):
        return {'result': 'NOT_REPRODUCED', 'phase': 'propagation-safety', 'errno': None,
                'message': 'source or fresh-directory parent is shared; no mount attempted',
                'state_reproduced': False}
    fresh = Path(tempfile.mkdtemp(prefix='nested-', dir=control))
    old_identity = identity(fresh)
    write_json(control / 'nested.json', {'path': str(fresh), 'identity_before': old_identity})
    mounted = False
    mounted_signature = None
    result = {'result': 'ERROR', 'phase': 'bind', 'message': 'attempt incomplete',
              'errno': None, 'state_reproduced': False}
    try:
        try:
            kernel.mount(target, fresh, MS_BIND)
        except OSError as exc:
            result = error_result(exc, 'bind')
            result['state_reproduced'] = False
            return result
        mounted = True
        take_snapshot(control, 'after-bind', kernel=kernel)
        records = exact_mounts(kernel.records(), fresh)
        if len(records) != 1 or not nonshared(records[0]) or identity(fresh) != identity(target):
            raise SafetyError('nested bind identity/propagation verification failed')
        mounted_signature = records[0]
        flags = MS_BIND | MS_REMOUNT
        for opt, bit in REMOUNT_KEEP.items():
            if opt in records[0]['options']:
                flags |= bit
        try:
            kernel.mount(None, fresh, flags)  # Clear only per-mount read-only flag.
        except OSError as exc:
            result = error_result(exc, 'remount-rw')
            result['state_reproduced'] = False
            return result
        take_snapshot(control, 'after-remount', kernel=kernel)
        after = exact_mounts(kernel.records(), fresh)
        if len(after) != 1 or after[0]['id'] != mounted_signature['id'] \
                or not nonshared(after[0]) or 'rw' not in after[0]['options']:
            raise SafetyError('remount succeeded but registered writable bind state is absent')
        result = atomic_replace(fresh, control)
        result.update(state_reproduced=True, nested_mount=after[0])
        return result
    except (OSError, SafetyError) as exc:
        result = error_result(exc, 'state-verification')
        result['state_reproduced'] = False
        return result
    finally:
        if mounted:
            current = exact_mounts(kernel.records(), fresh)
            try:
                if len(current) != 1 or not nonshared(current[0]) \
                        or identity(fresh) != identity(target) \
                        or (mounted_signature is not None and current[0]['id'] != mounted_signature['id']):
                    raise SafetyError('refusing to unmount changed/unconfirmed nested mount')
                kernel.unmount(fresh)
                if exact_mounts(kernel.records(), fresh):
                    raise SafetyError('nested mount remains after unmount')
            except (OSError, SafetyError) as exc:
                result['attempt_result'] = result.get('result')
                result.update(error_result(exc, 'nested-cleanup'))
                # A cleanup denial is an execution error, not a security success.
                result['result'] = 'ERROR'
        if not exact_mounts(kernel.records(), fresh):
            if identity(fresh) != old_identity:
                result.update(result='ERROR', phase='nested-cleanup',
                              message='fresh directory identity changed after unmount')
            else:
                fresh.rmdir()


def model(token, cell, host_namespace, timeout_seconds):
    loc = layout(token, cell)
    spec = read_json(loc['control'] / 'spec.json')
    verify_spec(spec, token, cell)
    kernel = Kernel()
    if os.geteuid() != spec['model_uid']:
        raise SafetyError('model UID does not match registered context')
    result = {'result': 'ERROR', 'phase': 'startup', 'errno': None,
              'message': 'model incomplete', 'state_reproduced': False}
    try:
        info = snapshot(loc['control'], 'ready', kernel=kernel)
        ready = dict(info, token=token, cell=cell, uid=os.geteuid(),
                     raw_ns=kernel.now(), target_identity=identity(loc['target']))
        write_json(loc['control'] / 'ready.json', ready)
        print(json.dumps({'event': 'READY', **ready}), flush=True)
        deadline = kernel.now() + int(timeout_seconds * 1_000_000_000)
        while not (loc['control'] / 'trigger.json').exists():
            if kernel.now() > deadline:
                raise TimeoutError('host trigger deadline exceeded')
            time.sleep(0.05)
        trigger = read_json(loc['control'] / 'trigger.json')
        if trigger.get('token') != token or trigger.get('cell') != cell:
            raise SafetyError('trigger token/cell mismatch')
        snapshot(loc['control'], 'after-state', kernel=kernel)
        if kernel.namespace() == host_namespace:
            result = {'result': 'NOT_REPRODUCED', 'phase': 'namespace-safety',
                      'errno': None, 'message': 'no independent model namespace',
                      'state_reproduced': False}
        elif spec['mode'] == 'late':
            result = late_attempt(spec, trigger, kernel)
        else:
            result = nested_attempt(spec, host_namespace, kernel)
    except (OSError, SafetyError, TimeoutError, KeyboardInterrupt) as exc:
        result = error_result(exc, 'model-protocol')
        result['result'] = 'ERROR'
        result['state_reproduced'] = False
    finally:
        snapshot(loc['control'], 'before-exit', kernel=kernel)
        result.update(token=token, cell=cell, pid=os.getpid(), uid=os.geteuid(),
                      namespace=kernel.namespace(), raw_ns=kernel.now())
        write_json(loc['control'] / 'result.json', result)
        print(json.dumps({'event': 'RESULT', **result}), flush=True)
    return 0 if result['result'] != 'ERROR' else 2


def registry_path(out):
    return canonical(out) / 'owned-fixture.json'


def save_registry(out, registry):
    path = registry_path(out)
    if path.exists():
        replace_json(path, registry)
    else:
        write_json(path, registry)


def fixture_init(token, out):
    loc = layout(token)
    canonical(SITE)
    if not SITE.is_dir():
        raise SafetyError('SITE must be an existing real directory')
    for path in (loc['source_base'], loc['control_base']):
        canonical(path, exists=False)
        if path.exists() or path.is_symlink():
            raise SafetyError(f'fixture conflict: {path}')
    registry = {'token': token, 'bases': [], 'cells': []}
    save_registry(out, registry)
    for path in (loc['source_base'], loc['control_base']):
        path.mkdir(mode=0o755)
        registry['bases'].append({'path': str(path), 'identity': identity(path)})
        save_registry(out, registry)
    write_json(loc['source_base'] / '.owner.json', {'token': token})
    write_json(loc['control_base'] / '.owner.json', {'token': token})


def fixture_cell(token, cell, out):
    loc = layout(token, cell)
    mode, profile, dac, context = cell_parts(cell)
    registry = read_json(registry_path(out))
    if registry['token'] != token or any(item['cell'] == cell for item in registry['cells']):
        raise SafetyError('registry token/cell conflict')
    for path in (loc['source_base'], loc['control_base']):
        if read_json(path / '.owner.json')['token'] != token:
            raise SafetyError('fixture base ownership mismatch')
    if pwd is None:
        raise SafetyError('Linux pwd support is required for fixture preparation')
    account = pwd.getpwnam('labweb')
    model_uid = 0 if context == 'master' else account.pw_uid
    model_gid = 0 if context == 'master' else account.pw_gid
    owner_uid = 0 if dac == 'rootown' else account.pw_uid
    owner_gid = 0 if dac == 'rootown' else account.pw_gid
    spec = {'token': token, 'cell': cell, 'mode': mode, 'profile': profile,
            'dac': dac, 'context': context, 'model_uid': model_uid,
            'model_gid': model_gid, 'fixture_owner_uid': owner_uid,
            'fixture_owner_gid': owner_gid, 'fixture_dir_mode': '0755',
            'source_marker': f'SOURCE:{token}:{cell}\n',
            'target_marker': f'TARGET:{token}:{cell}\n',
            **{k: str(loc[k]) for k in ('source', 'target', 'control')}}
    record = {'cell': cell, 'nodes': []}
    registry['cells'].append(record)
    save_registry(out, registry)
    for key in ('source', 'target', 'control'):
        path = canonical(loc[key], exists=False)
        if path.exists() or path.is_symlink():
            raise SafetyError(f'cell fixture conflict: {path}')
        if below_mounts(Kernel().records(), path):
            raise SafetyError(f'pre-existing mount in fixture path: {path}')
        path.mkdir(mode=0o700 if key == 'control' else 0o755)
        record['nodes'].append({'key': key, 'path': str(path), 'identity': identity(path)})
        save_registry(out, registry)
        if key == 'control':
            write_json(path / 'spec.json', spec)
            os.chown(path / 'spec.json', 0, 0)
            os.chmod(path / 'spec.json', 0o444)
            os.chown(path, model_uid, model_gid)
        else:
            write_bytes(path / 'document.txt', ORIGINAL, 0o444)
            marker = spec[f'{key}_marker']
            write_bytes(path / '.state-token', marker.encode(), 0o444)
            os.chown(path, owner_uid, owner_gid)
    cell_out = canonical(out) / 'cells' / cell
    cell_out.mkdir(parents=True)
    write_json(cell_out / 'spec.json', spec)


def host_bind(token, cell, out):
    loc = layout(token, cell)
    spec = read_json(canonical(out) / 'cells' / cell / 'spec.json')
    verify_spec(spec, token, cell)
    if spec['mode'] != 'late':
        raise SafetyError('host-bind is allowed only in late mode')
    registry = read_json(registry_path(out))
    owned = next((r for r in registry['cells'] if r['cell'] == cell), None)
    if registry['token'] != token or owned is None:
        raise SafetyError('host bind has no ownership record')
    for key in ('source', 'target'):
        node = next((n for n in owned['nodes'] if n['key'] == key), None)
        if node is None or node['path'] != str(loc[key]) or identity(loc[key]) != node['identity']:
            raise SafetyError('host fixture directory identity changed before bind')
    before = Kernel().records()
    if below_mounts(before, loc['source']) or below_mounts(before, loc['target']):
        raise SafetyError('host source/target already contains a mount')
    if regular(loc['source'] / '.state-token').read_text() != spec['source_marker'] \
            or regular(loc['target'] / '.state-token').read_text() != spec['target_marker']:
        raise SafetyError('host fixture marker mismatch')
    source_identity, target_identity = identity(loc['source']), identity(loc['target'])
    completed = subprocess.run(['mount', '--bind', '--', str(loc['source']), str(loc['target'])],
                               capture_output=True, text=True, timeout=10)
    binding = {'token': token, 'cell': cell, 'source': str(loc['source']),
               'target': str(loc['target']), 'source_identity': source_identity,
               'target_identity_before': target_identity, 'command_rc': completed.returncode,
               'stdout': completed.stdout, 'stderr': completed.stderr, 'confirmed': False}
    after = exact_mounts(Kernel().records(), loc['target'])
    binding['target_mounts_after'] = after
    if completed.returncode == 0 and len(after) == 1 \
            and identity(loc['target']) == source_identity:
        binding.update(confirmed=True, host_mount=after[0])
    write_json(canonical(out) / 'cells' / cell / 'host-bind.json', binding)
    if not binding['confirmed']:
        raise SafetyError('host bind failed or could not be confirmed; preserve raw diagnostics')


def verify_binding(binding, token, cell, records):
    loc = layout(token, cell)
    if binding.get('token') != token or binding.get('cell') != cell \
            or binding.get('source') != str(loc['source']) or binding.get('target') != str(loc['target']) \
            or not binding.get('confirmed'):
        raise SafetyError('unconfirmed or foreign binding record')
    canonical(loc['source']); canonical(loc['target'])
    mounts = below_mounts(records, loc['target'])
    if len(mounts) != 1 or any(mounts[0].get(k) != binding['host_mount'].get(k)
                              for k in ('id', 'device', 'root', 'target', 'fstype')) \
            or identity(loc['target']) != binding['source_identity']:
        raise SafetyError('refusing to unmount changed binding or subtree')
    return loc


def host_unbind(token, cell, out):
    directory = canonical(out) / 'cells' / cell
    path = directory / 'host-bind.json'
    if not path.exists():
        return
    binding = read_json(path)
    loc = layout(token, cell)
    if not exact_mounts(Kernel().records(), loc['target']):
        if binding.get('confirmed') and identity(loc['target']) != binding['target_identity_before']:
            raise SafetyError('unbound target identity differs from original fixture')
        return
    loc = verify_binding(binding, token, cell, Kernel().records())
    done = subprocess.run(['umount', '--', str(loc['target'])], capture_output=True,
                          text=True, timeout=10)
    report = {'rc': done.returncode, 'stdout': done.stdout, 'stderr': done.stderr,
              'target': str(loc['target']), 'mounts_after': exact_mounts(Kernel().records(), loc['target'])}
    write_json(directory / 'host-unbind.json', report)
    if done.returncode or report['mounts_after'] or identity(loc['target']) != binding['target_identity_before']:
        raise SafetyError('host unmount incomplete; no force/lazy/recursive fallback')


def wait_ready(token, cell, unit, out):
    loc = layout(token, cell)
    kernel = Kernel()
    deadline = kernel.now() + 15_000_000_000
    while not (loc['control'] / 'ready.json').exists():
        if kernel.now() > deadline:
            raise TimeoutError('READY deadline exceeded')
        time.sleep(0.05)
    ready = read_json(loc['control'] / 'ready.json')
    if ready.get('token') != token or ready.get('cell') != cell:
        raise SafetyError('READY token/cell mismatch')
    info = process_info(ready['pid'])
    if any(info[k] != ready.get(k) for k in ('pid', 'start_ticks', 'namespace')):
        raise SafetyError('READY process identity changed')
    done = subprocess.run(['systemctl', 'show', unit, '-p', 'MainPID', '--value'],
                          capture_output=True, text=True, timeout=5, check=True)
    if int(done.stdout.strip()) != ready['pid']:
        raise SafetyError('READY process is not the registered unit MainPID')
    if ready['namespace'] == os.readlink('/proc/self/ns/mnt'):
        raise SafetyError('launcher did not establish independent model namespace')
    write_json(canonical(out) / 'cells' / cell / 'ready-confirmed.json', ready)
    return ready['pid']


def trigger(token, cell, out):
    loc = layout(token, cell)
    data = {'token': token, 'cell': cell}
    if cell_parts(cell)[0] == 'late':
        binding = read_json(canonical(out) / 'cells' / cell / 'host-bind.json')
        verify_binding(binding, token, cell, Kernel().records())
        data.update(host_mount=binding['host_mount'], source_identity=binding['source_identity'])
    write_json(loc['control'] / 'trigger.json', data)
    os.chmod(loc['control'] / 'trigger.json', 0o444)


def collect_control(token, cell, out):
    loc = layout(token, cell)
    destination = canonical(out) / 'cells' / cell / 'model'
    destination.mkdir(parents=True, exist_ok=True)
    if not loc['control'].exists():
        return
    for name in sorted(CONTROL_FILES):
        path = loc['control'] / name
        if not path.exists() and not path.is_symlink():
            continue
        path = regular(path)
        dest = destination / name
        if dest.exists():
            if regular(dest).read_bytes() != path.read_bytes():
                raise SafetyError('model raw file changed after collection')
        else:
            shutil.copyfile(path, dest)


def provisional_outcome(result, http_code, body, baseline_ok=True, launcher_rc=0):
    if not baseline_ok:
        return 'ERROR'
    expected = REPLACED if result.get('result') == 'ALLOWED' else ORIGINAL
    if http_code != '200' or body != expected:
        return 'UNEXPECTED'
    if launcher_rc and result.get('result') != 'ERROR' \
            and result.get('phase') != 'harness-not-supported':
        return 'ERROR'
    return {'ALLOWED': 'ACHIEVED', 'DENIED': 'BLOCKED',
            'NOT_REPRODUCED': 'NOT_REPRODUCED', 'ERROR': 'ERROR'}.get(result.get('result'), 'ERROR')


def record_cell(token, cell, out):
    directory = canonical(out) / 'cells' / cell
    spec = read_json(directory / 'spec.json')
    result_path = directory / 'model' / 'result.json'
    result = read_json(result_path) if result_path.exists() else {
        'result': 'ERROR', 'phase': 'launch-or-protocol', 'errno': None,
        'message': 'no model result; this is not BLOCKED', 'state_reproduced': False}
    launcher_output = directory / 'launcher.out'
    if not result_path.exists() and launcher_output.exists():
        text = regular(launcher_output).read_text(encoding='utf-8', errors='replace')
        if re.search(r'Unknown assignment:?[ \t]+(?:MountFlags=slave|PrivateMounts=yes)', text):
            result.update(result='NOT_REPRODUCED', phase='harness-not-supported',
                          message='explicit unsupported safety-harness property; model did not execute')
    def http(label):
        code, body = directory / f'{label}.http.code', directory / f'{label}.http.body'
        return ((regular(code).read_text().strip() if code.exists() else 'MISSING'),
                (regular(body).read_bytes() if body.exists() else b''))
    baseline_code, baseline_body = http('baseline')
    final_code, final_body = http('final')
    launcher = directory / 'launcher.rc'
    launch_rc = int(regular(launcher).read_text().strip()) if launcher.exists() else 2
    baseline_ok = baseline_code == '200' and baseline_body == ORIGINAL
    observation = dict(spec, model_result=result, launcher_rc=launch_rc,
                       baseline_http=baseline_code, baseline_ok=baseline_ok,
                       final_http=final_code, final_body_hex=final_body.hex(),
                       provisional=provisional_outcome(result, final_code, final_body, baseline_ok, launch_rc))
    evidence_errors = []
    for label in ('before', 'final', 'after-state'):
        file = directory / f'snapshot-{label}.rc'
        if file.exists() and regular(file).read_text().strip() != '0':
            evidence_errors.append(f'incomplete nginx namespace snapshot: {label}')
    host_after = directory / 'host-after-attempt.mountinfo.txt'
    if host_after.exists():
        leaked = below_mounts(parse_mountinfo(regular(host_after).read_text()), Path(spec['control']))
        if leaked:
            evidence_errors.append('unexpected host mount under owned model control directory')
            observation['host_mount_leaks'] = leaked
    if evidence_errors:
        observation['unqualified_provisional'] = observation['provisional']
        observation['provisional'] = 'ERROR'
        result['evidence_errors'] = evidence_errors
    write_json(directory / 'observation.json', observation)


def final_rows(observations):
    controls = {(r['mode'], r['dac'], r['context']): r for r in observations if r['profile'] == 'P0'}
    rows = []
    for observation in observations:
        control = controls.get((observation['mode'], observation['dac'], observation['context']))
        positive = control is not None and control['provisional'] == 'ACHIEVED'
        control_outcome = control['provisional'] if control else 'MISSING'
        outcome = observation['provisional']
        if outcome == 'BLOCKED' and not positive:
            outcome = 'NOT_REPRODUCED'
        result = observation['model_result']
        rows.append(dict(observation, outcome=outcome, eligible=int(positive),
                         control_outcome=control_outcome,
                         detail=f"mode={observation['mode']} raw={result.get('result')} "
                         f"phase={result.get('phase')} errno={result.get('errno')} "
                         f"state_reproduced={int(bool(result.get('state_reproduced')))} "
                         f"P0_control={control_outcome} eligible={int(positive)} "
                         f"http={observation['final_http']} model_pid={result.get('pid')} "
                         f"message={result.get('message', '')} "
                         f"evidence_errors={result.get('evidence_errors', [])}"))
    return rows


def finalize(token, out):
    registry = read_json(registry_path(out))
    if registry['token'] != token:
        raise SafetyError('finalization registry mismatch')
    observations = []
    for cell in registry['cells']:
        path = canonical(out) / 'cells' / cell['cell'] / 'observation.json'
        if path.exists():
            observations.append(read_json(path))
    rows = final_rows(observations)
    for filename, fields in (
            ('goals.csv', ('service', 'goal', 'dac', 'context', 'profile', 'outcome', 'detail')),
            ('observations.csv', ('mode', 'profile', 'dac', 'context', 'outcome', 'eligible',
                                  'control_outcome', 'provisional', 'detail'))):
        path = canonical(out) / filename
        with path.open('x', encoding='utf-8', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore')
            writer.writeheader()
            for row in rows:
                writer.writerow(dict(row, service='nginx', goal='G1-replace-document'))
    counts = {status: sum(row['outcome'] == status for row in rows)
              for status in ('ACHIEVED', 'BLOCKED', 'NOT_REPRODUCED', 'UNEXPECTED', 'ERROR')}
    complete = len(rows) == 40
    report = {'planned_cells': 40, 'observed_cells': len(rows), 'counts': counts,
              'complete_cells': complete, 'selection_input': False,
              'baseline': 'P0+PrivateMounts=yes+MountFlags=slave harness, not primary P0',
              'status': 'COMPLETE' if complete and not counts['ERROR'] and not counts['UNEXPECTED']
                        else 'FAILED_OR_INCOMPLETE'}
    write_json(canonical(out) / 'summary.json', report)
    print(json.dumps(report), flush=True)
    return 0 if report['status'] == 'COMPLETE' else 2


def fixture_cleanup(token, out):
    registry = read_json(registry_path(out))
    if registry['token'] != token:
        raise SafetyError('cleanup registry mismatch')
    failures = []
    for record in reversed(registry['cells']):
        cell = record['cell']
        loc = layout(token, cell)
        try:
            host_unbind(token, cell, out)
            collect_control(token, cell, out)
            # Only this model's explicitly recorded empty fresh directory.
            nested_path = loc['control'] / 'nested.json'
            if nested_path.exists():
                nested = read_json(nested_path)
                path = canonical(nested['path'], exists=False)
                if path.parent != loc['control'] or not path.name.startswith('nested-'):
                    raise SafetyError('foreign nested directory record')
                if path.exists():
                    if below_mounts(Kernel().records(), path) or identity(path) != nested['identity_before']:
                        raise SafetyError('nested directory is mounted/changed in host; preserve')
                    path.rmdir()
            for node in reversed(record['nodes']):
                path = canonical(node['path'], exists=False)
                if path != loc[node['key']]:
                    raise SafetyError('foreign registry node')
                if not path.exists():
                    continue
                if identity(path) != node['identity'] or below_mounts(Kernel().records(), path):
                    raise SafetyError('fixture node changed or still mounted')
                names = CONTROL_FILES if node['key'] == 'control' else {'document.txt', '.state-token'}
                for name in sorted(names):
                    file = path / name
                    if file.exists() or file.is_symlink():
                        regular(file).unlink()
                # Unknown files are preserved; rmdir then fails, never recursive deletion.
                path.rmdir()
        except (OSError, SafetyError, subprocess.SubprocessError) as exc:
            failures.append({'cell': cell, 'error': str(exc)})
    loc = layout(token)
    for base in reversed(registry['bases']):
        try:
            path = canonical(base['path'], exists=False)
            if path not in (loc['source_base'], loc['control_base']):
                raise SafetyError('foreign base registry entry')
            if path.exists():
                if identity(path) != base['identity'] or below_mounts(Kernel().records(), path):
                    raise SafetyError('fixture base changed or mounted')
                owner = path / '.owner.json'
                if owner.exists():
                    if read_json(owner)['token'] != token:
                        raise SafetyError('fixture owner token changed')
                    if any(p.name != '.owner.json' for p in path.iterdir()):
                        raise SafetyError('fixture base contains retained data; keep owner marker')
                    owner.unlink()
                path.rmdir()
        except (OSError, SafetyError) as exc:
            failures.append({'base': base['path'], 'error': str(exc)})
    write_json(canonical(out) / 'fixture-cleanup.json', {'failures': failures})
    return 2 if failures else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('init', 'prepare', 'model', 'wait-ready', 'trigger',
                        'host-bind', 'host-unbind', 'snapshot', 'collect', 'record', 'finalize', 'cleanup'))
    parser.add_argument('--token', required=True)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--cell')
    parser.add_argument('--unit')
    parser.add_argument('--host-namespace')
    parser.add_argument('--timeout-seconds', type=float, default=15)
    parser.add_argument('--pid', type=int)
    parser.add_argument('--name')
    args = parser.parse_args()
    layout(args.token, args.cell)
    if args.command == 'model':
        if not args.cell or not args.host_namespace or not 1 <= args.timeout_seconds <= 20:
            parser.error('model requires cell, host namespace and bounded deadline')
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
        return model(args.token, args.cell, args.host_namespace, args.timeout_seconds)
    if os.geteuid() != 0:
        raise SafetyError('host commands require root on the experiment VM')
    if os.readlink('/proc/self/ns/mnt') != os.readlink('/proc/1/ns/mnt'):
        raise SafetyError('host runner must be in the service manager mount namespace')
    if args.out is None:
        parser.error('host command requires out')
    canonical(args.out)
    if args.command in ('prepare', 'wait-ready', 'trigger', 'host-bind', 'host-unbind', 'collect', 'record') \
            and args.cell is None:
        parser.error('cell required')
    if args.command == 'init': fixture_init(args.token, args.out)
    elif args.command == 'prepare': fixture_cell(args.token, args.cell, args.out)
    elif args.command == 'host-bind': host_bind(args.token, args.cell, args.out)
    elif args.command == 'host-unbind': host_unbind(args.token, args.cell, args.out)
    elif args.command == 'trigger': trigger(args.token, args.cell, args.out)
    elif args.command == 'wait-ready':
        if not args.unit or not args.unit.startswith(f'slab-v005-mountstate-{args.token}-'):
            raise SafetyError('foreign model unit name')
        print(wait_ready(args.token, args.cell, args.unit, args.out))
    elif args.command == 'snapshot':
        if not args.name: parser.error('snapshot name required')
        directory = args.out / 'cells' / args.cell if args.cell else args.out
        snapshot(directory, args.name, args.pid)
    elif args.command == 'collect': collect_control(args.token, args.cell, args.out)
    elif args.command == 'record': record_cell(args.token, args.cell, args.out)
    elif args.command == 'finalize': return finalize(args.token, args.out)
    elif args.command == 'cleanup': return fixture_cleanup(args.token, args.out)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, SafetyError, TimeoutError, subprocess.SubprocessError, ValueError) as exc:
        print(json.dumps({'host_or_model_error': str(exc), 'type': type(exc).__name__}), file=sys.stderr)
        sys.exit(2)
