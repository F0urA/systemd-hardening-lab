#!/usr/bin/env python3
"""Read-only final VM evidence. No existing laboratory scripts are executed."""
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(os.environ.get('SLAB_BASE', '/root/systemd-hardening-lab'))
RAW = BASE / 'results_v005'
errors = []


def run(argv):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        return {'rc': result.returncode, 'stdout': result.stdout.strip(),
                'stderr': result.stderr.strip()}
    except Exception as exc:
        errors.append(f'{argv[0]}: {exc}')
        return {'rc': None, 'stdout': '', 'stderr': str(exc)}


def sha(path):
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception as exc:
        errors.append(f'{path}: {exc}')
        return None


services = {}
for service in ('nginx', 'redis', 'postgresql'):
    dropin_dir = Path(f'/etc/systemd/system/slab-{service}.service.d')
    p4 = RAW / service / 'profiles' / 'P4.conf'
    live = dropin_dir / '90-hardening.conf'
    state = run(['systemctl', 'show', f'slab-{service}.service',
                 '-p', 'ActiveState', '-p', 'SubState', '-p', 'MainPID', '-p', 'DropInPaths'])
    properties = dict(line.split('=', 1) for line in state['stdout'].splitlines() if '=' in line)
    entries = sorted(str(p) for p in dropin_dir.iterdir())
    services[service] = {'systemctl': state, 'properties': properties,
                         'p4_sha256': sha(p4), 'live_sha256': sha(live), 'dropin_entries': entries}
    services[service]['exact_p4_active'] = (
        services[service]['p4_sha256'] is not None
        and services[service]['p4_sha256'] == services[service]['live_sha256']
        and properties.get('ActiveState') == 'active'
        and entries == [str(live)]
    )

workload_binaries = {'ab', 'pgbench', 'redis-benchmark', 'memcached'}
workload_scripts = {'benchmark_v005.sh', 'slab_heartbeat_v005.py',
                    'memcached_client_v005.py', 'mount_state_helper_v005.py',
                    'slab-mountstate-v005.py', 'driver_primary_resume_v005.sh',
                    'driver_post_primary_resume_v005.sh', 'driver_extensions_v005.sh'}
processes = []
proc_scan_errors = []
for entry in Path('/proc').iterdir():
    if not entry.name.isdigit():
        continue
    try:
        exe = Path(os.readlink(entry / 'exe')).name
        argv = (entry / 'cmdline').read_bytes().decode('utf-8', 'replace').split('\0')
        script_names = {Path(arg).name for arg in argv if arg and '\n' not in arg}
        if exe in workload_binaries or script_names & workload_scripts:
            processes.append({'pid': int(entry.name), 'exe': exe, 'argv': argv,
                              'cwd': os.readlink(entry / 'cwd')})
    except (FileNotFoundError, ProcessLookupError):
        pass
    except Exception as exc:
        proc_scan_errors.append(f'{entry.name}: {exc}')

fixture_paths = [
    '/etc/systemd/system/slab-nginx-ext.service',
    '/etc/systemd/system/slab-nginx-ext-upstream.service',
    '/etc/systemd/system/slab-nginx-ext.service.d',
    '/etc/systemd-lab/nginx-ext-v005', '/var/lib/systemd-lab/nginx-ext-v005',
    '/var/log/slab-nginx-ext-v005-error.log', '/run/slab-nginx-ext-v005.pid',
    '/var/lib/systemd-lab/mountstate-v005', '/usr/local/bin/slab-mountstate-v005.py',
    '/var/lib/systemd-lab/memcached-v005-fixture',
    '/etc/systemd/system/slab-memcached-v005.service',
    '/etc/systemd/system/slab-memcached-v005.service.d',
]
remaining_fixture_paths = [p for p in fixture_paths if os.path.lexists(p)]
for parent, pattern in [(Path('/run'), 'slab-mountstate-v005-*'),
                        (Path('/var/lib/systemd-lab/nginx-www'), 'mountstate-v005-*')]:
    remaining_fixture_paths.extend(str(p) for p in parent.glob(pattern))

owned_mounts = [line for line in Path('/proc/self/mountinfo').read_text().splitlines()
                if 'mountstate-v005' in line or 'nginx-ext-v005' in line
                or 'memcached-v005-fixture' in line]
transients = run(['systemctl', 'list-units', '--all', '--no-legend', '--no-pager',
                  'slab-v005-*', 'slab-mountstate-v005-*'])
default_memcached = run(['systemctl', 'show', 'memcached.service',
                        '-p', 'LoadState', '-p', 'ActiveState', '-p', 'UnitFileState'])
own_memcached = run(['systemctl', 'show', 'slab-memcached-v005.service',
                    '-p', 'LoadState', '-p', 'ActiveState', '-p', 'UnitFileState'])
memcached_user = run(['getent', 'passwd', 'labmemcachev005'])
tcp = run(['ss', '-H', '-ltnp', '( sport = :11211 or sport = :11212 or sport = :8443 or sport = :18080 )'])
udp = run(['ss', '-H', '-lnup', '( sport = :11211 or sport = :11212 )'])

installed = Path('/usr/local/bin/ptrace_seize.py')
expected = BASE / 'frozen-timing/v005/stand_v005/probes/ptrace_seize.py'
installed_bytes, expected_bytes = installed.read_bytes(), expected.read_bytes()
helper = {'installed_sha256': sha(installed), 'expected_sha256': sha(expected),
          'byte_equal': installed_bytes == expected_bytes,
          'equal_after_crlf_normalization': installed_bytes.replace(b'\r\n', b'\n')
                                           == expected_bytes.replace(b'\r\n', b'\n')}

evidence = {
    'schema': 'v005-final-read-only-vm-check-1',
    'utc': datetime.now(timezone.utc).isoformat(),
    'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
    'services': services, 'remaining_workloads_or_controllers': processes,
    'proc_scan_errors': proc_scan_errors, 'remaining_fixture_paths': remaining_fixture_paths,
    'owned_fixture_mounts': owned_mounts, 'transient_lab_units': transients,
    'default_memcached': default_memcached, 'own_memcached': own_memcached,
    'memcached_user': memcached_user, 'fixture_tcp_listeners': tcp, 'memcached_udp_listeners': udp,
    'reserved_ports': Path('/proc/sys/net/ipv4/ip_local_reserved_ports').read_text().strip(),
    'ptrace_helper_comparison': helper, 'errors': errors,
    'no_state_changes_performed': True,
}
print(json.dumps(evidence, ensure_ascii=False, indent=2))
