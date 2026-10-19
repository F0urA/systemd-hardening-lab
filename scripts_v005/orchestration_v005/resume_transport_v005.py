#!/usr/bin/env python3
"""Scoped transient PG transport guard. No statistics or persistent sysctl."""
import argparse
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(os.environ.get('SLAB_BASE', '/root/systemd-hardening-lab'))
ROOT = BASE / 'results_v005'
RESERVED = Path('/proc/sys/net/ipv4/ip_local_reserved_ports')
SCOPES = ['R3-postgresql-retry-only', 'planned-postgresql-extension-if-requested']
SPEC = {
    'R1-nginx': ('nginx', 60, ['P1c','P4','P5','P6'], 7),
    'R2-redis': ('redis', 20, ['P1','P2','P1d','P4','P6'], 5),
    'R3-postgresql': ('postgresql', 10, ['P1','P2','P1d','P4','P6'], 5),
    'R5-nginx-light': ('nginx', 60, ['P1','P2','P1r'], 7),
    'R4-nginx-nonsaturated': ('nginx', 60, ['P1c','P4'], 2),
}

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def plan_has_pg(path):
    """Structural envelope only; frozen analyzer/driver remains authoritative."""
    plan = json.loads(Path(path).read_text())
    if not isinstance(plan, dict) or plan.get('schema') != 'v005-first-look-plan-1' or \
            plan.get('looks') != 2 or plan.get('level') != 0.05 or \
            plan.get('trigger') != 'throughput_interval_contains_zero':
        raise ValueError('unexpected frozen plan envelope')
    rows, seen = plan.get('extensions'), set()
    if not isinstance(rows, list) or not isinstance(plan.get('primary', {}).get('series'), dict):
        raise ValueError('invalid frozen plan structure')
    for row in rows:
        if not isinstance(row, dict) or row.get('stage') not in SPEC or row['stage'] in seen:
            raise ValueError('duplicate/unknown planned stage')
        name = row['stage']; seen.add(name)
        service, blocks, profiles, family = SPEC[name]
        selected = row.get('profiles')
        if row.get('service') != service or row.get('blocks') != blocks or row.get('family') != family or \
                not isinstance(selected, list) or not selected or len(selected) != len(set(selected)) or \
                selected != [p for p in profiles if p in selected] or \
                str(row.get('nginx_c')) not in {'1','2','4','8','16','25'} or name not in plan['primary']['series']:
            raise ValueError('planned extension differs from frozen scope')
    return any(row['service'] == 'postgresql' for row in rows)

class Transport:
    def __init__(self, root=ROOT, reserved=RESERVED):
        self.root, self.reserved = Path(root), Path(reserved)
        self.driver = self.root / 'driver'
        self.registration = self.driver / 'resume-transport-registration.json'
        self.primary_record = self.driver / 'R3-retry-transport-restoration.json'
        self.extension_log = self.driver / 'extension-pg-transport.txt'

    def registration_hash(self):
        if self.registration.is_symlink() or self.registration.resolve().parent != self.driver.resolve():
            raise ValueError('unsafe transport registration')
        data = json.loads(self.registration.read_text())
        if not isinstance(data, dict) or data.get('prior_reserved_ports') != '' or data.get('reserved_ports') != '55432' or \
                data.get('scopes') != SCOPES:
            raise ValueError('registration must contain the two exact predeclared scopes')
        return sha(self.registration)

    def current(self):
        return self.reserved.read_text().strip()

    def write_exact(self, expected, target):
        observed = self.current()
        if observed != expected:
            raise ValueError(f'foreign reserved-ports change: expected {expected!r}, found {observed!r}; NOT OVERWRITTEN')
        # A compare-before-write guard, not a claim of kernel atomic CAS.
        self.reserved.write_text(target + '\n')
        if self.current() != target:
            raise ValueError('reserved-ports post-write verification failed')

    def save(self, path, data, append=False):
        if path.is_symlink() or path.resolve().parent != self.driver.resolve():
            raise ValueError('unsafe transport audit destination')
        data = {'schema':'v005-transport-event-1','utc':datetime.now(timezone.utc).isoformat(), **data}
        with path.open('a' if append else 'w', encoding='utf-8') as output:
            output.write(json.dumps(data, ensure_ascii=False) + '\n'); output.flush(); os.fsync(output.fileno())

    def primary_check(self):
        token = self.registration_hash()
        if self.primary_record.exists() or self.primary_record.is_symlink():
            raise ValueError('primary transport scope already has a restoration record')
        if self.current() != '55432':
            raise ValueError('parent must reserve exactly 55432 before the sole R3 retry')
        return token

    def primary_restore(self, token, phase):
        if token != self.registration_hash():
            raise ValueError('registration changed; reservation NOT OVERWRITTEN')
        if self.primary_record.is_symlink():
            raise ValueError('unsafe primary restoration record')
        if self.primary_record.exists():
            prior = json.loads(self.primary_record.read_text())
            if prior.get('registration_sha256') == token and prior.get('status') == 'RESTORED':
                if self.current() == '':
                    return 'ALREADY_RESTORED'
                raise ValueError('primary scope ended but another actor changed reservation; NOT OVERWRITTEN')
        try:
            self.write_exact('55432', '')
        except ValueError as exc:
            self.save(self.primary_record, {'scope':SCOPES[0], 'phase':phase, 'status':'ERROR',
                'registration_sha256':token, 'observed':self.current(), 'error':str(exc)})
            raise
        self.save(self.primary_record, {'scope':SCOPES[0], 'phase':phase, 'status':'RESTORED',
            'registration_sha256':token, 'prior':'55432', 'after':''})
        return 'RESTORED'

    def extension_start(self, path):
        if not plan_has_pg(path):
            raise ValueError('extension_start is forbidden for a non-PG plan')
        registration = self.registration_hash()
        if self.current() != '':
            raise ValueError('planned PG extension requires prior reserved ports EMPTY; NOT OVERWRITTEN')
        token = uuid.uuid4().hex
        event = {'scope':SCOPES[1], 'token':token, 'registration_sha256':registration,
                 'plan_sha256':sha(path), 'prior':'', 'after':'55432'}
        self.save(self.extension_log, {**event, 'status':'RESERVE_INTENT'}, append=True)
        applied = False
        try:
            self.write_exact('', '55432'); applied = True
            self.save(self.extension_log, {**event, 'status':'RESERVED_BEFORE_LOAD'}, append=True)
        except Exception:
            if applied and registration == self.registration_hash() and self.current() == '55432':
                self.write_exact('55432', '')
            raise
        return token

    def extension_restore(self, token, phase):
        registration = self.registration_hash()
        if self.extension_log.is_symlink():
            raise ValueError('unsafe extension transport log')
        events = [json.loads(line) for line in self.extension_log.read_text().splitlines() if line]
        owned = [event for event in events if event.get('token') == token and
                 event.get('scope') == SCOPES[1] and event.get('registration_sha256') == registration]
        if not owned or not any(event['status'] == 'RESERVED_BEFORE_LOAD' for event in owned):
            raise ValueError('no owned PG extension reservation; NOT OVERWRITTEN')
        if any(event['status'] == 'RESTORED' for event in owned):
            if self.current() == '':
                return 'ALREADY_RESTORED'
            raise ValueError('extension scope ended and another actor changed reservation; NOT OVERWRITTEN')
        try:
            self.write_exact('55432', '')
        except ValueError as exc:
            self.save(self.extension_log, {'scope':SCOPES[1], 'token':token, 'registration_sha256':registration,
                'phase':phase, 'status':'ERROR', 'observed':self.current(), 'error':str(exc)}, append=True)
            raise
        self.save(self.extension_log, {'scope':SCOPES[1], 'token':token, 'registration_sha256':registration,
            'phase':phase, 'status':'RESTORED', 'prior':'55432', 'after':''}, append=True)
        return 'RESTORED'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['plan-has-pg','primary-check','primary-restore','extension-start','extension-restore'])
    parser.add_argument('value', nargs='?'); parser.add_argument('--phase', default='EXIT')
    args = parser.parse_args()
    if args.action == 'plan-has-pg':
        print(int(plan_has_pg(args.value))); return  # Does not even read sysctl.
    driver = ROOT / 'driver'
    if ROOT.is_symlink() or ROOT.resolve(strict=True) != ROOT or driver.is_symlink() or \
            not driver.is_dir() or driver.resolve(strict=True) != driver:
        raise ValueError('unexpected result root')
    transport = Transport()
    if args.action == 'primary-check': print(transport.primary_check())
    elif args.action == 'primary-restore': print(transport.primary_restore(args.value, args.phase))
    elif args.action == 'extension-start': print(transport.extension_start(args.value))
    else: print(transport.extension_restore(args.value, args.phase))

if __name__ == '__main__':
    try: main()
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print('TRANSPORT_GUARD_ERROR: '+str(exc), file=sys.stderr); raise SystemExit(2)
