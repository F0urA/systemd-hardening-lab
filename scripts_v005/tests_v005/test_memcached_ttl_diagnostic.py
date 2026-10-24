"""memcached_ttl_diagnostic.py against synthetic rows and a fake loopback server. No VM."""
import csv
import importlib.util
import json
import socketserver
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
SCRIPTS = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ttl_tested', SCRIPTS / 'memcached_ttl_diagnostic.py')
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)


class FakeMemcached(socketserver.ThreadingTCPServer):
    """ASCII subset with the clock of memcached: whole seconds, updated once a second."""
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        super().__init__(('127.0.0.1', 0), Handler)
        self.items, self.start, self.current = {}, int(time.monotonic()), 0
        self.ticking = True
        threading.Thread(target=self.tick, daemon=True).start()

    def tick(self):
        while self.ticking:
            time.sleep(1)
            self.current = int(time.monotonic()) - self.start


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        s = self.server
        for line in self.rfile:
            words = line.split()
            if words == [b'version']:
                self.wfile.write(b'VERSION 1.6.42_alt1\r\n')
            elif words[:1] == [b'set']:
                key, exp, size = words[1], int(words[3]), int(words[4])
                value = self.rfile.read(size + 2)[:-2]
                s.items[key] = (value, s.current + exp if exp else 0)
                self.wfile.write(b'STORED\r\n')
            elif words[:1] == [b'get']:
                value, exptime = s.items.get(words[1], (None, 0))
                if value is not None and exptime and exptime <= s.current:
                    value = None
                if value is not None:
                    self.wfile.write(b'VALUE ' + words[1] + b' 0 ' + str(len(value)).encode() + b'\r\n' + value + b'\r\n')
                self.wfile.write(b'END\r\n')
            elif words[:1] == [b'delete']:
                s.items.pop(words[1], None)
                self.wfile.write(b'DELETED\r\n')


def rows(path, table):
    with open(path / 'rows.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(d.FIELDS)
        for i, (profile, expiration, expiry, gap) in enumerate(table, 1):
            w.writerow([i, 1, profile, expiration, int(expiration == 'PASS'), expiry, gap])


class TtlDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def verdict(self, table):
        rows(self.dir, table)
        with patch('sys.stdout'):
            d.summarize(self.dir)
        return (self.dir / 'summary.txt').read_text(encoding='utf-8').splitlines()[-1]

    def test_no_failure_is_not_reproduced(self):
        self.assertEqual(self.verdict([(p, 'PASS', 1.5, 40) for p in d.PROFILES]), 'VERDICT=NOT_REPRODUCED')

    def test_failures_only_with_pauses(self):
        table = [(p, 'PASS', 1.5, 40) for p in d.PROFILES] + [('P1', 'FAIL', 1.4, 2500), ('P0', 'FAIL', 1.2, 1800)]
        self.assertEqual(self.verdict(table), 'VERDICT=PAUSE_EFFECT')

    def test_quiet_failures_of_p1_only(self):
        table = [(p, 'PASS', 1.5, 40) for p in d.PROFILES] + [('P1', 'FAIL', 4.0, 30)] * 3
        self.assertEqual(self.verdict(table), 'VERDICT=PROFILE_EFFECT')

    def test_quiet_slow_expiry_is_unclassified(self):
        table = [(p, 'PASS', 1.5, 40) for p in d.PROFILES] + [('P2', 'PASS', 2.9, 30)]
        self.assertEqual(self.verdict(table), 'VERDICT=UNCLASSIFIED')

    def test_check_against_fake_server(self):
        server = FakeMemcached()
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            # CLOCK_MONOTONIC_RAW of the client is Linux-only
            with patch.object(d, 'PORT', server.server_address[1]),                     patch.object(d.client, 'elapsed_ns', time.monotonic_ns):
                d.check('1.6.42_alt1', self.dir / 'check.json')
        finally:
            server.ticking = False
            server.shutdown()
            server.server_close()
        result = json.loads((self.dir / 'check.json').read_text(encoding='utf-8'))
        self.assertEqual(result['expiration'], 'PASS')
        self.assertTrue(result['contract_before_pass'])
        self.assertTrue(0.9 <= result['time_to_expiry_s'] <= 2.3, result['time_to_expiry_s'])


if __name__ == '__main__':
    unittest.main()
