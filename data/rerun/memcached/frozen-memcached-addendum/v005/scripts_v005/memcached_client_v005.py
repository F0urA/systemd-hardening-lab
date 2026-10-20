#!/usr/bin/env python3
"""Standalone loopback-only memcached ASCII client; Python standard library.

Contract probes and a predeclared fixed-pipeline load, not a filesystem attacker
model. No connection is made on import. The runner alone restarts systemd units.
"""
import argparse
import csv
import json
import random
import re
import signal
import socket
import sys
import threading
import time
from pathlib import Path

BENCH_KEY = b"v005-memcached-bench"
BENCH_VALUE = b"V" * 128
RESTART_KEY = b"v005-memcached-restart"
RESTART_VALUE = b"RESTART_VALUE_V005"
PARAMETERS = {
    "service": "memcached", "unit": "slab-memcached-v005.service",
    "user": "labmemcachev005", "host": "127.0.0.1", "port": 11212,
    "memory_mb": 64, "server_threads": 1, "udp_port": 0,
    "protocol": "ascii", "profiles": ["P0", "P1", "P2", "P4", "P6"],
    "restricted_family": 4, "planned_looks": 2, "blocks_per_look": 20,
    "ops": 3000000, "connections": 50, "client_threads": 3,
    "pipeline": 32, "payload_bytes": 128, "warmup_ops": 5000,
    "server_cpu": 0, "client_cpus": "1-3", "stall_ms": 500,
    "elapsed_clock": "CLOCK_MONOTONIC_RAW", "wall_clock_use": "UTC labels only",
    "max_stalled_attempts": 5, "socket_timeout_sec": 10,
    "expiration_sec": 2, "expiration_wait_sec": 3.2,
    "noninferiority_delta": 0.05, "family_level": 0.05,
    "cost_budgets": [2, 5, 10, 15], "required_goals": [], "goals": [],
    "emicro": "36 model probes; calibrated against same-launcher P0",
    "diagnostic_policy": ["s", "emicro", "exposure", "n"],
}


class ProtocolError(ValueError):
    pass


class Connection:
    def __init__(self, host="127.0.0.1", port=11212, timeout=10):
        if host != "127.0.0.1":
            raise ValueError("this experiment only connects to IPv4 loopback")
        self.socket = socket.create_connection((host, port), timeout=timeout)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.stream = self.socket.makefile("rb")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.stream.close()
        self.socket.close()

    def line(self):
        value = self.stream.readline(4097)
        if len(value) > 4096 or not value.endswith(b"\r\n"):
            raise ProtocolError(f"invalid response line: {value[:160]!r}")
        return value

    def version(self):
        self.socket.sendall(b"version\r\n")
        response = self.line()
        if not response.startswith(b"VERSION "):
            raise ProtocolError(f"unexpected version response {response!r}")
        return response[8:-2].decode("ascii")

    def set(self, key, value, expiration=0):
        self.socket.sendall(b"set " + key + b" 0 " + str(expiration).encode() + b" "
                            + str(len(value)).encode() + b"\r\n" + value + b"\r\n")
        response = self.line()
        if response != b"STORED\r\n":
            raise ProtocolError(f"SET did not store: {response!r}")

    def get(self, key):
        self.socket.sendall(b"get " + key + b"\r\n")
        response = self.line()
        if response == b"END\r\n":
            return None
        fields = response[:-2].split()
        if len(fields) != 4 or fields[:3] != [b"VALUE", key, b"0"]:
            raise ProtocolError(f"unexpected GET header: {response!r}")
        size = int(fields[3])
        if not 0 <= size <= 1048576:
            raise ProtocolError("oversized GET value")
        value = self.stream.read(size + 2)
        if len(value) != size + 2 or not value.endswith(b"\r\n") or self.line() != b"END\r\n":
            raise ProtocolError("incomplete GET value or missing END")
        return value[:-2]

    def delete(self, key):
        self.socket.sendall(b"delete " + key + b"\r\n")
        response = self.line()
        if response != b"DELETED\r\n":
            raise ProtocolError(f"DELETE did not delete: {response!r}")


def expect(condition, detail):
    if not condition:
        raise ProtocolError(detail)


def observe(name, action):
    try:
        detail = action()
        return {"check": name, "result": "PASS", "detail": str(detail or "exact response verified")}
    except (OSError, TimeoutError) as error:
        return {"check": name, "result": "ERROR", "detail": str(error)}
    except (ValueError, AssertionError) as error:
        return {"check": name, "result": "FAIL", "detail": str(error)}


def contract_before(host, port, expected_version, sleeper=time.sleep):
    checks = []

    def with_connection(action):
        with Connection(host, port) as connection:
            return action(connection)

    def version(connection):
        actual = connection.version()
        expect(actual == expected_version, f"VERSION {actual!r}, expected {expected_version!r}")
        return "VERSION " + actual

    key, value = b"v005-memcached-contract", b"CONTRACT_VALUE_V005"
    checks.append(observe("version", lambda: with_connection(version)))
    checks.append(observe("set", lambda: with_connection(lambda c: c.set(key, value))))
    checks.append(observe("get", lambda: with_connection(lambda c: expect(c.get(key) == value, "GET payload mismatch"))))

    def delete(connection):
        connection.delete(key)
        expect(connection.get(key) is None, "deleted key remains reachable")
    checks.append(observe("delete", lambda: with_connection(delete)))

    def expiration(connection):
        expiry_key = b"v005-memcached-expiry"
        connection.set(expiry_key, value, expiration=PARAMETERS["expiration_sec"])
        expect(connection.get(expiry_key) == value, "expiring key was not initially present")
        sleeper(PARAMETERS["expiration_wait_sec"])
        expect(connection.get(expiry_key) is None, "key remains after predeclared expiration wait")
        return "TTL=2s; present before wait, absent after 3.2s"
    checks.append(observe("expiration", lambda: with_connection(expiration)))

    def prepare_restart(connection):
        connection.set(RESTART_KEY, RESTART_VALUE)
        expect(connection.get(RESTART_KEY) == RESTART_VALUE, "restart fixture was not present")
    prepared = observe("restart-value-prepared", lambda: with_connection(prepare_restart))
    checks.append(prepared)
    return {"checks": checks, "restart_prepared": prepared["result"] == "PASS"}


def contract_after(host, port, before_file):
    def lost():
        before = json.loads(before_file.read_text(encoding="utf-8"))
        expect(before.get("restart_prepared") is True, "restart value was not verified before restart")
        with Connection(host, port) as connection:
            expect(connection.get(RESTART_KEY) is None, "in-memory value survived restart unexpectedly")
        return "verified present before restart, absent after restart (expected)"
    return {"checks": [observe("restart-loses-value", lost)]}


def seed(host, port):
    with Connection(host, port) as connection:
        connection.set(BENCH_KEY, BENCH_VALUE)
        expect(connection.get(BENCH_KEY) == BENCH_VALUE, "benchmark seed mismatch")
    return {"seed": "PASS", "payload_bytes": len(BENCH_VALUE)}


def recv_exact(connection, count):
    chunks = bytearray()
    while len(chunks) < count:
        chunk = connection.recv(count - len(chunks))
        if not chunk:
            raise ProtocolError("EOF while receiving pipelined responses")
        chunks.extend(chunk)
    return bytes(chunks)


def elapsed_ns():
    # Linux scientific elapsed clock; never silently fall back to a slewed clock.
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)


def run_load(host, port, ops=3000000, connections=50, threads=3, pipeline=32):
    if host != "127.0.0.1" or not (0 < threads <= connections <= ops) or not 1 <= pipeline <= 256:
        raise ValueError("invalid loopback load parameters")
    quotas = [ops // connections + (index < ops % connections) for index in range(connections)]
    request = b"get " + BENCH_KEY + b"\r\n"
    response = b"VALUE " + BENCH_KEY + b" 0 128\r\n" + BENCH_VALUE + b"\r\nEND\r\n"
    results = [None] * threads
    start = [0]
    barrier = threading.Barrier(threads + 1, action=lambda: start.__setitem__(0, elapsed_ns()))
    stop = threading.Event()

    def worker(index):
        sockets, remaining = [], quotas[index::threads]
        completed, error = 0, None
        try:
            for _ in remaining:
                stream = socket.create_connection((host, port), timeout=PARAMETERS["socket_timeout_sec"])
                stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sockets.append(stream)
            barrier.wait(timeout=30)
            while any(remaining) and not stop.is_set():
                batches = [min(pipeline, left) for left in remaining]
                # Send one bounded batch on every active connection before receiving.
                for stream, count in zip(sockets, batches):
                    if count:
                        stream.sendall(request * count)
                for item, (stream, count) in enumerate(zip(sockets, batches)):
                    if count:
                        actual = recv_exact(stream, len(response) * count)
                        expect(actual == response * count, "pipelined GET payload/header/END mismatch")
                        completed += count
                        remaining[item] -= count
        except Exception as failure:
            error = f"{type(failure).__name__}: {failure}"
            stop.set()
            with_exception = barrier.broken
            if not with_exception:
                barrier.abort()
        finally:
            for stream in sockets:
                stream.close()
            results[index] = {"thread": index, "completed": completed, "error": error}

    workers = [threading.Thread(target=worker, args=(index,), daemon=True) for index in range(threads)]
    for worker_thread in workers:
        worker_thread.start()
    try:
        barrier.wait(timeout=30)
    except threading.BrokenBarrierError:
        stop.set()
    for worker_thread in workers:
        worker_thread.join()
    wall_ns = max(1, elapsed_ns() - start[0]) if start[0] else 0
    completed = sum(result["completed"] for result in results)
    errors = [result["error"] for result in results if result["error"]]
    if completed != ops and not errors:
        errors.append(f"only {completed} of {ops} responses verified")
    return {"ops": ops, "completed": completed, "failed": len(errors), "errors": errors,
            "wall_ns_client": wall_ns, "rps_client": completed * 1e9 / wall_ns if wall_ns else 0,
            "connections": connections, "threads": threads, "pipeline": pipeline,
            "payload_bytes": 128, "workers": results}


def heartbeat(path):
    stopping = [False]
    signal.signal(signal.SIGTERM, lambda *_: stopping.__setitem__(0, True))
    longest, last = 0, elapsed_ns()
    while not stopping[0]:
        time.sleep(0.02)
        now = elapsed_ns()
        longest = max(longest, now - last - 20000000)
        last = now
    path.write_text(f"{longest / 1000000:.1f}\n", encoding="ascii")


def validate_probes(directory, profiles):
    expected = {f"{category}-{number}" for category in ("FS", "DEV", "KER", "PROC", "PRIV", "NS", "NET", "ADV") for number in range(1, 5)} | {f"X{number}" for number in range(1, 5)}
    pattern = re.compile(r"^([A-Z]+-\d+|X\d)\s+(ALLOWED|BLOCKED|N/A|ERROR)\b")
    issues, states = [], {}
    for profile in profiles:
        path = directory / f"memcached__{profile}.txt"
        if not path.is_file():
            issues.append(f"{profile}: output missing"); continue
        statuses = {}
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            match = pattern.match(line.strip())
            if match:
                identity, state = match.groups()
                if identity in statuses:
                    issues.append(f"{profile}: duplicate {identity}")
                statuses[identity] = state
        if set(statuses) != expected:
            issues.append(f"{profile}: missing/unexpected probe identities")
        if any(state == "ERROR" for state in statuses.values()):
            issues.append(f"{profile}: ERROR in probe output")
        states[profile] = statuses
    baseline = states.get("P0", {})
    if not any(state == "ALLOWED" for state in baseline.values()):
        issues.append("P0: no allowed probes for baseline calibration")
    for profile, current in states.items():
        if any(current.get(identity) not in ("ALLOWED", "BLOCKED")
               for identity, state in baseline.items() if state == "ALLOWED"):
            issues.append(f"{profile}: missing/non-evaluable baseline-allowed probe")
    return {"failed": len(issues), "issues": issues, "profiles": states, "expected_count": 36}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["parameters", "order", "version", "contract-before", "contract-after", "seed", "load", "heartbeat", "rows", "validate-probes"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=11212)
    parser.add_argument("--expected-version")
    parser.add_argument("--file", type=Path)
    parser.add_argument("--binary")
    parser.add_argument("--seed")
    parser.add_argument("--block", type=int, default=1)
    parser.add_argument("--profiles", nargs="+", default=PARAMETERS["profiles"])
    parser.add_argument("--profile")
    parser.add_argument("--ops", type=int, default=PARAMETERS["ops"])
    parser.add_argument("--connections", type=int, default=PARAMETERS["connections"])
    parser.add_argument("--threads", type=int, default=PARAMETERS["client_threads"])
    parser.add_argument("--pipeline", type=int, default=PARAMETERS["pipeline"])
    args = parser.parse_args()
    if args.host != "127.0.0.1":
        parser.error("only 127.0.0.1 is allowed")
    if args.mode == "heartbeat":
        heartbeat(args.file); return 0
    if args.mode == "parameters":
        result = dict(PARAMETERS, binary=args.binary, expected_version=args.expected_version, randomization_seed=args.seed)
    elif args.mode == "order":
        profiles = list(args.profiles)
        random.Random(f"{args.seed}:{args.block}").shuffle(profiles)
        print("\n".join(profiles)); return 0
    elif args.mode == "version":
        with Connection(args.host, args.port) as connection:
            print(connection.version()); return 0
    elif args.mode == "contract-before":
        result = contract_before(args.host, args.port, args.expected_version)
    elif args.mode == "contract-after":
        result = contract_after(args.host, args.port, args.file)
    elif args.mode == "seed":
        result = seed(args.host, args.port)
    elif args.mode == "load":
        result = run_load(args.host, args.port, args.ops, args.connections, args.threads, args.pipeline)
    elif args.mode == "validate-probes":
        result = validate_probes(args.file, args.profiles)
    elif args.mode == "rows":
        result = json.loads(args.file.read_text(encoding="utf-8"))
        writer = csv.writer(sys.stdout, lineterminator="\n")
        for check in result["checks"]:
            writer.writerow(["memcached", args.profile, check["check"], check["result"], check["detail"], 1])
        return 0
    print(json.dumps(result, sort_keys=True))
    if "checks" in result:
        return int(any(check["result"] != "PASS" for check in result["checks"]))
    return int(bool(result.get("failed", 0)))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({"failed": 1, "error": f"{type(error).__name__}: {error}"}, sort_keys=True))
        sys.exit(2)
