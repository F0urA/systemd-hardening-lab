#!/usr/bin/env python3
import ctypes
import errno
import os
import platform
import struct

BLOCK_ERRNOS = {errno.EPERM, errno.EACCES}


def classify(name, rv, err, detail_ok):
    if rv >= 0:
        if name != "X4":
            try:
                os.close(rv)
            except OSError:
                pass
        return "ALLOWED", detail_ok(rv)
    if err in BLOCK_ERRNOS:
        return "BLOCKED", f"errno={err} {os.strerror(err)}"
    if err == errno.ENOSYS:
        return "N/A", "syscall not implemented"
    return "ERROR", f"errno={err} {os.strerror(err)}"


def main():
    machine = platform.machine().lower()
    print(f"ARCH={machine} UID={os.getuid()} EUID={os.geteuid()} GID={os.getgid()}")
    print("ID\tSTATUS\tDETAIL")

    if machine not in {"x86_64", "amd64"}:
        for tid in ("X1", "X2", "X3", "X4"):
            print(f"{tid}\tN/A\tunsupported architecture for fixed syscall numbers: {machine}")
        print("SUMMARY ALLOWED=0 BLOCKED=0 N/A=4 ERROR=0")
        return

    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long

    results = []

    # X1: bpf(BPF_MAP_CREATE). Creates one tiny ARRAY map and closes the fd immediately.
    # x86_64: __NR_bpf = 321
    BPF_MAP_CREATE = 0
    BPF_MAP_TYPE_ARRAY = 2
    attr = bytearray(144)
    struct.pack_into("IIIII", attr, 0, BPF_MAP_TYPE_ARRAY, 4, 4, 1, 0)
    buf = (ctypes.c_ubyte * len(attr)).from_buffer(attr)
    ctypes.set_errno(0)
    rv = libc.syscall(321, BPF_MAP_CREATE, ctypes.byref(buf), len(attr))
    err = ctypes.get_errno()
    results.append(("X1",) + classify("X1", rv, err, lambda fd: f"BPF_MAP_CREATE fd={fd}"))

    # X2: userfaultfd with no memory registration.
    # x86_64: __NR_userfaultfd = 323
    flags = os.O_CLOEXEC | os.O_NONBLOCK
    ctypes.set_errno(0)
    rv = libc.syscall(323, flags)
    err = ctypes.get_errno()
    results.append(("X2",) + classify("X2", rv, err, lambda fd: f"userfaultfd fd={fd}"))

    # X3: io_uring_setup(entries=2) with zeroed io_uring_params, then close fd.
    # x86_64: __NR_io_uring_setup = 425
    params = ctypes.create_string_buffer(256)
    ctypes.set_errno(0)
    rv = libc.syscall(425, 2, ctypes.byref(params))
    err = ctypes.get_errno()
    results.append(("X3",) + classify("X3", rv, err, lambda fd: f"io_uring fd={fd}"))

    # X4: join a new anonymous session keyring in this short-lived process.
    # x86_64: __NR_keyctl = 250; KEYCTL_JOIN_SESSION_KEYRING = 1
    KEYCTL_JOIN_SESSION_KEYRING = 1
    ctypes.set_errno(0)
    rv = libc.syscall(250, KEYCTL_JOIN_SESSION_KEYRING, ctypes.c_void_p(0))
    err = ctypes.get_errno()
    if rv >= 0:
        results.append(("X4", "ALLOWED", f"session keyring serial={rv}"))
    elif err in BLOCK_ERRNOS:
        results.append(("X4", "BLOCKED", f"errno={err} {os.strerror(err)}"))
    elif err == errno.ENOSYS:
        results.append(("X4", "N/A", "syscall not implemented"))
    else:
        results.append(("X4", "ERROR", f"errno={err} {os.strerror(err)}"))

    counts = {"ALLOWED": 0, "BLOCKED": 0, "N/A": 0, "ERROR": 0}
    for tid, status, detail in results:
        counts[status] += 1
        print(f"{tid}\t{status}\t{detail}")

    print(
        "SUMMARY "
        f"ALLOWED={counts['ALLOWED']} "
        f"BLOCKED={counts['BLOCKED']} "
        f"N/A={counts['N/A']} "
        f"ERROR={counts['ERROR']}"
    )


if __name__ == "__main__":
    main()
