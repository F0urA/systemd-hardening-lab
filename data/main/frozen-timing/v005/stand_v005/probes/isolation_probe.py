#!/usr/bin/env python3
import argparse
import ctypes
import errno
import json
import mmap
import os
import pwd
import grp
import socket
import stat
import subprocess
import sys
import tempfile

BLOCK_ERRNOS = {errno.EPERM, errno.EACCES, errno.EROFS}
ENOENT_BLOCK_TESTS = {"FS-1", "FS-2", "FS-3", "DEV-1", "DEV-2", "DEV-3", "PROC-3"}

TESTS = [
    ("FS-1", "read /home marker"),
    ("FS-2", "read /root marker"),
    ("FS-3", "read synthetic credential"),
    ("FS-4", "create file under /etc/systemd-lab/write"),
    ("DEV-1", "see /tmp host marker"),
    ("DEV-2", "see /var/tmp host marker"),
    ("DEV-3", "open control device"),
    ("DEV-4", "mknod char 1:3"),
    ("KER-1", "open hostname sysctl for write"),
    ("KER-2", "open sysrq-trigger for write"),
    ("KER-3", "query kernel log buffer size"),
    ("KER-4", "open printk module parameter for write"),
    ("PROC-1", "PTRACE_SEIZE same-UID target"),
    ("PROC-2", "kill(pid, 0) same-UID target"),
    ("PROC-3", "read same-UID target environ"),
    ("PROC-4", "set SCHED_FIFO on self"),
    ("PRIV-1", "setuid(labvictim)"),
    ("PRIV-2", "setgid(labvictim)"),
    ("PRIV-3", "chroot to empty directory"),
    ("PRIV-4", "execute SUID helper and obtain euid=0"),
    ("NS-1", "unshare user namespace"),
    ("NS-2", "unshare network namespace"),
    ("NS-3", "unshare mount namespace"),
    ("NS-4", "open cgroup.procs for write"),
    ("NET-1", "create AF_PACKET raw socket"),
    ("NET-2", "create AF_NETLINK route socket"),
    ("NET-3", "create AF_INET raw ICMP socket"),
    ("NET-4", "create AF_INET6 stream socket"),
    ("ADV-1", "anonymous RWX mmap"),
    ("ADV-2", "mprotect RW -> RX"),
    ("ADV-3", "set ADDR_NO_RANDOMIZE personality"),
    ("ADV-4", "set SUID bit on own /tmp file"),
]
TEST_NAMES = dict(TESTS)

def ok(detail=""):
    return {"status": "ALLOWED", "detail": detail}

def blocked(detail=""):
    return {"status": "BLOCKED", "detail": detail}

def na(detail=""):
    return {"status": "N/A", "detail": detail}

def error(detail=""):
    return {"status": "ERROR", "detail": detail}

def from_oserror(test_id, e):
    if isinstance(e, PermissionError) or e.errno in BLOCK_ERRNOS:
        return blocked(f"errno={e.errno} {e.strerror}")
    if e.errno == errno.ENOENT and test_id in ENOENT_BLOCK_TESTS:
        return blocked(f"errno={e.errno} {e.strerror}")
    if e.errno == errno.EAFNOSUPPORT and test_id.startswith("NET-"):
        return blocked(f"errno={e.errno} {e.strerror}")
    if e.errno == errno.ENOSYS:
        return na(f"errno={e.errno} {e.strerror}")
    return error(f"errno={e.errno} {e.strerror}")

def read_one(path, test_id):
    try:
        with open(path, "rb", buffering=0) as f:
            f.read(1)
        return ok(path)
    except OSError as e:
        return from_oserror(test_id, e)

def open_write_only(path, test_id, optional=False):
    try:
        fd = os.open(path, os.O_WRONLY)
        os.close(fd)
        return ok(path)
    except FileNotFoundError as e:
        return na(f"{path} absent") if optional else from_oserror(test_id, e)
    except OSError as e:
        return from_oserror(test_id, e)

def do_unshare(flag, test_id):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.unshare.argtypes = [ctypes.c_int]
    libc.unshare.restype = ctypes.c_int
    rc = libc.unshare(flag)
    if rc == 0:
        return ok(hex(flag))
    err = ctypes.get_errno()
    return from_oserror(test_id, OSError(err, os.strerror(err)))

def test_one(test_id, context, target_pid):
    try:
        if test_id == "FS-1":
            return read_one("/home/systemd-lab/marker", test_id)

        if test_id == "FS-2":
            return read_one("/root/systemd-lab-marker", test_id)

        if test_id == "FS-3":
            return read_one("/etc/systemd-lab/credential", test_id)

        if test_id == "FS-4":
            try:
                fd, path = tempfile.mkstemp(prefix="probe-", dir="/etc/systemd-lab/write")
                os.close(fd)
                os.unlink(path)
                return ok("create+unlink")
            except OSError as e:
                return from_oserror(test_id, e)

        if test_id == "DEV-1":
            return read_one("/tmp/systemd-lab-marker", test_id)

        if test_id == "DEV-2":
            return read_one("/var/tmp/systemd-lab-marker", test_id)

        if test_id == "DEV-3":
            try:
                fd = os.open("/dev/systemd-lab-null", os.O_RDONLY)
                os.close(fd)
                return ok("/dev/systemd-lab-null")
            except OSError as e:
                return from_oserror(test_id, e)

        if test_id == "DEV-4":
            d = tempfile.mkdtemp(prefix="mknod-", dir="/tmp")
            path = os.path.join(d, "node")
            try:
                os.mknod(path, stat.S_IFCHR | 0o600, os.makedev(1, 3))
                os.unlink(path)
                os.rmdir(d)
                return ok("mknod char 1:3")
            except OSError as e:
                try:
                    if os.path.exists(path):
                        os.unlink(path)
                    os.rmdir(d)
                except OSError:
                    pass
                return from_oserror(test_id, e)

        if test_id == "KER-1":
            return open_write_only("/proc/sys/kernel/hostname", test_id)

        if test_id == "KER-2":
            return open_write_only("/proc/sysrq-trigger", test_id)

        if test_id == "KER-3":
            libc = ctypes.CDLL(None, use_errno=True)
            try:
                fn = libc.klogctl
            except AttributeError:
                return na("klogctl not exported by libc")
            fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
            fn.restype = ctypes.c_int
            rc = fn(10, None, 0)  # SYSLOG_ACTION_SIZE_BUFFER
            if rc >= 0:
                return ok(f"size={rc}")
            err = ctypes.get_errno()
            return from_oserror(test_id, OSError(err, os.strerror(err)))

        if test_id == "KER-4":
            return open_write_only("/sys/module/printk/parameters/time", test_id, optional=True)

        if test_id == "PROC-1":
            if not target_pid:
                return error("target pid missing")
            libc = ctypes.CDLL(None, use_errno=True)
            PTRACE_SEIZE = 0x4206
            libc.ptrace.argtypes = [
                ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p
            ]
            libc.ptrace.restype = ctypes.c_long
            rc = libc.ptrace(PTRACE_SEIZE, int(target_pid), None, None)
            if rc == 0:
                return ok(f"pid={target_pid}")
            err = ctypes.get_errno()
            return from_oserror(test_id, OSError(err, os.strerror(err)))

        if test_id == "PROC-2":
            if not target_pid:
                return error("target pid missing")
            try:
                os.kill(int(target_pid), 0)
                return ok(f"pid={target_pid}")
            except OSError as e:
                return from_oserror(test_id, e)

        if test_id == "PROC-3":
            if not target_pid:
                return error("target pid missing")
            return read_one(f"/proc/{int(target_pid)}/environ", test_id)

        if test_id == "PROC-4":
            try:
                os.sched_setscheduler(0, os.SCHED_FIFO, os.sched_param(1))
                return ok("SCHED_FIFO priority=1")
            except OSError as e:
                return from_oserror(test_id, e)

        if test_id == "PRIV-1":
            victim_uid = pwd.getpwnam("labvictim").pw_uid
            try:
                os.setuid(victim_uid)
                return ok(f"uid={victim_uid}")
            except OSError as e:
                return from_oserror(test_id, e)

        if test_id == "PRIV-2":
            victim_gid = grp.getgrnam("labvictim").gr_gid
            try:
                os.setgid(victim_gid)
                return ok(f"gid={victim_gid}")
            except OSError as e:
                return from_oserror(test_id, e)

        if test_id == "PRIV-3":
            try:
                os.chroot("/var/lib/systemd-lab/empty")
                os.chdir("/")
                return ok("chroot succeeded")
            except OSError as e:
                return from_oserror(test_id, e)

        if test_id == "PRIV-4":
            if os.geteuid() == 0:
                return na("root context already has euid=0")
            try:
                cp = subprocess.run(
                    ["/usr/local/bin/uid-helper"],
                    text=True, capture_output=True, timeout=3, check=False
                )
                text = (cp.stdout + cp.stderr).strip()
                if cp.returncode != 0:
                    return error(f"helper rc={cp.returncode}: {text}")
                if "euid=0" in text:
                    return ok(text)
                return blocked(text or "helper did not obtain euid=0")
            except (OSError, subprocess.TimeoutExpired) as e:
                return error(str(e))

        if test_id == "NS-1":
            return do_unshare(0x10000000, test_id)  # CLONE_NEWUSER

        if test_id == "NS-2":
            return do_unshare(0x40000000, test_id)  # CLONE_NEWNET

        if test_id == "NS-3":
            return do_unshare(0x00020000, test_id)  # CLONE_NEWNS

        if test_id == "NS-4":
            return open_write_only("/sys/fs/cgroup/cgroup.procs", test_id)

        if test_id == "NET-1":
            try:
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
                s.close()
                return ok("AF_PACKET/SOCK_RAW")
            except OSError as e:
                return from_oserror(test_id, e)

        if test_id == "NET-2":
            try:
                s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
                s.close()
                return ok("AF_NETLINK/NETLINK_ROUTE")
            except OSError as e:
                return from_oserror(test_id, e)

        if test_id == "NET-3":
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                s.close()
                return ok("AF_INET/SOCK_RAW/IPPROTO_ICMP")
            except OSError as e:
                return from_oserror(test_id, e)

        if test_id == "NET-4":
            if not socket.has_ipv6:
                return na("Python reports no IPv6 support")
            try:
                s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
                s.close()
                return ok("AF_INET6/SOCK_STREAM")
            except OSError as e:
                return from_oserror(test_id, e)

        if test_id == "ADV-1":
            try:
                mm = mmap.mmap(
                    -1, 4096,
                    prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC
                )
                mm.close()
                return ok("RWX mmap")
            except OSError as e:
                return from_oserror(test_id, e)

        if test_id == "ADV-2":
            mm = None
            try:
                mm = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE)
                c = ctypes.c_char.from_buffer(mm)
                addr = ctypes.addressof(c)
                libc = ctypes.CDLL(None, use_errno=True)
                libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
                libc.mprotect.restype = ctypes.c_int
                rc = libc.mprotect(
                    ctypes.c_void_p(addr),
                    ctypes.c_size_t(4096),
                    mmap.PROT_READ | mmap.PROT_EXEC
                )
                del c
                if rc != 0:
                    err = ctypes.get_errno()
                    mm.close()
                    return from_oserror(test_id, OSError(err, os.strerror(err)))
                mm.close()
                return ok("mprotect RW->RX")
            except OSError as e:
                if mm is not None:
                    try:
                        mm.close()
                    except Exception:
                        pass
                return from_oserror(test_id, e)
            except Exception as e:
                if mm is not None:
                    try:
                        mm.close()
                    except Exception:
                        pass
                return error(str(e))

        if test_id == "ADV-3":
            libc = ctypes.CDLL(None, use_errno=True)
            libc.personality.argtypes = [ctypes.c_ulong]
            libc.personality.restype = ctypes.c_int
            current = libc.personality(0xFFFFFFFF)
            if current == -1:
                err = ctypes.get_errno()
                return from_oserror(test_id, OSError(err, os.strerror(err)))
            ADDR_NO_RANDOMIZE = 0x0040000
            new_value = current | ADDR_NO_RANDOMIZE
            rc = libc.personality(new_value)
            if rc == -1:
                err = ctypes.get_errno()
                return from_oserror(test_id, OSError(err, os.strerror(err)))
            libc.personality(current)
            return ok(f"personality {current:#x}->{new_value:#x}")

        if test_id == "ADV-4":
            fd, path = tempfile.mkstemp(prefix="suid-", dir="/tmp")
            os.close(fd)
            try:
                os.chmod(path, 0o4755)
                mode = stat.S_IMODE(os.stat(path).st_mode)
                os.unlink(path)
                if mode & stat.S_ISUID:
                    return ok(f"mode={mode:o}")
                return blocked(f"SUID bit not retained, mode={mode:o}")
            except OSError as e:
                try:
                    os.unlink(path)
                except OSError:
                    pass
                return from_oserror(test_id, e)

        return error("unknown test id")

    except Exception as e:
        return error(f"{type(e).__name__}: {e}")

def run_child(args):
    result = test_one(args.one, args.context, args.target_pid)
    result["id"] = args.one
    result["name"] = TEST_NAMES[args.one]
    print(json.dumps(result, ensure_ascii=False))
    return 0

def run_all(args):
    counts = {"ALLOWED": 0, "BLOCKED": 0, "N/A": 0, "ERROR": 0}
    results = []

    print(f"CONTEXT={args.context} UID={os.getuid()} EUID={os.geteuid()} "
          f"GID={os.getgid()} TARGET_PID={args.target_pid or '-'}")
    print("ID\tSTATUS\tDETAIL")

    for test_id, name in TESTS:
        cp = subprocess.run(
            [
                sys.executable, os.path.abspath(__file__),
                "--one", test_id,
                "--context", args.context,
                "--target-pid", str(args.target_pid or 0),
            ],
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
        if cp.returncode != 0:
            item = {"id": test_id, "name": name, "status": "ERROR",
                    "detail": f"child rc={cp.returncode}: {cp.stderr.strip()}"}
        else:
            try:
                item = json.loads(cp.stdout.strip().splitlines()[-1])
            except Exception:
                item = {"id": test_id, "name": name, "status": "ERROR",
                        "detail": f"invalid child output: {cp.stdout!r} {cp.stderr!r}"}

        counts[item["status"]] = counts.get(item["status"], 0) + 1
        results.append(item)
        print(f"{test_id}\t{item['status']}\t{item['detail']}")

    print("SUMMARY\t" + " ".join(f"{k}={v}" for k, v in counts.items()))

    if args.json_out:
        payload = {
            "context": args.context,
            "uid": os.getuid(),
            "euid": os.geteuid(),
            "gid": os.getgid(),
            "target_pid": args.target_pid,
            "counts": counts,
            "results": results,
        }
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)

    return 2 if counts["ERROR"] else 0

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--context", required=True)
    ap.add_argument("--target-pid", type=int, default=0)
    ap.add_argument("--json-out")
    ap.add_argument("--one", choices=TEST_NAMES.keys())
    args = ap.parse_args()

    if args.one:
        return run_child(args)
    return run_all(args)

if __name__ == "__main__":
    raise SystemExit(main())
