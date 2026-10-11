#!/usr/bin/env python3
"""slab_dropuser_v004.py USER CMD [ARG...]

Drop from root to a service user the way a daemon does (initgroups, setgid,
setuid) and exec CMD. Used to obtain a worker-equivalent process inside the
sandbox of the real unit and to model a root process that changes identity.
"""
import os
import pwd
import sys


def main():
    if len(sys.argv) < 3:
        print("usage: slab_dropuser_v004.py USER CMD [ARG...]", file=sys.stderr)
        return 64
    pw = pwd.getpwnam(sys.argv[1])
    try:
        os.initgroups(pw.pw_name, pw.pw_gid)
        os.setgid(pw.pw_gid)
        os.setuid(pw.pw_uid)
    except OSError as e:
        print(f"DROPUSER_FAILED errno={e.errno} {e.strerror}")
        return 77
    os.execv(sys.argv[2], sys.argv[2:])


if __name__ == "__main__":
    raise SystemExit(main())
