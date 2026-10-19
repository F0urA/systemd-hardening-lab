#!/usr/bin/env python3
"""Synthetic directory-descriptor scenario, not a production file operation."""
import errno
import os
import sys


def main():
    try:
        if int(os.environ.get("LISTEN_PID", "0")) != os.getpid():
            raise RuntimeError("LISTEN_PID does not identify this process")
        if int(os.environ.get("LISTEN_FDS", "0")) != 1:
            raise RuntimeError("expected one inherited directory descriptor")
        os.fstat(3)
        fd = os.open(".g1-fd-v005", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644, dir_fd=3)
        try:
            os.write(fd, b"G1_REPLACED_DOCUMENT\n")
        finally:
            os.close(fd)
        os.replace(".g1-fd-v005", "document.txt", src_dir_fd=3, dst_dir_fd=3)
        print(f"G_RESULT=ALLOWED via=inherited-directory-fd uid={os.getuid()}")
    except OSError as error:
        status = "BLOCKED" if error.errno in (errno.EACCES, errno.EPERM, errno.EROFS) else "ERROR"
        print(f"G_RESULT={status} via=inherited-directory-fd errno={error.errno} detail={error}")
    except (ValueError, RuntimeError) as error:
        print(f"G_RESULT=ERROR via=inherited-directory-fd detail={error}")


if __name__ == "__main__":
    main()
