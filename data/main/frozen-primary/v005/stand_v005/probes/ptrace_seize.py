#!/usr/bin/env python3
import ctypes
import os
import sys

PTRACE_SEIZE = 0x4206
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long
pid = int(sys.argv[1])
result = libc.ptrace(PTRACE_SEIZE, pid, None, None)
if result == 0:
    print("PROC1 ALLOWED")
else:
    err = ctypes.get_errno()
    print(f"PROC1 BLOCKED errno={err} ({os.strerror(err)})")
