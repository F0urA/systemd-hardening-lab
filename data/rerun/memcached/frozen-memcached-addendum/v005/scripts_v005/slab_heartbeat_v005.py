#!/usr/bin/env python3
"""slab_heartbeat_v005.py OUTFILE

Stall detector for the load series. Sleeps in 20 ms steps and remembers the
longest overshoot; on SIGTERM writes it to OUTFILE in milliseconds. A stall of
the whole virtual machine (or of the virtual CPU the detector is pinned to)
shows up as one long overshoot, independently of the profile being measured.
"""
import signal
import sys
import time

STEP = 0.02
stop = False


def on_term(*_):
    global stop
    stop = True


signal.signal(signal.SIGTERM, on_term)
gap = 0.0
last = time.clock_gettime(time.CLOCK_MONOTONIC_RAW)
while not stop:
    time.sleep(STEP)
    now = time.clock_gettime(time.CLOCK_MONOTONIC_RAW)
    gap = max(gap, now - last - STEP)
    last = now
with open(sys.argv[1], "w") as f:
    f.write(f"{gap * 1000:.1f}\n")
