#!/bin/sh
# slab_fp_v004.sh -- context fingerprint of a process (v004).
#   slab_fp_v004.sh [PID|self]            credentials, capabilities, seccomp, namespaces
#   slab_fp_v004.sh --mounts [PID|self]   normalized mount table
# The same program is used for the real service process (by PID, from the
# host) and inside every model process (self), so the outputs are comparable
# line by line.
mode=fp
if [ "${1:-}" = --mounts ]; then mode=mounts; shift; fi
p=${1:-self}

if [ "$mode" = fp ]; then
    grep -E '^(Uid|Gid|Groups|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp|Seccomp_filters):' \
        "/proc/$p/status" | tr '\t' ' ' | sed -e 's/  */ /g' -e 's/ $//'
    for n in cgroup ipc mnt net pid user uts; do
        printf 'ns_%s: %s\n' "$n" "$(readlink "/proc/$p/ns/$n" 2>/dev/null || echo unreadable)"
    done
else
    # root, mount point, per-mount options, filesystem type; mount IDs,
    # propagation groups and private-tmp directory names are dropped.
    awk '{ i = 7; while (i <= NF && $i != "-") i++; print $4, $5, $6, $(i + 1) }' \
        "/proc/$p/mountinfo" \
        | sed -E 's#systemd-private-[0-9a-f]+-[^/ ]+#systemd-private-X#g' \
        | LC_ALL=C sort
fi
