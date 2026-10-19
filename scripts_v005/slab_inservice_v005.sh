#!/bin/sh
# slab_inservice_v005.sh LABEL TARGET_PID -- one probe procedure for every
# context (v005): transient model unit, ExecStartPost= helper of the real
# Nginx unit, and a PostgreSQL backend (COPY ... FROM PROGRAM).
label=$1
target=$2
echo "## BEGIN $label"
echo "## FINGERPRINT"
/usr/local/bin/slab_fp_v005.sh self
echo "## MOUNTS"
/usr/local/bin/slab_fp_v005.sh --mounts self
echo "## ISOLATION"
/usr/bin/python3 /usr/local/bin/isolation_probe.py --context "$label" --target-pid "$target"
echo "ISOLATION_RC=$?"
echo "## EXTENDED"
/usr/bin/python3 /usr/local/bin/extended_probe.py
echo "EXTENDED_RC=$?"
echo "## END $label"
exit 0
