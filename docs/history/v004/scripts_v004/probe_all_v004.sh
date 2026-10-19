#!/usr/bin/env bash
# probe_all_v004.sh -- the 32 basic and 4 extended micro-probes for P0 and
# every saved profile, all started by one launcher (v004).
# The live services are not touched: every probe runs in a transient unit
# whose properties are read from the saved profile file; P0 uses the same
# launcher with an empty property list (not "su").
# PROBE_PROFILES lists the profiles; a profile without a saved file is skipped.
set -Eeuo pipefail
HERE=$(dirname "$(readlink -f "$0")")
. "$HERE/slab_common_v004.sh"
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: run as root'; exit 1; }
require_files "$PROBE" "$XPROBE" "$FP" "$INSERVICE"
PROBE_PROFILES=${PROBE_PROFILES:-P0 P1 P1r P1c P2 P3 P4 P5 P6}

OUT="$ROOT/probe-v004/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
exec > >(tee "$OUT/run.log") 2>&1

run_context() {  # CONTEXT SERVICE USER
    local ctx=$1 svc=$2 user=$3 dir profile file rc
    dir=$(svc_profiles "$svc")
    for profile in $PROBE_PROFILES; do
        file="$dir/$profile.conf"
        if [ "$profile" = P0 ]; then
            file=P0
        elif [ ! -f "$file" ]; then
            continue
        fi
        echo
        echo "===== CONTEXT=$ctx PROFILE=$profile ====="
        rc=0
        run_transient "$ctx-${profile,,}" "$user" "$file" "$OUT/${ctx}__${profile}.txt" || rc=$?
        echo "TRANSIENT_RC=$rc"
        grep -E '^SUMMARY' "$OUT/${ctx}__${profile}.txt" || echo 'NO SUMMARY LINE -- inspect the file'
    done
}

run_context nginx-worker nginx labweb
run_context nginx-master nginx root
run_context redis redis labredis
run_context postgresql postgresql labpg

echo
echo '===== METRICS ====='
python3 "$HERE/metric_summary_v004.py" "$OUT" | tee "$OUT/metrics.txt"
( cd "$OUT" && sha256sum -- *.txt *.csv > sha256.txt )
echo "RESULT_DIR=$OUT"
