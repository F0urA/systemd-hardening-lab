#!/usr/bin/env bash
# ladder_check_v005.sh -- descriptive check for Nginx (v005), run after the
# fixed series: the functional gate and Exposure of the ladder profiles
# P1-P3, and the necessity of each capability returned in P4.
#   P4c1 = P4 without CAP_NET_BIND_SERVICE
#   P4c2 = P4 without CAP_SETUID
#   P4c3 = P4 without CAP_SETGID
# v005 fixes v004, which stopped when no worker process existed (pgrep).
# The live profile is changed during the run and P4 is restored at the end.
set -Eeuo pipefail
HERE=$(dirname "$(readlink -f "$0")")
. "$HERE/slab_common_v003.sh"
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: run as root'; exit 1; }
require_rest_state nginx

DIR=$(svc_profiles nginx)
OUT="$ROOT/ladder-v005/$(date +%Y%m%d-%H%M%S)"
CSV="$OUT/ladder.csv"
LOG=/var/log/slab-nginx-error.log
mkdir -p "$OUT"
exec > >(tee "$OUT/run.log") 2>&1
echo 'profile,functional,exposure,n_directives,workers,reason' > "$CSV"

cleanup() {
    local status=$?
    trap - EXIT
    set +e
    echo
    echo '===== CLEANUP AND RESTORE P4 ====='
    [ -e "$LOG" ] && chown root:root "$LOG"
    restore_rest_state nginx || status=2
    echo "RESULT_DIR=$OUT"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

n=0
for cap in CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID; do
    n=$((n + 1))
    f="$DIR/P4c$n.conf"
    if [ ! -e "$f" ]; then
        sed -E "/^CapabilityBoundingSet=/ s/ ?$cap//; s/^CapabilityBoundingSet= /CapabilityBoundingSet=/" "$DIR/P4.conf" > "$f"
    fi
    echo "P4c$n: $(grep '^CapabilityBoundingSet=' "$f")"
done

for profile in P1 P2 P3 P4 P4c1 P4c2 P4c3; do
    echo
    echo "===== PROFILE=$profile ====="
    [ -e "$LOG" ] && chown root:root "$LOG"
    since=$(date '+%Y-%m-%d %H:%M:%S')
    functional=1
    svc_apply nginx "$profile" || functional=0
    exposure=$(systemd-analyze security slab-nginx.service --no-pager 2>/dev/null \
        | sed -n 's/.*Overall exposure level[^:]*: *\([0-9.]*\).*/\1/p' | tail -n 1)
    dirs=$(grep -Ec '^[A-Za-z].*=' "$DIR/$profile.conf" || true)
    main=$(systemctl show slab-nginx.service -p MainPID --value)
    workers=0
    if [ -n "$main" ] && [ "$main" != 0 ]; then workers=$(pgrep -P "$main" -u labweb | wc -l || true); fi
    reason=
    if [ "$functional" -ne 1 ]; then
        reason=$( { journalctl -u slab-nginx.service --since "$since" -o cat --no-pager 2>/dev/null; \
                    awk -v s="${since//-//}" '$1 " " $2 >= s' "$LOG" 2>/dev/null; } \
                  | grep -E '\[(emerg|alert|crit)\]' | tail -n 1 | sed -E 's/^.*\[(emerg|alert|crit)\] *[0-9#]*:? *//' \
                  | tr ',' ';' | cut -c1-120)
    fi
    echo "$profile,$functional,${exposure:-NA},$dirs,$workers,$reason" >> "$CSV"
    echo "FUNCTIONAL=$functional EXPOSURE=${exposure:-NA} WORKERS=$workers REASON=$reason"
done

echo
echo '===== SUMMARY ====='
column -t -s, "$CSV"
( cd "$OUT" && sha256sum ladder.csv > sha256.txt )
