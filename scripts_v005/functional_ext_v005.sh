#!/usr/bin/env bash
# functional_ext_v005.sh [nginx] [redis] [postgresql] -- extended functional
# check under every candidate (v005). In revision v005 these operations are the
# mandatory functional contract (protocol_review2_v005.txt, section 5): a
# candidate that fails any of them gets CONTRACT=FAIL in the summary and is
# excluded by the gate. The result is still reported as a table
# "operation x candidate"; the per-candidate contract verdict is written to
# contract.csv for build_criteria_v005.py.
# Operations per service:
#   nginx       reload (two workers), reopen-logs (USR1), restart, 404,
#               crash-recovery (SEGV of the master, then restart)
#   redis       BGSAVE, BGREWRITEAOF, restart keeps value, crash-recovery
#   postgresql  CHECKPOINT, reload, restart, query-with-jit, crash-recovery
# After the per-candidate table the Nginx migration check runs
# (protocol_review2_v005.txt, section 5): transitions P0 -> P1c and P1 -> P1c
# after a log reopen, without and with the migration step (return the error
# log to root).
# NGINX_PROFILES lists the Nginx candidates (space separated).
# The live profile is changed during the run and P4 is restored at the end.
#
# Note on the Nginx error log. After "reopen logs" (USR1) a privileged
# Nginx master hands the error log over to the worker user; a master without
# CAP_DAC_OVERRIDE (P1c, P4, P5, P6) then cannot open that file and does not start.
# The script therefore puts the log file back into its initial state (owner
# root) before each Nginx candidate and at the end, so that every candidate
# starts from the same state. The first revision of the script did not do
# this; its run is kept in results as functional-v005/<time>-failed.
set -Eeuo pipefail
HERE=$(dirname "$(readlink -f "$0")")
. "$HERE/slab_common_v005.sh"
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: run as root'; exit 1; }
if [ "$#" -gt 0 ]; then SERVICES=("$@"); else SERVICES=(nginx redis postgresql); fi
for s in "${SERVICES[@]}"; do svc_user "$s" >/dev/null; done
require_rest_state "${SERVICES[@]}"

OUT="$ROOT/functional-v005/$(date +%Y%m%d-%H%M%S)"
CSV="$OUT/functional.csv"
CONTRACT="$OUT/contract.csv"
mkdir -p "$OUT"
exec > >(tee "$OUT/run.log") 2>&1
echo 'service,profile,check,result,detail' > "$CSV"
echo 'service,profile,contract' > "$CONTRACT"

cleanup() {
    local status=$?
    trap - EXIT
    set +e
    echo
    echo '===== CLEANUP AND RESTORE P4 ====='
    reset_nginx_log
    restore_rest_state "${SERVICES[@]}" || status=2
    echo "RESULT_DIR=$OUT"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

NGINX_LOG=/var/log/slab-nginx-error.log
reset_nginx_log() {
    if [ -e "$NGINX_LOG" ]; then chown root:root "$NGINX_LOG"; chmod 0644 "$NGINX_LOG"; fi
}

declare -A FAILS=()
record() {  # SERVICE PROFILE CHECK RESULT DETAIL
    local detail
    detail=$(printf '%s' "$5" | tr ',\n\r' ';  ' | cut -c1-200)
    printf '%s,%s,%s,%s,%s\n' "$1" "$2" "$3" "$4" "$detail" >> "$CSV"
    echo "CHECK service=$1 profile=$2 check=$3 result=$4 detail=$detail"
    [ "$4" = PASS ] || FAILS["$1,$2"]=$(( ${FAILS["$1,$2"]:-0} + 1 ))
}

verdict() { if [ "$1" -eq 0 ]; then echo PASS; else echo FAIL; fi; }

# crash_recovery SERVICE PROFILE -- SEGV of the main process, then a manual
# restart (the unit has Restart=no) and the health check.
crash_recovery() {
    local svc=$1 p=$2 main rc=0
    main=$(systemctl show "$(svc_unit "$svc")" -p MainPID --value)
    [ -n "$main" ] && [ "$main" != 0 ] && kill -SEGV "$main" 2>/dev/null || true
    sleep 1
    systemctl restart "$(svc_unit "$svc")" && svc_health "$svc" || rc=1
    record "$svc" "$p" crash-recovery "$(verdict $rc)" "killed_pid=$main"
}

nginx_checks() {  # PROFILE
    local p=$1 main n code rc
    main=$(systemctl show slab-nginx.service -p MainPID --value)
    kill -USR1 "$main"; sleep 1
    rc=0; svc_health nginx && kill -0 "$main" || rc=1
    record nginx "$p" reopen-logs "$(verdict $rc)" "log_owner_after=$(stat -c %U "$NGINX_LOG")"
    rc=0; systemctl reload slab-nginx.service && sleep 1 && svc_health nginx || rc=1
    n=$(pgrep -P "$main" -u labweb | wc -l)
    [ "$n" -eq 2 ] || rc=1
    record nginx "$p" reload "$(verdict $rc)" "workers=$n"
    code=$(curl --max-time 5 -s -o /dev/null -w '%{http_code}' http://127.0.0.1:808/no-such-file || true)
    rc=0; [ "$code" = 404 ] || rc=1
    record nginx "$p" not-found-404 "$(verdict $rc)" "http=$code"
    rc=0; systemctl restart slab-nginx.service && svc_health nginx || rc=1
    record nginx "$p" restart "$(verdict $rc)" ""
    crash_recovery nginx "$p"
}

rinfo() { redis-cli -p 6380 INFO persistence 2>/dev/null | tr -d '\r' | sed -n "s/^$1://p"; }

redis_wait() {  # FIELD -- waits until the in-progress flag drops to 0
    local i
    for i in $(seq 1 20); do
        [ "$(rinfo "$1")" = 0 ] && return 0
        sleep 0.5
    done
    return 1
}

redis_checks() {  # PROFILE
    local p=$1 before after r rc
    redis-cli -p 6380 SET slab_ext_v005 EXT_VALUE >/dev/null
    before=$(redis-cli -p 6380 LASTSAVE)
    sleep 1
    r=$(redis-cli -p 6380 BGSAVE 2>&1)
    rc=0; redis_wait rdb_bgsave_in_progress || rc=1
    after=$(redis-cli -p 6380 LASTSAVE)
    { [ "$(rinfo rdb_last_bgsave_status)" = ok ] && [ "$after" -gt "$before" ]; } || rc=1
    record redis "$p" bgsave "$(verdict $rc)" "reply=$r status=$(rinfo rdb_last_bgsave_status)"
    r=$(redis-cli -p 6380 BGREWRITEAOF 2>&1)
    sleep 1
    rc=0; redis_wait aof_rewrite_in_progress || rc=1
    [ "$(rinfo aof_last_bgrewrite_status)" = ok ] || rc=1
    record redis "$p" bgrewriteaof "$(verdict $rc)" "reply=$r status=$(rinfo aof_last_bgrewrite_status)"
    rc=0; systemctl restart slab-redis.service && svc_health redis || rc=1
    [ "$(redis-cli -p 6380 GET slab_ext_v005 2>/dev/null)" = EXT_VALUE ] || rc=1
    record redis "$p" restart-keeps-value "$(verdict $rc)" ""
    redis-cli -p 6380 DEL slab_ext_v005 >/dev/null 2>&1 || true
    crash_recovery redis "$p"
}

psqlq() { psql -h 127.0.0.1 -p 55432 -U labpg -d postgres -qAt -v ON_ERROR_STOP=1 "$@" 2>&1; }

pg_checks() {  # PROFILE
    local p=$1 r rc used
    rc=0; r=$(psqlq -c 'CHECKPOINT') || rc=1
    record postgresql "$p" checkpoint "$(verdict $rc)" "$r"
    rc=0; systemctl reload slab-postgresql.service && svc_health postgresql || rc=1
    record postgresql "$p" reload "$(verdict $rc)" ""
    rc=0
    r=$(psqlq -c 'SET jit = on' -c 'SET jit_above_cost = 0' \
        -c 'EXPLAIN (ANALYZE) SELECT sum(g) FROM generate_series(1, 100000) g') || rc=1
    used=no; printf '%s' "$r" | grep -q '^JIT:' && used=yes
    record postgresql "$p" query-with-jit "$(verdict $rc)" "jit_used=$used $(printf '%s' "$r" | grep -iE 'error|fatal' | head -n 1)"
    rc=0; systemctl restart slab-postgresql.service && svc_health postgresql || rc=1
    record postgresql "$p" restart "$(verdict $rc)" ""
    crash_recovery postgresql "$p"
}

# nginx_migration -- transitions to P1c after a log reopen, without and with
# the migration step (protocol_review2_v005.txt, section 5). After USR1 under
# P0/P1 the privileged master hands the error log to labweb; a master without
# CAP_DAC_OVERRIDE (P1c) may then fail to open it on the next start.
nginx_migration() {
    local from main rc owner
    for from in P0 P1; do
        reset_nginx_log
        svc_apply nginx "$from" || { record nginx "$from->P1c" migrate-prepare FAIL "$from did not start"; continue; }
        main=$(systemctl show slab-nginx.service -p MainPID --value)
        kill -USR1 "$main"; sleep 1
        owner=$(stat -c %U "$NGINX_LOG" 2>/dev/null || echo '?')
        # transition without a migration step: P1c is expected to fail to start
        if svc_apply nginx P1c; then rc=0; else rc=1; fi
        record nginx "$from->P1c" migrate-without-step "$([ $rc -eq 1 ] && echo BLOCKED || echo STARTED)" \
            "log_owner_after_reopen=$owner (BLOCKED = P1c did not start, as expected)"
        # migration step: return the error log to root, then P1c must start
        reset_nginx_log
        rc=0; svc_apply nginx P1c && svc_health nginx || rc=1
        record nginx "$from->P1c" migrate-with-step "$(verdict $rc)" "log returned to root before the transition"
    done
    reset_nginx_log
}

for svc in "${SERVICES[@]}"; do
    case "$svc" in
        nginx) profiles=${NGINX_PROFILES:-P0 P1 P2 P1r P1c P4 P5 P6} ;;
        *) profiles='P0 P4 P6' ;;
    esac
    for profile in $profiles; do
        echo
        echo "===== SERVICE=$svc CANDIDATE=$profile ====="
        if [ "$svc" = nginx ]; then reset_nginx_log; fi
        if ! svc_apply "$svc" "$profile"; then
            record "$svc" "$profile" start FAIL 'candidate does not pass the functional gate'
            echo "$svc,$profile,FAIL" >> "$CONTRACT"
            continue
        fi
        record "$svc" "$profile" start PASS ''
        case "$svc" in
            nginx) nginx_checks "$profile" ;;
            redis) redis_checks "$profile" ;;
            postgresql) pg_checks "$profile" ;;
        esac
        if [ "${FAILS["$svc,$profile"]:-0}" -eq 0 ]; then
            echo "$svc,$profile,PASS" >> "$CONTRACT"
        else
            echo "$svc,$profile,FAIL" >> "$CONTRACT"
        fi
    done
    [ "$svc" != nginx ] || { echo; echo '===== NGINX MIGRATION TO P1c ====='; nginx_migration; }
done

echo
echo '===== SUMMARY: operation x candidate ====='
awk -F, 'NR > 1 { printf "%-11s %-6s %-22s %s\n", $1, $2, $3, $4 }' "$CSV"
echo
echo '===== MANDATORY CONTRACT PER CANDIDATE (FAIL = excluded by the gate) ====='
column -t -s, "$CONTRACT"
( cd "$OUT" && sha256sum functional.csv contract.csv > sha256.txt )
