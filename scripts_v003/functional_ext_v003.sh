#!/usr/bin/env bash
# functional_ext_v003.sh [nginx] [redis] [postgresql] -- extended functional
# check under every candidate (v003). The operations are listed in
# protocol_v003.txt, section 7. They do not enter the functional gate F; the
# result is reported as a table "operation x candidate".
# The live profile is changed during the run and P4 is restored at the end.
set -Eeuo pipefail
HERE=$(dirname "$(readlink -f "$0")")
. "$HERE/slab_common_v003.sh"
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: run as root'; exit 1; }
if [ "$#" -gt 0 ]; then SERVICES=("$@"); else SERVICES=(nginx redis postgresql); fi
for s in "${SERVICES[@]}"; do svc_user "$s" >/dev/null; done
require_rest_state "${SERVICES[@]}"

OUT="$ROOT/functional-v003/$(date +%Y%m%d-%H%M%S)"
CSV="$OUT/functional.csv"
mkdir -p "$OUT"
exec > >(tee "$OUT/run.log") 2>&1
echo 'service,profile,check,result,detail' > "$CSV"

cleanup() {
    local status=$?
    trap - EXIT
    set +e
    echo
    echo '===== CLEANUP AND RESTORE P4 ====='
    restore_rest_state "${SERVICES[@]}" || status=2
    echo "RESULT_DIR=$OUT"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

record() {  # SERVICE PROFILE CHECK RESULT DETAIL
    local detail
    detail=$(printf '%s' "$5" | tr ',\n\r' ';  ' | cut -c1-200)
    printf '%s,%s,%s,%s,%s\n' "$1" "$2" "$3" "$4" "$detail" >> "$CSV"
    echo "CHECK service=$1 profile=$2 check=$3 result=$4 detail=$detail"
}

verdict() { if [ "$1" -eq 0 ]; then echo PASS; else echo FAIL; fi; }

nginx_checks() {  # PROFILE
    local p=$1 main n code rc
    main=$(systemctl show slab-nginx.service -p MainPID --value)
    kill -USR1 "$main"; sleep 1
    rc=0; svc_health nginx && kill -0 "$main" || rc=1
    record nginx "$p" reopen-logs "$(verdict $rc)" "master=$main"
    rc=0; systemctl reload slab-nginx.service && sleep 1 && svc_health nginx || rc=1
    n=$(pgrep -P "$main" -u labweb | wc -l)
    [ "$n" -eq 2 ] || rc=1
    record nginx "$p" reload "$(verdict $rc)" "workers=$n"
    code=$(curl --max-time 5 -s -o /dev/null -w '%{http_code}' http://127.0.0.1:808/no-such-file || true)
    rc=0; [ "$code" = 404 ] || rc=1
    record nginx "$p" not-found-404 "$(verdict $rc)" "http=$code"
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
    redis-cli -p 6380 SET slab_ext_v003 EXT_VALUE >/dev/null
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
    [ "$(redis-cli -p 6380 GET slab_ext_v003 2>/dev/null)" = EXT_VALUE ] || rc=1
    record redis "$p" restart-keeps-value "$(verdict $rc)" ""
    redis-cli -p 6380 DEL slab_ext_v003 >/dev/null 2>&1 || true
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
}

for svc in "${SERVICES[@]}"; do
    case "$svc" in
        nginx) profiles='P0 P4 P5 P6' ;;
        *) profiles='P0 P4 P6' ;;
    esac
    for profile in $profiles; do
        echo
        echo "===== SERVICE=$svc CANDIDATE=$profile ====="
        if ! svc_apply "$svc" "$profile"; then
            record "$svc" "$profile" start FAIL 'candidate does not pass the functional gate'
            continue
        fi
        record "$svc" "$profile" start PASS ''
        case "$svc" in
            nginx) nginx_checks "$profile" ;;
            redis) redis_checks "$profile" ;;
            postgresql) pg_checks "$profile" ;;
        esac
    done
done

echo
echo '===== SUMMARY: operation x candidate ====='
awk -F, 'NR > 1 { printf "%-11s %-4s %-20s %s\n", $1, $2, $3, $4 }' "$CSV"
( cd "$OUT" && sha256sum functional.csv > sha256.txt )
