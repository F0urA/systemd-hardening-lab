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
#   redis       BGSAVE, BGREWRITEAOF, restart keeps value
#   postgresql  CHECKPOINT, reload, restart, query-with-jit
# Redis/PostgreSQL crash recovery remains a descriptive, non-mandatory check.
# After the per-candidate table the Nginx migration check runs
# (protocol_review2_v005.txt, section 5): transitions P0 -> P1c and P1 -> P1c
# after four independent operations: reopen, reload, restart and crash,
# without and with the explicit migration step (return the error log to root).
# NGINX_PROFILES, REDIS_PROFILES and PG_PROFILES list candidates.
# A separate loopback-only slab-nginx-ext unit checks HTTPS and a local HTTP
# upstream under P0 and P1c. Its nginx-tls verdict is separate from the F of
# the original port-808 benchmark configuration.
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
TLS_UNIT=/etc/systemd/system/slab-nginx-ext.service
TLS_UPSTREAM_UNIT=/etc/systemd/system/slab-nginx-ext-upstream.service
TLS_DROPIN_DIR=/etc/systemd/system/slab-nginx-ext.service.d
TLS_CONF_DIR=/etc/systemd-lab/nginx-ext-v005
TLS_DATA_DIR=/var/lib/systemd-lab/nginx-ext-v005
TLS_LOG=/var/log/slab-nginx-ext-v005-error.log
TLS_CREATED=0
mkdir -p "$OUT"
exec > >(tee "$OUT/run.log") 2>&1
echo 'service,profile,check,result,detail,mandatory' > "$CSV"
echo 'service,profile,contract' > "$CONTRACT"

cleanup() {
    local status=$?
    trap - EXIT
    set +e
    echo
    echo '===== CLEANUP AND RESTORE P4 ====='
    tls_cleanup || status=2
    reset_nginx_log cleanup
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
    echo "NGINX_LOG_INITIAL_STATE owner=root mode=0644 phase=${1:-candidate-preparation}"
}

declare -A FAILS=()
record() {  # SERVICE PROFILE CHECK RESULT DETAIL [MANDATORY=1]
    local detail mandatory=${6:-1}
    detail=$(printf '%s' "$5" | tr ',\n\r' ';  ' | cut -c1-200)
    printf '%s,%s,%s,%s,%s,%s\n' "$1" "$2" "$3" "$4" "$detail" "$mandatory" >> "$CSV"
    echo "CHECK service=$1 profile=$2 check=$3 result=$4 mandatory=$mandatory detail=$detail"
    if [ "$mandatory" = 1 ] && [ "$4" != PASS ]; then
        FAILS["$1,$2"]=$(( ${FAILS["$1,$2"]:-0} + 1 ))
    fi
}

verdict() { if [ "$1" -eq 0 ]; then echo PASS; else echo FAIL; fi; }

# crash_recovery SERVICE PROFILE -- SEGV of the main process, then a manual
# restart (the unit has Restart=no) and the health check.
crash_recovery() {
    local svc=$1 p=$2 main rc=0 mandatory=0
    [ "$svc" != nginx ] || mandatory=1
    main=$(systemctl show "$(svc_unit "$svc")" -p MainPID --value 2>/dev/null || true)
    if [[ ! "$main" =~ ^[1-9][0-9]*$ ]] || ! kill -SEGV "$main" 2>/dev/null; then
        record "$svc" "$p" crash-recovery ERROR "no live main process to kill; pid=${main:-missing}" "$mandatory"
        return 0
    fi
    sleep 1
    systemctl restart "$(svc_unit "$svc")" && svc_health "$svc" || rc=1
    record "$svc" "$p" crash-recovery "$(verdict $rc)" "killed_pid=$main" "$mandatory"
}

nginx_checks() {  # PROFILE
    local p=$1 main n code rc
    main=$(systemctl show slab-nginx.service -p MainPID --value 2>/dev/null || true)
    rc=0
    if [[ "$main" =~ ^[1-9][0-9]*$ ]] && kill -USR1 "$main"; then sleep 1; else rc=1; fi
    svc_health nginx && kill -0 "${main:-0}" 2>/dev/null || rc=1
    record nginx "$p" reopen-logs "$(verdict $rc)" "log_owner_after=$(stat -c %U "$NGINX_LOG" 2>/dev/null || echo missing)"
    rc=0; systemctl reload slab-nginx.service && sleep 1 && svc_health nginx || rc=1
    n=$({ pgrep -P "${main:-0}" -u labweb || true; } | wc -l)
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
    rc=0
    r=$(redis-cli -p 6380 SET slab_ext_v005 EXT_VALUE 2>&1) || rc=1
    [ "$r" = OK ] || rc=1
    if [ "$rc" -ne 0 ]; then
        record redis "$p" bgsave ERROR "cannot set contract fixture: $r"
        record redis "$p" bgrewriteaof ERROR 'contract fixture unavailable'
        record redis "$p" restart-keeps-value ERROR 'contract fixture unavailable'
        return 0
    fi
    before=$(redis-cli -p 6380 LASTSAVE 2>/dev/null || true)
    sleep 1
    rc=0; r=$(redis-cli -p 6380 BGSAVE 2>&1) || rc=1
    [[ "$r" == *"Background saving started"* ]] || rc=1
    redis_wait rdb_bgsave_in_progress || rc=1
    after=$(redis-cli -p 6380 LASTSAVE 2>/dev/null || true)
    { [ "$(rinfo rdb_last_bgsave_status)" = ok ] && [[ "$before" =~ ^[0-9]+$ ]] \
        && [[ "$after" =~ ^[0-9]+$ ]] && [ "$after" -gt "$before" ]; } || rc=1
    record redis "$p" bgsave "$(verdict $rc)" "reply=$r status=$(rinfo rdb_last_bgsave_status)"
    rc=0; r=$(redis-cli -p 6380 BGREWRITEAOF 2>&1) || rc=1
    [[ "$r" == *"rewriting started"* || "$r" == *"rewriting scheduled"* ]] || rc=1
    sleep 1
    redis_wait aof_rewrite_in_progress || rc=1
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

# nginx_migration -- each of the 2 x 4 cells begins in an explicitly recorded
# root-owned-log initial state. Only the named operation is then executed,
# followed by transition without the migration step and by the explicit step.
# No ownership reset is inserted between operations of a mandatory contract.
nginx_migration() {
    local from operation main rc owner
    if [ ! -f "$(svc_profiles nginx)/P1c.conf" ]; then
        record nginx P1c migrate-prepare ERROR 'P1c profile is missing'
        return 0
    fi
    for from in P0 P1; do
        for operation in reopen reload restart crash; do
            reset_nginx_log "migration-initial-$from-$operation"
            if ! svc_apply nginx "$from"; then
                record nginx "$from->P1c" "migrate-$operation-prepare" ERROR "$from did not start"
                continue
            fi
            main=$(systemctl show slab-nginx.service -p MainPID --value 2>/dev/null || true)
            rc=0
            case "$operation" in
                reopen)
                    [[ "$main" =~ ^[1-9][0-9]*$ ]] && kill -USR1 "$main" && sleep 1 && svc_health nginx || rc=1 ;;
                reload)
                    systemctl reload slab-nginx.service && sleep 1 && svc_health nginx || rc=1 ;;
                restart)
                    systemctl restart slab-nginx.service && svc_health nginx || rc=1 ;;
                crash)
                    if [[ "$main" =~ ^[1-9][0-9]*$ ]] && kill -SEGV "$main"; then
                        sleep 1
                        if kill -0 "$main" 2>/dev/null; then rc=1; fi
                    else rc=1; fi ;;
            esac
            record nginx "$from->P1c" "migrate-$operation-operation" "$(verdict $rc)" "initial_profile=$from main=$main"
            if [ "$rc" -ne 0 ]; then
                record nginx "$from->P1c" "migrate-$operation-without-step" ERROR 'preceding operation did not complete'
                record nginx "$from->P1c" "migrate-$operation-with-step" ERROR 'preceding operation did not complete'
                continue
            fi
            owner=$(stat -c %U "$NGINX_LOG" 2>/dev/null || echo missing)
            if svc_apply nginx P1c; then rc=0; else rc=1; fi
            record nginx "$from->P1c" "migrate-$operation-without-step" "$([ "$rc" -eq 1 ] && echo BLOCKED || echo STARTED)" \
                "log_owner_after_operation=$owner; BLOCKED means target did not start"
            reset_nginx_log "migration-explicit-step-$from-$operation"
            rc=0; svc_apply nginx P1c && svc_health nginx || rc=1
            record nginx "$from->P1c" "migrate-$operation-with-step" "$(verdict $rc)" 'explicit migration: log owner returned to root'
        done
    done
    reset_nginx_log migration-cleanup
}

# The TLS fixture is independent of the port-808 benchmark unit and uses only
# loopback listeners. Public configuration/certificate and journals are retained
# in OUT; the one-day synthetic TLS private key is removed with the fixture.
tls_cleanup() {
    [ "$TLS_CREATED" = 1 ] || return 0
    local rc=0
    if [ -f "$TLS_UNIT" ]; then systemctl stop slab-nginx-ext.service || rc=1; fi
    if [ -f "$TLS_UPSTREAM_UNIT" ]; then systemctl stop slab-nginx-ext-upstream.service || rc=1; fi
    journalctl -u slab-nginx-ext.service -u slab-nginx-ext-upstream.service --since "$TLS_SINCE" \
        -o short-iso-precise --no-pager > "$OUT/tls-variant/journal.txt" 2>&1 || true
    rm -f -- "$TLS_UNIT" "$TLS_UPSTREAM_UNIT" "$TLS_DROPIN_DIR/90-hardening.conf"
    if [ -d "$TLS_DROPIN_DIR" ]; then rmdir -- "$TLS_DROPIN_DIR" 2>/dev/null || rc=1; fi
    rm -f -- "$TLS_CONF_DIR/nginx.conf" "$TLS_CONF_DIR/cert.pem" "$TLS_CONF_DIR/key.pem" "$TLS_DATA_DIR/index.html"
    if [ -d "$TLS_CONF_DIR" ]; then rmdir -- "$TLS_CONF_DIR" 2>/dev/null || rc=1; fi
    if [ -d "$TLS_DATA_DIR" ]; then rmdir -- "$TLS_DATA_DIR" 2>/dev/null || rc=1; fi
    rm -f -- "$TLS_LOG" /run/slab-nginx-ext-v005.pid
    systemctl daemon-reload || rc=1
    TLS_CREATED=0
    echo "TLS_FIXTURE_CLEANUP=$(verdict "$rc")"
    return "$rc"
}

tls_health() {
    local attempt code
    for attempt in $(seq 1 15); do
        code=$(curl --max-time 3 --cacert "$TLS_CONF_DIR/cert.pem" -sS -o "$OUT/tls-variant/response.txt" \
            -w '%{http_code}' https://127.0.0.1:8443/ 2>/dev/null || true)
        if [ "$code" = 200 ] && cmp -s "$OUT/tls-variant/response.txt" "$TLS_DATA_DIR/index.html"; then return 0; fi
        sleep 1
    done
    return 1
}

tls_error() {
    local profile
    for profile in P0 P1c; do
        record nginx-tls "$profile" tls-setup ERROR "$1"
        echo "nginx-tls,$profile,ERROR" >> "$CONTRACT"
    done
}

nginx_tls_variant() {
    local path tool profile rc main workers sockets
    for tool in openssl curl python3 ss; do
        command -v "$tool" >/dev/null || { tls_error "missing tool $tool"; return 0; }
    done
    for path in "$TLS_UNIT" "$TLS_UPSTREAM_UNIT" "$TLS_DROPIN_DIR" "$TLS_CONF_DIR" "$TLS_DATA_DIR" "$TLS_LOG" /run/slab-nginx-ext-v005.pid; do
        if [ -e "$path" ] || [ -L "$path" ]; then tls_error "fixture path already exists: $path"; return 0; fi
    done
    if ! sockets=$(ss -H -ltn '( sport = :8443 or sport = :18080 )' 2>&1); then
        tls_error "cannot inspect fixture listeners: $sockets"; return 0
    fi
    if [ -n "$sockets" ]; then
        tls_error 'fixture ports 8443/18080 already in use'; return 0
    fi
    if [ ! -f "$(svc_profiles nginx)/P1c.conf" ]; then tls_error 'P1c profile is missing'; return 0; fi
    mkdir -p "$OUT/tls-variant"
    TLS_CREATED=1
    TLS_SINCE="@$(date +%s)"
    mkdir -m 0755 "$TLS_CONF_DIR" "$TLS_DATA_DIR" "$TLS_DROPIN_DIR"
    printf 'V005_TLS_UPSTREAM_OK\n' > "$TLS_DATA_DIR/index.html"
    chmod 0644 "$TLS_DATA_DIR/index.html"
    if ! openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 -subj '/CN=localhost' \
        -addext 'subjectAltName=IP:127.0.0.1,DNS:localhost' \
        -keyout "$TLS_CONF_DIR/key.pem" -out "$TLS_CONF_DIR/cert.pem" > "$OUT/tls-variant/certificate-setup.log" 2>&1; then
        tls_error 'synthetic certificate generation failed'; tls_cleanup; return 0
    fi
    chmod 0600 "$TLS_CONF_DIR/key.pem"
    cat > "$TLS_CONF_DIR/nginx.conf" <<'TLSCONF'
user labweb labweb;
worker_processes 2;
pid /run/slab-nginx-ext-v005.pid;
error_log /var/log/slab-nginx-ext-v005-error.log notice;
events { worker_connections 1024; }
http {
    access_log off;
    server {
        listen 127.0.0.1:8443 ssl;
        server_name localhost;
        ssl_certificate /etc/systemd-lab/nginx-ext-v005/cert.pem;
        ssl_certificate_key /etc/systemd-lab/nginx-ext-v005/key.pem;
        location / { proxy_pass http://127.0.0.1:18080; }
    }
}
TLSCONF
    cat > "$TLS_UNIT" <<'TLSUNIT'
[Unit]
Description=v005 separate Nginx TLS and local upstream functional variant
After=slab-nginx-ext-upstream.service
[Service]
Type=simple
ExecStartPre=/usr/sbin/nginx -t -c /etc/systemd-lab/nginx-ext-v005/nginx.conf
ExecStart=/usr/sbin/nginx -c /etc/systemd-lab/nginx-ext-v005/nginx.conf -g 'daemon off;'
ExecReload=/bin/kill -HUP $MAINPID
KillSignal=SIGQUIT
Restart=no
TLSUNIT
    cat > "$TLS_UPSTREAM_UNIT" <<'UPSTREAMUNIT'
[Unit]
Description=v005 loopback HTTP upstream for the Nginx functional variant
[Service]
Type=simple
User=labweb
Group=labweb
ExecStart=/usr/bin/python3 -m http.server 18080 --bind 127.0.0.1 --directory /var/lib/systemd-lab/nginx-ext-v005
Restart=no
UPSTREAMUNIT
    cp "$TLS_CONF_DIR/nginx.conf" "$TLS_CONF_DIR/cert.pem" "$TLS_UNIT" "$TLS_UPSTREAM_UNIT" "$OUT/tls-variant/"
    systemctl daemon-reload
    if ! systemctl start slab-nginx-ext-upstream.service; then
        tls_error 'upstream did not start'; tls_cleanup; return 0
    fi
    for profile in P0 P1c; do
        echo "===== SEPARATE TLS VARIANT PROFILE=$profile (benchmark port 808 unchanged) ====="
        if [ "$profile" = P0 ]; then rm -f "$TLS_DROPIN_DIR/90-hardening.conf";
        else cp "$(svc_profiles nginx)/$profile.conf" "$TLS_DROPIN_DIR/90-hardening.conf"; fi
        systemctl daemon-reload
        systemctl reset-failed slab-nginx-ext.service 2>/dev/null || true
        rc=0; systemctl restart slab-nginx-ext.service || rc=1
        record nginx-tls "$profile" tls-start "$(verdict "$rc")" 'separate unit; ports TLS=8443 upstream=18080'
        systemctl cat slab-nginx-ext.service --no-pager > "$OUT/tls-variant/unit-$profile.txt"
        rc=0; tls_health || rc=1
        record nginx-tls "$profile" https-proxy-response "$(verdict "$rc")" 'verified synthetic CA and exact upstream payload'
        rc=0; systemctl reload slab-nginx-ext.service && sleep 1 && tls_health || rc=1
        main=$(systemctl show slab-nginx-ext.service -p MainPID --value 2>/dev/null || true)
        workers=$({ pgrep -P "${main:-0}" -u labweb || true; } | wc -l)
        [ "$workers" -eq 2 ] || rc=1
        record nginx-tls "$profile" tls-reload "$(verdict "$rc")" "workers=$workers; HTTPS payload rechecked"
        if [ "${FAILS["nginx-tls,$profile"]:-0}" -eq 0 ]; then echo "nginx-tls,$profile,PASS" >> "$CONTRACT";
        else echo "nginx-tls,$profile,FAIL" >> "$CONTRACT"; fi
    done
    ( cd "$OUT/tls-variant" && sha256sum nginx.conf cert.pem *.service unit-*.txt > sha256.txt )
    tls_cleanup
}

for svc in "${SERVICES[@]}"; do
    case "$svc" in
        nginx) profiles=${NGINX_PROFILES:-P0 P1 P2 P1r P1c P4 P5 P6} ;;
        redis) profiles=${REDIS_PROFILES:-P0 P1 P2 P1d P4 P6} ;;
        postgresql) profiles=${PG_PROFILES:-P0 P1 P2 P1d P4 P6} ;;
    esac
    for profile in $profiles; do
        echo
        echo "===== SERVICE=$svc CANDIDATE=$profile ====="
        if [ "$svc" = nginx ]; then reset_nginx_log "contract-initial-$profile"; fi
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
    if [ "$svc" = nginx ]; then
        echo; echo '===== NGINX MIGRATION TO P1c ====='; nginx_migration
        echo; echo '===== SEPARATE NGINX TLS / LOCAL UPSTREAM VARIANT ====='; nginx_tls_variant
    fi
done

echo
echo '===== SUMMARY: operation x candidate ====='
awk -F, 'NR > 1 { printf "%-11s %-6s %-22s %s\n", $1, $2, $3, $4 }' "$CSV"
echo
echo '===== MANDATORY CONTRACT PER CANDIDATE (FAIL = excluded by the gate) ====='
column -t -s, "$CONTRACT"
( cd "$OUT" && sha256sum functional.csv contract.csv > sha256.txt )
