#!/usr/bin/env bash
# syscall_count_v004.sh -- descriptive measurement (protocol_review_v004.txt,
# section 8): how many system calls each service makes per operation and per
# second of its own processor time under the load of the series.
#
# The service runs under P0, pinned as in benchmark_v004.sh. strace attaches
# to every process of the service and counts calls (-c) while a fixed number
# of operations is executed; the processor time is read from the control
# group of the service, as in the series. Tracing slows the service down, so
# only the counts are used, not the throughput.
#
# The live profile is changed during the run and P4 is restored at the end.
set -Eeuo pipefail
HERE=$(dirname "$(readlink -f "$0")")
. "$HERE/slab_common_v004.sh"
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: run as root'; exit 1; }
command -v strace >/dev/null || { echo 'MISSING TOOL: strace (apt-get install strace)'; exit 1; }
require_rest_state nginx redis postgresql

SERVER_CPU=${SERVER_CPU:-0}
CLIENT_CPUS=${CLIENT_CPUS:-1-3}
NGINX_N=${NGINX_N:-20000}
REDIS_N=${REDIS_N:-200000}
PG_N=${PG_N:-2000}
OUT="$ROOT/syscalls-v004/$(date +%Y%m%d-%H%M%S)"
CSV="$OUT/syscalls.csv"
mkdir -p "$OUT"
exec > >(tee "$OUT/run.log") 2>&1
echo 'service,operations,syscalls,syscalls_per_op,cpu_us_per_op_traced,top_calls' > "$CSV"

cleanup() {
    local status=$?
    trap - EXIT
    set +e
    echo
    echo '===== CLEANUP AND RESTORE P4 ====='
    for s in nginx redis postgresql; do rm -f "/etc/systemd/system/$(svc_unit "$s").d/80-affinity-v004.conf"; done
    restore_rest_state nginx redis postgresql || status=2
    echo "RESULT_DIR=$OUT"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

load() {  # SERVICE -- runs the fixed number of operations, prints it
    case "$1" in
        nginx)
            taskset -c "$CLIENT_CPUS" ab -q -n "$NGINX_N" -c 25 http://127.0.0.1:808/ > "$OUT/load-nginx.txt" 2>&1
            awk '/^Complete requests:/ {print $3; exit}' "$OUT/load-nginx.txt" ;;
        redis)
            redis-cli -p 6380 SET systemd_bench_key SYSTEMD_BENCH_VALUE >/dev/null
            taskset -c "$CLIENT_CPUS" redis-benchmark -h 127.0.0.1 -p 6380 -n "$REDIS_N" -c 50 --threads 3 \
                -q GET systemd_bench_key > "$OUT/load-redis.txt" 2>&1
            echo "$REDIS_N" ;;
        postgresql)
            taskset -c "$CLIENT_CPUS" pgbench -h 127.0.0.1 -p 55432 -U labpg -c 10 -j 2 -t $((PG_N / 10)) \
                systemd_bench > "$OUT/load-postgresql.txt" 2>&1
            awk -F': *' '/number of transactions actually processed/ {print $2}' "$OUT/load-postgresql.txt" \
                | awk -F/ '{print $1}' ;;
    esac
}

for svc in nginx redis postgresql; do
    unit=$(svc_unit "$svc")
    echo
    echo "===== SERVICE=$svc ====="
    mkdir -p "/etc/systemd/system/$unit.d"
    printf '[Service]\nCPUAffinity=%s\n' "$SERVER_CPU" > "/etc/systemd/system/$unit.d/80-affinity-v004.conf"
    svc_apply "$svc" P0 || { echo "FUNCTIONAL FAILURE: $svc P0"; exit 1; }
    load "$svc" >/dev/null   # warm-up; for PostgreSQL the backends of the next run are new anyway
    pids=$(tr '\n' ',' < "/sys/fs/cgroup/system.slice/$unit/cgroup.procs" | sed 's/,$//')
    strace -f -c -q -o "$OUT/strace-$svc.txt" -p "$pids" &
    tracer=$!
    sleep 1
    cpu_before=$(systemctl show "$unit" -p CPUUsageNSec --value)
    ops=$(load "$svc")
    cpu_after=$(systemctl show "$unit" -p CPUUsageNSec --value)
    kill -INT "$tracer" 2>/dev/null || true
    wait "$tracer" 2>/dev/null || true
    total=$(awk '$NF == "total" {print $4}' "$OUT/strace-$svc.txt" | tail -n 1)
    top=$(awk 'NR > 2 && $NF != "total" && $1 ~ /^[0-9.]+$/ {print $NF "=" $4}' "$OUT/strace-$svc.txt" \
        | head -n 6 | tr '\n' ' ')
    [ -n "$ops" ] && [ -n "$total" ] || { echo "INVALID OUTPUT for $svc"; exit 1; }
    per_op=$(awk -v t="$total" -v o="$ops" 'BEGIN {printf "%.2f", t / o}')
    cpu_us=$(awk -v c="$((cpu_after - cpu_before))" -v o="$ops" 'BEGIN {printf "%.2f", c / o / 1000}')
    echo "$svc,$ops,$total,$per_op,$cpu_us,$top" >> "$CSV"
    echo "OPERATIONS=$ops SYSCALLS=$total PER_OPERATION=$per_op CPU_US_PER_OP_TRACED=$cpu_us"
    echo "TOP: $top"
    rm -f "/etc/systemd/system/$unit.d/80-affinity-v004.conf"
done

echo
cat "$CSV"
( cd "$OUT" && sha256sum -- *.csv *.txt > sha256.txt )
