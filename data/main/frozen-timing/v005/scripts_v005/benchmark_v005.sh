#!/usr/bin/env bash
# benchmark_v005.sh SERVICE [BLOCKS] [PROFILE...] -- randomized paired blocks
# for one service and any set of candidates (v005).
#
# Stall detector (protocol_load_v005.txt, section 3): two heartbeat
# processes run during every measurement, one on the server CPU and one on the
# generator CPUs. If either sees a pause longer than STALL_MS, the virtual
# machine was not running for that time: the measurement is invalid whatever
# the profile, it is written to invalid.csv and repeated at once.
#
#   SERVICE   nginx | redis | postgresql
#   BLOCKS    default 20 (nginx, redis) or 10 (postgresql)
#   PROFILE   default: P0 P4 P5 P6 (nginx), P0 P4 P6 (redis, postgresql);
#             P0 is always included; non-functional candidates are dropped.
#
# Environment:
#   PIN=1            pin the service to SERVER_CPU and the load generator to
#                    CLIENT_CPUS, so that the server and not the generator is
#                    the bottleneck (same pinning for every profile, incl. P0)
#   SERVER_CPU=0     CLIENT_CPUS=1-3
#   KEEPALIVE=0      nginx: 1 adds "ab -k"
#   NGINX_N=10000    nginx: requests per generator (two generators run)
#   NGINX_C=25       nginx: concurrent connections per generator
#   REDIS_N=100000   REDIS_THREADS=2
#   PG_T=60          postgresql: seconds per measurement
#   STALL_MS=500     longest tolerated pause of the virtual machine, ms
#
# CSV columns are compatible with audit_benchmark_csv_v005.py.
set -Eeuo pipefail
HERE=$(dirname "$(readlink -f "$0")")
. "$HERE/slab_common_v005.sh"
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: run as root'; exit 1; }

svc=${1:?usage: benchmark_v005.sh SERVICE [BLOCKS] [PROFILE...]}
svc_user "$svc" >/dev/null
shift
case "$svc" in
    nginx) default_blocks=20; default_profiles='P0 P4 P5 P6'; metric=rps ;;
    redis) default_blocks=20; default_profiles='P0 P4 P6'; metric=rps ;;
    postgresql) default_blocks=10; default_profiles='P0 P4 P6'; metric=tps ;;
esac
BLOCKS=${1:-$default_blocks}
[ "$#" -eq 0 ] || shift
if [ "$#" -gt 0 ]; then requested="P0 $*"; else requested=$default_profiles; fi

PIN=${PIN:-1}
SERVER_CPU=${SERVER_CPU:-0}
CLIENT_CPUS=${CLIENT_CPUS:-1-3}
KEEPALIVE=${KEEPALIVE:-0}
NGINX_N=${NGINX_N:-10000}
NGINX_C=${NGINX_C:-25}
REDIS_N=${REDIS_N:-100000}
REDIS_THREADS=${REDIS_THREADS:-2}
PG_T=${PG_T:-60}
STALL_MS=${STALL_MS:-500}
[[ "$NGINX_C" =~ ^[1-9][0-9]*$ ]] || { echo 'ERROR: NGINX_C must be a positive integer'; exit 1; }

UNIT=$(svc_unit "$svc")
AFFINITY="/etc/systemd/system/$UNIT.d/80-affinity-v005.conf"
OUT="$ROOT/$svc/benchmark-v005/$(date +%Y%m%d-%H%M%S)"
CSV="$OUT/results.csv"
URL=http://127.0.0.1:808/

case "$svc" in
    nginx) tools='ab curl' ;;
    redis) tools='redis-benchmark redis-cli' ;;
    postgresql) tools='pgbench psql pg_isready' ;;
esac
[ "$PIN" != 1 ] || tools="$tools taskset"
for tool in $tools shuf awk sha256sum; do
    command -v "$tool" >/dev/null || { echo "MISSING TOOL: $tool"; exit 1; }
done
require_rest_state "$svc"
if [ "$svc" = postgresql ]; then
    psql -h 127.0.0.1 -p 55432 -U labpg -d systemd_bench -qAt -c 'SELECT 1' >/dev/null \
        || { echo 'ERROR: database systemd_bench is missing (listing B.9 of the appendix)'; exit 1; }
fi

mkdir -p "$OUT"
exec > >(tee "$OUT/run.log") 2>&1

cleanup() {
    local status=$?
    trap - EXIT
    trap '' INT TERM
    set +e
    echo
    echo '===== CLEANUP AND RESTORE P4 ====='
    # A failed generator must not leave heartbeat processes contaminating a retry.
    for pid in "${LOAD1:-}" "${LOAD2:-}" "${HB1:-}" "${HB2:-}"; do
        [ -z "$pid" ] || kill -TERM "$pid" 2>/dev/null
    done
    for pid in "${LOAD1:-}" "${LOAD2:-}" "${HB1:-}" "${HB2:-}"; do
        [ -z "$pid" ] || wait "$pid" 2>/dev/null
    done
    rm -f "$AFFINITY"
    restore_rest_state "$svc" || status=2
    echo "RESULT_DIR=$OUT"
    echo "CSV=$CSV"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

CLIENT=()
if [ "$PIN" = 1 ]; then
    printf '[Service]\nCPUAffinity=%s\n' "$SERVER_CPU" > "$AFFINITY"
    CLIENT=(taskset -c "$CLIENT_CPUS")
fi
client() { ${CLIENT[@]+"${CLIENT[@]}"} "$@"; }
raw_ns() { python3 -c 'import time; print(time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW))'; }

{
    date -Is
    grep -E '^(NAME|VERSION|PRETTY_NAME)=' /etc/os-release
    uname -r
    systemctl --version | head -n 1
    nproc
    echo "SERVICE=$svc BLOCKS=$BLOCKS PIN=$PIN SERVER_CPU=$SERVER_CPU CLIENT_CPUS=$CLIENT_CPUS"
    echo "KEEPALIVE=$KEEPALIVE NGINX_N=$NGINX_N NGINX_C=$NGINX_C REDIS_N=$REDIS_N REDIS_THREADS=$REDIS_THREADS PG_T=$PG_T STALL_MS=$STALL_MS"
    echo 'ELAPSED_CLOCK=CLOCK_MONOTONIC_RAW (UTC only labels)'
} > "$OUT/platform.txt"
cat "$OUT/platform.txt"

# ---- functional gate: only candidates that work enter the benchmark
profiles=()
echo 'profile,functional' > "$OUT/functional.csv"
for profile in $requested; do
    if [ "$profile" != P0 ] && [ ! -f "$(svc_profiles "$svc")/$profile.conf" ]; then
        echo "SKIP $profile: profile file does not exist"
        continue
    fi
    if svc_apply "$svc" "$profile"; then
        profiles+=("$profile")
        echo "$profile,1" >> "$OUT/functional.csv"
        systemctl cat "$UNIT" --no-pager > "$OUT/unit-$profile.txt"
    else
        echo "DROP $profile: functional gate failed (F=0)"
        echo "$profile,0" >> "$OUT/functional.csv"
    fi
done
[ "${#profiles[@]}" -ge 2 ] || { echo 'ERROR: fewer than two functional candidates'; exit 1; }
echo "CANDIDATES IN THE BENCHMARK: ${profiles[*]}"
for profile in "${profiles[@]}"; do
    [ "$profile" = P0 ] || sha256sum "$(svc_profiles "$svc")/$profile.conf"
done > "$OUT/sha256-profiles.txt"

# ---- one measurement; sets OPS, THROUGHPUT, FAILED
measure_nginx() {  # TAG
    local tag=$1 k=() f1 f2 p1 p2 t1 t2 c1 c2
    [ "$KEEPALIVE" != 1 ] || k=(-k)
    client ab -q ${k[@]+"${k[@]}"} -n 1000 -c 50 "$URL" > "$OUT/warmup-$tag.txt" 2>&1
    f1="$OUT/ab-$tag-g1.txt"; f2="$OUT/ab-$tag-g2.txt"
    CPU_BEFORE=$(systemctl show "$UNIT" -p CPUUsageNSec --value)
    t1=$(raw_ns)
    ${CLIENT[@]+"${CLIENT[@]}"} ab ${k[@]+"${k[@]}"} -n "$NGINX_N" -c "$NGINX_C" "$URL" > "$f1" 2>&1 & p1=$!; LOAD1=$p1
    ${CLIENT[@]+"${CLIENT[@]}"} ab ${k[@]+"${k[@]}"} -n "$NGINX_N" -c "$NGINX_C" "$URL" > "$f2" 2>&1 & p2=$!; LOAD2=$p2
    wait "$p1"; wait "$p2"
    LOAD1=; LOAD2=
    t2=$(raw_ns)
    CPU_AFTER=$(systemctl show "$UNIT" -p CPUUsageNSec --value)
    WALL_NS=$((t2 - t1))
    c1=$(awk '/^Complete requests:/ {print $3; exit}' "$f1")
    c2=$(awk '/^Complete requests:/ {print $3; exit}' "$f2")
    FAILED=$(awk '/^Failed requests:/ {s += $3} /^Non-2xx responses:/ {s += $3} END {print s + 0}' "$f1" "$f2")
    [ -n "$c1" ] && [ -n "$c2" ] || { echo "INVALID AB OUTPUT: $f1 $f2"; return 1; }
    OPS=$((c1 + c2))
    [ "$OPS" -eq $((2 * NGINX_N)) ] || { echo 'ERROR: incomplete AB request count'; return 1; }
    THROUGHPUT=$(awk -v o="$OPS" -v w="$WALL_NS" 'BEGIN {printf "%.3f", o / (w / 1e9)}')
}

measure_redis() {  # TAG
    local tag=$1 line t1 t2
    redis-cli -p 6380 SET systemd_bench_key SYSTEMD_BENCH_VALUE >/dev/null
    client redis-benchmark -h 127.0.0.1 -p 6380 -n 5000 -c 50 -q GET systemd_bench_key >/dev/null
    CPU_BEFORE=$(systemctl show "$UNIT" -p CPUUsageNSec --value)
    t1=$(raw_ns)
    ${CLIENT[@]+"${CLIENT[@]}"} redis-benchmark -h 127.0.0.1 -p 6380 -n "$REDIS_N" -c 50 --threads "$REDIS_THREADS" \
        -q GET systemd_bench_key > "$OUT/redis-$tag.txt" 2>&1 & LOAD1=$!
    wait "$LOAD1"; LOAD1=
    t2=$(raw_ns)
    CPU_AFTER=$(systemctl show "$UNIT" -p CPUUsageNSec --value)
    WALL_NS=$((t2 - t1))
    if tr '\r' '\n' < "$OUT/redis-$tag.txt" | grep -qiE '(^Error:|^ERR |server closed|connection refused)'; then
        echo 'ERROR: redis-benchmark reported request/connection errors'; return 1
    fi
    line=$(tr '\r' '\n' < "$OUT/redis-$tag.txt" | grep 'requests per second' | tail -n 1)
    THROUGHPUT=$(echo "$line" | sed -n 's/.*: \([0-9.]*\) requests per second.*/\1/p')
    [ -n "$THROUGHPUT" ] || { echo "INVALID REDIS-BENCHMARK OUTPUT: $OUT/redis-$tag.txt"; return 1; }
    OPS=$REDIS_N
    FAILED=0
}

measure_postgresql() {  # TAG
    local tag=$1 t1 t2 file
    client pgbench -h 127.0.0.1 -p 55432 -U labpg -c 10 -j 2 -T 5 systemd_bench >/dev/null 2>&1
    file="$OUT/pgbench-$tag.txt"
    CPU_BEFORE=$(systemctl show "$UNIT" -p CPUUsageNSec --value)
    t1=$(raw_ns)
    ${CLIENT[@]+"${CLIENT[@]}"} pgbench -h 127.0.0.1 -p 55432 -U labpg -c 10 -j 2 -T "$PG_T" systemd_bench > "$file" 2>&1 & LOAD1=$!
    wait "$LOAD1"; LOAD1=
    t2=$(raw_ns)
    CPU_AFTER=$(systemctl show "$UNIT" -p CPUUsageNSec --value)
    WALL_NS=$((t2 - t1))
    THROUGHPUT=$(awk '/tps =/ && /without initial connection time/ {print $3}' "$file")
    OPS=$(awk -F': *' '/number of transactions actually processed/ {print $2}' "$file" | awk '{print $1}')
    [ -n "$THROUGHPUT" ] && [ -n "$OPS" ] || { echo "INVALID PGBENCH OUTPUT: $file"; return 1; }
    FAILED=$(awk -F': *' '/number of failed transactions/ {print $2}' "$file" | awk '{print $1}')
    FAILED=${FAILED:-0}
}

hb_start() {
    rm -f "$OUT/hb-server" "$OUT/hb-client"
    taskset -c "$SERVER_CPU" python3 "$HERE/slab_heartbeat_v005.py" "$OUT/hb-server" & HB1=$!
    taskset -c "$CLIENT_CPUS" python3 "$HERE/slab_heartbeat_v005.py" "$OUT/hb-client" & HB2=$!
}
hb_stop() {  # sets GAP_MS to the longest pause seen by either heartbeat
    kill -TERM "$HB1" "$HB2" 2>/dev/null || true
    wait "$HB1" "$HB2" 2>/dev/null || true
    HB1=; HB2=
    GAP_MS=$(cat "$OUT/hb-server" "$OUT/hb-client" 2>/dev/null | sort -n | tail -n 1)
    GAP_MS=${GAP_MS:-0}
}

echo "block,order,profile,$metric,cpu_pct,cpu_us_per_op,ops,wall_ns,failed,max_gap_ms,attempt" > "$CSV"
echo 'block,order,profile,attempt,throughput,max_gap_ms,reason' > "$OUT/invalid.csv"
echo "BENCHMARK START: $BLOCKS randomized blocks x (${profiles[*]})"
for block in $(seq 1 "$BLOCKS"); do
    order=0
    while IFS= read -r profile; do
        order=$((order + 1))
        echo
        echo "===== BLOCK=$block ORDER=$order PROFILE=$profile ====="
        attempt=0
        while :; do
            attempt=$((attempt + 1))
            svc_apply "$svc" "$profile" || { echo "FUNCTIONAL FAILURE: $profile"; exit 1; }
            hb_start
            "measure_$svc" "B${block}-${profile}-a${attempt}"
            hb_stop
            [ "$FAILED" = 0 ] || { echo "FAILED REQUESTS: $FAILED"; exit 1; }
            if awk -v g="$GAP_MS" -v t="$STALL_MS" 'BEGIN { exit !(g <= t) }'; then break; fi
            echo "$block,$order,$profile,$attempt,$THROUGHPUT,$GAP_MS,stall" >> "$OUT/invalid.csv"
            echo "INVALID MEASUREMENT: the virtual machine paused for $GAP_MS ms; repeating"
            [ "$attempt" -lt 5 ] || { echo 'ERROR: five stalled attempts in a row'; exit 1; }
        done
        CPU_NS=$((CPU_AFTER - CPU_BEFORE))
        if [ "$WALL_NS" -le 0 ] || [ "$CPU_NS" -lt 0 ] || [ "$OPS" -le 0 ]; then
            echo 'ERROR: invalid CPU/wall/ops values'; exit 1
        fi
        CPU_PCT=$(awk -v c="$CPU_NS" -v w="$WALL_NS" 'BEGIN {printf "%.3f", c / w * 100}')
        CPU_US=$(awk -v c="$CPU_NS" -v o="$OPS" 'BEGIN {printf "%.4f", c / o / 1000}')
        printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$block" "$order" "$profile" \
            "$THROUGHPUT" "$CPU_PCT" "$CPU_US" "$OPS" "$WALL_NS" "$FAILED" "$GAP_MS" "$attempt" >> "$CSV"
        echo "${metric^^}=$THROUGHPUT CPU_PCT=$CPU_PCT CPU_US_PER_OP=$CPU_US OPS=$OPS MAX_GAP_MS=$GAP_MS ATTEMPT=$attempt"
    done < <(printf '%s\n' "${profiles[@]}" | shuf)
done

echo
echo '===== BENCHMARK COMPLETE ====='
wc -l "$CSV"
echo "INVALID MEASUREMENTS REPEATED: $(($(wc -l < "$OUT/invalid.csv") - 1))"
sha256sum "$CSV" | tee "$OUT/sha256-results.txt"
for profile in "${profiles[@]}"; do
    [ "$profile" != P0 ] || continue
    echo
    python3 "$HERE/audit_benchmark_csv_v005.py" "$CSV" --baseline P0 --candidate "$profile" \
        | tee "$OUT/audit-P0-$profile.txt"
done
