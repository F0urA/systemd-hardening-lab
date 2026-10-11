#!/usr/bin/env bash
# benchmark_v003.sh SERVICE [BLOCKS] [PROFILE...] -- randomized paired blocks
# for one service and any set of candidates (v003).
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
#   REDIS_N=100000   REDIS_THREADS=2
#   PG_T=60          postgresql: seconds per measurement
#
# CSV columns are compatible with audit_benchmark_csv_v003.py.
set -Eeuo pipefail
HERE=$(dirname "$(readlink -f "$0")")
. "$HERE/slab_common_v003.sh"
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: run as root'; exit 1; }

svc=${1:?usage: benchmark_v003.sh SERVICE [BLOCKS] [PROFILE...]}
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
REDIS_N=${REDIS_N:-100000}
REDIS_THREADS=${REDIS_THREADS:-2}
PG_T=${PG_T:-60}

UNIT=$(svc_unit "$svc")
AFFINITY="/etc/systemd/system/$UNIT.d/80-affinity-v003.conf"
OUT="$ROOT/$svc/benchmark-v003/$(date +%Y%m%d-%H%M%S)"
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
    set +e
    echo
    echo '===== CLEANUP AND RESTORE P4 ====='
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

{
    date -Is
    grep -E '^(NAME|VERSION|PRETTY_NAME)=' /etc/os-release
    uname -r
    systemctl --version | head -n 1
    nproc
    echo "SERVICE=$svc BLOCKS=$BLOCKS PIN=$PIN SERVER_CPU=$SERVER_CPU CLIENT_CPUS=$CLIENT_CPUS"
    echo "KEEPALIVE=$KEEPALIVE NGINX_N=$NGINX_N REDIS_N=$REDIS_N REDIS_THREADS=$REDIS_THREADS PG_T=$PG_T"
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
    t1=$(date +%s%N)
    client ab ${k[@]+"${k[@]}"} -n "$NGINX_N" -c 25 "$URL" > "$f1" 2>&1 & p1=$!
    client ab ${k[@]+"${k[@]}"} -n "$NGINX_N" -c 25 "$URL" > "$f2" 2>&1 & p2=$!
    wait "$p1"; wait "$p2"
    t2=$(date +%s%N)
    CPU_AFTER=$(systemctl show "$UNIT" -p CPUUsageNSec --value)
    WALL_NS=$((t2 - t1))
    c1=$(awk '/^Complete requests:/ {print $3; exit}' "$f1")
    c2=$(awk '/^Complete requests:/ {print $3; exit}' "$f2")
    FAILED=$(awk '/^Failed requests:/ {s += $3} /^Non-2xx responses:/ {s += $3} END {print s + 0}' "$f1" "$f2")
    [ -n "$c1" ] && [ -n "$c2" ] || { echo "INVALID AB OUTPUT: $f1 $f2"; return 1; }
    OPS=$((c1 + c2))
    THROUGHPUT=$(awk -v o="$OPS" -v w="$WALL_NS" 'BEGIN {printf "%.3f", o / (w / 1e9)}')
}

measure_redis() {  # TAG
    local tag=$1 line t1 t2
    redis-cli -p 6380 SET systemd_bench_key SYSTEMD_BENCH_VALUE >/dev/null
    client redis-benchmark -h 127.0.0.1 -p 6380 -n 5000 -c 50 -q GET systemd_bench_key >/dev/null
    CPU_BEFORE=$(systemctl show "$UNIT" -p CPUUsageNSec --value)
    t1=$(date +%s%N)
    client redis-benchmark -h 127.0.0.1 -p 6380 -n "$REDIS_N" -c 50 --threads "$REDIS_THREADS" \
        -q GET systemd_bench_key > "$OUT/redis-$tag.txt" 2>&1
    t2=$(date +%s%N)
    CPU_AFTER=$(systemctl show "$UNIT" -p CPUUsageNSec --value)
    WALL_NS=$((t2 - t1))
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
    t1=$(date +%s%N)
    client pgbench -h 127.0.0.1 -p 55432 -U labpg -c 10 -j 2 -T "$PG_T" systemd_bench > "$file" 2>&1
    t2=$(date +%s%N)
    CPU_AFTER=$(systemctl show "$UNIT" -p CPUUsageNSec --value)
    WALL_NS=$((t2 - t1))
    THROUGHPUT=$(awk '/tps =/ && /without initial connection time/ {print $3}' "$file")
    OPS=$(awk -F': *' '/number of transactions actually processed/ {print $2}' "$file" | awk '{print $1}')
    [ -n "$THROUGHPUT" ] && [ -n "$OPS" ] || { echo "INVALID PGBENCH OUTPUT: $file"; return 1; }
    FAILED=0
}

echo "block,order,profile,$metric,cpu_pct,cpu_us_per_op,ops,wall_ns,failed" > "$CSV"
echo "BENCHMARK START: $BLOCKS randomized blocks x (${profiles[*]})"
for block in $(seq 1 "$BLOCKS"); do
    order=0
    while IFS= read -r profile; do
        order=$((order + 1))
        echo
        echo "===== BLOCK=$block ORDER=$order PROFILE=$profile ====="
        svc_apply "$svc" "$profile" || { echo "FUNCTIONAL FAILURE: $profile"; exit 1; }
        "measure_$svc" "B${block}-${profile}"
        [ "$FAILED" = 0 ] || { echo "FAILED REQUESTS: $FAILED"; exit 1; }
        CPU_NS=$((CPU_AFTER - CPU_BEFORE))
        if [ "$WALL_NS" -le 0 ] || [ "$CPU_NS" -lt 0 ] || [ "$OPS" -le 0 ]; then
            echo 'ERROR: invalid CPU/wall/ops values'; exit 1
        fi
        CPU_PCT=$(awk -v c="$CPU_NS" -v w="$WALL_NS" 'BEGIN {printf "%.3f", c / w * 100}')
        CPU_US=$(awk -v c="$CPU_NS" -v o="$OPS" 'BEGIN {printf "%.4f", c / o / 1000}')
        printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$block" "$order" "$profile" \
            "$THROUGHPUT" "$CPU_PCT" "$CPU_US" "$OPS" "$WALL_NS" "$FAILED" >> "$CSV"
        echo "${metric^^}=$THROUGHPUT CPU_PCT=$CPU_PCT CPU_US_PER_OP=$CPU_US OPS=$OPS"
    done < <(printf '%s\n' "${profiles[@]}" | shuf)
done

echo
echo '===== BENCHMARK COMPLETE ====='
wc -l "$CSV"
sha256sum "$CSV" | tee "$OUT/sha256-results.txt"
for profile in "${profiles[@]}"; do
    [ "$profile" != P0 ] || continue
    echo
    python3 "$HERE/audit_benchmark_csv_v003.py" "$CSV" --baseline P0 --candidate "$profile" \
        | tee "$OUT/audit-P0-$profile.txt"
done
