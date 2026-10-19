#!/usr/bin/env bash
set -Eeuo pipefail
HERE=$(dirname "$(readlink -f "$0")")
export SLAB_RESULTS_ROOT=${SLAB_RESULTS_ROOT:-${SLAB_BASE:-/root/systemd-hardening-lab}/results_v005}
. "$HERE/slab_common_v005.sh"
export PIN=1 SERVER_CPU=0 CLIENT_CPUS=1-3 KEEPALIVE=0 STALL_MS=500
export NGINX_N=100000 NGINX_C=25 REDIS_N=3000000 REDIS_THREADS=3 PG_T=60
mkdir -p "$ROOT/driver"
LEDGER="$ROOT/driver/preflight-ledger.csv"
[ ! -e "$LEDGER" ] || { echo 'Preflight already attempted; inspect ledger first'; exit 1; }
echo 'stage,start_guest_utc,end_guest_utc,exit_status' > "$LEDGER"
run_stage() {
    local name=$1 start end rc=0
    shift
    start=$(date -u -Is)
    "$@" > "$ROOT/driver/$name.out" 2>&1 || rc=$?
    end=$(date -u -Is)
    printf '%s,%s,%s,%s\n' "$name" "$start" "$end" "$rc" >> "$LEDGER"
    echo "STAGE=$name RC=$rc END=$end"
    tail -n 12 "$ROOT/driver/$name.out"
    require_rest_state nginx redis postgresql || exit 2
    [ "$rc" != 2 ] || exit 2
    return 0
}
run_stage functional bash "$HERE/functional_ext_v005.sh"
run_stage context env PROFILES='P0 P1 P1r P1c P4' bash "$HERE/context_compare_v005.sh"
run_stage scenarios env REDIS_PROFILES='P0 P1 P2 P1d P4 P6' PG_PROFILES='P0 P1 P2 P1d P4 P6' \
    bash "$HERE/scenarios_v005.sh"
run_stage capabilities env NGINX_PROFILES='P0 P1r P1c P1c+ADMIN P1c+PTRACE P1c+DAC P1c+CHROOT' \
    bash "$HERE/scenarios_v005.sh" nginx
run_stage supplemental bash "$HERE/supplement_goals_v005.sh"
run_stage microprobes env PROBE_PROFILES='P0 P1 P1r P1c P2 P1d P4 P5 P6' \
    bash "$HERE/probe_all_v005.sh"
run_stage pilot-saturation bash "$HERE/benchmark_v005.sh" nginx 10 P4
echo 'PREFLIGHT_FINISHED (pilot validity must be checked before primary series)'
