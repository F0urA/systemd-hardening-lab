#!/usr/bin/env bash
# Exactly one predeclared continuation per unresolved primary series.
set -Eeuo pipefail
BASE=/root/article-experiment/20261012-v005
HERE="$BASE/frozen-timing/v005/scripts_v005"
export SLAB_RESULTS_ROOT="$BASE/results_v005"
. "$HERE/slab_common_v005.sh"
PLAN=${1:?first-look extension-plan.json required}
PLAN=$(readlink -f "$PLAN")
ANALYZER=${SLAB_ANALYZER:-$BASE/post-analysis/analyze_v005.py}
ANALYZER=$(readlink -f "$ANALYZER")
[[ "$PLAN" == "$BASE/"* ]] && [ -f "$PLAN" ] || exit 1
[[ "$ANALYZER" == "$BASE/"* ]] && [ -f "$ANALYZER" ] || exit 1
[ -f "$ROOT/driver/primary-corrected-finished.txt" ] || { echo 'Primary series have not finished'; exit 1; }
[ ! -e "$ROOT/driver/extension-ledger.csv" ] || { echo 'Extension already attempted'; exit 1; }
[ ! -e "$ROOT/driver/extensions-finished.txt" ] || { echo 'Extension queue already closed'; exit 1; }
require_rest_state nginx redis postgresql
# Atomic claim: even concurrent controllers cannot start a second planned look.
mkdir "$ROOT/driver/extension-claim-v005" || { echo 'Extension queue already claimed'; exit 1; }
status=2
trap 'printf "%s\n" "$status" > "$ROOT/driver/extension-driver-exit.txt"' EXIT
export PIN=1 SERVER_CPU=0 CLIENT_CPUS=1-3 KEEPALIVE=0 STALL_MS=500
export NGINX_N=100000 REDIS_N=3000000 REDIS_THREADS=3 PG_T=60
for artifact in extension-plan.json extension-plan-sha256.txt extension-plan.tsv; do
    [ ! -e "$ROOT/driver/$artifact" ] || { echo "REFUSE OVERWRITE: $artifact"; exit 2; }
done
python3 "$ANALYZER" --validate-extension-plan "$PLAN" \
    --emit-plan-tsv "$ROOT/driver/extension-plan.tsv" \
    > "$ROOT/driver/extension-plan-validation.txt" 2>&1
cp "$PLAN" "$ROOT/driver/extension-plan.json"
sha256sum "$PLAN" "$0" "$ANALYZER" > "$ROOT/driver/extension-plan-sha256.txt"
echo 'stage,start_guest_utc,end_guest_utc,exit_status,result_directory' > "$ROOT/driver/extension-ledger.csv"
overall=0
run_attempt() {
    local stage=$1 svc=$2 blocks=$3 start rc=0 directory
    shift 3
    start=$(date -u -Is)
    bash "$HERE/benchmark_v005.sh" "$svc" "$blocks" "$@" \
        > "$ROOT/driver/$stage.out" 2>&1 || rc=$?
    directory=$(sed -n 's/^RESULT_DIR=//p' "$ROOT/driver/$stage.out" | tail -n 1)
    if [ "$rc" = 0 ]; then
        python3 "$ANALYZER" --validate-extension-plan "$PLAN" \
            --validate-extension-result "${stage%-extension*}" --result-directory "$directory" \
            > "$ROOT/driver/$stage-validation.txt" 2>&1 || rc=2
    fi
    printf '%s,%s,%s,%s,%s\n' "$stage" "$start" "$(date -u -Is)" "$rc" "$directory" \
        >> "$ROOT/driver/extension-ledger.csv"
    echo "STAGE=$stage RC=$rc RESULT_DIR=$directory"
    # A broken rest state is an unfinished queue, not evidence of a completed look.
    require_rest_state nginx redis postgresql
    ATTEMPT_RC=$rc
}
while IFS=$'\t' read -r name svc blocks concurrency profiles; do
    export NGINX_C=$concurrency
    read -r -a candidates <<< "$profiles"
    run_attempt "$name-extension" "$svc" "$blocks" "${candidates[@]}"
    if [ "$ATTEMPT_RC" != 0 ]; then
        run_attempt "$name-extension-retry" "$svc" "$blocks" "${candidates[@]}"
    fi
    # Continue other preplanned stages after terminal technical failure, never
    # inspect a partial series or authorize another statistical continuation.
    [ "$ATTEMPT_RC" = 0 ] || overall=2
done < "$ROOT/driver/extension-plan.tsv"
date -u -Is > "$ROOT/driver/extensions-finished.txt"
echo 'EXTENSIONS_FINISHED: no third statistical look is permitted'
status=$overall
exit "$overall"
