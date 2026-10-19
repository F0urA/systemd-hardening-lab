#!/usr/bin/env bash
# run_stage3.sh -- the whole stage-3 queue on a NEW stand, in the order and
# with the parameters of the executed run (data/main/protocol/RUN_PROTOCOL.md and
# its addenda). Written after the experiment, from the
# executed drivers: driver_preflight_v005.sh, driver_primary_resume_v005.sh,
# driver_post_primary_resume_v005.sh and driver_extensions_v005.sh. The drivers
# of the first primary run (driver_primary_v005.sh, driver_primary_corrected_v005.sh)
# are lost, only their SHA256 survive; their part (pilot, R1, R2, R3) is restored
# here from the protocol. The published data were NOT obtained with this script.
#
# Departures from the executed run, all forced by what that run revealed:
#   - one saturation pilot with the timing-corrected scripts instead of two;
#   - goals are measured once, with the diagnostic edition of scenarios_v005.sh
#     (GOAL_DIAGNOSTIC_ADDENDUM.md); the capability ablation is measured once,
#     with the corrected profile names (CAPABILITY_NAMES_ADDENDUM.md);
#   - port 55432 is reserved for every PostgreSQL series, not only the R3 retry
#     (RESUME_EXECUTION_ADDENDUM.md);
#   - memcached may come with dependencies and need not be 1.6.42-alt1 if
#     SLAB_ACCEPT_OTHER_MEMCACHED=1; the version is recorded either way.
#
# Usage, as root on the VM, after deploy_stage3.sh:
#   bash $SLAB_BASE/run_stage3.sh stand       # build the stand from scratch
#   bash $SLAB_BASE/run_stage3.sh preflight   # contract, goals, probes (about 20 min)
#   bash $SLAB_BASE/run_stage3.sh primary     # pilot, R1 R2 R3 R5, R4 (about 8 h)
#   bash $SLAB_BASE/run_stage3.sh post        # analysis, extension, CAP, mounts, memcached
#   bash $SLAB_BASE/run_stage3.sh seal        # SHA256 manifest and one archive of results_v005
#   bash $SLAB_BASE/run_stage3.sh all         # preflight + primary + post + seal
# Every phase runs once: a repeated start is refused, results are never overwritten.
set -Eeuo pipefail
export LC_ALL=C TZ=UTC
BASE=$(readlink -m "${SLAB_BASE:-/root/systemd-hardening-lab}")
export SLAB_BASE=$BASE
HERE="$BASE/frozen-timing/v005/scripts_v005"
ANALYSIS="$BASE/post-analysis"
MOUNT="$BASE/frozen-mount-states/scripts_v005"
export SLAB_RESULTS_ROOT="$BASE/results_v005"
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: run as root on the laboratory VM'; exit 1; }
[ -f "$HERE/slab_common_v005.sh" ] || { echo "ERROR: $BASE is not deployed (deploy_stage3.sh)"; exit 1; }
. "$HERE/slab_common_v005.sh"
DRIVER="$ROOT/driver"
mkdir -p "$DRIVER"
PHASE=${1:?usage: run_stage3.sh stand|preflight|primary|post|seal|all}
# Fixed load parameters of RUN_PROTOCOL.md; NGINX_C changes only for R4.
export PIN=1 SERVER_CPU=0 CLIENT_CPUS=1-3 KEEPALIVE=0 STALL_MS=500
export NGINX_N=100000 NGINX_C=25 REDIS_N=3000000 REDIS_THREADS=3 PG_T=60

rest() { require_rest_state nginx redis postgresql; }

claim() {  # PHASE: refuse a second start of the same phase
    ( set -o noclobber; date -u -Is > "$DRIVER/$1-started.txt" ) 2>/dev/null || {
        echo "Phase $1 was already started ($DRIVER/$1-started.txt); results are not overwritten"; exit 2;
    }
}

clock_check() {  # the executed run started its queue only with a synchronized clock
    chronyc tracking > "$DRIVER/$1-clock.txt" 2>&1 || true
    date -u -Is >> "$DRIVER/$1-clock.txt"
    [ "${SLAB_SKIP_CLOCK_CHECK:-0}" = 1 ] && { echo 'CLOCK CHECK SKIPPED' >> "$DRIVER/$1-clock.txt"; return 0; }
    python3 - "$DRIVER/$1-clock.txt" <<'CLOCK_PY'
import re, sys
text = open(sys.argv[1]).read()
offset = re.search(r'System time\s*:\s*([0-9.]+)\s+seconds', text)
if not offset or float(offset[1]) > 0.05:
    raise SystemExit('Clock is not synchronized (chronyc System time > 0.05 s); '
                     'fix it outside the load or set SLAB_SKIP_CLOCK_CHECK=1 and report it')
CLOCK_PY
}

# ---------------------------------------------------------------- port 55432
RESERVED=${SLAB_RESERVED_PORTS_FILE:-/proc/sys/net/ipv4/ip_local_reserved_ports}  # override: offline test only
PG_PORT_HELD=0
reserve_pg_port() {  # keep the client port allocator away from the PostgreSQL port
    local current
    current=$(tr -d '[:space:]' < "$RESERVED")
    [ -z "$current" ] || { echo "Reserved ports are not empty ($current); not overwritten"; return 2; }
    echo 55432 > "$RESERVED"
    [ "$(tr -d '[:space:]' < "$RESERVED")" = 55432 ] || return 2
    PG_PORT_HELD=1
    printf '%s RESERVED 55432 %s\n' "$(date -u -Is)" "$1" >> "$DRIVER/pg-port-reservation.txt"
}
release_pg_port() {
    [ "$PG_PORT_HELD" = 1 ] || return 0
    [ "$(tr -d '[:space:]' < "$RESERVED")" = 55432 ] || {
        echo 'Reserved ports were changed by someone else; not overwritten'; return 2;
    }
    echo > "$RESERVED"
    PG_PORT_HELD=0
    printf '%s RELEASED 55432 %s\n' "$(date -u -Is)" "$1" >> "$DRIVER/pg-port-reservation.txt"
}
trap 'rc=$?; release_pg_port EXIT || rc=2; exit $rc' EXIT

# ---------------------------------------------------------------- stand
phase_stand() {
    claim stand
    bash "$HERE/setup_stand_v005.sh"
    # prepare_existing_v005.sh was written for the stand of stages 1-2: it records
    # strace -V (strace 6.19-alt1 was on the executed stand) and lists the old
    # /root/systemd-lab-results; on a new stand both are provided here.
    apt-get install -y strace
    command -v openssl >/dev/null || { echo 'MISSING TOOL: openssl (TLS check of functional_ext_v005.sh)'; exit 2; }
    mkdir -p /root/systemd-lab-results
    bash "$HERE/prepare_existing_v005.sh"
    # The executed profiles are stand_v005/profiles byte for byte
    # (data/main/raw-vm/initial-state/profile-sha256.txt); generators never overwrite.
    local s f bad=0
    for s in nginx redis postgresql; do
        for f in "$HERE/../stand_v005/profiles/$s"/*.conf; do
            cmp -s "$f" "$(svc_profiles "$s")/$(basename "$f")" || { echo "PROFILE DIFFERS: $s/$(basename "$f")"; bad=1; }
        done
    done
    # memcached_stage3_v005.sh refuses helpers that differ from these sources;
    # in the executed run that stopped memcached (driver/post-memcached-register.out).
    for f in "$HERE/slab_fp_v005.sh" "$HERE/slab_inservice_v005.sh" "$HERE/../stand_v005/probes/isolation_probe.py" \
             "$HERE/../stand_v005/probes/extended_probe.py" "$HERE/../stand_v005/probes/ptrace_seize.py"; do
        cmp -s "$f" "/usr/local/bin/$(basename "$f")" || { echo "HELPER DIFFERS: /usr/local/bin/$(basename "$f")"; bad=1; }
    done
    {
        echo 'executed: ALT Server 11.1, Linux 6.12.74-6.12-alt1, systemd 257.9-alt1, nginx 1.30.4,'
        echo '          Redis 8.6.5, PostgreSQL 14.24, Python 3.12.7, strace 6.19-alt1'
        echo "this stand: $(. /etc/os-release; echo "$PRETTY_NAME"), Linux $(uname -r)"
        systemctl --version | head -n 1
        nginx -v 2>&1; redis-server -v; postgres -V; python3 -V; strace -V | head -n 1
    } | tee "$DRIVER/versions-vs-executed.txt"
    rest
    [ "$bad" = 0 ] || { echo 'STAND DIFFERS FROM THE EXECUTED ONE: inspect before measuring'; exit 2; }
    echo 'STAND_READY'
}

# ---------------------------------------------------------------- preflight
phase_preflight() {
    claim preflight
    rest
    clock_check preflight
    local ledger="$DRIVER/preflight-ledger.csv"
    echo 'stage,start_guest_utc,end_guest_utc,exit_status' > "$ledger"
    pre_stage() {
        local name=$1 start end rc=0
        shift
        start=$(date -u -Is)
        ( set -o noclobber; "$@" > "$DRIVER/$name.out" 2>&1 ) || rc=$?
        end=$(date -u -Is)
        printf '%s,%s,%s,%s\n' "$name" "$start" "$end" "$rc" >> "$ledger"
        echo "STAGE=$name RC=$rc END=$end"
        tail -n 12 "$DRIVER/$name.out"
        rest || exit 2
        [ "$rc" != 2 ] || exit 2
    }
    pre_stage functional bash "$HERE/functional_ext_v005.sh"
    pre_stage context env PROFILES='P0 P1 P1r P1c P4' bash "$HERE/context_compare_v005.sh"
    # analyze_v005.py takes the goals from driver/scenarios-diagnostic.out.
    pre_stage scenarios-diagnostic env REDIS_PROFILES='P0 P1 P2 P1d P4 P6' PG_PROFILES='P0 P1 P2 P1d P4 P6' \
        bash "$HERE/scenarios_v005.sh"
    pre_stage supplemental bash "$HERE/supplement_goals_v005.sh"
    pre_stage microprobes env PROBE_PROFILES='P0 P1 P1r P1c P2 P1d P4 P5 P6' bash "$HERE/probe_all_v005.sh"
    date -u -Is > "$DRIVER/preflight-finished.txt"
    echo 'PREFLIGHT_FINISHED'
}

# ---------------------------------------------------------------- primary
LEDGER="$DRIVER/primary-corrected-ledger.csv"   # the name analyze_v005.py reads
fresh_result_timestamp() {
    local svc=$1 i
    for i in 1 2 3 4 5; do
        [ -e "$ROOT/$svc/benchmark-v005/$(date +%Y%m%d-%H%M%S)" ] || return 0
        sleep 1
    done
    echo 'No fresh output timestamp; stop'; exit 2
}
run_attempt() {  # NAME SERVICE BLOCKS PROFILES...
    local name=$1 svc=$2 blocks=$3 start rc=0 output logfile="$DRIVER/primary-$1.out"
    shift 3
    [ ! -e "$logfile" ] || { echo "Attempt already made: $name"; exit 2; }
    fresh_result_timestamp "$svc"
    start=$(date -u -Is)
    ( set -o noclobber; bash "$HERE/benchmark_v005.sh" "$svc" "$blocks" "$@" > "$logfile" 2>&1 ) || rc=$?
    output=$(sed -n 's/^RESULT_DIR=//p' "$logfile" | tail -n 1)
    printf '%s,%s,%s,%s,%s\n' "$name" "$start" "$(date -u -Is)" "$rc" "$output" >> "$LEDGER"
    echo "STAGE=$name RC=$rc RESULT_DIR=$output"
    rest || exit 2
    LAST_STAGE_RC=$rc
    LAST_STAGE_DIRECTORY=$output
}
run_stage() {  # one complete technical repeat of a failed series, never more
    local name=$1
    shift
    run_attempt "$name" "$@"
    if [ "$LAST_STAGE_RC" != 0 ]; then run_attempt "$name-retry" "$@"; fi
}

phase_primary() {
    [ -f "$DRIVER/preflight-finished.txt" ] || { echo 'Preflight has not finished'; exit 2; }
    claim primary
    rest
    clock_check primary
    sha256sum "$0" "$HERE/benchmark_v005.sh" "$HERE/slab_common_v005.sh" "$HERE/slab_heartbeat_v005.py" \
        "$BASE/inspect_series_v005.py" > "$DRIVER/primary-source-sha256.txt"

    # Pilot (RUN_PROTOCOL.md): 10 paired blocks P0/P4; series only if CV(P0) <= 5 %.
    local pilot rc=0
    ( set -o noclobber; bash "$HERE/benchmark_v005.sh" nginx 10 P4 > "$DRIVER/pilot.out" 2>&1 ) || rc=$?
    rest || exit 2
    pilot=$(sed -n 's/^RESULT_DIR=//p' "$DRIVER/pilot.out" | tail -n 1)
    [ "$rc" = 0 ] && [ -n "$pilot" ] || { echo "PILOT FAILED (rc=$rc); see driver/pilot.out"; exit 2; }
    python3 "$BASE/inspect_series_v005.py" "$pilot" --expect-blocks 10 --expect-profiles P0,P4 --pilot \
        > "$DRIVER/pilot-verification.json" || {
            echo 'PILOT CONDITION NOT MET: CV(P0) > 5 % or invalid blocks; the series are not started'; exit 2;
        }
    echo "PILOT_OK $pilot"

    echo 'stage,start_guest_utc,end_guest_utc,exit_status,result_directory' > "$LEDGER"
    run_stage R1-nginx nginx 60 P1c P4 P5 P6
    run_stage R2-redis redis 20 P1 P2 P1d P4 P6
    reserve_pg_port R3 || exit 2
    run_stage R3-postgresql postgresql 10 P1 P2 P1d P4 P6
    release_pg_port R3 || exit 2
    run_stage R5-nginx-light nginx 60 P1 P2 P1r

    # R4: the first C with CPU(P0) 40-70 % in all three pilot blocks, else FAILED.
    local chosen='' concurrency entry
    for concurrency in 1 2 4 8 16; do
        export NGINX_C=$concurrency
        run_stage "R4-pilot-c$concurrency" nginx 3 P4
        [ "$LAST_STAGE_RC" = 0 ] && [ -n "$LAST_STAGE_DIRECTORY" ] || continue
        entry=$LAST_STAGE_DIRECTORY
        python3 "$BASE/inspect_series_v005.py" "$entry" --expect-blocks 3 --expect-profiles P0,P4 \
            > "$DRIVER/R4-pilot-c$concurrency.json" || continue
        if python3 - "$entry/results.csv" <<'RANGE_PY'
import csv, sys
with open(sys.argv[1], newline='') as file:
    rows = [row for row in csv.DictReader(file) if row['profile'] == 'P0']
raise SystemExit(not (len(rows) == 3 and all(40 <= float(row['cpu_pct']) <= 70 for row in rows)))
RANGE_PY
        then chosen=$concurrency; break; fi
    done
    if [ -n "$chosen" ]; then
        export NGINX_C=$chosen
        printf 'R4_CHOSEN_C=%s\n' "$chosen" > "$DRIVER/R4-condition.txt"
        run_stage R4-nginx-nonsaturated nginx 60 P1c P4
    else
        printf 'R4=FAILED: none of C=1,2,4,8,16 met CPU(P0)=40-70%% in every pilot block.\n' > "$DRIVER/R4-condition.txt"
    fi
    export NGINX_C=25
    date -u -Is > "$DRIVER/primary-corrected-finished.txt"
    echo 'PRIMARY_FINISHED: the first formal look is the post phase'
}

# ---------------------------------------------------------------- post
seal_log() {
    local directory
    directory=$(sed -n 's/^RESULT_DIR=//p' "$1" | tail -n 1)
    if [[ "$directory" == "$ROOT/"* ]] && [ -f "$directory/run.log" ]; then
        sha256sum "$directory/run.log" > "$directory/sha256-closed-run-log.txt"
    fi
}
run_logged() {
    local name=$1 rc=0
    shift
    ( set -o noclobber; "$@" > "$DRIVER/post-$name.out" 2>&1 ) || rc=$?
    printf '%s\n' "$rc" > "$DRIVER/post-$name.rc"
    seal_log "$DRIVER/post-$name.out"
    printf 'STAGE=%s RC=%s UTC=%s\n' "$name" "$rc" "$(date -u -Is)"
    return "$rc"
}
install_memcached() {  # only the new package, after every load series of the old services
    local listeners plan="$DRIVER/memcached-install-plan.txt" version
    ! rpm -q memcached >/dev/null 2>&1 || { echo 'memcached is already installed; inspect manually'; return 2; }
    [ "$(systemctl show memcached.service -p LoadState --value)" = not-found ] || {
        echo 'Default memcached unit already exists; preserve it'; return 2;
    }
    listeners=$(ss -H -ltn '( sport = :11211 or sport = :11212 )') || return 2
    [ -z "$listeners" ] || { echo 'Memcached ports occupied'; return 2; }
    apt-get -s install memcached > "$plan" 2>&1 || return 2
    # Nothing upgraded or removed; executed: one new package memcached 1.6.42-alt1.
    grep -E '^0 upgraded, [0-9]+ newly installed, 0 removed' "$plan" >/dev/null || {
        echo 'Installation would upgrade or remove packages; inspect manually'; return 2;
    }
    version=$(sed -n 's/^Inst memcached (\([^ ]*\) .*/\1/p' "$plan")
    [ -n "$version" ] || return 2
    if [ "$version" != 1.6.42-alt1 ] && [ "${SLAB_ACCEPT_OTHER_MEMCACHED:-0}" != 1 ]; then
        echo "memcached $version differs from 1.6.42-alt1 of the executed run; SLAB_ACCEPT_OTHER_MEMCACHED=1 accepts it"
        return 2
    fi
    systemctl mask --runtime memcached.service || return 2
    local rc=0
    apt-get -y install memcached || rc=$?
    systemctl daemon-reload || return 2
    systemctl mask memcached.service || return 2
    systemctl disable memcached.service || echo 'NOTE: default unit remains persistently masked'
    systemctl stop memcached.service || true
    systemctl is-active --quiet memcached.service && return 2
    listeners=$(ss -H -ltn '( sport = :11211 or sport = :11212 )') || return 2
    [ -z "$listeners" ] || { echo 'Unexpected new listener: refusing measurements'; return 2; }
    systemctl show memcached.service -p LoadState -p ActiveState -p UnitFileState
    rpm -q memcached
    return "$rc"
}
memcached_load() {  # LOOK: one complete technical repeat of a failed look
    local look=$1 rc=0
    MEMCACHED_LOG="$DRIVER/post-memcached-load-$look.out"
    run_logged "memcached-load-$look" bash "$HERE/memcached_stage3_v005.sh" measure "$REG" "$CONTRACT" "$look" || rc=$?
    if [ "$rc" != 0 ]; then
        rc=0
        MEMCACHED_LOG="$DRIVER/post-memcached-load-$look-retry.out"
        run_logged "memcached-load-$look-retry" bash "$HERE/memcached_stage3_v005.sh" measure "$REG" "$CONTRACT" "$look" || rc=$?
    fi
    return "$rc"
}
phase_memcached() {
    run_logged memcached-install install_memcached || return 0
    run_logged memcached-register bash "$HERE/memcached_stage3_v005.sh" register || return 0
    REG=$(sed -n 's/^REGISTERED_PARAMETERS=//p' "$DRIVER/post-memcached-register.out" | tail -n 1)
    [[ "$REG" == "$ROOT/memcached-v005-registrations/"* ]] || exit 2
    run_logged memcached-prepare bash "$HERE/memcached_stage3_v005.sh" prepare "$REG" || return 0
    if run_logged memcached-functional bash "$HERE/memcached_stage3_v005.sh" check "$REG" \
        && run_logged memcached-probe bash "$HERE/memcached_stage3_v005.sh" probe "$REG"; then
        CONTRACT=$(sed -n 's/^RESULT_DIR=//p' "$DRIVER/post-memcached-functional.out" | tail -n 1)
        local probe bench extension decision
        probe=$(sed -n 's/^RESULT_DIR=//p' "$DRIVER/post-memcached-probe.out" | tail -n 1)
        if memcached_load 1; then
            bench=$(sed -n 's/^RESULT_DIR=//p' "$MEMCACHED_LOG" | tail -n 1)
            if run_logged memcached-first-look python3 "$ANALYSIS/analyze_memcached_v005.py" \
                --functional "$CONTRACT" --probe "$probe" --bench "$bench"; then
                decision="$ANALYSIS/memcached-analysis-first-look/extension-decision.json"
                if [ -f "$decision" ] && python3 - "$decision" <<'PY'
import json, sys
raise SystemExit(not json.load(open(sys.argv[1]))['needs_extension'])
PY
                then
                    if memcached_load 2; then
                        extension=$(sed -n 's/^RESULT_DIR=//p' "$MEMCACHED_LOG" | tail -n 1)
                        run_logged memcached-final-analysis python3 "$ANALYSIS/analyze_memcached_v005.py" \
                            --functional "$CONTRACT" --probe "$probe" --bench "$bench" --extension "$extension" || true
                    else
                        echo 'NO_VALID_EXTENSION: no third look' > "$DRIVER/memcached-analysis-limitation.txt"
                    fi
                fi
            fi
        fi
    fi
    run_logged memcached-cleanup bash "$HERE/memcached_stage3_v005.sh" cleanup "$REG" || true
}

phase_post() {
    [ -f "$DRIVER/primary-corrected-finished.txt" ] || { echo 'Primary series have not finished'; exit 2; }
    claim post-primary
    rest
    # CONTINUATION_QUEUE_FREEZE.md: first look -> the one planned extension ->
    # final analysis -> CAP contract and ablation -> mount states -> memcached.
    local first_rc=0 extension_rc=0
    run_logged first-look python3 "$ANALYSIS/analyze_v005.py" || first_rc=$?
    if [ "$first_rc" = 0 ] && [ -f "$ANALYSIS/extension-plan.json" ]; then
        # A plan with PostgreSQL runs wholly under the port reservation.
        local pg=0
        grep -q '"service": *"postgresql"' "$ANALYSIS/extension-plan.json" && pg=1
        [ "$pg" = 0 ] || reserve_pg_port extension || exit 2
        run_logged extensions bash "$BASE/driver_extensions_v005.sh" "$ANALYSIS/extension-plan.json" || extension_rc=$?
        [ "$pg" = 0 ] || release_pg_port extension || exit 2
        printf '%s\n' "$extension_rc" > "$DRIVER/extension-queue-status.txt"
    else
        echo 'FIRST_LOOK_UNAVAILABLE: no adaptive measurements authorized by an invalid/missing analysis' \
            > "$DRIVER/extension-queue-status.txt"
    fi
    rest
    run_logged final-analysis python3 "$ANALYSIS/analyze_v005.py" --final || true

    # Descriptive and exploratory observations, not selection goals.
    export NGINX_PROFILES='P0 P1r P1c P1cADMIN P1cPTRACE P1cDAC P1cCHROOT'
    run_logged capability-contract bash "$HERE/functional_ext_v005.sh" nginx || true
    rest
    run_logged capability-ablation bash "$HERE/scenarios_v005.sh" nginx || true
    unset NGINX_PROFILES
    rest
    if run_logged mount-check bash "$MOUNT/supplement_mount_states_v005.sh" check; then
        SLAB_AFTER_PRIMARY=1 run_logged mount-states bash "$MOUNT/supplement_mount_states_v005.sh" run || true
    fi
    rest
    phase_memcached
    rest
    date -u -Is > "$DRIVER/post-primary-finished.txt"
    echo 'POST_PRIMARY_FINISHED: verify raw data and hashes (verify_raw_v005.py) before the report'
}

# ---------------------------------------------------------------- seal
# collect_results_v005.ps1 recognizes only the controllers of the executed run;
# a new run is closed here and copied as one archive, then checked on the host:
#   python verify_raw_v005.py results_v005 results_v005/SHA256-CLOSED-RESULTS.txt
phase_seal() {
    [ -f "$DRIVER/post-primary-finished.txt" ] || { echo 'Post phase has not finished'; exit 2; }
    if pgrep -f 'benchmark_v005.sh|slab_heartbeat_v005.py|memcached_stage3_v005.sh|driver_extensions_v005.sh|supplement_mount_states_v005.sh' >/dev/null; then
        echo 'A measurement process is still running; nothing sealed'; exit 2
    fi
    claim seal
    local manifest="$ROOT/SHA256-CLOSED-RESULTS.txt" archive="$BASE/results_v005-closed.tar.gz"
    [ ! -e "$manifest" ] && [ ! -e "$archive" ] || { echo 'Results were already sealed'; exit 2; }
    # Same format as the executed manifest: "<sha256>  ./<path>", regular files, byte order.
    python3 - "$ROOT" > "$BASE/SHA256-CLOSED-RESULTS.tmp" <<'MANIFEST_PY'
import hashlib, os, sys
root = sys.argv[1]
names = []
for directory, _, files in os.walk(root):
    for name in files:
        path = os.path.join(directory, name)
        relative = os.path.relpath(path, root).replace(os.sep, '/')
        if not os.path.islink(path) and relative != 'SHA256-CLOSED-RESULTS.txt':
            names.append(relative)
for relative in sorted(names, key=lambda n: n.encode()):
    with open(os.path.join(root, relative), 'rb') as stream:
        print(f'{hashlib.file_digest(stream, "sha256").hexdigest()}  ./{relative}')
MANIFEST_PY
    mv "$BASE/SHA256-CLOSED-RESULTS.tmp" "$manifest"
    tar -czf - -C "$BASE" results_v005 > "$archive"
    ( cd "$BASE" && sha256sum "$(basename "$archive")" ) | tee "$archive.sha256"
    echo "SEALED: $(wc -l < "$manifest") files; copy $archive to the host"
}

case "$PHASE" in
    stand) phase_stand ;;
    preflight) phase_preflight ;;
    primary) phase_primary ;;
    post) phase_post ;;
    seal) phase_seal ;;
    all) phase_preflight; phase_primary; phase_post; phase_seal ;;
    *) echo "unknown phase: $PHASE"; exit 1 ;;
esac
