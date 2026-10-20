#!/usr/bin/env bash
# Standalone stage 26. register -> prepare -> check/probe -> measure -> cleanup.
# Package installation belongs to the operator. Never source slab_common here.
# '_' is allowed in the version patterns: memcached -V on ALT prints 1.6.42_alt1,
# which the executed edition rejected (data/rerun/README.md).
set -Eeuo pipefail
export LC_ALL=C TZ=UTC
HERE=$(dirname "$(readlink -f "$0")")
CLIENT="$HERE/memcached_client_v005.py"
PROTOCOL="$HERE/protocol_memcached_v005.txt"
METRICS="$HERE/metric_summary_v005.py"
ROOT=${SLAB_RESULTS_ROOT:-${SLAB_BASE:-/root/systemd-hardening-lab}/results_v005}
REG_BASE="$ROOT/memcached-v005-registrations"
STATE=/var/lib/systemd-lab/memcached-v005-fixture
USER_NAME=labmemcachev005
UNIT=slab-memcached-v005.service
UNIT_FILE="/etc/systemd/system/$UNIT"
DROPIN_DIR="/etc/systemd/system/$UNIT.d"
DROPIN="$DROPIN_DIR/90-hardening.conf"
PROFILES="$ROOT/memcached/profiles"
FP=/usr/local/bin/slab_fp_v005.sh
INSERVICE=/usr/local/bin/slab_inservice_v005.sh
TARGET=lab-proc-target@labmemcachev005.service
ALL=(P0 P1 P2 P4 P6)
OUT=
HB1=0
HB2=0
RESTORE=0
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: run on the isolated lab VM as root'; exit 1; }
MODE=${1:?usage: memcached_stage3_v005.sh register|prepare|check|probe|measure|cleanup [REG_DIR] [CONTRACT_DIR] [LOOK=1|2]}

die() { echo "ERROR: $*" >&2; exit 1; }
tool() { command -v "$1" >/dev/null || die "missing tool: $1 (operator installs it)"; }
[[ "$ROOT" == /* ]] || die 'results root must be an absolute lab path'
if [[ "$ROOT" == /root/systemd-lab-results || "$ROOT" == /root/systemd-lab-results/* ]]; then
    die 'old results root is read-only reference material for this run'
fi
for required_tool in python3 systemctl sha256sum ss taskset awk find readlink; do tool "$required_tool"; done

helper_sources() {
    printf '%s\n' "$HERE/slab_fp_v005.sh" "$HERE/slab_inservice_v005.sh" \
        "$HERE/../stand_v005/probes/isolation_probe.py" "$HERE/../stand_v005/probes/extended_probe.py" \
        "$HERE/../stand_v005/probes/ptrace_seize.py"
}

helpers() { # MODE=verify|install; existing different helpers are never overwritten.
    local action=$1 source destination
    while IFS= read -r source; do
        [ -f "$source" ] || die "missing source helper $source"
        destination="/usr/local/bin/$(basename "$source")"
        if [ -e "$destination" ]; then cmp -s "$source" "$destination" || die "different installed helper $destination";
        elif [ "$action" = install ]; then install -m 0755 "$source" "$destination";
        else echo "NOTE: helper will be installed from frozen source: $destination"; fi
    done < <(helper_sources)
    for destination in /usr/local/bin/lab-target /usr/local/bin/uid-helper /etc/systemd/system/lab-proc-target@.service; do
        [ -e "$destination" ] || die "missing existing lab foundation $destination"
    done
}

registration() {
    REG=$(readlink -f "${2:?registration directory required}")
    [[ "$REG" == "$REG_BASE/"* ]] || die 'registration is outside the owned registration directory'
    [ -f "$REG/parameters.json" ] && [ -f "$REG/code.sha256" ] || die 'incomplete parameter registration'
    sha256sum -c "$REG/code.sha256" || die 'code/protocol/helper changed after registration'
    ( cd "$REG" && sha256sum -c registration.sha256 ) || die 'registered parameters/platform changed'
    VERSION=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["expected_version"])' "$REG/parameters.json")
    BINARY=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["binary"])' "$REG/parameters.json")
    SEED=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["randomization_seed"])' "$REG/parameters.json")
    [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+[a-zA-Z0-9._-]*$ ]] || die 'invalid registered memcached version'
    [[ "$BINARY" == /* ]] && [ -x "$BINARY" ] || die 'registered executable is unavailable'
}

owned() {
    [ -f "$STATE/owned-v005.txt" ] || die 'fixture was not prepared by this runner'
    grep -Fx "registration=$REG" "$STATE/owned-v005.txt" >/dev/null || die 'fixture belongs to another registration'
    grep -Fx "unit=$UNIT" "$STATE/owned-v005.txt" >/dev/null || die 'fixture unit identity mismatch'
    id "$USER_NAME" >/dev/null || die 'owned fixture user is missing'
    [ -f "$UNIT_FILE" ] && [ -f "$PROFILES/P4.conf" ] || die 'incomplete prepared fixture'
    sha256sum -c "$STATE/fixture.sha256" || die 'fixture unit/profile changed since preparation'
    helpers verify
}

health() {
    local attempt actual
    for attempt in $(seq 1 15); do
        actual=$(python3 "$CLIENT" version 2>/dev/null || true)
        [ "$actual" != "$VERSION" ] || return 0
        sleep 1
    done
    return 1
}

apply() {
    local profile=$1
    if [ "$profile" = P0 ]; then rm -f -- "$DROPIN" || return 1;
    else [ -f "$PROFILES/$profile.conf" ] || return 1; cp "$PROFILES/$profile.conf" "$DROPIN" || return 1; fi
    systemctl daemon-reload || return 1
    systemctl reset-failed "$UNIT" 2>/dev/null || true
    systemctl restart "$UNIT" && health
}

rest_state() {
    cmp -s "$PROFILES/P4.conf" "$DROPIN" || die 'fixture is not under its saved P4'
    [ -z "$(find "$DROPIN_DIR" -maxdepth 1 -type f ! -name 90-hardening.conf -print -quit)" ] || die 'extra fixture drop-in'
    systemctl is-active --quiet "$UNIT" || die 'fixture is not active'
}

hb_stop() {
    local pid
    for pid in "$HB1" "$HB2"; do
        [ "$pid" -le 0 ] || { kill -TERM "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
    done
    HB1=0; HB2=0
}

cleanup() {
    local status=$?
    trap - EXIT
    set +e
    hb_stop
    if [ "$RESTORE" = 1 ]; then
        if apply P4; then echo 'RESTORE_P4 memcached=PASS'; else echo 'RESTORE_P4 memcached=FAIL'; status=2; fi
    fi
    if [ -n "$OUT" ]; then
        [ "$status" -eq 0 ] || printf 'failed exit=%s utc=%s\n' "$status" "$(date -u -Is)" > "$OUT/FAILED.txt"
        journalctl -u "$UNIT" --since "@$OUT_START" -o short-iso-precise --no-pager > "$OUT/journal.txt" 2>&1
        # run.log still streams through tee; parent hashes it after this process ends.
        ( cd "$OUT" && find . -type f ! -name sha256-all.txt ! -name run.log -print0 | sort -z | xargs -0 sha256sum > sha256-all.txt )
        echo "RESULT_DIR=$OUT"
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

result_dir() {
    OUT="$1/$(date -u +%Y%m%dT%H%M%SZ)-$$"
    [ ! -e "$OUT" ] || die 'result directory already exists'
    mkdir -p "$OUT"
    OUT_START=$(date +%s)
    exec > >(tee "$OUT/run.log") 2>&1
    mkdir "$OUT/registration"
    cp "$REG/parameters.json" "$REG/code.sha256" "$REG/registration.sha256" "$REG/platform.txt" "$REG/target-unit.txt" "$OUT/registration/"
    printf 'REGISTRATION=%s\nMODE=%s\nUTC=%s\n' "$REG" "$MODE" "$(date -u -Is)" > "$OUT/source.txt"
}

if [ "$MODE" = register ]; then
    tool memcached
    helpers verify
    BINARY=$(readlink -f "$(command -v memcached)")
    VERSION=$("$BINARY" -V 2>&1 | awk '{print $NF}')
    [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+[a-zA-Z0-9._-]*$ ]] || die 'cannot identify installed memcached version'
    SEED=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
    REG="$REG_BASE/$(date -u +%Y%m%dT%H%M%SZ)-$$"
    mkdir -p "$REG"
    python3 "$CLIENT" parameters --binary "$BINARY" --expected-version "$VERSION" --seed "$SEED" > "$REG/parameters.json"
    {
        date -u -Is; uname -a; systemctl --version | head -n 1
        "$BINARY" -V; python3 -V; nproc; free -m
        echo 'REGISTRATION_PRECEDES_PROFILE_CREATION_AND_MEASUREMENTS=1'
    } > "$REG/platform.txt"
    systemctl cat lab-proc-target@.service --no-pager > "$REG/target-unit.txt"
    sources=("$HERE/memcached_stage3_v005.sh" "$CLIENT" "$PROTOCOL" "$METRICS" "$BINARY" \
        /usr/local/bin/lab-target /usr/local/bin/uid-helper /etc/systemd/system/lab-proc-target@.service)
    while IFS= read -r source; do sources+=("$source"); done < <(helper_sources)
    sha256sum "${sources[@]}" > "$REG/code.sha256"
    ( cd "$REG" && sha256sum parameters.json platform.txt target-unit.txt > registration.sha256 )
    echo "REGISTERED_PARAMETERS=$REG"
    exit 0
fi

registration "$@"
if [ "$MODE" = prepare ]; then
    result_dir "$ROOT/memcached/prepare-v005"
    for path in "$STATE" "$UNIT_FILE" "$DROPIN_DIR" "$PROFILES"; do
        [ ! -e "$path" ] && [ ! -L "$path" ] || die "fixture path already exists: $path"
    done
    if getent passwd "$USER_NAME" >/dev/null || getent group "$USER_NAME" >/dev/null; then die 'fixture user/group already exists'; fi
    listeners=$(ss -H -ltn '( sport = :11212 )' 2>&1) || die 'cannot inspect fixture TCP port'
    [ -z "$listeners" ] || die 'fixture TCP port is already in use'
    if systemctl cat "$UNIT" --no-pager >/dev/null 2>&1; then die 'fixture unit name already exists'; fi
    helpers install
    mkdir -m 0750 "$STATE"
    printf 'registration=%s\nunit=%s\nuser=%s\n' "$REG" "$UNIT" "$USER_NAME" > "$STATE/owned-v005.txt"
    useradd -r -M -U -d /var/empty -s /sbin/nologin "$USER_NAME"
    mkdir -p "$PROFILES" "$DROPIN_DIR"
    cat > "$UNIT_FILE" <<UNITFILE
[Unit]
Description=v005 independently registered memcached fixture (loopback only)
After=network.target
[Service]
Type=simple
User=$USER_NAME
Group=$USER_NAME
ExecStart=$BINARY -l 127.0.0.1 -p 11212 -U 0 -m 64 -t 1 -B ascii
Restart=no
CPUAccounting=yes
MemoryAccounting=yes
CPUAffinity=0
UNITFILE
    cat > "$PROFILES/P1.conf" <<'P1'
[Service]
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
NoNewPrivileges=yes
P1
    { cat "$PROFILES/P1.conf"; cat <<'P2'
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
P2
    } > "$PROFILES/P2.conf"
    { cat "$PROFILES/P2.conf"; cat <<'P4'
ProtectControlGroups=yes
ProtectProc=invisible
PrivateMounts=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_INET
CapabilityBoundingSet=
SystemCallFilter=~@mount @reboot @swap @module @raw-io @debug
SystemCallErrorNumber=EPERM
MemoryDenyWriteExecute=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
P4
    } > "$PROFILES/P4.conf"
    { cat "$PROFILES/P4.conf"; printf 'ProtectSystem=strict\n'; } > "$PROFILES/P6.conf"
    sha256sum "$UNIT_FILE" "$PROFILES"/*.conf > "$STATE/fixture.sha256"
    systemctl daemon-reload
    systemctl start "$TARGET"
    RESTORE=1
    apply P4 || die 'P4 fixture did not start; preserve this outcome and inspect the journal'
    echo 'PREPARED memcached: user/unit/profiles scoped; G=empty; loopback TCP11212; UDP disabled'
    exit 0
fi

owned
rest_state
RESTORE=1
if [ "$MODE" = cleanup ]; then exit 0; fi

if [ "$MODE" = check ]; then
    result_dir "$ROOT/memcached/functional-v005"
    echo 'service,profile,check,result,detail,mandatory' > "$OUT/functional.csv"
    echo 'service,profile,contract' > "$OUT/contract.csv"
    echo 'service,profile,F,contract' > "$OUT/F.csv"
    echo 'service,profile,functional,exposure,n_directives' > "$OUT/candidates.csv"
    echo 'service,goal,dac,context,profile,outcome,detail' > "$OUT/goals.csv"
    for profile in "${ALL[@]}"; do
        F=1
        if ! apply "$profile"; then
            F=0; echo "memcached,$profile,start,FAIL,service did not start,1" >> "$OUT/functional.csv"
        else
            echo "memcached,$profile,start,PASS,version endpoint ready,1" >> "$OUT/functional.csv"
            if ! python3 "$CLIENT" contract-before --expected-version "$VERSION" > "$OUT/pre-$profile.json"; then F=0; fi
            if ! python3 "$CLIENT" rows --file "$OUT/pre-$profile.json" --profile "$profile" >> "$OUT/functional.csv"; then
                F=0; echo "memcached,$profile,contract-output,ERROR,invalid pre-contract JSON,1" >> "$OUT/functional.csv"
            fi
            if systemctl restart "$UNIT" && health; then
                if ! python3 "$CLIENT" contract-after --file "$OUT/pre-$profile.json" > "$OUT/post-$profile.json"; then F=0; fi
                if ! python3 "$CLIENT" rows --file "$OUT/post-$profile.json" --profile "$profile" >> "$OUT/functional.csv"; then
                    F=0; echo "memcached,$profile,restart-loses-value,ERROR,invalid post-contract JSON,1" >> "$OUT/functional.csv"
                fi
            else F=0; echo "memcached,$profile,restart-loses-value,ERROR,restart failed,1" >> "$OUT/functional.csv"; fi
        fi
        exposure=$(systemd-analyze security "$UNIT" --no-pager 2>/dev/null | sed -n 's/.*Overall exposure level[^:]*: *\([0-9.]*\).*/\1/p' | tail -n 1 || true)
        n=0; [ "$profile" = P0 ] || n=$(grep -Ec '^[A-Za-z].*=' "$PROFILES/$profile.conf")
        verdict=FAIL; [ "$F" = 0 ] || verdict=PASS
        echo "memcached,$profile,$verdict" >> "$OUT/contract.csv"
        echo "memcached,$profile,$F,$verdict" >> "$OUT/F.csv"
        echo "memcached,$profile,$F,${exposure:-NA},$n" >> "$OUT/candidates.csv"
        if [ "$F" = 0 ] && [ "$profile" != P0 ]; then
            echo "PARTIAL_PROCEDURE: $profile F=0; the one-step minimal relaxation of procedure section 2 was not performed; frozen finite family remains M=4" >> "$OUT/F_RELAXATION_NOT_IMPLEMENTED.txt"
        fi
        systemctl cat "$UNIT" --no-pager > "$OUT/unit-$profile.txt"
        pid=$(systemctl show "$UNIT" -p MainPID --value)
        if [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then "$FP" "$pid" > "$OUT/real-$profile.fp"; "$FP" --mounts "$pid" > "$OUT/real-$profile.mnt"; fi
    done
    echo 'G_EMPTY=1; NETWORK_API_ALLOWANCE_IS_DIAGNOSTIC_NOT_A_GOAL_SCORE'
    exit 0
fi

if [ "$MODE" = probe ]; then
    result_dir "$ROOT/memcached/probe-v005"
    pid=$(systemctl show "$TARGET" -p MainPID --value)
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || die 'same-user target process is not running'
    for profile in "${ALL[@]}"; do
        props=()
        if [ "$profile" != P0 ]; then
            while IFS= read -r setting || [ -n "$setting" ]; do
                setting=${setting%$'\r'}
                case "$setting" in ''|'[Service]'|\#*) continue;; esac
                [[ "$setting" == *=* ]] || die "unsupported profile line: $setting"
                props+=(-p "$setting")
            done < "$PROFILES/$profile.conf"
        fi
        rc=0
        systemd-run --quiet --wait --pipe --collect --unit="slab-memcached-v005-probe-${profile,,}-$$" \
            -p Type=exec -p "User=$USER_NAME" -p "Group=$USER_NAME" -p CPUAffinity=0 \
            ${props[@]+"${props[@]}"} "$INSERVICE" "memcached-$profile" "$pid" \
            > "$OUT/memcached__$profile.txt" 2>&1 || rc=$?
        echo "PROBE profile=$profile transient_rc=$rc"
    done
    python3 "$CLIENT" validate-probes --file "$OUT" > "$OUT/probe-validation.json" || die 'incomplete/ERROR probe statuses; do not fabricate Emicro'
    python3 "$METRICS" "$OUT" | tee "$OUT/metrics.txt"
    exit 0
fi

if [ "$MODE" = measure ]; then
    CONTRACT_DIR=$(readlink -f "${3:?functional result directory required}")
    LOOK=${4:-1}; [[ "$LOOK" =~ ^[12]$ ]] || die 'only two predeclared looks are permitted'
    [ -f "$CONTRACT_DIR/contract.csv" ] && [ -f "$CONTRACT_DIR/source.txt" ] || die 'missing explicit mandatory contracts'
    grep -Fx "REGISTRATION=$REG" "$CONTRACT_DIR/source.txt" >/dev/null || die 'contracts came from another registration'
    ( cd "$CONTRACT_DIR" && sha256sum -c sha256-all.txt ) || die 'functional results changed'
    [ ! -e "$STATE/look-$LOOK-complete.txt" ] || die 'this planned look is already complete'
    if [ "$LOOK" = 2 ]; then [ -f "$STATE/look-1-complete.txt" ] || die 'planned extension requires completed first look'; fi
    result_dir "$ROOT/memcached/benchmark-v005"
    printf 'LOOK=%s\nBLOCKS=20\nOPS=3000000\nCONNECTIONS=50\nCLIENT_THREADS=3\nPIPELINE=32\nSERVER_CPU=0\nCLIENT_CPUS=1-3\nSTALL_MS=500\nELAPSED_CLOCK=CLOCK_MONOTONIC_RAW\nWALL_CLOCK_USE=UTC labels only\n' "$LOOK" > "$OUT/platform.txt"
    echo 'block,order,profile,rps,cpu_pct,cpu_us_per_op,ops,wall_ns,failed,max_gap_ms,attempt' > "$OUT/results.csv"
    echo 'block,order,profile,attempt,throughput,max_gap_ms,reason' > "$OUT/invalid.csv"
    mapfile -t candidates < <(python3 -c 'import csv,sys; rows=list(csv.DictReader(open(sys.argv[1]))); print("\n".join(r["profile"] for r in rows if r["service"]=="memcached" and r["contract"]=="PASS"))' "$CONTRACT_DIR/contract.csv")
    [[ " ${candidates[*]} " == *' P0 '* ]] || die 'mandatory P0 contract did not pass'
    if [ "${#candidates[@]}" -lt 2 ]; then
        echo 'NONE: no restricted candidate passed the mandatory F contract' > "$OUT/OUTCOME.txt"
        echo 'NO_LOAD_MEASUREMENTS: all restricted F=0; do not pass this empty results.csv as benchmark data' > "$OUT/NO_MEASUREMENTS.txt"
        exit 0
    fi
    printf '%s\n' "${candidates[@]}" > "$OUT/candidates-in-series.txt"
    sha256sum "$PROFILES"/*.conf > "$OUT/sha256-profiles.txt"
    for block in $(seq 1 20); do
        order=0
        while IFS= read -r profile; do
            order=$((order+1)); attempt=0
            while :; do
                attempt=$((attempt+1))
                apply "$profile" || die "functional failure during series: $profile"
                python3 "$CLIENT" seed > "$OUT/seed-B$block-$profile-a$attempt.json"
                taskset -c 1-3 python3 "$CLIENT" load --ops 5000 > "$OUT/warmup-B$block-$profile-a$attempt.json"
                rm -f -- "$OUT/hb-server" "$OUT/hb-client"
                taskset -c 0 python3 "$CLIENT" heartbeat --file "$OUT/hb-server" & HB1=$!
                taskset -c 1-3 python3 "$CLIENT" heartbeat --file "$OUT/hb-client" & HB2=$!
                cpu_before=$(systemctl show "$UNIT" -p CPUUsageNSec --value)
                start=$(python3 -c 'import time; print(time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW))')
                taskset -c 1-3 python3 "$CLIENT" load > "$OUT/load-B$block-$profile-a$attempt.json" || die 'GET failure; keep failed series'
                end=$(python3 -c 'import time; print(time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW))')
                cpu_after=$(systemctl show "$UNIT" -p CPUUsageNSec --value)
                hb_stop
                [ -s "$OUT/hb-server" ] && [ -s "$OUT/hb-client" ] || die 'heartbeat output missing'
                gap=$(cat "$OUT/hb-server" "$OUT/hb-client" | sort -n | tail -n 1)
                [[ "$gap" =~ ^[0-9]+([.][0-9]+)?$ ]] || die 'invalid heartbeat number'
                cp "$OUT/hb-server" "$OUT/hb-B$block-$profile-a$attempt-server.txt"
                cp "$OUT/hb-client" "$OUT/hb-B$block-$profile-a$attempt-client.txt"
                wall_ns=$((end-start)); cpu_ns=$((cpu_after-cpu_before))
                [ "$wall_ns" -gt 0 ] && [ "$cpu_ns" -gt 0 ] || die 'invalid wall/CPU values'
                throughput=$(awk -v w="$wall_ns" 'BEGIN {printf "%.3f", 3000000/(w/1e9)}')
                if awk -v gap="$gap" 'BEGIN {exit !(gap<=500)}'; then break; fi
                echo "$block,$order,$profile,$attempt,$throughput,$gap,stall" >> "$OUT/invalid.csv"
                [ "$attempt" -lt 5 ] || die 'five stalled attempts in a row'
            done
            cpu_pct=$(awk -v c="$cpu_ns" -v w="$wall_ns" 'BEGIN {printf "%.3f",100*c/w}')
            cpu_us=$(awk -v c="$cpu_ns" 'BEGIN {printf "%.4f",c/3000000/1000}')
            echo "$block,$order,$profile,$throughput,$cpu_pct,$cpu_us,3000000,$wall_ns,0,$gap,$attempt" >> "$OUT/results.csv"
            echo "BLOCK=$block ORDER=$order PROFILE=$profile RPS=$throughput CPU_PCT=$cpu_pct GAP_MS=$gap ATTEMPT=$attempt"
        done < <(python3 "$CLIENT" order --seed "$SEED" --block "$(( (LOOK-1)*20+block ))" --profiles "${candidates[@]}")
    done
    printf 'result=%s\n' "$OUT" > "$STATE/look-$LOOK-complete.txt"
    echo 'BENCHMARK_COMPLETE memcached'
    exit 0
fi
die "unknown mode $MODE"
