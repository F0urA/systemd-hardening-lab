#!/usr/bin/env bash
# Exploratory supplemental §6. NO primary CSV, profile, config, index, or benchmark edit.
# Usage: ./supplement_mount_states_v005.sh check
#        SLAB_AFTER_PRIMARY=1 ./supplement_mount_states_v005.sh run
set -Eeuo pipefail
export LC_ALL=C TZ=UTC
HERE=$(dirname "$(readlink -f "$0")")
export SLAB_RESULTS_ROOT=${SLAB_RESULTS_ROOT:-/root/article-experiment/20261012-v005/results_v005}
. "$HERE/slab_common_v005.sh"
MODE=${1:-check}
HELPER_SOURCE="$HERE/mount_state_helper_v005.py"
PROTOCOL="$HERE/protocol_mount_states_v005.md"
INSTALLED=/usr/local/bin/slab-mountstate-v005.py
SOURCE_BASE=/var/lib/systemd-lab/mountstate-v005
PROFILES=(P0 P1r P1c P5 P6)

preflight() {
    [ "$(id -u)" = 0 ] || { echo 'ERROR: host runner requires root on the laboratory VM'; return 1; }
    case "$(readlink -m "$ROOT")" in
        /root/systemd-lab-results|/root/systemd-lab-results/*|/|/root)
            echo 'ERROR: legacy or broad results root is forbidden'; return 1 ;;
    esac
    [ "$(readlink /proc/self/ns/mnt)" = "$(readlink /proc/1/ns/mnt)" ] || {
        echo 'ERROR: runner is not in the service-manager mount namespace'; return 1;
    }
    for command in python3 systemd-run systemctl journalctl curl mount umount \
                   sha256sum install readlink cmp find sort xargs timeout; do
        command -v "$command" >/dev/null || { echo "MISSING DEPENDENCY: $command"; return 1; }
    done
    require_files "$HELPER_SOURCE" "$PROTOCOL" "$HERE/slab_common_v005.sh"
    [ "$(readlink -m "$INSTALLED")" = "$INSTALLED" ] || {
        echo 'ERROR: installed helper path has a symlink component'; return 1;
    }
    [ ! -e "$INSTALLED" ] && [ ! -L "$INSTALLED" ] || { echo "CONFLICT: $INSTALLED"; return 1; }
    [ ! -e "$SOURCE_BASE" ] && [ ! -L "$SOURCE_BASE" ] || { echo "CONFLICT: $SOURCE_BASE"; return 1; }
    [ -d "$SITE" ] && [ ! -L "$SITE" ] || { echo 'ERROR: SITE must be an existing real directory'; return 1; }
    id labweb >/dev/null
    require_rest_state nginx
    for profile in P1r P1c P4 P5 P6; do
        require_files "$(svc_profiles nginx)/$profile.conf"
    done
    [ "$MODE" = check ] || [ "$MODE" = run ] || { echo 'ERROR: use check or run'; return 1; }
    python3 -c 'import time; time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)'
}

preflight
if [ "$MODE" = check ]; then
    echo 'CHECK=PASS; no fixture, unit, profile or package changed'
    exit 0
fi
[ "${SLAB_AFTER_PRIMARY:-0}" = 1 ] || {
    echo 'ERROR: only the serial parent queue AFTER primary series may set SLAB_AFTER_PRIMARY=1'; exit 1;
}
# require_rest_state additionally rejects the temporary benchmark affinity drop-in.
TOKEN=$(python3 -c 'import secrets; print(secrets.token_hex(8))')
CONTROL_BASE="/run/slab-mountstate-v005-$TOKEN"
OUT="$ROOT/mount-states-v005/$(date +%Y%m%d-%H%M%S)-$TOKEN"
[ ! -e "$OUT" ] && [ ! -L "$OUT" ] || { echo "CONFLICT: $OUT"; exit 1; }
mkdir -p "$OUT/source"
exec > >(tee "$OUT/run.log") 2>&1
START_EPOCH="@$(date +%s)"
HOST_NAMESPACE=$(readlink /proc/self/ns/mnt)
HELPER_CREATED=0
FIXTURE_STARTED=0
ACTIVE_UNIT=
LAUNCH_PID=
FINALIZED=0
CELL=
CELLS=()

h() { python3 "$HELPER_SOURCE" "$@" --token "$TOKEN" --out "$OUT"; }

stop_model() {
    local rc=0
    if [ -n "$ACTIVE_UNIT" ]; then
        case "$ACTIVE_UNIT" in
            "slab-v005-mountstate-$TOKEN-"*) ;;
            *) echo 'ERROR: refusing foreign transient unit cleanup'; return 2 ;;
        esac
        # No broad kill, no nginx PID kill, no namespace switch.
        local load
        load=$(systemctl show "$ACTIVE_UNIT" -p LoadState --value 2>/dev/null || true)
        printf '%s\n' "$load" > "$OUT/cells/$CELL/stop-unit-loadstate.txt"
        if [ -n "$load" ] && [ "$load" != not-found ]; then
            timeout 10 systemctl stop "$ACTIVE_UNIT" > "$OUT/cells/$CELL/stop-unit.out" 2>&1 || rc=$?
        fi
    fi
    if [ -n "$LAUNCH_PID" ]; then
        local launch_rc=0
        wait "$LAUNCH_PID" || launch_rc=$?
        printf '%s\n' "$launch_rc" > "$OUT/cells/$CELL/launcher.rc"
        LAUNCH_PID=
    fi
    ACTIVE_UNIT=
    return "$rc"
}

cleanup() {
    local rc=$? status=0
    trap - EXIT
    trap '' INT TERM
    set +e
    stop_model || status=2
    if [ "$FIXTURE_STARTED" = 1 ]; then
        # Collect raw files before fixture removal, including any interrupted cell.
        for cell in "${CELLS[@]}"; do
            h collect --cell "$cell" || status=2
        done
        h cleanup || status=2
        if [ "$FINALIZED" = 0 ]; then
            h finalize || status=2
            FINALIZED=1
        fi
    fi
    restore_rest_state nginx || status=2
    require_rest_state nginx || status=2
    sha256sum --check --strict "$OUT/source-integrity-before.sha256" \
        > "$OUT/source-integrity-after.txt" 2>&1 || status=2
    journalctl -u slab-nginx.service --since "$START_EPOCH" -o short-iso-precise --no-pager \
        > "$OUT/nginx-journal-all.txt" 2>&1 || status=2
    if [ "$HELPER_CREATED" = 1 ]; then
        if [ -f "$INSTALLED" ] && [ ! -L "$INSTALLED" ] && cmp -s "$HELPER_SOURCE" "$INSTALLED"; then
            rm -f -- "$INSTALLED"
        else
            echo 'ERROR: installed helper changed; preserved instead of deleting'; status=2
        fi
    fi
    [ "$rc" = 0 ] && [ "$status" = 0 ] && printf 'COMPLETE\n' > "$OUT/STATUS.txt" \
        || printf 'FAILED_OR_INCOMPLETE exit=%s cleanup=%s\n' "$rc" "$status" > "$OUT/STATUS.txt"
    # run.log is still being streamed by tee. Parent hashes the CLOSED log/archive.
    (cd "$OUT" && find . -type f ! -path './run.log' ! -path './sha256-all.txt' -print0 \
        | sort -z | xargs -0 -r sha256sum > sha256-all.txt) || status=2
    echo "RESULT_DIR=$OUT"
    [ "$rc" = 0 ] || exit "$rc"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cp "$HELPER_SOURCE" "$PROTOCOL" "$HERE/slab_common_v005.sh" "$0" "$OUT/source/"
for profile in P1r P1c P4 P5 P6; do
    cp "$(svc_profiles nginx)/$profile.conf" "$OUT/source/$profile.conf"
done
sha256sum "$HELPER_SOURCE" "$PROTOCOL" "$HERE/slab_common_v005.sh" "$0" \
    /etc/systemd-lab/nginx.conf /etc/systemd/system/slab-nginx.service \
    "$SITE/index.html" "$(svc_profiles nginx)"/{P1r,P1c,P4,P5,P6}.conf \
    > "$OUT/source-integrity-before.sha256"
systemctl cat slab-nginx.service > "$OUT/nginx-unit-before.txt"
printf 'elapsed_clock=CLOCK_MONOTONIC_RAW\nwall_clock=UTC_labels_only\n' > "$OUT/PARAMETERS.txt"
printf 'profiles=P0 P1r P1c P5 P6\nmodes=late nested\ncells=40\n' >> "$OUT/PARAMETERS.txt"
printf 'P0=namespace-harness_not_primary_P0\nPrivateMounts=yes MountFlags=slave_all_models\n' >> "$OUT/PARAMETERS.txt"
printf 'Type=exec RuntimeMaxSec=35s TimeoutStopSec=3s KillMode=control-group\n' >> "$OUT/PARAMETERS.txt"
printf 'READY_timeout=15s trigger_timeout=20s model_identity=no_UID_fallback\n' >> "$OUT/PARAMETERS.txt"
printf 'positive_control=same_mode_same_DAC_same_context_P0_ACHIEVED\n' >> "$OUT/PARAMETERS.txt"
printf 'primary_selection_input=no exploratory_after_known_FD_result=yes\n' >> "$OUT/PARAMETERS.txt"
printf 'SITE=%s\nSOURCE=%s\nCONTROL=%s\nHOST_NAMESPACE=%s\n' \
    "$SITE" "$SOURCE_BASE" "$CONTROL_BASE" "$HOST_NAMESPACE" >> "$OUT/PARAMETERS.txt"

FIXTURE_STARTED=1
h init
install -m 0755 "$HELPER_SOURCE" "$INSTALLED"
HELPER_CREATED=1

http_sample() {
    local label=$1 target=$2 code rc=0
    code=$(curl --max-time 5 --silent --show-error --header 'Cache-Control: no-cache' \
        -o "$OUT/cells/$CELL/$label.http.body" -w '%{http_code}' \
        "http://127.0.0.1:808/$(basename "$target")/document.txt" \
        2> "$OUT/cells/$CELL/$label.http.stderr") || rc=$?
    printf '%s\n' "$code" > "$OUT/cells/$CELL/$label.http.code"
    printf '%s\n' "$rc" > "$OUT/cells/$CELL/$label.http.rc"
}

capture_nginx() {
    local label=$1 pid child rc=0 workers=0
    pid=$(systemctl show slab-nginx.service -p MainPID --value)
    printf '%s\n' "$pid" > "$OUT/cells/$CELL/$label.nginx-mainpid.txt"
    [ -n "$pid" ] && [ "$pid" != 0 ] || return 1
    h snapshot --cell "$CELL" --name "$label-nginx-master" --pid "$pid" || rc=2
    for child in $(< "/proc/$pid/task/$pid/children"); do
        [ -f "/proc/$child/comm" ] || continue
        [ "$(< "/proc/$child/comm")" = nginx ] || continue
        workers=$((workers + 1))
        h snapshot --cell "$CELL" --name "$label-nginx-worker-$child" --pid "$child" || rc=2
    done
    printf '%s\n' "$workers" > "$OUT/cells/$CELL/$label.nginx-workers.txt"
    [ "$workers" = 2 ] || rc=2
    return "$rc"
}

for state in late nested; do
    for profile in "${PROFILES[@]}"; do
        apply_rc=0
        svc_apply nginx "$profile" > "$OUT/apply-$state-$profile.out" 2>&1 || apply_rc=$?
        for dac in rootown labweb; do
            for context in master worker; do
                CELL="$state-$profile-$dac-$context"
                CELLS+=("$CELL")
                h prepare --cell "$CELL"
                target="$SITE/mountstate-v005-$TOKEN-$CELL"
                http_sample baseline "$target"
                h snapshot --cell "$CELL" --name host-before
                snapshot_rc=0
                capture_nginx before > "$OUT/cells/$CELL/snapshot-before.out" 2>&1 || snapshot_rc=$?
                printf '%s\n' "$snapshot_rc" > "$OUT/cells/$CELL/snapshot-before.rc"
                since="@$(date +%s)"
                unit="slab-v005-mountstate-$TOKEN-${CELL,,}"
                printf '%s\n' "$unit" > "$OUT/cells/$CELL/unit.txt"
                printf '%s\n' "$apply_rc" > "$OUT/cells/$CELL/apply.rc"
                if [ "$apply_rc" = 0 ] && [ "$(< "$OUT/cells/$CELL/baseline.http.code")" = 200 ] \
                    && cmp -s "$OUT/cells/$CELL/baseline.http.body" <(printf 'G1_ORIGINAL_DOCUMENT\n'); then
                    file=P0
                    [ "$profile" = P0 ] || file="$(svc_profiles nginx)/$profile.conf"
                    props_from_profile "$file"
                    ident=()
                    [ "$context" = master ] || ident=(-p User=labweb -p Group=labweb)
                    ACTIVE_UNIT=$unit
                    systemd-run --quiet --wait --pipe --collect --unit="$unit" \
                        ${PROPS[@]+"${PROPS[@]}"} ${ident[@]+"${ident[@]}"} \
                        -p Type=exec -p PrivateMounts=yes -p MountFlags=slave -p RuntimeMaxSec=35s \
                        -p TimeoutStopSec=3s -p KillMode=control-group \
                        /usr/bin/python3 "$INSTALLED" model --token "$TOKEN" --cell "$CELL" \
                        --host-namespace "$HOST_NAMESPACE" --timeout-seconds 20 \
                        > "$OUT/cells/$CELL/launcher.out" 2>&1 &
                    LAUNCH_PID=$!
                    printf '%s\n' "$LAUNCH_PID" > "$OUT/cells/$CELL/launcher.pid"
                    model_pid=
                    if model_pid=$(h wait-ready --cell "$CELL" --unit "$unit" \
                            2> "$OUT/cells/$CELL/ready-error.out"); then
                        systemctl show "$unit" -p MainPID -p ActiveState -p SubState -p User -p Group \
                            -p PrivateMounts -p CapabilityBoundingSet -p NoNewPrivileges \
                            > "$OUT/cells/$CELL/unit-live-properties.txt"
                        h snapshot --cell "$CELL" --name model-ready --pid "$model_pid"
                        bind_rc=0
                        if [ "$state" = late ]; then
                            h host-bind --cell "$CELL" > "$OUT/cells/$CELL/host-bind.out" 2>&1 || bind_rc=$?
                        fi
                        printf '%s\n' "$bind_rc" > "$OUT/cells/$CELL/host-bind.rc"
                        h snapshot --cell "$CELL" --name host-after-state
                        h snapshot --cell "$CELL" --name model-after-state --pid "$model_pid"
                        snapshot_rc=0
                        capture_nginx afterstate > "$OUT/cells/$CELL/snapshot-after-state.out" 2>&1 || snapshot_rc=$?
                        printf '%s\n' "$snapshot_rc" > "$OUT/cells/$CELL/snapshot-after-state.rc"
                        http_sample afterstate "$target"
                        if [ "$bind_rc" = 0 ]; then
                            h trigger --cell "$CELL" > "$OUT/cells/$CELL/trigger.out" 2>&1 || stop_model
                        else
                            stop_model
                        fi
                    else
                        stop_model
                    fi
                    if [ -n "$LAUNCH_PID" ]; then
                        launch_rc=0
                        wait "$LAUNCH_PID" || launch_rc=$?
                        printf '%s\n' "$launch_rc" > "$OUT/cells/$CELL/launcher.rc"
                        LAUNCH_PID=
                    fi
                    ACTIVE_UNIT=
                else
                    printf '2\n' > "$OUT/cells/$CELL/launcher.rc"
                    printf 'Not launched: service or exact baseline HTTP precondition failed\n' \
                        > "$OUT/cells/$CELL/launcher.out"
                fi
                # Validate HTTP BEFORE unmounting a late target or destroying any fixture.
                http_sample final "$target"
                h snapshot --cell "$CELL" --name host-after-attempt
                snapshot_rc=0
                capture_nginx final > "$OUT/cells/$CELL/snapshot-final.out" 2>&1 || snapshot_rc=$?
                printf '%s\n' "$snapshot_rc" > "$OUT/cells/$CELL/snapshot-final.rc"
                journalctl -u "$unit" --since "$since" -o short-iso-precise --no-pager \
                    > "$OUT/cells/$CELL/unit-journal.txt" 2>&1
                h collect --cell "$CELL"
                h record --cell "$CELL"
                # Refuses any changed/unconfirmed bind; no lazy/recursive fallback.
                h host-unbind --cell "$CELL"
            done
        done
    done
done
FINALIZED=1
final_rc=0
h finalize || final_rc=$?
exit "$final_rc"
