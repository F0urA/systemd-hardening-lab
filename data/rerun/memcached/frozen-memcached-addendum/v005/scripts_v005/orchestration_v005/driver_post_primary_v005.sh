#!/usr/bin/env bash
# Serialized continuation of the existing v005 job; never starts primary again.
set -Eeuo pipefail
export LC_ALL=C TZ=UTC
BASE=${SLAB_BASE:-/root/systemd-hardening-lab}
HERE="$BASE/frozen-timing/v005/scripts_v005"
ANALYSIS="$BASE/post-analysis"
MOUNT="$BASE/frozen-mount-states/scripts_v005"
export SLAB_RESULTS_ROOT="$BASE/results_v005"
. "$HERE/slab_common_v005.sh"
DRIVER="$ROOT/driver"
[ ! -e "$DRIVER/post-primary-started.txt" ] || { echo 'Continuation was already attempted'; exit 1; }
exec 9>"$BASE/post-primary.lock"
flock -n 9 || { echo 'Another continuation owns the queue'; exit 1; }
date -u -Is > "$DRIVER/post-primary-started.txt"

rest() { require_rest_state nginx redis postgresql; }
seal_log() {
    local log=$1 directory
    directory=$(sed -n 's/^RESULT_DIR=//p' "$log" | tail -n 1)
    if [[ "$directory" == "$ROOT/"* ]] && [ -d "$directory" ]; then
        if [ -f "$directory/run.log" ] && python3 - "$directory/run.log" <<'PY'
import os, sys, time
from pathlib import Path
target = str(Path(sys.argv[1]).resolve())
deadline = time.monotonic() + 10
while True:
    opened = False
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            for fd in (proc / 'fd').iterdir():
                try:
                    opened |= os.readlink(fd) == target
                except OSError:
                    pass
        except OSError:
            pass
    if not opened:
        break
    if time.monotonic() > deadline:
        raise SystemExit('Log still open: defer its sealing until final verification')
    time.sleep(0.05)
PY
        then
            sha256sum "$directory/run.log" > "$directory/sha256-closed-run-log.txt"
        fi
    fi
}
run_logged() {
    local name=$1 rc=0
    shift
    "$@" > "$DRIVER/post-$name.out" 2>&1 || rc=$?
    printf '%s\n' "$rc" > "$DRIVER/post-$name.rc"
    seal_log "$DRIVER/post-$name.out"
    printf 'STAGE=%s RC=%s UTC=%s\n' "$name" "$rc" "$(date -u -Is)"
    return "$rc"
}

# This controller was launched once by the parent. Waiting does not change units.
controller=$(< "$DRIVER/corrected-controller.pid")
[[ "$controller" =~ ^[0-9]+$ ]] || exit 2
while kill -0 "$controller" 2>/dev/null; do
    if [ -r "/proc/$controller/cmdline" ]; then
        commandline=$(tr '\0' ' ' < "/proc/$controller/cmdline")
        [[ "$commandline" == *driver_primary_corrected_v005.sh* ]] || {
            echo 'Controller PID was reused; refusing to guess whether primary finished'; exit 2;
        }
    fi
    sleep 30
done
[ -f "$DRIVER/primary-corrected-finished.txt" ] || { echo 'Primary queue did not finish'; exit 2; }
[ -f "$DRIVER/primary-corrected-driver-exit.txt" ] || { echo 'Primary exit status missing'; exit 2; }
[ "$(< "$DRIVER/primary-corrected-driver-exit.txt")" = 0 ] || { echo 'Primary controller failed'; exit 2; }
rest

first_rc=0
run_logged first-look python3 "$ANALYSIS/analyze_v005.py" || first_rc=$?
if [ "$first_rc" = 0 ] && [ -f "$ANALYSIS/extension-plan.json" ]; then
    extension_rc=0
    run_logged extensions bash "$BASE/driver_extensions_v005.sh" "$ANALYSIS/extension-plan.json" || extension_rc=$?
    printf '%s\n' "$extension_rc" > "$DRIVER/extension-queue-status.txt"
else
    echo 'FIRST_LOOK_UNAVAILABLE: no adaptive measurements authorized by an invalid/missing analysis' \
        > "$DRIVER/extension-queue-status.txt"
fi
rest
run_logged final-analysis python3 "$ANALYSIS/analyze_v005.py" --final || true

# These are separate descriptive/exploratory observations, not new selection goals.
export NGINX_PROFILES='P0 P1r P1c P1cADMIN P1cPTRACE P1cDAC P1cCHROOT'
run_logged capability-contract bash "$HERE/functional_ext_v005.sh" nginx || true
rest
run_logged capability-ablation bash "$HERE/scenarios_v005.sh" nginx || true
unset NGINX_PROFILES
rest
run_logged mount-check bash "$MOUNT/supplement_mount_states_v005.sh" check || true
if [ "$(< "$DRIVER/post-mount-check.rc")" = 0 ]; then
    SLAB_AFTER_PRIMARY=1 run_logged mount-states bash "$MOUNT/supplement_mount_states_v005.sh" run || true
fi
rest

# Only the new package, after every old-service load series. Never upgrades the OS.
install_memcached() {
    local listeners
    ! rpm -q memcached >/dev/null 2>&1 || { echo 'Package appeared since preflight; inspect manually'; return 2; }
    [ "$(systemctl show memcached.service -p LoadState --value)" = not-found ] || {
        echo 'Default memcached unit is no longer absent; preserve it'; return 2;
    }
    listeners=$(ss -H -ltn '( sport = :11211 or sport = :11212 )') || return 2
    [ -z "$listeners" ] || {
        echo 'Memcached ports occupied; do not replace another service'; return 2;
    }
    apt-get -s install memcached > "$DRIVER/memcached-install-plan.txt" 2>&1 || return 2
    grep -Fx '0 upgraded, 1 newly installed, 0 removed and 450 not upgraded.' \
        "$DRIVER/memcached-install-plan.txt" >/dev/null || {
            echo 'Dependency transaction differs from read-only preflight'; return 2;
        }
    [ "$(grep -c '^Inst ' "$DRIVER/memcached-install-plan.txt")" = 1 ] || return 2
    grep '^Inst memcached (1\.6\.42-alt1' "$DRIVER/memcached-install-plan.txt" >/dev/null || return 2
    systemctl mask --runtime memcached.service || return 2
    local rc=0
    apt-get -y install memcached || rc=$?
    systemctl daemon-reload || return 2
    # The default service did not exist before this exact transaction.
    systemctl mask memcached.service || return 2
    systemctl disable memcached.service || echo 'NOTE: default unit remains persistently masked'
    systemctl stop memcached.service || true
    systemctl is-active --quiet memcached.service && return 2
    listeners=$(ss -H -ltn '( sport = :11211 or sport = :11212 )') || return 2
    [ -z "$listeners" ] || {
        echo 'Unexpected new listener: refusing measurements'; return 2;
    }
    systemctl show memcached.service -p LoadState -p ActiveState -p UnitFileState
    rpm -q memcached
    return "$rc"
}

if run_logged memcached-install install_memcached; then
    if run_logged memcached-register bash "$HERE/memcached_stage3_v005.sh" register; then
        reg=$(sed -n 's/^REGISTERED_PARAMETERS=//p' "$DRIVER/post-memcached-register.out" | tail -n 1)
        [[ "$reg" == "$ROOT/memcached-v005-registrations/"* ]] || exit 2
        if run_logged memcached-prepare bash "$HERE/memcached_stage3_v005.sh" prepare "$reg"; then
            if run_logged memcached-functional bash "$HERE/memcached_stage3_v005.sh" check "$reg" \
                && run_logged memcached-probe bash "$HERE/memcached_stage3_v005.sh" probe "$reg"; then
                contract=$(sed -n 's/^RESULT_DIR=//p' "$DRIVER/post-memcached-functional.out" | tail -n 1)
                probe=$(sed -n 's/^RESULT_DIR=//p' "$DRIVER/post-memcached-probe.out" | tail -n 1)
                load_rc=0
                run_logged memcached-load-1 bash "$HERE/memcached_stage3_v005.sh" measure "$reg" "$contract" 1 || load_rc=$?
                load_log="$DRIVER/post-memcached-load-1.out"
                if [ "$load_rc" != 0 ]; then
                    load_rc=0
                    run_logged memcached-load-1-retry bash "$HERE/memcached_stage3_v005.sh" measure "$reg" "$contract" 1 || load_rc=$?
                    load_log="$DRIVER/post-memcached-load-1-retry.out"
                fi
                if [ "$load_rc" = 0 ]; then
                    bench=$(sed -n 's/^RESULT_DIR=//p' "$load_log" | tail -n 1)
                    if run_logged memcached-first-look python3 "$ANALYSIS/analyze_memcached_v005.py" \
                        --functional "$contract" --probe "$probe" --bench "$bench"; then
                        decision="$ANALYSIS/memcached-analysis-first-look/extension-decision.json"
                        if [ -f "$decision" ] && python3 - "$decision" <<'PY'
import json, sys
raise SystemExit(not json.load(open(sys.argv[1]))['needs_extension'])
PY
                        then
                            load_rc=0
                            run_logged memcached-load-2 bash "$HERE/memcached_stage3_v005.sh" measure "$reg" "$contract" 2 || load_rc=$?
                            load_log="$DRIVER/post-memcached-load-2.out"
                            if [ "$load_rc" != 0 ]; then
                                load_rc=0
                                run_logged memcached-load-2-retry bash "$HERE/memcached_stage3_v005.sh" measure "$reg" "$contract" 2 || load_rc=$?
                                load_log="$DRIVER/post-memcached-load-2-retry.out"
                            fi
                            if [ "$load_rc" = 0 ]; then
                                extension=$(sed -n 's/^RESULT_DIR=//p' "$load_log" | tail -n 1)
                                run_logged memcached-final-analysis python3 "$ANALYSIS/analyze_memcached_v005.py" \
                                    --functional "$contract" --probe "$probe" --bench "$bench" --extension "$extension" || true
                            else
                                echo 'NO_VALID_EXTENSION: no third look' > "$DRIVER/memcached-analysis-limitation.txt"
                            fi
                        fi
                    fi
                fi
            fi
            run_logged memcached-cleanup bash "$HERE/memcached_stage3_v005.sh" cleanup "$reg" || true
        fi
    fi
fi
rest
date -u -Is > "$DRIVER/post-primary-finished.txt"
echo 'POST_PRIMARY_QUEUE_FINISHED: parent must verify and write the final report'
