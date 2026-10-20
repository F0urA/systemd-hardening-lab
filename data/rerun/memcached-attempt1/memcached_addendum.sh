#!/usr/bin/env bash
# memcached_addendum.sh -- the memcached part of run_stage3.sh (phase_memcached),
# run separately after the sealed run of 2026-10-19/20. In that run
# install_memcached refused the package: apt-get -s prints the ALT version as
# "1.6.42-alt1:p11+418735.100.1.1@1779279920" and the whole string was compared
# with "1.6.42-alt1". Here only the part before ':' is compared; everything else
# is phase_memcached unchanged. The sealed results (SHA256-CLOSED-RESULTS.txt,
# results_v005-closed.tar.gz) are not touched: files written now go to a second
# manifest and a second archive.
set -Eeuo pipefail
export LC_ALL=C TZ=UTC
BASE=$(readlink -m "${SLAB_BASE:-/root/systemd-hardening-lab}")
export SLAB_BASE=$BASE
HERE="$BASE/frozen-timing/v005/scripts_v005"
ANALYSIS="$BASE/post-analysis"
export SLAB_RESULTS_ROOT="$BASE/results_v005"
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: run as root on the laboratory VM'; exit 1; }
. "$HERE/slab_common_v005.sh"
DRIVER="$ROOT/driver"
[ -f "$DRIVER/seal-started.txt" ] && [ -f "$ROOT/SHA256-CLOSED-RESULTS.txt" ] || { echo 'The main run is not sealed'; exit 2; }
( set -o noclobber; date -u -Is > "$DRIVER/addendum-memcached-started.txt" ) 2>/dev/null || {
    echo 'The memcached addendum was already started'; exit 2;
}
sha256sum "$0" "$HERE/memcached_stage3_v005.sh" "$ANALYSIS/analyze_memcached_v005.py" > "$DRIVER/addendum-memcached-source-sha256.txt"

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
    ( set -o noclobber; "$@" > "$DRIVER/addendum-$name.out" 2>&1 ) || rc=$?
    printf '%s\n' "$rc" > "$DRIVER/addendum-$name.rc"
    seal_log "$DRIVER/addendum-$name.out"
    printf 'STAGE=%s RC=%s UTC=%s\n' "$name" "$rc" "$(date -u -Is)"
    return "$rc"
}
install_memcached() {
    local listeners plan="$DRIVER/addendum-memcached-install-plan.txt" version
    ! rpm -q memcached >/dev/null 2>&1 || { echo 'memcached is already installed; inspect manually'; return 2; }
    [ "$(systemctl show memcached.service -p LoadState --value)" = not-found ] || {
        echo 'Default memcached unit already exists; preserve it'; return 2;
    }
    listeners=$(ss -H -ltn '( sport = :11211 or sport = :11212 )') || return 2
    [ -z "$listeners" ] || { echo 'Memcached ports occupied'; return 2; }
    apt-get -s install memcached > "$plan" 2>&1 || return 2
    grep -E '^0 upgraded, [0-9]+ newly installed, 0 removed' "$plan" >/dev/null || {
        echo 'Installation would upgrade or remove packages; inspect manually'; return 2;
    }
    version=$(sed -n 's/^Inst memcached (\([^ ]*\) .*/\1/p' "$plan")
    [ -n "$version" ] || return 2
    echo "APT_VERSION=$version"
    # The correction: ALT appends ":<branch>+<build>@<time>" to version-release.
    if [ "${version%%:*}" != 1.6.42-alt1 ]; then
        echo "memcached ${version%%:*} differs from 1.6.42-alt1 of the executed run"; return 2
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
memcached_load() {
    local look=$1 rc=0
    MEMCACHED_LOG="$DRIVER/addendum-memcached-load-$look.out"
    run_logged "memcached-load-$look" bash "$HERE/memcached_stage3_v005.sh" measure "$REG" "$CONTRACT" "$look" || rc=$?
    if [ "$rc" != 0 ]; then
        rc=0
        MEMCACHED_LOG="$DRIVER/addendum-memcached-load-$look-retry.out"
        run_logged "memcached-load-$look-retry" bash "$HERE/memcached_stage3_v005.sh" measure "$REG" "$CONTRACT" "$look" || rc=$?
    fi
    return "$rc"
}
phase_memcached() {
    run_logged memcached-install install_memcached || return 0
    run_logged memcached-register bash "$HERE/memcached_stage3_v005.sh" register || return 0
    REG=$(sed -n 's/^REGISTERED_PARAMETERS=//p' "$DRIVER/addendum-memcached-register.out" | tail -n 1)
    [[ "$REG" == "$ROOT/memcached-v005-registrations/"* ]] || exit 2
    run_logged memcached-prepare bash "$HERE/memcached_stage3_v005.sh" prepare "$REG" || return 0
    if run_logged memcached-functional bash "$HERE/memcached_stage3_v005.sh" check "$REG" \
        && run_logged memcached-probe bash "$HERE/memcached_stage3_v005.sh" probe "$REG"; then
        CONTRACT=$(sed -n 's/^RESULT_DIR=//p' "$DRIVER/addendum-memcached-functional.out" | tail -n 1)
        local probe bench extension decision
        probe=$(sed -n 's/^RESULT_DIR=//p' "$DRIVER/addendum-memcached-probe.out" | tail -n 1)
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
                        echo 'NO_VALID_EXTENSION: no third look' > "$DRIVER/addendum-memcached-analysis-limitation.txt"
                    fi
                fi
            fi
        fi
    fi
    run_logged memcached-cleanup bash "$HERE/memcached_stage3_v005.sh" cleanup "$REG" || true
}

require_rest_state nginx redis postgresql
phase_memcached
require_rest_state nginx redis postgresql
date -u -Is > "$DRIVER/addendum-memcached-finished.txt"

# Second seal: every regular file under results_v005 that the first manifest
# does not list, in the same "<sha256>  ./<path>" format, plus one archive.
manifest="$ROOT/SHA256-ADDENDUM-MEMCACHED.txt" archive="$BASE/results_v005-memcached-addendum.tar.gz"
python3 - "$ROOT" > "$BASE/SHA256-ADDENDUM-MEMCACHED.tmp" <<'MANIFEST_PY'
import hashlib, os, sys
root = sys.argv[1]
closed = {line.split('  ./', 1)[1].rstrip('\n') for line in open(os.path.join(root, 'SHA256-CLOSED-RESULTS.txt'))}
names = []
for directory, _, files in os.walk(root):
    for name in files:
        path = os.path.join(directory, name)
        relative = os.path.relpath(path, root).replace(os.sep, '/')
        if not os.path.islink(path) and relative not in closed and relative not in (
                'SHA256-CLOSED-RESULTS.txt', 'SHA256-ADDENDUM-MEMCACHED.txt'):
            names.append(relative)
for relative in sorted(names, key=lambda n: n.encode()):
    with open(os.path.join(root, relative), 'rb') as stream:
        print(f'{hashlib.file_digest(stream, "sha256").hexdigest()}  ./{relative}')
MANIFEST_PY
mv "$BASE/SHA256-ADDENDUM-MEMCACHED.tmp" "$manifest"
files=(results_v005/SHA256-ADDENDUM-MEMCACHED.txt memcached_addendum.sh)
while IFS= read -r line; do files+=("results_v005/${line#*  ./}"); done < "$manifest"
for path in "$ANALYSIS"/memcached-analysis-*; do
    [ -e "$path" ] && files+=("post-analysis/${path#"$ANALYSIS"/}")
done
tar -czf - -C "$BASE" "${files[@]}" > "$archive"
( cd "$BASE" && sha256sum "$(basename "$archive")" ) | tee "$archive.sha256"
echo "ADDENDUM_SEALED: $(wc -l < "$manifest") files; copy $archive to the host"
