#!/usr/bin/env bash
# Resume only the previously unexecuted retry/tail of the original v005 plan.
set -Eeuo pipefail
export LC_ALL=C TZ=UTC
BASE=${SLAB_BASE:-/root/systemd-hardening-lab}
HERE="$BASE/frozen-timing/v005/scripts_v005"
export SLAB_RESULTS_ROOT="$BASE/results_v005"
. "$HERE/slab_common_v005.sh"
DRIVER="$ROOT/driver"
LEDGER="$DRIVER/primary-corrected-ledger.csv"
TRANSPORT="$BASE/resume_transport_v005.py"
export PIN=1 SERVER_CPU=0 CLIENT_CPUS=1-3 KEEPALIVE=0 STALL_MS=500
export NGINX_N=100000 NGINX_C=25 REDIS_N=3000000 REDIS_THREADS=3 PG_T=60
exec 9>"$BASE/primary-resume-v005.lock"
flock -n 9 || { echo 'Another primary resume owns the lock'; exit 2; }
[ ! -e "$DRIVER/primary-resume-started.txt" ] && [ ! -L "$DRIVER/primary-resume-started.txt" ] || {
    echo 'Resume already claimed: do not repeat the permitted retry'; exit 2;
}
require_files "$TRANSPORT" "$HERE/benchmark_v005.sh" "$BASE/inspect_series_v005.py"
transport_pin=$(python3 "$TRANSPORT" primary-check)
started=0
cleanup() {
    local status=$?
    trap - EXIT
    set +e
    # Restoration belongs to this R3 scope only. After its successful release,
    # a later actor's reservation is never cleared by the EXIT hook.
    python3 "$TRANSPORT" primary-restore "$transport_pin" --phase EXIT \
        > "$DRIVER/resume-primary-transport-exit.out" 2>&1 || status=2
    if [ "$started" = 1 ]; then printf '%s\n' "$status" > "$DRIVER/primary-corrected-driver-exit.txt"; fi
    exit "$status"
}
trap cleanup EXIT

# No load/data analysis here: exact closed prefix, archive proof and dead old
# controllers. The parent restores P4/clock and creates these receipts first.
python3 - "$BASE" "$ROOT" <<'PREFLIGHT_PY'
import csv, hashlib, os, re, shlex, sys
from datetime import datetime
from pathlib import Path, PurePosixPath
base, root = map(Path, sys.argv[1:])
driver = root / 'driver'
archive = driver / 'closed-before-resume-20261013'
expected_hashes = {
    'backup':'58816775bae35a4ff44a217f79b1cccfbe43583318fcb369df21669f5d928b9d',
    'manifest':'1050c79e966b28d746a3cffaf196c0f7eb6387ae84426d9e9fec3236f98a00da',
    'ledger':'9b048e9c6d2387437d1e0a4d6d1ce3954766dd7e763ecb4e1af5313a800b3b55',
}
def digest(path):
    if path.is_symlink() or path.resolve(strict=True) != path:
        raise ValueError('unsafe proof path: '+str(path))
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()
def require(condition, message):
    if not condition: raise ValueError(message)
require(base.resolve(strict=True) == base and root.resolve(strict=True) == root,
        'unexpected canonical experiment root')
receipt = driver / 'resume-backup-verified.txt'
values = re.findall(r'\b[0-9a-f]{64}\b', receipt.read_text().lower())
require(len(values) == 3 and set(values) == set(expected_hashes.values()), 'missing/different parent backup receipt')
require(digest(base / 'closed-before-resume-20261013.tar.gz') == expected_hashes['backup'], 'archive checksum mismatch')
require(digest(archive / 'SHA256-CLOSED-RESULTS.txt') == expected_hashes['manifest'], 'original closed manifest mismatch')
ledger = driver / 'primary-corrected-ledger.csv'
require(digest(ledger) == expected_hashes['ledger'] and
        digest(archive / ledger.name) == expected_hashes['ledger'], 'closed ledger prefix changed or not archived')
for name in ('primary-corrected-driver-exit.txt','post-primary-driver-exit.txt'):
    require((archive / name).is_file() and not (archive / name).is_symlink() and
            (archive / name).read_text().strip() == '2', 'original terminal marker not archived: '+name)
fields = ['stage','start_guest_utc','end_guest_utc','exit_status','result_directory']
with ledger.open(newline='', encoding='utf-8-sig') as file:
    reader = csv.DictReader(file); rows = list(reader)
    require(reader.fieldnames == fields, 'wrong original ledger schema')
require([(r.get('stage'),r.get('exit_status')) for r in rows] ==
        [('R1-nginx','0'),('R2-redis','0'),('R3-postgresql','2')], 'resume requires exactly R1=0/R2=0/R3=2; no retry/tail')
paths = set()
for row in rows:
    require(None not in row and all(row.get(key) is not None for key in fields), 'truncated ledger')
    start, end = (datetime.fromisoformat(row[key]) for key in ('start_guest_utc','end_guest_utc'))
    require(start.tzinfo is not None and end.tzinfo is not None and end >= start, 'invalid original timestamps')
    remote = row['result_directory']; prefix = str(root) + '/'
    require(remote.startswith(prefix), 'foreign result directory')
    suffix = PurePosixPath(remote[len(prefix):])
    require(len(suffix.parts)==3 and suffix.parts[1]=='benchmark-v005' and
            suffix.parts[0] in ('nginx','redis','postgresql') and
            re.fullmatch(r'\d{8}-\d{6}',suffix.parts[2]) and '..' not in suffix.parts,
            'unsafe original result path')
    require(remote not in paths, 'duplicate original result directory'); paths.add(remote)
for name in ('primary-corrected-finished.txt','R4-condition.txt','extension-ledger.csv',
             'extensions-finished.txt','extension-claim-v005'):
    require(not (driver / name).exists() and not (driver / name).is_symlink(), 'unexpected later-stage artifact: '+name)
require(not (base / 'post-analysis' / 'extension-plan.json').exists(), 'first formal look already occurred')
for path in driver.glob('corrected-*'):
    name = path.name
    require(not any(stem in name for stem in ('R3-postgresql-retry','R5-nginx-light','R4-pilot','R4-nginx-nonsaturated')),
            'unlogged retry/tail output already exists; do not overwrite: '+name)
old_names = ('driver_primary_corrected_v005.sh','driver_post_primary_v005.sh')
for proc in Path('/proc').iterdir():
    if not proc.name.isdecimal(): continue
    try:
        argv = [value.decode('utf-8','replace') for value in (proc/'cmdline').read_bytes().split(b'\0') if value]
        if not argv: continue
        cwd = str((proc/'cwd').resolve(strict=True))
        tokens = list(argv)
        for value in argv:
            try: tokens.extend(shlex.split(value))
            except ValueError: pass
        require(not any(str(base/name) in tokens or cwd==str(base) and
                        any(value in tokens for value in (name,'./'+name)) for name in old_names),
                'original controller still live: '+proc.name)
    except FileNotFoundError: pass
print('VALID_CLOSED_PREFIX_AND_PARENT_BACKUP; no statistical look performed')
PREFLIGHT_PY
require_rest_state nginx redis postgresql
( set -o noclobber; date -u -Is > "$DRIVER/primary-resume-started.txt" )
started=1
sha256sum "$0" "$TRANSPORT" "$HERE/benchmark_v005.sh" "$HERE/slab_common_v005.sh" \
    > "$DRIVER/primary-resume-source-sha256.txt"

fresh_result_timestamp() {
    local svc=$1 directory i
    for i in 1 2 3 4 5; do
        directory="$ROOT/$svc/benchmark-v005/$(date +%Y%m%d-%H%M%S)"
        [ -e "$directory" ] || [ -L "$directory" ] || return 0
        sleep 1
    done
    echo 'No fresh output timestamp; retain failed raw and stop'; exit 2
}
run_attempt() {
    local name=$1 svc=$2 blocks=$3 start rc=0 output logfile
    shift 3
    [ "$(awk -F, -v n="$name" '$1==n {c++} END {print c+0}' "$LEDGER")" = 0 ] || {
        echo "Attempt already recorded: $name"; exit 2;
    }
    logfile="$DRIVER/corrected-$name.out"
    [ ! -e "$logfile" ] && [ ! -L "$logfile" ] || { echo "Retain existing $logfile; do not overwrite"; exit 2; }
    fresh_result_timestamp "$svc"
    start=$(date -u -Is)
    ( set -o noclobber; bash "$HERE/benchmark_v005.sh" "$svc" "$blocks" "$@" > "$logfile" 2>&1 ) || rc=$?
    output=$(sed -n 's/^RESULT_DIR=//p' "$logfile" | tail -n 1)
    printf '%s,%s,%s,%s,%s\n' "$name" "$start" "$(date -u -Is)" "$rc" "$output" >> "$LEDGER"
    echo "STAGE=$name RC=$rc RESULT_DIR=$output"
    # If cleanup failed, EXIT restores only our temporary transport scope.
    require_rest_state nginx redis postgresql || exit 2
    LAST_STAGE_RC=$rc
    LAST_STAGE_DIRECTORY=$output
}
run_stage() {
    local name=$1
    shift
    run_attempt "$name" "$@"
    if [ "$LAST_STAGE_RC" != 0 ]; then run_attempt "$name-retry" "$@"; fi
}

# This is the original first R3 attempt's one unconsumed whole-series retry.
# It intentionally bypasses run_stage: no R3-retry-retry can exist.
run_attempt R3-postgresql-retry postgresql 10 P1 P2 P1d P4 P6
python3 "$TRANSPORT" primary-restore "$transport_pin" --phase AFTER_R3 \
    > "$DRIVER/resume-primary-transport-after-R3.out" 2>&1
require_rest_state nginx redis postgresql
run_stage R5-nginx-light nginx 60 P1 P2 P1r

chosen=
for concurrency in 1 2 4 8 16; do
    export NGINX_C=$concurrency
    run_stage "R4-pilot-c$concurrency" nginx 3 P4
    # The successful latest attempt, including -retry, not the old awk bug.
    [ "$LAST_STAGE_RC" = 0 ] && [ -n "$LAST_STAGE_DIRECTORY" ] || continue
    entry=$LAST_STAGE_DIRECTORY
    python3 "$BASE/inspect_series_v005.py" "$entry" --expect-blocks 3 --expect-profiles P0,P4 \
        > "$DRIVER/R4-pilot-c$concurrency.json" || continue
    if python3 - "$entry/results.csv" <<'RANGE_PY'
import csv, sys
with open(sys.argv[1], newline='') as file:
    rows = [row for row in csv.DictReader(file) if row['profile']=='P0']
raise SystemExit(not (len(rows)==3 and all(40 <= float(row['cpu_pct']) <= 70 for row in rows)))
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
date -u -Is > "$DRIVER/primary-corrected-finished.txt"
echo 'PRIMARY_RESUME_FINISHED: original remainder only; formal first look is still pending'
