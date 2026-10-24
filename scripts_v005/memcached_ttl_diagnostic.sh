#!/usr/bin/env bash
# Diagnostic after the experiment (protocol_memcached_ttl.md): why P1 failed the
# expiration check of the memcached contract once in data/rerun/memcached.
# Runs on the VM of the repeat, on the memcached fixture prepared there by
# memcached_stage3_v005.sh, from a clean clone of this repository. It does not
# write into results_v005 and leaves the fixture under its saved P4.
#
#   bash /root/src/scripts_v005/memcached_ttl_diagnostic.sh
set -Eeuo pipefail
export LC_ALL=C TZ=UTC
HERE=$(dirname "$(readlink -f "$0")")
SRC=$(dirname "$HERE")
HELPER="$HERE/memcached_ttl_diagnostic.py"
CLIENT="$HERE/memcached_client_v005.py"
BASE=${SLAB_BASE:-/root/systemd-hardening-lab}
ROOT="$BASE/results_v005"
STATE=/var/lib/systemd-lab/memcached-v005-fixture
UNIT=slab-memcached-v005.service
DROPIN_DIR="/etc/systemd/system/$UNIT.d"
DROPIN="$DROPIN_DIR/90-hardening.conf"
PROFILES="$ROOT/memcached/profiles"
ALL=(P0 P1 P2 P4 P6)
ROUNDS=30
SEED=20261021
HB1=0
HB2=0
OUT=
RESTORE=0

die() { echo "ERROR: $*" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || die 'run on the lab VM as root'
for t in git python3 systemctl sha256sum taskset tar journalctl; do command -v "$t" >/dev/null || die "missing tool $t"; done

# the clone: clean, its commit recorded
COMMIT=$(git -C "$SRC" rev-parse HEAD) || die "$SRC is not a git clone"
[ -z "$(git -C "$SRC" status --porcelain)" ] || die "the clone $SRC has local changes"

# the fixture of the repeat, unchanged since its preparation
[ -f "$STATE/owned-v005.txt" ] && [ -f "$STATE/fixture.sha256" ] || die 'memcached fixture of the repeat is missing'
sha256sum -c --quiet "$STATE/fixture.sha256" || die 'fixture unit/profiles changed since preparation'
REG=$(sed -n 's/^registration=//p' "$STATE/owned-v005.txt")
VERSION=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["expected_version"])' "$REG/parameters.json")
registered=$(awk '$2 ~ /memcached_client_v005.py$/ {print $1}' "$REG/code.sha256")
[ "$registered" = "$(sha256sum "$CLIENT" | cut -d' ' -f1)" ] || die 'contract client differs from the registered one'
cmp -s "$PROFILES/P4.conf" "$DROPIN" || die 'fixture is not under its saved P4'
systemctl is-active --quiet "$UNIT" || die 'fixture is not active'

health() {
    local attempt
    for attempt in $(seq 1 15); do
        [ "$(python3 "$CLIENT" version 2>/dev/null || true)" != "$VERSION" ] || return 0
        sleep 1
    done
    return 1
}

apply() {  # as memcached_stage3_v005.sh apply
    if [ "$1" = P0 ]; then rm -f -- "$DROPIN"; else cp "$PROFILES/$1.conf" "$DROPIN"; fi
    systemctl daemon-reload
    systemctl reset-failed "$UNIT" 2>/dev/null || true
    systemctl restart "$UNIT" && health
}

hb_stop() {
    local pid
    for pid in "$HB1" "$HB2"; do
        [ "$pid" -le 0 ] || { kill -TERM "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
    done
    HB1=0; HB2=0
}

finish() {
    local status=$?
    trap - EXIT
    set +e
    hb_stop
    [ "$RESTORE" = 0 ] || if apply P4 && cmp -s "$PROFILES/P4.conf" "$DROPIN"; then echo 'RESTORE_P4 memcached=PASS'; else echo 'RESTORE_P4 memcached=FAIL'; status=2; fi
    if [ -n "$OUT" ]; then
        [ "$status" -eq 0 ] || printf 'failed exit=%s utc=%s\n' "$status" "$(date -u -Is)" > "$OUT/FAILED.txt"
        journalctl -u "$UNIT" --since "@$START" -o short-iso-precise --no-pager > "$OUT/journal.txt" 2>&1
        journalctl -k --since "@$START" -o short-iso-precise --no-pager > "$OUT/kernel.txt" 2>&1
        printf 'finished=%s\n' "$(date -u -Is)" >> "$OUT/source.txt"
        ( cd "$OUT" && find . -type f ! -name sha256-all.txt -print0 | sort -z | xargs -0 sha256sum > sha256-all.txt )
        tar -C "$(dirname "$OUT")" -czf "/tmp/$(basename "$OUT").tar.gz" "$(basename "$OUT")"
        chmod 0644 "/tmp/$(basename "$OUT").tar.gz"
        sha256sum "/tmp/$(basename "$OUT").tar.gz"
        echo "RESULT_DIR=$OUT"
    fi
    exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

OUT="$BASE/diagnostic/memcached-ttl/$(date -u +%Y%m%dT%H%M%SZ)"
[ ! -e "$OUT" ] || die 'result directory already exists'
mkdir -p "$OUT"
START=$(date +%s)
RESTORE=1
{
    printf 'COMMIT=%s\nREGISTRATION=%s\nVERSION=%s\nROUNDS=%s\nSEED=%s\nstarted=%s\n' \
        "$COMMIT" "$REG" "$VERSION" "$ROUNDS" "$SEED" "$(date -u -Is)"
} > "$OUT/source.txt"
{ uname -a; systemctl --version | head -n 1; memcached -V; python3 -V; nproc; chronyc tracking 2>&1 || true; } > "$OUT/platform.txt"
sha256sum "$0" "$HELPER" "$CLIENT" "$HERE/protocol_memcached_ttl.md" "$PROFILES"/*.conf > "$OUT/code.sha256"
printf '%s\n' round order profile expiration contract_before_pass time_to_expiry_s max_gap_ms | paste -sd, > "$OUT/rows.csv"

for round in $(seq 1 "$ROUNDS"); do
    order=0
    while IFS= read -r profile; do
        order=$((order+1))
        apply "$profile" || die "service did not start under $profile"
        rm -f -- "$OUT/hb-server" "$OUT/hb-client"
        taskset -c 0 python3 "$CLIENT" heartbeat --file "$OUT/hb-server" & HB1=$!
        taskset -c 1-3 python3 "$CLIENT" heartbeat --file "$OUT/hb-client" & HB2=$!
        json="$OUT/check-R$round-$profile.json"
        python3 "$HELPER" check --expected-version "$VERSION" --out "$json" || die "check failed to run: $profile"
        hb_stop
        gap=$(cat "$OUT/hb-server" "$OUT/hb-client" | sort -n | tail -n 1)
        python3 "$HELPER" row --out "$json" --round "$round" --order "$order" --profile "$profile" --gap "$gap" >> "$OUT/rows.csv"
        tail -n 1 "$OUT/rows.csv"
    done < <(python3 "$CLIENT" order --seed "$SEED" --block "$round" --profiles "${ALL[@]}")
done
rm -f -- "$OUT/hb-server" "$OUT/hb-client"
python3 "$HELPER" summarize --dir "$OUT"
