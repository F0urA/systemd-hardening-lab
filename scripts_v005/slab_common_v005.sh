#!/usr/bin/env bash
# slab_common_v005.sh -- common functions of the v005 experiment scripts.
# Source this file; do not execute it.

export LC_ALL=C

ROOT=/root/systemd-lab-results
PROBE=/usr/local/bin/isolation_probe.py
XPROBE=/usr/local/bin/extended_probe.py
FP=/usr/local/bin/slab_fp_v005.sh
INSERVICE=/usr/local/bin/slab_inservice_v005.sh
DROPUSER=/usr/local/bin/slab_dropuser_v005.py
SITE=/var/lib/systemd-lab/nginx-www

svc_unit()     { echo "slab-$1.service"; }
svc_profiles() { echo "$ROOT/$1/profiles"; }
svc_dropin()   { echo "/etc/systemd/system/slab-$1.service.d/90-hardening.conf"; }
svc_user() {
    case "$1" in
        nginx) echo labweb ;;
        redis) echo labredis ;;
        postgresql) echo labpg ;;
        *) echo "UNKNOWN SERVICE: $1" >&2; return 1 ;;
    esac
}

# Functional health used as the minimal gate after every profile change.
svc_health() {
    local svc=$1 i code body
    body=$(mktemp)
    for i in $(seq 1 15); do
        case "$svc" in
            nginx)
                code=$(curl --max-time 3 -sS -o "$body" -w '%{http_code}' \
                    http://127.0.0.1:808/ 2>/dev/null || true)
                if [ "$code" = 200 ] && cmp -s "$body" "$SITE/index.html"; then
                    rm -f "$body"; return 0
                fi ;;
            redis)
                if [ "$(redis-cli -p 6380 PING 2>/dev/null || true)" = PONG ]; then
                    rm -f "$body"; return 0
                fi ;;
            postgresql)
                if pg_isready -h 127.0.0.1 -p 55432 -U labpg -d postgres >/dev/null 2>&1; then
                    rm -f "$body"; return 0
                fi ;;
        esac
        sleep 1
    done
    rm -f "$body"
    return 1
}

# svc_apply SERVICE PROFILE -- PROFILE is P0 (no drop-in) or the name of a
# saved file <profiles>/<PROFILE>.conf. Returns non-zero if the service does
# not start or fails the health check (F=0).
svc_apply() {
    local svc=$1 profile=$2 unit dropin file
    unit=$(svc_unit "$svc")
    dropin=$(svc_dropin "$svc")
    file="$(svc_profiles "$svc")/$profile.conf"
    if [ "$profile" = P0 ]; then
        rm -f "$dropin"
    else
        [ -f "$file" ] || { echo "MISSING PROFILE: $file"; return 1; }
        mkdir -p "$(dirname "$dropin")"
        cp "$file" "$dropin"
    fi
    systemctl daemon-reload
    systemctl reset-failed "$unit" 2>/dev/null || true
    systemctl restart "$unit" || return 1
    svc_health "$svc"
}

# props_from_profile FILE|P0 -- fills the global array PROPS with
# "-p Setting=value" pairs read from the saved profile, so that the model
# process gets exactly the settings of the drop-in (no hand-copied lists).
props_from_profile() {
    PROPS=()
    local file=$1 setting
    if [ "$file" = P0 ]; then return 0; fi
    [ -f "$file" ] || { echo "MISSING PROFILE: $file" >&2; return 1; }
    while IFS= read -r setting || [ -n "$setting" ]; do
        setting=${setting%$'\r'}
        case "$setting" in ''|'[Service]'|\#*) continue ;; esac
        if [[ "$setting" == *=* ]]; then
            PROPS+=(-p "$setting")
        else
            echo "ERROR: unsupported profile line: $setting" >&2
            return 1
        fi
    done < "$file"
}

target_pid() {
    local pid
    pid=$(systemctl show "lab-proc-target@$1.service" -p MainPID --value)
    if [ -z "$pid" ] || [ "$pid" = 0 ]; then
        echo "ERROR: lab-proc-target@$1.service is not running" >&2
        return 1
    fi
    echo "$pid"
}

# run_transient LABEL USER FILE|P0 OUTFILE -- runs the common probe helper in
# a transient unit. P0 uses the same launcher with an empty property list.
run_transient() {
    local label=$1 user=$2 file=$3 out=$4 target rc=0
    target=$(target_pid "$user") || return 1
    props_from_profile "$file" || return 1
    local -a ident=()
    if [ "$user" != root ]; then ident=(-p "User=$user" -p "Group=$user"); fi
    systemd-run --quiet --wait --pipe --collect \
        --unit="slab-v005-$label-$$" -p Type=exec \
        ${ident[@]+"${ident[@]}"} ${PROPS[@]+"${PROPS[@]}"} \
        "$INSERVICE" "$label" "$target" > "$out" 2>&1 || rc=$?
    return "$rc"
}

# require_rest_state SERVICE... -- the stand must be in its documented rest
# state: service active, live drop-in identical to the saved P4, nothing else.
require_rest_state() {
    local svc unit dropin p4 other
    for svc in "$@"; do
        unit=$(svc_unit "$svc")
        dropin=$(svc_dropin "$svc")
        p4="$(svc_profiles "$svc")/P4.conf"
        [ -f "$p4" ] || { echo "ERROR: $p4 is missing"; return 1; }
        cmp -s "$p4" "$dropin" || {
            echo "ERROR: live drop-in of $unit is not the saved P4"; return 1;
        }
        other=$(find "$(dirname "$dropin")" -maxdepth 1 -type f \
            ! -name 90-hardening.conf -print -quit)
        [ -z "$other" ] || { echo "ERROR: additional drop-in found: $other"; return 1; }
        systemctl is-active --quiet "$unit" || { echo "ERROR: $unit is not active"; return 1; }
    done
}

# restore_rest_state SERVICE... -- best effort, for EXIT traps.
restore_rest_state() {
    local svc rc=0
    for svc in "$@"; do
        if svc_apply "$svc" P4; then
            echo "RESTORE_P4 $svc=PASS"
        else
            echo "RESTORE_P4 $svc=FAIL -- inspect the unit and the journal"
            rc=2
        fi
    done
    return "$rc"
}

require_files() {
    local f
    for f in "$@"; do
        [ -e "$f" ] || { echo "MISSING: $f (see README_v005.md, installation)"; return 1; }
    done
}

# section FILE NAME -- prints the lines between "## NAME" and the next "## ".
section() {
    awk -v s="## $2" '$0 == s { f = 1; next } /^## / { f = 0 } f' "$1"
}

# status_lines FILE -- "ID STATUS" of every micro-probe, sorted.
status_lines() {
    grep -E '^([A-Z]+-[0-9]+|X[0-9])[[:space:]]+(ALLOWED|BLOCKED|N/A|ERROR)' "$1" \
        | awk '{ print $1, $2 }' | sort
}
