#!/usr/bin/env bash
# Supplemental E2/E6 observations. Separate from primary goals/selection data.
# All targets are newly created synthetic subdirectories of the existing website.
set -Eeuo pipefail
HERE=$(dirname "$(readlink -f "$0")")
. "$HERE/slab_common_v005.sh"
[ "$(id -u)" = 0 ] || exit 1
require_rest_state nginx
OUT="$ROOT/supplement-goals-v005/$(date +%Y%m%d-%H%M%S)"
GPROBE=/usr/local/bin/slab-g-supplement-v005.sh
FDPROBE=/usr/local/bin/slab-inherited-fd-v005.py
DROPIN=/etc/systemd/system/slab-nginx.service.d/96-inservice-goal-v005.conf
N_ROOT="$SITE/g1-supplement-v005-root"
N_LAB="$SITE/g1-supplement-v005-labweb"
for path in "$GPROBE" "$FDPROBE" "$DROPIN" "$N_ROOT" "$N_LAB"; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || { echo "CONFLICT: $path"; exit 1; }
done
mkdir -p "$OUT"
exec > >(tee "$OUT/run.log") 2>&1
echo 'service,goal,dac,context,profile,outcome,detail' > "$OUT/goals.csv"
cleanup() {
    local rc=$?
    trap - EXIT
    set +e
    rm -f -- "$DROPIN" "$GPROBE" "$FDPROBE"
    for path in "$N_ROOT" "$N_LAB"; do
        # Exact validated fixture paths only, never the website root.
        if [ -d "$path" ]; then
            rm -f -- "$path/document.txt" "$path/.g1-fd-v005" "$path"/.g1-*
            rmdir -- "$path" || rc=2
        fi
    done
    chown root:root /var/log/slab-nginx-error.log
    chmod 0644 /var/log/slab-nginx-error.log
    restore_rest_state nginx || rc=2
    ( cd "$OUT" && sha256sum goals.csv > sha256.txt )
    echo "RESULT_DIR=$OUT"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Reuse, byte for byte, the existing reviewed attack helper; do not source the
# scenario runner (which would execute its top-level actions).
awk "/^    cat > .*<<'PROBEOF'/ {copy=1; next} /^PROBEOF$/ {copy=0} copy" \
    "$HERE/scenarios_v005.sh" > "$GPROBE"
grep -q '^mode=\$1' "$GPROBE"
chmod 0755 "$GPROBE"
install -m 0755 "$HERE/inherited_fd_v005.py" "$FDPROBE"
cp "$GPROBE" "$FDPROBE" "$OUT/"
mkdir "$N_ROOT" "$N_LAB"
chown root:root "$N_ROOT"
chown labweb:labweb "$N_LAB"
chmod 0755 "$N_ROOT" "$N_LAB"
reset_document() {
    rm -f -- "$1/document.txt" "$1/.g1-fd-v005" "$1"/.g1-*
    printf 'G1_ORIGINAL_DOCUMENT\n' > "$1/document.txt"
    chown root:root "$1/document.txt"
    chmod 0444 "$1/document.txt"
}
record_cell() {
    local method=$1 profile=$2 dac=$3 context=$4 dir=$5 output=$6 code result outcome=UNEXPECTED
    code=$(curl --max-time 5 -sS -o "$OUT/http-body.txt" -w '%{http_code}' \
        "http://127.0.0.1:808/$(basename "$dir")/document.txt" 2>/dev/null || true)
    result=$(printf '%s\n' "$output" | sed -n 's/^G_RESULT=\([A-Z]*\).*/\1/p' | tail -n 1)
    if [ "$result" = ALLOWED ] && [ "$code" = 200 ] && grep -qx G1_REPLACED_DOCUMENT "$OUT/http-body.txt"; then
        outcome=ACHIEVED
    elif [ "$result" = BLOCKED ] && [ "$code" = 200 ] && grep -qx G1_ORIGINAL_DOCUMENT "$OUT/http-body.txt"; then
        outcome=BLOCKED
    fi
    local detail
    detail=$(printf '%s' "http=$code method=$method $output" | tr ',\r\n' ';  ')
    printf 'nginx,G1-replace-document,%s,%s,%s,%s,%s\n' "$dac" "$context" "$profile" "$outcome" "$detail" >> "$OUT/goals.csv"
    echo "RESULT method=$method profile=$profile dac=$dac context=$context outcome=$outcome"
}
for profile in P0 P1 P1r P1c P2 P4 P5 P6; do
    for dac in rootown labweb; do
        if [ "$dac" = rootown ]; then dir=$N_ROOT; else dir=$N_LAB; fi
        for context in master worker; do
            reset_document "$dir"
            # Unit ExecStartPost runs with the real unit namespace/properties.
            # Worker context is an explicit initgroups/setgid/setuid transition.
            if [ "$context" = master ]; then
                printf '[Service]\nExecStartPost=%s write %s\n' "$GPROBE" "$dir" > "$DROPIN"
            else
                printf '[Service]\nExecStartPost=/usr/bin/python3 %s labweb %s write %s\n' \
                    "$DROPUSER" "$GPROBE" "$dir" > "$DROPIN"
            fi
            since="@$(date +%s)"
            rc=0; svc_apply nginx "$profile" || rc=$?
            journalctl -u slab-nginx.service --since "$since" -o cat --no-pager \
                > "$OUT/inservice-$profile-$dac-$context.txt"
            output=$(cat "$OUT/inservice-$profile-$dac-$context.txt")
            record_cell inservice "$profile" "$dac" "$context" "$dir" "$output"
            echo "UNIT_START_RC=$rc"
            rm -f -- "$DROPIN"
            svc_apply nginx "$profile" || { echo 'SUPPLEMENT: unit failed without probe'; exit 1; }
            reset_document "$dir"
            file=P0
            [ "$profile" = P0 ] || file="$(svc_profiles nginx)/$profile.conf"
            props_from_profile "$file"
            ident=()
            [ "$context" = master ] || ident=(-p User=labweb -p Group=labweb)
            # systemd's OpenFile opens the descriptor before applying the
            # sandbox. If directory FDs are unsupported, the missing G_RESULT
            # is UNEXPECTED, not evidence of blocking.
            rc=0
            systemd-run --quiet --wait --pipe --collect --unit="slab-v005-fd-$$-$RANDOM" \
                -p Type=exec -p "OpenFile=$dir:inherited:read-only" \
                ${ident[@]+"${ident[@]}"} ${PROPS[@]+"${PROPS[@]}"} \
                /usr/bin/python3 "$FDPROBE" > "$OUT/fd-$profile-$dac-$context.txt" 2>&1 || rc=$?
            output=$(cat "$OUT/fd-$profile-$dac-$context.txt")
            record_cell inherited-fd "$profile" "$dac" "fd-$context" "$dir" "$output"
            echo "FD_LAUNCH_RC=$rc"
        done
    done
done
