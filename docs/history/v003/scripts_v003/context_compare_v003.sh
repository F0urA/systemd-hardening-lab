#!/usr/bin/env bash
# context_compare_v003.sh -- is the model process equivalent to the process
# of the real service? (v003, reviewer remark 3)
#
# For P0 and P4 of every service the script
#   1. applies the profile to the real unit and takes the fingerprint of the
#      real processes (credentials, capabilities incl. CapAmb, NoNewPrivs,
#      seccomp, namespaces, mount table);
#   2. runs the same probe helper in a transient unit built from the same
#      profile file and compares the fingerprints field by field;
#   3. where the service allows it, runs the helper INSIDE the real unit:
#        Nginx      -- ExecStartPost= of the unit (master context) and the
#                      same after initgroups/setgid/setuid to labweb (worker);
#        PostgreSQL -- COPY ... FROM PROGRAM in a real backend;
#        Redis      -- no command-execution primitive, fingerprint only;
#   4. reports whether the 36 probe statuses of the in-service run and of the
#      transient run are identical.
# The live profile is changed during the run and P4 is restored at the end.
set -Eeuo pipefail
HERE=$(dirname "$(readlink -f "$0")")
. "$HERE/slab_common_v003.sh"
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: run as root'; exit 1; }
SERVICES=(nginx redis postgresql)
require_files "$PROBE" "$XPROBE" "$FP" "$INSERVICE" "$DROPUSER"
require_rest_state "${SERVICES[@]}"

OUT="$ROOT/context-v003/$(date +%Y%m%d-%H%M%S)"
PROBE_DROPIN=/etc/systemd/system/slab-nginx.service.d/95-inservice-probe-v003.conf
mkdir -p "$OUT/transient" "$OUT/inservice" "$OUT/real"
exec > >(tee "$OUT/run.log") 2>&1

cleanup() {
    local status=$?
    trap - EXIT
    set +e
    echo
    echo '===== CLEANUP AND RESTORE P4 ====='
    rm -f "$PROBE_DROPIN"
    restore_rest_state "${SERVICES[@]}" || status=2
    echo "RESULT_DIR=$OUT"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fp_table() {  # REAL_FILE OTHER_FILE OTHER_NAME PROFILE
    awk -F': ' -v name="$3" -v prof="$4" '
        NR == FNR { real[$1] = $2; order[++n] = $1; next }
        { other[$1] = $2 }
        END {
            printf "  %-17s %-26s %-26s %s\n", "FIELD", "REAL", name, "VERDICT"
            for (i = 1; i <= n; i++) {
                k = order[i]
                v = "MATCH"
                if (real[k] != other[k])
                    v = (k == "ns_mnt" && prof != "P0") ? "DIFF_EXPECTED" : "DIFF"
                printf "  %-17s %-26s %-26s %s\n", k, real[k], other[k], v
            }
        }' "$1" "$2"
}

mount_diff() {  # REAL_MOUNTS OTHER_MOUNTS DIFF_FILE NAME
    comm -3 <(sort "$1") <(sort "$2") > "$3" || true
    echo "  MOUNT_TABLE real=$(wc -l < "$1") $4=$(wc -l < "$2") differing_lines=$(wc -l < "$3")"
}

status_diff() {  # INSERVICE_FILE TRANSIENT_FILE DIFF_FILE
    local n
    n=$(status_lines "$1" | wc -l)
    if diff <(status_lines "$1") <(status_lines "$2") > "$3"; then
        echo "  PROBE_STATUSES inservice_vs_transient=IDENTICAL ($n probes)"
    else
        echo "  PROBE_STATUSES inservice_vs_transient=DIFFERENT ($n probes), see $3"
        sed 's/^/    /' "$3"
    fi
}

pg_inservice() {  # LABEL TARGET_PID OUTFILE
    psql -h 127.0.0.1 -p 55432 -U labpg -d postgres -v ON_ERROR_STOP=1 -qAt > "$3" 2>&1 <<SQL
CREATE TEMP TABLE slab_out_v003 (n serial, line text);
COPY slab_out_v003 (line) FROM PROGRAM '$INSERVICE $1 $2 2>&1'
    WITH (FORMAT csv, DELIMITER E'\\x01', QUOTE E'\\x02');
SELECT line FROM slab_out_v003 ORDER BY n;
SQL
}

compare_context() {  # CONTEXT USER REAL_PID PROFILE FILE|P0
    local ctx=$1 user=$2 pid=$3 profile=$4 file=$5 base rc=0
    base="$ctx-$profile"
    echo
    echo "----- CONTEXT=$ctx PROFILE=$profile REAL_PID=$pid -----"
    "$FP" "$pid" > "$OUT/real/$base.fp"
    "$FP" --mounts "$pid" > "$OUT/real/$base.mnt"

    run_transient "$ctx-${profile,,}" "$user" "$file" "$OUT/transient/${ctx}__${profile}.txt" || rc=$?
    echo "  TRANSIENT_RC=$rc"
    section "$OUT/transient/${ctx}__${profile}.txt" FINGERPRINT > "$OUT/transient/$base.fp"
    section "$OUT/transient/${ctx}__${profile}.txt" MOUNTS > "$OUT/transient/$base.mnt"
    fp_table "$OUT/real/$base.fp" "$OUT/transient/$base.fp" TRANSIENT "$profile"
    mount_diff "$OUT/real/$base.mnt" "$OUT/transient/$base.mnt" "$OUT/transient/$base.mnt.diff" transient

    if [ -s "$OUT/inservice/${ctx}__${profile}.txt" ]; then
        section "$OUT/inservice/${ctx}__${profile}.txt" FINGERPRINT > "$OUT/inservice/$base.fp"
        section "$OUT/inservice/${ctx}__${profile}.txt" MOUNTS > "$OUT/inservice/$base.mnt"
        fp_table "$OUT/real/$base.fp" "$OUT/inservice/$base.fp" INSERVICE "$profile"
        mount_diff "$OUT/real/$base.mnt" "$OUT/inservice/$base.mnt" "$OUT/inservice/$base.mnt.diff" inservice
        status_diff "$OUT/inservice/${ctx}__${profile}.txt" "$OUT/transient/${ctx}__${profile}.txt" \
            "$OUT/inservice/$base.status.diff"
    else
        echo "  INSERVICE=not available for this context"
    fi
}

for svc in "${SERVICES[@]}"; do
    unit=$(svc_unit "$svc")
    user=$(svc_user "$svc")
    for profile in P0 P4; do
        echo
        echo "===== SERVICE=$svc PROFILE=$profile ====="
        file=P0
        [ "$profile" = P0 ] || file="$(svc_profiles "$svc")/$profile.conf"
        since=$(date '+%Y-%m-%d %H:%M:%S')
        if [ "$svc" = nginx ]; then
            # Helper processes of the real unit; "-" keeps a probe failure
            # from failing the start of the service.
            {
                echo '[Service]'
                echo "ExecStartPost=-$INSERVICE inservice-nginx-master $(target_pid root)"
                echo "ExecStartPost=-/usr/bin/python3 $DROPUSER labweb $INSERVICE inservice-nginx-worker $(target_pid labweb)"
            } > "$PROBE_DROPIN"
        fi
        svc_apply "$svc" "$profile" || { echo "ERROR: $svc does not work under $profile"; exit 1; }
        main=$(systemctl show "$unit" -p MainPID --value)
        [ -n "$main" ] && [ "$main" != 0 ] || { echo 'ERROR: no main PID'; exit 1; }

        case "$svc" in
            nginx)
                journalctl --sync >/dev/null 2>&1 || true
                sleep 1
                journalctl -u "$unit" --since "$since" -o cat --no-pager > "$OUT/journal-nginx-$profile.txt"
                for c in master worker; do
                    awk -v b="## BEGIN inservice-nginx-$c" -v e="## END inservice-nginx-$c" \
                        '$0 == b { f = 1 } f { print } $0 == e { f = 0 }' \
                        "$OUT/journal-nginx-$profile.txt" > "$OUT/inservice/nginx-${c}__${profile}.txt"
                done
                worker=$(pgrep -P "$main" | head -n 1 || true)
                [ -n "$worker" ] || { echo 'ERROR: no Nginx worker'; exit 1; }
                compare_context nginx-master root "$main" "$profile" "$file"
                compare_context nginx-worker "$user" "$worker" "$profile" "$file"
                ;;
            redis)
                compare_context redis "$user" "$main" "$profile" "$file"
                ;;
            postgresql)
                pg_inservice inservice-postgresql "$(target_pid "$user")" \
                    "$OUT/inservice/postgresql__${profile}.txt" \
                    || echo "  NOTE: COPY FROM PROGRAM failed, see the output file"
                compare_context postgresql "$user" "$main" "$profile" "$file"
                ;;
        esac
    done
    if [ "$svc" = nginx ]; then rm -f "$PROBE_DROPIN"; fi
done

echo
echo '===== METRICS: TRANSIENT RUNS ====='
python3 "$HERE/metric_summary_v003.py" "$OUT/transient" || true
echo
echo '===== METRICS: IN-SERVICE RUNS ====='
python3 "$HERE/metric_summary_v003.py" "$OUT/inservice" || true
