#!/usr/bin/env bash
# scenarios_v005.sh [nginx] [redis] [postgresql] -- attacker goals for every
# candidate profile (v005). Goals and outcome rules are fixed in
# protocol_v005.txt before this script is run.
#
#   Nginx       G1  replace a served document; factorial control of ordinary
#                   Linux permissions (DAC): directory owned by root / by
#                   labweb  x  context worker (labweb) / master (root)
#               G2  read the application secret (expected residual risk)
#               G3  replace a file in the service-config directory /etc/systemd-lab
#                   (independent goal, read-only via ProtectSystem=full rather
#                   than the hand-picked ReadOnlyPaths; master / worker)
#               G4  write the log directory /var/log (read-only only under
#                   ProtectSystem=strict; master / worker)
#   Redis       G1  write a file outside the data directory; DAC control as
#                   above  x  context server (CONFIG SET dir + SAVE through
#                   the real server) / process (a model process with the
#                   rights of the service writes the file itself)
#   PostgreSQL  G1  write a file outside the data directory; DAC control as
#                   above  x  context server (COPY ... TO) / process
#               G2  run a program through the real server: COPY FROM PROGRAM
#
# A root model process that cannot write directly also tries what a root
# process can do against a read-only mount (protocol_review_v005.txt, section 3;
# protocol_review2_v005.txt, section 6): the same directory through
# /proc/1/root, remounting the mount point read-write inside its own mount
# namespace, and a nested bind mount remounted read-write. The method that
# worked is written to the detail column (via=...). States that the transient
# model cannot reproduce (an fd inherited from before the profile applied) are
# named in the protocol and the conclusion is narrowed accordingly.
#
# Candidates: NGINX_PROFILES, REDIS_PROFILES, PG_PROFILES (space separated).
# The live profile is changed during the run and P4 is restored at the end.
set -Eeuo pipefail
HERE=$(dirname "$(readlink -f "$0")")
. "$HERE/slab_common_v005.sh"
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: run as root'; exit 1; }
if [ "$#" -gt 0 ]; then SERVICES=("$@"); else SERVICES=(nginx redis postgresql); fi
NGINX_PROFILES=${NGINX_PROFILES:-P0 P1 P2 P1r P1c P4 P5 P6}
REDIS_PROFILES=${REDIS_PROFILES:-P0 P4 P6}
PG_PROFILES=${PG_PROFILES:-P0 P4 P6}
for s in "${SERVICES[@]}"; do svc_user "$s" >/dev/null; done
require_files "$DROPUSER"
require_rest_state "${SERVICES[@]}"

OUT="$ROOT/scenarios-v005/$(date +%Y%m%d-%H%M%S)"
CSV="$OUT/goals.csv"
CAND="$OUT/candidates.csv"
GPROBE=/usr/local/bin/slab-g-probe-v005.sh
N_ROOT="$SITE/g1-v005-rootown"
N_LAB="$SITE/g1-v005-labweb"
N_SECRET_DIR=/var/lib/systemd-lab/g2-v005-private
# Independent goals derived from the configuration before the profiles were
# built (protocol_review2_v005.txt, section 4): G3 writes the service-config
# directory (read-only through ProtectSystem=full, not the hand-picked
# ReadOnlyPaths), G4 writes the log directory (read-only only under
# ProtectSystem=strict).
N_CONF=/etc/systemd-lab/g3-v005-config
N_LOGDIR=/var/log/g4-v005-logdir
R_OWN=/var/lib/systemd-lab/redis-g1-v005-own
R_ROOT=/var/lib/systemd-lab/redis-g1-v005-root
P_OWN=/var/lib/systemd-lab/pg-g1-v005-own
P_ROOT=/var/lib/systemd-lab/pg-g1-v005-root
REDIS_CONF=/etc/systemd-lab/redis.conf
REDIS_CONF_BACKUP=
for p in "$GPROBE" "$N_ROOT" "$N_LAB" "$N_SECRET_DIR" "$N_CONF" "$N_LOGDIR" \
         "$R_OWN" "$R_ROOT" "$P_OWN" "$P_ROOT"; do
    [ ! -e "$p" ] || { echo "ERROR: $p already exists; inspect before continuing"; exit 1; }
done

mkdir -p "$OUT"
exec > >(tee "$OUT/run.log") 2>&1
echo 'service,goal,dac,context,profile,outcome,detail' > "$CSV"
echo 'service,profile,functional,exposure,n_directives' > "$CAND"

cleanup() {
    local status=$?
    trap - EXIT
    set +e
    echo
    echo '===== CLEANUP AND RESTORE P4 ====='
    if [ -n "$REDIS_CONF_BACKUP" ] && [ -f "$REDIS_CONF_BACKUP" ]; then
        cp -p "$REDIS_CONF_BACKUP" "$REDIS_CONF" && rm -f "$REDIS_CONF_BACKUP"
        echo 'REDIS_CONF_RESTORED'
    fi
    rm -f "$GPROBE"
    rm -rf -- "$N_ROOT" "$N_LAB" "$N_SECRET_DIR" "$N_CONF" "$N_LOGDIR" "$R_OWN" "$R_ROOT" "$P_OWN" "$P_ROOT"
    rm -f /var/lib/systemd-lab/redis/g1-v005.rdb
    restore_rest_state "${SERVICES[@]}" || status=2
    echo "RESULT_DIR=$OUT"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

record() {  # SERVICE GOAL DAC CONTEXT PROFILE OUTCOME DETAIL
    local detail
    detail=$(printf '%s' "$7" | tr ',\n\r' ';  ')
    printf '%s,%s,%s,%s,%s,%s,%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$detail" >> "$CSV"
    echo "RESULT service=$1 goal=$2 dac=$3 context=$4 profile=$5 outcome=$6 detail=$detail"
}

# candidate SERVICE PROFILE -- applies the profile to the real unit, records
# the functional gate, Exposure and the number of directives. Returns
# non-zero when the candidate is not functional (it is then skipped).
candidate() {
    local svc=$1 profile=$2 unit file exposure n functional=1
    unit=$(svc_unit "$svc")
    file="$(svc_profiles "$svc")/$profile.conf"
    echo
    echo "===== SERVICE=$svc CANDIDATE=$profile ====="
    if [ "$profile" != P0 ] && [ ! -f "$file" ]; then
        echo "SKIP: $file does not exist (run make_candidates_v005.sh)"
        return 1
    fi
    svc_apply "$svc" "$profile" || functional=0
    exposure=$(systemd-analyze security "$unit" --no-pager 2>/dev/null \
        | sed -n 's/.*Overall exposure level[^:]*: *\([0-9.]*\).*/\1/p' | tail -n 1)
    n=0
    [ "$profile" = P0 ] || n=$(grep -Ec '^[A-Za-z].*=' "$file" || true)
    echo "$svc,$profile,$functional,${exposure:-NA},$n" >> "$CAND"
    echo "FUNCTIONAL=$functional EXPOSURE=${exposure:-NA} DIRECTIVES=$n"
    if [ "$functional" -ne 1 ]; then
        systemctl status "$unit" --no-pager -l | tail -n 15 || true
        return 1
    fi
}

goal_transient() {  # USER FILE|P0 CMD... -- prints the output of the model process
    local user=$1 file=$2
    shift 2
    props_from_profile "$file" || return 1
    local -a ident=()
    if [ "$user" != root ]; then ident=(-p "User=$user" -p "Group=$user"); fi
    systemd-run --quiet --wait --pipe --collect \
        --unit="slab-v005-goal-$$-$RANDOM" -p Type=exec \
        ${ident[@]+"${ident[@]}"} ${PROPS[@]+"${PROPS[@]}"} "$@" 2>&1 || true
}

profile_file() {  # SERVICE PROFILE
    if [ "$2" = P0 ]; then echo P0; else echo "$(svc_profiles "$1")/$2.conf"; fi
}

# ---------------------------------------------------------- goal helper
probe_setup() {
    cat > "$GPROBE" <<'PROBEOF'
#!/bin/sh
# Runtime helper of scenarios_v005.sh (removed by its cleanup).
#   slab-g-probe-v005.sh read FILE
#   slab-g-probe-v005.sh write DIR [nofallback]   replace DIR/document.txt
#   slab-g-probe-v005.sh writefile DIR            create DIR/g1-v005-process.txt
mode=$1
arg=$2
nofallback=${3:-}
uid=$(id -u)
if [ "$mode" = read ]; then
    if head -c 1 "$arg" >/dev/null 2>&1; then
        echo "G_RESULT=ALLOWED uid=$uid"
    else
        echo "G_RESULT=BLOCKED uid=$uid"
    fi
    exit 0
fi
attempt() {  # DIR -- one attempt to reach the goal through this path
    if [ "$mode" = writefile ]; then
        printf 'G1_PAYLOAD\n' 2>/dev/null > "$1/g1-v005-process.txt"
        return
    fi
    TEMP=$(mktemp "$1/.g1-XXXXXX" 2>/dev/null) || return 1
    if printf 'G1_REPLACED_DOCUMENT\n' > "$TEMP" 2>/dev/null && chmod 0644 "$TEMP" 2>/dev/null \
            && mv -f "$TEMP" "$1/document.txt" 2>/dev/null; then
        return 0
    fi
    rm -f "$TEMP" 2>/dev/null
    return 1
}
via=
( attempt "$arg" ) 2>/dev/null && via=direct
if [ -z "$via" ] && [ "$uid" = 0 ] && [ -z "$nofallback" ]; then
    # What a root process can try against a read-only mount.
    ( attempt "/proc/1/root$arg" ) 2>/dev/null && via=proc1root
    mp=$(findmnt -n -o TARGET --target "$arg" 2>/dev/null)
    opts=$(findmnt -n -o OPTIONS --target "$arg" 2>/dev/null)
    case ",$opts," in
        *,ro,*)
            if [ -n "$mp" ] && mount -o remount,rw,bind "$mp" 2>/dev/null \
                    && ( attempt "$arg" ) 2>/dev/null; then
                via=${via:+$via+}remount
            fi ;;
    esac
    # Nested bind mount: bind the read-only target onto a fresh directory and
    # remount that read-write (protocol_review2_v005.txt, section 6).
    if [ -z "$via" ]; then
        BM=$(mktemp -d 2>/dev/null) || BM=
        if [ -n "$BM" ] && mount --bind "$arg" "$BM" 2>/dev/null \
                && mount -o remount,rw,bind "$BM" 2>/dev/null \
                && ( attempt "$BM" ) 2>/dev/null; then
            via=${via:+$via+}nestedbind
        fi
        [ -z "$BM" ] || { umount "$BM" 2>/dev/null; rmdir "$BM" 2>/dev/null; }
    fi
fi
if [ -n "$via" ]; then
    echo "G_RESULT=ALLOWED via=$via uid=$uid"
    exit 0
fi
# A root process that still cannot write tries the identity of the worker
# user, as a compromised master holding CAP_SETUID could.
if [ "$mode" = write ] && [ "$uid" = 0 ] && [ -z "$nofallback" ]; then
    exec /usr/bin/python3 /usr/local/bin/slab_dropuser_v005.py labweb "$0" write "$arg" nofallback
fi
echo "G_RESULT=BLOCKED uid=$uid"
exit 0
PROBEOF
    chmod 0755 "$GPROBE"
}

# process_cell SERVICE PROFILE DAC DIR -- the same goal G1 attempted by a model
# process with the rights and the profile of the service, without the server.
process_cell() {
    local svc=$1 profile=$2 dac=$3 dir=$4 out outcome
    rm -f "$dir/g1-v005-process.txt"
    out=$(goal_transient "$(svc_user "$svc")" "$(profile_file "$svc" "$profile")" "$GPROBE" writefile "$dir")
    if [ -s "$dir/g1-v005-process.txt" ]; then
        outcome=ACHIEVED
    elif printf '%s\n' "$out" | grep -q '^G_RESULT=BLOCKED '; then
        outcome=BLOCKED
    else
        outcome=UNEXPECTED
    fi
    rm -f "$dir/g1-v005-process.txt"
    record "$svc" G1-write-outside-datadir "$dac" process "$profile" "$outcome" "$out"
}

# ---------------------------------------------------------------- Nginx
nginx_reset_document() {  # DIR
    rm -f "$1/document.txt" "$1"/.g1-*
    printf 'G1_ORIGINAL_DOCUMENT\n' > "$1/document.txt"
    chown root:root "$1/document.txt"
    chmod 0444 "$1/document.txt"
}

nginx_setup() {
    mkdir "$N_ROOT" "$N_LAB"
    chown root:root "$N_ROOT"; chmod 0755 "$N_ROOT"
    chown labweb:labweb "$N_LAB"; chmod 0755 "$N_LAB"
    install -d -o root -g labweb -m 0750 "$N_SECRET_DIR"
    printf 'LAB_G2_SYNTHETIC_TOKEN_V003\n' > "$N_SECRET_DIR/app-secret.txt"
    chown root:labweb "$N_SECRET_DIR/app-secret.txt"
    chmod 0640 "$N_SECRET_DIR/app-secret.txt"
    # G3 target in the service-config directory, G4 target in the log directory;
    # both root-owned, so DAC alone blocks the worker and only the master is of
    # interest. A synthetic document is used so the live config is never touched.
    mkdir "$N_CONF" "$N_LOGDIR"
    chown root:root "$N_CONF" "$N_LOGDIR"; chmod 0755 "$N_CONF" "$N_LOGDIR"
}

# nginx_write_goal GOAL DIR PROFILE -- G1-style write of DIR/document.txt by the
# model process in the master and worker contexts, recorded by the probe result
# (no HTTP check). Used for the independent goals G3 and G4.
nginx_write_goal() {
    local goal=$1 dir=$2 profile=$3 file user ctx out result outcome
    file=$(profile_file nginx "$profile")
    for user in labweb root; do
        if [ "$user" = root ]; then ctx=master; else ctx=worker; fi
        nginx_reset_document "$dir"
        out=$(goal_transient "$user" "$file" "$GPROBE" write "$dir")
        result=$(printf '%s\n' "$out" | sed -n 's/^G_RESULT=\([A-Z]*\).*/\1/p' | tail -n 1)
        case "$result" in
            ALLOWED) outcome=ACHIEVED ;;
            BLOCKED) outcome=BLOCKED ;;
            *) outcome=UNEXPECTED ;;
        esac
        record nginx "$goal" rootown "$ctx" "$profile" "$outcome" "$out"
    done
    nginx_reset_document "$dir"
}

nginx_goals() {  # PROFILE
    local profile=$1 file dir dac user ctx out result code body outcome
    file=$(profile_file nginx "$profile")
    body=$(mktemp)
    for dac in rootown labweb; do
        if [ "$dac" = rootown ]; then dir=$N_ROOT; else dir=$N_LAB; fi
        for user in labweb root; do
            if [ "$user" = root ]; then ctx=master; else ctx=worker; fi
            nginx_reset_document "$dir"
            out=$(goal_transient "$user" "$file" "$GPROBE" write "$dir")
            result=$(printf '%s\n' "$out" | sed -n 's/^G_RESULT=\([A-Z]*\).*/\1/p' | tail -n 1)
            code=$(curl --max-time 5 -sS -o "$body" -w '%{http_code}' \
                "http://127.0.0.1:808/$(basename "$dir")/document.txt" 2>/dev/null || true)
            if [ "$result" = ALLOWED ] && [ "$code" = 200 ] && grep -qx G1_REPLACED_DOCUMENT "$body"; then
                outcome=ACHIEVED
            elif [ "$result" = BLOCKED ] && [ "$code" = 200 ] && grep -qx G1_ORIGINAL_DOCUMENT "$body"; then
                outcome=BLOCKED
            else
                outcome=UNEXPECTED
            fi
            record nginx G1-replace-document "$dac" "$ctx" "$profile" "$outcome" "http=$code $out"
        done
        nginx_reset_document "$dir"
    done
    for user in labweb root; do
        if [ "$user" = root ]; then ctx=master; else ctx=worker; fi
        out=$(goal_transient "$user" "$file" "$GPROBE" read "$N_SECRET_DIR/app-secret.txt")
        result=$(printf '%s\n' "$out" | sed -n 's/^G_RESULT=\([A-Z]*\).*/\1/p' | tail -n 1)
        case "$result" in
            ALLOWED) outcome=ACHIEVED ;;
            BLOCKED) outcome=BLOCKED ;;
            *) outcome=UNEXPECTED ;;
        esac
        record nginx G2-read-app-secret needed-by-app "$ctx" "$profile" "$outcome" "$out"
    done
    rm -f "$body"
    nginx_write_goal G3-replace-config "$N_CONF" "$profile"
    nginx_write_goal G4-write-logdir "$N_LOGDIR" "$profile"
}

# ---------------------------------------------------------------- Redis
rcli() { redis-cli -p 6380 "$@" 2>&1 || true; }

redis_setup() {
    local cur resp
    mkdir "$R_OWN" "$R_ROOT"
    chown labredis:labredis "$R_OWN"; chmod 0755 "$R_OWN"
    chown root:root "$R_ROOT"; chmod 0755 "$R_ROOT"
    # Does the server itself refuse CONFIG SET dir (default since Redis 7)?
    cur=$(rcli CONFIG GET dir | tail -n 1)
    resp=$(rcli CONFIG SET dir "$cur")
    if [ "$resp" = OK ]; then
        record redis G1-app-guard - server P4 INFO 'CONFIG SET dir is accepted by the server configuration'
    else
        record redis G1-app-guard - server P4 INFO "default refuses CONFIG SET dir: $resp"
        REDIS_CONF_BACKUP="$REDIS_CONF.bak-v005-$$"
        cp -p "$REDIS_CONF" "$REDIS_CONF_BACKUP"
        printf '\n# v005 scenario G1, temporary: model of a server without this guard\nenable-protected-configs yes\n' >> "$REDIS_CONF"
        echo 'REDIS_CONF: enable-protected-configs yes added for the duration of the scenario'
    fi
}

redis_goals() {  # PROFILE
    local profile=$1 dac target odir odb r1 r2 r3 outcome
    for dac in own root; do
        if [ "$dac" = own ]; then target=$R_OWN; else target=$R_ROOT; fi
        odir=$(rcli CONFIG GET dir | tail -n 1)
        odb=$(rcli CONFIG GET dbfilename | tail -n 1)
        r1=$(rcli CONFIG SET dir "$target")
        r2=-; r3=-
        if [ "$r1" = OK ]; then
            r2=$(rcli CONFIG SET dbfilename g1-v005.rdb)
            rcli SET slab_g1_v005 G1_PAYLOAD >/dev/null
            r3=$(rcli SAVE)
        fi
        if [ -s "$target/g1-v005.rdb" ]; then
            outcome=ACHIEVED
        elif printf '%s\n' "$r1" "$r2" "$r3" | grep -qiE 'permission denied|read-only file system|operation not permitted'; then
            outcome=BLOCKED
        else
            outcome=UNEXPECTED
        fi
        rcli CONFIG SET dir "$odir" >/dev/null
        rcli CONFIG SET dbfilename "$odb" >/dev/null
        rcli DEL slab_g1_v005 >/dev/null
        rm -f "$target"/g1-v005.rdb "$target"/temp-*.rdb /var/lib/systemd-lab/redis/g1-v005.rdb
        record redis G1-write-outside-datadir "$dac" server "$profile" "$outcome" \
            "config_set_dir=$r1 config_set_dbfilename=$r2 save=$r3"
        process_cell redis "$profile" "$dac" "$target"
    done
}

# ----------------------------------------------------------- PostgreSQL
psqlc() { psql -h 127.0.0.1 -p 55432 -U labpg -d postgres -qAt "$@" 2>&1 || true; }

pg_setup() {
    mkdir "$P_OWN" "$P_ROOT"
    chown labpg:labpg "$P_OWN"; chmod 0755 "$P_OWN"
    chown root:root "$P_ROOT"; chmod 0755 "$P_ROOT"
}

pg_goals() {  # PROFILE
    local profile=$1 dac target r outcome
    for dac in own root; do
        if [ "$dac" = own ]; then target=$P_OWN; else target=$P_ROOT; fi
        rm -f "$target/g1-v005.txt"
        r=$(psqlc -c "COPY (SELECT 'G1_PAYLOAD') TO '$target/g1-v005.txt'")
        if [ -s "$target/g1-v005.txt" ]; then
            outcome=ACHIEVED
        elif printf '%s\n' "$r" | grep -qiE 'permission denied|read-only file system|operation not permitted'; then
            outcome=BLOCKED
        else
            outcome=UNEXPECTED
        fi
        rm -f "$target/g1-v005.txt"
        record postgresql G1-write-outside-datadir "$dac" server "$profile" "$outcome" "$r"
        process_cell postgresql "$profile" "$dac" "$target"
    done
    r=$(psqlc <<'SQL'
CREATE TEMP TABLE slab_g2_v005 (line text);
COPY slab_g2_v005 FROM PROGRAM 'id -un';
SELECT line FROM slab_g2_v005;
SQL
)
    if [ "$r" = labpg ]; then
        outcome=ACHIEVED
    elif printf '%s\n' "$r" | grep -qiE 'permission denied|operation not permitted'; then
        outcome=BLOCKED
    else
        outcome=UNEXPECTED
    fi
    record postgresql G2-run-program needed-by-app server "$profile" "$outcome" "$r"
}

# ------------------------------------------------------------------ main
probe_setup
for svc in "${SERVICES[@]}"; do
    case "$svc" in
        nginx) profiles=$NGINX_PROFILES; nginx_setup ;;
        redis) profiles=$REDIS_PROFILES; redis_setup ;;
        postgresql) profiles=$PG_PROFILES; pg_setup ;;
    esac
    for profile in $profiles; do
        if candidate "$svc" "$profile"; then
            case "$svc" in
                nginx) nginx_goals "$profile" ;;
                redis) redis_goals "$profile" ;;
                postgresql) pg_goals "$profile" ;;
            esac
        else
            record "$svc" ALL - - "$profile" NOT_FUNCTIONAL 'candidate excluded by the functional gate or missing'
        fi
    done
done

echo
echo '===== GOALS BLOCKED PER CANDIDATE (rows with outcome INFO are not counted) ====='
awk -F, 'NR > 1 && $6 != "INFO" && $6 != "NOT_FUNCTIONAL" {
        k = $1 "," $5; total[k]++; if ($6 == "BLOCKED") b[k]++; if ($6 == "UNEXPECTED") u[k]++ }
    END { for (k in total) printf "%s blocked=%d of %d unexpected=%d\n", k, b[k], total[k], u[k] }' \
    "$CSV" | sort
echo
echo '===== CANDIDATES ====='
cat "$CAND"
( cd "$OUT" && sha256sum goals.csv candidates.csv > sha256.txt )
