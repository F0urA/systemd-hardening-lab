#!/usr/bin/env bash
# scenarios_v004.sh [nginx] [redis] [postgresql] -- attacker goals for every
# candidate profile (v004). Goals and outcome rules are fixed in
# protocol_v004.txt before this script is run.
#
#   Nginx       G1  replace a served document; factorial control of ordinary
#                   Linux permissions (DAC): directory owned by root / by
#                   labweb  x  context worker (labweb) / master (root)
#               G2  read the application secret (expected residual risk)
#   Redis       G1  write a file outside the data directory through the real
#                   server: CONFIG SET dir + SAVE; DAC control as above
#   PostgreSQL  G1  write a file outside the data directory through the real
#                   server: COPY ... TO; DAC control as above
#               G2  run a program through the real server: COPY FROM PROGRAM
#
# The live profile is changed during the run and P4 is restored at the end.
set -Eeuo pipefail
HERE=$(dirname "$(readlink -f "$0")")
. "$HERE/slab_common_v004.sh"
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: run as root'; exit 1; }
if [ "$#" -gt 0 ]; then SERVICES=("$@"); else SERVICES=(nginx redis postgresql); fi
for s in "${SERVICES[@]}"; do svc_user "$s" >/dev/null; done
require_files "$DROPUSER"
require_rest_state "${SERVICES[@]}"

OUT="$ROOT/scenarios-v004/$(date +%Y%m%d-%H%M%S)"
CSV="$OUT/goals.csv"
CAND="$OUT/candidates.csv"
GPROBE=/usr/local/bin/slab-g-probe-v004.sh
N_ROOT="$SITE/g1-v004-rootown"
N_LAB="$SITE/g1-v004-labweb"
N_SECRET_DIR=/var/lib/systemd-lab/g2-v004-private
R_OWN=/var/lib/systemd-lab/redis-g1-v004-own
R_ROOT=/var/lib/systemd-lab/redis-g1-v004-root
P_OWN=/var/lib/systemd-lab/pg-g1-v004-own
P_ROOT=/var/lib/systemd-lab/pg-g1-v004-root
REDIS_CONF=/etc/systemd-lab/redis.conf
REDIS_CONF_BACKUP=
for p in "$GPROBE" "$N_ROOT" "$N_LAB" "$N_SECRET_DIR" "$R_OWN" "$R_ROOT" "$P_OWN" "$P_ROOT"; do
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
    rm -rf -- "$N_ROOT" "$N_LAB" "$N_SECRET_DIR" "$R_OWN" "$R_ROOT" "$P_OWN" "$P_ROOT"
    rm -f /var/lib/systemd-lab/redis/g1-v004.rdb
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
        echo "SKIP: $file does not exist (run make_candidates_v004.sh for P6)"
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
        --unit="slab-v004-goal-$$-$RANDOM" -p Type=exec \
        ${ident[@]+"${ident[@]}"} ${PROPS[@]+"${PROPS[@]}"} "$@" 2>&1 || true
}

profile_file() {  # SERVICE PROFILE
    if [ "$2" = P0 ]; then echo P0; else echo "$(svc_profiles "$1")/$2.conf"; fi
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
    cat > "$GPROBE" <<'PROBEOF'
#!/bin/sh
# Runtime helper of scenarios_v004.sh (removed by its cleanup).
#   slab-g-probe-v004.sh read FILE
#   slab-g-probe-v004.sh write DIR [nofallback]
mode=$1
arg=$2
nofallback=${3:-}
if [ "$mode" = read ]; then
    if head -c 1 "$arg" >/dev/null 2>&1; then
        echo "G_RESULT=ALLOWED uid=$(id -u)"
    else
        echo "G_RESULT=BLOCKED uid=$(id -u)"
    fi
    exit 0
fi
TEMP=$(mktemp "$arg/.g1-XXXXXX" 2>/dev/null) || TEMP=
if [ -n "$TEMP" ] && printf 'G1_REPLACED_DOCUMENT\n' > "$TEMP" 2>/dev/null \
        && chmod 0644 "$TEMP" 2>/dev/null && mv -f "$TEMP" "$arg/document.txt" 2>/dev/null; then
    echo "G_RESULT=ALLOWED uid=$(id -u)"
    exit 0
fi
[ -z "$TEMP" ] || rm -f "$TEMP" 2>/dev/null
# A root process that cannot write directly tries the identity of the
# worker user, as a compromised master holding CAP_SETUID could.
if [ "$(id -u)" = 0 ] && [ -z "$nofallback" ]; then
    exec /usr/bin/python3 /usr/local/bin/slab_dropuser_v004.py labweb "$0" write "$arg" nofallback
fi
echo "G_RESULT=BLOCKED uid=$(id -u)"
exit 0
PROBEOF
    chmod 0755 "$GPROBE"
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
            elif [ "$result" != ALLOWED ] && [ "$code" = 200 ] && grep -qx G1_ORIGINAL_DOCUMENT "$body"; then
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
        if [ "$result" = ALLOWED ]; then outcome=ACHIEVED; else outcome=BLOCKED; fi
        record nginx G2-read-app-secret needed-by-app "$ctx" "$profile" "$outcome" "$out"
    done
    rm -f "$body"
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
        REDIS_CONF_BACKUP="$REDIS_CONF.bak-v004-$$"
        cp -p "$REDIS_CONF" "$REDIS_CONF_BACKUP"
        printf '\n# v004 scenario G1, temporary: model of a server without this guard\nenable-protected-configs yes\n' >> "$REDIS_CONF"
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
            r2=$(rcli CONFIG SET dbfilename g1-v004.rdb)
            rcli SET slab_g1_v004 G1_PAYLOAD >/dev/null
            r3=$(rcli SAVE)
        fi
        if [ -s "$target/g1-v004.rdb" ]; then outcome=ACHIEVED; else outcome=BLOCKED; fi
        rcli CONFIG SET dir "$odir" >/dev/null
        rcli CONFIG SET dbfilename "$odb" >/dev/null
        rcli DEL slab_g1_v004 >/dev/null
        rm -f "$target"/g1-v004.rdb "$target"/temp-*.rdb /var/lib/systemd-lab/redis/g1-v004.rdb
        record redis G1-write-outside-datadir "$dac" server "$profile" "$outcome" \
            "config_set_dir=$r1 config_set_dbfilename=$r2 save=$r3"
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
        rm -f "$target/g1-v004.txt"
        r=$(psqlc -c "COPY (SELECT 'G1_PAYLOAD') TO '$target/g1-v004.txt'")
        if [ -s "$target/g1-v004.txt" ]; then outcome=ACHIEVED; else outcome=BLOCKED; fi
        rm -f "$target/g1-v004.txt"
        record postgresql G1-write-outside-datadir "$dac" server "$profile" "$outcome" "$r"
    done
    r=$(psqlc <<'SQL'
CREATE TEMP TABLE slab_g2_v004 (line text);
COPY slab_g2_v004 FROM PROGRAM 'id -un';
SELECT line FROM slab_g2_v004;
SQL
)
    if [ "$r" = labpg ]; then outcome=ACHIEVED; else outcome=BLOCKED; fi
    record postgresql G2-run-program needed-by-app server "$profile" "$outcome" "$r"
}

# ------------------------------------------------------------------ main
for svc in "${SERVICES[@]}"; do
    case "$svc" in
        nginx) profiles='P0 P4 P5 P6'; nginx_setup ;;
        redis) profiles='P0 P4 P6'; redis_setup ;;
        postgresql) profiles='P0 P4 P6'; pg_setup ;;
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
