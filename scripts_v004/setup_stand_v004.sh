#!/usr/bin/env bash
# setup_stand_v004.sh -- builds the laboratory stand on a clean ALT Server 11.1
# from the files in ../stand_v004 (unit files, configurations, profiles and
# probe programs taken from the appendices of the article). Safe to re-run.
#
# After it finishes the stand is in its rest state: three lab services are
# active under the saved P4, the four target processes run, the saved
# profiles lie in /root/systemd-lab-results/<service>/profiles.
set -Eeuo pipefail
HERE=$(dirname "$(readlink -f "$0")")
STAND=$(readlink -f "$HERE/../stand_v004")
. "$HERE/slab_common_v004.sh"
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: run as root'; exit 1; }
[ -d "$STAND/units" ] || { echo "ERROR: $STAND is missing"; exit 1; }
mkdir -p "$ROOT"
exec > >(tee -a "$ROOT/setup-v004.log") 2>&1
echo "===== SETUP START $(date -Is) ====="

echo '===== PACKAGES ====='
apt-get update -q
apt-get install -y nginx redis postgresql14-server postgresql14-contrib apache2-ab gcc
# The distribution's own instances must not run next to the lab instances.
systemctl disable --now nginx.service redis.service postgresql.service 2>/dev/null || true
for tool in nginx redis-server redis-cli redis-benchmark postgres initdb psql pgbench pg_isready \
            ab curl taskset shuf gcc python3; do
    command -v "$tool" >/dev/null || { echo "MISSING TOOL AFTER INSTALL: $tool"; exit 1; }
done

echo '===== USERS ====='
for u in labweb labredis labpg labvictim; do
    id "$u" >/dev/null 2>&1 || useradd -r -M -s /sbin/nologin "$u"
    if [ "$(id -gn "$u")" != "$u" ]; then
        getent group "$u" >/dev/null || groupadd -r "$u"
        usermod -g "$u" "$u"
    fi
    id "$u"
done

echo '===== SYNTHETIC OBJECTS ====='
mkdir -p /home/systemd-lab /etc/systemd-lab/write /var/lib/systemd-lab/empty
printf 'HOME_MARKER\n' > /home/systemd-lab/marker
printf 'ROOT_MARKER\n' > /root/systemd-lab-marker
printf 'SYNTHETIC_CREDENTIAL\n' > /etc/systemd-lab/credential
chmod 0644 /home/systemd-lab/marker /root/systemd-lab-marker /etc/systemd-lab/credential
chmod 1777 /etc/systemd-lab/write
printf 'VARTMP_MARKER\n' > /var/tmp/systemd-lab-marker
chmod 0644 /var/tmp/systemd-lab-marker
# /tmp is tmpfs and /dev is devtmpfs here: these two objects are recreated
# at every boot by a oneshot unit.
cat > /usr/local/sbin/slab-volatile-v004.sh <<'VOLEOF'
#!/bin/sh
printf 'TMP_MARKER\n' > /tmp/systemd-lab-marker
chmod 0644 /tmp/systemd-lab-marker
rm -f /dev/systemd-lab-null
mknod /dev/systemd-lab-null c 1 3
chmod 0666 /dev/systemd-lab-null
VOLEOF
chmod 0755 /usr/local/sbin/slab-volatile-v004.sh
cat > /etc/systemd/system/slab-volatile.service <<'VOLUNIT'
[Unit]
Description=systemd hardening experiment: volatile test objects
After=systemd-tmpfiles-setup.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/slab-volatile-v004.sh

[Install]
WantedBy=multi-user.target
VOLUNIT

echo '===== SERVICE DATA AND CONFIGURATION ====='
mkdir -p "$SITE"
printf 'SYSTEMD_LAB_NGINX_OK\n' > "$SITE/index.html"
chown -R root:root "$SITE"; chmod 0755 "$SITE"; chmod 0644 "$SITE/index.html"
install -m 0644 "$STAND/conf/nginx.conf" /etc/systemd-lab/nginx.conf
install -m 0644 "$STAND/conf/redis.conf" /etc/systemd-lab/redis.conf
install -d -o labredis -g labredis -m 0750 /var/lib/systemd-lab/redis

PGDATA=/var/lib/systemd-lab/postgresql
if [ ! -f "$PGDATA/PG_VERSION" ]; then
    mkdir -p "$PGDATA"
    chown labpg:labpg "$PGDATA"
    chmod 0700 "$PGDATA"
    su -s /bin/sh labpg -c "/usr/bin/initdb -D $PGDATA --no-locale --encoding=UTF8 --auth=trust"
    cat >> "$PGDATA/postgresql.conf" <<PGCONF

# systemd hardening experiment
listen_addresses = '127.0.0.1'
port = 55432
unix_socket_directories = '$PGDATA'
logging_collector = off
PGCONF
else
    echo "PostgreSQL cluster already initialized in $PGDATA"
fi

echo '===== PROBE PROGRAMS ====='
install -d /usr/local/src
install -m 0644 "$STAND/probes/uid_helper.c" "$STAND/probes/lab_target.c" /usr/local/src/
gcc -O2 -Wall /usr/local/src/uid_helper.c -o /usr/local/bin/uid-helper
chown root:root /usr/local/bin/uid-helper; chmod 4755 /usr/local/bin/uid-helper
gcc -O2 -Wall /usr/local/src/lab_target.c -o /usr/local/bin/lab-target
chown root:root /usr/local/bin/lab-target; chmod 0755 /usr/local/bin/lab-target
install -m 0755 "$STAND/probes/isolation_probe.py" "$STAND/probes/extended_probe.py" \
    "$STAND/probes/ptrace_seize.py" /usr/local/bin/
install -m 0755 "$HERE/slab_fp_v004.sh" "$HERE/slab_inservice_v004.sh" "$HERE/slab_dropuser_v004.py" \
    /usr/local/bin/

echo '===== UNITS AND PROFILES ====='
install -m 0644 "$STAND"/units/*.service /etc/systemd/system/
for svc in nginx redis postgresql; do
    mkdir -p "$(svc_profiles "$svc")"
    for f in "$STAND/profiles/$svc"/*.conf; do
        target="$(svc_profiles "$svc")/$(basename "$f")"
        if [ -e "$target" ] && ! cmp -s "$f" "$target"; then
            echo "ERROR: $target exists and differs from the stand file"; exit 1
        fi
        install -m 0644 "$f" "$target"
    done
done
systemctl daemon-reload
systemctl enable slab-volatile.service slab-nginx.service slab-redis.service slab-postgresql.service \
    lab-proc-target@labweb.service lab-proc-target@labredis.service \
    lab-proc-target@labpg.service lab-proc-target@root.service >/dev/null 2>&1
systemctl restart slab-volatile.service
for u in labweb labredis labpg root; do
    systemctl restart "lab-proc-target@$u.service"
    echo "lab-proc-target@$u: $(systemctl is-active "lab-proc-target@$u.service") pid=$(target_pid "$u")"
done

contract() {  # SERVICE -- the functional contract of table 2 of the article
    local svc=$1 unit main n code v
    unit=$(svc_unit "$svc")
    case "$svc" in
        nginx)
            main=$(systemctl show "$unit" -p MainPID --value)
            n=$(pgrep -P "$main" -u labweb | wc -l)
            [ "$n" -eq 2 ] || { echo "nginx: expected 2 workers of labweb, got $n"; return 1; }
            systemctl reload "$unit" && sleep 1 && svc_health nginx || return 1
            systemctl restart "$unit" && svc_health nginx || return 1
            code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:808/no-such-file)
            [ "$code" = 404 ] || { echo "nginx: expected 404, got $code"; return 1; } ;;
        redis)
            redis-cli -p 6380 SET slab_contract CONTRACT_VALUE >/dev/null
            [ "$(redis-cli -p 6380 GET slab_contract)" = CONTRACT_VALUE ] || return 1
            systemctl restart "$unit" && svc_health redis || return 1
            v=$(redis-cli -p 6380 GET slab_contract)
            [ "$v" = CONTRACT_VALUE ] || { echo "redis: value lost after restart: $v"; return 1; }
            redis-cli -p 6380 DEL slab_contract >/dev/null ;;
        postgresql)
            psqlq() { psql -h 127.0.0.1 -p 55432 -U labpg -d postgres -qAt -v ON_ERROR_STOP=1 "$@"; }
            [ "$(psqlq -c 'SELECT 1')" = 1 ] || return 1
            psqlq -c 'DROP TABLE IF EXISTS slab_contract' -c 'CREATE TABLE slab_contract (v text)' \
                  -c "INSERT INTO slab_contract VALUES ('CONTRACT_VALUE')" || return 1
            systemctl restart "$unit" && svc_health postgresql || return 1
            v=$(psqlq -c 'SELECT v FROM slab_contract')
            [ "$v" = CONTRACT_VALUE ] || { echo "postgresql: value lost after restart: $v"; return 1; }
            psqlq -c 'DROP TABLE slab_contract' ;;
    esac
}

for profile in P0 P4; do
    echo "===== START UNDER $profile AND FUNCTIONAL CONTRACT ====="
    for svc in nginx redis postgresql; do
        svc_apply "$svc" "$profile" || { echo "FAIL: $svc does not start under $profile"; \
            systemctl status "$(svc_unit "$svc")" --no-pager -l | tail -n 20; exit 1; }
        contract "$svc" || { echo "FAIL: functional contract of $svc under $profile"; exit 1; }
        echo "$svc $profile: FUNCTIONAL CONTRACT PASS"
    done
    if [ "$profile" = P0 ]; then
        if ! psql -h 127.0.0.1 -p 55432 -U labpg -d postgres -qAt \
                -c "SELECT 1 FROM pg_database WHERE datname = 'systemd_bench'" | grep -q 1; then
            psql -h 127.0.0.1 -p 55432 -U labpg -d postgres -v ON_ERROR_STOP=1 \
                -c 'CREATE DATABASE systemd_bench OWNER labpg;'
            pgbench -i -q -s 10 -h 127.0.0.1 -p 55432 -U labpg systemd_bench
        fi
    fi
done

echo '===== STAND DESCRIPTION ====='
{
    date -Is
    grep -E '^(PRETTY_NAME|VERSION)=' /etc/os-release
    echo "kernel=$(uname -r)"
    systemctl --version | head -n 1
    nginx -v 2>&1
    redis-server -v
    postgres -V
    python3 -V
    gcc --version | head -n 1
    ab -V 2>&1 | head -n 1
    echo "nproc=$(nproc) mem_mb=$(free -m | awk 'NR==2 {print $2}')"
    echo "cgroup=$(stat -fc %T /sys/fs/cgroup)"
    echo "lsm=$(cat /sys/kernel/security/lsm 2>/dev/null)"
    sysctl kernel.yama.ptrace_scope kernel.unprivileged_bpf_disabled vm.unprivileged_userfaultfd \
        kernel.io_uring_disabled net.ipv4.ip_unprivileged_port_start
    for svc in nginx redis postgresql; do
        echo "exposure_P4_$svc=$(systemd-analyze security "$(svc_unit "$svc")" --no-pager 2>/dev/null \
            | sed -n 's/.*Overall exposure level[^:]*: *\([0-9.]*\).*/\1/p' | tail -n 1)"
    done
    ( cd "$STAND" && find . -type f | sort | xargs sha256sum )
} | tee "$ROOT/stand-v004.txt"

require_rest_state nginx redis postgresql
echo "===== SETUP COMPLETE $(date -Is): stand is in its rest state (P4) ====="
