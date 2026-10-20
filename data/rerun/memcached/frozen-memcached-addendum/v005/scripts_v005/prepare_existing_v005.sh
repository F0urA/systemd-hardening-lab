#!/usr/bin/env bash
# Targeted preparation of the existing, previously backed-up laboratory.
set -Eeuo pipefail
HERE=$(dirname "$(readlink -f "$0")")
. "$HERE/slab_common_v005.sh"
[ "$(id -u)" -eq 0 ] || exit 1
case "$ROOT" in "${SLAB_BASE:-/root/systemd-hardening-lab}/results_v005") ;; *) echo 'ERROR: unexpected output root'; exit 1 ;; esac
STAND=$(readlink -f "$HERE/../stand_v005")
mkdir -p "$ROOT/initial-state"
exec > >(tee -a "$ROOT/initial-state/preparation.log") 2>&1
date -Is
printf 'unit,initial_active,initial_enabled\n' > "$ROOT/initial-state/services.csv"
for u in slab-nginx slab-redis slab-postgresql lab-proc-target@root lab-proc-target@labweb lab-proc-target@labredis lab-proc-target@labpg; do
    a=$(systemctl is-active "$u" || true)
    e=$(systemctl is-enabled "$u" || true)
    printf '%s,%s,%s\n' "$u" "$a" "$e" >> "$ROOT/initial-state/services.csv"
    systemctl cat "$u" --no-pager > "$ROOT/initial-state/$u.unit.txt"
done
tar -czf "$ROOT/initial-state/config-before.tar.gz" -C / \
    etc/systemd-lab etc/systemd/system/slab-nginx.service \
    etc/systemd/system/slab-redis.service etc/systemd/system/slab-postgresql.service \
    etc/systemd/system/slab-nginx.service.d etc/systemd/system/slab-redis.service.d \
    etc/systemd/system/slab-postgresql.service.d 'etc/systemd/system/lab-proc-target@.service'
for s in nginx redis postgresql; do
    mkdir -p "$(svc_profiles "$s")"
    for f in /root/systemd-lab-results/"$s"/profiles/*.conf; do
        [ -f "$f" ] || continue
        dst="$(svc_profiles "$s")/$(basename "$f")"
        if [ -e "$dst" ]; then cmp -s "$f" "$dst" || { echo "ERROR: different $dst"; exit 1; }
        else cp -p "$f" "$dst"; fi
    done
    cmp -s "$(svc_profiles "$s")/P4.conf" "$(svc_dropin "$s")" || { echo "ERROR: preexisting P4 differs for $s"; exit 1; }
done
if [ ! -f "$(svc_profiles nginx)/P3.conf" ]; then
    install -m 0644 "$STAND/profiles/nginx/P3.conf" "$(svc_profiles nginx)/P3.conf"
fi
install -m 0755 "$HERE/slab_fp_v005.sh" "$HERE/slab_inservice_v005.sh" "$HERE/slab_dropuser_v005.py" /usr/local/bin/
for f in /home/systemd-lab/marker /root/systemd-lab-marker /etc/systemd-lab/credential /var/tmp/systemd-lab-marker; do
    [ -f "$f" ] || { echo "ERROR: required existing synthetic object missing: $f"; exit 1; }
done
printf 'TMP_MARKER\n' > /tmp/systemd-lab-marker
chmod 0644 /tmp/systemd-lab-marker
if [ ! -e /dev/systemd-lab-null ]; then mknod /dev/systemd-lab-null c 1 3; fi
[ -c /dev/systemd-lab-null ] || { echo 'ERROR: incorrect synthetic device type'; exit 1; }
chmod 0666 /dev/systemd-lab-null
for u in root labweb labredis labpg; do systemctl start "lab-proc-target@$u"; done
for s in nginx redis postgresql; do systemctl start "$(svc_unit "$s")"; svc_health "$s"; done
require_rest_state nginx redis postgresql
psql -h 127.0.0.1 -p 55432 -U labpg -d systemd_bench -qAt -c 'SELECT 1'
bash "$HERE/make_candidates_v005.sh"
bash "$HERE/cap_ablation_v005.sh"
{
    date -Is
    cat /etc/os-release
    uname -a
    lscpu
    systemctl --version
    nginx -v 2>&1
    redis-server -v
    postgres -V
    python3 -V
    strace -V
    df -h /root /var
    systemctl --type=service --state=running --no-pager
    find /root/systemd-lab-results -maxdepth 2 -type d
} > "$ROOT/initial-state/platform.txt"
find "$ROOT/nginx/profiles" "$ROOT/redis/profiles" "$ROOT/postgresql/profiles" -type f -print0 | sort -z | xargs -0 sha256sum > "$ROOT/initial-state/profile-sha256.txt"
echo 'PREPARATION_COMPLETE'
