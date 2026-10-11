#!/usr/bin/env bash
# make_candidates_v004.sh -- builds the path-based candidate P6 for each
# service: P6 = saved P4 + ProtectSystem=strict + ReadWritePaths=<inventory>.
# Existing files are never overwritten.
set -Eeuo pipefail
HERE=$(dirname "$(readlink -f "$0")")
. "$HERE/slab_common_v004.sh"
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: run as root'; exit 1; }

nginx_rw_paths() {
    # pid file lives in /run; the error log and the compiled-in temp paths
    # are taken from the configuration and from "nginx -V".
    local paths="/run -/var/log/slab-nginx-error.log" p
    for p in $(/usr/sbin/nginx -V 2>&1 | tr ' ' '\n' \
            | sed -n 's/^--http-[a-z-]*-temp-path=//p' | sort -u); do
        paths="$paths -$p"
    done
    echo "$paths"
}

build() {
    local svc=$1 rw=$2 dir p4 p6
    dir=$(svc_profiles "$svc")
    p4="$dir/P4.conf"
    p6="$dir/P6.conf"
    [ -f "$p4" ] || { echo "ERROR: $p4 is missing"; exit 1; }
    if [ -e "$p6" ]; then
        echo "KEEP $p6 (already exists, not overwritten)"
    else
        {
            cat "$p4"
            # Guarantee a newline between P4 and the appended settings.
            [ -z "$(tail -c 1 "$p4")" ] || echo
            echo '# v004: P6 = P4 + read-only file system with explicit write paths'
            echo 'ProtectSystem=strict'
            echo "ReadWritePaths=$rw"
        } > "$p6"
        echo "CREATED $p6"
    fi
    # P6 must be an append-only extension of the exact saved P4.
    head -c "$(wc -c < "$p4")" "$p6" | cmp -s "$p4" - || {
        echo "ERROR: $p6 is not an extension of $p4"; exit 1;
    }
    echo "--- appended to P4 in $p6:"
    tail -c +"$(( $(wc -c < "$p4") + 1 ))" "$p6"
    sha256sum "$p4" "$p6"
    echo
}

build nginx "$(nginx_rw_paths)"
build redis /var/lib/systemd-lab/redis
build postgresql /var/lib/systemd-lab/postgresql
echo 'DONE. Candidates are not applied to any service by this script.'
