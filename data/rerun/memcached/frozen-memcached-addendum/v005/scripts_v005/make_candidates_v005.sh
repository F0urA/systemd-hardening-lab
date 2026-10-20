#!/usr/bin/env bash
# make_candidates_v005.sh -- builds the candidates that are derived from a
# saved profile by appending settings:
#   P6   (every service)  saved P4 + ProtectSystem=strict + ReadWritePaths=<inventory>
#   P1r  (Nginx)          saved P1 + ReadOnlyPaths=<web directory>
#   P1c  (Nginx)          P1r + CapabilityBoundingSet=<the three capabilities of P4>
# P1r and P1c were added in revision v004 (protocol_review_v005.txt, section 2).
# Existing files are never overwritten.
set -Eeuo pipefail
HERE=$(dirname "$(readlink -f "$0")")
. "$HERE/slab_common_v005.sh"
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

# extend SERVICE BASE NEW COMMENT SETTING... -- NEW = saved BASE + settings.
extend() {
    local svc=$1 from=$2 comment=$4 base new dir line
    dir=$(svc_profiles "$svc")
    base="$dir/$2.conf"
    new="$dir/$3.conf"
    shift 4
    [ -f "$base" ] || { echo "ERROR: $base is missing"; exit 1; }
    if [ -e "$new" ]; then
        echo "KEEP $new (already exists, not overwritten)"
    else
        {
            cat "$base"
            # Guarantee a newline between the base and the appended settings.
            [ -z "$(tail -c 1 "$base")" ] || echo
            echo "# $comment"
            for line in "$@"; do echo "$line"; done
        } > "$new"
        echo "CREATED $new"
    fi
    # The candidate must be an append-only extension of the exact saved base.
    head -c "$(wc -c < "$base")" "$new" | cmp -s "$base" - || {
        echo "ERROR: $new is not an extension of $base"; exit 1;
    }
    echo "--- appended to $from in $new:"
    tail -c +"$(( $(wc -c < "$base") + 1 ))" "$new"
    sha256sum "$base" "$new"
    echo
}

P6_NOTE='v003: P6 = P4 + read-only file system with explicit write paths'
extend nginx P4 P6 "$P6_NOTE" 'ProtectSystem=strict' "ReadWritePaths=$(nginx_rw_paths)"
extend redis P4 P6 "$P6_NOTE" 'ProtectSystem=strict' 'ReadWritePaths=/var/lib/systemd-lab/redis'
extend postgresql P4 P6 "$P6_NOTE" 'ProtectSystem=strict' 'ReadWritePaths=/var/lib/systemd-lab/postgresql'

CAPS=$(sed -n 's/^CapabilityBoundingSet=//p' "$(svc_profiles nginx)/P4.conf")
[ -n "$CAPS" ] || { echo 'ERROR: no CapabilityBoundingSet in the saved Nginx P4'; exit 1; }
extend nginx P1 P1r 'v004: P1r = P1 + read-only web directory' "ReadOnlyPaths=$SITE"
extend nginx P1r P1c 'v004: P1c = P1r + the capability set of P4' "CapabilityBoundingSet=$CAPS"

# v005 (protocol_review2_v005.txt, section 7, review remark 14): the ladder for
# Redis and PostgreSQL. The ladder groups P1 and P2 are generic (no service
# path), so they are copied from the saved Nginx ladder; P1d is P1 plus the
# write-path directive for the data directory of the service.
copy_step() {  # SERVICE STEP -- copy the generic ladder step from Nginx
    local svc=$1 step=$2 src dst
    src="$(svc_profiles nginx)/$step.conf"
    dst="$(svc_profiles "$svc")/$step.conf"
    [ -f "$src" ] || { echo "ERROR: $src is missing"; exit 1; }
    if [ -e "$dst" ]; then
        echo "KEEP $dst (already exists, not overwritten)"
    else
        cp "$src" "$dst"
        echo "CREATED $dst (copied from the Nginx ladder step $step)"
    fi
    sha256sum "$dst"
}
for svc in redis postgresql; do
    copy_step "$svc" P1
    copy_step "$svc" P2
done
extend redis P1 P1d 'v005: P1d = P1 + write path for the data directory' \
    'ProtectSystem=strict' 'ReadWritePaths=/var/lib/systemd-lab/redis'
extend postgresql P1 P1d 'v005: P1d = P1 + write path for the data directory' \
    'ProtectSystem=strict' 'ReadWritePaths=/var/lib/systemd-lab/postgresql'
echo 'DONE. Candidates are not applied to any service by this script.'
