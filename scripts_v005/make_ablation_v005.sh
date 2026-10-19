#!/usr/bin/env bash
# make_ablation_v005.sh -- two auxiliary Nginx profiles for the cost
# hypothesis (protocol_load_v005.txt, section 6):
#   P4s = only the directives of P4 that install system-call filters
#   P4n = P4 without those directives
# Together with P0 and P4 they form a 2x2 design: filter group on/off  x
# all other directives on/off. The profiles are not candidates of the
# selection rule. Existing files are never overwritten; no service is touched.
set -Eeuo pipefail
HERE=$(dirname "$(readlink -f "$0")")
. "$HERE/slab_common_v005.sh"
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: run as root'; exit 1; }
require_files "$FP"

DIR=$(svc_profiles nginx)
P4="$DIR/P4.conf"
GROUP='^(SystemCallFilter|SystemCallErrorNumber|RestrictAddressFamilies|MemoryDenyWriteExecute|RestrictNamespaces|LockPersonality|RestrictRealtime|RestrictSUIDSGID)='
[ -f "$P4" ] || { echo "ERROR: $P4 is missing"; exit 1; }

write_once() {  # FILE  (content on stdin)
    if [ -e "$1" ]; then
        cat > /dev/null
        echo "KEEP $1 (already exists, not overwritten)"
    else
        cat > "$1"
        echo "CREATED $1"
    fi
}

{ echo '[Service]'; grep -E "$GROUP" "$P4"; } | write_once "$DIR/P4s.conf"
grep -Ev "$GROUP" "$P4" | write_once "$DIR/P4n.conf"

# The two files must split the settings of P4 exactly.
settings() { grep -E '^[A-Za-z].*=' "$1" | sort; }
if ! diff <(settings "$P4") <(cat "$DIR/P4s.conf" "$DIR/P4n.conf" | grep -E '^[A-Za-z].*=' | sort) >/dev/null; then
    echo 'ERROR: P4s and P4n do not add up to P4'; exit 1
fi
echo "SETTINGS: P4=$(settings "$P4" | wc -l) P4s=$(settings "$DIR/P4s.conf" | wc -l) P4n=$(settings "$DIR/P4n.conf" | wc -l)"
sha256sum "$P4" "$DIR/P4s.conf" "$DIR/P4n.conf"

echo
echo '===== SYSTEM-CALL FILTERS SEEN BY A MODEL PROCESS (user labweb) ====='
for profile in P0 P4s P4n P4; do
    file=P0
    [ "$profile" = P0 ] || file="$DIR/$profile.conf"
    props_from_profile "$file"
    out=$(systemd-run --quiet --wait --pipe --collect --unit="slab-v005-abl-${profile,,}-$$" \
        -p Type=exec -p User=labweb -p Group=labweb ${PROPS[@]+"${PROPS[@]}"} \
        "$FP" self 2>&1 | grep -E '^Seccomp' | tr '\n' ' ' || true)
    echo "$profile: ${out:-no output}"
done
echo
echo 'DONE. Next: ./benchmark_v005.sh nginx 20 P4 P4s P4n'
