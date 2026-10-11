#!/usr/bin/env bash
# prepare_stand_v004.sh -- brings a stand built by the previous revision of
# setup_stand to the state the v004 scripts expect. A stand built by
# setup_stand_v004.sh needs nothing from this script.
#
# The only change: the three helper programs are installed in /usr/local/bin
# under their v004 names. Services, unit files, profiles and earlier results
# are not touched; the helpers of the previous revision stay in place.
set -Eeuo pipefail
HERE=$(dirname "$(readlink -f "$0")")
. "$HERE/slab_common_v004.sh"
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: run as root'; exit 1; }

install -m 0755 "$HERE/slab_fp_v004.sh" "$HERE/slab_inservice_v004.sh" "$HERE/slab_dropuser_v004.py" \
    /usr/local/bin/
sha256sum "$FP" "$INSERVICE" "$DROPUSER"
require_files "$PROBE" "$XPROBE"
for tool in findmnt mount ab curl taskset shuf; do
    command -v "$tool" >/dev/null || { echo "MISSING TOOL: $tool"; exit 1; }
done
require_rest_state nginx redis postgresql
for u in labweb labredis labpg root; do
    systemctl is-active --quiet "lab-proc-target@$u" \
        || echo "NOTE: lab-proc-target@$u is not running (start it before probe_all_v004.sh)"
done
echo 'STAND READY FOR v004'
