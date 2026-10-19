#!/usr/bin/env bash
# cap_ablation_v005.sh -- builds the capability-ablation variants of the Nginx
# profile P1c (protocol_review2_v005.txt, section 3; review remark 4). Each
# variant is P1r plus one CapabilityBoundingSet; this isolates the contribution
# of individual capabilities to the protective effect of P1c.
#
# It only BUILDS profiles (like make_candidates_v005.sh); the goal G1 is then
# measured for them by the tested scenarios_v005.sh:
#   ./cap_ablation_v005.sh
#   NGINX_PROFILES='P1r P1c P1cADMIN P1cPTRACE P1cDAC P1cCHROOT' \
#       ./scenarios_v005.sh nginx
# The smallest set under which every G1 cell stays BLOCKED is read from the
# resulting goals.csv (P1c is expected to be that set).
#
# Existing profile files are never overwritten.
set -Eeuo pipefail
HERE=$(dirname "$(readlink -f "$0")")
. "$HERE/slab_common_v005.sh"
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: run as root'; exit 1; }

DIR=$(svc_profiles nginx)
P1R="$DIR/P1r.conf"
[ -f "$P1R" ] || { echo "ERROR: $P1R is missing (run make_candidates_v005.sh)"; exit 1; }
BASE=$(sed -n 's/^CapabilityBoundingSet=//p' "$DIR/P1c.conf")
[ -n "$BASE" ] || { echo "ERROR: no CapabilityBoundingSet in P1c.conf"; exit 1; }

# build NAME EXTRA_CAP COMMENT -- P1r + CapabilityBoundingSet=<base + extra>.
# EXTRA_CAP empty reproduces P1c itself (the base set) under the ablation name.
build() {
    local name=$1 extra=$2 comment=$3 new caps
    new="$DIR/$name.conf"
    caps="$BASE"
    [ -z "$extra" ] || caps="$BASE $extra"
    if [ -e "$new" ]; then
        echo "KEEP $new (already exists, not overwritten)"
    else
        {
            cat "$P1R"
            [ -z "$(tail -c 1 "$P1R")" ] || echo
            echo "# $comment"
            echo "CapabilityBoundingSet=$caps"
        } > "$new"
        echo "CREATED $new"
    fi
    head -c "$(wc -c < "$P1R")" "$new" | cmp -s "$P1R" - || {
        echo "ERROR: $new is not an extension of $P1R"; exit 1;
    }
    echo "  CapabilityBoundingSet=$caps"
    sha256sum "$new"
}

echo '=== capability ablation of P1c (base set = the three capabilities of P4) ==='
build P1cADMIN  CAP_SYS_ADMIN  'v005 ablation: P1c base + CAP_SYS_ADMIN'
build P1cPTRACE CAP_SYS_PTRACE 'v005 ablation: P1c base + CAP_SYS_PTRACE'
build P1cDAC    CAP_DAC_OVERRIDE 'v005 ablation: P1c base + CAP_DAC_OVERRIDE'
build P1cCHROOT CAP_SYS_CHROOT 'v005 ablation: P1c base + CAP_SYS_CHROOT'
echo
echo 'DONE. Profiles are not applied to any service by this script.'
echo "NEXT: NGINX_PROFILES='P1r P1c P1cADMIN P1cPTRACE P1cDAC P1cCHROOT' ./scenarios_v005.sh nginx"
