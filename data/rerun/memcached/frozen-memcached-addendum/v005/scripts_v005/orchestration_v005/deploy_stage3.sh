#!/usr/bin/env bash
# deploy_stage3.sh -- lays out a checkout of this repository on the stand
# VM the way the stage-3 drivers expect it (docs/EXPERIMENTS_v005.md, "Раскладка
# на стенде"). Written after the experiment; the executed
# run had the same layout under /root/article-experiment/20261012-v005.
#
# Usage, as root on the VM, from a checkout that is NOT inside SLAB_BASE:
#   git clone https://github.com/F0urA/systemd-hardening-lab.git /root/src
#   bash /root/src/scripts_v005/orchestration_v005/deploy_stage3.sh
# Then: bash "$SLAB_BASE/run_stage3.sh" stand   (see GUIDE_v005.md, stage 3)
set -Eeuo pipefail
export LC_ALL=C
REPO=$(readlink -f "$(dirname "$(readlink -f "$0")")/../..")
BASE=$(readlink -m "${SLAB_BASE:-/root/systemd-hardening-lab}")
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: run as root on the laboratory VM'; exit 1; }
[ -d "$REPO/scripts_v005" ] && [ -d "$REPO/stand_v005" ] || { echo "ERROR: $REPO is not a checkout"; exit 1; }
case "$REPO/" in "$BASE"/*) echo "ERROR: checkout $REPO lies inside SLAB_BASE=$BASE; clone it elsewhere"; exit 1 ;; esac
[ ! -e "$BASE" ] || { echo "ERROR: $BASE exists; a new run needs a new SLAB_BASE"; exit 1; }
# Windows checkouts with CRLF in scripts would fail on the VM in obscure ways.
if grep -rlI $'\r' "$REPO/scripts_v005" "$REPO/stand_v005" --include='*.sh' --include='*.py' \
        --include='*.conf' --include='*.service' --include='*.c' | head -n 1 | grep -q .; then
    echo 'ERROR: CRLF line endings in scripts; clone on the VM or with core.autocrlf=false'; exit 1
fi

S="$REPO/scripts_v005"
mkdir -p "$BASE/frozen-timing/v005" "$BASE/frozen-mount-states" "$BASE/post-analysis/frozen-timing/v005" \
         "$BASE/post-analysis/frozen-primary/v005" "$BASE/results_v005"
# Measurement scripts and stand files, as frozen-timing of the executed run.
cp -a "$S" "$REPO/stand_v005" "$BASE/frozen-timing/v005/"
# Mount-state matrix (supplement_mount_states_v005.sh, mount_state_helper_v005.py).
cp -a "$S" "$BASE/frozen-mount-states/"
# Analyzers: analyze_v005.py imports build_criteria/select_profile from
# frozen-primary, analyze_memcached_v005.py from frozen-timing; both read the
# results through raw-vm.
cp -a "$S" "$BASE/post-analysis/frozen-primary/v005/"
cp -a "$S" "$BASE/post-analysis/frozen-timing/v005/"
cp -a "$S"/analysis_v005/analyze_v005.py "$S"/analysis_v005/analyze_memcached_v005.py \
      "$S"/analysis_v005/inspect_series_v005.py "$BASE/post-analysis/"
ln -s ../results_v005 "$BASE/post-analysis/raw-vm"
# Queue drivers live in BASE itself.
cp -a "$S"/orchestration_v005/driver_extensions_v005.sh "$S"/orchestration_v005/run_stage3.sh \
      "$S"/analysis_v005/inspect_series_v005.py "$BASE/"

( cd "$BASE" && find . -path ./results_v005 -prune -o -type f -print0 | sort -z | xargs -0 sha256sum ) \
    > "$BASE/deployed-sha256.txt"
commit=$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)
printf 'DEPLOYED_FROM=%s\nCOMMIT=%s\nUTC=%s\n' "$REPO" "$commit" "$(date -u -Is)" > "$BASE/deployed-from.txt"
cat "$BASE/deployed-from.txt"
echo "DEPLOYED: $BASE ($(wc -l < "$BASE/deployed-sha256.txt") files)"
