#!/usr/bin/env bash
# Launch one pre-reviewed resumption, never a second full experiment.
set -Eeuo pipefail
export LC_ALL=C TZ=UTC
BASE=${SLAB_BASE:-/root/systemd-hardening-lab}
ROOT="$BASE/results_v005"
export SLAB_RESULTS_ROOT="$ROOT"
DRIVER="$ROOT/driver"
[[ "$(realpath "$BASE")" == "$BASE" && "$(realpath "$ROOT")" == "$ROOT" ]]
exec 8>"$BASE/resume-launch-v005.lock"
flock -n 8 || exit 2
cd "$BASE"
sha256sum --quiet -c resume-source-sha256.txt
for marker in primary-resume-started.txt post-primary-resume-started.txt \
              primary-resume-launch.log post-primary-resume-launch.log; do
    [ ! -e "$DRIVER/$marker" ] && [ ! -L "$DRIVER/$marker" ] || {
        echo "Resume was already attempted: $marker"; exit 2;
    }
done
if ps -eo args | grep -E '[b]enchmark_v005.sh|[s]lab_heartbeat_v005.py|[d]river_primary_.*v005.sh|[d]river_post_primary_.*v005.sh|[m]emcached_stage3_v005.sh' >/dev/null; then
    echo 'Another measurement/controller is alive; nothing launched'; exit 2
fi
python3 - "$1" <<'PY'
import re, subprocess, sys, time
host_epoch = int(sys.argv[1])
tracking = subprocess.check_output(['chronyc','tracking'], text=True)
print(tracking, flush=True)
offset = re.search(r'System time\s*:\s*([0-9.]+)\s+seconds', tracking)
frequency = re.search(r'Frequency\s*:\s*([0-9.]+)\s+ppm', tracking)
if not offset or not frequency or float(offset[1]) > 0.05 or float(frequency[1]) > 100 \
        or abs(time.time()-host_epoch) > 120:
    raise SystemExit('Clock preparation not confirmed; no measurement launched')
PY
. "$BASE/frozen-timing/v005/scripts_v005/slab_common_v005.sh"
require_rest_state nginx redis postgresql
python3 - <<'PY'
from resume_transport_v005 import Transport
guard = Transport()
guard.registration_hash()
if guard.current() != '':
    raise SystemExit('Reserved-ports baseline changed; not overwritten')
guard.write_exact('', '55432')
print('TEMPORARY_PG_PORT_RESERVATION=55432; original empty, no persistent sysctl change')
PY
nohup bash -c 'rc=0; bash driver_primary_resume_v005.sh > results_v005/driver/primary-resume-launch.log 2>&1 || rc=$?; printf "%s\n" "$rc" > results_v005/driver/primary-corrected-driver-exit.txt' \
    </dev/null > "$DRIVER/primary-resume-nohup.out" 2>&1 &
primary_pid=$!
printf '%s\n' "$primary_pid" > "$DRIVER/corrected-controller.pid"
nohup bash -c 'rc=0; bash driver_post_primary_resume_v005.sh > results_v005/driver/post-primary-resume-launch.log 2>&1 || rc=$?; printf "%s\n" "$rc" > results_v005/driver/post-primary-driver-exit.txt' \
    </dev/null > "$DRIVER/post-primary-resume-nohup.out" 2>&1 &
post_pid=$!
printf '%s\n' "$post_pid" > "$DRIVER/post-primary-controller.pid"
printf 'PRIMARY_PID=%s\nPOST_PID=%s\nUTC=%s\n' "$primary_pid" "$post_pid" "$(date -u -Is)" \
    | tee "$DRIVER/resume-launch-receipt.txt"
