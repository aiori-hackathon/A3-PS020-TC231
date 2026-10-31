#!/usr/bin/env bash
# Usage: bash run_srv6.sh [unique-run-id] [--no-cut] [--miss-ms N] [--confirm-ms N]
# Detector settings: flags beat env MISS_MS/CONFIRM_MS, which beat the defaults 8 and 3.
set -euo pipefail
cd "$(dirname "$0")"
source ./run_params.sh
IS_SRV6=1; CONTROL=0; SCENARIO=srv6-monotonic; RUN_ID=
USAGE='Usage: bash run_srv6.sh [unique-run-id] [--no-cut] [--miss-ms N] [--confirm-ms N]'
while [ "$#" -gt 0 ]; do
    arg=$1; shift
    case "$arg" in
        --help|-h) echo "$USAGE"; exit 0;;
        --no-cut) CONTROL=1;;
        --miss-ms|--confirm-ms)
            [ "$#" -gt 0 ] || { echo "$arg needs a value"; exit 2; }
            if [ "$arg" = --miss-ms ]; then MISS_MS=$1; else CONFIRM_MS=$1; fi; shift;;
        --miss-ms=*) MISS_MS=${arg#*=};;
        --confirm-ms=*) CONFIRM_MS=${arg#*=};;
        --*) echo "Unknown option: $arg"; exit 2;;
        *) [ -z "$RUN_ID" ] || { echo 'Only one run ID is accepted'; exit 2; }; RUN_ID=$arg;;
    esac
done
finalize_detector_params || exit 2   # validated BEFORE any run folder, lock or container is touched
if [ "$CONTROL" = 1 ]; then SCENARIO=srv6-control-monotonic; fi
source ./run_common.sh "${RUN_ID:-$(date +%Y%m%d_%H%M%S)_$RANDOM}"
printf 'miss_ms=%s\nconfirm_ms=%s\n' "$MISS_MS" "$CONFIRM_MS" >> "$OUT/params.txt"
underA() { docker exec "$R1" ip -6 route get fc00:0:5::d6 | grep -q 'dev eth2'; }
for _ in $(seq 1 60); do underA && break; sleep 1; done
underA || { echo 'underlay not on Path A'; exit 1; }
bash srv6_policy.sh A
sleep 1
docker exec "$R1" ip -6 route show 2001:db8:b::2/128 > "$OUT/route_before.txt"
grep -q fc00:0:2::1 "$OUT/route_before.txt"
docker exec "$H1" ping -6 -c 3 -W 1 2001:db8:b::2 > "$OUT/ping_before.txt"
start_receiver
docker exec "$R1" python3 "$TMP/tools/failover.py" 2001:db8:b::2 "$TMP/fail.txt" "$((DUR+4))" "$MISS_MS" fc00:0:3::1,fc00:0:4::1,fc00:0:5::d6 eth3 "$CONFIRM_MS" > "$OUT/detector.log" 2>&1 &
DETPID=$!
ready=0
for _ in $(seq 1 50); do
    if docker exec "$R1" test -s "$TMP/fail.txt.ready"; then ready=1; break; fi
    sleep 0.1
done
[ "$ready" = 1 ] || { echo 'detector readiness timeout; inspect detector.log'; exit 1; }
start_sender
if [ "$CONTROL" = 0 ]; then
    sleep "$CUT_AT"
    docker exec "$R2" python3 "$TMP/tools/link.py" eth2 down "$TMP/cut.log"
fi
wait "$SENDPID"
wait "$DETPID"
wait "$RECVPID"
docker exec "$R1" ip -6 route show 2001:db8:b::2/128 > "$OUT/route_after.txt"
collect
restore_lab
RESTORE_OK=1; verify_restoration srv6 || RESTORE_OK=0   # enforced: policy A, underlay on A, 0% ping loss
echo "Evidence: $OUT"
if [ "$CONTROL" = 1 ]; then
    if python3 analyze_control.py "$OUT"; then
        write_control_marker "$OUT" "$MISS_MS" "$CONFIRM_MS"
        echo "Control marker written: $(control_marker_path "$MISS_MS" "$CONFIRM_MS")"
    else
        invalidate_control_marker "$MISS_MS" "$CONFIRM_MS"; exit 1
    fi
else
    python3 analyze_srv6.py "$OUT"
fi
[ "$RESTORE_OK" = 1 ] || { echo "RESTORATION FAILED: this attempt is excluded from statistics; see $OUT/RESTORE_ERROR.txt"; exit 1; }
