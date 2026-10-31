#!/usr/bin/env bash
# Same monotonic traffic and link tools as SRv6. Does not remove a live SR policy.
set -euo pipefail
cd "$(dirname "$0")"
if [ "${1:-}" = --help ] || [ "${1:-}" = -h ]; then
    echo 'Usage: bash run_baseline.sh [unique-run-id]'; exit 0
fi
[ "$#" -le 1 ] || { echo 'Only one run ID is accepted'; exit 2; }
IS_SRV6=0; CONTROL=0; SCENARIO=baseline-monotonic
source ./run_common.sh "${1:-$(date +%Y%m%d_%H%M%S)_$RANDOM}"
pathA() {
    local route
    route=$(docker exec "$R1" ip -6 route get 2001:db8:b::2)
    [[ "$route" == *'dev eth2'* && "$route" != *encap* ]]
}
for _ in $(seq 1 60); do pathA && break; sleep 1; done
pathA || { echo 'Ordinary IPv6 Path A is not active; inspect the R1 host policy first.'; exit 1; }
docker exec "$H1" traceroute6 -n 2001:db8:b::2 > "$OUT/trace_before.txt" 2>&1
start_receiver
start_sender
sleep "$CUT_AT"
docker exec "$R2" python3 "$TMP/tools/link.py" eth2 down "$TMP/cut.log"
wait "$SENDPID"
docker exec "$H1" traceroute6 -n 2001:db8:b::2 > "$OUT/trace_after.txt" 2>&1
wait "$RECVPID"
collect
restore_lab
RESTORE_OK=1; verify_restoration baseline || RESTORE_OK=0   # enforced: ordinary route via eth2, 0% ping loss
echo "Evidence: $OUT"
python3 analyze.py "$OUT"
[ "$RESTORE_OK" = 1 ] || { echo "RESTORATION FAILED: this attempt is excluded from statistics; see $OUT/RESTORE_ERROR.txt"; exit 1; }
