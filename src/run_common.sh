#!/usr/bin/env bash
# Sourced by both monotonic runners. Existing Docker lab and OSPF are required.
set -euo pipefail
RUN=${1:-$(date +%Y%m%d_%H%M%S)_$RANDOM}
[[ "$RUN" =~ ^[A-Za-z0-9_-]+$ ]] || { echo 'Use a run ID containing letters, digits, _ or -'; exit 1; }
RATE=1000; DUR=20; CUT_AT=5; PAYLOAD=64; PORT=5001
R1=clab-srv6-r1; R2=clab-srv6-r2; H1=clab-srv6-h1; H2=clab-srv6-h2
exec 9>/tmp/ps020-monotonic-lab.lock
flock -n 9 || { echo 'Another monotonic runner is active'; exit 1; }
mkdir -p "results/$SCENARIO"
OUT="results/$SCENARIO/run$RUN"
mkdir "$OUT"  # Refuse to overwrite an existing run.
TMP="/tmp/ps020-${SCENARIO}-${RUN}"
for c in "$H1" "$H2" "$R1" "$R2"; do
    docker exec "$c" mkdir "$TMP"
    docker cp tools "$c:$TMP/tools" >/dev/null
done
printf 'clock=monotonic\nschema_version=2\nscenario=%s\nrate=%s\ndur=%s\ncut_at=%s\npayload=%s\n' "$SCENARIO" "$RATE" "$DUR" "$CUT_AT" "$PAYLOAD" > "$OUT/params.txt"
COLLECTED=0; RESTORED=0
collect() {
    local rc=0
    docker cp "$H2:$TMP/recv.csv" "$OUT/recv.csv" >/dev/null 2>&1 || rc=1
    docker cp "$H1:$TMP/send.txt" "$OUT/send.txt" >/dev/null 2>&1 || rc=1
    if [ "$CONTROL" = 0 ]; then
        docker cp "$R2:$TMP/cut.log" "$OUT/cut.log" >/dev/null 2>&1 || rc=1
    fi
    if [ "$IS_SRV6" = 1 ]; then
        docker cp "$R1:$TMP/fail.txt" "$OUT/fail.txt" >/dev/null 2>&1 || rc=1
    fi
    COLLECTED=1
    return "$rc"
}
restore_lab() {
    [ "$RESTORED" = 0 ] || return 0
    docker exec "$R2" python3 "$TMP/tools/link.py" eth2 up "$TMP/restore.log" || return 1
    docker cp "$R2:$TMP/restore.log" "$OUT/restore.log" >/dev/null || return 1
    if [ "$IS_SRV6" = 1 ]; then bash srv6_policy.sh A || return 1; fi
    RESTORED=1
}
# verify_restoration srv6|baseline
# ENFORCES the post-run lab state; it does not merely record it. After restore_lab it captures the
# restored route, the R1->R5 underlay route and a fresh 5-packet ping, then judges them with
# restoration.py - the same code the analyzers use. A ping that exits 0 can still have lost packets,
# so only "0% packet loss" with every reply received passes. Retries (default 180 s, as long as the
# old underlay wait) exist only because OSPF needs time to reconverge after the link comes back;
# every failed attempt's ping output is kept as ping_restored_try<N>.txt, and the last attempt is
# ping_restored.txt. On failure RESTORE_ERROR.txt is written and the function returns 1.
verify_restoration() {
    local mode=$1 try=0 detail t0=$SECONDS
    local timeout=${PS020_RESTORE_TIMEOUT:-180} poll=${PS020_RESTORE_POLL_S:-2}
    while :; do
        try=$((try + 1))
        if [ "$mode" = srv6 ]; then
            docker exec "$R1" ip -6 route show 2001:db8:b::2/128 > "$OUT/route_restored.txt" 2>&1 || true
            docker exec "$R1" ip -6 route get fc00:0:5::d6 > "$OUT/underlay_restored.txt" 2>&1 || true
        else
            docker exec "$R1" ip -6 route get 2001:db8:b::2 > "$OUT/route_restored.txt" 2>&1 || true
        fi
        docker exec "$H1" ping -6 -c 5 -W 1 2001:db8:b::2 > "$OUT/ping_restored.txt" 2>&1 || true
        if detail=$(python3 restoration.py "$OUT" --mode "$mode" --require); then
            return 0
        fi
        cp "$OUT/ping_restored.txt" "$OUT/ping_restored_try$try.txt"
        [ $((SECONDS - t0)) -lt "$timeout" ] || break
        sleep "$poll"
    done
    {
        echo "RESTORATION FAILED after $try attempt(s) over $((SECONDS - t0))s (mode=$mode):"
        echo "$detail"
    } > "$OUT/RESTORE_ERROR.txt"
    cat "$OUT/RESTORE_ERROR.txt"
    return 1
}

cleanup() {
    local rc=$?
    trap - EXIT
    if [ "$COLLECTED" = 0 ]; then collect || true; fi
    if ! restore_lab; then
        echo 'RESTORATION FAILED: inspect the link and policy before the next run.' | tee "$OUT/RESTORE_ERROR.txt"
        rc=1
    fi
    if [ "$rc" != 0 ]; then echo "INCOMPLETE/INVALID: evidence retained in $OUT"; fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
docker exec "$R2" sysctl -w net.ipv6.conf.eth2.keep_addr_on_down=1 >/dev/null
docker exec "$R2" ip link set eth2 up
start_receiver() {
    docker exec "$H2" python3 "$TMP/tools/recv.py" "$PORT" "$((DUR+5))" "$TMP/recv.csv" > "$OUT/receiver.log" 2>&1 &
    RECVPID=$!
    local ready=0
    for _ in $(seq 1 50); do
        if docker exec "$H2" test -s "$TMP/recv.csv.ready"; then ready=1; break; fi
        sleep 0.1
    done
    [ "$ready" = 1 ] || { echo 'receiver readiness timeout'; return 1; }
}
start_sender() {
    docker exec "$H1" python3 "$TMP/tools/send.py" 2001:db8:b::2 "$PORT" "$RATE" "$DUR" "$PAYLOAD" "$TMP/send.txt" > "$OUT/sender.log" 2>&1 &
    SENDPID=$!
}
