#!/bin/bash
set -e
cd "$(dirname "$0")"
ROOT="pcaps/verified_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$ROOT"
for P in A B; do
    ./srv6_policy.sh "$P"
    sleep 2
    OUT="$ROOT/policy$P"
    mkdir -p "$OUT"
    if [ "$P" = A ]; then
        POINTS="r1:eth2 r2:eth2 r5:eth3"
    else
        POINTS="r1:eth3 r3:eth2 r4:eth2 r5:eth3"
    fi
    PIDS=""
    for POINT in $POINTS; do
        R=${POINT%%:*}
        I=${POINT##*:}
        FILE="/tmp/verified_${P}_${R}_${I}.pcap"
        FILTER='ip6 and ip6[6] == 43'
        if [ "$R" = r5 ]; then
            FILTER='ip6 and src host 2001:db8:a::2 and dst host 2001:db8:b::2 and ip6[6] == 58'
        fi
        docker exec "clab-srv6-$R" timeout 15 tcpdump \
            -i "$I" -Q out -nn -s 0 -U -c 3 \
            -w "$FILE" "$FILTER" \
            > "$OUT/${R}_${I}_capture.log" 2>&1 &
        PIDS="$PIDS $!"
    done
    sleep 3
    docker exec clab-srv6-h1 ping -6 -c 3 2001:db8:b::2 \
        | tee "$OUT/ping.txt"
    for PID in $PIDS; do
        wait "$PID" || {
            echo "Capture failed. Check logs in $OUT"
            exit 1
        }
    done
    for POINT in $POINTS; do
        R=${POINT%%:*}
        I=${POINT##*:}
        FILE="/tmp/verified_${P}_${R}_${I}.pcap"
        docker cp "clab-srv6-$R:$FILE" "$OUT/"
        echo "===== POLICY $P: $R $I OUTGOING ====="
        docker exec "clab-srv6-$R" tcpdump -nn -vv -r "$FILE" \
            2>&1 | tee "$OUT/${R}_${I}.txt"
    done
done
echo "Saved captures and decoded text in: $ROOT"
echo "Policy B remains active."
