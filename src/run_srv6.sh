#!/bin/bash
# SRv6: policy A (R1-R2-R5) -> cut R2-R5 (r2:eth2) -> R1 probe detects, switches to policy B (R1-R3-R4-R5)
cd "$(dirname "$0")"
RUN=${1:-1}; RATE=1000; DUR=20; CUT_AT=5; PAYLOAD=64; PORT=5001; MISS_MS=5
OUT=results/srv6/run$RUN; mkdir -p $OUT
R1=clab-srv6-r1; R2=clab-srv6-r2; H1=clab-srv6-h1; H2=clab-srv6-h2
BSEGS=fc00:0:3::1,fc00:0:4::1,fc00:0:5::d6
underA() { docker exec $R1 ip -6 route get fc00:0:5::d6 | grep -q "dev eth2"; }
for c in $H1 $H2 $R1 $R2; do docker cp tools $c:/ >/dev/null; done
docker exec $R2 sysctl -w net.ipv6.conf.eth2.keep_addr_on_down=1 >/dev/null
docker exec $H2 rm -f /tmp/recv.csv; docker exec $H1 rm -f /tmp/send.txt
docker exec $R2 rm -f /tmp/cut.log; docker exec $R1 rm -f /tmp/fail.txt
for i in $(seq 1 60); do underA && break; sleep 2; done
underA || { echo "underlay not on Path A at start"; exit 1; }
./srv6_policy.sh A
sleep 1
docker exec $R1 ip -6 route show 2001:db8:b::2/128 > $OUT/route_before.txt
grep -q "fc00:0:2::1" $OUT/route_before.txt || { echo "ABORT: policy A not installed"; exit 1; }
docker exec $H1 ping -c 2 -q 2001:db8:b::2 >/dev/null || { echo "ABORT: h1 cannot reach h2"; exit 1; }
docker exec -d $R1 python3 /tools/failover.py 2001:db8:b::2 /tmp/fail.txt $((DUR+2)) $MISS_MS $BSEGS eth3
docker exec -d $H2 python3 /tools/recv.py $PORT $((DUR+4)) /tmp/recv.csv
sleep 1
docker exec -d $H1 python3 /tools/send.py 2001:db8:b::2 $PORT $RATE $DUR $PAYLOAD /tmp/send.txt
sleep $CUT_AT
docker exec $R2 python3 /tools/link.py eth2 down /tmp/cut.log
sleep $((DUR - CUT_AT + 1))
docker exec $R1 ip -6 route show 2001:db8:b::2/128 > $OUT/route_after.txt
for i in $(seq 1 40); do docker exec $H2 test -s /tmp/recv.csv && docker exec $H1 test -s /tmp/send.txt && docker exec $R1 test -s /tmp/fail.txt && break; sleep 1; done
sleep 1
docker cp $H2:/tmp/recv.csv $OUT/recv.csv
docker cp $H1:/tmp/send.txt $OUT/send.txt
docker cp $R2:/tmp/cut.log $OUT/cut.log
docker cp $R1:/tmp/fail.txt $OUT/fail.txt
printf "scenario=srv6\nrate=%s\ndur=%s\ncut_at=%s\npayload=%s\nmiss_ms=%s\n" $RATE $DUR $CUT_AT $PAYLOAD $MISS_MS > $OUT/params.txt
docker exec $R2 python3 /tools/link.py eth2 up /tmp/restore.log
for i in $(seq 1 90); do underA && break; sleep 2; done
underA && echo "restored: underlay back on Path A" || echo "WARNING: underlay not restored"
python3 analyze_srv6.py $OUT
