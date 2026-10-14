#!/bin/bash
# Baseline (OSPFv3 only): UDP stream h1->h2, cut R2-R5 link (r2:eth2), log timestamps
cd "$(dirname "$0")"
RUN=${1:-1}; RATE=1000; DUR=20; CUT_AT=5; PAYLOAD=64; PORT=5001
OUT=results/baseline/run$RUN; mkdir -p $OUT
R1=clab-srv6-r1; R2=clab-srv6-r2; H1=clab-srv6-h1; H2=clab-srv6-h2
pathA() { r=$(docker exec $R1 ip -6 route get 2001:db8:b::2); echo "$r" | grep -q "dev eth2" && ! echo "$r" | grep -q encap; }
for c in $H1 $H2 $R2; do docker cp tools $c:/ >/dev/null; done
docker exec $R2 sysctl -w net.ipv6.conf.eth2.keep_addr_on_down=1 >/dev/null
docker exec $H2 rm -f /tmp/recv.csv; docker exec $H1 rm -f /tmp/send.txt; docker exec $R2 rm -f /tmp/cut.log
for i in $(seq 1 60); do pathA && break; sleep 2; done
pathA || { echo "Path A not active at start"; exit 1; }
docker exec $H1 traceroute6 -n 2001:db8:b::2 > $OUT/trace_before.txt 2>&1
docker exec -d $H2 python3 /tools/recv.py $PORT $((DUR+4)) /tmp/recv.csv
sleep 1
docker exec -d $H1 python3 /tools/send.py 2001:db8:b::2 $PORT $RATE $DUR $PAYLOAD /tmp/send.txt
sleep $CUT_AT
docker exec $R2 python3 /tools/link.py eth2 down /tmp/cut.log
sleep $((DUR - CUT_AT + 2))
docker exec $H1 traceroute6 -n 2001:db8:b::2 > $OUT/trace_after.txt 2>&1
for i in $(seq 1 30); do docker exec $H2 test -s /tmp/recv.csv && docker exec $H1 test -s /tmp/send.txt && break; sleep 1; done
sleep 1
docker cp $H2:/tmp/recv.csv $OUT/recv.csv
docker cp $H1:/tmp/send.txt $OUT/send.txt
docker cp $R2:/tmp/cut.log $OUT/cut.log
printf "scenario=baseline\nrate=%s\ndur=%s\ncut_at=%s\npayload=%s\n" $RATE $DUR $CUT_AT $PAYLOAD > $OUT/params.txt
docker exec $R2 python3 /tools/link.py eth2 up /tmp/restore.log
for i in $(seq 1 90); do pathA && break; sleep 2; done
pathA && echo "restored: Path A active again" || echo "WARNING: Path A not restored"
python3 analyze.py $OUT baseline
