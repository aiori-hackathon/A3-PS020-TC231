#!/bin/bash
# SRv6 End SIDs on r1..r5 + End.DT6 decap SID on r5
for n in 1 2 3 4 5; do
  docker exec clab-srv6-r$n ip -6 route replace fc00:0:$n::1/128 encap seg6local action End dev eth1
done

docker exec clab-srv6-r5 ip -6 route replace fc00:0:5::d6/128 encap seg6local action End.DT6 table 254 dev eth1
