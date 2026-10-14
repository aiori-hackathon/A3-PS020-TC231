#!/bin/bash
# usage: srv6_policy.sh A|B   (sets R1's SRv6 encap policy for h2)
case "$1" in
  A) SEGS=fc00:0:2::1,fc00:0:5::d6; DEV=eth2;;
  B) SEGS=fc00:0:3::1,fc00:0:4::1,fc00:0:5::d6; DEV=eth3;;
  *) echo "usage: $0 A|B"; exit 1;;
esac
docker exec clab-srv6-r1 ip -6 route replace 2001:db8:b::2/128 encap seg6 mode encap segs $SEGS dev $DEV
