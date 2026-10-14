#!/bin/bash
# Configure and start OSPFv3 (FRR) on r1..r5 of the clab-srv6 lab
cd "$(dirname "$0")"; mkdir -p frr
P2P="r1:eth2 r1:eth3 r2:eth1 r2:eth2 r3:eth1 r3:eth2 r4:eth1 r4:eth2 r5:eth1 r5:eth2"
PASSIVE="r1:eth1 r5:eth3"
for n in 1 2 3 4 5; do
  r=r$n; f=frr/$r.conf; c=clab-srv6-$r
  {
    echo "frr defaults traditional"; echo "hostname $r"; echo "!"
    echo "interface lo"; echo " ipv6 ospf6 area 0.0.0.0"
    for e in $P2P; do
      if [ "${e%%:*}" = "$r" ]; then
        echo "!"; echo "interface ${e##*:}"
        echo " ipv6 ospf6 area 0.0.0.0"; echo " ipv6 ospf6 network point-to-point"
      fi
    done
    for e in $PASSIVE; do
      if [ "${e%%:*}" = "$r" ]; then
        echo "!"; echo "interface ${e##*:}"
        echo " ipv6 ospf6 area 0.0.0.0"; echo " ipv6 ospf6 passive"
      fi
    done
    echo "!"; echo "ipv6 route fc00:0:$n::/48 blackhole"
    echo "!"; echo "router ospf6"; echo " ospf6 router-id 10.0.0.$n"; echo " redistribute static"; echo "!"
  } > $f
  docker exec $c ip -6 addr add 2001:db8:ffff::$n/128 dev lo 2>/dev/null
  docker exec $c sed -i 's/^ospf6d=no/ospf6d=yes/' /etc/frr/daemons
  docker cp $f $c:/etc/frr/frr.conf
  docker exec $c chown frr:frr /etc/frr/frr.conf
  docker exec $c chmod 640 /etc/frr/frr.conf
  docker exec $c /usr/lib/frr/frrinit.sh start
done
