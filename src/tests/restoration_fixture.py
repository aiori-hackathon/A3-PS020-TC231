"""Shared helper: write post-run restoration evidence into a fake run folder.
kinds: ok | busybox | wrongpolicy | loss20 | ping_errors | short_ping | no_stats | error_file |
       underlay_B | none  (none = write nothing, i.e. a runner that never captured evidence)"""
from pathlib import Path

PING_HDR = "PING 2001:db8:b::2(2001:db8:b::2) 56 data bytes\n64 bytes from 2001:db8:b::2: icmp_seq=1 ttl=60 time=0.4 ms\n"
ROUTE = {
    "srv6_A": "2001:db8:b::2  encap seg6 mode encap segs 2 [ fc00:0:2::1 fc00:0:5::d6 ] dev eth2 metric 1024 pref medium\n",
    "srv6_B": "2001:db8:b::2  encap seg6 mode encap segs 3 [ fc00:0:3::1 fc00:0:4::1 fc00:0:5::d6 ] dev eth3 metric 1024 pref medium\n",
    "plain":  "2001:db8:b::2 from :: via fe80::a8c1:abff:fe01:1 dev eth2 src 2001:db8:a::1 metric 1024 pref medium\n",
}
PING = {
    "ok":          "5 packets transmitted, 5 received, 0% packet loss, time 4005ms\n",
    "busybox":     "5 packets transmitted, 5 packets received, 0% packet loss\n",
    "loss20":      "5 packets transmitted, 4 received, 20% packet loss, time 4005ms\n",
    "ping_errors": "5 packets transmitted, 0 received, +5 errors, 100% packet loss, time 4090ms\n",
    "short_ping":  "1 packets transmitted, 1 received, 0% packet loss, time 0ms\n",
    "no_stats":    "ping: connect: Network is unreachable\n",
}

def write_restoration(root, kind="ok", mode="srv6"):
    root = Path(root)
    if kind == "none":
        return
    (root / "restore.log").write_text("clock=monotonic\nschema_version=2\nt_before_ns=1\nt_after_ns=2\n")
    if mode == "srv6":
        (root / "route_restored.txt").write_text(ROUTE["srv6_B" if kind == "wrongpolicy" else "srv6_A"])
        (root / "underlay_restored.txt").write_text(
            "fc00:0:5::d6 from :: via fe80::1 dev " + ("eth3" if kind == "underlay_B" else "eth2") + " proto ospf metric 1024\n")
    else:
        (root / "route_restored.txt").write_text(ROUTE["plain"])
    ping = kind if kind in PING else "ok"
    (root / "ping_restored.txt").write_text(PING_HDR + PING[ping])
    if kind == "error_file":
        (root / "RESTORE_ERROR.txt").write_text("RESTORATION FAILED after 1 attempt(s)\n")
