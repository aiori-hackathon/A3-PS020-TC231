import select, socket, struct, subprocess, sys, time
dst, out, dur, miss_ms, segs, dev = sys.argv[1], sys.argv[2], float(sys.argv[3]), float(sys.argv[4]), sys.argv[5], sys.argv[6]
IDENT = 0x5156
s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
s.setblocking(False)
seq = 0
nxt = time.perf_counter()
last_rx = time.time_ns()
switched = False
t_detect = t_sw = t_ok = 0
deadline = time.time() + dur
try:
    while time.time() < deadline:
        if time.perf_counter() >= nxt:
            try:
                s.sendto(struct.pack('!BBHHH', 128, 0, 0, IDENT, seq & 0xffff), (dst, 0))
            except OSError:
                pass
            seq += 1
            nxt += 0.001
        select.select([s], [], [], 0.0003)
        for _ in range(64):
            try:
                data = s.recv(2048)
            except BlockingIOError:
                break
            if len(data) >= 6 and data[0] == 129 and struct.unpack('!H', data[4:6])[0] == IDENT:
                last_rx = time.time_ns()
                if switched and not t_ok:
                    t_ok = last_rx
        if not switched and seq > 500 and (time.time_ns() - last_rx) / 1e6 > miss_ms:
            t_detect = time.time_ns()
            subprocess.run(['ip', '-6', 'route', 'replace', dst + '/128', 'encap', 'seg6', 'mode', 'encap', 'segs', segs, 'dev', dev], check=True)
            t_sw = time.time_ns()
            switched = True
finally:
    with open(out, 'w') as f:
        f.write('t_detect_ns=%d\nt_switched_ns=%d\nt_first_ok_ns=%d\nprobes_sent=%d\n' % (t_detect, t_sw, t_ok, seq))
