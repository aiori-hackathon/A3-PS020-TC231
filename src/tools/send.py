import socket, struct, sys, time
dst, port, rate, dur, payload, out = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4]), int(sys.argv[5]), sys.argv[6]
n = int(rate * dur); iv = 1.0 / rate
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
pad = b'x' * (payload - 16)
t0 = time.perf_counter(); start_ns = time.time_ns(); maxlate = 0.0; errs = 0
for seq in range(n):
    tgt = t0 + seq * iv
    while True:
        d = tgt - time.perf_counter()
        if d <= 0: break
        if d > 0.002: time.sleep(d - 0.001)
    maxlate = max(maxlate, -d)
    try:
        s.sendto(struct.pack('!QQ', seq, time.time_ns()) + pad, (dst, port))
    except OSError:
        errs += 1
end_ns = time.time_ns()
open(out, 'w').write('sent=%d\nstart_ns=%d\nend_ns=%d\nmax_late_us=%d\nsend_errors=%d\n' % (n, start_ns, end_ns, int(maxlate * 1e6), errs))
