import socket, struct, sys, time
port, dur, out = int(sys.argv[1]), float(sys.argv[2]), sys.argv[3]
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(('::', port)); s.settimeout(0.5)
rows = []; end = time.time() + dur
while time.time() < end:
    try:
        data, _ = s.recvfrom(2048)
    except socket.timeout:
        continue
    tr = time.time_ns()
    seq, ts = struct.unpack('!QQ', data[:16])
    rows.append((seq, ts, tr))
with open(out, 'w') as f:
    f.write('seq,t_send_ns,t_recv_ns\n')
    for r in rows: f.write('%d,%d,%d\n' % r)
