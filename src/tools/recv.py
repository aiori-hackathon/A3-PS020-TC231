"""Same-host UDP receiver; the CSV header explicitly declares monotonic stamps."""
import signal, socket, struct, sys, time

MAGIC = b'PS020M01'

def main():
    port, dur, out = int(sys.argv[1]), float(sys.argv[2]), sys.argv[3]
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.bind(('::', port)); s.settimeout(0.2)
    end = time.monotonic_ns() + int(dur*1e9)
    running = True
    def stop(*_):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with open(out, 'x') as f:
        f.write('seq,t_send_mono_ns,t_recv_mono_ns\n'); f.flush()
        with open(out+'.ready','x') as ready: ready.write('bound\n')
        while running and time.monotonic_ns() < end:
            try:
                data, _ = s.recvfrom(65535)
            except socket.timeout:
                continue
            stamp = time.monotonic_ns()
            if len(data)<24: continue
            magic, seq, sent = struct.unpack('!8sQQ', data[:24])
            if magic != MAGIC: continue
            f.write(f'{seq},{sent},{stamp}\n')
    s.close()

if __name__ == '__main__': main()
