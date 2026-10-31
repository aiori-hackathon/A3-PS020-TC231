"""Same-host UDP sender. Packet timestamps and durations use CLOCK_MONOTONIC."""
import socket, struct, sys, time

MAGIC = b'PS020M01'

def main():
    dst, port, rate, dur, payload, out = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4]), int(sys.argv[5]), sys.argv[6]
    if rate <= 0 or dur <= 0 or payload < 24:
        raise ValueError('positive rate/duration and payload >=24 required')
    n = int(rate * dur)
    interval = int(1e9 / rate)
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    start, wall = time.monotonic_ns(), time.time_ns()
    maxlate = errors = 0
    for seq in range(n):
        target = start + seq * interval
        while True:
            remaining = target - time.monotonic_ns()
            if remaining <= 0:
                break
            if remaining > 2_000_000:
                time.sleep((remaining - 1_000_000) / 1e9)
        stamp = time.monotonic_ns()
        maxlate = max(maxlate, stamp-target)
        try:
            s.sendto(struct.pack('!8sQQ', MAGIC, seq, stamp) + b'x'*(payload-24), (dst, port))
        except OSError:
            errors += 1
    end = time.monotonic_ns()
    with open(out, 'x') as f:
        f.write(f'clock=monotonic\nschema_version=2\nsent={n}\nstart_ns={start}\nend_ns={end}\nwall_start_ns={wall}\nwall_end_ns={time.time_ns()}\nmax_late_us={maxlate//1000}\nsend_errors={errors}\n')
    s.close()

if __name__ == '__main__': main()
