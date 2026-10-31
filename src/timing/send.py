"""Same-host UDP sender; timestamps are userspace pre-send stamps, not wire timestamps."""
import array, csv, gc, json, os, socket, struct, sys, time, resource
from common import register, write_json
from pathlib import Path

MAGIC = b'PS020M01'

def run_sender(sock, dst, port, rate, dur, payload, clock=None, sleep=None, ready=None):
    clock = clock or time.monotonic_ns
    sleep = sleep or time.sleep
    if rate <= 0 or rate > 1_000_000_000 or dur <= 0 or payload < 24:
        raise ValueError('positive supported rate/duration and payload >=24 required')
    n = int(rate * dur)
    if n < 2: raise ValueError('at least two packets required')
    interval = int(1e9 / rate)
    scheduled = array.array('q', [0]) * n
    actual = array.array('q', [0]) * n
    ok = bytearray(n)
    completed = array.array('q',[0]) * n
    packet = bytearray(b'x' * payload)
    pack = struct.Struct('!8sQQ').pack_into
    destination = (dst, port)
    diag_wall = array.array('q', [0]) * n
    diag_cpu = array.array('q', [0]) * n
    diag_vol = array.array('q', [0]) * n
    diag_invol = array.array('q', [0]) * n
    # Allocate storage before the timed interval. No growing journal or cyclic GC in the loop.
    gc_enabled = gc.isenabled()
    start = clock() + (300_000_000 if ready else 0)
    if ready: ready(start)
    target = start
    maxlate = errors = 0
    guard = min(200_000, interval // 2)
    # Wall deltas exactly match successive actual_ns stamps. CPU/rusage reads
    # follow those stamps and are sequential, not simultaneous observations.
    # Row zero has no previous packet and is excluded from gap diagnosis.
    diag_point_wall = start
    diag_point_cpu = time.thread_time_ns()
    _ru0 = resource.getrusage(resource.RUSAGE_THREAD)
    diag_point_vol, diag_point_invol = _ru0.ru_nvcsw, _ru0.ru_nivcsw
    try:
        gc.disable()
        for seq in range(n):
            while True:
                remaining = target - clock()
                if remaining <= 0: break
                if remaining > guard:
                    sleep((remaining - guard) / 1e9)
            stamp = clock()
            cpu_now = time.thread_time_ns()
            usage_now = resource.getrusage(resource.RUSAGE_THREAD)
            diag_wall[seq] = stamp - diag_point_wall if seq else 0
            diag_cpu[seq] = cpu_now - diag_point_cpu if seq else 0
            diag_vol[seq] = usage_now.ru_nvcsw - diag_point_vol if seq else 0
            diag_invol[seq] = usage_now.ru_nivcsw - diag_point_invol if seq else 0
            diag_point_wall, diag_point_cpu = stamp, cpu_now
            diag_point_vol, diag_point_invol = usage_now.ru_nvcsw, usage_now.ru_nivcsw
            scheduled[seq], actual[seq] = target, stamp
            maxlate = max(maxlate, stamp - target)
            pack(packet, 0, MAGIC, seq, stamp)
            try:
                sock.sendto(packet, destination)
                ok[seq] = 1
            except OSError:
                errors += 1
            completed[seq] = clock()
            # Retain bounded cadence: bounded catch-up, reanchor after a missed slot.
            target = max(target + interval, stamp + interval // 2)
            if stamp - scheduled[seq] >= interval:
                target = stamp + interval
        end = clock()
    finally:
        if gc_enabled: gc.enable()
    return dict(n=n, start=start, end=end, scheduled=scheduled, actual=actual,
                ok=ok, completed=completed, maxlate=maxlate, errors=errors,
                diag_wall=diag_wall, diag_cpu=diag_cpu,
                diag_vol=diag_vol, diag_invol=diag_invol)

def configure():
    cpu=os.environ.get('TIMING_CPU')
    if cpu is not None: os.sched_setaffinity(0,{int(cpu)})
    if os.environ.get('TIMING_REALTIME')=='1':
        os.sched_setscheduler(0,os.SCHED_FIFO,os.sched_param(10))
    def probe(f):
        try: return f()
        except OSError as e: return 'unavailable: errno %d' % e.errno
    return dict(policy=probe(lambda: os.sched_getscheduler(0)),
                priority=probe(lambda: os.sched_getparam(0).sched_priority),
                affinity=probe(lambda: sorted(os.sched_getaffinity(0))))

def main():
    original_policy=original_priority=None
    if os.environ.get('TIMING_REALTIME')=='1':
        original_policy=os.sched_getscheduler(0)
        original_priority=os.sched_getparam(0)
    scheduling=configure()
    if sys.argv[1:] == ['--check']:
        print(json.dumps(scheduling));return
    dst, port, rate, dur, payload, out = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4]), int(sys.argv[5]), sys.argv[6]
    register(out)
    wall = time.time_ns()
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            res = run_sender(sock, dst, port, rate, dur, payload,ready=lambda start: write_json(out+'.ready',dict(start_ns=start,scheduling=scheduling)))
    finally:
        # Never format/write the journal at FIFO priority and starve the remaining detector run.
        if os.environ.get('TIMING_REALTIME')=='1':os.sched_setscheduler(0,original_policy,original_priority)
    wall_end = time.time_ns()
    write_json(str(Path(out).with_name('send_gap_diagnostic.schema.json')), dict(
        schema_version=1, measurement='inter_send_gap', first_row_valid=False,
        wall_boundary='actual_ns[seq] - actual_ns[seq-1]',
        counter_boundary='successive sequential CPU/rusage reads after actual_ns',
        limitation='CPU/counter boundaries are approximate; zero switches do not prove a VM pause',
        instrumentation='one thread_time_ns and one RUSAGE_THREAD sample per packet'))
    with open(str(Path(out).with_name('send_gap_diagnostic.csv')), 'x', newline='') as f:
        w = csv.writer(f)
        w.writerow(['seq','elapsed_ns','cpu_ns','voluntary_switches','involuntary_switches'])
        w.writerows((q,res['diag_wall'][q],res['diag_cpu'][q],
                     res['diag_vol'][q],res['diag_invol'][q])
                    for q in range(res['n']))
    write_json(out+'.scheduling.json',scheduling)
    with open(str(Path(out).with_name('send_packets.csv')), 'x', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['seq','scheduled_ns','actual_ns','ok','submit_done_ns'])
        writer.writerows((q,res['scheduled'][q],res['actual'][q],res['ok'][q],res['completed'][q]) for q in range(res['n']))
    with open(out, 'x') as f:
        f.write(f"clock=monotonic\nschema_version=3\nsender_revision=timed_v3\nsent={res['n']}\nstart_ns={res['start']}\nend_ns={res['end']}\nwall_start_ns={wall}\nwall_end_ns={wall_end}\nmax_late_us={res['maxlate']//1000}\nsend_errors={res['errors']}\n")

if __name__ == '__main__': main()
