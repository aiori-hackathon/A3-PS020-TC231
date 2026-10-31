"""Full-duration no-cut control check. Never invents a cut timestamp."""
import os, sys
from pathlib import Path
from analyze import clock_domain, kv, load_recv, recv_clock
import restoration

def analyze_control(run):
    p,s,f = (kv(os.path.join(run,name)) for name in ('params.txt','send.txt','fail.txt'))
    if {clock_domain(x) for x in (p,s,f)} != {'monotonic'} or recv_clock(run+'/recv.csv')!='monotonic':
        raise ValueError('control requires monotonic logs throughout')
    rx=load_recv(run+'/recv.csv')
    lost=int(s['sent'])-len(rx)
    errors=[]
    if lost: errors.append(f'{lost} packets missing')
    if int(s['sent']) != int(float(p['rate'])*float(p['dur'])): errors.append('incomplete sender packet count')
    if int(s['send_errors']): errors.append('send errors')
    if f.get('status')!='finished': errors.append('detector error')
    if int(f.get('start_ns','0')) > int(s['start_ns']) or int(f.get('end_ns','0')) < int(s['end_ns']): errors.append('detector did not cover the complete sender interval')
    if any(received < tx for tx,received in rx.values()): errors.append('incomparable monotonic timestamps')
    if int(f['t_detect_ns']) or int(f['t_switched_ns']) or int(f['switch_count']): errors.append('false trigger in no-cut control')
    if 'fc00:0:2::1' not in Path(run+'/route_after.txt').read_text(): errors.append('primary policy changed')
    errors += ['RESTORATION FAILED: '+x for x in restoration.problems(run, 'srv6')]
    return errors,lost

if __name__=='__main__':
    errors,lost=analyze_control(sys.argv[1])
    print(('INVALID: '+ '; '.join(errors)) if errors else 'PASS: full-duration detector control, zero switches, zero loss')
    sys.exit(bool(errors))
