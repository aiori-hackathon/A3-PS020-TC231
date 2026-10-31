"""Optional full-packet capture; PID-managed and stopped cleanly after restoration proof."""
import os,signal,subprocess,sys,time
from pathlib import Path
from common import register

def main():
    interface,out=sys.argv[1:3];register(out);running=True
    def stop(*_):
        nonlocal running
        running=False
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    with open(out+'.stderr','x') as err:
        p=subprocess.Popen(['tcpdump','-n','-i',interface,'-s','0','-B','4096','-w',out,'ip6'],stderr=err,stdout=subprocess.DEVNULL,env={**os.environ,'LC_ALL':'C'})
        try:
            deadline=time.monotonic()+5
            while running and time.monotonic()<deadline:
                if p.poll() is not None:raise RuntimeError('tcpdump exited before readiness')
                if 'listening on' in Path(out+'.stderr').read_text():break
                time.sleep(.02)
            else:raise RuntimeError('tcpdump readiness timeout')
            Path(out+'.ready').write_text('listening\n')
            while running:
                if p.poll() is not None:raise RuntimeError('tcpdump exited during experiment')
                time.sleep(.1)
        finally:
            if p.poll() is None:p.send_signal(signal.SIGINT)
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill();p.wait(timeout=2)
                raise RuntimeError('tcpdump failed to flush/stop cleanly; capture cannot certify this run')
if __name__=='__main__':main()
