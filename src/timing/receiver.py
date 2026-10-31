"""Buffer H2 userspace receive observations; write CSV only after capture ends."""
import array,csv,signal,socket,struct,sys,time
from pathlib import Path
from common import register,write_json

def main():
    port,dur,out=int(sys.argv[1]),float(sys.argv[2]),sys.argv[3]
    capacity=100_000
    seq=array.array('Q',[0])*capacity;tx=array.array('Q',[0])*capacity;rx=array.array('Q',[0])*capacity
    s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4*1024*1024)
    s.bind(('::',port));s.settimeout(.1)
    register(out);running=True
    def stop(*_):
        nonlocal running
        running=False
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    start=time.monotonic_ns();deadline=start+int(dur*1e9);n=ignored=0;overflow=False
    Path(out+'.ready').write_text('bound\n')
    try:
        while running and time.monotonic_ns()<deadline:
            try:data,_=s.recvfrom(65535)
            except socket.timeout:continue
            stamp=time.monotonic_ns()
            if len(data)<24 or data[:8]!=b'PS020M01':ignored+=1;continue
            if n==capacity:overflow=True;break
            _,q,sent=struct.unpack('!8sQQ',data[:24]);seq[n],tx[n],rx[n]=q,sent,stamp;n+=1
    finally:
        end=time.monotonic_ns()
        with open(out,'x',newline='') as f:
            w=csv.writer(f);w.writerow(['seq','t_send_mono_ns','t_recv_mono_ns'])
            w.writerows((seq[i],tx[i],rx[i]) for i in range(n))
        write_json(out+'.json',dict(clock='monotonic',start_ns=start,end_ns=end,received=n,
                   ignored=ignored,overflow=overflow,receive_buffer_bytes=s.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF),
                   stamp_meaning='H2 userspace recvfrom return, not NIC arrival'))
        s.close()
if __name__=='__main__':main()
