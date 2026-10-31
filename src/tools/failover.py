"""Monotonic ICMP detector: positional CLI kept; default caller settings stay 8+3ms.
The earlier logs prove premature switching, not its precise cause. Neither clock
steps nor scheduler jitter can be diagnosed retrospectively from those summaries.
"""
import secrets, select, socket, struct, subprocess, sys, time

class GapDetector:
    def __init__(self, miss_ms, confirm_ms):
        self.miss_ns, self.confirm_ns = int(miss_ms*1e6), int(confirm_ms*1e6)
        self.last_rx = self.suspect_since = None
    def reply(self, now):
        self.last_rx, self.suspect_since = now, None
    def failure(self, now, armed):
        if not armed or self.last_rx is None: return False
        if now-self.last_rx <= self.miss_ns:
            self.suspect_since = None
        elif self.suspect_since is None:
            self.suspect_since = now
        elif now-self.suspect_since >= self.confirm_ns:
            return True
        return False

def install_backup(dst, segs, dev, runner=subprocess.run):
    # Any exception propagates: never mark an unsuccessful replacement as switched.
    runner(['ip','-6','route','replace',dst+'/128','encap','seg6','mode','encap',
            'segs',segs,'dev',dev],check=True,timeout=3)
    return time.monotonic_ns()

def main():
    dst,out,dur,miss_ms,segs,dev = sys.argv[1],sys.argv[2],float(sys.argv[3]),float(sys.argv[4]),sys.argv[5],sys.argv[6]
    confirm_ms = float(sys.argv[7]) if len(sys.argv)>7 else 3.0
    if min(dur,miss_ms)<=0 or confirm_ms<0: raise ValueError('invalid timing')
    ident, nonce = secrets.randbelow(65535)+1, secrets.token_bytes(16)
    s=socket.socket(socket.AF_INET6,socket.SOCK_RAW,socket.IPPROTO_ICMPV6)
    s.setblocking(False)
    detector=GapDetector(miss_ms,confirm_ms)
    start=time.monotonic_ns(); deadline=start+int(dur*1e9); nxt=start
    seq=received=0; pending={}; switched=False; armed=False
    detect=switch=first_ok=0; status='running'; error=''
    try:
        while time.monotonic_ns()<deadline:
            for _ in range(128):
                try: data,source=s.recvfrom(2048)
                except BlockingIOError: break
                if source[0]!=dst or len(data)!=40: continue
                typ,code,_,rid,wireseq,token,q,stamp=struct.unpack('!BBHHH16sQQ',data)
                if typ!=129 or code or rid!=ident or token!=nonce or wireseq!=(q&65535): continue
                if pending.pop(q,None)!=stamp: continue
                now=time.monotonic_ns()
                if now-stamp>100_000_000: continue  # stale replies cannot establish health
                detector.reply(now); received+=1
                if switched and not first_ok: first_ok=now
            now=time.monotonic_ns()
            if not armed and now-start>=500_000_000 and received>=20 and detector.last_rx is not None and now-detector.last_rx<=detector.miss_ns:
                armed=True
                with open(out+'.ready','x') as f: f.write('healthy probes\n')
            if not armed and now-start>=3_000_000_000:
                raise RuntimeError('primary probes did not establish initial health')
            if not switched and detector.failure(now,armed):
                detect=now
                switch=install_backup(dst,segs,dev)
                switched=True
                pending.clear()  # First OK must belong to a post-switch probe.
            if now>=nxt:
                stamp=time.monotonic_ns()
                packet=struct.pack('!BBHHH16sQQ',128,0,0,ident,seq&65535,nonce,seq,stamp)
                try:
                    s.sendto(packet,(dst,0)); pending[seq]=stamp
                except OSError:
                    pass
                seq+=1
                nxt=stamp+1_000_000  # no catch-up burst after a process pause
                pending={q:t for q,t in pending.items() if stamp-t<=100_000_000}
            select.select([s],[],[],0.0003)
        status='finished'
    except Exception as e:
        status='error'; error=type(e).__name__+': '+str(e)
        raise
    finally:
        with open(out,'x') as f:
            f.write(f'clock=monotonic\nschema_version=2\nstatus={status}\nstart_ns={start}\nend_ns={time.monotonic_ns()}\nt_detect_ns={detect}\nt_switched_ns={switch}\nt_first_ok_ns={first_ok}\nprobes_sent={seq}\nreplies_received={received}\nswitch_count={int(switched)}\nmiss_ms={miss_ms}\nconfirm_ms={confirm_ms}\n')
            if error: f.write('error='+error.replace('\n',' ')+'\n')
        s.close()

if __name__=='__main__': main()
