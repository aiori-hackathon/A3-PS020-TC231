"""Direct rtnetlink link operation; ACK bracket excludes spawning the ip executable.
The actual kernel transition is bounded by before_ns..after_ns, not known at their midpoint.
Constants/structures are the Linux UAPI: rtnetlink.h, if_link.h and netlink.h.
"""
import errno,json,os,socket,struct,sys,time
from pathlib import Path
from common import register,write_json

NLMSG_ERROR=2; RTM_NEWLINK=16; NLM_F_REQUEST=1; NLM_F_ACK=4; IFF_UP=1

def message(index,up,seq):
    payload=struct.pack('=BBHiII',socket.AF_UNSPEC,0,0,index,IFF_UP if up else 0,IFF_UP)
    return struct.pack('=IHHII',16+len(payload),RTM_NEWLINK,NLM_F_REQUEST|NLM_F_ACK,seq,0)+payload

def acknowledge(data,seq):
    pos=0
    while pos+16<=len(data):
        length,kind,flags,sq,pid=struct.unpack_from('=IHHII',data,pos)
        if length<16 or pos+length>len(data): raise ValueError('truncated netlink reply')
        if sq==seq and kind==NLMSG_ERROR:
            if length<36: raise ValueError('truncated netlink ACK')
            error=struct.unpack_from('=i',data,pos+16)[0]
            if error: raise OSError(-error,os.strerror(-error))
            return True
        pos+=(length+3)&~3
    return False

def change(interface,up,sock=None,now=time.monotonic_ns,index=None):
    index=socket.if_nametoindex(interface) if index is None else index
    own=sock is None
    if own:
        sock=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,socket.NETLINK_ROUTE)
        sock.bind((0,0));sock.settimeout(3)
    seq=1;request=message(index,up,seq)
    try:
        before=now()
        sock.sendto(request,(0,0))
        submitted=now()
        while True:
            data,source=sock.recvfrom(65535)
            if source[0]!=0:continue
            if acknowledge(data,seq):break
        after=now()
        return dict(clock='monotonic',operation='up' if up else 'down',interface=interface,
                    before_ns=before,submitted_ns=submitted,after_ns=after,
                    uncertainty_ns=after-before,status='acknowledged')
    finally:
        if own:sock.close()

def main():
    interface,action,out=sys.argv[1:4]
    if action not in ('up','down'):raise ValueError('action must be up or down')
    register(out)
    at=int(sys.argv[4]) if len(sys.argv)>4 else 0
    try:
        # Prepare the socket/index before the scheduled cut. Only send/ACK are bracketed.
        index=socket.if_nametoindex(interface)
        with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,socket.NETLINK_ROUTE) as sock:
            sock.bind((0,0));sock.settimeout(3)
            Path(out+'.ready').write_text('started\n')
            while at and time.monotonic_ns()<at:
                remaining=at-time.monotonic_ns()
                if remaining>200_000:time.sleep((remaining-100_000)/1e9)
            flags_before=int(Path('/sys/class/net',interface,'flags').read_text().strip(),16)
            if action=='down' and not flags_before & IFF_UP:
                raise RuntimeError('cut rejected: interface was already down')
            result=change(interface,action=='up',sock=sock,index=index)
            flags_after=int(Path('/sys/class/net',interface,'flags').read_text().strip(),16)
            result.update(flags_before=flags_before,flags_after=flags_after)
            if bool(flags_after & IFF_UP)!=(action=='up'):
                result.update(status='state_mismatch',error='interface state does not match acknowledged request')
        result['requested_at_ns']=at
        result['scheduled_cut_lateness_ns']=result['before_ns']-at if at else None
        write_json(out,result)
        if result['status']!='acknowledged':raise SystemExit(1)
    except Exception as e:
        write_json(out,dict(status='error',error=str(e),clock='monotonic',observed_ns=time.monotonic_ns()))
        raise
if __name__=='__main__':main()
