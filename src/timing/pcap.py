"""Read classic tcpdump pcaps. Correlate using inner UDP sequence + monotonic stamp,
not pcap wall-clock timestamps. Supports Ethernet and Linux cooked capture headers.
"""
import ipaddress,struct
from pathlib import Path

def decode_ipv6(data,offset=0):
    if len(data)<offset+40 or data[offset]>>4!=6:return None
    start=offset;next_header=data[offset+6];offset+=40;srh=None
    for _ in range(10):
        if next_header==43:
            if len(data)<offset+8:return None
            nxt,length,kind,left,last,flags,tag=struct.unpack_from('!BBBBBBH',data,offset)
            size=(length+1)*8
            if len(data)<offset+size or size<8+16*(last+1):return None
            if kind==4:
                srh=dict(sids_wire=[str(ipaddress.IPv6Address(data[offset+8+16*i:offset+24+16*i])) for i in range(last+1)],segments_left=left,srh_bytes=size,outer_ipv6_bytes=40,overhead_bytes=40+size)
            next_header=nxt;offset+=size
        elif next_header==41:
            inner=decode_ipv6(data,offset)
            if inner and srh:inner['srh']=srh
            return inner
        elif next_header==17:
            if len(data)<offset+32:return None
            payload=data[offset+8:]
            if payload[:8]!=b'PS020M01':return None
            seq,stamp=struct.unpack_from('!QQ',payload,8)
            return dict(seq=seq,send_ns=stamp,srh=srh)
        elif next_header in (0,60):
            if len(data)<offset+2:return None
            nxt,length=data[offset],data[offset+1];offset+=(length+1)*8;next_header=nxt
        else:return None
    return None

def read_packets(path):
    data=Path(path).read_bytes()
    if len(data)<24:raise ValueError('pcap header missing')
    magic=data[:4]
    if magic in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1'):endian='<'
    elif magic in (b'\xa1\xb2\xc3\xd4',b'\xa1\xb2\x3c\x4d'):endian='>'
    else:raise ValueError('unsupported pcap magic (classic pcap required)')
    dlt=struct.unpack_from(endian+'I',data,20)[0]
    if dlt not in (1,113,276):raise ValueError('unsupported pcap link type')
    pos=24;rows=[]
    while pos<len(data):
        if pos+16>len(data):raise ValueError('truncated pcap record header')
        sec,frac,size,wire=struct.unpack_from(endian+'IIII',data,pos);pos+=16
        if pos+size>len(data):raise ValueError('truncated pcap record')
        frame=data[pos:pos+size];pos+=size;offset={1:14,113:16,276:20}[dlt]
        if dlt==1:
            if len(frame)<14:continue
            typ=struct.unpack_from('!H',frame,12)[0]
            while typ in (0x8100,0x88a8) and len(frame)>=offset+4:
                typ=struct.unpack_from('!H',frame,offset+2)[0];offset+=4
            if typ!=0x86dd:continue
        row=decode_ipv6(frame,offset)
        if row:rows.append(row)
    return rows

def verify(root,main_send,received,cut,policy_end,restore_send,recovery_seq=None):
    root=Path(root)
    sid_a=['fc00:0:5::d6','fc00:0:2::1'];sid_b=['fc00:0:5::d6','fc00:0:4::1','fc00:0:3::1']
    files={name:read_packets(root/(name+'.pcap')) for name in ('r1_eth2','r1_eth3','r5_eth1','r3_eth2','r4_eth2','r5_eth3')}
    def count(name,sids,left,phase):
        def match(x):
            q=x['seq'];tx=x['send_ns'];srh=x['srh']
            if phase=='restored':good=q in restore_send and tx==restore_send[q]
            else:good=q in main_send and tx==main_send[q] and (tx<cut if phase=='primary' else tx>=policy_end)
            return good and srh is not None and srh['sids_wire']==sids and srh['segments_left']==left and srh['srh_bytes']==8+16*len(sids)
        rows=[x for x in files[name] if match(x)]
        return dict(samples=len(rows),overhead_bytes=sorted({x['srh']['overhead_bytes'] for x in rows}),sids_wire=sids,segments_left=left)
    checks=dict(primary_ingress=count('r1_eth2',sid_a,1,'primary'),primary_after_R2=count('r5_eth1',sid_a,0,'primary'),
                backup_ingress=count('r1_eth3',sid_b,2,'backup'),backup_after_R3=count('r3_eth2',sid_b,1,'backup'),
                backup_after_R4=count('r4_eth2',sid_b,0,'backup'),restored_ingress=count('r1_eth2',sid_a,1,'restored'),restored_after_R2=count('r5_eth1',sid_a,0,'restored'))
    checks['decapsulated_H2_link']=dict(samples=sum(x['srh'] is None and x['seq'] in received and x['seq'] in main_send and x['send_ns']==main_send[x['seq']] for x in files['r5_eth3']))
    checks['restored_H2_link']=dict(samples=sum(x['srh'] is None and x['seq'] in restore_send and x['send_ns']==restore_send[x['seq']] for x in files['r5_eth3']))
    if recovery_seq is not None:
        q=recovery_seq;stamp=main_send[q]
        hits={name:any(x['seq']==q and x['send_ns']==stamp for x in files[name]) for name in ('r1_eth3','r3_eth2','r4_eth2','r5_eth3')}
        checks['timeline_endpoint_on_backup']=dict(samples=int(all(hits.values())),sequence=q,interfaces=hits)
    return dict(verified=all(x['samples']>0 for x in checks.values()),checks=checks,
                timestamp_method='inner monotonic packet stamps; pcap epoch timestamps not used for recovery')

def verify_baseline(root,main_send,received,cut,restore_send):
    root=Path(root);checks={}
    for name,phase in [('r1_eth2','primary'),('r5_eth1','primary'),('r1_eth3','backup'),('r3_eth2','backup'),('r4_eth2','backup'),('r5_eth3','delivery'),('r1_eth2','restored'),('r5_eth1','restored'),('r5_eth3','restored')]:
        samples=0
        for x in read_packets(root/(name+'.pcap')):
            q=x['seq'];stamp=x['send_ns']
            if phase=='restored':match=q in restore_send and stamp==restore_send[q]
            else:match=q in main_send and stamp==main_send[q] and (stamp<cut if phase=='primary' else stamp>=cut if phase=='backup' else q in received)
            if match and x['srh'] is None:samples+=1
        checks[name+'_'+phase]=dict(samples=samples,srv6_header=False)
    return dict(verified=all(x['samples']>0 for x in checks.values()),checks=checks,
                timestamp_method='inner monotonic packet stamps; pcap epoch timestamps not used')

def recovery_policy(root,seq,stamp):
    root=Path(root);seen={}
    for name in ('r1_eth2','r1_eth3','r3_eth2','r4_eth2','r5_eth3'):
        rows=[x for x in read_packets(root/(name+'.pcap')) if x['seq']==seq and x['send_ns']==stamp]
        seen[name]=rows
    a=any(x['srh'] and x['srh']['sids_wire']==['fc00:0:5::d6','fc00:0:2::1'] for x in seen['r1_eth2'])
    b=any(x['srh'] and x['srh']['sids_wire']==['fc00:0:5::d6','fc00:0:4::1','fc00:0:3::1'] for x in seen['r1_eth3'])
    all_hops=b and all(seen[name] for name in ('r3_eth2','r4_eth2','r5_eth3'))
    return dict(all_backup_hops_seen=all_hops,ingress_policy='B' if b and not a else 'A' if a and not b else 'ambiguous' if a and b else 'unobserved',
                sequence=seq,seen_interfaces=[name for name,rows in seen.items() if rows],
                limitation='an A packet may be rerouted by the OSPF underlay; it does not prove ingress backup switching caused recovery')
