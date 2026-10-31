"""Auditable userspace timeline. No timestamp here claims a kernel or wire arrival."""
import csv,json,math,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import restoration, pcap as packet_capture

def read_json(path):return json.loads(Path(path).read_text())
def read_kv(path):
    return dict(line.strip().split('=',1) for line in Path(path).read_text().splitlines() if '=' in line)
def csv_rows(path):
    with open(path,newline='') as f:return list(csv.DictReader(f))
def duration(a,b):return (b-a)/1e6

def detection_parts(cut,det):
    t=det['trigger'];d=det['detect_ns']
    stages=[('last_reply_relative_to_cut',t['last_reply_ns']-cut),
            ('configured_miss_wait',t['miss_due_ns']-t['last_reply_ns']),
            ('miss_polling_overshoot',t['suspect_ns']-t['miss_due_ns']),
            ('configured_confirmation_wait',t['confirm_due_ns']-t['suspect_ns']),
            ('confirmation_polling_overshoot',d-t['confirm_due_ns'])]
    if any(value<0 for _,value in stages[1:]):raise ValueError('invalid detector event ordering')
    assert sum(value for _,value in stages)==d-cut
    return dict(stages_ns=dict(stages),total_ns=d-cut,
                signed_term='last_reply_relative_to_cut may be negative; it is an offset, not a negative delay')

def delivery_parts(cut,det,send,received):
    d=det['detect_ns'];cb=det['policy_command']['before_ns'];ce=det['policy_command']['after_ns']
    # Require this specific datagram's send stamp to follow successful policy command completion.
    eligible=[q for q in received if q in send and send[q]['actual_ns']>=ce]
    if not eligible:raise ValueError('no UDP delivery sent after policy command completion')
    q=min(eligible,key=lambda q:received[q]);tx=send[q]['actual_ns'];rx=received[q]
    stages=[('observed_detection',d-cut),('controller_dispatch',cb-d),
            ('ip_command_wall_time',ce-cb),('wait_for_this_delivered_datagram',tx-ce),
            ('send_stamp_to_H2_userspace_read',rx-tx)]
    if any(value<0 for _,value in stages):raise ValueError('delivery events out of order')
    assert sum(value for _,value in stages)==rx-cut
    return dict(sequence=q,send_ns=tx,receive_ns=rx,stages_ns=dict(stages),total_ns=rx-cut,
                limitation='last stage includes send syscall, network, receive queue and receiver scheduling; those cannot be isolated from these observations')

def recovery_parts(cut,det,send,sequence,rx):
    """Partition the actual recovery interval, clipping command phases if they overlap delivery."""
    d=det['detect_ns'];cb=det['policy_command']['before_ns'];ce=det['policy_command']['after_ns']
    if not cut<=d<=cb<=ce or rx<cut:raise ValueError('cannot order recovery/controller timeline')
    tx=send[sequence]['actual_ns']
    if tx>=ce:
        stages=[('observed_detection',d-cut),('controller_dispatch',cb-d),
                ('ip_command_wall_time',ce-cb),('wait_until_recovery_packet_send',tx-ce),
                ('send_stamp_to_H2_userspace_read',rx-tx)]
        overlap=False
    else:
        points=[cut,min(d,rx),min(cb,rx),min(ce,rx),rx]
        names=['elapsed_before_detection_or_recovery','dispatch_before_recovery',
               'ip_command_overlap_before_recovery','remaining_after_command_return_to_receive']
        stages=list(zip(names,[b-a for a,b in zip(points,points[1:])]))
        overlap=True
    if any(v<0 for _,v in stages):raise ValueError('negative recovery component')
    assert sum(v for _,v in stages)==rx-cut
    return dict(sequence=sequence,send_ns=tx,receive_ns=rx,total_ns=rx-cut,stages_ns=dict(stages),
                command_and_packet_overlap=overlap,
                limitation='temporal accounting, not isolation of network versus host scheduling; route may activate before ip returns; path attribution requires packet evidence')

def analyze(directory):
    root=Path(directory)
    errors=[];quality=[];result=dict(schema='ps020-timed-v3-1',run=root.name,mode='unknown',
        functional_pass=False,performance_pass=False,errors=errors,quality_reasons=quality,
        endpoint='H2 userspace UDP receive; not wire arrival')
    try:
        params=read_json(root/'params.json');lifecycle=read_json(root/'lifecycle.json')
        result['mode']=params['mode']
    except (OSError,ValueError,KeyError) as e:
        errors.append('missing trial metadata: '+str(e));return result
    if lifecycle.get('aborted'):errors.append('trial aborted; no performance statistics')
    errors.extend(lifecycle.get('errors',[]))
    if not lifecycle.get('restoration_verified'):errors.append('restoration not verified')
    if not lifecycle.get('udp_restoration_verified'):errors.append('fresh restored-path UDP delivery not verified')
    try:
        if params.get('schema')!='ps020-timed-v3-1':raise ValueError('unsupported measurement schema')
        mode='baseline' if params['mode']=='baseline' else 'srv6'
        errors.extend('restoration: '+x for x in restoration.problems(root,mode,True))
        meta=read_kv(root/'send.txt');sj=csv_rows(root/'send_packets.csv');rr=csv_rows(root/'recv.csv')
        sent={int(x['seq']):{k:int(v) for k,v in x.items()} for x in sj}
        if meta.get('clock')!='monotonic':raise ValueError('sender clock is not monotonic')
        n=int(meta['sent']);expected=int(params['rate']*params['duration'])
        if len(sj)!=n or set(sent)!=set(range(n)) or n!=expected:raise ValueError('incomplete or duplicate send journal')
        ordered=[sent[q] for q in range(n)];stamps=[p['actual_ns'] for p in ordered]
        if any(b<a for a,b in zip(stamps,stamps[1:])):raise ValueError('send times not monotonic')
        if any(p['actual_ns']<p['scheduled_ns'] or p['submit_done_ns']<p['actual_ns'] for p in ordered):raise ValueError('invalid sender event ordering')
        if int(meta['send_errors']) or any(p['ok']!=1 for p in ordered):errors.append('UDP send errors')
        received={};duplicates=0
        for r in rr:
            q,tx,rx=int(r['seq']),int(r['t_send_mono_ns']),int(r['t_recv_mono_ns'])
            if q not in sent or tx!=sent[q]['actual_ns'] or rx<tx:raise ValueError('receiver/send journal mismatch or incomparable clocks')
            if q in received:duplicates+=1
            received[q]=min(received.get(q,rx),rx)
        if not received:raise ValueError('no UDP deliveries')
        restored_tx_rows=csv_rows(root/'restored/send_packets.csv');restored_rx_rows=csv_rows(root/'restored/recv.csv')
        restored_tx={int(x['seq']):int(x['actual_ns']) for x in restored_tx_rows}
        restored_rx={int(x['seq']):int(x['t_send_mono_ns']) for x in restored_rx_rows}
        if len(restored_tx_rows)!=100 or len(restored_rx_rows)!=100 or set(restored_tx)!=set(range(100)) or restored_rx!=restored_tx:
            errors.append('restored-path UDP raw logs do not prove all 100 packets')
        if not restored_tx or min(restored_tx.values())<=int(meta['end_ns']):errors.append('restoration UDP evidence is not fresh')
        if any(int(x['ok'])!=1 for x in restored_tx_rows) or any(int(x['t_recv_mono_ns'])<int(x['t_send_mono_ns']) for x in restored_rx_rows):errors.append('invalid restoration UDP send/receive observation')
        receiver_meta=read_json(root/'recv.csv.json')
        if receiver_meta.get('clock')!='monotonic':errors.append('receiver clock is not monotonic')
        if receiver_meta['overflow']:errors.append('receiver observation buffer overflow')
        if receiver_meta['start_ns']>stamps[0] or receiver_meta['end_ns']<int(meta['end_ns']):errors.append('receiver did not cover sender interval')
        result.update(sent=n,received_unique=len(received),lost_total=n-len(received),duplicates=duplicates,
                      achieved_rate_pps=(n-1)*1e9/(stamps[-1]-stamps[0]),
                      max_sender_lateness_ms=max((p['actual_ns']-p['scheduled_ns'])/1e6 for p in ordered))
        if not .98*params['rate']<=result['achieved_rate_pps']<=1.02*params['rate']:quality.append('whole-run achieved rate differs by more than 2%')
        det=read_json(root/'fail.txt.json') if params['mode']!='baseline' else None
        if det and (det['status']!='finished' or det['start_ns']>int(meta['start_ns']) or det['end_ns']<int(meta['end_ns'])):
            errors.append('detector did not cover sender interval cleanly')
        if params['mode']=='control':
            if result['lost_total']:errors.append('loss in no-cut control')
            if det['switch_count'] or det['detect_ns']:errors.append('false trigger in no-cut control')
            if not restoration._has_addr((root/'route_after.txt').read_text(),'fc00:0:2::1'):errors.append('control primary policy changed')
            lo,hi=stamps[0],stamps[-1]
        else:
            cut=read_json(root/'cut.json')
            if cut['status']!='acknowledged':raise ValueError('link-down operation not acknowledged')
            before,after=cut['before_ns'],cut['after_ns'];lo,hi=before-100_000_000,before+500_000_000
            if stamps[0]>lo or stamps[-1]<hi:raise ValueError('traffic does not cover cut quality window')
            if not before<=cut['submitted_ns']<=after or cut['uncertainty_ns']!=after-before:
                raise ValueError('inconsistent link transition bracket')
            result['cut']=cut
            all_missing=[q for q in range(n) if q not in received]
            all_bursts=[]
            for q in all_missing:
                if all_bursts and q==all_bursts[-1][-1]+1:all_bursts[-1].append(q)
                else:all_bursts.append([q])
            bursts=[b for b in all_bursts if sent[b[0]]['actual_ns']<=hi and sent[b[-1]]['actual_ns']>=before]
            result['lost_at_cut']=sum(len(b) for b in bursts)
            result['loss_burst_selection']='full sequence bursts overlapping cut start through cut+500ms; not causal attribution'
            if len(bursts)!=len(all_bursts):quality.append('additional packet loss outside cut-overlapping bursts')
            recovery=[];unrecovered=False
            for b in bursts:
                later=[q for q in received if q>b[-1]]
                if not later:unrecovered=True;continue
                q=min(later,key=lambda q:received[q]);recovery.append((received[q],q))
            if unrecovered:errors.append('UDP loss burst has no observed recovery')
            if recovery and not unrecovered:
                rx,q=max(recovery)
                result['post_loss_udp_recovery']=dict(sequence=q,receive_ns=rx,
                      from_cut_start_ms=duration(before,rx),from_cut_end_ms=duration(after,rx))
            else:result['post_loss_udp_recovery']=None
            arrivals=sorted(received.values())
            result['max_receiver_gap_near_cut_ms']=max((duration(a,b) for a,b in zip(arrivals,arrivals[1:]) if a<=hi and b>=lo),default=0)
            if det:
                if det['status']!='finished' or det['switch_count']!=1:errors.append('detector did not finish with one successful switch')
                if det['detect_ns']<before:errors.append('false trigger before cut')
                if det['detect_ns']<after:quality.append('detection overlaps cut transition uncertainty')
                if not det['first_probe_ok_ns'] or det['first_probe_ok_ns']<det['policy_ack_observed_ns']:errors.append('no post-switch probe recovery')
                result['detection_delay_bounds_ms']=[duration(after,det['detect_ns']),duration(before,det['detect_ns'])]
                if not det['trigger']:errors.append('detector trigger breakdown missing')
                if det['policy_command'].get('after_ns')!=det['policy_ack_observed_ns']:errors.append('policy completion timestamps disagree')
                if det['trigger']:
                    result['detection_breakdown']=detection_parts(before,det)
                    result['post_policy_delivery_breakdown']=delivery_parts(before,det,sent,received)
                    if result.get('post_loss_udp_recovery'):
                        endpoint=result['post_loss_udp_recovery']
                        result['recovery_breakdown']=recovery_parts(before,det,sent,endpoint['sequence'],endpoint['receive_ns'])
                before_route=(root/'route_before.txt').read_text();after_route=(root/'route_after.txt').read_text()
                if not restoration._has_addr(before_route,'fc00:0:2::1') or not restoration._has_addr(after_route,'fc00:0:3::1'):errors.append('expected A to B ingress policy transition missing')
            else:
                if 'encap' in (root/'route_before.txt').read_text():errors.append('baseline still has SRv6 encapsulation')
                after_route=(root/'route_after.txt').read_text()
                if 'encap' in after_route or 'dev eth3' not in after_route:errors.append('ordinary IPv6 backup route not verified')
            # Pure network outage is not inferred from missing sequence count.
            result['loss_count_times_nominal_interval_is_outage']=False
        near=[p for p in ordered if lo<=p['actual_ns']<=hi]
        gaps=[(b-a)/1e6 for a,b in zip(stamps,stamps[1:]) if a<=hi and b>=lo]
        late=max((p['actual_ns']-p['scheduled_ns'])/1e6 for p in near)
        gap=max(gaps,default=0)
        result.update(pacing_window='whole stream' if params['mode']=='control' else 'cut-100ms to cut+500ms',
                      near_cut_max_send_gap_ms=gap,near_cut_max_lateness_ms=late,
                      near_cut_max_send_call_ms=max((p['submit_done_ns']-p['actual_ns'])/1e6 for p in near))
        # Same unchanged 2 ms gap criterion. Control reports it but is a functional gate, not v5's stall-count rule.
        if gap>2:quality.append('send-attempt gap exceeds 2ms in audited window')
        if late>2:quality.append('send lateness exceeds 2ms in audited window')
    except (OSError,ValueError,KeyError,ZeroDivisionError,AssertionError) as e:
        errors.append('measurement unavailable: '+str(e))
    if params.get('capture') and not errors and params['mode'] in ('srv6','baseline'):
        try:
            main_send={q:p['actual_ns'] for q,p in sent.items()}
            if params['mode']=='srv6':
                result['packet_path_evidence']=packet_capture.verify(root,main_send,received,cut['before_ns'],det['policy_command']['after_ns'],restored_tx,result['post_policy_delivery_breakdown']['sequence'])
                if result.get('post_loss_udp_recovery'):
                    q=result['post_loss_udp_recovery']['sequence']
                    result['actual_recovery_packet_path']=packet_capture.recovery_policy(root,q,main_send[q])
                    if result['actual_recovery_packet_path']['ingress_policy']!='B' or not result['actual_recovery_packet_path']['all_backup_hops_seen']:quality.append('actual UDP recovery packet not proven across backup policy B path')
            else:result['packet_path_evidence']=packet_capture.verify_baseline(root,main_send,received,cut['before_ns'],restored_tx)
            if not result['packet_path_evidence']['verified']:errors.append('capture does not prove required path/SID traversal stages')
        except (OSError,ValueError,KeyError) as e:errors.append('capture verification failed: '+str(e))
    result['functional_pass']=not errors
    result['performance_pass']=not errors and not quality
    result['path_attribution_verified']=bool(result.get('packet_path_evidence',{}).get('verified'))
    return result

def render(r):
    lines=[f"{r['run']}: functional={'PASS' if r['functional_pass'] else 'FAIL'}; measurement={'ACCEPTED' if r['performance_pass'] else 'NOT ACCEPTED'}"]
    lines.extend('ERROR: '+x for x in r['errors']);lines.extend('QUALITY: '+x for x in r['quality_reasons'])
    for key in ('sent','received_unique','lost_total','lost_at_cut','duplicates','achieved_rate_pps','near_cut_max_send_gap_ms','near_cut_max_send_call_ms','max_receiver_gap_near_cut_ms'):
        if key in r:lines.append(f'{key}: {r[key]}')
    if 'cut' in r:lines.append(f"cut transition uncertainty: {r['cut']['uncertainty_ns']/1e6:.6f} ms (ACK bracket, no midpoint assumption)")
    if r.get('post_loss_udp_recovery'):lines.append('post-loss UDP recovery relative to physical-cut bounds: '+str([r['post_loss_udp_recovery']['from_cut_end_ms'],r['post_loss_udp_recovery']['from_cut_start_ms']])+' ms')
    for name in ('detection_breakdown','recovery_breakdown','post_policy_delivery_breakdown'):
        if name not in r:continue
        part=r[name];lines.append(name+':')
        for stage,value in part['stages_ns'].items():lines.append(f'  {stage}: {value/1e6:.6f} ms')
        lines.append(f"  exact sum: {part['total_ns']/1e6:.6f} ms")
        if 'limitation' in part:lines.append('  '+part['limitation'])
    if 'actual_recovery_packet_path' in r:lines.append('Actual UDP recovery packet ingress policy: '+r['actual_recovery_packet_path']['ingress_policy'])
    if 'packet_path_evidence' not in r:lines.append('SID/path attribution not verified in this run; use --capture on the failure pilot.')
    if 'packet_path_evidence' in r:lines.append('SRH/packet path verification: '+('PASS' if r['packet_path_evidence']['verified'] else 'FAIL'))
    return '\n'.join(lines)+'\n'

def write_events(path,r):
    events=[]
    cut=r.get('cut')
    if cut:
        anchor=cut['before_ns']
        events.extend([('cut_request_start',anchor),('cut_ack_observed',cut['after_ns'])])
        if 'post_policy_delivery_breakdown' in r:
            p=r['post_policy_delivery_breakdown'];cursor=anchor
            labels=('failure_detected','policy_command_start','policy_command_done','endpoint_packet_send_stamp','endpoint_H2_userspace_receive')
            for label,value in zip(labels,p['stages_ns'].values()):
                cursor+=value;events.append((label,cursor))
    else:anchor=0
    with open(path,'w',newline='') as f:
        writer=csv.writer(f);writer.writerow(['event','monotonic_ns','relative_to_cut_request_ms'])
        for name,stamp in sorted(events,key=lambda e:e[1]):writer.writerow([name,stamp,(stamp-anchor)/1e6])

if __name__=='__main__':
    result=analyze(sys.argv[1]);print(render(result),end='')
    sys.exit(0 if result['performance_pass'] else 1)
