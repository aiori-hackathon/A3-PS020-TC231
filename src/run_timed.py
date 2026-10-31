#!/usr/bin/env python3
"""Auditable v3 experiment entry point. Existing Docker/containerlab topology required."""
import argparse,csv,fcntl,hashlib,json,os,secrets,signal,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent/'timing'))
import report as timeline
import pcap as packet_capture
import restoration

SRC=Path(__file__).resolve().parent
NODES={n:'clab-srv6-'+n for n in ('h1','h2','r1','r2','r3','r4','r5')}
DST='2001:db8:b::2'
CAPS=(('r1','eth2'),('r1','eth3'),('r5','eth1'),('r3','eth2'),('r4','eth2'),('r5','eth3'))

def docker(*args,check=True,timeout=15):
    p=subprocess.run(['docker',*map(str,args)],capture_output=True,text=True,check=False,timeout=timeout)
    if check and p.returncode:raise RuntimeError('Docker command failed: '+p.stderr.strip()+' '+p.stdout.strip())
    return p
def save(path,obj):Path(path).write_text(json.dumps(obj,indent=2)+'\n')
def helper_digest():
    h=hashlib.sha256()
    for p in sorted((SRC/'timing').glob('*.py')):h.update(p.name.encode());h.update(p.read_bytes())
    for name in ('run_timed.py','restoration.py','srv6_policy.sh','setup_srv6.sh'):
        if (SRC/name).exists():h.update(name.encode());h.update((SRC/name).read_bytes())
    return h.hexdigest()
def clocks_compatible(identities):
    if len({v['boot_id'] for v in identities.values()})!=1:raise ValueError('containers do not report the same kernel boot ID')
    if len({v['time_offsets'] for v in identities.values()})!=1:raise ValueError('containers have differing time-namespace offsets')

def campaign_signature(args):
    return dict(helper_sha256=helper_digest(),miss_ms=args.miss_ms,confirm_ms=args.confirm_ms,
                sender_cpu=args.sender_cpu,realtime=args.realtime,capture=args.capture)

def control_marker(args,result,run_directory):
    path=SRC/'control_markers'/'timed_v3.json';path.parent.mkdir(exist_ok=True)
    identities=timeline.read_json(run_directory/'clock_identity.json')
    save(path,dict(signature=campaign_signature(args),run=str(run_directory.relative_to(SRC)),
                   created_mono_ns=time.monotonic_ns(),boot_id=next(iter(identities.values()))['boot_id'],
                   functional_pass=result['functional_pass'],measurement_pass=result['performance_pass']))

def check_control(args):
    path=SRC/'control_markers'/'timed_v3.json'
    try:
        marker=timeline.read_json(path)
        if marker['signature']!=campaign_signature(args):raise ValueError('source/settings differ from control')
        age=time.monotonic_ns()-marker['created_mono_ns']
        if not 0<=age<=4*3600*1_000_000_000:raise ValueError('control older than 4 hours or host clock reset')
        run=SRC/marker['run'];fresh=timeline.analyze(run)
        if fresh['mode']!='control' or not fresh['functional_pass']:raise ValueError('control evidence no longer passes functional checks')
        return marker
    except (OSError,ValueError,KeyError) as e:
        raise ValueError('fresh matching control required: '+str(e))

class Trial:
    def __init__(self,args,run):
        self.a=args;self.out=SRC/'results'/'timed-v3'/('run'+run)
        self.out.mkdir(parents=True,exist_ok=False)
        self.tmp='/tmp/ps020-timed-'+run
        self.port=20000+secrets.randbelow(20000)
        self.jobs=[];self.captures=[];self.nodes=[];self.cut_started=False;self.restore_attempt=0;self.lab_mutated=False
        self.lifecycle=dict(aborted=False,errors=[],restoration_verified=False)
        self.params=dict(schema='ps020-timed-v3-1',mode=args.mode,rate=1000,duration=20,payload=64,
                         cut_at=5,miss_ms=args.miss_ms,confirm_ms=args.confirm_ms,
                         sender_cpu=args.sender_cpu,realtime=args.realtime,capture=args.capture,port=self.port,
                         helper_sha256=helper_digest(),pacing_gap_limit_ms=2,pacing_rate_tolerance_percent=2)
        save(self.out/'params.json',self.params)
        # Compatibility only for the unchanged v3 restoration checker.
        (self.out/'params.txt').write_text('clock=monotonic\nscenario='+('baseline' if args.mode=='baseline' else 'srv6')+'\n')
    def ex(self,node,*cmd,check=True,privileged=False,timeout=15):
        return docker('exec',*(['--privileged'] if privileged else []),NODES[node],*cmd,check=check,timeout=timeout)
    def start(self,node,helper,*args,label=None,sender=False):
        label=label or helper
        stream=open(self.out/(label+'.stderr'),'x')
        env=[]
        if sender:
            if self.a.sender_cpu is not None:env+=['-e','TIMING_CPU='+str(self.a.sender_cpu)]
            if self.a.realtime:env+=['-e','TIMING_REALTIME=1']
        p=subprocess.Popen(['docker','exec',*(['--privileged'] if sender and self.a.realtime else []),*env,NODES[node],
                            'python3',self.tmp+'/timing/'+helper+'.py',*map(str,args)],stdout=stream,stderr=subprocess.STDOUT)
        self.jobs.append((node,p,stream,label));return p
    def ready(self,node,file,process,timeout=6):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            if process.poll() is not None:raise RuntimeError(f'{file}: helper exited; see stderr log')
            p=self.ex(node,'cat',file,check=False)
            if p.returncode==0 and p.stdout.strip():return p.stdout
            time.sleep(.05)
        raise RuntimeError('helper readiness timeout: '+file)
    def copy(self,node,name,dest=None,required=True):
        dest=dest or name
        p=docker('cp',NODES[node]+':'+self.tmp+'/'+name,self.out/dest,check=False)
        if required and p.returncode:raise RuntimeError('missing evidence: '+name+' '+p.stderr.strip())
    def wait(self,p,timeout=35):
        rc=p.wait(timeout=timeout)
        if rc:raise RuntimeError('helper failed; see stderr logs')
    def prepare(self):
        needed=('h1','h2','r1','r2','r3','r4','r5') if self.a.capture else ('h1','h2','r1','r2')
        identities={}
        for n in needed:
            self.ex(n,'mkdir',self.tmp);self.nodes.append(n)
            docker('cp',SRC/'timing',NODES[n]+':'+self.tmp+'/timing')
            identities[n]=json.loads(self.ex(n,'python3',self.tmp+'/timing/common.py','clock').stdout)
        clocks_compatible(identities)
        if getattr(self.a,'control_boot_id',None) and next(iter(identities.values()))['boot_id']!=self.a.control_boot_id:
            raise RuntimeError('kernel rebooted since control; run a fresh control')
        save(self.out/'clock_identity.json',identities)
        env=[]
        if self.a.sender_cpu is not None:env+=['-e','TIMING_CPU='+str(self.a.sender_cpu)]
        if self.a.realtime:env+=['-e','TIMING_REALTIME=1']
        p=docker('exec',*(['--privileged'] if self.a.realtime else []),*env,NODES['h1'],'python3',self.tmp+'/timing/send.py','--check')
        (self.out/'sender_preflight.json').write_text(p.stdout)
        self.lab_mutated=True
        self.ex('r2','sysctl','-w','net.ipv6.conf.eth2.keep_addr_on_down=1')
        self.ex('r2','python3',self.tmp+'/timing/link.py','eth2','up',self.tmp+'/initial_up.json')
        if self.a.mode=='baseline':
            old=self.ex('r1','ip','-6','route','show',DST+'/128').stdout
            (self.out/'previous_host_policy.txt').write_text(old)
            if 'encap' in old:self.ex('r1','ip','-6','route','del',DST+'/128')
        else:subprocess.run(['bash',str(SRC/'srv6_policy.sh'),'A'],cwd=SRC,check=True)
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            if 'dev eth2' in self.ex('r1','ip','-6','route','get','fc00:0:5::d6').stdout:break
            time.sleep(1)
        else:raise RuntimeError('underlay not on Path A')
        before=self.ex('r1','ip','-6','route','get',DST).stdout
        (self.out/'route_before.txt').write_text(before)
        if self.a.mode=='baseline' and 'encap' in before:raise RuntimeError('baseline still encapsulates SRv6')
        if self.a.mode!='baseline' and 'fc00:0:2::1' not in before:raise RuntimeError('primary SRv6 policy missing')
        ping=self.ex('h1','ping','-6','-c','5','-W','1',DST,check=False).stdout
        (self.out/'ping_before.txt').write_text(ping)
        if restoration.ping_problem(ping):raise RuntimeError('primary ping check failed: '+str(restoration.ping_problem(ping)))
    def capture_start(self):
        if not self.a.capture:return
        for n,interface in CAPS:
            name=n+'_'+interface+'.pcap'
            p=self.start(n,'capture',interface,self.tmp+'/'+name,label=name)
            self.ready(n,self.tmp+'/'+name+'.ready',p);self.captures.append((n,name,p))
    def stop_remote(self):
        for n in self.nodes:
            try:self.ex(n,'python3',self.tmp+'/timing/common.py','stop',self.tmp,check=False)
            except Exception as e:self.lifecycle['errors'].append('helper-stop error: '+str(e))
        for n,p,stream,label in self.jobs:
            try:p.wait(timeout=6)
            except subprocess.TimeoutExpired:
                p.terminate();self.lifecycle['errors'].append('helper did not stop: '+label)
            stream.close()
    def experiment(self):
        self.capture_start()
        recv=self.start('h2','receiver',self.port,28,self.tmp+'/recv.csv',label='receiver')
        self.ready('h2',self.tmp+'/recv.csv.ready',recv)
        det=None
        if self.a.mode!='baseline':
            det=self.start('r1','detector',DST,self.tmp+'/fail.txt',26,self.a.miss_ms,
                           'fc00:0:3::1,fc00:0:4::1,fc00:0:5::d6','eth3',self.a.confirm_ms,label='detector')
            self.ready('r1',self.tmp+'/fail.txt.ready',det)
        sender=self.start('h1','send',DST,self.port,1000,20,64,self.tmp+'/send.txt',sender=True,label='sender')
        start=json.loads(self.ready('h1',self.tmp+'/send.txt.ready',sender))['start_ns']
        if self.a.mode!='control':
            cut=self.start('r2','link','eth2','down',self.tmp+'/cut.json',start+5_000_000_000,label='cut')
            self.cut_started=True
        self.wait(sender)
        if self.a.mode!='control':self.wait(cut)
        if det:self.wait(det)
        self.wait(recv)
        self.copy('h1','send.txt');self.copy('h1','send_packets.csv');self.copy('h1','send.txt.scheduling.json')
        self.copy('h1','send_gap_diagnostic.csv');self.copy('h1','send_gap_diagnostic.schema.json')
        self.copy('h2','recv.csv');self.copy('h2','recv.csv.json')
        if det:self.copy('r1','fail.txt');self.copy('r1','fail.txt.json')
        if self.a.mode!='control':self.copy('r2','cut.json')
        (self.out/'route_after.txt').write_text(self.ex('r1','ip','-6','route','get',DST).stdout)
    def restore(self):
        if 'r2' not in self.nodes:return
        self.restore_attempt+=1
        name=f'restore_{self.restore_attempt}.json'
        try:
            self.ex('r2','python3',self.tmp+'/timing/link.py','eth2','up',self.tmp+'/'+name)
            self.copy('r2',name)
        except Exception as e:
            # Emergency restoration only. Never replace the measured cut with an unreported fallback.
            detail='direct restoration failed; emergency ip link up required: '+str(e)
            self.lifecycle['errors'].append(detail)
            (self.out/f'emergency_restore_{self.restore_attempt}.txt').write_text(detail)
            code="import json,subprocess,time; b=time.monotonic_ns(); subprocess.run(['ip','link','set','eth2','up'],check=True); a=time.monotonic_ns(); print(json.dumps(dict(before_ns=b,after_ns=a,status='emergency_ip_up',clock='monotonic')))"
            up=self.ex('r2','python3','-c',code)
            (self.out/name).write_text(up.stdout)

        (self.out/'restore.json').write_text((self.out/name).read_text())
        up=timeline.read_json(self.out/'restore.json')
        (self.out/'restore.log').write_text(f"clock=monotonic\nt_before_ns={up['before_ns']}\nt_after_ns={up['after_ns']}\n")
        if self.a.mode!='baseline':subprocess.run(['bash',str(SRC/'srv6_policy.sh'),'A'],cwd=SRC,check=True)
        deadline=time.monotonic()+180;attempt=0
        while True:
            attempt+=1
            route=self.ex('r1','ip','-6','route','get',DST).stdout
            if self.a.mode!='baseline':
                # Show the ingress policy separately from its underlay resolution.
                route=self.ex('r1','ip','-6','route','show',DST+'/128').stdout
                (self.out/'underlay_restored.txt').write_text(self.ex('r1','ip','-6','route','get','fc00:0:5::d6').stdout)
            (self.out/'route_restored.txt').write_text(route)
            p=self.ex('h1','ping','-6','-c','5','-W','1',DST,check=False)
            text=p.stdout+p.stderr;(self.out/'ping_restored.txt').write_text(text)
            problems=restoration.problems(self.out,'baseline' if self.a.mode=='baseline' else 'srv6',True)
            if not problems:break
            (self.out/f'ping_restored_try{attempt}.txt').write_text(text)
            if time.monotonic()>=deadline:raise RuntimeError('restoration failed: '+'; '.join(problems))
            time.sleep(2)
        self.lifecycle['restoration_verified']=True
    def restoration_udp(self):
        remote=self.tmp+'/restored';self.ex('h1','mkdir',remote);self.ex('h2','mkdir',remote)
        receiver=self.start('h2','receiver',self.port+1,5,remote+'/recv.csv',label='restoration_receiver')
        self.ready('h2',remote+'/recv.csv.ready',receiver)
        sender=self.start('h1','send',DST,self.port+1,1000,.1,64,remote+'/send.txt',label='restoration_sender',sender=True)
        self.wait(sender);self.wait(receiver,8)
        (self.out/'restored').mkdir()
        self.copy('h1','restored/send_packets.csv','restored/send_packets.csv')
        self.copy('h1','restored/send.txt','restored/send.txt')
        self.copy('h1','restored/send_gap_diagnostic.csv','restored/send_gap_diagnostic.csv')
        self.copy('h1','restored/send_gap_diagnostic.schema.json','restored/send_gap_diagnostic.schema.json')
        self.copy('h2','restored/recv.csv','restored/recv.csv')
        rows=timeline.csv_rows(self.out/'restored/send_packets.csv');received=timeline.csv_rows(self.out/'restored/recv.csv')
        tx={int(x['seq']):int(x['actual_ns']) for x in rows}
        rx={int(x['seq']):int(x['t_send_mono_ns']) for x in received}
        if len(rows)!=100 or len(received)!=100 or tx!=rx or any(int(x['ok'])!=1 for x in rows):
            self.lifecycle['restoration_verified']=False
            raise RuntimeError('fresh restored-path UDP verification did not deliver all 100 packets')
        save(self.out/'restored/verification.json',dict(sent=100,received=100,loss=0))
        self.lifecycle['udp_restoration_verified']=True
    def finish_capture(self):
        if not self.captures:return
        # Captures run through restored-path UDP. Stop only after all proof traffic is finished.
        self.stop_remote()
        for node,name,p in self.captures:
            self.copy(node,name);self.copy(node,name+'.stderr',name+'.tcpdump.log')
            if p.returncode!=0:raise RuntimeError('capture helper did not finish cleanly: '+name)
    def run(self):
        try:
            self.prepare();self.experiment();self.restore();self.restoration_udp();self.finish_capture()
        except KeyboardInterrupt:
            self.lifecycle['aborted']=True
        except Exception as e:
            self.lifecycle['errors'].append(str(e))
        finally:
            # In an interrupted trial, cancel a scheduled future cut BEFORE restoring the link.
            if self.lifecycle['aborted'] or self.lifecycle['errors']:
                self.stop_remote()
                try:
                    if self.lab_mutated and not self.lifecycle['restoration_verified']:self.restore()
                except Exception as e:
                    self.lifecycle['errors'].append('cleanup restoration: '+str(e))
                    (self.out/'RESTORE_ERROR.txt').write_text(str(e))
            self.stop_remote()
            save(self.out/'lifecycle.json',self.lifecycle)
        result=timeline.analyze(self.out)
        save(self.out/'report.json',result);(self.out/'report.txt').write_text(timeline.render(result))
        timeline.write_events(self.out/'timeline.csv',result)
        print(timeline.render(result),end='');print('Evidence:',self.out)
        return result

def aggregate(rows,out):
    import statistics
    clean=[r for r in rows if r['performance_pass']];functional=[r for r in rows if r['functional_pass']]
    summary=dict(attempted=len(rows),functional_pass=len(functional),performance_pass=len(clean),
                 invalid=[dict(run=r['run'],errors=r['errors'],pacing=r['quality_reasons']) for r in rows if not r['performance_pass']])
    for label,selected in [('pacing_clean',clean),('all_functional_sensitivity',functional)]:
        metrics={}
        for key in ('lost_at_cut','max_receiver_gap_near_cut_ms'):
            values=[r[key] for r in selected if key in r]
            if values:metrics[key]=dict(n=len(values),mean=statistics.mean(values),min=min(values),max=max(values))
        recovery=[r['post_loss_udp_recovery']['from_cut_start_ms'] for r in selected if r.get('post_loss_udp_recovery')]
        if recovery:metrics['post_loss_udp_recovery_from_cut_start_ms']=dict(n=len(recovery),mean=statistics.mean(recovery),min=min(recovery),max=max(recovery))
        for stage_name in ('detection_breakdown','recovery_breakdown','post_policy_delivery_breakdown'):
            stage_stats={}
            keys={key for r in selected for key in r.get(stage_name,{}).get('stages_ns',{})}
            for key in sorted(keys):
                vals=[r[stage_name]['stages_ns'][key]/1e6 for r in selected if key in r.get(stage_name,{}).get('stages_ns',{})]
                stage_stats[key]=dict(n=len(vals),mean_ms=statistics.mean(vals),min_ms=min(vals),max_ms=max(vals))
            if stage_stats:metrics[stage_name]=stage_stats
        summary[label]=metrics
    csv_path=Path(out).with_suffix('.csv')
    fields=['run','mode','functional_pass','performance_pass','lost_total','lost_at_cut','recovery_from_cut_start_ms','recovery_from_cut_end_ms','cut_uncertainty_ms','max_send_gap_ms','detection_lower_ms','detection_upper_ms','policy_command_ms','errors','quality_reasons']
    with open(csv_path,'w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader()
        for r in rows:
            rec=r.get('post_loss_udp_recovery') or {};cut=r.get('cut') or {}
            writer.writerow(dict(run=r['run'],mode=r['mode'],functional_pass=r['functional_pass'],performance_pass=r['performance_pass'],
                lost_total=r.get('lost_total'),lost_at_cut=r.get('lost_at_cut'),recovery_from_cut_start_ms=rec.get('from_cut_start_ms'),
                recovery_from_cut_end_ms=rec.get('from_cut_end_ms'),cut_uncertainty_ms=cut.get('uncertainty_ns',0)/1e6 if cut else None,
                max_send_gap_ms=r.get('near_cut_max_send_gap_ms'),detection_lower_ms=(r.get('detection_delay_bounds_ms') or [None,None])[0],detection_upper_ms=(r.get('detection_delay_bounds_ms') or [None,None])[1],policy_command_ms=r.get('post_policy_delivery_breakdown',{}).get('stages_ns',{}).get('ip_command_wall_time',0)/1e6 if r.get('post_policy_delivery_breakdown') else None,errors='; '.join(r['errors']),quality_reasons='; '.join(r['quality_reasons'])))
    save(out,summary);print(json.dumps(summary,indent=2))

def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--mode',choices=('control','srv6','baseline'),default='control')
    ap.add_argument('--runs',type=int,default=1);ap.add_argument('--prefix',default='timed_'+time.strftime('%Y%m%d_%H%M%S'))
    ap.add_argument('--miss-ms',type=float,default=5);ap.add_argument('--confirm-ms',type=float,default=1)
    ap.add_argument('--capture',action='store_true',help='capture full IPv6 packets at all required path stages (roughly 10-30 MB per trial)')
    ap.add_argument('--sender-cpu',type=int);ap.add_argument('--realtime',action='store_true',help='require privileged Docker exec and SCHED_FIFO priority 10 for sender; no silent fallback')
    a=ap.parse_args(argv)
    if not 1<=a.runs<=1000 or a.miss_ms<=0 or a.confirm_ms<0:ap.error('invalid runs/detector values')
    import re,math
    if not math.isfinite(a.miss_ms+a.confirm_ms) or not re.fullmatch('[A-Za-z0-9_-]+',a.prefix):ap.error('finite timings and safe prefix required')
    if a.sender_cpu is not None and a.sender_cpu<0:ap.error('sender CPU must be nonnegative')
    # Same lock as the original v3 runner: experiments cannot overlap.
    with open('/tmp/ps020-monotonic-lab.lock','w') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:ap.error('another lab experiment is active')
        if a.runs>1 and a.mode!='control':
            try:a.control_boot_id=check_control(a)['boot_id']
            except ValueError as e:ap.error(str(e))
        rows=[];batch=SRC/'batches'/(a.prefix+'_timed');batch.mkdir(parents=True,exist_ok=False)
        for i in range(1,a.runs+1):
            print(f'Trial {i}/{a.runs}',flush=True)
            trial=Trial(a,f'{a.prefix}_{i:03d}');r=trial.run();rows.append(r)
            if a.mode=='control' and r['functional_pass']:
                control_marker(a,r,trial.out)
                print('Functional control marker saved. Per-trial pacing is judged independently; this is not a pacing certification.')
            aggregate(rows,batch/'summary.json')
            if trial.lifecycle['aborted'] or trial.lifecycle['errors']:break
        aggregate(rows,batch/'summary.json')
        return 0 if len(rows)==a.runs and all(r['functional_pass'] if a.mode=='control' else r['performance_pass'] for r in rows) else 1
if __name__=='__main__':sys.exit(main())
