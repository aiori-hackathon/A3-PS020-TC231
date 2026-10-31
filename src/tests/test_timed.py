"""Offline event-order, protocol, measurement and local UDP tests; not a live SRv6 lab."""
import csv,importlib.util,json,os,socket,struct,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
SRC=Path(__file__).resolve().parents[1];sys.path.insert(0,str(SRC/'timing'));sys.path.insert(0,str(SRC))
import report,pcap,link,run_timed
spec=importlib.util.spec_from_file_location('timed_sender',SRC/'timing/send.py');sender=importlib.util.module_from_spec(spec);spec.loader.exec_module(sender)
def fixture(root):
 root=Path(root)
 def put(name,obj):(root/name).write_text(json.dumps(obj))
 put('params.json',dict(schema='ps020-timed-v3-1',mode='srv6',rate=1000,duration=1))
 put('lifecycle.json',dict(aborted=False,errors=[],restoration_verified=True,udp_restoration_verified=True))
 (root/'send.txt').write_text('clock=monotonic\nsent=1000\nstart_ns=1000000000\nend_ns=2000000000\nsend_errors=0\n')
 put('recv.csv.json',dict(clock='monotonic',start_ns=900000000,end_ns=2100000000,overflow=False))
 with (root/'send_packets.csv').open('w',newline='') as f:
  w=csv.writer(f);w.writerow(['seq','scheduled_ns','actual_ns','ok','submit_done_ns'])
  for q in range(1000):
   tx=1_000_000_000+q*1_000_000;w.writerow([q,tx,tx,1,tx+10000])
 with (root/'recv.csv').open('w',newline='') as f:
  w=csv.writer(f);w.writerow(['seq','t_send_mono_ns','t_recv_mono_ns'])
  for q in range(1000):
   if 300<=q<308:continue
   tx=1_000_000_000+q*1_000_000;w.writerow([q,tx,tx+100000])
 put('cut.json',dict(status='acknowledged',before_ns=1300000000,submitted_ns=1300002000,after_ns=1300010000,uncertainty_ns=10000))
 put('fail.txt.json',dict(status='finished',start_ns=900000000,end_ns=2100000000,switch_count=1,detect_ns=1306000000,policy_ack_observed_ns=1308000000,first_probe_ok_ns=1309000000,
  trigger=dict(last_reply_ns=1299000000,miss_due_ns=1304000000,suspect_ns=1304500000,confirm_due_ns=1305500000),policy_command=dict(before_ns=1306100000,after_ns=1308000000)))
 (root/'route_before.txt').write_text('encap seg6 fc00:0:2::1 dev eth2');(root/'route_after.txt').write_text('encap seg6 fc00:0:3::1 dev eth3')
 from restoration_fixture import write_restoration
 write_restoration(root,'ok','srv6')
 (root/'restored').mkdir()
 with (root/'restored/send_packets.csv').open('w') as f:
  f.write('seq,scheduled_ns,actual_ns,ok,submit_done_ns\n')
  for q in range(100):
   tx=3_000_000_000+q*1_000_000;f.write(f'{q},{tx},{tx},1,{tx+10000}\n')
 with (root/'restored/recv.csv').open('w') as f:
  f.write('seq,t_send_mono_ns,t_recv_mono_ns\n')
  for q in range(100):
   tx=3_000_000_000+q*1_000_000;f.write(f'{q},{tx},{tx+100000}\n')
 return root
def change_json(path,**kw):
 obj=json.loads(path.read_text());obj.update(kw);path.write_text(json.dumps(obj))
class TimelineTests(unittest.TestCase):
 def test_exact_breakdown_and_bounds(self):
  with tempfile.TemporaryDirectory() as d:
   fixture(d);r=report.analyze(d);self.assertTrue(r['functional_pass'],r);self.assertTrue(r['performance_pass'],r)
   self.assertEqual(r['lost_at_cut'],8);self.assertAlmostEqual(r['post_loss_udp_recovery']['from_cut_start_ms'],8.1);self.assertEqual(r['detection_delay_bounds_ms'],[5.99,6.0])
   for key in ('detection_breakdown','recovery_breakdown','post_policy_delivery_breakdown'):self.assertEqual(sum(r[key]['stages_ns'].values()),r[key]['total_ns'])
   self.assertEqual(r['detection_breakdown']['stages_ns']['last_reply_relative_to_cut'],-1_000_000)
 def test_receiver_stamp_mismatch(self):
  with tempfile.TemporaryDirectory() as d:
   p=fixture(d)/'recv.csv';p.write_text(p.read_text().replace('1000000000,1000100000','999999999,1000100000'));self.assertFalse(report.analyze(d)['functional_pass'])
 def test_abort_not_valid(self):
  with tempfile.TemporaryDirectory() as d:
   p=fixture(d);change_json(p/'lifecycle.json',aborted=True);self.assertFalse(report.analyze(d)['functional_pass'])
 def test_restore_udp_required(self):
  with tempfile.TemporaryDirectory() as d:
   p=fixture(d);change_json(p/'lifecycle.json',udp_restoration_verified=False);self.assertFalse(report.analyze(d)['functional_pass'])
 def test_no_loss_not_zero_recovery(self):
  with tempfile.TemporaryDirectory() as d:
   p=fixture(d)
   with (p/'recv.csv').open('a') as f:
    for q in range(300,308):
     tx=1_000_000_000+q*1_000_000;f.write(f'{q},{tx},{tx+100000}\n')
   r=report.analyze(d);self.assertIsNone(r['post_loss_udp_recovery']);self.assertEqual(r['lost_at_cut'],0)
 def test_near_cut_pacing_failure_separate(self):
  with tempfile.TemporaryDirectory() as d:
   p=fixture(d);rows=report.csv_rows(p/'send_packets.csv')
   for row in rows:
    if int(row['seq'])>=500:
     for k in ('actual_ns','submit_done_ns'):row[k]=str(int(row[k])+3_000_000)
   with (p/'send_packets.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=rows[0]);w.writeheader();w.writerows(rows)
   rows=report.csv_rows(p/'recv.csv')
   for row in rows:
    if int(row['seq'])>=500:
     for k in ('t_send_mono_ns','t_recv_mono_ns'):row[k]=str(int(row[k])+3_000_000)
   with (p/'recv.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=rows[0]);w.writeheader();w.writerows(rows)
   r=report.analyze(d);self.assertTrue(r['functional_pass'],r);self.assertFalse(r['performance_pass'])
 def test_no_postpolicy_delivery(self):
  with tempfile.TemporaryDirectory() as d:
   p=fixture(d);rows=report.csv_rows(p/'recv.csv')
   with (p/'recv.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=rows[0]);w.writeheader();w.writerows(x for x in rows if int(x['seq'])<300)
   self.assertFalse(report.analyze(d)['functional_pass'])
 def test_false_trigger(self):
  with tempfile.TemporaryDirectory() as d:
   p=fixture(d);change_json(p/'fail.txt.json',detect_ns=1298000000);self.assertFalse(report.analyze(d)['functional_pass'])
 def test_receiver_coverage(self):
  with tempfile.TemporaryDirectory() as d:
   p=fixture(d);change_json(p/'recv.csv.json',end_ns=1900000000);self.assertFalse(report.analyze(d)['functional_pass'])
 def test_missing_metadata(self):
  with tempfile.TemporaryDirectory() as d:self.assertFalse(report.analyze(d)['functional_pass'])
 def test_event_csv_endpoint(self):
  with tempfile.TemporaryDirectory() as d:
   p=fixture(d);r=report.analyze(d);report.write_events(p/'timeline.csv',r);rows=report.csv_rows(p/'timeline.csv')
   self.assertEqual(rows[-1]['event'],'endpoint_H2_userspace_receive');self.assertAlmostEqual(float(rows[-1]['relative_to_cut_request_ms']),8.1)
class NetlinkTests(unittest.TestCase):
 def ack(self,error=0,seq=1):return struct.pack('=IHHIIi',36,2,0,seq,0,error)+bytes(16)
 def test_flags(self):
  for up in (True,False):
   msg=link.message(7,up,12);self.assertEqual(struct.unpack_from('=IHHII',msg),(32,16,5,12,0))
   values=struct.unpack_from('=BBHiII',msg,16);self.assertEqual(values[3:],(7,1 if up else 0,1))
 def test_error(self):
  with self.assertRaises(PermissionError):link.acknowledge(self.ack(-1),1)
 def test_unrelated_ack(self):self.assertFalse(link.acknowledge(self.ack(seq=2),1))
 def test_ack_bracket(self):
  outer=self
  class Sock:
   def sendto(self,msg,dst):pass
   def recvfrom(self,n):return outer.ack(),(0,0)
  clock=iter([100,110,130]);r=link.change('unused',True,sock=Sock(),now=lambda:next(clock),index=1)
  self.assertEqual(r['uncertainty_ns'],30);self.assertEqual(r['submitted_ns'],110)
 def test_truncated_ack(self):
  with self.assertRaises(ValueError):link.acknowledge(self.ack()[:-1],1)
class ClockTests(unittest.TestCase):
 def test_identity_mismatch(self):
  good=dict(boot_id='one',time_offsets='monotonic 0 0');run_timed.clocks_compatible({'a':good,'b':dict(good)})
  for bad in (dict(good,boot_id='two'),dict(good,time_offsets='monotonic 1 0')):
   with self.assertRaises(ValueError):run_timed.clocks_compatible({'a':good,'b':bad})
class SenderTests(unittest.TestCase):
 def test_stall_reanchor(self):
  class Clock:
   def __init__(self):self.t=1000000000
   def now(self):self.t+=10000;return self.t
   def sleep(self,s):self.t+=int(s*1e9)
  c=Clock()
  class Sock:
   count=0
   def sendto(self,data,dst):
    self.count+=1
    if self.count==2:c.t+=10_000_000
  r=sender.run_sender(Sock(),'::1',1,1000,.01,64,c.now,c.sleep)
  self.assertGreater(r['maxlate'],8_000_000);self.assertGreaterEqual(r['actual'][3]-r['actual'][2],1_000_000)
 def test_realtime_denial_no_fallback(self):
  with patch.dict(os.environ,{'TIMING_REALTIME':'1'}),patch.object(sender.os,'sched_setscheduler',side_effect=PermissionError):
   with self.assertRaises(PermissionError):sender.configure()
 def test_actual_ipv6_udp(self):
  with tempfile.TemporaryDirectory() as d:
   try:
    s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s.bind(('::1',0));port=s.getsockname()[1];s.close()
   except OSError as e:self.skipTest(str(e))
   out=Path(d);p=subprocess.Popen([sys.executable,str(SRC/'timing/receiver.py'),str(port),'3',str(out/'recv.csv')])
   try:
    for _ in range(100):
     if (out/'recv.csv.ready').exists():break
     time.sleep(.01)
    subprocess.run([sys.executable,str(SRC/'timing/send.py'),'::1',str(port),'1000','.2','64',str(out/'send.txt')],check=True,timeout=5)
    self.assertEqual(p.wait(timeout=5),0)
    tx=report.csv_rows(out/'send_packets.csv');rx=report.csv_rows(out/'recv.csv');self.assertEqual(len(tx),200);self.assertEqual(len(rx),200)
    self.assertTrue(all(int(x['submit_done_ns'])>=int(x['actual_ns']) for x in tx))
    self.assertEqual({int(x['seq']):int(x['actual_ns']) for x in tx},{int(x['seq']):int(x['t_send_mono_ns']) for x in rx})
   finally:
    if p.poll() is None:p.kill();p.wait()
class PacketTests(unittest.TestCase):
 def datagram(self,sids=None,left=0,seq=1,stamp=999):
  import ipaddress
  payload=b'PS020M01'+struct.pack('!QQ',seq,stamp)+b'x'*40;udp=struct.pack('!HHHH',1234,5001,len(payload)+8,0)+payload
  def ip(nxt,p):return struct.pack('!IHBB',6<<28,len(p),nxt,64)+bytes(32)+p
  inner=ip(17,udp)
  if not sids:return inner
  srh=struct.pack('!BBBBBBH',41,2*len(sids),4,left,len(sids)-1,0,0)+b''.join(ipaddress.IPv6Address(x).packed for x in sids)
  return ip(43,srh+inner)
 def test_srh_headers(self):
  for sids,left,expected in ((['fc00:0:5::d6','fc00:0:2::1'],1,80),(['fc00:0:5::d6','fc00:0:4::1','fc00:0:3::1'],2,96)):
   r=pcap.decode_ipv6(self.datagram(sids,left));self.assertEqual(r['srh']['sids_wire'],sids);self.assertEqual(r['srh']['segments_left'],left);self.assertEqual(r['srh']['overhead_bytes'],expected)
 def test_pcap_and_truncation(self):
  with tempfile.TemporaryDirectory() as d:
   frame=bytes(12)+b'\x86\xdd'+self.datagram();blob=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)+struct.pack('<IIII',0,0,len(frame),len(frame))+frame
   p=Path(d)/'sample.pcap';p.write_bytes(blob);self.assertEqual(pcap.read_packets(p)[0]['send_ns'],999);p.write_bytes(blob[:-1])
   with self.assertRaises(ValueError):pcap.read_packets(p)

class LifecycleTests(unittest.TestCase):
 def trial(self,root):
  import argparse
  args=argparse.Namespace(mode='srv6',miss_ms=5,confirm_ms=1,sender_cpu=None,realtime=False,capture=False)
  with patch.object(run_timed,'SRC',Path(root)):return run_timed.Trial(args,'test')
 def test_preflight_failure_does_not_mutate_link(self):
  with tempfile.TemporaryDirectory() as d:
   trial=self.trial(d)
   with patch.object(trial,'prepare',side_effect=RuntimeError('scheduling denied')),patch.object(trial,'stop_remote'),patch.object(trial,'restore') as restore:
    result=trial.run();restore.assert_not_called();self.assertFalse(result['functional_pass'])
 def test_pending_cut_cancelled_before_abort_restore(self):
  with tempfile.TemporaryDirectory() as d:
   trial=self.trial(d);events=[]
   def prepare():trial.lab_mutated=True
   def restore():events.append('restore');trial.lifecycle['restoration_verified']=True
   with patch.object(trial,'prepare',side_effect=prepare),patch.object(trial,'experiment',side_effect=KeyboardInterrupt),patch.object(trial,'stop_remote',side_effect=lambda:events.append('stop')),patch.object(trial,'restore',side_effect=restore):
    result=trial.run()
   self.assertEqual(events[:2],['stop','restore']);self.assertFalse(result['functional_pass']);self.assertTrue(trial.lifecycle['aborted'])
class ExtendedTimelineTests(unittest.TestCase):
 def test_loss_burst_not_truncated_at_window_end(self):
  with tempfile.TemporaryDirectory() as d:
   p=fixture(d);rows=report.csv_rows(p/'recv.csv')
   with (p/'recv.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=rows[0]);w.writeheader();w.writerows(x for x in rows if not 308<=int(x['seq'])<900)
   r=report.analyze(d);self.assertEqual(r['lost_at_cut'],600);self.assertAlmostEqual(r['post_loss_udp_recovery']['from_cut_start_ms'],600.1)
 def test_negative_cut_bracket_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=fixture(d);change_json(p/'cut.json',after_ns=1299999999);self.assertFalse(report.analyze(d)['functional_pass'])
 def test_legacy_icmp_pcaps_not_mislabelled_udp_proof(self):
  # Decode actual preserved frames, not only self-generated fixtures.
  root=SRC/'pcaps/verified_20261012_143331'
  a=pcap.read_packets(root/'policyA/verified_A_r1_eth2.pcap')
  # These original captures contain ICMP, so the UDP-specific decoder correctly ignores them.
  self.assertEqual(a,[])

class RestorationRawEvidenceTests(unittest.TestCase):
 def test_wrong_restored_policy_even_with_success_marker_is_invalid(self):
  with tempfile.TemporaryDirectory() as d:
   p=fixture(d);(p/'route_restored.txt').write_text('fc00:0:3::1 dev eth3');self.assertFalse(report.analyze(d)['functional_pass'])
 def test_partial_restoration_udp_is_invalid(self):
  with tempfile.TemporaryDirectory() as d:
   p=fixture(d);rows=(p/'restored/recv.csv').read_text().splitlines();(p/'restored/recv.csv').write_text('\n'.join(rows[:-1]));self.assertFalse(report.analyze(d)['functional_pass'])
 def test_capture_requested_but_missing_is_invalid(self):
  with tempfile.TemporaryDirectory() as d:
   p=fixture(d);change_json(p/'params.json',capture=True);self.assertFalse(report.analyze(d)['functional_pass'])


class RecoveryOverlapTests(unittest.TestCase):
 def test_early_route_activation_not_forced_into_negative_delays(self):
  det=dict(detect_ns=106,policy_command=dict(before_ns=107,after_ns=112))
  part=report.recovery_parts(100,det,{5:dict(actual_ns=109)},5,110)
  self.assertEqual(part['total_ns'],10);self.assertTrue(part['command_and_packet_overlap'])
  self.assertEqual(sum(part['stages_ns'].values()),10);self.assertTrue(all(x>=0 for x in part['stages_ns'].values()))
 def test_recovery_before_detector_is_reported_without_attribution(self):
  det=dict(detect_ns=106,policy_command=dict(before_ns=107,after_ns=112))
  part=report.recovery_parts(100,det,{5:dict(actual_ns=102)},5,104)
  self.assertEqual(sum(part['stages_ns'].values()),4);self.assertTrue(part['command_and_packet_overlap'])
class FullCaptureTests(unittest.TestCase):
 def write_capture(self,path,frames):
  blob=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
  for packet in frames:
   frame=bytes(12)+b'\x86\xdd'+packet;blob+=struct.pack('<IIII',0,0,len(frame),len(frame))+frame
  path.write_bytes(blob)
 def files(self,root,bad=False):
  packet=PacketTests().datagram;a=['fc00:0:5::d6','fc00:0:2::1'];b=['fc00:0:5::d6','fc00:0:4::1','fc00:0:3::1']
  frames={'r1_eth2':[packet(a,1,1,999),packet(a,1,0,3000)],'r5_eth1':[packet(a,0,1,999),packet(a,0,0,3000)],
   'r1_eth3':[packet(b,2,2,2000)],'r3_eth2':[packet(b,2 if bad else 1,2,2000)],'r4_eth2':[packet(b,0,2,2000)],
   'r5_eth3':[packet(None,0,1,999),packet(None,0,2,2000),packet(None,0,0,3000)]}
  for name,rows in frames.items():self.write_capture(root/(name+'.pcap'),rows)
 def test_all_stages_and_recovery_policy(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);self.files(root);r=pcap.verify(root,{1:999,2:2000},{1,2},1000,1500,{0:3000},2)
   self.assertTrue(r['verified'],r);self.assertEqual(pcap.recovery_policy(root,1,999)['ingress_policy'],'A');self.assertEqual(pcap.recovery_policy(root,2,2000)['ingress_policy'],'B')
 def test_wrong_segments_left_fails_path_proof(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);self.files(root,True);self.assertFalse(pcap.verify(root,{1:999,2:2000},{1,2},1000,1500,{0:3000},2)['verified'])
class CampaignTests(unittest.TestCase):
 def args(self):
  import argparse
  return argparse.Namespace(miss_ms=5,confirm_ms=1,sender_cpu=None,realtime=False,capture=False)
 def control(self,root):
  run=fixture(root/'control') if (root/'control').exists() else None
  if run is None:
   (root/'control').mkdir();run=fixture(root/'control')
  change_json(run/'params.json',mode='control');change_json(run/'fail.txt.json',switch_count=0,detect_ns=0)
  with (run/'recv.csv').open('a') as f:
   for q in range(300,308):
    tx=1_000_000_000+q*1_000_000;f.write(f'{q},{tx},{tx+100000}\n')
  (run/'route_after.txt').write_text('fc00:0:2::1 dev eth2');(run/'clock_identity.json').write_text(json.dumps({'h1':dict(boot_id='test',time_offsets='0')}))
  return run
 def test_fresh_control_and_source_change(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);run=self.control(root);args=self.args()
   with patch.object(run_timed,'SRC',root):
    r=report.analyze(run);self.assertTrue(r['functional_pass'],r);run_timed.control_marker(args,r,run);self.assertEqual(run_timed.check_control(args)['boot_id'],'test')
    (root/'srv6_policy.sh').write_text('modified policy')
    with self.assertRaises(ValueError):run_timed.check_control(args)
 def test_all_attempts_remain_in_csv(self):
  with tempfile.TemporaryDirectory() as d:
   ok=dict(run='ok',mode='srv6',functional_pass=True,performance_pass=True,errors=[],quality_reasons=[],lost_at_cut=7)
   bad=dict(run='bad',mode='srv6',functional_pass=True,performance_pass=False,errors=[],quality_reasons=['gap'])
   with patch('sys.stdout'):run_timed.aggregate([ok,bad],Path(d)/'summary.json')
   rows=report.csv_rows(Path(d)/'summary.csv');self.assertEqual([r['run'] for r in rows],['ok','bad'])


class OrchestrationTests(unittest.TestCase):
 def trial(self,root):
  import argparse
  args=argparse.Namespace(mode='srv6',miss_ms=5,confirm_ms=1,sender_cpu=None,realtime=False,capture=False)
  with patch.object(run_timed,'SRC',Path(root)):return run_timed.Trial(args,'orchestration')
 def test_cut_anchored_to_published_sender_clock(self):
  import types
  with tempfile.TemporaryDirectory() as d:
   trial=self.trial(d);calls=[]
   def start(node,helper,*args,**kw):calls.append((node,helper,args));return object()
   def ready(node,file,process):return json.dumps({'start_ns':10_000_000_000}) if file.endswith('send.txt.ready') else 'ready'
   with patch.object(trial,'capture_start'),patch.object(trial,'start',side_effect=start),patch.object(trial,'ready',side_effect=ready),patch.object(trial,'wait'),patch.object(trial,'copy'),patch.object(trial,'ex',return_value=types.SimpleNamespace(stdout='fc00:0:3::1 dev eth3')):
    trial.experiment()
   cut=[x for x in calls if x[1]=='link'][0];self.assertEqual(cut[2][-1],15_000_000_000)
 def test_privilege_only_requested_for_realtime_sender(self):
  with tempfile.TemporaryDirectory() as d:
   trial=self.trial(d);trial.a.realtime=True;trial.a.sender_cpu=2
   with patch.object(run_timed.subprocess,'Popen') as popen:
    trial.start('h1','send','argument',sender=True)
    args=popen.call_args.args[0];self.assertIn('--privileged',args);self.assertIn('TIMING_REALTIME=1',args);self.assertIn('TIMING_CPU=2',args)
   for _,_,stream,_ in trial.jobs:stream.close()
 def test_repeated_restore_attempts_preserve_individual_ack_files(self):
  import types
  from restoration_fixture import PING_HDR,PING,ROUTE
  with tempfile.TemporaryDirectory() as d:
   trial=self.trial(d);trial.nodes=['r2']
   def ex(node,*cmd,**kw):
    if cmd[0]=='ping':text=PING_HDR+PING['ok']
    elif 'fc00:0:5::d6' in cmd:text='fc00:0:5::d6 dev eth2'
    else:text=ROUTE['srv6_A']
    return types.SimpleNamespace(stdout=text,stderr='',returncode=0)
   def copy(node,name,*args,**kw):(trial.out/name).write_text(json.dumps({'before_ns':10,'after_ns':20}))
   with patch.object(trial,'ex',side_effect=ex),patch.object(trial,'copy',side_effect=copy),patch.object(run_timed.subprocess,'run'):
    trial.restore();trial.restore()
   self.assertTrue((trial.out/'restore_1.json').exists());self.assertTrue((trial.out/'restore_2.json').exists());self.assertTrue(trial.lifecycle['restoration_verified'])


class EmergencyRestorationTest(unittest.TestCase):
 def test_emergency_fallback_is_recorded_and_not_silently_accepted(self):
  import types
  from restoration_fixture import PING_HDR,PING,ROUTE
  with tempfile.TemporaryDirectory() as d:
   trial=OrchestrationTests().trial(d);trial.nodes=['r2']
   def ex(node,*cmd,**kw):
    if cmd[0]=='python3' and cmd[1].endswith('link.py'):raise RuntimeError('simulated netlink failure')
    if cmd[0]=='python3':text=json.dumps({'before_ns':10,'after_ns':20})
    elif cmd[0]=='ping':text=PING_HDR+PING['ok']
    elif 'fc00:0:5::d6' in cmd:text='fc00:0:5::d6 dev eth2'
    else:text=ROUTE['srv6_A']
    return types.SimpleNamespace(stdout=text,stderr='',returncode=0)
   with patch.object(trial,'ex',side_effect=ex),patch.object(run_timed.subprocess,'run'):trial.restore()
   self.assertTrue(trial.lifecycle['restoration_verified']);self.assertTrue(trial.lifecycle['errors']);self.assertTrue((trial.out/'emergency_restore_1.txt').exists())


class RealtimeExitTest(unittest.TestCase):
 def test_fifo_is_dropped_before_journal_output(self):
  with tempfile.TemporaryDirectory() as d:
   out=Path(d)/'send.txt';events=[]
   result=dict(n=2,start=1,end=1000001,scheduled=[1,1000001],actual=[1,1000001],completed=[2,1000002],ok=[1,1],maxlate=0,errors=0,diag_wall=[0,1000000],diag_cpu=[0,1],diag_vol=[0,0],diag_invol=[0,0])
   def run(*a,**kw):events.append('traffic');return result
   def lower(*a):events.append('scheduler_restored')
   def write(*a):events.append('metadata_write')
   with patch.dict(os.environ,{'TIMING_REALTIME':'1'}),patch.object(sys,'argv',['send.py','::1','5001','1000','.002','64',str(out)]),patch.object(sender,'configure',return_value={'policy':1}),patch.object(sender.os,'sched_setscheduler',side_effect=lower),patch.object(sender,'run_sender',side_effect=run),patch.object(sender,'write_json',side_effect=write):sender.main()
   self.assertEqual(events,['traffic','scheduler_restored','metadata_write','metadata_write'])


class LinkStateTests(unittest.TestCase):
 def invoke(self,d,flags):
  from unittest.mock import MagicMock
  sock=MagicMock();sock.__enter__.return_value=sock;sock.recvfrom.return_value=(struct.pack('=IHHIIi',36,2,0,1,0,0)+bytes(16),(0,0))
  context=(patch.object(sys,'argv',['link.py','eth2','down',str(Path(d)/'cut.json')]),patch.object(link.socket,'socket',return_value=sock),patch.object(link.socket,'if_nametoindex',return_value=2),patch.object(link.Path,'read_text',side_effect=flags))
  return sock,context
 def test_real_transition_ack_and_flags_recorded(self):
  with tempfile.TemporaryDirectory() as d:
   sock,c=self.invoke(d,['0x1','0x0'])
   with c[0],c[1],c[2],c[3]:link.main()
   r=json.loads((Path(d)/'cut.json').read_text());self.assertEqual(r['status'],'acknowledged');self.assertEqual(r['flags_before'],1);self.assertEqual(r['flags_after'],0)
 def test_already_down_does_not_count_as_a_new_cut(self):
  with tempfile.TemporaryDirectory() as d:
   sock,c=self.invoke(d,['0x0'])
   with c[0],c[1],c[2],c[3]:
    with self.assertRaises(RuntimeError):link.main()
   sock.sendto.assert_not_called();self.assertEqual(json.loads((Path(d)/'cut.json').read_text())['status'],'error')
 def test_ack_without_expected_state_is_invalid(self):
  with tempfile.TemporaryDirectory() as d:
   sock,c=self.invoke(d,['0x1','0x1'])
   with c[0],c[1],c[2],c[3]:
    with self.assertRaises(SystemExit):link.main()
   self.assertEqual(json.loads((Path(d)/'cut.json').read_text())['status'],'state_mismatch')
if __name__=='__main__':unittest.main()
