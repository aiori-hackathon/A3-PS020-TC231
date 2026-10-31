"""Offline clock-jump, failure, historical-schema, and UDP-loopback regressions."""
import csv
import importlib.util
import io
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SRC=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SRC)); sys.path.insert(0,str(SRC/'tools')); sys.path.insert(0,str(SRC/'tests'))
from restoration_fixture import write_restoration
import analyze
import analyze_srv6
import analyze_control
import failover

class FakeClock:
    def __init__(self): self.now=10_000_000_000
    def monotonic_ns(self): return self.now
    def select(self,*_): self.now+=500_000
    def time_ns(self): raise AssertionError('detector used wall time')
    def time(self): raise AssertionError('detector used wall time')

class EchoSocket:
    def __init__(self,clock,broken_after=None,wrong_source=False):
        self.clock=clock;self.queue=[];self.broken_after=broken_after;self.wrong_source=wrong_source
    def setblocking(self,*_): pass
    def close(self): pass
    def sendto(self,data,dst):
        if self.broken_after is None or self.clock.now<self.broken_after:
            self.queue.append((bytes([129])+data[1:],('::2' if self.wrong_source else dst[0],0,0,0)))
    def recvfrom(self,*_):
        if not self.queue: raise BlockingIOError
        return self.queue.pop(0)

class DetectorTests(unittest.TestCase):
    def test_confirmation_requires_elapsed_monotonic_time(self):
        d=failover.GapDetector(8,3);d.reply(0)
        self.assertFalse(d.failure(9_000_000,True))
        self.assertFalse(d.failure(11_000_000,True))
        self.assertTrue(d.failure(12_000_000,True))
    def test_reply_cancels_suspicion(self):
        d=failover.GapDetector(8,3);d.reply(0);d.failure(9_000_000,True)
        d.reply(10_000_000)
        self.assertFalse(d.failure(12_000_000,True))
    def test_no_health_no_trigger(self):
        self.assertFalse(failover.GapDetector(8,3).failure(10**12,True))
    def test_unarmed_no_trigger(self):
        d=failover.GapDetector(8,3);d.reply(0)
        self.assertFalse(d.failure(10**12,False))
    def execute(self,broken=False,install_error=False,wrong_source=False):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        out=Path(tmp.name)/'fail.txt'
        clock=FakeClock();sock=EchoSocket(clock,10_550_000_000 if broken else None,wrong_source)
        runner=lambda *args,**kwargs:None
        if install_error:
            def runner(*args,**kwargs):raise subprocess.CalledProcessError(2,args[0])
        args=['failover.py','::1',str(out),'0.7','8','fc00:0:3::1','eth3','3']
        real_install=failover.install_backup
        def install(dst,segs,dev):return real_install(dst,segs,dev,runner)
        with patch.object(failover,'time',clock),patch.object(failover.socket,'socket',return_value=sock),patch.object(failover.select,'select',side_effect=clock.select),patch.object(sys,'argv',args),patch.object(failover,'install_backup',side_effect=install) as installer:
            if install_error:
                with self.assertRaises(subprocess.CalledProcessError):failover.main()
            else:failover.main()
            count=installer.call_count
        return analyze.kv(str(out)),count
    def test_healthy_loop_never_reads_wall_clock_or_switches(self):
        stats,calls=self.execute()
        self.assertEqual(stats['status'],'finished')
        self.assertEqual(stats['switch_count'],'0')
        self.assertEqual(calls,0)
    def test_real_gap_installs_exactly_once(self):
        stats,calls=self.execute(broken=True)
        self.assertEqual(calls,1)
        self.assertEqual(stats['switch_count'],'1')
        self.assertGreaterEqual(int(stats['t_detect_ns']),10_550_000_000)
    def test_policy_error_cannot_be_recorded_as_success(self):
        stats,calls=self.execute(broken=True,install_error=True)
        self.assertEqual(stats['status'],'error')
        self.assertEqual(stats['switch_count'],'0')
        self.assertEqual(stats['t_switched_ns'],'0')

class AnalysisTests(unittest.TestCase):
    def fixture(self,root,mono=True,delay=False):
        prefix='clock=monotonic\n' if mono else ''
        (root/'params.txt').write_text(prefix+'rate=1000\ndur=0.1\n')
        (root/'send.txt').write_text(prefix+'sent=100\nstart_ns=1000000000\nend_ns=1100000000\nsend_errors=0\nwall_start_ns=900000000000\nwall_end_ns=1000000000\n')
        (root/'cut.log').write_text(prefix+'t_before_ns=1040000000\nt_after_ns=1041000000\n')
        with (root/'recv.csv').open('w') as f:
            f.write('seq,t_send_mono_ns,t_recv_mono_ns\n' if mono else 'seq,t_send_ns,t_recv_ns\n')
            for q in range(100):
                if not delay and 40<=q<=44:continue
                tx=10**9+q*10**6;rx=tx+100000+(100_000_000 if delay and q>=40 else 0)
                f.write(f'{q},{tx},{rx}\n')
        (root/'fail.txt').write_text(prefix+'status=finished\nswitch_count=1\nstart_ns=900000000\nend_ns=1200000000\nt_detect_ns=1042000000\nt_switched_ns=1044000000\nt_first_ok_ns=1045000000\n')
        (root/'route_before.txt').write_text('fc00:0:2::1')
        (root/'route_after.txt').write_text('fc00:0:3::1')
        if mono:write_restoration(root,'ok','srv6')
    def test_new_monotonic_metrics_ignore_wall_jumps(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.fixture(root)
            r=analyze.analyze(d)
            self.assertTrue(r['valid']);self.assertEqual(r['lost_at_cut'],5)
            self.assertAlmostEqual(r['recovery_ms'],5.1)
            self.assertNotIn('clock correction',r['note'])
    def test_historical_schema_stays_realtime(self):
        with tempfile.TemporaryDirectory() as d:
            self.fixture(Path(d),False)
            r=analyze.analyze(d)
            self.assertEqual(r['clock'],'realtime');self.assertAlmostEqual(r['recovery_ms'],5.1)
    def test_mixed_send_and_cut_clocks_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.fixture(root)
            p=root/'cut.log';p.write_text(p.read_text().replace('clock=monotonic\n',''))
            r=analyze.analyze(d)
            self.assertFalse(r['valid']);self.assertIn('mixed timestamp',r['note'])
    def test_mixed_receiver_schema_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.fixture(root)
            p=root/'recv.csv';p.write_text(p.read_text().replace('t_send_mono_ns,t_recv_mono_ns','t_send_ns,t_recv_ns'))
            self.assertFalse(analyze.analyze(d)['valid'])
    def test_clock_unknown_rejected(self):
        with self.assertRaises(ValueError):analyze.clock_domain({'clock':'madeup'})
    def test_delay_without_loss_is_reported_as_receiver_gap(self):
        with tempfile.TemporaryDirectory() as d:
            self.fixture(Path(d),delay=True)
            r=analyze.analyze(d)
            self.assertEqual(r['lost_total'],0)
            self.assertGreater(r['max_rx_gap_near_cut_ms'],100)
    def test_mixed_detector_clock_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.fixture(root)
            p=root/'fail.txt';p.write_text(p.read_text().replace('clock=monotonic\n',''))
            with patch.object(sys,'argv',['analyze_srv6.py',d]),patch('sys.stdout',new_callable=io.StringIO) as output:
                self.assertEqual(analyze_srv6.main(),1)
                self.assertIn('mixed',output.getvalue())
    def test_new_detector_run_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            self.fixture(Path(d))
            with patch.object(sys,'argv',['analyze_srv6.py',d]),patch('sys.stdout',new_callable=io.StringIO):
                self.assertEqual(analyze_srv6.main(),0)
    def test_incomplete_control_monitoring_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.fixture(root,delay=True)
            (root/'fail.txt').write_text('clock=monotonic\nstatus=finished\nswitch_count=0\nstart_ns=900000000\nend_ns=1050000000\nt_detect_ns=0\nt_switched_ns=0\n')
            (root/'route_after.txt').write_text('fc00:0:2::1')
            errors,_=analyze_control.analyze_control(d)
            self.assertIn('detector did not cover the complete sender interval',errors)

class ToolClockTests(unittest.TestCase):
    def module(self,name):
        spec=importlib.util.spec_from_file_location('clock_tool_'+name,SRC/'tools'/(name+'.py'))
        m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    def test_sender_payload_and_elapsed_ignore_large_wall_correction(self):
        m=self.module('send')
        class Clock:
            now=1_000_000_000
            wall_calls=0
            def monotonic_ns(self):self.now+=100_000;return self.now
            def time_ns(self):self.wall_calls+=1;return 9_000_000_000_000 if self.wall_calls==1 else 1_000_000_000
            def sleep(self,d):self.now+=int(d*1e9)
        class Sink:
            def __init__(self):self.packets=[]
            def sendto(self,b,*_):self.packets.append(b)
            def close(self):pass
        c=Clock();sink=Sink()
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'send.txt'
            with patch.object(m,'time',c),patch.object(m.socket,'socket',return_value=sink),patch.object(sys,'argv',['send.py','::1','5001','100','.03','64',str(out)]):m.main()
            stats=analyze.kv(str(out))
            self.assertLess(int(stats['wall_end_ns']),int(stats['wall_start_ns']))
            self.assertGreater(int(stats['end_ns']),int(stats['start_ns']))
            self.assertEqual(len(sink.packets),3)
            decoded=[struct.unpack('!8sQQ',p[:24]) for p in sink.packets]
            self.assertTrue(all(p[0]==b'PS020M01' for p in decoded))
            self.assertTrue(all(1_000_000_000 <= p[2] < 2_000_000_000 for p in decoded))
    def test_link_interval_ignores_wall_correction(self):
        m=self.module('link')
        from unittest.mock import Mock
        clock=Mock()
        clock.monotonic_ns.side_effect=[1000000,2000000]
        clock.time_ns.side_effect=[900000000000,1000000000]
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'cut.log'
            with patch.object(m,'time',clock),patch.object(m.subprocess,'run') as run,patch.object(sys,'argv',['link.py','eth2','down',str(out)]):m.main()
            stats=analyze.kv(str(out))
            self.assertEqual(int(stats['t_after_ns'])-int(stats['t_before_ns']),1000000)
            self.assertEqual(stats['clock'],'monotonic')
            run.assert_called_once_with(['ip','link','set','eth2','down'],check=True)

class LocalUDPTests(unittest.TestCase):
    def test_real_ipv6_loopback_new_packet_format(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            try:
                sock=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);sock.bind(('::1',0));port=sock.getsockname()[1];sock.close()
            except OSError as e:self.skipTest(str(e))
            recv=root/'recv.csv';send=root/'send.txt'
            process=subprocess.Popen([sys.executable,str(SRC/'tools/recv.py'),str(port),'30',str(recv)])
            try:
                for _ in range(100):
                    if Path(str(recv)+'.ready').exists():break
                    time.sleep(.01)
                self.assertTrue(Path(str(recv)+'.ready').exists())
                subprocess.run([sys.executable,str(SRC/'tools/send.py'),'::1',str(port),'100','.2','64',str(send)],check=True)
                time.sleep(.1)
                process.terminate()
                self.assertEqual(process.wait(timeout=5),0)
                rows=analyze.load_recv(str(recv))
                self.assertEqual(len(rows),20)
                self.assertTrue(all(rx>=tx for tx,rx in rows.values()))
                self.assertEqual(analyze.recv_clock(str(recv)),'monotonic')
                self.assertEqual(analyze.kv(str(send))['clock'],'monotonic')
            finally:
                if process.poll() is None:process.kill();process.wait()

if __name__=='__main__':unittest.main()
