"""Restoration enforcement: runner (verify_restoration, run_srv6.sh wiring) and every analyzer.
Offline only: stub `docker`, fabricated run folders. No lab, no real results/ touched."""
import io, os, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SRC)); sys.path.insert(0, str(SRC / 'tests'))
import analyze, analyze_control, analyze_srv6, batch_summary, restoration, summary
from restoration_fixture import write_restoration, PING, PING_HDR, ROUTE
from test_aggregation_and_batch import make_run, read_csv, scripts_copy, run

BAD_KINDS = ['wrongpolicy', 'loss20', 'ping_errors', 'short_ping', 'no_stats', 'error_file', 'underlay_B', 'none']


class SrvAnalyzerRejectsFailedRestoration(unittest.TestCase):
    def test_good_restoration_is_valid(self):
        for kind in ('ok', 'busybox'):                     # iputils and busybox ping wording
            with tempfile.TemporaryDirectory() as d:
                r = analyze_srv6.analyze_run(make_run(d + '/r', restored=kind))
                self.assertTrue(r['ok'], (kind, r['bad'])); self.assertFalse(r['restoration_failed'])
                self.assertEqual(r['status'], 'valid')
    def test_every_bad_restoration_makes_the_attempt_invalid(self):
        for kind in BAD_KINDS:
            with tempfile.TemporaryDirectory() as d:
                r = analyze_srv6.analyze_run(make_run(d + '/r', restored=kind))
                self.assertFalse(r['ok'], kind); self.assertEqual(r['status'], 'invalid', kind)
                self.assertTrue(r['restoration_failed'], kind); self.assertIn('RESTORATION FAILED', r['reasons'], kind)
    def test_users_reproduction_wrong_policy_and_20pct_loss(self):
        with tempfile.TemporaryDirectory() as d:
            a = analyze_srv6.analyze_run(make_run(d + '/a', restored='wrongpolicy'))
            b = analyze_srv6.analyze_run(make_run(d + '/b', restored='loss20'))
            self.assertIn('policy A', a['reasons']); self.assertIn('policy B', a['reasons'])
            self.assertIn('20%', b['reasons'])
            self.assertEqual((a['status'], b['status']), ('invalid', 'invalid'))
    def test_restore_error_file_alone_invalidates_standalone_analysis(self):
        with tempfile.TemporaryDirectory() as d:
            run_dir = make_run(d + '/r')
            self.assertEqual(analyze_srv6.analyze_run(run_dir)['status'], 'valid')
            (Path(run_dir) / 'RESTORE_ERROR.txt').write_text('x')
            r = analyze_srv6.analyze_run(run_dir)
            self.assertEqual(r['status'], 'invalid'); self.assertTrue(r['restoration_failed'])
            with patch.object(sys, 'argv', ['analyze_srv6.py', run_dir]), patch('sys.stdout', new_callable=io.StringIO) as o:
                self.assertEqual(analyze_srv6.main(), 1)
            self.assertIn('0/1 runs valid', o.getvalue())
    def test_false_trigger_plus_restoration_failure_stays_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            r = analyze_srv6.analyze_run(make_run(d + '/r', detect=1_030_000_000, restored='loss20'))
            self.assertEqual(r['status'], 'false_trigger'); self.assertTrue(r['restoration_failed']); self.assertFalse(r['ok'])
    def test_missing_evidence_on_new_schema_is_failure_not_pass(self):
        with tempfile.TemporaryDirectory() as d:
            r = analyze_srv6.analyze_run(make_run(d + '/r', restored='none'))
            self.assertFalse(r['ok']); self.assertIn('ping_restored.txt missing', r['reasons'])
    def test_historical_runs_keep_original_analysis(self):
        with tempfile.TemporaryDirectory() as d:
            run_dir = make_run(d + '/old', mono=False)       # realtime, no restoration evidence ever existed
            r = analyze.analyze(run_dir)
            self.assertTrue(r['valid']); self.assertFalse(r['restoration_failed'])
            (Path(run_dir) / 'RESTORE_ERROR.txt').write_text('x')
            r = analyze.analyze(run_dir)
            self.assertFalse(r['valid']); self.assertTrue(r['restoration_failed'])


class StatisticsExcludeFailedRestoration(unittest.TestCase):
    def test_counts_listing_csv_and_n(self):
        with tempfile.TemporaryDirectory() as d:
            runs = [make_run(d + '/ok1'), make_run(d + '/ok2'), make_run(d + '/pol', restored='wrongpolicy'),
                    make_run(d + '/loss', restored='loss20')]
            out = Path(d) / 'o.csv'
            with patch.object(sys, 'argv', ['analyze_srv6.py', *runs, '--csv', str(out)]), patch('sys.stdout', new_callable=io.StringIO) as o:
                rc = analyze_srv6.main()
            t = o.getvalue()
            self.assertEqual(rc, 1)
            self.assertIn('restoration failures (always excluded from statistics): 2', t)
            self.assertIn('statistics over 2 valid run(s)', t)
            self.assertEqual(sum(r['restoration_failed'] == 'True' for r in read_csv(out)), 2)
    def test_even_a_row_wrongly_marked_valid_is_not_used(self):
        rows = [dict(run='x', status='valid', reasons='', suspect=False, clock='monotonic', restoration_failed=True, lost_at_cut=999)]
        lines = []
        summary.summarize(rows, summary.SRV6_METRICS, 'x', out=lines.append)
        self.assertTrue(any('statistics over 0 valid run(s)' in l for l in lines))
    def test_batch_run_with_rc0_but_failed_restoration_is_not_valid(self):
        with tempfile.TemporaryDirectory() as d:
            good, bad = make_run(d + '/g'), make_run(d + '/b', restored='loss20')
            tsv = Path(d) / 'runs.tsv'; tsv.write_text(f'g\t{good}\t0\nb\t{bad}\t0\n')
            with patch('sys.stdout', new_callable=io.StringIO) as o:
                rc = batch_summary.main(['--tsv', str(tsv), '--csv', str(Path(d) / 'b.csv'), '--planned', '2'])
            self.assertEqual(rc, 1)
            self.assertIn('valid 1 |', o.getvalue()); self.assertIn('restoration failures 1', o.getvalue())
            self.assertIn('statistics over 1 valid run(s)', o.getvalue())


class BaselineAndControl(unittest.TestCase):
    def test_baseline_rejects_loss_and_encap_route(self):
        for kind in ('ok', 'loss20', 'error_file'):
            with tempfile.TemporaryDirectory() as d:
                r = make_run(d + '/b'); Path(r, 'trace_before.txt').write_text('2001:db8:a::1'); Path(r, 'trace_after.txt').write_text('2001:db8:b::1')
                write_restoration(r, kind, 'baseline')
                res = analyze.analyze(r, mode='baseline')
                self.assertEqual(res['valid'], kind == 'ok', kind)
        with tempfile.TemporaryDirectory() as d:        # baseline must be back on the ordinary route, not an SR policy
            r = make_run(d + '/b'); Path(r, 'trace_before.txt').write_text('2001:db8:a::1'); Path(r, 'trace_after.txt').write_text('2001:db8:b::1')
            write_restoration(r, 'ok', 'srv6')
            self.assertFalse(analyze.analyze(r, mode='baseline')['valid'])
    def _control(self, d, kind):
        c = Path(make_run(d + '/c'))
        (c / 'cut.log').unlink()
        (c / 'params.txt').write_text('clock=monotonic\nrate=1000\ndur=0.1\nmiss_ms=5\nconfirm_ms=1\n')
        (c / 'send.txt').write_text('clock=monotonic\nsent=100\nstart_ns=1000000000\nend_ns=1100000000\nsend_errors=0\n')
        with (c / 'recv.csv').open('w') as f:
            f.write('seq,t_send_mono_ns,t_recv_mono_ns\n')
            for q in range(100): f.write(f'{q},{10**9+q*10**6},{10**9+q*10**6+1}\n')
        (c / 'fail.txt').write_text('clock=monotonic\nstatus=finished\nstart_ns=900000000\nend_ns=1200000000\nt_detect_ns=0\nt_switched_ns=0\nswitch_count=0\n')
        (c / 'route_after.txt').write_text('fc00:0:2::1')
        for f in ('ping_restored.txt', 'route_restored.txt', 'restore.log', 'underlay_restored.txt'):
            if (c / f).exists(): (c / f).unlink()
        write_restoration(c, kind, 'srv6')
        return str(c)
    def test_control_must_also_restore_cleanly_or_no_marker_is_earned(self):
        with tempfile.TemporaryDirectory() as d:
            errs, _ = analyze_control.analyze_control(self._control(d, 'ok'))
            self.assertEqual(errs, [])
        for kind in ('loss20', 'wrongpolicy', 'error_file'):
            with tempfile.TemporaryDirectory() as d:
                errs, _ = analyze_control.analyze_control(self._control(d, kind))
                self.assertTrue(any('RESTORATION FAILED' in e for e in errs), kind)


class PingParsing(unittest.TestCase):
    def test_exit_status_is_not_enough_only_statistics_count(self):
        self.assertIsNone(restoration.ping_problem(PING_HDR + PING['ok']))
        self.assertIsNone(restoration.ping_problem(PING_HDR + PING['busybox']))
        self.assertIn('20%', restoration.ping_problem(PING_HDR + PING['loss20']))
        self.assertIn('errors', restoration.ping_problem(PING_HDR + PING['ping_errors']))
        self.assertIn('only 1', restoration.ping_problem(PING_HDR + PING['short_ping']))
        self.assertIn('no packet statistics', restoration.ping_problem(PING['no_stats']))
        self.assertIn('missing', restoration.ping_problem(None))
    def test_fractional_loss_is_loss(self):
        self.assertIn('loss', restoration.ping_problem('1000 packets transmitted, 995 received, 0.5% packet loss'))
    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            ok = make_run(d + '/ok'); bad = make_run(d + '/bad', restored='loss20')
            self.assertEqual(restoration.main([ok, '--mode', 'srv6']), 0)
            self.assertEqual(restoration.main([bad, '--mode', 'srv6']), 1)


STUB = r'''#!/usr/bin/env bash
args="$*"
case "$args" in
  *ping*) n=$(cat "$STUB_DIR/pingcount" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$STUB_DIR/pingcount"
          f="$STUB_DIR/ping$n"; [ -f "$f" ] || f="$STUB_DIR/ping_last"; cat "$f"; exit 0;;   # always exit 0, like real ping with partial loss
  *"route show"*) cat "$STUB_DIR/route";;
  *"route get fc00:0:5::d6"*) cat "$STUB_DIR/underlay";;
  *"route get"*) cat "$STUB_DIR/route";;
esac
exit 0
'''

class RunnerEnforcement(unittest.TestCase):
    """verify_restoration is extracted verbatim from run_common.sh and run with a stub docker."""
    def harness(self, t, route='srv6_A', pings=('ok',), underlay='dev eth2', mode='srv6', timeout='0'):
        stub = Path(t) / 'stub'; stub.mkdir()
        (stub / 'route').write_text(ROUTE[route]); (stub / 'underlay').write_text(f'fc00:0:5::d6 via fe80::1 {underlay} proto ospf\n')
        for i, k in enumerate(pings, 1): (stub / f'ping{i}').write_text(PING_HDR + PING[k])
        (stub / 'ping_last').write_text(PING_HDR + PING[pings[-1]])
        bindir = Path(t) / 'bin'; bindir.mkdir(); (bindir / 'docker').write_text(STUB); (bindir / 'docker').chmod(0o755)
        out = Path(t) / 'out'; out.mkdir(); (out / 'restore.log').write_text('clock=monotonic\nt_before_ns=1\nt_after_ns=2\n')
        (out / 'params.txt').write_text('clock=monotonic\n')
        fn = subprocess.run(['sed', '-n', '/^verify_restoration() {/,/^}/p', str(SRC / 'run_common.sh')], capture_output=True, text=True).stdout
        self.assertIn('verify_restoration', fn)
        script = f'set -uo pipefail\ncd {SRC}\nOUT={out}; R1=r1; H1=h1\n{fn}\nverify_restoration {mode}\necho rc=$?\n'
        env = dict(os.environ, PATH=f'{bindir}:{os.environ["PATH"]}', STUB_DIR=str(stub),
                   PS020_RESTORE_TIMEOUT=timeout, PS020_RESTORE_POLL_S='0')
        p = subprocess.run(['bash', '-c', script], env=env, capture_output=True, text=True, timeout=30)
        return p, out
    def test_clean_restoration_passes_and_writes_no_error(self):
        with tempfile.TemporaryDirectory() as t:
            p, out = self.harness(t)
            self.assertIn('rc=0', p.stdout); self.assertFalse((out / 'RESTORE_ERROR.txt').exists())
    def test_ping_exit_zero_with_partial_loss_still_fails(self):
        with tempfile.TemporaryDirectory() as t:
            p, out = self.harness(t, pings=('loss20',))
            self.assertIn('rc=1', p.stdout)
            err = (out / 'RESTORE_ERROR.txt').read_text(); self.assertIn('20%', err)
            self.assertTrue((out / 'ping_restored_try1.txt').exists())
    def test_wrong_restored_policy_fails(self):
        with tempfile.TemporaryDirectory() as t:
            p, out = self.harness(t, route='srv6_B')
            self.assertIn('rc=1', p.stdout); self.assertIn('policy A', (out / 'RESTORE_ERROR.txt').read_text())
    def test_underlay_not_on_A_fails(self):
        with tempfile.TemporaryDirectory() as t:
            p, out = self.harness(t, underlay='dev eth3')
            self.assertIn('rc=1', p.stdout); self.assertIn('Path A', (out / 'RESTORE_ERROR.txt').read_text())
    def test_baseline_mode_rejects_encap_route(self):
        with tempfile.TemporaryDirectory() as t:
            p, out = self.harness(t, route='srv6_A', mode='baseline')
            self.assertIn('rc=1', p.stdout)
        with tempfile.TemporaryDirectory() as t:
            p, out = self.harness(t, route='plain', mode='baseline')
            self.assertIn('rc=0', p.stdout)
    def test_retries_only_while_converging_and_keeps_every_failed_attempt(self):
        with tempfile.TemporaryDirectory() as t:
            p, out = self.harness(t, pings=('loss20', 'loss20', 'ok'), timeout='30')
            self.assertIn('rc=0', p.stdout); self.assertFalse((out / 'RESTORE_ERROR.txt').exists())
            self.assertTrue((out / 'ping_restored_try1.txt').exists() and (out / 'ping_restored_try2.txt').exists())
            self.assertIn('0% packet loss', (out / 'ping_restored.txt').read_text())
    def test_persistent_failure_gives_up_at_the_timeout(self):
        with tempfile.TemporaryDirectory() as t:
            p, out = self.harness(t, pings=('loss20',), timeout='1')
            self.assertIn('rc=1', p.stdout); self.assertTrue((out / 'RESTORE_ERROR.txt').exists())


RUN_STUB = r'''#!/usr/bin/env bash
args="$*"; echo "$args" >> "$STUB_LOG"
case "$args" in
  cp*restore.log*) printf 'clock=monotonic\nt_before_ns=1\nt_after_ns=2\n' > "${@: -1}"; exit 0;;   # like docker cp of link.py's log
  *ping*"-c 5"*) cat "$STUB_DIR/ping"; exit 0;;
  *"route show"*) echo "2001:db8:b::2 encap seg6 mode encap segs 2 [ fc00:0:2::1 fc00:0:5::d6 ] dev eth2";;
  *"route get"*) echo "fc00:0:5::d6 via fe80::1 dev eth2";;
esac
exit 0
'''

class RunnerWiring(unittest.TestCase):
    """run_srv6.sh really calls the enforcement and surfaces failure (stubbed lab, --no-cut = fast)."""
    def go(self, ping_kind):
        t = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__('shutil').rmtree(t, ignore_errors=True))
        dst, env = scripts_copy(t)
        (dst / 'tools').mkdir()
        stub = Path(t) / 'stub'; stub.mkdir(); (stub / 'ping').write_text(PING_HDR + PING[ping_kind])
        (Path(t) / 'bin' / 'docker').write_text(RUN_STUB)
        env['STUB_DIR'] = str(stub)
        p = run(['bash', 'run_srv6.sh', 'w1', '--no-cut'], dst, env)
        return p, dst / 'results/srv6-control-monotonic/runw1'
    def test_partial_loss_after_restore_writes_error_and_fails_the_runner(self):
        p, out = self.go('loss20')
        self.assertNotEqual(p.returncode, 0)
        self.assertTrue((out / 'RESTORE_ERROR.txt').exists(), p.stdout + p.stderr)
        self.assertIn('RESTORATION FAILED', p.stdout)
        self.assertFalse((out.parents[2] / 'control_markers').exists())     # no control marker earned
    def test_clean_restore_writes_no_error(self):
        p, out = self.go('ok')
        self.assertFalse((out / 'RESTORE_ERROR.txt').exists(), p.stdout + p.stderr)
        self.assertEqual((out / 'ping_restored.txt').read_text().count('0% packet loss'), 1)


if __name__ == '__main__':
    unittest.main()
