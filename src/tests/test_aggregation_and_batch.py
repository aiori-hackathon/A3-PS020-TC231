"""Offline tests for detector params, control markers, run_batch.sh, aggregation, suspect flag,
t_before zero point and the plot. Scripts run in a temp copy with a stub `docker`; the real
results/, evidence/ and pcaps/ are never touched. No lab is used."""
import csv, io, os, shutil, stat, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SRC)); sys.path.insert(0, str(SRC / 'tests'))
import analyze, analyze_srv6, batch_summary, summary
from restoration_fixture import write_restoration

def make_run(root, detect=1_042_000_000, late_us=500, mono=True, ok_route=True, cut=(1_040_000_000, 1_041_000_000), restored='ok'):
    root = Path(root); root.mkdir(parents=True, exist_ok=True)
    pre = 'clock=monotonic\n' if mono else ''
    (root/'params.txt').write_text(pre+'rate=1000\ndur=0.1\nmiss_ms=5\nconfirm_ms=1\n')
    (root/'send.txt').write_text(pre+f'sent=100\nstart_ns=1000000000\nend_ns=1100000000\nsend_errors=0\nmax_late_us={late_us}\n')
    (root/'cut.log').write_text(pre+f't_before_ns={cut[0]}\nt_after_ns={cut[1]}\n')
    with (root/'recv.csv').open('w') as f:
        f.write('seq,t_send_mono_ns,t_recv_mono_ns\n' if mono else 'seq,t_send_ns,t_recv_ns\n')
        for q in range(100):
            if 40 <= q <= 44: continue
            tx = 10**9+q*10**6; f.write(f'{q},{tx},{tx+100000}\n')
    (root/'fail.txt').write_text(pre+f'status=finished\nswitch_count=1\nstart_ns=900000000\nend_ns=1200000000\nt_detect_ns={detect}\nt_switched_ns={detect+2_000_000}\nt_first_ok_ns={detect+3_000_000}\n')
    (root/'route_before.txt').write_text('fc00:0:2::1')
    (root/'route_after.txt').write_text('fc00:0:3::1' if ok_route else 'fc00:0:2::1')
    if mono: write_restoration(root, restored, 'srv6')
    return str(root)

def read_csv(path):
    with open(path, newline='') as f:
        return list(csv.DictReader(f))

class ZeroPointAndSuspect(unittest.TestCase):
    def test_detection_delay_uses_t_before_and_uncertainty_reported(self):
        with tempfile.TemporaryDirectory() as d:
            r = analyze_srv6.analyze_run(make_run(d + '/r'))
            self.assertTrue(r['ok'])
            self.assertAlmostEqual(r['detect_ms'], 2.0)         # 1_042_000_000 - 1_040_000_000, NOT the midpoint
            self.assertAlmostEqual(r['cut_uncertainty_ms'], 1.0)
            self.assertAlmostEqual(r['recovery_ms'], 5.1)       # same zero point as before
    def test_false_trigger_is_classified(self):
        with tempfile.TemporaryDirectory() as d:
            r = analyze_srv6.analyze_run(make_run(d + '/r', detect=1_030_000_000))
            self.assertEqual(r['status'], 'false_trigger'); self.assertLess(r['detect_ms'], 0)
    def test_other_invalid_has_reason(self):
        with tempfile.TemporaryDirectory() as d:
            r = analyze_srv6.analyze_run(make_run(d + '/r', ok_route=False))
            self.assertEqual(r['status'], 'invalid'); self.assertIn('policy B not in place', r['reasons'])
    def test_suspect_threshold_default_and_configurable(self):
        with tempfile.TemporaryDirectory() as d:
            run = make_run(d + '/r', late_us=2500)
            self.assertTrue(analyze.analyze(run)['suspect'])                   # 2.5 ms > default 2 ms
            self.assertFalse(analyze.analyze(run, max_late_ms=3)['suspect'])
            r = analyze.analyze(run); self.assertTrue(r['valid']); self.assertIn('suspect', r['note'])
            self.assertFalse(analyze.analyze(make_run(d + '/ok', late_us=2000))['suspect'])  # equal is not above
    def test_missing_max_late_is_unknown_not_suspect(self):
        with tempfile.TemporaryDirectory() as d:
            run = make_run(d + '/r'); p = Path(run) / 'send.txt'
            p.write_text(p.read_text().replace('max_late_us=500\n', ''))
            r = analyze.analyze(run); self.assertIsNone(r['max_late_us']); self.assertFalse(r['suspect'])

class SummaryTests(unittest.TestCase):
    def test_describe(self):
        d = summary.describe(list(range(1, 11)))
        self.assertEqual(d['n'], 10); self.assertAlmostEqual(d['median'], 5.5)
        self.assertAlmostEqual(d['p95'], 9.55); self.assertEqual((d['min'], d['max']), (1, 10))
        self.assertAlmostEqual(d['std'], 3.0276503540974917)
        self.assertEqual(summary.describe([]), {'n': 0}); self.assertIsNone(summary.describe([4])['std'])
    def test_counts_listed_and_csv_includes_invalid(self):
        with tempfile.TemporaryDirectory() as d:
            runs = [make_run(d + '/ok1'), make_run(d + '/ok2', late_us=9000), make_run(d + '/ft', detect=1_030_000_000),
                    make_run(d + '/bad', ok_route=False)]
            (Path(d) / 'empty').mkdir()
            out = Path(d) / 'all.csv'
            with patch.object(sys, 'argv', ['analyze_srv6.py', *runs, d + '/empty', '--csv', str(out)]), \
                 patch('sys.stdout', new_callable=io.StringIO) as o:
                rc = analyze_srv6.main()
            text = o.getvalue()
            self.assertEqual(rc, 1)
            self.assertIn('runs: total 5 | valid 2 | false triggers 1 | other invalid 2', text)
            self.assertIn('false trigger:', text); self.assertIn('policy B not in place', text)
            self.assertIn('unanalysable:', text); self.assertIn('suspect sender lateness (> 2 ms): 1 run(s)', text)
            for w in ('median', 'p95', 'min', 'max', 'std', 'detection delay ms', 'cut-command uncertainty'):
                self.assertIn(w, text)
            rows = read_csv(out)
            self.assertEqual(len(rows), 5)
            self.assertEqual(sorted(r['status'] for r in rows), ['false_trigger', 'invalid', 'skipped', 'valid', 'valid'])
    def test_exclude_suspect_changes_n(self):
        with tempfile.TemporaryDirectory() as d:
            runs = [make_run(d + '/a'), make_run(d + '/b', late_us=9000)]
            lines = []
            rows = [analyze_srv6.analyze_run(r) for r in runs]
            summary.summarize(rows, summary.SRV6_METRICS, 'x', exclude_suspect=True, out=lines.append)
            self.assertTrue(any('over 1 valid run' in l and 'suspect excluded' in l for l in lines))
    def test_mixed_clock_aggregate_refused_no_numbers(self):
        with tempfile.TemporaryDirectory() as d:
            runs = [make_run(d + '/new'), make_run(d + '/old', mono=False)]
            out = Path(d) / 'm.csv'
            with patch.object(sys, 'argv', ['analyze_srv6.py', *runs, '--csv', str(out)]), \
                 patch('sys.stdout', new_callable=io.StringIO) as o:
                self.assertEqual(analyze_srv6.main(), 1)
            self.assertIn('aggregate comparison refused', o.getvalue()); self.assertNotIn('median', o.getvalue())
            self.assertFalse(out.exists())
    def test_baseline_same_format_and_no_false_trigger_category(self):
        with tempfile.TemporaryDirectory() as d:
            runs = [make_run(d + '/b1'), make_run(d + '/b2')]
            for r in runs: Path(r, 'trace_before.txt').write_text('2001:db8:a::1'); Path(r, 'trace_after.txt').write_text('2001:db8:b::1'); write_restoration(r, 'ok', 'baseline')
            out = Path(d) / 'b.csv'
            with patch.object(sys, 'argv', ['analyze.py', *runs, '--csv', str(out)]), patch('sys.stdout', new_callable=io.StringIO) as o:
                self.assertEqual(analyze.main(), 0)
            t = o.getvalue()
            self.assertIn('runs: total 2 | valid 2 | false triggers n/a (no detector) | other invalid 0', t)
            for w in ('median', 'p95', 'std', 'cut-command uncertainty'): self.assertIn(w, t)
            self.assertEqual({r['scenario'] for r in read_csv(out)}, {'baseline'})
    def test_baseline_invalid_listed_with_reason(self):
        with tempfile.TemporaryDirectory() as d:
            r = make_run(d + '/b'); Path(r, 'trace_before.txt').write_text('2001:db8:a::1'); Path(r, 'trace_after.txt').write_text('2001:db8:a::1'); write_restoration(r, 'ok', 'baseline')
            with patch.object(sys, 'argv', ['analyze.py', r]), patch('sys.stdout', new_callable=io.StringIO) as o:
                self.assertEqual(analyze.main(), 1)
            self.assertIn('other invalid 1', o.getvalue()); self.assertIn('did NOT change', o.getvalue())

STUB_DOCKER = '#!/usr/bin/env bash\n# stub: underlay probe succeeds unless $STUB_UNDERLAY=B\nargs="$*"\n' \
    'echo "$args" >> "$STUB_LOG"\ncase "$args" in\n *"route get"*) [ "${STUB_UNDERLAY:-A}" = A ] && echo "dev eth2";;\n *"route show"*) echo "fc00:0:2::1 fc00:0:3::1";;\nesac\nexit 0\n'

def scripts_copy(tmp):
    dst = Path(tmp) / 'src'; dst.mkdir()
    for n in ('run_srv6.sh', 'run_common.sh', 'run_params.sh', 'run_batch.sh', 'batch_summary.py', 'analyze.py',
              'analyze_srv6.py', 'analyze_control.py', 'summary.py', 'restoration.py'):
        shutil.copy(SRC / n, dst / n)
    (dst / 'results').mkdir()
    (dst / 'srv6_policy.sh').write_text('#!/usr/bin/env bash\nexit 0\n')   # no-op stand-in for the real policy script
    bindir = Path(tmp) / 'bin'; bindir.mkdir()
    (bindir / 'docker').write_text(STUB_DOCKER); (bindir / 'docker').chmod(0o755)
    env = dict(os.environ, PATH=f'{bindir}:{os.environ["PATH"]}', STUB_LOG=str(Path(tmp) / 'docker.log'),
               PS020_POLL_S='0', PS020_RESTORE_TIMEOUT='0', PS020_RESTORE_POLL_S='0')
    return dst, env

def run(cmd, cwd, env, **kw):
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=60, **kw)

class ParamTests(unittest.TestCase):
    def test_invalid_values_rejected_before_any_docker_or_folder(self):
        with tempfile.TemporaryDirectory() as t:
            dst, env = scripts_copy(t)
            for args in (['--miss-ms', 'abc'], ['--miss-ms', '0'], ['--confirm-ms', '-1'], ['--miss-ms'], ['--confirm-ms=1e3']):
                p = run(['bash', 'run_srv6.sh', 'x', *args], dst, env)
                self.assertEqual(p.returncode, 2, args)
            self.assertEqual(list((dst / 'results').iterdir()), [])
            self.assertFalse(Path(env['STUB_LOG']).exists())
    def params_for(self, args, extra_env=None):
        with tempfile.TemporaryDirectory() as t:
            dst, env = scripts_copy(t); env.update(extra_env or {})
            (dst / 'tools').mkdir()   # run_common copies tools; the stub docker ignores it
            run(['bash', 'run_srv6.sh', 'p1', *args], dst, env)   # later steps fail with the stub; params.txt exists by then
            txt = (dst / 'results/srv6-monotonic/runp1/params.txt').read_text()
            return txt, Path(env['STUB_LOG']).read_text()
    def test_defaults_are_8_and_3(self):
        txt, log = self.params_for([])
        self.assertIn('miss_ms=8\nconfirm_ms=3\n', txt)
    def test_flags_and_env_override_flags_win(self):
        txt, log = self.params_for(['--miss-ms', '5', '--confirm-ms=1'])
        self.assertIn('miss_ms=5\nconfirm_ms=1\n', txt)
        txt, _ = self.params_for([], {'MISS_MS': '6', 'CONFIRM_MS': '2'}); self.assertIn('miss_ms=6\nconfirm_ms=2\n', txt)
        txt, _ = self.params_for(['--miss-ms', '5'], {'MISS_MS': '6'}); self.assertIn('miss_ms=5\n', txt)
    def test_detector_gets_the_overridden_values(self):
        _, log = self.params_for(['--miss-ms', '5', '--confirm-ms', '1'])
        det = [l for l in log.splitlines() if 'failover.py' in l]
        self.assertTrue(det and det[0].endswith('eth3 1') and ' 5 fc00:0:3::1' in det[0], det)

class BatchTests(unittest.TestCase):
    def setup_batch(self, t, fake_rc, marker=True, control_ok=True):
        dst, env = scripts_copy(t)
        # fake runner: creates a run folder from the fixture and exits with the scripted code
        fake = ('#!/usr/bin/env bash\nid=$1; n=${id##*_}; n=$((10#$n))\n'
                'python3 - "$id" "$n" <<PY\nimport sys; sys.path.insert(0, "' + str(SRC / 'tests') + '")\n'
                'from test_aggregation_and_batch import make_run\nid, n = sys.argv[1], int(sys.argv[2])\n'
                'mode = {k: v for k, v in [' + ','.join(f'({i},"{m}")' for i, m in fake_rc.items()) + ']}.get(n, "ok")\n'
                'kw = {"detect": 1_030_000_000} if mode == "ft" else {}\n'
                'if mode != "crash": make_run("results/srv6-monotonic/run" + id, **kw)\nPY\n'
                '[ "$(python3 -c \'print(1)\')" = 1 ] && n2=$n\ncase "$n" in '
                + ' '.join(f'{i}) exit {0 if m=="ok" else 1};;' for i, m in fake_rc.items()) + ' *) exit 0;; esac\n')
        (dst / 'run_srv6.sh').write_text(fake)
        if marker:
            ctl = make_run(dst / 'results/srv6-control-monotonic/runc1')
            # control fixture: rewrite as a passing no-cut control
            c = Path(ctl); (c / 'cut.log').unlink()
            (c / 'params.txt').write_text('clock=monotonic\nrate=1000\ndur=0.1\nmiss_ms=5\nconfirm_ms=1\n')
            (c / 'send.txt').write_text('clock=monotonic\nsent=100\nstart_ns=1000000000\nend_ns=1100000000\nsend_errors=0\n')
            with (c / 'recv.csv').open('w') as f:
                f.write('seq,t_send_mono_ns,t_recv_mono_ns\n')
                for q in range(100): f.write(f'{q},{10**9+q*10**6},{10**9+q*10**6+1}\n')
            (c / 'fail.txt').write_text('clock=monotonic\nstatus=finished\nstart_ns=900000000\nend_ns=1200000000\nt_detect_ns=0\nt_switched_ns=0\nswitch_count=0\n')
            (c / 'route_after.txt').write_text('fc00:0:2::1')
            write_restoration(c, 'ok', 'srv6')
            if not control_ok: (c / 'fail.txt').write_text((c / 'fail.txt').read_text().replace('t_detect_ns=0', 't_detect_ns=5'))
            (dst / 'run_params.sh').write_text((dst / 'run_params.sh').read_text())
            p = run(['bash', '-c', 'source ./run_params.sh; write_control_marker results/srv6-control-monotonic/runc1 5 1'], dst, env)
            self.assertEqual(p.returncode, 0, p.stderr)
        return dst, env
    def test_refuses_without_control_marker(self):
        with tempfile.TemporaryDirectory() as t:
            dst, env = self.setup_batch(t, {}, marker=False)
            p = run(['bash', 'run_batch.sh', '-n', '2', '--prefix', 'b', '--miss-ms', '5', '--confirm-ms', '1'], dst, env)
            self.assertEqual(p.returncode, 3); self.assertIn('No passed no-cut control', p.stdout)
            self.assertFalse((dst / 'batches').exists())
    def test_refuses_when_marker_is_for_other_settings(self):
        with tempfile.TemporaryDirectory() as t:
            dst, env = self.setup_batch(t, {})
            p = run(['bash', 'run_batch.sh', '-n', '2', '--prefix', 'b', '--miss-ms', '8', '--confirm-ms', '3'], dst, env)
            self.assertEqual(p.returncode, 3)
    def test_refuses_when_control_no_longer_passes(self):
        with tempfile.TemporaryDirectory() as t:
            dst, env = self.setup_batch(t, {}, control_ok=False)
            p = run(['bash', 'run_batch.sh', '-n', '2', '--prefix', 'b', '--miss-ms', '5', '--confirm-ms', '1'], dst, env)
            self.assertEqual(p.returncode, 3); self.assertIn('no longer passes', p.stdout)
    def test_continues_after_failures_and_writes_summary(self):
        with tempfile.TemporaryDirectory() as t:
            dst, env = self.setup_batch(t, {2: 'ft', 3: 'crash'})
            p = run(['bash', 'run_batch.sh', '-n', '4', '--prefix', 'b', '--miss-ms', '5.0', '--confirm-ms', '1'], dst, env)
            self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
            self.assertIn('valid 2 | false triggers 1 | failures 1', p.stdout)
            rows = read_csv(dst / 'batches/b/batch_summary.csv')
            self.assertEqual([r['run'] for r in rows], ['b_01', 'b_02', 'b_03', 'b_04'])
            self.assertEqual([r['batch_status'] for r in rows], ['valid', 'false_trigger', 'failed', 'valid'])
            self.assertEqual({r['miss_ms'] for r in rows if r['miss_ms']}, {'5'})
    def test_all_valid_batch_exits_zero_and_refuses_reuse(self):
        with tempfile.TemporaryDirectory() as t:
            dst, env = self.setup_batch(t, {})
            a = ['bash', 'run_batch.sh', '-n', '3', '--prefix', 'ok', '--miss-ms', '5', '--confirm-ms', '1']
            p = run(a, dst, env); self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertIn('valid 3 | false triggers 0 | failures 0', p.stdout)
            self.assertEqual(run(a, dst, env).returncode, 4)       # run folders now exist: refused
    def test_underlay_never_on_A_stops_batch_and_still_summarizes(self):
        with tempfile.TemporaryDirectory() as t:
            dst, env = self.setup_batch(t, {}); env['STUB_UNDERLAY'] = 'B'
            p = run(['bash', 'run_batch.sh', '-n', '2', '--prefix', 'u', '--miss-ms', '5', '--confirm-ms', '1', '--underlay-timeout', '0'], dst, env)
            self.assertEqual(p.returncode, 1); self.assertIn('BATCH STOPPED EARLY', p.stdout)
            self.assertIn('0 of 2 planned', p.stdout)

class MarkerTests(unittest.TestCase):
    def test_marker_write_and_invalidate(self):
        with tempfile.TemporaryDirectory() as t:
            dst, env = scripts_copy(t)
            cmd = 'source ./run_params.sh; write_control_marker some/dir 5 1; cat "$(control_marker_path 5 1)"; invalidate_control_marker 5 1; ls control_markers'
            p = run(['bash', '-c', cmd], dst, env)
            self.assertIn('control_run=some/dir', p.stdout); self.assertIn('miss_ms=5', p.stdout)
            self.assertNotIn('.pass', p.stdout.split('passed_utc')[1])

class PlotTest(unittest.TestCase):
    def test_plot_written_and_not_overwritten(self):
        import plot_runs
        with tempfile.TemporaryDirectory() as d:
            s = [make_run(d + '/s1'), make_run(d + '/s2', detect=1_030_000_000)]
            b = [make_run(d + '/b1')]; Path(b[0], 'trace_before.txt').write_text('a::1'); Path(b[0], 'trace_after.txt').write_text('b::1')
            out = Path(d) / 'f.png'
            plot_runs.main(['--srv6', *s, '--baseline', *b, '--out', str(out)])
            self.assertTrue(out.read_bytes().startswith(b'\x89PNG'))
            with self.assertRaises(SystemExit): plot_runs.main(['--srv6', *s, '--out', str(out)])

if __name__ == '__main__': unittest.main()
