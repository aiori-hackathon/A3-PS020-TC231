import subprocess, sys, time
ifc, act, out = sys.argv[1:4]
t0 = time.time_ns()
subprocess.run(['ip', 'link', 'set', ifc, act], check=True)
t1 = time.time_ns()
open(out, 'w').write('t_before_ns=%d\nt_after_ns=%d\n' % (t0, t1))
