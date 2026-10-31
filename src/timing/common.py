"""Small helpers shared by the container processes. Every interval uses monotonic_ns."""
import json, os, signal, time
from pathlib import Path

def write_json(path, data):
    with open(path, 'x') as f:
        json.dump(data, f, indent=2); f.write('\n')

def register(out):
    Path(str(out)+'.pid').write_text(str(os.getpid()))

def clock_identity():
    p=Path('/proc/self/timens_offsets')
    return dict(boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                time_offsets=p.read_text().strip() if p.exists() else 'not-supported',
                monotonic_ns=time.monotonic_ns())

def stop(directory):
    # Only signal a helper whose live argv still contains this unique experiment directory.
    root=Path(directory)
    for p in root.rglob('*.pid'):
        try:
            pid=int(p.read_text());cmd=Path(f'/proc/{pid}/cmdline').read_bytes()
            if str(root).encode() in cmd: os.kill(pid,signal.SIGTERM)
        except (OSError,ValueError): pass

if __name__=='__main__':
    import sys
    if sys.argv[1]=='clock': print(json.dumps(clock_identity()))
    elif sys.argv[1]=='stop': stop(sys.argv[2])
