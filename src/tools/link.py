"""Timestamp a link operation in the shared kernel's monotonic clock domain."""
import subprocess, sys, time

def main():
    interface, action, out = sys.argv[1:4]
    before, wall_before = time.monotonic_ns(), time.time_ns()
    subprocess.run(['ip', 'link', 'set', interface, action], check=True)
    after, wall_after = time.monotonic_ns(), time.time_ns()
    with open(out, 'x') as f:
        f.write(f'clock=monotonic\nschema_version=2\nt_before_ns={before}\nt_after_ns={after}\nwall_before_ns={wall_before}\nwall_after_ns={wall_after}\n')

if __name__ == '__main__': main()
