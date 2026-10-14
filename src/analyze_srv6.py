#!/usr/bin/env python3
"""Usage: python3 analyze_srv6.py <run folders...>   (reuses analyze.py for loss/interruption)"""
import os, statistics as st, sys
from analyze import analyze, kv

def txt(p):
    try:
        return open(p).read()
    except OSError:
        return ""

def main():
    runs = [a for a in sys.argv[1:] if os.path.isdir(a)]
    if not runs:
        sys.exit("give run folders")
    res = []
    for run in runs:
        r = analyze(run)
        if "lost_total" not in r:
            print(f"{run}: SKIPPED - {r['note']}")
            continue
        bad = []
        f, c = kv(run + "/fail.txt"), kv(run + "/cut.log")
        det = swc = None
        try:
            tc = (int(c["t_before_ns"]) + int(c["t_after_ns"])) // 2
            td, ts = int(f["t_detect_ns"]), int(f["t_switched_ns"])
            if td == 0:
                bad.append("probe never detected the failure")
            else:
                det, swc = (td - tc) / 1e6, (ts - td) / 1e6
                if det < 0:
                    bad.append("probe fired BEFORE the cut (false trigger)")
        except KeyError:
            bad.append("fail.txt or cut.log missing")
        if "fc00:0:2::1" not in txt(run + "/route_before.txt"):
            bad.append("policy A not in place before the cut")
        if "fc00:0:3::1" not in txt(run + "/route_after.txt"):
            bad.append("policy B not in place after the cut")
        if r["note"] and "did NOT change" in r["note"]:
            bad.append(r["note"])
        r.update(det=det, swc=swc, ok=(r["valid"] and not bad), bad="; ".join(bad))
        res.append(r)
        d = "n/a" if det is None else f"{det:.1f} ms"
        s = "n/a" if swc is None else f"{swc:.1f} ms"
        rec = "n/a" if r["recovery_ms"] is None else f"{r['recovery_ms']:.1f} ms"
        print(f"{run}: {'VALID' if r['ok'] else 'INVALID - ' + r['bad']}")
        print(f"   lost@cut={r['lost_at_cut']}  interruption={r['interruption_ms']:.1f} ms (resolution {r['iv_ms']:.1f} ms)"
              f"  detection delay={d}  switch cmd={s}  first delivery after cut={rec}")
    ok = [r for r in res if r["ok"]]
    print(f"\n{len(ok)}/{len(res)} runs valid")
    for key, label in (("lost_at_cut", "packets lost"), ("interruption_ms", "interruption ms"),
                       ("det", "detection delay ms"), ("swc", "switch cmd ms"), ("recovery_ms", "first delivery after cut ms")):
        v = [r[key] for r in ok if r.get(key) is not None]
        if len(v) > 1:
            print(f"  {label} (n={len(v)}): mean {st.mean(v):.2f}  std {st.stdev(v):.2f}  min {min(v):.2f}  max {max(v):.2f}")
        elif v:
            print(f"  {label} (n=1): {v[0]:.2f}")

if __name__ == "__main__":
    main()
