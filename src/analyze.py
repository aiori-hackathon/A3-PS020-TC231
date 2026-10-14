#!/usr/bin/env python3
"""PS-020 analyzer (simple). Usage: python3 analyze.py <run folders...> [--csv out.csv]
A trailing word like 'baseline' (as run_baseline.sh passes it) is ignored."""
import bisect, csv, os, re, statistics as st, sys

WIN_BEFORE_MS, WIN_AFTER_MS = 10, 500

def kv(path):
    d = {}
    try:
        for line in open(path):
            m = re.match(r'\s*([A-Za-z_]\w*)\s*[=:]?\s*([-+\w.]+)', line)
            if m:
                d[m.group(1).lower()] = m.group(2)
    except OSError:
        pass
    return d

def load_recv(path):
    rows = {}
    try:
        for r in csv.reader(open(path)):
            try:
                rows.setdefault(int(r[0]), (int(r[1]), int(r[2])))
            except (ValueError, IndexError):
                pass
    except OSError:
        pass
    return rows

def hops(path):
    try:
        return set(re.findall(r'([0-9a-f]*:[0-9a-f:]+)', open(path).read()))
    except OSError:
        return None

def analyze(run):
    r = dict(run=run, valid=False, note="")
    p, s, c = kv(run + "/params.txt"), kv(run + "/send.txt"), kv(run + "/cut.log")
    try:
        rate, dur = float(p["rate"]), float(p["dur"])
        sent, t_cut = int(s["sent"]), int(c["t_before_ns"])
        start, end = int(s["start_ns"]), int(s["end_ns"])
    except KeyError as e:
        r["note"] = f"missing {e}"
        return r
    recv = load_recv(run + "/recv.csv")
    if len(recv) < 2:
        r["note"] = "recv.csv empty"
        return r
    iv_ns, iv_ms = int(1e9 / rate), 1000.0 / rate
    seqs = sorted(recv)

    def est(q):   # estimated send time of seq q, from the nearest received packet
        i = bisect.bisect_left(seqs, q)
        n = seqs[min(i, len(seqs) - 1)]
        return recv[n][0] + (q - n) * iv_ns

    lost = sorted(set(range(sent)) - set(recv))
    lo, hi = t_cut - WIN_BEFORE_MS * 10**6, t_cut + WIN_AFTER_MS * 10**6
    bursts = []
    for q in lost:
        if bursts and q == bursts[-1][1] + 1:
            bursts[-1][1] = q
        else:
            bursts.append([q, q])
    inwin = [b for b in bursts if lo <= est(b[0]) <= hi]
    lost_cut = sum(b[1] - b[0] + 1 for b in inwin)
    interruption, recovery = 0.0, None
    if inwin:
        b = max(inwin, key=lambda b: b[1] - b[0])
        interruption = (b[1] - b[0] + 1) * iv_ms
        i = bisect.bisect_right(seqs, b[1])
        if i < len(seqs):
            recovery = (recv[seqs[i]][1] - t_cut) / 1e6

    dl = lambda q: (recv[q][1] - recv[q][0]) / 1e6
    pre = [dl(q) for q in seqs if start + 10**9 <= recv[q][0] <= t_cut - 3 * 10**8]
    near = [dl(q) for q in seqs if lo <= recv[q][0] <= hi]
    spike = (max(near) - (st.median(pre) if pre else 0.0)) if near else 0.0

    hb, ha = hops(run + "/trace_before.txt"), hops(run + "/trace_after.txt")
    changed = None if hb is None or ha is None else hb != ha
    notes = []
    if changed is False:
        notes.append("traceroute path did NOT change: the cut had no effect on this traffic")
    if abs((end - start) / 1e9 - dur) > 0.2:
        notes.append(f"wall-clock run length {(end - start) / 1e9:.2f}s vs dur {dur:.0f}s (clock step; loss counts still fine)")
    if not inwin:
        notes.append("no loss at the cut")
    r.update(valid=(changed is not False), note="; ".join(notes), lost_total=len(lost),
             lost_at_cut=lost_cut, interruption_ms=interruption, iv_ms=iv_ms,
             recovery_ms=recovery, spike_ms=spike)
    return r

def main():
    args = sys.argv[1:]
    out = None
    if "--csv" in args:
        i = args.index("--csv")
        out = args[i + 1]
        del args[i:i + 2]
    runs = [a for a in args if os.path.isdir(a)]
    if not runs:
        sys.exit("give at least one run folder")
    res = [analyze(r) for r in runs]
    for r in res:
        if "lost_total" not in r:
            print(f"{r['run']}: SKIPPED - {r['note']}")
            continue
        rec = "n/a" if r["recovery_ms"] is None else f"{r['recovery_ms']:.1f} ms"
        print(f"{r['run']}: {'VALID' if r['valid'] else 'INVALID'}  lost@cut={r['lost_at_cut']}  "
              f"interruption={r['interruption_ms']:.1f} ms (resolution {r['iv_ms']:.1f} ms)  "
              f"first delivery after cut={rec}  delay spike near cut={r['spike_ms']:.1f} ms")
        if r["note"]:
            print("   note:", r["note"])
    ok = [r for r in res if r.get("valid")]
    print(f"\n{len(ok)}/{len(res)} runs valid")
    for key, label in (("lost_at_cut", "packets lost"), ("interruption_ms", "interruption ms"),
                       ("recovery_ms", "first delivery after cut ms")):
        v = [r[key] for r in ok if r.get(key) is not None]
        if len(v) > 1:
            print(f"  {label} (n={len(v)}): mean {st.mean(v):.2f}  std {st.stdev(v):.2f}  min {min(v):.2f}  max {max(v):.2f}")
        elif v:
            print(f"  {label} (n=1): {v[0]:.2f}")
    if out:
        cols = ["run", "valid", "lost_total", "lost_at_cut", "interruption_ms", "recovery_ms", "spike_ms", "note"]
        with open(out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(res)

if __name__ == "__main__":
    main()
