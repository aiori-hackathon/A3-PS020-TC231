#!/usr/bin/env python3
"""PS-020 analyzer (simple). Usage: python3 analyze.py <run folders...> [--csv out.csv] [--max-late-ms 2] [--exclude-suspect]
A trailing word like 'baseline' (as run_baseline.sh passes it) is ignored."""
import bisect, csv, os, re, statistics as st, sys
from pathlib import Path
import restoration, summary

WIN_BEFORE_MS, WIN_AFTER_MS = 10, 500
DEFAULT_MAX_LATE_MS = 2.0   # sender pacing lateness above this marks a run "suspect"

def clock_domain(meta):
    value = meta.get("clock", "realtime")
    if value not in ("realtime", "monotonic"):
        raise ValueError("unknown clock domain: " + value)
    return value

def recv_clock(path):
    with open(path, newline="") as f:
        header = next(csv.reader(f), [])
    if header == ["seq", "t_send_mono_ns", "t_recv_mono_ns"]:
        return "monotonic"
    if header == ["seq", "t_send_ns", "t_recv_ns"]:
        return "realtime"
    raise ValueError("unknown receiver timestamp schema")

def validate_clocks(run, *files):
    domains = [clock_domain(kv(run + "/" + name)) for name in files]
    domains.append(recv_clock(run + "/recv.csv"))
    if len(set(domains)) != 1:
        raise ValueError("mixed timestamp clocks: " + ", ".join(domains))
    return domains[0]

def kv(path):
    d = {}
    try:
        for line in Path(path).read_text().splitlines():
            m = re.match(r'\s*([A-Za-z_]\w*)\s*[=:]?\s*([-+\w.]+)', line)
            if m:
                d[m.group(1).lower()] = m.group(2)
    except OSError:
        pass
    return d

def load_recv(path):
    rows = {}
    try:
        for r in csv.reader(Path(path).read_text().splitlines()):
            try:
                rows.setdefault(int(r[0]), (int(r[1]), int(r[2])))
            except (ValueError, IndexError):
                pass
    except OSError:
        pass
    return rows

def hops(path):
    try:
        return set(re.findall(r'([0-9a-f]*:[0-9a-f:]+)', Path(path).read_text()))
    except OSError:
        return None

def _analyze_core(run, max_late_ms=DEFAULT_MAX_LATE_MS):
    r = dict(run=run, valid=False, note="")
    p, s, c = kv(run + "/params.txt"), kv(run + "/send.txt"), kv(run + "/cut.log")
    try:
        rate, dur = float(p["rate"]), float(p["dur"])
        sent, t_cut = int(s["sent"]), int(c["t_before_ns"])
        start, end = int(s["start_ns"]), int(s["end_ns"])
    except KeyError as e:
        r["note"] = f"missing {e}"
        return r
    try:
        clock = validate_clocks(run, "send.txt", "cut.log")
        if "clock" in p and clock_domain(p) != clock:
            raise ValueError("params clock differs from measurement logs")
    except (OSError, ValueError) as e:
        r["note"] = str(e)
        return r
    recv = load_recv(run + "/recv.csv")
    if len(recv) < 2:
        r["note"] = "recv.csv empty"
        return r
    iv_ns, iv_ms = int(1e9 / rate), 1000.0 / rate
    cut_unc = (int(c["t_after_ns"]) - t_cut) / 1e6 if "t_after_ns" in c else None
    late_us = int(s["max_late_us"]) if "max_late_us" in s else None
    suspect = late_us is not None and late_us / 1000.0 > max_late_ms
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
        notes.append(f"{clock} elapsed {(end-start)/1e9:.2f}s vs requested {dur:.0f}s; " +
                     ("legacy timing may be affected by clock corrections; total sequence loss is separate" if clock == "realtime" else "inspect sender lateness"))
    malformed = any(q < 0 or q >= sent for q in recv)
    if malformed: notes.append("receiver contains out-of-range sequences")
    if clock == "monotonic" and any(rx < tx for tx, rx in recv.values()):
        notes.append("negative packet delay: timestamps are not comparable")
        malformed = True
    if int(s.get("send_errors", 0)):
        notes.append("UDP send errors occurred")
        malformed = True
    receives = sorted(rx for tx, rx in recv.values())
    first_postcut = next((rx for rx in receives if rx >= t_cut), None)
    gaps = [(b-a)/1e6 for a,b in zip(receives, receives[1:]) if a<=hi and b>=lo]
    max_gap = max(gaps, default=0.0)
    if not inwin:
        notes.append("no loss at the cut")
    if suspect:
        notes.append(f"suspect: max sender lateness {late_us/1000:.2f} ms exceeds {max_late_ms:g} ms")
    r.update(valid=(changed is not False and not malformed), clock=clock, first_postcut_udp_ms=None if first_postcut is None else (first_postcut-t_cut)/1e6, max_rx_gap_near_cut_ms=max_gap, note="; ".join(notes), lost_total=len(lost),
             lost_at_cut=lost_cut, interruption_ms=interruption, iv_ms=iv_ms,
             recovery_ms=recovery, spike_ms=spike, cut_uncertainty_ms=cut_unc,
             max_late_us=late_us, max_late_ms=None if late_us is None else late_us / 1000.0,
             suspect=suspect)
    return r

def analyze(run, max_late_ms=DEFAULT_MAX_LATE_MS, mode=None):
    """Traffic analysis plus restoration enforcement.
    mode: 'baseline' (ordinary IPv6 route must be back) or 'srv6' (policy A + underlay must be back);
    None = inferred from the run folder (params.txt scenario= / presence of fail.txt).
    A run whose lab was not restored is never valid, whatever its traffic numbers look like."""
    r = _analyze_core(run, max_late_ms)
    rp = restoration.problems(run, mode or restoration.infer_mode(run))
    r["restoration_problems"], r["restoration_failed"] = rp, bool(rp)
    if rp:
        r["valid"] = False
        extra = "; ".join("RESTORATION FAILED: " + x for x in rp)
        r["note"] = (r["note"] + "; " if r["note"] else "") + extra
    return r

def classify(r):
    """Baseline status/reasons (no detector, so no false-trigger category)."""
    if "lost_total" not in r:
        return "skipped", r["note"]
    return ("valid", "") if r["valid"] else ("invalid", r["note"])

def main():
    args = sys.argv[1:]
    out = None
    if "--csv" in args:
        i = args.index("--csv")
        out = args[i + 1]
        del args[i:i + 2]
    max_late_ms, exclude_suspect = DEFAULT_MAX_LATE_MS, "--exclude-suspect" in args
    args = [a for a in args if a != "--exclude-suspect"]
    if "--max-late-ms" in args:
        i = args.index("--max-late-ms")
        max_late_ms = float(args[i + 1])
        del args[i:i + 2]
    runs = [a for a in args if os.path.isdir(a)]
    if not runs:
        sys.exit("give at least one run folder")
    res = [analyze(r, max_late_ms, mode="baseline") for r in runs]
    for r in res:
        if "lost_total" not in r:
            print(f"{r['run']}: SKIPPED - {r['note']}")
            continue
        rec = "n/a" if r["recovery_ms"] is None else f"{r['recovery_ms']:.1f} ms"
        print(f"{r['run']}: {'VALID' if r['valid'] else 'INVALID'}  lost@cut={r['lost_at_cut']}  "
              f"interruption={r['interruption_ms']:.1f} ms (resolution {r['iv_ms']:.1f} ms)  "
              f"post-loss UDP recovery={rec}  delay spike near cut={r['spike_ms']:.1f} ms")
        print(f"   clock={r['clock']}  max receiver gap near cut={r['max_rx_gap_near_cut_ms']:.2f} ms")
        if r["note"]:
            print("   note:", r["note"])
    ok = [r for r in res if r.get("valid")]
    print(f"\n{len(ok)}/{len(res)} runs valid")
    rows = []
    for r in res:
        r["status"], r["reasons"] = classify(r)
        r["false_trigger"] = False
        rows.append(r)
    if not summary.summarize(rows, summary.BASELINE_METRICS, "baseline (OSPF)", has_detector=False,
                             exclude_suspect=exclude_suspect, max_late_ms=max_late_ms):
        return 1
    if out:
        summary.write_csv(out, rows, "baseline")

    return 0 if res and all(r.get("valid") for r in res) else 1

if __name__ == "__main__":
    sys.exit(main())
