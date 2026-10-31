#!/usr/bin/env python3
"""Usage: python3 analyze_srv6.py <run folders...> [--csv out.csv] [--max-late-ms 2] [--exclude-suspect]
(reuses analyze.py for loss/interruption). Every timing uses t_before_ns of cut.log as time zero."""
import os, sys
from pathlib import Path
from analyze import analyze, kv, clock_domain, validate_clocks, DEFAULT_MAX_LATE_MS
import summary

def txt(p):
    try:
        return Path(p).read_text()
    except OSError:
        return ""

def analyze_run(run, max_late_ms=DEFAULT_MAX_LATE_MS):
    """Return analyze()'s dict plus detect_ms, switch_cmd_ms, ok, bad, false_trigger, status, reasons.
    Unanalysable runs come back with status 'skipped' and no 'lost_total'."""
    r = analyze(run, max_late_ms, mode="srv6")
    if "lost_total" not in r:
        r.update(status="skipped", reasons=r["note"], false_trigger=False, suspect=False)
        return r
    bad = []
    f, c = kv(run + "/fail.txt"), kv(run + "/cut.log")
    det = swc = None
    false_trigger = False
    try:
        clock = validate_clocks(run, "send.txt", "cut.log", "fail.txt")
        if clock == "monotonic":
            if f.get("status") != "finished": bad.append("detector did not finish cleanly")
            if int(f.get("switch_count", "0")) != 1: bad.append("require one successful policy switch")
            if int(f.get("t_first_ok_ns", "0")) < int(f.get("t_switched_ns", "0")) or not int(f.get("t_first_ok_ns", "0")):
                bad.append("no post-switch probe recovery")
        t0 = int(c["t_before_ns"])          # single zero point, same as analyze.py
        td, ts = int(f["t_detect_ns"]), int(f["t_switched_ns"])
        if td == 0:
            bad.append("probe never detected the failure")
        else:
            det, swc = (td - t0) / 1e6, (ts - td) / 1e6
            if td < t0:
                bad.append("probe fired BEFORE the cut (false trigger)")
                false_trigger = True
            elif td < int(c["t_after_ns"]):
                bad.append("detection overlaps cut-command uncertainty interval")
            if ts <= td: bad.append("no successful policy replacement timestamp")
    except (KeyError, ValueError, OSError) as e:
        bad.append("invalid/mixed detector timing: " + str(e))
    if "fc00:0:2::1" not in txt(run + "/route_before.txt"):
        bad.append("policy A not in place before the cut")
    if "fc00:0:3::1" not in txt(run + "/route_after.txt"):
        bad.append("policy B not in place after the cut")
    if not r["valid"] and r["note"] and r["note"] not in bad:
        bad.append(r["note"])
    ok = r["valid"] and not bad
    r.update(detect_ms=det, switch_cmd_ms=swc, ok=ok, bad="; ".join(bad), false_trigger=false_trigger,
             status="valid" if ok else "false_trigger" if false_trigger else "invalid",
             reasons="; ".join(bad))
    return r

def main():
    args = sys.argv[1:]
    out, max_late_ms = None, DEFAULT_MAX_LATE_MS
    exclude_suspect = "--exclude-suspect" in args
    args = [a for a in args if a != "--exclude-suspect"]
    for flag in ("--csv", "--max-late-ms"):
        if flag in args:
            i = args.index(flag)
            if flag == "--csv": out = args[i + 1]
            else: max_late_ms = float(args[i + 1])
            del args[i:i + 2]
    runs = [a for a in args if os.path.isdir(a)]
    if not runs:
        sys.exit("give run folders")
    rows = []
    for run in runs:
        r = analyze_run(run, max_late_ms)
        rows.append(r)
        if r["status"] == "skipped":
            print(f"{run}: SKIPPED - {r['note']}")
            continue
        d = "n/a" if r["detect_ms"] is None else f"{r['detect_ms']:.1f} ms"
        s = "n/a" if r["switch_cmd_ms"] is None else f"{r['switch_cmd_ms']:.1f} ms"
        rec = "n/a" if r["recovery_ms"] is None else f"{r['recovery_ms']:.1f} ms"
        unc = "n/a" if r["cut_uncertainty_ms"] is None else f"{r['cut_uncertainty_ms']:.2f} ms"
        print(f"{run}: {'VALID' if r['ok'] else 'INVALID - ' + r['bad']}")
        print(f"   clock={r['clock']}  max receiver gap near cut={r['max_rx_gap_near_cut_ms']:.2f} ms")
        print(f"   lost@cut={r['lost_at_cut']}  interruption={r['interruption_ms']:.1f} ms (resolution {r['iv_ms']:.1f} ms)"
              f"  detection delay={d} (from t_before)  switch cmd={s}  post-loss UDP recovery={rec}"
              f"  cut-command uncertainty={unc}")
        if r["suspect"]:
            print("   SUSPECT:", r["note"])
    ok = [r for r in rows if r["status"] == "valid"]
    print(f"\n{len(ok)}/{len(rows)} runs valid")
    if not summary.summarize(rows, summary.SRV6_METRICS, "SRv6", has_detector=True,
                             exclude_suspect=exclude_suspect, max_late_ms=max_late_ms):
        print("Mixed historical/new clocks: per-run results only; aggregate comparison refused")
        return 1
    if out:
        summary.write_csv(out, rows, "srv6")
    return 0 if rows and len(ok) == len(rows) else 1

if __name__ == "__main__":
    sys.exit(main())
