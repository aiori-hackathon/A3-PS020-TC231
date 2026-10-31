#!/usr/bin/env python3
"""Summarize one run_batch.sh batch.
Usage: python3 batch_summary.py --tsv runs.tsv --csv batch_summary.csv --planned N [--prefix P]
                                [--max-late-ms 2] [--exclude-suspect]
runs.tsv has one 'run_id<TAB>run_dir<TAB>runner_exit_code' line per ATTEMPTED run."""
import argparse, os, sys
from pathlib import Path
import analyze_srv6, summary
from analyze import DEFAULT_MAX_LATE_MS, kv

def batch_rows(tsv, max_late_ms):
    rows = []
    for line in Path(tsv).read_text().splitlines():
        if not line.strip():
            continue
        run_id, run_dir, rc = line.split("\t")
        rc = int(rc)
        if os.path.isdir(run_dir):
            r = analyze_srv6.analyze_run(run_dir, max_late_ms)
        else:
            r = dict(run=run_dir, valid=False, note="run folder missing", status="skipped",
                     reasons="run folder missing", false_trigger=False, suspect=False)
        reasons = [r["reasons"]] if r.get("reasons") else []
        if os.path.exists(os.path.join(run_dir, "RESTORE_ERROR.txt")) and not r.get("restoration_failed"):
            reasons.append("RESTORE_ERROR.txt present: inspect link/policy")   # folder unreadable by the analyzer
            r["restoration_failed"] = True
        if r["status"] == "valid" and rc != 0:
            reasons.append(f"runner exit code {rc} despite analysable data")
            r["status"] = "skipped"            # counted as a failure, excluded from statistics
        if r["status"] == "skipped" and rc != 0 and not reasons:
            reasons.append(f"runner exit code {rc}")
        p = kv(os.path.join(run_dir, "params.txt"))
        r.update(run=run_id, runner_rc=rc, reasons="; ".join(reasons),
                 batch_status="failed" if r["status"] == "skipped" else r["status"],
                 miss_ms=p.get("miss_ms", ""), confirm_ms=p.get("confirm_ms", ""))
        rows.append(r)
    return rows

def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--tsv", required=True); ap.add_argument("--csv", required=True)
    ap.add_argument("--planned", type=int, required=True); ap.add_argument("--prefix", default="")
    ap.add_argument("--max-late-ms", type=float, default=DEFAULT_MAX_LATE_MS)
    ap.add_argument("--exclude-suspect", action="store_true")
    a = ap.parse_args(argv)
    rows = batch_rows(a.tsv, a.max_late_ms)
    c = summary.count(rows)
    print(f"\n== batch {a.prefix}: {len(rows)} of {a.planned} planned runs attempted ==")
    print(f"valid {c['valid']} | false triggers {c['false_trigger']} | "
          f"failures {c['skipped']} (aborted/unanalysable) | other invalid {c['invalid']} | "
          f"suspect lateness {c['suspect']} | restoration failures {c['restoration_failed']}")
    shown = summary.summarize(rows, summary.SRV6_METRICS, f"SRv6 batch {a.prefix}",
                              exclude_suspect=a.exclude_suspect, max_late_ms=a.max_late_ms)
    summary.write_csv(a.csv, rows, "srv6", extra_cols=("runner_rc", "batch_status", "miss_ms", "confirm_ms"))
    print(f"batch_summary.csv: {a.csv}")
    return 0 if shown and len(rows) == a.planned and c["valid"] == a.planned else 1

if __name__ == "__main__":
    sys.exit(main())
