"""Shared run-aggregation helpers (counts, statistics table, CSV). Pure Python, no lab access.

Time zero for every timing is t_before_ns of cut.log (start of the cut command).
Row dicts need: run, status (valid|false_trigger|invalid|skipped), reasons, suspect, clock,
plus the metric keys below. p95 uses linear interpolation between order statistics, so with
fewer than ~20 runs it is dominated by the maximum.
"""
import csv, statistics as st

COMMON_METRICS = (
    ("lost_at_cut", "packets lost at cut"),
    ("interruption_ms", "interruption ms (loss-derived estimate)"),
    ("recovery_ms", "post-loss UDP recovery ms"),
    ("first_postcut_udp_ms", "first UDP rx after cut ms"),
    ("max_rx_gap_near_cut_ms", "max receiver gap near cut ms"),
    ("spike_ms", "delay spike near cut ms"),
    ("cut_uncertainty_ms", "cut-command uncertainty ms"),
    ("max_late_ms", "max sender lateness ms"),
)
SRV6_METRICS = COMMON_METRICS[:6] + (
    ("detect_ms", "detection delay ms (from t_before)"),
    ("switch_cmd_ms", "switch command ms (detect->switched)"),
) + COMMON_METRICS[6:]
BASELINE_METRICS = COMMON_METRICS

CSV_COLS = ["scenario", "run", "clock", "status", "valid", "false_trigger", "restoration_failed", "suspect", "reasons",
            "lost_total", "lost_at_cut", "interruption_ms", "iv_ms", "recovery_ms",
            "first_postcut_udp_ms", "max_rx_gap_near_cut_ms", "spike_ms", "detect_ms",
            "switch_cmd_ms", "cut_uncertainty_ms", "max_late_us", "note"]

def percentile(vals, p):
    s = sorted(vals)
    k = (len(s) - 1) * p / 100.0
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)

def describe(vals):
    vals = [float(v) for v in vals if v is not None]
    if not vals:
        return {"n": 0}
    return {"n": len(vals), "mean": st.mean(vals), "median": st.median(vals),
            "p95": percentile(vals, 95), "min": min(vals), "max": max(vals),
            "std": st.stdev(vals) if len(vals) > 1 else None}

def count(rows):
    c = {"total": len(rows), "valid": 0, "false_trigger": 0, "invalid": 0, "skipped": 0,
         "suspect": 0, "restoration_failed": 0}
    for r in rows:
        c[r["status"]] += 1
        c["suspect"] += bool(r.get("suspect"))
        c["restoration_failed"] += bool(r.get("restoration_failed"))
    c["other_invalid"] = c["invalid"] + c["skipped"]
    return c

def _cell(v, w=9):
    return f"{'n/a':>{w}}" if v is None else f"{v:>{w}.2f}"

def summarize(rows, metrics, label, has_detector=True, exclude_suspect=False, max_late_ms=None,
              out=print):
    """Print counts and statistics. Returns False (and prints nothing numeric) when the rows mix
    clock domains; invalid runs are listed, never silently dropped."""
    domains = {r["clock"] for r in rows if r.get("clock")}
    if len(domains) > 1:
        out("Mixed historical/new clocks: aggregate comparison refused")
        return False
    c = count(rows)
    out(f"\n== {label}: aggregate summary (time zero = t_before_ns of the cut command) ==")
    ft = str(c["false_trigger"]) if has_detector else "n/a (no detector)"
    out(f"runs: total {c['total']} | valid {c['valid']} | false triggers {ft} | "
        f"other invalid {c['other_invalid']}")
    out(f"restoration failures (always excluded from statistics): {c['restoration_failed']}")
    for r in rows:
        if r.get("restoration_failed"):
            out(f"  restoration failed: {r['run']} - " + "; ".join(r.get("restoration_problems") or ["see reasons"]))
    for r in rows:
        if r["status"] == "false_trigger":
            out(f"  false trigger: {r['run']} - {r['reasons']}")
    for r in rows:
        if r["status"] in ("invalid", "skipped"):
            tag = "unanalysable" if r["status"] == "skipped" else "invalid"
            out(f"  {tag}: {r['run']} - {r['reasons']}")
    lim = "" if max_late_ms is None else f" (> {max_late_ms:g} ms)"
    sus = [r["run"] for r in rows if r.get("suspect")]
    unknown = sum(1 for r in rows if r["status"] == "valid" and r.get("max_late_us") is None)
    out(f"suspect sender lateness{lim}: {len(sus)} run(s)" + (": " + ", ".join(sus) if sus else "")
        + (f"; lateness unknown for {unknown} valid run(s)" if unknown else ""))
    use = [r for r in rows if r["status"] == "valid" and not r.get("restoration_failed")
           and not (exclude_suspect and r.get("suspect"))]
    out(f"statistics over {len(use)} valid run(s)" + (" (suspect excluded)" if exclude_suspect else
        " (suspect included; use --exclude-suspect to drop them)") + ", sample std, p95 linear:")
    out(f"  {'metric':<42}{'n':>3}{'mean':>9}{'median':>9}{'p95':>9}{'min':>9}{'max':>9}{'std':>9}")
    for key, name in metrics:
        d = describe([r.get(key) for r in use])
        if not d["n"]:
            out(f"  {name:<42}{0:>3}" + _cell(None) * 6)
        else:
            out(f"  {name:<42}{d['n']:>3}" + "".join(_cell(d[k]) for k in
                ("mean", "median", "p95", "min", "max", "std")))
    return True

def write_csv(path, rows, scenario, extra_cols=()):
    cols = CSV_COLS + [c for c in extra_cols if c not in CSV_COLS]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore", restval="")
        w.writeheader()
        for r in rows:
            w.writerow({**r, "scenario": scenario})
