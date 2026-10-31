#!/usr/bin/env python3
"""Per-run plot: detection delay (SRv6 only), interruption and post-loss UDP recovery, SRv6 vs OSPF.
Usage: python3 plot_runs.py --srv6 DIR... --baseline DIR... --out fig.png [--force] [--max-late-ms 2]
Independent of make_results.py (which targets the historical evidence). Valid runs are filled
markers; invalid runs are plotted as hollow red x so they stay visible. Time zero = t_before_ns."""
import argparse, os, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import analyze, analyze_srv6, summary

PANELS = (("detect_ms", "Detection delay (ms)\nfrom cut-command start"),
          ("interruption_ms", "Interruption (ms)\nloss-derived estimate"),
          ("recovery_ms", "Post-loss UDP recovery (ms)\nfrom cut-command start"))

def load(srv6, baseline, max_late_ms):
    s = [analyze_srv6.analyze_run(d, max_late_ms) for d in srv6]
    b = []
    for d in baseline:
        r = analyze.analyze(d, max_late_ms, mode="baseline")
        r["status"], r["reasons"] = analyze.classify(r)
        b.append(r)
    return s, b

def draw(rows_by_name, out):
    domains = {r["clock"] for rows in rows_by_name.values() for r in rows if r.get("clock")}
    if len(domains) > 1:
        raise SystemExit("Mixed historical/new clocks: plot refused")
    fig, axes = plt.subplots(1, 3, figsize=(13, 4))
    for ax, (key, title) in zip(axes, PANELS):
        plotted = False
        for x, (name, rows) in enumerate(rows_by_name.items()):
            pts = [(i, r[key], r["status"] == "valid") for i, r in enumerate(rows)
                   if r.get(key) is not None and r["status"] != "skipped"]
            if not pts:
                continue
            plotted = True
            n = max(len(rows), 1)
            for i, v, ok in pts:
                xx = x + (i - (n - 1) / 2) * 0.6 / n
                ax.plot(xx, v, "o" if ok else "x", color="C%d" % x if ok else "red",
                        markerfacecolor="C%d" % x if ok else "none")
        if not plotted:
            ax.text(0.5, 0.5, "n/a (no detector)" if key == "detect_ms" else "no data",
                    ha="center", va="center", transform=ax.transAxes)
        ax.set_xticks(range(len(rows_by_name))); ax.set_xticklabels(list(rows_by_name))
        ax.set_xlim(-0.6, len(rows_by_name) - 0.4); ax.set_title(title, fontsize=9)
        ax.set_ylabel("ms"); ax.grid(alpha=0.3)
    fig.suptitle("Per-run timings (filled = valid, red x = invalid / false trigger)", fontsize=10)
    fig.tight_layout(); fig.savefig(out, dpi=150); plt.close(fig)

def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--srv6", nargs="*", default=[]); ap.add_argument("--baseline", nargs="*", default=[])
    ap.add_argument("--out", required=True); ap.add_argument("--force", action="store_true")
    ap.add_argument("--max-late-ms", type=float, default=analyze.DEFAULT_MAX_LATE_MS)
    a = ap.parse_args(argv)
    if os.path.exists(a.out) and not a.force:
        sys.exit(f"refusing to overwrite {a.out} (use --force)")
    s, b = load([d for d in a.srv6 if os.path.isdir(d)], [d for d in a.baseline if os.path.isdir(d)], a.max_late_ms)
    if not s and not b:
        sys.exit("give --srv6 and/or --baseline run folders")
    draw({"SRv6": s, "OSPF baseline": b}, a.out)
    print("wrote", a.out)

if __name__ == "__main__":
    main()
