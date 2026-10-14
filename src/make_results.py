import csv
import statistics as st
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from analyze import analyze, kv

OUT = Path("evidence")
OUT.mkdir(exist_ok=True)
records = []

for scenario, ids in (
    ("baseline", [6, 7, 8, 9, 10]),
    ("srv6", [1, 2, 3, 4, 5, 6, 7]),
):
    for number in ids:
        folder = f"results/{scenario}/run{number}"
        r = analyze(folder)
        if "lost_total" not in r:
            raise RuntimeError(f"{folder}: {r.get('note')}")

        valid = bool(r["valid"])
        reasons = [r["note"]] if r["note"] else []
        detection = switch = None

        if scenario == "srv6":
            f = kv(folder + "/fail.txt")
            c = kv(folder + "/cut.log")
            midpoint = (
                int(c["t_before_ns"]) + int(c["t_after_ns"])
            ) // 2
            detected = int(f["t_detect_ns"])
            switched = int(f["t_switched_ns"])
            detection = (detected - midpoint) / 1e6
            switch = (switched - detected) / 1e6

            before = Path(folder + "/route_before.txt").read_text()
            after = Path(folder + "/route_after.txt").read_text()

            if detected == 0 or detection < 0:
                valid = False
                reasons.append("No detection or false trigger before cut")
            if "fc00:0:2::1" not in before:
                valid = False
                reasons.append("Policy A missing before cut")
            if "fc00:0:3::1" not in after:
                valid = False
                reasons.append("Policy B missing after cut")

        records.append({
            "scenario": scenario,
            "run": number,
            "valid": valid,
            "lost_at_cut": r["lost_at_cut"],
            "interruption_ms": r["interruption_ms"],
            "recovery_ms": r["recovery_ms"],
            "detection_ms": detection,
            "switch_ms": switch,
            "note": "; ".join(reasons),
        })

with (OUT / "all_runs.csv").open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(records[0]))
    writer.writeheader()
    writer.writerows(records)

groups = {
    name: [r for r in records if r["scenario"] == name and r["valid"]]
    for name in ("baseline", "srv6")
}

for name, rows in groups.items():
    if len(rows) != 5:
        raise RuntimeError(f"{name}: expected 5 valid runs, found {len(rows)}")
    if any(r["recovery_ms"] is None for r in rows):
        raise RuntimeError(f"{name}: missing recovery measurement")

metrics = [
    ("lost_at_cut", "Packets lost at cut", "Packets"),
    ("interruption_ms", "Loss-based interruption estimate", "Milliseconds"),
    ("recovery_ms", "Cut-command start to first delivery", "Milliseconds"),
]

summary = []
fig, axes = plt.subplots(1, 3, figsize=(13, 5))

for ax, (key, title, unit) in zip(axes, metrics):
    means, deviations = [], []
    for name in ("baseline", "srv6"):
        values = [r[key] for r in groups[name]]
        mean, sd = st.mean(values), st.stdev(values)
        means.append(mean)
        deviations.append(sd)
        summary.append({
            "scenario": name,
            "metric": key,
            "n": len(values),
            "mean": mean,
            "sample_sd": sd,
            "min": min(values),
            "max": max(values),
        })
    ax.bar(["OSPFv3", "SRv6 switch"], means,
           yerr=deviations, capsize=5)
    ax.set_title(title, fontsize=10)
    ax.set_ylabel(unit)
    ax.set_ylim(0, max(m + s for m, s in zip(means, deviations)) * 1.3)
    for i, (mean, sd) in enumerate(zip(means, deviations)):
        ax.text(i, mean + sd + 0.2, f"{mean:.2f}", ha="center")

fig.suptitle("Controlled R2-R5 failure: five valid runs per scenario")
fig.text(
    0.5, 0.025,
    "Error bars: sample SD. 1000 packets/s; 20,000 packets/run. "
    "SRv6 runs 3 and 6 excluded: false triggers.",
    ha="center", fontsize=9,
)
fig.tight_layout(rect=(0, 0.09, 1, 0.93))
fig.savefig(OUT / "comparison.png", dpi=220)
plt.close(fig)

with (OUT / "comparison_summary.csv").open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(summary[0]))
    writer.writeheader()
    writer.writerows(summary)

with (OUT / "per_run_tables.md").open("w") as f:
    for name, rows in groups.items():
        f.write(f"\n## {name}: valid runs\n\n")
        f.write("| Run | Lost at cut | Interruption estimate (ms) | "
                "First delivery from cut-command start (ms) |\n")
        f.write("|---|---:|---:|---:|\n")
        for r in rows:
            f.write(f"| {r['run']} | {r['lost_at_cut']} | "
                    f"{r['interruption_ms']:.2f} | "
                    f"{r['recovery_ms']:.3f} |\n")
    f.write("\nSRv6 attempts 3 and 6 excluded: false triggers before cut.\n")
    f.write("\nDetection delay uses the cut-command midpoint; "
            "recovery uses cut-command start. These references differ.\n")

print("Saved:")
for name in ("comparison.png", "all_runs.csv",
             "comparison_summary.csv", "per_run_tables.md"):
    print(OUT / name)
