# SRv6 Path Steering and Measured Failure Recovery

**Team Sage · A3-PS020-TC231 · Abhinav G and Rajat R Pai · Mentor: Chaitra Ma’am**

We use a five-router containerlab network to compare IPv6/OSPFv3 forwarding with SRv6 path steering during a controlled R2–R5 link failure. A probe-based controller on R1 switches traffic to the backup SRv6 policy and restores the primary policy after the link returns.

- **Primary path A:** R1 → R2 → R5; SIDs `fc00:0:2::1, fc00:0:5::d6`.
- **Backup path B:** R1 → R3 → R4 → R5; SIDs `fc00:0:3::1, fc00:0:4::1, fc00:0:5::d6`.
- A separate captured trial shows SID progression, delivery on the backup path and restoration of the primary path.

## Results

Each campaign contained 50 trials with UDP traffic at 1,000 packets per second. All 100 trials passed the functional checks. The table shows the means for measurements that met the quality checks.

| Metric | IPv6/OSPFv3 | SRv6 |
|---|---:|---:|
| Functional passes | 50 / 50 | 50 / 50 |
| Accepted measurements | 47 / 50 | 46 / 50 |
| Packets lost at the cut | 12.49 | 7.26 |
| Maximum receiver gap | 13.71 ms | 8.40 ms |
| Post-loss UDP recovery from cut request | 13.42 ms | 8.04 ms |

In this testbed, SRv6 recovered faster on average and lost fewer packets than the IPv6/OSPFv3 baseline. Recovery is measured at H2 from the start of the link-down request. The SRv6 failover uses scripted ingress policy switching.

## Setup, demo and evidence

- [SETUP_AND_DEMO.md](SETUP_AND_DEMO.md) — prerequisites, lab setup, a captured demonstration and test commands.
- [START_HERE.md](START_HERE.md) — entry point for running the project.
- `src/run_timed.py` — runs controls, SRv6 trials and IPv6 baseline trials.
- `src/batches/` — summaries for the two 50-trial campaigns.
- `src/results/timed-v3/` — individual campaign results.
- `src/evidence/sid_validation_20261031/` — packet captures and report for the SID traversal demonstration.
- `A3-PS020-TC231 - srv6 path steering.pdf` — presentation summarising the initial prototype.

Team introduction: https://www.youtube.com/watch?v=MOveHIw-h10
