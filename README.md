# SRv6 Path Steering and Measured Failure Recovery

**Team Sage · A3-PS020-TC231 · Abhinav G and Rajat R Pai · Mentor: Chaitra Ma’am**

We use a five-router containerlab network to compare IPv6/OSPFv3 forwarding with SRv6 path steering during a controlled R2–R5 link failure. A probe-based controller on R1 switches traffic to a backup SRv6 policy. After the link is restored, the test harness reinstalls and verifies the primary policy.

- **Primary path A:** R1 → R2 → R5  
  SIDs: `fc00:0:2::1, fc00:0:5::d6`
- **Backup path B:** R1 → R3 → R4 → R5  
  SIDs: `fc00:0:3::1, fc00:0:4::1, fc00:0:5::d6`
- A separate captured trial shows SID progression, delivery on the backup path and restoration of the primary path.

## Results

Each campaign contained 50 trials with UDP traffic at 1,000 packets per second. All 100 trials passed the functional checks. The table shows means for measurements that met the quality checks.

| Metric | IPv6/OSPFv3 | SRv6 |
|---|---:|---:|
| Functional passes | 50 / 50 | 50 / 50 |
| Accepted measurements | 47 / 50 | 46 / 50 |
| Packets lost at the cut | 12.49 | 7.26 |
| Maximum receiver gap | 13.71 ms | 8.40 ms |
| Post-loss UDP recovery from cut request | 13.42 ms | 8.04 ms |
| Failure-detection delay from cut request | Not measured separately | 6.12 ms |

In this testbed, SRv6 with scripted switching recovered faster on average and lost fewer packets than the IPv6/OSPFv3 baseline. UDP recovery is measured at H2 from the start of the cut request. Detection delay measures when the SRv6 controller identified the failure; it is not the total UDP recovery time.

## Setup, demo and evidence

- [Project and Demo Report](Team_Sage_Project_and_Demo_Report.pdf) — topology, implementation, results and comparison with the prototype.
- [Setup and Demo Guide](SETUP_AND_DEMO.md) — prerequisites, lab setup, a captured demonstration and test commands.
- [Source Guide](src/README.md) — key scripts, folders and evidence.
- [SRv6 batch summary](src/batches/final_srv6_20261031_142455_timed/) — summary of the 50 SRv6 trials.
- [IPv6 batch summary](src/batches/final_ipv6_20261031_152505_timed/) — summary of the 50 IPv6/OSPFv3 trials.
- [Individual trial results](src/results/timed-v3/) — reports, packet logs, routes and timing data.
- [SID validation captures](src/evidence/sid_validation_20261031/) — packet captures and report from the captured failure and restoration trial.
- [Prototype presentation](A3-PS020-TC231%20-%20srv6%20path%20steering.pdf) — the initial prototype and its results.

**Team introduction:** https://www.youtube.com/watch?v=MOveHIw-h10
**Live Demo**https://www.youtube.com/watch?v=OAxIbgI-XLI
