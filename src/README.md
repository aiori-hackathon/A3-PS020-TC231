# Source guide

See the [project README](../README.md) for the overview and results, and the [setup and demo guide](../SETUP_AND_DEMO.md) for run instructions.

## Lab and execution

- [srv6-lab.clab.yml](srv6-lab.clab.yml) — five-router and two-host topology.
- [setup_ospf.sh](setup_ospf.sh) — starts OSPFv3 on the routers.
- [setup_srv6.sh](setup_srv6.sh) — installs SRv6 endpoint and decapsulation SIDs.
- [srv6_policy.sh](srv6_policy.sh) — installs the primary or backup policy on R1.
- [run_timed.py](run_timed.py) — runs control, SRv6 and IPv6 trials, with restoration checks and optional packet capture.
- [timing/](timing/) — sender, receiver, detector, link control, capture and analysis code.
- [restoration.py](restoration.py) — checks that the network and delivery are restored.

## Results and evidence

- [batches/](batches/) — summaries for the 50-trial [SRv6](batches/final_srv6_20261031_142455_timed/) and [IPv6/OSPFv3](batches/final_ipv6_20261031_152505_timed/) campaigns.
- [results/timed-v3/](results/timed-v3/) — individual reports, packet logs, route snapshots and timing data.
- [evidence/sid_validation_20261031/](evidence/sid_validation_20261031/) — captures and report for the SRv6 failure and restoration trial.
- [pcaps/](pcaps/) — captures from the earlier prototype.
- [tests/](tests/) — automated checks for the measurement and supporting code.
- [tools/](tools/) — supporting traffic and analysis utilities.

The other runner and analysis scripts support earlier workflows. Use `run_timed.py` and the [setup and demo guide](../SETUP_AND_DEMO.md) for the reported campaigns.
