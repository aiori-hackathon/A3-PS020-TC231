Repository Contents

Root source files
Topology configuration, IPv6 addressing and OSPFv3 setup, SRv6 SID installation, primary/backup policy selection, failure-experiment runners, result analyzers and chart-generation scripts.

tools/
Helper scripts for UDP traffic generation, packet reception, controlled link-down/up operations and probe-based failure detection with SRv6 policy replacement.

results/
Raw logs from the IPv6/OSPFv3 baseline and SRv6 experiments, including packet timestamps, traffic summaries, failure timestamps and path or policy evidence.
Final baseline dataset: runs 6–10.
Valid SRv6 dataset: runs 1, 2, 4, 5 and 7.
SRv6 runs 3 and 6 are retained but excluded from statistics because the detector triggered before the controlled failure.

evidence/
Comparison charts, per-run tables, statistical summaries and saved failure/recovery evidence. These summarize packet loss, loss-based interruption estimates, UDP recovery time, detection delay and policy-update duration.

pcaps/
Verified tcpdump captures and decoded logs for both SRv6 paths. These show the SID lists, Segments Left progression and removal of the outer encapsulation at R5 before delivery to h2.
