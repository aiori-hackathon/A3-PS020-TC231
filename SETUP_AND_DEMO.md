# Setup and single-trial demo

We ran the lab using Ubuntu on WSL2 with Docker Desktop. The commands below run in the Ubuntu terminal. Back up existing lab configurations and results before changing a running lab. Setup on other systems may require adjustments.

## Prerequisites

Docker Desktop with its engine running and WSL integration, an Ubuntu WSL2 distribution, Python 3, containerlab and locally available `frrouting/frr` and `alpine` images are needed. The FRR image needs Python 3, iproute2, tcpdump, and the FRR daemons. The published runs used containerlab 0.80.0 and `frrouting/frr:latest`; record the actual image digest and version on a new machine. Image tags can change. Downloads may be large; check sizes and use the installation tools' help and official documentation before downloading.

All WSL2 distributions and Docker Desktop share the WSL2 kernel. Stock WSL kernels may lack required SRv6 options. In Ubuntu check:

```bash
uname -r
zcat /proc/config.gz | grep -E 'CONFIG_LWTUNNEL=|CONFIG_IPV6_SEG6_LWTUNNEL=|CONFIG_IPV6_SEG6_HMAC=|CONFIG_IKCONFIG_PROC='
```

The demonstrated custom kernel had these enabled, and matching kernel modules available. If the kernel or `/proc/config.gz` is unavailable, resolve that first; installing Ubuntu alone does not add the kernel features. Use the Microsoft WSL kernel documentation for a custom kernel and module setup. Never overwrite another kernel or `.wslconfig` without a backup.

## Prepare the lab

In Ubuntu, enter the extracted `src` directory. Verify Docker works with `docker ps`. Run `containerlab deploy --help` to check your version's syntax; deploy `srv6-lab.clab.yml` with your normal containerlab environment. Containerlab requires sufficient privileges. The topology uses lab name `srv6` and the container names `clab-srv6-h1`, `h2`, and `r1`–`r5`; check for existing containers with those names before deploying. Do not destroy another lab.

**Docker Desktop limitation:** in our setup, Ubuntu's native containerlab could not access Docker Desktop's network namespaces, so we used a privileged helper container to restore the links. This behaviour is environment-specific. Inspect `containerlab deploy --help`, ensure the helper image is present, and test with a dry run before applying a deployment. After a Docker restart, containers can exist without their topology links or startup addresses; a deploy can add links without rerunning node startup commands. Check `docker exec clab-srv6-r2 ip -br addr`: `eth1` and `eth2` must be UP and show `2001:db8:12::2/64` and `2001:db8:25::1/64`. If they do not, stop and restore the topology configuration from `srv6-lab.clab.yml` before testing.

We used the following helper command on our Docker Desktop setup. It mounts the Docker socket and uses a privileged container; use it only if you understand and trust the local topology and helper image. From `src`, first run the dry run:

```bash
docker run --rm --pull=never --privileged --network host --pid host -v /var/run/docker.sock:/var/run/docker.sock -v /var/run/docker/netns:/var/run/docker/netns -v /var/run/netns:/var/run/netns -v /usr/bin/containerlab:/usr/local/bin/containerlab:ro -v "$PWD":/work -w /work --entrypoint /usr/local/bin/containerlab alpine:latest deploy --topo /work/srv6-lab.clab.yml --dry-run
```

Review the plan; if it shows the expected topology, repeat the same command without `--dry-run`. After restoring the links, we reapplied the topology addresses:

```bash
while read -r node iface address; do
  docker exec "clab-srv6-$node" ip -6 addr replace "$address" dev "$iface" nodad || break
done <<'ADDRS'
h1 eth1 2001:db8:a::2/64
r1 eth1 2001:db8:a::1/64
r1 eth2 2001:db8:12::1/64
r1 eth3 2001:db8:13::1/64
r2 eth1 2001:db8:12::2/64
r2 eth2 2001:db8:25::1/64
r3 eth1 2001:db8:13::2/64
r3 eth2 2001:db8:34::1/64
r4 eth1 2001:db8:34::2/64
r4 eth2 2001:db8:45::1/64
r5 eth1 2001:db8:25::2/64
r5 eth2 2001:db8:45::2/64
r5 eth3 2001:db8:b::1/64
h2 eth1 2001:db8:b::2/64
ADDRS
```

Check any error output before proceeding. Restore the host routes:

```bash
docker exec clab-srv6-h1 ip -6 route replace default via 2001:db8:a::1 dev eth1 && docker exec clab-srv6-h2 ip -6 route replace default via 2001:db8:b::1 dev eth1
```

Enable forwarding and SRv6 processing on the five routers:

```bash
for node in r1 r2 r3 r4 r5; do
  docker exec "clab-srv6-$node" sh -ec 'sysctl -w net.ipv6.conf.all.forwarding=1; for iface in /proc/sys/net/ipv6/conf/*/seg6_enabled; do echo 1 > "$iface"; done' || break
done
```

These commands configure the named running containers, not other host networking. On a clean native Linux deployment, topology startup commands may already configure them; inspect first.

Once all seven nodes have the addresses, host default routes, router forwarding and per-interface `seg6_enabled=1` specified by the topology, run:

```bash
bash setup_ospf.sh
```

Check all FRR startup messages. Allow OSPF to converge, then run:

```bash
docker exec clab-srv6-r1 ip -6 route get fc00:0:5::d6
```

Expect a `proto ospf` route via `eth2`. Install endpoint SIDs:

```bash
bash setup_srv6.sh
```

If a command fails, stop and inspect the error rather than starting a campaign. The setup scripts and topology can alter the live lab.

## Functional control and captured failure

Use a unique prefix for every run. The control generates a fresh marker; an old marker from another host or boot is not portable. Run in Ubuntu from `src`:

```bash
python3 run_timed.py --mode control --capture --miss-ms 5 --confirm-ms 1 --prefix "demo_control_$(date +%Y%m%d_%H%M%S)"
```

A functional pass means the control checks passed; measurement acceptance is reported separately. Capture uses roughly 10–30 MB per trial. Then run a controlled failure, which temporarily takes R2 eth2 down and restores it:

```bash
python3 run_timed.py --mode srv6 --capture --miss-ms 5 --confirm-ms 1 --prefix "demo_failure_$(date +%Y%m%d_%H%M%S)"
```

Expect a functional result, a separate measurement-quality result, and `SRH/packet path verification: PASS` when evidence verifies successfully. Check `Actual UDP recovery packet ingress policy`, the report and PCAPs; do not equate a policy command return with the exact activation time. The report records the result and measurement quality for each trial.

Runs are written to `src/results/timed-v3/`; summaries are in `src/batches/`. Use unique prefixes to avoid overwriting. A non-capture batch needs a matching non-capture functional control. Use the same capture setting and measurement method for IPv6 and SRv6 comparisons.

## Tests and pseudocode

In Ubuntu from `src`, run offline tests:

```bash
python3 -m unittest discover -s tests -p test_timed.py
```

Live functionality still requires the actual lab. Our results describe the tested environment.

```text
configure OSPFv3 and install SRv6 policy A
start UDP traffic and monitor probes
bring R2–R5 down and record the cut interval
if probe responses exceed the configured miss and confirmation thresholds:
    record detection and install policy B at R1
record UDP reception at H2
restore the link and policy A; verify delivery
inspect packet captures and analyze all attempted runs
```
