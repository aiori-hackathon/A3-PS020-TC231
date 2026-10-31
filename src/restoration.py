#!/usr/bin/env python3
"""Post-run lab restoration check: the single source of truth.

The runners (run_common.sh: verify_restoration) and every analyzer (analyze.py,
analyze_srv6.py, analyze_control.py) call this same code, so a run the runner
accepted as restored can never be re-labelled differently by the analysis, and
a run it rejected can never be counted as valid.

A run counts as RESTORED only if ALL of these hold (evidence files in the run folder):
  - no RESTORE_ERROR.txt                                       (any run, any schema)
  - restore.log present: the link-up command was executed      (schema-2 runs)
  - srv6 mode:     route_restored.txt shows policy A (fc00:0:2::1) and NOT policy B (fc00:0:3::1);
                   underlay_restored.txt shows R1's route to R5's SID leaving via eth2 (Path A)
    baseline mode: route_restored.txt shows the ordinary route via eth2 with no SRv6 encap
  - ping_restored.txt: >= 5 packets transmitted, every one received, exactly 0% loss, no ICMP errors.
    (A ping that merely exits 0 can still have lost packets; the printed statistics are what count.)

Historical (clock != monotonic) folders carry none of this evidence, so for them only
RESTORE_ERROR.txt is checked; their original numeric analysis is untouched.

CLI:  python3 restoration.py RUN_DIR --mode srv6|baseline [--require]
      prints one problem per line and exits 1, or prints 'restoration OK' and exits 0.
      --require forces the evidence checks regardless of the folder's clock schema.
"""
import re, sys
from pathlib import Path

PING_MIN_PACKETS = 5
POLICY_A, POLICY_B = "fc00:0:2::1", "fc00:0:3::1"
_PING = re.compile(r"(\d+) packets transmitted, (\d+) (?:packets )?received(.*?), (\d+(?:\.\d+)?)% packet loss")


def _has_addr(text, addr):
    return re.search(r"(?<![0-9A-Fa-f:])" + re.escape(addr) + r"(?![0-9A-Fa-f:])", text) is not None


def _read(path):
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return None


def _evidence_required(run):
    params = _read(Path(run) / "params.txt") or ""
    return re.search(r"^\s*clock\s*[=:]\s*monotonic\s*$", params, re.M) is not None


def infer_mode(run):
    """srv6 or baseline, from params.txt 'scenario=' (srv6-monotonic, srv6-control-monotonic,
    baseline-monotonic); falls back to whether the run has a detector log (fail.txt)."""
    m = re.search(r"^\s*scenario\s*[=:]\s*(\S+)", _read(Path(run) / "params.txt") or "", re.M)
    if m:
        return "srv6" if m.group(1).startswith("srv6") else "baseline"
    return "srv6" if (Path(run) / "fail.txt").exists() else "baseline"


def ping_problem(text):
    """None if the ping output proves 5+ packets, all answered, 0% loss; else a reason string."""
    if text is None:
        return "ping_restored.txt missing"
    m = None
    for m in _PING.finditer(text):
        pass                                   # use the final statistics line
    if m is None:
        return "ping_restored.txt has no packet statistics line (ping did not complete)"
    sent, got, extra, loss = int(m.group(1)), int(m.group(2)), m.group(3), float(m.group(4))
    if re.search(r"\+\d+ errors", extra):
        return f"restoration ping reported ICMP errors ({sent} sent, {got} received{extra})"
    if sent < PING_MIN_PACKETS:
        return f"restoration ping sent only {sent} packets (< {PING_MIN_PACKETS})"
    if loss != 0 or got < sent:
        return f"restoration ping loss {loss:g}% ({got}/{sent} replies); required 0%"
    return None


def problems(run, mode, require_evidence=None):
    run = Path(run)
    out = []
    if (run / "RESTORE_ERROR.txt").exists():
        out.append("RESTORE_ERROR.txt present (the runner reported failed restoration)")
    if require_evidence is None:
        require_evidence = _evidence_required(run)
    if not require_evidence:
        return out
    if mode not in ("srv6", "baseline"):
        raise ValueError("mode must be srv6 or baseline")

    log = _read(run / "restore.log")
    if log is None or "t_before_ns=" not in log:
        out.append("restore.log missing: link-up command not evidenced")

    route = _read(run / "route_restored.txt")
    if not route or not route.strip():
        out.append("route_restored.txt missing or empty")
    elif mode == "srv6":
        if not _has_addr(route, POLICY_A):
            out.append(f"restored route does not show policy A ({POLICY_A})")
        if _has_addr(route, POLICY_B):
            out.append(f"restored route still shows policy B ({POLICY_B})")
        under = _read(run / "underlay_restored.txt")
        if not under or "dev eth2" not in under:
            out.append("underlay not back on Path A (R1 route to R5 SID not via eth2)")
    else:
        if "dev eth2" not in route:
            out.append("restored ordinary route does not leave via eth2 (Path A)")
        if "encap" in route:
            out.append("restored ordinary route unexpectedly uses an SRv6 encap")

    p = ping_problem(_read(run / "ping_restored.txt"))
    if p:
        out.append(p)
    return out


def main(argv=None):
    a = list(sys.argv[1:] if argv is None else argv)
    if not a or a[0].startswith("-"):
        sys.exit(__doc__)
    run, mode, req = a[0], None, None
    if "--mode" in a:
        mode = a[a.index("--mode") + 1]
    if "--require" in a:
        req = True
    if mode is None:
        sys.exit("--mode srv6|baseline is required")
    found = problems(run, mode, req)
    for p in found:
        print(p)
    if not found:
        print("restoration OK")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
