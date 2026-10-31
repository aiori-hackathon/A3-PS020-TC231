# Inter-send diagnostic experiment
This is instrumentation, not a pacing fix or final benchmark package.
The 200 us guard, packet rate, routing and acceptance thresholds are unchanged.
New send_gap_diagnostic.csv and its schema are copied automatically for main and restoration traffic.
Row zero is invalid for gap analysis and has zero deltas. Subsequent elapsed_ns values exactly match successive actual_ns differences.
CPU/rusage reads follow wall stamps sequentially: counter intervals are approximate. Ordinary sleep creates voluntary switches. Zero switches do not establish a VM pause. resource.getrusage returns a new object per sample; preallocated output arrays do not make the loop allocation-free. Overhead must be measured on the laptop.
The older send_call_diagnostic.csv measures a different interval. Do not merge the two.
Original uploaded runs, controls, batches and caches are preserved, not newly validated. Code changes require a fresh control; historical results remain historical.
Capture point remains R5 eth1 instead of administratively cut R2 eth2.
First run from this package's src directory:
python3 run_timed.py --mode control --miss-ms 5 --confirm-ms 1 --prefix "gap_control_$(date +%Y%m%d_%H%M%S)"
No live Docker/WSL verification was performed here.
