#!/usr/bin/env bash
# Sourced by run_srv6.sh and run_batch.sh (not by run_common.sh): detector settings + control markers.
# Takes no lock and touches no container at source time.
DEFAULT_MISS_MS=8; DEFAULT_CONFIRM_MS=3
CONTROL_MARKER_DIR=control_markers

# norm_num <label> <value> <strict|nonneg>  -> prints a canonical number (5, 0.5, ...) or fails.
norm_num() {
    python3 - "$@" <<'PY'
import re, sys
label, value, kind = sys.argv[1:4]
if not re.fullmatch(r'[0-9]+(\.[0-9]+)?', value):
    sys.exit(f'{label} must be a plain non-negative number, got: {value!r}')
x = float(value)
if kind == 'strict' and x <= 0:
    sys.exit(f'{label} must be > 0')
print('%g' % x)
PY
}

# Applies MISS_MS / CONFIRM_MS (env or flags already stored by the caller) and normalizes them.
finalize_detector_params() {
    MISS_MS=$(norm_num miss-ms "${MISS_MS:-$DEFAULT_MISS_MS}" strict) || return 2
    CONFIRM_MS=$(norm_num confirm-ms "${CONFIRM_MS:-$DEFAULT_CONFIRM_MS}" nonneg) || return 2
}

control_marker_path() { echo "$CONTROL_MARKER_DIR/srv6_miss$1_confirm$2.pass"; }

write_control_marker() {   # <control run dir> <miss> <confirm>; only call after analyze_control passed
    local m; m=$(control_marker_path "$2" "$3")
    mkdir -p "$CONTROL_MARKER_DIR"
    printf 'miss_ms=%s\nconfirm_ms=%s\ncontrol_run=%s\npassed_utc=%s\n' "$2" "$3" "$1" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$m.tmp" && mv -f "$m.tmp" "$m"
}

invalidate_control_marker() {   # a control that FAILED for these settings withdraws an older pass
    rm -f "$(control_marker_path "$1" "$2")"
}

# check_control_marker <miss> <confirm>: marker exists, names a control folder whose params match
# and which re-passes analyze_control.py now.
check_control_marker() {
    local m run
    m=$(control_marker_path "$1" "$2")
    [ -f "$m" ] || { echo "No passed no-cut control for miss=$1 confirm=$2 (missing $m)."; return 1; }
    run=$(sed -n 's/^control_run=//p' "$m")
    [ -d "$run" ] || { echo "Marker $m names a control folder that is gone: $run"; return 1; }
    grep -qx "miss_ms=$1" "$run/params.txt" && grep -qx "confirm_ms=$2" "$run/params.txt" || {
        echo "Control folder $run was run with different settings than the marker claims."; return 1; }
    python3 analyze_control.py "$run" >/dev/null || { echo "Control $run no longer passes analyze_control.py."; return 1; }
}

# True when the R1 underlay route to R5 leaves via eth2 (Path A); same probe as run_srv6.sh.
underlay_on_A() { docker exec "${R1:-clab-srv6-r1}" ip -6 route get fc00:0:5::d6 2>/dev/null | grep -q 'dev eth2'; }
