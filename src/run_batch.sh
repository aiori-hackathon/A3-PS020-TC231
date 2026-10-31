#!/usr/bin/env bash
# Usage: bash run_batch.sh [--prefix P] [-n N] [--miss-ms N] [--confirm-ms N]
#                          [--max-late-ms N] [--underlay-timeout S]
# Runs N controlled-failure SRv6 trials (run IDs P_01..P_NN) one after another via run_srv6.sh.
# Refuses to start unless a no-cut control with the SAME miss/confirm settings has passed
# (bash run_srv6.sh <id> --no-cut --miss-ms .. --confirm-ms ..). Continues after a failed run.
# Waits (polling) for the underlay to be back on Path A before each run; if it never is, the batch
# stops (further runs would only fail) and still writes the summary of what was attempted.
set -uo pipefail
cd "$(dirname "$0")"
source ./run_params.sh
N=10; PREFIX=; MAX_LATE_MS=2; UNDERLAY_TIMEOUT=${UNDERLAY_TIMEOUT:-120}; POLL_S=${PS020_POLL_S:-2}
USAGE='Usage: bash run_batch.sh [--prefix P] [-n N] [--miss-ms N] [--confirm-ms N] [--max-late-ms N] [--underlay-timeout S]'
need() { [ "$2" -ge 2 ] || { echo "$1 needs a value"; exit 2; }; }
while [ "$#" -gt 0 ]; do
    case "$1" in
        --help|-h) echo "$USAGE"; exit 0;;
        -n|--runs) need "$1" "$#"; N=$2; shift 2;;
        --prefix) need "$1" "$#"; PREFIX=$2; shift 2;;
        --miss-ms) need "$1" "$#"; MISS_MS=$2; shift 2;;
        --confirm-ms) need "$1" "$#"; CONFIRM_MS=$2; shift 2;;
        --max-late-ms) need "$1" "$#"; MAX_LATE_MS=$2; shift 2;;
        --underlay-timeout) need "$1" "$#"; UNDERLAY_TIMEOUT=$2; shift 2;;
        *) echo "Unknown option: $1"; echo "$USAGE"; exit 2;;
    esac
done
[[ "$N" =~ ^[1-9][0-9]*$ ]] || { echo '-n must be a positive integer'; exit 2; }
[[ "$UNDERLAY_TIMEOUT" =~ ^[0-9]+$ ]] || { echo '--underlay-timeout must be whole seconds'; exit 2; }
MAX_LATE_MS=$(norm_num max-late-ms "$MAX_LATE_MS" strict) || exit 2
finalize_detector_params || exit 2
PREFIX=${PREFIX:-batch_$(date +%Y%m%d_%H%M%S)}
[[ "$PREFIX" =~ ^[A-Za-z0-9_-]+$ ]] || { echo 'Prefix may contain letters, digits, _ or -'; exit 2; }

check_control_marker "$MISS_MS" "$CONFIRM_MS" || {
    echo "Refusing to start. Run first:  bash run_srv6.sh control_${MISS_MS}_${CONFIRM_MS} --no-cut --miss-ms $MISS_MS --confirm-ms $CONFIRM_MS"
    exit 3; }
ID_FMT="%s_%02d"; [ "$N" -gt 99 ] && ID_FMT="%s_%03d"
for i in $(seq 1 "$N"); do
    id=$(printf "$ID_FMT" "$PREFIX" "$i")
    [ ! -e "results/srv6-monotonic/run$id" ] || { echo "run folder already exists, refusing: results/srv6-monotonic/run$id"; exit 4; }
done
BATCH_DIR="batches/$PREFIX"
mkdir -p batches
mkdir "$BATCH_DIR" || { echo "batch folder exists, refusing: $BATCH_DIR"; exit 4; }
exec 8>/tmp/ps020-batch.lock
flock -n 8 || { echo 'Another batch is active'; exit 1; }
TSV="$BATCH_DIR/runs.tsv"; : > "$TSV"
INTERRUPTED=0; trap 'INTERRUPTED=1' INT TERM
echo "Batch $PREFIX: $N runs, miss=${MISS_MS}ms confirm=${CONFIRM_MS}ms (control marker verified)"
STOPPED=
for i in $(seq 1 "$N"); do
    [ "$INTERRUPTED" = 0 ] || { STOPPED="interrupted before run $i"; break; }
    id=$(printf "$ID_FMT" "$PREFIX" "$i")
    waited=0
    until underlay_on_A; do
        [ "$waited" -lt "$UNDERLAY_TIMEOUT" ] && [ "$INTERRUPTED" = 0 ] || break
        sleep "$POLL_S"; waited=$((waited + POLL_S))
    done
    if ! underlay_on_A; then STOPPED="underlay not on Path A before run $i (waited ${waited}s)"; break; fi
    echo "--- run $i/$N: $id"
    bash run_srv6.sh "$id" --miss-ms "$MISS_MS" --confirm-ms "$CONFIRM_MS" 8>&-
    rc=$?
    printf '%s\t%s\t%s\n' "$id" "results/srv6-monotonic/run$id" "$rc" >> "$TSV"
    echo "--- run $id exit code $rc"
done
[ -z "$STOPPED" ] || echo "BATCH STOPPED EARLY: $STOPPED"
python3 batch_summary.py --tsv "$TSV" --csv "$BATCH_DIR/batch_summary.csv" --planned "$N" \
    --prefix "$PREFIX" --max-late-ms "$MAX_LATE_MS" | tee "$BATCH_DIR/batch_summary.txt"
exit "${PIPESTATUS[0]}"
