#!/usr/bin/env bash
# M6.2 / M16.2 — netem parameter sweep.
#
# Runs the Docker testbed across a PoW-difficulty × delay × loss × bandwidth
# matrix, collecting the tunnel round-trip latency stats (emitted by ct-client
# bench mode as a "RESULT <csv_row>" line) into a CSV for the thesis evaluation.
# The client's csv_row carries the M16 statistics (stddev, 95% CI, p99) plus the
# raw per-iteration samples (samples_ms, #52); this script prepends the
# PoW-difficulty axis it varied.
#
# The image is built once; link impairment and PoW difficulty are applied at
# runtime via env (netem-entrypoint.sh + EDGE_POW_DIFFICULTY), so there is no
# rebuild per condition.
#
# Usage:
#   scripts/sweep.sh                     # default matrix → docs/thesis/data/latency.csv
#   SWEEP_ITERATIONS=100 scripts/sweep.sh
#   SWEEP_POWS="8 16 20" scripts/sweep.sh                 # PoW-difficulty study
#   SWEEP_DELAYS="0ms 50ms" SWEEP_LOSSES="0% 2%" SWEEP_RATES="10mbit" scripts/sweep.sh
#   SWEEP_OUT=/tmp/x.csv SWEEP_DELAYS="20ms" SWEEP_LOSSES="0%" scripts/sweep.sh
#
# Direct-connection baseline for FF2 (#51) — same grid, no tunnel/edge hop, direct
# QUIC + direct TCP over the SAME netem path; emits mode=direct-tcp/direct-quic
# rows in the identical CSV format so tabulate.py diffs tunnel − baseline:
#   scripts/sweep.sh --baseline          # direct-tcp + direct-quic → latency-baseline.csv
#   SWEEP_APPEND=1 scripts/sweep.sh --baseline   # append baseline rows to latency.csv
#   SWEEP_BASELINE_PROTOS="tcp" SWEEP_DELAYS="20ms" SWEEP_LOSSES="0%" scripts/sweep.sh --baseline
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --baseline selects the direct-connection (no-tunnel) measurement path;
# --throughput selects the bulk-transfer bandwidth dimension (#57) instead of the
# latency round-trips, emitting mode=throughput rows to a separate throughput CSV.
BASELINE=0
THROUGHPUT=0
for arg in "$@"; do
    case "$arg" in
        --baseline) BASELINE=1 ;;
        --throughput) THROUGHPUT=1 ;;
        *) echo "sweep: unknown arg '$arg'" >&2; exit 2 ;;
    esac
done

if [ "$BASELINE" = "1" ]; then
    COMPOSE=(docker compose -f "$REPO_ROOT/docker/docker-compose.baseline.yml")
else
    COMPOSE=(docker compose -f "$REPO_ROOT/docker/docker-compose.yml")
fi

# Default output file. The throughput dimension writes a SEPARATE CSV (its rows
# have a different schema than the latency rows) so it never clobbers or misaligns
# the latency table; the baseline path likewise defaults to its own file so it
# never clobbers tunnel rows. SWEEP_APPEND=1 appends into the (existing) file --
# #992: specifically, into the TUNNEL file (latency.csv / throughput.csv), since
# the whole point of appending (rather than writing the baseline's own separate
# file) is so tabulate.py's single-file tunnel-vs-baseline diff sees both. Without
# this, `SWEEP_APPEND=1 ... --baseline` with SWEEP_OUT unset still defaulted to
# the baseline-only file, appending baseline rows to themselves and leaving
# latency.csv without the direct-* rows the documented workflow above promises.
if [ "$THROUGHPUT" = "1" ] && [ "$BASELINE" = "1" ]; then
    if [ "${SWEEP_APPEND:-0}" = "1" ] && [ -z "${SWEEP_OUT:-}" ]; then
        OUT="$REPO_ROOT/docs/thesis/data/throughput.csv"
    else
        OUT="${SWEEP_OUT:-$REPO_ROOT/docs/thesis/data/throughput-baseline.csv}"
    fi
elif [ "$THROUGHPUT" = "1" ]; then
    OUT="${SWEEP_OUT:-$REPO_ROOT/docs/thesis/data/throughput.csv}"
elif [ "$BASELINE" = "1" ]; then
    if [ "${SWEEP_APPEND:-0}" = "1" ] && [ -z "${SWEEP_OUT:-}" ]; then
        OUT="$REPO_ROOT/docs/thesis/data/latency.csv"
    else
        OUT="${SWEEP_OUT:-$REPO_ROOT/docs/thesis/data/latency-baseline.csv}"
    fi
else
    OUT="${SWEEP_OUT:-$REPO_ROOT/docs/thesis/data/latency.csv}"
fi
# A bulk transfer per iteration is expensive, so the throughput sweep defaults to
# a handful of transfers per grid point rather than 30 latency round-trips.
if [ "$THROUGHPUT" = "1" ]; then
    ITER="${SWEEP_ITERATIONS:-3}"
else
    ITER="${SWEEP_ITERATIONS:-30}"
fi
# Space-separated matrix axes. An empty RATES axis means "unlimited bandwidth".
# MODES selects the client bench path: "single" (one-shot) or "stream"
# (full-duplex). "udp" needs its own overlay + bench variant (M16.2c).
MODES="${SWEEP_MODES:-single}"
POWS="${SWEEP_POWS:-8}"
DELAYS="${SWEEP_DELAYS:-0ms 20ms 50ms 100ms}"
LOSSES="${SWEEP_LOSSES:-0% 1% 5%}"
# The throughput dimension is defined by the rate cap, so its RATES axis defaults
# to a couple of caps rather than "unlimited"; the latency sweep defaults to none.
if [ "$THROUGHPUT" = "1" ]; then
    RATES="${SWEEP_RATES:-10mbit 50mbit}"
else
    RATES="${SWEEP_RATES:-}"
fi
# Bulk payload size (bytes) per throughput transfer; drives CT_BENCH_BYTES.
BYTES="${SWEEP_BYTES:-8388608}"
# Baseline protocols: direct TCP (to the socat origin) and direct QUIC (to quic_echo).
BASELINE_PROTOS="${SWEEP_BASELINE_PROTOS:-tcp quic}"

# mode,pow prepended to the per-condition RESULT row. The throughput row carries
# the bulk-transfer columns (bytes,secs,mbps,mib_s); the latency row carries the
# client's 13-column csv_row (delay..p99_ms plus the trailing samples_ms, #52).
if [ "$THROUGHPUT" = "1" ]; then
    HEADER="mode,pow,delay,loss,rate,bytes,secs,mbps,mib_s"
else
    HEADER="mode,pow,delay,loss,rate,n,mean_ms,min_ms,max_ms,p50_ms,p95_ms,stddev_ms,ci95_ms,p99_ms,samples_ms"
fi

mkdir -p "$(dirname "$OUT")"
# Append mode keeps existing rows (e.g. tunnel rows) and reuses their header; a
# fresh run (or a missing file) writes the header first.
if [ "${SWEEP_APPEND:-0}" = "1" ] && [ -f "$OUT" ]; then
    echo "sweep: appending to existing $OUT"
else
    echo "$HEADER" > "$OUT"
fi

echo "sweep: building testbed image ..."
"${COMPOSE[@]}" build >/dev/null

run_condition() {
    local mode="$1" pow="$2" delay="$3" loss="$4" rate="$5"
    echo "sweep: mode=$mode pow=$pow delay=${delay:-none} loss=${loss:-none} rate=${rate:-none} (${ITER} iters)"
    # UDP mode needs the fixed-port echo Origin + agent-in-UDP overlay.
    local compose=("${COMPOSE[@]}")
    if [ "$mode" = "udp" ]; then
        compose+=(-f "$REPO_ROOT/docker/docker-compose.udpbench.yml")
    fi
    local out row
    out=$(BENCH_MODE="$mode" BENCH_BYTES="$BYTES" EDGE_POW_DIFFICULTY="$pow" \
          EDGE_DELAY="$delay" EDGE_LOSS="$loss" EDGE_RATE="$rate" \
          CLIENT_ITERATIONS="$ITER" \
          "${compose[@]}" up --no-build --abort-on-container-exit --exit-code-from client 2>&1 || true)
    row=$(printf '%s\n' "$out" | grep -m1 'RESULT ' | sed 's/.*RESULT //' | tr -d '\r')
    "${compose[@]}" down -v >/dev/null 2>&1 || true
    if [ -n "$row" ]; then
        echo "$mode,$pow,$row" >> "$OUT"
        echo "  -> $mode,$pow,$row"
    else
        echo "  !! no RESULT row — condition failed, skipping"
    fi
}

# One direct-baseline condition: same netem shaping on the server hop, no tunnel.
# Writes a row with mode=direct-<proto> and pow="-" (no PoW in the direct path).
run_baseline_condition() {
    local proto="$1" delay="$2" loss="$3" rate="$4"
    local target
    if [ "$proto" = "quic" ]; then target="10.5.0.2:4433"; else target="10.5.0.3:8080"; fi
    echo "sweep: baseline proto=$proto delay=${delay:-none} loss=${loss:-none} rate=${rate:-none} (${ITER} iters)"
    local out row
    out=$(DIRECT_PROTO="$proto" DIRECT_TARGET="$target" \
          BENCH_MODE="$BASELINE_BENCH_MODE" BENCH_BYTES="$BYTES" \
          EDGE_DELAY="$delay" EDGE_LOSS="$loss" EDGE_RATE="$rate" \
          CLIENT_ITERATIONS="$ITER" \
          "${COMPOSE[@]}" up --no-build --abort-on-container-exit --exit-code-from client 2>&1 || true)
    row=$(printf '%s\n' "$out" | grep -m1 'RESULT ' | sed 's/.*RESULT //' | tr -d '\r')
    "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
    if [ -n "$row" ]; then
        echo "direct-$proto,-,$row" >> "$OUT"
        echo "  -> direct-$proto,-,$row"
    else
        echo "  !! no RESULT row — condition failed, skipping"
    fi
}

# The throughput dimension reuses the same run/baseline drivers: the tunnel sweep
# drives the client's throughput bench mode (MODES=throughput), and the baseline
# sweep drives direct_bench's throughput mode (BASELINE_BENCH_MODE=throughput).
BASELINE_BENCH_MODE=""
if [ "$THROUGHPUT" = "1" ]; then
    BASELINE_BENCH_MODE="throughput"
    MODES="throughput"
fi

if [ "$BASELINE" = "1" ]; then
    for proto in $BASELINE_PROTOS; do
        for delay in $DELAYS; do
            for loss in $LOSSES; do
                if [ -z "$RATES" ]; then
                    run_baseline_condition "$proto" "$delay" "$loss" ""
                else
                    for rate in $RATES; do
                        run_baseline_condition "$proto" "$delay" "$loss" "$rate"
                    done
                fi
            done
        done
    done
else
    for mode in $MODES; do
        for pow in $POWS; do
            for delay in $DELAYS; do
                for loss in $LOSSES; do
                    if [ -z "$RATES" ]; then
                        run_condition "$mode" "$pow" "$delay" "$loss" ""
                    else
                        for rate in $RATES; do
                            run_condition "$mode" "$pow" "$delay" "$loss" "$rate"
                        done
                    fi
                done
            done
        done
    done
fi

echo "sweep: wrote $(( $(wc -l < "$OUT") - 1 )) rows to $OUT"
