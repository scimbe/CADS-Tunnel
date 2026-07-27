#!/usr/bin/env bash
# Human demo (issue #7) — SHOW the tunnel working, don't just assert it.
#
# Narrates, step by step, that a client reaches a PRIVATE origin (bound to
# 127.0.0.1, unreachable from outside) ONLY through the tunnel, over the central
# edge, and reports the round-trip path (via=quic|tcp) and latency. Meant to be
# understandable by someone without Rust/CLI knowledge.
#
# Local (loopback) demo — no central host needed, builds its own edge+cert via
# the compose smoke path is out of scope here; this variant onboards against an
# already-running control plane + edge:
#   CENTRAL=<host> EDGE_CERT=/path/to/edge-cert.der ./scripts/demo.sh
#   ... CT_CLIENT_FORCE_TCP=1 ./scripts/demo.sh    # show the TCP fallback path
#   ... CT_CLIENT_ITERATIONS=50 ./scripts/demo.sh  # more samples for the latency read
#
# Prereqs: built binaries (BIN=./target/debug), socat, curl, jq.
set -euo pipefail

CENTRAL="${CENTRAL:?set CENTRAL=<host> (control plane :8090, edge :4433)}"
EDGE_CERT="${EDGE_CERT:?set EDGE_CERT=<path to edge-cert.der from the central host>}"
CP_URL="${CP_URL:-http://${CENTRAL}:8090}"
EDGE="${EDGE:-${CENTRAL}:4433}"
TENANT="${TENANT:-t1}"
ORIGIN_PORT="${ORIGIN_PORT:-8080}"
AGENT_ID="${AGENT_ID:-demo-agent}"
BIN="${BIN:-./target/debug}"
WORK="$(umask 077 && mktemp -d)"
chmod 700 "$WORK"
CAP="$WORK/capability.bin"
ORIGIN_LOG="$WORK/origin.log"
SECRET="private-origin-$(date +%s)"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
step() { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m✗ DEMO FAILED: %s\033[0m\n' "$*" >&2; exit 1; }
cleanup() {
  [ -n "${AGENT_PID:-}" ] && kill "$AGENT_PID" 2>/dev/null || true
  [ -n "${ORIGIN_PID:-}" ] && kill "$ORIGIN_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

[ -f "$EDGE_CERT" ] || fail "edge cert not found at EDGE_CERT=$EDGE_CERT"
[ -x "$BIN/ct-agent" ] && [ -x "$BIN/ct-client" ] || fail "binaries not built — build the workspace first"
command -v socat >/dev/null || fail "socat is required (apt-get install socat)"
command -v curl >/dev/null || fail "curl is required"
command -v jq >/dev/null || fail "jq is required (apt-get install jq)"

bold "=== CADS-Tunnel demo: reaching a PRIVATE origin through the tunnel ==="

# 1. A private origin, bound to loopback, that echoes and logs every request.
# The per-request marker is written to the LOG FILE by a tiny handler, then the
# handler execs `cat` to echo — the marker never touches stdout, which is the
# tunnel data path. (Logging inline in `socat SYSTEM:"…"` corrupted the echoed
# payload: socat wires the child's stdout AND stderr to the data channel, and the
# nested shell quoting leaked `[origin]` into the stream → `tunnel response
# mismatch`, #7 re-test. A handler script sidesteps both traps.)
step "Starting a PRIVATE origin on 127.0.0.1:${ORIGIN_PORT} (echo; logs each request)"
ORIGIN_HANDLER="$WORK/origin-handler.sh"
cat > "$ORIGIN_HANDLER" <<HANDLER
#!/bin/sh
printf '[origin] served a request through the tunnel\n' >> "$ORIGIN_LOG"
exec cat
HANDLER
chmod +x "$ORIGIN_HANDLER"
socat "TCP-LISTEN:${ORIGIN_PORT},reuseaddr,fork,bind=127.0.0.1" EXEC:"$ORIGIN_HANDLER" \
      >/dev/null 2>&1 &
ORIGIN_PID=$!
sleep 1
ok "Origin is up on 127.0.0.1:${ORIGIN_PORT} — bound to loopback, so it is NOT reachable from another host."

# 2. Contrast: a 'remote' party (the public interface) cannot reach it.
step "Contrast — is the origin reachable directly from outside loopback?"
if timeout 2 bash -c "exec 3<>/dev/tcp/${CENTRAL}/${ORIGIN_PORT}" 2>/dev/null; then
  echo "   (reachable — note: on a single-host demo the origin shares this box)"
else
  ok "Direct connection to the origin from the public side is refused — it is genuinely private."
fi

# 3. Join token + onboard the agent (it registers on the central edge and serves).
step "Onboarding the agent against the central control plane + edge"
TOKEN="${CT_JOIN_TOKEN:-$(
  curl --connect-timeout 5 --max-time 10 -fsS -X POST "$CP_URL/enroll/issue" -H 'content-type: application/json' \
    -d "{\"tenant\":\"$TENANT\"}" \
    | jq -r '.token // empty' 2>/dev/null
)}"
[ -n "$TOKEN" ] || fail "could not mint a join token at $CP_URL/enroll/issue"
CT_AGENT_CP_URL="$CP_URL" CT_AGENT_JOIN_TOKEN="$TOKEN" CT_AGENT_ID="$AGENT_ID" \
CT_AGENT_EDGE="$EDGE" CT_AGENT_ORIGIN="127.0.0.1:${ORIGIN_PORT}" \
CT_AGENT_EDGE_CERT="$EDGE_CERT" CT_AGENT_CAPABILITY_OUT="$CAP" \
  "$BIN/ct-agent" onboard >"$WORK/agent.log" 2>&1 &
AGENT_PID=$!
for _ in $(seq 1 30); do [ -s "$CAP" ] && break; sleep 0.5; done
[ -s "$CAP" ] || fail "agent did not register (see $WORK/agent.log)"
ok "Agent onboarded and registered on the edge (${EDGE})."

# 4. A client reaches the private origin THROUGH the tunnel — visible content + timing.
MODE_NOTE="QUIC"; [ -n "${CT_CLIENT_FORCE_TCP:-}" ] && MODE_NOTE="TCP fallback"
step "A client sends \"${SECRET}\" through the tunnel (path: ${MODE_NOTE}) …"
START=$(date +%s%3N)
OUT="$(CT_CLIENT_CAPABILITY="$CAP" CT_CLIENT_EDGE_CERT="$EDGE_CERT" CT_CLIENT_PAYLOAD="$SECRET" \
        "$BIN/ct-client" 2>&1)" || true
END=$(date +%s%3N)
VIA="$(printf '%s' "$OUT" | sed -n 's/.*via=\([a-z]*\).*/\1/p' | head -1)"

if printf '%s' "$OUT" | grep -q "round-trip OK"; then
  ok "The client received \"${SECRET}\" back THROUGH the tunnel — via=${VIA:-?}, round-trip $((END-START)) ms."
  echo "   ↳ The PRIVATE origin's own log confirms it was reached only via the tunnel:"
  sed 's/^/     /' "$ORIGIN_LOG" 2>/dev/null || true

  # 5. Live performance — N timed round-trips through the same path (acceptance #4).
  ITERS="${CT_CLIENT_ITERATIONS:-20}"
  step "Measuring live performance — ${ITERS} round-trips through the tunnel (path: ${MODE_NOTE}) …"
  BENCH="$(CT_CLIENT_CAPABILITY="$CAP" CT_CLIENT_EDGE_CERT="$EDGE_CERT" CT_CLIENT_PAYLOAD="$SECRET" \
            CT_CLIENT_ITERATIONS="$ITERS" "$BIN/ct-client" 2>&1)" || true
  STATS="$(printf '%s' "$BENCH" | sed -n 's/.*bench \([0-9]*\/[0-9]*\) iterations, \(mean.*\)/\1: \2/p' | head -1)"
  if [ -n "$STATS" ]; then
    ok "Live latency over the tunnel — ${STATS}."
  else
    echo "   (bench produced no summary; raw: $(printf '%s' "$BENCH" | tail -1))"
  fi

  bold "=== DEMO OK — real client traffic reached the private origin over the tunnel (via=${VIA:-?}) ==="
else
  printf '%s\n' "$OUT" >&2
  fail "no tunnel round-trip (agent log: $WORK/agent.log)"
fi
