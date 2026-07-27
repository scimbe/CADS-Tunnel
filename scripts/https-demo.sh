#!/usr/bin/env bash
# HTTPS-through-the-tunnel demo (issue #22) — a REAL HTTPS website as the private
# origin, reached through the tunnel with the cert validated CLIENT-SIDE.
#
# Proves the v1 (Mesh Plane) claim: TLS terminates AT THE ORIGIN, not the edge.
# A self-signed HTTPS site is served on loopback; the agent bridges the tunnel to
# it (provider-blind, raw bytes); the client runs in forward mode so a normal
# `curl --cacert` speaks TLS end-to-end through the tunnel to the origin and gets
# a genuine HTTP 200. The edge only ever relays TLS-over-Noise ciphertext.
#
#   CENTRAL=<host-ip> EDGE_CERT=/path/to/edge-cert.der ./scripts/https-demo.sh
#
# Browser Plane (public hostname + Let's Encrypt over SNI) is deferred post-v1
# (ADR-0010) and out of scope here — this is the TLS-terminates-at-origin path.
#
# Prereqs: built binaries (BIN=./target/debug), openssl, curl, jq. CENTRAL must be an
# IP (the agent's CT_AGENT_EDGE needs a numeric socket address).
set -euo pipefail

CENTRAL="${CENTRAL:?set CENTRAL=<host ip> (control plane :8090, edge :4433)}"
EDGE_CERT="${EDGE_CERT:?set EDGE_CERT=<path to edge-cert.der>}"
CP_URL="${CP_URL:-http://${CENTRAL}:8090}"
EDGE="${EDGE:-${CENTRAL}:4433}"
TENANT="${TENANT:-t1}"
ORIGIN_PORT="${ORIGIN_PORT:-8443}"      # the private HTTPS origin (loopback)
CLIENT_LISTEN="${CLIENT_LISTEN:-18443}" # the client's local forward port
AGENT_ID="${AGENT_ID:-https-demo}"
BIN="${BIN:-./target/debug}"
W="$(umask 077 && mktemp -d)"
chmod 700 "$W"
OCERT="$W/origin-cert.pem"   # origin's self-signed cert (curl trusts this)
OKEY="$W/origin-key.pem"
CAP="$W/capability.bin"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
step() { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m✗ HTTPS DEMO FAILED: %s\033[0m\n' "$*" >&2; exit 1; }
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$W"; }
trap cleanup EXIT

[ -f "$EDGE_CERT" ] || fail "edge cert not found at $EDGE_CERT"
[ -x "$BIN/ct-agent" ] && [ -x "$BIN/ct-client" ] || fail "binaries not built (BIN=$BIN)"
command -v openssl >/dev/null || fail "openssl is required"
command -v curl >/dev/null || fail "curl is required"
command -v jq >/dev/null || fail "jq is required (apt-get install jq)"

bold "=== CADS-Tunnel HTTPS demo: a real HTTPS website through the tunnel ==="

# 1. A private HTTPS origin on loopback with its OWN self-signed cert (SAN
#    127.0.0.1). TLS terminates HERE — the tunnel never sees the plaintext.
step "Generating the origin's self-signed cert (SAN IP:127.0.0.1) and starting HTTPS on 127.0.0.1:${ORIGIN_PORT}"
openssl req -x509 -newkey rsa:2048 -keyout "$OKEY" -out "$OCERT" -days 1 -nodes \
  -subj "/CN=ct-private-origin" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1 \
  || fail "openssl could not generate the origin cert"
openssl s_server -accept "127.0.0.1:${ORIGIN_PORT}" -cert "$OCERT" -key "$OKEY" -www -quiet \
  >/dev/null 2>&1 &
PIDS+=($!); sleep 1
ok "Private HTTPS origin up (bound to loopback — not reachable from another host)."

# 2. Onboard the agent; it bridges the tunnel to the loopback HTTPS origin as raw
#    bytes (provider-blind — it never terminates TLS).
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
  "$BIN/ct-agent" onboard >"$W/agent.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 30); do [ -s "$CAP" ] && break; sleep 0.5; done
[ -s "$CAP" ] || fail "agent did not register (see $W/agent.log)"
ok "Agent onboarded and bridging the tunnel to the private HTTPS origin."

# 3. Start the client in FORWARD mode: a local TCP port that rides the tunnel.
step "Starting the client's local forward port on 127.0.0.1:${CLIENT_LISTEN} (rides the tunnel)"
CT_CLIENT_CAPABILITY="$CAP" CT_CLIENT_EDGE_CERT="$EDGE_CERT" \
CT_CLIENT_MODE=forward CT_CLIENT_LISTEN="127.0.0.1:${CLIENT_LISTEN}" \
  "$BIN/ct-client" >"$W/client.log" 2>&1 &
PIDS+=($!); sleep 2
ok "Forward port up — anything connecting here tunnels to the private origin."

# 4. A normal curl speaks HTTPS end-to-end THROUGH the tunnel, validating the
#    origin's cert with --cacert (proving TLS terminated at the origin).
step "curl --cacert https://127.0.0.1:${CLIENT_LISTEN}/ — real HTTPS through the tunnel, cert validated client-side"
CODE="$(curl -sS --cacert "$OCERT" -o "$W/page.html" -w '%{http_code}' \
        --max-time 15 "https://127.0.0.1:${CLIENT_LISTEN}/" 2>"$W/curl.err" || true)"
if [ "$CODE" = "200" ]; then
  ok "HTTP ${CODE} over TLS through the tunnel — and curl VALIDATED the origin's cert (--cacert), so TLS terminated at the origin, not the edge."
  echo "   ↳ first line the origin served through the tunnel:"
  sed -n '1p' "$W/page.html" 2>/dev/null | sed 's/^/     /' || true
  bold "=== HTTPS DEMO OK — a real HTTPS website rode the tunnel; cert validated at the client, ciphertext-only at the edge ==="
else
  echo "   curl said: $(tail -1 "$W/curl.err" 2>/dev/null)"
  fail "no HTTPS round-trip through the tunnel (http_code=${CODE:-none}; agent log $W/agent.log, client log $W/client.log)"
fi
