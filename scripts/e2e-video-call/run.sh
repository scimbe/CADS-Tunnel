#!/usr/bin/env bash
# Real end-to-end proof of the video-conferencing feature's channel-join + Noise +
# WebRTC-signaling pipeline (see crates/edge/src/ws_channel.rs, and
# scimbe/ct-agent's wasm/ -- ct-agent-wasm moved there as a sibling of the native
# ct-agent binary, one shared ct-common version for both; it's ct-agent for the
# browser, not CADS-Tunnel platform code, same reasoning that already moved the
# demo page itself to scimbe/CADS-webconference-demo). This script is CADS-Tunnel's
# own core regression test for ws_channel.rs/channel_broker.rs and stays fully
# self-contained -- setup.js mints its own test grants locally (see its own header
# comment) rather than depending on either external repo's own tooling; it only
# clones ct-agent to get ct-agent-wasm's SOURCE (built here, not vendored).
#
# Two independent "browser peers" (Alice, Bob), each driving their OWN instance of
# the actual compiled ct-agent-wasm module and a real WebSocket connection, join
# the SAME channel through the REAL, unmodified `ct-edge` binary's ws_channel.rs
# listener: real admission (a real signed possession-challenge response), real
# channel_broker pairing/relay, a real Noise_IK handshake, and real encrypted
# WebRTC signaling message exchange (offer/answer/ICE-candidate/bye) -- decrypted
# and decoded correctly on both sides.
#
# The ONLY thing not real here is the control plane's channel-membership lookup
# (mock-cp.js stands in for `POST /internal/channel/authorize` -- registering
# members for real needs a live OIDC session against the control plane, which is
# a separate, credentialed step tested in ct-control-plane's own suite). Every
# other component -- the edge binary, the WASM module, the WebSocket transport,
# the Noise handshake, the signaling protocol -- is the genuine, unmodified
# article.
#
# This is fully hermetic: builds everything itself in a throwaway container, runs
# entirely on loopback, and needs no live host or credentials.
#
#   scripts/e2e-video-call/run.sh
#
# Exit 0 + "E2E-OK" on success; non-zero + "E2E-FAIL" (from verify.js) otherwise.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# Which scimbe/ct-agent commit to build ct-agent-wasm from -- the workspace
# restructure that moved ct-agent-wasm in as a sibling of the native binary
# (before this, ct-agent had no wasm/ member at all). Bump deliberately.
CT_AGENT_REF="${CT_AGENT_REF:-v0.5.6}"

docker run --rm -m 3g --cpus 2 \
  -v "$REPO_ROOT":/work -w /work \
  -v ct-tunnel-target:/work/target \
  -v ct-e2e-video-call-agent-src:/agent-src \
  -v ct-e2e-video-call-agent-target:/agent-target \
  -v ct-build-cargo-registry:/usr/local/cargo/registry \
  -v ct-build-rustup:/usr/local/rustup \
  -v ct-wasm-bindgen-cli:/usr/local/cargo/bin-wbg \
  -e CT_AGENT_REF="$CT_AGENT_REF" \
  rust:1-slim bash -eu -o pipefail -c '
set -euo pipefail
export PATH=/usr/local/cargo/bin-wbg/bin:$PATH
export CARGO_TARGET_DIR=/agent-target
SCRIPTS=/work/scripts/e2e-video-call

apt-get update -qq >/dev/null
apt-get install -y -qq nodejs git >/dev/null

echo "== building ct-edge =="
(cd /work && CARGO_TARGET_DIR=/work/target cargo build -p ct-edge)

echo "== fetching scimbe/ct-agent@$CT_AGENT_REF (for ct-agent-wasm) =="
if [ ! -d /agent-src/.git ]; then
  git clone https://github.com/scimbe/ct-agent /agent-src
fi
git -C /agent-src fetch origin
git -C /agent-src checkout "$CT_AGENT_REF"

echo "== building ct-agent-wasm (wasm32) + JS glue =="
rustup target add wasm32-unknown-unknown >/dev/null 2>&1
(cd /agent-src && cargo build -p ct-agent-wasm --release --target wasm32-unknown-unknown)
if ! command -v wasm-bindgen >/dev/null; then
  cargo install wasm-bindgen-cli --version 0.2.126 --root /usr/local/cargo/bin-wbg
fi
mkdir -p /tmp/e2e-pkg
wasm-bindgen --target nodejs --out-dir /tmp/e2e-pkg /agent-target/wasm32-unknown-unknown/release/ct_agent_wasm.wasm

echo "== generating identities + minting grants =="
WASM_PKG_DIR=/tmp/e2e-pkg node "$SCRIPTS/setup.js"
# shellcheck source=/dev/null
source /tmp/e2e-env.sh

echo "== starting mock control-plane authorize endpoint =="
MOCK_CP_PORT=19701 node "$SCRIPTS/mock-cp.js" &
MOCK_CP_PID=$!

echo "== starting the real ct-edge binary =="
export CT_EDGE_LISTEN=127.0.0.1:14330
export CT_EDGE_CERT_OUT=/tmp/edge-cert.der
export CT_EDGE_WS_CHANNEL_LISTEN=127.0.0.1:19700
export CT_EDGE_CP_URL=http://127.0.0.1:19701
export CT_EDGE_ADMIN_TOKEN="$MOCK_CP_ADMIN_TOKEN_HEX"
./target/debug/ct-edge &
EDGE_PID=$!

cleanup() { kill "$MOCK_CP_PID" "$EDGE_PID" 2>/dev/null || true; }
trap cleanup EXIT

sleep 2
echo "== running the real two-peer channel-join + Noise + signaling flow =="
WASM_PKG_DIR=/tmp/e2e-pkg WS_URL=ws://127.0.0.1:19700/ws/channel \
  node "$SCRIPTS/verify.js"
'
