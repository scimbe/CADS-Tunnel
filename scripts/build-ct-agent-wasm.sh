#!/usr/bin/env bash
# Builds ct-agent-wasm -- the browser Agent-Fabric channel identity/attestation primitives
# (generate_holder_identity, generate_noise_identity, channel_id_for_link, holderSign) -- from
# scimbe/ct-agent's own wasm/ workspace member, for the portal's self-service channel-claim
# page (crates/control-plane/src/portal_api.rs's claim_html) to embed via
# crates/control-plane/build.rs's include_bytes! and serve at
# GET /portal/static/ct_agent_wasm{.js,_bg.wasm}.
#
# Same hermetic recipe as scripts/e2e-video-call/run.sh (which builds the same crate
# --target nodejs, for its own server-side E2E harness) and CADS-DEMO-sort's own
# build-wasm.sh -- only the wasm-bindgen --target differs here (`web`, for a real browser
# `<script type=module>`) and the output lands in this crate's wasm-pkg/ instead of a
# top-level pkg/.
#
# This script is for a manual/local rebuild only -- a real `docker build` (docker/Dockerfile)
# runs the equivalent steps itself in its own `wasm-builder` stage, so a plain `docker build`
# produces a fully self-contained image with no separate pre-build step required. Bump
# CT_AGENT_REF in BOTH places together when moving to a newer scimbe/ct-agent commit.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$REPO_ROOT/crates/control-plane/wasm-pkg"

# Pin by commit SHA, not a branch -- bump deliberately. scimbe/ct-agent's actual HEAD as of
# this feature's build (2026-08-12), the commit that tightened the TCP-fallback keepalive
# (ct-agent#15) -- includes the wasm/ crate at v0.4.2, unchanged by that commit.
CT_AGENT_REF="${CT_AGENT_REF:-v0.6.9}"

mkdir -p "$OUT_DIR"

docker run --rm -m 2g --cpus 2 \
  -v "$OUT_DIR":/out \
  -v ct-portal-wasm-agent-src:/agent-src \
  -v ct-portal-wasm-cargo-target:/cargo-target \
  -v ct-build-cargo-registry:/usr/local/cargo/registry \
  -v ct-build-rustup:/usr/local/rustup \
  -v ct-wasm-bindgen-cli:/usr/local/cargo/bin-wbg \
  -e CT_AGENT_REF="$CT_AGENT_REF" \
  rust:1-slim-bookworm bash -c '
set -euo pipefail
export PATH=/usr/local/cargo/bin-wbg/bin:$PATH
export CARGO_TARGET_DIR=/cargo-target
apt-get update -qq >/dev/null && apt-get install -y -qq git >/dev/null

if [ ! -d /agent-src/.git ]; then
  git clone https://github.com/scimbe/ct-agent /agent-src
fi
git -C /agent-src fetch origin
git -C /agent-src checkout "'"$CT_AGENT_REF"'"

cd /agent-src
rustup target add wasm32-unknown-unknown >/dev/null 2>&1
cargo build -p ct-agent-wasm --release --target wasm32-unknown-unknown
if ! command -v wasm-bindgen >/dev/null; then
  cargo install wasm-bindgen-cli --version 0.2.126 --root /usr/local/cargo/bin-wbg
fi
wasm-bindgen --target web --out-dir /out \
  /cargo-target/wasm32-unknown-unknown/release/ct_agent_wasm.wasm
'

echo "built: $OUT_DIR (from ct-agent@$CT_AGENT_REF)"
echo "run 'cargo build -p ct-control-plane' (or the full workspace build) to pick it up -- build.rs re-embeds it automatically."
