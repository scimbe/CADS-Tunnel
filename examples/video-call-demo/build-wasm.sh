#!/usr/bin/env bash
# Builds ct-agent-wasm for the browser (wasm-bindgen --target web) into
# examples/video-call-demo/pkg/ -- generated build output (gitignored), not
# source. Hermetic: runs entirely inside a throwaway container.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="$REPO_ROOT/examples/video-call-demo/pkg"

docker run --rm -m 2g --cpus 2 \
  -v "$REPO_ROOT":/work -w /work \
  -v ct-tunnel-target:/work/target \
  -v ct-build-cargo-registry:/usr/local/cargo/registry \
  -v ct-build-rustup:/usr/local/rustup \
  -v ct-wasm-bindgen-cli:/usr/local/cargo/bin-wbg \
  rust:1-slim bash -c '
set -euo pipefail
export PATH=/usr/local/cargo/bin-wbg/bin:$PATH
rustup target add wasm32-unknown-unknown >/dev/null 2>&1
cargo build -p ct-agent-wasm --release --target wasm32-unknown-unknown
if ! command -v wasm-bindgen >/dev/null; then
  cargo install wasm-bindgen-cli --version 0.2.126 --root /usr/local/cargo/bin-wbg
fi
mkdir -p /work/examples/video-call-demo/pkg
wasm-bindgen --target web --out-dir /work/examples/video-call-demo/pkg \
  target/wasm32-unknown-unknown/release/ct_agent_wasm.wasm
'

echo "built: $OUT_DIR"
