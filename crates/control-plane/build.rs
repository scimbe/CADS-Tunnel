//! Populates `$OUT_DIR/ct_agent_wasm.{js,bg.wasm}` for `portal_api.rs`'s `include_bytes!`
//! calls -- the compiled `ct-agent-wasm` bundle (in-browser Agent-Fabric channel identity
//! generation + attestation signing) the portal's self-service channel-claim page
//! (`GET /portal/channels/:channel/claim`) loads client-side and serves back out at
//! `GET /portal/static/ct_agent_wasm.js` / `ct_agent_wasm_bg.wasm`.
//!
//! The REAL files live at `wasm-pkg/` in this crate's own directory (gitignored -- a
//! generated build artifact, not source, same as `target/`) and are only ever produced by
//! `scripts/build-ct-agent-wasm.sh` (manual/local rebuild) or automatically inside
//! `docker/Dockerfile`'s `wasm-builder` stage (every real image build) -- both build
//! `ct-agent-wasm` from a pinned `scimbe/ct-agent` commit via `wasm-bindgen --target web`.
//!
//! When `wasm-pkg/` hasn't been populated -- true for a plain `cargo build`/`cargo test`
//! with no prior wasm build, which is exactly what this workspace's own hermetic gate runs
//! (no Docker-in-Docker, no network) -- this falls back to a tiny inert placeholder so the
//! workspace build/test suite NEVER depends on Docker or network access. It only means the
//! claim page's in-browser identity generation stays inert (its `wasm.generate_holder_identity()`
//! etc. calls throw) until a real deploy build actually runs the wasm-build step. See
//! `portal_api.rs`'s own doc comment on `CT_AGENT_WASM_JS` for the full picture.

use std::env;
use std::fs;
use std::path::Path;

const PLACEHOLDER_JS: &str = r#"// PLACEHOLDER -- NOT the real ct-agent-wasm bundle (see crates/control-plane/build.rs).
// Populate crates/control-plane/wasm-pkg/ via scripts/build-ct-agent-wasm.sh (or a real
// docker/Dockerfile build, whose wasm-builder stage does this automatically) to make the
// claim page's in-browser identity generation actually work; until then every export below
// just throws.
function unavailable() { throw new Error("ct-agent-wasm placeholder: run scripts/build-ct-agent-wasm.sh"); }
export default function init() { return Promise.reject(new Error("ct-agent-wasm placeholder: run scripts/build-ct-agent-wasm.sh")); }
export function generate_holder_identity() { unavailable(); }
export function generate_noise_identity() { unavailable(); }
export function channel_id_for_link() { unavailable(); }
export function holderSign() { unavailable(); }
"#;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR set by cargo");
    let src_dir = Path::new(&manifest_dir).join("wasm-pkg");
    let js_src = src_dir.join("ct_agent_wasm.js");
    let wasm_src = src_dir.join("ct_agent_wasm_bg.wasm");
    let js_dst = Path::new(&out_dir).join("ct_agent_wasm.js");
    let wasm_dst = Path::new(&out_dir).join("ct_agent_wasm_bg.wasm");

    if js_src.exists() && wasm_src.exists() {
        fs::copy(&js_src, &js_dst).expect("copy ct_agent_wasm.js into OUT_DIR");
        fs::copy(&wasm_src, &wasm_dst).expect("copy ct_agent_wasm_bg.wasm into OUT_DIR");
    } else {
        fs::write(&js_dst, PLACEHOLDER_JS).expect("write placeholder ct_agent_wasm.js");
        fs::write(&wasm_dst, []).expect("write placeholder ct_agent_wasm_bg.wasm");
    }

    // Re-run this script (and therefore re-embed) whenever the real wasm-pkg output changes
    // or newly appears/disappears -- otherwise a stale OUT_DIR copy would survive a rebuild.
    println!("cargo:rerun-if-changed={}", js_src.display());
    println!("cargo:rerun-if-changed={}", wasm_src.display());
}
