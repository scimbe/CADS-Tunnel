//! The browser side of an Agent-Fabric channel member: `ct-common`'s
//! identity/handshake/channel-framing primitives, exposed to JavaScript via
//! `wasm-bindgen`. This is NOT a port of `ct-agent` (which depends on
//! `quinn`/raw UDP/`socket2`, none of which exist in a browser) -- it produces
//! and consumes the exact same wire bytes a native member does, over whatever
//! transport the caller provides (a WebSocket bridge to the edge, not yet
//! built). Every function here is a thin, allocation-cheap wrapper: the real
//! logic lives in `ct_common`, verified once there.

use wasm_bindgen::prelude::*;

/// Panics inside wasm otherwise surface only as an opaque "unreachable
/// executed" in the browser console -- this routes them through `console.error`
/// with the real Rust message/location instead. A no-op on native targets.
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    #[cfg(target_arch = "wasm32")]
    console_error_panic_hook::set_once();
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// Plain `String` errors here (not `JsError`) deliberately: `JsError`/`JsValue`
// call into imported JS functions even just to construct, which panics on a
// native (non-wasm) target -- that would make these pure, otherwise-plain
// helpers untestable with `cargo test`. Converted to `JsError` only at the
// `#[wasm_bindgen]`-exposed boundary below, where a real JS runtime exists.
fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("hex string must have an even length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid hex character".to_string()))
        .collect()
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    let v = from_hex(s)?;
    <[u8; 32]>::try_from(v.as_slice()).map_err(|_| "expected 32 bytes (64 hex chars)".to_string())
}

/// A freshly generated holder identity (ed25519) -- the channel member's own,
/// stable identity, the same key the portal's Topology Editor uses as a node
/// id (a topology node id IS the agent's holder public key). Mirrors what
/// `ct-agent channel init` prints natively.
#[wasm_bindgen]
pub struct HolderIdentity {
    public_hex: String,
    private_hex: String,
}

#[wasm_bindgen]
impl HolderIdentity {
    #[wasm_bindgen(getter)]
    pub fn public_hex(&self) -> String {
        self.public_hex.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn private_hex(&self) -> String {
        self.private_hex.clone()
    }
}

/// Generate a fresh holder identity (ed25519 keypair), entirely in-browser --
/// the private key is never sent anywhere by this function; the caller decides
/// what to do with it (e.g. hold it only in page memory for the session).
#[wasm_bindgen]
pub fn generate_holder_identity() -> HolderIdentity {
    use ed25519_dalek::SigningKey;
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    HolderIdentity {
        public_hex: to_hex(sk.verifying_key().as_bytes()),
        private_hex: to_hex(&sk.to_bytes()),
    }
}

/// A freshly generated Noise (X25519) static keypair -- the channel member's
/// transport key, distinct from its holder identity (mirrors ct-agent's
/// CT_CHANNEL_NOISE_KEY, separate from CT_CHANNEL_HOLDER_KEY).
#[wasm_bindgen]
pub struct NoiseIdentity {
    public_hex: String,
    private_hex: String,
}

#[wasm_bindgen]
impl NoiseIdentity {
    #[wasm_bindgen(getter)]
    pub fn public_hex(&self) -> String {
        self.public_hex.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn private_hex(&self) -> String {
        self.private_hex.clone()
    }
}

/// Generate a fresh Noise static keypair, using ct_common's own generator --
/// bit-for-bit the same function a native ct-agent calls.
#[wasm_bindgen]
pub fn generate_noise_identity() -> NoiseIdentity {
    let kp = ct_common::noise::generate_static_keypair();
    NoiseIdentity {
        public_hex: to_hex(&kp.public),
        private_hex: to_hex(&kp.private),
    }
}

/// Derive the deterministic channel id for the link between two holder keys
/// under a channel operator -- the exact same computation
/// `ct_common::channel::channel_id_for_link` performs natively, so a browser
/// peer and a native peer independently compute the identical id with no
/// coordination round-trip (order-independent: swapping holder_a/holder_b
/// hex arguments yields the same result).
#[wasm_bindgen]
pub fn channel_id_for_link(operator_pubkey_hex: &str, holder_a_hex: &str, holder_b_hex: &str) -> Result<String, JsError> {
    let operator = hex32(operator_pubkey_hex).map_err(|e| JsError::new(&e))?;
    let a = hex32(holder_a_hex).map_err(|e| JsError::new(&e))?;
    let b = hex32(holder_b_hex).map_err(|e| JsError::new(&e))?;
    let id = ct_common::channel::channel_id_for_link(&operator, &a, &b);
    Ok(to_hex(&id.0))
}

/// Frame a Noise wire message for a byte-stream transport (2-byte big-endian
/// length prefix + body) -- the exact framing a native channel member uses,
/// so a browser peer's bytes are indistinguishable on the wire.
#[wasm_bindgen]
pub fn frame_message(msg: &[u8]) -> Vec<u8> {
    ct_common::noise::frame(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_id_for_link_matches_the_native_computation_and_is_order_independent() {
        let op = [0x11u8; 32];
        let a = [0x22u8; 32];
        let b = [0x33u8; 32];
        let native = ct_common::channel::channel_id_for_link(&op, &a, &b);

        let via_wasm_wrapper = channel_id_for_link(&to_hex(&op), &to_hex(&a), &to_hex(&b)).unwrap();
        assert_eq!(via_wasm_wrapper, to_hex(&native.0));

        // Order-independence survives the hex round trip too.
        let swapped = channel_id_for_link(&to_hex(&op), &to_hex(&b), &to_hex(&a)).unwrap();
        assert_eq!(via_wasm_wrapper, swapped);
    }

    #[test]
    fn from_hex_rejects_odd_length_and_bad_characters() {
        assert!(from_hex("abc").is_err());
        assert!(from_hex("zz").is_err());
        assert_eq!(from_hex("00ff").unwrap(), vec![0x00, 0xff]);
    }

    #[test]
    fn generated_identities_round_trip_through_hex() {
        let h = generate_holder_identity();
        assert_eq!(h.public_hex().len(), 64);
        assert_eq!(h.private_hex().len(), 64);
        let n = generate_noise_identity();
        assert_eq!(n.public_hex().len(), 64);
        assert_eq!(n.private_hex().len(), 64);
    }
}
