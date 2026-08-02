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

/// Noise message max size (RFC-fixed at 65535 -- the same buffer size
/// `ct_common::noise`'s own tests use, and what its 2-byte length prefix can
/// address). One fixed-size scratch buffer per call, sized for the worst case.
const NOISE_MAX_MESSAGE: usize = 65535;

// The pure, testable core behind NoiseHandshake/NoiseTransport below -- plain
// `Result<_, String>` (not JsError) for the same native-test reason as
// from_hex/hex32 above: constructing a JsError panics on a non-wasm target.
fn ik_initiator(local_private: &[u8; 32], remote_public: &[u8; 32]) -> Result<snow::HandshakeState, String> {
    ct_common::noise::client_handshake(local_private, remote_public).map_err(|e| e.to_string())
}
fn ik_responder(local_private: &[u8; 32]) -> Result<snow::HandshakeState, String> {
    ct_common::noise::origin_handshake(local_private).map_err(|e| e.to_string())
}

/// A Noise_IK handshake in progress -- the browser side of the SAME
/// authenticated key exchange a native channel member performs
/// (`ct_common::noise::client_handshake`/`origin_handshake`, the exact
/// primitives `ct-agent`'s own channel session uses under the hood). Exposes
/// `snow`'s own synchronous `write_message`/`read_message` step-by-step, since
/// a browser has no Rust-owned socket for an async driver to run against --
/// JavaScript owns the actual WebSocket and feeds bytes through this state
/// machine explicitly, one handshake message at a time.
///
/// Once `is_finished()` is true, call `into_transport()` (consumes this
/// handshake) to get the encrypted [`NoiseTransport`] session -- attempting
/// application messages before that point is a programmer error the caller
/// should never trigger, not a normal runtime condition, so it's an `Err`
/// rather than something silently tolerated.
#[wasm_bindgen]
pub struct NoiseHandshake {
    inner: Option<snow::HandshakeState>,
}

#[wasm_bindgen]
impl NoiseHandshake {
    /// The initiator side (mirrors `CT_CHANNEL_ROLE=initiate`): pins the
    /// peer's Noise public key up front, matching Noise_IK's "I know who I'm
    /// talking to" property for the initiator.
    #[wasm_bindgen(js_name = newInitiator)]
    pub fn new_initiator(local_noise_private_hex: &str, remote_noise_public_hex: &str) -> Result<NoiseHandshake, JsError> {
        let local = hex32(local_noise_private_hex).map_err(|e| JsError::new(&e))?;
        let remote = hex32(remote_noise_public_hex).map_err(|e| JsError::new(&e))?;
        let hs = ik_initiator(&local, &remote).map_err(|e| JsError::new(&e))?;
        Ok(NoiseHandshake { inner: Some(hs) })
    }

    /// The responder side (mirrors `CT_CHANNEL_ROLE=accept`): learns the
    /// peer's identity FROM the first handshake message (Noise_IK's own
    /// property), so it needs only its own private key up front.
    #[wasm_bindgen(js_name = newResponder)]
    pub fn new_responder(local_noise_private_hex: &str) -> Result<NoiseHandshake, JsError> {
        let local = hex32(local_noise_private_hex).map_err(|e| JsError::new(&e))?;
        let hs = ik_responder(&local).map_err(|e| JsError::new(&e))?;
        Ok(NoiseHandshake { inner: Some(hs) })
    }

    /// Produce the next handshake message to send to the peer (payload is
    /// almost always empty for the two Noise_IK handshake messages -- kept as
    /// a parameter since the protocol allows piggybacking early data).
    #[wasm_bindgen(js_name = writeMessage)]
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, JsError> {
        let hs = self.inner.as_mut().ok_or_else(|| JsError::new("handshake already consumed by into_transport()"))?;
        let mut buf = [0u8; NOISE_MAX_MESSAGE];
        let n = hs.write_message(payload, &mut buf).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(buf[..n].to_vec())
    }

    /// Consume a handshake message received from the peer.
    #[wasm_bindgen(js_name = readMessage)]
    pub fn read_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, JsError> {
        let hs = self.inner.as_mut().ok_or_else(|| JsError::new("handshake already consumed by into_transport()"))?;
        let mut buf = [0u8; NOISE_MAX_MESSAGE];
        let n = hs.read_message(msg, &mut buf).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(buf[..n].to_vec())
    }

    #[wasm_bindgen(js_name = isFinished)]
    pub fn is_finished(&self) -> Result<bool, JsError> {
        let hs = self.inner.as_ref().ok_or_else(|| JsError::new("handshake already consumed by into_transport()"))?;
        Ok(hs.is_handshake_finished())
    }

    /// Transition to the encrypted transport session once `is_finished()` is
    /// true -- consumes this handshake, matching `snow`'s own one-way
    /// state transition (a finished handshake can't be "used" for more
    /// handshake messages afterward, only for real traffic).
    #[wasm_bindgen(js_name = intoTransport)]
    pub fn into_transport(&mut self) -> Result<NoiseTransport, JsError> {
        let hs = self.inner.take().ok_or_else(|| JsError::new("handshake already consumed by into_transport()"))?;
        let t = hs.into_transport_mode().map_err(|e| JsError::new(&e.to_string()))?;
        Ok(NoiseTransport { inner: t })
    }
}

/// An established, encrypted Noise_IK session -- the browser side of a real
/// channel's application-data traffic (SDP offers/answers, ICE candidates,
/// and eventually media, once WebRTC signaling is layered on top of this).
#[wasm_bindgen]
pub struct NoiseTransport {
    inner: snow::TransportState,
}

#[wasm_bindgen]
impl NoiseTransport {
    #[wasm_bindgen]
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
        let mut buf = [0u8; NOISE_MAX_MESSAGE];
        let n = self.inner.write_message(plaintext, &mut buf).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(buf[..n].to_vec())
    }

    #[wasm_bindgen]
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
        let mut buf = [0u8; NOISE_MAX_MESSAGE];
        let n = self.inner.read_message(ciphertext, &mut buf).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(buf[..n].to_vec())
    }
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

    #[test]
    fn noise_ik_handshake_and_transport_round_trip_via_the_pure_helpers() {
        // The native-testable core behind NoiseHandshake/NoiseTransport (plain
        // snow types, no JsError) -- proves the SAME two-message Noise_IK flow
        // ct_common::noise's own frozen `noise_ik_handshake_establishes_e2e`
        // test exercises natively, now driven through ik_initiator/ik_responder
        // exactly as the wasm-bindgen wrapper above will drive it.
        let origin = ct_common::noise::generate_static_keypair();
        let client = ct_common::noise::generate_static_keypair();

        let mut ini = ik_initiator(&client.private, &origin.public).unwrap();
        let mut resp = ik_responder(&origin.private).unwrap();

        let mut buf = [0u8; NOISE_MAX_MESSAGE];
        let mut scratch = [0u8; NOISE_MAX_MESSAGE];
        let n = ini.write_message(&[], &mut buf).unwrap();
        resp.read_message(&buf[..n], &mut scratch).unwrap();
        let n = resp.write_message(&[], &mut buf).unwrap();
        ini.read_message(&buf[..n], &mut scratch).unwrap();

        assert!(ini.is_handshake_finished());
        assert!(resp.is_handshake_finished());

        let mut ini_t = ini.into_transport_mode().unwrap();
        let mut resp_t = resp.into_transport_mode().unwrap();

        let n = ini_t.write_message(b"sdp-offer: v=0...", &mut buf).unwrap();
        let m = resp_t.read_message(&buf[..n], &mut scratch).unwrap();
        assert_eq!(&scratch[..m], b"sdp-offer: v=0...");

        let n = resp_t.write_message(b"sdp-answer: v=0...", &mut buf).unwrap();
        let m = ini_t.read_message(&buf[..n], &mut scratch).unwrap();
        assert_eq!(&scratch[..m], b"sdp-answer: v=0...");
    }
}
