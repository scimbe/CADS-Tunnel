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

/// WebRTC signaling messages -- what actually rides over a [`NoiseTransport`]
/// session (encrypt the encoded bytes below, send over the WebSocket channel;
/// decrypt the peer's bytes, decode back into one of these). This is
/// deliberately a thin, self-delimiting wire format for the standard WebRTC
/// offer/answer/trickle-ICE dance -- it carries the SDP/candidate text
/// verbatim (browsers generate/consume that themselves via
/// `RTCPeerConnection`; this crate never parses SDP), it just gets it
/// authentically and confidentially to the peer over the SAME Agent-Fabric
/// channel session identity/admission already secures, instead of needing a
/// separate signaling server (the usual extra moving part in a WebRTC app).
///
/// Wire form: `type(1) | ...fields`, each string field length-prefixed
/// (`u16` BE for SDP text, `u8` for the shorter ICE `sdpMid`) so multiple
/// fields concatenate unambiguously.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SignalMessage {
    Offer { sdp: String },
    Answer { sdp: String },
    /// `sdp_mline_index` is `u16::MAX` standing in for "absent" (`None`) --
    /// WebRTC's own `RTCIceCandidateInit.sdpMLineIndex` is optional and a real
    /// index never reaches anywhere close to that value.
    IceCandidate { candidate: String, sdp_mid: Option<String>, sdp_mline_index: Option<u16> },
    /// An explicit "hanging up" signal -- lets the peer tear down its
    /// `RTCPeerConnection` promptly instead of waiting on an ICE-failure
    /// timeout when the other side just closes the underlying channel.
    Bye,
}

const SIGNAL_TYPE_OFFER: u8 = 1;
const SIGNAL_TYPE_ANSWER: u8 = 2;
const SIGNAL_TYPE_ICE: u8 = 3;
const SIGNAL_TYPE_BYE: u8 = 4;
const SIGNAL_NO_MLINE_INDEX: u16 = u16::MAX;

impl SignalMessage {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            SignalMessage::Offer { sdp } => {
                out.push(SIGNAL_TYPE_OFFER);
                push_u16_str(&mut out, sdp);
            }
            SignalMessage::Answer { sdp } => {
                out.push(SIGNAL_TYPE_ANSWER);
                push_u16_str(&mut out, sdp);
            }
            SignalMessage::IceCandidate { candidate, sdp_mid, sdp_mline_index } => {
                out.push(SIGNAL_TYPE_ICE);
                push_u16_str(&mut out, candidate);
                push_u8_str(&mut out, sdp_mid.as_deref().unwrap_or(""));
                out.extend_from_slice(&sdp_mline_index.unwrap_or(SIGNAL_NO_MLINE_INDEX).to_be_bytes());
            }
            SignalMessage::Bye => out.push(SIGNAL_TYPE_BYE),
        }
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut cur = bytes;
        let kind = take_u8(&mut cur)?;
        match kind {
            SIGNAL_TYPE_OFFER => Ok(SignalMessage::Offer { sdp: take_u16_str(&mut cur)? }),
            SIGNAL_TYPE_ANSWER => Ok(SignalMessage::Answer { sdp: take_u16_str(&mut cur)? }),
            SIGNAL_TYPE_ICE => {
                let candidate = take_u16_str(&mut cur)?;
                let mid = take_u8_str(&mut cur)?;
                let mline = u16::from_be_bytes(take_n(&mut cur, 2)?.try_into().unwrap());
                Ok(SignalMessage::IceCandidate {
                    candidate,
                    sdp_mid: (!mid.is_empty()).then_some(mid),
                    sdp_mline_index: (mline != SIGNAL_NO_MLINE_INDEX).then_some(mline),
                })
            }
            SIGNAL_TYPE_BYE => Ok(SignalMessage::Bye),
            other => Err(format!("unknown signal message type {other}")),
        }
    }
}

fn push_u16_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}
fn push_u8_str(out: &mut Vec<u8>, s: &str) {
    out.push(s.len() as u8);
    out.extend_from_slice(s.as_bytes());
}
fn take_n<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8], String> {
    if cur.len() < n {
        return Err("truncated signal message".to_string());
    }
    let (head, tail) = cur.split_at(n);
    *cur = tail;
    Ok(head)
}
fn take_u8(cur: &mut &[u8]) -> Result<u8, String> {
    Ok(take_n(cur, 1)?[0])
}
fn take_u16_str(cur: &mut &[u8]) -> Result<String, String> {
    let len = u16::from_be_bytes(take_n(cur, 2)?.try_into().unwrap()) as usize;
    String::from_utf8(take_n(cur, len)?.to_vec()).map_err(|_| "signal message field is not valid UTF-8".to_string())
}
fn take_u8_str(cur: &mut &[u8]) -> Result<String, String> {
    let len = take_u8(cur)? as usize;
    String::from_utf8(take_n(cur, len)?.to_vec()).map_err(|_| "signal message field is not valid UTF-8".to_string())
}

/// Encode a WebRTC SDP offer for sending -- encrypt the returned bytes with
/// [`NoiseTransport::encrypt`] before putting them on the wire.
#[wasm_bindgen(js_name = encodeSignalOffer)]
pub fn encode_signal_offer(sdp: &str) -> Vec<u8> {
    SignalMessage::Offer { sdp: sdp.to_string() }.encode()
}

/// Encode a WebRTC SDP answer for sending.
#[wasm_bindgen(js_name = encodeSignalAnswer)]
pub fn encode_signal_answer(sdp: &str) -> Vec<u8> {
    SignalMessage::Answer { sdp: sdp.to_string() }.encode()
}

/// Encode a trickle-ICE candidate for sending. `sdp_mid`/`sdp_mline_index`
/// mirror `RTCIceCandidateInit`'s own optional fields -- pass an empty string
/// / `undefined` (JS) for "absent", matching a candidate gathered before the
/// remote description is set.
#[wasm_bindgen(js_name = encodeSignalIceCandidate)]
pub fn encode_signal_ice_candidate(candidate: &str, sdp_mid: Option<String>, sdp_mline_index: Option<u16>) -> Vec<u8> {
    SignalMessage::IceCandidate { candidate: candidate.to_string(), sdp_mid, sdp_mline_index }.encode()
}

/// Encode the "hanging up" signal.
#[wasm_bindgen(js_name = encodeSignalBye)]
pub fn encode_signal_bye() -> Vec<u8> {
    SignalMessage::Bye.encode()
}

/// Decode a signal message received from the peer (after [`NoiseTransport::decrypt`])
/// into a plain JS object: `{kind: "offer"|"answer"|"ice-candidate"|"bye", sdp?,
/// candidate?, sdpMid?, sdpMlineIndex?}` -- shaped to drop straight into
/// `RTCPeerConnection.setRemoteDescription`/`.addIceCandidate` with minimal
/// glue on the JS side.
#[wasm_bindgen(js_name = decodeSignalMessage)]
pub fn decode_signal_message(bytes: &[u8]) -> Result<JsValue, JsError> {
    let msg = SignalMessage::decode(bytes).map_err(|e| JsError::new(&e))?;
    let obj = js_sys::Object::new();
    let set = |key: &str, val: JsValue| {
        let _ = js_sys::Reflect::set(&obj, &JsValue::from_str(key), &val);
    };
    match msg {
        SignalMessage::Offer { sdp } => {
            set("kind", JsValue::from_str("offer"));
            set("sdp", JsValue::from_str(&sdp));
        }
        SignalMessage::Answer { sdp } => {
            set("kind", JsValue::from_str("answer"));
            set("sdp", JsValue::from_str(&sdp));
        }
        SignalMessage::IceCandidate { candidate, sdp_mid, sdp_mline_index } => {
            set("kind", JsValue::from_str("ice-candidate"));
            set("candidate", JsValue::from_str(&candidate));
            set("sdpMid", sdp_mid.map(|s| JsValue::from_str(&s)).unwrap_or(JsValue::UNDEFINED));
            set("sdpMlineIndex", sdp_mline_index.map(JsValue::from).unwrap_or(JsValue::UNDEFINED));
        }
        SignalMessage::Bye => set("kind", JsValue::from_str("bye")),
    }
    Ok(obj.into())
}

// The pure, testable core behind holder_sign/build_channel_join_request below --
// plain `Result<_, String>` for the same native-test reason as from_hex/hex32/
// ik_initiator above.
fn holder_sign_inner(holder_private_hex: &str, message: &[u8]) -> Result<Vec<u8>, String> {
    use ed25519_dalek::Signer;
    let sk = ed25519_dalek::SigningKey::from_bytes(&hex32(holder_private_hex)?);
    Ok(sk.sign(message).to_bytes().to_vec())
}

fn build_channel_join_request_inner(grant_hex: &str, endpoint: &str) -> Result<Vec<u8>, String> {
    let grant_bytes = from_hex(grant_hex)?;
    let grant = ct_common::channel::SignedChannelGrant::decode(&grant_bytes).map_err(|e| e.to_string())?;
    let req = ct_common::channel::ChannelJoinRequest { grant, endpoint: endpoint.to_string() };
    Ok(req.encode())
}

/// Sign a byte string (the edge's 32-byte single-use possession challenge, in
/// practice -- see [`build_channel_join_request`]'s doc for the full join
/// sequence) with a holder's ed25519 private key. The signature this returns
/// is sent RAW on the wire (no length prefix, no [`frame_message`] framing --
/// `read_channel_join_on_stream` reads exactly 64 bytes) as the direct
/// response to that challenge.
#[wasm_bindgen(js_name = holderSign)]
pub fn holder_sign(holder_private_hex: &str, message: &[u8]) -> Result<Vec<u8>, JsError> {
    holder_sign_inner(holder_private_hex, message).map_err(|e| JsError::new(&e))
}

/// Build the exact bytes a browser member sends to join a channel, from a
/// pre-minted, hex-encoded [`ct_common::channel::SignedChannelGrant`] (a
/// browser peer cannot mint its own grant -- that needs the channel
/// operator's private key -- so a demo/app backend hands each peer its own
/// grant hex out of band) and the endpoint this member advertises (use
/// [`CHANNEL_ENDPOINT_RELAY_ONLY`]'s literal, `"relay-only"`, for a
/// browser member -- it has no dialable address of its own).
///
/// The full join sequence over the WebSocket, mirroring
/// `channel_broker::read_channel_join_on_stream` exactly:
/// 1. send `frame_message(build_channel_join_request(grant, "relay-only"))`
///    as one WebSocket binary message (the length prefix is already inside
///    those framed bytes -- message boundaries don't need to line up)
/// 2. read the next 32 bytes that arrive -- a `b"NO"` (2 bytes) means
///    refused; otherwise it's a 32-byte single-use possession challenge
/// 3. send `holderSign(holderPrivateHex, challenge)` (64 raw bytes, no
///    framing) as the next WebSocket binary message
/// 4. from here on the socket is a raw relay splice: nothing further
///    arrives until a channel partner also joins (a solo member parks in
///    silence), then a rich `"OK <peer...>\n"` ack line arrives on both
///    sides simultaneously and the Noise handshake begins immediately after
#[wasm_bindgen(js_name = buildChannelJoinRequest)]
pub fn build_channel_join_request(grant_hex: &str, endpoint: &str) -> Result<Vec<u8>, JsError> {
    build_channel_join_request_inner(grant_hex, endpoint).map_err(|e| JsError::new(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_message_offer_answer_bye_round_trip() {
        for msg in [
            SignalMessage::Offer { sdp: "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n".to_string() },
            SignalMessage::Answer { sdp: "v=0\r\no=- 3 4 IN IP4 127.0.0.1\r\n".to_string() },
            SignalMessage::Bye,
        ] {
            let encoded = msg.encode();
            let decoded = SignalMessage::decode(&encoded).unwrap();
            assert_eq!(decoded, msg);
        }
    }

    #[test]
    fn signal_message_ice_candidate_round_trips_with_and_without_optional_fields() {
        let full = SignalMessage::IceCandidate {
            candidate: "candidate:1 1 UDP 2130706431 192.0.2.1 54321 typ host".to_string(),
            sdp_mid: Some("audio".to_string()),
            sdp_mline_index: Some(0),
        };
        assert_eq!(SignalMessage::decode(&full.encode()).unwrap(), full);

        // Both optional fields absent (a candidate gathered before the remote
        // description sets mid/mline-index) -- proves None isn't confused with
        // Some(0)/Some("") on the wire.
        let bare = SignalMessage::IceCandidate {
            candidate: "candidate:2 1 UDP 2130706431 192.0.2.2 54322 typ host".to_string(),
            sdp_mid: None,
            sdp_mline_index: None,
        };
        assert_eq!(SignalMessage::decode(&bare.encode()).unwrap(), bare);

        // mline_index genuinely 0 (a real, valid index) must NOT decode as absent.
        let mline_zero = SignalMessage::IceCandidate {
            candidate: "candidate:3 1 UDP 2130706431 192.0.2.3 54323 typ host".to_string(),
            sdp_mid: None,
            sdp_mline_index: Some(0),
        };
        let decoded = SignalMessage::decode(&mline_zero.encode()).unwrap();
        assert_eq!(decoded, mline_zero);
        assert_ne!(decoded, bare, "Some(0) must stay distinguishable from None");
    }

    #[test]
    fn signal_message_decode_rejects_truncated_and_unknown_bytes() {
        assert!(SignalMessage::decode(&[]).is_err(), "empty input");
        assert!(SignalMessage::decode(&[SIGNAL_TYPE_OFFER]).is_err(), "offer with no length-prefixed sdp");
        assert!(SignalMessage::decode(&[0xEE]).is_err(), "unknown message type");
    }

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

    // A real, minted, operator-signed grant -- exactly the object a demo backend
    // would hand a browser peer as hex, built with ct_common's own real types
    // (not a hand-rolled fixture) so these tests exercise the identical wire
    // format `channel_broker::read_channel_join_on_stream` decodes.
    fn signed_test_grant(operator_sk: &ed25519_dalek::SigningKey, holder: [u8; 32]) -> ct_common::channel::SignedChannelGrant {
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ed25519_dalek::Signer;
        let grant = ChannelGrant {
            channel: ChannelId([0x77u8; 32]),
            holder,
            direction: Direction::Both,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 9_999_999_999,
        };
        let signature = operator_sk.sign(&grant.signing_bytes()).to_bytes();
        SignedChannelGrant { grant, signature }
    }

    #[test]
    fn build_channel_join_request_produces_bytes_the_real_ct_common_decoder_accepts_and_verifies() {
        use ct_common::channel::{verify, ChannelJoinRequest, CHANNEL_ENDPOINT_RELAY_ONLY};
        use ed25519_dalek::SigningKey;

        let operator_sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let holder = generate_holder_identity();
        let holder_pub = hex32(&holder.public_hex()).unwrap();
        let signed = signed_test_grant(&operator_sk, holder_pub);
        let grant_hex = to_hex(&signed.encode());

        let req_bytes = build_channel_join_request(&grant_hex, CHANNEL_ENDPOINT_RELAY_ONLY).unwrap();

        // Decoded exactly as the edge decodes it (channel_broker.rs reads a
        // u16 BE length prefix, then this many bytes, then calls this decode).
        let decoded = ChannelJoinRequest::decode(&req_bytes).unwrap();
        assert_eq!(decoded.grant, signed);
        assert_eq!(decoded.endpoint, CHANNEL_ENDPOINT_RELAY_ONLY);
        assert!(decoded.is_relay_only());
        assert!(verify(&operator_sk.verifying_key().to_bytes(), &decoded.grant, 0).is_ok());

        // frame_message wraps it exactly the way it goes on the wire (a u16 BE
        // length prefix that read_channel_join_on_stream's `len_buf` reads).
        let framed = frame_message(&req_bytes);
        let len = u16::from_be_bytes([framed[0], framed[1]]) as usize;
        assert_eq!(len, req_bytes.len());
        assert_eq!(&framed[2..], req_bytes.as_slice());
    }

    #[test]
    fn build_channel_join_request_rejects_a_malformed_grant_hex() {
        assert!(build_channel_join_request_inner("not-hex", "relay-only").is_err());
        assert!(build_channel_join_request_inner("aa", "relay-only").is_err(), "too short to be a real grant");
    }

    #[test]
    fn holder_sign_produces_a_signature_the_real_ct_common_possession_check_accepts() {
        use ct_common::channel::verify_holder_possession;
        let holder = generate_holder_identity();
        let holder_pub = hex32(&holder.public_hex()).unwrap();
        let challenge = [0x5cu8; 32]; // stands in for the edge's fresh random challenge

        let sig_bytes = holder_sign(&holder.private_hex(), &challenge).unwrap();
        let sig: [u8; 64] = sig_bytes.try_into().unwrap();
        assert!(verify_holder_possession(&holder_pub, &challenge, &sig));

        // A signature over the wrong challenge (or by the wrong key) must fail --
        // this is the exact anti-replay property #81 relies on.
        let other_challenge = [0x5du8; 32];
        assert!(!verify_holder_possession(&holder_pub, &other_challenge, &sig));
        let other_holder = generate_holder_identity();
        let other_pub = hex32(&other_holder.public_hex()).unwrap();
        assert!(!verify_holder_possession(&other_pub, &challenge, &sig));
    }

    #[test]
    fn holder_sign_rejects_a_malformed_private_key_hex() {
        assert!(holder_sign_inner("nothex", b"msg").is_err());
        assert!(holder_sign_inner("aa", b"msg").is_err(), "too short to be 32 bytes");
    }
}
