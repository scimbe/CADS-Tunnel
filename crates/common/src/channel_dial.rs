//! Agent-bridges-v2: a minimal, native-only channel **dialer** for a server-side caller
//! (`ct-control-plane`'s bridge dialer) that has no existing channel-dial code of its own.
//!
//! `ct-agent`'s own `channel.rs`/`transport.rs` already implement this wire protocol, but
//! that code is entangled with tunnel-registration concerns and lives in ct-agent's binary
//! crate, not a shared library (see the Agent-bridges-v2 plan's 2026-09-02 scoping note).
//! Rather than extract/refactor ct-agent's existing production code (real risk to a live
//! system for no benefit to ct-agent itself), this module is NEW, purpose-built code for
//! the one thing a bridge caller needs: dial the platform's own broker over QUIC, present
//! a grant, complete the Noise_IK handshake, send exactly one JSON-RPC `tools/call`, read
//! the reply, disconnect. It deliberately does NOT implement the direct-address path, the
//! `:443` front-door fallback, DCUtR, or the relay-leg wire variant — a bridge caller
//! always talks to this deployment's own trusted broker over its dedicated QUIC port, none
//! of that generality applies.
//!
//! The admission wire protocol (request → possession-challenge → signed response → ack)
//! below is a faithful port of `ct-agent`'s `channel::present_channel_join_on_stream` — the
//! byte-level ack-reading contract, the `NO`/`EX`/refusal-category handling, and the
//! possession-challenge signing are copied deliberately unchanged; this protocol has a real
//! bug history (ct-agent#21/#23/#129/#148/#524) and reimplementing it "simpler" would risk
//! silently reintroducing already-fixed bugs. Everything below the QUIC dial (the Noise_IK
//! handshake, the encrypted send/recv, the JSON-RPC request encoding) reuses this crate's
//! own [`crate::a2a`]/[`crate::mcp`] — already fully portable, no duplication needed there.
//!
//! `#[cfg(not(target_arch = "wasm32"))]`-gated: this crate is also compiled for the browser
//! channel-claim page (wasm32-unknown-unknown), which has no `quinn`/`rustls`/`tokio::net` —
//! see this crate's `Cargo.toml` for the matching `[target.'cfg(not(target_arch =
//! "wasm32"))'.dependencies]` block. A native build (ct-control-plane, ct-agent) sees this
//! module; a wasm32 build does not, and nothing here can ever be reached from one.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use quinn::{Connection, Endpoint};
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::a2a::{a2a_initiate, a2a_recv, a2a_send};
use crate::channel::{
    ChannelJoinRequest, SignedChannelGrant, CHANNEL_ENDPOINT_RELAY_ONLY,
    CHANNEL_REFUSAL_CATEGORY_MAX_LEN, PARK_EXPIRED_REASON_PREFIX, PARK_EXPIRED_TOKEN,
};
use crate::mcp::encode_request;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Outcome of presenting a channel join to the broker. A deliberately narrower copy of
/// ct-agent's own `ChannelJoinOutcome` — this caller never advertises a dialable endpoint of
/// its own (always [`CHANNEL_ENDPOINT_RELAY_ONLY`]), so it has no analog of that enum's
/// `observed_reflexive`/direct-upgrade fields; nothing here ever offers a direct-upgrade
/// candidate, so nothing needs to receive one back either.
#[derive(Debug, Clone, PartialEq, Eq)]
enum JoinOutcome {
    Admitted {
        peer_noise_pubkey: Option<[u8; 32]>,
        peer_holder: Option<[u8; 32]>,
        peer_attestation: Option<[u8; 64]>,
    },
    Refused {
        category: Option<String>,
    },
    ParkExpired,
}

/// Errors from [`dial_and_call`], named so a caller (the control-plane route handler) can
/// react differently to "your grant/setup is wrong" vs. "the peer just isn't there right
/// now" vs. "something in the wire protocol broke" instead of one opaque string.
#[derive(Debug)]
pub enum DialError {
    /// The broker refused admission — a bad/expired grant, or the grant's channel has no
    /// member matching this dial's identity. `category` is the broker's own refusal-reason
    /// token when it sent one (see `ct-agent`'s `channel.rs` for the full vocabulary).
    Refused { category: Option<String> },
    /// Admitted, but no second party was on the other end of the channel within the park
    /// window — the customer's own agent isn't currently connected to serve this channel.
    NoPeer,
    /// The QUIC dial to the broker itself failed (network/config problem, not a refusal).
    DialFailed(String),
    /// Admission succeeded but no peer Noise key/attestation came back, or the attestation
    /// didn't verify — the broker's registry has no attested member material for whoever we
    /// got paired with. Never proceeds to a handshake in this case.
    NoVerifiedPeer,
    /// The Noise_IK handshake or the encrypted call itself failed.
    Session(String),
    /// The peer's JSON-RPC reply wasn't well-formed, or the call returned a JSON-RPC error.
    BadReply(String),
    /// The whole dial+call exceeded its deadline.
    TimedOut,
}

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialError::Refused { category: Some(c) } => write!(f, "broker refused admission: {c}"),
            DialError::Refused { category: None } => write!(f, "broker refused admission"),
            DialError::NoPeer => write!(f, "admitted, but no peer is currently connected to this channel"),
            DialError::DialFailed(e) => write!(f, "could not reach the broker: {e}"),
            DialError::NoVerifiedPeer => write!(f, "broker paired us with a member it has no verifiable Noise key for"),
            DialError::Session(e) => write!(f, "channel session error: {e}"),
            DialError::BadReply(e) => write!(f, "malformed reply from peer: {e}"),
            DialError::TimedOut => write!(f, "timed out"),
        }
    }
}
impl std::error::Error for DialError {}

/// How long the whole dial+admit+handshake+call may take before giving up. Generous
/// relative to the broker's own ~45s admission-exchange bound (ct-agent#140) since this
/// also covers the QUIC dial and the Noise handshake round trip on top of that — but still
/// bounded, since this runs inside an HTTP request handler with its own caller waiting.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(20);

const POSSESSION_CHALLENGE_LEN: usize = 32;
const CHANNEL_ACK_MAX_BYTES: usize = 512;

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// A rustls verifier that accepts any server certificate — the QUIC/TLS layer here is
/// transport only; real mutual authentication is the Noise_IK session pinned to the
/// broker-attested peer key, exactly as `ct-agent`'s own channel dialer (`transport.rs`'s
/// `AcceptAnyServerCert`) already does for the identical reason.
#[derive(Debug)]
struct AcceptAnyServerCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn build_dialer() -> Result<Endpoint, BoxError> {
    install_crypto_provider();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)))
        .with_no_client_auth();
    let mut cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(20)).expect("20s < quinn max idle"),
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(5)));
    cfg.transport_config(Arc::new(transport));
    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    endpoint.set_default_client_config(cfg);
    Ok(endpoint)
}

async fn dial_broker(broker_addr: SocketAddr) -> Result<Connection, DialError> {
    let endpoint = build_dialer().map_err(|e| DialError::DialFailed(e.to_string()))?;
    let connecting = endpoint
        .connect(broker_addr, "localhost")
        .map_err(|e| DialError::DialFailed(e.to_string()))?;
    connecting.await.map_err(|e| DialError::DialFailed(e.to_string()))
}

/// Present `request` on `(send, recv)` and read the broker's decision — a direct, narrower
/// port of `ct-agent`'s `channel::present_channel_join_on_stream` (see the module doc for
/// why this is a faithful copy, not a reimplementation). Always the QUIC/broker leg shape:
/// no phase marker, finishes the send half after the possession signature.
async fn present_join<W, R>(
    mut send: W,
    mut recv: R,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    deadline: tokio::time::Instant,
) -> Result<JoinOutcome, DialError>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let pre = async {
        let bytes = request.encode();
        let len = u16::try_from(bytes.len())
            .map_err(|_| DialError::Session("channel join request too large".into()))?;
        send.write_all(&len.to_be_bytes()).await.map_err(|e| DialError::Session(e.to_string()))?;
        send.write_all(&bytes).await.map_err(|e| DialError::Session(e.to_string()))?;
        send.flush().await.map_err(|e| DialError::Session(e.to_string()))?;

        let mut resp = Vec::new();
        let _ = (&mut recv)
            .take(POSSESSION_CHALLENGE_LEN as u64)
            .read_to_end(&mut resp)
            .await;
        if resp.len() != POSSESSION_CHALLENGE_LEN {
            let text = String::from_utf8_lossy(&resp);
            if resp.is_empty() || text.starts_with("NO") {
                let category = resp.get(2..).and_then(decode_refusal_category);
                return Ok(Some(JoinOutcome::Refused { category }));
            }
            return Err(DialError::Session(format!(
                "broker sent a malformed {}-byte response before the possession challenge",
                resp.len()
            )));
        }
        let challenge: [u8; POSSESSION_CHALLENGE_LEN] = resp.try_into().expect("length checked above");
        let sig = holder.sign(&challenge).to_bytes();
        send.write_all(&sig).await.map_err(|e| DialError::Session(e.to_string()))?;
        send.flush().await.map_err(|e| DialError::Session(e.to_string()))?;
        let _ = send.shutdown().await;
        Ok::<Option<JoinOutcome>, DialError>(None)
    };
    match tokio::time::timeout_at(deadline, pre).await {
        Ok(Ok(None)) => {}
        Ok(Ok(Some(early))) => return Ok(early),
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(DialError::TimedOut),
    }

    let mut ack = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let bound = deadline.saturating_duration_since(tokio::time::Instant::now());
        let read = match tokio::time::timeout(bound, recv.read(&mut byte)).await {
            Ok(r) => r,
            Err(_) => return Err(DialError::TimedOut),
        };
        match read {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) if byte[0] == 0 && ack.is_empty() => continue,
            Ok(_) => {
                ack.push(byte[0]);
                if ack.len() >= CHANNEL_ACK_MAX_BYTES {
                    return Err(DialError::Session(format!(
                        "channel ack exceeded {CHANNEL_ACK_MAX_BYTES} bytes without a terminator"
                    )));
                }
            }
            Err(e) => {
                if error_names_park_expiry(&e) {
                    return Ok(JoinOutcome::ParkExpired);
                }
                break;
            }
        }
    }
    if ack.is_empty() {
        return Err(DialError::Session(
            "pairing dropped after admission before the broker ack (peer connection likely died mid-pairing); retry".into(),
        ));
    }
    let ack_text = String::from_utf8_lossy(&ack);
    Ok(parse_ack(&ack_text))
}

fn error_names_park_expiry(e: &(dyn std::error::Error + 'static)) -> bool {
    let marker = PARK_EXPIRED_REASON_PREFIX.strip_suffix(':').unwrap_or(PARK_EXPIRED_REASON_PREFIX);
    let mut cur: Option<&dyn std::error::Error> = Some(e);
    while let Some(err) = cur {
        if err.to_string().contains(marker) {
            return true;
        }
        cur = err.source();
    }
    false
}

fn is_refusal_token_shape(token: &[u8]) -> bool {
    !token.is_empty()
        && token.len() <= CHANNEL_REFUSAL_CATEGORY_MAX_LEN
        && token.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

fn decode_refusal_category(rest: &[u8]) -> Option<String> {
    let (&len, tail) = rest.split_first()?;
    let token = tail.get(..len as usize)?;
    if !is_refusal_token_shape(token) {
        return None;
    }
    Some(String::from_utf8(token.to_vec()).expect("charset-checked ASCII"))
}

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex_decode(s)?;
    bytes.try_into().ok()
}
fn decode_hex_64(s: &str) -> Option<[u8; 64]> {
    let bytes = hex_decode(s)?;
    bytes.try_into().ok()
}
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn parse_ack(ack: &str) -> JoinOutcome {
    if ack.trim().as_bytes() == PARK_EXPIRED_TOKEN.as_slice() {
        return JoinOutcome::ParkExpired;
    }
    match ack.strip_prefix("OK") {
        Some(rest) => {
            let mut fields: Vec<&str> = Vec::new();
            for tok in rest.split_whitespace() {
                if tok.contains('=') {
                    continue; // tagged tokens (r=, sp=, ...) don't apply to this caller
                }
                fields.push(tok);
            }
            let mut parts = fields.into_iter();
            let _peer_endpoint = parts.next();
            let peer_noise_pubkey = parts.next().and_then(decode_hex_32);
            let peer_holder = parts.next().and_then(decode_hex_32);
            let peer_attestation = parts.next().and_then(decode_hex_64);
            JoinOutcome::Admitted {
                peer_noise_pubkey,
                peer_holder,
                peer_attestation,
            }
        }
        None => JoinOutcome::Refused { category: None },
    }
}

/// Dial `broker_addr` over QUIC, present `grant` as `own_holder`, complete the Noise_IK
/// handshake with whoever the broker pairs this join with, send one JSON-RPC `tools/call`
/// for `tool_name` with `arguments`, and return the decoded JSON-RPC response's `result` (or
/// an error if the call itself returned a JSON-RPC error object).
///
/// `own_holder`/`own_noise_private` are the shared bridge identity's own keys — the SAME
/// keypair for every tunnel this deployment bridges into, admitted separately per-tunnel by
/// each owner's own `channel/grant` call (see the Agent-bridges-v2 plan's Decisions §2).
/// Never logs or returns either private key.
pub async fn dial_and_call(
    broker_addr: SocketAddr,
    grant: SignedChannelGrant,
    own_holder: &SigningKey,
    own_noise_private: &[u8; 32],
    tool_name: &str,
    arguments: serde_json::Value,
) -> Result<serde_json::Value, DialError> {
    let deadline = tokio::time::Instant::now() + DIAL_TIMEOUT;
    let channel = grant.grant.channel;
    let request = ChannelJoinRequest {
        grant,
        endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
    };

    let conn = tokio::time::timeout_at(deadline, dial_broker(broker_addr))
        .await
        .map_err(|_| DialError::TimedOut)??;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| DialError::DialFailed(e.to_string()))?;

    let outcome = present_join(&mut send, &mut recv, &request, own_holder, deadline).await?;
    let (peer_noise_pubkey, peer_holder, peer_attestation) = match outcome {
        JoinOutcome::Refused { category } => return Err(DialError::Refused { category }),
        JoinOutcome::ParkExpired => return Err(DialError::NoPeer),
        JoinOutcome::Admitted {
            peer_noise_pubkey: Some(pk),
            peer_holder: Some(holder),
            peer_attestation: Some(att),
        } => (pk, holder, att),
        JoinOutcome::Admitted { .. } => return Err(DialError::NoVerifiedPeer),
    };

    if !crate::channel::verify_member_noise_attestation(&channel, &peer_holder, &peer_noise_pubkey, &peer_attestation) {
        return Err(DialError::NoVerifiedPeer);
    }

    let mut session = tokio::time::timeout_at(
        deadline,
        a2a_initiate(&mut send, &mut recv, own_noise_private, &peer_noise_pubkey),
    )
    .await
    .map_err(|_| DialError::TimedOut)?
    .map_err(|e| DialError::Session(e.to_string()))?;

    let req_bytes = encode_request(1, "tools/call", serde_json::json!({ "name": tool_name, "arguments": arguments }));
    tokio::time::timeout_at(deadline, a2a_send(&mut send, &mut session, &req_bytes))
        .await
        .map_err(|_| DialError::TimedOut)?
        .map_err(|e| DialError::Session(e.to_string()))?;
    let reply_bytes = tokio::time::timeout_at(deadline, a2a_recv(&mut recv, &mut session))
        .await
        .map_err(|_| DialError::TimedOut)?
        .map_err(|e| DialError::Session(e.to_string()))?;

    let reply: serde_json::Value = serde_json::from_slice(&reply_bytes)
        .map_err(|e| DialError::BadReply(format!("not valid JSON: {e}")))?;
    if let Some(err) = reply.get("error") {
        return Err(DialError::BadReply(err.to_string()));
    }
    reply
        .get("result")
        .cloned()
        .ok_or_else(|| DialError::BadReply("reply had neither `result` nor `error`".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::ChannelId;

    #[test]
    fn parse_ack_reads_ok_and_the_three_attested_fields() {
        let ack = "OK relay-only aa11 bb22 cc33";
        // Not real hex-32/64, so decode_hex_32/64 return None below — this just proves the
        // positional parse and the "skip tagged tokens" rule, not decoding itself.
        assert_eq!(
            parse_ack(ack),
            JoinOutcome::Admitted { peer_noise_pubkey: None, peer_holder: None, peer_attestation: None }
        );
    }

    #[test]
    fn parse_ack_skips_tagged_tokens_positionally() {
        let noise = "11".repeat(32);
        let holder = "22".repeat(32);
        let attest = "33".repeat(64);
        let ack = format!("OK relay-only {noise} {holder} {attest} r=1.2.3.4:5");
        let JoinOutcome::Admitted { peer_noise_pubkey, peer_holder, peer_attestation } = parse_ack(&ack) else {
            panic!("expected Admitted");
        };
        assert_eq!(peer_noise_pubkey, decode_hex_32(&noise));
        assert_eq!(peer_holder, decode_hex_32(&holder));
        assert_eq!(peer_attestation, decode_hex_64(&attest));
    }

    #[test]
    fn parse_ack_refuses_on_anything_else() {
        assert_eq!(parse_ack("NO"), JoinOutcome::Refused { category: None });
    }

    #[test]
    fn parse_ack_recognizes_park_expired() {
        let token = std::str::from_utf8(PARK_EXPIRED_TOKEN.as_slice()).unwrap();
        assert_eq!(parse_ack(token), JoinOutcome::ParkExpired);
    }

    #[test]
    fn decode_refusal_category_round_trips_a_shaped_token() {
        let token = b"not-member";
        let mut rest = vec![token.len() as u8];
        rest.extend_from_slice(token);
        assert_eq!(decode_refusal_category(&rest).as_deref(), Some("not-member"));
    }

    #[test]
    fn decode_refusal_category_rejects_malshaped_tokens() {
        assert_eq!(decode_refusal_category(&[3, b'A', b'B', b'C']), None, "uppercase not in the shape");
        assert_eq!(decode_refusal_category(&[5, b'a', b'b']), None, "declared len longer than what's present");
    }

    #[tokio::test]
    async fn present_join_reports_a_no_refusal_without_a_category() {
        let (agent_side, mut broker_side) = tokio::io::duplex(4096);
        let holder = SigningKey::from_bytes(&[42u8; 32]);
        let grant = crate::channel::SignedChannelGrant {
            grant: crate::channel::ChannelGrant {
                channel: ChannelId([1u8; 32]),
                holder: holder.verifying_key().to_bytes(),
                direction: crate::channel::Direction::Initiate,
                rights: crate::channel::Rights::ReadWrite,
                delegable: false,
                expires_at: u64::MAX,
            },
            signature: [0u8; 64],
        };
        let request = ChannelJoinRequest { grant, endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string() };

        let broker = tokio::spawn(async move {
            let mut len_buf = [0u8; 2];
            broker_side.read_exact(&mut len_buf).await.unwrap();
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            broker_side.read_exact(&mut body).await.unwrap();
            broker_side.write_all(b"NO").await.unwrap();
            broker_side.shutdown().await.unwrap();
        });

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let (recv, send) = tokio::io::split(agent_side);
        let outcome = present_join(send, recv, &request, &holder, deadline).await.unwrap();
        assert_eq!(outcome, JoinOutcome::Refused { category: None });
        broker.await.unwrap();
    }

    #[tokio::test]
    async fn present_join_reports_an_ok_admission_with_attested_peer_material() {
        let (agent_side, mut broker_side) = tokio::io::duplex(4096);
        let holder = SigningKey::from_bytes(&[42u8; 32]);
        let grant = crate::channel::SignedChannelGrant {
            grant: crate::channel::ChannelGrant {
                channel: ChannelId([2u8; 32]),
                holder: holder.verifying_key().to_bytes(),
                direction: crate::channel::Direction::Initiate,
                rights: crate::channel::Rights::ReadWrite,
                delegable: false,
                expires_at: u64::MAX,
            },
            signature: [0u8; 64],
        };
        let request = ChannelJoinRequest { grant, endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string() };
        let noise = [7u8; 32];
        let peer_holder = [8u8; 32];
        let attest = [9u8; 64];

        let broker = tokio::spawn(async move {
            let mut len_buf = [0u8; 2];
            broker_side.read_exact(&mut len_buf).await.unwrap();
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            broker_side.read_exact(&mut body).await.unwrap();
            broker_side.write_all(&[0u8; POSSESSION_CHALLENGE_LEN]).await.unwrap();
            let mut sig = [0u8; 64];
            broker_side.read_exact(&mut sig).await.unwrap();
            let ack = format!(
                "OK relay-only {} {} {}\n",
                hex_encode(&noise),
                hex_encode(&peer_holder),
                hex_encode(&attest)
            );
            broker_side.write_all(ack.as_bytes()).await.unwrap();
        });

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let (recv, send) = tokio::io::split(agent_side);
        let outcome = present_join(send, recv, &request, &holder, deadline).await.unwrap();
        assert_eq!(
            outcome,
            JoinOutcome::Admitted {
                peer_noise_pubkey: Some(noise),
                peer_holder: Some(peer_holder),
                peer_attestation: Some(attest),
            }
        );
        broker.await.unwrap();
    }

    fn hex_encode(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
