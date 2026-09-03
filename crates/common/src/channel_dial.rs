//! Agent-bridges-v2: a minimal, native-only channel **dialer** for a server-side caller
//! (`ct-control-plane`'s bridge dialer) that has no existing channel-dial code of its own.
//!
//! `ct-agent`'s own `channel.rs`/`transport.rs` already implement this wire protocol, but
//! that code is entangled with tunnel-registration concerns and lives in ct-agent's binary
//! crate, not a shared library (see the Agent-bridges-v2 plan's 2026-09-02 scoping note).
//! Rather than extract/refactor ct-agent's existing production code (real risk to a live
//! system for no benefit to ct-agent itself), this module is NEW, purpose-built code for
//! the one thing a bridge caller needs: reach the customer's agent through this
//! deployment's own broker/relay pair over QUIC, present a grant, complete the Noise_IK
//! handshake, send exactly one JSON-RPC `tools/call`, read the reply, disconnect. It
//! deliberately does NOT implement the direct-address path, the `:443` front-door
//! fallback, or DCUtR — a bridge caller always talks to this deployment's own trusted
//! broker over its dedicated QUIC ports, none of that generality applies.
//!
//! **Two hops, two QUIC connections (#745).** A bridge caller is itself relay-only (it
//! advertises [`CHANNEL_ENDPOINT_RELAY_ONLY`]) and the customer's agent it dials is, in
//! the scenario this exists for, relay-only too (`CT_CHANNEL_RELAY_ONLY=1`). ct-agent's
//! own relay-only initiator (`channel_run/mod.rs::run_channel_join_with_admission` →
//! `join_via_relay`) therefore does exactly this, and so does [`dial_and_call`]:
//!
//! 1. **Rendezvous hop** — a QUIC connection to the broker (`:4435`), one admission
//!    bi-stream, `[0xFF, 0x01]` phase preamble + the join, possession challenge/signature,
//!    the EOF-terminated `OK …` ack carrying the PEER's attested Noise key/holder/attestation.
//!    That triple is verified (ct-agent#101) and kept; the connection is then dropped — the
//!    rendezvous port's contract is ack-and-close, nothing else is ever read or written on it.
//! 2. **Relay hop** — a SEPARATE QUIC connection to the relay (`:4436`), dialed only AFTER
//!    hop 1 acked (ct-agent#103: a relay connection held idle through hop 1 gets reaped as
//!    a spurious `[quic-bistream]` drop), one throwaway admission bi-stream with the SAME
//!    join request and the `[0xFF, 0x02]` preamble, the same challenge/signature/ack
//!    procedure (the relay ack's peer material is not authoritative — hop 1's is, as in
//!    ct-agent). Then a FRESH `open_bi()` on that relay connection is the session stream:
//!    the edge splices the initiator's NEXT bi-stream to the acceptor
//!    (`ct_edge::relay::relay_initiator_to_acceptor`), so the Noise_IK handshake and the
//!    encrypted `tools/call` run there — never on the admission stream, which was
//!    `finish()`ed after the signature and which the edge never reads session bytes from.
//!
//! Before #745 this module performed hop 1 only and then ran Noise on the already-finished
//! admission stream, so the relay-only acceptor parked on `:4436` reaped with "park expired
//! with no partner (#21)" on every call.
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
    ChannelId, ChannelJoinRequest, SignedChannelGrant, CHANNEL_ENDPOINT_RELAY_ONLY,
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
#[derive(Debug, PartialEq, Eq)]
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
    /// Admitted (possession handshake completed) but the leg closed with ZERO ack bytes —
    /// a transport/handoff race (the paired peer's connection died mid-pairing), NOT an
    /// authorization refusal, which is always an explicit `NO` (ct-agent#148/#23). Typed so
    /// a caller can retry it without string-matching; must never be treated as definitive.
    /// `leg` is `"rendezvous"` or `"relay"`, for operator logs.
    DroppedLeg { leg: &'static str },
    /// The Noise_IK handshake or the encrypted call itself failed.
    Session(String),
    /// The peer's JSON-RPC reply wasn't well-formed, or the call returned a JSON-RPC error.
    BadReply(String),
    /// One of the bounded phases (a hop's admission exchange, the session stream open, the
    /// Noise handshake, or the call itself) exceeded its deadline.
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
            DialError::DroppedLeg { leg } => write!(
                f,
                "{leg} pairing dropped after admission before the broker ack (peer connection likely died mid-pairing); retry"
            ),
            DialError::Session(e) => write!(f, "channel session error: {e}"),
            DialError::BadReply(e) => write!(f, "malformed reply from peer: {e}"),
            DialError::TimedOut => write!(f, "timed out"),
        }
    }
}
impl std::error::Error for DialError {}

/// Per-hop budget for the QUIC connect + admission bi-stream + the whole admission
/// exchange (join, possession challenge/signature, ack wait). Same value and same reasoning
/// as ct-agent's `ADMISSION_EXCHANGE_TIMEOUT` (ct-agent#140): the edge acks a pairing leg
/// only once the PARTNER arrives, and keeps a lone first-arriving member parked for its
/// full park TTL (`CHANNEL_PARK_TTL_SECS = 30` server-side). A client bound BELOW that
/// window fails deterministically whenever the partner shows up in the last part of it,
/// while the edge is still legitimately waiting on our behalf — the exact mistake ct-agent
/// shipped as a 15 s bound (and this module shipped as a single 20 s `DIAL_TIMEOUT` covering
/// everything, before #745). 45 s = the 30 s park window plus margin for the partner's own
/// ladder walk; still finite, so a genuinely dead broker fails in bounded time.
pub const ADMISSION_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(45);

/// Bound on opening the SESSION bi-stream on the relay connection after hop 2's ack (the
/// analog of ct-agent's `DIRECT_STREAM_SETUP_TIMEOUT`, #139): quinn's `open_bi()` resolves
/// only once the peer's flow control grants stream credit, so an edge that acked but never
/// grants a stream must not hang this past a bound.
pub const SESSION_STREAM_TIMEOUT: Duration = Duration::from_secs(15);

/// Bound on the Noise_IK handshake on the session stream (ct-agent's
/// `A2A_HANDSHAKE_TIMEOUT`, #126). Covers the edge's own splice setup: after both hop-2
/// acks the edge `accept_bi()`s our session stream and `open_bi()`s toward the acceptor
/// (each bounded by its `RELAY_SETUP_TIMEOUT = 5 s`), then relays msg1 and the reply.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound on the one encrypted `tools/call` round trip (send + receive the reply). This
/// runs inside an HTTP request handler with its own caller waiting, so it stays short.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(20);

/// `[0xFF, phase]` phase preamble written before the length-framed join (ct-agent
/// `channel.rs`'s `PHASE_PREAMBLE_MAGIC`/`PHASE_MARKER_*`, CADS-Tunnel#495 U2). The QUIC
/// edge peeks and DISCARDS it (its phase is fixed per port), but sending it keeps this
/// port byte-identical to ct-agent, and it is load-bearing on any `:443` stream leg where
/// the marker decides the completer. `0xFF` is unambiguous against the length prefix (it
/// would mean a >= 65280-byte join, refused as len-oob by every edge). Any OTHER phase byte
/// after the magic is a DEFINITIVE refusal that charges the per-IP penalty (#509) — only
/// these two values may ever be sent.
const PHASE_PREAMBLE_MAGIC: u8 = 0xFF;
/// Phase byte: rendezvous admission (the parked ack-and-close leg, hop 1).
const PHASE_MARKER_RENDEZVOUS: u8 = 0x01;
/// Phase byte: relay leg (hop 2; the session runs on the connection's NEXT bi-stream).
const PHASE_MARKER_RELAY: u8 = 0x02;

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

/// One fresh QUIC connection to `addr`. Returns the [`Endpoint`] alongside the
/// [`Connection`] so the caller keeps both alive together for the connection's lifetime —
/// each hop of [`dial_and_call`] gets its own, exactly like ct-agent dials `broker_conn`
/// and `relay_conn` separately (ct-agent#103 — see the module doc).
async fn dial_quic(addr: SocketAddr) -> Result<(Endpoint, Connection), DialError> {
    let endpoint = build_dialer().map_err(|e| DialError::DialFailed(e.to_string()))?;
    let connecting = endpoint
        .connect(addr, "localhost")
        .map_err(|e| DialError::DialFailed(e.to_string()))?;
    let conn = connecting.await.map_err(|e| DialError::DialFailed(e.to_string()))?;
    Ok((endpoint, conn))
}

/// Present `request` on `(send, recv)` and read the broker's decision — a direct, narrower
/// port of `ct-agent`'s `channel::present_channel_join_on_stream` (see the module doc for
/// why this is a faithful copy, not a reimplementation). Always the QUIC leg shape:
/// finishes the send half after the possession signature (`finish_send_after_sig = true`
/// in ct-agent's terms — on QUIC that is a clean per-stream `finish()`; it would be WRONG on
/// a TCP/TLS stream leg, ct-agent#21 follow-up, which this module never dials).
///
/// `phase_marker`: `Some(phase)` writes the `[PHASE_PREAMBLE_MAGIC, phase]` preamble before
/// the length prefix ([`PHASE_MARKER_RENDEZVOUS`] on hop 1, [`PHASE_MARKER_RELAY`] on hop 2);
/// `None` sends the bare length-framed join, byte-identical to this function before #745.
async fn present_join<W, R>(
    mut send: W,
    mut recv: R,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    deadline: tokio::time::Instant,
    phase_marker: Option<u8>,
) -> Result<JoinOutcome, DialError>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    // Which leg this is, for the typed #148 dropped-leg error below. Only the two known
    // markers are ever passed (see PHASE_PREAMBLE_MAGIC's doc); a bare join is the
    // rendezvous shape.
    let leg = if phase_marker == Some(PHASE_MARKER_RELAY) { "relay" } else { "rendezvous" };
    let pre = async {
        let bytes = request.encode();
        let len = u16::try_from(bytes.len())
            .map_err(|_| DialError::Session("channel join request too large".into()))?;
        if let Some(phase) = phase_marker {
            send.write_all(&[PHASE_PREAMBLE_MAGIC, phase])
                .await
                .map_err(|e| DialError::Session(e.to_string()))?;
        }
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
        // Signing a raw, broker-chosen 32-byte blob with this identity's key is safe because
        // no OTHER message this holder key ever signs is exactly 32 raw, undomain-separated
        // bytes -- every other signing site in this workspace (member_noise_attest_bytes,
        // topology_operator_binding_bytes, invitation_redeem_bytes, etc.) is domain-prefixed
        // and strictly longer, so there is no length collision a forged/replayed signature
        // here could exploit against a different meaning elsewhere (verified 2026-09-02 by
        // auditing every `.sign(` call site in the workspace; mirrors ct-agent's own #36 note
        // on the original this is ported from).
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
    // #524-collision recovery (see below): whether the loop ended because it read the 0x0A
    // terminator, vs. EOF/error -- needed to recover a category token whose length byte IS
    // 0x0A (e.g. "possession", "not-member" are both 10 bytes), which would otherwise look
    // like the ack ending right there with the token still unread.
    let mut ended_by_newline = false;
    loop {
        let bound = deadline.saturating_duration_since(tokio::time::Instant::now());
        let read = match tokio::time::timeout(bound, recv.read(&mut byte)).await {
            Ok(r) => r,
            Err(_) => return Err(DialError::TimedOut),
        };
        match read {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => {
                ended_by_newline = true;
                break;
            }
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
    // ct-agent#148/#23: zero ack bytes AFTER a completed possession handshake is a
    // transport/handoff race, never a refusal (a refusal is always an explicit `NO`) —
    // typed so a caller can retry it, and never charged as definitive.
    if ack.is_empty() {
        return Err(DialError::DroppedLeg { leg });
    }
    // A refusal arriving AFTER the possession challenge (e.g. category "pairing" -- admitted,
    // but pairing the two members was refused -- can only ever be delivered this way) is
    // classified at the BYTE level, before any lossy UTF-8 conversion: the framed category
    // token's length byte is binary, not text (2026-09-02 review finding — this was previously
    // missing here, silently losing the category for every post-possession refusal).
    if let Some(rest) = ack.strip_prefix(b"NO") {
        let category = if !rest.is_empty() {
            decode_refusal_category(rest)
        } else if ended_by_newline {
            read_refusal_tail_token(&mut recv, deadline).await
        } else {
            None
        };
        return Ok(JoinOutcome::Refused { category });
    }
    let ack_text = String::from_utf8_lossy(&ack);
    Ok(parse_ack(&ack_text))
}

/// #524 0x0A-collision recovery: a category token of exactly 10 bytes (`possession`,
/// `not-member`) has `0x0A` as its LENGTH byte, so the byte-wise ack reader above stops at the
/// bare `NO` with the token still unread on the wire. Only ever called after a `NO` that ended
/// on `0x0A` — a refusal's stream is closed right after the frame, so a short bounded read to
/// EOF yields exactly the token (10 bytes, token-shaped) or nothing.
async fn read_refusal_tail_token<R: AsyncRead + Unpin>(
    recv: &mut R,
    deadline: tokio::time::Instant,
) -> Option<String> {
    let mut tail = Vec::new();
    let mut bounded = (&mut *recv).take(CHANNEL_REFUSAL_CATEGORY_MAX_LEN as u64 + 1);
    let bound = deadline.saturating_duration_since(tokio::time::Instant::now());
    match tokio::time::timeout(bound, bounded.read_to_end(&mut tail)).await {
        Ok(Ok(_)) => (tail.len() == 0x0A && is_refusal_token_shape(&tail))
            .then(|| String::from_utf8(tail).expect("charset-checked ASCII")),
        _ => None,
    }
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

/// The one crypto trust gate between "the broker paired us with someone" and "we run a Noise
/// handshake with them": reject unless the peer's attested Noise key actually verifies against
/// the channel's own registry-backed attestation. Split out of [`dial_and_call`] so this
/// specific check — the property a 2026-09-02 review specifically asked to see tested, since
/// nothing else in this module proves it independent of reading the source — is directly
/// unit-testable without a real network dial.
fn reject_unverified_peer(
    channel: &ChannelId,
    peer_holder: &[u8; 32],
    peer_noise_pubkey: &[u8; 32],
    peer_attestation: &[u8; 64],
) -> Result<(), DialError> {
    if crate::channel::verify_member_noise_attestation(channel, peer_holder, peer_noise_pubkey, peer_attestation) {
        Ok(())
    } else {
        Err(DialError::NoVerifiedPeer)
    }
}

/// One admission hop: a fresh QUIC connection to `addr`, one admission bi-stream, and the
/// whole [`present_join`] exchange with `phase_marker`, all under ONE
/// [`ADMISSION_EXCHANGE_TIMEOUT`] budget (ct-agent#140). Returns the connection (and its
/// endpoint, kept alive with it) alongside the outcome — hop 1's caller drops it right
/// away, hop 2's caller opens the session stream on it.
async fn join_hop(
    addr: SocketAddr,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    phase_marker: u8,
) -> Result<((Endpoint, Connection), JoinOutcome), DialError> {
    let deadline = tokio::time::Instant::now() + ADMISSION_EXCHANGE_TIMEOUT;
    let (endpoint, conn) = tokio::time::timeout_at(deadline, dial_quic(addr))
        .await
        .map_err(|_| DialError::TimedOut)??;
    // Bounded like every other await — quinn's open_bi() resolves only once the peer's
    // flow control grants stream credit, so a broker (or an on-path party, given
    // AcceptAnyServerCert) that completes the handshake and keeps the connection's idle
    // timer alive but never grants a stream could otherwise hang this past the budget
    // (real finding, 2026-09-02 review; ct-agent#140 bounds its open_bi identically).
    let (mut send, mut recv) = tokio::time::timeout_at(deadline, conn.open_bi())
        .await
        .map_err(|_| DialError::TimedOut)?
        .map_err(|e| DialError::DialFailed(e.to_string()))?;
    let outcome = present_join(&mut send, &mut recv, request, holder, deadline, Some(phase_marker)).await?;
    Ok(((endpoint, conn), outcome))
}

/// Reach the customer's agent through this deployment's own broker (`broker_addr`, the
/// rendezvous port) and relay (`relay_addr`), presenting `grant` as `own_holder` on both
/// hops, complete the Noise_IK handshake with whoever the broker paired this join with,
/// send one JSON-RPC `tools/call` for `tool_name` with `arguments`, and return the decoded
/// JSON-RPC response's `result` (or an error if the call itself returned a JSON-RPC error
/// object). The two-hop sequence is described in the module doc (#745).
///
/// `own_holder`/`own_noise_private` are the shared bridge identity's own keys — the SAME
/// keypair for every tunnel this deployment bridges into, admitted separately per-tunnel by
/// each owner's own `channel/grant` call (see the Agent-bridges-v2 plan's Decisions §2).
/// Never logs or returns either private key.
pub async fn dial_and_call(
    broker_addr: SocketAddr,
    relay_addr: SocketAddr,
    grant: SignedChannelGrant,
    own_holder: &SigningKey,
    own_noise_private: &[u8; 32],
    tool_name: &str,
    arguments: serde_json::Value,
) -> Result<serde_json::Value, DialError> {
    let channel = grant.grant.channel;
    // The SAME request is presented on both hops (same grant, same holder, same
    // relay-only endpoint) — ct-agent passes one `&request` through `join_via_relay`.
    let request = ChannelJoinRequest {
        grant,
        endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
    };

    // Hop 1 — rendezvous. Its only product is the peer's attested Noise material; the
    // connection is dropped at the end of this block (the `:4435` completer just awaits
    // our close after acking — nothing further is ever read or written on it).
    let (peer_noise_pubkey, peer_holder, peer_attestation) = {
        let (_rendezvous_conn, outcome) =
            join_hop(broker_addr, &request, own_holder, PHASE_MARKER_RENDEZVOUS).await?;
        match outcome {
            JoinOutcome::Refused { category } => return Err(DialError::Refused { category }),
            JoinOutcome::ParkExpired => return Err(DialError::NoPeer),
            JoinOutcome::Admitted {
                peer_noise_pubkey: Some(pk),
                peer_holder: Some(holder),
                peer_attestation: Some(att),
            } => (pk, holder, att),
            // ct-agent#101: an `OK` with a missing triple is never a usable peer.
            JoinOutcome::Admitted { .. } => return Err(DialError::NoVerifiedPeer),
        }
    };

    reject_unverified_peer(&channel, &peer_holder, &peer_noise_pubkey, &peer_attestation)?;

    // Hop 2 — relay, on a SEPARATE connection dialed only now (ct-agent#103). Started
    // promptly after hop 1 so our `:4436` park overlaps the acceptor's, which re-parks
    // there right after its own hop-1 ack. The relay ack's peer material is NOT
    // authoritative (ct-agent's `join_via_relay` discards it and pins the hop-1-verified
    // key; a substituted key would fail the Noise_IK AEAD anyway), so an `OK` without
    // the triple is tolerated here — only refusal/expiry matter.
    let ((_relay_endpoint, relay_conn), outcome) =
        join_hop(relay_addr, &request, own_holder, PHASE_MARKER_RELAY).await?;
    match outcome {
        JoinOutcome::Refused { category } => return Err(DialError::Refused { category }),
        JoinOutcome::ParkExpired => return Err(DialError::NoPeer),
        JoinOutcome::Admitted { .. } => {}
    }

    // The SESSION stream: a fresh bi-stream on the relay connection — the admission
    // stream above was `finish()`ed after the signature and the edge never reads session
    // bytes from it; it splices our NEXT bi-stream to the acceptor. quinn's open_bi is
    // lazy: the edge's `accept_bi` (bounded 5 s from the acks) resolves only when the
    // first bytes — Noise msg1, written first thing by `a2a_initiate` — go out, so nothing
    // is awaited from the edge before writing.
    let (mut send, mut recv) = tokio::time::timeout(SESSION_STREAM_TIMEOUT, relay_conn.open_bi())
        .await
        .map_err(|_| DialError::TimedOut)?
        .map_err(|e| DialError::Session(format!("relay session stream open failed: {e}")))?;

    let mut session = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        a2a_initiate(&mut send, &mut recv, own_noise_private, &peer_noise_pubkey),
    )
    .await
    .map_err(|_| DialError::TimedOut)?
    .map_err(|e| DialError::Session(e.to_string()))?;

    let call_deadline = tokio::time::Instant::now() + CALL_TIMEOUT;
    let req_bytes = encode_request(1, "tools/call", serde_json::json!({ "name": tool_name, "arguments": arguments }));
    tokio::time::timeout_at(call_deadline, a2a_send(&mut send, &mut session, &req_bytes))
        .await
        .map_err(|_| DialError::TimedOut)?
        .map_err(|e| DialError::Session(e.to_string()))?;
    let reply_bytes = tokio::time::timeout_at(call_deadline, a2a_recv(&mut recv, &mut session))
        .await
        .map_err(|_| DialError::TimedOut)?
        .map_err(|e| DialError::Session(e.to_string()))?;
    // FIN our half now that the one reply is in hand (ct-agent#134's `finish()` habit;
    // the reply is already received, so no drain wait is needed for a one-shot call).
    let _ = send.finish();

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
        let outcome = present_join(send, recv, &request, &holder, deadline, None).await.unwrap();
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
        let outcome = present_join(send, recv, &request, &holder, deadline, None).await.unwrap();
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

    #[tokio::test]
    async fn present_join_recovers_the_category_of_a_post_possession_refusal() {
        // 2026-09-02 review finding: a refusal arriving AFTER the possession challenge (e.g.
        // "pairing" -- admitted, but pairing the two members was refused -- can only ever be
        // delivered this way) must not silently lose its category to a naive lossy-UTF8 parse.
        let (agent_side, mut broker_side) = tokio::io::duplex(4096);
        let holder = SigningKey::from_bytes(&[42u8; 32]);
        let grant = crate::channel::SignedChannelGrant {
            grant: crate::channel::ChannelGrant {
                channel: ChannelId([5u8; 32]),
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
            broker_side.write_all(&[0u8; POSSESSION_CHALLENGE_LEN]).await.unwrap();
            let mut sig = [0u8; 64];
            broker_side.read_exact(&mut sig).await.unwrap();
            // NO | len(u8) | token — the byte-level refusal frame, sent AFTER possession.
            let token = b"pairing";
            let mut frame = b"NO".to_vec();
            frame.push(token.len() as u8);
            frame.extend_from_slice(token);
            broker_side.write_all(&frame).await.unwrap();
        });

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let (recv, send) = tokio::io::split(agent_side);
        let outcome = present_join(send, recv, &request, &holder, deadline, None).await.unwrap();
        assert_eq!(
            outcome,
            JoinOutcome::Refused { category: Some("pairing".to_string()) },
            "the post-possession refusal's category must survive, not collapse to None"
        );
        broker.await.unwrap();
    }

    #[test]
    fn reject_unverified_peer_accepts_a_real_attestation_and_rejects_a_forged_one() {
        let channel = ChannelId([3u8; 32]);
        let holder_key = SigningKey::from_bytes(&[11u8; 32]);
        let holder_pub = holder_key.verifying_key().to_bytes();
        let noise_pub = [12u8; 32];
        let attest_bytes = crate::channel::member_noise_attest_bytes(&channel, &holder_pub, &noise_pub);
        let real_attestation: [u8; 64] = holder_key.sign(&attest_bytes).to_bytes().try_into().unwrap();

        assert!(
            reject_unverified_peer(&channel, &holder_pub, &noise_pub, &real_attestation).is_ok(),
            "a genuinely valid attestation must be accepted"
        );

        // Same holder/noise pair, but signed for a DIFFERENT channel — the exact shape of what
        // a broker (malicious or confused) pairing us against the wrong registry entry, or an
        // attacker replaying a real attestation from elsewhere, would produce.
        let wrong_channel = ChannelId([4u8; 32]);
        let wrong_bytes = crate::channel::member_noise_attest_bytes(&wrong_channel, &holder_pub, &noise_pub);
        let forged: [u8; 64] = holder_key.sign(&wrong_bytes).to_bytes().try_into().unwrap();
        assert_eq!(
            reject_unverified_peer(&channel, &holder_pub, &noise_pub, &forged),
            Err(DialError::NoVerifiedPeer),
            "an attestation signed for a different channel must be rejected, not silently accepted"
        );

        // A well-formed-looking but entirely wrong signature (not even from the claimed holder).
        assert_eq!(
            reject_unverified_peer(&channel, &holder_pub, &noise_pub, &[0u8; 64]),
            Err(DialError::NoVerifiedPeer),
        );
    }

    #[test]
    fn error_names_park_expiry_matches_the_edges_wire_reason_anywhere_in_the_source_chain() {
        #[derive(Debug)]
        struct Wrapped(std::io::Error);
        impl std::fmt::Display for Wrapped {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "wrapped: {}", self.0)
            }
        }
        impl std::error::Error for Wrapped {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        let marker = PARK_EXPIRED_REASON_PREFIX.strip_suffix(':').unwrap_or(PARK_EXPIRED_REASON_PREFIX);
        let inner = std::io::Error::other(format!("{marker}: no partner within the park TTL"));
        assert!(
            error_names_park_expiry(&Wrapped(inner)),
            "must recognize the marker anywhere in the error's source chain, not just at the top level"
        );

        let unrelated = std::io::Error::other("connection reset by peer");
        assert!(!error_names_park_expiry(&unrelated), "an unrelated error must not be misclassified as a park expiry");
    }

    // ------------------------------------------------------------------------------------
    // #745: the two-hop dial (rendezvous -> relay -> fresh session bi-stream).
    //
    // Two layers, by what each assertion can observe:
    //   (b) `present_join` over a `tokio::io::duplex` -- byte-level admission facts
    //       (preamble, identical request, NUL skip, `EX`, the per-hop budget under a
    //       paused clock);
    //   (a) a hermetic loopback quinn `MockBroker` (self-signed `rcgen` cert, `127.0.0.1:0`)
    //       -- the connection-level facts that ARE the bug: a second CONNECTION to the relay
    //       address, a second BI-STREAM on it carrying Noise msg1, hop 2 only after hop 1's
    //       ack, `park-expired` close reason -> `NoPeer`.
    // Every mock await is bounded (5 s) so a regression fails, never hangs, under CI.
    // ------------------------------------------------------------------------------------

    use std::sync::Mutex;
    use std::time::Instant;

    const MOCK_IO_TIMEOUT: Duration = Duration::from_secs(5);
    /// Outer bound on one whole `dial_and_call` under test: every mock path either acks
    /// promptly or closes, so a dial that takes longer than this has regressed.
    const DIAL_UNDER_TEST_TIMEOUT: Duration = Duration::from_secs(15);
    const CHANNEL_745: ChannelId = ChannelId([0x45u8; 32]);

    /// The customer's agent (acceptor) as the brokers describe it in the rich ack: a real
    /// holder key, a real Noise static key and the real #101 attestation binding them to
    /// the channel -- so hop 1's `reject_unverified_peer` passes on genuine material.
    struct Peer {
        holder: SigningKey,
        noise_public: [u8; 32],
        noise_private: [u8; 32],
        attest: [u8; 64],
    }

    fn peer_for(channel: &ChannelId) -> Peer {
        let holder = SigningKey::from_bytes(&[0xb2u8; 32]);
        let noise = crate::noise::generate_static_keypair();
        let holder_pub = holder.verifying_key().to_bytes();
        let bytes = crate::channel::member_noise_attest_bytes(channel, &holder_pub, &noise.public);
        let attest: [u8; 64] = holder.sign(&bytes).to_bytes();
        Peer { holder, noise_public: noise.public, noise_private: noise.private, attest }
    }

    /// The exact ack line the edge's `finish_quic_pair_inner` writes on BOTH QUIC completers
    /// (`OK <peer-endpoint> <noise> <holder> <attest> r=<own observed> sp=<0|1>`), EOF-terminated.
    fn rich_ack(peer: &Peer) -> String {
        format!(
            "OK relay-only {} {} {} r=127.0.0.1:1 sp=1",
            hex_encode(&peer.noise_public),
            hex_encode(&peer.holder.verifying_key().to_bytes()),
            hex_encode(&peer.attest)
        )
    }

    /// The bridge's own identity: holder key, Noise private key, and an Initiate grant on
    /// `CHANNEL_745` (the mocks never verify the operator signature, like the existing tests).
    struct Bridge {
        holder: SigningKey,
        noise_private: [u8; 32],
        grant: SignedChannelGrant,
    }

    fn bridge() -> Bridge {
        let holder = SigningKey::from_bytes(&[0xa1u8; 32]);
        let noise = crate::noise::generate_static_keypair();
        let grant = SignedChannelGrant {
            grant: crate::channel::ChannelGrant {
                channel: CHANNEL_745,
                holder: holder.verifying_key().to_bytes(),
                direction: crate::channel::Direction::Initiate,
                rights: crate::channel::Rights::ReadWrite,
                delegable: false,
                expires_at: u64::MAX,
            },
            signature: [0u8; 64],
        };
        Bridge { holder, noise_private: noise.private, grant }
    }

    fn join_request(bridge: &Bridge) -> ChannelJoinRequest {
        ChannelJoinRequest { grant: bridge.grant.clone(), endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string() }
    }

    /// What a mock does AFTER acking an admission.
    #[derive(Clone)]
    enum After {
        /// Rendezvous shape: idle until the client closes the connection.
        Nothing,
        /// Relay shape: `accept_bi()` the client's NEXT bi-stream, record its first
        /// `2 + 96` bytes (Noise_IK msg1 as one `frame()`), act as the acceptor
        /// (`a2a_respond`), decrypt the one JSON-RPC request and answer it with `result`.
        ServeSecondBi { noise_private: [u8; 32], result: serde_json::Value },
        /// Relay shape, but only record msg1 and then close the connection (no reply).
        RecordSecondBiThenClose,
    }

    /// The scripted broker decision, delivered after the possession signature.
    #[derive(Clone)]
    enum Reply {
        /// `leading_nuls` x `0x00` (#500 park keepalive shape), then `ack`, then FIN.
        Admit { ack: String, leading_nuls: usize, then: After },
        /// Raw post-possession bytes (e.g. a #524 `NO|len|token` frame), then FIN.
        RefusePostPossession(Vec<u8>),
        /// Park the member, then reap it: `conn.close(0, reason)` with no ack -- exactly
        /// what the edge does on a park TTL expiry (`quic_park_expired_reason`).
        ParkThenCloseWith(String),
    }

    /// Everything a mock observed on one accepted connection.
    struct ConnLog {
        accepted_at: Instant,
        preamble: Option<u8>,
        request: Option<ChannelJoinRequest>,
        admission_stream: quinn::StreamId,
        sig_valid: bool,
        /// The client FINed its send half right after the signature (the QUIC leg shape).
        eof_after_sig: bool,
        /// Anything the client wrote on the ADMISSION stream after the signature.
        admission_stream_extra_bytes: Vec<u8>,
        /// The SECOND bi-stream the client opened on this connection: its id + first bytes.
        second_bi: Option<(quinn::StreamId, Vec<u8>)>,
    }

    #[derive(Default)]
    struct Log {
        connections: Vec<ConnLog>,
        ack_written_at: Option<Instant>,
    }

    /// A loopback quinn broker that runs the edge's admission handshake for every accepted
    /// connection, records what it saw, and then executes its scripted [`Reply`]. `gate`, when
    /// set, is awaited AFTER the signature and BEFORE the ack -- so a test can hold an ack back.
    struct MockBroker {
        addr: SocketAddr,
        log: Arc<Mutex<Log>>,
        _endpoint: Endpoint,
    }

    fn mock_server_endpoint() -> Endpoint {
        install_crypto_provider();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("self-signed cert");
        let cert = certified.cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            certified.key_pair.serialize_der(),
        ));
        let cfg = quinn::ServerConfig::with_single_cert(vec![cert], key).expect("server config");
        Endpoint::server(cfg, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind 127.0.0.1:0")
    }

    impl MockBroker {
        fn spawn(reply: Reply, gate: Option<Arc<tokio::sync::Notify>>) -> Self {
            let endpoint = mock_server_endpoint();
            let addr = endpoint.local_addr().expect("local addr");
            let log = Arc::new(Mutex::new(Log::default()));
            let accept_on = endpoint.clone();
            let accept_log = log.clone();
            tokio::spawn(async move {
                while let Some(incoming) = accept_on.accept().await {
                    let reply = reply.clone();
                    let log = accept_log.clone();
                    let gate = gate.clone();
                    tokio::spawn(async move {
                        if let Ok(conn) = incoming.await {
                            let _ = mock_handle_connection(conn, reply, log, gate).await;
                        }
                    });
                }
            });
            MockBroker { addr, log, _endpoint: endpoint }
        }

        fn connections(&self) -> usize {
            self.log.lock().unwrap().connections.len()
        }

        fn ack_written_at(&self) -> Instant {
            self.log.lock().unwrap().ack_written_at.expect("the mock acked")
        }
    }

    async fn mock_handle_connection(
        conn: Connection,
        reply: Reply,
        log: Arc<Mutex<Log>>,
        gate: Option<Arc<tokio::sync::Notify>>,
    ) -> Result<(), BoxError> {
        let t = MOCK_IO_TIMEOUT;
        let accepted_at = Instant::now();
        let (mut send, mut recv) = tokio::time::timeout(t, conn.accept_bi()).await??;
        // The optional `[0xFF, phase]` preamble, peeked exactly like the edge's
        // `peek_optional_phase_marker`: 0xFF can never start a real u16 length here.
        let mut head = [0u8; 2];
        tokio::time::timeout(t, recv.read_exact(&mut head)).await??;
        let (preamble, len) = if head[0] == PHASE_PREAMBLE_MAGIC {
            let mut len_buf = [0u8; 2];
            tokio::time::timeout(t, recv.read_exact(&mut len_buf)).await??;
            (Some(head[1]), u16::from_be_bytes(len_buf))
        } else {
            (None, u16::from_be_bytes(head))
        };
        let mut body = vec![0u8; len as usize];
        tokio::time::timeout(t, recv.read_exact(&mut body)).await??;
        let request = ChannelJoinRequest::decode(&body).ok();
        let idx = {
            let mut l = log.lock().unwrap();
            l.connections.push(ConnLog {
                accepted_at,
                preamble,
                request: request.clone(),
                admission_stream: send.id(),
                sig_valid: false,
                eof_after_sig: false,
                admission_stream_extra_bytes: Vec::new(),
                second_bi: None,
            });
            l.connections.len() - 1
        };
        let challenge = [0x5au8; POSSESSION_CHALLENGE_LEN];
        send.write_all(&challenge).await?;
        let mut sig = [0u8; 64];
        tokio::time::timeout(t, recv.read_exact(&mut sig)).await??;
        let sig_valid = request
            .as_ref()
            .and_then(|r| ed25519_dalek::VerifyingKey::from_bytes(&r.grant.grant.holder).ok())
            .map(|vk| vk.verify_strict(&challenge, &ed25519_dalek::Signature::from_bytes(&sig)).is_ok())
            .unwrap_or(false);
        // The client FINs its send half right after the signature; drain to that FIN and keep
        // whatever else (wrongly) arrived on the admission stream.
        let drained = tokio::time::timeout(t, recv.read_to_end(1024)).await;
        {
            let mut l = log.lock().unwrap();
            let c = &mut l.connections[idx];
            c.sig_valid = sig_valid;
            if let Ok(Ok(extra)) = drained {
                c.eof_after_sig = true;
                c.admission_stream_extra_bytes = extra;
            }
        }
        if let Some(gate) = gate {
            gate.notified().await;
        }
        match reply {
            Reply::Admit { ack, leading_nuls, then } => {
                send.write_all(&vec![0u8; leading_nuls]).await?;
                send.write_all(ack.as_bytes()).await?;
                send.finish()?;
                log.lock().unwrap().ack_written_at = Some(Instant::now());
                match then {
                    After::Nothing => {
                        conn.closed().await;
                    }
                    After::RecordSecondBiThenClose => {
                        let (s2, mut r2) = tokio::time::timeout(t, conn.accept_bi()).await??;
                        let mut first = vec![0u8; 2 + 96];
                        tokio::time::timeout(t, r2.read_exact(&mut first)).await??;
                        log.lock().unwrap().connections[idx].second_bi = Some((s2.id(), first));
                        conn.close(0u32.into(), b"recorded");
                    }
                    After::ServeSecondBi { noise_private, result } => {
                        let (mut s2, mut r2) = tokio::time::timeout(t, conn.accept_bi()).await??;
                        // Record msg1's frame, then replay it in front of the live stream so the
                        // responder still sees the whole handshake.
                        let mut first = vec![0u8; 2 + 96];
                        tokio::time::timeout(t, r2.read_exact(&mut first)).await??;
                        log.lock().unwrap().connections[idx].second_bi = Some((s2.id(), first.clone()));
                        let mut r2 = std::io::Cursor::new(first).chain(r2);
                        let mut session =
                            tokio::time::timeout(t, crate::a2a::a2a_respond(&mut s2, &mut r2, &noise_private)).await??;
                        let req = tokio::time::timeout(t, a2a_recv(&mut r2, &mut session)).await??;
                        let req: serde_json::Value = serde_json::from_slice(&req)?;
                        let resp = serde_json::json!({ "jsonrpc": "2.0", "id": req["id"].clone(), "result": result });
                        tokio::time::timeout(t, a2a_send(&mut s2, &mut session, &serde_json::to_vec(&resp)?)).await??;
                        s2.finish()?;
                        conn.closed().await;
                    }
                }
            }
            Reply::RefusePostPossession(bytes) => {
                send.write_all(&bytes).await?;
                send.finish()?;
                conn.closed().await;
            }
            Reply::ParkThenCloseWith(reason) => {
                conn.close(0u32.into(), reason.as_bytes());
            }
        }
        Ok(())
    }

    fn admit(peer: &Peer, then: After) -> Reply {
        Reply::Admit { ack: rich_ack(peer), leading_nuls: 0, then }
    }

    fn serve(peer: &Peer) -> After {
        After::ServeSecondBi { noise_private: peer.noise_private, result: serde_json::json!({ "echoed": { "x": 1 } }) }
    }

    async fn dial(rendezvous: &MockBroker, relay: &MockBroker, bridge: &Bridge) -> Result<serde_json::Value, DialError> {
        tokio::time::timeout(
            DIAL_UNDER_TEST_TIMEOUT,
            dial_and_call(
                rendezvous.addr,
                relay.addr,
                bridge.grant.clone(),
                &bridge.holder,
                &bridge.noise_private,
                "echo",
                serde_json::json!({ "x": 1 }),
            ),
        )
        .await
        .expect("dial_and_call must finish well within the mocks' own bounds")
    }

    // --- duplex-side helpers (layer b) ---

    /// Read one length-framed join off a duplex, tolerating the optional `[0xFF, phase]`
    /// preamble exactly as the edge does. Returns `(preamble, raw request bytes)`.
    async fn read_join_on_duplex(s: &mut tokio::io::DuplexStream) -> (Option<u8>, Vec<u8>) {
        let mut head = [0u8; 2];
        s.read_exact(&mut head).await.unwrap();
        let (preamble, len) = if head[0] == PHASE_PREAMBLE_MAGIC {
            let mut len_buf = [0u8; 2];
            s.read_exact(&mut len_buf).await.unwrap();
            (Some(head[1]), u16::from_be_bytes(len_buf))
        } else {
            (None, u16::from_be_bytes(head))
        };
        let mut body = vec![0u8; len as usize];
        s.read_exact(&mut body).await.unwrap();
        (preamble, body)
    }

    async fn challenge_and_read_signature(s: &mut tokio::io::DuplexStream) {
        s.write_all(&[0u8; POSSESSION_CHALLENGE_LEN]).await.unwrap();
        let mut sig = [0u8; 64];
        s.read_exact(&mut sig).await.unwrap();
    }

    fn admitted_triple(peer: &Peer) -> JoinOutcome {
        JoinOutcome::Admitted {
            peer_noise_pubkey: Some(peer.noise_public),
            peer_holder: Some(peer.holder.verifying_key().to_bytes()),
            peer_attestation: Some(peer.attest),
        }
    }

    // --- (1) ---
    #[tokio::test]
    async fn dial_and_call_opens_a_second_connection_to_the_relay_address_not_the_broker_745() {
        let peer = peer_for(&CHANNEL_745);
        let bridge = bridge();
        let rendezvous = MockBroker::spawn(admit(&peer, After::Nothing), None);
        let relay = MockBroker::spawn(admit(&peer, serve(&peer)), None);

        let result = dial(&rendezvous, &relay, &bridge).await;
        assert_eq!(result, Ok(serde_json::json!({ "echoed": { "x": 1 } })), "the tools/call reply reaches the caller");

        let r = rendezvous.log.lock().unwrap();
        let l = relay.log.lock().unwrap();
        assert_eq!(r.connections.len(), 1, "exactly one rendezvous connection");
        assert_eq!(l.connections.len(), 1, "exactly one relay connection -- the hop that was missing before #745");
        assert!(r.connections[0].sig_valid, "hop 1 proved possession with the bridge holder key");
        assert!(l.connections[0].sig_valid, "hop 2 proved possession with the same key");
        // (3') at layer (a): the relay admission carries the RELAY marker and the IDENTICAL request.
        assert_eq!(l.connections[0].preamble, Some(PHASE_MARKER_RELAY), "hop 2 is marked as the relay phase");
        assert!(
            matches!(r.connections[0].preamble, None | Some(PHASE_MARKER_RENDEZVOUS)),
            "hop 1 is bare or marked rendezvous, never anything else (#509)"
        );
        assert_eq!(l.connections[0].request, r.connections[0].request, "both hops present the same ChannelJoinRequest");
        assert_eq!(
            l.connections[0].request.as_ref().map(|q| q.endpoint.as_str()),
            Some(CHANNEL_ENDPOINT_RELAY_ONLY),
            "the bridge is relay-only on both hops"
        );
    }

    // --- (2') ---
    #[tokio::test]
    async fn relay_session_runs_on_a_second_bi_stream_and_the_admission_stream_stays_silent_745() {
        let peer = peer_for(&CHANNEL_745);
        let bridge = bridge();
        let rendezvous = MockBroker::spawn(admit(&peer, After::Nothing), None);
        let relay = MockBroker::spawn(admit(&peer, After::RecordSecondBiThenClose), None);

        // The relay mock records msg1 and hangs up instead of answering, so the dial itself
        // ends in an error -- only the mock's log matters here.
        let result = dial(&rendezvous, &relay, &bridge).await;
        assert!(result.is_err(), "the mock never answers msg2, so the dial cannot succeed: {result:?}");

        let l = relay.log.lock().unwrap();
        assert_eq!(l.connections.len(), 1);
        let c = &l.connections[0];
        assert!(c.eof_after_sig, "the relay admission stream is FINed right after the signature (throwaway)");
        assert!(
            c.admission_stream_extra_bytes.is_empty(),
            "nothing is ever written on the admission stream after the signature (spec B5/B9), got {:?}",
            c.admission_stream_extra_bytes
        );
        let (session_stream, first) = c.second_bi.as_ref().expect("the session runs on a SECOND bi-stream");
        assert_ne!(*session_stream, c.admission_stream, "the session stream is a different stream from the admission stream");
        assert_eq!(&first[..2], &[0x00, 0x60], "Noise_IK msg1 is framed as a 2-byte length (96) + body");
        assert_eq!(first.len(), 98);
    }

    // --- (3') layer (b) ---
    #[tokio::test]
    async fn relay_admission_reuses_the_identical_join_request_and_marks_phase_relay_745() {
        let bridge = bridge();
        let request = join_request(&bridge);
        let mut seen = Vec::new();
        for marker in [PHASE_MARKER_RENDEZVOUS, PHASE_MARKER_RELAY] {
            let (agent_side, mut broker_side) = tokio::io::duplex(4096);
            let broker = tokio::spawn(async move {
                let observed = read_join_on_duplex(&mut broker_side).await;
                challenge_and_read_signature(&mut broker_side).await;
                broker_side.write_all(b"OK relay-only r=127.0.0.1:1 sp=1").await.unwrap();
                broker_side.shutdown().await.unwrap();
                observed
            });
            let deadline = tokio::time::Instant::now() + MOCK_IO_TIMEOUT;
            let (recv, send) = tokio::io::split(agent_side);
            let outcome = present_join(send, recv, &request, &bridge.holder, deadline, Some(marker)).await.unwrap();
            assert!(matches!(outcome, JoinOutcome::Admitted { .. }), "{outcome:?}");
            seen.push(tokio::time::timeout(MOCK_IO_TIMEOUT, broker).await.unwrap().unwrap());
        }
        let (rendezvous_preamble, rendezvous_bytes) = &seen[0];
        let (relay_preamble, relay_bytes) = &seen[1];
        assert!(matches!(rendezvous_preamble, None | Some(PHASE_MARKER_RENDEZVOUS)), "{rendezvous_preamble:?}");
        assert_eq!(*relay_preamble, Some(PHASE_MARKER_RELAY), "the relay leg is marked `[0xFF, 0x02]`");
        for p in [rendezvous_preamble, relay_preamble].into_iter().flatten() {
            assert!(
                *p == PHASE_MARKER_RENDEZVOUS || *p == PHASE_MARKER_RELAY,
                "an unknown phase byte is a definitive refusal that charges the per-IP penalty (#509)"
            );
        }
        assert_eq!(rendezvous_bytes, relay_bytes, "both legs present byte-identical requests");
        assert_eq!(*relay_bytes, request.encode());
        let decoded = ChannelJoinRequest::decode(relay_bytes).unwrap();
        assert_eq!(decoded.grant, bridge.grant);
        assert_eq!(decoded.endpoint, CHANNEL_ENDPOINT_RELAY_ONLY);
    }

    // --- (4) ---
    #[tokio::test]
    async fn relay_leg_skips_leading_nul_keepalives_before_the_ack_500_745() {
        let peer = peer_for(&CHANNEL_745);
        let bridge = bridge();

        // (b): `0x00 0x00 0x00` then the rich ack, EOF-terminated.
        let request = join_request(&bridge);
        let ack = rich_ack(&peer);
        let (agent_side, mut broker_side) = tokio::io::duplex(4096);
        let broker = tokio::spawn(async move {
            let _ = read_join_on_duplex(&mut broker_side).await;
            challenge_and_read_signature(&mut broker_side).await;
            broker_side.write_all(&[0u8, 0, 0]).await.unwrap();
            broker_side.write_all(ack.as_bytes()).await.unwrap();
            broker_side.shutdown().await.unwrap();
        });
        let deadline = tokio::time::Instant::now() + MOCK_IO_TIMEOUT;
        let (recv, send) = tokio::io::split(agent_side);
        let outcome = present_join(send, recv, &request, &bridge.holder, deadline, Some(PHASE_MARKER_RELAY)).await.unwrap();
        assert_eq!(outcome, admitted_triple(&peer), "leading NULs are park keepalives, not ack bytes");
        tokio::time::timeout(MOCK_IO_TIMEOUT, broker).await.unwrap().unwrap();

        // (a): the same through the real two-hop dial.
        let rendezvous = MockBroker::spawn(admit(&peer, After::Nothing), None);
        let relay = MockBroker::spawn(Reply::Admit { ack: rich_ack(&peer), leading_nuls: 3, then: serve(&peer) }, None);
        let result = dial(&rendezvous, &relay, &bridge).await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(relay.connections(), 1);
    }

    // --- (5) ---
    #[tokio::test]
    async fn relay_leg_park_expiry_maps_to_no_peer_745() {
        let peer = peer_for(&CHANNEL_745);
        let bridge = bridge();

        // (a): the relay reaps our park with the edge's exact close reason.
        let rendezvous = MockBroker::spawn(admit(&peer, After::Nothing), None);
        let reason = format!("{PARK_EXPIRED_REASON_PREFIX} no partner within the park TTL");
        let relay = MockBroker::spawn(Reply::ParkThenCloseWith(reason), None);
        let result = dial(&rendezvous, &relay, &bridge).await;
        assert_eq!(result, Err(DialError::NoPeer), "a reaped relay park is `NoPeer`, not a transport failure or refusal");
        assert!(rendezvous.log.lock().unwrap().connections[0].sig_valid, "hop 1 completed first");
        assert_eq!(relay.connections(), 1);

        // (b): the `EX` token on a stream leg maps the same way.
        let request = join_request(&bridge);
        let (agent_side, mut broker_side) = tokio::io::duplex(4096);
        let broker = tokio::spawn(async move {
            let _ = read_join_on_duplex(&mut broker_side).await;
            challenge_and_read_signature(&mut broker_side).await;
            broker_side.write_all(PARK_EXPIRED_TOKEN).await.unwrap();
            broker_side.shutdown().await.unwrap();
        });
        let deadline = tokio::time::Instant::now() + MOCK_IO_TIMEOUT;
        let (recv, send) = tokio::io::split(agent_side);
        let outcome = present_join(send, recv, &request, &bridge.holder, deadline, Some(PHASE_MARKER_RELAY)).await.unwrap();
        assert_eq!(outcome, JoinOutcome::ParkExpired);
        tokio::time::timeout(MOCK_IO_TIMEOUT, broker).await.unwrap().unwrap();
    }

    // --- (6) ---
    #[tokio::test]
    async fn relay_leg_refusal_preserves_a_ten_byte_category_524_745() {
        let peer = peer_for(&CHANNEL_745);
        let bridge = bridge();
        let rendezvous = MockBroker::spawn(admit(&peer, After::Nothing), None);
        // `NO | 0x0A | "possession"`: the length byte IS the newline -- the #524 collision.
        let mut frame = b"NO".to_vec();
        frame.push(0x0A);
        frame.extend_from_slice(b"possession");
        let relay = MockBroker::spawn(Reply::RefusePostPossession(frame), None);

        let result = dial(&rendezvous, &relay, &bridge).await;
        assert_eq!(result, Err(DialError::Refused { category: Some("possession".to_string()) }));
        let relay_accepted_at = relay.log.lock().unwrap().connections[0].accepted_at;
        assert!(rendezvous.ack_written_at() < relay_accepted_at, "hop 1 was acked before hop 2 was even dialed");
    }

    // --- (7) ---
    #[tokio::test]
    async fn rendezvous_leg_still_finishes_its_send_half_after_the_signature_745() {
        let peer = peer_for(&CHANNEL_745);
        let bridge = bridge();
        let rendezvous = MockBroker::spawn(admit(&peer, After::Nothing), None);
        let relay = MockBroker::spawn(admit(&peer, serve(&peer)), None);
        assert!(dial(&rendezvous, &relay, &bridge).await.is_ok());
        let r = rendezvous.log.lock().unwrap();
        assert!(r.connections[0].eof_after_sig, "the `:4435` completer expects the client's FIN after the signature");
        assert!(r.connections[0].admission_stream_extra_bytes.is_empty());
        assert!(r.connections[0].second_bi.is_none(), "no session stream is ever opened on the rendezvous connection");
    }

    // --- (8) ---
    #[tokio::test(start_paused = true)]
    async fn per_hop_admission_budget_outlives_the_park_ttl_745() {
        // A partner that arrives 25 s into our 30 s park window is a SUCCESS on the edge; the
        // client's per-hop budget must not give up first (the #140 mistake).
        let peer = peer_for(&CHANNEL_745);
        let bridge = bridge();
        let request = join_request(&bridge);
        let ack = rich_ack(&peer);
        let (agent_side, mut broker_side) = tokio::io::duplex(4096);
        let broker = tokio::spawn(async move {
            let _ = read_join_on_duplex(&mut broker_side).await;
            challenge_and_read_signature(&mut broker_side).await;
            tokio::time::sleep(Duration::from_secs(25)).await;
            broker_side.write_all(ack.as_bytes()).await.unwrap();
            broker_side.shutdown().await.unwrap();
        });
        let deadline = tokio::time::Instant::now() + ADMISSION_EXCHANGE_TIMEOUT;
        let (recv, send) = tokio::io::split(agent_side);
        let outcome = present_join(send, recv, &request, &bridge.holder, deadline, Some(PHASE_MARKER_RELAY)).await;
        assert_eq!(outcome, Ok(admitted_triple(&peer)), "a 25 s ack is inside the per-hop budget");
        broker.await.unwrap();
    }

    #[test]
    fn dial_budget_outlives_one_park_window_on_each_leg_745() {
        // Edge-side constants this pins against (ct-edge is not a dependency of this crate):
        // `CHANNEL_PARK_TTL_SECS = 30` (`serve.rs`) and the `BROKER_IDLE_TICK` of 10 s that
        // bounds how late after the TTL a reap can land (`channel_broker.rs`).
        const CHANNEL_PARK_TTL_SECS: u64 = 30;
        const BROKER_IDLE_TICK_SECS: u64 = 10;
        // Edge `RELAY_SETUP_TIMEOUT = 5 s` (`relay.rs`): accept_bi(initiator) then open_bi(acceptor).
        const RELAY_SETUP_TIMEOUT_SECS: u64 = 5;
        let park_window = Duration::from_secs(CHANNEL_PARK_TTL_SECS + BROKER_IDLE_TICK_SECS);
        assert!(
            ADMISSION_EXCHANGE_TIMEOUT >= park_window,
            "each hop's admission budget must outlive the edge's park window + reap tick, else a \
             legitimately late partner fails on the client while the edge is still waiting (#140)"
        );
        // Each hop is budgeted independently (`join_hop` computes its own deadline), so the
        // worst-case wall time of one dial is the sum of every phase -- at least two park windows.
        let worst_case = ADMISSION_EXCHANGE_TIMEOUT * 2 + SESSION_STREAM_TIMEOUT + HANDSHAKE_TIMEOUT + CALL_TIMEOUT;
        assert!(worst_case >= park_window * 2, "two hops, two full park windows");
        assert!(
            HANDSHAKE_TIMEOUT >= Duration::from_secs(2 * RELAY_SETUP_TIMEOUT_SECS),
            "the handshake bound covers the edge's own two sequential splice-setup bounds"
        );
    }

    // --- (9) ---
    #[tokio::test]
    async fn relay_connection_is_dialed_only_after_the_rendezvous_ack_103_745() {
        let peer = peer_for(&CHANNEL_745);
        let bridge = bridge();
        let gate = Arc::new(tokio::sync::Notify::new());
        let rendezvous = MockBroker::spawn(admit(&peer, After::Nothing), Some(gate.clone()));
        let relay = MockBroker::spawn(admit(&peer, serve(&peer)), None);

        let (rendezvous_addr, relay_addr) = (rendezvous.addr, relay.addr);
        let dialing = tokio::spawn(async move {
            let bridge = bridge;
            tokio::time::timeout(
                DIAL_UNDER_TEST_TIMEOUT,
                dial_and_call(
                    rendezvous_addr,
                    relay_addr,
                    bridge.grant.clone(),
                    &bridge.holder,
                    &bridge.noise_private,
                    "echo",
                    serde_json::json!({ "x": 1 }),
                ),
            )
            .await
            .expect("bounded")
        });

        // Hop 1 is admitted (signature seen) but its ack is being held back...
        let admitted = tokio::time::timeout(MOCK_IO_TIMEOUT, async {
            loop {
                if rendezvous.log.lock().unwrap().connections.first().is_some_and(|c| c.sig_valid) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(admitted.is_ok(), "hop 1 reached the signature");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(relay.connections(), 0, "the relay is NOT dialed while hop 1's ack is outstanding (ct-agent#103)");

        gate.notify_one();
        let result = dialing.await.unwrap();
        assert!(result.is_ok(), "{result:?}");
        let l = relay.log.lock().unwrap();
        assert_eq!(l.connections.len(), 1);
        assert!(l.connections[0].accepted_at > rendezvous.ack_written_at(), "hop 2 connects strictly after hop 1's ack");
        assert!(rendezvous.log.lock().unwrap().connections[0].eof_after_sig);
    }

    // --- (10) ---
    #[tokio::test]
    async fn relay_ack_without_an_attested_triple_is_tolerated_745() {
        // Hop 1's verified triple is authoritative (ct-agent's `join_via_relay` discards the
        // relay ack's fields); a bare `OK` on hop 2 must not be mistaken for `NoVerifiedPeer`.
        let peer = peer_for(&CHANNEL_745);
        let bridge = bridge();
        let rendezvous = MockBroker::spawn(admit(&peer, After::Nothing), None);
        let relay = MockBroker::spawn(
            Reply::Admit { ack: "OK relay-only r=127.0.0.1:1 sp=1".to_string(), leading_nuls: 0, then: serve(&peer) },
            None,
        );
        let result = dial(&rendezvous, &relay, &bridge).await;
        assert_eq!(result, Ok(serde_json::json!({ "echoed": { "x": 1 } })));
    }
}
