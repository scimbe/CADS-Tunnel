//! Agent-bridges-v2: the native-only channel **dialer policy** for a server-side caller
//! (`ct-control-plane`'s bridge dialer): reach the customer's agent through this
//! deployment's own broker/relay pair over QUIC, present a grant, complete the Noise_IK
//! handshake, send exactly one JSON-RPC `tools/call`, read the reply, disconnect.
//!
//! **This module no longer implements the wire protocol.** Phase 2 of the CADS-Tunnel/
//! ct-agent consolidation moved the channel join protocol's client half into this crate as
//! its normative home — [`crate::channel_wire`] (outcome type, ack parser, refusal-category
//! decoder, park-expiry classifier; `channel_wire::io` for the stream-generic admission
//! exchange) and [`crate::channel_quic`] (the accept-any-cert channel dialer) — a verbatim
//! port of ct-agent's `channel.rs`/`transport.rs` with its whole fix history (ct-agent#21
//! #23 #28 #36 #129 #140 #148, CADS-Tunnel#494 #495 #500 #506 #524 #557) and the guard
//! tests. Before that this module carried its own narrower copy of the same exchange; two
//! copies that each agreed with themselves could drift apart unnoticed (they already had,
//! in the reflexive/`r=` handling and the post-possession refusal category). What is left
//! here is only what a BRIDGE caller adds on top of the shared protocol:
//!
//! - the two-hop dial sequence and its per-phase budgets (#745, below),
//! - [`DialError`], the typed outcome the control-plane route handler and the portal's
//!   result page (which renders its `Display`) react to, and the ONE adapter
//!   ([`present_join`]) that maps the shared exchange's outcomes and `BoxError`s onto it,
//! - the ct-agent#101 trust gate [`reject_unverified_peer`] between "the broker paired us
//!   with someone" and "we run a Noise handshake with them".
//!
//! It deliberately does NOT implement the direct-address path, the `:443` front-door
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
//! Everything below the admission (the Noise_IK handshake, the encrypted send/recv, the
//! JSON-RPC request encoding) reuses this crate's own [`crate::a2a`]/[`crate::mcp`].
//!
//! `#[cfg(not(target_arch = "wasm32"))]`-gated: this crate is also compiled for the browser
//! channel-claim page (wasm32-unknown-unknown), which has no `quinn`/`rustls`/`tokio::net` —
//! see this crate's `Cargo.toml` for the matching `[target.'cfg(not(target_arch =
//! "wasm32"))'.dependencies]` block. A native build (ct-control-plane, ct-agent) sees this
//! module; a wasm32 build does not, and nothing here can ever be reached from one.

use std::net::SocketAddr;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use quinn::{Connection, Endpoint};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::a2a::{a2a_initiate, a2a_recv, a2a_send};
use crate::channel::{ChannelId, ChannelJoinRequest, SignedChannelGrant, CHANNEL_ENDPOINT_RELAY_ONLY};
use crate::channel_quic::build_channel_dialer;
use crate::channel_wire::io::present_channel_join_on_stream;
use crate::channel_wire::{
    error_names_park_expiry, ChannelJoinOutcome, DroppedLegBeforeAck, PHASE_MARKER_RELAY, PHASE_MARKER_RENDEZVOUS,
};
use crate::mcp::encode_request;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

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
/// exchange (join, possession challenge/signature, ack wait). The SAME constant as ct-agent's
/// `ADMISSION_EXCHANGE_TIMEOUT` (ct-agent#140) — now literally the shared one: the edge acks
/// a pairing leg only once the PARTNER arrives, and keeps a lone first-arriving member parked
/// for its full park TTL (`CHANNEL_PARK_TTL_SECS = 30` server-side). A client bound BELOW
/// that window fails deterministically whenever the partner shows up in the last part of it,
/// while the edge is still legitimately waiting on our behalf — the exact mistake ct-agent
/// shipped as a 15 s bound (and this module shipped as a single 20 s `DIAL_TIMEOUT` covering
/// everything, before #745). 45 s = the 30 s park window plus margin for the partner's own
/// ladder walk; still finite, so a genuinely dead broker fails in bounded time.
pub const ADMISSION_EXCHANGE_TIMEOUT: Duration = crate::channel_wire::io::ADMISSION_EXCHANGE_TIMEOUT;

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

/// The shared exchange's stall error text (`channel_wire::io::present_channel_join_on_stream`,
/// ct-agent#140) — the one `BoxError` this module classifies by text, exactly as ct-agent's
/// `channel_run/errors.rs` does. Pinned by `adapter_maps_the_shared_exchanges_stall_to_timed_out`
/// against the real function, so a reword upstream fails here instead of silently turning a
/// timeout into `DialError::Session`.
const ADMISSION_STALLED_TEXT: &str = "channel join admission exchange stalled (#140)";

/// One fresh QUIC connection to `addr` through the shared accept-any-cert channel dialer
/// ([`crate::channel_quic::build_channel_dialer`] — the QUIC/TLS layer is transport only; the
/// real authentication is the Noise_IK session pinned to the broker-attested peer key).
/// Returns the [`Endpoint`] alongside the [`Connection`] so the caller keeps both alive
/// together for the connection's lifetime — each hop of [`dial_and_call`] gets its own,
/// exactly like ct-agent dials `broker_conn` and `relay_conn` separately (ct-agent#103 —
/// see the module doc).
async fn dial_quic(addr: SocketAddr) -> Result<(Endpoint, Connection), DialError> {
    let endpoint = build_channel_dialer().map_err(|e| DialError::DialFailed(e.to_string()))?;
    let connecting = endpoint
        .connect(addr, "localhost")
        .map_err(|e| DialError::DialFailed(e.to_string()))?;
    let conn = connecting.await.map_err(|e| DialError::DialFailed(e.to_string()))?;
    Ok((endpoint, conn))
}

/// Present `request` on `(send, recv)` and read the broker's decision — the ONE adapter
/// between the shared exchange ([`present_channel_join_on_stream`]) and this module's typed
/// [`DialError`]. Always the QUIC leg shape: `finish_send_after_sig = true` (quinn's clean
/// per-stream `finish()` after the possession signature; it would be WRONG on a TCP/TLS
/// stream leg, ct-agent#21 follow-up, which this module never dials), `ka_tick_wait = false`
/// (the QUIC ports never park-tick), and the exchange bounded by whatever of the hop's
/// `deadline` is left — so one hop's connect + `open_bi` + exchange still share ONE
/// [`ADMISSION_EXCHANGE_TIMEOUT`] budget, unchanged from before this module became a thin
/// caller.
///
/// `phase_marker`: `Some(phase)` writes the `[0xFF, phase]` preamble before the length
/// prefix ([`PHASE_MARKER_RENDEZVOUS`] on hop 1, [`PHASE_MARKER_RELAY`] on hop 2); `None`
/// sends the bare length-framed join. Only those two markers may ever be sent: any OTHER
/// phase byte after the magic is a DEFINITIVE refusal that charges the per-IP penalty (#509).
///
/// Error mapping (the shared function returns `BoxError`, whose texts ct-agent classifies
/// the same way): a [`DroppedLegBeforeAck`] downcast → [`DialError::DroppedLeg`] with THIS
/// hop's leg name (the shared rendezvous-shaped reader always says `"rendezvous"`; hop 2 is
/// the relay leg to a bridge operator, exactly as before); an error whose source chain
/// names the edge's QUIC park-expiry close reason → [`DialError::NoPeer`]; the exchange
/// stall → [`DialError::TimedOut`]; anything else (malformed pre-challenge response #129,
/// oversized ack #23, an I/O failure) → [`DialError::Session`] carrying the text.
async fn present_join<W, R>(
    send: W,
    recv: R,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    deadline: tokio::time::Instant,
    phase_marker: Option<u8>,
) -> Result<ChannelJoinOutcome, DialError>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let leg = if phase_marker == Some(PHASE_MARKER_RELAY) { "relay" } else { "rendezvous" };
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    present_channel_join_on_stream(send, recv, request, holder, remaining, true, phase_marker, false)
        .await
        .map_err(|e| map_join_error(e, leg))
}

/// The `BoxError` → [`DialError`] half of [`present_join`]'s contract (see there).
fn map_join_error(e: BoxError, leg: &'static str) -> DialError {
    if e.downcast_ref::<DroppedLegBeforeAck>().is_some() {
        return DialError::DroppedLeg { leg };
    }
    if error_names_park_expiry(e.as_ref()) {
        return DialError::NoPeer;
    }
    if e.to_string() == ADMISSION_STALLED_TEXT {
        return DialError::TimedOut;
    }
    DialError::Session(e.to_string())
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
) -> Result<((Endpoint, Connection), ChannelJoinOutcome), DialError> {
    let deadline = tokio::time::Instant::now() + ADMISSION_EXCHANGE_TIMEOUT;
    let (endpoint, conn) = tokio::time::timeout_at(deadline, dial_quic(addr))
        .await
        .map_err(|_| DialError::TimedOut)??;
    // Bounded like every other await — quinn's open_bi() resolves only once the peer's
    // flow control grants stream credit, so a broker (or an on-path party, given the
    // accept-any-cert dialer) that completes the handshake and keeps the connection's idle
    // timer alive but never grants a stream could otherwise hang this past the budget
    // (real finding, 2026-09-02 review; ct-agent#140 bounds its open_bi identically).
    let (send, recv) = tokio::time::timeout_at(deadline, conn.open_bi())
        .await
        .map_err(|_| DialError::TimedOut)?
        .map_err(|e| DialError::DialFailed(e.to_string()))?;
    let outcome = present_join(send, recv, request, holder, deadline, Some(phase_marker)).await?;
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
    // our close after acking — nothing further is ever read or written on it). This caller
    // never advertises a dialable endpoint, so the ack's `peer_endpoint` and its own
    // `observed_reflexive` (`r=`) are parsed by the shared reader and simply not used.
    let (peer_noise_pubkey, peer_holder, peer_attestation) = {
        let (_rendezvous_conn, outcome) =
            join_hop(broker_addr, &request, own_holder, PHASE_MARKER_RENDEZVOUS).await?;
        match outcome {
            ChannelJoinOutcome::Refused { category } => return Err(DialError::Refused { category }),
            ChannelJoinOutcome::ParkExpired => return Err(DialError::NoPeer),
            ChannelJoinOutcome::Admitted {
                peer_noise_pubkey: Some(pk),
                peer_holder: Some(holder),
                peer_attestation: Some(att),
                ..
            } => (pk, holder, att),
            // ct-agent#101: an `OK` with a missing triple is never a usable peer.
            ChannelJoinOutcome::Admitted { .. } => return Err(DialError::NoVerifiedPeer),
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
        ChannelJoinOutcome::Refused { category } => return Err(DialError::Refused { category }),
        ChannelJoinOutcome::ParkExpired => return Err(DialError::NoPeer),
        ChannelJoinOutcome::Admitted { .. } => {}
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
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use ed25519_dalek::Signer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::channel::{PARK_EXPIRED_REASON_PREFIX, PARK_EXPIRED_TOKEN};
    use crate::channel_wire::{decode_refusal_category, PHASE_PREAMBLE_MAGIC, POSSESSION_CHALLENGE_LEN};

    // PR6 (channel_dial as a thin caller): the tests that unit-tested this module's former
    // private copies of the wire helpers are gone -- their guards now live with the shared
    // implementation in `channel_wire` (see that module's tests, moved verbatim from
    // ct-agent). What stays here tests the bridge-caller policy: the adapter onto
    // `DialError`, the #101 trust gate, and the #745 two-hop dial against the mock brokers.

    /// Ported onto the shared decoder (no moved ct-agent test covers the uppercase case).
    #[test]
    fn decode_refusal_category_rejects_malshaped_tokens() {
        assert_eq!(decode_refusal_category(&[3, b'A', b'B', b'C']), None, "uppercase not in the shape");
        assert_eq!(decode_refusal_category(&[5, b'a', b'b']), None, "declared len longer than what's present");
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
            ChannelJoinOutcome::Admitted {
                peer_endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
                peer_noise_pubkey: Some(noise),
                peer_holder: Some(peer_holder),
                peer_attestation: Some(attest),
                observed_reflexive: None,
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
            ChannelJoinOutcome::Refused { category: Some("pairing".to_string()) },
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
        let _ = rustls::crypto::ring::default_provider().install_default();
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

    fn admitted_triple(peer: &Peer) -> ChannelJoinOutcome {
        ChannelJoinOutcome::Admitted {
            peer_endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
            peer_noise_pubkey: Some(peer.noise_public),
            peer_holder: Some(peer.holder.verifying_key().to_bytes()),
            peer_attestation: Some(peer.attest),
            observed_reflexive: Some("127.0.0.1:1".parse().unwrap()),
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
            assert!(matches!(outcome, ChannelJoinOutcome::Admitted { .. }), "{outcome:?}");
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
        assert_eq!(outcome, ChannelJoinOutcome::ParkExpired);
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
    // ------------------------------------------------------------------------------------
    // PR6: the ONE adapter between the shared exchange and `DialError`.
    // ------------------------------------------------------------------------------------

    #[tokio::test]
    async fn adapter_maps_the_shared_exchanges_stall_to_timed_out_140() {
        // The shared exchange reports a stall as a `BoxError` with a fixed text; this module
        // classifies it by that text (as ct-agent's errors.rs does). Drive the REAL shared
        // function against a broker that never sends the challenge, so a reword upstream
        // would surface here as `Session(..)` instead of `TimedOut`.
        let bridge = bridge();
        let request = join_request(&bridge);
        let (agent_side, _silent_broker) = tokio::io::duplex(4096); // held open, never answers
        let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
        let (recv, send) = tokio::io::split(agent_side);
        let outcome = present_join(send, recv, &request, &bridge.holder, deadline, Some(PHASE_MARKER_RENDEZVOUS)).await;
        assert_eq!(outcome, Err(DialError::TimedOut), "a stalled admission is `TimedOut`, never a session error");
    }

    #[tokio::test]
    async fn adapter_names_this_hops_leg_in_a_dropped_leg_error_148() {
        // Zero ack bytes after a completed possession handshake is the typed, retryable
        // `DroppedLeg` (ct-agent#148/#23) -- and it must name THIS hop's leg: the shared
        // rendezvous-shaped reader always says "rendezvous", but a bridge operator reading
        // the portal's error page needs to know hop 2 (the relay) dropped, as before PR6.
        for (marker, leg) in [(PHASE_MARKER_RENDEZVOUS, "rendezvous"), (PHASE_MARKER_RELAY, "relay")] {
            let bridge = bridge();
            let request = join_request(&bridge);
            let (agent_side, mut broker_side) = tokio::io::duplex(4096);
            let broker = tokio::spawn(async move {
                let _ = read_join_on_duplex(&mut broker_side).await;
                challenge_and_read_signature(&mut broker_side).await;
                drop(broker_side); // no OK/NO/EX -- the leg dies
            });
            let deadline = tokio::time::Instant::now() + MOCK_IO_TIMEOUT;
            let (recv, send) = tokio::io::split(agent_side);
            let outcome = present_join(send, recv, &request, &bridge.holder, deadline, Some(marker)).await;
            assert_eq!(outcome, Err(DialError::DroppedLeg { leg }), "marker {marker:#04x}");
            tokio::time::timeout(MOCK_IO_TIMEOUT, broker).await.unwrap().unwrap();
        }
    }

    #[test]
    fn adapter_maps_a_park_expiry_named_error_to_no_peer_and_the_rest_to_session_21() {
        // An error whose source chain carries the edge's QUIC park-expiry close reason is
        // `NoPeer` (the customer's agent simply isn't there), wherever in the exchange it
        // surfaced; every other shared-exchange error keeps its text as `Session`.
        let reaped: BoxError = std::io::Error::other(format!(
            "connection lost: closed by peer: 0: {PARK_EXPIRED_REASON_PREFIX} no partner within the park TTL"
        ))
        .into();
        assert_eq!(map_join_error(reaped, "relay"), DialError::NoPeer);
        let malformed: BoxError = "channel ack exceeded 512 bytes without a terminator — malformed peer".into();
        assert_eq!(
            map_join_error(malformed, "relay"),
            DialError::Session("channel ack exceeded 512 bytes without a terminator — malformed peer".to_string())
        );
    }
}
