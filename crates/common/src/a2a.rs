//! Agent Fabric — agent-to-agent Noise_IK session (#72 AF4-session, ADR-0020).
//!
//! After the edge broker pairs two channel members (each learns the other's endpoint
//! via the rendezvous in `ct_edge::channel_broker` / `ct_agent::channel`), the
//! **initiator** dials the **responder** and the two run a `Noise_IK` session pinned
//! to each other's member Noise static key (AF4-keydist). This module drives that
//! handshake and frames application data over the resulting transport — the encrypted,
//! mutually-authenticated A2A data path that makes tunnel-to-tunnel communication
//! actually carry bytes.
//!
//! The drivers are generic over the byte stream, so they run over a QUIC bi-stream
//! (the live path — `quinn::SendStream`/`RecvStream`) or any `AsyncRead`/`AsyncWrite`
//! pair (an in-memory duplex, for hermetic tests).
//!
//! **Pinning is asymmetric by construction, and both sides must pin (#416).** The
//! initiator ([`a2a_initiate`]) always encrypts to a caller-supplied `peer_noise_pubkey`,
//! so a wrong one fails the AEAD tag outright — cheap and automatic. The responder
//! ([`a2a_respond`]) only *learns* the initiator's static key from message 1; Noise_IK
//! gives it no way to refuse based on that key during the handshake itself (any
//! initiator that holds a real private key completes a cryptographically valid session,
//! not just an attacker guessing). So the responder must check the learned key
//! **after** the handshake, against the channel-attested `noise_pubkey` for whichever
//! member it believes it's responding to — [`a2a_respond_verified`] does that; the raw
//! [`a2a_respond`] does not and exists only for callers with no attested identity to
//! check against.

use std::io;
use std::time::{Duration, Instant};

use snow::TransportState;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::noise::{client_handshake, frame, origin_handshake, read_frame};

/// Noise's plaintext ceiling per message (65535 − 16-byte tag). Callers that need to
/// move more than this per message must chunk; [`a2a_send`] rejects an over-size body.
pub const A2A_MAX_MESSAGE: usize = 65519;

fn noise_io(e: snow::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("noise: {e}"))
}

/// Opt-in timing visibility into the A2A handshake (found live, 2026-08-01, debugging why a
/// cross-NAT channel round to a real remote peer would hang until the caller's own outer
/// timeout fired with zero diagnostic signal in between): neither [`a2a_initiate`] nor
/// [`a2a_respond`] has any internal timeout of its own on the peer's handshake response --
/// they rely entirely on whatever the caller wraps them in, and until now gave no visibility
/// into whether/how long that read was actually blocked. Silent unless `CT_DEBUG_A2A_TIMING`
/// is set (any value), so normal operation is unaffected; the env check only runs once per
/// handshake, not a hot path. Callers needing this in a long-running process (not a one-shot
/// CLI process like ct-agent) should cache the env lookup themselves.
fn debug_a2a_timing_enabled() -> bool {
    std::env::var_os("CT_DEBUG_A2A_TIMING").is_some()
}

/// Initiator half of the A2A handshake: run `Noise_IK` over `(send, recv)` pinning the
/// peer's member Noise public key, returning the established transport session. Fails
/// if the peer's key doesn't match (AEAD tag failure on the response) — so a session
/// only forms with the intended member.
pub async fn a2a_initiate<W, R>(
    send: &mut W,
    recv: &mut R,
    own_noise_private: &[u8; 32],
    peer_noise_pubkey: &[u8; 32],
) -> io::Result<TransportState>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let debug = debug_a2a_timing_enabled();
    let mut hs = client_handshake(own_noise_private, peer_noise_pubkey).map_err(noise_io)?;
    let mut buf = [0u8; 1024];
    let mut tmp = [0u8; 1024];
    let n = hs.write_message(&[], &mut buf).map_err(noise_io)?;
    send.write_all(&frame(&buf[..n])).await?;
    if debug {
        eprintln!("ct-a2a-timing: initiator sent handshake message 1, waiting for the peer's message 2...");
    }
    let wait_start = Instant::now();
    let m2 = match read_frame(recv).await {
        Ok(m2) => {
            if debug {
                eprintln!("ct-a2a-timing: initiator received message 2 after {:?}", wait_start.elapsed());
            }
            m2
        }
        Err(e) => {
            if debug {
                eprintln!("ct-a2a-timing: initiator's read for message 2 failed after {:?}: {e}", wait_start.elapsed());
            }
            return Err(e);
        }
    };
    hs.read_message(&m2, &mut tmp).map_err(noise_io)?;
    hs.into_transport_mode().map_err(noise_io)
}

/// Responder half: read the initiator's first message (learning its static key), reply
/// with the second, and return the established transport session — discarding the
/// learned peer key. Kept with this exact name and signature for source compatibility
/// (a cross-repo caller, `scimbe/ct-agent`, is pinned by git rev and calls this by name —
/// a workspace path-dependency on this crate rebuilds that pinned source against
/// whatever's here *right now*, so a breaking signature change here breaks that build
/// immediately, not just "once the pin is bumped"; learned the hard way fixing #416's own
/// [`crate::upgrade::run_upgradable_session_responder`] regression). Prefer
/// [`a2a_respond_with_peer_key`] (or [`a2a_respond_verified`], which uses it) for any
/// new/updatable caller that can actually check the learned key.
pub async fn a2a_respond<W, R>(
    send: &mut W,
    recv: &mut R,
    own_noise_private: &[u8; 32],
) -> io::Result<TransportState>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    a2a_respond_with_peer_key(send, recv, own_noise_private).await.map(|(t, _peer)| t)
}

/// [`a2a_respond`], but also returns the initiator's learned static key.
///
/// **#416: unlike [`a2a_initiate`], the responder learns the initiator's static key from
/// message 1 but this alone proves only that the initiator holds *some* private key — not
/// that it's the *expected* member. Returns that learned key alongside the session so the
/// caller can check it against a channel-attested `noise_pubkey`
/// ([`crate::channel::verify_member_noise_attestation`] verifies the attestation itself at
/// registration time; nothing previously checked the live peer against it at handshake
/// time). Prefer [`a2a_respond_verified`], which does that check for you.
pub async fn a2a_respond_with_peer_key<W, R>(
    send: &mut W,
    recv: &mut R,
    own_noise_private: &[u8; 32],
) -> io::Result<(TransportState, [u8; 32])>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let debug = debug_a2a_timing_enabled();
    let mut hs = origin_handshake(own_noise_private).map_err(noise_io)?;
    let mut buf = [0u8; 1024];
    let mut tmp = [0u8; 1024];
    if debug {
        eprintln!("ct-a2a-timing: responder waiting for the initiator's message 1...");
    }
    let wait_start = Instant::now();
    let m1 = match read_frame(recv).await {
        Ok(m1) => {
            if debug {
                eprintln!("ct-a2a-timing: responder received message 1 after {:?}", wait_start.elapsed());
            }
            m1
        }
        Err(e) => {
            if debug {
                eprintln!("ct-a2a-timing: responder's read for message 1 failed after {:?}: {e}", wait_start.elapsed());
            }
            return Err(e);
        }
    };
    hs.read_message(&m1, &mut tmp).map_err(noise_io)?;
    // Captured before `write_message`'s second call below only touches the send-cipher
    // state, and before `into_transport_mode()` consumes `hs` -- `get_remote_static()` is
    // `None` only pre-message-1 (already past that) or for a pattern with no remote static
    // at all, which Noise_IK never is (`build_responder` fails at construction otherwise).
    let peer_static: [u8; 32] = hs
        .get_remote_static()
        .and_then(|k| k.try_into().ok())
        .expect("Noise_IK responder always learns a 32-byte remote static from message 1");
    let n = hs.write_message(&[], &mut buf).map_err(noise_io)?;
    send.write_all(&frame(&buf[..n])).await?;
    Ok((hs.into_transport_mode().map_err(noise_io)?, peer_static))
}

/// [`a2a_respond`], plus the check its own doc says most callers actually need: the learned
/// peer static key must equal `expected_peer_noise_pubkey` (the channel-attested value for
/// whichever member the caller believes it's responding to) or the session is refused with
/// `InvalidData` — the initiator already completed a valid Noise_IK handshake (it holds a
/// real private key), it's just not the member this responder was told to expect.
pub async fn a2a_respond_verified<W, R>(
    send: &mut W,
    recv: &mut R,
    own_noise_private: &[u8; 32],
    expected_peer_noise_pubkey: &[u8; 32],
) -> io::Result<TransportState>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let (transport, peer_static) = a2a_respond_with_peer_key(send, recv, own_noise_private).await?;
    if &peer_static != expected_peer_noise_pubkey {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a2a: peer completed the handshake with a static key that doesn't match the \
             channel-attested member key (#416)",
        ));
    }
    Ok(transport)
}

/// Encrypt and send one application message over an established A2A session.
pub async fn a2a_send<W: AsyncWrite + Unpin>(
    send: &mut W,
    session: &mut TransportState,
    plaintext: &[u8],
) -> io::Result<()> {
    if plaintext.len() > A2A_MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a2a message exceeds the Noise plaintext limit; chunk it",
        ));
    }
    let mut ct = vec![0u8; plaintext.len() + 16];
    let n = session.write_message(plaintext, &mut ct).map_err(noise_io)?;
    // #475: two writes (length prefix, then ciphertext) instead of `frame(&ct[..n])`, which
    // would allocate a THIRD buffer and copy `ct[..n]` into it a second time just to prepend
    // a 2-byte length -- `ct` is already sized exactly to `n`'s worth of real data plus the
    // untouched AEAD-tag slack, so writing it directly avoids that redundant allocation+copy
    // on every single send.
    send.write_all(&(n as u16).to_be_bytes()).await?;
    send.write_all(&ct[..n]).await?;
    Ok(())
}

/// Receive and decrypt one application message from an established A2A session.
pub async fn a2a_recv<R: AsyncRead + Unpin>(
    recv: &mut R,
    session: &mut TransportState,
) -> io::Result<Vec<u8>> {
    let ct = read_frame(recv).await?;
    let mut pt = vec![0u8; ct.len()];
    let n = session.read_message(&ct, &mut pt).map_err(noise_io)?;
    pt.truncate(n);
    Ok(pt)
}

// #476: the TAGGED cutover cluster built on top of a2a_send/a2a_recv above
// (a2a_send_framed/a2a_recv_framed/a2a_drain_relay_until_cutover, A2A_TAG_DATA/
// A2A_TAG_CUTOVER/DRAIN_UNTIL_CUTOVER_MAX_BYTES) was removed here -- an earlier,
// never-wired design for the #104 relay->direct cutover, fully superseded by
// crate::upgrade's own TAG_OFFER/TAG_READY/TAG_ABORT protocol (which IS what
// ct-agent drives in production). a2a_send/a2a_recv themselves are NOT part of
// that dead cluster -- they're the general encrypt-send/recv-decrypt primitives
// over an established session, and ct-agent's own test suite (p2p.rs, channel.rs)
// imports and calls them directly, so they stay. Confirmed the tagged cluster's
// unreachability via a repo-wide caller survey across both CADS-Tunnel and
// ct-agent before removal; its only non-test callers were within itself. Public
// API of a crate other repos depend on by tag, so this only takes effect for a
// consumer that pins a tag containing this commit.

/// **#104 direct-P2P — bring a freshly-connected direct link up as an A2A Noise_IK session.**
/// Given the two halves of a just-dialed direct byte stream (quinn `SendStream`/`RecvStream`, or
/// any split duplex), run the same Noise_IK handshake as the relay session and hand back the
/// established `(TransportState, read_half, write_half)` — exactly the tuple that
/// [`crate::noise::noise_pump_multiplexed`]'s late-bind one-shot consumes. `initiator` selects the
/// handshake role (it MUST be the opposite of the peer's and match the channel's original role so
/// the pinned keys line up). The direct session is independent of the relay session — a fresh
/// handshake with its own transport — so the two can run side by side until the cutover. The caller
/// feeds the result into the pump's `direct` one-shot and then triggers the cutover.
pub async fn establish_direct_session<W, R>(
    mut send: W,
    mut recv: R,
    initiator: bool,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
) -> io::Result<(TransportState, R, W)>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let session = if initiator {
        a2a_initiate(&mut send, &mut recv, own_noise_private, peer_noise_public).await?
    } else {
        // #416: previously discarded `peer_noise_public` entirely and trusted whatever key the
        // handshake happened to present. Both roles now share one call shape for the same real
        // reason: the responder must pin the same peer it's told to expect, exactly as the
        // initiator direction already did.
        a2a_respond_verified(&mut send, &mut recv, own_noise_private, peer_noise_public).await?
    };
    // The pump's late-bind tuple is (transport, read, write).
    Ok((session, recv, send))
}

/// [`establish_direct_session`] over a **single combined duplex** stream (#136 N136.2) — splits it
/// into halves first. The plain-QUIC upgrade path already has separate `SendStream`/`RecvStream`,
/// but a **DCUtR** hole-punched link (`ct-agent p2p`) yields one `AsyncRead + AsyncWrite` duplex, so
/// the NAT-to-NAT wire-in (N136.3) injects *this* as its direct-establishment op in place of
/// `dial_peer_direct`. Returns the pump-ready `(TransportState, read, write)`.
pub async fn establish_direct_over_duplex<S>(
    stream: S,
    initiator: bool,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
) -> io::Result<(TransportState, tokio::io::ReadHalf<S>, tokio::io::WriteHalf<S>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (recv, send) = tokio::io::split(stream);
    establish_direct_session(send, recv, initiator, own_noise_private, peer_noise_public).await
}

/// The maximum body size of one framed message (#135 L2.2). The `noise::frame` envelope carries a
/// **`u16`** length prefix, so a body over `u16::MAX` bytes makes `frame()`'s `msg.len() as u16`
/// silently TRUNCATE the length and corrupt the stream. This is the ceiling [`write_message`]
/// enforces. (Large/streaming results are out of scope — per sink's reality-check L2.4 returns
/// references/handles, not multi-frame blobs.)
pub const MAX_MESSAGE_BYTES: usize = u16::MAX as usize;

/// Write one length-prefixed message (#135 L2.2 — message-framing formalization). Same wire envelope
/// as [`noise::frame`](crate::noise::frame) (2-byte big-endian length + body), but **guarded**: a body
/// larger than [`MAX_MESSAGE_BYTES`] is rejected with `InvalidInput` **before anything is written**,
/// instead of the bare `frame()` silently truncating the `u16` length into stream corruption. The read
/// side stays [`read_frame`](crate::noise::read_frame), so this does NOT change the envelope shape — it
/// only hardens the size policy; any richer envelope (version / type / request-id) remains an additive
/// follow. `serve_request_loop` writes its responses through this, so a handler can't corrupt the
/// session with an oversize reply.
pub async fn write_message<W: AsyncWrite + Unpin>(send: &mut W, msg: &[u8]) -> io::Result<()> {
    if msg.len() > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "message body {} exceeds MAX_MESSAGE_BYTES ({MAX_MESSAGE_BYTES})",
                msg.len()
            ),
        ));
    }
    // ct-agent#105: opt-in, same switch as the handshake timing above -- pins whether a
    // corrupted/truncated response (live-observed: a physics fragment's leading field
    // missing between ct-agent 0.4.16 and 0.7.4's concurrent-serve mode, #200) already
    // left this call's plaintext malformed (a dispatch-side bug) or was still correct
    // here and got mangled in flight below (a transport-side bug, e.g. noise_pump/quinn
    // stream backpressure under genuinely concurrent streams). Logs the PLAINTEXT
    // app-layer frame (MCP JSON-RPC), before Noise encryption -- no wire secrets in it.
    if debug_a2a_timing_enabled() {
        eprintln!(
            "ct-a2a-timing: write_message len={} head={:?} tail={:?}",
            msg.len(),
            String::from_utf8_lossy(&msg[..msg.len().min(96)]),
            String::from_utf8_lossy(&msg[msg.len().saturating_sub(32)..]),
        );
    }
    send.write_all(&frame(msg)).await?;
    send.flush().await?;
    Ok(())
}

/// **L2.1 — persistent request/response runner (#135 MCP-over-channel).** The primitive that turns
/// `ct-agent channel` from one-shot **pipe-and-exit** (stdin-EOF → teardown) into a long-lived
/// **callable service**: read one length-prefixed request frame, hand its bytes to `handle`, write
/// that handler's length-prefixed response frame, and **loop** until the peer closes the stream —
/// a clean `UnexpectedEof` *between* frames ends the loop with `Ok(count)` (the number of requests
/// served), any mid-frame error propagates. This is a pure **runner** change over the app-side
/// duplex; the caller runs it in place of the stdin/stdout pipe and the existing byte-exact
/// bidirectional `noise_pump` carries the frames encrypted over the one Noise tunnel (no crypto
/// here, no new dependency). Framing reuses the codebase's `noise::{frame, read_frame}` 2-byte
/// length envelope; L2.2 formalizes message framing and L2.3 makes `handle` an MCP tool dispatch —
/// here `handle` is any request→response function so the loop is testable in isolation.
pub async fn serve_request_loop<W, R, H, Fut>(
    send: &mut W,
    recv: &mut R,
    handle: H,
) -> io::Result<u64>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    H: FnMut(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Vec<u8>>,
{
    serve_request_loop_with_idle_timeout(send, recv, handle, DEFAULT_IDLE_TIMEOUT).await
}

/// #269: a peer that completes the Noise_IK handshake and calls [`serve_request_loop`] but
/// never sends a request (or sends one, then stalls) held `read_frame` forever — the serve
/// task, and with it the single `--serve` session slot (#200), was pinned indefinitely by an
/// idle peer with no way to recover short of a process restart. Balanced against real
/// interactive/tool-calling cadences, which can legitimately go quiet between calls, so this
/// is generous compared to a transport-level dead-peer detector (contrast the Edge's much
/// shorter QUIC `max_idle_timeout`, `crates/edge/src/pki.rs` — that catches a genuinely dead
/// connection; this catches an alive-but-idle one at the application layer, above transport
/// keepalives that would otherwise mask it).
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// [`serve_request_loop`] with a configurable per-request idle deadline (#269): if no new
/// request frame arrives within `idle_timeout` of the loop becoming ready to read one, the
/// session ends with a `TimedOut` error (distinguishable from the peer's own clean close,
/// which still returns `Ok(served)`) instead of blocking forever.
pub async fn serve_request_loop_with_idle_timeout<W, R, H, Fut>(
    send: &mut W,
    recv: &mut R,
    mut handle: H,
    idle_timeout: Duration,
) -> io::Result<u64>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    H: FnMut(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Vec<u8>>,
{
    let mut served = 0u64;
    loop {
        let request = match tokio::time::timeout(idle_timeout, read_frame(recv)).await {
            Ok(Ok(msg)) => msg,
            // The peer closed the stream between requests — a clean, expected end of the session.
            Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(served),
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("serve_request_loop: idle for {idle_timeout:?} with no new request, closing"),
                ))
            }
        };
        // ct-agent#105: log what this loop actually RECEIVED, same switch as write_message's
        // outbound log above -- if a request already arrives short/mangled here, the bug is
        // upstream of `handle` (dispatch/subprocess-capture side); if it's correct here but
        // `write_message`'s log for the resulting response is already wrong, the bug is inside
        // `handle`; if both logs are correct, the bug is downstream, in the pump/transport.
        if debug_a2a_timing_enabled() {
            eprintln!(
                "ct-a2a-timing: serve_request_loop received len={} head={:?}",
                request.len(),
                String::from_utf8_lossy(&request[..request.len().min(96)]),
            );
        }
        let response = handle(request).await;
        // #135 L2.2: guarded write — an oversize response errors the loop rather than truncating the
        // u16 length and corrupting the session.
        write_message(send, &response).await?;
        served += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::generate_static_keypair;

    // #476: relay_to_direct_cutover_preserves_byte_exact_message_order removed here --
    // it exercised only the dead a2a_send_framed/a2a_recv_framed/a2a_drain_relay_until_cutover
    // cluster removed above. crate::upgrade's own tests cover the cutover mechanism that's
    // actually live.

    #[tokio::test]
    async fn two_agents_establish_a_session_and_exchange_data_both_ways() {
        // #72 AF4-session: two agents, each with a member Noise keypair, establish a
        // mutually-authenticated Noise_IK session over a duplex byte stream (standing
        // in for the paired QUIC bi-stream) and exchange application data in BOTH
        // directions — the encrypted A2A data path carrying real bytes.
        let initiator = generate_static_keypair();
        let responder = generate_static_keypair();
        let resp_priv = responder.private;
        let init_priv = initiator.private;
        let resp_pub = responder.public;

        // A duplex pair: initiator writes to a_w (responder reads a_r); responder
        // writes to b_w (initiator reads b_r).
        let (mut a_w, mut a_r) = tokio::io::duplex(4096);
        let (mut b_w, mut b_r) = tokio::io::duplex(4096);

        let responder_task = tokio::spawn(async move {
            let (mut sess, _peer) = a2a_respond_with_peer_key(&mut b_w, &mut a_r, &resp_priv).await.expect("respond");
            let got = a2a_recv(&mut a_r, &mut sess).await.expect("recv ping");
            assert_eq!(got, b"ping from initiator", "responder decrypts the initiator's message");
            a2a_send(&mut b_w, &mut sess, b"pong from responder").await.expect("send pong");
        });

        let mut sess = a2a_initiate(&mut a_w, &mut b_r, &init_priv, &resp_pub)
            .await
            .expect("initiate");
        a2a_send(&mut a_w, &mut sess, b"ping from initiator").await.expect("send ping");
        let pong = a2a_recv(&mut b_r, &mut sess).await.expect("recv pong");
        assert_eq!(pong, b"pong from responder", "initiator decrypts the responder's reply");

        responder_task.await.expect("responder task");
    }

    #[tokio::test]
    async fn a_session_only_forms_with_the_intended_peer_key() {
        // Noise_IK authenticates the responder: an initiator that pins the WRONG peer
        // key cannot complete the handshake (the responder can't decrypt msg1 under a
        // key it doesn't hold), so no A2A session is established with an impostor.
        let initiator = generate_static_keypair();
        let responder = generate_static_keypair();
        let wrong = generate_static_keypair();
        let resp_priv = responder.private;
        let init_priv = initiator.private;
        let wrong_pub = wrong.public;

        let (mut a_w, mut a_r) = tokio::io::duplex(4096);
        let (mut b_w, mut b_r) = tokio::io::duplex(4096);

        let responder_task =
            tokio::spawn(async move { a2a_respond(&mut b_w, &mut a_r, &resp_priv).await.is_ok() });

        // Initiator pins `wrong_pub`, not the responder's real key.
        let init = a2a_initiate(&mut a_w, &mut b_r, &init_priv, &wrong_pub).await;
        let responder_ok = responder_task.await.expect("responder task");
        assert!(
            init.is_err() || !responder_ok,
            "a mismatched peer key must not yield a session on either side"
        );
    }

    #[tokio::test]
    async fn a2a_respond_verified_rejects_a_genuine_handshake_from_an_unexpected_peer_416() {
        // #416: unlike the initiator direction (proven above), the raw `a2a_respond` never
        // checked the peer it actually handshaked with -- a real Noise_IK peer with ITS OWN
        // valid keypair (not an impostor pinning the wrong key; a genuinely different, fully
        // legitimate identity) could complete a session the responder never meant to accept.
        // This proves `a2a_respond_verified` closes that: a REAL, cryptographically-valid
        // handshake from the wrong peer must still be refused once checked against the
        // channel-attested key the responder actually expected.
        let responder = generate_static_keypair();
        let expected_initiator = generate_static_keypair();
        let actual_initiator = generate_static_keypair(); // a real peer, just not the expected one
        let resp_priv = responder.private;
        let expected_pub = expected_initiator.public;
        let actual_priv = actual_initiator.private;
        let actual_pub = actual_initiator.public;

        let (mut a_w, mut a_r) = tokio::io::duplex(4096);
        let (mut b_w, mut b_r) = tokio::io::duplex(4096);

        let responder_task = tokio::spawn(async move {
            a2a_respond_verified(&mut b_w, &mut a_r, &resp_priv, &expected_pub).await.is_ok()
        });

        // The actual initiator completes a fully valid Noise_IK handshake -- own real key,
        // pins the responder's real public key correctly. No AEAD failure anywhere.
        let init = a2a_initiate(&mut a_w, &mut b_r, &actual_priv, &responder.public).await;
        assert!(init.is_ok(), "the handshake itself is genuinely valid -- not an AEAD failure");
        let responder_ok = responder_task.await.expect("responder task");
        assert!(
            !responder_ok,
            "a real, valid handshake from an unexpected (if genuine) peer must still be refused"
        );

        // Sanity: the SAME actual peer succeeds once it's the one actually expected.
        let (mut a_w2, mut a_r2) = tokio::io::duplex(4096);
        let (mut b_w2, mut b_r2) = tokio::io::duplex(4096);
        let resp_priv2 = responder.private;
        let responder_task2 = tokio::spawn(async move {
            a2a_respond_verified(&mut b_w2, &mut a_r2, &resp_priv2, &actual_pub).await.is_ok()
        });
        let init2 = a2a_initiate(&mut a_w2, &mut b_r2, &actual_priv, &responder.public).await;
        assert!(init2.is_ok());
        assert!(
            responder_task2.await.expect("responder task 2"),
            "the expected peer's own real handshake must still succeed"
        );
    }

    #[tokio::test]
    async fn establish_direct_session_brings_up_a_paired_noise_ik_link_with_usable_halves() {
        // #104 direct-P2P (frozen): the two halves of a fresh direct link handshake into a paired
        // Noise_IK session, and the returned (transport, read, write) form a working encrypted
        // tunnel in both directions — exactly what the pump's late-bind one-shot consumes.
        let a_kp = generate_static_keypair();
        let b_kp = generate_static_keypair();
        let (a_priv, a_pub, b_priv, b_pub) = (a_kp.private, a_kp.public, b_kp.private, b_kp.public);

        // One duplex per direction: a→b and b→a.
        let (a2b_w, a2b_r) = tokio::io::duplex(1 << 16);
        let (b2a_w, b2a_r) = tokio::io::duplex(1 << 16);

        // a = initiator (send a→b, recv b→a); b = responder (send b→a, recv a→b).
        let a_task = tokio::spawn(async move {
            establish_direct_session(a2b_w, b2a_r, true, &a_priv, &b_pub).await
        });
        // #416: the responder now actually pins its peer, so this must be `a`'s real key.
        let (mut b_ts, mut b_recv, mut b_send) =
            establish_direct_session(b2a_w, a2b_r, false, &b_priv, &a_pub)
                .await
                .expect("responder establishes the direct session");
        let (mut a_ts, mut a_recv, mut a_send) =
            a_task.await.expect("join").expect("initiator establishes the direct session");

        // Round-trip a message each way over the established direct session + returned halves.
        a2a_send(&mut a_send, &mut a_ts, b"ping-direct").await.expect("a sends");
        let got = a2a_recv(&mut b_recv, &mut b_ts).await.expect("b receives");
        assert_eq!(got, b"ping-direct", "initiator→responder over the established direct session");

        a2a_send(&mut b_send, &mut b_ts, b"pong-direct").await.expect("b sends");
        let got2 = a2a_recv(&mut a_recv, &mut a_ts).await.expect("a receives");
        assert_eq!(got2, b"pong-direct", "responder→initiator over the established direct session");
    }

    #[tokio::test]
    async fn serve_request_loop_serves_many_requests_over_one_session_then_ends_on_peer_close() {
        // L2.1 (#135, frozen): the persistent runner reads a framed request, calls the handler,
        // writes a framed response, and LOOPS over ONE session (not pipe-and-exit) — several
        // request→response round-trips on the same stream — then returns Ok(count) when the peer
        // closes cleanly between requests. Handler here is an upper-casing echo (a stand-in for
        // L2.3's MCP dispatch) so the loop is exercised in isolation.
        let (mut c2s_w, mut c2s_r) = tokio::io::duplex(1 << 16); // client → server (requests)
        let (mut s2c_w, mut s2c_r) = tokio::io::duplex(1 << 16); // server → client (responses)

        let server = tokio::spawn(async move {
            serve_request_loop(&mut s2c_w, &mut c2s_r, |req: Vec<u8>| async move {
                req.to_ascii_uppercase()
            })
            .await
        });

        // THREE requests over the SAME session — proving it is persistent, not one-shot.
        for msg in [&b"first"[..], b"second", b"third"] {
            c2s_w.write_all(&frame(msg)).await.expect("send request frame");
            let resp = read_frame(&mut s2c_r).await.expect("read response frame");
            assert_eq!(resp, msg.to_ascii_uppercase(), "each request gets its response on the one session");
        }

        // Peer closes its send side → the runner's next read hits a clean EOF between frames.
        drop(c2s_w);
        let served = server.await.expect("join").expect("loop ends cleanly on peer close");
        assert_eq!(served, 3, "the runner served all three requests before the peer closed");
    }

    #[tokio::test(start_paused = true)]
    async fn serve_request_loop_times_out_on_a_peer_that_never_sends_a_request_269() {
        // #269: a peer that completes the session but never sends a request (the connection
        // stays open, nothing arrives) must not pin the serve task forever. Paused clock ->
        // tokio auto-advances virtual time, so this is deterministic and fast despite a real
        // multi-minute idle_timeout.
        let (mut _c2s_w, mut c2s_r) = tokio::io::duplex(1 << 16);
        let (mut s2c_w, _s2c_r) = tokio::io::duplex(1 << 16);
        let idle_timeout = Duration::from_secs(30);

        let start = tokio::time::Instant::now();
        let result = serve_request_loop_with_idle_timeout(&mut s2c_w, &mut c2s_r, |req: Vec<u8>| async move { req }, idle_timeout).await;
        let elapsed = start.elapsed();

        let err = result.expect_err("an idle peer must end the loop with an error, not hang forever");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "distinguishable from a clean close: {err}");
        assert!(elapsed >= idle_timeout, "must wait out the full idle deadline before giving up, elapsed {elapsed:?}");
        // Keep _c2s_w alive until here so the read times out rather than seeing an early EOF.
        drop(_c2s_w);
    }

    #[tokio::test(start_paused = true)]
    async fn serve_request_loop_idle_timeout_resets_after_each_served_request_269() {
        // #269: the deadline is per-request, not a single overall session cap -- a peer that
        // sends occasional requests, each within idle_timeout of the last, must be served
        // indefinitely (a real interactive/tool-calling cadence), only an actually-idle gap
        // ends the session.
        let (mut c2s_w, mut c2s_r) = tokio::io::duplex(1 << 16);
        let (mut s2c_w, mut s2c_r) = tokio::io::duplex(1 << 16);
        let idle_timeout = Duration::from_secs(10);

        let server = tokio::spawn(async move {
            serve_request_loop_with_idle_timeout(&mut s2c_w, &mut c2s_r, |req: Vec<u8>| async move { req }, idle_timeout).await
        });

        // Two requests, each well inside the idle window, spaced further apart than the window
        // WOULD allow if the deadline didn't reset per request.
        for msg in [&b"one"[..], b"two"] {
            tokio::time::sleep(idle_timeout / 2).await;
            c2s_w.write_all(&frame(msg)).await.expect("send request frame");
            let resp = read_frame(&mut s2c_r).await.expect("read response frame");
            assert_eq!(resp, msg, "served despite the cumulative gap exceeding one idle window");
        }

        drop(c2s_w);
        let served = server.await.expect("join").expect("loop ends cleanly on peer close, not a timeout");
        assert_eq!(served, 2, "both requests served -- the per-request deadline reset each time");
    }

    #[tokio::test]
    async fn write_message_frames_within_the_limit_and_rejects_oversize_before_writing() {
        // #135 L2.2 (frozen): write_message shares noise::frame's wire envelope (read back with
        // read_frame) but guards the u16 size ceiling — a body AT the max frames fine, one byte OVER
        // is rejected as InvalidInput BEFORE any bytes hit the stream, so it can never truncate the
        // length prefix into stream corruption.
        let (mut w, mut r) = tokio::io::duplex(1 << 17);

        write_message(&mut w, b"hello").await.expect("small body writes");
        assert_eq!(read_frame(&mut r).await.expect("read back"), b"hello");

        let at_max = vec![0xABu8; MAX_MESSAGE_BYTES];
        write_message(&mut w, &at_max).await.expect("a body exactly at the ceiling is allowed");
        assert_eq!(read_frame(&mut r).await.expect("read back max"), at_max);

        let over = vec![0u8; MAX_MESSAGE_BYTES + 1];
        let err = write_message(&mut w, &over).await.expect_err("one byte over is rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

        // The oversize call emitted NO bytes — the reader sees no further frame (no partial/corrupt one).
        let nothing =
            tokio::time::timeout(std::time::Duration::from_millis(50), read_frame(&mut r)).await;
        assert!(nothing.is_err(), "oversize write emitted no bytes — nothing to read");
    }
}
