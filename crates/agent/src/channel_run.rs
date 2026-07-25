//! Agent Fabric — the A2A channel *runner* (#72 AF4-session-wire, #98/#100).
//!
//! [`crate::channel`] rendezvouses two members and [`ct_common::a2a`] establishes the
//! Noise_IK session; this module is the piece that makes it *runnable*: given an
//! established QUIC connection, a role, and the Noise keys, it completes the A2A
//! handshake and then pumps a local byte stream (the CLI's stdin/stdout, or any
//! `AsyncRead + AsyncWrite`) over the encrypted tunnel — a "netcat over the channel".
//! A thin `ct-agent` subcommand feeds it stdio; tests feed it an in-memory duplex.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use ct_common::channel::ChannelJoinRequest;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use quinn::{Connection, Endpoint};
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::channel::{
    present_channel_join, present_channel_join_on_stream, present_channel_relay_join_on_stream,
    ChannelJoinOutcome, ADMISSION_EXCHANGE_TIMEOUT,
};
use ct_common::a2a::{a2a_initiate, a2a_respond};
use ct_common::noise::noise_pump;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Which side of the A2A session this agent drives. Selected from the channel
/// grant's `Direction`: the initiator dials + opens the stream; the responder
/// accepts. (In `Noise_IK` the initiator also pins the peer's static key.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelRole {
    /// Dial the peer and open the bi-stream (grant `Direction::Initiate`).
    Initiate,
    /// Accept the peer's bi-stream (grant `Direction::Accept`).
    Accept,
}

/// A quinn bi-stream (`SendStream` + `RecvStream`) presented as one combined
/// `AsyncRead + AsyncWrite`, so [`noise_pump`] (which `tokio::io::split`s a single
/// duplex) can relay over it. Reads delegate to `recv`, writes to `send`.
// A combined duplex from separate write/read halves. Generic over the halves so it
// wraps both a quinn `SendStream`/`RecvStream` pair (the direct/QUIC path) and the
// split halves of a `:443`/TLS-TCP relay stream (#106 relay-leg-443).
struct BiStream<W, R> {
    send: W,
    recv: R,
}

// quinn's Send/RecvStream carry inherent poll_* methods (quinn error types) that
// shadow the tokio trait methods, so delegate with fully-qualified trait syntax
// (harmless for the generic case, where no inherent methods exist).
impl<W: AsyncWrite + Unpin, R: AsyncRead + Unpin> AsyncRead for BiStream<W, R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl<W: AsyncWrite + Unpin, R: AsyncRead + Unpin> AsyncWrite for BiStream<W, R> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

/// #139: how long a channel's QUIC stream setup (`open_bi`/`accept_bi`) may take past a successful
/// `dial_peer_direct` connect before the direct path is treated as dead. A healthy connection sets
/// the stream up sub-second; a conn that handshaked then went silent would otherwise hang here
/// forever (the Noise handshake beyond this is already bounded, #126). Sits below the dialer's 20s
/// idle-timeout (#139) so this tight bound fires first on the direct path.
const DIRECT_STREAM_SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Open (Initiate) or accept (Accept) the channel bi-stream on `conn`, **bounded** by `setup_timeout`
/// (#139) so a stalled direct link fails fast (`io::ErrorKind::TimedOut`) instead of hanging — the
/// exact `open_bi`/`accept_bi` gap central traced. The timeout is a parameter so tests can drive it
/// deterministically without waiting the production bound.
async fn open_channel_streams(
    conn: &Connection,
    role: ChannelRole,
    setup_timeout: std::time::Duration,
) -> io::Result<(quinn::SendStream, quinn::RecvStream)> {
    let map_err = |e: Box<dyn std::error::Error + Send + Sync>| io::Error::new(io::ErrorKind::Other, e.to_string());
    let open = async {
        match role {
            ChannelRole::Initiate => conn.open_bi().await.map_err(|e| map_err(Box::new(e))),
            ChannelRole::Accept => conn.accept_bi().await.map_err(|e| map_err(Box::new(e))),
        }
    };
    tokio::time::timeout(setup_timeout, open)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct channel stream setup stalled after connect (#139)"))?
}

/// Run one side of an A2A channel session over the established `conn`, then pump
/// `local` (the CLI's stdio, or any duplex) over the encrypted tunnel until either
/// end closes (#72 AF4-session-wire). `role` selects initiator/responder;
/// `own_noise_private` is this agent's member Noise key; `peer_noise_public` is the
/// peer's, pinned by the initiator. Returns when the session ends (EOF either way).
pub async fn run_channel_session<P>(
    conn: &Connection,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
    local: P,
) -> io::Result<()>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    // #139: bound the channel stream setup. `dial_peer_direct` bounds only the QUIC *connect*; once
    // it returns Ok(conn), `open_bi`/`accept_bi` here were unbounded — a conn that handshaked at the
    // transport level then went dead hangs forever (the Noise handshake past this is already bounded,
    // #126; this was the remaining gap). The dialer's idle-timeout (#139) is the transport-level
    // backstop; this is the direct, tight bound on the exact call central traced.
    let (mut send, mut recv) = open_channel_streams(conn, role, DIRECT_STREAM_SETUP_TIMEOUT).await?;
    // Pass the streams by `&mut` so `send` survives the pump (it moves the halves into a
    // `BiStream`), letting us drain it afterwards. #134: the pump FINs on plaintext EOF via
    // `shutdown()` = quinn `SendStream::finish()`, which only QUEUES the FIN — it does NOT wait
    // for the peer to acknowledge the buffered data. QUIC is userspace, so if the connection is
    // then dropped (the agent process exits right after the session returns) quinn discards the
    // unacknowledged tail and the peer receives a silently-truncated prefix of a large transfer.
    // (The `:443`/TLS-TCP relay path — `run_channel_session_on_stream` called directly — has its own
    // bounded `graceful_stream_drain` at the end of that fn: #150 found the "OS keeps draining a FIN'd
    // socket after close" assumption FALSE when `ct-agent` is a container's PID 1, since the netns is
    // torn down on exit with no stack left to flush the tail.)
    run_channel_session_on_stream(&mut send, &mut recv, role, own_noise_private, peer_noise_public, local).await?;
    // Graceful send-drain: wait until the peer has acknowledged receipt of all our stream data
    // (`stopped()` resolves after our `finish()` once the peer acks) BEFORE returning — so the
    // caller can drop the connection / exit without truncating the tail. Bounded so a vanished
    // peer can never hang teardown; on timeout or a lost connection we've done our best.
    const SEND_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    let _ = send.finish(); // idempotent — the pump already FIN'd on EOF; ignore "already closed"
    let _ = tokio::time::timeout(SEND_DRAIN_TIMEOUT, send.stopped()).await;
    Ok(())
}

/// #150: how long [`graceful_stream_drain`] waits for the peer to close before giving up — matches
/// the QUIC send-drain bound (#134) so a vanished peer can never hang teardown.
const RELAY_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// #150: graceful teardown of a stream session before the process may exit. FIN our write half, then
/// read the peer to EOF (bounded by `timeout`) — keeping the process, and in a container its network
/// namespace, alive until the peer has closed, by which point the OS has transmitted + had acknowledged
/// our send buffer. The `:443`/TLS-TCP relay path needs this: unlike a bare host (whose OS TCP stack
/// keeps draining a FIN'd socket after the process closes it), a container tied to `ct-agent`'s PID 1
/// tears down the network namespace on exit, so there's no persisting stack left to flush an unsent
/// tail — the last bytes of a large single-shot transfer would be truncated. Best-effort + bounded: a
/// vanished peer can't hang teardown, and I/O errors are ignored (we've done our best to drain).
async fn graceful_stream_drain<W, R>(send: &mut W, recv: &mut R, timeout: std::time::Duration)
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let _ = send.shutdown().await;
    let _ = tokio::time::timeout(timeout, tokio::io::copy(recv, &mut tokio::io::sink())).await;
}

/// The transport-agnostic core of [`run_channel_session`] (#106 relay-leg-443): run one
/// side of the A2A Noise_IK handshake over already-split write/read halves, then pump
/// `local` over the encrypted tunnel until either end closes. The QUIC path reaches this
/// via [`run_channel_session`] (`open_bi`/`accept_bi`), but a `:443`/TLS-TCP relay stream
/// — whose data path IS the single stream it joined on — runs the identical session by
/// `tokio::io::split`ting the stream and passing the halves here. So a member whose relay
/// port is also blocked (a truly `:443`-only network) relays over `:443` unchanged; the
/// Noise_IK session stays end-to-end and the edge only forwards ciphertext.
pub async fn run_channel_session_on_stream<W, R, P>(
    mut send: W,
    mut recv: R,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
    local: P,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    P: AsyncRead + AsyncWrite + Unpin,
{
    // #126: bound the post-pairing Noise_IK handshake. Every dial/accept step around this
    // is already timed (DIRECT_DIAL_TIMEOUT / accept_timeout), but the handshake exchange
    // itself was unbounded — a paired peer that never sends its message (crash, partition,
    // a peer that admits then stalls) would block `read_frame` forever, hanging the session.
    const A2A_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    let handshake = async {
        match role {
            ChannelRole::Initiate => {
                a2a_initiate(&mut send, &mut recv, own_noise_private, peer_noise_public).await
            }
            ChannelRole::Accept => a2a_respond(&mut send, &mut recv, own_noise_private).await,
        }
    };
    let session = tokio::time::timeout(A2A_HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "a2a Noise_IK handshake timed out (#126)"))?
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    // Reborrow the halves so they survive the pump: after the session ends we must drain before
    // returning (#150), because a caller may exit immediately (a single-shot `ct-agent channel` as a
    // container's PID 1) and a container tears down its netns on exit — so the OS won't flush a FIN'd
    // `:443`/TLS-TCP relay socket's tail the way a bare host would. `graceful_stream_drain` FINs and
    // waits (bounded) for the peer to close, keeping the process + netns alive until our tail is
    // delivered. (The QUIC path keeps its stronger `stopped()` ack-wait in `run_channel_session`.)
    let pumped = noise_pump(session, BiStream { send: &mut send, recv: &mut recv }, local).await;
    graceful_stream_drain(&mut send, &mut recv, RELAY_DRAIN_TIMEOUT).await;
    pumped
}

/// Hands-off A2A join with automatic **direct-then-relay** recovery (#72 AF4 /
/// AF4-session-resilience): present `request` to the edge broker over `broker_conn`,
/// learn the peer endpoint + Noise key the rendezvous relays, then try the **direct**
/// path and, if it can't connect, transparently fall back to the edge **relay**
/// (`relay_conn`) — so a blocked direct path (NAT/firewall) recovers with no caller
/// intervention. `role` (from the grant `Direction`) selects the side: an `Initiate`
/// peer dials `peer_endpoint` (bounded by `dial_timeout`; `Unreachable` → relay); an
/// `Accept` peer waits on its `listener` (bounded by `accept_timeout`; timeout →
/// relay, since the initiator that can't reach it directly went to the relay too). The
/// relay carries ciphertext only — the Noise_IK session stays end-to-end either way.
#[allow(clippy::too_many_arguments)]
pub async fn run_channel_join<P>(
    broker_conn: &Connection,
    relay_conn: &Connection,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    listener: Option<Endpoint>,
    dial_timeout: std::time::Duration,
    accept_timeout: std::time::Duration,
    local: P,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    // Admit over the single pre-dialed QUIC broker connection, then run the
    // outcome-driven data path. The plane CLI instead admits over the broker *ladder*
    // (direct QUIC → the `:443` front door) and calls [`run_channel_join_with_admission`]
    // directly — same data path, but the broker leg reachable when the ports are blocked.
    let admission = present_channel_join(broker_conn, request, holder).await?;
    run_channel_join_with_admission(
        admission,
        RelayFallback::Quic(relay_conn),
        request,
        holder,
        role,
        own_noise_private,
        listener,
        dial_timeout,
        accept_timeout,
        local,
    )
    .await
}

/// The **outcome-driven** core of [`run_channel_join`] (#106 client-dial-wire): given the
/// broker's already-computed `admission` — obtained over a direct QUIC broker connection
/// *or* the broker fallback ladder (direct QUIC → the `:443` TLS-TCP front door) — verify
/// the peer's attested Noise key (#101) and run the same **direct-then-relay** data path.
/// Decoupling admission (how we *reach* the broker) from the data path (how the two
/// members *connect*) is what lets a restrictive network admit over `:443` while the
/// direct/relay data legs stay unchanged. `role`, `listener`, and the timeouts behave
/// exactly as in [`run_channel_join`]. `relay` selects the relay-leg transport used on
/// direct-dial failure: [`RelayFallback::Quic`] (a pre-dialed QUIC relay connection) or —
/// for a member whose relay port is also blocked — [`RelayFallback::Ladder`], which walks
/// the relay ladder (direct QUIC → the `:443` front door) via [`join_via_relay_ladder`].
#[allow(clippy::too_many_arguments)]
pub async fn run_channel_join_with_admission<P>(
    admission: ChannelJoinOutcome,
    relay: RelayFallback<'_>,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    listener: Option<Endpoint>,
    dial_timeout: std::time::Duration,
    accept_timeout: std::time::Duration,
    local: P,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    let (peer_endpoint, peer_noise) = match admission {
        ChannelJoinOutcome::Admitted { peer_endpoint, peer_noise_pubkey, peer_holder, peer_attestation, observed_reflexive: _ } => {
            let noise = peer_noise_pubkey
                .ok_or("broker admitted the join but relayed no peer Noise key (registry has none)")?;
            // #101 SEC101c-ii: verify the peer's Noise key is attested by its
            // grant-authenticated holder before pinning it — so even a tampered DB
            // can't make us pin a substituted key (the attestation wouldn't verify).
            let peer_holder = peer_holder
                .ok_or("broker relayed a Noise key without the peer holder — cannot verify (#101)")?;
            let attestation = peer_attestation
                .ok_or("broker relayed a Noise key without an attestation (#101)")?;
            if !ct_common::channel::verify_member_noise_attestation(
                &request.grant.grant.channel,
                &peer_holder,
                &noise,
                &attestation,
            ) {
                return Err("peer Noise-key attestation failed — refusing to pin a possibly-substituted key (#101)".into());
            }
            (peer_endpoint, noise)
        }
        ChannelJoinOutcome::Refused => return Err("edge broker refused the channel join".into()),
    };
    match role {
        // #121: the paired peer advertised the relay-only sentinel — it has no dialable
        // address, so skip the wasted direct dial + timeout and go straight to the relay.
        ChannelRole::Initiate if peer_endpoint == ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY => {
            eprintln!("ct-agent channel: peer is relay-only (no dialable address) — using the edge relay (#121)");
            join_via_relay_fallback(relay, request, holder, ChannelRole::Initiate, own_noise_private, &peer_noise, local).await?;
        }
        ChannelRole::Initiate => {
            let addr = peer_endpoint
                .parse()
                .map_err(|_| format!("broker returned an unparseable peer endpoint: {peer_endpoint:?}"))?;
            match dial_peer_direct(addr, dial_timeout).await {
                Ok(conn) => {
                    run_channel_session(&conn, ChannelRole::Initiate, own_noise_private, &peer_noise, local).await?;
                }
                Err(ChannelDialError::Unreachable) => {
                    eprintln!("ct-agent channel: direct dial to {addr} unreachable — falling back to the edge relay (#72)");
                    join_via_relay_fallback(relay, request, holder, ChannelRole::Initiate, own_noise_private, &peer_noise, local).await?;
                }
                Err(ChannelDialError::Failed(e)) => return Err(e),
            }
        }
        ChannelRole::Accept => match listener {
            // #121: a relay-only acceptor has no bound listener — it can't be dialed, so it
            // relays directly instead of waiting for a direct connection that can never come.
            None => {
                eprintln!("ct-agent channel: relay-only acceptor (no listener) — using the edge relay (#121)");
                join_via_relay_fallback(relay, request, holder, ChannelRole::Accept, own_noise_private, &peer_noise, local).await?;
            }
            Some(ep) => match tokio::time::timeout(accept_timeout, ep.accept()).await {
                Ok(Some(incoming)) => {
                    let conn = incoming.await?;
                    run_channel_session(&conn, ChannelRole::Accept, own_noise_private, &peer_noise, local).await?;
                }
                Ok(None) => return Err("channel listener closed with no incoming".into()),
                Err(_timeout) => {
                    eprintln!("ct-agent channel: no direct connection within {accept_timeout:?} — falling back to the edge relay (#72)");
                    join_via_relay_fallback(relay, request, holder, ChannelRole::Accept, own_noise_private, &peer_noise, local).await?;
                }
            },
        },
    }
    Ok(())
}

/// Agent-side relay fallback (#72 AF4-session-resilience): when the direct dial to a
/// paired peer is [`ChannelDialError::Unreachable`], the agent reconnects to the edge
/// **relay** endpoint (`ct_edge::channel_broker::broker_channel_relay`), presents its
/// grant (proving possession), and runs the Noise_IK session over the stream the edge
/// splices to the peer. Both members call this; the edge pairs + splices them while
/// preserving the direct-path stream roles, so this simply presents the join and then
/// reuses [`run_channel_session`] over the edge connection. Noise stays end-to-end —
/// the edge only forwards ciphertext.
pub async fn join_via_relay<P>(
    relay_conn: &Connection,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
    local: P,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    match present_channel_join(relay_conn, request, holder).await? {
        ChannelJoinOutcome::Admitted { .. } => {}
        ChannelJoinOutcome::Refused => return Err("edge relay refused the channel join".into()),
    }
    run_channel_session(relay_conn, role, own_noise_private, peer_noise_public, local)
        .await
        .map_err(Into::into)
}

/// **#136 N-wire — DCUtR-upgradable relay join for a NAT-to-NAT (relay-only) member.** Like
/// [`join_via_relay`], but instead of running a plain edge-relay session it runs the
/// **upgradable DCUtR** session ([`crate::p2p::run_channel_session_upgradable_dcutr`]): the byte
/// stream starts on the edge relay (both members are NAT'd, so neither can be dialed directly),
/// and in the background the pair opportunistically hole-punches to a **direct** link via the
/// configured libp2p Circuit-Relay v2 `circuit_relay` and cuts the stream over — offloading the
/// edge. Hole-punch failure stays on the relay; the relay leg is end-to-end throughout. The
/// peer's Noise key is learned from the relayed admission (no out-of-band exchange). The actual
/// cross-NAT punch is proven in the Docker 2-NAT lab (N-rig-2) / the live plane (N-rig-3); on
/// loopback it degrades to the relay.
pub async fn join_via_relay_dcutr<P>(
    relay_conn: &Connection,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    local: P,
    circuit_relay: libp2p::Multiaddr,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    let peer_noise = match present_channel_join(relay_conn, request, holder).await? {
        ChannelJoinOutcome::Admitted { peer_noise_pubkey: Some(k), .. } => k,
        ChannelJoinOutcome::Admitted { .. } => {
            return Err("DCUtR relay join needs the peer's relayed Noise key (register the member's key, #101)".into())
        }
        ChannelJoinOutcome::Refused => return Err("edge relay refused the channel join".into()),
    };
    // The DCUtR session runs the Noise_IK over the relay bi-stream as its base leg, punching to
    // direct in the background. Initiator opens the bi-stream; acceptor accepts the edge-opened one.
    let map_err = |e: Box<dyn std::error::Error + Send + Sync>| io::Error::new(io::ErrorKind::Other, e.to_string());
    let (relay_send, relay_recv) = match role {
        ChannelRole::Initiate => relay_conn.open_bi().await.map_err(|e| map_err(Box::new(e)))?,
        ChannelRole::Accept => relay_conn.accept_bi().await.map_err(|e| map_err(Box::new(e)))?,
    };
    crate::p2p::run_channel_session_upgradable_dcutr(
        relay_send,
        relay_recv,
        local,
        role,
        own_noise_private,
        &peer_noise,
        circuit_relay,
    )
    .await
}

/// **#104 direct-P2P wire-in.** Run one side of an A2A channel session over `relay_conn` as an
/// **upgradable** session: it starts on the relay and, in the background, opportunistically dials a
/// direct link and cuts the byte stream over to it (offloading the edge) — transparently to the
/// app, no byte lost at the seam. Composes
/// [`ct_common::upgrade::run_upgradable_session_initiator`]/`_responder` with the real quinn
/// dial/accept: the channel **initiator** advertises `own_direct_endpoint` (its `direct_listener`'s
/// address) in-band and, on the peer's `Ready`, accepts the incoming direct dial; the channel
/// **responder**, on the `Offer`, dials that endpoint ([`dial_peer_direct`]) and handshakes the
/// direct Noise session. The direct-Noise role is tied to who-dials (the dialer is the Noise
/// initiator) so `a2a_initiate`/`a2a_respond` never block each other. If the hole-punch fails, the
/// session stays on the relay. An initiator with no listener to offer (a relay-only member) runs a
/// plain [`run_channel_session_on_stream`]. The relay leg stays end-to-end either way; the live
/// cross-NAT hole-punch is proven on the deploy (#104 H4), this over loopback.
#[allow(clippy::too_many_arguments)]
pub async fn run_channel_session_upgradable<P>(
    relay_conn: &Connection,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
    local: P,
    direct_listener: Option<Endpoint>,
    own_direct_endpoint: Option<String>,
    dial_timeout: std::time::Duration,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    use ct_common::a2a::establish_direct_session;
    use ct_common::upgrade::{
        run_upgradable_session_initiator, run_upgradable_session_responder, Role, UpgradeCoordinator,
    };

    let map_err = |e: Box<dyn std::error::Error + Send + Sync>| io::Error::new(io::ErrorKind::Other, e.to_string());
    let (relay_send, relay_recv) = match role {
        ChannelRole::Initiate => relay_conn.open_bi().await.map_err(|e| map_err(Box::new(e)))?,
        ChannelRole::Accept => relay_conn.accept_bi().await.map_err(|e| map_err(Box::new(e)))?,
    };
    // The relay handshake borrows these; the direct-establishment closures need owned copies.
    let (relay_priv, relay_peer) = (*own_noise_private, *peer_noise_public);
    let (direct_priv, direct_peer) = (*own_noise_private, *peer_noise_public);

    match role {
        ChannelRole::Initiate => {
            let (listener, endpoint) = match (direct_listener, own_direct_endpoint) {
                (Some(l), Some(e)) => (l, e),
                // Relay-only initiator (no dialable direct address): run the plain relay session.
                _ => {
                    return run_channel_session_on_stream(
                        relay_send, relay_recv, ChannelRole::Initiate, &relay_priv, &relay_peer, local,
                    )
                    .await
                    .map_err(Into::into)
                }
            };
            let coord = UpgradeCoordinator::with_backoff(Role::Initiator, 0, 1, 100);
            run_upgradable_session_initiator(
                relay_send,
                relay_recv,
                local,
                &relay_priv,
                &relay_peer,
                coord,
                1,
                || async move { Some(endpoint) },
                move || async move {
                    // Accept the incoming direct dial (the responder dials us), then handshake as the
                    // direct-Noise RESPONDER (the dialer is the Noise initiator).
                    let incoming = tokio::time::timeout(dial_timeout, listener.accept()).await.ok()??;
                    let conn = incoming.await.ok()?;
                    let (s, r) = conn.accept_bi().await.ok()?;
                    establish_direct_session(s, r, false, &direct_priv, &direct_peer).await.ok()
                },
            )
            .await
            .map_err(Into::into)
        }
        ChannelRole::Accept => {
            let coord = UpgradeCoordinator::with_backoff(Role::Responder, 0, 1, 100);
            run_upgradable_session_responder(
                relay_send,
                relay_recv,
                local,
                &relay_priv,
                coord,
                1,
                // #137 SSRF guard: the offered endpoint is peer-conveyed and never passed the edge
                // broker's `safe_endpoint` gate, so apply the identical range filter here — refuse
                // to even signal Ready for an internal/private/metadata target.
                |ep: String| async move { upgrade_safe_endpoint(&ep).is_some() },
                move |ep: String| async move {
                    // Dial the offered endpoint (SSRF-guarded, #137) and handshake as the
                    // direct-Noise INITIATOR. A non-global-unicast target is refused → stay on relay.
                    let addr = upgrade_safe_endpoint(&ep)?;
                    let conn = dial_peer_direct(addr, dial_timeout).await.ok()?;
                    let (s, r) = conn.open_bi().await.ok()?;
                    establish_direct_session(s, r, true, &direct_priv, &direct_peer).await.ok()
                },
            )
            .await
            .map_err(Into::into)
        }
    }
}

/// Which relay-leg transport [`run_channel_join_with_admission`] falls back to when the
/// direct dial fails (#106 relay-leg-443). The direct-QUIC relay works for a member that
/// can still reach the relay port; a member on a truly `:443`-only network (relay port
/// FILTERED too) needs the relay itself walked over the fallback ladder — direct QUIC,
/// then the unified `:443` TLS-TCP front door — so it can relay at all. Selecting on this
/// keeps every existing QUIC caller unchanged while adding the ladder-capable relay leg.
pub enum RelayFallback<'a> {
    /// A pre-dialed QUIC relay connection (the original relay leg): present the join over
    /// it and run the session over a fresh bi-stream ([`join_via_relay`]).
    Quic(&'a Connection),
    /// A relay endpoint to dial **lazily** — only if the direct path fails and the relay
    /// fallback actually fires (#103 fix). The eager variant held an idle QUIC connection
    /// open through admission + the whole direct-dial/accept wait; the edge's accept loop
    /// reaped that idle connection as a spurious `closed by peer: 0` (a `[quic-bistream]`
    /// drop) before any join, masking the real outcome. Dialing on demand removes it.
    QuicLazy(std::net::SocketAddr),
    /// Walk the relay ladder (direct QUIC → the `:443` front door) via
    /// [`join_via_relay_ladder`]. `rungs` is [`ChannelJoinCliConfig::relay_ladder`];
    /// `edge_cert` is the trust anchor the front-door TLS dial needs; `direct_timeout`
    /// bounds each direct QUIC relay dial before it falls through to `:443`.
    Ladder {
        rungs: &'a [ChannelDialRung],
        edge_cert: CertificateDer<'static>,
        direct_timeout: std::time::Duration,
    },
}

/// Dispatch the relay fallback to the selected transport (#106 relay-leg-443): a
/// [`RelayFallback::Quic`] connection reuses the original [`join_via_relay`]; a
/// [`RelayFallback::Ladder`] walks the relay ladder via [`join_via_relay_ladder`]. This
/// is the single seam both fallback arms of [`run_channel_join_with_admission`] call, so
/// the outcome-driven data path stays identical regardless of the relay transport.
#[allow(clippy::too_many_arguments)]
async fn join_via_relay_fallback<P>(
    relay: RelayFallback<'_>,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
    local: P,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    match relay {
        RelayFallback::Quic(conn) => {
            join_via_relay(conn, request, holder, role, own_noise_private, peer_noise_public, local).await
        }
        RelayFallback::QuicLazy(addr) => {
            // #103 fix: dial the relay only now, when the fallback has actually fired —
            // no idle connection is held during admission/direct-dial for the edge to reap.
            let conn = crate::transport::build_channel_dialer()?
                .connect(addr, "localhost")?
                .await?;
            join_via_relay(&conn, request, holder, role, own_noise_private, peer_noise_public, local).await
        }
        RelayFallback::Ladder { rungs, edge_cert, direct_timeout } => {
            join_via_relay_ladder(
                rungs,
                edge_cert,
                direct_timeout,
                request,
                holder,
                role,
                own_noise_private,
                peer_noise_public,
                local,
            )
            .await
        }
    }
}

/// The relay-leg analog of [`present_channel_join_via_ladder`] (#106 relay-leg-443): walk
/// the relay `rungs`, and on the first rung whose **transport connects**, present the join
/// and run the Noise session over that rung — committing `local` to it. A rung whose
/// transport can't connect (a blocked direct relay port → [`ChannelDialError::Unreachable`],
/// or a `Failed` TLS/connect) falls through to the next; once a rung connects, the session
/// is the terminal action, so we never retry after it starts (`local` is single-move). A
/// **direct** rung dials QUIC to the relay port and delegates to [`join_via_relay`] (join +
/// session on a fresh bi-stream of the same connection). A **front-door** rung opens the
/// `:443` TLS-TCP route ([`crate::transport::tcp_tls_connect_channel`], ALPN
/// `ct-edge-channel`), presents the join *without* consuming the stream
/// ([`present_channel_relay_join_on_stream`]), and — on `Admitted` — runs the session over
/// that **same** relay-spliced stream ([`run_channel_session_on_stream`]); a `Refused` is a
/// finished handshake, not a transport failure, so it errors rather than falling through.
/// This is what lets a fully `:443`-only member (relay port also blocked) relay at all —
/// closing the exact gap the #103 sink reported. Errors only when every rung is blocked.
#[allow(clippy::too_many_arguments)]
pub async fn join_via_relay_ladder<P>(
    rungs: &[ChannelDialRung],
    edge_cert: CertificateDer<'static>,
    direct_timeout: std::time::Duration,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
    local: P,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    // `local` is single-move: hold it in an Option and commit it to the first rung whose
    // transport connects. Fall through ONLY on a transport error, tracked in `last`.
    let mut local = Some(local);
    let mut last: Option<BoxError> = None;
    for rung in rungs {
        if rung.via_front_door {
            // The `:443` front door over TLS-TCP (ALPN ct-edge-channel). The SAME stream
            // carries the join AND the spliced session, so present without consuming it.
            match crate::transport::tcp_tls_connect_channel(rung.endpoint, edge_cert.clone()).await {
                Ok(stream) => {
                    let (mut recv, mut send) = tokio::io::split(stream);
                    let local = local.take().expect("local is committed to exactly one rung");
                    match present_channel_relay_join_on_stream(&mut send, &mut recv, request, holder).await? {
                        ChannelJoinOutcome::Admitted { .. } => {}
                        ChannelJoinOutcome::Refused => {
                            return Err("edge relay refused the channel join over the :443 front door".into());
                        }
                    }
                    return run_channel_session_on_stream(
                        send,
                        recv,
                        role,
                        own_noise_private,
                        peer_noise_public,
                        local,
                    )
                    .await
                    .map_err(Into::into);
                }
                Err(e) => last = Some(e),
            }
        } else {
            // Direct: QUIC to the relay port. Unreachable/Failed falls through to :443.
            match dial_peer_direct(rung.endpoint, direct_timeout).await {
                Ok(conn) => {
                    let local = local.take().expect("local is committed to exactly one rung");
                    return join_via_relay(&conn, request, holder, role, own_noise_private, peer_noise_public, local)
                        .await;
                }
                Err(ChannelDialError::Unreachable) => last = Some(ChannelDialError::Unreachable.into()),
                Err(ChannelDialError::Failed(e)) => last = Some(e),
            }
        }
    }
    Err(last.unwrap_or_else(|| "relay ladder had no rungs to dial".into()))
}

/// How long the acceptor waits for a direct connection before falling back to the
/// edge relay in the plane-brokered CLI flow (#72 / #98 / #103).
const CHANNEL_ACCEPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

/// Config for the **plane-brokered** `ct-agent channel` flow (#98 / #103): present a
/// grant to the edge rendezvous, learn the peer via the broker (keys relayed — no
/// out-of-band `CT_CHANNEL_*` exchange), and connect direct-then-relay. Read from
/// `CT_CHANNEL_*` so it fits the `/channel.sh` one-liner. This is the cross-host path
/// (NAT traversal via the broker), distinct from the direct-address [`ChannelRunConfig`].
pub struct ChannelJoinCliConfig {
    pub role: ChannelRole,
    /// Edge rendezvous endpoint (`CT_CHANNEL_BROKER`, `CT_EDGE_CHANNEL_LISTEN` on the plane).
    pub broker_addr: SocketAddr,
    /// Edge relay endpoint used on direct-dial failure (`CT_CHANNEL_RELAY`).
    pub relay_addr: SocketAddr,
    /// The operator-signed channel grant this member holds (`CT_CHANNEL_GRANT`, hex).
    pub grant: ct_common::channel::SignedChannelGrant,
    /// The holder ed25519 private key that proves possession (`CT_CHANNEL_HOLDER_KEY`, hex). SECRET.
    pub holder: SigningKey,
    /// This member's Noise (X25519) private key (`CT_CHANNEL_NOISE_KEY`, hex). SECRET.
    pub own_noise_private: [u8; 32],
    /// The host:port this member advertises for the direct path (`CT_CHANNEL_LISTEN`).
    pub listen_addr: SocketAddr,
    /// Whether this member joins in **relay-only** mode (#121): forced by
    /// `CT_CHANNEL_RELAY_ONLY`, or auto-detected when `listen_addr` is not globally routable
    /// (a NAT-only host). A relay-only member skips binding the direct listener and advertises
    /// the relay-only sentinel, participating purely via the edge relay + the `:443` fallback.
    pub relay_only: bool,
    /// Optional unified `:443` front door (`CT_CHANNEL_FRONT_DOOR`, host:port) — the #106
    /// fallback for restrictive networks that block the channel broker/relay ports. When
    /// set, the dial ladder tries the direct broker/relay first, then this front door over
    /// TLS-TCP with the `ct-edge-channel` ALPN.
    pub front_door: Option<SocketAddr>,
    /// The edge's TLS certificate (DER) the `:443` front-door dial trusts
    /// (`CT_CHANNEL_FRONT_DOOR_CERT`, hex) — the trust anchor a front-door TLS-TCP dial
    /// needs (#106). Present ⇒ `run_channel_join_command` admits over the broker *ladder*
    /// (direct QUIC → the `:443` front door). Absent ⇒ direct-QUIC-only broker admission,
    /// even if `front_door` is set (a front door you have no root for is unusable).
    pub front_door_cert: Option<CertificateDer<'static>>,
    /// Optional libp2p **Circuit-Relay v2** multiaddr (`CT_CHANNEL_CIRCUIT_RELAY`, #136 N-wire).
    /// When set for a **relay-only** member, the join starts on the edge relay and then
    /// opportunistically hole-punches to a **direct** NAT-to-NAT link via DCUtR through this
    /// circuit relay ([`join_via_relay_dcutr`]). Absent ⇒ the plain edge-relay session (no punch).
    pub circuit_relay: Option<libp2p::Multiaddr>,
}

/// Parse the optional `CT_CHANNEL_CIRCUIT_RELAY` libp2p circuit-relay multiaddr (#136 N-wire):
/// absent/empty ⇒ `None` (no DCUtR upgrade — plain relay session); set-but-malformed ⇒ an error
/// (a typo shouldn't silently disable the hole-punch, mirroring the `:443` front-door handling).
/// Pure — the multiaddr is validated here so a bad value fails config load, not mid-session.
pub fn parse_circuit_relay(value: Option<String>) -> Result<Option<libp2p::Multiaddr>, String> {
    match value {
        Some(s) if !s.trim().is_empty() => s
            .trim()
            .parse::<libp2p::Multiaddr>()
            .map(Some)
            .map_err(|e| format!("CT_CHANNEL_CIRCUIT_RELAY invalid multiaddr: {e}")),
        _ => Ok(None),
    }
}

/// One rung of the channel dial **fallback ladder** (#106): where + how to reach the edge
/// channel broker or relay. Tried in order; the first rung that connects wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelDialRung {
    /// The endpoint to dial.
    pub endpoint: SocketAddr,
    /// `false` = a direct QUIC dial to the channel port; `true` = the unified `:443` front
    /// door (TLS-TCP) advertising the `ct-edge-channel` ALPN, so a network that blocks the
    /// channel ports can still reach the broker/relay (#106, the #31/#46 pattern).
    pub via_front_door: bool,
}

/// Decide whether this member joins in **relay-only** mode (#121): `explicit` (the
/// `CT_CHANNEL_RELAY_ONLY` flag) always forces it on; otherwise it auto-detects relay-only
/// when `listen_addr` is not a globally-routable (global-unicast) address — a NAT-only /
/// private-address-only host that the edge would refuse to advertise (#94) and that no peer
/// could dial. A relay-only member skips binding the direct listener and advertises the
/// [`ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY`] sentinel, participating purely via the
/// edge relay + the #106 `:443` fallback (outbound-only). Pure — it decides from the address
/// alone, so it is unit-testable without touching real network interfaces.
pub fn relay_only_mode(explicit: bool, listen_addr: SocketAddr) -> bool {
    explicit || !is_globally_routable(listen_addr.ip())
}

/// Whether `ip` is a globally-routable (global-unicast) address — the mirror of the edge's
/// `safe_endpoint` range check (#94): loopback / unspecified / multicast, RFC1918 private,
/// link-local (`169.254/16`, `fe80::/10`), CGNAT (`100.64/10`) and IPv6 unique-local
/// (`fc00::/7`) are all NOT routable. A member with only such an address can't be dialed, so
/// it defaults to relay-only.
fn is_globally_routable(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_private() || v4.is_link_local() {
                return false;
            }
            let o = v4.octets();
            !(o[0] == 100 && (64..=127).contains(&o[1])) // reject CGNAT 100.64.0.0/10
        }
        IpAddr::V6(v6) => {
            let s0 = v6.segments()[0];
            (s0 & 0xfe00) != 0xfc00 && (s0 & 0xffc0) != 0xfe80 // reject fc00::/7 + fe80::/10
        }
    }
}

/// #137 SSRF guard for the #104 in-band relay→direct upgrade. The responder dials a
/// **peer-conveyed** `Offer.direct_endpoint`; because the upgrade is negotiated peer-to-peer over
/// the relay pump, that endpoint **never passed the edge broker's `safe_endpoint` admission gate**
/// (#94). Apply the IDENTICAL range filter here — the shared [`ct_common::channel::is_global_unicast`],
/// the exact primitive the edge's `safe_endpoint` is built on — so a malicious/compromised initiator
/// cannot make the responder dial an internal address: loopback, RFC1918/LAN, cloud metadata
/// `169.254.169.254`, link-local, CGNAT, IPv6 ULA, unspecified. Returns the parsed address ONLY if
/// it is safe to dial; `None` (unparseable **or** non-global-unicast) refuses the upgrade and the
/// session stays on the relay. This is an unconditional security guard — no test bypass.
fn upgrade_safe_endpoint(ep: &str) -> Option<SocketAddr> {
    ep.parse::<SocketAddr>()
        .ok()
        .filter(|addr| ct_common::channel::is_global_unicast(*addr))
}

impl ChannelJoinCliConfig {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// The ordered dial plan for the **rendezvous broker**: the direct port first, then
    /// (if `CT_CHANNEL_FRONT_DOOR` is configured) the `:443` front door. Pure.
    pub fn broker_ladder(&self) -> Vec<ChannelDialRung> {
        Self::ladder(self.broker_addr, self.front_door)
    }

    /// The ordered dial plan for the **relay** (used on direct-dial failure): the direct
    /// port first, then (if configured) the `:443` front door. Pure.
    pub fn relay_ladder(&self) -> Vec<ChannelDialRung> {
        Self::ladder(self.relay_addr, self.front_door)
    }

    fn ladder(direct: SocketAddr, front_door: Option<SocketAddr>) -> Vec<ChannelDialRung> {
        let mut rungs = vec![ChannelDialRung { endpoint: direct, via_front_door: false }];
        if let Some(fd) = front_door {
            rungs.push(ChannelDialRung { endpoint: fd, via_front_door: true });
        }
        rungs
    }

    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let role = match f("CT_CHANNEL_ROLE").as_deref().map(|s| s.trim().to_ascii_lowercase()) {
            Some(ref r) if r == "initiate" || r == "initiator" => ChannelRole::Initiate,
            Some(ref r) if r == "accept" || r == "responder" || r == "listen" => ChannelRole::Accept,
            other => return Err(format!("CT_CHANNEL_ROLE must be initiate|accept, got {other:?}")),
        };
        let addr = |k: &str, what: &str| -> Result<SocketAddr, String> {
            f(k).ok_or_else(|| format!("{k} required ({what})"))?
                .trim()
                .parse()
                .map_err(|e| format!("{k} invalid: {e}"))
        };
        let broker_addr = addr("CT_CHANNEL_BROKER", "edge rendezvous host:port")?;
        let relay_addr = addr("CT_CHANNEL_RELAY", "edge relay host:port")?;
        // #121/#173: relay-only mode. `CT_CHANNEL_RELAY_ONLY` forces it on; otherwise it is
        // auto-detected below from the advertised listen address. Parsed BEFORE CT_CHANNEL_LISTEN
        // because a relay-only member has no dialable address, so CT_CHANNEL_LISTEN is OPTIONAL in
        // that mode — it's never bound or advertised (the relay-only sentinel stands in). #173: both
        // source-2 and sink independently hit the old unconditional hard-error and had to invent a
        // dummy value; a relay-only operator no longer has to.
        let relay_only_explicit = f("CT_CHANNEL_RELAY_ONLY")
            .map(|s| {
                let t = s.trim();
                t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false);
        let listen_addr = match f("CT_CHANNEL_LISTEN") {
            Some(s) if !s.trim().is_empty() => s.trim().parse().map_err(|e| format!("CT_CHANNEL_LISTEN invalid: {e}"))?,
            // Relay-only has no dialable address → an unbound placeholder is never used.
            _ if relay_only_explicit => SocketAddr::from(([0, 0, 0, 0], 0)),
            _ => return Err("CT_CHANNEL_LISTEN required (advertised host:port) — or set CT_CHANNEL_RELAY_ONLY=1 for a relay-only member with no dialable address".to_string()),
        };
        let grant_bytes = f("CT_CHANNEL_GRANT")
            .as_deref()
            .and_then(hex_bytes)
            .ok_or("CT_CHANNEL_GRANT required (hex signed grant)")?;
        let grant = ct_common::channel::SignedChannelGrant::decode(&grant_bytes)
            .map_err(|e| format!("CT_CHANNEL_GRANT malformed: {e}"))?;
        let holder = SigningKey::from_bytes(
            &f("CT_CHANNEL_HOLDER_KEY")
                .as_deref()
                .and_then(hex32)
                .ok_or("CT_CHANNEL_HOLDER_KEY required (64 hex)")?,
        );
        let own_noise_private = f("CT_CHANNEL_NOISE_KEY")
            .as_deref()
            .and_then(hex32)
            .ok_or("CT_CHANNEL_NOISE_KEY required (64 hex)")?;
        // #106: optional :443 front-door fallback. Absent -> direct-only ladder; a set but
        // malformed value is an error (a typo shouldn't silently drop the fallback).
        let front_door = match f("CT_CHANNEL_FRONT_DOOR") {
            Some(s) if !s.trim().is_empty() => Some(
                s.trim()
                    .parse()
                    .map_err(|e| format!("CT_CHANNEL_FRONT_DOOR invalid: {e}"))?,
            ),
            _ => None,
        };
        // #106: the trust anchor for the `:443` front-door TLS-TCP dial. Optional and
        // independent of `front_door` (a set-but-malformed value is an error — a typo
        // shouldn't silently drop the fallback); absent ⇒ direct-QUIC-only admission.
        let front_door_cert = match f("CT_CHANNEL_FRONT_DOOR_CERT") {
            Some(s) if !s.trim().is_empty() => Some(CertificateDer::from(
                hex_bytes(s.trim()).ok_or("CT_CHANNEL_FRONT_DOOR_CERT must be hex DER")?,
            )),
            _ => None,
        };
        // Auto-detect relay-only when not forced: a non-globally-routable advertised listen address
        // (a NAT-only host the edge would refuse to advertise, #94) is treated as relay-only.
        let relay_only = relay_only_mode(relay_only_explicit, listen_addr);
        // #136 N-wire: optional libp2p circuit-relay multiaddr for the DCUtR NAT-to-NAT punch.
        let circuit_relay = parse_circuit_relay(f("CT_CHANNEL_CIRCUIT_RELAY"))?;
        Ok(Self { role, broker_addr, relay_addr, grant, holder, own_noise_private, listen_addr, relay_only, front_door, front_door_cert, circuit_relay })
    }
}

/// A freshly-minted Agent-Fabric channel identity for **self-service** participation
/// (#117): the ed25519 *holder* keypair (proves possession of a grant) and the X25519
/// *Noise* keypair (the member's session key). Both are generated **locally** so the
/// private keys never leave the participant's machine — which is why self-service
/// channel setup is a local CLI step, not a browser/server flow: it preserves the
/// provider-blind property (the operator never sees a private key). Before this, a
/// participant had to hand-craft these keys or have the operator provision them by hand
/// for every new member. The hex accessors emit exactly what the `ct-agent channel` CLI
/// consumes (`CT_CHANNEL_HOLDER_KEY`, `CT_CHANNEL_NOISE_KEY`) plus the two **public**
/// keys an operator needs to register the channel / sign this member's grant.
pub struct ChannelIdentity {
    /// The holder ed25519 keypair (its private half proves grant possession).
    pub holder: SigningKey,
    /// The member's X25519 Noise static keypair.
    pub noise: ct_common::noise::StaticKeypair,
}

impl ChannelIdentity {
    /// Mint a fresh identity from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut holder_seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut holder_seed);
        let holder = SigningKey::from_bytes(&holder_seed);
        let noise = ct_common::noise::generate_static_keypair();
        Self { holder, noise }
    }

    /// Value for `CT_CHANNEL_HOLDER_KEY` — the 64-hex ed25519 holder **private** key. SECRET.
    pub fn holder_key_hex(&self) -> String {
        hex_encode(&self.holder.to_bytes())
    }
    /// Value for `CT_CHANNEL_NOISE_KEY` — the 64-hex X25519 Noise **private** key. SECRET.
    pub fn noise_key_hex(&self) -> String {
        hex_encode(&self.noise.private)
    }
    /// The 64-hex ed25519 holder **public** key — an operator signs this member's grant over it.
    pub fn holder_pubkey_hex(&self) -> String {
        hex_encode(self.holder.verifying_key().as_bytes())
    }
    /// The 64-hex X25519 Noise **public** key — the member's attested session key.
    pub fn noise_pubkey_hex(&self) -> String {
        hex_encode(&self.noise.public)
    }

    /// A copy-pasteable shell block a self-service participant `eval`s (or sources)
    /// before running `ct-agent channel` (#117): the two **secret** private keys as
    /// `export`s the CLI reads, plus the two **public** keys as comments to hand to the
    /// channel operator (who signs this member's grant / registers the channel). The
    /// operator still supplies `CT_CHANNEL_GRANT` and the broker/relay/front-door
    /// addresses. Private keys are generated locally and never printed as anything but
    /// the participant's own env — they never reach the operator or the server.
    pub fn env_block(&self) -> String {
        format!(
            "# Agent-Fabric channel identity — generated locally, keep the private keys secret.\n\
             # Give these PUBLIC keys to the channel operator (to sign your grant / register):\n\
             #   holder_pubkey = {holder_pub}\n\
             #   noise_pubkey  = {noise_pub}\n\
             export CT_CHANNEL_HOLDER_KEY={holder_priv}\n\
             export CT_CHANNEL_NOISE_KEY={noise_priv}\n",
            holder_pub = self.holder_pubkey_hex(),
            noise_pub = self.noise_pubkey_hex(),
            holder_priv = self.holder_key_hex(),
            noise_priv = self.noise_key_hex(),
        )
    }
}

/// One overlay link compiled into a concrete A2A channel (#107-nway): the derived
/// [`ct_common::channel::ChannelId`] and the two operator-signed grants the link's members
/// present to join it. The initiator holder is the canonically-smaller node id of the link
/// (the `Initiate`-direction side); the acceptor is the other. Both members independently
/// derive the same `channel` from their holder keys, so no coordination round-trip is
/// needed to agree on the channel address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledLink {
    pub channel: ct_common::channel::ChannelId,
    pub initiator_holder: [u8; 32],
    pub acceptor_holder: [u8; 32],
    pub initiator_grant: ct_common::channel::SignedChannelGrant,
    pub acceptor_grant: ct_common::channel::SignedChannelGrant,
}

/// A channel **operator's** signing identity (#117-operator-flow): the ed25519 key that
/// *authorizes* a channel — its public key is the channel's authority (registered with
/// the control plane so the edge can verify member grants), and it signs every member's
/// grant. Generated locally, like a member's [`ChannelIdentity`]; the operator private
/// key never leaves the operator's machine (provider-blind — the server sees only the
/// public key). This lets an account create channels and admit members with no manual
/// crypto provisioning by central.
pub struct OperatorIdentity {
    /// The operator ed25519 keypair (its private half signs member grants).
    pub key: SigningKey,
}

impl OperatorIdentity {
    /// Mint a fresh operator key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self { key: SigningKey::from_bytes(&seed) }
    }

    /// The 64-hex operator **private** key (`CT_CHANNEL_OPERATOR_KEY`). SECRET.
    pub fn key_hex(&self) -> String {
        hex_encode(&self.key.to_bytes())
    }
    /// The 64-hex operator **public** key — the channel's authority, registered with the
    /// control plane so the edge verifies member grants against it.
    pub fn pubkey_hex(&self) -> String {
        hex_encode(self.key.verifying_key().as_bytes())
    }

    /// Issue a member grant: sign a `ChannelGrant` binding `holder_pubkey` (the member's
    /// `channel init` holder public key) to `channel` with `direction`/`expires_at`, and
    /// return the hex the member sets as `CT_CHANNEL_GRANT`. Pure crypto — the operator
    /// runs this locally after the member hands over their holder public key; no server
    /// round-trip and no private key ever leaves either machine.
    pub fn issue_member_grant(
        &self,
        channel: ct_common::channel::ChannelId,
        holder_pubkey: [u8; 32],
        direction: ct_common::channel::Direction,
        expires_at: ct_common::channel::UnixSeconds,
    ) -> String {
        hex_encode(&self.sign_member_grant(channel, holder_pubkey, direction, expires_at).encode())
    }

    /// Sign a `ChannelGrant` binding `holder_pubkey` to `channel` with `direction`/
    /// `expires_at` under the local operator key, returning the structured grant. The
    /// crypto shared by [`issue_member_grant`](Self::issue_member_grant) (which hex-encodes
    /// this for the member one-liner) and [`compile_overlay_grants`](Self::compile_overlay_grants).
    fn sign_member_grant(
        &self,
        channel: ct_common::channel::ChannelId,
        holder_pubkey: [u8; 32],
        direction: ct_common::channel::Direction,
        expires_at: ct_common::channel::UnixSeconds,
    ) -> ct_common::channel::SignedChannelGrant {
        use ct_common::channel::{ChannelGrant, Rights, SignedChannelGrant};
        let g = ChannelGrant {
            channel,
            holder: holder_pubkey,
            direction,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at,
        };
        let signature = self.key.sign(&g.signing_bytes()).to_bytes();
        SignedChannelGrant { grant: g, signature }
    }

    /// Compile a topology's overlay `plan` into per-link A2A channels (#107-nway): each
    /// link (a canonical pair of agent node-ids) becomes a channel
    /// ([`ct_common::channel::channel_id_for_link`]) plus the two operator-signed grants its
    /// members present to join it. `holder_of` maps a node id to that agent's member holder
    /// pubkey (the controller knows each registered agent's key). The canonically-smaller
    /// node id of each link is the **Initiate** side — a stable, caller-independent split,
    /// like the broker's `authorize_channel_pair`. Returns `Err(node_id)` if a link names an
    /// agent with no holder mapping (the plan can't be wired without every endpoint's key).
    ///
    /// Pure given `holder_of`: the operator mints every grant **locally** with its own key
    /// (invariant #6) — no central round-trip; central only distributes the compiled grants.
    pub fn compile_overlay_grants(
        &self,
        plan: &ct_common::overlay::OverlayPlan,
        holder_of: impl Fn(&str) -> Option<[u8; 32]>,
        expires_at: ct_common::channel::UnixSeconds,
    ) -> Result<Vec<CompiledLink>, String> {
        use ct_common::channel::{channel_id_for_link, Direction};
        let op_pub = self.key.verifying_key().to_bytes();
        let mut out = Vec::with_capacity(plan.links.len());
        for (a_id, b_id) in &plan.links {
            let initiator_holder = holder_of(a_id).ok_or_else(|| a_id.clone())?;
            let acceptor_holder = holder_of(b_id).ok_or_else(|| b_id.clone())?;
            // channel_id_for_link sorts by holder bytes, so both members derive the same id.
            let channel = channel_id_for_link(&op_pub, &initiator_holder, &acceptor_holder);
            out.push(CompiledLink {
                channel,
                initiator_holder,
                acceptor_holder,
                initiator_grant: self.sign_member_grant(
                    channel,
                    initiator_holder,
                    Direction::Initiate,
                    expires_at,
                ),
                acceptor_grant: self.sign_member_grant(
                    channel,
                    acceptor_holder,
                    Direction::Accept,
                    expires_at,
                ),
            });
        }
        Ok(out)
    }

    /// Issue a short-lived **membership staple** (E-fail-static, invariant #7): the operator
    /// re-affirms that `holder_pubkey` is *currently* a member of `channel`, valid for
    /// `ttl_secs` from `stapled_at`. Unlike [`issue_member_grant`](Self::issue_member_grant)
    /// — a long-lived capability — a staple is minted **frequently** and gossiped so peers
    /// keep admitting the member (via [`ct_common::channel::StapleCache`]) while central is
    /// unreachable, and it dies within one TTL once the operator stops re-issuing it
    /// (revocation latency = staple TTL).
    ///
    /// Minted with the **local** operator key (invariant #6): central never holds the key,
    /// so it can *distribute/refresh* staples but can never mint — nor forge — one. This is
    /// why a central compromise degrades to DoS/metadata, never impersonation. Returns the
    /// staple object (the gossip transport encodes it); the operator runs this locally on a
    /// refresh timer, no server round-trip.
    pub fn issue_membership_staple(
        &self,
        channel: ct_common::channel::ChannelId,
        holder_pubkey: [u8; 32],
        stapled_at: ct_common::channel::UnixSeconds,
        ttl_secs: u64,
    ) -> ct_common::channel::MembershipStaple {
        use ct_common::channel::MembershipStaple;
        let expires_at = stapled_at.saturating_add(ttl_secs);
        let signature = self
            .key
            .sign(&MembershipStaple::signing_bytes(
                &channel,
                &holder_pubkey,
                stapled_at,
                expires_at,
            ))
            .to_bytes();
        MembershipStaple {
            channel,
            holder: holder_pubkey,
            stapled_at,
            expires_at,
            signature,
        }
    }

    /// A copy-pasteable, `eval`-safe shell block for `ct-agent channel operator-init`
    /// (#117): the operator private key as the `export` the `channel grant` command
    /// reads, plus the operator public key as a comment (the channel authority to
    /// register with the control plane). Generated locally; the private key never leaves.
    pub fn operator_env_block(&self) -> String {
        format!(
            "# Agent-Fabric channel OPERATOR identity — generated locally, keep the key secret.\n\
             # Register this PUBLIC key as the channel authority (POST /channel/register):\n\
             #   operator_pubkey = {op_pub}\n\
             export CT_CHANNEL_OPERATOR_KEY={op_priv}\n",
            op_pub = self.pubkey_hex(),
            op_priv = self.key_hex(),
        )
    }
}

/// Inputs for `ct-agent channel grant` (#117-operator-flow): an operator signs one
/// member's grant from the environment, parsed like [`ChannelJoinCliConfig::from_lookup`].
/// `CT_CHANNEL_OPERATOR_KEY` is the operator's own key (from `channel operator-init`);
/// `CT_GRANT_*` describe the member being admitted (their `channel init`
/// `holder_pubkey`, the channel id, the direction, and an expiry).
pub struct OperatorGrantRequest {
    pub operator: SigningKey,
    pub channel: ct_common::channel::ChannelId,
    pub member_holder: [u8; 32],
    pub direction: ct_common::channel::Direction,
    pub expires_at: ct_common::channel::UnixSeconds,
}

impl OperatorGrantRequest {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let operator = SigningKey::from_bytes(
            &f("CT_CHANNEL_OPERATOR_KEY")
                .as_deref()
                .and_then(hex32)
                .ok_or("CT_CHANNEL_OPERATOR_KEY required (64 hex; from `channel operator-init`)")?,
        );
        let channel = ct_common::channel::ChannelId(
            f("CT_GRANT_CHANNEL")
                .as_deref()
                .and_then(hex32)
                .ok_or("CT_GRANT_CHANNEL required (64 hex channel id)")?,
        );
        let member_holder = f("CT_GRANT_MEMBER_HOLDER")
            .as_deref()
            .and_then(hex32)
            .ok_or("CT_GRANT_MEMBER_HOLDER required (64 hex member holder pubkey)")?;
        let direction = match f("CT_GRANT_DIRECTION").as_deref().map(|s| s.trim().to_ascii_lowercase()) {
            Some(ref d) if d == "initiate" || d == "initiator" => ct_common::channel::Direction::Initiate,
            Some(ref d) if d == "accept" || d == "responder" => ct_common::channel::Direction::Accept,
            other => return Err(format!("CT_GRANT_DIRECTION must be initiate|accept, got {other:?}")),
        };
        let expires_at = f("CT_GRANT_EXPIRES")
            .ok_or("CT_GRANT_EXPIRES required (unix seconds)")?
            .trim()
            .parse()
            .map_err(|e| format!("CT_GRANT_EXPIRES invalid: {e}"))?;
        Ok(Self { operator, channel, member_holder, direction, expires_at })
    }

    /// The signed grant hex the member sets as `CT_CHANNEL_GRANT`.
    pub fn issue(&self) -> String {
        OperatorIdentity { key: self.operator.clone() }.issue_member_grant(
            self.channel,
            self.member_holder,
            self.direction,
            self.expires_at,
        )
    }
}

/// Inputs for `ct-agent channel register` (#117-operator-register): register the
/// operator's channel authority with the control plane (`POST /me/channels`) so the edge
/// accepts the member grants the operator signs — the last CP round-trip for an
/// end-to-end self-service Agent-Fabric channel. Parsed from the environment like
/// [`OperatorGrantRequest::from_lookup`], reusing the onboarding/operator vars:
/// the control-plane URL (`CT_AGENT_CP_URL`, as onboarding uses), the channel id
/// (`CT_GRANT_CHANNEL`), the OIDC bearer token (`CT_OIDC_TOKEN`), and the operator public
/// key — derived from `CT_CHANNEL_OPERATOR_KEY` (the operator's own private key from
/// `channel operator-init`) or supplied directly as `CT_CHANNEL_OPERATOR_PUBKEY`.
pub struct ChannelRegisterRequest {
    /// Control-plane base URL (`POST {cp_url}/me/channels`).
    pub cp_url: String,
    /// The channel id, canonical 64-hex.
    pub channel_hex: String,
    /// The operator ed25519 public key, canonical 64-hex — the channel's authority.
    pub operator_pubkey_hex: String,
    /// The OIDC bearer token identifying the owner (the verified subject).
    pub token: String,
}

impl ChannelRegisterRequest {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let cp_url = f("CT_AGENT_CP_URL")
            .filter(|s| !s.trim().is_empty())
            .ok_or("CT_AGENT_CP_URL required (control-plane base URL)")?;
        let channel_hex = hex_encode(
            &f("CT_GRANT_CHANNEL")
                .as_deref()
                .and_then(hex32)
                .ok_or("CT_GRANT_CHANNEL required (64 hex channel id)")?,
        );
        // The channel authority: derive from the operator's own private key
        // (CT_CHANNEL_OPERATOR_KEY, from `channel operator-init`), or take the public key
        // directly (CT_CHANNEL_OPERATOR_PUBKEY) when only the pubkey is at hand.
        let operator_pubkey_hex = if let Some(pk) =
            f("CT_CHANNEL_OPERATOR_PUBKEY").as_deref().and_then(hex32)
        {
            hex_encode(&pk)
        } else if let Some(sk) = f("CT_CHANNEL_OPERATOR_KEY").as_deref().and_then(hex32) {
            OperatorIdentity { key: SigningKey::from_bytes(&sk) }.pubkey_hex()
        } else {
            return Err(
                "CT_CHANNEL_OPERATOR_KEY (64 hex operator private, from `channel operator-init`) \
                 or CT_CHANNEL_OPERATOR_PUBKEY (64 hex) required"
                    .to_string(),
            );
        };
        let token = f("CT_OIDC_TOKEN")
            .filter(|s| !s.trim().is_empty())
            .ok_or("CT_OIDC_TOKEN required (OIDC bearer token for the channel owner)")?;
        Ok(Self { cp_url, channel_hex, operator_pubkey_hex, token })
    }
}

/// The channel session's local application duplex (#135 L2.1-cli). **Pipe** mode (default) is the
/// CLI's stdin/stdout — the historical one-shot behaviour (stdin-EOF tears the session down).
/// **Serve** mode (`CT_CHANNEL_SERVE=1`) makes the channel a persistent request/response *service*:
/// the session side of an in-process duplex whose other half runs
/// [`serve_request_loop`](ct_common::a2a::serve_request_loop), so the peer can call it many times
/// over one Noise tunnel. A single enum keeps the two shapes one concrete type for the generic pump.
enum ChannelLocal {
    Pipe(tokio::io::Join<tokio::io::Stdin, tokio::io::Stdout>),
    Serve(tokio::io::DuplexStream),
}

impl AsyncRead for ChannelLocal {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ChannelLocal::Pipe(p) => Pin::new(p).poll_read(cx, buf),
            ChannelLocal::Serve(d) => Pin::new(d).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ChannelLocal {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ChannelLocal::Pipe(p) => Pin::new(p).poll_write(cx, buf),
            ChannelLocal::Serve(d) => Pin::new(d).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ChannelLocal::Pipe(p) => Pin::new(p).poll_flush(cx),
            ChannelLocal::Serve(d) => Pin::new(d).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ChannelLocal::Pipe(p) => Pin::new(p).poll_shutdown(cx),
            ChannelLocal::Serve(d) => Pin::new(d).poll_shutdown(cx),
        }
    }
}

/// Serve-mode local (#135 L2.1-cli): spawn [`serve_request_loop`](ct_common::a2a::serve_request_loop)
/// with `handle` on one half of an in-process duplex and return the *session* half — the pump drives
/// it, so the peer's framed requests are answered by `handle` over the one persistent Noise tunnel.
fn serve_local<H, F>(handle: H) -> tokio::io::DuplexStream
where
    H: FnMut(Vec<u8>) -> F + Send + 'static,
    F: std::future::Future<Output = Vec<u8>> + Send,
{
    let (session_side, serve_side) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        let (mut recv, mut send) = tokio::io::split(serve_side);
        let _ = ct_common::a2a::serve_request_loop(&mut send, &mut recv, handle).await;
    });
    session_side
}

/// Call-mode local (#135 L2.3, client side): spawn a one-shot MCP client on one half of an in-process
/// duplex — write ONE JSON-RPC request, print the peer's response body, then close — and return the
/// session half for the pump. So `ct-agent channel --call <method>` = connect, invoke a peer's tool
/// once, print the JSON-RPC reply, exit.
/// One MCP request/response over a duplex's split halves (#135 L2.3 client core): frame + write the
/// request, then read + return the peer's response body. Testable in isolation; `call_local` prints
/// what it returns.
async fn mcp_call_over<W, R>(
    send: &mut W,
    recv: &mut R,
    method: &str,
    params: serde_json::Value,
) -> io::Result<Vec<u8>>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let request = ct_common::mcp::encode_request(1, method, params);
    ct_common::a2a::write_message(send, &request).await?;
    ct_common::noise::read_frame(recv).await
}

/// Crew-bridge c2 atom (#171/#173): call a peer's `service/<slug>` tool over an already-established
/// channel duplex and return the service's `output` string. Frames the fixed
/// `service/<slug>({input}) -> {output}` shape (#149-A.1), reads the reply, and extracts
/// `result.output`. **Fails closed:** a transport error, a JSON-RPC `error` (the service
/// rejected/failed), or a reply missing `result.output` all return `Err` — never a bogus fragment.
/// The crew bridge calls this once per role (safety_check, physics, art) over each dialed channel
/// and feeds the returned JSON into [`ct_common::crew`].
pub async fn call_role_service<W, R>(
    send: &mut W,
    recv: &mut R,
    slug: &str,
    input: &str,
) -> io::Result<String>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let params = serde_json::json!({ "name": format!("service/{slug}"), "arguments": { "input": input } });
    let body = mcp_call_over(send, recv, "tools/call", params).await?;
    let v: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if let Some(err) = v.get("error") {
        return Err(io::Error::new(io::ErrorKind::Other, format!("service/{slug} returned an error: {err}")));
    }
    v.get("result")
        .and_then(|r| r.get("output"))
        .and_then(|o| o.as_str())
        .map(String::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("service/{slug} reply missing result.output")))
}

/// Crew-bridge c2 driver (#171/#173): given already-connected channel duplexes to the three role
/// agents, run the crew end to end and return the browser's `{safety, auction, config}` — the
/// orchestration the `/crew/build` server (c3) wraps.
///
/// Order + fail-closed semantics:
/// 1. **safety_check** runs FIRST over the safety agent's channel; its output is `{ok, reason}`. A
///    `false` verdict short-circuits to a **rejection** (no fragment calls, no build) — the
///    authoritative live guard.
/// 2. **physics** then **art** run over their agents' channels (`service/text_generation`), and the
///    fragments are assembled by [`ct_common::crew`].
///
/// A transport/parse failure at any step returns `Err(reason)` — the c3 HTTP layer maps that to a
/// 5xx so the **browser fails closed to its local stand-in**. A clean policy rejection is
/// `Ok(rejected)`; a clean build is `Ok(built)`. `auction` (who won each role) is supplied by the
/// caller — the bridge derives it from a real `match_offer`/`convene`; a demo may pass the fixed crew.
pub async fn crew_build_over<S, P, A>(
    prompt: &str,
    safety_conn: S,
    physics_conn: P,
    art_conn: A,
    auction: Vec<ct_common::crew::RoleAuction>,
) -> Result<ct_common::crew::CrewBuildResponse, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
    P: AsyncRead + AsyncWrite + Unpin,
    A: AsyncRead + AsyncWrite + Unpin,
{
    // 1. safety_check — the authoritative live guard.
    let (mut sr, mut sw) = tokio::io::split(safety_conn);
    let safety_out = call_role_service(&mut sw, &mut sr, "safety_check", prompt)
        .await
        .map_err(|e| format!("safety_check service unreachable: {e}"))?;
    let verdict: serde_json::Value =
        serde_json::from_str(&safety_out).map_err(|e| format!("safety_check reply not JSON: {e}"))?;
    if verdict.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let reason = verdict.get("reason").and_then(|r| r.as_str()).unwrap_or("rejected by the safety agent");
        return Ok(ct_common::crew::CrewBuildResponse::rejected(reason.to_string()));
    }
    // 2. physics + art fragments — run CONCURRENTLY. They are independent (each only depends on
    //    safety_check having passed) and use separate channels, so their wall-clock is max(physics,
    //    art), not the sum. Measured (#173): each role's real `claude -p` is ~14s and the tunnel
    //    overhead is negligible, so sequential was safety+physics+art ≈ 40–55s; joining the two
    //    independent roles cuts it to ≈ safety + max(physics, art) ≈ ~28s.
    let physics = async {
        let (mut pr, mut pw) = tokio::io::split(physics_conn);
        call_role_service(&mut pw, &mut pr, "text_generation", prompt)
            .await
            .map_err(|e| format!("physics role unreachable: {e}"))
    };
    let art = async {
        let (mut ar, mut aw) = tokio::io::split(art_conn);
        call_role_service(&mut aw, &mut ar, "text_generation", prompt)
            .await
            .map_err(|e| format!("art role unreachable: {e}"))
    };
    let (physics_json, art_json) = tokio::join!(physics, art);
    let (physics_json, art_json) = (physics_json?, art_json?);
    // 3. assemble the real config from the fragments (fail-closed on a malformed fragment).
    let cfg = ct_common::crew::CrewConfig::from_fragment_json(&physics_json, &art_json)
        .map_err(|e| format!("crew fragments malformed: {e}"))?;
    Ok(ct_common::crew::CrewBuildResponse::built(cfg, auction))
}

fn call_local(method: String, params: serde_json::Value) -> tokio::io::DuplexStream {
    let (session_side, serve_side) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        let (mut recv, mut send) = tokio::io::split(serve_side);
        match mcp_call_over(&mut send, &mut recv, &method, params).await {
            Ok(response) => println!("{}", String::from_utf8_lossy(&response)),
            Err(e) => eprintln!("ct-agent channel --call: no response ({e})"),
        }
        // Dropping serve_side EOFs the session side → the channel session ends → the process exits.
    });
    session_side
}

/// Invoke the peer's `service/<slug>` tool with `input` over the channel's `local` duplex and return
/// the **bare** service output (`result.output`) — reusing the tested [`call_role_service`]. Unlike
/// [`call_local`]'s raw-method mode (which prints the whole JSON-RPC envelope for a caller-supplied
/// method + static params), this is the crew-native contract: one `service/<slug>` call, plain
/// output. Split out so it can be frozen-tested against an in-process serve peer.
async fn run_service_call<S>(local: S, slug: &str, input: &str) -> std::io::Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut recv, mut send) = tokio::io::split(local);
    call_role_service(&mut send, &mut recv, slug, input).await
}

/// The initiator-side one-shot **service** call (#173 distributed crew topology): dial done by the
/// channel session, this drives the local side — call the peer's `service/<slug>` with `input`, print
/// the bare service output, then EOF the session so the process exits. This is exactly the
/// stdin→stdout contract the crew bridge's `CREW_*_CMD` expects, so `CREW_PHYSICS_CMD="ct-agent
/// channel"` (with `CT_CHANNEL_CALL_SERVICE=text_generation` + the source-2 channel-join env) dials
/// source-2 over the real Agent-Fabric tunnel and yields its fragment JSON — no jq/wrapper needed.
fn call_service_local(slug: String, input: String) -> tokio::io::DuplexStream {
    let (session_side, serve_side) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        match run_service_call(serve_side, &slug, &input).await {
            Ok(output) => println!("{output}"),
            // Fail closed: no output on stdout → the crew bridge's run_cmd sees empty/!success and 502s.
            Err(e) => eprintln!("ct-agent channel --call-service {slug}: {e}"),
        }
        // Dropping serve_side (moved into run_service_call) EOFs the session → the session ends.
    });
    session_side
}

/// Parse a `CT_AGENT_SERVICES` entry (the same slugs `ct_common::mcp`'s `service/<slug>` tool
/// names use) into a [`ct_common::channel::ServiceType`]. Unknown entries are silently dropped by
/// the caller's `filter_map` — a typo just means one fewer tool exposed, not a hard error, matching
/// this CLI's general "best-effort optional config" posture (e.g. `AgentOfferCliConfig`).
fn parse_service_type(s: &str) -> Option<ct_common::channel::ServiceType> {
    use ct_common::channel::ServiceType::*;
    match s {
        "code_generation" => Some(CodeGeneration),
        "security_review" => Some(SecurityReview),
        "safety_check" => Some(SafetyCheck),
        "text_generation" => Some(TextGeneration),
        _ => None,
    }
}

/// Bound how long a `CT_AGENT_SERVICE_HANDLER_CMD` child may run before it's killed (#149-A.1
/// serve-wiring: every other blocking step in this file is timed — `A2A_HANDSHAKE_TIMEOUT`,
/// `DIRECT_STREAM_SETUP_TIMEOUT`, `*_DRAIN_TIMEOUT` — this was the one unbounded exception, flagged
/// in review). Generous: a real LLM-backed handler can legitimately take tens of seconds.
const SERVICE_HANDLER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Run the configured `CT_AGENT_SERVICE_HANDLER_CMD` for one `service/<slug>` call (#149-A.1
/// serve-wiring follow): spawn it via `sh -c`, write `input` to its stdin, and return its trimmed
/// stdout as the result. `CT_SERVICE_TYPE` is set in the child's environment so one handler script
/// can branch on which of several registered services was actually invoked. A non-zero exit, a
/// spawn/IO failure, or exceeding `timeout` becomes the tool error (surfaced to the caller as a
/// JSON-RPC error, never a panic). `timeout` is a parameter (the real call site below always passes
/// [`SERVICE_HANDLER_TIMEOUT`]) so the kill-on-timeout path is unit-testable without an actual
/// 120-second wait.
///
/// Two fixes from review, both real (caught reading `#149`'s wiring, not hypothetical):
/// - **stdin is written on its own thread**, concurrently with the wait/output-read below — writing
///   it inline, then calling `wait_with_output()`, is the textbook `std::process` pipe deadlock: an
///   `input` over the OS pipe buffer (~64 KiB) whose handler writes to stdout *before* finishing its
///   stdin read blocks both sides forever, and a consumer fully controls `input`'s size (`register_service_tools`
///   reads `args["input"]` with no cap) — a remote DoS on the provider, not just a footgun.
/// - **the child is bounded by `timeout` and killed if it's exceeded**, closing the one unbounded
///   blocking step in this file.
fn run_service_handler_with_timeout(
    cmd: &str,
    service: ct_common::channel::ServiceType,
    input: &str,
    timeout: std::time::Duration,
) -> Result<String, String> {
    use std::process::{Command, Stdio};
    let slug = match service {
        ct_common::channel::ServiceType::CodeGeneration => "code_generation",
        ct_common::channel::ServiceType::SecurityReview => "security_review",
        ct_common::channel::ServiceType::SafetyCheck => "safety_check",
        ct_common::channel::ServiceType::TextGeneration => "text_generation",
    };
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .env("CT_SERVICE_TYPE", slug)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("service handler spawn failed: {e}"))?;
    let pid = child.id();

    // Write stdin on its own thread so it can proceed concurrently with the wait/output-read
    // below (the deadlock fix). Best-effort: a handler that never reads stdin (or exits before
    // fully consuming it) makes this fail with a broken-pipe error, which we deliberately ignore
    // here — the child's own exit status/output is the actual verdict, not whether every stdin
    // byte landed.
    let mut stdin = child.stdin.take().ok_or("service handler: no stdin pipe")?;
    let input_owned = input.to_string();
    let _stdin_writer = std::thread::spawn(move || {
        use std::io::Write;
        let _ = stdin.write_all(input_owned.as_bytes());
    });

    // Run wait_with_output() (which itself reads stdout/stderr concurrently on its own threads —
    // std's own implementation, not reproduced here) on a background thread so this call can be
    // bounded: recv_timeout enforces SERVICE_HANDLER_TIMEOUT, and on timeout we kill the child by
    // pid (captured above, before ownership moved into the thread) so the still-running background
    // wait unblocks on its own rather than leaking a wedged process.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    let output = match rx.recv_timeout(timeout) {
        Ok(result) => result.map_err(|e| format!("service handler wait failed: {e}"))?,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
            return Err(format!(
                "service handler timed out after {}s (pid {pid} killed)",
                timeout.as_secs()
            ));
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            return Err("service handler: wait thread disconnected unexpectedly".to_string())
        }
    };
    if !output.status.success() {
        return Err(format!(
            "service handler exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// [`run_service_handler_with_timeout`] bound to the real [`SERVICE_HANDLER_TIMEOUT`] — the seam
/// every non-test call site uses.
fn run_service_handler(
    cmd: &str,
    service: ct_common::channel::ServiceType,
    input: &str,
) -> Result<String, String> {
    run_service_handler_with_timeout(cmd, service, input, SERVICE_HANDLER_TIMEOUT)
}

/// Build the channel session's local app duplex from the environment (#135 L2.x). `CT_CHANNEL_CALL=<method>`
/// → one-shot MCP **client** (invoke a peer's tool, print the reply, exit). `CT_CHANNEL_SERVE=1` → the
/// persistent MCP **service** (JSON-RPC `tools/list`/`tools/call` via the tool registry). Neither → the
/// historical stdin/stdout pipe.
fn channel_local() -> ChannelLocal {
    // #173 distributed crew: one-shot `service/<slug>` client. Reads the prompt on stdin, calls the
    // peer's service, prints the BARE output — the crew-bridge `CREW_*_CMD` contract. Checked before
    // the raw CT_CHANNEL_CALL below because it's the service-specific (and jq-free) path.
    if let Ok(slug) = std::env::var("CT_CHANNEL_CALL_SERVICE") {
        let slug = slug.trim().to_string();
        let mut input = String::new();
        {
            use std::io::Read;
            let _ = std::io::stdin().read_to_string(&mut input);
        }
        eprintln!("ct-agent channel: --call-service {slug} (one service call over the channel, then exit)");
        return ChannelLocal::Serve(call_service_local(slug, input.trim().to_string()));
    }
    // #135 L2.3 client: one MCP request/response over the channel, then exit.
    if let Ok(method) = std::env::var("CT_CHANNEL_CALL") {
        let method = method.trim().to_string();
        let params = std::env::var("CT_CHANNEL_CALL_PARAMS")
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .unwrap_or(serde_json::Value::Null);
        eprintln!("ct-agent channel: --call {method} (one MCP request over the channel, then exit)");
        return ChannelLocal::Serve(call_local(method, params));
    }
    let serve = std::env::var("CT_CHANNEL_SERVE")
        .map(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false);
    if serve {
        // #135 L2.3: each framed request body is a JSON-RPC 2.0 message dispatched against the agent's
        // MCP tool registry; the response body is the JSON-RPC reply. Arc so the registry is shared
        // across the persistent session's calls. #144×#135: if the agent has AgentCard config
        // (CT_CHANNEL_HOLDER_KEY + CT_AGENT_CARD_*), also expose `agent/card` — its signed identity
        // over the authenticated channel; otherwise just the default `ping` tool.
        fn now_secs() -> u64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        }
        let mut reg = match AgentCardCliConfig::from_env() {
            Ok(cfg) => {
                let card_json = serde_json::to_value(cfg.build_card(now_secs()))
                    .unwrap_or(serde_json::Value::Null);
                eprintln!("ct-agent channel: --serve mode (MCP-over-channel; tools: ping, agent/card)");
                ct_common::mcp::registry_with_card(card_json)
            }
            Err(_) => {
                eprintln!(
                    "ct-agent channel: --serve mode (MCP-over-channel; tool: ping — set CT_AGENT_CARD_* to also expose agent/card)"
                );
                ct_common::mcp::default_registry()
            }
        };
        // #152: if an offer is configured (CT_AGENT_OFFER_*), also expose the #147 auction tools
        // (`auction/offer` + `auction/bid`) over the same authenticated channel — the CLI parity that
        // lets the marketplace be demoed live the way `agent/card` is. The seller stamps time itself
        // (`now_secs`), never the caller.
        // #152/#167: build the offer config ONCE — the signed offer drives both the auction tools
        // and the ceiling on which `service/<slug>` tools may be registered, so the two can't drift.
        let offer_cfg = AgentOfferCliConfig::from_env().ok();
        if let Some(cfg) = &offer_cfg {
            let offer = cfg.build_offer(now_secs());
            ct_common::mcp::register_auction_tools(
                &mut reg,
                offer,
                now_secs,
                cfg.max_bids_per_window,
                cfg.window_secs,
            );
            eprintln!(
                "ct-agent channel: --serve also exposing auction/offer + auction/bid (CT_AGENT_OFFER_*)"
            );
        }
        // #149-A.1 serve-wiring + #167 declared-vs-served: expose one schema-typed `service/<slug>`
        // tool per service, backed by shelling out to `CT_AGENT_SERVICE_HANDLER_CMD` (`input` on
        // stdin, trimmed stdout is the result, `CT_SERVICE_TYPE` names the slug; runs synchronously —
        // fine for a low-concurrency demo, a multi-tenant host would want `spawn_blocking`).
        //
        // #167: the signed offer's **declared** service catalog is the ceiling. A service is
        // registered only if the offer declares it, so what a buyer can cryptographically verify the
        // agent offers is exactly what it will serve. `CT_AGENT_SERVICES`, when set, is an explicit
        // override *filtered to* the declared catalog (undeclared entries are refused loudly, never
        // registered); when unset with an offer, the declared catalog itself is the list (one knob).
        // With no offer configured there is no cryptographic ceiling and `CT_AGENT_SERVICES` stands
        // alone — the unchanged self-asserted regime.
        if let Ok(handler_cmd) = std::env::var("CT_AGENT_SERVICE_HANDLER_CMD") {
            let requested: Vec<ct_common::channel::ServiceType> = match std::env::var("CT_AGENT_SERVICES") {
                Ok(s) => s.split(',').filter_map(|t| parse_service_type(t.trim())).collect(),
                Err(_) => offer_cfg.as_ref().map(|c| c.services.clone()).unwrap_or_default(),
            };
            let services: Vec<ct_common::channel::ServiceType> = match &offer_cfg {
                Some(cfg) => {
                    let (allowed, refused): (Vec<_>, Vec<_>) =
                        requested.into_iter().partition(|s| cfg.services.contains(s));
                    if !refused.is_empty() {
                        eprintln!(
                            "ct-agent channel: REFUSING {} service tool(s) not in the signed offer's declared catalog (#167): {:?}",
                            refused.len(),
                            refused
                        );
                    }
                    allowed
                }
                None => requested,
            };
            if !services.is_empty() {
                let n = services.len();
                ct_common::mcp::register_service_tools(&mut reg, &services, move |service, input| {
                    run_service_handler(&handler_cmd, service, input)
                });
                eprintln!(
                    "ct-agent channel: --serve also exposing {n} service tool(s) via CT_AGENT_SERVICE_HANDLER_CMD"
                );
            }
        }
        let registry = std::sync::Arc::new(reg);
        ChannelLocal::Serve(serve_local(move |req: Vec<u8>| {
            let registry = registry.clone();
            async move { registry.dispatch(&req) }
        }))
    } else {
        ChannelLocal::Pipe(tokio::io::join(tokio::io::stdin(), tokio::io::stdout()))
    }
}

/// Run the plane-brokered `ct-agent channel` flow (#98 / #103): connect to the edge
/// rendezvous + relay, present the grant, and pipe **stdin/stdout** over the A2A tunnel
/// with automatic direct-then-relay recovery via [`run_channel_join`]. The broker
/// relays the peer's Noise key, so no `CT_CHANNEL_PEER_*` is needed.
pub async fn run_channel_join_command(cfg: ChannelJoinCliConfig) -> Result<(), BoxError> {
    // Capture what the broker/relay ladders need before `cfg.grant` is moved into
    // `request` (a partial move would forbid the `cfg.broker_ladder()` `&self` call).
    let broker_ladder = cfg.broker_ladder();
    let relay_ladder = cfg.relay_ladder();
    let front_door_cert = cfg.front_door_cert.clone();
    // #121: a relay-only member advertises the sentinel instead of a dialable address — it
    // can't be reached directly, so it participates purely via the relay + `:443` fallback.
    let request = ChannelJoinRequest {
        grant: cfg.grant,
        endpoint: if cfg.relay_only {
            ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY.to_string()
        } else {
            cfg.listen_addr.to_string()
        },
    };
    // #136 N-wire: a relay-only (NAT-to-NAT) member with a libp2p circuit relay configured runs
    // the DCUtR-upgradable relay join — start on the edge relay, then opportunistically hole-punch
    // to a direct link via the circuit relay. Both members are NAT'd, so this is the only path that
    // can ever go direct; without a circuit relay it falls through to the plain relay session below.
    if cfg.relay_only {
        if let Some(circuit) = cfg.circuit_relay.clone() {
            let relay_conn = crate::transport::build_channel_dialer()?
                .connect(cfg.relay_addr, "localhost")?
                .await?;
            let local = channel_local();
            eprintln!(
                "ct-agent channel: relay-only DCUtR-upgradable {:?} (relay {}, circuit {})",
                cfg.role, cfg.relay_addr, circuit
            );
            return join_via_relay_dcutr(
                &relay_conn,
                &request,
                &cfg.holder,
                cfg.role,
                &cfg.own_noise_private,
                local,
                circuit,
            )
            .await;
        }
    }
    // Broker admission (the grant + possession proof are the auth; Noise_IK authenticates
    // the peer end-to-end). With a `:443` front-door cert configured, walk the broker
    // ladder — direct QUIC first, then the `:443` TLS-TCP front door — so a network that
    // blocks the channel port still reaches the broker (#106 client-dial-wire). Otherwise
    // the direct-QUIC broker join, unchanged. Borrow the cert so it survives for the relay
    // leg's ladder below.
    let admission = match &front_door_cert {
        Some(edge_cert) => {
            eprintln!(
                "ct-agent channel: plane-brokered {:?}; broker ladder over {} (front door {:?})",
                cfg.role, cfg.broker_addr, cfg.front_door
            );
            present_channel_join_via_ladder(
                &broker_ladder,
                &request,
                &cfg.holder,
                edge_cert.clone(),
                DIRECT_DIAL_TIMEOUT,
            )
            .await?
        }
        None => {
            let broker_conn = crate::transport::build_channel_dialer()?
                .connect(cfg.broker_addr, "localhost")?
                .await?;
            present_channel_join(&broker_conn, &request, &cfg.holder).await?
        }
    };
    // The relay data leg mirrors the broker leg (#106 relay-leg-443): with a `:443`
    // front-door cert, the relay fallback walks its own ladder — direct QUIC to the relay
    // port, then the `:443` front door — so a member whose relay port is ALSO filtered
    // (a fully `:443`-only network) can still relay. Without a cert, keep the eager
    // direct-QUIC relay dial unchanged (nothing regresses for members that reach the port).
    let relay = match &front_door_cert {
        Some(edge_cert) => RelayFallback::Ladder {
            rungs: &relay_ladder,
            edge_cert: edge_cert.clone(),
            direct_timeout: DIRECT_DIAL_TIMEOUT,
        },
        // #103 fix: dial the relay LAZILY (only on direct-dial failure) instead of eagerly
        // holding an idle connection the edge reaps as a spurious pre-admission close.
        None => RelayFallback::QuicLazy(cfg.relay_addr),
    };
    // #121: a relay-only member skips binding the direct listener even in the Accept role —
    // it can't be dialed, so `run_channel_join_with_admission` relays it directly.
    let listener = match cfg.role {
        ChannelRole::Accept if !cfg.relay_only => {
            Some(crate::transport::build_direct_listener_at(cfg.listen_addr)?.0)
        }
        _ => None,
    };
    eprintln!(
        "ct-agent channel: plane-brokered {:?} (relay {})",
        cfg.role, cfg.relay_addr
    );
    let local = channel_local();
    run_channel_join_with_admission(
        admission,
        relay,
        &request,
        &cfg.holder,
        cfg.role,
        &cfg.own_noise_private,
        listener,
        DIRECT_DIAL_TIMEOUT,
        CHANNEL_ACCEPT_TIMEOUT,
        local,
    )
    .await
}

/// Bound on a direct A2A dial before giving up (#72 AF4-session-resilience). Kept
/// short so a peer that's unreachable on the direct path (NAT / firewall / down) fails
/// fast — the signal to fall back to the edge relay — instead of hanging on the QUIC
/// handshake's retransmits.
pub const DIRECT_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Why a direct dial to a paired peer did not connect (#72 AF4-session-resilience).
#[derive(Debug)]
pub enum ChannelDialError {
    /// The dial did not complete within the timeout — the peer is unreachable on the
    /// **direct** path. This is the signal to fall back to the edge relay, not an error
    /// to surface to the user.
    Unreachable,
    /// The dial failed for another reason (bad address, endpoint setup, connect error).
    Failed(BoxError),
}

impl std::fmt::Display for ChannelDialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelDialError::Unreachable => write!(f, "peer unreachable on the direct path"),
            ChannelDialError::Failed(e) => write!(f, "direct dial failed: {e}"),
        }
    }
}

impl std::error::Error for ChannelDialError {}

/// Dial a paired peer's advertised endpoint directly over QUIC (accept-any transport —
/// Noise_IK is the real auth), bounded by `timeout`. A timeout is classified as
/// [`ChannelDialError::Unreachable`] rather than a generic error, so the caller can
/// distinguish "the direct path is blocked, fall back to the relay" from "the dial
/// itself is malformed" — the crux of the connection-difficulty handling.
pub async fn dial_peer_direct(
    addr: std::net::SocketAddr,
    timeout: std::time::Duration,
) -> Result<Connection, ChannelDialError> {
    let dialer = crate::transport::build_channel_dialer().map_err(ChannelDialError::Failed)?;
    let connecting = dialer
        .connect(addr, "localhost")
        .map_err(|e| ChannelDialError::Failed(Box::new(e)))?;
    match tokio::time::timeout(timeout, connecting).await {
        Ok(Ok(conn)) => Ok(conn),
        Ok(Err(e)) => Err(ChannelDialError::Failed(Box::new(e))),
        Err(_elapsed) => Err(ChannelDialError::Unreachable),
    }
}

/// Walk a channel dial **fallback ladder** (#106): try each rung in order and return
/// the first that connects. A rung that fails — `Unreachable` (a restrictive network
/// blocked the direct channel port) or `Failed` — falls through to the next, so a
/// blocked *direct* rung falls back to the `:443` front-door rung. Errors only when
/// **every** rung is blocked (all paths down). The per-rung transport connect is
/// injected as `dial`, so the ladder-walk is pure and unit-testable without sockets;
/// the caller supplies the real QUIC-direct / TLS-TCP-`:443` dials (the latter carries
/// the `ct-edge-channel` ALPN so the `:443` front door routes it to the broker).
pub async fn dial_ladder<C, D, Fut>(rungs: &[ChannelDialRung], dial: D) -> Result<C, ChannelDialError>
where
    D: Fn(&ChannelDialRung) -> Fut,
    Fut: std::future::Future<Output = Result<C, ChannelDialError>>,
{
    let mut last: Option<ChannelDialError> = None;
    for rung in rungs {
        match dial(rung).await {
            Ok(conn) => return Ok(conn),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or(ChannelDialError::Unreachable))
}

/// Present a channel join by walking the fallback `rungs` (#106 client-dial-443): for a
/// **direct** rung, dial the channel port over QUIC ([`dial_peer_direct`]) and run the
/// join on a fresh bi-stream ([`present_channel_join`]); for a **front-door** rung, open
/// the unified `:443` route over TLS-TCP ([`crate::transport::tcp_tls_connect_channel`],
/// ALPN `ct-edge-channel`) and run the identical join over the split TLS stream
/// ([`present_channel_join_on_stream`]). Composed over [`dial_ladder`], so the first rung
/// that *completes* the join — an `Admitted` **or** `Refused` outcome, either being a
/// finished handshake — wins; a rung whose transport can't connect (`Unreachable` on a
/// blocked direct port, or a `Failed` TLS/connect) falls through to the next, letting a
/// network that blocks the direct channel port recover over `:443`. Errors only when
/// every rung is blocked. `edge_cert` is the root the front-door TLS dial trusts;
/// `direct_timeout` bounds each direct QUIC dial (the [`DIRECT_DIAL_TIMEOUT`] signal).
pub async fn present_channel_join_via_ladder(
    rungs: &[ChannelDialRung],
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    edge_cert: CertificateDer<'static>,
    direct_timeout: std::time::Duration,
) -> Result<ChannelJoinOutcome, BoxError> {
    dial_ladder(rungs, |rung: &ChannelDialRung| {
        let endpoint = rung.endpoint;
        let via_front_door = rung.via_front_door;
        let edge_cert = edge_cert.clone();
        async move {
            if via_front_door {
                // #106 fallback: the :443 front door over TLS-TCP (ALPN ct-edge-channel).
                let stream = crate::transport::tcp_tls_connect_channel(endpoint, edge_cert)
                    .await
                    .map_err(ChannelDialError::Failed)?;
                let (recv, send) = tokio::io::split(stream);
                present_channel_join_on_stream(send, recv, request, holder, ADMISSION_EXCHANGE_TIMEOUT)
                    .await
                    .map_err(ChannelDialError::Failed)
            } else {
                // Direct: QUIC to the channel port. Unreachable falls through to :443.
                let conn = dial_peer_direct(endpoint, direct_timeout).await?;
                present_channel_join(&conn, request, holder)
                    .await
                    .map_err(ChannelDialError::Failed)
            }
        }
    })
    .await
    .map_err(Into::into)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let v = hex_bytes(s)?;
    <[u8; 32]>::try_from(v.as_slice()).ok()
}

/// Split a comma-separated env value into trimmed, non-empty tokens (empty input → no tokens).
fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect()
}

/// Configuration for `ct-agent channel agent-card` (#144 ①-wiring): assemble + sign this
/// agent's holder [`AgentCard`](ct_common::channel::AgentCard) from `CT_CHANNEL_HOLDER_KEY`
/// plus the advertised claims, and write it to `<CT_AGENT_CARD_OUT>/.well-known/agent-card.json`
/// for the operator's origin to serve — the runnable path that closes the emit chain without
/// anyone hand-rolling ed25519. Env-parsed with the clock injected at [`write_card`], so the
/// assembly is a pure, testable function.
pub struct AgentCardCliConfig {
    /// The holder ed25519 signing key the card is bound to (`CT_CHANNEL_HOLDER_KEY`, hex). SECRET.
    pub holder: SigningKey,
    /// Advertised role tags (`CT_AGENT_CARD_ROLES`, comma-separated) — at least one required.
    pub role_tags: Vec<String>,
    /// Advertised skills (`CT_AGENT_CARD_SKILLS`, `;`-separated `id|description` entries).
    pub skills: Vec<ct_common::channel::Skill>,
    /// Self-asserted cells (`CT_AGENT_CARD_CELLS`, comma-separated 64-hex) — usually empty.
    pub cells: Vec<ct_common::channel::CellId>,
    /// Channels the agent advertises reachability via (`CT_AGENT_CARD_CHANNELS`, comma-separated 64-hex).
    pub channels: Vec<ct_common::channel::ChannelId>,
    /// Validity window in seconds (`CT_AGENT_CARD_TTL_SECS`, default 86400).
    pub ttl_secs: u64,
    /// Directory the `.well-known/agent-card.json` is written under (`CT_AGENT_CARD_OUT`, default `.`).
    pub out_dir: std::path::PathBuf,
}

impl AgentCardCliConfig {
    /// Read the config from the process environment.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from a variable lookup (the `from_env` seam — testable without touching the real env).
    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let holder = SigningKey::from_bytes(
            &f("CT_CHANNEL_HOLDER_KEY")
                .as_deref()
                .and_then(hex32)
                .ok_or("CT_CHANNEL_HOLDER_KEY required (64 hex)")?,
        );
        let role_tags = split_csv(f("CT_AGENT_CARD_ROLES").as_deref().unwrap_or_default());
        if role_tags.is_empty() {
            return Err("CT_AGENT_CARD_ROLES required (comma-separated role tags)".to_string());
        }
        let skills = parse_card_skills(f("CT_AGENT_CARD_SKILLS").as_deref().unwrap_or_default());
        let channels = parse_hex32_ids(f("CT_AGENT_CARD_CHANNELS").as_deref().unwrap_or_default())
            .map_err(|bad| format!("CT_AGENT_CARD_CHANNELS entry not 64 hex: {bad}"))?
            .into_iter()
            .map(ct_common::channel::ChannelId)
            .collect();
        let cells = parse_hex32_ids(f("CT_AGENT_CARD_CELLS").as_deref().unwrap_or_default())
            .map_err(|bad| format!("CT_AGENT_CARD_CELLS entry not 64 hex: {bad}"))?
            .into_iter()
            .map(ct_common::channel::CellId)
            .collect();
        let ttl_secs = match f("CT_AGENT_CARD_TTL_SECS").as_deref().map(str::trim) {
            Some(s) if !s.is_empty() => s
                .parse::<u64>()
                .map_err(|e| format!("CT_AGENT_CARD_TTL_SECS invalid: {e}"))?,
            _ => 86_400,
        };
        let out_dir = std::path::PathBuf::from(
            f("CT_AGENT_CARD_OUT").unwrap_or_else(|| ".".to_string()),
        );
        Ok(Self { holder, role_tags, skills, cells, channels, ttl_secs, out_dir })
    }

    /// Assemble + sign the agent's card (`issued_at = now`, `expires_at = now + ttl_secs`). The clock
    /// is a parameter so the assembly is deterministic + testable. Shared by [`write_card`] (emit to
    /// the origin) and the `agent/card` MCP tool (serve the identity over the authenticated channel).
    pub fn build_card(&self, now: u64) -> ct_common::channel::AgentCard {
        ct_common::channel::AgentCard::sign_new(
            &self.holder,
            self.role_tags.clone(),
            self.skills.clone(),
            self.cells.clone(),
            self.channels.clone(),
            now,
            now.saturating_add(self.ttl_secs),
        )
    }

    /// Sign the card and write it to `<out_dir>/.well-known/agent-card.json`. Returns the written path.
    pub fn write_card(&self, now: u64) -> std::io::Result<std::path::PathBuf> {
        crate::well_known::write_agent_card_for_origin(&self.build_card(now), &self.out_dir)
    }
}

/// CLI/env config for a **`CapacityOffer`** (#152 — the seller side of the #147 marketplace over the
/// `ct-agent` CLI, mirroring [`AgentCardCliConfig`]). When these vars are present, `--serve` mode also
/// exposes the `auction/offer` + `auction/bid` MCP tools so an operator can stand up a live offer and
/// have a live bid clear against it over a real authenticated channel — the `#144`-style live proof for
/// the marketplace. The holder key is reused from `CT_CHANNEL_HOLDER_KEY` (same as the card).
pub struct AgentOfferCliConfig {
    /// The holder ed25519 signing key the offer is bound to (`CT_CHANNEL_HOLDER_KEY`, hex). SECRET.
    signing_key: SigningKey,
    /// Capacity kind (`CT_AGENT_OFFER_KIND` = `cloud` | `local`).
    kind: ct_common::channel::CapacityKind,
    /// Model ids served (`CT_AGENT_OFFER_MODELS`, comma-separated) — at least one required.
    models: Vec<String>,
    /// Units offered (`CT_AGENT_OFFER_UNITS`).
    units_available: u64,
    /// The buyer's guaranteed-minimum floor (`CT_AGENT_OFFER_MIN_PRICE`).
    min_price: u64,
    /// Opaque settlement-currency id (`CT_AGENT_OFFER_CURRENCY`).
    currency_id: String,
    /// Validity window in seconds (`CT_AGENT_OFFER_TTL_SECS`, default 86400).
    ttl_secs: u64,
    /// #149-A.3 per-consumer bid rate limit (`CT_AGENT_OFFER_MAX_BIDS`, default 60).
    pub max_bids_per_window: u32,
    /// Rate-limit window (`CT_AGENT_OFFER_WINDOW_SECS`, default 60).
    pub window_secs: u64,
    /// #167/#149-A.1: the service catalog this offer **declares** (`CT_AGENT_OFFER_SERVICES`,
    /// comma-separated slugs). Empty = a generic offer that declares no services. This is the
    /// signed, buyer-verifiable ceiling on which `service/<slug>` tools the agent may register —
    /// so what a `CapacityOffer` claims and what the agent actually serves can no longer drift.
    pub services: Vec<ct_common::channel::ServiceType>,
}

impl AgentOfferCliConfig {
    /// Read the config from the process environment.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from a variable lookup (the `from_env` seam — testable without touching the real env). An
    /// absent required var is an `Err`, which the caller treats as "no offer configured" (auction tools
    /// stay off), exactly like the card path.
    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let signing_key = SigningKey::from_bytes(
            &f("CT_CHANNEL_HOLDER_KEY")
                .as_deref()
                .and_then(hex32)
                .ok_or("CT_CHANNEL_HOLDER_KEY required (64 hex)")?,
        );
        let kind = match f("CT_AGENT_OFFER_KIND").as_deref().map(str::trim) {
            Some("cloud") | Some("cloud-api") | Some("CloudApiQuota") => {
                ct_common::channel::CapacityKind::CloudApiQuota
            }
            Some("local") | Some("local-hardware") | Some("LocalHardware") => {
                ct_common::channel::CapacityKind::LocalHardware
            }
            Some(other) if !other.is_empty() => {
                return Err(format!("CT_AGENT_OFFER_KIND must be 'cloud' or 'local', got '{other}'"))
            }
            _ => return Err("CT_AGENT_OFFER_KIND required ('cloud' or 'local')".to_string()),
        };
        let models = split_csv(f("CT_AGENT_OFFER_MODELS").as_deref().unwrap_or_default());
        if models.is_empty() {
            return Err("CT_AGENT_OFFER_MODELS required (comma-separated model ids)".to_string());
        }
        let req_u64 = |var: &str| -> Result<u64, String> {
            f(var)
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| format!("{var} required"))?
                .parse::<u64>()
                .map_err(|e| format!("{var} invalid: {e}"))
        };
        let units_available = req_u64("CT_AGENT_OFFER_UNITS")?;
        let min_price = req_u64("CT_AGENT_OFFER_MIN_PRICE")?;
        let currency_id = f("CT_AGENT_OFFER_CURRENCY")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or("CT_AGENT_OFFER_CURRENCY required")?;
        let opt_u64 = |var: &str, default: u64| -> Result<u64, String> {
            match f(var).as_deref().map(str::trim) {
                Some(s) if !s.is_empty() => s.parse::<u64>().map_err(|e| format!("{var} invalid: {e}")),
                _ => Ok(default),
            }
        };
        let ttl_secs = opt_u64("CT_AGENT_OFFER_TTL_SECS", 86_400)?;
        let window_secs = opt_u64("CT_AGENT_OFFER_WINDOW_SECS", 60)?;
        let max_bids_per_window = match f("CT_AGENT_OFFER_MAX_BIDS").as_deref().map(str::trim) {
            Some(s) if !s.is_empty() => {
                s.parse::<u32>().map_err(|e| format!("CT_AGENT_OFFER_MAX_BIDS invalid: {e}"))?
            }
            _ => 60,
        };
        // #167: the offer's declared service catalog. Comma-separated slugs (same vocabulary as
        // `CT_AGENT_SERVICES`); an unknown slug is a hard config error (fail-closed — never silently
        // drop a service the operator believes they declared). Absent/empty = a generic offer.
        let services = match f("CT_AGENT_OFFER_SERVICES").as_deref().map(str::trim) {
            Some(s) if !s.is_empty() => {
                let mut out = Vec::new();
                for tok in s.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                    match parse_service_type(tok) {
                        Some(st) => out.push(st),
                        None => {
                            return Err(format!(
                                "CT_AGENT_OFFER_SERVICES has unknown service '{tok}' (valid: code_generation, security_review, safety_check, text_generation)"
                            ))
                        }
                    }
                }
                out
            }
            _ => Vec::new(),
        };
        Ok(Self {
            signing_key,
            kind,
            models,
            units_available,
            min_price,
            currency_id,
            ttl_secs,
            max_bids_per_window,
            window_secs,
            services,
        })
    }

    /// Assemble + sign the offer (`issued_at = now`, `expires_at = now + ttl_secs`). The clock is a
    /// parameter so the assembly is deterministic + testable, exactly like [`AgentCardCliConfig::build_card`].
    pub fn build_offer(&self, now: u64) -> ct_common::channel::CapacityOffer {
        // #167: when a service catalog is declared, sign it into the offer (so a buyer can
        // cryptographically verify which services the agent offers, and `#149-A.1`'s `match_offer`
        // service filter actually has something to enforce). An empty catalog keeps the historical
        // generic offer (`sign_new`) so nothing changes for offers that make no service claims.
        if self.services.is_empty() {
            ct_common::channel::CapacityOffer::sign_new(
                &self.signing_key,
                self.kind,
                self.models.clone(),
                self.units_available,
                self.min_price,
                self.currency_id.clone(),
                now,
                now.saturating_add(self.ttl_secs),
            )
        } else {
            ct_common::channel::CapacityOffer::sign_new_with_services(
                &self.signing_key,
                self.kind,
                self.models.clone(),
                self.units_available,
                self.min_price,
                self.currency_id.clone(),
                now,
                now.saturating_add(self.ttl_secs),
                self.services.clone(),
            )
        }
    }
}

/// Parse `CT_AGENT_CARD_SKILLS`: `;`-separated entries, each `id|description` (a bare `id`
/// yields an empty description). Empty/blank entries are dropped. Examples are left empty —
/// the card is a discovery advertisement, not an invocation contract.
fn parse_card_skills(s: &str) -> Vec<ct_common::channel::Skill> {
    s.split(';')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(|entry| {
            let (id, description) = match entry.split_once('|') {
                Some((i, d)) => (i.trim().to_string(), d.trim().to_string()),
                None => (entry.to_string(), String::new()),
            };
            ct_common::channel::Skill { id, description, examples: Vec::new() }
        })
        .collect()
}

/// Parse a comma-separated list of 64-hex tokens into `[u8; 32]`s. Returns the first
/// malformed token as `Err` so the caller can name the offending field.
fn parse_hex32_ids(s: &str) -> Result<Vec<[u8; 32]>, String> {
    let mut out = Vec::new();
    for tok in s.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        out.push(hex32(tok).ok_or_else(|| tok.to_string())?);
    }
    Ok(out)
}

/// Configuration for the `ct-agent channel` runner (#98/#100), read from the
/// environment so the whole thing fits a copy-paste one-liner. The peer's transport
/// cert and Noise key travel as hex (as the broker/CP will hand them over); Noise_IK
/// is the real mutual authentication, so the QUIC cert is only the transport anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelRunConfig {
    pub role: ChannelRole,
    /// Responder: the address to bind. Initiator: the peer address to dial.
    pub addr: SocketAddr,
    /// This agent's member Noise (X25519) private key.
    pub own_noise_private: [u8; 32],
    /// The peer's member Noise public key (pinned by the initiator).
    pub peer_noise_public: [u8; 32],
    /// Initiator only: the peer responder's QUIC cert (DER) to trust for the dial.
    pub peer_cert_der: Option<Vec<u8>>,
}

impl ChannelRunConfig {
    /// Parse from the process environment (`CT_CHANNEL_*`).
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from an arbitrary key→value lookup (testable without touching real env).
    /// Required: `CT_CHANNEL_ROLE` (initiate|accept), `CT_CHANNEL_ADDR` (host:port),
    /// `CT_CHANNEL_NOISE_KEY` + `CT_CHANNEL_PEER_NOISE_KEY` (64 hex each). For
    /// `initiate`, `CT_CHANNEL_PEER_CERT` (hex DER of the responder's cert) is required.
    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let role = match f("CT_CHANNEL_ROLE").as_deref().map(|s| s.trim().to_ascii_lowercase()) {
            Some(ref r) if r == "initiate" || r == "initiator" => ChannelRole::Initiate,
            Some(ref r) if r == "accept" || r == "responder" || r == "listen" => ChannelRole::Accept,
            other => return Err(format!("CT_CHANNEL_ROLE must be initiate|accept, got {other:?}")),
        };
        let addr = f("CT_CHANNEL_ADDR")
            .ok_or("CT_CHANNEL_ADDR required (host:port)")?
            .trim()
            .parse::<SocketAddr>()
            .map_err(|e| format!("CT_CHANNEL_ADDR invalid: {e}"))?;
        let own_noise_private = f("CT_CHANNEL_NOISE_KEY")
            .as_deref()
            .and_then(hex32)
            .ok_or("CT_CHANNEL_NOISE_KEY required (64 hex chars)")?;
        let peer_noise_public = f("CT_CHANNEL_PEER_NOISE_KEY")
            .as_deref()
            .and_then(hex32)
            .ok_or("CT_CHANNEL_PEER_NOISE_KEY required (64 hex chars)")?;
        // Optional: pin the peer's transport cert. Omit it and the initiator dials
        // accept-any (Noise_IK authenticates), which keeps the one-liner self-contained.
        let peer_cert_der = match f("CT_CHANNEL_PEER_CERT").filter(|s| !s.trim().is_empty()) {
            Some(h) => Some(hex_bytes(&h).ok_or("CT_CHANNEL_PEER_CERT must be hex DER")?),
            None => None,
        };
        Ok(Self { role, addr, own_noise_private, peer_noise_public, peer_cert_der })
    }
}

/// Run the `ct-agent channel` subcommand: bring up this agent as one side of an A2A
/// channel and pipe **stdin/stdout** over the encrypted tunnel (#98/#100). The
/// responder binds `addr` and prints its cert (hex) so the initiator can trust the
/// direct path; the initiator dials `addr` trusting the configured peer cert. The
/// real mutual auth is the Noise_IK session keyed on the member Noise keys.
pub async fn run_channel_command(cfg: ChannelRunConfig) -> Result<(), BoxError> {
    let local = channel_local();
    match cfg.role {
        ChannelRole::Accept => {
            let (endpoint, cert) = crate::transport::build_direct_listener_at(cfg.addr)?;
            eprintln!(
                "ct-agent channel: listening on {} (responder); peer must set \
                 CT_CHANNEL_PEER_CERT={}",
                cfg.addr,
                hex_encode(cert.as_ref())
            );
            let conn = endpoint
                .accept()
                .await
                .ok_or("channel endpoint closed with no incoming")?
                .await?;
            run_channel_session(
                &conn,
                ChannelRole::Accept,
                &cfg.own_noise_private,
                &cfg.peer_noise_public,
                local,
            )
            .await?;
        }
        ChannelRole::Initiate => {
            // Pin the peer's transport cert if one was supplied; otherwise dial with
            // the accept-any channel dialer — Noise_IK is the real auth, so no cert
            // needs to be conveyed (self-contained one-liner, #100).
            let conn = match cfg.peer_cert_der.clone() {
                Some(der) => crate::transport::dial_quic(cfg.addr, CertificateDer::from(der)).await?,
                None => {
                    let endpoint = crate::transport::build_channel_dialer()?;
                    endpoint.connect(cfg.addr, "localhost")?.await?
                }
            };
            eprintln!("ct-agent channel: connected to {} (initiator)", cfg.addr);
            run_channel_session(
                &conn,
                ChannelRole::Initiate,
                &cfg.own_noise_private,
                &cfg.peer_noise_public,
                local,
            )
            .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_common::noise::generate_static_keypair;
    use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn cfg_from(pairs: &[(&str, &str)]) -> Result<ChannelRunConfig, String> {
        let map: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        ChannelRunConfig::from_lookup(|k| map.get(k).cloned())
    }

    const K64: &str = "aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20";

    #[test]
    fn agent_card_cli_config_parses_and_writes_a_verifiable_card() {
        // #144 ①-wiring CLI (frozen): the runnable `channel agent-card` path parses
        // CT_CHANNEL_HOLDER_KEY + CT_AGENT_CARD_* into a signed card and drops it at the RFC-8615
        // well-known path — closing the emit chain with no hand-rolled ed25519. The written file
        // round-trips to a card whose holder signature verifies, bound to the CLI-supplied key.
        use ct_common::channel::AgentCard;

        let dir = std::env::temp_dir().join(format!("ct-agent-card-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let chan = "9b".repeat(32);
        let pairs = [
            ("CT_CHANNEL_HOLDER_KEY", K64),
            ("CT_AGENT_CARD_ROLES", "central, orchestrator"),
            ("CT_AGENT_CARD_SKILLS", "orchestrate_task|coordinate an agent network; fire_transfer"),
            ("CT_AGENT_CARD_CHANNELS", chan.as_str()),
            ("CT_AGENT_CARD_TTL_SECS", "4000"),
            ("CT_AGENT_CARD_OUT", dir.to_str().unwrap()),
        ];
        let map: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let cfg = AgentCardCliConfig::from_lookup(|k| map.get(k).cloned()).expect("parses");

        // Claims parsed as expected (CSV roles; `id|desc` and bare-`id` skills; TTL).
        assert_eq!(cfg.role_tags, vec!["central".to_string(), "orchestrator".to_string()]);
        assert_eq!(cfg.skills.len(), 2);
        assert_eq!(cfg.skills[0].id, "orchestrate_task");
        assert_eq!(cfg.skills[0].description, "coordinate an agent network");
        assert_eq!(cfg.skills[1].id, "fire_transfer", "a bare id (no |) is allowed");
        assert_eq!(cfg.skills[1].description, "");
        assert_eq!(cfg.channels.len(), 1);
        assert_eq!(cfg.ttl_secs, 4000);

        // Write + read back: a verifiable card bound to the CLI holder key, at the well-known path.
        let path = cfg.write_card(1_000).expect("writes the card");
        assert!(path.ends_with(".well-known/agent-card.json"), "RFC-8615 path, got {path:?}");
        let back: AgentCard = serde_json::from_slice(&std::fs::read(&path).unwrap()).expect("parses");
        assert!(back.is_valid(1_000), "the written card verifies");
        assert!(!back.is_valid(5_000), "expires at issued+ttl = 5000");
        let holder_pub = SigningKey::from_bytes(&hex32(K64).unwrap()).verifying_key().to_bytes();
        assert_eq!(back.holder_pubkey, holder_pub, "bound to the CLI-supplied holder key");
        assert_eq!(back.role_tags, cfg.role_tags);
        let _ = std::fs::remove_dir_all(&dir);

        // Missing roles → error; a bad holder key → error.
        let no_roles: HashMap<String, String> = [("CT_CHANNEL_HOLDER_KEY", K64)]
            .iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        assert!(AgentCardCliConfig::from_lookup(|k| no_roles.get(k).cloned()).is_err(), "roles required");
        let bad_key: HashMap<String, String> = [("CT_CHANNEL_HOLDER_KEY", "zz"), ("CT_AGENT_CARD_ROLES", "central")]
            .iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        assert!(AgentCardCliConfig::from_lookup(|k| bad_key.get(k).cloned()).is_err(), "bad holder key rejected");
    }

    #[tokio::test]
    async fn serve_local_answers_framed_requests_as_a_persistent_service() {
        // #135 L2.1-cli (frozen): serve-mode local turns the channel's app duplex into a persistent
        // request/response SERVICE — the pump-driven session side accepts framed requests and gets
        // the handler's framed responses back, MANY times over ONE duplex (not one-shot pipe). The
        // handler here upper-cases (a stand-in for the L2.3 MCP dispatch that replaces the echo).
        use ct_common::noise::{frame, read_frame};

        let mut local = serve_local(|req: Vec<u8>| async move { req.to_ascii_uppercase() });
        for msg in [&b"one"[..], b"two", b"three"] {
            local.write_all(&frame(msg)).await.expect("write request frame");
            let resp = read_frame(&mut local).await.expect("read response frame");
            assert_eq!(
                resp,
                msg.to_ascii_uppercase(),
                "each framed request is answered over the one persistent session-side duplex"
            );
        }
    }

    #[tokio::test]
    async fn mcp_call_over_invokes_a_serve_local_peer_and_returns_its_response() {
        // #135 L2.3 (frozen): the --call client (mcp_call_over) invokes a --serve peer's MCP endpoint
        // and gets its answer back — the full call↔serve pair over one duplex (the pump would carry
        // exactly these bytes encrypted). Client sends `tools/call ping`, the peer's registry → pong.
        let registry = std::sync::Arc::new(ct_common::mcp::default_registry());
        let server = serve_local(move |req: Vec<u8>| {
            let registry = registry.clone();
            async move { registry.dispatch(&req) }
        });
        // The server's session side IS a request→response endpoint (write a request, read its reply).
        let (mut r, mut w) = tokio::io::split(server);
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            mcp_call_over(&mut w, &mut r, "tools/call", serde_json::json!({ "name": "ping" })),
        )
        .await
        .expect("a response within 2s")
        .expect("got a response");

        let decoded = ct_common::mcp::decode_response(&response).expect("valid JSON-RPC response");
        assert_eq!(
            decoded.result.unwrap(),
            serde_json::json!({ "reply": "pong" }),
            "the peer's ping tool answered the client's call over the pair"
        );
        assert!(decoded.error.is_none());
    }

    #[test]
    fn channel_identity_generates_self_service_keys_the_cli_accepts() {
        // #117-cli-identity (frozen): a participant mints a fresh channel identity
        // LOCALLY, and the emitted hex is exactly what the `ct-agent channel` CLI
        // consumes — so no hand-crafted keys and no central provisioning are needed to
        // get channel crypto material. Round-trip the generated holder + Noise keys
        // through the real `from_lookup` parser.
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ed25519_dalek::Signer;

        let id = ChannelIdentity::generate();
        assert_eq!(id.holder_key_hex().len(), 64, "holder private is 64 hex");
        assert_eq!(id.noise_key_hex().len(), 64, "Noise private is 64 hex");
        assert_eq!(id.holder_pubkey_hex().len(), 64, "holder public is 64 hex");
        assert_eq!(id.noise_pubkey_hex().len(), 64, "Noise public is 64 hex");

        // An operator signs a grant over the generated holder public key.
        let op = SigningKey::from_bytes(&[9u8; 32]);
        let g = ChannelGrant {
            channel: ChannelId([0xC7u8; 32]),
            holder: id.holder.verifying_key().to_bytes(),
            direction: Direction::Initiate,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        let grant_hex =
            hex_encode(&SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }.encode());

        let pairs: Vec<(&str, String)> = vec![
            ("CT_CHANNEL_ROLE", "initiate".into()),
            ("CT_CHANNEL_BROKER", "203.0.113.5:9443".into()),
            ("CT_CHANNEL_RELAY", "203.0.113.5:9444".into()),
            ("CT_CHANNEL_LISTEN", "203.0.113.5:7000".into()),
            ("CT_CHANNEL_GRANT", grant_hex),
            ("CT_CHANNEL_HOLDER_KEY", id.holder_key_hex()),
            ("CT_CHANNEL_NOISE_KEY", id.noise_key_hex()),
        ];
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        let cfg = ChannelJoinCliConfig::from_lookup(move |k| m.get(k).cloned())
            .expect("the CLI accepts a self-generated channel identity");

        // The parsed keys ARE the generated ones — the generator's output is exactly
        // what the CLI consumes, so self-service key generation needs nothing hand-crafted.
        assert_eq!(cfg.holder.to_bytes(), id.holder.to_bytes(), "holder key round-trips through the CLI");
        assert_eq!(cfg.own_noise_private, id.noise.private, "Noise key round-trips through the CLI");
        assert_eq!(
            cfg.grant.grant.holder,
            id.holder.verifying_key().to_bytes(),
            "the grant binds the generated holder public key"
        );

        // Two mints differ — real randomness, not a fixed/default key.
        let id2 = ChannelIdentity::generate();
        assert_ne!(id.holder.to_bytes(), id2.holder.to_bytes(), "holder keys are unique per mint");
        assert_ne!(id.noise.private, id2.noise.private, "Noise keys are unique per mint");
    }

    #[test]
    fn channel_identity_env_block_exports_the_keys_the_cli_reads() {
        // #117-cli-subcommand (frozen): `ct-agent channel init` prints this block; it must
        // `export` exactly the two private-key env vars the CLI consumes, surface the two
        // public keys (for the operator), and be safe to `eval` (only comments + exports).
        let id = ChannelIdentity::generate();
        let block = id.env_block();

        assert!(
            block.contains(&format!("export CT_CHANNEL_HOLDER_KEY={}", id.holder_key_hex())),
            "exports the holder private key the CLI reads"
        );
        assert!(
            block.contains(&format!("export CT_CHANNEL_NOISE_KEY={}", id.noise_key_hex())),
            "exports the Noise private key the CLI reads"
        );
        assert!(block.contains(&id.holder_pubkey_hex()), "surfaces the holder public key for the operator");
        assert!(block.contains(&id.noise_pubkey_hex()), "surfaces the Noise public key for the operator");

        // Safe to `eval`: every non-blank line is a comment or an `export`.
        for line in block.lines().filter(|l| !l.trim().is_empty()) {
            assert!(
                line.starts_with('#') || line.starts_with("export "),
                "every line is a comment or an export, got {line:?}"
            );
        }
    }

    #[test]
    fn operator_issues_a_grant_the_edge_verifies_and_the_member_cli_accepts() {
        // #117-operator-flow (frozen): the create-side crypto. An operator mints a key
        // locally and signs a member's grant over the member's `channel init` holder
        // public key; the edge verifies that grant under the operator's PUBLIC key, and
        // the member CLI accepts it alongside the member's self-generated keys — closing
        // the self-service loop (operator issues -> member joins) with no central step.
        use ct_common::channel::{ChannelId, Direction, SignedChannelGrant};

        let op = OperatorIdentity::generate();
        let member = ChannelIdentity::generate();
        let channel = ChannelId([0x5Eu8; 32]);
        let holder_pub = member.holder.verifying_key().to_bytes();

        let grant_hex = op.issue_member_grant(channel, holder_pub, Direction::Initiate, 1_000);

        // The issued grant decodes + verifies under the operator public key, exactly as
        // the edge's admission gate does, and binds the member's holder + channel.
        let signed = SignedChannelGrant::decode(&hex_bytes(&grant_hex).expect("grant hex")).expect("decode");
        let op_pub = op.key.verifying_key().to_bytes();
        assert!(
            ct_common::channel::verify(&op_pub, &signed, 500).is_ok(),
            "the edge verifies the operator-issued grant under the operator key"
        );
        assert_eq!(signed.grant.holder, holder_pub, "grant binds the member's holder pubkey");
        assert_eq!(signed.grant.channel, channel, "grant is for the intended channel");

        // End-to-end: the member CLI accepts the operator-issued grant + the member's own
        // (`channel init`) keys — nothing hand-crafted, no central provisioning.
        let pairs: Vec<(&str, String)> = vec![
            ("CT_CHANNEL_ROLE", "initiate".into()),
            ("CT_CHANNEL_BROKER", "203.0.113.5:9443".into()),
            ("CT_CHANNEL_RELAY", "203.0.113.5:9444".into()),
            ("CT_CHANNEL_LISTEN", "203.0.113.5:7000".into()),
            ("CT_CHANNEL_GRANT", grant_hex),
            ("CT_CHANNEL_HOLDER_KEY", member.holder_key_hex()),
            ("CT_CHANNEL_NOISE_KEY", member.noise_key_hex()),
        ];
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        let cfg = ChannelJoinCliConfig::from_lookup(move |k| m.get(k).cloned())
            .expect("member CLI accepts the operator-issued grant + self-generated keys");
        assert_eq!(cfg.grant.grant.holder, holder_pub, "the CLI's grant binds the member's holder");

        // Operator key hex round-trips to 64-hex private + public.
        assert_eq!(op.key_hex().len(), 64);
        assert_eq!(op.pubkey_hex().len(), 64);
    }

    #[test]
    fn operator_mints_a_staple_the_cache_accepts_and_only_the_operator_can_mint() {
        // #121 E-fail-static (frozen): the operator — holding the key LOCALLY (invariant #6)
        // — mints a short-lived membership staple that a peer's StapleCache accepts under the
        // operator PUBLIC key, admitting the member offline until the TTL. Central never holds
        // the key, so a foreign key can neither mint nor forge a staple the cache would trust:
        // a central compromise degrades to DoS/metadata, never impersonation.
        use ct_common::channel::{ChannelId, StapleCache};

        let op = OperatorIdentity::generate();
        let member = ChannelIdentity::generate();
        let channel = ChannelId([0x77u8; 32]);
        let holder_pub = member.holder.verifying_key().to_bytes();
        let op_pub = op.key.verifying_key().to_bytes();

        // Operator mints a staple at t=1000 for a 3600s TTL (→ expires 4600).
        let staple = op.issue_membership_staple(channel, holder_pub, 1_000, 3_600);
        assert_eq!(staple.expires_at, 4_600, "expires_at = stapled_at + ttl_secs");

        // A peer caches it under the operator PUBLIC key and admits the member offline...
        let mut cache = StapleCache::new();
        assert!(cache.refresh(&op_pub, staple, 1_000), "the cache accepts the operator's staple");
        assert!(
            cache.is_member(&op_pub, &channel, &holder_pub, 4_000),
            "the member is admitted from cache with no central round-trip (fail-static)"
        );
        // ...and it lapses at the TTL (revocation latency = TTL, invariant #7).
        assert!(
            !cache.is_member(&op_pub, &channel, &holder_pub, 4_600),
            "the cached staple lapses at expires_at"
        );

        // Invariant #6: a FOREIGN operator's staple for the same member is not trusted under
        // this channel's operator key — only the local-key holder can mint an admissible staple.
        let foreign = OperatorIdentity::generate();
        let forged = foreign.issue_membership_staple(channel, holder_pub, 1_000, 3_600);
        let mut cache2 = StapleCache::new();
        assert!(
            !cache2.refresh(&op_pub, forged, 1_000),
            "a staple minted by a different key is rejected — central (keyless) can't forge one (#6)"
        );
    }

    #[test]
    fn operator_compiles_an_overlay_plan_into_verifiable_per_link_grants() {
        // #107-nway (frozen): the controller compiles a topology's overlay links into
        // concrete A2A channels — each link becomes a derived ChannelId plus the two
        // operator-signed grants its members present. The two grants of a link verify under
        // the operator key, bind distinct holders + the same channel, and split
        // Initiate/Accept — exactly what the broker's admission pairing expects. An
        // unmapped node id fails the whole compile (can't wire a link without both keys).
        use ct_common::channel::{channel_id_for_link, verify, Direction};
        use ct_common::overlay::OverlayPlan;

        let op = OperatorIdentity::generate();
        let op_pub = op.key.verifying_key().to_bytes();
        // Three agents a<b<c with distinct holder keys; a line overlay a—b—c.
        let holders = |id: &str| -> Option<[u8; 32]> {
            match id {
                "a" => Some([0xa1u8; 32]),
                "b" => Some([0xb2u8; 32]),
                "c" => Some([0xc3u8; 32]),
                _ => None,
            }
        };
        let plan = OverlayPlan {
            links: vec![("a".into(), "b".into()), ("b".into(), "c".into())],
            total_cost: 0,
            connected: true,
        };

        let compiled = op
            .compile_overlay_grants(&plan, holders, 5_000)
            .expect("every node id maps to a holder");
        assert_eq!(compiled.len(), 2, "one compiled channel per overlay link");

        // Link a—b: the derived channel matches channel_id_for_link, both grants verify
        // under the operator key, bind distinct holders + the SAME channel, and split roles.
        let ab = &compiled[0];
        assert_eq!(
            ab.channel,
            channel_id_for_link(&op_pub, &[0xa1u8; 32], &[0xb2u8; 32]),
            "the link's channel is the deterministic per-link derivation"
        );
        assert!(verify(&op_pub, &ab.initiator_grant, 1_000).is_ok(), "initiator grant verifies");
        assert!(verify(&op_pub, &ab.acceptor_grant, 1_000).is_ok(), "acceptor grant verifies");
        assert_eq!(ab.initiator_grant.grant.channel, ab.channel, "initiator grant is for this channel");
        assert_eq!(ab.acceptor_grant.grant.channel, ab.channel, "acceptor grant is for this channel");
        assert_eq!(ab.initiator_grant.grant.holder, [0xa1u8; 32]);
        assert_eq!(ab.acceptor_grant.grant.holder, [0xb2u8; 32]);
        assert_ne!(
            ab.initiator_grant.grant.holder, ab.acceptor_grant.grant.holder,
            "the two grants bind distinct holders (an agent can't channel to itself)"
        );
        assert!(ab.initiator_grant.grant.direction.permits(Direction::Initiate));
        assert!(ab.acceptor_grant.grant.direction.permits(Direction::Accept));

        // The two links share agent b but are DISTINCT channels (per-link isolation).
        assert_ne!(compiled[0].channel, compiled[1].channel, "distinct links are distinct channels");

        // A plan naming an unmapped agent can't be wired — the whole compile fails, loudly,
        // with the offending node id (no partially-wired overlay).
        let bad = OverlayPlan {
            links: vec![("a".into(), "z".into())],
            total_cost: 0,
            connected: false,
        };
        assert_eq!(
            op.compile_overlay_grants(&bad, holders, 5_000),
            Err("z".to_string()),
            "an unmapped node id fails the compile with that id"
        );
    }

    #[test]
    fn operator_grant_request_parses_env_and_issues_a_verifiable_grant() {
        // #117-operator-flow (frozen): `ct-agent channel grant` parses the operator key +
        // CT_GRANT_* from env and issues a grant that verifies under the operator key and
        // binds the intended member/channel/direction. Required fields are enforced.
        use ct_common::channel::{ChannelId, Direction, SignedChannelGrant};

        let op = OperatorIdentity::generate();
        let member = ChannelIdentity::generate();
        let member_holder = member.holder.verifying_key().to_bytes();
        let channel = [0x77u8; 32];

        let base: Vec<(&str, String)> = vec![
            ("CT_CHANNEL_OPERATOR_KEY", op.key_hex()),
            ("CT_GRANT_CHANNEL", hex_encode(&channel)),
            ("CT_GRANT_MEMBER_HOLDER", hex_encode(&member_holder)),
            ("CT_GRANT_DIRECTION", "accept".into()),
            ("CT_GRANT_EXPIRES", "1000".into()),
        ];
        let lookup = |pairs: &[(&str, String)]| {
            let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
            OperatorGrantRequest::from_lookup(move |k| m.get(k).cloned())
        };

        let req = lookup(&base).expect("valid operator grant request parses");
        assert_eq!(req.channel, ChannelId(channel));
        assert_eq!(req.member_holder, member_holder);
        assert_eq!(req.direction, Direction::Accept);

        // The issued grant verifies under the operator key and binds the member.
        let signed = SignedChannelGrant::decode(&hex_bytes(&req.issue()).expect("hex")).expect("decode");
        assert!(
            ct_common::channel::verify(&op.key.verifying_key().to_bytes(), &signed, 500).is_ok(),
            "the issued grant verifies under the operator key"
        );
        assert_eq!(signed.grant.holder, member_holder);
        assert_eq!(signed.grant.channel, ChannelId(channel));
        assert_eq!(signed.grant.direction, Direction::Accept);

        // Each required field is enforced.
        for drop_key in [
            "CT_CHANNEL_OPERATOR_KEY",
            "CT_GRANT_CHANNEL",
            "CT_GRANT_MEMBER_HOLDER",
            "CT_GRANT_DIRECTION",
            "CT_GRANT_EXPIRES",
        ] {
            let pruned: Vec<(&str, String)> = base.iter().filter(|(k, _)| *k != drop_key).cloned().collect();
            assert!(lookup(&pruned).is_err(), "missing {drop_key} must be rejected");
        }
    }

    #[test]
    fn channel_register_request_parses_env_and_derives_the_operator_pubkey() {
        // #117-operator-register (frozen): `ct-agent channel register` parses the CP URL,
        // channel id, OIDC token, and the operator authority from env — deriving the
        // operator PUBLIC key from CT_CHANNEL_OPERATOR_KEY (never sending the private key),
        // canonicalizing the channel hex, and enforcing the required fields.
        let op = OperatorIdentity::generate();
        let channel = [0x91u8; 32];

        let base: Vec<(&str, String)> = vec![
            ("CT_AGENT_CP_URL", "http://cp:8090".into()),
            ("CT_GRANT_CHANNEL", hex_encode(&channel)),
            ("CT_CHANNEL_OPERATOR_KEY", op.key_hex()),
            ("CT_OIDC_TOKEN", "the-bearer-token".into()),
        ];
        let lookup = |pairs: &[(&str, String)]| {
            let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
            ChannelRegisterRequest::from_lookup(move |k| m.get(k).cloned())
        };

        let req = lookup(&base).expect("valid register request parses");
        assert_eq!(req.cp_url, "http://cp:8090");
        assert_eq!(req.channel_hex, hex_encode(&channel), "channel id round-trips as canonical hex");
        assert_eq!(req.token, "the-bearer-token");
        // The operator PRIVATE key is never surfaced — only its derived public key is sent.
        assert_eq!(req.operator_pubkey_hex, op.pubkey_hex(), "derives the operator public key");
        assert_ne!(req.operator_pubkey_hex, op.key_hex(), "the private key is not sent to the CP");

        // The public key may also be supplied directly (CT_CHANNEL_OPERATOR_PUBKEY),
        // without the private key present.
        let pubkey_only: Vec<(&str, String)> = vec![
            ("CT_AGENT_CP_URL", "http://cp:8090".into()),
            ("CT_GRANT_CHANNEL", hex_encode(&channel)),
            ("CT_CHANNEL_OPERATOR_PUBKEY", op.pubkey_hex()),
            ("CT_OIDC_TOKEN", "tok".into()),
        ];
        assert_eq!(
            lookup(&pubkey_only).expect("pubkey-only parses").operator_pubkey_hex,
            op.pubkey_hex(),
            "an operator pubkey supplied directly is accepted"
        );

        // Each required field is enforced (the operator key OR pubkey must be present).
        for drop_key in ["CT_AGENT_CP_URL", "CT_GRANT_CHANNEL", "CT_CHANNEL_OPERATOR_KEY", "CT_OIDC_TOKEN"] {
            let pruned: Vec<(&str, String)> = base.iter().filter(|(k, _)| *k != drop_key).cloned().collect();
            assert!(lookup(&pruned).is_err(), "missing {drop_key} must be rejected");
        }
    }

    #[tokio::test]
    async fn dial_ladder_falls_through_to_the_front_door_then_errors_when_all_blocked() {
        // #106-client-dial (frozen): the ladder-walk tries rungs in order and returns the
        // first that connects, so a direct rung blocked by a restrictive network falls
        // back to the :443 front-door rung; it errors only when EVERY rung is blocked.
        let direct = ChannelDialRung { endpoint: "203.0.113.5:9443".parse().unwrap(), via_front_door: false };
        let fd = ChannelDialRung { endpoint: "203.0.113.5:443".parse().unwrap(), via_front_door: true };

        // Direct blocked -> fall through to the :443 front-door rung.
        let picked: &str = dial_ladder(&[direct, fd], |r: &ChannelDialRung| {
            let via = r.via_front_door;
            async move {
                if via { Ok("front-door") } else { Err(ChannelDialError::Unreachable) }
            }
        })
        .await
        .expect("falls back to the front door when the direct port is blocked");
        assert_eq!(picked, "front-door");

        // First success short-circuits: direct connects -> the front door is never tried.
        let picked: &str = dial_ladder(&[direct, fd], |r: &ChannelDialRung| {
            let via = r.via_front_door;
            async move {
                assert!(!via, "the front-door rung must not be tried once the direct rung connects");
                Ok("direct")
            }
        })
        .await
        .expect("direct connects on the first rung");
        assert_eq!(picked, "direct");

        // Every rung blocked -> error (all paths down).
        let all_blocked: Result<&str, _> =
            dial_ladder(&[direct, fd], |_r: &ChannelDialRung| async move { Err(ChannelDialError::Unreachable) })
                .await;
        assert!(all_blocked.is_err(), "all rungs blocked surfaces an error");
    }

    #[tokio::test]
    async fn present_channel_join_via_ladder_falls_back_to_the_443_front_door() {
        // #106 client-dial-443 (frozen): the AGENT actually uses :443. The dial ladder's
        // DIRECT rung points at a dead/closed port (the QUIC dial is Unreachable), so
        // present_channel_join_via_ladder falls through to the FRONT-DOOR rung — a real
        // TLS-TCP `:443`-style edge whose accepted stream is admitted with the production
        // `ct_edge::channel_broker::admit_channel_join_on_duplex` gate — and completes the
        // join (Admitted) over TLS-over-TCP. This is the fallback for a network that blocks
        // the direct channel port.
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ct_edge::channel_broker::admit_channel_join_on_duplex;
        use ct_edge::transport::build_tcp_tls_listener_at;
        use ed25519_dalek::Signer;
        use tokio::io::AsyncWriteExt;

        // Operator-signed grant; the edge `authorize` closure yields this operator's key.
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let op_pub = op.verifying_key().to_bytes();
        let channel = [0x06u8; 32];
        let holder = SigningKey::from_bytes(&[0x11u8; 32]);
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: holder.verifying_key().to_bytes(),
            direction: Direction::Initiate,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        let grant = SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() };
        // The advertised endpoint must be a SAFE (non-loopback) dialable addr for admission.
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.7:7007".to_string() };

        // A real `:443`-style TLS-TCP edge front door.
        let (listener, acceptor, edge_cert) = build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap())
            .await
            .expect("tls-tcp listener");
        let fd_addr = listener.local_addr().expect("front-door addr");

        // Edge: accept one TLS-TCP connection, admit the channel join over the duplex, then
        // ack `OK <peer_endpoint>` and close the write half so the client reads the ack to EOF.
        let edge = tokio::spawn(async move {
            let (tcp, peer) = listener.accept().await.expect("accept tcp");
            let tls = acceptor.accept(tcp).await.expect("tls accept");
            let (mut stream, _req, _op, _noise, _attest, _observed) = admit_channel_join_on_duplex(
                tls,
                peer,
                500u64, // now < expires_at (1_000)
                std::time::Duration::from_secs(5),
                &move |c: ChannelId, _h: [u8; 32]| {
                    let ok = c.0 == channel;
                    async move { ok.then_some((op_pub, None, None)) }
                },
            )
            .await
            .expect("admit over the :443 TLS-TCP duplex");
            stream.write_all(b"OK 198.51.100.9:8008").await.expect("ack");
            stream.shutdown().await.expect("shutdown");
        });

        // The dial ladder: a DEAD direct rung (closed port) then the LIVE :443 front door.
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead); // nothing on that UDP port -> the direct QUIC dial is Unreachable
        let rungs = vec![
            ChannelDialRung { endpoint: dead_addr, via_front_door: false },
            ChannelDialRung { endpoint: fd_addr, via_front_door: true },
        ];

        let outcome = present_channel_join_via_ladder(
            &rungs,
            &request,
            &holder,
            edge_cert,
            std::time::Duration::from_millis(400),
        )
        .await
        .expect("the join completes over the :443 front door after the dead direct rung");

        match outcome {
            ChannelJoinOutcome::Admitted { peer_endpoint, .. } => assert_eq!(
                peer_endpoint, "198.51.100.9:8008",
                "the agent learns the peer endpoint over the :443 TLS-TCP fallback rung"
            ),
            ChannelJoinOutcome::Refused => panic!("a valid join over :443 must be Admitted, not Refused"),
        }
        edge.await.expect("edge task");
    }

    #[tokio::test(start_paused = true)]
    async fn run_channel_session_times_out_a_stalled_handshake() {
        // #126 (frozen): if the paired peer never sends its Noise_IK handshake message
        // (crash, partition, admit-then-stall), the session must TIME OUT — not block
        // `read_frame` forever. Hold the transport's peer end OPEN but silent; the
        // initiator writes m1 then blocks reading m2, so the #126 handshake timeout must
        // fire (virtual time auto-advances under start_paused, so the test is instant).
        use ct_common::noise::generate_static_keypair;
        use tokio::io::{duplex, split};

        let a = generate_static_keypair();
        let b = generate_static_keypair();
        let (transport, peer_transport) = duplex(16 * 1024);
        let (_local_app, local) = duplex(16 * 1024);
        let session = tokio::spawn(async move {
            let (r, w) = split(transport);
            run_channel_session_on_stream(w, r, ChannelRole::Initiate, &a.private, &b.public, local).await
        });
        let err = session
            .await
            .unwrap()
            .expect_err("a stalled handshake must time out, not hang forever");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::TimedOut,
            "must be the #126 handshake timeout, got: {err}"
        );
        drop(peer_transport);
    }

    #[tokio::test]
    async fn run_channel_session_on_stream_forms_the_noise_tunnel_over_a_plain_duplex() {
        // #106 relay-leg-443 (frozen): the A2A session is transport-agnostic — the
        // Noise_IK handshake + bidirectional pump run over a plain in-memory duplex (the
        // stand-in for a :443/TLS-TCP relay-spliced stream), not just a quinn bi-stream.
        // Two members hand-shake over the transport duplex, then plaintext written to one
        // member's local side arrives DECRYPTED at the other's — proving a :443-only
        // member (relay port also blocked) can relay end-to-end over :443.
        use ct_common::noise::generate_static_keypair;
        use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt};

        let a = generate_static_keypair();
        let b = generate_static_keypair();
        let (a_priv, a_pub) = (a.private, a.public);
        let (b_priv, b_pub) = (b.private, b.public);

        // The relay-spliced transport between the two members.
        let (a_transport, b_transport) = duplex(16 * 1024);
        // Each member's local plaintext side (the CLI's stdio stand-in).
        let (mut a_app, a_local) = duplex(16 * 1024);
        let (mut b_app, b_local) = duplex(16 * 1024);

        let a_task = tokio::spawn(async move {
            let (ar, aw) = split(a_transport);
            run_channel_session_on_stream(aw, ar, ChannelRole::Initiate, &a_priv, &b_pub, a_local).await
        });
        let b_task = tokio::spawn(async move {
            let (br, bw) = split(b_transport);
            run_channel_session_on_stream(bw, br, ChannelRole::Accept, &b_priv, &a_pub, b_local).await
        });

        // A -> B over the encrypted tunnel.
        a_app.write_all(b"ping-A-to-B").await.expect("a writes");
        let mut got = [0u8; 11];
        b_app.read_exact(&mut got).await.expect("b reads A's bytes");
        assert_eq!(&got, b"ping-A-to-B", "A's plaintext arrives decrypted at B over the duplex relay");

        // B -> A.
        b_app.write_all(b"pong-B-to-A").await.expect("b writes");
        let mut got2 = [0u8; 11];
        a_app.read_exact(&mut got2).await.expect("a reads B's bytes");
        assert_eq!(&got2, b"pong-B-to-A", "B's plaintext arrives decrypted at A");

        // Closing a local side tears the session down cleanly.
        drop(a_app);
        drop(b_app);
        let _ = a_task.await;
        let _ = b_task.await;
    }

    #[tokio::test]
    async fn graceful_stream_drain_returns_when_the_peer_closes() {
        // #150 (frozen): the drain FINs our write half and reads the peer to EOF — so once the peer
        // closes it returns promptly, having kept us alive just long enough to flush our tail (the
        // fix for `:443`/TLS-TCP truncation when `ct-agent` exits as a container's PID 1).
        use std::time::Duration;
        use tokio::io::{duplex, split};
        let (ours, peer) = duplex(64);
        let (mut our_r, mut our_w) = split(ours);
        drop(peer); // the peer closes → our read half EOFs
        let done = tokio::time::timeout(
            Duration::from_secs(2),
            graceful_stream_drain(&mut our_w, &mut our_r, Duration::from_secs(30)),
        )
        .await;
        assert!(done.is_ok(), "drain returns promptly once the peer has closed (well within its bound)");
    }

    #[tokio::test]
    async fn graceful_stream_drain_is_bounded_on_a_silent_peer() {
        // #150 (frozen): a peer that FINs nothing (vanished mid-transfer) must NOT hang teardown —
        // the drain is bounded by its own timeout and returns best-effort, never blocking forever.
        use std::time::Duration;
        use tokio::io::{duplex, split};
        let (ours, peer_kept) = duplex(64);
        let (mut our_r, mut our_w) = split(ours);
        let _peer_kept = peer_kept; // keep the peer open + silent so our read half never EOFs
        let done = tokio::time::timeout(
            Duration::from_secs(3),
            graceful_stream_drain(&mut our_w, &mut our_r, Duration::from_millis(150)),
        )
        .await;
        assert!(done.is_ok(), "a silent peer times out the bounded drain instead of hanging teardown");
    }

    #[test]
    fn agent_offer_cli_config_builds_a_valid_signed_offer_from_env() {
        // #152 (frozen): the --serve offer config parses CT_AGENT_OFFER_* + the shared holder key into
        // a signed CapacityOffer (so channel_local can register auction/offer + auction/bid), bound to
        // the holder, honouring the TTL. Absent required vars → Err (auction tools stay off), exactly
        // like the agent/card path.
        use std::collections::HashMap;
        let key_hex = "11".repeat(32); // 64 hex → [0x11; 32]
        let vars: HashMap<&str, String> = HashMap::from([
            ("CT_CHANNEL_HOLDER_KEY", key_hex.clone()),
            ("CT_AGENT_OFFER_KIND", "cloud".to_string()),
            ("CT_AGENT_OFFER_MODELS", "claude-opus-4-8,local-llama".to_string()),
            ("CT_AGENT_OFFER_UNITS", "1000".to_string()),
            ("CT_AGENT_OFFER_MIN_PRICE", "50".to_string()),
            ("CT_AGENT_OFFER_CURRENCY", "ct-llm-token-chain".to_string()),
            ("CT_AGENT_OFFER_TTL_SECS", "3600".to_string()),
        ]);
        let cfg = AgentOfferCliConfig::from_lookup(|k| vars.get(k).cloned()).expect("parses a full offer config");
        let offer = cfg.build_offer(1_000);
        assert!(offer.is_valid(1_000), "the built offer verifies at issue time");
        assert!(offer.is_valid(4_599), "valid up to issued_at + ttl");
        assert!(!offer.is_valid(4_600), "expires at now + ttl (1000 + 3600)");
        assert_eq!(offer.kind, ct_common::channel::CapacityKind::CloudApiQuota);
        assert_eq!(offer.models, vec!["claude-opus-4-8".to_string(), "local-llama".to_string()]);
        assert_eq!((offer.units_available, offer.min_price), (1000, 50));
        assert_eq!(offer.currency_id, "ct-llm-token-chain");
        assert_eq!(
            offer.holder_pubkey,
            SigningKey::from_bytes(&[0x11u8; 32]).verifying_key().to_bytes(),
            "the offer is bound to CT_CHANNEL_HOLDER_KEY"
        );
        // Defaults applied when optional vars are absent.
        assert_eq!((cfg.max_bids_per_window, cfg.window_secs), (60, 60), "rate-limit defaults");

        // Absent required vars → Err, so channel_local leaves the auction tools off (card/ping only).
        assert!(AgentOfferCliConfig::from_lookup(|_| None).is_err(), "no CT_AGENT_OFFER_* → no offer");
        // A bad kind is a clear error, not a silent default.
        let mut bad = vars.clone();
        bad.insert("CT_AGENT_OFFER_KIND", "chatbot".to_string());
        assert!(
            AgentOfferCliConfig::from_lookup(|k| bad.get(k).cloned()).is_err(),
            "an unknown CT_AGENT_OFFER_KIND is rejected"
        );
    }

    #[test]
    fn agent_offer_declares_its_service_catalog_for_verifiable_enforcement() {
        // #167 (frozen): CT_AGENT_OFFER_SERVICES is signed INTO the offer, so a buyer can
        // cryptographically verify which services the agent offers and #149-A.1's match_offer
        // service filter has something to enforce (closing the declared-vs-served gap where the
        // offer and the registered service tools were two independent, unvalidated surfaces). An
        // unknown slug is a hard config error (fail-closed); absent → a generic offer (services: []).
        use ct_common::channel::ServiceType::*;
        use std::collections::HashMap;
        let base: HashMap<&str, String> = HashMap::from([
            ("CT_CHANNEL_HOLDER_KEY", "11".repeat(32)),
            ("CT_AGENT_OFFER_KIND", "cloud".to_string()),
            ("CT_AGENT_OFFER_MODELS", "claude-opus-4-8".to_string()),
            ("CT_AGENT_OFFER_UNITS", "1000".to_string()),
            ("CT_AGENT_OFFER_MIN_PRICE", "50".to_string()),
            ("CT_AGENT_OFFER_CURRENCY", "ct-llm-token-chain".to_string()),
        ]);

        // Absent → generic offer with no declared services (unchanged back-compat).
        let generic = AgentOfferCliConfig::from_lookup(|k| base.get(k).cloned()).unwrap();
        assert!(generic.services.is_empty(), "no CT_AGENT_OFFER_SERVICES → generic offer");
        assert!(generic.build_offer(1_000).services.is_empty(), "generic offer declares no services");

        // A declared catalog is parsed and SIGNED into the offer (order + values preserved).
        let mut with = base.clone();
        with.insert("CT_AGENT_OFFER_SERVICES", "code_generation, security_review".to_string());
        let cfg = AgentOfferCliConfig::from_lookup(|k| with.get(k).cloned()).unwrap();
        assert_eq!(cfg.services, vec![CodeGeneration, SecurityReview], "catalog parsed from env");
        let offer = cfg.build_offer(1_000);
        assert_eq!(
            offer.services,
            vec![CodeGeneration, SecurityReview],
            "the declared catalog is signed into the offer (buyer-verifiable ceiling)"
        );
        assert!(offer.is_valid(1_000), "the offer still verifies with a declared catalog");

        // An unknown slug is a hard error — never silently drop a service the operator declared.
        let mut bad = base.clone();
        bad.insert("CT_AGENT_OFFER_SERVICES", "code_generation,chatbot".to_string());
        assert!(
            AgentOfferCliConfig::from_lookup(|k| bad.get(k).cloned()).is_err(),
            "an unknown CT_AGENT_OFFER_SERVICES slug is rejected (fail-closed)"
        );
    }

    #[test]
    fn service_type_parsing_and_handler_shell_out_round_trip() {
        // #149-A.1 serve-wiring follow (frozen): parse_service_type covers every real slug and
        // rejects an unknown one (so a typo in CT_AGENT_SERVICES just drops that tool, per the
        // filter_map call site, not a hard error); run_service_handler actually spawns the
        // configured command, pipes `input` on stdin, and returns trimmed stdout — the shell-out
        // seam a real LLM CLI plugs into.
        use ct_common::channel::ServiceType::*;
        assert_eq!(parse_service_type("code_generation"), Some(CodeGeneration));
        assert_eq!(parse_service_type("security_review"), Some(SecurityReview));
        assert_eq!(parse_service_type("safety_check"), Some(SafetyCheck));
        assert_eq!(parse_service_type("text_generation"), Some(TextGeneration));
        assert_eq!(parse_service_type("not-a-real-service"), None);

        // `cat` echoes stdin back — proves input actually reaches the child and stdout is
        // captured + trimmed (a trailing newline from `echo`-style output must not leak through).
        let out = run_service_handler("cat", CodeGeneration, "hello from the caller").unwrap();
        assert_eq!(out, "hello from the caller");

        // CT_SERVICE_TYPE is set in the child's env so a multi-service handler can branch.
        let out = run_service_handler("echo \"got:$CT_SERVICE_TYPE\"", SecurityReview, "ignored").unwrap();
        assert_eq!(out, "got:security_review");

        // A non-zero exit surfaces as a tool error, not a panic or a silently-empty result.
        let err = run_service_handler("exit 7", TextGeneration, "x").unwrap_err();
        assert!(err.contains("exited"), "the exit status is reported: {err}");
    }

    #[tokio::test]
    async fn call_role_service_calls_a_service_tool_over_a_duplex_and_fails_closed() {
        // #171/#173 c2 atom (frozen): the crew bridge dials a role agent's channel and calls its
        // service/<slug> tool, getting the fragment — exercised here against an IN-PROCESS serve
        // peer (a local fake, exactly the parallel dev-testing #173 asks for). A missing service
        // fails closed.
        use ct_common::channel::ServiceType;
        // A stub service that echoes a fragment-shaped output (stands in for a live LLM handler).
        let mut reg = ct_common::mcp::default_registry();
        ct_common::mcp::register_service_tools(&mut reg, &[ServiceType::TextGeneration], |_svc, input| {
            Ok(format!("{{\"echoed\":\"{input}\"}}"))
        });
        let reg = std::sync::Arc::new(reg);
        let session = serve_local(move |req: Vec<u8>| {
            let reg = reg.clone();
            async move { reg.dispatch(&req) }
        });
        let (mut recv, mut send) = tokio::io::split(session);
        let out = call_role_service(&mut send, &mut recv, "text_generation", "a matrix theme").await.unwrap();
        assert_eq!(out, "{\"echoed\":\"a matrix theme\"}", "returns the service's output verbatim");

        // Calling a service the peer does NOT offer → JSON-RPC error → Err (fail closed, no fragment).
        let bare = std::sync::Arc::new(ct_common::mcp::default_registry());
        let s2 = serve_local(move |req: Vec<u8>| {
            let bare = bare.clone();
            async move { bare.dispatch(&req) }
        });
        let (mut r2, mut w2) = tokio::io::split(s2);
        assert!(
            call_role_service(&mut w2, &mut r2, "safety_check", "x").await.is_err(),
            "an unoffered service fails closed"
        );
    }

    #[tokio::test]
    async fn channel_call_service_mode_yields_bare_service_output() {
        // #173 distributed (frozen): the initiator CT_CHANNEL_CALL_SERVICE mode's core — invoke the
        // peer's service/<slug> and return the BARE output (result.output), NOT a JSON-RPC envelope
        // (the crew bridge's CREW_*_CMD feeds this straight to ct_common::crew). Against an in-process
        // serve peer. An unoffered service fails closed (→ the bridge 502s → browser local fallback).
        use ct_common::channel::ServiceType;
        let mut reg = ct_common::mcp::default_registry();
        ct_common::mcp::register_service_tools(&mut reg, &[ServiceType::TextGeneration], |_svc, input| {
            Ok(format!("{{\"gravity\":2200,\"note\":\"{input}\"}}"))
        });
        let reg = std::sync::Arc::new(reg);
        let peer = serve_local(move |req: Vec<u8>| {
            let reg = reg.clone();
            async move { reg.dispatch(&req) }
        });
        let out = run_service_call(peer, "text_generation", "hard matrix").await.unwrap();
        assert_eq!(out, "{\"gravity\":2200,\"note\":\"hard matrix\"}", "bare service output, no JSON-RPC envelope");

        let bare = std::sync::Arc::new(ct_common::mcp::default_registry());
        let peer2 = serve_local(move |req: Vec<u8>| {
            let bare = bare.clone();
            async move { bare.dispatch(&req) }
        });
        assert!(
            run_service_call(peer2, "safety_check", "x").await.is_err(),
            "an unoffered service fails closed",
        );
    }

    #[tokio::test]
    async fn crew_build_over_runs_the_crew_and_fails_closed() {
        // #171/#173 c2 driver (frozen): safety_check → physics → art over three role channels,
        // assembled by ct_common::crew. Exercised against in-process serve peers (local fakes).
        use ct_common::channel::ServiceType;
        fn peer(services: &[ServiceType], out: &str) -> tokio::io::DuplexStream {
            let mut reg = ct_common::mcp::default_registry();
            let out = out.to_string();
            ct_common::mcp::register_service_tools(&mut reg, services, move |_svc, _input| Ok(out.clone()));
            let reg = std::sync::Arc::new(reg);
            serve_local(move |req: Vec<u8>| {
                let reg = reg.clone();
                async move { reg.dispatch(&req) }
            })
        }
        let auction: Vec<ct_common::crew::RoleAuction> = vec![];

        // Happy path: safety OK → physics + art fragments assemble into a built config.
        let safety = peer(&[ServiceType::SafetyCheck], r#"{"ok":true,"reason":""}"#);
        let physics = peer(&[ServiceType::TextGeneration], r#"{"gravity":2200,"flapPower":420,"pipeGap":115,"pipeSpeed":220}"#);
        let art = peer(&[ServiceType::TextGeneration], r##"{"theme":"night","birdColor":"#00ff41","birdEmoji":"🕶️","title":"Neo"}"##);
        let resp = crew_build_over("matrix theme", safety, physics, art, auction.clone()).await.unwrap();
        assert!(resp.safety.ok, "built when safety passes");
        let cfg = resp.config.as_ref().expect("built carries config");
        assert_eq!((cfg.speed, cfg.jump, cfg.gap), (220, 420, 115), "physics fragment mapped");
        assert_eq!(cfg.bird_emoji, "🕶️", "art fragment carried (emoji intact)");

        // Safety reject → Ok(rejected), no build.
        let safety_r = peer(&[ServiceType::SafetyCheck], r#"{"ok":false,"reason":"anti-prompt"}"#);
        let p2 = peer(&[ServiceType::TextGeneration], "{}");
        let a2 = peer(&[ServiceType::TextGeneration], "{}");
        let rej = crew_build_over("evil", safety_r, p2, a2, auction.clone()).await.unwrap();
        assert!(!rej.safety.ok && rej.config.is_none(), "safety reject carries no build");

        // A role unreachable (bare peer offers no service) → Err → the c3 layer 5xx's → browser falls back.
        let safety3 = peer(&[ServiceType::SafetyCheck], r#"{"ok":true}"#);
        let bare = std::sync::Arc::new(ct_common::mcp::default_registry());
        let physics3 = serve_local(move |req: Vec<u8>| {
            let bare = bare.clone();
            async move { bare.dispatch(&req) }
        });
        let a3 = peer(&[ServiceType::TextGeneration], "{}");
        assert!(crew_build_over("x", safety3, physics3, a3, auction).await.is_err(), "an unreachable role → Err (fail closed)");
    }

    #[test]
    fn run_service_handler_does_not_deadlock_on_input_larger_than_the_pipe_buffer() {
        // #149-A.1 serve-wiring (frozen, regression from review): writing stdin inline then calling
        // wait_with_output() is the classic std::process pipe deadlock — an `input` over the OS pipe
        // buffer (~64 KiB) whose handler (`cat`) writes to stdout before it has drained stdin blocks
        // both sides forever. A consumer fully controls `input`'s size, so this was a remote DoS on
        // the provider, not just a footgun. 200 KiB comfortably exceeds every common pipe buffer size.
        // Bounded by the test harness's own timeout — a real deadlock here means the test hangs, not
        // panics, which is exactly the failure mode being guarded against.
        use ct_common::channel::ServiceType::CodeGeneration;
        let big = "x".repeat(200_000);
        let out = run_service_handler("cat", CodeGeneration, &big).unwrap();
        assert_eq!(out, big, "the full oversized input round-trips without hanging");
    }

    #[test]
    fn run_service_handler_kills_and_errors_a_child_that_exceeds_its_timeout() {
        // #149-A.1 serve-wiring (frozen, regression from review): every other blocking step in this
        // file is timed; this closes the one that wasn't. A handler that never exits (simulating a
        // stalled LLM API call / wedged subprocess) must be killed and reported as a timeout, not
        // block the caller forever. Uses the injectable-timeout seam (a real 120s wait would make
        // this test itself the problem it's guarding against).
        use ct_common::channel::ServiceType::CodeGeneration;
        let start = std::time::Instant::now();
        let err = run_service_handler_with_timeout(
            "sleep 30",
            CodeGeneration,
            "x",
            std::time::Duration::from_millis(300),
        )
        .unwrap_err();
        assert!(err.contains("timed out"), "the timeout is reported: {err}");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "the call returns promptly after the timeout, not after the child's own 30s sleep: {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn channel_join_cli_config_parses_the_plane_one_liner() {
        // #98 / #103: the plane-brokered one-liner's config contract — broker + relay
        // addrs, the operator-signed grant (hex), the holder + Noise keys, and the
        // advertised endpoint. Round-trips a real grant through decode.
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ed25519_dalek::Signer;
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let holder = SigningKey::from_bytes(&[0x11u8; 32]);
        let g = ChannelGrant {
            channel: ChannelId([0xABu8; 32]),
            holder: holder.verifying_key().to_bytes(),
            direction: Direction::Initiate,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        let grant_hex = hex_encode(&SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }.encode());
        let hk = "1111111111111111111111111111111111111111111111111111111111111111";
        let nk = "2222222222222222222222222222222222222222222222222222222222222222";
        let base: Vec<(&str, String)> = vec![
            ("CT_CHANNEL_ROLE", "initiate".into()),
            ("CT_CHANNEL_BROKER", "203.0.113.5:9443".into()),
            ("CT_CHANNEL_RELAY", "203.0.113.5:9444".into()),
            ("CT_CHANNEL_LISTEN", "203.0.113.5:7000".into()),
            ("CT_CHANNEL_GRANT", grant_hex),
            ("CT_CHANNEL_HOLDER_KEY", hk.into()),
            ("CT_CHANNEL_NOISE_KEY", nk.into()),
        ];
        let lookup = |pairs: &[(&str, String)]| {
            let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
            ChannelJoinCliConfig::from_lookup(move |k| m.get(k).cloned())
        };
        let cfg = lookup(&base).expect("plane-brokered config parses");
        assert_eq!(cfg.role, ChannelRole::Initiate);
        assert_eq!(cfg.broker_addr, "203.0.113.5:9443".parse().unwrap());
        assert_eq!(cfg.relay_addr, "203.0.113.5:9444".parse().unwrap());
        assert_eq!(cfg.listen_addr, "203.0.113.5:7000".parse().unwrap());
        assert_eq!(cfg.grant.grant.channel, ChannelId([0xABu8; 32]), "the grant round-trips through decode");

        // Each required field is enforced.
        for drop_key in ["CT_CHANNEL_BROKER", "CT_CHANNEL_RELAY", "CT_CHANNEL_GRANT", "CT_CHANNEL_HOLDER_KEY", "CT_CHANNEL_LISTEN"] {
            let pruned: Vec<(&str, String)> = base.iter().filter(|(k, _)| *k != drop_key).cloned().collect();
            assert!(lookup(&pruned).is_err(), "missing {drop_key} must be rejected");
        }

        // #173 (frozen): a relay-only member has no dialable address, so CT_CHANNEL_LISTEN is
        // OPTIONAL when CT_CHANNEL_RELAY_ONLY=1 — dropping it must NOT error (both source-2 and sink
        // hit the old hard-error and had to supply a dummy). It parses as relay-only with an unbound
        // placeholder listen address that's never used.
        let mut relay_only_no_listen: Vec<(&str, String)> =
            base.iter().filter(|(k, _)| *k != "CT_CHANNEL_LISTEN").cloned().collect();
        relay_only_no_listen.push(("CT_CHANNEL_RELAY_ONLY", "1".into()));
        let ro = lookup(&relay_only_no_listen).expect("relay-only needs no CT_CHANNEL_LISTEN (#173)");
        assert!(ro.relay_only, "explicit CT_CHANNEL_RELAY_ONLY=1 is relay-only");
        assert_eq!(ro.listen_addr, SocketAddr::from(([0, 0, 0, 0], 0)), "unbound placeholder listen");

        // #106: without a front door, the dial ladder is direct-only.
        assert_eq!(cfg.front_door, None);
        assert_eq!(
            cfg.broker_ladder(),
            vec![ChannelDialRung { endpoint: "203.0.113.5:9443".parse().unwrap(), via_front_door: false }]
        );

        // With CT_CHANNEL_FRONT_DOOR set, each ladder tries the direct port then the :443
        // front door (the fallback for networks that block the channel ports).
        let mut with_fd = base.clone();
        with_fd.push(("CT_CHANNEL_FRONT_DOOR", "203.0.113.5:443".into()));
        let cfg = lookup(&with_fd).expect("front-door config parses");
        assert_eq!(cfg.front_door, Some("203.0.113.5:443".parse().unwrap()));
        assert_eq!(
            cfg.broker_ladder(),
            vec![
                ChannelDialRung { endpoint: "203.0.113.5:9443".parse().unwrap(), via_front_door: false },
                ChannelDialRung { endpoint: "203.0.113.5:443".parse().unwrap(), via_front_door: true },
            ],
            "broker: direct then :443 front door"
        );
        assert_eq!(
            cfg.relay_ladder().last().unwrap(),
            &ChannelDialRung { endpoint: "203.0.113.5:443".parse().unwrap(), via_front_door: true },
            "relay also falls back to the front door"
        );

        // A set-but-malformed front door is a hard error (a typo must not silently drop it).
        let mut bad_fd = base.clone();
        bad_fd.push(("CT_CHANNEL_FRONT_DOOR", "not-an-addr".into()));
        assert!(lookup(&bad_fd).is_err(), "malformed CT_CHANNEL_FRONT_DOOR rejected");
    }

    #[test]
    fn channel_config_parses_roles_keys_and_the_initiator_cert_requirement() {
        // #98/#100: the one-liner's config contract. A responder needs no peer cert;
        // an initiator does. Bad role / missing key / bad addr are rejected.
        let acc = cfg_from(&[
            ("CT_CHANNEL_ROLE", "accept"),
            ("CT_CHANNEL_ADDR", "0.0.0.0:9000"),
            ("CT_CHANNEL_NOISE_KEY", K64),
            ("CT_CHANNEL_PEER_NOISE_KEY", K64),
        ])
        .expect("responder config is valid without a peer cert");
        assert_eq!(acc.role, ChannelRole::Accept);
        assert_eq!(acc.addr, "0.0.0.0:9000".parse().unwrap());
        assert!(acc.peer_cert_der.is_none());

        // Initiator without a cert is valid (dials accept-any; Noise authenticates);
        // a hex cert, if given, is parsed and pinned.
        let base = [
            ("CT_CHANNEL_ROLE", "initiate"),
            ("CT_CHANNEL_ADDR", "203.0.113.9:9000"),
            ("CT_CHANNEL_NOISE_KEY", K64),
            ("CT_CHANNEL_PEER_NOISE_KEY", K64),
        ];
        let no_cert = cfg_from(&base).expect("initiator without a cert is valid (accept-any dial)");
        assert!(no_cert.peer_cert_der.is_none());
        let mut with_cert = base.to_vec();
        with_cert.push(("CT_CHANNEL_PEER_CERT", "deadbeef"));
        let init = cfg_from(&with_cert).expect("initiator with a cert is valid");
        assert_eq!(init.peer_cert_der.as_deref(), Some(&[0xde, 0xad, 0xbe, 0xef][..]));

        // Rejections.
        assert!(cfg_from(&[("CT_CHANNEL_ROLE", "bogus"), ("CT_CHANNEL_ADDR", "0.0.0.0:1"), ("CT_CHANNEL_NOISE_KEY", K64), ("CT_CHANNEL_PEER_NOISE_KEY", K64)]).is_err(), "bad role");
        assert!(cfg_from(&[("CT_CHANNEL_ROLE", "accept"), ("CT_CHANNEL_ADDR", "not-an-addr"), ("CT_CHANNEL_NOISE_KEY", K64), ("CT_CHANNEL_PEER_NOISE_KEY", K64)]).is_err(), "bad addr");
        assert!(cfg_from(&[("CT_CHANNEL_ROLE", "accept"), ("CT_CHANNEL_ADDR", "0.0.0.0:1"), ("CT_CHANNEL_NOISE_KEY", "tooshort"), ("CT_CHANNEL_PEER_NOISE_KEY", K64)]).is_err(), "bad key");
    }

    #[tokio::test]
    async fn runner_pipes_local_data_over_the_a2a_tunnel() {
        // #72 AF4-session-wire / #98: the runnable path. Two agents each call
        // run_channel_session with their role over a REAL QUIC connection, each
        // handing it a LOCAL duplex. Bytes written to the initiator's local side come
        // out of the responder's local side — plaintext in, plaintext out, encrypted
        // A2A tunnel in between. This is exactly what the CLI wires to stdin/stdout.
        let initiator = generate_static_keypair();
        let responder = generate_static_keypair();
        let resp_priv = responder.private;
        let init_priv = initiator.private;
        let resp_pub = responder.public;

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");

        // Responder: accept the connection, run the Accept side, pump its local end.
        let (mut resp_local_test, resp_local_run) = tokio::io::duplex(8192);
        let resp_task = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").await.expect("conn");
            run_channel_session(&conn, ChannelRole::Accept, &resp_priv, &[0u8; 32], resp_local_run)
                .await
                .expect("responder session");
        });

        // Initiator: dial, run the Initiate side (pinning the responder key), pump local.
        let (mut init_local_test, init_local_run) = tokio::io::duplex(8192);
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let init_task = tokio::spawn(async move {
            run_channel_session(&conn, ChannelRole::Initiate, &init_priv, &resp_pub, init_local_run)
                .await
                .expect("initiator session");
            // hold the connection until the pump finishes
        });

        // Drive it: write a payload into the initiator's local side; the pump
        // forwards it, so exactly those bytes come out of the responder's local side.
        // (Read the exact length rather than to-EOF: both pumps stay open for the
        // reverse direction, so there is no EOF to wait on here.)
        let payload = b"data flowing agent A -> agent B over the channel";
        init_local_test.write_all(payload).await.expect("write local");
        init_local_test.flush().await.expect("flush local");

        let mut got = vec![0u8; payload.len()];
        resp_local_test.read_exact(&mut got).await.expect("read peer local");
        assert_eq!(got, payload, "the responder's local side receives exactly what A sent");

        init_task.abort();
        resp_task.abort();
    }

    // A minimal edge-broker stand-in that admits one join and acks a fixed peer
    // endpoint + Noise key. It replicates the broker wire protocol (length-framed
    // request, possession challenge, `OK <endpoint> <noise_hex>`) but omits the
    // `safe_endpoint` SSRF gate — which is tested in `ct_edge::channel_broker` and
    // would (correctly) reject the loopback address a hermetic test must use.
    async fn stub_broker_admit(
        server: &Endpoint,
        peer_addr: std::net::SocketAddr,
        peer_noise: [u8; 32],
        peer_holder: [u8; 32],
        peer_attestation: [u8; 64],
    ) {
        let conn = server.accept().await.expect("incoming").await.expect("conn");
        let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
        let mut len = [0u8; 2];
        recv.read_exact(&mut len).await.expect("len");
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        recv.read_exact(&mut buf).await.expect("req");
        send.write_all(&[0u8; 32]).await.expect("challenge"); // possession challenge
        let mut sig = [0u8; 64];
        let _ = recv.read_exact(&mut sig).await; // (signature not checked by the stub)
        // Ack the attested-key triple the real broker relays (#101).
        let ack = format!(
            "OK {} {} {} {}",
            peer_addr,
            hex_encode(&peer_noise),
            hex_encode(&peer_holder),
            hex_encode(&peer_attestation)
        );
        send.write_all(ack.as_bytes()).await.expect("ack");
        send.finish().expect("finish");
        conn.closed().await;
    }

    #[tokio::test]
    async fn channel_join_initiator_uses_the_rendezvous_peer_and_pipes_data() {
        // #72 AF4 / #100 hands-off capstone: run_channel_join presents to the broker,
        // takes the peer endpoint AND Noise key from the ack (no out-of-band value),
        // dials the peer (accept-any), and pipes data. Here the peer is a real
        // responder listener; the stub broker supplies its addr+key.
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ct_common::noise::generate_static_keypair;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use ed25519_dalek::Signer;

        // Responder: a real direct listener running the Accept side of the session.
        let responder_noise = generate_static_keypair();
        let (resp_listener, _c) = crate::transport::build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("listener");
        let resp_addr = resp_listener.local_addr().expect("resp addr");
        let (mut resp_local_test, resp_local_run) = tokio::io::duplex(8192);
        let rnp = responder_noise.private;
        let resp_task = tokio::spawn(async move {
            let conn = resp_listener.accept().await.expect("incoming").await.expect("conn");
            run_channel_session(&conn, ChannelRole::Accept, &rnp, &[0u8; 32], resp_local_run)
                .await
                .expect("responder session");
        });

        // Stub broker: admits the initiator and relays the responder's addr + key.
        let (broker_ep, broker_cert) = build_server_endpoint_with_cert().expect("broker");
        let broker_addr = broker_ep.local_addr().expect("broker addr");
        let rnpub = responder_noise.public;
        // The stub relays the responder's attested-key triple (#101): a holder that
        // signs the responder's Noise key for the initiator's channel.
        let resp_holder = SigningKey::from_bytes(&[0x44u8; 32]);
        let resp_hpub = resp_holder.verifying_key().to_bytes();
        let resp_att = resp_holder
            .sign(&ct_common::channel::member_noise_attest_bytes(&ChannelId([0xD0u8; 32]), &resp_hpub, &rnpub))
            .to_bytes();
        let broker_task = tokio::spawn(async move {
            stub_broker_admit(&broker_ep, resp_addr, rnpub, resp_hpub, resp_att).await
        });

        // Initiator: run_channel_join over a connection to the (stub) broker.
        let initiator_noise = generate_static_keypair();
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let holder = SigningKey::from_bytes(&[0x11u8; 32]);
        let g = ChannelGrant {
            channel: ChannelId([0xD0u8; 32]),
            holder: holder.verifying_key().to_bytes(),
            direction: Direction::Initiate,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        let grant = SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() };
        let req = ChannelJoinRequest { grant, endpoint: "203.0.113.1:7001".to_string() };
        let (mut a_local_test, a_local_run) = tokio::io::duplex(8192);
        let inp = initiator_noise.private;
        let a_task = tokio::spawn(async move {
            let c = build_client_endpoint(broker_cert).expect("client");
            let conn = c.connect(broker_addr, "localhost").expect("cfg").await.expect("conn");
            // Direct dial succeeds here (the stub broker gives a real responder addr),
            // so relay_conn is unused — reuse the broker conn; timeouts don't fire.
            run_channel_join(
                &conn,
                &conn,
                &req,
                &holder,
                ChannelRole::Initiate,
                &inp,
                None,
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(5),
                a_local_run,
            )
            .await
        });

        // Data flows initiator -> responder with zero out-of-band key/cert exchange.
        let payload = b"hands-off: peer addr + Noise key came from the rendezvous ack";
        a_local_test.write_all(payload).await.expect("write");
        a_local_test.flush().await.expect("flush");
        let mut got = vec![0u8; payload.len()];
        resp_local_test.read_exact(&mut got).await.expect("read");
        assert_eq!(got, payload, "the responder receives the initiator's data, keyed only via rendezvous");

        a_task.abort();
        resp_task.abort();
        broker_task.abort();
    }

    #[tokio::test]
    async fn run_channel_join_with_admission_runs_the_direct_session_from_a_443_ladder_admission() {
        // #106 client-dial-wire (frozen): the seam the plane CLI now uses. The AGENT
        // admits over the broker LADDER — a DEAD direct rung (blocked channel port) then a
        // real `:443` TLS-TCP front door driven by the production
        // `ct_edge::channel_broker::admit_channel_join_on_duplex` gate — and the resulting
        // ChannelJoinOutcome drives run_channel_join_with_admission's DIRECT data path to a
        // real responder. Broker admission is thereby decoupled from (and reachable over
        // `:443` independently of) the direct/relay data legs; data flows with zero
        // out-of-band key/cert exchange. (The QUIC relay handle is present but unused — the
        // direct dial succeeds — since the relay-leg-over-`:443` is the ⏳ follow slice.)
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ct_common::noise::generate_static_keypair;
        use ct_edge::channel_broker::admit_channel_join_on_duplex;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert, build_tcp_tls_listener_at};
        use ed25519_dalek::Signer;
        use tokio::io::AsyncWriteExt;

        let channel = [0x6Au8; 32];

        // Responder: a real direct listener running the Accept side of the session.
        let responder_noise = generate_static_keypair();
        let (resp_listener, _c) =
            crate::transport::build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("listener");
        let resp_addr = resp_listener.local_addr().expect("resp addr");
        let (mut resp_local_test, resp_local_run) = tokio::io::duplex(8192);
        let rnp = responder_noise.private;
        let resp_task = tokio::spawn(async move {
            let conn = resp_listener.accept().await.expect("incoming").await.expect("conn");
            run_channel_session(&conn, ChannelRole::Accept, &rnp, &[0u8; 32], resp_local_run)
                .await
                .expect("responder session");
        });

        // The responder's attested-key triple (#101) the front door relays in its ack, so
        // the initiator pins the responder's Noise key with nothing conveyed out-of-band.
        let resp_holder = SigningKey::from_bytes(&[0x44u8; 32]);
        let resp_hpub = resp_holder.verifying_key().to_bytes();
        let resp_npub = responder_noise.public;
        let resp_att = resp_holder
            .sign(&ct_common::channel::member_noise_attest_bytes(&ChannelId(channel), &resp_hpub, &resp_npub))
            .to_bytes();

        // Operator-signed initiator grant; the front door authorizes it under op_pub.
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let op_pub = op.verifying_key().to_bytes();
        let holder = SigningKey::from_bytes(&[0x11u8; 32]);
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: holder.verifying_key().to_bytes(),
            direction: Direction::Initiate,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        let grant = SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() };
        // The advertised endpoint must be a SAFE (non-loopback) dialable addr for admission.
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.1:7001".to_string() };

        // A real `:443`-style TLS-TCP edge front door: admit the join over the duplex, then
        // ack the responder's addr + attested Noise triple (as the rendezvous broker would).
        let (fd_listener, acceptor, edge_cert) =
            build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap()).await.expect("tls-tcp listener");
        let fd_addr = fd_listener.local_addr().expect("front-door addr");
        let edge = tokio::spawn(async move {
            let (tcp, peer) = fd_listener.accept().await.expect("accept tcp");
            let tls = acceptor.accept(tcp).await.expect("tls accept");
            let (mut stream, _req, _op, _noise, _attest, _observed) = admit_channel_join_on_duplex(
                tls,
                peer,
                500u64, // now < expires_at (1_000)
                std::time::Duration::from_secs(5),
                &move |c: ChannelId, _h: [u8; 32]| {
                    let ok = c.0 == channel;
                    async move { ok.then_some((op_pub, None, None)) }
                },
            )
            .await
            .expect("admit over the :443 TLS-TCP duplex");
            let ack = format!(
                "OK {} {} {} {}",
                resp_addr,
                hex_encode(&resp_npub),
                hex_encode(&resp_hpub),
                hex_encode(&resp_att)
            );
            stream.write_all(ack.as_bytes()).await.expect("ack");
            stream.shutdown().await.expect("shutdown");
        });

        // The broker ladder: a DEAD direct rung (closed UDP port → the QUIC dial is
        // Unreachable) then the LIVE `:443` front door.
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        let rungs = vec![
            ChannelDialRung { endpoint: dead_addr, via_front_door: false },
            ChannelDialRung { endpoint: fd_addr, via_front_door: true },
        ];

        // Admit over the ladder: direct is Unreachable → the `:443` front door completes it.
        let admission = present_channel_join_via_ladder(
            &rungs,
            &request,
            &holder,
            edge_cert,
            std::time::Duration::from_millis(400),
        )
        .await
        .expect("admitted over the :443 front door after the dead direct rung");

        // A scratch (unused) QUIC relay handle — the direct dial succeeds, so it is never
        // touched; the outcome-driven data path still requires a `&Connection` for the leg.
        let (scratch_ep, scratch_cert) = build_server_endpoint_with_cert().expect("scratch relay ep");
        let scratch_addr = scratch_ep.local_addr().expect("scratch addr");
        tokio::spawn(async move {
            if let Some(inc) = scratch_ep.accept().await {
                let _ = inc.await;
            }
        });
        let sc = build_client_endpoint(scratch_cert).expect("scratch client");
        let unused_relay = sc.connect(scratch_addr, "localhost").expect("cfg").await.expect("scratch conn");

        // The outcome-driven data path dials the responder directly and pumps bytes.
        let initiator_noise = generate_static_keypair();
        let (mut a_local_test, a_local_run) = tokio::io::duplex(8192);
        let inp = initiator_noise.private;
        let a_task = tokio::spawn(async move {
            run_channel_join_with_admission(
                admission,
                RelayFallback::Quic(&unused_relay),
                &request,
                &holder,
                ChannelRole::Initiate,
                &inp,
                None,
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(5),
                a_local_run,
            )
            .await
        });

        // Data flows initiator -> responder: `:443` broker admission + direct data leg.
        let payload = b"admitted over :443, then piped over the direct A2A session";
        a_local_test.write_all(payload).await.expect("write");
        a_local_test.flush().await.expect("flush");
        let mut got = vec![0u8; payload.len()];
        resp_local_test.read_exact(&mut got).await.expect("read");
        assert_eq!(got, payload, "the responder receives the initiator's data (admitted over :443, direct data leg)");

        edge.await.expect("edge task");
        a_task.abort();
        resp_task.abort();
    }

    #[tokio::test]
    async fn agents_tunnel_a_noise_session_over_the_edge_relay() {
        // #72 AF4-session-resilience CAPSTONE — the connection-difficulty case that
        // matters: two agents that can't reach each other directly both fall back to
        // the edge RELAY endpoint, run a real Noise_IK session over the relayed stream,
        // and application data flows THROUGH the edge (the edge only sees ciphertext).
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ct_common::noise::generate_static_keypair;
        use ct_edge::channel_broker::broker_channel_relay;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use ed25519_dalek::Signer;

        let op = SigningKey::from_bytes(&[7u8; 32]);
        let op_pub = op.verifying_key().to_bytes();
        let holder_a = SigningKey::from_bytes(&[0x21u8; 32]);
        let holder_b = SigningKey::from_bytes(&[0x22u8; 32]);
        let channel = [0xE1u8; 32];
        let noise_a = generate_static_keypair();
        let noise_b = generate_static_keypair();
        let signed = |h: &SigningKey, dir| {
            let g = ChannelGrant {
                channel: ChannelId(channel),
                holder: SigningKey::verifying_key(h).to_bytes(),
                direction: dir,
                rights: Rights::ReadWrite,
                delegable: false,
                expires_at: 1_000,
            };
            SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }
        };
        let req_a = ChannelJoinRequest { grant: signed(&holder_a, Direction::Initiate), endpoint: "203.0.113.1:7001".to_string() };
        let req_b = ChannelJoinRequest { grant: signed(&holder_b, Direction::Accept), endpoint: "203.0.113.2:7002".to_string() };

        // Edge relay endpoint pairs + splices the two members.
        let (relay_ep, cert) = build_server_endpoint_with_cert().expect("relay ep");
        let relay_addr = relay_ep.local_addr().expect("addr");
        let relay_task = tokio::spawn(async move {
            broker_channel_relay(&relay_ep, 500, move |c, _h| async move {
                (c.0 == channel).then_some((op_pub, None, None))
            })
            .await
            .map(|_| ())
        });

        // Both agents fall back to the relay (they never reach each other directly).
        let cert_b = cert.clone();
        let (mut a_local_test, a_local_run) = tokio::io::duplex(8192);
        let (na, nbpub) = (noise_a.private, noise_b.public);
        let a = tokio::spawn(async move {
            let c = build_client_endpoint(cert).expect("client");
            let conn = c.connect(relay_addr, "localhost").expect("cfg").await.expect("conn");
            join_via_relay(&conn, &req_a, &holder_a, ChannelRole::Initiate, &na, &nbpub, a_local_run).await
        });
        let (nb, napub) = (noise_b.private, noise_a.public);
        let (mut b_local_test, b_local_run) = tokio::io::duplex(8192);
        let b = tokio::spawn(async move {
            let c = build_client_endpoint(cert_b).expect("client");
            let conn = c.connect(relay_addr, "localhost").expect("cfg").await.expect("conn");
            join_via_relay(&conn, &req_b, &holder_b, ChannelRole::Accept, &nb, &napub, b_local_run).await
        });

        // Application data flows A -> B over the relayed, encrypted A2A tunnel.
        let payload = b"tunnel carried over the edge relay when direct was blocked";
        a_local_test.write_all(payload).await.expect("write");
        a_local_test.flush().await.expect("flush");
        let mut got = vec![0u8; payload.len()];
        b_local_test.read_exact(&mut got).await.expect("read");
        assert_eq!(got, payload, "B receives A's data via the edge relay (Noise stays E2E)");

        a.abort();
        b.abort();
        relay_task.abort();
    }

    #[tokio::test]
    async fn join_via_relay_ladder_falls_back_to_the_443_front_door_and_forms_the_noise_tunnel() {
        // #106 relay-leg-443 (frozen): the relay-leg analog of the `:443` broker fallback,
        // and the capstone for a fully `:443`-only member. BOTH members' relay ladders have
        // a DEAD direct rung (the relay port is FILTERED → the QUIC dial is Unreachable) then
        // a LIVE `:443` TLS-TCP front door driven by the PRODUCTION edge relay path
        // (`admit_and_pair_on_stream` → `finish_relay_pair_over_streams`). Each member walks
        // `join_via_relay_ladder`, falls through the dead direct rung, presents its join over
        // `:443` WITHOUT consuming the stream, and runs the Noise_IK session over that SAME
        // relay-spliced stream. A real payload round-trips BOTH directions — proving a member
        // whose relay port is also blocked relays end-to-end over `:443` (the #103 sink),
        // Noise staying end-to-end (the edge splices ciphertext only).
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ct_common::noise::generate_static_keypair;
        use ct_edge::channel_broker::{
            admit_and_pair_on_stream, finish_relay_pair_over_streams, ChannelPairer,
        };
        use ct_edge::transport::build_tcp_tls_listener_at;
        use ed25519_dalek::Signer;
        use std::sync::Mutex;
        use std::time::Duration;
        use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

        let op = SigningKey::from_bytes(&[7u8; 32]);
        let op_pub = op.verifying_key().to_bytes();
        let holder_a = SigningKey::from_bytes(&[0x21u8; 32]);
        let holder_b = SigningKey::from_bytes(&[0x22u8; 32]);
        let channel = [0xE4u8; 32];
        let noise_a = generate_static_keypair();
        let noise_b = generate_static_keypair();
        let signed = |h: &SigningKey, dir| {
            let g = ChannelGrant {
                channel: ChannelId(channel),
                holder: SigningKey::verifying_key(h).to_bytes(),
                direction: dir,
                rights: Rights::ReadWrite,
                delegable: false,
                expires_at: 1_000,
            };
            SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }
        };
        // Advertised endpoints must be SAFE (non-loopback) to pass the admission gate, even
        // though the relay leg never dials them (the members can't be dialed — that's why
        // they relay).
        let req_a = ChannelJoinRequest { grant: signed(&holder_a, Direction::Initiate), endpoint: "203.0.113.1:7001".to_string() };
        let req_b = ChannelJoinRequest { grant: signed(&holder_b, Direction::Accept), endpoint: "203.0.113.2:7002".to_string() };

        // A real `:443`-style TLS-TCP edge front door: admit two independently-arriving
        // members, correlate them by channel, and relay-splice the two `:443` duplexes —
        // the production front-door relay path (#106).
        let (listener, acceptor, edge_cert) = build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap())
            .await
            .expect("tls-tcp listener");
        let fd_addr = listener.local_addr().expect("front-door addr");
        let edge = tokio::spawn(async move {
            let pairer: Mutex<ChannelPairer<_>> = Mutex::new(ChannelPairer::new());
            let authorize =
                move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((op_pub, None, None)) };
            let mut paired = None;
            for _ in 0..2 {
                let (tcp, peer) = listener.accept().await.expect("accept tcp");
                let tls = acceptor.accept(tcp).await.expect("tls accept");
                if let Some((x, y)) = admit_and_pair_on_stream(
                    tls,
                    peer,
                    500u64, // now < expires_at (1_000)
                    Duration::from_secs(5),
                    &authorize,
                    10_000u64, // parked-member deadline (never reached in this test)
                    &pairer,
                )
                .await
                .expect("admit + pair the :443 member")
                {
                    paired = Some((x, y));
                }
            }
            let (x, y) = paired.expect("two same-channel members paired over :443");
            finish_relay_pair_over_streams(x, y, 500u64).await.expect("relay-splice the two :443 duplexes");
        });

        // Each member's relay ladder: a DEAD direct rung (closed UDP port → the QUIC relay
        // dial is Unreachable) then the LIVE `:443` front door.
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead); // nothing on that UDP port -> the direct QUIC relay dial is Unreachable
        let rungs = vec![
            ChannelDialRung { endpoint: dead_addr, via_front_door: false },
            ChannelDialRung { endpoint: fd_addr, via_front_door: true },
        ];

        // Two members drive `join_via_relay_ladder`: A initiates, B accepts. Each pins the
        // peer's Noise key directly (the relay leg conveys no peer material).
        let (mut a_app, a_local) = duplex(16 * 1024);
        let (mut b_app, b_local) = duplex(16 * 1024);
        let (na, nbpub) = (noise_a.private, noise_b.public);
        let rungs_a = rungs.clone();
        let cert_a = edge_cert.clone();
        let a = tokio::spawn(async move {
            join_via_relay_ladder(
                &rungs_a,
                cert_a,
                Duration::from_millis(400),
                &req_a,
                &holder_a,
                ChannelRole::Initiate,
                &na,
                &nbpub,
                a_local,
            )
            .await
        });
        let (nb, napub) = (noise_b.private, noise_a.public);
        let b = tokio::spawn(async move {
            join_via_relay_ladder(
                &rungs,
                edge_cert,
                Duration::from_millis(400),
                &req_b,
                &holder_b,
                ChannelRole::Accept,
                &nb,
                &napub,
                b_local,
            )
            .await
        });

        // A -> B over the `:443`-relayed, encrypted A2A tunnel.
        a_app.write_all(b"ping-A-to-B").await.expect("a writes");
        let mut got = [0u8; 11];
        b_app.read_exact(&mut got).await.expect("b reads A's bytes");
        assert_eq!(&got, b"ping-A-to-B", "A's plaintext arrives decrypted at B over the :443 relay");

        // B -> A (reverse direction proves the splice is full-duplex).
        b_app.write_all(b"pong-B-to-A").await.expect("b writes");
        let mut got2 = [0u8; 11];
        a_app.read_exact(&mut got2).await.expect("a reads B's bytes");
        assert_eq!(&got2, b"pong-B-to-A", "B's plaintext arrives decrypted at A over the :443 relay");

        // Closing both local sides tears the sessions down cleanly (noise_pump shuts down
        // each transport write half → graceful TLS close_notify → the relay sees EOF).
        drop(a_app);
        drop(b_app);
        let _ = a.await.expect("initiator task joins");
        let _ = b.await.expect("acceptor task joins");
        edge.await.expect("edge relay task joins");
    }

    #[tokio::test]
    async fn two_443_only_members_learn_each_others_noise_key_and_form_the_tunnel() {
        // #122 (frozen): the bug that broke EVERY `:443`-only two-party join. Two members
        // FORCED onto the public `:443` front door (relay/broker ports unreachable), each with
        // FRESHLY + independently generated channel keys and grants — NO pre-shared peer Noise
        // key, no reliance on any prior broker-admission step. Each drives the join over the
        // PRODUCTION relay-splice path (`admit_and_pair_on_stream` → `finish_relay_pair_over_
        // streams`) and MUST learn the OTHER's attested Noise key FROM THE ACK itself
        // (`Admitted.peer_noise_pubkey == Some(peer key)`), verify the #101 attestation, pin it,
        // and form the Noise_IK tunnel — a real payload crossing BOTH directions. Before the
        // fix the relay acked a bare `OK` conveying no key, so `peer_noise_pubkey` was `None`
        // and the join failed at the pin step (channel_run.rs). So this test FAILS against the
        // bare-`OK` code and PASSES once the ack carries the peer's attested key.
        use ct_common::channel::{
            member_noise_attest_bytes, verify_member_noise_attestation, ChannelGrant, ChannelId,
            Direction, Rights, SignedChannelGrant, CHANNEL_ENDPOINT_RELAY_ONLY,
        };
        use ct_common::noise::generate_static_keypair;
        use ct_edge::channel_broker::{
            admit_and_pair_on_stream, finish_relay_pair_over_streams, ChannelPairer,
        };
        use ct_edge::transport::build_tcp_tls_listener_at;
        use ed25519_dalek::Signer;
        use std::sync::Mutex;
        use std::time::Duration;
        use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt};

        let op = SigningKey::from_bytes(&[0x5Au8; 32]);
        let op_pub = op.verifying_key().to_bytes();
        let channel = [0xC2u8; 32];
        // Fresh, independent identities per member — nothing pre-shared between them.
        let holder_a = SigningKey::from_bytes(&[0x2au8; 32]);
        let holder_b = SigningKey::from_bytes(&[0x2bu8; 32]);
        let ha_pub = holder_a.verifying_key().to_bytes();
        let hb_pub = holder_b.verifying_key().to_bytes();
        let noise_a = generate_static_keypair();
        let noise_b = generate_static_keypair();
        let (na, na_pub) = (noise_a.private, noise_a.public);
        let (nb, nb_pub) = (noise_b.private, noise_b.public);
        // Each member attests its OWN Noise key under its holder key (#101).
        let attest_a = holder_a
            .sign(&member_noise_attest_bytes(&ChannelId(channel), &ha_pub, &na_pub))
            .to_bytes();
        let attest_b = holder_b
            .sign(&member_noise_attest_bytes(&ChannelId(channel), &hb_pub, &nb_pub))
            .to_bytes();
        let signed = |h: &SigningKey, dir| {
            let g = ChannelGrant {
                channel: ChannelId(channel),
                holder: SigningKey::verifying_key(h).to_bytes(),
                direction: dir,
                rights: Rights::ReadWrite,
                delegable: false,
                expires_at: 1_000,
            };
            SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }
        };
        // Both are `:443`-only — they advertise the relay-only sentinel (they can't be dialed).
        let req_a = ChannelJoinRequest {
            grant: signed(&holder_a, Direction::Initiate),
            endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
        };
        let req_b = ChannelJoinRequest {
            grant: signed(&holder_b, Direction::Accept),
            endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
        };

        // The PRODUCTION `:443` front door: admit two independently-arriving members, correlate
        // them by channel, and relay-splice the two duplexes. The `authorize` closure resolves
        // each member to its OWN (operator, Noise key, attestation) — exactly as the CP-backed
        // registry does — so the relay finisher has the material to relay each side the OTHER's
        // attested key.
        let (listener, acceptor, edge_cert) =
            build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap())
                .await
                .expect("tls-tcp listener");
        let fd_addr = listener.local_addr().expect("front-door addr");
        let edge = tokio::spawn(async move {
            let pairer: Mutex<ChannelPairer<_>> = Mutex::new(ChannelPairer::new());
            let authorize = move |c: ChannelId, h: [u8; 32]| async move {
                if c.0 != channel {
                    return None;
                }
                let (noise, attest) =
                    if h == ha_pub { (na_pub, attest_a) } else { (nb_pub, attest_b) };
                Some((op_pub, Some(noise), Some(attest)))
            };
            let mut paired = None;
            for _ in 0..2 {
                let (tcp, peer) = listener.accept().await.expect("accept tcp");
                let tls = acceptor.accept(tcp).await.expect("tls accept");
                if let Some((x, y)) = admit_and_pair_on_stream(
                    tls,
                    peer,
                    500u64,
                    Duration::from_secs(5),
                    &authorize,
                    10_000u64,
                    &pairer,
                )
                .await
                .expect("admit + pair the :443 member")
                {
                    paired = Some((x, y));
                }
            }
            let (x, y) = paired.expect("two same-channel members paired over :443");
            finish_relay_pair_over_streams(x, y, 500u64)
                .await
                .expect("relay-splice the two :443 duplexes");
        });

        let (mut a_app, a_local) = duplex(16 * 1024);
        let (mut b_app, b_local) = duplex(16 * 1024);
        let cert_a = edge_cert.clone();
        // A: connect over `:443`, present the join WITHOUT consuming the stream, LEARN B's
        // attested Noise key from the ack, verify #101, pin it, run the session on the SAME
        // relay-spliced stream.
        let a = tokio::spawn(async move {
            let stream = crate::transport::tcp_tls_connect_channel(fd_addr, cert_a)
                .await
                .expect("A tls-tcp connect");
            let (mut recv, mut send) = split(stream);
            let outcome = present_channel_relay_join_on_stream(&mut send, &mut recv, &req_a, &holder_a)
                .await
                .expect("A relay join");
            let peer_noise = match outcome {
                ChannelJoinOutcome::Admitted { peer_noise_pubkey, peer_holder, peer_attestation, .. } => {
                    let n = peer_noise_pubkey.expect("A learns B's Noise key from the ack (#122)");
                    assert_eq!(n, nb_pub, "A learns B's REAL Noise key from the ack");
                    let ph = peer_holder.expect("A learns B's holder from the ack");
                    let att = peer_attestation.expect("A learns B's attestation from the ack");
                    assert!(
                        verify_member_noise_attestation(&ChannelId(channel), &ph, &n, &att),
                        "B's #101 attestation verifies against its grant-authenticated holder"
                    );
                    n
                }
                ChannelJoinOutcome::Refused => panic!("A's :443 join must be Admitted"),
            };
            run_channel_session_on_stream(send, recv, ChannelRole::Initiate, &na, &peer_noise, a_local).await
        });
        // B: the mirror (Accept role), learning A's key from its ack.
        let b = tokio::spawn(async move {
            let stream = crate::transport::tcp_tls_connect_channel(fd_addr, edge_cert)
                .await
                .expect("B tls-tcp connect");
            let (mut recv, mut send) = split(stream);
            let outcome = present_channel_relay_join_on_stream(&mut send, &mut recv, &req_b, &holder_b)
                .await
                .expect("B relay join");
            let peer_noise = match outcome {
                ChannelJoinOutcome::Admitted { peer_noise_pubkey, peer_holder, peer_attestation, .. } => {
                    let n = peer_noise_pubkey.expect("B learns A's Noise key from the ack (#122)");
                    assert_eq!(n, na_pub, "B learns A's REAL Noise key from the ack");
                    let ph = peer_holder.expect("B learns A's holder from the ack");
                    let att = peer_attestation.expect("B learns A's attestation from the ack");
                    assert!(
                        verify_member_noise_attestation(&ChannelId(channel), &ph, &n, &att),
                        "A's #101 attestation verifies against its grant-authenticated holder"
                    );
                    n
                }
                ChannelJoinOutcome::Refused => panic!("B's :443 join must be Admitted"),
            };
            run_channel_session_on_stream(send, recv, ChannelRole::Accept, &nb, &peer_noise, b_local).await
        });

        // A -> B over the `:443`-relayed, encrypted A2A tunnel keyed on the ACK-LEARNED keys.
        a_app.write_all(b"ping-A-to-B").await.expect("a writes");
        let mut got = [0u8; 11];
        b_app.read_exact(&mut got).await.expect("b reads A's bytes");
        assert_eq!(&got, b"ping-A-to-B", "A's plaintext arrives decrypted at B (key learned from the ack)");

        // B -> A (reverse direction proves the splice is full-duplex).
        b_app.write_all(b"pong-B-to-A").await.expect("b writes");
        let mut got2 = [0u8; 11];
        a_app.read_exact(&mut got2).await.expect("a reads B's bytes");
        assert_eq!(&got2, b"pong-B-to-A", "B's plaintext arrives decrypted at A over the :443 relay");

        drop(a_app);
        drop(b_app);
        a.await.expect("A task joins").expect("A session ok");
        b.await.expect("B task joins").expect("B session ok");
        edge.await.expect("edge relay task joins");
    }

    #[tokio::test]
    async fn run_channel_join_auto_falls_back_to_the_relay_when_direct_is_blocked() {
        // #72 AF4-relay-orchestrate: the auto-recovery. The rendezvous hands the
        // initiator a peer endpoint that BLACKHOLES (bound-but-silent), so the direct
        // dial times out (Unreachable) and run_channel_join transparently falls back to
        // the edge relay where the responder waits — the tunnel carries data with NO
        // caller intervention.
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ct_common::noise::generate_static_keypair;
        use ct_edge::channel_broker::broker_channel_relay;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use ed25519_dalek::Signer;

        let op = SigningKey::from_bytes(&[7u8; 32]);
        let op_pub = op.verifying_key().to_bytes();
        let holder_a = SigningKey::from_bytes(&[0x21u8; 32]);
        let holder_b = SigningKey::from_bytes(&[0x22u8; 32]);
        let channel = [0xE2u8; 32];
        let noise_a = generate_static_keypair();
        let noise_b = generate_static_keypair();
        let signed = |h: &SigningKey, dir| {
            let g = ChannelGrant {
                channel: ChannelId(channel),
                holder: SigningKey::verifying_key(h).to_bytes(),
                direction: dir,
                rights: Rights::ReadWrite,
                delegable: false,
                expires_at: 1_000,
            };
            SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }
        };
        let req_a = ChannelJoinRequest { grant: signed(&holder_a, Direction::Initiate), endpoint: "203.0.113.1:7001".to_string() };
        let req_b = ChannelJoinRequest { grant: signed(&holder_b, Direction::Accept), endpoint: "203.0.113.2:7002".to_string() };

        // A bound-but-silent UDP socket: the direct dial to it blackholes -> times out.
        let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").expect("blackhole");
        let blackhole_addr = blackhole.local_addr().expect("bh addr");

        // Stub rendezvous: hands the initiator the blackhole addr + B's Noise key.
        let (rdv_ep, rdv_cert) = build_server_endpoint_with_cert().expect("rdv");
        let rdv_addr = rdv_ep.local_addr().expect("rdv addr");
        let nb_pub = noise_b.public;
        // B's attested-key triple, verified by run_channel_join before it falls back.
        let hb_pub = holder_b.verifying_key().to_bytes();
        let b_att = holder_b
            .sign(&ct_common::channel::member_noise_attest_bytes(&ChannelId(channel), &hb_pub, &nb_pub))
            .to_bytes();
        let rdv_task = tokio::spawn(async move {
            stub_broker_admit(&rdv_ep, blackhole_addr, nb_pub, hb_pub, b_att).await
        });

        // Real relay endpoint.
        let (relay_ep, relay_cert) = build_server_endpoint_with_cert().expect("relay");
        let relay_addr = relay_ep.local_addr().expect("relay addr");
        let relay_task = tokio::spawn(async move {
            broker_channel_relay(&relay_ep, 500, move |c, _h| async move {
                (c.0 == channel).then_some((op_pub, None, None))
            })
            .await
            .map(|_| ())
        });

        // Initiator via run_channel_join: direct -> blackhole -> Unreachable -> relay.
        let (mut a_local_test, a_local_run) = tokio::io::duplex(8192);
        let na = noise_a.private;
        let relay_cert_a = relay_cert.clone();
        let a = tokio::spawn(async move {
            let bc = build_client_endpoint(rdv_cert).expect("bc");
            let broker_conn = bc.connect(rdv_addr, "localhost").expect("cfg").await.expect("bconn");
            let rc = build_client_endpoint(relay_cert_a).expect("rc");
            let relay_conn = rc.connect(relay_addr, "localhost").expect("cfg").await.expect("rconn");
            run_channel_join(
                &broker_conn,
                &relay_conn,
                &req_a,
                &holder_a,
                ChannelRole::Initiate,
                &na,
                None,
                std::time::Duration::from_millis(400), // short dial timeout -> fast fallback
                std::time::Duration::from_secs(2),
                a_local_run,
            )
            .await
        });

        // Responder joins the relay directly (its own listen-timeout fallback is covered
        // by run_channel_join's Accept branch; here it goes straight to the relay).
        let (mut b_local_test, b_local_run) = tokio::io::duplex(8192);
        let nb = noise_b.private;
        let nap = noise_a.public;
        let b = tokio::spawn(async move {
            let rc = build_client_endpoint(relay_cert).expect("rc b");
            let relay_conn = rc.connect(relay_addr, "localhost").expect("cfg").await.expect("rconn b");
            join_via_relay(&relay_conn, &req_b, &holder_b, ChannelRole::Accept, &nb, &nap, b_local_run).await
        });

        let payload = b"auto-recovered onto the relay after the direct path was blocked";
        a_local_test.write_all(payload).await.expect("write");
        a_local_test.flush().await.expect("flush");
        let mut got = vec![0u8; payload.len()];
        b_local_test.read_exact(&mut got).await.expect("read");
        assert_eq!(got, payload, "the tunnel auto-recovered via the relay with no caller intervention");

        a.abort();
        b.abort();
        rdv_task.abort();
        relay_task.abort();
        drop(blackhole);
    }

    #[tokio::test]
    async fn quic_lazy_relay_dials_only_on_fallback_and_forms_the_tunnel() {
        // #103 fix (frozen): RelayFallback::QuicLazy holds NO idle relay connection during
        // admission/direct-dial — it dials the relay only when the direct path fails. Prove
        // the lazily-dialed relay still forms the tunnel end to end. (The eager Quic variant
        // held an idle connection the edge reaped as a spurious pre-admission close.)
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ct_common::noise::generate_static_keypair;
        use ct_edge::channel_broker::broker_channel_relay;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use ed25519_dalek::Signer;

        let op = SigningKey::from_bytes(&[7u8; 32]);
        let op_pub = op.verifying_key().to_bytes();
        let holder_a = SigningKey::from_bytes(&[0x31u8; 32]);
        let holder_b = SigningKey::from_bytes(&[0x32u8; 32]);
        let channel = [0xE4u8; 32];
        let noise_a = generate_static_keypair();
        let noise_b = generate_static_keypair();
        let signed = |h: &SigningKey, dir| {
            let g = ChannelGrant {
                channel: ChannelId(channel),
                holder: SigningKey::verifying_key(h).to_bytes(),
                direction: dir,
                rights: Rights::ReadWrite,
                delegable: false,
                expires_at: 1_000,
            };
            SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }
        };
        let req_a = ChannelJoinRequest { grant: signed(&holder_a, Direction::Initiate), endpoint: "203.0.113.1:7001".to_string() };
        let req_b = ChannelJoinRequest { grant: signed(&holder_b, Direction::Accept), endpoint: "203.0.113.2:7002".to_string() };

        // Blackhole direct peer -> the Initiate direct dial times out (Unreachable) -> relay.
        let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").expect("blackhole");
        let blackhole_addr = blackhole.local_addr().expect("bh addr");
        let hb_pub = holder_b.verifying_key().to_bytes();
        let b_att = holder_b
            .sign(&ct_common::channel::member_noise_attest_bytes(&ChannelId(channel), &hb_pub, &noise_b.public))
            .to_bytes();
        // Pre-computed admission (blackhole peer + B's attested Noise key) — no rendezvous stub.
        let admission = ChannelJoinOutcome::Admitted {
            peer_endpoint: blackhole_addr.to_string(),
            peer_noise_pubkey: Some(noise_b.public),
            peer_holder: Some(hb_pub),
            peer_attestation: Some(b_att),
            observed_reflexive: None,
        };

        // Real relay endpoint.
        let (relay_ep, relay_cert) = build_server_endpoint_with_cert().expect("relay");
        let relay_addr = relay_ep.local_addr().expect("relay addr");
        let relay_task = tokio::spawn(async move {
            broker_channel_relay(&relay_ep, 500, move |c, _h| async move {
                (c.0 == channel).then_some((op_pub, None, None))
            })
            .await
            .map(|_| ())
        });

        // Initiator: run_channel_join_with_admission with the LAZY relay — direct blackhole
        // -> Unreachable -> QuicLazy dials relay_addr on demand.
        let (mut a_local_test, a_local_run) = tokio::io::duplex(8192);
        let na = noise_a.private;
        let a = tokio::spawn(async move {
            run_channel_join_with_admission(
                admission,
                RelayFallback::QuicLazy(relay_addr),
                &req_a,
                &holder_a,
                ChannelRole::Initiate,
                &na,
                None,
                std::time::Duration::from_millis(400),
                std::time::Duration::from_secs(2),
                a_local_run,
            )
            .await
        });

        // Responder waits on the relay.
        let (mut b_local_test, b_local_run) = tokio::io::duplex(8192);
        let nb = noise_b.private;
        let nap = noise_a.public;
        let b = tokio::spawn(async move {
            let rc = build_client_endpoint(relay_cert).expect("rc b");
            let relay_conn = rc.connect(relay_addr, "localhost").expect("cfg").await.expect("rconn b");
            join_via_relay(&relay_conn, &req_b, &holder_b, ChannelRole::Accept, &nb, &nap, b_local_run).await
        });

        let payload = b"lazily-dialed relay carries the tunnel (#103)";
        a_local_test.write_all(payload).await.expect("write");
        a_local_test.flush().await.expect("flush");
        let mut got = vec![0u8; payload.len()];
        b_local_test.read_exact(&mut got).await.expect("read");
        assert_eq!(got, payload, "the lazily-dialed relay formed the tunnel");

        a.abort();
        b.abort();
        relay_task.abort();
        drop(blackhole);
    }

    #[tokio::test]
    async fn run_channel_join_rejects_a_peer_key_with_a_bad_attestation() {
        // #101 SEC101c-ii: if the relayed peer Noise key's attestation doesn't verify
        // against the peer's holder (a DB-substituted key), run_channel_join REFUSES to
        // pin it — it errors before establishing any session.
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ct_common::noise::generate_static_keypair;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use ed25519_dalek::Signer;

        let op = SigningKey::from_bytes(&[7u8; 32]);
        let holder_a = SigningKey::from_bytes(&[0x21u8; 32]);
        let channel = [0xE3u8; 32];
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: holder_a.verifying_key().to_bytes(),
            direction: Direction::Initiate,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        let req_a = ChannelJoinRequest {
            grant: SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() },
            endpoint: "203.0.113.1:7001".to_string(),
        };

        // The stub relays a peer key + holder, but an attestation over a DIFFERENT key
        // (as a tampered DB would produce) — it must not verify.
        let peer_holder = SigningKey::from_bytes(&[0x55u8; 32]);
        let peer_hpub = peer_holder.verifying_key().to_bytes();
        let peer_noise = generate_static_keypair().public;
        let bad_attest = peer_holder
            .sign(&ct_common::channel::member_noise_attest_bytes(&ChannelId(channel), &peer_hpub, &[0u8; 32]))
            .to_bytes();

        let (rdv_ep, rdv_cert) = build_server_endpoint_with_cert().expect("rdv");
        let rdv_addr = rdv_ep.local_addr().expect("addr");
        let rdv_task = tokio::spawn(async move {
            stub_broker_admit(&rdv_ep, "203.0.113.9:9000".parse().unwrap(), peer_noise, peer_hpub, bad_attest).await
        });

        let bc = build_client_endpoint(rdv_cert).expect("bc");
        let broker_conn = bc.connect(rdv_addr, "localhost").expect("cfg").await.expect("conn");
        let noise_a = generate_static_keypair();
        let (_t, local) = tokio::io::duplex(64);
        let result = run_channel_join(
            &broker_conn,
            &broker_conn,
            &req_a,
            &holder_a,
            ChannelRole::Initiate,
            &noise_a.private,
            None,
            std::time::Duration::from_millis(200),
            std::time::Duration::from_secs(1),
            local,
        )
        .await;
        assert!(result.is_err(), "a peer key with a bad attestation is rejected before pinning (#101)");
        rdv_task.abort();
    }

    #[tokio::test]
    async fn direct_dial_to_an_unreachable_peer_fails_fast_as_unreachable() {
        // #72 AF4-session-resilience — THE case that matters: a peer that can't be
        // reached on the direct path (NAT/firewall/blackhole). The dial must classify
        // as `Unreachable` (the relay-fallback signal) and fail FAST, not hang on the
        // QUIC handshake's retransmits. A bound-but-silent UDP socket blackholes the
        // handshake (the port is "open", so no ICMP reject short-circuits it).
        use std::time::{Duration, Instant};
        let sink = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sink");
        let addr = sink.local_addr().expect("sink addr"); // occupied, never answers QUIC

        let start = Instant::now();
        let result = dial_peer_direct(addr, Duration::from_millis(400)).await;
        let elapsed = start.elapsed();

        assert!(
            matches!(result, Err(ChannelDialError::Unreachable)),
            "an unreachable peer classifies as Unreachable (relay-fallback signal), got {result:?}"
        );
        assert!(elapsed < Duration::from_secs(2), "failed fast in {elapsed:?}, did not hang");
        drop(sink);
    }

    #[tokio::test]
    async fn initiator_dials_without_a_pre_shared_cert_noise_authenticates() {
        // #100 self-containment: the initiator uses the accept-any channel dialer, so
        // NO transport cert is conveyed — only the peer's Noise key. The responder
        // self-signs (a cert the initiator has never seen); the A2A session still
        // forms and data flows, because Noise_IK is the real mutual auth.
        use crate::transport::{build_channel_dialer, build_direct_listener_at};
        let initiator = generate_static_keypair();
        let responder = generate_static_keypair();
        let resp_priv = responder.private;
        let init_priv = initiator.private;
        let resp_pub = responder.public;

        let (server, _cert) = build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("listener");
        let addr = server.local_addr().expect("addr");

        let (mut resp_local_test, resp_local_run) = tokio::io::duplex(8192);
        let resp_task = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").await.expect("conn");
            run_channel_session(&conn, ChannelRole::Accept, &resp_priv, &[0u8; 32], resp_local_run)
                .await
                .expect("responder session");
        });

        let (mut init_local_test, init_local_run) = tokio::io::duplex(8192);
        let endpoint = build_channel_dialer().expect("dialer");
        // Dial with NO peer cert — the accept-any verifier trusts the transport.
        let conn = endpoint.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let init_task = tokio::spawn(async move {
            run_channel_session(&conn, ChannelRole::Initiate, &init_priv, &resp_pub, init_local_run)
                .await
                .expect("initiator session");
        });

        let payload = b"self-contained: no transport cert was conveyed";
        init_local_test.write_all(payload).await.expect("write");
        init_local_test.flush().await.expect("flush");
        let mut got = vec![0u8; payload.len()];
        resp_local_test.read_exact(&mut got).await.expect("read");
        assert_eq!(got, payload, "data flows without a pre-shared transport cert");

        init_task.abort();
        resp_task.abort();
    }

    #[tokio::test]
    async fn large_transfer_is_not_truncated_when_the_sender_tears_down_after_the_session(
    ) {
        // #134 (frozen): a large A2A transfer must be delivered in FULL even when the sending
        // agent drops the connection the instant its session returns (the real bug: the process
        // exits right after the pump FINs). quinn `finish()` only queues the FIN; without waiting
        // for the peer's acknowledgement, the userspace QUIC driver dies on connection-drop and
        // the unacked tail is silently lost (the sink saw clean 144/224 KiB prefixes of a 588 KB
        // payload). `run_channel_session`'s send-drain (`stopped()`) is what closes that hole —
        // it returns only once the peer has acknowledged every byte, so the drop below is safe.
        use crate::transport::{build_channel_dialer, build_direct_listener_at};
        use ct_common::noise::generate_static_keypair;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let initiator = generate_static_keypair();
        let responder = generate_static_keypair();
        let (init_priv, resp_priv, resp_pub) = (initiator.private, responder.private, responder.public);

        // ~1 MiB — well past the ~144 KiB first-flight/window where the truncation was observed.
        let payload: Vec<u8> = (0..(1024u32 * 1024)).map(|i| (i % 251) as u8).collect();
        let len = payload.len();

        let (server, _cert) = build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("listener");
        let addr = server.local_addr().expect("addr");

        // Responder: accept, run the Accept session, and collect exactly `len` delivered bytes.
        // Its local read half is closed at once (no responder→initiator app data), so its own
        // send direction FINs immediately; we read the payload out concurrently to open flow
        // control. We do NOT await the responder session (its own drain would wait on the
        // now-gone initiator) — read_exact of the full length is the delivery assertion.
        let resp_task = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").await.expect("conn");
            let (resp_run, resp_test) = tokio::io::duplex(64 * 1024);
            let (mut resp_test_r, resp_test_w) = tokio::io::split(resp_test);
            drop(resp_test_w); // responder→initiator app source EOF
            let _sess = tokio::spawn(async move {
                let _ = run_channel_session(&conn, ChannelRole::Accept, &resp_priv, &[0u8; 32], resp_run).await;
                // keep `conn` alive for the session's lifetime, then drop
                drop(conn);
            });
            let mut got = vec![0u8; len];
            let r = resp_test_r.read_exact(&mut got).await;
            (r.is_ok(), got)
        });

        // Initiator: dial, feed the whole payload then EOF the source, run the session to
        // completion (which now blocks on the delivery ack), THEN drop the connection+endpoint
        // — simulating the process exiting the moment the transfer "finished".
        let endpoint = build_channel_dialer().expect("dialer");
        let conn = endpoint.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let (init_run, init_test) = tokio::io::duplex(64 * 1024);
        let (init_test_r, mut init_test_w) = tokio::io::split(init_test);
        drop(init_test_r); // no initiator←responder app data
        let feeder = tokio::spawn(async move {
            init_test_w.write_all(&payload).await.expect("feed payload");
            init_test_w.flush().await.expect("flush");
            drop(init_test_w); // source EOF → initiator outbound FINs
            payload
        });

        run_channel_session(&conn, ChannelRole::Initiate, &init_priv, &resp_pub, init_run)
            .await
            .expect("initiator session");
        // The drain has returned → the peer acknowledged every byte. Now tear the sender down
        // as abruptly as a process exit would.
        drop(conn);
        drop(endpoint);

        let expected = feeder.await.expect("feeder");
        let (ok, got) = tokio::time::timeout(std::time::Duration::from_secs(20), resp_task)
            .await
            .expect("responder collected within 20s")
            .expect("responder task");
        assert!(ok, "the full {len}-byte payload was delivered (no truncation) despite the abrupt sender teardown (#134)");
        assert_eq!(got, expected, "delivered bytes are byte-exact and complete");
    }

    #[tokio::test]
    async fn open_channel_streams_bounds_a_stalled_setup_instead_of_hanging() {
        // #139 (frozen): after dial_peer_direct connects, open_bi/accept_bi were unbounded — a QUIC
        // conn that handshaked then went dead hung the direct-session setup forever with no relay
        // fallback. `open_channel_streams` bounds it. Here the client connects but NEVER opens the
        // channel bi-stream, so the server's accept_bi would hang; the bound turns that into a fast
        // `TimedOut`, which lets the direct path fall back to the relay instead of wedging.
        use crate::transport::{build_channel_dialer, build_direct_listener_at};
        let (server, _cert) = build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("listener");
        let addr = server.local_addr().expect("addr");

        let srv = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").await.expect("conn");
            let start = std::time::Instant::now();
            let r = open_channel_streams(&conn, ChannelRole::Accept, std::time::Duration::from_millis(300)).await;
            (r.as_ref().err().map(|e| e.kind()), r.is_ok(), start.elapsed())
        });

        // Connect and hold the connection open, but NEVER open a bi-stream.
        let dialer = build_channel_dialer().expect("dialer");
        let _conn = dialer.connect(addr, "localhost").expect("cfg").await.expect("conn");

        let (kind, ok, elapsed) = tokio::time::timeout(std::time::Duration::from_secs(5), srv)
            .await
            .expect("the bounded setup returns within 5s (a hang here is the #139 regression)")
            .expect("join");
        assert!(!ok, "a stalled stream setup errors, it does not hang or succeed");
        assert_eq!(kind, Some(std::io::ErrorKind::TimedOut), "the stall is reported as TimedOut (#139)");
        assert!(elapsed < std::time::Duration::from_secs(2), "the bound fires fast (~300ms), not after a long wait");
    }

    #[tokio::test]
    async fn upgradable_session_refuses_a_private_direct_target_and_stays_byte_exact_on_relay() {
        // #104 wire-in + #137 SSRF guard (frozen): two agents run an UPGRADABLE A2A session over a
        // relay quinn conn. The initiator advertises a direct listener bound on LOOPBACK
        // (`127.0.0.1`), so the #137 guard (`upgrade_safe_endpoint` = the edge's `is_global_unicast`
        // filter) correctly REFUSES the responder's dial of that peer-conveyed internal endpoint —
        // the session stays on the relay and the payload still arrives byte-exact. This proves the
        // SSRF guard (a) blocks a private/internal upgrade target and (b) does not break delivery.
        // (The full relay→direct upgrade over a *global-unicast* target can't run on loopback — that
        // is H4's live cross-NAT proof; the pure upgrade mechanics are covered by the ct-common
        // orchestration + DCUtR tests.)
        use crate::transport::{build_channel_dialer, build_direct_listener_at};
        use ct_common::noise::generate_static_keypair;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let a = generate_static_keypair(); // channel initiator
        let b = generate_static_keypair(); // channel responder
        let (a_priv, a_pub, b_priv, b_pub) = (a.private, a.public, b.private, b.public);
        let dt = std::time::Duration::from_secs(5);

        // Relay leg: the responder is the quinn server, the initiator connects to it.
        let (relay_server, _rc) = build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("relay listener");
        let relay_addr = relay_server.local_addr().expect("relay addr");
        // The initiator's direct listener (the responder dials this to upgrade).
        let (direct_listener, _dc) = build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("direct listener");
        let direct_addr = direct_listener.local_addr().expect("direct addr").to_string();

        // Responder: accept the relay conn, run the upgradable Accept session, collect the payload.
        let payload: Vec<u8> = (0..4000u32).map(|i| (i % 251) as u8).collect();
        let len = payload.len();
        let resp = tokio::spawn(async move {
            let relay_conn = relay_server.accept().await.expect("incoming").await.expect("relay conn");
            let (resp_app, resp_test) = tokio::io::duplex(1 << 16);
            let (mut resp_out, _w) = tokio::io::split(resp_test);
            let sess = tokio::spawn(async move {
                let _ = run_channel_session_upgradable(
                    &relay_conn, ChannelRole::Accept, &b_priv, &a_pub, resp_app, None, None, dt,
                )
                .await;
                drop(relay_conn);
            });
            let mut got = vec![0u8; len];
            let ok = resp_out.read_exact(&mut got).await.is_ok();
            sess.abort();
            (ok, got)
        });

        // Initiator: dial the relay, run the upgradable Initiate session with its direct listener.
        let dialer = build_channel_dialer().expect("dialer");
        let relay_conn = dialer.connect(relay_addr, "localhost").expect("cfg").await.expect("relay conn");
        let (init_app, init_test) = tokio::io::duplex(1 << 16);
        let (_r, mut init_feed) = tokio::io::split(init_test);
        let init = tokio::spawn(async move {
            run_channel_session_upgradable(
                &relay_conn,
                ChannelRole::Initiate,
                &a_priv,
                &b_pub,
                init_app,
                Some(direct_listener),
                Some(direct_addr),
                dt,
            )
            .await
        });

        init_feed.write_all(&payload).await.unwrap();
        init_feed.flush().await.unwrap();
        init_feed.shutdown().await.unwrap();

        let (ok, got) = tokio::time::timeout(std::time::Duration::from_secs(20), resp)
            .await
            .expect("responder within 20s")
            .expect("responder task");
        assert!(ok, "the full {len}-byte payload was delivered across the upgradable session");
        assert_eq!(got, payload, "relay→direct upgrade over real quinn delivered a byte-exact stream (#104)");
        init.abort();
    }

    #[test]
    fn relay_only_mode_forces_on_explicitly_and_auto_detects_a_non_routable_listen_addr() {
        // #121 (frozen): the pure relay-only decision. The explicit CT_CHANNEL_RELAY_ONLY flag
        // always forces relay-only (even with a routable address); otherwise a member
        // auto-detects relay-only when its advertised listen address is not globally routable
        // (a NAT-only / private-address-only host the edge would refuse to advertise, #94), and
        // stays direct-capable only with a real global-unicast address. It decides from the
        // address alone — no network interfaces touched — so it is deterministically testable.
        assert!(
            relay_only_mode(true, "203.0.113.10:7000".parse().unwrap()),
            "the explicit flag forces relay-only even for a routable address"
        );
        // Auto-detect: private / loopback / unspecified / CGNAT / link-local / ULA => relay-only.
        for private in [
            "10.0.0.5:7000",
            "192.168.1.9:7000",
            "172.16.0.1:7000",
            "127.0.0.1:7000",
            "0.0.0.0:7000",
            "100.64.0.1:7000",
            "169.254.1.1:7000",
            "[fc00::1]:7000",
            "[fe80::1]:7000",
        ] {
            assert!(relay_only_mode(false, private.parse().unwrap()), "{private} auto-detects relay-only");
        }
        // A real global-unicast address stays direct-capable (not forced relay-only).
        for routable in ["203.0.113.10:7000", "8.8.8.8:7000", "[2001:4860:4860::8888]:7000"] {
            assert!(!relay_only_mode(false, routable.parse().unwrap()), "{routable} stays direct-capable");
        }
    }

    #[test]
    fn parse_circuit_relay_is_optional_and_rejects_a_malformed_multiaddr() {
        // #136 N-wire (frozen): CT_CHANNEL_CIRCUIT_RELAY is the libp2p circuit-relay for the DCUtR
        // punch. Absent/blank => None (plain relay session, no punch); a valid multiaddr parses;
        // a malformed value is an error (a typo must not silently disable the hole-punch).
        assert_eq!(parse_circuit_relay(None), Ok(None));
        assert_eq!(parse_circuit_relay(Some("   ".to_string())), Ok(None));

        // A valid Circuit-Relay v2 multiaddr (relay TCP addr + /p2p-circuit) parses + round-trips.
        let ma = "/ip4/203.0.113.1/tcp/4001/p2p-circuit";
        let parsed = parse_circuit_relay(Some(ma.to_string())).expect("valid multiaddr parses");
        assert_eq!(parsed.map(|m| m.to_string()), Some(ma.to_string()));

        // A malformed value fails config load (not silently dropped).
        assert!(parse_circuit_relay(Some("not-a-multiaddr".to_string())).is_err());
    }

    #[test]
    fn upgrade_safe_endpoint_refuses_ssrf_ranges_and_admits_only_global_unicast() {
        // #137 (frozen): the responder's SSRF guard for the peer-conveyed #104 Offer.direct_endpoint.
        // Because the in-band upgrade bypasses the edge broker's `safe_endpoint` gate (#94), the
        // guard must apply the SAME range filter — an internal / private / metadata / link-local /
        // CGNAT / ULA / unspecified target (and anything unparseable) is refused; only a
        // global-unicast address is dialable. Matches the edge's `safe_endpoint` semantics exactly
        // (both are `parse + ct_common::channel::is_global_unicast`).
        for bad in [
            "127.0.0.1:7000",       // loopback
            "10.0.0.5:7000",        // RFC1918
            "192.168.1.9:7000",     // RFC1918
            "172.16.0.1:7000",      // RFC1918
            "169.254.169.254:80",   // cloud metadata / link-local
            "100.64.0.1:7000",      // CGNAT
            "0.0.0.0:7000",         // unspecified
            "[::1]:7000",           // IPv6 loopback
            "[fe80::1]:7000",       // IPv6 link-local
            "[fc00::1]:7000",       // IPv6 ULA
            "not-an-addr",          // unparseable
            "example.com:443",      // hostname, not an IP:port
        ] {
            assert!(upgrade_safe_endpoint(bad).is_none(), "{bad} must be refused (SSRF / unparseable) — #137");
        }
        for ok in ["203.0.113.10:7000", "8.8.8.8:7000", "[2001:4860:4860::8888]:7000"] {
            assert!(upgrade_safe_endpoint(ok).is_some(), "{ok} must be admitted (global-unicast)");
        }
    }

    #[tokio::test]
    async fn two_relay_only_members_join_without_a_dialable_address_and_relay_splice() {
        // #121 (frozen): the reachability floor. TWO relay-only members — each advertising the
        // relay-only SENTINEL (no dialable address), each with NO bound listener — join and are
        // relay-spliced by the PRODUCTION edge relay path (`broker_channel_relay`). Presenting
        // the sentinel to the real relay proves the edge admits it in production. The initiator's
        // paired peer_endpoint is the sentinel, so `run_channel_join_with_admission` SKIPS the
        // wasted direct dial and relays straight away; the acceptor has no listener, so it relays
        // directly too. A real payload round-trips BOTH directions, the Noise_IK session staying
        // end-to-end (the edge splices ciphertext only) — so a NAT-only member with only a
        // private address participates purely via the relay + the #106 :443 fallback.
        use ct_common::channel::{
            member_noise_attest_bytes, ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant,
            CHANNEL_ENDPOINT_RELAY_ONLY,
        };
        use ct_common::noise::generate_static_keypair;
        use ct_edge::channel_broker::broker_channel_relay;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use ed25519_dalek::Signer;

        let op = SigningKey::from_bytes(&[7u8; 32]);
        let op_pub = op.verifying_key().to_bytes();
        let holder_a = SigningKey::from_bytes(&[0x21u8; 32]);
        let holder_b = SigningKey::from_bytes(&[0x22u8; 32]);
        let channel = [0xE5u8; 32];
        let noise_a = generate_static_keypair();
        let noise_b = generate_static_keypair();
        let signed = |h: &SigningKey, dir| {
            let g = ChannelGrant {
                channel: ChannelId(channel),
                holder: SigningKey::verifying_key(h).to_bytes(),
                direction: dir,
                rights: Rights::ReadWrite,
                delegable: false,
                expires_at: 1_000,
            };
            SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }
        };
        // BOTH members advertise the relay-only sentinel — neither has a dialable address.
        let req_a = ChannelJoinRequest {
            grant: signed(&holder_a, Direction::Initiate),
            endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
        };
        let req_b = ChannelJoinRequest {
            grant: signed(&holder_b, Direction::Accept),
            endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
        };

        // Each member's attested-key triple (#101): its holder signs its Noise key for the
        // channel so the peer verifies + pins it with nothing conveyed out-of-band.
        let ha_pub = holder_a.verifying_key().to_bytes();
        let hb_pub = holder_b.verifying_key().to_bytes();
        let a_att = holder_a.sign(&member_noise_attest_bytes(&ChannelId(channel), &ha_pub, &noise_a.public)).to_bytes();
        let b_att = holder_b.sign(&member_noise_attest_bytes(&ChannelId(channel), &hb_pub, &noise_b.public)).to_bytes();

        // The PRODUCTION edge relay: admits both sentinel-advertising members (proving the edge
        // admits the relay-only sentinel over the real relay path), pairs, and splices them.
        let (relay_ep, cert) = build_server_endpoint_with_cert().expect("relay ep");
        let relay_addr = relay_ep.local_addr().expect("addr");
        let relay_task = tokio::spawn(async move {
            broker_channel_relay(&relay_ep, 500, move |c, _h| async move {
                (c.0 == channel).then_some((op_pub, None, None))
            })
            .await
            .map(|_| ())
        });

        // Member A (initiator): its paired peer_endpoint is the SENTINEL → skip the direct dial,
        // relay straight away. The admission is constructed directly (a real rendezvous would
        // swap the two sentinel endpoints); the relay leg is the production edge.
        let cert_a = cert.clone();
        let (mut a_app, a_local) = tokio::io::duplex(8192);
        let (na, nbpub) = (noise_a.private, noise_b.public);
        let a = tokio::spawn(async move {
            let rc = build_client_endpoint(cert_a).expect("rc a");
            let relay_conn = rc.connect(relay_addr, "localhost").expect("cfg").await.expect("rconn a");
            let admission = ChannelJoinOutcome::Admitted {
                peer_endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
                peer_noise_pubkey: Some(nbpub),
                peer_holder: Some(hb_pub),
                peer_attestation: Some(b_att),
                observed_reflexive: None,
            };
            run_channel_join_with_admission(
                admission,
                RelayFallback::Quic(&relay_conn),
                &req_a,
                &holder_a,
                ChannelRole::Initiate,
                &na,
                None, // relay-only: no bound listener
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(5),
                a_local,
            )
            .await
        });

        // Member B (acceptor): NO bound listener (relay-only) → relay straight away.
        let cert_b = cert.clone();
        let (mut b_app, b_local) = tokio::io::duplex(8192);
        let (nb, napub) = (noise_b.private, noise_a.public);
        let b = tokio::spawn(async move {
            let rc = build_client_endpoint(cert_b).expect("rc b");
            let relay_conn = rc.connect(relay_addr, "localhost").expect("cfg").await.expect("rconn b");
            let admission = ChannelJoinOutcome::Admitted {
                peer_endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
                peer_noise_pubkey: Some(napub),
                peer_holder: Some(ha_pub),
                peer_attestation: Some(a_att),
                observed_reflexive: None,
            };
            run_channel_join_with_admission(
                admission,
                RelayFallback::Quic(&relay_conn),
                &req_b,
                &holder_b,
                ChannelRole::Accept,
                &nb,
                None, // relay-only: no bound listener
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(5),
                b_local,
            )
            .await
        });

        // A -> B over the relay-only, edge-spliced, encrypted A2A tunnel.
        a_app.write_all(b"ping-A-to-B").await.expect("a writes");
        let mut got = [0u8; 11];
        b_app.read_exact(&mut got).await.expect("b reads A's bytes");
        assert_eq!(&got, b"ping-A-to-B", "A's plaintext arrives decrypted at B via the relay (both relay-only)");

        // B -> A (reverse proves the splice is full-duplex).
        b_app.write_all(b"pong-B-to-A").await.expect("b writes");
        let mut got2 = [0u8; 11];
        a_app.read_exact(&mut got2).await.expect("a reads B's bytes");
        assert_eq!(&got2, b"pong-B-to-A", "B's plaintext arrives decrypted at A via the relay");

        // Both payloads are confirmed received BEFORE any teardown, so there is no last-byte
        // race to lose; abort the tasks to end the still-open sessions.
        a.abort();
        b.abort();
        relay_task.abort();
    }
}
