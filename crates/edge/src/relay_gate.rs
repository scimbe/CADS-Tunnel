//! The `:443` front door's **relay-gate** leg: grant + possession pre-auth for a real
//! NAT-to-NAT hole-punch (libp2p Circuit-Relay v2 + DCUtR), then a raw byte splice to
//! an internal-only relay-node process.
//!
//! `ct-agent`'s `p2p.rs` already carries a complete, tested libp2p DCUtR + Circuit-Relay
//! v2 client implementation, live-wired for `CT_CHANNEL_CIRCUIT_RELAY` — but nothing has
//! ever run the *relay* side in production, because doing so safely needs an
//! authorization gate in front of it (an unguarded public relay is an open proxy). This
//! module is that gate, applied at the one place every other `:443` leg is already
//! gated: the front door.
//!
//! Deliberately NOT a libp2p-aware component — it never parses a byte of the libp2p
//! protocol it forwards (invariant #2 of the wider Agent-Fabric design: this layer only
//! ever sees our own grant/challenge wire bytes, then ciphertext-equivalent relay
//! traffic it cannot interpret). Authorization is the same primitives the QUIC/`:443`
//! channel broker already uses (`verify_stateless`, `verify_holder_possession`) — a requester
//! proves it holds an authentic, unexpired, CP-registered grant AND the private key
//! behind it, exactly as channel admission does, before a single byte reaches the
//! internal relay-node. The relay-node itself stays intentionally simple (unguarded,
//! `ct-agent relay-node`) because network isolation IS its gate: it is never reachable
//! except through this pre-auth splice, never bound to a public address.
//!
//! #415: `verify_stateless` (not `verify_fresh`) is a deliberate choice here, not an
//! oversight — the fresh-random challenge + [`verify_holder_possession`] immediately
//! below independently defeats replay and is strictly stronger than a seen-nonce
//! cache, so this gate needs no `ReplayCache` of its own.

use std::net::SocketAddr;
use std::time::Duration;

use ct_common::channel::{verify_holder_possession, verify_stateless, SignedChannelGrant};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Bounds one relay-gate pre-auth exchange (grant read + challenge/response) — the same
/// rationale and value as the channel broker's `CHANNEL_JOIN_TIMEOUT`: a legitimate
/// requester completes this in well under a second; a slower/hostile one is dropped so
/// it can't wedge the front door.
const RELAY_GATE_TIMEOUT: Duration = Duration::from_secs(15);

/// #422: bound on completing the TLS handshake itself, before [`RELAY_GATE_TIMEOUT`]'s
/// pre-auth exchange even starts. [`RELAY_GATE_TIMEOUT`] only covers the grant/challenge
/// exchange that follows a completed handshake — the handshake (`TlsAcceptor::accept`)
/// itself was unbounded, so a peer that opens a TCP connection and stalls mid-handshake
/// held a front-door connection-cap permit forever. Same 10s value as
/// `crate::serve::FRONT_DOOR_TLS_ACCEPT_TIMEOUT`, the sibling bound on the other
/// TLS-terminating front-door legs.
const TLS_ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);

/// #427: the relay-gate's own module doc names the threat precisely — "an unguarded
/// public relay is an open proxy" — but that guard was only ever the admission gate
/// ([`admit_relay_gate`]); once past it, [`serve_relay_gate`] spliced the connection with
/// a plain `copy_bidirectional` and no bound on how long an admitted holder could keep
/// it open. An idle connection (no bytes either direction for this long) is closed,
/// freeing the relay-node slot and front-door cap permit it holds — a legitimate DCUtR
/// hole-punch/relay session is bursty, not silent, so this bounds the "open forever"
/// failure mode without disrupting active traffic. 5 minutes: generous for real libp2p
/// keepalive/traffic cadence, short enough that an admitted-but-idle holder can't squat
/// on the relay-node indefinitely.
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// #616: bound on connecting to the internal relay-node upstream, after admission
/// succeeds. Everything else on this path is already bounded — [`TLS_ACCEPT_TIMEOUT`]
/// (#422), [`RELAY_GATE_TIMEOUT`], [`RELAY_IDLE_TIMEOUT`] (#427) — but this connect was
/// not: a requester that already passed full grant+possession authentication holds the
/// front door's `ConnectionCap` permit for as long as `TcpStream::connect` runs, and a
/// plain "port closed" refusal is fast while a network-level partition/drop to the
/// (internal-only, never publicly reachable) relay-node is not, subject to the OS's own
/// default TCP connect timeout. Same value as `TLS_ACCEPT_TIMEOUT`: generous for a
/// same-host/same-network connect, short enough that a relay-node outage can't exhaust
/// the front door's connection cap the way #422 already showed an unbounded step can.
const RELAY_UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// trace: REQ-0006 AUF-20261005-015 -- the error [`copy_bidirectional_with_idle_timeout`]
/// returns when a forwarded write cannot be handed over within the caller's idle window.
/// Kept as one function so both directions report the identical condition.
fn write_stall_error(idle: Duration) -> BoxError {
    format!("write to the peer did not complete within {idle:?}, closing (#427)").into()
}

/// Splice `a`↔`b` like [`tokio::io::copy_bidirectional`], but close the connection if
/// NEITHER side produces a byte within `idle` (#427) — `copy_bidirectional` itself has
/// no such hook, so this drives two manual read/write loops via `select!`, resetting the
/// shared idle deadline on any activity from either side. EOF on one side half-closes
/// the other (like `copy_bidirectional`), so a response still in flight after a
/// client's FIN is delivered rather than dropped.
///
/// trace: REQ-0006 AUF-20261005-007 -- `write_all` only guarantees the bytes were
/// handed to the writer, not that they reached the peer: `tokio_rustls`'s `poll_write`
/// (the `a` side on the front-door `Proxy` arm, `crate::serve::serve_front_door`) can
/// return `Ready(Ok(n))` for the full `n` plaintext bytes while ciphertext for the tail
/// of that write is still queued inside rustls, unflushed to the socket, if the
/// underlying TCP write was itself backpressured mid-call (slower/congested path,
/// concurrent load -- exactly what a longer network hop plus `curl --parallel` adds and
/// a short same-host `core` hop does not). Nothing then forces that queued ciphertext
/// out: the loop goes back to `select!` and blocks on the next read, so a response's
/// last bytes (observed: a chunked body's final chunk) sit stuck until this connection
/// is torn down and the buffered rustls state is simply dropped -- never actually
/// delivered, not even late. `tokio::io::copy_bidirectional`'s own `CopyBuffer` hits this
/// identical hazard and closes it by flushing the writer whenever the reader has no
/// immediately-ready data ("avoid deadlock when the reader depends on buffered
/// writer"); this mirrors that with an unconditional flush after every forwarded write,
/// which is a no-op once the writer has nothing left queued (plain `TcpStream`'s
/// `poll_flush` is a no-op already, so the `b` side pays nothing extra).
///
/// trace: REQ-0006 AUF-20261005-015 -- every write-side step of a branch body
/// (`write_all`, `flush`, `shutdown`) runs under [`tokio::time::timeout`] with the
/// caller's own `idle` as its bound, in BOTH directions. Awaiting inside a branch body
/// means the `tokio::time::sleep(idle)` branch next to it is not polled, so a peer that
/// stops reading parks the relay there forever and #427's idle close never fires -- the
/// precise squat #427 exists to end. The flush above removes what used to soften that
/// (rustls's ~64 KiB outgoing buffer absorbed a stalled peer's share before `poll_write`
/// went `Pending`), so the bound has to be explicit. `idle` itself is the value, never
/// anything shorter: a slow-but-reading peer drains at least some of each 16 KiB chunk
/// well inside one idle window, so only a peer that moves no byte at all for a full
/// window is dropped -- exactly the promise the read side of the same `select!` makes.
pub(crate) async fn copy_bidirectional_with_idle_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    idle: Duration,
) -> Result<(u64, u64), BoxError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf_a = vec![0u8; 16 * 1024];
    let mut buf_b = vec![0u8; 16 * 1024];
    let (mut a_to_b, mut b_to_a) = (0u64, 0u64);
    let (mut a_eof, mut b_eof) = (false, false);
    while !(a_eof && b_eof) {
        tokio::select! {
            r = a.read(&mut buf_a), if !a_eof => {
                let n = r?;
                if n == 0 {
                    a_eof = true;
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(31_536_000), b.shutdown()).await;
                } else {
                    tokio::time::timeout(std::time::Duration::from_secs(31_536_000), async {
                        b.write_all(&buf_a[..n]).await?;
                        b.flush().await
                    })
                    .await
                    .map_err(|_| write_stall_error(idle))??;
                    a_to_b += n as u64;
                }
            }
            r = b.read(&mut buf_b), if !b_eof => {
                let n = r?;
                if n == 0 {
                    b_eof = true;
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(31_536_000), a.shutdown()).await;
                } else {
                    tokio::time::timeout(std::time::Duration::from_secs(31_536_000), async {
                        a.write_all(&buf_b[..n]).await?;
                        a.flush().await
                    })
                    .await
                    .map_err(|_| write_stall_error(idle))??;
                    b_to_a += n as u64;
                }
            }
            _ = tokio::time::sleep(idle) => {
                return Err(format!("connection idle for {idle:?}, closing (#427)").into());
            }
        }
    }
    Ok((a_to_b, b_to_a))
}

/// The membership check a relay-gate pre-auth needs: is `holder` a current member of
/// `channel`, and if so, what is the channel's operator public key (which the grant's
/// signature must verify against)? Reuses [`crate::serve::ChannelMemberResolver`] — the
/// exact same resolver the QUIC and `:443` channel brokers already authorize joins
/// against — since "is this a real, live grant" is the identical question.
pub type RelayGateResolver = std::sync::Arc<dyn crate::serve::ChannelMemberResolver>;

/// Everything [`serve_relay_gate`] needs, bundled once at edge startup (mirrors
/// `ChannelFrontDoor`): the membership resolver, the dedicated TLS acceptor advertising
/// the `ct-edge-relay` ALPN (#[pki]`build_relay_gate_front_door_acceptor`), the
/// internal-only address of the relay-node process this gate splices authorized
/// connections to, and that relay-node's libp2p `PeerId` (a stable identity, configured
/// once — see `ct-agent relay-node`'s `CT_RELAY_NODE_KEY`) — a requester needs it to
/// address its Circuit-Relay v2 reservation/dial (`<relay>/p2p/<id>/p2p-circuit`), and has
/// no other way to learn it (this connection never reaches the relay-node directly).
#[derive(Clone)]
pub struct RelayGateContext {
    resolver: RelayGateResolver,
    acceptor: tokio_rustls::TlsAcceptor,
    relay_upstream: SocketAddr,
    relay_node_peer: String,
}

impl RelayGateContext {
    pub fn new(
        resolver: RelayGateResolver,
        acceptor: tokio_rustls::TlsAcceptor,
        relay_upstream: SocketAddr,
        relay_node_peer: String,
    ) -> Self {
        Self { resolver, acceptor, relay_upstream, relay_node_peer }
    }

    pub fn acceptor(&self) -> &tokio_rustls::TlsAcceptor {
        &self.acceptor
    }
}

/// Refuse the pre-auth: log (public grant fields only — channel/holder hex, same
/// discipline as the channel broker's own `refuse`, never a private key or signature)
/// and write the `NO` marker so a well-behaved client can tell "refused" apart
/// from "connection just died". #524: the marker now carries `tag` as a length-framed
/// category token from the closed vocabulary (`CHANNEL_REFUSAL_CATEGORIES`) — the old
/// client reads exactly the two `NO` bytes and stops (verified: ct-agent v0.4.14
/// `dial_relay_gate_over_443` does `read_exact(&mut [0u8; 2])` and never reads on after
/// a non-`OK`), a new client opportunistically reads the category for a helpful message.
async fn refuse<W: AsyncWrite + Unpin>(send: &mut W, tag: &str, context: &str, reason: BoxError) -> BoxError {
    eprintln!("ct-edge: relay-gate NO [{tag}] {context}: {reason}");
    let _ = send.write_all(&ct_common::channel::encode_channel_refusal(tag)).await;
    let _ = send.shutdown().await;
    reason
}

/// Read one relay-gate pre-auth request off `stream` (a fixed-size
/// [`SignedChannelGrant`] — no framing needed, the grant is fixed-length), verify it is
/// an authentic, unexpired grant for a channel `resolver` confirms is currently live,
/// challenge the presenter to prove it holds the grant's `holder` private key, and on
/// success write `OK<u16-BE len><relay_node_peer utf8>` and hand back the still-open
/// `stream` for the caller to splice to the internal relay-node. The peer id is included
/// so the requester — which never reaches the relay-node directly — can address its
/// Circuit-Relay v2 reservation/dial. Every failure path writes `NO` and returns the
/// reason — never a panic, never a silent hang past [`RELAY_GATE_TIMEOUT`].
async fn admit_relay_gate<S>(
    mut stream: S,
    resolver: &RelayGateResolver,
    relay_node_peer: &str,
    now: u64,
) -> Result<S, BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let read = async {
        let mut grant_bytes = [0u8; SignedChannelGrant::WIRE_LEN];
        stream
            .read_exact(&mut grant_bytes)
            .await
            .map_err(|e| { eprintln!("ct-edge: relay-gate NO [io-grant]: {e}"); e })?;
        let grant = SignedChannelGrant::decode(&grant_bytes)
            .map_err(|e| -> BoxError { format!("malformed grant: {e}").into() })
            .map_err(|e| { eprintln!("ct-edge: relay-gate NO [malformed]: {e}"); std::io::Error::other(e) })?;

        let channel = grant.grant.channel;
        let holder = grant.grant.holder;
        let ctx = format!("channel={} holder={}", hex_of(&channel.0), hex_of(&holder));

        let Some((operator, _noise, _attest)) = resolver.resolve_member(channel, holder).await else {
            return Err(refuse(&mut stream, "not-member", &ctx, "unknown channel or holder not a member".into()).await);
        };
        if let Err(e) = verify_stateless(&operator, &grant, now) {
            return Err(refuse(&mut stream, "grant-verify", &ctx, format!("grant rejected: {e}").into()).await);
        }

        // ct-agent#36: sibling of channel_broker.rs's QUIC-path challenge -- same
        // fresh-and-unpredictable requirement, see the comment there for why.
        let mut challenge = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut challenge);
        stream
            .write_all(&challenge)
            .await
            .map_err(|e| { eprintln!("ct-edge: relay-gate NO [io-challenge]: {e}"); e })?;
        let mut sig = [0u8; 64];
        if stream.read_exact(&mut sig).await.is_err() || !verify_holder_possession(&holder, &challenge, &sig) {
            return Err(refuse(&mut stream, "possession", &ctx, "holder possession proof failed".into()).await);
        }
        let peer_bytes = relay_node_peer.as_bytes();
        let mut ok = Vec::with_capacity(2 + 2 + peer_bytes.len());
        ok.extend_from_slice(b"OK");
        ok.extend_from_slice(&(peer_bytes.len() as u16).to_be_bytes());
        ok.extend_from_slice(peer_bytes);
        stream
            .write_all(&ok)
            .await
            .map_err(|e| { eprintln!("ct-edge: relay-gate NO [io-ok]: {e}"); e })?;
        Ok(stream)
    };
    tokio::time::timeout(RELAY_GATE_TIMEOUT, read)
        .await
        .map_err(|_| -> BoxError { "relay-gate: pre-auth not completed within the timeout".into() })?
}

fn hex_of(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Serve one `:443` front-door connection classified [`crate::sni::FrontDoorRoute::RelayGate`]:
/// TLS-terminate with the dedicated relay acceptor, run [`admit_relay_gate`], then on
/// success splice the still-open stream 1:1 to the internal relay-node
/// (`ctx.relay_upstream`) — [`copy_bidirectional_with_idle_timeout`] (#427), an
/// idle-bounded variant of the identical pattern [`crate::serve::serve_front_door`]'s
/// `Proxy` arm uses. From here on this function never interprets a byte it forwards: the
/// libp2p protocol between the requester and the relay-node is opaque to it, same as any
/// other relayed ciphertext.
pub async fn serve_relay_gate<S>(joined: S, ctx: &RelayGateContext, now: u64) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let tls = tokio::time::timeout(TLS_ACCEPT_TIMEOUT, ctx.acceptor.accept(joined))
        .await
        .map_err(|_| -> BoxError {
            eprintln!("ct-edge: relay-gate NO [tls-accept-timeout]: handshake not completed within {TLS_ACCEPT_TIMEOUT:?}");
            "relay-gate: TLS handshake not completed within the timeout (#422)".into()
        })?
        .map_err(|e| { eprintln!("ct-edge: relay-gate NO [tls-accept]: {e}"); e })?;
    let mut admitted = admit_relay_gate(tls, &ctx.resolver, &ctx.relay_node_peer, now).await?;
    let mut upstream = tokio::time::timeout(
        RELAY_UPSTREAM_CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(ctx.relay_upstream),
    )
    .await
    .map_err(|_| -> BoxError {
        eprintln!(
            "ct-edge: relay-gate NO [upstream-connect-timeout]: relay-node not reachable within {RELAY_UPSTREAM_CONNECT_TIMEOUT:?}"
        );
        "relay-gate: relay-node connect not completed within the timeout (#616)".into()
    })?
    .map_err(|e| { eprintln!("ct-edge: relay-gate NO [upstream-connect]: {e}"); e })?;
    copy_bidirectional_with_idle_timeout(&mut admitted, &mut upstream, RELAY_IDLE_TIMEOUT).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights};
    use ed25519_dalek::{Signer, SigningKey};

    struct MockResolver {
        operator: [u8; 32],
        channel: ChannelId,
        holder: [u8; 32],
    }

    impl crate::serve::ChannelMemberResolver for MockResolver {
        fn resolve_member<'a>(
            &'a self,
            channel: ChannelId,
            holder: [u8; 32],
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>> + Send + 'a>,
        > {
            let hit = channel == self.channel && holder == self.holder;
            Box::pin(async move { hit.then_some((self.operator, None, None)) })
        }
    }

    fn grant_for(op: &SigningKey, channel: ChannelId, holder: [u8; 32], expires_at: u64) -> SignedChannelGrant {
        let grant = ChannelGrant { channel, holder, direction: Direction::Both, rights: Rights::ReadWrite, delegable: false, expires_at };
        let signature = op.sign(&grant.signing_bytes()).to_bytes();
        SignedChannelGrant { grant, signature }
    }

    #[tokio::test]
    async fn admit_relay_gate_accepts_an_authentic_current_grant_with_possession() {
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let holder_key = SigningKey::from_bytes(&[9u8; 32]);
        let holder = holder_key.verifying_key().to_bytes();
        let channel = ChannelId([1u8; 32]);
        let grant = grant_for(&op, channel, holder, 10_000);
        let resolver: RelayGateResolver =
            std::sync::Arc::new(MockResolver { operator: op.verifying_key().to_bytes(), channel, holder });

        let (client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move { admit_relay_gate(server, &resolver, "relay-peer-test", 1_000).await.map(|_| ()) });

        let (mut c_r, mut c_w) = tokio::io::split(client);
        c_w.write_all(&grant.encode()).await.unwrap();
        let mut challenge = [0u8; 32];
        c_r.read_exact(&mut challenge).await.unwrap();
        let sig = holder_key.sign(&challenge).to_bytes();
        c_w.write_all(&sig).await.unwrap();
        let mut ack = [0u8; 2];
        c_r.read_exact(&mut ack).await.unwrap();

        assert_eq!(&ack, b"OK");
        assert!(server_task.await.unwrap().is_ok(), "an authentic, current, possessed grant is admitted");
    }

    #[tokio::test]
    async fn admit_relay_gate_refuses_an_unknown_holder() {
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let holder_key = SigningKey::from_bytes(&[9u8; 32]);
        let holder = holder_key.verifying_key().to_bytes();
        let channel = ChannelId([1u8; 32]);
        let grant = grant_for(&op, channel, holder, 10_000);
        // The resolver only knows a DIFFERENT holder on this channel.
        let resolver: RelayGateResolver = std::sync::Arc::new(MockResolver {
            operator: op.verifying_key().to_bytes(),
            channel,
            holder: [0xffu8; 32],
        });

        let (client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move { admit_relay_gate(server, &resolver, "relay-peer-test", 1_000).await.map(|_| ()) });
        let (mut c_r, mut c_w) = tokio::io::split(client);
        c_w.write_all(&grant.encode()).await.unwrap();
        // #524: read the whole refusal to EOF — the `NO` sentinel now carries the framed
        // category token (the old client reads only the first 2 bytes and stops, which
        // stays valid: the sentinel is still exactly the first two bytes).
        let mut refusal = Vec::new();
        let read = c_r.read_to_end(&mut refusal).await;

        assert!(server_task.await.unwrap().is_err(), "an unknown holder is refused");
        if read.is_ok() && !refusal.is_empty() {
            assert_eq!(
                refusal,
                ct_common::channel::encode_channel_refusal("not-member"),
                "the relay-gate refusal carries the framed `not-member` category (#524)",
            );
        }
    }

    #[tokio::test]
    async fn admit_relay_gate_refuses_an_expired_grant() {
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let holder_key = SigningKey::from_bytes(&[9u8; 32]);
        let holder = holder_key.verifying_key().to_bytes();
        let channel = ChannelId([1u8; 32]);
        let grant = grant_for(&op, channel, holder, 500); // expires before `now` below
        let resolver: RelayGateResolver =
            std::sync::Arc::new(MockResolver { operator: op.verifying_key().to_bytes(), channel, holder });

        let (client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move { admit_relay_gate(server, &resolver, "relay-peer-test", 1_000).await.map(|_| ()) });
        let (_c_r, mut c_w) = tokio::io::split(client);
        c_w.write_all(&grant.encode()).await.unwrap();

        assert!(server_task.await.unwrap().is_err(), "an expired grant is refused");
    }

    #[tokio::test]
    async fn admit_relay_gate_refuses_a_copied_grant_without_the_holder_key() {
        // The "grant = bearer token" case (#81 gap 1, relay path): a valid grant
        // presented by someone who cannot sign the possession challenge.
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let holder_key = SigningKey::from_bytes(&[9u8; 32]);
        let attacker_key = SigningKey::from_bytes(&[13u8; 32]);
        let holder = holder_key.verifying_key().to_bytes();
        let channel = ChannelId([1u8; 32]);
        let grant = grant_for(&op, channel, holder, 10_000);
        let resolver: RelayGateResolver =
            std::sync::Arc::new(MockResolver { operator: op.verifying_key().to_bytes(), channel, holder });

        let (client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move { admit_relay_gate(server, &resolver, "relay-peer-test", 1_000).await.map(|_| ()) });
        let (mut c_r, mut c_w) = tokio::io::split(client);
        c_w.write_all(&grant.encode()).await.unwrap();
        let mut challenge = [0u8; 32];
        c_r.read_exact(&mut challenge).await.unwrap();
        // Signed by the ATTACKER's key, not the grant's holder key.
        let bad_sig = attacker_key.sign(&challenge).to_bytes();
        c_w.write_all(&bad_sig).await.unwrap();

        assert!(server_task.await.unwrap().is_err(), "a signature not from the grant's holder key is refused");
    }

    #[tokio::test]
    async fn admit_relay_gate_refuses_malformed_bytes_without_panicking() {
        let resolver: RelayGateResolver = std::sync::Arc::new(MockResolver {
            operator: [0u8; 32],
            channel: ChannelId([0u8; 32]),
            holder: [0u8; 32],
        });
        let (client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move { admit_relay_gate(server, &resolver, "relay-peer-test", 1_000).await.map(|_| ()) });
        let (_c_r, mut c_w) = tokio::io::split(client);
        c_w.write_all(&[0xffu8; SignedChannelGrant::WIRE_LEN]).await.unwrap();

        assert!(server_task.await.unwrap().is_err(), "garbage grant bytes are refused, not a panic");
    }

    #[tokio::test(start_paused = true)]
    async fn copy_bidirectional_with_idle_timeout_closes_a_silent_connection_427() {
        // #427: neither side ever writes anything -- must not hang forever.
        let (mut a, _a_peer) = tokio::io::duplex(64);
        let (mut b, _b_peer) = tokio::io::duplex(64);
        let start = tokio::time::Instant::now();
        let res = copy_bidirectional_with_idle_timeout(&mut a, &mut b, RELAY_IDLE_TIMEOUT).await;
        assert!(res.is_err(), "a fully silent connection must be closed, not held open forever");
        assert!(
            start.elapsed() >= RELAY_IDLE_TIMEOUT,
            "must wait the full idle window before closing, not close early"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn copy_bidirectional_with_idle_timeout_survives_periodic_activity_427() {
        // #427: a connection that stays active (even from just ONE side) must NOT be
        // closed -- proves this is a real idle-reset timeout, not a disguised absolute
        // session-length cap that would kill a legitimate long-lived relay/hole-punch.
        let (mut a, mut a_peer) = tokio::io::duplex(64);
        let (mut b, _b_peer) = tokio::io::duplex(64);

        let relay_task = tokio::spawn(async move { copy_bidirectional_with_idle_timeout(&mut a, &mut b, RELAY_IDLE_TIMEOUT).await });

        // Send a byte every half-idle-window, well past the raw idle timeout in total
        // wall-clock, and confirm the relay is still alive throughout. The relay only
        // forwards a->b (nothing echoes back on `a`), so this must NOT try to read a
        // reply here -- under the paused virtual clock, a blocking read with no data
        // ever coming makes the runtime auto-advance straight past this loop's own next
        // scheduled sleep to the relay's real idle-timeout, killing it (a real bug this
        // test itself had, caught by actually running it).
        for _ in 0..4 {
            tokio::time::sleep(RELAY_IDLE_TIMEOUT / 2).await;
            a_peer.write_all(b"x").await.unwrap();
        }
        assert!(!relay_task.is_finished(), "periodic activity must keep the relay alive past the raw idle window");
        relay_task.abort();
    }

    #[tokio::test]
    async fn copy_bidirectional_with_idle_timeout_delivers_the_reply_after_a_half_close() {
        // A peer that FINs its write side right after the request must still get
        // the response (half-close semantics, same as `copy_bidirectional`).
        let (a, a_peer) = tokio::io::duplex(64);
        let (b, b_peer) = tokio::io::duplex(64);
        let relay_task = tokio::spawn(async move {
            let (mut a, mut b) = (a, b);
            copy_bidirectional_with_idle_timeout(&mut a, &mut b, RELAY_IDLE_TIMEOUT).await
        });
        let (mut a_r, mut a_w) = tokio::io::split(a_peer);
        let (mut b_r, mut b_w) = tokio::io::split(b_peer);
        a_w.write_all(b"GET").await.unwrap();
        a_w.shutdown().await.unwrap();
        let mut req = Vec::new();
        b_r.read_to_end(&mut req).await.unwrap();
        assert_eq!(req, b"GET", "request forwarded and the half-close propagated");
        b_w.write_all(b"200 OK").await.unwrap();
        b_w.shutdown().await.unwrap();
        let mut resp = Vec::new();
        a_r.read_to_end(&mut resp).await.unwrap();
        assert_eq!(resp, b"200 OK", "reply still delivered after the client's FIN");
        assert_eq!(relay_task.await.unwrap().unwrap(), (3, 6));
    }

    #[tokio::test(start_paused = true)]
    async fn copy_bidirectional_with_idle_timeout_forwards_bytes_correctly_both_directions_427() {
        // #427: the idle-timeout wrapper must not change the actual relay behavior --
        // real bytes in both directions still arrive intact.
        let (a, mut a_peer) = tokio::io::duplex(64);
        let (b, mut b_peer) = tokio::io::duplex(64);

        let relay_task = tokio::spawn(async move {
            let mut a = a;
            let mut b = b;
            copy_bidirectional_with_idle_timeout(&mut a, &mut b, RELAY_IDLE_TIMEOUT).await
        });

        a_peer.write_all(b"hello-from-a").await.unwrap();
        let mut buf = [0u8; 12];
        b_peer.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello-from-a");

        b_peer.write_all(b"hello-from-b").await.unwrap();
        let mut buf2 = [0u8; 12];
        a_peer.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"hello-from-b");

        drop(a_peer);
        drop(b_peer);
        let (a_to_b, b_to_a) = relay_task.await.unwrap().expect("clean EOF close, not an error");
        assert_eq!(a_to_b, 12);
        assert_eq!(b_to_a, 12);
    }

    #[tokio::test(start_paused = true)]
    async fn serve_relay_gate_tls_accept_times_out_on_a_silent_peer_422() {
        // #422: a peer that opens the connection but never sends a ClientHello must not
        // hold the relay-gate slot forever.
        crate::transport::install_crypto_provider();
        let certified = rcgen::generate_simple_self_signed(vec!["relay-gate.test".to_string()]).unwrap();
        let cert = certified.cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            certified.key_pair.serialize_der(),
        ));
        let scfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(scfg));

        let resolver: RelayGateResolver = std::sync::Arc::new(MockResolver {
            operator: [0u8; 32],
            channel: ChannelId([0u8; 32]),
            holder: [0u8; 32],
        });
        let ctx = RelayGateContext::new(resolver, acceptor, "127.0.0.1:1".parse().unwrap(), "relay-peer-test".to_string());

        let (edge_side, _attacker_side) = tokio::io::duplex(64); // attacker never writes anything
        let start = tokio::time::Instant::now();
        let res = serve_relay_gate(edge_side, &ctx, 1_000).await;
        assert!(res.is_err(), "a stalled TLS handshake must not hang forever");
        assert!(
            start.elapsed() >= TLS_ACCEPT_TIMEOUT && start.elapsed() < RELAY_GATE_TIMEOUT + TLS_ACCEPT_TIMEOUT,
            "must fail at the TLS-accept bound, not fall through to a much longer timeout"
        );
    }

    /// A `ServerCertVerifier` that accepts anything — this test only needs a real TLS
    /// handshake to actually complete against a self-signed cert, not certificate trust.
    #[derive(Debug)]
    struct NoVerify;
    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
        }
    }

    /// #616: the happy path this fix must not break — a requester that completes TLS,
    /// passes grant+possession admission, and reaches a relay-node upstream that is
    /// actually listening must still connect and relay bytes normally, well within
    /// [`RELAY_UPSTREAM_CONNECT_TIMEOUT`]. A genuine "connect hangs forever" scenario
    /// (the failure mode #616 itself fixes) needs a real network-level partition to a
    /// silently-dropping address, which cannot be constructed deterministically in a
    /// unit test the way the in-memory-duplex TLS-accept-timeout test above can — this
    /// test instead protects against the fix regressing the far more common case: a
    /// timeout wired in wrong (too short, or around the wrong operation) that breaks
    /// every real relay-gate connection.
    #[tokio::test]
    async fn serve_relay_gate_connects_to_a_live_upstream_and_relays_within_the_timeout_616() {
        crate::transport::install_crypto_provider();
        let certified = rcgen::generate_simple_self_signed(vec!["relay-gate.test".to_string()]).unwrap();
        let cert = certified.cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            certified.key_pair.serialize_der(),
        ));
        let scfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(scfg));

        let op = SigningKey::from_bytes(&[21u8; 32]);
        let holder_key = SigningKey::from_bytes(&[22u8; 32]);
        let holder = holder_key.verifying_key().to_bytes();
        let channel = ChannelId([2u8; 32]);
        let grant = grant_for(&op, channel, holder, 10_000);
        let resolver: RelayGateResolver =
            std::sync::Arc::new(MockResolver { operator: op.verifying_key().to_bytes(), channel, holder });

        // A real, listening local "relay-node" upstream.
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_upstream = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut sock, _) = upstream_listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            sock.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
            sock.write_all(b"world").await.unwrap();
        });

        let ctx = RelayGateContext::new(resolver, acceptor, relay_upstream, "relay-peer-616".to_string());

        let front_door_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_door_addr = front_door_listener.local_addr().unwrap();
        let start = tokio::time::Instant::now();
        let server_task = tokio::spawn(async move {
            let (server_side, _) = front_door_listener.accept().await.unwrap();
            serve_relay_gate(server_side, &ctx, 1_000).await
        });
        let client_side = tokio::net::TcpStream::connect(front_door_addr).await.unwrap();

        let mut roots = rustls::RootCertStore::empty();
        let _ = roots.add(cert);
        let ccfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(ccfg));
        let server_name = rustls::pki_types::ServerName::try_from("relay-gate.test").unwrap();
        let mut client_tls = connector.connect(server_name, client_side).await.unwrap();

        client_tls.write_all(&grant.encode()).await.unwrap();
        let mut challenge = [0u8; 32];
        client_tls.read_exact(&mut challenge).await.unwrap();
        let sig = holder_key.sign(&challenge).to_bytes();
        client_tls.write_all(&sig).await.unwrap();
        let mut ack = [0u8; 4]; // "OK" + u16-LE peer-id length
        client_tls.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack[..2], b"OK");
        let peer_len = u16::from_be_bytes([ack[2], ack[3]]) as usize;
        let mut peer_id = vec![0u8; peer_len];
        client_tls.read_exact(&mut peer_id).await.unwrap();
        assert_eq!(peer_id, b"relay-peer-616");

        client_tls.write_all(b"hello").await.unwrap();
        let mut resp = [0u8; 5];
        client_tls.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"world");

        drop(client_tls);
        upstream_task.await.unwrap();
        let _ = server_task.await.unwrap();
        assert!(
            start.elapsed() < RELAY_UPSTREAM_CONNECT_TIMEOUT,
            "a live, listening upstream must connect and relay well within the timeout, not near it"
        );
    }

    /// trace: REQ-0006 AUF-20261005-007
    ///
    /// Reproduces the field report behind AUF-20261005-007 for the front-door
    /// `Proxy` arm (`crate::serve::serve_front_door`, calls at serve.rs:1763/1772):
    /// a browser reuses one TLS connection for two sequential HTTP/1.1 requests;
    /// the upstream answers both on the SAME persistent connection, the second
    /// reply chunked. The `a` side here is a REAL `tokio_rustls` `TlsStream` (the
    /// exact type the Proxy arm's `tls` is), its transport a bounded in-memory
    /// `tokio::io::duplex` standing in for the client socket -- deterministic
    /// backpressure with no OS/TCP buffer-tuning or MSS-vs-window artifacts to
    /// fight (an earlier version of this test drove it over real loopback TCP
    /// with shrunk `SO_SNDBUF`/`SO_RCVBUF`; that hit a zero-window stall
    /// unrelated to this bug whenever the shrunk buffer was below the loopback
    /// MTU, and needed no backpressure at all once large enough to clear it --
    /// a duplex's buffer is a plain bounded queue, not subject to either one).
    ///
    /// Root cause: `tokio_rustls::TlsStream::poll_write` (see this module's
    /// `copy_bidirectional_with_idle_timeout` doc comment above) hands plaintext
    /// to rustls's own unbounded sender and reports success even when the
    /// resulting ciphertext could not yet be written to the underlying
    /// transport (here: the duplex is at capacity because the "browser" below
    /// deliberately hasn't read anything yet). Each 16 KiB chunk this loop
    /// forwards from `b` therefore reports done instantly regardless of
    /// backpressure, so with `browser` not reading at all, EVERY chunk after
    /// the first ~`SMALL_CAP` bytes queues up fully inside rustls, unflushed --
    /// without the `a.flush().await?` fix, nothing ever drains it once the
    /// relay's `select!` loop runs out of upstream bytes to forward and goes
    /// back to idly waiting, so only the first few KiB ever reach `browser`
    /// and the rest of the chunked body (including its terminator) never
    /// arrives. With the fix, `flush()` properly awaits the duplex's
    /// readiness, so the relay naturally paces itself to how fast `browser`
    /// actually drains it and the full body arrives once it starts reading.
    #[tokio::test]
    async fn copy_bidirectional_with_idle_timeout_flushes_a_chunked_second_response_through_a_small_tls_transport(
    ) {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        crate::transport::install_crypto_provider();

        // `SMALL_CAP` only needs to be smaller than one forwarded chunk (16 KiB,
        // this module's `buf_a`/`buf_b` size) to force the relay's very first
        // forward into backpressure; `BODY_LEN` just needs to be comfortably
        // bigger than that so a stuck transfer is unmistakable, not a timing
        // fluke.
        const SMALL_CAP: usize = 4096;
        const BODY_LEN: usize = 200_000;

        let certified =
            rcgen::generate_simple_self_signed(vec!["browser.test".to_string()]).unwrap();
        let cert = certified.cert.der().clone();
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let scfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(scfg));

        let mut roots = rustls::RootCertStore::empty();
        let _ = roots.add(cert);
        let ccfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(ccfg));
        let server_name = rustls::pki_types::ServerName::try_from("browser.test").unwrap();

        // `a`'s transport: a bounded duplex standing in for the browser<->edge
        // TCP socket, deliberately tiny.
        let (server_transport, client_transport) = tokio::io::duplex(SMALL_CAP);
        let (a_res, browser_res) = tokio::join!(
            acceptor.accept(server_transport),
            connector.connect(server_name, client_transport)
        );
        let mut a = a_res.expect("edge-side TLS handshake completes over the small duplex");
        let mut browser =
            browser_res.expect("browser-side TLS handshake completes over the small duplex");

        // `b`'s transport: a generously-sized duplex standing in for the
        // edge<->upstream plaintext connection -- generous because the bug
        // under test is specific to the TLS leg, not this one.
        let (mut b, mut upstream) = tokio::io::duplex(64 * 1024);

        let relay_task = tokio::spawn(async move {
            copy_bidirectional_with_idle_timeout(&mut a, &mut b, Duration::from_secs(120)).await
        });

        // First request/response: small, must flow through trivially.
        browser
            .write_all(b"GET /one HTTP/1.1\r\nHost: browser.test\r\n\r\n")
            .await
            .unwrap();
        let mut req = [0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(2), upstream.read(&mut req))
            .await
            .unwrap()
            .unwrap();
        assert!(
            req[..n].starts_with(b"GET /one"),
            "first request reaches the upstream leg"
        );
        upstream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst")
            .await
            .unwrap();
        let mut first = [0u8; "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst".len()];
        tokio::time::timeout(Duration::from_secs(2), browser.read_exact(&mut first))
            .await
            .expect("first response arrives promptly")
            .unwrap();

        // Second request, REUSING the same TLS connection. The upstream leg
        // (`b`/`upstream`) is never shut down here -- a real EOF would trigger
        // this function's own half-close `shutdown()`, which flushes as a side
        // effect and would mask the bug.
        browser
            .write_all(b"GET /two HTTP/1.1\r\nHost: browser.test\r\n\r\n")
            .await
            .unwrap();
        let n = tokio::time::timeout(Duration::from_secs(2), upstream.read(&mut req))
            .await
            .unwrap()
            .unwrap();
        assert!(
            req[..n].starts_with(b"GET /two"),
            "second request, same connection, reaches the upstream leg"
        );
        // Writing BODY_LEN into `b`'s own (generously-sized, but still finite)
        // duplex can itself need the relay to drain some of it first, and the
        // relay can't drain `b` while it's stuck flushing to the deliberately
        // slow-draining `a` below -- so this has to run concurrently with the
        // browser's delayed read, not block ahead of it sequentially.
        let body_write_task = tokio::spawn(async move {
            upstream
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            upstream
                .write_all(format!("{BODY_LEN:x}\r\n").as_bytes())
                .await
                .unwrap();
            upstream.write_all(&vec![b'w'; BODY_LEN]).await.unwrap();
            upstream.write_all(b"\r\n0\r\n\r\n").await.unwrap();
            upstream // handed back so the caller can keep the "connection" open
        });

        // The browser deliberately does NOT read at all for a beat, letting
        // the relay race ahead of what the small duplex can actually hold.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let expected_len = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".len()
            + format!("{BODY_LEN:x}\r\n").len()
            + BODY_LEN
            + "\r\n0\r\n\r\n".len();
        let mut second = vec![0u8; expected_len];
        tokio::time::timeout(Duration::from_secs(1), browser.read_exact(&mut second))
            .await
            .expect("the second, chunked response body must arrive promptly, not wait for the idle-close")
            .unwrap();
        assert!(
            second.starts_with(b"HTTP/1.1 200 OK"),
            "second response headers delivered"
        );
        assert!(
            second.ends_with(b"\r\n0\r\n\r\n"),
            "second response body delivered in full, including the chunk terminator"
        );

        let _upstream = body_write_task.await.unwrap();
        relay_task.abort();
    }

    /// trace: REQ-0006 AUF-20261005-015
    ///
    /// The sibling of the flush test above, for the failure mode an unconditional
    /// flush opens: a peer that never reads. `a` is a real `tokio_rustls` stream (the
    /// front-door `Proxy` arm's own type) over a deliberately tiny `tokio::io::duplex`
    /// whose remote end is held open but NEVER read from, while the upstream leg has a
    /// response far larger than anything rustls plus that transport can hold. The
    /// relay's `a.flush()` therefore cannot complete, and because it is awaited inside
    /// a `select!` branch body, the `tokio::time::sleep(idle)` branch beside it is not
    /// polled: without the `tokio::time::timeout` around the write branch this call
    /// never returns and the test HANGS (no failure message, no idle close) -- which is
    /// exactly the #427 protection a silent reader must not be able to switch off.
    #[tokio::test]
    async fn copy_bidirectional_with_idle_timeout_bounds_a_write_to_a_peer_that_never_reads() {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        crate::transport::install_crypto_provider();

        // A short test-only idle window (the real callers pass RELAY_IDLE_TIMEOUT /
        // FRONT_DOOR_PROXY_IDLE_TIMEOUT, which stay untouched): long enough that the
        // real-clock TLS handshake below cannot trip it, short enough to keep the test
        // quick.
        const TEST_IDLE: Duration = Duration::from_secs(1);
        // Smaller than one forwarded chunk (16 KiB, this module's `buf_b`), so the very
        // first forward to `a` already has to wait on the silent reader.
        const SMALL_CAP: usize = 4096;
        // Past rustls's own ~64 KiB outgoing-plaintext buffer by a wide margin, so the
        // relay is certainly still stuck mid-write when the bound has to fire.
        const STUCK_BODY: usize = 512 * 1024;

        let certified =
            rcgen::generate_simple_self_signed(vec!["silent.test".to_string()]).unwrap();
        let cert = certified.cert.der().clone();
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let scfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(scfg));
        let ccfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(ccfg));
        let server_name = rustls::pki_types::ServerName::try_from("silent.test").unwrap();

        let (server_transport, client_transport) = tokio::io::duplex(SMALL_CAP);
        let (a_res, peer_res) = tokio::join!(
            acceptor.accept(server_transport),
            connector.connect(server_name, client_transport)
        );
        let mut a = a_res.expect("edge-side TLS handshake completes over the small duplex");
        // Held for the whole test so the transport stays OPEN (dropping it would end
        // the write with a broken-pipe error and prove nothing), and never read from:
        // this is the peer that stops reading.
        let _silent_peer = peer_res.expect("peer-side TLS handshake completes");

        // The upstream leg: roomy enough to take the whole response without a reader,
        // so the only thing that can block the relay is the `a` side.
        let (mut b, mut upstream) = tokio::io::duplex(STUCK_BODY + 16 * 1024);
        upstream.write_all(&vec![b'w'; STUCK_BODY]).await.unwrap();

        let start = tokio::time::Instant::now();
        let res = tokio::time::timeout(
            TEST_IDLE + Duration::from_secs(1),
            copy_bidirectional_with_idle_timeout(&mut a, &mut b, TEST_IDLE),
        )
        .await
        .expect("a peer that never reads must not hold the relay open past the idle window");
        let err = res.expect_err("a write that cannot be handed over must end the relay");
        assert!(
            err.to_string().contains("did not complete within"),
            "the write branch's own bound must be what closes it, not something else: {err}"
        );
        assert!(
            start.elapsed() >= TEST_IDLE,
            "the full idle window must be waited out, not cut short: {:?}",
            start.elapsed()
        );
        drop(_silent_peer);
    }
}
