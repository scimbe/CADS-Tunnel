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
//! channel broker already uses (`verify`, `verify_holder_possession`) — a requester
//! proves it holds an authentic, unexpired, CP-registered grant AND the private key
//! behind it, exactly as channel admission does, before a single byte reaches the
//! internal relay-node. The relay-node itself stays intentionally simple (unguarded,
//! `ct-agent relay-node`) because network isolation IS its gate: it is never reachable
//! except through this pre-auth splice, never bound to a public address.

use std::net::SocketAddr;
use std::time::Duration;

use ct_common::channel::{verify, verify_holder_possession, SignedChannelGrant};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Bounds one relay-gate pre-auth exchange (grant read + challenge/response) — the same
/// rationale and value as the channel broker's `CHANNEL_JOIN_TIMEOUT`: a legitimate
/// requester completes this in well under a second; a slower/hostile one is dropped so
/// it can't wedge the front door.
const RELAY_GATE_TIMEOUT: Duration = Duration::from_secs(15);

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
/// and write a one-byte `NO` marker so a well-behaved client can tell "refused" apart
/// from "connection just died".
async fn refuse<W: AsyncWrite + Unpin>(send: &mut W, tag: &str, context: &str, reason: BoxError) -> BoxError {
    eprintln!("ct-edge: relay-gate NO [{tag}] {context}: {reason}");
    let _ = send.write_all(b"NO").await;
    let _ = send.shutdown().await;
    reason
}

/// Read one relay-gate pre-auth request off `stream` (a fixed-size
/// [`SignedChannelGrant`] — no framing needed, the grant is fixed-length), verify it is
/// an authentic, unexpired grant for a channel `resolver` confirms is currently live,
/// challenge the presenter to prove it holds the grant's `holder` private key, and on
/// success write `OK<u16-LE len><relay_node_peer utf8>` and hand back the still-open
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
        if let Err(e) = verify(&operator, &grant, now) {
            return Err(refuse(&mut stream, "grant-verify", &ctx, format!("grant rejected: {e}").into()).await);
        }

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
/// (`ctx.relay_upstream`) — `tokio::io::copy_bidirectional`, the identical pattern
/// [`crate::serve::serve_front_door`]'s `Proxy` arm already uses. From here on this
/// function never interprets a byte it forwards: the libp2p protocol between the
/// requester and the relay-node is opaque to it, same as any other relayed ciphertext.
pub async fn serve_relay_gate<S>(joined: S, ctx: &RelayGateContext, now: u64) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let tls = ctx
        .acceptor
        .accept(joined)
        .await
        .map_err(|e| { eprintln!("ct-edge: relay-gate NO [tls-accept]: {e}"); e })?;
    let mut admitted = admit_relay_gate(tls, &ctx.resolver, &ctx.relay_node_peer, now).await?;
    let mut upstream = tokio::net::TcpStream::connect(ctx.relay_upstream).await?;
    tokio::io::copy_bidirectional(&mut admitted, &mut upstream).await?;
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
        let mut ack = [0u8; 2];
        let read = c_r.read_exact(&mut ack).await;

        assert!(server_task.await.unwrap().is_err(), "an unknown holder is refused");
        if read.is_ok() {
            assert_eq!(&ack, b"NO");
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
}
