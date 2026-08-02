//! A browser-reachable Agent-Fabric channel entry point (video-conferencing feature,
//! step 3): a WebSocket listener that bridges into the exact same
//! [`crate::channel_broker::admit_and_pair_on_stream`]/[`crate::channel_broker::ChannelPairer`]
//! machinery the `:443` front door's `ChannelBroker` ALPN route already uses (see
//! `serve.rs`'s `ChannelFrontDoor`) -- that function is generic over any
//! `S: AsyncRead + AsyncWrite + Unpin`, and its own doc comment already names this exact
//! extension ("the transport-generic core ... wiring it into `serve_front_door` is the
//! follow slice"). Browsers have no raw UDP/QUIC and no TLS-ALPN control of their own
//! (a `fetch`/`WebSocket` call can't choose an ALPN protocol), so a browser-originated
//! member can't use the QUIC broker or the `:443` ALPN-demuxed front door at all --
//! this is a plain HTTP(S)-Upgrade WebSocket on its own listener instead.
//!
//! Scope of this increment: browser members (the [`crate::channel_broker::AdmittedStreamMember`]s
//! this listener produces) pair with **other browser members** via their own
//! [`crate::channel_broker::ChannelPairer`] -- NOT yet unified with the `:443` front door's
//! separate pairer (that pairer is generic over a *different* concrete stream type,
//! [`FrontDoorChannelStream`] in `serve.rs`, and `ChannelPairer<T>` is not type-erased, so
//! sharing one pairer across both transports needs both call sites to agree on a common
//! boxed `Pin<Box<dyn AsyncRead + AsyncWrite + Unpin + Send>>` stream type -- a real, but
//! separate, follow-up that touches the already-tested front-door path and so is
//! deliberately not bundled into this addition). Browser-to-browser channel admission,
//! authorization, and encrypted relay all go through the identical, already-tested
//! [`crate::channel_broker`] core either way.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::serve::ChannelMemberResolver;

/// Adapts an [`axum::extract::ws::WebSocket`] (message-framed: `Stream<Item = Message>` +
/// `Sink<Message>`) into a plain [`AsyncRead`] + [`AsyncWrite`] byte stream, so the
/// Noise-framed wire bytes [`crate::channel_broker`] already speaks over TCP/QUIC flow
/// over it unchanged. WebSocket message boundaries carry no meaning here -- the read side
/// concatenates every inbound Binary payload into one continuous buffer (served to the
/// caller in whatever chunk sizes it asks for) and the write side sends each `poll_write`
/// call's bytes as its own Binary message immediately; as long as both ends treat it as an
/// opaque byte stream (which every `crate::channel_broker`/`ct_common::noise` caller
/// already does -- Noise messages are self-delimiting via `noise::frame`/`take_frame`'s
/// own length prefix), the two framings never need to line up.
pub struct WsByteStream {
    inner: WebSocket,
    read_buf: std::collections::VecDeque<u8>,
    eof: bool,
    /// `Some(n)` once `start_send` has queued `n` bytes into the Sink but the
    /// follow-up `poll_flush` hasn't completed yet -- tracked so a `Poll::Pending`
    /// return from `poll_write` (which `AsyncWrite`'s contract requires retrying with
    /// the *same* `buf`) resumes at `poll_flush` instead of calling `start_send`
    /// again and queuing the same bytes twice.
    pending_write_len: Option<usize>,
}

impl WsByteStream {
    pub fn new(inner: WebSocket) -> Self {
        Self { inner, read_buf: std::collections::VecDeque::new(), eof: false, pending_write_len: None }
    }
}

impl AsyncRead for WsByteStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            if !self.read_buf.is_empty() {
                let n = buf.remaining().min(self.read_buf.len());
                for _ in 0..n {
                    // `VecDeque::pop_front` is O(1); looping n times beats any extra
                    // allocation for a `make_contiguous` + slice copy at this size.
                    if let Some(b) = self.read_buf.pop_front() {
                        buf.put_slice(&[b]);
                    }
                }
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(())); // 0 bytes read with no error = EOF (AsyncRead contract)
            }
            let this = self.as_mut().get_mut();
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(Message::Binary(bytes)))) => {
                    this.read_buf.extend(bytes);
                    // loop back around to serve from read_buf
                }
                Poll::Ready(Some(Ok(Message::Close(_)))) | Poll::Ready(None) => {
                    this.eof = true;
                }
                Poll::Ready(Some(Ok(_))) => {
                    // Ping/Pong/Text: axum answers Pings itself; anything else is
                    // outside this protocol's wire format -- skip and keep reading.
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for WsByteStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if this.pending_write_len.is_none() {
            match Pin::new(&mut this.inner).poll_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
                // Nothing accepted yet -- AsyncWrite's contract lets the caller
                // retry with the same `buf` once this task is woken again.
                Poll::Pending => return Poll::Pending,
            }
            if let Err(e) = Pin::new(&mut this.inner).start_send(Message::Binary(buf.to_vec())) {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
            }
            this.pending_write_len = Some(buf.len());
        }
        // `start_send` only QUEUES the message -- a message-framed WebSocket Sink
        // needs an explicit flush to actually put bytes on the wire. Every existing
        // caller of this byte-stream adapter (ct_common::noise/channel_broker) uses
        // plain `write_all()` with no separate flush call, matching real socket
        // semantics (the OS flushes on its own schedule) -- so `poll_write` flushes
        // inline rather than leaving writes queued forever with nothing to ever
        // trigger delivery.
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(this.pending_write_len.take().unwrap())),
            Poll::Ready(Err(e)) => {
                this.pending_write_len = None;
                Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner)
            .poll_flush(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner)
            .poll_close(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

/// The concrete stream type this listener's [`crate::channel_broker::ChannelPairer`] is
/// keyed on -- named once, mirroring [`FrontDoorChannelStream`] in `serve.rs`.
pub type WsChannelStream = WsByteStream;

type WsPairer = std::sync::Mutex<
    crate::channel_broker::ChannelPairer<crate::channel_broker::AdmittedStreamMember<WsChannelStream>>,
>;

/// Shared state for the browser channel-join route: the long-lived pairer (so two
/// independently-arriving browser members of the same channel correlate, exactly like
/// the `:443` front door's `ChannelFrontDoor::pairer`) and the CP-backed membership
/// resolver. Cloned cheaply (both fields are `Arc`s) into each connection's task.
#[derive(Clone)]
pub struct WsChannelState {
    pairer: Arc<WsPairer>,
    resolver: Arc<dyn ChannelMemberResolver>,
}

/// How long a browser member's join stays parked waiting for its channel partner
/// before the periodic reaper drops it -- same value the front door uses
/// (`CHANNEL_PARK_TTL_SECS`, kept in sync manually since it's a `const` in `serve.rs`,
/// not exported; both exist to bound the same "a lone parked member's stream/task
/// held forever" leak class).
const WS_CHANNEL_PARK_TTL_SECS: u64 = 120;
const WS_CHANNEL_JOIN_TIMEOUT: Duration = Duration::from_secs(15);

impl WsChannelState {
    pub fn new(resolver: Arc<dyn ChannelMemberResolver>) -> Self {
        let pairer: Arc<WsPairer> = Arc::new(std::sync::Mutex::new(crate::channel_broker::ChannelPairer::new()));
        // Mirrors serve.rs's `spawn_front_door_pairer_reaper` exactly: draining and
        // dropping is enough -- there's no explicit shutdown to do, `AdmittedStreamMember`'s
        // `stream` field has no public accessor from outside channel_broker.rs, and
        // dropping it closes the underlying connection anyway.
        let reaper_pairer = pairer.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(WS_CHANNEL_PARK_TTL_SECS / 3));
            loop {
                tick.tick().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let expired = reaper_pairer.lock().unwrap().drain_expired(now);
                if !expired.is_empty() {
                    eprintln!(
                        "ct-edge: ws-channel pairer reaped {} member(s) parked past their TTL with no partner",
                        expired.len()
                    );
                }
            }
        });
        Self { pairer, resolver }
    }
}

/// Build the browser channel-join router: `GET /ws/channel` upgrades to a WebSocket and
/// admits the connection through the same [`crate::channel_broker`] core every other
/// transport uses. Mount on its own listener (`CT_EDGE_WS_CHANNEL_LISTEN`) -- deliberately
/// not folded into the `:443` front door's ALPN dispatch in this pass (see the module doc).
pub fn ws_channel_router(state: WsChannelState) -> Router {
    Router::new().route("/ws/channel", get(ws_upgrade_handler)).with_state(state)
}

async fn ws_upgrade_handler(ws: WebSocketUpgrade, State(state): State<WsChannelState>) -> Response {
    ws.on_upgrade(move |socket| handle_ws_channel_join(socket, state))
}

async fn handle_ws_channel_join(socket: WebSocket, state: WsChannelState) {
    let stream = WsByteStream::new(socket);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // `observed` (the member's reflexive source address) has no meaning for a browser
    // leg the same way it does for a dialable UDP/TCP peer -- a browser is always
    // relay-only from the edge's perspective (WebSocket, always via the server), so a
    // fixed unspecified address is honest rather than fabricating a plausible-looking
    // one. Direct-upgrade candidate exchange (#104-style) simply never offers this leg
    // a real address, same as any other `:443`-only member.
    let observed: std::net::SocketAddr = ([0, 0, 0, 0], 0).into();
    let resolver = state.resolver.clone();
    let authorize = move |c: ct_common::channel::ChannelId, h: [u8; 32]| {
        let resolver = resolver.clone();
        async move { resolver.resolve_member(c, h).await }
    };
    let paired = crate::channel_broker::admit_and_pair_on_stream(
        stream,
        observed,
        now,
        WS_CHANNEL_JOIN_TIMEOUT,
        &authorize,
        now + WS_CHANNEL_PARK_TTL_SECS,
        &state.pairer,
    )
    .await;
    match paired {
        Ok(Some((a, b))) => {
            if let Err(e) = crate::channel_broker::finish_relay_pair_over_streams(a, b, now).await {
                eprintln!("ct-edge: ws-channel relay ended: {e}");
            }
        }
        Ok(None) => {} // parked, waiting for its channel partner (or already handed off)
        Err(e) => eprintln!("ct-edge: ws-channel join refused: {e}"),
    }
}

/// Serve the browser channel-join listener on `listen` (plain HTTP -- put a TLS-terminating
/// reverse proxy or the edge's own TLS listener in front in production; kept plain here so
/// this can be exercised directly in tests/dev without a certificate).
pub async fn serve_ws_channel(
    listen: std::net::SocketAddr,
    resolver: Arc<dyn ChannelMemberResolver>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = WsChannelState::new(resolver);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, ws_channel_router(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_common::channel::{ChannelGrant, ChannelId, ChannelJoinRequest, Direction, Rights, SignedChannelGrant, CHANNEL_ENDPOINT_RELAY_ONLY};
    use ed25519_dalek::{Signer, SigningKey};
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    /// A minimal `ChannelMemberResolver` that recognizes exactly the (channel, holder)
    /// pairs it's constructed with, returning the fixed operator pubkey for each --
    /// the test double every other `channel_broker`/`serve` test in this crate uses the
    /// same way (see e.g. `serve.rs`'s own "Mock resolver: yields the operator key iff
    /// the channel matches").
    struct FixedResolver {
        operator_pubkey: [u8; 32],
        channel: ChannelId,
        holders: Vec<[u8; 32]>,
    }

    impl ChannelMemberResolver for FixedResolver {
        fn resolve_member<'a>(
            &'a self,
            channel: ChannelId,
            holder: [u8; 32],
        ) -> Pin<Box<dyn std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>> + Send + 'a>> {
            let hit = channel == self.channel && self.holders.contains(&holder);
            let pk = self.operator_pubkey;
            Box::pin(async move { hit.then_some((pk, None, None)) })
        }
    }

    fn signed_grant(operator: &SigningKey, channel: ChannelId, holder: [u8; 32], direction: Direction) -> SignedChannelGrant {
        let grant = ChannelGrant {
            channel,
            holder,
            direction,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 9_999_999_999,
        };
        let signature = operator.sign(&grant.signing_bytes()).to_bytes();
        SignedChannelGrant { grant, signature }
    }

    /// Accumulate incoming WebSocket Binary payloads into `buf` until at least `n`
    /// bytes are available, then drain and return exactly `n` -- the test client's
    /// mirror of `WsByteStream::poll_read`'s own concatenate-and-serve behavior, so the
    /// test doesn't have to assume anything about how the server chunks its writes
    /// across WS message boundaries.
    async fn ws_read_exact(
        ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        buf: &mut Vec<u8>,
        n: usize,
    ) -> Vec<u8> {
        while buf.len() < n {
            match ws.next().await {
                Some(Ok(WsMessage::Binary(bytes))) => buf.extend_from_slice(&bytes),
                Some(Ok(_)) => {}
                Some(Err(e)) => panic!("ws read error: {e}"),
                None => panic!("ws closed before {n} bytes arrived (have {})", buf.len()),
            }
        }
        buf.drain(..n).collect()
    }

    /// Like [`ws_read_exact`], but reads until (and consumes) a `\n` byte -- for the
    /// text member-ack line `write_member_ack` sends after admission, before the raw
    /// relay payload begins.
    async fn ws_read_line(ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, buf: &mut Vec<u8>) -> String {
        loop {
            if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = buf.drain(..=pos).collect();
                return String::from_utf8_lossy(&line[..line.len() - 1]).to_string();
            }
            match ws.next().await {
                Some(Ok(WsMessage::Binary(bytes))) => buf.extend_from_slice(&bytes),
                Some(Ok(_)) => {}
                Some(Err(e)) => panic!("ws read error: {e}"),
                None => panic!("ws closed before a newline arrived"),
            }
        }
    }

    #[tokio::test]
    async fn two_real_websocket_clients_join_the_same_channel_and_relay_bytes_end_to_end() {
        // The strongest proof this listener actually does what it claims: two REAL
        // WebSocket client connections (tokio-tungstenite, a real TCP socket to a
        // really-bound listener -- not an in-process fake) each complete the exact
        // admission handshake ct-agent's own channel_run.rs drives, get paired by
        // ChannelId, and then bytes written on one arrive on the other -- the same
        // "browser reaches the edge, joins a channel, talks to its peer" path a real
        // WASM-in-browser member (ct-agent-wasm, already compiling/verified) would
        // drive, just with a plain Rust client standing in for the browser's own
        // WebSocket API for this test.
        let operator = SigningKey::from_bytes(&[0x42u8; 32]);
        let operator_pubkey = operator.verifying_key().to_bytes();
        let channel = ChannelId([0x77u8; 32]);
        let alice = SigningKey::from_bytes(&[0xA1u8; 32]);
        let bob = SigningKey::from_bytes(&[0xB0u8; 32]);
        let alice_holder = alice.verifying_key().to_bytes();
        let bob_holder = bob.verifying_key().to_bytes();

        let resolver = Arc::new(FixedResolver {
            operator_pubkey,
            channel,
            holders: vec![alice_holder, bob_holder],
        });
        let state = WsChannelState::new(resolver);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, ws_channel_router(state)).await;
        });

        let url = format!("ws://{addr}/ws/channel");

        async fn join(
            url: &str,
            channel: ChannelId,
            holder_key: &SigningKey,
            direction: Direction,
            operator_sk: &SigningKey,
        ) -> (tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Vec<u8>, String) {
            let (mut ws, _resp) = tokio_tungstenite::connect_async(url).await.expect("ws connect");
            let holder = holder_key.verifying_key().to_bytes();
            let grant = signed_grant(operator_sk, channel, holder, direction);
            let req = ChannelJoinRequest { grant, endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string() };
            let req_bytes = req.encode();
            let mut out = Vec::with_capacity(2 + req_bytes.len());
            out.extend_from_slice(&(req_bytes.len() as u16).to_be_bytes());
            out.extend_from_slice(&req_bytes);
            ws.send(WsMessage::Binary(out)).await.expect("send join request");

            let mut buf = Vec::new();
            let challenge = ws_read_exact(&mut ws, &mut buf, 32).await;
            let sig = holder_key.sign(&challenge).to_bytes();
            ws.send(WsMessage::Binary(sig.to_vec())).await.expect("send possession sig");

            // No bare ack follows admission by itself -- a solo/parked member (the
            // real `admit_and_pair_on_stream` "Ok(None)" case) gets nothing further
            // until a partner arrives; the FIRST thing either side ever reads after
            // its possession signature is the rich member-ack line, sent only once
            // both sides of the channel are actually paired (`write_member_ack`).
            let member_ack_line = ws_read_line(&mut ws, &mut buf).await;
            (ws, buf, member_ack_line)
        }

        // Alice arrives first and parks (no partner yet) -- her own member-ack line
        // only arrives once Bob joins, so both joins must run CONCURRENTLY (not
        // sequentially: awaiting Alice's join to completion first would hang forever,
        // since nothing acks a parked solo member).
        let (alice_res, bob_res) = tokio::join!(
            join(&url, channel, &alice, Direction::Initiate, &operator),
            join(&url, channel, &bob, Direction::Accept, &operator),
        );
        let (mut alice_ws, mut alice_buf, alice_member_ack) = alice_res;
        let (mut bob_ws, mut bob_buf, bob_member_ack) = bob_res;

        // Each side's member-ack line names the PEER's endpoint (both relay-only here,
        // since neither is dialable -- exactly what #121's relay-only sentinel is for).
        assert!(alice_member_ack.starts_with(&format!("OK {CHANNEL_ENDPOINT_RELAY_ONLY}")), "alice's ack: {alice_member_ack}");
        assert!(bob_member_ack.starts_with(&format!("OK {CHANNEL_ENDPOINT_RELAY_ONLY}")), "bob's ack: {bob_member_ack}");

        // The real proof: raw bytes written on one WebSocket connection arrive on the
        // other, through the edge's relay splice -- a genuine two-browser-peer channel.
        let payload = b"hello from alice, over a real websocket, through the real edge relay";
        alice_ws.send(WsMessage::Binary(payload.to_vec())).await.expect("alice sends");
        let received = ws_read_exact(&mut bob_ws, &mut bob_buf, payload.len()).await;
        assert_eq!(received, payload, "bob received exactly what alice sent, byte for byte");

        let reply = b"and hello back from bob";
        bob_ws.send(WsMessage::Binary(reply.to_vec())).await.expect("bob sends");
        let received_reply = ws_read_exact(&mut alice_ws, &mut alice_buf, reply.len()).await;
        assert_eq!(received_reply, reply, "alice received bob's reply, byte for byte");
    }

    #[tokio::test]
    async fn a_lone_member_with_no_partner_parks_instead_of_failing() {
        // Confirms admission alone (no partner yet) succeeds and simply waits -- the
        // connection is NOT dropped, matching admit_and_pair_on_stream's `Ok(None)` =
        // "parked" contract. There is deliberately no ack for this case in the real
        // protocol (only a PAIRED member gets the rich member-ack line, via
        // write_member_ack) -- so "succeeds and waits" is proven by completing the
        // full admission handshake (through the possession signature) without the
        // connection being refused/closed, then confirming nothing at all arrives
        // within a short window (parked, not stuck failing) via a short timeout that
        // is *expected* to elapse.
        let operator = SigningKey::from_bytes(&[0x99u8; 32]);
        let operator_pubkey = operator.verifying_key().to_bytes();
        let channel = ChannelId([0x55u8; 32]);
        let solo = SigningKey::from_bytes(&[0xC3u8; 32]);
        let solo_holder = solo.verifying_key().to_bytes();

        let resolver = Arc::new(FixedResolver { operator_pubkey, channel, holders: vec![solo_holder] });
        let state = WsChannelState::new(resolver);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, ws_channel_router(state)).await;
        });

        let (mut ws, _resp) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws/channel")).await.unwrap();
        let grant = signed_grant(&operator, channel, solo_holder, Direction::Initiate);
        let req = ChannelJoinRequest { grant, endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string() };
        let req_bytes = req.encode();
        let mut out = Vec::with_capacity(2 + req_bytes.len());
        out.extend_from_slice(&(req_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(&req_bytes);
        ws.send(WsMessage::Binary(out)).await.unwrap();

        let mut buf = Vec::new();
        let challenge = ws_read_exact(&mut ws, &mut buf, 32).await;
        let sig = solo.sign(&challenge).to_bytes();
        ws.send(WsMessage::Binary(sig.to_vec())).await.unwrap();

        // Nothing else ever arrives -- no partner ever joins this channel in this
        // test. A short bounded wait for "anything at all" timing out is the proof:
        // if admission had instead been refused, the connection would already have
        // received a "NO" (or closed) well within this window.
        let quiet = tokio::time::timeout(Duration::from_millis(500), ws.next()).await;
        assert!(quiet.is_err(), "a parked solo member gets silence, not a refusal or an ack: {quiet:?}");
    }
}
