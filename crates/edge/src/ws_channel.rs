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
//! Cross-transport pairing: in production ([`crate::serve::run_edge`]) this listener's
//! [`WsChannelState`] joins the SAME [`crate::channel_broker::SharedChannelPairer`] the
//! `:443` front door's `ChannelFrontDoor` uses, via [`crate::channel_broker::BoxedChannelStream`]
//! (a type-erased duplex both transports box their concrete stream into) -- so a browser
//! member and a `:443`/QUIC member of the same channel correlate through one pairer and can
//! pair with EACH OTHER, not only with another member of their own transport.
//! [`WsChannelState::standalone`] (used by this module's own tests, and available to any
//! caller that only ever runs this one listener) builds its own pairer instead, unchanged
//! from this listener's original browser-to-browser-only scope. Browser channel admission,
//! authorization, and encrypted relay all go through the identical, already-tested
//! [`crate::channel_broker`] core either way.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::{IntoResponse, Response};
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
/// How often an idle (no application bytes flowing) channel connection gets a
/// server-sent WebSocket Ping (#XXX): once two members are paired and their Noise/
/// signaling session is established, real call traffic is sparse (occasional SDP/
/// ICE messages, not a steady stream) -- exactly the shape of connection an
/// idle-timeout reverse proxy or load balancer in front of this listener is most
/// likely to drop. Conservative relative to common default idle-WebSocket timeouts
/// (many sit around 60s) so a Ping goes out well before any such timeout could fire.
const WS_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

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
    /// Fires every [`WS_KEEPALIVE_INTERVAL`]; `poll_read` checks it on every call
    /// (which registers this task's waker against the timer even on a call that
    /// finds nothing to read, so a purely idle connection still gets polled again
    /// when the timer fires -- `poll_next` alone only wakes on a real inbound
    /// message/state change, never on the mere passage of time).
    keepalive: tokio::time::Interval,
}

impl WsByteStream {
    pub fn new(inner: WebSocket) -> Self {
        Self::new_with_keepalive(inner, WS_KEEPALIVE_INTERVAL)
    }

    /// Like [`Self::new`], but with an explicit keepalive interval -- exposed so a
    /// test can use a short interval instead of waiting out the real 30s constant.
    fn new_with_keepalive(inner: WebSocket, keepalive_interval: Duration) -> Self {
        let mut keepalive = tokio::time::interval(keepalive_interval);
        // The first tick fires immediately (tokio::time::interval's own default) --
        // not useful here (a fresh connection is never "idle" yet) and would send a
        // pointless Ping before the first real byte. Consume it now so the first
        // REAL tick is a full interval away.
        keepalive.reset();
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Self { inner, read_buf: std::collections::VecDeque::new(), eof: false, pending_write_len: None, keepalive }
    }
}

impl AsyncRead for WsByteStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        // Best-effort periodic Ping to keep idle-timeout infra from dropping a
        // long-lived but signaling-sparse call session -- see WS_KEEPALIVE_INTERVAL's
        // doc comment. Skipped (not lost -- the interval just fires again on its own
        // schedule) if a data write is already in flight, so this never interleaves
        // a second `start_send` before `poll_write`'s own pending flush completes
        // (the WebSocket Sink requires strictly sequenced poll_ready/start_send/
        // poll_flush, never two starts in flight at once).
        {
            let this = self.as_mut().get_mut();
            if this.keepalive.poll_tick(cx).is_ready() && this.pending_write_len.is_none() {
                if let Poll::Ready(Ok(())) = Pin::new(&mut this.inner).poll_ready(cx) {
                    let _ = Pin::new(&mut this.inner).start_send(Message::Ping(Vec::new()));
                    let _ = Pin::new(&mut this.inner).poll_flush(cx);
                }
            }
        }
        loop {
            if !self.read_buf.is_empty() {
                let n = buf.remaining().min(self.read_buf.len());
                // #453: bulk-copy via `as_slices()` -- the two contiguous runs already
                // backing the deque, zero allocation and zero extra copy (unlike
                // `make_contiguous`, which WOULD copy to merge them into one). This is
                // not "avoiding a copy the byte-at-a-time version didn't need" -- it's
                // the same total bytes copied via few large `put_slice` calls instead of
                // up to 16,384 single-byte ones per relayed chunk.
                let (front, back) = self.read_buf.as_slices();
                let from_front = n.min(front.len());
                buf.put_slice(&front[..from_front]);
                if from_front < n {
                    buf.put_slice(&back[..n - from_front]);
                }
                self.read_buf.drain(..n);
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

/// The concrete stream type this listener produces before it's boxed into
/// [`crate::channel_broker::BoxedChannelStream`] for the shared pairer.
pub type WsChannelStream = WsByteStream;

/// Shared state for the browser channel-join route: the long-lived pairer -- by
/// default shared with the `:443` front door's own channel broker (cross-transport
/// pairing: a browser member and a `:443`/QUIC member of the same channel correlate
/// through the SAME pairer and can pair with each other, not only with another member
/// of their own transport; see [`crate::channel_broker::SharedChannelPairer`]) -- and
/// the CP-backed membership resolver. Cloned cheaply (both fields are `Arc`s) into
/// each connection's task.
#[derive(Clone)]
pub struct WsChannelState {
    pairer: crate::channel_broker::SharedChannelPairer,
    resolver: Arc<dyn ChannelMemberResolver>,
    /// Concurrency cap (#XXX), matching every other public listener's `ConnectionCap`
    /// (QUIC, TCP-fallback, the `:443` front door, BrowserTunnel) -- `None` means
    /// unbounded (the default for [`Self::standalone`]/tests; production always sets
    /// one, see `serve.rs`'s `CT_EDGE_MAX_WS_CHANNEL_CONNECTIONS`).
    cap: Option<crate::state::ConnectionCap>,
}

/// How long a browser member's join stays parked waiting for its channel partner
/// before the periodic reaper drops it -- same value the front door uses
/// (`CHANNEL_PARK_TTL_SECS`, kept in sync manually since it's a `const` in `serve.rs`,
/// not exported; both exist to bound the same "a lone parked member's stream/task
/// held forever" leak class).
const WS_CHANNEL_PARK_TTL_SECS: u64 = 120;
const WS_CHANNEL_JOIN_TIMEOUT: Duration = Duration::from_secs(15);

impl WsChannelState {
    /// Build around an EXTERNALLY shared pairer (cross-transport pairing) and an
    /// optional connection cap -- the caller (`serve.rs`'s `run_edge`) owns
    /// constructing the pairer + spawning its reaper once and shares it with every
    /// transport that opts into channel brokering, and owns resolving the cap from
    /// `CT_EDGE_MAX_WS_CHANNEL_CONNECTIONS`.
    pub fn new(
        resolver: Arc<dyn ChannelMemberResolver>,
        pairer: crate::channel_broker::SharedChannelPairer,
        cap: Option<crate::state::ConnectionCap>,
    ) -> Self {
        Self { pairer, resolver, cap }
    }

    /// Like [`Self::new`], but builds its OWN standalone pairer + reaper and has NO
    /// connection cap (unbounded) -- for callers (tests, or a deployment that only
    /// ever runs this one listener) that don't need cross-transport pairing with the
    /// `:443` front door or flood protection. This is what `new` did unconditionally
    /// before cross-transport pairing/the connection cap existed.
    pub fn standalone(resolver: Arc<dyn ChannelMemberResolver>) -> Self {
        let pairer = crate::channel_broker::new_shared_channel_pairer();
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
        Self::new(resolver, pairer, None)
    }
}

/// Build the browser channel-join router: `GET /ws/channel` upgrades to a WebSocket and
/// admits the connection through the same [`crate::channel_broker`] core every other
/// transport uses. Mount on its own listener (`CT_EDGE_WS_CHANNEL_LISTEN`) -- deliberately
/// not folded into the `:443` front door's ALPN dispatch in this pass (see the module doc).
pub fn ws_channel_router(state: WsChannelState) -> Router {
    Router::new().route("/ws/channel", get(ws_upgrade_handler)).with_state(state)
}

/// #412: axum's default `WebSocketConfig` allows a 64 MiB message (16 MiB frame), and
/// `WsByteStream::poll_read` copies a whole decoded message into `read_buf` before
/// admission ever reads a byte of it -- an unauthenticated peer could force up to that
/// much allocation per connection. The wire protocol this stream actually carries
/// (Agent-Fabric channel admission + relay) already has its own real ceiling --
/// `ct_common::a2a::MAX_MESSAGE_BYTES` (`u16::MAX`), the same bound the QUIC/TCP
/// transports' length-prefixed framing enforces -- so capping the WebSocket layer at the
/// identical value costs no legitimate message headroom while cutting the pre-auth
/// worst case by roughly 1000x (64 MiB -> 64 KiB).
const WS_MAX_MESSAGE_BYTES: usize = ct_common::a2a::MAX_MESSAGE_BYTES;

/// A `ConnectionCap` permit acquired at raw-TCP-accept time (before the TLS/HTTP-upgrade
/// handshake even starts), threaded into this ONE connection's axum service via a request
/// extension layered per-connection in `serve_with_optional_tls` (#451 gap 3 / #452): the
/// admission decision moves from "after the WS upgrade, inside the axum handler" to "at
/// accept, before any TLS/HTTP work" — `ws_upgrade_handler` takes over this SAME permit
/// instead of acquiring a second one, so one live connection costs exactly one cap slot,
/// end to end, from before its first byte to after its last.
#[derive(Clone)]
struct AcceptPermit(Arc<std::sync::Mutex<Option<tokio::sync::OwnedSemaphorePermit>>>);

impl AcceptPermit {
    fn new(permit: Option<tokio::sync::OwnedSemaphorePermit>) -> Self {
        Self(Arc::new(std::sync::Mutex::new(permit)))
    }

    /// Take the permit out. `None` either because there was no cap configured (an
    /// unbounded listener) or (defensively) because it was already taken.
    fn take(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.0.lock().unwrap().take()
    }
}

async fn ws_upgrade_handler(
    ws: WebSocketUpgrade,
    accept_permit: Option<axum::extract::Extension<AcceptPermit>>,
    State(state): State<WsChannelState>,
) -> Response {
    let ws = ws.max_message_size(WS_MAX_MESSAGE_BYTES).max_frame_size(WS_MAX_MESSAGE_BYTES);
    let permit = match accept_permit {
        // `serve_with_optional_tls` already admitted this connection against `state.cap`
        // (the SAME `ConnectionCap`, shared -- see `serve_ws_channel_with_pairer`) at raw
        // TCP-accept time (#451/#452): take over that permit instead of acquiring a second
        // one here, so a real connection consumes exactly one cap slot for its whole life,
        // not a slot at accept that's released the instant the upgrade handshake completes
        // PLUS a separate one from here on.
        Some(axum::extract::Extension(slot)) => slot.take(),
        // No accept-loop permit slot on this connection -- e.g. `WsChannelState` served
        // directly via plain `axum::serve` (this module's own standalone tests,
        // `serve_ws_channel`), which never layers the extension. Fall back to acquiring
        // directly from `state.cap`, unchanged from before this fix.
        None => match &state.cap {
            Some(cap) => match cap.try_admit() {
                Some(p) => Some(p),
                None => {
                    let total = cap.note_shed();
                    if total.is_power_of_two() || total % 1000 == 0 {
                        eprintln!(
                            "ct-edge: ws-channel shedding — CT_EDGE_MAX_WS_CHANNEL_CONNECTIONS cap full, {total} connection(s) shed since start"
                        );
                    }
                    return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "too many concurrent connections").into_response();
                }
            },
            None => None,
        },
    };
    ws.on_upgrade(move |socket| handle_ws_channel_join(socket, state, permit))
}

async fn handle_ws_channel_join(
    socket: WebSocket,
    state: WsChannelState,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
) {
    // Boxed into the shared cross-transport stream type so this browser member
    // correlates through the SAME pairer a `:443`/QUIC member offers itself to --
    // either can now be the partner.
    let stream: crate::channel_broker::BoxedChannelStream = Box::pin(WsByteStream::new(socket));
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
    // #451: `permit` (this connection's cap permit, `None` when uncapped) is moved into
    // admission here, not held as a task-local binding -- it ends up on the constructed
    // `AdmittedStreamMember` so it stays held for exactly as long as this connection
    // actually lives: through a park in `state.pairer` (until matched or TTL-swept), and
    // through the relay splice below once paired -- instead of releasing the instant this
    // function's caller task returns, which for the (very common) "parked, no partner yet"
    // case used to happen almost immediately, while the live socket stayed open uncounted.
    let paired = crate::channel_broker::admit_and_pair_on_stream(
        stream,
        observed,
        now,
        WS_CHANNEL_JOIN_TIMEOUT,
        &authorize,
        now + WS_CHANNEL_PARK_TTL_SECS,
        &state.pairer,
        permit,
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

/// Serve the browser channel-join listener on `listen` with its OWN standalone pairer
/// (no cross-transport pairing with the `:443` front door) -- plain HTTP, put a
/// TLS-terminating reverse proxy or the edge's own TLS listener in front in
/// production; kept plain here so this can be exercised directly in tests/dev without
/// a certificate.
pub async fn serve_ws_channel(
    listen: std::net::SocketAddr,
    resolver: Arc<dyn ChannelMemberResolver>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = WsChannelState::standalone(resolver);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, ws_channel_router(state)).await?;
    Ok(())
}

/// #451/#452: bound on the raw-TCP-accept loop's own TLS-accept-through-WS-upgrade
/// handshake phase, applied by [`crate::transport::serve_listener`] around the whole
/// `serve_with_optional_tls` per-connection handler below. A legitimate WS client
/// completes TLS (if any) and the HTTP upgrade request/response in one quick round
/// trip; the long-lived POST-upgrade WS session itself runs on a SEPARATE task axum's
/// own `WebSocketUpgrade::on_upgrade` spawns internally (decoupled from this
/// handler, which returns once the upgrade handoff completes) -- so this timeout
/// never bounds a real, live call session, only a stalled/hostile pre-upgrade client.
const WS_CHANNEL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Serve `router` on `inner`, optionally TLS-wrapping each accepted connection first
/// (`tls: None` = plain `ws://`, `Some(acceptor)` = native `wss://` termination).
/// axum 0.7's `axum::serve` only accepts a concrete [`tokio::net::TcpListener`] --
/// the generic `Listener` trait that would let a custom listener TLS-wrap per
/// connection arrived in axum 0.8, which this workspace doesn't use (its route-param
/// syntax change, `:id` -> `{id}`, is a much larger, unrelated migration across every
/// router in this crate). So this drives the connection at the hyper 1.x level
/// directly -- the same low-level approach axum's own examples use for exactly this
/// case. `.with_upgrades()` is required for the WebSocket `Connection: Upgrade`
/// handshake this listener exists for.
///
/// #451/#452: admission (`cap`), TCP keepalive, and spawning are now owned by the
/// SHARED [`crate::transport::serve_listener`] helper -- the fix for both "the cap was
/// only consulted inside the axum handler AFTER the WebSocket upgrade, so pre-upgrade
/// connections were entirely unbounded" (#451 gap 3) and "only some listeners call the
/// shared TCP-keepalive helper" (#452). The permit `serve_listener` hands this
/// per-connection handler is threaded into the per-connection router via an
/// [`AcceptPermit`] request extension, so `ws_upgrade_handler` can take over the SAME
/// permit rather than acquiring its own second one.
async fn serve_with_optional_tls(
    inner: tokio::net::TcpListener,
    tls: Option<tokio_rustls::TlsAcceptor>,
    router: Router,
    cap: Option<crate::state::ConnectionCap>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    crate::transport::serve_listener(
        inner,
        cap,
        "ws-channel",
        Some(WS_CHANNEL_HANDSHAKE_TIMEOUT),
        move |stream, addr, permit| {
            let router = router.clone().layer(axum::Extension(AcceptPermit::new(permit)));
            let tls = tls.clone();
            async move {
                let service = hyper_util::service::TowerToHyperService::new(router);
                let result = match tls {
                    None => {
                        let io = hyper_util::rt::TokioIo::new(stream);
                        hyper::server::conn::http1::Builder::new().serve_connection(io, service).with_upgrades().await
                    }
                    Some(acceptor) => match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let io = hyper_util::rt::TokioIo::new(tls_stream);
                            hyper::server::conn::http1::Builder::new().serve_connection(io, service).with_upgrades().await
                        }
                        Err(e) => {
                            // One failed TLS handshake (e.g. a plain-HTTP probe hitting a
                            // wss:// port) must not kill the listener -- log and drop just
                            // this connection.
                            eprintln!("ct-edge: ws-channel TLS handshake failed from {addr}: {e}");
                            return;
                        }
                    },
                };
                if let Err(e) = result {
                    eprintln!("ct-edge: ws-channel connection from {addr} ended: {e}");
                }
            }
        },
    )
    .await;
    Ok(())
}

/// Like [`serve_ws_channel`], but joins the shared cross-transport `pairer` (the
/// `:443` front door's own channel broker uses the same one) instead of building a
/// standalone one, applies the given connection `cap` (`None` = unbounded), and
/// optionally terminates TLS natively via `tls` (`None` = plain `ws://`, unchanged
/// default behavior) -- what `run_edge` wires up in production so a browser member
/// and a `:443`/QUIC member of the same channel correlate and can pair with each
/// other, with the same flood protection and TLS-termination option every other
/// public listener has.
pub async fn serve_ws_channel_with_pairer(
    listen: std::net::SocketAddr,
    resolver: Arc<dyn ChannelMemberResolver>,
    pairer: crate::channel_broker::SharedChannelPairer,
    cap: Option<crate::state::ConnectionCap>,
    tls: Option<tokio_rustls::TlsAcceptor>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = WsChannelState::new(resolver, pairer, cap.clone());
    let inner = tokio::net::TcpListener::bind(listen).await?;
    serve_with_optional_tls(inner, tls, ws_channel_router(state), cap).await
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
    async fn ws_read_exact<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        ws: &mut tokio_tungstenite::WebSocketStream<S>,
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
    async fn ws_read_line<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(ws: &mut tokio_tungstenite::WebSocketStream<S>, buf: &mut Vec<u8>) -> String {
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
        let state = WsChannelState::standalone(resolver);
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
    async fn wss_terminates_tls_natively_and_relays_exactly_like_plain_ws() {
        // CT_EDGE_WS_CHANNEL_CERT/_KEY (production): the SAME channel-join/relay
        // pipeline as the plain-ws test above, reached over a REAL TLS handshake
        // (tokio-rustls, a real cert, a real client trusting it) instead of
        // plaintext -- proves MaybeTlsListener's wrapping changes only the transport
        // underneath, none of the join/relay behavior. Brings this listener to the
        // same native-TLS-termination parity every other public edge listener
        // (portal/auth/wildcard) already has.
        let (unused_listener, acceptor, cert) =
            crate::transport::build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap()).await.unwrap();
        drop(unused_listener); // only the acceptor + cert are needed; ws_channel binds its own port below

        let operator = SigningKey::from_bytes(&[0x64u8; 32]);
        let operator_pubkey = operator.verifying_key().to_bytes();
        let channel = ChannelId([0x88u8; 32]);
        let alice = SigningKey::from_bytes(&[0xA2u8; 32]);
        let bob = SigningKey::from_bytes(&[0xB3u8; 32]);
        let alice_holder = alice.verifying_key().to_bytes();
        let bob_holder = bob.verifying_key().to_bytes();

        let resolver = Arc::new(FixedResolver {
            operator_pubkey,
            channel,
            holders: vec![alice_holder, bob_holder],
        });
        let pairer = crate::channel_broker::new_shared_channel_pairer();
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe); // free the port for serve_ws_channel_with_pairer to bind for real
        tokio::spawn(serve_ws_channel_with_pairer(addr, resolver, pairer, None, Some(acceptor)));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        async fn join_tls(
            addr: std::net::SocketAddr,
            cert: rustls::pki_types::CertificateDer<'static>,
            channel: ChannelId,
            holder_key: &SigningKey,
            direction: Direction,
            operator_sk: &SigningKey,
        ) -> (tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>, Vec<u8>, String) {
            let tls_stream = crate::transport::tcp_tls_connect(addr, cert).await.expect("tls connect");
            let (mut ws, _resp) = tokio_tungstenite::client_async("wss://localhost/ws/channel", tls_stream)
                .await
                .expect("ws handshake over tls");
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

            let member_ack_line = ws_read_line(&mut ws, &mut buf).await;
            (ws, buf, member_ack_line)
        }

        let (alice_res, bob_res) = tokio::join!(
            join_tls(addr, cert.clone(), channel, &alice, Direction::Initiate, &operator),
            join_tls(addr, cert.clone(), channel, &bob, Direction::Accept, &operator),
        );
        let (mut alice_ws, mut alice_buf, alice_member_ack) = alice_res;
        let (mut bob_ws, mut bob_buf, bob_member_ack) = bob_res;

        assert!(alice_member_ack.starts_with(&format!("OK {CHANNEL_ENDPOINT_RELAY_ONLY}")), "alice's ack: {alice_member_ack}");
        assert!(bob_member_ack.starts_with(&format!("OK {CHANNEL_ENDPOINT_RELAY_ONLY}")), "bob's ack: {bob_member_ack}");

        let payload = b"hello from alice, over a REAL TLS-terminated websocket";
        alice_ws.send(WsMessage::Binary(payload.to_vec())).await.expect("alice sends");
        let received = ws_read_exact(&mut bob_ws, &mut bob_buf, payload.len()).await;
        assert_eq!(received, payload, "bob received exactly what alice sent, byte for byte, over TLS");

        let reply = b"and hello back from bob, over TLS too";
        bob_ws.send(WsMessage::Binary(reply.to_vec())).await.expect("bob sends");
        let received_reply = ws_read_exact(&mut alice_ws, &mut alice_buf, reply.len()).await;
        assert_eq!(received_reply, reply, "alice received bob's reply, byte for byte, over TLS");
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
        let state = WsChannelState::standalone(resolver);
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

    #[tokio::test]
    async fn oversized_pre_auth_message_is_rejected_not_buffered_412() {
        // #412: axum's DEFAULT WebSocketConfig (64 MiB message) would let an
        // unauthenticated peer force a huge allocation via `WsByteStream::poll_read`
        // before a single byte of admission ever runs. `ws_upgrade_handler` now caps
        // both message and frame size at `WS_MAX_MESSAGE_BYTES` (`ct_common::a2a`'s own
        // `MAX_MESSAGE_BYTES`, `u16::MAX`) -- confirm a message over that bound is
        // refused at the WebSocket layer itself, never reaching admission at all.
        let operator = SigningKey::from_bytes(&[0x77u8; 32]);
        let channel = ChannelId([0x66u8; 32]);
        let resolver = Arc::new(FixedResolver { operator_pubkey: operator.verifying_key().to_bytes(), channel, holders: vec![] });
        let state = WsChannelState::standalone(resolver);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, ws_channel_router(state)).await;
        });

        let (mut ws, _resp) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws/channel")).await.unwrap();
        // One byte over the real wire-protocol ceiling -- a legitimate join request is
        // a couple hundred bytes at most (SignedChannelGrant::WIRE_LEN + a short
        // endpoint string), so this is purely an attacker-shaped oversized frame, not
        // anything a real client would ever send.
        let oversized = vec![0u8; WS_MAX_MESSAGE_BYTES + 1];
        ws.send(WsMessage::Binary(oversized)).await.unwrap();

        // Either the send itself is rejected client-side (tungstenite enforces its own
        // negotiated config) or the connection closes/errors when the server refuses
        // the oversized frame -- either way, nothing resembling a normal admission
        // response (a 32-byte challenge) can arrive.
        let outcome = tokio::time::timeout(Duration::from_secs(5), ws.next()).await;
        match outcome {
            Err(_) => panic!("server neither closed nor errored on an oversized pre-auth message"),
            Ok(None) => {} // connection closed -- correctly refused
            Ok(Some(Err(_))) => {} // protocol error -- correctly refused
            Ok(Some(Ok(msg))) => panic!("oversized message was NOT refused, server responded: {msg:?}"),
        }
    }

    #[tokio::test]
    async fn an_idle_ws_byte_stream_sends_periodic_keepalive_pings() {
        // #XXX: once paired, a real call's signaling traffic is sparse -- a
        // WsByteStream sitting idle (no application bytes to relay) must still keep
        // sending WS Pings so an idle-timeout reverse proxy/load balancer in front of
        // this listener doesn't drop the connection mid-call. Proves the mechanism
        // directly against a real WebSocket (tokio-tungstenite, real TCP): a server
        // task holds a WsByteStream open with NOTHING to read or write (mirroring a
        // real relay's read side blocked waiting for the next byte) and a real client
        // observes an actual `Ping` frame arrive within a bounded window, using a
        // short test-only interval instead of the real 30s constant.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        async fn ws_upgrade_test_handler(ws: WebSocketUpgrade) -> Response {
            ws.on_upgrade(|socket| async move {
                let mut stream = WsByteStream::new_with_keepalive(socket, Duration::from_millis(100));
                // Drive poll_read forever (nothing will ever actually arrive) -- the
                // exact same "blocked waiting for the next byte" shape a real
                // relay's read side has on an idle connection, which is precisely
                // when the keepalive needs to keep firing.
                let mut buf = [0u8; 1];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
            })
        }
        let app = Router::new().route("/ws/idle", get(ws_upgrade_test_handler));
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let (mut ws, _resp) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws/idle")).await.expect("ws connect");

        // Send nothing at all; just wait for the server's own unprompted Ping.
        let msg = tokio::time::timeout(Duration::from_millis(500), ws.next())
            .await
            .expect("a Ping should arrive well within 5x the 100ms test interval")
            .expect("stream item")
            .expect("no ws error");
        assert!(matches!(msg, WsMessage::Ping(_)), "expected a Ping frame, got {msg:?}");
    }

    #[tokio::test]
    async fn a_full_connection_cap_sheds_the_ws_upgrade_before_admission() {
        // #XXX: every OTHER public listener sheds cheaply under a ConnectionCap once
        // full; this listener had none at all until now. Proves the mechanism
        // directly: a cap of 1, a first real WebSocket connection that holds its slot
        // (never closes), and a second real connection that must be REJECTED AT THE
        // WS UPGRADE ITSELF (never reaches 101 Switching Protocols) -- cheaper than
        // admitting then dropping mid-handshake, same posture as every other cap.
        let resolver = Arc::new(FixedResolver { operator_pubkey: [0u8; 32], channel: ChannelId([0u8; 32]), holders: vec![] });
        let cap = crate::state::ConnectionCap::new(1);
        let state = WsChannelState::new(resolver, crate::channel_broker::new_shared_channel_pairer(), Some(cap));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, ws_channel_router(state)).await;
        });
        let url = format!("ws://{addr}/ws/channel");

        // First connection: admitted, takes the cap's only slot. Held open (not
        // dropped) for the rest of the test so the slot stays occupied.
        let (first_ws, _resp) = tokio_tungstenite::connect_async(&url).await.expect("first connection admitted");

        // Second connection: the cap is full -- the upgrade itself must be refused.
        let second = tokio_tungstenite::connect_async(&url).await;
        assert!(second.is_err(), "a full cap must refuse the WS upgrade, not just admit-then-drop: {second:?}");

        drop(first_ws);
    }
}
