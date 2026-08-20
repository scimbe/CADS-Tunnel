//! Edge serve orchestration (M5.1c).
//!
//! The Agent-registration path: an Agent opens a control stream and registers
//! the Routing Token it serves; the Edge stores the connection in [`EdgeState`]
//! so a later Client rendezvous for that token can be routed to it. The Client
//! route→relay path is exercised end to end in the M5.6 testbed smoke. The
//! live path is [`serve_connection`]'s `'A'` role branch, not [`register_agent`]
//! (#583 -- see that function's own doc comment).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::config::EdgeConfig;
use crate::relay::{framed_relay, relay, relay_quic};
use crate::state::{ConnectionCap, EdgeState};
use crate::pki::{build_dual_edge_from_ca, build_server_endpoint_from_ca, Ca};
use crate::transport::save_cert;
use ct_common::pow::{check_request, Challenge};
use ct_common::RoutingToken;
use ct_common::sync::MutexExt;
use quinn::{Connection, RecvStream, SendStream};
use rand::RngCore;
use tokio::io::{join, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Handle one Agent registration on `conn`: read `role='A'(1) | token(32)` on a
/// fresh bi-stream, register the connection in `state`, ack `OK`, and return the
/// registered token.
///
/// #583: despite the confident doc comment above, this is **not** the live
/// registration path -- the daemon's real accept loop (`run_edge` ->
/// `serve_agent_connection` -> `serve_connection`) registers via
/// `state.register_with_candidate_unless_revoked` directly in
/// `serve_connection`'s `'A'` branch, which also enforces the revocation
/// check this function skips. Every caller of `register_agent` today is a
/// test helper (`mod tests` below); kept as a test convenience, not because
/// production reaches it.
pub async fn register_agent(
    conn: &Connection,
    state: &EdgeState<Connection>,
) -> Result<RoutingToken, BoxError> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let hdr = recv.read_to_end(33).await?;
    if hdr.len() != 33 || hdr[0] != b'A' {
        return Err("malformed agent registration".into());
    }
    let mut token = [0u8; 32];
    token.copy_from_slice(&hdr[1..33]);
    let token = RoutingToken(token);

    // Record the Agent's Edge-observed reflexive address as its peer candidate
    // for P2P rendezvous (M11.2).
    state.register_with_candidate(token.clone(), conn.clone(), conn.remote_address());
    send.write_all(b"OK").await?;
    send.finish()?;
    Ok(token)
}

/// How long the Edge waits for `open_bi()` to the Agent to yield a stream before
/// declaring the tunnel unresponsive. Kept under the Client's own tunnel timeout
/// (8 s) so the Edge fails first with a precise reason instead of the Client
/// giving up with an opaque "no relay" (issue #2, mode b).
const RELAY_OPEN_BI_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a Client rendezvous will wait for a TCP-fallback registration to
/// free up before giving up (#229 follow-up: a real browser's burst of
/// parallel connections can momentarily exceed the Agent-side pool size).
/// Short enough to stay well under the Client's own tunnel timeout (8s, see
/// [`RELAY_OPEN_BI_TIMEOUT`]'s doc comment) even when combined with the
/// `open_agent_stream` attempt that precedes it.
///
/// #589: raised 1500ms -> 3000ms (live-caught on sort.bunsenbrenner.org, a
/// TCP-fallback-only tunnel with zero QUIC registrations ever -- for that
/// case `open_agent_stream`'s own attempt costs ~0ms, since `agents.is_empty()`
/// returns immediately rather than spending any of `RELAY_OPEN_BI_TIMEOUT`, so
/// this constant alone was the entire client-visible budget). The failure
/// this widens for is a single re-park round-trip (agent notices its one-shot
/// TCP-fallback slot was consumed, dials out again, completes TCP+TLS,
/// re-registers) racing a burst of parallel client connections against a
/// pool that only ever holds one spare slot per outstanding dial -- 1.5s left
/// too little margin for jitter on a real network. Doubling still leaves
/// comfortable headroom under the 8s ceiling even stacked on top of a
/// worst-case multi-agent `open_agent_stream` timeout elsewhere in this file.
const TCP_FALLBACK_DELIVER_WAIT: Duration = Duration::from_millis(3000);

/// First 8 hex chars of a token, for correlating an Edge trace line with a
/// field-supplied token during cross-host diagnosis.
/// #342: hex-encodes `token`'s first 4 bytes into `buf` (8 hex chars) and
/// returns a borrowed `&str` into it -- avoids the 5 heap allocations
/// (`format!` per byte, plus the final `collect::<String>()`) the previous
/// `-> String` version did on every relay call. This label is usually only a
/// trace-log argument, discarded unread whenever `CT_EDGE_TRACE` is unset (the
/// production default) -- pure allocation waste on the hot relay path at real
/// connection volume.
fn token_hex<'a>(token: &RoutingToken, buf: &'a mut [u8; 8]) -> &'a str {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in token.0.iter().take(4).enumerate() {
        buf[i * 2] = HEX[(b >> 4) as usize];
        buf[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    std::str::from_utf8(buf).expect("hex digits are always valid UTF-8")
}

/// Parse a 64-hex admin token (`CT_EDGE_ADMIN_TOKEN`) into 32 bytes, if valid (#27 RB3).
fn parse_admin_token_hex(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut t = [0u8; 32];
    for (i, b) in t.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(t)
}

/// Emit an Edge-side diagnostic line when `CT_EDGE_TRACE` is set. Off by default
/// (no overhead / noise in production); enabled for a lockstep cross-host capture.
fn edge_trace(args: std::fmt::Arguments<'_>) {
    if std::env::var_os("CT_EDGE_TRACE").is_some() {
        eprintln!("[edge-trace] {args}");
    }
}

/// Resolve `token` to its registered Agent connection and open a relay stream to
/// it, bounded by `timeout`. Distinguishes the two cross-host failure modes the
/// Client can't tell apart: **no registration** (`route` miss) vs a **live but
/// unresponsive** Agent whose `open_bi()` never yields a stream (e.g. it granted
/// no bidi-stream credit, or the return path is broken). Traces each decision
/// point under `CT_EDGE_TRACE` (issue #2, mode b).
async fn open_agent_stream_with(
    state: &EdgeState<Connection>,
    token: &RoutingToken,
    timeout: Duration,
) -> Result<(SendStream, RecvStream), BoxError> {
    let mut th_buf = [0u8; 8];
    let th = token_hex(token, &mut th_buf);
    let agents = state.routes(token);
    if agents.is_empty() {
        edge_trace(format_args!("route token={th} -> MISS (no registration)"));
        // The token prefix makes the operator-visible line attributable: during the
        // 2026-08-16 llm-path incident two same-day "no agent tunnel" bursts could
        // not be told apart because this line named no tunnel at all.
        return Err(format!("no agent tunnel for token {th}").into());
    }
    // Failover (#8 R2): try each live agent, newest first, until one opens a relay
    // stream. This covers redundant agents AND the race where the chosen agent's
    // connection is dead but not yet evicted — the next agent takes over instead
    // of the client seeing an opaque "no relay".
    let total = agents.len();
    let mut last_err = String::new();
    for (i, agent_conn) in agents.into_iter().enumerate() {
        edge_trace(format_args!(
            "route token={th} -> hit (agent {}/{total}); opening relay stream",
            i + 1
        ));
        match tokio::time::timeout(timeout, agent_conn.open_bi()).await {
            Ok(Ok(streams)) => {
                edge_trace(format_args!("open_bi token={th} agent {}/{total} -> ok", i + 1));
                if i > 0 {
                    state.note_failover(); // served by a non-primary agent (#10 O2)
                }
                return Ok(streams);
            }
            Ok(Err(e)) => {
                edge_trace(format_args!("open_bi token={th} agent {}/{total} -> err: {e}", i + 1));
                last_err = e.to_string();
            }
            Err(_) => {
                edge_trace(format_args!(
                    "open_bi token={th} agent {}/{total} -> TIMED OUT after {timeout:?}",
                    i + 1
                ));
                last_err = format!("open_bi to {th} timed out");
            }
        }
    }
    Err(format!("agent tunnel unresponsive: all {total} agent(s) failed ({last_err})").into())
}

/// [`open_agent_stream_with`] using the default [`RELAY_OPEN_BI_TIMEOUT`].
async fn open_agent_stream(
    state: &EdgeState<Connection>,
    token: &RoutingToken,
) -> Result<(SendStream, RecvStream), BoxError> {
    open_agent_stream_with(state, token, RELAY_OPEN_BI_TIMEOUT).await
}

/// Route a resolved Client stream to the Agent tunnel serving `token` and relay
/// bytes between them. Opens a fresh stream on the Agent's registered connection
/// and pipes the two together (provider-blind).
/// #554: run a relay future, but lose to this token's revocation.
///
/// Every tunnel-carrying relay in this module goes through here, because covering only
/// some of them would leave a revocation that works on one transport and silently does
/// not on another — and an operator has no way to tell which path a given session took.
///
/// Losing the race returns `Err`, which drops both stream halves at the call site: that
/// drop is what actually stops the bytes. The relay's byte counts are deliberately not
/// recorded for a cut session — `note_relay` runs only on a clean end, so the traffic
/// figures keep meaning "a relay that finished", not "a relay that was killed".
async fn until_revoked<T>(
    state: &EdgeState<Connection>,
    token: &RoutingToken,
    fut: impl std::future::Future<Output = std::io::Result<T>>,
) -> Result<T, BoxError> {
    tokio::select! {
        r = fut => Ok(r?),
        _ = state.revoked_signal(token) => {
            Err("relay cut: this tunnel's token was revoked mid-session (#554)".into())
        }
    }
}

pub async fn route_and_relay(
    state: &EdgeState<Connection>,
    token: &RoutingToken,
    client_send: SendStream,
    client_recv: RecvStream,
) -> Result<(), BoxError> {
    let (agent_send, agent_recv) = open_agent_stream(state, token).await?;
    let mut th_buf = [0u8; 8];
    // #554: race the copy against this token's revocation. Dropping the registration is
    // not enough on its own -- an already-spliced relay consults nothing and kept carrying
    // traffic for a revoked tunnel (measured). Losing the race drops both streams, which
    // is what actually stops the bytes; the byte counts of a cut relay are not recorded
    // because `relay_quic` only reports them on a clean end.
    let (a, b) = until_revoked(
        state,
        token,
        relay_quic(client_send, client_recv, agent_send, agent_recv, token_hex(token, &mut th_buf)),
    )
    .await?;
    state.note_relay(token, a, b, crate::state::RelayKind::DataPlane); // #10 O2
    Ok(())
}

/// Browser Plane (#23, sub-packet 1): serve one inbound TLS connection by SNI.
/// Peek the ClientHello's SNI hostname **without terminating TLS**, map it to a
/// routing token, open a stream to the serving Agent, replay the buffered
/// ClientHello, and relay the raw TLS bytes both ways. TLS terminates at the
/// Origin (which holds the certificate); the Edge sees only the hostname and
/// ciphertext, so the payload stays provider-blind.
/// A byte stream that yields `pre` (already-read bytes) first, then delegates to
/// `inner` — used to hand a TCP-fallback agent the browser's buffered ClientHello
/// followed by the rest of the connection (#41 FB2).
struct Prepend<S> {
    pre: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Prepend<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.pos < self.pre.len() {
            let rem = &self.pre[self.pos..];
            let n = rem.len().min(buf.remaining());
            buf.put_slice(&rem[..n]);
            self.pos += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prepend<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub async fn serve_sni_passthrough<S>(
    mut inbound: S,
    state: &EdgeState<Connection>,
) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // #111: bound the ClientHello read on this public `:443` SNI entry too, so a Slowloris
    // client that stalls mid-record is dropped rather than pinning the connection forever.
    let (hello, sni) = tokio::time::timeout(
        CLIENT_HELLO_READ_TIMEOUT,
        crate::sni::read_client_hello(&mut inbound),
    )
    .await
    .map_err(|_| "sni passthrough: ClientHello read timed out")?
    .ok_or("no SNI in the TLS ClientHello")?;
    let token = state
        .route_host(&sni)
        .ok_or_else(|| format!("no tunnel registered for host '{sni}'"))?;
    // #41 FB2: a TCP-fallback agent (UDP/QUIC blocked) is parked with no QUIC
    // connection — hand it the browser stream (buffered ClientHello + the rest)
    // directly, rather than opening a QUIC stream it doesn't have.
    //
    // #505: parked slots used to take ABSOLUTE precedence, and a dead one was a
    // terminal error for the request ("vanished before delivery") — after a flap
    // (an edge redeploy makes every agent fall back and park, then recover to
    // QUIC), the stale dead parks bricked the hostname for every browser despite
    // a healthy QUIC registration, until a human re-ran the demo script. Each
    // delivery attempt consumes one slot and hands the stream back on a dead
    // receiver, so: DRAIN dead parks in a loop, succeed on the first live one,
    // and fall through to the QUIC registration when none are left.
    let stream: crate::state::BoxedStream = Box::new(Prepend {
        pre: hello,
        pos: 0,
        inner: inbound,
    });
    let mut stream = match state.deliver_to_tcp_agent_draining(&token, stream) {
        Ok(()) => return Ok(()),
        Err(back) => back, // no live parked slot (#505); fall through to QUIC
    };
    match open_agent_stream(state, &token).await {
        Ok((agent_send, agent_recv)) => {
            // The buffered ClientHello replays from the Prepend wrapper on first
            // read, so the browser<->origin TLS handshake completes end-to-end.
            let mut agent = join(agent_recv, agent_send);
            let (a, b) = until_revoked(state, &token, relay(&mut stream, &mut agent)).await?; // #554
            state.note_relay(&token, a, b, crate::state::RelayKind::Browser);
            Ok(())
        }
        Err(e) => {
            // No QUIC registration -- likely a TCP-fallback-only agent (UDP
            // blocked) whose pool was momentarily exhausted by a burst of
            // parallel browser connections (#229 follow-up: real page loads
            // open several at once). Give it a brief window to free a slot
            // rather than failing this request outright. Draining too (#510):
            // the freed slot may sit behind stale dead ones.
            if state.wait_for_tcp_agent(&token, TCP_FALLBACK_DELIVER_WAIT).await {
                if state.deliver_to_tcp_agent_draining(&token, stream).is_ok() {
                    return Ok(());
                }
            }
            // Name the HOST, not only the token. `open_agent_stream` is a generic routing
            // helper and legitimately knows nothing but the token; this call site does know
            // the hostname, and it is the only place that can join the two.
            //
            // The line it enriches already carries a token because the 2026-08-16 llm
            // incident could not tell two same-day bursts apart. That fixed one level and
            // left the next: on 2026-08-18 a burst of `no agent tunnel for token 9a1aee0b`
            // could not be attributed to a site at all -- nothing in the logs maps a token
            // to a hostname, so "which site is down?" was unanswerable from the record.
            //
            // #589: name the TCP-fallback pool depth too, at the moment this call gives up
            // (after the wait above already found it empty). Distinguishes "pool was
            // genuinely empty" (0) from "pool had a slot but 1.5s wasn't enough to claim
            // it" (>0) -- two different failure shapes that read identically without this.
            let pool = state.tcp_parked_for(&token);
            Err(format!("{e} — host {sni} — tcp_fallback_pool={pool}").into())
        }
    }
}

/// Rot/Gelb/Grün certificate tier (#233), **Gelb** leg: terminate the
/// browser's TLS with the shared front-door **wildcard** certificate (rather
/// than passing raw TLS bytes through to the Origin, which doesn't hold a
/// certificate of its own yet), then relay the DECRYPTED application bytes
/// onward to the Agent over the same tunnel mechanism every other route
/// uses. The customer's own origin must therefore serve plain HTTP while a
/// hostname is Gelb — it starts speaking TLS itself again only once the
/// control plane flips it to Grün (`state.set_cert_tier(host, false)`),
/// which reverts new connections to [`serve_sni_passthrough`] so the
/// browser sees the origin's own, now-issued certificate.
///
/// `inbound` is the already-Prepend-joined stream (buffered ClientHello +
/// the rest of the socket) — the same shape [`serve_sni_passthrough`] takes,
/// so both legs plug into [`serve_front_door`]'s `BrowserTunnel` arm
/// identically; the only difference is TLS-terminate-then-relay-plaintext
/// versus relay-raw-bytes-through.
///
/// Handles a parked TCP-fallback agent (UDP/QUIC blocked) the same as
/// [`serve_sni_passthrough`] does — hand it the stream directly via
/// [`EdgeState::deliver_to_tcp_agent_draining`] rather than [`open_agent_stream`],
/// which only ever looks at the QUIC registration and would otherwise fail
/// "no agent tunnel for token" for a live but QUIC-less agent (found live,
/// #229: an agent behind a UDP-blocking network hit exactly this before the
/// fallback case was added here).
pub async fn serve_gelb_terminated<S>(
    inbound: S,
    host: &str,
    state: &EdgeState<Connection>,
    wildcard_acceptor: &tokio_rustls::TlsAcceptor,
) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let token = state
        .route_host(host)
        .ok_or_else(|| format!("no tunnel registered for host '{host}'"))?;
    let tls = tokio::time::timeout(FRONT_DOOR_TLS_ACCEPT_TIMEOUT, wildcard_acceptor.accept(inbound))
        .await
        .map_err(|_| -> BoxError { "gelb-terminate: TLS handshake not completed within the timeout (#422)".into() })??;
    // #233 follow-up (found live, #229): a TCP-fallback agent (UDP/QUIC
    // blocked) is parked with no QUIC connection to open a stream on at all
    // -- `open_agent_stream` below would always fail "no agent tunnel for
    // token" for it, indistinguishable from a genuinely dead agent. Hand it
    // the DECRYPTED stream directly, the same way `serve_sni_passthrough`
    // hands it the raw (still-encrypted) one -- the only difference is TLS
    // already came off at the edge here.
    // #505: same drain-then-fall-through as serve_sni_passthrough — dead parked
    // slots are consumed one by one and a healthy QUIC registration serves the
    // request instead of the old terminal "vanished before delivery".
    let stream: crate::state::BoxedStream = Box::new(tls);
    let mut stream = match state.deliver_to_tcp_agent_draining(&token, stream) {
        Ok(()) => return Ok(()),
        Err(back) => back, // no live parked slot (#505); fall through to QUIC
    };
    match open_agent_stream(state, &token).await {
        Ok((agent_send, agent_recv)) => {
            let mut agent = join(agent_recv, agent_send);
            let (a, b) = until_revoked(state, &token, relay(&mut stream, &mut agent)).await?; // #554
            state.note_relay(&token, a, b, crate::state::RelayKind::Browser);
            Ok(())
        }
        Err(e) => {
            // Same momentarily-exhausted-pool recovery as serve_sni_passthrough
            // (#229 follow-up), draining too (#510).
            if state.wait_for_tcp_agent(&token, TCP_FALLBACK_DELIVER_WAIT).await {
                if state.deliver_to_tcp_agent_draining(&token, stream).is_ok() {
                    return Ok(());
                }
            }
            // Same reason as the SNI leg above: this is the level that knows the host.
            // #589: pool depth at give-up time, same reasoning as the SNI leg's twin.
            let pool = state.tcp_parked_for(&token);
            Err(format!("{e} — host {host} — tcp_fallback_pool={pool}").into())
        }
    }
}

/// Resolve the `CT_CP_PROXY_ADDR` Portal upstream — a `host:port` (or literal
/// `IP:port`) — for the `:443` front door (#31; mirrors #45's `resolve_addr` on
/// the agent). A hostname like `control-plane:8090`, the natural docker-compose
/// value, resolves via the system resolver; a literal `IP:port` parses directly.
/// A set-but-unresolvable value is logged and yields `None` (Portal route
/// disabled) rather than silently becoming a dead route indistinguishable from a
/// reject — the failure mode scimbe hit when a hostname was configured.
fn resolve_proxy_addr(raw: Option<String>) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;
    let s = raw?;
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    match s.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(a) => Some(a),
            None => {
                eprintln!("ct-edge: CT_CP_PROXY_ADDR '{s}' resolved to no address; Portal route disabled");
                None
            }
        },
        Err(e) => {
            eprintln!("ct-edge: CT_CP_PROXY_ADDR '{s}' does not resolve ({e}); Portal route disabled");
            None
        }
    }
}

/// Build a front-door terminate-cert acceptor from an env cert/key PEM pair
/// (#31 FD4-a, #48) — used per proxy host (Portal, Auth IdP). `None` when the pair
/// is unset (the host is then raw-proxied) or invalid (logged, raw-proxied).
/// #142: why a configured front-door vhost has no usable TLS cert (pure, testable). This fn
/// is only ever called for a vhost the operator DID configure for TLS termination, so any gap
/// means the vhost would silently raw-proxy — a plaintext downgrade to a non-TLS upstream, i.e.
/// a total outage (curl exit 35) surfaced nowhere but a startup log. `None` => both a cert and
/// a key value are present (a build attempt follows). `Some(reason)` => the material is
/// missing/empty and TLS can't be terminated; the caller MUST warn loudly.
fn front_door_cert_gap(
    cert: Option<&str>,
    key: Option<&str>,
    cert_env: &str,
    key_env: &str,
) -> Option<String> {
    let present = |v: Option<&str>| v.map(|s| !s.trim().is_empty()).unwrap_or(false);
    match (present(cert), present(key)) {
        (true, true) => None,
        (false, false) => Some(format!("{cert_env} and {key_env} unset/empty")),
        (false, true) => Some(format!("{cert_env} unset/empty")),
        (true, false) => Some(format!("{key_env} unset/empty")),
    }
}

fn build_front_door_cert(
    label: &str,
    cert_env: &str,
    key_env: &str,
) -> Option<tokio_rustls::TlsAcceptor> {
    let cert = std::env::var(cert_env).ok();
    let key = std::env::var(key_env).ok();
    // #142: a configured-but-unusable cert must NEVER silently degrade to a plaintext raw-proxy
    // (the upstream doesn't speak TLS -> total outage). If the material is missing/empty, warn
    // LOUD and distinctly here instead of the old silent `_ => None`.
    if let Some(gap) = front_door_cert_gap(cert.as_deref(), key.as_deref(), cert_env, key_env) {
        eprintln!(
            "ct-edge: WARNING — {label} front door has no usable TLS cert ({gap}); NOT terminating \
             TLS, {label} will be raw-proxied — likely a PLAINTEXT OUTAGE for this host [#142]"
        );
        return None;
    }
    match crate::transport::build_portal_acceptor(cert.as_deref().unwrap(), key.as_deref().unwrap()) {
        Ok(a) => {
            eprintln!("ct-edge: front door terminates {label} TLS ({cert_env})");
            Some(a)
        }
        Err(e) => {
            eprintln!(
                "ct-edge: WARNING — {label} TLS cert configured but UNUSABLE ({e}); NOT terminating \
                 TLS, {label} will be raw-proxied — likely a PLAINTEXT OUTAGE (fix {cert_env}/{key_env}) [#142]"
            );
            None
        }
    }
}

/// Optional native TLS termination for the browser WS channel listener
/// (`CT_EDGE_WS_CHANNEL_CERT`/`_KEY`). Unlike [`build_front_door_cert`]'s front-door
/// hosts, an ABSENT cert here is a normal, expected configuration -- plain `ws://`,
/// e.g. behind a reverse proxy that already terminates TLS (the deployed
/// CADS-webconference-demo's Caddy front does exactly this) or local dev with no TLS
/// at all -- so this stays silent rather than warning about an "outage" the way
/// `build_front_door_cert` does. A PARTIALLY set or configured-but-unusable pair
/// still warns loudly; that IS a real misconfiguration, same as the front-door case.
fn build_ws_channel_cert() -> Option<tokio_rustls::TlsAcceptor> {
    let cert_env = "CT_EDGE_WS_CHANNEL_CERT";
    let key_env = "CT_EDGE_WS_CHANNEL_KEY";
    let cert = std::env::var(cert_env).ok();
    let key = std::env::var(key_env).ok();
    let present = |v: &Option<String>| v.as_deref().map(|s| !s.trim().is_empty()).unwrap_or(false);
    match (present(&cert), present(&key)) {
        (false, false) => None,
        (true, true) => match crate::transport::build_portal_acceptor(cert.as_deref().unwrap(), key.as_deref().unwrap()) {
            Ok(a) => {
                eprintln!("ct-edge: ws-channel listener terminates TLS natively (wss://, {cert_env})");
                Some(a)
            }
            Err(e) => {
                eprintln!(
                    "ct-edge: WARNING — {cert_env}/{key_env} configured but UNUSABLE ({e}); \
                     ws-channel listener stays plain ws://"
                );
                None
            }
        },
        _ => {
            eprintln!(
                "ct-edge: WARNING — only one of {cert_env}/{key_env} is set; ws-channel \
                 listener stays plain ws:// (set both, or neither)"
            );
            None
        }
    }
}

/// Serve one plaintext HTTP/1.x request on `:80` with a `308 Permanent Redirect`
/// to the HTTPS URL for the same Host + path — so a browser typing
/// `http://<host>/…` is bounced to `https://<host>/…` on the unified `:443`
/// gateway. Generic over the byte stream so it drives a real socket live and an
/// in-memory duplex in tests. Reads only the request head (bounded), never a body.
/// #470: bounds the whole head-read below -- a real read deadline, not just the existing
/// 16KB size cap. This is the cheapest entry point on the whole edge (plaintext, no TLS
/// handshake, no PoW gate), so it's the easiest way to drain the shared connection cap
/// this listener shares with the QUIC/TCP data planes: connect, send `GET / HTTP` and
/// nothing more, and (before this) the task blocked forever holding its permit. A
/// redirect response needs no more than a couple of seconds to receive its request.
const HTTP_REDIRECT_READ_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn serve_http_redirect<S>(inbound: S) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::time::timeout(HTTP_REDIRECT_READ_TIMEOUT, serve_http_redirect_inner(inbound)).await {
        Ok(res) => res,
        Err(_) => Err(format!(
            "http-redirect: no complete request head within {HTTP_REDIRECT_READ_TIMEOUT:?} (#470)"
        )
        .into()),
    }
}

async fn serve_http_redirect_inner<S>(mut inbound: S) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read up to the header terminator (bounded — a redirect never needs a body).
    //
    // #341: only scan the newly-read tail for `\r\n\r\n`, not the whole
    // accumulated buffer on every iteration. The old `buf.windows(4).any(...)`
    // re-scanned everything read so far on every single read() -- O(n^2) in the
    // total bytes for a client that trickles the request in slowly (a scanner
    // dribbling 1 byte per read on the public :80 port could force ~128M
    // comparisons for one redirect before ever hitting the 16KB cap, real CPU
    // cost the size cap alone doesn't bound). `scanned` tracks how much of `buf`
    // has already been confirmed terminator-free; each iteration only re-checks
    // from `scanned - 3` (the terminator can start up to 3 bytes before new
    // data, spanning a read boundary) through the end -- bounding total scan
    // work to O(total bytes), not O(total bytes^2).
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    let mut scanned = 0usize;
    loop {
        let n = inbound.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        let start = scanned.saturating_sub(3);
        if buf[start..].windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16384 {
            break;
        }
        scanned = buf.len();
    }
    let req = String::from_utf8_lossy(&buf);
    let mut lines = req.split("\r\n");
    // Request line: METHOD SP request-target SP HTTP/x.
    let target = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .filter(|t| t.starts_with('/'))
        .unwrap_or("/");
    // Host header (case-insensitive), with any :port stripped (default to 443).
    let host = lines.find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.trim().eq_ignore_ascii_case("host") {
            let h = v.trim();
            // Strip a trailing :port on a plain host (skip bracketed IPv6).
            let h = if h.starts_with('[') { h } else { h.split(':').next().unwrap_or(h) };
            (!h.is_empty()).then(|| h.to_string())
        } else {
            None
        }
    });
    let resp = match host {
        Some(h) => format!(
            "HTTP/1.1 308 Permanent Redirect\r\nLocation: https://{h}{target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ),
        // No Host header -> can't build an absolute HTTPS URL.
        None => {
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
        }
    };
    inbound.write_all(resp.as_bytes()).await?;
    inbound.flush().await?;
    Ok(())
}

/// #31 FD2 — the unified `:443` front door. Restrictive client networks often
/// allow only outbound TCP 443 (HAW field evidence: `:8090`/`:4433`/UDP all time
/// out), so the Portal, the customer Browser-Plane subdomains, and the tunnel
/// data-plane fallback must all share one port. Buffer the ClientHello, classify
/// by ALPN-then-SNI ([`classify_front_door`]), then dispatch **without consuming
/// the handshake** — a [`Prepend`] replays the buffered bytes to the chosen
/// backend so no TLS record is lost:
///
/// - `EdgeRelay` (ALPN `ct-edge`): terminate TLS with the edge leaf and run the
///   TLS-TCP relay protocol ([`serve_tcp_connection`]) — the ADR-0004 fallback.
/// - `Proxy(host)` (SNI matches a `proxies` terminate-host — the Portal or, since
///   #48, the Auth IdP): with a TLS acceptor, terminate the browser's TLS and
///   reverse-proxy plaintext HTTP to that host's upstream (FD4-a); without one,
///   raw-proxy the TLS stream (a TLS-terminating upstream, e.g. a fronting Caddy).
/// - `BrowserTunnel(host)`: SNI-passthrough to the bound tunnel (TLS at Origin).
/// - `Reject`: close.
///
/// `proxies` maps a lowercased terminate-host to `(upstream, Option<TlsAcceptor>)`;
/// `default_host` is the terminate-host a web client with no SNI falls back to
/// (the Portal). Direct `:8090`/`:4433` listeners keep working; the front door is
/// additive and off unless `CT_FRONT_DOOR` is set.
pub type ProxyTarget = (SocketAddr, Option<tokio_rustls::TlsAcceptor>);

/// The membership-resolution seam the `:443` front door's `ChannelBroker` arm uses to
/// authorize a channel join (#106 frontdoor-wire). The live edge resolves against the
/// control plane via [`crate::channel_authorize::ChannelAuthorizer`]; tests supply a
/// mock. It is a boxed trait object (not a generic) so [`serve_front_door`] stays
/// non-generic — every non-channel caller just passes `None`. It yields exactly the
/// tuple [`crate::channel_broker::admit_and_pair_on_stream`]'s `authorize` closure
/// needs — `(operator_pubkey, member_noise, member_attestation)` iff `holder` is a
/// current member of `channel`, else `None` (fail-closed).
pub trait ChannelMemberResolver: Send + Sync {
    fn resolve_member<'a>(
        &'a self,
        channel: ct_common::channel::ChannelId,
        holder: [u8; 32],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>
                + Send
                + 'a,
        >,
    >;

    /// #555: has this holder's membership been **definitively** withdrawn — as opposed to
    /// "this resolver could not find out"? Used to end a splice that is already carrying
    /// bytes, never to admit one.
    ///
    /// The default answers `false`, and that default is the safety property: a resolver
    /// that cannot tell the two apart must never cause a live conversation to be cut. Only
    /// an implementation that can distinguish an authoritative refusal from an unreachable
    /// control plane (`ChannelAuthorizer`) overrides it. Admission keeps using
    /// `resolve_member` and keeps failing closed; the two directions want opposite defaults
    /// and now have them.
    fn membership_revoked<'a>(
        &'a self,
        _channel: ct_common::channel::ChannelId,
        _holder: [u8; 32],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async { false })
    }
}

impl ChannelMemberResolver for crate::channel_authorize::ChannelAuthorizer {
    fn resolve_member<'a>(
        &'a self,
        channel: ct_common::channel::ChannelId,
        holder: [u8; 32],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.resolve(&channel, &holder)
                .await
                .map(|m| (m.operator_pubkey, m.noise_pubkey, m.noise_attestation))
        })
    }
    fn membership_revoked<'a>(
        &'a self,
        channel: ct_common::channel::ChannelId,
        holder: [u8; 32],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async move { self.definitively_not_a_member(&channel, &holder).await })
    }

}

/// The concrete stream the `:443` front door hands the channel broker: the buffered
/// ClientHello (`Prepend`) replayed into the raw TCP socket, then TLS-terminated with
/// the edge leaf (the same acceptor the `EdgeRelay` leg uses). The shared pairer keys
/// its `AdmittedStreamMember`s on exactly this `S`, so it is named once here.
type FrontDoorChannelStream = tokio_rustls::server::TlsStream<Prepend<tokio::net::TcpStream>>;

/// The optional channel-broker context the `:443` front door needs to service a
/// `ct-edge-channel` ALPN member (#106 frontdoor-wire). Bundles the **long-lived**
/// shared [`crate::channel_broker::ChannelPairer`] (so two independently-arriving
/// `:443` members of the same channel correlate + pair — front-door members can't be
/// dialed, so "pair the next two arrivals" is wrong; they must correlate by
/// `ChannelId`) and the CP-backed membership [`ChannelMemberResolver`]. A cloned-Arc
/// context is handed to each `serve_front_door`; `None` disables channel brokering (the
/// arm returns a clear error), so every non-channel front-door caller/test is unaffected.
#[derive(Clone)]
pub struct ChannelFrontDoor {
    pairer: crate::channel_broker::SharedChannelPairer,
    resolver: Arc<dyn ChannelMemberResolver>,
    /// The DEDICATED TLS acceptor the ChannelBroker arm terminates with (#118): a
    /// CA-issued leaf whose `ServerConfig` advertises the `ct-edge-channel` ALPN, so the
    /// `:443` channel leg genuinely negotiates it (a readiness probe reading
    /// `alpn_protocol()` post-handshake sees `Some("ct-edge-channel")`, not `None`). Kept
    /// separate from the shared edge acceptor — advertising the channel ALPN there would
    /// make rustls fatal-alert the `EdgeRelay` leg's `ct-edge` clients on ALPN mismatch.
    acceptor: tokio_rustls::TlsAcceptor,
}

impl ChannelFrontDoor {
    /// Build a front-door channel context around a shared membership `resolver` (the
    /// CP-backed [`crate::channel_authorize::ChannelAuthorizer`] in production) and the
    /// dedicated `acceptor` that advertises the `ct-edge-channel` ALPN (#118). The
    /// pairer starts empty and is shared across every connection this context serves.
    ///
    /// #256: unlike the QUIC broker's own accept loop (which sweeps `drain_expired` on every
    /// iteration — see `run_channel_broker_loop`), the `:443` front door has no equivalent
    /// per-accept sweep point (each connection is dispatched independently by
    /// `serve_front_door`, not pulled from one serial loop that owns this pairer), so a lone
    /// parked member whose partner never arrives was held — and its TLS stream + socket kept
    /// open — forever: unbounded memory/FD growth on a long-running edge. Spawns a periodic
    /// reaper here instead, at the one place this pairer is actually constructed, so every
    /// caller gets it for free with no risk of forgetting to wire it up per front-door
    /// instance. Ticks at a fraction of the park TTL so an expired member is reaped promptly,
    /// not up to a full TTL late.
    /// Build around an EXTERNALLY shared pairer (cross-transport pairing): the caller
    /// ([`run_edge`]) constructs the pairer + spawns its reaper ONCE and shares it with
    /// every transport that opts into channel brokering, so a browser member
    /// (`ws_channel.rs`) and a `:443`/QUIC member of the same channel correlate through
    /// the SAME pairer and can pair with each other.
    pub fn new(
        resolver: Arc<dyn ChannelMemberResolver>,
        acceptor: tokio_rustls::TlsAcceptor,
        pairer: crate::channel_broker::SharedChannelPairer,
    ) -> Self {
        Self {
            pairer,
            resolver,
            acceptor,
        }
    }

    /// Like [`Self::new`], but builds its OWN standalone pairer + reaper instead of
    /// taking a shared one — for tests/callers that don't need cross-transport pairing.
    /// This is what `new` did unconditionally before cross-transport pairing existed.
    #[cfg(test)]
    pub fn standalone(resolver: Arc<dyn ChannelMemberResolver>, acceptor: tokio_rustls::TlsAcceptor) -> Self {
        let pairer = crate::channel_broker::new_shared_channel_pairer();
        spawn_front_door_pairer_reaper(
            pairer.clone(),
            Duration::from_secs(CHANNEL_PARK_TTL_SECS / 3),
            unix_now,
            |m| drop(m),
        );
        Self::new(resolver, acceptor, pairer)
    }
}

/// The real wall clock, as `UnixSeconds` — the production `now_fn` for
/// [`spawn_front_door_pairer_reaper`] (and every other "sample real time" call site in this
/// module that doesn't already have a local helper).
fn unix_now() -> ct_common::channel::UnixSeconds {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Lowercase hex of arbitrary bytes — for logging the PUBLIC channel/holder grant
/// fields in the pairer reapers here and in `ws_channel.rs` (the channel broker has
/// its own private equivalent, `hex_of`).
pub(crate) fn hex_of_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// #256: periodically evict `:443` channel members parked past their park TTL with no
/// partner. Dropping the drained `WaitingMember`s closes their `TlsStream` (and the
/// underlying `TcpStream`) via `Drop` — no explicit shutdown call needed, unlike the QUIC
/// broker's `conn.close(..)` (a `quinn::Connection` has no implicit-drop teardown semantics
/// the peer would ever observe). Runs for the process lifetime, mirroring every other
/// "never returns" background task in this module (e.g. `run_channel_broker_loop`).
/// `interval`/`now_fn` are injected so a test can observe real eviction on a fast clock
/// instead of waiting out the real `CHANNEL_PARK_TTL_SECS`. Generic over the pairer's
/// member type `T` (production always instantiates it at
/// `AdmittedStreamMember<FrontDoorChannelStream>` via [`ChannelFrontDoor::new`]) so a test
/// can park a lightweight fake member instead of a real TLS stream.
fn spawn_front_door_pairer_reaper<T, N, R>(
    pairer: Arc<std::sync::Mutex<crate::channel_broker::ChannelPairer<T>>>,
    interval: Duration,
    now_fn: N,
    on_reap: R,
) where
    T: Send + 'static,
    N: Fn() -> ct_common::channel::UnixSeconds + Send + Sync + 'static,
    R: Fn(crate::channel_broker::WaitingMember<T>) + Send + Sync + 'static,
{
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // #530: bounded reap logging. A serve-loop client parks by design forever and is
        // reaped+re-parked every TTL cycle (ct-agent#21 — correct), so the per-member
        // line below repeated identically ~10k/day from a handful of pairs and drowned
        // real signals. First reap per (channel,holder) pair per window still logs in
        // full; repeats surface as ONE summary line per window.
        let mut throttle = crate::channel_broker::ReapLogThrottle::new(
            crate::channel_broker::REAP_LOG_SUMMARY_WINDOW_SECS,
            crate::channel_broker::REAP_LOG_MAX_TRACKED_PAIRS,
            crate::channel_broker::REAP_LOG_TOP_PAIRS,
        );
        loop {
            ticker.tick().await;
            let now = now_fn();
            // #497: poison-resilient; #499 slice B: drain also silently discards corpse
            // parks (client died while queued) -- surface the per-sweep count so silent
            // discards stay operator-visible without per-corpse identity spam.
            let (expired, dead_dropped) = {
                let mut p = pairer.lock_safe();
                (p.drain_expired(now), p.take_dead_dropped())
            };
            if dead_dropped > 0 {
                eprintln!(
                    "ct-edge: front-door channel pairer dropped {dead_dropped} corpse park(s) — client died while queued (#499)"
                );
            }
            // One full line per (channel,holder) pair PER SUMMARY WINDOW (#530), naming
            // the public grant fields (channel/holder hex -- never a secret): a live
            // operator watching repeated lone-member reaps (a client whose PARTNER never
            // arrives, e.g. still stuck on a blocked QUIC rung while this side came in
            // via :443) could previously see only that it was happening, never WHICH
            // channel kept half-joining. Same identification fields the admission
            // refusals already log (#124/#248-follow). Steady-state repeats of the same
            // pair are aggregated into the window summary below instead of repeating the
            // line unboundedly.
            for m in expired {
                crate::channel_broker::note_channel_park_reaped();
                if throttle.note_reap(now, &hex_of_bytes(&m.channel.0), &hex_of_bytes(&m.holder))
                    == crate::channel_broker::ReapLogDecision::LogFull
                {
                    eprintln!(
                        "ct-edge: front-door channel pairer reaped a member parked past its TTL with no partner — channel={} holder={}",
                        hex_of_bytes(&m.channel.0),
                        hex_of_bytes(&m.holder),
                    );
                }
                // ct-agent#21: the caller decides how a reaped member is torn down --
                // production notifies the live client with the EX token (so it re-parks on
                // the same rung instead of misreading a silent close as a rung failure);
                // tests pass a no-op.
                on_reap(m);
            }
            if let Some(s) = throttle.window_summary(now) {
                eprintln!(
                    "ct-edge: front-door channel pairer reap summary (#530) — {} reap(s) of {} distinct (channel,holder) pair(s) in the last {}s ({} beyond the tracking cap); repeats after each pair's first full line are aggregated here; top: {}",
                    s.total,
                    s.distinct_keys,
                    crate::channel_broker::REAP_LOG_SUMMARY_WINDOW_SECS,
                    s.untracked,
                    s.top
                        .iter()
                        .map(|((c, h), n)| format!("channel={c} holder={h} x{n}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                );
            }
        }
    });
}

/// Bounds one `:443` channel join's admission read (#105 parity with the QUIC broker's
/// `JOIN_READ_TIMEOUT`): a legitimate join completes in one CP authorize round-trip plus
/// a local possession exchange; a slower/hostile client is dropped so it can't wedge the
/// arm.
const CHANNEL_JOIN_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a lone first-arriving `:443` channel member stays parked in the pairer,
/// waiting for its partner, before it is eligible for eviction via
/// [`crate::channel_broker::ChannelPairer::drain_expired`] (#109 #3). Generous, since the
/// two holders of a channel may reach `:443` seconds apart. Actually evicted by the periodic
/// reaper [`ChannelFrontDoor::new`] spawns (#256) — this constant alone only marks eligibility.
const CHANNEL_PARK_TTL_SECS: u64 = 30;

/// #575: the first ct-agent release whose KA legs actually survive a long park.
///
/// This number is the whole safety argument for raising `CT_EDGE_KA_PARK_TTL_SECS`, and it
/// used to be prose repeated in three places, all three naming a release that was
/// **v0.4.19 — never cut** (the v0.4 line ends at v0.4.18). An operator checking their fleet
/// against it got an unanswerable question.
///
/// The real dates, from the ct-agent history:
///
/// | what | release |
/// |---|---|
/// | client OFFERS the KA ALPNs — which is what makes this edge grant the long TTL | v0.4.13 |
/// | client CARRIES the tick-based wait contract — which is what makes the long TTL safe | v0.5.0 |
///
/// Those are six releases apart, so `v0.4.13`…`v0.4.18` claim the capability without
/// implementing it: the edge grants them a long park and their unchanged 45 s admission
/// bound abandons it. The ALPN handshake is therefore NOT proof of the wait contract, and
/// this edge cannot tell the two generations apart — see #575 for the structural fix
/// (a distinct ALPN id for the tick generation, which needs a client release first).
/// Until then the floor is an operator obligation, not something the edge can verify.
pub(crate) const KA_TICK_CONTRACT_MIN_AGENT: &str = "v0.5.0";

/// #506: park TTL for a **KA-negotiated** `:443` leg, from `CT_EDGE_KA_PARK_TTL_SECS`.
/// The 30 s default TTL predates the KA contract — it was the only bound when parks
/// were blind; since #499b/#500 a KA park is OBSERVED (10 s NUL ticks, corpse
/// detection ≤10 s), so a long TTL is no resource risk and ends the idle EX/re-park
/// cycle. Defaults to [`CHANNEL_PARK_TTL_SECS`] (i.e. **unchanged**) because the
/// deployed client fleet must first carry the tick-based wait contract (ct-agent
/// [`KA_TICK_CONTRACT_MIN_AGENT`]): an older client's 45 s admission-exchange bound fires before a long
/// park's EX, cycling at 45 s with stale parks holding permits — flip the env only
/// once the fleet is ready (rollout order documented in #506). Non-KA legs always
/// keep the short TTL: without ticks, the short bound IS their corpse control.
fn ka_park_ttl_secs_from(v: Option<&str>) -> u64 {
    v.and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&s| s > 0)
        .unwrap_or(CHANNEL_PARK_TTL_SECS)
}

fn ka_park_ttl_secs() -> u64 {
    let ttl = ka_park_ttl_secs_from(std::env::var("CT_EDGE_KA_PARK_TTL_SECS").ok().as_deref());
    // #575: this edge CANNOT verify the precondition it depends on -- it never sees a client
    // version, and the ALPN handshake that grants the long TTL was shipped six releases
    // before the wait contract that makes it safe (see `KA_TICK_CONTRACT_MIN_AGENT`). So the
    // one thing it can do is state the obligation, once, at the moment the switch starts
    // mattering. Silence here was the whole problem: the flip left no trace naming what it
    // assumed about the fleet, and the number it was assumed against did not exist.
    if ttl != CHANNEL_PARK_TTL_SECS {
        static SAID: std::sync::Once = std::sync::Once::new();
        SAID.call_once(|| {
            eprintln!(
                "ct-edge: KA park TTL raised to {ttl}s (default {CHANNEL_PARK_TTL_SECS}s) -- \
                 this is SAFE ONLY IF every ct-agent reaching this edge is \
                 {KA_TICK_CONTRACT_MIN_AGENT} or newer; older KA clients (v0.4.13+) negotiate \
                 the same ALPN but abandon a long park at their 45s admission bound. This edge \
                 cannot check that (#575)."
            );
        });
    }
    ttl
}

/// Bound how long a public `:443` client may take to deliver its complete TLS ClientHello
/// (#111 Slowloris defense). A real browser ships the ClientHello in its first TCP
/// segment(s); a Slowloris client instead dribbles or stalls mid-record to pin the
/// connection open forever. #119 already caps concurrent front-door connections
/// (`ConnectionCap`), but a stalled read still holds its cap permit indefinitely, so N slow
/// clients exhaust the cap and lock out the port — the cap needs a companion read deadline.
/// Applied at BOTH public entry points ([`serve_front_door`] and [`serve_sni_passthrough`]);
/// the pure parsers in [`crate::sni`] stay timeout-free so their unit tests are unaffected.
const CLIENT_HELLO_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// #258: bound on the TLS handshake and admission exchange (role byte, per-role
/// fixed-size reads/writes like the token, hostname, or 40-byte PoW solution) on the
/// TCP-fallback path -- the same slow-drip concern [`CLIENT_HELLO_READ_TIMEOUT`]
/// addresses for the :443 front door, which that timeout does NOT cover (this is a
/// separate listener). Applies only to the bounded admission prefix of
/// [`serve_tcp_connection`]'s TLS handshake and each role arm; the long-lived phase
/// after admission (`park_tcp_agent`, relay, `wait_for_tcp_agent`) is deliberately left
/// unbounded, same as everywhere else in this file.
const TCP_FALLBACK_ADMISSION_TIMEOUT: Duration = Duration::from_secs(10);

/// ct-agent#15 flap follow-up: how often the Edge sends a real-payload PING
/// frame (see [`send_ping_and_await_pong`]) into a **parked** TCP-fallback
/// registration (role `'K'`, the ping-capable variant of `'A'`) while it
/// waits for a Client. Deliberately shorter than the 10s TCP keepalive
/// interval ([`crate::transport::apply_tcp_keepalive`]) so this fires FIRST:
/// keepalive is a bare ACK-only segment some enterprise firewalls/DPI/SASE
/// gateways don't count as "activity" for their own idle-timeout bookkeeping
/// (only real payload traffic does) -- this frame is real payload traffic on
/// both legs of the round trip (PING edge->agent, PONG agent->edge), closing
/// that gap. Pre-Noise, below the end-to-end-encrypted payload entirely (the
/// edge legitimately originates and observes it) -- see the module doc on
/// [`serve_tcp_connection`]'s `'K'` arm for the full wire format and the
/// race-free handoff design.
///
/// #528: the framed relay phase injects its in-flight keepalive on this SAME
/// measured cadence, via the codec's `KEEPALIVE_INTERVAL` constant -- the
/// coupling is textual (asserted in this file's invariants test), since the
/// codec crate cannot see this private constant.
const TCP_PING_INTERVAL: Duration = Duration::from_secs(8);

/// Bound on one PING/PONG round trip ([`send_ping_and_await_pong`]) during the
/// parked-ping loop. A missed/slow PONG is NOT treated as a hard failure --
/// TCP keepalive (tightened in ct-agent#15) remains the authoritative
/// liveness/failure-detection mechanism; this frame is a pure best-effort
/// activity-generation enhancement layered on top of it, never a replacement.
/// Only a genuine I/O error (EOF/reset/broken pipe) while writing the PING or
/// reading the PONG is propagated as fatal, since that means the connection
/// itself is dead, not merely that one probe was slow.
const TCP_PING_PONG_TIMEOUT: Duration = Duration::from_secs(5);

/// First byte of a parked-registration PING frame (Edge -> ping-capable
/// Agent): `0xF9 | counter(8 BE)`, 9 bytes total. Chosen from the unused
/// 0xF0-0xFF range so it can never collide with a role byte (`'A'`..`'Z'`,
/// ASCII) or an `OK`/`NO` ack.
const TCP_PING_MAGIC: u8 = 0xF9;

/// First byte of the matching PONG reply (ping-capable Agent -> Edge):
/// `0xFA | counter(8 BE)` echoing the PING's counter, 9 bytes total.
const TCP_PONG_MAGIC: u8 = 0xFA;

/// Single-byte STOP sentinel, written by the Edge into a ping-capable (`'K'`)
/// parked stream EXACTLY ONCE, strictly before it hands the stream to
/// [`relay`]'s `copy_bidirectional` for a real Client.
///
/// Why this is needed (not just "read until you don't see 0xF9 anymore"):
/// once a real Client is spliced in, the very next bytes on this stream are
/// the start of a genuine Noise handshake -- effectively-random-looking
/// ciphertext/DH-public-key material from the Agent's point of view. A ping-
/// capable Agent that tried to distinguish "still in ping phase" from "real
/// data started" purely by checking whether the first byte equals
/// [`TCP_PING_MAGIC`] would have a real (~1/256) chance of misreading a
/// genuine Noise byte as a spurious PING and corrupting/hanging the
/// handshake. `TCP_PING_STOP` removes that ambiguity entirely: the Agent's
/// ping-phase reader never has to guess from byte content, because the Edge
/// -- which is the sole authority on "has a Client actually arrived" (an
/// internal state transition on `parked`, never inferred from stream bytes)
/// -- explicitly announces the transition. TCP's in-order, single-connection
/// delivery guarantees the Agent sees this byte strictly before any relayed
/// byte, since the Edge only ever calls `relay` (which is the first point
/// real Client bytes can reach this stream) AFTER this write completes.
const TCP_PING_STOP: u8 = 0xFB;

/// #422: bound on completing the TLS handshake itself (`TlsAcceptor::accept`) on the
/// three `:443` front-door legs that terminate TLS at the edge -- `EdgeRelay`, `Proxy`,
/// and Gelb-terminate ([`serve_gelb_terminated`]). [`CLIENT_HELLO_READ_TIMEOUT`] only
/// bounds reading the ClientHello bytes; the handshake completion that follows (key
/// exchange, certificate send, Finished) was unbounded, so a peer that opens a TCP
/// connection, sends a valid ClientHello, then stalls mid-handshake held a
/// [`crate::state::ConnectionCap`] permit forever -- N such connections exhaust the cap
/// the same way an un-timed-out ClientHello read did before #111. Same 10s value as
/// [`CLIENT_HELLO_READ_TIMEOUT`]/[`TCP_FALLBACK_ADMISSION_TIMEOUT`] for consistency; a
/// real TLS handshake is a handful of round trips, not a long-lived exchange.
const FRONT_DOOR_TLS_ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);

/// #549: the mesh-relay leg's counterparts to [`FRONT_DOOR_TLS_ACCEPT_TIMEOUT`] -- same
/// class as #422, one leg over. [`relay_via_peer_edge`] dials a peer edge and waits for
/// its 2-byte `OK`; both waits were unbounded, so a peer edge that accepts the TCP
/// connection and then goes silent held the browser connection (and the
/// `browser_tunnel_cap` sub-permit taken by the `BrowserTunnel` arm, #254) forever. The
/// two are kept SEPARATE rather than folded into one bound because they fail for
/// different reasons and an operator has to tell them apart: a dial that never completes
/// means the peer edge is unreachable (network, firewall, wrong `peer_addr` in the
/// registry), while a missing ACK means it is reachable but not answering the mesh-relay
/// role (hung, wrong admin token, not serving 'M'). 10s each, matching every other
/// front-door bound in this file.
/// #555: guards the membership re-check loop against a second spawn -- the authorizer is
/// constructed at four places and more than one of them can run in a single configuration.
static MEMBERSHIP_RECHECK_STARTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

const MESH_RELAY_DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const MESH_RELAY_ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// Read the raw front-door ClientHello under [`CLIENT_HELLO_READ_TIMEOUT`] (#111): the
/// timeout-bounded seam wrapping the panic-free parser [`crate::sni::read_client_hello_bytes`]
/// so a client that stalls mid-record is dropped (freeing its #119 cap permit) instead of
/// wedging the port. Kept as a named helper — separate from the parser — so the timeout is
/// unit-testable over an in-memory duplex.
async fn read_client_hello_bytes_bounded<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<Vec<u8>, BoxError> {
    tokio::time::timeout(CLIENT_HELLO_READ_TIMEOUT, crate::sni::read_client_hello_bytes(stream))
        .await
        .map_err(|_| "front door: ClientHello read timed out")?
        .ok_or_else(|| "front door: not a TLS ClientHello".into())
}

/// #533: the classes of `:443` front-door failure that are just a client hanging up —
/// normal, expected browser/HTTP-client behavior, not an edge-side fault.
///
/// Measured on `help.bunsenbrenner.org` (2026-08-16 load test, 340 requests, **zero
/// failed requests**): 143 `ECONNRESET` + 15 missing-`close_notify` lines in the same
/// five minutes, against exactly 2 real signals (a scanner's hostname miss and a
/// non-TLS handshake). The real signals were unfindable in the noise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ClientAbortClass {
    /// `ECONNRESET` — the client sent an RST. The overwhelming majority case: a
    /// browser/`curl` that closes a keep-alive connection with unread data still in
    /// its receive buffer makes the kernel answer subsequent bytes with an RST.
    ConnectionReset,
    /// `EPIPE`/`BrokenPipe` — the client's half went away while the edge was writing.
    BrokenPipe,
    /// rustls' "peer closed connection without sending TLS close_notify": the client
    /// dropped the TCP connection instead of shutting the TLS session down cleanly.
    /// Ubiquitous among real HTTP clients.
    TlsCloseNotifyMissing,
}

impl ClientAbortClass {
    /// Stable, greppable label for the summary line (never an operator-visible
    /// error message — those keep their original wording).
    pub fn label(self) -> &'static str {
        match self {
            Self::ConnectionReset => "connection-reset",
            Self::BrokenPipe => "broken-pipe",
            Self::TlsCloseNotifyMissing => "tls-close-notify-missing",
        }
    }
}

/// #533: rustls' message for "the peer just dropped the TCP connection instead of
/// sending `close_notify`" (`rustls::conn` `UNEXPECTED_EOF_MESSAGE`, surfaced through
/// `tokio-rustls` as an `io::Error` of kind `UnexpectedEof` carrying exactly this
/// text). See [`classify_io_client_abort`] for why the text — not just the kind — is
/// the discriminator here.
const RUSTLS_MISSING_CLOSE_NOTIFY: &str = "peer closed connection without sending TLS close_notify";

/// #533: how far [`classify_client_abort`] walks an error's `source()` chain looking
/// for the underlying `io::Error`. The measured lines are bare boxed `io::Error`s
/// (depth 0), but an arm that wraps its transport error (hyper, a framing layer)
/// must not silently lose the classification. Bounded so a pathological/cyclic chain
/// can never spin this cold path.
const CLIENT_ABORT_SOURCE_CHAIN_DEPTH: usize = 8;

/// #533: does this `io::Error` mean "the client hung up", as opposed to a real
/// edge-side failure?
///
/// **Typed, not string-matched**, for the two socket classes: `ErrorKind` is the
/// contract, so a libc/OS message reword cannot silently re-enable the noise (nor,
/// worse, silently start suppressing something else).
///
/// The rustls class is the one exception, and deliberately so: rustls reports it as a
/// plain `io::Error` (`ErrorKind::UnexpectedEof` + a fixed message) rather than a
/// downcastable `rustls::Error`, so there is no type to match on — and `UnexpectedEof`
/// **alone** is NOT a benign-abort signal in this codebase (a torn frame mid-protocol
/// surfaces as exactly that kind, and is a genuine connection error the fallback
/// framing documents as such — see `ct_common::fallback_framing`). The substring is
/// therefore used to NARROW a typed check, never to replace one: it can only ever
/// shrink what is treated as benign. Same documented-fallback pattern as ct-agent's
/// `is_definitive_admission_refusal`, and it fails safe in the same direction — if
/// rustls ever rewords the message, this class simply reverts to being logged loudly
/// line by line (the pre-#533 behavior), never the reverse.
fn classify_io_client_abort(e: &std::io::Error) -> Option<ClientAbortClass> {
    match e.kind() {
        std::io::ErrorKind::ConnectionReset => Some(ClientAbortClass::ConnectionReset),
        std::io::ErrorKind::BrokenPipe => Some(ClientAbortClass::BrokenPipe),
        std::io::ErrorKind::UnexpectedEof if e.to_string().contains(RUSTLS_MISSING_CLOSE_NOTIFY) => {
            Some(ClientAbortClass::TlsCloseNotifyMissing)
        }
        _ => None,
    }
}

/// #533: pure classifier — is this front-door error a benign client abort, and which
/// class? `None` means "not provably benign", which is the ONLY verdict that matters
/// for #127: anything unclassified stays loud, line for line, unchanged.
pub fn classify_client_abort(e: &BoxError) -> Option<ClientAbortClass> {
    let root: &(dyn std::error::Error + 'static) = e.as_ref();
    let mut cur = Some(root);
    for _ in 0..CLIENT_ABORT_SOURCE_CHAIN_DEPTH {
        let err = cur?;
        if let Some(io) = err.downcast_ref::<std::io::Error>() {
            if let Some(class) = classify_io_client_abort(io) {
                return Some(class);
            }
        }
        cur = err.source();
    }
    None
}

/// #533: the boolean spelling of [`classify_client_abort`], for call sites that only
/// need "may this be condensed?".
pub fn is_benign_client_abort(e: &BoxError) -> bool {
    classify_client_abort(e).is_some()
}

/// #533: `ct_edge_front_door_client_aborts_total` — every benign `:443` front-door
/// client abort, INCLUDING the ones whose log line the throttle suppresses. Sibling of
/// `ct_edge_channel_park_reaped_total` (#530) and static for the same reason: the
/// front-door connection handler deliberately has no `EdgeState` handle for this.
/// The counter is the complete record; the log is the bounded diagnostic sample.
static FRONT_DOOR_CLIENT_ABORTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// #533: `ct_edge_front_door_client_aborts_total` for `/metrics`.
pub fn front_door_client_aborts_total() -> u64 {
    FRONT_DOOR_CLIENT_ABORTS.load(std::sync::atomic::Ordering::Relaxed)
}

/// #533: how long one front-door client-abort summary window lasts. Same 10 min as the
/// reap throttle's window (#530) — long enough that a busy edge condenses hundreds of
/// lines into one, short enough that a rate change is still visible in the log alone.
pub(crate) const FRONT_DOOR_ABORT_LOG_WINDOW_SECS: u64 = 600;

/// #533: cap on the abort classes tracked per window. The key space is a closed enum
/// today (3 variants), so the cap can never bite in production — it exists because the
/// shared throttle's memory bound is a property of the core, not of the caller, and it
/// keeps the invariant true if the classifier ever gains a data-derived key.
pub(crate) const FRONT_DOOR_ABORT_LOG_MAX_TRACKED_CLASSES: usize = 8;

/// #533: how many classes a window summary names explicitly.
pub(crate) const FRONT_DOOR_ABORT_LOG_TOP_CLASSES: usize = 3;

/// #533: what [`log_front_door_error`] did with one front-door error — returned so a
/// test can pin the decision without capturing stderr.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FrontDoorErrorLog {
    /// NOT a provably benign client abort: logged in full, unconditionally, exactly as
    /// before #533. This is the #127 property ("nothing fails invisibly") and it is
    /// never throttled — no window, no cap, no aggregation.
    Loud,
    /// A benign abort, first of its class this window: logged in full (annotated).
    BenignFirst(ClientAbortClass),
    /// A benign abort, a repeat this window: not logged (only under `CT_EDGE_TRACE`);
    /// counted in the metric and in the window summary.
    BenignSuppressed(ClientAbortClass),
}

/// #533: log one `:443` front-door handler error, condensing the benign client-abort
/// classes and leaving everything else exactly as loud as #127 made it.
///
/// Event-driven rather than tick-driven (unlike the #530 reapers, this path has no
/// periodic loop to hang a window rollover on): each abort first rolls the previous
/// window over if it has elapsed, then notes itself. Consequence, deliberately
/// accepted: on an edge that goes quiet, the last window's summary waits for the next
/// abort. That costs nothing in fidelity — `ct_edge_front_door_client_aborts_total`
/// counts every abort the moment it happens and is the complete record.
/// #533-follow: `leg` names which listener is reporting. The classifier and the throttle
/// are shared; only the prefix differs. The `:4433` TCP-fallback arm logged every failure
/// as a flat "connection error" -- 44 such lines in three hours on 2026-08-17, all of them
/// ordinary client aborts, in exactly the log an operator greps while investigating
/// ct-agent#15's "the edge drops connections" symptom. Classifying one arm and not its
/// sibling left the noise that made the fault look real.
fn log_front_door_error_on(
    leg: &str,
    log: &std::sync::Mutex<crate::log_throttle::WindowLogThrottle<ClientAbortClass>>,
    now: ct_common::channel::UnixSeconds,
    e: &BoxError,
) -> FrontDoorErrorLog {
    // #127: log any front-door failure (TLS accept, routing, every arm) — the whole
    // handler's `Result` used to be discarded, so a connection that reached the edge
    // but failed anywhere in serve_front_door was completely invisible to the
    // operator. Unclassified == loud, always, first thing.
    let Some(class) = classify_client_abort(e) else {
        eprintln!("ct-edge: {leg} connection error: {e}");
        return FrontDoorErrorLog::Loud;
    };
    FRONT_DOOR_CLIENT_ABORTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (summary, decision) = {
        let mut t = log.lock_safe(); // #497-style poison resilience; no await under the lock
        (t.window_summary(now), t.note(now, class))
    };
    if let Some(s) = summary {
        eprintln!(
            "ct-edge: {leg} benign client-abort summary (#533) — {} abort(s) of {} distinct class(es) in the last {}s ({} beyond the tracking cap); repeats after each class's first full line are aggregated here; top: {}",
            s.total,
            s.distinct_keys,
            FRONT_DOOR_ABORT_LOG_WINDOW_SECS,
            s.untracked,
            s.top
                .iter()
                .map(|(c, n)| format!("{} x{n}", c.label()))
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    match decision {
        crate::log_throttle::LogDecision::LogFull => {
            // Same leading text as before #533 (operators grep it; it is the line the
            // issue was filed about) plus the classification, so it is obvious that
            // further aborts of this class are being aggregated rather than lost.
            eprintln!(
                "ct-edge: {leg} connection error: {e} (benign client abort, class={}; further ones this window are aggregated — #533)",
                class.label()
            );
            FrontDoorErrorLog::BenignFirst(class)
        }
        crate::log_throttle::LogDecision::Suppress => {
            // The per-occurrence view the issue asked to keep reachable: still
            // available on demand, just not in the default operator log.
            edge_trace(format_args!(
                "{leg} benign client abort (class={}): {e}",
                class.label()
            ));
            FrontDoorErrorLog::BenignSuppressed(class)
        }
    }
}

/// The `:443` front door's leg label, kept as a named constant so the two call sites cannot
/// drift into differently-worded prefixes that an operator's grep would then miss.
const LEG_FRONT_DOOR: &str = ":443 front-door";
/// The direct `:4433` TCP-fallback listener (a client that bypasses the unified front door).
const LEG_TCP_FALLBACK: &str = "TCP fallback (:4433)";

fn log_front_door_error(
    log: &std::sync::Mutex<crate::log_throttle::WindowLogThrottle<ClientAbortClass>>,
    now: ct_common::channel::UnixSeconds,
    e: &BoxError,
) -> FrontDoorErrorLog {
    log_front_door_error_on(LEG_FRONT_DOOR, log, now, e)
}

pub async fn serve_front_door(
    mut inbound: tokio::net::TcpStream,
    state: &EdgeState<Connection>,
    acceptor: &tokio_rustls::TlsAcceptor,
    proxies: &std::collections::HashMap<String, ProxyTarget>,
    default_host: Option<&str>,
    challenge: &Challenge,
    channel: Option<&ChannelFrontDoor>,
    wildcard_acceptor: Option<&tokio_rustls::TlsAcceptor>,
    mesh_relay: Option<&MeshRelayConfig>,
    relay_gate: Option<&crate::relay_gate::RelayGateContext>,
    browser_tunnel_cap: Option<&ConnectionCap>,
    // #410: the TCP-fallback Agent-registration sub-cap -- threaded through to the
    // `EdgeRelay` arm's `serve_tcp_connection` call so a `:443` front-door connection
    // that ends up in role 'A'/'B' gets the SAME protection as the dedicated TCP
    // fallback listener (see `tcp_agent_cap`'s doc in `run_edge`).
    tcp_agent_cap: Option<&ConnectionCap>,
    // #451: this connection's own accept-loop `ConnectionCap` permit (`None` when
    // uncapped), OWNED by this call rather than held in a wrapping `let _permit = ..;`
    // by the caller. Every arm except `ChannelBroker` already blocks for the
    // connection's whole real lifetime inside this function, so simply letting Rust
    // drop it when this function returns reproduces the caller's old behavior exactly.
    // The `ChannelBroker` arm is the one that DOESN'T block for the connection's real
    // lifetime (it can return the instant a lone member parks, or after merely
    // spawning the relay for a matched pair) -- so it explicitly moves `permit` into
    // `admit_and_pair_on_boxed_stream`, which carries it on the constructed member so it
    // travels with the connection instead of dropping early. See #451's issue for the
    // "0 permits for 2N live sockets" gap this closes.
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> Result<(), BoxError> {
    // #121 Phase B1: the member's reflexive (post-NAT) source, captured from the accepted TCP
    // socket before `inbound` is consumed, so a `:443`/front-door channel join can observe it
    // (the TLS-TCP analog of QUIC's `conn.remote_address()`).
    let observed = inbound.peer_addr()?;
    let hello = read_client_hello_bytes_bounded(&mut inbound).await?;
    // #339: no per-connection `Vec<String>`/`Vec<&str>` collection here anymore --
    // `classify_front_door` parses `hello` directly and this closure does a
    // case-insensitive scan of `proxies`' own (already-lowercased) keys, which
    // costs nothing to build since it captures `proxies` by reference. `proxies`
    // is a small, fixed set (Portal + optional Auth IdP, built once at process
    // start, not one entry per live tunnel), so the O(n) scan here is negligible.
    match crate::sni::classify_front_door(&hello, |h| proxies.keys().any(|k| k.eq_ignore_ascii_case(h)), default_host) {
        crate::sni::FrontDoorRoute::EdgeRelay => {
            let joined = Prepend {
                pre: hello,
                pos: 0,
                inner: inbound,
            };
            let tls = tokio::time::timeout(FRONT_DOOR_TLS_ACCEPT_TIMEOUT, acceptor.accept(joined))
                .await
                .map_err(|_| -> BoxError { "front door: TLS handshake not completed within the timeout (#422)".into() })??;
            serve_tcp_connection(tls, state, challenge, tcp_agent_cap).await
        }
        crate::sni::FrontDoorRoute::Proxy(host) => {
            let (addr, tls) = proxies
                .get(&host)
                .ok_or("front door: no proxy target for the matched host")?;
            let joined = Prepend {
                pre: hello,
                pos: 0,
                inner: inbound,
            };
            match tls {
                // FD4-a / #48: TERMINATE the browser's TLS with this host's cert,
                // then reverse-proxy plaintext HTTP to its upstream (Portal control
                // plane, or the Keycloak IdP) — so an HTTP-only upstream serves over
                // HTTPS on :443, one cert per host.
                Some(pacc) => {
                    let mut tls = tokio::time::timeout(FRONT_DOOR_TLS_ACCEPT_TIMEOUT, pacc.accept(joined))
                        .await
                        .map_err(|_| -> BoxError { "front door: TLS handshake not completed within the timeout (#422)".into() })??;
                    let mut upstream = tokio::net::TcpStream::connect(*addr).await?;
                    tokio::io::copy_bidirectional(&mut tls, &mut upstream).await?;
                    Ok(())
                }
                // Raw-proxy: only serves if the upstream itself terminates TLS (e.g.
                // a fronting Caddy). Kept for that topology.
                None => {
                    let mut joined = joined;
                    let mut upstream = tokio::net::TcpStream::connect(*addr).await?;
                    tokio::io::copy_bidirectional(&mut joined, &mut upstream).await?;
                    Ok(())
                }
            }
        }
        crate::sni::FrontDoorRoute::BrowserTunnel(host) => {
            // #254: this arm is reached with an attacker-controlled SNI hostname and no
            // per-token/PoW gate of its own -- admit against its own sub-cap, separate
            // from the shared front-door `conn_cap` already held for this connection, so
            // a flood here sheds without touching the budget Portal/auth/channel traffic
            // depend on. Held for the rest of this arm's lifetime (relay or passthrough).
            let _browser_tunnel_permit = match browser_tunnel_cap {
                Some(cap) => Some(
                    cap.try_admit()
                        .ok_or("front door: BrowserTunnel connection cap reached — shedding (#254)")?,
                ),
                None => None,
            };
            let joined = Prepend {
                pre: hello,
                pos: 0,
                inner: inbound,
            };
            // ADR-0021 Part 1: a genuine LOCAL miss (no route on this edge at
            // all) tries the mesh-relay fallback first, when configured --
            // off by default (CT_EDGE_MESH_RELAY_ENABLED), so this is a no-op
            // until an operator actually runs a second edge. A raw byte relay
            // to whichever peer edge the registry says owns `host`, same as
            // `serve_sni_passthrough` relays raw bytes to a local Agent --
            // the peer edge applies its OWN tier dispatch (Gelb/Grün/etc), not
            // this one's, since it's the one that actually owns the tunnel.
            // A miss on the mesh lookup too (nobody owns it anywhere, or the
            // registry is unreachable) falls through to today's unchanged
            // behavior below.
            if state.route_host(&host).is_none() {
                if let Some(mesh) = mesh_relay {
                    if let Some(peer_addr) = mesh_relay_lookup_cached(mesh, &host).await {
                        let target = safe_peer_edge_target(&peer_addr).ok_or(
                            "mesh-relay registry returned an invalid or non-global-unicast peer_addr — refusing to dial (#253)",
                        )?;
                        return relay_via_peer_edge(joined, target, &host, mesh.edge_cert.clone(), mesh.admin_token)
                            .await;
                    }
                }
            }
            // #233: a hostname the control plane has explicitly marked Gelb
            // gets edge-terminated with the shared wildcard cert instead of
            // passthrough; every other hostname (not yet provisioned, or
            // already Grün with its own real cert) is completely unaffected
            // -- this is the ONLY new branch in this arm, the passthrough
            // call below is untouched.
            match wildcard_acceptor {
                Some(wildcard) if state.is_gelb(&host) => {
                    serve_gelb_terminated(joined, &host, state, wildcard).await
                }
                _ => serve_sni_passthrough(joined, state).await,
            }
        }
        // #106 frontdoor-wire: a channel member whose network blocks the channel port
        // (`:4435`) reached the `:443` front door with the channel ALPN. Without a
        // configured broker context we can't authorize joins (the CP-backed resolver is
        // the membership gate) — refuse clearly. With one: TLS-terminate with the edge
        // leaf (same as the `EdgeRelay` leg), admit the join over that stream, and offer
        // it to the shared channel-keyed pairer. The first holder of a channel parks
        // (`Ok(None)`); when its partner arrives (`Ok(Some((a, b)))`) relay-splice exactly
        // those two `:443` members on their own task so the accept loop stays free.
        crate::sni::FrontDoorRoute::ChannelBroker => {
            let Some(ctx) = channel else {
                return Err(
                    "front door: channel :443 brokering not configured \
                     (set CT_EDGE_CP_URL + CT_EDGE_ADMIN_TOKEN)"
                        .into(),
                );
            };
            // Per-IP definitive-refusal penalty (2026-08-13 storm), enforced BEFORE the
            // TLS handshake -- same budget the QUIC broker loops consult, so a storm
            // client that falls back to the `:443` leg (exactly what ct-agent's dial
            // ladder does when UDP fails) is shed just as cheaply here. Silent per shed
            // (power-of-two logging), and scoped to the ChannelBroker arm only: every
            // other front-door route from the same possibly-NAT-shared IP is untouched.
            {
                let now = unix_now();
                if state.join_penalized(observed.ip(), now) {
                    let total = state.join_refusal_penalty().note_shed();
                    if total.is_power_of_two() || total % 1000 == 0 {
                        eprintln!(
                            "ct-edge: channel-join penalty shedding {} pre-handshake (:443) — {total} connection(s) shed since start",
                            observed.ip()
                        );
                    }
                    return Ok(());
                }
            }
            let joined = Prepend {
                pre: hello,
                pos: 0,
                inner: inbound,
            };
            // #118: terminate with the DEDICATED channel acceptor (advertises the
            // `ct-edge-channel` ALPN) rather than the shared edge acceptor (empty ALPN),
            // so the channel leg actually negotiates the ALPN a readiness probe checks.
            // #127: a TLS-handshake failure at the dedicated channel-ALPN acceptor happens
            // BEFORE admission, so #124/#125's per-checkpoint logs never run — tag it so a
            // silent `Refused` (e.g. #103's) surfaces under `grep 'channel-join NO'`.
            // #452: this TLS accept was the one front-door arm with a cap but no handshake
            // timeout (the `EdgeRelay`/`Proxy` arms already wrap theirs in
            // `FRONT_DOOR_TLS_ACCEPT_TIMEOUT`, see #422) -- a peer that opens the TCP
            // connection, sends a valid ClientHello (so it classifies to this arm), then
            // stalls mid-handshake held this connection's cap permit forever.
            let tls: FrontDoorChannelStream = tokio::time::timeout(FRONT_DOOR_TLS_ACCEPT_TIMEOUT, ctx.acceptor.accept(joined))
                .await
                .map_err(|_| -> BoxError { "front door: channel TLS handshake not completed within the timeout (#422/#452)".into() })?
                .map_err(|e| { eprintln!("ct-edge: channel-join NO [tls-accept]: {e}"); e })?;
            // #500 K2: the negotiated ALPN IS the park-keepalive capability handshake --
            // `ct-edge-channel-ka` on the plain leg, or `http/1.1` on the boring leg
            // (deliberately selected over `h2` by the acceptor's preference order; an old
            // client's [h2]-only or bare-channel-ALPN offer lands on the non-KA ids). See
            // `build_channel_front_door_acceptor` for the full negotiation table.
            let keepalive = matches!(
                tls.get_ref().1.alpn_protocol(),
                Some(p) if p == crate::sni::CT_EDGE_CHANNEL_KA_ALPN.as_bytes() || p == b"http/1.1"
            );
            let now = unix_now();
            // Same closure shape the QUIC broker builds from its `ChannelAuthorizer`,
            // here routed through the boxed resolver so a test can supply a mock.
            let resolver = ctx.resolver.clone();
            let authorize = move |c: ct_common::channel::ChannelId, h: [u8; 32]| {
                let resolver = resolver.clone();
                async move { resolver.resolve_member(c, h).await }
            };
            // Boxed into the shared cross-transport stream type (#495) so this `:443`
            // member correlates through the SAME pairer a browser member
            // (ws_channel.rs) offers itself to -- either can now be the partner.
            let boxed: crate::channel_broker::BoxedChannelStream = Box::pin(tls);
            // #451: `permit` (this connection's own accept-loop cap permit) is moved into
            // admission here rather than merely held by the caller's task wrapper -- this
            // is the one arm where that distinction matters: a lone member parks (`Ok(None)`)
            // and this whole function returns while the live TLS stream stays open inside
            // `ctx.pairer`, or a matched pair's relay is handed to a freshly spawned task
            // below. Carrying the permit on the constructed `AdmittedStreamMember` (inside
            // `admit_and_pair_on_boxed_stream`) means it now travels with the connection through
            // either path instead of releasing the moment this function returns.
            let paired = match crate::channel_broker::admit_and_pair_on_boxed_stream(
                boxed,
                observed,
                now,
                CHANNEL_JOIN_TIMEOUT,
                &authorize,
                // #506: an observed (KA) park may outlive the blind 30 s default —
                // TTL choice is per-leg, driven by the negotiated ALPN generation.
                now + if keepalive { ka_park_ttl_secs() } else { CHANNEL_PARK_TTL_SECS },
                &ctx.pairer,
                permit,
                keepalive,
            )
            .await
            {
                Ok(p) => p,
                Err(e) => {
                    // Feed the shared per-IP penalty on DEFINITIVE refusals only (typed,
                    // never string-matched) -- mirror of the QUIC broker loop's recording.
                    if crate::channel_broker::is_definitive_join_refusal(&e)
                        && state.note_definitive_join_refusal(observed.ip(), now)
                    {
                        eprintln!(
                            "ct-edge: channel-join penalty engaged for {} — definitive-refusal budget exhausted; shedding its joins pre-handshake for the rest of the window",
                            observed.ip()
                        );
                    }
                    return Err(e);
                }
            };
            if let Some(((a, a_phase), (b, b_phase))) = paired {
                // #495 slice 2b / #511: the phase→completion rule lives in ONE place
                // (`channel_broker::completion_for`) — both-rendezvous pairs get
                // ack-then-close (the contract their ack readers expect), everything
                // else keeps the historical splice.
                let completion = crate::channel_broker::completion_for(a_phase, b_phase);
                tokio::spawn(async move {
                    let r = match completion {
                        crate::channel_broker::StreamPairCompletion::RendezvousClose => {
                            crate::channel_broker::finish_rendezvous_pair_over_streams(a, b, now).await
                        }
                        crate::channel_broker::StreamPairCompletion::Splice => {
                            crate::channel_broker::finish_relay_pair_over_streams(a, b, now).await
                        }
                    };
                    if let Err(e) = r {
                        eprintln!("ct-edge: front-door :443 channel pairing ended: {e}");
                    }
                });
            }
            Ok(())
        }
        // Real NAT-to-NAT hole-punch relay: grant + possession pre-auth
        // (`relay_gate::admit_relay_gate`), then a raw byte splice to the internal
        // relay-node — see `relay_gate.rs` for the full design rationale.
        crate::sni::FrontDoorRoute::RelayGate => {
            let Some(ctx) = relay_gate else {
                return Err(
                    "front door: relay gate not configured (set CT_EDGE_RELAY_UPSTREAM)".into(),
                );
            };
            // #547: the last of the four channel-join paths to consult the shared per-IP
            // budget. A refused attempt costs MORE here than anywhere else -- TLS with the
            // gate's own acceptor, a control-plane member lookup, an Ed25519 verify, fresh
            // challenge bytes and a write, all before anything is refused -- so shedding
            // early is worth more here, not less. Same budget as the QUIC loops, the
            // ChannelBroker arm and the WS listener (#542), never a fourth one beside them.
            {
                let now = unix_now();
                if state.join_penalized(observed.ip(), now) {
                    let total = state.join_refusal_penalty().note_shed();
                    if total.is_power_of_two() || total % 1000 == 0 {
                        eprintln!(
                            "ct-edge: channel-join penalty shedding {} pre-handshake (relay-gate) — {total} connection(s) shed since start",
                            observed.ip()
                        );
                    }
                    return Ok(());
                }
            }
            let joined = Prepend {
                pre: hello,
                pos: 0,
                inner: inbound,
            };
            let now = unix_now();
            let out = crate::relay_gate::serve_relay_gate(joined, ctx, now).await;
            // A definitive refusal here is the same class the budget was built for
            // (not-member / grant-verify / possession), typed rather than string-matched.
            if let Err(e) = &out {
                if crate::channel_broker::is_definitive_join_refusal(e)
                    && state.note_definitive_join_refusal(observed.ip(), now)
                {
                    eprintln!(
                        "ct-edge: channel-join penalty engaged for {} (relay-gate) — definitive-refusal budget exhausted; shedding its joins pre-handshake for the rest of the window",
                        observed.ip()
                    );
                }
            }
            out
        }
        crate::sni::FrontDoorRoute::Reject => Ok(()),
    }
}

/// #449: bounds the main data-plane path's own first-stream admission the same way
/// the channel broker already bounds its own (`accept_bi_timeout` in
/// `channel_broker.rs`) -- the Edge's QUIC transport keeps a connection's idle timer
/// alive via automatic keepalive ACKs regardless of whether the peer ever sends an
/// application byte, so a peer that completes the handshake and opens no stream
/// (or opens one and never sends its role byte) held its connection-cap permit
/// forever before this existed. `CLIENT_HELLO_READ_TIMEOUT`'s value (10s) is reused
/// for consistency; a real Agent/Client's role byte follows immediately after
/// `accept_bi`, so 10s is already generous slack, not a tight bound.
const ROLE_DISPATCH_TIMEOUT: Duration = Duration::from_secs(10);

/// #449: the PoW-response read (role `'C'`) needs more slack than
/// [`ROLE_DISPATCH_TIMEOUT`] -- unlike the other role-dispatch reads, the client is
/// expected to spend real CPU time solving the challenge before it can respond, not
/// just round-trip a fixed byte count. #413 already caps how much difficulty a
/// client will *attempt*, bounding legitimate solve time; this bounds the wait on
/// the Edge's side to something clearly larger than any legitimate capped solve.
const POW_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// Serve one connection by dispatching on its first stream's role byte. `'A'`
/// registers an Agent tunnel (`token`); `'C'` runs a PoW-gated rendezvous, then
/// routes and relays the same stream to the Agent. This is the unified
/// per-connection Edge protocol the daemon's accept loop runs.
pub async fn serve_connection(
    conn: &Connection,
    state: &EdgeState<Connection>,
    challenge: &Challenge,
) -> Result<Option<(RoutingToken, u64)>, BoxError> {
    let (mut send, mut recv) = tokio::time::timeout(ROLE_DISPATCH_TIMEOUT, conn.accept_bi())
        .await
        .map_err(|_| "serve_connection: no stream opened within the admission timeout (#449)")??;
    let mut role = [0u8; 1];
    tokio::time::timeout(ROLE_DISPATCH_TIMEOUT, recv.read_exact(&mut role))
        .await
        .map_err(|_| "serve_connection: role byte not received within the admission timeout (#449)")??;

    match role[0] {
        b'A' => {
            let mut token = [0u8; 32];
            tokio::time::timeout(ROLE_DISPATCH_TIMEOUT, recv.read_exact(&mut token))
                .await
                .map_err(|_| "serve_connection: token not received within the admission timeout (#449)")??;
            let token = RoutingToken(token);
            // #27 RB3 / #421: a revoked token stays down even though the agent
            // keeps reconnecting — refuse the registration instead of accepting
            // it. Checked-and-registered atomically (one `registration_lock`
            // acquisition inside `register_with_candidate_unless_revoked`) so a
            // concurrent revoke can't complete inside the gap between a
            // separate check and a separate register call — see that method's
            // doc for the exact race this closes.
            let Some(reg) =
                state.register_with_candidate_unless_revoked(token.clone(), conn.clone(), conn.remote_address())
            else {
                send.write_all(b"NO").await?;
                send.finish()?;
                return Ok(None);
            };
            send.write_all(b"OK").await?;
            send.finish()?;
            // #583: this event was previously silent -- diagnosing whether an
            // outage was a real deregistration or just a dead-but-not-yet-evicted
            // connection required inference from unrelated log lines.
            {
                let mut th_buf = [0u8; 8];
                let th = token_hex(&token, &mut th_buf);
                eprintln!(
                    "ct-edge: agent registered token={th} reg={reg} remote={:?} (#583)",
                    conn.remote_address()
                );
            }
            // #603: durable record of this registration's source IP -- a real
            // Agent (holder of the routing token), not a rendezvous client.
            if let Some(log) = state.audit_log() {
                if let Err(e) = log.record(
                    crate::audit_log::ConnTransport::QuicRelayAgent,
                    conn.remote_address().ip(),
                    unix_now() as i64,
                    Some(&hex_of_bytes(&token.0)),
                    None,
                    None,
                ) {
                    eprintln!("ct-edge: audit-log record failed: {e} (#603)");
                }
            }
            // Return the (token, registration id) so the caller can evict exactly
            // THIS agent when its connection drops — issue #2 (mode a): a dropped
            // agent's registration was never removed, so a later Client `route()`
            // kept resolving to a dead `Connection` whose `open_bi()` stalls.
            // The registration id (not just the token) is what makes eviction
            // precise now that multiple agents may register one token for
            // redundancy (#8): dropping one must not disturb the others.
            // Eviction lives in `run_edge`, which owns the connection lifetime;
            // keeping this path non-blocking preserves the "register then return"
            // contract the relay harnesses depend on (they serve 'A' then 'C' on
            // one task).
            Ok(Some((token, reg)))
        }
        b'C' => {
            let mut chal = [0u8; 17];
            chal[..16].copy_from_slice(&challenge.nonce);
            chal[16] = challenge.difficulty;
            send.write_all(&chal).await?;

            let mut req = [0u8; 40];
            tokio::time::timeout(POW_RESPONSE_TIMEOUT, recv.read_exact(&mut req))
                .await
                .map_err(|_| "serve_connection: PoW response not received within the timeout (#449)")??;
            let token = check_request(challenge, &req).map_err(|_| "proof of work rejected")?;

            // #472: reject a token that resolves to no registered Agent (QUIC
            // or TCP-fallback) before it ever reaches the rate limiter --
            // otherwise a flooder rotating random tokens gets a fresh
            // per-token budget and a fresh limiter-map entry on every
            // attempt, and the per-token cap below never actually engages
            // against that attack shape. Only resolvable tokens occupy a
            // limiter slot.
            if !state.is_resolvable(&token) {
                return Err("unknown routing token".into());
            }

            // #86 (ADR-0018): per-token rendezvous rate limit — PoW raises per-attempt
            // cost, this caps how many rendezvous a single token drives per window.
            if !state.rendezvous_allowed(&token, rendezvous_window()) {
                return Err("rendezvous rate limit exceeded".into());
            }

            // #603: durable record of this rendezvous client's source IP -- PoW
            // solved, token resolvable, rate limit clear, i.e. a real client about
            // to be routed to its tunnel (not yet whether TCP-fallback or QUIC).
            if let Some(log) = state.audit_log() {
                if let Err(e) = log.record(
                    crate::audit_log::ConnTransport::QuicRelayClient,
                    conn.remote_address().ip(),
                    unix_now() as i64,
                    Some(&hex_of_bytes(&token.0)),
                    None,
                    None,
                ) {
                    eprintln!("ct-edge: audit-log record failed: {e} (#603)");
                }
            }

            // A QUIC client must also reach a TCP-fallback agent (#13): the TCP
            // path prefers a parked TCP agent, and the QUIC path must mirror it or
            // a QUIC-client → TCP-agent tunnel is invisible and dies with
            // `early eof`. If one is parked, hand off the joined client stream
            // (cross-transport QUIC↔TCP relay); otherwise keep the QUIC→QUIC
            // relay_quic path unchanged.
            if state.has_tcp_agent(&token) {
                match state.deliver_to_tcp_agent_draining(&token, Box::new(join(recv, send))) {
                    Ok(()) => return Ok(None),
                    // Raced (the parked agent was consumed between check and
                    // deliver) → relay this client to a QUIC agent instead.
                    Err(mut client) => {
                        let (agent_send, agent_recv) = open_agent_stream(state, &token).await?;
                        let mut agent = join(agent_recv, agent_send);
                        let (a, b) = until_revoked(state, &token, relay(&mut client, &mut agent)).await?; // #554
                        state.note_relay(&token, a, b, crate::state::RelayKind::DataPlane);
                        return Ok(None);
                    }
                }
            }
            match open_agent_stream(state, &token).await {
                Ok((agent_send, agent_recv)) => {
                    let mut th_buf = [0u8; 8];
                    // #554: this is the QUIC data plane -- a ct-client talking to its agent --
                    // and it was the ONE token-carrying relay the guard never covered. The
                    // structural test enumerated `relay(&mut` / `framed_relay(&mut` and this
                    // call is neither: a different relay function, and split over two lines so
                    // no line-shaped pattern could have matched it either. Revoking a tunnel's
                    // token therefore did not cut an already-flowing client session here, while
                    // it did on every other transport.
                    let (a, b) = until_revoked(
                        state,
                        &token,
                        relay_quic(send, recv, agent_send, agent_recv, token_hex(&token, &mut th_buf)),
                    )
                    .await?;
                    state.note_relay(&token, a, b, crate::state::RelayKind::DataPlane); // #10 O2
                    Ok(None)
                }
                Err(e) => {
                    // Same momentarily-exhausted-pool recovery as
                    // serve_sni_passthrough (#229 follow-up): this QUIC client
                    // may be reaching an agent that is TCP-fallback-only.
                    if state.wait_for_tcp_agent(&token, TCP_FALLBACK_DELIVER_WAIT).await
                        && state
                            .deliver_to_tcp_agent_draining(&token, Box::new(join(recv, send)))
                            .is_ok()
                    {
                        return Ok(None);
                    }
                    // #589: pool depth at give-up time, same reasoning as the SNI/Gelb legs.
                    let pool = state.tcp_parked_for(&token);
                    Err(format!("{e} — tcp_fallback_pool={pool}").into())
                }
            }
        }
        b'D' => {
            // Agent advertises its direct-path listener (M11.4b-ii):
            // token(32) | addr_len(1) | addr | cert_len(2 BE) | cert.
            let mut token = [0u8; 32];
            recv.read_exact(&mut token).await?;
            let mut al = [0u8; 1];
            recv.read_exact(&mut al).await?;
            let mut addr_buf = vec![0u8; al[0] as usize];
            recv.read_exact(&mut addr_buf).await?;
            let mut cl = [0u8; 2];
            recv.read_exact(&mut cl).await?;
            let mut cert = vec![0u8; u16::from_be_bytes(cl) as usize];
            recv.read_exact(&mut cert).await?;
            let addr: SocketAddr = std::str::from_utf8(&addr_buf)?.parse()?;
            state.advertise_direct(RoutingToken(token), addr, cert);
            send.write_all(b"OK").await?;
            send.finish()?;
            Ok(None)
        }
        b'H' => {
            // Browser Plane (#23 BP3): bind a public hostname to a routing token
            // so an SNI-routed browser connection reaches this tunnel. Wire
            // format: 'H' | token(32) | host_len(2 BE) | host. A browser-mode
            // agent declares its hostname after registering the tunnel ('A').
            let mut token = [0u8; 32];
            recv.read_exact(&mut token).await?;
            let mut hl = [0u8; 2];
            recv.read_exact(&mut hl).await?;
            let hlen = u16::from_be_bytes(hl) as usize;
            if hlen == 0 || hlen > 253 {
                return Err("invalid Browser-Plane hostname length".into());
            }
            let mut host = vec![0u8; hlen];
            recv.read_exact(&mut host).await?;
            let host = std::str::from_utf8(&host).map_err(|_| "hostname is not valid UTF-8")?;
            let token = RoutingToken(token);
            // Hostname-ownership authorization (#23 BP4b): on a reachable :443,
            // refuse a bind the control plane hasn't authorized for this token —
            // an anonymous 'H' bind can't claim someone's name.
            if !state.host_bind_allowed(host, &token) {
                // #502: the wire answer is a bare "NO" either way, so this log line
                // is the only place the two refusal causes are distinguishable —
                // an authorization miss here is usually the agent's bind racing the
                // control plane's authorize-host call (freshly onboarded agent).
                eprintln!(
                    "ct-edge: refused hostname bind for '{host}' (no authorization for this token — \
                     authorize-host not yet landed, or never granted) (#502)"
                );
                send.write_all(b"NO").await?;
                send.finish()?;
                return Ok(None);
            }
            // Takeover-safe (#23 BP4a): refuse if the hostname is already bound to
            // a different tunnel, so a later bind can't silently steal the route.
            match state.register_host(host, token) {
                Ok(()) => send.write_all(b"OK").await?,
                Err(reason) => {
                    // #502/#513: name the WHY -- the revoke case (re-provision the
                    // agent) needs a different operator reaction than a takeover.
                    let why = match reason {
                        crate::state::HostBindRefusal::MalformedHostname => "malformed hostname",
                        crate::state::HostBindRefusal::Revoked => "token revoked -- re-provision this agent",
                        crate::state::HostBindRefusal::BoundToDifferentToken => "already bound to a DIFFERENT token",
                    };
                    eprintln!("ct-edge: refused hostname bind for '{host}': {why} (#502)");
                    send.write_all(b"NO").await?;
                }
            }
            send.finish()?;
            Ok(None)
        }
        b'P' => {
            // Client queries the Agent's advertised direct endpoint (M11.4b-ii):
            // reply `[0]` if none, else `[1] addr_len(1) addr cert_len(2 BE) cert`.
            // Separate from the 'C' relay flow — it changes no data path.
            let mut token = [0u8; 32];
            recv.read_exact(&mut token).await?;
            match state.direct_endpoint(&RoutingToken(token)) {
                Some((addr, cert)) => {
                    let a = addr.to_string();
                    let ab = a.as_bytes();
                    send.write_all(&[1u8, ab.len() as u8]).await?;
                    send.write_all(ab).await?;
                    send.write_all(&(cert.len() as u16).to_be_bytes()).await?;
                    send.write_all(&cert).await?;
                }
                None => {
                    send.write_all(&[0u8]).await?;
                }
            }
            send.finish()?;
            Ok(None)
        }
        b'W' => {
            // Reflexive-address echo (STUN-like, "whoami"): no token, no admission
            // check, no state mutation. quinn already knows the caller's real UDP
            // source address for THIS connection (`conn.remote_address()`) — this
            // just tells the caller what it is, so a DCUtR-punching channel member
            // can seed its candidate pool with a GENUINE UDP-observed reflexive
            // address instead of blindly reusing one observed over a different
            // transport (the :443 relay-gate's TCP admission), which a NAT maps to
            // a different external port and made the QUIC direct-dial upgrade
            // consistently fail (#248/#238). Safe unauthenticated: it reveals only
            // the caller's own already-known public address and offers no proxy/
            // relay capability to abuse, unlike an open relay.
            let addr = conn.remote_address().to_string();
            let ab = addr.as_bytes();
            send.write_all(&[ab.len() as u8]).await?;
            send.write_all(ab).await?;
            send.finish()?;
            Ok(None)
        }
        b'R' => {
            // #27 RB3: authenticated revoke — `'R' | admin_token(32) | routing_token(32)`.
            // The control plane calls this when a customer revokes a tunnel; the
            // edge tears the tunnel down and blocks its re-registration.
            let mut auth = [0u8; 32];
            recv.read_exact(&mut auth).await?;
            let mut token = [0u8; 32];
            recv.read_exact(&mut token).await?;
            if state.admin_revoke_ok(&auth) {
                state.revoke_token(&RoutingToken(token));
                send.write_all(b"OK").await?;
            } else {
                send.write_all(b"NO").await?;
            }
            send.finish()?;
            Ok(None)
        }
        other => Err(format!("unknown role byte: {other}").into()),
    }
}

/// Serve a whole QUIC connection: the first stream, then — if it was an Agent
/// registration (`'A'`) — every subsequent control stream the Agent opens on the
/// same connection until it closes (#40). An Agent binds its Browser-Plane
/// hostname with a **separate** `'H'` stream *after* `'A'`; handling only the
/// first stream left that bind unaccepted, so `route_host` never resolved.
/// Returns the registration (from the `'A'` stream) for eviction on drop. A
/// non-Agent first stream (a Client `'C'`, a direct query) is served once as
/// before.
pub async fn serve_agent_connection(
    conn: &Connection,
    state: &EdgeState<Connection>,
    challenge: &Challenge,
) -> Result<Option<(RoutingToken, u64)>, BoxError> {
    let registered = serve_connection(conn, state, challenge).await;
    if matches!(registered, Ok(Some(_))) {
        // Keep accepting the Agent's further streams ('H' bind, re-register);
        // the loop ends when accept_bi errors as the connection closes.
        while serve_connection(conn, state, challenge).await.is_ok() {}
    }
    registered
}

/// Write one [`TCP_PING_MAGIC`] frame carrying `counter`, then read back
/// exactly 9 bytes and check the first is [`TCP_PONG_MAGIC`] -- one full
/// PING/PONG round trip against a **ping-capable** (role `'K'`) parked Agent
/// stream. Bounded by [`TCP_PING_PONG_TIMEOUT`].
///
/// The reply's 8 counter bytes are deliberately NOT compared against
/// `counter`: the whole point of this frame is to put real payload bytes on
/// the wire so middleboxes see activity, and a reply that is well-formed but
/// carries a stale counter still proves exactly that (it just means an
/// in-flight probe crossed with a new one). Enforcing an exact echo would
/// turn a harmless crossing into a spurious dead-connection verdict. The
/// counter is still sent, and Agents are still specified to echo it (see
/// [`TCP_PONG_MAGIC`]), so it stays available for diagnostics and for any
/// future stricter check.
///
/// Returns `Ok(())` on a clean round trip. Returns `Err` ONLY on a genuine
/// I/O failure (write failed, or the read hit EOF/reset before 9 bytes
/// arrived), a reply whose magic byte is wrong (a peer that is not speaking
/// this protocol at all), or the round trip timing out -- all cases the
/// caller ([`park_and_ping`]) treats as the parked connection being dead,
/// same as any other relay I/O error.
async fn send_ping_and_await_pong<S>(stream: &mut S, counter: u64) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(TCP_PING_PONG_TIMEOUT, async {
        let mut frame = [0u8; 9];
        frame[0] = TCP_PING_MAGIC;
        frame[1..9].copy_from_slice(&counter.to_be_bytes());
        stream.write_all(&frame).await?;
        stream.flush().await?;

        let mut reply = [0u8; 9];
        stream.read_exact(&mut reply).await?;
        if reply[0] != TCP_PONG_MAGIC {
            return Err::<(), BoxError>("malformed PONG (bad magic byte)".into());
        }
        Ok(())
    })
    .await
    .map_err(|_: tokio::time::error::Elapsed| -> BoxError { "PING/PONG round trip timed out".into() })?
}

/// Park a **ping-capable** (role `'K'`) TCP-fallback registration and, while
/// waiting for a real Client to arrive, keep real payload bytes flowing over
/// the still-idle connection every [`TCP_PING_INTERVAL`] (ct-agent#15
/// follow-up: closes the gap left by TCP keepalive alone, whose bare ACK-only
/// probes some middleboxes don't count as "activity").
///
/// **Race-free handoff by construction**: the `select!` below only ever polls
/// `parked` OR runs one full, sequentially-awaited PING/PONG round trip via
/// [`send_ping_and_await_pong`] -- never both at once. A round trip is never
/// left half-finished when the loop yields back to `select!`, so there is
/// never a PING outstanding (and therefore never an unsolicited PONG that
/// could still be in flight) at the instant `parked` is observed to resolve.
/// `biased` additionally prefers delivering an already-arrived Client over
/// starting one more probe. The result: by the time this function returns
/// `Ok`, the connection is quiescent (no ping-protocol bytes pending on
/// either side), so the caller can hand `stream` straight to
/// [`relay`]'s `copy_bidirectional` with zero risk of a stray ping/pong byte
/// leaking into the real Client's Noise-encrypted payload. The only cost is a
/// bounded delivery delay (at most [`TCP_PING_PONG_TIMEOUT`]) if a Client
/// happens to arrive mid-round-trip.
/// Shared admission body for `serve_tcp_connection`'s `'A'` and `'K'` arms
/// (identical wire behavior up to and including the `OK`/`NO` ack -- they
/// differ only in what happens AFTER admission, which each arm handles
/// itself). Reads `token(32)`, admits against `tcp_agent_cap` (#410), parks
/// via `park_tcp_agent_unless_revoked` (#411), and acks. Returns `Ok(None)`
/// when admission was refused inline (`NO` already sent, nothing left to do)
/// or `Ok(Some((parked, sub_permit)))` on success. `role_label` is only used
/// in the timeout error message so each arm's diagnostics stay
/// distinguishable.
///
/// **The `#410` sub-cap permit is returned, not held here, and the caller MUST
/// keep it alive for as long as it keeps the connection** (parked, then
/// relaying). That is the whole point of the sub-cap: it bounds how many
/// TCP-fallback Agent registrations can sit parked at once, so an
/// unauthenticated flood exhausts at most this dedicated sub-budget instead of
/// the OUTER, shared connection cap that every other listener draws from. If
/// this helper dropped the permit on return, the cap would be released the
/// instant admission finished and would bound nothing at all -- see the two
/// `_410` regression tests, which assert `tcp_agent_cap.in_use()` while the
/// registration is still parked.
async fn admit_tcp_agent_a<S>(
    stream: &mut S,
    state: &EdgeState<Connection>,
    tcp_agent_cap: Option<&ConnectionCap>,
    role_label: &'static str,
) -> Result<
    Option<(
        RoutingToken,
        tokio::sync::oneshot::Receiver<crate::state::BoxedStream>,
        Option<tokio::sync::OwnedSemaphorePermit>,
    )>,
    BoxError,
>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (_token, parked, sub_permit) = tokio::time::timeout(TCP_FALLBACK_ADMISSION_TIMEOUT, async {
        let mut token_buf = [0u8; 32];
        stream.read_exact(&mut token_buf).await?;
        let token = RoutingToken(token_buf);
        let sub_permit = tcp_agent_cap.and_then(|cap| cap.try_admit());
        if tcp_agent_cap.is_some() && sub_permit.is_none() {
            stream.write_all(b"NO").await?;
            stream.flush().await?;
            return Ok::<_, BoxError>((token, None, None));
        }
        let parked = state.park_tcp_agent_unless_revoked(token.clone());
        if parked.is_some() {
            stream.write_all(b"OK").await?;
        } else {
            stream.write_all(b"NO").await?;
        }
        stream.flush().await?;
        Ok::<_, BoxError>((token, parked, sub_permit))
    })
    .await
    .map_err(|_| format!("tcp-fallback: role '{role_label}' admission timed out"))??;
    Ok(parked.map(|parked| (_token, parked, sub_permit)))
}

/// The Browser-Plane counterpart to [`admit_tcp_agent_a`]: the admission body
/// shared by roles `'B'`, `'L'` and `'F'` (#528), byte-identical between them
/// so the only difference between those arms is what happens *after* parking
/// (plain await vs [`park_and_ping`], raw [`relay`] vs [`framed_relay`]).
///
/// Browser register (#41 FB1): registers the tunnel AND binds a public hostname in
/// ONE message, because the TLS-TCP fallback has a single stream and cannot carry
/// a separate `'H'` bind like the QUIC path. Wire:
/// `<role> | token(32) | host_len(2 BE) | host`.
///
/// `None` means admission was refused inline (`NO` already sent) -- the caller just
/// returns. #258: the whole exchange is bounded. #410: admitted against
/// `tcp_agent_cap` right after the token is known, BEFORE the hostname is even
/// read, and ahead of `host_bind_allowed`/`register_host`, so a flood that finds
/// the sub-cap full never touches the hostname-routing table at all.
async fn admit_tcp_agent_b<S>(
    stream: &mut S,
    state: &EdgeState<Connection>,
    tcp_agent_cap: Option<&ConnectionCap>,
    role_label: &'static str,
) -> Result<
    Option<(
        RoutingToken,
        tokio::sync::oneshot::Receiver<crate::state::BoxedStream>,
        Option<tokio::sync::OwnedSemaphorePermit>,
    )>,
    BoxError,
>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let admitted = tokio::time::timeout(TCP_FALLBACK_ADMISSION_TIMEOUT, async {
        let mut token_buf = [0u8; 32];
        stream.read_exact(&mut token_buf).await?;
        let token = RoutingToken(token_buf);
        let sub_permit = tcp_agent_cap.and_then(|cap| cap.try_admit());
        if tcp_agent_cap.is_some() && sub_permit.is_none() {
            stream.write_all(b"NO").await?;
            stream.flush().await?;
            return Ok::<_, BoxError>(None);
        }
        let mut hl = [0u8; 2];
        stream.read_exact(&mut hl).await?;
        let hlen = u16::from_be_bytes(hl) as usize;
        if hlen == 0 || hlen > 253 {
            return Err("invalid Browser-Plane hostname length".into());
        }
        let mut host = vec![0u8; hlen];
        stream.read_exact(&mut host).await?;
        let host = std::str::from_utf8(&host).map_err(|_| "hostname is not valid UTF-8")?.to_string();
        // Same gates as the QUIC 'H' bind: authorization (#23 BP4b) + takeover-safe.
        if !state.host_bind_allowed(&host, &token) || state.register_host(&host, token.clone()).is_err() {
            stream.write_all(b"NO").await?;
            stream.flush().await?;
            return Ok::<_, BoxError>(None);
        }
        stream.write_all(b"OK").await?;
        stream.flush().await?;
        Ok(Some((token, sub_permit)))
    })
    .await
    .map_err(|_| format!("tcp-fallback: role '{role_label}' admission timed out"))??;
    let Some((token, sub_permit)) = admitted else { return Ok(None) };
    // Returned UN-awaited: the caller decides whether to await it plainly ('B') or
    // to keep the idle connection alive with `park_and_ping` while waiting ('L').
    let parked = state.park_tcp_agent(token.clone());
    Ok(Some((token, parked, sub_permit)))
}

async fn park_and_ping<S>(
    stream: &mut S,
    parked: tokio::sync::oneshot::Receiver<crate::state::BoxedStream>,
) -> Result<crate::state::BoxedStream, ParkAndPingError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::pin!(parked);
    let mut counter: u64 = 0;
    loop {
        tokio::select! {
            biased;
            res = &mut parked => {
                let client = res.map_err(|_| ParkAndPingError::NoClient(
                    "tcp-fallback: parked registration superseded/dropped before a Client arrived".into(),
                ))?;
                // Verify-at-delivery (ct-agent#15 follow-up, residual ~40% failure with 'L'
                // active): the cadence ping only proves liveness as of up to
                // TCP_PING_INTERVAL ago -- a connection the middlebox killed since then is
                // an up-to-8s-stale corpse, and splicing a Client onto it fails the
                // request. One final PING/PONG round trip right before the STOP sentinel
                // converts that stale-delivery failure into a detectable one, and --
                // crucially -- RESCUES the client stream so the caller can hand it to the
                // next parked slot instead of losing the request. Extra pre-STOP pings are
                // explicitly legal in the wire contract (both 'K' and 'L' clients consume
                // any number of well-formed PING frames until STOP), so this is compatible
                // with every ping-capable client already deployed.
                match send_ping_and_await_pong(stream, counter).await {
                    Ok(()) => return Ok(client),
                    Err(e) => return Err(ParkAndPingError::AgentDead { client, source: e }),
                }
            }
            _ = tokio::time::sleep(TCP_PING_INTERVAL) => {
                // #528 review finding 7: a cadence ping that FAILS must not silently
                // drop a Client that was delivered into the oneshot during this round
                // trip's (up to TCP_PING_PONG_TIMEOUT) window -- that lost the request
                // outright. Before giving up, check the slot: a Client already waiting
                // there is rescued via the SAME AgentDead failover the pre-STOP verify
                // ping uses (the parked agent is provably dead, but the Client's stream
                // is handed to the next parked slot instead of vanishing); only a
                // genuinely empty/closed slot is the terminal NoClient.
                if let Err(source) = send_ping_and_await_pong(stream, counter).await {
                    return Err(match parked.as_mut().get_mut().try_recv() {
                        Ok(client) => ParkAndPingError::AgentDead { client, source },
                        Err(_) => ParkAndPingError::NoClient(source),
                    });
                }
                counter = counter.wrapping_add(1);
                // Straddle (found by tcp_fallback_role_k_hands_off_cleanly_...: a Client that
                // arrives while THIS round trip is in flight): the PONG that just landed
                // already proves liveness AFTER the Client's arrival -- it IS the
                // verify-at-delivery round trip, so running the parked arm's extra PING would
                // be a redundant second verification (and the wire contract's readers document
                // STOP directly after a straddling PONG). `biased` guarantees the arrival
                // really was mid-flight: had the Client been delivered before this iteration,
                // the parked arm would have won instead. A `Closed` here is terminal for the
                // oneshot (polling it again would panic), so it maps to the same
                // superseded/dropped error the parked arm produces.
                match parked.as_mut().get_mut().try_recv() {
                    Ok(client) => return Ok(client),
                    Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                        return Err(ParkAndPingError::NoClient(
                            "tcp-fallback: parked registration superseded/dropped before a Client arrived".into(),
                        ))
                    }
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
                }
            }
        }
    }
}

/// Why [`park_and_ping`] failed -- split so the caller can failover a rescued Client.
enum ParkAndPingError {
    /// No Client was in flight (superseded registration, or a cadence ping failed).
    NoClient(BoxError),
    /// The final verify-ping failed AFTER a Client was delivered: the parked agent died
    /// within the last ping interval. The Client's stream is rescued for re-delivery to
    /// the next parked slot for the same token.
    AgentDead { client: crate::state::BoxedStream, source: BoxError },
}

/// Hand-written because the rescued `client` stream is not `Debug`/`Display`; only
/// the underlying cause is shown, verbatim.
///
/// #584: an earlier version of this comment claimed the verbatim wording (e.g.
/// "superseded") was needed to keep "existing diagnostics" matching on it --
/// checked, not true. No production code matches on that text; every real
/// `park_and_ping` caller ('K'/'F'/'L') already treats `NoClient` uniformly
/// (log and shut down). The two tests that do match on "superseded"
/// (`park_and_ping_...`) are a wording canary, same idea as #550 -- they
/// confirm this variant stays distinguishable from a generic ping failure in
/// its message, not a real diagnostic dependency.
impl std::fmt::Display for ParkAndPingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParkAndPingError::NoClient(e) => write!(f, "{e}"),
            ParkAndPingError::AgentDead { source, .. } => {
                write!(f, "parked agent died at delivery verification: {source}")
            }
        }
    }
}

impl std::fmt::Debug for ParkAndPingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParkAndPingError::NoClient(e) => f.debug_tuple("NoClient").field(e).finish(),
            ParkAndPingError::AgentDead { source, .. } => f
                .debug_struct("AgentDead")
                .field("source", source)
                .finish_non_exhaustive(),
        }
    }
}

/// Account a completed **park-phase** relay (a Client served by a parked
/// TLS-TCP fallback agent) as [`RelayKind::TcpFallback`](crate::state::RelayKind::TcpFallback).
///
/// #534: every park arm below used to discard the relay's byte counts
/// (`relay(..).await?;` with the tuple dropped) and book nothing at all, so
/// `ct_edge_relay_bytes_kind_total{kind="tcp_fallback"}` stayed at 0 while an
/// agent that was 100% on the fallback served real traffic — and
/// `ct_edge_relay_bytes_total` under-counted by exactly those bytes, since
/// `note_relay` is the only writer of both. The delivery counter
/// (`ct_edge_tcp_fallback_deliveries_total`) moved correctly the whole time,
/// which is what made the byte gap look like a mislabel rather than a miss.
///
/// **Direction mapping** (the easy thing to get backwards, hence this
/// wrapper's two named parameters instead of a positional tuple hand-off):
/// the park arms hold the AGENT side of the connection and call
/// `relay(agent, client)`, so [`relay`]'s documented `(a→b, b→a)` is
/// `(agent_to_client, client_to_agent)` — the mirror image of the
/// browser-plane sites, which call `relay(client, agent)`.
/// [`framed_relay`], by contrast, already returns
/// `(browser→agent, agent→browser)` for its `(agent, browser)` arguments.
/// Only the total matters for the fleet-wide counters, but
/// [`EdgeState::note_relay`] also feeds the PER-TUNNEL in/out split the
/// monitoring view shows, where a swap would be visible as inverted traffic.
fn note_parked_fallback_relay(
    state: &EdgeState<Connection>,
    token: &RoutingToken,
    client_to_agent: u64,
    agent_to_client: u64,
) {
    state.note_relay(token, client_to_agent, agent_to_client, crate::state::RelayKind::TcpFallback);
}

/// Serve one connection over the **TCP fallback** (M12.2b, issue #3 / P1.2c-3b)
/// by dispatching on the first byte's role:
///
/// * `'A'` — an Agent registers over TCP (UDP/QUIC blocked): read the token, ack
///   `OK`, park in the rendezvous, and relay this stream to the first Client that
///   arrives (single-tunnel — a TCP agent has one stream, no QUIC-style muxing).
/// * `'K'` (ct-agent#15 follow-up; "K" for Keepalive-ping-capable -- `'P'` was
///   already taken by [`serve_connection`]'s QUIC-side direct-endpoint query,
///   a wholly separate protocol/transport but avoided here to keep role-byte
///   letters non-confusing at a glance across the file) — the ping-capable
///   variant of `'A'`: byte-identical admission (`'K' | token(32)` instead of
///   `'A' | token(32)`, same `OK`/`NO` ack), but while parked waiting for a
///   Client, the Edge keeps real payload traffic flowing every
///   [`TCP_PING_INTERVAL`] via [`park_and_ping`]/[`send_ping_and_await_pong`]
///   -- a pre-Noise, transport-level PING/PONG the Edge legitimately
///   originates and observes, carrying no application data. A legacy Agent
///   (which only ever sends `'A'`) is completely unaffected: it never
///   receives a single ping-protocol byte. Opt-in only -- see those
///   functions' docs for the exact wire format and the race-free hand-off to
///   [`relay`] once a Client arrives.
/// * `'F'` (#528; "F" for Framed) — the framed-capable variant of `'L'`:
///   byte-identical Browser-Plane admission (`role | token(32) | host_len(2 BE)
///   | host`, hostname bound atomically) and the same park-phase keepalive, but
///   once a Client is delivered the relay phase speaks the
///   `ct_common::fallback_framing` codec on the edge↔agent hop
///   ([`framed_relay`]) instead of a raw byte pump, so an in-flight request
///   whose origin goes silent past the middlebox idle floor keeps keepalive
///   frames flowing and survives. Opt-in only; a legacy Agent never sends
///   `'F'`, and an old edge's `unknown role byte` drop is the refusal an
///   `'F'`-capable Agent downgrades on (`'F'`→`'L'`→`'B'`).
/// * `'C'` — a Client runs the `'C'` rendezvous (challenge → PoW) and is delivered
///   to a parked TCP agent if one exists, else relayed to a QUIC-registered agent.
///
/// The relay is transport-agnostic, so any Client (TCP or QUIC) bridges to either
/// a TCP-registered or a QUIC-registered agent.
///
/// `tcp_agent_cap` (#410) is a dedicated sub-cap admitted against for role 'A'/'B'
/// ONLY, before the connection parks -- see its doc in `run_edge` for why a park
/// TTL / known-token check isn't the right shape here, and `browser_tunnel_cap`
/// (#254) for the precedent this mirrors.
pub async fn serve_tcp_connection<S>(
    mut stream: S,
    state: &EdgeState<Connection>,
    challenge: &Challenge,
    tcp_agent_cap: Option<&ConnectionCap>,
) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut role = [0u8; 1];
    stream.read_exact(&mut role).await?;
    match role[0] {
        b'A' => {
            // #258: bound the admission exchange (not the park/relay that follows --
            // that's deliberately unbounded, same as everywhere else in this file).
            // #411: this arm previously acked `OK` and parked unconditionally --
            // no `is_revoked` check anywhere, unlike the QUIC role-`'A'` arm --
            // so a revoked token could still register (and keep re-registering)
            // over the TCP fallback, defeating `revoke_token` for any Agent
            // reachable over it. The token is read first, then checked+parked
            // atomically via `park_tcp_agent_unless_revoked` (same
            // `registration_lock`-guarded pattern as the QUIC arm's
            // `register_with_candidate_unless_revoked`), and the ack now
            // reflects the real outcome (`NO` on revoked, matching the QUIC
            // arm's wire behavior) instead of always claiming `OK` up front.
            //
            // #410: admitted against the dedicated `tcp_agent_cap` sub-cap right
            // after the token is read, BEFORE `park_tcp_agent_unless_revoked` queues
            // anything in `tcp_agents` -- so a flood that finds the sub-cap already
            // full is shed with nothing to clean back up, and never touches the
            // caller's own (shared, long-held-elsewhere) `conn_cap` permit for this
            // connection. The sub-permit is then held for the SAME lifetime the
            // connection itself already gets (parked, then relaying) -- it is simply
            // never acquired at all when `tcp_agent_cap` is unconfigured (uncapped).
            // `_sub_permit` is deliberately bound HERE, in the arm that owns the
            // connection for its whole life, not inside `admit_tcp_agent_a` --
            // #410's bound only means anything while the registration is still
            // parked, so the permit has to outlive admission.
            let Some((token, parked, _sub_permit)) =
                admit_tcp_agent_a(&mut stream, state, tcp_agent_cap, "A").await?
            else {
                let _ = stream.shutdown().await;
                return Ok(());
            };
            // Await the parked Client, then relay this agent stream to it.
            match parked.await {
                Ok(mut client) => {
                    // #534: this relay's bytes ARE the fallback's traffic -- see
                    // `note_parked_fallback_relay` for why they used to go
                    // uncounted and for the (mirrored) direction mapping.
                    let (agent_to_client, client_to_agent) = until_revoked(state, &token, relay(&mut stream, &mut client)).await?; // #554
                    note_parked_fallback_relay(state, &token, client_to_agent, agent_to_client);
                    Ok(())
                }
                // Never matched with a Client (edge shutdown / registration
                // replaced -- #229 follow-up: a later 'A'/'B' registration
                // for the SAME token overwrites this one's park slot, which
                // used to just drop this stream, so the superseded Agent's
                // TLS client saw an abrupt close and misreported it as a
                // connection failure. Shut down gracefully (sends a TLS
                // close_notify) so it reads as a clean, expected disconnect.
                Err(_) => {
                    let _ = stream.shutdown().await;
                    Ok(())
                }
            }
        }
        b'K' => {
            // ct-agent#15 follow-up: byte-identical admission to 'A' (same
            // token/cap/revoke checks, same OK/NO ack) -- the ONLY difference
            // is that once parked, this arm keeps real payload traffic
            // flowing over the idle connection via `park_and_ping` instead of
            // just awaiting the Client oneshot directly. A legacy Agent never
            // sends 'K' (it only ever sends 'A'), so it can never reach this
            // arm -- zero behavior change for any already-deployed client.
            // Held for the whole parked-and-relaying life of this connection,
            // exactly as in the 'A' arm -- see `admit_tcp_agent_a`'s doc.
            let Some((token, parked, _sub_permit)) =
                admit_tcp_agent_a(&mut stream, state, tcp_agent_cap, "K").await?
            else {
                let _ = stream.shutdown().await;
                return Ok(());
            };
            match park_and_ping(&mut stream, parked).await {
                Ok(mut client) => {
                    // Clean, unambiguous hand-off boundary (see TCP_PING_STOP's
                    // doc): announce the ping-phase's end BEFORE any real
                    // relayed byte can reach this stream. Written sequentially,
                    // strictly before `relay` starts -- TCP ordering guarantees
                    // the Agent sees it first.
                    stream.write_all(&[TCP_PING_STOP]).await?;
                    stream.flush().await?;
                    // #534, as in the 'A' arm above.
                    let (agent_to_client, client_to_agent) = until_revoked(state, &token, relay(&mut stream, &mut client)).await?; // #554
                    note_parked_fallback_relay(state, &token, client_to_agent, agent_to_client);
                    Ok(())
                }
                // Verify-at-delivery failover: the final pre-STOP ping caught a
                // corpse WITH a live Client in hand -- hand that Client to the
                // next parked slot for the same token instead of failing the
                // request. If no slot is free the stream drops, which is exactly
                // today's behaviour, so this is strictly an improvement.
                Err(ParkAndPingError::AgentDead { client, source }) => {
                    eprintln!(
                        "ct-edge: tcp-fallback 'K' verify-ping caught a dead parked agent at delivery ({source}); failing the client over to the next parked slot"
                    );
                    let _ = state.deliver_to_tcp_agent_draining(&token, client);
                    let _ = stream.shutdown().await;
                    Ok(())
                }
                // Same graceful-shutdown treatment as 'A' for a superseded/
                // never-delivered registration (#229 follow-up) -- see that
                // arm's comment. A cadence ping/pong I/O failure (the parked
                // Agent's connection died with no Client in flight) also lands
                // here and gets the same clean shutdown.
                Err(ParkAndPingError::NoClient(e)) => {
                    edge_trace(format_args!("tcp-fallback 'K' parked loop ended without a client: {e}"));
                    let _ = stream.shutdown().await;
                    Ok(())
                }
            }
        }
        b'F' => {
            // #528: the FRAMED-capable variant of 'L' (Browser-Plane). Admission
            // is BYTE-IDENTICAL to 'B'/'L' -- `role | token(32) | host_len(2 BE)
            // | host`, same cap/hostname gates (`host_bind_allowed` +
            // `register_host`), same OK/NO ack, via `admit_tcp_agent_b` -- and
            // the park phase runs the same PING/PONG keepalive as 'L'
            // (`park_and_ping`). A legacy Agent never sends 'F', so this arm is
            // unreachable for any already-deployed client, and an edge WITHOUT
            // this arm hits the `unknown role byte` error below and drops,
            // which is exactly the refusal signal the Agent's 'F'->'L'->'B'
            // downgrade ladder expects. The ONLY difference from 'L' is what
            // runs AFTER the `TCP_PING_STOP` hand-off byte: the relay phase
            // speaks the `ct_common::fallback_framing` codec on the
            // edge<->agent hop (`framed_relay`) instead of a raw byte pump, so
            // an in-flight request whose origin falls silent past the middlebox
            // idle floor keeps keepalive frames flowing and survives (#388
            // class). The browser side stays raw; `framed_relay` unframes agent
            // bytes before forwarding to the browser and frames browser bytes
            // before they reach the agent. `_sub_permit` is held for the whole
            // parked-and-relaying life exactly as in 'B'/'L'.
            //
            // Integration-review I1: this arm briefly used the 'K'-shaped
            // `admit_tcp_agent_a` (token only, no hostname) -- against the
            // 'L'-shaped frame the Agent actually sends. The hostname was never
            // bound (silent routing failure) and its 2+len trailing bytes
            // poisoned the first PING round trip ("malformed PONG"), driving an
            // endless redial loop.
            let Some((token, parked, _sub_permit)) =
                admit_tcp_agent_b(&mut stream, state, tcp_agent_cap, "F").await?
            else {
                return Ok(());
            };
            match park_and_ping(&mut stream, parked).await {
                Ok(mut client) => {
                    // Same clean park->relay boundary as 'K': the STOP sentinel
                    // ends the PING phase strictly before the first framed
                    // relay byte can reach the Agent (TCP ordering guarantees
                    // it is seen first). After STOP, both directions speak the
                    // frame codec until the connection ends -- single-use, no
                    // way back to a park phase.
                    stream.write_all(&[TCP_PING_STOP]).await?;
                    stream.flush().await?;
                    // #534: `framed_relay(agent, browser)` already returns
                    // `(browser->agent, agent->browser)`, i.e. the direction
                    // order `note_relay` wants -- unlike the raw `relay(agent,
                    // client)` arms, which return it mirrored. Application
                    // bytes only: frame overhead and the codec's keepalives are
                    // excluded by `framed_relay` itself, which is the right
                    // basis for a traffic-volume metric (the raw arms count the
                    // same payload, un-framed).
                    let (client_to_agent, agent_to_client) = until_revoked(state, &token, framed_relay(&mut stream, &mut client)).await?; // #554
                    note_parked_fallback_relay(state, &token, client_to_agent, agent_to_client);
                    Ok(())
                }
                // Verify-at-delivery failover, identical to 'K': the rescued
                // `client` is the RAW browser stream (framing lives only on the
                // edge<->agent hop, and only after STOP -- which this dead
                // agent never reached), so re-delivering it to the next parked
                // slot for the same token is correct whether that slot is
                // framed or not.
                Err(ParkAndPingError::AgentDead { client, source }) => {
                    eprintln!(
                        "ct-edge: tcp-fallback 'F' verify-ping caught a dead parked agent at delivery ({source}); failing the client over to the next parked slot"
                    );
                    let _ = state.deliver_to_tcp_agent_draining(&token, client);
                    let _ = stream.shutdown().await;
                    Ok(())
                }
                Err(ParkAndPingError::NoClient(e)) => {
                    edge_trace(format_args!("tcp-fallback 'F' parked loop ended without a client: {e}"));
                    let _ = stream.shutdown().await;
                    Ok(())
                }
            }
        }
        b'B' => {
            let Some((token, parked, _sub_permit)) =
                admit_tcp_agent_b(&mut stream, state, tcp_agent_cap, "B").await?
            else {
                return Ok(());
            };
            match parked.await {
                Ok(mut client) => {
                    // #534, as in the 'A' arm above.
                    let (agent_to_client, client_to_agent) = until_revoked(state, &token, relay(&mut stream, &mut client)).await?; // #554
                    note_parked_fallback_relay(state, &token, client_to_agent, agent_to_client);
                    Ok(())
                }
                // See the 'A' arm above (#229 follow-up): graceful shutdown
                // instead of an abrupt drop when a later registration for the
                // same token supersedes this one.
                Err(_) => {
                    let _ = stream.shutdown().await;
                    Ok(())
                }
            }
        }
        b'L' => {
            // The ping-capable Browser-Plane register: exactly what 'K' is to 'A',
            // but for 'B'. Byte-identical admission to 'B' (same token/cap/hostname
            // gates, same OK/NO ack); the ONLY difference is that once parked, this
            // arm keeps real payload traffic flowing over the idle connection via
            // `park_and_ping` instead of awaiting the Client oneshot directly.
            //
            // Why this exists (live incident, 2026-08-13, sort.bunsenbrenner.org):
            // 'K' only ever covered the Noise/mesh path. A Browser-Plane agent
            // (`CT_AGENT_MODE=browser`) registers over the fallback with 'B', so it
            // could not benefit from the ping treatment at all -- upgrading such an
            // agent to the release carrying 'K' changed nothing for it, which is
            // exactly what was observed. Measured on that deployment: a parked
            // fallback connection dies after ~10-15s idle (5s request spacing ->
            // 4/4 OK, 20s spacing -> 1/4), because the middlebox on that path
            // ignores ACK-only keepalive segments. Real payload traffic is the only
            // thing that keeps it alive, and that is what this arm sends.
            //
            // A legacy Browser-Plane agent never sends 'L' (it only ever sends 'B'),
            // so it can never reach this arm -- zero behavior change for any
            // already-deployed client.
            let Some((token, parked, _sub_permit)) =
                admit_tcp_agent_b(&mut stream, state, tcp_agent_cap, "L").await?
            else {
                return Ok(());
            };
            match park_and_ping(&mut stream, parked).await {
                Ok(mut client) => {
                    // Clean, unambiguous hand-off boundary, same as 'K': announce the
                    // ping phase's end BEFORE any relayed byte can reach this stream.
                    stream.write_all(&[TCP_PING_STOP]).await?;
                    stream.flush().await?;
                    // #534, as in the 'A' arm above.
                    let (agent_to_client, client_to_agent) = until_revoked(state, &token, relay(&mut stream, &mut client)).await?; // #554
                    note_parked_fallback_relay(state, &token, client_to_agent, agent_to_client);
                    Ok(())
                }
                // Verify-at-delivery failover, same as 'K': rescue the Client to
                // the next parked slot for this hostname's token.
                Err(ParkAndPingError::AgentDead { client, source }) => {
                    eprintln!(
                        "ct-edge: tcp-fallback 'L' verify-ping caught a dead parked agent at delivery ({source}); failing the client over to the next parked slot"
                    );
                    let _ = state.deliver_to_tcp_agent_draining(&token, client);
                    let _ = stream.shutdown().await;
                    Ok(())
                }
                // Same graceful shutdown as 'B'/'K' -- a superseded registration or
                // a parked agent that genuinely went away is an ordinary outcome
                // here, not an error to propagate.
                Err(ParkAndPingError::NoClient(e)) => {
                    edge_trace(format_args!("tcp-fallback 'L' parked loop ended without a client: {e}"));
                    let _ = stream.shutdown().await;
                    Ok(())
                }
            }
        }
        b'C' => {
            // #258: bound the challenge/PoW admission exchange; the deliver/relay
            // dispatch below is left unbounded (park/relay-wait, same as elsewhere).
            let token = tokio::time::timeout(TCP_FALLBACK_ADMISSION_TIMEOUT, async {
                let mut chal = [0u8; 17];
                chal[..16].copy_from_slice(&challenge.nonce);
                chal[16] = challenge.difficulty;
                stream.write_all(&chal).await?;
                stream.flush().await?;

                let mut req = [0u8; 40];
                stream.read_exact(&mut req).await?;
                let token = check_request(challenge, &req).map_err(|_| "proof of work rejected")?;

                // #472: same known-token-before-rate-limit ordering as the QUIC
                // 'C' arm above -- see `EdgeState::is_resolvable`'s doc for why.
                if !state.is_resolvable(&token) {
                    return Err("unknown routing token".into());
                }

                // #86 (ADR-0018): per-token rendezvous rate limit (same as the QUIC path).
                if !state.rendezvous_allowed(&token, rendezvous_window()) {
                    return Err("rendezvous rate limit exceeded".into());
                }
                Ok::<_, BoxError>(token)
            })
            .await
            .map_err(|_| "tcp-fallback: role 'C' admission timed out")??;

            // Prefer a parked TCP-fallback agent; else relay to a QUIC agent.
            match state.deliver_to_tcp_agent_draining(&token, Box::new(stream)) {
                Ok(()) => Ok(()),
                Err(stream) => match open_agent_stream(state, &token).await {
                    Ok((agent_send, agent_recv)) => {
                        let mut stream = stream;
                        let mut agent = join(agent_recv, agent_send);
                        let (a, b) = until_revoked(state, &token, relay(&mut stream, &mut agent)).await?; // #554
                        // #10 O2. #534 reviewed and DELIBERATELY LEFT AS
                        // `TcpFallback` (the issue proposed flipping it to
                        // `Browser` on the theory that the label was inverted):
                        // this Client reached the edge over the :4433 TLS-TCP
                        // fallback and only the AGENT leg is QUIC, so one leg of
                        // this relay really did run over the fallback transport
                        // -- which is exactly what the kind partitions on (see
                        // `RelayKind`). `Browser` would be doubly wrong here:
                        // role 'C' is the ct-client rendezvous, never a browser
                        // (browsers enter via `serve_sni_passthrough` /
                        // `serve_gelb_terminated`, which have no :4433 leg and
                        // therefore correctly book `Browser`). This site's true
                        // structural twin is the QUIC 'C' arm's identical
                        // race-fallthrough in `serve_connection`, which books
                        // `DataPlane` because BOTH its legs are QUIC.
                        state.note_relay(&token, a, b, crate::state::RelayKind::TcpFallback);
                        Ok(())
                    }
                    Err(e) => {
                        // Momentarily-exhausted pool recovery (#229 follow-up):
                        // give a burst of parallel browser connections a brief
                        // window to find a freed-up TCP-fallback slot.
                        if state.wait_for_tcp_agent(&token, TCP_FALLBACK_DELIVER_WAIT).await
                            && state.deliver_to_tcp_agent_draining(&token, stream).is_ok()
                        {
                            return Ok(());
                        }
                        // #589: pool depth at give-up time, same reasoning as the SNI/Gelb legs.
                        let pool = state.tcp_parked_for(&token);
                        Err(format!("{e} — tcp_fallback_pool={pool}").into())
                    }
                },
            }
        }
        b'M' => {
            // Edge-to-edge mesh relay (ADR-0021 Part 1): a PEER edge that got a
            // local miss for `host` dials here to reach the Agent this edge
            // actually owns. Authenticated by the shared CT_EDGE_ADMIN_TOKEN
            // (the same secret the control plane already uses to authorize
            // this edge) rather than a distinct PKI leaf -- deliberately reuses
            // the one constant-time admin-token check every other privileged
            // edge operation already goes through, so only a genuine peer edge
            // (or the operator) can reach this role, never a Client or Agent.
            // #258: bound the admin-token/hostname admission exchange, same as the
            // other roles -- the reads here happen BEFORE admin_revoke_ok is even
            // checked, so an unauthenticated dripper can still hold the cap permit
            // through this phase.
            let token = tokio::time::timeout(TCP_FALLBACK_ADMISSION_TIMEOUT, async {
                let mut admin_token = [0u8; 32];
                stream.read_exact(&mut admin_token).await?;
                let mut hl = [0u8; 2];
                stream.read_exact(&mut hl).await?;
                let hlen = u16::from_be_bytes(hl) as usize;
                if hlen == 0 || hlen > 253 {
                    return Err("invalid mesh-relay hostname length".into());
                }
                let mut host = vec![0u8; hlen];
                stream.read_exact(&mut host).await?;
                let host = std::str::from_utf8(&host).map_err(|_| "hostname is not valid UTF-8")?.to_string();

                if !state.admin_revoke_ok(&admin_token) {
                    stream.write_all(b"NO").await?;
                    stream.flush().await?;
                    return Err("mesh-relay auth rejected".into());
                }
                let Some(token) = state.route_host(&host) else {
                    stream.write_all(b"NO").await?;
                    stream.flush().await?;
                    return Err(format!("mesh-relay: no local route for '{host}'").into());
                };
                stream.write_all(b"OK").await?;
                stream.flush().await?;
                Ok::<_, BoxError>(token)
            })
            .await
            .map_err(|_| "tcp-fallback: role 'M' admission timed out")??;

            match state.deliver_to_tcp_agent_draining(&token, Box::new(stream)) {
                Ok(()) => Ok(()),
                Err(stream) => match open_agent_stream(state, &token).await {
                    Ok((agent_send, agent_recv)) => {
                        let mut stream = stream;
                        let mut agent = join(agent_recv, agent_send);
                        let (a, b) = until_revoked(state, &token, relay(&mut stream, &mut agent)).await?; // #554
                        // #534, same reasoning as the 'C' arm above: the PEER
                        // EDGE dialed this role over the :4433 TLS-TCP fallback
                        // listener, so the inbound leg is fallback transport
                        // even though the agent leg is QUIC. Kept as
                        // `TcpFallback` on purpose.
                        state.note_relay(&token, a, b, crate::state::RelayKind::TcpFallback);
                        Ok(())
                    }
                    Err(e) => {
                        // Momentarily-exhausted pool recovery (#229 follow-up),
                        // same as the 'C' arm above.
                        if state.wait_for_tcp_agent(&token, TCP_FALLBACK_DELIVER_WAIT).await
                            && state.deliver_to_tcp_agent_draining(&token, stream).is_ok()
                        {
                            return Ok(());
                        }
                        // #589: pool depth at give-up time, same reasoning as the SNI/Gelb legs.
                        let pool = state.tcp_parked_for(&token);
                        Err(format!("{e} — tcp_fallback_pool={pool}").into())
                    }
                },
            }
        }
        other => Err(format!("unknown TCP role byte: {other}").into()),
    }
}

/// Everything [`serve_front_door`] needs to attempt the ADR-0021 Part 1
/// mesh-relay fallback on a local routing miss. `None` anywhere this is
/// threaded through means the feature is off -- the existing "no tunnel
/// registered" error path is completely unchanged, which is the default
/// (opt in via `CT_EDGE_MESH_RELAY_ENABLED`, see [`run_edge`]).
#[derive(Clone)]
pub struct MeshRelayConfig {
    pub cp_url: String,
    pub admin_token: [u8; 32],
    pub edge_cert: rustls::pki_types::CertificateDer<'static>,
    /// #471: short-TTL negative cache on `(hostname -> no owner found)` — mirrors
    /// [`crate::channel_authorize::ChannelAuthorizer`]'s own negative-cache shape for the
    /// same reason: with mesh-relay enabled, every `:443` connection whose
    /// (attacker-controlled) SNI hostname has no local route triggered one authenticated
    /// control-plane HTTP request, with no cache and no rate limit on this specific path —
    /// roughly a 1:1 amplification from a cheap TCP connect + ClientHello into one
    /// authenticated CP request. Constructed once at edge startup and shared across every
    /// connection this edge serves, same lifetime as the rest of this config.
    ///
    /// `Arc`-wrapped (not a bare `Mutex`): `MeshRelayConfig` is `#[derive(Clone)]`d once per
    /// accepted connection (see the accept loop in [`run_edge`]) so each connection's task
    /// gets its own owned copy to move into its spawned future. Without the `Arc`, that
    /// per-connection clone would deep-copy an empty `HashMap` every time, silently
    /// defeating the cache entirely (every connection would see zero prior entries) while
    /// still compiling and running without error.
    negative_cache: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, tokio::time::Instant>>>,
}

/// How long an unrouted hostname's "nobody owns it" result is trusted before the next
/// lookup for that same hostname is allowed to hit the control plane again — long enough
/// to blunt a flood, short enough that a hostname provisioned moments ago (a real,
/// legitimate race between provisioning and first traffic) isn't stuck failing.
const MESH_RELAY_NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(30);

/// #471: [`crate::edge_mesh_client::lookup_owner_by_host`], but skips the real CP
/// round-trip entirely when `host`'s negative result is still fresh — see
/// [`MeshRelayConfig::negative_cache`]'s own doc for the amplification this closes. A
/// cache HIT still calls through (never cached — the whole point is that ownership is
/// rare/one-time-provisioned and worth re-confirming live; only "nobody owns it" is
/// cheap to trust for a short window).
async fn mesh_relay_lookup_cached(mesh: &MeshRelayConfig, host: &str) -> Option<String> {
    let cached_miss = mesh
        .negative_cache
        .lock()
        .ok()
        .and_then(|c| c.get(host).copied())
        .is_some_and(|at| at.elapsed() < MESH_RELAY_NEGATIVE_CACHE_TTL);
    if cached_miss {
        return None;
    }
    let result = crate::edge_mesh_client::lookup_owner_by_host(&mesh.cp_url, &mesh.admin_token, host).await;
    if result.is_none() {
        if let Ok(mut c) = mesh.negative_cache.lock() {
            c.insert(host.to_string(), tokio::time::Instant::now());
        }
    }
    result
}

/// #253: validate a peer edge address from the control plane's ownership registry before
/// [`relay_via_peer_edge`] ever dials it. `lookup_owner_by_host` returns a self-reported address
/// with no independent check on this side — a compromised CP or a rogue registered edge could hand
/// back a loopback/RFC1918/link-local/metadata target and this edge would dial it, admin-token in
/// hand. Same global-unicast-only filter the direct channel-endpoint dial already uses
/// (#137/#267's `ct_common::channel::is_global_unicast`) — the identical SSRF class, closed here.
fn safe_peer_edge_target(peer_addr: &str) -> Option<std::net::SocketAddr> {
    peer_addr.parse().ok().filter(|addr| ct_common::channel::is_global_unicast(*addr))
}

/// Dial a peer edge (ADR-0021 Part 1) that owns `host` and relay `inbound` to
/// it over the mesh-relay role. Used as the cache-miss fallback when this
/// edge has no local route for `host` but the control plane's registry says
/// another edge does. `edge_cert` is the SAME internal Mesh-Plane CA root this
/// edge already trusts Agents against (`crate::pki`) -- reused for transport
/// encryption between edges too; `admin_token` (not the cert) is what actually
/// authorizes the 'M' role on the receiving side. `target` must already be validated (#253) --
/// see [`safe_peer_edge_target`], applied by the one production caller below.
pub async fn relay_via_peer_edge<S>(
    mut inbound: S,
    target: std::net::SocketAddr,
    host: &str,
    edge_cert: rustls::pki_types::CertificateDer<'static>,
    admin_token: [u8; 32],
) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // #549: both waits on the peer edge are bounded -- see `MESH_RELAY_DIAL_TIMEOUT`.
    let mut peer = tokio::time::timeout(
        MESH_RELAY_DIAL_TIMEOUT,
        crate::transport::tcp_tls_connect(target, edge_cert),
    )
    .await
    .map_err(|_| -> BoxError {
        format!(
            "mesh-relay: peer edge {target} did not complete the dial+TLS handshake within \
             {MESH_RELAY_DIAL_TIMEOUT:?} -- treating it as unreachable (#549)"
        )
        .into()
    })??;

    let host_bytes = host.as_bytes();
    let host_len: u16 = host_bytes.len().try_into().map_err(|_| "hostname too long for the mesh-relay frame")?;
    let mut msg = vec![b'M'];
    msg.extend_from_slice(&admin_token);
    msg.extend_from_slice(&host_len.to_be_bytes());
    msg.extend_from_slice(host_bytes);
    peer.write_all(&msg).await?;
    peer.flush().await?;

    let mut ack = [0u8; 2];
    tokio::time::timeout(MESH_RELAY_ACK_TIMEOUT, peer.read_exact(&mut ack))
        .await
        .map_err(|_| -> BoxError {
            format!(
                "mesh-relay: peer edge {target} accepted the connection but sent no \
                 acknowledgement within {MESH_RELAY_ACK_TIMEOUT:?} -- it is reachable but not \
                 serving the mesh-relay role (#549)"
            )
            .into()
        })??;
    if &ack != b"OK" {
        return Err(format!("peer edge refused mesh-relay for '{host}'").into());
    }

    // This leg carries no routing token of OURS. We are the middle hop, and the peer edge
    // owns the tunnel and applies its own revocation to the session it terminates. Cutting
    // here on a local revocation would tear down traffic we do not own.
    //
    // Stated at the call site rather than left to the pattern: the previous version of the
    // guard happened not to match this line, which is indistinguishable from an exemption
    // nobody ever decided. The marker sits INSIDE the call expression: the guard reads
    // statements, so a marker in the prose above can be split off by any punctuation (a
    // semicolon in a sentence did exactly that), and one after the `;` already belongs to
    // the next statement. Inside the parentheses it cannot be separated from what it exempts.
    relay(&mut inbound, /* #554-exempt: peer edge owns this tunnel */ &mut peer).await?;
    Ok(())
}

/// Path of the persisted CA signing key: `edge-ca-key.pem` beside the published
/// root cert (`cert_out`), so both live on the Edge's shared/runtime volume.
fn ca_key_path_for(cert_out: &str) -> String {
    let p = std::path::Path::new(cert_out);
    match p.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => {
            dir.join("edge-ca-key.pem").to_string_lossy().into_owned()
        }
        _ => "edge-ca-key.pem".to_string(),
    }
}

/// Run the Edge daemon: bind to `config.listen`, write the cert to `cert_out`
/// (shared volume), and serve each incoming connection via [`serve_connection`]
/// with a fresh per-connection PoW challenge.
/// #84: decide whether hostname-ownership authorization is required. An explicit
/// `CT_EDGE_REQUIRE_HOST_AUTH` wins — any truthy value enables it, and `"0"` /
/// `"false"` / empty explicitly disable it. When unset, it **fail-closes by default
/// whenever a public front door is exposed** (`CT_FRONT_DOOR` set): a public `:443`
/// with unauthenticated hostname binds lets any routing-token holder squat an
/// unbound name. A mesh-only edge (no front door) stays off, so zero-config `:4433`
/// deployments are unaffected.
/// Current fixed-window index for the per-token rendezvous rate limit (#86): unix
/// seconds / the window length (a per-minute window). Wall-clock, but only used in
/// the live edge accept path; the limiter's own logic is tested deterministically.
fn rendezvous_window() -> u64 {
    const WINDOW_SECS: u64 = 60;
    unix_now() / WINDOW_SECS
}

/// What startup should DO about hostname-ownership authorization (#576).
///
/// [`host_auth_required`] below has always answered the policy question correctly, and a test
/// has always proved it. That test kept passing while the answer was never acted on: the call
/// sat inside the `CT_EDGE_ADMIN_TOKEN` block, so a front door configured without that token
/// left `host_auth` at `None` — and `host_bind_allowed` says `true` for every token then.
/// Proving a rule and applying it are different claims; this type exists so the second one can
/// be tested too, instead of living only inside a listener-spawning startup path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostAuthDecision {
    /// Enforce ownership. `orphaned` = required but no admin token exists, so nothing can ever
    /// authorize a host and every bind will be refused — correct, and worth saying out loud.
    Required { orphaned: bool },
    /// Do not enforce. `warn` = a public front door is exposed anyway, which is the open door
    /// the operator should hear about.
    Open { warn: bool },
}

fn host_auth_startup_decision(
    require_env: Option<&str>,
    front_door_set: bool,
    admin_token_present: bool,
) -> HostAuthDecision {
    if host_auth_required(require_env, front_door_set) {
        HostAuthDecision::Required { orphaned: !admin_token_present }
    } else {
        HostAuthDecision::Open { warn: front_door_set }
    }
}

fn host_auth_required(require_env: Option<&str>, front_door_set: bool) -> bool {
    match require_env {
        Some(v) if v == "0" || v.eq_ignore_ascii_case("false") || v.trim().is_empty() => false,
        Some(_) => true,
        None => front_door_set,
    }
}

/// Default per-token rendezvous rate limit (#95): 600/min ≈ 10/s per routing token.
/// Generous — a legitimate tunnel rendezvouses a handful of times per session, while
/// a solver-farm flood is orders of magnitude higher — so it protects a public edge
/// by default without throttling normal use or the testbed.
const DEFAULT_RENDEZVOUS_MAX_PER_MIN: u32 = 600;
/// Default cap on concurrently-handled connections (#95): well above any real
/// deployment or testbed footprint, but bounds an FD/memory-exhaustion flood.
const DEFAULT_MAX_CONNECTIONS: u32 = 8192;

/// Resolve an opt-out flood-control limit (#95). A public edge must be protected
/// **by default**, so an *unset* env var yields the safe `default` (on), not `None`.
/// The value is still fully tunable: a positive integer overrides the default, and an
/// explicit `0` / `off` / `false` / `none` disables the control. An unparseable value
/// falls back to `default` rather than silently disabling protection (fail-safe — a
/// typo never opens the flood gate). Returns `None` only for an explicit opt-out.
pub(crate) fn resolve_flood_limit(raw: Option<&str>, default: u32) -> Option<u32> {
    match raw.map(str::trim) {
        None => Some(default),
        Some(v)
            if v == "0"
                || v.eq_ignore_ascii_case("off")
                || v.eq_ignore_ascii_case("false")
                || v.eq_ignore_ascii_case("none") =>
        {
            None
        }
        Some(v) => Some(v.parse::<u32>().ok().filter(|&n| n > 0).unwrap_or(default)),
    }
}

/// Default bound (#400) on how long `run_edge` waits, after a shutdown signal, for
/// already-admitted connections to drain before it force-closes whatever's still open
/// and returns. 30s: generous enough for a real in-flight tunnel request/relay hop to
/// finish, short enough that an operator's own pod/container termination grace period
/// (commonly 30s, e.g. Kubernetes' default `terminationGracePeriodSeconds`) isn't
/// exceeded before this process would exit on its own anyway.
const DEFAULT_SHUTDOWN_GRACE_SECS: u64 = 30;

/// Resolve `CT_EDGE_SHUTDOWN_GRACE_SECS` (#400): unset or unparseable falls back to
/// [`DEFAULT_SHUTDOWN_GRACE_SECS`] (fail-safe -- a typo must not silently produce an
/// unbounded or zero-length drain), a valid non-negative integer is used as-is (`0` is
/// honored literally: no drain grace at all, immediate force-close on shutdown).
fn shutdown_grace_secs_from_env() -> u64 {
    match std::env::var("CT_EDGE_SHUTDOWN_GRACE_SECS") {
        Err(_) => DEFAULT_SHUTDOWN_GRACE_SECS,
        Ok(s) => match s.trim().parse::<u64>() {
            Ok(n) => n,
            Err(_) => {
                eprintln!(
                    "ct-edge: invalid CT_EDGE_SHUTDOWN_GRACE_SECS '{s}' -- using default {DEFAULT_SHUTDOWN_GRACE_SECS}s"
                );
                DEFAULT_SHUTDOWN_GRACE_SECS
            }
        },
    }
}

/// Resolves once a shutdown has been requested via SIGTERM (the real-world trigger: a
/// container/pod termination -- #376 made sure this actually reaches the process) or
/// Ctrl-C/SIGINT (a developer running the daemon directly). Mirrors the control plane's
/// own `shutdown_signal()` (`crates/control-plane/src/main.rs`, #350).
async fn wait_for_shutdown_request() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        let Ok(mut sig) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        else {
            std::future::pending::<()>().await;
            unreachable!();
        };
        sig.recv().await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

/// Resolve the Agent-Fabric channel **relay** listen address from the rendezvous
/// `chan_addr` and an optional `CT_EDGE_CHANNEL_RELAY_LISTEN` override — refusing a
/// collision with the rendezvous port. The relay MUST be a distinct endpoint: if the relay
/// and rendezvous `run_channel_broker_loop`s bind the **same** address, the OS load-balances
/// incoming channel connections across the two sockets (SO_REUSEADDR), so two members of one
/// channel can land on different loops' pairers and **never match** — silently breaking all
/// pairing (#103). Returns the default `chan_port + 1` when unset, the override when it
/// parses AND is distinct, or `Err` on a collision (an override equal to the rendezvous, or
/// the `port + 1` default saturating back onto `chan_addr` at port 65535).
fn resolve_channel_relay_addr(
    chan_addr: std::net::SocketAddr,
    relay_override: Option<&str>,
) -> Result<std::net::SocketAddr, String> {
    let relay = relay_override
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<std::net::SocketAddr>().ok())
        .unwrap_or_else(|| {
            std::net::SocketAddr::new(chan_addr.ip(), chan_addr.port().saturating_add(1))
        });
    if relay == chan_addr {
        return Err(format!(
            "channel relay address {relay} collides with the rendezvous address {chan_addr} — \
             the relay must be a distinct endpoint (set CT_EDGE_CHANNEL_RELAY_LISTEN to a free \
             port); refusing to bind two accept loops on one port (#103)"
        ));
    }
    Ok(relay)
}

pub async fn run_edge(config: &EdgeConfig, cert_out: &str) -> Result<(), BoxError> {
    // #400 (follow-up to #376): #376 fixed signal *delivery* (tini as PID 1, `STOPSIGNAL
    // SIGTERM`) so a SIGTERM/Ctrl-C actually reaches this process; this is the missing
    // application-level graceful-drain half. `shutdown` is cloned into every listener
    // spawned below (front door, TCP fallback, `:80` redirect, Browser-Plane SNI,
    // ws-channel, both QUIC channel-broker endpoints) and raced into the main QUIC accept
    // loop at the bottom of this function, so every accept point stops admitting new
    // connections the moment shutdown fires -- but does not touch any connection already
    // admitted. Once the main loop returns, this function waits (bounded by
    // `CT_EDGE_SHUTDOWN_GRACE_SECS`) for every configured `ConnectionCap` to drain to zero
    // in-use before returning -- see the SIGTERM/Ctrl-C task spawned right below and the
    // drain wait at the bottom of this function, and `crate::shutdown`'s module doc for
    // the full design writeup.
    let (shutdown_ctl, shutdown) = crate::shutdown::ShutdownController::new();
    {
        let shutdown_ctl = shutdown_ctl.clone();
        tokio::spawn(async move {
            wait_for_shutdown_request().await;
            eprintln!(
                "ct-edge: shutdown signal received -- stopping new accepts, draining in-flight \
                 connections for up to {}s (#400, CT_EDGE_SHUTDOWN_GRACE_SECS)",
                shutdown_grace_secs_from_env()
            );
            shutdown_ctl.trigger();
        });
    }

    // Issue the Edge's leaf from an internal CA (M20.3b) and listen on both QUIC
    // (primary) and TLS-TCP (fallback) with that one shared leaf. Persist the CA
    // signing key beside the published root so a redeploy reloads the SAME CA
    // and every pinned Agent/Client stays valid — a fresh CA per boot rotated
    // the root under everyone and broke pins with BadSignature (issue #2).
    let ca_key_path = ca_key_path_for(cert_out);
    let ca = Ca::load_or_create(&ca_key_path, "ct-edge-ca")?;
    let (endpoint, tcp_listener, acceptor, ca_root) =
        build_dual_edge_from_ca(&ca, config.listen, config.listen, vec!["localhost".to_string()])
            .await?;
    // Publish the CA *root* (not the leaf): Agents/Clients trust the CA and
    // therefore any Edge leaf it signs, so the cert can rotate without redistribution.
    save_cert(cert_out, &ca_root)?;

    let state = Arc::new(EdgeState::<Connection>::new());
    // #522: periodic reaper for DEAD TCP-fallback parks. Until this, dead parks
    // were only cleared lazily on a browser delivery, so a crash-loop / duplicate-
    // process flood accumulated corpses that eventually left a token with only dead
    // parks -- a browser then drained them all, found nothing live, and 000'd on the
    // UDP-blocked fallback path (no QUIC). Ten seconds matches the channel pairer's
    // own sweep cadence; the sweep is a cheap is_closed() scan, logged only when it
    // actually reaps so a healthy edge stays quiet.
    {
        let reaper_state = state.clone();
        let reaper_shutdown = shutdown.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(10));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = reaper_shutdown.cancelled() => return,
                    _ = tick.tick() => {
                        let reaped = reaper_state.reap_dead_tcp_parks();
                        if reaped > 0 {
                            eprintln!("ct-edge: reaped {reaped} dead TCP-fallback park(s) (#522)");
                        }
                    }
                }
            }
        });
    }
    // #86/#95 (ADR-0018): per-token rendezvous rate limit — at most N rendezvous per
    // routing token per minute. On by DEFAULT now (#95: a public edge must not ship
    // flood-exposed); CT_EDGE_RENDEZVOUS_MAX_PER_MIN tunes it, and `0`/`off` disables
    // it. Caps a token-specific rendezvous flood the PoW gate alone can't (solver farm).
    if let Some(n) = resolve_flood_limit(
        std::env::var("CT_EDGE_RENDEZVOUS_MAX_PER_MIN").ok().as_deref(),
        DEFAULT_RENDEZVOUS_MAX_PER_MIN,
    ) {
        state.set_rendezvous_limit(n);
        eprintln!("ct-edge: per-token rendezvous rate limit {n}/min (CT_EDGE_RENDEZVOUS_MAX_PER_MIN, #86/#95)");
    } else {
        eprintln!("ct-edge: per-token rendezvous rate limit DISABLED (CT_EDGE_RENDEZVOUS_MAX_PER_MIN=off, #95)");
    }
    // #86 SEC86b/#95 (ADR-0018): cap on concurrently-handled QUIC connections, on by
    // DEFAULT now (#95). CT_EDGE_MAX_CONNECTIONS tunes it, `0`/`off` disables it. Bounds
    // a connection flood so memory / FDs can't be exhausted before the PoW gate runs.
    let conn_cap = resolve_flood_limit(
        std::env::var("CT_EDGE_MAX_CONNECTIONS").ok().as_deref(),
        DEFAULT_MAX_CONNECTIONS,
    )
    .map(|n| {
        eprintln!("ct-edge: max {n} concurrent connections (CT_EDGE_MAX_CONNECTIONS, #86/#95)");
        ConnectionCap::new(n as usize)
    });
    // #254: a SEPARATE, smaller cap just for the BrowserTunnel/SNI-passthrough arm
    // (`serve_sni_passthrough`/`serve_gelb_terminated`) -- it's reached with an
    // attacker-controlled SNI hostname and no per-token/PoW gate of its own, so without
    // this it can consume the entire shared `conn_cap` budget and starve Portal/auth/
    // channel traffic, which all share that one cap too. This doesn't stop an attacker
    // from exhausting the BrowserTunnel arm's OWN sub-budget -- it stops that from
    // cascading into starving every other arm, same shed-cheaply posture as `conn_cap`.
    // Half of `DEFAULT_MAX_CONNECTIONS` by default: generous for legitimate multi-tenant
    // browser-tunnel traffic while always leaving the other half free for everything else.
    let browser_tunnel_cap = resolve_flood_limit(
        std::env::var("CT_EDGE_MAX_BROWSER_TUNNEL_CONNECTIONS").ok().as_deref(),
        DEFAULT_MAX_CONNECTIONS / 2,
    )
    .map(|n| {
        eprintln!("ct-edge: max {n} concurrent BrowserTunnel connections (CT_EDGE_MAX_BROWSER_TUNNEL_CONNECTIONS, #254)");
        ConnectionCap::new(n as usize)
    });
    // #410: a SEPARATE, smaller cap for the TCP-fallback Agent-registration park
    // (`serve_tcp_connection`'s role 'A'/'B' -> `park_tcp_agent`/`park_tcp_agent_unless_revoked`).
    // Reaching that park requires only a bare 32-byte token in the clear -- no PoW, and
    // (unlike role 'B''s hostname bind, gated by `host_bind_allowed` whenever host-auth
    // is required) role 'A' has no equivalent registry to check the token against: a
    // `RoutingToken` is an opaque bearer secret the control plane hands a tunnel owner
    // out of band, so the Edge genuinely cannot distinguish "a legitimate Agent's
    // first-ever registration for a brand-new token" from "an attacker's 32 random
    // bytes" -- refusing anything the Edge doesn't already recognize would break every
    // legitimate Agent's very first connect. A legitimate Agent is also intentionally
    // allowed to sit parked indefinitely waiting for a Client (same as the QUIC 'A'
    // arm), so this deliberately does NOT add a TTL that could kill a real, low-traffic
    // tunnel's registration. Instead, exactly like `browser_tunnel_cap` (#254) already
    // does for the OTHER no-PoW, attacker-reachable arm sharing the same `conn_cap`: an
    // attacker flooding bare 'A'/'B' registrations can now exhaust at most this
    // dedicated sub-budget, never cascading into the shared `conn_cap` that Portal/
    // auth/QUIC/`:80`-redirect all depend on (#410).
    let tcp_agent_cap = resolve_flood_limit(
        std::env::var("CT_EDGE_MAX_TCP_AGENT_CONNECTIONS").ok().as_deref(),
        DEFAULT_MAX_CONNECTIONS / 2,
    )
    .map(|n| {
        eprintln!("ct-edge: max {n} concurrent TCP-fallback Agent registrations (CT_EDGE_MAX_TCP_AGENT_CONNECTIONS, #410)");
        ConnectionCap::new(n as usize)
    });
    // Video-conferencing feature: every OTHER public listener sheds cheaply under a
    // ConnectionCap once its own budget is exhausted -- ws_channel.rs's browser
    // listener had none at all, an unbounded-concurrent-WS-upgrade gap (each admitted
    // connection does real work: an ed25519 signature verification, a CP authorize
    // round-trip). Computed here (not down where the listener itself is set up) so
    // it's available to the metrics endpoint below too, whether or not the listener
    // itself ends up enabled (a separate opt-in, CT_EDGE_WS_CHANNEL_LISTEN). Same
    // opt-out convention; default matches BrowserTunnel's own reasoning (half the
    // general cap -- public/attacker-reachable before any grant is verified).
    let ws_channel_cap = resolve_flood_limit(
        std::env::var("CT_EDGE_MAX_WS_CHANNEL_CONNECTIONS").ok().as_deref(),
        DEFAULT_MAX_CONNECTIONS / 2,
    )
    .map(|n| {
        eprintln!("ct-edge: max {n} concurrent ws-channel connections (CT_EDGE_MAX_WS_CHANNEL_CONNECTIONS)");
        ConnectionCap::new(n as usize)
    });
    // #450: the two QUIC Agent-Fabric channel-broker listeners (relay + rendezvous)
    // spawned an unbounded task per accept, unlike every other public listener here.
    // Same shed-cheaply posture, same default fraction of the general cap.
    let channel_broker_cap = resolve_flood_limit(
        std::env::var("CT_EDGE_MAX_CHANNEL_BROKER_CONNECTIONS").ok().as_deref(),
        DEFAULT_MAX_CONNECTIONS / 2,
    )
    .map(|n| {
        eprintln!("ct-edge: max {n} concurrent channel-broker connections (CT_EDGE_MAX_CHANNEL_BROKER_CONNECTIONS, #450)");
        ConnectionCap::new(n as usize)
    });
    // #546/#552: say which way endpoint attestation is set, in BOTH directions. Every cap
    // above prints its resolved value, but this one used to print nothing at all -- and a
    // security control that is silent when off is indistinguishable from one that is on.
    // That is the whole failure mode worth guarding here: an operator arms it in `.env`,
    // a later redeploy loses the line, and nothing in the log says the door reopened.
    eprintln!("{}", crate::channel_broker::attested_endpoint_startup_line());
    // #23 BP4b / #84: require hostname-ownership authorization for 'H'/'B' binds —
    // fail-closed by default when a public front door is exposed (CT_FRONT_DOOR), so an
    // anonymous bind can't squat an unbound name on :443.
    //
    // #576: this whole decision used to sit INSIDE the `CT_EDGE_ADMIN_TOKEN` block below.
    // The policy was computed correctly (`host_auth_required(None, front_door)` is `true`)
    // but never consulted without that token, so a front door configured without it left
    // `host_auth` at `None` — and `EdgeState::host_bind_allowed` answers `true` for EVERY
    // token in that state. Any proof-of-work token holder could bind any unbound hostname,
    // and no line said so: the `CT_EDGE_REQUIRE_HOST_AUTH=0` opt-out is warned about, this
    // path was not. Exactly the failure mode the `attested_endpoint_startup_line()` above
    // exists to prevent, ten lines further down the same function.
    let front_door_set = std::env::var_os("CT_FRONT_DOOR").is_some();
    let admin_token = std::env::var("CT_EDGE_ADMIN_TOKEN")
        .ok()
        .and_then(|s| parse_admin_token_hex(&s));
    let decision = host_auth_startup_decision(
        std::env::var("CT_EDGE_REQUIRE_HOST_AUTH").ok().as_deref(),
        front_door_set,
        admin_token.is_some(),
    );
    if let HostAuthDecision::Required { orphaned } = decision {
        state.require_host_auth();
        eprintln!(
            "ct-edge: hostname-ownership authorization required (#84 — fail-closed default under \
             CT_FRONT_DOOR; set CT_EDGE_REQUIRE_HOST_AUTH=0 to disable)"
        );
        if orphaned {
            // Fail-closed is now real without the token, which also means NOTHING can
            // authorize a host: the CP reaches this edge over the admin API, and that needs
            // the shared secret. Said plainly so the resulting refusals read as a
            // configuration gap rather than an unexplained outage.
            eprintln!(
                "ct-edge: WARNING — host-auth is required but CT_EDGE_ADMIN_TOKEN is unset, so no \
                 hostname can ever be authorized and every 'H'/'B' bind will be refused. Set \
                 CT_EDGE_ADMIN_TOKEN (matching the control plane's CT_CP_EDGE_ADMIN_TOKEN) (#576)."
            );
        }
    } else if decision == (HostAuthDecision::Open { warn: true }) {
        eprintln!(
            "ct-edge: WARNING — CT_FRONT_DOOR is exposed with host-auth DISABLED; any routing-token \
             holder can squat an unbound hostname (#84)"
        );
    }
    // #27 RB3: enable the authenticated revoke op only when the shared admin
    // secret is configured (64-hex CT_EDGE_ADMIN_TOKEN, matching the control
    // plane's CT_CP_EDGE_ADMIN_TOKEN). Absent -> revocation stays disabled.
    if let Some(tok) = admin_token {
        state.set_admin_token(tok);
        eprintln!("ct-edge: tunnel revocation enabled (CT_EDGE_ADMIN_TOKEN set)");
        // #27 RB4: serve the authenticated admin API (POST /admin/revoke/:token)
        // the control plane calls on a customer revoke — only when an admin
        // listener is configured, and bind it to a private interface in prod.
        if let Ok(addr) = std::env::var("CT_EDGE_ADMIN_LISTEN") {
            match addr.parse::<SocketAddr>() {
                Ok(listen) => {
                    let astate = state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = crate::admin::serve_admin(astate, listen).await {
                            eprintln!("ct-edge: admin endpoint on {listen} exited: {e}");
                        }
                    });
                }
                Err(e) => eprintln!("ct-edge: invalid CT_EDGE_ADMIN_LISTEN '{addr}': {e}"),
            }
        }
        // edge_mesh Phase 0 (#153): boot-time rehydration + periodic heartbeat
        // against the control plane's ownership registry — only when it's
        // configured (same CT_EDGE_CP_URL the channel broker already requires).
        // CT_EDGE_ID defaults to "primary", matching the control plane's own
        // default local-edge id, so a single-edge deployment needs zero extra
        // config for this to work end to end. Rehydration replays every
        // (token, hostname) pair the CP recorded this edge as owning back into
        // `host_auth` — the actual fix for a restart silently forgetting every
        // hostname authorization (the class of outage this session hit for
        // real). The heartbeat keeps the CP's view of "is this edge live"
        // fresh; CT_EDGE_PUBLIC_ADDR is what a peer edge would eventually use
        // to reach this one (informational only until the cross-edge relay —
        // a deliberately separate, later increment — exists).
        if let Ok(cp_url) = std::env::var("CT_EDGE_CP_URL").map(|s| s.trim().to_string()) {
            if !cp_url.is_empty() {
                // #279: one-time boot warning if the admin token would cross this
                // connection in cleartext — never blocks (see the fn's own doc).
                crate::edge_mesh_client::warn_if_insecure_cp_url(&cp_url);
                let edge_id = std::env::var("CT_EDGE_ID")
                    .ok()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "primary".to_string());
                let peer_addr = std::env::var("CT_EDGE_PUBLIC_ADDR")
                    .ok()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "unknown".to_string());
                eprintln!("ct-edge: mesh-registry heartbeat/rehydration enabled against {cp_url} (CT_EDGE_ID={edge_id})");
                // #503: rehydration and the #327 revocation replay used to be
                // fire-and-forget spawns, so every public accept loop below started
                // BEFORE they landed. Under #84 fail-closed host-auth that boot
                // window definitively refused every hostname bind (agents with a
                // one-shot bind then served hostname-less until restart), and the
                // mirror-image revocation window accepted registrations from
                // already-revoked tokens. Awaited inline instead — both calls are
                // bounded by the mesh client's own request timeout (10s) and
                // fail-soft to empty on an unreachable CP, so the boot is delayed,
                // never hung, and the listeners open with the replayed state loaded.
                let (pairs, revoked) = tokio::join!(
                    crate::edge_mesh_client::rehydrate(&cp_url, &tok, &edge_id),
                    crate::edge_mesh_client::fetch_revoked_tokens(&cp_url, &tok),
                );
                // #513: count what was actually AUTHORIZED -- `pairs` includes
                // hostname-less (mesh-only) entries, and the old `pairs.len()` line
                // overstated the rehydration by exactly those.
                // #548: an unavailable registry and an empty one are opposite situations and
                // must not produce the same line. Every Browser-Plane hostname routes off
                // this replay, so a silent failure here serves nothing while looking normal.
                let unavailable = match &pairs {
                    crate::edge_mesh_client::Rehydration::Unavailable(why) => Some(why.clone()),
                    crate::edge_mesh_client::Rehydration::Answered(_) => None,
                };
                let mut authorized = 0usize;
                for pair in pairs.pairs() {
                    if let Some(host) = pair.hostname {
                        state.authorize_host(&host, RoutingToken(pair.token));
                        authorized += 1;
                    }
                }
                match &unavailable {
                    None => eprintln!(
                        "ct-edge: rehydrated {authorized} hostname authorization(s) from {cp_url} (edge_id={edge_id})"
                    ),
                    Some(why) => eprintln!(
                        "ct-edge: #548 REHYDRATION FAILED ({why}) -- no hostname authorization was \
                         replayed, so every Browser-Plane hostname will fail to route until a retry \
                         succeeds. Retrying in the background."
                    ),
                }
                // Retry until ONE attempt answers. Without this a single hiccup at boot --
                // the control plane restarting alongside the edge is the ordinary case --
                // left the edge permanently unauthorized until someone restarted it again.
                if unavailable.is_some() {
                    let (rurl, rtok, rid, rstate) = (cp_url.clone(), tok, edge_id.clone(), state.clone());
                    tokio::spawn(async move {
                        let mut delay = std::time::Duration::from_secs(5);
                        loop {
                            tokio::time::sleep(delay).await;
                            match crate::edge_mesh_client::rehydrate(&rurl, &rtok, &rid).await {
                                crate::edge_mesh_client::Rehydration::Answered(pairs) => {
                                    let mut n = 0usize;
                                    for pair in pairs {
                                        if let Some(host) = pair.hostname {
                                            rstate.authorize_host(&host, RoutingToken(pair.token));
                                            n += 1;
                                        }
                                    }
                                    // The recovery is logged too: an operator who saw the
                                    // failure needs to see it end without having to probe.
                                    eprintln!(
                                        "ct-edge: #548 rehydration recovered -- replayed {n} hostname authorization(s)"
                                    );
                                    return;
                                }
                                crate::edge_mesh_client::Rehydration::Unavailable(why) => {
                                    eprintln!("ct-edge: #548 rehydration retry failed ({why}); next attempt in {delay:?}");
                                    delay = (delay * 2).min(std::time::Duration::from_secs(60));
                                }
                            }
                        }
                    });
                }
                let revoked_count = revoked.len();
                state.seed_revoked_tokens(revoked.into_iter().map(RoutingToken));
                eprintln!("ct-edge: replayed {revoked_count} revoked token(s) from {cp_url}");
                let hstate_cp_url = cp_url.clone();
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(30));
                    loop {
                        interval.tick().await;
                        crate::edge_mesh_client::heartbeat(&hstate_cp_url, &tok, &edge_id, &peer_addr).await;
                    }
                });
            }
        }
    }
    let difficulty = config.pow_difficulty;

    // Optional observability endpoint (#10): serve GET /metrics with the Edge's
    // live gauges when CT_EDGE_METRICS_LISTEN is set (off by default). Metadata
    // only — the Edge stays provider-blind.
    if let Ok(addr) = std::env::var("CT_EDGE_METRICS_LISTEN") {
        match addr.parse::<SocketAddr>() {
            Ok(listen) => {
                let mstate = state.clone();
                let mws_channel_cap = ws_channel_cap.clone();
                tokio::spawn(async move {
                    if let Err(e) = crate::observe::serve_metrics(listen, mstate, mws_channel_cap).await {
                        eprintln!("ct-edge: metrics endpoint on {listen} exited: {e}");
                    }
                });
                eprintln!("ct-edge: metrics endpoint on {listen} (GET /metrics)");
            }
            Err(e) => eprintln!("ct-edge: invalid CT_EDGE_METRICS_LISTEN '{addr}': {e}"),
        }
    }

    // Browser Plane public listener (#23 BP3): a RAW TCP listener that routes an
    // incoming browser TLS connection to a tunnel by its SNI hostname WITHOUT
    // terminating TLS (serve_sni_passthrough) — TLS terminates at the Origin, so
    // the Edge stays payload-blind. Off by default; set
    // CT_EDGE_BROWSER_LISTEN=0.0.0.0:443. Hostnames are bound by agents via 'H'.
    if let Ok(addr) = std::env::var("CT_EDGE_BROWSER_LISTEN") {
        // The intent is recorded HERE -- the operator set the variable, so this listener is
        // expected -- and NOT further down as an argument to `serve_listener`, which is only
        // reached once the bind has already succeeded. Same placement, and the same reason,
        // as the relay/rendezvous loops below (#539): a failed bind must read as "expected
        // but absent", not as "never wanted". Before the variable is even parsed, so a
        // malformed address counts too: that is also a listener the operator asked for and
        // did not get.
        let browser_health = state.expect_listener("Browser-Plane SNI listener", unix_now());
        match addr.parse::<SocketAddr>() {
            Ok(listen) => match tokio::net::TcpListener::bind(listen).await {
                Ok(bl) => {
                    let bstate = state.clone();
                    // #254: this listener previously admitted every accepted connection
                    // unconditionally -- unlike every other public accept loop in this file,
                    // it had NO cap at all. Apply both the shared `conn_cap` (consistent with
                    // the QUIC/TCP-fallback/:443 loops sharing one budget) and the
                    // BrowserTunnel-specific `browser_tunnel_cap` (#254), same shed-cheaply
                    // posture as everywhere else.
                    //
                    // #452: migrated onto the shared `serve_listener` helper for the FIRST
                    // (`conn_cap`) admission + keepalive (previously missing here) + spawn;
                    // this listener's own SECOND, BrowserTunnel-specific cap is applied inside
                    // the handler itself (a genuine second budget the shared helper has no
                    // concept of), same shed-cheaply posture as before.
                    let browser_tunnel_cap_bl = browser_tunnel_cap.clone();
                    tokio::spawn(crate::transport::serve_listener(
                        bl,
                        conn_cap.clone(),
                        "Browser-Plane SNI listener",
                        None,
                        shutdown.clone(),
                        Some(browser_health),
                        move |tcp, _addr, permit| {
                            let state = bstate.clone();
                            let browser_tunnel_cap = browser_tunnel_cap_bl.clone();
                            async move {
                                let sub_permit = match &browser_tunnel_cap {
                                    Some(cap) => match cap.try_admit() {
                                        Some(p) => Some(p),
                                        None => return,
                                    },
                                    None => None,
                                };
                                let _permit = permit;
                                let _sub_permit = sub_permit;
                                let _ = serve_sni_passthrough(tcp, &state).await;
                            }
                        },
                    ));
                    eprintln!("ct-edge: Browser-Plane SNI listener on {listen}");
                }
                Err(e) => eprintln!("ct-edge: cannot bind CT_EDGE_BROWSER_LISTEN {listen}: {e}"),
            },
            Err(e) => eprintln!("ct-edge: invalid CT_EDGE_BROWSER_LISTEN '{addr}': {e}"),
        }
    }

    // #31 FD2: the unified :443 front door — one TCP listener that classifies
    // each ClientHello (ALPN then SNI) and dispatches to the data-plane relay,
    // the Portal, or a Browser-Plane tunnel (serve_front_door). Off unless
    // CT_FRONT_DOOR is set; additive, so direct :8090/:4433 keep working. This is
    // the single port agents/clients/browsers on :443-only networks reach.
    // Cross-transport pairing (#495): populated below (inside the CT_FRONT_DOOR arm,
    // where the `:443` channel broker's pairer is actually constructed) whenever
    // channel brokering is enabled; the browser WebSocket listener further down
    // (unconditional on CT_FRONT_DOOR -- it can run standalone) picks it up if
    // present, so a `:443`/QUIC member and a browser member of the same channel
    // correlate through one pairer and can pair with each other.
    let mut shared_channel_pairer: Option<crate::channel_broker::SharedChannelPairer> = None;
    // #400: kept alive here (in `run_edge`'s own stack frame, which does not drop until
    // `run_edge` itself returns -- i.e. not until AFTER the bounded shutdown-drain wait
    // completes) so the QUIC channel-broker relay/rendezvous pairers -- constructed just
    // below, one each, never shared with each other -- survive their OWN
    // `run_channel_broker_loop`'s early return on shutdown. Without this, that loop
    // returning would drop the last `Arc` reference to its pairer and force-close every
    // parked member immediately on shutdown, instead of letting it survive the grace
    // period like every other in-flight connection. See `SharedQuicChannelPairer`'s and
    // `run_channel_broker_loop`'s own doc comments for the full story.
    let mut _relay_pairer_keepalive: Option<crate::channel_broker::SharedQuicChannelPairer> = None;
    let mut _rendezvous_pairer_keepalive: Option<crate::channel_broker::SharedQuicChannelPairer> = None;
    if let Ok(addr) = std::env::var("CT_FRONT_DOOR") {
        // The severe one. `:443` is the entire public surface of this edge: if this bind
        // fails, every tunnel is dead. Until this line the failure reached only the
        // `eprintln!` in the Err arm below -- `/healthz` kept answering 200 (the listener
        // that never started also never registered, and an absent row cannot fail a check),
        // the container healthcheck stayed green, and nothing restarted. Recorded before the
        // parse for the same reason as the Browser-Plane listener above.
        let front_door_health = state.expect_listener(":443 front door", unix_now());
        match addr.parse::<SocketAddr>() {
            Ok(listen) => match tokio::net::TcpListener::bind(listen).await {
                Ok(fl) => {
                    let fstate = state.clone();
                    let facceptor = acceptor.clone();
                    // #48: build the front door's terminate/reverse-proxy targets —
                    // the Portal (control plane; also the no-SNI-web default) plus an
                    // optional Auth IdP (Keycloak on auth.<zone>). Each is
                    // host -> (upstream, Option<cert-acceptor>); with a cert the edge
                    // terminates TLS + HTTP-proxies (FD4-a), without it raw-proxies.
                    let mut proxies: std::collections::HashMap<String, ProxyTarget> =
                        std::collections::HashMap::new();
                    let mut default_host: Option<String> = None;
                    if let (Some(host), Some(addr)) = (
                        std::env::var("CT_EDGE_PORTAL_HOST").ok().filter(|s| !s.is_empty()),
                        resolve_proxy_addr(std::env::var("CT_CP_PROXY_ADDR").ok()),
                    ) {
                        let tls = build_front_door_cert("Portal", "CT_EDGE_PORTAL_CERT", "CT_EDGE_PORTAL_KEY");
                        let h = host.to_ascii_lowercase();
                        proxies.insert(h.clone(), (addr, tls));
                        default_host = Some(h);
                    }
                    if let (Some(host), Some(addr)) = (
                        std::env::var("CT_EDGE_AUTH_HOST").ok().filter(|s| !s.is_empty()),
                        resolve_proxy_addr(std::env::var("CT_EDGE_AUTH_ADDR").ok()),
                    ) {
                        let tls = build_front_door_cert("Auth IdP", "CT_EDGE_AUTH_CERT", "CT_EDGE_AUTH_KEY");
                        proxies.insert(host.to_ascii_lowercase(), (addr, tls));
                    }
                    // #233: the shared front-door wildcard cert backing the Gelb
                    // tier — same env-var/loading convention as Portal/Auth IdP
                    // above. `None` (unset, or unusable per #142) means every
                    // BrowserTunnel host stays on ordinary passthrough even if
                    // the control plane ever pushes `channel_tier=gelb` for one — there
                    // is no cert to terminate with, so the arm falls through.
                    let wildcard_tls =
                        build_front_door_cert("Wildcard", "CT_EDGE_WILDCARD_CERT", "CT_EDGE_WILDCARD_KEY");
                    // ADR-0021 Part 1: the mesh-relay fallback for a genuine local
                    // routing miss -- OFF by default (CT_EDGE_MESH_RELAY_ENABLED),
                    // a no-op until an operator actually runs a second edge.
                    // Reuses the same CT_EDGE_CP_URL/CT_EDGE_ADMIN_TOKEN the
                    // rehydrate/heartbeat registry client already requires, and
                    // this edge's own published Mesh-Plane CA root (`ca_root`).
                    let mesh_relay_config = if std::env::var("CT_EDGE_MESH_RELAY_ENABLED")
                        .map(|v| {
                            let v = v.trim();
                            !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false")
                        })
                        .unwrap_or(false)
                    {
                        match (
                            std::env::var("CT_EDGE_CP_URL").ok().filter(|s| !s.is_empty()),
                            std::env::var("CT_EDGE_ADMIN_TOKEN").ok().and_then(|s| parse_admin_token_hex(&s)),
                        ) {
                            (Some(cp_url), Some(admin_token)) => {
                                eprintln!(
                                    "ct-edge: mesh-relay fallback ENABLED against {cp_url} (CT_EDGE_MESH_RELAY_ENABLED)"
                                );
                                Some(MeshRelayConfig {
                                    cp_url,
                                    admin_token,
                                    edge_cert: ca_root.clone(),
                                    negative_cache: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
                                })
                            }
                            _ => {
                                eprintln!(
                                    "ct-edge: CT_EDGE_MESH_RELAY_ENABLED set but CT_EDGE_CP_URL/CT_EDGE_ADMIN_TOKEN \
                                     missing -- mesh-relay stays off"
                                );
                                None
                            }
                        }
                    } else {
                        None
                    };
                    let n_proxies = proxies.len();
                    let proxies = std::sync::Arc::new(proxies);
                    let default_host = std::sync::Arc::new(default_host);
                    // #106 frontdoor-wire: when the CP URL + admin token are set, the front
                    // door also brokers `:443` channel joins (a member whose network blocks
                    // `:4435` reaches the broker here). Build the long-lived shared pairer +
                    // CP-backed resolver ONCE, outside the accept loop, so all `:443` channel
                    // members correlate through one pairer; hand a cloned-Arc context to each
                    // connection. Unset -> None (the ChannelBroker arm refuses with a clear
                    // "not configured" error). Mirrors the QUIC broker's opt-in style.
                    // `shared_channel_pairer` (declared at the top of `run_edge`) is assigned
                    // inside the match arm below, once channel brokering is confirmed enabled.
                    let channel_fd: Option<ChannelFrontDoor> = match (
                        std::env::var("CT_EDGE_CP_URL").ok().filter(|s| !s.is_empty()),
                        std::env::var("CT_EDGE_ADMIN_TOKEN")
                            .ok()
                            .and_then(|s| parse_admin_token_hex(&s)),
                    ) {
                        (Some(cp_url), Some(admin_tok)) => {
                            let authorizer =
                                crate::channel_authorize::ChannelAuthorizer::new(&cp_url, &admin_tok);
                            // #555: start the membership re-check exactly once. A splice is
                            // authorized at admission and then never again, so removing a
                            // member had no effect on their live connection (measured). This
                            // loop is the only thing that asks; without it the registry and
                            // the cut path are dead weight. Its own authorizer, so it is not
                            // entangled with the front door's lifetime, and it idles for free
                            // while no splice is registered.
                            if !MEMBERSHIP_RECHECK_STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                                let recheck: std::sync::Arc<dyn ChannelMemberResolver> =
                                    std::sync::Arc::new(
                                        crate::channel_authorize::ChannelAuthorizer::new(&cp_url, &admin_tok),
                                    );
                                eprintln!(
                                    "ct-edge: channel membership re-check active -- a member removed \
                                     from a channel loses their LIVE splice, not just future joins (#555)"
                                );
                                tokio::spawn(crate::channel_broker::run_membership_recheck_loop(recheck));
                            }
                            // #118: dedicated channel acceptor advertising `ct-edge-channel`
                            // (a CA-signed leaf; the same `ca` that issued the shared edge
                            // leaf) so the `:443` channel leg negotiates the ALPN. The shared
                            // `acceptor` keeps its empty ALPN for the `EdgeRelay` leg.
                            // The reserved fallback hostname joins "localhost" in the
                            // leaf's SANs: the low-DPI-visibility route's client presents
                            // it as its SNI, so without a matching SAN an ordinary rustls
                            // name verification would reject the leaf.
                            let channel_acceptor = crate::pki::build_channel_front_door_acceptor(
                                &ca,
                                vec![
                                    "localhost".to_string(),
                                    crate::sni::CT_EDGE_CHANNEL_FALLBACK_SNI.to_string(),
                                ],
                            )
                            .await?;
                            eprintln!(
                                "ct-edge: front-door :443 channel broker active \
                                 (authorize via {cp_url}, #106; ct-edge-channel ALPN #118)"
                            );
                            let pairer = crate::channel_broker::new_shared_channel_pairer();
                            spawn_front_door_pairer_reaper(
                                pairer.clone(),
                                Duration::from_secs(CHANNEL_PARK_TTL_SECS / 3),
                                unix_now,
                                // ct-agent#21: tell the live client its park EXPIRED (EX
                                // token) so it re-parks on the same rung immediately,
                                // instead of misreading the silent close as a rung failure.
                                |m| {
                                    tokio::spawn(m.payload.notify_park_expired());
                                },
                            );
                            shared_channel_pairer = Some(pairer.clone());
                            Some(ChannelFrontDoor::new(
                                std::sync::Arc::new(authorizer),
                                channel_acceptor,
                                pairer,
                            ))
                        }
                        _ => None,
                    };
                    // Real NAT-to-NAT hole-punch relay (multiplexed onto :443, no new public
                    // port): needs the same CP-backed membership resolver as the channel
                    // broker above, PLUS the internal-only address of the relay-node process
                    // this gate splices authorized connections to. Unset -> None (the
                    // RelayGate arm refuses with a clear "not configured" error) -- opt-in,
                    // same style as mesh-relay and the channel broker.
                    let relay_gate_ctx: Option<crate::relay_gate::RelayGateContext> = match (
                        std::env::var("CT_EDGE_CP_URL").ok().filter(|s| !s.is_empty()),
                        std::env::var("CT_EDGE_ADMIN_TOKEN")
                            .ok()
                            .and_then(|s| parse_admin_token_hex(&s)),
                        std::env::var("CT_EDGE_RELAY_UPSTREAM").ok().filter(|s| !s.is_empty()),
                        // The relay-node's own stable libp2p PeerId (matches its
                        // CT_RELAY_NODE_KEY) -- passed through in every pre-auth ack so a
                        // requester, which never reaches the relay-node directly, can
                        // address its Circuit-Relay v2 reservation/dial.
                        std::env::var("CT_EDGE_RELAY_NODE_PEER").ok().filter(|s| !s.is_empty()),
                    ) {
                        (Some(cp_url), Some(admin_tok), Some(upstream_raw), Some(relay_node_peer)) => {
                            match upstream_raw.parse::<std::net::SocketAddr>() {
                                Ok(upstream) => {
                                    let authorizer =
                                        crate::channel_authorize::ChannelAuthorizer::new(&cp_url, &admin_tok);
                                    let relay_acceptor = crate::pki::build_relay_gate_front_door_acceptor(
                                        &ca,
                                        vec!["localhost".to_string()],
                                    )
                                    .await?;
                                    eprintln!(
                                        "ct-edge: front-door :443 relay gate active \
                                         (authorize via {cp_url}, relay-node at {upstream} \
                                         (peer {relay_node_peer}), ct-edge-relay ALPN)"
                                    );
                                    Some(crate::relay_gate::RelayGateContext::new(
                                        std::sync::Arc::new(authorizer),
                                        relay_acceptor,
                                        upstream,
                                        relay_node_peer,
                                    ))
                                }
                                Err(e) => {
                                    eprintln!(
                                        "ct-edge: CT_EDGE_RELAY_UPSTREAM '{upstream_raw}' is not a valid \
                                         socket address ({e}) -- relay gate stays off"
                                    );
                                    None
                                }
                            }
                        }
                        _ => None,
                    };
                    // #119 SEC: apply the #95 connection cap to the `:443` front door too
                    // — the most-exposed public port. Like the QUIC and TCP-fallback loops,
                    // acquire a permit and SHED over the cap by dropping the socket, so an
                    // unauthenticated `:443` connection flood can't exhaust tasks/FDs/memory
                    // (each connection reaching the un-timed TLS handshake) before the PoW /
                    // grant / membership gates run. Was missing here — the cap was cloned to
                    // the TCP-fallback and QUIC loops but never to this one.
                    //
                    // #452: migrated onto the shared `serve_listener` helper (admission,
                    // keepalive, shed logging, spawning). No helper-level `handshake_timeout`
                    // — every arm this dispatches into already applies its OWN internal
                    // timeout to just its handshake/admission-read phase (`EdgeRelay`/`Proxy`
                    // via `FRONT_DOOR_TLS_ACCEPT_TIMEOUT`, `ChannelBroker` now too per #452's
                    // fix above, `BrowserTunnel`/`RelayGate` via their own paths) — this
                    // connection is meant to stay open for the tunnel's/session's whole real
                    // lifetime, which a whole-handler timeout here would incorrectly bound.
                    let browser_tunnel_cap_fd = browser_tunnel_cap.clone();
                    let tcp_agent_cap_fd = tcp_agent_cap.clone();
                    // #533: shared, memory-bounded state for condensing the benign
                    // client-abort log lines (see `log_front_door_error`). One per
                    // listener rather than a process-wide static, so it is scoped to the
                    // thing it describes; behind a `std::sync::Mutex` because — unlike the
                    // #530 reapers, which are single tasks — this is touched from every
                    // concurrently spawned connection handler. Never held across an await.
                    let front_door_abort_log = Arc::new(std::sync::Mutex::new(
                        crate::log_throttle::WindowLogThrottle::<ClientAbortClass>::new(
                            FRONT_DOOR_ABORT_LOG_WINDOW_SECS,
                            FRONT_DOOR_ABORT_LOG_MAX_TRACKED_CLASSES,
                            FRONT_DOOR_ABORT_LOG_TOP_CLASSES,
                        ),
                    ));
                    tokio::spawn(crate::transport::serve_listener(
                        fl,
                        conn_cap.clone(),
                        ":443 front door",
                        None,
                        shutdown.clone(),
                        Some(front_door_health),
                        move |tcp, _addr, permit| {
                            let state = fstate.clone();
                            let acceptor = facceptor.clone();
                            let proxies = proxies.clone();
                            let default_host = default_host.clone();
                            let channel_fd = channel_fd.clone();
                            let wildcard_tls = wildcard_tls.clone();
                            let mesh_relay_config = mesh_relay_config.clone();
                            let relay_gate_ctx = relay_gate_ctx.clone();
                            let browser_tunnel_cap = browser_tunnel_cap_fd.clone();
                            let tcp_agent_cap = tcp_agent_cap_fd.clone();
                            let abort_log = front_door_abort_log.clone();
                            async move {
                                let mut nonce = [0u8; 16];
                                rand::rngs::OsRng.fill_bytes(&mut nonce);
                                let challenge = Challenge { nonce, difficulty };
                                // #127: log any front-door failure (TLS accept, routing,
                                // every arm) — the whole handler's `Result` was discarded, so
                                // a connection that reached the edge but failed anywhere in
                                // serve_front_door was completely invisible to the operator.
                                // #533: that property is unchanged for every error that is
                                // not PROVABLY a benign client abort; the benign classes are
                                // counted (ct_edge_front_door_client_aborts_total) and
                                // condensed instead of repeated per occurrence.
                                if let Err(e) = serve_front_door(
                                    tcp,
                                    &state,
                                    &acceptor,
                                    &proxies,
                                    default_host.as_deref(),
                                    &challenge,
                                    channel_fd.as_ref(),
                                    wildcard_tls.as_ref(),
                                    mesh_relay_config.as_ref(),
                                    relay_gate_ctx.as_ref(),
                                    browser_tunnel_cap.as_ref(),
                                    tcp_agent_cap.as_ref(),
                                    permit,
                                )
                                .await
                                {
                                    log_front_door_error(&abort_log, unix_now(), &e);
                                }
                            }
                        },
                    ));
                    eprintln!("ct-edge: unified :443 front door on {listen} ({n_proxies} proxy host(s), CT_FRONT_DOOR)");
                }
                Err(e) => eprintln!("ct-edge: cannot bind CT_FRONT_DOOR {listen}: {e}"),
            },
            Err(e) => eprintln!("ct-edge: invalid CT_FRONT_DOOR '{addr}': {e}"),
        }
    }

    // Optional :80 -> :443 redirect: bounce a browser that types http://<host>/
    // to https on the unified gateway. Off unless CT_EDGE_HTTP_REDIRECT is set
    // (e.g. 0.0.0.0:80). Pairs with the front door / FD4-a Portal termination.
    if let Ok(addr) = std::env::var("CT_EDGE_HTTP_REDIRECT") {
        // Advisory, not gating: recorded before the bind like every other listener, so a
        // failed `:80` bind is visible in `/metrics` instead of leaving no trace at all --
        // but excluded from the `/healthz` verdict, because #553's reasoning below still
        // holds and restarting every live tunnel over a lost convenience redirect would be
        // worse than the fault. Until this existed the only two options were "fatal" and
        // "invisible", and #553 had to choose invisible.
        let redirect_health = state.expect_listener_advisory(":80 redirect", unix_now());
        match addr.parse::<SocketAddr>() {
            Ok(listen) => match tokio::net::TcpListener::bind(listen).await {
                Ok(rl) => {
                    // #255: same global ConnectionCap as the other accept loops (QUIC, TCP
                    // fallback, :443 front door) -- this listener is public and previously
                    // spawned an unbounded task per accepted connection, so a flood here
                    // could exhaust FDs/tasks for the whole edge process regardless of the
                    // caps already enforced everywhere else.
                    //
                    // #452: migrated onto the shared `serve_listener` helper — this whole
                    // connection is short-lived by design (connect, read one request, write
                    // one redirect, done), so unlike the other migrated loops it's correct to
                    // let the helper bound the WHOLE handler (`serve_http_redirect` already
                    // has its own internal `HTTP_REDIRECT_READ_TIMEOUT` too — #470 — so this
                    // is redundant-but-harmless belt and suspenders, and closes the
                    // "cap-vs-timeout divergence" #452 flagged for this specific loop).
                    tokio::spawn(crate::transport::serve_listener(
                        rl,
                        conn_cap.clone(),
                        ":80 redirect",
                        Some(HTTP_REDIRECT_READ_TIMEOUT),
                        shutdown.clone(),
                        // #553: deliberately NOT health-gated. The other three accept loops
                        // carry the data plane, so their death is an outage worth restarting
                        // the edge for. This one only 308s plain http:// to https://; losing
                        // it costs a convenience redirect, and tearing down every live tunnel
                        // to recover it would do far more damage than the fault. That
                        // reasoning is unchanged -- what changed is that "not fatal" no
                        // longer has to mean "not reported": the heartbeat below is advisory,
                        // so this loop shows up in /metrics and stays out of /healthz.
                        Some(redirect_health),
                        move |tcp, _addr, permit| async move {
                            let _permit = permit; // held for the connection's lifetime
                            let _ = serve_http_redirect(tcp).await;
                        },
                    ));
                    eprintln!("ct-edge: HTTP->HTTPS redirect on {listen} (CT_EDGE_HTTP_REDIRECT)");
                }
                Err(e) => eprintln!("ct-edge: cannot bind CT_EDGE_HTTP_REDIRECT {listen}: {e}"),
            },
            Err(e) => eprintln!("ct-edge: invalid CT_EDGE_HTTP_REDIRECT '{addr}': {e}"),
        }
    }

    // TCP fallback accept loop (for Clients whose outbound UDP is blocked).
    // #533-follow: the `:4433` arm gets its OWN throttle window, not a share of the front
    // door's. Merging them would put two different listeners' aborts in one summary, and the
    // whole point of the classification is that an operator can tell which leg is talking.
    let tcp_fallback_abort_log = Arc::new(std::sync::Mutex::new(
        crate::log_throttle::WindowLogThrottle::<ClientAbortClass>::new(
            FRONT_DOOR_ABORT_LOG_WINDOW_SECS,
            FRONT_DOOR_ABORT_LOG_MAX_TRACKED_CLASSES,
            FRONT_DOOR_ABORT_LOG_TOP_CLASSES,
        ),
    ));
    let state_tcp = state.clone();
    // #86 SEC86c: the TCP fallback is the same rendezvous surface as QUIC, so it
    // shares the one connection cap (a clone — the budget is global, not per-loop).
    //
    // #452: migrated onto the shared `serve_listener` helper (admission, keepalive,
    // shed logging, spawning). No helper-level `handshake_timeout` — this connection
    // stays open for the tunnel's whole life; only the TLS handshake itself is bounded,
    // via `TCP_FALLBACK_ADMISSION_TIMEOUT` inside the handler, unchanged from before.
    let tcp_agent_cap_loop = tcp_agent_cap.clone();
    tokio::spawn(crate::transport::serve_listener(
        tcp_listener,
        conn_cap.clone(),
        "TCP fallback",
        None,
        shutdown.clone(),
        Some(state.expect_listener("TCP fallback", unix_now())),
        move |tcp, _addr, permit| {
            let acceptor = acceptor.clone();
            let state = state_tcp.clone();
            let tcp_agent_cap = tcp_agent_cap_loop.clone();
            let abort_log_tcp = tcp_fallback_abort_log.clone();
            async move {
                let _permit = permit; // held for the connection's lifetime
                // #258: bound the handshake too, not just the admission reads inside
                // serve_tcp_connection -- a slow-drip TLS handshake holds the cap
                // permit exactly the same way a slow admission read does.
                let Ok(Ok(tls)) = tokio::time::timeout(TCP_FALLBACK_ADMISSION_TIMEOUT, acceptor.accept(tcp)).await else {
                    return;
                };
                let mut nonce = [0u8; 16];
                rand::rngs::OsRng.fill_bytes(&mut nonce);
                let challenge = Challenge { nonce, difficulty };
                // Mirrors the ":443 front door" arm above (#127): log any raw-listener
                // failure instead of discarding it -- a client connecting directly to
                // :4433 (not routed through the unified :443 front door) whose connection
                // fails for any reason, including a NAT/firewall silently dropping an
                // idle TCP-fallback connection mid-session, previously left zero log
                // output explaining why.
                if let Err(e) = serve_tcp_connection(tls, &state, &challenge, tcp_agent_cap.as_ref()).await {
                    // #533-follow: same classifier and throttle as the `:443` arm. A client
                    // that closes without close_notify is ordinary, not a fault -- logging
                    // it flat produced 44 error-shaped lines in three hours, in exactly the
                    // log read while chasing ct-agent#15's "the edge drops connections".
                    log_front_door_error_on(LEG_TCP_FALLBACK, &abort_log_tcp, unix_now(), &e);
                }
            }
        },
    ));

    // #81 SEC81c-c c-iii-3b: mount the Agent-Fabric broker on a DEDICATED channel-
    // rendezvous QUIC endpoint (a fresh leaf under the same CA, so agents already trust
    // it). Opt-in: only when the channel listen addr + control-plane URL + shared admin
    // token are all set. The broker's `authorize` closure resolves channel membership via
    // the control plane (c-i/c-ii, fail-closed); each rendezvous pairs two members and
    // hands each the other's advertised endpoint for a direct A2A connection.
    if let (Some(listen), Some(cp_url), Some(admin_tok)) = (
        std::env::var("CT_EDGE_CHANNEL_LISTEN").ok().filter(|s| !s.is_empty()),
        std::env::var("CT_EDGE_CP_URL").ok().filter(|s| !s.is_empty()),
        std::env::var("CT_EDGE_ADMIN_TOKEN")
            .ok()
            .and_then(|s| parse_admin_token_hex(&s)),
    ) {
        match listen.parse::<std::net::SocketAddr>() {
            Ok(chan_addr) => {
                match build_server_endpoint_from_ca(&ca, chan_addr, vec!["localhost".to_string()]) {
                    Ok((chan_ep, _root)) => {
                        let authorizer =
                            crate::channel_authorize::ChannelAuthorizer::new(&cp_url, &admin_tok);

                        // #105 / #72 AF4-relay: also mount the RELAY on a second endpoint
                        // (default channel port + 1, or CT_EDGE_CHANNEL_RELAY_LISTEN). Two
                        // members BOTH behind NAT can't reach each other on the direct path,
                        // so rendezvous alone can't pair them — they fall back to this relay,
                        // which authorizes both joins and splices their streams through the
                        // edge (ciphertext; the Noise_IK session stays end-to-end). Without
                        // this spawn, a NAT'd agent's relay connection has nowhere to go.
                        // #103 guard: the relay MUST be a distinct endpoint from the
                        // rendezvous. If the configured relay addr collides with `chan_addr`,
                        // two accept loops would bind one port and silently break all pairing
                        // — so we refuse to start the relay (loud warning) and keep only the
                        // rendezvous loop, which then owns a single pairer and pairs correctly.
                        let relay_addr = resolve_channel_relay_addr(
                            chan_addr,
                            std::env::var("CT_EDGE_CHANNEL_RELAY_LISTEN").ok().as_deref(),
                        );
                        if let Err(e) = &relay_addr {
                            eprintln!("ct-edge: NOT starting the channel relay — {e}");
                        }
                        if let Ok(relay_addr) = relay_addr {
                        // #539: the intent is recorded HERE -- past the #103 guard (so a
                        // deliberate no-relay stays healthy) but before the listener is bound,
                        // so a bind failure below is "expected but absent" rather than
                        // indistinguishable from "never wanted". Without this line, that
                        // failure reaches only the `eprintln!` in the Err arm and `/healthz`
                        // keeps answering 200 while both-NAT'd peers cannot pair at all.
                        state.relay_broker_heartbeat().expect_start(unix_now());
                        match build_server_endpoint_from_ca(&ca, relay_addr, vec!["localhost".to_string()]) {
                            Ok((relay_ep, _)) => {
                                let relay_az = authorizer.clone();
                                let relay_cap = channel_broker_cap.clone();
                                let shutdown_relay = shutdown.clone();
                                // Per-IP definitive-refusal penalty, SHARED with the
                                // rendezvous loop and the `:443` front-door arm via
                                // `EdgeState` -- one budget per IP across all three
                                // channel-join transports (2026-08-13 storm).
                                let relay_penalty = state.join_refusal_penalty();
                                let relay_heartbeat = state.relay_broker_heartbeat();
                                // #400: constructed here (not inside `run_channel_broker_loop`) so
                                // `run_edge` can keep its own clone alive independently of the
                                // loop's lifetime -- see `_relay_pairer_keepalive`'s own comment above.
                                let relay_pairer: crate::channel_broker::SharedQuicChannelPairer =
                                    std::sync::Arc::new(std::sync::Mutex::new(
                                        crate::channel_broker::ChannelPairer::new(),
                                    ));
                                _relay_pairer_keepalive = Some(relay_pairer.clone());
                                eprintln!("ct-edge: Agent-Fabric channel RELAY on {relay_addr} (#105/#72 AF4-relay, #109 concurrent)");
                                tokio::spawn(async move {
                                    // #109-concurrent-b: drive the relay with a channel-keyed
                                    // pairer that spawns each splice on its own task, so a
                                    // long-lived relay can't wedge the single global slot and
                                    // two channels can never cross-pair. Replaces the old serial
                                    // `loop { broker_channel_relay(..).await }` that ran the
                                    // splice inline on the accept loop.
                                    let now_fn = unix_now;
                                    let authorize =
                                        move |c: ct_common::channel::ChannelId, h: [u8; 32]| {
                                            let a = relay_az.clone();
                                            async move {
                                                a.resolve(&c, &h).await.map(|m| {
                                                    (m.operator_pubkey, m.noise_pubkey, m.noise_attestation)
                                                })
                                            }
                                        };
                                    crate::channel_broker::run_channel_broker_loop(
                                        &relay_ep,
                                        now_fn,
                                        authorize,
                                        CHANNEL_PARK_TTL_SECS,
                                        crate::channel_broker::ParkPhase::Relay,
                                        |a, b, now| {
                                            crate::channel_broker::finish_relay_pair(a, b, now)
                                        },
                                        relay_cap,
                                        shutdown_relay,
                                        relay_pairer,
                                        relay_penalty,
                                        relay_heartbeat,
                                        None, // #603: step 6 wires the real store
                                    )
                                    .await;
                                });
                            }
                            Err(e) => eprintln!("ct-edge: cannot bind channel relay {relay_addr}: {e}"),
                        }
                        }

                        eprintln!(
                            "ct-edge: Agent-Fabric channel broker on {chan_addr} \
                             (authorize via {cp_url}, #81 SEC81c-c, #120 concurrent)"
                        );
                        let rendezvous_cap = channel_broker_cap.clone();
                        let shutdown_rendezvous = shutdown.clone();
                        // Same shared penalty as the relay loop above (one per-IP budget
                        // across every channel-join transport).
                        let rendezvous_penalty = state.join_refusal_penalty();
                        let rendezvous_heartbeat = state.rendezvous_broker_heartbeat();
                        // #539: same as the relay above. The rendezvous loop has no
                        // "deliberately off" case today, which is exactly why its silence
                        // would be pure failure -- and just as invisible without this.
                        rendezvous_heartbeat.expect_start(unix_now());
                        // #400: same reasoning as the relay pairer above -- constructed here so
                        // `run_edge` can keep its own clone alive independently of the loop's
                        // own lifetime.
                        let rendezvous_pairer: crate::channel_broker::SharedQuicChannelPairer =
                            std::sync::Arc::new(std::sync::Mutex::new(
                                crate::channel_broker::ChannelPairer::new(),
                            ));
                        _rendezvous_pairer_keepalive = Some(rendezvous_pairer.clone());
                        tokio::spawn(async move {
                            // #120: drive the RENDEZVOUS endpoint with the same channel-keyed
                            // pairer that spawns each pair-completion on its own task, so a
                            // single member that holds its rendezvous connection open can't
                            // wedge the single global accept slot and two channels can never
                            // cross-pair. Replaces the old serial `loop { broker_channel_
                            // rendezvous(..).await }` that awaited both `conn.closed()` inline.
                            let now_fn = unix_now;
                            let authorize = move |c: ct_common::channel::ChannelId, h: [u8; 32]| {
                                let a = authorizer.clone();
                                // Resolve both the operator key (grant check) and the
                                // member's attested Noise key, which the broker relays to
                                // the paired peer (#72/#100).
                                async move {
                                    a.resolve(&c, &h)
                                        .await
                                        .map(|m| (m.operator_pubkey, m.noise_pubkey, m.noise_attestation))
                                }
                            };
                            crate::channel_broker::run_channel_broker_loop(
                                &chan_ep,
                                now_fn,
                                authorize,
                                CHANNEL_PARK_TTL_SECS,
                                crate::channel_broker::ParkPhase::Rendezvous,
                                |a, b, now| {
                                    crate::channel_broker::finish_rendezvous_pair(a, b, now)
                                },
                                rendezvous_cap,
                                shutdown_rendezvous,
                                rendezvous_pairer,
                                rendezvous_penalty,
                                rendezvous_heartbeat,
                                None, // #603: step 6 wires the real store
                            )
                            .await;
                        });
                    }
                    Err(e) => eprintln!("ct-edge: cannot bind CT_EDGE_CHANNEL_LISTEN {chan_addr}: {e}"),
                }
            }
            Err(e) => eprintln!("ct-edge: invalid CT_EDGE_CHANNEL_LISTEN '{listen}': {e}"),
        }
    }

    // Video-conferencing feature: a browser has no raw UDP/QUIC and no TLS-ALPN
    // control of its own, so it can't reach either broker above. This is the
    // browser-reachable entry point instead -- a plain WebSocket listener bridging
    // into the identical channel_broker admission/pairing/relay core (see
    // ws_channel.rs's module doc for the full design). Opt-in, same convention as
    // the brokers above: only when the listen addr + CP URL + admin token are set.
    if let (Some(ws_listen), Some(cp_url), Some(admin_tok)) = (
        std::env::var("CT_EDGE_WS_CHANNEL_LISTEN").ok().filter(|s| !s.is_empty()),
        std::env::var("CT_EDGE_CP_URL").ok().filter(|s| !s.is_empty()),
        std::env::var("CT_EDGE_ADMIN_TOKEN")
            .ok()
            .and_then(|s| parse_admin_token_hex(&s)),
    ) {
        match ws_listen.parse::<std::net::SocketAddr>() {
            Ok(ws_addr) => {
                let resolver: std::sync::Arc<dyn ChannelMemberResolver> = std::sync::Arc::new(
                    crate::channel_authorize::ChannelAuthorizer::new(&cp_url, &admin_tok),
                );
                // Cross-transport pairing (#495): reuse the SAME pairer the `:443` front
                // door's channel broker uses (constructed above whenever CP_URL+ADMIN_TOKEN
                // are set, which this branch already requires too) so a browser member and a
                // `:443`/QUIC member of the same channel correlate and can pair with each
                // other. Falls back to a standalone pairer only in the defensive case where
                // this branch somehow runs without the front-door one having constructed it.
                let pairer = shared_channel_pairer.clone().unwrap_or_else(|| {
                    let p = crate::channel_broker::new_shared_channel_pairer();
                    spawn_front_door_pairer_reaper(
                        p.clone(),
                        Duration::from_secs(CHANNEL_PARK_TTL_SECS / 3),
                        unix_now,
                        |m| {
                            tokio::spawn(m.payload.notify_park_expired());
                        },
                    );
                    p
                });
                // ws_channel_cap was resolved earlier (alongside conn_cap/browser_tunnel_cap)
                // so it's also available to the metrics endpoint above whether or not this
                // listener ends up enabled.
                eprintln!(
                    "ct-edge: browser (WebSocket) Agent-Fabric channel listener on {ws_addr} \
                     (authorize via {cp_url}, cross-transport pairing with the :443 front door)"
                );
                let ws_channel_cap = ws_channel_cap.clone();
                let ws_channel_tls = build_ws_channel_cert();
                let shutdown_ws = shutdown.clone();
                // #542: the SAME budget the QUIC loops and the `:443` arm consult -- one
                // per-IP budget across every channel-join transport, not a third one.
                let ws_penalty = state.join_refusal_penalty();
                // #553: the fifth accept loop. Declared expected HERE, where the listener is
                // configured -- a bind failure below then reads as "expected, never started"
                // rather than "not wanted", which is the whole point of `expect_start`.
                let ws_heartbeat = state.expect_listener("ws-channel", unix_now());
                tokio::spawn(async move {
                    if let Err(e) = crate::ws_channel::serve_ws_channel_with_pairer(
                        ws_addr,
                        resolver,
                        pairer,
                        ws_channel_cap,
                        ws_channel_tls,
                        shutdown_ws,
                        Some(ws_penalty),
                        Some(ws_heartbeat),
                    )
                    .await
                    {
                        eprintln!("ct-edge: ws-channel listener on {ws_addr} ended: {e}");
                    }
                });
            }
            Err(e) => eprintln!("ct-edge: invalid CT_EDGE_WS_CHANNEL_LISTEN '{ws_listen}': {e}"),
        }
    }

    // QUIC accept loop (primary). #400: raced against `shutdown` so a pending
    // `endpoint.accept()` doesn't stop this from noticing shutdown promptly -- once
    // triggered, this breaks out (stops admitting new Agent connections) instead of
    // looping forever; already-admitted connections are untouched here (each runs to
    // completion on its own already-spawned task, same as before this change).
    loop {
        let incoming = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                eprintln!("ct-edge: QUIC front door stopping new accepts (shutdown)");
                break;
            }
            accepted = endpoint.accept() => match accepted {
                Some(i) => i,
                None => break,
            },
        };
        // #86 SEC86b: when a connection cap is configured and full, shed this
        // connection cheaply (no handshake response) rather than spawning unbounded.
        let permit = match &conn_cap {
            Some(cap) => match cap.try_admit() {
                Some(p) => Some(p),
                None => {
                    incoming.ignore();
                    continue;
                }
            },
            None => None,
        };
        let state = state.clone();
        tokio::spawn(async move {
            // Hold the admission permit for the whole connection lifetime, so the
            // slot frees only when this handler returns.
            let _permit = permit;
            if let Ok(conn) = incoming.await {
                let mut nonce = [0u8; 16];
                rand::rngs::OsRng.fill_bytes(&mut nonce);
                let challenge = Challenge { nonce, difficulty };
                let registered = serve_agent_connection(&conn, &state, &challenge).await;
                conn.closed().await;
                // Evict exactly this dropped agent's registration so a later
                // Client route() fails fast instead of hitting a dead handle (#2)
                // — and, with redundant agents (#8), so the OTHER agents serving
                // the same token keep the tunnel up.
                if let Ok(Some((token, reg))) = registered {
                    state.remove_registration(&token, reg);
                    // #583: previously silent; see the matching registration
                    // log line in `serve_connection`'s `'A'` branch.
                    let mut th_buf = [0u8; 8];
                    let th = token_hex(&token, &mut th_buf);
                    eprintln!("ct-edge: agent deregistered token={th} reg={reg} (#583)");
                }
            }
        });
    }

    // #400: bounded grace-drain. Every accept point above has already stopped admitting
    // (the SIGTERM/Ctrl-C task triggered `shutdown`, which every listener spawned in this
    // function selects against); this waits for the connections THEY ALREADY ADMITTED to
    // finish, up to `CT_EDGE_SHUTDOWN_GRACE_SECS` (default 30s), before returning. Every
    // public accept path in this daemon is gated by one of these five caps, so "every cap
    // reports zero in-use" is this process's actual "fully drained" signal -- a cap an
    // operator explicitly disabled (`CT_EDGE_MAX_*=off`) can't be waited on (no permit to
    // observe), so that specific listener's connections are simply not represented in the
    // drain wait; see `wait_for_drain`'s own doc comment. Once this returns, `run_edge`
    // returns, `main()` returns, and the Tokio runtime drop aborts anything still
    // running -- the actual "force-close" for whatever didn't finish in time.
    if shutdown.is_cancelled() {
        let grace = std::time::Duration::from_secs(shutdown_grace_secs_from_env());
        let caps = [
            conn_cap.clone(),
            browser_tunnel_cap.clone(),
            tcp_agent_cap.clone(),
            ws_channel_cap.clone(),
            channel_broker_cap.clone(),
        ];
        let still_open = crate::shutdown::wait_for_drain(&caps, grace).await;
        if still_open == 0 {
            eprintln!("ct-edge: shutdown drain complete -- every in-flight connection finished cleanly");
        } else {
            eprintln!(
                "ct-edge: shutdown grace period ({}s) elapsed with {still_open} connection(s) \
                 still open -- force-closing and exiting",
                grace.as_secs()
            );
        }
    }
    // #400: explicit, not merely incidental to scope end -- this is the precise point the
    // relay/rendezvous channel-broker pairers' extra keep-alive references (see
    // `_relay_pairer_keepalive`'s own comment near the top of this function) are meant to
    // survive UNTIL: after the drain wait above, together with every other still-open
    // connection this function was already about to drop by returning anyway.
    drop(_relay_pairer_keepalive);
    drop(_rendezvous_pairer_keepalive);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{build_client_endpoint, build_server_endpoint_with_cert};
    use std::sync::Arc;

    /// #533: build the front-door abort throttle a test drives by hand.
    fn front_door_abort_log(
        window_secs: u64,
        max_tracked: usize,
    ) -> std::sync::Mutex<crate::log_throttle::WindowLogThrottle<ClientAbortClass>> {
        std::sync::Mutex::new(crate::log_throttle::WindowLogThrottle::new(
            window_secs,
            max_tracked,
            FRONT_DOOR_ABORT_LOG_TOP_CLASSES,
        ))
    }

    /// #533: the classifier separates the three benign client-abort classes from
    /// everything else, TYPED (`io::ErrorKind`), not by matching the OS message — so a
    /// libc/OS reword can neither re-enable the noise nor start hiding something else.
    #[test]
    fn client_abort_classifier_separates_the_benign_classes_typed_533() {
        let reset: BoxError = Box::new(std::io::Error::from_raw_os_error(104)); // ECONNRESET
        assert!(
            reset.to_string().contains("Connection reset by peer"),
            "the exact line measured in the load test: {reset}"
        );
        assert_eq!(
            classify_client_abort(&reset),
            Some(ClientAbortClass::ConnectionReset),
            "143/158 of the measured noise"
        );
        let pipe: BoxError = Box::new(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "whatever"));
        assert_eq!(
            classify_client_abort(&pipe),
            Some(ClientAbortClass::BrokenPipe),
            "EPIPE is classified by KIND, regardless of message"
        );
        assert!(is_benign_client_abort(&reset) && is_benign_client_abort(&pipe));
    }

    /// #533: the rustls "no close_notify" class. rustls surfaces it as a plain
    /// `io::Error(UnexpectedEof, <fixed text>)` — there is no `rustls::Error` to
    /// downcast to — so the text NARROWS the typed kind check. That narrowing is the
    /// point: a bare `UnexpectedEof` (e.g. a torn frame, which
    /// `ct_common::fallback_framing` documents as a real connection error) must stay
    /// loud.
    #[test]
    fn client_abort_classifier_narrows_unexpected_eof_to_the_rustls_close_notify_case_533() {
        let close_notify: BoxError = Box::new(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            RUSTLS_MISSING_CLOSE_NOTIFY,
        ));
        assert_eq!(
            classify_client_abort(&close_notify),
            Some(ClientAbortClass::TlsCloseNotifyMissing),
            "15/158 of the measured noise"
        );
        let torn_frame: BoxError = Box::new(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "failed to fill whole buffer",
        ));
        assert_eq!(
            classify_client_abort(&torn_frame),
            None,
            "UnexpectedEof alone is NOT benign — a torn frame is a real connection error"
        );
    }

    /// #550: the enforcer for [`RUSTLS_MISSING_CLOSE_NOTIFY`].
    ///
    /// The two tests around it build the error from OUR OWN constant, which only ever
    /// proves that our classifier recognises our own string — a statement about us, not
    /// about rustls. This test makes **rustls produce the error itself**: a real TLS
    /// session over a real socket, whose client half is dropped after the handshake so
    /// the peer sees a FIN with no `close_notify` — exactly the case the constant names.
    ///
    /// Without this, a rustls patch release that rewords the message (it is a display
    /// string, not a public contract) would leave the gate green while the classification
    /// silently stopped matching in production. That failure is invisible by construction:
    /// it looks exactly like the normal state. Now it fails here instead.
    #[tokio::test]
    async fn rustls_still_words_the_missing_close_notify_error_the_way_we_match_it_550() {
        use tokio::io::AsyncReadExt;

        let (listener, acceptor, cert) =
            crate::transport::build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut buf = [0u8; 64];
            // The client is gone by now; this read is what surfaces rustls's verdict.
            tls.read(&mut buf).await
        });

        // Complete a real handshake, then close the WRITE half only: a FIN with no
        // `close_notify` ahead of it. Deliberately not a plain `drop` -- the server sends
        // TLS 1.3 session tickets right after the handshake, and closing a socket that
        // still has unread bytes in its receive buffer emits RST, not FIN. That yields
        // `ConnectionReset` (a different, separately-handled benign class) and would test
        // the wrong thing. The stream is held alive until the server has read.
        let mut client = crate::transport::tcp_tls_connect(addr, cert).await.unwrap();
        {
            let (tcp, _conn) = client.get_mut();
            tokio::io::AsyncWriteExt::shutdown(tcp).await.unwrap();
        }

        let err = server
            .await
            .unwrap()
            .expect_err("a peer that vanishes without close_notify must surface an error");

        assert_eq!(
            err.kind(),
            std::io::ErrorKind::UnexpectedEof,
            "the typed half of the check: rustls still reports this as UnexpectedEof (got {:?})",
            err.kind()
        );
        assert!(
            err.to_string().contains(RUSTLS_MISSING_CLOSE_NOTIFY),
            "rustls reworded its missing-close_notify message. RUSTLS_MISSING_CLOSE_NOTIFY no \
             longer matches, so `classify_io_client_abort` has silently stopped recognising this \
             class and #533's log condensation is off for it. Update the constant to rustls's \
             new wording. rustls said: {err}"
        );

        // And the classifier must actually accept the genuine article, not just our replica.
        let boxed: BoxError = Box::new(err);
        assert_eq!(
            classify_client_abort(&boxed),
            Some(ClientAbortClass::TlsCloseNotifyMissing),
            "a REAL rustls close_notify-less abort must classify, not only the hand-built one"
        );
    }

    /// #533: an `io::Error` reached through a wrapping error's `source()` chain is
    /// still classified (an arm that wraps its transport error must not silently lose
    /// the classification), and the walk is depth-bounded.
    #[test]
    fn client_abort_classifier_walks_the_source_chain_533() {
        #[derive(Debug)]
        struct Wrap(std::io::Error);
        impl std::fmt::Display for Wrap {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "front door: {}", self.0)
            }
        }
        impl std::error::Error for Wrap {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        let wrapped: BoxError = Box::new(Wrap(std::io::Error::from_raw_os_error(104)));
        assert_eq!(
            classify_client_abort(&wrapped),
            Some(ClientAbortClass::ConnectionReset),
            "a wrapped ECONNRESET is the same benign abort"
        );
    }

    /// #533 / #127 GUARD: the two real signals the load test drowned — and any other
    /// unrecognized error — must stay LOUD, line for line, unthrottled. This is the
    /// property #127 bought and #533 must not spend: `Loud` every time, no window, no
    /// suppression, and no contribution to the client-abort counter.
    #[test]
    fn real_front_door_errors_are_never_suppressed_127() {
        let log = front_door_abort_log(FRONT_DOOR_ABORT_LOG_WINDOW_SECS, FRONT_DOOR_ABORT_LOG_MAX_TRACKED_CLASSES);
        let before = front_door_client_aborts_total();
        for real in [
            // The two real signals measured in the same window as the 158 benign lines.
            "no tunnel registered for host 'scanner.example'",
            "front door: not a TLS ClientHello",
            // ... and a few other genuine failures from this handler's arms.
            "front door: ClientHello read timed out",
            "channel join admission exchange stalled (#140)",
        ] {
            let e: BoxError = real.into();
            assert!(!is_benign_client_abort(&e), "{real} must not classify as benign");
            // Repeated 5x: a benign class would be condensed after the first; a real
            // error must produce `Loud` EVERY time.
            for i in 0..5 {
                assert_eq!(
                    log_front_door_error(&log, 1_000 + i, &e),
                    FrontDoorErrorLog::Loud,
                    "occurrence {i} of '{real}' must stay loud"
                );
            }
        }
        // "A real error must never raise ct_edge_front_door_client_aborts_total" is proven by
        // the `Loud` verdicts above, not by reading the counter: `log_front_door_error`
        // increments only AFTER the unclassified early-return, so `Loud` and "did not count"
        // are the same event. Reading the process-wide counter here would have added no
        // information and one race -- any other test in this binary can bump it between the
        // `before` snapshot and this line. Its sibling assertion a few tests down failed
        // exactly that way in a full-suite run while passing 6/6 in isolation.
        let _ = before;
    }

    /// #533: the condensing itself — first abort of a class logs full, repeats are
    /// suppressed, and the metric counts EVERY abort including the suppressed ones.
    #[test]
    fn benign_client_aborts_are_condensed_but_all_counted_533() {
        let log = front_door_abort_log(FRONT_DOOR_ABORT_LOG_WINDOW_SECS, FRONT_DOOR_ABORT_LOG_MAX_TRACKED_CLASSES);
        // Delta-based: the counter is a process-wide static other tests also touch.
        let before = front_door_client_aborts_total();
        let reset: BoxError = Box::new(std::io::Error::from_raw_os_error(104));
        assert_eq!(
            log_front_door_error(&log, 1_000, &reset),
            FrontDoorErrorLog::BenignFirst(ClientAbortClass::ConnectionReset),
            "first of its class this window -> full line"
        );
        for i in 1..143u64 {
            assert_eq!(
                log_front_door_error(&log, 1_000 + i, &reset),
                FrontDoorErrorLog::BenignSuppressed(ClientAbortClass::ConnectionReset),
                "repeat {i} is condensed"
            );
        }
        // A different class is its own first sighting (the two classes measured live).
        let close_notify: BoxError = Box::new(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            RUSTLS_MISSING_CLOSE_NOTIFY,
        ));
        assert_eq!(
            log_front_door_error(&log, 1_100, &close_notify),
            FrontDoorErrorLog::BenignFirst(ClientAbortClass::TlsCloseNotifyMissing),
        );
        // The counter is a process-wide static and several other tests in this binary also
        // call `log_front_door_error*`, so an exact equality here is a statement about what
        // else happens to be running -- it failed that way in a full-suite run while passing
        // 6/6 in isolation. A lower bound still carries the property under test (every one of
        // this test's 144 occurrences was counted, suppressed ones included); the *precision*
        // it gives up was never real.
        assert!(
            front_door_client_aborts_total() >= before + 144,
            "the counter rises for suppressed aborts too — it is the complete record: {} vs {}",
            front_door_client_aborts_total(),
            before + 144
        );
        // 144 occurrences produced exactly 2 log lines: the measured 158-from-340 noise
        // collapses to one line per class per window.
        let s = log
            .lock_safe()
            .window_summary(1_000 + FRONT_DOOR_ABORT_LOG_WINDOW_SECS)
            .expect("the window elapsed with repeats -> one summary");
        assert_eq!(s.total, 144, "the summary accounts for every abort in the window");
        assert_eq!(s.distinct_keys, 2);
        assert_eq!(s.untracked, 0);
        assert_eq!(s.top[0], (ClientAbortClass::ConnectionReset, 143), "busiest class first");
        assert_eq!(s.top[1], (ClientAbortClass::TlsCloseNotifyMissing, 1));
    }

    /// #533: the window rolls over event-driven (this path has no periodic tick), and
    /// the tracking cap bounds the state even though today's key space is a closed
    /// enum — the memory bound is a property of the shared core, not of this caller.
    #[test]
    fn front_door_abort_window_rolls_over_and_the_cap_bounds_the_state_533() {
        let log = front_door_abort_log(FRONT_DOOR_ABORT_LOG_WINDOW_SECS, 1);
        let reset: BoxError = Box::new(std::io::Error::from_raw_os_error(104));
        let pipe: BoxError = Box::new(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "gone"));
        assert_eq!(
            log_front_door_error(&log, 1_000, &reset),
            FrontDoorErrorLog::BenignFirst(ClientAbortClass::ConnectionReset)
        );
        assert_eq!(
            log_front_door_error(&log, 1_001, &pipe),
            FrontDoorErrorLog::BenignSuppressed(ClientAbortClass::BrokenPipe),
            "beyond the tracking cap -> no full line, counted without identity"
        );
        assert_eq!(log.lock_safe().tracked_len(), 1, "the map never exceeds the cap");
        // The next abort AFTER the window elapsed rolls it over: state resets (the
        // reset IS the eviction) and the class logs in full again.
        assert_eq!(
            log_front_door_error(&log, 1_000 + FRONT_DOOR_ABORT_LOG_WINDOW_SECS, &reset),
            FrontDoorErrorLog::BenignFirst(ClientAbortClass::ConnectionReset),
            "after the rollover the class logs in full again"
        );
        assert_eq!(log.lock_safe().tracked_len(), 1, "the rolled-over window starts clean");
    }

    /// #506: the KA park TTL is env-driven and DEFAULTS to the unchanged 30 s — the
    /// long-park flip must be an explicit operator decision gated on the client
    /// fleet carrying the [`KA_TICK_CONTRACT_MIN_AGENT`] tick-based wait contract (an older client's 45 s
    /// exchange bound would fire before a long park's EX). Garbage/zero stays safe.
    /// #575: the operator-facing floor and the code's floor are the same number.
    ///
    /// The floor lived as a hand-copied version in three places and all three named
    /// **v0.4.19, a release that was never cut** — so an operator checking their fleet
    /// against the runbook got an unanswerable question, and the safety argument for
    /// raising `CT_EDGE_KA_PARK_TTL_SECS` rested on nothing.
    ///
    /// Two assertions, both about things that actually drift: the runbook is where the
    /// operator reads the floor, so it must state the constant; and the dead version must
    /// be gone from the repo entirely, since a stale copy elsewhere is what produced this.
    #[test]
    fn the_runbook_states_the_same_ka_fleet_floor_as_the_code_575() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("crates/edge -> repo root");
        let runbook = std::fs::read_to_string(root.join("docs/ops/runbook.md"))
            .expect("the runbook is the operator-facing half of this contract");
        let claims: Vec<&str> = runbook
            .lines()
            .filter(|l| l.contains("ct-agent \u{2265} v"))
            .collect();
        assert!(
            !claims.is_empty(),
            "the runbook states no ct-agent version floor at all -- either the wording \
             changed or the guidance was lost; both leave the operator without the number"
        );
        for line in &claims {
            assert!(
                line.contains(KA_TICK_CONTRACT_MIN_AGENT),
                "the runbook states a ct-agent floor that is not {KA_TICK_CONTRACT_MIN_AGENT}: \
                 {line}"
            );
        }

        // Assembled, never spelled out: a test that searches for a literal cannot carry
        // that literal in its own source, or it reports itself on every run.
        const DEAD: &str = concat!("v0.4.", "19");
        // The specific defect: a floor pointing at a release that does not exist. Searched
        // across the whole repo because it was copied, and a copy left behind is the exact
        // mechanism that made three sites agree on a wrong number.
        let mut walk = vec![root.to_path_buf()];
        let mut scanned = 0usize;
        while let Some(dir) = walk.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for e in entries.flatten() {
                let p = e.path();
                let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
                if p.is_dir() {
                    // `.git` carries every OLD revision of these files; failing on history
                    // nobody can edit would make this test impossible to satisfy. `.claude`
                    // holds agent worktrees -- scratch checkouts of arbitrary older commits,
                    // found carrying exactly this stale copy on the first run of this test.
                    if !matches!(name, "target" | ".git" | ".claude" | "node_modules") {
                        walk.push(p);
                    }
                    continue;
                }
                if !matches!(
                    p.extension().and_then(|s| s.to_str()),
                    Some("rs") | Some("md") | Some("sh") | Some("yml")
                ) {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&p) else { continue };
                scanned += 1;
                for (i, line) in text.lines().enumerate() {
                    // The one line that documents the dead version ON PURPOSE, as the
                    // finding itself, says so on the same line -- deliberately, so this
                    // exemption cannot silently widen to cover a genuine stale copy.
                    if line.contains("never cut") {
                        continue;
                    }
                    assert!(
                        !line.contains(DEAD),
                        "{}:{} still names {DEAD}, a ct-agent release that was never cut: \
                         {line}",
                        p.display(),
                        i + 1
                    );
                }
            }
        }
        assert!(
            scanned >= 50,
            "only {scanned} files scanned -- the walk broke, so finding no stale copy \
             proves nothing"
        );
    }

    #[test]
    fn ka_park_ttl_defaults_to_the_short_ttl_and_parses_the_env_506() {
        assert_eq!(ka_park_ttl_secs_from(None), CHANNEL_PARK_TTL_SECS, "unset: unchanged");
        assert_eq!(ka_park_ttl_secs_from(Some("900")), 900, "explicit long TTL");
        assert_eq!(ka_park_ttl_secs_from(Some(" 60 ")), 60, "trimmed");
        assert_eq!(ka_park_ttl_secs_from(Some("0")), CHANNEL_PARK_TTL_SECS, "zero is not a TTL");
        assert_eq!(ka_park_ttl_secs_from(Some("abc")), CHANNEL_PARK_TTL_SECS, "garbage falls back");
    }

    /// #505: stale DEAD TCP-fallback parks (an edge-flap leftover: agents fall back,
    /// park, then recover to QUIC — the dead parks linger) must not brick delivery.
    /// The old code took the first park and errored terminally when it was dead
    /// ("vanished before delivery"), bricking the hostname for every browser until a
    /// human re-ran the demo script. Delivery now DRAINS dead parks and lands on the
    /// first live one.
    #[tokio::test]
    async fn delivery_drains_dead_tcp_parks_and_reaches_the_live_one_505() {
        use tokio::io::AsyncWriteExt;
        let state = Arc::new(EdgeState::<Connection>::new());
        let token = RoutingToken([0x55; 32]);
        let _ = state.register_host("drain.test", token.clone());

        // Two dead parks (receivers dropped -- the flap leftovers), then a live one.
        drop(state.park_tcp_agent(token.clone()));
        drop(state.park_tcp_agent(token.clone()));
        let live_rx = state.park_tcp_agent(token.clone());

        let (mut browser, edge_end) = tokio::io::duplex(8192);
        let hello = crate::sni::synth_client_hello(Some("drain.test"), &[]);
        browser.write_all(&hello).await.unwrap();

        let st = state.clone();
        let serve = tokio::spawn(async move { serve_sni_passthrough(edge_end, &st).await });

        // The LIVE park receives the browser stream -- the two dead parks were
        // drained on the way instead of erroring the request.
        let delivered = tokio::time::timeout(std::time::Duration::from_secs(5), live_rx)
            .await
            .expect("delivery must not hang")
            .expect("the live park receives the stream (dead parks drained, #505)");
        drop(delivered);
        drop(browser);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), serve).await;
        assert!(
            !state.has_tcp_agent(&token),
            "all parked slots consumed: two dead drained + one live delivered"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn mesh_relay_lookup_cached_suppresses_repeat_cp_calls_within_the_ttl_471() {
        // #471: a flood of unrouted-SNI connections for the SAME hostname used to drive
        // one authenticated control-plane request each -- real proof this is now capped
        // to one CP call per hostname per TTL window, via a real mock CP counting hits.
        use axum::extract::Query;
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        use axum::routing::get;
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let hits = Arc::new(AtomicUsize::new(0));
        let hits2 = hits.clone();
        let app = axum::Router::new().route(
            "/internal/edges/lookup",
            get(move |Query(_q): Query<HashMap<String, String>>| {
                let hits = hits2.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::NOT_FOUND, "no owner recorded").into_response()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let mesh = MeshRelayConfig {
            cp_url: format!("http://{addr}"),
            admin_token: [0u8; 32],
            edge_cert: rustls::pki_types::CertificateDer::from(vec![]),
            negative_cache: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        };

        assert_eq!(mesh_relay_lookup_cached(&mesh, "evil.example").await, None);
        assert_eq!(hits.load(Ordering::SeqCst), 1, "the real first lookup hits the CP");

        // A flood of repeats for the SAME hostname, still within the TTL: must not hit
        // the CP again at all.
        for _ in 0..20 {
            assert_eq!(mesh_relay_lookup_cached(&mesh, "evil.example").await, None);
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1, "20 repeats within the TTL cost zero extra CP calls");

        // A DIFFERENT hostname is tracked independently -- the cache doesn't over-suppress.
        assert_eq!(mesh_relay_lookup_cached(&mesh, "other.example").await, None);
        assert_eq!(hits.load(Ordering::SeqCst), 2, "an unrelated hostname's own lookup is unaffected");

        // Past the TTL, the same hostname is allowed to hit the CP again.
        tokio::time::advance(MESH_RELAY_NEGATIVE_CACHE_TTL + Duration::from_secs(1)).await;
        assert_eq!(mesh_relay_lookup_cached(&mesh, "evil.example").await, None);
        assert_eq!(hits.load(Ordering::SeqCst), 3, "past the TTL, a fresh lookup is allowed through");
    }

    #[test]
    fn front_door_cert_gap_flags_every_configured_but_unusable_tls_vhost() {
        // #142 (frozen): a front-door vhost is only asked for a cert when it's configured for TLS
        // termination, so any missing/empty material must be REPORTED (→ a loud warning), never a
        // silent plaintext raw-proxy downgrade. Only a full cert+key pair returns None (build it).
        let c = "CT_EDGE_PORTAL_CERT";
        let k = "CT_EDGE_PORTAL_KEY";
        // Both present -> no gap (a build attempt follows).
        assert_eq!(front_door_cert_gap(Some("/certs/fullchain.pem"), Some("/certs/privkey.pem"), c, k), None);
        // The #142 trap: cert/key unset or empty -> a reported gap naming the offending var(s).
        assert!(front_door_cert_gap(None, None, c, k).unwrap().contains(c));
        assert!(front_door_cert_gap(None, None, c, k).unwrap().contains(k));
        assert!(front_door_cert_gap(Some(""), Some(""), c, k).is_some(), "empty strings are a gap");
        assert!(front_door_cert_gap(Some("   "), Some("x"), c, k).unwrap().contains(c), "whitespace cert is a gap");
        // Partial config (one half missing) is a gap naming the missing half.
        assert_eq!(front_door_cert_gap(Some("/c"), None, c, k), Some(format!("{k} unset/empty")));
        assert_eq!(front_door_cert_gap(None, Some("/k"), c, k), Some(format!("{c} unset/empty")));
    }

    #[test]
    fn token_hex_matches_the_first_4_bytes_lowercase_hex_342() {
        // #342: the stack-buffer rewrite must produce byte-identical output to
        // the old `.iter().take(4).map(|b| format!("{b:02x}")).collect()` --
        // real correctness proof, not just "it compiles and doesn't allocate".
        let token = RoutingToken({
            let mut b = [0u8; 32];
            b[0] = 0xde;
            b[1] = 0x0a;
            b[2] = 0xff;
            b[3] = 0x01;
            b[4] = 0xff; // must NOT appear -- only the first 4 bytes are hex-encoded
            b
        });
        let mut buf = [0u8; 8];
        assert_eq!(token_hex(&token, &mut buf), "de0aff01");

        // All-zero token -> all-zero hex, not e.g. an empty string or a panic.
        let zero = RoutingToken([0u8; 32]);
        let mut buf2 = [0u8; 8];
        assert_eq!(token_hex(&zero, &mut buf2), "00000000");
    }

    #[test]
    fn safe_peer_edge_target_rejects_private_and_internal_ranges() {
        // #253: peer_addr comes from the control plane's ownership registry, not from anything
        // this edge itself controls -- a compromised CP or rogue registered edge must not be able
        // to make this edge dial its own loopback/LAN/cloud-metadata surface.
        for bad in [
            "127.0.0.1:22",
            "0.0.0.0:80",
            "224.0.0.1:80",
            "10.0.0.5:22",
            "172.16.0.1:22",
            "192.168.1.1:22",
            "169.254.169.254:80", // cloud metadata
            "100.64.0.1:22",      // CGNAT
            "[::1]:22",
            "[fe80::1]:22",
            "[fc00::1]:22",
            "not-an-address",
            "",
        ] {
            assert!(safe_peer_edge_target(bad).is_none(), "{bad} must be rejected");
        }
        for ok in ["203.0.113.10:7001", "8.8.8.8:443", "[2001:4860:4860::8888]:443"] {
            assert!(safe_peer_edge_target(ok).is_some(), "{ok} must be admitted");
        }
    }

    #[test]
    fn channel_relay_addr_refuses_to_collide_with_the_rendezvous_port() {
        // #103 (frozen): the relay endpoint must be DISTINCT from the rendezvous — two accept
        // loops on one port silently break pairing (each member parks in a separate pairer).
        use std::net::SocketAddr;
        let chan: SocketAddr = "0.0.0.0:4435".parse().unwrap();

        // Default (unset / empty) -> chan_port + 1, distinct.
        assert_eq!(
            resolve_channel_relay_addr(chan, None),
            Ok("0.0.0.0:4436".parse().unwrap()),
            "default relay is the rendezvous port + 1"
        );
        assert_eq!(resolve_channel_relay_addr(chan, Some("")), Ok("0.0.0.0:4436".parse().unwrap()));

        // A distinct, valid override is honoured.
        assert_eq!(
            resolve_channel_relay_addr(chan, Some("0.0.0.0:9444")),
            Ok("0.0.0.0:9444".parse().unwrap()),
            "a distinct override is used as-is"
        );

        // An override EQUAL to the rendezvous is refused (the #103 collision).
        assert!(
            resolve_channel_relay_addr(chan, Some("0.0.0.0:4435")).is_err(),
            "a relay override colliding with the rendezvous port is refused"
        );

        // An unparseable override falls back to the distinct default (not an error).
        assert_eq!(
            resolve_channel_relay_addr(chan, Some("not-an-addr")),
            Ok("0.0.0.0:4436".parse().unwrap()),
            "an unparseable override falls back to the default port+1"
        );

        // Edge case: at port 65535 the `+1` default saturates back onto the rendezvous -> refused.
        let hi: SocketAddr = "0.0.0.0:65535".parse().unwrap();
        assert!(
            resolve_channel_relay_addr(hi, None).is_err(),
            "the port+1 default saturating onto the rendezvous port is refused, not silently bound"
        );
    }

    #[tokio::test]
    async fn front_door_pairer_reaper_evicts_a_lone_member_past_its_deadline() {
        // #256: the QUIC broker's own accept loop sweeps `drain_expired` on every iteration,
        // but the `:443` front door has no equivalent per-accept sweep point, so a lone parked
        // member with no partner was held forever. `spawn_front_door_pairer_reaper` is the fix
        // — prove it actually evicts on a real (injected, fast) clock, not just that the wiring
        // compiles. `T = u8` here: the pairer itself doesn't care what a member's payload is
        // (see `WaitingMember`'s own doc comment — "opaque to the pairer"), so a real TLS
        // stream isn't needed to exercise the reaper's sweep-and-evict behavior.
        use crate::channel_broker::{ChannelPairer, WaitingMember};
        use ct_common::channel::ChannelId;

        let pairer: Arc<std::sync::Mutex<ChannelPairer<u8>>> =
            Arc::new(std::sync::Mutex::new(ChannelPairer::new()));
        // #530: every reap must also raise the process-wide counter behind
        // ct_edge_channel_park_reaped_total. Delta-based because other tests may
        // increment it concurrently.
        let reaped_before = crate::channel_broker::channel_park_reaped_total();

        // Park one lone member whose deadline is already in the past relative to the fake
        // clock's first tick — it has no partner, so it must be reaped, not held forever.
        pairer.lock().unwrap().offer(WaitingMember {
            channel: ChannelId([7u8; 32]),
            holder: [1u8; 32],
            observed: None,
            deadline: 100,
            liveness: crate::channel_broker::ParkLiveness::default(),
            phase: crate::channel_broker::ParkPhase::Unmarked,
            payload: 0u8,
        });
        assert_eq!(pairer.lock().unwrap().len(), 1, "parked before the reaper ticks");

        // A fake clock that reports far past the deadline from its very first read, ticking
        // the reaper at a real (but tiny) interval instead of the production 10s cadence.
        let now: Arc<std::sync::atomic::AtomicU64> = Arc::new(std::sync::atomic::AtomicU64::new(1_000));
        let now_reader = now.clone();
        spawn_front_door_pairer_reaper(
            pairer.clone(),
            Duration::from_millis(5),
            move || now_reader.load(std::sync::atomic::Ordering::SeqCst),
            |m| drop(m),
        );

        // Give the spawned task a handful of real ticks to run — generous relative to the 5ms
        // interval, but nowhere near the real CHANNEL_PARK_TTL_SECS this replaces waiting for.
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(
            pairer.lock().unwrap().len(),
            0,
            "the reaper must have evicted the expired lone member by now"
        );
        assert!(
            crate::channel_broker::channel_park_reaped_total() >= reaped_before + 1,
            "#530: the reap must raise ct_edge_channel_park_reaped_total"
        );
    }

    /// #576: the fail-closed policy is APPLIED, not merely computed.
    ///
    /// Its sibling below has always proved `host_auth_required` answers correctly, and it kept
    /// passing while the answer was unreachable: startup only consulted it inside the
    /// `CT_EDGE_ADMIN_TOKEN` block, so a front door without that token left `host_auth` at
    /// `None` — the state in which `EdgeState::host_bind_allowed` returns `true` for every
    /// token. The cell that used to be wrong is the third one, and it is the whole point.
    #[test]
    fn the_fail_closed_host_auth_default_does_not_depend_on_the_admin_token_576() {
        assert_eq!(
            host_auth_startup_decision(None, true, true),
            HostAuthDecision::Required { orphaned: false },
            "front door + admin token: enforce, nothing unusual to report"
        );
        assert_eq!(
            host_auth_startup_decision(None, false, true),
            HostAuthDecision::Open { warn: false },
            "no front door: no enforcement and nothing to warn about"
        );
        assert_eq!(
            host_auth_startup_decision(None, true, false),
            HostAuthDecision::Required { orphaned: true },
            "front door WITHOUT the admin token: still enforce -- this is the cell that used \
             to fall through to a silently open door -- and say that nothing can authorize a \
             host, so the refusals that follow read as configuration, not as an outage"
        );
        assert_eq!(
            host_auth_startup_decision(Some("0"), true, false),
            HostAuthDecision::Open { warn: true },
            "an explicit opt-out stays possible, and stays loud"
        );
    }

    #[test]
    fn host_auth_fail_closes_under_a_front_door_by_default() {
        // #84: explicit setting wins in both directions.
        assert!(host_auth_required(Some("1"), false), "explicit truthy -> on");
        assert!(host_auth_required(Some("true"), false), "explicit true -> on");
        assert!(!host_auth_required(Some("0"), true), "explicit 0 -> off even with a front door");
        assert!(!host_auth_required(Some("false"), true), "explicit false -> off");
        assert!(!host_auth_required(Some(""), true), "explicit empty -> off");
        // Unset: fail-closed only when a public front door is exposed.
        assert!(
            host_auth_required(None, true),
            "unset + CT_FRONT_DOOR -> ON (no unbound-hostname squatting on :443)"
        );
        assert!(
            !host_auth_required(None, false),
            "unset + mesh-only (:4433, no front door) -> OFF (zero-config unaffected)"
        );
    }

    #[test]
    fn flood_limits_are_on_by_default_but_tunable_and_disable_able() {
        // #95: a public edge must ship protected. Unset -> the safe default (ON);
        // a positive value overrides; an explicit 0/off/false/none disables; an
        // unparseable value fails safe to the default (a typo never opens the gate).
        assert_eq!(resolve_flood_limit(None, 600), Some(600), "unset -> on by default");
        assert_eq!(resolve_flood_limit(Some("250"), 600), Some(250), "positive value overrides");
        assert_eq!(resolve_flood_limit(Some("  0 "), 600), None, "0 disables");
        assert_eq!(resolve_flood_limit(Some("off"), 600), None, "off disables");
        assert_eq!(resolve_flood_limit(Some("False"), 600), None, "false disables (case-insensitive)");
        assert_eq!(resolve_flood_limit(Some("none"), 600), None, "none disables");
        assert_eq!(resolve_flood_limit(Some("garbage"), 600), Some(600), "unparseable -> safe default, not off");
        assert_eq!(resolve_flood_limit(Some("-5"), 600), Some(600), "negative -> safe default, not off");
    }

    #[tokio::test(start_paused = true)]
    async fn front_door_drops_a_stalled_client_hello_after_the_timeout() {
        // #111 Slowloris: a client sends a valid TLS record header claiming a full-size
        // (16384-byte) record, then stalls forever — no body, never closes. The bounded
        // front-door read must return the timeout error rather than hanging indefinitely
        // (which, with #119's ConnectionCap, would otherwise pin the cap permit). With the
        // clock paused, tokio auto-advances virtual time to the deadline, so this is
        // deterministic and fast.
        let (mut client, mut edge) = tokio::io::duplex(64);
        // TLS handshake record header: type=0x16, version 0x0303, length=0x4000 (16384).
        client.write_all(&[0x16, 0x03, 0x03, 0x40, 0x00]).await.unwrap();
        client.flush().await.unwrap();

        let start = tokio::time::Instant::now();
        let res = read_client_hello_bytes_bounded(&mut edge).await;
        let elapsed = start.elapsed();

        assert!(res.is_err(), "a stalled ClientHello must be dropped, got Ok");
        assert!(
            elapsed >= CLIENT_HELLO_READ_TIMEOUT,
            "must wait for the read timeout before dropping, elapsed {elapsed:?}"
        );
        // Keep the stalling client end alive until after the read resolves, so the read
        // times out rather than seeing an EOF.
        drop(client);
    }

    #[tokio::test]
    async fn whoami_echoes_the_callers_real_quic_observed_address() {
        // #248/#238: 'W' is the stateless reflexive-address echo a DCUtR-punching
        // channel member queries to learn its GENUINE UDP-observed address,
        // instead of blindly reusing one observed over the :443 TCP relay-gate
        // admission (a different NAT mapping). No token, no admission gate --
        // proves the response matches the connection's own real remote_address(),
        // and that it works with no prior 'A'/'C' handshake on this connection.
        let state: Arc<EdgeState<Connection>> = Arc::new(EdgeState::new());
        let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let state_srv = state.clone();
        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let result = serve_connection(&conn, &state_srv, &challenge).await;
            assert!(result.is_ok(), "'W' is not an 'A' registration -> Ok(None)");
            // Wait for the client to finish reading + close, rather than dropping
            // `conn` (and tearing down the QUIC connection) the instant this
            // function returns -- the response bytes are already on the wire, but
            // an immediate drop can race the client's read of them.
            conn.closed().await;
        });

        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"W").await.unwrap();
        send.finish().unwrap();
        let mut len = [0u8; 1];
        recv.read_exact(&mut len).await.unwrap();
        let mut buf = vec![0u8; len[0] as usize];
        recv.read_exact(&mut buf).await.unwrap();
        let reported: std::net::SocketAddr = std::str::from_utf8(&buf).unwrap().parse().unwrap();

        // The server observed the client connecting from 127.0.0.1:<ephemeral port> --
        // the exact loopback-address family this in-process test actually dials from.
        assert_eq!(reported.ip(), std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        conn.close(0u32.into(), b"done");
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn agent_registers_and_becomes_known() {
        let token = RoutingToken([5u8; 32]);
        let state: Arc<EdgeState<Connection>> = Arc::new(EdgeState::new());

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let state_srv = state.clone();
        let token_srv = token.clone();
        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let registered = register_agent(&conn, &state_srv)
                .await
                .map_err(|e| e.to_string())?;
            assert_eq!(registered, token_srv);
            conn.closed().await;
            Ok::<(), String>(())
        });

        let client = build_client_endpoint(cert).expect("client");
        let conn = client
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("conn");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let mut msg = vec![b'A'];
        msg.extend_from_slice(&token.0);
        send.write_all(&msg).await.unwrap();
        send.finish().unwrap();
        let ack = recv.read_to_end(8).await.unwrap();
        assert_eq!(ack, b"OK");

        // The Edge registers before acking, so by the time we read OK the tunnel
        // is routable in the shared state.
        assert!(state.is_known(&token), "agent tunnel is now routable");
        // And its Edge-observed peer candidate is recorded (M11.2).
        assert!(
            state.candidate(&token).is_some(),
            "agent peer candidate recorded at registration"
        );
        conn.close(0u32.into(), b"done");
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn agent_registers_and_binds_hostname_over_one_connection() {
        // #40: an Agent opens 'A' (register) then a SEPARATE 'H' (bind hostname)
        // on the same connection. The edge must accept BOTH so route_host resolves
        // — the Browser-Plane demo failed because only the first stream was served.
        let token = RoutingToken([9u8; 32]);
        let state: Arc<EdgeState<Connection>> = Arc::new(EdgeState::new());

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let state_srv = state.clone();
        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
            let _ = serve_agent_connection(&conn, &state_srv, &challenge).await;
        });

        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");

        // 'A' — register the tunnel.
        let (mut s, mut r) = conn.open_bi().await.unwrap();
        let mut a = vec![b'A'];
        a.extend_from_slice(&token.0);
        s.write_all(&a).await.unwrap();
        s.finish().unwrap();
        assert_eq!(r.read_to_end(8).await.unwrap(), b"OK", "register acked");

        // 'H' — bind the public hostname on a SECOND stream.
        let host = "help.bunsenbrenner.org";
        let (mut s, mut r) = conn.open_bi().await.unwrap();
        let mut h = vec![b'H'];
        h.extend_from_slice(&token.0);
        h.extend_from_slice(&(host.len() as u16).to_be_bytes());
        h.extend_from_slice(host.as_bytes());
        s.write_all(&h).await.unwrap();
        s.finish().unwrap();
        assert_eq!(r.read_to_end(8).await.unwrap(), b"OK", "hostname bind acked (was never accepted before)");

        // The hostname now routes to the tunnel — the #40 fix.
        assert_eq!(state.route_host(host), Some(token.clone()), "SNI now routes to the agent");
        assert!(state.is_known(&token));

        conn.close(0u32.into(), b"done");
        let _ = server_task.await;
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_fallback_admission_times_out_on_a_stalled_role_a_registration_258() {
        // #258: a client that completes the TLS handshake, sends the 'A' role byte,
        // then stalls forever (never sends its 32-byte token) must not hold the
        // ConnectionCap permit indefinitely -- the admission read needs its own
        // deadline, same discipline as #111's ClientHello timeout for the :443 path.
        // Paused clock -> tokio auto-advances virtual time, so this is deterministic
        // and fast despite the real 10s TCP_FALLBACK_ADMISSION_TIMEOUT.
        let state: Arc<EdgeState<Connection>> = Arc::new(EdgeState::new());
        let (edge_side, mut attacker_side) = tokio::io::duplex(64);
        let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };

        let server_task = tokio::spawn(async move {
            let start = tokio::time::Instant::now();
            let res = serve_tcp_connection(edge_side, &state, &challenge, None).await;
            (res, start.elapsed())
        });

        // Send only the role byte, then stall -- never send the token.
        attacker_side.write_all(b"A").await.unwrap();
        attacker_side.flush().await.unwrap();

        let (res, elapsed) = server_task.await.unwrap();
        assert!(res.is_err(), "a stalled 'A' registration must be dropped, got Ok");
        assert!(
            elapsed >= TCP_FALLBACK_ADMISSION_TIMEOUT,
            "must wait for the admission timeout before dropping, elapsed {elapsed:?}"
        );
        // Keep the stalling attacker end alive until after the read resolves, so the
        // read times out rather than seeing an EOF (same discipline as the front-door
        // ClientHello timeout test above).
        drop(attacker_side);
    }

    #[tokio::test]
    async fn tcp_fallback_browser_register_binds_hostname() {
        // #41 FB1: 'B' over the TLS-TCP fallback registers the tunnel AND binds the
        // hostname in ONE message (a single stream can't carry a separate 'H').
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let token = RoutingToken([0x2b; 32]);
        let state: Arc<EdgeState<Connection>> = Arc::new(EdgeState::new());
        let (edge_side, mut agent_side) = tokio::io::duplex(4096);
        let state_srv = state.clone();
        tokio::spawn(async move {
            let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
            let _ = serve_tcp_connection(edge_side, &state_srv, &challenge, None).await;
        });

        let host = "help.bunsenbrenner.org";
        let mut msg = vec![b'B'];
        msg.extend_from_slice(&token.0);
        msg.extend_from_slice(&(host.len() as u16).to_be_bytes());
        msg.extend_from_slice(host.as_bytes());
        agent_side.write_all(&msg).await.unwrap();
        agent_side.flush().await.unwrap();

        let mut ack = [0u8; 2];
        agent_side.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack, b"OK", "browser register acked over TCP");
        assert_eq!(
            state.route_host(host),
            Some(token),
            "hostname routes over the TCP fallback (was impossible before)"
        );
    }

    #[tokio::test]
    async fn mesh_relay_reaches_a_hostname_owned_by_a_peer_edge() {
        // ADR-0021 Part 1: a Client lands on edge A, which has no local route
        // for `host` -- edge A discovers (out of band here; in production via
        // the control plane's GET /internal/edges/lookup) that edge B owns it,
        // dials edge B over the 'M' mesh-relay role, and the Client's bytes
        // reach the Agent parked on edge B. Two independent `EdgeState`s and
        // two independent real TCP+TLS listeners -- not one process's
        // in-memory state -- the bar `edge_mesh.rs`'s own doc comment sets.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let admin_token = [0x42u8; 32];
        let host = "app.example.test";

        // Edge B: owns `host`, has a real Agent parked (TCP-fallback 'B' role).
        let (listener_b, acceptor_b, cert_b) =
            crate::transport::build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
        let addr_b = listener_b.local_addr().unwrap();
        let state_b: Arc<EdgeState<Connection>> = Arc::new(EdgeState::new());
        state_b.set_admin_token(admin_token);
        let state_b2 = state_b.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = match listener_b.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                let acceptor = acceptor_b.clone();
                let state = state_b2.clone();
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
                        let _ = serve_tcp_connection(tls, &state, &challenge, None).await;
                    }
                });
            }
        });

        // The Agent: registers + binds `host` on edge B directly, then echoes
        // one request as "world" (standing in for a real origin round-trip).
        let agent_task = tokio::spawn({
            let cert_b = cert_b.clone();
            async move {
                let mut stream = crate::transport::tcp_tls_connect(addr_b, cert_b).await.unwrap();
                let token = RoutingToken([0x77; 32]);
                let mut msg = vec![b'B'];
                msg.extend_from_slice(&token.0);
                msg.extend_from_slice(&(host.len() as u16).to_be_bytes());
                msg.extend_from_slice(host.as_bytes());
                stream.write_all(&msg).await.unwrap();
                stream.flush().await.unwrap();
                let mut ack = [0u8; 2];
                stream.read_exact(&mut ack).await.unwrap();
                assert_eq!(&ack, b"OK", "agent registers directly on edge B");
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"hello", "agent sees the Client's bytes via the mesh relay");
                stream.write_all(b"world").await.unwrap();
                stream.flush().await.unwrap();
            }
        });

        // Edge A: a completely separate EdgeState -- genuinely has no local route.
        let state_a: Arc<EdgeState<Connection>> = Arc::new(EdgeState::new());
        assert!(state_a.route_host(host).is_none(), "edge A has no local route for host");

        // Wait for the Agent to actually be parked on edge B before relaying,
        // avoiding a race where the Client's bytes arrive before it's ready.
        for _ in 0..200 {
            if state_b.route_host(host).is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(state_b.route_host(host).is_some(), "agent is registered on edge B");

        let (mut client_side, edge_a_inbound) = tokio::io::duplex(4096);
        let host_owned = host.to_string();
        let relay_task = tokio::spawn(async move {
            relay_via_peer_edge(edge_a_inbound, addr_b, &host_owned, cert_b, admin_token).await
        });

        client_side.write_all(b"hello").await.unwrap();
        client_side.flush().await.unwrap();
        let mut resp = [0u8; 1024];
        let n = client_side.read(&mut resp).await.unwrap();
        assert_eq!(&resp[..n], b"world", "Client's bytes reached the Agent on edge B via edge A's mesh relay");

        drop(client_side);
        agent_task.await.unwrap();
        let _ = relay_task.await;
    }

    #[tokio::test]
    async fn mesh_relay_is_rejected_with_the_wrong_admin_token() {
        // The 'M' role's authorization: a mesh-relay attempt presenting the
        // WRONG shared admin token must be refused, not silently relayed.
        let (listener_b, acceptor_b, cert_b) =
            crate::transport::build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
        let addr_b = listener_b.local_addr().unwrap();
        let state_b: Arc<EdgeState<Connection>> = Arc::new(EdgeState::new());
        state_b.set_admin_token([0x42u8; 32]);
        let host = "app.example.test";
        let _ = state_b.register_host(host, RoutingToken([0x77; 32]));
        tokio::spawn(async move {
            let (tcp, _) = listener_b.accept().await.unwrap();
            if let Ok(tls) = acceptor_b.accept(tcp).await {
                let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
                let _ = serve_tcp_connection(tls, &state_b, &challenge, None).await;
            }
        });

        let (_client_side, edge_a_inbound) = tokio::io::duplex(4096);
        let wrong_token = [0x99u8; 32]; // != the [0x42; 32] edge B is configured with
        let result = relay_via_peer_edge(edge_a_inbound, addr_b, host, cert_b, wrong_token).await;
        assert!(result.is_err(), "wrong admin token must be refused, not relayed");
    }

    #[tokio::test]
    async fn mesh_relay_dial_times_out_against_a_peer_that_never_speaks_tls_549() {
        // #549: a peer edge that accepts the TCP connection and then never completes the
        // TLS handshake must not hold the browser connection (and its `browser_tunnel_cap`
        // sub-permit) forever. Deliberately a PLAIN listener, not a TLS one: it accepts and
        // stays silent, which is exactly the half-open state that used to hang here.
        let (_l, _a, cert) =
            crate::transport::build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(); // borrowed only for a well-formed root cert
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = silent.local_addr().unwrap();
        tokio::spawn(async move {
            // Accept and hold: never send a ServerHello, never close.
            let held = silent.accept().await;
            std::future::pending::<()>().await;
            drop(held);
        });

        let (_client_side, edge_a_inbound) = tokio::io::duplex(4096);
        let start = tokio::time::Instant::now();
        let res = relay_via_peer_edge(edge_a_inbound, addr, "app.example.test", cert, [0x42u8; 32]).await;
        let err = res.expect_err("a peer edge that never completes TLS must not hang the caller");
        assert!(
            err.to_string().contains("did not complete the dial+TLS handshake"),
            "the error must name the DIAL stage so an operator reads 'unreachable', not \
             'not answering': {err}"
        );
        assert!(
            start.elapsed() >= MESH_RELAY_DIAL_TIMEOUT && start.elapsed() < Duration::from_secs(30),
            "must fail at the dial bound (~{MESH_RELAY_DIAL_TIMEOUT:?}), not hang: {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn mesh_relay_ack_times_out_against_a_peer_that_never_acknowledges_549() {
        // #549, second wait: this peer edge is fully reachable -- real TLS, reads the whole
        // 'M' frame -- and then simply never answers. Distinct from the dial case above and
        // from the wrong-token case (which gets a definitive refusal); silence is the one
        // failure that used to be unbounded.
        use tokio::io::AsyncReadExt;

        let (listener_b, acceptor_b, cert_b) =
            crate::transport::build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
        let addr_b = listener_b.local_addr().unwrap();
        tokio::spawn(async move {
            let (tcp, _) = listener_b.accept().await.unwrap();
            if let Ok(mut tls) = acceptor_b.accept(tcp).await {
                // Consume the 'M' frame so the failure is provably the MISSING ACK and not
                // an unread socket, then go silent without closing.
                let mut sink = [0u8; 64];
                let _ = tls.read(&mut sink).await;
                std::future::pending::<()>().await;
            }
        });

        let (_client_side, edge_a_inbound) = tokio::io::duplex(4096);
        let start = tokio::time::Instant::now();
        let res =
            relay_via_peer_edge(edge_a_inbound, addr_b, "app.example.test", cert_b, [0x42u8; 32]).await;
        let err = res.expect_err("a peer edge that never acknowledges must not hang the caller");
        assert!(
            err.to_string().contains("sent no acknowledgement"),
            "the error must name the ACK stage so an operator reads 'reachable but not serving \
             the role', not 'unreachable': {err}"
        );
        assert!(
            start.elapsed() >= MESH_RELAY_ACK_TIMEOUT && start.elapsed() < Duration::from_secs(30),
            "must fail at the ACK bound (~{MESH_RELAY_ACK_TIMEOUT:?}), not hang: {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn registration_is_evicted_when_the_agent_connection_drops() {
        // issue #2 (mode a): after an Agent registers over QUIC and its
        // connection drops, the Edge must evict the registration so a later
        // Client `route()` returns None (fail fast) rather than resolving to a
        // dead Connection. Drives the real `serve_connection` 'A' path.
        let token = RoutingToken([7u8; 32]);
        let state: Arc<EdgeState<Connection>> = Arc::new(EdgeState::new());

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let state_srv = state.clone();
        let edge = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let challenge = Challenge {
                nonce: [0u8; 16],
                difficulty: 0,
            };
            // Mirror run_edge: serve, then on close evict the returned registration.
            let registered = serve_connection(&conn, &state_srv, &challenge).await;
            assert!(
                matches!(&registered, Ok(Some(_))),
                "'A' registration returns its (token, id) for eviction"
            );
            conn.closed().await;
            if let Ok(Some((token, reg))) = registered {
                state_srv.remove_registration(&token, reg);
            }
        });

        let client = build_client_endpoint(cert).expect("client");
        let conn = client
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("conn");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let mut msg = vec![b'A'];
        msg.extend_from_slice(&token.0);
        send.write_all(&msg).await.unwrap();
        send.finish().unwrap();
        let ack = recv.read_to_end(8).await.unwrap();
        assert_eq!(ack, b"OK");
        assert!(state.route(&token).is_some(), "routable while the agent is alive");

        // The agent drops — the edge must evict within a bounded window.
        conn.close(0u32.into(), b"gone");
        drop(client);
        let evicted = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while state.route(&token).is_some() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(evicted.is_ok(), "dead registration evicted after the connection dropped");
        assert!(state.candidate(&token).is_none(), "candidate evicted too");
        edge.abort();
    }

    #[tokio::test]
    async fn registration_is_evicted_when_a_killed_agent_goes_idle() {
        // issue #8 (failover regression): the test above covers a *graceful*
        // drop (`conn.close` sends a QUIC CLOSE frame → `conn.closed()` fires at
        // once). A *killed* agent sends NO close frame, so eviction can only fire
        // on the Edge server's idle timeout. Without an Edge-side
        // `max_idle_timeout` the dead registration lingers (~30s peer-negotiated),
        // clients keep routing to the corpse, and redundancy failover never
        // engages — which is exactly what `redundancy-smoke.sh` caught. This pins
        // the mechanism the production fix adds (`edge_server_transport`): build a
        // server with a short idle timeout, register an agent, then let its
        // connection go SILENT (no keepalive, no close — the kill analogue) and
        // assert the idle timeout tears it down so `run_edge`'s eviction runs.
        use quinn::{Endpoint, IdleTimeout, TransportConfig};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::net::Ipv4Addr;

        let token = RoutingToken([11u8; 32]);
        let state: Arc<EdgeState<Connection>> = Arc::new(EdgeState::new());

        // Edge server with a 1s idle timeout (fast analogue of the production
        // ~10s) and NO keepalive — so a silent peer idles out within the test
        // window instead of being kept warm.
        crate::transport::install_crypto_provider();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = certified.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.key_pair.serialize_der(),
        ));
        let mut server_config =
            quinn::ServerConfig::with_single_cert(vec![cert.clone()], key).unwrap();
        let mut t = TransportConfig::default();
        t.max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(1)).unwrap()));
        server_config.transport_config(Arc::new(t));
        let server =
            Endpoint::server(server_config, (Ipv4Addr::LOCALHOST, 0).into()).expect("server");
        let addr = server.local_addr().expect("addr");

        let state_srv = state.clone();
        let edge = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
            // Mirror run_edge exactly: serve, await close, evict on drop.
            let registered = serve_connection(&conn, &state_srv, &challenge).await;
            conn.closed().await;
            if let Ok(Some((token, reg))) = registered {
                state_srv.remove_registration(&token, reg);
            }
        });

        let client = build_client_endpoint(cert).expect("client");
        let conn = client
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("conn");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let mut msg = vec![b'A'];
        msg.extend_from_slice(&token.0);
        send.write_all(&msg).await.unwrap();
        send.finish().unwrap();
        let ack = recv.read_to_end(8).await.unwrap();
        assert_eq!(ack, b"OK");
        assert!(state.route(&token).is_some(), "routable while the agent is alive");

        // The agent goes SILENT — no close frame, no keepalive (the kill case).
        // The Edge's idle timeout must tear the connection down so eviction runs
        // well before the old ~30s peer-negotiated timeout. Hold `conn`/`client`
        // (do NOT drop them, which would send a close) so only the idle path can
        // trigger eviction.
        let evicted = tokio::time::timeout(Duration::from_secs(5), async {
            while state.route(&token).is_some() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            evicted.is_ok(),
            "a killed (silent) agent is evicted via the edge idle timeout"
        );
        drop(conn);
        drop(client);
        edge.abort();
    }

    #[tokio::test]
    async fn open_agent_stream_distinguishes_missing_from_unresponsive() {
        // issue #2 (mode b): the Client can't tell "no registration" from "live
        // agent that never yields a relay stream" — both look like "no relay".
        // The Edge must: (1) return the missing-registration error for an unknown
        // token, and (2) time out with a distinct "unresponsive" verdict when a
        // registered, still-connected agent grants no bidi-stream credit (so the
        // Edge's open_bi() never completes) — instead of hanging until the Client
        // gives up.
        use quinn::{Endpoint, TransportConfig};
        use std::net::Ipv4Addr;

        let state: Arc<EdgeState<Connection>> = Arc::new(EdgeState::new());

        // (1) Unknown token → immediate missing-registration error.
        let miss = open_agent_stream_with(&state, &RoutingToken([9u8; 32]), Duration::from_millis(300))
            .await
            .unwrap_err()
            .to_string();
        assert!(miss.contains("no agent tunnel"), "unknown token: {miss}");

        // (2) A live agent that grants the Edge zero bidi streams.
        let token = RoutingToken([8u8; 32]);
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().unwrap();
        let state_srv = state.clone();
        let edge = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
            let _ = serve_connection(&conn, &state_srv, &challenge).await;
        });

        // Starved client: allows the peer (edge) to open 0 bidi streams toward it.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
        ));
        let mut tc = TransportConfig::default();
        tc.max_concurrent_bidi_streams(0u32.into());
        cfg.transport_config(Arc::new(tc));
        let mut client = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        client.set_default_client_config(cfg);

        let conn = client.connect(addr, "localhost").unwrap().await.unwrap();
        // Registration is a client-initiated stream, so it succeeds despite the 0
        // peer-bidi limit; the agent then stays connected.
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let mut msg = vec![b'A'];
        msg.extend_from_slice(&token.0);
        send.write_all(&msg).await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(8).await.unwrap(), b"OK");
        assert!(state.route(&token).is_some(), "registered and live");

        // The Edge tries to open a relay stream: it can't (0 credit) and must time
        // out with the distinct unresponsive verdict, not hang.
        let err = open_agent_stream_with(&state, &token, Duration::from_millis(300))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("unresponsive"), "live-but-starved agent: {err}");

        conn.close(0u32.into(), b"done");
        edge.abort();
    }

    #[tokio::test]
    async fn relay_fails_over_from_a_dead_agent_to_a_live_one() {
        // #8 R2: two agents serve one token; the most-recent one can't open a
        // relay stream (0 bidi-stream credit = effectively dead), so
        // open_agent_stream must fail over to the surviving agent instead of
        // returning "no relay".
        use quinn::{Endpoint, TransportConfig};
        use std::net::Ipv4Addr;

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().unwrap();
        let state: Arc<EdgeState<Connection>> = Arc::new(EdgeState::new());
        let token = RoutingToken([5u8; 32]);

        // Healthy agent (default bidi credit) connects first → registered older.
        let healthy_ep = build_client_endpoint(cert.clone()).unwrap();
        let h_task =
            tokio::spawn(async move { healthy_ep.connect(addr, "localhost").unwrap().await.unwrap() });
        let srv_healthy = server.accept().await.unwrap().await.unwrap();
        let _h_client = h_task.await.unwrap();
        state.register(token.clone(), srv_healthy);

        // Starved agent (0 bidi credit) connects second → registered most-recent.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
        ));
        let mut tc = TransportConfig::default();
        tc.max_concurrent_bidi_streams(0u32.into());
        cfg.transport_config(Arc::new(tc));
        let mut starved_ep = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        starved_ep.set_default_client_config(cfg);
        let s_task =
            tokio::spawn(async move { starved_ep.connect(addr, "localhost").unwrap().await.unwrap() });
        let srv_starved = server.accept().await.unwrap().await.unwrap();
        let _s_client = s_task.await.unwrap();
        state.register(token.clone(), srv_starved);

        assert_eq!(state.registration_count(&token), 2, "two redundant agents");

        // Tries the starved (most-recent) agent first → times out → fails over to
        // the healthy one and returns a stream.
        let r = open_agent_stream_with(&state, &token, Duration::from_millis(300)).await;
        assert!(r.is_ok(), "failed over to the surviving agent: {:?}", r.err());
    }

    /// #554 drift guard: a NEW tunnel-carrying relay call site must not silently skip the
    /// revocation check.
    ///
    /// This is the failure mode that produced the finding in the first place and that has
    /// recurred all session: a protection gets added on one path, and the next call site
    /// written next to it quietly does not get it. Behaviour tests cover the two paths
    /// that exist today; this one covers the path somebody adds tomorrow.
    #[test]
    fn every_token_carrying_relay_goes_through_the_revocation_guard_554() {
        let src = include_str!("serve.rs");
        // Only production code -- test modules legitimately call `relay` directly to stand
        // in for an agent or origin.
        let prod = src.split("\n#[cfg(test)]\n").next().unwrap();

        // Statement-shaped, not line-shaped, and by relay FUNCTION rather than by call form.
        // The first version enumerated `let (… = relay(&mut` / `= framed_relay(&mut`, and
        // missed the QUIC data plane twice over: `relay_quic` was not in the list, and its
        // call is split across two lines so no line-shaped pattern could match it. That is
        // the one relay a ct-client's own traffic takes, and it went unguarded while this
        // test read as "every token-carrying relay is covered".
        //
        // Now: join continuations, split on `;`, and require the guard in the same statement
        // as any relay-family call. A new relay function is caught by being a call at all.
        let flat = prod.replace('\n', " ");
        let unguarded: Vec<String> = flat
            .split(';')
            .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|s| {
                ["relay(", "framed_relay(", "relay_quic("]
                    .iter()
                    .any(|f| s.contains(&format!(" {f}")) || s.contains(&format!("={f}")) || s.contains(&format!("= {f}")))
            })
            .filter(|s| !s.contains("until_revoked") && !s.contains("#554-exempt"))
            .collect();

        assert!(
            unguarded.is_empty(),
            "these relay call sites bypass `until_revoked`, so a revocation would not cut \
             sessions on their transport while it does on every other one -- wrap them or, \
             if the traffic genuinely is not token-routed (e.g. the mesh leg, which the peer \
             edge revokes itself), say so at the call site: {unguarded:#?}"
        );
    }

    /// #554 on a SECOND transport family: the TCP-fallback client leg. The first test
    /// covers the QUIC data plane; this one exists because "the call site now mentions
    /// `until_revoked`" is a textual claim, not a behavioural one — the wiring has to be
    /// shown to actually cut bytes on a path that reaches the relay through a completely
    /// different arm (`serve_tcp_connection`'s 'C' rendezvous, agent leg over QUIC).
    #[tokio::test]
    async fn revocation_cuts_a_live_tcp_fallback_relay_too_554() {
        use crate::transport::{
            build_client_endpoint, build_server_endpoint_with_cert, build_tcp_tls_listener_at,
            tcp_tls_connect,
        };
        use ct_common::pow::build_request;
        use std::net::Ipv4Addr;

        let token = RoutingToken([0x67; 32]);
        let challenge = Challenge { nonce: [0x44; 16], difficulty: 8 };
        let state = Arc::new(EdgeState::<Connection>::new());

        let (server, qcert) = build_server_endpoint_with_cert().expect("quic edge");
        let qaddr = server.local_addr().unwrap();
        let (tcp_listener, acceptor, tcert) =
            build_tcp_tls_listener_at((Ipv4Addr::LOCALHOST, 0).into()).await.expect("tcp edge");
        let taddr = tcp_listener.local_addr().unwrap();

        let state_q = state.clone();
        tokio::spawn(async move {
            let agent_conn = server.accept().await.unwrap().await.unwrap();
            register_agent(&agent_conn, &state_q).await.unwrap();
            agent_conn.closed().await;
        });

        let agent_ep = build_client_endpoint(qcert).expect("agent ep");
        let aconn = agent_ep.connect(qaddr, "localhost").unwrap().await.unwrap();
        let (mut rs, mut rr) = aconn.open_bi().await.unwrap();
        rs.write_all(b"A").await.unwrap();
        rs.write_all(&token.0).await.unwrap();
        rs.finish().unwrap();
        assert_eq!(rr.read_to_end(8).await.unwrap(), b"OK");

        // Agent echoes twice, so a surviving relay would visibly deliver the second chunk.
        tokio::spawn(async move {
            let (mut s, mut r) = aconn.accept_bi().await.unwrap();
            for _ in 0..2 {
                let mut buf = [0u8; 3];
                if r.read_exact(&mut buf).await.is_err() {
                    break;
                }
                if s.write_all(&buf).await.is_err() {
                    break;
                }
            }
            aconn.closed().await;
        });

        let state_t = state.clone();
        let chal_t = challenge.clone();
        tokio::spawn(async move {
            let (tcp, _) = tcp_listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let _ = serve_tcp_connection(tls, &state_t, &chal_t, None).await;
        });

        let mut client = tcp_tls_connect(taddr, tcert).await.expect("tcp connect");
        client.write_all(b"C").await.unwrap();
        let mut chal = [0u8; 17];
        client.read_exact(&mut chal).await.unwrap();
        let ch = Challenge { nonce: chal[..16].try_into().unwrap(), difficulty: chal[16] };
        client.write_all(&build_request(&ch, &token).unwrap()).await.unwrap();

        client.write_all(b"one").await.unwrap();
        client.flush().await.unwrap();
        let mut echo = [0u8; 3];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"one", "the relay is live before the revocation");

        state.revoke_token(&token);
        tokio::time::sleep(Duration::from_millis(300)).await;

        let _ = client.write_all(b"two").await;
        let _ = client.flush().await;
        let mut echo2 = [0u8; 3];
        let got = tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut echo2)).await;
        let delivered = matches!(&got, Ok(Ok(_)) if &echo2 == b"two");
        assert!(
            !delivered,
            "the TCP-fallback leg kept relaying after revocation -- the guard is wired on the \
             QUIC path only, which is the half-coverage this test exists to prevent"
        );
    }

    #[tokio::test]
    async fn edge_relays_tcp_fallback_client_to_quic_agent() {
        // M12.2b: a Client on the TCP fallback ('C' + PoW over TLS-TCP) is
        // relayed to a QUIC-registered Agent (cross-transport relay).
        use crate::transport::{
            build_client_endpoint, build_server_endpoint_with_cert, build_tcp_tls_listener_at,
            tcp_tls_connect,
        };
        use ct_common::pow::build_request;
        use std::net::Ipv4Addr;

        let token = RoutingToken([0x66; 32]);
        let challenge = Challenge {
            nonce: [0x44; 16],
            difficulty: 8,
        };
        let state = Arc::new(EdgeState::<Connection>::new());

        // QUIC edge (for the Agent) + TLS-TCP listener (for the fallback Client).
        let (server, qcert) = build_server_endpoint_with_cert().expect("quic edge");
        let qaddr = server.local_addr().unwrap();
        let (tcp_listener, acceptor, tcert) =
            build_tcp_tls_listener_at((Ipv4Addr::LOCALHOST, 0).into()).await.expect("tcp edge");
        let taddr = tcp_listener.local_addr().unwrap();

        // QUIC edge: register the Agent, keep the connection alive.
        let state_q = state.clone();
        let quic_edge = tokio::spawn(async move {
            let agent_conn = server.accept().await.unwrap().await.unwrap();
            register_agent(&agent_conn, &state_q).await.map_err(|e| e.to_string())?;
            agent_conn.closed().await;
            Ok::<(), String>(())
        });

        // Agent: QUIC connect, register, echo the relayed stream (fixed 15 bytes).
        let agent_ep = build_client_endpoint(qcert).expect("agent ep");
        let aconn = agent_ep.connect(qaddr, "localhost").unwrap().await.unwrap();
        let (mut rs, mut rr) = aconn.open_bi().await.unwrap();
        rs.write_all(b"A").await.unwrap();
        rs.write_all(&token.0).await.unwrap();
        rs.finish().unwrap();
        assert_eq!(rr.read_to_end(8).await.unwrap(), b"OK");
        let agent = tokio::spawn(async move {
            let (mut s, mut r) = aconn.accept_bi().await.unwrap();
            let mut buf = [0u8; 15];
            r.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
            s.finish().unwrap();
            aconn.closed().await;
        });

        // TLS-TCP edge: serve one fallback client.
        let state_t = state.clone();
        let chal_t = challenge.clone();
        let tcp_edge = tokio::spawn(async move {
            let (tcp, _) = tcp_listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let _ = serve_tcp_connection(tls, &state_t, &chal_t, None).await;
        });

        // Client over TLS-TCP: 'C' rendezvous + 15 bytes, read the 15-byte echo.
        let mut client = tcp_tls_connect(taddr, tcert).await.expect("tcp connect");
        client.write_all(b"C").await.unwrap();
        let mut chal = [0u8; 17];
        client.read_exact(&mut chal).await.unwrap();
        let ch = Challenge {
            nonce: chal[..16].try_into().unwrap(),
            difficulty: chal[16],
        };
        client.write_all(&build_request(&ch, &token).unwrap()).await.unwrap();
        client.write_all(b"tcp-tunnel-data").await.unwrap();
        client.flush().await.unwrap();
        let mut got = [0u8; 15];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"tcp-tunnel-data", "TCP fallback client relayed to the QUIC agent");

        // #534: pin WHICH kind this fallthrough books. The issue proposed
        // flipping it to `browser` on the theory that the labels were inverted;
        // they are not -- this Client reached the edge over the :4433 TLS-TCP
        // fallback and only the AGENT leg is QUIC, so one leg really did run
        // over the fallback transport, which is what `RelayKind` partitions on.
        // `browser` would be doubly wrong: role 'C' is the ct-client rendezvous,
        // never a browser. (The real bug was the PARKED-agent success path
        // booking nothing at all -- see the two `..._books_its_bytes_as_
        // tcp_fallback_534` tests.)
        client.shutdown().await.unwrap(); // close_notify -> the relay returns Ok
        tcp_edge.await.unwrap();
        let payload = 2 * b"tcp-tunnel-data".len() as u64;
        assert_eq!(
            state.relay_bytes_by_kind(),
            (0, 0, payload),
            "a Client on the :4433 fallback is tcp_fallback even when the agent leg is QUIC",
        );
        assert_eq!(state.relay_bytes_total(), payload, "the kinds partition the total");

        agent.await.unwrap();
        quic_edge.abort();
    }

    /// #554: revoking a token must cut a relay that is ALREADY flowing, not only stop new
    /// ones. `admin.rs` promises the edge "tears the tunnel down"; before this it dropped
    /// the registration and let the live splice carry on. Measured that way first: bytes
    /// written after `revoke_token` still reached the agent.
    ///
    /// A customer revokes because the tunnel is compromised, so the long-lived sessions
    /// are exactly the ones that matter.
    #[tokio::test]
    async fn revoking_a_token_cuts_a_relay_that_is_already_flowing_554() {
        let token = RoutingToken([0x5b; 32]);
        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");

        let state_e = state.clone();
        tokio::spawn(async move {
            let agent_conn = server.accept().await.unwrap().await.unwrap();
            register_agent(&agent_conn, &state_e).await.unwrap();
            let client_conn = server.accept().await.unwrap().await.unwrap();
            let (c_send, mut c_recv) = client_conn.accept_bi().await.unwrap();
            let mut tok = [0u8; 32];
            c_recv.read_exact(&mut tok).await.unwrap();
            let _ = route_and_relay(&state_e, &RoutingToken(tok), c_send, c_recv).await;
        });

        let agent_ep = build_client_endpoint(cert.clone()).expect("agent ep");
        let agent_conn = agent_ep.connect(addr, "localhost").unwrap().await.unwrap();
        let (mut reg_send, mut reg_recv) = agent_conn.open_bi().await.unwrap();
        let mut reg = vec![b'A'];
        reg.extend_from_slice(&token.0);
        reg_send.write_all(&reg).await.unwrap();
        reg_send.finish().unwrap();
        assert_eq!(reg_recv.read_to_end(8).await.unwrap(), b"OK");

        let agent_task = tokio::spawn(async move {
            let (_s, mut r) = agent_conn.accept_bi().await.unwrap();
            let mut first = [0u8; 6];
            r.read_exact(&mut first).await.unwrap();
            // Second read AFTER the revocation happens on the edge.
            let mut second = [0u8; 6];
            let got = tokio::time::timeout(Duration::from_secs(3), r.read_exact(&mut second)).await;
            (first, got.map(|res| res.map(|_| second)))
        });

        let client_ep = build_client_endpoint(cert).expect("client ep");
        let client_conn = client_ep.connect(addr, "localhost").unwrap().await.unwrap();
        let (mut c_send, _c_recv) = client_conn.open_bi().await.unwrap();
        let mut opening = Vec::new();
        opening.extend_from_slice(&token.0);
        opening.extend_from_slice(b"first!");
        c_send.write_all(&opening).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        // The customer revokes the tunnel while this stream is live.
        state.revoke_token(&token);
        assert!(state.is_revoked(&token), "revocation recorded");
        assert_eq!(state.registration_count(&token), 0, "registration dropped");

        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = c_send.write_all(b"after!").await;
        let (first, second) = agent_task.await.unwrap();
        assert_eq!(&first, b"first!", "the pre-revocation bytes arrive");

        let still_flowing = matches!(&second, Ok(Ok(b)) if b == b"after!");
        assert!(
            !still_flowing,
            "bytes written after revoke_token still reached the agent -- the live splice was \
             not cut, so revocation only stops NEW connections and every long-lived session \
             on a compromised tunnel keeps being served"
        );
    }

    /// #554, the other direction: the wake-up is a SHARED tick, so revoking some other
    /// customer's token wakes every live relay. Each must re-check its own token and go
    /// back to work. A guard that over-fires here would tear down healthy tunnels on every
    /// unrelated revocation — worse than the gap it closes.
    #[tokio::test]
    async fn revoking_a_different_token_leaves_this_relay_untouched_554() {
        let token = RoutingToken([0x5c; 32]);
        let unrelated = RoutingToken([0xee; 32]);
        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");

        let state_e = state.clone();
        tokio::spawn(async move {
            let agent_conn = server.accept().await.unwrap().await.unwrap();
            register_agent(&agent_conn, &state_e).await.unwrap();
            let client_conn = server.accept().await.unwrap().await.unwrap();
            let (c_send, mut c_recv) = client_conn.accept_bi().await.unwrap();
            let mut tok = [0u8; 32];
            c_recv.read_exact(&mut tok).await.unwrap();
            let _ = route_and_relay(&state_e, &RoutingToken(tok), c_send, c_recv).await;
        });

        let agent_ep = build_client_endpoint(cert.clone()).expect("agent ep");
        let agent_conn = agent_ep.connect(addr, "localhost").unwrap().await.unwrap();
        let (mut reg_send, mut reg_recv) = agent_conn.open_bi().await.unwrap();
        let mut reg = vec![b'A'];
        reg.extend_from_slice(&token.0);
        reg_send.write_all(&reg).await.unwrap();
        reg_send.finish().unwrap();
        assert_eq!(reg_recv.read_to_end(8).await.unwrap(), b"OK");

        let agent_task = tokio::spawn(async move {
            let (_s, mut r) = agent_conn.accept_bi().await.unwrap();
            let mut first = [0u8; 6];
            r.read_exact(&mut first).await.unwrap();
            let mut second = [0u8; 6];
            let got = tokio::time::timeout(Duration::from_secs(3), r.read_exact(&mut second)).await;
            got.map(|res| res.map(|_| second))
        });

        let client_ep = build_client_endpoint(cert).expect("client ep");
        let client_conn = client_ep.connect(addr, "localhost").unwrap().await.unwrap();
        let (mut c_send, _c_recv) = client_conn.open_bi().await.unwrap();
        let mut opening = Vec::new();
        opening.extend_from_slice(&token.0);
        opening.extend_from_slice(b"first!");
        c_send.write_all(&opening).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Somebody else's tunnel is revoked. Three times, so a single missed re-check
        // cannot pass by luck.
        for _ in 0..3 {
            state.revoke_token(&unrelated);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(state.is_revoked(&unrelated));
        assert!(!state.is_revoked(&token), "ours was never revoked");

        c_send.write_all(b"after!").await.unwrap();
        let second = agent_task.await.unwrap();
        assert!(
            matches!(&second, Ok(Ok(b)) if b == b"after!"),
            "an unrelated revocation must not disturb this relay, got {second:?}"
        );
    }

    #[tokio::test]
    async fn edge_routes_client_data_to_registered_agent() {
        let token = RoutingToken([5u8; 32]);
        let state = Arc::new(EdgeState::<Connection>::new());

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");

        // Edge orchestrator: register the Agent, then route the Client's stream.
        let state_e = state.clone();
        let edge = tokio::spawn(async move {
            let agent_conn = server.accept().await.unwrap().await.unwrap();
            register_agent(&agent_conn, &state_e)
                .await
                .map_err(|e| e.to_string())?;

            let client_conn = server.accept().await.unwrap().await.unwrap();
            let (c_send, mut c_recv) = client_conn.accept_bi().await.unwrap();
            let mut tok = [0u8; 32];
            c_recv.read_exact(&mut tok).await.unwrap();
            route_and_relay(&state_e, &RoutingToken(tok), c_send, c_recv)
                .await
                .map_err(|e| e.to_string())?;
            Ok::<(), String>(())
        });

        // Agent connects, registers, then reads the relayed stream.
        let agent_ep = build_client_endpoint(cert.clone()).expect("agent ep");
        let agent_conn = agent_ep
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("agent conn");
        let (mut reg_send, mut reg_recv) = agent_conn.open_bi().await.unwrap();
        let mut reg = vec![b'A'];
        reg.extend_from_slice(&token.0);
        reg_send.write_all(&reg).await.unwrap();
        reg_send.finish().unwrap();
        assert_eq!(reg_recv.read_to_end(8).await.unwrap(), b"OK");
        let agent_task = tokio::spawn(async move {
            let (_s, mut r) = agent_conn.accept_bi().await.unwrap();
            r.read_to_end(1024).await.unwrap()
        });

        // Client connects and sends token + data on one stream.
        let client_ep = build_client_endpoint(cert).expect("client ep");
        let client_conn = client_ep
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("client conn");
        let (mut c_send, _c_recv) = client_conn.open_bi().await.unwrap();
        let mut payload = Vec::new();
        payload.extend_from_slice(&token.0);
        payload.extend_from_slice(b"client-data");
        c_send.write_all(&payload).await.unwrap();
        c_send.finish().unwrap();

        let received = agent_task.await.unwrap();
        assert_eq!(
            received, b"client-data",
            "agent receives the client's data relayed by the edge"
        );
        drop(client_conn);
        edge.abort();
    }

    #[tokio::test]
    async fn quic_client_reaches_a_tcp_fallback_agent() {
        // #13: the mirror of edge_relays_tcp_fallback_client_to_quic_agent — a
        // QUIC client must reach a parked TCP-fallback agent. Before the fix,
        // serve_connection's 'C' arm ignored deliver_to_tcp_agent and the tunnel
        // died with `early eof`.
        use crate::transport::{
            build_client_endpoint, build_server_endpoint_with_cert, build_tcp_tls_listener_at,
            tcp_tls_connect,
        };
        use ct_common::pow::build_request;
        use std::net::Ipv4Addr;

        let token = RoutingToken([0x77; 32]);
        let challenge = Challenge {
            nonce: [0x55; 16],
            difficulty: 8,
        };
        let state = Arc::new(EdgeState::<Connection>::new());

        // QUIC edge (for the client) + TLS-TCP listener (for the fallback agent).
        let (server, qcert) = build_server_endpoint_with_cert().expect("quic edge");
        let qaddr = server.local_addr().unwrap();
        let (tcp_listener, acceptor, tcert) =
            build_tcp_tls_listener_at((Ipv4Addr::LOCALHOST, 0).into()).await.expect("tcp edge");
        let taddr = tcp_listener.local_addr().unwrap();

        // TLS-TCP edge: serve the fallback AGENT ('A' → park → relay).
        let state_t = state.clone();
        let chal_t = challenge.clone();
        let tcp_edge = tokio::spawn(async move {
            let (tcp, _) = tcp_listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let _ = serve_tcp_connection(tls, &state_t, &chal_t, None).await;
        });

        // Agent over TLS-TCP: register 'A', then echo the relayed client bytes.
        let agent = tokio::spawn(async move {
            let mut a = tcp_tls_connect(taddr, tcert).await.expect("agent tcp connect");
            a.write_all(b"A").await.unwrap();
            a.write_all(&token.0).await.unwrap();
            a.flush().await.unwrap();
            let mut ok = [0u8; 2];
            a.read_exact(&mut ok).await.unwrap();
            assert_eq!(&ok, b"OK");
            let mut buf = [0u8; 15];
            a.read_exact(&mut buf).await.unwrap();
            a.write_all(&buf).await.unwrap();
            a.flush().await.unwrap();
        });

        // Let the agent register + park before the client rendezvouses.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // QUIC edge: serve one client connection.
        let state_q = state.clone();
        let chal_q = challenge.clone();
        let quic_edge = tokio::spawn(async move {
            let client_conn = server.accept().await.unwrap().await.unwrap();
            let _ = serve_connection(&client_conn, &state_q, &chal_q).await;
            client_conn.closed().await;
        });

        // QUIC client: 'C' rendezvous + 15 bytes, read the 15-byte echo.
        let client_ep = build_client_endpoint(qcert).expect("client ep");
        let cconn = client_ep.connect(qaddr, "localhost").unwrap().await.unwrap();
        let (mut cs, mut cr) = cconn.open_bi().await.unwrap();
        cs.write_all(b"C").await.unwrap();
        let mut chal = [0u8; 17];
        cr.read_exact(&mut chal).await.unwrap();
        let ch = Challenge {
            nonce: chal[..16].try_into().unwrap(),
            difficulty: chal[16],
        };
        cs.write_all(&build_request(&ch, &token).unwrap()).await.unwrap();
        cs.write_all(b"quic-to-tcp-agt").await.unwrap();
        let mut got = [0u8; 15];
        cr.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"quic-to-tcp-agt", "QUIC client relayed to the TCP-fallback agent");

        agent.await.unwrap();
        quic_edge.abort();
        tcp_edge.abort();
    }

    #[tokio::test]
    async fn unknown_token_is_rejected_before_touching_the_rate_limiter() {
        // #472: the rendezvous rate limiter is keyed on the routing token a
        // Client supplies in its own PoW response, so before this fix it was
        // consulted BEFORE any known-token lookup -- a flooder rotating
        // random tokens got a fresh limiter budget and a fresh map entry on
        // every attempt, and the per-token cap never actually engaged
        // against that attack shape. Proves the fix: a token that resolves
        // to no registered Agent (QUIC or TCP-fallback) is rejected outright
        // and never occupies a limiter slot.
        use crate::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use ct_common::pow::build_request;

        let unknown_token = RoutingToken([0x99; 32]);
        let challenge = Challenge { nonce: [0x33; 16], difficulty: 8 };
        let state = Arc::new(EdgeState::<Connection>::new());
        // Effectively unlimited -- isolates the known-token gate from the
        // per-window cap itself; a limiter slot consumed by the unknown
        // token would still be observable via `rendezvous_tracked_keys`.
        state.set_rendezvous_limit(1_000_000);

        let (server, cert) = build_server_endpoint_with_cert().expect("quic edge");
        let addr = server.local_addr().unwrap();

        let state_q = state.clone();
        let chal_q = challenge.clone();
        let edge = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let result = serve_connection(&conn, &state_q, &chal_q).await;
            conn.close(0u32.into(), b"done");
            result
        });

        let client_ep = build_client_endpoint(cert).expect("client ep");
        let conn = client_ep.connect(addr, "localhost").unwrap().await.unwrap();
        let (mut cs, mut cr) = conn.open_bi().await.unwrap();
        cs.write_all(b"C").await.unwrap();
        let mut chal = [0u8; 17];
        cr.read_exact(&mut chal).await.unwrap();
        let ch = Challenge {
            nonce: chal[..16].try_into().unwrap(),
            difficulty: chal[16],
        };
        cs.write_all(&build_request(&ch, &unknown_token).unwrap())
            .await
            .unwrap();
        let _ = cs.finish();

        let result = edge.await.unwrap();
        assert!(result.is_err(), "an unresolvable routing token must be rejected");
        assert_eq!(
            state.rendezvous_tracked_keys(),
            0,
            "an unresolvable token must never occupy a rate-limiter slot (#472)"
        );
    }

    #[tokio::test]
    async fn tcp_agent_registers_and_relays_a_delivered_client() {
        // issue #3 / P1.2c-3b: an Agent registers over the TCP fallback ('A'),
        // parks, and the edge relays a delivered Client stream to it end to end.
        let state = Arc::new(EdgeState::<Connection>::new());
        let token = RoutingToken([0x55; 32]);
        let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };

        // Run the edge 'A' handler on the edge side of the agent duplex.
        let (mut agent_peer, agent_edge) = tokio::io::duplex(1024);
        let state_a = state.clone();
        let chal_a = challenge.clone();
        let edge = tokio::spawn(async move { serve_tcp_connection(agent_edge, &state_a, &chal_a, None).await });

        // Agent peer: register 'A' | token, read OK, then echo (origin-relay sim).
        let mut hdr = vec![b'A'];
        hdr.extend_from_slice(&token.0);
        agent_peer.write_all(&hdr).await.unwrap();
        let mut ok = [0u8; 2];
        agent_peer.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"OK", "edge acks the TCP registration");
        let echo = tokio::spawn(async move {
            let mut buf = [0u8; 5];
            agent_peer.read_exact(&mut buf).await.unwrap();
            agent_peer.write_all(&buf).await.unwrap();
            agent_peer.flush().await.unwrap();
        });

        // Once parked, deliver a Client stream (the 'C'/PoW path is tested
        // separately); the edge relays agent <-> client.
        while !state.has_tcp_agent(&token) {
            tokio::task::yield_now().await;
        }
        let (mut client_peer, client_edge) = tokio::io::duplex(1024);
        state
            .deliver_to_tcp_agent_draining(&token, Box::new(client_edge))
            .map_err(|_| "deliver failed")
            .unwrap();

        client_peer.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 5];
        client_peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello", "round-trip relayed through the TCP-registered agent");

        echo.await.unwrap();
        drop(client_peer);
        let _ = edge.await;
    }

    #[tokio::test]
    async fn tcp_fallback_role_a_sheds_once_the_tcp_agent_cap_is_full_410() {
        // #410: role 'A' must admit against the dedicated `tcp_agent_cap` sub-cap
        // BEFORE parking -- proven the same way #254's own sibling sub-cap is proven
        // (`front_door_sheds_a_browser_tunnel_connection_once_its_own_sub_cap_is_full_254`):
        // hold the sub-cap's only permit BEFORE the connection arrives, then confirm
        // `serve_tcp_connection` refuses (NO, prompt return) instead of queuing the
        // token into `tcp_agents` and parking forever.
        let state = Arc::new(EdgeState::<Connection>::new());
        let token = RoutingToken([0x41; 32]);
        let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };

        let cap = ConnectionCap::new(1);
        let _held = cap.try_admit().unwrap(); // the sub-cap's only permit is already taken

        let (mut attacker, edge_side) = tokio::io::duplex(64);
        let edge = tokio::spawn(async move {
            serve_tcp_connection(edge_side, &state, &challenge, Some(&cap)).await
        });

        let mut hdr = vec![b'A'];
        hdr.extend_from_slice(&token.0);
        attacker.write_all(&hdr).await.unwrap();
        attacker.flush().await.unwrap();

        let mut ack = [0u8; 2];
        attacker.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack, b"NO", "shed once the tcp-agent sub-cap is full, not parked forever");

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), edge)
            .await
            .expect("serve_tcp_connection returns promptly when shed by the sub-cap, it never blocks waiting on it")
            .unwrap();
        assert!(result.is_ok(), "a sub-cap shed is a clean close, not an error: {result:?}");
    }

    #[tokio::test]
    async fn tcp_fallback_role_a_still_parks_and_relays_when_the_tcp_agent_cap_has_room_410() {
        // #410 regression guard: the new `tcp_agent_cap` sub-cap must not break a
        // legitimate registration + delivery when it has room -- same shape as
        // `tcp_agent_registers_and_relays_a_delivered_client` above, just with the
        // cap configured, so a fresh/first-ever token (no pre-existing registration
        // record -- there IS none to check, see `tcp_agent_cap`'s doc) still parks
        // and relays exactly as before.
        let state = Arc::new(EdgeState::<Connection>::new());
        let token = RoutingToken([0x44; 32]);
        let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
        let cap = ConnectionCap::new(2);

        let (mut agent_peer, agent_edge) = tokio::io::duplex(1024);
        let state_a = state.clone();
        let cap_a = cap.clone();
        let edge = tokio::spawn(async move {
            serve_tcp_connection(agent_edge, &state_a, &challenge, Some(&cap_a)).await
        });

        let mut hdr = vec![b'A'];
        hdr.extend_from_slice(&token.0);
        agent_peer.write_all(&hdr).await.unwrap();
        let mut ok = [0u8; 2];
        agent_peer.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"OK", "a legitimate registration is still acked OK with the sub-cap configured");
        assert_eq!(cap.in_use(), 1, "the successful park holds exactly one tcp_agent_cap permit");

        let echo = tokio::spawn(async move {
            let mut buf = [0u8; 5];
            agent_peer.read_exact(&mut buf).await.unwrap();
            agent_peer.write_all(&buf).await.unwrap();
            agent_peer.flush().await.unwrap();
        });

        while !state.has_tcp_agent(&token) {
            tokio::task::yield_now().await;
        }
        let (mut client_peer, client_edge) = tokio::io::duplex(1024);
        state
            .deliver_to_tcp_agent_draining(&token, Box::new(client_edge))
            .map_err(|_| "deliver failed")
            .unwrap();

        client_peer.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 5];
        client_peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello", "round-trip relayed through the TCP-registered agent, cap configured");

        echo.await.unwrap();
        drop(client_peer);
        let _ = edge.await;
    }

    #[tokio::test]
    async fn tcp_fallback_flood_of_unauthenticated_role_a_registrations_never_exhausts_the_shared_conn_cap_410() {
        // #410 core regression: before this fix, ANY 32-byte value sent as role 'A'
        // parked forever holding the connection's OUTER, SHARED connection cap
        // permit -- the exact cap the QUIC loop / `:443` front door / `:80` redirect
        // all share (`DEFAULT_MAX_CONNECTIONS` in production, `conn_cap` in
        // `run_edge`). A flood of one-shot, never-delivered, garbage-token
        // registrations -- exactly the attack #410 describes ("8192 TLS connections
        // sending 33 bytes each, once") -- must now exhaust at most the dedicated
        // `tcp_agent_cap` sub-budget, leaving the shared cap mostly free for every
        // other listener. Mirrors the real accept loop's own permit-holding shape
        // (`let _permit = permit;` around the whole `serve_tcp_connection` call, see
        // `run_edge`'s TCP-fallback loop) plus the stress-test style of state.rs's
        // `revoke_and_register_race_never_leaves_a_revoked_token_registered_421`:
        // real concurrent tasks, not a single-threaded simulation.
        let state = Arc::new(EdgeState::<Connection>::new());
        let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };

        // Mirrors run_edge's real shape (one large shared conn_cap, one smaller
        // dedicated tcp_agent_cap), scaled down for a fast test.
        let conn_cap = ConnectionCap::new(50);
        let tcp_agent_cap = ConnectionCap::new(4);

        let mut attacker_streams = Vec::new();
        let mut tasks = Vec::new();
        for i in 0..20u8 {
            let (attacker_side, edge_side) = tokio::io::duplex(64);
            let state_i = state.clone();
            let chal_i = challenge.clone();
            let tcp_agent_cap_i = tcp_agent_cap.clone();
            // Mirror the REAL TCP-fallback accept loop exactly: acquire the shared
            // conn_cap permit BEFORE dispatching, hold it for `serve_tcp_connection`'s
            // whole call (`let _permit = permit;` in `run_edge`).
            let permit = conn_cap.try_admit().expect("conn_cap has room for every one of these");
            let task = tokio::spawn(async move {
                let _permit = permit;
                let _ = serve_tcp_connection(edge_side, &state_i, &chal_i, Some(&tcp_agent_cap_i)).await;
            });
            tasks.push(task);
            attacker_streams.push((i, attacker_side));
        }

        // Every "attacker" connection sends a DIFFERENT garbage 32-byte token and
        // never sends anything else, never reads its own ack, never delivers a
        // Client -- exactly issue #410's one-shot attack shape. Kept alive in
        // `_attackers` for the rest of the test: dropping a `DuplexStream` closes
        // it, and the edge side's own ack write would then fail (broken pipe) --
        // a real attacker keeps its TCP socket open exactly the same way.
        let mut _attackers = Vec::new();
        for (i, mut attacker) in attacker_streams {
            let mut hdr = vec![b'A'];
            hdr.extend_from_slice(&[i; 32]);
            attacker.write_all(&hdr).await.unwrap();
            attacker.flush().await.unwrap();
            _attackers.push(attacker);
        }

        // Let every task reach its steady state: the ones admitted by
        // tcp_agent_cap (at most its capacity, 4) park forever; the rest are shed
        // (NO, prompt return), releasing their conn_cap permit.
        for _ in 0..200 {
            if conn_cap.in_use() <= tcp_agent_cap.max() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        assert_eq!(
            tcp_agent_cap.in_use(),
            tcp_agent_cap.max(),
            "the flood saturates its OWN dedicated sub-cap (an accepted, bounded blast radius)"
        );
        assert!(
            conn_cap.in_use() <= tcp_agent_cap.max(),
            "the shared conn_cap must NOT be driven down by the flood beyond the sub-cap's own \
             bound (#410) -- got {} of {} in use, expected at most {}",
            conn_cap.in_use(),
            conn_cap.max(),
            tcp_agent_cap.max(),
        );
        assert!(
            conn_cap.available() >= conn_cap.max() - tcp_agent_cap.max(),
            "the shared conn_cap must stay overwhelmingly free for every OTHER listener \
             (Portal/auth/QUIC/:80-redirect) even under a sustained, 4x-over-sub-cap role-'A' \
             flood -- available {} of {}",
            conn_cap.available(),
            conn_cap.max(),
        );

        for task in tasks {
            task.abort();
        }
    }

    #[tokio::test]
    async fn a_second_concurrent_tcp_agent_registration_does_not_evict_the_first() {
        // #229 follow-up: `park_tcp_agent` used to be a HashMap::insert, so a
        // second 'A'/'B' registration for the SAME token silently evicted the
        // first (an abrupt close the superseded Agent misreported as a
        // connection failure) -- exactly what happens once an Agent pools
        // several concurrent registrations on purpose (a real browser page
        // load opens multiple parallel connections per origin; one parked
        // slot could only ever serve one). Now additive: both stay parked,
        // and two deliveries are each served by a DIFFERENT registration.
        let token = RoutingToken([0x99; 32]);
        let state: Arc<EdgeState<Connection>> = Arc::new(EdgeState::new());

        let first_rx = state.park_tcp_agent(token.clone());
        let second_rx = state.park_tcp_agent(token.clone());
        assert!(state.has_tcp_agent(&token), "at least one parked");

        let (a_client, a_edge) = tokio::io::duplex(64);
        let (b_client, b_edge) = tokio::io::duplex(64);
        state
            .deliver_to_tcp_agent_draining(&token, Box::new(a_edge))
            .map_err(|_| "first delivery failed")
            .unwrap();
        state
            .deliver_to_tcp_agent_draining(&token, Box::new(b_edge))
            .map_err(|_| "second delivery failed")
            .unwrap();
        assert!(!state.has_tcp_agent(&token), "both slots consumed, pool now empty");

        // The FIRST park's receiver got the FIRST delivered stream (FIFO), not
        // dropped/evicted by the second park -- prove each is independently
        // usable by relaying one byte each way through both simultaneously.
        let mut first_stream = first_rx.await.expect("first registration received a stream");
        let mut second_stream = second_rx.await.expect("second registration received a stream");
        let mut a_client = a_client;
        let mut b_client = b_client;
        a_client.write_all(b"A").await.unwrap();
        b_client.write_all(b"B").await.unwrap();
        let mut buf = [0u8; 1];
        first_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"A", "first registration got the first delivery");
        second_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"B", "second registration got the second delivery, not evicted");
    }

    // ---- ct-agent#15 follow-up: the ping-capable TCP-fallback role 'K' -------
    //
    // Context (see 5e3dd3c's commit message, which deliberately deferred this):
    // tightening TCP keepalive to 10s/10s cut sort.bunsenbrenner.org's parked
    // TCP-fallback flapping but did not eliminate it, because a keepalive probe
    // is a bare ACK-only segment that some enterprise firewalls/DPI/SASE
    // gateways do not count as "activity" for their own idle-timeout
    // bookkeeping -- only real payload traffic does. Role 'K' puts real payload
    // bytes on the otherwise-idle parked connection. The timing-dependent
    // tests below run on paused virtual time, so the real 8s cadence is
    // exercised end to end without any test actually sleeping 8 seconds.

    /// Build the well-formed PONG that a ping-capable Agent replies with,
    /// echoing the PING frame's counter bytes verbatim.
    fn pong_echoing(ping: &[u8; 9]) -> [u8; 9] {
        let mut pong = [0u8; 9];
        pong[0] = TCP_PONG_MAGIC;
        pong[1..9].copy_from_slice(&ping[1..9]);
        pong
    }

    #[test]
    fn the_ping_interval_stays_strictly_below_the_tcp_keepalive_interval() {
        // The whole point of TCP_PING_INTERVAL is that it fires BEFORE the
        // keepalive timer, so the connection's next activity is real payload
        // (which every middlebox counts) rather than an ACK-only keepalive
        // probe (which some do not). `apply_tcp_keepalive` (transport.rs) sets
        // both time and interval to 10s; if anyone ever raises the ping
        // interval to or past that, the design silently stops working -- the
        // keepalive would win the race and we would be back to the flapping
        // this whole change exists to fix. Guard it here rather than trusting
        // a doc comment.
        assert!(
            TCP_PING_INTERVAL < Duration::from_secs(10),
            "TCP_PING_INTERVAL ({TCP_PING_INTERVAL:?}) must stay strictly below the 10s \
             keepalive time/interval set by apply_tcp_keepalive, so real payload beats the \
             ACK-only probe to the wire"
        );
        assert!(
            TCP_PING_PONG_TIMEOUT < TCP_PING_INTERVAL,
            "one round trip ({TCP_PING_PONG_TIMEOUT:?}) must be bounded well inside one ping \
             period ({TCP_PING_INTERVAL:?}), so probes can never pile up on top of each other"
        );
        // #528: the framed relay phase's keepalive cadence (the codec's
        // KEEPALIVE_INTERVAL) reuses THIS measured park-phase interval by
        // contract. The coupling is textual (the codec crate cannot see this
        // private constant), so it is asserted here instead of trusted.
        assert_eq!(
            TCP_PING_INTERVAL,
            ct_common::fallback_framing::KEEPALIVE_INTERVAL,
            "the codec's KEEPALIVE_INTERVAL must stay in lockstep with the park phase's \
             TCP_PING_INTERVAL -- both are the same calibrated middlebox-survival cadence"
        );
    }

    #[test]
    fn the_ping_protocol_bytes_can_never_collide_with_a_role_byte_or_an_ack() {
        // The three ping-protocol bytes live in the 0xF0-0xFF range precisely
        // so they are outside ASCII: a role byte ('A'/'B'/'C'/'K'...) and the
        // 'OK'/'NO' ack are all ASCII, so no reader on either side can ever
        // confuse the two framings even though they share one TCP stream.
        for b in [TCP_PING_MAGIC, TCP_PONG_MAGIC, TCP_PING_STOP] {
            assert!(
                !b.is_ascii(),
                "ping-protocol byte {b:#04x} must stay out of ASCII so it cannot collide with a \
                 role byte or an OK/NO ack"
            );
        }
        assert_ne!(TCP_PING_MAGIC, TCP_PONG_MAGIC);
        assert_ne!(TCP_PING_MAGIC, TCP_PING_STOP);
        assert_ne!(TCP_PONG_MAGIC, TCP_PING_STOP);
    }

    #[tokio::test]
    async fn send_ping_and_await_pong_writes_a_9_byte_big_endian_frame_and_accepts_the_echo() {
        // Happy path + the exact wire format, asserted against hardcoded bytes
        // rather than against `to_be_bytes()` (which would just restate the
        // implementation): a ping-capable Agent in another repo has to parse
        // this, so the encoding is a real contract, not an internal detail.
        let (mut agent, mut edge) = tokio::io::duplex(64);

        let agent_task = tokio::spawn(async move {
            let mut ping = [0u8; 9];
            agent.read_exact(&mut ping).await.unwrap();
            agent.write_all(&pong_echoing(&ping)).await.unwrap();
            agent.flush().await.unwrap();
            ping
        });

        send_ping_and_await_pong(&mut edge, 0x0102_0304_0506_0708)
            .await
            .expect("a well-formed echoed PONG is a clean round trip");

        let ping = agent_task.await.unwrap();
        assert_eq!(ping[0], TCP_PING_MAGIC, "frame starts with the PING magic byte 0xF9");
        assert_eq!(
            &ping[1..9],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            "the 8 counter bytes are big-endian, most-significant byte first"
        );
    }

    #[tokio::test]
    async fn send_ping_and_await_pong_rejects_a_reply_carrying_the_wrong_magic_byte() {
        // A peer that answers with 9 bytes of something that is not a PONG is
        // not speaking this protocol at all -- treat it as a dead/garbage
        // connection rather than silently accepting whatever arrived, since
        // accepting it would leave those bytes to be misread later.
        let (mut agent, mut edge) = tokio::io::duplex(64);

        let agent_task = tokio::spawn(async move {
            let mut ping = [0u8; 9];
            agent.read_exact(&mut ping).await.unwrap();
            // Right length, wrong magic -- notably the PING magic itself, the
            // most plausible way a buggy Agent could get this wrong (reflecting
            // the frame verbatim instead of rewriting the first byte).
            let mut bad = pong_echoing(&ping);
            bad[0] = TCP_PING_MAGIC;
            agent.write_all(&bad).await.unwrap();
            agent.flush().await.unwrap();
            // Hold the stream open so this is unambiguously a magic-byte
            // rejection and not an EOF/timeout in disguise.
            std::future::pending::<()>().await;
        });

        let err = send_ping_and_await_pong(&mut edge, 0)
            .await
            .expect_err("a reply with a bad magic byte must be an error");
        assert!(
            err.to_string().contains("malformed PONG"),
            "the error names the real cause (bad magic), got: {err}"
        );
        agent_task.abort();
    }

    #[tokio::test]
    async fn send_ping_and_await_pong_accepts_a_well_formed_but_stale_counter_echo() {
        // Deliberate, documented behavior: the counter is NOT compared. A
        // well-formed PONG carrying a stale counter still proves the one thing
        // this frame exists to prove -- real payload bytes crossed the wire in
        // both directions, so every middlebox on the path saw genuine activity.
        // Enforcing an exact echo would turn a harmless crossing of an
        // in-flight probe with a new one into a spurious dead-connection
        // verdict, which is exactly the flapping we are trying to stop.
        let (mut agent, mut edge) = tokio::io::duplex(64);

        let agent_task = tokio::spawn(async move {
            let mut ping = [0u8; 9];
            agent.read_exact(&mut ping).await.unwrap();
            let mut stale = [0u8; 9];
            stale[0] = TCP_PONG_MAGIC;
            stale[1..9].copy_from_slice(&7u64.to_be_bytes()); // not the 4242 we sent
            agent.write_all(&stale).await.unwrap();
            agent.flush().await.unwrap();
        });

        send_ping_and_await_pong(&mut edge, 4242)
            .await
            .expect("a well-formed PONG with a stale counter is still a successful round trip");
        agent_task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn send_ping_and_await_pong_times_out_when_the_peer_never_replies() {
        // The middlebox-stall case: the connection is still open (no reset, no
        // EOF) but nothing ever comes back. Must be bounded by
        // TCP_PING_PONG_TIMEOUT rather than hanging the parked loop forever.
        let (mut agent, mut edge) = tokio::io::duplex(64);

        let agent_task = tokio::spawn(async move {
            let mut ping = [0u8; 9];
            agent.read_exact(&mut ping).await.unwrap();
            // Never reply, but keep the stream open (holding `agent` alive is
            // what makes this a stall rather than an EOF).
            std::future::pending::<()>().await;
        });

        let start = tokio::time::Instant::now();
        let err = send_ping_and_await_pong(&mut edge, 0)
            .await
            .expect_err("a never-answered PING must time out, not hang");
        let waited = start.elapsed();

        assert!(
            err.to_string().contains("timed out"),
            "the error names the timeout, got: {err}"
        );
        assert!(
            waited >= TCP_PING_PONG_TIMEOUT && waited < TCP_PING_PONG_TIMEOUT + Duration::from_secs(1),
            "the round trip is bounded by TCP_PING_PONG_TIMEOUT ({TCP_PING_PONG_TIMEOUT:?}), waited {waited:?}"
        );
        agent_task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn send_ping_and_await_pong_fails_fast_when_the_connection_is_already_dead() {
        // A genuinely dead connection (peer gone) must surface immediately as
        // an I/O error, NOT sit out the full timeout -- the parked loop's whole
        // value as a dead-connection signal depends on this being prompt.
        let (agent, mut edge) = tokio::io::duplex(64);
        drop(agent);

        let start = tokio::time::Instant::now();
        let err = send_ping_and_await_pong(&mut edge, 0)
            .await
            .expect_err("writing a PING into a dead connection must error");
        let waited = start.elapsed();

        assert!(
            !err.to_string().contains("timed out"),
            "a dead connection is an I/O error, not a timeout, got: {err}"
        );
        assert!(
            waited < TCP_PING_PONG_TIMEOUT,
            "a dead connection surfaces immediately ({waited:?}), it does not burn the full \
             {TCP_PING_PONG_TIMEOUT:?} timeout"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn park_and_ping_keeps_pinging_on_the_interval_cadence_while_no_client_arrives() {
        // The core behavior: an idle parked registration must keep generating
        // real payload traffic, forever, on the TCP_PING_INTERVAL cadence, with
        // a counter that advances each time.
        let (mut agent, edge_side) = tokio::io::duplex(64);
        // Held for the whole test: while this sender is alive the registration
        // is neither superseded nor delivered, i.e. genuinely parked and idle.
        let (_tx, rx) = tokio::sync::oneshot::channel::<crate::state::BoxedStream>();

        let start = tokio::time::Instant::now();
        let edge_task = tokio::spawn(async move {
            let mut edge = edge_side;
            park_and_ping(&mut edge, rx).await.map(|_| ())
        });

        let mut arrivals = Vec::new();
        let mut counters = Vec::new();
        for _ in 0..3 {
            let mut ping = [0u8; 9];
            agent.read_exact(&mut ping).await.unwrap();
            arrivals.push(start.elapsed());
            assert_eq!(ping[0], TCP_PING_MAGIC, "every parked-phase frame is a PING");
            counters.push(u64::from_be_bytes(ping[1..9].try_into().unwrap()));
            agent.write_all(&pong_echoing(&ping)).await.unwrap();
            agent.flush().await.unwrap();
        }

        assert_eq!(counters, vec![0, 1, 2], "the counter advances by one per probe");
        for (i, at) in arrivals.iter().enumerate() {
            let expected = TCP_PING_INTERVAL * (i as u32 + 1);
            let skew = if *at > expected { *at - expected } else { expected - *at };
            assert!(
                skew < Duration::from_millis(100),
                "ping #{i} must land one TCP_PING_INTERVAL after the previous one \
                 (expected ~{expected:?}, got {at:?})"
            );
        }

        edge_task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn park_and_ping_delivers_a_prompt_client_after_exactly_one_verify_ping() {
        // `biased` in the select! means an already-arrived Client always wins over
        // starting another cadence probe -- but verify-at-delivery (ct-agent#15
        // follow-up) still runs ONE final PING/PONG round trip before handing the
        // Client over, proving the parked agent is alive *now*, not "as of up to an
        // interval ago". Proven in the strongest available form: the Agent side is
        // read to EOF and must have received exactly that one 9-byte PING frame --
        // no cadence pings, no other bytes.
        let (mut agent, edge_side) = tokio::io::duplex(64);
        let (tx, rx) = tokio::sync::oneshot::channel::<crate::state::BoxedStream>();
        let (mut client_peer, client_edge) = tokio::io::duplex(64);

        let edge_task = tokio::spawn(async move {
            let mut edge = edge_side;
            let mut client = park_and_ping(&mut edge, rx)
                .await
                .expect("a promptly delivered Client is a successful park once the agent PONGs");
            // Prove the receiver handed back the REAL delivered stream, not
            // some other one, by writing through it.
            client.write_all(b"delivered").await.unwrap();
            client.flush().await.unwrap();
            // Closing the edge side gives the agent's read_to_end below an EOF.
            drop(edge);
        });

        tx.send(Box::new(client_edge) as crate::state::BoxedStream)
            .map_err(|_| "the parked receiver was already gone")
            .unwrap();

        // Agent: answer the single verify-at-delivery ping.
        let mut ping = [0u8; 9];
        agent.read_exact(&mut ping).await.unwrap();
        assert_eq!(ping[0], TCP_PING_MAGIC, "the delivery is preceded by one verify PING");
        let mut pong = [0u8; 9];
        pong[0] = TCP_PONG_MAGIC;
        pong[1..].copy_from_slice(&ping[1..]);
        agent.write_all(&pong).await.unwrap();
        agent.flush().await.unwrap();

        let mut via_client = [0u8; 9];
        client_peer.read_exact(&mut via_client).await.unwrap();
        assert_eq!(&via_client, b"delivered", "park_and_ping returned the delivered Client stream");

        edge_task.await.unwrap();

        let mut seen = Vec::new();
        agent.read_to_end(&mut seen).await.unwrap();
        assert!(
            seen.is_empty(),
            "a prompt Client is delivered after EXACTLY one verify ping -- the Agent additionally \
             saw {seen:02x?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn park_and_ping_propagates_a_dead_parked_connection_as_an_error() {
        // The dead-connection signal: when the parked Agent's connection has
        // actually died, the next probe must fail and surface as Err so the 'K'
        // arm tears the registration down instead of parking on a corpse.
        let (agent, edge_side) = tokio::io::duplex(64);
        drop(agent);
        let (_tx, rx) = tokio::sync::oneshot::channel::<crate::state::BoxedStream>();

        let mut edge = edge_side;
        let err = park_and_ping(&mut edge, rx)
            .await
            .err()
            .expect("a ping I/O failure on a dead parked connection must surface as Err");
        assert!(
            !err.to_string().contains("superseded"),
            "this is a ping/IO failure, not a superseded registration, got: {err}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn park_and_ping_reports_a_superseded_registration_distinctly_from_a_ping_failure() {
        // The other way a park ends without a Client (#229 follow-up): the
        // registration was superseded/dropped. Must be distinguishable from a
        // dead connection so the two are not conflated in diagnostics.
        let (_agent, edge_side) = tokio::io::duplex(64);
        let (tx, rx) = tokio::sync::oneshot::channel::<crate::state::BoxedStream>();
        drop(tx);

        let mut edge = edge_side;
        let err = park_and_ping(&mut edge, rx)
            .await
            .err()
            .expect("a dropped registration must surface as Err");
        assert!(
            err.to_string().contains("superseded"),
            "the error names the real cause (superseded/dropped registration), got: {err}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn park_and_ping_rescues_a_client_delivered_while_the_cadence_ping_then_fails_528_finding_7() {
        // #528 finding 7: a Client delivered into the oneshot DURING a cadence
        // round trip must not be lost if that ping then fails. Here the parked
        // agent is dead (it reads the PING but never PONGs, so the round trip
        // times out); a Client that arrives mid-round-trip must be RESCUED as
        // AgentDead{client} (the 'K'/'L' failover then hands it to the next parked
        // slot), never dropped as a terminal NoClient. Before the fix the cadence
        // arm returned NoClient on the ping failure and the delivered Client
        // vanished.
        let (mut agent, edge_side) = tokio::io::duplex(64);
        let (tx, rx) = tokio::sync::oneshot::channel::<crate::state::BoxedStream>();
        let (mut client_peer, client_edge) = tokio::io::duplex(64);

        let edge_task = tokio::spawn(async move {
            let mut edge = edge_side;
            park_and_ping(&mut edge, rx).await
        });

        // Auto-advanced paused time fires the first cadence ping; read it but do
        // NOT reply -- this is the dead-but-still-connected middlebox case.
        let mut ping = [0u8; 9];
        agent.read_exact(&mut ping).await.unwrap();
        assert_eq!(ping[0], TCP_PING_MAGIC, "the cadence probe was sent");

        // A Client is delivered while that ping is still awaiting its (never-coming) PONG.
        tx.send(Box::new(client_edge) as crate::state::BoxedStream)
            .map_err(|_| "the parked receiver was already gone")
            .unwrap();

        // The ping times out (dead agent); the outcome must carry the delivered
        // Client as AgentDead, not lose it as NoClient.
        let err = edge_task.await.unwrap().err().expect("a dead parked agent is an error");
        match err {
            ParkAndPingError::AgentDead { mut client, .. } => {
                client.write_all(b"rescued").await.unwrap();
                client.flush().await.unwrap();
                let mut got = [0u8; 7];
                client_peer.read_exact(&mut got).await.unwrap();
                assert_eq!(&got, b"rescued", "the rescued stream is the real delivered Client");
            }
            ParkAndPingError::NoClient(e) => {
                panic!("the in-flight Client was lost as NoClient instead of rescued: {e}")
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_fallback_role_k_failover_drains_a_dead_park_and_rescues_the_client_528_findings_8_9() {
        // #528 findings 8/9: the 'K' verify-at-delivery failover used the
        // NON-draining single-shot delivery -- if the next parked slot in the
        // FIFO was a corpse (dropped receiver), the attempt handed the stream
        // back and `let _ =` discarded it, losing the request even though a
        // LIVE park sat right behind the dead one. The failover must drain.
        let state = Arc::new(EdgeState::<Connection>::new());
        let token = RoutingToken([0x58; 32]);
        let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };

        // The 'K' agent registers and parks (FIFO slot A).
        let (mut agent_peer, agent_edge) = tokio::io::duplex(4096);
        let state_k = state.clone();
        let edge = tokio::spawn(async move {
            serve_tcp_connection(agent_edge, &state_k, &challenge, None).await
        });
        let mut hdr = vec![b'K'];
        hdr.extend_from_slice(&token.0);
        agent_peer.write_all(&hdr).await.unwrap();
        agent_peer.flush().await.unwrap();
        let mut ok = [0u8; 2];
        agent_peer.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"OK");

        // Behind it: a DEAD park (slot B -- receiver dropped, e.g. a crashed
        // worker) and then a LIVE one (slot C, the rescue target).
        drop(state.park_tcp_agent(token.clone()));
        let live_rx = state.park_tcp_agent(token.clone());

        // A Client is delivered; FIFO hands it to the 'K' slot (A) first.
        let (mut client_peer, client_edge) = tokio::io::duplex(4096);
        state
            .deliver_to_tcp_agent_draining(&token, Box::new(client_edge))
            .map_err(|_| "deliver failed")
            .unwrap();

        // The agent reads its PING but stays SILENT -- the round trip times out
        // (paused time auto-advances), so the delivery becomes AgentDead and the
        // failover must hand the Client onward. (Whether the Client landed before
        // the verify ping or mid-cadence-ping is interleaving-dependent and both
        // are correct: either path carries the rescued Client into the failover.)
        let mut ping = [0u8; 9];
        agent_peer.read_exact(&mut ping).await.unwrap();
        assert_eq!(ping[0], TCP_PING_MAGIC, "the delivery-verify probe was sent");

        // The failover DRAINS: dead slot B is consumed, live slot C receives the
        // rescued Client. Before the fix, nothing ever arrived here.
        let mut rescued = tokio::time::timeout(Duration::from_secs(60), live_rx)
            .await
            .expect("the failover must re-deliver promptly, not drop the client")
            .expect("the live park behind the corpse receives the rescued client");
        rescued.write_all(b"rescued").await.unwrap();
        rescued.flush().await.unwrap();
        let mut got = [0u8; 7];
        client_peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"rescued", "the rescued stream is the real delivered Client");

        drop(agent_peer);
        let _ = edge.await;
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_fallback_role_f_admits_and_pings_like_l_then_relays_framed_end_to_end_528() {
        // #528 (iii): the full 'F' lifecycle through the real
        // `serve_tcp_connection` dispatch, driven by EXACTLY the bytes
        // ct-agent's register_tunnel_stream_browser_with_role(b'F') sends:
        // `'F' | token(32) | host_len(2 BE) | host` -- the 'L'-shaped
        // Browser-Plane registration (integration-review I1: an earlier
        // 'K'-shaped reading of this frame never bound the hostname and let
        // the trailing host bytes poison the first PING round trip). After
        // the STOP sentinel the edge<->agent hop speaks the frame codec: raw
        // client bytes arrive as DATA frames, agent DATA is unframed toward
        // the client, an agent keepalive is ACKed and discarded -- never
        // leaked into the raw client stream.
        use ct_common::fallback_framing::{Frame, FrameReader, FrameWriter};

        let state = Arc::new(EdgeState::<Connection>::new());
        let token = RoutingToken([0x46; 32]); // 0x46 == b'F'
        let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };

        let (mut agent_peer, agent_edge) = tokio::io::duplex(1 << 16);
        let state_f = state.clone();
        let edge =
            tokio::spawn(async move { serve_tcp_connection(agent_edge, &state_f, &challenge, None).await });

        // Admission: identical wire to 'B'/'L' -- role, token, then the
        // length-prefixed hostname, OK out, hostname routable.
        let host = "framed.bunsenbrenner.org";
        let mut hdr = vec![b'F'];
        hdr.extend_from_slice(&token.0);
        hdr.extend_from_slice(&(host.len() as u16).to_be_bytes());
        hdr.extend_from_slice(host.as_bytes());
        agent_peer.write_all(&hdr).await.unwrap();
        agent_peer.flush().await.unwrap();
        let mut ok = [0u8; 2];
        agent_peer.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"OK", "'F' admission is byte-identical to 'B'/'L'");
        assert_eq!(
            state.route_host(host),
            Some(token.clone()),
            "the 'F' registration binds the hostname atomically, exactly like 'B'/'L'"
        );

        // One real park-phase PING/PONG round trip, exactly as 'K' -- framing
        // begins only AFTER the STOP sentinel, never during the park phase.
        let mut ping = [0u8; 9];
        agent_peer.read_exact(&mut ping).await.unwrap();
        assert_eq!(ping[0], TCP_PING_MAGIC, "the park phase still runs the raw PING keepalive");
        agent_peer.write_all(&pong_echoing(&ping)).await.unwrap();
        agent_peer.flush().await.unwrap();

        // A real Client arrives and is delivered to the parked 'F' agent.
        assert!(state.has_tcp_agent(&token), "the 'F' registration is parked and routable");
        let (mut client_peer, client_edge) = tokio::io::duplex(1 << 16);
        state
            .deliver_to_tcp_agent_draining(&token, Box::new(client_edge))
            .map_err(|_| "deliver failed")
            .unwrap();

        // Drain the ping phase until STOP (same contract as 'K': every pre-STOP
        // byte is a well-formed PING; a Client can straddle one round trip).
        loop {
            let mut lead = [0u8; 1];
            agent_peer.read_exact(&mut lead).await.unwrap();
            if lead[0] == TCP_PING_STOP {
                break;
            }
            assert_eq!(lead[0], TCP_PING_MAGIC, "every pre-STOP byte belongs to a PING frame");
            let mut rest = [0u8; 8];
            agent_peer.read_exact(&mut rest).await.unwrap();
            let mut ping = [0u8; 9];
            ping[0] = lead[0];
            ping[1..9].copy_from_slice(&rest);
            agent_peer.write_all(&pong_echoing(&ping)).await.unwrap();
            agent_peer.flush().await.unwrap();
        }

        // Post-STOP the agent side speaks the frame codec.
        let (far_r, far_w) = tokio::io::split(agent_peer);
        let mut far_reader = FrameReader::new(far_r);
        let mut far_writer = FrameWriter::new(far_w);

        // Client -> Agent: raw bytes (packed with park-phase magic AND frame
        // discriminators -- a Noise handshake will contain them) arrive as ONE
        // DATA frame.
        const FROM_CLIENT: &[u8] = &[0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0x42, 0xFF];
        client_peer.write_all(FROM_CLIENT).await.unwrap();
        client_peer.flush().await.unwrap();
        assert_eq!(
            far_reader.next().await.unwrap(),
            Some(Frame::Data(FROM_CLIENT.to_vec())),
            "post-STOP Client->Agent bytes arrive wrapped in a DATA frame",
        );

        // Agent -> Client: a keepalive then DATA. The keepalive is discarded
        // (never a byte of it reaches the raw client) and ACKed through the
        // edge's writer-owner; the DATA payload arrives unframed.
        far_writer.keepalive(9).await.unwrap();
        const FROM_AGENT: &[u8] = &[0xFA, 0xFB, 0xF9, 0x01, 0xFC];
        far_writer.data(FROM_AGENT).await.unwrap();
        far_writer.flush().await.unwrap();
        let mut back = [0u8; 5];
        client_peer.read_exact(&mut back).await.unwrap();
        assert_eq!(
            &back[..],
            FROM_AGENT,
            "agent DATA payload reaches the client unframed; the interleaved keepalive was discarded",
        );

        // The ACK for counter 9 comes back framed (skipping any keepalives the
        // edge's own idle injector may have interleaved under paused time).
        loop {
            match far_reader.next().await.unwrap() {
                Some(Frame::KeepaliveAck { counter }) => {
                    assert_eq!(counter, 9, "the edge ACKs the agent's keepalive counter");
                    break;
                }
                Some(Frame::Keepalive { counter, .. }) => {
                    // The edge's own injected keepalive (paused-time idle); the
                    // real agent would ACK it -- irrelevant to this assertion.
                    let _ = counter;
                }
                other => panic!("expected the keepalive ACK, got {other:?}"),
            }
        }

        drop(client_peer);
        drop(far_reader);
        drop(far_writer);
        let _ = edge.await;
    }

    /// Drive `park_and_ping`'s pre-STOP phase from the agent side: answer every
    /// well-formed PING with its PONG until the STOP sentinel ends the phase.
    /// Shared by the #534 accounting tests, which care about what happens AFTER
    /// STOP, not about the ping cadence itself.
    async fn drain_park_pings_until_stop<S: AsyncRead + AsyncWrite + Unpin>(agent_peer: &mut S) {
        loop {
            let mut lead = [0u8; 1];
            agent_peer.read_exact(&mut lead).await.unwrap();
            if lead[0] == TCP_PING_STOP {
                return;
            }
            assert_eq!(lead[0], TCP_PING_MAGIC, "every pre-STOP byte belongs to a PING frame");
            let mut ping = [0u8; 9];
            ping[0] = lead[0];
            agent_peer.read_exact(&mut ping[1..]).await.unwrap();
            agent_peer.write_all(&pong_echoing(&ping)).await.unwrap();
            agent_peer.flush().await.unwrap();
        }
    }

    #[tokio::test]
    async fn parked_framed_fallback_relay_books_its_bytes_as_tcp_fallback_534() {
        // #534 (field-measured): `ct_edge_relay_bytes_kind_total{kind=
        // "tcp_fallback"}` stayed at 0 while an agent forced onto the framed
        // 'F' fallback (CT_AGENT_REGISTER_TCP_ONLY=1 + CT_AGENT_FRAMED_FALLBACK=1)
        // served 60 real requests -- `ct_edge_tcp_fallback_deliveries_total`
        // moved by exactly 60, the bytes did not move at all. Cause: this arm
        // dropped `framed_relay`'s byte counts on the floor and called
        // `note_relay` NOWHERE, so those bytes were missing from the kind split
        // AND from `ct_edge_relay_bytes_total` (`note_relay` is the sole writer
        // of both). The counter that answers "how much of my traffic is on the
        // DPI/NAT fallback?" therefore answered 0 for an agent that was 100% on
        // it.
        //
        // Real time, deliberately NOT `start_paused`: the 8s ping/keepalive
        // cadences cannot fire inside a millisecond-scale test, so exactly one
        // verify-at-delivery PING precedes STOP and no injected keepalive can
        // race the teardown into an I/O error (which would skip the accounting
        // this test is about).
        use ct_common::fallback_framing::{Frame, FrameReader, FrameWriter};

        let state = Arc::new(EdgeState::<Connection>::new());
        let token = RoutingToken([0x53; 32]);
        let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };

        let (mut agent_peer, agent_edge) = tokio::io::duplex(1 << 16);
        let state_f = state.clone();
        let edge =
            tokio::spawn(async move { serve_tcp_connection(agent_edge, &state_f, &challenge, None).await });

        let host = "kinds-framed.bunsenbrenner.org";
        let mut hdr = vec![b'F'];
        hdr.extend_from_slice(&token.0);
        hdr.extend_from_slice(&(host.len() as u16).to_be_bytes());
        hdr.extend_from_slice(host.as_bytes());
        agent_peer.write_all(&hdr).await.unwrap();
        agent_peer.flush().await.unwrap();
        let mut ok = [0u8; 2];
        agent_peer.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"OK", "'F' admission succeeded");

        // A Browser stream is handed to the parked agent -- the exact success
        // path the field measurement exercised.
        let (mut client_peer, client_edge) = tokio::io::duplex(1 << 16);
        state
            .deliver_to_tcp_agent_draining(&token, Box::new(client_edge))
            .map_err(|_| "deliver failed")
            .unwrap();
        drain_park_pings_until_stop(&mut agent_peer).await;

        let (far_r, far_w) = tokio::io::split(agent_peer);
        let mut far_reader = FrameReader::new(far_r);
        let mut far_writer = FrameWriter::new(far_w);

        const FROM_CLIENT: &[u8] = b"browser-request-11"; // 18 bytes
        const FROM_AGENT: &[u8] = b"origin-reply"; // 12 bytes
        client_peer.write_all(FROM_CLIENT).await.unwrap();
        client_peer.flush().await.unwrap();
        assert_eq!(
            far_reader.next().await.unwrap(),
            Some(Frame::Data(FROM_CLIENT.to_vec())),
            "the browser's bytes reach the agent as one DATA frame",
        );
        far_writer.data(FROM_AGENT).await.unwrap();
        far_writer.flush().await.unwrap();
        let mut back = [0u8; FROM_AGENT.len()];
        client_peer.read_exact(&mut back).await.unwrap();
        assert_eq!(&back[..], FROM_AGENT, "the agent's reply reaches the browser unframed");

        // Clean bilateral teardown so the relay RETURNS: accounting happens on
        // the Ok path, exactly like every other `note_relay` site in this file.
        drop(client_peer); // browser EOF -> the edge FINs toward the agent
        assert_eq!(
            far_reader.next().await.unwrap(),
            Some(Frame::Fin),
            "the browser's EOF is forwarded as the codec's in-band FIN",
        );
        far_writer.fin().await.unwrap();
        far_writer.flush().await.unwrap();
        edge.await.unwrap().expect("the 'F' park relay ends cleanly once FIN passed both ways");

        let payload = (FROM_CLIENT.len() + FROM_AGENT.len()) as u64;
        assert_eq!(
            state.relay_bytes_by_kind(),
            (0, 0, payload),
            "#534: a request served by a PARKED framed fallback agent is tcp_fallback -- \
             not browser (the label the field measurement found moving instead), and not \
             silently uncounted (what the code actually did)",
        );
        assert_eq!(
            state.relay_bytes_total(),
            payload,
            "the fallback's bytes reach the fleet-wide total too -- the three kinds partition it",
        );
        assert_eq!(
            state.tunnel_bytes(&token),
            (FROM_CLIENT.len() as u64, FROM_AGENT.len() as u64),
            "the per-tunnel in/out split is not mirrored: framed_relay returns \
             (browser->agent, agent->browser) already in note_relay's order",
        );
    }

    #[tokio::test]
    async fn parked_raw_fallback_relay_books_its_bytes_as_tcp_fallback_534() {
        // #534, the RAW ('L') half of the same gap: the ping-capable
        // Browser-Plane park arm relays with `relay` instead of `framed_relay`
        // and had the identical missing-`note_relay` bug. Also pins the
        // direction mapping, which is MIRRORED here: the park arms call
        // `relay(agent, client)`, so `relay`'s `(a->b, b->a)` is
        // `(agent_to_client, client_to_agent)` -- swapping it would leave the
        // fleet totals right and the per-tunnel in/out split inverted.
        let state = Arc::new(EdgeState::<Connection>::new());
        let token = RoutingToken([0x54; 32]);
        let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };

        let (mut agent_peer, agent_edge) = tokio::io::duplex(1 << 16);
        let state_l = state.clone();
        let edge =
            tokio::spawn(async move { serve_tcp_connection(agent_edge, &state_l, &challenge, None).await });

        let host = "kinds-raw.bunsenbrenner.org";
        let mut hdr = vec![b'L'];
        hdr.extend_from_slice(&token.0);
        hdr.extend_from_slice(&(host.len() as u16).to_be_bytes());
        hdr.extend_from_slice(host.as_bytes());
        agent_peer.write_all(&hdr).await.unwrap();
        agent_peer.flush().await.unwrap();
        let mut ok = [0u8; 2];
        agent_peer.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"OK", "'L' admission succeeded");

        let (mut client_peer, client_edge) = tokio::io::duplex(1 << 16);
        state
            .deliver_to_tcp_agent_draining(&token, Box::new(client_edge))
            .map_err(|_| "deliver failed")
            .unwrap();
        drain_park_pings_until_stop(&mut agent_peer).await;

        const FROM_CLIENT: &[u8] = b"raw-browser-request"; // 19 bytes
        const FROM_AGENT: &[u8] = b"raw-reply"; // 9 bytes
        client_peer.write_all(FROM_CLIENT).await.unwrap();
        client_peer.flush().await.unwrap();
        let mut seen = [0u8; FROM_CLIENT.len()];
        agent_peer.read_exact(&mut seen).await.unwrap();
        assert_eq!(&seen[..], FROM_CLIENT, "'L' stays a raw byte pump");
        agent_peer.write_all(FROM_AGENT).await.unwrap();
        agent_peer.flush().await.unwrap();
        let mut back = [0u8; FROM_AGENT.len()];
        client_peer.read_exact(&mut back).await.unwrap();
        assert_eq!(&back[..], FROM_AGENT);

        // Both halves close, so `copy_bidirectional` returns its counts.
        drop(client_peer);
        let mut tail = Vec::new();
        agent_peer.read_to_end(&mut tail).await.unwrap();
        assert!(tail.is_empty(), "the browser's EOF is a shutdown, not stray bytes");
        drop(agent_peer);
        edge.await.unwrap().expect("the 'L' park relay ends cleanly once both halves closed");

        let payload = (FROM_CLIENT.len() + FROM_AGENT.len()) as u64;
        assert_eq!(
            state.relay_bytes_by_kind(),
            (0, 0, payload),
            "#534: the raw park path books tcp_fallback as well",
        );
        assert_eq!(state.relay_bytes_total(), payload);
        assert_eq!(
            state.tunnel_bytes(&token),
            (FROM_CLIENT.len() as u64, FROM_AGENT.len() as u64),
            "in = browser->agent, out = agent->browser: `relay(agent, client)`'s mirrored \
             tuple is un-mirrored at the call site, not passed through positionally",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_fallback_role_k_relay_stays_a_raw_byte_pump_not_framed_regression_528() {
        // #528 regression (iv): adding the framed 'F' path must NOT change 'K'.
        // A 'K' agent keeps the RAW post-STOP byte pump -- a payload that
        // deliberately STARTS with the frame codec's DATA discriminator (0xFC)
        // is delivered verbatim, never re-interpreted as a length-prefixed
        // frame header.
        let state = Arc::new(EdgeState::<Connection>::new());
        let token = RoutingToken([0x4B; 32]); // 0x4B == b'K'
        let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };

        let (mut agent_peer, agent_edge) = tokio::io::duplex(1 << 16);
        let state_k = state.clone();
        let edge =
            tokio::spawn(async move { serve_tcp_connection(agent_edge, &state_k, &challenge, None).await });

        let mut hdr = vec![b'K'];
        hdr.extend_from_slice(&token.0);
        agent_peer.write_all(&hdr).await.unwrap();
        agent_peer.flush().await.unwrap();
        let mut ok = [0u8; 2];
        agent_peer.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"OK");

        assert!(state.has_tcp_agent(&token), "'K' is parked after OK");
        let (mut client_peer, client_edge) = tokio::io::duplex(1 << 16);
        state
            .deliver_to_tcp_agent_draining(&token, Box::new(client_edge))
            .map_err(|_| "deliver failed")
            .unwrap();

        // Drain PINGs until STOP.
        loop {
            let mut lead = [0u8; 1];
            agent_peer.read_exact(&mut lead).await.unwrap();
            if lead[0] == TCP_PING_STOP {
                break;
            }
            assert_eq!(lead[0], TCP_PING_MAGIC);
            let mut rest = [0u8; 8];
            agent_peer.read_exact(&mut rest).await.unwrap();
            let mut ping = [0u8; 9];
            ping[0] = lead[0];
            ping[1..9].copy_from_slice(&rest);
            agent_peer.write_all(&pong_echoing(&ping)).await.unwrap();
            agent_peer.flush().await.unwrap();
        }

        // A payload that parses as a plausible DATA frame header must arrive
        // RAW and byte-exact -- 'K' has no framing in either direction.
        const RAW: &[u8] = &[0xFC, 0x00, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
        client_peer.write_all(RAW).await.unwrap();
        client_peer.flush().await.unwrap();
        let mut got = [0u8; 8];
        agent_peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..], RAW, "'K' relay stays raw: bytes arrive verbatim, never re-framed");

        // And the reverse direction is raw too.
        agent_peer.write_all(&[0xFD, 0xFE, 0x01]).await.unwrap();
        agent_peer.flush().await.unwrap();
        let mut rev = [0u8; 3];
        client_peer.read_exact(&mut rev).await.unwrap();
        assert_eq!(&rev, &[0xFD, 0xFE, 0x01], "agent->client stays raw as well");

        drop(client_peer);
        drop(agent_peer);
        let _ = edge.await;
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_fallback_role_k_admits_exactly_like_a_then_pings_then_relays_end_to_end() {
        // The full 'K' lifecycle through the real `serve_tcp_connection`
        // dispatch: identical admission to 'A', REAL ping/pong cycles over the
        // wire while parked, then a real bidirectional relay once a Client
        // arrives. The relayed payload is deliberately packed with the three
        // ping-protocol magic bytes (0xF9/0xFA/0xFB) because a real Noise
        // handshake is effectively-random bytes and WILL contain them -- this
        // is the property that makes the TCP_PING_STOP sentinel necessary, so
        // it is asserted here rather than assumed.
        let state = Arc::new(EdgeState::<Connection>::new());
        let token = RoutingToken([0x4b; 32]);
        let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };

        let (mut agent_peer, agent_edge) = tokio::io::duplex(4096);
        let state_k = state.clone();
        let edge = tokio::spawn(async move {
            serve_tcp_connection(agent_edge, &state_k, &challenge, None).await
        });

        let mut hdr = vec![b'K'];
        hdr.extend_from_slice(&token.0);
        agent_peer.write_all(&hdr).await.unwrap();
        agent_peer.flush().await.unwrap();
        let mut ok = [0u8; 2];
        agent_peer.read_exact(&mut ok).await.unwrap();
        assert_eq!(
            &ok, b"OK",
            "'K' admission is byte-identical to 'A': role byte + 32-byte token in, OK out"
        );

        // Two real ping/pong round trips over the actual wire, before any
        // Client exists -- this is the traffic that keeps the middlebox's idle
        // timer from expiring.
        for expected in 0..2u64 {
            let mut ping = [0u8; 9];
            agent_peer.read_exact(&mut ping).await.unwrap();
            assert_eq!(ping[0], TCP_PING_MAGIC);
            assert_eq!(
                u64::from_be_bytes(ping[1..9].try_into().unwrap()),
                expected,
                "the parked loop's counter advances across real round trips"
            );
            agent_peer.write_all(&pong_echoing(&ping)).await.unwrap();
            agent_peer.flush().await.unwrap();
        }

        // Now a real Client arrives.
        assert!(state.has_tcp_agent(&token), "the 'K' registration is parked and routable");
        let (mut client_peer, client_edge) = tokio::io::duplex(4096);
        state
            .deliver_to_tcp_agent_draining(&token, Box::new(client_edge))
            .map_err(|_| "deliver failed")
            .unwrap();

        // Drain the ping phase exactly the way a real ping-capable Agent must:
        // never guess from byte content, just consume well-formed PING frames
        // until the unambiguous STOP sentinel arrives. (Extra pings are legal
        // here -- a Client can arrive mid-cadence -- but every pre-STOP byte
        // must still be part of a well-formed PING frame.)
        let mut extra_pings = 0;
        loop {
            let mut lead = [0u8; 1];
            agent_peer.read_exact(&mut lead).await.unwrap();
            if lead[0] == TCP_PING_STOP {
                break;
            }
            assert_eq!(
                lead[0], TCP_PING_MAGIC,
                "every byte before the STOP sentinel belongs to a well-formed PING frame, got {:#04x}",
                lead[0]
            );
            let mut rest = [0u8; 8];
            agent_peer.read_exact(&mut rest).await.unwrap();
            let mut ping = [0u8; 9];
            ping[0] = lead[0];
            ping[1..9].copy_from_slice(&rest);
            agent_peer.write_all(&pong_echoing(&ping)).await.unwrap();
            agent_peer.flush().await.unwrap();
            extra_pings += 1;
        }
        assert!(extra_pings <= 1, "at most one probe can straddle the delivery, saw {extra_pings}");

        // Client -> Agent, byte-exact, magic bytes and all.
        const FROM_CLIENT: &[u8] = &[0xf9, 0xfa, 0xfb, 0x00, 0xf9, 0xf9, 0xfb, 0xfa, 0x42, 0xff];
        client_peer.write_all(FROM_CLIENT).await.unwrap();
        client_peer.flush().await.unwrap();
        let mut got = [0u8; 10];
        agent_peer.read_exact(&mut got).await.unwrap();
        assert_eq!(
            &got[..],
            FROM_CLIENT,
            "post-STOP Client->Agent bytes relay verbatim; ping-protocol magic bytes inside the \
             real (Noise handshake) payload are ordinary data, never framing"
        );

        // Agent -> Client, byte-exact. A 0xFA lead byte here is the sharp case:
        // if the edge were still reading PONGs it would swallow this instead of
        // relaying it.
        const FROM_AGENT: &[u8] = &[0xfa, 0xfb, 0xf9, 0x01, 0xfa];
        agent_peer.write_all(FROM_AGENT).await.unwrap();
        agent_peer.flush().await.unwrap();
        let mut back = [0u8; 5];
        client_peer.read_exact(&mut back).await.unwrap();
        assert_eq!(
            &back[..],
            FROM_AGENT,
            "post-STOP Agent->Client bytes relay verbatim; the edge is no longer consuming PONGs"
        );

        drop(client_peer);
        drop(agent_peer);
        let _ = edge.await;
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_fallback_role_k_hands_off_cleanly_when_a_client_arrives_mid_ping_round_trip() {
        // THE race the TCP_PING_STOP design exists to make impossible: a Client
        // is delivered while a PING is still outstanding, so the Agent's PONG
        // and the Client's first real bytes are in flight at the same time on
        // the same connection. Proven here by forcing exactly that interleaving
        // rather than hoping to hit it by chance:
        //   1. the edge sends a PING; the Agent reads it but does NOT reply yet
        //   2. the Client is delivered RIGHT NOW, mid-round-trip
        //   3. only then does the Agent send its PONG
        // The PONG must be consumed by the edge's own ping reader (never
        // relayed into the Client's stream), and the Client's payload must
        // reach the Agent byte-exact, after exactly one STOP byte.
        let state = Arc::new(EdgeState::<Connection>::new());
        let token = RoutingToken([0x4c; 32]);
        let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };

        let (mut agent_peer, agent_edge) = tokio::io::duplex(4096);
        let state_k = state.clone();
        let edge = tokio::spawn(async move {
            serve_tcp_connection(agent_edge, &state_k, &challenge, None).await
        });

        let mut hdr = vec![b'K'];
        hdr.extend_from_slice(&token.0);
        agent_peer.write_all(&hdr).await.unwrap();
        agent_peer.flush().await.unwrap();
        let mut ok = [0u8; 2];
        agent_peer.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"OK");

        // 1. A PING goes out and is read, but deliberately left unanswered.
        let mut ping = [0u8; 9];
        agent_peer.read_exact(&mut ping).await.unwrap();
        assert_eq!(ping[0], TCP_PING_MAGIC);

        // 2. The Client arrives while that probe is still outstanding.
        assert!(state.has_tcp_agent(&token));
        let (mut client_peer, client_edge) = tokio::io::duplex(4096);
        state
            .deliver_to_tcp_agent_draining(&token, Box::new(client_edge))
            .map_err(|_| "deliver failed")
            .unwrap();

        // The Client speaks first, as a real Client does (a Noise handshake's
        // opening message), while the edge is still awaiting the PONG. These
        // bytes must queue behind the handoff, not race ahead of it.
        const FROM_CLIENT: &[u8] = &[0xfa, 0xfa, 0xf9, 0xfb, 0x11];
        client_peer.write_all(FROM_CLIENT).await.unwrap();
        client_peer.flush().await.unwrap();

        // 3. Only now the PONG, completing the straddling round trip.
        agent_peer.write_all(&pong_echoing(&ping)).await.unwrap();
        agent_peer.flush().await.unwrap();

        // The very next byte the Agent sees must be STOP: the round trip
        // completed, `biased` then picked the already-delivered Client over
        // starting another probe, and the arm wrote the sentinel before relay.
        let mut stop = [0u8; 1];
        agent_peer.read_exact(&mut stop).await.unwrap();
        assert_eq!(
            stop[0], TCP_PING_STOP,
            "after the straddling round trip the ping phase ends with STOP, not another PING"
        );

        let mut got = [0u8; 5];
        agent_peer.read_exact(&mut got).await.unwrap();
        assert_eq!(
            &got[..],
            FROM_CLIENT,
            "the Client's first real bytes arrive intact and byte-exact after the STOP boundary, \
             even though they were written while a PING was still outstanding"
        );

        // And the decisive half of the race: the Agent's PONG was consumed by
        // the edge's ping reader and never leaked into the Client's stream. If
        // it had leaked, the Client's next bytes would start with 0xFA.
        const FROM_AGENT: &[u8] = &[0x77, 0x88];
        agent_peer.write_all(FROM_AGENT).await.unwrap();
        agent_peer.flush().await.unwrap();
        let mut back = [0u8; 2];
        client_peer.read_exact(&mut back).await.unwrap();
        assert_eq!(
            &back[..],
            FROM_AGENT,
            "the straddling PONG was consumed by the edge, never relayed -- the Client's stream \
             starts at the Agent's first REAL byte"
        );

        drop(client_peer);
        drop(agent_peer);
        let _ = edge.await;
    }

    #[tokio::test]
    async fn tcp_fallback_role_k_sheds_once_the_tcp_agent_cap_is_full_just_like_a() {
        // Admission parity (#410): 'K' shares `admit_tcp_agent_a` with 'A', so
        // the new role must not become a way around the dedicated sub-cap.
        let state = Arc::new(EdgeState::<Connection>::new());
        let token = RoutingToken([0x4d; 32]);
        let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };

        let cap = ConnectionCap::new(1);
        let _held = cap.try_admit().unwrap();

        let (mut attacker, edge_side) = tokio::io::duplex(64);
        let edge = tokio::spawn(async move {
            serve_tcp_connection(edge_side, &state, &challenge, Some(&cap)).await
        });

        let mut hdr = vec![b'K'];
        hdr.extend_from_slice(&token.0);
        attacker.write_all(&hdr).await.unwrap();
        attacker.flush().await.unwrap();

        let mut ack = [0u8; 2];
        attacker.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack, b"NO", "'K' sheds on a full sub-cap exactly as 'A' does, never parks");

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), edge)
            .await
            .expect("a shed 'K' registration returns promptly, it never starts the ping loop")
            .unwrap();
        assert!(result.is_ok(), "a sub-cap shed is a clean close, not an error: {result:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_fallback_role_k_holds_its_tcp_agent_cap_permit_for_the_whole_parked_lifetime() {
        // #410's sub-cap only bounds anything if the permit is HELD for as long
        // as the registration occupies a parked slot. Refusing when full is not
        // enough on its own: if every admitted registration handed its permit
        // straight back and then parked forever, the cap would read empty while
        // an unbounded number of registrations sat parked -- precisely the
        // unbounded-park blast radius #410 exists to prevent. Asserted here at
        // three distinct points in the 'K' lifecycle (freshly parked, after a
        // real ping round trip, and while actually relaying) because the ping
        // loop is new code between admission and relay, and it is exactly the
        // stretch where a mislaid permit would go unnoticed.
        let state = Arc::new(EdgeState::<Connection>::new());
        let token = RoutingToken([0x4e; 32]);
        let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
        let cap = ConnectionCap::new(2);

        let (mut agent_peer, agent_edge) = tokio::io::duplex(4096);
        let state_k = state.clone();
        let cap_k = cap.clone();
        let edge = tokio::spawn(async move {
            serve_tcp_connection(agent_edge, &state_k, &challenge, Some(&cap_k)).await
        });

        let mut hdr = vec![b'K'];
        hdr.extend_from_slice(&token.0);
        agent_peer.write_all(&hdr).await.unwrap();
        agent_peer.flush().await.unwrap();
        let mut ok = [0u8; 2];
        agent_peer.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"OK");
        assert_eq!(cap.in_use(), 1, "a freshly parked 'K' registration holds exactly one sub-cap permit");

        // Still held across a real ping round trip.
        let mut ping = [0u8; 9];
        agent_peer.read_exact(&mut ping).await.unwrap();
        agent_peer.write_all(&pong_echoing(&ping)).await.unwrap();
        agent_peer.flush().await.unwrap();
        assert_eq!(cap.in_use(), 1, "the permit survives the ping loop, it is not released per probe");

        // Still held once a Client is spliced in and bytes are actually moving.
        let (mut client_peer, client_edge) = tokio::io::duplex(4096);
        state
            .deliver_to_tcp_agent_draining(&token, Box::new(client_edge))
            .map_err(|_| "deliver failed")
            .unwrap();
        loop {
            let mut lead = [0u8; 1];
            agent_peer.read_exact(&mut lead).await.unwrap();
            if lead[0] == TCP_PING_STOP {
                break;
            }
            assert_eq!(lead[0], TCP_PING_MAGIC);
            let mut rest = [0u8; 8];
            agent_peer.read_exact(&mut rest).await.unwrap();
            let mut extra = [0u8; 9];
            extra[0] = lead[0];
            extra[1..9].copy_from_slice(&rest);
            agent_peer.write_all(&pong_echoing(&extra)).await.unwrap();
            agent_peer.flush().await.unwrap();
        }
        client_peer.write_all(b"payload").await.unwrap();
        client_peer.flush().await.unwrap();
        let mut got = [0u8; 7];
        agent_peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"payload");
        assert_eq!(cap.in_use(), 1, "the permit is still held while the connection is relaying");

        drop(client_peer);
        drop(agent_peer);
        let _ = edge.await;
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_fallback_legacy_role_a_never_receives_a_single_ping_protocol_byte() {
        // Backward-compatibility guarantee, stated as a test rather than as a
        // comment: every already-deployed Agent only ever sends 'A'. Such a
        // registration must stay byte-for-byte what it was before this change
        // -- it parks silently and the first byte it EVER receives after the
        // OK ack is the Client's own first byte. Here the registration sits
        // parked for four full ping intervals (virtual time) before the Client
        // arrives: more than long enough for any stray probe to show up.
        let state = Arc::new(EdgeState::<Connection>::new());
        let token = RoutingToken([0x41; 32]);
        let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };

        let (mut agent_peer, agent_edge) = tokio::io::duplex(4096);
        let state_a = state.clone();
        let edge = tokio::spawn(async move {
            serve_tcp_connection(agent_edge, &state_a, &challenge, None).await
        });

        let mut hdr = vec![b'A'];
        hdr.extend_from_slice(&token.0);
        agent_peer.write_all(&hdr).await.unwrap();
        agent_peer.flush().await.unwrap();
        let mut ok = [0u8; 2];
        agent_peer.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"OK");

        tokio::time::sleep(TCP_PING_INTERVAL * 4).await;

        assert!(state.has_tcp_agent(&token), "the legacy 'A' registration is still parked");
        let (mut client_peer, client_edge) = tokio::io::duplex(4096);
        state
            .deliver_to_tcp_agent_draining(&token, Box::new(client_edge))
            .map_err(|_| "deliver failed")
            .unwrap();

        // No STOP sentinel either: 'A' never enters the ping phase, so there is
        // no phase to end. The Client's very first byte is the Agent's very
        // first post-ack byte -- and it is 0xF9, the PING magic, precisely to
        // catch any implementation that starts pinging legacy registrations.
        const FROM_CLIENT: &[u8] = &[0xf9, 0xfb, 0xfa, 0x05];
        client_peer.write_all(FROM_CLIENT).await.unwrap();
        client_peer.flush().await.unwrap();
        let mut got = [0u8; 4];
        agent_peer.read_exact(&mut got).await.unwrap();
        assert_eq!(
            &got[..],
            FROM_CLIENT,
            "a legacy 'A' Agent's first post-ack bytes are the Client's, with no PING and no STOP \
             sentinel spliced in front of them"
        );

        drop(client_peer);
        drop(agent_peer);
        let _ = edge.await;
    }

    #[tokio::test]
    async fn sni_passthrough_routes_a_browser_tls_connection_to_the_origin() {
        // #23 Browser Plane (sub-packet 1): a plain rustls "browser" reaches a
        // public-hostname HTTPS origin THROUGH the tunnel, routed purely by the
        // TLS SNI — the edge never terminates TLS (provider-blind), and the
        // browser validates the origin's cert client-side (TLS terminates at the
        // origin). No ct-client protocol, no capability: just SNI -> tunnel.
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        crate::transport::install_crypto_provider();

        // A "public" HTTPS origin with a cert for browser.test (the browser
        // trusts it, standing in for a publicly-trusted / Let's Encrypt cert).
        let certified =
            rcgen::generate_simple_self_signed(vec!["browser.test".to_string()]).unwrap();
        let origin_cert = certified.cert.der().clone();
        let origin_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let scfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![origin_cert.clone()], origin_key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(scfg));
        let origin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (sock, _) = origin_listener.accept().await.unwrap();
            let mut tls = acceptor.accept(sock).await.expect("origin TLS handshake");
            let mut b = [0u8; 1024];
            let n = tls.read(&mut b).await.unwrap();
            assert!(b[..n].starts_with(b"GET "), "origin got an HTTP request over TLS");
            tls.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .await
                .unwrap();
            tls.shutdown().await.unwrap();
        });

        // Edge + a raw-forwarding Agent: the agent pipes the tunnel stream to the
        // origin verbatim (Browser Plane carries raw TLS, not Noise).
        let token = RoutingToken([0x42; 32]);
        let state = Arc::new(EdgeState::<Connection>::new());
        let _ = state.register_host("Browser.Test", token.clone()); // case-insensitive
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let edge_addr = server.local_addr().unwrap();
        let state_e = state.clone();
        let edge_srv = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
            let _ = serve_connection(&conn, &state_e, &challenge).await;
            conn.closed().await;
        });
        let agent_ep = build_client_endpoint(cert).expect("agent ep");
        let agent_conn = agent_ep
            .connect(edge_addr, "localhost")
            .expect("cfg")
            .await
            .expect("agent conn");
        let (mut a_s, mut a_r) = agent_conn.open_bi().await.unwrap();
        a_s.write_all(b"A").await.unwrap();
        a_s.write_all(&token.0).await.unwrap();
        a_s.finish().unwrap();
        assert_eq!(a_r.read_to_end(8).await.unwrap(), b"OK");
        let agent_task = tokio::spawn(async move {
            let (e_send, e_recv) = agent_conn.accept_bi().await.unwrap();
            let mut edge_side = tokio::io::join(e_recv, e_send);
            let mut origin_tcp = tokio::net::TcpStream::connect(origin_addr).await.unwrap();
            let _ = crate::relay::relay(&mut edge_side, &mut origin_tcp).await;
        });

        // Browser: rustls over a duplex; the other end feeds serve_sni_passthrough.
        let (browser_side, edge_inbound) = tokio::io::duplex(64 * 1024);
        let state_p = state.clone();
        let pass =
            tokio::spawn(async move { serve_sni_passthrough(edge_inbound, &state_p).await });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(origin_cert).unwrap();
        let ccfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(ccfg));
        let sni = rustls::pki_types::ServerName::try_from("browser.test").unwrap();
        let mut tls = connector
            .connect(sni, browser_side)
            .await
            .expect("browser validates the cert and completes TLS via SNI routing");
        tls.write_all(b"GET / HTTP/1.0\r\nHost: browser.test\r\n\r\n").await.unwrap();
        tls.flush().await.unwrap();
        let mut resp = Vec::new();
        tls.read_to_end(&mut resp).await.unwrap();
        let page = String::from_utf8_lossy(&resp);
        assert!(
            page.contains("200 OK") && page.contains("hello"),
            "HTTPS 200 through the tunnel via SNI passthrough: {page}"
        );

        // #534 control case: a browser request served by a QUIC-registered
        // agent has NO TLS-TCP fallback leg anywhere, so its bytes stay
        // `browser` -- the label the parked-fallback arms must NOT reuse. Exact
        // counts are not asserted (a real TLS session's byte count is not a
        // stable constant); the SPLIT is what this pins.
        tls.shutdown().await.unwrap();
        pass.await.unwrap().expect("the passthrough relay ends cleanly");
        let (browser, dataplane, tcp_fallback) = state.relay_bytes_by_kind();
        assert!(browser > 0, "the browser plane booked its bytes");
        assert_eq!(
            (dataplane, tcp_fallback),
            (0, 0),
            "a QUIC-agent browser request is neither data plane nor TLS-TCP fallback",
        );
        assert_eq!(browser, state.relay_bytes_total(), "the three kinds partition the total");

        agent_task.abort();
        edge_srv.abort();
        origin.abort();
    }

    #[tokio::test]
    async fn front_door_terminates_gelb_hosts_with_the_wildcard_cert_and_relays_to_the_agent() {
        // #233: a hostname the control plane has marked Gelb gets its TLS
        // TERMINATED at the edge with the SHARED wildcard certificate
        // (rather than passed through raw -- the origin doesn't hold a
        // certificate of its own yet) and the DECRYPTED bytes relayed
        // onward to the agent exactly like any other tunnel route. Proven
        // end-to-end through the real `:443` front door (not just the
        // `serve_gelb_terminated` function in isolation), a real QUIC agent,
        // and a real rustls browser handshake that only succeeds because it
        // trusts the WILDCARD cert specifically (not an origin-specific one
        // -- if the edge had instead raw-passed-through, there would be no
        // origin TLS listener at all for it to validate against).
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        crate::transport::install_crypto_provider();

        // The shared wildcard cert (stands in for `*.bunsenbrenner.org`).
        let certified = rcgen::generate_simple_self_signed(vec!["app.example.test".to_string()]).unwrap();
        let wildcard_cert = certified.cert.der().clone();
        let wildcard_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let scfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![wildcard_cert.clone()], wildcard_key)
            .unwrap();
        let wildcard_tls = tokio_rustls::TlsAcceptor::from(Arc::new(scfg));

        // A plain-HTTP "origin": a Gelb-tier customer serves HTTP, not TLS,
        // since TLS is now terminated at the edge instead.
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut sock, _) = origin.accept().await.unwrap();
            let mut b = [0u8; 1024];
            let n = sock.read(&mut b).await.unwrap();
            assert!(
                b[..n].starts_with(b"GET "),
                "origin sees a PLAINTEXT request -- TLS was already stripped at the edge"
            );
            sock.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 10\r\n\r\nhello gelb")
                .await
                .unwrap();
            sock.shutdown().await.unwrap();
        });

        // Edge + a real QUIC agent relaying the tunnel stream verbatim to the
        // plain origin (same registration dance as the passthrough test above).
        let token = RoutingToken([0x77; 32]);
        let state = Arc::new(EdgeState::<Connection>::new());
        let _ = state.register_host("app.example.test", token.clone());
        state.set_cert_tier("app.example.test", true); // <-- the new bit: Gelb
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let edge_addr = server.local_addr().unwrap();
        let state_e = state.clone();
        let edge_srv = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
            let _ = serve_connection(&conn, &state_e, &challenge).await;
            conn.closed().await;
        });
        let agent_ep = build_client_endpoint(cert).expect("agent ep");
        let agent_conn = agent_ep
            .connect(edge_addr, "localhost")
            .expect("cfg")
            .await
            .expect("agent conn");
        let (mut a_s, mut a_r) = agent_conn.open_bi().await.unwrap();
        a_s.write_all(b"A").await.unwrap();
        a_s.write_all(&token.0).await.unwrap();
        a_s.finish().unwrap();
        assert_eq!(a_r.read_to_end(8).await.unwrap(), b"OK");
        let agent_task = tokio::spawn(async move {
            let (e_send, e_recv) = agent_conn.accept_bi().await.unwrap();
            let mut edge_side = tokio::io::join(e_recv, e_send);
            let mut origin_tcp = tokio::net::TcpStream::connect(origin_addr).await.unwrap();
            let _ = crate::relay::relay(&mut edge_side, &mut origin_tcp).await;
        });

        // The public `:443` front door, wired with the wildcard acceptor. No
        // `proxies` entries -- this host is an ordinary BrowserTunnel, not a
        // configured terminate-host.
        let dummy_acceptor = {
            let c = rcgen::generate_simple_self_signed(vec!["edge.test".to_string()]).unwrap();
            let cfg = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![c.cert.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(c.key_pair.serialize_der())),
                )
                .unwrap();
            tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
        };
        let proxies: std::collections::HashMap<String, ProxyTarget> = std::collections::HashMap::new();
        let fd = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fd_addr = fd.local_addr().unwrap();
        let fd_task = tokio::spawn(async move {
            let (tcp, _) = fd.accept().await.unwrap();
            let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
            serve_front_door(
                tcp, &state, &dummy_acceptor, &proxies, None, &challenge, None, Some(&wildcard_tls), None, None, None, None,
                None,
            )
            .await
        });

        // Browser: a real rustls handshake trusting the WILDCARD cert
        // specifically (not an origin-specific one) -- proving the EDGE, not
        // the origin, terminated this TLS session.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(wildcard_cert).unwrap();
        let ccfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(ccfg));
        let tcp = tokio::net::TcpStream::connect(fd_addr).await.unwrap();
        let sni = rustls::pki_types::ServerName::try_from("app.example.test").unwrap();
        let mut tls = connector.connect(sni, tcp).await.expect("browser trusts the shared wildcard cert");
        tls.write_all(b"GET / HTTP/1.0\r\nHost: app.example.test\r\n\r\n").await.unwrap();
        let mut resp = Vec::new();
        tls.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(
            text.contains("200 OK") && text.contains("hello gelb"),
            "round-tripped through edge-terminated TLS to the plain-HTTP origin: {text}"
        );

        origin_task.await.unwrap();
        agent_task.abort();
        edge_srv.abort();
        fd_task.abort();
    }

    #[tokio::test]
    async fn serve_gelb_terminated_delivers_the_decrypted_stream_to_a_parked_tcp_fallback_agent() {
        // #229 (found live): an agent on a UDP/QUIC-blocked network registers
        // over the TLS-TCP fallback, not QUIC -- `open_agent_stream` alone
        // always fails "no agent tunnel for token" for it (there is no QUIC
        // registration to open a stream on), indistinguishable from a
        // genuinely dead agent. `serve_gelb_terminated` must hand the
        // DECRYPTED stream to the parked TCP-fallback agent instead, exactly
        // like `serve_sni_passthrough` already does for the raw one.
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        crate::transport::install_crypto_provider();

        let certified = rcgen::generate_simple_self_signed(vec!["app.example.test".to_string()]).unwrap();
        let wildcard_cert = certified.cert.der().clone();
        let wildcard_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let scfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![wildcard_cert.clone()], wildcard_key)
            .unwrap();
        let wildcard_tls = tokio_rustls::TlsAcceptor::from(Arc::new(scfg));

        let token = RoutingToken([0x88; 32]);
        let state = Arc::new(EdgeState::<Connection>::new());
        let _ = state.register_host("app.example.test", token.clone());
        state.set_cert_tier("app.example.test", true);
        // Park a TCP-fallback "agent" instead of registering one over QUIC --
        // this is the exact state a UDP-blocked agent leaves the edge in.
        let parked_rx = state.park_tcp_agent(token.clone());
        assert!(state.has_tcp_agent(&token), "agent is parked, not QUIC-registered");

        let (browser_side, edge_inbound) = tokio::io::duplex(64 * 1024);
        let state_g = state.clone();
        let gelb_task = tokio::spawn(async move {
            serve_gelb_terminated(edge_inbound, "app.example.test", &state_g, &wildcard_tls).await
        });

        // The "agent": receives the delivered (already-decrypted) stream and
        // echoes back a fixed HTTP response, exactly as a plain-HTTP Gelb-tier
        // origin would.
        let agent_task = tokio::spawn(async move {
            let mut stream = parked_rx.await.expect("agent receives the delivered stream");
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            assert!(buf[..n].starts_with(b"GET "), "agent sees a PLAINTEXT request -- TLS already stripped");
            stream
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 15\r\n\r\nhello tcp-agent")
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(wildcard_cert).unwrap();
        let ccfg = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(ccfg));
        let sni = rustls::pki_types::ServerName::try_from("app.example.test").unwrap();
        let mut tls = connector.connect(sni, browser_side).await.expect("browser trusts the wildcard cert");
        tls.write_all(b"GET / HTTP/1.0\r\nHost: app.example.test\r\n\r\n").await.unwrap();
        let mut resp = Vec::new();
        tls.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(
            text.contains("200 OK") && text.contains("hello tcp-agent"),
            "delivered through the TCP-fallback path, not silently dropped: {text}"
        );

        agent_task.await.unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), gelb_task).await;
    }

    #[tokio::test(start_paused = true)]
    async fn serve_gelb_terminated_tls_accept_times_out_on_a_silent_peer_422() {
        // #422: `wildcard_acceptor.accept(inbound)` was unbounded -- a peer that opens
        // the connection but never sends a ClientHello must not hold this Gelb-terminate
        // slot forever.
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        crate::transport::install_crypto_provider();

        let certified = rcgen::generate_simple_self_signed(vec!["app.example.test".to_string()]).unwrap();
        let wildcard_cert = certified.cert.der().clone();
        let wildcard_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let scfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![wildcard_cert], wildcard_key)
            .unwrap();
        let wildcard_tls = tokio_rustls::TlsAcceptor::from(Arc::new(scfg));

        let token = RoutingToken([0x89; 32]);
        let state = Arc::new(EdgeState::<Connection>::new());
        let _ = state.register_host("app.example.test", token.clone());
        state.set_cert_tier("app.example.test", true);

        let (_attacker_side, edge_inbound) = tokio::io::duplex(64); // attacker never writes anything
        let start = tokio::time::Instant::now();
        let res = serve_gelb_terminated(edge_inbound, "app.example.test", &state, &wildcard_tls).await;
        assert!(res.is_err(), "a stalled TLS handshake must not hang forever");
        assert!(
            start.elapsed() >= FRONT_DOOR_TLS_ACCEPT_TIMEOUT && start.elapsed() < Duration::from_secs(30),
            "must fail at the TLS-accept bound (~{FRONT_DOOR_TLS_ACCEPT_TIMEOUT:?}), not hang: {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn agent_binds_a_hostname_via_the_h_role() {
        // #23 BP3: an agent binds host -> token over the edge protocol (role 'H'),
        // so an SNI-routed browser can later reach this tunnel. Case-insensitive.
        let token = RoutingToken([0x5A; 32]);
        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().unwrap();
        let state_e = state.clone();
        let edge = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
            let _ = serve_connection(&conn, &state_e, &challenge).await;
            conn.closed().await;
        });
        let ep = build_client_endpoint(cert).expect("client");
        let conn = ep.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let (mut s, mut r) = conn.open_bi().await.unwrap();
        let host = b"Shop.Example.Test";
        s.write_all(b"H").await.unwrap();
        s.write_all(&token.0).await.unwrap();
        s.write_all(&(host.len() as u16).to_be_bytes()).await.unwrap();
        s.write_all(host).await.unwrap();
        s.finish().unwrap();
        assert_eq!(r.read_to_end(8).await.unwrap(), b"OK");
        assert_eq!(
            state.route_host("shop.example.test"),
            Some(token),
            "host bound case-insensitively to the token"
        );
        conn.close(0u32.into(), b"done");
        edge.abort();
    }

    #[tokio::test]
    async fn front_door_proxies_the_portal_sni_to_the_control_plane() {
        // #31 FD2: a browser reaching the unified :443 with the Portal's SNI is
        // classified ControlPlane and raw-proxied to the Portal verbatim — the
        // buffered ClientHello is replayed first (no handshake byte lost) and the
        // edge never terminates TLS on this leg. Proven with a plain echo upstream
        // standing in for the Portal: whatever the client sends comes back intact.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        crate::transport::install_crypto_provider();

        // Upstream "Portal": echo back exactly the bytes it receives.
        let hello = crate::sni::synth_client_hello(Some("portal.test"), &[]);
        let extra = b"PING-after-hello";
        let total = hello.len() + extra.len();
        let portal = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let portal_addr = portal.local_addr().unwrap();
        let n_echo = total;
        let portal_task = tokio::spawn(async move {
            let (mut sock, _) = portal.accept().await.unwrap();
            let mut buf = vec![0u8; n_echo];
            sock.read_exact(&mut buf).await.unwrap();
            sock.write_all(&buf).await.unwrap();
            sock.flush().await.unwrap();
        });

        // A TLS acceptor is required by the signature (used only on the EdgeRelay
        // arm); build a throwaway one so the ControlPlane arm can run.
        let certified =
            rcgen::generate_simple_self_signed(vec!["edge.test".to_string()]).unwrap();
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        let scfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certified.cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    certified.key_pair.serialize_der(),
                )),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(scfg));

        // Front door: one connection through serve_front_door with portal routing.
        let state = Arc::new(EdgeState::<Connection>::new());
        let fd = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fd_addr = fd.local_addr().unwrap();
        let fd_task = tokio::spawn(async move {
            let (tcp, _) = fd.accept().await.unwrap();
            let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
            // Portal as a raw-proxy target (no cert).
            let mut proxies: std::collections::HashMap<String, ProxyTarget> =
                std::collections::HashMap::new();
            proxies.insert("portal.test".into(), (portal_addr, None));
            serve_front_door(tcp, &state, &acceptor, &proxies, Some("portal.test"), &challenge, None, None, None, None, None, None, None)
                .await
        });

        // Client: send the ClientHello (SNI=portal.test) + extra, read it echoed.
        let mut client = tokio::net::TcpStream::connect(fd_addr).await.unwrap();
        client.write_all(&hello).await.unwrap();
        client.write_all(extra).await.unwrap();
        client.flush().await.unwrap();
        let mut got = vec![0u8; total];
        client.read_exact(&mut got).await.unwrap();

        let mut expected = hello.clone();
        expected.extend_from_slice(extra);
        assert_eq!(got, expected, "portal SNI is raw-proxied, ClientHello replayed");

        portal_task.await.unwrap();
        // Close the client so the proxy's client->upstream half sees EOF and
        // serve_front_door returns (the upstream already closed after the echo).
        drop(client);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), fd_task).await;
    }

    #[tokio::test]
    async fn front_door_wires_the_ct_edge_alpn_to_the_real_tcp_fallback_admission_protocol_329() {
        // #329 area 5, integration-level: proves classify_front_door's EdgeRelay
        // decision is actually wired through serve_front_door's real dispatch into
        // serve_tcp_connection's real role/admission protocol -- not just that the
        // pure classifier function returns the right enum variant in isolation
        // (already proven by classify_front_door_routes_the_channel_alpn_to_the_broker
        // and friends in sni.rs). No prior test in this file drives the plain
        // "ct-edge" ALPN through a real listener + real TLS handshake.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        crate::transport::install_crypto_provider();

        let state = Arc::new(EdgeState::<Connection>::new());
        let certified = rcgen::generate_simple_self_signed(vec!["edge.test".to_string()]).unwrap();
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        let scfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certified.cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der())),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(scfg));
        let proxies: std::collections::HashMap<String, ProxyTarget> = std::collections::HashMap::new();

        let fd = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fd_addr = fd.local_addr().unwrap();
        let fd_task = tokio::spawn(async move {
            let (tcp, _) = fd.accept().await.unwrap();
            let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
            serve_front_door(tcp, &state, &acceptor, &proxies, None, &challenge, None, None, None, None, None, None, None).await
        });

        // Real client: TCP connect, real TLS handshake offering ONLY the ct-edge
        // ALPN (no SNI -- the data-plane leg carries none), trusting the same
        // self-signed cert the acceptor above presents.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certified.cert.der().clone()).unwrap();
        let mut ccfg = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        ccfg.alpn_protocols = vec![crate::sni::CT_EDGE_ALPN.as_bytes().to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(ccfg));
        let tcp = tokio::net::TcpStream::connect(fd_addr).await.unwrap();
        let sni = rustls::pki_types::ServerName::try_from("edge.test").unwrap();
        let mut tls = connector.connect(sni, tcp).await.expect("real TLS handshake completes");

        // Speak serve_tcp_connection's OWN real admission protocol (role 'A' +
        // a 32-byte token) and get back its real "OK" ack -- this is only reachable
        // if classify_front_door really routed this connection to EdgeRelay and
        // serve_front_door really dispatched it into serve_tcp_connection, not some
        // other arm (which would speak a different protocol or hang differently).
        tls.write_all(b"A").await.unwrap();
        tls.write_all(&[0x42u8; 32]).await.unwrap(); // an arbitrary but well-formed RoutingToken
        tls.flush().await.unwrap();
        let mut ack = [0u8; 2];
        tls.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack, b"OK", "the real serve_tcp_connection admission ack proves EdgeRelay dispatch actually happened");

        drop(tls);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), fd_task).await;
    }

    #[tokio::test]
    async fn front_door_sheds_a_browser_tunnel_connection_once_its_own_sub_cap_is_full_254() {
        // #254: the BrowserTunnel arm must admit against its own sub-cap, separate
        // from the shared front-door `conn_cap` -- proven here by holding the sub-cap's
        // only permit BEFORE the connection arrives and confirming serve_front_door
        // refuses it (instead of proceeding to serve_sni_passthrough's route lookup,
        // which would fail differently -- with "no such host", not a cap error).
        use tokio::io::AsyncWriteExt;
        crate::transport::install_crypto_provider();

        let hello = crate::sni::synth_client_hello(Some("unrouted.test"), &[]);
        let state = Arc::new(EdgeState::<Connection>::new()); // nothing registered

        let certified = rcgen::generate_simple_self_signed(vec!["edge.test".to_string()]).unwrap();
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        let scfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certified.cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der())),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(scfg));
        let proxies: std::collections::HashMap<String, ProxyTarget> = std::collections::HashMap::new();

        let cap = ConnectionCap::new(1);
        let _held = cap.try_admit().unwrap(); // the sub-cap's only permit is already taken

        let fd = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fd_addr = fd.local_addr().unwrap();
        let fd_task = tokio::spawn(async move {
            let (tcp, _) = fd.accept().await.unwrap();
            let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
            serve_front_door(tcp, &state, &acceptor, &proxies, None, &challenge, None, None, None, None, Some(&cap), None, None).await
        });

        let mut client = tokio::net::TcpStream::connect(fd_addr).await.unwrap();
        client.write_all(&hello).await.unwrap();
        client.flush().await.unwrap();

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), fd_task)
            .await
            .expect("serve_front_door returns promptly, it never blocks waiting on the cap")
            .unwrap();
        let err = result.expect_err("an over-sub-cap BrowserTunnel connection is shed, not served");
        assert!(err.to_string().contains("254"), "shed for the expected reason, got: {err}");
    }

    #[test]
    fn resolve_proxy_addr_accepts_hostnames_and_literals() {
        // #31: CT_CP_PROXY_ADDR must resolve a hostname (control-plane:8090), not
        // only a literal IP:port — else it silently became None -> dead Portal
        // route. `localhost` stands in for a resolvable service name in the gate.
        let a = resolve_proxy_addr(Some("localhost:8090".into())).expect("hostname resolves");
        assert_eq!(a.port(), 8090);
        assert!(a.ip().is_loopback());
        assert_eq!(
            resolve_proxy_addr(Some("127.0.0.1:8090".into())),
            Some("127.0.0.1:8090".parse().unwrap()),
            "literal IP:port parses directly"
        );
        assert!(resolve_proxy_addr(None).is_none(), "unset -> None");
        assert!(resolve_proxy_addr(Some("  ".into())).is_none(), "blank -> None");
        assert!(
            resolve_proxy_addr(Some("no-port".into())).is_none(),
            "unresolvable -> None (not a panic)"
        );
    }

    #[tokio::test]
    async fn http_redirect_bounces_to_https_preserving_host_and_path() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // A browser hitting http://<host>/path gets a 308 to the https URL.
        let (mut browser, edge) = tokio::io::duplex(4096);
        let srv = tokio::spawn(async move { serve_http_redirect(edge).await });
        browser
            .write_all(b"GET /help?x=1 HTTP/1.1\r\nHost: bunsenbrenner.org\r\nUser-Agent: t\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        browser.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 308"), "permanent redirect: {text:?}");
        assert!(
            text.contains("Location: https://bunsenbrenner.org/help?x=1"),
            "redirects to https preserving host+path: {text:?}"
        );
        srv.await.unwrap().unwrap();

        // A :port on the Host is stripped (default 443).
        let (mut b2, e2) = tokio::io::duplex(4096);
        let s2 = tokio::spawn(async move { serve_http_redirect(e2).await });
        b2.write_all(b"GET / HTTP/1.1\r\nHost: example.test:80\r\n\r\n").await.unwrap();
        let mut r2 = Vec::new();
        b2.read_to_end(&mut r2).await.unwrap();
        assert!(
            String::from_utf8_lossy(&r2).contains("Location: https://example.test/"),
            "host port stripped"
        );
        s2.await.unwrap().unwrap();
    }

    /// #341: an `AsyncRead` that always returns exactly one byte per `poll_read`
    /// (until its source is exhausted) -- the worst case for a header-terminator
    /// scanner, and the exact shape the finding described (a client/scanner on
    /// the public `:80` port dribbling bytes one at a time). Forces
    /// `serve_http_redirect` to actually go through many small reads rather than
    /// relying on `tokio::io::duplex`'s own batching (which the existing
    /// `http_redirect_bounces_to_https_preserving_host_and_path` test never
    /// exercises, since it writes the whole request in one `write_all`).
    struct OneByteAtATime {
        data: Vec<u8>,
        pos: usize,
    }
    impl AsyncRead for OneByteAtATime {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if this.pos < this.data.len() {
                buf.put_slice(&this.data[this.pos..this.pos + 1]);
                this.pos += 1;
            }
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn http_redirect_finds_the_terminator_correctly_one_byte_at_a_time_341() {
        // Correctness under the worst-case read pattern: the \r\n\r\n terminator
        // (and every other byte of the request) arrives as its own single-byte
        // read. The old whole-buffer `windows(4)` rescan was still CORRECT here
        // (just slow) -- this proves the new tail-only scan (#341) is too, not
        // just faster: a terminator split across many read-boundary-adjacent
        // positions must still be found.
        let req = b"GET /path?q=1 HTTP/1.1\r\nHost: slow.example\r\n\r\n".to_vec();
        let reader = OneByteAtATime { data: req, pos: 0 };
        let (mut out_rx, out_tx) = tokio::io::duplex(4096);
        let stream = tokio::io::join(reader, out_tx);
        let srv = tokio::spawn(async move { serve_http_redirect(stream).await });
        let mut resp = Vec::new();
        out_rx.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 308"), "terminator found even one byte at a time: {text:?}");
        assert!(text.contains("Location: https://slow.example/path?q=1"), "host+path still parsed correctly: {text:?}");
        srv.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn http_redirect_stays_fast_under_a_slow_drip_up_to_the_16kb_cap_341() {
        // #341: the real regression guard. Before this fix, `buf.windows(4)`
        // rescanned the WHOLE accumulated buffer on every one-byte read --
        // O(n^2) in the total bytes. A client dribbling ~16KB of padding one
        // byte at a time (never sending a real terminator, so this runs all the
        // way to the 16KB cap) forced roughly (16384/1)^2 / 2 ~= 128M four-byte
        // comparisons pre-fix. Post-fix, each read only rescans its own tail
        // (bounded overlap), so total work is O(n). Assert real wall-clock time
        // stays well under what the quadratic version would need -- this is a
        // real regression guard, not a micro-benchmark: it would reliably fail
        // (multi-second+) against the old implementation and reliably pass
        // (sub-second) against this fix.
        let req = vec![b'A'; 16400]; // never contains \r\n\r\n; > 16384 so the loop exits on the size cap, not EOF
        let reader = OneByteAtATime { data: req, pos: 0 };
        let (_out_rx, out_tx) = tokio::io::duplex(4096);
        let stream = tokio::io::join(reader, out_tx);

        let started = std::time::Instant::now();
        tokio::time::timeout(std::time::Duration::from_secs(5), serve_http_redirect(stream))
            .await
            .expect("must finish well under 5s -- the old O(n^2) scan could take far longer than this for 16000 one-byte reads")
            .unwrap();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "tail-only scan should finish in well under a second for 16KB of one-byte reads, took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn http_redirect_drops_a_connection_that_never_sends_a_complete_head_470() {
        // #470: the whole head-read had no timeout at all -- connect on :80, send
        // nothing (or an incomplete request), and the task held its shared connection-cap
        // permit forever. With the clock paused, tokio auto-advances virtual time to the
        // deadline, so this is deterministic and fast, same style as #111's ClientHello
        // timeout test above.
        let (mut client, edge) = tokio::io::duplex(64);
        // Send a partial request line -- no \r\n\r\n terminator ever arrives, and `client`
        // stays alive (in scope) for the rest of the test, so the connection is held open
        // (not closed) -- only the new read deadline can end this.
        client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        client.flush().await.unwrap();

        let start = tokio::time::Instant::now();
        let res = serve_http_redirect(edge).await;
        let elapsed = start.elapsed();

        assert!(res.is_err(), "an incomplete request head must be dropped, not hang forever");
        assert!(
            elapsed >= HTTP_REDIRECT_READ_TIMEOUT,
            "must wait for the real read deadline before dropping, elapsed {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn front_door_terminates_portal_tls_and_proxies_http_to_the_control_plane() {
        // #31 FD4-a: a browser hitting :443 with the Portal SNI gets its TLS
        // TERMINATED at the edge (Portal cert) and its HTTP reverse-proxied to the
        // plain-HTTP control plane — so a real landing page renders over HTTPS.
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        crate::transport::install_crypto_provider();

        // Portal cert for portal.test + the edge's terminating acceptor.
        let certified = rcgen::generate_simple_self_signed(vec!["portal.test".to_string()]).unwrap();
        let portal_cert = certified.cert.der().clone();
        let portal_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let scfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![portal_cert.clone()], portal_key)
            .unwrap();
        let portal_tls = tokio_rustls::TlsAcceptor::from(Arc::new(scfg));

        // A plain-HTTP "control plane": read the request line, reply with a page.
        let cp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cp_addr = cp.local_addr().unwrap();
        let cp_task = tokio::spawn(async move {
            let (mut sock, _) = cp.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = sock.read(&mut buf).await.unwrap();
            assert!(buf[..n].starts_with(b"GET "), "control plane sees a plaintext HTTP request");
            sock.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 12\r\n\r\nhello portal")
                .await
                .unwrap();
            sock.shutdown().await.unwrap();
        });

        // Front door with the Portal cert wired in (FD4-a path).
        let state = Arc::new(EdgeState::<Connection>::new());
        let dummy_acceptor = {
            let c = rcgen::generate_simple_self_signed(vec!["edge.test".to_string()]).unwrap();
            let cfg = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![c.cert.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(c.key_pair.serialize_der())),
                )
                .unwrap();
            tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
        };
        let fd = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fd_addr = fd.local_addr().unwrap();
        let fd_task = tokio::spawn(async move {
            let (tcp, _) = fd.accept().await.unwrap();
            let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
            // Portal as a TLS-terminating target (FD4-a); also the default host.
            let mut proxies: std::collections::HashMap<String, ProxyTarget> =
                std::collections::HashMap::new();
            proxies.insert("portal.test".into(), (cp_addr, Some(portal_tls)));
            serve_front_door(
                tcp, &state, &dummy_acceptor, &proxies, Some("portal.test"), &challenge, None, None, None, None, None, None,
                None,
            )
            .await
        });

        // Browser: a real rustls TLS handshake to the edge, trusting the Portal
        // cert, then a plain HTTP GET — expects the control plane's page back.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(portal_cert).unwrap();
        let ccfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(ccfg));
        let tcp = tokio::net::TcpStream::connect(fd_addr).await.unwrap();
        let sni = rustls::pki_types::ServerName::try_from("portal.test").unwrap();
        let mut tls = connector.connect(sni, tcp).await.expect("browser TLS terminates at the edge");
        tls.write_all(b"GET / HTTP/1.0\r\nHost: portal.test\r\n\r\n").await.unwrap();
        let mut resp = Vec::new();
        tls.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.0 200 OK"), "landing page served over HTTPS: {text:?}");
        assert!(text.contains("hello portal"), "control-plane body proxied back to the browser");

        cp_task.await.unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), fd_task).await;
    }

    #[tokio::test]
    async fn front_door_routes_a_second_terminate_host_to_its_own_upstream() {
        // #48: with two terminate targets in the map (Portal + Auth IdP), a browser
        // with SNI=auth.test must terminate with the AUTH cert and be proxied to the
        // AUTH upstream — not the Portal's — proving the host->target map dispatch.
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        crate::transport::install_crypto_provider();

        // Build a self-signed cert + acceptor and a matching browser root for a host.
        fn cert_for(host: &str) -> (tokio_rustls::TlsAcceptor, rustls::RootCertStore) {
            let c = rcgen::generate_simple_self_signed(vec![host.to_string()]).unwrap();
            let der = c.cert.der().clone();
            let cfg = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![der.clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(c.key_pair.serialize_der())),
                )
                .unwrap();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(der).unwrap();
            (tokio_rustls::TlsAcceptor::from(Arc::new(cfg)), roots)
        }
        // A plain-HTTP upstream that replies with a fixed body.
        async fn http_upstream(body: &'static str) -> SocketAddr {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap();
            tokio::spawn(async move {
                if let Ok((mut s, _)) = l.accept().await {
                    let mut b = [0u8; 512];
                    let _ = s.read(&mut b).await;
                    let _ = s
                        .write_all(
                            format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len())
                                .as_bytes(),
                        )
                        .await;
                    let _ = s.shutdown().await;
                }
            });
            a
        }

        let (portal_tls, _) = cert_for("portal.test");
        let (auth_tls, auth_roots) = cert_for("auth.test");
        let portal_up = http_upstream("PORTAL").await;
        let auth_up = http_upstream("AUTH").await;

        let mut proxies: std::collections::HashMap<String, ProxyTarget> =
            std::collections::HashMap::new();
        proxies.insert("portal.test".into(), (portal_up, Some(portal_tls)));
        proxies.insert("auth.test".into(), (auth_up, Some(auth_tls)));

        let dummy = cert_for("edge.test").0;
        let state = Arc::new(EdgeState::<Connection>::new());
        let fd = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fd_addr = fd.local_addr().unwrap();
        let fd_task = tokio::spawn(async move {
            let (tcp, _) = fd.accept().await.unwrap();
            let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
            serve_front_door(tcp, &state, &dummy, &proxies, Some("portal.test"), &challenge, None, None, None, None, None, None, None)
                .await
        });

        // Browser -> SNI=auth.test -> AUTH cert terminates -> AUTH upstream.
        let ccfg = rustls::ClientConfig::builder()
            .with_root_certificates(auth_roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(ccfg));
        let tcp = tokio::net::TcpStream::connect(fd_addr).await.unwrap();
        let sni = rustls::pki_types::ServerName::try_from("auth.test").unwrap();
        let mut tls = connector.connect(sni, tcp).await.expect("auth-host TLS terminates at the edge");
        tls.write_all(b"GET / HTTP/1.0\r\nHost: auth.test\r\n\r\n").await.unwrap();
        let mut resp = Vec::new();
        tls.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains("AUTH"), "routed to the AUTH upstream: {text:?}");
        assert!(!text.contains("PORTAL"), "not the Portal upstream");

        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), fd_task).await;
    }

    #[tokio::test]
    async fn front_door_wires_channel_alpn_to_the_admit_pair_relay_broker() {
        // #106 frontdoor-wire (frozen): the WIRED `:443` front door end-to-end for the
        // channel path. Two `:443`-only members of the same channel each reach the front
        // door over REAL TLS-over-TCP carrying ALPN `ct-edge-channel`, drive the full
        // admission handshake (framed ChannelJoinRequest → possession challenge → OK)
        // through `serve_front_door` — with a `Some(ctx)` built from a MOCK resolver (no
        // HTTP control plane) and a SHARED long-lived pairer. The first parks; the second
        // pairs, so the arm `tokio::spawn`s the relay splice. An app byte must cross both
        // ways: proof the two independently-arriving `:443` members were paired by
        // `ChannelId` and relay-spliced through the front door.
        use ct_common::channel::{
            ChannelGrant, ChannelId, ChannelJoinRequest, Direction, Rights, SignedChannelGrant,
        };
        use ed25519_dalek::{Signer, SigningKey};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        crate::transport::install_crypto_provider();

        const OP_SEED: [u8; 32] = [5u8; 32];
        let op_sk = SigningKey::from_bytes(&OP_SEED);
        let operator = op_sk.verifying_key().to_bytes();
        let channel = ChannelId([0x9Au8; 32]);

        // A grant bound to a real holder pubkey, signed by the operator. `expires_at` is
        // far in the future because `serve_front_door` verifies against the real system
        // clock (unlike the unit tests, which pass a fixed `now`).
        let grant_h = |holder: &SigningKey, dir: Direction| -> SignedChannelGrant {
            let g = ChannelGrant {
                channel,
                holder: holder.verifying_key().to_bytes(),
                direction: dir,
                rights: Rights::ReadWrite,
                delegable: false,
                expires_at: 4_000_000_000,
            };
            let signature = op_sk.sign(&g.signing_bytes()).to_bytes();
            SignedChannelGrant { grant: g, signature }
        };

        let src = SigningKey::from_bytes(&[0xa1u8; 32]); // Initiate → initiator
        let snk = SigningKey::from_bytes(&[0xb2u8; 32]); // Accept → acceptor
        let req_src = ChannelJoinRequest {
            grant: grant_h(&src, Direction::Initiate),
            endpoint: "203.0.113.1:9001".to_string(),
        };
        let req_snk = ChannelJoinRequest {
            grant: grant_h(&snk, Direction::Accept),
            endpoint: "203.0.113.2:9002".to_string(),
        };

        // Mock resolver: yields the operator key iff the channel matches — no HTTP CP.
        struct MockResolver {
            operator: [u8; 32],
            channel: ChannelId,
        }
        impl ChannelMemberResolver for MockResolver {
            fn resolve_member<'a>(
                &'a self,
                channel: ChannelId,
                _holder: [u8; 32],
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>,
                        > + Send
                        + 'a,
                >,
            > {
                let op = self.operator;
                let ok = channel == self.channel;
                Box::pin(async move { ok.then_some((op, None, None)) })
            }
        }

        // #118: one internal CA underpins BOTH the client's trusted root AND the
        // dedicated channel acceptor the ChannelBroker arm terminates with. The channel
        // acceptor advertises the `ct-edge-channel` ALPN (via build_channel_front_door_
        // acceptor); clients trust `ca.root_der()` and connect with server_name "edge.test"
        // (the leaf's SAN), so the CA-signed leaf validates. The SHARED acceptor below is
        // never touched by the channel arm now — kept only to satisfy the signature.
        let ca = crate::pki::Ca::new("ct-edge-ca").unwrap();
        let ca_root = ca.root_der();
        let channel_acceptor =
            crate::pki::build_channel_front_door_acceptor(&ca, vec!["edge.test".to_string()])
                .await
                .unwrap();
        let (shared_leaf, shared_key) = ca.issue(vec!["edge.test".to_string()]).unwrap();
        let scfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![shared_leaf], shared_key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(scfg));

        // The SHARED front-door channel context — one pairer across both connections, so
        // the two independently-arriving members correlate by ChannelId (cloning shares
        // the same Arc pairer + resolver + dedicated channel acceptor).
        let ctx =
            ChannelFrontDoor::standalone(Arc::new(MockResolver { operator, channel }), channel_acceptor);

        let state = Arc::new(EdgeState::<Connection>::new());
        let fd = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fd_addr = fd.local_addr().unwrap();
        let fd_task = tokio::spawn(async move {
            // Accept exactly the two channel members and serve each through the WIRED
            // front door with the shared ctx. The channel ALPN classifies to the
            // ChannelBroker arm; the first parks, the second pairs + spawns the relay.
            for _ in 0..2 {
                let (tcp, _) = fd.accept().await.unwrap();
                let ctx = ctx.clone();
                let acceptor = acceptor.clone();
                let state = state.clone();
                tokio::spawn(async move {
                    let proxies: std::collections::HashMap<String, ProxyTarget> =
                        std::collections::HashMap::new();
                    let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
                    let _ = serve_front_door(
                        tcp, &state, &acceptor, &proxies, None, &challenge, Some(&ctx), None, None, None, None, None,
                        None,
                    )
                    .await;
                });
            }
        });

        // One channel member: TLS-connect to `:443` with ALPN `ct-edge-channel`, run the
        // admission handshake, wait for the relay's OK (written once both are paired),
        // then push one app byte and read the peer's — the bytes cross only if the front
        // door paired the two and relay-spliced them.
        async fn channel_member(
            addr: SocketAddr,
            cert: rustls::pki_types::CertificateDer<'static>,
            req: ChannelJoinRequest,
            holder: SigningKey,
            send_byte: u8,
        ) -> u8 {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert).unwrap();
            let mut ccfg = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            // The front door classifies on the peeked ClientHello ALPN — set it so the
            // connection routes to the ChannelBroker arm (not EdgeRelay / a proxy).
            ccfg.alpn_protocols = vec![b"ct-edge-channel".to_vec()];
            let connector = tokio_rustls::TlsConnector::from(Arc::new(ccfg));
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let sni = rustls::pki_types::ServerName::try_from("edge.test").unwrap();
            let mut tls = connector.connect(sni, tcp).await.expect("channel TLS terminates at :443");

            // #118: the dedicated channel acceptor NEGOTIATES `ct-edge-channel`, so the
            // client sees it echoed post-handshake (previously `None` — a readiness-probe
            // false-negative). This is the assertion the fix exists for.
            assert_eq!(
                tls.get_ref().1.alpn_protocol(),
                Some(b"ct-edge-channel".as_ref()),
                "the :443 channel leg negotiates the ct-edge-channel ALPN (#118)"
            );

            let rb = req.encode();
            tls.write_all(&(rb.len() as u16).to_be_bytes()).await.unwrap();
            tls.write_all(&rb).await.unwrap();
            let mut ch = [0u8; 32];
            tls.read_exact(&mut ch).await.unwrap();
            tls.write_all(&holder.sign(&ch).to_bytes()).await.unwrap();
            // #122: the relay now acks the RICH `OK <endpoint> ...\n` line (the peer's attested
            // Noise key etc.), terminated by a newline so the app/session bytes that follow on
            // this same spliced stream stay unread — consume up to the newline, then the byte.
            let mut ack = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                tls.read_exact(&mut byte).await.unwrap();
                if byte[0] == b'\n' {
                    break;
                }
                ack.push(byte[0]);
            }
            assert!(
                ack.starts_with(b"OK"),
                "the front door acks OK once both :443 members are paired, got {:?}",
                String::from_utf8_lossy(&ack)
            );
            tls.write_all(&[send_byte]).await.unwrap();
            let mut got = [0u8; 1];
            tls.read_exact(&mut got).await.unwrap();
            let _ = tls.shutdown().await;
            got[0]
        }

        let c1 = ca_root.clone();
        let src_task =
            tokio::spawn(async move { channel_member(fd_addr, c1, req_src, src, 0x11).await });
        let c2 = ca_root.clone();
        let snk_task =
            tokio::spawn(async move { channel_member(fd_addr, c2, req_snk, snk, 0x22).await });

        let got_src = src_task.await.expect("src task");
        let got_snk = snk_task.await.expect("snk task");
        assert_eq!(got_src, 0x22, "source got the sink's byte through the wired :443 front door");
        assert_eq!(got_snk, 0x11, "sink got the source's byte through the wired :443 front door");

        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), fd_task).await;
    }

    /// #494: the SAME wired real-TLS front-door pairing as
    /// [`front_door_wires_channel_alpn_to_the_admit_pair_relay_broker`], but with the
    /// KA generation ALPN (`ct-edge-channel-ka`) both v0.4.13+ clients negotiate in the
    /// field -- keepalive=true engages the preamble peek + PrependBytes + NUL-ticking
    /// park pump. In the field two such members hung ~45s with the park consumed and no
    /// ack; the in-memory path is proven clean (channel_broker's `two_ka_members_...`),
    /// so this pins the real-TLS layer. Hard 10s timeout: a hang FAILS loudly.
    #[tokio::test]
    async fn front_door_pairs_two_ka_alpn_members_promptly_over_real_tls_494() {
        use ct_common::channel::{
            ChannelGrant, ChannelId, ChannelJoinRequest, Direction, Rights, SignedChannelGrant,
        };
        use ed25519_dalek::{Signer, SigningKey};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        crate::transport::install_crypto_provider();

        const OP_SEED: [u8; 32] = [6u8; 32];
        let op_sk = SigningKey::from_bytes(&OP_SEED);
        let operator = op_sk.verifying_key().to_bytes();
        let channel = ChannelId([0x4Eu8; 32]);
        let grant_h = |holder: &SigningKey, dir: Direction| -> SignedChannelGrant {
            let g = ChannelGrant {
                channel,
                holder: holder.verifying_key().to_bytes(),
                direction: dir,
                rights: Rights::ReadWrite,
                delegable: false,
                expires_at: 4_000_000_000,
            };
            let signature = op_sk.sign(&g.signing_bytes()).to_bytes();
            SignedChannelGrant { grant: g, signature }
        };
        let src = SigningKey::from_bytes(&[0xc1u8; 32]);
        let snk = SigningKey::from_bytes(&[0xd2u8; 32]);
        let req_src = ChannelJoinRequest {
            grant: grant_h(&src, Direction::Initiate),
            endpoint: ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
        };
        let req_snk = ChannelJoinRequest {
            grant: grant_h(&snk, Direction::Accept),
            endpoint: ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
        };

        struct MockResolver {
            operator: [u8; 32],
            channel: ChannelId,
        }
        impl ChannelMemberResolver for MockResolver {
            fn resolve_member<'a>(
                &'a self,
                channel: ChannelId,
                _holder: [u8; 32],
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>,
                        > + Send
                        + 'a,
                >,
            > {
                let op = self.operator;
                let ok = channel == self.channel;
                Box::pin(async move { ok.then_some((op, None, None)) })
            }
        }

        let ca = crate::pki::Ca::new("ct-edge-ca").unwrap();
        let ca_root = ca.root_der();
        let channel_acceptor =
            crate::pki::build_channel_front_door_acceptor(&ca, vec!["edge.test".to_string()])
                .await
                .unwrap();
        let (shared_leaf, shared_key) = ca.issue(vec!["edge.test".to_string()]).unwrap();
        let scfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![shared_leaf], shared_key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(scfg));
        let ctx =
            ChannelFrontDoor::standalone(Arc::new(MockResolver { operator, channel }), channel_acceptor);

        let state = Arc::new(EdgeState::<Connection>::new());
        let fd = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fd_addr = fd.local_addr().unwrap();
        let fd_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (tcp, _) = fd.accept().await.unwrap();
                let ctx = ctx.clone();
                let acceptor = acceptor.clone();
                let state = state.clone();
                tokio::spawn(async move {
                    let proxies: std::collections::HashMap<String, ProxyTarget> =
                        std::collections::HashMap::new();
                    let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
                    let _ = serve_front_door(
                        tcp, &state, &acceptor, &proxies, None, &challenge, Some(&ctx), None, None, None, None, None,
                        None,
                    )
                    .await;
                });
            }
        });

        // A KA-generation member (v0.4.13 shape): ka ALPN, NO phase preamble, ack read
        // tolerating leading keepalive NULs (#500).
        async fn ka_member(
            addr: SocketAddr,
            cert: rustls::pki_types::CertificateDer<'static>,
            req: ChannelJoinRequest,
            holder: SigningKey,
            send_byte: u8,
        ) -> u8 {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert).unwrap();
            let mut ccfg = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            ccfg.alpn_protocols = vec![crate::sni::CT_EDGE_CHANNEL_KA_ALPN.as_bytes().to_vec()];
            let connector = tokio_rustls::TlsConnector::from(Arc::new(ccfg));
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let sni = rustls::pki_types::ServerName::try_from("edge.test").unwrap();
            let mut tls = connector.connect(sni, tcp).await.expect("channel TLS terminates");
            assert_eq!(
                tls.get_ref().1.alpn_protocol(),
                Some(crate::sni::CT_EDGE_CHANNEL_KA_ALPN.as_bytes()),
                "the ka ALPN negotiates (#500)"
            );
            let rb = req.encode();
            tls.write_all(&(rb.len() as u16).to_be_bytes()).await.unwrap();
            tls.write_all(&rb).await.unwrap();
            let mut ch = [0u8; 32];
            tls.read_exact(&mut ch).await.unwrap();
            tls.write_all(&holder.sign(&ch).to_bytes()).await.unwrap();
            let mut ack = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                tls.read_exact(&mut byte).await.unwrap();
                if byte[0] == 0 && ack.is_empty() {
                    continue; // leading park keepalive NUL (#500)
                }
                if byte[0] == b'\n' {
                    break;
                }
                ack.push(byte[0]);
            }
            assert!(
                ack.starts_with(b"OK"),
                "paired ack expected, got {:?}",
                String::from_utf8_lossy(&ack)
            );
            tls.write_all(&[send_byte]).await.unwrap();
            let mut got = [0u8; 1];
            tls.read_exact(&mut got).await.unwrap();
            let _ = tls.shutdown().await;
            got[0]
        }

        let c1 = ca_root.clone();
        let src_task = tokio::spawn(async move { ka_member(fd_addr, c1, req_src, src, 0x33).await });
        let c2 = ca_root.clone();
        let snk_task = tokio::spawn(async move { ka_member(fd_addr, c2, req_snk, snk, 0x44).await });

        let (got_src, got_snk) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            (src_task.await.expect("src"), snk_task.await.expect("snk"))
        })
        .await
        .expect("KA members must be acked+spliced promptly -- a hang here is the #494 field defect");
        assert_eq!(got_src, 0x44, "source got the sink's byte (ka path)");
        assert_eq!(got_snk, 0x33, "sink got the source's byte (ka path)");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), fd_task).await;
    }

    #[tokio::test]
    async fn front_door_channel_arm_holds_the_connection_caps_permit_while_parked_and_relaying_451() {
        // #451, end to end through `serve_front_door`'s own accept-loop wiring (production
        // shape, not just the lower-level `channel_broker` unit): a real `ConnectionCap`
        // permit, acquired the way `run_edge`'s `:443` front-door loop does, is passed all
        // the way into `serve_front_door`'s new `permit` parameter. Before the fix,
        // `serve_front_door` returned (dropping the caller's permit) the instant a lone
        // `:443` channel member parked -- even though its live TLS stream stayed open inside
        // `ChannelFrontDoor`'s pairer -- and a matched pair's relay ran on a freshly spawned
        // task holding NO permit at all. Proves both are now fixed: the cap's available-permit
        // count drops and STAYS down while a member is parked (not released the instant
        // `serve_front_door` returns), and while a matched pair actively relays, both
        // permits are accounted for.
        use ct_common::channel::{
            ChannelGrant, ChannelId, ChannelJoinRequest, Direction, Rights, SignedChannelGrant,
        };
        use ed25519_dalek::{Signer, SigningKey};

        crate::transport::install_crypto_provider();

        let operator = SigningKey::from_bytes(&[0x39u8; 32]);
        let operator_pk = operator.verifying_key().to_bytes();
        let channel = ChannelId([0x39u8; 32]);

        struct MockResolver {
            operator: [u8; 32],
            channel: ChannelId,
        }
        impl ChannelMemberResolver for MockResolver {
            fn resolve_member<'a>(
                &'a self,
                channel: ChannelId,
                _holder: [u8; 32],
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>
                        + Send
                        + 'a,
                >,
            > {
                let op = self.operator;
                let ok = channel == self.channel;
                Box::pin(async move { ok.then_some((op, None, None)) })
            }
        }

        let ca = crate::pki::Ca::new("ct-edge-ca").unwrap();
        let channel_acceptor =
            crate::pki::build_channel_front_door_acceptor(&ca, vec!["edge.test".to_string()])
                .await
                .unwrap();
        let (shared_leaf, shared_key) = ca.issue(vec!["edge.test".to_string()]).unwrap();
        let scfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![shared_leaf], shared_key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(scfg));

        let ctx = ChannelFrontDoor::standalone(
            Arc::new(MockResolver { operator: operator_pk, channel }),
            channel_acceptor,
        );
        let cap = ConnectionCap::new(2);
        let state = Arc::new(EdgeState::<Connection>::new());
        let fd = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fd_addr = fd.local_addr().unwrap();
        let cap_loop = cap.clone();
        let fd_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (tcp, _) = fd.accept().await.unwrap();
                // Mirrors `run_edge`'s real front-door accept loop: acquire the cap permit
                // BEFORE dispatching, pass it into `serve_front_door`.
                let permit = cap_loop.try_admit().expect("cap has room");
                let ctx = ctx.clone();
                let acceptor = acceptor.clone();
                let state = state.clone();
                tokio::spawn(async move {
                    let proxies: std::collections::HashMap<String, ProxyTarget> =
                        std::collections::HashMap::new();
                    let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
                    let _ = serve_front_door(
                        tcp, &state, &acceptor, &proxies, None, &challenge, Some(&ctx), None, None, None, None,
                        None, Some(permit),
                    )
                    .await;
                });
            }
        });

        async fn connect_and_admit(
            addr: SocketAddr,
            cert: rustls::pki_types::CertificateDer<'static>,
            req: ChannelJoinRequest,
            holder: SigningKey,
        ) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert).unwrap();
            let mut ccfg = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            ccfg.alpn_protocols = vec![b"ct-edge-channel".to_vec()];
            let connector = tokio_rustls::TlsConnector::from(Arc::new(ccfg));
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let sni = rustls::pki_types::ServerName::try_from("edge.test").unwrap();
            let mut tls = connector.connect(sni, tcp).await.expect("channel TLS terminates at :443");
            let rb = req.encode();
            tls.write_all(&(rb.len() as u16).to_be_bytes()).await.unwrap();
            tls.write_all(&rb).await.unwrap();
            let mut ch = [0u8; 32];
            tls.read_exact(&mut ch).await.unwrap();
            tls.write_all(&holder.sign(&ch).to_bytes()).await.unwrap();
            tls
        }

        let ca_root = ca.root_der();
        assert_eq!(cap.available(), 2, "nothing admitted yet");

        // Member 1 connects and admits, then parks (no partner yet) -- held open (not
        // dropped) so its live TLS stream genuinely stays open, exactly the #451 scenario.
        let src = SigningKey::from_bytes(&[0x40u8; 32]);
        let req_src = ChannelJoinRequest {
            grant: {
                let g = ChannelGrant {
                    channel,
                    holder: src.verifying_key().to_bytes(),
                    direction: Direction::Initiate,
                    rights: Rights::ReadWrite,
                    delegable: false,
                    expires_at: 4_000_000_000,
                };
                let signature = operator.sign(&g.signing_bytes()).to_bytes();
                SignedChannelGrant { grant: g, signature }
            },
            endpoint: "relay-only".to_string(),
        };
        let member1 = connect_and_admit(fd_addr, ca_root.clone(), req_src, src).await;

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(
            cap.available(),
            1,
            "the parked member's permit must still be held — the connection is live and \
             uncounted-for in the pairer, the #451 gap"
        );

        // Member 2 joins the SAME channel: pairs with member 1, and the arm spawns the relay
        // splice. Both members' streams are held open (not dropped), so the relay is actively
        // live while we sample the cap.
        let snk = SigningKey::from_bytes(&[0x41u8; 32]);
        let req_snk = ChannelJoinRequest {
            grant: {
                let g = ChannelGrant {
                    channel,
                    holder: snk.verifying_key().to_bytes(),
                    direction: Direction::Accept,
                    rights: Rights::ReadWrite,
                    delegable: false,
                    expires_at: 4_000_000_000,
                };
                let signature = operator.sign(&g.signing_bytes()).to_bytes();
                SignedChannelGrant { grant: g, signature }
            },
            endpoint: "relay-only".to_string(),
        };
        let member2 = connect_and_admit(fd_addr, ca_root, req_snk, snk).await;

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(
            cap.available(),
            0,
            "both live sockets of the matched, actively-relaying pair are counted against the \
             cap — not 0, per #451"
        );

        drop(member1);
        drop(member2);
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(cap.available(), 2, "both permits release once the relay (and the pair) end");

        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), fd_task).await;
    }
    #[test]
    fn both_legs_share_one_classifier_and_label_themselves_533_follow() {
        // #533 classified benign client aborts on the `:443` arm and left the `:4433`
        // TCP-fallback arm logging every failure flat. Measured on 2026-08-17: 44
        // error-shaped lines in three hours, all ordinary aborts -- in exactly the log an
        // operator reads while investigating ct-agent#15's "the edge drops connections".
        // The noise was part of why the fault looked real.
        let log = front_door_abort_log(FRONT_DOOR_ABORT_LOG_WINDOW_SECS, FRONT_DOOR_ABORT_LOG_MAX_TRACKED_CLASSES);
        let eof: BoxError = std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "peer closed connection without sending TLS close_notify",
        )
        .into();

        // Same input, both legs: classified benign, first occurrence logged in full.
        assert!(matches!(
            log_front_door_error_on(LEG_FRONT_DOOR, &log, 1_000, &eof),
            FrontDoorErrorLog::BenignFirst(_)
        ));
        let log2 = front_door_abort_log(FRONT_DOOR_ABORT_LOG_WINDOW_SECS, FRONT_DOOR_ABORT_LOG_MAX_TRACKED_CLASSES);
        assert!(matches!(
            log_front_door_error_on(LEG_TCP_FALLBACK, &log2, 1_000, &eof),
            FrontDoorErrorLog::BenignFirst(_)
        ));
        // Repeats within the window are aggregated on the fallback leg too -- otherwise the
        // classification would only rename the flood instead of condensing it.
        assert!(matches!(
            log_front_door_error_on(LEG_TCP_FALLBACK, &log2, 1_001, &eof),
            FrontDoorErrorLog::BenignSuppressed(_)
        ));
        // The two legs keep SEPARATE windows: one leg's aborts must not silence the other's
        // first line, or an operator loses the ability to tell which listener is talking.
        assert!(matches!(
            log_front_door_error_on(LEG_FRONT_DOOR, &log, 1_001, &eof),
            FrontDoorErrorLog::BenignSuppressed(_)
        ));

        // An unclassified error stays loud on both legs -- the classification must never
        // become a way to lose a real fault.
        let odd: BoxError = "something genuinely unexpected".into();
        assert!(matches!(
            log_front_door_error_on(LEG_TCP_FALLBACK, &log2, 1_002, &odd),
            FrontDoorErrorLog::Loud
        ));
    }

    #[test]
    fn every_channel_join_path_shares_one_per_ip_budget_547() {
        // #547: the budget only works if ALL paths feed and consult it. Three did; the
        // relay-gate arm of the `:443` front door did not, and a refused attempt is more
        // expensive there than anywhere else (TLS, a control-plane member lookup, an
        // Ed25519 verify, fresh challenge bytes) -- so it is the last place that should
        // have been left unmetered.
        //
        // Asserted at the budget itself rather than through a live TLS handshake: the
        // property is that one IP's refusals on ANY path exhaust the same budget that every
        // path checks, and that is a property of the shared JoinRefusalPenalty.
        let penalty = crate::state::JoinRefusalPenalty::new();
        let ip: std::net::IpAddr = [198, 51, 100, 7].into();
        let now = 1_000u64;
        assert!(!penalty.penalized(ip, now), "an unseen IP starts unpenalised");

        // Refusals accumulate regardless of which path reported them.
        let mut engaged = false;
        for _ in 0..64 {
            engaged |= penalty.note_definitive_refusal(ip, now);
        }
        assert!(engaged, "a definitive-refusal run must engage the budget");
        assert!(penalty.penalized(ip, now), "and the SAME budget is what every path reads");

        // A different source is unaffected -- the budget is per IP, not global, so one
        // hostile peer cannot shed everyone else's joins.
        let other: std::net::IpAddr = [203, 0, 113, 9].into();
        assert!(!penalty.penalized(other, now), "the penalty must not be collective");

        // And it is a window, not a life sentence: a later window starts clean.
        assert!(
            !penalty.penalized(ip, now + 10_000),
            "the budget is per window -- a peer that misbehaved once is not banned forever"
        );
    }

}
