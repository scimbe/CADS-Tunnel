//! Edge serve orchestration (M5.1c).
//!
//! The Agent-registration path: an Agent opens a control stream and registers
//! the Routing Token it serves; the Edge stores the connection in [`EdgeState`]
//! so a later Client rendezvous for that token can be routed to it. The Client
//! route→relay path is exercised end to end in the M5.6 testbed smoke.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::config::EdgeConfig;
use crate::relay::{relay, relay_quic};
use crate::state::{ConnectionCap, EdgeState};
use crate::pki::{build_dual_edge_from_ca, build_server_endpoint_from_ca, Ca};
use crate::transport::save_cert;
use ct_common::pow::{check_request, Challenge};
use ct_common::RoutingToken;
use quinn::{Connection, RecvStream, SendStream};
use rand::RngCore;
use tokio::io::{join, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Handle one Agent registration on `conn`: read `role='A'(1) | token(32)` on a
/// fresh bi-stream, register the connection in `state`, ack `OK`, and return the
/// registered token.
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
const TCP_FALLBACK_DELIVER_WAIT: Duration = Duration::from_millis(1500);

/// First 8 hex chars of a token, for correlating an Edge trace line with a
/// field-supplied token during cross-host diagnosis.
fn token_hex(token: &RoutingToken) -> String {
    token.0.iter().take(4).map(|b| format!("{b:02x}")).collect()
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
    let th = token_hex(token);
    let agents = state.routes(token);
    if agents.is_empty() {
        edge_trace(format_args!("route token={th} -> MISS (no registration)"));
        return Err("no agent tunnel for token".into());
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
pub async fn route_and_relay(
    state: &EdgeState<Connection>,
    token: &RoutingToken,
    client_send: SendStream,
    client_recv: RecvStream,
) -> Result<(), BoxError> {
    let (agent_send, agent_recv) = open_agent_stream(state, token).await?;
    let (a, b) = relay_quic(client_send, client_recv, agent_send, agent_recv, &token_hex(token)).await?;
    state.note_relay(token, a, b); // #10 O2
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
    if state.has_tcp_agent(&token) {
        let joined: crate::state::BoxedStream = Box::new(Prepend {
            pre: hello,
            pos: 0,
            inner: inbound,
        });
        return match state.deliver_to_tcp_agent(&token, joined) {
            Ok(()) => Ok(()),
            Err(_) => Err("tcp-fallback agent vanished before delivery".into()),
        };
    }
    match open_agent_stream(state, &token).await {
        Ok((mut agent_send, agent_recv)) => {
            // Replay the buffered ClientHello to the Agent first, then relay the
            // rest so the browser<->origin TLS handshake completes end-to-end.
            agent_send.write_all(&hello).await?;
            let mut agent = join(agent_recv, agent_send);
            let (a, b) = relay(&mut inbound, &mut agent).await?;
            state.note_relay(&token, a, b);
            Ok(())
        }
        Err(e) => {
            // No QUIC registration -- likely a TCP-fallback-only agent (UDP
            // blocked) whose pool was momentarily exhausted by a burst of
            // parallel browser connections (#229 follow-up: real page loads
            // open several at once). Give it a brief window to free a slot
            // rather than failing this request outright.
            if state.wait_for_tcp_agent(&token, TCP_FALLBACK_DELIVER_WAIT).await {
                let joined: crate::state::BoxedStream = Box::new(Prepend {
                    pre: hello,
                    pos: 0,
                    inner: inbound,
                });
                if state.deliver_to_tcp_agent(&token, joined).is_ok() {
                    return Ok(());
                }
            }
            Err(e)
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
/// [`EdgeState::deliver_to_tcp_agent`] rather than [`open_agent_stream`],
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
    let tls = wildcard_acceptor.accept(inbound).await?;
    // #233 follow-up (found live, #229): a TCP-fallback agent (UDP/QUIC
    // blocked) is parked with no QUIC connection to open a stream on at all
    // -- `open_agent_stream` below would always fail "no agent tunnel for
    // token" for it, indistinguishable from a genuinely dead agent. Hand it
    // the DECRYPTED stream directly, the same way `serve_sni_passthrough`
    // hands it the raw (still-encrypted) one -- the only difference is TLS
    // already came off at the edge here.
    if state.has_tcp_agent(&token) {
        let boxed: crate::state::BoxedStream = Box::new(tls);
        return match state.deliver_to_tcp_agent(&token, boxed) {
            Ok(()) => Ok(()),
            Err(_) => Err("tcp-fallback agent vanished before delivery".into()),
        };
    }
    let mut tls = tls;
    match open_agent_stream(state, &token).await {
        Ok((agent_send, agent_recv)) => {
            let mut agent = join(agent_recv, agent_send);
            let (a, b) = relay(&mut tls, &mut agent).await?;
            state.note_relay(&token, a, b);
            Ok(())
        }
        Err(e) => {
            // Same momentarily-exhausted-pool recovery as serve_sni_passthrough
            // (#229 follow-up).
            if state.wait_for_tcp_agent(&token, TCP_FALLBACK_DELIVER_WAIT).await {
                let boxed: crate::state::BoxedStream = Box::new(tls);
                if state.deliver_to_tcp_agent(&token, boxed).is_ok() {
                    return Ok(());
                }
            }
            Err(e)
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
pub async fn serve_http_redirect<S>(mut inbound: S) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read up to the header terminator (bounded — a redirect never needs a body).
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    loop {
        let n = inbound.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16384 {
            break;
        }
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
fn spawn_front_door_pairer_reaper<T, N>(
    pairer: Arc<std::sync::Mutex<crate::channel_broker::ChannelPairer<T>>>,
    interval: Duration,
    now_fn: N,
) where
    T: Send + 'static,
    N: Fn() -> ct_common::channel::UnixSeconds + Send + Sync + 'static,
{
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let expired = pairer.lock().unwrap().drain_expired(now_fn());
            if !expired.is_empty() {
                eprintln!(
                    "ct-edge: front-door channel pairer reaped {} member(s) parked past their TTL with no partner",
                    expired.len()
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
) -> Result<(), BoxError> {
    // #121 Phase B1: the member's reflexive (post-NAT) source, captured from the accepted TCP
    // socket before `inbound` is consumed, so a `:443`/front-door channel join can observe it
    // (the TLS-TCP analog of QUIC's `conn.remote_address()`).
    let observed = inbound.peer_addr()?;
    let hello = read_client_hello_bytes_bounded(&mut inbound).await?;
    let alpn = crate::sni::peek_alpn(&hello);
    let sni = crate::sni::peek_sni(&hello);
    let hosts: Vec<&str> = proxies.keys().map(|s| s.as_str()).collect();
    match crate::sni::classify_front_door(&alpn, sni.as_deref(), &hosts, default_host) {
        crate::sni::FrontDoorRoute::EdgeRelay => {
            let joined = Prepend {
                pre: hello,
                pos: 0,
                inner: inbound,
            };
            let tls = acceptor.accept(joined).await?;
            serve_tcp_connection(tls, state, challenge).await
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
                    let mut tls = pacc.accept(joined).await?;
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
                    if let Some(peer_addr) =
                        crate::edge_mesh_client::lookup_owner_by_host(&mesh.cp_url, &mesh.admin_token, &host).await
                    {
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
            let tls: FrontDoorChannelStream = ctx
                .acceptor
                .accept(joined)
                .await
                .map_err(|e| { eprintln!("ct-edge: channel-join NO [tls-accept]: {e}"); e })?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            // Same closure shape the QUIC broker builds from its `ChannelAuthorizer`,
            // here routed through the boxed resolver so a test can supply a mock.
            let resolver = ctx.resolver.clone();
            let authorize = move |c: ct_common::channel::ChannelId, h: [u8; 32]| {
                let resolver = resolver.clone();
                async move { resolver.resolve_member(c, h).await }
            };
            // Boxed into the shared cross-transport stream type (#XXX) so this `:443`
            // member correlates through the SAME pairer a browser member
            // (ws_channel.rs) offers itself to -- either can now be the partner.
            let boxed: crate::channel_broker::BoxedChannelStream = Box::pin(tls);
            let paired = crate::channel_broker::admit_and_pair_on_stream(
                boxed,
                observed,
                now,
                CHANNEL_JOIN_TIMEOUT,
                &authorize,
                now + CHANNEL_PARK_TTL_SECS,
                &ctx.pairer,
            )
            .await?;
            if let Some((a, b)) = paired {
                tokio::spawn(async move {
                    if let Err(e) =
                        crate::channel_broker::finish_relay_pair_over_streams(a, b, now).await
                    {
                        eprintln!("ct-edge: front-door :443 channel relay ended: {e}");
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
            let joined = Prepend {
                pre: hello,
                pos: 0,
                inner: inbound,
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            crate::relay_gate::serve_relay_gate(joined, ctx, now).await
        }
        crate::sni::FrontDoorRoute::Reject => Ok(()),
    }
}

/// Serve one connection by dispatching on its first stream's role byte. `'A'`
/// registers an Agent tunnel (`token`); `'C'` runs a PoW-gated rendezvous, then
/// routes and relays the same stream to the Agent. This is the unified
/// per-connection Edge protocol the daemon's accept loop runs.
pub async fn serve_connection(
    conn: &Connection,
    state: &EdgeState<Connection>,
    challenge: &Challenge,
) -> Result<Option<(RoutingToken, u64)>, BoxError> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let mut role = [0u8; 1];
    recv.read_exact(&mut role).await?;

    match role[0] {
        b'A' => {
            let mut token = [0u8; 32];
            recv.read_exact(&mut token).await?;
            let token = RoutingToken(token);
            // #27 RB3: a revoked token stays down even though the agent keeps
            // reconnecting — refuse the registration instead of accepting it.
            if state.is_revoked(&token) {
                send.write_all(b"NO").await?;
                send.finish()?;
                return Ok(None);
            }
            let reg = state.register_with_candidate(token.clone(), conn.clone(), conn.remote_address());
            send.write_all(b"OK").await?;
            send.finish()?;
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
            recv.read_exact(&mut req).await?;
            let token = check_request(challenge, &req).map_err(|_| "proof of work rejected")?;

            // #86 (ADR-0018): per-token rendezvous rate limit — PoW raises per-attempt
            // cost, this caps how many rendezvous a single token drives per window.
            if !state.rendezvous_allowed(&token, rendezvous_window()) {
                return Err("rendezvous rate limit exceeded".into());
            }

            // A QUIC client must also reach a TCP-fallback agent (#13): the TCP
            // path prefers a parked TCP agent, and the QUIC path must mirror it or
            // a QUIC-client → TCP-agent tunnel is invisible and dies with
            // `early eof`. If one is parked, hand off the joined client stream
            // (cross-transport QUIC↔TCP relay); otherwise keep the QUIC→QUIC
            // relay_quic path unchanged.
            if state.has_tcp_agent(&token) {
                match state.deliver_to_tcp_agent(&token, Box::new(join(recv, send))) {
                    Ok(()) => return Ok(None),
                    // Raced (the parked agent was consumed between check and
                    // deliver) → relay this client to a QUIC agent instead.
                    Err(mut client) => {
                        let (agent_send, agent_recv) = open_agent_stream(state, &token).await?;
                        let mut agent = join(agent_recv, agent_send);
                        let (a, b) = relay(&mut client, &mut agent).await?;
                        state.note_relay(&token, a, b);
                        return Ok(None);
                    }
                }
            }
            match open_agent_stream(state, &token).await {
                Ok((agent_send, agent_recv)) => {
                    let (a, b) =
                        relay_quic(send, recv, agent_send, agent_recv, &token_hex(&token)).await?;
                    state.note_relay(&token, a, b); // #10 O2
                    Ok(None)
                }
                Err(e) => {
                    // Same momentarily-exhausted-pool recovery as
                    // serve_sni_passthrough (#229 follow-up): this QUIC client
                    // may be reaching an agent that is TCP-fallback-only.
                    if state.wait_for_tcp_agent(&token, TCP_FALLBACK_DELIVER_WAIT).await
                        && state
                            .deliver_to_tcp_agent(&token, Box::new(join(recv, send)))
                            .is_ok()
                    {
                        return Ok(None);
                    }
                    Err(e)
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
                send.write_all(b"NO").await?;
                send.finish()?;
                return Ok(None);
            }
            // Takeover-safe (#23 BP4a): refuse if the hostname is already bound to
            // a different tunnel, so a later bind can't silently steal the route.
            if state.register_host(host, token) {
                send.write_all(b"OK").await?;
            } else {
                send.write_all(b"NO").await?;
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

/// Serve one connection over the **TCP fallback** (M12.2b, issue #3 / P1.2c-3b)
/// by dispatching on the first byte's role:
///
/// * `'A'` — an Agent registers over TCP (UDP/QUIC blocked): read the token, ack
///   `OK`, park in the rendezvous, and relay this stream to the first Client that
///   arrives (single-tunnel — a TCP agent has one stream, no QUIC-style muxing).
/// * `'C'` — a Client runs the `'C'` rendezvous (challenge → PoW) and is delivered
///   to a parked TCP agent if one exists, else relayed to a QUIC-registered agent.
///
/// The relay is transport-agnostic, so any Client (TCP or QUIC) bridges to either
/// a TCP-registered or a QUIC-registered agent.
pub async fn serve_tcp_connection<S>(
    mut stream: S,
    state: &EdgeState<Connection>,
    challenge: &Challenge,
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
            let token = tokio::time::timeout(TCP_FALLBACK_ADMISSION_TIMEOUT, async {
                let mut token_buf = [0u8; 32];
                stream.read_exact(&mut token_buf).await?;
                let token = RoutingToken(token_buf);
                stream.write_all(b"OK").await?;
                stream.flush().await?;
                Ok::<_, BoxError>(token)
            })
            .await
            .map_err(|_| "tcp-fallback: role 'A' admission timed out")??;
            // Park and await a Client, then relay this agent stream to it.
            match state.park_tcp_agent(token).await {
                Ok(mut client) => {
                    relay(&mut stream, &mut client).await?;
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
        b'B' => {
            // Browser register (#41 FB1): register the tunnel AND bind a public
            // hostname in ONE message — the TLS-TCP fallback has a single stream,
            // so it can't carry a separate 'H' bind like the QUIC path. Wire:
            // `'B' | token(32) | host_len(2 BE) | host`.
            // #258: bound the admission exchange, same as arm 'A'. `None` means
            // admission was refused inline (NO already sent) -- just return.
            let admitted = tokio::time::timeout(TCP_FALLBACK_ADMISSION_TIMEOUT, async {
                let mut token_buf = [0u8; 32];
                stream.read_exact(&mut token_buf).await?;
                let token = RoutingToken(token_buf);
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
                if !state.host_bind_allowed(&host, &token) || !state.register_host(&host, token.clone()) {
                    stream.write_all(b"NO").await?;
                    stream.flush().await?;
                    return Ok::<_, BoxError>(None);
                }
                stream.write_all(b"OK").await?;
                stream.flush().await?;
                Ok(Some(token))
            })
            .await
            .map_err(|_| "tcp-fallback: role 'B' admission timed out")??;
            let Some(token) = admitted else { return Ok(()) };
            match state.park_tcp_agent(token).await {
                Ok(mut client) => {
                    relay(&mut stream, &mut client).await?;
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

                // #86 (ADR-0018): per-token rendezvous rate limit (same as the QUIC path).
                if !state.rendezvous_allowed(&token, rendezvous_window()) {
                    return Err("rendezvous rate limit exceeded".into());
                }
                Ok::<_, BoxError>(token)
            })
            .await
            .map_err(|_| "tcp-fallback: role 'C' admission timed out")??;

            // Prefer a parked TCP-fallback agent; else relay to a QUIC agent.
            match state.deliver_to_tcp_agent(&token, Box::new(stream)) {
                Ok(()) => Ok(()),
                Err(stream) => match open_agent_stream(state, &token).await {
                    Ok((agent_send, agent_recv)) => {
                        let mut stream = stream;
                        let mut agent = join(agent_recv, agent_send);
                        let (a, b) = relay(&mut stream, &mut agent).await?;
                        state.note_relay(&token, a, b); // #10 O2
                        Ok(())
                    }
                    Err(e) => {
                        // Momentarily-exhausted pool recovery (#229 follow-up):
                        // give a burst of parallel browser connections a brief
                        // window to find a freed-up TCP-fallback slot.
                        if state.wait_for_tcp_agent(&token, TCP_FALLBACK_DELIVER_WAIT).await
                            && state.deliver_to_tcp_agent(&token, stream).is_ok()
                        {
                            return Ok(());
                        }
                        Err(e)
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

            match state.deliver_to_tcp_agent(&token, Box::new(stream)) {
                Ok(()) => Ok(()),
                Err(stream) => match open_agent_stream(state, &token).await {
                    Ok((agent_send, agent_recv)) => {
                        let mut stream = stream;
                        let mut agent = join(agent_recv, agent_send);
                        let (a, b) = relay(&mut stream, &mut agent).await?;
                        state.note_relay(&token, a, b);
                        Ok(())
                    }
                    Err(e) => {
                        // Momentarily-exhausted pool recovery (#229 follow-up),
                        // same as the 'C' arm above.
                        if state.wait_for_tcp_agent(&token, TCP_FALLBACK_DELIVER_WAIT).await
                            && state.deliver_to_tcp_agent(&token, stream).is_ok()
                        {
                            return Ok(());
                        }
                        Err(e)
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
    let mut peer = crate::transport::tcp_tls_connect(target, edge_cert).await?;

    let host_bytes = host.as_bytes();
    let host_len: u16 = host_bytes.len().try_into().map_err(|_| "hostname too long for the mesh-relay frame")?;
    let mut msg = vec![b'M'];
    msg.extend_from_slice(&admin_token);
    msg.extend_from_slice(&host_len.to_be_bytes());
    msg.extend_from_slice(host_bytes);
    peer.write_all(&msg).await?;
    peer.flush().await?;

    let mut ack = [0u8; 2];
    peer.read_exact(&mut ack).await?;
    if &ack != b"OK" {
        return Err(format!("peer edge refused mesh-relay for '{host}'").into());
    }

    relay(&mut inbound, &mut peer).await?;
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
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / WINDOW_SECS)
        .unwrap_or(0)
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
    // #27 RB3: enable the authenticated revoke op only when the shared admin
    // secret is configured (64-hex CT_EDGE_ADMIN_TOKEN, matching the control
    // plane's CT_CP_EDGE_ADMIN_TOKEN). Absent -> revocation stays disabled.
    if let Some(tok) = std::env::var("CT_EDGE_ADMIN_TOKEN")
        .ok()
        .and_then(|s| parse_admin_token_hex(&s))
    {
        state.set_admin_token(tok);
        eprintln!("ct-edge: tunnel revocation enabled (CT_EDGE_ADMIN_TOKEN set)");
        // #23 BP4b / #84: require hostname-ownership authorization for 'H'/'B' binds —
        // fail-closed by default when a public front door is exposed (CT_FRONT_DOOR),
        // so an anonymous bind can't squat an unbound name on :443.
        let front_door_set = std::env::var_os("CT_FRONT_DOOR").is_some();
        if host_auth_required(
            std::env::var("CT_EDGE_REQUIRE_HOST_AUTH").ok().as_deref(),
            front_door_set,
        ) {
            state.require_host_auth();
            eprintln!(
                "ct-edge: hostname-ownership authorization required (#84 — fail-closed default under \
                 CT_FRONT_DOOR; set CT_EDGE_REQUIRE_HOST_AUTH=0 to disable)"
            );
        } else if front_door_set {
            eprintln!(
                "ct-edge: WARNING — CT_FRONT_DOOR is exposed with host-auth DISABLED; any routing-token \
                 holder can squat an unbound hostname (#84)"
            );
        }
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
                let rstate = state.clone();
                let r_cp_url = cp_url.clone();
                let r_edge_id = edge_id.clone();
                tokio::spawn(async move {
                    let pairs = crate::edge_mesh_client::rehydrate(&r_cp_url, &tok, &r_edge_id).await;
                    let n = pairs.len();
                    for pair in pairs {
                        if let Some(host) = pair.hostname {
                            rstate.authorize_host(&host, RoutingToken(pair.token));
                        }
                    }
                    eprintln!(
                        "ct-edge: rehydrated {n} hostname authorization(s) from {r_cp_url} (edge_id={r_edge_id})"
                    );
                });
                // #327: replay the control plane's durable revoked-token record into
                // this boot's local revoked set — without this, a restart silently
                // forgets every revocation and a still-reconnecting Agent for an
                // already-revoked tunnel would successfully re-register. Same
                // fire-and-forget shape as the rehydration above (accepted trade-off:
                // a brief boot window before this lands, never a blocked/hung boot).
                let vstate = state.clone();
                let v_cp_url = cp_url.clone();
                tokio::spawn(async move {
                    let tokens = crate::edge_mesh_client::fetch_revoked_tokens(&v_cp_url, &tok).await;
                    let n = tokens.len();
                    vstate.seed_revoked_tokens(tokens.into_iter().map(RoutingToken));
                    eprintln!("ct-edge: replayed {n} revoked token(s) from {v_cp_url}");
                });
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
                    let conn_cap_bl = conn_cap.clone();
                    let browser_tunnel_cap_bl = browser_tunnel_cap.clone();
                    tokio::spawn(async move {
                        while let Ok((tcp, _)) = bl.accept().await {
                            let permit = match &conn_cap_bl {
                                Some(cap) => match cap.try_admit() {
                                    Some(p) => Some(p),
                                    None => {
                                        drop(tcp);
                                        continue;
                                    }
                                },
                                None => None,
                            };
                            let sub_permit = match &browser_tunnel_cap_bl {
                                Some(cap) => match cap.try_admit() {
                                    Some(p) => Some(p),
                                    None => {
                                        drop(tcp);
                                        continue;
                                    }
                                },
                                None => None,
                            };
                            let state = bstate.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                let _sub_permit = sub_permit;
                                let _ = serve_sni_passthrough(tcp, &state).await;
                            });
                        }
                    });
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
    // Cross-transport pairing (#XXX): populated below (inside the CT_FRONT_DOOR arm,
    // where the `:443` channel broker's pairer is actually constructed) whenever
    // channel brokering is enabled; the browser WebSocket listener further down
    // (unconditional on CT_FRONT_DOOR -- it can run standalone) picks it up if
    // present, so a `:443`/QUIC member and a browser member of the same channel
    // correlate through one pairer and can pair with each other.
    let mut shared_channel_pairer: Option<crate::channel_broker::SharedChannelPairer> = None;
    if let Ok(addr) = std::env::var("CT_FRONT_DOOR") {
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
                                Some(MeshRelayConfig { cp_url, admin_token, edge_cert: ca_root.clone() })
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
                            // #118: dedicated channel acceptor advertising `ct-edge-channel`
                            // (a CA-signed leaf; the same `ca` that issued the shared edge
                            // leaf) so the `:443` channel leg negotiates the ALPN. The shared
                            // `acceptor` keeps its empty ALPN for the `EdgeRelay` leg.
                            let channel_acceptor = crate::pki::build_channel_front_door_acceptor(
                                &ca,
                                vec!["localhost".to_string()],
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
                    let conn_cap_fd = conn_cap.clone();
                    let browser_tunnel_cap_fd = browser_tunnel_cap.clone();
                    tokio::spawn(async move {
                        while let Ok((tcp, _)) = fl.accept().await {
                            let permit = match &conn_cap_fd {
                                Some(cap) => match cap.try_admit() {
                                    Some(p) => Some(p),
                                    None => {
                                        // #119's shed path previously left no trace anywhere in
                                        // the edge's own logs -- indistinguishable, from here,
                                        // from any other closed socket. A client sees this as a
                                        // bare TCP-connect-then-EOF with no TLS bytes exchanged
                                        // at all (the ClientHello it sends lands on an already-
                                        // dropped socket), which is otherwise easy to misdiagnose
                                        // as a TLS-layer bug rather than "the cap is full". Log
                                        // occasionally (powers of two, then every 1000) so a
                                        // sustained shed streak is visible without spamming
                                        // stdout under a real flood -- the shed itself stays as
                                        // cheap as before, this is just a counter + rare eprintln.
                                        let total = cap.note_shed();
                                        if total.is_power_of_two() || total % 1000 == 0 {
                                            eprintln!(
                                                "ct-edge: :443 front door shedding — CT_EDGE_MAX_CONNECTIONS cap full, {total} connection(s) shed since start"
                                            );
                                        }
                                        drop(tcp); // shed: over the cap, close cheaply
                                        continue;
                                    }
                                },
                                None => None,
                            };
                            crate::transport::apply_tcp_keepalive(&tcp);
                            let state = fstate.clone();
                            let acceptor = facceptor.clone();
                            let proxies = proxies.clone();
                            let default_host = default_host.clone();
                            let channel_fd = channel_fd.clone();
                            let wildcard_tls = wildcard_tls.clone();
                            let mesh_relay_config = mesh_relay_config.clone();
                            let relay_gate_ctx = relay_gate_ctx.clone();
                            let browser_tunnel_cap = browser_tunnel_cap_fd.clone();
                            tokio::spawn(async move {
                                let _permit = permit; // held for the connection's lifetime
                                let mut nonce = [0u8; 16];
                                rand::rngs::OsRng.fill_bytes(&mut nonce);
                                let challenge = Challenge { nonce, difficulty };
                                // #127: log any front-door failure (TLS accept, routing,
                                // every arm) — the whole handler's `Result` was discarded, so
                                // a connection that reached the edge but failed anywhere in
                                // serve_front_door was completely invisible to the operator.
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
                                )
                                .await
                                {
                                    eprintln!("ct-edge: :443 front-door connection error: {e}");
                                }
                            });
                        }
                    });
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
        match addr.parse::<SocketAddr>() {
            Ok(listen) => match tokio::net::TcpListener::bind(listen).await {
                Ok(rl) => {
                    // #255: same global ConnectionCap as the other accept loops (QUIC, TCP
                    // fallback, :443 front door) -- this listener is public and previously
                    // spawned an unbounded task per accepted connection, so a flood here
                    // could exhaust FDs/tasks for the whole edge process regardless of the
                    // caps already enforced everywhere else.
                    let conn_cap_redirect = conn_cap.clone();
                    tokio::spawn(async move {
                        while let Ok((tcp, _)) = rl.accept().await {
                            let permit = match &conn_cap_redirect {
                                Some(cap) => match cap.try_admit() {
                                    Some(p) => Some(p),
                                    None => {
                                        drop(tcp); // shed: over the cap, close cheaply
                                        continue;
                                    }
                                },
                                None => None,
                            };
                            tokio::spawn(async move {
                                let _permit = permit; // held for the connection's lifetime
                                let _ = serve_http_redirect(tcp).await;
                            });
                        }
                    });
                    eprintln!("ct-edge: HTTP->HTTPS redirect on {listen} (CT_EDGE_HTTP_REDIRECT)");
                }
                Err(e) => eprintln!("ct-edge: cannot bind CT_EDGE_HTTP_REDIRECT {listen}: {e}"),
            },
            Err(e) => eprintln!("ct-edge: invalid CT_EDGE_HTTP_REDIRECT '{addr}': {e}"),
        }
    }

    // TCP fallback accept loop (for Clients whose outbound UDP is blocked).
    let state_tcp = state.clone();
    // #86 SEC86c: the TCP fallback is the same rendezvous surface as QUIC, so it
    // shares the one connection cap (a clone — the budget is global, not per-loop).
    let conn_cap_tcp = conn_cap.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = tcp_listener.accept().await {
            // Shed over the cap by dropping the socket (closes it), as on QUIC.
            let permit = match &conn_cap_tcp {
                Some(cap) => match cap.try_admit() {
                    Some(p) => Some(p),
                    None => {
                        drop(tcp);
                        continue;
                    }
                },
                None => None,
            };
            crate::transport::apply_tcp_keepalive(&tcp);
            let acceptor = acceptor.clone();
            let state = state_tcp.clone();
            tokio::spawn(async move {
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
                let _ = serve_tcp_connection(tls, &state, &challenge).await;
            });
        }
    });

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
                        match build_server_endpoint_from_ca(&ca, relay_addr, vec!["localhost".to_string()]) {
                            Ok((relay_ep, _)) => {
                                let relay_az = authorizer.clone();
                                eprintln!("ct-edge: Agent-Fabric channel RELAY on {relay_addr} (#105/#72 AF4-relay, #109 concurrent)");
                                tokio::spawn(async move {
                                    // #109-concurrent-b: drive the relay with a channel-keyed
                                    // pairer that spawns each splice on its own task, so a
                                    // long-lived relay can't wedge the single global slot and
                                    // two channels can never cross-pair. Replaces the old serial
                                    // `loop { broker_channel_relay(..).await }` that ran the
                                    // splice inline on the accept loop.
                                    let now_fn = || {
                                        std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .map(|d| d.as_secs())
                                            .unwrap_or(0)
                                    };
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
                                        |a, b, now| {
                                            crate::channel_broker::finish_relay_pair(a, b, now)
                                        },
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
                        tokio::spawn(async move {
                            // #120: drive the RENDEZVOUS endpoint with the same channel-keyed
                            // pairer that spawns each pair-completion on its own task, so a
                            // single member that holds its rendezvous connection open can't
                            // wedge the single global accept slot and two channels can never
                            // cross-pair. Replaces the old serial `loop { broker_channel_
                            // rendezvous(..).await }` that awaited both `conn.closed()` inline.
                            let now_fn = || {
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs())
                                    .unwrap_or(0)
                            };
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
                                |a, b, now| {
                                    crate::channel_broker::finish_rendezvous_pair(a, b, now)
                                },
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
                // Cross-transport pairing (#XXX): reuse the SAME pairer the `:443` front
                // door's channel broker uses (constructed above whenever CP_URL+ADMIN_TOKEN
                // are set, which this branch already requires too) so a browser member and a
                // `:443`/QUIC member of the same channel correlate and can pair with each
                // other. Falls back to a standalone pairer only in the defensive case where
                // this branch somehow runs without the front-door one having constructed it.
                let pairer = shared_channel_pairer.clone().unwrap_or_else(|| {
                    let p = crate::channel_broker::new_shared_channel_pairer();
                    spawn_front_door_pairer_reaper(p.clone(), Duration::from_secs(CHANNEL_PARK_TTL_SECS / 3), unix_now);
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
                tokio::spawn(async move {
                    if let Err(e) = crate::ws_channel::serve_ws_channel_with_pairer(
                        ws_addr,
                        resolver,
                        pairer,
                        ws_channel_cap,
                        ws_channel_tls,
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

    // QUIC accept loop (primary).
    while let Some(incoming) = endpoint.accept().await {
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
                }
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{build_client_endpoint, build_server_endpoint_with_cert};
    use std::sync::Arc;

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

        // Park one lone member whose deadline is already in the past relative to the fake
        // clock's first tick — it has no partner, so it must be reaped, not held forever.
        pairer.lock().unwrap().offer(WaitingMember {
            channel: ChannelId([7u8; 32]),
            holder: [1u8; 32],
            deadline: 100,
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
        );

        // Give the spawned task a handful of real ticks to run — generous relative to the 5ms
        // interval, but nowhere near the real CHANNEL_PARK_TTL_SECS this replaces waiting for.
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(
            pairer.lock().unwrap().len(),
            0,
            "the reaper must have evicted the expired lone member by now"
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
            let res = serve_tcp_connection(edge_side, &state, &challenge).await;
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
            let _ = serve_tcp_connection(edge_side, &state_srv, &challenge).await;
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
                        let _ = serve_tcp_connection(tls, &state, &challenge).await;
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
        state_b.register_host(host, RoutingToken([0x77; 32]));
        tokio::spawn(async move {
            let (tcp, _) = listener_b.accept().await.unwrap();
            if let Ok(tls) = acceptor_b.accept(tcp).await {
                let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };
                let _ = serve_tcp_connection(tls, &state_b, &challenge).await;
            }
        });

        let (_client_side, edge_a_inbound) = tokio::io::duplex(4096);
        let wrong_token = [0x99u8; 32]; // != the [0x42; 32] edge B is configured with
        let result = relay_via_peer_edge(edge_a_inbound, addr_b, host, cert_b, wrong_token).await;
        assert!(result.is_err(), "wrong admin token must be refused, not relayed");
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
            let _ = serve_tcp_connection(tls, &state_t, &chal_t).await;
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
        client.write_all(&build_request(&ch, &token)).await.unwrap();
        client.write_all(b"tcp-tunnel-data").await.unwrap();
        client.flush().await.unwrap();
        let mut got = [0u8; 15];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"tcp-tunnel-data", "TCP fallback client relayed to the QUIC agent");

        agent.await.unwrap();
        quic_edge.abort();
        tcp_edge.abort();
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
            let _ = serve_tcp_connection(tls, &state_t, &chal_t).await;
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
        cs.write_all(&build_request(&ch, &token)).await.unwrap();
        cs.write_all(b"quic-to-tcp-agt").await.unwrap();
        let mut got = [0u8; 15];
        cr.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"quic-to-tcp-agt", "QUIC client relayed to the TCP-fallback agent");

        agent.await.unwrap();
        quic_edge.abort();
        tcp_edge.abort();
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
        let edge = tokio::spawn(async move { serve_tcp_connection(agent_edge, &state_a, &chal_a).await });

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
            .deliver_to_tcp_agent(&token, Box::new(client_edge))
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
            .deliver_to_tcp_agent(&token, Box::new(a_edge))
            .map_err(|_| "first delivery failed")
            .unwrap();
        state
            .deliver_to_tcp_agent(&token, Box::new(b_edge))
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
        state.register_host("Browser.Test", token.clone()); // case-insensitive
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

        pass.abort();
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
        state.register_host("app.example.test", token.clone());
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
                tcp, &state, &dummy_acceptor, &proxies, None, &challenge, None, Some(&wildcard_tls), None, None, None,
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
        state.register_host("app.example.test", token.clone());
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
            serve_front_door(tcp, &state, &acceptor, &proxies, Some("portal.test"), &challenge, None, None, None, None, None)
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
            serve_front_door(tcp, &state, &acceptor, &proxies, None, &challenge, None, None, None, None, Some(&cap)).await
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
                tcp, &state, &dummy_acceptor, &proxies, Some("portal.test"), &challenge, None, None, None, None, None,
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
            serve_front_door(tcp, &state, &dummy, &proxies, Some("portal.test"), &challenge, None, None, None, None, None)
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
                        tcp, &state, &acceptor, &proxies, None, &challenge, Some(&ctx), None, None, None, None,
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
}
