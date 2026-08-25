//! ADR-0024 M2: a standalone RFC 9298 CONNECT-UDP proxy over HTTP/2 Extended CONNECT
//! (RFC 9220), fronted by the edge's existing `FrontDoorRoute::Proxy` TLS-terminate-
//! and-forward arm -- see the crate-level `Cargo.toml` description and
//! `docs/adr/0024-masque-connect-udp-fallback.md` for the full design.
//!
//! **Deliberately not a general-purpose relay.** A real MASQUE proxy typically lets a
//! client name any destination; this one exists for exactly one purpose (tunneling a
//! ct-agent's QUIC traffic to this edge's own `CT_EDGE_LISTEN` port when the agent's
//! network blocks raw UDP), so it hard-restricts every request to one configured
//! target address `by construction` -- there is no code path that can proxy anywhere
//! else, which is a much stronger guarantee than an allowlist check would be (#559:
//! "the user must not be compromisable through any of our services" -- an accidental
//! open UDP relay would be exactly that).

pub mod capsule;
pub mod varint;

use bytes::Bytes;
use h2::ext::Protocol;
use http::{Method, Request, Response};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;

/// How the URI path for the one legitimate target is spelled -- see
/// [`expected_connect_udp_path`]. Not RFC-mandated (RFC 9298 lets a deployment choose
/// its own URI Template and advertise it out of band); fixed here since this proxy
/// only ever has one client (ct-agent, M3) and one server, both under our control.
const CONNECT_UDP_PATH_PREFIX: &str = "/.well-known/masque/udp";

/// RFC 9298 section 2's target_host encoding: IPv4/DNS names appear literally; an
/// IPv6 literal has its colons percent-encoded (`:` -> `%3A`) since the URI Template
/// otherwise can't tell a port-separator colon from an address one. Brackets are not
/// used (unlike a normal IPv6 URI authority) -- this is the RFC's own template shape,
/// not ours to change, even though this proxy only ever compares against one fixed
/// value rather than parsing an arbitrary one.
fn encode_target_host(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => v4.ip().to_string(),
        SocketAddr::V6(v6) => v6.ip().to_string().replace(':', "%3A"),
    }
}

/// The one legitimate CONNECT-UDP request path -- computed once from the configured
/// target, then compared byte-for-byte against every incoming request's path (see
/// [`Config`]'s doc). Deliberately not a general URI-template parser: this proxy has
/// exactly one valid destination, so "does the path exactly match the one we computed
/// for it" is both simpler and strictly safer than parsing an arbitrary target_host/
/// target_port and then checking it against an allowlist of one entry.
fn expected_connect_udp_path(target: SocketAddr) -> String {
    format!("{CONNECT_UDP_PATH_PREFIX}/{}/{}/", encode_target_host(&target), target.port())
}

/// Runtime configuration. Constructed by `main.rs` from `CT_MASQUE_PROXY_*` env vars
/// (kept out of this module so the framing/proxy logic here stays testable without
/// touching process environment).
#[derive(Clone)]
pub struct Config {
    /// Local address this proxy listens on. Never exposed publicly by itself -- the
    /// edge terminates the browser/agent-facing TLS and forwards plaintext bytes here,
    /// exactly like the Portal control plane's own `:8090` (see ADR-0024 Decision 2).
    pub listen: SocketAddr,
    /// The one legitimate CONNECT-UDP destination -- this edge's own `CT_EDGE_LISTEN`
    /// QUIC port (default `0.0.0.0:4433`; reachable from this proxy at `127.0.0.1:4433`
    /// when co-located, as it is in every deployment this ADR anticipates).
    pub target: SocketAddr,
    /// Maximum concurrent CONNECT-UDP tunnels this proxy will hold open at once
    /// (#559/#54 convention: every listener in this codebase is resource-bounded, not
    /// just timeout-bounded). A new connection beyond this is refused with a 503-
    /// equivalent (RST_STREAM), not queued.
    pub max_concurrent_tunnels: usize,
    /// A tunnel with no traffic in either direction for this long is torn down --
    /// same missing-timeout-family reasoning as every other long-lived stream in this
    /// codebase (CADS-Tunnel#54 family): an agent that vanished mid-session must not
    /// pin a UDP socket + h2 stream open forever.
    pub idle_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:4434".parse().unwrap(),
            target: "127.0.0.1:4433".parse().unwrap(),
            max_concurrent_tunnels: 256,
            idle_timeout: Duration::from_secs(120),
        }
    }
}

/// Runs the proxy until `listener` errors or the process is torn down (there is no
/// graceful-shutdown signal wired in yet -- `main.rs` runs this for the lifetime of
/// the process, same as the edge's own long-running listeners).
pub async fn run(config: Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(config.listen).await?;
    let expected_path = Arc::new(expected_connect_udp_path(config.target));
    let admission = Arc::new(Semaphore::new(config.max_concurrent_tunnels));
    let target = config.target;
    let idle_timeout = config.idle_timeout;

    loop {
        let (io, _peer) = listener.accept().await?;
        let expected_path = expected_path.clone();
        let admission = admission.clone();
        tokio::spawn(async move {
            // #559: a connection that can't get a permit is refused immediately, not
            // queued -- an unbounded queue is the same resource-exhaustion shape as no
            // bound at all, just with extra steps.
            let Ok(_permit) = admission.try_acquire_owned() else {
                return;
            };
            if let Err(e) = serve_connection(io, target, &expected_path, idle_timeout).await {
                eprintln!("masque-proxy: connection ended with error: {e}");
            }
        });
    }
}

async fn serve_connection(
    io: TcpStream,
    target: SocketAddr,
    expected_path: &str,
    idle_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut conn = h2::server::Builder::new()
        .enable_connect_protocol()
        .handshake::<_, Bytes>(io)
        .await?;

    // One CONNECT-UDP tunnel per TCP connection is all this proxy needs to support
    // (ct-agent, M3, opens one connection per MASQUE dial attempt) -- but the accept
    // loop still keeps `conn` driven for its whole lifetime (ADR-0024 M1 finding:
    // dropping it early strands buffered-but-unflushed frames), so this doesn't
    // return after the first request.
    while let Some(result) = conn.accept().await {
        let (req, respond) = result?;
        if let Err(e) = handle_request(req, respond, target, expected_path, idle_timeout).await {
            eprintln!("masque-proxy: request handling ended with error: {e}");
        }
    }
    Ok(())
}

async fn handle_request(
    req: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    target: SocketAddr,
    expected_path: &str,
    idle_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let is_connect_udp = req.method() == Method::CONNECT
        && req.extensions().get::<Protocol>() == Some(&Protocol::from_static("connect-udp"));
    // By-construction target restriction (see the crate/module doc): the ONLY path
    // this proxy ever accepts is the one it precomputed for its single configured
    // target. Anything else -- a different host, a different port, a malformed
    // template, an attempt to probe for other targets -- fails this same equality
    // check and is refused identically, with no separate "is this destination
    // allowed" logic to get wrong.
    if !is_connect_udp || req.uri().path() != expected_path {
        respond.send_reset(h2::Reason::REFUSED_STREAM);
        return Ok(());
    }

    let response = Response::builder().status(200).body(()).unwrap();
    let mut send_stream = respond.send_response(response, false)?;

    let udp = UdpSocket::bind("0.0.0.0:0").await?;
    udp.connect(target).await?;

    let mut recv_stream = req.into_body();
    let mut inbound_buf: Vec<u8> = Vec::new();
    // RFC 9298 section 6's own ceiling (see capsule.rs's MAX_CAPSULE_VALUE_LEN doc) --
    // matched here for the UDP-socket-read side of the pump.
    let mut udp_read_buf = vec![0u8; 65_527];

    loop {
        tokio::select! {
            // Agent -> target: decode capsule-framed datagrams off the h2 stream,
            // write the raw UDP payload to the (fixed-destination) socket.
            chunk = recv_stream.data() => {
                let Some(chunk) = chunk else { break; }; // client ended its send side
                let chunk = chunk?;
                recv_stream.flow_control().release_capacity(chunk.len())?;
                inbound_buf.extend_from_slice(&chunk);
                loop {
                    match capsule::decode(&inbound_buf) {
                        Ok(Some((cap_type, value, consumed))) => {
                            if cap_type == 0x00 {
                                if let Some(udp_payload) = capsule::udp_datagram_payload::decode(value) {
                                    // Best-effort: a send failure here (e.g. target
                                    // transiently unreachable) tears down neither the
                                    // h2 stream nor this loop -- same "don't let one
                                    // lost datagram kill the tunnel" semantics real UDP
                                    // traffic already has.
                                    let _ = udp.send(udp_payload).await;
                                }
                            }
                            inbound_buf.drain(..consumed);
                        }
                        Ok(None) => break, // capsule still arriving, wait for more bytes
                        Err(_) => return Ok(()), // protocol violation -- tear down cleanly
                    }
                }
            }
            // target -> agent: encode each raw UDP datagram as a capsule-framed HTTP
            // Datagram and write it to the h2 send stream.
            recv = udp.recv(&mut udp_read_buf) => {
                let n = recv?;
                let datagram_payload = capsule::udp_datagram_payload::encode(&udp_read_buf[..n]);
                let framed = capsule::encode_datagram(&datagram_payload);
                send_stream.send_data(Bytes::from(framed), false)?;
            }
            _ = tokio::time::sleep(idle_timeout) => {
                break; // #54-family: no traffic either direction within idle_timeout
            }
        }
    }

    let _ = send_stream.send_data(Bytes::new(), true);
    Ok(())
}
