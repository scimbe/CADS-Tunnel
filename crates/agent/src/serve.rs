//! Agent origin-serving (M5.2b).
//!
//! When the Edge relays a Client stream to this Agent, the Agent dials the local
//! Origin (TCP) and pipes the QUIC stream to it. The Client↔Origin payload is
//! Noise-encrypted end to end (ADR-0013); the Agent forwards opaque bytes to the
//! Origin, which terminates the Noise session (P3). The Agent never inspects
//! them beyond forwarding.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use quinn::{Connection, Endpoint, RecvStream, SendStream};

use crate::reconnect::Backoff;
use rustls::pki_types::CertificateDer;
use tokio::io::{copy_bidirectional, join, split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::config::{AgentConfig, OriginProto};
use crate::transport::{
    bind_hostname, dial_quic, dial_quic_or_blocked_error, register_tunnel, register_tunnel_stream,
    register_tunnel_stream_browser, tcp_tls_connect,
};
use ct_common::metrics::{Metered, TunnelMetrics};
use ct_common::noise::{frame, noise_pump, origin_handshake, origin_handshake_any};
use ct_common::RoutingToken;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Read one length-prefixed frame (2-byte big-endian length + body).
async fn read_frame<R: AsyncRead + Unpin>(recv: &mut R) -> Result<Vec<u8>, BoxError> {
    let mut len = [0u8; 2];
    recv.read_exact(&mut len).await?;
    let n = u16::from_be_bytes(len) as usize;
    let mut body = vec![0u8; n];
    recv.read_exact(&mut body).await?;
    Ok(body)
}

/// Serve one relayed QUIC stream: dial the local `origin` (TCP) and relay bytes
/// bidirectionally between the QUIC stream and the Origin connection.
pub async fn serve_stream_to_origin(
    quic_send: SendStream,
    quic_recv: RecvStream,
    origin: SocketAddr,
) -> Result<(), BoxError> {
    serve_duplex_to_origin(join(quic_recv, quic_send), origin).await
}

/// Raw-forward any relayed duplex byte stream to the Origin verbatim (issue #41
/// FB3): the transport-agnostic core of [`serve_stream_to_origin`]. The QUIC
/// path joins its two half-streams; the TLS-TCP fallback hands its whole stream
/// straight in. Either way the browser's TLS terminates AT the Origin — the
/// Edge only ever relays opaque bytes.
///
/// Dials the Origin **lazily**, only once the Client has actually sent its
/// first bytes (#229 follow-up), rather than eagerly the moment this function
/// is entered. The TCP-fallback path in particular can sit parked for an
/// arbitrary amount of time — however long until the Edge delivers a real
/// Client — waiting with an Origin connection already open the whole time.
/// An eagerly-opened connection can idle past the Origin's own read/keep-alive
/// timeout before a Client ever arrives, so the very first real request lands
/// on an already-dead connection and never completes, even though the
/// Client↔Edge TLS layer works perfectly every time. Since this relay only
/// ever carries request/response protocols (HTTP, or the Noise handshake in
/// [`serve_noise_bridge`]), the Client always speaks first, so waiting for
/// its first chunk before dialing costs nothing.
pub async fn serve_duplex_to_origin<T>(mut client: T, origin: SocketAddr) -> Result<(), BoxError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut first = [0u8; 4096];
    let n = client.read(&mut first).await?;
    if n == 0 {
        return Ok(()); // Client closed before ever sending anything -- nothing to relay.
    }
    let mut tcp = TcpStream::connect(origin).await?;
    tcp.write_all(&first[..n]).await?;
    copy_bidirectional(&mut client, &mut tcp).await?;
    Ok(())
}

/// Serve one relayed stream as the Origin's Noise responder (M8.3): terminate
/// the `Noise_IK` handshake with the Origin private key, then bridge one
/// request/response to the local `origin` — decrypt the Client's frame, forward
/// the plaintext to the Origin (TCP), read its reply, and return it encrypted.
///
/// Generic over the byte transport so it drives a QUIC stream in the live path
/// (M8.4) and an in-memory duplex in tests. The Edge only ever relays the
/// encrypted frames.
pub async fn serve_noise_bridge<S, R>(
    send: &mut S,
    recv: &mut R,
    origin: SocketAddr,
    origin_private: &[u8; 32],
) -> Result<(), BoxError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut hs = origin_handshake(origin_private)?;
    let mut buf = vec![0u8; 65535];
    let mut tmp = vec![0u8; 65535];

    // <- handshake message 1, -> handshake message 2
    let m1 = read_frame(recv).await?;
    hs.read_message(&m1, &mut tmp)?;
    let n = hs.write_message(&[], &mut buf)?;
    send.write_all(&frame(&buf[..n])).await?;
    send.flush().await?;

    let mut transport = hs.into_transport_mode()?;

    // Decrypt the Client's request and forward the plaintext to the Origin.
    let req_ct = read_frame(recv).await?;
    let n = transport.read_message(&req_ct, &mut tmp)?;
    let request = tmp[..n].to_vec();

    let mut tcp = TcpStream::connect(origin).await?;
    tcp.write_all(&request).await?;
    tcp.shutdown().await?;
    let mut response = Vec::new();
    tcp.read_to_end(&mut response).await?;

    // Encrypt the Origin's response back to the Client.
    let n = transport.write_message(&response, &mut buf)?;
    send.write_all(&frame(&buf[..n])).await?;
    send.flush().await?;
    Ok(())
}

/// Serve one relayed stream as the Origin's Noise responder with a **full-duplex
/// streaming** bridge (M9.2): terminate the `Noise_IK` handshake, then
/// [`noise_pump`] between the decrypted Client stream and the local Origin TCP
/// socket — arbitrary bidirectional, multi-message traffic, not a single
/// request/response. Generic over the byte transport (QUIC live, duplex in tests).
pub async fn serve_noise_stream<S, R>(
    mut send: S,
    mut recv: R,
    origin: SocketAddr,
    origin_keys: &[[u8; 32]],
    metrics: Arc<TunnelMetrics>,
) -> Result<(), BoxError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; 65535];

    // <- handshake message 1, -> handshake message 2. Time it and count the
    // outcome for observability (M14.1b). During a key rotation (#12) the Agent
    // may hold several Origin keys; `origin_handshake_any` selects whichever one
    // the Client pinned. A completed handshake is an opened tunnel; a failed one
    // increments the failure counter.
    let started = Instant::now();
    let m1 = match read_frame(&mut recv).await {
        Ok(m) => m,
        Err(e) => {
            metrics.tunnels_failed.inc();
            return Err(e);
        }
    };
    let mut hs = match origin_handshake_any(origin_keys, &m1) {
        Some(hs) => hs,
        None => {
            metrics.tunnels_failed.inc();
            return Err("no origin identity matched the client handshake".into());
        }
    };
    let write_msg2 = async {
        let n = hs.write_message(&[], &mut buf)?;
        send.write_all(&frame(&buf[..n])).await?;
        send.flush().await?;
        Ok::<(), BoxError>(())
    }
    .await;
    if let Err(e) = write_msg2 {
        metrics.tunnels_failed.inc();
        return Err(e);
    }
    let transport = match hs.into_transport_mode() {
        Ok(t) => {
            metrics.observe_handshake(started.elapsed());
            metrics.tunnels_opened.inc();
            t
        }
        Err(e) => {
            metrics.tunnels_failed.inc();
            return Err(e.into());
        }
    };

    // Bridge the Noise session <-> the Origin TCP socket, both ways, streaming.
    // Meter the Origin socket: bytes read from it flow back to the Client
    // (bytes_to_client); bytes written to it came from the Client
    // (bytes_to_origin).
    let tcp = TcpStream::connect(origin).await?;
    let tcp = Metered::new(
        tcp,
        Arc::clone(&metrics.bytes_to_client),
        Arc::clone(&metrics.bytes_to_origin),
    );
    let cipher = join(recv, send);
    noise_pump(transport, cipher, tcp).await?;
    Ok(())
}

/// Serve one relayed stream as the Origin's Noise responder bridging to a **UDP**
/// Origin (M10.1). One Noise frame carries exactly one UDP datagram, so the
/// tunnel's framing preserves datagram boundaries: each decrypted frame is `send`
/// as a datagram to the Origin, and each datagram `recv`d from the Origin is
/// encrypted back as one frame. Runs until the Client closes the tunnel.
pub async fn serve_noise_udp<S, R>(
    mut send: S,
    mut recv: R,
    origin: SocketAddr,
    origin_keys: &[[u8; 32]],
) -> Result<(), BoxError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut hbuf = vec![0u8; 65535];
    let m1 = read_frame(&mut recv).await?;
    let mut hs = origin_handshake_any(origin_keys, &m1)
        .ok_or("no origin identity matched the client handshake")?;
    let n = hs.write_message(&[], &mut hbuf)?;
    send.write_all(&frame(&hbuf[..n])).await?;
    send.flush().await?;
    let transport = hs.into_transport_mode()?;

    let udp = UdpSocket::bind("0.0.0.0:0").await?;
    udp.connect(origin).await?;

    let ts = Mutex::new(transport);
    // `e` is inferred as snow::Error from the map_err call sites (naming it would
    // need snow as a direct dep, which ct-agent gets only transitively).
    let noise_err = |e| io::Error::new(io::ErrorKind::Other, format!("{e}"));

    // Client -> decrypt frame -> UDP datagram to Origin.
    let to_origin = async {
        let mut tmp = vec![0u8; 65535];
        loop {
            let fr = match read_frame(&mut recv).await {
                Ok(f) => f,
                Err(_) => break, // tunnel closed
            };
            let len = ts.lock().unwrap().read_message(&fr, &mut tmp).map_err(noise_err)?;
            udp.send(&tmp[..len]).await?;
        }
        Ok::<(), io::Error>(())
    };

    // Origin datagram -> encrypt -> frame to Client.
    let to_client = async {
        let mut dgram = vec![0u8; 65535];
        let mut ct = vec![0u8; 65535 + 256];
        loop {
            let n = udp.recv(&mut dgram).await?;
            let len = ts.lock().unwrap().write_message(&dgram[..n], &mut ct).map_err(noise_err)?;
            send.write_all(&frame(&ct[..len])).await?;
            send.flush().await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), io::Error>(())
    };

    // The Client closing the tunnel ends `to_origin`; UDP has no EOF, so
    // `to_client` only ends on error — whichever finishes first tears down.
    tokio::select! {
        r = to_origin => r?,
        r = to_client => r?,
    }
    Ok(())
}

/// Serve the Agent's **direct-path** listener (M11.4b-iii): accept direct Client
/// connections (which bypass the Edge relay) and serve each one as the Origin's
/// Noise responder — streaming for TCP, datagram-preserving for UDP. Loops until
/// the listener closes.
pub async fn serve_direct(
    listener: Endpoint,
    origin: SocketAddr,
    origin_keys: Arc<Vec<[u8; 32]>>,
    proto: OriginProto,
    metrics: Arc<TunnelMetrics>,
) -> Result<(), BoxError> {
    while let Some(incoming) = listener.accept().await {
        let metrics = Arc::clone(&metrics);
        let keys = Arc::clone(&origin_keys);
        tokio::spawn(async move {
            if let Ok(conn) = incoming.await {
                if let Ok((send, recv)) = conn.accept_bi().await {
                    let _ = match proto {
                        OriginProto::Tcp => {
                            serve_noise_stream(send, recv, origin, &keys, metrics).await
                        }
                        OriginProto::Udp => serve_noise_udp(send, recv, origin, &keys).await,
                    };
                }
                conn.closed().await;
            }
        });
    }
    Ok(())
}

/// Run the Agent: dial the Edge, register the tunnel for `token`, then serve each
/// relayed stream as the Origin's Noise responder, bridging plaintext to the
/// local Origin (M8.4c-i). `origin_private` is the Agent-held Origin static key.
/// Loops until the connection closes.
pub async fn run_agent(
    config: &AgentConfig,
    edge_cert: CertificateDer<'static>,
    token: RoutingToken,
    origin_keys: Arc<Vec<[u8; 32]>>,
) -> Result<(), BoxError> {
    // Shared tunnel metrics for this Agent (M14.1b), plus optional one-time
    // endpoints — set up once, outside the reconnect loop.
    let metrics = Arc::new(TunnelMetrics::new());
    if let Some(addr) = config.metrics_listen {
        let mmetrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            let _ = crate::observe::serve_metrics(addr, mmetrics).await;
        });
    }
    if let Some(ip) = config.direct_advertise_ip {
        if let Ok((listener, cert)) = crate::transport::build_direct_listener() {
            if let Ok(bound) = listener.local_addr() {
                let advertised = SocketAddr::new(ip, bound.port());
                if let Ok(adv) = dial_quic(config.edge, edge_cert.clone()).await {
                    let _ = crate::transport::advertise_direct_listener(&adv, &token, advertised, &cert)
                        .await;
                    adv.close(0u32.into(), b"advertised");
                }
                let (origin, proto) = (config.origin, config.origin_proto);
                let dmetrics = Arc::clone(&metrics);
                let dkeys = Arc::clone(&origin_keys);
                tokio::spawn(async move {
                    let _ = serve_direct(listener, origin, dkeys, proto, dmetrics).await;
                });
            }
        }
    }

    // Reconnect loop (issue #5 / P1.2b): (re)dial + (re)register + serve until the
    // connection drops, then back off and retry, so a transient edge/network
    // failure doesn't kill the tunnel. A *first*-dial failure means UDP is blocked
    // → the TLS-TCP fallback (issue #3).
    let mut backoff = Backoff::new(RECONNECT_BASE, RECONNECT_MAX, reconnect_max_attempts());
    let mut first = true;
    loop {
        let conn = match dial_quic_or_blocked_error(config.edge, edge_cert.clone(), Duration::from_secs(5))
            .await
        {
            Ok(conn) => conn,
            Err(e) => {
                if first {
                    return run_agent_tcp_fallback(
                        config,
                        edge_cert.clone(),
                        token.clone(),
                        Arc::clone(&origin_keys),
                    )
                    .await;
                }
                eprintln!("ct-agent: edge dial failed ({e}); will reconnect");
                match backoff.next_delay_jittered(rand::random::<f64>()) {
                    Some(d) => {
                        tokio::time::sleep(d).await;
                        continue;
                    }
                    None => return Err("ct-agent: gave up reconnecting to the edge".into()),
                }
            }
        };
        first = false;
        if let Err(e) = register_tunnel(&conn, &token).await {
            eprintln!("ct-agent: registration failed ({e}); will reconnect");
            match backoff.next_delay_jittered(rand::random::<f64>()) {
                Some(d) => {
                    tokio::time::sleep(d).await;
                    continue;
                }
                None => return Err("ct-agent: gave up re-registering with the edge".into()),
            }
        }
        backoff.reset();
        // Browser Plane (#23 BP3b): bind the public hostname to this token so an
        // SNI-routed browser reaches this tunnel. Re-bound on every reconnect.
        if config.browser_forward {
            if let Some(host) = &config.hostname {
                if let Err(e) = bind_hostname(&conn, &token, host).await {
                    eprintln!("ct-agent: hostname binding for '{host}' failed ({e})");
                }
            }
        }
        eprintln!("ct-agent: registered with edge {} (serving)", config.edge);
        serve_quic_connection(
            &conn,
            config.origin,
            config.origin_proto,
            config.browser_forward,
            &origin_keys,
            Arc::clone(&metrics),
        )
        .await;
        eprintln!("ct-agent: edge connection dropped; reconnecting");
        match backoff.next_delay_jittered(rand::random::<f64>()) {
            Some(d) => tokio::time::sleep(d).await,
            None => return Err("ct-agent: gave up reconnecting after the connection dropped".into()),
        }
    }
}

/// Reconnect backoff parameters (issue #5 / P1.2b).
const RECONNECT_BASE: Duration = Duration::from_millis(500);
const RECONNECT_MAX: Duration = Duration::from_secs(30);
const RECONNECT_MAX_ATTEMPTS: u32 = 10;

/// How many reconnect attempts before the agent gives up and exits. Configurable
/// via `CT_AGENT_RECONNECT_MAX_ATTEMPTS`; `0` means retry forever (#36): a
/// long-lived public demo must rejoin a redeployed edge automatically rather than
/// exit — the process holds a single-use join token, so exiting can't cleanly
/// re-onboard, and a bare `restart:` would just crash-loop redeeming a spent token.
/// Retrying forever keeps the onboarded credential and simply waits out the edge.
fn reconnect_max_attempts() -> u32 {
    parse_reconnect_max_attempts(std::env::var("CT_AGENT_RECONNECT_MAX_ATTEMPTS").ok())
}

/// Pure core of [`reconnect_max_attempts`]: `Some("0")` → unbounded (`u32::MAX`),
/// a valid count → itself, anything else (unset/garbage) → the default.
fn parse_reconnect_max_attempts(raw: Option<String>) -> u32 {
    match raw.and_then(|s| s.trim().parse::<u32>().ok()) {
        Some(0) => u32::MAX,
        Some(n) => n,
        None => RECONNECT_MAX_ATTEMPTS,
    }
}

/// Serve Client tunnels over a live QUIC `conn` until it drops, then return so
/// the caller can reconnect. Each accepted bi-stream is one Client's Noise tunnel.
async fn serve_quic_connection(
    conn: &Connection,
    origin: SocketAddr,
    proto: OriginProto,
    browser_forward: bool,
    origin_keys: &[[u8; 32]],
    metrics: Arc<TunnelMetrics>,
) {
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(x) => x,
            Err(_) => return,
        };
        // Browser Plane (#23): forward the relayed stream to the Origin verbatim
        // (raw TLS passthrough); the browser's TLS terminates at the Origin.
        if browser_forward {
            tokio::spawn(async move {
                let _ = serve_stream_to_origin(send, recv, origin).await;
            });
            continue;
        }
        let keys = origin_keys.to_vec();
        let m = Arc::clone(&metrics);
        tokio::spawn(async move {
            let _ = match proto {
                OriginProto::Tcp => serve_noise_stream(send, recv, origin, &keys, m).await,
                OriginProto::Udp => serve_noise_udp(send, recv, origin, &keys).await,
            };
        });
    }
}

/// Serve the Agent over the **TLS-TCP fallback** when UDP/QUIC to the Edge is
/// blocked (issue #3 / P1.2c-4): run [`config.tcp_fallback_pool_size`]
/// independent registration workers concurrently (#229) rather than just
/// one. Each individual registration is still single-use/single-Client (no
/// QUIC-style multiplexing within one TCP connection) -- pooling several of
/// them is what lets more than one simultaneous Client be served at once, the
/// way a real browser's several-parallel-connections-per-origin page load
/// needs. A pool of 1 (`CT_AGENT_TCP_FALLBACK_POOL_SIZE=1`) reproduces the
/// old, implicit one-at-a-time behavior exactly.
///
/// [`config.tcp_fallback_pool_size`]: AgentConfig::tcp_fallback_pool_size
async fn run_agent_tcp_fallback(
    config: &AgentConfig,
    edge_cert: CertificateDer<'static>,
    token: RoutingToken,
    origin_keys: Arc<Vec<[u8; 32]>>,
) -> Result<(), BoxError> {
    let n = config.tcp_fallback_pool_size.max(1);
    let mut workers = Vec::with_capacity(n);
    for _ in 0..n {
        let config = config.clone();
        let edge_cert = edge_cert.clone();
        let token = token.clone();
        let origin_keys = Arc::clone(&origin_keys);
        workers.push(tokio::spawn(async move {
            run_agent_tcp_fallback_worker(&config, edge_cert, token, origin_keys).await
        }));
    }
    // If any one worker gives up (its own backoff exhausted), that's fatal to
    // the whole fallback mode, matching the pre-pool single-worker behavior --
    // a customer running with a pool > 1 should learn about a systemic outage
    // as loudly as they would have with a pool of 1.
    for w in workers {
        w.await??;
    }
    Ok(())
}

/// One TCP-fallback pool worker (#229): connect, register, serve one Client,
/// repeat -- the body [`run_agent_tcp_fallback`] runs N of concurrently. Each
/// registration is still single-use/single-Client; see that function's doc
/// for why several of these run at once.
async fn run_agent_tcp_fallback_worker(
    config: &AgentConfig,
    edge_cert: CertificateDer<'static>,
    token: RoutingToken,
    origin_keys: Arc<Vec<[u8; 32]>>,
) -> Result<(), BoxError> {
    let metrics = Arc::new(TunnelMetrics::new());
    // Reconnect loop (issue #5 / P1.2b): re-register and serve again after each
    // single tunnel ends or the connection drops, with backoff on failure.
    let mut backoff = Backoff::new(RECONNECT_BASE, RECONNECT_MAX, reconnect_max_attempts());
    // #46 FB-c: the TCP-fallback rungs to try in order — the configured edge port,
    // then the unified :443 front door when CT_AGENT_FALLBACK_443 is set. The first
    // rung that connects+registers serves the client; if all fail, back off.
    let rungs = crate::ladder::tcp_rungs(config.edge, config.fallback_443);
    loop {
        let mut served = false;
        let mut last_err: Option<BoxError> = None;
        for addr in &rungs {
            match tcp_connect_register_serve(config, *addr, &edge_cert, &token, &origin_keys, &metrics)
                .await
            {
                // A tunnel completed cleanly — re-register (re-walk from the primary).
                Ok(()) => {
                    backoff.reset();
                    served = true;
                    break;
                }
                Err(e) => {
                    eprintln!("ct-agent: TLS-TCP rung {addr} failed: {e}; trying next rung");
                    last_err = Some(e);
                }
            }
        }
        if !served {
            let e = last_err
                .map(|e| e.to_string())
                .unwrap_or_else(|| "no TCP rung configured".to_string());
            eprintln!("ct-agent: all TLS-TCP rungs failed ({e}); will reconnect");
            match backoff.next_delay_jittered(rand::random::<f64>()) {
                Some(d) => tokio::time::sleep(d).await,
                None => {
                    return Err("ct-agent: gave up reconnecting over the TLS-TCP fallback".into())
                }
            }
        }
    }
}

/// Connect over TLS-TCP to `target`, register the tunnel over the stream, and
/// serve one Client's Noise tunnel over it — the single-shot body of the
/// TCP-fallback reconnect loop (issue #5 / P1.2b), one rung of the #46 ladder.
async fn tcp_connect_register_serve(
    config: &AgentConfig,
    target: SocketAddr,
    edge_cert: &CertificateDer<'static>,
    token: &RoutingToken,
    origin_keys: &[[u8; 32]],
    metrics: &Arc<TunnelMetrics>,
) -> Result<(), BoxError> {
    let mut stream = tcp_tls_connect(target, edge_cert.clone()).await?;
    // Browser Plane over the TCP fallback (#41 FB3): register+bind the public
    // hostname in one 'B' frame, then raw-forward the relayed browser stream to
    // the Origin verbatim — the browser's TLS terminates AT the Origin, so this
    // agent never speaks Noise. Mirrors the QUIC browser path in serve_quic_connection.
    if config.browser_forward {
        if let Some(host) = &config.hostname {
            register_tunnel_stream_browser(&mut stream, token, host).await?;
            eprintln!(
                "ct-agent: browser-registered '{host}' over the TLS-TCP fallback (UDP blocked), \
                 raw-forwarding to {}",
                config.origin
            );
            return serve_duplex_to_origin(stream, config.origin).await;
        }
    }
    register_tunnel_stream(&mut stream, token).await?;
    eprintln!(
        "ct-agent: registered over the TLS-TCP fallback (UDP blocked), serving one tunnel to {}",
        config.origin
    );
    let (recv, send) = split(stream);
    serve_noise_stream(send, recv, config.origin, origin_keys, Arc::clone(metrics)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::dial_quic;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn parse_reconnect_max_attempts_maps_zero_to_unbounded() {
        // #36: unset/garbage keeps the default; an explicit 0 means retry forever
        // (so the public-demo agent rejoins a redeployed edge instead of exiting).
        assert_eq!(parse_reconnect_max_attempts(None), RECONNECT_MAX_ATTEMPTS);
        assert_eq!(parse_reconnect_max_attempts(Some("not-a-number".into())), RECONNECT_MAX_ATTEMPTS);
        assert_eq!(parse_reconnect_max_attempts(Some("0".into())), u32::MAX, "0 -> retry forever");
        assert_eq!(parse_reconnect_max_attempts(Some(" 7 ".into())), 7);
    }

    /// issue #3 acceptance: with UDP blocked, the agent registers over the TLS-TCP
    /// fallback and a Client completes a full Noise round-trip through the edge to
    /// the origin — the cross-host tunnel works without QUIC/UDP.
    #[tokio::test]
    async fn tcp_fallback_agent_serves_a_noise_round_trip_end_to_end() {
        use ct_common::noise::generate_static_keypair;
        use ct_common::pow::Challenge;
        use ct_common::{Capability, OriginIdentity};
        use ct_edge::pki::{build_dual_edge_from_ca, Ca};
        use ct_edge::serve::serve_tcp_connection;
        use ct_edge::state::EdgeState;
        use quinn::Connection;
        use std::net::Ipv4Addr;

        // Real dual edge (TCP + QUIC); we exercise only the TCP fallback side.
        let ca = Ca::new("e2e-ca").unwrap();
        let (_ep, tcp_listener, acceptor, ca_root) = build_dual_edge_from_ca(
            &ca,
            (Ipv4Addr::LOCALHOST, 0).into(),
            (Ipv4Addr::LOCALHOST, 0).into(),
            vec!["localhost".to_string()],
        )
        .await
        .unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let token = RoutingToken([0x33; 32]);
        let state = Arc::new(EdgeState::<Connection>::new());
        let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };

        // Edge: accept each TCP connection and serve it ('A' parks, 'C' delivers).
        let state_e = state.clone();
        let edge = tokio::spawn(async move {
            for _ in 0..2 {
                let (tcp, _) = tcp_listener.accept().await.unwrap();
                let (acc, st, ch) = (acceptor.clone(), state_e.clone(), challenge.clone());
                tokio::spawn(async move {
                    if let Ok(tls) = acc.accept(tcp).await {
                        let _ = serve_tcp_connection(tls, &st, &ch).await;
                    }
                });
            }
        });

        // Origin: a streaming TCP echo (copy) — echoes bytes as they arrive, so
        // the round-trip does not depend on a half-close propagating through the
        // relay chain (matches the known-good TCP-fallback harness).
        let origin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = origin_listener.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
            let _ = w.shutdown().await;
        });

        // The agent holds the origin private key; the Capability pins its public.
        let origin_kp = generate_static_keypair();
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: tcp_addr.to_string(),
        };

        // Agent: run the TCP fallback (connect + register + serve one tunnel).
        // Pool size 1: this test's mock edge accepts exactly 2 connections
        // total (one Agent registration + one Client), so the default pool
        // (#229) would have the Agent alone consume both.
        let mut cfg = AgentConfig::parse(&tcp_addr.to_string(), &origin_addr.to_string()).unwrap();
        cfg.tcp_fallback_pool_size = 1;
        let ca_root_a = ca_root.clone();
        let a_token = token.clone();
        let agent = tokio::spawn(async move {
            let _ = run_agent_tcp_fallback(&cfg, ca_root_a, a_token, std::sync::Arc::new(vec![origin_kp.private])).await;
        });

        // Wait until the agent has registered (parked) at the edge.
        for _ in 0..200 {
            if state.has_tcp_agent(&token) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(state.has_tcp_agent(&token), "agent parked over TLS-TCP");

        // Client: tunnel over TLS-TCP through the edge to the origin, expect echo.
        let client_kp = generate_static_keypair();
        let client_stream = ct_client::transport::tcp_tls_connect(tcp_addr, ca_root)
            .await
            .unwrap();
        let resp = tokio::time::timeout(
            Duration::from_secs(15),
            ct_client::transport::client_tunnel_noise_tcp(
                client_stream,
                &token,
                &cap,
                &client_kp.private,
                b"hello-tcp-fallback",
            ),
        )
        .await
        .expect("round-trip timed out (relay/serve deadlock)")
        .unwrap();
        assert_eq!(
            resp, b"hello-tcp-fallback",
            "cross-host TCP-fallback Noise round-trip succeeds"
        );

        agent.abort();
        edge.abort();
    }
    use tokio::net::TcpListener;

    async fn echo_origin() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
            sock.shutdown().await.unwrap();
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn agent_relays_quic_stream_to_local_origin() {
        // Local TCP echo origin that closes its write side after echoing.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
            sock.shutdown().await.unwrap();
        });

        let (server, cert) = ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");

        // "Edge": open a relayed stream to the Agent, send "ping", read the echo.
        let edge = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            send.write_all(b"ping").await.unwrap();
            send.finish().unwrap();
            recv.read_to_end(64).await.unwrap()
        });

        // Agent: dial the edge, accept the relayed stream, serve it to origin.
        let conn = dial_quic(addr, cert).await.expect("agent dial");
        let (a_send, a_recv) = conn.accept_bi().await.unwrap();
        serve_stream_to_origin(a_send, a_recv, origin_addr)
            .await
            .expect("serve to origin");

        let echoed = edge.await.unwrap();
        assert_eq!(echoed, b"ping", "edge gets the origin's echo through the agent");
        let _ = origin.await;
    }

    #[tokio::test]
    async fn noise_bridge_decrypts_to_origin_and_reencrypts() {
        use ct_common::noise::{client_handshake_for, frame, generate_static_keypair};
        use ct_common::{Capability, OriginIdentity, RoutingToken};

        // A real TCP echo Origin — it only ever sees plaintext.
        let (origin_addr, origin) = echo_origin().await;

        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: RoutingToken([0u8; 32]),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "edge:443".into(),
        };

        let (client_io, server_io) = tokio::io::duplex(8192);
        let (mut c_read, mut c_write) = tokio::io::split(client_io);

        // Agent-side responder bridge (the code under test).
        let origin_priv = origin_kp.private;
        let bridge = tokio::spawn(async move {
            let (mut s_read, mut s_write) = tokio::io::split(server_io);
            serve_noise_bridge(&mut s_write, &mut s_read, origin_addr, &origin_priv).await
        });

        // Inline Client initiator (mirrors ct-client::noise::client_noise_exchange).
        let mut hs = client_handshake_for(&client_kp.private, &cap).expect("initiator");
        let mut buf = vec![0u8; 65535];
        let mut tmp = vec![0u8; 65535];
        let n = hs.write_message(&[], &mut buf).unwrap();
        c_write.write_all(&frame(&buf[..n])).await.unwrap();
        let m2 = read_frame(&mut c_read).await.unwrap();
        hs.read_message(&m2, &mut tmp).unwrap();
        let mut transport = hs.into_transport_mode().unwrap();
        let n = transport.write_message(b"secret-request", &mut buf).unwrap();
        c_write.write_all(&frame(&buf[..n])).await.unwrap();
        let resp_ct = read_frame(&mut c_read).await.unwrap();
        let n = transport.read_message(&resp_ct, &mut tmp).unwrap();

        assert_eq!(
            &tmp[..n],
            b"secret-request",
            "agent decrypted to origin, origin echoed, agent re-encrypted"
        );
        bridge.await.unwrap().expect("bridge ok");
        let _ = origin.await;
    }

    #[tokio::test]
    async fn serve_noise_stream_bridges_streaming_to_origin() {
        use ct_common::noise::{
            client_handshake_for, frame, generate_static_keypair, noise_pump, read_frame,
        };
        use ct_common::{Capability, OriginIdentity, RoutingToken};
        use tokio::net::TcpListener;

        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: RoutingToken([0u8; 32]),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "edge:443".into(),
        };

        // Streaming TCP echo Origin (echoes bytes as they arrive).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = sock.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
            let _ = w.shutdown().await;
        });

        let (ini_cipher, agent_cipher) = tokio::io::duplex(64 * 1024);

        // Agent under test: serve_noise_stream over the relayed cipher stream.
        let origin_priv = origin_kp.private;
        let metrics = std::sync::Arc::new(ct_common::metrics::TunnelMetrics::new());
        let mcheck = std::sync::Arc::clone(&metrics);
        let (a_read, a_write) = tokio::io::split(agent_cipher);
        let agent = tokio::spawn(async move {
            serve_noise_stream(a_write, a_read, origin_addr, &[origin_priv], metrics).await
        });

        // Initiator: handshake, then pump a 100 KB app stream over the session.
        let (mut i_read, mut i_write) = tokio::io::split(ini_cipher);
        let mut hs = client_handshake_for(&client_kp.private, &cap).unwrap();
        let mut buf = vec![0u8; 65535];
        let mut tmp = vec![0u8; 65535];
        let n = hs.write_message(&[], &mut buf).unwrap();
        i_write.write_all(&frame(&buf[..n])).await.unwrap();
        let m2 = read_frame(&mut i_read).await.unwrap();
        hs.read_message(&m2, &mut tmp).unwrap();
        let ini_t = hs.into_transport_mode().unwrap();

        let (app_local, app_remote) = tokio::io::duplex(1024 * 1024);
        let cipher = tokio::io::join(i_read, i_write);
        let pump = tokio::spawn(noise_pump(ini_t, cipher, app_local));

        let expected: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let (mut app_r, mut app_w) = tokio::io::split(app_remote);
        let payload = expected.clone();
        let writer = tokio::spawn(async move {
            app_w.write_all(&payload).await.unwrap();
            app_w.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        app_r.read_to_end(&mut got).await.unwrap();

        assert_eq!(got, expected, "100 KB streams through serve_noise_stream to the echo Origin");
        writer.await.unwrap();
        pump.await.unwrap().unwrap();
        agent.await.unwrap().unwrap();
        origin.abort();

        // The serve task recorded the handshake and metered both directions.
        assert_eq!(mcheck.tunnels_opened.get(), 1, "one tunnel opened");
        assert_eq!(mcheck.tunnels_failed.get(), 0, "no failures");
        assert_eq!(mcheck.handshakes.get(), 1, "one handshake observed");
        assert_eq!(mcheck.bytes_to_origin.get(), 100_000, "100 KB forwarded to the origin");
        assert_eq!(mcheck.bytes_to_client.get(), 100_000, "100 KB echoed back to the client");
    }

    #[tokio::test]
    async fn serve_noise_stream_selects_the_pinned_key_from_a_rotation_set() {
        // #12 K2: an agent serving a SET of origin keys (a rotation window)
        // terminates the handshake for the identity the client pinned, even when
        // it isn't the first key in the set.
        use ct_common::noise::{
            client_handshake_for, frame, generate_static_keypair, noise_pump, read_frame,
        };
        use ct_common::{Capability, OriginIdentity, RoutingToken};
        use tokio::net::TcpListener;

        let old_kp = generate_static_keypair();
        let new_kp = generate_static_keypair(); // the client pins THIS one
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: RoutingToken([0u8; 32]),
            origin: OriginIdentity(new_kp.public),
            edge_addr: "edge:443".into(),
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = sock.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
            let _ = w.shutdown().await;
        });

        let (ini_cipher, agent_cipher) = tokio::io::duplex(64 * 1024);
        // Rotation window: old key first, the pinned new key second.
        let key_set = vec![old_kp.private, new_kp.private];
        let metrics = std::sync::Arc::new(ct_common::metrics::TunnelMetrics::new());
        let mcheck = std::sync::Arc::clone(&metrics);
        let (a_read, a_write) = tokio::io::split(agent_cipher);
        let agent = tokio::spawn(async move {
            serve_noise_stream(a_write, a_read, origin_addr, &key_set, metrics).await
        });

        let (mut i_read, mut i_write) = tokio::io::split(ini_cipher);
        let mut hs = client_handshake_for(&client_kp.private, &cap).unwrap();
        let mut buf = vec![0u8; 65535];
        let mut tmp = vec![0u8; 65535];
        let n = hs.write_message(&[], &mut buf).unwrap();
        i_write.write_all(&frame(&buf[..n])).await.unwrap();
        let m2 = read_frame(&mut i_read).await.unwrap();
        hs.read_message(&m2, &mut tmp).unwrap();
        let ini_t = hs.into_transport_mode().unwrap();

        let (app_local, app_remote) = tokio::io::duplex(1024 * 1024);
        let cipher = tokio::io::join(i_read, i_write);
        let pump = tokio::spawn(noise_pump(ini_t, cipher, app_local));
        let (mut app_r, mut app_w) = tokio::io::split(app_remote);
        let writer = tokio::spawn(async move {
            app_w.write_all(b"hello-rotation").await.unwrap();
            app_w.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        app_r.read_to_end(&mut got).await.unwrap();

        assert_eq!(got, b"hello-rotation", "round-trip via the pinned (non-first) key");
        writer.await.unwrap();
        pump.await.unwrap().unwrap();
        agent.await.unwrap().unwrap();
        origin.abort();
        assert_eq!(mcheck.tunnels_opened.get(), 1, "agent selected the pinned key and served");
    }

    #[tokio::test]
    async fn serve_noise_udp_bridges_datagrams_to_origin() {
        use ct_common::noise::{client_handshake_for, frame, generate_static_keypair, read_frame};
        use ct_common::{Capability, OriginIdentity, RoutingToken};
        use tokio::io::AsyncWriteExt;
        use tokio::net::UdpSocket;

        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: RoutingToken([0u8; 32]),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "edge:443".into(),
        };

        // UDP echo Origin.
        let origin_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_sock.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let mut b = vec![0u8; 65535];
            while let Ok((n, peer)) = origin_sock.recv_from(&mut b).await {
                let _ = origin_sock.send_to(&b[..n], peer).await;
            }
        });

        let (ini_cipher, agent_cipher) = tokio::io::duplex(64 * 1024);
        let origin_priv = origin_kp.private;
        let (a_read, a_write) = tokio::io::split(agent_cipher);
        let agent =
            tokio::spawn(async move { serve_noise_udp(a_write, a_read, origin_addr, &[origin_priv]).await });

        // Initiator: handshake, then send discrete datagrams and read echoes.
        let (mut i_read, mut i_write) = tokio::io::split(ini_cipher);
        let mut hs = client_handshake_for(&client_kp.private, &cap).unwrap();
        let mut buf = vec![0u8; 65535];
        let mut tmp = vec![0u8; 65535];
        let n = hs.write_message(&[], &mut buf).unwrap();
        i_write.write_all(&frame(&buf[..n])).await.unwrap();
        let m2 = read_frame(&mut i_read).await.unwrap();
        hs.read_message(&m2, &mut tmp).unwrap();
        let mut transport = hs.into_transport_mode().unwrap();

        for msg in [b"one".as_slice(), b"two", b"a-longer-datagram-payload"] {
            let n = transport.write_message(msg, &mut buf).unwrap();
            i_write.write_all(&frame(&buf[..n])).await.unwrap();
            let fr = read_frame(&mut i_read).await.unwrap();
            let n = transport.read_message(&fr, &mut tmp).unwrap();
            assert_eq!(&tmp[..n], msg, "UDP datagram boundary + content preserved through the tunnel");
        }

        // Close the tunnel so serve_noise_udp's reader hits EOF and returns.
        // NOTE: `drop(i_write)` does NOT signal EOF while the split ReadHalf is
        // alive (the DuplexStream stays open) — an explicit shutdown is required.
        i_write.shutdown().await.unwrap();
        agent.await.unwrap().unwrap();
        origin.abort();
    }

    #[tokio::test]
    async fn serve_direct_bridges_a_direct_connection() {
        // M11.4b-iii: serve_direct accepts a direct Client connection and serves
        // it as the Noise responder straight to the Origin (no Edge).
        use crate::transport::build_direct_listener_at;
        use ct_common::noise::{client_handshake_for, frame, generate_static_keypair, read_frame};
        use ct_common::{Capability, OriginIdentity, RoutingToken};
        use std::net::Ipv4Addr;

        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: RoutingToken([0u8; 32]),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "edge:443".into(),
        };

        let (origin_addr, origin) = echo_origin().await;
        let (listener, cert) =
            build_direct_listener_at((Ipv4Addr::LOCALHOST, 0).into()).expect("listener");
        let laddr = listener.local_addr().expect("laddr");
        let opriv = origin_kp.private;
        let dmetrics = std::sync::Arc::new(ct_common::metrics::TunnelMetrics::new());
        let srv = tokio::spawn(async move {
            let _ = serve_direct(listener, origin_addr, std::sync::Arc::new(vec![opriv]), OriginProto::Tcp, dmetrics).await;
        });

        // Inline Client: connect directly to the listener, handshake, one payload.
        let client = ct_edge::transport::build_client_endpoint(cert).expect("client");
        let conn = client.connect(laddr, "localhost").expect("cfg").await.expect("conn");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let mut hs = client_handshake_for(&client_kp.private, &cap).unwrap();
        let mut buf = vec![0u8; 65535];
        let mut tmp = vec![0u8; 65535];
        let n = hs.write_message(&[], &mut buf).unwrap();
        send.write_all(&frame(&buf[..n])).await.unwrap();
        let m2 = read_frame(&mut recv).await.unwrap();
        hs.read_message(&m2, &mut tmp).unwrap();
        let mut transport = hs.into_transport_mode().unwrap();
        let n = transport.write_message(b"direct-serve", &mut buf).unwrap();
        send.write_all(&frame(&buf[..n])).await.unwrap();
        let resp = read_frame(&mut recv).await.unwrap();
        let n = transport.read_message(&resp, &mut tmp).unwrap();
        assert_eq!(&tmp[..n], b"direct-serve", "serve_direct bridged the direct connection to the origin");

        conn.close(0u32.into(), b"done");
        srv.abort();
        let _ = origin.await;
    }

    #[tokio::test]
    async fn run_agent_reconnects_after_the_edge_connection_drops() {
        // issue #5 / P1.2b: when the registered edge connection closes, the agent
        // re-dials and re-registers instead of dying.
        use ct_edge::serve::register_agent;
        use ct_edge::state::EdgeState;
        use ct_edge::transport::build_server_endpoint_with_cert;
        use quinn::Connection;
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        use std::sync::Arc;

        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().unwrap();
        let state = Arc::new(EdgeState::<Connection>::new());
        let regs = Arc::new(AtomicUsize::new(0));

        let state_e = state.clone();
        let regs_e = regs.clone();
        let edge = tokio::spawn(async move {
            // First registration, then close the connection to force a reconnect.
            let c1 = server.accept().await.unwrap().await.unwrap();
            register_agent(&c1, &state_e).await.unwrap();
            regs_e.fetch_add(1, SeqCst);
            c1.close(0u32.into(), b"drop");
            // A second registration proves the agent reconnected + re-registered.
            let c2 = server.accept().await.unwrap().await.unwrap();
            register_agent(&c2, &state_e).await.unwrap();
            regs_e.fetch_add(1, SeqCst);
            c2.closed().await;
        });

        let cfg = AgentConfig::parse(&addr.to_string(), "127.0.0.1:9").unwrap();
        let agent = tokio::spawn(async move {
            let _ = run_agent(&cfg, cert, RoutingToken([1u8; 32]), std::sync::Arc::new(vec![[0u8; 32]])).await;
        });

        // Initial registration + one reconnect, within the backoff window.
        for _ in 0..400 {
            if regs.load(SeqCst) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            regs.load(SeqCst),
            2,
            "agent re-registered after the edge connection dropped"
        );
        agent.abort();
        edge.abort();
    }

    #[tokio::test]
    async fn tcp_fallback_reconnects_after_a_tunnel_drops() {
        // issue #5 / P1.2b: the TLS-TCP fallback re-registers after each tunnel.
        use ct_edge::pki::{build_dual_edge_from_ca, Ca};
        use std::net::Ipv4Addr;
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        use std::sync::Arc;

        let ca = Ca::new("f53-ca").unwrap();
        let (_ep, tcp_listener, acceptor, ca_root) = build_dual_edge_from_ca(
            &ca,
            (Ipv4Addr::LOCALHOST, 0).into(),
            (Ipv4Addr::LOCALHOST, 0).into(),
            vec!["localhost".to_string()],
        )
        .await
        .unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let regs = Arc::new(AtomicUsize::new(0));

        // Edge: accept two TLS registrations, ack each, then drop the stream.
        let regs_e = regs.clone();
        let edge = tokio::spawn(async move {
            for _ in 0..2 {
                let (tcp, _) = tcp_listener.accept().await.unwrap();
                let mut tls = acceptor.accept(tcp).await.unwrap();
                let mut hdr = [0u8; 33];
                tls.read_exact(&mut hdr).await.unwrap();
                assert_eq!(hdr[0], b'A');
                tls.write_all(b"OK").await.unwrap();
                tls.flush().await.unwrap();
                regs_e.fetch_add(1, SeqCst);
                // drop `tls` -> the agent's serve sees EOF -> reconnects.
            }
        });

        let cfg = AgentConfig::parse(&tcp_addr.to_string(), "127.0.0.1:9").unwrap();
        let agent = tokio::spawn(async move {
            let _ = run_agent_tcp_fallback(&cfg, ca_root, RoutingToken([2u8; 32]), std::sync::Arc::new(vec![[0u8; 32]])).await;
        });

        for _ in 0..400 {
            if regs.load(SeqCst) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            regs.load(SeqCst),
            2,
            "TLS-TCP fallback re-registered after the tunnel dropped"
        );
        agent.abort();
        edge.abort();
    }

    #[tokio::test]
    async fn tcp_fallback_pool_holds_n_registrations_parked_concurrently() {
        // #229: a real browser page load opens several parallel connections
        // per origin. With the old implicit pool-of-1, only ever one
        // registration was parked at a time -- every simultaneous Client
        // beyond the first got "no agent tunnel for token" even though the
        // Agent process was completely healthy. Proves a pool of N actually
        // holds N registrations parked AT ONCE (not released until this test
        // says so), rather than one-at-a-time.
        use ct_edge::pki::{build_dual_edge_from_ca, Ca};
        use std::net::Ipv4Addr;
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

        const POOL: usize = 4;

        let ca = Ca::new("pool-ca").unwrap();
        let (_ep, tcp_listener, acceptor, ca_root) = build_dual_edge_from_ca(
            &ca,
            (Ipv4Addr::LOCALHOST, 0).into(),
            (Ipv4Addr::LOCALHOST, 0).into(),
            vec!["localhost".to_string()],
        )
        .await
        .unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let registered = Arc::new(AtomicUsize::new(0));

        // Edge: accept POOL registrations, ack each, then hold every stream
        // open (parked, not dropped/relayed) so they stay outstanding at once
        // -- proving the Agent actually opened POOL concurrent connections
        // rather than opening #2 only after #1 finished.
        let registered_e = registered.clone();
        let edge = tokio::spawn(async move {
            let mut held = Vec::with_capacity(POOL);
            for _ in 0..POOL {
                let (tcp, _) = tcp_listener.accept().await.unwrap();
                let mut tls = acceptor.accept(tcp).await.unwrap();
                let mut hdr = [0u8; 33];
                tls.read_exact(&mut hdr).await.unwrap();
                assert_eq!(hdr[0], b'A');
                tls.write_all(b"OK").await.unwrap();
                tls.flush().await.unwrap();
                registered_e.fetch_add(1, SeqCst);
                held.push(tls); // keep it open -- prove it doesn't need to close first
            }
            // Hold until the test has observed all POOL, then let them drop.
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let mut cfg = AgentConfig::parse(&tcp_addr.to_string(), "127.0.0.1:9").unwrap();
        cfg.tcp_fallback_pool_size = POOL;
        let agent = tokio::spawn(async move {
            let _ =
                run_agent_tcp_fallback(&cfg, ca_root, RoutingToken([0x44u8; 32]), Arc::new(vec![[0u8; 32]])).await;
        });

        // If pooling didn't work (still one-at-a-time), this never reaches
        // POOL within the bound -- the 2nd+ registration would only start
        // once the edge released the 1st, which it deliberately never does
        // here until the sleep above ends.
        let mut reached = 0;
        for _ in 0..300 {
            reached = registered.load(SeqCst);
            if reached >= POOL {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(reached, POOL, "all {POOL} registrations were parked concurrently, not one-at-a-time");

        agent.abort();
        edge.abort();
    }

    #[tokio::test]
    async fn run_agent_registers_and_serves_relayed_streams() {
        use ct_common::noise::{client_handshake_for, frame, generate_static_keypair};
        use ct_common::{Capability, OriginIdentity};
        use ct_edge::state::EdgeState;
        use quinn::Connection;
        use std::sync::Arc;

        let (origin_addr, origin) = echo_origin().await;

        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let token = RoutingToken([3u8; 32]);
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "edge:443".into(),
        };

        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let edge_addr = server.local_addr().expect("addr");

        // Edge: accept the Agent, register it, then act as the Noise initiator
        // over a relayed stream and return the decrypted echo.
        let state_e = state.clone();
        let cap_e = cap.clone();
        let client_priv = client_kp.private;
        let edge = tokio::spawn(async move {
            let agent_conn = server.accept().await.unwrap().await.unwrap();
            ct_edge::serve::register_agent(&agent_conn, &state_e)
                .await
                .map_err(|e| e.to_string())?;
            let (mut send, mut recv) = agent_conn.open_bi().await.unwrap();

            let mut hs = client_handshake_for(&client_priv, &cap_e).map_err(|e| e.to_string())?;
            let mut buf = vec![0u8; 65535];
            let mut tmp = vec![0u8; 65535];
            let n = hs.write_message(&[], &mut buf).unwrap();
            send.write_all(&frame(&buf[..n])).await.unwrap();
            let m2 = read_frame(&mut recv).await.map_err(|e| e.to_string())?;
            hs.read_message(&m2, &mut tmp).unwrap();
            let mut transport = hs.into_transport_mode().unwrap();
            let n = transport.write_message(b"ping", &mut buf).unwrap();
            send.write_all(&frame(&buf[..n])).await.unwrap();
            let resp_ct = read_frame(&mut recv).await.map_err(|e| e.to_string())?;
            let n = transport.read_message(&resp_ct, &mut tmp).unwrap();
            Ok::<Vec<u8>, String>(tmp[..n].to_vec())
        });

        // Agent: run the full loop (dial → register → accept-and-serve-noise).
        let config = AgentConfig {
            edge: edge_addr,
            origin: origin_addr,
            origin_proto: OriginProto::Tcp,
            direct_advertise_ip: None,
            metrics_listen: None,
            browser_forward: false,
            hostname: None,
            fallback_443: false,
            tcp_fallback_pool_size: 4,
        };
        let token_a = token.clone();
        let origin_priv = origin_kp.private;
        let agent = tokio::spawn(async move {
            let _ = run_agent(&config, cert, token_a, std::sync::Arc::new(vec![origin_priv])).await;
        });

        let echoed = edge.await.unwrap().unwrap();
        assert_eq!(echoed, b"ping", "Noise-relayed stream reaches origin and echoes back");
        assert!(state.is_known(&token), "agent registered its tunnel");
        agent.abort();
        let _ = origin.await;
    }

    #[tokio::test]
    async fn serve_stream_to_origin_carries_a_full_tls_session() {
        // #23 BP2: the Agent's browser-forward mode pipes a relayed stream to the
        // Origin verbatim, so a browser's TLS terminates AT the Origin. Prove a
        // full TLS handshake + HTTP exchange survives serve_stream_to_origin.
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _ = rustls::crypto::ring::default_provider().install_default();
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
        let ol = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = ol.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (s, _) = ol.accept().await.unwrap();
            let mut tls = acceptor.accept(s).await.expect("origin TLS handshake");
            let mut b = [0u8; 1024];
            let n = tls.read(&mut b).await.unwrap();
            assert!(b[..n].starts_with(b"GET "), "origin got an HTTP request over TLS");
            tls.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .await
                .unwrap();
            tls.shutdown().await.unwrap();
        });

        // Agent under test: QUIC server; accept a bi-stream, raw-forward to origin.
        let (server, cert) =
            ct_edge::transport::build_server_endpoint_with_cert().expect("agent quic");
        let agent_addr = server.local_addr().unwrap();
        let agent = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let (send, recv) = conn.accept_bi().await.unwrap();
            let _ = serve_stream_to_origin(send, recv, origin_addr).await;
            conn.closed().await;
        });

        // "Browser" over a QUIC bi-stream (standing in for the edge relay).
        let ep = ct_edge::transport::build_client_endpoint(cert).expect("client");
        let conn = ep
            .connect(agent_addr, "localhost")
            .expect("cfg")
            .await
            .expect("conn");
        let (send, recv) = conn.open_bi().await.unwrap();
        let stream = tokio::io::join(recv, send);
        let mut roots = rustls::RootCertStore::empty();
        roots.add(origin_cert).unwrap();
        let ccfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(ccfg));
        let sni = rustls::pki_types::ServerName::try_from("browser.test").unwrap();
        let mut tls = connector
            .connect(sni, stream)
            .await
            .expect("browser TLS completes end-to-end through the raw forward");
        tls.write_all(b"GET / HTTP/1.0\r\nHost: browser.test\r\n\r\n").await.unwrap();
        tls.flush().await.unwrap();
        let mut resp = Vec::new();
        tls.read_to_end(&mut resp).await.unwrap();
        let page = String::from_utf8_lossy(&resp);
        assert!(
            page.contains("200 OK") && page.contains("hello"),
            "HTTP 200 over TLS survives the agent raw forward: {page}"
        );
        conn.close(0u32.into(), b"done");
        agent.abort();
        origin.abort();
    }

    #[tokio::test]
    async fn serve_duplex_to_origin_dials_the_origin_lazily_after_the_clients_first_bytes() {
        // #229 follow-up: dialing the Origin eagerly (before any Client has
        // actually arrived) leaves an idle connection open for however long
        // this Agent sits parked waiting for a real Client -- long enough, in
        // practice, to outlive the Origin's own idle/keep-alive timeout, so
        // the very first real request lands on an already-dead connection.
        // Prove the Origin is untouched while the Client side is silent, and
        // only dialed once real bytes actually arrive.
        let ol = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = ol.local_addr().unwrap();
        let accepted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let accepted_w = accepted.clone();
        let origin = tokio::spawn(async move {
            let (mut s, _) = ol.accept().await.unwrap();
            accepted_w.store(true, std::sync::atomic::Ordering::SeqCst);
            let mut b = [0u8; 1024];
            let n = s.read(&mut b).await.unwrap();
            assert_eq!(&b[..n], b"hello origin");
            s.write_all(b"hi client").await.unwrap();
        });

        let (mut client_side, agent_side) = tokio::io::duplex(1024);
        let relay = tokio::spawn(async move { serve_duplex_to_origin(agent_side, origin_addr).await });

        // Give the relay every chance to have dialed already, if it were going
        // to dial eagerly -- it must not have.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!accepted.load(std::sync::atomic::Ordering::SeqCst), "must not dial the Origin before the Client sends anything");

        client_side.write_all(b"hello origin").await.unwrap();
        client_side.flush().await.unwrap();
        let mut resp = [0u8; 1024];
        let n = client_side.read(&mut resp).await.unwrap();
        assert_eq!(&resp[..n], b"hi client");
        assert!(accepted.load(std::sync::atomic::Ordering::SeqCst), "dials once the Client actually speaks");

        drop(client_side);
        let _ = relay.await;
        let _ = origin.await;
    }
}
