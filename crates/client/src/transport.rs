//! Client → Edge transport (M5.3a).

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use crate::noise::client_noise_exchange;
use ct_common::noise::{client_handshake_for, frame, noise_pump, read_frame, read_frame_into};
use ct_common::pow::{assemble_request, solve, Challenge};
use ct_common::{Capability, RoutingToken};
use quinn::{Connection, Endpoint};
use rustls::pki_types::CertificateDer;
use std::io;
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::{join, split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a PoW-gated rendezvous request, offloading the CPU-bound solve to a blocking
/// thread (#202). `pow::solve` is a tight brute-force loop whose cost grows ~2^difficulty;
/// called inline it would occupy an async worker thread for the whole solve — on exactly
/// the flood-gating path. `spawn_blocking` runs it on Tokio's blocking pool so the async
/// runtime keeps servicing other tasks meanwhile, then we assemble the wire form via
/// `pow::assemble_request` (the shared layout, no duplication). Used by every client
/// rendezvous path in place of the sync `build_request`.
pub(crate) async fn build_request_blocking(challenge: &Challenge, token: &RoutingToken) -> Result<Vec<u8>, BoxError> {
    let challenge = challenge.clone();
    let solve_token = token.clone();
    let solution = tokio::task::spawn_blocking(move || solve(&challenge, &solve_token))
        .await
        .expect("pow solve task panicked")?;
    Ok(assemble_request(solution, token))
}

/// Build a fresh outgoing-only `quinn::Endpoint` (one ephemeral UDP socket),
/// bound to all interfaces (not loopback) so the Client can reach a non-local
/// Edge.
///
/// #368: split out of [`dial_edge`] so a caller that dials multiple times
/// within its own already-bounded async scope -- concretely,
/// [`crate::ladder::connect_via_ladder`]'s own concurrent rung racing (#367),
/// which can now genuinely call [`dial_edge_with_endpoint`] more than once at
/// the same moment for one connection attempt -- can build ONE endpoint once
/// and reuse it across every rung dial, instead of each racing rung binding
/// its own throwaway socket. A **process-global** shared endpoint was tried
/// first and reverted: `quinn::Endpoint` owns a background driver task tied to
/// the specific Tokio runtime it was created under, and a `static` shared
/// across `#[tokio::test]`'s separate per-test runtimes (or, in principle,
/// across separate runtimes in one real process) breaks with a real
/// `ConnectError::EndpointStopping` -- proven live by 24 real test failures
/// during this fix's own development, not a hypothetical. Explicitly scoping
/// the shared endpoint's lifetime to one caller's own async call (never a
/// process-wide `static`) avoids that hazard entirely, mirroring
/// `client_forward_conn`'s own explicitly-owned-and-passed shared-state
/// pattern (#366) rather than a bare global.
pub fn new_client_endpoint() -> io::Result<Endpoint> {
    Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
}

/// Dial the Edge over `endpoint`, trusting `edge_cert`, via quinn's own
/// per-connection [`Endpoint::connect_with`] (not a single cached "default"
/// config set on the endpoint) -- `edge_cert` genuinely varies per call on a
/// SHARED endpoint in this codebase: [`client_direct_connect`] dials an
/// Agent's own `agent_cert` through the exact same connect path, a real,
/// different-cert-in-the-same-endpoint case, not a hypothetical. Building the
/// per-cert `rustls`/`quinn::ClientConfig` fresh each call is real but
/// comparatively cheap next to binding a new UDP socket and spawning a new
/// endpoint driver task -- the actual cost #368's own review flagged, and the
/// part [`new_client_endpoint`] lets a caller stop paying repeatedly.
pub async fn dial_edge_with_endpoint(
    endpoint: &Endpoint,
    edge: SocketAddr,
    edge_cert: CertificateDer<'static>,
) -> Result<Connection, BoxError> {
    install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(edge_cert)?;
    let crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    let conn = endpoint.connect_with(cfg, edge, "localhost")?.await?;
    Ok(conn)
}

/// Dial the Edge over QUIC, trusting `edge_cert`, on a fresh one-shot endpoint.
/// Unchanged single-dial behavior (#368 adds [`dial_edge_with_endpoint`]
/// alongside this, for callers that want to reuse one endpoint across several
/// dials within their own async scope; see its own doc comment for why that's
/// scoped per-caller, not a process-global).
pub async fn dial_edge(
    edge: SocketAddr,
    edge_cert: CertificateDer<'static>,
) -> Result<Connection, BoxError> {
    let endpoint = new_client_endpoint()?;
    dial_edge_with_endpoint(&endpoint, edge, edge_cert).await
}

/// [`dial_edge`] bounded by `timeout` (#284). The p2p/udp client modes dial the
/// Edge directly (unlike single-tunnel/forward modes, which route through
/// `dial_rung`'s own per-rung timeout via the Ladder) -- a blackholed or
/// stalled Edge IP hung the bare call forever, and p2p mode's 5-attempt retry
/// loop never advanced past attempt 1.
pub async fn dial_edge_timed(
    edge: SocketAddr,
    edge_cert: CertificateDer<'static>,
    timeout: Duration,
) -> Result<Connection, BoxError> {
    match tokio::time::timeout(timeout, dial_edge(edge, edge_cert)).await {
        Ok(r) => r,
        Err(_) => Err(tunnel_timeout_error(timeout)),
    }
}

/// Load an Edge certificate (DER) the Edge published to a shared path.
pub fn load_cert(path: impl AsRef<Path>) -> std::io::Result<CertificateDer<'static>> {
    Ok(CertificateDer::from(std::fs::read(path)?))
}

/// Tunnel `payload` to the Origin over Noise E2E (M8.4a): open a stream, complete
/// the PoW-gated rendezvous for `token`, then run the `Noise_IK` exchange
/// (pinning `cap`'s Origin Identity) and return the decrypted response. The Edge
/// only relays the resulting ciphertext frames.
pub async fn client_tunnel_noise(
    conn: &Connection,
    token: &RoutingToken,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>, BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"C").await?;

    let mut chal = [0u8; 17];
    recv.read_exact(&mut chal).await?;
    let challenge = Challenge {
        nonce: chal[..16].try_into().unwrap(),
        difficulty: chal[16],
    };
    let req = build_request_blocking(&challenge, token).await?;
    send.write_all(&req).await?;

    // The stream is now bridged to the Agent; run Noise over it.
    let response = client_noise_exchange(&mut send, &mut recv, client_private, cap, payload).await?;
    send.finish()?;
    Ok(response)
}

/// Connect to the Edge's TCP+TLS fallback at `addr`, trusting `edge_cert`
/// (M12.3b) — used when outbound UDP/QUIC is blocked.
pub async fn tcp_tls_connect(
    addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, BoxError> {
    install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(edge_cert)?;
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(addr).await?;
    let server_name = rustls::pki_types::ServerName::try_from("localhost")?;
    Ok(connector.connect(server_name, tcp).await?)
}

/// A live Edge connection over whichever ladder rung succeeded (#31 FD3-b): QUIC
/// (primary/fast) or the TLS-TCP fallback. The tunnel operation dispatches on the
/// variant — QUIC opens a bi-stream, TCP reuses the single stream — so both the
/// direct ports and the `:443` front-door rungs converge on one connection type.
pub enum EdgeConn {
    Quic(Connection),
    Tcp(tokio_rustls::client::TlsStream<TcpStream>),
}

/// Dial one ladder [`Rung`](crate::ladder::Rung) at `edge_ip`, trusting
/// `edge_cert`, bounded by `timeout`. A QUIC rung maps to [`dial_edge`], a TLS-TCP
/// rung to [`tcp_tls_connect`], each on the rung's own port. Returns `None` on
/// timeout or failure so [`crate::ladder::connect_via_ladder`] walks to the next
/// rung instead of surfacing the error — the ladder only cares "did this rung
/// connect?", and a blocked rung on a restrictive network simply times out.
/// #368: `quic_endpoint` is the one real endpoint every `Rung::Quic` dial for
/// this connection attempt reuses -- built once by the caller (see
/// [`new_client_endpoint`]) before racing the ladder (#367 lets multiple
/// rungs genuinely dial concurrently), instead of each rung binding its own
/// throwaway UDP socket. TLS-TCP rungs are unaffected; they never used QUIC.
pub async fn dial_rung(
    rung: crate::ladder::Rung,
    edge_ip: std::net::IpAddr,
    edge_cert: CertificateDer<'static>,
    quic_endpoint: &Endpoint,
    timeout: Duration,
) -> Option<EdgeConn> {
    use crate::ladder::Rung;
    match rung {
        Rung::Quic(port) => {
            let addr = SocketAddr::new(edge_ip, port);
            match tokio::time::timeout(timeout, dial_edge_with_endpoint(quic_endpoint, addr, edge_cert)).await {
                Ok(Ok(c)) => Some(EdgeConn::Quic(c)),
                _ => None,
            }
        }
        Rung::TlsTcp(port) => {
            let addr = SocketAddr::new(edge_ip, port);
            match tokio::time::timeout(timeout, tcp_tls_connect(addr, edge_cert)).await {
                Ok(Ok(c)) => Some(EdgeConn::Tcp(c)),
                _ => None,
            }
        }
    }
}

/// Tunnel `payload` to the Origin over a **TCP-fallback** stream (M12.2c): when
/// UDP/QUIC is blocked, the Client connects to the Edge via TLS-TCP and runs the
/// same `'C'` rendezvous + Noise exchange over that single byte stream. Generic
/// over the stream so it works with a `tokio-rustls` client TLS stream.
pub async fn client_tunnel_noise_tcp<T>(
    mut stream: T,
    token: &RoutingToken,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>, BoxError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // 'C' rendezvous over the single stream.
    stream.write_all(b"C").await?;
    let mut chal = [0u8; 17];
    stream.read_exact(&mut chal).await?;
    let challenge = Challenge {
        nonce: chal[..16].try_into().unwrap(),
        difficulty: chal[16],
    };
    let req = build_request_blocking(&challenge, token).await?;
    stream.write_all(&req).await?;

    // Noise over the same stream (split into read/write halves).
    let (mut r, mut w) = split(stream);
    let response = client_noise_exchange(&mut w, &mut r, client_private, cap, payload).await?;
    Ok(response)
}

/// Default bound on streaming-tunnel *setup* (the rendezvous challenge + Noise
/// handshake), mirroring the one-shot timed tunnels' `deadline` (issue #123). A
/// stalled edge that accepts the connection but never relays fails fast here
/// instead of leaking a blocked task holding an open local socket. Matches the
/// client's default tunnel timeout.
pub const DEFAULT_STREAM_SETUP_DEADLINE: Duration = Duration::from_secs(10);

/// A tunnel-operation timeout error (issue #2): the edge accepted the connection
/// but never relayed, so the client would otherwise block indefinitely.
fn tunnel_timeout_error(deadline: Duration) -> BoxError {
    format!(
        "tunnel operation timed out after {}s (edge reachable but no relay — is an agent registered for this token?)",
        deadline.as_secs()
    )
    .into()
}

/// [`client_tunnel_noise`] with an overall `deadline` on the tunnel operation, so
/// the client never hangs when the edge accepts the QUIC connection but cannot
/// relay (e.g. no agent is registered for the token). Returns a clear timeout
/// error instead of blocking. (issue #2)
pub async fn client_tunnel_noise_timed(
    conn: &Connection,
    token: &RoutingToken,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
    deadline: Duration,
) -> Result<Vec<u8>, BoxError> {
    match tokio::time::timeout(
        deadline,
        client_tunnel_noise(conn, token, cap, client_private, payload),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => Err(tunnel_timeout_error(deadline)),
    }
}

/// [`client_tunnel_noise_tcp`] with an overall `deadline` — the TLS-over-TCP
/// equivalent of [`client_tunnel_noise_timed`]. (issue #2)
pub async fn client_tunnel_noise_tcp_timed<T>(
    stream: T,
    token: &RoutingToken,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
    deadline: Duration,
) -> Result<Vec<u8>, BoxError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::time::timeout(
        deadline,
        client_tunnel_noise_tcp(stream, token, cap, client_private, payload),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => Err(tunnel_timeout_error(deadline)),
    }
}

/// Open a **streaming** Noise tunnel (M9.3): PoW-gated rendezvous for `token`,
/// then the `Noise_IK` initiator handshake (pinning `cap`'s Origin Identity),
/// then [`noise_pump`] bridging the local `app` stream to the Origin over the
/// live session. Runs until either side closes. The Edge relays only ciphertext.
pub async fn client_tunnel_stream<P>(
    conn: &Connection,
    token: &RoutingToken,
    cap: &Capability,
    client_private: &[u8; 32],
    app: P,
    setup_deadline: Duration,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    let (mut send, mut recv) = conn.open_bi().await?;

    // Bound the rendezvous + Noise handshake with `setup_deadline`, mirroring the
    // one-shot timed tunnels (issue #123): if the edge accepts the connection but
    // never relays (no agent for the token, or a stalled/hostile edge), setup
    // fails fast instead of leaving this task blocked forever on a handshake read
    // while holding the local socket open. The bridge itself runs unbounded once
    // the session is up.
    let transport = match tokio::time::timeout(setup_deadline, async {
        send.write_all(b"C").await?;

        let mut chal = [0u8; 17];
        recv.read_exact(&mut chal).await?;
        let challenge = Challenge {
            nonce: chal[..16].try_into().unwrap(),
            difficulty: chal[16],
        };
        let req = build_request_blocking(&challenge, token).await?;
        send.write_all(&req).await?;

        // Noise_IK initiator handshake over the relayed stream.
        let mut hs = client_handshake_for(client_private, cap)?;
        let mut buf = vec![0u8; 65535];
        let mut tmp = vec![0u8; 65535];
        let n = hs.write_message(&[], &mut buf)?;
        send.write_all(&frame(&buf[..n])).await?;
        let m2 = read_frame(&mut recv).await?;
        hs.read_message(&m2, &mut tmp)?;
        Ok::<_, BoxError>(hs.into_transport_mode()?)
    })
    .await
    {
        Ok(r) => r?,
        Err(_) => return Err(tunnel_timeout_error(setup_deadline)),
    };

    // Bridge the local app stream <-> the Origin over the Noise session.
    let cipher = join(recv, send);
    noise_pump(transport, cipher, app).await?;
    Ok(())
}

/// #366: get the shared QUIC connection [`client_forward`] reuses across every
/// accepted local connection, redialing (a full QUIC handshake + TLS) only when
/// none is cached yet or the cached one is actually closed/closing --
/// `close_reason()` is a real, direct check (quinn's own API for this), not an
/// arbitrary IO error inferred to mean the connection died. Holds `shared`'s
/// lock across the redial itself so concurrently-accepted local connections
/// racing this call never redial in parallel: the first task to notice a
/// dead/missing connection redials once and caches it; every other task
/// blocked on the lock in the meantime simply reuses what it just cached,
/// instead of each independently paying for its own redundant QUIC handshake.
async fn client_forward_conn(
    shared: &tokio::sync::Mutex<Option<Connection>>,
    edge_addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
) -> Result<Connection, BoxError> {
    let mut guard = shared.lock().await;
    let needs_dial = match guard.as_ref() {
        Some(c) => c.close_reason().is_some(),
        None => true,
    };
    if needs_dial {
        let conn = dial_edge(edge_addr, edge_cert).await?;
        *guard = Some(conn.clone());
        Ok(conn)
    } else {
        Ok(guard.as_ref().expect("checked Some above").clone())
    }
}

/// Local-forward proxy (#22 HW2a): accept plain TCP connections on `listener`
/// and bridge each to the Origin via [`client_tunnel_stream`]. This turns the
/// payload-only client into a usable local port: any TCP/TLS app (curl, a
/// browser) can connect to `listener` and ride the tunnel, with TLS
/// terminating **at the Origin** (the Edge stays provider-blind). Runs until
/// cancelled.
///
/// #366: local connections share ONE underlying QUIC connection to the Edge
/// (dialed lazily on first accept, redialed via [`client_forward_conn`] only
/// if it's actually gone) instead of each paying for its own fresh QUIC
/// handshake + TLS. This changes zero cryptographic/trust properties: each
/// local connection still gets its own independent PoW-gated rendezvous AND
/// its own independent, fresh `Noise_IK` handshake, exactly as before --
/// [`client_tunnel_stream`] does both per call by opening its own
/// `conn.open_bi()` bidirectional QUIC **stream** and negotiating rendezvous +
/// Noise on that stream alone, regardless of which QUIC connection carries it.
/// That per-stream Noise session -- not the outer QUIC transport connection --
/// is what actually makes concurrent local connections independent (the Edge
/// only ever relays ciphertext it cannot decrypt or correlate across
/// sessions); sharing the transport connection removes only redundant
/// QUIC-handshake setup cost, nothing the tunnel's own trust model relies on.
pub async fn client_forward(
    listener: tokio::net::TcpListener,
    edge_addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    token: RoutingToken,
    cap: Capability,
    client_private: [u8; 32],
    setup_deadline: Duration,
) -> Result<(), BoxError> {
    let shared_conn: Arc<tokio::sync::Mutex<Option<Connection>>> = Arc::new(tokio::sync::Mutex::new(None));
    loop {
        let (sock, _peer) = listener.accept().await?;
        let edge_cert = edge_cert.clone();
        let token = token.clone();
        let cap = cap.clone();
        let shared_conn = shared_conn.clone();
        tokio::spawn(async move {
            match client_forward_conn(&shared_conn, edge_addr, edge_cert).await {
                Ok(conn) => {
                    // Never `conn.close()` here -- it's shared; closing it here would
                    // sever every OTHER local connection currently riding it. A dead
                    // connection is naturally noticed and redialed by the next accept's
                    // own `client_forward_conn` call via `close_reason()`.
                    if let Err(e) =
                        client_tunnel_stream(&conn, &token, &cap, &client_private, sock, setup_deadline)
                            .await
                    {
                        eprintln!("ct-client: forwarded connection ended: {e}");
                    }
                }
                Err(e) => eprintln!("ct-client: forward dial failed: {e}"),
            }
        });
    }
}

/// Open a **UDP** tunnel (M10.2): PoW-gated rendezvous + `Noise_IK` initiator
/// handshake, then bridge the local (connected) UDP socket `local` to the UDP
/// Origin over the Noise session. One datagram from `local` becomes one Noise
/// frame and vice versa, preserving datagram boundaries. Runs until the tunnel
/// stream closes (UDP itself has no EOF).
pub async fn client_tunnel_udp(
    conn: &Connection,
    token: &RoutingToken,
    cap: &Capability,
    client_private: &[u8; 32],
    local: UdpSocket,
    setup_deadline: Duration,
) -> Result<(), BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;

    // #419: bound the rendezvous + Noise handshake, mirroring every other
    // client entry point (`client_tunnel_stream`'s `setup_deadline`,
    // `client_tunnel_noise_timed`/`client_tunnel_noise_tcp_timed`'s `deadline`)
    // -- this was the one mode the existing timeout sweep missed, so a stalled
    // or hostile Edge could block this task on the setup read forever instead
    // of failing fast. The datagram bridge itself stays unbounded once the
    // session is actually up, same as every sibling.
    let transport = match tokio::time::timeout(setup_deadline, async {
        send.write_all(b"C").await?;

        let mut chal = [0u8; 17];
        recv.read_exact(&mut chal).await?;
        let challenge = Challenge {
            nonce: chal[..16].try_into().unwrap(),
            difficulty: chal[16],
        };
        let req = build_request_blocking(&challenge, token).await?;
        send.write_all(&req).await?;

        let mut hs = client_handshake_for(client_private, cap)?;
        let mut buf = vec![0u8; 65535];
        let mut tmp = vec![0u8; 65535];
        let n = hs.write_message(&[], &mut buf)?;
        send.write_all(&frame(&buf[..n])).await?;
        let m2 = read_frame(&mut recv).await?;
        hs.read_message(&m2, &mut tmp)?;
        Ok::<_, BoxError>(hs.into_transport_mode()?)
    })
    .await
    {
        Ok(r) => r?,
        Err(_) => return Err(tunnel_timeout_error(setup_deadline)),
    };

    let ts = Mutex::new(transport);
    // `e` infers to snow::Error (naming it needs snow as a direct dep).
    let noise_err = |e| io::Error::other(format!("{e}"));

    // Local datagram -> encrypt -> frame to the Edge.
    let to_edge = async {
        let mut dg = vec![0u8; 65535];
        let mut ct = vec![0u8; 65535 + 256];
        loop {
            let n = local.recv(&mut dg).await?;
            let len = ts.lock().unwrap().write_message(&dg[..n], &mut ct).map_err(noise_err)?;
            send.write_all(&frame(&ct[..len])).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), io::Error>(())
    };

    // Frame from the Edge -> decrypt -> local datagram.
    //
    // #373: this used to call `read_frame` (a fresh `Vec` allocated per call) even
    // though it already holds a reusable `pt` scratch buffer right below for the
    // decrypt side -- `read_frame_into` (already real, tested, and used by
    // `noise_pump`'s own bulk data path for the identical reason, #114) reads into
    // a caller-owned buffer instead, so this loop no longer allocates a fresh `Vec`
    // per received datagram.
    let from_edge = async {
        let mut fr = Vec::new();
        let mut pt = vec![0u8; 65535];
        loop {
            if read_frame_into(&mut recv, &mut fr).await.is_err() {
                break;
            }
            let len = ts.lock().unwrap().read_message(&fr, &mut pt).map_err(noise_err)?;
            local.send(&pt[..len]).await?;
        }
        Ok::<(), io::Error>(())
    };

    tokio::select! {
        r = to_edge => r?,
        r = from_edge => r?,
    }
    Ok(())
}

/// Attempt a **direct** QUIC connection to the Agent's advertised candidate
/// (M11.3c), trusting `agent_cert`, within `timeout`. On success the Client can
/// tunnel straight to the Agent, bypassing the Edge relay; on timeout/failure the
/// caller falls back to the relay path (M11.4).
pub async fn client_direct_connect(
    candidate: SocketAddr,
    agent_cert: CertificateDer<'static>,
    timeout: Duration,
) -> Result<Connection, BoxError> {
    match tokio::time::timeout(timeout, dial_edge(candidate, agent_cert)).await {
        Ok(res) => res,
        Err(_) => Err("direct connect timed out".into()),
    }
}

/// Tunnel `payload` to the Origin over a **direct** connection to the Agent
/// (M11.3c): no Edge rendezvous or PoW — the Noise handshake authenticates the
/// path (Client pins the Origin Identity). Returns the decrypted response.
pub async fn client_tunnel_direct(
    conn: &Connection,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>, BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let response = client_noise_exchange(&mut send, &mut recv, client_private, cap, payload).await?;
    send.finish()?;
    Ok(response)
}

/// Auto P2P tunnel (M11.4b-iv): discover the Agent's advertised direct endpoint
/// from the Edge (`'P'`), then try the direct path, falling back to the Edge
/// relay if none is advertised or the direct attempt fails. Returns
/// `(used_direct, response)`.
pub async fn client_tunnel_auto(
    edge_conn: &Connection,
    token: &RoutingToken,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
    timeout: Duration,
) -> Result<(bool, Vec<u8>), BoxError> {
    // #283: query_direct_endpoint's read_to_end had no deadline of its own -- a
    // stalled/malicious Edge that accepts the 'P' query but never answers could
    // hang here forever, before the direct attempt (which DOES already respect
    // `timeout`) even starts. A bounded query that fails/times out is treated
    // the same as "no direct endpoint advertised" (falls through to relay),
    // matching the existing `.ok().flatten()` fail-soft contract.
    let direct = tokio::time::timeout(timeout, query_direct_endpoint(edge_conn, token))
        .await
        .ok()
        .and_then(|r| r.ok())
        .flatten();
    client_tunnel_p2p_or_relay(edge_conn, token, cap, client_private, payload, direct, timeout).await
}

/// #374: how much of a real head start the direct P2P attempt gets over the
/// relay fallback once both are raced concurrently -- within RFC 8305's own
/// suggested 50-100ms connection-attempt-delay range (the same convention
/// #367's ladder racing already cites). Short enough that a genuinely
/// reachable direct path (the common case: it's cheaper than the relay's own
/// PoW-gated rendezvous, so it almost always finishes first regardless) still
/// avoids paying for relay setup at all; long enough that a slow-but-live
/// direct path isn't starved by a relay that happens to be faster to reach.
const DIRECT_HEAD_START: Duration = Duration::from_millis(75);

/// Try the **direct** P2P path, racing it against the **Edge relay** fallback
/// (M11.4, #374). `direct` is the Agent's advertised `(candidate, cert)`; if
/// it is `None`, the tunnel goes straight through the Edge relay on
/// `edge_conn` with no racing overhead, unchanged from before #374. Returns
/// `(used_direct, response)`.
///
/// #374: previously ran fully serially -- the direct attempt got the WHOLE
/// `timeout` budget before the relay fallback was even started, so a
/// slow-but-not-dead direct candidate (e.g. behind NAT with high packet loss)
/// made every tunnel operation eat the full timeout even though the relay
/// path was reachable the whole time. Now both race concurrently
/// (`futures_util::future::select`, not the `tokio::select!` macro -- this
/// needs the *other* future handed back on one side resolving so a failed
/// direct attempt can keep waiting on a relay attempt already in flight,
/// rather than restarting it from scratch), with the direct attempt getting
/// [`DIRECT_HEAD_START`] before the relay attempt is even started, so a fast
/// direct connect still wins outright without ever touching `edge_conn`.
///
/// Real correctness properties preserved, not just perf: if the relay
/// resolves first (whether success or error), that IS the terminal outcome,
/// exactly as when relay was the last-resort fallback before -- there is no
/// "fall back again" past the relay. If direct resolves first with an error,
/// this keeps polling the SAME already-in-flight relay future (not a fresh
/// one) for its real result, matching the original "then try relay" order
/// while still getting the real concurrency win. Cancelling whichever side
/// loses a race is real, safe async cancellation: `client_direct_connect`
/// dials via `dial_edge` (Drop-safe per #366/#367's own investigation of the
/// identical call), and dropping `edge_conn`'s `SendStream`/`RecvStream`
/// mid-flight (a relay attempt that loses after already opening its stream)
/// only finishes/resets that one stream (quinn's own `Drop` impls) -- `
/// edge_conn` itself is untouched and stays valid, moot anyway since the one
/// real caller (`main.rs`'s p2p mode) always closes `edge_conn` right after
/// this call returns regardless of outcome.
pub async fn client_tunnel_p2p_or_relay(
    edge_conn: &Connection,
    token: &RoutingToken,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
    direct: Option<(SocketAddr, CertificateDer<'static>)>,
    timeout: Duration,
) -> Result<(bool, Vec<u8>), BoxError> {
    let Some((candidate, cert)) = direct else {
        // No advertised direct endpoint at all -- straight to the relay, no
        // racing overhead, byte-for-byte the same path as before #374.
        let resp = relay_attempt(edge_conn, token, cap, client_private, payload, timeout).await?;
        return Ok((false, resp));
    };

    let direct_fut = std::pin::pin!(async {
        let conn = client_direct_connect(candidate, cert, timeout).await?;
        let resp = client_tunnel_direct(&conn, cap, client_private, payload).await;
        conn.close(0u32.into(), b"done");
        resp
    });
    let relay_fut = std::pin::pin!(async {
        tokio::time::sleep(DIRECT_HEAD_START).await;
        relay_attempt(edge_conn, token, cap, client_private, payload, timeout).await
    });

    match futures_util::future::select(direct_fut, relay_fut).await {
        futures_util::future::Either::Left((Ok(resp), _relay_dropped)) => Ok((true, resp)),
        futures_util::future::Either::Left((Err(_), relay_fut)) => {
            // Direct failed -- fall back to relay, same as before #374. The
            // relay attempt may already be in flight (its own head start may
            // have already elapsed); keep polling THIS future, don't restart.
            let resp = relay_fut.await?;
            Ok((false, resp))
        }
        futures_util::future::Either::Right((relay_result, _direct_dropped)) => {
            // Relay is the terminal fallback -- its result (success or error)
            // is the real outcome either way, matching the original
            // "direct, then relay, nothing past that" order.
            Ok((false, relay_result?))
        }
    }
}

/// PoW-gated rendezvous + Noise tunnel through the Edge relay -- the shared
/// core of [`client_tunnel_p2p_or_relay`]'s relay path, factored out so the
/// `direct: None` fast path and the raced relay attempt both go through the
/// identical real call. #283: bounded by `timeout` (a stalled/malicious Edge
/// that accepts the connection but never sends the challenge, or stalls the
/// Noise handshake, must not hang forever) via the existing `_timed` wrapper.
async fn relay_attempt(
    edge_conn: &Connection,
    token: &RoutingToken,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, BoxError> {
    client_tunnel_noise_timed(edge_conn, token, cap, client_private, payload, timeout).await
}

/// Ask the Edge for the Agent's advertised direct endpoint for `token`
/// (M11.4b-ii): send a `'P'` query and parse the reply `[0]` (none) or
/// `[1] addr_len(1) addr cert_len(2 BE) cert` into `(addr, cert)`. Used to
/// attempt the direct P2P path before falling back to the Edge relay.
pub async fn query_direct_endpoint(
    conn: &Connection,
    token: &RoutingToken,
) -> Result<Option<(SocketAddr, CertificateDer<'static>)>, BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"P").await?;
    send.write_all(&token.0).await?;
    send.finish()?;
    let resp = recv.read_to_end(4096).await?;
    if resp.is_empty() || resp[0] == 0 {
        return Ok(None);
    }
    let truncated = || -> BoxError { "truncated direct-endpoint reply".into() };
    if resp.len() < 2 {
        return Err(truncated());
    }
    let addr_end = 2 + resp[1] as usize;
    if resp.len() < addr_end + 2 {
        return Err(truncated());
    }
    let addr: SocketAddr = std::str::from_utf8(&resp[2..addr_end])?.parse()?;
    let clen = u16::from_be_bytes([resp[addr_end], resp[addr_end + 1]]) as usize;
    let cert_start = addr_end + 2;
    if resp.len() < cert_start + clen {
        return Err(truncated());
    }
    let cert = CertificateDer::from(resp[cert_start..cert_start + clen].to_vec());
    Ok(Some((addr, cert)))
}

/// UDP self-test (M10.4): bind a local app UDP socket, send `payload` as one
/// datagram through [`client_tunnel_udp`] to the Origin, and return the echoed
/// datagram. The tunnel runs concurrently and is torn down once the echo arrives.
pub async fn udp_selftest(
    conn: &Connection,
    token: &RoutingToken,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>, BoxError> {
    // A local "app" socket mutually connected to the tunnel's local socket.
    let app = UdpSocket::bind("127.0.0.1:0").await?;
    let app_addr = app.local_addr()?;
    let local = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = local.local_addr()?;
    app.connect(local_addr).await?;
    local.connect(app_addr).await?;

    let mut got = vec![0u8; 65535];
    tokio::select! {
        // #419: same DEFAULT_STREAM_SETUP_DEADLINE every other setup-bounded
        // client entry point uses.
        r = client_tunnel_udp(conn, token, cap, client_private, local, DEFAULT_STREAM_SETUP_DEADLINE) => {
            r?;
            Err("udp tunnel exited before the echo arrived".into())
        }
        res = async {
            app.send(payload).await?;
            let n = app.recv(&mut got).await?;
            Ok::<usize, std::io::Error>(n)
        } => {
            let n = res?;
            Ok(got[..n].to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_common::noise::generate_static_keypair;
    use ct_common::OriginIdentity;
    use ct_edge::transport::build_server_endpoint_with_cert;
    use std::time::Instant;

    /// #202 (frozen): the CPU-bound PoW solve must NOT run inline on the async worker.
    /// On a single-threaded (`current_thread`) runtime there is exactly ONE async worker;
    /// an inline `solve` would monopolize it for the whole solve, so a concurrently-spawned
    /// task could not run until the solve finished. `build_request_blocking` offloads the
    /// solve to the blocking pool, so awaiting it yields the async worker and the concurrent
    /// task makes progress WHILE the solve is in flight. The difficulty is chosen non-trivial
    /// so the blocking solve is still running when we await (guaranteeing the yield hands the
    /// worker to the ticker) yet stays fast (tens of ms). This test FAILS against an inline
    /// `build_request` (the ticker never gets scheduled before the assert) and PASSES with the
    /// offload — it pins the fix, not just the current behaviour.
    #[tokio::test(flavor = "current_thread")]
    async fn build_request_blocking_offloads_the_solve_so_a_concurrent_task_progresses() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let progressed = Arc::new(AtomicBool::new(false));
        let p = progressed.clone();
        // A concurrent async task that can only run if the single async worker is free.
        let ticker = tokio::spawn(async move {
            for _ in 0..10_000 {
                p.store(true, Ordering::SeqCst);
                tokio::task::yield_now().await;
            }
        });

        let token = RoutingToken([5u8; 32]);
        let challenge = Challenge { nonce: [0x11; 16], difficulty: 20 };
        let req = build_request_blocking(&challenge, &token).await.expect("difficulty 20 is well under the client's cap");

        assert_eq!(req.len(), 40, "solution(8) | token(32)");
        let solution = u64::from_le_bytes(req[..8].try_into().unwrap());
        assert!(
            ct_common::pow::verify(&challenge, &token, solution),
            "the offloaded solve still produces a valid PoW solution"
        );
        assert_eq!(&req[8..], &token.0, "the token is appended after the solution");
        assert!(
            progressed.load(Ordering::SeqCst),
            "a concurrent async task ran while the PoW solve was offloaded to the blocking pool \
             (an inline solve would have starved the single async worker)"
        );
        ticker.abort();
    }

    /// issue #2 regression: when the edge accepts the QUIC connection but never
    /// relays (no agent registered for the token), the tunnel op must return a
    /// timeout error promptly instead of hanging indefinitely.
    #[tokio::test]
    async fn tunnel_noise_timed_errors_when_edge_never_relays() {
        let token = RoutingToken([7u8; 32]);
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();

        // A "silent edge": accept the client's connection, then do nothing (no
        // rendezvous, no relay) — the client would block reading the challenge.
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let edge = tokio::spawn(async move {
            let _conn = server.accept().await.unwrap().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: addr.to_string(),
        };
        let conn = dial_edge(addr, cert).await.expect("client dial");

        let start = Instant::now();
        let r = client_tunnel_noise_timed(
            &conn,
            &token,
            &cap,
            &client_kp.private,
            b"x",
            Duration::from_millis(300),
        )
        .await;
        let elapsed = start.elapsed();

        assert!(r.is_err(), "must error, not hang, when the edge never relays");
        assert!(
            r.unwrap_err().to_string().contains("timed out"),
            "error should name the timeout"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "must return near the deadline, took {elapsed:?}"
        );
        edge.abort();
    }

    /// issue #123 regression: the live local-forward path (`client_forward` →
    /// `client_tunnel_stream`) must bound its setup like the one-shot timed
    /// tunnels. Against a stalled edge that accepts the QUIC connection but never
    /// sends the rendezvous challenge, the streaming setup returns a timeout error
    /// promptly instead of hanging forever and leaking the blocked task's socket.
    #[tokio::test]
    async fn client_forward_setup_times_out_against_a_stalled_edge() {
        let token = RoutingToken([9u8; 32]);
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();

        // A stalled edge: accept the client's connection, then go silent — never
        // send the challenge, never relay. The client would block on read_exact.
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let edge = tokio::spawn(async move {
            let _conn = server.accept().await.unwrap().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: addr.to_string(),
        };
        let conn = dial_edge(addr, cert).await.expect("client dial");

        // The forwarded local socket, stubbed by an in-memory duplex.
        let (app, _peer) = tokio::io::duplex(4096);

        let start = Instant::now();
        let r = client_tunnel_stream(
            &conn,
            &token,
            &cap,
            &client_kp.private,
            app,
            Duration::from_millis(300),
        )
        .await;
        let elapsed = start.elapsed();

        assert!(r.is_err(), "must error, not hang, when the edge never relays");
        assert!(
            r.unwrap_err().to_string().contains("timed out"),
            "error should name the timeout"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "must return near the setup deadline, took {elapsed:?}"
        );
        edge.abort();
    }

    /// #419: `client_tunnel_udp` was the one client entry point the existing
    /// timeout sweep missed — against a stalled edge that accepts the QUIC
    /// connection but never sends the rendezvous challenge, setup must return a
    /// timeout error promptly instead of hanging forever.
    #[tokio::test]
    async fn client_tunnel_udp_setup_times_out_against_a_stalled_edge_419() {
        let token = RoutingToken([9u8; 32]);
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();

        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let edge = tokio::spawn(async move {
            let _conn = server.accept().await.unwrap().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: addr.to_string(),
        };
        let conn = dial_edge(addr, cert).await.expect("client dial");
        let local = UdpSocket::bind("127.0.0.1:0").await.expect("bind");

        let start = Instant::now();
        let r = client_tunnel_udp(&conn, &token, &cap, &client_kp.private, local, Duration::from_millis(300)).await;
        let elapsed = start.elapsed();

        assert!(r.is_err(), "must error, not hang, when the edge never relays");
        assert!(
            r.unwrap_err().to_string().contains("timed out"),
            "error should name the timeout"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "must return near the setup deadline, took {elapsed:?}"
        );
        edge.abort();
    }

    /// #366: `client_forward`'s shared-connection helper must actually reuse
    /// the cached QUIC connection across calls, not silently redial every
    /// time. A real fake edge counts every genuine QUIC connection it accepts
    /// (each accepted connection is held open in its own spawned task so the
    /// edge's own accept loop is free to notice a second dial immediately, if
    /// one wrongly happened).
    #[tokio::test]
    async fn client_forward_conn_reuses_the_cached_connection_across_calls_366() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let accept_count = Arc::new(AtomicUsize::new(0));
        let ac = accept_count.clone();
        let edge = tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                let ac = ac.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        ac.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        drop(conn);
                    }
                });
            }
        });

        let shared: tokio::sync::Mutex<Option<Connection>> = tokio::sync::Mutex::new(None);
        let conn1 = client_forward_conn(&shared, addr, cert.clone()).await.expect("first dial");
        let conn2 = client_forward_conn(&shared, addr, cert.clone()).await.expect("second call");
        let conn3 = client_forward_conn(&shared, addr, cert).await.expect("third call");

        assert_eq!(conn1.stable_id(), conn2.stable_id(), "second call reused the cached connection");
        assert_eq!(conn1.stable_id(), conn3.stable_id(), "third call reused the cached connection too");
        // Give the edge's spawned accept-handler tasks a moment to actually
        // register the connection before checking the counter.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            accept_count.load(Ordering::SeqCst),
            1,
            "the edge saw exactly ONE real QUIC connection across all three calls, not three"
        );
        edge.abort();
    }

    /// #366: when the cached connection is actually closed, the next call must
    /// notice (via `close_reason()`, not an inferred IO error) and redial a
    /// genuinely new one -- rather than keep handing out a dead connection
    /// forever, which would silently black-hole every subsequent local
    /// connection accepted after the shared connection died.
    #[tokio::test]
    async fn client_forward_conn_redials_after_the_cached_connection_closes_366() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let accept_count = Arc::new(AtomicUsize::new(0));
        let ac = accept_count.clone();
        let edge = tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                let ac = ac.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        ac.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        drop(conn);
                    }
                });
            }
        });

        let shared: tokio::sync::Mutex<Option<Connection>> = tokio::sync::Mutex::new(None);
        let conn1 = client_forward_conn(&shared, addr, cert.clone()).await.expect("first dial");
        assert!(conn1.close_reason().is_none(), "freshly dialed connection is not closed");

        // Simulate the shared connection dying (network blip / edge restart):
        // close it directly, exactly what `close_reason()` is meant to detect.
        conn1.close(0u32.into(), b"simulated death");
        assert!(conn1.close_reason().is_some(), "close() takes effect immediately per quinn's own docs");

        let conn2 = client_forward_conn(&shared, addr, cert).await.expect("redial after death");
        assert_ne!(
            conn1.stable_id(),
            conn2.stable_id(),
            "the next call detected the dead connection and dialed a genuinely new one"
        );
        assert!(conn2.close_reason().is_none(), "the redialed connection is alive");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            accept_count.load(Ordering::SeqCst),
            2,
            "the edge saw exactly two real QUIC connections: the original, then the redial"
        );
        edge.abort();
    }

    /// #283 regression: client_tunnel_p2p_or_relay's Edge-relay fallback ran
    /// with no deadline of its own -- only the (skipped here, `direct: None`)
    /// direct-connect attempt respected `timeout`. Against a stalled edge that
    /// accepts the connection but never sends the rendezvous challenge, the
    /// relay fallback must now return a timeout error promptly instead of
    /// hanging forever.
    #[tokio::test]
    async fn p2p_or_relay_fallback_times_out_against_a_stalled_edge() {
        let token = RoutingToken([11u8; 32]);
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();

        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let edge = tokio::spawn(async move {
            let _conn = server.accept().await.unwrap().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: addr.to_string(),
        };
        let conn = dial_edge(addr, cert).await.expect("client dial");

        let start = Instant::now();
        let r = client_tunnel_p2p_or_relay(
            &conn,
            &token,
            &cap,
            &client_kp.private,
            b"hello",
            None, // no direct candidate -> straight to the relay fallback
            Duration::from_millis(300),
        )
        .await;
        let elapsed = start.elapsed();

        assert!(r.is_err(), "must error, not hang, when the edge never relays");
        assert!(
            r.unwrap_err().to_string().contains("timed out"),
            "error should name the timeout"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "must return near the deadline, took {elapsed:?}"
        );
        edge.abort();
    }

    /// #283 regression: query_direct_endpoint's read had no deadline of its
    /// own -- client_tunnel_auto's whole `timeout` budget could be exhausted
    /// before the direct attempt even started, against an edge that accepts
    /// the 'P' query but never answers. A timed-out query must fall through to
    /// the relay path (same as "no direct endpoint advertised"), not hang.
    #[tokio::test]
    async fn client_tunnel_auto_falls_through_to_relay_when_the_direct_endpoint_query_stalls() {
        let token = RoutingToken([12u8; 32]);
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();

        // A stalled edge: accepts the 'P' query's stream but never answers it,
        // and never answers the relay fallback's rendezvous challenge either --
        // both stages must be bounded by client_tunnel_auto's overall `timeout`.
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let edge = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let _stream = conn.accept_bi().await; // accepts the 'P' query's stream, never answers
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: addr.to_string(),
        };
        let conn = dial_edge(addr, cert).await.expect("client dial");

        let start = Instant::now();
        let r = client_tunnel_auto(&conn, &token, &cap, &client_kp.private, b"hello", Duration::from_millis(300))
            .await;
        let elapsed = start.elapsed();

        assert!(r.is_err(), "must error, not hang, when both the direct query and the relay stall");
        assert!(
            elapsed < Duration::from_secs(3),
            "must return near the deadline, took {elapsed:?} (a stuck direct-endpoint query must not eat the whole budget silently)"
        );
        edge.abort();
    }

    /// #284 regression: `dial_edge` itself has no deadline (only `dial_rung`,
    /// forward-mode-only, wraps it). p2p/udp client modes dial the Edge
    /// directly -- against a blackholed/stalled Edge IP (here: a bound UDP
    /// port nothing ever `accept()`s on, so the QUIC handshake never
    /// completes) the bare call hangs until QUIC's own internal handshake
    /// timeout. `dial_edge_timed` must return promptly instead.
    #[tokio::test]
    async fn dial_edge_timed_returns_promptly_against_a_handshake_that_never_completes() {
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        // Deliberately never call server.accept() -- the port is bound (so the
        // client's handshake packets are received by the OS, not rejected
        // outright) but nothing ever processes them, exactly like a
        // stalled/blackholed Edge.

        let start = Instant::now();
        let r = dial_edge_timed(addr, cert, Duration::from_millis(300)).await;
        let elapsed = start.elapsed();

        assert!(r.is_err(), "must error, not hang, when the handshake never completes");
        assert!(
            r.unwrap_err().to_string().contains("timed out"),
            "error should name the timeout"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "must return near the deadline, took {elapsed:?}"
        );
    }

    /// #368: `dial_edge_with_endpoint` genuinely reuses the caller-supplied
    /// endpoint's own UDP socket across calls -- the real, observable proof is
    /// that the endpoint's own bound local port stays identical across two
    /// dials, unlike plain `dial_edge` (which binds a fresh ephemeral port
    /// every single call, confirmed as the second half of this same test).
    #[tokio::test]
    async fn dial_edge_with_endpoint_reuses_the_same_local_socket_across_calls_368() {
        let (server1, cert1) = build_server_endpoint_with_cert().expect("edge 1");
        let addr1 = server1.local_addr().expect("addr 1");
        let edge1 = tokio::spawn(async move {
            let _c = server1.accept().await.unwrap().await.unwrap();
        });
        let (server2, cert2) = build_server_endpoint_with_cert().expect("edge 2");
        let addr2 = server2.local_addr().expect("addr 2");
        let edge2 = tokio::spawn(async move {
            let _c = server2.accept().await.unwrap().await.unwrap();
        });

        let endpoint = new_client_endpoint().expect("client endpoint");
        let local_port_before = endpoint.local_addr().expect("local addr").port();

        // Two dials to two DIFFERENT real edges (different certs, proving
        // #368's own real production scenario -- client_direct_connect dials
        // an Agent's own agent_cert through this same path) on the SAME
        // supplied endpoint.
        let conn1 = dial_edge_with_endpoint(&endpoint, addr1, cert1).await.expect("dial 1");
        let conn2 = dial_edge_with_endpoint(&endpoint, addr2, cert2).await.expect("dial 2");
        assert_eq!(conn1.remote_address(), addr1, "conn1 reached edge 1");
        assert_eq!(conn2.remote_address(), addr2, "conn2 reached edge 2");
        assert_eq!(
            endpoint.local_addr().expect("local addr").port(),
            local_port_before,
            "the shared endpoint's own local UDP port never changed across two dials to two different, differently-certed edges"
        );
        edge1.abort();
        edge2.abort();

        // Contrast: a plain dial_edge call still works unchanged, binding its
        // OWN fresh ephemeral endpoint rather than reusing anything above.
        let (server3, cert3) = build_server_endpoint_with_cert().expect("edge 3");
        let addr3 = server3.local_addr().expect("addr 3");
        let edge3 = tokio::spawn(async move {
            let _c = server3.accept().await.unwrap().await.unwrap();
        });
        let conn3 = dial_edge(addr3, cert3).await.expect("plain dial_edge still works, unchanged");
        assert_eq!(conn3.remote_address(), addr3);
        edge3.abort();
    }

    // #21 WC4: cover client_tunnel_noise_tcp_timed (the TLS-over-TCP timed
    // variant, issue #2) over an in-memory duplex — both the deadline arm and
    // the surfaced-inner-error arm, without needing a real edge.
    #[tokio::test]
    async fn tcp_timed_surfaces_timeout_and_inner_error() {
        let token = RoutingToken([8u8; 32]);
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "127.0.0.1:4433".into(),
        };

        // (a) Idle peer: the inner op blocks -> the deadline (Err) arm fires.
        let (client_side, peer) = tokio::io::duplex(4096);
        let start = Instant::now();
        let r = client_tunnel_noise_tcp_timed(
            client_side,
            &token,
            &cap,
            &client_kp.private,
            b"hi",
            Duration::from_millis(200),
        )
        .await;
        assert!(r.is_err(), "idle peer -> error, not a hang");
        assert!(start.elapsed() < Duration::from_secs(2), "returned near the deadline");
        drop(peer);

        // (b) Closed peer: the inner op hits EOF and errors before the deadline,
        // so the Ok(inner) arm surfaces that error.
        let (client_side2, peer2) = tokio::io::duplex(4096);
        drop(peer2);
        let r2 = client_tunnel_noise_tcp_timed(
            client_side2,
            &token,
            &cap,
            &client_kp.private,
            b"hi",
            Duration::from_secs(5),
        )
        .await;
        assert!(r2.is_err(), "closed peer -> inner error surfaced");
    }

    #[tokio::test]
    async fn dial_rung_walks_the_ladder_to_the_live_quic_rung_and_caches_it() {
        // #31 FD3-b: the live per-rung dialer, driven by the FD3-a ladder, skips a
        // dead rung and lands on the reachable one — then caches it. A real edge
        // listens on an ephemeral QUIC (UDP) port; nothing listens on TCP there, so
        // the TLS-TCP rung is refused and the ladder walks on to the QUIC rung.
        use crate::ladder::{connect_via_ladder, LadderCache, Rung};

        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let edge = tokio::spawn(async move {
            let _conn = server.accept().await.unwrap().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        // Dead TLS-TCP rung first (no TCP listener on the QUIC port), then live QUIC.
        let ladder = vec![Rung::TlsTcp(addr.port()), Rung::Quic(addr.port())];
        let mut cache = LadderCache::new();
        let ip = addr.ip();
        let quic_endpoint = new_client_endpoint().expect("client endpoint");
        let got = connect_via_ladder(&mut cache, "test-net", &ladder, |rung| {
            let cert = cert.clone();
            let quic_endpoint = &quic_endpoint;
            async move { dial_rung(rung, ip, cert, quic_endpoint, Duration::from_millis(500)).await }
        })
        .await;

        let (rung, conn) = got.expect("a rung connected");
        assert_eq!(rung, Rung::Quic(addr.port()), "landed on the live QUIC rung");
        assert!(matches!(conn, EdgeConn::Quic(_)), "connection is the QUIC transport");
        assert_eq!(
            cache.remembered("test-net"),
            Some(Rung::Quic(addr.port())),
            "the working rung is cached for the network"
        );
        edge.abort();
    }
}
