//! Client → Edge transport (M5.3a).

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use crate::noise::client_noise_exchange;
use ct_common::noise::{client_handshake_for, frame, noise_pump, read_frame};
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
pub(crate) async fn build_request_blocking(challenge: &Challenge, token: &RoutingToken) -> Vec<u8> {
    let challenge = challenge.clone();
    let solve_token = token.clone();
    let solution = tokio::task::spawn_blocking(move || solve(&challenge, &solve_token))
        .await
        .expect("pow solve task panicked");
    assemble_request(solution, token)
}

/// Dial the Edge over QUIC, trusting `edge_cert`.
pub async fn dial_edge(
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
    // Bind all interfaces (not loopback) so the Client can reach a non-local Edge.
    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    endpoint.set_default_client_config(cfg);
    let conn = endpoint.connect(edge, "localhost")?.await?;
    Ok(conn)
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

/// After rendezvous, open a data stream to the Edge and exchange `input` for the
/// tunnel's response. In the daemon, `input`/output are the Client's local
/// socket; the Edge relays the stream to the Agent → Origin.
pub async fn client_exchange(conn: &Connection, input: &[u8]) -> Result<Vec<u8>, BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(input).await?;
    send.finish()?;
    let response = recv.read_to_end(64 * 1024).await?;
    Ok(response)
}

/// Load an Edge certificate (DER) the Edge published to a shared path.
pub fn load_cert(path: impl AsRef<Path>) -> std::io::Result<CertificateDer<'static>> {
    Ok(CertificateDer::from(std::fs::read(path)?))
}

/// Tunnel `input` to the Origin through the Edge in one stream, matching the
/// Edge's `serve_connection` `'C'` path: send role `'C'`, read the challenge,
/// present `solution | token`, send the data, and read the tunnel's response.
pub async fn client_tunnel(
    conn: &Connection,
    token: &RoutingToken,
    input: &[u8],
) -> Result<Vec<u8>, BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"C").await?;

    let mut chal = [0u8; 17];
    recv.read_exact(&mut chal).await?;
    let challenge = Challenge {
        nonce: chal[..16].try_into().unwrap(),
        difficulty: chal[16],
    };

    let req = build_request_blocking(&challenge, token).await; // solution(8) | token(32) = 40 bytes
    send.write_all(&req).await?;
    send.write_all(input).await?;
    send.finish()?;

    let response = recv.read_to_end(64 * 1024).await?;
    Ok(response)
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
    let req = build_request_blocking(&challenge, token).await;
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
pub async fn dial_rung(
    rung: crate::ladder::Rung,
    edge_ip: std::net::IpAddr,
    edge_cert: CertificateDer<'static>,
    timeout: Duration,
) -> Option<EdgeConn> {
    use crate::ladder::Rung;
    match rung {
        Rung::Quic(port) => {
            let addr = SocketAddr::new(edge_ip, port);
            match tokio::time::timeout(timeout, dial_edge(addr, edge_cert)).await {
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
    let req = build_request_blocking(&challenge, token).await;
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
        let req = build_request_blocking(&challenge, token).await;
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

/// Local-forward proxy (#22 HW2a): accept plain TCP connections on `listener`
/// and bridge each, over its own fresh tunnel, to the Origin via
/// [`client_tunnel_stream`]. This turns the payload-only client into a usable
/// local port: any TCP/TLS app (curl, a browser) can connect to `listener` and
/// ride the tunnel, with TLS terminating **at the Origin** (the Edge stays
/// provider-blind). One local connection = one edge connection = one tunnel, so
/// concurrent connections are independent. Runs until cancelled.
pub async fn client_forward(
    listener: tokio::net::TcpListener,
    edge_addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    token: RoutingToken,
    cap: Capability,
    client_private: [u8; 32],
    setup_deadline: Duration,
) -> Result<(), BoxError> {
    loop {
        let (sock, _peer) = listener.accept().await?;
        let edge_cert = edge_cert.clone();
        let token = token.clone();
        let cap = cap.clone();
        tokio::spawn(async move {
            match dial_edge(edge_addr, edge_cert).await {
                Ok(conn) => {
                    if let Err(e) =
                        client_tunnel_stream(&conn, &token, &cap, &client_private, sock, setup_deadline)
                            .await
                    {
                        eprintln!("ct-client: forwarded connection ended: {e}");
                    }
                    conn.close(0u32.into(), b"done");
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
) -> Result<(), BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"C").await?;

    let mut chal = [0u8; 17];
    recv.read_exact(&mut chal).await?;
    let challenge = Challenge {
        nonce: chal[..16].try_into().unwrap(),
        difficulty: chal[16],
    };
    let req = build_request_blocking(&challenge, token).await;
    send.write_all(&req).await?;

    let mut hs = client_handshake_for(client_private, cap)?;
    let mut buf = vec![0u8; 65535];
    let mut tmp = vec![0u8; 65535];
    let n = hs.write_message(&[], &mut buf)?;
    send.write_all(&frame(&buf[..n])).await?;
    let m2 = read_frame(&mut recv).await?;
    hs.read_message(&m2, &mut tmp)?;
    let transport = hs.into_transport_mode()?;

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
    let from_edge = async {
        let mut pt = vec![0u8; 65535];
        loop {
            let fr = match read_frame(&mut recv).await {
                Ok(f) => f,
                Err(_) => break,
            };
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

/// Try the **direct** P2P path first, else fall back to the **Edge relay**
/// (M11.4). `direct` is the Agent's advertised `(candidate, cert)`; if it is
/// `None`, or the direct connect/tunnel fails within `timeout`, the tunnel goes
/// through the Edge relay on `edge_conn`. Returns `(used_direct, response)`.
pub async fn client_tunnel_p2p_or_relay(
    edge_conn: &Connection,
    token: &RoutingToken,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
    direct: Option<(SocketAddr, CertificateDer<'static>)>,
    timeout: Duration,
) -> Result<(bool, Vec<u8>), BoxError> {
    if let Some((candidate, cert)) = direct {
        if let Ok(conn) = client_direct_connect(candidate, cert, timeout).await {
            if let Ok(resp) = client_tunnel_direct(&conn, cap, client_private, payload).await {
                conn.close(0u32.into(), b"done");
                return Ok((true, resp));
            }
        }
    }
    // Fallback: PoW-gated rendezvous + Noise tunnel through the Edge relay. #283:
    // this ran with no deadline of its own -- only the direct-connect attempt
    // above respected `timeout`. A stalled/malicious Edge that accepts the
    // connection but never sends the challenge (or stalls the Noise handshake)
    // hung this forever after a failed/absent direct attempt, undercutting the
    // caller's tunnel-timeout guarantee. Reuses `timeout` (same bound already
    // applied to the direct attempt) via the existing _timed wrapper
    // (client_tunnel_noise_tcp_timed's QUIC analog) rather than inventing a
    // second, separate relay deadline.
    let resp = client_tunnel_noise_timed(edge_conn, token, cap, client_private, payload, timeout).await?;
    Ok((false, resp))
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
        r = client_tunnel_udp(conn, token, cap, client_private, local) => {
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
        let req = build_request_blocking(&challenge, &token).await;

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
        let got = connect_via_ladder(&mut cache, "test-net", &ladder, |rung| {
            let cert = cert.clone();
            async move { dial_rung(rung, ip, cert, Duration::from_millis(500)).await }
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
