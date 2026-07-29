//! Agent → Edge transport (ADR-0004).
//!
//! The Agent dials outbound (no inbound ports). QUIC/UDP-443 is primary; when
//! outbound UDP is blocked it falls back to HTTP/2 over TCP/443.
//!
//! P1.2a implements the transport-selection decision and the QUIC dialer. The
//! actual TCP fallback transport (P1.2c) and reconnect-on-drop (P1.2b) follow.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use std::path::Path;

use ct_common::credential::SignedCredential;
use ct_common::RoutingToken;
use quinn::{Connection, Endpoint};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Generate a self-signed cert/key for the Agent's direct-path listener.
fn self_signed() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), BoxError> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    Ok((cert, key))
}

/// Build the Agent's direct-path QUIC **server** endpoint bound to `addr`
/// (M11.3b) — a listener for direct Client connections that bypass the Edge
/// relay. Returns the endpoint and its self-signed cert (advertised to Clients
/// so they can trust the direct path).
pub fn build_direct_listener_at(
    addr: SocketAddr,
) -> Result<(Endpoint, CertificateDer<'static>), BoxError> {
    install_crypto_provider();
    let (cert, key) = self_signed()?;
    let server_config = quinn::ServerConfig::with_single_cert(vec![cert.clone()], key)?;
    let endpoint = Endpoint::server(server_config, addr)?;
    Ok((endpoint, cert))
}

/// Build the direct-path listener on `0.0.0.0:0` (reachable on the container's
/// bridge IP, ephemeral port).
pub fn build_direct_listener() -> Result<(Endpoint, CertificateDer<'static>), BoxError> {
    build_direct_listener_at(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
}

/// A rustls verifier that accepts **any** server certificate but still checks the
/// handshake signature is internally consistent (the peer holds the key for the cert
/// it presented). This is intentional for the Agent-Fabric A2A channel dialer
/// (#72/#100): the QUIC/TLS layer is only transport, and the *real* mutual
/// authentication is the Noise_IK session keyed on the members' pinned static keys —
/// a transport-layer MITM cannot complete the Noise handshake without the peer's
/// private key. So the initiator needs no pre-shared transport cert (only the peer's
/// Noise key), which is what lets the A2A one-liner stay self-contained.
#[derive(Debug)]
struct AcceptAnyServerCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Build the Agent-Fabric A2A channel **dialer** (#72/#100): a QUIC client endpoint
/// that trusts any responder transport cert (see [`AcceptAnyServerCert`]), so the
/// initiator can dial a paired peer without a pre-shared cert. Authentication is the
/// Noise_IK session run over the connection, not the QUIC cert.
pub fn build_channel_dialer() -> Result<Endpoint, BoxError> {
    // #114 #4: cache the runtime-independent rustls/QUIC client config so it is built
    // ONCE, not rebuilt (rustls builder + cert verifier + QUIC crypto) on every channel
    // dial (broker, relay, and each direct-peer / ladder rung). The UDP socket is still
    // bound per call: a quinn `Endpoint`'s driver is tied to its creating tokio runtime,
    // so it cannot be safely memoized process-wide (that would break across runtimes);
    // reusing one `Endpoint` per join flow is a separate, localized follow.
    static CLIENT_CONFIG: OnceLock<quinn::ClientConfig> = OnceLock::new();
    let cfg = match CLIENT_CONFIG.get() {
        Some(c) => c.clone(),
        None => {
            install_crypto_provider();
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let crypto = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)))
                .with_no_client_auth();
            let mut cfg = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
            ));
            // #139: bound a dead-but-connected direct link at the transport level. Without a
            // max_idle_timeout a QUIC connection that handshakes then goes silent (asymmetric NAT, a
            // middlebox dropping post-handshake packets) never dies, so an await on it — `open_bi`,
            // the Noise_IK handshake, the pump — can hang forever with no relay fallback. A ~20s idle
            // timeout kills such a connection so those awaits error and the direct path can fall
            // back; a 5s keepalive (< the idle timeout) holds a *live* but idle data session open so
            // the timeout only ever fires on a genuinely dead path.
            let mut transport = quinn::TransportConfig::default();
            transport.max_idle_timeout(Some(
                quinn::IdleTimeout::try_from(std::time::Duration::from_secs(20)).expect("20s < quinn max idle"),
            ));
            transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
            cfg.transport_config(Arc::new(transport));
            // A concurrent racer may win the set(); either config is equivalent.
            let _ = CLIENT_CONFIG.set(cfg.clone());
            cfg
        }
    };
    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    endpoint.set_default_client_config(cfg);
    Ok(endpoint)
}

/// Advertise the Agent's direct-path listener to the Edge (M11.4b-ii): send a
/// `'D'` message — `token(32) | addr_len(1) | addr | cert_len(2 BE) | cert` — so
/// Clients querying with `'P'` can discover and connect to it directly.
pub async fn advertise_direct_listener(
    conn: &Connection,
    token: &RoutingToken,
    addr: SocketAddr,
    cert: &CertificateDer<'_>,
) -> Result<(), BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"D").await?;
    send.write_all(&token.0).await?;
    let a = addr.to_string();
    let ab = a.as_bytes();
    send.write_all(&[ab.len() as u8]).await?;
    send.write_all(ab).await?;
    let cb = cert.as_ref();
    send.write_all(&(cb.len() as u16).to_be_bytes()).await?;
    send.write_all(cb).await?;
    send.finish()?;
    let ack = recv.read_to_end(8).await?;
    if ack == b"OK" {
        Ok(())
    } else {
        Err("direct-listener advertisement rejected".into())
    }
}

/// Transport the Agent uses to reach the Edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Primary: QUIC over UDP/443.
    Quic,
    /// Fallback when outbound UDP is blocked: HTTP/2 over TCP/443.
    TcpFallback,
}

/// Select the transport given whether outbound UDP is reachable. QUIC is
/// preferred; TCP fallback is used only when UDP is blocked (ADR-0004).
pub fn select_transport(udp_reachable: bool) -> Transport {
    if udp_reachable {
        Transport::Quic
    } else {
        Transport::TcpFallback
    }
}

/// Probe whether outbound QUIC/UDP to `edge` works (M12.1): attempt a QUIC
/// handshake within `timeout`. Returns `true` if it connects — the input to
/// [`select_transport`] (QUIC vs the TCP fallback when UDP is blocked).
pub async fn probe_udp_reachable(
    edge: SocketAddr,
    edge_cert: CertificateDer<'static>,
    timeout: Duration,
) -> bool {
    matches!(
        tokio::time::timeout(timeout, dial_quic(edge, edge_cert)).await,
        Ok(Ok(_))
    )
}

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// QUIC keepalive on the Agent's control connection to the Edge (issue #2).
/// Without it, quinn's idle timeout tears down the registered connection, the
/// Edge evicts the tunnel, and a Client arriving seconds later gets "no relay".
/// 5s also keeps the cross-host NAT/UDP mapping warm; the idle timeout sits
/// comfortably above it.
const AGENT_KEEPALIVE: Duration = Duration::from_secs(5);
const AGENT_MAX_IDLE: Duration = Duration::from_secs(30);

fn client_endpoint(edge_cert: CertificateDer<'static>) -> Result<Endpoint, BoxError> {
    client_endpoint_with(edge_cert, Some(AGENT_KEEPALIVE), AGENT_MAX_IDLE)
}

/// Build the Agent's QUIC client endpoint trusting `edge_cert`, applying a
/// `keep_alive_interval` and `max_idle_timeout` so the registered control
/// connection to the Edge stays alive across idle gaps (issue #2).
fn client_endpoint_with(
    edge_cert: CertificateDer<'static>,
    keep_alive: Option<Duration>,
    max_idle: Duration,
) -> Result<Endpoint, BoxError> {
    install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(edge_cert)?;
    let crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(keep_alive);
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(max_idle).map_err(|_| "agent max_idle_timeout out of range")?,
    ));
    cfg.transport_config(Arc::new(transport));
    // Bind all interfaces (not loopback) so the Agent can reach a non-local Edge.
    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    endpoint.set_default_client_config(cfg);
    Ok(endpoint)
}

/// Dial the Edge over QUIC, returning the established connection. `edge_cert` is
/// the Edge's certificate the Agent trusts for this dial.
pub async fn dial_quic(
    edge_addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
) -> Result<Connection, BoxError> {
    let endpoint = client_endpoint(edge_cert)?;
    let conn = endpoint.connect(edge_addr, "localhost")?.await?;
    Ok(conn)
}

/// Dial the Edge over QUIC within `timeout`, mapping a timeout/failure to a
/// clear, actionable error instead of quinn's bare `TimedOut` (issue #3 /
/// P1.2c-1). Agent registration is currently QUIC/UDP-only, so a blocked UDP
/// path is the common cause; the error names it and points at the TCP-fallback
/// work still to come, rather than leaving the operator with an opaque timeout.
pub async fn dial_quic_or_blocked_error(
    edge_addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    timeout: Duration,
) -> Result<Connection, BoxError> {
    match tokio::time::timeout(timeout, dial_quic(edge_addr, edge_cert)).await {
        Ok(Ok(conn)) => Ok(conn),
        _ => Err(format!(
            "edge UDP/QUIC unreachable at {edge_addr} — agent registration requires UDP; \
             TCP-fallback registration is not yet implemented (issue #3 / P1.2c). \
             Open UDP/{} between hosts, or track the fallback work.",
            edge_addr.port()
        )
        .into()),
    }
}

/// Present `signed` to the Edge over a fresh bidirectional stream and await the
/// Edge's decision. Returns `Ok(())` only if the Edge accepted the credential.
pub async fn present_credential(
    conn: &Connection,
    signed: &SignedCredential,
) -> Result<(), BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&signed.encode()).await?;
    send.finish()?;
    let ack = recv.read_to_end(64).await?;
    if ack == b"OK" {
        Ok(())
    } else {
        Err("edge rejected credential".into())
    }
}

/// Register this Agent's tunnel for `token` with the Edge over `conn`: open a
/// control stream, send `role='A' | token(32)`, and await the Edge's `OK`.
pub async fn register_tunnel(conn: &Connection, token: &RoutingToken) -> Result<(), BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let mut msg = vec![b'A'];
    msg.extend_from_slice(&token.0);
    send.write_all(&msg).await?;
    send.finish()?;
    let ack = recv.read_to_end(8).await?;
    if ack == b"OK" {
        Ok(())
    } else {
        Err("edge rejected tunnel registration".into())
    }
}

/// Bind a public hostname to this Agent's routing token at the Edge (#23 BP3b):
/// open a control stream and send `role='H' | token(32) | host_len(2 BE) | host`,
/// then await the Edge's `OK`. Enables SNI-routed browser access to this tunnel.
pub async fn bind_hostname(
    conn: &Connection,
    token: &RoutingToken,
    host: &str,
) -> Result<(), BoxError> {
    let hb = host.as_bytes();
    if hb.is_empty() || hb.len() > 253 {
        return Err("hostname length out of range (1..=253)".into());
    }
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"H").await?;
    send.write_all(&token.0).await?;
    send.write_all(&(hb.len() as u16).to_be_bytes()).await?;
    send.write_all(hb).await?;
    send.finish()?;
    let ack = recv.read_to_end(8).await?;
    if ack == b"OK" {
        Ok(())
    } else {
        Err("edge rejected hostname binding".into())
    }
}

/// Register this Agent's tunnel for `token` over a generic byte stream — the
/// TLS-over-TCP fallback (issue #3 / P1.2c-2): write `role='A' | token(32)` and
/// await the Edge's `OK`. Unlike the QUIC path (which opens a fresh bi-stream
/// per client), a TCP agent uses one stream, so the *same* stream then carries
/// the relayed tunnel — a TCP-fallback agent serves one client at a time.
pub async fn register_tunnel_stream<S>(
    stream: &mut S,
    token: &RoutingToken,
) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut msg = vec![b'A'];
    msg.extend_from_slice(&token.0);
    stream.write_all(&msg).await?;
    stream.flush().await?;
    let mut ack = [0u8; 2];
    stream.read_exact(&mut ack).await?;
    if &ack == b"OK" {
        Ok(())
    } else {
        Err("edge rejected tunnel registration".into())
    }
}

/// Register **and** bind a public hostname in one message over a TLS-TCP stream
/// (issue #41 FB3): the Browser Plane's TCP fallback. Sends the `'B'` frame —
/// `'B' | token(32) | host_len(u16 BE) | host` — so a UDP-blocked browser-mode
/// agent both registers its token and claims its hostname atomically, mirroring
/// the QUIC path's separate `'A'` register + `'H'` bind. Awaits the 2-byte "OK".
pub async fn register_tunnel_stream_browser<S>(
    stream: &mut S,
    token: &RoutingToken,
    host: &str,
) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let host_bytes = host.as_bytes();
    let host_len: u16 = host_bytes
        .len()
        .try_into()
        .map_err(|_| "hostname too long for the browser-register frame")?;
    let mut msg = vec![b'B'];
    msg.extend_from_slice(&token.0);
    msg.extend_from_slice(&host_len.to_be_bytes());
    msg.extend_from_slice(host_bytes);
    stream.write_all(&msg).await?;
    stream.flush().await?;
    let mut ack = [0u8; 2];
    stream.read_exact(&mut ack).await?;
    if &ack == b"OK" {
        Ok(())
    } else {
        Err("edge rejected browser hostname registration".into())
    }
}

/// Connect to the Edge over **TLS-over-TCP** — the UDP-blocked fallback dialer
/// (issue #3 / P1.2c-4), trusting `edge_cert` (the CA root). Mirrors the Client's
/// `tcp_tls_connect`; the returned stream is then used with
/// [`register_tunnel_stream`] to register the Agent when QUIC/UDP is unavailable.
pub async fn tcp_tls_connect(
    addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, BoxError> {
    // #46 FB-b: advertise ALPN `ct-edge` so the unified :443 front door (#31 FD2)
    // classifies this as the data-plane relay (EdgeRelay) and routes it to
    // serve_tcp_connection — the register ('A'/'B') + revoke ('R') path.
    tcp_tls_connect_with_alpn(addr, edge_cert, b"ct-edge").await
}

/// Connect to the unified `:443` **front door** for the Agent-Fabric A2A channel
/// route (#106): TLS-over-TCP to `addr`, trusting `edge_cert`, advertising ALPN
/// `ct-edge-channel` so the front door (#31/#46 pattern) classifies this as the
/// channel broker/relay and dispatches it to the channel admit+pair path — the
/// fallback dialer for a restrictive network that blocks the direct channel ports.
/// The returned stream is then split and driven with
/// [`crate::channel::present_channel_join_on_stream`].
pub async fn tcp_tls_connect_channel(
    addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, BoxError> {
    tcp_tls_connect_with_alpn(addr, edge_cert, b"ct-edge-channel").await
}

/// TLS-over-TCP dialer to `addr` trusting `edge_cert`, advertising `alpn` in the
/// ClientHello (issue #3 / P1.2c-4 core, generalized for #106). The ALPN selects
/// which unified `:443` front-door route the connection is classified into:
/// `ct-edge` → the data-plane relay, `ct-edge-channel` → the A2A channel broker.
/// Harmless on the direct TLS listeners (they advertise no ALPN, so the offer is
/// ignored). The thin [`tcp_tls_connect`] / [`tcp_tls_connect_channel`] wrappers
/// pin the two protocol strings.
/// Enable TCP keepalive on `stream` (#229): a parked TLS-TCP fallback
/// registration is otherwise a plain, silent TCP connection with nothing to
/// refresh it over however long it sits waiting for a Client -- over a real,
/// geographically distant network, any NAT/firewall between the Agent and
/// the Edge can drop an idle mapping without either endpoint noticing, so a
/// Client later delivered onto that "parked" connection gets nothing back
/// (found live: reproduced on hugging's real UDP-blocked network, never on a
/// same-host hermetic/loopback test, exactly what an idle-NAT-drop
/// hypothesis predicts). 20s/20s is comfortably under common NAT idle
/// timeouts (typically 60s+) while staying cheap. Best-effort: unsupported
/// platforms or an already-broken socket just don't get the option, same as
/// today.
fn apply_tcp_keepalive(stream: &TcpStream) {
    let sock = socket2::SockRef::from(stream);
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(20))
        .with_interval(Duration::from_secs(20));
    let _ = sock.set_tcp_keepalive(&ka);
}

pub async fn tcp_tls_connect_with_alpn(
    addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    alpn: &[u8],
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, BoxError> {
    install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(edge_cert)?;
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![alpn.to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(addr).await?;
    apply_tcp_keepalive(&tcp);
    let server_name = rustls::pki_types::ServerName::try_from("localhost")?;
    Ok(connector.connect(server_name, tcp).await?)
}

/// Load an Edge certificate (DER) the Edge published to a shared path.
pub fn load_cert(path: impl AsRef<Path>) -> std::io::Result<CertificateDer<'static>> {
    Ok(CertificateDer::from(std::fs::read(path)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_quic_when_udp_reachable() {
        assert_eq!(select_transport(true), Transport::Quic);
    }

    #[tokio::test]
    async fn apply_tcp_keepalive_actually_sets_the_socket_option() {
        // #229: a parked TLS-TCP fallback connection is otherwise a plain,
        // silent TCP socket an idle NAT/firewall can drop unnoticed. Prove
        // apply_tcp_keepalive isn't a silent no-op -- read the option back.
        let bind = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = bind.local_addr().unwrap();
        let accept = tokio::spawn(async move { bind.accept().await.unwrap().0 });
        let client = TcpStream::connect(addr).await.unwrap();
        let _server = accept.await.unwrap();

        let sock = socket2::SockRef::from(&client);
        assert!(!sock.keepalive().unwrap(), "keepalive is off by default before applying it");
        apply_tcp_keepalive(&client);
        assert!(sock.keepalive().unwrap(), "apply_tcp_keepalive must actually enable SO_KEEPALIVE");
    }

    #[tokio::test]
    async fn build_channel_dialer_reuses_config_but_binds_its_own_socket() {
        // #114 #4 (frozen): the client config is now built once and reused across dials,
        // but each dialer still binds its OWN UDP socket (a quinn Endpoint's driver is
        // tied to its creating runtime, so it can't be shared process-wide). Both calls
        // must yield working, independently-bound client endpoints.
        let a = build_channel_dialer().expect("first dialer builds");
        let b = build_channel_dialer().expect("second dialer builds (config cache hit)");
        let la = a.local_addr().expect("a is bound");
        let lb = b.local_addr().expect("b is bound");
        assert_ne!(la, lb, "each dialer binds its own socket (endpoints are not shared)");
        assert!(la.port() != 0 && lb.port() != 0, "both endpoints are bound to a real port");
    }

    #[tokio::test]
    async fn direct_listener_accepts_a_connection() {
        // M11.3b: the Agent's direct-path listener accepts a Client that trusts
        // its advertised cert and connects directly (bypassing the Edge relay).
        let (listener, cert) =
            build_direct_listener_at((Ipv4Addr::LOCALHOST, 0).into()).expect("listener");
        let addr = listener.local_addr().expect("addr");

        let srv = tokio::spawn(async move {
            let conn = listener.accept().await.unwrap().await.unwrap();
            let (mut s, mut r) = conn.accept_bi().await.unwrap();
            let data = r.read_to_end(64).await.unwrap();
            s.write_all(&data).await.unwrap();
            s.finish().unwrap();
            conn.closed().await;
        });

        let client = ct_edge::transport::build_client_endpoint(cert).expect("client");
        let conn = client
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("direct conn");
        let (mut s, mut r) = conn.open_bi().await.unwrap();
        s.write_all(b"direct-hello").await.unwrap();
        s.finish().unwrap();
        let echoed = r.read_to_end(64).await.unwrap();
        assert_eq!(echoed, b"direct-hello", "direct listener accepts and echoes");
        conn.close(0u32.into(), b"done");
        let _ = srv.await;
    }

    #[test]
    fn falls_back_to_tcp_when_udp_blocked() {
        assert_eq!(select_transport(false), Transport::TcpFallback);
    }

    #[tokio::test]
    async fn probe_reachable_edge_selects_quic() {
        let (server, cert) =
            ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let accept = tokio::spawn(async move {
            if let Some(inc) = server.accept().await {
                let _ = inc.await;
            }
        });
        let reachable = probe_udp_reachable(addr, cert, Duration::from_secs(2)).await;
        assert!(reachable, "QUIC to a live edge is reachable");
        assert_eq!(select_transport(reachable), Transport::Quic);
        accept.abort();
    }

    #[tokio::test]
    async fn probe_dead_udp_selects_tcp_fallback() {
        // Nothing listening at this UDP address → probe times out.
        let (_ep, cert) =
            build_direct_listener_at((Ipv4Addr::LOCALHOST, 0).into()).expect("cert");
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        let reachable = probe_udp_reachable(dead_addr, cert, Duration::from_millis(400)).await;
        assert!(!reachable, "blocked UDP is not reachable");
        assert_eq!(select_transport(reachable), Transport::TcpFallback);
    }

    #[tokio::test]
    async fn agent_connects_and_registers_over_tls_tcp() {
        // issue #3 / P1.2c-4: the agent dials the real edge over TLS-TCP and
        // registers ('A') through the edge's TCP handler, which parks it.
        use ct_common::pow::Challenge;
        use ct_edge::pki::{build_dual_edge_from_ca, Ca};
        use ct_edge::serve::serve_tcp_connection;
        use ct_edge::state::EdgeState;
        use quinn::Connection;

        let ca = Ca::new("test-ca").expect("ca");
        let (_ep, tcp_listener, acceptor, ca_root) = build_dual_edge_from_ca(
            &ca,
            (Ipv4Addr::LOCALHOST, 0).into(),
            (Ipv4Addr::LOCALHOST, 0).into(),
            vec!["localhost".to_string()],
        )
        .await
        .expect("dual edge");
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let token = RoutingToken([0x77; 32]);
        let state = std::sync::Arc::new(EdgeState::<Connection>::new());
        let challenge = Challenge {
            nonce: [0u8; 16],
            difficulty: 0,
        };

        // Minimal edge TCP loop: accept one TLS connection, serve it.
        let state_e = state.clone();
        let edge = tokio::spawn(async move {
            let (tcp, _) = tcp_listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let _ = serve_tcp_connection(tls, &state_e, &challenge).await;
        });

        // Agent: connect over TLS-TCP (trusting the CA root) and register.
        let mut stream = tcp_tls_connect(tcp_addr, ca_root)
            .await
            .expect("agent TLS-TCP connect");
        register_tunnel_stream(&mut stream, &token)
            .await
            .expect("register over TLS-TCP");

        // The edge's 'A' handler parked this TCP agent.
        for _ in 0..100 {
            if state.has_tcp_agent(&token) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            state.has_tcp_agent(&token),
            "agent registered over TLS-TCP and is parked at the edge"
        );
        edge.abort();
    }

    #[tokio::test]
    async fn agent_registers_through_the_443_front_door_via_alpn() {
        // #46 FB-b: the agent's TLS-TCP connect advertises ALPN=ct-edge, so the
        // unified :443 front door (#31 FD2) classifies it as EdgeRelay and routes
        // it to serve_tcp_connection — the firewall-fallback register path. Same as
        // the direct-listener test above, but the edge runs the FRONT DOOR.
        use ct_common::pow::Challenge;
        use ct_edge::pki::{build_dual_edge_from_ca, Ca};
        use ct_edge::serve::serve_front_door;
        use ct_edge::state::EdgeState;
        use quinn::Connection;

        let ca = Ca::new("test-ca").expect("ca");
        let (_ep, tcp_listener, acceptor, ca_root) = build_dual_edge_from_ca(
            &ca,
            (Ipv4Addr::LOCALHOST, 0).into(),
            (Ipv4Addr::LOCALHOST, 0).into(),
            vec!["localhost".to_string()],
        )
        .await
        .expect("dual edge");
        let fd_addr = tcp_listener.local_addr().unwrap();
        let token = RoutingToken([0x46; 32]);
        let state = std::sync::Arc::new(EdgeState::<Connection>::new());
        let challenge = Challenge {
            nonce: [0u8; 16],
            difficulty: 0,
        };

        // Edge FRONT DOOR: classify by ALPN/SNI and dispatch (no portal wired).
        let state_e = state.clone();
        let edge = tokio::spawn(async move {
            let (tcp, _) = tcp_listener.accept().await.unwrap();
            let proxies: std::collections::HashMap<String, ct_edge::serve::ProxyTarget> =
                std::collections::HashMap::new();
            let _ = serve_front_door(tcp, &state_e, &acceptor, &proxies, None, &challenge, None, None, None).await;
        });

        // Agent: TLS-TCP connect (ALPN=ct-edge set in tcp_tls_connect) + register.
        let mut stream = tcp_tls_connect(fd_addr, ca_root)
            .await
            .expect("agent TLS-TCP connect via the front door");
        register_tunnel_stream(&mut stream, &token)
            .await
            .expect("register through the :443 front door");

        for _ in 0..100 {
            if state.has_tcp_agent(&token) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            state.has_tcp_agent(&token),
            "agent registered through the front door (ALPN=ct-edge -> EdgeRelay)"
        );
        edge.abort();
    }

    #[tokio::test]
    async fn register_tunnel_stream_sends_role_and_token_and_reads_ok() {
        // issue #3 / P1.2c-2: the TCP-fallback register primitive writes
        // 'A' | token(32) and accepts the edge's OK over a generic stream.
        let (mut agent_side, mut edge_side) = tokio::io::duplex(1024);
        let token = RoutingToken([0x42; 32]);

        // Mock edge: read role+token, verify, ack "OK".
        let t = token.clone();
        let edge = tokio::spawn(async move {
            let mut hdr = [0u8; 33];
            edge_side.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr[0], b'A', "role byte");
            assert_eq!(&hdr[1..], &t.0, "token echoed");
            edge_side.write_all(b"OK").await.unwrap();
            edge_side.flush().await.unwrap();
        });

        register_tunnel_stream(&mut agent_side, &token)
            .await
            .expect("register over a TLS-TCP-style stream");
        edge.await.unwrap();
    }

    #[tokio::test]
    async fn register_tunnel_stream_browser_sends_b_frame_token_and_host() {
        // issue #41 FB3: the browser-mode TCP fallback writes a single
        // 'B' | token(32) | host_len(u16 BE) | host frame and accepts the OK.
        let (mut agent_side, mut edge_side) = tokio::io::duplex(1024);
        let token = RoutingToken([0x37; 32]);
        let host = "help.bunsenbrenner.org";

        let t = token.clone();
        let edge = tokio::spawn(async move {
            let mut role = [0u8; 1];
            edge_side.read_exact(&mut role).await.unwrap();
            assert_eq!(role[0], b'B', "browser register role byte");
            let mut tok = [0u8; 32];
            edge_side.read_exact(&mut tok).await.unwrap();
            assert_eq!(&tok, &t.0, "token echoed");
            let mut len = [0u8; 2];
            edge_side.read_exact(&mut len).await.unwrap();
            let n = u16::from_be_bytes(len) as usize;
            let mut host_buf = vec![0u8; n];
            edge_side.read_exact(&mut host_buf).await.unwrap();
            assert_eq!(host_buf, b"help.bunsenbrenner.org", "hostname echoed");
            edge_side.write_all(b"OK").await.unwrap();
            edge_side.flush().await.unwrap();
        });

        register_tunnel_stream_browser(&mut agent_side, &token, host)
            .await
            .expect("browser-register over a TLS-TCP-style stream");
        edge.await.unwrap();
    }

    #[tokio::test]
    async fn register_tunnel_stream_errors_on_non_ok_ack() {
        let (mut agent_side, mut edge_side) = tokio::io::duplex(1024);
        let token = RoutingToken([0x01; 32]);
        let edge = tokio::spawn(async move {
            let mut hdr = [0u8; 33];
            edge_side.read_exact(&mut hdr).await.unwrap();
            edge_side.write_all(b"NO").await.unwrap(); // rejection
            edge_side.flush().await.unwrap();
        });
        let r = register_tunnel_stream(&mut agent_side, &token).await;
        assert!(r.is_err(), "a non-OK ack is a rejection");
        edge.await.unwrap();
    }

    #[tokio::test]
    async fn keepalive_holds_the_connection_across_an_idle_gap() {
        // issue #2: a server with a 1s idle timeout evicts an idle peer, but a
        // client with a 300ms keepalive holds the connection open past 2s of no
        // application traffic — so the edge retains the tunnel registration
        // instead of leaving a later client with "no relay".
        install_crypto_provider();
        let (cert, key) = self_signed().unwrap();
        let mut sc = quinn::ServerConfig::with_single_cert(vec![cert.clone()], key).unwrap();
        let mut st = quinn::TransportConfig::default();
        st.max_idle_timeout(Some(quinn::IdleTimeout::try_from(Duration::from_secs(1)).unwrap()));
        // Deliberately NO keepalive on the server side.
        sc.transport_config(std::sync::Arc::new(st));
        let server = Endpoint::server(sc, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let addr = server.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            if let Ok((mut s, mut r)) = conn.accept_bi().await {
                let mut buf = [0u8; 4];
                if r.read_exact(&mut buf).await.is_ok() {
                    let _ = s.write_all(&buf).await;
                    let _ = s.finish();
                }
            }
            conn.closed().await;
        });

        // Client with a keepalive shorter than the server's idle timeout.
        let ep =
            client_endpoint_with(cert, Some(Duration::from_millis(300)), Duration::from_secs(30))
                .unwrap();
        let conn = ep.connect(addr, "localhost").unwrap().await.unwrap();

        // Idle longer than the server's 1s timeout — keepalive must hold it open.
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Bounded round-trip: with keepalive it completes fast; without it the
        // connection is dead and this fails within the timeout (never hangs).
        let got = tokio::time::timeout(Duration::from_secs(4), async {
            let (mut s, mut r) = conn.open_bi().await.expect("connection alive after idle gap");
            s.write_all(b"ping").await.unwrap();
            s.finish().unwrap();
            let mut got = [0u8; 4];
            r.read_exact(&mut got).await.unwrap();
            got
        })
        .await
        .expect("round-trip within 4s — keepalive should hold the connection open");
        assert_eq!(&got, b"ping", "keepalive kept the connection past the idle timeout");
        srv.abort();
    }

    #[tokio::test]
    async fn dial_quic_or_blocked_error_reports_udp_blocked() {
        // Nothing listening at this UDP address → the QUIC dial cannot complete;
        // the agent must surface a clear, actionable error (issue #3 / P1.2c-1)
        // instead of a bare TimedOut.
        let (_ep, cert) =
            build_direct_listener_at((Ipv4Addr::LOCALHOST, 0).into()).expect("cert");
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        let start = std::time::Instant::now();
        let r = dial_quic_or_blocked_error(dead_addr, cert, Duration::from_millis(400)).await;
        assert!(r.is_err(), "blocked UDP must error, not hang");
        let msg = r.unwrap_err().to_string();
        assert!(
            msg.contains("UDP") && msg.contains("issue #3"),
            "error must be clear + actionable, got: {msg}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "must fail fast, not after a long timeout"
        );
    }

    #[tokio::test]
    async fn agent_dials_edge_over_quic() {
        let (server, cert) =
            ct_edge::transport::build_server_endpoint_with_cert().expect("edge server");
        let addr = server.local_addr().expect("edge addr");

        let server_task = tokio::spawn(async move {
            ct_edge::transport::accept_and_echo_one(&server)
                .await
                .expect("edge echo");
        });

        let conn = dial_quic(addr, cert).await.expect("agent dial");
        let (mut send, mut recv) = conn.open_bi().await.expect("open bi");
        send.write_all(b"agent-hello").await.expect("write");
        send.finish().expect("finish");
        let echoed = recv.read_to_end(64 * 1024).await.expect("read echo");
        assert_eq!(&echoed, b"agent-hello", "agent must round-trip via the Edge");

        conn.close(0u32.into(), b"done");
        server_task.await.expect("edge task join");
    }

    // --- P1.4d-ii: credential handshake over QUIC ---

    use crate::identity::AgentIdentity;
    use ct_common::{AgentId, TenantId};
    use ct_control_plane::credential::CredentialIssuer;
    use ct_control_plane::enrollment::Enrollment;
    use ct_control_plane::issuance::mint_for_enrolled;

    fn enrolled_credential(
        expires_at: u64,
    ) -> (ct_common::credential::SignedCredential, [u8; 32]) {
        let issuer = CredentialIssuer::generate();
        let mut enrollment = Enrollment::new();
        let tenant = TenantId("tenant-1".into());
        let token = enrollment.issue_join_token(tenant);
        let identity = AgentIdentity::generate();
        let agent_id = AgentId("agent-1".into());
        enrollment
            .redeem(&token, agent_id.clone(), identity.public_key_bytes())
            .unwrap();
        let signed = mint_for_enrolled(&issuer, &enrollment, &agent_id, expires_at).unwrap();
        (signed, issuer.public_key_bytes())
    }

    #[tokio::test]
    async fn agent_authenticates_to_edge_with_valid_credential() {
        let (signed, issuer_pk) = enrolled_credential(1_000);
        let (server, cert) =
            ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");

        let server_task = tokio::spawn(async move {
            let conn = ct_edge::auth::accept_and_authenticate(&server, &issuer_pk, 500)
                .await
                .map_err(|e| e.to_string())?;
            conn.closed().await;
            Ok::<(), String>(())
        });

        let conn = dial_quic(addr, cert).await.expect("dial");
        present_credential(&conn, &signed)
            .await
            .expect("edge accepts valid credential");
        conn.close(0u32.into(), b"done");
        server_task.await.expect("join").expect("edge auth ok");
    }

    #[tokio::test]
    async fn edge_rejects_expired_credential() {
        let (signed, issuer_pk) = enrolled_credential(100); // expires at 100
        let (server, cert) =
            ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");

        let server_task = tokio::spawn(async move {
            // now = 500 >= 100 → expired → Err
            ct_edge::auth::accept_and_authenticate(&server, &issuer_pk, 500)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        });

        let conn = dial_quic(addr, cert).await.expect("dial");
        let result = present_credential(&conn, &signed).await;
        assert!(result.is_err(), "expired credential must be rejected");
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn agent_registers_tunnel_with_edge() {
        use ct_edge::state::EdgeState;
        use quinn::Connection;
        use std::sync::Arc;

        let token = RoutingToken([9u8; 32]);
        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");

        let state_e = state.clone();
        let edge = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            ct_edge::serve::register_agent(&conn, &state_e)
                .await
                .map_err(|e| e.to_string())?;
            conn.closed().await;
            Ok::<(), String>(())
        });

        let conn = dial_quic(addr, cert).await.expect("dial");
        register_tunnel(&conn, &token)
            .await
            .expect("agent registers tunnel");
        assert!(state.is_known(&token), "edge now routes the agent's token");
        conn.close(0u32.into(), b"done");
        let _ = edge.await;
    }

    #[tokio::test]
    async fn load_cert_reads_written_der() {
        let (_endpoint, cert) =
            ct_edge::transport::build_server_endpoint_with_cert().expect("cert");
        let path = std::env::temp_dir().join(format!("ct-agent-cert-{}.der", std::process::id()));
        std::fs::write(&path, cert.as_ref()).unwrap();
        let loaded = load_cert(&path).expect("load");
        assert_eq!(loaded, cert, "agent loads the edge cert from the shared file");
        let _ = std::fs::remove_file(&path);
    }

    // #20 TC3: a mock edge that reads one bi-stream request and replies with a
    // fixed ack — lets us drive the reject branches the real edge never takes.
    async fn mock_edge_replying(
        ack: &'static [u8],
    ) -> (SocketAddr, CertificateDer<'static>, tokio::task::JoinHandle<()>) {
        let (server, cert) = ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let h = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let _ = recv.read_to_end(8192).await.unwrap();
            send.write_all(ack).await.unwrap();
            send.finish().unwrap();
            conn.closed().await;
        });
        (addr, cert, h)
    }

    #[tokio::test]
    async fn register_tunnel_surfaces_an_edge_rejection() {
        let (addr, cert, edge) = mock_edge_replying(b"NO").await;
        let conn = dial_quic(addr, cert).await.expect("dial");
        let err = register_tunnel(&conn, &RoutingToken([3u8; 32]))
            .await
            .err()
            .expect("non-OK ack must error")
            .to_string();
        assert!(err.contains("rejected tunnel registration"), "{err}");
        conn.close(0u32.into(), b"done");
        let _ = edge.await;
    }

    #[tokio::test]
    async fn advertise_direct_listener_roundtrips_and_surfaces_rejection() {
        let (_ep, dcert) = build_direct_listener().expect("direct listener");
        let dummy: SocketAddr = "10.5.0.4:40001".parse().unwrap();
        let token = RoutingToken([4u8; 32]);

        for (ack, expect_ok) in [(&b"OK"[..], true), (&b"NO"[..], false)] {
            let (addr, cert, edge) = mock_edge_replying(ack).await;
            let conn = dial_quic(addr, cert).await.expect("dial");
            let res = advertise_direct_listener(&conn, &token, dummy, &dcert).await;
            assert_eq!(res.is_ok(), expect_ok, "ack={ack:?}");
            if !expect_ok {
                assert!(res
                    .err()
                    .expect("rejected")
                    .to_string()
                    .contains("advertisement rejected"));
            }
            conn.close(0u32.into(), b"done");
            let _ = edge.await;
        }
    }

    // #23 BP3b: bind_hostname writes 'H' | token | len | host and surfaces the ack.
    #[tokio::test]
    async fn bind_hostname_sends_h_and_surfaces_the_ack() {
        let token = RoutingToken([7u8; 32]);

        let (addr, cert, edge) = mock_edge_replying(b"OK").await;
        let conn = dial_quic(addr, cert).await.expect("dial");
        bind_hostname(&conn, &token, "shop.example.test").await.expect("bind ok");
        // An empty hostname is rejected locally, before any network use.
        assert!(bind_hostname(&conn, &token, "").await.is_err(), "empty hostname rejected");
        conn.close(0u32.into(), b"done");
        let _ = edge.await;

        let (addr2, cert2, edge2) = mock_edge_replying(b"NO").await;
        let conn2 = dial_quic(addr2, cert2).await.expect("dial");
        let err = bind_hostname(&conn2, &token, "x.test")
            .await
            .err()
            .expect("non-OK ack must error");
        assert!(err.to_string().contains("rejected hostname"), "{err}");
        conn2.close(0u32.into(), b"done");
        let _ = edge2.await;
    }
}
