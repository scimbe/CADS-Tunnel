//! Edge QUIC transport (ADR-0004).
//!
//! P1.1a: construct a server [`quinn::Endpoint`] with a self-signed certificate.
//! P1.1b: connect a client and echo one bidirectional stream. The self-signed
//! cert is test/dev scaffolding; production certs are Agent-held (ADR-0003) and,
//! for the Mesh Plane, replaced by Noise (ADR-0013).

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use quinn::Endpoint;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Errors constructing or driving an Edge endpoint.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub(crate) fn install_crypto_provider() {
    // Idempotent: a second call returns Err, which we ignore.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Enable TCP keepalive on `stream` (#229) -- see the matching helper in
/// `ct-agent`'s `transport.rs` for the full rationale: a parked TLS-TCP
/// fallback registration is a plain, silent TCP connection with nothing to
/// refresh it, so an idle NAT/firewall mapping between the Agent and this
/// Edge can be dropped without either side noticing until a Client is
/// delivered onto the now-dead connection. Applied here on the Edge's own
/// accept side too, for the same reason and for symmetry with any
/// intermediate stateful device on this leg of the path. Best-effort.
pub(crate) fn apply_tcp_keepalive(stream: &TcpStream) {
    let sock = socket2::SockRef::from(stream);
    let ka = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(20))
        .with_interval(std::time::Duration::from_secs(20));
    let _ = sock.set_tcp_keepalive(&ka);
}

fn self_signed() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), BoxError> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    Ok((cert, key))
}

/// Build a QUIC server [`Endpoint`] bound to `127.0.0.1:0` (ephemeral port)
/// with a fresh self-signed cert, returning the cert so a client can trust it.
///
/// Must be called within a Tokio runtime (quinn spawns an I/O driver).
pub fn build_server_endpoint_with_cert() -> Result<(Endpoint, CertificateDer<'static>), BoxError> {
    build_server_endpoint_at(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
}

/// Build a QUIC server [`Endpoint`] bound to `addr` with a fresh self-signed
/// cert, returning the cert. Used by the Edge daemon to bind its configured
/// listen address.
pub fn build_server_endpoint_at(
    addr: SocketAddr,
) -> Result<(Endpoint, CertificateDer<'static>), BoxError> {
    install_crypto_provider();
    let (cert, key) = self_signed()?;
    let server_config = quinn::ServerConfig::with_single_cert(vec![cert.clone()], key)?;
    let endpoint = Endpoint::server(server_config, addr)?;
    Ok((endpoint, cert))
}

/// Write the Edge's certificate (DER) to `path` so Agents/Clients can trust it
/// (a shared volume in the testbed).
pub fn save_cert(path: impl AsRef<Path>, cert: &CertificateDer<'_>) -> std::io::Result<()> {
    std::fs::write(path, cert.as_ref())
}

/// Load an Edge certificate (DER) previously written by [`save_cert`].
pub fn load_cert(path: impl AsRef<Path>) -> std::io::Result<CertificateDer<'static>> {
    Ok(CertificateDer::from(std::fs::read(path)?))
}

/// Build a TLS acceptor for the Portal from an operator-supplied PEM cert chain +
/// private key (#31 FD4-a). The Edge uses this to TERMINATE TLS for the Portal
/// host on the unified `:443` front door and reverse-proxy plaintext HTTP to the
/// control plane — so a browser gets a real landing page over HTTPS, rather than
/// the raw-proxy path which needs a TLS-speaking upstream. The cert is a publicly
/// trusted one for the Portal hostname (e.g. an LE cert obtained out-of-band, as
/// the help-site already does), configured via `CT_EDGE_PORTAL_CERT`/`_KEY`.
pub fn build_portal_acceptor(
    cert_pem: impl AsRef<Path>,
    key_pem: impl AsRef<Path>,
) -> Result<TlsAcceptor, BoxError> {
    install_crypto_provider();
    // PEM parsing via the maintained rustls-pki-types PemObject decoders (#80 SEC80b —
    // replaces the unmaintained rustls-pemfile).
    use rustls::pki_types::pem::PemObject;
    let cert_bytes = std::fs::read(cert_pem)?;
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("portal cert PEM parse failed: {e}"))?;
    if chain.is_empty() {
        return Err("portal cert file had no certificates".into());
    }
    let key_bytes = std::fs::read(key_pem)?;
    let key = PrivateKeyDer::from_pem_slice(&key_bytes)
        .map_err(|e| format!("portal key file had no usable private key: {e}"))?;
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// Build a QUIC server [`Endpoint`] (P1.1a), discarding the cert.
pub fn build_server_endpoint() -> Result<Endpoint, BoxError> {
    Ok(build_server_endpoint_with_cert()?.0)
}

/// Build a QUIC client [`Endpoint`] that trusts exactly `server_cert`.
pub fn build_client_endpoint(server_cert: CertificateDer<'static>) -> Result<Endpoint, BoxError> {
    install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(server_cert)?;
    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));
    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Accept one connection, accept one bidirectional stream, and echo its bytes
/// back. Returns after the stream is finished.
pub async fn accept_and_echo_one(endpoint: &Endpoint) -> Result<(), BoxError> {
    let incoming = endpoint.accept().await.ok_or("endpoint closed with no incoming")?;
    let conn = incoming.await?;
    let (mut send, mut recv) = conn.accept_bi().await?;
    let data = recv.read_to_end(64 * 1024).await?;
    send.write_all(&data).await?;
    send.finish()?;
    // Keep the connection alive until the peer has acknowledged closure.
    conn.closed().await;
    Ok(())
}

/// Build a TCP+TLS listener bound to `addr` (M12.2a) — the Edge's fallback
/// transport for Clients that can't reach it over UDP/QUIC. Returns the
/// listener, a TLS acceptor with a fresh self-signed cert, and that cert (which
/// Clients trust). The tunnel's transport-agnostic byte protocol runs over it.
pub async fn build_tcp_tls_listener_at(
    addr: SocketAddr,
) -> Result<(TcpListener, TlsAcceptor, CertificateDer<'static>), BoxError> {
    install_crypto_provider();
    let (cert, key) = self_signed()?;
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)?;
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind(addr).await?;
    Ok((listener, acceptor, cert))
}

/// Connect to a TCP+TLS Edge fallback at `addr`, trusting `edge_cert` (M12.2a).
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
    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(addr).await?;
    let server_name = rustls::pki_types::ServerName::try_from("localhost")?;
    Ok(connector.connect(server_name, tcp).await?)
}

/// Build both Edge listeners sharing one self-signed cert (M12.3a): a QUIC
/// endpoint on `quic_addr` (UDP) and a TLS-TCP listener on `tcp_addr` (the
/// fallback). Clients trust the single returned cert for either transport.
pub async fn build_dual_edge(
    quic_addr: SocketAddr,
    tcp_addr: SocketAddr,
) -> Result<(Endpoint, TcpListener, TlsAcceptor, CertificateDer<'static>), BoxError> {
    install_crypto_provider();
    let (cert, key) = self_signed()?;
    let quic_cfg = quinn::ServerConfig::with_single_cert(vec![cert.clone()], key.clone_key())?;
    let endpoint = Endpoint::server(quic_cfg, quic_addr)?;
    let tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));
    let listener = TcpListener::bind(tcp_addr).await?;
    Ok((endpoint, listener, acceptor, cert))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn build_portal_acceptor_parses_pem_via_pki_types() {
        // #80 SEC80b: the rustls-pki-types PEM decoders (replacing the unmaintained
        // rustls-pemfile) must accept a real PEM cert + PKCS#8 key and reject junk.
        let certified = rcgen::generate_simple_self_signed(vec!["portal.example".to_string()]).unwrap();
        let dir = std::env::temp_dir().join(format!("ct-portal-acc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, certified.cert.pem()).unwrap();
        std::fs::write(&key_path, certified.key_pair.serialize_pem()).unwrap();

        assert!(
            build_portal_acceptor(&cert_path, &key_path).is_ok(),
            "a real PEM cert + key parse into a TLS acceptor"
        );
        // A key file with no PEM key material is rejected (not silently accepted).
        std::fs::write(&key_path, b"-----BEGIN NONSENSE-----\nnope\n-----END NONSENSE-----\n").unwrap();
        assert!(
            build_portal_acceptor(&cert_path, &key_path).is_err(),
            "a file with no usable private key is rejected"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn tcp_tls_stream_echoes() {
        // M12.2a: a Client connects to the Edge's TCP+TLS fallback and a byte
        // stream round-trips (the transport the tunnel protocol runs over).
        let (listener, acceptor, cert) =
            build_tcp_tls_listener_at((Ipv4Addr::LOCALHOST, 0).into()).await.expect("listener");
        let addr = listener.local_addr().expect("addr");
        let srv = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut buf = [0u8; 64];
            let n = tls.read(&mut buf).await.unwrap();
            tls.write_all(&buf[..n]).await.unwrap();
            tls.shutdown().await.unwrap();
        });

        let mut client = tcp_tls_connect(addr, cert).await.expect("connect");
        client.write_all(b"tcp-fallback").await.unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"tcp-fallback", "TLS-over-TCP stream round-trips");
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn dual_edge_serves_quic_and_tcp_with_one_cert() {
        // M12.3a: one self-signed cert works for both the QUIC endpoint and the
        // TLS-TCP fallback listener.
        let loop_v4 = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let (endpoint, tcp_listener, acceptor, cert) =
            build_dual_edge(loop_v4, loop_v4).await.expect("dual edge");
        let qaddr = endpoint.local_addr().unwrap();
        let taddr = tcp_listener.local_addr().unwrap();

        // QUIC side: accept + handshake.
        let quic = tokio::spawn(async move {
            if let Some(inc) = endpoint.accept().await {
                let _ = inc.await;
            }
        });
        // TCP side: accept + TLS handshake.
        let tcp = tokio::spawn(async move {
            let (s, _) = tcp_listener.accept().await.unwrap();
            let _ = acceptor.accept(s).await;
        });

        let qclient = build_client_endpoint(cert.clone()).unwrap();
        let qconn = qclient.connect(qaddr, "localhost").unwrap().await;
        assert!(qconn.is_ok(), "QUIC connects with the shared cert");

        let tclient = tcp_tls_connect(taddr, cert).await;
        assert!(tclient.is_ok(), "TLS-TCP connects with the shared cert");

        let _ = quic.await;
        let _ = tcp.await;
    }

    #[tokio::test]
    async fn server_endpoint_binds_to_ephemeral_port() {
        let endpoint = build_server_endpoint().expect("build server endpoint");
        let port = endpoint
            .local_addr()
            .expect("endpoint has a local address")
            .port();
        assert_ne!(port, 0, "server must bind a concrete ephemeral UDP port");
    }

    #[tokio::test]
    async fn echo_roundtrip_over_bidirectional_stream() {
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let server_addr = server.local_addr().expect("server addr");

        let server_task = tokio::spawn(async move {
            accept_and_echo_one(&server).await.expect("server echo");
        });

        let client = build_client_endpoint(cert).expect("client");
        let conn = client
            .connect(server_addr, "localhost")
            .expect("connect config")
            .await
            .expect("connected");

        let (mut send, mut recv) = conn.open_bi().await.expect("open bi");
        send.write_all(b"ping").await.expect("write");
        send.finish().expect("finish");

        let echoed = recv.read_to_end(64 * 1024).await.expect("read echo");
        assert_eq!(&echoed, b"ping", "echoed bytes must match sent");

        conn.close(0u32.into(), b"done");
        server_task.await.expect("server task join");
    }

    #[tokio::test]
    async fn untrusted_server_cert_is_rejected() {
        let (server, _real_cert) = build_server_endpoint_with_cert().expect("server");
        let server_addr = server.local_addr().expect("server addr");

        let server_task = tokio::spawn(async move {
            if let Some(incoming) = server.accept().await {
                let _ = incoming.await; // handshake is expected to fail
            }
        });

        // Client trusts a DIFFERENT self-signed cert, not the server's.
        let wrong = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("wrong cert");
        let wrong_cert = wrong.cert.der().clone();
        let client = build_client_endpoint(wrong_cert).expect("client");

        let result = client
            .connect(server_addr, "localhost")
            .expect("connect config")
            .await;
        assert!(
            result.is_err(),
            "handshake with an untrusted server cert must be rejected"
        );

        server_task.abort();
    }

    #[tokio::test]
    async fn cert_save_load_roundtrip() {
        let (_endpoint, cert) = build_server_endpoint_with_cert().expect("cert");
        let path = std::env::temp_dir().join(format!("ct-edge-cert-{}.der", std::process::id()));
        save_cert(&path, &cert).expect("save");
        let loaded = load_cert(&path).expect("load");
        assert_eq!(loaded, cert, "cert round-trips through the shared file");
        let _ = std::fs::remove_file(&path);
    }
}
