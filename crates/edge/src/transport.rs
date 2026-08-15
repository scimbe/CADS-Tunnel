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

/// Enable TCP keepalive on `stream` (#229, tightened for the ct-agent#15 flap
/// investigation) -- see the matching helper in `ct-agent`'s `transport.rs`
/// for the full rationale: a parked TLS-TCP fallback registration is a
/// plain, silent TCP connection with nothing to refresh it, so an idle
/// NAT/firewall mapping between the Agent and this Edge can be dropped
/// without either side noticing until a Client is delivered onto the
/// now-dead connection. Applied here on the Edge's own accept side too, for
/// the same reason and for symmetry with any intermediate stateful device on
/// this leg of the path. Best-effort.
///
/// `time`/`interval` are 20s/20s with the OS-default retry count (typically 9 on
/// Linux), so a genuinely dead connection surfaces after ~200s (20 + 9*20).
///
/// **These were briefly tightened to 10s/10s + `with_retries(3)` (worst case 40s)
/// on 2026-08-12 and reverted the next day.** The reasoning for tightening was
/// that a parked Agent registration sits silently broken for minutes before
/// either side notices. Both halves of that reasoning turned out to be wrong for
/// this knob:
///
/// 1. **It did not fix what it was for.** The parked-registration flapping it
///    targeted continued at exactly the same rate afterwards, because the real
///    cause is a middlebox that ignores ACK-only segments entirely — no keepalive
///    *timing* helps against that, which is precisely why the ping-capable `'K'`
///    role (real payload traffic on parked connections) exists.
/// 2. **Its blast radius is every accepted TCP connection, not just parked
///    registrations.** `serve_listener` applies this to every socket it accepts,
///    including browser connections to the `:443` front door. Cutting the
///    tolerance 5x therefore also cut how long *any* legitimately-idle connection
///    may stay quiet — and when the probes themselves are the thing being
///    dropped, retries add nothing. Live symptom after the tightening: a
///    long-running request (an LLM call taking 15-20s, during which its
///    connection is genuinely idle) started dying mid-flight, with ~52
///    `ETIMEDOUT` per 30 minutes across `:443` and the fallback listener where
///    there had been none.
///
/// Detecting a dead peer faster is not worth killing live-but-quiet connections:
/// a dead registration is already covered by the `open_bi` failover path (#8 R2),
/// whereas a killed in-flight request is an outright user-visible failure. Do not
/// re-tighten this without a mechanism that distinguishes "idle" from "dead" —
/// which is what the `'K'` ping role does, at the protocol level, where it
/// belongs.
pub(crate) fn apply_tcp_keepalive(stream: &TcpStream) {
    let sock = socket2::SockRef::from(stream);
    let ka = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(20))
        .with_interval(std::time::Duration::from_secs(20));
    let _ = sock.set_tcp_keepalive(&ka);
}

/// Shared accept-loop policy for every plain-TCP public listener (#452): admission
/// (acquire-or-shed against a [`crate::state::ConnectionCap`], with a uniform occasional
/// shed-event log), TCP keepalive ([`apply_tcp_keepalive`]), and spawning — the steps
/// every one of this crate's hand-rolled TCP accept loops was independently reimplementing
/// with its own small divergence (one had a cap but never called the keepalive helper,
/// another logged shed events and another didn't, ...). `label` names the listener in its
/// shed/accept-error/handshake-timeout logs.
///
/// `handshake_timeout`, when `Some`, bounds the ENTIRE `handler` future — correct for a
/// listener whose whole connection is meant to be short-lived end to end (e.g. the `:80`
/// redirect: connect, read a request, write a redirect, done). A listener whose connection
/// is meant to stay open for a long-lived tunnel/session (the `:443` front door, the TCP
/// fallback, the ws-channel listener's post-upgrade phase) must pass `None` here and keep
/// applying its OWN finer-grained timeout(s) to just its handshake/admission-read phase
/// internally, same as before this helper existed — wrapping the WHOLE handler in one
/// timeout for those would incorrectly bound the long-lived phase, not just the handshake.
///
/// `handler` receives the accepted [`TcpStream`], its peer address, and the OWNED permit
/// (`None` when `cap` is `None`) so it can be moved into whatever value ends up owning the
/// connection for its true lifetime (#451) rather than just held as a task-local binding —
/// necessary whenever the connection can outlive this one task (e.g. a channel member that
/// parks in a `ChannelPairer` and is later handed to a different, freshly spawned task).
///
/// `shutdown` (#400): checked before every `accept()`, raced against it via `tokio::select!`
/// so a pending `accept()` doesn't stop this from noticing shutdown promptly. Once triggered,
/// this function returns instead of accepting further connections — it does NOT touch any
/// connection already admitted (those keep running in their own already-spawned task exactly
/// as before); bounding how long already-admitted connections are given to finish is
/// `run_edge`'s job ([`crate::shutdown::wait_for_drain`]), not this loop's.
///
/// Otherwise never returns (mirrors every accept loop it replaces): a per-connection
/// `accept()` error is transient and logged, not fatal to the listener.
pub(crate) async fn serve_listener<F, Fut>(
    listener: TcpListener,
    cap: Option<crate::state::ConnectionCap>,
    label: &'static str,
    handshake_timeout: Option<std::time::Duration>,
    shutdown: crate::shutdown::ShutdownSignal,
    handler: F,
) where
    F: Fn(TcpStream, SocketAddr, Option<tokio::sync::OwnedSemaphorePermit>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let handler = Arc::new(handler);
    loop {
        let (stream, addr) = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                eprintln!("ct-edge: {label} stopping new accepts (shutdown)");
                return;
            }
            accepted = listener.accept() => match accepted {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ct-edge: {label} accept error: {e}");
                    // 2026-08-15 outage: on RESOURCE exhaustion (EMFILE/ENFILE --
                    // "Too many open files") an immediate retry cannot succeed and
                    // hot-spins the loop at 100% CPU with a log line per iteration,
                    // which both sustains the very fd pressure it suffers from and
                    // floods the disk (the 15-minute :443 outage's amplifier). Back
                    // off briefly so in-flight connections can close and return fds;
                    // every other accept error keeps the immediate-retry behavior
                    // (transient per-connection failures are the common case).
                    // EMFILE=24 / ENFILE=23 (Linux, the only deploy target) -- matched
                    // by raw value to avoid a libc dependency for two constants.
                    if matches!(e.raw_os_error(), Some(24) | Some(23)) {
                        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                    }
                    continue;
                }
            },
        };
        let permit = match &cap {
            Some(cap) => match cap.try_admit() {
                Some(p) => Some(p),
                None => {
                    // Shed BEFORE spawning (cheaper than admitting then dropping
                    // mid-handshake); logged occasionally (powers of two, then every
                    // 1000) so a sustained shed streak is visible without spamming
                    // stdout under a real flood.
                    let total = cap.note_shed();
                    if total.is_power_of_two() || total % 1000 == 0 {
                        eprintln!(
                            "ct-edge: {label} shedding — connection cap full, {total} connection(s) shed since start"
                        );
                    }
                    drop(stream);
                    continue;
                }
            },
            None => None,
        };
        apply_tcp_keepalive(&stream);
        let handler = handler.clone();
        tokio::spawn(async move {
            let fut = handler(stream, addr, permit);
            match handshake_timeout {
                Some(d) => {
                    if tokio::time::timeout(d, fut).await.is_err() {
                        eprintln!("ct-edge: {label} handshake timed out from {addr}");
                    }
                }
                None => fut.await,
            }
        });
    }
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

    // ---- serve_listener (#452 shared accept-loop helper) ---------------------------------

    #[tokio::test]
    async fn serve_listener_enforces_its_cap_and_admits_again_once_a_slot_frees_452() {
        // The core policy #452's shared helper exists to apply consistently everywhere: a
        // full `ConnectionCap` sheds (the connection never reaches `handler` at all), and a
        // freed slot admits again -- proven directly against `serve_listener` itself so
        // every migrated call site (the `:443` front door, TCP fallback, `:80` redirect,
        // Browser-Plane SNI, ws-channel) inherits this from one tested place.
        let cap = crate::state::ConnectionCap::new(1);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let admitted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let admitted_h = admitted.clone();
        // The handler holds the connection open (never returns) until told to, so the cap's
        // one slot stays occupied for as long as the test needs it to.
        let (hold_tx, hold_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(serve_listener(listener, Some(cap.clone()), "test-listener", None, crate::shutdown::ShutdownSignal::never(), move |_s, _addr, permit| {
            let admitted_h = admitted_h.clone();
            let mut hold_rx = hold_rx.clone();
            async move {
                admitted_h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _permit = permit;
                let _ = hold_rx.changed().await; // block until released
            }
        }));

        // First connection: admitted, takes the cap's only slot.
        let first = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(admitted.load(std::sync::atomic::Ordering::SeqCst), 1, "first connection admitted");
        assert_eq!(cap.available(), 0, "the cap's only slot is now in use");

        // Second connection: the cap is full -- shed, never reaches the handler. Proven by
        // the peer closing the socket immediately (a real client sees EOF/reset, not a
        // hanging connection) and the admitted counter staying at 1.
        let mut second = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(std::time::Duration::from_secs(2), second.read(&mut buf))
            .await
            .expect("a shed connection is closed promptly, not left hanging");
        assert!(matches!(read, Ok(0) | Err(_)), "shed connection closes without any handler bytes: {read:?}");
        assert_eq!(admitted.load(std::sync::atomic::Ordering::SeqCst), 1, "the shed connection never reached the handler");
        assert_eq!(cap.shed_total(), 1, "the shed was recorded");

        // Free the slot: a third connection is admitted again.
        drop(first);
        let _ = hold_tx.send(true);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(cap.available(), 1, "the freed slot is available again");
        let _third = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(admitted.load(std::sync::atomic::Ordering::SeqCst), 2, "a THIRD connection is admitted once a slot frees");
    }

    #[tokio::test]
    async fn serve_listener_applies_tcp_keepalive_to_every_admitted_connection_452() {
        // #452: "only some listeners call the shared TCP-keepalive helper" -- `serve_listener`
        // now calls it unconditionally for every admitted connection, closing that gap for
        // every migrated loop at once. Proven directly: the accepted stream's SO_KEEPALIVE
        // option is set once the handler runs (readable back via socket2, the same crate
        // `apply_tcp_keepalive` itself uses to set it).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<bool>(1);
        tokio::spawn(serve_listener(listener, None, "test-listener", None, crate::shutdown::ShutdownSignal::never(), move |stream, _addr, _permit| {
            let tx = tx.clone();
            async move {
                let sock = socket2::SockRef::from(&stream);
                let ka = sock.keepalive().unwrap_or(false);
                let _ = tx.send(ka).await;
            }
        }));

        let _client = TcpStream::connect(addr).await.unwrap();
        let ka = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("handler ran")
            .expect("keepalive flag sent");
        assert!(ka, "serve_listener must apply TCP keepalive before handing the connection to its handler");
    }

    #[tokio::test]
    async fn apply_tcp_keepalive_stays_tolerant_enough_for_a_legitimately_idle_connection() {
        // Regression guard for a real production incident (2026-08-13). These values
        // were briefly tightened to 10s/10s + retries(3) -- worst case 40s instead of
        // ~200s -- to surface dead parked registrations faster. That was wrong twice
        // over: it did not reduce the flapping it targeted (the cause is a middlebox
        // dropping ACK-only segments, which no keepalive *timing* can fix), and
        // `serve_listener` applies this to EVERY accepted socket, including browser
        // connections to the :443 front door. So it also cut how long any
        // legitimately-quiet connection may stay quiet, and a long-running request
        // (an LLM call taking 15-20s, idle on the wire while it thinks) started
        // dying mid-flight -- ~52 ETIMEDOUT per 30 min where there had been none.
        //
        // Pin the tolerant values, and pin the property that actually matters: the
        // window must stay comfortably above the tens-of-seconds an ordinary slow
        // request can legitimately be idle. Killing a live-but-quiet connection is a
        // user-visible failure; a dead registration is already covered by the
        // `open_bi` failover path (#8 R2). Distinguishing idle from dead belongs in
        // the protocol (the 'K' ping role), not in a socket timeout.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            apply_tcp_keepalive(&stream);
            stream
        });
        let _client = TcpStream::connect(addr).await.unwrap();
        let stream = accept.await.unwrap();

        let sock = socket2::SockRef::from(&stream);
        assert!(sock.keepalive().unwrap_or(false), "SO_KEEPALIVE must be enabled");
        let idle = sock.keepalive_time().unwrap();
        assert_eq!(idle, std::time::Duration::from_secs(20), "TCP_KEEPIDLE");
        assert_eq!(
            sock.keepalive_interval().unwrap(),
            std::time::Duration::from_secs(20),
            "TCP_KEEPINTVL"
        );

        // The load-bearing assertion: probing must not even BEGIN until well past the
        // idle stretch of an ordinary slow request. A 15-20s LLM call is the concrete
        // case that broke; require real margin over it rather than pinning a number
        // whose purpose is easy to lose.
        assert!(
            idle >= std::time::Duration::from_secs(20),
            "keepalive probing starts after {idle:?} -- too soon: a request that is \
             legitimately idle for 15-20s (an LLM call) must not be treated as dead"
        );

        // Retries are deliberately left at the OS default (~9 on Linux) rather than
        // bounded: an explicit low bound only shortens the window further, and when
        // the probes themselves are what a middlebox drops, more retries cost nothing
        // while fewer retries kill live connections sooner.
        if let Ok(retries) = sock.keepalive_retries() {
            assert!(
                retries >= 5,
                "TCP_KEEPCNT={retries} is too aggressive; leave the OS default so the \
                 total window stays long enough for a legitimately idle connection"
            );
        }
    }

    #[tokio::test]
    async fn serve_listener_times_out_a_stalled_handler_when_a_handshake_timeout_is_set_452() {
        // #452 (closing #451 gap 3's general form): when a caller supplies a
        // `handshake_timeout`, a handler that never completes (a stalled/hostile
        // pre-upgrade client) is abandoned within that bound instead of holding its cap
        // permit -- and the task slot -- forever. Proven by a handler that blocks forever
        // and a short timeout: the cap's permit must be back to available soon after,
        // without the handler itself ever completing normally.
        let cap = crate::state::ConnectionCap::new(1);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let completed_normally = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let completed_h = completed_normally.clone();
        tokio::spawn(serve_listener(
            listener,
            Some(cap.clone()),
            "test-listener",
            Some(std::time::Duration::from_millis(150)),
            crate::shutdown::ShutdownSignal::never(),
            move |_s, _addr, permit| {
                let completed_h = completed_h.clone();
                async move {
                    let _permit = permit;
                    std::future::pending::<()>().await; // stalled -- never completes on its own
                    completed_h.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            },
        ));

        let _client = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(cap.available(), 0, "the permit is held while the (stalled) handler is in flight");

        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert_eq!(cap.available(), 1, "the handshake timeout gives the permit back once it fires");
        assert!(
            !completed_normally.load(std::sync::atomic::Ordering::SeqCst),
            "the handler was abandoned by the timeout, not allowed to run to completion"
        );
    }

    #[tokio::test]
    async fn serve_listener_stops_accepting_promptly_once_shutdown_is_triggered_400() {
        // #400 property (a): once shutdown fires, `serve_listener` must stop admitting NEW
        // connections promptly -- a client dialing after the trigger sees the listener socket
        // closed (connection refused), not silently queued/hanging. Existing in-flight
        // handlers are untouched by this loop; that's proven separately by the
        // wait_for_drain tests in `shutdown.rs`.
        let cap = crate::state::ConnectionCap::new(4);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let admitted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let admitted_h = admitted.clone();
        let (ctl, shutdown) = crate::shutdown::ShutdownController::new();
        let task = tokio::spawn(serve_listener(listener, Some(cap.clone()), "test-listener", None, shutdown, move |_s, _addr, _permit| {
            let admitted_h = admitted_h.clone();
            async move {
                admitted_h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }));

        // Before shutdown: a connection is admitted normally.
        let _first = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(admitted.load(std::sync::atomic::Ordering::SeqCst), 1, "admits normally before shutdown");

        ctl.trigger();
        // The accept loop must return promptly (not on some later spurious wakeup) --
        // proven by the spawned task itself joining quickly.
        tokio::time::timeout(std::time::Duration::from_millis(300), task)
            .await
            .expect("serve_listener returns promptly once shutdown is triggered")
            .expect("task joined without panicking");

        // The OS listener socket is now closed (serve_listener owned it and dropped it on
        // return) -- a fresh dial fails fast rather than hanging or being silently accepted.
        let dialed = tokio::time::timeout(std::time::Duration::from_secs(2), TcpStream::connect(addr)).await;
        match dialed {
            Ok(Ok(_)) => panic!("no new connection should be admitted once shutdown has fired"),
            _ => {} // connection refused (Err) or the timeout itself firing are both fine here
        }
        assert_eq!(admitted.load(std::sync::atomic::Ordering::SeqCst), 1, "no further connection reached the handler after shutdown");
    }
}
