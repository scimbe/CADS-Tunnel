//! Internal CA + certificate issuance (M20.1, productionization).
//!
//! Replaces the per-certificate pinning of the dev/testbed scaffolding with a
//! proper PKI: an internal Certificate Authority signs the Edge's leaf
//! certificate, and Clients trust the **CA root** instead of a specific leaf.
//! Rotating the Edge cert then means issuing a new leaf under the same CA — no
//! client re-pinning required.

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::Endpoint;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::transport::install_crypto_provider;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// How often the Edge pings each peer connection (Agents and Clients), and how
/// long it tolerates silence before declaring one dead.
///
/// #8 failover hinges on this: a **killed** Agent sends no QUIC CLOSE frame, so
/// the Edge can only notice it via the idle timeout. Without an Edge-side
/// `max_idle_timeout` the connection lingers at the peer-negotiated timeout
/// (~30s), the dead registration is never evicted (`conn.closed()` never fires),
/// and clients keep routing to the corpse instead of failing over to a surviving
/// Agent. With these set, the Edge actively pings and tears a dead connection
/// down within ~`EDGE_MAX_IDLE`, firing `conn.closed()` so `run_edge` evicts.
///
/// `EDGE_MAX_IDLE` is kept comfortably above the Agent's 5s keepalive so a
/// *live* Agent — which both keepalives and ACKs the Edge's pings, generating
/// traffic every ~`EDGE_KEEP_ALIVE` — is never falsely disconnected.
const EDGE_KEEP_ALIVE: std::time::Duration = std::time::Duration::from_secs(3);
const EDGE_MAX_IDLE: std::time::Duration = std::time::Duration::from_secs(10);

/// Transport config for the Edge's QUIC **server** side: keepalive + idle
/// timeout so dead Agent connections are detected and evicted (#8). Shared by
/// both production server builders below.
fn edge_server_transport() -> Result<Arc<quinn::TransportConfig>, BoxError> {
    let mut t = quinn::TransportConfig::default();
    t.keep_alive_interval(Some(EDGE_KEEP_ALIVE));
    t.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(EDGE_MAX_IDLE).map_err(|_| "edge max_idle out of range")?,
    ));
    Ok(Arc::new(t))
}

/// An in-memory Certificate Authority that issues leaf certificates.
pub struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

/// Write `bytes` to `path`, restricting the file to owner read/write (0600) on
/// Unix so a persisted CA signing key is never world-readable.
fn write_owner_only(path: &str, bytes: &[u8]) -> Result<(), BoxError> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

impl Ca {
    /// Generate a fresh CA with the given common name.
    pub fn new(common_name: &str) -> Result<Self, BoxError> {
        Self::from_key(KeyPair::generate()?, common_name)
    }

    /// Load a CA whose signing key is persisted at `key_pem_path`, or generate a
    /// fresh one and persist it there. Persisting the CA **key** across restarts
    /// is what makes the published CA root stable: Agents/Clients trust the CA
    /// (by its public key + subject), so an Edge redeploy that reloads the same
    /// key keeps every pinned peer valid. Regenerating the CA on each boot — the
    /// previous behaviour — rotated the root under everyone and broke all pins
    /// with `BadSignature` (issue #2). The key file is written owner-only (0600)
    /// and lives on the Edge's runtime volume, never in the repo.
    pub fn load_or_create(key_pem_path: &str, common_name: &str) -> Result<Self, BoxError> {
        match std::fs::read_to_string(key_pem_path) {
            Ok(pem) => Self::from_key(KeyPair::from_pem(&pem)?, common_name),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = KeyPair::generate()?;
                write_owner_only(key_pem_path, key.serialize_pem().as_bytes())?;
                Self::from_key(key, common_name)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Build the CA certificate deterministically from an existing signing key,
    /// so a reloaded key yields a root that still validates previously issued
    /// leaves (trust chains to the CA's public key, unchanged across restarts).
    fn from_key(key: KeyPair, common_name: &str) -> Result<Self, BoxError> {
        let mut params = CertificateParams::new(Vec::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let cert = params.self_signed(&key)?;
        Ok(Self { cert, key })
    }

    /// The CA root certificate (DER) that Clients must trust.
    pub fn root_der(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }

    /// Issue a leaf certificate for `sans` (hostnames/IPs), signed by this CA.
    /// Returns the leaf certificate (DER) and its private key.
    pub fn issue(
        &self,
        sans: Vec<String>,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), BoxError> {
        let leaf_key = KeyPair::generate()?;
        let params = CertificateParams::new(sans)?;
        let leaf = params.signed_by(&leaf_key, &self.cert, &self.key)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        Ok((leaf.der().clone(), key))
    }
}

/// Build a QUIC server [`Endpoint`] bound to `addr` using a CA-issued leaf for
/// `sans`; returns the endpoint and the CA root (which Clients trust). This is
/// the production replacement for the self-signed `build_server_endpoint_at`.
pub fn build_server_endpoint_from_ca(
    ca: &Ca,
    addr: SocketAddr,
    sans: Vec<String>,
) -> Result<(Endpoint, CertificateDer<'static>), BoxError> {
    install_crypto_provider();
    let (cert, key) = ca.issue(sans)?;
    let mut server_config = quinn::ServerConfig::with_single_cert(vec![cert], key)?;
    server_config.transport_config(edge_server_transport()?);
    let endpoint = Endpoint::server(server_config, addr)?;
    Ok((endpoint, ca.root_der()))
}

/// Build both Edge listeners sharing one **CA-issued** leaf (the PKI equivalent
/// of `build_dual_edge`): a QUIC endpoint on `quic_addr` and a TLS-TCP fallback
/// on `tcp_addr`. Returns the endpoint, listener, acceptor, and the CA root that
/// Clients trust for either transport.
pub async fn build_dual_edge_from_ca(
    ca: &Ca,
    quic_addr: SocketAddr,
    tcp_addr: SocketAddr,
    sans: Vec<String>,
) -> Result<(Endpoint, TcpListener, TlsAcceptor, CertificateDer<'static>), BoxError> {
    install_crypto_provider();
    let (cert, key) = ca.issue(sans)?;
    let mut quic_cfg = quinn::ServerConfig::with_single_cert(vec![cert.clone()], key.clone_key())?;
    quic_cfg.transport_config(edge_server_transport()?);
    let endpoint = Endpoint::server(quic_cfg, quic_addr)?;
    let tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));
    let listener = TcpListener::bind(tcp_addr).await?;
    Ok((endpoint, listener, acceptor, ca.root_der()))
}

/// Build a dedicated TLS acceptor for the `:443` front door's **channel** leg (#118).
///
/// Like [`build_dual_edge_from_ca`] this terminates with a fresh CA-issued leaf for
/// `sans` (clients trust the CA *root*, so any leaf it signs validates), but its
/// `ServerConfig` advertises the `ct-edge-channel` ALPN. The shared edge acceptor
/// carries an EMPTY ALPN list and MUST stay that way: rustls answers an ALPN mismatch
/// with a fatal `no_application_protocol` alert, so advertising `ct-edge-channel` on the
/// shared acceptor would break the `EdgeRelay` leg's clients (which offer `ct-edge`, no
/// overlap). This dedicated acceptor is used ONLY by the ChannelBroker arm, so the
/// channel leg genuinely *negotiates* `ct-edge-channel` and a readiness probe reading
/// `alpn_protocol()` post-handshake sees `Some("ct-edge-channel")` instead of `None`.
///
/// The resulting stream type is identical to the shared acceptor's
/// (`tokio_rustls::server::TlsStream<Prepend<TcpStream>>`), so the front-door pairer
/// keying is unchanged.
pub async fn build_channel_front_door_acceptor(
    ca: &Ca,
    sans: Vec<String>,
) -> Result<TlsAcceptor, BoxError> {
    install_crypto_provider();
    let (cert, key) = ca.issue(sans)?;
    let mut tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    tls_cfg.alpn_protocols = vec![crate::sni::CT_EDGE_CHANNEL_ALPN.as_bytes().to_vec()];
    Ok(TlsAcceptor::from(Arc::new(tls_cfg)))
}

/// Build a dedicated TLS acceptor for the `:443` front door's **relay-gate** leg (the
/// real NAT-to-NAT hole-punch relay, multiplexed onto :443 rather than a new port).
/// Structurally identical to [`build_channel_front_door_acceptor`] except its
/// `ServerConfig` advertises `ct-edge-relay` instead — kept as its own dedicated
/// acceptor for the same reason: the shared edge acceptor's ALPN list MUST stay empty,
/// or an ALPN mismatch fatally alerts the `EdgeRelay` leg's `ct-edge` clients.
pub async fn build_relay_gate_front_door_acceptor(
    ca: &Ca,
    sans: Vec<String>,
) -> Result<TlsAcceptor, BoxError> {
    install_crypto_provider();
    let (cert, key) = ca.issue(sans)?;
    let mut tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    tls_cfg.alpn_protocols = vec![crate::sni::CT_EDGE_RELAY_ALPN.as_bytes().to_vec()];
    Ok(TlsAcceptor::from(Arc::new(tls_cfg)))
}

/// Build a QUIC client [`Endpoint`] that trusts a **CA root** — and therefore
/// any leaf that CA signs (enabling Edge cert rotation without re-pinning).
pub fn build_client_endpoint_trusting_ca(
    ca_root: CertificateDer<'static>,
) -> Result<Endpoint, BoxError> {
    install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_root)?;
    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::accept_and_echo_one;

    /// A leaf signed by the CA is accepted by a client that trusts the CA root
    /// (not the leaf) — the PKI trust chain works and rotation is possible.
    #[tokio::test]
    async fn ca_issued_leaf_is_trusted_via_ca_root() {
        let ca = Ca::new("ct-edge-ca").unwrap();
        let (server, ca_root) =
            build_server_endpoint_from_ca(&ca, "127.0.0.1:0".parse().unwrap(), vec!["localhost".into()])
                .unwrap();
        let addr = server.local_addr().unwrap();
        let srv = tokio::spawn(async move { accept_and_echo_one(&server).await });

        let client = build_client_endpoint_trusting_ca(ca_root).unwrap();
        let conn = client
            .connect(addr, "localhost")
            .unwrap()
            .await
            .expect("handshake against CA-issued cert");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"ping").await.unwrap();
        send.finish().unwrap();
        let echoed = recv.read_to_end(64).await.unwrap();
        assert_eq!(echoed, b"ping", "echo over the CA-trusted connection");

        conn.close(0u32.into(), b"done");
        let _ = srv.await;
    }

    /// A client trusting a *different* CA root rejects the Edge's leaf.
    #[tokio::test]
    async fn leaf_from_unknown_ca_is_rejected() {
        let ca = Ca::new("ct-edge-ca").unwrap();
        let (server, _ca_root) =
            build_server_endpoint_from_ca(&ca, "127.0.0.1:0".parse().unwrap(), vec!["localhost".into()])
                .unwrap();
        let addr = server.local_addr().unwrap();
        let _srv = tokio::spawn(async move {
            let _ = accept_and_echo_one(&server).await;
        });

        let other = Ca::new("other-ca").unwrap();
        let client = build_client_endpoint_trusting_ca(other.root_der()).unwrap();
        let result = client.connect(addr, "localhost").unwrap().await;
        assert!(result.is_err(), "leaf signed by an untrusted CA is rejected");
    }

    /// Rotation: a client that trusted the CA root once keeps working after the
    /// Edge rotates to a brand-new leaf (fresh cert + key) under the same CA — no
    /// client re-pinning required. This is the whole point of CA-based trust.
    #[tokio::test]
    async fn client_survives_edge_cert_rotation() {
        let ca = Ca::new("ct-edge-ca").unwrap();

        // First Edge instance + a client that trusts the CA root (obtained once).
        let (server1, ca_root) = build_server_endpoint_from_ca(
            &ca,
            "127.0.0.1:0".parse().unwrap(),
            vec!["localhost".into()],
        )
        .unwrap();
        let addr1 = server1.local_addr().unwrap();
        let srv1 = tokio::spawn(async move { accept_and_echo_one(&server1).await });
        let client = build_client_endpoint_trusting_ca(ca_root).unwrap();
        let conn1 = client.connect(addr1, "localhost").unwrap().await.unwrap();
        conn1.close(0u32.into(), b"done");
        let _ = srv1.await;

        // Rotate: a brand-new leaf under the same CA on a new endpoint.
        let (server2, _root2) = build_server_endpoint_from_ca(
            &ca,
            "127.0.0.1:0".parse().unwrap(),
            vec!["localhost".into()],
        )
        .unwrap();
        let addr2 = server2.local_addr().unwrap();
        let srv2 = tokio::spawn(async move { accept_and_echo_one(&server2).await });

        // The SAME client (same trust config) connects to the rotated cert.
        let conn2 = client
            .connect(addr2, "localhost")
            .unwrap()
            .await
            .expect("connect after rotation without re-pinning");
        let (mut send, mut recv) = conn2.open_bi().await.unwrap();
        send.write_all(b"after-rotation").await.unwrap();
        send.finish().unwrap();
        let echoed = recv.read_to_end(64).await.unwrap();
        assert_eq!(echoed, b"after-rotation", "works against the rotated cert");

        conn2.close(0u32.into(), b"done");
        let _ = srv2.await;
    }

    /// Issue #2: an Edge **restart** must reload the *same* CA so peers that
    /// pinned the root before the restart still validate the post-restart leaf.
    /// Unlike `client_survives_edge_cert_rotation` (one in-memory CA, rotated
    /// leaf), this simulates a process redeploy: two independent `load_or_create`
    /// calls against the same persisted key file. Regenerating the CA per boot
    /// broke this and produced `BadSignature` in the field.
    #[tokio::test]
    async fn persisted_ca_reload_keeps_pinned_clients_valid() {
        let key_path = std::env::temp_dir()
            .join(format!("ct-edge-ca-{}.pem", std::process::id()))
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_file(&key_path);

        // First boot: generate + persist the CA; a peer pins this root once.
        let ca_boot1 = Ca::load_or_create(&key_path, "ct-edge-ca").unwrap();
        let pinned_root = ca_boot1.root_der();

        // Redeploy: a brand-new process reloads the CA from the persisted key.
        let ca_boot2 = Ca::load_or_create(&key_path, "ct-edge-ca").unwrap();
        // Same signing key survived the "restart".
        assert_eq!(
            ca_boot1.key.public_key_der(),
            ca_boot2.key.public_key_der(),
            "reloaded CA keeps the same signing key"
        );

        // The post-restart Edge serves a leaf from the reloaded CA…
        let (server, _root2) = build_server_endpoint_from_ca(
            &ca_boot2,
            "127.0.0.1:0".parse().unwrap(),
            vec!["localhost".into()],
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let srv = tokio::spawn(async move { accept_and_echo_one(&server).await });

        // …and a client that pinned the pre-restart root still handshakes.
        let client = build_client_endpoint_trusting_ca(pinned_root).unwrap();
        let conn = client
            .connect(addr, "localhost")
            .unwrap()
            .await
            .expect("pre-restart pin trusts the reloaded CA's leaf");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"after-restart").await.unwrap();
        send.finish().unwrap();
        let echoed = recv.read_to_end(64).await.unwrap();
        assert_eq!(echoed, b"after-restart", "round-trip after an edge restart");

        conn.close(0u32.into(), b"done");
        let _ = srv.await;
        let _ = std::fs::remove_file(&key_path);
    }

    /// The dual-transport Edge with a CA-issued leaf is trusted over QUIC by a
    /// client that trusts the CA root.
    #[tokio::test]
    async fn dual_edge_from_ca_is_trusted_over_quic() {
        let ca = Ca::new("ct-edge-ca").unwrap();
        let (server, _listener, _acceptor, ca_root) = build_dual_edge_from_ca(
            &ca,
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            vec!["localhost".into()],
        )
        .await
        .unwrap();
        let addr = server.local_addr().unwrap();
        let srv = tokio::spawn(async move { accept_and_echo_one(&server).await });

        let client = build_client_endpoint_trusting_ca(ca_root).unwrap();
        let conn = client.connect(addr, "localhost").unwrap().await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"dual").await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(64).await.unwrap(), b"dual");

        conn.close(0u32.into(), b"done");
        let _ = srv.await;
    }
}
