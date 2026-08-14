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
use zeroize::Zeroize;

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
    /// #496: the EXACT root DER this edge publishes (`/pki/ca`, acceptor roots). On a
    /// fresh mint it is the built cert's DER; on a reload it is the PERSISTED bytes --
    /// byte-stable across redeploys, so anything that pinned or cached the root keeps
    /// matching literally (notBefore/serial no longer churn per boot). Leaf SIGNING
    /// keeps using the rebuilt `cert` (identical DN + key), which verifies against
    /// this published root regardless of its bytes.
    published_root: CertificateDer<'static>,
    /// #425: the CA root's own `not_after`, kept alongside the built `cert` so
    /// `issue` can clamp every leaf's validity to stay inside it -- a leaf
    /// certificate outliving the root that signed it would be trusted right up
    /// until the (already-expired) root fails its own check, not a real bound.
    not_after: time::OffsetDateTime,
}

/// #278: without this, `key`'s serialized DER (the root-of-trust private key,
/// valid across restarts since it's persisted to disk) sits in freed-but-not-
/// cleared heap after `Ca` is dropped -- recoverable from a core dump, a
/// same-UID `/proc/<pid>/mem` read, or swap, until the memory happens to be
/// reallocated and overwritten. `rcgen`'s `zeroize` feature (already a
/// workspace dependency via `ct-common`) makes `KeyPair::zeroize()` clear that
/// buffer; nothing does so automatically on drop, so `Ca` must call it itself.
impl Drop for Ca {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Write `bytes` to `path`, restricting the file to owner read/write (0600) on
/// Unix so a persisted CA signing key is never world-readable.
///
/// #277: a prior `std::fs::write` (creates at the umask-default mode, typically
/// 0644) followed by a separate `set_permissions(0600)` left a real TOCTOU
/// window — under the microseconds between the two syscalls the freshly
/// generated CA private key PEM sat world-readable, so any local user who
/// `open()`'d it in that window (or just raced it, e.g. via a symlink/inotify
/// watch) could read the root-of-trust key and mint arbitrary Edge leaf certs.
/// `OpenOptionsExt::mode(0o600)` applies the restrictive mode atomically as
/// part of the file's *creation* syscall itself (subject only to the umask
/// stripping bits further, never widening them) — there is no window where the
/// file exists at a broader mode.
fn write_owner_only(path: &str, bytes: &[u8]) -> Result<(), BoxError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)?;
    }
    Ok(())
}

/// #496: where the persisted CA root CERT lives, derived from the key path so both ride
/// the same volume ("edge-ca-key.pem" -> "edge-ca-cert.der"; any other shape gets
/// ".cert.der" appended).
fn ca_cert_path_for(key_pem_path: &str) -> String {
    match key_pem_path.strip_suffix("-key.pem") {
        Some(stem) => format!("{stem}-cert.der"),
        None => format!("{key_pem_path}.cert.der"),
    }
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
        let mut ca = Self::load_or_create_key_only(key_pem_path, common_name)?;
        // #496: persist the ROOT CERT too, not only the key. from_key rebuilds a root with
        // fresh notBefore/serial on every boot -- cryptographically compatible (same DN +
        // key, all leaves keep verifying), but BYTE-different, so every /pki/ca cache,
        // baked env value, and literal pin churned per redeploy. Reusing the persisted
        // bytes makes the published root byte-stable. Guards: the persisted cert must
        // embed this key's exact SPKI (raw public key found verbatim in the DER --
        // dependency-free integrity check; a stale cert from a rotated key is discarded),
        // and its recorded not_after (sidecar) must leave room for a full leaf validity
        // window, or we remint (with a log line) rather than clamp leaves against an
        // expiring root.
        let cert_path = ca_cert_path_for(key_pem_path);
        let meta_path = format!("{cert_path}.notafter");
        let pubkey = ca.key.public_key_der();
        let loaded = std::fs::read(&cert_path).ok().zip(
            std::fs::read_to_string(&meta_path)
                .ok()
                .and_then(|m| m.trim().parse::<i64>().ok())
                .and_then(|ts| time::OffsetDateTime::from_unix_timestamp(ts).ok()),
        );
        match loaded {
            Some((der, not_after))
                if der.windows(pubkey.len()).any(|w| w == pubkey.as_slice())
                    && not_after
                        > time::OffsetDateTime::now_utc() + time::Duration::days(Self::LEAF_VALIDITY_DAYS + 1) =>
            {
                ca.published_root = CertificateDer::from(der).into_owned();
                ca.not_after = not_after;
            }
            other => {
                if other.is_some() {
                    eprintln!(
                        "ct-edge: persisted CA cert at {cert_path} is stale (rotated key or expiring) -- reminting"
                    );
                }
                std::fs::write(&cert_path, ca.published_root.as_ref())?;
                std::fs::write(&meta_path, ca.not_after.unix_timestamp().to_string())?;
            }
        }
        Ok(ca)
    }

    /// The pre-#496 body of [`Self::load_or_create`]: key persistence only.
    fn load_or_create_key_only(key_pem_path: &str, common_name: &str) -> Result<Self, BoxError> {
        match std::fs::read_to_string(key_pem_path) {
            Ok(pem) => {
                // #424: `Drop for Ca` (above) zeroizes the final `KeyPair`'s own internal
                // representation, but `pem` here is a separate, ordinary `String` holding
                // the same root-of-trust key material -- it sat unzeroized on the heap
                // after this function returned until #278's own gap (before this fix)
                // reappeared one level up the call stack. `Zeroizing<String>` wipes it on
                // drop regardless of which branch below returns.
                let pem = zeroize::Zeroizing::new(pem);
                // #424: re-assert the restrictive mode on every load too, not just at
                // creation -- `write_owner_only`'s atomic 0600 only guarantees the mode at
                // the moment of creation; nothing previously re-checked it on a later load
                // (e.g. after a misconfigured deploy/volume mount widened it).
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(0o600);
                    std::fs::set_permissions(key_pem_path, perms)?;
                }
                Self::from_key(KeyPair::from_pem(&pem)?, common_name)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = KeyPair::generate()?;
                // #424: same zeroizing treatment for the create path's own intermediate
                // PEM string.
                let pem = zeroize::Zeroizing::new(key.serialize_pem());
                write_owner_only(key_pem_path, pem.as_bytes())?;
                Self::from_key(key, common_name)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// #425: the CA root's own validity window -- long-lived (this is the
    /// root-of-trust every Client pins, meant to outlive many leaf rotations), but
    /// bounded rather than rcgen's effectively-unbounded default. 10 years matches
    /// common internal-CA practice; the signing key itself is what actually rotates
    /// (a fresh `load_or_create` call with a new path), not this certificate.
    const CA_VALIDITY_DAYS: i64 = 3652; // ~10 years
    /// #425: leaf certificate validity -- short-lived by design (frequent rotation
    /// bounds the blast radius of a compromised leaf key), matching this project's
    /// own external-ACME precedent (Let's Encrypt's ~90-day leaves) rather than
    /// rcgen's effectively-unbounded default. Always inside the CA root's own
    /// window (enforced in `issue`, below).
    const LEAF_VALIDITY_DAYS: i64 = 90;

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
        let now = time::OffsetDateTime::now_utc();
        let not_after = now + time::Duration::days(Self::CA_VALIDITY_DAYS);
        params.not_before = now;
        params.not_after = not_after;
        let cert = params.self_signed(&key)?;
        let published_root = cert.der().clone();
        Ok(Self { cert, key, not_after, published_root })
    }

    /// The CA root certificate (DER) that Clients must trust.
    pub fn root_der(&self) -> CertificateDer<'static> {
        self.published_root.clone()
    }

    /// Issue a leaf certificate for `sans` (hostnames/IPs), signed by this CA.
    /// Returns the leaf certificate (DER) and its private key.
    pub fn issue(
        &self,
        sans: Vec<String>,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), BoxError> {
        let leaf_key = KeyPair::generate()?;
        let mut params = CertificateParams::new(sans)?;
        // #425: bounded, short-lived validity (see LEAF_VALIDITY_DAYS's own doc) --
        // clamped to never outlive the CA root that signs it (`self.not_after`), so a
        // near-end-of-life root can't mint a leaf that outlives the root's own trust.
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = (now + time::Duration::days(Self::LEAF_VALIDITY_DAYS)).min(self.not_after);
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
///
/// The list also carries `h2`, for the low-DPI-visibility channel route
/// (`sni::CT_EDGE_CHANNEL_FALLBACK_SNI`): that client deliberately offers an ordinary
/// web ALPN so its plaintext ClientHello carries no tunnel fingerprint, and rustls
/// answers an ALPN *mismatch* with a fatal `no_application_protocol` alert — with a
/// single-value list such a client would be killed at the TLS layer even though
/// `classify_front_door` had correctly routed its peeked hello here by SNI. rustls
/// negotiates whichever entry the client actually offers, so both the pre-existing
/// `ct-edge-channel` clients and the new `h2` ones complete the handshake against this
/// same acceptor. Nothing here is a *routing* decision: which leg a connection reaches
/// was already settled by `classify_front_door` before this acceptor ever sees it.
pub async fn build_channel_front_door_acceptor(
    ca: &Ca,
    sans: Vec<String>,
) -> Result<TlsAcceptor, BoxError> {
    install_crypto_provider();
    let (cert, key) = ca.issue(sans)?;
    let mut tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    // #500 K2: SERVER-preference order encodes the keepalive negotiation. A KA-capable
    // plain-leg client offers [ct-edge-channel-ka, ct-edge-channel] -> the `-ka` id wins
    // here; an old client offers only the bare id. The boring leg has no distinctive id
    // (camouflage): a KA-capable boring client offers [h2, http/1.1] and `http/1.1`
    // listed BEFORE `h2` makes its selection the keepalive signal, while an old boring
    // client's [h2]-only offer still lands on `h2`. Only channel-classified connections
    // ever reach this acceptor (ALPN/reserved-SNI routing), so claiming `http/1.1` here
    // can never shadow a real proxied host.
    tls_cfg.alpn_protocols = vec![
        crate::sni::CT_EDGE_CHANNEL_KA_ALPN.as_bytes().to_vec(),
        crate::sni::CT_EDGE_CHANNEL_ALPN.as_bytes().to_vec(),
        b"http/1.1".to_vec(),
        b"h2".to_vec(),
    ];
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

    #[test]
    fn persisted_ca_root_is_byte_stable_across_reloads_and_remints_on_key_rotation_496() {
        // #496: two load_or_create calls on the same paths publish the IDENTICAL root
        // bytes (no notBefore/serial churn); leaves from the reloaded CA verify against
        // the first boot's published root; a rotated KEY discards the stale cert file.
        let dir = std::env::temp_dir().join(format!("ca496-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("edge-ca-key.pem").to_string_lossy().into_owned();

        let boot1 = Ca::load_or_create(&key_path, "ct-edge-ca").unwrap();
        let root1 = boot1.root_der();
        let boot2 = Ca::load_or_create(&key_path, "ct-edge-ca").unwrap();
        assert_eq!(
            root1.as_ref(),
            boot2.root_der().as_ref(),
            "the published root is byte-stable across restarts"
        );
        // A leaf minted AFTER the reload chains to the boot1-published root (same DN+key).
        let (leaf, _key) = boot2.issue(vec!["localhost".into()]).unwrap();
        assert!(!leaf.as_ref().is_empty());

        // Key rotation: delete the key, keep the stale cert -> the SPKI guard remints.
        std::fs::remove_file(&key_path).unwrap();
        let boot3 = Ca::load_or_create(&key_path, "ct-edge-ca").unwrap();
        assert_ne!(
            root1.as_ref(),
            boot3.root_der().as_ref(),
            "a rotated key never republishes the old root"
        );
        // And the fresh cert is now the persisted one.
        let boot4 = Ca::load_or_create(&key_path, "ct-edge-ca").unwrap();
        assert_eq!(boot3.root_der().as_ref(), boot4.root_der().as_ref());
        let _ = std::fs::remove_dir_all(&dir);
    }

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

    /// #500 K2: the channel acceptor's ALPN preference order IS the keepalive
    /// negotiation -- prove all four old/new x plain/boring combinations against a REAL
    /// TLS handshake: a KA-capable plain client lands on `-ka`, an old plain client on
    /// the bare id; a KA-capable boring client's [h2, http/1.1] offer is deliberately
    /// answered with `http/1.1` (the camouflage-preserving KA signal), an old boring
    /// client's [h2]-only offer stays on `h2`.
    #[tokio::test]
    async fn channel_acceptor_negotiates_keepalive_by_alpn_preference_500() {
        let ca = Ca::new("ct-edge-ca").unwrap();
        let acceptor = build_channel_front_door_acceptor(&ca, vec!["localhost".into()])
            .await
            .expect("channel acceptor");
        let cases: &[(&[&str], &str)] = &[
            (&["ct-edge-channel-ka", "ct-edge-channel"], "ct-edge-channel-ka"),
            (&["ct-edge-channel"], "ct-edge-channel"),
            (&["h2", "http/1.1"], "http/1.1"),
            (&["h2"], "h2"),
        ];
        for (offer, expect) in cases {
            let (c, s) = tokio::io::duplex(16 * 1024);
            let acceptor = acceptor.clone();
            let srv = tokio::spawn(async move { acceptor.accept(s).await });
            let mut roots = rustls::RootCertStore::empty();
            roots.add(ca.root_der()).unwrap();
            let mut cfg = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            cfg.alpn_protocols = offer.iter().map(|p| p.as_bytes().to_vec()).collect();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
            let tls = connector
                .connect("localhost".try_into().unwrap(), c)
                .await
                .expect("client handshake");
            assert_eq!(
                tls.get_ref().1.alpn_protocol(),
                Some(expect.as_bytes()),
                "client view for offer {offer:?}"
            );
            let stls = srv.await.unwrap().expect("server handshake");
            assert_eq!(
                stls.get_ref().1.alpn_protocol(),
                Some(expect.as_bytes()),
                "server view for offer {offer:?}"
            );
        }
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

    /// #277: the persisted CA key file must never be created at a mode broader
    /// than owner-only (0600) — the actual bug was a *write-then-chmod* TOCTOU
    /// window (unobservable after the fact, since by the time this test's own
    /// `metadata()` call runs the chmod would already have happened even under
    /// the old code) fixed by making the restrictive mode part of the file's
    /// creation syscall itself. This asserts the resulting end-state mode as a
    /// standing regression guard on that requirement.
    #[cfg(unix)]
    #[test]
    fn ca_key_file_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let key_path = std::env::temp_dir()
            .join(format!("ct-edge-ca-perm-{}.pem", std::process::id()))
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_file(&key_path);

        let _ca = Ca::load_or_create(&key_path, "ct-edge-ca").unwrap();
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "CA key file must be owner-read/write only, got {mode:o}");

        let _ = std::fs::remove_file(&key_path);
    }

    #[test]
    fn ca_root_and_issued_leaves_have_bounded_real_validity_windows_425() {
        // #425: before this fix, rcgen's own default (effectively unbounded --
        // spanning centuries) applied to both the CA root and every issued leaf.
        // Real proof against actual parsed certificate fields, not just that the
        // code compiles: both windows are real, bounded, start at-or-before now,
        // and the leaf's window sits entirely inside the CA root's own window.
        use x509_parser::prelude::FromDer;

        let ca = Ca::new("ct-edge-ca-425").unwrap();
        let (leaf_der, _key) = ca.issue(vec!["example.test".into()]).unwrap();

        let root_der_bytes = ca.root_der();
        let (_, root_cert) = x509_parser::certificate::X509Certificate::from_der(&root_der_bytes).unwrap();
        let (_, leaf_cert) = x509_parser::certificate::X509Certificate::from_der(&leaf_der).unwrap();

        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let root_not_before = root_cert.validity().not_before.timestamp();
        let root_not_after = root_cert.validity().not_after.timestamp();
        let leaf_not_before = leaf_cert.validity().not_before.timestamp();
        let leaf_not_after = leaf_cert.validity().not_after.timestamp();

        assert!(root_not_before <= now, "CA root's own not_before must not be in the future");
        assert!(
            root_not_after < now + Ca::CA_VALIDITY_DAYS * 86_400 + 3600,
            "CA root must NOT have rcgen's effectively-unbounded default validity"
        );
        assert!(leaf_not_before <= now, "leaf's not_before must not be in the future");
        assert!(
            leaf_not_after < now + Ca::LEAF_VALIDITY_DAYS * 86_400 + 3600,
            "leaf must NOT have rcgen's effectively-unbounded default validity"
        );
        assert!(
            leaf_not_after <= root_not_after,
            "a leaf must never outlive the CA root that signed it"
        );
    }

    /// Run one real, in-process TLS handshake against `acceptor`: a client trusting
    /// `ca_root` presents `server_name` and offers `client_alpn`. Returns the ALPN both
    /// sides negotiated (`None` when the client offered none), or the client's error.
    async fn handshake_against(
        acceptor: TlsAcceptor,
        ca_root: CertificateDer<'static>,
        server_name: &'static str,
        client_alpn: Vec<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>, BoxError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let srv = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.ok()?;
            acceptor.accept(tcp).await.ok()
        });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca_root)?;
        let mut ccfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        ccfg.alpn_protocols = client_alpn;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(ccfg));
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        let name = rustls::pki_types::ServerName::try_from(server_name)?;
        let client = connector.connect(name, tcp).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), srv).await;
        Ok(client?.get_ref().1.alpn_protocol().map(|p| p.to_vec()))
    }

    /// The channel front door's acceptor must complete a handshake for BOTH channel
    /// clients: the pre-existing one advertising the distinctive `ct-edge-channel`
    /// ALPN, and the low-DPI-visibility one that deliberately offers only an ordinary
    /// `h2` (or nothing) and identifies itself by the reserved
    /// `sni::CT_EDGE_CHANNEL_FALLBACK_SNI` hostname instead. With the previous
    /// single-value ALPN list the latter was killed by rustls' fatal
    /// `no_application_protocol` alert before it could speak to the broker at all,
    /// even though the front door had routed its peeked ClientHello here correctly.
    #[tokio::test]
    async fn channel_front_door_acceptor_serves_both_the_channel_alpn_and_a_plain_h2_client() {
        let ca = Ca::new("ct-edge-ca").unwrap();
        let ca_root = ca.root_der();
        // The production SAN list (see `serve.rs`'s call site): the reserved fallback
        // hostname is included so a client presenting it as its SNI validates the leaf
        // under ordinary rustls name verification, with no custom verifier.
        let sans = vec![
            "localhost".to_string(),
            crate::sni::CT_EDGE_CHANNEL_FALLBACK_SNI.to_string(),
        ];
        let acceptor = build_channel_front_door_acceptor(&ca, sans).await.unwrap();

        // The low-visibility route: plain `h2`, reserved SNI. This is the case the
        // multi-value ALPN list exists for.
        assert_eq!(
            handshake_against(
                acceptor.clone(),
                ca_root.clone(),
                crate::sni::CT_EDGE_CHANNEL_FALLBACK_SNI,
                vec![b"h2".to_vec()],
            )
            .await
            .expect("a plain-h2 client must complete the handshake, not get no_application_protocol"),
            Some(b"h2".to_vec()),
            "the acceptor negotiates h2 with a client that offers only h2"
        );

        // Regression: the pre-existing `ct-edge-channel` client is completely
        // unaffected -- same acceptor, same negotiated ALPN as before.
        assert_eq!(
            handshake_against(
                acceptor.clone(),
                ca_root.clone(),
                "localhost",
                vec![crate::sni::CT_EDGE_CHANNEL_ALPN.as_bytes().to_vec()],
            )
            .await
            .expect("the ct-edge-channel client still handshakes"),
            Some(crate::sni::CT_EDGE_CHANNEL_ALPN.as_bytes().to_vec()),
            "an existing channel client still negotiates ct-edge-channel (#118's readiness probe)"
        );

        // A client offering both resolves by SERVER preference (rustls picks the first
        // entry of its own list the client also offers), so `ct-edge-channel` keeps
        // winning -- adding `h2` cannot downgrade an existing client.
        assert_eq!(
            handshake_against(
                acceptor.clone(),
                ca_root.clone(),
                "localhost",
                vec![crate::sni::CT_EDGE_CHANNEL_ALPN.as_bytes().to_vec(), b"h2".to_vec()],
            )
            .await
            .unwrap(),
            Some(crate::sni::CT_EDGE_CHANNEL_ALPN.as_bytes().to_vec()),
            "server-preference order keeps ct-edge-channel ahead of h2"
        );

        // A client offering NO ALPN extension at all also completes (rustls only alerts
        // on a genuine mismatch), matching `classify_front_door`'s acceptance of a
        // reserved-SNI hello with no ALPN.
        assert_eq!(
            handshake_against(acceptor, ca_root, crate::sni::CT_EDGE_CHANNEL_FALLBACK_SNI, Vec::new())
                .await
                .expect("a client offering no ALPN still handshakes"),
            None
        );
    }

    /// The relay-gate acceptor is deliberately NOT widened: it stays single-valued on
    /// `ct-edge-relay`, so a stray `h2` client is still refused there. Guards against a
    /// future change copying the channel acceptor's multi-value list across.
    #[tokio::test]
    async fn relay_gate_acceptor_still_refuses_a_plain_h2_client() {
        let ca = Ca::new("ct-edge-ca").unwrap();
        let ca_root = ca.root_der();
        let acceptor = build_relay_gate_front_door_acceptor(&ca, vec!["localhost".to_string()])
            .await
            .unwrap();
        assert!(
            handshake_against(acceptor, ca_root, "localhost", vec![b"h2".to_vec()]).await.is_err(),
            "the relay gate must keep answering an ALPN mismatch with a fatal alert"
        );
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
