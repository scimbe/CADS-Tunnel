//! The QUIC (`quinn`) half of the channel join/dial protocol: the accept-any-cert channel
//! **dialer** and the QUIC wrappers over [`crate::channel_wire::io`]'s stream-generic
//! exchange, plus the bounded post-admission stream setup.
//!
//! Ported verbatim from ct-agent `native/src/transport.rs:52-140` (the dialer),
//! `native/src/channel.rs:191-253` (the QUIC join wrappers) and
//! `native/src/channel_run/session.rs:152-178` (stream setup) @ v0.7.23 — see
//! [`crate::channel_wire`]'s provenance note. ct-agent re-exports these in place of its own
//! bodies (consolidation PR5). The one signature change is [`open_channel_streams`], which
//! takes `initiator: bool` instead of ct-agent's session-level `ChannelRole` enum (that enum
//! stays in ct-agent; its `open_channel_streams` becomes a one-line adapter).
//!
//! Native-only: needs `quinn`/`rustls`/`tokio::net`, which this crate does not pull in for
//! the wasm32 build (see `Cargo.toml`'s `[target.'cfg(not(target_arch = "wasm32"))']` block —
//! versions there are pinned to match ct-agent's `native/Cargo.toml` exactly: both sides
//! build QUIC connections against the same broker wire protocol, so a drift would be a real
//! wire-protocol risk, not a style nit).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};

use ed25519_dalek::SigningKey;
use quinn::{Connection, Endpoint};
use rustls::pki_types::CertificateDer;

use crate::channel::ChannelJoinRequest;
use crate::channel_wire::io::{present_channel_join_on_stream, ADMISSION_EXCHANGE_TIMEOUT};
use crate::channel_wire::ChannelJoinOutcome;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

// Deliberately duplicated 3-liner (ct-agent native/src/transport.rs:203, and this crate's
// channel_dial.rs): a `pub` re-export would couple ct-agent's cert-pinned tunnel dialer to
// ct_common for nothing (consolidation design §2).
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

// ported verbatim from ct-agent native/src/transport.rs:52-93 @ v0.7.23
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

// ported verbatim from ct-agent native/src/transport.rs:95-140 @ v0.7.23
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

// ported verbatim from ct-agent native/src/channel.rs:191-208 @ v0.7.23
/// Present `request` on `conn` and complete the edge's possession handshake, signing
/// the edge-issued challenge with `holder` — whose public key must equal the grant's
/// `holder`. Returns whether the edge admitted the join and, if paired, the peer's
/// advertised endpoint.
///
/// Wire protocol (matches `ct_edge::channel_broker`): send a `u16`-BE length prefix +
/// the encoded request, keeping the stream open; if the edge replies with a 32-byte
/// challenge, answer with a 64-byte ed25519 signature over it; then read the
/// `OK[ <endpoint>]` / `NO` ack (see the module header's ack contract). A refusal
/// before the possession step finishes the stream with no challenge, which surfaces
/// as [`ChannelJoinOutcome::Refused`].
pub async fn present_channel_join(
    conn: &Connection,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
) -> Result<ChannelJoinOutcome, BoxError> {
    present_channel_join_quic(conn, request, holder, None).await
}

// ported verbatim from ct-agent native/src/channel.rs:239-253 @ v0.7.23 (was private there;
// ct-agent's `present_channel_join_marked` — the operator-switch-gated caller, which stays
// in ct-agent — is a one-liner over this)
/// The QUIC join with an explicit phase preamble (CADS-Tunnel#495 U2 (a')): opens the
/// bi-stream on `conn` (bounded, #140) and runs [`present_channel_join_on_stream`] over it
/// with `phase_marker` — `None` for the byte-identical legacy wire, or
/// [`crate::channel_wire::PHASE_MARKER_RENDEZVOUS`] / [`crate::channel_wire::PHASE_MARKER_RELAY`].
/// Whether to send a marker at all is the caller's policy (ct-agent's `phase_marker_enabled`).
pub async fn present_channel_join_quic(
    conn: &Connection,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    phase_marker: Option<u8>,
) -> Result<ChannelJoinOutcome, BoxError> {
    // #140: bound `open_bi` too — it is the QUIC-path analog of the unbounded exchange below and
    // was equally unbounded past dial_peer_direct's connect timeout.
    let (send, recv) = tokio::time::timeout(ADMISSION_EXCHANGE_TIMEOUT, conn.open_bi())
        .await
        .map_err(|_| -> BoxError { "channel join open_bi stalled after connect (#140)".into() })??;
    // finish_send_after_sig = true: on QUIC the post-signature shutdown is quinn's clean
    // per-stream finish() -- connection-scoped state is untouched (unlike a TCP/TLS leg).
    present_channel_join_on_stream(send, recv, request, holder, ADMISSION_EXCHANGE_TIMEOUT, true, phase_marker, false).await
}

// ported verbatim from ct-agent native/src/channel_run/session.rs:152-178 @ v0.7.23
// (`role: ChannelRole` → `initiator: bool`; `Initiate` ⇔ `true`, `Accept` ⇔ `false`)
/// #139: how long a channel's QUIC stream setup (`open_bi`/`accept_bi`) may take past a successful
/// `dial_peer_direct` connect before the direct path is treated as dead. A healthy connection sets
/// the stream up sub-second; a conn that handshaked then went silent would otherwise hang here
/// forever (the Noise handshake beyond this is already bounded, #126). Sits below the dialer's 20s
/// idle-timeout (#139) so this tight bound fires first on the direct path.
pub const DIRECT_STREAM_SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Open (Initiate) or accept (Accept) the channel bi-stream on `conn`, **bounded** by `setup_timeout`
/// (#139) so a stalled direct link fails fast (`io::ErrorKind::TimedOut`) instead of hanging — the
/// exact `open_bi`/`accept_bi` gap central traced. The timeout is a parameter so tests can drive it
/// deterministically without waiting the production bound. `initiator` selects `open_bi`
/// (`true`, the grant's `Direction::Initiate` side) or `accept_bi` (`false`, `Direction::Accept`).
pub async fn open_channel_streams(
    conn: &Connection,
    initiator: bool,
    setup_timeout: std::time::Duration,
) -> std::io::Result<(quinn::SendStream, quinn::RecvStream)> {
    let map_err = |e: Box<dyn std::error::Error + Send + Sync>| std::io::Error::other(e.to_string());
    let open = async {
        if initiator {
            conn.open_bi().await.map_err(|e| map_err(Box::new(e)))
        } else {
            conn.accept_bi().await.map_err(|e| map_err(Box::new(e)))
        }
    };
    tokio::time::timeout(setup_timeout, open)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "direct channel stream setup stalled after connect (#139)"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    // ported verbatim from ct-agent native/src/transport.rs:942-954 @ v0.7.23
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
}
