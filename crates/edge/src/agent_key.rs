//! trace: INC-20261011-305, INC-20261011-004, AUF-20261011-049
//!
//! Local, CP-free proof of agent-key possession for Rolle `A` (serve.rs). The Edge
//! sends a fresh nonce and the Agent answers with a `SignedAgentBinding` plus a
//! proof-of-possession signature over `(nonce, token)`; both are checked here,
//! before any `registration_lock`, without contacting the control plane.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ct_common::agent_binding::{AgentBindingError, SignedAgentBinding};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::state::{parse_enforce_list, AgentKeyMode, AgentKeyReason, ProvenKey};

/// Mirrors `serve.rs`'s `ROLE_DISPATCH_TIMEOUT` (which is private there): every read
/// or write of the handshake is bounded by the same 10s admission slack.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The wire-encoded `SignedAgentBinding` may not exceed this many bytes.
const MAX_BINDING_LEN: usize = 512;

/// Run the Rolle-`A` handshake over an already-accepted stream: send a 32 byte
/// nonce, read back `u16` length | `SignedAgentBinding::encode()` | 64 byte
/// proof-of-possession signature, and verify both without any CP round trip.
pub async fn prove_agent_key<R, W>(
    recv: &mut R,
    send: &mut W,
    token: &ct_common::RoutingToken,
    issuers: &[[u8; 32]],
    now: u64,
) -> Result<ProvenKey, AgentKeyReason>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);

    tokio::time::timeout(HANDSHAKE_TIMEOUT, send.write_all(&nonce))
        .await
        .map_err(|_| AgentKeyReason::Timeout)?
        .map_err(|_| AgentKeyReason::Timeout)?;

    let mut len_bytes = [0u8; 2];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, recv.read_exact(&mut len_bytes))
        .await
        .map_err(|_| AgentKeyReason::Timeout)?
        .map_err(|_| AgentKeyReason::Timeout)?;
    let len = u16::from_be_bytes(len_bytes) as usize;
    if len > MAX_BINDING_LEN {
        return Err(AgentKeyReason::Oversize);
    }

    let mut binding_bytes = vec![0u8; len];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, recv.read_exact(&mut binding_bytes))
        .await
        .map_err(|_| AgentKeyReason::Timeout)?
        .map_err(|_| AgentKeyReason::Timeout)?;

    let mut signature = [0u8; 64];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, recv.read_exact(&mut signature))
        .await
        .map_err(|_| AgentKeyReason::Timeout)?
        .map_err(|_| AgentKeyReason::Timeout)?;

    let signed = SignedAgentBinding::decode(&binding_bytes).map_err(map_binding_error)?;

    ct_common::agent_binding::verify_registration(
        issuers, &signed, &token.0, &nonce, &signature, now,
    )
    .map_err(map_binding_error)?;

    Ok(ProvenKey {
        key: signed.binding.agent_pubkey,
        issued_at: signed.binding.issued_at,
    })
}

fn map_binding_error(err: AgentBindingError) -> AgentKeyReason {
    match err {
        AgentBindingError::TokenMismatch | AgentBindingError::TunnelIdTooLong => {
            AgentKeyReason::BindingToken
        }
        AgentBindingError::Malformed
        | AgentBindingError::UnknownIssuer
        | AgentBindingError::BadKey
        | AgentBindingError::IssuedInFuture => AgentKeyReason::BadBinding,
        AgentBindingError::BadSignature => AgentKeyReason::BadProof,
        AgentBindingError::Expired => AgentKeyReason::Expired,
    }
}

/// `CT_EDGE_AGENT_KEY_MODE`, `CT_EDGE_AGENT_BINDING_ISSUER_PUBKEYS` and
/// `CT_EDGE_AGENT_KEY_ENFORCE_FILE`, resolved into what [`prove_agent_key`] and its
/// caller need. Built by a pure function over an injected lookup so it is testable
/// without touching the process environment (mirrors `config.rs`'s `from_env_with`).
pub struct AgentKeyConfig {
    pub mode: AgentKeyMode,
    pub enforce_file: Option<PathBuf>,
    pub enforce_set: HashSet<[u8; 32]>,
    pub issuers: Vec<[u8; 32]>,
    pub warnings: Vec<String>,
}

/// Resolve [`AgentKeyConfig`] from an injected variable lookup and file reader.
/// Fails closed only when enforcement actually applies (mode `enforce`, or a
/// non-empty enforce list) and either no valid issuer is configured or the
/// enforce file could not be read; in Log mode with an empty enforce list, every
/// problem with the new configuration becomes a warning instead (log for all).
pub fn agent_key_config_with(
    get: impl Fn(&str) -> Option<String>,
    read_file: impl Fn(&Path) -> std::io::Result<String>,
) -> Result<AgentKeyConfig, String> {
    let mut warnings = Vec::new();

    let mode = match get("CT_EDGE_AGENT_KEY_MODE").as_deref() {
        None | Some("log") => AgentKeyMode::Log,
        Some("enforce") => AgentKeyMode::Enforce,
        Some(other) => {
            warnings.push(format!(
                "CT_EDGE_AGENT_KEY_MODE: unbekannter Wert '{other}', verwende log"
            ));
            AgentKeyMode::Log
        }
    };

    let mut issuers = Vec::new();
    if let Some(raw) = get("CT_EDGE_AGENT_BINDING_ISSUER_PUBKEYS") {
        for part in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match ct_common::hex::decode_32(part) {
                Some(key) => issuers.push(key),
                None => warnings.push(format!(
                    "CT_EDGE_AGENT_BINDING_ISSUER_PUBKEYS: ungueltiger Schluessel '{part}' ignoriert"
                )),
            }
        }
    }

    let enforce_file = get("CT_EDGE_AGENT_KEY_ENFORCE_FILE").map(PathBuf::from);
    let mut enforce_set = HashSet::new();
    let mut enforce_file_unreadable = false;
    if let Some(path) = &enforce_file {
        match read_file(path) {
            Ok(text) => match parse_enforce_list(&text) {
                Ok(set) => enforce_set = set,
                Err(err) => {
                    enforce_file_unreadable = true;
                    warnings.push(format!(
                        "CT_EDGE_AGENT_KEY_ENFORCE_FILE: Inhalt von '{}' ungueltig: {err:?}",
                        path.display()
                    ));
                }
            },
            Err(err) => {
                enforce_file_unreadable = true;
                warnings.push(format!(
                    "CT_EDGE_AGENT_KEY_ENFORCE_FILE: '{}' nicht lesbar: {err}",
                    path.display()
                ));
            }
        }
    }

    let enforce_applies = matches!(mode, AgentKeyMode::Enforce) || !enforce_set.is_empty();
    if enforce_applies && (issuers.is_empty() || enforce_file_unreadable) {
        return Err(
            "agent_key: Enforce verlangt mindestens einen gueltigen Aussteller und eine lesbare Enforce-Datei"
                .to_string(),
        );
    }

    Ok(AgentKeyConfig {
        mode,
        enforce_file,
        enforce_set,
        issuers,
        warnings,
    })
}

/// [`agent_key_config_with`] over the real process environment and filesystem.
pub fn agent_key_config_from_env() -> Result<AgentKeyConfig, String> {
    agent_key_config_with(|k| std::env::var(k).ok(), |p| std::fs::read_to_string(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_common::agent_binding::{sign_registration, AgentBinding};
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};
    use tokio::io::duplex;

    fn token_hash(token: &[u8]) -> [u8; 32] {
        let digest = Sha256::digest(token);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    fn mint(
        issuer_signing_key: &SigningKey,
        agent_signing_key: &SigningKey,
        token: &[u8],
        tunnel_id: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> SignedAgentBinding {
        let binding = AgentBinding {
            tunnel_id: tunnel_id.to_string(),
            token_hash: token_hash(token),
            agent_pubkey: agent_signing_key.verifying_key().to_bytes(),
            issued_at,
            expires_at,
        };
        SignedAgentBinding::mint(issuer_signing_key, binding)
    }

    /// Drive the Agent side of the handshake over one duplex pair's halves.
    async fn run_agent<R, W>(
        mut nonce_recv: R,
        mut response_send: W,
        signed: &SignedAgentBinding,
        agent_signing_key: &SigningKey,
        token: &[u8],
    ) where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut nonce = [0u8; 32];
        nonce_recv.read_exact(&mut nonce).await.unwrap();
        let encoded = signed.encode();
        let signature = sign_registration(agent_signing_key, &nonce, token);
        response_send
            .write_all(&(encoded.len() as u16).to_be_bytes())
            .await
            .unwrap();
        response_send.write_all(&encoded).await.unwrap();
        response_send.write_all(&signature).await.unwrap();
    }

    const TOKEN_A: [u8; 32] = [1u8; 32];
    const TOKEN_B: [u8; 32] = [2u8; 32];

    #[tokio::test]
    async fn agent_key_hs_049_valid_handshake() {
        let issuer = SigningKey::from_bytes(&[11u8; 32]);
        let agent = SigningKey::from_bytes(&[22u8; 32]);
        let issuers = vec![issuer.verifying_key().to_bytes()];
        let signed = mint(&issuer, &agent, &TOKEN_A, "tunnel-a", 1_000, 2_000);
        let agent_pubkey = agent.verifying_key().to_bytes();
        let token = ct_common::RoutingToken(TOKEN_A);

        let (edge_send, agent_recv) = duplex(1024);
        let (agent_send, edge_recv) = duplex(1024);
        let mut edge_send = edge_send;
        let mut edge_recv = edge_recv;

        let agent_task = tokio::spawn(async move {
            run_agent(agent_recv, agent_send, &signed, &agent, &TOKEN_A).await;
        });

        let result = prove_agent_key(&mut edge_recv, &mut edge_send, &token, &issuers, 1_500).await;
        agent_task.await.unwrap();

        let proven = result.expect("valid handshake must be accepted");
        assert_eq!(proven.key, agent_pubkey);
        assert_eq!(proven.issued_at, 1_000);
    }

    #[tokio::test]
    async fn agent_key_hs_049_second_issuer() {
        let issuer_one = SigningKey::from_bytes(&[11u8; 32]);
        let issuer_two = SigningKey::from_bytes(&[12u8; 32]);
        let agent = SigningKey::from_bytes(&[22u8; 32]);
        let issuers = vec![
            issuer_one.verifying_key().to_bytes(),
            issuer_two.verifying_key().to_bytes(),
        ];
        let signed = mint(&issuer_two, &agent, &TOKEN_A, "tunnel-a", 1_000, 2_000);
        let token = ct_common::RoutingToken(TOKEN_A);

        let (edge_send, agent_recv) = duplex(1024);
        let (agent_send, edge_recv) = duplex(1024);
        let mut edge_send = edge_send;
        let mut edge_recv = edge_recv;

        let agent_task = tokio::spawn(async move {
            run_agent(agent_recv, agent_send, &signed, &agent, &TOKEN_A).await;
        });

        let result = prove_agent_key(&mut edge_recv, &mut edge_send, &token, &issuers, 1_500).await;
        agent_task.await.unwrap();

        assert!(result.is_ok(), "second issuer in the list must verify");
    }

    #[tokio::test]
    async fn agent_key_hs_049_binding_for_other_token() {
        let issuer = SigningKey::from_bytes(&[11u8; 32]);
        let agent = SigningKey::from_bytes(&[22u8; 32]);
        let issuers = vec![issuer.verifying_key().to_bytes()];
        let signed = mint(&issuer, &agent, &TOKEN_A, "tunnel-a", 1_000, 2_000);
        let token_b = ct_common::RoutingToken(TOKEN_B);

        let (edge_send, agent_recv) = duplex(1024);
        let (agent_send, edge_recv) = duplex(1024);
        let mut edge_send = edge_send;
        let mut edge_recv = edge_recv;

        let agent_task = tokio::spawn(async move {
            run_agent(agent_recv, agent_send, &signed, &agent, &TOKEN_A).await;
        });

        let result =
            prove_agent_key(&mut edge_recv, &mut edge_send, &token_b, &issuers, 1_500).await;
        agent_task.await.unwrap();

        assert_eq!(result, Err(AgentKeyReason::BindingToken));
    }

    #[tokio::test]
    async fn agent_key_hs_049_foreign_signing_key() {
        let issuer = SigningKey::from_bytes(&[11u8; 32]);
        let agent = SigningKey::from_bytes(&[22u8; 32]);
        let foreign = SigningKey::from_bytes(&[33u8; 32]);
        let issuers = vec![issuer.verifying_key().to_bytes()];
        let signed = mint(&issuer, &agent, &TOKEN_A, "tunnel-a", 1_000, 2_000);
        let token = ct_common::RoutingToken(TOKEN_A);

        let (edge_send, agent_recv) = duplex(1024);
        let (agent_send, edge_recv) = duplex(1024);
        let mut edge_send = edge_send;
        let mut edge_recv = edge_recv;

        let agent_task = tokio::spawn(async move {
            run_agent(agent_recv, agent_send, &signed, &foreign, &TOKEN_A).await;
        });

        let result = prove_agent_key(&mut edge_recv, &mut edge_send, &token, &issuers, 1_500).await;
        agent_task.await.unwrap();

        assert_eq!(result, Err(AgentKeyReason::BadProof));
    }

    #[tokio::test]
    async fn agent_key_hs_049_expired() {
        let issuer = SigningKey::from_bytes(&[11u8; 32]);
        let agent = SigningKey::from_bytes(&[22u8; 32]);
        let issuers = vec![issuer.verifying_key().to_bytes()];
        let signed = mint(&issuer, &agent, &TOKEN_A, "tunnel-a", 1_000, 2_000);
        let token = ct_common::RoutingToken(TOKEN_A);

        let (edge_send, agent_recv) = duplex(1024);
        let (agent_send, edge_recv) = duplex(1024);
        let mut edge_send = edge_send;
        let mut edge_recv = edge_recv;

        let agent_task = tokio::spawn(async move {
            run_agent(agent_recv, agent_send, &signed, &agent, &TOKEN_A).await;
        });

        let result = prove_agent_key(&mut edge_recv, &mut edge_send, &token, &issuers, 9_999).await;
        agent_task.await.unwrap();

        assert_eq!(result, Err(AgentKeyReason::Expired));
    }

    #[tokio::test]
    async fn agent_key_hs_049_timeout() {
        let issuers: Vec<[u8; 32]> = vec![];
        let token = ct_common::RoutingToken(TOKEN_A);

        let (edge_send, agent_recv) = duplex(1024);
        let (_agent_send, edge_recv) = duplex(1024);
        let mut edge_send = edge_send;
        let mut edge_recv = edge_recv;

        // Agent receives the nonce but never answers; the Edge side must time out.
        let agent_task = tokio::spawn(async move {
            let mut agent_recv = agent_recv;
            let mut nonce = [0u8; 32];
            let _ = agent_recv.read_exact(&mut nonce).await;
        });

        let result = prove_agent_key(&mut edge_recv, &mut edge_send, &token, &issuers, 1_500).await;
        agent_task.await.unwrap();

        assert_eq!(result, Err(AgentKeyReason::Timeout));
    }

    #[tokio::test]
    async fn agent_key_hs_049_oversize() {
        let issuers: Vec<[u8; 32]> = vec![];
        let token = ct_common::RoutingToken(TOKEN_A);

        let (edge_send, agent_recv) = duplex(1024);
        let (agent_send, edge_recv) = duplex(1024);
        let mut edge_send = edge_send;
        let mut edge_recv = edge_recv;

        let agent_task = tokio::spawn(async move {
            let mut agent_recv = agent_recv;
            let mut agent_send = agent_send;
            let mut nonce = [0u8; 32];
            agent_recv.read_exact(&mut nonce).await.unwrap();
            agent_send.write_all(&600u16.to_be_bytes()).await.unwrap();
        });

        let result = prove_agent_key(&mut edge_recv, &mut edge_send, &token, &issuers, 1_500).await;
        agent_task.await.unwrap();

        assert_eq!(result, Err(AgentKeyReason::Oversize));
    }

    #[test]
    fn agent_key_hs_049_enforce_without_issuer_fails() {
        let result = agent_key_config_with(
            |k| match k {
                "CT_EDGE_AGENT_KEY_MODE" => Some("enforce".to_string()),
                _ => None,
            },
            |_| Ok(String::new()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn agent_key_hs_049_log_mode_tolerates_broken_issuer_and_unreadable_file() {
        let cfg = agent_key_config_with(
            |k| match k {
                "CT_EDGE_AGENT_KEY_MODE" => Some("log".to_string()),
                "CT_EDGE_AGENT_BINDING_ISSUER_PUBKEYS" => Some("not-hex".to_string()),
                "CT_EDGE_AGENT_KEY_ENFORCE_FILE" => Some(format!(
                    "{}/agent-key-enforce-{}-missing.txt",
                    std::env::temp_dir().display(),
                    std::process::id()
                )),
                _ => None,
            },
            |_| Err(std::io::Error::new(std::io::ErrorKind::NotFound, "missing")),
        )
        .expect("log mode must never fail startup over bad new config");

        assert!(matches!(cfg.mode, AgentKeyMode::Log));
        assert!(!cfg.warnings.is_empty());
        assert!(cfg.issuers.is_empty());
        assert!(cfg.enforce_set.is_empty());
    }
}
