//! Signed agent-binding v1 (trace: AUF-20261011-079, AUF-20261011-049;
//! INC-20261011-305, INC-20261011-004).
//!
//! Binds a join/routing token to a specific tunnel AND to the agent's public key.
//! `crate::credential::Credential` binds only a `(tenant, agent)` pair — it carries
//! no token hash and no agent key, so a party that intercepts a join token can redeem
//! it under a key of its own choosing; the existing proof-of-possession only proves
//! possession of *some* key, not that it is the key the token was meant for
//! (INC-20261011-305). This module is a distinct type rather than a reshaping of
//! `Credential`, because `Credential::signing_bytes` is sealed to the `ct-cred:v1`
//! domain and changing its field set would move that preimage out from under every
//! already-signed credential.
//!
//! Domain-separated from `ct-cred:v1`: a binding signs under `ct-agent-binding:v1`
//! and a registration challenge under `ct-agent-reg:v1`, so neither a `Credential`
//! signature nor a signature over one domain can ever verify as the other.

use crate::credential::UnixSeconds;
use crate::preimage::Preimage;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Clock skew tolerance for `issued_at` (N11): a binding "issued" up to this many
/// seconds in the verifier's future is still accepted, to absorb drift between the
/// issuer's and the verifier's clocks. Anything further ahead is rejected outright.
pub const CLOCK_SKEW_SECS: u64 = 300;

/// Maximum encoded size of a [`SignedAgentBinding`] (N10): generous for the payload's
/// fixed shape (a signature, two 32-byte fields, two `u64`s, and a bounded
/// `tunnel_id`) while bounding [`SignedAgentBinding::decode`]'s allocation against a
/// hostile peer.
const MAX_ENCODED_LEN: usize = 512;

/// Maximum byte length of [`AgentBinding::tunnel_id`].
const MAX_TUNNEL_ID_LEN: usize = 128;

/// Why binding verification, registration verification, or decode failed.
#[derive(Debug, PartialEq, Eq)]
pub enum AgentBindingError {
    /// The wire bytes were not a well-formed binding, or exceeded the size bound.
    Malformed,
    /// `tunnel_id` exceeds [`MAX_TUNNEL_ID_LEN`].
    TunnelIdTooLong,
    /// The presented token does not hash to the binding's `token_hash`.
    TokenMismatch,
    /// `now >= expires_at`.
    Expired,
    /// `issued_at` is further in the future than [`CLOCK_SKEW_SECS`] allows.
    IssuedInFuture,
    /// No issuer in the supplied list produced a valid `verify_strict` signature.
    UnknownIssuer,
    /// The agent's own signature over the registration challenge did not verify.
    BadSignature,
    /// The agent public key in the binding is not a valid ed25519 point.
    BadKey,
}

impl std::fmt::Display for AgentBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentBindingError::Malformed => write!(f, "agent binding bytes malformed"),
            AgentBindingError::TunnelIdTooLong => write!(f, "tunnel_id too long"),
            AgentBindingError::TokenMismatch => write!(f, "token does not match binding"),
            AgentBindingError::Expired => write!(f, "agent binding expired"),
            AgentBindingError::IssuedInFuture => {
                write!(f, "agent binding issued too far in the future")
            }
            AgentBindingError::UnknownIssuer => {
                write!(f, "agent binding signature matches no known issuer")
            }
            AgentBindingError::BadSignature => {
                write!(f, "registration challenge signature invalid")
            }
            AgentBindingError::BadKey => write!(f, "agent public key invalid"),
        }
    }
}

impl std::error::Error for AgentBindingError {}

/// The claims of an agent binding: this agent key, for this token, on this tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBinding {
    pub tunnel_id: String,
    pub token_hash: [u8; 32],
    pub agent_pubkey: [u8; 32],
    pub issued_at: UnixSeconds,
    pub expires_at: UnixSeconds,
}

impl AgentBinding {
    /// Canonical, domain-separated bytes covered by the issuer signature.
    pub fn signing_bytes(&self) -> Vec<u8> {
        Preimage::new(b"ct-agent-binding:v1")
            .var_bytes(self.tunnel_id.as_bytes())
            .fixed(&self.token_hash)
            .fixed(&self.agent_pubkey)
            .u64(self.issued_at)
            .u64(self.expires_at)
            .finish()
    }

    /// `sha256(agent_pubkey)`, a stable short identifier for the bound key.
    pub fn key_fingerprint(&self) -> [u8; 32] {
        Sha256::digest(self.agent_pubkey).into()
    }
}

/// An [`AgentBinding`] together with an issuer's signature over its claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAgentBinding {
    pub binding: AgentBinding,
    pub signature: [u8; 64],
}

impl SignedAgentBinding {
    /// Sign `binding` with `signing_key`, producing the wire-ready pair.
    pub fn mint(signing_key: &SigningKey, binding: AgentBinding) -> Self {
        let signature = signing_key.sign(&binding.signing_bytes()).to_bytes();
        Self { binding, signature }
    }

    /// Encode to a self-describing binary wire form:
    /// `signature(64) | tunnel_id_len(u32 LE) | tunnel_id | token_hash(32) | agent_pubkey(32) | issued_at(u64 LE) | expires_at(u64 LE)`.
    pub fn encode(&self) -> Vec<u8> {
        let tunnel_id = self.binding.tunnel_id.as_bytes();
        let mut out = Vec::with_capacity(64 + 4 + tunnel_id.len() + 32 + 32 + 8 + 8);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&(tunnel_id.len() as u32).to_le_bytes());
        out.extend_from_slice(tunnel_id);
        out.extend_from_slice(&self.binding.token_hash);
        out.extend_from_slice(&self.binding.agent_pubkey);
        out.extend_from_slice(&self.binding.issued_at.to_le_bytes());
        out.extend_from_slice(&self.binding.expires_at.to_le_bytes());
        out
    }

    /// Decode from [`SignedAgentBinding::encode`]'s wire form. Rejects input over
    /// [`MAX_ENCODED_LEN`] and a `tunnel_id` over [`MAX_TUNNEL_ID_LEN`] before
    /// attempting to read it, so a hostile length prefix cannot drive an oversized
    /// allocation or read past the buffer.
    pub fn decode(bytes: &[u8]) -> Result<Self, AgentBindingError> {
        if bytes.len() > MAX_ENCODED_LEN {
            return Err(AgentBindingError::Malformed);
        }

        fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8], AgentBindingError> {
            if cur.len() < n {
                return Err(AgentBindingError::Malformed);
            }
            let (head, tail) = cur.split_at(n);
            *cur = tail;
            Ok(head)
        }

        let mut cur = bytes;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(take(&mut cur, 64)?);

        let tunnel_id_len = u32::from_le_bytes(take(&mut cur, 4)?.try_into().unwrap()) as usize;
        if tunnel_id_len > MAX_TUNNEL_ID_LEN {
            return Err(AgentBindingError::TunnelIdTooLong);
        }
        let tunnel_id = String::from_utf8(take(&mut cur, tunnel_id_len)?.to_vec())
            .map_err(|_| AgentBindingError::Malformed)?;

        let mut token_hash = [0u8; 32];
        token_hash.copy_from_slice(take(&mut cur, 32)?);
        let mut agent_pubkey = [0u8; 32];
        agent_pubkey.copy_from_slice(take(&mut cur, 32)?);

        let issued_at = u64::from_le_bytes(take(&mut cur, 8)?.try_into().unwrap());
        let expires_at = u64::from_le_bytes(take(&mut cur, 8)?.try_into().unwrap());

        if !cur.is_empty() {
            return Err(AgentBindingError::Malformed);
        }

        Ok(SignedAgentBinding {
            binding: AgentBinding {
                tunnel_id,
                token_hash,
                agent_pubkey,
                issued_at,
                expires_at,
            },
            signature,
        })
    }
}

/// Verify a signed binding against one of `issuers` at time `now`: that `token`
/// hashes to the bound `token_hash`, that it is neither expired nor implausibly
/// far in the future, and that it carries a strict ed25519 signature from one of
/// `issuers`. Cheap checks run first (N17) so a malformed or mismatched binding
/// never reaches signature verification. Stateless: no database, no network, no
/// lock, no replay cache.
pub fn verify_binding(
    issuers: &[[u8; 32]],
    signed: &SignedAgentBinding,
    token: &[u8],
    now: UnixSeconds,
) -> Result<(), AgentBindingError> {
    let binding = &signed.binding;

    if binding.tunnel_id.len() > MAX_TUNNEL_ID_LEN {
        return Err(AgentBindingError::TunnelIdTooLong);
    }

    let presented_hash: [u8; 32] = Sha256::digest(token).into();
    if !crate::ct::eq(&binding.token_hash, &presented_hash) {
        return Err(AgentBindingError::TokenMismatch);
    }

    if now >= binding.expires_at {
        return Err(AgentBindingError::Expired);
    }

    if binding.issued_at > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(AgentBindingError::IssuedInFuture);
    }

    let sig = Signature::from_bytes(&signed.signature);
    let message = binding.signing_bytes();
    for issuer in issuers {
        if let Ok(vk) = VerifyingKey::from_bytes(issuer) {
            if vk.verify_strict(&message, &sig).is_ok() {
                return Ok(());
            }
        }
    }
    Err(AgentBindingError::UnknownIssuer)
}

/// Canonical, domain-separated bytes for a registration challenge: binds the
/// verifier's `nonce` to the specific `token` being redeemed, under its own
/// `ct-agent-reg:v1` domain (never shared with [`AgentBinding::signing_bytes`]).
pub fn registration_challenge_bytes(nonce: &[u8; 32], token: &[u8]) -> Vec<u8> {
    Preimage::new(b"ct-agent-reg:v1")
        .fixed(nonce)
        .var_bytes(token)
        .finish()
}

/// Sign a registration challenge as the agent side of the exchange.
pub fn sign_registration(
    agent_signing_key: &SigningKey,
    nonce: &[u8; 32],
    token: &[u8],
) -> [u8; 64] {
    agent_signing_key
        .sign(&registration_challenge_bytes(nonce, token))
        .to_bytes()
}

/// Verify both sides of registration: the binding itself ([`verify_binding`]), and
/// that `signature` over `(nonce, token)` verifies **strictly** under the binding's
/// own `agent_pubkey` — proof that the peer presenting the binding holds the
/// private key the binding names, not merely some key of its own choosing.
pub fn verify_registration(
    issuers: &[[u8; 32]],
    signed: &SignedAgentBinding,
    token: &[u8],
    nonce: &[u8; 32],
    signature: &[u8; 64],
    now: UnixSeconds,
) -> Result<(), AgentBindingError> {
    verify_binding(issuers, signed, token, now)?;

    let vk = VerifyingKey::from_bytes(&signed.binding.agent_pubkey)
        .map_err(|_| AgentBindingError::BadKey)?;
    let sig = Signature::from_bytes(signature);
    let challenge = registration_challenge_bytes(nonce, token);
    vk.verify_strict(&challenge, &sig)
        .map_err(|_| AgentBindingError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::Credential;
    use crate::{AgentId, TenantId};

    fn test_binding(
        sk: &SigningKey,
        tunnel_id: &str,
        token: &[u8],
        issued_at: UnixSeconds,
        expires_at: UnixSeconds,
    ) -> SignedAgentBinding {
        let binding = AgentBinding {
            tunnel_id: tunnel_id.into(),
            token_hash: Sha256::digest(token).into(),
            agent_pubkey: sk.verifying_key().to_bytes(),
            issued_at,
            expires_at,
        };
        SignedAgentBinding::mint(sk, binding)
    }

    #[test]
    fn verify_binding_accepts_a_valid_binding() {
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let issuer = sk.verifying_key().to_bytes();
        let signed = test_binding(&sk, "tunnel-a", b"token-a", 0, 1_000);
        assert_eq!(verify_binding(&[issuer], &signed, b"token-a", 500), Ok(()));
    }

    #[test]
    fn verify_binding_accepts_the_second_issuer_in_the_list() {
        let sk1 = SigningKey::from_bytes(&[11u8; 32]);
        let sk2 = SigningKey::from_bytes(&[12u8; 32]);
        let issuer1 = sk1.verifying_key().to_bytes();
        let issuer2 = sk2.verifying_key().to_bytes();
        let signed = test_binding(&sk2, "tunnel-a", b"token-a", 0, 1_000);
        assert_eq!(
            verify_binding(&[issuer1, issuer2], &signed, b"token-a", 500),
            Ok(())
        );
    }

    #[test]
    fn verify_binding_rejects_an_unknown_issuer() {
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let other = SigningKey::from_bytes(&[13u8; 32])
            .verifying_key()
            .to_bytes();
        let signed = test_binding(&sk, "tunnel-a", b"token-a", 0, 1_000);
        assert_eq!(
            verify_binding(&[other], &signed, b"token-a", 500),
            Err(AgentBindingError::UnknownIssuer)
        );
    }

    #[test]
    fn verify_binding_rejects_a_binding_minted_for_a_different_token() {
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let issuer = sk.verifying_key().to_bytes();
        let signed = test_binding(&sk, "tunnel-a", b"token-a", 0, 1_000);
        assert_eq!(
            verify_binding(&[issuer], &signed, b"token-b", 500),
            Err(AgentBindingError::TokenMismatch)
        );
    }

    #[test]
    fn verify_binding_rejects_at_the_expiry_boundary() {
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let issuer = sk.verifying_key().to_bytes();
        let signed = test_binding(&sk, "tunnel-a", b"token-a", 0, 1_000);
        assert_eq!(
            verify_binding(&[issuer], &signed, b"token-a", 1_000),
            Err(AgentBindingError::Expired)
        );
    }

    #[test]
    fn verify_binding_allows_issued_at_within_skew_and_rejects_just_beyond() {
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let issuer = sk.verifying_key().to_bytes();
        let now = 1_000u64;

        let within = test_binding(
            &sk,
            "tunnel-a",
            b"token-a",
            now + CLOCK_SKEW_SECS,
            now + 10_000,
        );
        assert_eq!(verify_binding(&[issuer], &within, b"token-a", now), Ok(()));

        let beyond = test_binding(
            &sk,
            "tunnel-a",
            b"token-a",
            now + CLOCK_SKEW_SECS + 1,
            now + 10_000,
        );
        assert_eq!(
            verify_binding(&[issuer], &beyond, b"token-a", now),
            Err(AgentBindingError::IssuedInFuture)
        );
    }

    #[test]
    fn verify_registration_accepts_the_bound_agent_key_over_the_challenge() {
        let issuer_sk = SigningKey::from_bytes(&[21u8; 32]);
        let issuer = issuer_sk.verifying_key().to_bytes();
        let agent_sk = SigningKey::from_bytes(&[22u8; 32]);
        let token: &[u8] = b"token-a";
        let nonce = [7u8; 32];

        let binding = AgentBinding {
            tunnel_id: "tunnel-a".into(),
            token_hash: Sha256::digest(token).into(),
            agent_pubkey: agent_sk.verifying_key().to_bytes(),
            issued_at: 0,
            expires_at: 1_000,
        };
        let signed = SignedAgentBinding::mint(&issuer_sk, binding);
        let sig = sign_registration(&agent_sk, &nonce, token);
        assert_eq!(
            verify_registration(&[issuer], &signed, token, &nonce, &sig, 500),
            Ok(())
        );
    }

    #[test]
    fn verify_registration_rejects_a_challenge_signed_by_a_foreign_key() {
        let issuer_sk = SigningKey::from_bytes(&[21u8; 32]);
        let issuer = issuer_sk.verifying_key().to_bytes();
        let agent_sk = SigningKey::from_bytes(&[22u8; 32]);
        let foreign_sk = SigningKey::from_bytes(&[23u8; 32]);
        let token: &[u8] = b"token-a";
        let nonce = [7u8; 32];

        let binding = AgentBinding {
            tunnel_id: "tunnel-a".into(),
            token_hash: Sha256::digest(token).into(),
            agent_pubkey: agent_sk.verifying_key().to_bytes(),
            issued_at: 0,
            expires_at: 1_000,
        };
        let signed = SignedAgentBinding::mint(&issuer_sk, binding);
        let sig = sign_registration(&foreign_sk, &nonce, token);
        assert_eq!(
            verify_registration(&[issuer], &signed, token, &nonce, &sig, 500),
            Err(AgentBindingError::BadSignature)
        );
    }

    #[test]
    fn verify_registration_rejects_a_mismatched_nonce() {
        let issuer_sk = SigningKey::from_bytes(&[21u8; 32]);
        let issuer = issuer_sk.verifying_key().to_bytes();
        let agent_sk = SigningKey::from_bytes(&[22u8; 32]);
        let token: &[u8] = b"token-a";
        let nonce = [7u8; 32];
        let other_nonce = [8u8; 32];

        let binding = AgentBinding {
            tunnel_id: "tunnel-a".into(),
            token_hash: Sha256::digest(token).into(),
            agent_pubkey: agent_sk.verifying_key().to_bytes(),
            issued_at: 0,
            expires_at: 1_000,
        };
        let signed = SignedAgentBinding::mint(&issuer_sk, binding);
        let sig = sign_registration(&agent_sk, &nonce, token);
        assert_eq!(
            verify_registration(&[issuer], &signed, token, &other_nonce, &sig, 500),
            Err(AgentBindingError::BadSignature)
        );
    }

    #[test]
    fn identity_point_is_weak_and_rejected_by_verify_strict() {
        let mut weak_bytes = [0u8; 32];
        weak_bytes[0] = 1;
        let vk =
            VerifyingKey::from_bytes(&weak_bytes).expect("identity point parses as a valid key");
        assert!(vk.is_weak(), "identity point must be flagged as weak");
        let sig = Signature::from_bytes(&[0u8; 64]);
        assert!(
            vk.verify_strict(b"anything", &sig).is_err(),
            "verify_strict must reject a weak key"
        );
    }

    #[test]
    fn verify_binding_rejects_an_issuer_that_is_a_weak_key() {
        let mut weak_bytes = [0u8; 32];
        weak_bytes[0] = 1;
        let binding = AgentBinding {
            tunnel_id: "tunnel-a".into(),
            token_hash: Sha256::digest(b"token-a").into(),
            agent_pubkey: weak_bytes,
            issued_at: 0,
            expires_at: 1_000,
        };
        let signed = SignedAgentBinding {
            binding,
            signature: [0u8; 64],
        };
        assert_eq!(
            verify_binding(&[weak_bytes], &signed, b"token-a", 500),
            Err(AgentBindingError::UnknownIssuer)
        );
    }

    #[test]
    fn encode_decode_roundtrip() {
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let signed = test_binding(&sk, "tunnel-a", b"token-a", 0, 1_000);
        let bytes = signed.encode();
        let back = SignedAgentBinding::decode(&bytes).expect("decode");
        assert_eq!(back, signed);
    }

    #[test]
    fn decode_rejects_oversized_input() {
        let bytes = vec![0u8; MAX_ENCODED_LEN + 1];
        assert_eq!(
            SignedAgentBinding::decode(&bytes),
            Err(AgentBindingError::Malformed)
        );
    }

    #[test]
    fn decode_rejects_a_truncated_section() {
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let signed = test_binding(&sk, "tunnel-a", b"token-a", 0, 1_000);
        let mut bytes = signed.encode();
        bytes.truncate(bytes.len() - 1);
        assert_eq!(
            SignedAgentBinding::decode(&bytes),
            Err(AgentBindingError::Malformed)
        );
    }

    #[test]
    fn credential_signature_does_not_verify_as_a_binding_domain_separation() {
        let sk = SigningKey::from_bytes(&[33u8; 32]);
        let issuer = sk.verifying_key().to_bytes();
        let credential = Credential {
            tenant: TenantId("tenant-1".into()),
            agent: AgentId("agent-1".into()),
            expires_at: 9_999,
        };
        let cred_signature = sk.sign(&credential.signing_bytes()).to_bytes();

        let binding = AgentBinding {
            tunnel_id: "tunnel-a".into(),
            token_hash: Sha256::digest(b"token-a").into(),
            agent_pubkey: issuer,
            issued_at: 0,
            expires_at: 9_999,
        };
        let signed = SignedAgentBinding {
            binding,
            signature: cred_signature,
        };
        assert_eq!(
            verify_binding(&[issuer], &signed, b"token-a", 100),
            Err(AgentBindingError::UnknownIssuer)
        );
    }
}
