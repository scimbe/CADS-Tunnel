//! Short-lived credential wire type and verification (ADR-0005).
//!
//! Shared by the control plane (which mints via its `CredentialIssuer`) and the
//! Edge (which verifies presented credentials). The issuer signing key lives
//! only in the control plane; this module holds the claims, the wire form, and
//! the stateless verification. Time is caller-supplied so this stays
//! deterministic and wall-clock-free.

use crate::{AgentId, TenantId};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Unix timestamp in whole seconds, supplied by the caller.
pub type UnixSeconds = u64;

/// The claims of a short-lived credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub tenant: TenantId,
    pub agent: AgentId,
    pub expires_at: UnixSeconds,
}

impl Credential {
    /// Canonical bytes covered by the issuer signature.
    ///
    /// #249: previously a raw `format!("ct-cred:v1|{tenant}|{agent}|{expires_at}")` with an
    /// unescaped `|` separator — two distinct `(tenant, agent)` pairs could serialize identically
    /// (e.g. `tenant="a|b", agent="c"` vs `tenant="a", agent="b|c"`, both `TenantId`/`AgentId` being
    /// unvalidated `String`s), so an issuer signature over one verified as valid over the other —
    /// real identity confusion. [`crate::preimage::Preimage`]'s `var_bytes` length-prefixes each
    /// field, so no byte content in `tenant`/`agent` can shift the field boundary; this is a wire
    /// format change (any credential signed under the old scheme no longer verifies), acceptable
    /// since credentials are explicitly short-lived (see module docs).
    pub fn signing_bytes(&self) -> Vec<u8> {
        crate::preimage::Preimage::new(b"ct-cred:v1")
            .var_bytes(self.tenant.0.as_bytes())
            .var_bytes(self.agent.0.as_bytes())
            .u64(self.expires_at)
            .finish()
    }
}

/// A credential together with the issuer's signature over its claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCredential {
    pub credential: Credential,
    pub signature: [u8; 64],
}

/// Why credential verification or decoding failed.
#[derive(Debug, PartialEq, Eq)]
pub enum CredError {
    BadSignature,
    Expired,
    BadKey,
    /// The wire bytes were not a well-formed credential.
    Malformed,
    /// A previously-accepted credential was presented again before its expiry
    /// (#88 SEC88b) — rejected by the replay cache in [`verify_fresh`].
    Replayed,
}

impl std::fmt::Display for CredError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredError::BadSignature => write!(f, "credential signature invalid"),
            CredError::Expired => write!(f, "credential expired"),
            CredError::BadKey => write!(f, "issuer public key invalid"),
            CredError::Malformed => write!(f, "credential bytes malformed"),
            CredError::Replayed => write!(f, "credential replayed"),
        }
    }
}

impl std::error::Error for CredError {}

impl SignedCredential {
    /// Encode to a self-describing binary wire form:
    /// `signature(64) | tenant_len(u32 LE) | tenant | agent_len(u32 LE) | agent | expires_at(u64 LE)`.
    /// (`[u8; 64]` is hand-encoded because serde does not derive arrays > 32.)
    pub fn encode(&self) -> Vec<u8> {
        let c = &self.credential;
        let tenant = c.tenant.0.as_bytes();
        let agent = c.agent.0.as_bytes();
        let mut out = Vec::with_capacity(64 + 8 + tenant.len() + agent.len() + 8);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&(tenant.len() as u32).to_le_bytes());
        out.extend_from_slice(tenant);
        out.extend_from_slice(&(agent.len() as u32).to_le_bytes());
        out.extend_from_slice(agent);
        out.extend_from_slice(&c.expires_at.to_le_bytes());
        out
    }

    /// Decode from [`SignedCredential::encode`]'s wire form.
    pub fn decode(bytes: &[u8]) -> Result<Self, CredError> {
        fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8], CredError> {
            if cur.len() < n {
                return Err(CredError::Malformed);
            }
            let (head, tail) = cur.split_at(n);
            *cur = tail;
            Ok(head)
        }

        let mut cur = bytes;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(take(&mut cur, 64)?);

        let tenant_len = u32::from_le_bytes(take(&mut cur, 4)?.try_into().unwrap()) as usize;
        let tenant = String::from_utf8(take(&mut cur, tenant_len)?.to_vec())
            .map_err(|_| CredError::Malformed)?;
        let agent_len = u32::from_le_bytes(take(&mut cur, 4)?.try_into().unwrap()) as usize;
        let agent = String::from_utf8(take(&mut cur, agent_len)?.to_vec())
            .map_err(|_| CredError::Malformed)?;
        let expires_at = u64::from_le_bytes(take(&mut cur, 8)?.try_into().unwrap());

        if !cur.is_empty() {
            return Err(CredError::Malformed);
        }
        Ok(SignedCredential {
            credential: Credential {
                tenant: TenantId(tenant),
                agent: AgentId(agent),
                expires_at,
            },
            signature,
        })
    }
}

/// Verify a signed credential against `issuer_pubkey` at time `now` — signature and
/// expiry only, with **no replay protection** (#415): a captured credential verifies
/// successfully *every* time it is presented, until it expires. The name is explicit
/// about that tradeoff so it reads as a deliberate choice at the call site rather than
/// an oversight next to [`verify_fresh`] — this and `verify_fresh` have identical
/// signatures apart from the cache, so picking the wrong one for a new bearer-style
/// admission path would otherwise silently drop replay protection with nothing to
/// flag it. Prefer [`verify_fresh`] for any *new* admission point; use this one only
/// where the caller already has its own independent replay/possession defense (e.g.
/// the Edge's grant admission pairs [`crate::channel::verify_stateless`] with a
/// fresh-challenge holder-possession proof, which is strictly stronger than a
/// seen-nonce cache) or is deliberately stateless for a documented reason.
pub fn verify_stateless(
    issuer_pubkey: &[u8; 32],
    signed: &SignedCredential,
    now: UnixSeconds,
) -> Result<(), CredError> {
    let vk = VerifyingKey::from_bytes(issuer_pubkey).map_err(|_| CredError::BadKey)?;
    let sig = Signature::from_bytes(&signed.signature);
    vk.verify(&signed.credential.signing_bytes(), &sig)
        .map_err(|_| CredError::BadSignature)?;
    if now >= signed.credential.expires_at {
        return Err(CredError::Expired);
    }
    Ok(())
}

/// Like [`verify_stateless`], but additionally rejects a **replay** (#88 SEC88b). A
/// captured credential is otherwise valid until `expires_at` *any number of times*;
/// `cache` records the credential's 64-byte signature (unique per token — a replay
/// carries the identical bytes) until that expiry, so the first presentation of a
/// valid, unexpired credential succeeds and any later presentation of the same
/// signature fails with [`CredError::Replayed`]. Call this at the single admission
/// point that owns `cache`; the cache evicts on expiry so it stays bounded.
/// Signature/expiry are checked first, so an invalid or expired credential never
/// populates the cache.
///
/// #581: currently unused, deliberately — checked, not assumed. `SignedCredential` is
/// minted (`control-plane`'s `credential.rs`/`issuance.rs`) but not currently
/// *presented and verified* anywhere in either workspace; only the more specific
/// `SignedChannelGrant` (`crate::channel`) is live, and its own `verify_fresh`
/// sibling carries the equivalent reasoning for why it too is unused without being
/// forgotten. If a live consumer of `SignedCredential` is ever wired up, call this
/// instead of `verify_stateless` there.
pub fn verify_fresh(
    issuer_pubkey: &[u8; 32],
    signed: &SignedCredential,
    now: UnixSeconds,
    cache: &mut crate::replay::ReplayCache,
) -> Result<(), CredError> {
    verify_stateless(issuer_pubkey, signed, now)?;
    if !cache.check_and_record(&signed.signature, signed.credential.expires_at, now) {
        return Err(CredError::Replayed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Sign a credential with a deterministic key (no rng needed in tests).
    fn signed_cred(expires_at: UnixSeconds) -> ([u8; 32], SignedCredential) {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let credential = Credential {
            tenant: TenantId("tenant-1".into()),
            agent: AgentId("agent-1".into()),
            expires_at,
        };
        let signature = sk.sign(&credential.signing_bytes()).to_bytes();
        (
            sk.verifying_key().to_bytes(),
            SignedCredential {
                credential,
                signature,
            },
        )
    }

    #[test]
    fn signing_bytes_is_injective_across_a_shifted_tenant_agent_boundary() {
        // #249: the old `format!("ct-cred:v1|{tenant}|{agent}|{expires_at}")` let a `|` inside
        // tenant/agent shift the field boundary -- tenant="a|b",agent="c" and tenant="a",agent="b|c"
        // both serialized to the same bytes, so a signature over one verified as valid over the
        // other. Length-prefixed encoding must keep these two distinct.
        let a = Credential { tenant: TenantId("a|b".into()), agent: AgentId("c".into()), expires_at: 100 };
        let b = Credential { tenant: TenantId("a".into()), agent: AgentId("b|c".into()), expires_at: 100 };
        assert_ne!(a.signing_bytes(), b.signing_bytes(), "shifted tenant/agent boundary must not collide");

        // A signature over A must not verify as a signature over B.
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let sig_a = sk.sign(&a.signing_bytes());
        let signed_as_b = SignedCredential { credential: b, signature: sig_a.to_bytes() };
        assert_eq!(verify_stateless(&pk, &signed_as_b, 50), Err(CredError::BadSignature));
    }

    #[test]
    fn verify_ok_before_expiry() {
        let (pk, signed) = signed_cred(1_000);
        assert_eq!(verify_stateless(&pk, &signed, 999), Ok(()));
    }

    #[test]
    fn verify_rejects_expired() {
        let (pk, signed) = signed_cred(1_000);
        assert_eq!(verify_stateless(&pk, &signed, 1_000), Err(CredError::Expired));
    }

    #[test]
    fn verify_rejects_tampered_claims() {
        let (pk, mut signed) = signed_cred(1_000);
        signed.credential.expires_at = 9_999;
        assert_eq!(verify_stateless(&pk, &signed, 500), Err(CredError::BadSignature));
    }

    #[test]
    fn verify_fresh_admits_once_then_rejects_the_replay() {
        // #88 SEC88b: a valid, unexpired credential is admitted the first time and
        // rejected as a replay thereafter; an expired credential is rejected on
        // expiry and never cached (so it can't consume a slot or mask itself).
        use crate::replay::ReplayCache;
        let (pk, signed) = signed_cred(1_000);
        let mut cache = ReplayCache::new();

        assert_eq!(verify_fresh(&pk, &signed, 500, &mut cache), Ok(()), "first use admitted");
        assert_eq!(
            verify_fresh(&pk, &signed, 700, &mut cache),
            Err(CredError::Replayed),
            "the same credential again is a replay"
        );

        // An expired credential is rejected on expiry, not by the cache.
        let (pk2, expired) = signed_cred(1_000);
        assert_eq!(
            verify_fresh(&pk2, &expired, 1_000, &mut cache),
            Err(CredError::Expired),
            "an expired credential is rejected before the cache"
        );
    }

    #[test]
    fn encode_decode_roundtrip() {
        let (_pk, signed) = signed_cred(1_234);
        let bytes = signed.encode();
        let back = SignedCredential::decode(&bytes).expect("decode");
        assert_eq!(back, signed);
    }

    #[test]
    fn decode_rejects_truncated() {
        assert_eq!(SignedCredential::decode(&[0u8; 10]), Err(CredError::Malformed));
    }

    #[test]
    fn decode_rejects_trailing_garbage() {
        let (_pk, signed) = signed_cred(1_234);
        let mut bytes = signed.encode();
        bytes.push(0xff);
        assert_eq!(SignedCredential::decode(&bytes), Err(CredError::Malformed));
    }
}
