//! Credential issuance (ADR-0005).
//!
//! The credential claims, wire form, and stateless verification live in
//! [`ct_common::credential`] (shared with the Edge). This module adds the
//! **minting** side — the issuer signing key, which is held only by the control
//! plane.

pub use ct_common::credential::{
    verify_stateless, Credential, CredError, SignedCredential, UnixSeconds,
};

use ed25519_dalek::{Signer, SigningKey};

/// Mints signed credentials. The signing key lives only in the control plane;
/// the Edge only needs [`CredentialIssuer::public_key_bytes`].
pub struct CredentialIssuer {
    signing: SigningKey,
}

impl CredentialIssuer {
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut rand::rngs::OsRng),
        }
    }

    /// The issuer public key the Edge uses to verify credentials.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Mint a signed credential over `credential`'s claims.
    pub fn mint(&self, credential: Credential) -> SignedCredential {
        let signature = self.signing.sign(&credential.signing_bytes()).to_bytes();
        SignedCredential {
            credential,
            signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_common::{AgentId, TenantId};

    fn cred(expires_at: UnixSeconds) -> Credential {
        Credential {
            tenant: TenantId("tenant-1".into()),
            agent: AgentId("agent-1".into()),
            expires_at,
        }
    }

    #[test]
    fn mint_then_verify_ok_before_expiry() {
        let issuer = CredentialIssuer::generate();
        let signed = issuer.mint(cred(1_000));
        assert_eq!(verify_stateless(&issuer.public_key_bytes(), &signed, 999), Ok(()));
    }

    #[test]
    fn expired_credential_rejected() {
        let issuer = CredentialIssuer::generate();
        let signed = issuer.mint(cred(1_000));
        assert_eq!(
            verify_stateless(&issuer.public_key_bytes(), &signed, 1_000),
            Err(CredError::Expired)
        );
    }

    #[test]
    fn wrong_issuer_rejected() {
        let issuer = CredentialIssuer::generate();
        let other = CredentialIssuer::generate();
        let signed = issuer.mint(cred(1_000));
        assert_eq!(
            verify_stateless(&other.public_key_bytes(), &signed, 500),
            Err(CredError::BadSignature)
        );
    }
}
