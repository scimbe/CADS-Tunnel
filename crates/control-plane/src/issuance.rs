//! Enrollment-gated credential minting (ADR-0005).
//!
//! P1.4b: the control plane mints a short-lived credential for an Agent only if
//! it is enrolled (its public key is bound to a Tenant). This is the "minted
//! from that identity" gate — an unenrolled Agent cannot obtain a credential.

use ct_common::AgentId;

use crate::credential::{Credential, CredentialIssuer, SignedCredential, UnixSeconds};
use crate::enrollment::Enrollment;

/// Why minting was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum MintError {
    /// The Agent has no enrollment binding, so no credential may be minted.
    NotEnrolled,
}

impl std::fmt::Display for MintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MintError::NotEnrolled => write!(f, "agent is not enrolled"),
        }
    }
}

impl std::error::Error for MintError {}

/// Mint a short-lived credential for `agent`, but only if it is enrolled. The
/// credential's Tenant is taken from the enrollment binding, not from the caller.
pub fn mint_for_enrolled(
    issuer: &CredentialIssuer,
    enrollment: &Enrollment,
    agent: &AgentId,
    expires_at: UnixSeconds,
) -> Result<SignedCredential, MintError> {
    let (tenant, _pubkey) = enrollment.binding(agent).ok_or(MintError::NotEnrolled)?;
    let credential = Credential {
        tenant: tenant.clone(),
        agent: agent.clone(),
        expires_at,
    };
    Ok(issuer.mint(credential))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::verify_stateless;
    use ct_common::TenantId;

    #[test]
    fn mints_for_enrolled_agent() {
        let issuer = CredentialIssuer::generate();
        let mut enrollment = Enrollment::new();
        let tenant = TenantId("tenant-1".into());
        let token = enrollment.issue_join_token(tenant.clone());
        let agent = AgentId("agent-1".into());
        enrollment.redeem(&token, agent.clone(), [5u8; 32]).unwrap();

        let signed = mint_for_enrolled(&issuer, &enrollment, &agent, 1_000).expect("mint");
        assert_eq!(signed.credential.tenant, tenant);
        assert_eq!(signed.credential.agent, agent);
        assert_eq!(verify_stateless(&issuer.public_key_bytes(), &signed, 500), Ok(()));
    }

    #[test]
    fn rejects_unenrolled_agent() {
        let issuer = CredentialIssuer::generate();
        let enrollment = Enrollment::new();
        let result = mint_for_enrolled(&issuer, &enrollment, &AgentId("nope".into()), 1_000);
        assert_eq!(result, Err(MintError::NotEnrolled));
    }
}
