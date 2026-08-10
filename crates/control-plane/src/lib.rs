//! CADS Tunnel Control Plane — thin, self-hostable-ready coordination:
//! enrollment, Tunnel Registry, Rendezvous, billing. Holds no Agent/CA private
//! keys and never sees payload — but is not trust-material-free (#266): it
//! holds the credential-issuer signing key ([`credential::CredentialIssuer`],
//! currently unwired, #260), per-CA EAB credentials ([`acme_broker`]), and any
//! configured DNS-provider token ([`dns01_challenge`]) — operator secrets that
//! need the same protection/rotation care as any other. See ADR-0005
//! (enrollment/identity), ADR-0017 (thin control plane).

pub mod accounts;
pub mod acme_broker;
pub mod billing;
pub mod client;
pub mod credential;
pub mod dns01_challenge;
pub mod edge_mesh;
pub mod enrollment;
pub mod gate;
/// #438: real test scaffolding (M13.1's in-memory, unauthenticated router) that
/// otherwise read as shipping API -- gated out of every real build. Reachable from
/// this crate's own tests via `cfg(test)`; a dependent crate's tests enable
/// `test-support` on its dev-dependency to reach it too (see `ct-client`'s
/// `rendezvous.rs`).
#[cfg(any(test, feature = "test-support"))]
pub mod http;
pub mod installer;
pub mod issuance;
pub mod keycloak_admin;
pub mod oidc;
pub mod payment;
pub mod portal;
pub mod portal_api;
pub mod payment_provider;
pub mod registry;
pub mod service;
pub mod storage;
pub mod topology;

/// Stable crate identifier, used by the P0.1 smoke test.
pub const CRATE_NAME: &str = "ct-control-plane";

#[cfg(test)]
mod tests {
    #[test]
    fn depends_on_common() {
        assert_eq!(ct_common::CRATE_NAME, "ct-common");
        assert_eq!(super::CRATE_NAME, "ct-control-plane");
    }
}
