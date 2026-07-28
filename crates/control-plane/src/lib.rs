//! CADS Tunnel Control Plane — thin, self-hostable-ready coordination:
//! enrollment, Tunnel Registry, Rendezvous, billing. Holds no trust material or
//! payload. See ADR-0005 (enrollment/identity), ADR-0017 (thin control plane).

pub mod accounts;
pub mod billing;
pub mod client;
pub mod credential;
pub mod dns01_challenge;
pub mod edge_mesh;
pub mod enrollment;
pub mod http;
pub mod installer;
pub mod issuance;
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
