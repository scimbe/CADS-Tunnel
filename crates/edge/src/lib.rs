//! CADS Tunnel Edge — operator-run, public. Coordinates Rendezvous and relays
//! ciphertext only as fallback; never in the trust path. See ADR-0004/0015.

pub mod admin;
pub mod auth;
pub mod channel_authorize;
pub mod channel_broker;
pub mod config;
pub mod edge_mesh_client;
pub mod observe;
pub mod pki;
pub mod relay;
pub mod relay_gate;
pub mod rendezvous;
pub mod serve;
pub mod sni;
pub mod state;
pub mod transport;

/// Stable crate identifier, used by the P0.1 smoke test.
pub const CRATE_NAME: &str = "ct-edge";

#[cfg(test)]
mod tests {
    #[test]
    fn depends_on_common() {
        assert_eq!(ct_common::CRATE_NAME, "ct-common");
        assert_eq!(super::CRATE_NAME, "ct-edge");
    }
}
