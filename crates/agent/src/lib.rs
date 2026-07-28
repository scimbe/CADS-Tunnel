//! CADS Tunnel Agent — customer-run, outbound-only. Custodian of the Origin
//! key; mints Capabilities. See ADR-0004 (transport), ADR-0005 (identity).

pub mod acme;
pub mod acme_client;
pub mod acme_jws;
pub mod acme_orchestrate;
pub mod capability;
pub mod channel;
pub mod channel_run;
pub mod config;
pub mod dns01_authoritative;
pub mod dns01_propagation;
pub mod ladder;
pub mod identity;
pub mod observe;
pub mod onboard;
pub mod origin;
pub mod p2p;
pub mod reconnect;
pub mod serve;
pub mod transport;
pub mod well_known;

/// Stable crate identifier, used by the P0.1 smoke test.
pub const CRATE_NAME: &str = "ct-agent";

#[cfg(test)]
mod tests {
    #[test]
    fn depends_on_common() {
        assert_eq!(ct_common::CRATE_NAME, "ct-common");
        assert_eq!(super::CRATE_NAME, "ct-agent");
    }
}
