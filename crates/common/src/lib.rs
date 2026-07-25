//! Shared wire types for Claude Tunnel (P0.2).
//!
//! Logic-free and serde-serializable. Terms follow `CONTEXT.md`; see ADR-0013
//! (Origin Identity) and ADR-0014 (Capability). This crate must not depend on
//! `ct-agent` or `ct-edge`.

use serde::{Deserialize, Serialize};

pub mod a2a;
pub mod channel;
pub mod credential;
pub mod crew;
pub mod mcp;
pub mod metrics;
pub mod noise;
pub mod overlay;
pub mod pipeline;
pub mod policy;
pub mod pow;
pub mod ratelimit;
pub mod replay;
pub mod settlement;
pub mod sync;
pub mod upgrade;

/// Stable crate identifier, used by downstream smoke tests.
pub const CRATE_NAME: &str = "ct-common";

/// The customer account that owns Agents, hostnames, and Tunnels; the unit of
/// authorization and isolation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(pub String);

/// A single Agent's stable identifier within a Tenant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub String);

/// Opaque identifier that addresses a Tunnel in the Mesh Plane; routes a Client
/// to the right Agent without revealing a hostname to the operator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RoutingToken(pub [u8; 32]);

/// The Origin's static Noise public key, pinned by Clients to authenticate the
/// Origin end-to-end.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OriginIdentity(pub [u8; 32]);

/// Self-contained connection grant the customer distributes out of band
/// (ADR-0014): possession is sufficient to reach and authenticate an Origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub token: RoutingToken,
    pub origin: OriginIdentity,
    pub edge_addr: String,
}

/// A Capability's wire bytes were not well-formed.
#[derive(Debug, PartialEq, Eq)]
pub struct MalformedCapability;

impl std::fmt::Display for MalformedCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "malformed capability bytes")
    }
}

impl std::error::Error for MalformedCapability {}

impl Capability {
    /// Encode to a portable binary form for out-of-band distribution:
    /// `token(32) | origin(32) | addr_len(u32 LE) | addr`.
    pub fn encode(&self) -> Vec<u8> {
        let addr = self.edge_addr.as_bytes();
        let mut out = Vec::with_capacity(32 + 32 + 4 + addr.len());
        out.extend_from_slice(&self.token.0);
        out.extend_from_slice(&self.origin.0);
        out.extend_from_slice(&(addr.len() as u32).to_le_bytes());
        out.extend_from_slice(addr);
        out
    }

    /// Import a Capability from [`Capability::encode`]'s wire form.
    pub fn decode(bytes: &[u8]) -> Result<Capability, MalformedCapability> {
        if bytes.len() < 68 {
            return Err(MalformedCapability);
        }
        let mut token = [0u8; 32];
        token.copy_from_slice(&bytes[0..32]);
        let mut origin = [0u8; 32];
        origin.copy_from_slice(&bytes[32..64]);
        let addr_len = u32::from_le_bytes(bytes[64..68].try_into().unwrap()) as usize;
        if bytes.len() != 68 + addr_len {
            return Err(MalformedCapability);
        }
        let edge_addr =
            String::from_utf8(bytes[68..68 + addr_len].to_vec()).map_err(|_| MalformedCapability)?;
        Ok(Capability {
            token: RoutingToken(token),
            origin: OriginIdentity(origin),
            edge_addr,
        })
    }
}

/// Minimal control-plane framing for the Mesh Plane. Logic-free; variants gain
/// fields as the transport (P1.x) and rendezvous (P1.1) packets land.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlFrame {
    /// Client asks the Edge to rendezvous with the Agent holding `token`.
    RendezvousRequest { token: RoutingToken },
    /// Edge acknowledges with opaque rendezvous coordination bytes.
    RendezvousAccept { coordination: Vec<u8> },
    /// Opaque ciphertext relayed on the fallback path (never decrypted by Edge).
    Relay { payload: Vec<u8> },
}

/// Normalize + validate a DNS hostname for Browser-Plane routing (#23 BP4b-d):
/// trim, strip a single trailing dot, lowercase, and validate the DNS charset and
/// label/length limits (RFC 1123). Returns the canonical form, or `None` if
/// invalid. Applied consistently at the edge (bind / lookup / authorize) and the
/// control plane (create) so `victim.com.` and `victim.com` can't be distinct
/// keys and non-DNS junk never enters the routing table. (Unicode must be
/// punycode-encoded by the caller; `xn--…` labels pass.)
pub fn normalize_hostname(s: &str) -> Option<String> {
    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() || s.len() > 253 {
        return None;
    }
    for label in s.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return None;
        }
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_hostname_canonicalizes_and_validates() {
        // Lowercase + trailing-dot strip; `x.` and `x` collapse.
        assert_eq!(
            normalize_hostname("Help.Bunsenbrenner.ORG."),
            Some("help.bunsenbrenner.org".to_string())
        );
        assert_eq!(normalize_hostname("victim.com."), normalize_hostname("victim.com"));
        assert_eq!(normalize_hostname("xn--nxasmq6b.example"), Some("xn--nxasmq6b.example".into()));
        // Rejects: empty, bad chars, empty/over-long label, leading/trailing hyphen.
        assert!(normalize_hostname("").is_none());
        assert!(normalize_hostname("a b.com").is_none(), "space");
        assert!(normalize_hostname("under_score.com").is_none(), "underscore not a DNS host char");
        assert!(normalize_hostname("a..b").is_none(), "empty label");
        assert!(normalize_hostname("-lead.com").is_none());
        assert!(normalize_hostname("trail-.com").is_none());
        assert!(normalize_hostname(&format!("{}.com", "a".repeat(64))).is_none(), "label too long");
    }

    fn roundtrip<T>(v: &T)
    where
        T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
    {
        let json = serde_json::to_string(v).expect("serialize");
        let back: T = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(v, &back, "round-trip mismatch for {json}");
    }

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(CRATE_NAME, "ct-common");
    }

    #[test]
    fn roundtrip_ids() {
        roundtrip(&TenantId("tenant-1".into()));
        roundtrip(&AgentId("agent-1".into()));
    }

    #[test]
    fn roundtrip_keys_and_tokens() {
        roundtrip(&RoutingToken([7u8; 32]));
        roundtrip(&OriginIdentity([9u8; 32]));
    }

    #[test]
    fn roundtrip_capability() {
        roundtrip(&Capability {
            token: RoutingToken([1u8; 32]),
            origin: OriginIdentity([2u8; 32]),
            edge_addr: "edge.example:443".into(),
        });
    }

    #[test]
    fn capability_encode_decode_roundtrip() {
        let cap = Capability {
            token: RoutingToken([5u8; 32]),
            origin: OriginIdentity([6u8; 32]),
            edge_addr: "edge.example:443".into(),
        };
        let bytes = cap.encode();
        assert_eq!(Capability::decode(&bytes), Ok(cap));
    }

    #[test]
    fn capability_decode_rejects_truncated() {
        assert_eq!(Capability::decode(&[0u8; 10]), Err(MalformedCapability));
    }

    #[test]
    fn roundtrip_control_frames() {
        roundtrip(&ControlFrame::RendezvousRequest {
            token: RoutingToken([3u8; 32]),
        });
        roundtrip(&ControlFrame::RendezvousAccept {
            coordination: vec![1, 2, 3],
        });
        roundtrip(&ControlFrame::Relay {
            payload: vec![9, 9, 9],
        });
    }
}
