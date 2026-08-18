//! CADS Tunnel Client (Mesh Plane).
//!
//! Imports a Capability, performs PoW-gated rendezvous with the Edge, and reaches
//! the Origin over Noise E2E (ADR-0013; the Noise session is P3). M5.3a provides
//! the dial + rendezvous; the data path to the Origin is M5.3b.

pub mod bench;
pub mod config;
pub mod ladder;
pub mod noise;
pub mod transport;

/// Stable crate identifier.
pub const CRATE_NAME: &str = "ct-client";
