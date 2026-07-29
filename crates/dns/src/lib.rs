//! `ct-dns` — a minimal **authoritative DNS for ACME DNS-01**, run as part of the
//! SaaS so Let's Encrypt certificates (the :443 front-door cert #31 FD4, and
//! customer origin certs #23 BP4c) can be issued even though the registrar
//! (Strato) has no usable DNS API. It answers `_acme-challenge.<name> TXT`
//! records that a **localhost-only** HTTP API publishes; the registrar delegates
//! the challenge (CNAME / NS + glue) to this server's `:53`. See ADR-0019.
//!
//! AD1 (this file): the hand-rolled, bounds-checked DNS wire codec (parse a query,
//! build a TXT response) plus the in-memory record store. No sockets/deps yet —
//! the UDP `:53` server and the HTTP API are later sub-packets.

pub mod api;
pub mod client;
pub mod convergence;
pub mod message;
pub mod provider;
pub mod server;
pub mod store;

/// Stable crate identifier.
pub const CRATE_NAME: &str = "ct-dns";
