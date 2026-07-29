//! Re-export of the shared top-CA registry. Moved to `ct-common`
//! (`ct_common::acme_ca`) so both `ct-agent` and `ct-control-plane` (which
//! cannot depend on `ct-agent` — Cargo forbids the cycle, since `ct-agent`
//! already depends on `ct-control-plane`) share one source of truth for the
//! CA list, rate-limit rationale, and Mesh-Plane-vs-public-CA trust-boundary
//! warning, instead of a second copy drifting out of sync. See
//! [`ct_common::acme_ca`] for the full module documentation.
pub use ct_common::acme_ca::*;
