//! Workflow-pipeline convening (maintainer vision, 2026-07-25).
//!
//! > *"Someone designs a workflow-pipeline and publishes the needed agent profiles online, with
//! > the information about the network of the workflow pipeline. Agents scan the offers and the
//! > pipeline and connect to a pipeline network; the pipeline arranges, then runs the auction. If
//! > not enough agents are online for an auction, the protocol raises an error for the workflow
//! > pipeline."*
//!
//! This is the protocol core of that idea, generalizing the flappy-demo crew (#171) into a
//! first-class concept. A [`PipelineSpec`] declares the ROLES a workflow needs — each a required
//! [`ServiceType`] and a units amount. Agents publish [`CapacityOffer`]s declaring the services
//! they serve (#149-A.1/#167). [`PipelineSpec::convene`] discovers the currently-online offers and
//! runs a **per-role auction**; if any required role has **no matchable offer online**, convening
//! fails with [`PipelineError::UnfilledRole`] — the protocol raises an error rather than
//! half-arranging a workflow it cannot actually run.
//!
//! This module is pure/offer-matching only: it does not itself do discovery (that is
//! `/registry/agents` + the published spec) or the channel wiring (the crew bridge, #171 c2/c3);
//! it decides, given the offers a discovery pass found, whether the pipeline can convene and who
//! wins each role.

use crate::channel::{CapacityOffer, ServiceType, UnixSeconds};
use serde::{Deserialize, Serialize};

/// One role a pipeline requires: the service the role performs, and the units the workflow needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequiredRole {
    pub service: ServiceType,
    pub units: u64,
}

/// A workflow-pipeline spec — the roles that must ALL be filled for the pipeline to run. This is
/// the "needed agent profiles + network info" a designer publishes for agents to scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineSpec {
    pub id: String,
    pub roles: Vec<RequiredRole>,
}

/// Why a pipeline could not convene.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineError {
    /// A required role had no valid, online offer declaring its service with enough units — the
    /// workflow cannot run, so the protocol raises this rather than proceeding underfilled.
    UnfilledRole { service: ServiceType },
    /// The spec declares no roles (nothing to convene).
    Empty,
}

impl core::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PipelineError::UnfilledRole { service } => {
                write!(f, "workflow pipeline cannot convene: no online agent offers the {service:?} role")
            }
            PipelineError::Empty => write!(f, "workflow pipeline declares no roles"),
        }
    }
}
impl std::error::Error for PipelineError {}

/// The offer that won one role's auction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleAssignment {
    pub service: ServiceType,
    /// The winning offer's holder public key (the provider agent).
    pub provider: [u8; 32],
    /// The units the pipeline reserves from the role.
    pub units: u64,
    /// The winning offer's floor (`min_price`) — the cleared price for this role.
    pub price: u64,
}

impl PipelineSpec {
    /// Convene the pipeline against the currently-online `offers`. Runs a per-role auction and
    /// returns the winning [`RoleAssignment`] for **every** role, or the first
    /// [`PipelineError::UnfilledRole`] if any role has no matchable offer online.
    ///
    /// An offer fills a role iff it (a) [`is_valid`](CapacityOffer::is_valid) at `now`
    /// (signature + not expired), (b) its declared `services` contains the role's service (the
    /// #167 opt-in catalog — a generic empty-services offer never fills a role), and (c) it
    /// advertises at least the units the role needs. Among qualifying offers the winner is the
    /// one with the **lowest floor** (`min_price`, cheapest for the buyer), ties broken by holder
    /// key for determinism.
    pub fn convene(
        &self,
        offers: &[CapacityOffer],
        now: UnixSeconds,
    ) -> Result<Vec<RoleAssignment>, PipelineError> {
        if self.roles.is_empty() {
            return Err(PipelineError::Empty);
        }
        let mut assignments = Vec::with_capacity(self.roles.len());
        for role in &self.roles {
            let winner = offers
                .iter()
                .filter(|o| {
                    o.is_valid(now)
                        && o.services.contains(&role.service)
                        && o.units_available >= role.units
                })
                .min_by(|a, b| {
                    a.min_price
                        .cmp(&b.min_price)
                        .then_with(|| a.holder_pubkey.cmp(&b.holder_pubkey))
                });
            match winner {
                Some(o) => assignments.push(RoleAssignment {
                    service: role.service,
                    provider: o.holder_pubkey,
                    units: role.units,
                    price: o.min_price,
                }),
                None => return Err(PipelineError::UnfilledRole { service: role.service }),
            }
        }
        Ok(assignments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{CapacityKind, ServiceType::*};
    use ed25519_dalek::SigningKey;

    fn offer(seed: u8, services: Vec<ServiceType>, units: u64, price: u64, expires: UnixSeconds) -> CapacityOffer {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        CapacityOffer::sign_new_with_services(
            &sk, CapacityKind::CloudApiQuota, vec!["m".into()], units, price, "cur".into(), 0, expires, services,
        )
    }
    fn holder(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes()
    }

    #[test]
    fn pipeline_convenes_only_when_every_role_has_an_online_offer() {
        // Maintainer vision (frozen): a pipeline auctions each declared role and RAISES an error if
        // a role can't be filled by an online offer — never half-arranges.
        let spec = PipelineSpec {
            id: "flappy".into(),
            roles: vec![
                RequiredRole { service: SafetyCheck, units: 5 },
                RequiredRole { service: CodeGeneration, units: 10 },
            ],
        };
        // Two agents online: #1 offers SafetyCheck, #2 offers CodeGeneration — both roles fillable.
        let safety = offer(1, vec![SafetyCheck], 20, 50, 1000);
        let codegen = offer(2, vec![CodeGeneration], 20, 40, 1000);
        let a = spec.convene(&[safety.clone(), codegen.clone()], 100).expect("both roles online → convenes");
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].service, SafetyCheck);
        assert_eq!(a[0].provider, holder(1));
        assert_eq!(a[1].service, CodeGeneration);
        assert_eq!(a[1].provider, holder(2));

        // Take the CodeGeneration agent offline → the protocol raises UnfilledRole, not a partial run.
        assert_eq!(
            spec.convene(&[safety.clone()], 100),
            Err(PipelineError::UnfilledRole { service: CodeGeneration }),
            "a role with no online offer fails the whole convene"
        );

        // Auction: two CodeGeneration bidders → the LOWER floor (cheaper for the buyer) wins.
        let cheap = offer(3, vec![CodeGeneration], 20, 25, 1000);
        let a2 = spec.convene(&[safety.clone(), codegen.clone(), cheap.clone()], 100).unwrap();
        assert_eq!(a2[1].provider, holder(3), "lowest min_price wins the role auction");
        assert_eq!(a2[1].price, 25);

        // An offer that DOESN'T declare the service can't fill the role (generic offer opts out).
        let generic = offer(4, vec![], 999, 1, 1000); // declares nothing, huge units, cheapest
        assert_eq!(
            spec.convene(&[generic.clone(), codegen.clone()], 100),
            Err(PipelineError::UnfilledRole { service: SafetyCheck }),
            "a generic (no-services) offer never fills a declared role"
        );

        // Too few units → doesn't qualify → role unfilled.
        let tiny = offer(5, vec![SafetyCheck], 3, 10, 1000); // only 3 units, role needs 5
        assert_eq!(
            spec.convene(&[tiny, codegen.clone()], 100),
            Err(PipelineError::UnfilledRole { service: SafetyCheck }),
            "an offer without enough units doesn't fill the role"
        );

        // Expired offer (not is_valid at `now`) → role unfilled.
        let expired = offer(6, vec![SafetyCheck], 20, 10, 50); // expires_at 50, now 100
        assert_eq!(
            spec.convene(&[expired, codegen], 100),
            Err(PipelineError::UnfilledRole { service: SafetyCheck }),
            "an expired offer doesn't fill the role"
        );

        // An empty spec convenes nothing.
        assert_eq!(
            PipelineSpec { id: "e".into(), roles: vec![] }.convene(&[safety], 100),
            Err(PipelineError::Empty),
        );
    }
}
