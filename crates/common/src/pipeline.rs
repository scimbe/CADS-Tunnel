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

use crate::channel::{AgentCard, CapacityOffer, ChannelId, ServiceType, UnixSeconds};
use serde::{Deserialize, Serialize};

/// One role a pipeline requires. The `service` is the [`ServiceType`] the role's capacity
/// [`CapacityOffer`] must declare (the auction/offer dimension); the `tag` is the human role name
/// agents advertise in their [`AgentCard::role_tags`] (the invite-by-card dimension). The two are
/// distinct on purpose — an offer says *what task-type it serves*, a card says *what role the agent
/// plays* — so a pipeline can both auction offers AND invite by card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequiredRole {
    pub service: ServiceType,
    pub units: u64,
    /// The role tag agents advertise on their `AgentCard` for this role (e.g. `"physics"`).
    pub tag: String,
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

/// An agent the pipeline can invite for a role (the PUSH path), with the channels its card
/// advertises it is reachable via.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteCandidate {
    pub holder: [u8; 32],
    pub channels: Vec<ChannelId>,
}

/// The invite list for one role: the valid agents whose card advertises the role's tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleInvitation {
    pub service: ServiceType,
    pub tag: String,
    pub candidates: Vec<InviteCandidate>,
}

impl PipelineSpec {
    /// The **invite-by-card** (PUSH) discovery mode: given the [`AgentCard`]s a discovery pass found
    /// (`/registry/agents`, #144), return per role the valid agents whose card advertises that role
    /// (`role_tags` contains the role's `tag`) — the agents the pipeline can **invite** over their
    /// advertised `channels`, rather than waiting for them to find the job. A role whose
    /// `candidates` is empty has no invitable agent (the same underfilled signal
    /// [`convene`](Self::convene) raises for offers, surfaced at discovery time). Only
    /// [`is_valid`](AgentCard::is_valid) cards (signature + not expired) are considered — an expired
    /// or forged card can't get its holder invited.
    pub fn invitations(&self, cards: &[AgentCard], now: UnixSeconds) -> Vec<RoleInvitation> {
        self.roles
            .iter()
            .map(|role| {
                let candidates = cards
                    .iter()
                    .filter(|c| c.is_valid(now) && c.role_tags.iter().any(|t| t == &role.tag))
                    .map(|c| InviteCandidate { holder: c.holder_pubkey, channels: c.channels.clone() })
                    .collect();
                RoleInvitation { service: role.service, tag: role.tag.clone(), candidates }
            })
            .collect()
    }

    /// Convene the pipeline against the currently-online `offers`. Runs a per-role auction and
    /// returns the winning [`RoleAssignment`] for **every** role, or the first
    /// [`PipelineError::UnfilledRole`] if any role has no matchable offer online.
    ///
    /// An offer fills a role iff it (a) [`is_valid`](CapacityOffer::is_valid) at `now`
    /// (signature + not expired), (b) its declared `services` contains the role's service (the
    /// #167 opt-in catalog — a generic empty-services offer never fills a role), and (c) it
    /// advertises at least the units the role needs. Among qualifying offers the winner is the
    /// one with the **lowest floor** (`min_price`, cheapest for the buyer), ties broken by holder
    /// key for determinism. A provider wins **at most one** role per convene (#172 cross-role
    /// exclusivity), so N roles sharing a `ServiceType` require N *distinct* online providers —
    /// otherwise the surplus roles error, preserving the "not enough online → error" guarantee even
    /// when the closed `ServiceType` set is coarser than the roles.
    pub fn convene(
        &self,
        offers: &[CapacityOffer],
        now: UnixSeconds,
    ) -> Result<Vec<RoleAssignment>, PipelineError> {
        if self.roles.is_empty() {
            return Err(PipelineError::Empty);
        }
        let mut assignments = Vec::with_capacity(self.roles.len());
        // Cross-role EXCLUSIVITY within one convene (#172): a single provider wins **at most one**
        // role per convene, even if it qualifies for several. Without this, two roles sharing a
        // (coarse, closed) `ServiceType` — e.g. flappy's `physics` + `art` both declare
        // `TextGeneration` — could both be won by one cheapest offer, silently "filling" a role
        // whose distinct provider is actually offline and breaking the "not enough online → error"
        // guarantee. With it, N same-typed roles genuinely need N distinct online providers.
        let mut assigned: Vec<[u8; 32]> = Vec::with_capacity(self.roles.len());
        for role in &self.roles {
            let winner = offers
                .iter()
                .filter(|o| {
                    o.is_valid(now)
                        && o.services.contains(&role.service)
                        && o.units_available >= role.units
                        && !assigned.contains(&o.holder_pubkey)
                })
                .min_by(|a, b| {
                    a.min_price
                        .cmp(&b.min_price)
                        .then_with(|| a.holder_pubkey.cmp(&b.holder_pubkey))
                });
            match winner {
                Some(o) => {
                    assigned.push(o.holder_pubkey);
                    assignments.push(RoleAssignment {
                        service: role.service,
                        provider: o.holder_pubkey,
                        units: role.units,
                        price: o.min_price,
                    });
                }
                None => return Err(PipelineError::UnfilledRole { service: role.service }),
            }
        }
        Ok(assignments)
    }
}

/// A published pipeline this agent can help run, from the agent's own scan of the registry: the
/// spec's id plus which of its roles (by `tag`) the agent qualifies for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportedPipeline {
    pub pipeline_id: String,
    /// The `tag`s of the roles in this pipeline whose service the agent serves — the roles it can
    /// offer to fill (bid into via [`PipelineSpec::convene`]).
    pub supportable_roles: Vec<String>,
}

/// The **agent-side PULL** discovery mode — the third face of the marketplace, the one the vision
/// (#175, gap 1) named but no primitive covered: given the pipeline specs a discovery pass found
/// (`GET /registry/pipelines`, #174) and the services THIS agent serves (its #167 opt-in catalog),
/// return the pipelines it can help run and which roles it qualifies for.
///
/// This is the complement of the pipeline-side methods: [`convene`](PipelineSpec::convene) asks
/// "who can fill *my* roles" (offer-side pull-and-clear) and [`invitations`](PipelineSpec::invitations)
/// asks "who can I invite" (card-side push); this asks, from the *agent's* seat, "which published
/// pipelines do *I* support" so an agent can proactively find and join jobs rather than only being
/// invited. Role matching mirrors `convene`'s capability filter exactly — an agent supports a role
/// iff `my_services` contains the role's [`ServiceType`] (the #167 opt-in dimension the auction
/// actually assigns on), so this never claims a role the agent could not then win. A spec with no
/// supportable role is omitted (nothing this agent can offer it); the result preserves spec order.
pub fn pipelines_supported_by_services(specs: &[PipelineSpec], my_services: &[ServiceType]) -> Vec<SupportedPipeline> {
    specs
        .iter()
        .filter_map(|spec| {
            let supportable_roles: Vec<String> = spec
                .roles
                .iter()
                .filter(|r| my_services.contains(&r.service))
                .map(|r| r.tag.clone())
                .collect();
            (!supportable_roles.is_empty()).then(|| SupportedPipeline { pipeline_id: spec.id.clone(), supportable_roles })
        })
        .collect()
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
                RequiredRole { service: SafetyCheck, units: 5, tag: "guard".into() },
                RequiredRole { service: CodeGeneration, units: 10, tag: "coder".into() },
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

        // #172: two roles sharing one (coarse) ServiceType need TWO distinct online providers —
        // a single offer cannot double-book both. flappy's physics + art both declare TextGeneration.
        let spec_same = PipelineSpec {
            id: "flappy".into(),
            roles: vec![
                RequiredRole { service: TextGeneration, units: 1, tag: "physics".into() },
                RequiredRole { service: TextGeneration, units: 1, tag: "art".into() },
            ],
        };
        let s2 = offer(7, vec![TextGeneration], 20, 50, 1000);
        let sk = offer(8, vec![TextGeneration], 20, 40, 1000);
        let both = spec_same.convene(&[s2.clone(), sk], 100).expect("two distinct providers fill both roles");
        assert_ne!(both[0].provider, both[1].provider, "each same-typed role gets a DISTINCT provider (no double-book)");
        // Only ONE provider online → the second same-typed role is unfillable → error, not a silent
        // double-book (the exact #172 reproduction).
        assert_eq!(
            spec_same.convene(&[s2], 100),
            Err(PipelineError::UnfilledRole { service: TextGeneration }),
            "#172: one offer cannot fill two same-typed roles — the second role errors"
        );

        // An empty spec convenes nothing.
        assert_eq!(
            PipelineSpec { id: "e".into(), roles: vec![] }.convene(&[safety], 100),
            Err(PipelineError::Empty),
        );
    }

    #[test]
    fn pipeline_invites_agents_by_their_card_role_tags() {
        // Maintainer vision (frozen): the PUSH path — the pipeline invites agents using the info on
        // their AgentCard (role_tags), returning who to invite per role over their advertised
        // channels. A role no card advertises has no candidates (invitable-underfilled).
        use crate::channel::AgentCard;
        let card = |seed: u8, tags: Vec<&str>, chans: Vec<[u8; 32]>, expires: UnixSeconds| {
            let sk = SigningKey::from_bytes(&[seed; 32]);
            AgentCard::sign_new(
                &sk,
                tags.into_iter().map(String::from).collect(),
                vec![],
                vec![],
                chans.into_iter().map(crate::channel::ChannelId).collect(),
                0,
                expires,
            )
        };
        let spec = PipelineSpec {
            id: "flappy".into(),
            roles: vec![
                RequiredRole { service: CodeGeneration, units: 10, tag: "physics".into() },
                RequiredRole { service: CodeGeneration, units: 10, tag: "art".into() },
            ],
        };
        // source-2 advertises "physics" (+ an existing tag), sink advertises "art"; a stranger
        // advertises neither.
        let source2 = card(1, vec!["physics", "mechanics-design"], vec![[0x11; 32]], 1000);
        let sink = card(2, vec!["art", "ux-design"], vec![[0x22; 32]], 1000);
        let stranger = card(3, vec!["marketing"], vec![[0x33; 32]], 1000);
        let expired_physics = card(4, vec!["physics"], vec![[0x44; 32]], 50); // expired at now=100

        let inv = spec.invitations(&[source2, sink, stranger, expired_physics], 100);
        assert_eq!(inv.len(), 2);
        assert_eq!(inv[0].tag, "physics");
        assert_eq!(inv[0].candidates.len(), 1, "only the valid physics card is invitable (expired one excluded)");
        assert_eq!(inv[0].candidates[0].holder, holder(1));
        assert_eq!(inv[0].candidates[0].channels, vec![crate::channel::ChannelId([0x11; 32])], "invite over the card's channel");
        assert_eq!(inv[1].tag, "art");
        assert_eq!(inv[1].candidates[0].holder, holder(2));

        // A role no card advertises → no one to invite.
        let spec2 = PipelineSpec {
            id: "x".into(),
            roles: vec![RequiredRole { service: SafetyCheck, units: 1, tag: "nobody-has-this".into() }],
        };
        assert!(spec2.invitations(&[card(5, vec!["physics"], vec![], 1000)], 100)[0].candidates.is_empty());
    }

    #[test]
    fn agent_finds_published_pipelines_it_supports() {
        // #175 gap 1 (frozen): the agent-side PULL — from the agent's OWN seat, scan the published
        // specs and find which pipelines it can help run, matching its served services against each
        // spec's roles (the complement of convene/invitations). Never claims a role it couldn't win.
        let flappy = PipelineSpec {
            id: "flappy".into(),
            roles: vec![
                RequiredRole { service: TextGeneration, units: 1, tag: "physics".into() },
                RequiredRole { service: TextGeneration, units: 1, tag: "art".into() },
                RequiredRole { service: SafetyCheck, units: 1, tag: "guard".into() },
            ],
        };
        let audit = PipelineSpec {
            id: "audit".into(),
            roles: vec![RequiredRole { service: SecurityReview, units: 1, tag: "reviewer".into() }],
        };

        // A text-generation agent (source-2/sink) supports flappy's physics + art, but NOT its
        // SafetyCheck role, and is not involved in the security-audit pipeline at all (omitted).
        let text_agent = pipelines_supported_by_services(&[flappy.clone(), audit.clone()], &[TextGeneration]);
        assert_eq!(text_agent.len(), 1, "the audit pipeline (no TextGeneration role) is omitted");
        assert_eq!(text_agent[0].pipeline_id, "flappy");
        assert_eq!(text_agent[0].supportable_roles, vec!["physics", "art"], "only the roles it can actually fill");

        // A multi-service agent supports flappy's guard role AND the audit pipeline.
        let multi = pipelines_supported_by_services(&[flappy.clone(), audit.clone()], &[SafetyCheck, SecurityReview]);
        assert_eq!(multi.len(), 2, "both pipelines have a role this agent serves");
        assert_eq!(multi[0].supportable_roles, vec!["guard"]);
        assert_eq!(multi[1].pipeline_id, "audit");
        assert_eq!(multi[1].supportable_roles, vec!["reviewer"]);

        // An agent that serves nothing the marketplace needs finds no pipelines (never a false claim).
        assert!(pipelines_supported_by_services(&[flappy, audit], &[CodeGeneration]).is_empty());
    }
}
