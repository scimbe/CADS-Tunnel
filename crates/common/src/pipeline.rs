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
use crate::preimage::Preimage;
use crate::settlement::Hold;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
    /// Optional per-role override of the pipeline's [`SelectionPolicy`]: `Some(p)` clears *this*
    /// role with `p` regardless of the pipeline-wide default, `None` inherits it. Lets one pipeline
    /// e.g. load-balance a fungible role while priority-failing-over a scarce one. `#[serde(default)]`
    /// so specs published before this field existed deserialize as `None` (inherit) — unchanged.
    #[serde(default)]
    pub selection_policy: Option<SelectionPolicy>,
}

/// A workflow-pipeline spec — the roles that must ALL be filled for the pipeline to run. This is
/// the "needed agent profiles + network info" a designer publishes for agents to scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineSpec {
    pub id: String,
    pub roles: Vec<RequiredRole>,
    /// The channel-operator public key (64 hex chars) whose grants/ownership govern this
    /// pipeline's Agent-Fabric role channels (#214 follow-up: generic pipeline provisioning).
    /// Publishing it here — alongside `id` and each role's `tag`, both already public — lets any
    /// bridge or role-serving agent derive every role's [`ChannelId`] via
    /// [`crate::channel::channel_id_for_pipeline_role`] with **no coordination round-trip**: no
    /// GitHub-comment pubkey relay, no per-pipeline core change. `#[serde(default)]` so specs
    /// published before this field existed still deserialize (as `None` — no channel wiring
    /// implied, exactly today's behavior).
    #[serde(default)]
    pub operator_pubkey_hex: Option<String>,
    /// The pipeline-wide default auction [`SelectionPolicy`] the designer publishes for this
    /// workflow — the "list of possible strategies, changeable by config" surfaced via
    /// `/registry/pipelines` so a bridge (or any joiner) can see how roles clear without a side
    /// channel. A per-role [`RequiredRole::selection_policy`] overrides it for that role.
    /// `#[serde(default)]` (→ [`SelectionPolicy::LowestFloor`]) so specs published before this field
    /// existed still deserialize unchanged — the same discipline #223 used for `operator_pubkey_hex`.
    ///
    /// Note: the legacy [`convene`](Self::convene) deliberately ignores this field and always clears
    /// `LowestFloor`, so no existing caller's behavior shifts when a spec starts declaring a policy;
    /// [`convene_with_policy`](Self::convene_with_policy) is where it (and any per-role override) takes effect.
    #[serde(default)]
    pub selection_policy: SelectionPolicy,
}

impl PipelineSpec {
    /// This pipeline's derived [`ChannelId`] for `role_tag`, iff `role_tag` is one of its
    /// declared roles AND `operator_pubkey_hex` is set and valid hex. `None` otherwise — a spec
    /// with no operator key declares no channel wiring (today's behavior, unchanged); an unknown
    /// role tag has no channel to derive.
    pub fn role_channel_id(&self, role_tag: &str) -> Option<crate::channel::ChannelId> {
        if !self.roles.iter().any(|r| r.tag == role_tag) {
            return None;
        }
        let hex = self.operator_pubkey_hex.as_deref()?;
        let operator = decode_hex_32(hex)?;
        Some(crate::channel::channel_id_for_pipeline_role(&operator, &self.id, role_tag))
    }
}

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
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

/// One bid in a role's [`auction_view`](PipelineSpec::auction_view): a qualifying offer as the UI
/// shows it. Generic (no pipeline-specific fields) so it belongs in core — unlike the demo-shaped
/// `ct_common::crew` types it is meant to replace (#180/#219). `Serialize` only: it is an output view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RoleBidView {
    /// The provider's display identity (resolved by the caller's `label`), not the raw pubkey.
    pub who: String,
    /// The units the offer advertises (`units_available`) — the quantity this bid can serve.
    pub units: u64,
    /// The offer's floor (`min_price`) — the price this bid clears at if it wins.
    pub price: u64,
    /// Whether this bid won the role under the active [`SelectionPolicy`].
    pub win: bool,
}

/// The full auction for one role: every qualifying bid, winner flagged — the honest counterpart to a
/// hardcoded fixture. Produced by [`PipelineSpec::auction_view`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RoleAuctionView {
    /// The role's `tag` (e.g. `"physics"`).
    pub role: String,
    pub bids: Vec<RoleBidView>,
}

/// The rule [`convene_with_policy`](PipelineSpec::convene_with_policy) uses to pick the winner **among the offers
/// that already qualify** for a role (all equally valid/eligible — this only decides *which*
/// qualifying offer wins, never whether a role is fillable). A workflow-pipeline owner selects the
/// policy in their bridge config, so cheapest-price clearing can be traded for fair load
/// distribution across N interchangeable providers **without any core change** (#207/#208 asked for
/// "fallback / load-balancing, controlled by the auction"; #207 only ever designed the failover
/// half — the priority-tiered-floor case below — and named load-balancing as an undelivered bonus).
///
/// Every policy ranks *only the currently-valid* offers (a role's stale/expired offers are already
/// filtered out before it runs), so **failover is preserved under all three**: when the current
/// winner's offer goes stale (its short-TTL heartbeat stops, #207), the next convene simply re-picks
/// over whoever is still live. `LowestFloor` + tiered floors = priority failover; `RoundRobin` /
/// `LeastCalls` over equal-floor live offers = load-balancing. Same offer pool, swappable rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SelectionPolicy {
    /// Cheapest offer wins (lowest `min_price`), ties broken by holder key for determinism. The
    /// original — and **default** — behavior: convening with this over a fresh
    /// [`SelectionState`] is byte-identical to the pre-policy `convene`. Gives priority-failover
    /// when a preferred provider publishes a *lower* floor than its standby (source-2 primary vs
    /// sink standby, #207/#208). Stateless.
    #[default]
    LowestFloor,
    /// Rotate across the qualifying providers: each convene picks the next provider (deterministic
    /// order by holder key, wrap-around) after the one that last won this role. Over N stable live
    /// providers this cycles 1→2→…→N→1, spreading load evenly. Stateful — see [`SelectionState`].
    RoundRobin,
    /// Route to the qualifying provider that has served the fewest jobs so far (ties broken by
    /// floor, then holder key). Self-balancing: a freshly added *copy* provider starts at zero and
    /// is preferred until it catches up, so adding a clone drains the backlog off the busy ones
    /// with no reconfig. Stateful — see [`SelectionState`].
    LeastCalls,
}

/// The cross-convene state the stateful [`SelectionPolicy`] variants carry between calls. The
/// auction engine stays pure — the **caller** (a pipeline's bridge) owns this value and threads the
/// same instance through successive convenes, so a policy change or a core restart can never corrupt
/// engine internals. [`SelectionPolicy::LowestFloor`] reads and writes none of it, so a default
/// (empty) state convenes identically to the old stateless `convene` — the reason back-compat holds.
///
/// Persistence, if any, is the caller's choice (in-memory is enough for load-balancing while the
/// bridge runs); core deliberately does not pin a wire format for it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SelectionState {
    /// Per role `tag` → the holder key that last won it, so `RoundRobin` can advance to the next.
    pub round_robin_cursor: BTreeMap<String, [u8; 32]>,
    /// Per provider holder key → jobs it has been assigned, so `LeastCalls` can prefer the laggard.
    pub served_counts: BTreeMap<[u8; 32], u64>,
}

impl SelectionPolicy {
    /// Pick the winner among `qualifying` (already filtered to the valid, eligible, not-yet-assigned
    /// offers for one role — the caller guarantees it is **non-empty**) and update `state` so the
    /// next convene of this role sees the effect. `role_tag` scopes the `RoundRobin` cursor.
    fn pick<'o>(
        self,
        role_tag: &str,
        qualifying: &[&'o CapacityOffer],
        state: &mut SelectionState,
    ) -> &'o CapacityOffer {
        match self {
            SelectionPolicy::LowestFloor => qualifying
                .iter()
                .copied()
                .min_by(|a, b| a.min_price.cmp(&b.min_price).then_with(|| a.holder_pubkey.cmp(&b.holder_pubkey)))
                .expect("caller guarantees qualifying is non-empty"),
            SelectionPolicy::RoundRobin => {
                // Deterministic ring so rotation is stable regardless of offer arrival order.
                let mut ring: Vec<&CapacityOffer> = qualifying.to_vec();
                ring.sort_by_key(|a| a.holder_pubkey);
                // Next provider strictly after the last winner. If the last winner is gone
                // (offline) this lands on the next-higher key; if it was the highest (or unset),
                // wrap to the ring start. Either way we advance over the *live* set → failover.
                let start = match state.round_robin_cursor.get(role_tag) {
                    Some(last) => ring.iter().position(|o| o.holder_pubkey > *last).unwrap_or(0),
                    None => 0,
                };
                let chosen = ring[start];
                state.round_robin_cursor.insert(role_tag.to_string(), chosen.holder_pubkey);
                chosen
            }
            SelectionPolicy::LeastCalls => {
                let chosen = qualifying
                    .iter()
                    .copied()
                    .min_by(|a, b| {
                        let ca = state.served_counts.get(&a.holder_pubkey).copied().unwrap_or(0);
                        let cb = state.served_counts.get(&b.holder_pubkey).copied().unwrap_or(0);
                        ca.cmp(&cb)
                            .then_with(|| a.min_price.cmp(&b.min_price))
                            .then_with(|| a.holder_pubkey.cmp(&b.holder_pubkey))
                    })
                    .expect("caller guarantees qualifying is non-empty");
                *state.served_counts.entry(chosen.holder_pubkey).or_insert(0) += 1;
                chosen
            }
        }
    }
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
                RoleInvitation { service: role.service.clone(), tag: role.tag.clone(), candidates }
            })
            .collect()
    }

    /// Convene the pipeline against the currently-online `offers` with the cheapest-floor
    /// [`SelectionPolicy::LowestFloor`] auction — the original signature and behavior, preserved
    /// **byte-identically** for every existing caller. It deliberately ignores the (opt-in)
    /// [`selection_policy`](Self::selection_policy) fields entirely and always clears `LowestFloor`,
    /// so no existing call site can shift behavior just because a spec starts declaring a policy;
    /// [`convene_with_policy`](Self::convene_with_policy) is the entry point that honors them.
    pub fn convene(
        &self,
        offers: &[CapacityOffer],
        now: UnixSeconds,
    ) -> Result<Vec<RoleAssignment>, PipelineError> {
        self.convene_roles(offers, now, |_role| SelectionPolicy::LowestFloor, &mut SelectionState::default())
    }

    /// Convene the pipeline against the currently-online `offers`, clearing each role's auction with
    /// `policy` as the pipeline-wide default and honoring any per-role
    /// [`RequiredRole::selection_policy`] override. Runs a per-role auction and returns the winning
    /// [`RoleAssignment`] for **every** role, or the first [`PipelineError::UnfilledRole`] if any
    /// role has no matchable offer online.
    ///
    /// An offer fills a role iff it (a) [`is_valid`](CapacityOffer::is_valid) at `now`
    /// (signature + not expired), (b) its declared `services` contains the role's service (the
    /// #167 opt-in catalog — a generic empty-services offer never fills a role), and (c) it
    /// advertises at least the units the role needs. **Which** qualifying offer wins is decided by
    /// the role's effective policy (`role.selection_policy.unwrap_or(policy)`, see
    /// [`SelectionPolicy`]); `LowestFloor` is the cheapest-floor auction `convene` has always run. A
    /// provider wins **at most one** role per convene (#172 cross-role exclusivity), so N roles
    /// sharing a `ServiceType` require N *distinct* online providers — otherwise the surplus roles
    /// error, preserving the "not enough online → error" guarantee even when the closed
    /// `ServiceType` set is coarser than the roles.
    ///
    /// Pass `self.selection_policy` for `policy` to clear with the pipeline's own published default.
    /// `state` carries the cross-convene bookkeeping the stateful policies need; pass the *same*
    /// instance across successive convenes (the caller owns it). `LowestFloor` ignores it, so a
    /// fresh `SelectionState::default()` is fine when every effective policy is `LowestFloor`.
    pub fn convene_with_policy(
        &self,
        offers: &[CapacityOffer],
        now: UnixSeconds,
        policy: SelectionPolicy,
        state: &mut SelectionState,
    ) -> Result<Vec<RoleAssignment>, PipelineError> {
        self.convene_roles(offers, now, |role| role.selection_policy.unwrap_or(policy), state)
    }

    /// Compute the currently-valid subset of `offers` at `now` — the single point where each
    /// offer's ed25519 signature gets verified (not a cheap check). Any caller that needs to
    /// consult validity more than once while handling one request (e.g. [`auction_view`]
    /// (Self::auction_view), which both convenes AND lists every qualifying bid) MUST compute
    /// this ONCE and reuse the result, rather than calling [`CapacityOffer::is_valid`] again per
    /// offer per role — see #473 (this used to cost `2 * roles * offers` verifications per call).
    fn valid_offers<'o>(offers: &'o [CapacityOffer], now: UnixSeconds) -> Vec<&'o CapacityOffer> {
        #[cfg(test)]
        tests::VALID_OFFERS_CALLS.with(|c| c.set(c.get() + 1));
        offers.iter().filter(|o| o.is_valid(now)).collect()
    }

    /// Shared convene core: `policy_for` maps each role to the [`SelectionPolicy`] that clears it, so
    /// [`convene`](Self::convene) can pin `LowestFloor` (legacy, byte-identical) while
    /// [`convene_with_policy`](Self::convene_with_policy) resolves per-role overrides. Eligibility
    /// and #172 cross-role exclusivity are policy-independent and identical to the pre-policy code.
    fn convene_roles(
        &self,
        offers: &[CapacityOffer],
        now: UnixSeconds,
        policy_for: impl Fn(&RequiredRole) -> SelectionPolicy,
        state: &mut SelectionState,
    ) -> Result<Vec<RoleAssignment>, PipelineError> {
        let valid = Self::valid_offers(offers, now);
        self.convene_valid(&valid, policy_for, state)
    }

    /// Shared convene core operating on an ALREADY-validated offer set (see [`Self::valid_offers`])
    /// — no signature verification happens in here, so a caller that already holds a valid set
    /// (e.g. [`auction_view`](Self::auction_view)) can reuse it without re-verifying (#473).
    fn convene_valid(
        &self,
        valid: &[&CapacityOffer],
        policy_for: impl Fn(&RequiredRole) -> SelectionPolicy,
        state: &mut SelectionState,
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
            // Eligibility is policy-independent: already-valid + declares the service + enough
            // units + not already assigned this convene. The policy only ranks whoever survives.
            let qualifying: Vec<&CapacityOffer> = valid
                .iter()
                .copied()
                .filter(|o| {
                    o.services.contains(&role.service)
                        && o.units_available >= role.units
                        && !assigned.contains(&o.holder_pubkey)
                })
                .collect();
            if qualifying.is_empty() {
                return Err(PipelineError::UnfilledRole { service: role.service.clone() });
            }
            let o = policy_for(role).pick(&role.tag, &qualifying, state);
            assigned.push(o.holder_pubkey);
            assignments.push(RoleAssignment {
                service: role.service.clone(),
                provider: o.holder_pubkey,
                units: role.units,
                price: o.min_price,
            });
        }
        Ok(assignments)
    }

    /// The **browser-facing auction view** of a real clear (#180): run
    /// [`convene_with_policy`](Self::convene_with_policy), then for every role list *each* qualifying
    /// offer as a bid (`who` = `label(provider)`, `units`/`price` straight off the signed offer) with
    /// the policy's winner flagged `win: true`. This is the honest replacement for a hardcoded
    /// `demo_auction()` fixture: the numbers are the agents' own signed offer terms, and adding a
    /// second offer for a role turns the single-bidder display into a genuine contest with no code
    /// change. Errors with the same [`PipelineError::UnfilledRole`] as `convene` if any role has no
    /// online offer — no market is shown for a pipeline that cannot actually run.
    ///
    /// `label` resolves a provider's holder pubkey to the human `who` string the UI shows (e.g. a
    /// registry/[`AgentCard`] name, or hex as a fallback) — the display identity core doesn't carry
    /// on the economic [`CapacityOffer`]. Bids are returned winner-first, then cheapest, then by
    /// `who`, for a stable display order. `state` threads the stateful policies exactly as in
    /// `convene_with_policy` (the winner shown is the one that would be dialed).
    pub fn auction_view(
        &self,
        offers: &[CapacityOffer],
        now: UnixSeconds,
        policy: SelectionPolicy,
        state: &mut SelectionState,
        label: impl Fn(&[u8; 32]) -> String,
    ) -> Result<Vec<RoleAuctionView>, PipelineError> {
        // #473: verify every offer's signature ONCE for this call, then reuse the already-valid
        // set for both the real clear below AND the per-role bid listing — this used to run
        // `is_valid` a second full `roles * offers` pass after `convene_with_policy` had already
        // paid that cost internally (`2 * roles * offers` ed25519 verifications per call on a
        // browser-facing endpoint).
        let valid = Self::valid_offers(offers, now);
        // Clear for real first: winners honor policy + #172 cross-role exclusivity + state.
        let assignments =
            self.convene_valid(&valid, |role| role.selection_policy.unwrap_or(policy), state)?;
        let views = self
            .roles
            .iter()
            .zip(&assignments)
            .map(|(role, assignment)| {
                let mut bids: Vec<RoleBidView> = valid
                    .iter()
                    .copied()
                    .filter(|o| o.services.contains(&role.service) && o.units_available >= role.units)
                    .map(|o| RoleBidView {
                        who: label(&o.holder_pubkey),
                        units: o.units_available,
                        price: o.min_price,
                        win: o.holder_pubkey == assignment.provider,
                    })
                    .collect();
                // Winner first, then cheapest floor, then `who` — deterministic display order.
                bids.sort_by(|a, b| {
                    b.win.cmp(&a.win).then(a.price.cmp(&b.price)).then_with(|| a.who.cmp(&b.who))
                });
                RoleAuctionView { role: role.tag.clone(), bids }
            })
            .collect();
        Ok(views)
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

/// Domain separator for the per-role escrow match id, so a pipeline hold can never collide with an
/// id minted for a different purpose (offer match, transfer, etc.).
const PIPELINE_MATCH_DOMAIN: &[u8] = b"ct-pipeline-escrow-match-v1";

/// The deterministic escrow `match_ref` for one convened role: the id that binds this role's escrow
/// [`Hold`] to the [`UsageReceipt`](crate::channel::UsageReceipt) that later releases it. Derived
/// from the pipeline id + the assignment's terms; because [`convene`](PipelineSpec::convene) gives
/// each role a **distinct** provider (#172 cross-role exclusivity), `(pipeline_id, provider)` is
/// unique per role, so no two roles of one convened pipeline share a match id.
///
/// #454: built via [`Preimage`] rather than hand-rolled — the domain constant used to be appended
/// with no length prefix of its own, reopening the exact gap #252 closed in `Preimage::new` (a
/// future second pipeline-match domain that happens to be a byte-prefix of this one could collide).
/// Not exploitable with today's single domain constant, but `Preimage` makes it unconditionally
/// safe rather than relying on that staying true. **Breaking change**: this changes the derived
/// `match_ref` for any already-minted hold, matching #252's own precedent — no in-place migration
/// exists for durably-stored pre-#454 match refs.
pub fn role_match_ref(pipeline_id: &str, assignment: &RoleAssignment) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let preimage = Preimage::new(PIPELINE_MATCH_DOMAIN)
        .var_bytes(pipeline_id.as_bytes())
        .fixed(&assignment.provider)
        .u64(assignment.units)
        .u64(assignment.price)
        .finish();
    Sha256::digest(preimage).into()
}

/// **Settle a convened pipeline for real** (#175 gap 2, maintainer 2026-07-25: settlement is now):
/// turn the [`RoleAssignment`]s that [`convene`](PipelineSpec::convene) cleared into the signed
/// escrow [`Hold`]s that actually lock the money — one per role, not a mere display of who won.
///
/// Each hold locks the role's cleared `price` from the buyer (`buyer_key`'s account) to the winning
/// `provider`, bound to this role's [`role_match_ref`], with sequential nonces from `first_nonce`
/// (the buyer's next escrow nonce — 0 for a buyer that has never locked) and a shared `expires_at`.
/// Feed the results straight to [`Escrow::lock`](crate::settlement::Escrow::lock): on a co-signed
/// [`UsageReceipt`](crate::channel::UsageReceipt) for the same `match_ref` the provider is paid
/// ([`release`](crate::settlement::Escrow::release)); if none arrives by `expires_at` the buyer is
/// refunded ([`refund`](crate::settlement::Escrow::refund)) — so a convened role is a *held* amount
/// (a cap), never a unilateral loss. The buyer signs, so it can only lock its own funds.
pub fn holds_for_convened(
    pipeline_id: &str,
    assignments: &[RoleAssignment],
    buyer_key: &SigningKey,
    first_nonce: u64,
    expires_at: UnixSeconds,
) -> Vec<Hold> {
    assignments
        .iter()
        .enumerate()
        .map(|(i, a)| {
            Hold::sign_new(
                buyer_key,
                a.provider,
                a.price,
                role_match_ref(pipeline_id, a),
                first_nonce + i as u64,
                expires_at,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{CapacityKind, ServiceType::*};
    use ed25519_dalek::SigningKey;

    // #473: counts calls to `PipelineSpec::valid_offers` — the single choke point where offer
    // signatures are verified — so tests can prove a whole `auction_view`/`convene_*` call
    // verifies each offer's signature exactly once, never once per role.
    thread_local! {
        pub(super) static VALID_OFFERS_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }
    fn reset_valid_offers_calls() {
        VALID_OFFERS_CALLS.with(|c| c.set(0));
    }
    fn valid_offers_calls() -> usize {
        VALID_OFFERS_CALLS.with(|c| c.get())
    }

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
    fn spec_without_operator_pubkey_still_deserializes_and_derives_no_channel() {
        // Backward compat: a PipelineSpec published before operator_pubkey_hex existed has no
        // such field in its JSON at all -> must still deserialize (as None), and role_channel_id
        // must return None (no channel wiring implied) rather than panic or guess.
        let json = r#"{"id":"old-pipeline","roles":[{"service":"TextGeneration","units":1,"tag":"physics"}]}"#;
        let spec: PipelineSpec = serde_json::from_str(json).expect("old-shape JSON still parses");
        assert_eq!(spec.operator_pubkey_hex, None);
        assert_eq!(spec.role_channel_id("physics"), None, "no operator key -> no derivable channel");
    }

    #[test]
    fn role_channel_id_derives_only_for_declared_roles_with_a_valid_operator_key() {
        let op_hex = "11".repeat(32);
        let spec = PipelineSpec {
            id: "flappy-demo".to_string(),
            roles: vec![RequiredRole { service: TextGeneration, units: 1, tag: "physics".into(), selection_policy: None }],
            operator_pubkey_hex: Some(op_hex.clone()), selection_policy: SelectionPolicy::LowestFloor,
        };
        let op = decode_hex_32(&op_hex).unwrap();
        assert_eq!(
            spec.role_channel_id("physics"),
            Some(crate::channel::channel_id_for_pipeline_role(&op, "flappy-demo", "physics")),
            "matches the canonical derivation any independent joiner would compute"
        );
        assert_eq!(spec.role_channel_id("art"), None, "role not declared by this pipeline -> no channel");

        let bad = PipelineSpec { operator_pubkey_hex: Some("not-hex".into()), ..spec };
        assert_eq!(bad.role_channel_id("physics"), None, "malformed hex -> None, not a panic");
    }

    #[test]
    fn pipeline_convenes_only_when_every_role_has_an_online_offer() {
        // Maintainer vision (frozen): a pipeline auctions each declared role and RAISES an error if
        // a role can't be filled by an online offer — never half-arranges.
        let spec = PipelineSpec {
            id: "flappy".into(),
            roles: vec![
                RequiredRole { service: SafetyCheck, units: 5, tag: "guard".into(), selection_policy: None },
                RequiredRole { service: CodeGeneration, units: 10, tag: "coder".into(), selection_policy: None },
            ],
            operator_pubkey_hex: None, selection_policy: SelectionPolicy::LowestFloor,
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
            spec.convene(std::slice::from_ref(&safety), 100),
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
                RequiredRole { service: TextGeneration, units: 1, tag: "physics".into(), selection_policy: None },
                RequiredRole { service: TextGeneration, units: 1, tag: "art".into(), selection_policy: None },
            ],
            operator_pubkey_hex: None, selection_policy: SelectionPolicy::LowestFloor,
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
            PipelineSpec { id: "e".into(), roles: vec![], operator_pubkey_hex: None, selection_policy: SelectionPolicy::LowestFloor }.convene(&[safety], 100),
            Err(PipelineError::Empty),
        );
    }

    #[test]
    fn a_pipeline_designer_can_declare_a_role_ct_tunnel_never_hardcoded() {
        // #382 follow-up: the actual proof "generalize RequiredRole/convene() for non-demo
        // pipeline roles" holds -- a pipeline for The Development System's plan/test/implement/
        // review/verify/remember/improve stages needs service types (StaticAnalysis,
        // AndroidInstrumentedTest, ...) this crate never declared and never will need to, one
        // core-crate release per new pipeline-stage type. ServiceType::Custom makes that a
        // pipeline-designer-level decision instead of a CADS-Tunnel core change.
        let static_analysis = ServiceType::Custom("StaticAnalysis".into());
        let instrumented_test = ServiceType::Custom("AndroidInstrumentedTest".into());
        let spec = PipelineSpec {
            id: "devsystem-android".into(),
            roles: vec![
                RequiredRole { service: static_analysis.clone(), units: 1, tag: "lint".into(), selection_policy: None },
                RequiredRole { service: instrumented_test.clone(), units: 1, tag: "device-test".into(), selection_policy: None },
            ],
            operator_pubkey_hex: None,
            selection_policy: SelectionPolicy::LowestFloor,
        };

        let lint_agent = offer(11, vec![static_analysis.clone()], 5, 10, 1000);
        let device_farm = offer(12, vec![instrumented_test.clone()], 5, 200, 1000);
        let assignments = spec
            .convene(&[lint_agent.clone(), device_farm.clone()], 100)
            .expect("both custom-service roles have a matching online offer -> convenes");
        assert_eq!(assignments.len(), 2);
        assert_eq!(assignments[0].service, static_analysis, "the winning assignment carries the SAME custom service, not a stand-in");
        assert_eq!(assignments[0].provider, holder(11));
        assert_eq!(assignments[1].service, instrumented_test);
        assert_eq!(assignments[1].provider, holder(12));

        // A fixed built-in service (CodeGeneration) never matches a custom-named role, and vice
        // versa -- custom and fixed service types don't silently alias each other.
        let wrong_kind_offer = offer(13, vec![CodeGeneration], 5, 1, 1000);
        assert_eq!(
            spec.convene(&[wrong_kind_offer, device_farm], 100),
            Err(PipelineError::UnfilledRole { service: ServiceType::Custom("StaticAnalysis".into()) }),
            "a CodeGeneration offer does not fill a Custom(\"StaticAnalysis\") role"
        );

        // Two DIFFERENT custom-named offers never cross-qualify for each other's role, even
        // though both are ServiceType::Custom (the tag byte alone is NOT how these compare --
        // Custom carries its own name, checked by full equality).
        let mislabeled = offer(14, vec![ServiceType::Custom("SomethingElse".into())], 5, 1, 1000);
        assert_eq!(
            spec.convene(&[mislabeled, offer(12, vec![instrumented_test], 5, 200, 1000)], 100),
            Err(PipelineError::UnfilledRole { service: static_analysis }),
            "a differently-NAMED custom service never fills a role it wasn't declared for"
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
                RequiredRole { service: CodeGeneration, units: 10, tag: "physics".into(), selection_policy: None },
                RequiredRole { service: CodeGeneration, units: 10, tag: "art".into(), selection_policy: None },
            ],
            operator_pubkey_hex: None, selection_policy: SelectionPolicy::LowestFloor,
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
            roles: vec![RequiredRole { service: SafetyCheck, units: 1, tag: "nobody-has-this".into(), selection_policy: None }],
            operator_pubkey_hex: None, selection_policy: SelectionPolicy::LowestFloor,
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
                RequiredRole { service: TextGeneration, units: 1, tag: "physics".into(), selection_policy: None },
                RequiredRole { service: TextGeneration, units: 1, tag: "art".into(), selection_policy: None },
                RequiredRole { service: SafetyCheck, units: 1, tag: "guard".into(), selection_policy: None },
            ],
            operator_pubkey_hex: None, selection_policy: SelectionPolicy::LowestFloor,
        };
        let audit = PipelineSpec {
            id: "audit".into(),
            roles: vec![RequiredRole { service: SecurityReview, units: 1, tag: "reviewer".into(), selection_policy: None }],
            operator_pubkey_hex: None, selection_policy: SelectionPolicy::LowestFloor,
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

    #[test]
    fn convened_pipeline_opens_real_escrow_holds_paid_on_receipt_refunded_on_expiry() {
        // #175 gap 2 (frozen, maintainer 2026-07-25 "settlement is now"): a convened pipeline opens
        // REAL escrow holds — money actually locks — then a co-signed UsageReceipt pays the winning
        // provider, or the buyer is refunded after expiry. The full convene→hold→lock→settle path.
        use crate::channel::{CapacityKind, UsageReceipt};
        use crate::settlement::Escrow;
        use std::collections::BTreeMap;

        let spec = PipelineSpec {
            id: "flappy".into(),
            roles: vec![
                RequiredRole { service: SafetyCheck, units: 5, tag: "guard".into(), selection_policy: None },
                RequiredRole { service: CodeGeneration, units: 10, tag: "coder".into(), selection_policy: None },
            ],
            operator_pubkey_hex: None, selection_policy: SelectionPolicy::LowestFloor,
        };
        let guard = offer(1, vec![SafetyCheck], 20, 50, 1000); // provider holder(1), price 50
        let coder = offer(2, vec![CodeGeneration], 20, 40, 1000); // provider holder(2), price 40
        let assignments = spec.convene(&[guard, coder], 100).expect("both roles clear");

        // Buyer signs the holds → can only lock its OWN funds. Fund it in escrow genesis.
        let buyer_key = SigningKey::from_bytes(&[9; 32]);
        let buyer = buyer_key.verifying_key().to_bytes();
        let holds = holds_for_convened("flappy", &assignments, &buyer_key, 0, 500);

        assert_eq!(holds.len(), 2);
        assert!(holds.iter().all(|h| h.verify()), "buyer's holds are authentically signed");
        assert_eq!((holds[0].to, holds[0].amount), (holder(1), 50), "role 0 holds its cleared price to its provider");
        assert_eq!((holds[1].to, holds[1].amount), (holder(2), 40));
        assert_eq!(holds[0].match_ref, role_match_ref("flappy", &assignments[0]), "hold bound to the role's match id");
        assert_ne!(holds[0].match_ref, holds[1].match_ref, "distinct roles → distinct escrow matches");
        assert_eq!((holds[0].nonce, holds[1].nonce), (0, 1), "sequential buyer nonces");

        // Lock both holds → the money really moves out of the buyer's available balance into escrow.
        let mut escrow = Escrow::new(BTreeMap::from([(buyer, 1000)]));
        for h in &holds {
            escrow.lock(h).expect("hold locks against funded buyer");
        }
        assert_eq!(escrow.balance(&buyer), 1000 - 90, "90 locked (50 + 40) out of available");
        assert_eq!(escrow.held_amount(&holds[0].match_ref), 50);
        assert_eq!(escrow.held_amount(&holds[1].match_ref), 40);

        // Role 0 delivers: a co-signed UsageReceipt for its match_ref RELEASES the funds to the provider.
        let guard_key = SigningKey::from_bytes(&[1; 32]);
        let receipt = UsageReceipt::co_sign(
            &guard_key, &buyer_key, CapacityKind::CloudApiQuota, "m".into(), 5, holds[0].match_ref, 200,
        );
        escrow.release(&receipt).expect("valid receipt pays the provider");
        assert_eq!(escrow.balance(&holder(1)), 50, "provider paid its cleared price");
        assert_eq!(escrow.held_amount(&holds[0].match_ref), 0, "hold consumed on release");

        // Role 1 never delivers: refund is blocked until expiry, then returns the funds to the buyer.
        assert_eq!(
            escrow.refund(&holds[1].match_ref, 100),
            Err(crate::settlement::EscrowError::NotYetExpired { expires_at: 500, now: 100 }),
            "no refund before expiry — the provider still has time to prove",
        );
        escrow.refund(&holds[1].match_ref, 500).expect("refund after expiry");
        assert_eq!(escrow.balance(&buyer), 910 + 40, "unspent role refunded to the buyer");
    }

    #[test]
    fn role_match_ref_length_prefixes_the_pipeline_id_so_boundary_ambiguity_cant_collide_454() {
        // The classic missing-length-prefix collision: "ab" + "c" vs "a" + "bc" -- without
        // length-prefixing pipeline_id, both would concatenate to the same bytes after the domain.
        let assignment = RoleAssignment { service: SafetyCheck, provider: [7u8; 32], units: 1, price: 1 };
        let a = role_match_ref("abc", &assignment);
        let b = role_match_ref("ab", &assignment);
        assert_ne!(a, b, "different pipeline_id lengths must never collide");

        // Direct proof the domain itself is now length-prefixed: a hand-built preimage using the
        // OLD (pre-#454) unprefixed-domain scheme must NOT match the new one for identical inputs.
        use sha2::{Digest, Sha256};
        let old_scheme: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(PIPELINE_MATCH_DOMAIN);
            h.update((b"abc".len() as u64).to_le_bytes());
            h.update(b"abc");
            h.update(assignment.provider);
            h.update(assignment.units.to_le_bytes());
            h.update(assignment.price.to_le_bytes());
            h.finalize().into()
        };
        assert_ne!(a, old_scheme, "the fixed encoding must differ from the old hand-rolled one");
    }

    /// A single-role flappy-style `physics` spec — the reference role of #207/#208.
    fn physics_spec() -> PipelineSpec {
        PipelineSpec {
            id: "flappy".into(),
            roles: vec![RequiredRole { service: TextGeneration, units: 1, tag: "physics".into(), selection_policy: None }],
            operator_pubkey_hex: None, selection_policy: SelectionPolicy::LowestFloor,
        }
    }

    #[test]
    fn lowest_floor_is_the_default_and_convene_matches_convene_with_policy() {
        // Back-compat contract: the default policy is LowestFloor, and the old `convene` is exactly
        // `convene_with_policy(LowestFloor, fresh state)` — cheapest floor still wins, nothing regresses.
        assert_eq!(SelectionPolicy::default(), SelectionPolicy::LowestFloor);
        let spec = physics_spec();
        let dear = offer(1, vec![TextGeneration], 20, 50, 1000);
        let cheap = offer(2, vec![TextGeneration], 20, 30, 1000);
        let offers = [dear, cheap];
        let via_default = spec.convene(&offers, 100).unwrap();
        let via_policy = spec
            .convene_with_policy(&offers, 100, SelectionPolicy::LowestFloor, &mut SelectionState::default())
            .unwrap();
        assert_eq!(via_default, via_policy, "convene() == convene_with_policy(LowestFloor, fresh)");
        assert_eq!(via_default[0].provider, holder(2), "cheapest floor wins by default");
        assert_eq!(via_default[0].price, 30);
    }

    #[test]
    fn round_robin_spreads_load_across_equal_floor_providers() {
        // Two interchangeable providers with an identical floor: LowestFloor would pin every job to
        // the same one; RoundRobin alternates so each serves exactly half — the load-balancing #207
        // named but never implemented.
        let spec = physics_spec();
        let offers = [
            offer(1, vec![TextGeneration], 20, 50, 1000),
            offer(2, vec![TextGeneration], 20, 50, 1000),
        ];
        let mut state = SelectionState::default();
        let winners: Vec<[u8; 32]> = (0..4)
            .map(|_| spec.convene_with_policy(&offers, 100, SelectionPolicy::RoundRobin, &mut state).unwrap()[0].provider)
            .collect();
        assert_ne!(winners[0], winners[1], "never the same provider twice in a row");
        assert_eq!(winners[0], winners[2], "cycles back after all providers had a turn");
        assert_eq!(winners[1], winners[3]);
        assert_eq!(winners.iter().filter(|w| **w == holder(1)).count(), 2, "half the jobs each");
        assert_eq!(winners.iter().filter(|w| **w == holder(2)).count(), 2);
    }

    #[test]
    fn least_calls_routes_to_the_laggard_and_absorbs_a_fresh_copy() {
        let spec = physics_spec();
        let p1 = offer(1, vec![TextGeneration], 20, 50, 1000);
        let p2 = offer(2, vec![TextGeneration], 20, 50, 1000);
        let mut state = SelectionState::default();

        // Two equal providers → least-calls balances 1:1 over an even number of jobs.
        let two = [p1.clone(), p2.clone()];
        for _ in 0..4 {
            spec.convene_with_policy(&two, 100, SelectionPolicy::LeastCalls, &mut state).unwrap();
        }
        assert_eq!(state.served_counts.get(&holder(1)).copied().unwrap_or(0), 2);
        assert_eq!(state.served_counts.get(&holder(2)).copied().unwrap_or(0), 2);

        // A brand-new *copy* joins at zero served → it is preferred until it catches up, draining
        // the backlog off the busy providers with no reconfig ("provide agents as a copy the auction
        // can take as an alternative").
        let three = [p1, p2, offer(3, vec![TextGeneration], 20, 50, 1000)];
        let next: Vec<[u8; 32]> = (0..2)
            .map(|_| spec.convene_with_policy(&three, 100, SelectionPolicy::LeastCalls, &mut state).unwrap()[0].provider)
            .collect();
        assert!(next.iter().all(|w| *w == holder(3)), "the fresh copy drains the backlog first");
        assert_eq!(state.served_counts.get(&holder(3)).copied().unwrap_or(0), 2, "copy caught up");
    }

    #[test]
    fn stateful_policy_still_fails_over_to_whoever_is_live() {
        // The #207 failover guarantee must survive a load-balancing policy: when the current winner
        // goes offline, the next convene re-clears over the live set with no reconfig — and an
        // all-offline role still errors (a policy never invents a provider).
        let spec = physics_spec();
        let p1 = offer(1, vec![TextGeneration], 20, 50, 1000);
        let p2 = offer(2, vec![TextGeneration], 20, 50, 1000);
        let mut state = SelectionState::default();

        let first = spec
            .convene_with_policy(&[p1.clone(), p2.clone()], 100, SelectionPolicy::RoundRobin, &mut state)
            .unwrap()[0]
            .provider;
        let (survivor_offer, survivor) =
            if first == holder(1) { (p2, holder(2)) } else { (p1, holder(1)) };
        let a = spec
            .convene_with_policy(&[survivor_offer], 100, SelectionPolicy::RoundRobin, &mut state)
            .unwrap();
        assert_eq!(a[0].provider, survivor, "re-clears over the live set → automatic failover");

        assert_eq!(
            spec.convene_with_policy(&[], 100, SelectionPolicy::RoundRobin, &mut state),
            Err(PipelineError::UnfilledRole { service: TextGeneration }),
            "all offline → unfilled, exactly as before",
        );
    }

    #[test]
    fn selection_policy_fields_default_and_old_specs_still_deserialize() {
        // #223 discipline: a PipelineSpec published before selection_policy existed has neither the
        // pipeline field nor a per-role override in its JSON → both must default (LowestFloor /
        // inherit), so old published specs behave exactly as before.
        let json = r#"{"id":"old","roles":[{"service":"TextGeneration","units":1,"tag":"physics"}]}"#;
        let spec: PipelineSpec = serde_json::from_str(json).expect("pre-policy spec still parses");
        assert_eq!(spec.selection_policy, SelectionPolicy::LowestFloor, "pipeline default is LowestFloor");
        assert_eq!(spec.roles[0].selection_policy, None, "role inherits (no override)");
        // And it round-trips (serialize → deserialize is stable), so re-publishing doesn't drift.
        let round: PipelineSpec = serde_json::from_str(&serde_json::to_string(&spec).unwrap()).unwrap();
        assert_eq!(round, spec);
    }

    #[test]
    fn convene_ignores_the_published_policy_but_convene_with_policy_honors_it() {
        // The published pipeline default must NOT leak into the legacy convene() (byte-identical
        // guarantee), yet convene_with_policy(spec.selection_policy, ..) must actually use it.
        let mut spec = physics_spec();
        spec.selection_policy = SelectionPolicy::RoundRobin; // published default = round-robin
        let offers = [
            offer(1, vec![TextGeneration], 20, 50, 1000),
            offer(2, vec![TextGeneration], 20, 50, 1000),
        ];
        // Legacy convene(): still lowest-floor (ties → holder key), so it pins the SAME provider
        // every call regardless of the spec's declared RoundRobin.
        let a = spec.convene(&offers, 100).unwrap()[0].provider;
        let b = spec.convene(&offers, 100).unwrap()[0].provider;
        assert_eq!(a, b, "convene() ignores the published policy and stays deterministic lowest-floor");
        // convene_with_policy(spec.selection_policy, ..) honors it → alternates across the two.
        let mut state = SelectionState::default();
        let w0 = spec.convene_with_policy(&offers, 100, spec.selection_policy, &mut state).unwrap()[0].provider;
        let w1 = spec.convene_with_policy(&offers, 100, spec.selection_policy, &mut state).unwrap()[0].provider;
        assert_ne!(w0, w1, "convene_with_policy applies the pipeline's published RoundRobin default");
    }

    #[test]
    fn per_role_override_beats_the_pipeline_default() {
        // A two-role pipeline: pipeline default = LeastCalls, but one role pins RoundRobin. Each role
        // must clear under its own effective policy (override wins for the role that sets it).
        let spec = PipelineSpec {
            id: "flappy".into(),
            roles: vec![
                RequiredRole {
                    service: TextGeneration,
                    units: 1,
                    tag: "physics".into(),
                    selection_policy: Some(SelectionPolicy::RoundRobin),
                },
                RequiredRole { service: SafetyCheck, units: 1, tag: "guard".into(), selection_policy: None },
            ],
            operator_pubkey_hex: None,
            selection_policy: SelectionPolicy::LeastCalls,
        };
        // physics has two interchangeable text providers; guard has two safety providers.
        let phys_a = offer(1, vec![TextGeneration], 20, 50, 1000);
        let phys_b = offer(2, vec![TextGeneration], 20, 50, 1000);
        let guard_a = offer(3, vec![SafetyCheck], 20, 50, 1000);
        let guard_b = offer(4, vec![SafetyCheck], 20, 50, 1000);
        let offers = [phys_a, phys_b, guard_a, guard_b];
        let mut state = SelectionState::default();

        // Two convenes. physics (override=RoundRobin) must alternate; guard (inherits LeastCalls)
        // balances too, but the point is the override is applied independently per role.
        let r0 = spec.convene_with_policy(&offers, 100, spec.selection_policy, &mut state).unwrap();
        let r1 = spec.convene_with_policy(&offers, 100, spec.selection_policy, &mut state).unwrap();
        assert_ne!(r0[0].provider, r1[0].provider, "physics role rotates under its RoundRobin override");
        assert_ne!(r0[1].provider, r1[1].provider, "guard role balances under the inherited LeastCalls default");
    }

    /// Resolve the two reference providers to their demo names, anything else to a short hex tag.
    fn who_label(pk: &[u8; 32]) -> String {
        if *pk == holder(1) {
            "source-2".into()
        } else if *pk == holder(2) {
            "sink".into()
        } else {
            format!("agent-{:02x}", pk[0])
        }
    }

    #[test]
    fn auction_view_shows_real_signed_bids_with_the_winner_flagged() {
        // #180: the auction view is a real clear, not a fixture — every qualifying offer is a bid
        // with the agent's own signed price/units, and the policy winner is flagged. Two bidders at
        // different floors → lowest-floor wins, both are shown.
        let spec = physics_spec();
        let source2 = offer(1, vec![TextGeneration], 20, 50, 1000);
        let sink = offer(2, vec![TextGeneration], 30, 40, 1000); // cheaper floor, more units
        let view = spec
            .auction_view(&[source2, sink], 100, SelectionPolicy::LowestFloor, &mut SelectionState::default(), who_label)
            .unwrap();
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].role, "physics");
        assert_eq!(view[0].bids.len(), 2, "both agents' offers are shown as bids");
        // Winner first: sink (floor 40) beats source-2 (floor 50); numbers are the offers', not a fixture.
        assert_eq!(view[0].bids[0], RoleBidView { who: "sink".into(), units: 30, price: 40, win: true });
        assert_eq!(view[0].bids[1], RoleBidView { who: "source-2".into(), units: 20, price: 50, win: false });
    }

    #[test]
    fn auction_view_tracks_the_policy_winner_but_always_shows_every_bid() {
        // Under a load-balancing policy the *winner* alternates, but the auction always shows the
        // full field of bidders (one flagged win) — the display stays honest as load shifts.
        let spec = physics_spec();
        let offers = [
            offer(1, vec![TextGeneration], 20, 50, 1000),
            offer(2, vec![TextGeneration], 20, 50, 1000),
        ];
        let mut state = SelectionState::default();
        let mut winners = vec![];
        for _ in 0..2 {
            let v = spec
                .auction_view(&offers, 100, SelectionPolicy::RoundRobin, &mut state, who_label)
                .unwrap();
            assert_eq!(v[0].bids.len(), 2, "both bidders always shown");
            assert_eq!(v[0].bids.iter().filter(|b| b.win).count(), 1, "exactly one winner per clear");
            winners.push(v[0].bids.iter().find(|b| b.win).unwrap().who.clone());
        }
        assert_ne!(winners[0], winners[1], "round-robin moves the winner between the shown bids");
    }

    #[test]
    fn auction_view_errors_when_a_role_has_no_bidder() {
        // No market is shown for a pipeline that cannot convene — same guarantee as `convene`.
        let spec = physics_spec();
        assert_eq!(
            spec.auction_view(&[], 100, SelectionPolicy::LowestFloor, &mut SelectionState::default(), who_label),
            Err(PipelineError::UnfilledRole { service: TextGeneration }),
        );
    }

    #[test]
    fn auction_view_verifies_each_offer_signature_exactly_once_473() {
        // #473: `auction_view` used to call `convene_with_policy` (which validated every offer
        // once per role internally) and THEN re-validate every offer again per role in its own
        // bid-listing loop — `2 * roles * offers` ed25519 verifications per call. After the fix,
        // validity is computed exactly once per call (via `valid_offers`) and reused for both the
        // convene step and the bid listing, regardless of how many roles the pipeline has.
        let spec = physics_spec(); // one role
        let offers = [
            offer(1, vec![TextGeneration], 20, 50, 1000),
            offer(2, vec![TextGeneration], 20, 40, 1000),
            offer(3, vec![TextGeneration], 20, 60, 1000),
        ];
        reset_valid_offers_calls();
        let view = spec
            .auction_view(&offers, 100, SelectionPolicy::LowestFloor, &mut SelectionState::default(), who_label)
            .unwrap();
        assert_eq!(view[0].bids.len(), 3, "sanity: all three offers are real bids");
        assert_eq!(
            valid_offers_calls(),
            1,
            "auction_view must compute the valid offer set exactly once per call, not once per role \
             for the clear plus once again for the bid listing"
        );
    }

    #[test]
    fn auction_view_signature_check_count_does_not_scale_with_role_count_473() {
        // Same guarantee as above, but with TWO roles: before the fix this cost scaled with
        // `roles * offers` inside convene alone, so a naive partial fix could still leave the
        // per-call `valid_offers` count growing with the role count. It must not.
        let spec = PipelineSpec {
            id: "flappy".into(),
            roles: vec![
                RequiredRole { service: TextGeneration, units: 1, tag: "physics".into(), selection_policy: None },
                RequiredRole { service: SafetyCheck, units: 1, tag: "guard".into(), selection_policy: None },
            ],
            operator_pubkey_hex: None,
            selection_policy: SelectionPolicy::LowestFloor,
        };
        let offers = [
            offer(1, vec![TextGeneration], 20, 50, 1000),
            offer(2, vec![SafetyCheck], 20, 50, 1000),
        ];
        reset_valid_offers_calls();
        spec.auction_view(&offers, 100, SelectionPolicy::LowestFloor, &mut SelectionState::default(), who_label)
            .unwrap();
        assert_eq!(valid_offers_calls(), 1, "two roles must not double the signature-verification pass");
    }

    #[test]
    fn convene_with_policy_also_verifies_each_offer_signature_exactly_once_473() {
        // The hoist benefits `convene`/`convene_with_policy` directly too: before the fix,
        // `convene_roles`' per-role loop called `is_valid` once per (role, offer) pair, i.e. the
        // verification pass itself scaled with role count. Now it is computed once per call.
        let spec = PipelineSpec {
            id: "flappy".into(),
            roles: vec![
                RequiredRole { service: TextGeneration, units: 1, tag: "physics".into(), selection_policy: None },
                RequiredRole { service: SafetyCheck, units: 1, tag: "guard".into(), selection_policy: None },
                RequiredRole { service: CodeGeneration, units: 1, tag: "critic".into(), selection_policy: None },
            ],
            operator_pubkey_hex: None,
            selection_policy: SelectionPolicy::LowestFloor,
        };
        let offers = [
            offer(1, vec![TextGeneration], 20, 50, 1000),
            offer(2, vec![SafetyCheck], 20, 50, 1000),
            offer(3, vec![CodeGeneration], 20, 50, 1000),
        ];
        reset_valid_offers_calls();
        spec.convene_with_policy(&offers, 100, SelectionPolicy::LowestFloor, &mut SelectionState::default())
            .unwrap();
        assert_eq!(valid_offers_calls(), 1, "convene_with_policy must verify each offer's signature exactly once");
    }
}
