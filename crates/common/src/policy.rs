//! Policy decision engine for the intent-/policy-driven mesh control plane (#102).
//!
//! A pure, wire-serializable **RBAC + MAC** (label flow-control) evaluator. Given a
//! declarative [`Policy`] — ordered security levels, default-deny allow-rules, and an
//! optional mandatory no-write-down constraint — and two agents, it decides whether
//! `from` may establish a directed flow to `to`, with a human/AI-legible reason.
//!
//! This is the SDN-style control plane's core, independent of the live mesh — it is a
//! pure decision function, tested standalone, with no live caller today. The intended
//! end state (#102) is that the controller compiles a declaration into channel grants
//! from it, the edge broker consults it at channel admission, and an MCP `net.explain`
//! tool renders its [`Decision`] — **none of that wiring exists yet** (#235): the edge
//! broker's admission path never references this module, and there is no `explain` MCP
//! tool. Until that wiring lands, this is a network-*planning* tool, not a live control;
//! the actually-enforced access control today is channel admission itself. Two
//! access-control models compose, matching the locked design in #102:
//!
//! * **RBAC** (discretionary): default-deny — a flow is permitted only if at least one
//!   [`AllowRule`] matches the `(from, to)` pair by group and/or label.
//! * **MAC** (mandatory, non-discretionary): when [`Policy::mac_flow_control`] is on,
//!   a Bell–LaPadula **no-write-down** rule overrides RBAC — a higher-level `from` may
//!   never initiate a flow to a lower-level `to`, so sensitive data cannot leak down a
//!   level even if an allow-rule would otherwise permit it.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// An agent's policy attributes: its RBAC `group` and its security `label`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Agent {
    /// Stable agent id (for reasons/audit).
    pub id: String,
    /// RBAC group / role (e.g. `dev`, `ops`, `finance`).
    pub group: String,
    /// Security label; must appear in [`Levels`] when MAC is enforced.
    pub label: String,
}

impl Agent {
    /// Convenience constructor.
    pub fn new(id: impl Into<String>, group: impl Into<String>, label: impl Into<String>) -> Self {
        Self { id: id.into(), group: group.into(), label: label.into() }
    }
}

/// Ordered security levels, least→most sensitive (e.g. `public < internal < secret`).
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Levels {
    /// Labels in ascending sensitivity; index is the rank.
    pub order: Vec<String>,
}

impl Levels {
    /// Build from an ordered (least→most sensitive) list of labels.
    pub fn new<I, S>(order: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self { order: order.into_iter().map(Into::into).collect() }
    }

    /// The rank of `label` (0 = least sensitive), or `None` if it is not a known level.
    pub fn rank(&self, label: &str) -> Option<usize> {
        self.order.iter().position(|l| l == label)
    }
}

/// Selects a set of agents by (optionally) group and/or label. A `None` field matches
/// any value; an all-`None` selector matches every agent.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Selector {
    /// Match this RBAC group, or any group when `None`.
    #[serde(default)]
    pub group: Option<String>,
    /// Match this security label, or any label when `None`.
    #[serde(default)]
    pub label: Option<String>,
}

impl Selector {
    /// A selector matching every agent (both fields unconstrained).
    pub fn any() -> Self {
        Self::default()
    }

    /// A selector matching a group (any label).
    pub fn group(group: impl Into<String>) -> Self {
        Self { group: Some(group.into()), label: None }
    }

    fn matches(&self, a: &Agent) -> bool {
        self.group.as_ref().is_none_or(|g| g == &a.group)
            && self.label.as_ref().is_none_or(|l| l == &a.label)
    }
}

/// A default-deny **allow-rule**: agents matching `from` may initiate a directed flow
/// to agents matching `to`. Absent any matching rule, the flow is denied.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowRule {
    pub from: Selector,
    pub to: Selector,
}

/// A network's declarative policy (#102): ordered security levels, default-deny
/// allow-rules, and whether the mandatory no-write-down flow constraint is enforced.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Policy {
    /// Ordered security levels; only consulted when `mac_flow_control` is on.
    #[serde(default)]
    pub levels: Levels,
    /// Default-deny allow-rules (RBAC). A flow needs at least one match.
    #[serde(default)]
    pub rules: Vec<AllowRule>,
    /// Enforce Bell–LaPadula no-write-down on `levels`: a higher-level `from` may not
    /// initiate a flow to a lower-level `to` (mandatory — overrides the allow-rules).
    #[serde(default)]
    pub mac_flow_control: bool,
}

/// The outcome of a policy check: allow/deny + a human/AI-legible reason (rendered by
/// the MCP `net.explain` tool and used in the broker's `NO <reason>` refusal).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub reason: String,
}

impl Decision {
    fn deny(reason: String) -> Self {
        Self { allowed: false, reason }
    }
    fn allow(reason: String) -> Self {
        Self { allowed: true, reason }
    }
}

impl Policy {
    /// Decide whether `from` may establish a **directed** flow to `to`.
    ///
    /// Mandatory access control is checked first and overrides RBAC: with
    /// `mac_flow_control` on, a write-down (`rank(from) > rank(to)`) is denied even if
    /// an allow-rule matches, and an unknown label fails closed. Otherwise the flow is
    /// allowed iff at least one [`AllowRule`] matches (default-deny).
    pub fn evaluate(&self, from: &Agent, to: &Agent) -> Decision {
        if self.mac_flow_control {
            match (self.levels.rank(&from.label), self.levels.rank(&to.label)) {
                (Some(rf), Some(rt)) => {
                    if rf > rt {
                        return Decision::deny(format!(
                            "MAC write-down blocked: {} ({}) may not initiate a flow to lower level {} ({})",
                            from.id, from.label, to.id, to.label
                        ));
                    }
                }
                _ => {
                    return Decision::deny(format!(
                        "MAC enabled but a label is not a known level (from={}, to={})",
                        from.label, to.label
                    ));
                }
            }
        }
        if self.rules.iter().any(|r| r.from.matches(from) && r.to.matches(to)) {
            Decision::allow(format!(
                "allowed: an allow-rule permits {} ({}/{}) -> {} ({}/{})",
                from.id, from.group, from.label, to.id, to.group, to.label
            ))
        } else {
            Decision::deny(format!(
                "default-deny: no allow-rule permits {} ({}/{}) -> {} ({}/{})",
                from.id, from.group, from.label, to.id, to.group, to.label
            ))
        }
    }

    /// Decide whether `a` and `b` may **establish a channel** — a bidirectional flow,
    /// so it is permitted only if the directed flow is allowed **both** ways. Returns
    /// the first-denied direction's [`Decision`] (so the reason names the actual
    /// blocker), else an allow. This is the check the edge broker applies at channel
    /// admission (a cross-level pair is refused because one direction is a write-down).
    pub fn may_establish_channel(&self, a: &Agent, b: &Agent) -> Decision {
        let ab = self.evaluate(a, b);
        if !ab.allowed {
            return ab;
        }
        let ba = self.evaluate(b, a);
        if !ba.allowed {
            return ba;
        }
        Decision::allow(format!("allowed: {} and {} may establish a channel (both directions permitted)", a.id, b.id))
    }
}

/// An unordered pair of agent ids — a channel is between two agents, so `(a, b)` and
/// `(b, a)` are the same pair. Canonicalized (sorted) on construction so it dedups and
/// compares regardless of argument order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Pair(pub String, pub String);

impl Pair {
    /// Build the canonical (sorted) pair of two agent ids.
    pub fn new(a: impl Into<String>, b: impl Into<String>) -> Self {
        let (a, b) = (a.into(), b.into());
        if a <= b {
            Pair(a, b)
        } else {
            Pair(b, a)
        }
    }
}

/// A tenant's declared network (#102): the member agents and the [`Policy`] governing
/// who may talk to whom. The declarative desired state the SDN-style controller
/// reconciles the live mesh toward.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Network {
    /// The agents that are members of this network.
    #[serde(default)]
    pub agents: Vec<Agent>,
    /// The policy governing channel establishment between them.
    #[serde(default)]
    pub policy: Policy,
}

impl Network {
    /// #275: reject duplicate agent ids before this `Network` is ever used. Without
    /// this, `min_latency_overlay`'s id->index map silently collapses two agents
    /// with the same id to one index -- the other becomes an unreachable overlay
    /// component with no error (`plan.connected` just reports `false`), and
    /// `explain(id, ...)` silently resolves to whichever duplicate happens to be
    /// first, both with zero diagnostic pointing at the actual cause (a typo'd
    /// duplicate id). Called at the REST deserialization boundary
    /// (`PUT /me/networks/:id`) so a malformed declaration is a clear 400, not a
    /// silently-partitioned overlay discovered later.
    pub fn validate(&self) -> Result<(), String> {
        let mut seen = std::collections::HashSet::with_capacity(self.agents.len());
        for a in &self.agents {
            if !seen.insert(a.id.as_str()) {
                return Err(format!("duplicate agent id: {:?}", a.id));
            }
        }
        Ok(())
    }

    /// Explain whether agents `a_id` and `b_id` may establish a channel under this
    /// network's policy — the **`net.explain(a, b) → allowed? why`** decision (#102 MCP /
    /// broker-enforce): resolve both ids to members, then
    /// [`Policy::may_establish_channel`]. An id that is not a member is a **deny** with a
    /// clear reason (fail-closed) — you can't reason about an agent outside the network.
    pub fn explain(&self, a_id: &str, b_id: &str) -> Decision {
        let a = self.agents.iter().find(|x| x.id == a_id);
        let b = self.agents.iter().find(|x| x.id == b_id);
        match (a, b) {
            (Some(a), Some(b)) => self.policy.may_establish_channel(a, b),
            _ => Decision::deny(format!(
                "not both members of the network: {a_id} / {b_id}"
            )),
        }
    }

    /// The set of agent-pairs that **may** establish a channel under the policy — the
    /// desired connectivity. A pair is included iff
    /// [`Policy::may_establish_channel`] allows it (bidirectional). Self-pairs are
    /// excluded; the result is canonicalized (each pair once, order-independent).
    pub fn desired_channels(&self) -> BTreeSet<Pair> {
        let mut out = BTreeSet::new();
        for (i, a) in self.agents.iter().enumerate() {
            for b in &self.agents[i + 1..] {
                if a.id == b.id {
                    continue;
                }
                if self.policy.may_establish_channel(a, b).allowed {
                    out.insert(Pair::new(&a.id, &b.id));
                }
            }
        }
        out
    }
}

/// The diff between a network's desired connectivity and what is live now (#102): the
/// channels to **establish** (compile grants for + bring up) and to **revoke** (tear
/// down), so the controller makes the live mesh match the declaration. A pure set diff —
/// the actual grant minting / teardown is the caller's job.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reconciliation {
    /// In desired but not live — bring these channels up.
    pub to_establish: Vec<Pair>,
    /// Live but no longer desired — tear these channels down.
    pub to_revoke: Vec<Pair>,
}

impl Reconciliation {
    /// Whether the live mesh already matches the desired state (nothing to do).
    pub fn is_empty(&self) -> bool {
        self.to_establish.is_empty() && self.to_revoke.is_empty()
    }
}

/// Compute the reconciliation from `desired` (e.g. [`Network::desired_channels`]) against
/// the `current` live channel set: `to_establish = desired − current`,
/// `to_revoke = current − desired`. Deterministic (sorted) output.
pub fn reconcile(desired: &BTreeSet<Pair>, current: &BTreeSet<Pair>) -> Reconciliation {
    Reconciliation {
        to_establish: desired.difference(current).cloned().collect(),
        to_revoke: current.difference(desired).cloned().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The "verteilte Firma" fixture from #102: segments dev/ops/finance at levels
    /// internal/secret, default-deny with a small allow-list and MAC on.
    fn company_policy() -> Policy {
        Policy {
            levels: Levels::new(["public", "internal", "secret"]),
            rules: vec![
                // dev may talk within dev and out to ops; finance may talk within finance.
                AllowRule { from: Selector::group("dev"), to: Selector::group("dev") },
                AllowRule { from: Selector::group("dev"), to: Selector::group("ops") },
                AllowRule { from: Selector::group("ops"), to: Selector::group("dev") },
                AllowRule { from: Selector::group("finance"), to: Selector::group("finance") },
            ],
            mac_flow_control: true,
        }
    }

    #[test]
    fn rbac_allows_a_permitted_pair_and_default_denies_the_rest() {
        let p = company_policy();
        let dev = Agent::new("dev-1", "dev", "internal");
        let ops = Agent::new("ops-1", "ops", "internal");
        let fin = Agent::new("fin-1", "finance", "internal");

        // An allow-rule permits dev -> ops (same level, so MAC is satisfied).
        let d = p.evaluate(&dev, &ops);
        assert!(d.allowed, "dev->ops permitted: {}", d.reason);

        // No rule permits dev -> finance: default-deny.
        let d = p.evaluate(&dev, &fin);
        assert!(!d.allowed, "dev->finance must be default-denied");
        assert!(d.reason.contains("default-deny"), "reason: {}", d.reason);
    }

    #[test]
    fn mac_blocks_write_down_but_allows_write_up_even_with_a_matching_rule() {
        let p = company_policy();
        let fin_secret = Agent::new("fin-s", "finance", "secret");
        let fin_internal = Agent::new("fin-i", "finance", "internal");

        // finance->finance rule matches BOTH ways, but MAC overrides:
        // secret -> internal is a write-down -> denied.
        let down = p.evaluate(&fin_secret, &fin_internal);
        assert!(!down.allowed, "write-down must be blocked despite the allow-rule");
        assert!(down.reason.contains("write-down"), "reason: {}", down.reason);

        // internal -> secret is a write-up -> allowed (rule matches, MAC satisfied).
        let up = p.evaluate(&fin_internal, &fin_secret);
        assert!(up.allowed, "write-up permitted: {}", up.reason);
    }

    #[test]
    fn mac_fails_closed_on_an_unknown_label() {
        let p = company_policy();
        let known = Agent::new("a", "dev", "internal");
        let unknown = Agent::new("b", "dev", "top-secret"); // not in the level order
        let d = p.evaluate(&known, &unknown);
        assert!(!d.allowed && d.reason.contains("not a known level"), "reason: {}", d.reason);
    }

    #[test]
    fn channel_establishment_needs_both_directions_and_refuses_cross_level() {
        let p = company_policy();
        let dev1 = Agent::new("dev-1", "dev", "internal");
        let dev2 = Agent::new("dev-2", "dev", "internal");
        let ops = Agent::new("ops-1", "ops", "internal");
        let fin_i = Agent::new("fin-i", "finance", "internal");
        let fin_s = Agent::new("fin-s", "finance", "secret");

        // Same group + level, rule both ways -> a channel forms.
        assert!(p.may_establish_channel(&dev1, &dev2).allowed, "dev<->dev channel allowed");
        // dev<->ops: rules exist both ways (dev->ops, ops->dev), same level -> allowed.
        assert!(p.may_establish_channel(&dev1, &ops).allowed, "dev<->ops channel allowed");
        // finance internal<->secret: one direction is a write-down -> channel refused.
        let d = p.may_establish_channel(&fin_i, &fin_s);
        assert!(!d.allowed && d.reason.contains("write-down"), "cross-level channel refused: {}", d.reason);
        // dev<->finance: no rule at all -> refused.
        assert!(!p.may_establish_channel(&dev1, &fin_i).allowed, "dev<->finance channel refused");
    }

    #[test]
    fn policy_round_trips_through_serde() {
        let p = company_policy();
        let json = serde_json::to_string(&p).unwrap();
        let back: Policy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back, "policy survives a JSON round-trip (REST/OpenAPI surface)");
    }

    #[test]
    fn pair_is_canonical_regardless_of_order() {
        assert_eq!(Pair::new("b", "a"), Pair::new("a", "b"));
        assert_eq!(Pair::new("a", "b"), Pair("a".into(), "b".into()));
    }

    #[test]
    fn network_desired_channels_compiles_only_policy_permitted_pairs() {
        let net = Network {
            agents: vec![
                Agent::new("dev-1", "dev", "internal"),
                Agent::new("dev-2", "dev", "internal"),
                Agent::new("ops-1", "ops", "internal"),
                Agent::new("fin-i", "finance", "internal"),
                Agent::new("fin-s", "finance", "secret"),
            ],
            policy: company_policy(),
        };
        let desired = net.desired_channels();
        // dev<->dev and dev<->ops (rules both ways, same level) are allowed…
        assert!(desired.contains(&Pair::new("dev-1", "dev-2")));
        assert!(desired.contains(&Pair::new("dev-1", "ops-1")));
        assert!(desired.contains(&Pair::new("dev-2", "ops-1")));
        // …dev<->finance has no rule, and finance internal<->secret is a MAC write-down,
        // so neither is a desired channel.
        assert!(!desired.contains(&Pair::new("dev-1", "fin-i")));
        assert!(!desired.contains(&Pair::new("fin-i", "fin-s")));
        assert_eq!(desired.len(), 3, "exactly the three mutually-permitted pairs");
    }

    #[test]
    fn network_validate_rejects_duplicate_agent_ids_275() {
        let dup = Network {
            agents: vec![
                Agent::new("worker", "dev", "internal"),
                Agent::new("ops-1", "ops", "internal"),
                Agent::new("worker", "dev", "internal"), // typo'd duplicate id
            ],
            policy: company_policy(),
        };
        let err = dup.validate().expect_err("duplicate agent id must be rejected");
        assert!(err.contains("worker"), "error names the duplicate id: {err}");

        let unique = Network {
            agents: vec![Agent::new("dev-1", "dev", "internal"), Agent::new("ops-1", "ops", "internal")],
            policy: company_policy(),
        };
        assert!(unique.validate().is_ok(), "no duplicates -> valid");

        assert!(Network::default().validate().is_ok(), "no agents at all -> trivially valid");
    }

    #[test]
    fn network_explain_answers_allowed_and_why_for_two_agent_ids() {
        // #102 net.explain: resolve two ids and return the policy decision + reason.
        let net = Network {
            agents: vec![
                Agent::new("dev-1", "dev", "internal"),
                Agent::new("ops-1", "ops", "internal"),
                Agent::new("fin-i", "finance", "internal"),
                Agent::new("fin-s", "finance", "secret"),
            ],
            policy: company_policy(),
        };
        // A permitted pair -> allowed.
        assert!(net.explain("dev-1", "ops-1").allowed, "dev<->ops permitted");
        // No rule -> denied, with a legible reason.
        let d = net.explain("dev-1", "fin-i");
        assert!(!d.allowed && d.reason.contains("default-deny"), "reason: {}", d.reason);
        // A MAC write-down cross-level pair -> denied at the channel (one direction down).
        let m = net.explain("fin-i", "fin-s");
        assert!(!m.allowed && m.reason.contains("write-down"), "reason: {}", m.reason);
        // An unknown agent id -> fail-closed deny.
        let u = net.explain("dev-1", "ghost");
        assert!(!u.allowed && u.reason.contains("not both members"), "reason: {}", u.reason);
    }

    #[test]
    fn reconcile_diffs_desired_against_the_live_mesh() {
        let net = Network {
            agents: vec![
                Agent::new("dev-1", "dev", "internal"),
                Agent::new("dev-2", "dev", "internal"),
                Agent::new("ops-1", "ops", "internal"),
            ],
            policy: company_policy(),
        };
        let desired = net.desired_channels(); // {dev1-dev2, dev1-ops1, dev2-ops1}

        // Live now: dev1-dev2 is already up; dev1-fin-i is stale (policy no longer
        // permits it — the agent left / the rule changed).
        let current: BTreeSet<Pair> =
            [Pair::new("dev-1", "dev-2"), Pair::new("dev-1", "fin-i")].into_iter().collect();

        let r = reconcile(&desired, &current);
        // Establish the two missing allowed channels; revoke the stale one.
        assert_eq!(r.to_establish, vec![Pair::new("dev-1", "ops-1"), Pair::new("dev-2", "ops-1")]);
        assert_eq!(r.to_revoke, vec![Pair::new("dev-1", "fin-i")]);
        assert!(!r.is_empty());

        // Reconciling the desired state against itself is a no-op.
        assert!(reconcile(&desired, &desired).is_empty(), "converged mesh needs no changes");
    }
}
