//! Overlay-topology optimization for the Topology Editor (#107).
//!
//! Given a network's agents and the **candidate links** it may form — the pairs the
//! [`crate::policy`] permits, each annotated with a measured latency — compute the
//! **best-connectivity overlay**. Per the locked design (scimbe, 2026-07-19) the
//! objective is **latency** and the scale is **arbitrary N**, so this is a real graph
//! algorithm, not a heuristic: a **minimum spanning tree** (Kruskal + union-find) over
//! the latency-weighted candidate edges. That yields a connected overlay of `N-1` links
//! whose **total link latency is minimal** while every agent stays reachable, for any N.
//!
//! This is the first, graph-wiring phase (the issue's phased "SDN" answer): it emits an
//! edge-list the controller wires as A2A channels. Later phases can add latency-reducing
//! shortcuts (stretch, cf. #76's smart-routing/shortcut study) and, eventually, real
//! flow-rules — this MST is the connectivity backbone they build on. Pure and
//! deterministic (ties broken by the canonical node pair), so it is exhaustively testable
//! before any live mesh exists.

use serde::{Deserialize, Serialize};

/// A candidate overlay link between two agents and its measured latency cost. The unit
/// is opaque (microseconds by convention); only the ordering matters to the optimizer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeightedLink {
    pub a: String,
    pub b: String,
    /// Lower is better — the optimizer minimizes the total of the chosen links' costs.
    pub cost: u64,
}

impl WeightedLink {
    pub fn new(a: impl Into<String>, b: impl Into<String>, cost: u64) -> Self {
        Self { a: a.into(), b: b.into(), cost }
    }
}

/// The computed overlay: the chosen links (a minimum-latency spanning tree), their total
/// cost, and whether the candidate links could connect **all** the agents.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct OverlayPlan {
    /// The chosen links, each canonical `(a, b)` with `a <= b`, in the order added.
    pub links: Vec<(String, String)>,
    /// Sum of the chosen links' costs.
    pub total_cost: u64,
    /// `true` iff every agent is reachable in the result (a spanning tree exists over the
    /// candidates); `false` means the candidates leave the overlay partitioned — the
    /// operator must allow/measure more links to fully connect it.
    pub connected: bool,
}

/// A minimal union-find (disjoint-set) with path compression + union by size.
struct DisjointSet {
    parent: Vec<usize>,
    size: Vec<usize>,
}

impl DisjointSet {
    fn new(n: usize) -> Self {
        Self { parent: (0..n).collect(), size: vec![1; n] }
    }

    fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            self.parent[x] = self.parent[self.parent[x]]; // path halving
            x = self.parent[x];
        }
        x
    }

    /// Union `x` and `y`; returns `true` if they were in different sets (an edge that
    /// reduces the component count — i.e. one the spanning tree keeps).
    fn union(&mut self, x: usize, y: usize) -> bool {
        let (rx, ry) = (self.find(x), self.find(y));
        if rx == ry {
            return false;
        }
        let (big, small) = if self.size[rx] >= self.size[ry] { (rx, ry) } else { (ry, rx) };
        self.parent[small] = big;
        self.size[big] += self.size[small];
        true
    }
}

/// Canonicalize an unordered link `(a, b)` so `a <= b`.
fn canon(a: &str, b: &str) -> (String, String) {
    if a <= b {
        (a.to_string(), b.to_string())
    } else {
        (b.to_string(), a.to_string())
    }
}

/// Compute the minimum-latency connected overlay over `nodes` using the candidate
/// `links` (each an allowed pair + its measured latency): a minimum spanning tree via
/// Kruskal's algorithm with union-find, for arbitrary N (#107). Deterministic — links are
/// considered in ascending `(cost, canonical-pair)` order, so ties resolve stably.
///
/// A link whose endpoint is not in `nodes`, or a self-loop, is ignored. If the candidates
/// cannot span all nodes the result is the minimum spanning **forest** found so far with
/// `connected = false`. An empty or single-node network is trivially `connected` with no
/// links.
pub fn min_latency_overlay(nodes: &[String], links: &[WeightedLink]) -> OverlayPlan {
    // Map node ids to dense indices; ignore links that reference an unknown node.
    let index: std::collections::HashMap<&str, usize> =
        nodes.iter().enumerate().map(|(i, n)| (n.as_str(), i)).collect();

    // Sort candidate links by (cost, canonical pair) for a deterministic MST.
    let mut sorted: Vec<(u64, String, String, usize, usize)> = links
        .iter()
        .filter_map(|l| {
            if l.a == l.b {
                return None; // self-loop
            }
            let (ia, ib) = (*index.get(l.a.as_str())?, *index.get(l.b.as_str())?);
            let (ca, cb) = canon(&l.a, &l.b);
            Some((l.cost, ca, cb, ia, ib))
        })
        .collect();
    sorted.sort_by(|x, y| (x.0, &x.1, &x.2).cmp(&(y.0, &y.1, &y.2)));

    let mut ds = DisjointSet::new(nodes.len());
    let mut plan = OverlayPlan::default();
    for (cost, ca, cb, ia, ib) in sorted {
        if ds.union(ia, ib) {
            plan.links.push((ca, cb));
            plan.total_cost = plan.total_cost.saturating_add(cost);
            if plan.links.len() == nodes.len().saturating_sub(1) {
                break; // a spanning tree is complete
            }
        }
    }
    plan.connected = plan.links.len() == nodes.len().saturating_sub(1);
    plan
}

/// Extend an overlay `base` (typically a [`min_latency_overlay`] spanning tree) with up
/// to `budget` latency-reducing **shortcut** links beyond the tree backbone (#107 /
/// #76's smart-shortcuts topology). Greedy + deterministic: each round adds the candidate
/// link — not already chosen — that most reduces the overlay's **worst pairwise path
/// latency** (the two agents currently farthest apart get a direct link), until the
/// budget is spent or no remaining candidate shortens any path. Pure; ties broken by the
/// canonical pair. The tree keeps the graph connected, so shortcuts only ever *reduce*
/// path latency — they never disconnect it.
pub fn add_shortcuts(
    nodes: &[String],
    links: &[WeightedLink],
    base: OverlayPlan,
    budget: usize,
) -> OverlayPlan {
    let n = nodes.len();
    if n < 2 || budget == 0 {
        return base;
    }
    let index: std::collections::HashMap<&str, usize> =
        nodes.iter().enumerate().map(|(i, x)| (x.as_str(), i)).collect();

    // Cheapest candidate cost per canonical pair (ignore self-loops / unknown nodes).
    let mut cost: std::collections::HashMap<(usize, usize), u64> = std::collections::HashMap::new();
    for l in links {
        if l.a == l.b {
            continue;
        }
        let (ia, ib) = match (index.get(l.a.as_str()), index.get(l.b.as_str())) {
            (Some(&ia), Some(&ib)) => (ia.min(ib), ia.max(ib)),
            _ => continue,
        };
        cost.entry((ia, ib)).and_modify(|c| *c = (*c).min(l.cost)).or_insert(l.cost);
    }

    let mut chosen: std::collections::HashSet<(usize, usize)> = base
        .links
        .iter()
        .filter_map(|(a, b)| Some((*index.get(a.as_str())?, *index.get(b.as_str())?)))
        .map(|(a, b)| (a.min(b), a.max(b)))
        .collect();

    let inf = u64::MAX / 4;
    let mut plan = base;
    for _ in 0..budget {
        // All-pairs shortest paths over the currently-chosen links (Floyd–Warshall).
        let mut dist = vec![vec![inf; n]; n];
        for (d, di) in dist.iter_mut().enumerate() {
            di[d] = 0;
        }
        for &(a, b) in &chosen {
            // #274: `chosen` seeds from `base.links`, a caller-supplied plan that
            // isn't guaranteed to be built from THIS function's own `links` slice
            // -- a base-link pair with no matching entry in `cost` must never
            // panic a public fn on untrusted/inconsistent input (this ran inside
            // the control-plane's own request path). Treat an unknown cost as
            // `inf`: Floyd-Warshall still runs correctly, it just can't use that
            // pair's real (unknown) weight to discover a cheaper shortcut through
            // it -- a safe, non-panicking degradation, not a correctness bug for
            // any caller whose `base` actually IS derived from `links` (the only
            // supported use today), where every pair already has a cost.
            let c = cost.get(&(a, b)).copied().unwrap_or(inf);
            dist[a][b] = dist[a][b].min(c);
            dist[b][a] = dist[b][a].min(c);
        }
        for k in 0..n {
            for i in 0..n {
                if dist[i][k] == inf {
                    continue;
                }
                for j in 0..n {
                    let via = dist[i][k].saturating_add(dist[k][j]);
                    if via < dist[i][j] {
                        dist[i][j] = via;
                    }
                }
            }
        }
        // Pick the candidate link that most reduces its endpoints' current path latency.
        let mut best: Option<((usize, usize), u64)> = None;
        for (&(a, b), &c) in &cost {
            if chosen.contains(&(a, b)) {
                continue;
            }
            let improvement = dist[a][b].saturating_sub(c);
            if improvement == 0 {
                continue;
            }
            // Deterministic: max improvement, ties broken by the smaller (a, b) pair
            // (the HashMap iteration order is otherwise unspecified).
            let better = match best {
                None => true,
                Some((pair, bi)) => improvement > bi || (improvement == bi && (a, b) < pair),
            };
            if better {
                best = Some(((a, b), improvement));
            }
        }
        match best {
            Some(((a, b), _)) => {
                chosen.insert((a, b));
                let (ca, cb) = canon(&nodes[a], &nodes[b]);
                plan.links.push((ca, cb));
                plan.total_cost = plan.total_cost.saturating_add(cost[&(a, b)]);
            }
            None => break, // no shortcut improves any path
        }
    }
    plan
}

/// Compile a [`Network`](crate::policy::Network) into the concrete overlay to wire (#107
/// controller step): the candidate links are exactly the pairs the network's **policy
/// permits** ([`crate::policy::Network::desired_channels`]), each weighted by its
/// **measured latency** from `latency(a, b)`; the result is the two-phase optimizer's plan
/// — the MST backbone plus up to `shortcut_budget` latency-reducing shortcuts. A pair with
/// no measured latency is dropped (an unmeasured link can't be wired). Policy-forbidden
/// pairs are never candidates, so the plan is always policy-conformant by construction.
/// Pure given `latency`; the controller then compiles each returned link into an A2A
/// channel grant (the per-link grant minting + live establishment is a follow).
pub fn plan_network_overlay<F>(
    network: &crate::policy::Network,
    mut latency: F,
    shortcut_budget: usize,
) -> OverlayPlan
where
    F: FnMut(&str, &str) -> Option<u64>,
{
    let nodes: Vec<String> = network.agents.iter().map(|a| a.id.clone()).collect();
    let links: Vec<WeightedLink> = network
        .desired_channels()
        .into_iter()
        .filter_map(|p| latency(&p.0, &p.1).map(|c| WeightedLink::new(p.0, p.1, c)))
        .collect();
    let base = min_latency_overlay(&nodes, &links);
    add_shortcuts(&nodes, &links, base, shortcut_budget)
}

/// Why a topology was rejected before optimization (#113 preventive). The overlay optimizer is
/// **O(`shortcut_budget` · n³)** — `add_shortcuts` runs Floyd–Warshall over the n agents once
/// per shortcut round — so an unbounded topology is a DoS vector against the control plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopologyTooLarge {
    /// More agents than the caller's `max_agents` policy allows.
    TooManyAgents { agents: usize, max: usize },
    /// A larger shortcut budget than the caller's `max_shortcut_budget` policy allows.
    ShortcutBudgetTooHigh { budget: usize, max: usize },
}

impl std::fmt::Display for TopologyTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TopologyTooLarge::TooManyAgents { agents, max } => {
                write!(f, "topology has {agents} agents, exceeding the limit of {max}")
            }
            TopologyTooLarge::ShortcutBudgetTooHigh { budget, max } => {
                write!(f, "shortcut budget {budget} exceeds the limit of {max}")
            }
        }
    }
}

impl std::error::Error for TopologyTooLarge {}

/// **Size-checked entry point** to [`plan_network_overlay`] (#113 precondition). A live handler
/// MUST call this — not the raw optimizer — so an oversized request can't wedge the control
/// plane: planning is O(`shortcut_budget` · n³), so a large agent count or budget is a DoS
/// vector. Rejects a topology whose agent count exceeds `max_agents`, or whose `shortcut_budget`
/// exceeds `max_shortcut_budget`, **before** any O(n³) work; on acceptance it delegates to
/// [`plan_network_overlay`]. The limits are **parameters** — the caller supplies them as a
/// product policy decided in its request-auth context, deliberately not hardcoded into the pure
/// library fn (both bounds are inclusive).
pub fn plan_network_overlay_bounded<F>(
    network: &crate::policy::Network,
    latency: F,
    shortcut_budget: usize,
    max_agents: usize,
    max_shortcut_budget: usize,
) -> Result<OverlayPlan, TopologyTooLarge>
where
    F: FnMut(&str, &str) -> Option<u64>,
{
    let agents = network.agents.len();
    if agents > max_agents {
        return Err(TopologyTooLarge::TooManyAgents { agents, max: max_agents });
    }
    if shortcut_budget > max_shortcut_budget {
        return Err(TopologyTooLarge::ShortcutBudgetTooHigh {
            budget: shortcut_budget,
            max: max_shortcut_budget,
        });
    }
    Ok(plan_network_overlay(network, latency, shortcut_budget))
}

/// Reduce a link's raw latency **probe samples** (per-sample RTT/one-way costs — opaque
/// unit, microseconds by convention, the same as [`WeightedLink::cost`]) to the single
/// robust cost the overlay optimizer consumes (#107-optimize-follow: the pure half of
/// "edge latency probes feed `plan_network_overlay`'s latency"). Uses the **median**, not
/// the mean: edge latency is right-skewed — a single slow sample (a scheduling hiccup, a
/// retransmit) would inflate a mean and mis-rank an otherwise-fast link (#52's caution about
/// tail samples vs. central tendency), whereas the median is the robust central estimate that
/// keeps [`min_latency_overlay`]'s edge ordering stable. Returns `None` for an empty sample
/// set — an *unmeasured* link the controller must omit from the candidate set rather than
/// wire at an invented cost. Pure and deterministic (it sorts a local copy; input order and
/// duplicates do not change the result).
pub fn link_cost_from_probes(samples: &[u64]) -> Option<u64> {
    if samples.is_empty() {
        return None;
    }
    let mut v = samples.to_vec();
    v.sort_unstable();
    let n = v.len();
    let mid = n / 2;
    Some(if n % 2 == 1 {
        v[mid]
    } else {
        // Floor of the two-middle average, computed as lo + (hi-lo)/2 so it never overflows
        // (a plain (lo+hi)/2 would wrap for costs near u64::MAX).
        let (lo, hi) = (v[mid - 1], v[mid]);
        lo + (hi - lo) / 2
    })
}

/// The routing-approach factor for the #76 overlay study — the single cleanly-isolated
/// independent variable a DoE run pins (#76 **OV3**, `CT_OVERLAY_ROUTING`). Each value
/// selects how the controller wires the agents' A2A channels (#72) for that run, so runs
/// differ in exactly this one factor:
///
/// - [`Baseline`](RoutingApproach::Baseline) — no overlay optimization: every pair relays
///   through the edge (today's path); the control the overlay approaches are measured against.
/// - [`SmartRoute`](RoutingApproach::SmartRoute) — the minimum-latency spanning tree
///   ([`min_latency_overlay`]): a connected `N-1`-link backbone of least total latency.
/// - [`Shortcut`](RoutingApproach::Shortcut) — the spanning tree plus latency-reducing
///   shortcut links ([`add_shortcuts`]): extra links for lower worst-case path latency.
/// - [`RandomMesh`](RoutingApproach::RandomMesh) — a random set of allowed links (the mesh
///   control): connectivity without latency-awareness, isolating what latency-directed
///   wiring actually buys.
///
/// This packet is the factor *selector* only (the enum + its `CT_OVERLAY_ROUTING` parse);
/// threading a pinned value into the live N-agent run + emulator sweep is OV4/OV5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum RoutingApproach {
    /// No overlay optimization — relay through the edge (the study's control).
    #[default]
    Baseline,
    /// Minimum-latency spanning tree ([`min_latency_overlay`]).
    SmartRoute,
    /// Spanning tree + latency-reducing shortcuts ([`add_shortcuts`]).
    Shortcut,
    /// A random allowed-link mesh — connectivity without latency-awareness.
    RandomMesh,
}

impl RoutingApproach {
    /// The canonical `CT_OVERLAY_ROUTING` token — stable across runs, so it can key a
    /// results-CSV column (#76 OV1/OV6) without ambiguity.
    pub fn as_str(&self) -> &'static str {
        match self {
            RoutingApproach::Baseline => "baseline",
            RoutingApproach::SmartRoute => "smart-route",
            RoutingApproach::Shortcut => "shortcut",
            RoutingApproach::RandomMesh => "random-mesh",
        }
    }

    /// Parse the `CT_OVERLAY_ROUTING` factor token. Case-insensitive and accepts `_` as an
    /// alias for `-` (so `SMART_ROUTE` == `smart-route`). An unknown token is an explicit
    /// error — a DoE run must pin a **known** factor level, never silently fall back to the
    /// baseline and thereby mislabel its results.
    pub fn parse(token: &str) -> Result<Self, UnknownRoutingApproach> {
        match token.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "baseline" => Ok(RoutingApproach::Baseline),
            "smart-route" => Ok(RoutingApproach::SmartRoute),
            "shortcut" => Ok(RoutingApproach::Shortcut),
            "random-mesh" => Ok(RoutingApproach::RandomMesh),
            _ => Err(UnknownRoutingApproach(token.to_string())),
        }
    }
}

impl std::str::FromStr for RoutingApproach {
    type Err = UnknownRoutingApproach;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl std::fmt::Display for RoutingApproach {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An unrecognized `CT_OVERLAY_ROUTING` token (echoes the offending value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownRoutingApproach(pub String);

impl std::fmt::Display for UnknownRoutingApproach {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown CT_OVERLAY_ROUTING factor {:?} (expected baseline|smart-route|shortcut|random-mesh)",
            self.0
        )
    }
}

impl std::error::Error for UnknownRoutingApproach {}

#[cfg(test)]
mod tests {
    use super::*;

    fn nodes(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn plan_network_overlay_bounded_rejects_oversized_topologies_before_optimizing() {
        // #113 (frozen): the optimizer is O(budget·n³), so the live entry point must reject an
        // oversized topology BEFORE running it. `plan_network_overlay_bounded` enforces
        // caller-supplied inclusive limits on agent count and shortcut budget.
        use crate::policy::{Agent, AllowRule, Levels, Network, Policy, Selector};

        // A network of `n` all-`dev` agents (dev↔dev permitted, so links exist).
        let net = |n: usize| Network {
            agents: (0..n).map(|i| Agent::new(format!("dev-{i}"), "dev", "internal")).collect(),
            policy: Policy {
                levels: Levels::new(["internal"]),
                rules: vec![AllowRule { from: Selector::group("dev"), to: Selector::group("dev") }],
                mac_flow_control: true,
            },
        };
        let lat = |_a: &str, _b: &str| Some(1u64);

        // Within both limits -> Ok, and it really planned (delegated to plan_network_overlay).
        let ok = plan_network_overlay_bounded(&net(4), lat, 2, 8, 5).expect("within limits");
        assert!(ok.connected, "4 all-permitted dev agents form a connected overlay");

        // Too many agents -> rejected before any O(n³) work, with the offending counts.
        assert_eq!(
            plan_network_overlay_bounded(&net(10), lat, 2, 8, 5),
            Err(TopologyTooLarge::TooManyAgents { agents: 10, max: 8 }),
            "an over-limit agent count is refused"
        );

        // Budget over the cap -> rejected.
        assert_eq!(
            plan_network_overlay_bounded(&net(4), lat, 9, 8, 5),
            Err(TopologyTooLarge::ShortcutBudgetTooHigh { budget: 9, max: 5 }),
            "an over-limit shortcut budget is refused"
        );

        // Both limits are INCLUSIVE: exactly-at-max is accepted.
        assert!(
            plan_network_overlay_bounded(&net(8), lat, 5, 8, 5).is_ok(),
            "agent count == max and budget == max are both allowed (inclusive bounds)"
        );
    }

    #[test]
    fn mst_minimizes_total_latency_and_connects_all_nodes() {
        // Classic 4-node MST: the cheapest spanning tree is a-b(1), b-c(2), a-d(3) = 6,
        // dropping the pricier c-d(4) and a-c(5).
        let ns = nodes(&["a", "b", "c", "d"]);
        let links = vec![
            WeightedLink::new("a", "b", 1),
            WeightedLink::new("b", "c", 2),
            WeightedLink::new("a", "d", 3),
            WeightedLink::new("c", "d", 4),
            WeightedLink::new("a", "c", 5),
        ];
        let plan = min_latency_overlay(&ns, &links);
        assert!(plan.connected, "all nodes reachable");
        assert_eq!(plan.links.len(), 3, "N-1 links");
        assert_eq!(plan.total_cost, 6, "minimum total latency");
        assert_eq!(
            plan.links,
            vec![("a".into(), "b".into()), ("b".into(), "c".into()), ("a".into(), "d".into())],
            "the three cheapest tree links, in ascending cost order"
        );
    }

    #[test]
    fn a_partitioned_candidate_set_reports_not_connected() {
        // {a,b} and {c,d} are each linked but nothing bridges the two components.
        let ns = nodes(&["a", "b", "c", "d"]);
        let links = vec![WeightedLink::new("a", "b", 1), WeightedLink::new("c", "d", 1)];
        let plan = min_latency_overlay(&ns, &links);
        assert!(!plan.connected, "candidates can't span all nodes");
        assert_eq!(plan.links.len(), 2, "the spanning forest is kept");
        assert_eq!(plan.total_cost, 2);
    }

    #[test]
    fn ties_and_unordered_or_bad_links_are_handled_deterministically() {
        // Reversed endpoints canonicalize; a self-loop and an unknown-node link are
        // ignored; equal costs break ties by the canonical pair (a-b before a-c).
        let ns = nodes(&["a", "b", "c"]);
        let links = vec![
            WeightedLink::new("b", "a", 5),      // reversed -> (a,b)
            WeightedLink::new("a", "c", 5),      // same cost -> tie
            WeightedLink::new("a", "a", 1),      // self-loop -> ignored
            WeightedLink::new("a", "ghost", 0),  // unknown node -> ignored
        ];
        let plan = min_latency_overlay(&ns, &links);
        assert!(plan.connected);
        assert_eq!(plan.links, vec![("a".into(), "b".into()), ("a".into(), "c".into())], "tie broken by pair");
        assert_eq!(plan.total_cost, 10);
    }

    #[test]
    fn trivial_networks_are_connected_with_no_links() {
        assert_eq!(min_latency_overlay(&[], &[]), OverlayPlan { links: vec![], total_cost: 0, connected: true });
        let one = min_latency_overlay(&nodes(&["solo"]), &[]);
        assert!(one.connected && one.links.is_empty(), "a single agent needs no links");
    }

    #[test]
    fn shortcuts_cut_the_worst_path_latency_within_budget() {
        // Line a-b-c-d (each hop cost 1): the MST is that line (cost 3), so a<->d costs 3
        // over it. A direct a-d candidate of cost 2 is skipped by the MST (the three cost-1
        // hops span first) but is a genuine shortcut (2 < the 3-hop path).
        let ns = nodes(&["a", "b", "c", "d"]);
        let links = vec![
            WeightedLink::new("a", "b", 1),
            WeightedLink::new("b", "c", 1),
            WeightedLink::new("c", "d", 1),
            WeightedLink::new("a", "d", 2), // shortcut across the ends: dearer than a hop, cheaper than the path
        ];
        let base = min_latency_overlay(&ns, &links);
        assert_eq!(base.links.len(), 3, "MST is the line (a-d not needed for connectivity)");
        assert!(!base.links.contains(&("a".to_string(), "d".to_string())), "the line MST excludes a-d");

        // Budget 1 adds the highest-improvement shortcut: a-d (path 3 -> direct 2).
        let one = add_shortcuts(&ns, &links, base.clone(), 1);
        assert_eq!(one.links.len(), 4, "one shortcut added");
        assert!(one.links.contains(&("a".to_string(), "d".to_string())), "the a-d shortcut");
        assert_eq!(one.total_cost, base.total_cost + 2);

        // Budget 0 is a no-op; a huge budget adds no more once no path improves.
        assert_eq!(add_shortcuts(&ns, &links, base.clone(), 0), base, "budget 0 -> unchanged");
        let maxed = add_shortcuts(&ns, &links, base.clone(), 100);
        assert_eq!(maxed.links.len(), 4, "only the improving shortcut is added, then it stops");
    }

    #[test]
    fn shortcuts_are_a_noop_when_no_candidate_improves_a_path() {
        // A triangle where every pair is already a direct MST/base edge -> no shortcut helps.
        let ns = nodes(&["a", "b", "c"]);
        let links = vec![WeightedLink::new("a", "b", 1), WeightedLink::new("b", "c", 1)];
        let base = min_latency_overlay(&ns, &links); // a-b, b-c
        // Only candidate not chosen would be... none improving (no a-c candidate exists).
        let out = add_shortcuts(&ns, &links, base.clone(), 5);
        assert_eq!(out, base, "no improving candidate -> unchanged");
    }

    #[test]
    fn add_shortcuts_never_panics_on_a_base_link_absent_from_the_links_slice_274() {
        // #274: `base` is a caller-supplied OverlayPlan, not guaranteed to have been
        // built from the SAME `links` slice passed alongside it -- a base link with no
        // matching cost entry must degrade gracefully (treated as an unknown/infinite
        // cost), never panic this public fn on inconsistent input.
        let ns = nodes(&["a", "b", "c"]);
        let base = OverlayPlan {
            links: vec![("a".to_string(), "b".to_string())], // NOT present in `links` below
            total_cost: 999,
            connected: true,
        };
        let links = vec![WeightedLink::new("b", "c", 1)]; // unrelated candidate set
        let out = add_shortcuts(&ns, &links, base.clone(), 3); // must not panic
        // The inconsistent base link is preserved as-is (never removed); no crash.
        assert!(out.links.contains(&("a".to_string(), "b".to_string())));
    }

    #[test]
    fn plan_network_overlay_wires_only_policy_permitted_links_by_latency() {
        use crate::policy::{Agent, AllowRule, Levels, Network, Policy, Selector};

        // dev + ops may connect (both ways, same level); finance is isolated by policy.
        let net = Network {
            agents: vec![
                Agent::new("dev-1", "dev", "internal"),
                Agent::new("dev-2", "dev", "internal"),
                Agent::new("ops-1", "ops", "internal"),
                Agent::new("fin-1", "finance", "internal"),
            ],
            policy: Policy {
                levels: Levels::new(["public", "internal", "secret"]),
                rules: vec![
                    AllowRule { from: Selector::group("dev"), to: Selector::group("dev") },
                    AllowRule { from: Selector::group("dev"), to: Selector::group("ops") },
                    AllowRule { from: Selector::group("ops"), to: Selector::group("dev") },
                ],
                mac_flow_control: true,
            },
        };
        // Measured latencies (symmetric); finance links are permitted by NO policy rule,
        // so they never become candidates even though we'd "measure" them.
        let lat = |a: &str, b: &str| -> Option<u64> {
            let (x, y) = if a <= b { (a, b) } else { (b, a) };
            match (x, y) {
                ("dev-1", "dev-2") => Some(1),
                ("dev-1", "ops-1") => Some(2),
                ("dev-2", "ops-1") => Some(3),
                _ => Some(9), // e.g. any finance pair — but policy excludes them upstream
            }
        };

        // No shortcuts: the MST over the 3 permitted dev/ops links (1,2,3) = {dev1-dev2,
        // dev1-ops1}, total 3, and fin-1 is left unconnected (policy isolates it).
        let plan = plan_network_overlay(&net, lat, 0);
        assert_eq!(
            plan.links,
            vec![("dev-1".into(), "dev-2".into()), ("dev-1".into(), "ops-1".into())]
        );
        assert_eq!(plan.total_cost, 3);
        assert!(!plan.connected, "fin-1 is policy-isolated, so the overlay can't span it");
        // No finance link ever appears — the plan is policy-conformant by construction.
        assert!(!plan.links.iter().any(|(a, b)| a.starts_with("fin") || b.starts_with("fin")));

        // Here the only unchosen candidate (dev2-ops1, cost 3) equals its current path
        // latency (dev2-dev1-ops1 = 3), so no shortcut improves anything and a budget adds
        // nothing — assert the plan never regresses (shortcuts only ever add links).
        let with_budget = plan_network_overlay(&net, lat, 5);
        assert!(with_budget.links.len() >= plan.links.len(), "shortcuts never drop links");
        assert_eq!(with_budget.links.len(), 2, "no candidate improves a path -> no shortcut");
    }

    #[test]
    fn overlay_plan_round_trips_through_serde() {
        let plan = min_latency_overlay(&nodes(&["a", "b", "c"]), &[
            WeightedLink::new("a", "b", 2),
            WeightedLink::new("b", "c", 3),
        ]);
        let json = serde_json::to_string(&plan).unwrap();
        assert_eq!(serde_json::from_str::<OverlayPlan>(&json).unwrap(), plan);
    }

    #[test]
    fn routing_approach_parses_the_four_doe_factor_levels_and_rejects_unknown() {
        // #76 OV3: the DoE factor selector. Every level parses, round-trips its canonical
        // CT_OVERLAY_ROUTING token, and an unknown token is an explicit error (never a
        // silent fallback to baseline — that would mislabel a run's results).
        use RoutingApproach::*;
        for (token, approach) in [
            ("baseline", Baseline),
            ("smart-route", SmartRoute),
            ("shortcut", Shortcut),
            ("random-mesh", RandomMesh),
        ] {
            assert_eq!(RoutingApproach::parse(token), Ok(approach), "{token} parses");
            // Canonical token round-trips: as_str() is exactly the accepted token.
            assert_eq!(approach.as_str(), token);
            assert_eq!(RoutingApproach::parse(approach.as_str()), Ok(approach));
            // Display == as_str, and FromStr agrees with parse.
            assert_eq!(approach.to_string(), token);
            assert_eq!(token.parse::<RoutingApproach>(), Ok(approach));
        }

        // Case-insensitive + `_` alias for `-` (env values are forgiving on separator/case).
        assert_eq!(RoutingApproach::parse("SMART_ROUTE"), Ok(SmartRoute));
        assert_eq!(RoutingApproach::parse("  Random_Mesh  "), Ok(RandomMesh));

        // Default is the control (baseline).
        assert_eq!(RoutingApproach::default(), Baseline);

        // An unknown factor is rejected and the offending token is echoed.
        let err = RoutingApproach::parse("mesh-routing").unwrap_err();
        assert_eq!(err, UnknownRoutingApproach("mesh-routing".to_string()));
        assert!(err.to_string().contains("mesh-routing"));
    }

    #[test]
    fn link_cost_from_probes_is_the_robust_median_and_none_when_unmeasured() {
        // #107-optimize-follow (pure half): reduce a link's probe samples to the cost the
        // optimizer consumes. Empty = unmeasured -> None (omit the link, never invent a cost).
        assert_eq!(link_cost_from_probes(&[]), None);
        // Single sample is its own median.
        assert_eq!(link_cost_from_probes(&[42]), Some(42));
        // Odd n: the middle order statistic, independent of input order.
        assert_eq!(link_cost_from_probes(&[30, 10, 20]), Some(20));
        // Even n: floor of the two-middle midpoint (sorted [10,20,30,40] -> (20+30)/2 = 25).
        assert_eq!(link_cost_from_probes(&[40, 10, 30, 20]), Some(25));
        // Robust to a right-tail outlier: one huge sample does NOT move the median the way a
        // mean would (#52 — tail samples must not distort the central-tendency link cost).
        assert_eq!(link_cost_from_probes(&[10, 10, 10, 10, 1_000_000]), Some(10));
        // No overflow for costs near u64::MAX (a plain (lo+hi)/2 would wrap).
        assert_eq!(
            link_cost_from_probes(&[u64::MAX, u64::MAX - 1]),
            Some(u64::MAX - 1)
        );
        // Duplicates and order do not change the result.
        assert_eq!(
            link_cost_from_probes(&[5, 5, 9, 1]),
            link_cost_from_probes(&[9, 1, 5, 5])
        );
    }
}
