//! Waits until a DNS-01 TXT record is served by **every** deSEC anycast node,
//! not merely by whichever node happens to be nearest.
//!
//! ## Why the obvious check does not work (#229)
//!
//! `ns1.desec.io` and `ns2.desec.org` are not two servers — each is an anycast
//! address fronting ~6 nodes spread across continents. Querying them from any
//! single vantage point reaches the *nearest* node of each cloud and says
//! nothing about the rest. Measured on this deployment's own zone, publishing
//! one TXT record and polling every node individually:
//!
//! ```text
//! +0s     8/12 nodes have it   ns1 says YES   ns2 says no
//! +26s   11/12 (jnb-1 missing) ns1 says YES   ns2 says no
//! +126s  11/12 (jnb-1 missing) ns1 says YES   ns2 says YES   <- both anycast names agree
//! +152s  12/12                                               <- actually converged
//! ```
//!
//! So `ns1` reported success while a third of the fleet did not have the
//! record, and *both* anycast names agreed a full 26 seconds before the last
//! node caught up. Let's Encrypt validates from several geographically
//! separate perspectives (multi-perspective validation, CA/Browser Forum
//! SC-067), so it reaches those lagging nodes — which is exactly how a
//! challenge fails with `NXDOMAIN` moments after a local check said the
//! record was live.
//!
//! deSEC exposes each node under its own unicast hostname (`<site>.a.desec.io`
//! / `<site>.c.desec.io`), so global convergence *is* directly observable —
//! just not through the anycast names. deSEC's own maintainers acknowledge
//! replication "isn't always real-time" and should "converge within a few
//! minutes max"; independent user measurements of 107–170s match what is
//! measured above, with the Johannesburg node consistently the slowest.
//!
//! This check belongs on the operator's control plane rather than in the
//! agent: the control plane already writes the record and knows the backend
//! is deSEC, and putting it here means an agent needs no outbound DNS at all
//! — which matters, because a reporting agent's host had UDP/53 blocked
//! entirely and could not run any authoritative check of its own.

use std::time::{Duration, Instant};

use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::Resolver;

/// deSEC's per-node hostnames, discovered by probing and confirmed to resolve
/// to distinct unicast addresses. Two independent anycast clouds (`a` and
/// `c`); a node that no longer resolves is skipped rather than treated as
/// lagging, so this list going stale degrades the check instead of breaking
/// issuance.
pub const DESEC_NODES: &[&str] = &[
    "fra-1.a.desec.io",
    "fra-1.c.desec.io",
    "ams-1.a.desec.io",
    "lhr-1.c.desec.io",
    "dfw-1.a.desec.io",
    "lax-1.c.desec.io",
    "jnb-1.a.desec.io",
    "sin-1.c.desec.io",
    "hkg-1.a.desec.io",
    "syd-1.a.desec.io",
    "scl-1.c.desec.io",
    "dxb-1.c.desec.io",
];

/// Measured worst case here was 152s and independent reports reach ~170s, so
/// this leaves real headroom. Overshooting only makes issuance slower;
/// undershooting hands Let's Encrypt a record its remote perspectives cannot
/// see yet, which costs a whole failed authorization.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// Outcome of waiting for a record to reach every node.
#[derive(Debug, Clone, PartialEq)]
pub enum Convergence {
    /// Every node that answered is serving the expected value.
    Converged { nodes: usize, took: Duration },
    /// Ran out of time. #488: split into two separately-tracked sets that used
    /// to be conflated into one ambiguous `lagging` list --
    /// `lagging` is nodes that DID resolve and respond (a TXT miss the node's
    /// own SOA proved was answered by a live server) but simply don't have the
    /// expected value yet -- ordinary replication delay, "the provider is
    /// slow". `unreachable` is nodes that resolved but never answered ANY
    /// query (TXT or SOA) on ANY of their addresses -- something on the path
    /// between here and that one specific node is broken (a firewall rule, a
    /// routing black hole), a materially different fault from provider lag,
    /// and one the caller/operator needs to know about separately since it is
    /// a fact about reachability from THIS vantage point, not about the
    /// provider's own propagation.
    TimedOut { lagging: Vec<String>, unreachable: Vec<String> },
    /// Not one node could be reached — this says something about *our* network,
    /// not about propagation, so the caller must not read it as failure.
    NoNodesReachable,
    /// #265: [`ConvergenceCoalescer::MAX_CONCURRENT_POLLERS`] distinct polls were
    /// already in flight and this caller did not get a slot within
    /// [`ConvergenceCoalescer::PERMIT_WAIT`] — distinct from [`Convergence::TimedOut`]
    /// (which means deSEC itself is slow) so a caller/operator can tell "the DNS
    /// provider is lagging" apart from "this control plane is under a concurrent-key
    /// burst, retry shortly".
    Saturated,
}

/// Poll every node in `nodes` until all of them serve `expected` for `name`,
/// a record in `zone` (used only for the SOA reachability probe below --
/// pass the zone the caller already knows, e.g. from its own `DesecClient`,
/// rather than have this module guess it from `name`).
pub async fn wait_for_convergence(
    nodes: &[&str],
    zone: &str,
    name: &str,
    expected: &str,
    timeout: Duration,
) -> Convergence {
    let started = Instant::now();
    let deadline = started + timeout;
    // #485: resolve_nodes itself now resolves every hostname concurrently (see
    // its own doc comment), but this outer timeout is a second, independent
    // safety net -- even a fully concurrent resolution phase is still one
    // round-trip per host to a resolver that could, in principle, hang past
    // this call's own deadline before the first probe round ever starts.
    // Bounding it to `timeout` means resolution can never itself eat MORE than
    // the caller's whole stated budget; a resolution phase that blows through
    // it is treated exactly like every host failing to resolve (fail-open, not
    // a hang).
    let addrs = tokio::time::timeout(timeout, resolve_nodes(nodes)).await.unwrap_or_default();
    if addrs.is_empty() {
        return Convergence::NoNodesReachable;
    }
    loop {
        // #354: probe every node concurrently (JoinSet), not one after another --
        // a strictly sequential poll round could take up to
        // nodes.len() * addrs_per_node * QUERY_TIMEOUT (worst case, all nodes
        // slow/unreachable on their first address), which can exceed both
        // POLL_INTERVAL and this call's own deadline even though the nodes are
        // fully independent probes with nothing to serialize on. The within-node
        // IP-fallback (try each of a node's addresses in turn) stays sequential --
        // only the nodes themselves run in parallel.
        let mut set = tokio::task::JoinSet::new();
        for (host, ips) in &addrs {
            set.spawn(probe_node(host.clone(), ips.clone(), zone.to_string(), name.to_string(), expected.to_string()));
        }
        let (answered, mut lagging, mut unreachable) = drain_probe_round(set).await;
        if answered == 0 {
            return Convergence::NoNodesReachable;
        }
        if lagging.is_empty() && unreachable.is_empty() {
            return Convergence::Converged { nodes: answered, took: started.elapsed() };
        }
        if Instant::now() >= deadline {
            // Concurrent probes finish in arbitrary order -- sort so the
            // operator-facing lists are stable/reproducible, not an artifact of
            // which task happened to resolve first.
            lagging.sort();
            unreachable.sort();
            return Convergence::TimedOut { lagging, unreachable };
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// #488: the outcome of probing one node, kept as three explicit cases rather
/// than the ambiguous `(bool, Option<String>)` this replaced -- a node that
/// resolved and answered but simply doesn't have the expected value YET
/// ([`Lagging`](Self::Lagging)) is a materially different fault from a node
/// that never answered anything at all ([`Unreachable`](Self::Unreachable)):
/// the first is ordinary provider replication lag, the second is a fact about
/// reachability from this specific vantage point (a firewall rule, a routing
/// black hole) that an operator needs to go fix somewhere entirely different.
#[derive(Debug, Clone, PartialEq)]
enum ProbeOutcome {
    /// The node is serving the expected value.
    Converged,
    /// The node resolved and answered (a TXT miss whose SOA probe proved the
    /// server is live), but not yet with the expected value.
    Lagging(String),
    /// Every address for this node failed even the SOA liveness probe.
    Unreachable(String),
}

/// Probe one node -- try each of its resolved addresses in turn (typically one
/// IPv4 and one IPv6), taking the first that actually answers, rather than only
/// the first address hickory happened to return. One address family being
/// unreachable from this host is not the same as the node being down --
/// conflating them silently halved the fleet this checked on a host whose
/// outbound UDP/53 over IPv6 stalled while IPv4 to the very same node answered
/// immediately. That would have reintroduced this module's own root cause (a
/// check quietly covering fewer nodes than it claims to) one layer down.
async fn probe_node(
    host: String,
    ips: Vec<(std::net::IpAddr, std::sync::Arc<Resolver<TokioRuntimeProvider>>)>,
    zone: String,
    name: String,
    expected: String,
) -> ProbeOutcome {
    for (_ip, resolver) in &ips {
        match txt_at(resolver, &name).await {
            Ok(values) => {
                return if values.iter().any(|v| v == &expected) {
                    ProbeOutcome::Converged
                } else {
                    ProbeOutcome::Lagging(host)
                };
            }
            // This cannot be read off the TXT query's own error: hickory renders
            // BOTH a genuine "no such record" answer from a live, reachable
            // server AND a bare timeout with the same "no records found" text
            // (confirmed directly against this same fleet -- see
            // dns01_authoritative.rs, which hit the exact same rendering
            // ambiguity for the same reason). Ask the same address for the
            // zone's SOA, which every authoritative server for the zone must
            // serve: an SOA answer proves the node is live and the TXT miss is
            // real lag; no SOA answer means we could not reach this node at all.
            Err(_) => {
                if soa_reachable(resolver, &zone).await {
                    return ProbeOutcome::Lagging(host);
                }
            }
        }
    }
    // Every address for this node failed even the SOA probe -- that IS a real
    // gap in this check's coverage, unlike a single-address miss.
    ProbeOutcome::Unreachable(format!("{host} (unreachable on all {} address(es))", ips.len()))
}

/// Drain a round of [`probe_node`] tasks, tallying reachable-and-converged
/// nodes, reachable-but-lagging nodes, and unreachable nodes.
///
/// #490: a panicked probe task is treated exactly like a node whose every
/// address failed the SOA probe -- conservatively "unreachable this round" --
/// rather than propagating the panic (what `res.expect("probe_node task
/// panicked")` used to do) out of the whole convergence wait. `probe_node`
/// itself has no unwrap of its own, so triggering this needs a genuine panic
/// inside the DNS resolution library, but the blast radius of letting it
/// propagate was disproportionate: it would take down the WHOLE wait, not
/// just that one node's probe.
async fn drain_probe_round(mut set: tokio::task::JoinSet<ProbeOutcome>) -> (usize, Vec<String>, Vec<String>) {
    let mut answered = 0usize;
    let mut lagging = Vec::new();
    let mut unreachable = Vec::new();
    while let Some(res) = set.join_next().await {
        let outcome = match res {
            Ok(outcome) => outcome,
            Err(join_err) => {
                eprintln!(
                    "ct-dns: WARNING -- a convergence probe task panicked ({join_err}); treating that \
                     node as unreachable this round rather than aborting the whole convergence wait"
                );
                ProbeOutcome::Unreachable("(a probe task panicked)".to_string())
            }
        };
        match outcome {
            ProbeOutcome::Converged => answered += 1,
            ProbeOutcome::Lagging(host) => {
                answered += 1;
                lagging.push(host);
            }
            ProbeOutcome::Unreachable(host) => unreachable.push(host),
        }
    }
    (answered, lagging, unreachable)
}

/// #301: coalesce concurrent [`wait_for_convergence`] calls for the same
/// `(zone, name, expected)` into ONE shared poll cycle. Without this, a burst of N
/// simultaneous issuances for the same record (e.g. a retried publish, or several
/// tenants renewing around the same time) each independently poll all 12 deSEC
/// nodes every 5s for up to 300s -- N-fold amplification of query traffic against
/// deSEC's unicast nodes, risking exactly the rate-limiting/IO-blocking the
/// convergence probe itself depends on not hitting.
///
/// A caller that is first for a key becomes the poller and drives the real
/// [`wait_for_convergence`] call; every concurrent caller for the SAME key
/// subscribes to that one poll's result instead of starting its own. The map entry
/// is removed once the poll finishes, so a later call for the same key (e.g. a
/// genuinely new challenge value after renewal) starts a fresh poll rather than
/// replaying a stale result.
pub struct ConvergenceCoalescer {
    inflight: std::sync::Mutex<std::collections::HashMap<String, tokio::sync::watch::Receiver<Option<Convergence>>>>,
    /// #265: caps the number of *distinct* keys polling concurrently. Coalescing
    /// (above) already collapses a same-key burst to one poll; this bounds the
    /// orthogonal case -- many *different* hostnames publishing at once, each of
    /// which becomes its own poller and would otherwise stack unboundedly, each
    /// holding a handler task for up to [`DEFAULT_TIMEOUT`].
    poll_slots: std::sync::Arc<tokio::sync::Semaphore>,
}

impl Default for ConvergenceCoalescer {
    fn default() -> Self {
        Self::new()
    }
}

impl ConvergenceCoalescer {
    /// this control plane runs with `cpus: 1.0` (docker/deploy/compose.selfhost.yml,
    /// #312) -- a small, deliberately conservative cap on simultaneous distinct
    /// pollers rather than a throughput target. Real-world fan-out (one operator's
    /// tenants renewing/publishing around the same time) is expected to be far
    /// below this; it exists to bound a pathological burst, not ordinary use.
    const MAX_CONCURRENT_POLLERS: usize = 4;
    /// How long a would-be poller waits for a free slot before giving up as
    /// [`Convergence::Saturated`] rather than silently queuing for up to another
    /// [`DEFAULT_TIMEOUT`] on top of whatever it already waited in the handler.
    const PERMIT_WAIT: Duration = Duration::from_secs(10);

    pub fn new() -> Self {
        Self {
            inflight: std::sync::Mutex::new(std::collections::HashMap::new()),
            poll_slots: std::sync::Arc::new(tokio::sync::Semaphore::new(Self::MAX_CONCURRENT_POLLERS)),
        }
    }

    /// [`wait_for_convergence`], coalesced by `key` (the caller picks it -- typically
    /// something that uniquely identifies `(zone, name, expected)`, e.g.
    /// `format!("{zone}/{name}/{expected}")`, so two different desired values for the
    /// same record name are never accidentally coalesced together).
    pub async fn wait_for_convergence(
        &self,
        key: &str,
        nodes: &[&str],
        zone: &str,
        name: &str,
        expected: &str,
        timeout: Duration,
    ) -> Convergence {
        self.coalesce(key, || wait_for_convergence(nodes, zone, name, expected, timeout)).await
    }

    /// Core coalescing logic (#301), independent of what "poll" actually does --
    /// injectable so a test can prove the dedup behavior itself (a concurrent
    /// same-key burst runs the poll exactly once) without touching real DNS.
    async fn coalesce<F, Fut>(&self, key: &str, poll: F) -> Convergence
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Convergence>,
    {
        // Atomically check-and-claim under one lock acquisition: whoever inserts the
        // map entry is the poller, everyone else observed an existing entry and
        // subscribes -- no window where two concurrent callers both think they're
        // first.
        let existing_or_new_rx = {
            let mut map = self.inflight.lock().expect("convergence coalescer mutex poisoned");
            match map.get(key) {
                Some(rx) => Err(rx.clone()),
                None => {
                    let (tx, rx) = tokio::sync::watch::channel(None);
                    map.insert(key.to_string(), rx);
                    Ok(tx)
                }
            }
        };

        match existing_or_new_rx {
            Ok(tx) => {
                // #418: the map entry is removed by an RAII guard, not just after
                // `poll().await` returns -- `poll().await` is a real cancellation point
                // (the whole `coalesce` future can be dropped mid-poll if ITS caller times
                // out or is itself cancelled), and a plain post-await `remove` never runs
                // in that case. Without the guard, the stale `inflight` entry outlives the
                // poller forever: every later caller for the same key sees `Some(rx)`,
                // subscribes to a channel whose sender is already gone, and immediately
                // gets `NoNodesReachable` from the "sender dropped" fail-safe below --
                // permanently, since no real poll for that key is ever attempted again.
                struct RemoveOnDrop<'a> {
                    inflight: &'a std::sync::Mutex<
                        std::collections::HashMap<String, tokio::sync::watch::Receiver<Option<Convergence>>>,
                    >,
                    key: &'a str,
                }
                impl Drop for RemoveOnDrop<'_> {
                    fn drop(&mut self) {
                        self.inflight
                            .lock()
                            .expect("convergence coalescer mutex poisoned")
                            .remove(self.key);
                    }
                }
                let _guard = RemoveOnDrop { inflight: &self.inflight, key };

                // This caller is the poller -- bounded by `poll_slots` (#265): only
                // subscribers (the `Err` arm below) skip this, since they don't run
                // `poll` themselves and would otherwise wait on both this permit AND
                // the poller's own permit-wait, double-counting the same slot.
                let result = match tokio::time::timeout(Self::PERMIT_WAIT, self.poll_slots.clone().acquire_owned()).await {
                    Ok(Ok(_permit)) => poll().await,
                    // Either the wait itself timed out, or `acquire_owned` returned
                    // `Err` (the semaphore was closed) -- both mean "no slot", and the
                    // semaphore is never explicitly closed in this process's lifetime,
                    // so in practice this is always the timeout.
                    _ => Convergence::Saturated,
                };
                let _ = tx.send(Some(result.clone()));
                result
            }
            Err(mut rx) => {
                // A subscriber: wait for the poller's result. `watch` always retains
                // its most recent value, so even if the poller already finished
                // between our lock release above and getting here, `rx.borrow()`
                // sees it immediately without an extra wakeup.
                loop {
                    if let Some(result) = rx.borrow_and_update().clone() {
                        return result;
                    }
                    if rx.changed().await.is_err() {
                        // The poller's sender dropped without ever sending (a panic
                        // mid-poll) -- fail safe as unreachable rather than hang.
                        return Convergence::NoNodesReachable;
                    }
                }
            }
        }
    }
}

/// Resolve each node hostname to every address it has (typically one IPv4 and
/// one IPv6), skipping any node that no longer resolves at all so a stale
/// entry cannot block issuance. #355: builds each address's [`Resolver`] here,
/// once, rather than leaving `txt_at`/`soa_reachable` to build a fresh one on
/// every single probe call -- a long convergence wait (12 nodes, up to 60 poll
/// rounds over 300s) previously meant up to ~720 identical Resolver
/// constructions for the same, unchanging set of (node, ip) pairs.
///
/// #485: this used to be a strictly sequential `for host in nodes` loop -- 12
/// sequential DNS lookups, run BEFORE [`wait_for_convergence`]'s own deadline
/// was ever checked, so a resolver that's slow or partly unreachable could by
/// itself take on the order of minutes before the first probe round even
/// started, potentially exceeding the caller's whole stated timeout. Now
/// delegates to [`resolve_concurrently`], the same JoinSet-per-host construct
/// probing already uses (#354).
async fn resolve_nodes(nodes: &[&str]) -> Vec<(String, Vec<(std::net::IpAddr, std::sync::Arc<Resolver<TokioRuntimeProvider>>)>)> {
    let Ok(system) = Resolver::builder_tokio() else {
        return Vec::new();
    };
    let Ok(system) = system.build() else {
        return Vec::new();
    };
    let system = std::sync::Arc::new(system);
    resolve_concurrently(nodes, move |host| {
        let system = system.clone();
        async move {
            let lookup = system.lookup_ip(format!("{host}.")).await.ok()?;
            let ips: Vec<_> = lookup
                .iter()
                .filter_map(|ip| build_resolver(ip).map(|r| (ip, std::sync::Arc::new(r))))
                .collect();
            if ips.is_empty() {
                None
            } else {
                Some(ips)
            }
        }
    })
    .await
}

/// #485: resolve every host in `nodes` concurrently (one task per host, joined
/// as they complete) by awaiting `lookup` for each -- generic/injectable
/// purely so a test can prove the concurrency itself with a synthetic,
/// controlled delay, no real DNS involved, exactly as
/// [`ConvergenceCoalescer::coalesce`] already does for its own concurrency
/// claim. A host whose `lookup` returns `None` (fails to resolve) or whose
/// task panics is simply dropped from the result -- same fail-open philosophy
/// as a stale node hostname elsewhere in this module: resolution trouble for
/// one host degrades the check rather than blocking or crashing the rest.
async fn resolve_concurrently<F, Fut, T>(nodes: &[&str], lookup: F) -> Vec<(String, T)>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Option<T>> + Send + 'static,
    T: Send + 'static,
{
    let mut set = tokio::task::JoinSet::new();
    for host in nodes {
        let host = host.to_string();
        let fut = lookup(host.clone());
        set.spawn(async move { (host, fut.await) });
    }
    let mut out = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok((host, Some(value))) = res {
            out.push((host, value));
        }
    }
    out
}

/// #355 (test-only instrumentation): hickory's `Resolver` exposes no public
/// identity/equality check, so this is the only way to directly measure "was a
/// fresh resolver actually built here" rather than just asserting the code
/// looks like it builds one only once.
#[cfg(test)]
static RESOLVER_BUILD_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Build the resolver used to query one specific node directly -- shared by
/// [`txt_at`] and [`soa_reachable`], since both want the exact same
/// [`NameServerConfig`]/[`ResolverOpts`] for a given address; only the query
/// type (TXT vs SOA) differs, and that's chosen at lookup time, not at
/// resolver-construction time.
fn build_resolver(server: std::net::IpAddr) -> Option<Resolver<TokioRuntimeProvider>> {
    #[cfg(test)]
    RESOLVER_BUILD_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let name_server = NameServerConfig::udp_and_tcp(server);
    let config = ResolverConfig::from_parts(None, Vec::new(), vec![name_server]);
    let mut opts = ResolverOpts::default();
    opts.timeout = QUERY_TIMEOUT;
    opts.attempts = 1;
    opts.cache_size = 0;
    Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .ok()
}

/// Query one specific node directly for `name`'s TXT values.
async fn txt_at(resolver: &Resolver<TokioRuntimeProvider>, name: &str) -> Result<Vec<String>, String> {
    let lookup = resolver.txt_lookup(format!("{name}.")).await.map_err(|e| e.to_string())?;
    Ok(lookup
        .answers()
        .iter()
        .filter_map(|rec| match &rec.data {
            hickory_resolver::proto::rr::RData::TXT(txt) => Some(txt.to_string()),
            _ => None,
        })
        .collect())
}

/// Ask one node for the zone's SOA -- a record every authoritative server for
/// that zone must serve. Used purely as a liveness probe: a TXT-query error
/// alone cannot distinguish "this node is live and simply doesn't have the
/// record yet" from "this node never answered at all", since both render
/// with the same "no records found" text.
async fn soa_reachable(resolver: &Resolver<TokioRuntimeProvider>, zone: &str) -> bool {
    resolver.soa_lookup(format!("{zone}.")).await.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn the_node_list_covers_both_anycast_clouds_and_several_continents() {
        // The whole point is breadth: a list that only covered nearby nodes
        // would reproduce exactly the blind spot the anycast names have.
        let a = DESEC_NODES.iter().filter(|n| n.contains(".a.")).count();
        let c = DESEC_NODES.iter().filter(|n| n.contains(".c.")).count();
        assert!(a >= 4 && c >= 4, "both clouds represented: a={a} c={c}");
        // jnb (Johannesburg) is the node measured lagging longest -- losing it
        // from the list would silently restore the old false-positive.
        assert!(DESEC_NODES.iter().any(|n| n.starts_with("jnb-")), "the slowest observed node is covered");
        for n in DESEC_NODES {
            assert!(n.ends_with(".desec.io"), "{n} is a deSEC node hostname");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn joinset_based_probing_runs_concurrently_not_sequentially_354() {
        // #354: the real property being claimed -- N node probes must run
        // concurrently, not one after another. An earlier version of this test
        // measured real calls to genuinely unreachable addresses (192.0.2.0/24,
        // RFC 5737 TEST-NET-1) and was flaky in CI: that environment answers
        // packets to reserved space with an immediate rejection instead of
        // silently dropping them (unlike this crate's own dev sandbox), so both
        // the sequential and concurrent runs finished in ~1ms with nothing real
        // to compare -- real network timeout behavior is not portable across
        // environments and isn't a sound basis for a hermetic assertion.
        //
        // Prove the actual mechanism instead, deterministically: exercise the
        // exact same construct wait_for_convergence's poll loop now uses (spawn
        // one task per node into a tokio::task::JoinSet, join them as they
        // complete) against a controlled, in-process delay under tokio's paused
        // virtual clock -- no real time or network involved, so the comparison
        // is exact rather than a generous-threshold guess. `probe_node`'s own
        // per-address fallback correctness (unreachable -> lagging, TXT
        // mismatch -> lagging, TXT match -> converged) is unchanged by this
        // commit and is exercised by the pre-existing tests around it.
        const DELAY: Duration = Duration::from_millis(100);
        const NODES: usize = 4;

        let seq_start = tokio::time::Instant::now();
        for _ in 0..NODES {
            tokio::time::sleep(DELAY).await;
        }
        let sequential = seq_start.elapsed();

        let conc_start = tokio::time::Instant::now();
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..NODES {
            set.spawn(tokio::time::sleep(DELAY));
        }
        let mut count = 0;
        while set.join_next().await.is_some() {
            count += 1;
        }
        let concurrent = conc_start.elapsed();

        assert_eq!(count, NODES);
        assert_eq!(sequential, DELAY * NODES as u32, "sequential really did sum the delays");
        assert_eq!(concurrent, DELAY, "concurrent (JoinSet) ran every node's delay in parallel, not summed");
    }

    #[tokio::test(start_paused = true)]
    async fn resolve_concurrently_resolves_every_host_in_parallel_not_sequentially_485() {
        // #485: hostname resolution ahead of the poll loop used to be a strict
        // sequential for-loop over resolve_nodes' hosts -- 12 sequential DNS
        // lookups could by themselves exceed wait_for_convergence's own
        // deadline before the first probe round even started. resolve_nodes now
        // delegates to resolve_concurrently, the exact JoinSet-per-host
        // construct probing itself already used (#354, proved above) -- prove
        // resolve_concurrently the same way: a controlled, in-process delay
        // under tokio's paused virtual clock, no real DNS involved (see #354's
        // own comment for why a real-network timing comparison isn't a sound
        // basis for a hermetic assertion).
        const DELAY: Duration = Duration::from_millis(100);
        let hosts: Vec<&str> = DESEC_NODES.to_vec();

        let started = tokio::time::Instant::now();
        let out = resolve_concurrently(&hosts, |host| async move {
            tokio::time::sleep(DELAY).await;
            Some(host)
        })
        .await;
        let elapsed = started.elapsed();

        assert_eq!(out.len(), hosts.len(), "every host resolved");
        assert_eq!(
            elapsed, DELAY,
            "all {} lookups ran concurrently (one DELAY total), not summed to {} * DELAY",
            hosts.len(),
            hosts.len()
        );
    }

    #[tokio::test]
    async fn resolve_concurrently_skips_hosts_that_fail_to_resolve_or_whose_lookup_panics_485() {
        // Fail-open per host, same philosophy as a stale node hostname
        // elsewhere in this module: one host's resolution trouble (a lookup
        // returning nothing, or -- defensively -- even a genuine panic inside
        // it) must not take the other hosts down with it or drop them from the
        // result.
        let hosts = ["resolves-fine", "resolves-to-nothing", "lookup-panics"];
        let out = resolve_concurrently(&hosts, |host| async move {
            match host.as_str() {
                "resolves-fine" => Some("addr-for-resolves-fine"),
                "resolves-to-nothing" => None,
                _ => panic!("simulated resolver panic for {host}"),
            }
        })
        .await;
        assert_eq!(out, vec![("resolves-fine".to_string(), "addr-for-resolves-fine")]);
    }

    #[tokio::test]
    async fn a_panicking_probe_task_is_folded_in_as_unreachable_not_propagated_490() {
        // #490: `res.expect("probe_node task panicked")` used to propagate a
        // panicked probe task's panic out of the WHOLE convergence wait -- one
        // node's probe panicking took every other node's probe down with it.
        // drain_probe_round is the exact mechanism wait_for_convergence's poll
        // loop now uses to join a round of probes; spawn a genuinely panicking
        // task alongside normal Converged/Lagging outcomes (real panics, not a
        // simulated JoinError -- JoinSet has no public way to construct one) and
        // confirm the round still completes with a real, usable result instead
        // of propagating the panic. Also doubles as an #488 proof: Converged and
        // Lagging are tallied into `answered`/`lagging` while the panicked task
        // lands in `unreachable`, not merged into `lagging`.
        let mut set = tokio::task::JoinSet::new();
        set.spawn(async { ProbeOutcome::Converged });
        set.spawn(async { panic!("simulated probe_node panic") });
        set.spawn(async { ProbeOutcome::Lagging("lagging-node".to_string()) });

        let (answered, lagging, unreachable) = drain_probe_round(set).await;

        assert_eq!(answered, 2, "the converged node and the reachable-but-lagging node both counted as answered; the panicked task did not");
        assert_eq!(lagging, vec!["lagging-node".to_string()], "the panicked task must not be merged into the lagging list");
        assert_eq!(
            unreachable,
            vec!["(a probe task panicked)".to_string()],
            "the panicked task is folded in as unreachable, not lost or propagated out of this function"
        );
    }

    #[tokio::test]
    async fn a_reachable_but_lagging_node_and_a_genuinely_unreachable_node_are_tracked_separately_488() {
        // #488: before this fix, Convergence::TimedOut carried one ambiguous
        // `lagging` list that conflated "resolved and answered, just doesn't
        // have the value yet" (ordinary provider replication lag) with
        // "resolved but never answered anything at all" (a reachability fault
        // specific to this vantage point). drain_probe_round is the real
        // aggregation wait_for_convergence's TimedOut branch is built from --
        // prove the two outcomes land in their own separately-tracked sets.
        let mut set = tokio::task::JoinSet::new();
        set.spawn(async { ProbeOutcome::Converged });
        set.spawn(async { ProbeOutcome::Lagging("slow-but-reachable.desec.io".to_string()) });
        set.spawn(async { ProbeOutcome::Unreachable("firewalled.desec.io (unreachable on all 2 address(es))".to_string()) });

        let (answered, lagging, unreachable) = drain_probe_round(set).await;

        assert_eq!(answered, 2, "Converged and Lagging both counted as answered -- Unreachable did not");
        assert_eq!(lagging, vec!["slow-but-reachable.desec.io".to_string()]);
        assert_eq!(unreachable, vec!["firewalled.desec.io (unreachable on all 2 address(es))".to_string()]);
    }

    #[tokio::test]
    async fn resolve_nodes_builds_one_resolver_per_address_and_polling_never_rebuilds_one_355() {
        // #355: two real claims to prove, not just assert -- (1) resolve_nodes
        // builds exactly one Resolver per resolved address, not more; (2) once
        // built, probing (what every poll round does) never triggers another
        // build -- txt_at/soa_reachable just use the resolver handed to them.
        // "localhost" always resolves via loopback, so resolve_nodes itself
        // succeeds without needing a real DNS server anywhere on the network;
        // no other test in this file calls resolve_nodes with a hostname that
        // actually resolves, so this counter is exclusively this test's.
        use std::sync::atomic::Ordering;

        RESOLVER_BUILD_COUNT.store(0, Ordering::SeqCst);
        let addrs = resolve_nodes(&["localhost"]).await;
        let total_addrs: usize = addrs.iter().map(|(_, ips)| ips.len()).sum();
        assert!(total_addrs > 0, "localhost must resolve to at least one address for this test to prove anything");
        let after_resolve = RESOLVER_BUILD_COUNT.load(Ordering::SeqCst);
        assert_eq!(after_resolve, total_addrs, "exactly one Resolver built per resolved address");

        // Simulate two poll rounds against the SAME addrs -- exactly how
        // wait_for_convergence's loop reuses them (ips.clone() clones the Arc
        // pointers, never rebuilds the Resolver inside).
        for (host, ips) in &addrs {
            probe_node(host.clone(), ips.clone(), "example.invalid".to_string(), "_acme-challenge.example.invalid".to_string(), "v".to_string()).await;
            probe_node(host.clone(), ips.clone(), "example.invalid".to_string(), "_acme-challenge.example.invalid".to_string(), "v".to_string()).await;
        }
        assert_eq!(
            RESOLVER_BUILD_COUNT.load(Ordering::SeqCst),
            after_resolve,
            "probing (what every poll round does) must never build another Resolver"
        );
    }

    #[tokio::test]
    async fn no_reachable_nodes_is_distinct_from_lagging_nodes() {
        // Fail-open, not fail-closed: if this host cannot reach any node, that
        // is a fact about our network. Reporting it as lag would block an
        // issuance that is actually fine.
        let outcome =
            wait_for_convergence(&["192.0.2.1.invalid"], "example.invalid", "_acme-challenge.example.invalid", "v", Duration::from_millis(50))
                .await;
        assert_eq!(outcome, Convergence::NoNodesReachable);
    }

    #[tokio::test]
    async fn an_empty_node_list_reports_no_nodes_rather_than_claiming_convergence() {
        // An empty list must never read as "everything agrees" -- that would
        // silently disable the check.
        let outcome =
            wait_for_convergence(&[], "example.invalid", "_acme-challenge.example.invalid", "v", Duration::from_millis(50)).await;
        assert_eq!(outcome, Convergence::NoNodesReachable);
    }

    #[tokio::test]
    async fn coalescer_runs_the_poll_exactly_once_for_a_concurrent_same_key_burst_301() {
        // #301: N concurrent callers for the SAME key must share ONE poll, not each
        // run their own -- the whole point, and not observable through real DNS
        // timing (concurrent polls would overlap in wall-clock time either way), so
        // prove it directly against an injected poll that counts its own invocations.
        // Only ONE of the 8 concurrent callers ever becomes the poller (the other 7
        // are subscribers that never touch the closure at all), so the closure holds
        // itself open briefly with a short sleep -- long enough for all 8 spawned
        // tasks to reach the coalescer and register as poller-or-subscriber before
        // the single poll resolves, without any explicit cross-task coordination.
        let coalescer = Arc::new(ConvergenceCoalescer::new());
        let poll_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let coalescer = coalescer.clone();
            let poll_count = poll_count.clone();
            handles.push(tokio::spawn(async move {
                coalescer
                    .coalesce("zone/name/expected", || async move {
                        poll_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        Convergence::Converged { nodes: 12, took: Duration::from_millis(1) }
                    })
                    .await
            }));
        }

        for h in handles {
            let result = h.await.unwrap();
            assert_eq!(result, Convergence::Converged { nodes: 12, took: Duration::from_millis(1) });
        }
        assert_eq!(poll_count.load(std::sync::atomic::Ordering::SeqCst), 1, "exactly one poll served all 8 callers");
    }

    #[tokio::test]
    async fn coalescer_runs_independent_polls_for_different_keys_301() {
        // Different keys must NOT be coalesced together -- each gets its own poll.
        let coalescer = ConvergenceCoalescer::new();
        let poll_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let a = coalescer.coalesce("zone/a/expected", || {
            let poll_count = poll_count.clone();
            async move {
                poll_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Convergence::NoNodesReachable
            }
        });
        let b = coalescer.coalesce("zone/b/expected", || {
            let poll_count = poll_count.clone();
            async move {
                poll_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Convergence::NoNodesReachable
            }
        });
        let (ra, rb) = tokio::join!(a, b);
        assert_eq!((ra, rb), (Convergence::NoNodesReachable, Convergence::NoNodesReachable));
        assert_eq!(poll_count.load(std::sync::atomic::Ordering::SeqCst), 2, "two distinct keys, two independent polls");
    }

    #[tokio::test]
    async fn coalescer_starts_a_fresh_poll_after_the_prior_one_for_the_same_key_finished_301() {
        // A finished poll's map entry must be cleaned up -- a LATER call for the same
        // key (e.g. a genuinely new challenge value after renewal) must run its own
        // fresh poll, not replay a stale cached result forever.
        let coalescer = ConvergenceCoalescer::new();
        let poll_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        for _ in 0..3 {
            let poll_count = poll_count.clone();
            coalescer
                .coalesce("zone/name/expected", || async move {
                    poll_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Convergence::NoNodesReachable
                })
                .await;
        }
        assert_eq!(poll_count.load(std::sync::atomic::Ordering::SeqCst), 3, "three sequential calls, three fresh polls");
    }

    #[tokio::test]
    async fn a_cancelled_poller_does_not_permanently_poison_its_key_418() {
        // #418: before the RAII guard, the `inflight` map entry was only removed
        // AFTER `poll().await` returned -- if the poller's own task is aborted
        // mid-poll (a real scenario: its caller timed out, or the task was itself
        // cancelled), that cleanup never ran. Every LATER call for the same key
        // would then see the stale entry, subscribe to a channel whose sender is
        // already gone, and immediately get NoNodesReachable from the
        // sender-dropped fail-safe -- permanently, since no real poll for that key
        // is ever attempted again. Real proof: abort an in-flight poller, then
        // confirm a fresh call for the SAME key actually runs its own poll (not a
        // fail-safe echo of the aborted one).
        let coalescer = Arc::new(ConvergenceCoalescer::new());
        let poll_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let started = Arc::new(tokio::sync::Notify::new());

        let c = coalescer.clone();
        let pc = poll_count.clone();
        let s = started.clone();
        let handle = tokio::spawn(async move {
            c.coalesce("zone/name/expected", || {
                let pc = pc.clone();
                let s = s.clone();
                async move {
                    pc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    s.notify_one();
                    // Never resolves on its own -- only abort() ends this poller.
                    std::future::pending::<()>().await;
                    unreachable!();
                }
            })
            .await
        });
        started.notified().await; // the poller has genuinely started (registered the key)
        handle.abort();
        let _ = handle.await; // reap the aborted task

        // The key must be usable again -- a fresh, real poll, not a permanently
        // poisoned entry.
        let result = coalescer
            .coalesce("zone/name/expected", || {
                let poll_count = poll_count.clone();
                async move {
                    poll_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Convergence::NoNodesReachable
                }
            })
            .await;
        assert_eq!(result, Convergence::NoNodesReachable, "the fresh poll's own real result, not a fail-safe echo");
        assert_eq!(
            poll_count.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the aborted poller's one increment, plus a genuine second poll after cleanup -- not stuck at 1"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_of_distinct_keys_beyond_the_cap_is_reported_saturated_not_left_unbounded_265() {
        // #265: MAX_CONCURRENT_POLLERS (4) distinct-key pollers can run at once; a
        // 5th distinct key must not become a 5th unbounded concurrent poll -- it
        // should wait for a slot and, since every slot here is held for longer than
        // PERMIT_WAIT, eventually give up as Saturated rather than hang.
        let coalescer = Arc::new(ConvergenceCoalescer::new());
        let concurrent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak_concurrent = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let mut handles = Vec::new();
        for i in 0..(ConvergenceCoalescer::MAX_CONCURRENT_POLLERS + 1) {
            let coalescer = coalescer.clone();
            let concurrent = concurrent.clone();
            let peak_concurrent = peak_concurrent.clone();
            handles.push(tokio::spawn(async move {
                coalescer
                    .coalesce(&format!("zone/{i}/expected"), || async move {
                        let now = concurrent.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                        peak_concurrent.fetch_max(now, std::sync::atomic::Ordering::SeqCst);
                        // Longer than PERMIT_WAIT: a slot never frees up in time for
                        // the (MAX+1)th caller, which is the scenario under test.
                        tokio::time::sleep(ConvergenceCoalescer::PERMIT_WAIT * 2).await;
                        concurrent.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                        Convergence::Converged { nodes: 12, took: Duration::from_millis(1) }
                    })
                    .await
            }));
        }

        let mut results = Vec::new();
        for h in handles {
            results.push(h.await.unwrap());
        }
        assert_eq!(
            results.iter().filter(|r| **r == Convergence::Saturated).count(),
            1,
            "exactly one of the {} callers exceeded the cap and gave up: {results:?}",
            ConvergenceCoalescer::MAX_CONCURRENT_POLLERS + 1
        );
        assert_eq!(
            results.iter().filter(|r| matches!(r, Convergence::Converged { .. })).count(),
            ConvergenceCoalescer::MAX_CONCURRENT_POLLERS,
            "the other callers actually ran their poll and converged"
        );
        assert!(
            peak_concurrent.load(std::sync::atomic::Ordering::SeqCst) <= ConvergenceCoalescer::MAX_CONCURRENT_POLLERS,
            "never more than {} pollers ran their closure at once",
            ConvergenceCoalescer::MAX_CONCURRENT_POLLERS
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_saturated_result_is_shared_with_coalesced_subscribers_for_the_same_key_265() {
        // The poller giving up as Saturated must still notify same-key subscribers
        // with that same result, not hang them waiting for a poll that never ran --
        // and it must never invoke the poll closure at all once every slot stays
        // held for the whole test (so which of the concurrent callers happens to
        // become the poller doesn't matter: none of them ever gets to run `poll`).
        let coalescer = Arc::new(ConvergenceCoalescer::new());
        for i in 0..ConvergenceCoalescer::MAX_CONCURRENT_POLLERS {
            let coalescer = coalescer.clone();
            tokio::spawn(async move {
                coalescer
                    .coalesce(&format!("zone/filler-{i}/expected"), || async move {
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        Convergence::Converged { nodes: 12, took: Duration::from_millis(1) }
                    })
                    .await
            });
        }
        // Under paused time this drives the runtime through a full turn -- enough
        // for all 4 spawned fillers to run up to (and register) their long sleep,
        // so their semaphore permits are genuinely held before we proceed.
        tokio::time::sleep(Duration::from_millis(1)).await;

        let poll_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..3 {
            let coalescer = coalescer.clone();
            let poll_count = poll_count.clone();
            handles.push(tokio::spawn(async move {
                coalescer
                    .coalesce("zone/contended/expected", || {
                        let poll_count = poll_count.clone();
                        async move {
                            poll_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            Convergence::Converged { nodes: 12, took: Duration::from_millis(1) }
                        }
                    })
                    .await
            }));
        }
        let mut results = Vec::new();
        for h in handles {
            results.push(h.await.unwrap());
        }
        assert!(results.iter().all(|r| *r == Convergence::Saturated), "every caller for the contended key sees the same Saturated result: {results:?}");
        assert_eq!(poll_count.load(std::sync::atomic::Ordering::SeqCst), 0, "the poll closure never ran -- no slot was ever available");
    }
}
