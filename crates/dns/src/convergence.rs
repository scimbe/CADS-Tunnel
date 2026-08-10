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
    /// Ran out of time; these nodes were still behind.
    TimedOut { lagging: Vec<String> },
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
    let addrs = resolve_nodes(nodes).await;
    if addrs.is_empty() {
        return Convergence::NoNodesReachable;
    }
    loop {
        let mut lagging = Vec::new();
        let mut answered = 0usize;
        for (host, ips) in &addrs {
            // Try every address this node resolved to (typically one IPv4 and
            // one IPv6) and take the first that actually answers, rather than
            // only the first address hickory happened to return. One address
            // family being unreachable from this host is not the same as the
            // node being down -- conflating them silently halved the fleet
            // this checked on a host whose outbound UDP/53 over IPv6 stalled
            // while IPv4 to the very same node answered immediately. That
            // would have reintroduced this module's own root cause (a check
            // quietly covering fewer nodes than it claims to) one layer down.
            let mut node_answered = false;
            for ip in ips {
                match txt_at(*ip, name).await {
                    Ok(values) => {
                        node_answered = true;
                        answered += 1;
                        if !values.iter().any(|v| v == expected) {
                            lagging.push(host.clone());
                        }
                        break;
                    }
                    // This cannot be read off the TXT query's own error: hickory
                    // renders BOTH a genuine "no such record" answer from a live,
                    // reachable server AND a bare timeout with the same "no
                    // records found" text (confirmed directly against this same
                    // fleet -- see dns01_authoritative.rs, which hit the exact
                    // same rendering ambiguity for the same reason). Ask the same
                    // address for the zone's SOA, which every authoritative
                    // server for the zone must serve: an SOA answer proves the
                    // node is live and the TXT miss is real lag; no SOA answer
                    // means we could not reach this node at all.
                    Err(_) => {
                        if soa_reachable(*ip, zone).await {
                            node_answered = true;
                            answered += 1;
                            lagging.push(host.clone());
                            break;
                        }
                    }
                }
            }
            // Every address for this node failed even the SOA probe -- that IS
            // a real gap in this check's coverage, unlike a single-address
            // miss. Surface it as lagging (conservative: keep waiting) rather
            // than quietly dropping the node from consideration.
            if !node_answered {
                lagging.push(format!("{host} (unreachable on all {} address(es))", ips.len()));
            }
        }
        if answered == 0 {
            return Convergence::NoNodesReachable;
        }
        if lagging.is_empty() {
            return Convergence::Converged { nodes: answered, took: started.elapsed() };
        }
        if Instant::now() >= deadline {
            return Convergence::TimedOut { lagging };
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
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
                self.inflight.lock().expect("convergence coalescer mutex poisoned").remove(key);
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
/// entry cannot block issuance.
async fn resolve_nodes(nodes: &[&str]) -> Vec<(String, Vec<std::net::IpAddr>)> {
    let Ok(system) = Resolver::builder_tokio() else {
        return Vec::new();
    };
    let Ok(system) = system.build() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for host in nodes {
        if let Ok(lookup) = system.lookup_ip(format!("{host}.")).await {
            let ips: Vec<_> = lookup.iter().collect();
            if !ips.is_empty() {
                out.push((host.to_string(), ips));
            }
        }
    }
    out
}

/// Query one specific node directly for `name`'s TXT values.
async fn txt_at(server: std::net::IpAddr, name: &str) -> Result<Vec<String>, String> {
    let name_server = NameServerConfig::udp_and_tcp(server);
    let config = ResolverConfig::from_parts(None, Vec::new(), vec![name_server]);
    let mut opts = ResolverOpts::default();
    opts.timeout = QUERY_TIMEOUT;
    opts.attempts = 1;
    opts.cache_size = 0;
    let resolver = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .map_err(|e| e.to_string())?;
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
async fn soa_reachable(server: std::net::IpAddr, zone: &str) -> bool {
    let name_server = NameServerConfig::udp_and_tcp(server);
    let config = ResolverConfig::from_parts(None, Vec::new(), vec![name_server]);
    let mut opts = ResolverOpts::default();
    opts.timeout = QUERY_TIMEOUT;
    opts.attempts = 1;
    opts.cache_size = 0;
    let Ok(resolver) = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
    else {
        return false;
    };
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
