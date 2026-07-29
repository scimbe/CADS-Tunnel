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

use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
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
#[derive(Debug, PartialEq)]
pub enum Convergence {
    /// Every node that answered is serving the expected value.
    Converged { nodes: usize, took: Duration },
    /// Ran out of time; these nodes were still behind.
    TimedOut { lagging: Vec<String> },
    /// Not one node could be reached — this says something about *our* network,
    /// not about propagation, so the caller must not read it as failure.
    NoNodesReachable,
}

/// Poll every node in `nodes` until all of them serve `expected` for `name`.
pub async fn wait_for_convergence(
    nodes: &[&str],
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
                if let Ok(values) = txt_at(*ip, name).await {
                    node_answered = true;
                    answered += 1;
                    if !values.iter().any(|v| v == expected) {
                        lagging.push(host.clone());
                    }
                    break;
                }
            }
            // Every address for this node failed -- that IS a real gap in
            // this check's coverage, unlike a single-address miss. Surface
            // it as lagging (conservative: keep waiting) rather than quietly
            // dropping the node from consideration.
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

/// Resolve each node hostname to every address it has (typically one IPv4 and
/// one IPv6), skipping any node that no longer resolves at all so a stale
/// entry cannot block issuance.
async fn resolve_nodes(nodes: &[&str]) -> Vec<(String, Vec<std::net::IpAddr>)> {
    let Ok(system) = Resolver::builder_tokio() else {
        return Vec::new();
    };
    let system = system.build();
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
    let group = NameServerConfigGroup::from_ips_clear(&[server], 53, true);
    let config = ResolverConfig::from_parts(None, Vec::new(), group);
    let mut opts = ResolverOpts::default();
    opts.timeout = QUERY_TIMEOUT;
    opts.attempts = 1;
    opts.cache_size = 0;
    let resolver = Resolver::builder_with_config(config, TokioConnectionProvider::default())
        .with_options(opts)
        .build();
    let lookup = resolver.txt_lookup(format!("{name}.")).await.map_err(|e| e.to_string())?;
    Ok(lookup.iter().map(|t| t.to_string()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            wait_for_convergence(&["192.0.2.1.invalid"], "_acme-challenge.example.invalid", "v", Duration::from_millis(50))
                .await;
        assert_eq!(outcome, Convergence::NoNodesReachable);
    }

    #[tokio::test]
    async fn an_empty_node_list_reports_no_nodes_rather_than_claiming_convergence() {
        // An empty list must never read as "everything agrees" -- that would
        // silently disable the check.
        let outcome =
            wait_for_convergence(&[], "_acme-challenge.example.invalid", "v", Duration::from_millis(50)).await;
        assert_eq!(outcome, Convergence::NoNodesReachable);
    }
}
