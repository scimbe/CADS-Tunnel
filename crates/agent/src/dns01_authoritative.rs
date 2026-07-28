//! Confirms a DNS-01 TXT record is live on **every authoritative nameserver**
//! of its zone — which is what Let's Encrypt actually checks, and what public
//! resolvers cannot tell you.
//!
//! ## Why this exists (#229)
//!
//! [`crate::dns01_propagation`] asks public DoH resolvers (Cloudflare, Google)
//! whether the challenge record is visible. That turns out to be the wrong
//! question. Let's Encrypt does not consult public resolvers: it queries the
//! zone's own authoritative nameservers, and since the CA/Browser Forum's
//! multi-perspective requirement (SC067) it does so from several
//! geographically separate vantage points and requires them to corroborate.
//!
//! Measured directly against this deployment's own zone, publishing one TXT
//! record and polling both authoritative servers every few seconds:
//!
//! ```text
//! +4s    ns1.desec.io = "probe-B"      ns2.desec.org = (nothing)
//! +53s   ns1.desec.io = "probe-B"      ns2.desec.org = (nothing)
//! ~+60s  ns1.desec.io = "probe-B"      ns2.desec.org = "probe-B"
//! ```
//!
//! (one earlier run had `ns2` still empty at +145s). Both servers report the
//! **same SOA serial** throughout, so the divergence is not even detectable
//! from the serial — only by asking each server for the record itself.
//!
//! A resolver-based check is blind to this: Cloudflare or Google may well have
//! taken their answer from the fast server, so they say "visible" while the
//! slow one still answers NXDOMAIN. Validation then gets triggered, Let's
//! Encrypt's own multi-perspective pass inevitably reaches the lagging server,
//! and the authorization fails "during secondary validation" — exactly the
//! failure this module was written to stop.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;

/// How long to keep waiting for every authoritative server to agree.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Confirms a TXT value is served by every authoritative nameserver for its
/// zone. Construct with [`AuthoritativeChecker::from_system`], which uses the
/// host's own resolver only to *discover* the zone's nameservers and their
/// addresses — every check of the challenge record itself goes straight to
/// those authoritative servers, so no cache sits in between.
pub struct AuthoritativeChecker {
    system: Resolver<TokioConnectionProvider>,
    timeout: Duration,
    interval: Duration,
}

impl AuthoritativeChecker {
    pub fn from_system() -> Result<Self, String> {
        Self::with_timeout(DEFAULT_TIMEOUT)
    }

    pub fn with_timeout(timeout: Duration) -> Result<Self, String> {
        let builder = Resolver::builder_tokio().map_err(|e| format!("system resolver unavailable: {e}"))?;
        Ok(Self { system: builder.build(), timeout, interval: POLL_INTERVAL })
    }

    /// The zone apex responsible for `name`, per its SOA. Walks up label by
    /// label so it works for any depth of subdomain without assuming a
    /// public-suffix rule.
    async fn zone_of(&self, name: &str) -> Result<String, String> {
        let trimmed = name.trim_end_matches('.');
        let labels: Vec<&str> = trimmed.split('.').collect();
        // Skip the leaf (`_acme-challenge`) and stop before the bare TLD.
        for start in 0..labels.len().saturating_sub(1) {
            let candidate = labels[start..].join(".");
            if self.system.ns_lookup(format!("{candidate}.")).await.is_ok() {
                return Ok(candidate);
            }
        }
        Err(format!("no zone with an NS RRset found for {name}"))
    }

    /// Every authoritative nameserver address for `zone` (each NS name resolved
    /// to all of its A/AAAA addresses -- an anycast name can front several).
    async fn authoritative_addrs(&self, zone: &str) -> Result<Vec<(String, IpAddr)>, String> {
        let ns = self
            .system
            .ns_lookup(format!("{zone}."))
            .await
            .map_err(|e| format!("NS lookup for {zone} failed: {e}"))?;
        let mut out = Vec::new();
        for rec in ns.iter() {
            let host = rec.0.to_utf8();
            if let Ok(lookup) = self.system.lookup_ip(host.clone()).await {
                for ip in lookup.iter() {
                    out.push((host.clone(), ip));
                }
            }
        }
        if out.is_empty() {
            return Err(format!("no authoritative nameserver addresses resolved for {zone}"));
        }
        Ok(out)
    }

    /// Ask one specific server, directly, for `name`'s TXT values.
    async fn txt_at(&self, server: IpAddr, name: &str) -> Result<Vec<String>, String> {
        let group = NameServerConfigGroup::from_ips_clear(&[server], 53, true);
        let config = ResolverConfig::from_parts(None, Vec::new(), group);
        let mut opts = ResolverOpts::default();
        opts.timeout = QUERY_TIMEOUT;
        opts.attempts = 1;
        // Never let a cached/edns oddity stand in for the server's own answer.
        opts.cache_size = 0;
        let resolver = Resolver::builder_with_config(config, TokioConnectionProvider::default())
            .with_options(opts)
            .build();
        let lookup = resolver.txt_lookup(format!("{name}.")).await.map_err(|e| e.to_string())?;
        Ok(lookup.iter().map(|txt| txt.to_string()).collect())
    }

    /// Block until **every** authoritative server for `record_name`'s zone
    /// serves `expected_value`, or `timeout` elapses. The error names the
    /// servers still missing it, so a persistently lagging one is obvious
    /// rather than looking like a generic timeout.
    pub async fn wait_for_all(&self, record_name: &str, expected_value: &str) -> Result<(), String> {
        let zone = self.zone_of(record_name).await?;
        let servers = self.authoritative_addrs(&zone).await?;
        let deadline = Instant::now() + self.timeout;
        loop {
            let mut missing: Vec<String> = Vec::new();
            for (host, ip) in &servers {
                let has = match self.txt_at(*ip, record_name).await {
                    Ok(values) => values.iter().any(|v| v == expected_value),
                    Err(_) => false,
                };
                if !has {
                    missing.push(format!("{host} ({ip})"));
                }
            }
            if missing.is_empty() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "TXT {record_name} is not yet served by every authoritative nameserver of {zone} after {:?} -- still missing from: {}. \
                     Let's Encrypt validates against these servers from multiple perspectives, so triggering validation now would fail secondary validation.",
                    self.timeout,
                    missing.join(", ")
                ));
            }
            tokio::time::sleep(self.interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_walk_candidates_go_from_most_to_least_specific() {
        // Pure string-shape check of the walk order zone_of relies on: the
        // leaf label is skipped and the bare TLD is never a candidate, so a
        // deep hostname still tries the real zone before giving up.
        let name = "_acme-challenge.a.b.example.com";
        let labels: Vec<&str> = name.split('.').collect();
        let candidates: Vec<String> =
            (0..labels.len().saturating_sub(1)).map(|s| labels[s..].join(".")).collect();
        assert_eq!(candidates[0], "_acme-challenge.a.b.example.com");
        assert_eq!(candidates[1], "a.b.example.com");
        assert_eq!(candidates[2], "b.example.com");
        assert_eq!(candidates[3], "example.com");
        assert!(!candidates.contains(&"com".to_string()), "never queries the bare TLD");
    }

    #[tokio::test]
    async fn a_server_that_cannot_be_reached_counts_as_missing_not_as_satisfied() {
        // Fail-closed: an unreachable authoritative server must never be
        // silently treated as agreeing -- that would reintroduce exactly the
        // too-weak signal this module exists to replace.
        let checker = AuthoritativeChecker::with_timeout(Duration::from_millis(50)).unwrap();
        // TEST-NET-1 (RFC 5737), guaranteed not to answer.
        let unreachable: IpAddr = "192.0.2.1".parse().unwrap();
        let values = checker.txt_at(unreachable, "_acme-challenge.example.invalid").await;
        assert!(values.is_err(), "an unreachable server errors rather than returning an empty success");
    }
}
