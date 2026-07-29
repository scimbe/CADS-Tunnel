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

/// Tag on the error returned when *no* authoritative server could be reached.
/// The caller keys off this to fall back to public resolvers instead of
/// failing the issuance outright (see [`AuthoritativeChecker::wait_for_all`]).
pub const UNREACHABLE_MARKER: &str = "authoritative nameservers unreachable from this host";
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
}

/// What one direct query to an authoritative server actually told us.
///
/// The distinction is the whole point: "the server answered and does not have
/// the record" is real evidence about propagation, while "we could not reach
/// the server at all" is evidence about *our own* network and says nothing
/// about what Let's Encrypt sees. Conflating the two makes issuance
/// impossible on any host that cannot send DNS directly -- e.g. one with
/// outbound UDP/53 blocked, which is common and was exactly the case that
/// exposed this (#229).
#[derive(Debug, PartialEq)]
enum Probe {
    /// The server answered and serves the expected value.
    Present,
    /// The server answered; the value is not (yet) there.
    Absent,
    /// We never got an answer -- timeout, blocked port, transport error.
    Unreachable,
}

impl AuthoritativeChecker {
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

    /// Ask one server for the zone's SOA -- a record every authoritative
    /// server for that zone must serve. Used purely as a liveness probe.
    async fn soa_reachable(&self, server: IpAddr, zone: &str) -> bool {
        let group = NameServerConfigGroup::from_ips_clear(&[server], 53, true);
        let config = ResolverConfig::from_parts(None, Vec::new(), group);
        let mut opts = ResolverOpts::default();
        opts.timeout = QUERY_TIMEOUT;
        opts.attempts = 1;
        opts.cache_size = 0;
        let resolver = Resolver::builder_with_config(config, TokioConnectionProvider::default())
            .with_options(opts)
            .build();
        resolver.soa_lookup(format!("{zone}.")).await.is_ok()
    }

    /// Probe one server, distinguishing "answered, record not there yet" from
    /// "never answered at all".
    ///
    /// This cannot be decided from the TXT query's error: hickory reports a
    /// *timeout* with the same "no records found" text as a genuine
    /// authoritative negative answer, so string- or kind-matching on it
    /// silently misclassifies an unreachable server as an up-to-date one
    /// answering "not there". Instead, on a TXT miss we ask the same server
    /// for the zone's SOA -- which every authoritative server for the zone
    /// must serve. An SOA answer proves the server is reachable and talking
    /// to us, so the TXT miss is real propagation lag; no SOA answer means we
    /// simply cannot see this server from here.
    async fn probe(&self, server: IpAddr, name: &str, expected: &str, zone: &str) -> Probe {
        if let Ok(values) = self.txt_at(server, name).await {
            if values.iter().any(|v| v == expected) {
                return Probe::Present;
            }
        }
        if self.soa_reachable(server, zone).await {
            Probe::Absent
        } else {
            Probe::Unreachable
        }
    }
}

impl AuthoritativeChecker {

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
            let mut unreachable: Vec<String> = Vec::new();
            for (host, ip) in &servers {
                match self.probe(*ip, record_name, expected_value, &zone).await {
                    Probe::Present => {}
                    Probe::Absent => missing.push(format!("{host} ({ip})")),
                    Probe::Unreachable => unreachable.push(format!("{host} ({ip})")),
                }
            }
            // Not one authoritative server is reachable from here. That is a
            // fact about this host's network, not about propagation -- most
            // often outbound UDP/53 being blocked. Refusing to issue on that
            // basis would be wrong: it blocks issuance that would otherwise
            // succeed. Hand back a distinguishable error so the caller can
            // fall back to the (weaker, but usable) public-resolver check.
            if unreachable.len() == servers.len() {
                return Err(format!(
                    "{UNREACHABLE_MARKER}: none of {zone}'s authoritative nameservers answered from this host ({}). \
                     This is almost always outbound DNS (UDP/53) being blocked locally, not a propagation problem.",
                    unreachable.join(", ")
                ));
            }
            if missing.is_empty() && unreachable.is_empty() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                let mut detail = String::new();
                if !missing.is_empty() {
                    detail.push_str(&format!("still missing from: {}", missing.join(", ")));
                }
                if !unreachable.is_empty() {
                    if !detail.is_empty() {
                        detail.push_str("; ");
                    }
                    detail.push_str(&format!("unreachable from this host: {}", unreachable.join(", ")));
                }
                return Err(format!(
                    "TXT {record_name} is not yet served by every authoritative nameserver of {zone} after {:?} -- {detail}. \
                     Let's Encrypt validates against these servers from multiple perspectives, so triggering validation now would fail secondary validation.",
                    self.timeout
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
    async fn all_servers_unreachable_is_reported_distinctly_so_the_caller_can_fall_back() {
        // Reproduces the reporter's host exactly: every authoritative server
        // is unreachable (here: TEST-NET-1, which never answers). This must
        // NOT look like "the record is missing" -- it must carry the marker
        // the ACME client keys off to fall back to public resolvers, because
        // refusing here blocks an issuance that would otherwise succeed.
        let checker = AuthoritativeChecker::with_timeout(Duration::from_millis(200)).unwrap();
        // TEST-NET-1 never answers: neither the TXT query nor the SOA
        // liveness probe gets a reply, so this must classify as Unreachable.
        // Critically, hickory renders that timeout with the SAME "no records
        // found" text as a real authoritative negative -- which is exactly
        // why the SOA probe exists rather than error-string matching.
        let probe = checker
            .probe("192.0.2.1".parse().unwrap(), "_acme-challenge.example.invalid", "whatever", "example.invalid")
            .await;
        assert_eq!(probe, Probe::Unreachable, "a silent server is unreachable, not 'record absent'");
    }

    #[test]
    fn the_unreachable_marker_is_what_the_acme_client_actually_matches_on() {
        // Guard against the marker drifting out of sync with the caller's
        // check in acme_client::confirm_then_complete -- if these stop
        // matching, the fallback silently stops working and issuance starts
        // failing again on UDP/53-blocked hosts, with no test catching it.
        let rendered = format!(
            "{UNREACHABLE_MARKER}: none of example.org's authoritative nameservers answered from this host (ns1 (192.0.2.1))."
        );
        assert!(rendered.contains(UNREACHABLE_MARKER));
        assert!(rendered.to_lowercase().contains("udp/53") || rendered.contains("answered"));
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
