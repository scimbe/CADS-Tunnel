//! Confirms a DNS-01 `_acme-challenge` TXT record is *publicly* resolvable
//! before telling the ACME server to validate it.
//!
//! A successful [`ct_dns::provider::Dns01Provider::set_txt`] call only proves
//! the control plane's DNS backend (e.g. deSEC) *accepted* the write — not
//! that it has replicated to the public-facing authoritative nameservers the
//! CA will actually query. Triggering validation before that replication
//! finishes is a real race (deSEC and most managed DNS backends have a short
//! but nonzero propagation delay), and once an ACME authorization is marked
//! `invalid` it cannot be retried — the client must start a fresh order. So
//! this self-checks via public DNS-over-HTTPS resolvers first, over HTTPS
//! (443), which stays reachable even on hosts that block outbound UDP/53.
//!
//! Queries more than one independent resolver operator (not just one): a
//! resolver that already answered NXDOMAIN for this exact query name (e.g.
//! from an earlier failed attempt at the same hostname) keeps serving that
//! cached negative answer for the zone's negative-cache TTL (the SOA
//! `minimum` field -- commonly up to an hour), regardless of whether the
//! authoritative data has since changed. A single retried hostname can very
//! plausibly have already been queried against the default resolver by an
//! earlier attempt; a second, independent resolver operator is unlikely to
//! share that exact cache poisoning.
//!
//! [`DEFAULT_TIMEOUT`] has real margin built in on purpose: measured deSEC
//! propagation to a public resolver has ranged from ~10s up to just over 90s
//! across repeated live tests against the same zone -- a short timeout here
//! doesn't just risk a slower issuance, it risks the record briefly
//! *becoming* valid just after giving up, only for the caller's own
//! post-attempt cleanup (always run, success or failure -- see
//! `crate::acme_client::AcmeClient::validate_authorization`) to delete it
//! moments later, which from the outside looks indistinguishable from
//! "never published at all."

use std::time::{Duration, Instant};

pub const DEFAULT_RESOLVER_URLS: &[&str] = &["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"];
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(180);
const DEFAULT_INTERVAL: Duration = Duration::from_secs(3);

/// Wait this long after publishing before the *first* lookup.
///
/// This is not politeness -- it is the difference between working and not.
/// Querying a name before it has propagated makes the resolver cache the
/// resulting NXDOMAIN for the zone's SOA `minimum` (3600s on deSEC, which
/// enforces a 3600 floor -- a `ttl: 60` PATCH is rejected outright with
/// "Ensure this value is greater than or equal to 3600"). So an eager first
/// poll *causes* the very stale-negative-cache failure the rest of this
/// module then spends its whole timeout budget fighting: every subsequent
/// poll for the next hour sees our own poisoned entry, not reality.
///
/// `acme.sh` -- the manual path that has always worked here -- does the same
/// thing for the same reason ("Let's check each DNS record now. Sleeping for
/// 20 seconds first." before `_check_dns_entries`).
///
/// The value is deliberately **not** acme.sh's 20s. Measured on this
/// deployment's own deSEC zone, a freshly written TXT record reaches:
///   - deSEC's own authoritative NS in ~11-55s,
///   - Google's public resolver at ~38s,
///   - Cloudflare's not yet at 53s.
/// A 20s delay would therefore still fire the first lookup into a
/// not-yet-visible record on this zone and re-poison the cache -- the exact
/// bug this constant exists to prevent. 75s clears the measured worst case
/// with margin. If a deployment's DNS is faster, lower it via
/// `CT_ACME_DNS01_INITIAL_DELAY_SECS`; the cost of being too high is only a
/// slower issuance, while too low silently breaks issuance for an hour.
const DEFAULT_INITIAL_DELAY: Duration = Duration::from_secs(75);

/// Cloudflare's own DoH endpoint, and the public (unauthenticated) 1.1.1.1
/// resolver cache-purge endpoint the same one `acme.sh`'s `dns_desec`/
/// `_ns_purge_cf` uses -- verified directly (not from a docs page; no public
/// Cloudflare docs page actually covers this specific endpoint):
/// `curl -sL -X POST 'https://cloudflare-dns.com/api/v1/purge?domain=example.com&type=A'`
/// returns a genuine `200` with
/// `{"msg":"purge request queued. Please wait a few seconds and verify the
/// request was successful"}`, distinct from Cloudflare's real error page for
/// an actually-nonexistent path on the same host. Purges the **public 1.1.1.1
/// resolver's cached answer** for a query name -- unrelated to, and much
/// narrower than, Cloudflare's authenticated zone-level CDN cache-purge API
/// (`api.cloudflare.com`), which only affects zones you own.
const CLOUDFLARE_DOH: &str = "https://cloudflare-dns.com/dns-query";
const CLOUDFLARE_PURGE_URL: &str = "https://cloudflare-dns.com/api/v1/purge";

pub struct PropagationWaiter {
    http: reqwest::Client,
    resolver_urls: Vec<String>,
    timeout: Duration,
    interval: Duration,
    // Which configured resolver_url gets the active cache-purge treatment on
    // a miss, and where its purge endpoint lives -- real Cloudflare in
    // production; a mock server in tests, so this is hermetically testable
    // without ever calling the live purge API from a test.
    cloudflare_doh_url: String,
    cloudflare_purge_url: String,
    initial_delay: Duration,
}

impl PropagationWaiter {
    pub fn new(resolver_urls: Vec<String>, timeout: Duration) -> Self {
        Self::with_interval(resolver_urls, timeout, DEFAULT_INTERVAL)
    }

    /// Override the pre-check delay (see [`DEFAULT_INITIAL_DELAY`] -- too low
    /// silently breaks issuance for an hour, too high only costs time).
    pub fn with_initial_delay(mut self, initial_delay: Duration) -> Self {
        self.initial_delay = initial_delay;
        self
    }

    pub(crate) fn with_interval(resolver_urls: Vec<String>, timeout: Duration, interval: Duration) -> Self {
        Self {
            http: reqwest::Client::new(),
            resolver_urls,
            timeout,
            interval,
            cloudflare_doh_url: CLOUDFLARE_DOH.to_string(),
            cloudflare_purge_url: CLOUDFLARE_PURGE_URL.to_string(),
            initial_delay: DEFAULT_INITIAL_DELAY,
        }
    }

    /// Tests only: skip the pre-check delay (its whole point is real-world
    /// resolver-cache behavior, which a mock server does not have).
    #[cfg(test)]
    fn without_initial_delay(mut self) -> Self {
        self.initial_delay = Duration::ZERO;
        self
    }

    #[cfg(test)]
    fn with_cloudflare_urls(
        resolver_urls: Vec<String>,
        timeout: Duration,
        interval: Duration,
        cloudflare_doh_url: String,
        cloudflare_purge_url: String,
    ) -> Self {
        Self {
            http: reqwest::Client::new(),
            resolver_urls,
            timeout,
            interval,
            cloudflare_doh_url,
            cloudflare_purge_url,
            initial_delay: Duration::ZERO,
        }
    }

    /// Poll every configured resolver for `record_name`'s TXT value each
    /// round, succeeding only once **all** of them agree on `expected_value`
    /// in the *same* round -- until `timeout` elapses. This is deliberately
    /// stronger than "any one resolver": Let's Encrypt's own validation does
    /// a primary check plus multi-perspective secondary validation from
    /// several geographically distributed vantage points (CA/Browser Forum
    /// SC067), and requires them to agree. A single resolver we happen to
    /// query from this one network location is a weak proxy for that -- we
    /// saw exactly this gap directly: our own (single-resolver-satisfied)
    /// check passed, then Let's Encrypt's own secondary validation still
    /// failed, because the record genuinely wasn't visible everywhere yet.
    /// Requiring every configured resolver to agree is a stronger, closer
    /// (if still imperfect) proxy for that global visibility.
    ///
    /// A resolver-side hiccup (network error, non-2xx) is treated as "not
    /// yet visible from that resolver" and retried rather than failing
    /// immediately; only running out of time without full agreement is a
    /// hard error. A miss on Cloudflare specifically also actively purges
    /// that query from Cloudflare's own cache before the next round, rather
    /// than only hoping either real propagation or the cached TTL wins the
    /// race first.
    pub async fn wait_for(&self, record_name: &str, expected_value: &str) -> Result<(), String> {
        // Deliberately BEFORE the deadline is taken: this delay buys propagation
        // headroom, it must not eat the polling budget (see DEFAULT_INITIAL_DELAY
        // -- an early first lookup poisons the resolver cache with an NXDOMAIN
        // that then outlives the entire timeout).
        tokio::time::sleep(self.initial_delay).await;
        let deadline = Instant::now() + self.timeout;
        let mut last_seen: Vec<String> = Vec::new();
        loop {
            let mut cloudflare_missed = false;
            let mut all_agree = true;
            for resolver_url in &self.resolver_urls {
                let matched = match self.lookup(resolver_url, record_name).await {
                    Ok(values) => {
                        let matched = values.iter().any(|v| v == expected_value);
                        if !matched {
                            last_seen = values;
                        }
                        matched
                    }
                    Err(_) => false,
                };
                if !matched {
                    all_agree = false;
                    if *resolver_url == self.cloudflare_doh_url {
                        cloudflare_missed = true;
                    }
                }
            }
            if all_agree {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "TXT record for {record_name} did not become publicly resolvable everywhere within {:?} across {} resolver(s) (last seen: {last_seen:?})",
                    self.timeout,
                    self.resolver_urls.len()
                ));
            }
            if cloudflare_missed {
                self.purge_cloudflare(record_name).await;
            }
            tokio::time::sleep(self.interval).await;
        }
    }

    /// Best-effort: ask Cloudflare to drop its own cached answer for this
    /// exact query so the *next* poll has a real chance of seeing a fresh
    /// answer instead of a stale one served for the rest of its TTL.
    /// Failure is not fatal -- the retry loop still works without it, just
    /// slower (limited to whatever the multi-resolver fallback already
    /// covers).
    async fn purge_cloudflare(&self, record_name: &str) {
        let _ = self
            .http
            .post(&self.cloudflare_purge_url)
            .query(&[("domain", record_name), ("type", "TXT")])
            .send()
            .await;
    }

    async fn lookup(&self, resolver_url: &str, name: &str) -> Result<Vec<String>, String> {
        let resp = self
            .http
            .get(resolver_url)
            .header("accept", "application/dns-json")
            .query(&[("name", name), ("type", "TXT")])
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("resolver returned {}", resp.status()));
        }
        let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        let answers = json.get("Answer").and_then(|a| a.as_array()).cloned().unwrap_or_default();
        Ok(answers
            .iter()
            .filter_map(|a| a.get("data").and_then(|d| d.as_str()))
            .map(|d| d.trim_matches('"').to_string())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    use axum::extract::{Query, State};
    use axum::routing::get;
    use axum::{Json, Router};

    use super::*;

    #[derive(Clone)]
    struct MockResolver {
        calls: Arc<AtomicU32>,
        answers_after: u32,
        value: String,
    }

    async fn doh_handler(
        State(state): State<MockResolver>,
        Query(_params): Query<std::collections::HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        let n = state.calls.fetch_add(1, Ordering::SeqCst);
        if n < state.answers_after {
            Json(serde_json::json!({"Status": 0, "Answer": []}))
        } else {
            Json(serde_json::json!({"Status": 0, "Answer": [{"data": format!("\"{}\"", state.value)}]}))
        }
    }

    async fn spawn_mock(state: MockResolver) -> String {
        let app = Router::new().route("/dns-query", get(doh_handler)).with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/dns-query")
    }

    #[tokio::test]
    async fn succeeds_immediately_when_the_record_is_already_visible() {
        let calls = Arc::new(AtomicU32::new(0));
        let url = spawn_mock(MockResolver { calls: calls.clone(), answers_after: 0, value: "abc123".into() }).await;
        let waiter = PropagationWaiter::with_interval(vec![url], Duration::from_secs(5), Duration::from_millis(10)).without_initial_delay();
        waiter.wait_for("_acme-challenge.example.test", "abc123").await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retries_until_the_record_appears() {
        let calls = Arc::new(AtomicU32::new(0));
        let url = spawn_mock(MockResolver { calls: calls.clone(), answers_after: 3, value: "xyz789".into() }).await;
        let waiter = PropagationWaiter::with_interval(vec![url], Duration::from_secs(5), Duration::from_millis(10)).without_initial_delay();
        waiter.wait_for("_acme-challenge.example.test", "xyz789").await.unwrap();
        assert!(calls.load(Ordering::SeqCst) >= 4);
    }

    #[tokio::test]
    async fn times_out_with_a_clear_error_if_the_value_never_matches() {
        let calls = Arc::new(AtomicU32::new(0));
        let url = spawn_mock(MockResolver { calls, answers_after: 0, value: "wrong-value".into() }).await;
        let waiter =
            PropagationWaiter::with_interval(vec![url], Duration::from_millis(50), Duration::from_millis(10)).without_initial_delay();
        let err = waiter.wait_for("_acme-challenge.example.test", "expected-value").await.unwrap_err();
        assert!(err.contains("did not become publicly resolvable"), "{err}");
        assert!(err.contains("wrong-value"), "{err}");
    }

    #[tokio::test]
    async fn tolerates_resolver_errors_and_keeps_retrying() {
        // Point at a URL with nothing listening -- every lookup errors -- and
        // confirm we still hit the timeout deadline rather than panicking or
        // returning early on the first transport error.
        let waiter = PropagationWaiter::with_interval(
            vec!["http://127.0.0.1:1".to_string()],
            Duration::from_millis(50),
            Duration::from_millis(10),
        ).without_initial_delay();
        let err = waiter.wait_for("_acme-challenge.example.test", "whatever").await.unwrap_err();
        assert!(err.contains("did not become publicly resolvable"), "{err}");
    }

    #[tokio::test]
    async fn succeeds_once_a_transiently_lagging_resolver_catches_up_too() {
        // One resolver is briefly behind (still propagating), the other is
        // already there -- success requires BOTH to agree, so this must wait
        // for the lagging one rather than declaring victory on the first hit.
        let lagging_calls = Arc::new(AtomicU32::new(0));
        let lagging =
            spawn_mock(MockResolver { calls: lagging_calls.clone(), answers_after: 3, value: "v1".into() }).await;
        let fast = spawn_mock(MockResolver { calls: Arc::new(AtomicU32::new(0)), answers_after: 0, value: "v1".into() }).await;

        let waiter = PropagationWaiter::with_interval(
            vec![lagging, fast],
            Duration::from_secs(5),
            Duration::from_millis(10),
        ).without_initial_delay();
        waiter.wait_for("_acme-challenge.example.test", "v1").await.unwrap();
        assert!(lagging_calls.load(Ordering::SeqCst) >= 4, "kept polling the lagging resolver until it agreed too");
    }

    #[tokio::test]
    async fn does_not_falsely_succeed_when_only_one_of_two_resolvers_ever_agrees() {
        // Reproduces the actual #229 failure this design change fixes: our
        // own check was satisfied by a single resolver while Let's Encrypt's
        // own multi-perspective secondary validation still failed, because
        // one resolver agreeing is a weak proxy for genuinely global
        // visibility. A resolver permanently stuck on a stale/wrong value
        // must NOT be outvoted by the other one appearing to work --
        // requiring unanimous agreement should time out here, not succeed.
        let stale_calls = Arc::new(AtomicU32::new(0));
        let stale =
            spawn_mock(MockResolver { calls: stale_calls.clone(), answers_after: u32::MAX, value: "v1".into() })
                .await;
        let fresh = spawn_mock(MockResolver { calls: Arc::new(AtomicU32::new(0)), answers_after: 0, value: "v1".into() }).await;

        let waiter = PropagationWaiter::with_interval(
            vec![stale, fresh],
            Duration::from_millis(100),
            Duration::from_millis(10),
        ).without_initial_delay();
        let err = waiter.wait_for("_acme-challenge.example.test", "v1").await.unwrap_err();
        assert!(err.contains("did not become publicly resolvable everywhere"), "{err}");
        assert!(stale_calls.load(Ordering::SeqCst) >= 1, "did poll the lagging resolver, just didn't accept an outvote");
    }

    #[test]
    fn the_default_waiter_delays_before_its_first_lookup() {
        // Regression guard for the actual #229 root cause: an eager first
        // lookup caches an NXDOMAIN for the zone's SOA minimum (3600s on
        // deSEC, which rejects any lower TTL), which then outlives the whole
        // timeout budget. The delay must be non-zero on the real constructor,
        // and must not be silently folded into the polling deadline.
        let waiter = PropagationWaiter::new(vec!["https://example.test/dns-query".into()], DEFAULT_TIMEOUT);
        assert_eq!(waiter.initial_delay, DEFAULT_INITIAL_DELAY);
        assert!(!waiter.initial_delay.is_zero(), "a zero pre-check delay reintroduces the self-poisoning bug");
        assert_eq!(waiter.timeout, DEFAULT_TIMEOUT, "the delay is extra headroom, not taken out of the poll budget");
    }

    #[derive(Clone, Default)]
    struct PurgeableCloudflareMock {
        lookups: Arc<AtomicU32>,
        purge_calls: Arc<Mutex<Vec<(String, String)>>>,
        purged: Arc<std::sync::atomic::AtomicBool>,
    }

    async fn cf_doh_handler(
        State(state): State<PurgeableCloudflareMock>,
        Query(_params): Query<std::collections::HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        state.lookups.fetch_add(1, Ordering::SeqCst);
        if state.purged.load(Ordering::SeqCst) {
            Json(serde_json::json!({"Status": 0, "Answer": [{"data": "\"fresh-value\""}]}))
        } else {
            // Stale cached hit -- keeps answering this, no matter how many
            // times it's asked, exactly like a resolver serving a cached
            // record for the rest of its TTL, until purged.
            Json(serde_json::json!({"Status": 0, "Answer": [{"data": "\"stale-cached-value\""}]}))
        }
    }

    async fn cf_purge_handler(
        State(state): State<PurgeableCloudflareMock>,
        Query(params): Query<std::collections::HashMap<String, String>>,
    ) -> axum::http::StatusCode {
        let domain = params.get("domain").cloned().unwrap_or_default();
        let rtype = params.get("type").cloned().unwrap_or_default();
        state.purge_calls.lock().unwrap().push((domain, rtype));
        state.purged.store(true, Ordering::SeqCst);
        axum::http::StatusCode::OK
    }

    #[tokio::test]
    async fn a_miss_on_the_cloudflare_resolver_actively_purges_its_cache_instead_of_only_waiting() {
        // Mirrors acme.sh's own dns_desec/_ns_purge_cf behavior: don't just
        // wait out a stale Cloudflare cache entry (or lean entirely on a
        // second resolver) -- actively tell Cloudflare to drop it, so the
        // very next poll has a real chance at a fresh answer.
        let state = PurgeableCloudflareMock::default();
        let app = Router::new()
            .route("/dns-query", get(cf_doh_handler))
            .route("/api/v1/purge", axum::routing::post(cf_purge_handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let cf_doh_url = format!("http://{addr}/dns-query");
        let cf_purge_url = format!("http://{addr}/api/v1/purge");

        let waiter = PropagationWaiter::with_cloudflare_urls(
            vec![cf_doh_url.clone()],
            Duration::from_secs(5),
            Duration::from_millis(10),
            cf_doh_url,
            cf_purge_url,
        );
        waiter.wait_for("_acme-challenge.example.test", "fresh-value").await.unwrap();

        let purges = state.purge_calls.lock().unwrap().clone();
        assert!(!purges.is_empty(), "purged at least once after a stale-cache miss");
        assert_eq!(purges[0], ("_acme-challenge.example.test".to_string(), "TXT".to_string()));
        assert!(state.lookups.load(Ordering::SeqCst) >= 2, "looked up again after purging, not just once");
    }
}
