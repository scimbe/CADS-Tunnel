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
}

impl PropagationWaiter {
    pub fn new(resolver_urls: Vec<String>, timeout: Duration) -> Self {
        Self::with_interval(resolver_urls, timeout, DEFAULT_INTERVAL)
    }

    pub(crate) fn with_interval(resolver_urls: Vec<String>, timeout: Duration, interval: Duration) -> Self {
        Self {
            http: reqwest::Client::new(),
            resolver_urls,
            timeout,
            interval,
            cloudflare_doh_url: CLOUDFLARE_DOH.to_string(),
            cloudflare_purge_url: CLOUDFLARE_PURGE_URL.to_string(),
        }
    }

    #[cfg(test)]
    fn with_cloudflare_urls(
        resolver_urls: Vec<String>,
        timeout: Duration,
        interval: Duration,
        cloudflare_doh_url: String,
        cloudflare_purge_url: String,
    ) -> Self {
        Self { http: reqwest::Client::new(), resolver_urls, timeout, interval, cloudflare_doh_url, cloudflare_purge_url }
    }

    /// Poll every configured resolver for `record_name`'s TXT value each
    /// round, succeeding as soon as *any one* of them shows `expected_value`
    /// -- until `timeout` elapses. A resolver-side hiccup (network error,
    /// non-2xx) is treated as "not yet visible from that resolver" and
    /// retried rather than failing immediately; only running out of time
    /// with no resolver agreeing is a hard error. A miss on Cloudflare
    /// specifically also actively purges that query from Cloudflare's own
    /// cache before the next round, rather than only hoping either real
    /// propagation or the cached TTL wins the race first.
    pub async fn wait_for(&self, record_name: &str, expected_value: &str) -> Result<(), String> {
        let deadline = Instant::now() + self.timeout;
        let mut last_seen: Vec<String> = Vec::new();
        loop {
            let mut cloudflare_missed = false;
            for resolver_url in &self.resolver_urls {
                if let Ok(values) = self.lookup(resolver_url, record_name).await {
                    if values.iter().any(|v| v == expected_value) {
                        return Ok(());
                    }
                    last_seen = values;
                }
                if *resolver_url == self.cloudflare_doh_url {
                    cloudflare_missed = true;
                }
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "TXT record for {record_name} did not become publicly resolvable within {:?} across {} resolver(s) (last seen: {last_seen:?})",
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
        let waiter = PropagationWaiter::with_interval(vec![url], Duration::from_secs(5), Duration::from_millis(10));
        waiter.wait_for("_acme-challenge.example.test", "abc123").await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retries_until_the_record_appears() {
        let calls = Arc::new(AtomicU32::new(0));
        let url = spawn_mock(MockResolver { calls: calls.clone(), answers_after: 3, value: "xyz789".into() }).await;
        let waiter = PropagationWaiter::with_interval(vec![url], Duration::from_secs(5), Duration::from_millis(10));
        waiter.wait_for("_acme-challenge.example.test", "xyz789").await.unwrap();
        assert!(calls.load(Ordering::SeqCst) >= 4);
    }

    #[tokio::test]
    async fn times_out_with_a_clear_error_if_the_value_never_matches() {
        let calls = Arc::new(AtomicU32::new(0));
        let url = spawn_mock(MockResolver { calls, answers_after: 0, value: "wrong-value".into() }).await;
        let waiter =
            PropagationWaiter::with_interval(vec![url], Duration::from_millis(50), Duration::from_millis(10));
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
        );
        let err = waiter.wait_for("_acme-challenge.example.test", "whatever").await.unwrap_err();
        assert!(err.contains("did not become publicly resolvable"), "{err}");
    }

    #[tokio::test]
    async fn a_second_resolver_still_confirms_when_the_first_has_a_stale_negative_cache() {
        // Reproduces #229's actual failure shape: one resolver has already
        // cached NXDOMAIN for this exact query (e.g. from an earlier failed
        // attempt at the same hostname) and never sees the record no matter
        // how long we wait; a second, independent resolver has not, and
        // shows it immediately -- succeeding overall.
        let stale_calls = Arc::new(AtomicU32::new(0));
        let stale =
            spawn_mock(MockResolver { calls: stale_calls.clone(), answers_after: u32::MAX, value: "v1".into() })
                .await;
        let fresh = spawn_mock(MockResolver { calls: Arc::new(AtomicU32::new(0)), answers_after: 0, value: "v1".into() }).await;

        let waiter = PropagationWaiter::with_interval(
            vec![stale, fresh],
            Duration::from_secs(5),
            Duration::from_millis(10),
        );
        waiter.wait_for("_acme-challenge.example.test", "v1").await.unwrap();
        assert_eq!(stale_calls.load(Ordering::SeqCst), 1, "queried the stale resolver too, just didn't wait on it");
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
