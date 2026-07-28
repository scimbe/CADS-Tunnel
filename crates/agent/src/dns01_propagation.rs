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

use std::time::{Duration, Instant};

pub const DEFAULT_RESOLVER_URLS: &[&str] = &["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"];
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(90);
const DEFAULT_INTERVAL: Duration = Duration::from_secs(3);

pub struct PropagationWaiter {
    http: reqwest::Client,
    resolver_urls: Vec<String>,
    timeout: Duration,
    interval: Duration,
}

impl PropagationWaiter {
    pub fn new(resolver_urls: Vec<String>, timeout: Duration) -> Self {
        Self::with_interval(resolver_urls, timeout, DEFAULT_INTERVAL)
    }

    pub(crate) fn with_interval(resolver_urls: Vec<String>, timeout: Duration, interval: Duration) -> Self {
        Self { http: reqwest::Client::new(), resolver_urls, timeout, interval }
    }

    /// Poll every configured resolver for `record_name`'s TXT value each
    /// round, succeeding as soon as *any one* of them shows `expected_value`
    /// -- until `timeout` elapses. A resolver-side hiccup (network error,
    /// non-2xx) is treated as "not yet visible from that resolver" and
    /// retried rather than failing immediately; only running out of time
    /// with no resolver agreeing is a hard error.
    pub async fn wait_for(&self, record_name: &str, expected_value: &str) -> Result<(), String> {
        let deadline = Instant::now() + self.timeout;
        let mut last_seen: Vec<String> = Vec::new();
        loop {
            for resolver_url in &self.resolver_urls {
                if let Ok(values) = self.lookup(resolver_url, record_name).await {
                    if values.iter().any(|v| v == expected_value) {
                        return Ok(());
                    }
                    last_seen = values;
                }
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "TXT record for {record_name} did not become publicly resolvable within {:?} across {} resolver(s) (last seen: {last_seen:?})",
                    self.timeout,
                    self.resolver_urls.len()
                ));
            }
            tokio::time::sleep(self.interval).await;
        }
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
    use std::sync::Arc;

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
}
