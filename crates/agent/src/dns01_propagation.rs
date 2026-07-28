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
//! this self-checks via a public DNS-over-HTTPS resolver first, over HTTPS
//! (443), which stays reachable even on hosts that block outbound UDP/53.

use std::time::{Duration, Instant};

pub const DEFAULT_RESOLVER_URL: &str = "https://cloudflare-dns.com/dns-query";
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(90);
const DEFAULT_INTERVAL: Duration = Duration::from_secs(3);

pub struct PropagationWaiter {
    http: reqwest::Client,
    resolver_url: String,
    timeout: Duration,
    interval: Duration,
}

impl PropagationWaiter {
    pub fn new(resolver_url: String, timeout: Duration) -> Self {
        Self::with_interval(resolver_url, timeout, DEFAULT_INTERVAL)
    }

    pub(crate) fn with_interval(resolver_url: String, timeout: Duration, interval: Duration) -> Self {
        Self { http: reqwest::Client::new(), resolver_url, timeout, interval }
    }

    /// Poll the resolver for `record_name`'s TXT value until it contains
    /// `expected_value`, or `timeout` elapses. A resolver-side hiccup (network
    /// error, non-2xx) is treated as "not yet visible" and retried rather than
    /// failing immediately -- only running out of time is a hard error.
    pub async fn wait_for(&self, record_name: &str, expected_value: &str) -> Result<(), String> {
        let deadline = Instant::now() + self.timeout;
        let mut last_seen: Vec<String> = Vec::new();
        loop {
            if let Ok(values) = self.lookup(record_name).await {
                if values.iter().any(|v| v == expected_value) {
                    return Ok(());
                }
                last_seen = values;
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "TXT record for {record_name} did not become publicly resolvable within {:?} (last seen: {last_seen:?})",
                    self.timeout
                ));
            }
            tokio::time::sleep(self.interval).await;
        }
    }

    async fn lookup(&self, name: &str) -> Result<Vec<String>, String> {
        let resp = self
            .http
            .get(&self.resolver_url)
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
        let waiter = PropagationWaiter::with_interval(url, Duration::from_secs(5), Duration::from_millis(10));
        waiter.wait_for("_acme-challenge.example.test", "abc123").await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retries_until_the_record_appears() {
        let calls = Arc::new(AtomicU32::new(0));
        let url = spawn_mock(MockResolver { calls: calls.clone(), answers_after: 3, value: "xyz789".into() }).await;
        let waiter = PropagationWaiter::with_interval(url, Duration::from_secs(5), Duration::from_millis(10));
        waiter.wait_for("_acme-challenge.example.test", "xyz789").await.unwrap();
        assert!(calls.load(Ordering::SeqCst) >= 4);
    }

    #[tokio::test]
    async fn times_out_with_a_clear_error_if_the_value_never_matches() {
        let calls = Arc::new(AtomicU32::new(0));
        let url = spawn_mock(MockResolver { calls, answers_after: 0, value: "wrong-value".into() }).await;
        let waiter = PropagationWaiter::with_interval(url, Duration::from_millis(50), Duration::from_millis(10));
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
            "http://127.0.0.1:1".to_string(),
            Duration::from_millis(50),
            Duration::from_millis(10),
        );
        let err = waiter.wait_for("_acme-challenge.example.test", "whatever").await.unwrap_err();
        assert!(err.contains("did not become publicly resolvable"), "{err}");
    }
}
