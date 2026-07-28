//! Edge-side client for the control plane's multi-edge ownership registry
//! (`ct-control-plane`'s `edge_mesh` module, #153/edge_mesh Phase 0).
//!
//! Two calls: [`rehydrate`] (boot-time — replay every (token, hostname) pair
//! the control plane recorded this edge as owning back into local `host_auth`,
//! so a container restart no longer silently forgets every hostname
//! authorization) and [`heartbeat`] (periodic — tell the control plane this
//! edge is live and how to reach it, the prerequisite for a second edge to
//! ever be assigned traffic). Mirrors [`crate::channel_authorize::ChannelAuthorizer`]'s
//! shape: a small `reqwest::Client` with a bounded timeout, fail-soft (a
//! failure here must never crash the edge — it only means this boot starts
//! with an empty/stale registry view, exactly like today's pre-registry
//! behavior).

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Bound on a single rehydrate/heartbeat round-trip — the control plane must
/// never hang the edge's boot sequence or its periodic heartbeat loop.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[derive(Deserialize)]
struct RehydratePair {
    token: String,
    hostname: Option<String>,
}

#[derive(Serialize)]
struct HeartbeatReq<'a> {
    id: &'a str,
    peer_addr: &'a str,
}

/// A resolved `(routing_token, hostname)` pair to replay locally, or a token
/// that failed to parse (skipped, not fatal — one malformed row must not
/// drop every other valid one).
pub struct RehydratedPair {
    pub token: [u8; 32],
    pub hostname: Option<String>,
}

/// Fetch every (token, hostname) pair the control plane has recorded as owned
/// by `edge_id`, for boot-time replay into local `host_auth`. Fail-soft:
/// returns an empty vec (not an error the caller must handle specially) on
/// any transport/auth/parse failure — a fresh/unreachable registry just means
/// this boot starts with nothing to replay, the same as before this feature
/// existed. Malformed individual token hex strings are skipped, not fatal.
pub async fn rehydrate(cp_url: &str, admin_token: &[u8; 32], edge_id: &str) -> Vec<RehydratedPair> {
    let client = match reqwest::Client::builder().timeout(DEFAULT_TIMEOUT).build() {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let url = format!("{}/internal/edges/rehydrate/{}", cp_url.trim_end_matches('/'), edge_id);
    let resp = match client.get(&url).header("x-ct-admin-token", hex(admin_token)).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return Vec::new(),
    };
    let pairs: Vec<RehydratePair> = match resp.json().await {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    pairs
        .into_iter()
        .filter_map(|p| hex_decode_32(&p.token).map(|token| RehydratedPair { token, hostname: p.hostname }))
        .collect()
}

/// Announce this edge (`id`, reachable at `peer_addr`) to the control plane's
/// mesh registry. Fail-soft: a failure is silent (no panic, no log spam on a
/// tight retry loop) — the next heartbeat tick tries again.
pub async fn heartbeat(cp_url: &str, admin_token: &[u8; 32], id: &str, peer_addr: &str) {
    let client = match reqwest::Client::builder().timeout(DEFAULT_TIMEOUT).build() {
        Ok(c) => c,
        Err(_) => return,
    };
    let url = format!("{}/internal/edges/heartbeat", cp_url.trim_end_matches('/'));
    let _ = client
        .post(&url)
        .header("x-ct-admin-token", hex(admin_token))
        .json(&HeartbeatReq { id, peer_addr })
        .send()
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Json as AxJson, Path as AxPath};
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::{get, post};
    use axum::Router;
    use serde_json::Value;
    use std::sync::{Arc, Mutex};

    fn admin_ok(headers: &HeaderMap, expected: &[u8; 32]) -> bool {
        headers.get("x-ct-admin-token").and_then(|v| v.to_str().ok()) == Some(&hex(expected))
    }

    async fn spawn_mock_cp(
        secret: [u8; 32],
        pairs_json: &'static str,
        heartbeat_hits: Arc<Mutex<Vec<Value>>>,
    ) -> String {
        let hits = heartbeat_hits.clone();
        let app = Router::new()
            .route(
                "/internal/edges/rehydrate/:edge_id",
                get(move |headers: HeaderMap, AxPath(_edge_id): AxPath<String>| async move {
                    if !admin_ok(&headers, &secret) {
                        return (StatusCode::UNAUTHORIZED, "").into_response();
                    }
                    (StatusCode::OK, pairs_json).into_response()
                }),
            )
            .route(
                "/internal/edges/heartbeat",
                post(move |headers: HeaderMap, AxJson(body): AxJson<Value>| {
                    let hits = hits.clone();
                    async move {
                        if !admin_ok(&headers, &secret) {
                            return StatusCode::UNAUTHORIZED;
                        }
                        hits.lock().unwrap().push(body);
                        StatusCode::OK
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    use axum::response::IntoResponse;

    #[tokio::test]
    async fn rehydrate_replays_valid_pairs_and_skips_malformed_ones() {
        let secret = [0x11u8; 32];
        let hits = Arc::new(Mutex::new(Vec::new()));
        let base = spawn_mock_cp(
            secret,
            r#"[{"token":"aa11223344556677889900112233445566778899001122334455667788990011","hostname":"a.example.com"},
                {"token":"not-hex","hostname":"b.example.com"},
                {"token":"bb11223344556677889900112233445566778899001122334455667788990011","hostname":null}]"#,
            hits.clone(),
        )
        .await;

        let got = rehydrate(&base, &secret, "primary").await;
        assert_eq!(got.len(), 2, "the malformed-token row is skipped, not fatal to the others");
        assert_eq!(got[0].hostname.as_deref(), Some("a.example.com"));
        assert_eq!(got[1].hostname, None, "a Mesh-Plane-only token (no hostname) round-trips as None");
    }

    #[tokio::test]
    async fn rehydrate_fails_soft_on_wrong_token_or_unreachable_cp() {
        let secret = [0x22u8; 32];
        let hits = Arc::new(Mutex::new(Vec::new()));
        let base = spawn_mock_cp(secret, r#"[]"#, hits).await;

        let wrong = rehydrate(&base, &[0u8; 32], "primary").await;
        assert!(wrong.is_empty(), "wrong admin token -> empty, not a panic");

        let down = rehydrate("http://127.0.0.1:1", &secret, "primary").await;
        assert!(down.is_empty(), "unreachable CP -> empty, not a panic");
    }

    #[tokio::test]
    async fn heartbeat_posts_id_and_peer_addr_with_the_admin_token() {
        let secret = [0x33u8; 32];
        let hits = Arc::new(Mutex::new(Vec::new()));
        let base = spawn_mock_cp(secret, r#"[]"#, hits.clone()).await;

        heartbeat(&base, &secret, "primary", "10.0.0.5:4433").await;
        let recorded = hits.lock().unwrap().clone();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0]["id"], "primary");
        assert_eq!(recorded[0]["peer_addr"], "10.0.0.5:4433");
    }

    #[tokio::test]
    async fn heartbeat_fails_soft_on_wrong_token_or_unreachable_cp() {
        let secret = [0x44u8; 32];
        let hits = Arc::new(Mutex::new(Vec::new()));
        let base = spawn_mock_cp(secret, r#"[]"#, hits.clone()).await;

        // Wrong token: server refuses, but the call itself must not panic.
        heartbeat(&base, &[0u8; 32], "primary", "10.0.0.5:4433").await;
        assert!(hits.lock().unwrap().is_empty(), "refused heartbeat never recorded");

        // Unreachable CP: same, no panic.
        heartbeat("http://127.0.0.1:1", &secret, "primary", "10.0.0.5:4433").await;
    }
}
