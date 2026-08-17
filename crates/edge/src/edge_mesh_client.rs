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

/// #279: warn (never block — some deployments legitimately run the control
/// plane on a private/internal network, e.g. this project's own self-host
/// Docker Compose default of `http://control-plane:8090` on an internal
/// bridge network) when `cp_url` is plain HTTP and isn't an explicit
/// loopback address. Every call in this module (`rehydrate`/`heartbeat`/
/// `lookup_owner_by_host`/`fetch_revoked_tokens`) sends the shared
/// `x-ct-admin-token` (and rehydrated routing tokens/revocations) as a
/// header; over a genuinely untrusted network (a self-hoster who splits
/// Edge and control plane across separate hosts over the public internet)
/// that's cleartext-interceptable, and the code never rejected a non-TLS
/// URL. Call once at boot, not per-request — this would spam the log on
/// every 30s heartbeat otherwise.
pub fn warn_if_insecure_cp_url(cp_url: &str) {
    if is_insecure_cp_url(cp_url) {
        eprintln!(
            "ct-edge: WARNING -- CT_EDGE_CP_URL ({cp_url}) is plain HTTP, not HTTPS. The shared admin \
             token (and rehydrated routing tokens/revocations, #327) travel in cleartext on this \
             connection. Fine on a genuinely private/internal network (e.g. this project's own self-host \
             Docker Compose default); a real exposure if the Edge and control plane are reachable from an \
             untrusted network. Set CT_EDGE_CP_URL to an https:// endpoint if they aren't on the same \
             trusted private network."
        );
    }
}

/// The pure check behind [`warn_if_insecure_cp_url`], split out so it's
/// testable without capturing stderr: `true` iff `cp_url` is plain HTTP and
/// isn't an explicit loopback address.
fn is_insecure_cp_url(cp_url: &str) -> bool {
    let is_https = cp_url.starts_with("https://");
    let is_loopback = ["http://127.", "http://localhost", "http://[::1]"]
        .iter()
        .any(|prefix| cp_url.starts_with(prefix));
    !is_https && !is_loopback
}

/// Bound on a single rehydrate/heartbeat round-trip — the control plane must
/// never hang the edge's boot sequence or its periodic heartbeat loop.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// #358: a single, shared `reqwest::Client` for every call in this module,
/// instead of `rehydrate`/`fetch_revoked_tokens`/`heartbeat`/`lookup_owner_by_host`
/// each building (and TLS-handshaking) a fresh one per invocation. Deliberately
/// the opposite tradeoff from [`crate::channel_authorize::ChannelAuthorizer`]'s
/// own `pool_max_idle_per_host(0)`: that call is low-frequency and
/// latency-sensitive per-call (one real user-facing channel join), so a stale
/// pooled connection surviving a CP restart risks a single request stuck until
/// an OS-level TCP timeout. `heartbeat` here runs every 10-30s and is already
/// fail-soft/retried by design — a stale pooled connection on one tick just
/// means that tick's request fails fast (hyper's pool evicts a dead connection
/// on a failed write) and the next tick, seconds later, succeeds fresh. At that
/// call frequency, reusing keep-alive/TLS-session state is the real win the
/// issue asks for, not a risk.
static SHARED_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| reqwest::Client::builder().timeout(DEFAULT_TIMEOUT).build().unwrap_or_else(|_| reqwest::Client::new()));

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
/// #548: the outcome of a rehydration attempt, because "0 pairs" has two opposite meanings.
/// An empty registry is a normal fresh deployment; an unreachable or unreadable one means
/// every Browser-Plane hostname will fail to route until a later attempt succeeds. Both used
/// to produce the identical `rehydrated 0 hostname authorization(s)` line, which gives an
/// operator watching a deploy no reason to act while nothing is being served.
pub enum Rehydration {
    /// The registry answered. `pairs` may legitimately be empty.
    Answered(Vec<RehydratedPair>),
    /// The registry could not be reached or its answer could not be read. `why` is for the
    /// log line, not for control flow -- the caller retries regardless of the reason.
    Unavailable(String),
}

impl Rehydration {
    /// The pairs to replay; empty when the registry was unavailable. Keeps the call site's
    /// replay loop unchanged -- the distinction drives logging and retry, not the replay.
    pub fn pairs(self) -> Vec<RehydratedPair> {
        match self {
            Self::Answered(p) => p,
            Self::Unavailable(_) => Vec::new(),
        }
    }
}

pub async fn rehydrate(cp_url: &str, admin_token: &[u8; 32], edge_id: &str) -> Rehydration {
    let url = format!("{}/internal/edges/rehydrate/{}", cp_url.trim_end_matches('/'), edge_id);
    let resp = match SHARED_CLIENT.get(&url).header("x-ct-admin-token", hex(admin_token)).send().await {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => return Rehydration::Unavailable(format!("registry answered {}", r.status())),
        Err(e) => return Rehydration::Unavailable(format!("registry unreachable: {e}")),
    };
    let pairs: Vec<RehydratePair> = match resp.json().await {
        Ok(p) => p,
        Err(e) => return Rehydration::Unavailable(format!("registry answer unreadable: {e}")),
    };
    Rehydration::Answered(
        pairs
            .into_iter()
            .filter_map(|p| hex_decode_32(&p.token).map(|token| RehydratedPair { token, hostname: p.hostname }))
            .collect(),
    )
}

#[derive(Deserialize)]
struct RevokedTokensResp {
    tokens: Vec<String>,
}

/// Fetch every routing token the control plane has durably recorded as
/// revoked (#327), for boot-time replay into the local `revoked` set
/// (`crate::state::EdgeState`) — without this, an Edge restart silently
/// forgets every revocation and a still-reconnecting Agent for an
/// already-revoked tunnel would successfully re-register. Same fail-soft
/// contract as [`rehydrate`]: any transport/auth/parse failure yields an
/// empty vec rather than blocking or crashing boot — a fresh/unreachable
/// registry just means this boot starts with nothing replayed, the same gap
/// that existed before this feature (not a regression). Malformed individual
/// token hex strings are skipped, not fatal.
pub async fn fetch_revoked_tokens(cp_url: &str, admin_token: &[u8; 32]) -> Vec<[u8; 32]> {
    let url = format!("{}/internal/revoked-tokens", cp_url.trim_end_matches('/'));
    let resp = match SHARED_CLIENT.get(&url).header("x-ct-admin-token", hex(admin_token)).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return Vec::new(),
    };
    let body: RevokedTokensResp = match resp.json().await {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    body.tokens.into_iter().filter_map(|t| hex_decode_32(&t)).collect()
}

/// Announce this edge (`id`, reachable at `peer_addr`) to the control plane's
/// mesh registry. Fail-soft: a failure is silent (no panic, no log spam on a
/// tight retry loop) — the next heartbeat tick tries again.
pub async fn heartbeat(cp_url: &str, admin_token: &[u8; 32], id: &str, peer_addr: &str) {
    let url = format!("{}/internal/edges/heartbeat", cp_url.trim_end_matches('/'));
    let _ = SHARED_CLIENT
        .post(&url)
        .header("x-ct-admin-token", hex(admin_token))
        .json(&HeartbeatReq { id, peer_addr })
        .send()
        .await;
}

#[derive(Deserialize)]
struct OwnerResp {
    #[allow(dead_code)]
    edge_id: String,
    peer_addr: String,
}

/// Ask the control plane which edge (ADR-0021 Part 1) owns `hostname`, for the
/// edge-to-edge mesh-relay fallback when a Client lands on an edge that has no
/// local route for it. Fail-soft: `None` on any transport/auth/parse failure or
/// a genuine 404 (nobody owns this hostname) -- the caller's existing "no
/// tunnel registered" error path is the correct fallback either way, so a
/// registry hiccup never turns into a hard failure beyond what already existed
/// before this feature.
pub async fn lookup_owner_by_host(cp_url: &str, admin_token: &[u8; 32], hostname: &str) -> Option<String> {
    let url = format!("{}/internal/edges/lookup", cp_url.trim_end_matches('/'));
    let resp = SHARED_CLIENT
        .get(&url)
        .query(&[("host", hostname)])
        .header("x-ct-admin-token", hex(admin_token))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<OwnerResp>().await.ok().map(|o| o.peer_addr)
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

        let got = rehydrate(&base, &secret, "primary").await.pairs();
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
        assert!(wrong.pairs().is_empty(), "wrong admin token -> empty, not a panic");

        let down = rehydrate("http://127.0.0.1:1", &secret, "primary").await;
        assert!(down.pairs().is_empty(), "unreachable CP -> empty, not a panic");
    }

    #[tokio::test]
    async fn rehydrate_distinguishes_an_empty_registry_from_an_unavailable_one_548() {
        // #548: both used to be an empty Vec, so the boot line read `rehydrated 0` either
        // way. One is a normal fresh deployment; the other means NO Browser-Plane hostname
        // routes at all. An operator watching a deploy could not tell them apart, and the
        // boot-time call is never retried -- so a single hiccup served nothing until the
        // next restart.
        let secret = [0x24u8; 32];
        let hits = Arc::new(Mutex::new(Vec::new()));
        let base = spawn_mock_cp(secret, r#"[]"#, hits).await;

        // A registry that answers with nothing: legitimately empty, not a failure.
        assert!(
            matches!(rehydrate(&base, &secret, "primary").await, Rehydration::Answered(p) if p.is_empty()),
            "an empty registry ANSWERED -- it must not be reported as unavailable"
        );

        // Refused and unreachable are both unavailable, and each says why, because the two
        // need different operator responses (a token/permission problem vs. a down CP).
        let refused = rehydrate(&base, &[0u8; 32], "primary").await;
        let Rehydration::Unavailable(why) = refused else { panic!("wrong token must be Unavailable") };
        assert!(why.contains("answered"), "a refusal names the status: {why}");

        let down = rehydrate("http://127.0.0.1:1", &secret, "primary").await;
        let Rehydration::Unavailable(why) = down else { panic!("unreachable CP must be Unavailable") };
        assert!(why.contains("unreachable"), "an unreachable CP says so: {why}");
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

    async fn spawn_mock_lookup(secret: [u8; 32], known_host: &'static str, peer_addr: &'static str) -> String {
        let app = Router::new().route(
            "/internal/edges/lookup",
            get(move |headers: HeaderMap, axum::extract::Query(q): axum::extract::Query<Value>| async move {
                if !admin_ok(&headers, &secret) {
                    return (StatusCode::UNAUTHORIZED, "").into_response();
                }
                match q.get("host").and_then(Value::as_str) {
                    Some(h) if h == known_host => {
                        (StatusCode::OK, AxJson(serde_json::json!({"edge_id": "edge-2", "peer_addr": peer_addr})))
                            .into_response()
                    }
                    _ => (StatusCode::NOT_FOUND, "no owner recorded").into_response(),
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

    #[tokio::test]
    async fn lookup_owner_by_host_returns_the_peer_addr_on_a_hit() {
        let secret = [0x55u8; 32];
        let base = spawn_mock_lookup(secret, "app.example.com", "10.0.0.9:4433").await;

        let hit = lookup_owner_by_host(&base, &secret, "app.example.com").await;
        assert_eq!(hit.as_deref(), Some("10.0.0.9:4433"));
    }

    #[tokio::test]
    async fn lookup_owner_by_host_fails_soft_on_miss_wrong_token_or_unreachable_cp() {
        let secret = [0x66u8; 32];
        let base = spawn_mock_lookup(secret, "app.example.com", "10.0.0.9:4433").await;

        assert!(lookup_owner_by_host(&base, &secret, "unknown.example.com").await.is_none(), "no owner -> None");
        assert!(lookup_owner_by_host(&base, &[0u8; 32], "app.example.com").await.is_none(), "wrong token -> None");
        assert!(
            lookup_owner_by_host("http://127.0.0.1:1", &secret, "app.example.com").await.is_none(),
            "unreachable CP -> None, not a panic"
        );
    }

    #[test]
    fn is_insecure_cp_url_flags_plain_http_except_loopback_279() {
        assert!(is_insecure_cp_url("http://control-plane:8090"), "internal Docker hostname over HTTP -> insecure");
        assert!(is_insecure_cp_url("http://cp.example.com:8090"), "a real hostname over HTTP -> insecure");
        assert!(!is_insecure_cp_url("https://cp.example.com"), "HTTPS is never flagged");
        assert!(!is_insecure_cp_url("http://127.0.0.1:8090"), "loopback IPv4 is exempt");
        assert!(!is_insecure_cp_url("http://localhost:8090"), "loopback hostname is exempt");
        assert!(!is_insecure_cp_url("http://[::1]:8090"), "loopback IPv6 is exempt");
    }
}
