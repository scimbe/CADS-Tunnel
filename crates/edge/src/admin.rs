//! Edge admin API (#27 RB4) — an authenticated `POST /admin/revoke/:token` the
//! control plane calls when a customer revokes a tunnel. The edge then tears the
//! tunnel down and blocks its re-registration (see [`EdgeState::revoke_token`]).
//!
//! This is the HTTP counterpart of the QUIC `'R'` op (RB3b); the thin,
//! HTTP-based control plane calls it with `reqwest` rather than opening a QUIC
//! client. It is served on its own listener (`CT_EDGE_ADMIN_LISTEN`) so an
//! operator can bind it to a private interface, and every request must carry the
//! shared admin secret (`x-ct-admin-token`), checked in constant time.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use quinn::Connection;
use serde::Serialize;

use crate::state::EdgeState;
use ct_common::RoutingToken;

/// Build the admin router (#27 revoke, #23 BP4b authorize-host, #153 host-auth dump).
pub fn admin_router(state: Arc<EdgeState<Connection>>) -> Router {
    Router::new()
        .route("/admin/revoke/:token", post(revoke))
        .route("/admin/authorize-host/:token/:host", post(authorize_host))
        .route("/admin/host-auth-dump", get(host_auth_dump))
        .with_state(state)
}

/// Constant-time check of the `x-ct-admin-token` header against the shared secret.
fn admin_authed(state: &EdgeState<Connection>, headers: &HeaderMap) -> bool {
    headers
        .get("x-ct-admin-token")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_token_hex)
        .is_some_and(|a| state.admin_revoke_ok(&a))
}

/// Serve the admin API on `listen` until the process ends.
pub async fn serve_admin(
    state: Arc<EdgeState<Connection>>,
    listen: SocketAddr,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, admin_router(state))
        .await
        .map_err(std::io::Error::other)
}

async fn revoke(
    State(state): State<Arc<EdgeState<Connection>>>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> StatusCode {
    if !admin_authed(&state, &headers) {
        return StatusCode::UNAUTHORIZED;
    }
    match parse_token_hex(&token) {
        Some(t) => {
            state.revoke_token(&RoutingToken(t));
            StatusCode::OK
        }
        None => StatusCode::BAD_REQUEST,
    }
}

/// `POST /admin/authorize-host/:token/:host` (#23 BP4b): the control plane
/// authorizes `host` to be bound by `token` (called when a customer sets a
/// hostname on a tunnel they own). Authenticated by the shared admin secret.
async fn authorize_host(
    State(state): State<Arc<EdgeState<Connection>>>,
    headers: HeaderMap,
    Path((token, host)): Path<(String, String)>,
) -> StatusCode {
    if !admin_authed(&state, &headers) {
        return StatusCode::UNAUTHORIZED;
    }
    let host = host.trim();
    match parse_token_hex(&token) {
        Some(t) if !host.is_empty() => {
            state.authorize_host(host, RoutingToken(t));
            StatusCode::OK
        }
        _ => StatusCode::BAD_REQUEST,
    }
}

#[derive(Serialize, serde::Deserialize)]
struct HostAuthEntry {
    hostname: String,
    token: String,
}

/// `GET /admin/host-auth-dump` (#153): a **read-only** dump of every currently
/// authorized (hostname, token) pair on this edge — this deployment's own
/// live state, the only place it exists (the control plane's host-authorize
/// proxy is a pure pass-through; it never persisted what it forwarded). Exists
/// to safely backfill a durable control-plane-side ownership registry BEFORE
/// this edge is ever restarted (a restart wipes `host_auth`, which is exactly
/// the bug the registry fixes) — read this first, seed the registry, then it's
/// safe to redeploy. Authenticated the same way as every other admin route.
async fn host_auth_dump(
    State(state): State<Arc<EdgeState<Connection>>>,
    headers: HeaderMap,
) -> Result<Json<Vec<HostAuthEntry>>, StatusCode> {
    if !admin_authed(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let entries = state
        .dump_host_auth()
        .unwrap_or_default()
        .into_iter()
        .map(|(hostname, token)| HostAuthEntry {
            hostname,
            token: token.0.iter().map(|b| format!("{b:02x}")).collect(),
        })
        .collect();
    Ok(Json(entries))
}

/// Parse a 64-hex string into 32 bytes.
fn parse_token_hex(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut t = [0u8; 32];
    for (i, b) in t.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn revoke_endpoint_authenticates_then_revokes() {
        let state = Arc::new(EdgeState::<Connection>::new());
        let secret = [0x22u8; 32];
        state.set_admin_token(secret);
        let secret_hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        let target = "aa".repeat(32);
        let target_token = RoutingToken([0xaa; 32]);

        let post = |auth: Option<String>, tok: &str| {
            let app = admin_router(state.clone());
            let mut req = Request::post(format!("/admin/revoke/{tok}"));
            if let Some(a) = auth {
                req = req.header("x-ct-admin-token", a);
            }
            app.oneshot(req.body(Body::empty()).unwrap())
        };

        // No / wrong admin token -> 401, nothing revoked.
        assert_eq!(post(None, &target).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        let wrong: String = [0x00u8; 32].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(post(Some(wrong), &target).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        assert!(!state.is_revoked(&target_token), "not revoked without valid auth");

        // Correct admin token -> 200 and the token is revoked.
        assert_eq!(
            post(Some(secret_hex.clone()), &target).await.unwrap().status(),
            StatusCode::OK
        );
        assert!(state.is_revoked(&target_token), "token revoked");

        // Malformed token with valid auth -> 400.
        assert_eq!(
            post(Some(secret_hex), "not-hex").await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn authorize_host_endpoint_authenticates_then_authorizes() {
        let state = Arc::new(EdgeState::<Connection>::new());
        let secret = [0x33u8; 32];
        state.set_admin_token(secret);
        state.require_host_auth(); // #23 BP4b: nothing binds until authorized
        let secret_hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        let tok = "cc".repeat(32);
        let tok_token = RoutingToken([0xcc; 32]);

        let post = |auth: Option<String>| {
            let app = admin_router(state.clone());
            let mut req = Request::post(format!("/admin/authorize-host/{tok}/help.bunsenbrenner.org"));
            if let Some(a) = auth {
                req = req.header("x-ct-admin-token", a);
            }
            app.oneshot(req.body(Body::empty()).unwrap())
        };

        // Wrong auth -> 401, nothing authorized.
        assert_eq!(post(None).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        assert!(!state.host_bind_allowed("help.bunsenbrenner.org", &tok_token));

        // Correct auth -> 200, the (host, token) pair is now bind-allowed.
        assert_eq!(post(Some(secret_hex)).await.unwrap().status(), StatusCode::OK);
        assert!(state.host_bind_allowed("help.bunsenbrenner.org", &tok_token));
        assert!(!state.host_bind_allowed("evil.example", &tok_token), "only the authorized host");
    }

    #[tokio::test]
    async fn host_auth_dump_is_admin_gated_and_reports_current_authorizations() {
        // #153: the safe-backfill read path -- must require the admin token (it's
        // a live inventory of every hostname this edge currently serves) and must
        // report exactly what's actually authorized, in the hex form the control
        // plane's ownership registry stores.
        let state = Arc::new(EdgeState::<Connection>::new());
        let secret = [0x44u8; 32];
        state.set_admin_token(secret);
        state.require_host_auth();
        state.authorize_host("help.bunsenbrenner.org", RoutingToken([0xaa; 32]));
        state.authorize_host("flappy-demo.bunsenbrenner.org", RoutingToken([0xbb; 32]));
        let secret_hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();

        let get = |auth: Option<String>| {
            let app = admin_router(state.clone());
            let mut req = Request::get("/admin/host-auth-dump");
            if let Some(a) = auth {
                req = req.header("x-ct-admin-token", a);
            }
            app.oneshot(req.body(Body::empty()).unwrap())
        };

        assert_eq!(get(None).await.unwrap().status(), StatusCode::UNAUTHORIZED, "no admin token -> 401");

        let resp = get(Some(secret_hex)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let entries: Vec<HostAuthEntry> = serde_json::from_slice(&body).unwrap();
        let mut pairs: Vec<(String, String)> = entries.into_iter().map(|e| (e.hostname, e.token)).collect();
        pairs.sort();
        assert_eq!(
            pairs,
            vec![
                ("flappy-demo.bunsenbrenner.org".to_string(), "bb".repeat(32)),
                ("help.bunsenbrenner.org".to_string(), "aa".repeat(32)),
            ]
        );
    }
}
