//! Localhost-only mutation API for the ACME challenge store (#31 AD3).
//!
//! The ACME client publishes/clears `_acme-challenge` TXT records here (its
//! DNS-01 present/cleanup hooks); the authoritative `:53` responder (AD2) then
//! serves them. Bind this to `127.0.0.1` so it is never reachable from the
//! internet — only `:53` (query answers) is public. An optional shared token
//! (`CT_DNS_API_TOKEN`) adds defence-in-depth on top of the localhost boundary.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::put;
use axum::Router;

use crate::store::AcmeDnsStore;

#[derive(Clone)]
struct ApiState {
    store: Arc<AcmeDnsStore>,
    token: Option<Arc<str>>,
}

/// Build the localhost mutation API router. `token`, if set, is required in the
/// `x-ct-dns-token` header.
pub fn api_router(store: Arc<AcmeDnsStore>, token: Option<String>) -> Router {
    let state = ApiState {
        store,
        token: token.map(Arc::from),
    };
    Router::new()
        .route("/txt/:name", put(put_txt).delete(delete_txt))
        .with_state(state)
}

/// Serve the mutation API on `listen` (must be a loopback address in production).
pub async fn serve_api(
    store: Arc<AcmeDnsStore>,
    token: Option<String>,
    listen: SocketAddr,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, api_router(store, token))
        .await
        .map_err(std::io::Error::other)
}

fn authorized(st: &ApiState, headers: &HeaderMap) -> bool {
    match &st.token {
        None => true,
        Some(t) => {
            headers.get("x-ct-dns-token").and_then(|v| v.to_str().ok()) == Some(t.as_ref())
        }
    }
}

/// #299: a real ACME DNS-01 key authorization digest (base64url SHA-256) is exactly
/// 43 bytes; this is a generous ceiling above any realistic challenge value, chosen
/// so a stored TXT record can never itself be the reason [`crate::message::build_response`]
/// has to truncate an otherwise-small answer set.
const MAX_TXT_VALUE_BYTES: usize = 256;

/// `PUT /txt/:name` — body is the TXT value; replaces any existing value.
async fn put_txt(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    body: String,
) -> StatusCode {
    if !authorized(&st, &headers) {
        return StatusCode::UNAUTHORIZED;
    }
    let value = body.trim();
    if name.is_empty() || value.is_empty() {
        return StatusCode::BAD_REQUEST;
    }
    if value.len() > MAX_TXT_VALUE_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE;
    }
    st.store.set_txt(&name, value);
    StatusCode::OK
}

/// `DELETE /txt/:name` — clears the challenge record (cleanup hook).
async fn delete_txt(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> StatusCode {
    if !authorized(&st, &headers) {
        return StatusCode::UNAUTHORIZED;
    }
    st.store.clear(&name);
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    async fn send(app: &Router, req: Request<Body>) -> StatusCode {
        app.clone().oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn api_publishes_and_clears_a_txt_record() {
        let store = Arc::new(AcmeDnsStore::new());
        let app = api_router(store.clone(), None);
        let name = "_acme-challenge.host.test";

        let put = Request::put(format!("/txt/{name}")).body(Body::from("the-token")).unwrap();
        assert_eq!(send(&app, put).await, StatusCode::OK);
        assert_eq!(store.txt(name), vec!["the-token".to_string()]);

        // Empty value -> 400, record unchanged.
        let bad = Request::put(format!("/txt/{name}")).body(Body::from("  ")).unwrap();
        assert_eq!(send(&app, bad).await, StatusCode::BAD_REQUEST);
        assert_eq!(store.txt(name), vec!["the-token".to_string()]);

        let del = Request::delete(format!("/txt/{name}")).body(Body::empty()).unwrap();
        assert_eq!(send(&app, del).await, StatusCode::OK);
        assert!(store.txt(name).is_empty());
    }

    #[tokio::test]
    async fn api_rejects_a_txt_value_over_the_size_cap_299() {
        // #299: a real ACME key authorization digest is 43 bytes -- a value wildly
        // beyond that (this is deliberately >> a UDP-safe DNS answer) must never reach
        // the store, which is what let a single oversized record force build_response
        // to emit a multi-KiB, un-truncated UDP datagram.
        let store = Arc::new(AcmeDnsStore::new());
        let app = api_router(store.clone(), None);
        let name = "_acme-challenge.host.test";

        let huge = "x".repeat(MAX_TXT_VALUE_BYTES + 1);
        let put = Request::put(format!("/txt/{name}")).body(Body::from(huge)).unwrap();
        assert_eq!(send(&app, put).await, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(store.txt(name).is_empty(), "the oversized value was never stored");

        // Exactly at the cap is still accepted.
        let at_cap = "y".repeat(MAX_TXT_VALUE_BYTES);
        let put = Request::put(format!("/txt/{name}")).body(Body::from(at_cap.clone())).unwrap();
        assert_eq!(send(&app, put).await, StatusCode::OK);
        assert_eq!(store.txt(name), vec![at_cap]);
    }

    #[tokio::test]
    async fn api_enforces_the_token_when_configured() {
        let store = Arc::new(AcmeDnsStore::new());
        let app = api_router(store.clone(), Some("secret".to_string()));
        let path = "/txt/_acme-challenge.host.test";

        // Missing / wrong token -> 401, nothing published.
        assert_eq!(
            send(&app, Request::put(path).body(Body::from("x")).unwrap()).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send(
                &app,
                Request::put(path).header("x-ct-dns-token", "nope").body(Body::from("x")).unwrap()
            )
            .await,
            StatusCode::UNAUTHORIZED
        );
        assert!(store.txt("_acme-challenge.host.test").is_empty());

        // Correct token -> 200.
        assert_eq!(
            send(
                &app,
                Request::put(path).header("x-ct-dns-token", "secret").body(Body::from("x")).unwrap()
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(store.txt("_acme-challenge.host.test"), vec!["x".to_string()]);
    }
}
