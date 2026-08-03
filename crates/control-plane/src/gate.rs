//! Browser-Plane login gate (#382-follow): let a tunnel owner protect their
//! public content behind a Keycloak login, restricted to a per-tunnel email
//! allow-list (`crate::storage::SqliteTunnelStore`'s `require_login`/
//! `tunnel_login_allowlist`). The tunnel owner toggles this and manages the
//! allow-list from the portal (see `portal_api.rs`'s tunnel-settings routes);
//! this module is the gate itself, sitting in front of the demo's own origin
//! via Caddy's `forward_auth` directive.
//!
//! Fully additive: a separate router, separate OIDC callback, and separate
//! session cookie from the existing customer portal login (`portal.rs`) --
//! zero changes to that already-tested path. Uses its **own** registered
//! redirect URI (`CT_GATE_REDIRECT_URI`, defaulting to swapping the portal's
//! own `/portal/callback` for `/gate/callback` when unset) -- this must be
//! added to the Keycloak client's `redirectUris` (`ct-demo-realm.json`, and
//! applied to an already-running realm via the Admin REST API, the exact
//! pattern `scripts/apply-realm-theme.sh` already uses for `accountTheme`).
//!
//! Flow: Caddy's `forward_auth` calls `GET /gate/check` for every request to a
//! gated hostname. No/invalid `ct_gate_session` cookie -> `401`, which Caddy's
//! `handle_errors` turns into a redirect to `GET /gate/start`. That mints a
//! CSRF state + a short-lived cookie recording which hostname/path the visitor
//! wanted, then sends them through the SAME Keycloak realm the portal uses.
//! `GET /gate/callback` verifies the CSRF state, exchanges the code, checks the
//! resulting email against that hostname's allow-list, and either mints a
//! `ct_gate_session` cookie (scoped to the parent domain via
//! `CT_GATE_COOKIE_DOMAIN`, so it's shared across every `*.<zone>` subdomain)
//! and redirects back to the original URL, or shows a clear "not on the access
//! list" page.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

use crate::portal::{identity_from_verified_id_token, oidc_http_client, ExchangedIdentity, PortalOidc};
use crate::storage::SqliteTunnelStore;

const GATE_STATE_COOKIE: &str = "ct_gate_state";
const GATE_TARGET_COOKIE: &str = "ct_gate_target";
const GATE_SESSION_COOKIE: &str = "ct_gate_session";
const GATE_SESSION_TTL_SECS: u64 = 8 * 60 * 60;

/// Exchanges an authorization `code` (against the gate's own `redirect_uri`)
/// for the authenticated identity. Injectable so `gate_callback` is
/// hermetically testable without a live IdP -- same pattern as `portal.rs`'s
/// own `Exchanger`.
type GateExchanger =
    Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<ExchangedIdentity, String>> + Send>> + Send + Sync>;

#[derive(Clone)]
struct GateState {
    tunnels: Arc<SqliteTunnelStore>,
    oidc: Option<PortalOidc>,
    exchange: GateExchanger,
    session_key: Arc<[u8]>,
    /// `Domain=` attribute for `ct_gate_session` (e.g. `.bunsenbrenner.org`), so
    /// the cookie set from this host is sent back on requests to any gated
    /// `*.bunsenbrenner.org` subdomain -- without it the cookie would only ever
    /// be readable on whichever exact host happened to mint it. `None` disables
    /// the gate entirely (routes answer 503): a gate cookie scoped to just one
    /// host is not the cross-subdomain primitive this feature needs.
    cookie_domain: Option<Arc<str>>,
}

/// Build the Browser-Plane login-gate router: `GET /gate/check` (Caddy
/// `forward_auth` target), `GET /gate/start` (begins the Keycloak login),
/// `GET /gate/callback` (the OIDC redirect target). Mounted unconditionally;
/// each handler answers `503` until both `oidc` and `CT_GATE_COOKIE_DOMAIN`
/// are configured, matching this project's opt-in-until-configured convention.
pub fn gate_router(tunnels: Arc<SqliteTunnelStore>, oidc: Option<PortalOidc>, session_key: &[u8]) -> Router {
    let cookie_domain = std::env::var("CT_GATE_COOKIE_DOMAIN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(Arc::from);
    let exchange = default_gate_exchanger();
    gate_router_with(tunnels, oidc, session_key, exchange, cookie_domain)
}

fn gate_router_with(
    tunnels: Arc<SqliteTunnelStore>,
    oidc: Option<PortalOidc>,
    session_key: &[u8],
    exchange: GateExchanger,
    cookie_domain: Option<Arc<str>>,
) -> Router {
    let state = GateState {
        tunnels,
        oidc,
        exchange,
        session_key: Arc::from(session_key.to_vec()),
        cookie_domain,
    };
    Router::new()
        .route("/gate/check", get(gate_check))
        .route("/gate/start", get(gate_start))
        .route("/gate/callback", get(gate_callback))
        .with_state(state)
}

/// The production code->identity exchanger: structurally identical to
/// `portal.rs`'s `default_exchanger`, except the token exchange's
/// `redirect_uri` is resolved per-call from the `PortalOidc` handed to the
/// closure at call time (the gate's own, via [`gate_redirect_uri`]) rather
/// than the portal's -- the token endpoint rejects a mismatch against what
/// was sent in the authorize request.
fn default_gate_exchanger() -> GateExchanger {
    Arc::new(move |code: String| {
        Box::pin(async move {
            // The caller (gate_callback) already resolved cfg+redirect_uri once;
            // re-deriving here would need them threaded through the closure's
            // capture, which the injectable-for-tests shape doesn't have. So the
            // production exchanger is invoked with `code` PRE-FORMATTED by
            // gate_callback to carry the resolved redirect_uri alongside it --
            // see the `\u{0}`-joined encoding below and its matching split.
            let Some((code, redirect_uri, token_url, jwks_url, client_id, issuer)) = decode_exchange_args(&code)
            else {
                return Err("malformed internal exchange arguments".to_string());
            };
            let secret =
                std::env::var("CT_OIDC_CLIENT_SECRET").map_err(|_| "missing CT_OIDC_CLIENT_SECRET".to_string())?;
            let form = [
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", redirect_uri.as_str()),
                ("client_id", client_id.as_str()),
                ("client_secret", secret.as_str()),
            ];
            let resp = oidc_http_client()
                .post(&token_url)
                .form(&form)
                .send()
                .await
                .map_err(|e| e.to_string())?;
            if !resp.status().is_success() {
                return Err(format!("token endpoint returned {}", resp.status()));
            }
            let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
            let id_token = body
                .get("id_token")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "token response has no id_token".to_string())?;
            let jwks: serde_json::Value = oidc_http_client()
                .get(&jwks_url)
                .send()
                .await
                .map_err(|e| e.to_string())?
                .json()
                .await
                .map_err(|e| e.to_string())?;
            identity_from_verified_id_token(id_token, &jwks, &issuer, &client_id)
        })
    })
}

/// Packs everything the production exchanger's closure needs (it captures
/// nothing itself, unlike the portal's exchanger, so this is threaded through
/// via the `code` string) -- see [`encode_exchange_args`]/[`decode_exchange_args`].
/// A `\u{0}`-joined encoding is safe here: neither an OAuth authorization code
/// nor any of these URLs/ids can contain a NUL byte.
fn encode_exchange_args(code: &str, redirect_uri: &str, cfg: &PortalOidc) -> String {
    format!("{code}\u{0}{redirect_uri}\u{0}{}\u{0}{}\u{0}{}\u{0}{}", cfg.token_url, cfg.jwks_url(), cfg.client_id, cfg.issuer())
}

fn decode_exchange_args(packed: &str) -> Option<(String, String, String, String, String, String)> {
    let mut parts = packed.splitn(6, '\u{0}');
    Some((
        parts.next()?.to_string(),
        parts.next()?.to_string(),
        parts.next()?.to_string(),
        parts.next()?.to_string(),
        parts.next()?.to_string(),
        parts.next()?.to_string(),
    ))
}

fn gate_unconfigured() -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, "Browser-Plane login gate is not configured on this deployment").into_response()
}

/// The gate's own redirect URI: `CT_GATE_REDIRECT_URI` if set, else the
/// portal's `redirect_uri` with `/portal/callback` swapped for `/gate/callback`
/// -- a sensible zero-extra-config default for the common case where both
/// live on the same host.
fn gate_redirect_uri(portal_redirect_uri: &str) -> Option<String> {
    std::env::var("CT_GATE_REDIRECT_URI")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            portal_redirect_uri
                .ends_with("/portal/callback")
                .then(|| portal_redirect_uri.replace("/portal/callback", "/gate/callback"))
        })
}

#[derive(Deserialize)]
struct CheckQuery {
    host: Option<String>,
}

/// `GET /gate/check`: Caddy's `forward_auth` target. `X-Forwarded-Host` (Caddy
/// sets this automatically) or a `?host=` query param names the hostname being
/// visited. A demo's Caddyfile wires this call UNCONDITIONALLY -- the on/off
/// toggle lives entirely server-side (the tunnel owner's `require_login`
/// setting), not in Caddy's own config -- so: `200` immediately when the host
/// doesn't have the gate enabled at all; `200` when it does AND a valid,
/// unexpired `ct_gate_session` cookie for exactly that host is present;
/// `401` otherwise (Caddy turns a `401` here into the login redirect via its
/// own `handle_errors`).
async fn gate_check(State(st): State<GateState>, headers: HeaderMap, Query(q): Query<CheckQuery>) -> StatusCode {
    let Some(host) = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or(q.host)
    else {
        return StatusCode::BAD_REQUEST;
    };
    match st.tunnels.require_login_for_hostname(&host) {
        Ok(false) => return StatusCode::OK,
        Ok(true) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    }
    let now = now_secs();
    match cookie_value(&headers, GATE_SESSION_COOKIE).and_then(|t| verify_gate_session(&st.session_key, &t, now)) {
        Some(claims) if claims.host == host => StatusCode::OK,
        _ => StatusCode::UNAUTHORIZED,
    }
}

#[derive(Deserialize)]
struct StartQuery {
    host: String,
    #[serde(rename = "return")]
    return_path: Option<String>,
}

/// `GET /gate/start?host=X&return=Y`: begins the Keycloak login for the gate.
/// `404` if `host` doesn't have the login gate enabled at all -- refusing to
/// act as an open redirect for an arbitrary hostname that isn't actually gated.
async fn gate_start(State(st): State<GateState>, Query(q): Query<StartQuery>) -> Response {
    let (Some(cfg), Some(_domain)) = (&st.oidc, &st.cookie_domain) else {
        return gate_unconfigured();
    };
    match st.tunnels.require_login_for_hostname(&q.host) {
        Ok(true) => {}
        Ok(false) => return (StatusCode::NOT_FOUND, "this hostname does not require login").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
    let Some(redirect_uri) = gate_redirect_uri(&cfg.redirect_uri) else {
        return gate_unconfigured();
    };
    let return_path = q.return_path.filter(|p| p.starts_with('/')).unwrap_or_else(|| "/".to_string());
    let state = random_state();
    let target = format!("{}|{}", q.host, return_path);
    let authorize_url = cfg.authorize_redirect_to(&state, &redirect_uri);
    let mut resp = Redirect::to(&authorize_url).into_response();
    set_cookie(&mut resp, &gate_state_cookie(&state));
    set_cookie(&mut resp, &gate_target_cookie(&target));
    resp
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
}

/// `GET /gate/callback`: the gate's own OIDC redirect target -- see the module
/// doc comment for the full flow. Verifies CSRF state, exchanges the code,
/// checks the resulting email against the target hostname's allow-list, and
/// either mints `ct_gate_session` + redirects back, or shows a clear rejection
/// page (no session minted).
async fn gate_callback(State(st): State<GateState>, headers: HeaderMap, Query(q): Query<CallbackQuery>) -> Response {
    let (Some(cfg), Some(domain)) = (&st.oidc, &st.cookie_domain) else {
        return gate_unconfigured();
    };
    let code = q.code.as_deref().unwrap_or("");
    let state = q.state.as_deref().unwrap_or("");
    if code.is_empty() || state.is_empty() {
        return (StatusCode::BAD_REQUEST, "missing code or state").into_response();
    }
    if cookie_value(&headers, GATE_STATE_COOKIE).as_deref() != Some(state) {
        return (StatusCode::FORBIDDEN, "invalid or missing CSRF state").into_response();
    }
    let Some(target) = cookie_value(&headers, GATE_TARGET_COOKIE) else {
        return (StatusCode::BAD_REQUEST, "missing gate target -- please retry from the original link").into_response();
    };
    let Some((host, return_path)) = target.split_once('|') else {
        return (StatusCode::BAD_REQUEST, "malformed gate target").into_response();
    };
    let Some(redirect_uri) = gate_redirect_uri(&cfg.redirect_uri) else {
        return gate_unconfigured();
    };

    let packed = encode_exchange_args(code, &redirect_uri, cfg);
    match (st.exchange)(packed).await {
        Ok(identity) => {
            let email = identity.email.unwrap_or_default();
            let allowed = st.tunnels.email_allowed_for_hostname(host, &email).unwrap_or(false);
            if !allowed {
                let mut resp = (StatusCode::FORBIDDEN, Html(access_denied_html(host))).into_response();
                set_cookie(&mut resp, &cleared_gate_state_cookie());
                set_cookie(&mut resp, &cleared_gate_target_cookie());
                return resp;
            }
            let now = now_secs();
            let token = sign_gate_session(&st.session_key, host, &email, now + GATE_SESSION_TTL_SECS);
            let mut resp = Redirect::to(&format!("https://{host}{return_path}")).into_response();
            set_cookie(&mut resp, &gate_session_cookie(&token, domain));
            set_cookie(&mut resp, &cleared_gate_state_cookie());
            set_cookie(&mut resp, &cleared_gate_target_cookie());
            resp
        }
        Err(e) => {
            eprintln!("ct-cp: gate OIDC code exchange failed: {e}");
            let mut resp = (StatusCode::BAD_GATEWAY, "sign-in failed").into_response();
            set_cookie(&mut resp, &cleared_gate_state_cookie());
            set_cookie(&mut resp, &cleared_gate_target_cookie());
            resp
        }
    }
}

fn access_denied_html(host: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Not on the access list</title>
<style>
 :root{{--bg:#0e1116;--panel:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;
       --accent:#d98a4f;--accent-ink:#20130a;--serif:ui-serif,Georgia,"Iowan Old Style","Palatino Linotype",serif}}
 body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;margin:0;background:var(--bg);color:var(--text);
      display:flex;min-height:100vh;align-items:center;justify-content:center}}
 .card{{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:2.5rem;max-width:480px}}
 h1{{font-family:var(--serif);font-weight:600;font-size:1.4rem;margin:.2rem 0 1rem}}
 p{{color:var(--muted);font-size:.95rem;line-height:1.5}}
 code{{background:#0d1117;border:1px solid var(--border);border-radius:6px;padding:.1rem .35rem}}
</style></head><body>
<div class="card">
 <h1>You're not on the access list</h1>
 <p>Your sign-in succeeded, but your email isn't on the list of people invited to
    <code>{host}</code>. If you think this is a mistake, contact whoever shared
    this link with you.</p>
</div>
</body></html>"#,
        host = crate::portal::escape(host)
    )
}

fn set_cookie(resp: &mut Response, cookie: &str) {
    if let Ok(v) = HeaderValue::from_str(cookie) {
        resp.headers_mut().append(SET_COOKIE, v);
    }
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|part| {
        let part = part.trim();
        part.strip_prefix(name).and_then(|rest| rest.strip_prefix('=')).map(str::to_string)
    })
}

fn random_state() -> String {
    let mut b = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn gate_state_cookie(state: &str) -> String {
    format!("{GATE_STATE_COOKIE}={state}; Path=/gate; Max-Age=600; HttpOnly; Secure; SameSite=Lax")
}

fn cleared_gate_state_cookie() -> String {
    format!("{GATE_STATE_COOKIE}=; Path=/gate; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
}

fn gate_target_cookie(target: &str) -> String {
    format!("{GATE_TARGET_COOKIE}={target}; Path=/gate; Max-Age=600; HttpOnly; Secure; SameSite=Lax")
}

fn cleared_gate_target_cookie() -> String {
    format!("{GATE_TARGET_COOKIE}=; Path=/gate; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
}

/// `Domain=` (not `Path=`) scoped, unlike every other cookie here: this one
/// must be readable by `GET /gate/check` when a visitor hits ANY gated
/// `*.<zone>` subdomain, not just the host that minted it.
fn gate_session_cookie(token: &str, domain: &str) -> String {
    format!(
        "{GATE_SESSION_COOKIE}={token}; Domain={domain}; Path=/; Max-Age={GATE_SESSION_TTL_SECS}; \
         HttpOnly; Secure; SameSite=Lax"
    )
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

type HmacSha256 = Hmac<Sha256>;

/// Domain-separation label, distinct from `portal.rs`'s own `SESSION_CTX` (even
/// though both may share the same signing key bytes) -- a gate-session token
/// must never be reinterpretable as a portal session or vice versa.
const GATE_SESSION_CTX: &[u8] = b"ct-gate-session-v1";

fn gate_session_mac(key: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(GATE_SESSION_CTX);
    m.update(payload);
    m.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn sign_gate_session(key: &[u8], host: &str, email: &str, exp: u64) -> String {
    let payload = format!("{}:{}:{exp}", hex(host.as_bytes()), hex(email.as_bytes()));
    format!("{payload}.{}", hex(&gate_session_mac(key, payload.as_bytes())))
}

struct GateSessionClaims {
    host: String,
}

fn verify_gate_session(key: &[u8], token: &str, now: u64) -> Option<GateSessionClaims> {
    let (payload, tag_hex) = token.rsplit_once('.')?;
    let mut parts = payload.splitn(3, ':');
    let host_hex = parts.next()?;
    let _email_hex = parts.next()?;
    let exp_str = parts.next()?;
    if exp_str.parse::<u64>().ok()? <= now {
        return None;
    }
    if !ct_eq(&gate_session_mac(key, payload.as_bytes()), &unhex(tag_hex)?) {
        return None;
    }
    let host = String::from_utf8(unhex(host_hex)?).ok()?;
    Some(GateSessionClaims { host })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    const TEST_KEY: &[u8] = b"test-session-key";

    fn cfg() -> PortalOidc {
        PortalOidc {
            authorize_url: "https://kc.example/realms/ct/protocol/openid-connect/auth".to_string(),
            token_url: "https://kc.example/realms/ct/protocol/openid-connect/token".to_string(),
            client_id: "ct-portal".to_string(),
            redirect_uri: "https://bunsenbrenner.org/portal/callback".to_string(),
        }
    }

    fn stub_exchanger(email: &str) -> GateExchanger {
        let email = email.to_string();
        Arc::new(move |_code: String| {
            let email = email.clone();
            Box::pin(async move {
                Ok(ExchangedIdentity {
                    subject: "test-subject".to_string(),
                    email: Some(email),
                    email_verified: true,
                })
            })
        })
    }

    fn failing_exchanger() -> GateExchanger {
        Arc::new(|_code: String| Box::pin(async move { Err("boom".to_string()) }))
    }

    #[test]
    fn gate_session_roundtrips_and_rejects_a_wrong_host_or_expired_token() {
        let now = 1_000_000u64;
        let token = sign_gate_session(TEST_KEY, "demo.example", "alice@example.com", now + 3600);
        let claims = verify_gate_session(TEST_KEY, &token, now).unwrap();
        assert_eq!(claims.host, "demo.example");

        assert!(verify_gate_session(TEST_KEY, &token, now + 3601).is_none(), "expired token rejected");
        assert!(verify_gate_session(b"wrong-key", &token, now).is_none(), "wrong key rejected");
        assert!(verify_gate_session(TEST_KEY, "garbage", now).is_none(), "malformed token rejected");
    }

    #[test]
    fn gate_redirect_uri_defaults_by_swapping_the_portal_callback_path() {
        assert_eq!(
            gate_redirect_uri("https://bunsenbrenner.org/portal/callback"),
            Some("https://bunsenbrenner.org/gate/callback".to_string())
        );
        assert_eq!(gate_redirect_uri("https://bunsenbrenner.org/something-else"), None);
    }

    #[tokio::test]
    async fn gate_check_is_always_200_for_a_hostname_that_doesnt_require_login() {
        // The on/off toggle lives entirely server-side -- a demo's Caddyfile calls
        // /gate/check unconditionally, so an ungated hostname must never 401 just
        // because no session cookie is present.
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        tunnels.create("alice", "demo", Some("not-gated.bunsenbrenner.org")).unwrap();
        // Deliberately never call set_require_login.
        let app =
            gate_router_with(tunnels, Some(cfg()), TEST_KEY, stub_exchanger("alice@example.com"), Some(Arc::from(".bunsenbrenner.org")));
        let resp = app
            .oneshot(
                Request::get("/gate/check")
                    .header("x-forwarded-host", "not-gated.bunsenbrenner.org")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn gate_check_requires_a_session_cookie_matching_the_requested_host() {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "demo", Some("demo.bunsenbrenner.org")).unwrap();
        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());
        let app =
            gate_router_with(tunnels, Some(cfg()), TEST_KEY, stub_exchanger("alice@example.com"), Some(Arc::from(".bunsenbrenner.org")));

        // No cookie at all -> 401.
        let bare = app
            .clone()
            .oneshot(
                Request::get("/gate/check")
                    .header("x-forwarded-host", "demo.bunsenbrenner.org")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bare.status(), StatusCode::UNAUTHORIZED);

        // A valid session for a DIFFERENT host -> still 401 (no cross-tunnel replay).
        let now = now_secs();
        let wrong_host_token = sign_gate_session(TEST_KEY, "other.bunsenbrenner.org", "alice@example.com", now + 3600);
        let wrong = app
            .clone()
            .oneshot(
                Request::get("/gate/check")
                    .header("x-forwarded-host", "demo.bunsenbrenner.org")
                    .header("cookie", format!("{GATE_SESSION_COOKIE}={wrong_host_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED, "a session minted for a different host is refused");

        // A valid session for the RIGHT host -> 200.
        let right_token = sign_gate_session(TEST_KEY, "demo.bunsenbrenner.org", "alice@example.com", now + 3600);
        let ok = app
            .oneshot(
                Request::get("/gate/check")
                    .header("x-forwarded-host", "demo.bunsenbrenner.org")
                    .header("cookie", format!("{GATE_SESSION_COOKIE}={right_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn gate_start_refuses_to_act_as_an_open_redirect_for_a_hostname_that_isnt_gated() {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let app =
            gate_router_with(tunnels, Some(cfg()), TEST_KEY, stub_exchanger("alice@example.com"), Some(Arc::from(".bunsenbrenner.org")));
        let resp = app
            .oneshot(Request::get("/gate/start?host=not-gated.bunsenbrenner.org&return=/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn gate_start_mints_csrf_and_target_cookies_and_redirects_to_keycloak_for_a_gated_hostname() {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "demo", Some("demo.bunsenbrenner.org")).unwrap();
        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());

        let app =
            gate_router_with(tunnels, Some(cfg()), TEST_KEY, stub_exchanger("alice@example.com"), Some(Arc::from(".bunsenbrenner.org")));
        let resp = app
            .oneshot(
                Request::get("/gate/start?host=demo.bunsenbrenner.org&return=/room/1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with("https://kc.example/realms/ct/protocol/openid-connect/auth?"));
        assert!(location.contains("redirect_uri=https%3A%2F%2Fbunsenbrenner.org%2Fgate%2Fcallback"));

        let cookies: Vec<_> = resp.headers().get_all("set-cookie").iter().map(|v| v.to_str().unwrap().to_string()).collect();
        assert!(cookies.iter().any(|c| c.starts_with(&format!("{GATE_STATE_COOKIE}="))));
        assert!(cookies
            .iter()
            .any(|c| c.starts_with(&format!("{GATE_TARGET_COOKIE}=demo.bunsenbrenner.org"))));
    }

    #[tokio::test]
    async fn gate_callback_rejects_a_mismatched_or_missing_csrf_state() {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let app =
            gate_router_with(tunnels, Some(cfg()), TEST_KEY, stub_exchanger("alice@example.com"), Some(Arc::from(".bunsenbrenner.org")));

        let no_state = app
            .clone()
            .oneshot(Request::get("/gate/callback?code=abc&state=xyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(no_state.status(), StatusCode::FORBIDDEN, "no state cookie at all -> refused");

        let mismatched = app
            .oneshot(
                Request::get("/gate/callback?code=abc&state=xyz")
                    .header("cookie", format!("{GATE_STATE_COOKIE}=different"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mismatched.status(), StatusCode::FORBIDDEN, "mismatched state -> refused");
    }

    #[tokio::test]
    async fn gate_callback_denies_a_successful_login_whose_email_is_not_allow_listed() {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "demo", Some("demo.bunsenbrenner.org")).unwrap();
        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());
        // Deliberately do NOT allow-list bob@example.com.

        let app =
            gate_router_with(tunnels, Some(cfg()), TEST_KEY, stub_exchanger("bob@example.com"), Some(Arc::from(".bunsenbrenner.org")));
        let resp = app
            .oneshot(
                Request::get("/gate/callback?code=abc&state=xyz")
                    .header(
                        "cookie",
                        format!("{GATE_STATE_COOKIE}=xyz; {GATE_TARGET_COOKIE}=demo.bunsenbrenner.org|/room/1"),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(
            !resp
                .headers()
                .get_all("set-cookie")
                .iter()
                .any(|c| c.to_str().unwrap().starts_with(&format!("{GATE_SESSION_COOKIE}="))),
            "no gate session is minted for a successful-but-unlisted login"
        );
    }

    #[tokio::test]
    async fn gate_callback_admits_a_successful_login_whose_email_is_allow_listed() {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "demo", Some("demo.bunsenbrenner.org")).unwrap();
        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());
        assert!(tunnels.login_allowlist_add("alice", &t.id, "bob@example.com", now_secs()).unwrap());

        let app =
            gate_router_with(tunnels, Some(cfg()), TEST_KEY, stub_exchanger("bob@example.com"), Some(Arc::from(".bunsenbrenner.org")));
        let resp = app
            .clone()
            .oneshot(
                Request::get("/gate/callback?code=abc&state=xyz")
                    .header(
                        "cookie",
                        format!("{GATE_STATE_COOKIE}=xyz; {GATE_TARGET_COOKIE}=demo.bunsenbrenner.org|/room/1"),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "https://demo.bunsenbrenner.org/room/1");
        let session_cookie = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .find(|c| c.starts_with(&format!("{GATE_SESSION_COOKIE}=")))
            .expect("gate session cookie minted for an allow-listed, successful login");
        assert!(session_cookie.contains("Domain=.bunsenbrenner.org"), "scoped to the parent domain");

        // GET /gate/check with that minted cookie now succeeds for the gated host.
        let token = session_cookie.split(';').next().unwrap().strip_prefix(&format!("{GATE_SESSION_COOKIE}=")).unwrap();
        let check = app
            .oneshot(
                Request::get("/gate/check")
                    .header("x-forwarded-host", "demo.bunsenbrenner.org")
                    .header("cookie", format!("{GATE_SESSION_COOKIE}={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(check.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn gate_callback_shows_bad_gateway_on_a_failed_exchange_and_mints_no_session() {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "demo", Some("demo.bunsenbrenner.org")).unwrap();
        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());

        let app = gate_router_with(tunnels, Some(cfg()), TEST_KEY, failing_exchanger(), Some(Arc::from(".bunsenbrenner.org")));
        let resp = app
            .oneshot(
                Request::get("/gate/callback?code=abc&state=xyz")
                    .header(
                        "cookie",
                        format!("{GATE_STATE_COOKIE}=xyz; {GATE_TARGET_COOKIE}=demo.bunsenbrenner.org|/room/1"),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        assert!(!resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .any(|c| c.to_str().unwrap().starts_with(&format!("{GATE_SESSION_COOKIE}="))));
    }
}
