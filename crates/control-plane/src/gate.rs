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

use axum::extract::{Form, Query, State};
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

use crate::oidc::OidcVerifierHandle;
use crate::portal::{identity_from_verified_id_token, oidc_http_client, urlencode, ExchangedIdentity, PortalOidc};
use crate::storage::SqliteTunnelStore;

/// #429: `__Host-`-prefixed, same reasoning as `portal.rs`'s `STATE_COOKIE` --
/// every gated hostname lives on this same shared zone, so without the
/// prefix any OTHER customer subdomain could inject a same-named,
/// `Domain=`-scoped cookie that collides with this one on a victim's gate
/// callback (a login-CSRF against a *different* tenant's gate this time,
/// same mechanism). `__Host-` forces `Secure` + no `Domain=` + `Path=/`,
/// which browsers enforce can only ever be set by the exact host being
/// navigated to -- no subdomain can inject a collision anymore.
const GATE_STATE_COOKIE: &str = "__Host-ct_gate_state";
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
    /// M2M bearer-token path for `/gate/check` (#382-follow): a *different*
    /// verifier than `oidc` above -- `oidc` is authorization-code-flow config
    /// for the interactive browser login this gate already does; `verifier`
    /// validates an already-issued token (real service-account JWTs from
    /// #42's `client_credentials` flow) presented directly in the request,
    /// the same `OidcVerifierHandle` every other bearer-token-accepting route
    /// in this crate already shares (`service.rs::subject_of`). See
    /// `gate_check`'s own doc comment for why this doesn't widen the gate's
    /// actual security property.
    verifier: OidcVerifierHandle,
    /// Whether an email-**allow-list** match must additionally carry the IdP's
    /// `email_verified: true` claim (`CT_GATE_REQUIRE_VERIFIED_EMAIL`). The
    /// allow-list keys on email, but with an open-self-registration realm and no
    /// `verifyEmail`, a self-asserted email is not proof of ownership — so an
    /// unverified account registering an allow-listed address would pass the gate.
    ///
    /// The code default stays `false` (an operator whose realm has no confirmation
    /// flow must not be locked out by upgrading), but **the shipped deployment sets
    /// it to `1`** in `docker/deploy/compose.sso.yml`: since 2026-08-16 ct-demo runs
    /// `verifyEmail=true` over a working SMTP sender, which is exactly the
    /// precondition this doc used to name as missing. Requiring it before that would
    /// have locked out every self-registered user. The
    /// `allow_any_login` path is deliberately unaffected — it never consults the
    /// email at all, so it carries no ownership claim to weaken.
    require_verified_email: bool,
}

/// Build the Browser-Plane login-gate router: `GET /gate/check` (Caddy
/// `forward_auth` target), `GET /gate/start` (begins the Keycloak login),
/// `GET /gate/callback` (the OIDC redirect target). Mounted unconditionally;
/// each handler answers `503` until both `oidc` and `CT_GATE_COOKIE_DOMAIN`
/// are configured, matching this project's opt-in-until-configured convention.
pub fn gate_router(
    tunnels: Arc<SqliteTunnelStore>,
    oidc: Option<PortalOidc>,
    session_key: &[u8],
    verifier: OidcVerifierHandle,
) -> Router {
    let cookie_domain = std::env::var("CT_GATE_COOKIE_DOMAIN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(Arc::from);
    let exchange = default_gate_exchanger();
    let require_verified_email = crate::portal::is_truthy_env("CT_GATE_REQUIRE_VERIFIED_EMAIL");
    gate_router_full(tunnels, oidc, session_key, exchange, cookie_domain, verifier, require_verified_email)
}

/// Test-only 6-arg builder: keeps the pre-`CT_GATE_REQUIRE_VERIFIED_EMAIL` behavior
/// (email-allow-list match does NOT additionally require a verified email). Production
/// goes through [`gate_router`] → [`gate_router_full`]; only the tests below still use
/// this thin `require_verified_email = false` shim, so it is `#[cfg(test)]`.
#[cfg(test)]
fn gate_router_with(
    tunnels: Arc<SqliteTunnelStore>,
    oidc: Option<PortalOidc>,
    session_key: &[u8],
    exchange: GateExchanger,
    cookie_domain: Option<Arc<str>>,
    verifier: OidcVerifierHandle,
) -> Router {
    gate_router_full(tunnels, oidc, session_key, exchange, cookie_domain, verifier, false)
}

#[allow(clippy::too_many_arguments)]
fn gate_router_full(
    tunnels: Arc<SqliteTunnelStore>,
    oidc: Option<PortalOidc>,
    session_key: &[u8],
    exchange: GateExchanger,
    cookie_domain: Option<Arc<str>>,
    verifier: OidcVerifierHandle,
    require_verified_email: bool,
) -> Router {
    let state = GateState {
        tunnels,
        oidc,
        exchange,
        session_key: Arc::from(session_key.to_vec()),
        cookie_domain,
        verifier,
        require_verified_email,
    };
    Router::new()
        .route("/gate/check", get(gate_check))
        .route("/gate/start", get(gate_start))
        .route("/gate/callback", get(gate_callback))
        .route("/gate/logout", get(gate_logout))
        .route("/gate/request-access", get(gate_request_access_form).post(gate_request_access_submit))
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

/// The verified-email response header `GET /gate/check` sets on a `200` when a
/// real gate session backs it (never on the "not gated at all" `200` -- there's
/// no identity to report there). A demo's Caddyfile forwards this into the
/// actual request via `forward_auth`'s `copy_headers`, so the origin/bridge can
/// read who's really signed in instead of trusting anything client-supplied.
const GATE_EMAIL_HEADER: &str = "x-gate-email";

/// `GET /gate/check`: Caddy's `forward_auth` target. `X-Forwarded-Host` (Caddy
/// sets this automatically) or a `?host=` query param names the hostname being
/// visited. A demo's Caddyfile wires this call UNCONDITIONALLY -- the on/off
/// toggle lives entirely server-side (the tunnel owner's `require_login`
/// setting), not in Caddy's own config -- so: `200` immediately when the host
/// doesn't have the gate enabled at all; `200` (with the verified email in
/// `X-Gate-Email`) when it does AND a valid, unexpired `ct_gate_session` cookie
/// for exactly that host is present.
///
/// Otherwise a `302` straight to `/gate/start` -- **not** a bare `401` for
/// Caddy's `handle_errors` to convert. Confirmed against Caddy's own docs:
/// `forward_auth` copies a non-2xx auth-backend response straight to the
/// client verbatim, it never reaches `handle_errors` at all ("this response
/// should typically involve a redirect to the login page... of the
/// authentication gateway" -- i.e. issuing the redirect is *this handler's*
/// job, not Caddy's). An earlier version of this handler returned a bare
/// `401` and relied on `handle_errors`, which never actually fired -- caught
/// live testing the first real gated demo (devsystem-demo.bunsenbrenner.org,
/// #382), not from re-reading the docs first.
async fn gate_check(State(st): State<GateState>, headers: HeaderMap, Query(q): Query<CheckQuery>) -> Response {
    // #393: normalize at the boundary -- DNS hostnames are case-insensitive
    // (RFC 4343), and everything downstream of this point (the target cookie
    // this handler's own redirect below encodes, the session claims minted
    // at /gate/callback, `claims.host == host` a few lines down) compares
    // this value verbatim. storage.rs's own lookups are additionally
    // COLLATE NOCASE as defense-in-depth against already-stored mixed-case
    // data, but the request/session/target flow itself needs ONE canonical
    // casing to stay internally consistent across the whole login round trip.
    let Some(host) = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or(q.host)
        .map(|h| h.to_ascii_lowercase())
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match st.tunnels.require_login_for_hostname(&host) {
        // #433: this used to be a bare `200` with NO `X-Gate-Email` header at
        // all -- fine for a well-behaved `forward_auth copy_headers` config
        // (which only forwards headers this response actually sets), but a
        // reverse proxy configured to copy the auth response's headers onto
        // the ALREADY-INCOMING client request (rather than starting from a
        // clean slate) would leave whatever `X-Gate-Email` value the CLIENT
        // itself supplied completely untouched on the "not gated at all"
        // path -- there being nothing here to overwrite it with. The origin
        // is meant to trust this header as verified identity; a client that
        // can set it directly defeats that. Setting it explicitly to EMPTY
        // here means any client-supplied value is always overwritten with a
        // definite "no identity", never silently left as whatever the client
        // sent, regardless of how the reverse proxy's copy semantics work.
        Ok(false) => return (StatusCode::OK, [(GATE_EMAIL_HEADER, HeaderValue::from_static(""))]).into_response(),
        Ok(true) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    let now = now_secs();
    if let Some(claims) =
        cookie_value(&headers, GATE_SESSION_COOKIE).and_then(|t| verify_gate_session(&st.session_key, &t, now))
    {
        if claims.host == host {
            if let Ok(v) = HeaderValue::from_str(&claims.email) {
                return (StatusCode::OK, [(GATE_EMAIL_HEADER, v)]).into_response();
            }
            // A malformed/non-ASCII email can't ride in a header value -- fall
            // through to the redirect below (no identity to report is worse
            // than none at all here).
        }
    }
    // M2M path (#382-follow): a headless caller (e.g. devsystem_iterate --remote)
    // has no browser session to hold `ct_gate_session` and never will -- it can
    // only ever authenticate via a real, already-verified `Authorization: Bearer`
    // token (a #42 service-account `client_credentials` JWT). Accepting it here
    // is NOT a scope-widening of the gate's own security property, for the same
    // reason `service.rs::subject_of_topology`'s doc comment gives for its
    // identical dual-auth precedent: both paths must resolve to a subject this
    // host's OWNER explicitly allow-listed -- reusing `tunnel_login_allowlist`
    // (the exact table/check `email_allowed_for_hostname` already enforces for
    // the cookie path, not a new parallel authorization surface) rather than
    // trusting any valid token from any service account anywhere. The column is
    // untyped TEXT; a service-account token's `sub` (its real Keycloak client id)
    // is stored/checked the same way an email is -- the owner adds it to the
    // allow-list the same way, from the same UI, once #42-follow exposes that.
    if let Ok(subject) = crate::service::subject_of(&st.verifier, &headers) {
        // #501: same order as the browser callback -- allow-any first, then the strict
        // list. The bearer token was already cryptographically verified by subject_of.
        if matches!(st.tunnels.allow_any_login_for_hostname(&host), Ok(true))
            || matches!(st.tunnels.email_allowed_for_hostname(&host, &subject), Ok(true))
        {
            if let Ok(v) = HeaderValue::from_str(&subject) {
                return (StatusCode::OK, [(GATE_EMAIL_HEADER, v)]).into_response();
            }
        }
    }
    let Some(cfg) = &st.oidc else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(gate_host) = gate_public_host(&cfg.redirect_uri) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // Caddy's forward_auth sets X-Forwarded-Uri to the ORIGINAL request path
    // the visitor wanted -- so the round trip through Keycloak lands them back
    // where they meant to go, not always the site root.
    let return_path = headers
        .get("x-forwarded-uri")
        .and_then(|v| v.to_str().ok())
        .filter(|p| p.starts_with('/'))
        .unwrap_or("/");
    let location = format!(
        "https://{gate_host}/gate/start?host={}&return={}",
        urlencode(&host),
        urlencode(return_path)
    );
    (StatusCode::FOUND, [(axum::http::header::LOCATION, location)]).into_response()
}

/// The control plane's own public host, e.g. `bunsenbrenner.org` from
/// `https://bunsenbrenner.org/portal/callback` -- where `/gate/start` (and
/// this whole gate router) actually lives, as opposed to whichever gated
/// hostname `gate_check` was just asked about.
fn gate_public_host(portal_redirect_uri: &str) -> Option<&str> {
    portal_redirect_uri.strip_prefix("https://").or_else(|| portal_redirect_uri.strip_prefix("http://"))?.split('/').next()
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
    // #393: this endpoint is independently public (not just reached via
    // gate_check's own redirect), so it normalizes its own `host` too --
    // this is what actually flows into the target cookie below and becomes
    // /gate/callback's `claims.host`, so it's the canonical point where the
    // whole login round trip's casing gets fixed for good.
    let host = q.host.to_ascii_lowercase();
    let (Some(cfg), Some(_domain)) = (&st.oidc, &st.cookie_domain) else {
        return gate_unconfigured();
    };
    match st.tunnels.require_login_for_hostname(&host) {
        Ok(true) => {}
        Ok(false) => return (StatusCode::NOT_FOUND, "this hostname does not require login").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
    let Some(redirect_uri) = gate_redirect_uri(&cfg.redirect_uri) else {
        return gate_unconfigured();
    };
    let return_path = q.return_path.filter(|p| p.starts_with('/')).unwrap_or_else(|| "/".to_string());
    let state = random_state();
    let target = format!("{host}|{return_path}");
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
        return gate_csrf_mismatch_response(&headers);
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
            // #501: "any authenticated account" mode short-circuits the allow-list -- the
            // successful OIDC exchange above IS the legitimation then. Checked first so an
            // empty allow-list no longer means "nobody" for self-service tunnels; with the
            // flag off (the default), behavior is byte-for-byte the strict membership check.
            //
            // CT_GATE_REQUIRE_VERIFIED_EMAIL: the allow-list keys on email, but in an
            // open-self-registration realm with no verifyEmail a self-asserted email is not
            // proof of ownership -- so under the flag an allow-list match ALSO requires the
            // IdP's `email_verified`. `allow_any_login` is untouched: it never reads the
            // email, so there is no ownership claim to protect there.
            let email_allowlisted = st.tunnels.email_allowed_for_hostname(host, &email).unwrap_or(false)
                && (!st.require_verified_email || identity.email_verified);
            let allowed =
                st.tunnels.allow_any_login_for_hostname(host).unwrap_or(false) || email_allowlisted;
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

/// The CSRF-state cookie is a single slot per browser/host: a second
/// `/gate/start` in flight at the same time (a second tab, a reload of the
/// Keycloak redirect, going back and retrying) silently overwrites it, so
/// completing an earlier attempt lands here with a state that no longer
/// matches. Rather than a dead-end error, `ct_gate_target` is left untouched
/// on this path (only the success/denied/exchange-error branches clear it),
/// so it still names the most recent attempt's host+return -- enough to offer
/// a one-click "try again" straight back into `/gate/start` instead of making
/// the visitor navigate back to wherever they started.
fn gate_csrf_mismatch_response(headers: &HeaderMap) -> Response {
    let retry = cookie_value(headers, GATE_TARGET_COOKIE).and_then(|target| {
        let (host, return_path) = target.split_once('|')?;
        Some(format!("/gate/start?host={}&return={}", urlencode(host), urlencode(return_path)))
    });
    match retry {
        Some(retry_url) => {
            let mut resp = (StatusCode::FORBIDDEN, Html(csrf_expired_html(&retry_url))).into_response();
            set_cookie(&mut resp, &cleared_gate_state_cookie());
            set_cookie(&mut resp, &cleared_gate_target_cookie());
            resp
        }
        // No target cookie either -- nothing to recover to (e.g. a forged
        // callback hit with no prior /gate/start at all); the old plain
        // 403 is the honest response here.
        None => (StatusCode::FORBIDDEN, "invalid or missing CSRF state").into_response(),
    }
}

#[derive(Deserialize)]
struct LogoutQuery {
    host: Option<String>,
    #[serde(rename = "return")]
    return_path: Option<String>,
}

/// `GET /gate/logout`: clears the `ct_gate_session` cookie -- the piece that
/// was entirely missing before (#214-follow): `ct_gate_session` is HttpOnly by
/// design (same reasoning as the portal's own session cookie), so no
/// client-side JS on a gated page could ever clear it, and there was no
/// server route to do it either. Logs the visitor out of **every** gated
/// hostname at once (the cookie is shared across the whole `Domain=` zone by
/// design -- see `gate_session_cookie`), matching how a single Keycloak SSO
/// identity backs every gate session. Does **not** end the underlying
/// Keycloak SSO session (unlike `/portal/logout`'s RP-Initiated Logout) --
/// deliberately scoped to just this gate, since the same `ct-portal` Keycloak
/// client also backs the portal login, and ending that SSO session here would
/// silently log the visitor out of the portal too, a much bigger blast radius
/// than "log out of this one gated demo" implies.
async fn gate_logout(State(st): State<GateState>, Query(q): Query<LogoutQuery>) -> Response {
    let Some(domain) = &st.cookie_domain else {
        return gate_unconfigured();
    };
    // #428: `q.host` used to go straight into the redirect target with no
    // check that it's a real, currently-tracked hostname at all -- a bare
    // `?host=evil.example` issued a 302 to an attacker from this trusted
    // origin (a phishing primitive that also launders the domain's
    // reputation). Validated against `routing_token_for_hostname` (the same
    // durable `subject_tunnels` lookup every other real-hostname check in
    // this module uses) before it's ever allowed into the redirect target;
    // an unknown host falls through to the same safe default as "no host
    // given at all". Lowercased first, matching #393's normalize-at-entry
    // convention (the lookup itself isn't `COLLATE NOCASE`).
    let known_host = q
        .host
        .map(|h| h.to_ascii_lowercase())
        .filter(|h| matches!(st.tunnels.routing_token_for_hostname(h), Ok(Some(_))));
    let target = match known_host {
        Some(host) => {
            let return_path = q.return_path.filter(|p| p.starts_with('/')).unwrap_or_else(|| "/".to_string());
            format!("https://{host}{return_path}")
        }
        // No specific (or no *known*) hostname given -- land on the control plane's own
        // public host (the same one /gate/start's redirects resolve to),
        // never a bare, hardcoded domain.
        None => match st.oidc.as_ref().and_then(|cfg| gate_public_host(&cfg.redirect_uri)) {
            Some(h) => format!("https://{h}/"),
            None => return gate_unconfigured(),
        },
    };
    let mut resp = Redirect::to(&target).into_response();
    set_cookie(&mut resp, &cleared_gate_session_cookie(domain));
    resp
}

/// Shown when the CSRF-state cookie no longer matches the callback's `state`
/// -- almost always a second `/gate/start` (another tab, a reload, going back
/// and retrying) clobbering the single state-cookie slot before the first
/// attempt finished, not an actual forged callback. `retry_url` is built by
/// [`gate_csrf_mismatch_response`] entirely from `urlencode`-escaped pieces of
/// our own previously-set `ct_gate_target` cookie, so it's safe to embed as-is.
fn csrf_expired_html(retry_url: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign-in session expired</title>
<style>
 :root{{--bg:#0e1116;--panel:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;
       --accent:#d98a4f;--accent-ink:#20130a;--serif:ui-serif,Georgia,"Iowan Old Style","Palatino Linotype",serif}}
 body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;margin:0;background:var(--bg);color:var(--text);
      display:flex;min-height:100vh;align-items:center;justify-content:center}}
 .card{{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:2.5rem;max-width:480px}}
 h1{{font-family:var(--serif);font-weight:600;font-size:1.4rem;margin:.2rem 0 1rem}}
 p{{color:var(--muted);font-size:.95rem;line-height:1.5}}
 a.retry{{display:inline-block;margin-top:1rem;background:var(--accent);color:var(--accent-ink);
      font-weight:600;text-decoration:none;padding:.6rem 1.1rem;border-radius:8px}}
 a.retry:hover{{filter:brightness(1.05)}}
</style></head><body>
<div class="card">
 <h1>Sign-in session expired</h1>
 <p>This usually happens when sign-in was started twice at once &mdash; a second
    tab, a page reload, or going back and trying again. Just start over below;
    it only takes a moment.</p>
 <a class="retry" href="{retry_url}">Try signing in again</a>
</div>
</body></html>"#
    )
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
 a{{color:var(--accent)}}
 code{{background:#0d1117;border:1px solid var(--border);border-radius:6px;padding:.1rem .35rem}}
</style></head><body>
<div class="card">
 <h1>You're not on the access list</h1>
 <p>Your sign-in succeeded, but your email isn't on the list of people invited to
    <code>{host}</code>. If you think this is a mistake, contact whoever shared
    this link with you.</p>
 <p>New here and don't know who to ask?
    <a href="/gate/request-access?host={host_q}">Request access</a> instead.</p>
</div>
</body></html>"#,
        host = crate::portal::escape(host),
        host_q = urlencode(host),
    )
}

/// `GET /gate/request-access?host=...` (#382-follow, issue #18): the real
/// self-service next step linked from `access_denied_html` above -- a visitor
/// who just failed the allow-list check gets a real form instead of a dead
/// end with no way to reach whoever administers it. Only rendered for a
/// hostname that actually has the gate enabled right now (mirrors
/// `record_access_request`'s own check) -- a stray or typo'd host gets an
/// honest 404 rather than a form that can never actually be recorded.
async fn gate_request_access_form(State(st): State<GateState>, Query(q): Query<RequestAccessQuery>) -> Response {
    // #393: normalized here too -- rendered into the form's own hidden `host`
    // field below, so the POST submit (gate_request_access_submit) inherits
    // the same canonical casing without needing its own separate fix.
    let host = q.host.to_ascii_lowercase();
    match st.tunnels.require_login_for_hostname(&host) {
        Ok(true) => Html(request_access_form_html(&host, None)).into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "unknown or ungated hostname").into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "lookup failed").into_response(),
    }
}

#[derive(Deserialize)]
struct RequestAccessQuery {
    host: String,
}

#[derive(Deserialize)]
struct RequestAccessForm {
    host: String,
    email: String,
    #[serde(default)]
    note: String,
}

async fn gate_request_access_submit(State(st): State<GateState>, Form(form): Form<RequestAccessForm>) -> Response {
    let email = form.email.trim();
    // Real bound, not just cosmetic: the column has no length constraint of its
    // own (SQLite is dynamically typed), so an unbounded note/email would let a
    // single submission bloat this table -- same discipline as every other
    // free-text field this session's own Trojan-Source/injection sweep already
    // applies elsewhere in this codebase's request bodies.
    let note: String = form.note.chars().take(500).collect();
    if email.is_empty() || !email.contains('@') || email.len() > 254 {
        return Html(request_access_form_html(&form.host, Some("Enter a real email address."))).into_response();
    }
    match st.tunnels.record_access_request(&form.host, email, &note, now_secs()) {
        Ok(true) => Html(request_recorded_html(&form.host)).into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "unknown or ungated hostname").into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "could not record the request").into_response(),
    }
}

fn request_access_form_html(host: &str, error: Option<&str>) -> String {
    let host_escaped = crate::portal::escape(host);
    let error_html = error
        .map(|e| format!(r#"<p class="err">{}</p>"#, crate::portal::escape(e)))
        .unwrap_or_default();
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Request access</title>
<style>
 :root{{--bg:#0e1116;--panel:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;
       --accent:#d98a4f;--accent-ink:#20130a;--serif:ui-serif,Georgia,"Iowan Old Style","Palatino Linotype",serif}}
 body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;margin:0;background:var(--bg);color:var(--text);
      display:flex;min-height:100vh;align-items:center;justify-content:center}}
 .card{{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:2.5rem;max-width:480px}}
 h1{{font-family:var(--serif);font-weight:600;font-size:1.4rem;margin:.2rem 0 1rem}}
 p{{color:var(--muted);font-size:.95rem;line-height:1.5}}
 p.err{{color:#f0883e}}
 label{{display:block;margin-top:1rem;font-size:.9rem;color:var(--text)}}
 input,textarea{{width:100%;box-sizing:border-box;margin-top:.3rem;background:#0d1117;border:1px solid var(--border);
       border-radius:6px;color:var(--text);padding:.5rem;font:inherit}}
 button{{margin-top:1.4rem;background:var(--accent);color:var(--accent-ink);border:0;border-radius:8px;
       padding:.55rem 1.1rem;font-weight:600;cursor:pointer}}
 code{{background:#0d1117;border:1px solid var(--border);border-radius:6px;padding:.1rem .35rem}}
</style></head><body>
<div class="card">
 <h1>Request access</h1>
 <p>Ask the owner of <code>{host_escaped}</code> to add you to its access list.</p>
 {error_html}
 <form method="post" action="/gate/request-access">
  <input type="hidden" name="host" value="{host_escaped}">
  <label>Your email
   <input type="email" name="email" required maxlength="254" placeholder="you@example.com">
  </label>
  <label>Note (optional)
   <textarea name="note" maxlength="500" rows="3" placeholder="Who you are / why you're asking"></textarea>
  </label>
  <button type="submit">Send request</button>
 </form>
</div>
</body></html>"#
    )
}

fn request_recorded_html(host: &str) -> String {
    let host_escaped = crate::portal::escape(host);
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Request recorded</title>
<style>
 :root{{--bg:#0e1116;--panel:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;
       --serif:ui-serif,Georgia,"Iowan Old Style","Palatino Linotype",serif}}
 body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;margin:0;background:var(--bg);color:var(--text);
      display:flex;min-height:100vh;align-items:center;justify-content:center}}
 .card{{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:2.5rem;max-width:480px}}
 h1{{font-family:var(--serif);font-weight:600;font-size:1.4rem;margin:.2rem 0 1rem}}
 p{{color:var(--muted);font-size:.95rem;line-height:1.5}}
 code{{background:#0d1117;border:1px solid var(--border);border-radius:6px;padding:.1rem .35rem}}
</style></head><body>
<div class="card">
 <h1>Request recorded</h1>
 <p>The owner of <code>{host_escaped}</code> can see your request and grant access from their
    dashboard. No automatic notification is sent -- if it's urgent, reach them another way too.</p>
</div>
</body></html>"#
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
    format!("{GATE_STATE_COOKIE}={state}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax")
}

fn cleared_gate_state_cookie() -> String {
    format!("{GATE_STATE_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
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

/// The same cookie with an immediate expiry -- `Domain=`/`Path=` MUST match
/// [`gate_session_cookie`] exactly, or the browser treats this as a
/// *different* cookie and the original one survives untouched (#214-follow).
fn cleared_gate_session_cookie(domain: &str) -> String {
    format!("{GATE_SESSION_COOKIE}=; Domain={domain}; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
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
    email: String,
}

fn verify_gate_session(key: &[u8], token: &str, now: u64) -> Option<GateSessionClaims> {
    let (payload, tag_hex) = token.rsplit_once('.')?;
    let mut parts = payload.splitn(3, ':');
    let host_hex = parts.next()?;
    let email_hex = parts.next()?;
    let exp_str = parts.next()?;
    if exp_str.parse::<u64>().ok()? <= now {
        return None;
    }
    if !ct_eq(&gate_session_mac(key, payload.as_bytes()), &unhex(tag_hex)?) {
        return None;
    }
    let host = String::from_utf8(unhex(host_hex)?).ok()?;
    let email = String::from_utf8(unhex(email_hex)?).ok()?;
    Some(GateSessionClaims { host, email })
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

    /// Like [`stub_exchanger`] but the IdP does NOT assert `email_verified` — a
    /// self-registered account in an open-registration, no-verifyEmail realm.
    fn stub_exchanger_unverified(email: &str) -> GateExchanger {
        let email = email.to_string();
        Arc::new(move |_code: String| {
            let email = email.clone();
            Box::pin(async move {
                Ok(ExchangedIdentity {
                    subject: "test-subject".to_string(),
                    email: Some(email),
                    email_verified: false,
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
            gate_router_with(tunnels, Some(cfg()), TEST_KEY, stub_exchanger("alice@example.com"), Some(Arc::from(".bunsenbrenner.org")), OidcVerifierHandle::empty());
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
            gate_router_with(tunnels, Some(cfg()), TEST_KEY, stub_exchanger("alice@example.com"), Some(Arc::from(".bunsenbrenner.org")), OidcVerifierHandle::empty());

        // No cookie at all -> 302 straight to /gate/start (NOT a bare 401 --
        // forward_auth copies our response to the client verbatim, so this
        // handler must issue the redirect itself; Caddy's handle_errors never
        // sees a forward_auth non-2xx at all).
        let bare = app
            .clone()
            .oneshot(
                Request::get("/gate/check")
                    .header("x-forwarded-host", "demo.bunsenbrenner.org")
                    .header("x-forwarded-uri", "/room/1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bare.status(), StatusCode::FOUND);
        let location = bare.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with("https://bunsenbrenner.org/gate/start?"), "got {location}");
        assert!(location.contains("host=demo.bunsenbrenner.org"));
        assert!(location.contains("return=%2Froom%2F1"), "carries the original path so the round trip lands back where the visitor meant to go: {location}");

        // A valid session for a DIFFERENT host -> still redirected (no cross-tunnel replay).
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
        assert_eq!(wrong.status(), StatusCode::FOUND, "a session minted for a different host is refused");

        // A valid session for the RIGHT host -> 200, with the verified email
        // available to Caddy's forward_auth via X-Gate-Email.
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
        assert_eq!(ok.headers().get(GATE_EMAIL_HEADER).unwrap(), "alice@example.com");
    }

    #[tokio::test]
    async fn gate_check_sets_an_explicitly_empty_email_header_when_the_hostname_isnt_gated_at_all_433() {
        // #433: this used to omit the header entirely on the "not gated" path,
        // relying on ABSENCE as the "no verified identity" signal -- fragile
        // under a reverse-proxy config that copies auth-response headers onto
        // an already-incoming client request rather than a clean slate, where
        // an absent header leaves a client-forged `X-Gate-Email` untouched
        // instead of overwriting it. Now the header is always present, and
        // explicitly EMPTY (not absent) is the "no verified identity" signal
        // -- a value a client-supplied header can be overwritten with but
        // never be genuinely mistaken for, regardless of proxy copy semantics.
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        tunnels.create("alice", "demo", Some("not-gated.bunsenbrenner.org")).unwrap();
        let app =
            gate_router_with(tunnels, Some(cfg()), TEST_KEY, stub_exchanger("alice@example.com"), Some(Arc::from(".bunsenbrenner.org")), OidcVerifierHandle::empty());
        let resp = app
            .oneshot(
                Request::get("/gate/check")
                    .header("x-forwarded-host", "not-gated.bunsenbrenner.org")
                    // A client attempting to spoof identity by supplying the
                    // header itself -- this must never survive as a non-empty
                    // value on the response Caddy would copy from.
                    .header(GATE_EMAIL_HEADER, "attacker@evil.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(GATE_EMAIL_HEADER).map(|v| v.to_str().unwrap()),
            Some(""),
            "must be explicitly empty, not absent and not the client-supplied value"
        );
    }

    /// #382-follow (M2M): a headless caller with no browser session (e.g.
    /// `devsystem_iterate --remote`) can never hold `ct_gate_session`, but a
    /// real Keycloak service-account bearer token whose subject the tunnel
    /// owner explicitly allow-listed must clear the gate exactly like a
    /// cookie session does -- same 200 + X-Gate-Email contract.
    #[tokio::test]
    async fn gate_check_accepts_an_allow_listed_bearer_token_as_an_alternative_to_the_cookie() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header as JwtHeader};

        let secret = b"realm-secret";
        let issuer = "https://kc.example/realms/ct";
        let verifier = std::sync::Arc::new(crate::oidc::OidcVerifier::from_hs_secret(secret, issuer));

        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "demo", Some("demo.bunsenbrenner.org")).unwrap();
        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());
        assert!(tunnels
            .login_allowlist_add("alice", &t.id, "svc-android-build@clients", now_secs())
            .unwrap());

        let app = gate_router_with(
            tunnels,
            Some(cfg()),
            TEST_KEY,
            stub_exchanger("alice@example.com"),
            Some(Arc::from(".bunsenbrenner.org")),
            OidcVerifierHandle::new(Some(verifier)),
        );

        let now = now_secs();
        let claims = serde_json::json!({ "sub": "svc-android-build@clients", "iss": issuer, "exp": now + 3600 });
        let jwt = encode(&JwtHeader::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(secret)).unwrap();

        let resp = app
            .oneshot(
                Request::get("/gate/check")
                    .header("x-forwarded-host", "demo.bunsenbrenner.org")
                    .header("authorization", format!("Bearer {jwt}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "an allow-listed service-account token clears the gate");
        assert_eq!(resp.headers().get(GATE_EMAIL_HEADER).unwrap(), "svc-android-build@clients");
    }

    /// A valid, correctly-signed bearer token whose subject the owner never
    /// allow-listed must NOT bypass the gate -- it's a real credential, just
    /// not one this host's owner authorized, so it falls through to the
    /// normal redirect exactly like "no credential at all" would.
    #[tokio::test]
    async fn gate_check_falls_through_to_redirect_for_a_valid_bearer_token_thats_not_allow_listed() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header as JwtHeader};

        let secret = b"realm-secret";
        let issuer = "https://kc.example/realms/ct";
        let verifier = std::sync::Arc::new(crate::oidc::OidcVerifier::from_hs_secret(secret, issuer));

        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "demo", Some("demo.bunsenbrenner.org")).unwrap();
        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());
        // Deliberately never allow-list this subject.

        let app = gate_router_with(
            tunnels,
            Some(cfg()),
            TEST_KEY,
            stub_exchanger("alice@example.com"),
            Some(Arc::from(".bunsenbrenner.org")),
            OidcVerifierHandle::new(Some(verifier)),
        );

        let now = now_secs();
        let claims = serde_json::json!({ "sub": "some-other-service@clients", "iss": issuer, "exp": now + 3600 });
        let jwt = encode(&JwtHeader::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(secret)).unwrap();

        let resp = app
            .oneshot(
                Request::get("/gate/check")
                    .header("x-forwarded-host", "demo.bunsenbrenner.org")
                    .header("authorization", format!("Bearer {jwt}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND, "a valid but non-allow-listed token doesn't bypass the gate");
    }

    /// An invalid/malformed/garbage bearer token must never bypass the gate
    /// either -- `subject_of` returning `Err` is just another reason to fall
    /// through to the normal redirect, not a special case.
    #[tokio::test]
    async fn gate_check_falls_through_to_redirect_for_a_malformed_bearer_token() {
        let secret = b"realm-secret";
        let issuer = "https://kc.example/realms/ct";
        let verifier = std::sync::Arc::new(crate::oidc::OidcVerifier::from_hs_secret(secret, issuer));

        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "demo", Some("demo.bunsenbrenner.org")).unwrap();
        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());

        let app = gate_router_with(
            tunnels,
            Some(cfg()),
            TEST_KEY,
            stub_exchanger("alice@example.com"),
            Some(Arc::from(".bunsenbrenner.org")),
            OidcVerifierHandle::new(Some(verifier)),
        );

        let resp = app
            .oneshot(
                Request::get("/gate/check")
                    .header("x-forwarded-host", "demo.bunsenbrenner.org")
                    .header("authorization", "Bearer not-a-real-jwt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND, "a malformed token doesn't bypass the gate");
    }

    #[tokio::test]
    async fn gate_start_refuses_to_act_as_an_open_redirect_for_a_hostname_that_isnt_gated() {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let app =
            gate_router_with(tunnels, Some(cfg()), TEST_KEY, stub_exchanger("alice@example.com"), Some(Arc::from(".bunsenbrenner.org")), OidcVerifierHandle::empty());
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
            gate_router_with(tunnels, Some(cfg()), TEST_KEY, stub_exchanger("alice@example.com"), Some(Arc::from(".bunsenbrenner.org")), OidcVerifierHandle::empty());
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
        assert!(
            location.contains("&prompt=login&"),
            "devsystem#20: gate_start must force a real re-auth, never silently reuse an existing Keycloak SSO session: {location}"
        );

        let cookies: Vec<_> = resp.headers().get_all("set-cookie").iter().map(|v| v.to_str().unwrap().to_string()).collect();
        let state_cookie = cookies
            .iter()
            .find(|c| c.starts_with(&format!("{GATE_STATE_COOKIE}=")))
            .expect("sets the state cookie");
        // #429: the real guarantees the `__Host-` prefix's name relies on --
        // browsers refuse to honor the prefix at all unless these hold, so
        // this is what actually makes the cookie un-collidable by another
        // subdomain of the shared zone.
        assert!(!state_cookie.contains("Domain="), "__Host- cookies must be host-only, no Domain=: {state_cookie}");
        assert!(
            state_cookie.contains("Path=/;") || state_cookie.ends_with("Path=/"),
            "__Host- requires exact Path=/: {state_cookie}"
        );
        assert!(state_cookie.contains("Secure"), "__Host- requires Secure: {state_cookie}");
        assert!(cookies
            .iter()
            .any(|c| c.starts_with(&format!("{GATE_TARGET_COOKIE}=demo.bunsenbrenner.org"))));
    }

    #[tokio::test]
    // devsystem#20: reported live -- clicking the in-app "logout" link only clears
    // this host's own gate cookie (see `gate_logout`'s doc comment), so the very
    // next "Sign in" click silently re-authenticated as the SAME account via the
    // still-live `auth.bunsenbrenner.org` SSO session, with no prompt at all. This
    // is the one place `gate_start` can still force a real credentials check.
    async fn gate_start_forces_a_real_reauth_instead_of_silently_reusing_an_existing_sso_session_devsystem_20() {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "demo", Some("demo.bunsenbrenner.org")).unwrap();
        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());

        let app =
            gate_router_with(tunnels, Some(cfg()), TEST_KEY, stub_exchanger("alice@example.com"), Some(Arc::from(".bunsenbrenner.org")), OidcVerifierHandle::empty());
        let resp = app
            .oneshot(Request::get("/gate/start?host=demo.bunsenbrenner.org&return=/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(
            location.contains("prompt=login"),
            "must send the standard OIDC prompt=login parameter so Keycloak re-authenticates \
             regardless of any existing SSO session, instead of silently redirecting straight \
             back into the app as whoever was already signed in: {location}"
        );
    }

    #[tokio::test]
    async fn gate_callback_rejects_a_mismatched_or_missing_csrf_state() {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let app =
            gate_router_with(tunnels, Some(cfg()), TEST_KEY, stub_exchanger("alice@example.com"), Some(Arc::from(".bunsenbrenner.org")), OidcVerifierHandle::empty());

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

    /// The realistic case behind #CSRF-state reports: a second `/gate/start`
    /// (another tab, a reload) overwrote `ct_gate_state` before the first
    /// attempt's Keycloak redirect landed back at `/gate/callback`. The
    /// mismatch is still refused, but since `ct_gate_target` still names a
    /// real host+return (untouched on this path), the response should offer a
    /// one-click way back into `/gate/start` instead of a dead end.
    #[tokio::test]
    async fn gate_callback_csrf_mismatch_offers_a_retry_link_when_target_cookie_present() {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let app = gate_router_with(
            tunnels,
            Some(cfg()),
            TEST_KEY,
            stub_exchanger("alice@example.com"),
            Some(Arc::from(".bunsenbrenner.org")),
            OidcVerifierHandle::empty(),
        );

        let resp = app
            .oneshot(
                Request::get("/gate/callback?code=abc&state=stale-state")
                    .header(
                        "cookie",
                        format!("{GATE_STATE_COOKIE}=fresh-state-from-second-tab; {GATE_TARGET_COOKIE}=demo.bunsenbrenner.org|/room/1"),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "still refused -- CSRF protection itself is unaffected");
        // Stale state/target cookies get cleared so the retry starts clean.
        let set_cookies: Vec<_> = resp.headers().get_all(SET_COOKIE).iter().map(|v| v.to_str().unwrap().to_string()).collect();
        assert!(set_cookies.iter().any(|c| c.starts_with(&format!("{GATE_STATE_COOKIE}=;"))), "clears the stale state cookie");
        assert!(set_cookies.iter().any(|c| c.starts_with(&format!("{GATE_TARGET_COOKIE}=;"))), "clears the stale target cookie");

        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            html.contains("/gate/start?host=demo.bunsenbrenner.org&return=%2Froom%2F1"),
            "offers a retry link built from the still-present target cookie, got: {html}"
        );
    }

    #[tokio::test]
    async fn gate_callback_denies_a_successful_login_whose_email_is_not_allow_listed() {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "demo", Some("demo.bunsenbrenner.org")).unwrap();
        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());
        // Deliberately do NOT allow-list bob@example.com.

        let app =
            gate_router_with(tunnels, Some(cfg()), TEST_KEY, stub_exchanger("bob@example.com"), Some(Arc::from(".bunsenbrenner.org")), OidcVerifierHandle::empty());
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
    async fn allowlist_requires_verified_email_under_the_flag_but_allow_any_is_unaffected() {
        // CT_GATE_REQUIRE_VERIFIED_EMAIL: an allow-listed but UNVERIFIED email is rejected
        // when the flag is on (an open-self-registration, no-verifyEmail realm makes a
        // self-asserted email no proof of ownership); a verified one passes; the flag OFF is
        // the existing behavior; and `allow_any_login` never consults the email, so an
        // unverified account still passes there.
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "demo", Some("demo.bunsenbrenner.org")).unwrap();
        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());
        assert!(tunnels.login_allowlist_add("alice", &t.id, "bob@example.com", now_secs()).unwrap());

        async fn status(
            tunnels: Arc<SqliteTunnelStore>,
            exchange: GateExchanger,
            require_verified: bool,
        ) -> StatusCode {
            let app = gate_router_full(
                tunnels,
                Some(cfg()),
                TEST_KEY,
                exchange,
                Some(Arc::from(".bunsenbrenner.org")),
                OidcVerifierHandle::empty(),
                require_verified,
            );
            app.oneshot(
                Request::get("/gate/callback?code=abc&state=xyz")
                    .header(
                        "cookie",
                        format!("{GATE_STATE_COOKIE}=xyz; {GATE_TARGET_COOKIE}=demo.bunsenbrenner.org|/join.html"),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        }

        // Flag ON + allow-listed but UNVERIFIED -> rejected.
        assert_eq!(
            status(tunnels.clone(), stub_exchanger_unverified("bob@example.com"), true).await,
            StatusCode::FORBIDDEN,
            "an unverified allow-listed email must not pass the gate under the flag"
        );
        // Flag ON + allow-listed AND verified -> passes.
        assert_eq!(
            status(tunnels.clone(), stub_exchanger("bob@example.com"), true).await,
            StatusCode::SEE_OTHER,
            "a verified allow-listed email passes"
        );
        // Flag OFF + allow-listed but UNVERIFIED -> passes (pre-flag behavior preserved).
        assert_eq!(
            status(tunnels.clone(), stub_exchanger_unverified("bob@example.com"), false).await,
            StatusCode::SEE_OTHER,
            "flag off keeps the existing byte-for-byte behavior"
        );
        // allow_any_login + UNVERIFIED + flag ON -> passes (email never consulted).
        assert!(tunnels.set_allow_any_login("alice", &t.id, true).unwrap());
        assert_eq!(
            status(tunnels.clone(), stub_exchanger_unverified("nobody@example.com"), true).await,
            StatusCode::SEE_OTHER,
            "allow_any_login carries no email claim, so the verified-email flag never applies to it"
        );
    }

    #[tokio::test]
    async fn allow_any_login_admits_a_fresh_account_and_off_keeps_the_strict_list_501() {
        // #501: with "allow any signed-in account" ON, a successful login whose email is
        // NOT on the allow-list passes the gate (the OIDC exchange IS the legitimation);
        // with the flag OFF the very same account is rejected exactly as before -- the
        // issue's pre-registered falsification criterion, both directions.
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "demo", Some("demo.bunsenbrenner.org")).unwrap();
        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());
        assert!(tunnels.set_allow_any_login("alice", &t.id, true).unwrap());
        assert_eq!(tunnels.allow_any_login("alice", &t.id).unwrap(), Some(true));
        assert!(tunnels.allow_any_login_for_hostname("Demo.Bunsenbrenner.ORG").unwrap(), "NOCASE like #393");
        // Deliberately no allow-list entry for fresh@example.com.

        let app = gate_router_with(
            tunnels.clone(),
            Some(cfg()),
            TEST_KEY,
            stub_exchanger("fresh@example.com"),
            Some(Arc::from(".bunsenbrenner.org")),
            OidcVerifierHandle::empty(),
        );
        let resp = app
            .oneshot(
                Request::get("/gate/callback?code=abc&state=xyz")
                    .header(
                        "cookie",
                        format!("{GATE_STATE_COOKIE}=xyz; {GATE_TARGET_COOKIE}=demo.bunsenbrenner.org|/join.html"),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "any authenticated account passes with the flag on");
        assert_eq!(resp.headers().get("location").unwrap(), "https://demo.bunsenbrenner.org/join.html");
        assert!(
            resp.headers()
                .get_all("set-cookie")
                .iter()
                .any(|c| c.to_str().unwrap().starts_with(&format!("{GATE_SESSION_COOKIE}="))),
            "a real gate session is minted -- X-Gate-Email keeps carrying the verified identity"
        );

        // Flip the flag OFF: the same fresh account must be rejected again (strict list).
        assert!(tunnels.set_allow_any_login("alice", &t.id, false).unwrap());
        let app = gate_router_with(
            tunnels,
            Some(cfg()),
            TEST_KEY,
            stub_exchanger("fresh@example.com"),
            Some(Arc::from(".bunsenbrenner.org")),
            OidcVerifierHandle::empty(),
        );
        let resp = app
            .oneshot(
                Request::get("/gate/callback?code=abc&state=xyz")
                    .header(
                        "cookie",
                        format!("{GATE_STATE_COOKIE}=xyz; {GATE_TARGET_COOKIE}=demo.bunsenbrenner.org|/join.html"),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "flag off = byte-for-byte the strict behavior");
    }

    #[tokio::test]
    async fn gate_callback_admits_a_successful_login_whose_email_is_allow_listed() {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "demo", Some("demo.bunsenbrenner.org")).unwrap();
        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());
        assert!(tunnels.login_allowlist_add("alice", &t.id, "bob@example.com", now_secs()).unwrap());

        let app =
            gate_router_with(tunnels, Some(cfg()), TEST_KEY, stub_exchanger("bob@example.com"), Some(Arc::from(".bunsenbrenner.org")), OidcVerifierHandle::empty());
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

        let app = gate_router_with(tunnels, Some(cfg()), TEST_KEY, failing_exchanger(), Some(Arc::from(".bunsenbrenner.org")), OidcVerifierHandle::empty());
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

    #[tokio::test]
    async fn gate_logout_clears_the_session_cookie_and_redirects_back_to_the_gated_host() {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "demo", Some("demo.bunsenbrenner.org")).unwrap();
        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());
        let app =
            gate_router_with(tunnels, Some(cfg()), TEST_KEY, stub_exchanger("alice@example.com"), Some(Arc::from(".bunsenbrenner.org")), OidcVerifierHandle::empty());

        let resp = app
            .clone()
            .oneshot(
                Request::get("/gate/logout?host=demo.bunsenbrenner.org&return=/room/1")
                    .header("cookie", format!("{GATE_SESSION_COOKIE}=some-token"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "https://demo.bunsenbrenner.org/room/1");
        let cleared = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .find(|c| c.starts_with(&format!("{GATE_SESSION_COOKIE}=")))
            .expect("clears the gate session cookie");
        assert!(cleared.contains("Max-Age=0"), "actually expires it, not just overwrites: {cleared}");
        assert!(cleared.contains("Domain=.bunsenbrenner.org"), "same Domain= as the cookie that was set, or the browser won't clear it: {cleared}");

        // After logout, a fresh /gate/check for the same host is refused again --
        // proves this isn't just a redirect theater, the session is genuinely gone.
        let recheck = app
            .oneshot(
                Request::get("/gate/check")
                    .header("x-forwarded-host", "demo.bunsenbrenner.org")
                    .header("cookie", "ct_gate_session=")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(recheck.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn gate_logout_refuses_to_redirect_to_an_unknown_host_428() {
        // #428: `?host=` used to go straight into the redirect target with no
        // check that it names a real, currently-tracked hostname -- a bare
        // `?host=evil.example` issued a 302 to an attacker from this trusted
        // origin. Only `demo.bunsenbrenner.org` is a real tunnel here;
        // `evil.example` is not, and must fall back to the safe default
        // (the control plane's own public host) instead of redirecting there.
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        tunnels.create("alice", "demo", Some("demo.bunsenbrenner.org")).unwrap();
        let app =
            gate_router_with(tunnels, Some(cfg()), TEST_KEY, stub_exchanger("alice@example.com"), Some(Arc::from(".bunsenbrenner.org")), OidcVerifierHandle::empty());

        let resp = app
            .oneshot(
                Request::get("/gate/logout?host=evil.example&return=/steal-session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(!location.contains("evil.example"), "must never redirect to an unknown host: {location}");
        assert_eq!(location, "https://bunsenbrenner.org/", "falls back to the same safe default as no host at all");
    }

    #[tokio::test]
    async fn gate_logout_without_a_host_falls_back_to_the_control_planes_own_public_host() {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let app =
            gate_router_with(tunnels, Some(cfg()), TEST_KEY, stub_exchanger("alice@example.com"), Some(Arc::from(".bunsenbrenner.org")), OidcVerifierHandle::empty());
        let resp = app
            .oneshot(Request::get("/gate/logout").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "https://bunsenbrenner.org/");
    }

    /// #382-follow, issue #18: the "not on the access list" page must actually
    /// link somewhere real, not just apologize -- a visitor arriving with no
    /// prior contact otherwise has no discoverable next step at all.
    #[tokio::test]
    async fn gate_callback_denial_page_links_to_the_real_request_access_form() {
        use axum::body::to_bytes;

        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "demo", Some("demo.bunsenbrenner.org")).unwrap();
        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());

        let app =
            gate_router_with(tunnels, Some(cfg()), TEST_KEY, stub_exchanger("bob@example.com"), Some(Arc::from(".bunsenbrenner.org")), OidcVerifierHandle::empty());
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
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            html.contains("/gate/request-access?host=demo.bunsenbrenner.org"),
            "the denial page must link a real visitor to a real next step, not just apologize: {html}"
        );
    }

    #[tokio::test]
    async fn gate_request_access_form_404s_for_an_ungated_or_unknown_hostname() {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let app =
            gate_router_with(tunnels, Some(cfg()), TEST_KEY, stub_exchanger("alice@example.com"), Some(Arc::from(".bunsenbrenner.org")), OidcVerifierHandle::empty());
        let resp = app
            .oneshot(Request::get("/gate/request-access?host=not-a-real-host.bunsenbrenner.org").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "a stray/typo'd host must not render a form that can never be recorded");
    }

    #[tokio::test]
    async fn gate_request_access_submit_records_a_real_request_the_owner_can_see_and_rejects_a_bad_email() {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "demo", Some("demo.bunsenbrenner.org")).unwrap();
        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());

        let app =
            gate_router_with(tunnels.clone(), Some(cfg()), TEST_KEY, stub_exchanger("alice@example.com"), Some(Arc::from(".bunsenbrenner.org")), OidcVerifierHandle::empty());

        // A bad email is rejected before ever touching storage.
        let bad = app
            .clone()
            .oneshot(
                Request::post("/gate/request-access")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("host=demo.bunsenbrenner.org&email=not-an-email&note="))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::OK, "re-renders the form (with an error), not a redirect or a 400");
        assert!(tunnels.pending_access_requests("alice", &t.id).unwrap().unwrap().is_empty(), "the bad submission must not have been recorded");

        // A real submission is recorded and visible to the tunnel's real owner.
        let ok = app
            .oneshot(
                Request::post("/gate/request-access")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("host=demo.bunsenbrenner.org&email=carol%40example.com&note=found+via+the+README"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);

        let pending = tunnels.pending_access_requests("alice", &t.id).unwrap().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, "carol@example.com");
        assert_eq!(pending[0].1, "found via the README");
    }

    #[tokio::test]
    async fn record_access_request_is_idempotent_per_hostname_and_email_and_rejects_an_ungated_host() {
        let tunnels = SqliteTunnelStore::open_in_memory().unwrap();
        let t = tunnels.create("alice", "demo", Some("demo.bunsenbrenner.org")).unwrap();

        // Not yet gated -- rejected outright, not silently recorded.
        assert!(!tunnels.record_access_request("demo.bunsenbrenner.org", "carol@example.com", "hi", 100).unwrap());

        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());
        assert!(tunnels.record_access_request("demo.bunsenbrenner.org", "carol@example.com", "first note", 100).unwrap());
        assert!(tunnels.record_access_request("demo.bunsenbrenner.org", "carol@example.com", "updated note", 200).unwrap());

        let pending = tunnels.pending_access_requests("alice", &t.id).unwrap().unwrap();
        assert_eq!(pending.len(), 1, "resubmitting the same email must refresh, not duplicate");
        assert_eq!(pending[0].1, "updated note");
        assert_eq!(pending[0].2, 200);
    }

    #[tokio::test]
    async fn require_login_and_email_allowed_match_hostname_case_insensitively_393() {
        // #393: the real auth-bypass shape -- enroll a hostname with ONE casing,
        // then query with a DIFFERENT casing (exactly what a mixed-case gate
        // input vs. the stored casing would produce). Before this fix,
        // require_login_for_hostname would have returned `false` (gate not
        // required -> the tunnel admitted with NO authentication), and
        // email_allowed_for_hostname would have returned `false` even for a
        // correctly allow-listed email (a real lockout).
        let tunnels = SqliteTunnelStore::open_in_memory().unwrap();
        let t = tunnels.create("alice", "demo", Some("Demo.Bunsenbrenner.Org")).unwrap();
        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());
        assert!(tunnels.login_allowlist_add("alice", &t.id, "bob@example.com", 100).unwrap());

        // Queried with every casing variant a real gate input could produce.
        for variant in ["demo.bunsenbrenner.org", "DEMO.BUNSENBRENNER.ORG", "Demo.Bunsenbrenner.Org"] {
            assert!(
                tunnels.require_login_for_hostname(variant).unwrap(),
                "require_login_for_hostname({variant}) must find the gated tunnel regardless of casing -- \
                 a false negative here means the gate is silently bypassed"
            );
            assert!(
                tunnels.email_allowed_for_hostname(variant, "bob@example.com").unwrap(),
                "email_allowed_for_hostname({variant}) must find the allow-listed email regardless of casing -- \
                 a false negative here locks out a correctly-added user"
            );
        }
        // An email that genuinely isn't allow-listed is still correctly denied --
        // the case-insensitivity fix must not have widened this into "anyone".
        assert!(!tunnels.email_allowed_for_hostname("demo.bunsenbrenner.org", "eve@example.com").unwrap());
    }

    #[tokio::test]
    async fn pending_access_requests_finds_a_request_recorded_under_different_hostname_casing_393() {
        // #393: record_access_request is called with the GATE's own caller-
        // supplied hostname casing, while pending_access_requests looks it up
        // via the tunnel's canonical (owner-facing) hostname -- these two must
        // never be assumed to agree in casing.
        let tunnels = SqliteTunnelStore::open_in_memory().unwrap();
        let t = tunnels.create("alice", "demo", Some("Demo.Bunsenbrenner.Org")).unwrap();
        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());

        assert!(tunnels
            .record_access_request("demo.bunsenbrenner.org", "carol@example.com", "hi", 100)
            .unwrap());

        let pending = tunnels.pending_access_requests("alice", &t.id).unwrap().unwrap();
        assert_eq!(pending.len(), 1, "the request must be visible to the owner despite the casing mismatch");
        assert_eq!(pending[0].0, "carol@example.com");

        assert!(
            tunnels.dismiss_access_request("alice", &t.id, "carol@example.com").unwrap(),
            "dismissal must also find the row despite the same casing mismatch"
        );
        assert!(tunnels.pending_access_requests("alice", &t.id).unwrap().unwrap().is_empty());
    }

    #[tokio::test]
    async fn gate_check_still_requires_login_when_x_forwarded_host_casing_differs_from_enrollment_393() {
        // #393: the actual end-to-end auth-bypass this issue describes --
        // a tunnel enrolled/require_login-enabled under one hostname casing,
        // then a real gate_check request arriving with X-Forwarded-Host in a
        // DIFFERENT casing (exactly what a proxy/CDN/browser could plausibly
        // send). Before this fix this returned 200 with no X-Gate-Email header
        // set -- the exact "admitted with no authentication at all" shape.
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "demo", Some("Demo.Bunsenbrenner.Org")).unwrap();
        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());

        let app = gate_router_with(
            tunnels,
            Some(cfg()),
            TEST_KEY,
            stub_exchanger("alice@example.com"),
            Some(Arc::from(".bunsenbrenner.org")),
            OidcVerifierHandle::empty(),
        );

        let resp = app
            .oneshot(
                Request::get("/gate/check")
                    .header("x-forwarded-host", "demo.bunsenbrenner.org") // enrolled as "Demo.Bunsenbrenner.Org"
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Gate required, no session cookie present -> a 302 redirect to
        // /gate/start, not the 200-no-auth-required bypass response.
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "a casing mismatch between the request and the enrolled hostname must never \
             read as \"this hostname doesn't require login\""
        );
        assert_eq!(resp.status(), StatusCode::FOUND, "must redirect to the real login flow");
    }

    #[tokio::test]
    async fn granting_access_via_the_allowlist_auto_dismisses_the_matching_pending_request() {
        // dismiss_access_request itself, and the auto-dismiss wiring in
        // login_allowlist_add_route (portal_api.rs), are exercised together
        // here at the storage layer -- the route's own auto-dismiss call is a
        // thin, untestable-in-isolation wrapper around exactly this method.
        let tunnels = SqliteTunnelStore::open_in_memory().unwrap();
        let t = tunnels.create("alice", "demo", Some("demo.bunsenbrenner.org")).unwrap();
        assert!(tunnels.set_require_login("alice", &t.id, true).unwrap());
        assert!(tunnels.record_access_request("demo.bunsenbrenner.org", "carol@example.com", "", 100).unwrap());

        assert!(tunnels.dismiss_access_request("alice", &t.id, "carol@example.com").unwrap());
        assert!(tunnels.pending_access_requests("alice", &t.id).unwrap().unwrap().is_empty());
        // Dismissing again (nothing left to dismiss) is an honest no-op, not an error.
        assert!(!tunnels.dismiss_access_request("alice", &t.id, "carol@example.com").unwrap());
    }
}
