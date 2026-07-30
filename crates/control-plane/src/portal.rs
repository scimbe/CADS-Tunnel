//! Customer self-service portal (#25) — server-rendered, self-contained HTML
//! (CSP-safe, no external assets), distinct from the operator status page at `/`.
//!
//! - PP1: the portal shell (`GET /portal`) + SSO-login entry (`GET /portal/login`)
//!   that starts the OIDC Authorization Code flow.
//! - PP2: `GET /portal/callback` with the CSRF-`state` cookie binding.
//! - PP3 (this addition): the **signed session** primitive — a tamper-proof
//!   session cookie, the logged-in customer home (`GET /portal/home`) gated on it,
//!   and logout (`GET /portal/logout`). The code→token exchange that mints a
//!   session at the callback lands in PP4.

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

/// Name of the single-use CSRF cookie that binds the `state` in the authorize
/// redirect to the browser, so the callback can reject a forged/replayed `state`.
const STATE_COOKIE: &str = "ct_portal_state";

/// Name of the signed session cookie identifying the logged-in customer.
const SESSION_COOKIE: &str = "ct_portal_session";

/// Session lifetime (8 hours).
const SESSION_TTL_SECS: u64 = 8 * 60 * 60;

/// The identity extracted from a verified id_token at the OIDC callback: the
/// durable account key (`sub`) plus the optional `email` claim used only to make
/// the access-list decision (#43) — never stored or logged beyond that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExchangedIdentity {
    pub subject: String,
    pub email: Option<String>,
}

/// Exchanges an authorization `code` for the authenticated identity (OIDC `sub`
/// + `email`). Injectable so the callback flow is hermetically testable without a
/// live IdP; the production default calls the token endpoint over TLS.
type Exchanger =
    Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<ExchangedIdentity, String>> + Send>> + Send + Sync>;

/// Router state: the OIDC login config, the session-cookie signing key, the
/// code→identity exchanger, and the optional email-domain access-list (#43).
#[derive(Clone)]
struct PortalState {
    oidc: Option<PortalOidc>,
    session_key: Arc<[u8]>,
    exchange: Exchanger,
    /// `None` = the acceptance gate is OFF (allow every authenticated subject);
    /// `Some(domains)` = admit only subjects whose id_token email is under one of
    /// these lowercase domains.
    allowed_domains: Option<Arc<[String]>>,
}

/// OIDC login configuration for the Authorization Code flow (#25). Built from
/// env at startup. The client **secret** is deliberately NOT held here — it is
/// only needed at the callback token exchange (PP2) and read from the
/// environment then, never logged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortalOidc {
    /// The IdP authorize endpoint (Keycloak: `<issuer>/protocol/openid-connect/auth`).
    pub authorize_url: String,
    /// The IdP token endpoint (Keycloak: `<issuer>/protocol/openid-connect/token`),
    /// where the callback exchanges the authorization code (PP4).
    pub token_url: String,
    pub client_id: String,
    pub redirect_uri: String,
}

impl PortalOidc {
    /// Read the login config from `CT_OIDC_CLIENT_ID`, `CT_OIDC_REDIRECT_URI`,
    /// and either `CT_OIDC_AUTHORIZE_URL` or (derived) `CT_OIDC_ISSUER`. Returns
    /// `None` if login is not fully configured — the portal then shows the shell
    /// but the login button reports "SSO not configured".
    pub fn from_env() -> Option<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Testable core of [`from_env`]: resolve the config from a variable lookup.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let nonempty = |k: &str| get(k).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let client_id = nonempty("CT_OIDC_CLIENT_ID")?;
        let redirect_uri = nonempty("CT_OIDC_REDIRECT_URI")?;
        let issuer = nonempty("CT_OIDC_ISSUER");
        let authorize_url = nonempty("CT_OIDC_AUTHORIZE_URL").or_else(|| {
            issuer
                .as_deref()
                .map(|iss| format!("{}/protocol/openid-connect/auth", iss.trim_end_matches('/')))
        })?;
        // Token endpoint: explicit, else issuer-derived, else swap the authorize
        // path for the token path (Keycloak's `/auth` -> `/token`).
        let token_url = nonempty("CT_OIDC_TOKEN_URL")
            .or_else(|| {
                issuer
                    .as_deref()
                    .map(|iss| format!("{}/protocol/openid-connect/token", iss.trim_end_matches('/')))
            })
            .unwrap_or_else(|| authorize_url.replace("/auth", "/token"));
        Some(Self {
            authorize_url,
            token_url,
            client_id,
            redirect_uri,
        })
    }

    /// The realm issuer (an id_token's `iss`), derived from the token endpoint by
    /// stripping Keycloak's `/protocol/openid-connect/token` suffix (#82).
    fn issuer(&self) -> &str {
        self.token_url
            .strip_suffix("/protocol/openid-connect/token")
            .unwrap_or(&self.token_url)
    }

    /// The realm JWKS (signing-key) endpoint used to verify the id_token (#82).
    fn jwks_url(&self) -> String {
        crate::oidc::jwks_uri_for(self.issuer())
    }

    /// Keycloak's own Account Console for this realm -- where a customer can
    /// change their password, review active sessions, and (once the realm's
    /// `delete_account` required action is enabled) delete their own account,
    /// without CADS-Tunnel reimplementing any of that itself.
    pub(crate) fn account_console_url(&self) -> String {
        format!("{}/account", self.issuer())
    }

    /// Build the Authorization Code redirect URL, carrying a CSRF `state`. `idp_hint`
    /// (Keycloak's `kc_idp_hint`) sends the browser straight to a specific brokered
    /// identity provider (e.g. `google`, `github`) instead of Keycloak's own
    /// provider-chooser screen -- the "Continue with Google/GitHub" buttons on the
    /// portal shell use this so picking a provider is a single click, not two.
    /// `login_hint` is the standard OIDC param (Keycloak honors it) that pre-fills
    /// the username/email field on Keycloak's own login+register form -- lets the
    /// landing page's email-first entry point hand the typed address straight
    /// through instead of the visitor retyping it a second time.
    /// `start_at_register` swaps the target from Keycloak's login form to its
    /// registration form (`/protocol/openid-connect/registrations`, same params,
    /// Keycloak's own documented deep link) -- the landing page's email-first CTA
    /// is a new-visitor path, so it should land someone with no account yet
    /// straight on "create an account", not on a login screen with the register
    /// link buried. `/portal`'s own "Sign in" links keep going through the
    /// ordinary `/auth` login form via `false`.
    fn authorize_redirect(
        &self,
        state: &str,
        idp_hint: Option<&str>,
        login_hint: Option<&str>,
        start_at_register: bool,
    ) -> String {
        let base = if start_at_register {
            std::borrow::Cow::Owned(self.authorize_url.replace("/protocol/openid-connect/auth", "/protocol/openid-connect/registrations"))
        } else {
            std::borrow::Cow::Borrowed(&self.authorize_url)
        };
        let hint_param = idp_hint
            .map(|h| format!("&kc_idp_hint={}", urlencode(h)))
            .unwrap_or_default();
        let login_hint_param = login_hint
            .filter(|h| !h.is_empty())
            .map(|h| format!("&login_hint={}", urlencode(h)))
            .unwrap_or_default();
        format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope=openid&state={}{}{}",
            base,
            urlencode(&self.client_id),
            urlencode(&self.redirect_uri),
            urlencode(state),
            hint_param,
            login_hint_param,
        )
    }

    /// RP-Initiated Logout (OIDC): end the session at the IdP too, not just
    /// locally. Clearing only our own session cookie leaves Keycloak's own SSO
    /// session alive, so the next "sign in" click (or a silent re-auth) logs
    /// the user straight back in without asking for credentials again --
    /// which looks exactly like logout doing nothing. `post_logout_redirect_uri`
    /// is the portal root (the callback URL with its `/callback` suffix
    /// stripped); the realm's `ct-portal` client already allow-lists exactly
    /// this in `post.logout.redirect.uris` (`docker/deploy/keycloak/ct-demo-realm.json`).
    fn end_session_redirect(&self) -> String {
        let portal_root = self.redirect_uri.trim_end_matches("/callback");
        format!(
            "{}/protocol/openid-connect/logout?client_id={}&post_logout_redirect_uri={}",
            self.issuer(),
            urlencode(&self.client_id),
            urlencode(portal_root),
        )
    }
}

/// Build the customer portal router (#25 PP1): `GET /portal` (shell) and
/// `GET /portal/login` (SSO Authorization Code redirect). The email-domain
/// access-list (#43) is read from `CT_PORTAL_ALLOWED_EMAIL_DOMAINS` here.
pub fn portal_router(oidc: Option<PortalOidc>, session_key: &[u8]) -> Router {
    let exchange = default_exchanger(oidc.clone());
    let allowed_domains = parse_allowed_domains(std::env::var("CT_PORTAL_ALLOWED_EMAIL_DOMAINS").ok());
    portal_router_with(oidc, session_key, exchange, allowed_domains)
}

/// Parse `CT_PORTAL_ALLOWED_EMAIL_DOMAINS` (comma-separated) into a lowercase
/// domain allow-list. `None` = the acceptance gate is OFF (unset/empty → admit
/// every authenticated subject), matching the project's opt-in-restriction
/// pattern (`CT_EDGE_REQUIRE_HOST_AUTH`): the policy stays disabled until an
/// operator names the domains, so zero-config self-host is unaffected. `Some`
/// enables the gate for exactly those domains (a leading `@` is tolerated).
fn parse_allowed_domains(raw: Option<String>) -> Option<Arc<[String]>> {
    let list: Vec<String> = raw?
        .split(',')
        .map(|s| s.trim().trim_start_matches('@').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    (!list.is_empty()).then(|| Arc::from(list))
}

/// Is `email` admitted by the domain allow-list? The domain is the case-insensitive
/// part after the last `@`. A missing/malformed email is rejected — the list is
/// only consulted when the gate is enabled, so "no email" means "not on the list".
fn email_domain_allowed(email: Option<&str>, allowed: &[String]) -> bool {
    match email
        .and_then(|e| e.rsplit_once('@'))
        .map(|(_, d)| d.trim().to_ascii_lowercase())
        .filter(|d| !d.is_empty())
    {
        Some(domain) => allowed.iter().any(|a| a == &domain),
        None => false,
    }
}

/// Router builder with an injectable exchanger + access-list (for tests).
fn portal_router_with(
    oidc: Option<PortalOidc>,
    session_key: &[u8],
    exchange: Exchanger,
    allowed_domains: Option<Arc<[String]>>,
) -> Router {
    let state = PortalState {
        oidc,
        session_key: Arc::from(session_key.to_vec()),
        exchange,
        allowed_domains,
    };
    Router::new()
        .route("/portal", get(portal_home))
        .route("/portal/login", get(portal_login))
        .route("/portal/callback", get(portal_callback))
        .route("/portal/home", get(portal_home_authed))
        .route("/portal/logout", get(portal_logout))
        .with_state(state)
}

/// The production code→subject exchanger: POST the authorization code to the
/// IdP token endpoint (confidential client — secret read from
/// `CT_OIDC_CLIENT_SECRET` at call time, never stored or logged), then read the
/// `sub` from the returned `id_token`. The id_token is obtained directly from
/// the token endpoint over the authenticated TLS back-channel, so its `sub` is
/// taken as-is; full JWKS signature verification is a hardening follow-up.
/// Timeout for the OIDC back-channel calls a portal login makes (#96): each callback
/// fetches the token exchange + the realm JWKS, so a slow/hanging IdP must fail fast
/// rather than pile up blocked login requests and wedge the login path. Kept short —
/// these are single HTTP round-trips to the realm.
const OIDC_HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// A reqwest client for the OIDC back-channel with a bounded total + connect timeout
/// (#96), so a hanging IdP errors instead of blocking forever. `timeout` is
/// parameterised so tests can drive a short window; production uses [`OIDC_HTTP_TIMEOUT`].
fn oidc_http_client_with(timeout: std::time::Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn oidc_http_client() -> reqwest::Client {
    oidc_http_client_with(OIDC_HTTP_TIMEOUT)
}

fn default_exchanger(oidc: Option<PortalOidc>) -> Exchanger {
    Arc::new(move |code: String| {
        let oidc = oidc.clone();
        Box::pin(async move {
            let cfg = oidc.ok_or_else(|| "SSO not configured".to_string())?;
            let secret = std::env::var("CT_OIDC_CLIENT_SECRET")
                .map_err(|_| "missing CT_OIDC_CLIENT_SECRET".to_string())?;
            let form = [
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", cfg.redirect_uri.as_str()),
                ("client_id", cfg.client_id.as_str()),
                ("client_secret", secret.as_str()),
            ];
            let resp = oidc_http_client()
                .post(&cfg.token_url)
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
            // #82: verify the id_token's signature against the realm JWKS (kid-bound),
            // issuer, audience and expiry BEFORE trusting its sub/email. The TLS
            // back-channel is not a substitute for verifying the token itself — a
            // tampered/confused response could otherwise inject an arbitrary subject.
            let jwks: serde_json::Value = oidc_http_client()
                .get(cfg.jwks_url())
                .send()
                .await
                .map_err(|e| e.to_string())?
                .json()
                .await
                .map_err(|e| e.to_string())?;
            identity_from_verified_id_token(id_token, &jwks, cfg.issuer(), &cfg.client_id)
        })
    })
}

/// Verify an id_token against the realm JWKS and extract the `sub` (required) and
/// `email` (optional, #43 access-list gate). #82: replaces the previous insecure
/// decode — the signature (RS256, key selected by the token's `kid`), the issuer,
/// the audience (an id_token's `aud` IS the client that requested it) and expiry
/// are all checked, so a tampered token endpoint response cannot inject a subject.
/// Kept standalone so it is unit-tested directly against a JWKS.
fn identity_from_verified_id_token(
    jwt: &str,
    jwks: &serde_json::Value,
    issuer: &str,
    client_id: &str,
) -> Result<ExchangedIdentity, String> {
    let (n, e) = crate::oidc::token_kid(jwt)
        .as_deref()
        .and_then(|kid| crate::oidc::jwks_signing_key_for_kid(jwks, kid))
        .or_else(|| crate::oidc::jwks_signing_key(jwks))
        .ok_or_else(|| "no usable RS256 signing key in realm JWKS".to_string())?;
    let key = jsonwebtoken::DecodingKey::from_rsa_components(&n, &e).map_err(|e| e.to_string())?;
    let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    v.set_issuer(&[issuer]);
    v.set_audience(&[client_id]);
    v.validate_exp = true;
    let data = jsonwebtoken::decode::<serde_json::Value>(jwt, &key, &v).map_err(|e| e.to_string())?;
    let subject = data
        .claims
        .get("sub")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "id_token has no sub".to_string())?;
    let email = data
        .claims
        .get("email")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string());
    Ok(ExchangedIdentity { subject, email })
}

async fn portal_home() -> Html<&'static str> {
    Html(PORTAL_HTML)
}

/// `kc_idp_hint` from the portal shell's "Continue with Google/GitHub" buttons.
/// Allowlisted against the identity providers actually declared in the `ct-demo`
/// realm (`keycloak/ct-demo-realm.json`) -- anything else is dropped rather than
/// passed through, since this value is embedded verbatim into a redirect URL.
/// `login_hint` comes from the landing page's email-first entry point -- passed
/// through as-is (urlencoded at the call site); it only pre-fills a form field,
/// never authenticates anything, so it needs no allowlisting. `register`, when
/// present at all (any value, including empty), routes to Keycloak's
/// registration form instead of its login form -- also not a security-relevant
/// value, just which of Keycloak's own two forms to land on.
#[derive(Deserialize)]
struct LoginQuery {
    kc_idp_hint: Option<String>,
    login_hint: Option<String>,
    register: Option<String>,
}

fn known_idp_hint(hint: Option<&str>) -> Option<&str> {
    hint.filter(|h| matches!(*h, "google" | "github" | "gitlab"))
}

async fn portal_login(State(st): State<PortalState>, Query(q): Query<LoginQuery>) -> Response {
    match st.oidc {
        Some(cfg) => {
            // Mint the CSRF `state`, carry it BOTH in the authorize redirect and
            // in a single-use HttpOnly cookie so the callback can prove the
            // response came back to the same browser we sent out.
            let state = random_state();
            let hint = known_idp_hint(q.kc_idp_hint.as_deref());
            let mut resp = Redirect::to(&cfg.authorize_redirect(
                &state,
                hint,
                q.login_hint.as_deref(),
                q.register.is_some(),
            ))
            .into_response();
            set_cookie(&mut resp, &state_cookie(&state));
            resp
        }
        None => sso_unconfigured(),
    }
}

/// Query parameters the IdP appends to the `redirect_uri` on success.
#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
}

/// `GET /portal/callback` (#25 PP2): the OIDC Authorization Code redirect target.
///
/// This sub-packet enforces the **CSRF `state` binding**: the `state` echoed by
/// the IdP must equal the one in the single-use cookie set at login, else the
/// request is rejected before anything else happens. On a valid `state` the
/// single-use cookie is cleared. The code→token exchange and the session cookie
/// land in PP3 — `code` is intentionally not consumed yet.
async fn portal_callback(
    State(st): State<PortalState>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    if st.oidc.is_none() {
        return sso_unconfigured();
    }
    let code = q.code.as_deref().unwrap_or("");
    let state = q.state.as_deref().unwrap_or("");
    if code.is_empty() || state.is_empty() {
        return (StatusCode::BAD_REQUEST, "missing code or state").into_response();
    }
    // The `state` must match the single-use cookie from login (CSRF defence).
    if cookie_value(&headers, STATE_COOKIE).as_deref() != Some(state) {
        return (StatusCode::FORBIDDEN, "invalid or missing CSRF state").into_response();
    }
    // Valid state (PP4): exchange the code for the subject, then mint a session
    // cookie and land the customer on their home. The single-use state cookie is
    // retired either way.
    match (st.exchange)(code.to_string()).await {
        Ok(identity) => {
            // #43 acceptance gate: when an email-domain access-list is configured,
            // only subjects whose id_token email is under an allowed domain may
            // mint a session. A clear 403 page (not a generic error) makes an
            // access-policy rejection obviously distinct from a broken login, and
            // no session cookie is set. The gate is skipped entirely when OFF.
            if let Some(allowed) = &st.allowed_domains {
                if !email_domain_allowed(identity.email.as_deref(), allowed) {
                    let mut resp = (StatusCode::FORBIDDEN, Html(ACCESS_DENIED_HTML)).into_response();
                    set_cookie(&mut resp, &cleared_state_cookie());
                    return resp;
                }
            }
            let subject = identity.subject;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let token = sign_session(&st.session_key, &subject, now + SESSION_TTL_SECS);
            let mut resp = Redirect::to("/portal/home").into_response();
            set_cookie(&mut resp, &session_cookie(&token));
            set_cookie(&mut resp, &cleared_state_cookie());
            resp
        }
        Err(e) => {
            // Don't surface IdP/exchange error detail to the browser, but DO log it
            // server-side (#65): a bare 502 with nothing in the logs gave an operator
            // no lead on client-secret drift. The message never reaches the browser.
            eprintln!("ct-cp: OIDC code exchange failed: {e}");
            let mut resp = (StatusCode::BAD_GATEWAY, "sign-in failed").into_response();
            set_cookie(&mut resp, &cleared_state_cookie());
            resp
        }
    }
}

/// `GET /portal/home` (#25 PP3): the logged-in customer home. Gated on a valid
/// signed session cookie; without one the visitor is bounced to the shell.
async fn portal_home_authed(State(st): State<PortalState>, headers: HeaderMap) -> Response {
    match session_subject(&st, &headers) {
        Some(sub) => Html(home_html(&sub)).into_response(),
        None => Redirect::to("/portal").into_response(),
    }
}

/// `GET /portal/logout` (#25 PP3): clear the session cookie AND end the session
/// at the IdP (RP-Initiated Logout, [`PortalOidc::end_session_redirect`]) --
/// clearing only our own cookie leaves Keycloak's SSO session alive, so the
/// next sign-in silently re-authenticates without asking for credentials
/// again, which looks like logout not working. Falls back to a plain local
/// redirect when OIDC isn't configured (dev/test).
async fn portal_logout(State(st): State<PortalState>) -> Response {
    let mut resp = match &st.oidc {
        Some(cfg) => Redirect::to(&cfg.end_session_redirect()).into_response(),
        None => Redirect::to("/portal").into_response(),
    };
    set_cookie(&mut resp, &cleared_session_cookie());
    resp
}

fn sso_unconfigured() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "SSO login is not configured on this deployment",
    )
        .into_response()
}

/// Shown (with `403`) when a successfully-authenticated subject is not on the
/// email-domain access-list (#43): a clear acceptance-policy rejection, distinct
/// from a broken login, with no session minted. Self-contained/CSP-safe.
const ACCESS_DENIED_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CADS-Tunnel — access not permitted</title>
<style>
 body{font-family:system-ui,sans-serif;margin:0;background:#0e1116;color:#e6edf3;
      display:flex;min-height:100vh;align-items:center;justify-content:center}
 .card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:2.5rem;max-width:480px}
 h1{font-size:1.3rem;margin:.2rem 0 1rem} p{color:#8b949e;font-size:.95rem;line-height:1.5}
 a.btn{display:inline-block;margin-top:1.4rem;background:#21262d;color:#e6edf3;text-decoration:none;
       padding:.55rem 1.1rem;border-radius:8px;border:1px solid #30363d} a.btn:hover{background:#30363d}
</style></head><body>
<div class="card">
 <h1>You're not on the access list</h1>
 <p>Your sign-in succeeded, but your email domain isn't permitted on this
    deployment yet. If you think you should have access, contact the operator.</p>
 <a class="btn" href="/portal">Back</a>
</div>
</body></html>"#;

type HmacSha256 = Hmac<Sha256>;

/// Domain-separation label mixed into every session MAC, so the signing key can
/// never be confused with another use of the same secret.
const SESSION_CTX: &[u8] = b"ct-portal-session-v1";

fn session_mac(key: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(SESSION_CTX);
    m.update(payload);
    m.finalize().into_bytes().to_vec()
}

/// Mint a signed session token for `subject`, valid until `exp` (unix seconds).
/// Format: `<hex(subject)>:<exp>.<hex(hmac)>` — opaque, tamper-evident, and the
/// subject carries no secret. Minted at the callback once the code is exchanged.
fn sign_session(key: &[u8], subject: &str, exp: u64) -> String {
    let payload = format!("{}:{exp}", hex(subject.as_bytes()));
    format!("{payload}.{}", hex(&session_mac(key, payload.as_bytes())))
}

/// Verify a session token and return its subject if the MAC checks out and it
/// has not expired (`now` in unix seconds). Constant-time MAC comparison.
fn verify_session(key: &[u8], token: &str, now: u64) -> Option<String> {
    let (payload, tag_hex) = token.rsplit_once('.')?;
    let (sub_hex, exp_str) = payload.split_once(':')?;
    if exp_str.parse::<u64>().ok()? <= now {
        return None;
    }
    if !ct_eq(&session_mac(key, payload.as_bytes()), &unhex(tag_hex)?) {
        return None;
    }
    String::from_utf8(unhex(sub_hex)?).ok()
}

/// Constant-time byte-slice equality, so MAC verification leaks no timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Resolve the subject of the request's session cookie, if valid and unexpired.
fn session_subject(st: &PortalState, headers: &HeaderMap) -> Option<String> {
    session_subject_for(&st.session_key, headers)
}

/// Resolve the logged-in subject from a request's session cookie against `key`.
/// Shared with the authed portal API (`portal_api`) so every portal endpoint
/// gates on the same signed session.
pub(crate) fn session_subject_for(key: &[u8], headers: &HeaderMap) -> Option<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    verify_session(key, &cookie_value(headers, SESSION_COOKIE)?, now)
}

/// Mint a valid session token for `subject` (test helper for sibling modules).
#[cfg(test)]
pub(crate) fn sign_session_for_test(key: &[u8], subject: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    sign_session(key, subject, now + SESSION_TTL_SECS)
}

/// The session cookie: HttpOnly, Secure, SameSite=Lax, scoped to `/portal`.
/// Set by the callback once a session is minted.
fn session_cookie(token: &str) -> String {
    format!("{SESSION_COOKIE}={token}; Path=/portal; Max-Age={SESSION_TTL_SECS}; HttpOnly; Secure; SameSite=Lax")
}

fn cleared_session_cookie() -> String {
    format!("{SESSION_COOKIE}=; Path=/portal; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// HTML-escape untrusted text before embedding it in the page.
pub(crate) fn escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '&' => "&amp;".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect(),
            '>' => "&gt;".chars().collect(),
            '"' => "&quot;".chars().collect(),
            '\'' => "&#39;".chars().collect(),
            other => vec![other],
        })
        .collect()
}

/// The logged-in customer home page (self-contained, CSP-safe).
fn home_html(subject: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CADS-Tunnel — your account</title>
<style>
 body{{font-family:system-ui,sans-serif;margin:0;background:#0e1116;color:#e6edf3;
      display:flex;min-height:100vh;align-items:center;justify-content:center}}
 .card{{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:2.5rem;max-width:480px}}
 h1{{font-size:1.3rem;margin:.2rem 0 1rem}} .sub{{color:#8b949e;font-size:.9rem;word-break:break-all}}
 a.btn{{display:inline-block;margin-top:1.4rem;background:#21262d;color:#e6edf3;text-decoration:none;
       padding:.55rem 1.1rem;border-radius:8px;border:1px solid #30363d}} a.btn:hover{{background:#30363d}}
 a.pri{{background:#238636;border-color:#238636;color:#fff;margin-right:.6rem}} a.pri:hover{{background:#2ea043}}
</style></head><body>
<div class="card">
 <h1>Signed in</h1>
 <div class="sub">Subject: {subject}</div>
 <a class="btn pri" href="/portal/tunnels">Manage tunnels &rarr;</a>
 <a class="btn" href="/portal/logout">Sign out</a>
</div>
</body></html>"#,
        subject = escape(subject)
    )
}

/// Attach a `Set-Cookie` header (skipped silently if the value is not a valid
/// header — it never is for our fixed, percent-safe cookie strings).
fn set_cookie(resp: &mut Response, cookie: &str) {
    if let Ok(v) = HeaderValue::from_str(cookie) {
        resp.headers_mut().append(SET_COOKIE, v);
    }
}

/// The single-use CSRF state cookie: HttpOnly (no JS access), Secure (HTTPS
/// only), SameSite=Lax (sent on the top-level IdP redirect back), scoped to
/// `/portal`, expiring in 10 minutes.
fn state_cookie(state: &str) -> String {
    format!("{STATE_COOKIE}={state}; Path=/portal; Max-Age=600; HttpOnly; Secure; SameSite=Lax")
}

/// The same cookie with an immediate expiry, to retire it after the callback.
fn cleared_state_cookie() -> String {
    format!("{STATE_COOKIE}=; Path=/portal; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
}

/// Read a named cookie from the request `Cookie` header, if present.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|part| {
        let part = part.trim();
        part.strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('='))
            .map(|v| v.to_string())
    })
}

/// A fresh, unpredictable CSRF `state` value. PP2 will bind it to a cookie and
/// validate it at the callback; here it simply makes the redirect single-use-ish.
fn random_state() -> String {
    let mut b = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Percent-encode a query-parameter value (encode everything but the RFC 3986
/// unreserved set), so `redirect_uri` (with `:` and `/`) survives intact.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The customer portal shell (logged-out state): a self-contained, CSP-safe HTML
/// page offering real "Continue with Google/GitHub" buttons (via Keycloak's
/// `kc_idp_hint`, #portal-idp-hint) plus a direct email/password path -- one
/// click straight into the right flow instead of a single generic "Sign in with
/// SSO" button that just forwarded to another chooser screen.
const PORTAL_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bunsenbrenner.org — sign in or create an account</title>
<style>
 :root{--bg:#0b0e13;--panel:#161b22;--border:#30363d;--border2:#3d4551;--text:#e6edf3;--muted:#8b949e}
 *{box-sizing:border-box}
 body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;margin:0;background:var(--bg);
      color:var(--text);display:flex;min-height:100vh;align-items:center;justify-content:center;padding:1.5rem}
 .card{background:linear-gradient(180deg,#1c2128,var(--panel));border:1px solid var(--border);border-radius:14px;
       padding:2.3rem 2.1rem;max-width:400px;width:100%}
 .back{display:inline-block;margin-bottom:1.2rem;color:var(--muted);font-size:.85rem;text-decoration:none}
 .back:hover{color:#c9d1d9}
 h1{font-size:1.35rem;margin:.2rem 0 .35rem} .sub{color:#8b949e;font-size:.9rem;margin-bottom:1.6rem}
 .providers{display:flex;flex-direction:column;gap:.65rem;margin-bottom:1.2rem}
 a.provider{display:flex;align-items:center;gap:.7rem;background:#0d1117;border:1px solid var(--border);
   border-radius:9px;padding:.7rem 1rem;color:var(--text);text-decoration:none;font-weight:600;font-size:.92rem;
   transition:border-color .15s ease,background .15s ease}
 a.provider:hover{border-color:var(--border2);background:#1c2128}
 a.provider svg{width:1.1rem;height:1.1rem;flex-shrink:0}
 .divider{display:flex;align-items:center;gap:.7rem;color:var(--muted);font-size:.74rem;text-transform:uppercase;
   letter-spacing:.05em;margin:.9rem 0}
 .divider::before,.divider::after{content:"";flex:1;height:1px;background:var(--border)}
 a.btn-email{display:block;text-align:center;background:#238636;color:#fff;text-decoration:none;padding:.7rem 1.4rem;
       border-radius:9px;font-weight:600} a.btn-email:hover{background:#2ea043}
 .foot{color:var(--muted);font-size:.8rem;margin-top:1.6rem;text-align:center}
</style></head><body>
<div class="card">
 <a class="back" href="/">&larr; bunsenbrenner.org</a>
 <h1>&#128293; Sign in or create an account</h1>
 <div class="sub">One account for your tunnels, pipelines, and agents.</div>

 <div class="providers">
  <a class="provider" href="/portal/login?kc_idp_hint=google">
   <svg viewBox="0 0 18 18"><path fill='#4285F4' d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84c-.21 1.13-.84 2.09-1.8 2.73v2.27h2.92c1.7-1.57 2.68-3.87 2.68-6.64z"/><path fill='#34A853' d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.92-2.27c-.81.54-1.84.86-3.04.86-2.34 0-4.32-1.58-5.03-3.71H.96v2.33C2.44 15.98 5.48 18 9 18z"/><path fill='#FBBC05' d="M3.97 10.7c-.18-.54-.28-1.11-.28-1.7s.1-1.16.28-1.7V4.97H.96A8.99 8.99 0 0 0 0 9c0 1.45.35 2.83.96 4.03l3.01-2.33z"/><path fill='#EA4335' d="M9 3.58c1.32 0 2.51.45 3.44 1.35l2.59-2.59C13.46.89 11.43 0 9 0 5.48 0 2.44 2.02.96 4.97l3.01 2.33C4.68 5.16 6.66 3.58 9 3.58z"/></svg>
   Continue with Google
  </a>
  <a class="provider" href="/portal/login?kc_idp_hint=github">
   <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
   Continue with GitHub
  </a>
 </div>

 <div class="divider">or</div>

 <a class="btn-email" href="/portal/login">Continue with email</a>

 <div class="foot">Provider-blind tunnels — the operator never sees your payload.</div>
</div>
</body></html>"#;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn oidc_back_channel_client_times_out_a_hanging_idp() {
        // #96: a hanging IdP (accepts the TCP connection but never sends a response)
        // must make the OIDC back-channel call fail FAST via the client timeout, not
        // block the login path forever piling up requests.
        use std::time::{Duration, Instant};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if let Ok((sock, _)) = listener.accept().await {
                    // Hold the connection open, never writing a response.
                    tokio::spawn(async move {
                        let _held = sock;
                        std::future::pending::<()>().await;
                    });
                }
            }
        });

        let client = oidc_http_client_with(Duration::from_millis(400));
        let start = Instant::now();
        let result = client.get(format!("http://{addr}/token")).send().await;
        let elapsed = start.elapsed();

        assert!(result.is_err(), "a hanging IdP errors, it does not hang the login path");
        assert!(elapsed < Duration::from_secs(2), "failed fast in {elapsed:?}, not forever");
    }

    const TEST_KEY: &[u8] = b"portal-test-session-key";

    /// An injected exchanger returning a fixed subject and no email.
    fn stub_exchanger(subject: &'static str) -> Exchanger {
        Arc::new(move |_code| {
            Box::pin(async move {
                Ok(ExchangedIdentity {
                    subject: subject.to_string(),
                    email: None,
                })
            })
        })
    }

    /// An injected exchanger returning a fixed subject + email (#43 gate tests).
    fn stub_exchanger_email(subject: &'static str, email: &'static str) -> Exchanger {
        Arc::new(move |_code| {
            Box::pin(async move {
                Ok(ExchangedIdentity {
                    subject: subject.to_string(),
                    email: Some(email.to_string()),
                })
            })
        })
    }

    /// An injected exchanger that always fails (simulates an IdP/token error).
    fn failing_exchanger() -> Exchanger {
        Arc::new(|_code| Box::pin(async { Err("boom".to_string()) }))
    }

    #[test]
    fn from_lookup_derives_authorize_url_from_issuer() {
        let cfg = PortalOidc::from_lookup(|k| {
            match k {
                "CT_OIDC_CLIENT_ID" => Some("ct-portal".into()),
                "CT_OIDC_REDIRECT_URI" => Some("https://portal.example/portal/callback".into()),
                "CT_OIDC_ISSUER" => Some("https://kc.example/realms/ct/".into()),
                _ => None,
            }
        })
        .expect("configured");
        assert_eq!(
            cfg.authorize_url,
            "https://kc.example/realms/ct/protocol/openid-connect/auth"
        );
        assert_eq!(
            cfg.token_url,
            "https://kc.example/realms/ct/protocol/openid-connect/token"
        );
        // Missing redirect_uri -> not configured.
        assert!(PortalOidc::from_lookup(|k| (k == "CT_OIDC_CLIENT_ID").then(|| "x".into())).is_none());
    }

    #[test]
    fn demo_realm_matches_the_portal_oidc_contract() {
        // #42 KC1: the declarative Keycloak realm shipped for the SSO overlay must
        // stay in lock-step with what PortalOidc::from_env will actually consume —
        // a drifted client_id/redirect/realm-name would 503 the live login. Embed
        // the realm export at compile time (so a missing/renamed file fails the
        // build) and ground its client against the portal's own config derivation.
        let raw = include_str!("../../../docker/deploy/keycloak/ct-demo-realm.json");
        let realm: serde_json::Value = serde_json::from_str(raw).expect("realm export is valid JSON");

        assert_eq!(realm["realm"], "ct-demo", "realm name");
        assert_eq!(realm["registrationAllowed"], true, "self-registration on (no shipped credential)");
        assert_eq!(realm["defaultSignatureAlgorithm"], "RS256", "RS256 — the from_rsa_pem path");

        // #42 regression: Keycloak's RealmRepresentation deserializer is STRICT —
        // any unknown top-level field (e.g. a `_comment` doc note) aborts
        // --import-realm on every boot and crash-loops the container. Keep the
        // realm export free of non-schema fields; put explanation in comments in
        // compose.sso.yml / the runbook instead.
        for key in realm.as_object().expect("realm is an object").keys() {
            assert!(
                !key.starts_with('_'),
                "non-schema realm field {key:?} breaks Keycloak's strict import"
            );
        }

        let client = realm["clients"]
            .as_array()
            .and_then(|cs| cs.iter().find(|c| c["clientId"] == "ct-portal"))
            .expect("ct-portal client present");
        assert_eq!(client["publicClient"], false, "confidential client (secret-backed)");
        assert_eq!(client["standardFlowEnabled"], true, "Authorization Code flow");

        // #65: the confidential client's secret must be PINNED to the env placeholder
        // so Keycloak adopts the same value on every ephemeral realm reimport (else it
        // mints a fresh random secret and the control-plane's CT_OIDC_CLIENT_SECRET
        // drifts → every login 401/502s). CRITICAL: the realm-import resolver looks the
        // placeholder up via System.getenv(<inner>), so it MUST be `${KC_PORTAL_CLIENT_SECRET}`
        // — the `${env.KC_...}` form is NEVER substituted (verified live against KC 25.0:
        // it stays a literal and 401s the token exchange). Assert the exact resolvable form.
        let secret = client["secret"].as_str().unwrap_or("");
        assert_eq!(
            secret, "${KC_PORTAL_CLIENT_SECRET}",
            "ct-portal secret must be the resolvable ${{KC_PORTAL_CLIENT_SECRET}} placeholder (NOT ${{env....}}, which realm import leaves literal), got {secret:?}"
        );

        // #65 regression guard: the `${env.X}` form silently fails realm-import
        // substitution (System.getenv(\"env.X\") is null) and leaves a literal that
        // breaks the login. It must never reappear ANYWHERE in the realm export.
        assert!(
            !raw.contains("${env."),
            "realm export must not use the ${{env.VAR}} form — realm import does not substitute it (#65)"
        );

        // #42 regression: `defaultClientScopes` may only name real Keycloak client
        // scopes. `openid` is the request-time scope param (the portal sends
        // scope=openid), NOT a client scope — listing it fails the realm import.
        if let Some(scopes) = client["defaultClientScopes"].as_array() {
            assert!(
                !scopes.iter().any(|s| s == "openid"),
                "'openid' is not a Keycloak client scope; it breaks the realm import"
            );
        }

        // #49: identity-brokering providers (google/github/gitlab) are declared, with
        // credentials sourced from ${KC_*:} placeholders (resolvable form, empty
        // default so an unconfigured broker imports blank instead of a literal) —
        // never baked into the export. #65: same env-prefix fix as the portal secret.
        let idps = realm["identityProviders"].as_array().expect("identityProviders present");
        for want in ["google", "github", "gitlab"] {
            let idp = idps
                .iter()
                .find(|p| p["alias"] == want)
                .unwrap_or_else(|| panic!("{want} broker declared"));
            assert_eq!(idp["providerId"], want, "{want} providerId");
            assert_eq!(idp["trustEmail"], true, "{want} trustEmail (so #43's email gate works)");
            let cid = idp["config"]["clientId"].as_str().unwrap_or("");
            let sec = idp["config"]["clientSecret"].as_str().unwrap_or("");
            assert!(cid.starts_with("${KC_") && cid.ends_with(":}"), "{want} clientId from a resolvable ${{KC_*:}} placeholder, not baked/env-prefixed: {cid}");
            assert!(sec.starts_with("${KC_") && sec.ends_with(":}"), "{want} clientSecret from a resolvable ${{KC_*:}} placeholder, not baked/env-prefixed: {sec}");
        }

        let redirect = client["redirectUris"]
            .as_array()
            .and_then(|u| u.iter().find_map(|v| v.as_str().filter(|s| s.ends_with("/portal/callback"))))
            .expect("a /portal/callback redirect URI");

        // Feed the realm's own client_id + redirect + a realm-shaped issuer into
        // the portal's config derivation: it must resolve to Keycloak's real
        // authorize/token endpoints for THIS realm. This is the exact wiring KC3
        // will place in the compose env, proven consistent here.
        let client_id = client["clientId"].as_str().unwrap().to_string();
        let redirect_owned = redirect.to_string();
        let issuer = "https://kc.example/realms/ct-demo".to_string();
        let cfg = PortalOidc::from_lookup(|k| match k {
            "CT_OIDC_CLIENT_ID" => Some(client_id.clone()),
            "CT_OIDC_REDIRECT_URI" => Some(redirect_owned.clone()),
            "CT_OIDC_ISSUER" => Some(issuer.clone()),
            _ => None,
        })
        .expect("realm-derived config is fully resolvable");
        assert_eq!(cfg.client_id, "ct-portal");
        assert_eq!(
            cfg.authorize_url,
            "https://kc.example/realms/ct-demo/protocol/openid-connect/auth"
        );
        assert_eq!(
            cfg.token_url,
            "https://kc.example/realms/ct-demo/protocol/openid-connect/token"
        );
    }

    #[test]
    fn realm_ct_portal_access_token_carries_sub_claim() {
        // #92: setting the ct-portal client's `defaultClientScopes` explicitly
        // ("email"/"profile") overrides Keycloak's realm defaults and drops the
        // built-in `basic` scope that emits `sub`, so the ACCESS token loses `sub`.
        // That breaks OidcVerifier::subject() for EVERY /me/* bearer endpoint
        // (billing + the #81 channel registry). Guard that the client ships an
        // explicit protocol mapper putting `sub` into the access token, so this
        // realm-config regression is caught hermetically instead of only live.
        let raw = include_str!("../../../docker/deploy/keycloak/ct-demo-realm.json");
        let realm: serde_json::Value = serde_json::from_str(raw).expect("realm export is valid JSON");
        let client = realm["clients"]
            .as_array()
            .and_then(|cs| cs.iter().find(|c| c["clientId"] == "ct-portal"))
            .expect("ct-portal client present");

        let sub_mapper = client["protocolMappers"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|m| m["config"]["claim.name"] == "sub")
            .expect("ct-portal must ship a `sub` protocol mapper (else the access token has no sub — #92)");

        assert_eq!(
            sub_mapper["config"]["access.token.claim"], "true",
            "the sub mapper must emit into the ACCESS token — that is the token /me/* verifies"
        );
        // Maps the user's stable id (the same value the id_token's sub carries), not
        // a recyclable username, so the bearer identity matches the browser-session one.
        assert_eq!(sub_mapper["config"]["user.attribute"], "id", "sub = the user's stable id");
    }

    #[test]
    fn sso_compose_wires_the_control_plane_to_the_demo_realm() {
        // #42 KC3: the SSO overlay must feed the control-plane exactly the
        // client_id, redirect and realm that the declarative realm + portal code
        // already agree on (grounded in demo_realm_matches_the_portal_oidc_contract).
        // Embed the compose at compile time so drift fails the build, and ensure no
        // client secret is ever committed in the compose.
        let compose = include_str!("../../../docker/deploy/compose.sso.yml");
        assert!(
            compose.contains(r#"CT_OIDC_CLIENT_ID: "ct-portal""#),
            "compose client id matches the realm's ct-portal client"
        );
        assert!(compose.contains("/portal/callback"), "redirect uri hits the /portal/callback route");
        assert!(compose.contains("/realms/ct-demo"), "issuer points at the ct-demo realm");
        // #65: the client secret is single-sourced from ONE .env var
        // (KC_PORTAL_CLIENT_SECRET) that both drives Keycloak's realm import AND the
        // control-plane's code→token exchange — so they can never drift across a
        // Keycloak reimport. Neither side may carry a baked-in literal value.
        for var in ["KC_PORTAL_CLIENT_SECRET", "CT_OIDC_CLIENT_SECRET"] {
            let line = compose
                .lines()
                .find(|l| l.trim().starts_with(&format!("{var}:")))
                .unwrap_or_else(|| panic!("{var} must be wired in the compose"));
            assert!(
                line.contains("${KC_PORTAL_CLIENT_SECRET"),
                "{var} must reference the single .env var, not a literal secret: {line}"
            );
        }

        // #42 regression (bug 2): Keycloak 25 serves /health on the management
        // interface :9000, not the main :8080 — probing 8080 404s and the
        // healthcheck never passes, so depends_on: service_healthy never resolves.
        assert!(
            compose.contains("localhost/9000"),
            "the Keycloak healthcheck must probe the :9000 management port"
        );
        assert!(
            !compose.contains("localhost/8080"),
            "the healthcheck must not probe :8080 (health 404s there on KC 25)"
        );

        // #42 regression (bug 3): on the pinned :25.0 image the admin bootstrap
        // env is KEYCLOAK_ADMIN[_PASSWORD]; the KC_BOOTSTRAP_ADMIN_* names are
        // 26+ only and silently create no admin, blocking client-secret retrieval.
        assert!(compose.contains("KEYCLOAK_ADMIN"), "uses the :25.0 admin bootstrap env names");
        // Check active (non-comment) lines only — a comment may still mention the
        // wrong name to explain the pitfall.
        let sets_bootstrap_admin = compose
            .lines()
            .any(|l| l.trim().starts_with("KC_BOOTSTRAP_ADMIN"));
        assert!(
            !sets_bootstrap_admin,
            "KC_BOOTSTRAP_ADMIN_* is ignored on KC 25 — no admin gets created"
        );

        // #48: Keycloak is reached through the edge :443 front door (auth route),
        // NOT a published host port — so the SSO URLs are externally reachable.
        assert!(
            compose.contains("CT_EDGE_AUTH_HOST"),
            "the Auth (Keycloak) route is wired onto the edge front door"
        );
        assert!(
            !compose.contains("KEYCLOAK_PORT"),
            "Keycloak must not publish a host port — it's reached via the front door only"
        );
    }

    #[test]
    fn frontdoor_overlay_wires_the_443_front_door() {
        // #60 regression: the :443 front door (Portal landing page / SSO / browser
        // tunnels) must be REPRODUCIBLE from a checked-in compose overlay — not a
        // local uncommitted patch. compose.frontdoor.yml must enable CT_FRONT_DOOR,
        // route the Portal, mount its cert, and publish :443.
        let fd = include_str!("../../../docker/deploy/compose.frontdoor.yml");
        assert!(fd.contains("CT_FRONT_DOOR"), "front-door listener enabled");
        assert!(fd.contains("CT_EDGE_PORTAL_HOST"), "Portal host routed");
        assert!(fd.contains("CT_CP_PROXY_ADDR"), "Portal upstream (control plane) set");
        assert!(fd.contains("CT_EDGE_PORTAL_CERT"), "Portal TLS cert wired (FD4-a)");
        assert!(fd.contains("/certs/portal"), "Portal cert dir mounted");
        assert!(fd.contains(r#""443:443""#), "the :443 port is published");
        // env_file on the edge, so the above are overridable from .env (the gap #60 hit).
        assert!(fd.contains("env_file"), "edge reads .env for the front-door vars");
        // #66: the :80 -> :443 redirect must also be wired (env var + published port),
        // else plain http://<zone>/ is connection-refused. Same gap class as #60.
        assert!(fd.contains("CT_EDGE_HTTP_REDIRECT"), "the :80->:443 redirect listener is enabled");
        assert!(fd.contains(r#""80:80""#), "the :80 port is published for the redirect");
        // #68: the customer install one-liner's public base URL must be wired from
        // the front door's Portal host — else it defaults to https://localhost.
        let base_line = fd
            .lines()
            .find(|l| l.trim().starts_with("CT_PORTAL_BASE_URL:"))
            .expect("CT_PORTAL_BASE_URL wired in the overlay (#68)");
        assert!(
            base_line.contains("${PORTAL_PUBLIC_HOST"),
            "install base URL derives from PORTAL_PUBLIC_HOST, not a localhost default: {base_line}"
        );
    }

    #[test]
    fn selfhost_compose_binds_plaintext_ports_to_loopback() {
        // #85: the base self-host stack must NOT publish the control plane's plain-HTTP
        // :8090 (OIDC bearer tokens + portal session cookies in cleartext) or the
        // unauthenticated edge /metrics :9600 on a public interface — bind both host
        // publishes to loopback. Public access is the :443 front door. The mesh-plane
        // :4433 data plane stays public (opaque, authenticated).
        let sh = include_str!("../../../docker/deploy/compose.selfhost.yml");
        // Only `ports:` list items (`- "host:container"`), not env-var lines.
        let published = |container_port: &str| -> Vec<String> {
            sh.lines()
                .map(str::trim)
                .filter(|l| l.starts_with("- \"") && l.trim_end_matches('"').ends_with(container_port))
                .map(|l| l.trim_start_matches("- \"").trim_end_matches('"').to_string())
                .collect()
        };
        for line in published(":8090") {
            assert!(line.starts_with("127.0.0.1:"), "control-plane :8090 must be loopback-bound, got {line:?}");
        }
        for line in published(":9600") {
            assert!(line.starts_with("127.0.0.1:"), "edge metrics :9600 must be loopback-bound, got {line:?}");
        }
        // The mesh-plane data plane is intentionally still published to all interfaces.
        assert!(
            sh.contains(":4433/tcp") && !sh.contains("127.0.0.1:${EDGE_PORT:-4433}:4433"),
            "the :4433 tunnel data plane stays publicly reachable"
        );
    }

    #[tokio::test]
    async fn portal_home_renders_the_sso_cta() {
        let app = portal_router(None, TEST_KEY);
        let resp = app
            .oneshot(Request::get("/portal").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Continue with email"), "direct email/password login CTA present");
        assert!(html.contains(r#"href="/portal/login""#), "the email path links to the plain login route");
        assert!(
            html.contains(r#"href="/portal/login?kc_idp_hint=google""#),
            "the Google button hints Keycloak straight to that provider"
        );
        assert!(
            html.contains(r#"href="/portal/login?kc_idp_hint=github""#),
            "the GitHub button hints Keycloak straight to that provider"
        );
        assert!(!html.contains("http://") && !html.contains("https://cdn"), "self-contained, no external assets");
    }

    #[tokio::test]
    async fn login_redirects_to_the_authorize_endpoint() {
        let cfg = PortalOidc {
            authorize_url: "https://kc.example/realms/ct/protocol/openid-connect/auth".into(),
            token_url: "https://kc.example/realms/ct/protocol/openid-connect/token".into(),
            client_id: "ct-portal".into(),
            redirect_uri: "https://portal.example/portal/callback".into(),
        };
        let app = portal_router(Some(cfg), TEST_KEY);
        let resp = app
            .oneshot(Request::get("/portal/login").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(loc.starts_with("https://kc.example/realms/ct/protocol/openid-connect/auth?"));
        assert!(loc.contains("response_type=code"));
        assert!(loc.contains("client_id=ct-portal"));
        assert!(loc.contains("redirect_uri=https%3A%2F%2Fportal.example%2Fportal%2Fcallback"));
        assert!(loc.contains("scope=openid"));
        assert!(loc.contains("state="), "carries a CSRF state");
    }

    #[tokio::test]
    async fn login_passes_a_known_idp_hint_but_drops_an_unknown_one() {
        // The portal shell's "Continue with Google/GitHub" buttons send
        // ?kc_idp_hint=<provider> so Keycloak skips straight to that broker
        // instead of showing its own chooser. Only providers actually declared
        // in the ct-demo realm are allowlisted -- anything else is dropped
        // rather than reflected verbatim into the redirect URL.
        let cfg = PortalOidc {
            authorize_url: "https://kc.example/realms/ct/protocol/openid-connect/auth".into(),
            token_url: "https://kc.example/realms/ct/protocol/openid-connect/token".into(),
            client_id: "ct-portal".into(),
            redirect_uri: "https://portal.example/portal/callback".into(),
        };
        let app = portal_router(Some(cfg.clone()), TEST_KEY);
        let resp = app
            .oneshot(
                Request::get("/portal/login?kc_idp_hint=google")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(loc.contains("kc_idp_hint=google"), "known hint is passed through, got {loc}");

        let app2 = portal_router(Some(cfg), TEST_KEY);
        let resp2 = app2
            .oneshot(
                Request::get("/portal/login?kc_idp_hint=evil.com%2Fx")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::SEE_OTHER);
        let loc2 = resp2.headers().get("location").unwrap().to_str().unwrap();
        assert!(!loc2.contains("kc_idp_hint"), "an unrecognized hint is dropped, not reflected, got {loc2}");
    }

    #[tokio::test]
    async fn login_passes_the_landing_pages_email_through_as_a_login_hint() {
        // The landing page's email-first entry point submits straight to
        // /portal/login?login_hint=<email> -- Keycloak pre-fills its own
        // login+register form with it. No allowlist needed (unlike kc_idp_hint):
        // this only pre-fills a form field client-side, it authenticates nothing.
        let cfg = PortalOidc {
            authorize_url: "https://kc.example/realms/ct/protocol/openid-connect/auth".into(),
            token_url: "https://kc.example/realms/ct/protocol/openid-connect/token".into(),
            client_id: "ct-portal".into(),
            redirect_uri: "https://portal.example/portal/callback".into(),
        };
        let app = portal_router(Some(cfg), TEST_KEY);
        let resp = app
            .oneshot(
                Request::get("/portal/login?login_hint=me%40example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(loc.contains("login_hint=me%40example.com"), "email is passed through, got {loc}");
    }

    #[tokio::test]
    async fn login_with_register_lands_on_keycloaks_registration_form_not_login() {
        // The landing page's email-first CTA is a new-visitor path -- a first-time
        // visitor typing their email and hitting "Continue" should land on
        // Keycloak's own account-creation form, not its login form with the
        // register link buried in it. /portal/login?register (any value, or bare)
        // swaps the target from .../auth to .../registrations, Keycloak's own
        // documented deep link for this, keeping every other param identical.
        let cfg = PortalOidc {
            authorize_url: "https://kc.example/realms/ct/protocol/openid-connect/auth".into(),
            token_url: "https://kc.example/realms/ct/protocol/openid-connect/token".into(),
            client_id: "ct-portal".into(),
            redirect_uri: "https://portal.example/portal/callback".into(),
        };
        let app = portal_router(Some(cfg.clone()), TEST_KEY);
        let resp = app
            .oneshot(
                Request::get("/portal/login?register=1&login_hint=me%40example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(
            loc.starts_with("https://kc.example/realms/ct/protocol/openid-connect/registrations?"),
            "routes to the registrations form, got {loc}"
        );
        assert!(loc.contains("login_hint=me%40example.com"), "still carries the email, got {loc}");
        assert!(loc.contains("client_id=ct-portal") && loc.contains("state="), "other params unaffected, got {loc}");

        // Without ?register, the ordinary /portal "Sign in" links still land on login.
        let app2 = portal_router(Some(cfg), TEST_KEY);
        let resp2 = app2.oneshot(Request::get("/portal/login").body(Body::empty()).unwrap()).await.unwrap();
        let loc2 = resp2.headers().get("location").unwrap().to_str().unwrap();
        assert!(
            loc2.starts_with("https://kc.example/realms/ct/protocol/openid-connect/auth?"),
            "plain /portal/login still goes to the login form, got {loc2}"
        );
    }

    fn cfg() -> PortalOidc {
        PortalOidc {
            authorize_url: "https://kc.example/realms/ct/protocol/openid-connect/auth".into(),
            token_url: "https://kc.example/realms/ct/protocol/openid-connect/token".into(),
            client_id: "ct-portal".into(),
            redirect_uri: "https://portal.example/portal/callback".into(),
        }
    }

    #[tokio::test]
    async fn login_binds_state_in_an_httponly_cookie_matching_the_redirect() {
        // #25 PP2: the CSRF state travels both in the redirect and a single-use cookie.
        let app = portal_router(Some(cfg()), TEST_KEY);
        let resp = app
            .oneshot(Request::get("/portal/login").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
        let cookie = resp
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(cookie.contains("ct_portal_state="), "sets the state cookie");
        assert!(cookie.contains("HttpOnly"), "not readable by JS");
        assert!(cookie.contains("Secure"), "HTTPS only");
        assert!(cookie.contains("SameSite=Lax"), "sent on the IdP top-level redirect back");
        // The cookie's state must equal the redirect's state.
        let from_cookie = cookie
            .split(';')
            .next()
            .unwrap()
            .trim_start_matches("ct_portal_state=")
            .to_string();
        assert!(
            loc.contains(&format!("state={from_cookie}")),
            "redirect state matches the cookie"
        );
    }

    #[tokio::test]
    async fn callback_rejects_missing_params_and_mismatched_state() {
        let app = portal_router(Some(cfg()), TEST_KEY);

        // Missing code/state -> 400.
        let resp = app
            .clone()
            .oneshot(Request::get("/portal/callback?code=abc").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // State present but no cookie -> 403 (CSRF).
        let resp = app
            .clone()
            .oneshot(
                Request::get("/portal/callback?code=abc&state=s1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // State present but cookie differs -> 403 (CSRF).
        let resp = app
            .oneshot(
                Request::get("/portal/callback?code=abc&state=s1")
                    .header("cookie", "ct_portal_state=OTHER")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn callback_exchanges_the_code_and_mints_a_session() {
        // #25 PP4: valid state -> exchange -> session cookie -> redirect to home.
        let app = portal_router_with(Some(cfg()), TEST_KEY, stub_exchanger("kc-user-9"), None);
        let resp = app
            .oneshot(
                Request::get("/portal/callback?code=abc&state=s1")
                    .header("cookie", "ct_portal_state=s1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/portal/home");

        // Two Set-Cookie headers: a valid session, and the state cookie cleared.
        let cookies: Vec<String> = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        let session = cookies
            .iter()
            .find(|c| c.starts_with("ct_portal_session="))
            .expect("session cookie set");
        assert!(session.contains("HttpOnly") && session.contains("Secure"));
        assert!(
            cookies.iter().any(|c| c.starts_with("ct_portal_state=;")),
            "state cookie cleared"
        );
        // The minted session verifies to the exchanged subject.
        let token = session
            .strip_prefix("ct_portal_session=")
            .and_then(|s| s.split(';').next())
            .unwrap();
        assert_eq!(
            verify_session(TEST_KEY, token, 0).as_deref(),
            Some("kc-user-9")
        );
    }

    #[tokio::test]
    async fn callback_reports_bad_gateway_when_exchange_fails() {
        let app = portal_router_with(Some(cfg()), TEST_KEY, failing_exchanger(), None);
        let resp = app
            .oneshot(
                Request::get("/portal/callback?code=abc&state=s1")
                    .header("cookie", "ct_portal_state=s1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        // No session is minted on a failed exchange; the state cookie is retired.
        let cookies: Vec<String> = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert!(cookies.iter().all(|c| !c.starts_with("ct_portal_session=")), "no session");
        assert!(cookies.iter().any(|c| c.starts_with("ct_portal_state=;")), "state cleared");
    }

    /// Sign an id_token with a throwaway RSA key (RS256, kid `k1`) and return it
    /// with the matching JWKS — the realm-signing-key model, hermetic (#82).
    fn signed_id_token_and_jwks(claims: serde_json::Value) -> (String, serde_json::Value) {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use rsa::pkcs8::{EncodePrivateKey, LineEnding};
        use rsa::traits::PublicKeyParts;
        use rsa::{RsaPrivateKey, RsaPublicKey};
        let mut rng = rand::rngs::OsRng;
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("rsa key");
        let public = RsaPublicKey::from(&private);
        let n = URL_SAFE_NO_PAD.encode(public.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public.e().to_bytes_be());
        let pem = private.to_pkcs8_pem(LineEnding::LF).expect("pem");
        let mut h = Header::new(Algorithm::RS256);
        h.kid = Some("k1".to_string());
        let jwt = encode(&h, &claims, &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap()).unwrap();
        let jwks = serde_json::json!({"keys": [
            {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1", "n": n, "e": e}
        ]});
        (jwt, jwks)
    }

    #[test]
    fn id_token_signature_issuer_and_audience_are_verified() {
        let iss = "https://kc.example/realms/ct-demo";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // A validly-signed id_token yields sub + email.
        let (jwt, jwks) = signed_id_token_and_jwks(
            serde_json::json!({"sub":"kc-user-42","email":"a@becke.biz","iss":iss,"aud":"ct-portal","exp":now+3600}),
        );
        let id = identity_from_verified_id_token(&jwt, &jwks, iss, "ct-portal").unwrap();
        assert_eq!(id.subject, "kc-user-42");
        assert_eq!(id.email.as_deref(), Some("a@becke.biz"));

        // #82 core: a token NOT signed by the realm key (attacker-forged, same kid)
        // is rejected — the JWKS-published key doesn't match the signature.
        let (forged, _) = signed_id_token_and_jwks(
            serde_json::json!({"sub":"attacker","iss":iss,"aud":"ct-portal","exp":now+3600}),
        );
        assert!(
            identity_from_verified_id_token(&forged, &jwks, iss, "ct-portal").is_err(),
            "a token not signed by the realm key must be rejected"
        );

        // Wrong issuer and wrong audience are rejected.
        let (bad_iss, j2) = signed_id_token_and_jwks(
            serde_json::json!({"sub":"x","iss":"https://evil/realms/x","aud":"ct-portal","exp":now+3600}),
        );
        assert!(identity_from_verified_id_token(&bad_iss, &j2, iss, "ct-portal").is_err(), "wrong issuer rejected");
        let (bad_aud, j3) = signed_id_token_and_jwks(
            serde_json::json!({"sub":"x","iss":iss,"aud":"other-client","exp":now+3600}),
        );
        assert!(identity_from_verified_id_token(&bad_aud, &j3, iss, "ct-portal").is_err(), "wrong audience rejected");

        // #43: sub required, email optional; garbage rejected.
        let (no_email, j4) = signed_id_token_and_jwks(
            serde_json::json!({"sub":"kc-user-7","iss":iss,"aud":"ct-portal","exp":now+3600}),
        );
        assert_eq!(identity_from_verified_id_token(&no_email, &j4, iss, "ct-portal").unwrap().email, None);
        assert!(identity_from_verified_id_token("garbage", &jwks, iss, "ct-portal").is_err());
    }

    #[test]
    fn allowed_domains_parses_and_matches_case_insensitively() {
        // #43: unset/empty -> gate OFF (None). A leading '@' and whitespace are
        // tolerated; matching is on the case-folded domain after the last '@'.
        assert!(parse_allowed_domains(None).is_none(), "unset -> gate off");
        assert!(parse_allowed_domains(Some("  , ".into())).is_none(), "empty entries -> off");

        let allow = parse_allowed_domains(Some(" becke.biz , @Example.org ".into())).unwrap();
        assert_eq!(&*allow, &["becke.biz".to_string(), "example.org".to_string()]);

        assert!(email_domain_allowed(Some("Alice@Becke.BIZ"), &allow), "case-insensitive host");
        assert!(email_domain_allowed(Some("x@example.org"), &allow));
        assert!(!email_domain_allowed(Some("mallory@evil.test"), &allow), "other domain rejected");
        assert!(!email_domain_allowed(None, &allow), "no email -> rejected when gate on");
        assert!(!email_domain_allowed(Some("no-at-sign"), &allow), "malformed -> rejected");
    }

    #[tokio::test]
    async fn callback_gate_admits_allowed_domain_and_mints_a_session() {
        // #43: an allowed-domain subject reaches /portal/home WITH a session cookie.
        let allow = parse_allowed_domains(Some("becke.biz".into()));
        let app = portal_router_with(
            Some(cfg()),
            TEST_KEY,
            stub_exchanger_email("kc-user-9", "dev@becke.biz"),
            allow,
        );
        let resp = app
            .oneshot(
                Request::get("/portal/callback?code=abc&state=s1")
                    .header("cookie", "ct_portal_state=s1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/portal/home");
        assert!(
            resp.headers()
                .get_all("set-cookie")
                .iter()
                .any(|c| c.to_str().unwrap().starts_with("ct_portal_session=")
                    && !c.to_str().unwrap().contains("ct_portal_session=;")),
            "an allowed subject gets a real session cookie"
        );
    }

    #[tokio::test]
    async fn callback_gate_rejects_disallowed_domain_without_a_session() {
        // #43: a non-allowed-domain subject is 403'd with the access-list page and
        // NO session cookie — an obvious acceptance-policy rejection.
        let allow = parse_allowed_domains(Some("becke.biz".into()));
        let app = portal_router_with(
            Some(cfg()),
            TEST_KEY,
            stub_exchanger_email("kc-user-x", "mallory@evil.test"),
            allow,
        );
        let resp = app
            .oneshot(
                Request::get("/portal/callback?code=abc&state=s1")
                    .header("cookie", "ct_portal_state=s1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let sets: Vec<String> = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert!(
            !sets.iter().any(|c| c.starts_with("ct_portal_session=")
                && !c.contains("ct_portal_session=;")),
            "no session cookie is minted for a rejected subject"
        );
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert!(
            String::from_utf8_lossy(&body).contains("not on the access list"),
            "a clear access-policy message, not a generic error"
        );
    }

    #[tokio::test]
    async fn callback_gate_off_admits_any_domain() {
        // #43: with the gate OFF (None), any authenticated subject is admitted —
        // zero-config self-host is unchanged even with an email present.
        let app = portal_router_with(
            Some(cfg()),
            TEST_KEY,
            stub_exchanger_email("kc-user-z", "anyone@wherever.test"),
            None,
        );
        let resp = app
            .oneshot(
                Request::get("/portal/callback?code=abc&state=s1")
                    .header("cookie", "ct_portal_state=s1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "gate off -> admitted");
    }

    #[tokio::test]
    async fn callback_reports_unconfigured_without_oidc() {
        let app = portal_router(None, TEST_KEY);
        let resp = app
            .oneshot(
                Request::get("/portal/callback?code=abc&state=s1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn login_without_config_reports_unconfigured() {
        let app = portal_router(None, TEST_KEY);
        let resp = app
            .oneshot(Request::get("/portal/login").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn session_sign_verify_roundtrips_and_rejects_tampering() {
        // #25 PP3: a signed session yields its subject; any tampering fails.
        let now = 1_000_000u64;
        let tok = sign_session(TEST_KEY, "kc-user-7", now + SESSION_TTL_SECS);
        assert_eq!(verify_session(TEST_KEY, &tok, now).as_deref(), Some("kc-user-7"));

        // Wrong key -> rejected.
        assert!(verify_session(b"other-key", &tok, now).is_none());
        // Expired -> rejected.
        assert!(verify_session(TEST_KEY, &tok, now + SESSION_TTL_SECS + 1).is_none());
        // Flipped MAC byte -> rejected.
        let mut bad = tok.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == 'a' { 'b' } else { 'a' });
        assert!(verify_session(TEST_KEY, &bad, now).is_none());
        // Garbage -> rejected, no panic.
        assert!(verify_session(TEST_KEY, "not-a-token", now).is_none());
    }

    #[tokio::test]
    async fn home_requires_a_valid_session_else_redirects() {
        let app = portal_router(Some(cfg()), TEST_KEY);

        // No session cookie -> bounce to the shell.
        let resp = app
            .clone()
            .oneshot(Request::get("/portal/home").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/portal");

        // A valid session cookie -> the logged-in home showing the subject.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let tok = sign_session(TEST_KEY, "kc-user-7", now + SESSION_TTL_SECS);
        let resp = app
            .oneshot(
                Request::get("/portal/home")
                    .header("cookie", format!("{SESSION_COOKIE}={tok}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("kc-user-7"), "shows the signed-in subject");
        assert!(html.contains("/portal/logout"), "offers sign-out");
        // #67: home must offer a discoverable path into tunnel management — else a
        // signed-in customer can't reach the product without knowing the URL.
        assert!(
            html.contains(r#"href="/portal/tunnels""#),
            "links to tunnel management (#67)"
        );
    }

    #[tokio::test]
    async fn logout_clears_the_session_cookie_and_ends_the_idp_session() {
        // Clearing only our own cookie leaves Keycloak's SSO session alive, so the
        // next sign-in silently re-authenticates -- logout must also redirect
        // through the IdP's RP-Initiated Logout endpoint (#logout-fix).
        let app = portal_router(Some(cfg()), TEST_KEY);
        let resp = app
            .oneshot(Request::get("/portal/logout").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(
            location.starts_with("https://kc.example/realms/ct/protocol/openid-connect/logout?"),
            "redirects through the IdP's end_session_endpoint, got {location}"
        );
        assert!(location.contains("client_id=ct-portal"));
        assert!(
            location.contains("post_logout_redirect_uri=https%3A%2F%2Fportal.example%2Fportal"),
            "post_logout_redirect_uri is the portal root (allow-listed in the realm's \
             post.logout.redirect.uris), got {location}"
        );
        let cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
        assert!(cookie.starts_with("ct_portal_session=;"), "session cookie cleared");
        assert!(cookie.contains("Max-Age=0"));
    }

    #[tokio::test]
    async fn logout_falls_back_to_a_local_redirect_without_oidc() {
        let app = portal_router(None, TEST_KEY);
        let resp = app
            .oneshot(Request::get("/portal/logout").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/portal");
        let cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
        assert!(cookie.starts_with("ct_portal_session=;"), "session cookie still cleared");
    }

    #[test]
    fn session_cookie_carries_the_hardening_flags() {
        let c = session_cookie("tok123");
        assert!(c.starts_with("ct_portal_session=tok123;"));
        for flag in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/portal"] {
            assert!(c.contains(flag), "cookie sets {flag}");
        }
    }
}
