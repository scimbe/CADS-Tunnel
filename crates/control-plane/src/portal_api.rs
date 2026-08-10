//! Authenticated customer-portal API (#26–#29) — the logged-in surface behind
//! the SSO session (#25). Every endpoint resolves the caller's subject from the
//! signed session cookie via [`crate::portal::session_subject_for`]; without a
//! valid session the visitor is bounced to the portal shell. All pages are
//! server-rendered, self-contained, CSP-safe HTML, and every subject only ever
//! sees or changes their own data.

use std::sync::Arc;

use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};


use crate::accounts::AccountId;
use crate::edge_mesh::EdgeMeshHandle;
use crate::portal::{escape, session_subject_for};
use crate::storage::{GrantError, SqliteBootstrap, SqliteEnrollment, SqliteLedger, SqliteTunnelStore};
use ct_common::TenantId;
use ct_dns::provider::DesecClient;

/// #297: map a storage/DB error to a generic 500 instead of leaking `e`'s `Display`
/// (SQLite internals — constraint/table/column names, schema state) to the caller.
/// The real error still reaches the operator, just server-side in the log, tagged
/// with `context` (the handler/call site) so it's still diagnosable.
fn internal_error(context: &str, e: impl std::fmt::Display) -> (StatusCode, String) {
    eprintln!("ct-cp portal: {context}: {e}");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
}

/// Shared HTTP client for the edge admin API calls (#112): a hung edge admin
/// endpoint must not block the portal's authenticated request path (create /
/// delete tunnel). Mirrors the timeout guard already on the OIDC client
/// (`portal.rs`, #96) and the `/status` scrape (`service.rs`). Split so a test
/// can inject a short timeout.
fn edge_admin_http_client_with(timeout: std::time::Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// The edge admin client with the production timeout — a hung edge must not wedge
/// the portal request. `pub(crate)`: also reused by `acme_broker`'s
/// channel-tier-push calls (#233), the same shared secret and endpoint shape as here.
/// #349: same reasoning as `portal::oidc_http_client` -- built once (lazily) and cloned
/// (a cheap `Arc` bump) instead of paying a fresh TLS handshake + DNS lookup to the edge
/// admin API on every create/delete_tunnel/authorize_hostname call.
pub(crate) fn edge_admin_http_client() -> reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| edge_admin_http_client_with(std::time::Duration::from_secs(5))).clone()
}

/// Automatic DNS-record management for tunnel hostnames (#38 DL2): create the A
/// record on hostname-set, delete it on revoke, pointing at the edge's public IP.
#[derive(Clone)]
struct DnsAutopilot {
    client: DesecClient,
    edge_ip: Arc<str>,
}

/// Where to reach the edge's admin revoke API (#27 RB4), if configured.
#[derive(Clone)]
struct EdgeAdmin {
    url: Arc<str>,
    token: Arc<str>,
}

/// Shared state for the authed portal API.
#[derive(Clone)]
struct ApiState {
    session_key: Arc<[u8]>,
    ledger: Arc<SqliteLedger>,
    tunnels: Arc<SqliteTunnelStore>,
    enrollment: Arc<SqliteEnrollment>,
    /// Bootstrap-token store (#90/#97 SEC90b): the install page's one-liner used
    /// this to mint a short-lived token over the `{join, routing}` bundle so the
    /// shown one-liner carried no secret. Temporarily unused -- the one-liner
    /// itself is hidden until `/install.sh`/`/install.ps1` actually ship (#75) --
    /// kept (not removed) so re-enabling it doesn't need to re-thread this field
    /// through `portal_api_router`'s signature and every test call site again.
    #[allow(dead_code)]
    bootstrap: Arc<SqliteBootstrap>,
    /// Public portal origin (e.g. `https://portal.example`) baked into installers.
    portal_base: Arc<str>,
    /// Edge admin revoke endpoint (#27 RB4b); `None` disables edge propagation.
    edge_admin: Option<EdgeAdmin>,
    /// Automatic DNS for tunnel hostnames (#38 DL2); `None` disables it.
    dns: Option<DnsAutopilot>,
    /// Keycloak's own Account Console (password change, sessions, self-service
    /// account deletion) — `None` when OIDC isn't configured, in which case the
    /// account page simply omits the link rather than pointing at nothing.
    account_console_url: Option<Arc<str>>,
    /// Records which edge owns a tunnel's (token, hostname) once it's authorized —
    /// the multi-edge ownership registry's first hook point (edge_mesh Phase 0).
    /// Always present (no config gate): purely additive bookkeeping alongside the
    /// edge-authorize call, never blocking tunnel creation on its own.
    edge_mesh: EdgeMeshHandle,
    /// Shared admin secret gating [`admin_provision_tunnel`] -- the operator-only
    /// escape hatch for a custom/vanity hostname (today's Standard tier only ever
    /// auto-assigns one). `None` disables the route entirely (404s), matching
    /// this crate's "absent unless configured" convention.
    admin_token: Option<[u8; 32]>,
}

/// Build the authenticated portal API router (#26 account, #27 tunnels, #28 install).
/// `edge_admin` is `(base_url, admin_token)` for the edge revoke API (#27 RB4b).
pub fn portal_api_router(
    session_key: &[u8],
    ledger: Arc<SqliteLedger>,
    tunnels: Arc<SqliteTunnelStore>,
    enrollment: Arc<SqliteEnrollment>,
    bootstrap: Arc<SqliteBootstrap>,
    portal_base: &str,
    edge_admin: Option<(String, String)>,
    dns: Option<(DesecClient, String)>,
    account_console_url: Option<String>,
    edge_mesh: EdgeMeshHandle,
    admin_token: Option<[u8; 32]>,
) -> Router {
    let state = ApiState {
        session_key: Arc::from(session_key.to_vec()),
        ledger,
        tunnels,
        enrollment,
        bootstrap,
        portal_base: Arc::from(portal_base),
        edge_admin: edge_admin.map(|(url, token)| EdgeAdmin {
            url: Arc::from(url),
            token: Arc::from(token),
        }),
        dns: dns.map(|(client, edge_ip)| DnsAutopilot {
            client,
            edge_ip: Arc::from(edge_ip),
        }),
        account_console_url: account_console_url.map(Arc::from),
        edge_mesh,
        admin_token,
    };
    Router::new()
        .route("/portal/account", get(account_page))
        .route("/portal/account/credits", post(buy_credits))
        .route("/portal/tunnels", get(tunnels_page).post(create_tunnel))
        .route("/portal/tunnels/:id/delete", post(delete_tunnel))
        .route("/portal/tunnels/:id/reclaim-cert-slot", post(reclaim_cert_slot))
        .route("/portal/tunnels/:id/install", get(install_page))
        .route("/portal/tunnels/:id/grants", get(grants_page).post(add_grant))
        .route("/portal/tunnels/:id/grants/:grantee/delete", post(delete_grant))
        .route("/admin/provision-tunnel", post(admin_provision_tunnel))
        .route("/admin/accounts/:subject/max-tunnels", post(admin_set_max_tunnels))
        .with_state(state)
}

#[derive(Deserialize)]
struct ProvisionTunnelReq {
    subject: String,
    name: String,
    hostname: String,
}

#[derive(Serialize)]
struct ProvisionTunnelResp {
    routing_token: String,
    hostname: String,
}

/// `POST /admin/provision-tunnel` (operator-only, `x-ct-admin-token`): create a
/// tunnel with an explicit, chosen hostname rather than the Standard tier's
/// auto-assigned one -- e.g. a vanity subdomain for a known project/maintainer.
/// Runs the SAME edge-authorize + DNS-A-record side effects
/// ([`authorize_hostname`]) as the self-service path, so the resulting tunnel
/// is a real `subject_tunnels` row that participates in the Rot/Gelb/Grün
/// admission broker exactly like any other -- the recipient can run
/// `ct-agent certificate` against it like any Standard-tier customer.
/// The one `x-ct-admin-token` check every `/admin/*` route in this file needs:
/// `404` when no admin token is configured at all (the route doesn't exist),
/// `401` on a missing/malformed/wrong header, constant-time comparison against
/// the real token either way. Factored out so `admin_set_max_tunnels` doesn't
/// duplicate [`admin_provision_tunnel`]'s own copy of this.
fn admin_authed(headers: &HeaderMap, admin_token: Option<[u8; 32]>) -> Result<(), StatusCode> {
    let Some(expected) = admin_token else {
        return Err(StatusCode::NOT_FOUND);
    };
    let authed = headers
        .get("x-ct-admin-token")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            if s.len() != 64 {
                return None;
            }
            let mut out = [0u8; 32];
            for (i, b) in out.iter_mut().enumerate() {
                *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
            }
            Some(out)
        })
        .is_some_and(|got| got.iter().zip(&expected).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0);
    if authed {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn admin_provision_tunnel(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<ProvisionTunnelReq>,
) -> Response {
    if let Err(code) = admin_authed(&headers, st.admin_token) {
        return code.into_response();
    }
    let Some(hostname) = ct_common::normalize_hostname(&req.hostname) else {
        return (StatusCode::BAD_REQUEST, "invalid hostname").into_response();
    };
    let name = req.name.trim();
    if name.is_empty() || req.subject.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "subject and name are required").into_response();
    }
    let tunnel = match st.tunnels.create(req.subject.trim(), name, Some(&hostname)) {
        Ok(t) => t,
        Err(e) => return internal_error("admin_provision_tunnel/create", e).into_response(),
    };
    authorize_hostname(&st, &tunnel).await;
    Json(ProvisionTunnelResp { routing_token: tunnel.routing_token.clone(), hostname }).into_response()
}

#[derive(Deserialize)]
struct SetMaxTunnelsReq {
    max: u32,
}

/// `POST /admin/accounts/:subject/max-tunnels {max}` (operator-only, #214):
/// raise (or lower) how many tunnels ONE SPECIFIC account may own at once,
/// above the Standard tier's default of 1 -- unlocks self-service creation of
/// additional subdomains (`POST /portal/tunnels`, the same customer-facing
/// route every Standard-tier account already uses) for a trusted account
/// instead of the operator running [`admin_provision_tunnel`] by hand for
/// every additional hostname that account wants. `:subject` is the OIDC
/// subject, resolved the exact same way every other self-service action here
/// resolves an account ([`crate::storage::SqliteLedger::account_for_subject`]),
/// so this always targets exactly the account that subject's own portal login
/// reaches -- never any other account.
async fn admin_set_max_tunnels(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(subject): Path<String>,
    Json(req): Json<SetMaxTunnelsReq>,
) -> Response {
    if let Err(code) = admin_authed(&headers, st.admin_token) {
        return code.into_response();
    }
    let account = match st.ledger.account_for_subject(&subject) {
        Ok(a) => a,
        Err(e) => return internal_error("admin_set_max_tunnels/account_for_subject", e).into_response(),
    };
    if let Err(e) = st.ledger.set_max_tunnels(&account, req.max) {
        return internal_error("admin_set_max_tunnels/set", e).into_response();
    }
    StatusCode::OK.into_response()
}

/// Resolve the caller's account from the session, or an early response
/// (redirect to the shell when unauthenticated, 500 on a store error).
fn account_for_session(st: &ApiState, headers: &HeaderMap) -> Result<(String, AccountId), Response> {
    let subject = session_subject_for(&st.session_key, headers)
        .ok_or_else(|| Redirect::to("/portal").into_response())?;
    let account = st
        .ledger
        .account_for_subject(&subject)
        .map_err(|e| internal_error("account_for_session", e).into_response())?;
    Ok((subject, account))
}

/// `GET /portal/account` (#26 PP2): the logged-in customer's account page —
/// account id, credit balance (Guthaben) and subject. Self-scoped: the subject
/// comes from the session, so a caller only ever sees their own account.
async fn account_page(State(st): State<ApiState>, headers: HeaderMap) -> Response {
    let (subject, account) = match account_for_session(&st, &headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let balance = st.ledger.balance(&account).unwrap_or(0);
    Html(account_html(
        &subject,
        &hex(&account.0),
        balance,
        st.account_console_url.as_deref(),
    ))
    .into_response()
}

/// Credits to add, from the buy-credits form.
#[derive(Deserialize)]
struct BuyCreditsForm {
    credits: u64,
}

/// `POST /portal/account/credits` (#26): create a payment intent for the
/// caller's own account against the existing billing surface. Actual crediting
/// happens only via the signature-verified provider webhook (never here), so
/// this just registers the intent the customer then pays.
async fn buy_credits(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Form(form): Form<BuyCreditsForm>,
) -> Response {
    let (_subject, account) = match account_for_session(&st, &headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if form.credits == 0 {
        return (StatusCode::BAD_REQUEST, "credits must be > 0").into_response();
    }
    let intent = match st.ledger.create_intent(&account, form.credits) {
        Ok(id) => id,
        Err(e) => return internal_error("buy_credits/create_intent", e).into_response(),
    };
    let body = format!(
        r#"<h1>Payment intent created</h1>
<div class="row"><span class="k">Credits</span><span class="v">{credits}</span></div>
<div class="row"><span class="k">Intent&nbsp;ID</span><span class="v"><code>{intent}</code></span></div>
<h2>Next</h2>
<p class="k">Pay this intent with your provider. Your balance updates once the
provider's signed webhook confirms the payment.</p>
<a class="btn sec" href="/portal/account">Back to account</a>"#,
        credits = form.credits,
        intent = escape(&hex(&intent.0)),
    );
    Html(page("buy credits", &body)).into_response()
}

/// Shared state for the account-deletion cascade (Keycloak/account overhaul): every
/// store that holds data keyed by a portal subject. Before this, `account_html`'s
/// "manage your account" section punted entirely to Keycloak's own Account Console
/// -- correct for identity concerns (password, sessions, the Keycloak login itself)
/// but Keycloak has no idea CADS-Tunnel's own tunnels/channels/topologies/networks/
/// pipelines exist, so a Keycloak-side account deletion would silently leave every
/// bit of a customer's CADS-Tunnel data behind. Kept as its own small state/router
/// (matching `ClaimState`/`TopologyPortalState`'s pattern) rather than widening
/// `ApiState`, so this doesn't have to thread five more stores through every
/// existing `portal_api_router` call site.
#[derive(Clone)]
struct AccountDeleteState {
    session_key: Arc<[u8]>,
    tunnels: Arc<SqliteTunnelStore>,
    channels: Arc<crate::storage::SqliteChannelStore>,
    topologies: Arc<crate::storage::SqliteTopologyStore>,
    networks: Arc<crate::storage::SqliteNetworkStore>,
    pipelines: Arc<crate::storage::SqlitePipelineRegistry>,
}

/// Build the account-deletion router: `POST /portal/account/delete`, session-cookie
/// authed, cascading across every store this crate keeps that's keyed by a portal
/// subject. Mount alongside `portal_api_router` wherever those stores are already
/// in scope.
pub fn account_delete_router(
    session_key: &[u8],
    tunnels: Arc<SqliteTunnelStore>,
    channels: Arc<crate::storage::SqliteChannelStore>,
    topologies: Arc<crate::storage::SqliteTopologyStore>,
    networks: Arc<crate::storage::SqliteNetworkStore>,
    pipelines: Arc<crate::storage::SqlitePipelineRegistry>,
) -> Router {
    Router::new()
        .route("/portal/account/delete", post(delete_account))
        .with_state(AccountDeleteState {
            session_key: Arc::from(session_key.to_vec()),
            tunnels,
            channels,
            topologies,
            networks,
            pipelines,
        })
}

#[derive(Deserialize, Default)]
struct DeleteAccountForm {
    #[serde(default)]
    confirm: String,
}

/// `POST /portal/account/delete`: irreversibly delete every CADS-Tunnel resource the
/// caller's account owns -- tunnels (revoked), channels (deleted, with members and
/// allow-list), topologies (deleted, with their agents/edges/share-list), declarative
/// networks, and published pipelines -- then strips the caller's e-mail out of anyone
/// else's channel allow-list / topology share-list so a deleted account stops showing
/// up in other people's "shared with" views. Requires the literal confirmation text
/// `DELETE` in the form body (a lightweight guard against an accidental submit; the
/// real "are you sure" friction lives in the account page's own JS confirm). Does
/// **not** touch the Keycloak account itself -- the account page's own copy tells the
/// caller to also use the linked Account Console for that, matching the existing
/// division of concerns (identity vs. this crate's own data).
async fn delete_account(State(st): State<AccountDeleteState>, headers: HeaderMap, Form(form): Form<DeleteAccountForm>) -> Response {
    let Some(claims) = crate::portal::session_claims_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    if form.confirm.trim() != "DELETE" {
        // Belt-and-suspenders: the form's own `pattern="DELETE"` + submit-time
        // `window.confirm()` (account_html) mean a real browser never reaches this,
        // but a crafted/JS-disabled request shouldn't dead-end on a bare text
        // response either -- send it back to a real page with a way out.
        let body = r#"<h1>Confirmation text didn't match</h1>
<p class="help">Type <code>DELETE</code> exactly to confirm account deletion.</p>
<a class="btn sec" href="/portal/account">Back to account</a>"#;
        return (StatusCode::BAD_REQUEST, Html(page("account deletion", body))).into_response();
    }
    let subject = claims.subject.as_str();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if let Ok(owned) = st.tunnels.list_for_subject(subject) {
        for t in owned {
            let _ = st.tunnels.revoke(subject, &t.id, now);
        }
    }

    if let Ok(owned) = st.channels.channels_owned_by(subject) {
        for c in owned {
            let _ = st.channels.delete_channel(subject, &c);
        }
    }

    let _ = st.topologies.delete_all_owned_by(subject);

    if let Ok(owned) = st.networks.list(subject) {
        for id in owned {
            let _ = st.networks.delete(subject, &id);
        }
    }

    if let Ok(all) = st.pipelines.list() {
        for (id, owner) in all {
            if owner == subject {
                let _ = st.pipelines.unpublish(subject, &id);
            }
        }
    }

    if let Some(email) = claims.email.as_deref() {
        let _ = st.channels.remove_allowlist_entries_for_email(email);
        let _ = st.topologies.remove_shares_by_email(email);
    }

    let body = r#"<h1 class="deleted-check">Your account data has been deleted</h1>
<p class="help">Every tunnel, channel, topology, network and pipeline this account owned is gone,
along with your e-mail on anyone else's allow-list or share list. Your sign-in itself is
managed by Keycloak, not this page -- use <strong>Open Account Console</strong> from the account
page (while still signed in elsewhere) if you also want to remove your Keycloak login.</p>
<a class="btn" href="/portal/logout">Sign out</a>"#;
    let mut resp = Html(page("account deleted", body)).into_response();
    if let Ok(v) = axum::http::HeaderValue::from_str(&crate::portal::cleared_session_cookie()) {
        resp.headers_mut().append(axum::http::header::SET_COOKIE, v);
    }
    resp
}

/// A new tunnel from the (defense-in-depth; not linked from the UI in the
/// Standard tier — see [`tunnels_page`]) create form.
#[derive(Deserialize)]
struct CreateTunnelForm {
    name: String,
}

/// Derive a DNS-safe label from a free-form name: lowercase, alphanumeric and
/// hyphens only, collapsed/trimmed, falling back to `"tunnel"` if empty.
fn dns_label_from(name: &str) -> String {
    let mut out = String::new();
    for c in name.trim().to_ascii_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    let trimmed = if trimmed.is_empty() { "tunnel" } else { trimmed };
    trimmed.chars().take(40).collect()
}

/// A short, stable, non-choosable per-account suffix (8 hex chars / 4 bytes of
/// SHA-256(subject)) — the "unique user id" half of the Standard tier's
/// auto-assigned hostname `<name>-<user-id>.<zone>` (see the landing page's
/// subdomain-policy step and the /publish onboarding). 4 bytes (~4 billion
/// values) keeps collisions negligible at real scale — 2 bytes (65536 values)
/// was fine for a demo but not for production: the birthday paradox makes a
/// collision likely well under a thousand accounts.
fn account_suffix(subject: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(subject.as_bytes());
    hex(&digest[..4])
}

/// Standard tier: the public hostname is always auto-assigned from the tunnel
/// name + the caller's account suffix — never user-chosen. Custom/vanity
/// hostnames are a planned paid tier.
fn auto_hostname(zone: &str, name: &str, subject: &str) -> String {
    format!("{}-{}.{}", dns_label_from(name), account_suffix(subject), zone)
}

/// `GET /portal/tunnels` (#27): the caller's tunnel(s). Standard tier: exactly
/// one tunnel per account, auto-provisioned right here on first view (with an
/// auto-assigned hostname when DNS is configured) — there is no manual create
/// step to onboard with; see the tunnel's Install link for its tokens.
/// Additional tunnels and custom hostnames are a planned paid tier (shown,
/// disabled, in [`tunnels_html`]).
/// Live per-tunnel status pulled from the edge's `GET /admin/tunnel-status/:token`
/// (`crates/edge/src/admin.rs`) -- monitoring feature v1's connection flag
/// plus the byte-counter follow-up (both 2026-08-01).
#[derive(Deserialize, Clone, Copy)]
struct EdgeTunnelStatus {
    connected: bool,
    #[serde(default)]
    bytes_received: u64,
    #[serde(default)]
    bytes_sent: u64,
}

/// Monitoring feature: `routing_token_hex`'s live status, queried from the edge.
/// Best-effort like [`tunnels_page`]'s existing admission lookup: `None` when
/// `edge_admin` isn't configured or the call fails, so a transient edge/network
/// hiccup just omits the badge rather than failing the whole page. `routing_token`
/// is server-side-only (never rendered) but the edge call itself needs it in the
/// URL path, same trust boundary as every other edge-admin call this file already
/// makes.
async fn edge_tunnel_status(st: &ApiState, routing_token_hex: &str) -> Option<EdgeTunnelStatus> {
    let edge = st.edge_admin.as_ref()?;
    let endpoint = format!("{}/admin/tunnel-status/{routing_token_hex}", edge.url.trim_end_matches('/'));
    let resp = edge_admin_http_client()
        .get(&endpoint)
        .header("x-ct-admin-token", edge.token.as_ref())
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<EdgeTunnelStatus>().await.ok()
}

async fn tunnels_page(State(st): State<ApiState>, headers: HeaderMap) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    let owns_one = match st.tunnels.list_authorized_for_subject(&subject) {
        Ok(rows) => rows.iter().any(|(_, owned)| *owned),
        Err(e) => return internal_error("tunnels_page/list(owns_one)", e).into_response(),
    };
    if !owns_one {
        provision_tunnel(&st, &subject, "site").await;
    }
    match st.tunnels.list_authorized_for_subject(&subject) {
        Ok(tunnels) => {
            // #233: fetch each hostname's Rot/Gelb/Grün admission state, and
            // (monitoring v1) its live connection status, alongside its tunnel row
            // -- best-effort per-row (a lookup failure just omits that row's badge
            // rather than failing the whole page, matching this handler's existing
            // tolerance for partial data). Sequential, not concurrent: Standard tier
            // is one tunnel per account, so this is at most one extra HTTP round
            // trip per page view today.
            let mut rows = Vec::with_capacity(tunnels.len());
            for (t, owned) in tunnels {
                let admission = t
                    .hostname
                    .as_deref()
                    .and_then(|h| st.tunnels.cert_admission_for_hostname(h).ok().flatten());
                let status = edge_tunnel_status(&st, &t.routing_token).await;
                // #382-follow (Browser-Plane login gate): owner-scoped, so a shared
                // (not-owned) row simply gets the off/empty defaults -- matching the
                // existing owner-only convention for Revoke/Share above.
                let require_login = st.tunnels.require_login(&subject, &t.id).ok().flatten().unwrap_or(false);
                let login_allowlist = st.tunnels.login_allowlist_list(&subject, &t.id).ok().flatten().unwrap_or_default();
                // Self-service access requests (#382-follow, issue #18): same
                // owner-scoped, best-effort-defaults-empty convention as
                // login_allowlist above.
                let pending_requests = st.tunnels.pending_access_requests(&subject, &t.id).ok().flatten().unwrap_or_default();
                rows.push((t, owned, admission, status, require_login, login_allowlist, pending_requests));
            }
            Html(tunnels_html(&rows)).into_response()
        }
        Err(e) => internal_error("tunnels_page/list", e).into_response(),
    }
}

/// Create `name`'s tunnel for `subject` (auto-assigning its hostname when DNS
/// is configured) and run the same edge-authorize + DNS-A-record side effects
/// [`create_tunnel`] does — shared so the Standard tier's auto-provisioned
/// tunnel ([`tunnels_page`]) and a direct `POST /portal/tunnels` behave
/// identically. Errors are logged, not surfaced — a failed auto-provision
/// just leaves the tunnel list empty and the next page view retries it.
async fn provision_tunnel(st: &ApiState, subject: &str, name: &str) {
    let hostname = st
        .dns
        .as_ref()
        .map(|d| auto_hostname(d.client.domain(), name, subject))
        .as_deref()
        .and_then(ct_common::normalize_hostname);
    // The stored/displayed name is the hostname's own (already account-unique)
    // first label when one was assigned -- e.g. "site-a1b2c3d4", not the bare
    // "site" every account would otherwise show identically on its own tunnels
    // page. Falls back to the plain name when no hostname was assigned (no DNS
    // configured -- a Mesh-Plane-only tunnel has no hostname to borrow from).
    let display_name = hostname
        .as_deref()
        .and_then(|h| h.split('.').next())
        .unwrap_or(name);
    let tunnel = match st.tunnels.create(subject, display_name, hostname.as_deref()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ct-cp: auto-provisioning a tunnel for {subject} failed: {e}");
            return;
        }
    };
    authorize_hostname(st, &tunnel).await;
}

/// The edge-authorize + DNS-A-record side effects of giving a tunnel a public
/// hostname (#23 BP4b-c, #38 DL2) — best-effort, logged, never fails the
/// caller's request (the tunnel row already exists either way).
async fn authorize_hostname(st: &ApiState, tunnel: &crate::storage::SubjectTunnel) {
    let Some(host) = tunnel.hostname.as_deref() else {
        return;
    };
    // #23 BP4b-c: authorize the hostname at the edge (host -> routing token)
    // so the agent's 'H' bind is accepted under CT_EDGE_REQUIRE_HOST_AUTH.
    if let Some(edge) = &st.edge_admin {
        let endpoint = format!(
            "{}/admin/authorize-host/{}/{}",
            edge.url.trim_end_matches('/'),
            tunnel.routing_token,
            host
        );
        match edge_admin_http_client()
            .post(&endpoint)
            .header("x-ct-admin-token", edge.token.as_ref())
            .send()
            .await
        {
            // #71: log success too (not just failures), so tunnel creation's
            // auto-authorize is diagnosable from control-plane logs alone —
            // previously a success was silent and indistinguishable from the
            // edge_admin=None skip below.
            Ok(r) if r.status().is_success() => {
                eprintln!("ct-cp: edge authorize-host for {host} succeeded");
                // edge_mesh Phase 0: record that this deployment's local edge now owns
                // this (token, hostname) pair -- best-effort, never blocks the caller.
                st.edge_mesh.record(&tunnel.routing_token, Some(host));
                // #233 follow-up: promote Rot -> Gelb right now instead of waiting up
                // to a full admission-loop tick (found live testing a fresh tunnel --
                // nothing previously did this synchronously despite doc comments
                // elsewhere assuming it already happened here).
                let edge_admin_tuple = Some((edge.url.to_string(), edge.token.to_string()));
                crate::acme_broker::try_promote_rot_to_gelb(&st.tunnels, &st.edge_mesh, &edge_admin_tuple, host)
                    .await;
            }
            Ok(r) => eprintln!("ct-cp: edge authorize-host for {host} returned {}", r.status()),
            Err(e) => eprintln!("ct-cp: edge authorize-host for {host} failed: {e}"),
        }
    } else {
        // #71: the most likely silent cause — the edge admin API isn't wired, so
        // the hostname is never authorized and the agent's bind is rejected under
        // CT_EDGE_REQUIRE_HOST_AUTH. Say so loudly instead of doing nothing.
        eprintln!(
            "ct-cp: edge authorize-host SKIPPED for {host} — edge admin API not configured \
             (set CT_CP_EDGE_ADMIN_URL + CT_CP_EDGE_ADMIN_TOKEN); the agent's hostname bind \
             will be rejected while CT_EDGE_REQUIRE_HOST_AUTH is on"
        );
    }
    // #38 DL2: auto-create the A record (host -> edge IP) so the hostname is
    // publicly resolvable without a manual DNS step. Both best-effort; logged.
    if let Some(dns) = &st.dns {
        if let Err(e) = dns.client.set_a(host, &dns.edge_ip).await {
            eprintln!("ct-cp: DNS A-record create for {host} failed: {e}");
        }
    }
}

/// `POST /portal/tunnels`: kept as a server-side-enforced safety net, not
/// linked from the Standard-tier UI (which auto-provisions the one included
/// tunnel — see [`tunnels_page`]). Rejects a second tunnel even if posted
/// directly: "not enabled in the free tier" is enforced here, not just by
/// hiding the form.
async fn create_tunnel(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Form(form): Form<CreateTunnelForm>,
) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    let name = form.name.trim();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "tunnel name required").into_response();
    }
    // #214: the Standard tier's default is 1 tunnel per account, but an
    // operator can raise this for a SPECIFIC account (SqliteLedger::
    // set_max_tunnels, via POST /admin/accounts/:subject/max-tunnels) to
    // unlock self-service creation of additional subdomains -- so the gate
    // compares against that account's own limit, not a hardcoded "ever own
    // one at all".
    let owned_count = match st.tunnels.list_authorized_for_subject(&subject) {
        Ok(rows) => rows.iter().filter(|(_, owned)| *owned).count() as u32,
        Err(e) => return internal_error("create_tunnel/list(owns_one)", e).into_response(),
    };
    let max = match st.ledger.account_for_subject(&subject) {
        Ok(account) => match st.ledger.max_tunnels(&account) {
            Ok(m) => m,
            Err(e) => return internal_error("create_tunnel/max_tunnels", e).into_response(),
        },
        Err(e) => return internal_error("create_tunnel/account_for_subject", e).into_response(),
    };
    if owned_count >= max {
        return (
            StatusCode::FORBIDDEN,
            "the Standard tier includes one tunnel per account; additional tunnels are a planned paid-tier feature (or ask the operator to raise your account's limit)",
        )
            .into_response();
    }
    let hostname = st
        .dns
        .as_ref()
        .map(|d| auto_hostname(d.client.domain(), name, &subject))
        .as_deref()
        .and_then(ct_common::normalize_hostname);
    // Same reasoning as provision_tunnel: show the account-unique hostname
    // label, not the bare user-typed name two different accounts could share.
    let display_name = hostname.as_deref().and_then(|h| h.split('.').next()).unwrap_or(name);
    let tunnel = match st.tunnels.create(&subject, display_name, hostname.as_deref()) {
        Ok(t) => t,
        Err(e) => return internal_error("create_tunnel/create", e).into_response(),
    };
    authorize_hostname(&st, &tunnel).await;
    Redirect::to("/portal/tunnels").into_response()
}

/// `POST /portal/tunnels/{id}/delete` (#27): revoke one of the caller's tunnels.
/// Self-scoped: `revoke` only removes a row owned by this subject. When the edge
/// admin API is configured, the revoke is propagated so the live tunnel is torn
/// down and blocked from re-registering (#27 RB4b) — without this, "revoke" only
/// hid the tunnel while the agent kept serving.
async fn delete_tunnel(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    // #38 DL2: grab the hostname before revoke so we can clear its DNS afterward.
    let hostname = st.tunnels.tunnel_hostname(&subject, &id).ok().flatten();
    // `revoke` returns the removed tunnel's routing token (owner-scoped).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Ok(Some(routing_token)) = st.tunnels.revoke(&subject, &id, now) {
        // edge_mesh Phase 0: the tunnel row is gone either way, so its ownership
        // record must not keep claiming an edge still holds this token.
        st.edge_mesh.forget(&routing_token);
        // Auto-delete the A record so a revoked tunnel leaves no orphaned DNS.
        if let (Some(dns), Some(host)) = (&st.dns, hostname.as_deref()) {
            if let Err(e) = dns.client.clear_a(host).await {
                eprintln!("ct-cp: DNS A-record delete for {host} failed: {e}");
            }
        }
        if let Some(edge) = &st.edge_admin {
            let endpoint = format!("{}/admin/revoke/{}", edge.url.trim_end_matches('/'), routing_token);
            // Best-effort: the DB row is already gone; log if the edge call fails
            // so an operator can see a tunnel that may still be serving.
            match edge_admin_http_client()
                .post(&endpoint)
                .header("x-ct-admin-token", edge.token.as_ref())
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => {}
                Ok(r) => eprintln!("ct-cp: edge revoke for tunnel {id} returned {}", r.status()),
                // #90: the reqwest error's Display embeds the request URL, which
                // carries the routing token — redact it before logging.
                Err(e) => eprintln!(
                    "ct-cp: edge revoke for tunnel {id} failed: {}",
                    redact_routing_tokens(&e.to_string())
                ),
            }
        }
    }
    Redirect::to("/portal/tunnels").into_response()
}

/// `POST /portal/tunnels/:id/reclaim-cert-slot` (#233): the customer's
/// explicit re-request after a lapsed claim window — the only way a lapsed
/// hostname re-enters the Gelb queue (never automatic, per the admission
/// broker's design: a lapse must cost the same as starting over, at the
/// back of the queue). Owner-scoped via the existing `tunnel_hostname`
/// lookup; a no-op (redirect, no error surfaced) for a stranger's tunnel id
/// or a hostname that isn't actually `lapsed` — [`SqliteTunnelStore::reclaim_cert_slot`]
/// itself already guards both.
async fn reclaim_cert_slot(State(st): State<ApiState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    if let Some(hostname) = st.tunnels.tunnel_hostname(&subject, &id).ok().flatten() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if let Err(e) = st.tunnels.reclaim_cert_slot(&subject, &hostname, now) {
            eprintln!("ct-cp: reclaim-cert-slot for {hostname} failed: {e}");
        }
    }
    Redirect::to("/portal/tunnels").into_response()
}

/// `GET /portal/tunnels/:id/install` (#28): render the tokens (and how to use
/// them) to bring an agent up for one of the caller's own tunnels. A fresh,
/// single-use join token is minted per request and embedded via an env var.
/// The one-line installer (`/install.sh`/`/install.ps1`, #75) isn't live yet,
/// so its copy-paste blocks are deliberately not shown here for now.
///
/// The token is a secret: it is shown once to the authenticated owner and never
/// logged, cached or persisted anywhere in cleartext.
/// The Mesh-Plane tunnel rendezvous address (`host:mesh_edge_port`) a freshly
/// built `ct-agent` should point `CT_AGENT_EDGE` at — derived from the portal's
/// own public base URL (same host the edge's :443 front door and :4433 Mesh
/// Plane both serve) plus this deployment's real mesh edge port (`/network-info`,
/// [`crate::service::NetworkInfoResp`]), so the Install page never hardcodes or
/// guesses a port that could drift from the actual deployment.
pub(crate) fn edge_host_port(portal_base: &str) -> String {
    let host = portal_base
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    format!("{host}:{}", crate::service::NetworkInfoResp::from_env().mesh_edge_port)
}

async fn install_page(State(st): State<ApiState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    // Authorized = owner OR grantee (#29): a shared-with subject may also install
    // an agent for the tunnel. `None` when unknown or the caller isn't authorized.
    let routing_token = match st.tunnels.routing_token_if_authorized(&subject, &id) {
        Ok(Some(t)) => t,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such tunnel").into_response(),
        Err(e) => return internal_error("install_page/routing_token_if_authorized", e).into_response(),
    };
    // Best-effort: a Mesh-Plane-only tunnel (no DNS configured) has no
    // hostname, and this must never fail the page over that -- only the
    // env block's CT_AGENT_HOSTNAME line is affected, not the tunnel's
    // actual tokens above.
    let hostname = st.tunnels.hostname_if_authorized(&subject, &id).ok().flatten();
    // Mint a fresh single-use join token bound to the customer (subject as tenant).
    let token = match st.enrollment.issue_join_token(&TenantId(subject.clone())) {
        Ok(t) => hex(&t.0),
        Err(e) => return internal_error("install_page/issue_join_token", e).into_response(),
    };
    let edge_host = edge_host_port(&st.portal_base);
    let build_cmd = "git clone https://github.com/scimbe/CADS-Tunnel.git && cd CADS-Tunnel\ndocker run --rm -v \"$PWD\":/work -w /work rust:1-slim \\\n  cargo build --release -p ct-agent --bin ct-agent\n# binary is now at ./target/release/ct-agent -- no Rust toolchain needed on your machine";
    // Only this tunnel's own already-assigned hostname -- never a value the
    // caller supplies -- so the agent never has to copy it by hand from the
    // tunnels list, and can never accidentally (or otherwise) end up with a
    // hostname it doesn't actually own in its own .env. Omitted entirely for
    // a Mesh-Plane-only tunnel (no DNS configured, so no hostname exists).
    let hostname_line = hostname
        .as_deref()
        .map(|h| format!("\nCT_AGENT_HOSTNAME={h}   # this tunnel's own assigned hostname -- for CT_AGENT_MODE=browser and `ct-agent certificate`"))
        .unwrap_or_default();
    let env_block = format!(
        "CT_AGENT_JOIN_TOKEN={jt}\nCT_AGENT_TOKEN={rt}\nCT_AGENT_ID={id}\nCT_AGENT_CP_URL={cp}\nCT_AGENT_EDGE={edge}\nCT_AGENT_EDGE_CERT_URL={cp}{hostname_line}\nCT_AGENT_ORIGIN=127.0.0.1:8080   # <- change to your own service's host:port",
        jt = token,
        rt = routing_token,
        id = id,
        cp = st.portal_base,
        edge = edge_host,
    );
    let run_cmd = "set -a; source .env; set +a\n./target/release/ct-agent onboard";
    let body = format!(
        r#"<h1>Install an agent</h1>
<p class="help">Save this <strong>on the machine you want to expose</strong> &mdash;
the <em>origin</em>: the server or device running the service you are tunnelling,
not the device you are reading this on. The agent connects out to the relay and
serves your origin through it (no inbound firewall port needed).</p>

<h2>Save your tunnel's tokens into a <code>.env</code> file</h2>
<p class="k"><strong>Single-use join token — shown only once; reopen this Install page for a fresh one.</strong></p>
<p class="help">Minted ready to use &mdash; accepted immediately, no separate approval step. Save this
as <code>.env</code> <strong>next to the binary, on the machine you want to expose</strong>.</p>
<div class="code-block">
 <div class="code-block-head"><span>.env</span><button class="copy-btn" onclick="copyCode(this)" type="button">Copy</button></div>
 <pre><code>{env_block}</code></pre>
</div>

<details>
 <summary>How to bring your tunnel up with these tokens</summary>
 <p class="help">For doing it yourself by hand, step by step. If you'd rather have an AI agent do
 this part for you instead, use the Claude Code prompt on the
 <a href="/#get-started">landing page</a> — it downloads, builds, and runs all of this on its own.</p>
 <h3>1. Build <code>ct-agent</code> (Docker, no Rust toolchain needed)</h3>
 <div class="code-block">
  <div class="code-block-head"><span>shell</span><button class="copy-btn" onclick="copyCode(this)" type="button">Copy</button></div>
  <pre><code>{build_cmd}</code></pre>
 </div>
 <h3>2. Run it</h3>
 <div class="code-block">
  <div class="code-block-head"><span>shell</span><button class="copy-btn" onclick="copyCode(this)" type="button">Copy</button></div>
  <pre><code>{run_cmd}</code></pre>
 </div>
 <p class="help">That's it &mdash; <code>ct-agent</code> redeems the join token, binds your tunnel's
 routing token, and starts serving your origin through the relay end-to-end encrypted. A one-line
 installer is planned but not ready yet (#75). See the
 <a href="https://github.com/scimbe/CADS-Tunnel/blob/main/docs/onboarding/quickstart.md">onboarding guide</a>
 for troubleshooting.</p>
</details>

<a class="btn sec" href="/portal/tunnels">Back to tunnels</a>"#,
    );
    Html(page("install", &body)).into_response()
}

/// A subject to grant tunnel access to.
#[derive(Deserialize)]
struct GrantForm {
    grantee: String,
}

/// Map a grant-management result: `NotOwner` (or unknown tunnel) -> 404 so a
/// non-owner cannot even probe a tunnel's sharing; DB errors -> 500.
fn grant_err(e: GrantError) -> Response {
    match e {
        GrantError::NotOwner => (StatusCode::NOT_FOUND, "no such tunnel").into_response(),
        GrantError::Db(e) => internal_error("grant_err", e).into_response(),
    }
}

/// `GET /portal/tunnels/:id/grants` (#29): list the subjects a tunnel is shared
/// with + an add form. Owner-only.
async fn grants_page(State(st): State<ApiState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    match st.tunnels.list_grants(&subject, &id) {
        Ok(grantees) => Html(grants_html(&id, &grantees)).into_response(),
        Err(e) => grant_err(e),
    }
}

/// `POST /portal/tunnels/:id/grants` (#29): grant a subject access. Owner-only.
async fn add_grant(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<GrantForm>,
) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    let grantee = form.grantee.trim();
    if grantee.is_empty() {
        return (StatusCode::BAD_REQUEST, "grantee required").into_response();
    }
    match st.tunnels.grant(&subject, &id, grantee) {
        Ok(()) => Redirect::to(&format!("/portal/tunnels/{id}/grants")).into_response(),
        Err(e) => grant_err(e),
    }
}

/// `POST /portal/tunnels/:id/grants/:grantee/delete` (#29): revoke a grant. Owner-only.
async fn delete_grant(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path((id, grantee)): Path<(String, String)>,
) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    match st.tunnels.revoke_grant(&subject, &id, &grantee) {
        Ok(_) => Redirect::to(&format!("/portal/tunnels/{id}/grants")).into_response(),
        Err(e) => grant_err(e),
    }
}

fn grants_html(id: &str, grantees: &[String]) -> String {
    let rows = if grantees.is_empty() {
        "<p class=\"k\">Not shared with anyone yet.</p>".to_string()
    } else {
        grantees
            .iter()
            .map(|g| {
                format!(
                    r#"<div class="row"><span class="v">{g}</span>
 <form class="inline" method="post" action="/portal/tunnels/{id}/grants/{ge}/delete">
  <button class="sec" type="submit">Revoke</button></form></div>"#,
                    g = escape(g),
                    id = escape(id),
                    ge = escape(g),
                )
            })
            .collect::<String>()
    };
    let body = format!(
        r#"<h1>Share this tunnel</h1>
<p class="k">Grant other signed-in subjects access to this tunnel.</p>
{rows}
<h2>Add a subject</h2>
<form method="post" action="/portal/tunnels/{id}/grants">
 <input type="text" name="grantee" placeholder="subject" required>
 <button type="submit">Grant</button>
</form>
<a class="btn sec" href="/portal/tunnels">Back to tunnels</a>"#,
        id = escape(id),
    );
    page("share tunnel", &body)
}

/// Rot/Gelb/Grün status badge + (when applicable) the persistent private-key
/// disclosure and queue/claim details for one tunnel's row (#233). Returns
/// an empty string for a Mesh-Plane-only tunnel (no hostname, so no
/// admission state at all) — nothing new to show, today's row is unaffected.
fn cert_tier_html(id: &str, admission: &crate::storage::CertAdmission) -> String {
    match admission.status.as_str() {
        // Deliberately does not repeat the phrase "privaten Schlüssel" here (even
        // to reassure) -- it must appear ONLY in the Gelb warning, so a customer
        // (or a test) scanning for that exact phrase gets an unambiguous signal
        // of which tier they are actually in.
        // Grün is the settled, final state -- its dot is solid, not pulsing (nothing
        // left in flux). Rot/Gelb are both transitional (still being set up, or
        // time-limited), so their dot pulses -- same "pulse means still in motion"
        // rule as the connection-status dot in `page()`.
        "gruen" => r#"<div class="tier tier-gruen"><i class="tier-dot"></i>Grün &mdash; eigenes, vollständig eigenständiges
 Zertifikat aktiv.</div>"#
            .to_string(),
        "rot" => {
            r#"<div class="tier tier-rot"><i class="tier-dot pulse"></i>Rot &mdash; Ihre Subdomain wird gerade eingerichtet.</div>"#
                .to_string()
        }
        _ /* gelb */ => {
            let disclosure = r#"<p class="help">Solange <strong>Gelb</strong> aktiv ist, wird Ihre Subdomain
 über ein gemeinsam genutztes Zertifikat ausgeliefert &mdash; der Betreiber besitzt in dieser Phase
 auch den privaten Schlüssel dieses Zertifikats. Sobald Ihr eigenes Zertifikat ausgestellt ist
 (Status Grün), gilt das nicht mehr.</p>"#;
            match admission.claim_state.as_str() {
                "offered" => {
                    let deadline_note = match admission.claim_deadline {
                        Some(d) => {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|dur| dur.as_secs() as i64)
                                .unwrap_or(0);
                            let hours_left = ((d - now).max(0)) / 3600;
                            format!(" &mdash; noch ca. {hours_left}h Zeit, das eigene Zertifikat zu erhalten")
                        }
                        None => String::new(),
                    };
                    format!(
                        r#"<div class="tier tier-gelb"><i class="tier-dot pulse"></i>Gelb &mdash; Sie sind an der Reihe{deadline_note}.</div>{disclosure}"#
                    )
                }
                "lapsed" => format!(
                    r#"<div class="tier tier-gelb"><i class="tier-dot pulse"></i>Gelb &mdash; die Frist ist abgelaufen.</div>{disclosure}
<form class="inline" method="post" action="/portal/tunnels/{id}/reclaim-cert-slot">
 <button class="sec" type="submit">Erneut anfragen</button></form>"#
                ),
                _ => {
                    let position_note = match admission.queue_position {
                        Some(p) => format!(" &mdash; Warteschlangenposition {}", p + 1),
                        None => String::new(),
                    };
                    format!(
                        r#"<div class="tier tier-gelb"><i class="tier-dot pulse"></i>Gelb &mdash; bereits erreichbar{position_note}.</div>{disclosure}"#
                    )
                }
            }
        }
    }
}

/// Render a byte count the way a tunnel owner reads it -- `0 B`/`512 B`/`3.4 KB`/
/// `1.2 GB`, one decimal past the first three-digit boundary, never more.
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Browser-Plane login gate section (#382-follow): a checkbox to require a
/// Keycloak login (checked against this tunnel's own email allow-list) before
/// its public content is served, and -- while enabled -- the allow-list itself
/// with add/remove forms. Owner-scoped by construction: only called for owned
/// rows (see `tunnels_html`).
fn login_gate_html(id: &str, require_login: bool, login_allowlist: &[String], pending_requests: &[(String, String, i64)]) -> String {
    let checked = if require_login { " checked" } else { "" };
    let allowlist_section = if require_login {
        let items = login_allowlist
            .iter()
            .map(|email| {
                let email = escape(email);
                format!(
                    r#"<li>{email} <form class="inline fade-out-submit" method="post" action="/portal/tunnels/{id}/login-allowlist/{email}/remove">
 <button class="sec" type="submit">Remove</button></form></li>"#
                )
            })
            .collect::<String>();
        let empty_note = if login_allowlist.is_empty() {
            r#"<p class="k">No one is allowed in yet -- add an email below.</p>"#
        } else {
            ""
        };
        // Self-service access requests (#382-follow, issue #18): a visitor who
        // hit the gate's own "not on the access list" page can now leave a
        // real request instead of a dead end -- surfaced here, right next to
        // the allow-list it's asking to join, with one click to grant it
        // (reuses the exact same add-to-allowlist form/route the manual entry
        // below already posts to) or dismiss it.
        let requests_section = if pending_requests.is_empty() {
            String::new()
        } else {
            let items = pending_requests
                .iter()
                .map(|(email, note, _requested_at)| {
                    let email_esc = escape(email);
                    let note_html = if note.is_empty() {
                        String::new()
                    } else {
                        format!(r#" <span class="k">&mdash; {}</span>"#, escape(note))
                    };
                    format!(
                        r#"<li>{email_esc}{note_html}
 <form class="inline" method="post" action="/portal/tunnels/{id}/login-allowlist">
  <input type="hidden" name="email" value="{email_esc}">
  <button class="sec" type="submit">Grant</button></form>
 <form class="inline fade-out-submit" method="post" action="/portal/tunnels/{id}/access-requests/{email_esc}/dismiss">
  <button class="sec" type="submit">Dismiss</button></form></li>"#
                    )
                })
                .collect::<String>();
            format!(r#"<div class="row"><p class="k">Pending access requests:</p><ul class="login-allowlist">{items}</ul></div>"#)
        };
        format!(
            r#"<div class="row"><ul class="login-allowlist">{items}</ul>{empty_note}
<form class="inline" method="post" action="/portal/tunnels/{id}/login-allowlist">
 <input type="email" name="email" placeholder="invite@example.com" required>
 <button class="sec" type="submit">Add to access list</button>
</form></div>{requests_section}"#
        )
    } else {
        String::new()
    };
    format!(
        r#"<div class="row"><form class="inline" method="post" action="/portal/tunnels/{id}/require-login">
 <label><input type="checkbox" name="enabled" value="1"{checked}> Require login to access this tunnel</label>
 <button class="sec" type="submit">Update</button>
</form></div>{allowlist_section}"#
    )
}

/// One row of `GET /portal/tunnels`: the tunnel itself, whether the caller owns
/// it, its cert-admission tier, live connection status, and (owner-only) its
/// Browser-Plane login-gate state -- whether it's required, the allow-list, and
/// any pending self-service access requests (#382-follow, issue #18). Named
/// (clippy's `type_complexity`, found running clippy across the whole crate for
/// this same change) rather than left as an inline 7-tuple.
type TunnelRow = (
    crate::storage::SubjectTunnel,
    bool,
    Option<crate::storage::CertAdmission>,
    Option<EdgeTunnelStatus>,
    bool,
    Vec<String>,
    Vec<(String, String, i64)>,
);

fn tunnels_html(tunnels: &[TunnelRow]) -> String {
    let rows = tunnels
        .iter()
        .map(|(t, owned, admission, status, require_login, login_allowlist, pending_requests)| {
            let host = t
                .hostname
                .as_deref()
                .map(|h| format!(" · <code>{}</code>", escape(h)))
                .unwrap_or_default();
            let id = escape(&t.id);
            // Owner-only actions are hidden on shared tunnels; an authorized
            // grantee can still install an agent for it. Sharing itself is a
            // planned paid-tier feature — shown so owners know it exists, but
            // disabled (Standard tier ships one tunnel, not shared access).
            //
            // Share used to be a bare <span class="btn sec disabled">: the
            // page's own CSS only ever styles `a.btn`/`button` (never a plain
            // `.btn` class alone), so it rendered with none of Install/Revoke's
            // padding, background, or border -- three actions meant to read as
            // one button group instead looked visibly misaligned. A real
            // disabled <button> picks up the page's existing `button:disabled`
            // rule for free and needs no new CSS.
            let owner_actions = if *owned {
                format!(
                    r#"<div class="actions">
 <a class="btn sec" href="/portal/tunnels/{id}/install">Install</a>
 <button type="button" class="btn sec" disabled title="Sharing tunnels is a planned paid-tier feature">Share</button>
 <form class="inline fade-out-submit" method="post" action="/portal/tunnels/{id}/delete">
  <button class="btn danger" type="submit">Revoke</button></form>
</div>"#
                )
            } else {
                format!(
                    r#"<div class="actions">
 <a class="btn sec" href="/portal/tunnels/{id}/install">Install</a>
 <span class="k">(shared with you)</span>
</div>"#
                )
            };
            let tier = admission.as_ref().map(|a| cert_tier_html(&id, a)).unwrap_or_default();
            // Monitoring feature: live connection status + byte counters, best-effort
            // -- absent (edge unreachable, or CT_CP_EDGE_ADMIN_URL not configured)
            // renders nothing rather than a misleading "offline"/"0 B".
            let status_badge = match status {
                Some(s) if s.connected => r#" <span class="tier"><i class="status-dot live"></i>Connected</span>"#.to_string(),
                Some(_) => r#" <span class="tier"><i class="status-dot off"></i>Not connected</span>"#.to_string(),
                None => String::new(),
            };
            let bytes_line = match status {
                Some(s) if s.bytes_received > 0 || s.bytes_sent > 0 => format!(
                    r#"<div class="row"><span class="k">↓ {} received · ↑ {} sent</span></div>"#,
                    human_bytes(s.bytes_received),
                    human_bytes(s.bytes_sent),
                ),
                _ => String::new(),
            };
            // Browser-Plane login gate (#382-follow): owner-only, and only shown for
            // a tunnel that actually has public content to protect (a hostname).
            let login_gate = if *owned && t.hostname.is_some() {
                login_gate_html(&id, *require_login, login_allowlist, pending_requests)
            } else {
                String::new()
            };
            format!(
                r#"<div class="tunnel-card">
<div class="row"><span class="v">{name}{host}{status_badge}</span></div>
{owner_actions}{bytes_line}{tier}{login_gate}
</div>"#,
                name = escape(&t.name),
            )
        })
        .collect::<String>();
    let body = format!(
        r#"<h1>Your tunnels</h1>
{rows}
<p class="help">Included in every tier: <strong>one</strong> tunnel with an automatically
assigned hostname (e.g. <code>site-a1b2c3d4.bunsenbrenner.org</code>) &mdash; already set up for
you above, nothing to configure. Click <strong>Install</strong> to get its tokens.</p>
<h2>Create another tunnel</h2>
<p class="help">Additional tunnels and custom/vanity hostnames are a planned paid tier, coming
later.</p>
<form aria-disabled="true">
 <label>Name
  <input type="text" placeholder="e.g. my-api" disabled>
 </label>
 <button type="submit" disabled>Create</button>
</form>
<h2>Next steps</h2>
<ol class="steps">
 <li>Click <strong>Install</strong> on your tunnel above to get its tokens.</li>
 <li>Run the shown command <strong>on the machine you want to expose</strong> (the
 <em>origin</em> &mdash; e.g. your server or laptop running the service), not on
 the device you are browsing from.</li>
 <li>Done &mdash; requests reach your origin through the relay, end-to-end
 encrypted; the operator never sees your payload.</li>
</ol>"#,
    );
    page("your tunnels", &body)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Redact routing-token-shaped substrings (#90): a routing token is a 32-byte
/// value rendered as 64 lowercase-hex chars, and it appears in the edge-revoke URL
/// path — so a `reqwest` error's `Display` (which embeds the request URL) would leak
/// it into control-plane logs. Replace any maximal run of ≥64 lowercase-hex chars
/// with a marker before logging, so the secret never reaches the log regardless of
/// where in the error chain the URL surfaces.
fn redact_routing_tokens(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.len() >= 64 {
            out.push_str("<redacted-token>");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in s.chars() {
        if matches!(c, '0'..='9' | 'a'..='f') {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

/// Shared page chrome: dark card layout, a title and body. `body` is trusted
/// (built from escaped parts by the caller).
///
/// Brand tokens match the landing page (bunsenbrenner.org's own hero/nav) --
/// see docs/design/tokens.md. #337's own pass unified this page, the Keycloak
/// login form, and the account console to EACH OTHER, but never cross-checked
/// against the landing page's actual established identity (warm orange
/// `--accent`, teal `--accent2`, serif headings, the pulsing live-dot motif) --
/// so the "unified" result was still just generic dark-mode blue/green,
/// disconnected from the one surface with a real brand. Fixed here.
pub(crate) fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CADS-Tunnel — {title}</title>
<style>
 :root{{--bg:#0e1116;--panel:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;
       --accent:#d98a4f;--accent-hover:#e39a63;--accent-ink:#20130a;
       --accent2:#5fb8ab;--accent2-hover:#7cc9bd;
       --serif:ui-serif,Georgia,"Iowan Old Style","Palatino Linotype",serif}}
 body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;margin:0;background:var(--bg);color:var(--text);
      display:flex;min-height:100vh;align-items:flex-start;justify-content:center;padding:3rem 1rem}}
 .card{{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:2rem;max-width:640px;width:100%;
      animation:cardIn .32s ease-out}}
 @keyframes cardIn{{from{{opacity:0;transform:translateY(6px)}}to{{opacity:1;transform:translateY(0)}}}}
 @keyframes checkIn{{0%{{opacity:0;transform:scale(.85)}}60%{{opacity:1;transform:scale(1.03)}}100%{{transform:scale(1)}}}}
 @keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.35}}}}
 h1,h2{{font-family:var(--serif);font-weight:600;letter-spacing:-.01em}}
 h1{{font-size:1.55rem;margin:.1rem 0 1.1rem}} h2{{font-size:1.05rem;color:var(--muted);margin:1.5rem 0 .6rem}}
 .row{{display:flex;flex-wrap:wrap;justify-content:space-between;gap:.25rem 1rem;padding:.5rem 0;border-bottom:1px solid #21262d;
      transition:background .15s ease;animation:rowIn .28s ease-out backwards}}
 .row:hover{{background:#1c222b}}
 @keyframes rowIn{{from{{opacity:0;transform:translateX(-4px)}}to{{opacity:1;transform:translateX(0)}}}}
 /* A light stagger across the first several rows reads as a deliberate reveal
    rather than the whole list popping in at once -- capped so a long tunnel
    list doesn't end with a visibly-delayed tail. */
 .row:nth-child(1){{animation-delay:0ms}} .row:nth-child(2){{animation-delay:30ms}}
 .row:nth-child(3){{animation-delay:60ms}} .row:nth-child(4){{animation-delay:90ms}}
 .row:nth-child(n+5){{animation-delay:120ms}}
 .k{{color:var(--muted);flex-shrink:0}} .v{{word-break:break-all;min-width:0}}
 nav a{{color:var(--accent2);text-decoration:none;margin-right:1rem;font-size:.9rem;transition:color .15s ease}}
 nav a:hover{{color:var(--accent2-hover)}} nav{{margin-bottom:1.2rem}}
 a.btn,button{{background:var(--accent);color:var(--accent-ink);border:0;border-radius:8px;padding:.5rem 1rem;
      font:inherit;font-weight:600;cursor:pointer;text-decoration:none;display:inline-block;position:relative;overflow:hidden;
      transition:background .15s ease,transform .08s ease,opacity .15s ease,box-shadow .2s ease}}
 a.btn:hover,button:hover{{background:var(--accent-hover)}} a.btn:active,button:active{{transform:scale(.96)}}
 a.btn:focus-visible,button:focus-visible{{outline:none;box-shadow:0 0 0 3px rgba(217,138,79,.35)}}
 /* A quick diagonal shine sweep on the primary CTA only -- one small, tasteful
    flourish rather than motion everywhere; skipped entirely for .sec/.danger
    so secondary actions stay visually quiet. */
 a.btn::before,button::before{{content:"";position:absolute;inset:0;
      background:linear-gradient(115deg,transparent 20%,rgba(255,255,255,.35) 45%,transparent 70%);
      transform:translateX(-120%);transition:transform .5s ease}}
 a.btn:hover::before,button:hover::before{{transform:translateX(120%)}}
 a.btn.sec::before,button.sec::before,a.btn.danger::before,button.danger::before{{display:none}}
 a.btn.sec,button.sec{{background:#21262d;border:1px solid var(--border);color:var(--text);font-weight:500}}
 a.btn.sec:hover,button.sec:hover{{background:#30363d}}
 a.btn.danger,button.danger{{background:#3d1418;border:1px solid #6e2530;color:#ff9a9a}}
 a.btn.danger:hover,button.danger:hover{{background:#5a1c22}}
 .deleted-check{{animation:checkIn .45s ease-out}}
 /* The connection-status indicator (was a raw 🟢/⚪ emoji before this pass) --
    same pulsing-dot motif the landing page uses for its own "live" markers. A
    dead/idle tunnel doesn't pulse (no activity to signal); a live one does. */
 .status-dot{{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:.45rem;vertical-align:middle}}
 .status-dot.live{{background:var(--accent2);animation:pulse 1.6s ease-in-out infinite}}
 .status-dot.off{{background:var(--muted)}}
 /* Each tunnel is its own self-contained card, not just another row in one
    long flat list -- previously every tunnel's rows (including its OWN
    access list, when "Require login" is on) ran together with nothing but a
    faint row divider between them, which read as one shared list across all
    tunnels rather than each tunnel owning its own (it never was shared --
    login_allowlist_list is already scoped per tunnel id -- the bug was purely
    that the boundary between tunnels wasn't visible). */
 .tunnel-card{{border:1px solid var(--border);border-radius:10px;padding:.2rem 1rem;margin:0 0 1rem;
      background:#131820;max-height:640px;animation:cardIn .3s ease-out backwards;
      transition:opacity .2s ease,transform .2s ease,max-height .25s ease,margin .25s ease,padding .25s ease}}
 .tunnel-card:nth-of-type(1){{animation-delay:0ms}} .tunnel-card:nth-of-type(2){{animation-delay:50ms}}
 .tunnel-card:nth-of-type(3){{animation-delay:100ms}} .tunnel-card:nth-of-type(n+4){{animation-delay:150ms}}
 .tunnel-card .row:last-child{{border-bottom:0}}
 .tunnel-card .actions{{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;padding:.6rem 0}}
 /* Progressive enhancement: a form with this class fades/collapses its
    ancestor .tunnel-card or <li> out before letting the (unmodified) POST
    proceed -- see the script at the bottom of `page()`. Without JS the form
    just submits immediately, same as before. */
 .leaving{{opacity:0!important;transform:translateX(8px) scale(.98)!important;max-height:0!important;
      padding-top:0!important;padding-bottom:0!important;margin:0!important;overflow:hidden;pointer-events:none}}
 .login-allowlist li{{animation:rowIn .22s ease-out backwards;max-height:60px;
      transition:opacity .2s ease,transform .2s ease,max-height .2s ease,padding .2s ease,margin .2s ease}}
 .login-allowlist li:nth-child(1){{animation-delay:0ms}} .login-allowlist li:nth-child(2){{animation-delay:25ms}}
 .login-allowlist li:nth-child(n+3){{animation-delay:50ms}}
 @media (prefers-reduced-motion: reduce){{ *{{animation:none!important;transition:none!important}} }}
 input,select{{background:#0d1117;border:1px solid var(--border);color:var(--text);border-radius:8px;padding:.5rem;font:inherit;
      transition:border-color .15s ease}}
 input:focus,select:focus{{outline:none;border-color:var(--accent2)}}
 code{{background:#0d1117;border:1px solid var(--border);border-radius:6px;padding:.15rem .4rem}}
 form.inline{{display:inline}}
 label{{display:block;margin:.85rem 0;font-size:.9rem}}
 label input{{display:block;margin-top:.3rem;width:100%;max-width:360px}}
 .help{{color:#8b949e;font-size:.82rem;display:block}} label .help{{margin-top:.35rem}}
 p.help{{margin:.2rem 0 1rem}} .opt{{color:#8b949e;font-weight:400}}
 ol.steps{{color:#8b949e;font-size:.86rem;margin:.2rem 0;padding-left:1.2rem}}
 ol.steps li{{margin:.35rem 0}} ol.steps strong{{color:#e6edf3}}
 .warn{{background:#3d1e00;border:1px solid #7d4e00;color:#f0c674;border-radius:8px;padding:.7rem .9rem;margin:1rem 0;font-size:.88rem;line-height:1.6}}
 .tier{{font-size:.85rem;margin:.2rem 0 .1rem}} .tier-rot{{color:#f85149}} .tier-gelb{{color:#f0c674}} .tier-gruen{{color:#3fb950}}
 .tier-dot{{display:inline-block;width:7px;height:7px;border-radius:50%;background:currentColor;margin-right:.45rem;vertical-align:middle}}
 .tier-dot.pulse{{animation:pulse 1.6s ease-in-out infinite}}
 .warn code{{background:#2a1500;border-color:#7d4e00}} h2.muted{{color:#6e7681}}
 .btn.disabled,button:disabled,input:disabled{{opacity:.45;cursor:not-allowed;pointer-events:none}}
 .code-block{{margin:.6rem 0 1rem;border:1px solid #30363d;border-radius:8px;overflow:hidden;background:#0d1117}}
 .code-block-head{{display:flex;justify-content:space-between;align-items:center;gap:.8rem;background:#161b22;
  padding:.45rem .5rem .45rem .8rem;border-bottom:1px solid #30363d}}
 .code-block-head span{{font-size:.78rem;color:#8b949e}}
 .code-block pre{{margin:0;padding:.8rem .9rem;overflow-x:auto}}
 .code-block code{{background:none;border:none;padding:0}}
 .copy-btn{{background:#21262d;border:1px solid #30363d;color:#e6edf3;flex-shrink:0;border-radius:6px;
  padding:.3rem .65rem;font-size:.76rem;font-weight:600;cursor:pointer}}
 .copy-btn:hover{{background:#30363d}}
 details{{margin:1.1rem 0;border:1px solid #30363d;border-radius:8px;padding:.7rem .9rem}}
 summary{{cursor:pointer;color:#58a6ff;font-weight:600}}
 summary:hover{{color:#79c0ff}}
 details h3{{font-size:.95rem;color:#e6edf3;margin:1rem 0 .4rem}}
 details[open] summary{{margin-bottom:.4rem}}
</style></head><body>
<div class="card">
<nav><a href="/portal/account">Account</a><a href="/portal/tunnels">Tunnels</a><a href="/portal/channels">Channels</a><a href="/portal/topologies">Topologies</a><a href="/portal/logout">Sign out</a></nav>
{body}
</div>
<script>
 function copyCode(btn){{
  const code = btn.closest('.code-block').querySelector('code');
  const text = code ? code.textContent : '';
  const done = () => {{ const orig = btn.textContent; btn.textContent = 'Copied'; setTimeout(()=>{{ btn.textContent = orig; }}, 1600); }};
  if(navigator.clipboard && navigator.clipboard.writeText){{ navigator.clipboard.writeText(text).then(done).catch(()=>{{}}); }}
 }}
 // Progressive enhancement for any `form.fade-out-submit` (tunnel Revoke,
 // login-allowlist Remove): fade/collapse the enclosing .tunnel-card or <li>
 // out before letting the real (unmodified) POST proceed, instead of the row
 // just vanishing on the next full-page reload. Without JS, or with reduced
 // motion requested, the form submits immediately -- nothing here is load-bearing.
 document.addEventListener('submit', function(ev){{
  var form = ev.target;
  if(!form.classList || !form.classList.contains('fade-out-submit')){{ return; }}
  if(window.matchMedia('(prefers-reduced-motion: reduce)').matches){{ return; }}
  // Most-specific ancestor first: a login-allowlist Remove form sits inside a
  // <li> that is itself inside the tunnel's own .tunnel-card -- closest('li')
  // must win so removing one email only fades that one list item, not the
  // whole tunnel card it happens to live inside.
  var target = form.closest('li') || form.closest('.tunnel-card') || form;
  if(target.classList.contains('leaving')){{ return; }}
  ev.preventDefault();
  target.classList.add('leaving');
  setTimeout(function(){{ form.submit(); }}, 220);
 }});
</script>
</body></html>"#
    )
}

fn account_html(subject: &str, account_hex: &str, balance: u64, account_console_url: Option<&str>) -> String {
    // Password change, active sessions, and 2FA (TOTP) live in Keycloak's own
    // Account Console -- correct, since those are identity concerns Keycloak
    // already handles well; not reimplemented here. Account deletion is split the
    // same way: this page's own "Danger zone" removes every CADS-Tunnel-side
    // resource the account owns (tunnels/channels/topologies/networks/pipelines --
    // Keycloak has no idea any of that exists), while the Account Console link
    // remains how a caller removes the Keycloak login itself. Omitted (not a dead
    // link) when OIDC isn't configured.
    let manage_section = match account_console_url {
        Some(url) => format!(
            r#"<h2>Manage your sign-in</h2>
<p class="help">Change your password, set up two-factor authentication, or review active
sessions -- all handled by your identity provider, not by CADS-Tunnel itself.</p>
<a class="btn sec" href="{url}" target="_blank" rel="noopener">Open Account Console &rarr;</a>"#,
            url = escape(url)
        ),
        None => String::new(),
    };
    let danger_kc_note = if account_console_url.is_some() {
        " Your Keycloak sign-in itself is untouched; use Account Console above if you also want to remove that."
    } else {
        ""
    };
    let body = format!(
        r#"<h1>Your account</h1>
<div class="row"><span class="k">Subject</span><span class="v">{subject}</span></div>
<div class="row"><span class="k">Account&nbsp;ID</span><span class="v">{account}</span></div>
<div class="row"><span class="k">Credit&nbsp;balance</span><span class="v">{balance}</span></div>
<h2>Buy credits</h2>
<form method="post" action="/portal/account/credits">
 <input type="number" name="credits" min="1" value="100" required>
 <button type="submit">Create payment intent</button>
</form>
{manage_section}
{service_accounts_section}
<h2>Danger zone</h2>
<p class="help">Permanently deletes every tunnel, channel, topology (including ones shared with
you), declarative network and published pipeline this account owns -- credits are forfeited, and
this cannot be undone.{danger_kc_note}</p>
<form method="post" action="/portal/account/delete" id="deleteAccountForm">
 <label>Type <code>DELETE</code> to confirm
  <input type="text" name="confirm" id="confirmDelete" autocomplete="off" placeholder="DELETE" required pattern="DELETE" title="Type DELETE exactly, in capitals">
 </label>
 <button type="submit" class="danger">Delete account and all data</button>
</form>
<script>
 document.getElementById('deleteAccountForm').addEventListener('submit', function(ev){{
  if(!window.confirm('This permanently deletes all CADS-Tunnel data for this account. Continue?')){{ ev.preventDefault(); }}
 }});
</script>"#,
        subject = escape(subject),
        account = escape(account_hex),
        balance = balance,
        manage_section = manage_section,
        service_accounts_section = service_accounts_section_html(),
        danger_kc_note = danger_kc_note,
    );
    page("your account", &body)
}

/// Real self-service M2M credentials (2026-08-04): a fetch()-driven section on
/// the account page, same pattern as `topologies_html`'s own client-side shell
/// -- all actual data access goes through the already dual-authed
/// `/me/service-accounts*` API (`subject_of_topology`, service.rs), this is
/// purely the shell. A freshly created or rotated secret is shown exactly
/// once, inline, with an explicit "copy it now" warning -- `GET
/// /me/service-accounts` itself never carries a secret, so there is no second
/// chance to view it here or anywhere else.
fn service_accounts_section_html() -> &'static str {
    r#"<h2>Service accounts (API credentials)</h2>
<p class="help">Machine-to-machine credentials for your own bots/bridges/integrations --
authenticate as <code>client_id</code> + <code>client_secret</code>
(<code>grant_type=client_credentials</code>) instead of a browser session. Each one is its
own, separate identity: it can only ever access/own what it itself creates, never your
existing tunnels/channels or anyone else's data.</p>
<div id="sa-secret-box" class="help" style="display:none"></div>
<form id="sa-create-form" class="inline">
 <input type="text" id="sa-name" placeholder="e.g. webconference bridge" required maxlength="200">
 <button type="submit">Create service account</button>
</form>
<span id="sa-msg" class="help"></span>
<div id="sa-list" class="help">Loading…</div>
<script>
(function(){
 var list=document.getElementById('sa-list'),msg=document.getElementById('sa-msg'),secretBox=document.getElementById('sa-secret-box');
 function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;');}
 function say(t){if(msg)msg.textContent=t;}
 function showSecret(clientId,secret){
  secretBox.style.display='block';
  secretBox.innerHTML='<strong>Copy this secret now -- it will not be shown again:</strong>'
   +'<div class="row"><span class="k">client_id</span><span class="v"><code>'+esc(clientId)+'</code></span></div>'
   +'<div class="row"><span class="k">client_secret</span><span class="v"><code>'+esc(secret)+'</code></span></div>';
 }
 function rows(items){
  return items.map(function(sa){
   return '<div class="row"><span class="v">'+esc(sa.name)+' <code>'+esc(sa.client_id)+'</code></span>'
        + '<span><button type="button" class="btn sec" data-rotate="'+esc(sa.client_id)+'">Rotate</button> '
        + '<button type="button" class="btn danger" data-revoke="'+esc(sa.client_id)+'">Revoke</button></span></div>';
  }).join('');
 }
 function load(){
  fetch('/me/service-accounts').then(function(r){return r.ok?r.json():Promise.reject(r.status);})
   .then(function(items){
    list.innerHTML=items.length?rows(items):'<p class="help">No service accounts yet.</p>';
    Array.prototype.forEach.call(list.querySelectorAll('[data-rotate]'),function(b){
     b.addEventListener('click',function(){
      if(!window.confirm('Rotate the secret for '+b.getAttribute('data-rotate')+'? The old secret stops working immediately.'))return;
      say('rotating…');
      fetch('/me/service-accounts/'+encodeURIComponent(b.getAttribute('data-rotate'))+'/rotate',{method:'POST'})
       .then(function(r){return r.ok?r.json():Promise.reject(r.status);})
       .then(function(res){say('');showSecret(b.getAttribute('data-rotate'),res.secret);})
       .catch(function(s){say('rotate failed ('+s+')');});
     });
    });
    Array.prototype.forEach.call(list.querySelectorAll('[data-revoke]'),function(b){
     b.addEventListener('click',function(){
      if(!window.confirm('Revoke '+b.getAttribute('data-revoke')+'? This deletes the real credential immediately and cannot be undone.'))return;
      say('revoking…');
      fetch('/me/service-accounts/'+encodeURIComponent(b.getAttribute('data-revoke')),{method:'DELETE'})
       .then(function(r){if(!r.ok)return Promise.reject(r.status);say('');load();})
       .catch(function(s){say('revoke failed ('+s+')');});
     });
    });
   })
   .catch(function(s){list.textContent='';say('could not load service accounts ('+s+')');});
 }
 load();
 var form=document.getElementById('sa-create-form');
 form.addEventListener('submit',function(ev){
  ev.preventDefault();
  var name=document.getElementById('sa-name').value.trim();
  if(!name)return;
  say('creating…');
  fetch('/me/service-accounts',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:name})})
   .then(function(r){return r.ok?r.json():Promise.reject(r.status);})
   .then(function(res){say('');document.getElementById('sa-name').value='';showSecret(res.client_id,res.secret);load();})
   .catch(function(s){say('create failed ('+s+')');});
 });
})();
</script>"#
}

/// Shared state for the self-service channel-allowlist **claim** route (#248-follow):
/// just the session key + the channel store, kept deliberately separate from the
/// much larger [`ApiState`] so this addition doesn't have to thread a new param
/// through every existing `portal_api_router` call site.
#[derive(Clone)]
struct ClaimState {
    session_key: Arc<[u8]>,
    channels: Arc<crate::storage::SqliteChannelStore>,
}

/// Build the channel-allowlist claim router (#248-follow): a `GET`/`POST` page for
/// people to self-serve their claim from a browser, plus the pre-existing `POST
/// .../claim` JSON API for programmatic callers, session-cookie authed either way.
/// Mount alongside [`portal_api_router`] wherever the channel store is already in scope.
pub fn channel_claim_router(session_key: &[u8], channels: Arc<crate::storage::SqliteChannelStore>) -> Router {
    Router::new()
        .route("/portal/channels", get(channels_page))
        .route("/portal/channels/:channel/claim", get(claim_page).post(claim_channel))
        .route("/portal/channels/:channel/claim-form", post(claim_page_submit))
        .with_state(ClaimState {
            session_key: Arc::from(session_key.to_vec()),
            channels,
        })
}

/// Shared state for the Topology Editor's portal discoverability shell (#237-follow):
/// just the session key, so this can gate access without needing the topology store
/// directly -- the actual listing/creation happens client-side against the already
/// session-cookie-authed `/me/topologies*` API (`subject_of_topology`, service.rs),
/// keeping topology data access in exactly one place.
#[derive(Clone)]
struct TopologyPortalState {
    session_key: Arc<[u8]>,
}

/// Build the Topology Editor's portal-discoverability router (#237-follow): before this,
/// the Topology Editor (`GET /me/topologies/:id/editor`, a real draggable SVG node-graph
/// editor, #107-ui) existed and worked, but nothing in the portal a real logged-in user
/// browses ever linked to it, and it required a bearer token no portal session carries --
/// from an actual user's perspective it was simply "not there." `/portal/topologies` is a
/// thin, session-gated shell; the listing and "create new" action are plain client-side
/// `fetch()` calls against `/me/topologies` (now dual-auth: portal session cookie OR
/// bearer token, see `subject_of_topology`), which the browser's ambient session cookie
/// satisfies with zero extra plumbing.
pub fn topology_portal_router(session_key: &[u8]) -> Router {
    Router::new()
        .route("/portal/topologies", get(topologies_page))
        .with_state(TopologyPortalState { session_key: Arc::from(session_key.to_vec()) })
}

/// Shared state for the Browser-Plane login-gate's owner-scoped management
/// routes (#382-follow): toggle the gate + manage its email allow-list. Kept
/// separate from `ApiState` (not folded into `portal_api_router`) so this
/// genuinely new, still-settling feature doesn't widen that struct (and its
/// many existing test call sites) for what is otherwise an independent concern
/// -- same rationale as `ClaimState`/`TopologyPortalState` above.
#[derive(Clone)]
struct LoginGateState {
    session_key: Arc<[u8]>,
    tunnels: Arc<crate::storage::SqliteTunnelStore>,
    /// `None` disables Keycloak account auto-provisioning: the allow-list entry
    /// is still recorded, but the invitee needs an already-existing Keycloak
    /// account to actually sign in (matches this crate's "off unless configured"
    /// convention -- see `EdgeAdmin`/`DnsAutopilot` above for the same shape).
    kc_admin: Option<crate::keycloak_admin::KeycloakAdminConfig>,
}

/// Build the Browser-Plane login-gate's owner-scoped management router
/// (#382-follow): `POST /portal/tunnels/:id/require-login` (toggle),
/// `POST /portal/tunnels/:id/login-allowlist` (add + auto-provision),
/// `POST /portal/tunnels/:id/login-allowlist/:email/remove`. Mount alongside
/// `portal_api_router` wherever the tunnel store is already in scope -- the
/// actual gate (`GET /gate/*`) lives in `crate::gate`, fronting each demo's own
/// Caddy via `forward_auth`; this router is only the owner-facing settings UI.
pub fn login_gate_portal_router(
    session_key: &[u8],
    tunnels: Arc<crate::storage::SqliteTunnelStore>,
    kc_admin: Option<crate::keycloak_admin::KeycloakAdminConfig>,
) -> Router {
    Router::new()
        .route("/portal/tunnels/:id/require-login", post(set_require_login_route))
        .route(
            "/portal/tunnels/:id/login-allowlist",
            post(login_allowlist_add_route).get(login_allowlist_list_route),
        )
        .route("/portal/tunnels/:id/login-allowlist/:email/remove", post(login_allowlist_remove_route))
        .route("/portal/tunnels/:id/access-requests/:email/dismiss", post(access_request_dismiss_route))
        .with_state(LoginGateState {
            session_key: Arc::from(session_key.to_vec()),
            tunnels,
            kc_admin,
        })
}

#[derive(Deserialize)]
struct RequireLoginForm {
    /// Present (any value) when the portal checkbox was checked; absent when
    /// unchecked -- standard HTML checkbox-form semantics, not a boolean field.
    enabled: Option<String>,
}

async fn set_require_login_route(
    State(st): State<LoginGateState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<RequireLoginForm>,
) -> Response {
    let Some(subject) = crate::portal::session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    match st.tunnels.set_require_login(&subject, &id, form.enabled.is_some()) {
        Ok(true) => Redirect::to("/portal/tunnels").into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "unknown tunnel".to_string()).into_response(),
        Err(e) => internal_error("set_require_login", e).into_response(),
    }
}

#[derive(Deserialize)]
struct AllowlistEmailForm {
    email: String,
}

async fn login_allowlist_add_route(
    State(st): State<LoginGateState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<AllowlistEmailForm>,
) -> Response {
    let Some(subject) = crate::portal::session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    let email = form.email.trim();
    if email.is_empty() {
        return (StatusCode::BAD_REQUEST, "email required".to_string()).into_response();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match st.tunnels.login_allowlist_add(&subject, &id, email, now) {
        Ok(true) => {
            // Self-service access requests (#382-follow, issue #18): once this
            // email is actually granted access, its pending request (if any)
            // is satisfied -- clear it so it doesn't linger in the "pending"
            // list after the owner just acted on it. Best-effort: a missing
            // request is the normal case (most grants aren't self-service
            // requests at all), not an error.
            let _ = st.tunnels.dismiss_access_request(&subject, &id, email);
            // Best-effort account provisioning (#382-follow): never blocks the
            // allow-list add itself, matching `authorize_hostname`'s own
            // "side effect, logged not surfaced" convention above. This realm has
            // no outbound-email mechanism (see `portal.rs`'s
            // `require_verified_email` doc comment for the same gap), so a fresh
            // account's one-time temporary password is only ever logged
            // server-side -- the operator relays it to the invitee out of band.
            if let Some(kc) = &st.kc_admin {
                let client = reqwest::Client::new();
                match crate::keycloak_admin::ensure_user(&client, kc, email).await {
                    Ok(result) if !result.already_existed => eprintln!(
                        "ct-cp: provisioned a new Keycloak account for {email} (tunnel {id}) -- \
                         one-time temporary password, relay to them out of band: {}",
                        result.temporary_password.unwrap_or_default()
                    ),
                    Ok(_) => {}
                    Err(e) => eprintln!("ct-cp: Keycloak account provisioning for {email} failed: {e}"),
                }
            }
            Redirect::to("/portal/tunnels").into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "unknown tunnel or no hostname assigned yet".to_string()).into_response(),
        Err(e) => internal_error("login_allowlist_add", e).into_response(),
    }
}

async fn login_allowlist_remove_route(
    State(st): State<LoginGateState>,
    headers: HeaderMap,
    Path((id, email)): Path<(String, String)>,
) -> Response {
    let Some(subject) = crate::portal::session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    match st.tunnels.login_allowlist_remove(&subject, &id, &email) {
        Ok(true) => Redirect::to("/portal/tunnels").into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "unknown tunnel".to_string()).into_response(),
        Err(e) => internal_error("login_allowlist_remove", e).into_response(),
    }
}

/// `POST /portal/tunnels/:id/access-requests/:email/dismiss` (#382-follow,
/// issue #18): the owner's "Dismiss" action next to a pending self-service
/// request in `login_gate_html` -- declines it without granting access,
/// same owner-scoping as `login_allowlist_remove_route` above.
async fn access_request_dismiss_route(
    State(st): State<LoginGateState>,
    headers: HeaderMap,
    Path((id, email)): Path<(String, String)>,
) -> Response {
    let Some(subject) = crate::portal::session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    match st.tunnels.dismiss_access_request(&subject, &id, &email) {
        Ok(true) => Redirect::to("/portal/tunnels").into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "unknown tunnel or request".to_string()).into_response(),
        Err(e) => internal_error("access_request_dismiss", e).into_response(),
    }
}

#[derive(Serialize)]
struct LoginAllowlistResp {
    emails: Vec<String>,
}

/// `GET /portal/tunnels/:id/login-allowlist` -- the JSON read side the write
/// routes above never had (core request, 2026-08-04): an address-book-style
/// consumer (a bridge, not a browser navigating pages) can now see the current
/// allow-list instead of only being able to blindly add/remove. Same owner
/// scoping as add/remove, via the exact same `login_allowlist_list` the
/// storage layer already exposed -- this handler is genuinely just a thin
/// wrapper, no new storage-layer code needed.
///
/// Deliberately a real `401`/`404` here rather than `Redirect::to("/portal")`
/// like the sibling form-POST routes: those redirect because a browser is
/// mid-navigation when the session's missing; a JSON GET has no page to land
/// on, and a fetch() caller needs a real status code to branch on, not a
/// redirect to follow into an HTML page.
async fn login_allowlist_list_route(
    State(st): State<LoginGateState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(subject) = crate::portal::session_subject_for(&st.session_key, &headers) else {
        return (StatusCode::UNAUTHORIZED, "not signed in".to_string()).into_response();
    };
    match st.tunnels.login_allowlist_list(&subject, &id) {
        Ok(Some(emails)) => Json(LoginAllowlistResp { emails }).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "unknown tunnel, not owned by you, or no hostname assigned yet".to_string()).into_response(),
        Err(e) => internal_error("login_allowlist_list", e).into_response(),
    }
}

async fn topologies_page(State(st): State<TopologyPortalState>, headers: HeaderMap) -> Response {
    if crate::portal::session_claims_for(&st.session_key, &headers).is_none() {
        return Redirect::to("/portal").into_response();
    }
    Html(topologies_html()).into_response()
}

/// A static shell: `#list` and the "New topology" button are filled/wired entirely by the
/// inline script below via `fetch()` against `/me/topologies*` -- no server-side topology
/// read here, matching [`TopologyPortalState`]'s doc comment.
fn topologies_html() -> String {
    let body = r#"<h1>Your topologies</h1>
<p class="help">Compose overlay networks by assigning agents and wiring links in the
<strong>Topology Editor</strong> -- a draggable node graph. A topology authorizes real
channel admission only once bound to an operator key (see the editor's own hint for that
step). Share a topology (from inside its editor) with another Keycloak account's e-mail
to compose it together -- they wire in their own agents, never yours.</p>
<button id="newtopo" class="btn">New topology</button>
<span id="msg" class="help"></span>
<h2>Owned by you</h2>
<div id="list" class="help">Loading…</div>
<h2>Shared with you</h2>
<div id="sharedlist" class="help">Loading…</div>
<script>
(function(){
 var list=document.getElementById('list'),shared=document.getElementById('sharedlist'),msg=document.getElementById('msg');
 function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;');}
 function say(t){if(msg)msg.textContent=t;}
 function rows(items){
  return items.map(function(t){
   return '<div class="row"><span class="v"><code>'+esc(t.id)+'</code></span>'
        + '<span><a class="btn sec" href="/me/topologies/'+encodeURIComponent(t.id)+'/editor">Open editor</a></span></div>';
  }).join('');
 }
 fetch('/me/topologies').then(function(r){return r.ok?r.json():Promise.reject(r.status);})
  .then(function(items){list.innerHTML=items.length?rows(items):'<p class="help">No topologies yet -- create one to start composing an overlay.</p>';})
  .catch(function(s){list.textContent='';say('could not load topologies ('+s+')');});
 fetch('/me/topologies/shared').then(function(r){return r.ok?r.json():Promise.reject(r.status);})
  .then(function(items){shared.innerHTML=items.length?rows(items):'<p class="help">Nothing shared with you yet -- ask the owner to share by your account\'s e-mail.</p>';})
  .catch(function(s){shared.textContent='';say('could not load shared topologies ('+s+')');});
 var btn=document.getElementById('newtopo');
 if(btn){btn.addEventListener('click',function(){
  say('creating…');
  fetch('/me/topologies',{method:'POST'}).then(function(r){return r.ok?r.json():Promise.reject(r.status);})
   .then(function(t){location.href='/me/topologies/'+encodeURIComponent(t.id)+'/editor';})
   .catch(function(s){say('create failed ('+s+')');});
 });}
})();
</script>"#;
    page("your topologies", body)
}

/// `GET /portal/channels` (self-service discoverability, 2026-08-01): the account
/// page's "Your Channels" view -- every channel the logged-in session's own
/// **verified** email has been allow-listed for
/// ([`crate::storage::SqliteChannelStore::channels_for_email`]), with claim status
/// and a direct link to [`claim_page`] for anything still pending. Closes the gap
/// that kept forcing a manual, out-of-band hand-off of a raw channel id (chat,
/// email, whatever) just so an allow-listed person could find out *what* to claim
/// -- now discoverable purely from being logged in. Self-scoped by construction:
/// the query is keyed on the session's own email, never a caller-supplied one, so
/// there is no way to view another subject's invitations from this route.
async fn channels_page(State(st): State<ClaimState>, headers: HeaderMap) -> Response {
    let Some(claims) = crate::portal::session_claims_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    let Some(email) = claims.email else {
        return Html(page(
            "your channels",
            r#"<h1>Your channels</h1><p class="help">Your session has no verified e-mail, so channel
invitations (which are matched by e-mail) can't be shown. Log in again with an identity
provider that verifies e-mail.</p>"#,
        ))
        .into_response();
    };
    let entries = match st.channels.channels_for_email(&email) {
        Ok(v) => v,
        Err(e) => return internal_error("channels_page/channels_for_email", e).into_response(),
    };
    Html(channels_html(&entries)).into_response()
}

/// Render the "Your Channels" list: each row is a channel id (the only stable,
/// non-secret identifier a channel has in this schema -- there's no separate
/// human name) plus a status badge, and a Claim link for anything pending.
fn channels_html(entries: &[(ct_common::channel::ChannelId, Option<u64>)]) -> String {
    let rows = if entries.is_empty() {
        r#"<p class="help">No channel invitations yet. A channel owner adds your e-mail to their
allow-list (<code>ct-agent channel allowlist add &lt;your-email&gt;</code> or the owner's own
portal), and it appears here automatically -- nothing to request.</p>"#
            .to_string()
    } else {
        entries
            .iter()
            .map(|(channel, claimed_at)| {
                let channel_hex = escape(&hex(&channel.0));
                let status = match claimed_at {
                    Some(_) => r#" <span class="tier" style="color:#3fb950">Claimed</span>"#.to_string(),
                    None => r#" <span class="tier" style="color:#f0c674">Pending</span>"#.to_string(),
                };
                let action = if claimed_at.is_none() {
                    format!(r#"<a class="btn sec" href="/portal/channels/{channel_hex}/claim">Claim</a>"#)
                } else {
                    String::new()
                };
                format!(
                    r#"<div class="row"><span class="v"><code>{channel_hex}</code>{status}</span><span>{action}</span></div>"#
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let body = format!(
        r#"<h1>Your channels</h1>
<p class="help">Channels your e-mail has been invited to (matched against your verified
sign-in e-mail) -- claim a pending one to add yourself as a member, no manual
exchange with the owner needed.</p>
{rows}"#
    );
    page("your channels", &body)
}

#[derive(Deserialize)]
struct ClaimReq {
    holder: String,
    noise_pubkey: String,
    noise_attestation: String,
}

#[derive(Serialize)]
struct ClaimResp {
    claimed: bool,
}

/// The outcome of a claim attempt, shared by the JSON API ([`claim_channel`]) and
/// the HTML form ([`claim_channel`]'s `GET` sibling, [`claim_page`]) so the
/// verification + allow-list logic lives in exactly one place.
async fn do_claim(st: &ClaimState, headers: &HeaderMap, channel_hex: &str, req: &ClaimReq) -> Result<(), (StatusCode, String)> {
    let claims = crate::portal::session_claims_for(&st.session_key, headers)
        .ok_or((StatusCode::UNAUTHORIZED, "log in to the portal first".to_string()))?;
    let email = claims
        .email
        .ok_or((StatusCode::FORBIDDEN, "your session has no verified email — log in again".to_string()))?;
    let channel = crate::service::hex_decode_32(channel_hex).ok_or((StatusCode::BAD_REQUEST, "malformed channel".to_string()))?;
    let holder = crate::service::hex_decode_32(&req.holder).ok_or((StatusCode::BAD_REQUEST, "malformed holder".to_string()))?;
    let noise_pubkey = crate::service::hex_decode_32(&req.noise_pubkey)
        .ok_or((StatusCode::BAD_REQUEST, "malformed noise_pubkey".to_string()))?;
    let noise_attestation = crate::service::hex_decode_64(&req.noise_attestation)
        .ok_or((StatusCode::BAD_REQUEST, "malformed noise_attestation".to_string()))?;
    // #101 SEC101b, same bar as the owner-driven `channel_add_member`: the Noise key
    // must be attested by the holder itself, so a spoofed/forged key is rejected here
    // too — the allow-list only authorizes *which* email may join, not *what key*.
    if !ct_common::channel::verify_member_noise_attestation(
        &ct_common::channel::ChannelId(channel),
        &holder,
        &noise_pubkey,
        &noise_attestation,
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            "noise_attestation does not verify against the holder key".to_string(),
        ));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let claimed = st
        .channels
        .claim_via_allowlist(&ct_common::channel::ChannelId(channel), &email, &holder, &noise_pubkey, &noise_attestation, now)
        .map_err(|e| internal_error("do_claim/claim_via_allowlist", e))?;
    if claimed {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "this email is not allow-listed for this channel".to_string()))
    }
}

/// `POST /portal/channels/:channel/claim` (#248-follow): the self-service
/// counterpart to the owner-driven `POST /me/channels/:channel/members` — a portal
/// user whose **verified** session email is on the channel's allow-list
/// ([`crate::storage::SqliteChannelStore::allowlist_add`]) can add themselves as a
/// member directly, no manual out-of-band exchange with the owner needed. Requires:
/// (1) a valid portal session, (2) that session carrying a *verified* email (an
/// unverified/absent one — see [`crate::portal::ExchangedIdentity::email_verified`]
/// — simply can't use this route, matching the owner-driven flow's own trust bar),
/// (3) the same holder-signed Noise-key attestation `channel_add_member` requires
/// (#101 SEC101b), and (4) that email actually being allow-listed for this channel.
/// JSON-only (a `Content-Type: application/json` API for programmatic callers,
/// e.g. tests / scripted onboarding); [`claim_page`] is the human-facing HTML form.
async fn claim_channel(
    State(st): State<ClaimState>,
    headers: HeaderMap,
    Path(channel_hex): Path<String>,
    Json(req): Json<ClaimReq>,
) -> Result<Json<ClaimResp>, (StatusCode, String)> {
    do_claim(&st, &headers, &channel_hex, &req).await?;
    Ok(Json(ClaimResp { claimed: true }))
}

/// `GET /portal/channels/:channel/claim` (#248-follow): render the self-serve
/// claim form; its submission posts (url-encoded, matching every other portal
/// form) to [`claim_page_submit`] on a distinct path, `.../claim-form`, so the
/// browser form and the JSON API client above never contend over the same
/// method+extractor on the same route.
async fn claim_page(State(st): State<ClaimState>, headers: HeaderMap, Path(channel_hex): Path<String>) -> Response {
    if crate::portal::session_subject_for(&st.session_key, &headers).is_none() {
        return Redirect::to("/portal").into_response();
    }
    Html(claim_html(&channel_hex, None)).into_response()
}

async fn claim_page_submit(
    State(st): State<ClaimState>,
    headers: HeaderMap,
    Path(channel_hex): Path<String>,
    Form(req): Form<ClaimReq>,
) -> Response {
    if crate::portal::session_subject_for(&st.session_key, &headers).is_none() {
        return Redirect::to("/portal").into_response();
    }
    match do_claim(&st, &headers, &channel_hex, &req).await {
        Ok(()) => Html(claim_html(&channel_hex, Some(Ok(())))).into_response(),
        Err((_, msg)) => Html(claim_html(&channel_hex, Some(Err(msg)))).into_response(),
    }
}

/// The self-serve claim form (#248-follow): a portal user pastes the three values
/// [`ct-agent channel member-material`] (or whatever locally produced them) prints,
/// and the claim runs -- no manual out-of-band exchange with the channel owner.
fn claim_html(channel_hex: &str, result: Option<Result<(), String>>) -> String {
    let banner = match &result {
        Some(Ok(())) => r#"<div class="warn" style="border-color:#238636;background:#0d2818;color:#3fb950">Claimed -- you're now a member of this channel.</div>"#.to_string(),
        Some(Err(msg)) => format!(r#"<div class="warn">Could not claim: {}</div>"#, escape(msg)),
        None => String::new(),
    };
    let body = format!(
        r#"<h1>Join a channel</h1>
<p class="k">Your signed-in e-mail must already be on this channel's allow-list (ask its owner to add
you with <code>ct-agent channel allowlist add &lt;your-email&gt;</code> if it isn't yet).</p>
{banner}
<form method="post" action="/portal/channels/{channel}/claim-form">
 <label>Channel<input type="text" value="{channel}" disabled></label>
 <label>Holder public key
  <input type="text" name="holder" placeholder="64 hex chars" required pattern="[0-9a-fA-F]{{64}}">
  <span class="help">Your member holder public key.</span></label>
 <label>Noise public key
  <input type="text" name="noise_pubkey" placeholder="64 hex chars" required pattern="[0-9a-fA-F]{{64}}">
  <span class="help">Your member Noise static public key.</span></label>
 <label>Noise attestation
  <input type="text" name="noise_attestation" placeholder="128 hex chars" required pattern="[0-9a-fA-F]{{128}}">
  <span class="help">Your holder key's signature over (channel, holder, noise_pubkey) -- #101.</span></label>
 <button type="submit">Claim membership</button>
</form>
<details>
 <summary>Where do these come from?</summary>
 <p class="help">Run <code>ct-agent channel member-material</code> locally (never paste a private key here) --
 it derives your holder public key and signs the Noise-key attestation from your own holder private key,
 without sending anything over the network. Paste its three printed values above.</p>
</details>
<a class="btn sec" href="/portal">Back to account</a>"#,
        channel = escape(channel_hex),
    );
    page("join channel", &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portal::sign_session_for_test;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    const KEY: &[u8] = b"portal-api-test-key";

    #[test]
    fn human_bytes_formats_at_the_unit_a_reader_would_expect() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KB");
        assert_eq!(human_bytes(2048), "2.0 KB");
        assert_eq!(human_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(human_bytes(1024 * 1024 * 1024), "1.0 GB");
        assert_eq!(human_bytes(u64::MAX), "16777216.0 TB", "never panics/overflows at the top of the range");
    }

    // #112 (frozen): a hung edge admin endpoint must NOT block the portal path.
    // The tuned client returns a timeout error promptly instead of hanging — the
    // exact failure mode `create_tunnel`/`delete_tunnel` now avoid.
    #[tokio::test]
    async fn edge_admin_client_times_out_against_a_hung_endpoint() {
        // A listener that accepts the connection but never writes an HTTP response.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _held = stream; // hold the socket open, send nothing
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        });
        let client = edge_admin_http_client_with(std::time::Duration::from_millis(200));
        let start = std::time::Instant::now();
        let res = client
            .post(format!("http://{addr}/admin/revoke/tok"))
            .send()
            .await;
        let err = res.expect_err("a hung endpoint must produce an error, not hang");
        assert!(err.is_timeout(), "the error must be a timeout, got: {err}");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "must time out promptly (~200ms), not hang"
        );
    }

    #[test]
    fn redact_routing_tokens_strips_the_token_from_a_revoke_error() {
        // #90: a routing token is 64 lowercase-hex chars and rides in the edge-revoke
        // URL, which reqwest's error Display embeds — so it must be redacted before
        // logging. Mirror that error shape and assert the token is gone.
        let token = "a".repeat(64);
        let err = format!(
            "error sending request for url (https://edge.example/admin/revoke/{token}): \
             connection refused"
        );
        let red = redact_routing_tokens(&err);
        assert!(!red.contains(&token), "the routing token must not survive redaction");
        assert!(red.contains("<redacted-token>"), "token replaced by the marker");
        // Non-secret context is preserved so the log line is still useful.
        assert!(red.contains("admin/revoke/"), "url structure kept");
        assert!(red.contains("connection refused"), "error reason kept");

        // A short hex value (e.g. a status code fragment) is left alone.
        assert_eq!(redact_routing_tokens("returned 503 deadbeef"), "returned 503 deadbeef");
    }

    fn session_header(subject: &str) -> String {
        format!("ct_portal_session={}", sign_session_for_test(KEY, subject))
    }

    fn test_edge_mesh() -> EdgeMeshHandle {
        EdgeMeshHandle::new(
            Arc::new(crate::edge_mesh::SqliteEdgeMesh::open_in_memory().unwrap()),
            Arc::from("test-edge"),
        )
    }

    fn test_app() -> Router {
        test_app_with_tunnels().0
    }

    /// Same as [`test_app`] but also returns the `SqliteTunnelStore` directly,
    /// so a test can drive cert-tier state (#233: `enter_gelb_queue`,
    /// `offer_claim`, ...) before hitting the page.
    fn test_app_with_tunnels() -> (Router, Arc<SqliteTunnelStore>) {
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let enrollment = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let bootstrap = Arc::new(SqliteBootstrap::open_in_memory().unwrap());
        let app = portal_api_router(
            KEY,
            ledger,
            tunnels.clone(),
            enrollment,
            bootstrap,
            "https://portal.example",
            None,
            None,
            None,
            test_edge_mesh(),
            None,
        );
        (app, tunnels)
    }

    #[tokio::test]
    async fn account_page_requires_a_session() {
        let app = test_app();
        let resp = app
            .oneshot(Request::get("/portal/account").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/portal");
    }

    #[tokio::test]
    async fn account_page_shows_self_scoped_account_and_balance() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::get("/portal/account")
                    .header("cookie", session_header("kc-user-1"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("kc-user-1"), "shows the subject");
        assert!(html.contains("Credit&nbsp;balance"), "shows the balance row");
        assert!(html.contains("/portal/account/credits"), "offers buy-credits");
        assert!(html.contains("/portal/logout"), "offers sign-out");
        assert!(html.contains("Service accounts"), "the account page must surface real self-service M2M credentials, not just link out");
        assert!(html.contains("/me/service-accounts"), "the shell must target the real API, not a placeholder");
        assert!(html.contains("will not be shown again"), "the secret-shown-once warning must be real, present copy, not implied");
        // No OIDC configured in test_app() -- omitted, not a dead link.
        assert!(
            !html.contains("Account Console"),
            "no account-console link when OIDC/account_console_url isn't configured"
        );
    }

    #[tokio::test]
    async fn account_page_links_to_the_idp_account_console_when_configured() {
        // Password change, sessions, and self-service account deletion are all
        // Keycloak's own Account Console -- CADS-Tunnel doesn't reimplement any
        // of it, just links there.
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let enrollment = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let app = portal_api_router(
            KEY,
            ledger,
            tunnels,
            enrollment,
            Arc::new(SqliteBootstrap::open_in_memory().unwrap()),
            "https://portal.example",
            None,
            None,
            Some("https://auth.example/realms/ct-demo/account".to_string()),
            test_edge_mesh(),
            None,
        );
        let resp = app
            .oneshot(
                Request::get("/portal/account")
                    .header("cookie", session_header("kc-user-1"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = String::from_utf8(to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap();
        assert!(
            html.contains(r#"href="https://auth.example/realms/ct-demo/account""#),
            "links to the real account console URL"
        );
        assert!(
            html.contains("two-factor authentication"),
            "explains password/2FA/session management is available via the account console"
        );
        assert!(
            html.contains("Danger zone") && html.contains("/portal/account/delete"),
            "offers CADS-Tunnel's own self-service account-data deletion, not just a link out"
        );
    }

    #[tokio::test]
    async fn buy_credits_creates_an_intent_for_the_callers_account() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::post("/portal/account/credits")
                    .header("cookie", session_header("kc-user-1"))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("credits=250"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Payment intent created"));
        assert!(html.contains("250"), "echoes the credit amount");
    }

    #[tokio::test]
    async fn buy_credits_requires_a_session() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::post("/portal/account/credits")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("credits=250"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn delete_account_requires_a_session_and_the_literal_confirm_text() {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let channels = Arc::new(crate::storage::SqliteChannelStore::open_in_memory().unwrap());
        let topologies = Arc::new(crate::storage::SqliteTopologyStore::open_in_memory().unwrap());
        let networks = Arc::new(crate::storage::SqliteNetworkStore::open_in_memory().unwrap());
        let pipelines = Arc::new(crate::storage::SqlitePipelineRegistry::open_in_memory().unwrap());
        let app = account_delete_router(KEY, tunnels, channels, topologies, networks, pipelines);

        // No session -> bounced, nothing happens.
        let resp = app
            .clone()
            .oneshot(
                Request::post("/portal/account/delete")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("confirm=DELETE"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        // Wrong confirm text -> rejected.
        let resp = app
            .clone()
            .oneshot(
                Request::post("/portal/account/delete")
                    .header("cookie", session_header("kc-alice"))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("confirm=nope"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn delete_account_cascades_every_owned_resource_and_strips_cross_account_grants() {
        // Account-deletion cascade (Keycloak/account overhaul): before this,
        // `account_html`'s "manage your account" section punted deletion entirely
        // to Keycloak's Account Console, which has no idea CADS-Tunnel's own
        // tunnels/channels/topologies/networks/pipelines exist. This proves the
        // real self-service teardown, including cleaning the deleted account's
        // e-mail off OTHER people's allow-lists / share-lists.
        use ct_common::channel::ChannelId;
        use ct_common::policy::{Agent, Levels, Network, Policy};
        use ct_common::pipeline::{PipelineSpec, SelectionPolicy};

        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let channels = Arc::new(crate::storage::SqliteChannelStore::open_in_memory().unwrap());
        let topologies = Arc::new(crate::storage::SqliteTopologyStore::open_in_memory().unwrap());
        let networks = Arc::new(crate::storage::SqliteNetworkStore::open_in_memory().unwrap());
        let pipelines = Arc::new(crate::storage::SqlitePipelineRegistry::open_in_memory().unwrap());

        // Alice's own stuff.
        tunnels.create("kc-alice", "my-tunnel", None).unwrap();
        let alice_chan = ChannelId([0xA1; 32]);
        channels.register_channel(&alice_chan, &[0x01; 32], "kc-alice").unwrap();
        channels.allowlist_add(&alice_chan, "kc-alice", "friend@example.com", 1).unwrap();
        topologies.create_topology("kc-alice", "alice-topo", "u-alice").unwrap();
        topologies.share_add("kc-alice", "alice-topo", "friend@example.com", 1).unwrap();
        let net = Network { agents: vec![Agent::new("a1", "dev", "internal")], policy: Policy { levels: Levels::new(["public", "internal"]), rules: vec![], mac_flow_control: false } };
        networks.put("kc-alice", "alice-net", &net).unwrap();
        pipelines
            .publish("kc-alice", &PipelineSpec { id: "alice-pipeline".into(), roles: vec![], operator_pubkey_hex: None, selection_policy: SelectionPolicy::LowestFloor }, 1)
            .unwrap();

        // Bob owns a separate channel and topology, and has shared/allow-listed
        // alice's e-mail into them -- these must survive Bob's ownership intact,
        // just with alice's e-mail stripped out.
        let bob_chan = ChannelId([0xB0; 32]);
        channels.register_channel(&bob_chan, &[0x02; 32], "kc-bob").unwrap();
        channels.allowlist_add(&bob_chan, "kc-bob", "alice@example.com", 1).unwrap();
        topologies.create_topology("kc-bob", "bob-topo", "u-bob").unwrap();
        topologies.share_add("kc-bob", "bob-topo", "alice@example.com", 1).unwrap();

        let app = account_delete_router(KEY, tunnels.clone(), channels.clone(), topologies.clone(), networks.clone(), pipelines.clone());
        let session = format!(
            "ct_portal_session={}",
            crate::portal::sign_session_with_email_for_test(KEY, "kc-alice", "alice@example.com")
        );
        let resp = app
            .oneshot(
                Request::post("/portal/account/delete")
                    .header("cookie", session)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("confirm=DELETE"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get("set-cookie").is_some(), "session cookie cleared");
        let html = String::from_utf8(to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap();
        assert!(html.contains("account data has been deleted"));

        // Alice's own resources are gone.
        assert!(tunnels.list_for_subject("kc-alice").unwrap().is_empty());
        assert_eq!(channels.channel_owner(&alice_chan).unwrap(), None);
        assert!(topologies.list_topologies("kc-alice").unwrap().is_empty());
        assert_eq!(networks.get("kc-alice", "alice-net").unwrap(), None);
        assert_eq!(pipelines.get("alice-pipeline").unwrap(), None);

        // Bob's resources survive, but alice's e-mail is gone from both grant lists.
        assert_eq!(channels.channel_owner(&bob_chan).unwrap(), Some("kc-bob".to_string()));
        assert!(!channels.allowlist_contains(&bob_chan, "alice@example.com").unwrap());
        assert!(topologies.topology("bob-topo").unwrap().is_some());
        assert!(!topologies.is_shared_with("bob-topo", "alice@example.com").unwrap());
    }

    async fn get(app: &Router, path: &str, subject: Option<&str>) -> (StatusCode, String) {
        let mut req = Request::get(path);
        if let Some(s) = subject {
            req = req.header("cookie", session_header(s));
        }
        let resp = app.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
        let status = resp.status();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    async fn post_form(app: &Router, path: &str, subject: &str, form: &str) -> StatusCode {
        app.clone()
            .oneshot(
                Request::post(path)
                    .header("cookie", session_header(subject))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    fn first_id(html: &str) -> String {
        html.split("/portal/tunnels/")
            .nth(1)
            .and_then(|s| s.split('/').next())
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn tunnels_are_auto_provisioned_one_per_account_and_revoke_is_self_scoped() {
        let app = test_app();
        let count = |h: &str| h.matches("/delete").count();

        // Unauthenticated -> bounced.
        assert_eq!(get(&app, "/portal/tunnels", None).await.0, StatusCode::SEE_OTHER);

        // First view auto-provisions exactly one tunnel each — no create step.
        let (_s, alice_html) = get(&app, "/portal/tunnels", Some("alice")).await;
        assert_eq!(count(&alice_html), 1, "alice's one Standard-tier tunnel was auto-provisioned");
        assert_eq!(
            count(&get(&app, "/portal/tunnels", Some("bob")).await.1),
            1,
            "bob gets his own, separate auto-provisioned tunnel"
        );
        // Revisiting doesn't provision a second one.
        assert_eq!(count(&get(&app, "/portal/tunnels", Some("alice")).await.1), 1, "still just one on a re-view");

        // A direct POST for a second tunnel is rejected server-side (not just hidden in the UI).
        assert_eq!(
            post_form(&app, "/portal/tunnels", "alice", "name=second").await,
            StatusCode::FORBIDDEN,
            "additional tunnels are rejected even via a direct POST"
        );

        // alice revokes her tunnel -> none remain immediately...
        assert_eq!(
            post_form(&app, &format!("/portal/tunnels/{}/delete", first_id(&alice_html)), "alice", "").await,
            StatusCode::SEE_OTHER
        );
        // ...but the next view auto-provisions a fresh one again.
        let (_s, after) = get(&app, "/portal/tunnels", Some("alice")).await;
        assert_eq!(count(&after), 1, "revoking and revisiting re-provisions a tunnel");

        // bob cannot revoke alice's tunnel (self-scoped) — it survives.
        post_form(&app, &format!("/portal/tunnels/{}/delete", first_id(&after)), "bob", "").await;
        assert_eq!(
            count(&get(&app, "/portal/tunnels", Some("alice")).await.1),
            1,
            "self-scoped: bob cannot revoke alice's tunnel"
        );
    }

    #[tokio::test]
    async fn tunnels_page_explains_the_standard_tier_and_shows_share_disabled() {
        // #69 T69.1 (updated for the Standard-tier auto-provision policy): a
        // first-time customer must understand, without reading the architecture
        // docs, that their one tunnel is already set up, that Sharing exists but
        // is a paid-tier feature, and that "Create another" is visible-but-disabled
        // rather than silently missing.
        let app = test_app();
        let (status, html) = get(&app, "/portal/tunnels", Some("alice")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("automatically\nassigned hostname") || html.contains("automatically assigned hostname"),
            "explains the auto-assigned hostname");
        assert!(html.contains("disabled") && html.contains(">Share<"), "Share is shown but disabled");
        assert!(html.contains("paid tier") || html.contains("paid-tier"), "names the paid-tier gate");
        assert!(
            html.contains("disabled") && html.contains("Create another tunnel"),
            "the second-tunnel form is visible but disabled, not hidden"
        );
        assert!(
            html.to_lowercase().contains("hostname"),
            "gives hostname guidance"
        );
        // Still self-contained / CSP-safe: no external asset URLs.
        assert!(
            !html.contains("http://") && !html.contains("https://cdn"),
            "no external assets"
        );
    }

    #[tokio::test]
    async fn tunnels_page_shows_getting_started_steps() {
        // #69 T69.2: after creating a tunnel a first-time customer lands back on the
        // list with no idea what to do next. A "Next steps" walkthrough must be
        // present, and it must make the critical create->install->run-on-the-origin
        // distinction (run the one-liner on the machine you want to expose, not the
        // browsing device) explicit. Frozen so the walkthrough can't silently vanish.
        let app = test_app();
        let (status, html) = get(&app, "/portal/tunnels", Some("alice")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("Next steps"), "a next-steps walkthrough is shown");
        assert!(html.contains("<ol class=\"steps\">"), "rendered as ordered steps");
        assert!(html.contains("Install"), "step references the Install action");
        assert!(
            html.contains("machine you want to expose"),
            "explains the one-liner runs on the origin, not the browsing device"
        );
    }

    #[tokio::test]
    async fn tunnels_page_shows_the_cert_tier_badge_and_the_private_key_disclosure_while_gelb() {
        // #233: a customer must see their subdomain's Rot/Gelb/Grün status, and
        // while Gelb specifically, a persistent (not one-time) disclosure that
        // the operator holds this certificate's private key.
        let (app, tunnels) = test_app_with_tunnels();
        // Seed the tunnel directly with a hostname (no DNS backend configured
        // in this harness, so the page's own auto-provision wouldn't assign one).
        let hostname = "site-abc.example.com".to_string();
        tunnels.create("alice", "site", Some(&hostname)).unwrap();

        // Rot (freshly created, not yet queued): the badge shows, no disclosure.
        let (_, html) = get(&app, "/portal/tunnels", Some("alice")).await;
        assert!(html.contains("Rot"), "shows the Rot badge: {html}");
        assert!(!html.contains("privaten Schlüssel"), "no disclosure needed while Rot");

        // Gelb, queued (not yet offered): disclosure IS shown.
        tunnels.enter_gelb_queue(&hostname, 100).unwrap();
        let (_, html) = get(&app, "/portal/tunnels", Some("alice")).await;
        assert!(html.contains("Gelb"), "shows the Gelb badge");
        assert!(html.contains("privaten Schlüssel"), "persistent disclosure while Gelb: {html}");

        // Gelb, offered: the claim-deadline note appears too.
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        tunnels.offer_claim(&hostname, "letsencrypt", now, now + 3600).unwrap();
        let (_, html) = get(&app, "/portal/tunnels", Some("alice")).await;
        assert!(html.contains("Zeit"), "shows a claim-window time note: {html}");
        assert!(html.contains("privaten Schlüssel"), "disclosure still shown while offered");

        // Gruen: no disclosure, no reclaim form.
        tunnels.record_issuance_complete(&hostname, "example.com", now).unwrap();
        let (_, html) = get(&app, "/portal/tunnels", Some("alice")).await;
        assert!(html.contains("Grün"), "shows the Grün badge");
        assert!(!html.contains("privaten Schlüssel"), "no disclosure once Grün");
        assert!(!html.contains("reclaim-cert-slot"), "no reclaim action once Grün");
    }

    #[tokio::test]
    async fn reclaim_cert_slot_only_reenters_the_queue_from_lapsed_and_only_for_the_owner() {
        // #233: re-request after a lapse must (a) require ownership, (b) be a
        // no-op unless the hostname is actually `lapsed`, and (c) land the
        // hostname back at the queue's back (fresh queued_at), never restoring
        // its old position.
        let (app, tunnels) = test_app_with_tunnels();
        let alice_hostname = "alice-site.example.com".to_string();
        let alice_id = tunnels.create("alice", "site", Some(&alice_hostname)).unwrap().id;

        // Not lapsed yet (still rot) -> reclaim is a no-op, still rot.
        let status = post_form(&app, &format!("/portal/tunnels/{alice_id}/reclaim-cert-slot"), "alice", "").await;
        assert_eq!(status, StatusCode::SEE_OTHER, "redirects back regardless");
        assert_eq!(tunnels.cert_admission_for_hostname(&alice_hostname).unwrap().unwrap().status, "rot");

        // Queue it, offer it, then let it lapse.
        tunnels.enter_gelb_queue(&alice_hostname, 100).unwrap();
        tunnels.offer_claim(&alice_hostname, "letsencrypt", 100, 200).unwrap();
        tunnels.lapse_expired_claims(300).unwrap();
        assert_eq!(tunnels.cert_admission_for_hostname(&alice_hostname).unwrap().unwrap().claim_state, "lapsed");

        // A stranger cannot reclaim alice's tunnel.
        let _ = get(&app, "/portal/tunnels", Some("bob")).await; // provisions bob's own tunnel
        post_form(&app, &format!("/portal/tunnels/{alice_id}/reclaim-cert-slot"), "bob", "").await;
        assert_eq!(
            tunnels.cert_admission_for_hostname(&alice_hostname).unwrap().unwrap().claim_state,
            "lapsed",
            "bob cannot reclaim alice's slot"
        );

        // Alice reclaims her own -> back to none/gelb, queued_at reset.
        post_form(&app, &format!("/portal/tunnels/{alice_id}/reclaim-cert-slot"), "alice", "").await;
        let a = tunnels.cert_admission_for_hostname(&alice_hostname).unwrap().unwrap();
        assert_eq!(a.claim_state, "none");
        assert_eq!(a.status, "gelb");
    }

    #[tokio::test]
    async fn delete_tunnel_propagates_the_revoke_to_the_edge() {
        // #27 RB4b: revoking a tunnel POSTs the edge admin revoke endpoint with
        // the tunnel's routing token + admin auth, so the live tunnel is torn down.
        use axum::extract::{Path as AxPath, State as AxState};
        use axum::http::HeaderMap as AxHeaderMap;
        use std::sync::Mutex;

        let received: Arc<Mutex<Option<(String, String)>>> = Arc::new(Mutex::new(None));
        let mock = Router::new()
            .route(
                "/admin/revoke/:token",
                post(
                    |AxState(rec): AxState<Arc<Mutex<Option<(String, String)>>>>,
                     headers: AxHeaderMap,
                     AxPath(token): AxPath<String>| async move {
                        let auth = headers
                            .get("x-ct-admin-token")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        *rec.lock().unwrap() = Some((token, auth));
                        StatusCode::OK
                    },
                ),
            )
            .with_state(received.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });

        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let enrollment = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let created = tunnels.create("alice", "web", None).unwrap();
        // Pre-seed an edge_mesh ownership record, as authorize_hostname would have
        // written when the tunnel was created -- revoke must clean it up too.
        let mesh_store = Arc::new(crate::edge_mesh::SqliteEdgeMesh::open_in_memory().unwrap());
        mesh_store
            .record_ownership(&created.routing_token, None, "test-edge", 0)
            .unwrap();
        let edge_mesh = EdgeMeshHandle::new(mesh_store.clone(), Arc::from("test-edge"));
        let app = portal_api_router(
            KEY,
            ledger,
            tunnels.clone(),
            enrollment,
            Arc::new(SqliteBootstrap::open_in_memory().unwrap()),
            "https://portal.example",
            Some((format!("http://{addr}"), "edge-secret".to_string())),
            None,
            None,
            edge_mesh,
            None,
        );

        let status = post_form(&app, &format!("/portal/tunnels/{}/delete", created.id), "alice", "").await;
        assert_eq!(status, StatusCode::SEE_OTHER);

        let got = received.lock().unwrap().clone().expect("edge revoke was called");
        assert_eq!(got.0, created.routing_token, "revoked the tunnel's routing token");
        assert_eq!(got.1, "edge-secret", "carried the admin auth header");
        assert!(tunnels.list_for_subject("alice").unwrap().is_empty(), "tunnel removed");
        assert!(
            mesh_store.lookup_by_token(&created.routing_token).unwrap().is_none(),
            "edge_mesh ownership record forgotten on revoke"
        );
    }

    #[tokio::test]
    async fn auto_provisioned_tunnel_with_a_hostname_authorizes_it_at_the_edge() {
        // #23 BP4b-c (updated for the Standard-tier auto-provision policy, #226):
        // the tunnel's auto-assigned (not user-chosen) hostname still authorizes
        // (host -> token) at the edge so the agent's 'H' bind is accepted under
        // required auth.
        use axum::extract::{Path as AxPath, State as AxState};
        use axum::http::{HeaderMap as AxHeaderMap, Uri as AxUri};
        use std::sync::Mutex;

        // A Vec, not a single slot: the happy path now hits this endpoint twice
        // (the plain authorize, then the #233 synchronous Rot->Gelb channel-tier
        // push) -- a single slot would silently only keep the last one.
        let received: Arc<Mutex<Vec<(String, String, String, Option<String>)>>> = Arc::new(Mutex::new(Vec::new()));
        let mock = Router::new()
            .route(
                "/admin/authorize-host/:token/:host",
                post(
                    |AxState(rec): AxState<Arc<Mutex<Vec<(String, String, String, Option<String>)>>>>,
                     headers: AxHeaderMap,
                     uri: AxUri,
                     AxPath((token, host)): AxPath<(String, String)>| async move {
                        let auth = headers
                            .get("x-ct-admin-token")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        rec.lock().unwrap().push((token, host, auth, uri.query().map(str::to_string)));
                        StatusCode::OK
                    },
                ),
            )
            .with_state(received.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });

        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let enrollment = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let desec = ct_dns::provider::DesecClient::from_lookup(|k| match k {
            "DESEC_TOKEN" => Some("t".into()),
            "DESEC_DOMAIN" => Some("bunsenbrenner.org".into()),
            _ => None,
        })
        .unwrap();
        let mesh_store = Arc::new(crate::edge_mesh::SqliteEdgeMesh::open_in_memory().unwrap());
        // lookup_by_token/lookup_by_host join against mesh_edges, so the owning edge must
        // have heartbeated at least once to be resolvable (mirrors persistent_control_plane_router's
        // boot-time self-heartbeat for the real deployment).
        // #285: the heartbeat must also be recent (within OWNERSHIP_LIVENESS_SECS), not just present.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        mesh_store.heartbeat("primary", "test", None, now).unwrap();
        let app = portal_api_router(
            KEY,
            ledger,
            tunnels.clone(),
            enrollment,
            Arc::new(SqliteBootstrap::open_in_memory().unwrap()),
            "https://portal.example",
            Some((format!("http://{addr}"), "edge-secret".to_string())),
            Some((desec, "1.2.3.4".to_string())),
            None,
            EdgeMeshHandle::new(mesh_store.clone(), Arc::from("primary")),
            None,
        );

        // Viewing the tunnels page auto-provisions the one Standard-tier tunnel.
        assert_eq!(get(&app, "/portal/tunnels", Some("alice")).await.0, StatusCode::OK);

        let tunnel = &tunnels.list_for_subject("alice").unwrap()[0];
        let expected_host = tunnel.hostname.clone().expect("auto-assigned a hostname");
        assert!(
            expected_host.starts_with("site-") && expected_host.ends_with(".bunsenbrenner.org"),
            "auto-assigned from the tunnel name + account suffix, not user-chosen: {expected_host}"
        );
        // The displayed/stored name matches the hostname's own label, not the
        // bare "site" every account would otherwise show identically.
        assert_ne!(tunnel.name, "site", "the tunnel's name is account-unique, not the literal default");
        assert_eq!(
            Some(tunnel.name.as_str()),
            expected_host.split('.').next(),
            "the stored name is exactly the hostname's first label"
        );

        // The edge received authorize-host with this tunnel's routing token + auth.
        let calls = received.lock().unwrap().clone();
        let (token, host, auth, _) = calls.first().cloned().expect("edge authorize called");
        assert_eq!(token, tunnel.routing_token, "authorizes the tunnel's routing token");
        assert_eq!(host, expected_host);
        assert_eq!(auth, "edge-secret");

        // edge_mesh Phase 0: a successful edge-authorize records this deployment's
        // local edge as the owner of the tunnel's (token, hostname) pair.
        let (owner_id, _) = mesh_store
            .lookup_by_token(&tunnel.routing_token)
            .unwrap()
            .expect("ownership recorded after a successful edge authorize");
        assert_eq!(owner_id, "primary");
        assert_eq!(
            mesh_store.lookup_by_host(&expected_host).unwrap().map(|(id, _)| id),
            Some("primary".to_string()),
            "resolvable by hostname too"
        );

        // #233: Rot -> Gelb must happen synchronously right here, not only on
        // the next (up-to-60s) admission-loop tick -- this is exactly the bug
        // the user caught live ("why does Rot->Gelb take up to two minutes").
        assert!(
            tunnels.gelb_hostnames().unwrap().contains(&expected_host),
            "hostname enters the Gelb queue synchronously on the happy path, not after a sweep tick"
        );
        let gelb_push = calls
            .iter()
            .find(|(_, h, _, q)| h == &expected_host && q.as_deref() == Some("channel_tier=gelb"))
            .expect("a second authorize-host call pushed channel_tier=gelb synchronously");
        assert_eq!(gelb_push.0, tunnel.routing_token);
        assert_eq!(gelb_push.2, "edge-secret");
    }

    #[tokio::test]
    async fn tunnels_page_shows_live_connection_status_from_the_edge_248() {
        // Monitoring feature v1 (2026-08-01): the portal queries the edge's
        // GET /admin/tunnel-status/:token for the caller's own tunnel and renders a
        // Connected/Not-connected badge -- best-effort (the page must still render
        // if the edge call fails), and must never be shown for a tunnel the caller
        // doesn't own (implicitly covered: tunnels_page only ever queries the
        // caller's own routing_token).
        use axum::extract::{Path as AxPath, State as AxState};
        use axum::http::HeaderMap as AxHeaderMap;
        use std::sync::atomic::{AtomicBool, Ordering};

        let seen_token: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
        let connected = Arc::new(AtomicBool::new(true));
        let seen = seen_token.clone();
        let conn = connected.clone();
        let mock = Router::new()
            .route("/admin/authorize-host/:token/:host", post(|| async { StatusCode::OK }))
            .route(
                "/admin/tunnel-status/:token",
                axum::routing::get(move |AxState(_): AxState<()>, headers: AxHeaderMap, AxPath(token): AxPath<String>| {
                    let seen = seen.clone();
                    let conn = conn.clone();
                    async move {
                        assert_eq!(
                            headers.get("x-ct-admin-token").and_then(|v| v.to_str().ok()),
                            Some("edge-secret"),
                            "the portal must authenticate this call the same way as every other edge-admin call"
                        );
                        *seen.lock().unwrap() = Some(token);
                        Json(serde_json::json!({
                            "connected": conn.load(Ordering::SeqCst),
                            "registrations": 1,
                            "bytes_received": 2048,
                            "bytes_sent": 1024,
                        }))
                    }
                }),
            )
            .with_state(());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });

        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let app = portal_api_router(
            KEY,
            Arc::new(SqliteLedger::open_in_memory().unwrap()),
            tunnels.clone(),
            Arc::new(SqliteEnrollment::open_in_memory().unwrap()),
            Arc::new(SqliteBootstrap::open_in_memory().unwrap()),
            "https://portal.example",
            Some((format!("http://{addr}"), "edge-secret".to_string())),
            None,
            None,
            EdgeMeshHandle::new(Arc::new(crate::edge_mesh::SqliteEdgeMesh::open_in_memory().unwrap()), Arc::from("primary")),
            None,
        );

        // Connected -> the green badge, and the edge was queried with this exact
        // tunnel's routing token (server-side only, never rendered itself).
        let (status, html) = get(&app, "/portal/tunnels", Some("alice")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("Connected"), "shows the connected badge");
        assert!(html.contains("2.0 KB"), "shows bytes received, human-formatted: {html}");
        assert!(html.contains("1.0 KB"), "shows bytes sent, human-formatted: {html}");
        let tunnel = &tunnels.list_for_subject("alice").unwrap()[0];
        assert_eq!(seen_token.lock().unwrap().as_deref(), Some(tunnel.routing_token.as_str()));
        assert!(!html.contains(&tunnel.routing_token), "the raw routing token itself is never rendered");

        // Not connected -> the different badge, not a page failure.
        connected.store(false, Ordering::SeqCst);
        let (status, html) = get(&app, "/portal/tunnels", Some("alice")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("Not connected"));
    }

    #[tokio::test]
    async fn tunnels_page_renders_fine_when_edge_admin_is_unconfigured_248() {
        // Best-effort per tunnels_page's own established tolerance (#233's admission
        // lookup has the same posture): no edge_admin configured -> no status badge,
        // but the page must still render successfully, not error out.
        let app = portal_api_router(
            KEY,
            Arc::new(SqliteLedger::open_in_memory().unwrap()),
            Arc::new(SqliteTunnelStore::open_in_memory().unwrap()),
            Arc::new(SqliteEnrollment::open_in_memory().unwrap()),
            Arc::new(SqliteBootstrap::open_in_memory().unwrap()),
            "https://portal.example",
            None, // no edge_admin
            None,
            None,
            EdgeMeshHandle::new(Arc::new(crate::edge_mesh::SqliteEdgeMesh::open_in_memory().unwrap()), Arc::from("primary")),
            None,
        );
        let (status, html) = get(&app, "/portal/tunnels", Some("alice")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!html.contains("Connected") && !html.contains("Not connected"));
    }

    #[tokio::test]
    async fn admin_provision_tunnel_requires_the_admin_token_and_creates_a_custom_hostname() {
        // Operator-only escape hatch for a vanity hostname the Standard tier's
        // auto-assign would never produce -- proves it's gated, actually creates
        // the requested hostname verbatim (not a "site-<suffix>" auto name), and
        // runs the same edge-authorize side effect as the self-service path.
        let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let secret = [0x77u8; 32];

        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let enrollment = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let mesh_store = Arc::new(crate::edge_mesh::SqliteEdgeMesh::open_in_memory().unwrap());
        let app = portal_api_router(
            KEY,
            ledger,
            tunnels.clone(),
            enrollment,
            Arc::new(SqliteBootstrap::open_in_memory().unwrap()),
            "https://portal.example",
            None,
            None,
            None,
            EdgeMeshHandle::new(mesh_store, Arc::from("primary")),
            Some(secret),
        );

        let body = r#"{"subject":"flappy-demo-maintainer","name":"flappy-demo","hostname":"flappy-demo.bunsenbrenner.org"}"#;
        let post_provision = |token_header: Option<String>| {
            let app = app.clone();
            let mut req = Request::post("/admin/provision-tunnel").header("content-type", "application/json");
            if let Some(t) = token_header {
                req = req.header("x-ct-admin-token", t);
            }
            let req = req.body(Body::from(body)).unwrap();
            async move { app.oneshot(req).await.unwrap() }
        };

        assert_eq!(
            post_provision(None).await.status(),
            StatusCode::UNAUTHORIZED,
            "no token -> refused"
        );
        assert_eq!(
            post_provision(Some(hex(&[0x11u8; 32]))).await.status(),
            StatusCode::UNAUTHORIZED,
            "wrong token -> refused"
        );

        let resp = post_provision(Some(hex(&secret))).await;
        assert_eq!(resp.status(), StatusCode::OK, "correct admin token -> provisions");
        let respbody = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&respbody).unwrap();
        assert_eq!(parsed["hostname"], "flappy-demo.bunsenbrenner.org", "the EXACT requested hostname, not auto-assigned");
        let routing_token = parsed["routing_token"].as_str().unwrap().to_string();

        let created = &tunnels.list_for_subject("flappy-demo-maintainer").unwrap()[0];
        assert_eq!(created.hostname.as_deref(), Some("flappy-demo.bunsenbrenner.org"));
        assert_eq!(created.routing_token, routing_token);
    }

    #[tokio::test]
    async fn admin_set_max_tunnels_unlocks_self_service_creation_for_one_specific_account() {
        // #214: remote asked to self-service-create MORE than the Standard
        // tier's one tunnel, for their own specific account, rather than the
        // operator running admin_provision_tunnel by hand for every additional
        // hostname. Proves: default stays 1 for everyone (existing behavior
        // unchanged), the admin route is gated the same way
        // admin_provision_tunnel already is, raising the limit targets ONLY
        // the named subject's account (a sibling account's own limit is
        // untouched), and the raised account can then really create a second
        // tunnel via the SAME customer-facing POST /portal/tunnels route
        // every Standard-tier account already uses -- no new/parallel
        // creation path.
        let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let secret = [0x88u8; 32];
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let enrollment = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let mesh_store = Arc::new(crate::edge_mesh::SqliteEdgeMesh::open_in_memory().unwrap());
        let app = portal_api_router(
            KEY,
            ledger,
            tunnels.clone(),
            enrollment,
            Arc::new(SqliteBootstrap::open_in_memory().unwrap()),
            "https://portal.example",
            None,
            None,
            None,
            EdgeMeshHandle::new(mesh_store, Arc::from("primary")),
            Some(secret),
        );

        let remote = "remote-maintainer";
        let sibling = "someone-else";

        // First tunnel: succeeds for anyone (default limit 1, 0 owned so far).
        assert_eq!(post_form(&app, "/portal/tunnels", remote, "name=first").await, StatusCode::SEE_OTHER);
        // Second tunnel for the SAME account, still at the default limit: refused.
        assert_eq!(post_form(&app, "/portal/tunnels", remote, "name=second").await, StatusCode::FORBIDDEN);

        let set_max = |subject: &str, max: u32, token_header: Option<String>| {
            let app = app.clone();
            let mut req = Request::post(format!("/admin/accounts/{subject}/max-tunnels")).header("content-type", "application/json");
            if let Some(t) = token_header {
                req = req.header("x-ct-admin-token", t);
            }
            let req = req.body(Body::from(format!(r#"{{"max":{max}}}"#))).unwrap();
            async move { app.oneshot(req).await.unwrap() }
        };

        // Gated the same way admin_provision_tunnel already is.
        assert_eq!(set_max(remote, 3, None).await.status(), StatusCode::UNAUTHORIZED, "no token -> refused");
        assert_eq!(set_max(remote, 3, Some(hex(&[0x11u8; 32]))).await.status(), StatusCode::UNAUTHORIZED, "wrong token -> refused");
        assert_eq!(set_max(remote, 3, Some(hex(&secret))).await.status(), StatusCode::OK);

        // Now the SAME account's second attempt succeeds (0->1 already owned,
        // 1 < 3), and a third also succeeds (2 < 3).
        assert_eq!(post_form(&app, "/portal/tunnels", remote, "name=second").await, StatusCode::SEE_OTHER, "raised limit unlocks a second tunnel");
        assert_eq!(post_form(&app, "/portal/tunnels", remote, "name=third").await, StatusCode::SEE_OTHER, "and a third, still under the raised limit of 3");
        assert_eq!(post_form(&app, "/portal/tunnels", remote, "name=fourth").await, StatusCode::FORBIDDEN, "the 4th hits the raised limit itself");

        // A sibling account's OWN limit is untouched -- still refused at 1.
        assert_eq!(post_form(&app, "/portal/tunnels", sibling, "name=first").await, StatusCode::SEE_OTHER);
        assert_eq!(post_form(&app, "/portal/tunnels", sibling, "name=second").await, StatusCode::FORBIDDEN, "sibling account was never raised");

        assert_eq!(tunnels.list_for_subject(remote).unwrap().len(), 3, "remote really owns 3 real tunnel rows, not just 3 successful responses");
    }

    #[tokio::test]
    async fn install_page_carries_the_tunnels_own_assigned_hostname_not_a_bare_mesh_tunnel() {
        // The agent should never have to copy its own already-assigned hostname
        // by hand from the tunnels list -- the install page's .env carries it
        // directly, for CT_AGENT_MODE=browser and `ct-agent certificate`.
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let enrollment = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let desec = ct_dns::provider::DesecClient::from_lookup(|k| match k {
            "DESEC_TOKEN" => Some("t".into()),
            "DESEC_DOMAIN" => Some("bunsenbrenner.org".into()),
            _ => None,
        })
        .unwrap();
        let mesh_store = Arc::new(crate::edge_mesh::SqliteEdgeMesh::open_in_memory().unwrap());
        let app = portal_api_router(
            KEY,
            ledger,
            tunnels.clone(),
            enrollment,
            Arc::new(SqliteBootstrap::open_in_memory().unwrap()),
            "https://portal.example",
            None,
            Some((desec, "1.2.3.4".to_string())),
            None,
            EdgeMeshHandle::new(mesh_store, Arc::from("primary")),
            None,
        );

        assert_eq!(get(&app, "/portal/tunnels", Some("alice")).await.0, StatusCode::OK);
        let tunnel = &tunnels.list_for_subject("alice").unwrap()[0];
        let expected_host = tunnel.hostname.clone().expect("DNS configured -- auto-assigned a hostname");

        let (status, html) = get(&app, &format!("/portal/tunnels/{}/install", tunnel.id), Some("alice")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            html.contains(&format!("CT_AGENT_HOSTNAME={expected_host}")),
            "carries this tunnel's own hostname, not left for the agent to copy by hand: {html}"
        );

        // A tunnel with no hostname (no DNS configured at all) must not show a
        // bogus/empty CT_AGENT_HOSTNAME line -- omitted entirely, not blank.
        let no_dns_tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let no_dns_mesh = Arc::new(crate::edge_mesh::SqliteEdgeMesh::open_in_memory().unwrap());
        let no_dns_app = portal_api_router(
            KEY,
            Arc::new(SqliteLedger::open_in_memory().unwrap()),
            no_dns_tunnels.clone(),
            Arc::new(SqliteEnrollment::open_in_memory().unwrap()),
            Arc::new(SqliteBootstrap::open_in_memory().unwrap()),
            "https://portal.example",
            None,
            None,
            None,
            EdgeMeshHandle::new(no_dns_mesh, Arc::from("primary")),
            None,
        );
        assert_eq!(get(&no_dns_app, "/portal/tunnels", Some("bob")).await.0, StatusCode::OK);
        let bare_tunnel = &no_dns_tunnels.list_for_subject("bob").unwrap()[0];
        assert!(bare_tunnel.hostname.is_none(), "no DNS configured -- no hostname assigned");
        let (_, bare_html) =
            get(&no_dns_app, &format!("/portal/tunnels/{}/install", bare_tunnel.id), Some("bob")).await;
        assert!(!bare_html.contains("CT_AGENT_HOSTNAME"), "omitted, not blank, when there's no hostname to carry");
    }

    #[tokio::test]
    async fn tunnel_hostname_creates_and_deletes_its_dns_a_record() {
        // #38 DL2: set a hostname -> A record created at the edge IP; revoke ->
        // A record cleared, so no orphaned DNS.
        use axum::extract::State as AxState;
        use axum::routing::patch;
        use std::sync::Mutex;

        let bodies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let mock = Router::new()
            .route(
                "/domains/:domain/rrsets/",
                patch(|AxState(b): AxState<Arc<Mutex<Vec<String>>>>, body: String| async move {
                    b.lock().unwrap().push(body);
                    StatusCode::OK
                }),
            )
            .with_state(bodies.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });

        let desec = ct_dns::provider::DesecClient::from_lookup(|k| match k {
            "DESEC_TOKEN" => Some("t".into()),
            "DESEC_DOMAIN" => Some("bunsenbrenner.org".into()),
            "DESEC_API_BASE" => Some(format!("http://{addr}")),
            _ => None,
        })
        .unwrap();

        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let enrollment = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let app = portal_api_router(
            KEY,
            ledger,
            tunnels.clone(),
            enrollment,
            Arc::new(SqliteBootstrap::open_in_memory().unwrap()),
            "https://portal.example",
            None,
            Some((desec, "45.133.9.145".to_string())),
            None,
            test_edge_mesh(),
            None,
        );

        // Viewing the tunnels page auto-provisions the tunnel with its auto-assigned
        // hostname -> an A record for that hostname's label, pointing at the edge IP.
        assert_eq!(get(&app, "/portal/tunnels", Some("alice")).await.0, StatusCode::OK);
        let tunnel = &tunnels.list_for_subject("alice").unwrap()[0];
        let id = tunnel.id.clone();
        let subname = tunnel
            .hostname
            .as_deref()
            .expect("auto-assigned a hostname")
            .split('.')
            .next()
            .unwrap()
            .to_string();
        assert!(
            bodies.lock().unwrap().iter().any(|x| x.contains(&format!("\"subname\":\"{subname}\""))
                && x.contains("\"type\":\"A\"")
                && x.contains("45.133.9.145")),
            "A record created on hostname-set"
        );

        // Revoke -> A record cleared (empty records list).
        post_form(&app, &format!("/portal/tunnels/{id}/delete"), "alice", "").await;
        assert!(
            bodies.lock().unwrap().iter().any(|x| x.contains(&format!("\"subname\":\"{subname}\""))
                && x.contains("\"records\":[]")),
            "A record cleared on revoke"
        );
    }

    #[tokio::test]
    async fn create_tunnel_rejects_an_empty_name() {
        let app = test_app();
        assert_eq!(
            post_form(&app, "/portal/tunnels", "alice", "name=%20").await,
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn dns_label_from_sanitizes_arbitrary_names_into_valid_labels() {
        // #226-tiers: the hostname is now auto-assigned from the tunnel name, not
        // typed by the user, so it must always sanitize into something DNS-valid
        // rather than rejecting a "bad" name outright (there's no form to reject on).
        assert_eq!(dns_label_from("My Cool App!!"), "my-cool-app");
        assert_eq!(dns_label_from("...."), "tunnel", "an all-invalid name falls back, never empty");
        assert_eq!(dns_label_from(""), "tunnel");
        assert_eq!(dns_label_from("a..b"), "a-b", "collapses runs of separators, no empty labels");
    }

    #[test]
    fn auto_hostname_is_deterministic_and_account_scoped() {
        // Idempotent: revoking and re-viewing (tunnels_page) must land the same
        // account back on the same hostname, not a fresh random one each time.
        let h1 = auto_hostname("bunsenbrenner.org", "site", "alice");
        assert_eq!(h1, auto_hostname("bunsenbrenner.org", "site", "alice"), "deterministic per (name, subject)");
        assert_ne!(
            h1,
            auto_hostname("bunsenbrenner.org", "site", "bob"),
            "different accounts never collide on the same default name"
        );
        assert!(h1.ends_with(".bunsenbrenner.org"));
        assert!(h1.starts_with("site-"));
    }

    #[tokio::test]
    async fn install_page_is_owner_only_and_surfaces_a_genuinely_working_path() {
        let app = test_app();
        post_form(&app, "/portal/tunnels", "alice", "name=web").await;
        let id = first_id(&get(&app, "/portal/tunnels", Some("alice")).await.1);

        // Non-owner (bob) is refused; unauthenticated is bounced.
        assert_eq!(
            get(&app, &format!("/portal/tunnels/{id}/install"), Some("bob")).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get(&app, &format!("/portal/tunnels/{id}/install"), None).await.0,
            StatusCode::SEE_OTHER
        );

        // Owner sees the env-carried tokens.
        let (status, html) = get(&app, &format!("/portal/tunnels/{id}/install"), Some("alice")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("CT_AGENT_JOIN_TOKEN="), "join token carried via env");
        assert!(html.contains("CT_AGENT_TOKEN="), "tunnel routing token carried via env (#27 RB2)");
        assert!(html.contains("single-use") || html.contains("Single-use"), "warns token is single-use");
        // #69 T69.3: the page must frame WHERE to run the command (on the origin,
        // not the browsing device) and signpost recovery for a lost single-use
        // token (reopen the page for a fresh one).
        assert!(
            html.contains("machine you want to expose"),
            "explains the command runs on the origin, not the browsing device"
        );
        assert!(
            html.contains("reopen this Install page"),
            "signposts lost-token recovery (a fresh token per visit)"
        );
        // #75: /install.sh + /install.ps1 don't exist yet, so their one-liners must
        // NOT be shown as if they worked -- the page surfaces only the genuinely
        // working manual path, tucked behind a <details> disclosure, not the tokens
        // themselves (those stay visible up front).
        assert!(!html.contains("curl -fsSL"), "no non-functional one-liner shown");
        assert!(!html.contains("irm "), "no non-functional PowerShell one-liner shown");
        assert!(
            html.contains("<details>") && html.contains("<summary>"),
            "the how-to-run steps are collapsible, not dumped inline"
        );
        assert!(
            html.contains("Build") && html.contains("ct-agent onboard"),
            "surfaces the working manual onboarding path with the tokens"
        );
        // The manual path must be genuinely runnable today: a real hermetic Docker
        // build command (no Rust toolchain assumed) and the correct env var names
        // ct-agent's onboard flow actually reads (CT_AGENT_CP_URL/CT_AGENT_EDGE),
        // not just a vague pointer to "the onboarding guide".
        assert!(
            html.contains("docker run") && html.contains("cargo build --release -p ct-agent"),
            "gives a real, working build command, not just a link"
        );
        assert!(
            html.contains("CT_AGENT_CP_URL=https://portal.example"),
            "carries the real control-plane URL, not a placeholder"
        );
        assert!(
            html.contains("CT_AGENT_EDGE=portal.example:4433"),
            "carries the real edge host:mesh-port, not a placeholder"
        );
        // A real onboarding attempt hung forever waiting for /shared/edge-cert.der:
        // without CT_AGENT_EDGE_CERT_URL, ct-agent's cert fetch falls back to
        // polling a shared-docker-volume path that doesn't exist for an external
        // (non-docker-compose) agent, and waits indefinitely by design (main.rs) --
        // the fix is this page must always set it, not a behavior change to the
        // fallback itself (other deployments rely on that indefinite wait).
        assert!(
            html.contains("CT_AGENT_EDGE_CERT_URL=https://portal.example"),
            "sets the cert URL so an external agent self-fetches the CA root instead of \
             hanging forever waiting for the shared-volume path"
        );
        assert!(
            html.contains(".env"),
            "advises copying the tokens into a .env file on the exposing machine"
        );
        assert!(
            html.contains("copyCode(this)") && html.matches("copy-btn").count() >= 3,
            "every code block (tokens + build + run) has a copy button"
        );
        // The tokens section reads before the (collapsible) how-to-run steps.
        assert!(
            html.find("Save your tunnel's tokens").unwrap() < html.find("<details>").unwrap(),
            "the tokens are the first thing shown, ahead of the collapsible how-to"
        );
    }

    #[tokio::test]
    async fn grants_are_owner_managed_via_http() {
        let app = test_app();
        post_form(&app, "/portal/tunnels", "alice", "name=web").await;
        let id = first_id(&get(&app, "/portal/tunnels", Some("alice")).await.1);

        // Non-owner cannot even view the sharing page.
        assert_eq!(
            get(&app, &format!("/portal/tunnels/{id}/grants"), Some("bob")).await.0,
            StatusCode::NOT_FOUND
        );
        // Non-owner cannot grant.
        assert_eq!(
            post_form(&app, &format!("/portal/tunnels/{id}/grants"), "bob", "grantee=mallory").await,
            StatusCode::NOT_FOUND
        );

        // Owner grants bob, then sees him listed.
        assert_eq!(
            post_form(&app, &format!("/portal/tunnels/{id}/grants"), "alice", "grantee=bob").await,
            StatusCode::SEE_OTHER
        );
        let (status, html) = get(&app, &format!("/portal/tunnels/{id}/grants"), Some("alice")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("bob"), "grantee listed");

        // Owner revokes bob -> no longer listed.
        assert_eq!(
            post_form(&app, &format!("/portal/tunnels/{id}/grants/bob/delete"), "alice", "").await,
            StatusCode::SEE_OTHER
        );
        let (_s, after) = get(&app, &format!("/portal/tunnels/{id}/grants"), Some("alice")).await;
        assert!(after.contains("Not shared with anyone"), "grant removed");
    }

    #[tokio::test]
    async fn a_grant_lets_the_grantee_see_and_install_the_shared_tunnel() {
        // #29 fix: grants have real effect — the grantee sees the tunnel (read-only)
        // and is authorized to install an agent for it; a non-grantee gets neither.
        let app = test_app();
        post_form(&app, "/portal/tunnels", "alice", "name=web").await;
        let id = first_id(&get(&app, "/portal/tunnels", Some("alice")).await.1);
        assert_eq!(
            post_form(&app, &format!("/portal/tunnels/{id}/grants"), "alice", "grantee=bob").await,
            StatusCode::SEE_OTHER
        );

        // bob sees the shared tunnel, marked, without owner actions. Key on the
        // tunnel's unique id (its install row), not the name — a common word like
        // "web" also appears in the create-form help text (#69 T69.1).
        let (_s, bob_list) = get(&app, "/portal/tunnels", Some("bob")).await;
        assert!(
            bob_list.contains(&format!("/portal/tunnels/{id}/install"))
                && bob_list.contains("shared with you"),
            "grantee sees the shared tunnel row"
        );
        assert!(!bob_list.contains(&format!("/portal/tunnels/{id}/delete")), "no revoke for a grantee");
        // ...and can install an agent for it (authorized, not just owner).
        assert_eq!(
            get(&app, &format!("/portal/tunnels/{id}/install"), Some("bob")).await.0,
            StatusCode::OK
        );

        // carol (no grant) sees nothing and cannot install. Key on the tunnel's
        // unique install row, not the name "web" (now a substring of the form help).
        assert!(
            !get(&app, "/portal/tunnels", Some("carol"))
                .await
                .1
                .contains(&format!("/portal/tunnels/{id}/install")),
            "non-grantee sees no row for the tunnel"
        );
        assert_eq!(
            get(&app, &format!("/portal/tunnels/{id}/install"), Some("carol")).await.0,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn add_grant_rejects_empty_subject() {
        let app = test_app();
        post_form(&app, "/portal/tunnels", "alice", "name=web").await;
        let id = first_id(&get(&app, "/portal/tunnels", Some("alice")).await.1);
        assert_eq!(
            post_form(&app, &format!("/portal/tunnels/{id}/grants"), "alice", "grantee=%20").await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn install_mints_a_fresh_single_use_token_each_request() {
        let app = test_app();
        post_form(&app, "/portal/tunnels", "alice", "name=web").await;
        let id = first_id(&get(&app, "/portal/tunnels", Some("alice")).await.1);
        let extract = |h: &str| {
            h.split("CT_AGENT_JOIN_TOKEN=")
                .nth(1)
                .and_then(|s| s.split([' ', '<']).next())
                .unwrap()
                .to_string()
        };
        let a = extract(&get(&app, &format!("/portal/tunnels/{id}/install?os=linux"), Some("alice")).await.1);
        let b = extract(&get(&app, &format!("/portal/tunnels/{id}/install?os=linux"), Some("alice")).await.1);
        assert_ne!(a, b, "a fresh token is minted per request");
        assert!(!a.is_empty());
    }

    #[tokio::test]
    async fn channel_claim_requires_a_verified_session_email_on_the_allowlist_248() {
        use crate::portal::sign_session_with_email_for_test;
        use crate::storage::SqliteChannelStore;
        use ct_common::channel::{member_noise_attest_bytes, ChannelId};
        use ed25519_dalek::{Signer, SigningKey};

        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let ch = ChannelId([0x5cu8; 32]);
        assert!(channels.register_channel(&ch, &[0x22u8; 32], "alice-owner").unwrap());
        assert!(channels.allowlist_add(&ch, "alice-owner", "nat@example.com", 1_000).unwrap());
        let app = channel_claim_router(KEY, channels.clone());

        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let holder_sk = SigningKey::from_bytes(&[0xc3u8; 32]);
        let holder_bytes = holder_sk.verifying_key().to_bytes();
        let noise = [0xd4u8; 32];
        let attest = holder_sk.sign(&member_noise_attest_bytes(&ch, &holder_bytes, &noise)).to_bytes();
        let body = |holder: &[u8; 32], noise: &[u8; 32], attest: &[u8; 64]| {
            serde_json::json!({
                "holder": hex(holder),
                "noise_pubkey": hex(noise),
                "noise_attestation": hex(attest),
            })
            .to_string()
        };
        let ch_hex = hex(&ch.0);
        let post = |cookie: Option<String>, body: String| {
            let mut req = Request::post(format!("/portal/channels/{ch_hex}/claim")).header("content-type", "application/json");
            if let Some(c) = &cookie {
                req = req.header("cookie", c.clone());
            }
            app.clone().oneshot(req.body(Body::from(body)).unwrap())
        };

        // No session at all -> 401.
        assert_eq!(
            post(None, body(&holder_bytes, &noise, &attest)).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        // A session with NO verified email (plain `sign_session_for_test`) -> 403.
        let unverified_cookie = format!("ct_portal_session={}", sign_session_for_test(KEY, "someone"));
        assert_eq!(
            post(Some(unverified_cookie), body(&holder_bytes, &noise, &attest)).await.unwrap().status(),
            StatusCode::FORBIDDEN,
            "no verified email on the session -> can't claim"
        );

        // A verified email NOT on the allow-list -> 403, and no member is recorded.
        let stranger_cookie =
            format!("ct_portal_session={}", sign_session_with_email_for_test(KEY, "stranger", "stranger@example.com"));
        assert_eq!(
            post(Some(stranger_cookie), body(&holder_bytes, &noise, &attest)).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        assert!(!channels.is_member(&ch, &holder_bytes).unwrap());

        // The allow-listed verified email succeeds and becomes a real member.
        let allowed_cookie =
            format!("ct_portal_session={}", sign_session_with_email_for_test(KEY, "nat-subject", "nat@example.com"));
        let resp = post(Some(allowed_cookie.clone()), body(&holder_bytes, &noise, &attest)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(channels.is_member(&ch, &holder_bytes).unwrap());

        // A forged/unattested Noise key is rejected even for an allow-listed email (#101).
        let other_holder = [0x99u8; 32];
        let s = post(Some(allowed_cookie), body(&other_holder, &noise, &[0u8; 64])).await.unwrap().status();
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert!(!channels.is_member(&ch, &other_holder).unwrap());
    }

    #[tokio::test]
    async fn claim_page_renders_the_form_when_logged_in_and_claims_via_the_html_form_248() {
        use crate::portal::sign_session_with_email_for_test;
        use crate::storage::SqliteChannelStore;
        use ct_common::channel::{member_noise_attest_bytes, ChannelId};
        use ed25519_dalek::{Signer, SigningKey};

        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let ch = ChannelId([0x7au8; 32]);
        assert!(channels.register_channel(&ch, &[0x22u8; 32], "alice-owner").unwrap());
        assert!(channels.allowlist_add(&ch, "alice-owner", "nat@example.com", 1_000).unwrap());
        let app = channel_claim_router(KEY, channels.clone());
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let ch_hex = hex(&ch.0);

        // Logged out -> bounced to the portal, not the form.
        let (status, _) = get(&app, &format!("/portal/channels/{ch_hex}/claim"), None).await;
        assert_eq!(status, StatusCode::SEE_OTHER);

        // Logged in -> the form renders with the channel pre-filled.
        let (status, html) = get(&app, &format!("/portal/channels/{ch_hex}/claim"), Some("nat-subject")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains(&ch_hex), "channel hex is pre-filled into the form");
        assert!(html.contains("name=\"holder\""));
        let holder_sk = SigningKey::from_bytes(&[0xc3u8; 32]);
        let holder_bytes = holder_sk.verifying_key().to_bytes();
        let noise = [0xd4u8; 32];
        let attest = holder_sk.sign(&member_noise_attest_bytes(&ch, &holder_bytes, &noise)).to_bytes();
        let form = format!(
            "holder={}&noise_pubkey={}&noise_attestation={}",
            hex(&holder_bytes),
            hex(&noise),
            hex(&attest)
        );

        // A verified session email NOT on the allow-list -> the page re-renders with an error, no member recorded.
        let stranger_cookie =
            format!("ct_portal_session={}", sign_session_with_email_for_test(KEY, "stranger", "stranger@example.com"));
        let resp = app
            .clone()
            .oneshot(
                Request::post(format!("/portal/channels/{ch_hex}/claim-form"))
                    .header("cookie", stranger_cookie)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "re-renders the page (not a raw 403) with the error inline");
        let body_text = String::from_utf8(to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap();
        assert!(body_text.contains("Could not claim"));
        assert!(!channels.is_member(&ch, &holder_bytes).unwrap());

        // The allow-listed verified email succeeds via the HTML form and becomes a real member.
        let allowed_cookie =
            format!("ct_portal_session={}", sign_session_with_email_for_test(KEY, "nat-subject", "nat@example.com"));
        let resp = app
            .clone()
            .oneshot(
                Request::post(format!("/portal/channels/{ch_hex}/claim-form"))
                    .header("cookie", allowed_cookie)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_text = String::from_utf8(to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap();
        assert!(body_text.contains("Claimed"));
        assert!(channels.is_member(&ch, &holder_bytes).unwrap());
    }

    #[tokio::test]
    async fn channels_page_lists_only_the_sessions_own_invitations_with_claim_status() {
        // Self-service discoverability (2026-08-01): GET /portal/channels is the
        // account page's "Your Channels" view -- must show only the logged-in
        // session's own (verified-email-matched) invitations, with correct
        // pending/claimed status, and never another subject's.
        use crate::portal::sign_session_with_email_for_test;
        use crate::storage::SqliteChannelStore;
        use ct_common::channel::ChannelId;

        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let ch_pending = ChannelId([0x91u8; 32]);
        let ch_claimed = ChannelId([0x92u8; 32]);
        let ch_other_user = ChannelId([0x93u8; 32]);
        let op = [0x22u8; 32];
        assert!(channels.register_channel(&ch_pending, &op, "owner").unwrap());
        assert!(channels.register_channel(&ch_claimed, &op, "owner").unwrap());
        assert!(channels.register_channel(&ch_other_user, &op, "owner").unwrap());
        assert!(channels.allowlist_add(&ch_pending, "owner", "nat@example.com", 1_000).unwrap());
        assert!(channels.allowlist_add(&ch_claimed, "owner", "nat@example.com", 1_100).unwrap());
        assert!(channels.allowlist_add(&ch_other_user, "owner", "someone-else@example.com", 1_200).unwrap());
        assert!(channels
            .claim_via_allowlist(&ch_claimed, "nat@example.com", &[0xc3u8; 32], &[0xd4u8; 32], &[0u8; 64], 2_000)
            .unwrap());

        let app = channel_claim_router(KEY, channels.clone());
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();

        // Logged out -> bounced, not a raw 401/500.
        let resp = app
            .clone()
            .oneshot(Request::get("/portal/channels").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        // Logged in as nat -> sees exactly her two invitations, correct status each,
        // and never the other user's channel (no cross-subject leakage).
        let nat_cookie =
            format!("ct_portal_session={}", sign_session_with_email_for_test(KEY, "nat-subject", "nat@example.com"));
        let resp = app
            .clone()
            .oneshot(Request::get("/portal/channels").header("cookie", nat_cookie).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8(to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap();
        assert!(body.contains(&hex(&ch_pending.0)), "pending channel listed");
        assert!(body.contains(&hex(&ch_claimed.0)), "claimed channel listed");
        assert!(!body.contains(&hex(&ch_other_user.0)), "another user's invitation never shown");
        assert!(body.contains("Pending"), "pending status shown");
        assert!(body.contains("Claimed"), "claimed status shown");
        // The pending channel gets a Claim link; a claimed one shouldn't repeat it.
        assert!(body.contains(&format!("/portal/channels/{}/claim", hex(&ch_pending.0))));

        // A different verified email with no invitations -> empty state, not an error.
        let stranger_cookie = format!(
            "ct_portal_session={}",
            sign_session_with_email_for_test(KEY, "stranger-subject", "stranger@example.com")
        );
        let resp = app
            .clone()
            .oneshot(Request::get("/portal/channels").header("cookie", stranger_cookie).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8(to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap();
        assert!(body.contains("No channel invitations yet"));
    }

    #[tokio::test]
    async fn topologies_page_bounces_when_logged_out_and_renders_the_shell_when_logged_in_237() {
        // #237-follow: /portal/topologies is the portal-discoverability shell for the
        // Topology Editor -- gated on the session cookie exactly like every other portal
        // page, and (unlike a bare 401/500) bounces a logged-out visitor to /portal.
        use crate::portal::sign_session_for_test;

        let app = topology_portal_router(KEY);

        let resp = app
            .clone()
            .oneshot(Request::get("/portal/topologies").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "logged out -> bounced, not a raw error");
        assert_eq!(resp.headers().get("location").unwrap(), "/portal");

        let cookie = format!("ct_portal_session={}", sign_session_for_test(KEY, "alice"));
        let resp = app
            .oneshot(Request::get("/portal/topologies").header("cookie", cookie).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8(to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap();
        assert!(body.contains("Your topologies"));
        // The shell drives everything via fetch() against the already dual-authed
        // /me/topologies* API -- proves it targets that endpoint, not a dead/placeholder one.
        assert!(body.contains("/me/topologies"));
        assert!(body.contains("New topology"));
        // #107-complex: both "owned" and "shared with me" sections are present.
        assert!(body.contains("/me/topologies/shared"), "fetches the shared-with-me listing too");
        assert!(body.contains("Shared with you"));
    }

    #[tokio::test]
    async fn login_allowlist_get_route_returns_the_real_owner_scoped_emails_in_order() {
        // Core request (2026-08-04): a JSON read side for a tunnel's login
        // allow-list, mirroring the existing owner-scoped write routes exactly --
        // login_allowlist_list already existed in the storage layer with zero
        // changes needed, so this is purely the HTTP wrapper being proven.
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "site", Some("alice.example")).unwrap();
        tunnels.login_allowlist_add("alice", &t.id, "bob@example.com", 1000).unwrap();
        tunnels.login_allowlist_add("alice", &t.id, "carol@example.com", 2000).unwrap();

        let app = login_gate_portal_router(KEY, tunnels, None);
        let resp = app
            .oneshot(
                Request::get(format!("/portal/tunnels/{}/login-allowlist", t.id))
                    .header("cookie", session_header("alice"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["emails"], serde_json::json!(["bob@example.com", "carol@example.com"]), "added-at order, matching login_allowlist_list");
    }

    #[tokio::test]
    async fn login_allowlist_get_route_requires_a_real_session_not_a_redirect() {
        // Deliberately a 401, unlike the sibling form-POST routes' Redirect --
        // this is a JSON endpoint for a fetch() caller (e.g. an address-book
        // view), which has no page to land on and needs a real status to branch on.
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let app = login_gate_portal_router(KEY, tunnels, None);
        let resp = app.oneshot(Request::get("/portal/tunnels/doesnotmatter/login-allowlist").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_allowlist_get_route_404s_for_a_tunnel_owned_by_someone_else() {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "site", Some("alice.example")).unwrap();
        tunnels.login_allowlist_add("alice", &t.id, "bob@example.com", 1000).unwrap();

        let app = login_gate_portal_router(KEY, tunnels, None);
        let resp = app
            .oneshot(
                Request::get(format!("/portal/tunnels/{}/login-allowlist", t.id))
                    .header("cookie", session_header("mallory"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "a real subject mismatch must not leak another owner's allow-list");
    }

    #[tokio::test]
    async fn login_allowlist_get_route_returns_an_empty_list_honestly_not_an_error() {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "site", Some("alice.example")).unwrap();
        let app = login_gate_portal_router(KEY, tunnels, None);
        let resp = app
            .oneshot(
                Request::get(format!("/portal/tunnels/{}/login-allowlist", t.id))
                    .header("cookie", session_header("alice"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["emails"], serde_json::json!([]));
    }
}
