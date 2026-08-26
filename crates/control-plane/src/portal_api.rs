//! Authenticated customer-portal API (#26–#29) — the logged-in surface behind
//! the SSO session (#25). Every endpoint resolves the caller's subject from the
//! signed session cookie via [`crate::portal::session_subject_for`]; without a
//! valid session the visitor is bounced to the portal shell. All pages are
//! server-rendered, self-contained, CSP-safe HTML, and every subject only ever
//! sees or changes their own data.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};


use crate::accounts::AccountId;
use crate::edge_mesh::EdgeMeshHandle;
use crate::portal::{escape, session_claims_for, session_subject_for};
use crate::storage::{GrantError, SqliteBootstrap, SqliteEnrollment, SqliteLedger, SqliteTunnelStore, SubjectTunnel};
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

/// #435: the same `OnceLock`-cached-client shape as [`edge_admin_http_client`] and
/// `portal::oidc_http_client`, for the Keycloak admin-provisioning call in the
/// allow-list-add handler below -- was a fresh `reqwest::Client::new()` per call
/// (no pooling, no timeout, so a hung Keycloak blocked the handler indefinitely).
fn keycloak_admin_http_client() -> reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT
        .get_or_init(|| edge_admin_http_client_with(std::time::Duration::from_secs(5)))
        .clone()
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
            // #606: chunk bytes rather than slicing `s` by index -- `HeaderValue::to_str()`
            // above already rejects any non-ASCII byte, so this specific site can never
            // actually receive a multi-byte char (confirmed, same header-vs-path-segment
            // distinction as #595's admin.rs), but the pattern is fixed here too for
            // consistency with every other hex-decode in this codebase.
            if s.len() != 64 {
                return None;
            }
            let mut out = [0u8; 32];
            for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
                out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
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
        Ok(crate::storage::CreateTunnelOutcome::Created(t)) => t,
        // #545: a taken hostname is a conflict the operator can act on, not an internal
        // error. It used to arrive as the unique index's failure and surface as a 500,
        // which says only "something broke" -- the same poor diagnosis reported for the
        // self-service path on 15.08. Name the hostname so the collision is readable.
        Ok(crate::storage::CreateTunnelOutcome::HostnameTaken) => {
            return (StatusCode::CONFLICT, format!("hostname already taken: {hostname}")).into_response()
        }
        Ok(crate::storage::CreateTunnelOutcome::OverLimit) => {
            // Unreachable here: this path deliberately bypasses the per-account limit
            // (that is what makes it the operator escape hatch). Answered explicitly
            // rather than with a catch-all, so a future change to `create` cannot make
            // this arm silently mean something else.
            return internal_error("admin_provision_tunnel/create", "unexpected OverLimit").into_response()
        }
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
/// (redirect to the shell when unauthenticated, 500 on a store error). Also
/// returns the session's verified email (#492), if any -- `None` when this
/// deployment's OIDC IdP never asserted one (or `CT_PORTAL_REQUIRE_VERIFIED_EMAIL`
/// is on and it wasn't verified); callers degrade gracefully by simply not
/// showing it, same as [`page`]'s own `email` parameter.
fn account_for_session(st: &ApiState, headers: &HeaderMap) -> Result<(String, AccountId, Option<String>), Response> {
    let claims = session_claims_for(&st.session_key, headers)
        .ok_or_else(|| Redirect::to("/portal").into_response())?;
    let account = st
        .ledger
        .account_for_subject(&claims.subject)
        .map_err(|e| internal_error("account_for_session", e).into_response())?;
    Ok((claims.subject, account, claims.email))
}

/// `GET /portal/account` (#26 PP2): the logged-in customer's account page —
/// account id, credit balance (Guthaben) and subject. Self-scoped: the subject
/// comes from the session, so a caller only ever sees their own account.
async fn account_page(State(st): State<ApiState>, headers: HeaderMap) -> Response {
    let (subject, account, email) = match account_for_session(&st, &headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let balance = st.ledger.balance(&account).unwrap_or(0);
    Html(account_html(
        &subject,
        &hex(&account.0),
        balance,
        st.account_console_url.as_deref(),
        email.as_deref(),
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
    let (_subject, account, email) = match account_for_session(&st, &headers) {
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
    Html(page("buy credits", &body, email.as_deref())).into_response()
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
        return (StatusCode::BAD_REQUEST, Html(page("account deletion", body, claims.email.as_deref()))).into_response();
    }
    let subject = claims.subject.as_str();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Real gap found live 2026-08-24: every step below discarded its Result
    // with a bare `let _ =` and no log line, unlike this same file's own
    // established `eprintln!("ct-cp: {context}: {e}")` convention used for
    // every comparable best-effort operation elsewhere (auto-provision,
    // edge authorize-host, DNS record create/delete, Keycloak provisioning).
    // A failed step here (SQLite busy/locked, disk error) silently left the
    // resource live -- for the allowlist/share-list removal below,
    // specifically, that means the deleted account's e-mail can remain on
    // OTHER accounts' channel/topology share lists, a real privacy residue
    // -- while the response unconditionally told the caller everything was
    // gone, with nothing anywhere to show an operator otherwise. Logging
    // each failure (not turning it into an HTTP error -- this cascade is
    // deliberately best-effort across independent resource kinds, one
    // failure must not abort the rest) makes it at least diagnosable.
    if let Ok(owned) = st.tunnels.list_for_subject(subject) {
        for t in owned {
            if let Err(e) = st.tunnels.revoke(subject, &t.id, now) {
                eprintln!("ct-cp: account deletion for {subject}: revoking tunnel {} failed: {e}", t.id);
            }
        }
    }

    if let Ok(owned) = st.channels.channels_owned_by(subject) {
        for c in owned {
            if let Err(e) = st.channels.delete_channel(subject, &c) {
                eprintln!("ct-cp: account deletion for {subject}: deleting channel {} failed: {e}", hex(&c.0));
            }
        }
    }

    if let Err(e) = st.topologies.delete_all_owned_by(subject) {
        eprintln!("ct-cp: account deletion for {subject}: deleting owned topologies failed: {e}");
    }

    if let Ok(owned) = st.networks.list(subject) {
        for id in owned {
            if let Err(e) = st.networks.delete(subject, &id) {
                eprintln!("ct-cp: account deletion for {subject}: deleting network {id} failed: {e}");
            }
        }
    }

    if let Ok(all) = st.pipelines.list() {
        for (id, owner) in all {
            if owner == subject {
                if let Err(e) = st.pipelines.unpublish(subject, &id) {
                    eprintln!("ct-cp: account deletion for {subject}: unpublishing pipeline {id} failed: {e}");
                }
            }
        }
    }

    if let Some(email) = claims.email.as_deref() {
        if let Err(e) = st.channels.remove_allowlist_entries_for_email(email) {
            eprintln!("ct-cp: account deletion for {subject}: removing channel allowlist entries for {email} failed: {e}");
        }
        if let Err(e) = st.topologies.remove_shares_by_email(email) {
            eprintln!("ct-cp: account deletion for {subject}: removing topology shares for {email} failed: {e}");
        }
    }

    let body = r#"<h1 class="deleted-check">Your account data has been deleted</h1>
<p class="help">Every tunnel, channel, topology, network and pipeline this account owned is gone,
along with your e-mail on anyone else's allow-list or share list. Your sign-in itself is
managed by Keycloak, not this page -- use <strong>Open Account Console</strong> from the account
page (while still signed in elsewhere) if you also want to remove your Keycloak login.</p>
<a class="btn" href="/portal/logout">Sign out</a>"#;
    let mut resp = Html(page("account deleted", body, claims.email.as_deref())).into_response();
    if let Ok(v) = axum::http::HeaderValue::from_str(&crate::portal::cleared_session_cookie(crate::portal::configured_cookie_domain().as_deref())) {
        resp.headers_mut().append(axum::http::header::SET_COOKIE, v);
    }
    resp
}

// ===== ADR-0025: `/admin-ui/*` -- admin-identity-gated account/user operations =====
//
// Every route below requires a verified admin session (`admin_ui_authed`, wrapping
// `admin_identity::admin_session_from_headers`), NOT the shared `x-ct-admin-token`
// the pre-existing `/admin/*` routes above use -- that token stays for edge-to-edge
// internal calls (ADR-0025 task framing), this surface is what a real admin-console
// UI session drives. Every successful mutation is recorded via `audit`
// (`crate::audit_log::SqliteAuditLog`) -- ADR-0025 Decision 6's "operator must be
// able to see everything" convention applied to the admin surface itself.

/// Shared state for the `/admin-ui/*` routes. Kept as its own router/state
/// (mirrors [`AccountDeleteState`]'s own reasoning) rather than widening `ApiState`:
/// `ApiState` is built once in `portal_api_router` and exercised by many pre-existing
/// tests that construct it directly with a fixed field set, and the admin-identity/
/// audit-log values this needs don't exist at that call site's callers before
/// ADR-0025.
#[derive(Clone)]
struct AdminUiState {
    session_key: Arc<[u8]>,
    admin: Arc<crate::admin_identity::AdminIdentity>,
    audit: Arc<crate::audit_log::SqliteAuditLog>,
    ledger: Arc<SqliteLedger>,
    tunnels: Arc<SqliteTunnelStore>,
    channels: Arc<crate::storage::SqliteChannelStore>,
    topologies: Arc<crate::storage::SqliteTopologyStore>,
    networks: Arc<crate::storage::SqliteNetworkStore>,
    pipelines: Arc<crate::storage::SqlitePipelineRegistry>,
    /// ADR-0025 Decision 4: the onboarded-zone registry.
    managed_domains: Arc<crate::storage::SqliteManagedDomains>,
    /// ADR-0025 Decision 4/6: everything else the domain/hostname routes need.
    domain_admin: DomainAdminConfig,
    /// ADR-0025 Decision 6: everything the read-only observability routes
    /// (`/admin-ui/traffic`, `/admin-ui/tunnels`, `/admin-ui/health`) need.
    observability: ObservabilityConfig,
}

/// ADR-0025 Decision 4/6: config for the domain/hostname admin routes, bundled
/// into one struct (rather than five more positional params on
/// [`admin_ui_router`]) so a future field addition doesn't ripple through
/// every call site's positional argument list.
#[derive(Clone, Default)]
pub struct DomainAdminConfig {
    /// Edge admin API base + shared token (`CT_CP_EDGE_ADMIN_URL`/`_TOKEN`) --
    /// same config [`portal_api_router`]'s own `edge_admin` param takes,
    /// reused here for the hostname-disable route's revoke call.
    pub edge_admin: Option<(String, String)>,
    /// The public IP a newly onboarded zone's A records should point at
    /// (`CT_CP_DNS_EDGE_IP`) -- same value `portal_api_router`'s own DNS
    /// autopilot uses for auto-assigned Standard-tier hostnames.
    pub dns_edge_ip: Option<String>,
    /// The deSEC API token (`DESEC_TOKEN`). Kept as a raw value here (not a
    /// pre-built `DesecClient`) because [`DesecClient`] is bound to exactly
    /// ONE zone at construction (`DESEC_DOMAIN`) -- onboarding a NEW zone
    /// needs a fresh, differently-zoned client per call
    /// ([`desec_client_for_zone`]), built from this token.
    pub desec_token: Option<String>,
    /// `DESEC_API_BASE`, if the operator overrode the default.
    pub desec_api_base: Option<String>,
    /// Subdomain cert issuance config (`POST /admin-ui/domains/:zone/hostnames`)
    /// -- `None` when `CT_CP_LIB_ACME_PATH` isn't configured, in which case
    /// that route `503`s with a clear reason instead of trying and failing
    /// opaquely partway through a subprocess call.
    pub managed_cert: Option<ManagedCertConfig>,
    /// Front-door cert file paths for the expiry dashboard (`GET
    /// /admin-ui/certs`) -- each `None` renders as `NotConfigured`, never
    /// silently omitted from the response.
    pub front_door_certs: FrontDoorCertPaths,
    /// This deployment's own root domain (`CT_CP_PLATFORM_ZONE`, e.g.
    /// `bunsenbrenner.org`) -- deliberately separate from `managed_domains`
    /// (the customer-onboarded-zone registry `POST /admin-ui/domains` writes
    /// to). The platform's own zone was never "onboarded" through that flow
    /// (it predates this admin console and isn't a customer tenant), so it's
    /// absent from that table by design -- but an operator looking at
    /// `/admin-ui/domains` reasonably expects to see the domain the whole
    /// platform actually runs on somewhere on that page (operator feedback,
    /// 2026-08-26: "why don't I see bunsenbrenner.org?"). `None` when unset
    /// reproduces the exact pre-existing behavior (no platform row rendered,
    /// just the explanatory caption) -- purely additive, opt-in config.
    pub platform_zone: Option<String>,
}

/// Where + how to issue a subdomain cert under a managed zone
/// ([`crate::cert_issuer::issue_cert`]'s config, plus the base directory
/// individual hostnames' cert dirs nest under).
#[derive(Clone)]
pub struct ManagedCertConfig {
    pub acme: crate::cert_issuer::AcmeConfig,
    pub cert_base_dir: String,
}

/// Configured front-door cert file paths this control-plane process can read
/// directly off its own filesystem (mirrors `CT_CP_EDGE_CERT_PATH`'s existing
/// shared-volume-with-the-edge convention, `service.rs`) -- `GET
/// /admin-ui/certs`'s fixed four slots, before any per-managed-domain certs.
#[derive(Clone, Default)]
pub struct FrontDoorCertPaths {
    pub portal: Option<String>,
    pub auth: Option<String>,
    pub masque: Option<String>,
    pub admin_ui: Option<String>,
}

/// ADR-0025 Decision 6: config for the read-only observability routes
/// (`/admin-ui/traffic`, `/admin-ui/tunnels`, `/admin-ui/health`), bundled the
/// same way as [`DomainAdminConfig`] and for the same reason -- a future field
/// addition doesn't ripple through [`admin_ui_router`]'s already-long
/// positional argument list.
#[derive(Clone, Default)]
pub struct ObservabilityConfig {
    /// Which edge currently owns a token (ADR-0021's multi-edge ownership
    /// registry) -- `/admin-ui/tunnels`' `edge_id` column. `None` when this
    /// deployment never wires one up (a router built with `Default`, e.g. in
    /// tests that don't exercise this column).
    pub edge_mesh: Option<EdgeMeshHandle>,
    /// The edge's `/metrics` URL -- the SAME value `status_router`'s
    /// `CT_CP_EDGE_METRICS_URL` already reads (`service.rs`). `/admin-ui/health`
    /// derives the co-located `/healthz` URL from it (both live on the edge's
    /// `metrics_router`, `crates/edge/src/observe.rs`, on the same listener).
    pub edge_metrics_url: Option<String>,
    /// Operator feedback (2026-08-26): "mehr informationen ueber das system
    /// auf dem der cads tunnel gerade laeuft" -- which path `GET /admin-ui/
    /// system`'s disk-usage figure measures (`CT_CP_HOST_INFO_DISK_PATH`,
    /// `None` defaults to `/` inside [`crate::host_info::collect`] -- see its
    /// own doc for why `/` is right for every deployment this project ships).
    pub host_info_disk_path: Option<String>,
    /// Operator feedback (2026-08-26): the Accounts page should show each
    /// account's email and be searchable by it, not just by the opaque
    /// Keycloak subject id. The ledger's own `account_subjects` table has no
    /// email column (it's keyed purely on the OIDC `sub` claim -- see
    /// `service.rs`'s `subject_of`), so this is resolved live per page render
    /// via Keycloak's own Admin API instead of a schema change. `None` when
    /// `KeycloakAdminConfig::from_env()` didn't find a full config (the exact
    /// same config `authed_service_account_router`'s provisioning already
    /// needs, so on a deployment where THAT already works this needs no new
    /// env var) -- the Accounts page then falls back to subject-only search,
    /// same as before this field existed.
    pub keycloak_admin: Option<crate::keycloak_admin::KeycloakAdminConfig>,
}

/// Resolve + require an admin session for an `/admin-ui/*` handler — the one gate
/// every route below calls first (mirrors `admin_authed`'s role for the legacy
/// `/admin/*` shared-token routes, and `account_for_session`'s role for the
/// self-service `/portal/*` routes). `401`/`403` per `admin_session_from_headers`'s
/// own contract (no session / not verified vs. verified-but-not-an-admin).
fn admin_ui_authed(
    st: &AdminUiState,
    headers: &HeaderMap,
) -> Result<crate::admin_identity::AdminSession, Response> {
    crate::admin_identity::admin_session_from_headers(&st.session_key, &st.admin, headers)
}

// ===== ADR-0025 integration pass: server-rendered `/admin-ui/*` HTML pages =====
//
// Everything below renders what the JSON handlers above already compute/store --
// no new business logic, only view code, per this pass's own scope. Every page
// handler gates on [`admin_ui_page_authed`] (never the bare [`admin_ui_authed`]
// used by the JSON routes), so a logged-out or non-admin visitor always gets a
// clean redirect or a real rendered 403, never a bodyless status code.

/// Whether the caller is a top-level browser navigation expecting an HTML page, as
/// opposed to this same console's own `fetch()` calls (default `Accept: */*`, never
/// `text/html`) or a JSON API test/tool. Lets the four routes earlier ADR-0025
/// phases already shipped as JSON (`/admin-ui/traffic`, `/admin-ui/admins`,
/// `/admin-ui/domains`, `/admin-ui/certs`) serve BOTH their already-tested JSON
/// contract (default, preserved byte-for-byte -- see each handler's own early
/// `wants_html` branch) AND this pass's HTML page at the exact same path ADR-0025's
/// own task framing names, without renaming or duplicating either.
fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("text/html"))
        .unwrap_or(false)
}

/// The same admin-session gate as [`admin_ui_authed`], but for a browser-navigated
/// HTML page instead of a JSON API call: a page must never answer with a bare,
/// bodyless `401`/`403` -- no session at all becomes a redirect to the existing
/// Keycloak login entry point (`/portal/login`, the SAME Authorization Code flow
/// every other login on this deployment already uses -- nothing new invented here);
/// a verified-but-not-an-admin session becomes a real, rendered `403` page.
///
/// **Known limitation (ADR-0025 Decision 5 addendum, deliberately left open by
/// this integration pass):** `/portal/login` mints `ct_portal_session` host-only on
/// Portal's own hostname; Decision 5 serves the admin console from a DIFFERENT
/// hostname (`CT_EDGE_ADMIN_UI_HOST`). Per RFC 6265 a host-only cookie is never sent
/// to a different host, so today this redirect reaches the correct login FLOW but
/// does not yet leave behind a session `admin_session_from_headers` can read back on
/// THIS host -- an admin who completes it lands back at the Portal, not the console.
/// The addendum names two real fixes (widen `ct_portal_session` to a `Domain=`-scoped
/// cookie shared across the zone, mirroring `gate.rs`'s `CT_GATE_COOKIE_DOMAIN`; or
/// give admin-ui its own dedicated OIDC login + session, fully mirroring `gate.rs`'s
/// shape) and explicitly asks that the choice be weighed, not defaulted -- this
/// integration pass renders/wires what the previous four phases already built and
/// does not invent either fix. Every route gated by this function is fully correct
/// and independently testable regardless of which fix lands; only the end-to-end
/// "click login, land back on admin.<zone> signed in" path is blocked until then.
fn admin_ui_page_authed(
    st: &AdminUiState,
    headers: &HeaderMap,
) -> Result<crate::admin_identity::AdminSession, Response> {
    admin_ui_authed(st, headers).map_err(|resp| {
        if resp.status() == StatusCode::UNAUTHORIZED {
            Redirect::to("/portal/login").into_response()
        } else {
            admin_forbidden_page()
        }
    })
}

/// A real, rendered `403` for a verified session whose email just isn't in the
/// `admins` table -- distinct from [`admin_ui_page_authed`]'s `401` case (no
/// session at all, which redirects instead): this visitor IS logged in, just not
/// an admin, so the honest answer is "wrong account", not a login prompt that
/// would just loop them back here.
fn admin_forbidden_page() -> Response {
    (
        StatusCode::FORBIDDEN,
        Html(
            r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CADS-Tunnel Admin — access denied</title>
<style>
 body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;margin:0;background:#0e1116;color:#e6edf3;
      display:flex;min-height:100vh;align-items:center;justify-content:center;padding:1rem}
 .card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:2rem;max-width:440px;text-align:center}
 h1{font-size:1.3rem;margin:0 0 .6rem}
 p{color:#8b949e;font-size:.92rem;line-height:1.6}
 a{color:#5fb8ab}
</style></head><body>
<div class="card">
<h1>Access denied</h1>
<p>You're signed in, but this account isn't registered as a CADS-Tunnel admin.
Ask the super-admin to add your e-mail, or <a href="/portal">go back to the portal</a>.</p>
</div></body></html>"#
                .to_string(),
        ),
    )
        .into_response()
}

/// Shared page chrome for every `/admin-ui/*` HTML page -- deliberately its own
/// shell, not [`page`] (Portal's own nav points at `/portal/*`, a different surface
/// with different login and owner-scoped data; reusing it here would put customer
/// navigation on an admin page and vice versa). Same brand tokens/animations as
/// [`page`] (docs/design/tokens.md) so the console reads as part of one product.
fn admin_page(title: &str, session: &crate::admin_identity::AdminSession, body: &str) -> String {
    let role_badge = if session.is_super_admin {
        r#" <span class="badge super">super-admin</span>"#
    } else {
        ""
    };
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CADS-Tunnel Admin — {title}</title>
<style>
 :root{{--bg:#0e1116;--panel:#161b22;--border:#30363d;--text:#e6edf3;--muted:#9aa4b0;
       --accent:#d98a4f;--accent-hover:#e39a63;--accent-ink:#20130a;
       --accent2:#5fb8ab;--accent2-hover:#7cc9bd;
       --serif:ui-serif,Georgia,"Iowan Old Style","Palatino Linotype",serif}}
 body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;margin:0;background:var(--bg);color:var(--text);
      font-size:16px;line-height:1.55;
      display:flex;min-height:100vh;align-items:flex-start;justify-content:center;padding:2.5rem 1rem}}
 .card{{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:2rem;max-width:1100px;width:100%;
      animation:cardIn .32s ease-out}}
 @keyframes cardIn{{from{{opacity:0;transform:translateY(6px)}}to{{opacity:1;transform:translateY(0)}}}}
 @keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.35}}}}
 h1,h2{{font-family:var(--serif);font-weight:600;letter-spacing:-.01em}}
 h1{{font-size:1.6rem;margin:.1rem 0 1.1rem}} h2{{font-size:1.1rem;color:var(--muted);margin:1.5rem 0 .6rem}}
 nav{{display:flex;flex-wrap:wrap;align-items:center;gap:.3rem 1rem;margin-bottom:1.2rem;border-bottom:1px solid var(--border);padding-bottom:.9rem}}
 nav a{{color:var(--accent2);text-decoration:none;font-size:.92rem;font-weight:600;transition:color .15s ease}}
 nav a:hover{{color:var(--accent2-hover)}}
 nav .spacer{{flex:1 1 auto}}
 nav .signed-in-as{{color:var(--muted);font-size:.88rem}}
 nav .signed-in-as strong{{color:var(--text);font-weight:600}}
 .badge{{display:inline-block;padding:.1rem .5rem;border-radius:999px;font-size:.72rem;font-weight:700;vertical-align:middle}}
 .badge.super{{background:#2d1a00;color:#f0c674;border:1px solid #7d4e00}}
 .badge.blocked{{background:#3d1418;color:#ff9a9a;border:1px solid #6e2530}}
 .badge.ok{{background:#0d2818;color:#3fb950;border:1px solid #1f5c33}}
 .badge.warn{{background:#3d2e00;color:#f0c674;border:1px solid #7d4e00}}
 a.btn,button{{background:var(--accent);color:var(--accent-ink);border:0;border-radius:8px;padding:.5rem 1rem;
      font:inherit;font-weight:600;cursor:pointer;text-decoration:none;display:inline-block;
      transition:background .15s ease,transform .08s ease}}
 a.btn:hover,button:hover{{background:var(--accent-hover)}} a.btn:active,button:active{{transform:scale(.96)}}
 a.btn.sec,button.sec{{background:#21262d;border:1px solid var(--border);color:var(--text);font-weight:500}}
 a.btn.sec:hover,button.sec:hover{{background:#30363d}}
 a.btn.danger,button.danger{{background:#3d1418;border:1px solid #6e2530;color:#ff9a9a}}
 a.btn.danger:hover,button.danger:hover{{background:#5a1c22}}
 button:disabled{{opacity:.4;cursor:not-allowed}}
 table.data{{width:100%;border-collapse:collapse;margin:.4rem 0 1rem;font-size:.92rem}}
 table.data th,table.data td{{padding:.55rem .6rem;border-bottom:1px solid #21262d;text-align:left;vertical-align:top}}
 table.data th{{color:var(--muted);font-weight:600;font-size:.78rem;text-transform:uppercase;letter-spacing:.03em}}
 table.data tr:hover td{{background:#1c222b}}
 table.data code{{font-size:.86rem}}
 table.data th.sortable{{cursor:pointer;user-select:none;white-space:nowrap}}
 table.data th.sortable:hover{{color:var(--text)}}
 table.data th.sortable .sort-arrow{{display:inline-block;width:.9em;opacity:.55}}
 table.data th.sort-asc .sort-arrow::after{{content:"\25b2"}}
 table.data th.sort-desc .sort-arrow::after{{content:"\25bc"}}
 .status-dot{{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:.4rem;vertical-align:middle}}
 .status-dot.live{{background:var(--accent2);animation:pulse 1.6s ease-in-out infinite}}
 .status-dot.off{{background:var(--muted)}}
 .tier-rot{{color:#f85149}} .tier-gelb{{color:#f0c674}} .tier-gruen{{color:#3fb950}} .tier-muted{{color:var(--muted)}}
 input,select{{background:#0d1117;border:1px solid var(--border);color:var(--text);border-radius:8px;padding:.5rem;font:inherit}}
 input:focus,select:focus{{outline:none;border-color:var(--accent2)}}
 code{{background:#0d1117;border:1px solid var(--border);border-radius:6px;padding:.15rem .4rem}}
 form.inline{{display:inline;margin:0}}
 label{{display:block;margin:.7rem 0;font-size:.92rem}}
 .help{{color:var(--muted);font-size:.86rem;line-height:1.5}}
 p.help{{margin:.2rem 0 1rem}}
 .msg{{font-size:.88rem;margin:.3rem 0;min-height:1.2em}}
 .msg.err{{color:#ff9a9a}} .msg.ok{{color:#3fb950}}
 .section{{margin-bottom:2rem}}
 .kv{{display:flex;flex-wrap:wrap;gap:1.5rem;margin:.6rem 0 1rem}}
 .kv .stat{{min-width:120px}} .kv .stat .n{{font-family:var(--serif);font-size:1.5rem;display:block}}
 .kv .stat .l{{color:var(--muted);font-size:.8rem;text-transform:uppercase;letter-spacing:.03em}}
 @media (prefers-reduced-motion: reduce){{ *{{animation:none!important;transition:none!important}} }}
</style></head><body>
<div class="card">
<nav>
 <a href="/admin-ui/">Dashboard</a>
 <a href="/admin-ui/traffic">Traffic</a>
 <a href="/admin-ui/accounts">Accounts</a>
 <a href="/admin-ui/domains">Domains</a>
 <a href="/admin-ui/admins">Admins</a>
 <a href="/admin-ui/certs">Certs</a>
 <a href="/admin-ui/audit">Audit</a>
 <span class="spacer"></span>
 <span class="signed-in-as">Signed in as <strong>{email}</strong>{role_badge}</span>
 <a href="/admin-ui/logout">Sign out</a>
</nav>
{body}
</div>
<script>
 // Render every [data-ts] element's unix-seconds content as a local date/time --
 // avoids a chrono/humantime dependency for what is purely a display concern.
 document.querySelectorAll('[data-ts]').forEach(function(el){{
  var secs = parseInt(el.getAttribute('data-ts'), 10);
  if(!isNaN(secs) && secs > 0){{ el.textContent = new Date(secs*1000).toLocaleString(); }}
 }});
 // Every admin action is a JSON API call (Json<...> extractors, not Form<...>) --
 // this is the one shared fetch wrapper every page's own inline script below uses.
 function adminApi(method, url, body){{
  var opts = {{method: method}};
  if(body !== undefined){{ opts.headers = {{'Content-Type':'application/json'}}; opts.body = JSON.stringify(body); }}
  return fetch(url, opts).then(function(r){{
   if(r.ok) return r;
   return r.text().then(function(t){{ throw new Error(t || ('HTTP '+r.status)); }});
  }});
 }}
 document.addEventListener('submit', function(ev){{
  var form = ev.target;
  if(form.classList && form.classList.contains('confirm-danger')){{
   var msg = form.getAttribute('data-confirm') || 'Are you sure?';
   if(!window.confirm(msg)){{ ev.preventDefault(); }}
  }}
 }});
 // Click-to-sort for every table.data on the page (and any table a page's own
 // script builds later via innerHTML, e.g. traffic.html's two fetch()-populated
 // tables -- those call window.ctSortableInit(el) themselves right after setting
 // innerHTML). A column is skipped when its header has no text, or when any of
 // its body cells hold an interactive control (button/form/input) rather than
 // plain data -- sorting an "Actions" column by button label isn't useful and
 // risks confusing a click-to-sort with a click-to-act.
 function ctSortableInit(root){{
  var tables = root
   ? (root.matches && root.matches('table.data') ? [root] : Array.prototype.slice.call(root.querySelectorAll('table.data')))
   : Array.prototype.slice.call(document.querySelectorAll('table.data'));
  tables.forEach(function(table){{
   if(table.getAttribute('data-sortable-init')) return;
   table.setAttribute('data-sortable-init', '1');
   var headRow = table.tHead && table.tHead.rows[0];
   var tbody = table.tBodies[0];
   if(!headRow || !tbody) return;
   var bodyRows = Array.prototype.slice.call(tbody.rows);
   if(bodyRows.length < 2) return; // nothing meaningful to sort (0 or 1 rows, incl. a "none yet" placeholder)
   Array.prototype.forEach.call(headRow.cells, function(th, colIndex){{
    var text = (th.textContent || '').trim();
    var hasControl = bodyRows.some(function(r){{ var c = r.cells[colIndex]; return c && c.querySelector('button,form,input,a.btn'); }});
    if(!text || hasControl) return;
    th.classList.add('sortable');
    th.innerHTML = th.innerHTML + ' <span class="sort-arrow"></span>';
    th.addEventListener('click', function(){{ ctSortTable(table, colIndex, th, headRow); }});
   }});
  }});
 }}
 function ctSortTable(table, colIndex, th, headRow){{
  var tbody = table.tBodies[0];
  if(!tbody) return;
  var asc = !th.classList.contains('sort-asc');
  Array.prototype.forEach.call(headRow.cells, function(c){{ c.classList.remove('sort-asc', 'sort-desc'); }});
  th.classList.add(asc ? 'sort-asc' : 'sort-desc');
  var rows = Array.prototype.slice.call(tbody.rows);
  rows.sort(function(a, b){{
   var ca = a.cells[colIndex], cb = b.cells[colIndex];
   var av = ((ca && (ca.getAttribute('data-sort') || ca.textContent)) || '').trim();
   var bv = ((cb && (cb.getAttribute('data-sort') || cb.textContent)) || '').trim();
   var an = parseFloat(av.replace(/[,\s]/g, '')), bn = parseFloat(bv.replace(/[,\s]/g, ''));
   var bothNumeric = /^-?[\d.,]+$/.test(av) && /^-?[\d.,]+$/.test(bv) && !isNaN(an) && !isNaN(bn);
   var cmp = bothNumeric ? (an - bn) : av.toLowerCase().localeCompare(bv.toLowerCase());
   return asc ? cmp : -cmp;
  }});
  rows.forEach(function(r){{ tbody.appendChild(r); }});
 }}
 window.ctSortableInit = ctSortableInit;
 ctSortableInit();
</script>
</body></html>"#,
        title = escape(title),
        email = escape(&session.email),
        role_badge = role_badge,
        body = body,
    )
}

/// `GET /admin-ui/logout`: clears the admin session cookie (same name/HMAC key as
/// Portal's `ct_portal_session` -- [`crate::admin_identity::admin_session_from_headers`]
/// reads it via [`crate::portal::session_claims_for`]) and returns to the public
/// portal shell. Deliberately local (not `PortalOidc::end_session_redirect`, unlike
/// `portal::portal_logout`): this route has no `PortalOidc` config in scope, and
/// clearing this host's own cookie is the only thing an admin-console sign-out needs
/// to do (see [`admin_ui_page_authed`]'s doc for why the underlying session's origin
/// is still an open question this pass doesn't resolve).
async fn admin_ui_logout() -> Response {
    let mut resp = Redirect::to("/portal").into_response();
    if let Ok(v) = axum::http::HeaderValue::from_str(&crate::portal::cleared_session_cookie(crate::portal::configured_cookie_domain().as_deref())) {
        resp.headers_mut().append(axum::http::header::SET_COOKIE, v);
    }
    resp
}

// ===== end ADR-0025 integration pass shared page chrome =====

/// Build the `/admin-ui/*` router (ADR-0025): account credit/block/unblock/delete,
/// an admin-identity-gated mirror of the legacy max-tunnels unlock, and
/// admin-management (list/add/remove).
pub fn admin_ui_router(
    session_key: &[u8],
    admin: Arc<crate::admin_identity::AdminIdentity>,
    audit: Arc<crate::audit_log::SqliteAuditLog>,
    ledger: Arc<SqliteLedger>,
    tunnels: Arc<SqliteTunnelStore>,
    channels: Arc<crate::storage::SqliteChannelStore>,
    topologies: Arc<crate::storage::SqliteTopologyStore>,
    networks: Arc<crate::storage::SqliteNetworkStore>,
    pipelines: Arc<crate::storage::SqlitePipelineRegistry>,
    managed_domains: Arc<crate::storage::SqliteManagedDomains>,
    domain_admin: DomainAdminConfig,
    observability: ObservabilityConfig,
) -> Router {
    Router::new()
        .route("/admin-ui/accounts/:subject/credit", post(admin_ui_credit_account))
        .route("/admin-ui/accounts/:subject/block", post(admin_ui_block_account))
        .route("/admin-ui/accounts/:subject/unblock", post(admin_ui_unblock_account))
        .route("/admin-ui/accounts/:subject/delete", post(admin_ui_delete_account))
        .route("/admin-ui/accounts/:subject/max-tunnels", post(admin_ui_set_max_tunnels))
        .route("/admin-ui/admins", get(admin_ui_list_admins).post(admin_ui_add_admin))
        .route("/admin-ui/admins/:email", delete(admin_ui_remove_admin))
        // ADR-0025 Decision 4/6: hostname disable/enable + multi-domain onboarding
        // + cert-expiry dashboard. See each handler's own doc for its exact contract.
        .route("/admin-ui/hostnames/:host/disable", post(admin_ui_disable_hostname))
        .route("/admin-ui/hostnames/:host/enable", post(admin_ui_enable_hostname))
        .route("/admin-ui/hostnames/disabled", get(admin_ui_list_disabled_hostnames))
        .route("/admin-ui/domains", get(admin_ui_list_domains).post(admin_ui_register_domain))
        .route("/admin-ui/domains/:zone/hostnames", post(admin_ui_add_domain_hostname))
        .route("/admin-ui/certs", get(admin_ui_certs))
        // ADR-0025 Decision 6: read-only traffic/topology/health observability --
        // no mutation, no audit_log call (see each handler's own doc).
        .route("/admin-ui/traffic", get(admin_ui_traffic))
        .route("/admin-ui/tunnels", get(admin_ui_tunnels))
        .route("/admin-ui/health", get(admin_ui_health))
        .route("/admin-ui/system", get(admin_ui_system))
        // ADR-0025 integration pass: server-rendered HTML pages. `/admin-ui/traffic`,
        // `/admin-ui/admins`, `/admin-ui/domains`, `/admin-ui/certs` are ALREADY
        // routed above as JSON -- their handlers branch on `wants_html` internally
        // rather than being registered a second time here (axum has exactly one
        // handler per method+path). `/admin-ui/accounts` and `/admin-ui/audit` are
        // brand new paths (no prior JSON contract to preserve), so they're plain
        // HTML-only handlers.
        .route("/admin-ui/", get(admin_ui_dashboard))
        .route("/admin-ui/accounts", get(admin_ui_accounts_page))
        .route("/admin-ui/audit", get(admin_ui_audit_page))
        .route("/admin-ui/logout", get(admin_ui_logout))
        .with_state(AdminUiState {
            session_key: Arc::from(session_key.to_vec()),
            admin,
            audit,
            ledger,
            tunnels,
            channels,
            topologies,
            networks,
            pipelines,
            managed_domains,
            domain_admin,
            observability,
        })
}

#[derive(Deserialize)]
struct CreditReq {
    amount: u64,
}

#[derive(Serialize)]
struct CreditResp {
    balance: u64,
}

/// `POST /admin-ui/accounts/:subject/credit {amount}` (admin-identity-gated):
/// grant `amount` credits to `subject`'s account. Wraps `SqliteLedger::credit`
/// directly -- the same durable ledger the payment webhook credits -- no
/// payment-intent step; this IS the admin top-up.
async fn admin_ui_credit_account(
    State(st): State<AdminUiState>,
    headers: HeaderMap,
    Path(subject): Path<String>,
    Json(req): Json<CreditReq>,
) -> Response {
    let session = match admin_ui_authed(&st, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let account = match st.ledger.account_for_subject(&subject) {
        Ok(a) => a,
        Err(e) => return internal_error("admin_ui_credit_account/account_for_subject", e).into_response(),
    };
    let balance = match st.ledger.credit(&account, req.amount) {
        Ok(b) => b,
        Err(e) => return internal_error("admin_ui_credit_account/credit", e).into_response(),
    };
    let _ = st.audit.record(
        &session.email,
        "credit_grant",
        Some(&subject),
        Some(&format!("+{} credits (new balance {balance})", req.amount)),
    );
    Json(CreditResp { balance }).into_response()
}

/// `POST /admin-ui/accounts/:subject/block` (admin-identity-gated): the admin
/// console's block action. `SqliteLedger::debit`/`debit_and_record_issuance` (the
/// credit-gated token-issuance admission path) and `create_tunnel` above (the
/// self-service tunnel-creation admission path) both check this flag -- see
/// their doc comments; a block flag nobody checks is worthless.
async fn admin_ui_block_account(State(st): State<AdminUiState>, headers: HeaderMap, Path(subject): Path<String>) -> Response {
    admin_ui_set_blocked(st, headers, subject, true, "account_block").await
}

/// `POST /admin-ui/accounts/:subject/unblock` (admin-identity-gated): the inverse
/// of [`admin_ui_block_account`].
async fn admin_ui_unblock_account(State(st): State<AdminUiState>, headers: HeaderMap, Path(subject): Path<String>) -> Response {
    admin_ui_set_blocked(st, headers, subject, false, "account_unblock").await
}

async fn admin_ui_set_blocked(
    st: AdminUiState,
    headers: HeaderMap,
    subject: String,
    blocked: bool,
    action: &str,
) -> Response {
    let session = match admin_ui_authed(&st, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let account = match st.ledger.account_for_subject(&subject) {
        Ok(a) => a,
        Err(e) => return internal_error("admin_ui_set_blocked/account_for_subject", e).into_response(),
    };
    if let Err(e) = st.ledger.set_blocked(&account, blocked) {
        return internal_error("admin_ui_set_blocked/set_blocked", e).into_response();
    }
    let _ = st.audit.record(&session.email, action, Some(&subject), None);
    StatusCode::OK.into_response()
}

/// `POST /admin-ui/accounts/:subject/delete` (admin-identity-gated): the
/// admin-target-any-account variant of [`delete_account`] -- same resource
/// cascade (owned tunnels revoked; channels/topologies/networks/pipelines
/// deleted), PLUS the ledger account row itself removed
/// (`SqliteLedger::delete_account_for_subject`). Self-service `delete_account`
/// deliberately leaves that row (Keycloak still owns the caller's own identity,
/// and a returning login would just re-create it); an admin deleting someone
/// else's account has no such expectation, so this actually removes it.
///
/// Does **not** strip `subject`'s e-mail from other accounts' channel/topology
/// share lists the way [`delete_account`] strips the CALLER's own verified
/// e-mail — unlike that self-service path, an admin acting on a bare `subject`
/// string has no verified e-mail for that account in hand here (accounts are
/// pseudonymous by design, ADR-0012); scrubbing a specific e-mail from other
/// accounts' share lists once it's known is still available via the existing
/// self-service primitives (`remove_allowlist_entries_for_email`/
/// `remove_shares_by_email`).
async fn admin_ui_delete_account(
    State(st): State<AdminUiState>,
    headers: HeaderMap,
    Path(subject): Path<String>,
) -> Response {
    let session = match admin_ui_authed(&st, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Same best-effort, independently-logged cascade shape as `delete_account`
    // (2026-08-24 gap fix: log every step's failure, never `let _ =` it away).
    if let Ok(owned) = st.tunnels.list_for_subject(&subject) {
        for t in owned {
            if let Err(e) = st.tunnels.revoke(&subject, &t.id, now) {
                eprintln!("ct-cp: admin account deletion for {subject}: revoking tunnel {} failed: {e}", t.id);
            }
        }
    }
    if let Ok(owned) = st.channels.channels_owned_by(&subject) {
        for c in owned {
            if let Err(e) = st.channels.delete_channel(&subject, &c) {
                eprintln!("ct-cp: admin account deletion for {subject}: deleting channel {} failed: {e}", hex(&c.0));
            }
        }
    }
    if let Err(e) = st.topologies.delete_all_owned_by(&subject) {
        eprintln!("ct-cp: admin account deletion for {subject}: deleting owned topologies failed: {e}");
    }
    if let Ok(owned) = st.networks.list(&subject) {
        for id in owned {
            if let Err(e) = st.networks.delete(&subject, &id) {
                eprintln!("ct-cp: admin account deletion for {subject}: deleting network {id} failed: {e}");
            }
        }
    }
    if let Ok(all) = st.pipelines.list() {
        for (id, owner) in all {
            if owner == subject {
                if let Err(e) = st.pipelines.unpublish(&subject, &id) {
                    eprintln!("ct-cp: admin account deletion for {subject}: unpublishing pipeline {id} failed: {e}");
                }
            }
        }
    }
    if let Err(e) = st.ledger.delete_account_for_subject(&subject) {
        eprintln!("ct-cp: admin account deletion for {subject}: removing ledger row failed: {e}");
    }

    let _ = st.audit.record(&session.email, "account_delete", Some(&subject), None);
    StatusCode::OK.into_response()
}

/// `POST /admin-ui/accounts/:subject/max-tunnels {max}` (admin-identity-gated):
/// the admin-identity-gated mirror of [`admin_set_max_tunnels`] -- same effect
/// (raises/lowers `subject`'s tunnel-count limit), reachable by a verified admin
/// session instead of the shared `x-ct-admin-token`. The legacy
/// `/admin/accounts/:subject/max-tunnels` route stays mounted unchanged for
/// edge-to-edge/internal callers that only hold the shared token -- ADR-0025's
/// task framing keeps that mechanism for those callers rather than replacing it.
async fn admin_ui_set_max_tunnels(
    State(st): State<AdminUiState>,
    headers: HeaderMap,
    Path(subject): Path<String>,
    Json(req): Json<SetMaxTunnelsReq>,
) -> Response {
    let session = match admin_ui_authed(&st, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let account = match st.ledger.account_for_subject(&subject) {
        Ok(a) => a,
        Err(e) => return internal_error("admin_ui_set_max_tunnels/account_for_subject", e).into_response(),
    };
    if let Err(e) = st.ledger.set_max_tunnels(&account, req.max) {
        return internal_error("admin_ui_set_max_tunnels/set", e).into_response();
    }
    let _ = st
        .audit
        .record(&session.email, "max_tunnels_set", Some(&subject), Some(&format!("max={}", req.max)));
    StatusCode::OK.into_response()
}

#[derive(Serialize)]
struct AdminRowResp {
    email: String,
    added_by: Option<String>,
    added_at: i64,
}

/// `GET /admin-ui/admins` (admin-identity-gated): list current admins for the
/// admin-console UI to render. Any verified admin may view this (not
/// super-admin-only) -- knowing who else has admin access is not itself a
/// privileged mutation.
async fn admin_ui_list_admins(State(st): State<AdminUiState>, headers: HeaderMap) -> Response {
    if wants_html(&headers) {
        let session = match admin_ui_page_authed(&st, &headers) {
            Ok(s) => s,
            Err(resp) => return resp,
        };
        return match st.admin.list_admins() {
            Ok(rows) => Html(admin_admins_page_html(&session, &st.admin, &rows)).into_response(),
            Err(e) => internal_error("admin_ui_list_admins/html", e).into_response(),
        };
    }
    if let Err(resp) = admin_ui_authed(&st, &headers) {
        return resp;
    }
    match st.admin.list_admins() {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|r| AdminRowResp { email: r.email, added_by: r.added_by, added_at: r.added_at })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => internal_error("admin_ui_list_admins", e).into_response(),
    }
}

#[derive(Deserialize)]
struct AddAdminReq {
    email: String,
}

/// `POST /admin-ui/admins {email}` (admin-identity-gated, super-admin-only):
/// add a new admin. Requires the CALLER be the super-admin -- checked here (an
/// honest `403` before even calling `AdminIdentity::add_admin`, so a
/// non-super-admin gets a clear reason rather than a generic failure) AND again
/// inside `add_admin` itself (defense in depth, ADR-0025 Decision 2).
async fn admin_ui_add_admin(State(st): State<AdminUiState>, headers: HeaderMap, Json(req): Json<AddAdminReq>) -> Response {
    let session = match admin_ui_authed(&st, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if !session.is_super_admin {
        return (StatusCode::FORBIDDEN, "only the super-admin may add admins").into_response();
    }
    let email = req.email.trim();
    if email.is_empty() {
        return (StatusCode::BAD_REQUEST, "email is required").into_response();
    }
    match st.admin.add_admin(&session.email, email) {
        Ok(()) => {
            let _ = st.audit.record(&session.email, "admin_add", Some(email), None);
            StatusCode::OK.into_response()
        }
        Err(e) => (StatusCode::FORBIDDEN, e.to_string()).into_response(),
    }
}

/// `DELETE /admin-ui/admins/:email` (admin-identity-gated, super-admin-only):
/// remove an admin. Same super-admin gate as [`admin_ui_add_admin`];
/// `AdminIdentity::remove_admin` additionally refuses the super-admin's own row
/// unconditionally, regardless of who is asking (ADR-0025 Decision 2).
async fn admin_ui_remove_admin(State(st): State<AdminUiState>, headers: HeaderMap, Path(email): Path<String>) -> Response {
    let session = match admin_ui_authed(&st, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if !session.is_super_admin {
        return (StatusCode::FORBIDDEN, "only the super-admin may remove admins").into_response();
    }
    match st.admin.remove_admin(&session.email, &email) {
        Ok(()) => {
            let _ = st.audit.record(&session.email, "admin_remove", Some(&email), None);
            StatusCode::OK.into_response()
        }
        Err(e) => (StatusCode::FORBIDDEN, e.to_string()).into_response(),
    }
}

/// `GET /admin-ui/admins` HTML branch (ADR-0025 integration pass): the super-admin
/// row's Remove control is omitted SERVER-SIDE, not merely disabled or left for the
/// click to 403 -- the task's own requirement ("no delete control rendered for that
/// row at all, not just a server-side check") is stronger than "the click would be
/// refused", and this is the one place that guarantee actually lives. A non-super
/// viewer gets the identical list read-only, with an explicit reason the add/remove
/// form is missing rather than a button that would just 403 on click.
fn admin_admins_page_html(
    session: &crate::admin_identity::AdminSession,
    admin: &crate::admin_identity::AdminIdentity,
    rows: &[crate::storage::AdminRow],
) -> String {
    let mut table = String::from(
        r#"<table class="data"><thead><tr><th>E-mail</th><th>Added by</th><th>Added</th><th></th></tr></thead><tbody>"#,
    );
    for r in rows {
        let is_super = admin.is_super_admin(&r.email);
        let added_by = r.added_by.as_deref().unwrap_or("(startup seed)");
        let super_badge = if is_super { r#" <span class="badge super">super-admin</span>"# } else { "" };
        let action_cell = if is_super {
            r#"<span class="help">cannot be removed</span>"#.to_string()
        } else if session.is_super_admin {
            format!(
                r#"<form class="inline" data-email="{email}" onsubmit="return removeAdmin(event)"><button type="submit" class="danger">Remove</button></form>"#,
                email = escape(&r.email),
            )
        } else {
            String::new()
        };
        table.push_str(&format!(
            r#"<tr><td>{email}{super_badge}</td><td>{added_by}</td><td><span data-ts="{added_at}">{added_at}</span></td><td>{action_cell}</td></tr>"#,
            email = escape(&r.email),
            super_badge = super_badge,
            added_by = escape(added_by),
            added_at = r.added_at,
            action_cell = action_cell,
        ));
    }
    table.push_str("</tbody></table>");

    let manage_section = if session.is_super_admin {
        r#"<h2>Add an admin</h2>
<form id="addAdminForm" onsubmit="return addAdmin(event)">
 <label>E-mail (must be a Google-verified login) <input type="email" name="email" required></label>
 <button type="submit">Add admin</button>
</form>
<p class="msg" id="addMsg"></p>"#
            .to_string()
    } else {
        r#"<p class="help">Only the super-admin can add or remove other admins. You can see who
currently has access above; the add/remove form is hidden here rather than shown and refused.</p>"#
            .to_string()
    };

    let body = format!(
        r#"<h1>Admins</h1>
<p class="help">Every account that can reach this console. Access is bound to a verified Google
login (ADR-0025) -- there is no separate admin password.</p>
{table}
{manage_section}
<script>
function addAdmin(ev){{
 ev.preventDefault();
 var form = ev.target, msg = document.getElementById('addMsg');
 var email = form.email.value.trim();
 msg.className = 'msg'; msg.textContent = 'adding…';
 adminApi('POST', '/admin-ui/admins', {{email: email}})
  .then(function(){{ location.reload(); }})
  .catch(function(e){{ msg.className = 'msg err'; msg.textContent = 'failed: ' + e.message; }});
 return false;
}}
function removeAdmin(ev){{
 ev.preventDefault();
 var email = ev.target.getAttribute('data-email');
 if(!window.confirm('Remove admin access for ' + email + '?')) return false;
 adminApi('DELETE', '/admin-ui/admins/' + encodeURIComponent(email))
  .then(function(){{ location.reload(); }})
  .catch(function(e){{ window.alert('failed: ' + e.message); }});
 return false;
}}
</script>"#,
        table = table,
        manage_section = manage_section,
    );
    admin_page("admins", session, &body)
}

fn admin_ui_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `POST /admin-ui/hostnames/:host/disable` (admin-identity-gated): revoke
/// authorization for `host` AND prevent it being re-authorized until an
/// explicit [`admin_ui_enable_hostname`] reverses it.
///
/// Two independent effects, matching the task's own split:
/// 1. **Prevent future re-authorization** -- [`crate::storage::SqliteTunnelStore::
///    disable_hostname`] marks the row; the enforcer is `authorize_hostname`'s
///    own `is_hostname_disabled` check (the ADR's "flag needs an enforcer"
///    discipline, same shape as the blocked-account check).
/// 2. **Revoke the currently-live authorization**, if any -- reuses the exact
///    same edge machinery [`delete_tunnel`] already uses (`POST
///    /admin/revoke/:token` via [`edge_admin_http_client`]), looking the
///    routing token up via [`crate::storage::SqliteTunnelStore::
///    routing_token_for_hostname`]. Best-effort and logged like every other
///    edge-admin call in this file: a hostname with no live tunnel on it right
///    now still gets step 1 (there's simply nothing to revoke).
async fn admin_ui_disable_hostname(
    State(st): State<AdminUiState>,
    headers: HeaderMap,
    Path(host): Path<String>,
) -> Response {
    let session = match admin_ui_authed(&st, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let Some(host) = ct_common::normalize_hostname(&host) else {
        return (StatusCode::BAD_REQUEST, "invalid hostname").into_response();
    };
    if let Err(e) = st.tunnels.disable_hostname(&host, &session.email, admin_ui_now_secs()) {
        return internal_error("admin_ui_disable_hostname/disable_hostname", e).into_response();
    }

    let mut detail = "no live tunnel on this hostname to revoke".to_string();
    if let Some((edge_url, edge_token)) = &st.domain_admin.edge_admin {
        match st.tunnels.routing_token_for_hostname(&host) {
            Ok(Some(token)) => {
                let endpoint = format!("{}/admin/revoke/{}", edge_url.trim_end_matches('/'), token);
                match edge_admin_http_client()
                    .post(&endpoint)
                    .header("x-ct-admin-token", edge_token.as_str())
                    .send()
                    .await
                {
                    Ok(r) if r.status().is_success() => detail = "revoked the live tunnel on this hostname".to_string(),
                    Ok(r) => {
                        detail = format!("edge revoke returned {}", r.status());
                        eprintln!("ct-cp: admin_ui_disable_hostname: edge revoke for {host} returned {}", r.status());
                    }
                    Err(e) => {
                        let redacted = redact_routing_tokens(&e.to_string());
                        detail = format!("edge revoke failed: {redacted}");
                        eprintln!("ct-cp: admin_ui_disable_hostname: edge revoke for {host} failed: {redacted}");
                    }
                }
            }
            Ok(None) => {}
            Err(e) => eprintln!("ct-cp: admin_ui_disable_hostname: routing_token_for_hostname for {host} failed: {e}"),
        }
    }
    let _ = st.audit.record(&session.email, "hostname_disable", Some(&host), Some(&detail));
    StatusCode::OK.into_response()
}

/// `POST /admin-ui/hostnames/:host/enable` (admin-identity-gated): reverse
/// [`admin_ui_disable_hostname`]'s block. Deliberately does NOT re-push an
/// edge authorize-host call itself -- disabling revoked any live tunnel's
/// registration, so this only permits the NEXT ordinary authorize_hostname
/// call (the owner recreating the tunnel, or the admin re-provisioning it) to
/// succeed again.
async fn admin_ui_enable_hostname(State(st): State<AdminUiState>, headers: HeaderMap, Path(host): Path<String>) -> Response {
    let session = match admin_ui_authed(&st, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let Some(host) = ct_common::normalize_hostname(&host) else {
        return (StatusCode::BAD_REQUEST, "invalid hostname").into_response();
    };
    match st.tunnels.enable_hostname(&host) {
        Ok(was_disabled) => {
            let _ = st.audit.record(
                &session.email,
                "hostname_enable",
                Some(&host),
                Some(if was_disabled { "was disabled" } else { "was not disabled (no-op)" }),
            );
            StatusCode::OK.into_response()
        }
        Err(e) => internal_error("admin_ui_enable_hostname/enable_hostname", e).into_response(),
    }
}

#[derive(Serialize)]
struct DisabledHostnameResp {
    hostname: String,
    disabled_by: String,
    disabled_at: i64,
}

/// `GET /admin-ui/hostnames/disabled` (admin-identity-gated): every currently
/// admin-disabled hostname -- the console's own visibility into what it has
/// blocked, mirroring [`admin_ui_list_admins`]'s "any verified admin may view"
/// posture (viewing isn't itself a privileged mutation).
async fn admin_ui_list_disabled_hostnames(State(st): State<AdminUiState>, headers: HeaderMap) -> Response {
    if let Err(resp) = admin_ui_authed(&st, &headers) {
        return resp;
    }
    match st.tunnels.list_disabled_hostnames() {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|r| DisabledHostnameResp { hostname: r.hostname, disabled_by: r.disabled_by, disabled_at: r.disabled_at })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => internal_error("admin_ui_list_disabled_hostnames", e).into_response(),
    }
}

/// Build a [`DesecClient`] scoped to `zone` from a raw token (ADR-0025 Decision
/// 4): [`DesecClient::from_env`]/the module-wide client `portal_api_router`
/// already builds are bound to exactly ONE zone (`DESEC_DOMAIN`) at
/// construction and refuse (`guard_under_zone`) any host outside it -- onboarding
/// a genuinely NEW zone needs a differently-zoned client, built here via
/// [`DesecClient::from_lookup`] rather than `from_env` reading the process
/// environment (which still only ever names the ORIGINAL zone).
fn desec_client_for_zone(zone: &str, token: &str, api_base: Option<&str>) -> Option<DesecClient> {
    let token = token.to_string();
    let zone = zone.to_string();
    let api_base = api_base.map(str::to_string);
    DesecClient::from_lookup(move |k| match k {
        "DESEC_TOKEN" => Some(token.clone()),
        "DESEC_DOMAIN" => Some(zone.clone()),
        "DESEC_API_BASE" => api_base.clone(),
        _ => None,
    })
}

#[derive(Deserialize)]
struct RegisterDomainReq {
    zone: String,
}

#[derive(Serialize)]
struct ManagedDomainResp {
    zone: String,
    added_by: Option<String>,
    added_at: i64,
    status: String,
}

/// `POST /admin-ui/domains {zone}` (admin-identity-gated, ADR-0025 Decision 4):
/// register a new zone as managed. Does **not** attempt DNS delegation --
/// per the ADR, that's the documented one-time human step at the registrar,
/// assumed already done by the time this is called. Issues the apex + wildcard
/// A records via [`DesecClient::set_a`], pointed at [`DomainAdminConfig::
/// dns_edge_ip`], and only inserts the `managed_domains` row once BOTH
/// succeed -- a `DesecClient` call failing (e.g. the zone isn't actually under
/// deSEC's management yet) reports a clear, actionable error and leaves NO
/// half-registered row behind, rather than a zone that looks managed but has
/// no real DNS.
async fn admin_ui_register_domain(
    State(st): State<AdminUiState>,
    headers: HeaderMap,
    Json(req): Json<RegisterDomainReq>,
) -> Response {
    let session = match admin_ui_authed(&st, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let Some(zone) = ct_common::normalize_hostname(req.zone.trim()) else {
        return (StatusCode::BAD_REQUEST, "invalid zone").into_response();
    };
    match st.managed_domains.zone(&zone) {
        Ok(Some(_)) => return (StatusCode::CONFLICT, format!("{zone} is already managed")).into_response(),
        Ok(None) => {}
        Err(e) => return internal_error("admin_ui_register_domain/zone", e).into_response(),
    }
    let Some(token) = st.domain_admin.desec_token.as_deref().filter(|s| !s.is_empty()) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "DESEC_TOKEN is not configured on this deployment -- cannot manage DNS for a new zone",
        )
            .into_response();
    };
    let Some(edge_ip) = st.domain_admin.dns_edge_ip.as_deref().filter(|s| !s.is_empty()) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "CT_CP_DNS_EDGE_IP is not configured -- cannot point the new zone's A records anywhere",
        )
            .into_response();
    };
    let Some(client) = desec_client_for_zone(&zone, token, st.domain_admin.desec_api_base.as_deref()) else {
        return internal_error("admin_ui_register_domain/desec_client_for_zone", "failed to build a deSEC client").into_response();
    };
    if let Err(e) = client.set_a(&zone, edge_ip).await {
        return (
            StatusCode::BAD_GATEWAY,
            format!("apex A record for {zone} failed -- is the zone actually delegated to deSEC yet? ({e})"),
        )
            .into_response();
    }
    let wildcard = format!("*.{zone}");
    if let Err(e) = client.set_a(&wildcard, edge_ip).await {
        return (
            StatusCode::BAD_GATEWAY,
            format!(
                "the apex A record for {zone} WAS created, but the wildcard record for {wildcard} failed: {e} \
                 -- retrying this call is safe (both records are idempotent upserts)"
            ),
        )
            .into_response();
    }
    let now = admin_ui_now_secs();
    match st.managed_domains.add_zone(&zone, &session.email, now, "active") {
        Ok(_) => {
            let _ = st.audit.record(&session.email, "domain_register", Some(&zone), Some("apex+wildcard A records issued"));
            Json(ManagedDomainResp { zone, added_by: Some(session.email), added_at: now, status: "active".to_string() }).into_response()
        }
        Err(e) => internal_error("admin_ui_register_domain/add_zone", e).into_response(),
    }
}

/// `GET /admin-ui/domains` (admin-identity-gated): every managed domain +
/// status, newest first.
async fn admin_ui_list_domains(State(st): State<AdminUiState>, headers: HeaderMap) -> Response {
    if wants_html(&headers) {
        let session = match admin_ui_page_authed(&st, &headers) {
            Ok(s) => s,
            Err(resp) => return resp,
        };
        let zones = match st.managed_domains.list_zones() {
            Ok(v) => v,
            Err(e) => return internal_error("admin_ui_list_domains/html/zones", e).into_response(),
        };
        let disabled = match st.tunnels.list_disabled_hostnames() {
            Ok(v) => v,
            Err(e) => return internal_error("admin_ui_list_domains/html/disabled", e).into_response(),
        };
        let tunnels = match st.tunnels.all() {
            Ok(v) => v,
            Err(e) => return internal_error("admin_ui_list_domains/html/tunnels", e).into_response(),
        };
        return Html(admin_domains_page_html(&session, &zones, &disabled, &tunnels, st.domain_admin.platform_zone.as_deref())).into_response();
    }
    if let Err(resp) = admin_ui_authed(&st, &headers) {
        return resp;
    }
    match st.managed_domains.list_zones() {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|r| ManagedDomainResp { zone: r.zone, added_by: r.added_by, added_at: r.added_at, status: r.status })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => internal_error("admin_ui_list_domains", e).into_response(),
    }
}

#[derive(Deserialize)]
struct AddDomainHostnameReq {
    subdomain: String,
}

#[derive(Serialize)]
struct AddDomainHostnameResp {
    hostname: String,
    cert_dir: String,
}

/// `POST /admin-ui/domains/:zone/hostnames {subdomain}` (admin-identity-gated,
/// ADR-0025 Decision 4): given an already-managed zone, issue a cert for
/// `subdomain.zone` via [`crate::cert_issuer::issue_cert`] (`lib-acme.sh`'s
/// `issue_cert`, shelled out to -- see that module's doc for why). Runs the
/// blocking subprocess call on `spawn_blocking` so it doesn't stall this
/// handler's async worker for the (potentially tens-of-seconds) duration of a
/// real ACME issuance.
async fn admin_ui_add_domain_hostname(
    State(st): State<AdminUiState>,
    headers: HeaderMap,
    Path(zone): Path<String>,
    Json(req): Json<AddDomainHostnameReq>,
) -> Response {
    let session = match admin_ui_authed(&st, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let Some(zone) = ct_common::normalize_hostname(&zone) else {
        return (StatusCode::BAD_REQUEST, "invalid zone").into_response();
    };
    match st.managed_domains.zone(&zone) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                format!("{zone} is not a managed domain -- register it first via POST /admin-ui/domains"),
            )
                .into_response()
        }
        Err(e) => return internal_error("admin_ui_add_domain_hostname/zone", e).into_response(),
    }
    let subdomain = req.subdomain.trim().trim_end_matches('.').to_ascii_lowercase();
    if subdomain.is_empty() || subdomain.contains('.') {
        return (
            StatusCode::BAD_REQUEST,
            "subdomain must be a single label (e.g. \"app\"), not a full hostname",
        )
            .into_response();
    }
    let Some(hostname) = ct_common::normalize_hostname(&format!("{subdomain}.{zone}")) else {
        return (StatusCode::BAD_REQUEST, "invalid hostname").into_response();
    };
    let Some(cert_cfg) = st.domain_admin.managed_cert.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "cert issuance is not configured on this deployment (CT_CP_LIB_ACME_PATH unset)",
        )
            .into_response();
    };
    let cert_dir = std::path::PathBuf::from(&cert_cfg.cert_base_dir).join(&hostname);
    let issue_result = {
        let hostname = hostname.clone();
        let cert_dir = cert_dir.clone();
        tokio::task::spawn_blocking(move || crate::cert_issuer::issue_cert(&cert_cfg.acme, &hostname, &cert_dir)).await
    };
    match issue_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return (StatusCode::BAD_GATEWAY, format!("cert issuance for {hostname} failed: {e}")).into_response(),
        Err(e) => return internal_error("admin_ui_add_domain_hostname/spawn_blocking", e).into_response(),
    }
    let cert_dir_str = cert_dir.to_string_lossy().into_owned();
    if let Err(e) =
        st.managed_domains
            .record_hostname_cert(&hostname, &zone, &cert_dir_str, &session.email, admin_ui_now_secs())
    {
        return internal_error("admin_ui_add_domain_hostname/record_hostname_cert", e).into_response();
    }
    let _ = st.audit.record(&session.email, "domain_hostname_cert_issue", Some(&hostname), Some(&format!("zone={zone}")));
    Json(AddDomainHostnameResp { hostname, cert_dir: cert_dir_str }).into_response()
}

/// `GET /admin-ui/domains` HTML branch (ADR-0025 Decision 4/6 integration pass):
/// managed zones + an onboard-a-domain form, a per-hostname disable/enable toggle
/// (Decision 4's "a natural sibling of the existing revoke call") built from the
/// union of every LIVE tunnel hostname and every already-disabled one -- a
/// hostname can be disabled with no live tunnel on it right now (the owner hasn't
/// recreated it yet), so `disabled` is the authority on current state, not
/// `tunnels` alone.
fn admin_domains_page_html(
    session: &crate::admin_identity::AdminSession,
    zones: &[crate::storage::ManagedDomainRow],
    disabled: &[crate::storage::DisabledHostnameRow],
    tunnels: &[SubjectTunnel],
    platform_zone: Option<&str>,
) -> String {
    let platform_row = match platform_zone {
        Some(z) => format!(
            r#"<table class="data"><thead><tr><th>Zone</th><th>Role</th></tr></thead><tbody>
<tr><td><code>{z}</code></td><td><span class="badge ok">platform</span> this deployment's own root domain -- always active, not part of the onboarded-zone registry below</td></tr>
</tbody></table>"#,
            z = escape(z),
        ),
        None => String::from(
            r#"<p class="help">No <code>CT_CP_PLATFORM_ZONE</code> configured for this deployment, so the platform's own root domain isn't shown here.</p>"#,
        ),
    };
    let mut zones_table = String::from(
        r#"<table class="data"><thead><tr><th>Zone</th><th>Status</th><th>Added by</th><th>Added</th><th>Add a hostname</th></tr></thead><tbody>"#,
    );
    if zones.is_empty() {
        zones_table.push_str(r#"<tr><td colspan="5" class="help">No domains onboarded yet -- use the form below.</td></tr>"#);
    }
    for z in zones {
        zones_table.push_str(&format!(
            r#"<tr><td><code>{zone}</code></td><td>{status}</td><td>{added_by}</td><td><span data-ts="{added_at}">{added_at}</span></td>
<td><form class="inline" data-zone="{zone}" onsubmit="return addHostname(event)">
 <input type="text" name="subdomain" placeholder="app" required style="width:6rem">
 <button type="submit" class="sec">Issue cert</button>
</form></td></tr>"#,
            zone = escape(&z.zone),
            status = escape(&z.status),
            added_by = z.added_by.as_deref().map(escape).unwrap_or_else(|| "-".to_string()),
            added_at = z.added_at,
        ));
    }
    zones_table.push_str("</tbody></table>");

    let disabled_set: std::collections::HashSet<&str> = disabled.iter().map(|d| d.hostname.as_str()).collect();
    let mut hostnames: Vec<(String, bool, bool)> = Vec::new(); // (hostname, disabled, has_live_tunnel)
    for t in tunnels {
        if let Some(h) = &t.hostname {
            hostnames.push((h.clone(), disabled_set.contains(h.as_str()), true));
        }
    }
    for d in disabled {
        if !hostnames.iter().any(|(h, _, _)| h == &d.hostname) {
            hostnames.push((d.hostname.clone(), true, false));
        }
    }
    hostnames.sort_by(|a, b| a.0.cmp(&b.0));

    let mut host_table = String::from(
        r#"<table class="data"><thead><tr><th>Hostname</th><th>State</th><th></th></tr></thead><tbody>"#,
    );
    if hostnames.is_empty() {
        host_table.push_str(r#"<tr><td colspan="3" class="help">No hostnames yet.</td></tr>"#);
    }
    for (host, is_disabled, live) in &hostnames {
        let state = if *is_disabled {
            r#"<span class="badge blocked">disabled</span>"#.to_string()
        } else if *live {
            r#"<span class="badge ok">active</span>"#.to_string()
        } else {
            r#"<span class="help">no live tunnel</span>"#.to_string()
        };
        let action = if *is_disabled {
            format!(r#"<button class="sec" data-host="{h}" onclick="return toggleHostname(event,'enable')">Enable</button>"#, h = escape(host))
        } else {
            format!(r#"<button class="danger" data-host="{h}" onclick="return toggleHostname(event,'disable')">Disable</button>"#, h = escape(host))
        };
        host_table.push_str(&format!(
            r#"<tr><td><code>{host}</code></td><td>{state}</td><td>{action}</td></tr>"#,
            host = escape(host),
        ));
    }
    host_table.push_str("</tbody></table>");

    let mut known_zones: Vec<&str> = zones.iter().map(|z| z.zone.as_str()).collect();
    if let Some(z) = platform_zone {
        known_zones.push(z);
    }
    let known_zones_json = serde_json::to_string(&known_zones).unwrap_or_else(|_| "[]".to_string());

    let body = format!(
        r#"<h1>Domains</h1>
<p class="help">Every zone this platform serves. The <strong>Platform</strong> row below is this
deployment's own root domain -- it predates this console and was never "onboarded" through the
form beneath Managed zones, which is only for zones added AFTER this console existed. DNS
delegation to deSEC at a new zone's registrar is a manual one-time step performed BEFORE
onboarding here -- that form only issues the apex/wildcard A records and (per-hostname) certs, it
never touches a registrar.</p>
<h2>Platform</h2>
{platform_row}
<h2>Managed zones</h2>
{zones_table}
<form id="registerForm" onsubmit="return registerDomain(event)">
 <label>Onboard a new zone (already delegated to deSEC) <input type="text" name="zone" placeholder="example.org" required></label>
 <button type="submit">Onboard domain</button>
</form>
<p class="msg" id="registerMsg"></p>
<h2>Traffic by domain</h2>
<p class="help">Relay-plane bytes from <a href="/admin-ui/traffic">Traffic monitor</a>, summed per
zone by matching each tunnel's hostname against the zones above (exact apex match or a
<code>*.zone</code> subdomain). Same "relay bytes are real, direct P2P is availability-only"
caveat as the Traffic monitor page applies here too.</p>
<div id="domainTrafficTable" class="help">Loading…</div>
<h2>Hostnames</h2>
{host_table}
<script>
var CT_KNOWN_ZONES = {known_zones_json};
(function(){{
 function esc(s){{ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;'); }}
 function zoneFor(hostname){{
  if(!hostname) return null;
  var best = null;
  CT_KNOWN_ZONES.forEach(function(z){{
   if(hostname === z || hostname.slice(-(z.length + 1)) === '.' + z){{
    if(!best || z.length > best.length) best = z;
   }}
  }});
  return best;
 }}
 fetch('/admin-ui/traffic').then(function(r){{ return r.ok ? r.json() : Promise.reject(r.status); }})
  .then(function(rows){{
   var byZone = {{}}, other = {{bytes_received: 0, bytes_sent: 0, tunnels: 0}};
   rows.forEach(function(t){{
    var z = zoneFor(t.hostname);
    var bucket = z ? (byZone[z] || (byZone[z] = {{bytes_received: 0, bytes_sent: 0, tunnels: 0}})) : other;
    bucket.bytes_received += t.bytes_received || 0;
    bucket.bytes_sent += t.bytes_sent || 0;
    bucket.tunnels += 1;
   }});
   var zoneNames = Object.keys(byZone);
   if(!zoneNames.length && !other.tunnels){{
    document.getElementById('domainTrafficTable').innerHTML = '<p class="help">No tunnels registered yet.</p>';
    return;
   }}
   var html = '<table class="data"><thead><tr><th>Zone</th><th>Tunnels</th><th>Relay bytes in</th><th>Relay bytes out</th></tr></thead><tbody>';
   zoneNames.sort().forEach(function(z){{
    var b = byZone[z];
    html += '<tr><td><code>' + esc(z) + '</code></td><td>' + b.tunnels + '</td><td>' + b.bytes_received.toLocaleString() + '</td><td>' + b.bytes_sent.toLocaleString() + '</td></tr>';
   }});
   if(other.tunnels){{
    html += '<tr><td><span class="help">(unmatched hostname)</span></td><td>' + other.tunnels + '</td><td>' + other.bytes_received.toLocaleString() + '</td><td>' + other.bytes_sent.toLocaleString() + '</td></tr>';
   }}
   html += '</tbody></table>';
   document.getElementById('domainTrafficTable').innerHTML = html;
   window.ctSortableInit(document.getElementById('domainTrafficTable'));
  }})
  .catch(function(s){{ document.getElementById('domainTrafficTable').innerHTML = '<p class="msg err">could not load traffic (' + s + ')</p>'; }});
}})();
function registerDomain(ev){{
 ev.preventDefault();
 var form = ev.target, msg = document.getElementById('registerMsg');
 msg.className = 'msg'; msg.textContent = 'onboarding… (issuing DNS records, this can take a moment)';
 adminApi('POST', '/admin-ui/domains', {{zone: form.zone.value.trim()}})
  .then(function(){{ location.reload(); }})
  .catch(function(e){{ msg.className = 'msg err'; msg.textContent = 'failed: ' + e.message; }});
 return false;
}}
function addHostname(ev){{
 ev.preventDefault();
 var form = ev.target;
 var zone = form.getAttribute('data-zone');
 var subdomain = form.subdomain.value.trim();
 form.querySelector('button').disabled = true;
 adminApi('POST', '/admin-ui/domains/' + encodeURIComponent(zone) + '/hostnames', {{subdomain: subdomain}})
  .then(function(){{ location.reload(); }})
  .catch(function(e){{ form.querySelector('button').disabled = false; window.alert('cert issuance failed: ' + e.message); }});
 return false;
}}
function toggleHostname(ev, action){{
 ev.preventDefault();
 var host = ev.target.getAttribute('data-host');
 if(action === 'disable' && !window.confirm('Disable ' + host + '? This revokes its live tunnel and blocks re-authorization until re-enabled.')) return false;
 adminApi('POST', '/admin-ui/hostnames/' + encodeURIComponent(host) + '/' + action)
  .then(function(){{ location.reload(); }})
  .catch(function(e){{ window.alert('failed: ' + e.message); }});
 return false;
}}
</script>"#,
        zones_table = zones_table,
        host_table = host_table,
    );
    admin_page("domains", session, &body)
}

#[derive(Serialize)]
struct CertStatusResp {
    label: String,
    state: &'static str,
    days_remaining: Option<i64>,
    not_after_unix: Option<i64>,
    reason: Option<String>,
}

impl From<crate::cert_status::CertStatus> for CertStatusResp {
    fn from(s: crate::cert_status::CertStatus) -> Self {
        match s.state {
            crate::cert_status::CertState::Ok { days_remaining, not_after_unix } => {
                CertStatusResp { label: s.label, state: "ok", days_remaining: Some(days_remaining), not_after_unix: Some(not_after_unix), reason: None }
            }
            crate::cert_status::CertState::NotConfigured => {
                CertStatusResp { label: s.label, state: "not_configured", days_remaining: None, not_after_unix: None, reason: None }
            }
            crate::cert_status::CertState::Unreadable { reason } => {
                CertStatusResp { label: s.label, state: "unreadable", days_remaining: None, not_after_unix: None, reason: Some(reason) }
            }
        }
    }
}

/// `GET /admin-ui/certs` (admin-identity-gated, ADR-0025 Decision 6): for
/// every currently-configured front-door cert (Portal/Auth/MASQUE/Admin, per
/// [`DomainAdminConfig::front_door_certs`]) plus every per-managed-domain cert
/// ([`crate::storage::SqliteManagedDomains::list_hostname_certs`]), report
/// days-until-expiry. A missing/unreadable/unconfigured cert is reported as
/// its own explicit state (see [`crate::cert_status::CertState`]) rather than
/// omitted -- an admin needs to see gaps, not just healthy entries.
async fn admin_ui_certs(State(st): State<AdminUiState>, headers: HeaderMap) -> Response {
    if wants_html(&headers) {
        let session = match admin_ui_page_authed(&st, &headers) {
            Ok(s) => s,
            Err(resp) => return resp,
        };
        let rows = admin_ui_cert_rows(&st);
        return Html(admin_certs_page_html(&session, rows)).into_response();
    }
    if let Err(resp) = admin_ui_authed(&st, &headers) {
        return resp;
    }
    Json(admin_ui_cert_rows(&st)).into_response()
}

/// The four fixed front-door slots plus every per-managed-domain cert, in ONE
/// place -- both [`admin_ui_certs`]'s JSON branch and its HTML branch call this,
/// so the two views can never disagree about which certs exist or their state.
fn admin_ui_cert_rows(st: &AdminUiState) -> Vec<CertStatusResp> {
    let paths = &st.domain_admin.front_door_certs;
    let mut out = vec![
        crate::cert_status::check("portal", paths.portal.as_deref().map(std::path::Path::new)),
        crate::cert_status::check("auth", paths.auth.as_deref().map(std::path::Path::new)),
        crate::cert_status::check("masque", paths.masque.as_deref().map(std::path::Path::new)),
        crate::cert_status::check("admin-ui", paths.admin_ui.as_deref().map(std::path::Path::new)),
    ];
    match st.managed_domains.list_hostname_certs() {
        Ok(rows) => {
            for r in rows {
                let path = std::path::PathBuf::from(&r.cert_dir).join("fullchain.pem");
                out.push(crate::cert_status::check(r.hostname, Some(path.as_path())));
            }
        }
        Err(e) => eprintln!("ct-cp: admin_ui_certs: list_hostname_certs failed: {e} -- per-domain certs omitted from this response"),
    }
    out.into_iter().map(CertStatusResp::from).collect()
}

/// Sort key for the cert-expiry dashboard: an `unreadable` cert needs the most
/// urgent attention (something is actively broken -- #142-class incident), then
/// `ok` entries soonest-expiring first (the task's own requirement), then
/// `not_configured` last (nothing to expire, lowest urgency of the three).
fn cert_status_sort_key(s: &CertStatusResp) -> (u8, i64) {
    match s.state {
        "unreadable" => (0, 0),
        "ok" => (1, s.days_remaining.unwrap_or(i64::MAX)),
        _ => (2, 0),
    }
}

/// Below this many days remaining, a cert is flagged the same way an `unreadable`
/// one is -- close enough to expiry that "still technically ok" is the wrong signal
/// to give an operator glancing at this page (ADR-0025 Decision 6's own framing:
/// this dashboard exists specifically to make that visible before it becomes an
/// outage, matching tonight's own #142-class incident).
const CERT_EXPIRY_WARN_DAYS: i64 = 14;

/// `GET /admin-ui/certs` HTML branch (ADR-0025 Decision 6 integration pass):
/// soonest-expiring first, with anything under [`CERT_EXPIRY_WARN_DAYS`] or
/// unreadable visually flagged -- see [`cert_status_sort_key`].
fn admin_certs_page_html(session: &crate::admin_identity::AdminSession, mut rows: Vec<CertStatusResp>) -> String {
    rows.sort_by_key(cert_status_sort_key);
    let mut table = String::from(
        r#"<table class="data"><thead><tr><th>Hostname</th><th>State</th><th>Days remaining</th><th>Detail</th></tr></thead><tbody>"#,
    );
    if rows.is_empty() {
        table.push_str(r#"<tr><td colspan="4" class="help">No certs to report.</td></tr>"#);
    }
    for r in &rows {
        let flagged = r.state == "unreadable" || r.days_remaining.map(|d| d < CERT_EXPIRY_WARN_DAYS).unwrap_or(false);
        let (state_html, days_html) = match r.state {
            "ok" => (
                if flagged { r#"<span class="badge warn">expiring soon</span>"#.to_string() } else { r#"<span class="badge ok">ok</span>"#.to_string() },
                r.days_remaining.map(|d| d.to_string()).unwrap_or_default(),
            ),
            "unreadable" => (r#"<span class="badge blocked">unreadable</span>"#.to_string(), "-".to_string()),
            _ => (r#"<span class="help">not configured</span>"#.to_string(), "-".to_string()),
        };
        table.push_str(&format!(
            r#"<tr><td><code>{label}</code></td><td>{state_html}</td><td>{days_html}</td><td class="help">{detail}</td></tr>"#,
            label = escape(&r.label),
            state_html = state_html,
            days_html = days_html,
            detail = escape(r.reason.as_deref().unwrap_or("")),
        ));
    }
    table.push_str("</tbody></table>");
    let body = format!(
        r#"<h1>Certificates</h1>
<p class="help">Every front-door hostname's TLS cert -- Portal/Auth/MASQUE/Admin plus every
managed-domain hostname -- and how many days remain before it needs renewal. Sorted
soonest-expiring first; anything unreadable or under {warn} days is flagged.</p>
{table}"#,
        table = table,
        warn = CERT_EXPIRY_WARN_DAYS,
    );
    admin_page("certs", session, &body)
}

// ===== ADR-0025 Decision 6: read-only observability (traffic/tunnels/health) =====
//
// No mutation anywhere below, so no `audit.record` calls -- ADR-0025's own framing
// ("read-only actions aren't audit-worthy the way grants/blocks/deletes are").

/// ADR-0025 Decision 3: whether an Agent currently has a direct/P2P listener
/// advertised for a tunnel, translated to the two-value transport label the UI
/// renders. Deliberately only two values, never "unknown" -- the absence of a
/// direct advertisement structurally means the tunnel can ONLY be served over
/// the relay (there is no third path), so this is knowable either way, unlike
/// a byte count the edge structurally cannot measure for the direct leg. This
/// is an AVAILABILITY signal ("a direct path is currently advertised"), not a
/// claim that traffic is actually flowing over it -- seeing the mismatch
/// between this and the also-reported relay byte counts is exactly what the
/// admin console exists to make visible, not something to paper over here.
fn infer_transport(direct_active: bool) -> &'static str {
    if direct_active { "direct_p2p" } else { "relay" }
}

/// ADR-0025 Decision 3/6's own wording: "routing token (or its safe display
/// form)". A routing token is the live identifier that routes traffic to a
/// tunnel (`RoutingToken`, `ct_common`) -- even though the admin console is
/// already gated at least as strictly as the shared edge-admin secret, there
/// is no reason to additionally put the full value into a browser's
/// DOM/devtools/history when a short prefix+suffix still lets an operator
/// cross-reference rows across this dashboard and the raw edge admin API.
/// Not `pub` / not reversible -- this is a display helper, not an encoding.
fn redact_token_for_display(hex: &str) -> String {
    if hex.len() <= 12 {
        return hex.to_string();
    }
    format!("{}…{}", &hex[..8], &hex[hex.len() - 4..])
}

/// ADR-0025 Decision 6: "uptime" is only ever meaningful while a tunnel is
/// actually connected right now -- `None` while disconnected, regardless of
/// whether `connected_since` happens to still carry a stale value (it
/// shouldn't, per `EdgeState`'s own contract, but this function doesn't have
/// to trust that to be correct). Takes `now` as a parameter rather than
/// reading the clock itself specifically so it is a plain, deterministic unit
/// -- see the tests below.
fn tunnel_uptime_secs(now: i64, connected: bool, connected_since: Option<i64>) -> Option<i64> {
    if !connected {
        return None;
    }
    connected_since.map(|since| (now - since).max(0))
}

/// One tunnel's live status, as reported by the edge's `POST
/// /admin/tunnel-status/bulk` (`crates/edge/src/admin.rs`'s `BulkTunnelStatusEntry`,
/// flattened). Every field is `#[serde(default)]` so a future edge that omits one
/// (or an edge running an older binary during a rolling upgrade) degrades to the
/// same "nothing known yet" default this struct already uses for a tunnel the
/// bulk response has no entry for at all, rather than failing the whole response.
#[derive(Deserialize, Clone, Default)]
struct EdgeBulkStatusEntry {
    token: String,
    #[serde(default)]
    connected: bool,
    #[serde(default)]
    registrations: usize,
    #[serde(default)]
    fallback_parked: usize,
    #[serde(default)]
    bytes_received: u64,
    #[serde(default)]
    bytes_sent: u64,
    #[serde(default)]
    direct: bool,
    #[serde(default)]
    connected_since: Option<i64>,
    #[serde(default)]
    last_seen: Option<i64>,
}

/// Bulk-fetch live status for `tokens` from the edge in ONE HTTP round trip
/// (`POST /admin/tunnel-status/bulk`) -- the whole reason this exists is so
/// `/admin-ui/traffic`/`/admin-ui/tunnels` don't make the caller (or this
/// handler) loop one HTTP call per tunnel the way `portal_api.rs`'s own
/// `edge_tunnel_status` does for a single subject's small tunnel list.
/// Best-effort, matching every other edge-admin call in this file: `None`
/// configured, an unsuccessful response, or a transport/decode error all
/// return an empty map, so a transient edge/network hiccup degrades every
/// row to its "nothing known" defaults instead of failing the whole page.
async fn edge_tunnel_status_bulk(st: &AdminUiState, tokens: &[String]) -> HashMap<String, EdgeBulkStatusEntry> {
    let Some((edge_url, edge_token)) = &st.domain_admin.edge_admin else {
        return HashMap::new();
    };
    if tokens.is_empty() {
        return HashMap::new();
    }
    let endpoint = format!("{}/admin/tunnel-status/bulk", edge_url.trim_end_matches('/'));
    let resp = edge_admin_http_client()
        .post(&endpoint)
        .header("x-ct-admin-token", edge_token.as_str())
        .json(&serde_json::json!({ "tokens": tokens }))
        .send()
        .await;
    match resp {
        Ok(r) if r.status().is_success() => match r.json::<Vec<EdgeBulkStatusEntry>>().await {
            Ok(entries) => entries.into_iter().map(|e| (e.token.clone(), e)).collect(),
            Err(e) => {
                eprintln!("ct-cp: edge_tunnel_status_bulk: decoding the edge's response failed: {e}");
                HashMap::new()
            }
        },
        Ok(r) => {
            eprintln!("ct-cp: edge_tunnel_status_bulk: edge returned {}", r.status());
            HashMap::new()
        }
        Err(e) => {
            eprintln!("ct-cp: edge_tunnel_status_bulk: request failed: {}", redact_routing_tokens(&e.to_string()));
            HashMap::new()
        }
    }
}

#[derive(Serialize)]
struct TrafficRow {
    tunnel_id: String,
    name: String,
    hostname: Option<String>,
    routing_token_display: String,
    connected: bool,
    /// ADR-0025 Decision 3: `"relay"` | `"direct_p2p"` -- see [`infer_transport`].
    transport: &'static str,
    bytes_received: u64,
    bytes_sent: u64,
}

/// Pure join of `tunnels` (the control plane's own tunnel registry,
/// `SqliteTunnelStore::all`) against `edge_status` (this process's bulk edge
/// scrape) -- no I/O, so it's directly unit-testable (see the tests below) and
/// is exactly why [`admin_ui_traffic`] itself stays a thin wrapper around it.
/// A tunnel with no entry in `edge_status` (never connected since the edge's
/// own process start, or the scrape failed) reports `connected: false`,
/// `transport: "relay"` (the honest default -- no direct advertisement is
/// known, so relay is the only path that could be serving it) and zeroed byte
/// counts, rather than being omitted from the list.
fn build_traffic_rows(tunnels: &[SubjectTunnel], edge_status: &HashMap<String, EdgeBulkStatusEntry>) -> Vec<TrafficRow> {
    tunnels
        .iter()
        .map(|t| {
            let status = edge_status.get(&t.routing_token);
            TrafficRow {
                tunnel_id: t.id.clone(),
                name: t.name.clone(),
                hostname: t.hostname.clone(),
                routing_token_display: redact_token_for_display(&t.routing_token),
                connected: status.map(|s| s.connected).unwrap_or(false),
                transport: infer_transport(status.map(|s| s.direct).unwrap_or(false)),
                bytes_received: status.map(|s| s.bytes_received).unwrap_or(0),
                bytes_sent: status.map(|s| s.bytes_sent).unwrap_or(0),
            }
        })
        .collect()
}

/// `GET /admin-ui/traffic` (admin-identity-gated, ADR-0025 Decision 6, read-only):
/// per registered tunnel, its relay byte counts (real, edge-measured) and its
/// transport (Decision 3's honest relay-vs-direct-advertised signal, never a
/// direct-path byte count the edge doesn't have).
async fn admin_ui_traffic(State(st): State<AdminUiState>, headers: HeaderMap) -> Response {
    if wants_html(&headers) {
        let session = match admin_ui_page_authed(&st, &headers) {
            Ok(s) => s,
            Err(resp) => return resp,
        };
        return Html(admin_traffic_page_html(&session)).into_response();
    }
    if let Err(resp) = admin_ui_authed(&st, &headers) {
        return resp;
    }
    let tunnels = match st.tunnels.all() {
        Ok(v) => v,
        Err(e) => return internal_error("admin_ui_traffic/tunnels.all", e).into_response(),
    };
    let tokens: Vec<String> = tunnels.iter().map(|t| t.routing_token.clone()).collect();
    let edge_status = edge_tunnel_status_bulk(&st, &tokens).await;
    Json(build_traffic_rows(&tunnels, &edge_status)).into_response()
}

/// `GET /admin-ui/traffic` HTML branch (ADR-0025 Decision 3/6 integration pass):
/// client-fetches its OWN already-shipped JSON endpoints (`/admin-ui/traffic` --
/// same path, differentiated by [`wants_html`] -- and `/admin-ui/tunnels`) rather
/// than SSR-ing them, since both need the SAME async edge scrape
/// [`admin_ui_traffic`]'s and [`admin_ui_tunnels`]'s own JSON branches already do;
/// duplicating that here would mean two independent code paths that could drift.
/// Decision 3's own wording is rendered verbatim in the transport column's help
/// text -- never a byte count for the direct/P2P leg, only "the relay saw N bytes"
/// (real) alongside "a direct path is currently advertised" (an availability
/// signal, not a traffic measurement).
fn admin_traffic_page_html(session: &crate::admin_identity::AdminSession) -> String {
    let body = r#"<h1>Traffic monitor</h1>
<p class="help">Relay-plane bytes below are real, edge-measured counts. "Direct P2P" means a
direct advertisement is currently active for that tunnel -- it is an <strong>availability
signal</strong>, not a byte count: the edge structurally cannot see traffic that bypasses it
entirely, so no number is shown for that leg. A tunnel can show relay bytes AND direct P2P at
once; that mismatch is exactly what this page exists to make visible, not hide.</p>
<span id="msg" class="help"></span>
<div id="trafficTable" class="help">Loading…</div>
<h2>Live tunnel overview</h2>
<p class="help">Every registered tunnel, which edge it's on, and how long its current
connection has been up.</p>
<div id="tunnelsTable" class="help">Loading…</div>
<script>
(function(){
 function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;'); }
 function transportBadge(t){
  return t === 'direct_p2p'
   ? '<span class="badge ok">direct P2P (advertised)</span>'
   : '<span class="help">relay</span>';
 }
 fetch('/admin-ui/traffic').then(function(r){ return r.ok ? r.json() : Promise.reject(r.status); })
  .then(function(rows){
   if(!rows.length){ document.getElementById('trafficTable').innerHTML = '<p class="help">No tunnels registered yet.</p>'; return; }
   var html = '<table class="data"><thead><tr><th>Name</th><th>Hostname</th><th>Connected</th>'
     + '<th>Transport</th><th>Relay bytes in</th><th>Relay bytes out</th></tr></thead><tbody>';
   rows.forEach(function(t){
    html += '<tr><td>' + esc(t.name) + '</td><td>' + esc(t.hostname || '-') + '</td>'
      + '<td><span class="status-dot ' + (t.connected ? 'live' : 'off') + '"></span>' + (t.connected ? 'yes' : 'no') + '</td>'
      + '<td>' + transportBadge(t.transport) + '</td>'
      + '<td>' + t.bytes_received.toLocaleString() + '</td><td>' + t.bytes_sent.toLocaleString() + '</td></tr>';
   });
   html += '</tbody></table>';
   document.getElementById('trafficTable').innerHTML = html;
   window.ctSortableInit(document.getElementById('trafficTable'));
  })
  .catch(function(s){ document.getElementById('msg').textContent = 'could not load traffic (' + s + ')'; });
 fetch('/admin-ui/tunnels').then(function(r){ return r.ok ? r.json() : Promise.reject(r.status); })
  .then(function(rows){
   if(!rows.length){ document.getElementById('tunnelsTable').innerHTML = '<p class="help">No tunnels registered yet.</p>'; return; }
   var html = '<table class="data"><thead><tr><th>Name</th><th>Hostname</th><th>Edge</th>'
     + '<th>Transport</th><th>Uptime</th><th>Last seen</th></tr></thead><tbody>';
   rows.forEach(function(t){
    var uptime = t.uptime_seconds != null ? Math.round(t.uptime_seconds/60) + ' min' : '-';
    var lastSeen = t.last_seen_unix ? new Date(t.last_seen_unix*1000).toLocaleString() : 'never';
    html += '<tr><td>' + esc(t.name) + '</td><td>' + esc(t.hostname || '-') + '</td><td>' + esc(t.edge_id || '-') + '</td>'
      + '<td>' + transportBadge(t.transport) + '</td><td data-sort="' + (t.uptime_seconds || 0) + '">' + uptime + '</td><td data-sort="' + (t.last_seen_unix || 0) + '">' + esc(lastSeen) + '</td></tr>';
   });
   html += '</tbody></table>';
   document.getElementById('tunnelsTable').innerHTML = html;
   window.ctSortableInit(document.getElementById('tunnelsTable'));
  })
  .catch(function(s){ document.getElementById('msg').textContent = 'could not load tunnel overview (' + s + ')'; });
})();
</script>"#;
    admin_page("traffic", session, body)
}

#[derive(Serialize)]
struct TunnelOverviewRow {
    tunnel_id: String,
    name: String,
    hostname: Option<String>,
    routing_token_display: String,
    connected: bool,
    /// QUIC registrations (redundant Agents, #8, count separately from `fallback_parked`).
    registrations: usize,
    fallback_parked: usize,
    /// ADR-0025 Decision 3: `"relay"` | `"direct_p2p"` -- see [`infer_transport`].
    transport: &'static str,
    /// ADR-0021's multi-edge ownership registry: which edge this tunnel is
    /// currently assigned to, `None` when no ownership row exists yet (a
    /// tunnel with no hostname ever set, or a deployment that hasn't wired the
    /// registry up at all).
    edge_id: Option<String>,
    created_at: i64,
    /// Seconds the CURRENT connection streak has been up, `None` while
    /// disconnected. See [`tunnel_uptime_secs`].
    uptime_seconds: Option<i64>,
    /// Unix seconds of the most recent activity, `None` if never seen at all
    /// (survives disconnect -- see `EdgeState::connection_timing`'s own doc).
    last_seen_unix: Option<i64>,
}

/// Pure join of `tunnels` against `edge_status` (this process's bulk edge
/// scrape) and `edge_by_token` (a pre-resolved `routing_token -> edge_id` map,
/// so this function itself makes no DB calls and is directly unit-testable --
/// see [`admin_ui_tunnels`] for where `edge_by_token` is actually built). `now`
/// is threaded through to [`tunnel_uptime_secs`] rather than read here, for the
/// same testability reason.
fn build_tunnel_overview_rows(
    now: i64,
    tunnels: &[SubjectTunnel],
    edge_status: &HashMap<String, EdgeBulkStatusEntry>,
    edge_by_token: &HashMap<String, String>,
) -> Vec<TunnelOverviewRow> {
    tunnels
        .iter()
        .map(|t| {
            let status = edge_status.get(&t.routing_token);
            let connected = status.map(|s| s.connected).unwrap_or(false);
            TunnelOverviewRow {
                tunnel_id: t.id.clone(),
                name: t.name.clone(),
                hostname: t.hostname.clone(),
                routing_token_display: redact_token_for_display(&t.routing_token),
                connected,
                registrations: status.map(|s| s.registrations).unwrap_or(0),
                fallback_parked: status.map(|s| s.fallback_parked).unwrap_or(0),
                transport: infer_transport(status.map(|s| s.direct).unwrap_or(false)),
                edge_id: edge_by_token.get(&t.routing_token).cloned(),
                created_at: t.created_at,
                uptime_seconds: tunnel_uptime_secs(now, connected, status.and_then(|s| s.connected_since)),
                last_seen_unix: status.and_then(|s| s.last_seen),
            }
        })
        .collect()
}

/// `GET /admin-ui/tunnels` (admin-identity-gated, ADR-0025 Decision 6, read-only):
/// live tunnel/topology overview -- every registered tunnel, which edge it's on
/// (ADR-0021), transport, uptime, and last-seen, aggregated server-side into one
/// response (one bulk edge scrape, one edge_mesh lookup per tunnel) rather than a
/// dashboard the UI has to build itself out of N per-token calls.
async fn admin_ui_tunnels(State(st): State<AdminUiState>, headers: HeaderMap) -> Response {
    if let Err(resp) = admin_ui_authed(&st, &headers) {
        return resp;
    }
    let tunnels = match st.tunnels.all() {
        Ok(v) => v,
        Err(e) => return internal_error("admin_ui_tunnels/tunnels.all", e).into_response(),
    };
    let tokens: Vec<String> = tunnels.iter().map(|t| t.routing_token.clone()).collect();
    let edge_status = edge_tunnel_status_bulk(&st, &tokens).await;
    let mut edge_by_token = HashMap::new();
    if let Some(mesh) = &st.observability.edge_mesh {
        for t in &tunnels {
            match mesh.lookup_by_token(&t.routing_token) {
                Ok(Some((edge_id, _peer_addr))) => {
                    edge_by_token.insert(t.routing_token.clone(), edge_id);
                }
                Ok(None) => {}
                Err(e) => eprintln!("ct-cp: admin_ui_tunnels: edge_mesh lookup for tunnel {} failed: {e}", t.id),
            }
        }
    }
    let rows = build_tunnel_overview_rows(admin_ui_now_secs(), &tunnels, &edge_status, &edge_by_token);
    Json(rows).into_response()
}

#[derive(Serialize, Default)]
struct EdgeHealthSummary {
    /// Whether `CT_CP_EDGE_METRICS_URL` is set at all on this deployment --
    /// every other field is `None` when this is `false`, distinctly from a
    /// scrape that ran and came back empty/failed (see `detail`).
    configured: bool,
    /// The edge's own `/healthz` verdict (#498/#553's real gated-listener
    /// check, reused as-is -- see `edge_health_summary`'s doc), `None` only
    /// when `configured` is `false` or the `/healthz` URL couldn't be derived.
    healthy: Option<bool>,
    /// The edge `/healthz` response body verbatim (which loops it checked, or
    /// why it's unhealthy) -- an operator-facing detail line, not parsed
    /// further here.
    detail: Option<String>,
    active_tunnels: Option<i64>,
    active_agents: Option<i64>,
    relay_bytes_total: Option<i64>,
    tcp_fallback_parked: Option<i64>,
}

#[derive(Serialize)]
struct HealthResp {
    /// Same signal as this process's own `/readyz` (`SqliteLedger::ping`) --
    /// reused directly, not re-derived (see `admin_ui_health`'s doc).
    control_plane_ready: bool,
    edge: EdgeHealthSummary,
}

/// Real HTTP calls against the edge's OWN `/healthz` and `/metrics` (reusing
/// their exact, already-tested underlying data -- #498/#553's gated-listener
/// classifier for `/healthz`, `EdgeState`'s live gauges via
/// `render_edge_metrics` for `/metrics` -- rather than re-deriving either).
/// `/healthz` is derived from [`ObservabilityConfig::edge_metrics_url`] by
/// swapping its `/metrics` suffix for `/healthz`: both routes are served from
/// the SAME `metrics_router` (`crates/edge/src/observe.rs`), so they are
/// always co-located, and no separate config knob exists (or is needed) for
/// the second URL.
async fn edge_health_summary(edge_metrics_url: Option<&str>) -> EdgeHealthSummary {
    let Some(metrics_url) = edge_metrics_url.filter(|s| !s.is_empty()) else {
        return EdgeHealthSummary { configured: false, ..Default::default() };
    };
    let client = edge_admin_http_client();
    let metrics_text = match client.get(metrics_url).timeout(std::time::Duration::from_secs(2)).send().await {
        Ok(r) if r.status().is_success() => r.text().await.ok(),
        Ok(r) => {
            eprintln!("ct-cp: edge_health_summary: /metrics scrape returned {}", r.status());
            None
        }
        Err(e) => {
            eprintln!("ct-cp: edge_health_summary: /metrics scrape failed: {e}");
            None
        }
    };
    let (active_tunnels, active_agents, relay_bytes_total, tcp_fallback_parked) = match &metrics_text {
        Some(body) => (
            crate::service::parse_metric(body, "ct_edge_active_tunnels"),
            crate::service::parse_metric(body, "ct_edge_active_agents"),
            crate::service::parse_metric(body, "ct_edge_relay_bytes_total"),
            crate::service::parse_metric(body, "ct_edge_tcp_fallback_parked"),
        ),
        None => (None, None, None, None),
    };
    let healthz_url = metrics_url.strip_suffix("/metrics").map(|base| format!("{base}/healthz"));
    let (healthy, detail) = match &healthz_url {
        Some(u) => match client.get(u).timeout(std::time::Duration::from_secs(2)).send().await {
            Ok(r) => {
                let ok = r.status().is_success();
                let body = r.text().await.unwrap_or_default();
                (Some(ok), Some(body.trim().to_string()))
            }
            Err(e) => (Some(false), Some(format!("/healthz request failed: {e}"))),
        },
        None => (
            None,
            Some("CT_CP_EDGE_METRICS_URL does not end in /metrics -- cannot derive the edge's /healthz URL".to_string()),
        ),
    };
    EdgeHealthSummary { configured: true, healthy, detail, active_tunnels, active_agents, relay_bytes_total, tcp_fallback_parked }
}

/// `GET /admin-ui/health` (admin-identity-gated, ADR-0025 Decision 6, read-only):
/// one glance at both processes' health -- this control plane's own readiness
/// (`SqliteLedger::ping`, the same check `/readyz` runs) plus the edge's real
/// `/healthz` verdict and a handful of its `/metrics` gauges, aggregated so an
/// admin doesn't have to separately poll two endpoints on two hosts/ports.
async fn admin_ui_health(State(st): State<AdminUiState>, headers: HeaderMap) -> Response {
    if let Err(resp) = admin_ui_authed(&st, &headers) {
        return resp;
    }
    let control_plane_ready = st.ledger.ping().is_ok();
    let edge = edge_health_summary(st.observability.edge_metrics_url.as_deref()).await;
    Json(HealthResp { control_plane_ready, edge }).into_response()
}

/// `GET /admin-ui/system` (admin-identity-gated, read-only): host-level info
/// for the machine this control-plane process is actually running on --
/// hostname, kernel, uptime, load average, CPU count, memory, disk (see
/// [`crate::host_info`] for exactly what's read and why). Operator feedback
/// (2026-08-26): the console showed plenty about the *platform's* state
/// (tunnels, traffic, accounts) but nothing about the *box* it runs on.
/// [`crate::host_info::collect`] does blocking file/subprocess I/O, so it
/// runs on `spawn_blocking` -- same convention `admin_ui_add_domain_hostname`
/// already uses for its own (much slower) subprocess call.
async fn admin_ui_system(State(st): State<AdminUiState>, headers: HeaderMap) -> Response {
    if let Err(resp) = admin_ui_authed(&st, &headers) {
        return resp;
    }
    let disk_path = st.observability.host_info_disk_path.clone();
    match tokio::task::spawn_blocking(move || crate::host_info::collect(disk_path.as_deref())).await {
        Ok(info) => Json(info).into_response(),
        Err(e) => internal_error("admin_ui_system/spawn_blocking", e).into_response(),
    }
}

// ===== end ADR-0025 Decision 6 =====

// ===== ADR-0025 integration pass: dashboard, accounts, audit pages =====
//
// Brand new paths (no prior JSON contract from an earlier phase to preserve), so
// these are plain HTML-only handlers -- no `wants_html` branch needed.

/// `GET /admin-ui/` (admin-identity-gated): the dashboard home -- an at-a-glance
/// health summary (client-fetched from the already-shipped `GET /admin-ui/health`,
/// Observability phase) plus links to every other section.
async fn admin_ui_dashboard(State(st): State<AdminUiState>, headers: HeaderMap) -> Response {
    let session = match admin_ui_page_authed(&st, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    Html(admin_dashboard_page_html(&session)).into_response()
}

fn admin_dashboard_page_html(session: &crate::admin_identity::AdminSession) -> String {
    let body = r#"<h1>Admin console</h1>
<p class="help">At-a-glance health for the control plane and its edge (ADR-0025).</p>
<div id="health" class="help">Loading…</div>
<h2>Host system</h2>
<p class="help">The machine this control-plane process is actually running on -- not the platform's own
traffic/tunnel state (that's everywhere else in this console), just the box underneath it.</p>
<div id="hostSystem" class="help">Loading…</div>
<h2>Sections</h2>
<ul class="steps">
 <li><a href="/admin-ui/traffic">Traffic monitor</a> -- relay bytes and transport per tunnel.</li>
 <li><a href="/admin-ui/accounts">Accounts</a> -- credit, block/unblock, delete, subdomain quota.</li>
 <li><a href="/admin-ui/domains">Domains</a> -- onboard a zone, manage hostnames.</li>
 <li><a href="/admin-ui/admins">Admins</a> -- who can reach this console.</li>
 <li><a href="/admin-ui/certs">Certificates</a> -- front-door and per-domain cert expiry.</li>
 <li><a href="/admin-ui/audit">Audit log</a> -- every privileged action, who and when.</li>
</ul>
<script>
fetch('/admin-ui/health').then(function(r){return r.ok?r.json():Promise.reject(r.status);})
 .then(function(h){
  var edge = h.edge;
  var edgeBadge = !edge.configured ? '<span class="badge warn">not configured</span>'
    : (edge.healthy ? '<span class="badge ok">healthy</span>' : '<span class="badge blocked">unhealthy</span>');
  var stats = '<div class="kv">'
   + '<div class="stat"><span class="n">' + (h.control_plane_ready ? 'OK' : 'DOWN') + '</span><span class="l">Control plane</span></div>'
   + '<div class="stat"><span class="n">' + edgeBadge + '</span><span class="l">Edge</span></div>';
  if(edge.active_tunnels != null){ stats += '<div class="stat"><span class="n">' + edge.active_tunnels + '</span><span class="l">Active tunnels</span></div>'; }
  if(edge.active_agents != null){ stats += '<div class="stat"><span class="n">' + edge.active_agents + '</span><span class="l">Active agents</span></div>'; }
  stats += '</div>';
  if(edge.detail){ stats += '<p class="help">' + String(edge.detail).replace(/&/g,'&amp;').replace(/</g,'&lt;') + '</p>'; }
  document.getElementById('health').innerHTML = stats;
 })
 .catch(function(s){ document.getElementById('health').textContent = 'could not load health (' + s + ')'; });
fetch('/admin-ui/system').then(function(r){return r.ok?r.json():Promise.reject(r.status);})
 .then(function(s){
  function gb(bytes){ return bytes == null ? null : (bytes / (1024*1024*1024)).toFixed(1) + ' GB'; }
  function fmtUptime(secs){
   if(secs == null) return '-';
   var d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600), m = Math.floor((secs % 3600) / 60);
   return (d ? d + 'd ' : '') + (h ? h + 'h ' : '') + m + 'm';
  }
  var memPct = (s.mem_total_bytes && s.mem_available_bytes != null)
   ? Math.round(100 * (s.mem_total_bytes - s.mem_available_bytes) / s.mem_total_bytes) + '% used'
   : null;
  var diskPct = (s.disk_total_bytes && s.disk_available_bytes != null)
   ? Math.round(100 * (s.disk_total_bytes - s.disk_available_bytes) / s.disk_total_bytes) + '% used'
   : null;
  var html = '<div class="kv">'
   + '<div class="stat"><span class="n">' + (s.hostname || '-') + '</span><span class="l">Hostname</span></div>'
   + '<div class="stat"><span class="n">' + (s.kernel || '-') + '</span><span class="l">Kernel</span></div>'
   + '<div class="stat"><span class="n">' + fmtUptime(s.uptime_seconds) + '</span><span class="l">Host uptime</span></div>'
   + '<div class="stat"><span class="n">' + s.cpu_count + '</span><span class="l">CPUs</span></div>'
   + '<div class="stat"><span class="n">' + (s.load_avg_1m != null ? s.load_avg_1m.toFixed(2) + ' / ' + s.load_avg_5m.toFixed(2) + ' / ' + s.load_avg_15m.toFixed(2) : '-') + '</span><span class="l">Load (1/5/15m)</span></div>'
   + '<div class="stat"><span class="n">' + (gb(s.mem_available_bytes) || '-') + ' free of ' + (gb(s.mem_total_bytes) || '-') + '</span><span class="l">Memory' + (memPct ? ' (' + memPct + ')' : '') + '</span></div>'
   + '<div class="stat"><span class="n">' + (gb(s.disk_available_bytes) || '-') + ' free of ' + (gb(s.disk_total_bytes) || '-') + '</span><span class="l">Disk' + (diskPct ? ' (' + diskPct + ')' : '') + ' -- ' + (s.disk_mount || s.disk_path_checked) + '</span></div>'
   + '</div>';
  document.getElementById('hostSystem').innerHTML = html;
 })
 .catch(function(s){ document.getElementById('hostSystem').textContent = 'could not load host system info (' + s + ')'; });
</script>"#;
    admin_page("dashboard", session, body)
}

#[derive(Deserialize)]
struct AccountsPageQuery {
    q: Option<String>,
}

/// `GET /admin-ui/accounts?q=<substring>` (admin-identity-gated): account list +
/// search, wired to the Account Ops phase's per-subject routes. `q` filters by a
/// case-insensitive substring of either the subject or the account id (hex) --
/// server-side, so it works with JS disabled and never ships the full account list
/// to the client just to filter it there.
///
/// The listing itself ([`crate::storage::SqliteLedger::list_accounts`]) is new in
/// this integration pass: the Account Ops phase shipped per-subject credit/block/
/// delete/max-tunnels routes but never a bulk listing to find a subject from in the
/// first place, which this page needs to exist at all -- see this session's final
/// report for why that's flagged as a gap rather than silently worked around.
async fn admin_ui_accounts_page(State(st): State<AdminUiState>, headers: HeaderMap, Query(q): Query<AccountsPageQuery>) -> Response {
    let session = match admin_ui_page_authed(&st, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let rows = match st.ledger.list_accounts() {
        Ok(v) => v,
        Err(e) => return internal_error("admin_ui_accounts_page/list_accounts", e).into_response(),
    };
    // Resolve every row's email live via Keycloak (see ObservabilityConfig::
    // keycloak_admin's doc for why this isn't a ledger column). Concurrent,
    // not sequential -- same join_all shape edge_tunnel_status_bulk already
    // uses for its own N-calls-per-page-render scrape. A failed/missing
    // lookup for one subject just leaves it out of `emails` (rendered as "-",
    // never blocks the rest of the page).
    let emails: std::collections::HashMap<String, String> = match &st.observability.keycloak_admin {
        Some(cfg) => {
            let client = keycloak_admin_http_client();
            futures::future::join_all(rows.iter().map(|r| {
                let subject = r.subject.clone();
                let client = client.clone();
                async move {
                    let email = crate::keycloak_admin::get_user_email(&client, cfg, &subject).await.ok().flatten();
                    (subject, email)
                }
            }))
            .await
            .into_iter()
            .filter_map(|(s, e)| e.map(|e| (s, e)))
            .collect()
        }
        None => std::collections::HashMap::new(),
    };
    let query = q.q.unwrap_or_default();
    let filter = query.trim().to_ascii_lowercase();
    let filtered: Vec<_> = if filter.is_empty() {
        rows
    } else {
        rows.into_iter()
            .filter(|r| {
                r.subject.to_ascii_lowercase().contains(&filter)
                    || r.account_hex.contains(&filter)
                    || emails.get(&r.subject).map(|e| e.to_ascii_lowercase().contains(&filter)).unwrap_or(false)
            })
            .collect()
    };
    Html(admin_accounts_page_html(&session, &filtered, query.trim(), &emails)).into_response()
}

fn admin_accounts_page_html(
    session: &crate::admin_identity::AdminSession,
    rows: &[crate::storage::AccountSummaryRow],
    query: &str,
    emails: &std::collections::HashMap<String, String>,
) -> String {
    let mut table = String::from(
        r#"<table class="data"><thead><tr><th>Subject</th><th>Email</th><th>Account id</th><th>Balance</th><th>State</th><th>Max tunnels</th><th>Actions</th></tr></thead><tbody>"#,
    );
    if rows.is_empty() {
        table.push_str(r#"<tr><td colspan="7" class="help">No accounts match.</td></tr>"#);
    }
    for r in rows {
        let state_badge = if r.blocked { r#"<span class="badge blocked">blocked</span>"# } else { r#"<span class="badge ok">active</span>"# };
        let block_label = if r.blocked { "Unblock" } else { "Block" };
        let email = emails.get(&r.subject).map(|e| escape(e)).unwrap_or_else(|| r#"<span class="help">-</span>"#.to_string());
        table.push_str(&format!(
            r#"<tr>
<td>{subject}</td>
<td>{email}</td>
<td><code style="word-break:break-all">{account}</code></td>
<td>{balance}</td>
<td>{state_badge}</td>
<td>{max_tunnels}</td>
<td><div style="display:flex;flex-wrap:wrap;gap:.35rem;align-items:center">
 <form class="inline" data-subject="{subject}" onsubmit="return creditAccount(event)">
  <input type="number" name="amount" min="1" value="100" style="width:5rem">
  <button type="submit" class="sec">Credit</button>
 </form>
 <button class="sec" data-subject="{subject}" data-blocked="{blocked_flag}" onclick="return toggleBlock(event)">{block_label}</button>
 <form class="inline" data-subject="{subject}" onsubmit="return setMaxTunnels(event)">
  <input type="number" name="max" min="1" value="{max_tunnels}" style="width:4rem">
  <button type="submit" class="sec">Set quota</button>
 </form>
 <button class="danger" data-subject="{subject}" onclick="return deleteAccount(event)">Delete</button>
</div></td>
</tr>"#,
            subject = escape(&r.subject),
            email = email,
            account = escape(&r.account_hex),
            balance = r.balance,
            state_badge = state_badge,
            max_tunnels = r.max_tunnels,
            blocked_flag = r.blocked,
            block_label = block_label,
        ));
    }
    table.push_str("</tbody></table>");

    let body = format!(
        r#"<h1>Accounts</h1>
<p class="help">Every subject with an account, its credit balance, block state, and
tunnel-creation quota. Credit grants call the same durable ledger a payment webhook
credits -- this IS the admin top-up, not a separate mechanism. Email is resolved live
from Keycloak (not stored in the ledger itself) -- shows "-" for a subject whose
Keycloak account no longer exists, or if this deployment has no Keycloak admin API
configured at all.</p>
<form method="get" action="/admin-ui/accounts" class="search-form">
 <label>Search by subject, email, or account id <input type="text" name="q" value="{query}" placeholder="alice@example.com"></label>
 <button type="submit" class="sec">Search</button>
</form>
{table}
<script>
function creditAccount(ev){{
 ev.preventDefault();
 var form = ev.target;
 var subject = form.getAttribute('data-subject');
 var amount = parseInt(form.amount.value, 10);
 if(!amount || amount < 1) return false;
 adminApi('POST', '/admin-ui/accounts/' + encodeURIComponent(subject) + '/credit', {{amount: amount}})
  .then(function(){{ location.reload(); }})
  .catch(function(e){{ window.alert('credit failed: ' + e.message); }});
 return false;
}}
function toggleBlock(ev){{
 ev.preventDefault();
 var btn = ev.target;
 var subject = btn.getAttribute('data-subject');
 var blocked = btn.getAttribute('data-blocked') === 'true';
 var action = blocked ? 'unblock' : 'block';
 if(action === 'block' && !window.confirm('Block ' + subject + '? This refuses new credit-gated issuance and self-service tunnel creation for this account.')) return false;
 adminApi('POST', '/admin-ui/accounts/' + encodeURIComponent(subject) + '/' + action)
  .then(function(){{ location.reload(); }})
  .catch(function(e){{ window.alert(action + ' failed: ' + e.message); }});
 return false;
}}
function setMaxTunnels(ev){{
 ev.preventDefault();
 var form = ev.target;
 var subject = form.getAttribute('data-subject');
 var max = parseInt(form.max.value, 10);
 if(!max || max < 1) return false;
 adminApi('POST', '/admin-ui/accounts/' + encodeURIComponent(subject) + '/max-tunnels', {{max: max}})
  .then(function(){{ location.reload(); }})
  .catch(function(e){{ window.alert('quota update failed: ' + e.message); }});
 return false;
}}
function deleteAccount(ev){{
 ev.preventDefault();
 var subject = ev.target.getAttribute('data-subject');
 if(!window.confirm('Permanently delete ' + subject + '? This revokes every tunnel and deletes every channel, topology, network, and pipeline this account owns, plus the ledger row itself. This cannot be undone.')) return false;
 adminApi('POST', '/admin-ui/accounts/' + encodeURIComponent(subject) + '/delete')
  .then(function(){{ location.reload(); }})
  .catch(function(e){{ window.alert('delete failed: ' + e.message); }});
 return false;
}}
</script>"#,
        query = escape(query),
        table = table,
    );
    admin_page("accounts", session, &body)
}

/// `GET /admin-ui/audit` (admin-identity-gated): the most recent admin-audit-log
/// entries (Foundation phase's `audit_log::SqliteAuditLog::recent`) -- who did
/// what, to what, and when. Any verified admin may view this (mirrors
/// `admin_ui_list_admins`'s "viewing isn't itself a privileged mutation" posture);
/// only the actions themselves are privileged, not reading the record of them.
async fn admin_ui_audit_page(State(st): State<AdminUiState>, headers: HeaderMap) -> Response {
    let session = match admin_ui_page_authed(&st, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let entries = match st.audit.recent(200) {
        Ok(v) => v,
        Err(e) => return internal_error("admin_ui_audit_page/recent", e).into_response(),
    };
    Html(admin_audit_page_html(&session, &entries)).into_response()
}

fn admin_audit_page_html(session: &crate::admin_identity::AdminSession, entries: &[crate::audit_log::AuditLogEntry]) -> String {
    let mut table = String::from(
        r#"<table class="data"><thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead><tbody>"#,
    );
    if entries.is_empty() {
        table.push_str(r#"<tr><td colspan="5" class="help">No admin actions recorded yet.</td></tr>"#);
    }
    for e in entries {
        table.push_str(&format!(
            r#"<tr><td><span data-ts="{at}">{at}</span></td><td>{actor}</td><td><code>{action}</code></td><td>{target}</td><td class="help">{detail}</td></tr>"#,
            at = e.at,
            actor = escape(&e.actor_email),
            action = escape(&e.action),
            target = e.target.as_deref().map(escape).unwrap_or_else(|| "-".to_string()),
            detail = e.detail.as_deref().map(escape).unwrap_or_default(),
        ));
    }
    table.push_str("</tbody></table>");
    let body = format!(
        r#"<h1>Audit log</h1>
<p class="help">Every privileged admin action recorded immutably -- actor, action, target, and
detail (ADR-0025 Decision 6). The most recent {count} entries, newest first.</p>
{table}"#,
        count = entries.len(),
        table = table,
    );
    admin_page("audit", session, &body)
}

// ===== end ADR-0025 integration pass: dashboard, accounts, audit pages =====

// ===== end ADR-0025 `/admin-ui/*` =====

/// A new tunnel from the create form. #439 follow-up: linked from the UI
/// (`tunnels_html`'s create-another-tunnel form) whenever the caller's owned
/// tunnel count is under their account's real `max_tunnels` — see
/// [`tunnels_page`]. Server-side enforcement (`create_tunnel`'s own
/// owned-count-vs-limit check) stays authoritative either way, so a direct
/// POST past a stale/cached page is still rejected.
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
/// one tunnel per account by default, auto-provisioned right here on first
/// view (with an auto-assigned hostname when DNS is configured) — see the
/// tunnel's Install link for its tokens. #439 follow-up: an account's real
/// `max_tunnels` (default 1, admin-raisable via `POST
/// /admin/accounts/:subject/max-tunnels`) governs whether [`tunnels_html`]'s
/// create-another-tunnel form is real/enabled or disabled-with-quota-copy —
/// custom/vanity hostnames stay a planned paid tier either way (see
/// [`auto_hostname`]).
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
    let Some(claims) = session_claims_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    let subject = claims.subject;
    let owns_one = match st.tunnels.list_authorized_for_subject(&subject) {
        Ok(rows) => rows.iter().any(|(_, owned)| *owned),
        Err(e) => return internal_error("tunnels_page/list(owns_one)", e).into_response(),
    };
    if !owns_one {
        provision_tunnel(&st, &subject, "site").await;
    }
    // #439 follow-up (operator instruction): the "create another tunnel" form
    // must reflect the account's REAL quota (owned-tunnel count vs. its real
    // max_tunnels, admin-raisable via POST /admin/accounts/:subject/max-tunnels)
    // instead of always being hard-disabled -- so a revoke really does free up
    // a slot for self-service creation. Same account/limit lookup create_tunnel
    // itself already gates on.
    let max_tunnels = match st.ledger.account_for_subject(&subject) {
        Ok(account) => match st.ledger.max_tunnels(&account) {
            Ok(m) => m,
            Err(e) => return internal_error("tunnels_page/max_tunnels", e).into_response(),
        },
        Err(e) => return internal_error("tunnels_page/account_for_subject", e).into_response(),
    };
    match st.tunnels.list_authorized_for_subject(&subject) {
        Ok(tunnels) => {
            // #233/#437: fetch each hostname's Rot/Gelb/Grün admission state, and
            // (monitoring v1) its live connection status, alongside its tunnel row
            // -- best-effort per-row (a lookup failure just omits that row's badge
            // rather than failing the whole page, matching this handler's existing
            // tolerance for partial data). Every store lookup is now batched into
            // one query regardless of row count (the admission lookup already was,
            // #351); `edge_tunnel_status`'s HTTP scrape runs concurrently via
            // `join_all` instead of one sequential await per row.
            let hostnames: Vec<&str> =
                tunnels.iter().filter_map(|(t, _)| t.hostname.as_deref()).collect();
            let admissions = st.tunnels.cert_admission_for_hostnames(&hostnames).unwrap_or_default();
            let tunnel_ids: Vec<&str> = tunnels.iter().map(|(t, _)| t.id.as_str()).collect();
            let require_logins = st.tunnels.require_login_batch(&subject, &tunnel_ids).unwrap_or_default();
            let allow_and_pending = st.tunnels.allowlist_and_pending_batch(&subject, &tunnel_ids).unwrap_or_default();
            let statuses: Vec<_> =
                futures::future::join_all(tunnels.iter().map(|(t, _)| edge_tunnel_status(&st, &t.routing_token))).await;
            let mut rows = Vec::with_capacity(tunnels.len());
            for ((t, owned), status) in tunnels.into_iter().zip(statuses) {
                let admission = t.hostname.as_deref().and_then(|h| admissions.get(h).cloned());
                // #382-follow (Browser-Plane login gate): owner-scoped, so a shared
                // (not-owned) row simply gets the off/empty defaults -- matching the
                // existing owner-only convention for Revoke/Share above.
                let (require_login, allow_any_login) =
                    require_logins.get(&t.id).copied().unwrap_or((false, false));
                let (login_allowlist, pending_requests) =
                    allow_and_pending.get(&t.id).cloned().unwrap_or_default();
                rows.push((t, owned, admission, status, require_login, allow_any_login, login_allowlist, pending_requests));
            }
            Html(tunnels_html(&rows, max_tunnels, claims.email.as_deref())).into_response()
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
    // #432: atomic count-check + insert (see create_if_under_owned_limit's own
    // doc) -- auto-provisioning has always been capped at exactly 1 regardless of
    // an account's real (possibly admin-raised) max_tunnels, matching this
    // function's existing "owns_one" caller-side pre-check in tunnels_page;
    // unchanged here, just made race-free. `Ok(None)` means a concurrent request
    // already provisioned one first -- nothing to do, not an error.
    let tunnel = match st.tunnels.create_if_under_owned_limit(subject, display_name, hostname.as_deref(), 1) {
        Ok(crate::storage::CreateTunnelOutcome::Created(t)) => t,
        // OverLimit: a concurrent request provisioned first -- nothing to do, not an
        // error. HostnameTaken: the derived hostname already exists (e.g. an older
        // row); auto-provisioning must not fight it -- the page shows what exists.
        Ok(_) => return,
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
    // ADR-0025: the enforcer for `POST /admin-ui/hostnames/:host/disable` -- this
    // is the ONE function every path that would (re-)authorize a hostname at the
    // edge already funnels through (auto-provision, admin_provision_tunnel,
    // create_tunnel), so it is the one place the check needs to live. Fails
    // CLOSED on a storage error (skips authorization) rather than open: the whole
    // point of this check is a security control an admin explicitly asked for,
    // and a transient DB hiccup letting a disabled hostname back onto the edge
    // would defeat it silently -- a spurious skip on a healthy, non-disabled
    // hostname self-heals on the next call, which a live block being bypassed
    // does not.
    match st.tunnels.is_hostname_disabled(host) {
        Ok(true) => {
            eprintln!(
                "ct-cp: edge authorize-host SKIPPED for {host} -- hostname is admin-disabled \
                 (ADR-0025); re-enable it via /admin-ui/hostnames/{host}/enable first"
            );
            return;
        }
        Ok(false) => {}
        Err(e) => {
            eprintln!("ct-cp: is_hostname_disabled check for {host} failed: {e} -- authorize SKIPPED (fail-closed)");
            return;
        }
    }
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

/// `POST /portal/tunnels`: the caller's own included tunnel is
/// auto-provisioned elsewhere (see [`tunnels_page`]) — this handler is for
/// self-service creation of ADDITIONAL tunnels, once the account's owned
/// count is under its real `max_tunnels`. #439 follow-up: now genuinely
/// linked from the UI (`tunnels_html`'s create-another-tunnel form) whenever
/// that's true, rather than only reachable by a direct POST. Still the sole
/// enforcement point either way: rejects a request over the limit even if
/// posted directly, so a stale/cached page can never bypass the real quota
/// check.
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
    let account = match st.ledger.account_for_subject(&subject) {
        Ok(a) => a,
        Err(e) => return internal_error("create_tunnel/account_for_subject", e).into_response(),
    };
    // ADR-0025: the tunnel-creation admission gate for an admin-blocked account --
    // checked before the max-tunnels gate below so a blocked account gets an
    // honest "you are blocked" rather than being told it's merely over its quota.
    // This is the OTHER real admission point the admin console's block action
    // relies on, alongside `SqliteLedger::debit`/`debit_and_record_issuance` --
    // portal-created tunnels never call those (they're free within the account's
    // `max_tunnels`), so without this check here specifically, a blocked account
    // could still self-serve new tunnels.
    match st.ledger.is_blocked(&account) {
        Ok(true) => {
            return (StatusCode::FORBIDDEN, "this account is blocked from creating tunnels").into_response()
        }
        Ok(false) => {}
        Err(e) => return internal_error("create_tunnel/is_blocked", e).into_response(),
    }
    // #214: the Standard tier's default is 1 tunnel per account, but an
    // operator can raise this for a SPECIFIC account (SqliteLedger::
    // set_max_tunnels, via POST /admin/accounts/:subject/max-tunnels) to
    // unlock self-service creation of additional subdomains -- so the gate
    // compares against that account's own limit, not a hardcoded "ever own
    // one at all".
    let max = match st.ledger.max_tunnels(&account) {
        Ok(m) => m,
        Err(e) => return internal_error("create_tunnel/max_tunnels", e).into_response(),
    };
    let hostname = st
        .dns
        .as_ref()
        .map(|d| auto_hostname(d.client.domain(), name, &subject))
        .as_deref()
        .and_then(ct_common::normalize_hostname);
    // Same reasoning as provision_tunnel: show the account-unique hostname
    // label, not the bare user-typed name two different accounts could share.
    let display_name = hostname.as_deref().and_then(|h| h.split('.').next()).unwrap_or(name);
    // #432: the count check and the insert now run as one atomic unit under the
    // store's own writer lock (create_if_under_owned_limit) -- previously a
    // separate list_authorized_for_subject() read followed by create() let two
    // concurrent requests both observe owned_count < max before either commit.
    let tunnel = match st.tunnels.create_if_under_owned_limit(&subject, display_name, hostname.as_deref(), max) {
        Ok(crate::storage::CreateTunnelOutcome::Created(t)) => t,
        Ok(crate::storage::CreateTunnelOutcome::OverLimit) => {
            return (
                StatusCode::FORBIDDEN,
                "the Standard tier includes one tunnel per account; additional tunnels are a planned paid-tier feature (or ask the operator to raise your account's limit)",
            )
                .into_response()
        }
        // Operator bug report (15.08.): this used to hit the UNIQUE(hostname)
        // constraint and render as a bare 500 "internal error".
        Ok(crate::storage::CreateTunnelOutcome::HostnameTaken) => {
            return (
                StatusCode::CONFLICT,
                "that name is already taken by one of your tunnels (hostnames derive \
                 deterministically from the name) -- pick a different name",
            )
                .into_response()
        }
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
/// Strip the scheme + any trailing slash from a portal base URL down to a bare
/// `host[:port]` -- the common first step for deriving any Mesh-Plane/Agent-Fabric
/// rendezvous address from the portal's own public origin (shared by
/// [`edge_host_port`] and [`channel_deployment`]).
fn portal_host(portal_base: &str) -> &str {
    portal_base
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
}

/// #512: the ONE source for the released ct-agent tag this repo points users at —
/// the repo-root `CT_AGENT_RELEASE` file, embedded at compile time. A release bump
/// is a one-file change; the help-site example's Dockerfile/compose defaults are
/// asserted against this same source by the install-page test, so the pin
/// scatter that caused the #502 class (seven pins, four values) cannot re-grow
/// around the user-facing install surfaces. (The wasm/relay-node/e2e build pins
/// are deliberately NOT tied to this: they are API-drift-gated, see #507.)
pub(crate) fn ct_agent_release_tag() -> &'static str {
    include_str!("../../../CT_AGENT_RELEASE").trim()
}

pub(crate) fn edge_host_port(portal_base: &str) -> String {
    format!("{}:{}", portal_host(portal_base), crate::service::NetworkInfoResp::from_env().mesh_edge_port)
}

async fn install_page(State(st): State<ApiState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let Some(claims) = session_claims_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    let subject = claims.subject;
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
    // #502-class audit finding (2026-08-14): this used to clone CADS-Tunnel and build
    // its `-p ct-agent` GIT DEPENDENCY -- pinned at a v0.3.0-era rev, months behind
    // the released agent (missing the #16 UDP fallback, the whole v0.4.x line, and
    // the #494 first-contact fix). Every self-service install got a stale agent that
    // LOOKED broken for its first minute. Build the standalone release tag instead;
    // bump this tag alongside releases.
    let tag = ct_agent_release_tag();
    let build_cmd = format!(
        "git clone https://github.com/scimbe/ct-agent.git && cd ct-agent && git checkout {tag}\ndocker run --rm -v \"$PWD\":/work -w /work rust:1-slim \\\n  cargo build --release --locked -p ct-agent --bin ct-agent\n# binary is now at ./target/release/ct-agent -- no Rust toolchain needed on your machine\n# (or skip the build: download a prebuilt binary from https://github.com/scimbe/ct-agent/releases/tag/{tag})"
    );
    let build_cmd = build_cmd.as_str();
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
    // Windows/PowerShell has no `source` concept, so `.env` isn't picked up on
    // its own -- ct-agent has no built-in dotenv support (only reads live
    // process env vars, confirmed: no dotenv-family crate in this workspace),
    // so the bash step's `source .env` is doing real, necessary work of
    // exporting each line into the shell that PowerShell needs an equivalent
    // for. The `.env` file content itself stays the SAME single source of
    // truth above (not duplicated here) -- only this run step gets a second,
    // OS-appropriate form. `.exe` under `target\release\` is the standard
    // Cargo cross-compile convention (this repo has no Windows CI/build docs
    // that say otherwise).
    let run_cmd_ps = "Get-Content .env | ForEach-Object {\n  if ($_ -match '^\\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {\n    $value = $matches[2] -replace '\\s+#.*$', ''\n    [System.Environment]::SetEnvironmentVariable($matches[1], $value.Trim(), 'Process')\n  }\n}\n.\\target\\release\\ct-agent.exe onboard";
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
 <div class="tab-row">
  <button type="button" class="tab-btn active" onclick="showTab(this,'run-bash')">bash</button>
  <button type="button" class="tab-btn" onclick="showTab(this,'run-powershell')">PowerShell</button>
 </div>
 <div class="code-block" id="run-bash" data-tab="bash">
  <div class="code-block-head"><span>bash</span><button class="copy-btn" onclick="copyCode(this)" type="button">Copy</button></div>
  <pre><code>{run_cmd}</code></pre>
 </div>
 <div class="code-block" id="run-powershell" data-tab="powershell" style="display:none">
  <div class="code-block-head"><span>PowerShell</span><button class="copy-btn" onclick="copyCode(this)" type="button">Copy</button></div>
  <pre><code>{run_cmd_ps}</code></pre>
 </div>
 <p class="help">That's it &mdash; <code>ct-agent</code> redeems the join token, binds your tunnel's
 routing token, and starts serving your origin through the relay end-to-end encrypted. A one-line
 installer is planned but not ready yet (#75). See the
 <a href="https://github.com/scimbe/CADS-Tunnel/blob/main/docs/onboarding/quickstart.md">onboarding guide</a>
 for troubleshooting.</p>
</details>

<a class="btn sec" href="/portal/tunnels">Back to tunnels</a>"#,
    );
    Html(page("install", &body, claims.email.as_deref())).into_response()
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
    let Some(claims) = session_claims_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    match st.tunnels.list_grants(&claims.subject, &id) {
        Ok(grantees) => Html(grants_html(&id, &grantees, claims.email.as_deref())).into_response(),
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

fn grants_html(id: &str, grantees: &[String], email: Option<&str>) -> String {
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
    page("share tunnel", &body, email)
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
fn login_gate_html(id: &str, require_login: bool, allow_any_login: bool, login_allowlist: &[String], pending_requests: &[(String, String, i64)]) -> String {
    let checked = if require_login { " checked" } else { "" };
    let allowlist_section = if require_login {
        // #501: the self-service complement -- while this is on, the access list below
        // is ignored and ANY signed-in account passes the gate. Rendered first so the
        // owner reads the mode before the list it overrides.
        let any_checked = if allow_any_login { " checked" } else { "" };
        let any_note = if allow_any_login {
            r#"<p class="k">Any signed-in account may enter -- the access list below is ignored while this is on.</p>"#
        } else {
            ""
        };
        let allow_any_form = format!(
            r#"<form method="post" action="/portal/tunnels/{id}/allow-any-login">
 <label><input type="checkbox" name="enabled"{any_checked}> Allow any signed-in account</label>
 <button type="submit">Update</button></form>{any_note}"#
        );
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
            r#"<div class="row">{allow_any_form}<ul class="login-allowlist">{items}</ul>{empty_note}
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
    bool, // #501: allow_any_login
    Vec<String>,
    Vec<(String, String, i64)>,
);

fn tunnels_html(tunnels: &[TunnelRow], max_tunnels: u32, email: Option<&str>) -> String {
    // #439 follow-up: owned_count is derived from the SAME rows the page just
    // fetched live from the store (list_authorized_for_subject), not a cached
    // value -- so a revoke that already committed (delete_tunnel -> revoke())
    // before this render is reflected immediately: revoke frees a slot on the
    // very next GET /portal/tunnels.
    let owned_count = tunnels.iter().filter(|(_, owned, ..)| *owned).count() as u32;
    let rows = tunnels
        .iter()
        .map(|(t, owned, admission, status, require_login, allow_any_login, login_allowlist, pending_requests)| {
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
 <form class="inline fade-out-submit confirm-revoke" method="post" action="/portal/tunnels/{id}/delete">
  <button class="btn danger" type="submit" title="Permanently deletes this tunnel. This cannot be undone via self-service today.">Revoke</button></form>
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
                login_gate_html(&id, *require_login, *allow_any_login, login_allowlist, pending_requests)
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
    // #439 follow-up: the create-another-tunnel form now reflects the
    // account's REAL quota state instead of always being hard-disabled.
    // `create_tunnel` (POST /portal/tunnels) already enforces the same
    // owned_count < max_tunnels check server-side (#432's atomic
    // create_if_under_owned_limit) -- this form is what makes that real,
    // already-working endpoint actually discoverable/usable, not a new
    // creation path. `CreateTunnelForm { name: String }` is exactly the
    // `<input name="name">` shape posted below.
    let create_form = if owned_count < max_tunnels {
        format!(
            r#"<h2>Create another tunnel</h2>
<p class="help">You're using {owned_count} of {max_tunnels} tunnels included in your plan.</p>
<form method="post" action="/portal/tunnels">
 <label>Name
  <input type="text" name="name" placeholder="e.g. my-api" required>
 </label>
 <button type="submit">Create</button>
</form>"#
        )
    } else {
        format!(
            r#"<h2>Create another tunnel</h2>
<p class="help">You've used all {max_tunnels} tunnel{plural} included in your plan. More tunnels
may become available for your account &mdash; contact the operator if you need another one now.</p>
<form aria-disabled="true">
 <label>Name
  <input type="text" placeholder="e.g. my-api" disabled>
 </label>
 <button type="submit" disabled>Create</button>
</form>"#,
            plural = if max_tunnels == 1 { "" } else { "s" }
        )
    };
    let body = format!(
        r#"<h1>Your tunnels</h1>
{rows}
<p class="help">Included in every tier: <strong>one</strong> tunnel with an automatically
assigned hostname (e.g. <code>site-a1b2c3d4.bunsenbrenner.org</code>) &mdash; already set up for
you above, nothing to configure. Click <strong>Install</strong> to get its tokens.</p>
{create_form}
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
    page("your tunnels", &body, email)
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
/// #492: the signed-in session's e-mail, shown in the nav next to "Sign out" so
/// it's never ambiguous which account a page is acting as -- easy to lose track
/// of when switching between several test/demo accounts. `email` comes straight
/// from the session cookie's own verified-email claim ([`crate::portal::SessionClaims`]),
/// never a fresh lookup, so this can never fail or block: `None` (no verified
/// email on this session, or OIDC not configured in this deployment mode) simply
/// omits the line entirely, same "absent renders nothing rather than a
/// misleading state" rule the connection-status badge already follows
/// ([`tunnels_html`]).
pub(crate) fn page(title: &str, body: &str, email: Option<&str>) -> String {
    let signed_in_as = email
        .map(|e| format!(r#"<span class="signed-in-as">Signed in as <strong>{}</strong></span>"#, escape(e)))
        .unwrap_or_default();
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
 nav .signed-in-as{{color:var(--muted);margin-right:1rem;font-size:.9rem}}
 nav .signed-in-as strong{{color:var(--text);font-weight:600}}
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
 /* No resting max-height: a fixed cap (640px historically) let long cards --
    require-login + allowlist + pending requests + the Gelb notice easily exceed
    it on a phone -- BLEED over the neighbouring card (overflow is visible at
    rest by design; only .leaving clips). The collapse-to-0 removal animation
    gets its from-value measured in JS (scrollHeight) right before .leaving is
    added, so it stays smooth without any cap. */
 .tunnel-card{{border:1px solid var(--border);border-radius:10px;padding:.2rem 1rem;margin:0 0 1rem;
      background:#131820;animation:cardIn .3s ease-out backwards;
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
 /* Only the access-list itself scrolls internally when it gets long -- not the
    whole .tunnel-card (that used to have its own overflow-y:auto, which
    clipped/scrolled the entire card, tokens/buttons and all, instead of just
    this list). 220px comfortably shows ~3-4 rows (each <li> caps at 60px)
    before it starts scrolling. */
 .login-allowlist{{max-height:220px;overflow-y:auto}}
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
 label input:not([type=checkbox]):not([type=radio]){{display:block;margin-top:.3rem;width:100%;max-width:360px}}
 /* Checkboxes/radios must stay inline with their label text (e.g. "Require
    login to access this tunnel") -- the block-level rule above was written
    for text inputs nested `<label>Name<input></label>`-style and previously
    matched checkboxes too, forcing them onto their own line above the text. */
 label input[type=checkbox],label input[type=radio]{{width:auto;margin:0 .4rem 0 0;vertical-align:middle}}
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
 /* bash/PowerShell (or any other OS-specific step) toggle: two labeled tab
    buttons switching which sibling .code-block is shown -- see showTab() below. */
 .tab-row{{display:flex;gap:.4rem;margin:.6rem 0 -.2rem}}
 .tab-btn{{background:#161b22;border:1px solid #30363d;color:#8b949e;border-radius:6px 6px 0 0;
  padding:.35rem .8rem;font-size:.78rem;font-weight:600;cursor:pointer}}
 .tab-btn:hover{{color:#e6edf3}}
 .tab-btn.active{{background:#0d1117;color:#e6edf3;border-bottom-color:#0d1117}}
 details{{margin:1.1rem 0;border:1px solid #30363d;border-radius:8px;padding:.7rem .9rem}}
 summary{{cursor:pointer;color:#58a6ff;font-weight:600}}
 summary:hover{{color:#79c0ff}}
 details h3{{font-size:.95rem;color:#e6edf3;margin:1rem 0 .4rem}}
 details[open] summary{{margin-bottom:.4rem}}
</style></head><body>
<div class="card">
<nav><a href="/portal/account">Account</a><a href="/portal/tunnels">Tunnels</a><a href="/portal/channels">Channels</a><a href="/portal/topologies">Topologies</a>{signed_in_as}<a href="/portal/logout">Sign out</a></nav>
{body}
</div>
<script>
 function copyCode(btn){{
  const code = btn.closest('.code-block').querySelector('code');
  const text = code ? code.textContent : '';
  const done = () => {{ const orig = btn.textContent; btn.textContent = 'Copied'; setTimeout(()=>{{ btn.textContent = orig; }}, 1600); }};
  if(navigator.clipboard && navigator.clipboard.writeText){{ navigator.clipboard.writeText(text).then(done).catch(()=>{{}}); }}
 }}
 // Generic OS/shell tab toggle (e.g. install page's bash vs PowerShell "Run it"
 // step): switches which sibling .code-block is visible and which .tab-btn is
 // marked active, all within the same .tab-row's parent -- no new JS framework,
 // same inline-<script> style as copyCode above.
 function showTab(btn, showId){{
  var row = btn.closest('.tab-row');
  if(!row) return;
  var group = row.parentElement;
  var buttons = row.querySelectorAll('.tab-btn');
  for(var i=0;i<buttons.length;i++){{ buttons[i].classList.toggle('active', buttons[i] === btn); }}
  var blocks = group.querySelectorAll('.code-block[data-tab]');
  for(var j=0;j<blocks.length;j++){{ blocks[j].style.display = (blocks[j].id === showId) ? '' : 'none'; }}
 }}
 // Progressive enhancement for any `form.fade-out-submit` (tunnel Revoke,
 // login-allowlist Remove): fade/collapse the enclosing .tunnel-card or <li>
 // out before letting the real (unmodified) POST proceed, instead of the row
 // just vanishing on the next full-page reload. Without JS, or with reduced
 // motion requested, the form submits immediately -- nothing here is load-bearing.
 document.addEventListener('submit', function(ev){{
  var form = ev.target;
  // #439 (part 2 only -- whether Revoke should step down to a shared Gelb
  // certificate instead of deleting is an unresolved product decision, left
  // alone here): make the destructive, irreversible-via-self-service nature
  // of tunnel Revoke explicit before the request goes out, since the button
  // itself otherwise reads like any other action.
  if(form.classList && form.classList.contains('confirm-revoke')){{
   if(!window.confirm('Revoke this tunnel? This permanently deletes it right now. There is no self-service way to undo this or get it back.')){{
    ev.preventDefault();
    return;
   }}
  }}
  if(!form.classList || !form.classList.contains('fade-out-submit')){{ return; }}
  if(window.matchMedia('(prefers-reduced-motion: reduce)').matches){{ return; }}
  // Most-specific ancestor first: a login-allowlist Remove form sits inside a
  // <li> that is itself inside the tunnel's own .tunnel-card -- closest('li')
  // must win so removing one email only fades that one list item, not the
  // whole tunnel card it happens to live inside.
  var target = form.closest('li') || form.closest('.tunnel-card') || form;
  if(target.classList.contains('leaving')){{ return; }}
  ev.preventDefault();
  // Measure the collapse's from-value: .leaving animates max-height to 0, and
  // since the resting card carries NO max-height (a fixed cap made tall cards
  // bleed over their neighbours on phones), the transition needs a concrete
  // starting height set inline first (reflow forced so it takes effect).
  target.style.maxHeight = target.scrollHeight + 'px';
  void target.offsetHeight;
  target.classList.add('leaving');
  setTimeout(function(){{ form.submit(); }}, 220);
 }});
</script>
</body></html>"#
    )
}

fn account_html(subject: &str, account_hex: &str, balance: u64, account_console_url: Option<&str>, email: Option<&str>) -> String {
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
    page("your account", &body, email)
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
/// the session key + the channel store, plus (as of the post-claim onboarding
/// follow-up) what [`channel_deployment`] needs to render a real `.env` after a
/// successful claim -- kept deliberately separate from the much larger [`ApiState`]
/// so this addition doesn't have to thread a new param through every existing
/// `portal_api_router` call site.
#[derive(Clone)]
struct ClaimState {
    session_key: Arc<[u8]>,
    channels: Arc<crate::storage::SqliteChannelStore>,
    /// Public portal origin -- same value/purpose as [`ApiState::portal_base`],
    /// duplicated here rather than merging the two states (see the struct doc).
    portal_base: Arc<str>,
    /// Where the edge CA root DER lives on disk -- the SAME file/value `GET /pki/ca`
    /// serves (`CT_CP_EDGE_CERT_PATH`), reused as the `:443` channel front door's
    /// trust anchor. See [`channel_deployment`]'s doc for why this is the live
    /// source of truth instead of a value baked in at build time.
    edge_cert_path: Arc<str>,
}

/// Build the channel-allowlist claim router (#248-follow): a `GET`/`POST` page for
/// people to self-serve their claim from a browser, plus the pre-existing `POST
/// .../claim` JSON API for programmatic callers, session-cookie authed either way.
/// Mount alongside [`portal_api_router`] wherever the channel store is already in scope.
/// `portal_base`/`edge_cert_path` are the same values `install_page`/`pki_router`
/// already use elsewhere (see [`ApiState::portal_base`], `pki_router`'s `cert_path`).
pub fn channel_claim_router(
    session_key: &[u8],
    channels: Arc<crate::storage::SqliteChannelStore>,
    portal_base: &str,
    edge_cert_path: &str,
) -> Router {
    Router::new()
        .route("/portal/channels", get(channels_page))
        .route("/portal/channels/:channel/claim", get(claim_page).post(claim_channel))
        .route("/portal/channels/:channel/grant", get(fetch_deposited_grant))
        .route("/portal/channels/:channel/claim-form", post(claim_page_submit))
        .route("/portal/static/ct_agent_wasm.js", get(serve_ct_agent_wasm_js))
        .route("/portal/static/ct_agent_wasm_bg.wasm", get(serve_ct_agent_wasm_bg))
        .with_state(ClaimState {
            session_key: Arc::from(session_key.to_vec()),
            channels,
            portal_base: Arc::from(portal_base),
            edge_cert_path: Arc::from(edge_cert_path),
        })
}

/// The compiled `ct-agent-wasm` bundle (in-browser Agent-Fabric channel identity generation +
/// attestation signing -- see [`claim_html`]'s `<script type="module">`), embedded at compile
/// time via `include_bytes!` so the control plane ships as one self-contained binary with no
/// separate static-file directory to manage -- matches this crate's existing "every page is an
/// inline-HTML-string handler" architecture (there is no `ServeDir`/tower-http static-file
/// setup anywhere in this crate; this is deliberately NOT the exception that introduces one).
///
/// These bytes come from `$OUT_DIR` (populated by `crates/control-plane/build.rs`, NOT this
/// crate's own `wasm-pkg/` directly) -- see that build script's doc comment for the full
/// picture: the REAL bundle is produced by `scripts/build-ct-agent-wasm.sh` or automatically by
/// `docker/Dockerfile`'s `wasm-builder` stage; a plain `cargo build`/`cargo test` with neither
/// of those having run falls back to an inert placeholder, so the workspace gate never depends
/// on Docker or network access. A deployment that skips the real wasm build ships a portal
/// claim page whose in-browser identity generation simply doesn't work (a clear, loud JS error,
/// not a silent/incorrect one -- see the placeholder's own `throw`) rather than failing to
/// compile.
const CT_AGENT_WASM_JS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ct_agent_wasm.js"));
const CT_AGENT_WASM_BG: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ct_agent_wasm_bg.wasm"));

/// `GET /portal/static/ct_agent_wasm.js` -- the wasm-bindgen `--target web` JS glue module
/// [`claim_html`]'s script `import`s. `application/javascript` (not `text/javascript`; both are
/// valid per the WHATWG HTML spec's "JavaScript MIME type" list, but `application/javascript`
/// matches what every other example in this ecosystem -- CADS-webconference-demo,
/// CADS-DEMO-sort -- already serves it as).
async fn serve_ct_agent_wasm_js() -> impl IntoResponse {
    ([(axum::http::header::CONTENT_TYPE, "application/javascript")], CT_AGENT_WASM_JS)
}

/// `GET /portal/static/ct_agent_wasm_bg.wasm` -- the compiled wasm binary itself.
/// `application/wasm` is required (not merely conventional): browsers only take the
/// streaming-compilation fast path (`WebAssembly.instantiateStreaming`, which wasm-bindgen's
/// `--target web` glue calls internally) when the response's `Content-Type` is exactly this.
async fn serve_ct_agent_wasm_bg() -> impl IntoResponse {
    ([(axum::http::header::CONTENT_TYPE, "application/wasm")], CT_AGENT_WASM_BG)
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
        .route("/portal/tunnels/:id/allow-any-login", post(set_allow_any_login_route))
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
struct LoginPolicyForm {
    /// Present (any value) when the portal checkbox was checked; absent when
    /// unchecked -- standard HTML checkbox-form semantics, not a boolean field.
    enabled: Option<String>,
}

async fn set_allow_any_login_route(
    State(st): State<LoginGateState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<LoginPolicyForm>,
) -> Response {
    // #501: same owner-scoping and form shape as the require-login toggle below.
    let Some(subject) = crate::portal::session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    match st.tunnels.set_allow_any_login(&subject, &id, form.enabled.is_some()) {
        Ok(true) => Redirect::to("/portal/tunnels").into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "unknown tunnel".to_string()).into_response(),
        Err(e) => internal_error("set_allow_any_login", e).into_response(),
    }
}

async fn set_require_login_route(
    State(st): State<LoginGateState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<LoginPolicyForm>,
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
            // "side effect, logged not surfaced" convention above. The one-time
            // temporary password is only ever logged server-side -- the operator
            // relays it to the invitee out of band.
            //
            // The account is created UNVERIFIED (`emailVerified: false` in
            // `keycloak_admin`), which since 2026-08-16 is load-bearing rather than
            // incidental: the realm carries `verifyEmail=true` over a working SMTP
            // sender, so the invitee proves ownership of the address by confirming
            // Keycloak's mail before the account is usable -- and #527's gate
            // (`CT_GATE_REQUIRE_VERIFIED_EMAIL`) refuses the allow-list match until
            // they have. An earlier version of this comment claimed the realm had
            // "no outbound-email mechanism"; that stopped being true once SMTP was
            // configured, and the claim outlived its truth for a while.
            if let Some(kc) = &st.kc_admin {
                let client = keycloak_admin_http_client();
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
    let Some(claims) = crate::portal::session_claims_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    Html(topologies_html(claims.email.as_deref())).into_response()
}

/// A static shell: `#list` and the "New topology" button are filled/wired entirely by the
/// inline script below via `fetch()` against `/me/topologies*` -- no server-side topology
/// read here, matching [`TopologyPortalState`]'s doc comment.
fn topologies_html(email: Option<&str>) -> String {
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
    page("your topologies", body, email)
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
            None,
        ))
        .into_response();
    };
    let entries = match st.channels.channels_for_email(&email) {
        Ok(v) => v,
        Err(e) => return internal_error("channels_page/channels_for_email", e).into_response(),
    };
    Html(channels_html(&entries, Some(&email))).into_response()
}

/// Render the "Your Channels" list: each row is a channel id (the only stable,
/// non-secret identifier a channel has in this schema -- there's no separate
/// human name) plus a status badge, and a Claim link for anything pending.
fn channels_html(entries: &[(ct_common::channel::ChannelId, Option<u64>)], email: Option<&str>) -> String {
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
    page("your channels", &body, email)
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
/// `GET /portal/channels/:channel/grant` (#514): a member re-fetches the signed
/// grant its channel owner deposited (`POST /me/channels/:channel/grants/:holder`)
/// -- any number of times, from any later session of the same account. This is the
/// persistent replacement for demo-side one-shot delivery (the sort#26 class:
/// a redeploy between approval and pickup used to strand the grant forever).
/// Resolution is session-subject -> the holders THIS account claimed on the
/// channel (recorded at claim time) -> their deposited grants; holders whose
/// grant has not been deposited yet are listed with `grant: null` so a caller
/// can render "waiting for your grant" instead of a bare 404.
async fn fetch_deposited_grant(
    State(st): State<ClaimState>,
    headers: HeaderMap,
    Path(channel_hex): Path<String>,
) -> Response {
    let Some(claims) = crate::portal::session_claims_for(&st.session_key, &headers) else {
        return (StatusCode::UNAUTHORIZED, "log in to the portal first").into_response();
    };
    let Some(channel) = crate::service::hex_decode_32(&channel_hex) else {
        return (StatusCode::BAD_REQUEST, "malformed channel").into_response();
    };
    let rows = match st
        .channels
        .deposited_grants_for_subject(&ct_common::channel::ChannelId(channel), &claims.subject)
    {
        Ok(rows) => rows,
        Err(e) => return internal_error("fetch_deposited_grant/list", e).into_response(),
    };
    if rows.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            "no claimed identity on this channel for your account -- claim membership first",
        )
            .into_response();
    }
    let items: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(holder, grant)| {
            serde_json::json!({
                "holder": holder.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                "grant": grant,
            })
        })
        .collect();
    axum::Json(serde_json::json!({ "channel": channel_hex, "identities": items })).into_response()
}

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
        .claim_via_allowlist(&ct_common::channel::ChannelId(channel), &email, &holder, &noise_pubkey, &noise_attestation, now, Some(&claims.subject))
        .map_err(|e| internal_error("do_claim/claim_via_allowlist", e))?;
    // #577: two refusals, two answers. Reporting the second one as "not allow-listed" would
    // send a member who IS allow-listed off to ask for an invitation they already have.
    match claimed {
        crate::storage::ClaimOutcome::Claimed => Ok(()),
        crate::storage::ClaimOutcome::NotAllowlisted => Err((
            StatusCode::FORBIDDEN,
            "this email is not allow-listed for this channel".to_string(),
        )),
        crate::storage::ClaimOutcome::HolderClaimedByAnother => Err((
            StatusCode::CONFLICT,
            "this holder identity was already claimed by a different account — claim your \
             own holder key, or ask the channel owner to remove the stale membership"
                .to_string(),
        )),
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
/// #521: where an unauthenticated visitor to a claim URL is sent, so the login round-trip
/// brings them back to the page they actually wanted instead of the portal root.
///
/// Only a **valid** channel id rides into the target. This value lands in a `Location`
/// header and then in `?next=`, so it must not be able to carry anything else: 32-byte hex
/// is URL-safe by construction, and anything that fails to decode drops to the plain shell
/// rather than being reflected. `sanitized_next` rejects non-portal targets independently on
/// the receiving side — this is the near half of that pair, not a substitute for it.
///
/// Shared by the GET page and the POST submit. The GET is the deep link the issue was filed
/// about; the POST is the same friction reached from the other direction, when a session
/// expires while the participant is filling in the form.
fn claim_login_target(channel_hex: &str) -> String {
    match crate::service::hex_decode_32(channel_hex) {
        Some(_) => format!("/portal?next=/portal/channels/{}/claim", channel_hex.to_ascii_lowercase()),
        None => "/portal".to_string(),
    }
}

async fn claim_page(State(st): State<ClaimState>, headers: HeaderMap, Path(channel_hex): Path<String>) -> Response {
    let Some(claims) = crate::portal::session_claims_for(&st.session_key, &headers) else {
        return Redirect::to(&claim_login_target(&channel_hex)).into_response();
    };
    // #514: a RETURNING member sees its claimed identities and any deposited grant
    // right on this page -- re-fetchable delivery, the point of the deposit flow.
    let mut existing_block = String::new();
    // #523: the holders THIS account already claimed on this channel. The claim
    // script compares the browser's current identity against these -- a fresh
    // browser (new localStorage identity) shown a grant deposited for a DIFFERENT,
    // earlier holder must NOT be allowed to pair its new private key with that
    // grant (it can't authenticate, and fails silently much later at pairing).
    let mut claimed_holders: Vec<String> = Vec::new();
    if let Some(channel) = crate::service::hex_decode_32(&channel_hex) {
        if let Ok(rows) = st
            .channels
            .deposited_grants_for_subject(&ct_common::channel::ChannelId(channel), &claims.subject)
        {
            if !rows.is_empty() {
                let dep = channel_deployment(&st.portal_base, &st.edge_cert_path).await;
                existing_block.push_str("<h2>Your identities on this channel</h2>");
                for (holder, grant) in &rows {
                    let holder_hex: String = holder.iter().map(|b| format!("{b:02x}")).collect();
                    claimed_holders.push(holder_hex.clone());
                    match grant {
                        Some(g) => existing_block.push_str(&channel_onboarding_html(&channel_hex, &holder_hex, &dep, Some(g))),
                        None => existing_block.push_str(&format!(
                            r#"<p class="help">Holder <code>{}…</code>: claimed -- waiting for your channel
 owner to deposit the grant; reload this page once they have (no need to claim again).</p>"#,
                            escape(&holder_hex[..16])
                        )),
                    }
                }
            }
        }
    }
    // #523: hand the claim script the claimed-holder list (public hex only, no
    // secret) so it can detect the fresh-browser mismatch client-side -- the
    // browser is the only place that knows which private holder it currently holds.
    if !claimed_holders.is_empty() {
        let json: Vec<String> = claimed_holders.iter().map(|h| format!("\"{h}\"")).collect();
        existing_block.push_str(&format!(
            r#"<script id="claimed-holders" type="application/json">[{}]</script>"#,
            json.join(",")
        ));
    }
    Html(claim_html(&channel_hex, None, claims.email.as_deref(), None, None, None, &existing_block)).into_response()
}

async fn claim_page_submit(
    State(st): State<ClaimState>,
    headers: HeaderMap,
    Path(channel_hex): Path<String>,
    Form(req): Form<ClaimReq>,
) -> Response {
    let Some(claims) = crate::portal::session_claims_for(&st.session_key, &headers) else {
        // #521: the GET path already carried the deep link through login; a session that
        // expires mid-form used to drop the participant on the portal root, which is the
        // same friction reached from the other side.
        return Redirect::to(&claim_login_target(&channel_hex)).into_response();
    };
    match do_claim(&st, &headers, &channel_hex, &req).await {
        // Live onboarding material only ever computed on the SUCCESS path -- an
        // extra disk read for every failed/retried attempt would be wasted work,
        // and `req.holder` is only proven-valid hex once `do_claim` has actually
        // accepted it (malformed input already errored out above).
        Ok(()) => {
            let deployment = channel_deployment(&st.portal_base, &st.edge_cert_path).await;
            // #514: a re-claim of an already-granted holder ships the deposited grant
            // immediately (a fresh first claim almost never has one yet -- the page
            // then shows the reload-to-pick-it-up hint instead).
            let deposited = crate::service::hex_decode_32(&channel_hex)
                .and_then(|ch| {
                    st.channels
                        .deposited_grants_for_subject(&ct_common::channel::ChannelId(ch), &claims.subject)
                        .ok()
                })
                .and_then(|rows| {
                    rows.into_iter()
                        .find(|(h, _)| h.iter().map(|b| format!("{b:02x}")).collect::<String>() == req.holder.to_ascii_lowercase())
                        .and_then(|(_, g)| g)
                });
            Html(claim_html(
                &channel_hex,
                Some(Ok(())),
                claims.email.as_deref(),
                Some(&req.holder),
                Some(&deployment),
                deposited.as_deref(),
                "",
            ))
            .into_response()
        }
        Err((_, msg)) => Html(claim_html(&channel_hex, Some(Err(msg)), claims.email.as_deref(), None, None, None, "")).into_response(),
    }
}

/// A deployment's Agent-Fabric channel connection info -- the SAME broker/relay/
/// front-door values for every member of a given channel (never secret, unlike a
/// member's own keys or an owner-issued grant). Computed fresh per request from
/// [`crate::service::NetworkInfoResp::from_env`] + the portal's own base URL/edge
/// CA cert file -- the exact same sources [`install_page`]'s `edge_host_port`/
/// `CT_AGENT_EDGE_CERT_URL` already use for the Mesh-Plane tunnel path, so this
/// can never drift from the real deployment either.
struct ChannelDeployment {
    broker: String,
    relay: String,
    front_door: Option<FrontDoor>,
}

/// The `:443` TLS-TCP fallback (#106, `ct-edge-channel` ALPN) for a network that
/// blocks the direct broker/relay ports (`4435`/`4436`) -- the exact fix the live
/// support case behind this feature needed. `cert_hex` is the edge CA root DER,
/// hex-encoded: the SAME bytes `GET /pki/ca` publishes, not a value that goes
/// stale on the edge's next Let's-Encrypt leaf rotation (the front-door acceptor's
/// leaf and the shared edge leaf are issued by the same `Ca`, so a client that
/// trusts the CA root trusts either -- see `pki::build_channel_front_door_acceptor`'s
/// doc comment on the edge side). Present only once the edge has actually
/// published that root (checked live, not assumed) -- absent on a deployment that
/// hasn't started an edge yet, matching [`install_page`]'s own "absent -> omitted"
/// convention (e.g. its `hostname_line`).
struct FrontDoor {
    addr: String,
    cert_hex: String,
}

/// Read live, once per request: cheap (a small file, an infrequent page render --
/// nothing like the broker/relay's own per-connection admission path, which is why
/// `GET /pki/ca` bothers caching), and freshness matters more than the save here.
async fn channel_deployment(portal_base: &str, edge_cert_path: &str) -> ChannelDeployment {
    let info = crate::service::NetworkInfoResp::from_env();
    let host = portal_host(portal_base);
    let front_door = match tokio::fs::read(edge_cert_path).await {
        Ok(der) if !der.is_empty() => Some(FrontDoor {
            addr: format!("{host}:{}", info.channel_relay_gate_port),
            cert_hex: hex(&der),
        }),
        _ => None,
    };
    ChannelDeployment {
        broker: format!("{host}:{}", info.channel_broker_port),
        relay: format!("{host}:{}", info.channel_relay_port),
        front_door,
    }
}

/// Post-claim onboarding (live support case: a Windows client's network blocked
/// the channel broker/relay ports outright, ports 4435/4436, requiring the
/// operator to hand-assemble the `:443` fallback env by hand -- this closes that
/// gap the same way [`install_page`] already closes it for tunnels). Renders the
/// `.env` + the same bash/PowerShell "Run it" tab toggle [`install_page`] uses
/// (identical CSS classes / `showTab`/`copyCode` JS, both from [`page`]).
///
/// SECURITY BOUNDARY -- read before touching this function: `CT_CHANNEL_HOLDER_KEY`
/// / `CT_CHANNEL_NOISE_KEY` are the member's own PRIVATE keys. This server has
/// NEVER seen either (the claim form only ever submitted the public holder key +
/// a signature, #101 SEC101b) and must not try to -- they stay clearly-labeled
/// placeholders the member fills in from their own local
/// `ct-agent channel member-material` run. `CT_CHANNEL_GRANT` is the same kind of
/// boundary for a DIFFERENT key: it is signed by the channel OPERATOR's PRIVATE
/// key, which this control plane has also never held (only the operator's PUBLIC
/// key -- `SqliteChannelStore::register_channel`'s doc: "Never stores a channel
/// signing key"). By the grant design's own invariant #6
/// (`OperatorIdentity::compile_overlay_grants`'s doc: "the operator mints every
/// grant locally with its own key -- no central round-trip"), no server -- this
/// one included -- can ever synthesize a `CT_CHANNEL_GRANT`. What this function
/// DOES add over the bare allow-list claim that existed before it: the exact
/// command the channel's owner needs to run (`ct-agent channel grant`),
/// pre-filled with the now-known channel id and this member's just-submitted
/// holder key, so the owner only has to paste one value back instead of
/// hand-assembling a whole onboarding bundle from scratch.
fn channel_onboarding_html(
    channel_hex: &str,
    holder_hex: &str,
    dep: &ChannelDeployment,
    deposited_grant: Option<&str>,
) -> String {
    let channel_hex = escape(channel_hex);
    let holder_hex = escape(holder_hex);
    let (front_door_env, front_door_note) = match &dep.front_door {
        Some(fd) => (
            format!("\nCT_CHANNEL_FRONT_DOOR={}\nCT_CHANNEL_FRONT_DOOR_CERT={}", fd.addr, fd.cert_hex),
            r#"<p class="help">Includes the <code>:443</code> fallback (#106) for networks that block the
 direct broker/relay ports (<code>4435</code>/<code>4436</code>) outright -- <code>ct-agent</code> tries
 the direct ports first, then this. The cert is this deployment's real, live edge CA root (the same one
 <code>GET /pki/ca</code> publishes), not a value that goes stale when the edge's certificate rotates.</p>"#,
        ),
        None => (
            String::new(),
            r#"<p class="help">This deployment hasn't published its edge CA root yet, so the <code>:443</code>
 fallback for a restrictive network isn't available here -- only the direct broker/relay ports below.</p>"#,
        ),
    };
    // #514: when the channel owner has already DEPOSITED this member's signed grant
    // (POST /me/channels/:channel/grants/:holder), the env block ships it filled in --
    // re-fetchable from this page any time, which is the whole point of the deposit
    // flow (the sort#26 class: one-shot delivery stranding a grant forever). Without
    // a deposit the placeholder stays, plus the "reload later" hint below.
    let grant_line = match deposited_grant {
        Some(g) => format!(
            "CT_CHANNEL_GRANT={}   # deposited by your channel owner -- re-fetch it from this page anytime",
            escape(g)
        ),
        None => "CT_CHANNEL_GRANT=PASTE_YOUR_CT_CHANNEL_GRANT_HERE   # your channel owner signs this, see \"Get your grant\" below -- this server never holds the operator key and cannot issue it".to_string(),
    };
    // #517-follow / tester finding (15.08.): once the owner has DEPOSITED the grant,
    // the participant's role is no longer a "ask your owner" placeholder -- the grant
    // wire-encoding carries the direction byte (hex chars 256..258 of the 278-hex
    // grant: sig64‖channel32‖holder32‖DIR‖…). Prefill CT_CHANNEL_ROLE from it so the
    // arena's always-`accept` participant needs no out-of-band question. `Both` (3)
    // legitimately serves either side, so it keeps the choose-your-side placeholder.
    let role_line = deposited_grant
        .and_then(|g| g.get(256..258))
        .and_then(|dir| match dir {
            "01" => Some("CT_CHANNEL_ROLE=initiate   # from your deposited grant"),
            "02" => Some("CT_CHANNEL_ROLE=accept   # from your deposited grant"),
            _ => None, // Both (03) or unparseable: keep the explicit choice
        })
        .unwrap_or("CT_CHANNEL_ROLE=PASTE_INITIATE_OR_ACCEPT   # ask your channel owner which side you are");
    let env_block = format!(
        "CT_CHANNEL_BROKER={broker}\n\
         CT_CHANNEL_RELAY={relay}{front_door_env}\n\
         {role_line}\n\
         {grant_line}\n\
         CT_CHANNEL_HOLDER_KEY=PASTE_YOUR_PRIVATE_HOLDER_KEY_HERE   # from 'ct-agent channel member-material' -- never share this, never sent to or stored by this server\n\
         CT_CHANNEL_NOISE_KEY=PASTE_YOUR_PRIVATE_NOISE_KEY_HERE   # from 'ct-agent channel member-material' -- never share this, never sent to or stored by this server\n\
         CT_CHANNEL_RELAY_ONLY=1   # safe default behind a restrictive network; unset and set CT_CHANNEL_LISTEN=host:port instead if you can accept inbound connections",
        broker = dep.broker,
        relay = dep.relay,
    );
    let grant_cmd = format!(
        "CT_CHANNEL_OPERATOR_KEY=THEIR_OPERATOR_PRIVATE_KEY \\\n\
         CT_GRANT_CHANNEL={channel_hex} \\\n\
         CT_GRANT_MEMBER_HOLDER={holder_hex} \\\n\
         CT_GRANT_DIRECTION=PASTE_INITIATE_OR_ACCEPT \\\n\
         CT_GRANT_EXPIRES=UNIX_TIMESTAMP   # e.g. output of: date -d +90days +%s\n\
         ct-agent channel grant",
    );
    let run_cmd = "set -a; source .env; set +a\nct-agent channel";
    // #514: with a deposited grant the owner-side minting walkthrough is noise --
    // replace it with the re-fetch note; without one, keep the walkthrough and add
    // the deposit hint so the member knows a reload (not a re-claim) picks it up.
    let grant_section = match deposited_grant {
        Some(_) => r#"<p class="help"><code>CT_CHANNEL_GRANT</code> above was deposited by your channel
 owner and is filled in for real -- come back to this page (or <code>GET
 /portal/channels/&lt;channel&gt;/grant</code>) anytime to re-fetch it, e.g. after a grant rotation.
 The private keys were never here and stay yours alone.</p>"#
            .to_string(),
        None => format!(
            r#"<details open>
 <summary>Get your grant</summary>
 <p class="help"><code>CT_CHANNEL_GRANT</code> is signed by your channel owner's own OPERATOR private
 key, which this server has never held either (only the operator's PUBLIC key) -- the same
 never-store-a-private-key boundary as your own holder/Noise keys above. Send your channel owner your
 holder public key (<code>{holder_hex}</code>, already captured from your claim above) and ask them to
 run this locally, then paste back what it prints as your <code>CT_CHANNEL_GRANT</code>:</p>
 <div class="code-block">
  <div class="code-block-head"><span>owner runs this</span><button class="copy-btn" onclick="copyCode(this)" type="button">Copy</button></div>
  <pre><code>{grant_cmd}</code></pre>
 </div>
 <p class="help">Owners with an automated bridge instead DEPOSIT the grant here (<code>POST
 /me/channels/&lt;channel&gt;/grants/&lt;holder&gt;</code>) -- once that happened, simply RELOAD this
 page: the block above then ships your grant filled in. No need to claim again.</p>
</details>"#
        ),
    };
    let run_cmd_ps = "Get-Content .env | ForEach-Object {\n  if ($_ -match '^\\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {\n    $value = $matches[2] -replace '\\s+#.*$', ''\n    [System.Environment]::SetEnvironmentVariable($matches[1], $value.Trim(), 'Process')\n  }\n}\n.\\ct-agent.exe channel";
    format!(
        r#"<h2>Connect as this member</h2>
<p class="help">This deployment's broker/relay/front-door addresses are the same for every member (not
secret) and are filled in for real below. Save this now -- reopening this page later won't show it again.</p>
<div class="warn">Never share <code>CT_CHANNEL_HOLDER_KEY</code> or <code>CT_CHANNEL_NOISE_KEY</code> --
this server generated neither and cannot generate them; they came from your own local
<code>ct-agent channel member-material</code> run and were never sent here.</div>
<div class="code-block">
 <div class="code-block-head"><span>.env</span><button class="copy-btn" onclick="copyCode(this)" type="button">Copy</button></div>
 <pre><code>{env_block}</code></pre>
</div>
{front_door_note}
{grant_section}
<details>
 <summary>Run it</summary>
 <div class="tab-row">
  <button type="button" class="tab-btn active" onclick="showTab(this,'channel-run-bash')">bash</button>
  <button type="button" class="tab-btn" onclick="showTab(this,'channel-run-powershell')">PowerShell</button>
 </div>
 <div class="code-block" id="channel-run-bash" data-tab="bash">
  <div class="code-block-head"><span>bash</span><button class="copy-btn" onclick="copyCode(this)" type="button">Copy</button></div>
  <pre><code>{run_cmd}</code></pre>
 </div>
 <div class="code-block" id="channel-run-powershell" data-tab="powershell" style="display:none">
  <div class="code-block-head"><span>PowerShell</span><button class="copy-btn" onclick="copyCode(this)" type="button">Copy</button></div>
  <pre><code>{run_cmd_ps}</code></pre>
 </div>
 <p class="help">Fill in every placeholder above first. Get <code>ct-agent</code> the same way as a tunnel
 install (see your Install page's Docker build step) if you don't already have the binary.</p>
</details>"#
    )
}

/// The client-side identity-generation + attestation-signing script for [`claim_html`] --
/// brings the SAME in-browser WASM pattern `join.js` (CADS-DEMO-sort) and
/// `CADS-webconference-demo`'s own `join.js` already use, adapted to this page's plain
/// `<form method=post>`-reload style (every other portal form in this file works this way;
/// unlike those two demos' own fetch()+JSON SPA flow, there is no reason to introduce one
/// here) -- so a member no longer needs to run `ct-agent channel member-material` locally
/// just to get a holder/Noise keypair and a signature to paste in.
///
/// `__CHANNEL_HEX__` is substituted (not run through `format!`, to keep this template's own
/// `{`/`}` literal -- see [`claim_html`]) with the already hex-validated channel id; the
/// preimage this builds MUST stay byte-identical to
/// [`ct_common::channel::member_noise_attest_bytes`] (`crates/common/src/channel.rs`) /
/// [`ct_common::preimage::Preimage`] (`crates/common/src/preimage.rs`) -- see
/// `member_noise_attest_bytes_js_reimplementation_matches_the_server_side_byte_layout` in this
/// module's tests for the check that they actually agree.
const CLAIM_SCRIPT_TEMPLATE: &str = r#"<script type="module">
import init, * as wasm from "/portal/static/ct_agent_wasm.js";

const STORAGE_KEY = "ct-portal-channel-identity";
const CHANNEL_HEX = "__CHANNEL_HEX__";
const identityBox = document.getElementById("identity-box");
const noteEl = document.getElementById("claim-note");
const submitBtn = document.getElementById("claim-submit");
const fHolder = document.getElementById("f-holder");
const fNoisePub = document.getElementById("f-noise-pubkey");
const fAttest = document.getElementById("f-noise-attestation");

let wasmInitPromise = null;
function ensureWasmInit() {
  return wasmInitPromise || (wasmInitPromise = init({ module_or_path: "/portal/static/ct_agent_wasm_bg.wasm" }));
}

function loadOrCreateIdentity() {
  const existing = localStorage.getItem(STORAGE_KEY);
  if (existing) return JSON.parse(existing);
  const holder = wasm.generate_holder_identity();
  const noise = wasm.generate_noise_identity();
  const identity = {
    holderPub: holder.public_hex,
    holderPriv: holder.private_hex,
    noisePub: noise.public_hex,
    noisePriv: noise.private_hex,
    createdAt: Date.now(),
  };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(identity));
  return identity;
}

// member_noise_attest_bytes (crates/common/src/{channel.rs,preimage.rs}) -- domain-separated,
// length-prefixed: u32-LE(domain.len()) || domain || channel(32) || holder(32) ||
// noise_pubkey(32). Kept independent here (client-side JS has no access to the Rust crate)
// but must stay byte-identical -- see this file's own Rust test for the vector this was
// checked against.
function hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("hexToBytes: not a valid even-length hex string");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}
function memberNoiseAttestBytes(channelHex, holderHex, noisePubHex) {
  const domain = new TextEncoder().encode("ct-a2a-noise-attest-v1");
  const lenPrefix = new Uint8Array(4);
  new DataView(lenPrefix.buffer).setUint32(0, domain.length, true);
  return concatBytes(lenPrefix, domain, hexToBytes(channelHex), hexToBytes(holderHex), hexToBytes(noisePubHex));
}

function renderIdentity(identity) {
  identityBox.innerHTML =
    '<p class="k">Holder public key <span class="v"><code>' + identity.holderPub + "</code></span></p>" +
    '<div class="warn">Save your PRIVATE keys below now -- they never leave this browser and are never ' +
    "submitted anywhere; this page only ever sends your PUBLIC keys + a signature. You'll need them for " +
    "your own <code>ct-agent channel --serve</code> process once you're a member.</div>" +
    '<div class="code-block"><div class="code-block-head"><span>your private keys -- save now</span>' +
    '<button class="copy-btn" onclick="copyCode(this)" type="button">Copy</button></div>' +
    "<pre><code>CT_CHANNEL_HOLDER_KEY=" + identity.holderPriv + "\n" +
    "CT_CHANNEL_NOISE_KEY=" + identity.noisePriv + "\n" +
    "CT_CHANNEL_NOISE_PUBKEY=" + identity.noisePub + "</code></pre></div>" +
    '<button type="button" id="regen-identity" class="btn sec">Generate a different identity</button>';
  document.getElementById("regen-identity").addEventListener("click", () => {
    if (!confirm("This replaces the identity stored in this browser. Only do this before you've claimed with the old one.")) return;
    localStorage.removeItem(STORAGE_KEY);
    boot();
  });
}

function showNote(text, kind) {
  if (!noteEl) return;
  noteEl.textContent = text;
  noteEl.dataset.kind = kind || "";
}

// #523: a grant deposited for an EARLIER identity is useless with this browser's
// current private key, and pairing it fails silently much later. If the page shows
// deposited grants (claimed-holders) and NONE is this browser's holder, warn loudly:
// the private key that matches those grants lives only in another browser.
function checkIdentityMismatch(holderPub) {
  const el = document.getElementById("claimed-holders");
  const warn = document.getElementById("identity-mismatch");
  if (!el || !warn) return;
  let claimed = [];
  try { claimed = JSON.parse(el.textContent || "[]"); } catch (_) { return; }
  if (claimed.length === 0 || claimed.includes(holderPub)) { warn.style.display = "none"; return; }
  warn.innerHTML =
    "<strong>This browser holds a DIFFERENT identity than the grant(s) shown below.</strong> " +
    "This browser's holder is <code>" + holderPub.slice(0, 16) + "…</code>; the grant(s) above were " +
    "issued for another identity you claimed in a different browser. The matching private key lives ONLY " +
    "in that original browser and never left it — so those <code>.env</code> blocks will NOT " +
    "authenticate with this browser's key. Either open this page in the browser you first claimed from, " +
    "or claim again here and ask the channel owner to deposit a new grant for <code>" +
    holderPub.slice(0, 16) + "…</code>.";
  warn.style.display = "block";
}

async function boot() {
  submitBtn.disabled = true;
  identityBox.innerHTML = '<p class="help">generating your channel identity…</p>';
  showNote("", "");
  try {
    await ensureWasmInit();
    const identity = loadOrCreateIdentity();
    renderIdentity(identity);
    checkIdentityMismatch(identity.holderPub);
    const preimage = memberNoiseAttestBytes(CHANNEL_HEX, identity.holderPub, identity.noisePub);
    const signature = wasm.holderSign(identity.holderPriv, preimage);
    fHolder.value = identity.holderPub;
    fNoisePub.value = identity.noisePub;
    fAttest.value = bytesToHex(signature);
    submitBtn.disabled = false;
  } catch (e) {
    showNote("Could not generate your channel identity: " + e.message, "error");
  }
}

boot();
</script>"#;

/// The self-serve claim form (#248-follow, in-browser-WASM follow-up): a portal user's holder
/// + Noise keypair is generated ENTIRELY in this browser (via [`CLAIM_SCRIPT_TEMPLATE`],
/// loading the same `ct-agent-wasm` bundle [`serve_ct_agent_wasm_js`]/[`serve_ct_agent_wasm_bg`]
/// serve) and the claim runs from that -- no `ct-agent channel member-material` CLI step, no
/// manual out-of-band exchange with the channel owner. `claimed_holder_hex`/`deployment` are
/// `Some` only right after a successful claim (see [`channel_onboarding_html`]) -- `None`
/// otherwise (a fresh `GET`, or a failed attempt), in which case no onboarding block is shown.
///
/// `channel_hex` is validated (`ascii-hexdigit, len 64`, the same bar
/// [`crate::service::hex_decode_32`] enforces) BEFORE it is spliced into
/// [`CLAIM_SCRIPT_TEMPLATE`]'s `<script>` body -- unlike every other use of `channel_hex` in
/// this file (which only ever lands in an HTML-escaped attribute/text context via [`escape`]),
/// a value embedded straight into a `<script>` block is not made safe by HTML-escaping alone
/// (`&lt;` isn't valid hex either, so HTML-escaping the value would just break the script
/// without closing the injection). A malformed channel id (only reachable via a hand-crafted
/// URL; every real link into this page always carries a real channel hex) gets a plain error
/// card instead of the form, with no script emitted at all.
fn claim_html(
    channel_hex: &str,
    result: Option<Result<(), String>>,
    email: Option<&str>,
    claimed_holder_hex: Option<&str>,
    deployment: Option<&ChannelDeployment>,
    deposited_grant: Option<&str>,
    existing_block: &str,
) -> String {
    let banner = match &result {
        Some(Ok(())) => r#"<div class="warn" style="border-color:#238636;background:#0d2818;color:#3fb950">Claimed -- you're now a member of this channel.</div>"#.to_string(),
        Some(Err(msg)) => format!(r#"<div class="warn">Could not claim: {}</div>"#, escape(msg)),
        None => String::new(),
    };

    if crate::service::hex_decode_32(channel_hex).is_none() {
        let body = format!(
            r#"<h1>Join a channel</h1>
{banner}
<div class="warn">Malformed channel id.</div>
<a class="btn sec" href="/portal">Back to account</a>"#
        );
        return page("join channel", &body, email);
    }

    let onboarding = match (claimed_holder_hex, deployment) {
        (Some(holder_hex), Some(dep)) => channel_onboarding_html(channel_hex, holder_hex, dep, deposited_grant),
        _ => String::new(),
    };
    let script = CLAIM_SCRIPT_TEMPLATE.replace("__CHANNEL_HEX__", channel_hex);
    let body = format!(
        r#"<h1>Join a channel</h1>
<p class="k">Your signed-in e-mail must already be on this channel's allow-list (ask its owner to add
you with <code>ct-agent channel allowlist add &lt;your-email&gt;</code> if it isn't yet).</p>
{banner}
{existing_block}
<div id="identity-mismatch" class="warn" style="display:none"></div>
{onboarding}
<label>Channel<input type="text" value="{channel}" disabled></label>
<div id="identity-box" class="help">generating your channel identity…</div>
<form method="post" action="/portal/channels/{channel}/claim-form" id="claim-form">
 <input type="hidden" name="holder" id="f-holder">
 <input type="hidden" name="noise_pubkey" id="f-noise-pubkey">
 <input type="hidden" name="noise_attestation" id="f-noise-attestation">
 <button type="submit" id="claim-submit" disabled>Claim membership</button>
</form>
<span id="claim-note" class="help"></span>
<details>
 <summary>How does this work?</summary>
 <p class="help">Your holder and Noise keypairs are generated entirely IN THIS BROWSER (a real
 compiled copy of <code>ct-agent</code>'s own cryptography, run as WebAssembly) -- the private
 keys never leave this page and are never submitted anywhere; only your public keys and a
 signature over them are sent when you click "Claim membership". No local CLI install needed
 for this step.</p>
</details>
<a class="btn sec" href="/portal">Back to account</a>
{script}"#,
        channel = escape(channel_hex),
    );
    page("join channel", &body, email)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #521: both claim entry points send an unauthenticated visitor back to the page they
    /// wanted, and neither lets an unvalidated channel id into the `Location` header.
    #[test]
    fn claim_login_target_carries_only_a_valid_channel_id_521() {
        let good = "ab".repeat(32);
        assert_eq!(
            claim_login_target(&good),
            format!("/portal?next=/portal/channels/{good}/claim"),
            "a real channel id rides through, so the login round-trip returns here"
        );
        assert_eq!(
            claim_login_target(&good.to_ascii_uppercase()),
            format!("/portal?next=/portal/channels/{good}/claim"),
            "normalised to lowercase so the returned path matches the route"
        );

        // Anything that is not a 32-byte hex id falls back to the plain shell instead of
        // being reflected -- this value ends up in a Location header and then in `?next=`.
        let long = "ab".repeat(64);
        for bad in ["", "zz", "../../admin", "ab12/../../admin", "https://evil.example", &long] {
            assert_eq!(claim_login_target(bad), "/portal", "{bad:?} must not reach the target");
        }
        assert_eq!(
            claim_login_target("ab\r\nSet-Cookie: x=1"),
            "/portal",
            "a header-injection attempt must not survive into a Location header"
        );
    }
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

    // Screenshot bug report: the "Require login" checkbox rendered on its own
    // line above its label text instead of inline before it. The markup was
    // never wrong (input already precedes the text) -- the regression was a
    // too-broad `label input{{display:block;...}}` CSS rule (written for text
    // inputs like the "Create another tunnel" name field) that unintentionally
    // also matched the checkbox and forced it onto its own block-level line.
    #[test]
    fn require_login_checkbox_markup_has_input_before_its_label_text() {
        let html = login_gate_html("tun1", false, false, &[], &[]);
        let input_pos = html.find(r#"<input type="checkbox" name="enabled" value="1">"#).expect("checkbox present");
        let text_pos = html.find("Require login to access this tunnel").expect("label text present");
        assert!(input_pos < text_pos, "checkbox markup must precede its label text");
        // Both must live inside the SAME <label>...</label> for the browser to
        // treat them as one inline unit -- not just present somewhere on the
        // page: the nearest preceding "<label>" to the input, and the nearest
        // following "</label>" after the text, must bracket both.
        let label_open = html[..input_pos].rfind("<label>").expect("a <label> opens before the checkbox");
        let label_close = html[text_pos..].find("</label>").map(|p| p + text_pos).expect("a </label> closes after the text");
        assert!(label_open < input_pos && input_pos < label_close, "checkbox is inside the label");
        assert!(label_open < text_pos && text_pos < label_close, "label text is inside the label");
    }

    // Regression guard for the CSS fix itself: the block-level `label input`
    // rule must exclude checkbox/radio (so they stay inline with their label
    // text), and a dedicated inline rule must exist to size/space them
    // correctly -- while the original text-input behavior (full-width input
    // dropped below the label text, e.g. "Create another tunnel"'s name field)
    // must be unchanged for every OTHER input type.
    #[test]
    fn label_input_css_scopes_the_block_layout_rule_away_from_checkboxes() {
        let full_page = page("t", "", None);
        assert!(
            full_page.contains("label input:not([type=checkbox]):not([type=radio]){display:block"),
            "the full-width block-below-label-text rule must now exclude checkboxes/radios"
        );
        assert!(
            full_page.contains("label input[type=checkbox]") && full_page.contains("vertical-align:middle"),
            "a dedicated inline rule must keep the checkbox itself sized/spaced correctly"
        );
    }

    // Screenshot bug reports, two generations: (1) the whole tunnel card
    // scrolled internally (clipping rows/buttons) -- fixed by giving only
    // `.login-allowlist` its own scroll container; (2) the resting
    // `max-height:640px` cap that was kept as "load-bearing" for the removal
    // animation made tall cards (require-login + allowlist + pending requests
    // + Gelb notice, on a phone) BLEED over the neighbouring card, because the
    // resting card never clips. The cap is gone now: the `.leaving` collapse
    // measures its from-value in JS (scrollHeight, set inline, reflow forced)
    // right before the class is added.
    #[test]
    fn only_the_access_list_scrolls_internally_not_the_whole_tunnel_card() {
        let full_page = page("t", "", None);
        let rule_start = full_page.find(".tunnel-card{").expect(".tunnel-card rule present");
        let rule_body_start = rule_start + ".tunnel-card{".len();
        let rule_end = full_page[rule_body_start..].find('}').map(|p| p + rule_body_start).expect("rule closes");
        let tunnel_card_rule = &full_page[rule_start..rule_end];
        assert!(
            !tunnel_card_rule.contains("overflow-y:auto"),
            ".tunnel-card must not clip/scroll its own content: {tunnel_card_rule}"
        );
        assert!(
            !tunnel_card_rule.contains("max-height:"),
            "the resting card must carry NO max-height DECLARATION -- a fixed cap made tall \
             cards bleed over their neighbours (2026-08-14 phone screenshot). The word may \
             still appear in the transition property list (needed for the .leaving collapse): \
             {tunnel_card_rule}"
        );
        assert!(
            full_page.contains(".login-allowlist{max-height:220px;overflow-y:auto}"),
            "the access list itself keeps its own scroll container"
        );
        assert!(full_page.contains(".leaving{"), "the removal-animation class is unaffected");
        assert!(
            full_page.contains("target.style.maxHeight = target.scrollHeight + 'px'"),
            "the removal animation measures its collapse from-value in JS now"
        );
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

    // ===== ADR-0025 Decision 6: observability (traffic/tunnels) pure-logic tests =====
    //
    // `infer_transport`/`redact_token_for_display`/`tunnel_uptime_secs`/
    // `build_traffic_rows`/`build_tunnel_overview_rows` are pure joins/derivations
    // with no I/O, unlike the handlers around them -- these are the actual "genuine
    // logic" ADR-0025 calls out, so they get real unit tests here rather than only
    // being exercised indirectly through a live edge/DB in an integration test.

    #[test]
    fn infer_transport_reports_direct_p2p_only_when_a_direct_advertisement_is_active() {
        // ADR-0025 Decision 3: an availability signal, never a byte count -- exactly
        // two values, no third "unknown" state (see the fn's own doc comment).
        assert_eq!(infer_transport(true), "direct_p2p");
        assert_eq!(infer_transport(false), "relay");
    }

    #[test]
    fn redact_token_for_display_keeps_prefix_and_suffix_but_hides_the_middle() {
        let token = format!("a1b2c3d4e5f6{}", "0".repeat(52));
        assert_eq!(token.len(), 64, "sanity: a real routing token is 64 hex chars");
        let shown = redact_token_for_display(&token);
        assert_eq!(shown, "a1b2c3d4…0000");
        assert!(!shown.contains(&token), "the raw routing token must never appear in the display form");
        assert!(shown.len() < token.len(), "display form is materially shorter than the real token");
    }

    #[test]
    fn redact_token_for_display_leaves_a_short_value_alone() {
        // The fn's own documented escape hatch (`hex.len() <= 12`) -- exercised so a
        // short/malformed token can't silently start panicking on the `hex[..8]` slice.
        assert_eq!(redact_token_for_display("short"), "short");
        let twelve = "a".repeat(12);
        assert_eq!(redact_token_for_display(&twelve), twelve);
    }

    #[test]
    fn tunnel_uptime_secs_is_none_while_disconnected_even_if_connected_since_is_stale() {
        // A disconnected tunnel must never show an uptime, regardless of whatever
        // stale `connected_since` might still be lying around -- the whole reason
        // this takes `connected` as its own explicit parameter rather than inferring
        // it from `connected_since.is_some()`.
        assert_eq!(tunnel_uptime_secs(1_000, false, Some(500)), None);
        assert_eq!(tunnel_uptime_secs(1_000, false, None), None);
    }

    #[test]
    fn tunnel_uptime_secs_is_none_when_connected_but_the_edge_never_reported_a_streak_start() {
        assert_eq!(tunnel_uptime_secs(1_000, true, None), None);
    }

    #[test]
    fn tunnel_uptime_secs_is_now_minus_since_clamped_at_zero() {
        assert_eq!(tunnel_uptime_secs(1_500, true, Some(1_000)), Some(500));
        // Clock skew between this process and the edge's `connected_since` report
        // must never produce a negative uptime.
        assert_eq!(tunnel_uptime_secs(900, true, Some(1_000)), Some(0));
    }

    fn test_subject_tunnel(id: &str, routing_token: &str) -> SubjectTunnel {
        SubjectTunnel {
            id: id.to_string(),
            name: format!("{id}-name"),
            hostname: Some(format!("{id}.example.org")),
            created_at: 1_700_000_000,
            routing_token: routing_token.to_string(),
        }
    }

    #[test]
    fn build_traffic_rows_defaults_an_unreported_tunnel_to_disconnected_relay_zero_bytes() {
        // A tunnel the bulk edge scrape has no entry for at all (never connected
        // since the edge's own process start, or the scrape itself failed) must
        // still show up as a row -- degraded to the honest defaults, not dropped.
        let t = test_subject_tunnel("t1", &"a".repeat(64));
        let rows = build_traffic_rows(std::slice::from_ref(&t), &HashMap::new());
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].connected);
        assert_eq!(rows[0].transport, "relay");
        assert_eq!(rows[0].bytes_received, 0);
        assert_eq!(rows[0].bytes_sent, 0);
    }

    #[test]
    fn build_traffic_rows_reports_real_bytes_and_direct_transport_for_a_known_tunnel() {
        let token = "b".repeat(64);
        let t = test_subject_tunnel("t2", &token);
        let mut edge_status = HashMap::new();
        edge_status.insert(
            token.clone(),
            EdgeBulkStatusEntry {
                token: token.clone(),
                connected: true,
                bytes_received: 111,
                bytes_sent: 222,
                direct: true,
                ..Default::default()
            },
        );
        let rows = build_traffic_rows(std::slice::from_ref(&t), &edge_status);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].connected);
        assert_eq!(rows[0].transport, "direct_p2p");
        assert_eq!(rows[0].bytes_received, 111);
        assert_eq!(rows[0].bytes_sent, 222);
    }

    #[test]
    fn build_traffic_rows_never_puts_the_raw_routing_token_in_the_response() {
        // The whole reason `redact_token_for_display` exists -- prove the join
        // actually calls it rather than leaking `t.routing_token` verbatim.
        let token = "c".repeat(64);
        let t = test_subject_tunnel("t3", &token);
        let rows = build_traffic_rows(std::slice::from_ref(&t), &HashMap::new());
        assert_ne!(rows[0].routing_token_display, token);
        assert!(rows[0].routing_token_display.len() < token.len());
    }

    #[test]
    fn build_tunnel_overview_rows_joins_edge_id_and_reports_uptime_only_while_connected() {
        let token = "d".repeat(64);
        let t = test_subject_tunnel("t4", &token);
        let mut edge_status = HashMap::new();
        edge_status.insert(
            token.clone(),
            EdgeBulkStatusEntry {
                token: token.clone(),
                connected: true,
                registrations: 2,
                fallback_parked: 1,
                direct: false,
                connected_since: Some(1_000),
                last_seen: Some(1_450),
                ..Default::default()
            },
        );
        let mut edge_by_token = HashMap::new();
        edge_by_token.insert(token.clone(), "edge-eu-1".to_string());

        let rows = build_tunnel_overview_rows(1_500, std::slice::from_ref(&t), &edge_status, &edge_by_token);
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert!(row.connected);
        assert_eq!(row.registrations, 2);
        assert_eq!(row.fallback_parked, 1);
        assert_eq!(row.transport, "relay");
        assert_eq!(row.edge_id.as_deref(), Some("edge-eu-1"));
        assert_eq!(row.uptime_seconds, Some(500));
        assert_eq!(row.last_seen_unix, Some(1_450));
    }

    #[test]
    fn build_tunnel_overview_rows_reports_no_uptime_but_keeps_last_seen_for_a_disconnected_tunnel() {
        // The "last seen" column's entire reason to exist: it must survive a
        // disconnect even though uptime (correctly) does not.
        let token = "e".repeat(64);
        let t = test_subject_tunnel("t5", &token);
        let mut edge_status = HashMap::new();
        edge_status.insert(
            token.clone(),
            EdgeBulkStatusEntry {
                token: token.clone(),
                connected: false,
                connected_since: None,
                last_seen: Some(1_000),
                ..Default::default()
            },
        );
        let rows = build_tunnel_overview_rows(2_000, std::slice::from_ref(&t), &edge_status, &HashMap::new());
        assert!(!rows[0].connected);
        assert_eq!(rows[0].uptime_seconds, None);
        assert_eq!(rows[0].last_seen_unix, Some(1_000));
        assert_eq!(rows[0].edge_id, None, "no edge_mesh entry for this token -> None, not fabricated");
    }

    // ===== end ADR-0025 Decision 6 pure-logic tests =====

    fn session_header(subject: &str) -> String {
        format!("ct_portal_session={}", sign_session_for_test(KEY, subject))
    }

    /// #492: like [`session_header`], but the session also carries a verified
    /// email -- for asserting the signed-in email actually shows up on real
    /// portal pages.
    fn session_header_with_email(subject: &str, email: &str) -> String {
        format!(
            "ct_portal_session={}",
            crate::portal::sign_session_with_email_for_test(KEY, subject, email)
        )
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

    /// #492: no page in the portal showed which account (email) was currently
    /// signed in -- the nav never surfaced it. Fixed by threading the session's
    /// verified email (already carried in the signed session cookie, see
    /// `crate::portal::SessionClaims`) into the shared `page()` nav. Checked on
    /// `/portal/tunnels` (not just `/portal/account`) since the fix is meant to
    /// show on every real portal page, not just one.
    #[tokio::test]
    async fn tunnels_page_shows_the_signed_in_email_in_the_nav_492() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::get("/portal/tunnels")
                    .header("cookie", session_header_with_email("alice", "alice@example.com"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("alice@example.com"), "the signed-in email appears somewhere in the page: {html}");
        assert!(html.contains("Signed in as"), "labeled, not a bare unexplained address: {html}");
        // Lives in the nav, next to Sign out, on every page -- not buried in the body.
        let nav_start = html.find("<nav>").expect("page has a nav");
        let nav_end = html.find("</nav>").expect("nav closes");
        let nav = &html[nav_start..nav_end];
        assert!(nav.contains("alice@example.com"), "email is in the shared nav, not just the page body: {nav}");
    }

    /// #492 follow-up: a session with no resolvable/verified email (this
    /// deployment's OIDC not configured, or the IdP never asserted one) must
    /// degrade gracefully -- omit the line entirely, same as the connection-status
    /// badge's existing "absent renders nothing rather than a misleading state"
    /// rule -- never panic, error, or show a broken lookup inline.
    #[tokio::test]
    async fn account_page_degrades_cleanly_when_the_session_has_no_email_492() {
        let app = test_app();
        // session_header() (unlike session_header_with_email()) signs a session
        // with no email at all -- exactly the "OIDC not configured"/"IdP never
        // asserted an email" case.
        let (status, html) = get(&app, "/portal/account", Some("bob-no-email")).await;
        assert_eq!(status, StatusCode::OK, "must still render, not error: {html}");
        assert!(!html.contains("Signed in as"), "no email to show, so the line is omitted entirely: {html}");
        assert!(html.contains("bob-no-email"), "the page still renders its normal content");
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
        tunnels.create("kc-alice", "my-tunnel", None).unwrap().created().expect("hostname is free in this test");
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
        // #439 (part 2): the Revoke button/form must make its destructive,
        // irreversible-via-self-service nature explicit -- both for JS (the
        // page's `confirm-revoke` submit-time window.confirm) and as a plain
        // HTML fallback (the button's own `title`), so this holds regardless
        // of whether the page's own <script> ran.
        assert!(
            alice_html.contains("confirm-revoke"),
            "the tunnel Revoke form must opt into the destructive-action confirm dialog"
        );
        assert!(
            alice_html.contains("cannot be undone via self-service"),
            "the Revoke button must say plainly that this can't be undone via self-service today"
        );
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
        // docs, that their one tunnel is already set up and that Sharing exists
        // but is a paid-tier feature. The account is at its default limit (1
        // owned, max_tunnels=1) here, so "Create another" is expected
        // visible-but-disabled -- see
        // tunnels_page_at_limit_shows_a_disabled_create_form_with_real_quota_copy
        // for that form's own assertions, and
        // tunnels_page_under_limit_shows_a_real_enabled_create_form for the
        // enabled case (#439 follow-up).
        let app = test_app();
        let (status, html) = get(&app, "/portal/tunnels", Some("alice")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("automatically\nassigned hostname") || html.contains("automatically assigned hostname"),
            "explains the auto-assigned hostname");
        assert!(html.contains("disabled") && html.contains(">Share<"), "Share is shown but disabled");
        assert!(html.contains("paid tier") || html.contains("paid-tier"), "names Share's paid-tier gate");
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
    async fn tunnels_page_at_limit_shows_a_disabled_create_form_with_real_quota_copy() {
        // #439 follow-up (operator instruction): an account at its real
        // max_tunnels limit still sees a visually-disabled create form (not
        // hidden), but the copy must state the REAL quota reason -- not the
        // old hardcoded "planned paid tier, coming later" framing, since an
        // admin-raised max_tunnels can make that framing untrue for other
        // accounts. No unfounded payment/pricing promise either.
        let app = test_app();
        let (status, html) = get(&app, "/portal/tunnels", Some("alice")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("Create another tunnel"), "the second-tunnel section is visible, not hidden");
        assert!(
            html.contains(r#"<form aria-disabled="true">"#),
            "the create form itself is visually disabled at the limit: {html}"
        );
        assert!(
            html.contains("You've used all 1 tunnel included in your plan"),
            "states the REAL quota reason with the real numbers: {html}"
        );
        assert!(
            !html.contains("planned paid tier, coming later"),
            "no longer claims a fixed, unconditional paid-tier-not-built-yet story"
        );
    }

    #[tokio::test]
    async fn tunnels_page_under_limit_shows_a_real_enabled_create_form() {
        // #439 follow-up: once an account's max_tunnels is raised above its
        // owned count, the create form must become REAL -- a working
        // <form method="post" action="/portal/tunnels"> with a non-disabled
        // name input and submit button (matching CreateTunnelForm's
        // `{ name: String }` shape), not just less-disabled-looking markup.
        let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let secret = [0x99u8; 32];
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
            None,
            test_edge_mesh(),
            Some(secret),
        );

        // First view auto-provisions alice's one included tunnel (owned=1).
        assert_eq!(get(&app, "/portal/tunnels", Some("alice")).await.0, StatusCode::OK);

        // Raise alice's account limit to 2 -- now 1 owned < 2 max.
        let req = Request::post("/admin/accounts/alice/max-tunnels")
            .header("content-type", "application/json")
            .header("x-ct-admin-token", hex(&secret))
            .body(Body::from(r#"{"max":2}"#))
            .unwrap();
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

        let (status, html) = get(&app, "/portal/tunnels", Some("alice")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            html.contains(r#"<form method="post" action="/portal/tunnels">"#),
            "a real, working, non-disabled form posting to the real create_tunnel handler: {html}"
        );
        assert!(
            html.contains(r#"<input type="text" name="name""#) && !html.contains(r#"name="name" placeholder="e.g. my-api" disabled"#),
            "a real, non-disabled name input matching CreateTunnelForm's shape: {html}"
        );
        assert!(
            html.contains("You're using 1 of 2 tunnels included in your plan"),
            "accurate real-numbers copy: {html}"
        );
    }

    /// #439 follow-up, full end-to-end proof (not just at the handler level,
    /// which `admin_set_max_tunnels_unlocks_self_service_creation_for_one_specific_account`
    /// already covers): raising an account's quota makes GET /portal/tunnels
    /// render the real enabled form, and POSTing through that exact form shape
    /// (not a hand-crafted request bypassing the UI) really creates a second
    /// tunnel.
    #[tokio::test]
    async fn tunnels_page_enabled_create_form_actually_creates_a_second_tunnel_end_to_end() {
        let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let secret = [0xaau8; 32];
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
            None,
            None,
            test_edge_mesh(),
            Some(secret),
        );

        assert_eq!(get(&app, "/portal/tunnels", Some("remote")).await.0, StatusCode::OK);

        let req = Request::post("/admin/accounts/remote/max-tunnels")
            .header("content-type", "application/json")
            .header("x-ct-admin-token", hex(&secret))
            .body(Body::from(r#"{"max":2}"#))
            .unwrap();
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

        let (_, html) = get(&app, "/portal/tunnels", Some("remote")).await;
        assert!(
            html.contains(r#"<form method="post" action="/portal/tunnels">"#),
            "UI now discoverably offers a real create form"
        );

        // Post exactly what that form posts: name=<value> to /portal/tunnels.
        assert_eq!(
            post_form(&app, "/portal/tunnels", "remote", "name=second-tunnel").await,
            StatusCode::SEE_OTHER,
            "the discoverable form's own POST shape succeeds"
        );
        assert_eq!(tunnels.list_for_subject("remote").unwrap().len(), 2, "really owns 2 real tunnel rows");

        // At the (now-reached) limit again, the form goes back to disabled.
        let (_, html_after) = get(&app, "/portal/tunnels", Some("remote")).await;
        assert!(
            html_after.contains(r#"<form aria-disabled="true">"#),
            "back at the limit, the form is disabled again: {html_after}"
        );
    }

    /// #439 follow-up: confirms the Revoke scenario the operator specifically
    /// asked about end-to-end -- revoking a tunnel at the limit really frees a
    /// slot (owned_count is read live from the store on every GET, not
    /// cached), and self-service creation of a replacement then succeeds
    /// through the same discoverable form.
    #[tokio::test]
    async fn revoking_a_tunnel_at_the_limit_reenables_the_create_form_and_creation_succeeds() {
        // #439 follow-up: the specific Revoke scenario the operator asked
        // about -- revoking a tunnel at the limit really frees a slot
        // (owned_count is read live from the store on every GET, never
        // cached), and self-service creation of a replacement then succeeds
        // through the same discoverable, now-enabled form.
        let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let secret = [0x11u8; 32];
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
            None,
            None,
            test_edge_mesh(),
            Some(secret),
        );

        // Raise alice's limit to 2, then use up both slots.
        let req = Request::post("/admin/accounts/alice/max-tunnels")
            .header("content-type", "application/json")
            .header("x-ct-admin-token", hex(&secret))
            .body(Body::from(r#"{"max":2}"#))
            .unwrap();
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
        assert_eq!(get(&app, "/portal/tunnels", Some("alice")).await.0, StatusCode::OK); // auto-provision #1
        assert_eq!(post_form(&app, "/portal/tunnels", "alice", "name=second").await, StatusCode::SEE_OTHER); // #2, now at the limit

        let (_, at_limit_html) = get(&app, "/portal/tunnels", Some("alice")).await;
        assert!(at_limit_html.contains(r#"<form aria-disabled="true">"#), "at 2/2, the form is disabled");

        // Revoke ONE of the two -> owned_count drops from 2 to 1 -- the create
        // form must become enabled again on the very next GET, live, not stale.
        let revoke_id = first_id(&at_limit_html);
        assert_eq!(
            post_form(&app, &format!("/portal/tunnels/{revoke_id}/delete"), "alice", "").await,
            StatusCode::SEE_OTHER
        );
        let (_, after_revoke_html) = get(&app, "/portal/tunnels", Some("alice")).await;
        assert!(
            after_revoke_html.contains(r#"<form method="post" action="/portal/tunnels">"#),
            "revoke freed a slot -> the real create form is enabled again: {after_revoke_html}"
        );

        // And creation through that now-enabled form succeeds.
        assert_eq!(
            post_form(&app, "/portal/tunnels", "alice", "name=replacement").await,
            StatusCode::SEE_OTHER,
            "the freed slot really accepts a new tunnel"
        );
        assert_eq!(tunnels.list_for_subject("alice").unwrap().len(), 2, "back to 2 real owned tunnel rows");
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
        tunnels.create("alice", "site", Some(&hostname)).unwrap().created().expect("hostname is free in this test");

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
        let alice_id = tunnels.create("alice", "site", Some(&alice_hostname)).unwrap().created().expect("hostname is free in this test").id;

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
        let created = tunnels.create("alice", "web", None).unwrap().created().expect("hostname is free in this test");
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

    /// ADR-0025 "flag needs an enforcer" fail-first proof: a hostname an admin
    /// has disabled must never reach the edge's authorize-host call, even via
    /// the operator-only `admin_provision_tunnel` escape hatch -- the row
    /// still gets CREATED (disabling a hostname doesn't retroactively forbid
    /// naming it), but `authorize_hostname`'s edge push must be skipped.
    /// Without the `is_hostname_disabled` check in `authorize_hostname`, this
    /// test fails: the mock endpoint receives the call.
    #[tokio::test]
    async fn admin_provision_tunnel_never_authorizes_a_disabled_hostname_at_the_edge() {
        let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let secret = [0x77u8; 32];
        let host = "blocked.bunsenbrenner.org";

        let received = Arc::new(std::sync::Mutex::new(0u32));
        let mock = Router::new()
            .route(
                "/admin/authorize-host/:token/:host",
                post({
                    let received = received.clone();
                    move || {
                        let received = received.clone();
                        async move {
                            *received.lock().unwrap() += 1;
                            StatusCode::OK
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });

        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        tunnels.disable_hostname(host, "admin@example.com", 1000).unwrap();

        let mesh_store = Arc::new(crate::edge_mesh::SqliteEdgeMesh::open_in_memory().unwrap());
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
            EdgeMeshHandle::new(mesh_store, Arc::from("primary")),
            Some(secret),
        );

        let body = format!(r#"{{"subject":"someone","name":"blocked","hostname":"{host}"}}"#);
        let req = Request::post("/admin/provision-tunnel")
            .header("content-type", "application/json")
            .header("x-ct-admin-token", hex(&secret))
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "the tunnel ROW is still created");

        assert_eq!(
            tunnels.list_for_subject("someone").unwrap()[0].hostname.as_deref(),
            Some(host),
            "disabling a hostname doesn't forbid naming a new tunnel with it"
        );
        assert_eq!(
            *received.lock().unwrap(),
            0,
            "authorize-host must NEVER be called at the edge for a disabled hostname"
        );
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

    // ===== ADR-0025 `/admin-ui/*` tests =====

    const SUPER_ADMIN: &str = "super@example.com";

    /// One app merging BOTH the self-service portal API and the `/admin-ui/*`
    /// router over the SAME `ledger`/`tunnels` `Arc`s -- exactly how
    /// `service.rs`'s `persistent_control_plane_router` wires them together in
    /// production, which matters for the blocked-account test below (the block
    /// action and the tunnel-creation attempt must observe the same storage).
    fn test_admin_ui_app() -> (
        Router,
        Arc<SqliteLedger>,
        Arc<SqliteTunnelStore>,
        Arc<crate::admin_identity::AdminIdentity>,
    ) {
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let enrollment = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let bootstrap = Arc::new(SqliteBootstrap::open_in_memory().unwrap());
        let channels = Arc::new(crate::storage::SqliteChannelStore::open_in_memory().unwrap());
        let topologies = Arc::new(crate::storage::SqliteTopologyStore::open_in_memory().unwrap());
        let networks = Arc::new(crate::storage::SqliteNetworkStore::open_in_memory().unwrap());
        let pipelines = Arc::new(crate::storage::SqlitePipelineRegistry::open_in_memory().unwrap());
        let admin_store = Arc::new(crate::storage::SqliteAdminStore::open_in_memory().unwrap());
        let admin = Arc::new(crate::admin_identity::AdminIdentity::new(admin_store, SUPER_ADMIN));
        admin.ensure_super_admin_seeded().unwrap();
        let audit = Arc::new(crate::audit_log::SqliteAuditLog::open_in_memory().unwrap());

        let portal_app = portal_api_router(
            KEY,
            ledger.clone(),
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
        let admin_app = admin_ui_router(
            KEY,
            admin.clone(),
            audit,
            ledger.clone(),
            tunnels.clone(),
            channels,
            topologies,
            networks,
            pipelines,
            Arc::new(crate::storage::SqliteManagedDomains::open_in_memory().unwrap()),
            DomainAdminConfig::default(),
            ObservabilityConfig::default(),
        );
        (portal_app.merge(admin_app), ledger, tunnels, admin)
    }

    async fn admin_ui_req(app: &Router, method: &str, path: &str, cookie: &str, json_body: Option<&str>) -> StatusCode {
        let mut b = Request::builder().method(method).uri(path).header("cookie", cookie);
        let body = match json_body {
            Some(j) => {
                b = b.header("content-type", "application/json");
                Body::from(j.to_string())
            }
            None => Body::empty(),
        };
        app.clone().oneshot(b.body(body).unwrap()).await.unwrap().status()
    }

    /// Every `/admin-ui/*` route must refuse a session that is verified (a real
    /// `email_verified` IdP assertion, per `admin_session_from_headers`) but not
    /// in the `admins` table -- `403`, not merely "not 200".
    #[tokio::test]
    async fn every_admin_ui_route_refuses_a_verified_but_non_admin_session_403() {
        let (app, ledger, _tunnels, _admin) = test_admin_ui_app();
        ledger.account_for_subject("kc-target").unwrap();
        let non_admin = session_header_with_email("kc-someone", "not-an-admin@example.com");

        let cases: &[(&str, &str, Option<&str>)] = &[
            ("POST", "/admin-ui/accounts/kc-target/credit", Some(r#"{"amount":10}"#)),
            ("POST", "/admin-ui/accounts/kc-target/block", None),
            ("POST", "/admin-ui/accounts/kc-target/unblock", None),
            ("POST", "/admin-ui/accounts/kc-target/delete", None),
            ("POST", "/admin-ui/accounts/kc-target/max-tunnels", Some(r#"{"max":3}"#)),
            ("GET", "/admin-ui/admins", None),
            ("POST", "/admin-ui/admins", Some(r#"{"email":"new@example.com"}"#)),
            ("DELETE", "/admin-ui/admins/someone@example.com", None),
            // ADR-0025 Decision 4/6: hostname disable/enable + domain onboarding + certs.
            ("POST", "/admin-ui/hostnames/blocked.example/disable", None),
            ("POST", "/admin-ui/hostnames/blocked.example/enable", None),
            ("GET", "/admin-ui/hostnames/disabled", None),
            ("GET", "/admin-ui/domains", None),
            ("POST", "/admin-ui/domains", Some(r#"{"zone":"example.org"}"#)),
            ("POST", "/admin-ui/domains/example.org/hostnames", Some(r#"{"subdomain":"app"}"#)),
            ("GET", "/admin-ui/certs", None),
            // ADR-0025 Decision 6: read-only observability.
            ("GET", "/admin-ui/traffic", None),
            ("GET", "/admin-ui/tunnels", None),
            ("GET", "/admin-ui/health", None),
        ];
        for (method, path, body) in cases {
            let status = admin_ui_req(&app, method, path, &non_admin, *body).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path} must 403 a verified non-admin session");
        }
    }

    /// No session at all -> `401` (distinct from the 403-for-verified-non-admin
    /// case above), on a representative route -- `admin_session_from_headers`'s
    /// own `401`-vs-`403` contract is exhaustively unit-tested in
    /// `admin_identity.rs`; this just proves the ROUTING actually reaches that
    /// same check rather than, say, redirecting like the self-service `/portal/*`
    /// routes do.
    #[tokio::test]
    async fn admin_ui_route_with_no_session_at_all_is_401_not_a_redirect() {
        let (app, ..) = test_admin_ui_app();
        let resp = app
            .oneshot(Request::post("/admin-ui/accounts/kc-target/block").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Operator feedback (2026-08-26): host-system-info panel. `GET
    /// /admin-ui/system` must (a) gate like every other admin-identity route
    /// and (b) actually return real data from the host this test runs on --
    /// `host_info::collect`'s own unit tests already prove the /proc parsing
    /// in isolation; this proves the HTTP route wires it up correctly end to
    /// end (right status, right content type, a real positive CPU count).
    #[tokio::test]
    async fn admin_ui_system_requires_a_session_and_returns_real_host_data() {
        let (app, ..) = test_admin_ui_app();
        let resp = app
            .clone()
            .oneshot(Request::get("/admin-ui/system").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "no session at all must be 401, matching every other JSON admin route");

        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);
        let status = admin_ui_req(&app, "GET", "/admin-ui/system", &super_session, None).await;
        assert_eq!(status, StatusCode::OK);
        let resp = app
            .oneshot(Request::get("/admin-ui/system").header("cookie", &super_session).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let info: crate::host_info::HostInfo = serde_json::from_slice(&body).expect("must be valid HostInfo JSON");
        assert!(info.cpu_count >= 1, "must report a real positive CPU count: {info:?}");
    }

    /// `admin_ui_add_admin`/`admin_ui_remove_admin` require the SUPER-admin
    /// specifically -- a regular (non-super) admin is an admin (passes
    /// `admin_ui_authed`) but must still be refused here, with the target admin
    /// row provably untouched.
    #[tokio::test]
    async fn admin_management_routes_refuse_a_regular_non_super_admin() {
        let (app, _ledger, _tunnels, admin) = test_admin_ui_app();
        admin.add_admin(SUPER_ADMIN, "regular-admin@example.com").unwrap();
        let regular = session_header_with_email("kc-regular", "regular-admin@example.com");

        let status = admin_ui_req(&app, "POST", "/admin-ui/admins", &regular, Some(r#"{"email":"third@example.com"}"#)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(!admin.is_admin("third@example.com"), "the refused add must not have happened");

        let status = admin_ui_req(&app, "DELETE", "/admin-ui/admins/regular-admin@example.com", &regular, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(admin.is_admin("regular-admin@example.com"), "the refused remove must not have happened");
    }

    #[tokio::test]
    async fn super_admin_can_add_list_and_remove_a_regular_admin() {
        let (app, _ledger, _tunnels, admin) = test_admin_ui_app();
        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);

        let status = admin_ui_req(&app, "POST", "/admin-ui/admins", &super_session, Some(r#"{"email":"second@example.com"}"#)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(admin.is_admin("second@example.com"));

        let resp = app
            .clone()
            .oneshot(
                Request::get("/admin-ui/admins")
                    .header("cookie", &super_session)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json.as_array().unwrap().iter().any(|r| r["email"] == "second@example.com"),
            "listing includes the newly added admin: {json}"
        );

        let status = admin_ui_req(&app, "DELETE", "/admin-ui/admins/second@example.com", &super_session, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!admin.is_admin("second@example.com"));
    }

    #[tokio::test]
    async fn admin_ui_credit_route_credits_the_target_accounts_real_ledger_balance() {
        let (app, ledger, _tunnels, _admin) = test_admin_ui_app();
        let account = ledger.account_for_subject("kc-target").unwrap();
        assert_eq!(ledger.balance(&account).unwrap(), 0);

        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);
        let status = admin_ui_req(&app, "POST", "/admin-ui/accounts/kc-target/credit", &super_session, Some(r#"{"amount":500}"#)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ledger.balance(&account).unwrap(), 500, "the real durable ledger balance actually moved");
    }

    /// Operator feedback (2026-08-26): the Accounts page should show each
    /// subject's email (resolved live from Keycloak, see
    /// `ObservabilityConfig::keycloak_admin`'s doc) and be searchable by it.
    #[tokio::test]
    async fn admin_ui_accounts_page_shows_and_searches_by_email_when_keycloak_admin_is_configured() {
        use axum::extract::Path as AxPath;
        use axum::routing::{get, post};
        use axum::Json;

        async fn token() -> Json<serde_json::Value> {
            Json(serde_json::json!({ "access_token": "test-admin-token" }))
        }
        async fn user(AxPath(id): AxPath<String>) -> axum::response::Response {
            let email = match id.as_str() {
                "kc-alice" => Some("alice@example.com"),
                "kc-bob" => Some("bob@example.com"),
                _ => None,
            };
            match email {
                Some(e) => Json(serde_json::json!({ "id": id, "email": e })).into_response(),
                None => StatusCode::NOT_FOUND.into_response(),
            }
        }
        let kc_app = Router::new()
            .route("/realms/master/protocol/openid-connect/token", post(token))
            .route("/admin/realms/ct-demo/users/:id", get(user));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let kc_addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, kc_app).await.unwrap() });

        let admin_store = Arc::new(crate::storage::SqliteAdminStore::open_in_memory().unwrap());
        let admin = Arc::new(crate::admin_identity::AdminIdentity::new(admin_store, SUPER_ADMIN));
        admin.ensure_super_admin_seeded().unwrap();
        let audit = Arc::new(crate::audit_log::SqliteAuditLog::open_in_memory().unwrap());
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        ledger.account_for_subject("kc-alice").unwrap();
        ledger.account_for_subject("kc-bob").unwrap();
        let app = admin_ui_router(
            KEY,
            admin,
            audit,
            ledger,
            Arc::new(SqliteTunnelStore::open_in_memory().unwrap()),
            Arc::new(crate::storage::SqliteChannelStore::open_in_memory().unwrap()),
            Arc::new(crate::storage::SqliteTopologyStore::open_in_memory().unwrap()),
            Arc::new(crate::storage::SqliteNetworkStore::open_in_memory().unwrap()),
            Arc::new(crate::storage::SqlitePipelineRegistry::open_in_memory().unwrap()),
            Arc::new(crate::storage::SqliteManagedDomains::open_in_memory().unwrap()),
            DomainAdminConfig::default(),
            ObservabilityConfig {
                keycloak_admin: Some(crate::keycloak_admin::KeycloakAdminConfig {
                    base_url: format!("http://{kc_addr}"),
                    realm: "ct-demo".to_string(),
                    admin_user: "admin".to_string(),
                    admin_password: "pw".to_string(),
                }),
                ..Default::default()
            },
        );
        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);

        let resp = admin_ui_html_get(&app, "/admin-ui/accounts", Some(&super_session)).await;
        let html = String::from_utf8(to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap();
        assert!(html.contains("alice@example.com"), "resolved email must render: {html}");
        assert!(html.contains("bob@example.com"), "resolved email must render: {html}");

        let resp = admin_ui_html_get(&app, "/admin-ui/accounts?q=alice%40example.com", Some(&super_session)).await;
        let html = String::from_utf8(to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap();
        assert!(html.contains("kc-alice"), "searching by email must find the matching subject: {html}");
        assert!(!html.contains("kc-bob"), "searching by email must exclude a non-matching subject: {html}");
    }

    /// Fail-first proof (ADR-0025): before `create_tunnel`'s `is_blocked` check
    /// existed, this exact sequence (admin blocks the account, then that
    /// account's own session tries `/portal/tunnels`) returned `303 See Other`
    /// (self-service creation succeeded) instead of `403` -- the block flag was
    /// set in storage but nothing on the tunnel-creation path ever read it. This
    /// proves the check is real: the admin-console block action, the self-service
    /// tunnel-creation admission path, and the SAME underlying account row.
    #[tokio::test]
    async fn a_blocked_account_is_refused_when_it_tries_to_create_a_tunnel() {
        let (app, ledger, tunnels, _admin) = test_admin_ui_app();
        let account = ledger.account_for_subject("kc-blocked").unwrap();
        // Raise the limit so a refusal can only be the blocked check, never the
        // (also-real, separately tested) max-tunnels quota.
        ledger.set_max_tunnels(&account, 5).unwrap();

        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);
        let status = admin_ui_req(&app, "POST", "/admin-ui/accounts/kc-blocked/block", &super_session, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(ledger.is_blocked(&account).unwrap());

        assert_eq!(
            post_form(&app, "/portal/tunnels", "kc-blocked", "name=my-tunnel").await,
            StatusCode::FORBIDDEN,
            "a blocked account must be refused tunnel creation, not merely quota-limited"
        );
        assert!(tunnels.list_for_subject("kc-blocked").unwrap().is_empty(), "no tunnel was actually created");

        // Unblock: the same account can now create normally -- proves the check
        // is a live gate, not an accidental permanent lockout once blocked.
        let status = admin_ui_req(&app, "POST", "/admin-ui/accounts/kc-blocked/unblock", &super_session, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(post_form(&app, "/portal/tunnels", "kc-blocked", "name=my-tunnel").await, StatusCode::SEE_OTHER);
        assert_eq!(tunnels.list_for_subject("kc-blocked").unwrap().len(), 1);
    }

    #[tokio::test]
    async fn admin_ui_delete_account_cascades_and_removes_the_ledger_row_for_any_subject() {
        let (app, ledger, tunnels, _admin) = test_admin_ui_app();
        tunnels.create("kc-target", "t1", None).unwrap();
        let account = ledger.account_for_subject("kc-target").unwrap();
        ledger.credit(&account, 42).unwrap();

        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);
        let status = admin_ui_req(&app, "POST", "/admin-ui/accounts/kc-target/delete", &super_session, None).await;
        assert_eq!(status, StatusCode::OK);

        assert!(tunnels.list_for_subject("kc-target").unwrap().is_empty(), "owned tunnels revoked");
        // account_for_subject idempotently RE-CREATES a fresh (zero-balance)
        // account for an unseen subject -- so a freshly-minted, different id with
        // a zero balance proves the OLD funded row is really gone, not merely
        // left alone.
        let recreated = ledger.account_for_subject("kc-target").unwrap();
        assert_ne!(recreated.0, account.0, "a fresh account id was minted -- the old row is gone");
        assert_eq!(ledger.balance(&recreated).unwrap(), 0);
    }

    // ===== ADR-0025 Decision 4/6: hostname disable/enable + domains + certs =====

    /// Builds a standalone `/admin-ui/*` app (not via [`test_admin_ui_app`], which
    /// always uses an empty [`DomainAdminConfig`]) so each test below can inject
    /// its own edge-admin/deSEC mock + `managed_domains` store.
    fn domain_admin_ui_app(tunnels: Arc<SqliteTunnelStore>, managed_domains: Arc<crate::storage::SqliteManagedDomains>, domain_admin: DomainAdminConfig) -> Router {
        let admin_store = Arc::new(crate::storage::SqliteAdminStore::open_in_memory().unwrap());
        let admin = Arc::new(crate::admin_identity::AdminIdentity::new(admin_store, SUPER_ADMIN));
        admin.ensure_super_admin_seeded().unwrap();
        let audit = Arc::new(crate::audit_log::SqliteAuditLog::open_in_memory().unwrap());
        admin_ui_router(
            KEY,
            admin,
            audit,
            Arc::new(SqliteLedger::open_in_memory().unwrap()),
            tunnels,
            Arc::new(crate::storage::SqliteChannelStore::open_in_memory().unwrap()),
            Arc::new(crate::storage::SqliteTopologyStore::open_in_memory().unwrap()),
            Arc::new(crate::storage::SqliteNetworkStore::open_in_memory().unwrap()),
            Arc::new(crate::storage::SqlitePipelineRegistry::open_in_memory().unwrap()),
            managed_domains,
            domain_admin,
            ObservabilityConfig::default(),
        )
    }

    /// Fail-first proof of both halves of ADR-0025's hostname-disable contract:
    /// the CURRENTLY-live tunnel on that hostname gets revoked at the edge (the
    /// same `POST /admin/revoke/:token` primitive `delete_tunnel` uses), AND the
    /// hostname is marked disabled so a FUTURE `authorize_hostname` call would be
    /// refused (proven directly against `is_hostname_disabled`, since the
    /// enforcement itself is proven end-to-end by
    /// `admin_provision_tunnel_never_authorizes_a_disabled_hostname_at_the_edge`
    /// above). `enable` then reverses only the future-block half.
    #[tokio::test]
    async fn admin_ui_disable_hostname_revokes_the_live_tunnel_and_blocks_future_reauthorization() {
        use axum::extract::Path as AxPath;
        let host = "blocked.example.org";
        let received: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mock = Router::new().route(
            "/admin/revoke/:token",
            post({
                let received = received.clone();
                move |AxPath(token): AxPath<String>| {
                    let received = received.clone();
                    async move {
                        received.lock().unwrap().push(token);
                        StatusCode::OK
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });

        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let created = match tunnels.create("alice", "site", Some(host)).unwrap() {
            crate::storage::CreateTunnelOutcome::Created(t) => t,
            other => panic!("expected Created, got {other:?}"),
        };

        let app = domain_admin_ui_app(
            tunnels.clone(),
            Arc::new(crate::storage::SqliteManagedDomains::open_in_memory().unwrap()),
            DomainAdminConfig { edge_admin: Some((format!("http://{addr}"), "edge-secret".to_string())), ..Default::default() },
        );

        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);
        let status = admin_ui_req(&app, "POST", &format!("/admin-ui/hostnames/{host}/disable"), &super_session, None).await;
        assert_eq!(status, StatusCode::OK);

        assert_eq!(
            received.lock().unwrap().as_slice(),
            &[created.routing_token.clone()],
            "the tunnel currently on this hostname was revoked at the edge"
        );
        assert!(tunnels.is_hostname_disabled(host).unwrap());

        // enable reverses the future-block half.
        let status = admin_ui_req(&app, "POST", &format!("/admin-ui/hostnames/{host}/enable"), &super_session, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!tunnels.is_hostname_disabled(host).unwrap());
    }

    /// A hostname with no live tunnel still gets disabled (nothing to revoke,
    /// but the future-block half must still apply) -- and the response is still
    /// `200`, not an error, since "nothing to revoke" isn't a failure.
    #[tokio::test]
    async fn admin_ui_disable_hostname_with_no_live_tunnel_still_blocks_future_reauthorization() {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let app = domain_admin_ui_app(
            tunnels.clone(),
            Arc::new(crate::storage::SqliteManagedDomains::open_in_memory().unwrap()),
            DomainAdminConfig::default(), // no edge_admin configured at all
        );
        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);
        let status = admin_ui_req(&app, "POST", "/admin-ui/hostnames/never-existed.example/disable", &super_session, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(tunnels.is_hostname_disabled("never-existed.example").unwrap());
    }

    #[tokio::test]
    async fn admin_ui_register_domain_issues_apex_and_wildcard_a_records_then_persists_the_zone() {
        let captured: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mock = Router::new().route(
            "/domains/:domain/rrsets/",
            axum::routing::patch({
                let captured = captured.clone();
                move |body: String| {
                    let captured = captured.clone();
                    async move {
                        captured.lock().unwrap().push(body);
                        StatusCode::OK
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });

        let managed_domains = Arc::new(crate::storage::SqliteManagedDomains::open_in_memory().unwrap());
        let app = domain_admin_ui_app(
            Arc::new(SqliteTunnelStore::open_in_memory().unwrap()),
            managed_domains.clone(),
            DomainAdminConfig {
                desec_token: Some("t".to_string()),
                desec_api_base: Some(format!("http://{addr}")),
                dns_edge_ip: Some("9.9.9.9".to_string()),
                ..Default::default()
            },
        );
        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);

        let status = admin_ui_req(&app, "POST", "/admin-ui/domains", &super_session, Some(r#"{"zone":"example.org"}"#)).await;
        assert_eq!(status, StatusCode::OK);

        let bodies = captured.lock().unwrap().clone();
        assert_eq!(bodies.len(), 2, "apex + wildcard A records, both pushed: {bodies:?}");
        assert!(bodies.iter().any(|b| b.contains("\"subname\":\"\"") && b.contains("9.9.9.9")), "apex record present: {bodies:?}");
        assert!(bodies.iter().any(|b| b.contains("\"subname\":\"*\"") && b.contains("9.9.9.9")), "wildcard record present: {bodies:?}");

        let zone = managed_domains.zone("example.org").unwrap().expect("zone persisted");
        assert_eq!(zone.status, "active");
        assert_eq!(zone.added_by.as_deref(), Some(SUPER_ADMIN));

        // Re-registering an already-managed zone is a conflict, not a second DNS push.
        let status = admin_ui_req(&app, "POST", "/admin-ui/domains", &super_session, Some(r#"{"zone":"example.org"}"#)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(captured.lock().unwrap().len(), 2, "no new DNS calls for an already-managed zone");

        let listed = admin_ui_req(&app, "GET", "/admin-ui/domains", &super_session, None).await;
        assert_eq!(listed, StatusCode::OK);
    }

    /// Fail-first proof of "do not half-register a broken zone": when the apex
    /// A-record push fails (e.g. the zone isn't actually delegated to deSEC
    /// yet), the handler must report a clear error AND leave no `managed_domains`
    /// row behind -- a zone that "looks managed" with no real DNS is worse than
    /// having to retry.
    #[tokio::test]
    async fn admin_ui_register_domain_leaves_no_row_behind_when_the_apex_record_push_fails() {
        let mock = Router::new().route("/domains/:domain/rrsets/", axum::routing::patch(|| async { StatusCode::BAD_REQUEST }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });

        let managed_domains = Arc::new(crate::storage::SqliteManagedDomains::open_in_memory().unwrap());
        let app = domain_admin_ui_app(
            Arc::new(SqliteTunnelStore::open_in_memory().unwrap()),
            managed_domains.clone(),
            DomainAdminConfig {
                desec_token: Some("t".to_string()),
                desec_api_base: Some(format!("http://{addr}")),
                dns_edge_ip: Some("9.9.9.9".to_string()),
                ..Default::default()
            },
        );
        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);
        let status = admin_ui_req(&app, "POST", "/admin-ui/domains", &super_session, Some(r#"{"zone":"never-delegated.example"}"#)).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(
            managed_domains.zone("never-delegated.example").unwrap().is_none(),
            "a failed apex DNS push must not leave a managed_domains row behind"
        );
    }

    /// `POST /admin-ui/domains` without `DESEC_TOKEN`/`CT_CP_DNS_EDGE_IP`
    /// configured reports a clear `503`, not a confusing failure deep inside a
    /// DNS client construction -- and, same as the failure-path test above,
    /// leaves no row behind.
    #[tokio::test]
    async fn admin_ui_register_domain_503s_clearly_when_desec_is_not_configured() {
        let managed_domains = Arc::new(crate::storage::SqliteManagedDomains::open_in_memory().unwrap());
        let app = domain_admin_ui_app(
            Arc::new(SqliteTunnelStore::open_in_memory().unwrap()),
            managed_domains.clone(),
            DomainAdminConfig::default(),
        );
        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);
        let status = admin_ui_req(&app, "POST", "/admin-ui/domains", &super_session, Some(r#"{"zone":"example.org"}"#)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(managed_domains.zone("example.org").unwrap().is_none());
    }

    /// Operator feedback (2026-08-26): "why don't I see bunsenbrenner.org in
    /// Domains?" -- the platform's own root domain was never `POST
    /// /admin-ui/domains`-onboarded, so it never appeared in `managed_domains`.
    /// With `CT_CP_PLATFORM_ZONE` configured, the Domains page must show it in
    /// its own "Platform" row, distinct from the onboarded-zone table.
    #[tokio::test]
    async fn admin_ui_domains_page_shows_the_platform_zone_row_when_configured() {
        let app = domain_admin_ui_app(
            Arc::new(SqliteTunnelStore::open_in_memory().unwrap()),
            Arc::new(crate::storage::SqliteManagedDomains::open_in_memory().unwrap()),
            DomainAdminConfig { platform_zone: Some("bunsenbrenner.org".to_string()), ..Default::default() },
        );
        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);
        let resp = admin_ui_html_get(&app, "/admin-ui/domains", Some(&super_session)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("bunsenbrenner.org"), "platform zone must be rendered: {html}");
        assert!(html.contains("platform"), "platform zone must be labeled as such, not just listed: {html}");
    }

    /// Without `CT_CP_PLATFORM_ZONE` set (the pre-existing default), the Domains
    /// page must say so explicitly rather than silently rendering nothing where
    /// the platform row would go -- an operator staring at an empty section with
    /// no explanation is exactly the confusion this whole feature responds to.
    #[tokio::test]
    async fn admin_ui_domains_page_explains_the_platform_zone_gap_when_unconfigured() {
        let app = domain_admin_ui_app(
            Arc::new(SqliteTunnelStore::open_in_memory().unwrap()),
            Arc::new(crate::storage::SqliteManagedDomains::open_in_memory().unwrap()),
            DomainAdminConfig::default(),
        );
        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);
        let resp = admin_ui_html_get(&app, "/admin-ui/domains", Some(&super_session)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            html.contains("CT_CP_PLATFORM_ZONE"),
            "an unconfigured platform zone must be explained, not just absent: {html}"
        );
    }

    /// `POST /admin-ui/domains/:zone/hostnames` against a zone that was never
    /// registered via `POST /admin-ui/domains` must `404`, not silently try to
    /// issue a cert for it anyway.
    #[tokio::test]
    async fn admin_ui_add_domain_hostname_404s_for_an_unmanaged_zone() {
        let app = domain_admin_ui_app(
            Arc::new(SqliteTunnelStore::open_in_memory().unwrap()),
            Arc::new(crate::storage::SqliteManagedDomains::open_in_memory().unwrap()),
            DomainAdminConfig::default(),
        );
        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);
        let status = admin_ui_req(&app, "POST", "/admin-ui/domains/never-registered.example/hostnames", &super_session, Some(r#"{"subdomain":"app"}"#)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// Proves the full cert-issuance plumbing against a FAKE `issue_cert` (never
    /// touches real acme.sh/deSEC), and that a successful issuance is recorded in
    /// `managed_domains` so `GET /admin-ui/certs` can find it afterward.
    #[tokio::test]
    async fn admin_ui_add_domain_hostname_issues_a_cert_and_records_it_for_the_certs_dashboard() {
        let dir = std::env::temp_dir().join(format!("ct-cp-domainhostname-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("lib-acme.sh");
        std::fs::write(
            &script,
            r#"issue_cert() {
  local host="$1" dir="$2"
  mkdir -p "$dir"
  echo "cert" > "$dir/fullchain.pem"
  echo "key" > "$dir/privkey.pem"
}
"#,
        )
        .unwrap();

        let managed_domains = Arc::new(crate::storage::SqliteManagedDomains::open_in_memory().unwrap());
        managed_domains.add_zone("example.org", SUPER_ADMIN, 1000, "active").unwrap();
        let app = domain_admin_ui_app(
            Arc::new(SqliteTunnelStore::open_in_memory().unwrap()),
            managed_domains.clone(),
            DomainAdminConfig {
                managed_cert: Some(ManagedCertConfig {
                    acme: crate::cert_issuer::AcmeConfig {
                        lib_acme_path: script.to_string_lossy().into_owned(),
                        acme_home: dir.join("acme-home").to_string_lossy().into_owned(),
                        acme_email: "acme-test@example.com".to_string(),
                        desec_token: Some("t".to_string()),
                    },
                    cert_base_dir: dir.join("certs").to_string_lossy().into_owned(),
                }),
                ..Default::default()
            },
        );
        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);
        let status = admin_ui_req(&app, "POST", "/admin-ui/domains/example.org/hostnames", &super_session, Some(r#"{"subdomain":"app"}"#)).await;
        assert_eq!(status, StatusCode::OK);

        let rows = managed_domains.list_hostname_certs().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].hostname, "app.example.org");
        assert_eq!(rows[0].zone, "example.org");
        assert!(std::path::Path::new(&rows[0].cert_dir).join("fullchain.pem").is_file());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `GET /admin-ui/certs`: a front-door slot with no path configured reports
    /// `not_configured`; one pointed at a missing file reports `unreadable`
    /// (never silently omitted from the response, per ADR-0025's own
    /// requirement) -- proven together so the two states are visibly distinct.
    #[tokio::test]
    async fn admin_ui_certs_reports_not_configured_and_unreadable_as_distinct_explicit_states() {
        let app = domain_admin_ui_app(
            Arc::new(SqliteTunnelStore::open_in_memory().unwrap()),
            Arc::new(crate::storage::SqliteManagedDomains::open_in_memory().unwrap()),
            DomainAdminConfig {
                front_door_certs: FrontDoorCertPaths {
                    portal: None,
                    auth: Some("/does/not/exist/fullchain.pem".to_string()),
                    masque: None,
                    admin_ui: None,
                },
                ..Default::default()
            },
        );
        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);
        let req = Request::get("/admin-ui/certs")
            .header("cookie", &super_session)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let entries = parsed.as_array().unwrap();
        assert_eq!(entries.len(), 4, "all four fixed front-door slots always appear: {entries:?}");

        let portal = entries.iter().find(|e| e["label"] == "portal").unwrap();
        assert_eq!(portal["state"], "not_configured");

        let auth = entries.iter().find(|e| e["label"] == "auth").unwrap();
        assert_eq!(auth["state"], "unreadable");
        assert!(auth["reason"].as_str().unwrap().contains("read failed"));
    }

    // ===== ADR-0025 integration pass: `/admin-ui/*` HTML page tests =====

    async fn admin_ui_html_get(app: &Router, path: &str, cookie: Option<&str>) -> Response {
        let mut b = Request::builder().method("GET").uri(path).header("accept", "text/html,application/xhtml+xml");
        if let Some(c) = cookie {
            b = b.header("cookie", c);
        }
        app.clone().oneshot(b.body(Body::empty()).unwrap()).await.unwrap()
    }

    /// A logged-out visitor to any `/admin-ui/*` PAGE gets a clean redirect to the
    /// existing login entry point, never a bare `401` -- job #2's own requirement.
    /// Distinct from [`admin_ui_route_with_no_session_at_all_is_401_not_a_redirect`],
    /// which proves the JSON API surface keeps its own `401` contract; content
    /// negotiation ([`wants_html`]) is what tells the two cases apart.
    #[tokio::test]
    async fn admin_ui_page_with_no_session_redirects_to_portal_login() {
        let (app, ..) = test_admin_ui_app();
        let resp = admin_ui_html_get(&app, "/admin-ui/", None).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "axum's Redirect defaults to 303");
        let loc = resp.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(loc, "/portal/login", "the SAME login entry point every other Portal page uses");
    }

    /// A verified-but-not-an-admin session gets a real, rendered `403` page (a
    /// non-empty HTML body), never a bare status code -- job #2's other half.
    #[tokio::test]
    async fn admin_ui_page_for_a_non_admin_session_is_a_real_rendered_403() {
        let (app, ..) = test_admin_ui_app();
        let non_admin = session_header_with_email("kc-someone", "not-an-admin@example.com");
        let resp = admin_ui_html_get(&app, "/admin-ui/", Some(&non_admin)).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("<html"), "a real page, not an empty/bare 403: {html}");
        assert!(html.contains("access denied") || html.contains("Access denied"));
    }

    /// Every `/admin-ui/*` page renders `200` with real HTML for a verified admin
    /// session -- one broad smoke test across all seven pages, so a future change
    /// that silently breaks one page's render (a panic, a bad format! arg) is
    /// caught here rather than only in a screenshot review.
    #[tokio::test]
    async fn every_admin_ui_page_renders_ok_for_an_admin_session() {
        let (app, ledger, _tunnels, admin) = test_admin_ui_app();
        ledger.account_for_subject("kc-someone").unwrap();
        admin.add_admin(SUPER_ADMIN, "second@example.com").unwrap();
        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);
        for path in [
            "/admin-ui/",
            "/admin-ui/traffic",
            "/admin-ui/accounts",
            "/admin-ui/domains",
            "/admin-ui/admins",
            "/admin-ui/certs",
            "/admin-ui/audit",
        ] {
            let resp = admin_ui_html_get(&app, path, Some(&super_session)).await;
            assert_eq!(resp.status(), StatusCode::OK, "{path} must render OK for an admin session");
            let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            let html = String::from_utf8(body.to_vec()).unwrap();
            assert!(html.contains("<html"), "{path} must render a real page: {html}");
        }
    }

    /// Operator feedback (2026-08-26): every `/admin-ui/*` data table should be
    /// sortable by clicking a column header. The click-to-sort behavior itself
    /// lives in browser JS and isn't exercisable from a Rust test, but the hook
    /// every page's table relies on (`window.ctSortableInit`, wired from
    /// `admin_page`'s shared chrome) must ship on every page -- this is the
    /// regression guard that a future edit to the shared chrome doesn't silently
    /// drop it from one page while leaving it on the others.
    #[tokio::test]
    async fn every_admin_ui_page_ships_the_sortable_table_hook() {
        let (app, ledger, _tunnels, admin) = test_admin_ui_app();
        ledger.account_for_subject("kc-someone").unwrap();
        admin.add_admin(SUPER_ADMIN, "second@example.com").unwrap();
        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);
        for path in [
            "/admin-ui/",
            "/admin-ui/traffic",
            "/admin-ui/accounts",
            "/admin-ui/domains",
            "/admin-ui/admins",
            "/admin-ui/certs",
            "/admin-ui/audit",
        ] {
            let resp = admin_ui_html_get(&app, path, Some(&super_session)).await;
            let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            let html = String::from_utf8(body.to_vec()).unwrap();
            assert!(
                html.contains("function ctSortableInit") && html.contains("window.ctSortableInit = ctSortableInit"),
                "{path} must ship the sortable-table hook: {html}"
            );
        }
    }

    /// Without an explicit `Accept: text/html`, the four paths this pass shares
    /// with an earlier phase's already-tested JSON contract (`/admin-ui/traffic`,
    /// `/admin-ui/admins`, `/admin-ui/domains`, `/admin-ui/certs`) still answer
    /// JSON -- the content-negotiation branch this pass adds must never change
    /// their default behavior for an existing caller (a test, a script, another
    /// service) that doesn't ask for HTML.
    #[tokio::test]
    async fn shared_json_html_paths_still_default_to_json_without_an_html_accept_header() {
        let (app, ..) = test_admin_ui_app();
        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);
        for path in ["/admin-ui/traffic", "/admin-ui/admins", "/admin-ui/domains", "/admin-ui/certs"] {
            let resp = app
                .clone()
                .oneshot(Request::get(path).header("cookie", &super_session).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{path}");
            let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            let html = String::from_utf8_lossy(&body);
            assert!(!html.contains("<html"), "{path} must still default to JSON, not HTML: {html}");
            serde_json::from_slice::<serde_json::Value>(&body).unwrap_or_else(|e| panic!("{path} must still be valid JSON: {e}"));
        }
    }

    /// ADR-0025's own hard requirement, proven at the RENDER layer (not just the
    /// route-level 403 [`admin_management_routes_refuse_a_regular_non_super_admin`]
    /// already proves): a non-super-admin's admins page has NO remove control for
    /// ANY row (not even for a regular admin they could otherwise imagine removing)
    /// and no add-admin form -- the task's explicit "don't show a button that will
    /// just 403" bar, which only a fail-first proof against the rendered markup
    /// actually establishes.
    #[tokio::test]
    async fn admins_page_hides_every_remove_control_and_the_add_form_for_a_non_super_admin() {
        let (app, _ledger, _tunnels, admin) = test_admin_ui_app();
        admin.add_admin(SUPER_ADMIN, "regular@example.com").unwrap();
        let regular = session_header_with_email("kc-regular", "regular@example.com");
        let resp = admin_ui_html_get(&app, "/admin-ui/admins", Some(&regular)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(!html.contains("removeAdmin(event)"), "no row may carry a working remove control: {html}");
        assert!(!html.contains("id=\"addAdminForm\""), "the add-admin form must not render at all: {html}");
    }

    /// The super-admin's OWN row never carries a remove control, even when the
    /// viewer IS the super-admin and every other row does -- "no delete control
    /// rendered for that row at all", proven per-row, not merely "the page has a
    /// remove button somewhere".
    #[tokio::test]
    async fn admins_page_never_renders_a_remove_control_on_the_super_admins_own_row() {
        let (app, _ledger, _tunnels, admin) = test_admin_ui_app();
        admin.add_admin(SUPER_ADMIN, "regular@example.com").unwrap();
        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);
        let resp = admin_ui_html_get(&app, "/admin-ui/admins", Some(&super_session)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        // The regular admin's row DOES get a remove control...
        assert!(
            html.contains(&format!(r#"data-email="regular@example.com""#)),
            "the regular admin's row must carry a working remove control: {html}"
        );
        // ...but the super-admin's own row must not, even though this viewer IS
        // the super-admin and the add/remove form is otherwise shown.
        assert!(
            !html.contains(&format!(r#"data-email="{SUPER_ADMIN}""#)),
            "the super-admin's own row must never carry a remove control: {html}"
        );
        assert!(html.contains("cannot be removed"));
        assert!(html.contains("id=\"addAdminForm\""), "the super-admin DOES see the add form");
    }

    /// `GET /admin-ui/accounts` lists a real account (from the SAME durable
    /// ledger every other admin route reads) and its search box filters by
    /// subject substring server-side -- proving both the new `list_accounts`
    /// plumbing and the page's `?q=` filter actually work end-to-end, not just
    /// that the storage method returns rows in isolation.
    #[tokio::test]
    async fn accounts_page_lists_real_accounts_and_search_filters_by_subject() {
        let (app, ledger, _tunnels, _admin) = test_admin_ui_app();
        let alice = ledger.account_for_subject("kc-alice").unwrap();
        ledger.credit(&alice, 250).unwrap();
        ledger.account_for_subject("kc-bob").unwrap();
        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);

        let resp = admin_ui_html_get(&app, "/admin-ui/accounts", Some(&super_session)).await;
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("kc-alice") && html.contains("kc-bob"), "both accounts listed: {html}");
        assert!(html.contains("250"), "the real credited balance is shown: {html}");

        let filtered = admin_ui_html_get(&app, "/admin-ui/accounts?q=alice", Some(&super_session)).await;
        let body = to_bytes(filtered.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("kc-alice"), "matching subject still shown: {html}");
        assert!(!html.contains("kc-bob"), "non-matching subject filtered out: {html}");
    }

    /// `GET /admin-ui/logout` clears the session cookie -- the one thing an
    /// admin-console sign-out needs to do locally (see `admin_ui_page_authed`'s
    /// doc for why the underlying session's origin is otherwise still open).
    #[tokio::test]
    async fn admin_ui_logout_clears_the_session_cookie() {
        let (app, ..) = test_admin_ui_app();
        let super_session = session_header_with_email("kc-super", SUPER_ADMIN);
        let resp = app
            .clone()
            .oneshot(Request::get("/admin-ui/logout").header("cookie", &super_session).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let set_cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
        assert!(set_cookie.contains("ct_portal_session=;"), "clears the session cookie: {set_cookie}");
        assert!(set_cookie.contains("Max-Age=0"));
    }

    // ===== end ADR-0025 integration pass: `/admin-ui/*` HTML page tests =====

    // ===== end ADR-0025 `/admin-ui/*` tests =====

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
        // 2026-08-14 audit: the build step must produce a CURRENT released agent.
        // The old command cloned CADS-Tunnel and built its git-pinned `ct-agent`
        // dependency -- stuck at a v0.3.0-era rev, months behind the releases --
        // so every self-service install got a stale agent.
        // #512: asserted against the ONE pin source (repo-root CT_AGENT_RELEASE),
        // not a version prefix -- the old `git checkout v0.4` check would have
        // stayed green on a frozen pin until v0.5.
        let tag = ct_agent_release_tag();
        {
            // The source itself must be a plausible release tag: `v` + three
            // dot-separated numeric parts (a corrupted/empty file must fail HERE,
            // not ship a broken install command).
            let parts: Vec<&str> = tag.trim_start_matches('v').split('.').collect();
            assert!(
                tag.starts_with('v') && parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())),
                "CT_AGENT_RELEASE must hold a vX.Y.Z tag, got {tag:?}"
            );
        }
        assert!(
            html.contains("clone https://github.com/scimbe/ct-agent.git")
                && html.contains(&format!("git checkout {tag}"))
                && html.contains(&format!("releases/tag/{tag}")),
            "the install build clones the standalone agent repo at the pinned release tag"
        );
        // #512: the help-site example (the other user-facing install surface) must
        // default to the same source -- this is what keeps the pin scatter from
        // re-growing (seven pins with four different values caused the #502 class).
        assert!(
            include_str!("../../../examples/help-site/Agent.Dockerfile").contains(&format!("ARG CT_AGENT_REF={tag}")),
            "help-site Agent.Dockerfile default must match CT_AGENT_RELEASE ({tag})"
        );
        assert!(
            include_str!("../../../examples/help-site/compose.help-site.yml").contains(&format!("CT_AGENT_REF:-{tag}")),
            "help-site compose fallback must match CT_AGENT_RELEASE ({tag})"
        );
        // The two assertions above name two files. `every_ct_agent_pin_matches_the_release`
        // below covers the rest -- they are kept because they also pin the exact SHAPE of
        // each line, which the repo-wide scan deliberately does not.
        assert!(
            !html.contains("clone https://github.com/scimbe/CADS-Tunnel.git"),
            "must not build the workspace's stale git-pinned agent dependency"
        );
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
            html.contains("docker run") && html.contains("cargo build --release --locked -p ct-agent"),
            "gives a real, working build command (locked to the release tag's lockfile), not just a link"
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

        // Windows/PowerShell users previously had no working "Run it" equivalent
        // at all (bash-only `source .env` + a forward-slash, extension-less
        // binary path). Both the bash and PowerShell variants must now be
        // present -- as a tab toggle, not a second full page -- and the .env
        // block itself must stay a single, unduplicated source of truth.
        assert!(html.contains(">bash<") && html.contains(">PowerShell<"), "both a bash and PowerShell tab are present");
        assert!(
            html.contains("set -a; source .env; set +a") && html.contains("./target/release/ct-agent onboard"),
            "the original bash run command is unchanged"
        );
        assert!(
            html.contains(".\\target\\release\\ct-agent.exe onboard"),
            "the PowerShell run command uses the Windows binary extension and backslash path"
        );
        assert!(
            html.contains("SetEnvironmentVariable") && html.contains("Get-Content .env"),
            "the PowerShell step does the same real work as bash's `source .env` -- parses \
             the file and exports each var into the process, since ct-agent only reads live \
             process env vars (no dotenv support)"
        );
        assert!(!html.contains("irm "), "no non-functional PowerShell one-liner shown (#75 still applies)");
        assert!(
            html.contains(r#"onclick="showTab(this,'run-bash')""#) && html.contains(r#"onclick="showTab(this,'run-powershell')""#),
            "the tabs actually toggle via the shared showTab() inline script, same style as copyCode()"
        );
        // The .env block itself is OS-agnostic and must appear exactly once,
        // not duplicated in a PowerShell-specific rendering.
        assert_eq!(html.matches("CT_AGENT_JOIN_TOKEN=").count(), 1, ".env content is not duplicated for PowerShell");
    }

    /// #512 was written to stop the ct-agent pin from scattering again — "seven pins with
    /// four different values caused the #502 class". It checked three of them.
    ///
    /// The portal HTML, `examples/help-site/Agent.Dockerfile` and that example's compose
    /// file were named explicitly; `docker/Dockerfile`, `scripts/build-ct-agent-wasm.sh`,
    /// `scripts/e2e-video-call/run.sh` and the two `Cargo.toml` git pins were not. They agree
    /// today only because someone bumped them by hand. The next bump that touches the three
    /// covered surfaces would pass this crate's tests with three pins left behind — which is
    /// exactly the failure #512 exists to prevent, reproduced by the guard's own scope.
    ///
    /// So the file set is derived: walk the repository and check every pin-shaped occurrence.
    /// A pin added in a file nobody thought of is covered on the day it is written.
    #[test]
    fn every_ct_agent_pin_matches_the_release() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("crates/<name> sits two levels below the repo root")
            .to_path_buf();
        let tag = std::fs::read_to_string(root.join("CT_AGENT_RELEASE"))
            .expect("CT_AGENT_RELEASE is readable")
            .trim()
            .to_string();

        // Only pin-SHAPED occurrences. A bare `vX.Y.Z` anywhere would drag in prose like
        // ct-client's "#507: was a v0.3.0-era rev", which is history, not a pin.
        let pin_forms = |line: &str| -> Vec<String> {
            let mut found = Vec::new();
            for (needle, skip) in [("CT_AGENT_REF=", 13), ("CT_AGENT_REF:-", 14)] {
                let mut rest = line;
                while let Some(i) = rest.find(needle) {
                    let v: String = rest[i + skip..]
                        .chars()
                        .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == 'v')
                        .collect();
                    if v.starts_with('v') && v.contains('.') {
                        found.push(v);
                    }
                    rest = &rest[i + skip..];
                }
            }
            if line.contains("ct-agent") {
                if let Some(i) = line.find("tag = \"") {
                    let v: String = line[i + 7..].chars().take_while(|c| *c != '"').collect();
                    if v.starts_with('v') {
                        found.push(v);
                    }
                }
            }
            found
        };

        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            let skip = ["target", ".git", ".claude", "node_modules"];
            let Ok(entries) = std::fs::read_dir(dir) else { return };
            for e in entries.flatten() {
                let p = e.path();
                let name = p.file_name().unwrap_or_default().to_string_lossy().to_string();
                if p.is_dir() {
                    if !skip.contains(&name.as_str()) {
                        walk(&p, out);
                    }
                } else if matches!(
                    p.extension().and_then(|x| x.to_str()),
                    Some("toml") | Some("yml") | Some("yaml") | Some("sh")
                ) || name.starts_with("Dockerfile")
                    || name.ends_with(".Dockerfile")
                {
                    out.push(p);
                }
            }
        }
        let mut files = Vec::new();
        walk(&root, &mut files);

        let mut checked = 0usize;
        let mut wrong: Vec<String> = Vec::new();
        for f in &files {
            let Ok(src) = std::fs::read_to_string(f) else { continue };
            for (n, line) in src.lines().enumerate() {
                for v in pin_forms(line) {
                    checked += 1;
                    if v != tag {
                        wrong.push(format!("{}:{} pins {v}", f.strip_prefix(&root).unwrap_or(f).display(), n + 1));
                    }
                }
            }
        }
        // A walk that found nothing passes exactly like a walk that found everything in
        // order. The count is the difference between "checked and clean" and "never ran".
        assert!(
            checked >= 5,
            "expected at least the five known pin sites, found {checked} -- the scan is not \
             reaching the repository (root: {})",
            root.display()
        );
        assert!(
            wrong.is_empty(),
            "these ct-agent pins disagree with CT_AGENT_RELEASE ({tag}) -- bump them together \
             or the fleet runs mixed versions (#502/#512): {wrong:#?}"
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

    /// #514: after a self-service claim, the SAME account's session re-fetches the
    /// owner-deposited grant from `GET /portal/channels/:channel/grant` -- before the
    /// deposit the claimed identity is listed with `grant: null` ("waiting"), and an
    /// unauthenticated fetch is refused. The persistent replacement for demo-side
    /// one-shot grant delivery (the sort#26 class).
    #[tokio::test]
    async fn a_claimed_member_refetches_its_deposited_grant_514() {
        use crate::portal::sign_session_with_email_for_test;
        use crate::storage::{GrantDepositOutcome, SqliteChannelStore};
        use ct_common::channel::{member_noise_attest_bytes, ChannelId};
        use ed25519_dalek::{Signer, SigningKey};

        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let ch = ChannelId([0x6eu8; 32]);
        assert!(channels.register_channel(&ch, &[0x22u8; 32], "alice-owner").unwrap());
        assert!(channels.allowlist_add(&ch, "alice-owner", "nat@example.com", 1_000).unwrap());
        let app = channel_claim_router(KEY, channels.clone(), "https://portal.example", "/nonexistent/ct-edge-ca.der");

        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let holder_sk = SigningKey::from_bytes(&[0xc5u8; 32]);
        let holder_bytes = holder_sk.verifying_key().to_bytes();
        let noise = [0xd6u8; 32];
        let attest = holder_sk.sign(&member_noise_attest_bytes(&ch, &holder_bytes, &noise)).to_bytes();
        let ch_hex = hex(&ch.0);
        let cookie = format!("ct_portal_session={}", sign_session_with_email_for_test(KEY, "subj-nat", "nat@example.com"));

        // Unauthenticated fetch: refused.
        let resp = app
            .clone()
            .oneshot(Request::get(format!("/portal/channels/{ch_hex}/grant")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Claim with the session, then fetch: identity listed, grant still null.
        let claim_body = serde_json::json!({
            "holder": hex(&holder_bytes),
            "noise_pubkey": hex(&noise),
            "noise_attestation": hex(&attest),
        })
        .to_string();
        let resp = app
            .clone()
            .oneshot(
                Request::post(format!("/portal/channels/{ch_hex}/claim"))
                    .header("content-type", "application/json")
                    .header("cookie", cookie.clone())
                    .body(Body::from(claim_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "claim succeeds");
        let resp = app
            .clone()
            .oneshot(
                Request::get(format!("/portal/channels/{ch_hex}/grant"))
                    .header("cookie", cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["identities"][0]["holder"], serde_json::json!(hex(&holder_bytes)));
        assert!(v["identities"][0]["grant"].is_null(), "no deposit yet: waiting state");

        // Owner deposits; the member's next fetch carries the grant bytes.
        // sig(128 hex) ‖ channel(64) ‖ holder(64) ‖ DIR ‖ rights ‖ deleg ‖ expires:
        // byte 128 (hex 256..258) is the direction -- 02 = Accept, so the page
        // prefills CT_CHANNEL_ROLE=accept (the #517-follow tester finding).
        let grant_hex = format!("{}{}{}02{}", "ab".repeat(64), hex(&ch.0), hex(&holder_bytes), "cd".repeat(10));
        assert_eq!(grant_hex.len(), 278, "wire-encoding length the endpoint validates");
        assert_eq!(
            channels.deposit_grant(&ch, "alice-owner", &holder_bytes, &grant_hex, 3_000).unwrap(),
            GrantDepositOutcome::Deposited
        );
        let resp = app
            .clone()
            .oneshot(
                Request::get(format!("/portal/channels/{ch_hex}/grant"))
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["identities"][0]["grant"], serde_json::json!(grant_hex));

        // #514 slice 2: the RETURNING member's claim PAGE ships the deposited grant
        // filled into the onboarding block -- re-fetchable delivery in the UI, not
        // only the JSON endpoint.
        let resp = app
            .clone()
            .oneshot(
                Request::get(format!("/portal/channels/{ch_hex}/claim"))
                    .header(
                        "cookie",
                        format!(
                            "ct_portal_session={}",
                            sign_session_with_email_for_test(KEY, "subj-nat", "nat@example.com")
                        ),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = String::from_utf8(to_bytes(resp.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap();
        assert!(
            html.contains(&format!("CT_CHANNEL_GRANT={grant_hex}")),
            "the returning member's page fills the deposited grant into the env block"
        );
        // #517-follow: the grant's direction byte (accept = "02" at hex 256..258)
        // prefills CT_CHANNEL_ROLE instead of the ask-your-owner placeholder.
        assert!(
            html.contains("CT_CHANNEL_ROLE=accept"),
            "the deposited grant's accept direction prefills the role"
        );
        // #523: the returning member's page carries the claimed-holder list (so the
        // claim script can detect a fresh-browser mismatch) and the hidden warn box.
        assert!(
            html.contains(&format!(r#"<script id="claimed-holders" type="application/json">["{}"]"#, hex(&holder_bytes))),
            "the claimed holder is embedded for client-side mismatch detection"
        );
        assert!(
            html.contains(r#"<div id="identity-mismatch" class="warn" style="display:none"></div>"#),
            "the (hidden) mismatch warn box is present for the script to fill"
        );
        assert!(
            !html.contains("CT_CHANNEL_ROLE=PASTE_INITIATE_OR_ACCEPT"),
            "no placeholder once the role is known from the grant"
        );
        assert!(
            !html.contains("PASTE_YOUR_CT_CHANNEL_GRANT_HERE") || html.contains("Your identities on this channel"),
            "the existing-identity block renders"
        );
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
        let app = channel_claim_router(KEY, channels.clone(), "https://portal.example", "/nonexistent/ct-edge-ca.der");

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

    /// Proves the CLIENT-SIDE JS preimage builder in [`CLAIM_SCRIPT_TEMPLATE`]'s
    /// `memberNoiseAttestBytes` is byte-identical to the server-side
    /// [`ct_common::channel::member_noise_attest_bytes`] a browser-generated claim signature
    /// must match to verify. A real browser can't run inside this test suite, so this mirrors
    /// the JS algorithm in Rust byte-for-byte -- domain length-prefixed `u32-LE` || domain ||
    /// channel(32) || holder(32) || noise_pubkey(32), read straight off `CLAIM_SCRIPT_TEMPLATE`'s
    /// `memberNoiseAttestBytes`/`hexToBytes`/`concatBytes` above -- and checks it against
    /// [`ct_common::channel::member_noise_attest_bytes`] (`crates/common/src/channel.rs:760-771`)
    /// built via [`ct_common::preimage::Preimage`] (`crates/common/src/preimage.rs:39-58` for the
    /// `u32-LE length || domain` seed, `:91-95` for `var_bytes`, though this preimage only uses
    /// `.fixed()` after the domain since channel/holder/noise_pubkey are all fixed-32-byte
    /// fields). Then signs the JS-computed preimage with a real ed25519 key and confirms the
    /// SAME verifier `do_claim` calls, [`ct_common::channel::verify_member_noise_attestation`],
    /// accepts it -- proving a browser-generated signature really does verify server-side, not
    /// just that the byte builder happens to match in isolation. A byte-layout drift here would
    /// be a SILENT correctness bug (every browser-generated claim would fail verification with
    /// no clear error, since `holderSign` itself can't tell it signed the "wrong" bytes) -- this
    /// is the regression guard for that.
    #[test]
    fn member_noise_attest_bytes_js_reimplementation_matches_the_server_side_byte_layout() {
        use ct_common::channel::{verify_member_noise_attestation, ChannelId};
        use ed25519_dalek::{Signer, SigningKey};

        // Byte-for-byte port of CLAIM_SCRIPT_TEMPLATE's memberNoiseAttestBytes (JS
        // reimplemented in Rust here, since the test suite can't execute browser JS).
        fn js_member_noise_attest_bytes(channel: &[u8; 32], holder: &[u8; 32], noise_pubkey: &[u8; 32]) -> Vec<u8> {
            let domain = b"ct-a2a-noise-attest-v1";
            let mut out = Vec::new();
            out.extend_from_slice(&(domain.len() as u32).to_le_bytes());
            out.extend_from_slice(domain);
            out.extend_from_slice(channel);
            out.extend_from_slice(holder);
            out.extend_from_slice(noise_pubkey);
            out
        }

        let channel = ChannelId([0x11u8; 32]);
        let holder_sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let holder_pub = holder_sk.verifying_key().to_bytes();
        let noise_pubkey = [0x33u8; 32];

        let js_bytes = js_member_noise_attest_bytes(&channel.0, &holder_pub, &noise_pubkey);
        let server_bytes = ct_common::channel::member_noise_attest_bytes(&channel, &holder_pub, &noise_pubkey);
        assert_eq!(js_bytes, server_bytes, "the JS reimplementation's preimage bytes must match the server's exactly");

        // Sign the JS-computed preimage with a real holder key -- exactly what wasm.holderSign
        // does in the browser -- and confirm the real server-side verifier accepts it.
        let signature: [u8; 64] = holder_sk.sign(&js_bytes).to_bytes();
        assert!(
            verify_member_noise_attestation(&channel, &holder_pub, &noise_pubkey, &signature),
            "a signature over the JS-computed preimage must verify against the real server-side verifier"
        );

        // A signature over a DIFFERENT noise_pubkey must NOT verify against the original --
        // proves this check isn't accidentally too weak to catch a real byte-layout mismatch.
        let wrong_noise = [0x44u8; 32];
        let wrong_bytes = js_member_noise_attest_bytes(&channel.0, &holder_pub, &wrong_noise);
        let wrong_sig: [u8; 64] = holder_sk.sign(&wrong_bytes).to_bytes();
        assert!(!verify_member_noise_attestation(&channel, &holder_pub, &noise_pubkey, &wrong_sig));
    }

    /// A malformed channel id (only reachable via a hand-crafted URL) must render a plain error
    /// card with NO `<script>` emitted at all -- `claim_html` splices `channel_hex` straight into
    /// a `<script>` body for a valid one, so an attacker-controlled value must never reach that
    /// path unvalidated (see `claim_html`'s own doc comment on why HTML-escaping alone isn't
    /// sufficient there).
    #[tokio::test]
    async fn claim_page_rejects_a_malformed_channel_id_before_ever_emitting_the_identity_script() {
        use crate::storage::SqliteChannelStore;

        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let app = channel_claim_router(KEY, channels, "https://portal.example", "/nonexistent/ct-edge-ca.der");

        let (status, html) = get(&app, "/portal/channels/not-hex-and-also-not-64-chars/claim", Some("nat-subject")).await;
        assert_eq!(status, StatusCode::OK, "renders an error page, not a raw error status");
        assert!(html.contains("Malformed channel id"));
        assert!(!html.contains("<script type=\"module\">"), "no identity-generation script for a malformed channel id");
        assert!(!html.contains("ct_agent_wasm.js"), "never references the wasm bundle for a malformed channel id");
    }

    /// The claim page's in-browser identity-generation script: present for a real channel,
    /// loads the SAME `ct-agent-wasm` bundle [`serve_ct_agent_wasm_js`]/[`serve_ct_agent_wasm_bg`]
    /// serve, and has the real (hex-validated) channel id spliced in -- not the CLI-paste form
    /// this replaced.
    #[tokio::test]
    async fn claim_page_embeds_the_in_browser_identity_script_with_the_real_channel_hex() {
        use crate::storage::SqliteChannelStore;
        use ct_common::channel::ChannelId;

        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let ch = ChannelId([0x6bu8; 32]);
        assert!(channels.register_channel(&ch, &[0x22u8; 32], "alice-owner").unwrap());
        let app = channel_claim_router(KEY, channels, "https://portal.example", "/nonexistent/ct-edge-ca.der");
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let ch_hex = hex(&ch.0);

        let (status, html) = get(&app, &format!("/portal/channels/{ch_hex}/claim"), Some("nat-subject")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains(r#"<script type="module">"#), "the identity-generation script is present");
        assert!(html.contains(r#"import init, * as wasm from "/portal/static/ct_agent_wasm.js""#));
        assert!(html.contains(&format!(r#"const CHANNEL_HEX = "{ch_hex}""#)), "the real channel hex is spliced in");
        assert!(!html.contains("ct-agent channel member-material"), "the old CLI-paste instructions are gone");
        assert!(html.contains(r#"id="f-holder""#) && html.contains(r#"id="f-noise-pubkey""#) && html.contains(r#"id="f-noise-attestation""#));
        assert!(html.contains(r#"id="claim-submit" disabled"#), "submit starts disabled until identity generation finishes");
    }

    /// The two static routes the in-browser script depends on: present, and served with the
    /// exact `Content-Type`s a browser needs (`application/javascript` for the glue module,
    /// `application/wasm` for the binary -- the latter is what gates
    /// `WebAssembly.instantiateStreaming`'s fast path).
    #[tokio::test]
    async fn ct_agent_wasm_static_routes_serve_with_the_correct_content_types() {
        use crate::storage::SqliteChannelStore;

        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let app = channel_claim_router(KEY, channels, "https://portal.example", "/nonexistent/ct-edge-ca.der");

        let resp = app
            .clone()
            .oneshot(Request::get("/portal/static/ct_agent_wasm.js").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(axum::http::header::CONTENT_TYPE).unwrap(), "application/javascript");

        let resp = app
            .oneshot(Request::get("/portal/static/ct_agent_wasm_bg.wasm").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(axum::http::header::CONTENT_TYPE).unwrap(), "application/wasm");
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
        let app = channel_claim_router(KEY, channels.clone(), "https://portal.example", "/nonexistent/ct-edge-ca.der");
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

    /// Post-claim onboarding follow-up (live support case: a Windows client whose
    /// network blocked the channel broker/relay ports outright, 4435/4436). A
    /// successful claim must now hand the member a real, ready-to-fill `.env`
    /// (broker/relay/front-door filled in for real, exactly like `install_page`'s
    /// tunnel `.env`) -- but the two PRIVATE keys AND the operator-signed grant
    /// must never be anything but clearly-labeled placeholders, since this server
    /// has never held any of the three private keys involved (the member's holder
    /// key, the member's Noise key, or the channel operator's key).
    #[tokio::test]
    async fn successful_claim_shows_a_real_onboarding_env_with_private_material_as_placeholders() {
        use crate::portal::sign_session_with_email_for_test;
        use crate::storage::SqliteChannelStore;
        use ct_common::channel::{member_noise_attest_bytes, ChannelId};
        use ed25519_dalek::{Signer, SigningKey};

        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let ch = ChannelId([0x5eu8; 32]);
        assert!(channels.register_channel(&ch, &[0x22u8; 32], "alice-owner").unwrap());
        assert!(channels.allowlist_add(&ch, "alice-owner", "nat@example.com", 1_000).unwrap());

        // A real edge CA root DER on disk -- the front door must be live-fetched
        // from here, never hardcoded/baked in (the whole point of #345/GET /pki/ca
        // being the live source of truth this reuses).
        let der: &[u8] = b"\x30\x82\x01\x0a-fake-edge-ca-root-der";
        let cert_path = std::env::temp_dir().join(format!("ct-cp-claim-onboarding-ca-{}.der", std::process::id()));
        std::fs::write(&cert_path, der).unwrap();
        let cert_path_str = cert_path.to_string_lossy().into_owned();

        let app = channel_claim_router(KEY, channels.clone(), "https://portal.example", &cert_path_str);
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let ch_hex = hex(&ch.0);
        let holder_sk = SigningKey::from_bytes(&[0xc7u8; 32]);
        let holder_bytes = holder_sk.verifying_key().to_bytes();
        let holder_hex = hex(&holder_bytes);
        let noise = [0xd8u8; 32];
        let attest = holder_sk.sign(&member_noise_attest_bytes(&ch, &holder_bytes, &noise)).to_bytes();
        let form = format!("holder={}&noise_pubkey={}&noise_attestation={}", holder_hex, hex(&noise), hex(&attest));

        let allowed_cookie =
            format!("ct_portal_session={}", sign_session_with_email_for_test(KEY, "nat-subject", "nat@example.com"));
        let resp = app
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
        let html = String::from_utf8(to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap();
        let _ = std::fs::remove_file(&cert_path);

        assert!(html.contains("Claimed"));

        // Real, filled-in deployment-wide values -- broker/relay always real; the
        // front door real too since the CA root file existed above.
        assert!(html.contains("CT_CHANNEL_BROKER=portal.example:4435"), "real broker host:port");
        assert!(html.contains("CT_CHANNEL_RELAY=portal.example:4436"), "real relay host:port");
        assert!(html.contains("CT_CHANNEL_FRONT_DOOR=portal.example:443"), "real front-door host:port");
        assert!(
            html.contains(&format!("CT_CHANNEL_FRONT_DOOR_CERT={}", hex(der))),
            "the front-door cert is the REAL edge CA root DER read live from disk, hex-encoded -- \
             the same bytes GET /pki/ca serves, not a hardcoded value that goes stale on rotation"
        );

        // The grant command is pre-filled with the REAL channel id + the member's
        // just-claimed holder key, so the owner only pastes one command.
        assert!(html.contains(&format!("CT_GRANT_CHANNEL={ch_hex}")), "grant command carries the real channel id");
        assert!(
            html.contains(&format!("CT_GRANT_MEMBER_HOLDER={holder_hex}")),
            "grant command carries the member's real just-claimed holder key"
        );
        assert!(html.contains("ct-agent channel grant"), "the real ct-agent CLI invocation the owner runs");

        // SECURITY: never a real private key, never a real grant -- both are
        // categorically impossible for this server to produce, and must stay
        // obvious, unmistakable placeholders. Assert the placeholder text is
        // present and that neither of the member's actually-generated SECRET
        // values (which this test never even submits to the server) could
        // possibly appear.
        assert!(
            html.contains("CT_CHANNEL_HOLDER_KEY=PASTE_YOUR_PRIVATE_HOLDER_KEY_HERE"),
            "holder private key stays an unmistakable placeholder"
        );
        assert!(
            html.contains("CT_CHANNEL_NOISE_KEY=PASTE_YOUR_PRIVATE_NOISE_KEY_HERE"),
            "Noise private key stays an unmistakable placeholder"
        );
        assert!(
            html.contains("CT_CHANNEL_GRANT=PASTE_YOUR_CT_CHANNEL_GRANT_HERE"),
            "the grant stays an unmistakable placeholder -- this server never held the operator \
             key and categorically cannot issue one"
        );
        assert!(
            html.contains("this server has never held either") || html.contains("this server never holds the operator key"),
            "explains WHY these stay placeholders, not just that they do"
        );

        // Both bash and PowerShell "Run it" tabs, same toggle mechanism as install_page.
        assert!(html.contains(r#"onclick="showTab(this,'channel-run-bash')""#));
        assert!(html.contains(r#"onclick="showTab(this,'channel-run-powershell')""#));
        assert!(html.contains("set -a; source .env; set +a") && html.contains("ct-agent channel"), "bash run command");
        assert!(html.contains(".\\ct-agent.exe channel"), "PowerShell run command");
        assert!(
            html.matches("CT_CHANNEL_BROKER=").count() == 1,
            "the .env block itself is not duplicated for the PowerShell tab"
        );
    }

    /// Graceful "absent -> omitted" behavior (matching `install_page`'s own
    /// convention, e.g. its `hostname_line`): a deployment that hasn't published
    /// its edge CA root yet must cleanly omit the `:443` front-door lines, not
    /// error the whole onboarding block.
    #[tokio::test]
    async fn onboarding_omits_the_front_door_cleanly_when_the_edge_hasnt_published_its_cert_yet() {
        use crate::portal::sign_session_with_email_for_test;
        use crate::storage::SqliteChannelStore;
        use ct_common::channel::{member_noise_attest_bytes, ChannelId};
        use ed25519_dalek::{Signer, SigningKey};

        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let ch = ChannelId([0x5fu8; 32]);
        assert!(channels.register_channel(&ch, &[0x22u8; 32], "alice-owner").unwrap());
        assert!(channels.allowlist_add(&ch, "alice-owner", "nat@example.com", 1_000).unwrap());

        let app = channel_claim_router(KEY, channels.clone(), "https://portal.example", "/nonexistent/ct-edge-ca.der");
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let ch_hex = hex(&ch.0);
        let holder_sk = SigningKey::from_bytes(&[0xc9u8; 32]);
        let holder_bytes = holder_sk.verifying_key().to_bytes();
        let noise = [0xdau8; 32];
        let attest = holder_sk.sign(&member_noise_attest_bytes(&ch, &holder_bytes, &noise)).to_bytes();
        let form = format!("holder={}&noise_pubkey={}&noise_attestation={}", hex(&holder_bytes), hex(&noise), hex(&attest));

        let allowed_cookie =
            format!("ct_portal_session={}", sign_session_with_email_for_test(KEY, "nat-subject", "nat@example.com"));
        let resp = app
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
        let html = String::from_utf8(to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap();

        assert!(html.contains("Claimed"));
        assert!(html.contains("CT_CHANNEL_BROKER=portal.example:4435"), "broker/relay stay real+present");
        assert!(html.contains("CT_CHANNEL_RELAY=portal.example:4436"));
        assert!(!html.contains("CT_CHANNEL_FRONT_DOOR="), "front-door lines cleanly absent, not an error");
        assert!(!html.contains("CT_CHANNEL_FRONT_DOOR_CERT="));
        assert!(
            html.contains("hasn't published its edge CA root yet"),
            "explains WHY the fallback is unavailable on this deployment"
        );
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
            .claim_via_allowlist(&ch_claimed, "nat@example.com", &[0xc3u8; 32], &[0xd4u8; 32], &[0u8; 64], 2_000, None)
            .unwrap().claimed());

        let app = channel_claim_router(KEY, channels.clone(), "https://portal.example", "/nonexistent/ct-edge-ca.der");
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
        let t = tunnels.create("alice", "site", Some("alice.example")).unwrap().created().expect("hostname is free in this test");
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
        let t = tunnels.create("alice", "site", Some("alice.example")).unwrap().created().expect("hostname is free in this test");
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
        let t = tunnels.create("alice", "site", Some("alice.example")).unwrap().created().expect("hostname is free in this test");
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
