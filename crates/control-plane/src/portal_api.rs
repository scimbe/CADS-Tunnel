//! Authenticated customer-portal API (#26–#29) — the logged-in surface behind
//! the SSO session (#25). Every endpoint resolves the caller's subject from the
//! signed session cookie via [`crate::portal::session_subject_for`]; without a
//! valid session the visitor is bounced to the portal shell. All pages are
//! server-rendered, self-contained, CSP-safe HTML, and every subject only ever
//! sees or changes their own data.

use std::sync::Arc;

use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;

use std::time::{SystemTime, UNIX_EPOCH};

use crate::accounts::AccountId;
use crate::installer::{install_bundle_secret, install_one_liner_bootstrap, InstallOs};
use crate::portal::{escape, session_subject_for};
use crate::storage::{GrantError, SqliteBootstrap, SqliteEnrollment, SqliteLedger, SqliteTunnelStore};
use ct_common::TenantId;
use ct_dns::provider::DesecClient;

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
/// the portal request.
fn edge_admin_http_client() -> reqwest::Client {
    edge_admin_http_client_with(std::time::Duration::from_secs(5))
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
    /// Bootstrap-token store (#90/#97 SEC90b): the install page mints a short-lived
    /// token over the `{join, routing}` bundle so the shown one-liner carries no secret.
    bootstrap: Arc<SqliteBootstrap>,
    /// Public portal origin (e.g. `https://portal.example`) baked into installers.
    portal_base: Arc<str>,
    /// Edge admin revoke endpoint (#27 RB4b); `None` disables edge propagation.
    edge_admin: Option<EdgeAdmin>,
    /// Automatic DNS for tunnel hostnames (#38 DL2); `None` disables it.
    dns: Option<DnsAutopilot>,
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
    };
    Router::new()
        .route("/portal/account", get(account_page))
        .route("/portal/account/credits", post(buy_credits))
        .route("/portal/tunnels", get(tunnels_page).post(create_tunnel))
        .route("/portal/tunnels/:id/delete", post(delete_tunnel))
        .route("/portal/tunnels/:id/install", get(install_page))
        .route("/portal/tunnels/:id/grants", get(grants_page).post(add_grant))
        .route("/portal/tunnels/:id/grants/:grantee/delete", post(delete_grant))
        .with_state(state)
}

/// Resolve the caller's account from the session, or an early response
/// (redirect to the shell when unauthenticated, 500 on a store error).
fn account_for_session(st: &ApiState, headers: &HeaderMap) -> Result<(String, AccountId), Response> {
    let subject = session_subject_for(&st.session_key, headers)
        .ok_or_else(|| Redirect::to("/portal").into_response())?;
    let account = st
        .ledger
        .account_for_subject(&subject)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())?;
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
    Html(account_html(&subject, &hex(&account.0), balance)).into_response()
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
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
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

/// A short, stable, non-choosable per-account suffix (4 hex chars of
/// SHA-256(subject)) — the "unique user id" half of the Standard tier's
/// auto-assigned hostname `<name>-<user-id>.<zone>` (see the landing page's
/// subdomain-policy step and the /publish onboarding).
fn account_suffix(subject: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(subject.as_bytes());
    hex(&digest[..2])
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
async fn tunnels_page(State(st): State<ApiState>, headers: HeaderMap) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    let owns_one = match st.tunnels.list_authorized_for_subject(&subject) {
        Ok(rows) => rows.iter().any(|(_, owned)| *owned),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if !owns_one {
        provision_tunnel(&st, &subject, "site").await;
    }
    match st.tunnels.list_authorized_for_subject(&subject) {
        Ok(tunnels) => Html(tunnels_html(&tunnels)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
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
    let tunnel = match st.tunnels.create(subject, name, hostname.as_deref()) {
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
                eprintln!("ct-cp: edge authorize-host for {host} succeeded")
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
    match st.tunnels.list_authorized_for_subject(&subject) {
        Ok(rows) if rows.iter().any(|(_, owned)| *owned) => {
            return (
                StatusCode::FORBIDDEN,
                "the Standard tier includes one tunnel per account; additional tunnels are a planned paid-tier feature",
            )
                .into_response();
        }
        Ok(_) => {}
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
    let hostname = st
        .dns
        .as_ref()
        .map(|d| auto_hostname(d.client.domain(), name, &subject))
        .as_deref()
        .and_then(ct_common::normalize_hostname);
    let tunnel = match st.tunnels.create(&subject, name, hostname.as_deref()) {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
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
    if let Ok(Some(routing_token)) = st.tunnels.revoke(&subject, &id) {
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

/// Which OS installer to show; absent = show all.
#[derive(Deserialize)]
struct InstallQuery {
    os: Option<String>,
}

/// TTL (seconds) for the bootstrap token minted for an install one-liner (#90/#97
/// SEC90b): short — it exists only to be redeemed once, promptly, by the installer.
const INSTALL_BOOTSTRAP_TTL_SECS: u64 = 600;

/// `GET /portal/tunnels/:id/install` (#28): render the copy-paste one-liner(s)
/// that install + onboard an agent for one of the caller's own tunnels. A fresh,
/// single-use join token is minted per request and embedded via an env var.
///
/// The token is a secret: it is shown once to the authenticated owner and never
/// logged, cached or persisted anywhere in cleartext.
async fn install_page(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<InstallQuery>,
) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    // Authorized = owner OR grantee (#29): a shared-with subject may also install
    // an agent for the tunnel. `None` when unknown or the caller isn't authorized.
    let routing_token = match st.tunnels.routing_token_if_authorized(&subject, &id) {
        Ok(Some(t)) => t,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such tunnel").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    // Mint a fresh single-use join token bound to the customer (subject as tenant).
    let token = match st.enrollment.issue_join_token(&TenantId(subject.clone())) {
        Ok(t) => hex(&t.0),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    // #90/#97 SEC90b: mint a short-lived, single-use bootstrap token over the
    // {join, routing} bundle and carry only *that* in the copy-paste one-liner, so
    // no real secret lands in shell history / `ps`. The install script redeems it
    // server-side (`POST /bootstrap/redeem`). The raw tokens are still shown once,
    // separately, for the manual onboarding path below.
    let bundle = install_bundle_secret(&token, &routing_token);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let boot = match st.bootstrap.mint(&bundle, INSTALL_BOOTSTRAP_TTL_SECS, now) {
        Ok(b) => hex(&b),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let oses = match q.os.as_deref().and_then(InstallOs::parse) {
        Some(os) => vec![os],
        None => vec![InstallOs::Unix, InstallOs::Windows],
    };
    let blocks = oses
        .iter()
        .map(|os| {
            let label = match os {
                InstallOs::Unix => "Linux / macOS",
                InstallOs::Windows => "Windows (PowerShell)",
            };
            let cmd = install_one_liner_bootstrap(&st.portal_base, &boot, *os);
            format!(
                r#"<h2>{label}</h2><div class="code-block">
 <div class="code-block-head"><span>one-liner</span><button class="copy-btn" onclick="copyCode(this)" type="button">Copy</button></div>
 <pre><code>{}</code></pre>
</div>"#,
                escape(&cmd)
            )
        })
        .collect::<String>();
    let body = format!(
        r#"<h1>Install an agent</h1>
<p class="help">Run this <strong>on the machine you want to expose</strong> &mdash;
the <em>origin</em>: the server or device running the service you are tunnelling,
not the device you are reading this on. The agent connects out to the relay and
serves your origin through it (no inbound firewall port needed).</p>
<div class="warn"><strong>&#9888; The one-line installer isn't live yet (#75).</strong> It will
work once <code>ct-agent</code> prebuilt binaries ship. For now, use the tokens below with
<code>ct-agent onboard</code> directly &mdash; see the
<a href="https://github.com/scimbe/CADS-Tunnel/blob/main/docs/onboarding/quickstart.md">onboarding guide</a>.</div>
<h2>Your tunnel's tokens (for manual onboarding)</h2>
<p class="k"><strong>Single-use token — shown only once; reopen this Install page for a fresh one.</strong></p>
<p class="help">Minted ready to use &mdash; accepted immediately, no separate approval step. Copy
this into a <code>.env</code> file <strong>on the machine you want to expose</strong> (the
<em>origin</em>), then <code>set -a; source .env; set +a</code> before running
<code>ct-agent onboard</code>, rather than leaving it in your shell history.</p>
<div class="code-block">
 <div class="code-block-head"><span>.env</span><button class="copy-btn" onclick="copyCode(this)" type="button">Copy</button></div>
 <pre><code>CT_JOIN_TOKEN={jt}
CT_AGENT_TOKEN={rt}
# also set CT_AGENT_CP_URL, CT_AGENT_EDGE, CT_AGENT_ORIGIN (see the onboarding guide), then run: ct-agent onboard</code></pre>
</div>
<h2 class="muted">One-line installer &mdash; coming soon (not functional yet)</h2>
{blocks}
<a class="btn sec" href="/portal/tunnels">Back to tunnels</a>"#,
        jt = escape(&token),
        rt = escape(&routing_token),
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
        GrantError::Db(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
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

fn tunnels_html(tunnels: &[(crate::storage::SubjectTunnel, bool)]) -> String {
    let rows = tunnels
        .iter()
        .map(|(t, owned)| {
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
            let owner_actions = if *owned {
                format!(
                    r#" <a class="btn sec" href="/portal/tunnels/{id}/install">Install</a>
 <span class="btn sec disabled" title="Sharing tunnels is a planned paid-tier feature">Share</span>
 <form class="inline" method="post" action="/portal/tunnels/{id}/delete">
  <button class="sec" type="submit">Revoke</button></form>"#
                )
            } else {
                format!(
                    r#" <a class="btn sec" href="/portal/tunnels/{id}/install">Install</a>
 <span class="k">(shared with you)</span>"#
                )
            };
            format!(
                r#"<div class="row"><span class="v">{name}{host}</span><span>{owner_actions}
</span></div>"#,
                name = escape(&t.name),
            )
        })
        .collect::<String>();
    let body = format!(
        r#"<h1>Your tunnels</h1>
{rows}
<p class="help">Included in every tier: <strong>one</strong> tunnel with an automatically
assigned hostname (e.g. <code>site-a3f9.bunsenbrenner.org</code>) &mdash; already set up for
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
pub(crate) fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CADS-Tunnel — {title}</title>
<style>
 body{{font-family:system-ui,sans-serif;margin:0;background:#0e1116;color:#e6edf3;
      display:flex;min-height:100vh;align-items:flex-start;justify-content:center;padding:3rem 1rem}}
 .card{{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:2rem;max-width:640px;width:100%}}
 h1{{font-size:1.3rem;margin:.1rem 0 1rem}} h2{{font-size:1rem;color:#8b949e;margin:1.4rem 0 .6rem}}
 .row{{display:flex;justify-content:space-between;padding:.5rem 0;border-bottom:1px solid #21262d}}
 .k{{color:#8b949e}} .v{{word-break:break-all}}
 nav a{{color:#58a6ff;text-decoration:none;margin-right:1rem;font-size:.9rem}} nav{{margin-bottom:1.2rem}}
 a.btn,button{{background:#238636;color:#fff;border:0;border-radius:8px;padding:.5rem 1rem;
      font:inherit;font-weight:600;cursor:pointer;text-decoration:none;display:inline-block}}
 a.btn.sec,button.sec{{background:#21262d;border:1px solid #30363d;color:#e6edf3;font-weight:500}}
 input,select{{background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:8px;padding:.5rem;font:inherit}}
 code{{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:.15rem .4rem}}
 form.inline{{display:inline}}
 label{{display:block;margin:.85rem 0;font-size:.9rem}}
 label input{{display:block;margin-top:.3rem;width:100%;max-width:360px}}
 .help{{color:#8b949e;font-size:.82rem;display:block}} label .help{{margin-top:.35rem}}
 p.help{{margin:.2rem 0 1rem}} .opt{{color:#8b949e;font-weight:400}}
 ol.steps{{color:#8b949e;font-size:.86rem;margin:.2rem 0;padding-left:1.2rem}}
 ol.steps li{{margin:.35rem 0}} ol.steps strong{{color:#e6edf3}}
 .warn{{background:#3d1e00;border:1px solid #7d4e00;color:#f0c674;border-radius:8px;padding:.7rem .9rem;margin:1rem 0;font-size:.88rem;line-height:1.6}}
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
</style></head><body>
<div class="card">
<nav><a href="/portal/account">Account</a><a href="/portal/tunnels">Tunnels</a><a href="/portal/logout">Sign out</a></nav>
{body}
</div>
<script>
 function copyCode(btn){{
  const code = btn.closest('.code-block').querySelector('code');
  const text = code ? code.textContent : '';
  const done = () => {{ const orig = btn.textContent; btn.textContent = 'Copied'; setTimeout(()=>{{ btn.textContent = orig; }}, 1600); }};
  if(navigator.clipboard && navigator.clipboard.writeText){{ navigator.clipboard.writeText(text).then(done).catch(()=>{{}}); }}
 }}
</script>
</body></html>"#
    )
}

fn account_html(subject: &str, account_hex: &str, balance: u64) -> String {
    let body = format!(
        r#"<h1>Your account</h1>
<div class="row"><span class="k">Subject</span><span class="v">{subject}</span></div>
<div class="row"><span class="k">Account&nbsp;ID</span><span class="v">{account}</span></div>
<div class="row"><span class="k">Credit&nbsp;balance</span><span class="v">{balance}</span></div>
<h2>Buy credits</h2>
<form method="post" action="/portal/account/credits">
 <input type="number" name="credits" min="1" value="100" required>
 <button type="submit">Create payment intent</button>
</form>"#,
        subject = escape(subject),
        account = escape(account_hex),
        balance = balance,
    );
    page("your account", &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portal::sign_session_for_test;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    const KEY: &[u8] = b"portal-api-test-key";

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

    fn test_app() -> Router {
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let enrollment = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let bootstrap = Arc::new(SqliteBootstrap::open_in_memory().unwrap());
        portal_api_router(KEY, ledger, tunnels, enrollment, bootstrap, "https://portal.example", None, None)
    }

    #[tokio::test]
    async fn install_page_shows_a_bootstrap_one_liner_carrying_no_real_token() {
        // #90/#97 SEC90b: the copy-paste one-liner must carry only CT_BOOTSTRAP, never
        // the raw join/routing tokens (those appear only in the separate manual block).
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let enrollment = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let bootstrap = Arc::new(SqliteBootstrap::open_in_memory().unwrap());
        // Own a tunnel so the install page authorizes and has a routing token.
        let tunnel = tunnels.create("kc-user-1", "t", None).unwrap();
        let routing = tunnel.routing_token.clone();
        let app = portal_api_router(
            KEY,
            ledger,
            tunnels,
            enrollment,
            bootstrap,
            "https://portal.example",
            None,
            None,
        );
        let resp = app
            .oneshot(
                Request::get(format!("/portal/tunnels/{}/install?os=linux", tunnel.id))
                    .header("cookie", session_header("kc-user-1"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // The one-liner carries CT_BOOTSTRAP and pipes to the installer.
        assert!(html.contains("CT_BOOTSTRAP="), "one-liner carries the bootstrap token");
        assert!(html.contains("/install.sh"), "pipes the installer script");
        // The routing token must NOT appear inside a shown `curl … | … sh` command.
        for line in html.lines().filter(|l| l.contains("CT_BOOTSTRAP=")) {
            assert!(
                !line.contains(&routing),
                "the routing token must not be embedded in the one-liner command"
            );
        }
        // The manual block still exists (raw tokens shown once, separately).
        assert!(html.contains("CT_JOIN_TOKEN=") && html.contains("manual onboarding"), "manual path retained");
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
        let app = portal_api_router(
            KEY,
            ledger,
            tunnels.clone(),
            enrollment,
            Arc::new(SqliteBootstrap::open_in_memory().unwrap()),
            "https://portal.example",
            Some((format!("http://{addr}"), "edge-secret".to_string())),
            None,
        );

        let status = post_form(&app, &format!("/portal/tunnels/{}/delete", created.id), "alice", "").await;
        assert_eq!(status, StatusCode::SEE_OTHER);

        let got = received.lock().unwrap().clone().expect("edge revoke was called");
        assert_eq!(got.0, created.routing_token, "revoked the tunnel's routing token");
        assert_eq!(got.1, "edge-secret", "carried the admin auth header");
        assert!(tunnels.list_for_subject("alice").unwrap().is_empty(), "tunnel removed");
    }

    #[tokio::test]
    async fn auto_provisioned_tunnel_with_a_hostname_authorizes_it_at_the_edge() {
        // #23 BP4b-c (updated for the Standard-tier auto-provision policy, #226):
        // the tunnel's auto-assigned (not user-chosen) hostname still authorizes
        // (host -> token) at the edge so the agent's 'H' bind is accepted under
        // required auth.
        use axum::extract::{Path as AxPath, State as AxState};
        use axum::http::HeaderMap as AxHeaderMap;
        use std::sync::Mutex;

        let received: Arc<Mutex<Option<(String, String, String)>>> = Arc::new(Mutex::new(None));
        let mock = Router::new()
            .route(
                "/admin/authorize-host/:token/:host",
                post(
                    |AxState(rec): AxState<Arc<Mutex<Option<(String, String, String)>>>>,
                     headers: AxHeaderMap,
                     AxPath((token, host)): AxPath<(String, String)>| async move {
                        let auth = headers
                            .get("x-ct-admin-token")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        *rec.lock().unwrap() = Some((token, host, auth));
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
        let app = portal_api_router(
            KEY,
            ledger,
            tunnels.clone(),
            enrollment,
            Arc::new(SqliteBootstrap::open_in_memory().unwrap()),
            "https://portal.example",
            Some((format!("http://{addr}"), "edge-secret".to_string())),
            Some((desec, "1.2.3.4".to_string())),
        );

        // Viewing the tunnels page auto-provisions the one Standard-tier tunnel.
        assert_eq!(get(&app, "/portal/tunnels", Some("alice")).await.0, StatusCode::OK);

        let tunnel = &tunnels.list_for_subject("alice").unwrap()[0];
        let expected_host = tunnel.hostname.clone().expect("auto-assigned a hostname");
        assert!(
            expected_host.starts_with("site-") && expected_host.ends_with(".bunsenbrenner.org"),
            "auto-assigned from the tunnel name + account suffix, not user-chosen: {expected_host}"
        );

        // The edge received authorize-host with this tunnel's routing token + auth.
        let (token, host, auth) = received.lock().unwrap().clone().expect("edge authorize called");
        assert_eq!(token, tunnel.routing_token, "authorizes the tunnel's routing token");
        assert_eq!(host, expected_host);
        assert_eq!(auth, "edge-secret");
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
    async fn install_page_is_owner_only_and_renders_per_os_one_liners() {
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

        // Owner sees both one-liners with the portal base and env-carried token.
        let (status, html) = get(&app, &format!("/portal/tunnels/{id}/install"), Some("alice")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("curl -fsSL https://portal.example/install.sh"));
        assert!(html.contains("CT_JOIN_TOKEN="), "join token carried via env");
        assert!(html.contains("CT_AGENT_TOKEN="), "tunnel routing token carried via env (#27 RB2)");
        assert!(html.contains("irm https://portal.example/install.ps1 | iex"));
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
        // #75: the /install.sh + /install.ps1 endpoints don't exist yet, so the page
        // must NOT present the one-liner as a working command — it must carry an
        // honest "isn't live yet" notice and surface the working manual path
        // (the tokens for `ct-agent onboard`), not a broken copy-paste.
        assert!(
            html.contains("isn't live yet (#75)"),
            "honestly flags the one-liner as non-functional until #75 ships"
        );
        assert!(
            html.contains("manual onboarding") && html.contains("ct-agent onboard"),
            "surfaces the working manual onboarding path with the tokens"
        );
        assert!(
            html.contains(".env"),
            "advises copying the tokens into a .env file on the exposing machine"
        );
        assert!(
            html.contains("copyCode(this)") && html.matches("copy-btn").count() >= 3,
            "every code block (tokens + both one-liners) has a copy button"
        );

        // os filter renders just one block.
        let (_s, only_win) = get(&app, &format!("/portal/tunnels/{id}/install?os=windows"), Some("alice")).await;
        assert!(only_win.contains("irm ") && !only_win.contains("curl -fsSL"));
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
            h.split("CT_JOIN_TOKEN=")
                .nth(1)
                .and_then(|s| s.split(|c| c == ' ' || c == '<').next())
                .unwrap()
                .to_string()
        };
        let a = extract(&get(&app, &format!("/portal/tunnels/{id}/install?os=linux"), Some("alice")).await.1);
        let b = extract(&get(&app, &format!("/portal/tunnels/{id}/install?os=linux"), Some("alice")).await.1);
        assert_ne!(a, b, "a fresh token is minted per request");
        assert!(!a.is_empty());
    }
}
