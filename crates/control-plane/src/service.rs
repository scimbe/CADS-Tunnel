//! Persistent HTTP surface (M18.4): the same JSON API as [`crate::http`], but
//! backed by the durable SQLite stores instead of in-memory state, so a service
//! restart preserves enrollment / registry / billing. This module grows one
//! router per store; M18.4a wires enrollment.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::accounts::{AccountId, LedgerError};
use crate::enrollment::{EnrollError, JoinToken};
use crate::oidc::OidcVerifierHandle;
#[cfg(test)]
use crate::oidc::OidcVerifier;
use crate::payment::{PaymentError, PaymentId};
use crate::payment_provider::WebhookVerifier;
use crate::registry::TunnelInfo;
use crate::storage::{
    AgentDirectoryEntry, AgentDirectoryError, BootstrapError, IssueBatchError, LedgerOpError,
    PaymentOpError, RedeemError, SqliteAgentDirectory, SqliteBootstrap, SqliteChannelStore,
    SqliteEnrollment,
    SqliteLedger, SqliteNetworkStore, SqlitePipelineRegistry, SqliteRegistry, SqliteTopologyStore,
};
use ct_common::channel::ChannelId;
use ct_common::ratelimit::KeyedRateLimiter;
use ct_common::{AgentId, RoutingToken, TenantId};
use ct_common::sync::MutexExt;

/// State for the enrollment router: the durable store plus, when configured, the
/// shared admin token that gates `/enroll/issue` (#87 SEC87b-auth).
#[derive(Clone)]
struct EnrollState {
    store: Arc<SqliteEnrollment>,
    /// When `Some`, `/enroll/issue` requires this token (machine-to-machine auth —
    /// minting join tokens is an operator action, not a public one). `None` leaves it
    /// open (dev/back-compat); the live CP sets it from `CT_CP_EDGE_ADMIN_TOKEN`.
    issue_admin_token: Option<[u8; 32]>,
}

/// Build the persistent enrollment router: `POST /enroll/issue`,
/// `POST /enroll/redeem`, backed by a durable [`SqliteEnrollment`]. `/enroll/issue`
/// is unauthenticated (dev/back-compat); use [`enrollment_router_sqlite_with_admin`]
/// to require the admin token on issuance.
pub fn enrollment_router_sqlite(store: Arc<SqliteEnrollment>) -> Router {
    enrollment_router_sqlite_with_admin(store, None)
}

/// Like [`enrollment_router_sqlite`] but gates `POST /enroll/issue` behind the shared
/// admin token (#87 SEC87b-auth): a caller must present `x-ct-admin-token`. `/enroll/redeem`
/// stays open — an agent redeems with its single-use join token + proof-of-possession,
/// which is its own auth. Only the *issuance* of join tokens is restricted here.
pub fn enrollment_router_sqlite_with_admin(
    store: Arc<SqliteEnrollment>,
    issue_admin_token: Option<[u8; 32]>,
) -> Router {
    Router::new()
        .route("/enroll/issue", post(issue))
        .route("/enroll/issue-batch", post(issue_batch))
        .route("/enroll/redeem", post(redeem))
        .with_state(EnrollState { store, issue_admin_token })
}

#[derive(Deserialize)]
struct IssueReq {
    tenant: String,
}
#[derive(Serialize, Deserialize)]
struct IssueResp {
    token: String,
}

/// #186: the ONE admin-token extract-and-compare. A presented `x-ct-admin-token` header hex-decodes
/// to 32 bytes and constant-time-equals `expected`. EVERY admin gate — the axum layer
/// ([`require_admin_token`]) and every inline guard ([`require_admin`]) — goes through this, so the
/// control-plane's write-authorization check has exactly one implementation and cannot drift (a
/// header rename, an added audit line, a per-IP limit lands in one place, not four). Constant-time via
/// [`ct_token_eq`]; a missing/malformed/wrong header is `false`.
fn admin_token_ok(headers: &HeaderMap, expected: &[u8; 32]) -> bool {
    headers
        .get("x-ct-admin-token")
        .and_then(|v| v.to_str().ok())
        .and_then(hex_decode_32)
        .map(|got| ct_token_eq(&got, expected))
        .unwrap_or(false)
}

/// #186: the shared INLINE admin guard. `Ok(())` when no token is configured (dev/back-compat) OR the
/// correct `x-ct-admin-token` is presented; `401` with the route-specific `msg` otherwise. The inline
/// gates (`/enroll/issue*`, `/registry/agents`, `/registry/pipelines`) are thin wrappers over this so
/// they share [`admin_token_ok`]'s single extract-and-compare. `pub(crate)` so [`crate::edge_mesh`]'s
/// endpoints reuse the exact same gate rather than growing a second copy.
pub(crate) fn require_admin(
    headers: &HeaderMap,
    expected: &Option<[u8; 32]>,
    msg: &'static str,
) -> Result<(), (StatusCode, String)> {
    match expected {
        Some(exp) if !admin_token_ok(headers, exp) => Err((StatusCode::UNAUTHORIZED, msg.to_string())),
        _ => Ok(()),
    }
}

/// #87 SEC87b-auth / #145: gate join-token issuance behind the configured admin token. Shared by
/// single (`/enroll/issue`) and batch (`/enroll/issue-batch`) issuance so both enforce the exact same
/// gate. Thin wrapper over [`require_admin`] (#186).
fn require_issue_admin(
    headers: &HeaderMap,
    expected: &Option<[u8; 32]>,
) -> Result<(), (StatusCode, String)> {
    require_admin(headers, expected, "join-token issuance requires the admin token")
}

/// #161/#87 SEC87b-auth: gate agent-directory self-registration (`POST /registry/agents`) behind the
/// shared machine-writer admin token. Thin wrapper over [`require_admin`] (#186).
fn require_agent_registry_admin(
    headers: &HeaderMap,
    expected: &Option<[u8; 32]>,
) -> Result<(), (StatusCode, String)> {
    require_admin(headers, expected, "agent-directory self-registration requires the admin token")
}

async fn issue(
    State(st): State<EnrollState>,
    headers: HeaderMap,
    Json(req): Json<IssueReq>,
) -> Result<Json<IssueResp>, (StatusCode, String)> {
    require_issue_admin(&headers, &st.issue_admin_token)?;
    let token = st
        .store
        .issue_join_token(&TenantId(req.tenant))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(IssueResp {
        token: hex_encode(&token.0),
    }))
}

/// Cap on one batch issuance so a single call can't exhaust the store (#145 bulk provisioning).
const MAX_BATCH_TOKENS: usize = 100;

#[derive(Deserialize)]
struct IssueBatchReq {
    tenant: String,
    count: usize,
    /// Optional idempotency key (#145, Marq): when present, a retried request with the same key
    /// returns the same token set instead of minting duplicates.
    #[serde(default)]
    idempotency_key: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct IssueBatchResp {
    tokens: Vec<String>,
}

/// `POST /enroll/issue-batch` (#145 bulk provisioning): mint `count` single-use join tokens for a
/// tenant in ONE admin call — turning "provision N agents" from N manual mints into one. Same
/// admin gate as `/enroll/issue`; `count` must be `1..=MAX_BATCH_TOKENS` (a `400` otherwise so one
/// call can't exhaust the store). Each token is independently redeemable exactly once.
async fn issue_batch(
    State(st): State<EnrollState>,
    headers: HeaderMap,
    Json(req): Json<IssueBatchReq>,
) -> Result<Json<IssueBatchResp>, (StatusCode, String)> {
    require_issue_admin(&headers, &st.issue_admin_token)?;
    if req.count == 0 || req.count > MAX_BATCH_TOKENS {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("count must be 1..={MAX_BATCH_TOKENS}"),
        ));
    }
    let tenant = TenantId(req.tenant);
    // #145: an idempotency key makes a retried mint return the same tokens instead of duplicating.
    // A key reused with a *different* tenant/count is a 409 Conflict (idem-conflict), not a silent
    // replay of the original set — so a client key-reuse bug surfaces loudly instead of mis-provisioning.
    let tokens = match req.idempotency_key.as_deref() {
        Some(key) => st
            .store
            .issue_join_tokens_idempotent(
                &tenant,
                req.count,
                key,
                SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            )
            .map_err(|e| {
                let code = match e {
                    IssueBatchError::Conflict => StatusCode::CONFLICT,
                    IssueBatchError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
                };
                (code, e.to_string())
            })?,
        None => st
            .store
            .issue_join_tokens(&tenant, req.count)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
    };
    Ok(Json(IssueBatchResp {
        tokens: tokens.iter().map(|t| hex_encode(&t.0)).collect(),
    }))
}

#[derive(Deserialize)]
struct RedeemReq {
    token: String,
    agent: String,
    pubkey: String,
    /// Hex ed25519 signature over the join token by `pubkey` (#88 SEC88c).
    proof: String,
}
#[derive(Serialize, Deserialize)]
struct RedeemResp {
    tenant: String,
}

async fn redeem(
    State(st): State<EnrollState>,
    Json(req): Json<RedeemReq>,
) -> Result<Json<RedeemResp>, (StatusCode, String)> {
    let token =
        hex_decode_32(&req.token).ok_or((StatusCode::BAD_REQUEST, "malformed token".to_string()))?;
    let pubkey = hex_decode_32(&req.pubkey)
        .ok_or((StatusCode::BAD_REQUEST, "malformed pubkey".to_string()))?;
    let proof = hex_decode_64(&req.proof)
        .ok_or((StatusCode::BAD_REQUEST, "malformed proof".to_string()))?;
    let tenant = st
        .store
        .redeem_with_proof(&JoinToken(token), &AgentId(req.agent), pubkey, &proof)
        .map_err(|e| {
            let code = match &e {
                RedeemError::Enroll(EnrollError::TokenAlreadyUsed) => StatusCode::CONFLICT,
                RedeemError::Enroll(EnrollError::UnknownToken) => StatusCode::NOT_FOUND,
                RedeemError::Enroll(EnrollError::BadProof) => StatusCode::FORBIDDEN,
                RedeemError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (code, e.to_string())
        })?;
    Ok(Json(RedeemResp { tenant: tenant.0 }))
}

/// Build the persistent registry router: `POST /registry/register`,
/// `GET /registry/resolve/:token`, backed by a durable [`SqliteRegistry`].
pub fn registry_router_sqlite(store: Arc<SqliteRegistry>) -> Router {
    Router::new()
        .route("/registry/register", post(register_tunnel))
        .route("/registry/resolve/:token", get(resolve_tunnel))
        .with_state(store)
}

/// Build the **production** registry router with the write route (`POST
/// /registry/register`) optionally gated behind the shared admin token (#87
/// SEC87b-auth-registry), while the read route (`GET /registry/resolve/:token`)
/// stays open (the rendezvous lookup a client needs, no durable write).
///
/// `/registry/register` maps a client-supplied routing token → `(tenant, agent)`
/// in the durable registry; left open it is an unauthenticated durable-SQLite
/// writer surface (#87). No live customer path uses it — the agent registers its
/// tunnel over the **QUIC data path to the edge** (`register_tunnel_stream`), not
/// this HTTP route; the only HTTP caller is the operator selftest (`cp_selftest`),
/// which now presents the admin token. So — like `/enroll/issue` and the billing
/// writers — it's gated with the same `CT_CP_EDGE_ADMIN_TOKEN`. When `admin_token`
/// is `None` it stays open (dev/back-compat).
pub fn registry_router_sqlite_gated(store: Arc<SqliteRegistry>, admin_token: Option<[u8; 32]>) -> Router {
    let resolve = Router::new()
        .route("/registry/resolve/:token", get(resolve_tunnel))
        .with_state(store.clone());
    let register = Router::new()
        .route("/registry/register", post(register_tunnel))
        .with_state(store);
    resolve.merge(admin_gated(register, admin_token))
}

/// Default TTL (seconds) for a minted bootstrap token (#90/#97 SEC90b-wire): short,
/// because it exists only to be redeemed once, promptly, by the install one-liner.
const BOOTSTRAP_TTL_SECS: u64 = 600;

/// Shared state for the bootstrap-token exchange routes.
#[derive(Clone)]
struct BootstrapState {
    store: Arc<SqliteBootstrap>,
}

/// Build the **bootstrap-token exchange** router (#90/#97 SEC90b-wire): the wire
/// half of the exchange whose durable core is [`SqliteBootstrap`]. It lets the
/// install/channel one-liner carry only a short-lived, single-use opaque token
/// instead of the real secrets (which today are embedded in the shown command and so
/// land in shell history / `ps`).
///
/// * `POST /bootstrap/mint` `{secret, ttl_secs?}` → `{token}` — **admin-gated** (minting
///   hands off control of a secret bundle; same `CT_CP_EDGE_ADMIN_TOKEN` as the other
///   operator writers). The operator/portal mints when generating an install one-liner.
/// * `POST /bootstrap/redeem` `{token}` → `{secret}` — **public**: possession of the
///   short-lived single-use token is the authorization, and it is handed off over TLS
///   in the response body (never on the command line). `404` unknown, `409` already
///   used, `410` expired.
pub fn bootstrap_router(store: Arc<SqliteBootstrap>, admin_token: Option<[u8; 32]>) -> Router {
    let redeem = Router::new()
        .route("/bootstrap/redeem", post(bootstrap_redeem))
        .with_state(BootstrapState { store: store.clone() });
    let mint = Router::new()
        .route("/bootstrap/mint", post(bootstrap_mint))
        .with_state(BootstrapState { store });
    redeem.merge(admin_gated(mint, admin_token))
}

/// Seconds since the Unix epoch (wall clock), for the bootstrap-token TTL.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Deserialize)]
struct BootstrapMintReq {
    secret: String,
    ttl_secs: Option<u64>,
}
#[derive(Serialize, Deserialize)]
struct BootstrapMintResp {
    token: String,
}

async fn bootstrap_mint(
    State(st): State<BootstrapState>,
    Json(req): Json<BootstrapMintReq>,
) -> Result<Json<BootstrapMintResp>, (StatusCode, String)> {
    let ttl = req.ttl_secs.unwrap_or(BOOTSTRAP_TTL_SECS);
    let token = st
        .store
        .mint(&req.secret, ttl, now_secs())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(BootstrapMintResp {
        token: hex_encode(&token),
    }))
}

#[derive(Deserialize)]
struct BootstrapRedeemReq {
    token: String,
}
#[derive(Serialize, Deserialize)]
struct BootstrapRedeemResp {
    secret: String,
}

async fn bootstrap_redeem(
    State(st): State<BootstrapState>,
    Json(req): Json<BootstrapRedeemReq>,
) -> Result<Json<BootstrapRedeemResp>, (StatusCode, String)> {
    let token = hex_decode_32(&req.token)
        .ok_or((StatusCode::BAD_REQUEST, "malformed token".to_string()))?;
    match st.store.redeem(&token, now_secs()) {
        Ok(secret) => Ok(Json(BootstrapRedeemResp { secret })),
        Err(BootstrapError::UnknownToken) => {
            Err((StatusCode::NOT_FOUND, "unknown bootstrap token".to_string()))
        }
        Err(BootstrapError::AlreadyUsed) => {
            Err((StatusCode::CONFLICT, "bootstrap token already used".to_string()))
        }
        Err(BootstrapError::Expired) => {
            Err((StatusCode::GONE, "bootstrap token expired".to_string()))
        }
        Err(BootstrapError::Db(e)) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

#[derive(Deserialize)]
struct RegisterReq {
    token: String,
    tenant: String,
    agent: String,
}

async fn register_tunnel(
    State(store): State<Arc<SqliteRegistry>>,
    Json(req): Json<RegisterReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let token =
        hex_decode_32(&req.token).ok_or((StatusCode::BAD_REQUEST, "malformed token".to_string()))?;
    store
        .register(
            &RoutingToken(token),
            &TunnelInfo {
                tenant: TenantId(req.tenant),
                agent: AgentId(req.agent),
            },
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

#[derive(Serialize, Deserialize)]
struct ResolveResp {
    tenant: String,
    agent: String,
}

async fn resolve_tunnel(
    State(store): State<Arc<SqliteRegistry>>,
    Path(token_hex): Path<String>,
) -> Result<Json<ResolveResp>, StatusCode> {
    let token = hex_decode_32(&token_hex).ok_or(StatusCode::BAD_REQUEST)?;
    let info = store
        .lookup(&RoutingToken(token))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(ResolveResp {
        tenant: info.tenant.0,
        agent: info.agent.0,
    }))
}

/// Build the persistent billing router (accounts / payment / credit-gated
/// issuance) backed by a durable [`SqliteLedger`].
pub fn billing_router_sqlite(store: Arc<SqliteLedger>) -> Router {
    Router::new()
        .route("/accounts/open", post(open_account))
        .route("/payment/intent", post(create_payment_intent))
        .route("/payment/confirm", post(confirm_payment))
        .route("/billing/issue", post(buy_token))
        .with_state(store)
}

/// Shared token for a machine/operator-writer admin gate (#87 SEC87b-auth): the
/// `x-ct-admin-token` a caller must present to reach a gated durable-writer route.
#[derive(Clone)]
struct AdminGate {
    token: [u8; 32],
}

/// Reject a request that does not carry the correct `x-ct-admin-token`
/// (constant-time compare). Applied as a layer only when the CP has an admin
/// token configured; shared by the billing and registry writer gates.
async fn require_admin_token(
    State(state): State<AdminGate>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Response {
    if admin_token_ok(&headers, &state.token) {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            "this control-plane write requires the admin token\n",
        )
            .into_response()
    }
}

/// #186: apply the admin-token [`require_admin_token`] layer to `router` **iff** a token is configured
/// — else leave it open (dev/back-compat). Collapses the `match admin_token { Some => .layer(..), None
/// => r }` that was repeated at every gated writer router (registry, bootstrap-mint, billing writers).
fn admin_gated(router: Router, admin_token: Option<[u8; 32]>) -> Router {
    match admin_token {
        Some(token) => router.layer(from_fn_with_state(AdminGate { token }, require_admin_token)),
        None => router,
    }
}

/// Build the **production** billing-writer router — `/accounts/open`,
/// `/payment/intent`, `/billing/issue` — optionally gated behind the shared admin
/// token (#87 SEC87b-auth-billing).
///
/// These three routes take a **client-supplied** account (or mint an anonymous one),
/// so left open they are an unauthenticated durable-SQLite writer surface (#87). The
/// real customer top-up path is **not** here: it is the session-authenticated portal
/// (`POST /portal/account/credits`, which derives the account from the verified
/// subject and calls the ledger in-process). So — exactly like `/enroll/issue` — these
/// HTTP routes are a machine/operator surface, gated with the same
/// `CT_CP_EDGE_ADMIN_TOKEN` the edge/operator already hold rather than an OIDC user
/// bearer. When `admin_token` is `None` they stay open (dev/back-compat). `/payment/webhook`
/// (provider-signature-authed) and the customer `/me/*` / portal paths are unaffected.
pub fn billing_writers_gated(store: Arc<SqliteLedger>, admin_token: Option<[u8; 32]>) -> Router {
    let writers = Router::new()
        .route("/accounts/open", post(open_account))
        .route("/payment/intent", post(create_payment_intent))
        .route("/billing/issue", post(buy_token))
        .with_state(store);
    admin_gated(writers, admin_token)
}

#[derive(Serialize, Deserialize)]
struct AccountResp {
    account: String,
}

async fn open_account(
    State(store): State<Arc<SqliteLedger>>,
) -> Result<Json<AccountResp>, (StatusCode, String)> {
    let account = store
        .open_account()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AccountResp {
        account: hex_encode(&account.0),
    }))
}

#[derive(Deserialize)]
struct IntentReq {
    account: String,
    credits: u64,
}
#[derive(Serialize, Deserialize)]
struct IntentResp {
    payment: String,
}

async fn create_payment_intent(
    State(store): State<Arc<SqliteLedger>>,
    Json(req): Json<IntentReq>,
) -> Result<Json<IntentResp>, (StatusCode, String)> {
    let account = hex_decode_32(&req.account)
        .ok_or((StatusCode::BAD_REQUEST, "malformed account".to_string()))?;
    let id = store
        .create_intent(&AccountId(account), req.credits)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(IntentResp {
        payment: hex_encode(&id.0),
    }))
}

#[derive(Deserialize)]
struct ConfirmReq {
    payment: String,
}
#[derive(Serialize, Deserialize)]
struct BalanceResp {
    balance: u64,
}

async fn confirm_payment(
    State(store): State<Arc<SqliteLedger>>,
    Json(req): Json<ConfirmReq>,
) -> Result<Json<BalanceResp>, (StatusCode, String)> {
    let payment = hex_decode_32(&req.payment)
        .ok_or((StatusCode::BAD_REQUEST, "malformed payment".to_string()))?;
    let balance = store.confirm_payment(&PaymentId(payment)).map_err(|e| {
        let code = match &e {
            PaymentOpError::Payment(PaymentError::AlreadyConfirmed) => StatusCode::CONFLICT,
            PaymentOpError::Payment(_) => StatusCode::NOT_FOUND,
            PaymentOpError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (code, e.to_string())
    })?;
    Ok(Json(BalanceResp { balance }))
}

#[derive(Deserialize)]
struct BuyReq {
    account: String,
    price: u64,
    /// #272: optional client-supplied idempotency key (64-hex, like every other token
    /// in this API). A caller retrying after a lost response passes the SAME key to
    /// get back the already-minted token instead of being debited again. Absent ->
    /// unchanged legacy behavior (no idempotency protection), so existing callers
    /// keep working exactly as before.
    idempotency_key: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct TokenResp {
    token: String,
}

async fn buy_token(
    State(store): State<Arc<SqliteLedger>>,
    Json(req): Json<BuyReq>,
) -> Result<Json<TokenResp>, (StatusCode, String)> {
    let account = hex_decode_32(&req.account)
        .ok_or((StatusCode::BAD_REQUEST, "malformed account".to_string()))?;
    // #87 SEC87a: a token costs at least TOKEN_PRICE — reject an underpayment
    // (notably price:0) before touching the ledger, so it can't mint a free token.
    if !crate::billing::issuance_price_ok(req.price) {
        return Err((
            StatusCode::PAYMENT_REQUIRED,
            format!("a routing token costs at least {} credit(s)", crate::billing::TOKEN_PRICE),
        ));
    }
    let idempotency_key = match req.idempotency_key.as_deref() {
        Some(s) => Some(
            hex_decode_32(s).ok_or((StatusCode::BAD_REQUEST, "malformed idempotency_key".to_string()))?,
        ),
        None => None,
    };

    // #272: a caller retrying after a lost response (crash, timeout, network drop)
    // would otherwise be debited a second time for a token it already paid for. With
    // a key, check for a prior issuance FIRST -- if found, hand back the same token,
    // no new debit.
    if let Some(key) = &idempotency_key {
        if let Some(existing) = store
            .issuance_for_key(key)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        {
            return Ok(Json(TokenResp { token: hex_encode(&existing) }));
        }
    }

    let mut token = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token);

    match &idempotency_key {
        // Debit and durably record the issuance atomically -- a crash between the two
        // can't happen, so a retry with this same key always finds a consistent state.
        Some(key) => {
            store
                .debit_and_record_issuance(&AccountId(account), req.price, key, &token, now_secs())
                .map_err(|e| {
                    let code = match &e {
                        LedgerOpError::Ledger(LedgerError::InsufficientCredit { .. }) => {
                            StatusCode::PAYMENT_REQUIRED
                        }
                        LedgerOpError::Ledger(LedgerError::UnknownAccount) => StatusCode::NOT_FOUND,
                        LedgerOpError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
                    };
                    (code, e.to_string())
                })?;
        }
        // No key supplied: unchanged legacy behavior, no idempotency protection.
        None => {
            store.debit(&AccountId(account), req.price).map_err(|e| {
                let code = match &e {
                    LedgerOpError::Ledger(LedgerError::InsufficientCredit { .. }) => {
                        StatusCode::PAYMENT_REQUIRED
                    }
                    LedgerOpError::Ledger(LedgerError::UnknownAccount) => StatusCode::NOT_FOUND,
                    LedgerOpError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
                };
                (code, e.to_string())
            })?;
        }
    }

    Ok(Json(TokenResp {
        token: hex_encode(&token),
    }))
}

/// Shared state for the payment webhook: the durable ledger and the provider
/// webhook signature verifier.
#[derive(Clone)]
pub struct WebhookState {
    ledger: Arc<SqliteLedger>,
    verifier: Arc<WebhookVerifier>,
}

/// Build the payment **webhook** router (M24.2): `POST /payment/webhook`.
///
/// This is the *real* payment path — a credit is applied only for an event whose
/// signature verifies against the provider's shared secret, replacing the M18
/// stub where any caller could confirm a payment. The provider echoes our
/// `PaymentId` (attached as intent metadata) in the event body, so no separate
/// intent→payment mapping is needed. Delivery is idempotent (a replayed event
/// acks `200` without double-crediting).
///
/// The provider signs `"<timestamp>.<raw-body>"`; the timestamp and hex
/// signature arrive in the `X-CT-Webhook-Timestamp` / `X-CT-Webhook-Signature`
/// headers.
pub fn payment_webhook_router(
    ledger: Arc<SqliteLedger>,
    verifier: Arc<WebhookVerifier>,
) -> Router {
    Router::new()
        .route("/payment/webhook", post(payment_webhook))
        .with_state(WebhookState { ledger, verifier })
}

#[derive(Deserialize)]
struct WebhookEvent {
    /// Hex-encoded `PaymentId` we attached to the provider intent as metadata.
    payment: String,
    /// Provider event status; we credit only on `"succeeded"`.
    status: String,
}

async fn payment_webhook(
    State(state): State<WebhookState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, (StatusCode, String)> {
    let timestamp = headers
        .get("x-ct-webhook-timestamp")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or((
            StatusCode::BAD_REQUEST,
            "missing or invalid X-CT-Webhook-Timestamp".to_string(),
        ))?;
    let signature = headers
        .get("x-ct-webhook-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::BAD_REQUEST,
            "missing X-CT-Webhook-Signature".to_string(),
        ))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Authenticate the event against the provider secret before trusting it.
    state
        .verifier
        .verify(timestamp, &body, signature, now)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;

    let event: WebhookEvent = serde_json::from_slice(&body)
        .map_err(|_| (StatusCode::BAD_REQUEST, "malformed event body".to_string()))?;
    // Acknowledge non-terminal events without crediting.
    if event.status != "succeeded" {
        return Ok(StatusCode::OK);
    }
    let payment = hex_decode_32(&event.payment)
        .ok_or((StatusCode::BAD_REQUEST, "malformed payment id".to_string()))?;
    match state.ledger.confirm_payment(&PaymentId(payment)) {
        // Fresh confirmation credited the account.
        Ok(_) => Ok(StatusCode::OK),
        // Provider retried a delivered event — idempotent, do not double-credit.
        Err(PaymentOpError::Payment(PaymentError::AlreadyConfirmed)) => Ok(StatusCode::OK),
        Err(PaymentOpError::Payment(PaymentError::UnknownPayment)) => {
            Err((StatusCode::NOT_FOUND, "unknown payment".to_string()))
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// Accepted age (seconds, either direction) of a payment webhook timestamp (M24.3).
const WEBHOOK_TOLERANCE_SECS: u64 = 300;

/// Per-subject `/me/issue` cap per window on the production authed router (M26.1).
const AUTHED_ISSUES_PER_WINDOW: u32 = 60;

/// Fixed window (seconds) for the per-subject issuance rate limit (M23.1).
const ISSUE_WINDOW_SECS: u64 = 60;

/// Shared state for the authenticated billing endpoints: the durable ledger, the
/// OIDC verifier, and a per-subject issuance rate limiter (M23.1).
#[derive(Clone)]
pub struct AuthedState {
    ledger: Arc<SqliteLedger>,
    verifier: OidcVerifierHandle,
    /// Caps `/me/issue` requests per authenticated subject per fixed window, so
    /// a single account cannot exhaust the control plane with issuance calls.
    issue_limiter: Arc<Mutex<KeyedRateLimiter<String>>>,
}

/// Build the **authenticated** billing router (M19.3): the account is derived
/// from the verified `Authorization: Bearer` token's subject rather than passed
/// in the request, so only an authenticated (Keycloak) user can act, and always
/// on their own account.
///
/// * `GET /me/account` → `{account, balance, subject}` for the authenticated subject
/// * `POST /me/issue` `{price}` → `{token}` (402 on insufficient credit, 429 over
///   the per-subject rate limit of `max_issues_per_window` per fixed window)
pub fn authed_billing_router(
    ledger: Arc<SqliteLedger>,
    verifier: OidcVerifierHandle,
    max_issues_per_window: u32,
) -> Router {
    Router::new()
        .route("/me/account", get(me_account))
        .route("/me/issue", post(me_issue))
        .with_state(AuthedState {
            ledger,
            verifier,
            issue_limiter: Arc::new(Mutex::new(KeyedRateLimiter::new(max_issues_per_window))),
        })
}

/// Shared state for the authenticated Agent-Fabric channel registry (#81 SEC81c-b):
/// the durable channel store + the OIDC verifier. The channel `owner` is always the
/// verified token subject, never a request field, so a caller can only register or
/// manage channels they own.
#[derive(Clone)]
pub struct AuthedChannelState {
    channels: Arc<SqliteChannelStore>,
    verifier: OidcVerifierHandle,
}

/// Build the **authenticated** Agent-Fabric channel-registry router (#81 SEC81c-b):
/// owner-scoped channel registration + membership management, backed by
/// [`SqliteChannelStore`]. Like `/me/*`, mounted only when an OIDC verifier is
/// configured; the `owner` is the verified subject, so this adds **no** unauthenticated
/// DB-writing surface (cf. #87). It provides the operator-key + membership records that
/// the edge channel broker's `authorize` lookup (SEC81c-a `authorize_holder`) reads.
///
/// * `POST /me/channels` `{channel, operator_pubkey}` → register (owner = subject); `403` if
///   the channel is already owned by another subject
/// * `POST /me/channels/:channel/members` `{holder}` → add a member (owner-scoped)
/// * `POST /me/channels/:channel/members/:holder/remove` → remove a member (revocation)
/// * `POST /me/channels/:channel/allowlist` `{email}` → allow-list an email for
///   self-service claiming (#248-follow, owner-scoped)
/// * `GET /me/channels/:channel/allowlist` → list allow-listed emails (owner-scoped)
/// * `POST /me/channels/:channel/allowlist/:email/remove` → de-list an email (owner-scoped)
pub fn authed_channel_router(
    channels: Arc<SqliteChannelStore>,
    verifier: OidcVerifierHandle,
) -> Router {
    Router::new()
        .route("/me/channels", post(channel_register))
        .route("/me/channels/:channel/members", post(channel_add_member))
        .route(
            "/me/channels/:channel/members/:holder/remove",
            post(channel_remove_member),
        )
        .route(
            "/me/channels/:channel/allowlist",
            post(channel_allowlist_add).get(channel_allowlist_list),
        )
        .route(
            "/me/channels/:channel/allowlist/:email/remove",
            post(channel_allowlist_remove),
        )
        .with_state(AuthedChannelState { channels, verifier })
}

/// Shared state for the authenticated declarative **network** API (#102-rest): the
/// durable [`SqliteNetworkStore`] + the OIDC verifier. Networks are keyed by the
/// verified subject, so a caller only ever reads/writes its own (owner isolation).
#[derive(Clone)]
pub struct AuthedNetworkState {
    networks: Arc<SqliteNetworkStore>,
    verifier: OidcVerifierHandle,
}

/// Build the **authenticated** declarative-network router (#102-rest): the REST surface
/// the SDN-style control plane exposes to a network owner, following the `/me/*`
/// OIDC-bearer, subject-scoped conventions (the `owner` is always the verified subject,
/// never a request field — no unauthenticated write surface, cf. #87).
///
/// * `PUT /me/networks/:id` `{Network}` → persist the caller's declared network (desired
///   state); idempotent.
/// * `GET /me/networks/:id` → the caller's network, or `404`.
/// * `GET /me/networks/:id/plan` → `{desired: [[a,b],…]}`, the channel set the policy
///   compiles to ([`Network::desired_channels`]) — what the controller would establish.
pub fn authed_network_router(
    networks: Arc<SqliteNetworkStore>,
    verifier: OidcVerifierHandle,
) -> Router {
    Router::new()
        .route("/me/networks/:id", put(network_put).get(network_get))
        .route("/me/networks/:id/plan", get(network_plan))
        .with_state(AuthedNetworkState { networks, verifier })
}

async fn network_put(
    State(state): State<AuthedNetworkState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(network): Json<ct_common::policy::Network>,
) -> Result<StatusCode, (StatusCode, String)> {
    let owner = subject_of(&state.verifier, &headers)?;
    // #275: reject a duplicate-agent-id declaration here, at the REST boundary --
    // before it's ever stored and silently produces a partitioned overlay plan or
    // a wrong explain() resolution with no diagnostic pointing at the real cause.
    network.validate().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    state
        .networks
        .put(&owner, &id, &network)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

async fn network_get(
    State(state): State<AuthedNetworkState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ct_common::policy::Network>, (StatusCode, String)> {
    let owner = subject_of(&state.verifier, &headers)?;
    let network = state
        .networks
        .get(&owner, &id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "no such network".to_string()))?;
    Ok(Json(network))
}

#[derive(Serialize, Deserialize)]
struct NetworkPlanResp {
    /// The agent-pairs the policy permits a channel between — the desired connectivity.
    desired: Vec<ct_common::policy::Pair>,
}

async fn network_plan(
    State(state): State<AuthedNetworkState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<NetworkPlanResp>, (StatusCode, String)> {
    let owner = subject_of(&state.verifier, &headers)?;
    let network = state
        .networks
        .get(&owner, &id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "no such network".to_string()))?;
    let desired = network.desired_channels().into_iter().collect();
    Ok(Json(NetworkPlanResp { desired }))
}

/// Shared state for the authenticated **Topology Editor** API (#107-rest): the durable
/// [`SqliteTopologyStore`] + the OIDC verifier. Every topology is owned by the verified
/// subject, so a caller only composes its own overlays.
#[derive(Clone)]
pub struct AuthedTopologyState {
    topologies: Arc<SqliteTopologyStore>,
    verifier: OidcVerifierHandle,
    /// #237-follow: the portal session-cookie signing key, so the Topology Editor's own
    /// client-side JS (which authenticates via the ambient portal session cookie, not a
    /// bearer token it has no way to hold) can actually drive these endpoints. See
    /// [`subject_of_topology`]'s doc comment for why accepting either is not a
    /// scope-widening.
    session_key: Arc<[u8]>,
    /// #107-complex: the channel store, so an edge's explicit channel association
    /// (`topology_edge_channel`) can validate the caller actually owns or is a member of
    /// the channel it's attaching — "account related channels or shared to account
    /// channels", never an arbitrary id with no relationship to the caller.
    channels: Arc<SqliteChannelStore>,
}

/// Build the **authenticated** Topology Editor router (#107-rest): compose an overlay by
/// creating a topology, assigning agents into it (exclusive membership), and wiring
/// edges — the REST half of the "click-together" editor, following the `/me/*`
/// OIDC-bearer, subject-scoped convention (owner = verified subject, never a request
/// field, so no unauthenticated write surface, cf. #87).
///
/// * `POST /me/topologies` → create (server-generated `id` + `net_uuid`) → `{id, net_uuid}`
/// * `GET  /me/topologies` → the caller's topologies
/// * `GET  /me/topologies/:id` → a composite view `{id, net_uuid, agents, edges}`
/// * `POST /me/topologies/:id/agents` `{agent}` → assign (exclusive; `409` if already in a topology)
/// * `POST /me/topologies/:id/edges` `{a, b}` → wire an undirected edge
pub fn authed_topology_router(
    topologies: Arc<SqliteTopologyStore>,
    verifier: OidcVerifierHandle,
    session_key: Arc<[u8]>,
    channels: Arc<SqliteChannelStore>,
) -> Router {
    Router::new()
        .route("/me/topologies", post(topology_create).get(topology_list))
        .route("/me/topologies/shared", get(topology_shared_list))
        .route("/me/topologies/:id", get(topology_view))
        .route("/me/topologies/:id/mode", axum::routing::put(topology_set_mode))
        .route("/me/topologies/:id/operator", axum::routing::put(topology_set_operator))
        .route("/me/topologies/:id/suggest", post(topology_suggest))
        .route("/me/topologies/:id/editor", get(topology_editor))
        .route("/me/topologies/:id/agents", post(topology_assign))
        .route("/me/topologies/:id/edges", post(topology_add_edge).delete(topology_remove_edge))
        .route("/me/topologies/:id/edges/channel", axum::routing::put(topology_edge_channel))
        .route("/me/topologies/:id/share", post(topology_share_add))
        .route("/me/topologies/:id/share/:email/remove", post(topology_share_remove))
        .with_state(AuthedTopologyState { topologies, verifier, session_key, channels })
}

/// State for the searchable agent directory (#144 ②): the store + the shared
/// machine-writer admin token that gates self-registration (#161).
#[derive(Clone)]
struct AgentDirectoryState {
    directory: Arc<SqliteAgentDirectory>,
    admin_token: Option<[u8; 32]>,
}

/// #144 ②: the **searchable agent-directory** REST.
///
/// * `POST /registry/agents` `{holder_pubkey, card_url, role_tags?, skill_ids?}` — an agent
///   self-registers (upsert) its published card URL + advertised facets. Gated by the shared
///   **machine-writer admin token** (`CT_CP_EDGE_ADMIN_TOKEN`, #161/#87 SEC87b-auth) — the same
///   gate as `/enroll/issue`, `/registry/register` and `/bootstrap/mint`, NOT a *human* OIDC
///   bearer: an autonomous agent has no browser-interactive login (the `ct-portal` client has
///   direct-access + service-accounts disabled), so requiring a user bearer made the directory
///   un-writable by the very agents it exists to list (#161). Trust is NOT the registry: a
///   searcher fetches `card_url` (`/.well-known/agent-card.json`) and re-checks the holder
///   signature, which is the actual trust anchor; the admin token is only the anti-anonymous-spam
///   gate. `None` → open (dev/back-compat).
/// * `GET /registry/agents?role=&skill=` — **public** search by exact role/skill token → the
///   matching entries (each = holder key + card URL + facets to fetch & verify).
pub fn agent_directory_router(
    directory: Arc<SqliteAgentDirectory>,
    admin_token: Option<[u8; 32]>,
) -> Router {
    Router::new()
        .route("/registry/agents", post(agent_register).get(agent_search))
        .with_state(AgentDirectoryState { directory, admin_token })
}

#[derive(Deserialize)]
struct RegisterAgentReq {
    holder_pubkey: String,
    card_url: String,
    #[serde(default)]
    role_tags: Vec<String>,
    #[serde(default)]
    skill_ids: Vec<String>,
}

async fn agent_register(
    State(state): State<AgentDirectoryState>,
    headers: HeaderMap,
    Json(req): Json<RegisterAgentReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    // #161/#87 SEC87b-auth: self-registration is a machine-to-machine write, gated by the shared
    // edge/operator admin token (the same `CT_CP_EDGE_ADMIN_TOKEN` as every other machine-writer),
    // NOT a human OIDC bearer — an autonomous agent has no interactive-login path to obtain one.
    // The card's holder signature (re-checked when a peer fetches `card_url`) is the actual trust
    // anchor; this gate is only the anti-anonymous-spam control. `None` → open (dev/back-compat).
    require_agent_registry_admin(&headers, &state.admin_token)?;
    // SSRF defence-in-depth (same class as #137): only accept https card URLs. The authoritative
    // internal/link-local/metadata-range block belongs at the (not-yet-existent) fetcher; rejecting
    // a non-https `card_url` at registration closes the door before any fetcher lands.
    if !req.card_url.starts_with("https://") {
        return Err((StatusCode::BAD_REQUEST, "card_url must be an https:// URL".to_string()));
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    state
        .directory
        .register(&req.holder_pubkey, &req.card_url, &req.role_tags, &req.skill_ids, now)
        .map_err(|e| match e {
            // A newline-bearing facet token is a client error (token-injection), not a 500.
            AgentDirectoryError::InvalidToken(_) => (StatusCode::BAD_REQUEST, e.to_string()),
            AgentDirectoryError::Db(_) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        })?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct AgentSearchQuery {
    role: Option<String>,
    skill: Option<String>,
}

async fn agent_search(
    State(state): State<AgentDirectoryState>,
    Query(q): Query<AgentSearchQuery>,
) -> Result<Json<Vec<AgentDirectoryEntry>>, (StatusCode, String)> {
    let entries = state
        .directory
        .search(q.role.as_deref(), q.skill.as_deref())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(entries))
}

/// State for the workflow-pipeline registry (#174 B): the store + the machine-writer admin token.
#[derive(Clone)]
struct PipelineRegistryState {
    registry: Arc<SqlitePipelineRegistry>,
    admin_token: Option<[u8; 32]>,
}

/// #174 B: the **workflow-pipeline registry** REST — where a designer publishes a `PipelineSpec`
/// so scanning agents can discover workflows to join (the pipeline analogue of `/registry/agents`).
///
/// * `POST /registry/pipelines` `{owner?, spec}` — publish (upsert) a spec. **Machine-writer
///   admin-token-gated** (same `CT_CP_EDGE_ADMIN_TOKEN` as `/registry/agents`, #161): a pipeline
///   designer is an operator-class actor, not a human OIDC subject. Owner-scoped in the store —
///   a `409` if the id is owned by someone else. `None` admin token → open (dev/back-compat).
/// * `GET /registry/pipelines` — **public** list of `[{id, owner}]` (discovery).
/// * `GET /registry/pipelines/:id` — **public** fetch of the full published `PipelineSpec`.
pub fn pipeline_registry_router(
    registry: Arc<SqlitePipelineRegistry>,
    admin_token: Option<[u8; 32]>,
) -> Router {
    Router::new()
        .route("/registry/pipelines", post(pipeline_publish).get(pipeline_list))
        .route("/registry/pipelines/:id", get(pipeline_get))
        .with_state(PipelineRegistryState { registry, admin_token })
}

fn default_pipeline_owner() -> String {
    "operator".to_string()
}

#[derive(Deserialize)]
struct PublishPipelineReq {
    #[serde(default = "default_pipeline_owner")]
    owner: String,
    spec: ct_common::pipeline::PipelineSpec,
}

#[derive(Serialize)]
struct PipelineListEntry {
    id: String,
    owner: String,
}

async fn pipeline_publish(
    State(state): State<PipelineRegistryState>,
    headers: HeaderMap,
    Json(req): Json<PublishPipelineReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    // #174 B / #161 SEC87b-auth: machine-writer gate — publishing a workflow spec is an
    // operator-class write, gated by the shared admin token (not a human OIDC bearer).
    require_admin(&headers, &state.admin_token, "publishing a pipeline requires the admin token")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let published = state
        .registry
        .publish(&req.owner, &req.spec, now)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if published {
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::CONFLICT, "a pipeline with this id is owned by another owner".to_string()))
    }
}

async fn pipeline_list(
    State(state): State<PipelineRegistryState>,
) -> Result<Json<Vec<PipelineListEntry>>, (StatusCode, String)> {
    let rows = state
        .registry
        .list()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(rows.into_iter().map(|(id, owner)| PipelineListEntry { id, owner }).collect()))
}

async fn pipeline_get(
    State(state): State<PipelineRegistryState>,
    Path(id): Path<String>,
) -> Result<Json<ct_common::pipeline::PipelineSpec>, (StatusCode, String)> {
    match state.registry.get(&id).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))? {
        Some(spec) => Ok(Json(spec)),
        None => Err((StatusCode::NOT_FOUND, "no such pipeline".to_string())),
    }
}

/// Shared state for the authenticated pipeline-publish endpoint (below): the
/// pipeline store + the OIDC verifier. The owner is always the verified
/// subject, never a request field — same `/me/*` convention as
/// [`AuthedChannelState`]/[`AuthedNetworkState`].
#[derive(Clone)]
struct AuthedPipelineState {
    registry: Arc<SqlitePipelineRegistry>,
    verifier: OidcVerifierHandle,
}

/// `POST /me/pipelines` `{spec}` → publish (owner = verified subject); `403` if the id
/// is already owned by a different subject.
///
/// Publishing a pipeline was admin-token-gated only (`pipeline_publish`/`#174 B`) — fine
/// for the operator, but that token is never handed to an ordinary onboarded pipeline
/// designer (they only ever get a join token + agent token, #218/agent-onboarding.md §A),
/// so nobody but the operator could actually publish one. That directly contradicted the
/// "generic, coordination-free" self-service design already shipped for channels
/// (`/me/channels`, #214 follow-up) and joining (`ct-agent channel join-pipeline-role`) —
/// a designer could derive every role's channel id and describe how to join it, but had no
/// way to actually publish the spec that makes it discoverable. This closes that gap the
/// same way `/me/channels` did: owner = the caller's verified OIDC subject, no shared
/// secret required. The admin-gated `/registry/pipelines` stays mounted unchanged for
/// operator/back-compat use (e.g. scripted publishes without an interactive login).
pub fn authed_pipeline_router(registry: Arc<SqlitePipelineRegistry>, verifier: OidcVerifierHandle) -> Router {
    Router::new()
        .route("/me/pipelines", post(me_pipeline_publish))
        .with_state(AuthedPipelineState { registry, verifier })
}

#[derive(Deserialize)]
struct MePublishPipelineReq {
    spec: ct_common::pipeline::PipelineSpec,
}

async fn me_pipeline_publish(
    State(state): State<AuthedPipelineState>,
    headers: HeaderMap,
    Json(req): Json<MePublishPipelineReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let owner = subject_of(&state.verifier, &headers)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let published = state
        .registry
        .publish(&owner, &req.spec, now)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if published {
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::FORBIDDEN, "a pipeline with this id is owned by another subject".to_string()))
    }
}

/// State for the public edge host-authorization proxy (below).
#[derive(Clone)]
struct EdgeAuthorizeState {
    edge_admin_url: Arc<str>,
    edge_admin_token: Arc<str>,
    admin_token: Option<[u8; 32]>,
    http: reqwest::Client,
    edge_mesh: crate::edge_mesh::EdgeMeshHandle,
}

/// `POST /registry/authorize-host/:token/:host` — a public, admin-token-gated proxy
/// to the edge's own `/admin/authorize-host/:token/:host` (#23 BP4b).
///
/// Host authorization was previously reachable only two ways: the session-authed
/// portal's automatic call in `create_tunnel` (human browser login required), or
/// the edge's admin API directly — which is loopback-only on the operator's host,
/// unreachable by a remote pipeline maintainer's own agent process. That forced
/// every hostname bind through the operator relaying tokens by hand (the flow
/// `help.<zone>` and `flappy-demo.<zone>` both needed, out of band, per-hostname).
///
/// This closes that gap: a remote pipeline maintainer holding just the shared
/// `CT_CP_EDGE_ADMIN_TOKEN` (the same one `/enroll/issue`/`/registry/agents`/
/// `/registry/pipelines` already require) can now self-serve host authorization
/// over the public HTTPS control-plane, with no further per-deployment relay
/// through the operator or a GitHub issue. Mounted only when the edge admin
/// URL+token are configured (nothing to proxy to otherwise) — same fail-closed
/// posture as every other admin-gated writer here.
fn edge_authorize_host_router(
    edge_admin_url: String,
    edge_admin_token: String,
    admin_token: Option<[u8; 32]>,
    edge_mesh: crate::edge_mesh::EdgeMeshHandle,
) -> Router {
    Router::new()
        .route("/registry/authorize-host/:token/:host", post(authorize_host_proxy))
        .with_state(EdgeAuthorizeState {
            edge_admin_url: Arc::from(edge_admin_url),
            edge_admin_token: Arc::from(edge_admin_token),
            admin_token,
            // #296: a bare `reqwest::Client::new()` has no timeout, so a hanging edge
            // admin endpoint wedged this proxy's request (and its caller) forever —
            // a sibling of #112, which fixed the exact same class in portal_api.rs's
            // `create_tunnel`/`delete_tunnel` via this same 5s-timeout client, but
            // never touched this call site. Reusing it here instead of duplicating
            // the builder.
            http: crate::portal_api::edge_admin_http_client(),
            edge_mesh,
        })
}

async fn authorize_host_proxy(
    State(state): State<EdgeAuthorizeState>,
    headers: HeaderMap,
    Path((token, host)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_admin(&headers, &state.admin_token, "authorizing a hostname requires the admin token")?;
    let host = ct_common::normalize_hostname(&host)
        .ok_or((StatusCode::BAD_REQUEST, "invalid hostname".to_string()))?;
    let endpoint = format!(
        "{}/admin/authorize-host/{}/{}",
        state.edge_admin_url.trim_end_matches('/'),
        token,
        host
    );
    let resp = state
        .http
        .post(&endpoint)
        .header("x-ct-admin-token", state.edge_admin_token.as_ref())
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("edge unreachable: {e}")))?;
    if resp.status().is_success() {
        // edge_mesh Phase 0: record that this deployment's local edge now owns
        // this (token, hostname) pair -- best-effort, never blocks the caller.
        state.edge_mesh.record(&token, Some(&host));
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::BAD_GATEWAY, format!("edge returned {}", resp.status())))
    }
}

/// A random opaque id (16 bytes, hex) for a topology id / net_uuid.
fn gen_hex_id() -> String {
    let mut b = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    hex_encode(&b)
}

#[derive(Serialize, Deserialize)]
struct TopologyCreatedResp {
    id: String,
    net_uuid: String,
}

async fn topology_create(
    State(state): State<AuthedTopologyState>,
    headers: HeaderMap,
) -> Result<Json<TopologyCreatedResp>, (StatusCode, String)> {
    let owner = subject_of_topology(&state.session_key, &state.verifier, &headers)?;
    // Generate a unique (id, net_uuid); retry the negligible collision a few times.
    for _ in 0..4 {
        let id = gen_hex_id();
        let net_uuid = gen_hex_id();
        let created = state
            .topologies
            .create_topology(&owner, &id, &net_uuid)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if created {
            return Ok(Json(TopologyCreatedResp { id, net_uuid }));
        }
    }
    Err((StatusCode::INTERNAL_SERVER_ERROR, "could not allocate a unique topology id".to_string()))
}

#[derive(Serialize, Deserialize)]
struct TopologySummary {
    id: String,
    net_uuid: String,
}

async fn topology_list(
    State(state): State<AuthedTopologyState>,
    headers: HeaderMap,
) -> Result<Json<Vec<TopologySummary>>, (StatusCode, String)> {
    let owner = subject_of_topology(&state.session_key, &state.verifier, &headers)?;
    let list = state
        .topologies
        .list_topologies(&owner)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .into_iter()
        .map(|t| TopologySummary { id: t.id, net_uuid: t.net_uuid })
        .collect();
    Ok(Json(list))
}

/// An edge plus its optional explicitly-attached channel (#107-complex link info) — the
/// derived `channel_id_for_link(a, b)` always applies regardless; `channel` is only ever an
/// explicit, informational override/association a collaborator attached.
#[derive(Debug, Serialize, Deserialize)]
struct EdgeView {
    a: String,
    b: String,
    /// 64-hex channel id, if one has been explicitly attached to this edge.
    #[serde(skip_serializing_if = "Option::is_none")]
    channel: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct TopologyView {
    id: String,
    net_uuid: String,
    /// `(agent id, kind)` — kind is `"peer"` or `"super-peer"` (#107-complex).
    agents: Vec<(String, String)>,
    edges: Vec<EdgeView>,
    /// The overlay mode (#107-ui-mode): `baseline` (direct) vs `smart-route`/`shortcut`
    /// (complex-adaptive). Legacy/absent rows read back as `baseline`.
    overlay_mode: String,
    /// Whether the CALLER owns this topology (vs. viewing it as a share, #107-complex) —
    /// lets a client distinguish "my topology" from "shared with me" without a second call.
    owner: String,
}

/// Resolve `id` as a topology owned by `owner`, or a `404` (owner isolation — a topology
/// a subject doesn't own is invisible, not a `403`).
fn owned_topology(
    state: &AuthedTopologyState,
    owner: &str,
    id: &str,
) -> Result<crate::topology::Topology, (StatusCode, String)> {
    let t = state
        .topologies
        .topology(id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .filter(|t| t.owner == owner)
        .ok_or((StatusCode::NOT_FOUND, "no such topology".to_string()))?;
    Ok(t)
}

/// Resolve `id` as a topology `subject` may **view** (#107-complex): owned by them, OR
/// shared with their verified session e-mail. A topology that's neither is a `404` (owner/
/// share isolation — never a `403`, matching `owned_topology`'s existing idiom).
fn viewable_topology(
    state: &AuthedTopologyState,
    subject: &str,
    subject_email: Option<&str>,
    id: &str,
) -> Result<crate::topology::Topology, (StatusCode, String)> {
    let t = state
        .topologies
        .topology(id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "no such topology".to_string()))?;
    if t.owner == subject {
        return Ok(t);
    }
    if let Some(email) = subject_email {
        if state
            .topologies
            .is_shared_with(&t.id, email)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        {
            return Ok(t);
        }
    }
    Err((StatusCode::NOT_FOUND, "no such topology".to_string()))
}

async fn topology_view(
    State(state): State<AuthedTopologyState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<TopologyView>, (StatusCode, String)> {
    let (subject, email) = topology_actor_of(&state.session_key, &state.verifier, &headers)?;
    let t = viewable_topology(&state, &subject, email.as_deref(), &id)?;
    let agents = state
        .topologies
        .agents_with_kind(&t.id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let edges = state
        .topologies
        .edges_with_channel(&t.id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .into_iter()
        .map(|(a, b, channel)| EdgeView { a, b, channel: channel.map(|c| hex_encode(&c)) })
        .collect();
    let overlay_mode = state
        .topologies
        .overlay_mode(&t.id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .unwrap_or(ct_common::overlay::RoutingApproach::Baseline)
        .as_str()
        .to_string();
    Ok(Json(TopologyView { id: t.id, net_uuid: t.net_uuid, agents, edges, overlay_mode, owner: t.owner }))
}

/// `PUT /me/topologies/:id/mode` — set the topology's **overlay mode** (#107-ui-mode):
/// the owner's choice of *direct* (`baseline`) vs *complex-adaptive* (`smart-route`/
/// `shortcut`/`random-mesh`). Owner-scoped (`404` on non-owner). An unrecognized mode token
/// is a `400` — a topology can only ever hold a known `RoutingApproach`.
async fn topology_set_mode(
    State(state): State<AuthedTopologyState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<ModeReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let owner = subject_of_topology(&state.session_key, &state.verifier, &headers)?;
    let mode = ct_common::overlay::RoutingApproach::parse(&req.mode)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    // Owner isolation: a topology the subject doesn't own is a 404 (never a 403).
    owned_topology(&state, &owner, &id)?;
    state
        .topologies
        .set_overlay_mode(&owner, &id, mode)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct ModeReq {
    mode: String,
}

/// `GET /me/topologies/:id/editor` — the owner-scoped, self-contained **Topology
/// Editor** page (#107-ui): a modern draggable SVG node-graph of the topology's agents
/// and links. Owner-isolated exactly like [`topology_view`] (a topology the subject does
/// not own is a `404`, never a `403`). Returns HTML, not JSON.
async fn topology_editor(
    State(state): State<AuthedTopologyState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<axum::response::Html<String>, (StatusCode, String)> {
    let (subject, email) = topology_actor_of(&state.session_key, &state.verifier, &headers)?;
    let t = viewable_topology(&state, &subject, email.as_deref(), &id)?;
    let is_owner = t.owner == subject;
    let agents = state
        .topologies
        .agents_with_kind(&t.id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let edges = state
        .topologies
        .edges_with_channel(&t.id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mode = state
        .topologies
        .overlay_mode(&t.id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .unwrap_or(ct_common::overlay::RoutingApproach::Baseline);
    // #107-complex: the share list is only ever fetched (and rendered) for the owner --
    // shares_for is itself owner-scoped, so a non-owner viewer gets an empty Vec here
    // regardless, matching render_topology_editor's own is_owner-gated section.
    let shares = state
        .topologies
        .shares_for(&t.owner, &t.id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(axum::response::Html(render_topology_editor(&t, &agents, &edges, mode.as_str(), is_owner, &shares)))
}

/// A caller-supplied candidate link + its measured latency cost, the input to the overlay
/// suggestion (#107-ui-suggest). Costs will later come from live probes via
/// `ct_common::overlay::link_cost_from_probes`; the endpoint stays transport-agnostic.
#[derive(Deserialize)]
struct SuggestLink {
    a: String,
    b: String,
    cost: u64,
}

#[derive(Deserialize)]
struct SuggestReq {
    #[serde(default)]
    links: Vec<SuggestLink>,
    #[serde(default)]
    shortcut_budget: usize,
}

#[derive(Serialize, Deserialize)]
struct SuggestResp {
    /// The topology's overlay mode the suggestion was computed under.
    mode: String,
    /// The suggested overlay links (canonical `(a, b)`).
    links: Vec<(String, String)>,
    total_cost: u64,
    connected: bool,
}

/// The suggest endpoint's size caps (#113 — the optimizer must never wedge the control
/// plane): `add_shortcuts` is O(budget·n³), so both the agent count and the shortcut budget
/// are bounded before any optimization work.
const MAX_SUGGEST_AGENTS: usize = 64;
const MAX_SUGGEST_BUDGET: usize = 16;

/// `POST /me/topologies/:id/suggest {links:[{a,b,cost}], shortcut_budget}` — surface the
/// **adaptive overlay optimizer** (#107-ui-suggest): compute the best-physical-usage overlay
/// over the topology's agents from the caller-supplied candidate link costs, respecting the
/// topology's [`overlay mode`](topology_set_mode). *Direct* (`Baseline`) has no overlay to
/// suggest → `409`; a complex-adaptive mode returns the minimum-latency spanning tree
/// (`SmartRoute`), plus capped shortcut edges when the mode is `Shortcut`. Owner-scoped
/// (`404`); size-capped (`400`) so it can't wedge the control plane.
async fn topology_suggest(
    State(state): State<AuthedTopologyState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<SuggestReq>,
) -> Result<Json<SuggestResp>, (StatusCode, String)> {
    use ct_common::overlay::RoutingApproach;
    let owner = subject_of_topology(&state.session_key, &state.verifier, &headers)?;
    let t = owned_topology(&state, &owner, &id)?;
    let mode = state
        .topologies
        .overlay_mode(&t.id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .unwrap_or(RoutingApproach::Baseline);
    // Direct mode: the overlay is relay/direct only — there is nothing to optimize.
    if mode == RoutingApproach::Baseline {
        return Err((
            StatusCode::CONFLICT,
            "topology is in direct mode; switch to a complex overlay mode to compute a suggestion".to_string(),
        ));
    }
    // Size caps before any O(budget·n³) work (#113).
    if req.shortcut_budget > MAX_SUGGEST_BUDGET {
        return Err((StatusCode::BAD_REQUEST, format!("shortcut_budget exceeds the cap ({MAX_SUGGEST_BUDGET})")));
    }
    let agents = state
        .topologies
        .agents_in(&t.id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if agents.len() > MAX_SUGGEST_AGENTS {
        return Err((StatusCode::BAD_REQUEST, format!("topology exceeds the suggest agent cap ({MAX_SUGGEST_AGENTS})")));
    }
    let links: Vec<ct_common::overlay::WeightedLink> = req
        .links
        .iter()
        .map(|l| ct_common::overlay::WeightedLink::new(l.a.as_str(), l.b.as_str(), l.cost))
        .collect();
    // The minimum-latency spanning-tree backbone; add capped shortcuts only in Shortcut mode.
    let base = ct_common::overlay::min_latency_overlay(&agents, &links);
    let plan = if mode == RoutingApproach::Shortcut {
        ct_common::overlay::add_shortcuts(&agents, &links, base, req.shortcut_budget)
    } else {
        base
    };
    Ok(Json(SuggestResp {
        mode: mode.as_str().to_string(),
        links: plan.links,
        total_cost: plan.total_cost,
        connected: plan.connected,
    }))
}

#[derive(Deserialize)]
struct AssignReq {
    agent: String,
    /// #107-complex: the agent's node kind -- `"peer"` (default when absent) or
    /// `"super-peer"`. Applied via `set_agent_kind` immediately after a successful assign,
    /// so it's scoped to the SAME "caller owns this agent" authority `assign` already
    /// enforces (never the topology's own owner/collaborator authority).
    #[serde(default)]
    kind: Option<String>,
}

async fn topology_assign(
    State(state): State<AuthedTopologyState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<AssignReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let (subject, email) = topology_actor_of(&state.session_key, &state.verifier, &headers)?;
    // #107-complex: the caller must own the topology OR be a collaborator it's shared with
    // (view access is the prerequisite for wiring in an agent at all); viewable_topology
    // 404s otherwise, same owner/share isolation idiom as everywhere else in this router.
    viewable_topology(&state, &subject, email.as_deref(), &id)?;
    state.topologies.assign(&subject, &req.agent, &id).map_err(|e| {
        use crate::topology::AssignError;
        let code = match e {
            crate::storage::TopologyError::Assign(AssignError::AlreadyAssigned { .. }) => StatusCode::CONFLICT,
            crate::storage::TopologyError::Assign(AssignError::NotAuthorized) => StatusCode::FORBIDDEN,
            crate::storage::TopologyError::Assign(AssignError::NotAssigned) => StatusCode::BAD_REQUEST,
            crate::storage::TopologyError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (code, e.to_string())
    })?;
    if let Some(kind) = req.kind.as_deref().filter(|k| !k.is_empty()) {
        state
            .topologies
            .set_agent_kind(&subject, &req.agent, kind)
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    }
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct EdgeReq {
    a: String,
    b: String,
}

async fn topology_add_edge(
    State(state): State<AuthedTopologyState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<EdgeReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let (subject, email) = topology_actor_of(&state.session_key, &state.verifier, &headers)?;
    // #107-complex: owner OR shared collaborator may wire an edge.
    let added = state
        .topologies
        .add_edge_collab(&subject, email.as_deref(), &id, &req.a, &req.b)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // false → the caller can't edit the topology, a self-loop, or a duplicate edge.
    if added {
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::CONFLICT, "edge not added (no edit access, self-loop, or duplicate)".to_string()))
    }
}

/// Remove an undirected edge `a—b` from a topology the caller may edit (#107-ui-compose,
/// #107-complex) — the owner-or-collaborator inverse of [`topology_add_edge`], backing the
/// editor's "unlink" gesture. `404` when the edge isn't the caller's to remove (no edit
/// access OR no such edge — deliberately indistinguishable, so a caller without access
/// learns nothing about the topology's shape).
async fn topology_remove_edge(
    State(state): State<AuthedTopologyState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<EdgeReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let (subject, email) = topology_actor_of(&state.session_key, &state.verifier, &headers)?;
    let removed = state
        .topologies
        .remove_edge_collab(&subject, email.as_deref(), &id, &req.a, &req.b)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if removed {
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::NOT_FOUND, "edge not removed (no edit access or no such edge)".to_string()))
    }
}

#[derive(Deserialize)]
struct EdgeChannelReq {
    a: String,
    b: String,
    /// 64-hex channel id to attach, or `None`/absent to clear.
    #[serde(default)]
    channel: Option<String>,
}

/// `PUT /me/topologies/:id/edges/channel {a, b, channel}` (#107-complex link info): attach
/// (or, with `channel: null`/absent, clear) an edge's explicitly-associated channel. Owner
/// or shared collaborator, like the edge wiring endpoints. Validates `channel` (when
/// present) is 64-hex AND a channel the caller either owns or is a member of — "account
/// related channels or shared to account channels", never an arbitrary channel id the
/// caller has no relationship to at all.
async fn topology_edge_channel(
    State(state): State<AuthedTopologyState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<EdgeChannelReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let (subject, email) = topology_actor_of(&state.session_key, &state.verifier, &headers)?;
    let channel_id = match req.channel.as_deref().filter(|c| !c.is_empty()) {
        Some(hex) => {
            let raw = hex_decode_32(hex).ok_or((StatusCode::BAD_REQUEST, "channel must be 64 hex chars".to_string()))?;
            let cid = ct_common::channel::ChannelId(raw);
            let is_owner = state
                .channels
                .channel_owner(&cid)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                .is_some_and(|o| o == subject);
            // "related to the account" for a non-owner means allow-listed by e-mail
            // (channels_for_email) -- channel membership itself is keyed by a holder
            // ed25519 pubkey, not by this portal session's subject string, so there is
            // no direct "is this subject a member" query to make here; the allow-list
            // is the actual account-level relationship this codebase tracks.
            let is_related = match &email {
                Some(e) => state
                    .channels
                    .channels_for_email(e)
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                    .iter()
                    .any(|(c, _)| *c == cid),
                None => false,
            };
            if !is_owner && !is_related {
                return Err((
                    StatusCode::FORBIDDEN,
                    "not a channel this account owns or has been allow-listed on".to_string(),
                ));
            }
            Some(raw)
        }
        None => None,
    };
    let ok = state
        .topologies
        .set_edge_channel(&subject, email.as_deref(), &id, &req.a, &req.b, channel_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if ok {
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::NOT_FOUND, "edge not updated (no edit access or no such edge)".to_string()))
    }
}

#[derive(Deserialize)]
struct ShareReq {
    email: String,
}

/// `POST /me/topologies/:id/share {email}` (#107-complex) — owner-only: share this
/// topology with another Keycloak account's e-mail. Idempotent.
async fn topology_share_add(
    State(state): State<AuthedTopologyState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<ShareReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let owner = subject_of_topology(&state.session_key, &state.verifier, &headers)?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let ok = state
        .topologies
        .share_add(&owner, &id, &req.email, now)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if ok {
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::NOT_FOUND, "no such topology".to_string()))
    }
}

/// `POST /me/topologies/:id/share/:email/remove` (#107-complex) — owner-only, de-lists an
/// e-mail. `404` indistinguishably whether the topology isn't the caller's or the e-mail
/// was never on the share list.
async fn topology_share_remove(
    State(state): State<AuthedTopologyState>,
    headers: HeaderMap,
    Path((id, email)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let owner = subject_of_topology(&state.session_key, &state.verifier, &headers)?;
    let removed = state
        .topologies
        .share_remove(&owner, &id, &email)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if removed {
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::NOT_FOUND, "not shared with that email, or not the owner".to_string()))
    }
}

/// `GET /me/topologies/shared` (#107-complex) — the topologies-shared-with-me portal view's
/// data source, mirroring `channels_for_email`: keyed on the CALLER's own verified e-mail,
/// never a caller-supplied one, so there's no way to enumerate another account's shares.
/// Empty (not an error) when the caller's session has no verified email — a bearer-token
/// caller included, since only a real portal login ever carries one.
async fn topology_shared_list(
    State(state): State<AuthedTopologyState>,
    headers: HeaderMap,
) -> Result<Json<Vec<TopologySummary>>, (StatusCode, String)> {
    let (_subject, email) = topology_actor_of(&state.session_key, &state.verifier, &headers)?;
    let list = match email {
        Some(email) => state
            .topologies
            .topologies_shared_with_email(&email)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
        None => Vec::new(),
    };
    Ok(Json(list.into_iter().map(|t| TopologySummary { id: t.id, net_uuid: t.net_uuid }).collect()))
}

#[derive(Deserialize)]
struct OperatorBindReq {
    /// 64-hex operator ed25519 public key — the channel authority this topology's overlay
    /// links derive channels under.
    operator_pubkey: String,
    /// 128-hex operator signature over
    /// [`ct_common::channel::topology_operator_binding_bytes`] — proof the caller controls
    /// `operator_pubkey`'s private half, not just its public bytes.
    proof: String,
}

/// `PUT /me/topologies/:id/operator {operator_pubkey, proof}` — bind this topology to an
/// operator key (#237, #107-enforce ii-a's REST surface): the prerequisite `#235`'s live
/// admission-wiring needs to actually reach a topology from outside the control plane. Without
/// this endpoint the crypto primitives (`topology_operator_binding_bytes`/
/// `verify_topology_operator_binding`, already live in [`storage::TopologyStore::set_operator`])
/// were real and tested but unreachable — drawn edges "authorized nothing" per the topology
/// editor's own honest caveat. `404` (not `403`) on failure, matching [`topology_remove_edge`]'s
/// idiom: a non-owner topology and a bad proof-of-possession are deliberately indistinguishable,
/// so a caller probing topology ids learns nothing either way.
async fn topology_set_operator(
    State(state): State<AuthedTopologyState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<OperatorBindReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let owner = subject_of_topology(&state.session_key, &state.verifier, &headers)?;
    let operator_pubkey = hex_decode_32(&req.operator_pubkey)
        .ok_or((StatusCode::BAD_REQUEST, "operator_pubkey must be 64 hex chars".to_string()))?;
    let proof = hex_decode_64(&req.proof)
        .ok_or((StatusCode::BAD_REQUEST, "proof must be 128 hex chars".to_string()))?;
    let bound = state
        .topologies
        .set_operator(&owner, &id, &operator_pubkey, &proof)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if bound {
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::NOT_FOUND, "operator not bound (not owner, no such topology, or invalid proof-of-possession)".to_string()))
    }
}

/// Render the overlay as a self-contained inline **SVG node-graph** (#107 "live
/// diagram"): agents are laid out on a circle as labelled nodes, edges as lines between
/// them. Pure, no external assets. A single node is centred; an empty topology yields an
/// empty canvas with a hint.
fn render_topology_svg(agents: &[String], edges: &[(String, String)]) -> String {
    use std::f64::consts::PI;
    let esc = crate::portal::escape;
    const W: f64 = 420.0;
    const CX: f64 = 210.0;
    const CY: f64 = 190.0;
    const R: f64 = 140.0;
    if agents.is_empty() {
        return format!(
            "<svg viewBox=\"0 0 {W} 360\" width=\"100%\" role=\"img\" aria-label=\"empty topology\">\
             <text x=\"{CX}\" y=\"180\" text-anchor=\"middle\">no agents yet</text></svg>"
        );
    }
    // Position each agent on a circle (a single node sits at the centre).
    let n = agents.len();
    let pos: std::collections::HashMap<&str, (f64, f64)> = agents
        .iter()
        .enumerate()
        .map(|(i, a)| {
            if n == 1 {
                (a.as_str(), (CX, CY))
            } else {
                let theta = 2.0 * PI * (i as f64) / (n as f64) - PI / 2.0;
                (a.as_str(), (CX + R * theta.cos(), CY + R * theta.sin()))
            }
        })
        .collect();
    // Edges first (drawn under the nodes).
    let lines: String = edges
        .iter()
        .filter_map(|(a, b)| {
            let (&(x1, y1), &(x2, y2)) = (pos.get(a.as_str())?, pos.get(b.as_str())?);
            Some(format!(
                "<line x1=\"{x1:.1}\" y1=\"{y1:.1}\" x2=\"{x2:.1}\" y2=\"{y2:.1}\" stroke=\"#888\" stroke-width=\"2\"/>"
            ))
        })
        .collect();
    let nodes: String = agents
        .iter()
        .map(|a| {
            let (x, y) = pos[a.as_str()];
            format!(
                "<circle cx=\"{x:.1}\" cy=\"{y:.1}\" r=\"10\" fill=\"#4a90d9\"/>\
                 <text x=\"{x:.1}\" y=\"{ty:.1}\" text-anchor=\"middle\" font-size=\"12\">{label}</text>",
                ty = y - 16.0,
                label = esc(a),
            )
        })
        .collect();
    format!(
        "<svg viewBox=\"0 0 {W} 360\" width=\"100%\" role=\"img\" aria-label=\"topology diagram\">\
         {lines}{nodes}</svg>"
    )
}

/// Render the public **live-status page** for a topology (#107-subdomain): a
/// self-contained (CSP-safe, no external assets) HTML view of the overlay — its
/// net-uuid, a live node-graph diagram, and the member agents + links. Addressed by
/// net-uuid (unauthenticated for now).
fn render_topology_status(
    t: &crate::topology::Topology,
    agents: &[String],
    edges: &[(String, String)],
) -> String {
    let esc = crate::portal::escape;
    let svg = render_topology_svg(agents, edges);
    let agents_html: String = agents
        .iter()
        .map(|a| format!("<li><code>{}</code></li>", esc(a)))
        .collect();
    let edges_html: String = edges
        .iter()
        .map(|(a, b)| format!("<li><code>{}</code> &mdash; <code>{}</code></li>", esc(a), esc(b)))
        .collect();
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>topology {uuid}</title></head><body>\
         <h1>Overlay topology</h1>\
         <p>net-uuid: <code>{uuid}</code></p>\
         <figure>{svg}</figure>\
         <h2>Agents ({na})</h2><ul>{agents_html}</ul>\
         <h2>Links ({ne})</h2><ul>{edges_html}</ul>\
         </body></html>",
        uuid = esc(&t.net_uuid),
        na = agents.len(),
        ne = edges.len(),
    )
}

/// The Topology-Editor stylesheet (#107-ui) — self-contained, CSP-safe (no external
/// assets), theme-aware (light/dark via `prefers-color-scheme`, GitHub-family palette).
/// CSS custom properties are only ever read from CSS rules (never SVG presentation
/// attributes, where `var()` is unsupported), so every node/edge colour flows through a
/// class.
const EDITOR_CSS: &str = r#"
:root{--bg:#f6f8fa;--panel:#fff;--ink:#1f2328;--muted:#59636e;--line:#d1d9e0;--accent:#2da44e;--accent2:#0969da;--edge:#8c959f;--node:#fff;--nodeln:#d1d9e0}
@media (prefers-color-scheme:dark){:root{--bg:#0e1116;--panel:#161b22;--ink:#e6edf3;--muted:#8b949e;--line:#30363d;--accent:#3fb950;--accent2:#58a6ff;--edge:#484f58;--node:#1c2128;--nodeln:#30363d}}
*{box-sizing:border-box}html,body{height:100%}
body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--ink);display:flex;flex-direction:column}
header.bar{display:flex;align-items:center;flex-wrap:wrap;gap:.9rem;padding:.7rem 1.1rem;border-bottom:1px solid var(--line);background:var(--panel)}
.title{font-size:1rem;font-weight:650;letter-spacing:-.01em}
.chip{font:500 .78rem/1 ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted);background:var(--bg);border:1px solid var(--line);border-radius:999px;padding:.32rem .62rem}
.hint{color:var(--muted);font-size:.82rem}
.stage{flex:1;min-height:0}
svg.canvas{width:100%;height:100%;display:block;touch-action:none;background:var(--bg)}
.dot{fill:var(--line);opacity:.55}
.edge{fill:none;stroke:var(--edge);stroke-width:2;stroke-linecap:round;opacity:.9}
.node{cursor:grab}.node:active{cursor:grabbing}
.node .card{fill:var(--node);stroke:var(--nodeln);stroke-width:1}
.node:hover .card,.node:focus .card{stroke:var(--accent2)}
.node:focus{outline:none}
.node .accent{fill:var(--accent)}
.node .handle{fill:var(--accent2);opacity:.85}
.node .label{fill:var(--ink);font:600 12px system-ui,sans-serif;pointer-events:none}
.empty{fill:var(--muted);font:500 15px system-ui,sans-serif}
.bar label{margin-left:auto;color:var(--muted);font-size:.82rem;display:flex;align-items:center;gap:.4rem}
.bar select,.bar button{font:inherit;font-size:.82rem;color:var(--ink);background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:.35rem .6rem;cursor:pointer}
.bar input{font:inherit;font-size:.82rem;color:var(--ink);background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:.35rem .6rem;width:8.5rem}
.bar button.primary{background:var(--accent);color:#fff;border-color:transparent;font-weight:600}
.bar button.primary:hover{filter:brightness(1.06)}
#msg{color:var(--muted);font-size:.8rem;min-width:0;max-width:16rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar button.active{background:var(--accent);color:#fff;border-color:transparent;font-weight:600}
.node.linking .card{stroke:var(--accent);stroke-width:2px}
svg[data-linkmode="1"] .edge{cursor:pointer;stroke-width:5px}
.edge{cursor:pointer}
.node.superpeer .card{stroke:var(--accent2);stroke-width:2px}
.node.superpeer .accent{fill:var(--accent2)}
.badge{fill:var(--accent2)}.badge-t{fill:#fff;font:700 9px ui-monospace,monospace;pointer-events:none}
label.sp{color:var(--muted);font-size:.82rem;display:flex;align-items:center;gap:.3rem;margin-left:0}
.panel{border-top:1px solid var(--line);background:var(--panel);padding:.7rem 1.1rem;display:flex;align-items:center;gap:.6rem;flex-wrap:wrap}
.panel h2{font-size:.82rem;color:var(--muted);margin:0;font-weight:600}
.sharee{font:500 .8rem ui-monospace,monospace;background:var(--bg);border:1px solid var(--line);border-radius:999px;padding:.25rem .5rem;display:inline-flex;align-items:center;gap:.35rem}
.sharee .unshare{background:none;border:0;color:var(--muted);cursor:pointer;font-size:.9rem;padding:0;line-height:1}
.sharee .unshare:hover{color:var(--accent2)}
body:not([data-uimode="flexible"]) .flex-only{display:none}
.modebtn{font:600 .78rem system-ui,sans-serif;background:var(--panel);border:1px solid var(--line);border-radius:999px;padding:.3rem .2rem;display:inline-flex;overflow:hidden}
.modebtn button{border:0;background:none;color:var(--muted);padding:.15rem .6rem;border-radius:999px;cursor:pointer;font:inherit}
.modebtn button.on{background:var(--accent);color:#fff}
.cmds{border-top:1px solid var(--line);background:var(--panel);padding:.9rem 1.1rem 1.2rem;max-height:38vh;overflow-y:auto}
.cmds[hidden]{display:none}
.cmds h2{font-size:.85rem;margin:0 0 .3rem;color:var(--ink)}
.cmds .lede{color:var(--muted);font-size:.8rem;margin:0 0 .8rem}
.cmds .hostrow{display:flex;align-items:center;gap:.5rem;margin-bottom:.9rem;font-size:.8rem;color:var(--muted)}
.cmds .hostrow input{font:inherit;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:.3rem .5rem;color:var(--ink);width:14rem}
.cmd-block{margin:0 0 1rem}
.cmd-block h3{font-size:.78rem;font-weight:650;color:var(--muted);margin:0 0 .35rem;text-transform:uppercase;letter-spacing:.02em}
.cmd-block pre{margin:0;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:.6rem .7rem;overflow-x:auto;position:relative}
.cmd-block code{font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--ink);white-space:pre}
.cmd-block .copy{position:absolute;top:.4rem;right:.4rem;font:600 .68rem system-ui,sans-serif;background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:.2rem .5rem;cursor:pointer;color:var(--muted)}
.cmd-block .copy:hover{color:var(--ink)}
.cmd-empty{color:var(--muted);font-size:.8rem;font-style:italic}
"#;

/// The Topology-Editor behaviour (#107-ui) — CSP-safe inline JS, no external assets.
/// Pointer-drag any node; connected edges re-route live. Progressive enhancement: the
/// server already emits correct node/edge geometry, so the graph renders identically with
/// JS disabled — this only adds interactivity.
const EDITOR_JS: &str = r#"
(function(){
 var svg=document.getElementById('cv');if(!svg)return;
 var sel=null,dx=0,dy=0;
 function pt(e){var m=svg.getScreenCTM().inverse(),p=svg.createSVGPoint();p.x=e.clientX;p.y=e.clientY;return p.matrixTransform(m);}
 function centers(){var m={};svg.querySelectorAll('.node').forEach(function(n){m[n.getAttribute('data-node')]=[+n.getAttribute('data-cx'),+n.getAttribute('data-cy')];});return m;}
 function redraw(){var c=centers();svg.querySelectorAll('.edge').forEach(function(ed){var a=c[ed.getAttribute('data-a')],b=c[ed.getAttribute('data-b')];if(!a||!b)return;var mx=(a[0]+b[0])/2;ed.setAttribute('d','M '+a[0]+' '+a[1]+' C '+mx+' '+a[1]+', '+mx+' '+b[1]+', '+b[0]+' '+b[1]);});}
 svg.addEventListener('pointerdown',function(e){if(svg.getAttribute('data-linkmode')==='1'){var ed=e.target.closest('.edge');if(ed){removeEdge(ed);return;}}else{var ed2=e.target.closest('.edge');if(ed2){editLinkInfo(ed2);return;}}var g=e.target.closest('.node');if(!g)return;if(svg.getAttribute('data-linkmode')==='1'){linkPick(g);return;}sel=g;var p=pt(e);dx=p.x-(+g.getAttribute('data-cx'));dy=p.y-(+g.getAttribute('data-cy'));try{g.setPointerCapture(e.pointerId);}catch(_){}});
 svg.addEventListener('pointermove',function(e){if(!sel)return;var p=pt(e),x=p.x-dx,y=p.y-dy;sel.setAttribute('data-cx',x);sel.setAttribute('data-cy',y);sel.setAttribute('transform','translate('+x+','+y+')');redraw();});
 svg.addEventListener('pointerup',function(){sel=null;});
 redraw();
 // #107-ui: the overlay-mode toggle + suggest button, wired to the owner REST endpoints.
 var tid=document.body.getAttribute('data-tid');
 var msg=document.getElementById('msg');
 function say(t){if(msg)msg.textContent=t;}
 var modeSel=document.getElementById('mode');
 if(modeSel){modeSel.addEventListener('change',function(){
  fetch('/me/topologies/'+encodeURIComponent(tid)+'/mode',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({mode:modeSel.value})})
   .then(function(r){say(r.ok?'mode: '+modeSel.value:'mode change failed ('+r.status+')');});
 });}
 var sug=document.getElementById('suggest');
 if(sug){sug.addEventListener('click',function(){
  var links=[];svg.querySelectorAll('.edge').forEach(function(ed){links.push({a:ed.getAttribute('data-a'),b:ed.getAttribute('data-b'),cost:1});});
  fetch('/me/topologies/'+encodeURIComponent(tid)+'/suggest',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({links:links})})
   .then(function(r){return r.ok?r.json():Promise.reject(r.status);})
   .then(function(p){say('suggested '+p.links.length+' links, cost '+p.total_cost+(p.connected?' (connected)':' (partition)'));})
   .catch(function(s){say('suggest unavailable ('+s+')');});
 });}
 // #107-ui-compose: click-to-connect — toggle Connect, then click two agents to draw a new
 // overlay link; it POSTs the existing owner `…/edges` endpoint and the edge appears live.
 var src=null;
 function xesc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');}
 function shortId(s){s=String(s);return s.length>14?s.slice(0,10)+'…':s;}
 function clearSrc(){if(src){src.classList.remove('linking');src=null;}}
 function edgeExists(a,b){var f=false;svg.querySelectorAll('.edge').forEach(function(ed){var x=ed.getAttribute('data-a'),y=ed.getAttribute('data-b');if((x===a&&y===b)||(x===b&&y===a))f=true;});return f;}
 function addEdgeEl(a,b){var first=svg.querySelector('.node');if(!first)return;first.insertAdjacentHTML('beforebegin','<path data-a="'+xesc(a)+'" data-b="'+xesc(b)+'"/>');var np=first.previousElementSibling;if(np)np.setAttribute('class','edge');redraw();}
 function linkPick(g){var id=g.getAttribute('data-node');if(!src){src=g;g.classList.add('linking');say('connect: pick the target agent');return;}var a=src.getAttribute('data-node');clearSrc();if(a===id){say('connect: pick two different agents');return;}if(edgeExists(a,id)){say('already linked');return;}fetch('/me/topologies/'+encodeURIComponent(tid)+'/edges',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({a:a,b:id})}).then(function(r){if(r.ok){addEdgeEl(a,id);say('linked '+shortId(a)+' — '+shortId(id));}else{say('link failed ('+r.status+')');}}).catch(function(){say('link failed');});}
 function removeEdge(ed){var a=ed.getAttribute('data-a'),b=ed.getAttribute('data-b');fetch('/me/topologies/'+encodeURIComponent(tid)+'/edges',{method:'DELETE',headers:{'content-type':'application/json'},body:JSON.stringify({a:a,b:b})}).then(function(r){if(r.ok){ed.remove();say('unlinked '+shortId(a)+' — '+shortId(b));}else{say('unlink failed ('+r.status+')');}}).catch(function(){say('unlink failed');});}
 var linkBtn=document.getElementById('link');
 if(linkBtn){linkBtn.addEventListener('click',function(){var on=svg.getAttribute('data-linkmode')!=='1';svg.setAttribute('data-linkmode',on?'1':'');linkBtn.setAttribute('aria-pressed',on?'true':'false');linkBtn.classList.toggle('active',on);if(!on)clearSrc();say(on?'connect: click two agents to link, or a link to remove':'');});}
 // #107-ui-compose: add-agent — assign an existing agent into this topology, then re-render
 // (the server lays out the new node with correct geometry). Exclusive-membership 409 is surfaced.
 var addBtn=document.getElementById('addagent'),agIn=document.getElementById('agent');
 var kindIn=document.getElementById('agentkind');
 if(addBtn&&agIn){addBtn.addEventListener('click',function(){var a=agIn.value.trim();if(!a){say('enter an agent id');return;}var kind=(kindIn&&kindIn.checked)?'super-peer':'peer';fetch('/me/topologies/'+encodeURIComponent(tid)+'/agents',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({agent:a,kind:kind})}).then(function(r){if(r.ok){say('added '+shortId(a));location.reload();}else if(r.status===409){say('that agent is already in a topology');}else{say('add failed ('+r.status+')');}}).catch(function(){say('add failed');});});}
 // #107-complex: click an edge OUTSIDE connect-mode to view/attach its explicit channel
 // (link info) -- the derived channel always applies regardless; this is purely the
 // optional, explicit association a collaborator can attach for their own bookkeeping.
 function editLinkInfo(ed){
  var a=ed.getAttribute('data-a'),b=ed.getAttribute('data-b'),cur=ed.getAttribute('data-channel')||'';
  var msgLine=cur?('current channel: '+cur):'no channel explicitly attached (edge still authorizes its derived channel)';
  var next=window.prompt('Link '+a+' — '+b+'\n'+msgLine+'\n\nEnter a 64-hex channel id to attach, or leave blank to clear:',cur);
  if(next===null)return;
  next=next.trim();
  if(next&&!/^[0-9a-fA-F]{64}$/.test(next)){say('channel id must be 64 hex chars');return;}
  fetch('/me/topologies/'+encodeURIComponent(tid)+'/edges/channel',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({a:a,b:b,channel:next?next:null})})
   .then(function(r){if(r.ok){ed.setAttribute('data-channel',next);say(next?'channel attached':'channel cleared');}else{say('link-info update failed ('+r.status+')');}})
   .catch(function(){say('link-info update failed');});
 }
 // #107-complex: owner-only share management.
 var shareBtn=document.getElementById('shareBtn'),shareEmail=document.getElementById('shareEmail'),sharesEl=document.getElementById('shares');
 function addShareRow(email){if(!sharesEl)return;var s=document.createElement('span');s.className='sharee';s.textContent=email+' ';var btn=document.createElement('button');btn.className='unshare';btn.setAttribute('data-email',email);btn.setAttribute('aria-label','stop sharing with '+email);btn.textContent='×';btn.addEventListener('click',function(){unshare(email,s);});s.appendChild(btn);sharesEl.appendChild(s);}
 function unshare(email,el){fetch('/me/topologies/'+encodeURIComponent(tid)+'/share/'+encodeURIComponent(email)+'/remove',{method:'POST'}).then(function(r){if(r.ok){if(el&&el.remove)el.remove();say('unshared '+email);}else{say('unshare failed ('+r.status+')');}}).catch(function(){say('unshare failed');});}
 if(sharesEl){sharesEl.querySelectorAll('.unshare').forEach(function(btn){btn.addEventListener('click',function(){unshare(btn.getAttribute('data-email'),btn.closest('.sharee'));});});}
 if(shareBtn&&shareEmail){shareBtn.addEventListener('click',function(){var email=shareEmail.value.trim();if(!email){say('enter an email address');return;}fetch('/me/topologies/'+encodeURIComponent(tid)+'/share',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:email})}).then(function(r){if(r.ok){addShareRow(email);shareEmail.value='';say('shared with '+email);}else{say('share failed ('+r.status+')');}}).catch(function(){say('share failed');});});}

 // Easy/Flexible presentation toggle (#ux-overhaul): purely a client-side view
 // preference, persisted in localStorage -- the real graph/API underneath is
 // identical either way. Easy hides the overlay-mode/suggest planning tools and
 // keeps the "how do I bring this to life?" commands panel open by default;
 // Flexible shows the full toolbar with the panel collapsed.
 var easyBtn=document.getElementById('modeeasy'),flexBtn=document.getElementById('modeflex');
 var cmds=document.getElementById('cmds');
 function setUiMode(m){
  document.body.setAttribute('data-uimode',m);
  if(easyBtn)easyBtn.classList.toggle('on',m==='easy');
  if(flexBtn)flexBtn.classList.toggle('on',m==='flexible');
  try{localStorage.setItem('ct-topology-uimode',m);}catch(_){}
  if(cmds)cmds.hidden=(m!=='easy');
 }
 if(easyBtn)easyBtn.addEventListener('click',function(){setUiMode('easy');});
 if(flexBtn)flexBtn.addEventListener('click',function(){setUiMode('flexible');});
 var storedMode='easy';
 try{storedMode=localStorage.getItem('ct-topology-uimode')||'easy';}catch(_){}
 setUiMode(storedMode);

 // "How do I bring this to life?" -- real, copy-paste ct-agent one-liners for
 // what's actually drawn on the canvas right now: one per super-peer node, one
 // pair per edge (derive + grant, using the edge's REAL two holder-key node ids
 // -- a topology node id already IS the agent's holder key, #107-enforce). Ports
 // come from this deployment's own /network-info (real values); the host is a
 // best-effort default (this page's own hostname) the visitor can correct --
 // never asserted as fact, since the edge can genuinely be a different host.
 var hostIn=document.getElementById('cmdhost');
 function esc2(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;');}
 function block(title,body){return '<div class="cmd-block"><h3>'+esc2(title)+'</h3><pre><code>'+esc2(body)+'</code></pre><button type="button" class="copy">Copy</button></div>';}
 var netInfo=null;
 function renderCmds(){
  if(!cmds)return;
  var host=(hostIn&&hostIn.value.trim())||location.hostname;
  var brokerPort=netInfo?netInfo.channel_broker_port:4435;
  var out='';
  out+='<div class="cmd-block"><h3>New agent identity</h3><p class="lede" style="margin:.1rem 0 .5rem">Run once per machine you\'re adding to this topology, then paste the printed <code>holder_pubkey</code> into "agent id" above.</p><pre><code>ct-agent channel init</code></pre><button type="button" class="copy" data-copy="ct-agent channel init">Copy</button></div>';
  var sps=[];svg.querySelectorAll('.node.superpeer').forEach(function(g){sps.push(g.getAttribute('data-node'));});
  if(sps.length){
   sps.forEach(function(id){
    var cmd='CT_CHANNEL_SUPER_PEER_LISTEN=0.0.0.0:9443 \\\nCT_CHANNEL_SUPER_PEER_UPSTREAM='+host+':'+brokerPort+' \\\nct-agent channel super-peer';
    out+=block('Run super-peer '+id.slice(0,12)+'…',cmd);
   });
  }
  var seen={};
  svg.querySelectorAll('.edge').forEach(function(ed){
   var a=ed.getAttribute('data-a'),b=ed.getAttribute('data-b'),key=a+'|'+b;
   if(seen[key])return;seen[key]=true;
   var shortA=a.slice(0,12)+'...';
   var cmd='# run on '+shortA+' (repeat with roles swapped on the other machine)\nCT_CHANNEL_OPERATOR_PUBKEY=<operator pubkey> \\\nCT_CHANNEL_BRIDGE_HOLDER='+b+' \\\nCT_CHANNEL_HOLDER_KEY=<'+shortA+' own holder private key, from its own channel init> \\\nCT_CHANNEL_NOISE_PUBKEY=<'+shortA+' own noise public key, from its own channel init> \\\nct-agent channel member-material';
   out+=block('Wire '+a.slice(0,10)+'… ↔ '+b.slice(0,10)+'…',cmd);
  });
  if(!sps.length && !Object.keys(seen).length){
   out+='<p class="cmd-empty">Add an agent or draw a connection to see the real commands for it here.</p>';
  }
  out+='<p class="lede" style="margin-top:.8rem">Full walkthroughs on docs.bunsenbrenner.org: <strong>/how-to/join-a-channel</strong>, <strong>/how-to/run-a-super-peer</strong>, <strong>/how-to/tunnel-plus-channel</strong>.</p>';
  cmds.innerHTML='<h2>How do I bring this to life?</h2><p class="lede">Real commands for what\'s on the canvas right now &mdash; run them on the actual machines, not here.</p><div class="hostrow"><label for="cmdhost">edge host</label><input id="cmdhost" value="'+esc2(host)+'"/></div>'+out;
  var hi=document.getElementById('cmdhost');
  if(hi)hi.addEventListener('input',renderCmds);
  cmds.querySelectorAll('.copy').forEach(function(btn){
   btn.addEventListener('click',function(){
    var pre=btn.previousElementSibling;var text=pre?pre.textContent:'';
    var done=function(){var o=btn.textContent;btn.textContent='Copied';setTimeout(function(){btn.textContent=o;},1400);};
    if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text).then(done).catch(function(){});}
   });
  });
 }
 fetch('/network-info').then(function(r){return r.ok?r.json():null;}).then(function(j){netInfo=j;renderCmds();}).catch(function(){renderCmds();});
 var cmdsBtn=document.getElementById('cmdstoggle');
 if(cmdsBtn&&cmds){cmdsBtn.addEventListener('click',function(){cmds.hidden=!cmds.hidden;});}
 // Re-render the commands panel whenever the graph actually changes (new agent,
 // new/removed edge) so it never drifts from what's really on the canvas.
 var _origAddEdgeEl=addEdgeEl;addEdgeEl=function(a,b){_origAddEdgeEl(a,b);renderCmds();};
 var _origRemoveEdge=removeEdge;removeEdge=function(ed){_origRemoveEdge(ed);renderCmds();};
})();
"#;

/// Render the owner-facing **Topology Editor** page (#107-ui): a self-contained
/// (CSP-safe, no external assets), theme-aware, **draggable** SVG node-graph of the
/// topology — agents as rounded node-cards on a dotted canvas, links as smooth bezier
/// edges. Server-emitted geometry means it renders correctly without JS (progressive
/// enhancement); the inline JS only adds drag interactivity + the overlay-mode toggle,
/// "Suggest overlay", the "Connect" click-to-compose tool (#107-ui-compose — toggle it,
/// click two agents to draw a link, or click a link to remove it, via the owner
/// `POST`/`DELETE …/edges` endpoints), and an add-agent input (`POST …/agents`, re-rendering
/// so the server lays out the new node). Agent ids are HTML-escaped
/// (XSS-safe). An empty topology yields a valid page with an empty-state hint. `mode` is the
/// topology's current [`overlay mode`](topology_set_mode) token, pre-selected in the toggle.
fn render_topology_editor(
    t: &crate::topology::Topology,
    agents: &[(String, String)],
    edges: &[(String, String, Option<[u8; 32]>)],
    mode: &str,
    is_owner: bool,
    shares: &[String],
) -> String {
    use std::f64::consts::PI;
    let esc = crate::portal::escape;
    // Fixed design canvas (the SVG scales to the viewport via width/height:100%).
    const VW: f64 = 900.0;
    const VH: f64 = 560.0;
    const CX: f64 = VW / 2.0;
    const CY: f64 = VH / 2.0;
    const R: f64 = 200.0;

    // Circular initial layout — one node sits at the centre.
    let n = agents.len();
    let pos: std::collections::HashMap<&str, (f64, f64)> = agents
        .iter()
        .enumerate()
        .map(|(i, (a, _))| {
            if n == 1 {
                (a.as_str(), (CX, CY))
            } else {
                let theta = 2.0 * PI * (i as f64) / (n as f64) - PI / 2.0;
                (a.as_str(), (CX + R * theta.cos(), CY + R * theta.sin()))
            }
        })
        .collect();

    let defs = "<defs>\
        <pattern id=\"grid\" width=\"26\" height=\"26\" patternUnits=\"userSpaceOnUse\">\
        <circle class=\"dot\" cx=\"1\" cy=\"1\" r=\"1\"/></pattern>\
        <filter id=\"nsh\" x=\"-30%\" y=\"-40%\" width=\"160%\" height=\"200%\">\
        <feDropShadow dx=\"0\" dy=\"2\" stdDeviation=\"3\" flood-color=\"#1f232833\"/></filter>\
        </defs><rect width=\"100%\" height=\"100%\" fill=\"url(#grid)\"/>";

    let content = if agents.is_empty() {
        format!(
            "{defs}<text class=\"empty\" x=\"{CX}\" y=\"{CY}\" text-anchor=\"middle\">\
             no agents yet — assign one to start composing</text>"
        )
    } else {
        // Edges first (drawn under the nodes), each a bezier between node centres. #107-complex:
        // data-channel carries the explicitly-attached channel id (hex), if any -- the click
        // handler reads it to show/edit link info without a extra round-trip.
        let edge_svg: String = edges
            .iter()
            .filter_map(|(a, b, channel)| {
                let (&(x1, y1), &(x2, y2)) = (pos.get(a.as_str())?, pos.get(b.as_str())?);
                let mx = (x1 + x2) / 2.0;
                let ch = channel.map(|c| hex_encode(&c)).unwrap_or_default();
                Some(format!(
                    "<path class=\"edge\" data-a=\"{a}\" data-b=\"{b}\" data-channel=\"{ch}\" \
                     d=\"M {x1:.1} {y1:.1} C {mx:.1} {y1:.1}, {mx:.1} {y2:.1}, {x2:.1} {y2:.1}\"/>",
                    a = esc(a),
                    b = esc(b),
                    ch = esc(&ch),
                ))
            })
            .collect();
        // #107-complex: a super-peer node gets a distinct class (`node superpeer`, styled in
        // EDITOR_CSS) and a small "SP" badge instead of the plain accent bar -- a peer routing
        // through it is a visually distinguishable graph shape, not just a same-looking agent.
        let node_svg: String = agents
            .iter()
            .map(|(a, kind)| {
                let (x, y) = pos[a.as_str()];
                // Truncate long ids for the card face (raw, then escape).
                let raw: String = a.chars().take(16).collect();
                let label = if a.chars().count() > 16 { format!("{raw}…") } else { raw };
                let is_sp = kind == "super-peer";
                let cls = if is_sp { "node superpeer" } else { "node" };
                let badge = if is_sp {
                    "<rect class=\"badge\" x=\"32\" y=\"-34\" width=\"28\" height=\"16\" rx=\"8\" ry=\"8\"/>\
                     <text class=\"badge-t\" x=\"46\" y=\"-22\" text-anchor=\"middle\">SP</text>"
                } else {
                    ""
                };
                format!(
                    "<g class=\"{cls}\" data-node=\"{id}\" data-kind=\"{kind}\" data-cx=\"{x:.1}\" data-cy=\"{y:.1}\" \
                     transform=\"translate({x:.1},{y:.1})\" tabindex=\"0\" role=\"listitem\" aria-label=\"agent {id}\">\
                     <rect class=\"card\" x=\"-60\" y=\"-22\" width=\"120\" height=\"44\" rx=\"12\" ry=\"12\" filter=\"url(#nsh)\"/>\
                     <rect class=\"accent\" x=\"-60\" y=\"-22\" width=\"120\" height=\"4\" rx=\"2\"/>\
                     <circle class=\"handle\" cx=\"60\" cy=\"0\" r=\"4\"/>\
                     <text class=\"label\" x=\"0\" y=\"5\" text-anchor=\"middle\">{label}</text>{badge}</g>",
                    id = esc(a),
                    kind = esc(kind),
                    label = esc(&label),
                )
            })
            .collect();
        format!("{defs}{edge_svg}{node_svg}")
    };

    // The overlay-mode toggle (#107-ui-mode): direct vs the complex-adaptive modes, current
    // pre-selected. Each option value is a canonical `RoutingApproach` token the `PUT …/mode`
    // endpoint accepts.
    let opt = |v: &str, label: &str| {
        format!(
            "<option value=\"{v}\"{sel}>{label}</option>",
            sel = if mode == v { " selected" } else { "" }
        )
    };
    let mode_options = format!(
        "{}{}{}{}",
        opt("baseline", "Direct"),
        opt("smart-route", "Adaptive (min-latency)"),
        opt("shortcut", "Adaptive + shortcuts"),
        opt("random-mesh", "Random mesh"),
    );

    // #107-complex: owner-only share management -- a subject viewing via a share never sees
    // (or can reach) another collaborator's e-mail or the share-management controls.
    let share_section = if is_owner {
        let rows: String = shares
            .iter()
            .map(|e| {
                format!(
                    "<span class=\"sharee\">{email} <button class=\"unshare\" data-email=\"{email}\" \
                     aria-label=\"stop sharing with {email}\">&times;</button></span>",
                    email = esc(e)
                )
            })
            .collect();
        format!(
            "<div class=\"panel\"><h2>Shared with</h2>\
             <div id=\"shares\">{rows}</div>\
             <input id=\"shareEmail\" type=\"email\" placeholder=\"email address\" aria-label=\"share with email\"/>\
             <button id=\"shareBtn\">Share</button></div>"
        )
    } else {
        String::new()
    };

    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>Topology Editor — {uuid}</title><style>{css}</style></head>\
         <body data-tid=\"{tid}\" data-owner=\"{is_owner}\">\
         <header class=\"bar\"><span class=\"title\">Topology Editor</span>\
         <span class=\"chip\">net:{uuid}</span>\
         <span class=\"chip\" id=\"agentcount\">{na} agents</span><span class=\"chip\" id=\"edgecount\">{ne} links</span>\
         <span class=\"hint\">drag nodes to arrange</span>\
         <div class=\"modebtn\" role=\"group\" aria-label=\"editor complexity\">\
         <button type=\"button\" id=\"modeeasy\">Easy</button><button type=\"button\" id=\"modeflex\">Flexible</button></div>\
         <label class=\"flex-only\">overlay <select id=\"mode\"{mode_dis}>{mode_options}</select></label>\
         <button id=\"link\" aria-pressed=\"false\">Connect</button>\
         <input id=\"agent\" placeholder=\"agent id (paste holder_pubkey)\" aria-label=\"agent id to add\"/>\
         <label class=\"sp\"><input type=\"checkbox\" id=\"agentkind\"/> super-peer</label>\
         <button id=\"addagent\">Add</button>\
         <button id=\"suggest\" class=\"primary flex-only\">Suggest overlay</button>\
         <button id=\"cmdstoggle\">Commands</button>\
         <span id=\"msg\"></span></header>\
         <div class=\"stage\"><svg id=\"cv\" class=\"canvas\" viewBox=\"0 0 {VW:.0} {VH:.0}\" \
         preserveAspectRatio=\"xMidYMid meet\" role=\"application\" aria-label=\"topology node graph\">\
         {content}</svg></div>{share_section}\
         <div class=\"cmds\" id=\"cmds\" hidden></div>\
         <script>{js}</script></body></html>",
        uuid = esc(&t.net_uuid),
        tid = esc(&t.id),
        na = agents.len(),
        ne = edges.len(),
        mode_dis = if is_owner { "" } else { " disabled" },
        css = EDITOR_CSS,
        js = EDITOR_JS,
    )
}

/// Build the public **topology live-status** router (#107-subdomain): `GET /net/:net_uuid`
/// resolves the topology by its net-uuid and renders [`render_topology_status`]. UUID-only
/// access for now (an owner auth-gate is a tracked follow); the eventual
/// `<net_uuid>.<zone>` subdomain routing reuses the Browser-Plane / #38 DL2 pipeline.
pub fn topology_status_router(topologies: Arc<SqliteTopologyStore>) -> Router {
    Router::new()
        .route("/net/:net_uuid", get(topology_status_page))
        .with_state(topologies)
}

async fn topology_status_page(
    State(topologies): State<Arc<SqliteTopologyStore>>,
    Path(net_uuid): Path<String>,
) -> Response {
    match topologies.topology_by_uuid(&net_uuid) {
        Ok(Some(t)) => {
            let agents = topologies.agents_in(&t.id).unwrap_or_default();
            let edges = topologies.edges(&t.id).unwrap_or_default();
            axum::response::Html(render_topology_status(&t, &agents, &edges)).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "no such topology").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct ChannelRegisterReq {
    channel: String,
    operator_pubkey: String,
}

async fn channel_register(
    State(state): State<AuthedChannelState>,
    headers: HeaderMap,
    Json(req): Json<ChannelRegisterReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let owner = subject_of(&state.verifier, &headers)?;
    let channel = hex_decode_32(&req.channel)
        .ok_or((StatusCode::BAD_REQUEST, "malformed channel".to_string()))?;
    let operator = hex_decode_32(&req.operator_pubkey)
        .ok_or((StatusCode::BAD_REQUEST, "malformed operator_pubkey".to_string()))?;
    let ok = state
        .channels
        .register_channel(&ChannelId(channel), &operator, &owner)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // `register_channel` returns false only when the channel already belongs to a
    // different subject — never let one owner re-key another's channel.
    if ok {
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::FORBIDDEN, "channel owned by another subject".to_string()))
    }
}

#[derive(Deserialize)]
struct MemberReq {
    holder: String,
    /// The member's X25519 Noise static key (#72 AF4) — the peer pins this for the
    /// direct-path Noise_IK handshake.
    noise_pubkey: String,
    /// The member's attestation over `noise_pubkey` (#101): the holder's ed25519
    /// signature over `member_noise_attest_bytes(channel, holder, noise_pubkey)`,
    /// hex. The CP verifies it, so an un-attested / operator-forged key is rejected.
    noise_attestation: String,
}

async fn channel_add_member(
    State(state): State<AuthedChannelState>,
    headers: HeaderMap,
    Path(channel_hex): Path<String>,
    Json(req): Json<MemberReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let owner = subject_of(&state.verifier, &headers)?;
    let channel = hex_decode_32(&channel_hex)
        .ok_or((StatusCode::BAD_REQUEST, "malformed channel".to_string()))?;
    let holder = hex_decode_32(&req.holder)
        .ok_or((StatusCode::BAD_REQUEST, "malformed holder".to_string()))?;
    let noise_pubkey = hex_decode_32(&req.noise_pubkey)
        .ok_or((StatusCode::BAD_REQUEST, "malformed noise_pubkey".to_string()))?;
    let noise_attestation = hex_decode_64(&req.noise_attestation)
        .ok_or((StatusCode::BAD_REQUEST, "malformed noise_attestation".to_string()))?;
    // #101 SEC101b: the Noise key must be attested by the holder — a signature over
    // (channel, holder, noise_pubkey) under the holder key. Reject an un-attested or
    // forged key so a DB-controlling operator can't seed a MITM key.
    if !ct_common::channel::verify_member_noise_attestation(
        &ChannelId(channel),
        &holder,
        &noise_pubkey,
        &noise_attestation,
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            "noise_attestation does not verify against the holder key".to_string(),
        ));
    }
    let ok = state
        .channels
        .add_member(&ChannelId(channel), &owner, &holder, &noise_pubkey, &noise_attestation)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // false → not the owner (or unknown channel): only the owner manages members.
    if ok {
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::FORBIDDEN, "not the channel owner".to_string()))
    }
}

async fn channel_remove_member(
    State(state): State<AuthedChannelState>,
    headers: HeaderMap,
    Path((channel_hex, holder_hex)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let owner = subject_of(&state.verifier, &headers)?;
    let channel = hex_decode_32(&channel_hex)
        .ok_or((StatusCode::BAD_REQUEST, "malformed channel".to_string()))?;
    let holder = hex_decode_32(&holder_hex)
        .ok_or((StatusCode::BAD_REQUEST, "malformed holder".to_string()))?;
    let ok = state
        .channels
        .remove_member(&ChannelId(channel), &owner, &holder)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if ok {
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::FORBIDDEN, "not the channel owner".to_string()))
    }
}

/// Loose email-syntax sanity check (#248-follow) — this is NOT verification (that's
/// the IdP's job via `email_verified`, checked at claim time), just enough to reject
/// obvious garbage before it lands in the allow-list: one `@`, a non-empty local part
/// and a domain part containing at least one `.`, total length bounded.
fn plausible_email(email: &str) -> bool {
    if email.is_empty() || email.len() > 254 {
        return false;
    }
    match email.split_once('@') {
        Some((local, domain)) => !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.'),
        None => false,
    }
}

#[derive(Deserialize)]
struct AllowlistEmailReq {
    email: String,
}

#[derive(Serialize)]
struct AllowlistResp {
    emails: Vec<String>,
}

/// `POST /me/channels/:channel/allowlist` (#248-follow): owner-scoped, add `email`
/// to the channel's self-service allow-list. See [`SqliteChannelStore::allowlist_add`].
async fn channel_allowlist_add(
    State(state): State<AuthedChannelState>,
    headers: HeaderMap,
    Path(channel_hex): Path<String>,
    Json(req): Json<AllowlistEmailReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let owner = subject_of(&state.verifier, &headers)?;
    let channel = hex_decode_32(&channel_hex)
        .ok_or((StatusCode::BAD_REQUEST, "malformed channel".to_string()))?;
    if !plausible_email(&req.email) {
        return Err((StatusCode::BAD_REQUEST, "malformed email".to_string()));
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let ok = state
        .channels
        .allowlist_add(&ChannelId(channel), &owner, &req.email, now)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if ok {
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::FORBIDDEN, "not the channel owner".to_string()))
    }
}

/// `GET /me/channels/:channel/allowlist` (#248-follow): owner-scoped list of
/// allow-listed emails.
async fn channel_allowlist_list(
    State(state): State<AuthedChannelState>,
    headers: HeaderMap,
    Path(channel_hex): Path<String>,
) -> Result<Json<AllowlistResp>, (StatusCode, String)> {
    let owner = subject_of(&state.verifier, &headers)?;
    let channel = hex_decode_32(&channel_hex)
        .ok_or((StatusCode::BAD_REQUEST, "malformed channel".to_string()))?;
    let emails = state
        .channels
        .allowlist_list(&ChannelId(channel), &owner)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    match emails {
        Some(emails) => Ok(Json(AllowlistResp { emails })),
        None => Err((StatusCode::FORBIDDEN, "not the channel owner".to_string())),
    }
}

/// `POST /me/channels/:channel/allowlist/:email/remove` (#248-follow): owner-scoped
/// removal from the allow-list. Path-encoded email, mirroring
/// `/members/:holder/remove`'s shape; only stops *future* claims (an already-claimed
/// member keeps their grant — use the existing member-remove route to revoke that).
async fn channel_allowlist_remove(
    State(state): State<AuthedChannelState>,
    headers: HeaderMap,
    Path((channel_hex, email)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let owner = subject_of(&state.verifier, &headers)?;
    let channel = hex_decode_32(&channel_hex)
        .ok_or((StatusCode::BAD_REQUEST, "malformed channel".to_string()))?;
    // axum's `Path` extractor percent-decodes each segment already — `email` here is
    // the raw address, not the wire-encoded form.
    let ok = state
        .channels
        .allowlist_remove(&ChannelId(channel), &owner, &email)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if ok {
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::FORBIDDEN, "not the channel owner".to_string()))
    }
}

/// Build the **cross-user channel invitation redemption** router (#72 AF3-redeem-cp):
/// `POST /channel/invite/redeem`, backed by the durable [`SqliteChannelStore`].
///
/// This is how a *different* user's agent joins a channel it was invited to. It is
/// **public but proof-gated** — not an open write surface (cf. #87): every redemption
/// must carry an operator-signed `SignedChannelInvitation` (the channel owner's
/// authorization, verified against the registry's `operator_pubkey`), the invitee's
/// redemption signature binding the member `holder` key, and the holder's Noise-key
/// attestation (#101). Only when all three verify does the CP record the invitee's
/// holder as a member — on the owner's behalf, since the invitation *is* the owner's
/// authorization. No operator/owner session is involved (the invitee is another user).
pub fn channel_invite_router(channels: Arc<SqliteChannelStore>) -> Router {
    Router::new()
        .route("/channel/invite/challenge", post(channel_invite_challenge))
        .route("/channel/invite/redeem", post(channel_invite_redeem))
        .with_state(channels)
}

/// TTL (seconds) for a redemption challenge nonce (#108): short — it exists only to be
/// signed into the immediately-following redeem.
const INVITE_CHALLENGE_TTL_SECS: u64 = 120;

#[derive(Serialize, Deserialize)]
struct InviteChallengeResp {
    /// A fresh, single-use nonce (hex) the invitee binds into its redemption signature.
    challenge: String,
}

/// `POST /channel/invite/challenge` (#108 defense-in-depth): issue a fresh, single-use
/// redemption challenge. The invitee signs it into `invitation_redeem_challenge_bytes`
/// and presents it (+ the nonce) to `/channel/invite/redeem`, so a captured redemption is
/// non-replayable even independent of the single-use invitation record. Public — the
/// nonce is not a secret and confers nothing on its own.
async fn channel_invite_challenge(
    State(channels): State<Arc<SqliteChannelStore>>,
) -> Result<Json<InviteChallengeResp>, (StatusCode, String)> {
    let nonce = channels
        .issue_challenge(now_secs(), INVITE_CHALLENGE_TTL_SECS)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(InviteChallengeResp { challenge: hex_encode(&nonce) }))
}

#[derive(Deserialize)]
struct InviteRedeemReq {
    /// The operator-signed invitation, hex of [`SignedChannelInvitation::encode`].
    invitation: String,
    /// The invitee's ed25519 signature over the redemption bytes, hex — proves the
    /// intended invitee accepted + chose `holder`. Without `challenge` it covers
    /// `invitation_redeem_bytes`; with `challenge` it covers
    /// `invitation_redeem_challenge_bytes` (the nonce-bound v2 form).
    redeem_sig: String,
    /// The member (holder) key the invitee will use on the channel, hex.
    holder: String,
    /// The holder's X25519 Noise static key, hex.
    noise_pubkey: String,
    /// The holder's attestation over `noise_pubkey` (#101), hex.
    noise_attestation: String,
    /// Optional fresh CP challenge nonce (#108, hex from `/channel/invite/challenge`).
    /// When present, the redemption must be bound to it and it is consumed single-use —
    /// belt-and-braces over the invitation single-use record. Absent → the static path.
    #[serde(default)]
    challenge: Option<String>,
}

async fn channel_invite_redeem(
    State(channels): State<Arc<SqliteChannelStore>>,
    Json(req): Json<InviteRedeemReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    use ct_common::channel::{verify_member_noise_attestation, SignedChannelInvitation};

    let inv_bytes = hex_decode(&req.invitation)
        .ok_or((StatusCode::BAD_REQUEST, "malformed invitation".to_string()))?;
    let signed = SignedChannelInvitation::decode(&inv_bytes)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invitation: {e}")))?;
    let redeem_sig = hex_decode_64(&req.redeem_sig)
        .ok_or((StatusCode::BAD_REQUEST, "malformed redeem_sig".to_string()))?;
    let holder = hex_decode_32(&req.holder)
        .ok_or((StatusCode::BAD_REQUEST, "malformed holder".to_string()))?;
    let noise_pubkey = hex_decode_32(&req.noise_pubkey)
        .ok_or((StatusCode::BAD_REQUEST, "malformed noise_pubkey".to_string()))?;
    let noise_attestation = hex_decode_64(&req.noise_attestation)
        .ok_or((StatusCode::BAD_REQUEST, "malformed noise_attestation".to_string()))?;

    let channel = signed.invitation.channel;
    // The operator authority is the channel's registered signing key; an unknown
    // channel has no operator, so a redemption for it is a 404.
    let operator = channels
        .operator_pubkey(&channel)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "unknown channel".to_string()))?;

    // Proof 1: the operator-signed invitation is authentic + current.
    let now = now_secs();
    ct_common::channel::verify_invitation(&operator, &signed, now).map_err(|e| {
        let code = match e {
            ct_common::channel::GrantError::Expired => StatusCode::GONE,
            _ => StatusCode::FORBIDDEN,
        };
        (code, format!("invitation: {e}"))
    })?;
    // Proof 2: the intended invitee accepted + bound this holder key. Two variants:
    // - with a fresh CP `challenge` (#108 defense-in-depth): the redemption is bound to a
    //   single-use nonce we consume here, so a captured signature is non-replayable even
    //   independent of the invitation single-use record below;
    // - without one: the static v1 redemption (still protected by single-use consumption).
    let invitee = signed.invitation.invitee_identity;
    let redemption_ok = match &req.challenge {
        Some(ch) => {
            let nonce = hex_decode_32(ch)
                .ok_or((StatusCode::BAD_REQUEST, "malformed challenge".to_string()))?;
            if !channels
                .consume_challenge(&nonce, now)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            {
                return Err((StatusCode::FORBIDDEN, "stale or unknown challenge".to_string()));
            }
            ct_common::channel::verify_invitation_redemption_challenge(
                &channel, &invitee, &holder, &nonce, &redeem_sig,
            )
        }
        None => ct_common::channel::verify_invitation_redemption(&channel, &invitee, &holder, &redeem_sig),
    };
    if !redemption_ok {
        return Err((StatusCode::FORBIDDEN, "invitation redemption proof invalid".to_string()));
    }
    // Proof 3 (#101): the Noise key is attested by the holder, so a substituted key
    // (e.g. by a DB-controlling operator) is rejected before it can MITM the A2A path.
    if !verify_member_noise_attestation(&channel, &holder, &noise_pubkey, &noise_attestation) {
        return Err((
            StatusCode::FORBIDDEN,
            "noise_attestation does not verify against the holder key".to_string(),
        ));
    }
    // #108: enforce single-use. The invitation is a static signed object with a static
    // redemption proof, so without this a **revoked** member could replay the identical
    // redemption to restore membership until expiry (bypassing remove_member). Consume it
    // by its operator signature *after* the proofs verify (a bad proof burns nothing) and
    // *before* add_member; a replay is a 409. Mirrors verify_fresh/ReplayCache for grants.
    let fresh = channels
        .consume_invitation(&signed.signature, signed.invitation.expires_at, now)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if !fresh {
        return Err((
            StatusCode::CONFLICT,
            "invitation already redeemed (single-use)".to_string(),
        ));
    }
    // The invitation is the owner's authorization, so add the member on the owner's
    // behalf (add_member is owner-scoped; look up the channel's owner to satisfy it).
    let owner = channels
        .channel_owner(&channel)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "unknown channel".to_string()))?;
    let ok = channels
        .add_member(&channel, &owner, &holder, &noise_pubkey, &noise_attestation)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if ok {
        Ok(StatusCode::OK)
    } else {
        // The owner was looked up from the same channel row, so a false here means the
        // channel vanished between reads — treat as gone.
        Err((StatusCode::NOT_FOUND, "channel no longer registered".to_string()))
    }
}

/// Extract + verify the `Authorization: Bearer` token against `handle`'s current
/// verifier, returning the authenticated subject. Shared by every self-scoped
/// endpoint so the acting identity always comes from a verified token, never the
/// request body.
///
/// #328: `/me/*` routers are always mounted now (no more boot-time
/// present-or-absent decision), so "no verifier installed yet" is a real,
/// distinct state from "bad/missing token" -- surfaced as `503` (retry later,
/// the background refresh may still bring it up) rather than `401` (this
/// specific request's credentials are the problem) or the old, indistinguishable
/// `404` (route not found at all).
fn subject_of(
    handle: &OidcVerifierHandle,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, String)> {
    let verifier = handle.get().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "OIDC verifier not yet available -- a background refresh is retrying; check /status's oidc_enabled (#328)".to_string(),
    ))?;
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "missing bearer token".to_string()))?;
    verifier
        .subject(token)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))
}

/// #237-follow: resolve the acting subject for the Topology Editor's owner-scoped
/// endpoints from EITHER a valid portal session cookie OR a valid OIDC bearer token,
/// whichever is present -- tried in that order. The editor page's own client-side JS
/// (`EDITOR_JS`'s `fetch()` calls for mode/suggest/agents/edges) authenticates the only
/// way a browser page can: via the ambient session cookie the portal login flow already
/// set, not a bearer token it has no way to hold. Before this, `GET .../editor` alone
/// required a header no real portal session ever carries, and even manually supplying one
/// wouldn't have helped: the page's own fetch() calls send cookies, never an Authorization
/// header, so the editor was fully unreachable/inert for an actual logged-in user.
///
/// This is not a scope-widening: both paths resolve to the exact same "subject" identity
/// concept the topology store's ownership model already keys every operation on, and the
/// portal session cookie is itself minted only after a real OIDC login (`portal_callback`)
/// -- accepting it here is accepting the SAME verified identity via its second, browser-
/// native delivery mechanism, not a weaker check.
fn subject_of_topology(
    session_key: &[u8],
    verifier: &OidcVerifierHandle,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, String)> {
    if let Some(claims) = crate::portal::session_claims_for(session_key, headers) {
        return Ok(claims.subject);
    }
    subject_of(verifier, headers)
}

/// Like [`subject_of_topology`], but also returns the caller's verified e-mail when resolved
/// via the portal session cookie (#107-complex share checks need it). A bearer-token caller
/// has no email available here — `None` — so shared-topology access is only reachable via a
/// real portal login today, which is the only path that ever carries a verified email to
/// begin with.
fn topology_actor_of(
    session_key: &[u8],
    verifier: &OidcVerifierHandle,
    headers: &HeaderMap,
) -> Result<(String, Option<String>), (StatusCode, String)> {
    if let Some(claims) = crate::portal::session_claims_for(session_key, headers) {
        return Ok((claims.subject, claims.email));
    }
    subject_of(verifier, headers).map(|s| (s, None))
}

/// Extract + verify the bearer token, returning the authenticated subject.
fn authed_subject(state: &AuthedState, headers: &HeaderMap) -> Result<String, (StatusCode, String)> {
    subject_of(&state.verifier, headers)
}

/// The authenticated customer's own account view (#26): account id, current
/// credit balance (Guthaben) and the verified subject. Strictly self-scoped —
/// the subject comes from the verified token, never from the request body — so a
/// caller can only ever see their own account. Serves the portal account page.
#[derive(Serialize, Deserialize)]
struct MeAccountResp {
    account: String,
    balance: u64,
    subject: String,
}

async fn me_account(
    State(state): State<AuthedState>,
    headers: HeaderMap,
) -> Result<Json<MeAccountResp>, (StatusCode, String)> {
    let sub = authed_subject(&state, &headers)?;
    let account = state
        .ledger
        .account_for_subject(&sub)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let balance = state
        .ledger
        .balance(&account)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(MeAccountResp {
        account: hex_encode(&account.0),
        balance,
        subject: sub,
    }))
}

#[derive(Deserialize)]
struct MeIssueReq {
    price: u64,
}

async fn me_issue(
    State(state): State<AuthedState>,
    headers: HeaderMap,
    Json(req): Json<MeIssueReq>,
) -> Result<Json<TokenResp>, (StatusCode, String)> {
    let sub = authed_subject(&state, &headers)?;
    // Per-subject rate limit (M23.1): reject over-limit callers before touching
    // the ledger, so a throttled request spends no credit.
    let window = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / ISSUE_WINDOW_SECS)
        .unwrap_or(0);
    if !state.issue_limiter.lock_safe().allow(&sub, window) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "issue rate limit exceeded".to_string(),
        ));
    }
    // #87 SEC87a: reject an underpayment (notably price:0) before the ledger, so a
    // funded, in-rate subject still cannot mint a token for less than TOKEN_PRICE.
    if !crate::billing::issuance_price_ok(req.price) {
        return Err((
            StatusCode::PAYMENT_REQUIRED,
            format!("a routing token costs at least {} credit(s)", crate::billing::TOKEN_PRICE),
        ));
    }
    let account = state
        .ledger
        .account_for_subject(&sub)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Debit the authenticated user's own account; mint only if they can pay.
    state.ledger.debit(&account, req.price).map_err(|e| {
        let code = match &e {
            LedgerOpError::Ledger(LedgerError::InsufficientCredit { .. }) => {
                StatusCode::PAYMENT_REQUIRED
            }
            LedgerOpError::Ledger(LedgerError::UnknownAccount) => StatusCode::NOT_FOUND,
            LedgerOpError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (code, e.to_string())
    })?;
    let mut token = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token);
    Ok(Json(TokenResp {
        token: hex_encode(&token),
    }))
}

/// Build the health/readiness router (M21.1a): `GET /healthz` (liveness, always
/// `200`) and `GET /readyz` (readiness — `200` if the database is reachable,
/// else `503`). Used by orchestrator liveness/readiness probes.
pub fn health_router(ledger: Arc<SqliteLedger>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route("/readyz", get(readyz))
        .with_state(ledger)
}

async fn readyz(State(ledger): State<Arc<SqliteLedger>>) -> StatusCode {
    match ledger.ping() {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// Shared state for the operator status view (F4.1): the three durable stores
/// plus the service start instant for uptime (F4.2).
#[derive(Clone)]
pub struct StatusState {
    enrollment: Arc<SqliteEnrollment>,
    registry: Arc<SqliteRegistry>,
    ledger: Arc<SqliteLedger>,
    /// The public agent directory (#144 ②) and workflow-pipeline registry (#174 B) —
    /// shared with `agent_directory_router`/`pipeline_registry_router` (same Arc,
    /// same underlying tables) so the landing page's counts and the actual
    /// discovery endpoints can never drift apart.
    agent_directory: Arc<SqliteAgentDirectory>,
    pipeline_registry: Arc<SqlitePipelineRegistry>,
    started: std::time::Instant,
    /// When set, `/status.tunnels` reports the edge's live registration count
    /// scraped from this URL (the edge's `/metrics` `ct_edge_active_tunnels`
    /// gauge, #10) instead of the CP rendezvous registry — which the live
    /// onboard/serve path never writes, so it read 0 even with active tunnels
    /// (#17). Falls back to the registry count if the scrape fails or is unset.
    edge_metrics_url: Option<String>,
    http: reqwest::Client,
    /// #328: a live handle, not a boot-time snapshot -- `oidc.is_ready()` reflects
    /// the CURRENT state, so a background refresh task healing a failed boot-time
    /// fetch becomes visible on `/status` within one poll, no restart needed.
    /// `CT_OIDC_ISSUER` unset entirely also reads not-ready here -- deliberately:
    /// from the outside, "OIDC not configured" and "OIDC configured but not
    /// available yet" both mean the exact same thing for `/me/*`'s availability.
    oidc: OidcVerifierHandle,
}

/// Aggregated operator status — health plus metadata counts the operator
/// legitimately sees (never payload; consistent with ADR-0016 / the threat model).
#[derive(Serialize, Deserialize)]
pub struct StatusResp {
    /// Database reachable (same signal as `/readyz`).
    pub ready: bool,
    /// Registered tunnels.
    pub tunnels: i64,
    /// Enrolled agents (bound public keys).
    pub agents: i64,
    /// Open accounts.
    pub accounts: i64,
    /// Confirmed payments.
    pub payments_confirmed: i64,
    /// Published workflow pipelines (#174 B `GET /registry/pipelines`).
    pub pipelines_published: i64,
    /// Publicly discoverable agents (#144 ② `GET /registry/agents`) — distinct
    /// from `agents` above, which counts raw enrollment (join-token redemptions),
    /// not agents that opted into the searchable directory.
    pub agents_directory: i64,
    /// Seconds since the control plane started.
    pub uptime_seconds: u64,
    /// #328: whether `/me/*` is actually mounted and serving right now -- `false`
    /// covers both "CT_OIDC_ISSUER unset" and "set but the boot-time JWKS fetch
    /// never got a usable key", since both mean the same thing from here: nothing
    /// under `/me/*` will authenticate successfully until this reads `true`.
    pub oidc_enabled: bool,
}

/// Build the status router (F4.1): `GET /status` returns aggregated counts as
/// JSON, backing the operator landing page (F4.2).
pub fn status_router(
    enrollment: Arc<SqliteEnrollment>,
    registry: Arc<SqliteRegistry>,
    ledger: Arc<SqliteLedger>,
    agent_directory: Arc<SqliteAgentDirectory>,
    pipeline_registry: Arc<SqlitePipelineRegistry>,
    edge_metrics_url: Option<String>,
    oidc: OidcVerifierHandle,
) -> Router {
    Router::new().route("/status", get(status_handler)).with_state(StatusState {
        enrollment,
        registry,
        ledger,
        agent_directory,
        pipeline_registry,
        started: std::time::Instant::now(),
        edge_metrics_url,
        http: reqwest::Client::new(),
        oidc,
    })
}

async fn status_handler(State(s): State<StatusState>) -> Json<StatusResp> {
    Json(StatusResp {
        ready: s.ledger.ping().is_ok(),
        tunnels: live_tunnel_count(&s).await,
        agents: s.enrollment.agent_count().unwrap_or(0),
        pipelines_published: s.pipeline_registry.list().map(|v| v.len() as i64).unwrap_or(0),
        agents_directory: s.agent_directory.search(None, None).map(|v| v.len() as i64).unwrap_or(0),
        accounts: s.ledger.account_count().unwrap_or(0),
        payments_confirmed: s.ledger.confirmed_payment_count().unwrap_or(0),
        uptime_seconds: s.started.elapsed().as_secs(),
        oidc_enabled: s.oidc.is_ready(),
    })
}

/// Resolve the operator "registered tunnels" count. The live tunnel registry
/// lives in the **edge** (`EdgeState`, evicted on drop, #8), exposed as the
/// `ct_edge_active_tunnels` gauge on the edge `/metrics` (#10). When an edge
/// metrics URL is configured, report that live count; otherwise (or if the
/// scrape fails) fall back to the CP rendezvous registry. The CP registry is not
/// written by the onboard/serve path, so without this `/status.tunnels` read 0
/// even with active tunnels (#17).
async fn live_tunnel_count(s: &StatusState) -> i64 {
    if let Some(url) = &s.edge_metrics_url {
        if let Ok(resp) = s
            .http
            .get(url.as_str())
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .await
        {
            if let Ok(body) = resp.text().await {
                if let Some(n) = parse_metric(&body, "ct_edge_active_tunnels") {
                    return n;
                }
            }
        }
    }
    s.registry.tunnel_count().unwrap_or(0)
}

/// Parse a Prometheus gauge value by metric name from a metrics exposition body:
/// the first `<name> <value>` sample line, ignoring `# HELP`/`# TYPE` comments.
fn parse_metric(body: &str, name: &str) -> Option<i64> {
    body.lines()
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| {
            let mut it = l.split_whitespace();
            match (it.next(), it.next()) {
                (Some(k), Some(v)) if k == name => v.parse::<f64>().ok().map(|f| f as i64),
                _ => None,
            }
        })
}

/// The operator landing page (F4.2): a single self-contained HTML document (no
/// external assets, CSP-safe) that fetches `/status` and renders the health and
/// metadata counts, auto-refreshing. Shows only what the operator legitimately
/// sees — never payload.
const LANDING_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bunsenbrenner.org — create at home, publish world wide</title>
<style>
 :root{
  --bg:#0c111d; --panel:#141b2c; --panel2:#1a2338; --line:#2a3450; --line-soft:#212a41;
  --text:#eef1f7; --muted:#8a93ad; --muted2:#c3c9db;
  --accent:#d98a4f; --accent-soft:#a8683a; --accent2:#5fb8ab;
  --mono:ui-monospace,SFMono-Regular,"SF Mono","Cascadia Code",Menlo,Consolas,monospace;
  --serif:ui-serif,Georgia,"Iowan Old Style","Palatino Linotype",serif;
 }
 @media (prefers-color-scheme: light){
  :root{
   --bg:#f5f7fb; --panel:#ffffff; --panel2:#eef1f8; --line:#d7deec; --line-soft:#e3e8f3;
   --text:#131a2c; --muted:#5b6478; --muted2:#333d54;
   --accent:#b8672f; --accent-soft:#8f4f24; --accent2:#2f8a7d;
  }
 }
 *{box-sizing:border-box}
 html{scroll-behavior:smooth}
 body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;margin:0;background:var(--bg);color:var(--text);line-height:1.6;-webkit-font-smoothing:antialiased}
 a{color:inherit}
 code{font-family:var(--mono)}
 h1,h2,h3{font-family:var(--serif);font-weight:600;letter-spacing:-.01em}

 .hero{border-bottom:1px solid var(--line);
  background-image:linear-gradient(var(--line-soft) 1px, transparent 1px),linear-gradient(90deg, var(--line-soft) 1px, transparent 1px);
  background-size:34px 34px}
 .hero-inner{max-width:68rem;margin:0 auto;padding:0 1.5rem}
 .hero-top{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;row-gap:.6rem;column-gap:.75rem;padding:1.4rem 0}
 .brand{font-size:1.24rem;font-weight:700;letter-spacing:-.01em;display:flex;align-items:center;gap:.55rem;font-family:var(--serif);flex-shrink:0}
 .brand .flame{width:9px;height:9px;border-radius:50%;background:var(--accent);flex-shrink:0;box-shadow:0 0 0 3px rgba(217,138,79,.22)}
 .brand .tld{color:var(--muted);font-weight:400}
 .hero-nav{display:flex;align-items:center;flex-wrap:wrap;gap:.6rem 1.2rem;font-size:.88rem;min-width:0}
 .hero-nav a.plain{text-decoration:none;color:var(--muted2);white-space:nowrap}
 .hero-nav a.plain:hover{color:var(--text)}

 .hero-grid{display:grid;grid-template-columns:1.05fr 1fr;gap:3rem;align-items:center;padding:2.6rem 0 3.4rem}

 .eyebrow{font-family:var(--mono);font-size:.76rem;letter-spacing:.08em;text-transform:uppercase;color:var(--accent2);
  display:flex;align-items:center;gap:.5rem;margin:0 0 1.1rem}
 .eyebrow::before{content:"";width:1.4rem;height:1px;background:var(--accent2)}

 h1{font-size:clamp(2rem,4.3vw,2.9rem);line-height:1.15;margin:0 0 1.05rem;color:var(--text)}
 .lede{font-size:1.06rem;color:var(--muted2);max-width:34rem;margin:0 0 1.6rem}

 .trust-strip{display:flex;flex-wrap:wrap;gap:1.2rem;margin:1.1rem 0 0;font-size:.83rem;color:var(--muted)}
 .trust-strip span{display:flex;align-items:center;gap:.45rem}
 .trust-strip .dot{width:6px;height:6px;border-radius:50%;background:var(--accent2);flex-shrink:0}

 a.btn{display:inline-flex;align-items:center;gap:.4rem;background:var(--accent);color:#20130a;
  padding:.65rem 1.2rem;border-radius:6px;font-weight:600;font-size:.92rem;text-decoration:none;border:1px solid transparent;
  transition:filter .15s ease,transform .15s ease}
 a.btn:hover{filter:brightness(1.08);transform:translateY(-1px)}
 a.btn:active{transform:translateY(0)}
 a.btn.secondary{background:transparent;color:var(--text);border-color:var(--line)}
 a.btn.secondary:hover{background:var(--panel2);border-color:var(--muted)}

 .join{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:1.15rem 1.25rem;max-width:30rem}
 .join label{display:block;font-family:var(--mono);font-size:.72rem;letter-spacing:.05em;text-transform:uppercase;
  color:var(--muted);margin-bottom:.55rem}
 .join-row{display:flex;gap:.55rem}
 .join input[type=email]{flex:1;min-width:0;background:var(--bg);border:1px solid var(--line);border-radius:6px;
  padding:.62rem .8rem;color:var(--text);font-size:.94rem;font-family:inherit}
 .join input[type=email]:focus{outline:none;border-color:var(--accent2)}
 .join button{cursor:pointer}
 .join .fine{margin:.75rem 0 0;font-size:.79rem;color:var(--muted)}
 .join .fine strong{color:var(--muted2);font-weight:600}
 .join-divider{display:flex;align-items:center;gap:.7rem;color:var(--muted);font-size:.72rem;text-transform:uppercase;
  letter-spacing:.05em;margin:.9rem 0}
 .join-divider::before,.join-divider::after{content:"";flex:1;height:1px;background:var(--line)}
 .join-providers{display:flex;gap:.6rem}
 a.provider{flex:1;display:flex;align-items:center;justify-content:center;gap:.55rem;background:var(--bg);
  border:1px solid var(--line);border-radius:6px;padding:.55rem .8rem;color:var(--text);text-decoration:none;
  font-weight:600;font-size:.86rem;transition:border-color .15s ease,background .15s ease}
 a.provider:hover{border-color:var(--muted);background:var(--panel2)}
 a.provider svg{width:1rem;height:1rem;flex-shrink:0}
 .alt-signin{margin:.85rem 0 0;font-size:.82rem;color:var(--muted)}
 .alt-signin a{color:var(--muted2);text-decoration:underline}

 .diagram-card{border:1px solid var(--line);border-radius:12px;background:var(--panel);overflow:hidden}
 .diagram-head{display:flex;justify-content:space-between;align-items:center;padding:.75rem .95rem;
  border-bottom:1px solid var(--line);font-family:var(--mono);font-size:.7rem;color:var(--muted)}
 .diagram-head .live{display:flex;align-items:center;gap:.4rem;color:var(--accent2)}
 .diagram-head .live i{width:6px;height:6px;border-radius:50%;background:var(--accent2);display:inline-block;
  animation:pulse 1.6s ease-in-out infinite;font-style:normal}
 @keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
 canvas#net{display:block;width:100%;height:220px}
 .diagram-foot{display:flex;justify-content:space-between;padding:.65rem .95rem;border-top:1px solid var(--line);
  font-family:var(--mono);font-size:.68rem;color:var(--muted)}
 @media (prefers-reduced-motion: reduce){ .diagram-head .live i{animation:none} }
 @media (max-width:860px){ .hero-grid{grid-template-columns:1fr} }

 /* -------- inline mini-diagrams distributed through the page -------- */
 .use-case{display:grid;grid-template-columns:1fr 1.15fr;gap:1.8rem;align-items:center;margin:1.6rem 0}
 .use-case.reverse{grid-template-columns:1.15fr 1fr}
 .use-case.reverse .diagram-card{order:-1}
 .use-case h3{font-size:1.02rem;margin:0 0 .5rem;font-family:inherit;font-weight:700}
 .use-case p{margin:0;color:var(--muted2);font-size:.9rem}
 .use-case .diagram-card canvas{height:160px}
 @media (max-width:760px){ .use-case,.use-case.reverse{grid-template-columns:1fr} .use-case.reverse .diagram-card{order:0} }

 .alt-link{margin:.7rem 0 0;font-size:.82rem;color:var(--muted)}
 .alt-link a{text-decoration:none;color:var(--muted2)}
 .alt-link a:hover{text-decoration:underline}

 .code-block{margin-top:.7rem;border:1px solid var(--line);border-radius:8px;overflow:hidden;background:var(--bg)}
 .code-block-head{display:flex;justify-content:space-between;align-items:center;gap:.8rem;background:var(--panel2);
  padding:.55rem .55rem .55rem .9rem;font-family:var(--mono);font-size:.74rem;color:var(--muted)}
 .copy-btn{background:var(--panel);border:1px solid var(--line);color:var(--text);flex-shrink:0;font-family:var(--mono);
  border-radius:6px;padding:.35rem .7rem;font-size:.72rem;font-weight:600;cursor:pointer;transition:border-color .15s ease}
 .copy-btn:hover{border-color:var(--muted)}

 .callout{background:var(--panel);border:1px solid var(--line);border-left:2px solid var(--accent2);border-radius:8px;
  padding:1.1rem 1.3rem;font-size:.92rem;color:var(--muted2);margin-top:2rem}
 .callout a{color:var(--accent2)}

 .demo-carousel{display:flex;gap:1rem;overflow-x:auto;padding:.2rem .1rem .9rem;scroll-snap-type:x mandatory;-webkit-overflow-scrolling:touch}
 .demo-carousel::-webkit-scrollbar{height:6px}
 .demo-carousel::-webkit-scrollbar-thumb{background:var(--line);border-radius:3px}
 .demo-card{flex:0 0 auto;width:min(80vw,300px);scroll-snap-align:start;background:var(--panel);border:1px solid var(--line);
  border-radius:12px;padding:1.1rem 1.2rem;display:flex;flex-direction:column;gap:.7rem}
 .demo-card-top{display:flex;align-items:center;justify-content:space-between;gap:.55rem;font-family:var(--mono)}
 .demo-name{color:var(--muted2);font-weight:600;font-size:.82rem}
 .demo-badge{display:flex;align-items:center;gap:.4rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;font-size:.66rem}
 .demo-badge.live{color:var(--accent2)}
 .demo-badge i{width:6px;height:6px;border-radius:50%;background:currentColor;display:inline-block;font-style:normal}
 .demo-badge.live i{animation:pulse 1.6s ease-in-out infinite}
 .demo-card p{margin:0;color:var(--muted2);font-size:.87rem;flex:1}
 .demo-links{display:flex;align-items:center;gap:1rem}
 .demo-links a.btn{padding:.45rem .95rem;font-size:.83rem}
 .demo-links a.plain{color:var(--muted2);text-decoration:none;font-size:.83rem}
 .demo-links a.plain:hover{text-decoration:underline}
 @media (prefers-reduced-motion: reduce){ .demo-badge.live i{animation:none} }

 main{max-width:68rem;margin:0 auto;padding:3.2rem 1.5rem 2rem}
 .features{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:1px;background:var(--line);
  border:1px solid var(--line);border-radius:12px;overflow:hidden;margin:0 0 3rem}
 .feature{padding:1.25rem 1.35rem;background:var(--panel)}
 .feature h3{margin:0 0 .35rem;font-size:1rem;font-family:inherit;font-weight:700} .feature p{margin:0;color:var(--muted);font-size:.87rem}

 .lab{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:1.7rem 1.9rem;margin-bottom:3rem}
 .lab h2{margin-top:0}

 h2{font-size:1.22rem;color:var(--text);margin:0 0 .8rem}
 .section{margin-bottom:3rem}
 .section-head{display:flex;justify-content:space-between;align-items:baseline;gap:1rem;flex-wrap:wrap;margin-bottom:.6rem}
 .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1px;background:var(--line);
  border:1px solid var(--line);border-radius:12px;overflow:hidden;margin-top:1rem}
 .card{background:var(--panel);padding:1.05rem 1.2rem}
 .n{font-family:var(--mono);font-size:1.7rem;font-weight:600;font-variant-numeric:tabular-nums} .l{color:var(--muted);font-size:.85rem}
 .ok{color:var(--accent2)} .bad{color:#e5654f}
 ul.list{list-style:none;margin:.5rem 0 0;padding:0;display:flex;flex-direction:column;gap:1px;background:var(--line);
  border:1px solid var(--line);border-radius:12px;overflow:hidden}
 ul.list li{background:var(--panel);padding:.8rem 1.05rem;
  display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.5rem}
 ul.list .id{font-weight:600;font-family:var(--mono);font-size:.88rem} ul.list .meta{color:var(--muted);font-size:.85rem}
 ul.list a{text-decoration:none;color:var(--muted2)} ul.list a:hover{text-decoration:underline}
 .empty{color:var(--muted);font-size:.85rem;padding:.5rem 0}

 .mcp-strip{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1.3rem;
  border:1px solid var(--line);border-radius:12px;padding:1.4rem 1.6rem;background:var(--panel)}
 .mcp-strip p{margin:0;color:var(--muted2);font-size:.92rem;max-width:40rem}
 .mcp-strip .install{font-family:var(--mono);font-size:.76rem;background:var(--bg);border:1px solid var(--line);
  border-radius:6px;padding:.55rem .85rem;color:var(--muted);white-space:nowrap}

 .support{background:var(--panel);border:1px solid var(--line);
  border-radius:12px;padding:1.6rem 1.8rem;display:flex;justify-content:space-between;align-items:center;gap:1.5rem;flex-wrap:wrap}
 .support p{margin:0;color:var(--muted2);max-width:32rem;font-size:.95rem}
 .support .actions{display:flex;gap:.7rem;flex-wrap:wrap}

 footer.site-footer{border-top:1px solid var(--line);padding:2rem 1.5rem}
 footer.site-footer .footer-inner{max-width:68rem;margin:0 auto;display:flex;justify-content:space-between;
  align-items:center;flex-wrap:wrap;gap:1rem}
 footer.site-footer .foot{color:var(--muted);font-size:.82rem;max-width:34rem}
 footer.site-footer .legal-links{display:flex;gap:.9rem;flex-wrap:wrap;font-size:.83rem;font-family:var(--mono)}
 footer.site-footer .legal-links a{color:var(--muted2);text-decoration:none}
 footer.site-footer .legal-links a:hover{text-decoration:underline}
 footer.site-footer .copyright{color:var(--muted);font-size:.8rem;width:100%;margin-top:1.2rem;padding-top:1.2rem;
  border-top:1px solid var(--line)}

 .cookie-notice{position:fixed;left:1rem;right:1rem;bottom:1rem;max-width:40rem;margin:0 auto;background:var(--panel);
  border:1px solid var(--line);border-radius:10px;padding:1rem 1.2rem;font-size:.85rem;color:var(--muted2);
  box-shadow:0 10px 30px rgba(0,0,0,.3);z-index:100;display:none}
 .cookie-notice.show{display:flex;gap:1rem;align-items:center;flex-wrap:wrap;justify-content:space-between}
 .cookie-notice button{background:var(--accent);color:#20130a;border:none;border-radius:6px;padding:.5rem 1.1rem;font-weight:600;cursor:pointer}

 @media (max-width:640px){ .support{flex-direction:column;align-items:flex-start} }
</style></head><body>

<header class="hero">
 <div class="hero-inner">
  <div class="hero-top">
   <div class="brand"><span class="flame"></span>Bunsenbrenner<span class="tld">.org</span></div>
   <div class="hero-nav">
    <a class="plain" href="/llms.txt">For AI agents &rarr;</a>
    <a class="btn secondary" href="/portal">Sign in &rarr;</a>
   </div>
  </div>

  <div class="hero-grid" id="get-started">
   <div>
    <div class="eyebrow">Self-hosted &middot; end-to-end encrypted</div>
    <h1>Better homemade ideas.</h1>
    <p class="lede">
     But bunsenbrenner.org is far more than just a tunnel. It's the foundation for your decentralized
     projects. One device is enough to start. Later, you effortlessly combine several machines once an
     idea grows and demands more computing power.
    </p>
    <p class="lede">
     Whether you're connecting distributed edge-computing nodes, orchestrating autonomous AI agents, or
     wiring together protected microservices: you keep absolute control. Thanks to strict end-to-end
     encryption, absolutely nobody sees what's flowing through the connection — not even us.
    </p>

    <form class="join" action="/portal/login" method="get">
     <input type="hidden" name="register" value="1">
     <label for="email">Get your tunnel</label>
     <div class="join-row">
      <input id="email" name="login_hint" type="email" placeholder="you@example.com" autocomplete="email" required>
      <button class="btn" type="submit">Continue &rarr;</button>
     </div>
     <div class="join-divider"><span>or</span></div>
     <div class="join-providers">
      <a class="provider" href="/portal/login?kc_idp_hint=google">
       <svg viewBox="0 0 18 18" aria-hidden="true"><path fill='#4285F4' d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84c-.21 1.13-.84 2.09-1.8 2.73v2.27h2.92c1.7-1.57 2.68-3.87 2.68-6.64z"/><path fill='#34A853' d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.92-2.27c-.81.54-1.84.86-3.04.86-2.34 0-4.32-1.58-5.03-3.71H.96v2.33C2.44 15.98 5.48 18 9 18z"/><path fill='#FBBC05' d="M3.97 10.7c-.18-.54-.28-1.11-.28-1.7s.1-1.16.28-1.7V4.97H.96A8.99 8.99 0 0 0 0 9c0 1.45.35 2.83.96 4.03l3.01-2.33z"/><path fill='#EA4335' d="M9 3.58c1.32 0 2.51.45 3.44 1.35l2.59-2.59C13.46.89 11.43 0 9 0 5.48 0 2.44 2.02.96 4.97l3.01 2.33C4.68 5.16 6.66 3.58 9 3.58z"/></svg>
       Google
      </a>
      <a class="provider" href="/portal/login?kc_idp_hint=github">
       <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
       GitHub
      </a>
     </div>
     <p class="alt-signin">Already have an account? <a href="/portal">Sign in →</a></p>
    </form>
   </div>

   <div>
    <div class="diagram-card">
     <div class="diagram-head">
      <span>ROUTE · your device &rarr; agent &rarr; edge &rarr; browser</span>
      <span class="live"><i></i>encrypted</span>
     </div>
     <canvas id="net" width="600" height="220" aria-label="Animated diagram: an encrypted packet travels from your device through the agent and edge to the browser"></canvas>
     <div class="diagram-foot">
      <span>Noise_IK &middot; QUIC / TLS 1.3</span>
      <span>0 open ports on your device</span>
     </div>
    </div>
    <div class="trust-strip">
     <span><span class="dot"></span>Open source (for private use) — audit the code yourself</span>
     <span><span class="dot"></span>Zero-knowledge transport</span>
     <span><span class="dot"></span>No credit card required</span>
     <span><span class="dot"></span>First tunnel live in minutes</span>
     <span><span class="dot"></span>DSGVO</span>
     <span><span class="dot"></span>European Service</span>
     <span><span class="dot"></span>Focus on Standards</span>
    </div>
   </div>
  </div>
 </div>
</header>

<main>

 <div class="section" id="demos">
  <div class="section-head"><h2>See it live</h2><a class="btn secondary" href="https://github.com/scimbe/CADS-Tunnel" target="_blank" rel="noopener">All demos on GitHub &rarr;</a></div>
  <div class="demo-carousel">
   <div class="demo-card">
    <div class="demo-card-top"><span class="demo-name">flappy-demo</span><span class="demo-badge live"><i></i>live</span></div>
    <p>Flappy Pipeline Studio — customize and generate your own Flappy Bird game over the Agent-Fabric channel.</p>
    <div class="demo-links"><a class="btn" href="https://flappy-demo.bunsenbrenner.org" target="_blank" rel="noopener">Try it &rarr;</a><a class="plain" href="https://github.com/scimbe/CADS-flappy-demo" target="_blank" rel="noopener">Source</a></div>
   </div>
   <div class="demo-card">
    <div class="demo-card-top"><span class="demo-name">cookbook-demo</span><span class="demo-badge"><i></i>source</span></div>
    <p>Recipe generator with photo input, wired over the Agent-Fabric channel — a reference pipeline. Live instance coming soon.</p>
    <div class="demo-links"><a class="plain" href="https://github.com/scimbe/CADS-cookbook-demo" target="_blank" rel="noopener">Source &rarr;</a></div>
   </div>
   <div class="demo-card">
    <div class="demo-card-top"><span class="demo-name">a2a-demo</span><span class="demo-badge"><i></i>source</span></div>
    <p>Live dashboard over a real Agent-Fabric channel call between two independent ct-agent processes.</p>
    <div class="demo-links"><a class="plain" href="https://github.com/scimbe/CADS-a2a-demo" target="_blank" rel="noopener">Source &rarr;</a></div>
   </div>
   <div class="demo-card">
    <div class="demo-card-top"><span class="demo-name">auction-demo</span><span class="demo-badge"><i></i>source</span></div>
    <p>Live dashboard over CADS-Tunnel's real workflow-pipeline auction algorithm (ct_common::pipeline).</p>
    <div class="demo-links"><a class="plain" href="https://github.com/scimbe/CADS-auction-demo" target="_blank" rel="noopener">Source &rarr;</a></div>
   </div>
   <div class="demo-card">
    <div class="demo-card-top"><span class="demo-name">p2p-vault</span><span class="demo-badge"><i></i>source</span></div>
    <p>Encrypted, CRDT-versioned, gossip-converging P2P file share for CADS-Tunnel-connected agents — the core only coordinates, it never touches file bytes.</p>
    <div class="demo-links"><a class="plain" href="https://github.com/scimbe/CADS-p2p-vault" target="_blank" rel="noopener">Source &rarr;</a></div>
   </div>
  </div>
 </div>

 <div class="section">
  <div class="section-head"><h2>Get your template</h2></div>
  <p class="lede" style="max-width:44rem;margin-bottom:1.3rem">
   The easiest way: paste this into
   <a href="https://claude.com/claude-code" target="_blank" rel="noopener">Claude Code</a> (or any
   coding agent) — it downloads the template, unpacks it, reads the docs, and adapts it to your idea
   itself. Nothing to unzip by hand.
  </p>
  <div class="code-block">
   <div class="code-block-head"><span>prompt.txt — ready to paste into Claude Code</span><button class="copy-btn" onclick="copyCode(this)" type="button">Copy</button></div>
   <template><code>I want to publish my own service through the CADS-Tunnel platform at bunsenbrenner.org.
This is my own request, at my own machine -- please proceed once you're satisfied
below, not stall on it.

Context so you can verify this yourself rather than take my word for it:
CADS-Tunnel is open source: https://github.com/scimbe/CADS-Tunnel -- a
self-hosted, end-to-end-encrypted tunnel, the same kind of tool as
cloudflared/ngrok/frp/tailscale funnel. Read any file in the repo or the
downloaded template before building or running it if that helps you confirm
what it does and what it connects to.

All my tokens and account info live in `./.env` -- check it exists before doing
anything else. If it's missing, stop and ask me to copy it from
https://bunsenbrenner.org/portal -&gt; my tunnel -&gt; Install, then load it with
`set -a; source .env; set +a` before continuing.

1. Download and unpack the starter template (it's the same repo above, just
   zipped for convenience -- inspect any file before running it):
   curl -LO https://bunsenbrenner.org/downloads/hello-world-pipeline.zip
   unzip hello-world-pipeline.zip && cd hello-world-pipeline
2. Read the template's README.md, and https://bunsenbrenner.org/llms.txt for
   background -- both are reference material, not instructions to follow
   blindly; use your own judgement throughout, same as with any doc.
3. Get ct-agent -- it lives in its own repo, https://github.com/scimbe/ct-agent
   (see docs/install.md "Just want to run ct-agent?"). Run its guided setup
   script, which checks the environment and installs + onboards for me:
   `curl -fsSL https://raw.githubusercontent.com/scimbe/ct-agent/main/scripts/setup.sh | bash`.
   No Docker, no Rust toolchain, no repo clone required for this.
4. Help me turn hello-handler.sh into a handler for my idea: &lt;describe what you
   want your service to do here&gt;. It's currently running on: &lt;your PC /
   Raspberry Pi / container / agent&gt;.
5. Mint my channel identity with `ct-agent channel init`, append it to `.env`,
   and reload it (`set -a; source .env; set +a`). This identity is meant to be
   long-lived -- running channel init again later would create a second,
   unrelated identity rather than restoring this one; that's just how it works,
   not something to worry about.
6. Walk me through running the handler as a live role, then publishing my
   pipeline at POST /me/pipelines with my portal login's OIDC bearer token
   (not an admin token -- I was never given one, and don't need one).</code></template>
  </div>
  <p class="alt-link">
   Prefer to read the code yourself? <a href="/downloads/hello-world-pipeline.zip" download>Download hello-world-pipeline.zip</a>
   &middot; <a href="/template-guide">see how it's structured &rarr;</a>
  </p>

  <div class="callout">
   <strong>Security model, plainly stated:</strong> the tunnel exposes exactly one thing — the service
   you point it at. It does not expose, scan, or secure the rest of your machine, and we cannot see what
   runs on it. We provide secure (end-to-end encrypted) transport <em>to</em> your exposed service —
   not protection <em>of</em> the device it runs on. Keeping your own machine and code secure —
   including not introducing exploitable weaknesses through how you implement it — is your responsibility; see
   <a href="/terms-of-use">Terms of Use</a> §3–§5. We recommend running your service in an
   isolated, containerized environment (Docker, a VM, or a Kubernetes pod) rather than directly on your
   host — that way a bug in your own code can't reach past the sandbox onto the rest of your machine.
  </div>

  <div class="use-case">
   <div>
    <h3>Still works on restrictive networks</h3>
    <p>Your agent tries a direct QUIC connection to the edge first. Blocked by a firewall that only
     allows outbound HTTPS? It falls back through the relay ports, and if even those are closed, all
     the way to the same <code>:443</code> port every browser already uses — one of the few outbound
     ports almost nothing blocks. Same encrypted session the whole way down; only the route changes.</p>
   </div>
   <div class="diagram-card">
    <div class="diagram-head"><span>ESCAPE LADDER · direct → relay → :443</span><span class="live"><i></i>connected</span></div>
    <canvas id="diagram-ladder" width="400" height="160" aria-label="Animated diagram of a connection attempt trying direct QUIC, then a relay port, then finally the shared 443 port used by all browser traffic"></canvas>
   </div>
  </div>
 </div>

 <div class="features">
  <div class="feature"><h3>Zero-knowledge</h3><p>Noise-encrypted end to end — the operator cannot see your payload, only that a tunnel is active.</p></div>
  <div class="feature"><h3>Any hardware</h3><p>Laptop, Raspberry Pi, spare VM, container, or your own AI agent — nothing runs on our infrastructure.</p></div>
  <div class="feature"><h3>Agent-native</h3><p>Built to be driven by Claude Code or any coding agent — /llms.txt is a machine-readable onboarding doc.</p></div>
 </div>

 <div class="use-case">
  <div>
   <h3>Your own mesh, optimized</h3>
   <p>Draw your agents into a graph in the topology editor — direct links, or let it plan for you.
    CADS-Tunnel computes an optimized routing plan over your own declared mesh (shortcuts, minimum
    latency) from real measured link costs between your agents. It's your ad-hoc network, not ours —
    we only compute the plan, your agents run it.</p>
  </div>
  <div class="diagram-card">
   <div class="diagram-head"><span>YOUR TOPOLOGY · 5 agents, self-declared</span><span class="live"><i></i>routed</span></div>
   <canvas id="diagram-mesh" width="400" height="160" aria-label="Animated diagram of five of your agents connected in a mesh, with one optimized route highlighted"></canvas>
  </div>
 </div>

 <div class="lab">
  <h2 style="margin-top:0">What is "Bunsenbrenner"?</h2>
  <p>
   Picture a lab bench. A Bunsen burner isn't the experiment — it's the reliable, unglamorous heat
   source every experiment on that bench depends on, so you can focus on the idea instead of
   re-inventing how to make fire.
  </p>
  <p style="margin-bottom:0">
   <strong>bunsenbrenner.org is that bench.</strong> A shared lab where you can test an idea, run it on
   whatever hardware you already have, and hand the result to other people — over a real, encrypted,
   publicly reachable address — without having to build or trust a whole platform first. Some ideas here
   started as a weekend demo and are now real, working pipelines with their own community of
   contributors. That's the point: a straight line from "it works on my machine" to "here, try it."
  </p>
 </div>

 <div class="section" id="pipelines-usecase">
  <div class="section-head"><h2>Workflow pipelines</h2><a class="btn secondary" href="/registry/pipelines">Pipeline registry (raw) &rarr;</a></div>
  <ul class="list" id="pipeline-list"><li class="empty">loading…</li></ul>

  <div class="use-case reverse">
   <div class="diagram-card">
    <div class="diagram-head"><span>ROLE AUCTION · 3 devices, 1 role each</span><span class="live"><i></i>live</span></div>
    <canvas id="diagram-pipeline" width="400" height="160" aria-label="Animated diagram of three devices each publishing an offer, an auction selecting winners, and one composed service"></canvas>
   </div>
   <div>
    <h3>One service, several devices</h3>
    <p>No single device has to run the whole thing. Each agent can publish a signed capacity offer for
     one role in a pipeline spec; when several agents offer the same role, the registry's clearing
     mechanism picks the winner (cheapest valid offer, cross-role exclusive) and the winners wire
     together into one published service. A laptop, a Pi, and a spare VM can each carry one part of the
     same pipeline — this is the underlying primitive our own example pipelines are progressively
     adopting, not something that requires you to build it yourself.</p>
   </div>
  </div>
 </div>

 <div class="section" id="mcp">
  <h2>MCP</h2>
  <div class="mcp-strip">
   <p>
    Once your <code>ct-agent channel --serve</code> process joins a channel, it answers real
    <a href="https://modelcontextprotocol.io" target="_blank" rel="noopener">Model Context Protocol</a>
    requests from whichever peer it's channeled with — over the same end-to-end-encrypted connection
    your tunnel already uses. That's agent-to-agent, not something you add to your own coding
    assistant's <code>.mcp.json</code>. Nothing separate to install: it's the same <code>ct-agent</code>
    binary, turned on by which env vars you set. Full wire details and env vars:
    <a href="/llms.txt">/llms.txt</a>, section E.
   </p>
   <div class="install">curl … | ct-agent onboard</div>
  </div>

  <div class="use-case">
   <div>
    <h3>Direct, agent to agent</h3>
    <p>Two agents connect directly when the network allows it; when it doesn't, the same Noise session
     reroutes through a relay that only ever sees ciphertext — never a plaintext hub in the middle.
     The same channel mechanism also admits <em>other people's</em> agents, not just your own: a
     redeemable invitation plus a possession proof lets someone else's agent join your channel, so a
     pipeline can span accounts, not just devices.</p>
   </div>
   <div class="diagram-card">
    <div class="diagram-head"><span>CHANNEL · direct-first, relay fallback</span><span class="live"><i></i>encrypted</span></div>
    <canvas id="diagram-p2p" width="400" height="160" aria-label="Animated diagram of two agents connecting directly, with a relay fallback path shown for when direct connection is blocked"></canvas>
   </div>
  </div>

  <div class="use-case reverse">
   <div class="diagram-card">
    <div class="diagram-head"><span>REGISTRY · publish once, found by many</span><span class="live"><i></i>public</span></div>
    <canvas id="diagram-directory" width="400" height="160" aria-label="Animated diagram of your agent publishing a card to the public registry, then several other agents discovering and connecting to it"></canvas>
   </div>
   <div>
    <h3>Discoverable by agents you've never met</h3>
    <p>Publish your agent's signed capability card once, and any agent can find it in the public
     directory (<a href="/registry/agents">/registry/agents</a>) by role or skill — no manual key
     exchange, no out-of-band introduction. The directory hands them your identity and address; from
     there they still connect through the same channel mechanism as anyone else. It's the difference
     between a phone number you hand out and a listing someone else can look up.</p>
   </div>
  </div>
 </div>

 <div class="section">
  <h2>Live operator status</h2>
  <p style="max-width:36rem;margin:-.6rem 0 1.2rem;color:var(--muted);font-size:.9rem">
   Not a promise — this pulls straight from <code>/status</code> right now. Structural health and
   metadata only; the payload itself stays invisible even to us.
  </p>
  <div id="health" class="l">loading…</div>
  <div class="grid">
   <div class="card"><div class="n" id="tunnels">–</div><div class="l">registered tunnels</div></div>
   <div class="card"><div class="n" id="agents">–</div><div class="l">enrolled agents</div></div>
   <div class="card"><div class="n" id="pipelines">–</div><div class="l">published pipelines</div></div>
   <div class="card"><div class="n" id="directory">–</div><div class="l">discoverable agents</div></div>
   <div class="card"><div class="n" id="uptime">–</div><div class="l">uptime (s)</div></div>
  </div>
 </div>

 <div class="section support">
  <p><strong>Keep the lab running.</strong> Bunsenbrenner is free to use and runs on donated time and
  server costs. If it helped you get something live, a small contribution keeps it going.</p>
  <div class="actions">
   <a class="btn" href="https://steady.page/plans/77a32d9c-c399-4ca1-9515-7a628c7a9413" target="_blank" rel="noopener">Support as a member &rarr;</a>
   <a class="btn secondary" href="https://buymeacoffee.com/bunsenbrenner" target="_blank" rel="noopener">Buy me a coffee &rarr;</a>
   <a class="btn secondary" href="https://github.com/scimbe/CADS-Tunnel" target="_blank" rel="noopener">GitHub — feature requests, code review, issues &rarr;</a>
  </div>
 </div>

</main>

<footer class="site-footer">
 <div class="footer-inner">
  <div class="foot">Operator view — structural health and metadata only; the payload is end-to-end encrypted and never visible here.</div>
  <div class="legal-links"><a href="/legal-notice">Legal Notice</a><a href="/privacy-policy">Privacy Policy</a><a href="/terms-of-use">Terms of Use</a></div>
  <div class="copyright">&copy; Bunsenbrenner.org — Martin Becke</div>
 </div>
</footer>

<script>
 async function refresh(){
  try{
   const r=await fetch('/status'); const s=await r.json();
   document.getElementById('health').innerHTML = s.ready ? '<span class="ok">● ready</span>' : '<span class="bad">● not ready</span>';
   document.getElementById('tunnels').textContent=s.tunnels;
   document.getElementById('agents').textContent=s.agents;
   document.getElementById('pipelines').textContent=s.pipelines_published;
   document.getElementById('directory').textContent=s.agents_directory;
   document.getElementById('uptime').textContent=s.uptime_seconds;
  }catch(e){ document.getElementById('health').innerHTML='<span class="bad">● unreachable</span>'; }
 }
 function esc(s){ return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
 async function refreshPipelines(){
  const el = document.getElementById('pipeline-list');
  try{
   const r = await fetch('/registry/pipelines'); const rows = await r.json();
   if(!rows.length){ el.innerHTML = '<li class="empty">No pipelines published yet.</li>'; return; }
   el.innerHTML = rows.map(p =>
     '<li><span class="id">'+esc(p.id)+'</span><span class="meta">owner: '+esc(p.owner)+'</span>'+
     '<a href="/registry/pipelines/'+encodeURIComponent(p.id)+'">spec &rarr;</a></li>'
   ).join('');
  }catch(e){ el.innerHTML = '<li class="empty">unreachable</li>'; }
 }
 function copyCode(btn){
  const container = btn.closest('.code-block');
  const tmpl = container.querySelector('template');
  const code = tmpl ? tmpl.content.querySelector('code') : container.querySelector('code');
  const text = code ? code.textContent : '';
  const done = () => { const orig = btn.innerHTML; btn.innerHTML = '&#9989; Copied'; setTimeout(()=>{ btn.innerHTML = orig; }, 1600); };
  if(navigator.clipboard && navigator.clipboard.writeText){ navigator.clipboard.writeText(text).then(done).catch(()=>{}); }
 }
 refresh(); refreshPipelines();
 setInterval(refresh,5000); setInterval(refreshPipelines,15000);

 // Network schematic animation -- device -> agent -> edge -> browser, an
 // encrypted packet travels the path. Purely decorative; respects reduced-motion.
 (function(){
  var c = document.getElementById('net');
  if(!c) return;
  var ctx = c.getContext('2d');
  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  function cssVar(name){ return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
  function resize(){
   var r = c.getBoundingClientRect();
   c.width = r.width * devicePixelRatio; c.height = r.height * devicePixelRatio;
   ctx.setTransform(devicePixelRatio,0,0,devicePixelRatio,0,0);
  }
  window.addEventListener('resize', resize);
  resize();
  var labels = ['Device','Agent','Edge','Browser'];
  var t = 0;
  function draw(){
   var r = c.getBoundingClientRect(); var w = r.width, h = r.height;
   ctx.clearRect(0,0,w,h);
   var line = cssVar('--line'), muted = cssVar('--muted'), text = cssVar('--text'),
       accent = cssVar('--accent'), accent2 = cssVar('--accent2'), panel = cssVar('--panel');
   var n = labels.length, pad = 40;
   var xs = []; for (var i=0;i<n;i++){ xs.push(pad + (w-2*pad) * (i/(n-1))); }
   var y = h/2 - 8;
   ctx.strokeStyle = line; ctx.lineWidth = 2;
   ctx.beginPath(); ctx.moveTo(xs[0], y); ctx.lineTo(xs[n-1], y); ctx.stroke();
   for (var i=0;i<n;i++){
    ctx.beginPath(); ctx.arc(xs[i], y, 7, 0, Math.PI*2);
    ctx.fillStyle = panel; ctx.fill();
    ctx.lineWidth = 2; ctx.strokeStyle = (i===0||i===n-1) ? muted : accent2; ctx.stroke();
    ctx.font = '11px ' + (cssVar('--mono') || 'monospace');
    ctx.fillStyle = text; ctx.textAlign = 'center';
    ctx.fillText(labels[i], xs[i], y + 26);
   }
   var pos = reduce ? 0.5 : (Math.sin(t/60) + 1) / 2;
   var px = xs[0] + (xs[n-1]-xs[0]) * pos;
   ctx.beginPath(); ctx.arc(px, y, 4, 0, Math.PI*2);
   ctx.fillStyle = accent; ctx.shadowColor = accent; ctx.shadowBlur = 8; ctx.fill(); ctx.shadowBlur = 0;
   ctx.font = '10px ' + (cssVar('--mono') || 'monospace');
   ctx.fillStyle = muted; ctx.textAlign = 'left';
   ctx.fillText('ciphertext only -- 0 bytes of payload visible to the operator', pad, h/2 + 52);
   t += 1;
   if (!reduce) requestAnimationFrame(draw);
  }
  draw();
 })();

 // Generic small network diagram -- nodes at relative (0..1) coords, straight
 // hairline edges (some dashed for "attempted, not guaranteed" paths), and one
 // or more packets that travel a path of node indices, looping. Used for the
 // three "what people build with this" diagrams below; purely decorative,
 // respects reduced-motion (freezes packets at their midpoint).
 function initMiniDiagram(id, nodes, edges, packets){
  var c = document.getElementById(id);
  if(!c) return;
  var ctx = c.getContext('2d');
  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  function cssVar(name){ return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
  function resize(){
   var r = c.getBoundingClientRect();
   c.width = r.width * devicePixelRatio; c.height = r.height * devicePixelRatio;
   ctx.setTransform(devicePixelRatio,0,0,devicePixelRatio,0,0);
  }
  window.addEventListener('resize', resize);
  resize();
  var t = 0;
  function pt(i, w, h){
   var mx = Math.min(w * .12, 34);
   return { x: mx + nodes[i].x * (w - mx * 2), y: nodes[i].y * h };
  }
  function draw(){
   var r = c.getBoundingClientRect(); var w = r.width, h = r.height;
   ctx.clearRect(0,0,w,h);
   var line = cssVar('--line'), muted = cssVar('--muted'), text = cssVar('--text'),
       accent = cssVar('--accent'), accent2 = cssVar('--accent2'), panel = cssVar('--panel');
   edges.forEach(function(e){
    var a = pt(e.from, w, h), b = pt(e.to, w, h);
    ctx.strokeStyle = e.dim ? line : accent2;
    ctx.globalAlpha = e.dim ? 1 : .55;
    ctx.lineWidth = 1.5;
    if (e.dashed) ctx.setLineDash([3,4]); else ctx.setLineDash([]);
    ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
    ctx.setLineDash([]); ctx.globalAlpha = 1;
   });
   nodes.forEach(function(n){
    var p = pt(nodes.indexOf(n), w, h);
    ctx.beginPath(); ctx.arc(p.x, p.y, n.r || 6, 0, Math.PI*2);
    ctx.fillStyle = panel; ctx.fill();
    ctx.lineWidth = 2; ctx.strokeStyle = n.dim ? muted : accent2; ctx.stroke();
    if (n.label){
     ctx.font = '10px ' + (cssVar('--mono') || 'monospace');
     ctx.fillStyle = text; ctx.textAlign = 'center';
     ctx.fillText(n.label, p.x, p.y + (n.labelBelow === false ? -12 : 20));
    }
   });
   packets.forEach(function(pk){
    var path = pk.path, segs = path.length - 1;
    var pos = reduce ? 0.5 : ((t * (pk.speed || 1)) / 90 + (pk.phase || 0)) % 1;
    var segF = pos * segs, seg = Math.min(Math.floor(segF), segs - 1), f = segF - seg;
    var a = pt(path[seg], w, h), b = pt(path[seg+1], w, h);
    var px = a.x + (b.x - a.x) * f, py = a.y + (b.y - a.y) * f;
    var col = pk.color === 'accent2' ? accent2 : accent;
    ctx.beginPath(); ctx.arc(px, py, 3.5, 0, Math.PI*2);
    ctx.fillStyle = col; ctx.shadowColor = col; ctx.shadowBlur = 7; ctx.fill(); ctx.shadowBlur = 0;
   });
   t += 1;
   if (!reduce) requestAnimationFrame(draw);
  }
  draw();
 }

 // 1. One service, several devices: each publishes a capacity offer for a role;
 // the pipeline registry auctions each role and wires the winners into one
 // published service (crates/common/src/pipeline.rs convene/SelectionPolicy).
 initMiniDiagram('diagram-pipeline',
  [
   {x:.14,y:.18,label:'Laptop'}, {x:.14,y:.5,label:'Pi'}, {x:.14,y:.82,label:'VM'},
   {x:.52,y:.5,label:'Auction',dim:true,r:7},
   {x:.88,y:.5,label:'Your service',r:7},
  ],
  [ {from:0,to:3,dim:true}, {from:1,to:3,dim:true}, {from:2,to:3,dim:true}, {from:3,to:4,dim:true} ],
  [
   {path:[0,3,4],speed:1,phase:0}, {path:[1,3,4],speed:1,phase:.33}, {path:[2,3,4],speed:1,phase:.66},
  ]
 );

 // 2. Direct, agent to agent: tries a direct line first; on failure the same
 // Noise session reroutes through a relay that only ever sees ciphertext
 // (ct-agent/src/channel_run.rs's fallback ladder).
 initMiniDiagram('diagram-p2p',
  [
   {x:.14,y:.5,label:'Agent A'}, {x:.86,y:.5,label:'Agent B'}, {x:.5,y:.85,label:'Relay',dim:true,labelBelow:false},
  ],
  [ {from:0,to:1}, {from:0,to:2,dim:true,dashed:true}, {from:2,to:1,dim:true,dashed:true} ],
  [ {path:[0,1],speed:1,phase:0,color:'accent2'}, {path:[0,2,1],speed:.8,phase:.5} ]
 );

 // 3. Your own mesh, optimized: draw your agents into a graph in the topology
 // editor; CADS-Tunnel computes a routing plan over it (shortcuts, minimum
 // latency, from measured link costs) -- crates/common/src/overlay.rs.
 initMiniDiagram('diagram-mesh',
  [
   {x:.5,y:.12,label:'1'}, {x:.88,y:.38,label:'2'}, {x:.74,y:.85,label:'3'},
   {x:.26,y:.85,label:'4'}, {x:.12,y:.38,label:'5'},
  ],
  [
   {from:0,to:1,dim:true}, {from:1,to:2,dim:true}, {from:2,to:3,dim:true}, {from:3,to:4,dim:true}, {from:4,to:0,dim:true},
   {from:0,to:2}, {from:1,to:4},
  ],
  [ {path:[0,2,4,0],speed:.7,phase:0,color:'accent2'} ]
 );

 // 4. Escape ladder: direct QUIC first, relay ports next, :443 front door last
 // -- same encrypted session throughout, only the route changes on failure
 // (ct-agent/src/channel_run.rs's fallback ladder; crates/edge/src/serve.rs's
 // QUIC->TCP dispatch only after a real TLS handshake).
 initMiniDiagram('diagram-ladder',
  [
   {x:.1,y:.5,label:'You'},
   {x:.42,y:.15,label:'direct',dim:true}, {x:.42,y:.5,label:'relay',dim:true}, {x:.42,y:.85,label:':443'},
   {x:.9,y:.5,label:'Edge'},
  ],
  [
   {from:0,to:1,dim:true}, {from:0,to:2,dim:true}, {from:0,to:3,dim:true},
   {from:1,to:4,dim:true,dashed:true}, {from:2,to:4,dim:true,dashed:true}, {from:3,to:4},
  ],
  [ {path:[0,3,4],speed:.9,phase:0,color:'accent2'} ]
 );

 // 5. Public directory: publish a signed card once, any agent can look you up
 // by role/skill afterward (crates/control-plane/src/service.rs's
 // agent_directory_router, POST/GET /registry/agents).
 initMiniDiagram('diagram-directory',
  [
   {x:.12,y:.5,label:'You'}, {x:.5,y:.5,label:'Registry',dim:true,r:7},
   {x:.88,y:.18,label:'Agent'}, {x:.88,y:.5,label:'Agent'}, {x:.88,y:.82,label:'Agent'},
  ],
  [ {from:0,to:1,dim:true}, {from:1,to:2,dim:true}, {from:1,to:3,dim:true}, {from:1,to:4,dim:true} ],
  [
   {path:[0,1],speed:1,phase:0},
   {path:[1,2],speed:1,phase:.2,color:'accent2'}, {path:[1,3],speed:1,phase:.5,color:'accent2'}, {path:[1,4],speed:1,phase:.8,color:'accent2'},
  ]
 );
</script>
<div class="cookie-notice" id="cookie-notice">
 <span>We only use technically necessary cookies (login session, CSRF protection) — no tracking, no
 analytics, no marketing cookies. See the <a href="/privacy-policy">Privacy Policy</a>.</span>
 <button onclick="document.getElementById('cookie-notice').classList.remove('show');localStorage.setItem('ct-cookie-notice-seen','1')">Got it</button>
</div>
<script>
 if(!localStorage.getItem('ct-cookie-notice-seen')){ document.getElementById('cookie-notice').classList.add('show'); }
</script>
</body></html>"#;

/// The AI-agent onboarding doc (`docs/agent-onboarding.md`, #174), embedded so the control plane can
/// serve it live at `/llms.txt` — the machine-readable entry point the operator status page links to
/// so agents can discover how to register, join a pipeline, and publish one (the "linked,
/// discoverable entry point" #174 asked for). Kept in sync at compile time via `include_str!`.
const LLMS_TXT: &str = include_str!("../../../docs/agent-onboarding.md");

/// Legal notice (Impressum, §5 TMG/DDG) — real, verified operator facts (name, address, contact,
/// Kleinunternehmer/§19 UStG status), not placeholder text. A fabricated Impressum is itself a legal
/// defect (worse than none), so this is only ever edited with real, current facts.
const IMPRESSUM_HTML: &str = include_str!("../../../docs/legal/impressum.html");

/// Privacy notice (Datenschutzerklärung, Art. 13 DSGVO). Documents what this deployment ACTUALLY
/// processes (checked against the code, not assumed): only two cookies (OIDC CSRF-state + session,
/// both strictly necessary, no consent required under §25 TTDSG), no analytics/tracking, and the
/// zero-knowledge-payload architecture (the operator cannot see tunneled content).
const DATENSCHUTZ_HTML: &str = include_str!("../../../docs/legal/datenschutz.html");

/// Terms of use (Nutzungsbedingungen). §4/§5 establish the platform-liability boundary: the operator
/// provides infrastructure only (§§7-10 TMG/DDG host-provider privilege) and does not adopt users'
/// own workflow-pipelines/services as its own; each user is solely responsible for (and indemnifies
/// the operator against third-party claims arising from) their own service run through the platform.
const NUTZUNGSBEDINGUNGEN_HTML: &str = include_str!("../../../docs/legal/nutzungsbedingungen.html");

/// English courtesy translations of the three legal pages above (the site itself is English-first;
/// German remains the legally binding version for each, per its own translation notice). Kept as
/// separate files rather than templated from the German source so each stays independently reviewable.
const LEGAL_NOTICE_HTML: &str = include_str!("../../../docs/legal/legal-notice.html");
const PRIVACY_POLICY_HTML: &str = include_str!("../../../docs/legal/privacy-policy.html");
const TERMS_OF_USE_HTML: &str = include_str!("../../../docs/legal/terms-of-use.html");

/// The downloadable "hello world" starter template (register → download → adapt with Claude Code →
/// publish), zipped so a human onboarding on the landing page gets it with one click instead of
/// needing `git`. Rebuild via the same `python3 -m zipfile` invocation whenever
/// `examples/hello-world-pipeline/{pipeline-spec.json,hello-handler.sh,README.md}` change.
const HELLO_WORLD_ZIP: &[u8] =
    include_bytes!("../../../examples/hello-world-pipeline/hello-world-pipeline.zip");

/// A read-it-yourself guide to the hello-world-pipeline template: what each of the three files in the
/// zip does, how to adapt it into your own idea, and how to persist the identity `ct-agent channel
/// init` mints (the `.env` file, why it must never be re-minted) -- for the "download and build it
/// your way" path on the landing page, as opposed to the "hand it to your LLM" path.
const TEMPLATE_GUIDE_HTML: &str = include_str!("../../../docs/landing/template-guide.html");

/// Build the landing-page router (F4.2): `GET /` serves [`LANDING_HTML`], which now also carries the
/// full human "get started" onboarding (register → get the template → subdomain policy) inline rather
/// than on a separate `/publish` subpage. `/publish` redirects to `/#get-started` for anyone with an
/// old link. `GET /llms.txt` serves the AI-agent onboarding doc (#174) as plain text so a CLI agent can
/// `curl` it. `/downloads/hello-world-pipeline.zip` serves the starter template as a real download (no
/// `git clone` required); `/template-guide` explains its structure for the "build it yourself" path.
/// `/impressum`, `/datenschutz`, `/nutzungsbedingungen` serve the legal pages linked from the footer.
pub fn landing_router() -> Router {
    Router::new()
        .route("/", get(landing_handler))
        .route("/llms.txt", get(llms_txt_handler))
        .route(
            "/publish",
            get(|| async { axum::response::Redirect::temporary("/#get-started") }),
        )
        .route(
            "/downloads/hello-world-pipeline.zip",
            get(|| async {
                (
                    [
                        ("content-type", "application/zip"),
                        (
                            "content-disposition",
                            "attachment; filename=\"hello-world-pipeline.zip\"",
                        ),
                    ],
                    HELLO_WORLD_ZIP,
                )
            }),
        )
        .route(
            "/template-guide",
            get(|| async { axum::response::Html(TEMPLATE_GUIDE_HTML) }),
        )
        .route("/impressum", get(|| async { axum::response::Html(IMPRESSUM_HTML) }))
        .route("/datenschutz", get(|| async { axum::response::Html(DATENSCHUTZ_HTML) }))
        .route(
            "/nutzungsbedingungen",
            get(|| async { axum::response::Html(NUTZUNGSBEDINGUNGEN_HTML) }),
        )
        .route("/legal-notice", get(|| async { axum::response::Html(LEGAL_NOTICE_HTML) }))
        .route("/privacy-policy", get(|| async { axum::response::Html(PRIVACY_POLICY_HTML) }))
        .route("/terms-of-use", get(|| async { axum::response::Html(TERMS_OF_USE_HTML) }))
}

/// This deployment's actual mesh/channel-broker/channel-relay ports (#214 follow-up: generic
/// pipeline provisioning). A workflow-pipeline maintainer pointed `CT_CHANNEL_BROKER`/
/// `CT_CHANNEL_RELAY` at the tunnel's Mesh-Plane rendezvous port (`4433`) instead of the
/// Agent-Fabric channel broker/relay (`4435`/`4436`) — a completely different listener/protocol —
/// because nothing told them which port served which purpose. `/network-info` closes that gap: a
/// generic `ct-agent` (or any future pipeline's onboarding docs) reads this once instead of
/// hardcoding or guessing port numbers.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct NetworkInfoResp {
    /// The Mesh-Plane tunnel rendezvous port (`CT_EDGE_LISTEN`) — Client⇄Origin capability
    /// tunnels. NOT the Agent-Fabric channel broker below; pointing `CT_CHANNEL_BROKER` here
    /// fails every channel join immediately (wrong protocol, not an auth/membership refusal).
    pub mesh_edge_port: u16,
    /// The Agent-Fabric channel broker port (`CT_EDGE_CHANNEL_LISTEN`) — what `CT_CHANNEL_BROKER`
    /// must point at.
    pub channel_broker_port: u16,
    /// The Agent-Fabric channel relay port (`CT_EDGE_CHANNEL_RELAY_LISTEN`) — what
    /// `CT_CHANNEL_RELAY` must point at.
    pub channel_relay_port: u16,
    /// #330: the unified `:443` front door (`CT_EDGE_BROWSER_LISTEN`) a relay-only
    /// (NAT'd) channel member should point `CT_CHANNEL_RELAY_GATE` at — the relay-gate is
    /// ALPN-demuxed onto this SAME listener as Browser-Plane/Portal traffic, not a
    /// separate port, so there is deliberately no distinct `channel_relay_gate_port`
    /// field. This value is the EXTERNAL convention (default `443`); a member co-located
    /// on the plane's own Docker network must use the edge container's real bound port
    /// instead (e.g. `edge:8443`, not `edge:443` — a host-level Docker port-publish like
    /// `"443:8443"` only translates traffic entering from OUTSIDE Docker, see
    /// `compose.frontdoor.yml`'s own comment on this exact trap, first hit live in
    /// `#248`). `CT_CHANNEL_RELAY_GATE_CERT` is the same CA root every other `/pki/ca`
    /// consumer already fetches — no separate cert endpoint needed.
    pub channel_relay_gate_port: u16,
}

impl NetworkInfoResp {
    /// Read from `CT_CP_MESH_EDGE_PORT`/`CT_CP_CHANNEL_BROKER_PORT`/`CT_CP_CHANNEL_RELAY_PORT`,
    /// defaulting to the same `4433`/`4435`/`4436` defaults `docker/deploy/compose.selfhost.yml`
    /// uses for the edge, so an unconfigured deployment still reports the right values.
    pub fn from_env() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Testable core: an injectable lookup instead of `std::env::var` directly, so tests never
    /// mutate real process environment (racy under parallel `cargo test`).
    fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Self {
        let port = |name: &str, default: u16| -> u16 {
            f(name).and_then(|s| s.parse().ok()).unwrap_or(default)
        };
        Self {
            mesh_edge_port: port("CT_CP_MESH_EDGE_PORT", 4433),
            channel_broker_port: port("CT_CP_CHANNEL_BROKER_PORT", 4435),
            channel_relay_port: port("CT_CP_CHANNEL_RELAY_PORT", 4436),
            channel_relay_gate_port: port("CT_CP_CHANNEL_RELAY_GATE_PORT", 443),
        }
    }
}

#[derive(Clone)]
struct NetworkInfoState {
    info: NetworkInfoResp,
}

/// Build the `/network-info` router: a public, stateless `GET` returning this deployment's actual
/// ports (read once at startup — see [`NetworkInfoResp::from_env`]).
pub fn network_info_router() -> Router {
    Router::new()
        .route("/network-info", get(network_info_handler))
        .with_state(NetworkInfoState { info: NetworkInfoResp::from_env() })
}

async fn network_info_handler(State(s): State<NetworkInfoState>) -> Json<NetworkInfoResp> {
    Json(s.info)
}

#[cfg(test)]
mod network_info_tests {
    use super::*;

    #[test]
    fn network_info_defaults_match_the_selfhost_compose_ports() {
        // No env configured -> the same 4433/4435/4436 docker/deploy/compose.selfhost.yml uses,
        // plus 443 for the relay-gate's shared front door (#330).
        let info = NetworkInfoResp::from_lookup(|_| None);
        assert_eq!(info.mesh_edge_port, 4433);
        assert_eq!(info.channel_broker_port, 4435);
        assert_eq!(info.channel_relay_port, 4436);
        assert_eq!(info.channel_relay_gate_port, 443);
    }

    #[test]
    fn network_info_honors_overrides_and_ignores_unparseable_values() {
        let env = |k: &str| match k {
            "CT_CP_MESH_EDGE_PORT" => Some("5000".to_string()),
            "CT_CP_CHANNEL_BROKER_PORT" => Some("not-a-port".to_string()), // falls back to default
            "CT_CP_CHANNEL_RELAY_GATE_PORT" => Some("8443".to_string()),
            _ => None,
        };
        let info = NetworkInfoResp::from_lookup(env);
        assert_eq!(info.mesh_edge_port, 5000, "explicit override honored");
        assert_eq!(info.channel_broker_port, 4435, "unparseable value falls back to default, not 0/panic");
        assert_eq!(info.channel_relay_port, 4436, "unset falls back to default");
        assert_eq!(info.channel_relay_gate_port, 8443, "explicit override honored (e.g. a Docker-co-located deployment)");
    }

    #[tokio::test]
    async fn network_info_endpoint_serves_the_computed_json() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = network_info_router();
        let resp = app
            .oneshot(Request::get("/network-info").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let info: NetworkInfoResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(info.mesh_edge_port, 4433);
        assert_eq!(info.channel_broker_port, 4435);
        assert_eq!(info.channel_relay_port, 4436);
        assert_eq!(info.channel_relay_gate_port, 443);
    }
}

async fn landing_handler() -> axum::response::Html<&'static str> {
    axum::response::Html(LANDING_HTML)
}

async fn llms_txt_handler() -> impl axum::response::IntoResponse {
    ([(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")], LLMS_TXT)
}

/// Build the CA-publish router (#11 C1): `GET /pki/ca` serves the edge CA root
/// DER read from `cert_path` — the same file the edge writes (`CT_EDGE_CERT_OUT`),
/// co-located with the control plane on the central host. This is **public key
/// material** (the trust root, never the signing key), so publishing it over HTTP
/// lets remote agents/clients fetch the root instead of copying it out of band.
/// Returns 503 until the edge has written its cert. The root is stable across
/// edge redeploys now that the CA persists (#2 `f9e64e9`).
pub fn pki_router(cert_path: String) -> Router {
    Router::new()
        .route("/pki/ca", get(ca_handler))
        .with_state(Arc::new(cert_path))
}

async fn ca_handler(State(path): State<Arc<String>>) -> axum::response::Response {
    use axum::response::IntoResponse;
    match std::fs::read(path.as_str()) {
        Ok(der) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/x-x509-ca-cert")],
            der,
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "edge CA root not published yet",
        )
            .into_response(),
    }
}

/// Build the full persistent control-plane router: enrollment + registry +
/// billing + health, all backed by durable SQLite stores opened on **one**
/// database file (`db_path`). The stores share the file via separate
/// connections — each owns its own tables, and each is opened with WAL +
/// `busy_timeout` (#110) so concurrent writers queue instead of hitting
/// `SQLITE_BUSY`. This is what a real deployment serves.
/// Fixed window (seconds) for the unauthenticated-writer rate limit (#87 SEC87b-rl).
const UNAUTH_WRITE_WINDOW_SECS: u64 = 60;

/// The unauthenticated, DB-writing endpoints a flood could grow the durable SQLite
/// store with (#87). They take no bearer token, so the only stable caller key is the
/// client IP — the per-IP limiter is applied to exactly these `POST` paths.
const UNAUTH_WRITE_PATHS: &[&str] = &[
    "/enroll/issue",
    "/accounts/open",
    "/registry/register",
    "/payment/intent",
];

/// Per-client-IP fixed-window limiter state for the unauthenticated DB-writers.
#[derive(Clone)]
struct UnauthWriteLimit {
    limiter: Arc<Mutex<KeyedRateLimiter<IpAddr>>>,
}

/// Wrap `app` so that each unauthenticated DB-writing `POST` (see
/// [`UNAUTH_WRITE_PATHS`]) is capped at `per_window` requests per client IP per
/// fixed window (#87 SEC87b-rl) — a flood from one source gets `429` before it can
/// grow the durable store, bounding the disk-DoS. Only those paths are metered;
/// every other request (reads, authed `/me/*`, health) passes straight through. The
/// client IP comes from the connection (`ConnectInfo`); if it can't be determined
/// the request fails **open** (passes through) rather than erroring.
pub(crate) fn with_unauth_write_limit(app: Router, per_window: u32) -> Router {
    let state = UnauthWriteLimit {
        limiter: Arc::new(Mutex::new(KeyedRateLimiter::new(per_window))),
    };
    app.layer(from_fn_with_state(state, limit_unauth_writes))
}

async fn limit_unauth_writes(
    State(state): State<UnauthWriteLimit>,
    peer: Option<ConnectInfo<SocketAddr>>,
    req: Request,
    next: Next,
) -> Response {
    let metered =
        req.method() == Method::POST && UNAUTH_WRITE_PATHS.contains(&req.uri().path());
    if let (true, Some(ConnectInfo(addr))) = (metered, peer) {
        let window = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() / UNAUTH_WRITE_WINDOW_SECS)
            .unwrap_or(0);
        if !state.limiter.lock_safe().allow(&addr.ip(), window) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "rate limit: too many unauthenticated requests from your address\n",
            )
                .into_response();
        }
    }
    next.run(req).await
}

/// `session_key` (#294): the portal session cookie's HMAC key. Deliberately a
/// **separate** secret from `webhook_secret` — `webhook_secret` is
/// `CT_PAYMENT_WEBHOOK_SECRET`, shared by definition with the external payment
/// provider, so anyone who learns it (a rogue insider there, a provider
/// compromise, interception) could otherwise forge a `ct_portal_session` cookie
/// for any subject (`SESSION_CTX` is a public domain-separation label, not a
/// secret) and take over any customer's account. Reusing it as the session key
/// was the actual bug; a distinct key closes that regardless of how it's sourced.
pub fn persistent_control_plane_router(
    db_path: &str,
    webhook_secret: &[u8],
    session_key: &[u8],
    oidc: OidcVerifierHandle,
) -> rusqlite::Result<Router> {
    // #328: `/me/*` used to be conditionally *mounted* based on whether `oidc` was
    // `Some` at this exact call -- a boot-time-only decision. It's now always a
    // handle, mounted unconditionally below; readiness is a per-request check
    // against the handle instead, which is what lets a background refresh task
    // (main.rs) heal a failed boot without a restart.
    let enrollment = Arc::new(SqliteEnrollment::open(db_path)?);
    let registry = Arc::new(SqliteRegistry::open(db_path)?);
    let ledger = Arc::new(SqliteLedger::open(db_path)?);
    let tunnels = Arc::new(crate::storage::SqliteTunnelStore::open(db_path)?);
    let channels = Arc::new(SqliteChannelStore::open(db_path)?);
    let bootstrap = Arc::new(SqliteBootstrap::open(db_path)?);
    // #107: the Topology Editor store — its public live-status page is always mounted;
    // the authed `/me/topologies*` editor mounts only with an OIDC verifier (below).
    let topologies = Arc::new(SqliteTopologyStore::open(db_path)?);
    let verifier = Arc::new(WebhookVerifier::new(
        webhook_secret.to_vec(),
        WEBHOOK_TOLERANCE_SECS,
    ));
    // Production billing surface: accounts, payment intents and credit-gated
    // issuance, but **no** client-callable `/payment/confirm` — credits flow only
    // from a signature-verified provider webhook (M24). That defuses the M18 stub
    // where any caller could top up an account for free. #87 SEC87b-auth-billing:
    // these three client-supplied-account writers are gated behind the shared admin
    // token when the CP has one configured (the customer path is the session-authed
    // portal, not these HTTP routes); wired just below with `issue_admin_token`.
    // Opened here (rather than inline at their .merge() call sites below) so the
    // SAME Arcs back both the actual registry endpoints and the landing page's
    // counts — they can never read a different table than what /registry/agents
    // and /registry/pipelines actually serve.
    let agent_directory = Arc::new(SqliteAgentDirectory::open(db_path)?);
    let pipeline_registry = Arc::new(SqlitePipelineRegistry::open(db_path)?);
    // edge_mesh Phase 0 (multi-edge ownership registry): which edge owns which
    // routing token/hostname, keyed by a stable per-deployment identifier. Defaults
    // to "primary" so an unconfigured deployment still gets a consistent id rather
    // than an empty string; only matters once a second real edge reports in.
    let edge_mesh_store = Arc::new(crate::edge_mesh::SqliteEdgeMesh::open(db_path)?);
    let local_edge_id: Arc<str> = Arc::from(
        std::env::var("CT_EDGE_ID")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "primary".to_string()),
    );
    {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        // Self-heartbeat the local edge at boot: `lookup_by_token`/`lookup_by_host` join
        // against `mesh_edges`, so an ownership record is only resolvable once its owning
        // edge has heartbeated at least once. This deployment's own edge is live by
        // definition (the CP just proxies authorize calls to it) well before any real
        // edge-side heartbeat loop exists (that's a later increment) -- without this, every
        // record_ownership written below/at the two hook points would be silently
        // unresolvable via lookup. "local" is a placeholder peer_addr; a real edge-side
        // heartbeat will overwrite it with its actual reachable address once that lands.
        if let Err(e) = edge_mesh_store.heartbeat(&local_edge_id, "local", None, now) {
            eprintln!("ct-cp: edge_mesh self-heartbeat failed: {e}");
        }
    }
    // One-time-per-boot, idempotent backfill: portal-created tunnels that predate
    // edge_mesh (or were created before this deploy) get an ownership record under
    // this deployment's local edge, skipping any token already recorded (never
    // overwrites a token that's since been assigned elsewhere). Safe to run every
    // boot -- it's a no-op once every tunnel has a record.
    {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        match tunnels.all() {
            Ok(existing) => {
                for t in existing {
                    if edge_mesh_store.lookup_by_token(&t.routing_token).ok().flatten().is_some() {
                        continue;
                    }
                    if let Err(e) =
                        edge_mesh_store.record_ownership(&t.routing_token, t.hostname.as_deref(), &local_edge_id, now)
                    {
                        eprintln!("ct-cp: edge_mesh backfill failed for tunnel {}: {e}", t.id);
                    }
                }
            }
            Err(e) => eprintln!("ct-cp: edge_mesh backfill: could not list existing tunnels: {e}"),
        }
    }
    let edge_mesh = crate::edge_mesh::EdgeMeshHandle::new(edge_mesh_store.clone(), local_edge_id);
    // Where to reach the edge's admin API (host-authorize/revoke, #23 BP4b / #27
    // RB4b) — hoisted here (rather than inline at each of its call sites below)
    // so the portal's automatic authorize-on-create-tunnel, the public
    // authorize-host proxy (#214), and the admission broker's tier-push (#233)
    // all read the exact same config.
    let edge_admin_config = match (
        std::env::var("CT_CP_EDGE_ADMIN_URL").ok().filter(|s| !s.is_empty()),
        std::env::var("CT_CP_EDGE_ADMIN_TOKEN").ok().filter(|s| !s.is_empty()),
    ) {
        (Some(url), Some(token)) => Some((url, token)),
        _ => None,
    };
    // #233: the Rot/Gelb/Grün admission-queue sweep. Opt-in and off by
    // default (matches this crate's "absent unless configured" convention
    // for every other internal writer) -- a deployment that hasn't set this
    // simply never promotes anything past Rot, so turning the feature on is
    // a deliberate, single-flag operator action, not a side effect of an
    // upgrade.
    if std::env::var("CT_CP_ACME_BROKER_ENABLED").ok().as_deref() == Some("1") {
        let tick_secs = std::env::var("CT_CP_ACME_BROKER_TICK_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(60);
        let broker_tunnels = tunnels.clone();
        let broker_edge_mesh = edge_mesh_store.clone();
        let broker_edge_admin = edge_admin_config.clone();
        tokio::spawn(crate::acme_broker::run_admission_loop(
            broker_tunnels,
            broker_edge_mesh,
            broker_edge_admin,
            std::time::Duration::from_secs(tick_secs),
        ));
    }
    // Operator status view + landing page (F4.1/F4.2): aggregate counts across
    // the stores, plus a self-contained HTML dashboard at `/`.
    let status = status_router(
        enrollment.clone(),
        registry.clone(),
        ledger.clone(),
        agent_directory.clone(),
        pipeline_registry.clone(),
        std::env::var("CT_CP_EDGE_METRICS_URL")
            .ok()
            .filter(|u| !u.is_empty()),
        oidc.clone(),
    );
    // Publish the edge CA root (#11): read from the path the edge writes it to,
    // co-located on the central host (CT_CP_EDGE_CERT_PATH, default matches the
    // edge's CT_EDGE_CERT_OUT).
    let pki = pki_router(
        std::env::var("CT_CP_EDGE_CERT_PATH").unwrap_or_else(|_| "/shared/edge-cert.der".to_string()),
    );
    // #87 SEC87b-auth: gate the machine/operator durable-writer surfaces behind the
    // shared admin token when the CP has one configured (the same CT_CP_EDGE_ADMIN_TOKEN
    // the edge/operator hold), so a public deployment can't have anyone mint join tokens
    // (`/enroll/issue`), grow the billing store with client-supplied accounts
    // (`/accounts/open`, `/payment/intent`, `/billing/issue`), or write the durable
    // routing registry (`/registry/register`). The real customer/agent flows (in-process
    // portal mint / session-authed top-up / QUIC tunnel registration to the edge) don't
    // use these routes, so this is transparent to customers; `/registry/resolve` (read)
    // stays open. The operator selftest presents the token via ControlPlaneClient.
    let admin_token = std::env::var("CT_CP_EDGE_ADMIN_TOKEN")
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|s| hex_decode_32(&s));
    // #194: the client-supplied-account billing WRITERS (/accounts/open, /payment/intent,
    // /billing/issue) debit/grow the ledger by an account named in the request body, with no
    // possession proof. Gated by the admin token when set — but mounting them OPEN when it's unset
    // means a deploy that forgot CT_CP_EDGE_ADMIN_TOKEN silently exposes an UNAUTHENTICATED
    // account-debit endpoint (anyone can drain any account's credits). Fail closed in production:
    // only mount them when the admin token is configured; without it they're simply absent (404).
    // The real customer/agent paths (session-authed portal /portal/account/credits, OIDC /me/issue,
    // the signature-verified /payment/webhook) don't use these routes, so this is transparent.
    let billing_writers = if admin_token.is_some() {
        billing_writers_gated(ledger.clone(), admin_token)
    } else {
        Router::new()
    };
    let mut app = enrollment_router_sqlite_with_admin(enrollment.clone(), admin_token)
        .merge(registry_router_sqlite_gated(registry, admin_token))
        .merge(billing_writers)
        // #90/#97 SEC90b-wire: bootstrap-token exchange — /bootstrap/mint (admin-gated)
        // + /bootstrap/redeem (public, single-use short-TTL token handed off over TLS).
        .merge(bootstrap_router(bootstrap.clone(), admin_token))
        // #144 ②/#161: the searchable agent directory — public `GET /registry/agents` search +
        // machine-writer-gated `POST` self-register (same `CT_CP_EDGE_ADMIN_TOKEN` as the other
        // agent-facing writers). Mounted unconditionally (no OIDC dependency): autonomous agents
        // self-enroll M2M and any peer searches — neither has a browser-interactive login path.
        .merge(agent_directory_router(agent_directory, admin_token))
        // #174 B: the workflow-pipeline registry — POST publish (admin-gated) + public GET
        // discovery, so a designer can publish a PipelineSpec agents scan to find workflows to join.
        .merge(pipeline_registry_router(pipeline_registry.clone(), admin_token))
        // edge_mesh Phase 0: heartbeat/lookup/rehydrate — admin-token-gated the same as
        // every other internal machine-writer surface here.
        .merge(crate::edge_mesh::edge_mesh_router(edge_mesh_store.clone(), admin_token))
        // ACME DNS-01 challenge-publish (ADR-0003 follow-up): an agent proves hostname
        // ownership via its routing token (checked against edge_mesh) instead of ever
        // holding the zone-wide DNS credential itself. Absent when no DNS-01 backend
        // is configured (same deSEC config the A-record autopilot already reads).
        .merge(crate::dns01_challenge::dns01_challenge_router(
            edge_mesh_store.clone(),
            tunnels.clone(),
            ct_dns::provider::DesecClient::from_env().map(ct_dns::provider::Dns01Provider::Desec),
        ))
        // #233: Rot/Gelb/Grün admission-broker endpoints (agent admission poll +
        // issuance-complete callback). Always mounted -- unlike the sweep loop
        // above, these need no DNS backend and are harmless no-ops until the
        // loop is enabled (a hostname just reports `rot` forever).
        .merge(crate::acme_broker::acme_broker_router(
            edge_mesh_store.clone(),
            tunnels.clone(),
            edge_admin_config.clone(),
        ))
        // #214: public, admin-token-gated host-authorization proxy to the edge — lets a
        // remote pipeline maintainer holding just the admin token self-serve hostname
        // binds (the same shared secret /enroll/issue already requires), no operator
        // relay or GitHub coordination needed per deployment. Absent when the edge
        // admin URL/token aren't configured (nothing to proxy to).
        .merge(match edge_admin_config.clone() {
            Some((url, token)) => edge_authorize_host_router(url, token, admin_token, edge_mesh.clone()),
            None => Router::new(),
        })
        // #72 AF3-redeem-cp: cross-user channel invitation redemption — public but
        // proof-gated (operator-signed invitation + invitee redemption + Noise attest).
        .merge(channel_invite_router(channels.clone()))
        // #107-subdomain: the public UUID-only topology live-status page (/net/:net_uuid).
        .merge(topology_status_router(topologies.clone()))
        .merge(payment_webhook_router(ledger.clone(), verifier))
        .merge(status)
        .merge(landing_router())
        .merge(network_info_router())
        .merge({
            let oidc_cfg = crate::portal::PortalOidc::from_env();
            let portal_base_url =
                std::env::var("CT_PORTAL_BASE_URL").unwrap_or_else(|_| "https://localhost".to_string());
            let account_console_url = oidc_cfg
                .as_ref()
                .map(|c| c.account_console_url_with_referrer(&portal_base_url, "/portal/account"));
            crate::portal::portal_router(oidc_cfg, session_key).merge(
                crate::portal_api::portal_api_router(
                    session_key,
                    ledger.clone(),
                    tunnels.clone(),
                    enrollment.clone(),
                    bootstrap.clone(),
                    &std::env::var("CT_PORTAL_BASE_URL").unwrap_or_else(|_| "https://localhost".to_string()),
                    // #27 RB4b: propagate tunnel revokes to the edge when both the admin
                    // URL and shared secret are configured.
                    edge_admin_config.clone(),
                    // #38 DL2: automatic tunnel-hostname DNS via deSEC, pointing A records
                    // at the edge's public IP. Enabled when the deSEC config + edge IP are set.
                    match (
                        ct_dns::provider::DesecClient::from_env(),
                        std::env::var("CT_CP_DNS_EDGE_IP").ok().filter(|s| !s.is_empty()),
                    ) {
                        (Some(client), Some(ip)) => Some((client, ip)),
                        _ => None,
                    },
                    // Keycloak's own Account Console (password change, sessions, and
                    // self-service account deletion) -- linked from /portal/account
                    // instead of CADS-Tunnel reimplementing any of it.
                    account_console_url,
                    edge_mesh.clone(),
                    admin_token,
                ),
            )
            // #248-follow: the session-authed channel-allowlist self-service claim —
            // same session key as the portal login above, so a claim just works right
            // after a portal login with no separate auth step.
            .merge(crate::portal_api::channel_claim_router(session_key, channels.clone()))
            // #237-follow: the Topology Editor's portal discoverability shell — same
            // session key, so the editor (already dual-auth via subject_of_topology)
            // is reachable and linked from the portal nav, not just a bare URL.
            .merge(crate::portal_api::topology_portal_router(session_key))
        })
        .merge(pki)
        // /install.sh + /install.ps1 now just redirect to ct-agent's own setup
        // scripts (#75 IS3b originally, retired in installer.rs's doc comment);
        // /channel.sh + /channel.ps1 still render live. CT_PORTAL_BASE_URL is the
        // origin the served channel scripts POST /bootstrap/redeem to (#90/#97
        // SEC90b); CT_RELEASE_BASE overrides the GitHub-Releases asset base they
        // download the prebuilt ct-agent from.
        .merge({
            let portal_base =
                std::env::var("CT_PORTAL_BASE_URL").unwrap_or_else(|_| "https://localhost".to_string());
            crate::installer::installer_router(
                portal_base,
                std::env::var("CT_RELEASE_BASE")
                    .ok()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| crate::installer::DEFAULT_RELEASE_BASE.to_string()),
            )
        });
    // #81 SEC81c-c (c-i): the live edge queries this to authorize channel-joins (the
    // broker's `authorize` closure). Gated by the shared edge↔CP admin token; mounted
    // only when CT_CP_EDGE_ADMIN_TOKEN is a valid 64-hex value.
    if let Some(admin_tok) = std::env::var("CT_CP_EDGE_ADMIN_TOKEN")
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|s| hex_decode_32(&s))
    {
        app = app
            .merge(internal_channel_authorize_router(channels.clone(), topologies.clone(), admin_tok))
            // #327: the Edge's boot-time revoked-tokens fetch.
            .merge(internal_revoked_tokens_router(tunnels.clone(), admin_tok));
    }
    // Authenticated per-subject endpoints (`/me/*`) (M26.1). #328: always mounted
    // now, regardless of whether a verifier is installed yet -- each handler
    // checks `oidc`'s current readiness per-request via `subject_of`, returning
    // `503` (not `404`) while unready. This is what lets a background refresh
    // task in main.rs heal a failed boot-time JWKS fetch without a restart: the
    // SAME `OidcVerifierHandle` clone captured here keeps observing later
    // `set()` calls for this process's entire lifetime.
    {
        // #102-rest: the declarative-network REST surface (owner = verified subject).
        let networks = Arc::new(SqliteNetworkStore::open(db_path)?);
        app = app
            .merge(authed_billing_router(
                ledger.clone(),
                oidc.clone(),
                AUTHED_ISSUES_PER_WINDOW,
            ))
            // Keycloak/account overhaul: "delete my account and all data" cascades
            // across every store keyed by a portal subject -- see
            // `account_delete_router`'s doc comment for why this stays a separate
            // small router rather than widening `ApiState`.
            .merge(crate::portal_api::account_delete_router(
                session_key,
                tunnels.clone(),
                channels.clone(),
                topologies.clone(),
                networks.clone(),
                pipeline_registry.clone(),
            ))
            .merge(authed_network_router(networks, oidc.clone()))
            .merge(authed_topology_router(topologies.clone(), oidc.clone(), Arc::from(session_key), channels.clone()))
            // #81 SEC81c-b: authenticated Agent-Fabric channel registry (owner =
            // verified subject), so it carries no unauthenticated write surface.
            .merge(authed_channel_router(channels, oidc.clone()))
            // Self-service pipeline publish (owner = verified subject) — see
            // `authed_pipeline_router`'s doc comment for why this exists alongside
            // the admin-gated `/registry/pipelines`.
            .merge(authed_pipeline_router(pipeline_registry, oidc));
    }
    let app = app.merge(health_router(ledger));
    // #87 SEC87b-rl: optional per-IP flood cap on the unauthenticated DB-writers.
    // Off by default (no behavior change — the auth model + a default-on policy are
    // the maintainer decision this doesn't presume); set CT_CP_UNAUTH_WRITE_PER_MIN
    // to a positive integer to bound the disk-DoS from a single address.
    let app = match std::env::var("CT_CP_UNAUTH_WRITE_PER_MIN")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|&n| n > 0)
    {
        Some(per_min) => with_unauth_write_limit(app, per_min),
        None => app,
    };
    Ok(app)
}

/// Shared state for the edge-facing channel-authorize endpoint (#81 SEC81c-c c-i):
/// the channel registry + the shared edge↔CP admin token the edge presents.
#[derive(Clone)]
pub struct AdminChannelState {
    channels: Arc<SqliteChannelStore>,
    // #235/#107-enforce (ii-b), the live-wiring the Topology Editor's own docs page names as
    // its remaining "does not currently change how your agents actually connect" gap: consulted
    // ADDITIVELY alongside `channels` below (never restrictively) -- an existing, unrelated
    // channel is completely unaffected whether or not its operator happens to also have a bound
    // topology elsewhere. `topology_authorizes` (already real, tested, and doc-commented "the
    // gate consults it additively alongside channel-members") was simply never called by
    // anything live before this.
    topologies: Arc<SqliteTopologyStore>,
    admin_token: [u8; 32],
}

/// Constant-time 32-byte token comparison (avoid leaking the admin token via timing).
fn ct_token_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Build the **edge-facing** channel-authorize router (#81 SEC81c-c c-i): the live edge
/// broker's admission gate needs `authorize(channel, holder) -> Option<operator_pubkey>`
/// (the operator key iff the holder is a current member — folding gap-2 membership/
/// revocation into the key source). The registry lives in the control plane, so the edge
/// queries this endpoint, presenting the shared edge↔CP admin token. Read-only; mounted
/// only when the admin token is configured.
///
/// * `POST /internal/channel/authorize` `{channel, holder}` + header `x-ct-admin-token`
///   → `200 {operator_pubkey}` iff member; `401` bad/missing token; `404` non-member.
fn internal_channel_authorize_router(
    channels: Arc<SqliteChannelStore>,
    topologies: Arc<SqliteTopologyStore>,
    admin_token: [u8; 32],
) -> Router {
    Router::new()
        .route("/internal/channel/authorize", post(channel_authorize))
        .with_state(AdminChannelState {
            channels,
            topologies,
            admin_token,
        })
}

#[derive(Deserialize)]
struct AuthorizeReq {
    channel: String,
    holder: String,
}
#[derive(Serialize, Deserialize)]
struct AuthorizeResp {
    operator_pubkey: String,
    /// The member's attested Noise static key (hex), when the registry has one
    /// (#72 AF4 / #100): the edge broker relays it to the paired peer so an A2A
    /// initiator can pin it without the operator pasting it. Absent for members
    /// enrolled before AF4-keydist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    noise_pubkey: Option<String>,
    /// The member's holder-signed attestation over `noise_pubkey` (#101, hex): the
    /// broker relays it so the peer can verify the Noise key is genuinely the holder's
    /// before pinning it (rejecting a DB-substituted key). Absent for members enrolled
    /// before attestation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    noise_attestation: Option<String>,
}

async fn channel_authorize(
    State(state): State<AdminChannelState>,
    headers: HeaderMap,
    Json(req): Json<AuthorizeReq>,
) -> Result<Json<AuthorizeResp>, StatusCode> {
    // Verify the shared edge↔CP admin token (constant time) before any lookup — this route's token is
    // mandatory (no dev-open path), so it calls the #186 core directly rather than the Option-aware guard.
    if !admin_token_ok(&headers, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let channel = hex_decode_32(&req.channel).ok_or(StatusCode::BAD_REQUEST)?;
    let holder = hex_decode_32(&req.holder).ok_or(StatusCode::BAD_REQUEST)?;
    // #231 root-cause candidate (2026-08-01): the three SqliteChannelStore lookups below
    // are plain synchronous `fn`s over a `Mutex<rusqlite::Connection>` -- calling them
    // directly here blocks whichever tokio worker thread is running this handler for the
    // full duration of the lock wait + DB I/O. This host runs the control-plane at
    // `cpus: 1.0` while tokio's default runtime still spawns one worker thread per HOST
    // core (4 here) -- under ANY concurrent request load those threads share a single CPU's
    // worth of CFS quota, so a handful of blocking calls landing close together can queue
    // for real, multi-second time even though each individual query is trivial. This is
    // exactly the edge broker's `authorize()` call this issue already bounds at 10s
    // (`DEFAULT_AUTHORIZE_TIMEOUT`, channel_authorize.rs) -- a queueing delay approaching
    // that bound is indistinguishable from a genuinely slow CP from the edge's side, and
    // is a very plausible source of the intermittent "channel join admission exchange
    // stalled (#140)" pattern this issue tracks. `spawn_blocking` moves the lock wait +
    // query execution onto tokio's dedicated blocking-thread pool, so a slow/contended
    // lookup here no longer starves the same small pool of async worker threads every
    // other request (including unrelated ones) depends on.
    let channels = state.channels.clone();
    let topologies = state.topologies.clone();
    let lookup = tokio::task::spawn_blocking(move || {
        let cid = ChannelId(channel);
        let op = channels.authorize_holder(&cid, &holder)?;
        let op = match op {
            Some(op) => Some(op),
            // #235/#107-enforce (ii-b): a declared topology edge is an ADDITIVE second path
            // to authorization, consulted only when the channel-membership registry has no
            // match -- a bound topology never removes an existing channel's authorization,
            // it only ever ADDS one for a channel its own drawn edges name.
            None => topologies.topology_authorizes(&cid, &holder)?,
        };
        let Some(op) = op else { return Ok(None) };
        // Also hand back the member's attested Noise key (if registered) so the
        // broker can deliver it to the paired peer (#72 AF4 / #100). A topology-only
        // authorization (no channel-store registration at all) simply has neither --
        // AuthorizeResp already treats both as optional.
        let noise = channels.member_noise_key(&cid, &holder).ok().flatten();
        let attestation = channels.member_noise_attestation(&cid, &holder).ok().flatten();
        Ok::<_, rusqlite::Error>(Some((op, noise, attestation)))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    match lookup {
        Some((op, noise, attestation)) => Ok(Json(AuthorizeResp {
            operator_pubkey: hex_encode(&op),
            noise_pubkey: noise.map(|n| hex_encode(&n)),
            noise_attestation: attestation.map(|a| hex_encode(&a)),
        })),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Shared state for the edge-facing revoked-tokens sync endpoint (#327).
#[derive(Clone)]
struct AdminRevokedTokensState {
    tunnels: Arc<crate::storage::SqliteTunnelStore>,
    admin_token: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct RevokedTokensResp {
    tokens: Vec<String>,
}

/// Build the **edge-facing** revoked-tokens sync router (#327): closes the gap where
/// an Edge's in-memory revoked-token set (`crates/edge/src/state.rs`) doesn't survive
/// a restart, silently letting a still-reconnecting Agent for an already-revoked
/// tunnel re-register. The Edge fetches this once at boot (before serving any
/// connections) and seeds its local set from it — same shared edge↔CP admin token as
/// every other internal machine endpoint here, and read-only. Mounted only when the
/// admin token is configured, matching every other internal route's fail-closed
/// posture.
///
/// * `GET /internal/revoked-tokens` + header `x-ct-admin-token` → `200 {tokens: [...]}`;
///   `401` bad/missing token.
fn internal_revoked_tokens_router(
    tunnels: Arc<crate::storage::SqliteTunnelStore>,
    admin_token: [u8; 32],
) -> Router {
    Router::new()
        .route("/internal/revoked-tokens", get(revoked_tokens))
        .with_state(AdminRevokedTokensState { tunnels, admin_token })
}

async fn revoked_tokens(
    State(state): State<AdminRevokedTokensState>,
    headers: HeaderMap,
) -> Result<Json<RevokedTokensResp>, StatusCode> {
    if !admin_token_ok(&headers, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let tokens = state.tunnels.list_revoked_tokens().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(RevokedTokensResp { tokens }))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub(crate) fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Decode an arbitrary-length lowercase/upper hex string to bytes (even length).
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

pub(crate) fn hex_decode_64(s: &str) -> Option<[u8; 64]> {
    if s.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ControlPlaneClient;

    #[test]
    fn admin_token_ok_is_the_one_extract_and_compare() {
        // #186 (frozen): after unifying the five copies, the single admin-token core must still
        // reject a missing / malformed / wrong header and accept only the exact hex of the expected
        // 32 bytes. Every gate (the layer + all inline guards) now routes through this, so this test
        // pins the shared behaviour that used to live in five places.
        use axum::http::{HeaderMap, HeaderValue};
        let expected = [0x11u8; 32];
        let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let mut h = HeaderMap::new();
        assert!(!admin_token_ok(&h, &expected), "missing header → false");
        h.insert("x-ct-admin-token", HeaderValue::from_static("not-hex"));
        assert!(!admin_token_ok(&h, &expected), "malformed header → false");
        let mut wrong = expected;
        wrong[0] ^= 0xff;
        h.insert("x-ct-admin-token", hex(&wrong).parse().unwrap());
        assert!(!admin_token_ok(&h, &expected), "wrong token → false");
        h.insert("x-ct-admin-token", hex(&expected).parse().unwrap());
        assert!(admin_token_ok(&h, &expected), "correct token → true");
    }

    #[tokio::test]
    async fn enroll_issue_requires_the_admin_token_when_configured() {
        // #87 SEC87b-auth: with an admin token configured, POST /enroll/issue requires
        // x-ct-admin-token (401 without / wrong, 200 with). With none configured it's
        // open (dev/back-compat). /enroll/redeem is unaffected (agent-authed by its
        // single-use token + proof).
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let admin = [0x7au8; 32];
        let store = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let app = enrollment_router_sqlite_with_admin(store, Some(admin));
        let issue = |tok: Option<String>| {
            let mut req = Request::post("/enroll/issue").header("content-type", "application/json");
            if let Some(t) = tok {
                req = req.header("x-ct-admin-token", t);
            }
            app.clone().oneshot(req.body(Body::from(r#"{"tenant":"t1"}"#)).unwrap())
        };
        assert_eq!(issue(None).await.unwrap().status(), StatusCode::UNAUTHORIZED, "no token -> 401");
        assert_eq!(
            issue(Some(hex_encode(&[0u8; 32]))).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "wrong token -> 401"
        );
        assert_eq!(
            issue(Some(hex_encode(&admin))).await.unwrap().status(),
            StatusCode::OK,
            "correct admin token issues a join token"
        );

        // No admin token configured -> issuance is open (dev/back-compat).
        let open = enrollment_router_sqlite_with_admin(Arc::new(SqliteEnrollment::open_in_memory().unwrap()), None);
        let r = open
            .oneshot(
                Request::post("/enroll/issue")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"tenant":"t"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "issuance open when no admin token is configured");
    }

    #[tokio::test]
    async fn enroll_issue_batch_is_admin_gated_caps_count_and_mints_n_tokens() {
        // #145 bulk provisioning (frozen): POST /enroll/issue-batch mints N tokens in one admin call,
        // enforces the SAME admin gate as /enroll/issue, and caps count to 1..=MAX_BATCH_TOKENS.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        let admin = [0x5eu8; 32];
        let store = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let app = enrollment_router_sqlite_with_admin(store, Some(admin));
        let batch = |tok: Option<String>, body: &'static str| {
            let mut req =
                Request::post("/enroll/issue-batch").header("content-type", "application/json");
            if let Some(t) = tok {
                req = req.header("x-ct-admin-token", t);
            }
            app.clone().oneshot(req.body(Body::from(body)).unwrap())
        };

        // Same admin gate as /enroll/issue.
        assert_eq!(
            batch(None, r#"{"tenant":"t1","count":3}"#).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "no admin token -> 401"
        );

        // Correct admin token → 200 with exactly `count` distinct hex tokens.
        let ok = batch(Some(hex_encode(&admin)), r#"{"tenant":"t1","count":3}"#).await.unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        let body = to_bytes(ok.into_body(), 1 << 16).await.unwrap();
        let resp: IssueBatchResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.tokens.len(), 3, "three tokens minted in one call");
        assert_eq!(
            resp.tokens.iter().collect::<std::collections::HashSet<_>>().len(),
            3,
            "the batch tokens are distinct"
        );
        assert!(resp.tokens.iter().all(|t| t.len() == 64), "each is 64 hex chars");

        // count out of range → 400 (can't exhaust the store, can't ask for zero).
        assert_eq!(
            batch(Some(hex_encode(&admin)), r#"{"tenant":"t1","count":0}"#).await.unwrap().status(),
            StatusCode::BAD_REQUEST,
            "count 0 -> 400"
        );
        assert_eq!(
            batch(Some(hex_encode(&admin)), r#"{"tenant":"t1","count":101}"#).await.unwrap().status(),
            StatusCode::BAD_REQUEST,
            "count over MAX_BATCH_TOKENS -> 400"
        );

        // #145 (Marq): with an idempotency_key, a retried request returns the SAME tokens (no dup mint).
        let tokens_of = |body: &'static str| async move {
            let r = batch(Some(hex_encode(&admin)), body).await.unwrap();
            assert_eq!(r.status(), StatusCode::OK);
            let b = to_bytes(r.into_body(), 1 << 16).await.unwrap();
            serde_json::from_slice::<IssueBatchResp>(&b).unwrap().tokens
        };
        let first = tokens_of(r#"{"tenant":"t1","count":2,"idempotency_key":"k1"}"#).await;
        let replay = tokens_of(r#"{"tenant":"t1","count":2,"idempotency_key":"k1"}"#).await;
        assert_eq!(replay, first, "same idempotency_key -> identical token set on replay");
        let other = tokens_of(r#"{"tenant":"t1","count":2,"idempotency_key":"k2"}"#).await;
        assert_ne!(other, first, "a different idempotency_key mints a fresh set");

        // #145 idem-conflict: reusing key "k1" with a mismatched count or tenant is a loud 409,
        // not a silent replay of the original set (a client key-reuse bug can't mis-provision).
        assert_eq!(
            batch(Some(hex_encode(&admin)), r#"{"tenant":"t1","count":3,"idempotency_key":"k1"}"#)
                .await.unwrap().status(),
            StatusCode::CONFLICT,
            "same key + different count -> 409"
        );
        assert_eq!(
            batch(Some(hex_encode(&admin)), r#"{"tenant":"t2","count":2,"idempotency_key":"k1"}"#)
                .await.unwrap().status(),
            StatusCode::CONFLICT,
            "same key + different tenant -> 409"
        );
        // The original operation still replays cleanly after the rejected conflicts.
        assert_eq!(
            tokens_of(r#"{"tenant":"t1","count":2,"idempotency_key":"k1"}"#).await,
            first,
            "matching retry still returns the original set after conflicts"
        );
    }

    #[tokio::test]
    async fn billing_writers_require_the_admin_token_when_configured() {
        // #87 SEC87b-auth-billing: with an admin token configured, the client-supplied-account
        // billing writers (/accounts/open, /payment/intent, /billing/issue) require
        // x-ct-admin-token (401 without / wrong). With none configured they stay open
        // (dev/back-compat). The customer path is the session-authed portal, not these routes.
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let admin = [0x3cu8; 32];
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let gated = billing_writers_gated(ledger.clone(), Some(admin));
        let open_req = |tok: Option<String>| {
            let mut req = Request::post("/accounts/open").header("content-type", "application/json");
            if let Some(t) = tok {
                req = req.header("x-ct-admin-token", t);
            }
            gated.clone().oneshot(req.body(Body::from("{}")).unwrap())
        };
        assert_eq!(open_req(None).await.unwrap().status(), StatusCode::UNAUTHORIZED, "no token -> 401");
        assert_eq!(
            open_req(Some(hex_encode(&[0u8; 32]))).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "wrong token -> 401"
        );
        // Correct token opens an account (200 with a JSON account id).
        let r = open_req(Some(hex_encode(&admin))).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK, "correct admin token opens an account");

        // /payment/intent is gated too (needs a real account first — open one with the token).
        let intent_no_tok = gated
            .clone()
            .oneshot(
                Request::post("/payment/intent")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"account":"00","credits":5}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(intent_no_tok.status(), StatusCode::UNAUTHORIZED, "/payment/intent gated");

        // No admin token configured -> writers stay open (dev/back-compat).
        let open = billing_writers_gated(Arc::new(SqliteLedger::open_in_memory().unwrap()), None);
        let r = open
            .oneshot(
                Request::post("/accounts/open")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "billing writers open when no admin token is configured");
    }

    #[tokio::test]
    async fn registry_register_requires_the_admin_token_but_resolve_stays_open() {
        // #87 SEC87b-auth-registry: with an admin token configured, POST /registry/register
        // requires x-ct-admin-token (401 without / wrong, 200 with), while GET
        // /registry/resolve stays open (a read, no durable write). With no token
        // configured, register is open (dev/back-compat).
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let admin = [0x5eu8; 32];
        let store = Arc::new(SqliteRegistry::open_in_memory().unwrap());
        let gated = registry_router_sqlite_gated(store.clone(), Some(admin));
        let tok = hex_encode(&[0x11u8; 32]); // routing token to register/resolve
        let reg = |admin_hdr: Option<String>| {
            let mut req = Request::post("/registry/register").header("content-type", "application/json");
            if let Some(t) = admin_hdr {
                req = req.header("x-ct-admin-token", t);
            }
            gated.clone().oneshot(
                req.body(Body::from(format!(
                    r#"{{"token":"{tok}","tenant":"t","agent":"a"}}"#
                )))
                .unwrap(),
            )
        };
        assert_eq!(reg(None).await.unwrap().status(), StatusCode::UNAUTHORIZED, "no token -> 401");
        assert_eq!(
            reg(Some(hex_encode(&[0u8; 32]))).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "wrong token -> 401"
        );
        assert_eq!(
            reg(Some(hex_encode(&admin))).await.unwrap().status(),
            StatusCode::OK,
            "correct admin token registers"
        );
        // Resolve (read) is open even with a token configured, and returns the row
        // the authorized register just wrote.
        let resolved = gated
            .clone()
            .oneshot(Request::get(format!("/registry/resolve/{tok}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resolved.status(), StatusCode::OK, "resolve stays open (no admin token needed)");

        // No admin token configured -> register is open (dev/back-compat).
        let open = registry_router_sqlite_gated(Arc::new(SqliteRegistry::open_in_memory().unwrap()), None);
        let r = open
            .oneshot(
                Request::post("/registry/register")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"token":"{tok}","tenant":"t","agent":"a"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "register open when no admin token is configured");
    }

    #[tokio::test]
    async fn bootstrap_mint_is_admin_gated_and_redeem_hands_off_once() {
        // #90/#97 SEC90b-wire: /bootstrap/mint is admin-gated (minting hands off a
        // secret bundle); /bootstrap/redeem is public (possession of the short-lived
        // single-use token is the auth) and returns the secret in the TLS body exactly
        // once — 409 on reuse, 404 on unknown.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        let admin = [0x9au8; 32];
        let store = Arc::new(SqliteBootstrap::open_in_memory().unwrap());
        let app = bootstrap_router(store, Some(admin));

        // Mint requires the admin token.
        let mint_no = app
            .clone()
            .oneshot(
                Request::post("/bootstrap/mint")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"secret":"join=aa;routing=bb"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mint_no.status(), StatusCode::UNAUTHORIZED, "mint needs the admin token");

        // Mint with the admin token returns a bootstrap token.
        let mint = app
            .clone()
            .oneshot(
                Request::post("/bootstrap/mint")
                    .header("content-type", "application/json")
                    .header("x-ct-admin-token", hex_encode(&admin))
                    .body(Body::from(r#"{"secret":"join=aa;routing=bb"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mint.status(), StatusCode::OK);
        let mb = to_bytes(mint.into_body(), 1 << 16).await.unwrap();
        let minted: BootstrapMintResp = serde_json::from_slice(&mb).unwrap();

        let redeem = |tok: String| {
            app.clone().oneshot(
                Request::post("/bootstrap/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"token":"{tok}"}}"#)))
                    .unwrap(),
            )
        };

        // Redeem is public and hands off the exact secret once.
        let r1 = redeem(minted.token.clone()).await.unwrap();
        assert_eq!(r1.status(), StatusCode::OK, "redeem is public");
        let b1 = to_bytes(r1.into_body(), 1 << 16).await.unwrap();
        let got: BootstrapRedeemResp = serde_json::from_slice(&b1).unwrap();
        assert_eq!(got.secret, "join=aa;routing=bb", "hands off the exact minted secret");

        // Second redemption -> 409 (single-use), unknown token -> 404.
        assert_eq!(
            redeem(minted.token.clone()).await.unwrap().status(),
            StatusCode::CONFLICT,
            "single-use: second redeem is 409"
        );
        assert_eq!(
            redeem(hex_encode(&[0u8; 32])).await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "unknown token -> 404"
        );

        // With no admin token configured, mint is open (dev/back-compat).
        let open = bootstrap_router(Arc::new(SqliteBootstrap::open_in_memory().unwrap()), None);
        let r = open
            .oneshot(
                Request::post("/bootstrap/mint")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"secret":"x"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "mint open when no admin token is configured");
    }

    #[tokio::test]
    async fn channel_invite_redeem_with_fresh_challenge_is_single_use() {
        // #108 defense-in-depth: fetch a challenge, sign the challenge-bound redemption,
        // redeem -> 200; the same challenge again -> 403 (nonce consumed); a redemption
        // bound to a stale/unknown nonce -> 403.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use ed25519_dalek::{Signer, SigningKey};
        use tower::ServiceExt;

        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let operator_sk = SigningKey::from_bytes(&[0x51u8; 32]);
        let operator_pk = operator_sk.verifying_key().to_bytes();
        let chan = ChannelId([0xa1u8; 32]);
        channels.register_channel(&chan, &operator_pk, "alice").unwrap();

        let invitee_sk = SigningKey::from_bytes(&[0x62u8; 32]);
        let invitee = invitee_sk.verifying_key().to_bytes();
        let holder_sk = SigningKey::from_bytes(&[0x73u8; 32]);
        let holder = holder_sk.verifying_key().to_bytes();
        let nk = [0xd4u8; 32];

        let invitation = ct_common::channel::ChannelInvitation {
            channel: chan,
            invitee_identity: invitee,
            direction: ct_common::channel::Direction::Both,
            rights: ct_common::channel::Rights::ReadWrite,
            delegable: false,
            expires_at: 10_000_000_000,
        };
        let inv_sig = operator_sk.sign(&invitation.signing_bytes()).to_bytes();
        let signed = ct_common::channel::SignedChannelInvitation { invitation, signature: inv_sig };
        let inv_hex = hex_encode(&signed.encode());
        let attest = hex_encode(
            &holder_sk.sign(&ct_common::channel::member_noise_attest_bytes(&chan, &holder, &nk)).to_bytes(),
        );

        let app = channel_invite_router(channels.clone());

        // 1) Fetch a fresh challenge nonce.
        let ch_resp = app
            .clone()
            .oneshot(Request::post("/channel/invite/challenge").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(ch_resp.status(), StatusCode::OK);
        let cb = to_bytes(ch_resp.into_body(), 1 << 16).await.unwrap();
        let challenge: InviteChallengeResp = serde_json::from_slice(&cb).unwrap();
        let nonce = hex_decode_32(&challenge.challenge).unwrap();

        // 2) Sign the challenge-bound redemption and redeem.
        let redeem = hex_encode(
            &invitee_sk
                .sign(&ct_common::channel::invitation_redeem_challenge_bytes(&chan, &invitee, &holder, &nonce))
                .to_bytes(),
        );
        let body = format!(
            r#"{{"invitation":"{inv_hex}","redeem_sig":"{redeem}","holder":"{h}","noise_pubkey":"{n}","noise_attestation":"{a}","challenge":"{c}"}}"#,
            h = hex_encode(&holder), n = hex_encode(&nk), a = attest, c = challenge.challenge,
        );
        let redeem_req = |b: String| {
            app.clone().oneshot(
                Request::post("/channel/invite/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(b))
                    .unwrap(),
            )
        };
        assert_eq!(redeem_req(body.clone()).await.unwrap().status(), StatusCode::OK, "challenge redemption admits");
        assert_eq!(channels.authorize_holder(&chan, &holder).unwrap(), Some(operator_pk));

        // 3) Replaying the SAME challenge-bound redemption -> the nonce is already consumed
        // (403 stale/unknown challenge) — non-replayable independent of invitation single-use.
        assert_eq!(redeem_req(body).await.unwrap().status(), StatusCode::FORBIDDEN, "consumed nonce -> 403");
    }

    #[tokio::test]
    async fn channel_invite_redeem_single_use_survives_revocation() {
        // #108: a redemption is single-use — a replay is 409, and a REVOKED member cannot
        // replay the identical redemption to restore membership (the bypass this fixes).
        use axum::body::Body;
        use axum::http::Request;
        use ed25519_dalek::{Signer, SigningKey};
        use tower::ServiceExt;

        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let operator_sk = SigningKey::from_bytes(&[0x51u8; 32]);
        let operator_pk = operator_sk.verifying_key().to_bytes();
        let chan = ChannelId([0xa1u8; 32]);
        channels.register_channel(&chan, &operator_pk, "alice").unwrap();

        let invitee_sk = SigningKey::from_bytes(&[0x62u8; 32]);
        let invitee = invitee_sk.verifying_key().to_bytes();
        let holder_sk = SigningKey::from_bytes(&[0x73u8; 32]);
        let holder = holder_sk.verifying_key().to_bytes();
        let nk = [0xd4u8; 32];

        let invitation = ct_common::channel::ChannelInvitation {
            channel: chan,
            invitee_identity: invitee,
            direction: ct_common::channel::Direction::Both,
            rights: ct_common::channel::Rights::ReadWrite,
            delegable: false,
            expires_at: 10_000_000_000,
        };
        let inv_sig = operator_sk.sign(&invitation.signing_bytes()).to_bytes();
        let signed = ct_common::channel::SignedChannelInvitation { invitation, signature: inv_sig };
        let inv_hex = hex_encode(&signed.encode());
        let redeem = hex_encode(
            &invitee_sk
                .sign(&ct_common::channel::invitation_redeem_bytes(&chan, &invitee, &holder))
                .to_bytes(),
        );
        let attest = hex_encode(
            &holder_sk
                .sign(&ct_common::channel::member_noise_attest_bytes(&chan, &holder, &nk))
                .to_bytes(),
        );

        let app = channel_invite_router(channels.clone());
        let body = format!(
            r#"{{"invitation":"{inv_hex}","redeem_sig":"{redeem}","holder":"{h}","noise_pubkey":"{n}","noise_attestation":"{a}"}}"#,
            h = hex_encode(&holder),
            n = hex_encode(&nk),
            a = attest,
        );
        let post = || {
            app.clone().oneshot(
                Request::post("/channel/invite/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
        };

        // First redemption admits the member.
        assert_eq!(post().await.unwrap().status(), StatusCode::OK, "first redeem admits");
        assert_eq!(channels.authorize_holder(&chan, &holder).unwrap(), Some(operator_pk));

        // An identical replay is rejected — single-use.
        assert_eq!(post().await.unwrap().status(), StatusCode::CONFLICT, "replay -> 409");

        // The owner revokes the member.
        assert!(channels.remove_member(&chan, "alice", &holder).unwrap());
        assert_eq!(channels.authorize_holder(&chan, &holder).unwrap(), None, "revoked at the gate");

        // The revoked member replays the identical redemption -> still 409; membership is
        // NOT restored. This is the #108 bypass, now closed.
        assert_eq!(
            post().await.unwrap().status(),
            StatusCode::CONFLICT,
            "a revoked member cannot replay the redemption to restore membership"
        );
        assert_eq!(channels.authorize_holder(&chan, &holder).unwrap(), None, "still revoked -- remove_member holds");
    }

    #[tokio::test]
    async fn channel_invite_redeem_admits_a_cross_user_member_from_the_proofs() {
        // #72 AF3-redeem-cp: a *different* user's agent joins a channel it was invited
        // to, with no session — the operator-signed invitation + the invitee redemption
        // + the holder Noise attestation are the authorization.
        use axum::body::Body;
        use axum::http::Request;
        use ed25519_dalek::{Signer, SigningKey};
        use tower::ServiceExt;

        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        // The channel owner ("alice") registers her channel under a REAL operator key.
        let operator_sk = SigningKey::from_bytes(&[0x51u8; 32]);
        let operator_pk = operator_sk.verifying_key().to_bytes();
        let chan = ChannelId([0xa1u8; 32]);
        channels.register_channel(&chan, &operator_pk, "alice").unwrap();

        // A different user's agent: an identity key (invited) + a member holder key.
        let invitee_sk = SigningKey::from_bytes(&[0x62u8; 32]);
        let invitee = invitee_sk.verifying_key().to_bytes();
        let holder_sk = SigningKey::from_bytes(&[0x73u8; 32]);
        let holder = holder_sk.verifying_key().to_bytes();
        let nk = [0xd4u8; 32];

        // The owner (operator) signs an invitation for the invitee identity.
        let invitation = ct_common::channel::ChannelInvitation {
            channel: chan,
            invitee_identity: invitee,
            direction: ct_common::channel::Direction::Both,
            rights: ct_common::channel::Rights::ReadWrite,
            delegable: false,
            expires_at: 10_000_000_000, // far future — the handler uses the wall clock
        };
        let inv_sig = operator_sk.sign(&invitation.signing_bytes()).to_bytes();
        let signed = ct_common::channel::SignedChannelInvitation { invitation, signature: inv_sig };
        let inv_hex = hex_encode(&signed.encode());
        // The invitee accepts + binds `holder`; the holder attests its Noise key.
        let redeem = hex_encode(
            &invitee_sk
                .sign(&ct_common::channel::invitation_redeem_bytes(&chan, &invitee, &holder))
                .to_bytes(),
        );
        let attest = hex_encode(
            &holder_sk
                .sign(&ct_common::channel::member_noise_attest_bytes(&chan, &holder, &nk))
                .to_bytes(),
        );

        let app = channel_invite_router(channels.clone());
        let body = |redeem: &str| {
            format!(
                r#"{{"invitation":"{inv_hex}","redeem_sig":"{redeem}","holder":"{h}","noise_pubkey":"{n}","noise_attestation":"{a}"}}"#,
                h = hex_encode(&holder),
                n = hex_encode(&nk),
                a = attest,
            )
        };
        let post = |b: String| {
            app.clone().oneshot(
                Request::post("/channel/invite/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(b))
                    .unwrap(),
            )
        };

        // Valid proofs -> the invitee's holder is admitted as a member.
        assert_eq!(post(body(&redeem)).await.unwrap().status(), StatusCode::OK, "valid redemption admits");
        assert_eq!(
            channels.authorize_holder(&chan, &holder).unwrap(),
            Some(operator_pk),
            "the invited member now resolves the channel operator key (drives the broker)"
        );
        assert_eq!(
            channels.member_noise_key(&chan, &holder).unwrap(),
            Some(nk),
            "the invited member's attested Noise key is pinned"
        );

        // A redemption signature that bound a DIFFERENT holder does not verify -> 403.
        let wrong = hex_encode(
            &invitee_sk
                .sign(&ct_common::channel::invitation_redeem_bytes(&chan, &invitee, &[0xee; 32]))
                .to_bytes(),
        );
        assert_eq!(post(body(&wrong)).await.unwrap().status(), StatusCode::FORBIDDEN, "bad redemption -> 403");

        // An invitation for an unregistered channel -> 404 (no operator to verify against).
        let other_chan = ChannelId([0x0bu8; 32]);
        let other_inv = ct_common::channel::ChannelInvitation {
            channel: other_chan,
            invitee_identity: invitee,
            direction: ct_common::channel::Direction::Both,
            rights: ct_common::channel::Rights::ReadWrite,
            delegable: false,
            expires_at: 10_000_000_000,
        };
        let other_sig = operator_sk.sign(&other_inv.signing_bytes()).to_bytes();
        let other_hex = hex_encode(
            &ct_common::channel::SignedChannelInvitation { invitation: other_inv, signature: other_sig }.encode(),
        );
        let other_redeem = hex_encode(
            &invitee_sk
                .sign(&ct_common::channel::invitation_redeem_bytes(&other_chan, &invitee, &holder))
                .to_bytes(),
        );
        let b = format!(
            r#"{{"invitation":"{other_hex}","redeem_sig":"{other_redeem}","holder":"{h}","noise_pubkey":"{n}","noise_attestation":"{a}"}}"#,
            h = hex_encode(&holder),
            n = hex_encode(&nk),
            a = attest,
        );
        assert_eq!(post(b).await.unwrap().status(), StatusCode::NOT_FOUND, "unknown channel -> 404");
    }

    #[tokio::test]
    async fn unauthenticated_writers_are_rate_limited_per_ip() {
        // #87 SEC87b-rl: a per-IP fixed-window cap on the unauthenticated
        // DB-writers. One address that floods a metered POST is `429`'d past the
        // limit; a different address has its own budget; a non-listed path and a
        // read are never metered.
        use axum::body::Body;
        use tower::ServiceExt;

        let app = with_unauth_write_limit(
            Router::new()
                .route("/accounts/open", post(|| async { StatusCode::OK }))
                .route("/other", post(|| async { StatusCode::OK }))
                .route("/registry/resolve/x", get(|| async { StatusCode::OK })),
            2,
        );

        let a: SocketAddr = "203.0.113.5:5000".parse().unwrap();
        let b: SocketAddr = "203.0.113.6:5000".parse().unwrap();
        async fn call(app: &Router, method: Method, path: &str, peer: SocketAddr) -> StatusCode {
            let mut req = Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(peer));
            app.clone().oneshot(req).await.unwrap().status()
        }

        // A: first two metered POSTs pass, the third is throttled.
        assert_eq!(call(&app, Method::POST, "/accounts/open", a).await, StatusCode::OK);
        assert_eq!(call(&app, Method::POST, "/accounts/open", a).await, StatusCode::OK);
        assert_eq!(
            call(&app, Method::POST, "/accounts/open", a).await,
            StatusCode::TOO_MANY_REQUESTS,
            "the 3rd metered POST from the same IP is rate limited"
        );
        // B: a different address keeps its own budget.
        assert_eq!(
            call(&app, Method::POST, "/accounts/open", b).await,
            StatusCode::OK,
            "a different client IP is not affected"
        );
        // A non-listed POST and a read are never metered, even for the throttled IP.
        assert_eq!(
            call(&app, Method::POST, "/other", a).await,
            StatusCode::OK,
            "a path outside the unauth-writer set is not metered"
        );
        assert_eq!(
            call(&app, Method::GET, "/registry/resolve/x", a).await,
            StatusCode::OK,
            "reads are not metered"
        );
    }

    fn temp_db_path() -> String {
        let mut b = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
        let name: String = b.iter().map(|x| format!("{x:02x}")).collect();
        std::env::temp_dir()
            .join(format!("ct_svc_{name}.db"))
            .to_string_lossy()
            .into_owned()
    }

    /// Serve the persistent enrollment router (on `db_path`) on an ephemeral
    /// port; returns the base URL. Simulates one process instance.
    async fn spawn(db_path: &str) -> String {
        let store = Arc::new(SqliteEnrollment::open(db_path).unwrap());
        let app = enrollment_router_sqlite(store);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    /// The production requirement at the service level: state survives a restart.
    /// Enroll against one service instance, then start a fresh instance on the
    /// same DB file and confirm the consumed token stays consumed.
    #[tokio::test]
    async fn enrollment_survives_service_restart() {
        use ed25519_dalek::{Signer, SigningKey};
        let db = temp_db_path();
        let agent = AgentId("agent-x".to_string());
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pubkey = sk.verifying_key().to_bytes();
        let token;
        let proof;
        {
            let cp = ControlPlaneClient::new(spawn(&db).await);
            token = cp
                .issue_join_token(&TenantId("tenant-x".to_string()))
                .await
                .unwrap();
            proof = sk.sign(&token).to_bytes();
            let tenant = cp.redeem(&token, &agent, &pubkey, &proof).await.unwrap();
            assert_eq!(tenant.0, "tenant-x", "redeem binds the tenant");
        }

        // Fresh service instance on the same database (a restart).
        let cp2 = ControlPlaneClient::new(spawn(&db).await);
        let replay = cp2.redeem(&token, &agent, &pubkey, &proof).await;
        assert!(
            matches!(replay, Err(crate::client::CpError::Status(_))),
            "the token stays consumed across a service restart"
        );

        let _ = std::fs::remove_file(&db);
    }

    /// Serve the persistent registry router (on `db_path`) on an ephemeral port.
    async fn spawn_registry(db_path: &str) -> String {
        let store = Arc::new(SqliteRegistry::open(db_path).unwrap());
        let app = registry_router_sqlite(store);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn registry_survives_service_restart() {
        let db = temp_db_path();
        let token = RoutingToken([0x5a; 32]);
        {
            let cp = ControlPlaneClient::new(spawn_registry(&db).await);
            cp.register(&token, &TenantId("t".to_string()), &AgentId("a".to_string()))
                .await
                .unwrap();
        }
        // Fresh instance on the same DB file.
        let cp2 = ControlPlaneClient::new(spawn_registry(&db).await);
        let (t, a) = cp2.resolve(&token).await.unwrap();
        assert_eq!(
            (t.0.as_str(), a.0.as_str()),
            ("t", "a"),
            "registration survives a service restart"
        );
        let _ = std::fs::remove_file(&db);
    }

    /// Serve the persistent billing router (on `db_path`) on an ephemeral port.
    async fn spawn_billing(db_path: &str) -> String {
        let store = Arc::new(SqliteLedger::open(db_path).unwrap());
        let app = billing_router_sqlite(store);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn billing_survives_service_restart() {
        let db = temp_db_path();
        let account;
        let payment;
        {
            let cp = ControlPlaneClient::new(spawn_billing(&db).await);
            account = cp.open_account().await.unwrap();
            payment = cp.create_payment_intent(&account, 3).await.unwrap();
            cp.confirm_payment(&payment).await.unwrap(); // balance -> 3
        }
        // Fresh instance on the same DB file.
        let cp2 = ControlPlaneClient::new(spawn_billing(&db).await);
        // Balance persisted -> buying a token succeeds (debits the credit).
        let token = cp2.buy_token(&account, 1).await.unwrap();
        assert_ne!(token.0, [0u8; 32], "a token is minted for the funded account");
        // Idempotency persisted -> confirming the same payment again is refused.
        let replay = cp2.confirm_payment(&payment).await;
        assert!(
            matches!(replay, Err(crate::client::CpError::Status(_))),
            "payment stays confirmed across a service restart"
        );
        let _ = std::fs::remove_file(&db);
    }

    #[tokio::test]
    async fn buy_token_idempotent_replays_the_same_token_without_a_second_debit_272() {
        // #272: retrying /billing/issue with the SAME idempotency key (simulating a
        // caller that never saw the first response) must return the same token and
        // must NOT debit the account again. ControlPlaneClient has no direct balance
        // getter, so correctness is proven indirectly: credit exactly 10, spend 3,
        // "retry" that same purchase, then spend the remaining 7 exactly -- if the
        // retry had double-debited, only 4 would be left and this last purchase would
        // be refused.
        let db = temp_db_path();
        let cp = ControlPlaneClient::new(spawn_billing(&db).await);
        let account = cp.open_account().await.unwrap();
        let payment = cp.create_payment_intent(&account, 10).await.unwrap();
        cp.confirm_payment(&payment).await.unwrap(); // balance -> 10

        let key = [0x42u8; 32];
        let first = cp.buy_token_idempotent(&account, 3, &key).await.unwrap();

        // The retry: same key, same price -- as a caller would send after a lost response.
        let replay = cp.buy_token_idempotent(&account, 3, &key).await.unwrap();
        assert_eq!(replay.0, first.0, "the retry gets back the SAME token");

        // Exactly the remaining balance -- fails if the retry above secretly re-debited.
        let key2 = [0x43u8; 32];
        let second = cp.buy_token_idempotent(&account, 7, &key2).await.unwrap();
        assert_ne!(second.0, first.0, "a different key mints a different token");

        // Now genuinely broke: even 1 more credit is refused.
        let key3 = [0x44u8; 32];
        let broke = cp.buy_token_idempotent(&account, 1, &key3).await;
        assert!(matches!(broke, Err(crate::client::CpError::Status(_))), "exhausted after exactly one debit per key");

        let _ = std::fs::remove_file(&db);
    }

    /// Serve the full unified persistent control-plane on an ephemeral port.
    /// The webhook secret the unified-router tests sign their credit events with.
    const TEST_WEBHOOK_SECRET: &[u8] = b"whsec_unified_test";

    async fn spawn_unified(db_path: &str) -> String {
        // #194: the production router fail-closes the client-supplied-account billing writers
        // (/accounts/open, /payment/intent, /billing/issue) when no admin token is configured. This
        // E2E restart test legitimately drives them (open_account / buy_token) to prove billing
        // persists across a restart, so mount the OPEN (ungated) writers here against the SAME db —
        // test-only, and no route conflict since the production router mounts none without a token.
        let app = persistent_control_plane_router(db_path, TEST_WEBHOOK_SECRET, b"test-session-key", OidcVerifierHandle::empty())
            .unwrap()
            .merge(billing_writers_gated(std::sync::Arc::new(SqliteLedger::open(db_path).unwrap()), None));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    /// Credit an account by posting a signed "payment succeeded" webhook to a
    /// live unified router — the production top-up path (there is no client
    /// `/payment/confirm`). Returns the HTTP status.
    async fn credit_via_webhook(base: &str, payment: &[u8; 32]) -> reqwest::StatusCode {
        let verifier = WebhookVerifier::new(TEST_WEBHOOK_SECRET.to_vec(), 300);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = format!(
            r#"{{"payment":"{}","status":"succeeded"}}"#,
            hex_encode(payment)
        );
        let sig = verifier.sign(now, body.as_bytes());
        reqwest::Client::new()
            .post(format!("{base}/payment/webhook"))
            .header("x-ct-webhook-timestamp", now.to_string())
            .header("x-ct-webhook-signature", sig)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn persistent_control_plane_mounts_the_agent_registry() {
        // #144 ②/#161: the searchable agent directory is MOUNTED unconditionally — its public
        // `GET /registry/agents` search is reachable (200, not 404) with OR without an OIDC
        // verifier. The write (`POST`) is a machine-writer gated by the admin token (not OIDC),
        // so the directory no longer rides on the authed `/me/*` surface; both autonomous agents
        // (self-enroll M2M) and any peer (search) reach it without a browser-interactive login.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        let db = temp_db_path();
        let oidc = Some(Arc::new(OidcVerifier::from_hs_secret(b"realm-secret", "https://kc/realms/ct")));
        let app =
            persistent_control_plane_router(&db, b"webhook-secret", b"test-session-key", OidcVerifierHandle::from(oidc)).unwrap();
        let resp = app
            .oneshot(Request::get("/registry/agents?role=source").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "GET /registry/agents is mounted (not 404)");
        let body = to_bytes(resp.into_body(), 1 << 16).await.unwrap();
        assert!(serde_json::from_slice::<Vec<AgentDirectoryEntry>>(&body).unwrap().is_empty(), "empty directory");

        // Without an OIDC verifier the public search is STILL mounted (#161): it is a public,
        // machine-facing surface, not part of the authed `/me/*` set that OIDC gates.
        let no_oidc = persistent_control_plane_router(&db, b"webhook-secret", b"test-session-key", OidcVerifierHandle::empty()).unwrap();
        let still = no_oidc
            .oneshot(Request::get("/registry/agents?role=source").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(still.status(), StatusCode::OK, "public search mounts without OIDC (#161)");

        let _ = std::fs::remove_file(&db);
    }

    /// The milestone E2E: the whole control plane (enrollment + registry +
    /// billing on one DB) survives a restart. Drive all three against one
    /// instance, restart on the same file, and confirm every concern persisted.
    #[tokio::test]
    async fn unified_control_plane_survives_restart() {
        use ed25519_dalek::{Signer, SigningKey};
        let db = temp_db_path();
        let agent = AgentId("agent-u".to_string());
        let token = RoutingToken([0x33; 32]);
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let pubkey = sk.verifying_key().to_bytes();
        let join;
        let proof;
        let account;
        {
            let base = spawn_unified(&db).await;
            let cp = ControlPlaneClient::new(base.clone());
            // enrollment
            join = cp.issue_join_token(&TenantId("tu".to_string())).await.unwrap();
            proof = sk.sign(&join).to_bytes();
            cp.redeem(&join, &agent, &pubkey, &proof).await.unwrap();
            // registry
            cp.register(&token, &TenantId("tu".to_string()), &agent).await.unwrap();
            // billing — credit via the signed provider webhook (production path;
            // there is no client-callable /payment/confirm on the unified router).
            account = cp.open_account().await.unwrap();
            let p = cp.create_payment_intent(&account, 2).await.unwrap();
            let status = credit_via_webhook(&base, &p).await;
            assert!(status.is_success(), "signed webhook credits the account");
        }

        // Restart on the same database file.
        let cp2 = ControlPlaneClient::new(spawn_unified(&db).await);
        assert!(
            cp2.redeem(&join, &agent, &pubkey, &proof).await.is_err(),
            "enrollment persisted (token consumed)"
        );
        let (t, a) = cp2.resolve(&token).await.unwrap();
        assert_eq!((t.0.as_str(), a.0.as_str()), ("tu", "agent-u"), "registry persisted");
        let bought = cp2.buy_token(&account, 1).await.unwrap();
        assert_ne!(bought.0, [0u8; 32], "billing persisted (funded account buys a token)");

        let _ = std::fs::remove_file(&db);
    }

    /// M19.3: issuance is tied to the authenticated OIDC subject. Without a valid
    /// bearer token the request is 401; with one, the debit hits the subject's
    /// own account (derived from `sub`, not from the request body).
    #[tokio::test]
    async fn authed_issue_uses_the_subject_account_and_requires_a_token() {
        use axum::body::Body;
        use axum::http::Request;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        let secret = b"realm-secret";
        let issuer = "https://kc/realms/ct";
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let verifier = Arc::new(OidcVerifier::from_hs_secret(secret, issuer));

        // Pre-credit the account bound to the subject so issuance can succeed.
        let account = ledger.account_for_subject("user-1").unwrap();
        ledger.credit(&account, 5).unwrap();

        let app = authed_billing_router(ledger.clone(), OidcVerifierHandle::new(Some(verifier)), 100);

        // No token -> 401.
        let resp = app
            .clone()
            .oneshot(
                Request::post("/me/issue")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"price":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "no bearer token");

        // Valid token -> 200 and the subject's own account is debited.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({ "sub": "user-1", "iss": issuer, "exp": now + 3600 });
        let jwt = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        let resp = app
            .clone()
            .oneshot(
                Request::post("/me/issue")
                    .header("authorization", format!("Bearer {jwt}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"price":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "authenticated issue succeeds");
        assert_eq!(
            ledger.balance(&account).unwrap(),
            4,
            "the subject's account was debited"
        );
    }

    /// #328: before this fix, an unavailable OIDC verifier meant the `/me/*`
    /// routers were never mounted at all -- an unavailable-vs-nonexistent route
    /// was indistinguishable, both surfacing as `404`. Routers are now always
    /// mounted against a handle; a request while the verifier isn't installed
    /// yet must get a clear `503`, and a later `set()` (what the background
    /// self-heal task does) must make the SAME already-built router start
    /// authenticating requests with zero rebuild/reconnect.
    #[tokio::test]
    async fn authed_router_returns_503_while_unready_then_self_heals_once_the_handle_is_set() {
        use axum::body::Body;
        use axum::http::Request;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        let secret = b"realm-secret";
        let issuer = "https://kc/realms/ct";
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let account = ledger.account_for_subject("user-1").unwrap();
        ledger.credit(&account, 5).unwrap();

        let handle = OidcVerifierHandle::empty();
        assert!(!handle.is_ready());
        let app = authed_billing_router(ledger.clone(), handle.clone(), 100);

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let claims = serde_json::json!({ "sub": "user-1", "iss": issuer, "exp": now + 3600 });
        let jwt = encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(secret)).unwrap();

        // Even a genuinely valid-looking bearer token can't be checked yet -- 503, not
        // 401 (401 would wrongly imply "this specific token is bad") and not 404 (the
        // route DOES exist, mounted unconditionally now).
        let resp = app
            .clone()
            .oneshot(
                Request::post("/me/issue")
                    .header("authorization", format!("Bearer {jwt}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"price":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "verifier not installed yet -> 503, not 404/401");

        // The background self-heal task's only action: set() on the SAME handle the
        // already-built router closed over.
        handle.set(Arc::new(OidcVerifier::from_hs_secret(secret, issuer)));
        assert!(handle.is_ready());

        let resp = app
            .oneshot(
                Request::post("/me/issue")
                    .header("authorization", format!("Bearer {jwt}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"price":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "#328: the same router self-heals once the handle is set, no restart/rebuild");
    }

    /// #328: `/status`'s `oidc_enabled` must track the handle live, not a
    /// boot-time snapshot -- otherwise the whole point of self-healing (an
    /// operator/monitor observing recovery without restarting the process) is
    /// lost even though the routes themselves did recover.
    #[tokio::test]
    async fn status_oidc_enabled_reflects_the_live_handle_not_a_boot_time_snapshot() {
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        let enrollment = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let registry = Arc::new(SqliteRegistry::open_in_memory().unwrap());
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let agent_directory = Arc::new(SqliteAgentDirectory::open_in_memory().unwrap());
        let pipeline_registry = Arc::new(SqlitePipelineRegistry::open_in_memory().unwrap());
        let handle = OidcVerifierHandle::empty();

        let app = status_router(enrollment, registry, ledger, agent_directory, pipeline_registry, None, handle.clone());

        let get_oidc_enabled = |app: Router| async {
            let resp = app.oneshot(Request::get("/status").body(Body::empty()).unwrap()).await.unwrap();
            let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            serde_json::from_slice::<StatusResp>(&body).unwrap().oidc_enabled
        };
        assert!(!get_oidc_enabled(app.clone()).await, "not ready yet");

        handle.set(Arc::new(OidcVerifier::from_hs_secret(b"s", "https://kc/realms/ct")));
        assert!(get_oidc_enabled(app).await, "#328: reflects the self-heal live, without rebuilding the router");
    }

    #[tokio::test]
    async fn authed_network_api_is_owner_scoped_and_plans_from_the_policy() {
        // #102-rest: PUT/GET /me/networks/:id is subject-scoped; /plan returns the
        // policy-compiled desired connectivity.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use ct_common::policy::{Agent, AllowRule, Levels, Network, Pair, Policy, Selector};
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        let secret = b"realm-secret";
        let issuer = "https://kc/realms/ct";
        let verifier = Arc::new(OidcVerifier::from_hs_secret(secret, issuer));
        let networks = Arc::new(SqliteNetworkStore::open_in_memory().unwrap());
        let app = authed_network_router(networks, OidcVerifierHandle::new(Some(verifier)));

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let jwt_for = |sub: &str| {
            let claims = serde_json::json!({ "sub": sub, "iss": issuer, "exp": now + 3600 });
            encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(secret)).unwrap()
        };
        let alice = jwt_for("alice");
        let mallory = jwt_for("mallory");

        let net = Network {
            agents: vec![
                Agent::new("dev-1", "dev", "internal"),
                Agent::new("ops-1", "ops", "internal"),
            ],
            policy: Policy {
                levels: Levels::new(["public", "internal", "secret"]),
                rules: vec![
                    AllowRule { from: Selector::group("dev"), to: Selector::group("ops") },
                    AllowRule { from: Selector::group("ops"), to: Selector::group("dev") },
                ],
                mac_flow_control: true,
            },
        };
        let net_json = serde_json::to_string(&net).unwrap();

        // A bearer is required.
        let no_auth = app
            .clone()
            .oneshot(
                Request::put("/me/networks/corp")
                    .header("content-type", "application/json")
                    .body(Body::from(net_json.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_auth.status(), StatusCode::UNAUTHORIZED, "no bearer -> 401");

        // Alice stores her network, then reads it back.
        let put = app
            .clone()
            .oneshot(
                Request::put("/me/networks/corp")
                    .header("authorization", format!("Bearer {alice}"))
                    .header("content-type", "application/json")
                    .body(Body::from(net_json.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put.status(), StatusCode::OK, "owner stores the network");

        let get = app
            .clone()
            .oneshot(
                Request::get("/me/networks/corp")
                    .header("authorization", format!("Bearer {alice}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get.status(), StatusCode::OK);
        let body = to_bytes(get.into_body(), 1 << 16).await.unwrap();
        assert_eq!(serde_json::from_slice::<Network>(&body).unwrap(), net, "round-trips the network");

        // Owner isolation: mallory can't see alice's network.
        let cross = app
            .clone()
            .oneshot(
                Request::get("/me/networks/corp")
                    .header("authorization", format!("Bearer {mallory}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross.status(), StatusCode::NOT_FOUND, "another subject sees nothing");

        // The plan compiles the desired connectivity from the policy.
        let plan = app
            .clone()
            .oneshot(
                Request::get("/me/networks/corp/plan")
                    .header("authorization", format!("Bearer {alice}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(plan.status(), StatusCode::OK);
        let body = to_bytes(plan.into_body(), 1 << 16).await.unwrap();
        let resp: NetworkPlanResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.desired, vec![Pair::new("dev-1", "ops-1")], "dev<->ops is the one permitted channel");
    }

    #[tokio::test]
    async fn network_put_rejects_a_duplicate_agent_id_275() {
        // #275: a duplicate agent id must be a clear 400 at the REST boundary, never
        // silently stored and discovered later as a partitioned overlay plan.
        use axum::body::Body;
        use axum::http::Request;
        use ct_common::policy::{Agent, Network, Policy};
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        let secret = b"realm-secret";
        let issuer = "https://kc/realms/ct";
        let verifier = Arc::new(OidcVerifier::from_hs_secret(secret, issuer));
        let networks = Arc::new(SqliteNetworkStore::open_in_memory().unwrap());
        let app = authed_network_router(networks, OidcVerifierHandle::new(Some(verifier)));

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let claims = serde_json::json!({ "sub": "alice", "iss": issuer, "exp": now + 3600 });
        let alice = encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(secret)).unwrap();

        let dup_net = Network {
            agents: vec![
                Agent::new("worker", "dev", "internal"),
                Agent::new("worker", "dev", "internal"), // typo'd duplicate id
            ],
            policy: Policy::default(),
        };
        let resp = app
            .oneshot(
                Request::put("/me/networks/corp")
                    .header("authorization", format!("Bearer {alice}"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&dup_net).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "duplicate agent id -> 400, not silently stored");
    }

    #[tokio::test]
    async fn authed_topology_editor_composes_an_overlay_and_is_owner_scoped() {
        // #107-rest: create a topology, assign agents (exclusive), wire an edge, and
        // read the composite view — all subject-scoped.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        let secret = b"realm-secret";
        let issuer = "https://kc/realms/ct";
        let verifier = Arc::new(OidcVerifier::from_hs_secret(secret, issuer));
        let topologies = Arc::new(SqliteTopologyStore::open_in_memory().unwrap());
        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let app = authed_topology_router(
            topologies,
            OidcVerifierHandle::new(Some(verifier)),
            Arc::from(b"test-session-key".as_slice()),
            channels,
        );

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let jwt_for = |sub: &str| {
            let claims = serde_json::json!({ "sub": sub, "iss": issuer, "exp": now + 3600 });
            encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(secret)).unwrap()
        };
        let alice = jwt_for("alice");
        let mallory = jwt_for("mallory");
        let send = |method: &str, path: String, bearer: Option<&str>, body: String| {
            let mut req = Request::builder().method(method).uri(&path).header("content-type", "application/json");
            if let Some(b) = bearer {
                req = req.header("authorization", format!("Bearer {b}"));
            }
            app.clone().oneshot(req.body(Body::from(body)).unwrap())
        };

        // A bearer is required.
        assert_eq!(
            send("POST", "/me/topologies".into(), None, String::new()).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        // Alice creates a topology; the server returns a generated id + net_uuid.
        let created = send("POST", "/me/topologies".into(), Some(&alice), String::new()).await.unwrap();
        assert_eq!(created.status(), StatusCode::OK);
        let body = to_bytes(created.into_body(), 1 << 16).await.unwrap();
        let created: TopologyCreatedResp = serde_json::from_slice(&body).unwrap();
        let tid = created.id;

        // Assign two agents; the second assignment of the same agent is exclusive (409).
        for agent in ["agent-1", "agent-2"] {
            let s = send("POST", format!("/me/topologies/{tid}/agents"), Some(&alice), format!(r#"{{"agent":"{agent}"}}"#))
                .await.unwrap().status();
            assert_eq!(s, StatusCode::OK, "assign {agent}");
        }
        // agent-1 is already in this topology -> exclusivity conflict.
        let dup = send("POST", format!("/me/topologies/{tid}/agents"), Some(&alice), r#"{"agent":"agent-1"}"#.into())
            .await.unwrap().status();
        assert_eq!(dup, StatusCode::CONFLICT, "an agent belongs to at most one topology");

        // Wire an edge between them.
        let e = send("POST", format!("/me/topologies/{tid}/edges"), Some(&alice), r#"{"a":"agent-2","b":"agent-1"}"#.into())
            .await.unwrap().status();
        assert_eq!(e, StatusCode::OK, "edge wired");

        // The composite view reflects the agents + the canonical edge.
        let view = send("GET", format!("/me/topologies/{tid}"), Some(&alice), String::new()).await.unwrap();
        assert_eq!(view.status(), StatusCode::OK);
        let body = to_bytes(view.into_body(), 1 << 16).await.unwrap();
        let v: TopologyView = serde_json::from_slice(&body).unwrap();
        assert_eq!(v.agents, vec![("agent-1".to_string(), "peer".to_string()), ("agent-2".to_string(), "peer".to_string())]);
        assert_eq!(v.edges.len(), 1);
        assert_eq!(v.edges[0].a, "agent-1");
        assert_eq!(v.edges[0].b, "agent-2");
        assert_eq!(v.edges[0].channel, None);
        // #107-ui-mode: a fresh topology defaults to the direct overlay mode.
        assert_eq!(v.overlay_mode, "baseline", "default overlay mode is direct");

        // #107-ui-mode: the owner switches to a complex-adaptive mode; the view reflects it.
        let set = send("PUT", format!("/me/topologies/{tid}/mode"), Some(&alice), r#"{"mode":"smart-route"}"#.into())
            .await.unwrap().status();
        assert_eq!(set, StatusCode::OK, "owner sets overlay mode");
        let view = send("GET", format!("/me/topologies/{tid}"), Some(&alice), String::new()).await.unwrap();
        let body = to_bytes(view.into_body(), 1 << 16).await.unwrap();
        assert_eq!(serde_json::from_slice::<TopologyView>(&body).unwrap().overlay_mode, "smart-route");
        // An unknown mode token is rejected (400) — a topology only ever holds a known mode.
        assert_eq!(
            send("PUT", format!("/me/topologies/{tid}/mode"), Some(&alice), r#"{"mode":"telepathy"}"#.into())
                .await.unwrap().status(),
            StatusCode::BAD_REQUEST,
            "unknown overlay mode -> 400"
        );

        // #107-ui-suggest: in a complex-adaptive mode (smart-route, set above), the optimizer
        // returns the minimum-latency overlay over the topology's agents. With one candidate
        // link between the two members, the MST is exactly that link.
        let sug = send("POST", format!("/me/topologies/{tid}/suggest"), Some(&alice),
            r#"{"links":[{"a":"agent-1","b":"agent-2","cost":7}]}"#.into()).await.unwrap();
        assert_eq!(sug.status(), StatusCode::OK, "suggest in a complex mode");
        let body = to_bytes(sug.into_body(), 1 << 16).await.unwrap();
        let s: SuggestResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(s.mode, "smart-route");
        assert_eq!(s.links, vec![("agent-1".to_string(), "agent-2".to_string())]);
        assert_eq!((s.total_cost, s.connected), (7, true), "MST spans both members");
        // Size cap (#113): an over-budget shortcut request is refused before any O(n^3) work.
        assert_eq!(
            send("POST", format!("/me/topologies/{tid}/suggest"), Some(&alice), r#"{"links":[],"shortcut_budget":999}"#.into())
                .await.unwrap().status(),
            StatusCode::BAD_REQUEST,
            "over-cap shortcut_budget -> 400"
        );
        // Direct mode has no overlay to suggest -> 409.
        assert_eq!(
            send("PUT", format!("/me/topologies/{tid}/mode"), Some(&alice), r#"{"mode":"baseline"}"#.into())
                .await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            send("POST", format!("/me/topologies/{tid}/suggest"), Some(&alice), r#"{"links":[]}"#.into())
                .await.unwrap().status(),
            StatusCode::CONFLICT,
            "direct mode -> nothing to suggest (409)"
        );
        // Restore the complex mode so later assertions are unaffected.
        let _ = send("PUT", format!("/me/topologies/{tid}/mode"), Some(&alice), r#"{"mode":"smart-route"}"#.into()).await;

        // #107-ui-compose (edge removal): the DELETE leg is owner-scoped and canonical. A
        // non-owner can't remove alice's edge (404), the edge survives that rejected delete,
        // the owner removes it (order-independent — deleting b,a clears a,b), and deleting an
        // already-absent edge is a 404 (not a silent success).
        assert_eq!(
            send("DELETE", format!("/me/topologies/{tid}/edges"), Some(&mallory), r#"{"a":"agent-1","b":"agent-2"}"#.into())
                .await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "non-owner can't remove alice's edge"
        );
        let view = send("GET", format!("/me/topologies/{tid}"), Some(&alice), String::new()).await.unwrap();
        let body = to_bytes(view.into_body(), 1 << 16).await.unwrap();
        let survived = serde_json::from_slice::<TopologyView>(&body).unwrap().edges;
        assert_eq!(survived.len(), 1, "the edge survives a non-owner delete");
        assert_eq!(survived[0].a, "agent-1");
        assert_eq!(survived[0].b, "agent-2");
        assert_eq!(
            send("DELETE", format!("/me/topologies/{tid}/edges"), Some(&alice), r#"{"a":"agent-2","b":"agent-1"}"#.into())
                .await.unwrap().status(),
            StatusCode::OK,
            "owner removes the edge (order-independent)"
        );
        let view = send("GET", format!("/me/topologies/{tid}"), Some(&alice), String::new()).await.unwrap();
        let body = to_bytes(view.into_body(), 1 << 16).await.unwrap();
        assert!(serde_json::from_slice::<TopologyView>(&body).unwrap().edges.is_empty(), "the edge is gone");
        assert_eq!(
            send("DELETE", format!("/me/topologies/{tid}/edges"), Some(&alice), r#"{"a":"agent-1","b":"agent-2"}"#.into())
                .await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "removing an already-absent edge -> 404"
        );

        // #237: PUT /me/topologies/:id/operator — the operator-binding endpoint's REST surface.
        // Wraps the already-tested storage::TopologyStore::set_operator crypto primitive
        // (topology_operator_binding_bytes/verify_topology_operator_binding), which had no HTTP
        // route to reach it at all before this endpoint (#107-enforce ii-a, the drawn-edges
        // "authorize nothing" gap).
        {
            use ed25519_dalek::{Signer, SigningKey};
            let op = SigningKey::from_bytes(&[7u8; 32]);
            let op_pub = op.verifying_key().to_bytes();
            let genuine_proof = op.sign(&ct_common::channel::topology_operator_binding_bytes(&tid, &op_pub)).to_bytes();
            let body = |pk: &[u8; 32], sig: &[u8; 64]| {
                format!(r#"{{"operator_pubkey":"{}","proof":"{}"}}"#, hex_encode(pk), hex_encode(sig))
            };

            // Malformed hex -> 400, not a panic or a silent no-op.
            assert_eq!(
                send("PUT", format!("/me/topologies/{tid}/operator"), Some(&alice), r#"{"operator_pubkey":"nope","proof":"nope"}"#.into())
                    .await.unwrap().status(),
                StatusCode::BAD_REQUEST,
                "malformed hex -> 400"
            );

            // A forged proof (signed by an attacker key, not `op`) -> 404, indistinguishable
            // from a non-owner or a non-existent topology.
            let attacker = SigningKey::from_bytes(&[9u8; 32]);
            let forged = attacker.sign(&ct_common::channel::topology_operator_binding_bytes(&tid, &op_pub)).to_bytes();
            assert_eq!(
                send("PUT", format!("/me/topologies/{tid}/operator"), Some(&alice), body(&op_pub, &forged))
                    .await.unwrap().status(),
                StatusCode::NOT_FOUND,
                "forged proof-of-possession -> 404, not bound"
            );

            // A non-owner (mallory) can't bind alice's topology, even with a genuine proof.
            assert_eq!(
                send("PUT", format!("/me/topologies/{tid}/operator"), Some(&mallory), body(&op_pub, &genuine_proof))
                    .await.unwrap().status(),
                StatusCode::NOT_FOUND,
                "non-owner can't bind an operator key to alice's topology"
            );

            // The genuine owner, with a genuine proof, binds successfully.
            assert_eq!(
                send("PUT", format!("/me/topologies/{tid}/operator"), Some(&alice), body(&op_pub, &genuine_proof))
                    .await.unwrap().status(),
                StatusCode::OK,
                "owner binds with a genuine proof-of-possession"
            );

            // Idempotent: binding the same (topology, operator, proof) again still succeeds.
            assert_eq!(
                send("PUT", format!("/me/topologies/{tid}/operator"), Some(&alice), body(&op_pub, &genuine_proof))
                    .await.unwrap().status(),
                StatusCode::OK,
                "re-bind is idempotent"
            );
        }

        // Owner isolation: mallory can't see or edit alice's topology.
        assert_eq!(
            send("GET", format!("/me/topologies/{tid}"), Some(&mallory), String::new()).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            send("POST", format!("/me/topologies/{tid}/agents"), Some(&mallory), r#"{"agent":"x"}"#.into())
                .await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "mallory can't assign into alice's topology"
        );
        // #107-ui-mode: mallory can't retune alice's topology either (owner isolation -> 404).
        assert_eq!(
            send("PUT", format!("/me/topologies/{tid}/mode"), Some(&mallory), r#"{"mode":"baseline"}"#.into())
                .await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "mallory can't set alice's overlay mode"
        );
        // Mallory's own listing is empty.
        let list = send("GET", "/me/topologies".into(), Some(&mallory), String::new()).await.unwrap();
        let body = to_bytes(list.into_body(), 1 << 16).await.unwrap();
        assert_eq!(serde_json::from_slice::<Vec<TopologySummary>>(&body).unwrap().len(), 0);
    }

    #[tokio::test]
    async fn authed_topology_router_also_accepts_a_portal_session_cookie_with_no_bearer_token_237() {
        // #237-follow: the Topology Editor's own client-side JS (EDITOR_JS) authenticates via
        // the ambient portal session cookie a real browser carries -- it never has a bearer
        // token to attach. Before this fix, GET/POST/PUT to every one of these routes
        // required Authorization: Bearer, which a real portal session never sends, making the
        // editor fully unreachable/inert for an actual logged-in user. This proves the whole
        // create -> assign -> edge -> view -> editor -> mode flow works via ONLY a session
        // cookie, no bearer token anywhere in the request.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        let session_key = b"test-session-key".as_slice();
        let verifier = Arc::new(OidcVerifier::from_hs_secret(b"realm-secret", "https://kc/realms/ct"));
        let topologies = Arc::new(SqliteTopologyStore::open_in_memory().unwrap());
        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let app = authed_topology_router(
            topologies,
            OidcVerifierHandle::new(Some(verifier)),
            Arc::from(session_key),
            channels,
        );

        let alice_cookie = format!("ct_portal_session={}", crate::portal::sign_session_for_test(session_key, "alice"));
        let send = |method: &str, path: String, body: String| {
            app.clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(&path)
                        .header("content-type", "application/json")
                        .header("cookie", alice_cookie.clone())
                        .body(Body::from(body))
                        .unwrap(),
                )
        };

        // No cookie AND no bearer -> still refused (the fallback bearer path's own 401).
        let bare = app
            .clone()
            .oneshot(Request::post("/me/topologies").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(bare.status(), StatusCode::UNAUTHORIZED, "neither a session cookie nor a bearer token -> refused");

        let created = send("POST", "/me/topologies".into(), String::new()).await.unwrap();
        assert_eq!(created.status(), StatusCode::OK, "session-cookie-only create succeeds");
        let body = to_bytes(created.into_body(), 1 << 16).await.unwrap();
        let created: TopologyCreatedResp = serde_json::from_slice(&body).unwrap();
        let tid = created.id;

        assert_eq!(
            send("POST", format!("/me/topologies/{tid}/agents"), r#"{"agent":"agent-a"}"#.into()).await.unwrap().status(),
            StatusCode::OK,
            "session-cookie-only assign succeeds"
        );
        assert_eq!(
            send("POST", format!("/me/topologies/{tid}/agents"), r#"{"agent":"agent-b"}"#.into()).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            send("POST", format!("/me/topologies/{tid}/edges"), r#"{"a":"agent-a","b":"agent-b"}"#.into())
                .await
                .unwrap()
                .status(),
            StatusCode::OK,
            "session-cookie-only edge wiring succeeds"
        );

        let view = send("GET", format!("/me/topologies/{tid}"), String::new()).await.unwrap();
        assert_eq!(view.status(), StatusCode::OK);
        let body = to_bytes(view.into_body(), 1 << 16).await.unwrap();
        let view: TopologyView = serde_json::from_slice(&body).unwrap();
        assert_eq!(view.agents.len(), 2);
        assert_eq!(view.edges.len(), 1);

        // The actual editor PAGE itself -- what a real browser navigates to -- also renders
        // via the session cookie alone.
        let editor = send("GET", format!("/me/topologies/{tid}/editor"), String::new()).await.unwrap();
        assert_eq!(editor.status(), StatusCode::OK, "the editor page itself is reachable via the session cookie");
        let editor_body = to_bytes(editor.into_body(), 1 << 16).await.unwrap();
        assert!(
            String::from_utf8_lossy(&editor_body).contains("Topology Editor"),
            "renders the real editor page, not an error"
        );
    }

    #[tokio::test]
    async fn topology_sharing_lets_a_collaborator_view_and_wire_their_own_agents_but_not_govern_107_complex() {
        // #107-complex: a topology defaults to owner-only (no share rows at all). Sharing is
        // strictly additive: the shared subject can VIEW and wire in THEIR OWN agents/edges
        // (the collaborative use case topology.rs's own original module doc anticipated --
        // "their own, or ones shared to them") but never owner-only governance (delete,
        // operator-bind, managing the share list itself).
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        let session_key = b"test-session-key".as_slice();
        let verifier = Arc::new(OidcVerifier::from_hs_secret(b"realm-secret", "https://kc/realms/ct"));
        let topologies = Arc::new(SqliteTopologyStore::open_in_memory().unwrap());
        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let app = authed_topology_router(
            topologies,
            OidcVerifierHandle::new(Some(verifier)),
            Arc::from(session_key),
            channels,
        );
        let alice_cookie = format!("ct_portal_session={}", crate::portal::sign_session_with_email_for_test(session_key, "alice", "alice@example.test"));
        let bob_cookie = format!("ct_portal_session={}", crate::portal::sign_session_with_email_for_test(session_key, "bob", "bob@example.test"));
        let stranger_cookie = format!("ct_portal_session={}", crate::portal::sign_session_with_email_for_test(session_key, "stranger", "stranger@example.test"));
        let send = |method: &str, path: String, cookie: &str, body: String| {
            app.clone().oneshot(
                Request::builder()
                    .method(method)
                    .uri(&path)
                    .header("content-type", "application/json")
                    .header("cookie", cookie)
                    .body(Body::from(body))
                    .unwrap(),
            )
        };

        let created = send("POST", "/me/topologies".into(), &alice_cookie, String::new()).await.unwrap();
        let body = to_bytes(created.into_body(), 1 << 16).await.unwrap();
        let tid = serde_json::from_slice::<TopologyCreatedResp>(&body).unwrap().id;

        // Before sharing: bob can't even see it.
        assert_eq!(
            send("GET", format!("/me/topologies/{tid}"), &bob_cookie, String::new()).await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "not shared yet -> invisible to bob, indistinguishable from nonexistent"
        );
        // And bob can't share it with himself (owner-only governance).
        assert_eq!(
            send("POST", format!("/me/topologies/{tid}/share"), &bob_cookie, r#"{"email":"bob@example.test"}"#.into())
                .await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "only the owner may manage the share list"
        );

        // Alice shares with bob's email.
        assert_eq!(
            send("POST", format!("/me/topologies/{tid}/share"), &alice_cookie, r#"{"email":"bob@example.test"}"#.into())
                .await.unwrap().status(),
            StatusCode::OK
        );

        // Now bob can view it...
        assert_eq!(
            send("GET", format!("/me/topologies/{tid}"), &bob_cookie, String::new()).await.unwrap().status(),
            StatusCode::OK,
            "shared -> visible to bob"
        );
        // ...and it shows up in bob's "shared with me" listing, by email -- not a stranger's.
        let shared_resp = send("GET", "/me/topologies/shared".into(), &bob_cookie, String::new()).await.unwrap();
        let shared_body = to_bytes(shared_resp.into_body(), 1 << 16).await.unwrap();
        let shared: Vec<TopologySummary> = serde_json::from_slice(&shared_body).unwrap();
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].id, tid);
        let stranger_shared = send("GET", "/me/topologies/shared".into(), &stranger_cookie, String::new()).await.unwrap();
        let stranger_body = to_bytes(stranger_shared.into_body(), 1 << 16).await.unwrap();
        assert!(serde_json::from_slice::<Vec<TopologySummary>>(&stranger_body).unwrap().is_empty(), "a stranger has nothing shared");

        // Bob wires in HIS OWN agent, marked as a super-peer.
        assert_eq!(
            send(
                "POST",
                format!("/me/topologies/{tid}/agents"),
                &bob_cookie,
                r#"{"agent":"bob-relay","kind":"super-peer"}"#.into()
            )
            .await.unwrap().status(),
            StatusCode::OK,
            "bob may assign his OWN agent into alice's shared topology"
        );
        // Bob cannot wire in an agent he doesn't own (alice's, first-touched by her below).
        send("POST", format!("/me/topologies/{tid}/agents"), &alice_cookie, r#"{"agent":"alice-peer"}"#.into())
            .await
            .unwrap();
        assert_eq!(
            send("POST", format!("/me/topologies/{tid}/agents"), &bob_cookie, r#"{"agent":"alice-peer"}"#.into())
                .await.unwrap().status(),
            StatusCode::FORBIDDEN,
            "bob still can't touch an agent alice already owns -- collaboration widens WHO can edit the topology, never agent ownership"
        );

        // Bob wires an edge between the two (topology-edit access, not agent ownership, gates this).
        assert_eq!(
            send("POST", format!("/me/topologies/{tid}/edges"), &bob_cookie, r#"{"a":"bob-relay","b":"alice-peer"}"#.into())
                .await.unwrap().status(),
            StatusCode::OK,
            "bob may wire an edge in a topology shared with him"
        );

        // The view shows bob-relay as a super-peer.
        let view = send("GET", format!("/me/topologies/{tid}"), &alice_cookie, String::new()).await.unwrap();
        let body = to_bytes(view.into_body(), 1 << 16).await.unwrap();
        let v: TopologyView = serde_json::from_slice(&body).unwrap();
        assert!(v.agents.contains(&("bob-relay".to_string(), "super-peer".to_string())), "bob-relay recorded as a super-peer");
        assert!(v.agents.contains(&("alice-peer".to_string(), "peer".to_string())), "alice-peer stays a plain peer");

        // Bob still can't govern: no operator-bind, can't delete the share list.
        assert_eq!(
            send("PUT", format!("/me/topologies/{tid}/mode"), &bob_cookie, r#"{"mode":"smart-route"}"#.into())
                .await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "a collaborator can't retune the topology's overlay mode either (owner-only governance)"
        );
        assert_eq!(
            send("POST", format!("/me/topologies/{tid}/share/{}/remove", "bob@example.test"), &bob_cookie, String::new())
                .await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "a collaborator can't manage the share list, not even to remove their own access"
        );

        // Alice de-lists bob; he loses access immediately.
        assert_eq!(
            send("POST", format!("/me/topologies/{tid}/share/{}/remove", "bob@example.test"), &alice_cookie, String::new())
                .await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            send("GET", format!("/me/topologies/{tid}"), &bob_cookie, String::new()).await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "de-listed -> access revoked"
        );
    }

    #[tokio::test]
    async fn topology_edge_channel_association_requires_a_real_owned_or_member_channel_107_complex() {
        // #107-complex link info: attaching a channel to an edge must be a real channel the
        // caller owns or is a member of ("account related channels or shared to account
        // channels") -- never an arbitrary id with no relationship to the caller. Clearing
        // (channel: null) always works once attached.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use ct_common::channel::ChannelId;
        use tower::ServiceExt;

        let session_key = b"test-session-key".as_slice();
        let verifier = Arc::new(OidcVerifier::from_hs_secret(b"realm-secret", "https://kc/realms/ct"));
        let topologies = Arc::new(SqliteTopologyStore::open_in_memory().unwrap());
        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());

        // A real channel alice owns.
        let owned = ChannelId([0xa1u8; 32]);
        assert!(channels.register_channel(&owned, &[0x11u8; 32], "alice").unwrap());
        // A real channel someone else owns, but alice's e-mail is allow-listed on
        // (invited, #248-follow's channel_allowlist -- the actual account-level
        // relationship this codebase tracks; channel *membership* is keyed by a
        // holder ed25519 pubkey, not by a portal session's subject string, so there
        // is no separate "is this subject a member" concept to test here).
        let member_of = ChannelId([0xb2u8; 32]);
        assert!(channels.register_channel(&member_of, &[0x22u8; 32], "carol").unwrap());
        assert!(channels.allowlist_add(&member_of, "carol", "alice@example.test", 1_000).unwrap());
        // A real channel alice has no relationship to at all.
        let unrelated = ChannelId([0xc3u8; 32]);
        assert!(channels.register_channel(&unrelated, &[0x44u8; 32], "carol").unwrap());

        let app = authed_topology_router(
            topologies,
            OidcVerifierHandle::new(Some(verifier)),
            Arc::from(session_key),
            channels,
        );
        let alice_cookie = format!(
            "ct_portal_session={}",
            crate::portal::sign_session_with_email_for_test(session_key, "alice", "alice@example.test")
        );
        let send = |method: &str, path: String, body: String| {
            app.clone().oneshot(
                Request::builder()
                    .method(method)
                    .uri(&path)
                    .header("content-type", "application/json")
                    .header("cookie", alice_cookie.clone())
                    .body(Body::from(body))
                    .unwrap(),
            )
        };

        let created = send("POST", "/me/topologies".into(), String::new()).await.unwrap();
        let body = to_bytes(created.into_body(), 1 << 16).await.unwrap();
        let tid = serde_json::from_slice::<TopologyCreatedResp>(&body).unwrap().id;
        send("POST", format!("/me/topologies/{tid}/agents"), r#"{"agent":"a"}"#.into()).await.unwrap();
        send("POST", format!("/me/topologies/{tid}/agents"), r#"{"agent":"b"}"#.into()).await.unwrap();
        send("POST", format!("/me/topologies/{tid}/edges"), r#"{"a":"a","b":"b"}"#.into()).await.unwrap();

        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();

        // An unrelated channel is refused.
        assert_eq!(
            send(
                "PUT",
                format!("/me/topologies/{tid}/edges/channel"),
                format!(r#"{{"a":"a","b":"b","channel":"{}"}}"#, hex(&unrelated.0))
            )
            .await.unwrap().status(),
            StatusCode::FORBIDDEN,
            "not owned or a member of -> refused"
        );

        // A channel alice OWNS is accepted.
        assert_eq!(
            send(
                "PUT",
                format!("/me/topologies/{tid}/edges/channel"),
                format!(r#"{{"a":"a","b":"b","channel":"{}"}}"#, hex(&owned.0))
            )
            .await.unwrap().status(),
            StatusCode::OK
        );
        let view = send("GET", format!("/me/topologies/{tid}"), String::new()).await.unwrap();
        let body = to_bytes(view.into_body(), 1 << 16).await.unwrap();
        let v: TopologyView = serde_json::from_slice(&body).unwrap();
        assert_eq!(v.edges[0].channel.as_deref(), Some(hex(&owned.0).as_str()));

        // A channel alice is only a MEMBER of (not the owner) is also accepted.
        assert_eq!(
            send(
                "PUT",
                format!("/me/topologies/{tid}/edges/channel"),
                format!(r#"{{"a":"a","b":"b","channel":"{}"}}"#, hex(&member_of.0))
            )
            .await.unwrap().status(),
            StatusCode::OK,
            "a channel the caller's e-mail is allow-listed (not owner) on is also \"account related\""
        );

        // Clearing works.
        assert_eq!(
            send("PUT", format!("/me/topologies/{tid}/edges/channel"), r#"{"a":"a","b":"b","channel":null}"#.into())
                .await.unwrap().status(),
            StatusCode::OK
        );
        let view = send("GET", format!("/me/topologies/{tid}"), String::new()).await.unwrap();
        let body = to_bytes(view.into_body(), 1 << 16).await.unwrap();
        let v: TopologyView = serde_json::from_slice(&body).unwrap();
        assert_eq!(v.edges[0].channel, None, "cleared");
    }

    #[test]
    fn topology_svg_diagram_has_a_node_per_agent_and_a_line_per_edge() {
        // #107 "live diagram": the status page renders an inline SVG node-graph.
        let agents = vec!["agent-1".to_string(), "agent-2".to_string(), "agent-3".to_string()];
        let edges = vec![
            ("agent-1".to_string(), "agent-2".to_string()),
            ("agent-2".to_string(), "agent-3".to_string()),
        ];
        let svg = render_topology_svg(&agents, &edges);
        assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"), "self-contained inline SVG");
        assert_eq!(svg.matches("<circle").count(), 3, "one node per agent");
        assert_eq!(svg.matches("<line").count(), 2, "one line per edge");
        for a in &agents {
            assert!(svg.contains(&format!(">{a}</text>")), "labels {a}");
        }
        // An edge to an unknown agent is skipped (no dangling line), never a panic.
        let dangling = render_topology_svg(&agents, &[("agent-1".into(), "ghost".into())]);
        assert_eq!(dangling.matches("<line").count(), 0, "an edge to a non-member is dropped");
        // Empty topology -> a valid empty canvas, no panic.
        assert!(render_topology_svg(&[], &[]).contains("no agents yet"));
    }

    #[test]
    fn topology_editor_page_is_a_self_contained_draggable_node_graph() {
        // #107-ui: the editor renders a full, self-contained (CSP-safe) HTML page — a
        // draggable SVG node-graph of an ARBITRARY (complex) topology, one node per agent
        // and one bezier edge per link, with agent ids escaped and no external assets.
        let t = crate::topology::Topology {
            id: "t1".into(),
            owner: "alice".into(),
            net_uuid: "uuid-xyz".into(),
        };
        let agents = vec![
            ("agent-1".to_string(), "peer".to_string()),
            ("agent-2".to_string(), "peer".to_string()),
            ("agent-3".to_string(), "peer".to_string()),
        ];
        // A complex (non-direct) wiring: a triangle among three agents.
        let edges = vec![
            ("agent-1".to_string(), "agent-2".to_string(), None),
            ("agent-2".to_string(), "agent-3".to_string(), None),
            ("agent-1".to_string(), "agent-3".to_string(), None),
        ];
        let html = render_topology_editor(&t, &agents, &edges, "smart-route", true, &[]);

        // A complete, self-contained HTML document.
        assert!(html.starts_with("<!doctype html>") && html.contains("</html>"), "full HTML doc");
        assert!(html.contains("<style>") && html.contains("<script>"), "inline CSS + JS");
        // Self-contained / CSP-safe: NO external assets of any kind.
        for external in ["http://", "https://", "<link", "src=\"", "@import"] {
            assert!(!html.contains(external), "no external asset: {external:?}");
        }
        // The full (complex) graph is preserved: one draggable node per agent, one edge per link.
        assert_eq!(html.matches("class=\"node\"").count(), 3, "one node per agent");
        assert_eq!(html.matches("class=\"edge\"").count(), 3, "one bezier edge per link");
        assert!(html.contains("data-node=\"agent-2\"") && html.contains("data-cx="), "draggable node geometry");
        assert!(html.contains("net:uuid-xyz"), "shows the net-uuid");
        // #107-ui-mode/-suggest controls: the overlay-mode toggle (current pre-selected), the
        // suggest button, and the topology id for the REST fetches.
        assert!(html.contains("<select id=\"mode\">"), "overlay-mode toggle present");
        assert!(html.contains("value=\"baseline\">Direct") && html.contains("value=\"smart-route\" selected"), "current mode pre-selected");
        assert!(html.contains("id=\"suggest\""), "suggest button present");
        assert!(html.contains("data-tid=\"t1\""), "topology id embedded for the REST fetches");
        assert!(html.contains("/mode") && html.contains("/suggest"), "wired to the owner endpoints");

        // Agent ids are HTML-escaped (XSS-safe): a hostile id never emits raw markup.
        let evil = vec![("<script>alert(1)</script>".to_string(), "peer".to_string())];
        let evil_html = render_topology_editor(&t, &evil, &[], "baseline", true, &[]);
        assert!(!evil_html.contains("<script>alert(1)"), "hostile agent id is escaped");
        assert!(evil_html.contains("&lt;script&gt;alert(1)"), "escaped form is present");

        // An empty topology still yields a valid page with an empty-state hint (no panic).
        let empty = render_topology_editor(&t, &[], &[], "baseline", true, &[]);
        assert!(empty.starts_with("<!doctype html>") && empty.contains("no agents yet"), "empty-state");
    }

    #[test]
    fn topology_editor_has_an_easy_flexible_toggle_and_a_commands_panel_ux_overhaul() {
        // UX overhaul: "as easy as hell, then as flexible as hell" -- a client-side
        // presentation toggle (same underlying graph/API either way) plus a
        // generated-one-liners panel for what's actually on the canvas. Still fully
        // self-contained/CSP-safe (covered by the sibling test above); this pins the
        // new elements exist and stay wired to the same real endpoints.
        let t = crate::topology::Topology {
            id: "t1".into(),
            owner: "alice".into(),
            net_uuid: "uuid-xyz".into(),
        };
        let agents = vec![("agent-1".to_string(), "peer".to_string()), ("agent-2".to_string(), "super-peer".to_string())];
        let edges = vec![("agent-1".to_string(), "agent-2".to_string(), None)];
        let html = render_topology_editor(&t, &agents, &edges, "baseline", true, &[]);

        assert!(html.contains("id=\"modeeasy\"") && html.contains("id=\"modeflex\""), "easy/flexible toggle present");
        assert!(html.contains("id=\"cmdstoggle\"") && html.contains("id=\"cmds\""), "commands panel present");
        assert!(html.contains("class=\"flex-only\""), "advanced-only controls (overlay mode, suggest) are marked for the easy-mode CSS to hide");
        assert!(html.contains("ct-agent channel init"), "the identity one-liner is embedded in the client-side renderer");
        assert!(html.contains("CT_CHANNEL_SUPER_PEER_UPSTREAM") && html.contains("CT_CHANNEL_SUPER_PEER_LISTEN"), "the super-peer one-liner template is embedded");
        assert!(html.contains("CT_CHANNEL_BRIDGE_HOLDER") && html.contains("member-material"), "the connect one-liner template is embedded");
        // Still fully self-contained -- the new panel's guidance text names the docs
        // site but never links out (CSP-safe stays CSP-safe).
        for external in ["http://", "https://", "<link", "src=\"", "@import"] {
            assert!(!html.contains(external), "commands panel stays CSP-safe: no {external:?}");
        }
    }

    #[test]
    fn topology_editor_supports_click_to_connect_compose() {
        // #107-ui-compose: the editor lets the owner GRAPHICALLY compose the overlay — a
        // "Connect" tool that, when armed, turns clicking two agents into a new link POSTed to
        // the existing owner `…/edges` endpoint (the edge then appears live). Still fully
        // self-contained / CSP-safe — the compose JS adds no external assets and (critically)
        // creates the live edge via `insertAdjacentHTML` in SVG context, NOT `createElementNS`
        // with an `http://…/svg` namespace literal that would break the CSP-safe invariant.
        let t = crate::topology::Topology {
            id: "t1".into(),
            owner: "alice".into(),
            net_uuid: "uuid-xyz".into(),
        };
        let agents = vec![("agent-1".to_string(), "peer".to_string()), ("agent-2".to_string(), "peer".to_string())];
        let html = render_topology_editor(&t, &agents, &[], "baseline", true, &[]);

        // The Connect tool is present and starts un-armed (a11y state exposed).
        assert!(html.contains("id=\"link\"") && html.contains("aria-pressed=\"false\""), "Connect tool present, un-armed");
        // The compose behaviour: a link mode that turns clicks into an edge POST to `…/edges`.
        assert!(html.contains("data-linkmode"), "link-mode gate wired");
        assert!(html.contains("function linkPick"), "click-to-connect handler present");
        assert!(html.contains("/edges") && html.contains("method:'POST'"), "POSTs new links to the owner edges endpoint");
        assert!(html.contains("insertAdjacentHTML"), "live edge created without a namespace literal");
        // ...and the inverse gesture: clicking an existing link (while armed) removes it via DELETE.
        assert!(html.contains("function removeEdge"), "edge-remove handler present");
        assert!(html.contains("method:'DELETE'"), "removal DELETEs the owner edges endpoint");
        // ...and add-agent: an input + button that assign an existing agent into the topology.
        assert!(html.contains("id=\"agent\"") && html.contains("id=\"addagent\""), "add-agent control present");
        assert!(html.contains("/agents"), "add-agent POSTs the owner agents endpoint");
        // Still zero external assets — the compose JS must not smuggle any in (the SVG
        // namespace URL in particular must be absent).
        for external in ["http://", "https://", "<link", "src=\"", "@import"] {
            assert!(!html.contains(external), "compose editor stays CSP-safe: no {external:?}");
        }
    }

    #[tokio::test]
    async fn topology_status_page_is_public_and_resolves_by_net_uuid() {
        // #107-subdomain: the live-status page is addressed by net-uuid, no auth, and
        // renders the overlay's agents + links; an unknown uuid is 404.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        let topologies = Arc::new(SqliteTopologyStore::open_in_memory().unwrap());
        topologies.create_topology("alice", "t1", "uuid-live").unwrap();
        topologies.assign("alice", "agent-1", "t1").unwrap();
        topologies.assign("alice", "agent-2", "t1").unwrap();
        topologies.add_edge("alice", "t1", "agent-1", "agent-2").unwrap();
        let app = topology_status_router(topologies);

        // Known net-uuid -> 200 HTML showing the agents + the link (no bearer needed).
        let resp = app
            .clone()
            .oneshot(Request::get("/net/uuid-live").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "public UUID access");
        let ct = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
        assert!(ct.contains("text/html"), "html content-type: {ct}");
        let body = to_bytes(resp.into_body(), 1 << 16).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("uuid-live"), "shows the net-uuid");
        assert!(html.contains("agent-1") && html.contains("agent-2"), "lists the member agents");
        assert!(html.contains("agent-1</code> &mdash; <code>agent-2"), "renders the link");

        // Unknown net-uuid -> 404.
        let miss = app
            .oneshot(Request::get("/net/nope").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(miss.status(), StatusCode::NOT_FOUND, "unknown uuid -> 404");
    }

    #[tokio::test]
    async fn agent_directory_rest_registers_with_admin_token_and_searches_publicly() {
        // #161/#87 SEC87b-auth: POST self-register is a machine-to-machine write gated by the
        // shared `CT_CP_EDGE_ADMIN_TOKEN` (the same gate as `/enroll/issue`, `/registry/register`,
        // `/bootstrap/mint`) — NOT a human OIDC bearer, which an autonomous agent cannot obtain
        // (the `ct-portal` client disables direct-access + service-accounts). GET search stays
        // public. A registered agent is discoverable by its advertised role; the response carries
        // the card URL a peer fetches + verifies (the holder signature is the real trust anchor).
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        let admin = [0x5au8; 32];
        let dir = Arc::new(SqliteAgentDirectory::open_in_memory().unwrap());
        let app = agent_directory_router(dir, Some(admin));

        // POST without the admin token -> 401.
        let unauth = app
            .clone()
            .oneshot(
                Request::post("/registry/agents")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"holder_pubkey":"aa","card_url":"https://x/.well-known/agent-card.json","role_tags":["source"]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED, "self-register needs the admin token (#161)");

        // POST with a wrong admin token -> 401.
        let wrong = app
            .clone()
            .oneshot(
                Request::post("/registry/agents")
                    .header("x-ct-admin-token", hex_encode(&[0u8; 32]))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"holder_pubkey":"aa","card_url":"https://x/.well-known/agent-card.json","role_tags":["source"]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED, "wrong admin token -> 401");

        // POST with the correct admin token -> 200.
        let reg = app
            .clone()
            .oneshot(
                Request::post("/registry/agents")
                    .header("x-ct-admin-token", hex_encode(&admin))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"holder_pubkey":"aa","card_url":"https://source-1/.well-known/agent-card.json","role_tags":["source"],"skill_ids":["transfer"]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reg.status(), StatusCode::OK, "admin-token self-register succeeds");

        // GET is public: search by role returns the registered agent + its card URL.
        let hit = app
            .clone()
            .oneshot(Request::get("/registry/agents?role=source").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(hit.status(), StatusCode::OK, "search is public (no token)");
        let body = to_bytes(hit.into_body(), 1 << 16).await.unwrap();
        let hits: Vec<AgentDirectoryEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].holder_pubkey, "aa");
        assert_eq!(hits[0].card_url, "https://source-1/.well-known/agent-card.json");

        // No match -> empty list.
        let miss = app
            .clone()
            .oneshot(Request::get("/registry/agents?role=nobody").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = to_bytes(miss.into_body(), 1 << 16).await.unwrap();
        assert!(serde_json::from_slice::<Vec<AgentDirectoryEntry>>(&body).unwrap().is_empty());

        // SSRF defence-in-depth: a non-https card_url is rejected 400 (source's finding).
        let non_https = app
            .clone()
            .oneshot(
                Request::post("/registry/agents")
                    .header("x-ct-admin-token", hex_encode(&admin))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"holder_pubkey":"bb","card_url":"http://169.254.169.254/latest/meta-data","role_tags":["x"]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(non_https.status(), StatusCode::BAD_REQUEST, "non-https card_url rejected");

        // Token-injection: a newline in a facet is rejected 400, not silently smuggled in.
        let injected = app
            .oneshot(
                Request::post("/registry/agents")
                    .header("x-ct-admin-token", hex_encode(&admin))
                    .header("content-type", "application/json")
                    .body(Body::from("{\"holder_pubkey\":\"cc\",\"card_url\":\"https://x/.well-known/agent-card.json\",\"role_tags\":[\"source\\nadmin\"]}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(injected.status(), StatusCode::BAD_REQUEST, "newline-injected facet token rejected");
    }

    #[tokio::test]
    async fn pipeline_registry_rest_publishes_admin_gated_and_discovers_publicly() {
        // #174 B (frozen): POST /registry/pipelines is machine-writer admin-gated (like #161's
        // agent directory); GET list + GET :id are public discovery; unknown id → 404.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;
        let admin = [0x6au8; 32];
        let reg = Arc::new(SqlitePipelineRegistry::open_in_memory().unwrap());
        let app = pipeline_registry_router(reg, Some(admin));
        let body = r#"{"owner":"alice","spec":{"id":"flappy","roles":[{"service":"TextGeneration","units":1,"tag":"physics"}]}}"#;
        let publish = |tok: Option<String>| {
            let mut req = Request::post("/registry/pipelines").header("content-type", "application/json");
            if let Some(t) = tok {
                req = req.header("x-ct-admin-token", t);
            }
            app.clone().oneshot(req.body(Body::from(body)).unwrap())
        };
        assert_eq!(publish(None).await.unwrap().status(), StatusCode::UNAUTHORIZED, "no admin token → 401");
        assert_eq!(
            publish(Some(hex_encode(&[0u8; 32]))).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "wrong admin token → 401"
        );
        assert_eq!(publish(Some(hex_encode(&admin))).await.unwrap().status(), StatusCode::OK, "admin token publishes");

        // Public list shows the published id.
        let list = app.clone().oneshot(Request::get("/registry/pipelines").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(list.status(), StatusCode::OK, "list is public");
        let lb = to_bytes(list.into_body(), 1 << 16).await.unwrap();
        assert!(String::from_utf8_lossy(&lb).contains("\"flappy\""), "the published pipeline is discoverable");

        // Public fetch by id returns the full spec.
        let get = app.clone().oneshot(Request::get("/registry/pipelines/flappy").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(get.status(), StatusCode::OK, "get is public");
        let gb = to_bytes(get.into_body(), 1 << 16).await.unwrap();
        assert!(String::from_utf8_lossy(&gb).contains("\"physics\""), "the full spec is fetchable: {}", String::from_utf8_lossy(&gb));

        // Unknown id → 404.
        let miss = app.oneshot(Request::get("/registry/pipelines/nope").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(miss.status(), StatusCode::NOT_FOUND, "unknown pipeline → 404");
    }

    #[tokio::test]
    async fn me_pipelines_publishes_self_service_owned_by_the_bearer_subject() {
        // An ordinary onboarded pipeline designer only ever holds a join token + agent
        // token, never the admin token (#218/agent-onboarding.md §A) — so the admin-gated
        // `/registry/pipelines` was never actually reachable by them. `/me/pipelines`
        // closes that gap the same way `/me/channels` did: owner = the verified subject.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use tower::ServiceExt;

        let secret = b"realm-secret";
        let issuer = "https://kc/realms/ct";
        let reg = Arc::new(SqlitePipelineRegistry::open_in_memory().unwrap());
        let verifier = Arc::new(OidcVerifier::from_hs_secret(secret, issuer));
        let app = authed_pipeline_router(reg.clone(), OidcVerifierHandle::new(Some(verifier)));

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let jwt_for = |sub: &str| {
            let claims = serde_json::json!({ "sub": sub, "iss": issuer, "exp": now + 3600 });
            encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(secret)).unwrap()
        };
        let alice = jwt_for("alice");
        let mallory = jwt_for("mallory");
        let body = r#"{"spec":{"id":"flappy","roles":[{"service":"TextGeneration","units":1,"tag":"physics"}]}}"#;
        let publish = |bearer: Option<String>| {
            let mut req = Request::post("/me/pipelines").header("content-type", "application/json");
            if let Some(b) = &bearer {
                req = req.header("authorization", format!("Bearer {b}"));
            }
            app.clone().oneshot(req.body(Body::from(body)).unwrap())
        };

        assert_eq!(publish(None).await.unwrap().status(), StatusCode::UNAUTHORIZED, "no bearer token → 401");
        assert_eq!(publish(Some(alice.clone())).await.unwrap().status(), StatusCode::OK, "alice publishes her own spec");
        assert_eq!(
            reg.get("flappy").unwrap().expect("published").id,
            "flappy",
            "the spec is actually persisted"
        );
        assert_eq!(
            publish(Some(mallory)).await.unwrap().status(),
            StatusCode::FORBIDDEN,
            "a different subject can't re-publish alice's id"
        );
        // Re-publishing under the SAME subject (an update) still succeeds.
        let ok_republish = publish(Some(alice)).await.unwrap();
        assert_eq!(ok_republish.status(), StatusCode::OK, "the owning subject can republish/update");

        // Discoverable via the existing public GET (same registry, shared with #174 B's router).
        let list = pipeline_registry_router(reg, None)
            .oneshot(Request::get("/registry/pipelines").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let lb = to_bytes(list.into_body(), 1 << 16).await.unwrap();
        assert!(String::from_utf8_lossy(&lb).contains("\"flappy\""), "self-published pipeline is publicly discoverable");
    }

    #[tokio::test]
    async fn authorize_host_proxy_is_admin_gated_and_forwards_to_the_edge() {
        // #214: a remote pipeline maintainer holding just the admin token can self-serve
        // host authorization over the public control plane, without operator/GitHub relay.
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let admin = [0x7au8; 32];
        let edge_admin_token = "edge-secret";

        // Mock edge admin API: records the exact path it was hit on.
        let hit = Arc::new(std::sync::Mutex::new(None::<String>));
        let hit2 = hit.clone();
        let mock_edge = Router::new().route(
            "/admin/authorize-host/:token/:host",
            post(move |axum::extract::Path((token, host)): axum::extract::Path<(String, String)>, headers: HeaderMap| {
                let hit = hit2.clone();
                async move {
                    if headers.get("x-ct-admin-token").and_then(|v| v.to_str().ok()) != Some(edge_admin_token) {
                        return StatusCode::UNAUTHORIZED;
                    }
                    *hit.lock().unwrap() = Some(format!("{token}/{host}"));
                    StatusCode::OK
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, mock_edge).await.unwrap() });

        let mesh_store = Arc::new(crate::edge_mesh::SqliteEdgeMesh::open_in_memory().unwrap());
        // lookup_by_token joins against mesh_edges, so "primary" must have heartbeated at
        // least once to be resolvable (mirrors the real deployment's boot-time self-heartbeat).
        // #285: the heartbeat must also be recent (within OWNERSHIP_LIVENESS_SECS), not just present.
        mesh_store.heartbeat("primary", "test", None, now_secs() as i64).unwrap();
        let edge_mesh = crate::edge_mesh::EdgeMeshHandle::new(mesh_store.clone(), Arc::from("primary"));
        let app = edge_authorize_host_router(format!("http://{addr}"), edge_admin_token.to_string(), Some(admin), edge_mesh);
        let call = |tok: Option<String>| {
            let mut req = Request::post("/registry/authorize-host/deadbeef/flappy-demo.bunsenbrenner.org");
            if let Some(t) = tok {
                req = req.header("x-ct-admin-token", t);
            }
            app.clone().oneshot(req.body(Body::empty()).unwrap())
        };

        assert_eq!(call(None).await.unwrap().status(), StatusCode::UNAUTHORIZED, "no admin token → 401");
        assert_eq!(
            call(Some(hex_encode(&[0u8; 32]))).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "wrong admin token → 401"
        );
        assert_eq!(call(Some(hex_encode(&admin))).await.unwrap().status(), StatusCode::OK, "admin token authorizes");
        assert_eq!(
            hit.lock().unwrap().as_deref(),
            Some("deadbeef/flappy-demo.bunsenbrenner.org"),
            "forwarded to the edge with the exact token/host and its admin header"
        );
        // edge_mesh Phase 0: a successful proxy call records the local edge's ownership.
        assert_eq!(
            mesh_store.lookup_by_token("deadbeef").unwrap().map(|(id, _)| id),
            Some("primary".to_string()),
            "ownership recorded after a successful authorize-host proxy call"
        );
    }

    #[tokio::test]
    async fn authed_issue_is_rate_limited_per_subject() {
        use axum::body::Body;
        use axum::http::Request;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        let secret = b"realm-secret";
        let issuer = "https://kc/realms/ct";
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let verifier = Arc::new(OidcVerifier::from_hs_secret(secret, issuer));

        // Fund user-1 so issuance at the token price succeeds and only the rate
        // limit — not credit or the #87 price floor — decides the outcome.
        let acct = ledger.account_for_subject("user-1").unwrap();
        ledger.credit(&acct, 2).unwrap();
        // Cap issuance at 2 per window for each subject.
        let app = authed_billing_router(ledger, OidcVerifierHandle::new(Some(verifier)), 2);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({ "sub": "user-1", "iss": issuer, "exp": now + 3600 });
        let jwt = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        // price 1 (the token price) with a funded account — issuance succeeds until
        // the rate limit bites, which is what this test isolates.
        let issue = || {
            app.clone().oneshot(
                Request::post("/me/issue")
                    .header("authorization", format!("Bearer {jwt}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"price":1}"#))
                    .unwrap(),
            )
        };

        // All three requests land in the same wall-clock window.
        assert_eq!(issue().await.unwrap().status(), StatusCode::OK, "1st allowed");
        assert_eq!(issue().await.unwrap().status(), StatusCode::OK, "2nd allowed");
        assert_eq!(
            issue().await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS,
            "3rd over the per-subject cap is throttled"
        );
    }

    #[tokio::test]
    async fn issuance_rejects_price_below_the_token_price() {
        // #87 SEC87a: /me/issue took a client-supplied `price`, and price:0 minted a
        // routing token for free (debiting nothing). A funded, in-rate subject must
        // still not be able to buy a token below TOKEN_PRICE, and a refusal must not
        // touch the ledger.
        use axum::body::Body;
        use axum::http::Request;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        let secret = b"realm-secret";
        let issuer = "https://kc/realms/ct";
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let verifier = Arc::new(OidcVerifier::from_hs_secret(secret, issuer));

        // Fund the subject so any refusal is the price floor, not insufficient credit,
        // and set a high rate cap so the limiter never interferes.
        let acct = ledger.account_for_subject("payer").unwrap();
        ledger.credit(&acct, 5).unwrap();
        let probe = ledger.clone();
        let app = authed_billing_router(ledger, OidcVerifierHandle::new(Some(verifier)), 100);

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let claims = serde_json::json!({ "sub": "payer", "iss": issuer, "exp": now + 3600 });
        let jwt = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        let issue = |price: u64| {
            app.clone().oneshot(
                Request::post("/me/issue")
                    .header("authorization", format!("Bearer {jwt}"))
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"price":{price}}}"#)))
                    .unwrap(),
            )
        };

        // price:0 is refused and mints/debits nothing — the free-token hole is closed.
        assert_eq!(
            issue(0).await.unwrap().status(),
            StatusCode::PAYMENT_REQUIRED,
            "price:0 must not mint a free token"
        );
        assert_eq!(probe.balance(&acct).unwrap(), 5, "a refused issuance debits nothing");

        // Paying the token price succeeds and debits exactly that.
        assert_eq!(issue(1).await.unwrap().status(), StatusCode::OK, "paying TOKEN_PRICE mints a token");
        assert_eq!(probe.balance(&acct).unwrap(), 4, "the token price was debited");
    }

    #[tokio::test]
    async fn authed_channel_registry_is_owner_scoped() {
        // #81 SEC81c-b: the channel registry is authenticated and owner-scoped —
        // owner = verified subject. Only the owner registers/manages a channel; a
        // non-owner is forbidden; and the records drive the SEC81c-a authorize
        // lookup (add → resolvable, remove → denied).
        use axum::body::Body;
        use axum::http::Request;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        let secret = b"realm-secret";
        let issuer = "https://kc/realms/ct";
        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let verifier = Arc::new(OidcVerifier::from_hs_secret(secret, issuer));
        let probe = channels.clone();
        let app = authed_channel_router(channels, OidcVerifierHandle::new(Some(verifier)));

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let jwt_for = |sub: &str| {
            let claims = serde_json::json!({ "sub": sub, "iss": issuer, "exp": now + 3600 });
            encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(secret),
            )
            .unwrap()
        };
        let alice = jwt_for("alice");
        let mallory = jwt_for("mallory");
        let post = |path: String, bearer: Option<String>, body: String| {
            let mut req = Request::post(&path).header("content-type", "application/json");
            if let Some(b) = &bearer {
                req = req.header("authorization", format!("Bearer {b}"));
            }
            app.clone().oneshot(req.body(Body::from(body)).unwrap())
        };

        use ed25519_dalek::{Signer, SigningKey};
        let ch = "a1".repeat(32);
        let op = "b2".repeat(32);
        let chan = ChannelId(hex_decode_32(&ch).unwrap());
        // #101: the member attests its Noise key with its holder key, so the holder
        // must be a real keypair and the POST must carry a valid attestation.
        let holder_sk = SigningKey::from_bytes(&[0xc3u8; 32]);
        let hbytes = holder_sk.verifying_key().to_bytes();
        let holder = hex_encode(&hbytes);
        let nk_bytes = [0xd4u8; 32];
        let attest = |sk: &SigningKey, hb: &[u8; 32]| {
            hex_encode(&sk.sign(&ct_common::channel::member_noise_attest_bytes(&chan, hb, &nk_bytes)).to_bytes())
        };

        // Unauthenticated registration is rejected.
        let s = post(
            "/me/channels".into(),
            None,
            format!(r#"{{"channel":"{ch}","operator_pubkey":"{op}"}}"#),
        )
        .await
        .unwrap()
        .status();
        assert_eq!(s, StatusCode::UNAUTHORIZED, "no bearer -> 401");

        // Alice registers her channel and adds a member.
        let s = post(
            "/me/channels".into(),
            Some(alice.clone()),
            format!(r#"{{"channel":"{ch}","operator_pubkey":"{op}"}}"#),
        )
        .await
        .unwrap()
        .status();
        assert_eq!(s, StatusCode::OK, "owner registers");
        let nk = hex_encode(&nk_bytes);
        let att = attest(&holder_sk, &hbytes);
        let s = post(
            format!("/me/channels/{ch}/members"),
            Some(alice.clone()),
            format!(r#"{{"holder":"{holder}","noise_pubkey":"{nk}","noise_attestation":"{att}"}}"#),
        )
        .await
        .unwrap()
        .status();
        assert_eq!(s, StatusCode::OK, "owner adds a member");
        assert_eq!(
            probe.authorize_holder(&chan, &hbytes).unwrap(),
            Some(hex_decode_32(&op).unwrap()),
            "an added member resolves the operator key (drives SEC81c-a)"
        );
        assert_eq!(
            probe.member_noise_key(&chan, &hbytes).unwrap(),
            Some(hex_decode_32(&nk).unwrap()),
            "the member's pinned X25519 Noise key round-trips (AF4 key distribution)"
        );

        // #101 SEC101b: a member POST whose attestation doesn't verify (here all-zero)
        // is rejected — the CP won't store an un-attested / operator-forged Noise key.
        let s = post(
            format!("/me/channels/{ch}/members"),
            Some(alice.clone()),
            format!(r#"{{"holder":"{holder}","noise_pubkey":"{nk}","noise_attestation":"{}"}}"#, "00".repeat(64)),
        )
        .await
        .unwrap()
        .status();
        assert_eq!(s, StatusCode::BAD_REQUEST, "an unattested Noise key is rejected (#101)");

        // Mallory cannot manage or re-key alice's channel (valid attestation, so the
        // rejection is on ownership at 403, not the attestation check).
        let m_sk = SigningKey::from_bytes(&[0xeeu8; 32]);
        let m_h = hex_encode(&m_sk.verifying_key().to_bytes());
        let m_att = attest(&m_sk, &m_sk.verifying_key().to_bytes());
        let s = post(
            format!("/me/channels/{ch}/members"),
            Some(mallory.clone()),
            format!(r#"{{"holder":"{m_h}","noise_pubkey":"{nk}","noise_attestation":"{m_att}"}}"#),
        )
        .await
        .unwrap()
        .status();
        assert_eq!(s, StatusCode::FORBIDDEN, "non-owner cannot add members");
        let s = post(
            "/me/channels".into(),
            Some(mallory),
            format!(r#"{{"channel":"{ch}","operator_pubkey":"{}"}}"#, "ff".repeat(32)),
        )
        .await
        .unwrap()
        .status();
        assert_eq!(s, StatusCode::FORBIDDEN, "non-owner cannot re-key");
        assert_eq!(
            probe.operator_pubkey(&chan).unwrap(),
            Some(hex_decode_32(&op).unwrap()),
            "operator key unchanged by the refused re-key"
        );

        // Alice revokes the member → the authorize lookup denies it.
        let s = post(
            format!("/me/channels/{ch}/members/{holder}/remove"),
            Some(alice),
            String::new(),
        )
        .await
        .unwrap()
        .status();
        assert_eq!(s, StatusCode::OK, "owner removes a member");
        assert_eq!(
            probe.authorize_holder(&chan, &hbytes).unwrap(),
            None,
            "a revoked member is no longer authorized"
        );
    }

    #[tokio::test]
    async fn channel_allowlist_routes_are_owner_scoped_248() {
        // #248-follow: the allow-list management routes share `authed_channel_router`'s
        // owner-scoping with the member routes tested above.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        let secret = b"realm-secret";
        let issuer = "https://kc/realms/ct";
        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let verifier = Arc::new(OidcVerifier::from_hs_secret(secret, issuer));
        let app = authed_channel_router(channels, OidcVerifierHandle::new(Some(verifier)));

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let jwt_for = |sub: &str| {
            let claims = serde_json::json!({ "sub": sub, "iss": issuer, "exp": now + 3600 });
            encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(secret)).unwrap()
        };
        let alice = jwt_for("alice");
        let mallory = jwt_for("mallory");
        let ch = "c3".repeat(32);
        let op = "d4".repeat(32);
        let post = |path: String, bearer: Option<String>, body: String| {
            let mut req = Request::post(&path).header("content-type", "application/json");
            if let Some(b) = &bearer {
                req = req.header("authorization", format!("Bearer {b}"));
            }
            app.clone().oneshot(req.body(Body::from(body)).unwrap())
        };
        let get = |path: String, bearer: Option<String>| {
            let mut req = Request::get(&path);
            if let Some(b) = &bearer {
                req = req.header("authorization", format!("Bearer {b}"));
            }
            app.clone().oneshot(req.body(Body::empty()).unwrap())
        };

        assert_eq!(
            post("/me/channels".into(), Some(alice.clone()), format!(r#"{{"channel":"{ch}","operator_pubkey":"{op}"}}"#))
                .await.unwrap().status(),
            StatusCode::OK
        );

        // Non-owner: can't add, can't list (403, not an empty list — no membership leak).
        assert_eq!(
            post(format!("/me/channels/{ch}/allowlist"), Some(mallory.clone()), r#"{"email":"nat@example.com"}"#.into())
                .await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(get(format!("/me/channels/{ch}/allowlist"), Some(mallory.clone())).await.unwrap().status(), StatusCode::FORBIDDEN);

        // Malformed email is rejected before it ever reaches storage.
        assert_eq!(
            post(format!("/me/channels/{ch}/allowlist"), Some(alice.clone()), r#"{"email":"not-an-email"}"#.into())
                .await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );

        // Owner adds, then lists.
        assert_eq!(
            post(format!("/me/channels/{ch}/allowlist"), Some(alice.clone()), r#"{"email":"Nat@Example.com"}"#.into())
                .await.unwrap().status(),
            StatusCode::OK
        );
        let resp = get(format!("/me/channels/{ch}/allowlist"), Some(alice.clone())).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["emails"], serde_json::json!(["nat@example.com"]), "stored lowercased");

        // Non-owner can't remove either.
        assert_eq!(
            post(format!("/me/channels/{ch}/allowlist/nat@example.com/remove"), Some(mallory), String::new())
                .await.unwrap().status(),
            StatusCode::FORBIDDEN
        );

        // Owner removes it; list is empty again.
        assert_eq!(
            post(format!("/me/channels/{ch}/allowlist/nat@example.com/remove"), Some(alice.clone()), String::new())
                .await.unwrap().status(),
            StatusCode::OK
        );
        let resp = get(format!("/me/channels/{ch}/allowlist"), Some(alice)).await.unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["emails"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn internal_channel_authorize_requires_admin_token_and_membership() {
        // #81 SEC81c-c c-i: the edge queries this (with the shared admin token) to
        // source the broker's `authorize` closure — operator key iff the holder is a
        // current member; bad/missing token -> 401; non-member -> 404.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        let admin = [0x7au8; 32];
        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let ch = ChannelId([0xC5u8; 32]);
        let op = [0xEEu8; 32];
        let member = [0x33u8; 32];
        assert!(channels.register_channel(&ch, &op, "alice").unwrap());
        assert!(channels.add_member(&ch, "alice", &member, &[0xd4u8; 32], &[0u8; 64]).unwrap());

        let topologies = Arc::new(SqliteTopologyStore::open_in_memory().unwrap());
        let app = internal_channel_authorize_router(channels, topologies, admin);
        let admin_hex = hex_encode(&admin);
        let wrong_hex = hex_encode(&[0u8; 32]);
        let ch_hex = hex_encode(&ch.0);
        let post = |tok: Option<String>, holder: [u8; 32]| {
            let mut req =
                Request::post("/internal/channel/authorize").header("content-type", "application/json");
            if let Some(t) = tok {
                req = req.header("x-ct-admin-token", t);
            }
            let body = format!(r#"{{"channel":"{ch_hex}","holder":"{}"}}"#, hex_encode(&holder));
            app.clone().oneshot(req.body(Body::from(body)).unwrap())
        };

        // Correct token + member -> 200 + the operator key.
        let r = post(Some(admin_hex.clone()), member).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let bytes = to_bytes(r.into_body(), 1 << 16).await.unwrap();
        let resp: AuthorizeResp = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(resp.operator_pubkey, hex_encode(&op), "member resolves the operator key");
        assert_eq!(
            resp.noise_pubkey.as_deref(),
            Some(hex_encode(&[0xd4u8; 32]).as_str()),
            "the member's attested Noise key is served for A2A key delivery (#72/#100)"
        );

        // Wrong / missing token -> 401 (before any lookup).
        assert_eq!(post(Some(wrong_hex), member).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        assert_eq!(post(None, member).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        // Valid token, non-member holder -> 404.
        assert_eq!(
            post(Some(admin_hex), [0x44u8; 32]).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn internal_channel_authorize_additively_consults_a_bound_topologys_declared_edges() {
        // #235/#107-enforce (ii-b): a declared topology edge is a SECOND, ADDITIVE path to
        // channel authorization -- neither replaces nor restricts the existing
        // channel-membership path. Exercises both halves: a topology-only holder (never
        // registered in the channel store at all) gets authorized purely from a declared
        // edge, and a genuinely unrelated channel/holder pair with NO topology involvement
        // is completely unaffected by topologies existing elsewhere in the same store.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use ed25519_dalek::{Signer, SigningKey};
        use tower::ServiceExt;

        let admin = [0x7au8; 32];
        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let topologies = Arc::new(SqliteTopologyStore::open_in_memory().unwrap());

        // A topology owner binds a real operator key (genuine proof-of-possession) and draws
        // one edge between two holder-key node ids -- no channel-store registration at all.
        let op_key = SigningKey::from_bytes(&[0x11u8; 32]);
        let op_pub = op_key.verifying_key().to_bytes();
        let holder_a = [0x22u8; 32];
        let holder_b = [0x33u8; 32];
        let tid = "t1";
        assert!(topologies.create_topology("owner1", tid, "net1").unwrap());
        topologies.assign("owner1", &hex_encode(&holder_a), tid).unwrap();
        topologies.assign("owner1", &hex_encode(&holder_b), tid).unwrap();
        assert!(topologies.add_edge("owner1", tid, &hex_encode(&holder_a), &hex_encode(&holder_b)).unwrap());
        let proof = op_key.sign(&ct_common::channel::topology_operator_binding_bytes(tid, &op_pub)).to_bytes();
        assert!(topologies.set_operator("owner1", tid, &op_pub, &proof).unwrap());
        let topo_channel = ct_common::channel::channel_id_for_link(&op_pub, &holder_a, &holder_b);

        let app = internal_channel_authorize_router(channels, topologies, admin);
        let admin_hex = hex_encode(&admin);
        let post = |channel: &ct_common::channel::ChannelId, holder: [u8; 32]| {
            let req = Request::post("/internal/channel/authorize")
                .header("content-type", "application/json")
                .header("x-ct-admin-token", admin_hex.clone());
            let body = format!(r#"{{"channel":"{}","holder":"{}"}}"#, hex_encode(&channel.0), hex_encode(&holder));
            app.clone().oneshot(req.body(Body::from(body)).unwrap())
        };

        // The topology-declared edge authorizes holder_a on the derived channel -- purely
        // from the drawn edge, with no channel-store registration whatsoever.
        let r = post(&topo_channel, holder_a).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK, "topology edge authorizes a never-registered holder");
        let bytes = to_bytes(r.into_body(), 1 << 16).await.unwrap();
        let resp: AuthorizeResp = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(resp.operator_pubkey, hex_encode(&op_pub));
        assert_eq!(resp.noise_pubkey, None, "no channel-store registration -> no noise key to hand back");

        // A genuinely unrelated (channel, holder) pair -- no edge names it -- is still a
        // clean 404, unaffected by the topology store having OTHER real topologies in it.
        let unrelated: ct_common::channel::ChannelId = ct_common::channel::ChannelId([0x99u8; 32]);
        assert_eq!(post(&unrelated, [0x44u8; 32]).await.unwrap().status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn internal_revoked_tokens_requires_the_admin_token_and_lists_every_revocation_327() {
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        let admin = [0x7au8; 32];
        let tunnels = Arc::new(crate::storage::SqliteTunnelStore::open_in_memory().unwrap());
        let a = tunnels.create("alice", "web", None).unwrap();
        let b = tunnels.create("alice", "api", None).unwrap();
        tunnels.revoke("alice", &a.id, 1_000).unwrap();

        let app = internal_revoked_tokens_router(tunnels.clone(), admin);
        let get = |tok: Option<String>| {
            let mut req = Request::get("/internal/revoked-tokens");
            if let Some(t) = tok {
                req = req.header("x-ct-admin-token", t);
            }
            app.clone().oneshot(req.body(Body::empty()).unwrap())
        };

        // Wrong / missing token -> 401, before any lookup.
        assert_eq!(get(Some(hex_encode(&[0u8; 32]))).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        assert_eq!(get(None).await.unwrap().status(), StatusCode::UNAUTHORIZED);

        // Correct token -> 200 + exactly the revoked token, not the live one.
        let r = get(Some(hex_encode(&admin))).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let bytes = to_bytes(r.into_body(), 1 << 16).await.unwrap();
        let resp: RevokedTokensResp = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(resp.tokens, vec![a.routing_token]);
        assert!(!resp.tokens.contains(&b.routing_token), "the live tunnel's token is never listed");
    }

    #[tokio::test]
    async fn payment_webhook_credits_only_on_a_valid_signature() {
        use axum::body::Body;
        use axum::http::Request;
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        let secret = b"whsec_test";
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let verifier = Arc::new(WebhookVerifier::new(secret.to_vec(), 300));

        // A pending intent for 7 credits on a fresh account.
        let account = ledger.open_account().unwrap();
        let payment = ledger.create_intent(&account, 7).unwrap();
        assert_eq!(ledger.balance(&account).unwrap(), 0);

        let app = payment_webhook_router(ledger.clone(), verifier.clone());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = format!(
            r#"{{"payment":"{}","status":"succeeded"}}"#,
            hex_encode(&payment.0)
        );

        let post = |ts: u64, sig: String, body: String| {
            app.clone().oneshot(
                Request::post("/payment/webhook")
                    .header("x-ct-webhook-timestamp", ts.to_string())
                    .header("x-ct-webhook-signature", sig)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
        };

        // Forged signature -> 401, no credit.
        let resp = post(now, "deadbeef".to_string(), body.clone()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "forged webhook rejected");
        assert_eq!(ledger.balance(&account).unwrap(), 0, "no credit on a bad signature");

        // Valid signature -> 200, account credited.
        let sig = verifier.sign(now, body.as_bytes());
        let resp = post(now, sig.clone(), body.clone()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "signed webhook accepted");
        assert_eq!(ledger.balance(&account).unwrap(), 7, "credited exactly the intent");

        // Replayed valid event -> 200 (idempotent), still credited once.
        let resp = post(now, sig, body).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "replay acknowledged");
        assert_eq!(
            ledger.balance(&account).unwrap(),
            7,
            "idempotent: no double credit"
        );
    }

    #[tokio::test]
    async fn payment_webhook_rejects_a_stale_event() {
        use axum::body::Body;
        use axum::http::Request;
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        let secret = b"whsec_test";
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let verifier = Arc::new(WebhookVerifier::new(secret.to_vec(), 300));
        let account = ledger.open_account().unwrap();
        let payment = ledger.create_intent(&account, 5).unwrap();

        let app = payment_webhook_router(ledger.clone(), verifier.clone());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Timestamp 10 minutes in the past; tolerance is 5 minutes. The signature
        // is valid for that timestamp, but the event is too old to accept.
        let stale = now - 600;
        let body = format!(
            r#"{{"payment":"{}","status":"succeeded"}}"#,
            hex_encode(&payment.0)
        );
        let sig = verifier.sign(stale, body.as_bytes());
        let resp = app
            .oneshot(
                Request::post("/payment/webhook")
                    .header("x-ct-webhook-timestamp", stale.to_string())
                    .header("x-ct-webhook-signature", sig)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "stale event rejected");
        assert_eq!(ledger.balance(&account).unwrap(), 0, "no credit for a replay");
    }

    #[tokio::test]
    async fn production_router_mounts_oidc_authed_endpoints_when_configured() {
        use axum::body::Body;
        use axum::http::Request;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        let secret = b"realm-secret";
        let issuer = "https://kc/realms/ct";
        let oidc = Arc::new(OidcVerifier::from_hs_secret(secret, issuer));
        let app =
            persistent_control_plane_router(":memory:", b"whsec", b"test-session-key", OidcVerifierHandle::from(Some(oidc))).unwrap();

        // Without a bearer token the mounted endpoint rejects with 401 (not 404).
        let resp = app
            .clone()
            .oneshot(Request::get("/me/account").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "authed endpoint is gated");

        // A valid token resolves the subject's account through the production router.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({ "sub": "user-1", "iss": issuer, "exp": now + 3600 });
        let jwt = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        let resp = app
            .oneshot(
                Request::get("/me/account")
                    .header("authorization", format!("Bearer {jwt}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "authenticated subject gets an account");
    }

    #[tokio::test]
    async fn me_account_exposes_balance_and_subject_for_the_authenticated_customer() {
        // #26 PP1: the self-service account view carries the credit balance
        // (Guthaben) and the verified subject, self-scoped to the caller.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        let secret = b"realm-secret";
        let issuer = "https://kc/realms/ct";
        let oidc = Arc::new(OidcVerifier::from_hs_secret(secret, issuer));
        let app = persistent_control_plane_router(":memory:", b"whsec", b"test-session-key", OidcVerifierHandle::from(Some(oidc))).unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({ "sub": "kc-user-42", "iss": issuer, "exp": now + 3600 });
        let jwt = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        let resp = app
            .oneshot(
                Request::get("/me/account")
                    .header("authorization", format!("Bearer {jwt}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["subject"], "kc-user-42", "echoes the verified subject");
        assert_eq!(v["balance"], 0, "a fresh account starts with zero credit");
        assert!(
            v["account"].as_str().is_some_and(|a| !a.is_empty()),
            "carries the account id"
        );
    }

    #[tokio::test]
    async fn production_router_serves_authed_endpoints_as_503_without_oidc() {
        // #328: /me/* used to not be mounted at all without a boot-time OIDC verifier
        // (404 -- indistinguishable from a route that plain doesn't exist). It's now
        // always mounted, so an unconfigured/unavailable verifier reads 503 (the
        // route exists, but can't authenticate you right now) -- and, unlike a 404,
        // it can recover to 401/200 without a restart the moment a background retry
        // (or, in this constructed test, an explicit `set()`) installs a verifier.
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let handle = OidcVerifierHandle::empty();
        let app = persistent_control_plane_router(":memory:", b"whsec", b"test-session-key", handle.clone()).unwrap();
        let resp = app
            .clone()
            .oneshot(Request::get("/me/account").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "authed endpoints are mounted but unavailable when OIDC is unconfigured"
        );

        handle.set(Arc::new(OidcVerifier::from_hs_secret(b"s", "https://kc/realms/ct")));
        let resp = app
            .oneshot(Request::get("/me/account").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "#328: the same already-built production router recovers to normal auth behavior once the handle is set"
        );
    }

    #[tokio::test]
    async fn portal_session_key_is_independent_of_the_payment_webhook_secret_294() {
        // #294: the portal session cookie's HMAC key must be a genuinely distinct
        // secret from the payment webhook secret — that one is shared by
        // definition with an external payment provider, so if it were also the
        // session key, anyone who learned it could forge a `ct_portal_session`
        // for any subject. A cookie signed with the WEBHOOK secret must be
        // rejected; one signed with the real SESSION key must be accepted.
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = persistent_control_plane_router(":memory:", b"the-webhook-secret", b"the-session-key", OidcVerifierHandle::empty()).unwrap();

        // A cookie forged with the webhook secret (what an attacker who only
        // learned THAT secret could produce) is rejected -> bounced to /portal.
        let forged = crate::portal::sign_session_for_test(b"the-webhook-secret", "mallory");
        let resp = app
            .clone()
            .oneshot(
                Request::get("/portal/home")
                    .header("cookie", format!("ct_portal_session={forged}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "a session forged with the webhook secret is rejected");

        // A cookie signed with the REAL session key is accepted.
        let real = crate::portal::sign_session_for_test(b"the-session-key", "alice");
        let resp = app
            .oneshot(
                Request::get("/portal/home")
                    .header("cookie", format!("ct_portal_session={real}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "a session signed with the real session key is accepted");
    }

    #[tokio::test]
    async fn production_router_has_no_client_payment_confirm() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        // The unified production router must not expose the M18 stub endpoint —
        // credits come only from the signed webhook (proven crediting-side by
        // unified_control_plane_survives_restart).
        let app = persistent_control_plane_router(":memory:", b"whsec_prod", b"test-session-key", OidcVerifierHandle::empty()).unwrap();
        let resp = app
            .oneshot(
                Request::post("/payment/confirm")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"payment":"00"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "client-callable /payment/confirm is removed from production"
        );
    }

    #[tokio::test]
    async fn landing_page_serves_self_contained_html() {
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        // The full production router serves the landing page at `/`.
        let app = persistent_control_plane_router(":memory:", b"whsec", b"test-session-key", OidcVerifierHandle::empty()).unwrap();
        let resp = app
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(ct.starts_with("text/html"), "serves HTML, got {ct}");
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        // Self-contained (no external asset URLs) and renders the status figures.
        assert!(html.contains("Bunsenbrenner"), "has the Bunsenbrenner branding");
        // #241 restructured the hero; "published worldwide" left with it.
        assert!(html.contains("Better homemade ideas"), "has the hero headline");
        assert!(html.contains("operator status"), "has the live-status section");
        assert!(html.contains("fetch('/status')"), "fetches the status endpoint");
        assert!(
            html.contains("registered tunnels") && html.contains("uptime"),
            "renders the key metadata figures"
        );
        // #64: the apex landing page must offer a discoverable path to the customer
        // Portal (sign-up/sign-in). A relative /portal link keeps it host-agnostic.
        assert!(
            html.contains(r#"href="/portal""#),
            "links to the customer portal (#64)"
        );
        // CSP-safe means no external *asset* (script/style/image) sources -- an outbound <a href>
        // link (e.g. the support/membership page below) is plain navigation, not a CSP concern.
        assert!(
            !html.contains("src=\"http") && !html.contains("<link") && !html.contains("//cdn"),
            "no externally-sourced scripts/styles/images (CSP-safe)"
        );
        // A simple, honest cookie notice (not a consent gate -- only strictly-necessary cookies are
        // set, so DSGVO/TTDSG §25 Abs.2 Nr.2 requires no consent, just transparency): dismissible,
        // remembered via localStorage, linking to the actual Datenschutzerklärung.
        assert!(html.contains(r#"id="cookie-notice""#), "shows the cookie notice");
        assert!(html.contains("technically necessary cookies"), "explains what cookies are set and why");
        assert!(html.contains("ct-cookie-notice-seen"), "remembers dismissal so it doesn't nag on every visit");
        // #194: fail closed — with no CT_CP_EDGE_ADMIN_TOKEN set (unset in the test env → admin_token
        // = None), the unauthenticated client-supplied-account billing writer must NOT be served;
        // /billing/issue is absent (404), not an open account-debit endpoint.
        let app_b = persistent_control_plane_router(":memory:", b"whsec", b"test-session-key", OidcVerifierHandle::empty()).unwrap();
        let resp_b = app_b
            .oneshot(
                Request::post("/billing/issue")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"account":"0000000000000000000000000000000000000000000000000000000000000000","price":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_b.status(), StatusCode::NOT_FOUND, "billing writers absent without the admin token (#194)");
        // #174: the operator status page links AI agents to the onboarding entry point, and that
        // entry point is served live at /llms.txt (the doc as plain text a CLI agent can curl).
        assert!(html.contains(r#"href="/llms.txt""#), "links AI agents to the onboarding doc (#174)");
        // The human "get started" onboarding (register/download/prompt/subdomain) now lives inline
        // on the landing page itself, not a separate /publish subpage.
        assert!(html.contains(r#"id="get-started""#), "the onboarding steps are anchored for deep-linking");
        assert!(
            html.contains("/downloads/hello-world-pipeline.zip"),
            "offers a one-click template download (no git required)"
        );
        assert!(html.contains("copyCode"), "the Claude Code prompt has a copy-to-clipboard button");
        // The "get your template" step offers both a self-serve download+guide path and a
        // self-fetching LLM-prompt path, and the prompt tells the LLM to persist the minted
        // identity into a .env file rather than just holding it in the current shell.
        assert!(html.contains(r#"href="/template-guide""#), "links to the read-it-yourself template guide");
        assert!(html.contains(".env"), "the LLM prompt is told to persist the identity into a .env file");
        assert!(
            html.contains("containerized") || html.contains("Kubernetes pod"),
            "the security callout recommends running the user's service in an isolated sandbox"
        );
        assert!(
            html.contains("https://steady.page/plans/77a32d9c-c399-4ca1-9515-7a628c7a9413"),
            "links to the project's support/membership page"
        );
        assert!(
            html.contains("https://buymeacoffee.com/bunsenbrenner"),
            "links to the project's Buy Me a Coffee page"
        );
        // /publish still redirects (old links / bookmarks keep working) to the merged section.
        let app_pub = persistent_control_plane_router(":memory:", b"whsec", b"test-session-key", OidcVerifierHandle::empty()).unwrap();
        let resp_pub = app_pub.oneshot(Request::get("/publish").body(Body::empty()).unwrap()).await.unwrap();
        assert!(resp_pub.status().is_redirection(), "/publish redirects, got {}", resp_pub.status());
        assert_eq!(
            resp_pub.headers().get("location").and_then(|v| v.to_str().ok()),
            Some("/#get-started"),
            "/publish redirects into the merged landing-page section"
        );
        // The starter template is a real, downloadable zip (not a 404, not HTML).
        let app_zip = persistent_control_plane_router(":memory:", b"whsec", b"test-session-key", OidcVerifierHandle::empty()).unwrap();
        let resp_zip = app_zip
            .oneshot(Request::get("/downloads/hello-world-pipeline.zip").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp_zip.status(), StatusCode::OK);
        assert_eq!(
            resp_zip.headers().get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/zip")
        );
        assert!(
            resp_zip
                .headers()
                .get("content-disposition")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .contains("hello-world-pipeline.zip"),
            "downloads with a real filename, not just an octet stream"
        );
        let zip_bytes = to_bytes(resp_zip.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&zip_bytes[..2], b"PK", "serves a real zip archive (PK magic bytes)");
        // The read-it-yourself template guide actually serves (not a dead link).
        let app_guide = persistent_control_plane_router(":memory:", b"whsec", b"test-session-key", OidcVerifierHandle::empty()).unwrap();
        let resp_guide = app_guide
            .oneshot(Request::get("/template-guide").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp_guide.status(), StatusCode::OK);
        let guide_html =
            String::from_utf8_lossy(&to_bytes(resp_guide.into_body(), usize::MAX).await.unwrap()).to_string();
        assert!(
            guide_html.contains("pipeline-spec.json") && guide_html.contains(".env"),
            "the template guide explains the file structure and the .env identity file"
        );
        let app2 = persistent_control_plane_router(":memory:", b"whsec", b"test-session-key", OidcVerifierHandle::empty()).unwrap();
        let resp2 = app2.oneshot(Request::get("/llms.txt").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let ct2 = resp2.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        assert!(ct2.starts_with("text/plain"), "llms.txt is plain text, got {ct2}");
        let doc = String::from_utf8_lossy(&to_bytes(resp2.into_body(), usize::MAX).await.unwrap()).to_string();
        assert!(
            doc.contains("AI-agent onboarding") && doc.contains("Register yourself as a discoverable agent"),
            "/llms.txt serves the onboarding doc"
        );
        // The footer links to the three (English) legal pages, and each actually serves
        // (not a dead link). The German originals stay reachable at their own URLs too
        // (checked in legal_pages_serve_real_operator_facts_not_placeholders below) but
        // are no longer what the footer itself links to -- the site is English-first.
        assert!(
            html.contains(r#"href="/legal-notice""#)
                && html.contains(r#"href="/privacy-policy""#)
                && html.contains(r#"href="/terms-of-use""#),
            "footer links to the English legal pages"
        );
        // The accounts stat is no longer shown on the landing page (operator request).
        assert!(!html.contains(r#"id="accounts""#), "accounts counter removed from the landing page");
    }

    #[tokio::test]
    async fn legal_pages_serve_real_operator_facts_not_placeholders() {
        // A fabricated/placeholder Impressum is itself a legal defect (worse than none) -- this
        // pins that the served page carries real, specific operator facts, not a TODO/placeholder.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        for (path, must_contain) in [
            ("/impressum", vec!["Martin Becke", "Mettinger", "Neuenkirchen", "§ 19 UStG"]),
            ("/datenschutz", vec!["DSGVO", "TTDSG", "Cookies"]),
            ("/nutzungsbedingungen", vec!["Freistellung", "Nutzerdienst", "§§ 7", "TMG"]),
            // English courtesy translations (the site is English-first) -- each still names
            // real operator facts / statute citations, not placeholder prose, and each points
            // back at its own German original as the legally binding version.
            ("/legal-notice", vec!["Martin Becke", "Mettinger", "Neuenkirchen", "§ 19 UStG", "courtesy translation", "/impressum"]),
            ("/privacy-policy", vec!["GDPR", "TTDSG", "Cookies", "courtesy translation", "/datenschutz"]),
            ("/terms-of-use", vec!["Indemnification", "user service", "Art. 9", "TMG", "courtesy translation", "/nutzungsbedingungen"]),
            (
                // The human "get started" onboarding now lives inline on the landing page itself.
                // #237 redesign: the entry point is an email-first join form (login_hint into the
                // existing Keycloak/OIDC flow), not a bare "Register" button -- so this checks for
                // that CTA's own copy instead of the retired word. #241 dropped the "Your
                // subdomain" callout (the only place "Standard"/"subdomain" appeared) as part of
                // the hero restructure -- those two assertions went with it.
                "/",
                vec![
                    "Get your tunnel",
                    "login_hint",
                    "hello-world-pipeline",
                    "Claude Code",
                    "Bunsenbrenner",
                    "not protection",
                ],
            ),
        ] {
            let app = persistent_control_plane_router(":memory:", b"whsec", b"test-session-key", OidcVerifierHandle::empty()).unwrap();
            let resp = app.oneshot(Request::get(path).body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{path} should serve");
            let ct = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            assert!(ct.starts_with("text/html"), "{path} serves HTML, got {ct}");
            let body = String::from_utf8_lossy(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).to_string();
            for needle in must_contain {
                assert!(body.contains(needle), "{path} should mention {needle:?}");
            }
        }
    }

    #[tokio::test]
    async fn pki_endpoint_publishes_the_edge_ca_root() {
        // #11 C1: GET /pki/ca serves the edge CA root DER read from the shared
        // path, and 503s until it exists.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        let der: &[u8] = b"\x30\x82\x01\x0a-fake-ca-root-der";
        let path = std::env::temp_dir().join(format!("ct-cp-ca-{}.der", std::process::id()));
        std::fs::write(&path, der).unwrap();

        let app = pki_router(path.to_string_lossy().into_owned());
        let resp = app
            .oneshot(Request::get("/pki/ca").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/x-x509-ca-cert"
        );
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], der, "serves the exact CA root DER");

        // Missing file (edge hasn't published yet) → 503.
        let app2 = pki_router("/nonexistent/ct-edge-ca.der".to_string());
        let resp2 = app2
            .oneshot(Request::get("/pki/ca").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::SERVICE_UNAVAILABLE);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn status_endpoint_reports_aggregated_counts() {
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        let enrollment = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let registry = Arc::new(SqliteRegistry::open_in_memory().unwrap());
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());

        // Seed one of each metadata kind.
        let tenant = TenantId("t".into());
        let jt = enrollment.issue_join_token(&tenant).unwrap();
        enrollment
            .redeem(&jt, &AgentId("a".into()), [1u8; 32])
            .unwrap();
        registry
            .register(
                &RoutingToken([2u8; 32]),
                &TunnelInfo {
                    tenant: tenant.clone(),
                    agent: AgentId("a".into()),
                },
            )
            .unwrap();
        let acct = ledger.open_account().unwrap();
        let pid = ledger.create_intent(&acct, 5).unwrap();
        ledger.confirm_payment(&pid).unwrap();
        let agent_directory = Arc::new(SqliteAgentDirectory::open_in_memory().unwrap());
        agent_directory
            .register("holder1", "https://example.test/card.json", &["physics".into()], &[], 1)
            .unwrap();
        let pipeline_registry = Arc::new(SqlitePipelineRegistry::open_in_memory().unwrap());
        pipeline_registry
            .publish(
                "owner1",
                &ct_common::pipeline::PipelineSpec { id: "flappy".into(), roles: vec![], operator_pubkey_hex: None, selection_policy: ct_common::pipeline::SelectionPolicy::LowestFloor },
                1,
            )
            .unwrap();

        let app = status_router(
            enrollment,
            registry,
            ledger,
            agent_directory,
            pipeline_registry,
            None,
            OidcVerifierHandle::empty(),
        );
        let resp = app
            .oneshot(Request::get("/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let s: StatusResp = serde_json::from_slice(&body).unwrap();
        assert!(s.ready, "db reachable");
        assert_eq!(s.tunnels, 1, "no edge url -> falls back to the CP registry count");
        assert_eq!(s.agents, 1);
        assert_eq!(s.accounts, 1);
        assert_eq!(s.payments_confirmed, 1);
        assert_eq!(s.pipelines_published, 1);
        assert_eq!(s.agents_directory, 1);
        assert!(!s.oidc_enabled, "328: unconfigured/unavailable OIDC must read false on /status");
    }

    #[test]
    fn parse_metric_reads_the_named_gauge() {
        let body = "# HELP ct_edge_active_tunnels x\n\
                    # TYPE ct_edge_active_tunnels gauge\n\
                    ct_edge_active_tunnels 4\n\
                    ct_edge_active_agents 9\n";
        assert_eq!(parse_metric(body, "ct_edge_active_tunnels"), Some(4));
        assert_eq!(parse_metric(body, "ct_edge_active_agents"), Some(9));
        assert_eq!(parse_metric(body, "nonexistent"), None);
    }

    #[tokio::test]
    async fn status_reports_live_edge_tunnels_when_configured() {
        // #17: the live tunnel registry lives in the edge, not the CP rendezvous
        // registry (which the onboard/serve path never writes). With an edge
        // metrics URL configured, /status.tunnels must report the edge's live
        // ct_edge_active_tunnels gauge — even when the CP registry is EMPTY.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        // Mock edge /metrics reporting 3 live tunnels (7 redundant agents).
        let metrics = "# HELP ct_edge_active_tunnels x\n\
                       # TYPE ct_edge_active_tunnels gauge\n\
                       ct_edge_active_tunnels 3\n\
                       # TYPE ct_edge_active_agents gauge\n\
                       ct_edge_active_agents 7\n";
        let edge = Router::new().route("/metrics", get(move || async move { metrics }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, edge).await.unwrap() });

        // CP stores with an EMPTY registry (0 rendezvous entries).
        let enrollment = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let registry = Arc::new(SqliteRegistry::open_in_memory().unwrap());
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());

        let app = status_router(
            enrollment,
            registry,
            ledger,
            Arc::new(SqliteAgentDirectory::open_in_memory().unwrap()),
            Arc::new(SqlitePipelineRegistry::open_in_memory().unwrap()),
            Some(format!("http://{addr}/metrics")),
            OidcVerifierHandle::from(Some(Arc::new(OidcVerifier::from_hs_secret(b"s", "https://kc/realms/ct")))),
        );
        let resp = app
            .oneshot(Request::get("/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let s: StatusResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            s.tunnels, 3,
            "reports the live edge tunnel count, not the empty CP registry"
        );
        assert!(s.oidc_enabled, "328: a configured/available OIDC verifier must read true on /status");
    }

    #[tokio::test]
    async fn health_and_readiness_endpoints() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = persistent_control_plane_router(":memory:", b"whsec_health", b"test-session-key", OidcVerifierHandle::empty()).unwrap();

        let health = app
            .clone()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK, "liveness ok");

        let ready = app
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::OK, "readiness ok (db reachable)");
    }
}
