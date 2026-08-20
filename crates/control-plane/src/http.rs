//! HTTP surface for the control plane (M13.1).
//!
//! Wraps the in-memory [`Enrollment`] service in a small JSON API so Agents can
//! enroll against a running control-plane service (ADR-0017 — thin, holds no
//! trust material or payload). This packet exposes enrollment; the Tunnel
//! Registry and Rendezvous endpoints follow (M13.2).

use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::accounts::{AccountId, Ledger, LedgerError};
use crate::billing::issue_token_for_payment;
use crate::enrollment::{Enrollment, JoinToken};
use crate::payment::{PaymentError, PaymentId, PaymentIntake};
use crate::registry::{TunnelInfo, TunnelRegistry};
use ct_common::{AgentId, RoutingToken, TenantId};
use ct_common::sync::MutexExt;

/// Shared enrollment state behind the HTTP handlers.
pub type SharedEnrollment = Arc<Mutex<Enrollment>>;

/// Build the enrollment HTTP router: `POST /enroll/issue`, `POST /enroll/redeem`.
pub fn enrollment_router(state: SharedEnrollment) -> Router {
    Router::new()
        .route("/enroll/issue", post(issue))
        .route("/enroll/redeem", post(redeem))
        .with_state(state)
}

#[derive(Deserialize)]
struct IssueReq {
    tenant: String,
}
#[derive(Serialize, Deserialize)]
struct IssueResp {
    token: String,
}

async fn issue(State(enr): State<SharedEnrollment>, Json(req): Json<IssueReq>) -> Json<IssueResp> {
    let token = enr.lock_safe().issue_join_token(TenantId(req.tenant));
    Json(IssueResp {
        token: hex_encode(&token.0),
    })
}

#[derive(Deserialize)]
struct RedeemReq {
    token: String,
    agent: String,
    pubkey: String,
}
#[derive(Serialize, Deserialize)]
struct RedeemResp {
    tenant: String,
}

async fn redeem(
    State(enr): State<SharedEnrollment>,
    Json(req): Json<RedeemReq>,
) -> Result<Json<RedeemResp>, (StatusCode, String)> {
    let token = hex_decode_32(&req.token)
        .ok_or((StatusCode::BAD_REQUEST, "malformed token".to_string()))?;
    let pubkey = hex_decode_32(&req.pubkey)
        .ok_or((StatusCode::BAD_REQUEST, "malformed pubkey".to_string()))?;
    let tenant = enr
        .lock_safe()
        .redeem(&JoinToken(token), AgentId(req.agent), pubkey)
        .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
    Ok(Json(RedeemResp { tenant: tenant.0 }))
}

/// Build the full control-plane router: enrollment + registry/rendezvous +
/// billing (accounts/payment/gated issuance, M15.4b) on one app, each with its
/// own shared state.
pub fn control_plane_router(
    enrollment: SharedEnrollment,
    registry: SharedRegistry,
    billing: SharedBilling,
) -> Router {
    enrollment_router(enrollment)
        .merge(registry_router(registry))
        .merge(billing_router(billing))
}

/// Shared Tunnel Registry behind the HTTP handlers.
pub type SharedRegistry = Arc<Mutex<TunnelRegistry>>;

/// Build the registry router: `POST /registry/register`,
/// `GET /registry/resolve/:token` (the Rendezvous lookup).
pub fn registry_router(state: SharedRegistry) -> Router {
    Router::new()
        .route("/registry/register", post(register_tunnel))
        .route("/registry/resolve/:token", get(resolve_tunnel))
        .with_state(state)
}

#[derive(Deserialize)]
struct RegisterReq {
    token: String,
    tenant: String,
    agent: String,
}

async fn register_tunnel(
    State(reg): State<SharedRegistry>,
    Json(req): Json<RegisterReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let token = hex_decode_32(&req.token)
        .ok_or((StatusCode::BAD_REQUEST, "malformed token".to_string()))?;
    reg.lock_safe().register(
        RoutingToken(token),
        TunnelInfo {
            tenant: TenantId(req.tenant),
            agent: AgentId(req.agent),
        },
    );
    Ok(StatusCode::OK)
}

#[derive(Serialize, Deserialize)]
struct ResolveResp {
    tenant: String,
    agent: String,
}

async fn resolve_tunnel(
    State(reg): State<SharedRegistry>,
    Path(token_hex): Path<String>,
) -> Result<Json<ResolveResp>, StatusCode> {
    let token = hex_decode_32(&token_hex).ok_or(StatusCode::BAD_REQUEST)?;
    let guard = reg.lock_safe();
    let info = guard.lookup(&RoutingToken(token)).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(ResolveResp {
        tenant: info.tenant.0.clone(),
        agent: info.agent.0.clone(),
    }))
}

/// Combined billing state: the credit [`Ledger`] and the [`PaymentIntake`] live
/// behind one lock so a handler that touches both (confirm → credit) is atomic
/// and there is no lock-ordering to get wrong.
#[derive(Default)]
pub struct BillingState {
    pub ledger: Ledger,
    pub intake: PaymentIntake,
}

/// Shared billing state behind the HTTP handlers.
pub type SharedBilling = Arc<Mutex<BillingState>>;

/// Build the billing router (M15.4): pseudonymous accounts, prepaid top-ups and
/// credit-gated token issuance.
///
/// * `POST /accounts/open` → `{account}` (a fresh pseudonymous account)
/// * `POST /payment/intent` `{account, credits}` → `{payment}`
/// * `POST /payment/confirm` `{payment}` → `{balance}` (409 if already confirmed)
/// * `POST /billing/issue` `{account, price}` → `{token}` (402 if insufficient credit)
pub fn billing_router(state: SharedBilling) -> Router {
    Router::new()
        .route("/accounts/open", post(open_account))
        .route("/payment/intent", post(create_payment_intent))
        .route("/payment/confirm", post(confirm_payment))
        .route("/billing/issue", post(buy_token))
        .with_state(state)
}

#[derive(Serialize, Deserialize)]
struct AccountResp {
    account: String,
}

async fn open_account(State(state): State<SharedBilling>) -> Json<AccountResp> {
    let account = state.lock_safe().ledger.open_account();
    Json(AccountResp {
        account: hex_encode(&account.0),
    })
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
    State(state): State<SharedBilling>,
    Json(req): Json<IntentReq>,
) -> Result<Json<IntentResp>, (StatusCode, String)> {
    let account = hex_decode_32(&req.account)
        .ok_or((StatusCode::BAD_REQUEST, "malformed account".to_string()))?;
    let id = state
        .lock_safe()
        .intake
        .create_intent(AccountId(account), req.credits);
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
    State(state): State<SharedBilling>,
    Json(req): Json<ConfirmReq>,
) -> Result<Json<BalanceResp>, (StatusCode, String)> {
    let payment = hex_decode_32(&req.payment)
        .ok_or((StatusCode::BAD_REQUEST, "malformed payment".to_string()))?;
    let mut guard = state.lock_safe();
    let BillingState { ledger, intake } = &mut *guard;
    let balance = intake
        .confirm_payment(&PaymentId(payment), ledger)
        .map_err(|e| {
            let code = match e {
                PaymentError::UnknownPayment | PaymentError::Ledger(_) => StatusCode::NOT_FOUND,
                PaymentError::AlreadyConfirmed => StatusCode::CONFLICT,
            };
            (code, e.to_string())
        })?;
    Ok(Json(BalanceResp { balance }))
}

#[derive(Deserialize)]
struct BuyReq {
    account: String,
    price: u64,
}
#[derive(Serialize, Deserialize)]
struct TokenResp {
    token: String,
}

async fn buy_token(
    State(state): State<SharedBilling>,
    Json(req): Json<BuyReq>,
) -> Result<Json<TokenResp>, (StatusCode, String)> {
    let account = hex_decode_32(&req.account)
        .ok_or((StatusCode::BAD_REQUEST, "malformed account".to_string()))?;
    let token = issue_token_for_payment(&mut state.lock_safe().ledger, &AccountId(account), req.price)
        .map_err(|e| {
            let code = match e {
                LedgerError::UnknownAccount => StatusCode::NOT_FOUND,
                // Not enough credit to pay for the token.
                LedgerError::InsufficientCredit { .. } => StatusCode::PAYMENT_REQUIRED,
                LedgerError::IdempotencyKeyReused => StatusCode::CONFLICT,
                // #604: this in-memory Ledger's own `credit()` can't actually produce
                // this (it has no i64-cast to guard against), but the variant is shared
                // with SqliteLedger's, so the match must stay exhaustive.
                LedgerError::CreditAmountTooLarge { .. } => StatusCode::BAD_REQUEST,
            };
            (code, e.to_string())
        })?;
    Ok(Json(TokenResp {
        token: hex_encode(&token.0),
    }))
}

fn hex_encode(bytes: &[u8]) -> String {
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
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn post_json(app: Router, path: &str, body: String) -> (StatusCode, Vec<u8>) {
        let resp = app
            .oneshot(
                Request::post(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
        (status, bytes)
    }

    #[tokio::test]
    async fn issue_then_redeem_binds_the_tenant() {
        let state = Arc::new(Mutex::new(Enrollment::new()));
        let app = enrollment_router(state);

        // Issue a join token.
        let (status, body) =
            post_json(app.clone(), "/enroll/issue", r#"{"tenant":"tenant-1"}"#.into()).await;
        assert_eq!(status, StatusCode::OK);
        let issued: IssueResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(issued.token.len(), 64, "32-byte token as hex");

        // Redeem it → binds the tenant.
        let redeem = format!(
            r#"{{"token":"{}","agent":"agent-1","pubkey":"{}"}}"#,
            issued.token,
            "11".repeat(32)
        );
        let (status, body) = post_json(app.clone(), "/enroll/redeem", redeem.clone()).await;
        assert_eq!(status, StatusCode::OK);
        let redeemed: RedeemResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(redeemed.tenant, "tenant-1");

        // A second redemption of the same token is rejected.
        let (status, _) = post_json(app, "/enroll/redeem", redeem).await;
        assert_eq!(status, StatusCode::CONFLICT, "single-use join token");
    }

    #[tokio::test]
    async fn register_then_resolve_tunnel() {
        let reg = Arc::new(Mutex::new(TunnelRegistry::new()));
        let app = registry_router(reg);
        let token = "44".repeat(32);

        // Register a tunnel.
        let body = format!(r#"{{"token":"{token}","tenant":"t","agent":"a"}}"#);
        let (status, _) = post_json(app.clone(), "/registry/register", body).await;
        assert_eq!(status, StatusCode::OK);

        // Resolve it.
        let resp = app
            .clone()
            .oneshot(
                Request::get(format!("/registry/resolve/{token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let r: ResolveResp = serde_json::from_slice(&bytes).unwrap();
        assert_eq!((r.tenant.as_str(), r.agent.as_str()), ("t", "a"));

        // An unknown token → 404.
        let resp = app
            .oneshot(
                Request::get(format!("/registry/resolve/{}", "55".repeat(32)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn merged_router_serves_enrollment_and_registry() {
        let enr = Arc::new(Mutex::new(Enrollment::new()));
        let reg = Arc::new(Mutex::new(TunnelRegistry::new()));
        let bill = Arc::new(Mutex::new(BillingState::default()));
        let app = control_plane_router(enr, reg, bill);

        let (s, _) = post_json(app.clone(), "/enroll/issue", r#"{"tenant":"t"}"#.into()).await;
        assert_eq!(s, StatusCode::OK, "enrollment route served");

        let body = format!(r#"{{"token":"{}","tenant":"t","agent":"a"}}"#, "66".repeat(32));
        let (s, _) = post_json(app.clone(), "/registry/register", body).await;
        assert_eq!(s, StatusCode::OK, "registry route served");

        let (s, _) = post_json(app, "/accounts/open", "{}".into()).await;
        assert_eq!(s, StatusCode::OK, "billing route served");
    }

    #[tokio::test]
    async fn redeem_unknown_token_conflicts() {
        let state = Arc::new(Mutex::new(Enrollment::new()));
        let app = enrollment_router(state);
        let redeem = format!(
            r#"{{"token":"{}","agent":"a","pubkey":"{}"}}"#,
            "22".repeat(32),
            "33".repeat(32)
        );
        let (status, _) = post_json(app, "/enroll/redeem", redeem).await;
        assert_eq!(status, StatusCode::CONFLICT, "unknown token rejected");
    }

    #[tokio::test]
    async fn billing_open_topup_then_buy_token() {
        let app = billing_router(Arc::new(Mutex::new(BillingState::default())));

        // Open a fresh pseudonymous account.
        let (s, body) = post_json(app.clone(), "/accounts/open", "{}".into()).await;
        assert_eq!(s, StatusCode::OK);
        let acct: AccountResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(acct.account.len(), 64, "32-byte account id as hex");

        // Broke: buying a token is Payment Required.
        let buy = format!(r#"{{"account":"{}","price":1}}"#, acct.account);
        let (s, _) = post_json(app.clone(), "/billing/issue", buy.clone()).await;
        assert_eq!(s, StatusCode::PAYMENT_REQUIRED, "zero balance is denied a token");

        // Create + confirm a payment top-up of 3 credits.
        let intent = format!(r#"{{"account":"{}","credits":3}}"#, acct.account);
        let (s, body) = post_json(app.clone(), "/payment/intent", intent).await;
        assert_eq!(s, StatusCode::OK);
        let pay: IntentResp = serde_json::from_slice(&body).unwrap();
        let confirm = format!(r#"{{"payment":"{}"}}"#, pay.payment);
        let (s, body) = post_json(app.clone(), "/payment/confirm", confirm.clone()).await;
        assert_eq!(s, StatusCode::OK);
        let bal: BalanceResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(bal.balance, 3, "top-up credited the account");

        // Now issuance succeeds.
        let (s, body) = post_json(app.clone(), "/billing/issue", buy).await;
        assert_eq!(s, StatusCode::OK, "funded account gets a token");
        let tok: TokenResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(tok.token.len(), 64, "32-byte routing token as hex");

        // A replayed confirmation is rejected (idempotent).
        let (s, _) = post_json(app, "/payment/confirm", confirm).await;
        assert_eq!(s, StatusCode::CONFLICT, "confirmation is single-use");
    }

    #[tokio::test]
    async fn confirming_an_unknown_payment_is_not_found() {
        let app = billing_router(Arc::new(Mutex::new(BillingState::default())));
        let confirm = format!(r#"{{"payment":"{}"}}"#, "ab".repeat(32));
        let (s, _) = post_json(app, "/payment/confirm", confirm).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "unknown payment");
    }
}
