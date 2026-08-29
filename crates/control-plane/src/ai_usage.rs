//! AI-usage-as-a-metered-service (`/me/ai/*`) -- the metering/billing/cap-
//! enforcement layer `pricing.rs`'s own doc flagged as missing ("KI-Nutzung ist
//! eine neue Produktfläche... es gibt noch keinen 'KI-Dienst als abrechenbaren
//! Service' im Code"). This module does NOT include an actual GPU inference
//! server -- that is real infrastructure scimbe needs to stand up separately
//! (see the confidential pricing model §1.1, a self-hosted GPU box). What this
//! module gives him the moment that box exists: a real, deployable proxy that
//! meters and caps against it with zero further code changes -- just set
//! `CT_AI_STANDARD_BACKEND_URL`.
//!
//! Absent unless configured (this crate's established convention, cf. `dns`/
//! `edge_admin`): with no backend URL set, `/me/ai/chat`/`/me/ai/transcribe`
//! answer `503` with a clear "not configured" message rather than 404ing or
//! silently doing nothing.
//!
//! Two independently configurable backends, matching the pricing model's two
//! tiers: `CT_AI_STANDARD_BACKEND_URL` (self-hosted, every plan including Free)
//! and `CT_AI_PREMIUM_BACKEND_URL` (Mistral-compatible proxy, Medium+ plans only
//! -- enforced here in code via `SqliteLedger::plan_for`, not just documented).
//!
//! **Known, accepted MVP limitations, stated plainly rather than silently
//! shipped as if exact:**
//! - Transcription duration is CLIENT-REPORTED (`AiTranscribeReq::duration_seconds`),
//!   not measured server-side from the actual audio. A client could under-report
//!   to dodge metering. Real fix: measure server-side (from the backend's own
//!   response, or a local audio-duration probe) -- not done here.
//! - Premium-tier per-request cost isn't known from Mistral's real billing here;
//!   it's approximated as the Standard rate plus the configured margin
//!   (`CT_PRICING_PREMIUM_AI_MARGIN_PERCENT`). Reconciling against Mistral's own
//!   invoice is a real follow-up.
//! - `max_tokens` is server-side bounded (not just passed through) specifically
//!   to cap worst-case overdraft: exact cost is only known AFTER the backend
//!   responds (token count is not knowable in advance), so admission is a
//!   pre-flight balance/cap check against the bounded worst case, and the debit
//!   itself happens post-call against the actual usage reported.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::accounts::LedgerError;
use crate::pricing::PricingConfig;
use crate::storage::{LedgerOpError, SqliteLedger};

/// Which plans unlock Premium-KI access, per the pricing model's own table
/// ("Zugang ab Medium-Plan"). Plain strings, matching how `plan` is stored
/// (admin-settable today, see `storage.rs`'s `plan` column doc) -- not an enum,
/// since the set of plan names is business config, not a compile-time contract.
const PREMIUM_AI_PLANS: &[&str] = &["medium", "pro", "business"];

/// Server-side ceiling on `max_tokens`, applied regardless of what the caller
/// requests -- see this module's doc on why worst-case cost must be bounded
/// before the call, not just billed accurately after it.
const MAX_TOKENS_CEILING: u32 = 2048;
const DEFAULT_MAX_TOKENS: u32 = 512;

#[derive(Clone, Default)]
pub struct AiBackendConfig {
    pub standard_url: Option<Arc<str>>,
    pub standard_key: Option<Arc<str>>,
    pub premium_url: Option<Arc<str>>,
    pub premium_key: Option<Arc<str>>,
}

impl AiBackendConfig {
    pub fn from_env() -> Self {
        let get = |k: &str| std::env::var(k).ok().filter(|s| !s.is_empty()).map(Arc::from);
        Self {
            standard_url: get("CT_AI_STANDARD_BACKEND_URL"),
            standard_key: get("CT_AI_STANDARD_BACKEND_KEY"),
            premium_url: get("CT_AI_PREMIUM_BACKEND_URL"),
            premium_key: get("CT_AI_PREMIUM_BACKEND_KEY"),
        }
    }
}

fn ai_http_client() -> reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .connect_timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new())
        })
        .clone()
}

#[derive(Clone)]
struct AiUsageState {
    ledger: Arc<SqliteLedger>,
    verifier: crate::oidc::OidcVerifierHandle,
    backends: AiBackendConfig,
}

/// Build the `/me/ai/*` router. Always mounted (the individual routes fail soft
/// with `503` when their specific backend isn't configured, matching this
/// crate's convention for `/me/*` overall -- see `#328`'s reasoning on
/// `authed_billing_router`).
pub fn ai_usage_router(ledger: Arc<SqliteLedger>, verifier: crate::oidc::OidcVerifierHandle, backends: AiBackendConfig) -> Router {
    Router::new()
        .route("/me/ai/chat", post(ai_chat))
        .route("/me/ai/transcribe", post(ai_transcribe))
        .route("/me/ai/usage", get(ai_usage))
        .with_state(AiUsageState { ledger, verifier, backends })
}

fn internal(context: &str, e: impl std::fmt::Display) -> (StatusCode, String) {
    eprintln!("ct-cp ai_usage: {context}: {e}");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
}

fn ledger_err_status(e: &LedgerOpError) -> StatusCode {
    match e {
        LedgerOpError::Ledger(LedgerError::InsufficientCredit { .. }) => StatusCode::PAYMENT_REQUIRED,
        LedgerOpError::Ledger(LedgerError::UnknownAccount) => StatusCode::NOT_FOUND,
        LedgerOpError::Ledger(LedgerError::AccountBlocked) => StatusCode::FORBIDDEN,
        LedgerOpError::Ledger(LedgerError::FreeAiCapExceeded) => StatusCode::FORBIDDEN,
        // Unreachable via the AI-debit calls this module makes -- kept for
        // match exhaustiveness, same reasoning as service.rs's own such arms.
        LedgerOpError::Ledger(LedgerError::IdempotencyKeyReused) => StatusCode::INTERNAL_SERVER_ERROR,
        LedgerOpError::Ledger(LedgerError::CreditAmountTooLarge { .. }) => StatusCode::INTERNAL_SERVER_ERROR,
        LedgerOpError::Ledger(LedgerError::DeviceLimitExceeded) => StatusCode::INTERNAL_SERVER_ERROR,
        LedgerOpError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[derive(Deserialize)]
struct AiChatReq {
    /// `"standard"` (self-hosted, every plan) or `"premium"` (Mistral proxy,
    /// Medium+ plans only -- checked server-side against the caller's plan).
    #[serde(default = "default_model")]
    model: String,
    /// OpenAI-compatible message array, passed through as-is.
    messages: Vec<serde_json::Value>,
    #[serde(default)]
    max_tokens: Option<u32>,
}

fn default_model() -> String {
    "standard".to_string()
}

#[derive(Serialize)]
struct AiChatResp {
    /// The backend's own response, passed through as-is (OpenAI-compatible shape).
    upstream: serde_json::Value,
    credits_spent: u64,
}

async fn ai_chat(State(st): State<AiUsageState>, headers: HeaderMap, Json(req): Json<AiChatReq>) -> Result<Json<AiChatResp>, (StatusCode, String)> {
    let subject = crate::service::subject_of(&st.verifier, &headers)?;
    let is_premium = req.model == "premium";

    let (backend_url, backend_key) =
        if is_premium { (st.backends.premium_url.clone(), st.backends.premium_key.clone()) } else { (st.backends.standard_url.clone(), st.backends.standard_key.clone()) };
    let Some(backend_url) = backend_url else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, format!("{} AI backend not configured on this deployment", if is_premium { "Premium" } else { "Standard" })));
    };

    let account = st.ledger.account_for_subject(&subject).map_err(|e| internal("ai_chat/account_for_subject", e))?;

    if is_premium {
        let plan = st.ledger.plan_for(&account).map_err(|e| internal("ai_chat/plan_for", e))?;
        if !plan.as_deref().is_some_and(|p| PREMIUM_AI_PLANS.contains(&p)) {
            return Err((StatusCode::FORBIDDEN, "Premium AI requires the Medium plan or higher".to_string()));
        }
    }

    let bounded_max_tokens = req.max_tokens.unwrap_or(DEFAULT_MAX_TOKENS).min(MAX_TOKENS_CEILING);
    let pricing = PricingConfig::from_env();
    let standard_rate = pricing.standard_ai_credits_per_1k_tokens.unwrap_or(0) as u64;
    let rate = if is_premium {
        let margin = pricing.premium_ai_margin_percent.unwrap_or(0) as u64;
        standard_rate + (standard_rate * margin / 100)
    } else {
        standard_rate
    };
    // Pre-flight admission against the worst-case cost (see this module's doc
    // on why exact cost is only known post-call): a READ-ONLY peek, refusing
    // before spending a real backend call on an account that's already broke or
    // capped. The single real debit (cap increment + balance decrement
    // together, exactly once) happens after the call, against the true cost.
    let worst_case_cost = (bounded_max_tokens as u64 * rate) / 1000;
    let free_cap = if is_premium { None } else { pricing.free_ai_request_cap };
    let snapshot = st.ledger.ai_usage_for(&account).map_err(|e| internal("ai_chat/ai_usage_for", e))?.ok_or((StatusCode::NOT_FOUND, "unknown account".to_string()))?;
    if snapshot.plan.is_none() {
        if let Some(cap) = free_cap {
            if snapshot.free_requests_used >= cap {
                return Err((StatusCode::FORBIDDEN, LedgerError::FreeAiCapExceeded.to_string()));
            }
        }
    }
    if snapshot.balance < worst_case_cost {
        return Err((StatusCode::PAYMENT_REQUIRED, LedgerError::InsufficientCredit { balance: snapshot.balance, requested: worst_case_cost }.to_string()));
    }

    let client = ai_http_client();
    let mut body = serde_json::json!({ "messages": req.messages, "max_tokens": bounded_max_tokens });
    if let Some(obj) = body.as_object_mut() {
        obj.insert("stream".to_string(), serde_json::Value::Bool(false));
    }
    let mut rb = client.post(format!("{backend_url}/v1/chat/completions")).json(&body);
    if let Some(key) = &backend_key {
        rb = rb.header("authorization", format!("Bearer {key}"));
    }
    let resp = rb.send().await.map_err(|e| (StatusCode::BAD_GATEWAY, format!("AI backend request failed: {e}")))?;
    if !resp.status().is_success() {
        return Err((StatusCode::BAD_GATEWAY, format!("AI backend returned {}", resp.status())));
    }
    let upstream: serde_json::Value = resp.json().await.map_err(|e| (StatusCode::BAD_GATEWAY, format!("AI backend returned an unparseable response: {e}")))?;

    let total_tokens = upstream.get("usage").and_then(|u| u.get("total_tokens")).and_then(|v| v.as_u64()).unwrap_or(bounded_max_tokens as u64);
    let credits_spent = (total_tokens * rate) / 1000;
    // The one real debit for this request: decrements the balance by the true
    // cost AND (for a Free-tier account) increments the free-request counter,
    // atomically, exactly once. The pre-flight peek above never mutates state,
    // so there is no double-count regardless of what the backend actually used.
    st.ledger.debit_ai_chat(&account, credits_spent, free_cap).map_err(|e| (ledger_err_status(&e), e.to_string()))?;

    Ok(Json(AiChatResp { upstream, credits_spent }))
}

#[derive(Deserialize)]
struct AiTranscribeReq {
    /// Base64-encoded audio bytes, passed through to the backend.
    audio_base64: String,
    /// Client-reported duration -- see this module's doc for why this is a
    /// known, accepted MVP limitation, not measured server-side.
    duration_seconds: u32,
}

#[derive(Serialize)]
struct AiTranscribeResp {
    upstream: serde_json::Value,
    credits_spent: u64,
}

async fn ai_transcribe(State(st): State<AiUsageState>, headers: HeaderMap, Json(req): Json<AiTranscribeReq>) -> Result<Json<AiTranscribeResp>, (StatusCode, String)> {
    let subject = crate::service::subject_of(&st.verifier, &headers)?;
    let Some(backend_url) = st.backends.standard_url.clone() else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "Standard AI backend not configured on this deployment".to_string()));
    };
    let account = st.ledger.account_for_subject(&subject).map_err(|e| internal("ai_transcribe/account_for_subject", e))?;

    let pricing = PricingConfig::from_env();
    let rate_per_minute = pricing.standard_stt_credits_per_minute.unwrap_or(0) as u64;
    let credits_cost = (req.duration_seconds as u64 * rate_per_minute) / 60;

    let client = ai_http_client();
    let body = serde_json::json!({ "audio_base64": req.audio_base64 });
    let mut rb = client.post(format!("{backend_url}/v1/audio/transcriptions")).json(&body);
    if let Some(key) = &st.backends.standard_key {
        rb = rb.header("authorization", format!("Bearer {key}"));
    }
    // Debit BEFORE the call this time: unlike chat, the cost is already known
    // in full up front (duration is client-reported, not backend-dependent),
    // so there is no "worst-case then true-up" split needed.
    st.ledger
        .debit_ai_transcribe(&account, credits_cost, req.duration_seconds, pricing.free_ai_seconds_cap)
        .map_err(|e| (ledger_err_status(&e), e.to_string()))?;

    let resp = rb.send().await.map_err(|e| (StatusCode::BAD_GATEWAY, format!("AI backend request failed: {e}")))?;
    if !resp.status().is_success() {
        return Err((StatusCode::BAD_GATEWAY, format!("AI backend returned {}", resp.status())));
    }
    let upstream: serde_json::Value = resp.json().await.map_err(|e| (StatusCode::BAD_GATEWAY, format!("AI backend returned an unparseable response: {e}")))?;

    Ok(Json(AiTranscribeResp { upstream, credits_spent: credits_cost }))
}

#[derive(Serialize)]
struct AiUsageResp {
    balance: u64,
    plan: Option<String>,
    free_requests_used: u32,
    free_requests_cap: Option<u32>,
    free_seconds_used: u32,
    free_seconds_cap: Option<u32>,
}

/// `GET /me/ai/usage`: the customer-facing "how much have I used against my
/// caps" view -- the review's own finding ("Kunden sehen ihre Nutzung nicht
/// gegen ihre Caps") this endpoint directly answers.
async fn ai_usage(State(st): State<AiUsageState>, headers: HeaderMap) -> Result<Json<AiUsageResp>, (StatusCode, String)> {
    let subject = crate::service::subject_of(&st.verifier, &headers)?;
    let account = st.ledger.account_for_subject(&subject).map_err(|e| internal("ai_usage/account_for_subject", e))?;
    let snapshot = st.ledger.ai_usage_for(&account).map_err(|e| internal("ai_usage/ai_usage_for", e))?.ok_or((StatusCode::NOT_FOUND, "unknown account".to_string()))?;
    let pricing = PricingConfig::from_env();
    Ok(Json(AiUsageResp {
        balance: snapshot.balance,
        plan: snapshot.plan,
        free_requests_used: snapshot.free_requests_used,
        free_requests_cap: pricing.free_ai_request_cap,
        free_seconds_used: snapshot.free_seconds_used,
        free_seconds_cap: pricing.free_ai_seconds_cap,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::{OidcVerifier, OidcVerifierHandle};
    use crate::storage::SqliteLedger;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::ServiceExt;

    fn jwt_for(secret: &[u8], issuer: &str, sub: &str) -> String {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let claims = serde_json::json!({ "sub": sub, "iss": issuer, "exp": now + 3600 });
        encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(secret)).unwrap()
    }

    fn test_app(ledger: Arc<SqliteLedger>, backends: AiBackendConfig) -> (Router, Vec<u8>, String) {
        let secret = b"realm-secret".to_vec();
        let issuer = "https://kc/realms/ct".to_string();
        let oidc = Arc::new(OidcVerifier::from_hs_secret(&secret, &issuer));
        let router = ai_usage_router(ledger, OidcVerifierHandle::from(Some(oidc)), backends);
        (router, secret, issuer)
    }

    #[tokio::test]
    async fn ai_chat_is_503_without_a_configured_backend() {
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let (app, secret, issuer) = test_app(ledger, AiBackendConfig::default());
        let jwt = jwt_for(&secret, &issuer, "no-backend-user");
        let resp = app
            .oneshot(
                Request::post("/me/ai/chat")
                    .header("authorization", format!("Bearer {jwt}"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({"messages": []}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn premium_model_is_refused_without_a_medium_plus_plan() {
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let backends = AiBackendConfig { premium_url: Some("http://127.0.0.1:1".into()), ..Default::default() };
        let (app, secret, issuer) = test_app(ledger, backends);
        let jwt = jwt_for(&secret, &issuer, "free-tier-user");
        let resp = app
            .oneshot(
                Request::post("/me/ai/chat")
                    .header("authorization", format!("Bearer {jwt}"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({"model": "premium", "messages": []}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn free_tier_request_cap_refuses_the_next_request_once_reached() {
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let account = ledger.account_for_subject("cap-test-user").unwrap();
        ledger.credit(&account, 1000).unwrap();
        // Cap already at 1/1 for this fingerprint-free-tier account.
        ledger.debit_ai_chat(&account, 5, Some(1)).unwrap();
        let err = ledger.debit_ai_chat(&account, 5, Some(1)).expect_err("cap already reached");
        assert!(matches!(err, LedgerOpError::Ledger(LedgerError::FreeAiCapExceeded)));
    }

    #[tokio::test]
    async fn a_paid_plan_is_never_subject_to_the_free_cap() {
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let account = ledger.account_for_subject("paid-user").unwrap();
        ledger.credit(&account, 1000).unwrap();
        ledger.set_plan(&account, Some("pro")).unwrap();
        // Cap of 1, but this account has a plan -- both calls succeed.
        ledger.debit_ai_chat(&account, 5, Some(1)).unwrap();
        ledger.debit_ai_chat(&account, 5, Some(1)).unwrap();
    }

    #[tokio::test]
    async fn ai_usage_reports_balance_plan_and_free_tier_counters() {
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let account = ledger.account_for_subject("usage-view-user").unwrap();
        ledger.credit(&account, 500).unwrap();
        ledger.debit_ai_chat(&account, 50, Some(20)).unwrap();
        let (app, secret, issuer) = test_app(ledger, AiBackendConfig::default());
        let jwt = jwt_for(&secret, &issuer, "usage-view-user");
        let resp = app.oneshot(Request::get("/me/ai/usage").header("authorization", format!("Bearer {jwt}")).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["balance"], 450);
        assert_eq!(v["free_requests_used"], 1);
        assert_eq!(v["plan"], serde_json::Value::Null);
    }
}
