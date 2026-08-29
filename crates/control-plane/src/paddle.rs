//! Merchant-of-Record payment integration (Paddle Billing), directed by scimbe
//! in response to the fresh-eyes review's #1 finding ("no payment pipeline
//! wired at all -- the ledger and webhook-signature verifier exist and are
//! solid, but aren't wired to any HTTP route or to each other"). A
//! merchant-of-record absorbs cross-border EU VAT/OSS registration, mandatory
//! invoicing (§14 UStG), and keeps PCI scope at the lowest tier (SAQ A) in one
//! vendor decision -- see the review's own reasoning for why this over
//! building custom billing.
//!
//! **Honest caveat, stated plainly**: this is built against Paddle Billing's
//! documented REST API v1 (`api.paddle.com`), but has not been exercised
//! against a live Paddle account (none exists yet -- creating one needs
//! scimbe's own business registration, bank details, and tax ID; that's not
//! something this session can do). Verify the exact request/response shape
//! against Paddle's current docs before the first real transaction. The
//! signature-verification scheme (`Paddle-Signature: ts=...;h1=...`) is the
//! piece I'm most confident is stable -- HMAC-over-`ts:body` is a slow-changing
//! provider convention this crate already has the Stripe-style version of
//! (`payment_provider::WebhookVerifier`); Paddle's own format differs slightly
//! (colon join, not dot; header carries both fields itself rather than two
//! separate headers), so this is its own small verifier, not a reuse.
//!
//! **Double-gated, on purpose** (absent unless configured, same convention as
//! `dns`/`edge_admin` elsewhere in this crate, PLUS a second, independent
//! switch): `CT_PADDLE_API_KEY` unset -> `/me/checkout` is mounted but `503`s.
//! `CT_CHECKOUT_ENABLED` unset/not `"true"` -> the route is 404, absent
//! entirely, even with real (or Paddle sandbox) API keys configured -- so
//! scimbe can test against a live Paddle account without it being reachable by
//! a real customer yet ("schalte das wie die Pläne noch nicht frei", his own
//! instruction). Flipping it on for real customers is a separate, later
//! decision -- this module only builds the mechanism.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::pricing::PricingConfig;
use crate::storage::SqliteLedger;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Default)]
pub struct PaddleConfig {
    pub api_key: Option<Arc<str>>,
    pub webhook_secret: Option<Arc<str>>,
    /// See this module's doc: a SEPARATE switch from `api_key` being set --
    /// must be exactly `"true"` for `/me/checkout` to be mounted at all.
    pub checkout_enabled: bool,
    /// Where Paddle should send the customer back after a successful/failed
    /// checkout -- `CT_PORTAL_BASE_URL`-derived if unset.
    pub return_url: Option<Arc<str>>,
}

impl PaddleConfig {
    pub fn from_env() -> Self {
        let get = |k: &str| std::env::var(k).ok().filter(|s| !s.is_empty()).map(Arc::from);
        Self {
            api_key: get("CT_PADDLE_API_KEY"),
            webhook_secret: get("CT_PADDLE_WEBHOOK_SECRET"),
            checkout_enabled: std::env::var("CT_CHECKOUT_ENABLED").ok().as_deref() == Some("true"),
            return_url: get("CT_PADDLE_RETURN_URL"),
        }
    }
}

fn paddle_http_client() -> reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .connect_timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new())
        })
        .clone()
}

/// Paddle's own signature scheme: `Paddle-Signature: ts=<unix_seconds>;h1=<hex_hmac>`,
/// the HMAC computed over `"<ts>:<raw_body>"`. Returns `Ok(())` only when the
/// signature matches and the timestamp is within `tolerance_secs` of `now`.
fn verify_paddle_signature(secret: &str, header: &str, body: &[u8], now: u64, tolerance_secs: u64) -> Result<(), &'static str> {
    let mut ts: Option<u64> = None;
    let mut h1: Option<&str> = None;
    for part in header.split(';') {
        let mut kv = part.splitn(2, '=');
        match (kv.next(), kv.next()) {
            (Some("ts"), Some(v)) => ts = v.parse().ok(),
            (Some("h1"), Some(v)) => h1 = Some(v),
            _ => {}
        }
    }
    let (ts, h1) = (ts.ok_or("missing ts")?, h1.ok_or("missing h1")?);
    if now.abs_diff(ts) > tolerance_secs {
        return Err("stale timestamp");
    }
    let expected_hex = h1;
    let sig = hex_decode(expected_hex).ok_or("malformed signature hex")?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| "bad secret")?;
    mac.update(ts.to_string().as_bytes());
    mac.update(b":");
    mac.update(body);
    mac.verify_slice(&sig).map_err(|_| "signature mismatch")
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()).collect()
}

#[derive(Clone)]
struct PaddleState {
    ledger: Arc<SqliteLedger>,
    verifier: crate::oidc::OidcVerifierHandle,
    config: PaddleConfig,
}

/// Always mounts `/webhooks/paddle` (its own gate is the signature, same
/// posture as the existing generic `/payment/webhook`). `/me/checkout` is
/// additionally gated behind `checkout_enabled` -- see this module's doc.
pub fn paddle_router(ledger: Arc<SqliteLedger>, verifier: crate::oidc::OidcVerifierHandle, config: PaddleConfig) -> Router {
    let mut router = Router::new().route("/webhooks/paddle", post(paddle_webhook));
    if config.checkout_enabled {
        router = router.route("/me/checkout", post(create_checkout));
    }
    router.with_state(PaddleState { ledger, verifier, config })
}

#[derive(Deserialize)]
struct CheckoutReq {
    /// One of "starter"/"medium"/"pro" -- Business is individually negotiated,
    /// not self-checkout.
    plan: String,
}

#[derive(Serialize)]
struct CheckoutResp {
    checkout_url: String,
}

async fn create_checkout(State(st): State<PaddleState>, headers: HeaderMap, Json(req): Json<CheckoutReq>) -> Result<Json<CheckoutResp>, (StatusCode, String)> {
    let Some(api_key) = st.config.api_key.clone() else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "payment provider not configured on this deployment".to_string()));
    };
    let subject = crate::service::subject_of(&st.verifier, &headers)?;
    let account = st.ledger.account_for_subject(&subject).map_err(|e| internal("create_checkout/account_for_subject", e))?;

    let pricing = PricingConfig::from_env();
    let tier = pricing.tier(&req.plan).ok_or((StatusCode::BAD_REQUEST, "unknown plan".to_string()))?;
    let Some(price_id) = &tier.paddle_price_id else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, format!("the {} plan has no Paddle price configured yet", req.plan)));
    };
    // The credit bundle this plan grants monthly -- what confirm_payment
    // credits once Paddle's webhook reports the subscription active. `0` (not
    // configured) is a real, valid state (a plan sold on relay/AI access
    // alone), not an error.
    let credits = tier.credits.unwrap_or(0) as u64;
    let intent = st.ledger.create_intent(&account, credits).map_err(|e| internal("create_checkout/create_intent", e))?;

    let client = paddle_http_client();
    let body = serde_json::json!({
        "items": [{ "price_id": price_id, "quantity": 1 }],
        "custom_data": { "payment_id": hex_encode(&intent.0), "subject": subject, "plan": req.plan },
    });
    let resp = client
        .post("https://api.paddle.com/transactions")
        .header("authorization", format!("Bearer {api_key}"))
        .json(&body)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Paddle request failed: {e}")))?;
    if !resp.status().is_success() {
        return Err((StatusCode::BAD_GATEWAY, format!("Paddle returned {}", resp.status())));
    }
    let payload: serde_json::Value = resp.json().await.map_err(|e| (StatusCode::BAD_GATEWAY, format!("Paddle returned an unparseable response: {e}")))?;
    let checkout_url = payload
        .get("data")
        .and_then(|d| d.get("checkout"))
        .and_then(|c| c.get("url"))
        .and_then(|u| u.as_str())
        .ok_or((StatusCode::BAD_GATEWAY, "Paddle response carried no checkout URL".to_string()))?
        .to_string();

    Ok(Json(CheckoutResp { checkout_url }))
}

fn internal(context: &str, e: impl std::fmt::Display) -> (StatusCode, String) {
    eprintln!("ct-cp paddle: {context}: {e}");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex_decode(s)?;
    <[u8; 32]>::try_from(bytes).ok()
}

/// `POST /webhooks/paddle`: Paddle's real webhook wire format (not the
/// internal `{payment,status}` placeholder shape `/payment/webhook` uses --
/// see this module's doc). Credits the ledger AND, on a subscription-activated
/// event, sets the account's `plan` (the same lever `/admin-ui/accounts/
/// :subject/plan` uses manually today) so `ai_usage`'s Premium-AI gate picks
/// it up with zero further code once a real subscription exists.
async fn paddle_webhook(State(st): State<PaddleState>, headers: HeaderMap, body: Bytes) -> Result<StatusCode, (StatusCode, String)> {
    let Some(secret) = &st.config.webhook_secret else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "payment provider not configured on this deployment".to_string()));
    };
    let sig_header = headers.get("paddle-signature").and_then(|v| v.to_str().ok()).ok_or((StatusCode::BAD_REQUEST, "missing Paddle-Signature".to_string()))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    verify_paddle_signature(secret, sig_header, &body, now, 300).map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;

    let event: serde_json::Value = serde_json::from_slice(&body).map_err(|_| (StatusCode::BAD_REQUEST, "malformed event body".to_string()))?;
    let event_type = event.get("event_type").and_then(|v| v.as_str()).unwrap_or("");
    let custom_data = event.get("data").and_then(|d| d.get("custom_data"));
    let payment_id_hex = custom_data.and_then(|c| c.get("payment_id")).and_then(|v| v.as_str());

    match event_type {
        "transaction.completed" => {
            let Some(payment_id_hex) = payment_id_hex else {
                // A transaction we didn't originate via create_checkout (e.g.
                // created directly in the Paddle dashboard) -- nothing to
                // reconcile against; ack so Paddle doesn't retry forever.
                return Ok(StatusCode::OK);
            };
            let payment = hex_decode_32(payment_id_hex).ok_or((StatusCode::BAD_REQUEST, "malformed payment id".to_string()))?;
            match st.ledger.confirm_payment(&crate::payment::PaymentId(payment)) {
                Ok(_) => {}
                Err(crate::storage::PaymentOpError::Payment(crate::payment::PaymentError::AlreadyConfirmed)) => {}
                Err(crate::storage::PaymentOpError::Payment(crate::payment::PaymentError::UnknownPayment)) => {
                    return Err((StatusCode::NOT_FOUND, "unknown payment".to_string()));
                }
                Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
            }
            if let (Some(subject), Some(plan)) = (
                custom_data.and_then(|c| c.get("subject")).and_then(|v| v.as_str()),
                custom_data.and_then(|c| c.get("plan")).and_then(|v| v.as_str()),
            ) {
                if let Ok(account) = st.ledger.account_for_subject(subject) {
                    let _ = st.ledger.set_plan(&account, Some(plan));
                }
            }
        }
        // Cancellation/refund handling is real, separate follow-up scope --
        // acked here (so Paddle doesn't retry) but not yet acted on. Flagged
        // plainly rather than silently pretending it's handled.
        _ => {}
    }
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_round_trips_and_is_verifiable() {
        let secret = "whsec_test";
        let body = br#"{"event_type":"transaction.completed"}"#;
        let ts = 1_700_000_000u64;
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(ts.to_string().as_bytes());
        mac.update(b":");
        mac.update(body);
        let sig = hex_encode(&mac.finalize().into_bytes());
        let header = format!("ts={ts};h1={sig}");
        assert!(verify_paddle_signature(secret, &header, body, ts, 300).is_ok());
    }

    #[test]
    fn tampered_body_is_rejected() {
        let secret = "whsec_test";
        let ts = 1_700_000_000u64;
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(ts.to_string().as_bytes());
        mac.update(b":");
        mac.update(b"original");
        let sig = hex_encode(&mac.finalize().into_bytes());
        let header = format!("ts={ts};h1={sig}");
        assert!(verify_paddle_signature(secret, &header, b"tampered", ts, 300).is_err());
    }

    #[test]
    fn stale_timestamp_is_rejected() {
        let secret = "whsec_test";
        let ts = 1_700_000_000u64;
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(ts.to_string().as_bytes());
        mac.update(b":");
        mac.update(b"body");
        let sig = hex_encode(&mac.finalize().into_bytes());
        let header = format!("ts={ts};h1={sig}");
        assert!(verify_paddle_signature(secret, &header, b"body", ts + 600, 300).is_err());
    }

    #[test]
    fn malformed_header_is_rejected_not_panicking() {
        assert!(verify_paddle_signature("s", "garbage", b"body", 0, 300).is_err());
        assert!(verify_paddle_signature("s", "ts=abc;h1=zz", b"body", 0, 300).is_err());
    }

    #[tokio::test]
    async fn checkout_route_is_absent_when_not_enabled() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let router = paddle_router(ledger, crate::oidc::OidcVerifierHandle::empty(), PaddleConfig { checkout_enabled: false, ..Default::default() });
        let resp = router.oneshot(Request::post("/me/checkout").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "absent, not just unauthenticated -- checkout_enabled gates mounting itself");
    }

    #[tokio::test]
    async fn webhook_is_503_without_a_configured_secret() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let router = paddle_router(ledger, crate::oidc::OidcVerifierHandle::empty(), PaddleConfig::default());
        let resp = router.oneshot(Request::post("/webhooks/paddle").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
