//! Dead-man alerts (#777): a tunnel owner registers a webhook per tunnel; a
//! background loop asks the edge once a minute whether the tunnel is up and POSTs a
//! signed `tunnel.down` once it has been unreachable for the owner's threshold, then a
//! `tunnel.up` when it returns. No new notification infrastructure: the receiver is
//! whatever the owner already runs (a pager bridge, a chat hook, a script).
//!
//! # Webhook contract
//!
//! Every delivery is `POST <webhook_url>` with
//!
//! * `Content-Type: application/json`
//! * `X-CT-Timestamp: <unix seconds>` -- when the request was signed/sent
//! * `X-CT-Signature: sha256=<hex>` -- HMAC-SHA256, keyed with the alert's secret
//!   exactly as shown once in the portal (its ASCII bytes), over the ASCII string
//!   `"<X-CT-Timestamp>.<raw request body>"` -- the same `"<timestamp>.<body>"`
//!   convention [`crate::payment_provider::WebhookVerifier`] verifies inbound, so a
//!   receiver can reuse any Stripe-style verifier.
//!
//! and the JSON body
//!
//! ```json
//! {
//!   "event": "tunnel.down" | "tunnel.up" | "tunnel.test",
//!   "tunnel_id": "<portal tunnel id>",
//!   "name": "<tunnel display name>",
//!   "since": <unix seconds the current state began: outage start for down, recovery for up>,
//!   "threshold_secs": <the alert's configured threshold>,
//!   "sent_at": <unix seconds, equals X-CT-Timestamp>
//! }
//! ```
//!
//! A receiver should recompute the HMAC over `"<X-CT-Timestamp>.<body>"`, compare it
//! constant-time against the header (strip the `sha256=` prefix), and reject timestamps
//! outside a few minutes of its own clock. Any 2xx acknowledges the delivery; anything
//! else (or no answer within 5 s) is retried twice more inside the same tick with 2 s /
//! 8 s backoff, then logged as `failed` on the tunnel card. The "Test" button sends a
//! single-attempt `tunnel.test` with the same headers.
//!
//! # Semantics
//!
//! `up` = the edge's `GET /admin/tunnel-status/:token` reports `connected` OR its
//! `GET /internal/tunnel/history/:token` reports an `open` session. If the edge cannot
//! be asked at all (no `CT_CP_EDGE_ADMIN_URL`, timeout, error) the alert is simply not
//! evaluated that tick -- an unreachable edge is never reported as a down tunnel. The
//! pure decision is [`next_transition`]; `down` fires once, only after the tunnel has
//! been unreachable for at least `threshold_secs` measured from when it was last seen
//! up (or from the alert's creation if it never was), and `up` fires once on recovery.
//! Per owner, at most [`MAX_DELIVERIES_PER_HOUR`] deliveries actually go out per hour;
//! beyond that an alert is left un-transitioned (so it catches up once the window
//! frees) and a single `skipped` row is logged. Neither the secret nor the webhook
//! URL's query string ever reaches a log line or a delivery-log row.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::{Deserialize, Serialize};

use crate::audit_log::SqliteAuditLog;
use crate::payment_provider::WebhookVerifier;
use crate::portal::{escape, SessionClaims};
use crate::storage::{AlertDelivery, AlertRow, AlertUpsert, SqliteTunnelStore, TunnelAlert};

/// How often the loop evaluates every enabled alert.
pub const ALERT_TICK: Duration = Duration::from_secs(60);
/// Per-owner delivery budget (deliveries that actually went out, `ok` or `failed`,
/// across all of the owner's alerts) per rolling hour.
pub const MAX_DELIVERIES_PER_HOUR: i64 = 20;
/// Per-attempt HTTP timeout for a webhook delivery.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);
/// Attempts per delivery inside one tick (the loop), and the waits between them.
const LOOP_ATTEMPTS: usize = 3;
const BACKOFF: [Duration; 2] = [Duration::from_secs(2), Duration::from_secs(8)];
/// Threshold bounds as the portal form accepts them: 1 minute .. 7 days.
const MIN_THRESHOLD_MINUTES: i64 = 1;
const MAX_THRESHOLD_MINUTES: i64 = 7 * 24 * 60;
/// Delivery rows the tunnel card shows.
const CARD_DELIVERIES: u32 = 5;
const RATE_LIMIT_DETAIL: &str = "rate limit: at most 20 deliveries per hour per account";

/// What a delivery announces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertEvent {
    Down,
    Up,
    Test,
}

impl AlertEvent {
    /// The `event` field / delivery-log value.
    pub fn wire(self) -> &'static str {
        match self {
            AlertEvent::Down => "tunnel.down",
            AlertEvent::Up => "tunnel.up",
            AlertEvent::Test => "tunnel.test",
        }
    }
}

/// The pure decision of one evaluation. `state` is the alert's persisted state
/// (`"unknown"` | `"up"` | `"down"`), `up` the edge's answer this tick, `since` the
/// reference the outage is measured from (the last time the tunnel was seen up, or the
/// alert's creation if never), `now`/`threshold_secs` unix seconds.
///
/// * down, not yet in `down`, and `now - since >= threshold` -> `Down`, exactly once
///   (the caller then persists `"down"`, after which this returns `None` while down);
/// * down but under the threshold -> `None` (flap suppression, no state change);
/// * up while in `down` -> `Up`, exactly once;
/// * up otherwise -> `None`.
pub fn next_transition(state: &str, up: bool, since: i64, now: i64, threshold_secs: i64) -> Option<AlertEvent> {
    match (up, state) {
        (true, "down") => Some(AlertEvent::Up),
        (true, _) | (false, "down") => None,
        (false, _) => (now.saturating_sub(since) >= threshold_secs).then_some(AlertEvent::Down),
    }
}

/// The JSON body of one delivery (see the module doc).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlertPayload {
    pub event: String,
    pub tunnel_id: String,
    pub name: String,
    pub since: i64,
    pub threshold_secs: i64,
    pub sent_at: i64,
}

impl AlertPayload {
    fn new(event: AlertEvent, row: &AlertRow, since: i64, sent_at: i64) -> Self {
        Self {
            event: event.wire().to_string(),
            tunnel_id: row.alert.tunnel_id.clone(),
            name: row.name.clone(),
            since,
            threshold_secs: row.alert.threshold_secs,
            sent_at,
        }
    }
}

/// The `X-CT-Signature` header value for `body` sent at `ts`: `sha256=<hex HMAC over
/// "<ts>.<body>">`, keyed with the secret's own bytes as shown to the owner.
pub fn signature_header(secret: &str, ts: u64, body: &[u8]) -> String {
    format!("sha256={}", WebhookVerifier::new(secret.as_bytes(), 0).sign(ts, body))
}

/// How one delivery went; `detail` is safe for the delivery log (no URL, no secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryOutcome {
    pub ok: bool,
    pub detail: String,
}

impl DeliveryOutcome {
    fn status(&self) -> &'static str {
        if self.ok {
            "ok"
        } else {
            "failed"
        }
    }
}

/// A `reqwest::Error`'s `Display` embeds the request URL (query string included), so it
/// must never reach a log row -- classify instead.
fn describe_error(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connection failed"
    } else if e.is_redirect() {
        "redirect refused"
    } else {
        "request failed"
    }
}

/// The outbound webhook client: 5 s per attempt, and NO redirect following -- a
/// redirect would let an owner-supplied URL bounce this process at an address the
/// URL validation never saw.
pub(crate) fn delivery_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(DELIVERY_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("ct-control-plane-alerts/1")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// POST `payload` to `url`, signed with `secret`, up to `attempts` times with
/// [`BACKOFF`] between attempts. The signed timestamp is `payload.sent_at`.
pub(crate) async fn deliver(
    http: &reqwest::Client,
    url: &str,
    secret: &str,
    payload: &AlertPayload,
    attempts: usize,
) -> DeliveryOutcome {
    let body = match serde_json::to_vec(payload) {
        Ok(b) => b,
        Err(_) => {
            return DeliveryOutcome {
                ok: false,
                detail: "payload serialization failed".to_string(),
            }
        }
    };
    let ts = u64::try_from(payload.sent_at).unwrap_or(0);
    let signature = signature_header(secret, ts, &body);
    let mut last = String::new();
    for attempt in 0..attempts.max(1) {
        if attempt > 0 {
            tokio::time::sleep(BACKOFF[(attempt - 1).min(BACKOFF.len() - 1)]).await;
        }
        let sent = http
            .post(url)
            .header(header::CONTENT_TYPE, "application/json")
            .header("X-CT-Timestamp", ts.to_string())
            .header("X-CT-Signature", &signature)
            .timeout(DELIVERY_TIMEOUT)
            .body(body.clone())
            .send()
            .await;
        match sent {
            Ok(resp) if resp.status().is_success() => {
                return DeliveryOutcome {
                    ok: true,
                    detail: format!("HTTP {} (attempt {})", resp.status().as_u16(), attempt + 1),
                }
            }
            Ok(resp) => last = format!("HTTP {}", resp.status().as_u16()),
            Err(e) => last = describe_error(&e).to_string(),
        }
    }
    DeliveryOutcome {
        ok: false,
        detail: format!("{last} after {} attempt(s)", attempts.max(1)),
    }
}

/// The edge-admin lookups the loop needs, mirroring `portal_api`'s
/// `edge_tunnel_status`/`edge_tunnel_history` (same routes, same admin-token header,
/// same 2 s fail-open timeout) without depending on that module's private state.
pub(crate) struct EdgeProbe {
    base: String,
    token: String,
    http: reqwest::Client,
}

#[derive(Deserialize)]
struct EdgeStatusResp {
    connected: bool,
}

#[derive(Deserialize)]
struct EdgeHistoryResp {
    #[serde(default)]
    open: bool,
}

impl EdgeProbe {
    pub(crate) fn new(base_url: &str, token: &str) -> Self {
        Self {
            base: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str, query: &[(&str, usize)]) -> Option<T> {
        let resp = self
            .http
            .get(format!("{}{path}", self.base))
            .query(query)
            .header("x-ct-admin-token", &self.token)
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.json::<T>().await.ok()
    }

    /// `Some(up)` when the edge answered at least one of the two lookups; `None` when it
    /// could be asked neither way (never treated as "down" by the caller).
    pub(crate) async fn tunnel_up(&self, routing_token_hex: &str) -> Option<bool> {
        let status = self.get_json::<EdgeStatusResp>(&format!("/admin/tunnel-status/{routing_token_hex}"), &[]).await;
        let history = self
            .get_json::<EdgeHistoryResp>(&format!("/internal/tunnel/history/{routing_token_hex}"), &[("limit", 1)])
            .await;
        match (status, history) {
            (None, None) => None,
            (s, h) => Some(s.map(|s| s.connected).unwrap_or(false) || h.map(|h| h.open).unwrap_or(false)),
        }
    }
}

/// The same `CT_CP_EDGE_ADMIN_URL`/`CT_CP_EDGE_ADMIN_TOKEN` pair `service.rs` wires
/// into the portal -- read here too so `main.rs` can spawn the loop without threading
/// the router's internal config out.
pub fn edge_admin_from_env() -> Option<(String, String)> {
    let url = std::env::var("CT_CP_EDGE_ADMIN_URL").ok().filter(|s| !s.is_empty())?;
    let token = std::env::var("CT_CP_EDGE_ADMIN_TOKEN").ok().filter(|s| !s.is_empty())?;
    Some((url, token))
}

/// What [`run_alert_loop`] needs from `main.rs`.
pub struct AlertLoopConfig {
    /// The control-plane SQLite path; the loop opens its own [`SqliteTunnelStore`] on
    /// it, same as every other store shares that one file.
    pub db_path: String,
    /// `(base_url, admin_token)` of the edge admin API; `None` means every alert is
    /// left unevaluated (logged once at start), never reported down.
    pub edge_admin: Option<(String, String)>,
}

/// Run the alert loop until `shutdown` turns `true` (or its sender goes away). Spawned
/// once from `main.rs`; every tick is [`tick`].
pub async fn run_alert_loop(cfg: AlertLoopConfig, shutdown: tokio::sync::watch::Receiver<bool>) {
    let store = match SqliteTunnelStore::open(&cfg.db_path) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("ct-cp: alerts: cannot open the tunnel store, dead-man alerts disabled: {e}");
            return;
        }
    };
    let probe = match &cfg.edge_admin {
        Some((url, token)) => Some(EdgeProbe::new(url, token)),
        None => {
            eprintln!("ct-cp: alerts: CT_CP_EDGE_ADMIN_URL unset -- dead-man alerts are stored but never evaluated");
            None
        }
    };
    run_alert_loop_with(store, probe, shutdown, ALERT_TICK).await;
}

/// [`run_alert_loop`] with injectable store/probe/period (tests). `MissedTickBehavior::
/// Skip`: a tick that overran (many slow receivers) does not burst-catch-up; it just
/// waits for the next period boundary.
pub(crate) async fn run_alert_loop_with(
    store: Arc<SqliteTunnelStore>,
    probe: Option<EdgeProbe>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    period: Duration,
) {
    let http = delivery_http_client();
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _ = interval.tick() => {
                tick(&store, probe.as_ref(), &http, unix_now()).await;
            }
            changed = shutdown.changed() => {
                if changed.is_err() {
                    break;
                }
            }
        }
    }
    eprintln!("ct-cp: alerts: loop stopped (shutdown)");
}

/// One evaluation pass over every enabled alert. Sequential per alert (a delivery's
/// retries wait inside this call), which is what the loop's skip-missed-ticks policy
/// is for. `now` is injected for the tests' deterministic thresholds.
pub(crate) async fn tick(store: &SqliteTunnelStore, probe: Option<&EdgeProbe>, http: &reqwest::Client, now: i64) {
    let Some(probe) = probe else {
        return;
    };
    let rows = match store.all_enabled_alerts() {
        Ok(rows) => rows,
        Err(e) => {
            eprintln!("ct-cp: alerts: listing alerts failed: {e}");
            return;
        }
    };
    for row in rows {
        let Some(up) = probe.tunnel_up(&row.routing_token).await else {
            continue;
        };
        evaluate_one(store, http, &row, up, now).await;
    }
}

/// Fold one edge answer into one alert: persist the "seen up" hint, decide via
/// [`next_transition`], deliver + log + transition. The transition is persisted even
/// when the delivery failed -- otherwise a broken receiver would be hammered with the
/// same event's three attempts every single tick.
pub(crate) async fn evaluate_one(
    store: &SqliteTunnelStore,
    http: &reqwest::Client,
    row: &AlertRow,
    up: bool,
    now: i64,
) {
    let a = &row.alert;
    if up {
        if let Err(e) = store.touch_alert_seen(&a.tunnel_id, now) {
            eprintln!("ct-cp: alerts: recording last-seen for tunnel {} failed: {e}", a.tunnel_id);
        }
    }
    let reference = if up { now } else { a.last_seen_hint.unwrap_or(a.state_since) };
    match next_transition(&a.state, up, reference, now, a.threshold_secs) {
        None => {
            if up && a.state != "up" {
                let _ = store.set_alert_state(&a.tunnel_id, "up", now);
            }
        }
        Some(event) => {
            let since = if event == AlertEvent::Down { reference } else { now };
            if rate_limited(store, &a.subject, now) {
                record_skipped_once(store, row, event, now);
                return;
            }
            let payload = AlertPayload::new(event, row, since, unix_now());
            let outcome = deliver(http, &a.webhook_url, &row.secret_hex, &payload, LOOP_ATTEMPTS).await;
            let recorded =
                store.record_delivery(&a.tunnel_id, now, event.wire(), outcome.status(), Some(&outcome.detail));
            if let Err(e) = recorded {
                eprintln!("ct-cp: alerts: recording delivery for tunnel {} failed: {e}", a.tunnel_id);
            }
            let new_state = match event {
                AlertEvent::Down => "down",
                AlertEvent::Up => "up",
                AlertEvent::Test => a.state.as_str(),
            };
            let _ = store.set_alert_state(&a.tunnel_id, new_state, since);
            eprintln!(
                "ct-cp: alerts: {} for tunnel {} -> {} : {} ({})",
                event.wire(),
                a.tunnel_id,
                url_host_for_log(&a.webhook_url),
                outcome.status(),
                outcome.detail
            );
        }
    }
}

/// Whether `subject` has used up its hourly delivery budget as of `now`. A store error
/// counts as limited: refusing one delivery is the cheaper mistake than an unbounded
/// burst while the database is unhappy.
pub(crate) fn rate_limited(store: &SqliteTunnelStore, subject: &str, now: i64) -> bool {
    match store.delivery_count_since(subject, now - 3600) {
        Ok(n) => n >= MAX_DELIVERIES_PER_HOUR,
        Err(e) => {
            eprintln!("ct-cp: alerts: counting deliveries for the rate limit failed, refusing: {e}");
            true
        }
    }
}

/// Log a rate-limit refusal, but only once per (tunnel, event) streak -- a flapping
/// tunnel refused every tick must not push the real deliveries out of the kept log.
fn record_skipped_once(store: &SqliteTunnelStore, row: &AlertRow, event: AlertEvent, now: i64) {
    let last = store
        .deliveries_for(&row.alert.subject, &row.alert.tunnel_id, 1)
        .ok()
        .and_then(|v| v.into_iter().next());
    if last.map(|d| d.status == "skipped" && d.event == event.wire()).unwrap_or(false) {
        return;
    }
    let _ = store.record_delivery(&row.alert.tunnel_id, now, event.wire(), "skipped", Some(RATE_LIMIT_DETAIL));
}

/// `scheme://host[:port]` of a webhook URL -- the only part of it that ever appears in
/// a log line or audit row (the path/query may carry a receiver's own token).
fn url_host_for_log(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(u) => match (u.host_str(), u.port()) {
            (Some(h), Some(p)) => format!("{}://{h}:{p}", u.scheme()),
            (Some(h), None) => format!("{}://{h}", u.scheme()),
            (None, _) => "<no host>".to_string(),
        },
        Err(_) => "<unparseable>".to_string(),
    }
}

use ct_common::time::now_secs_i64 as unix_now;

// ----- portal side -----

/// The tunnel card's alert form, as posted to `POST /portal/tunnels/:id/alert`.
/// `threshold_minutes` is a string so a non-numeric value is a clean 400 from
/// [`parse_threshold_minutes`] rather than axum's generic 422.
#[derive(Deserialize)]
pub struct AlertForm {
    pub webhook_url: String,
    pub threshold_minutes: String,
}

/// `https://` only, or `http://` to `127.0.0.1` / `localhost` / `[::1]` (a local
/// receiver, and the tests' mock server); never embedded credentials.
pub fn validate_webhook_url(raw: &str) -> Result<reqwest::Url, &'static str> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 2048 {
        return Err("webhook URL must be between 1 and 2048 characters");
    }
    let url = reqwest::Url::parse(raw).map_err(|_| "webhook URL is not a valid absolute URL")?;
    let host = url.host_str().ok_or("webhook URL needs a host")?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("webhook URL must not embed credentials");
    }
    let scheme_ok = match url.scheme() {
        "https" => true,
        "http" => matches!(host, "127.0.0.1" | "localhost" | "[::1]"),
        _ => false,
    };
    if !scheme_ok {
        return Err("webhook URL must use https:// (http:// is allowed for 127.0.0.1 / localhost only)");
    }
    Ok(url)
}

/// Whole minutes in `1..=10080` (7 days), returned as seconds.
pub fn parse_threshold_minutes(raw: &str) -> Result<i64, &'static str> {
    let minutes: i64 = raw.trim().parse().map_err(|_| "threshold must be a whole number of minutes")?;
    if !(MIN_THRESHOLD_MINUTES..=MAX_THRESHOLD_MINUTES).contains(&minutes) {
        return Err("threshold must be between 1 minute and 7 days");
    }
    Ok(minutes * 60)
}

fn audit(audit: Option<&SqliteAuditLog>, claims: &SessionClaims, action: &str, tunnel_id: &str, detail: &str) {
    if let Some(log) = audit {
        // Best-effort by that store's own contract (its doc: never fail the action).
        let _ = log.record(&claims.subject, action, Some(tunnel_id), Some(detail));
    }
}

fn internal(context: &str, e: impl std::fmt::Display) -> Response {
    eprintln!("ct-cp: alerts: {context}: {e}");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
}

/// `POST /portal/tunnels/:id/alert`: validate, upsert, and -- on a fresh create only --
/// answer with the secret-once page instead of the usual redirect. 404 for a foreign /
/// unknown tunnel ("existence leaks nothing", as every owner-scoped tunnel action),
/// 400 for a bad URL or threshold.
pub(crate) fn set_alert(
    store: &SqliteTunnelStore,
    audit_log: Option<&SqliteAuditLog>,
    claims: &SessionClaims,
    tunnel_id: &str,
    form: AlertForm,
) -> Response {
    let url = match validate_webhook_url(&form.webhook_url) {
        Ok(u) => u,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    let threshold_secs = match parse_threshold_minutes(&form.threshold_minutes) {
        Ok(s) => s,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    let detail = format!("receiver={} threshold_secs={threshold_secs}", url_host_for_log(url.as_str()));
    match store.upsert_alert(&claims.subject, tunnel_id, url.as_str(), threshold_secs, unix_now()) {
        Ok(None) => (StatusCode::NOT_FOUND, "unknown tunnel").into_response(),
        Ok(Some(AlertUpsert::Updated)) => {
            audit(audit_log, claims, "tunnel_alert_set", tunnel_id, &detail);
            Redirect::to("/portal/tunnels").into_response()
        }
        Ok(Some(AlertUpsert::Created { secret_hex })) => {
            audit(audit_log, claims, "tunnel_alert_set", tunnel_id, &format!("{detail} created"));
            let body = secret_once_html(&secret_hex, &url_host_for_log(url.as_str()));
            let page = crate::portal_api::page("dead-man alert", &body, claims.email.as_deref());
            let mut resp = Html(page).into_response();
            resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Err(e) => internal("set_alert/upsert", e),
    }
}

/// `POST /portal/tunnels/:id/alert/test`: one immediate, single-attempt `tunnel.test`
/// delivery, logged like any other; 404 foreign/unknown/no alert, 429 when the owner's
/// hourly budget is spent (the button must not be an amplifier).
pub(crate) async fn test_alert(
    store: &SqliteTunnelStore,
    audit_log: Option<&SqliteAuditLog>,
    claims: &SessionClaims,
    tunnel_id: &str,
) -> Response {
    let row = match store.alert_row_for(&claims.subject, tunnel_id) {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "unknown tunnel or no alert configured").into_response(),
        Err(e) => return internal("test_alert/lookup", e),
    };
    let now = unix_now();
    if rate_limited(store, &claims.subject, now) {
        record_skipped_once(store, &row, AlertEvent::Test, now);
        return (StatusCode::TOO_MANY_REQUESTS, RATE_LIMIT_DETAIL).into_response();
    }
    let payload = AlertPayload::new(AlertEvent::Test, &row, row.alert.state_since, now);
    let outcome = deliver(&delivery_http_client(), &row.alert.webhook_url, &row.secret_hex, &payload, 1).await;
    let recorded =
        store.record_delivery(tunnel_id, now, AlertEvent::Test.wire(), outcome.status(), Some(&outcome.detail));
    if let Err(e) = recorded {
        return internal("test_alert/record", e);
    }
    audit(audit_log, claims, "tunnel_alert_test", tunnel_id, &format!("{}: {}", outcome.status(), outcome.detail));
    Redirect::to("/portal/tunnels").into_response()
}

/// `POST /portal/tunnels/:id/alert/delete`: 404 foreign/unknown/none, else redirect.
pub(crate) fn delete_alert(
    store: &SqliteTunnelStore,
    audit_log: Option<&SqliteAuditLog>,
    claims: &SessionClaims,
    tunnel_id: &str,
) -> Response {
    match store.delete_alert(&claims.subject, tunnel_id) {
        Ok(true) => {
            audit(audit_log, claims, "tunnel_alert_deleted", tunnel_id, "");
            Redirect::to("/portal/tunnels").into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "unknown tunnel or no alert configured").into_response(),
        Err(e) => internal("delete_alert", e),
    }
}

/// The per-tunnel "Dead-man alert" card blocks for the tunnels page, keyed by tunnel
/// id -- pre-rendered here so `portal_api::tunnels_html` stays a pure renderer and its
/// only knowledge of this feature is one placeholder. Owner scoping is the store's
/// (`alert_for`/`deliveries_for`), and the caller only renders a block on owned cards.
pub(crate) fn card_blocks(store: &SqliteTunnelStore, subject: &str, tunnel_ids: &[&str]) -> HashMap<String, String> {
    tunnel_ids
        .iter()
        .map(|id| {
            let alert = store.alert_for(subject, id).unwrap_or(None);
            let deliveries = store.deliveries_for(subject, id, CARD_DELIVERIES).unwrap_or_default();
            (id.to_string(), card_html(id, alert.as_ref(), &deliveries))
        })
        .collect()
}

fn state_label(alert: &TunnelAlert) -> String {
    match alert.state.as_str() {
        "up" => format!("up since {} UTC", crate::portal_api::utc_ymd_hm(alert.state_since)),
        "down" => format!("DOWN since {} UTC", crate::portal_api::utc_ymd_hm(alert.state_since)),
        _ => "not checked yet".to_string(),
    }
}

/// One card block. Reuses the page's existing `details.history`/`table.history` styling
/// so this needs no CSS of its own.
fn card_html(tunnel_id: &str, alert: Option<&TunnelAlert>, deliveries: &[AlertDelivery]) -> String {
    let id = escape(tunnel_id);
    let (summary, status_line, url, minutes, submit) = match alert {
        Some(a) => {
            let last = match (&a.last_delivery_status, a.last_delivery_at) {
                (Some(s), Some(at)) => format!(
                    " &middot; last delivery {} at {} UTC",
                    escape(s),
                    crate::portal_api::utc_ymd_hm(at)
                ),
                _ => String::new(),
            };
            (
                state_label(a),
                format!(
                    r#"<div class="row"><span class="k">Status:</span><span class="v">{}{last}</span></div>"#,
                    state_label(a)
                ),
                escape(&a.webhook_url),
                (a.threshold_secs / 60).max(1).to_string(),
                "Save",
            )
        }
        None => ("not configured".to_string(), String::new(), String::new(), "5".to_string(), "Set up"),
    };
    let actions = if alert.is_some() {
        format!(
            r#"<div class="actions">
 <form class="inline" method="post" action="/portal/tunnels/{id}/alert/test"><button type="submit" class="sec">Test</button></form>
 <form class="inline" method="post" action="/portal/tunnels/{id}/alert/delete"><button type="submit" class="sec">Remove</button></form>
</div>"#
        )
    } else {
        String::new()
    };
    let log = if deliveries.is_empty() {
        if alert.is_some() {
            r#"<p class="help">No deliveries yet. Use Test to send a signed <code>tunnel.test</code> event now.</p>"#
                .to_string()
        } else {
            String::new()
        }
    } else {
        let rows = deliveries
            .iter()
            .map(|d| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    crate::portal_api::utc_ymd_hm(d.ts),
                    escape(&d.event),
                    escape(&d.status),
                    d.detail.as_deref().map(escape).unwrap_or_else(|| "&ndash;".to_string()),
                )
            })
            .collect::<String>();
        format!(
            r#"<table class="history"><thead><tr><th>When (UTC)</th><th>Event</th><th>Status</th><th>Detail</th></tr></thead>
<tbody>{rows}</tbody></table>"#
        )
    };
    format!(
        r#"<details class="history alert"><summary class="row"><span class="k">Dead-man alert</span><span class="v">{summary}</span></summary>
{status_line}
<form method="post" action="/portal/tunnels/{id}/alert">
 <label>Webhook URL
  <input type="url" name="webhook_url" value="{url}" required maxlength="2048" placeholder="https://hooks.example/ct-alerts">
 </label>
 <label>Threshold (minutes)
  <input type="number" name="threshold_minutes" value="{minutes}" min="1" max="10080" required>
 </label>
 <button type="submit" class="sec">{submit}</button>
</form>
{actions}
{log}
<p class="help">Sends a signed <code>tunnel.down</code> once this tunnel has been unreachable for the threshold, and
<code>tunnel.up</code> when it is back. Checked once a minute; at most 20 deliveries per hour per account.</p>
</details>"#
    )
}

/// The create-only confirmation page: the secret, shown here and never again.
fn secret_once_html(secret_hex: &str, receiver: &str) -> String {
    format!(
        r#"<h1>Dead-man alert configured</h1>
<p>Alerts for this tunnel will be POSTed to <code>{receiver}</code>.</p>
<div class="warn">This signing secret is shown <strong>once</strong> and will not be shown again. Copy it into your
receiver now. To rotate it, remove the alert on the tunnel card and set it up again.</div>
<div class="code-block">
 <div class="code-block-head"><span>webhook secret</span><button class="copy-btn" onclick="copyCode(this)" type="button">Copy</button></div>
 <pre><code>{secret}</code></pre>
</div>
<h2>Verifying a delivery</h2>
<p class="help">Every POST carries <code>X-CT-Timestamp</code> (unix seconds) and
<code>X-CT-Signature: sha256=&lt;hex&gt;</code>, an HMAC-SHA256 keyed with this secret over the string
<code>&lt;timestamp&gt;.&lt;raw body&gt;</code>. Recompute it, compare in constant time, and reject timestamps more than a
few minutes off your clock. The JSON body has <code>event</code> (<code>tunnel.down</code>, <code>tunnel.up</code>,
<code>tunnel.test</code>), <code>tunnel_id</code>, <code>name</code>, <code>since</code>, <code>threshold_secs</code> and
<code>sent_at</code>. Use <em>Test</em> on the tunnel card to send a <code>tunnel.test</code> event right away.</p>
<p><a class="btn sec" href="/portal/tunnels">Back to tunnels</a></p>"#,
        receiver = escape(receiver),
        secret = escape(secret_hex),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{SqliteBootstrap, SqliteEnrollment, SqliteLedger};
    use axum::body::{to_bytes, Body};
    use axum::http::{HeaderMap, Request};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    use tower::ServiceExt;

    const KEY: &[u8] = b"alerts-test-key";

    // ----- pure decision -----

    #[test]
    fn next_transition_holds_while_down_is_under_the_threshold() {
        assert_eq!(next_transition("up", false, 1_000, 1_100, 300), None);
        assert_eq!(next_transition("unknown", false, 1_000, 1_299, 300), None);
    }

    #[test]
    fn next_transition_fires_down_once_past_the_threshold_then_stays_quiet() {
        assert_eq!(next_transition("up", false, 1_000, 1_300, 300), Some(AlertEvent::Down));
        assert_eq!(next_transition("unknown", false, 1_000, 5_000, 300), Some(AlertEvent::Down));
        // Once persisted as "down", the same observation is silent.
        assert_eq!(next_transition("down", false, 1_000, 9_000, 300), None);
    }

    #[test]
    fn next_transition_fires_up_once_on_recovery_and_never_while_up() {
        assert_eq!(next_transition("down", true, 1_000, 1_400, 300), Some(AlertEvent::Up));
        assert_eq!(next_transition("up", true, 1_000, 1_400, 300), None);
        assert_eq!(next_transition("unknown", true, 1_000, 1_400, 300), None);
    }

    // ----- signing -----

    #[test]
    fn signature_header_is_the_hmac_over_timestamp_dot_body_the_inbound_verifier_accepts() {
        let secret = "0123abcd";
        let body = br#"{"event":"tunnel.down","tunnel_id":"t1"}"#;
        let ts = 1_757_100_000u64;
        let header = signature_header(secret, ts, body);
        let hex = header.strip_prefix("sha256=").expect("prefixed");
        // The exact receiver-side check: recompute over "<ts>.<body>" with the secret's bytes.
        assert_eq!(WebhookVerifier::new(secret.as_bytes(), 300).verify(ts, body, hex, ts + 1), Ok(()));
        assert!(WebhookVerifier::new(b"other".to_vec(), 300).verify(ts, body, hex, ts).is_err());
        assert!(WebhookVerifier::new(secret.as_bytes(), 300).verify(ts + 1, body, hex, ts).is_err());
    }

    // ----- URL / threshold validation -----

    #[test]
    fn webhook_url_validation_allows_https_and_loopback_http_only() {
        assert!(validate_webhook_url("https://hooks.example/ct?token=x").is_ok());
        assert!(validate_webhook_url("http://127.0.0.1:8080/hook").is_ok());
        assert!(validate_webhook_url("http://localhost/hook").is_ok());
        assert!(validate_webhook_url("http://[::1]:9/hook").is_ok());
        assert!(validate_webhook_url("http://hooks.example/ct").is_err(), "plain http to a real host");
        assert!(validate_webhook_url("ftp://hooks.example/ct").is_err());
        assert!(validate_webhook_url("javascript:alert(1)").is_err());
        assert!(validate_webhook_url("https://user:pw@hooks.example/ct").is_err(), "embedded credentials");
        assert!(validate_webhook_url("").is_err());
        assert!(validate_webhook_url("not a url").is_err());
    }

    #[test]
    fn threshold_minutes_parse_to_seconds_within_bounds() {
        assert_eq!(parse_threshold_minutes("5"), Ok(300));
        assert_eq!(parse_threshold_minutes(" 1 "), Ok(60));
        assert!(parse_threshold_minutes("0").is_err());
        assert!(parse_threshold_minutes("-3").is_err());
        assert!(parse_threshold_minutes("10081").is_err());
        assert!(parse_threshold_minutes("five").is_err());
    }

    #[test]
    fn log_host_never_carries_the_path_or_query() {
        assert_eq!(url_host_for_log("https://hooks.example/ct?token=SECRET"), "https://hooks.example");
        assert_eq!(url_host_for_log("http://127.0.0.1:8080/x?y=1"), "http://127.0.0.1:8080");
        assert_eq!(url_host_for_log("nope"), "<unparseable>");
    }

    // ----- storage round trip -----

    fn store_with_tunnel() -> (Arc<SqliteTunnelStore>, String) {
        let store = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = store.create("alice", "web", None).unwrap().created().expect("no hostname collision");
        (store, t.id)
    }

    #[test]
    fn storage_round_trip_mints_the_secret_once_keeps_it_on_update_and_is_owner_scoped() {
        let (store, id) = store_with_tunnel();
        let created = store.upsert_alert("alice", &id, "https://hooks.example/a", 300, 1_000).unwrap();
        let secret = match created {
            Some(AlertUpsert::Created { secret_hex }) => secret_hex,
            other => panic!("expected Created, got {other:?}"),
        };
        assert_eq!(secret.len(), 64, "32 random bytes, hex");

        let a = store.alert_for("alice", &id).unwrap().expect("stored");
        assert_eq!(a.webhook_url, "https://hooks.example/a");
        assert_eq!(a.threshold_secs, 300);
        assert_eq!(a.state, "unknown");
        assert_eq!(a.state_since, 1_000);
        assert!(a.enabled);

        // Update: URL/threshold replaced, secret untouched, state reset to unknown.
        store.set_alert_state(&id, "down", 1_500).unwrap();
        assert_eq!(
            store.upsert_alert("alice", &id, "https://hooks.example/b", 600, 2_000).unwrap(),
            Some(AlertUpsert::Updated)
        );
        let row = store.alert_row_for("alice", &id).unwrap().expect("stored");
        assert_eq!(row.secret_hex, secret, "the secret survives an update");
        assert_eq!(row.alert.webhook_url, "https://hooks.example/b");
        assert_eq!(row.alert.threshold_secs, 600);
        assert_eq!(row.alert.state, "unknown");
        assert_eq!(row.name, "web");
        assert!(!row.routing_token.is_empty());

        // Owner scoping: a stranger can neither create, read, nor delete.
        assert_eq!(store.upsert_alert("bob", &id, "https://evil.example/", 60, 0).unwrap(), None);
        assert_eq!(store.alert_for("bob", &id).unwrap(), None);
        assert_eq!(store.alert_row_for("bob", &id).unwrap(), None);
        assert!(!store.delete_alert("bob", &id).unwrap());
        assert_eq!(store.upsert_alert("alice", "no-such-id", "https://x.example/", 60, 0).unwrap(), None);

        // The loop's work list sees it; delete removes it and its log.
        assert_eq!(store.all_enabled_alerts().unwrap().len(), 1);
        store.record_delivery(&id, 2_100, "tunnel.test", "ok", Some("HTTP 200")).unwrap();
        assert_eq!(store.deliveries_for("alice", &id, 10).unwrap().len(), 1);
        assert!(store.deliveries_for("bob", &id, 10).unwrap().is_empty());
        assert!(store.delete_alert("alice", &id).unwrap());
        assert_eq!(store.alert_for("alice", &id).unwrap(), None);
        assert!(store.all_enabled_alerts().unwrap().is_empty());
        assert!(!store.delete_alert("alice", &id).unwrap(), "already gone");
    }

    #[test]
    fn record_delivery_prunes_to_fifty_and_tracks_the_failure_streak() {
        let (store, id) = store_with_tunnel();
        store.upsert_alert("alice", &id, "https://hooks.example/a", 300, 0).unwrap();
        for i in 0..60 {
            store.record_delivery(&id, i, "tunnel.down", "failed", Some("HTTP 500")).unwrap();
        }
        let kept = store.deliveries_for("alice", &id, 100).unwrap();
        assert_eq!(kept.len() as i64, crate::storage::ALERT_DELIVERY_KEEP);
        assert_eq!(kept[0].ts, 59, "newest first");
        assert_eq!(kept.last().unwrap().ts, 10, "the oldest ten were pruned");
        let a = store.alert_for("alice", &id).unwrap().unwrap();
        assert_eq!(a.failures, 60);
        assert_eq!(a.last_delivery_status.as_deref(), Some("failed"));
        store.record_delivery(&id, 100, "tunnel.up", "ok", None).unwrap();
        let a = store.alert_for("alice", &id).unwrap().unwrap();
        assert_eq!(a.failures, 0, "a success resets the streak");
        assert_eq!(a.last_delivery_at, Some(100));
        store.record_delivery(&id, 101, "tunnel.up", "skipped", Some(RATE_LIMIT_DETAIL)).unwrap();
        assert_eq!(store.alert_for("alice", &id).unwrap().unwrap().failures, 0, "skipped leaves the streak alone");
    }

    // ----- mock servers -----

    /// What the mock receiver saw: `(X-CT-Timestamp, X-CT-Signature, raw body)` per POST.
    type Received = Arc<Mutex<Vec<(u64, String, Vec<u8>)>>>;

    async fn mock_webhook() -> (String, Received) {
        let received: Received = Arc::new(Mutex::new(Vec::new()));
        let sink = received.clone();
        let app = Router::new().route(
            "/hook",
            post(move |headers: HeaderMap, body: axum::body::Bytes| {
                let sink = sink.clone();
                async move {
                    assert_eq!(
                        headers.get("content-type").and_then(|v| v.to_str().ok()),
                        Some("application/json")
                    );
                    let ts: u64 = headers.get("x-ct-timestamp").unwrap().to_str().unwrap().parse().unwrap();
                    let sig = headers.get("x-ct-signature").unwrap().to_str().unwrap().to_string();
                    sink.lock().unwrap().push((ts, sig, body.to_vec()));
                    StatusCode::NO_CONTENT
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}/hook"), received)
    }

    /// A mock edge whose `/admin/tunnel-status/:token` answers `connected` from a flag
    /// and which has NO history route (an older edge: 404 -> fail open on that half).
    async fn mock_edge(connected: Arc<AtomicBool>) -> EdgeProbe {
        let app = Router::new().route(
            "/admin/tunnel-status/:token",
            get(move |headers: HeaderMap| {
                let connected = connected.clone();
                async move {
                    assert_eq!(headers.get("x-ct-admin-token").and_then(|v| v.to_str().ok()), Some("edge-secret"));
                    Json(serde_json::json!({ "connected": connected.load(Ordering::SeqCst) }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        EdgeProbe::new(&format!("http://{addr}"), "edge-secret")
    }

    fn verify_received(secret: &str, (ts, sig, body): &(u64, String, Vec<u8>)) -> AlertPayload {
        let hex = sig.strip_prefix("sha256=").expect("sha256= prefix");
        WebhookVerifier::new(secret.as_bytes(), 300).verify(*ts, body, hex, *ts).expect("valid signature");
        let payload: AlertPayload = serde_json::from_slice(body).expect("json body");
        assert_eq!(payload.sent_at as u64, *ts, "sent_at equals the signed timestamp");
        payload
    }

    // ----- loop -----

    #[tokio::test]
    async fn loop_tick_fires_down_once_after_the_threshold_and_up_once_on_recovery() {
        let (hook_url, received) = mock_webhook().await;
        let connected = Arc::new(AtomicBool::new(false));
        let probe = mock_edge(connected.clone()).await;
        let (store, id) = store_with_tunnel();
        let secret = match store.upsert_alert("alice", &id, &hook_url, 300, 0).unwrap() {
            Some(AlertUpsert::Created { secret_hex }) => secret_hex,
            other => panic!("{other:?}"),
        };
        let http = delivery_http_client();

        // Down from creation, still under the threshold: nothing, state untouched.
        tick(&store, Some(&probe), &http, 100).await;
        assert!(received.lock().unwrap().is_empty());
        assert_eq!(store.alert_for("alice", &id).unwrap().unwrap().state, "unknown");

        // Past the threshold: exactly one tunnel.down, `since` = the reference (creation).
        tick(&store, Some(&probe), &http, 400).await;
        tick(&store, Some(&probe), &http, 460).await;
        {
            let got = received.lock().unwrap();
            assert_eq!(got.len(), 1, "down fires once, not every tick");
            let p = verify_received(&secret, &got[0]);
            assert_eq!(p.event, "tunnel.down");
            assert_eq!(p.tunnel_id, id);
            assert_eq!(p.name, "web");
            assert_eq!(p.since, 0);
            assert_eq!(p.threshold_secs, 300);
        }
        let a = store.alert_for("alice", &id).unwrap().unwrap();
        assert_eq!(a.state, "down");
        assert_eq!(a.state_since, 0);
        assert_eq!(a.last_delivery_status.as_deref(), Some("ok"));

        // Recovery: exactly one tunnel.up, then quiet while up.
        connected.store(true, Ordering::SeqCst);
        tick(&store, Some(&probe), &http, 500).await;
        tick(&store, Some(&probe), &http, 560).await;
        {
            let got = received.lock().unwrap();
            assert_eq!(got.len(), 2);
            let p = verify_received(&secret, &got[1]);
            assert_eq!(p.event, "tunnel.up");
            assert_eq!(p.since, 500);
        }
        let a = store.alert_for("alice", &id).unwrap().unwrap();
        assert_eq!(a.state, "up");
        assert_eq!(a.state_since, 500);
        assert_eq!(a.last_seen_hint, Some(560));

        // A short blip under the threshold after that: no event, still "up".
        connected.store(false, Ordering::SeqCst);
        tick(&store, Some(&probe), &http, 700).await;
        assert_eq!(received.lock().unwrap().len(), 2);
        assert_eq!(store.alert_for("alice", &id).unwrap().unwrap().state, "up");
        // ...but measured from the last seen-up time (560), 860 crosses it.
        tick(&store, Some(&probe), &http, 860).await;
        let got = received.lock().unwrap();
        assert_eq!(got.len(), 3);
        let p = verify_received(&secret, &got[2]);
        assert_eq!(p.event, "tunnel.down");
        assert_eq!(p.since, 560, "outage start is the last time the tunnel was seen up");

        let log = store.deliveries_for("alice", &id, 10).unwrap();
        assert_eq!(log.len(), 3);
        assert_eq!(log[0].event, "tunnel.down");
        assert_eq!(log[0].status, "ok");
        assert_eq!(log[0].detail.as_deref(), Some("HTTP 204 (attempt 1)"));
    }

    #[tokio::test]
    async fn loop_tick_leaves_an_alert_alone_when_the_edge_cannot_be_asked() {
        // A dead edge port: both lookups fail -> None -> no evaluation, never "down".
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let probe = EdgeProbe::new(&format!("http://{addr}"), "edge-secret");
        let (hook_url, received) = mock_webhook().await;
        let (store, id) = store_with_tunnel();
        store.upsert_alert("alice", &id, &hook_url, 60, 0).unwrap();
        tick(&store, Some(&probe), &delivery_http_client(), 10_000).await;
        assert!(received.lock().unwrap().is_empty());
        assert_eq!(store.alert_for("alice", &id).unwrap().unwrap().state, "unknown");
        // And with no edge configured at all, likewise.
        tick(&store, None, &delivery_http_client(), 10_000).await;
        assert!(received.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn rate_limit_refuses_the_twenty_first_delivery_in_an_hour() {
        let (hook_url, received) = mock_webhook().await;
        let connected = Arc::new(AtomicBool::new(false));
        let probe = mock_edge(connected).await;
        let (store, id) = store_with_tunnel();
        store.upsert_alert("alice", &id, &hook_url, 60, 0).unwrap();
        let now = 10_000;
        for i in 0..19 {
            store.record_delivery(&id, now - 100 - i, "tunnel.up", "ok", None).unwrap();
        }
        assert!(!rate_limited(&store, "alice", now), "19 in the window is still allowed");
        store.record_delivery(&id, now - 50, "tunnel.down", "failed", Some("HTTP 500")).unwrap();
        assert!(rate_limited(&store, "alice", now), "20 in the window spends the budget");
        assert!(!rate_limited(&store, "bob", now), "per owner, not global");

        // The 21st (a real down transition) is refused: nothing sent, state NOT transitioned
        // (so it catches up later), one skipped row -- and only one, however often refused.
        let http = delivery_http_client();
        tick(&store, Some(&probe), &http, now).await;
        tick(&store, Some(&probe), &http, now + 60).await;
        assert!(received.lock().unwrap().is_empty(), "no delivery went out");
        let a = store.alert_for("alice", &id).unwrap().unwrap();
        assert_eq!(a.state, "unknown", "left un-transitioned to catch up once the window frees");
        let log = store.deliveries_for("alice", &id, 100).unwrap();
        assert_eq!(log.iter().filter(|d| d.status == "skipped").count(), 1);
        assert_eq!(log[0].detail.as_deref(), Some(RATE_LIMIT_DETAIL));
        assert!(rate_limited(&store, "alice", now), "a skipped row does not extend the budget");

        // An hour later the window has freed and the alert fires.
        assert!(!rate_limited(&store, "alice", now + 3_601));
        tick(&store, Some(&probe), &http, now + 3_601).await;
        assert_eq!(received.lock().unwrap().len(), 1);
        assert_eq!(store.alert_for("alice", &id).unwrap().unwrap().state, "down");
    }

    #[tokio::test]
    async fn loop_stops_when_the_shutdown_signal_fires() {
        let (store, _id) = store_with_tunnel();
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(run_alert_loop_with(store, None, rx, Duration::from_millis(20)));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!handle.is_finished(), "runs until told to stop");
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), handle).await.expect("stops promptly").unwrap();
    }

    // ----- portal routes -----

    fn portal_app() -> (Router, Arc<SqliteTunnelStore>) {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let edge_mesh = crate::edge_mesh::EdgeMeshHandle::new(
            Arc::new(crate::edge_mesh::SqliteEdgeMesh::open_in_memory().unwrap()),
            Arc::from("test-edge"),
        );
        let app = crate::portal_api::portal_api_router(
            KEY,
            Arc::new(SqliteLedger::open_in_memory().unwrap()),
            tunnels.clone(),
            Arc::new(SqliteEnrollment::open_in_memory().unwrap()),
            Arc::new(SqliteBootstrap::open_in_memory().unwrap()),
            "https://portal.example",
            None,
            None,
            None,
            None,
            edge_mesh,
            None,
        );
        (app, tunnels)
    }

    fn cookie(subject: &str) -> String {
        format!("ct_portal_session={}", crate::portal::sign_session_for_test(KEY, subject))
    }

    async fn post_form(app: &Router, path: &str, subject: &str, form: &str) -> (StatusCode, String) {
        let resp = app
            .clone()
            .oneshot(
                Request::post(path)
                    .header("cookie", cookie(subject))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    async fn get_page(app: &Router, path: &str, subject: &str) -> (StatusCode, String) {
        let resp = app
            .clone()
            .oneshot(Request::get(path).header("cookie", cookie(subject)).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn portal_create_rejects_bad_input_with_400_is_owner_scoped_404_and_shows_the_secret_once() {
        let (app, tunnels) = portal_app();
        let t = tunnels.create("alice", "web", None).unwrap().created().unwrap();
        let path = format!("/portal/tunnels/{}/alert", t.id);

        let plain_http = "webhook_url=http%3A%2F%2Fhooks.example%2Fct&threshold_minutes=5";
        let (status, _) = post_form(&app, &path, "alice", plain_http).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "plain http to a real host");
        let zero = "webhook_url=https%3A%2F%2Fhooks.example%2Fct&threshold_minutes=0";
        let (status, _) = post_form(&app, &path, "alice", zero).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "threshold < 1");
        let nan = "webhook_url=https%3A%2F%2Fhooks.example%2Fct&threshold_minutes=x";
        let (status, _) = post_form(&app, &path, "alice", nan).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "non-numeric threshold");
        assert_eq!(tunnels.alert_for("alice", &t.id).unwrap(), None, "nothing stored on a 400");

        let good = "webhook_url=https%3A%2F%2Fhooks.example%2Fct%3Ftoken%3Dabc&threshold_minutes=5";
        let (status, _) = post_form(&app, &path, "bob", good).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "a stranger gets 404, never 403");
        let (status, _) = post_form(&app, "/portal/tunnels/no-such-id/alert", "alice", good).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // The owner's create answers with the secret-once page (200, not a redirect).
        let (status, html) = post_form(&app, &path, "alice", good).await;
        assert_eq!(status, StatusCode::OK);
        let row = tunnels.alert_row_for("alice", &t.id).unwrap().expect("stored");
        assert!(html.contains(&row.secret_hex), "the secret is rendered exactly here");
        assert!(html.contains("will not be shown again"));
        assert!(html.contains("copyCode(this)"), "a Copy button");
        assert!(html.contains("https://hooks.example"), "the receiver host is named");
        assert!(!html.contains("token=abc"), "the URL's query never appears on the page");
        assert_eq!(row.alert.threshold_secs, 300);

        // An update redirects and does NOT show the secret again; the card never does either.
        let update = "webhook_url=https%3A%2F%2Fhooks.example%2Fv2&threshold_minutes=10";
        let (status, html) = post_form(&app, &path, "alice", update).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert!(!html.contains(&row.secret_hex));
        let (status, html) = get_page(&app, "/portal/tunnels", "alice").await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("Dead-man alert"), "{html}");
        assert!(html.contains("https://hooks.example/v2"), "the form is prefilled with the current URL");
        assert!(html.contains(r#"value="10""#), "and threshold");
        assert!(html.contains("not checked yet"));
        assert!(html.contains(&format!("/portal/tunnels/{}/alert/test", t.id)));
        assert!(html.contains(&format!("/portal/tunnels/{}/alert/delete", t.id)));
        assert!(!html.contains(&row.secret_hex), "the secret is never rendered on the card");
        assert_eq!(tunnels.alert_row_for("alice", &t.id).unwrap().unwrap().secret_hex, row.secret_hex);

        // Remove: owner-scoped too, and the card offers set-up again afterwards.
        let del = format!("/portal/tunnels/{}/alert/delete", t.id);
        assert_eq!(post_form(&app, &del, "bob", "").await.0, StatusCode::NOT_FOUND);
        assert_eq!(post_form(&app, &del, "alice", "").await.0, StatusCode::SEE_OTHER);
        assert_eq!(post_form(&app, &del, "alice", "").await.0, StatusCode::NOT_FOUND, "already removed");
        let (_, html) = get_page(&app, "/portal/tunnels", "alice").await;
        assert!(html.contains("not configured"));
    }

    #[tokio::test]
    async fn portal_test_route_delivers_a_signed_tunnel_test_event_and_logs_it() {
        let (hook_url, received) = mock_webhook().await;
        let (app, tunnels) = portal_app();
        let t = tunnels.create("alice", "web", None).unwrap().created().unwrap();
        let secret = match tunnels.upsert_alert("alice", &t.id, &hook_url, 300, 1_000).unwrap() {
            Some(AlertUpsert::Created { secret_hex }) => secret_hex,
            other => panic!("{other:?}"),
        };
        let path = format!("/portal/tunnels/{}/alert/test", t.id);

        assert_eq!(post_form(&app, &path, "bob", "").await.0, StatusCode::NOT_FOUND);
        assert!(received.lock().unwrap().is_empty());

        let (status, _) = post_form(&app, &path, "alice", "").await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let got = received.lock().unwrap();
        assert_eq!(got.len(), 1);
        let p = verify_received(&secret, &got[0]);
        assert_eq!(p.event, "tunnel.test");
        assert_eq!(p.tunnel_id, t.id);
        assert_eq!(p.name, "web");
        assert_eq!(p.threshold_secs, 300);
        assert_eq!(p.since, 1_000);
        drop(got);

        let log = tunnels.deliveries_for("alice", &t.id, 10).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].event, "tunnel.test");
        assert_eq!(log[0].status, "ok");
        let (_, html) = get_page(&app, "/portal/tunnels", "alice").await;
        assert!(html.contains("<td>tunnel.test</td><td>ok</td>"), "{html}");

        // A spent budget makes the button answer 429 instead of sending.
        for i in 0..19 {
            tunnels.record_delivery(&t.id, unix_now() - i, "tunnel.up", "ok", None).unwrap();
        }
        let (status, body) = post_form(&app, &path, "alice", "").await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
        assert_eq!(received.lock().unwrap().len(), 1, "nothing more was sent");
    }

    #[tokio::test]
    async fn portal_test_route_logs_a_failed_delivery_without_leaking_the_url() {
        // A dead receiver port: connection refused -> "failed", detail classified only.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let (app, tunnels) = portal_app();
        let t = tunnels.create("alice", "web", None).unwrap().created().unwrap();
        tunnels.upsert_alert("alice", &t.id, &format!("http://{addr}/hook?token=SECRET"), 300, 0).unwrap();
        let (status, _) = post_form(&app, &format!("/portal/tunnels/{}/alert/test", t.id), "alice", "").await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let log = tunnels.deliveries_for("alice", &t.id, 10).unwrap();
        assert_eq!(log[0].status, "failed");
        let detail = log[0].detail.clone().unwrap();
        assert!(detail.starts_with("connection failed") || detail.starts_with("request failed"), "{detail}");
        assert!(!detail.contains("SECRET") && !detail.contains("hook"), "{detail}");
        assert_eq!(tunnels.alert_for("alice", &t.id).unwrap().unwrap().failures, 1);
    }
}
