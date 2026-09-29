//! #779: access windows / auto-expiring exposure -- the portal half.
//!
//! The owner sets, per tunnel, an expiry (absolute UTC time or "in N hours") and/or a
//! weekly schedule (days, hours, fixed UTC offset). The policy itself is
//! `ct_common::access_window::AccessPolicy` (pure, shared with the edge); this module
//! owns the "Access window" block on the tunnel card, the two owner-scoped routes, the
//! audit rows, and the best-effort push that hands every change to the edge's admin
//! listener (`POST /internal/tunnel/access-policy`) so it enforces the window locally.
//!
//! A child module of `portal_api` on purpose: it needs that module's private
//! `ApiState`/`EdgeAdmin` and its edge-admin HTTP client, but sibling PRs touch
//! `portal_api.rs` itself, so everything here stays out of that file except one
//! `mod access;`, one `.merge(access::routes())`, one card-block hook, and one call in
//! `authorize_hostname`.

use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::post;
use axum::Router;
use serde::Deserialize;

use ct_common::access_window::{
    days_from_civil, format_utc_ymd_hm, AccessPolicy, Slot, WeeklySchedule, MINUTES_PER_DAY,
};

use super::{edge_admin_http_client, human_duration, internal_error, ApiState};
use crate::portal::session_subject_for;

/// Audit action recorded when a policy is saved (detail = the policy JSON).
pub(super) const AUDIT_SET: &str = "tunnel_access_policy_set";
/// Audit action recorded when a policy is cleared.
pub(super) const AUDIT_CLEARED: &str = "tunnel_access_policy_cleared";

/// "Re-arm 24 h": how long a re-armed exposure stays open.
const REARM_SECS: i64 = 24 * 3_600;
/// Upper bound for "in N hours" (one year), so a typo cannot pin a hostname open for decades.
const MAX_EXPIRES_IN_HOURS: i64 = 24 * 365;

/// The two owner-scoped routes, mounted into `portal_api_router` via one `.merge`.
pub(super) fn routes() -> Router<ApiState> {
    Router::new()
        .route("/portal/tunnels/:id/access", post(set_access))
        .route("/portal/tunnels/:id/access/clear", post(clear_access))
}

use ct_common::time::now_secs_i64 as now_secs;

/// What the card's form posts. Every field optional: radio/checkbox inputs are simply
/// absent when not selected, and the "Re-arm 24 h" button posts only `rearm`.
#[derive(Deserialize, Default, Debug)]
pub(super) struct AccessForm {
    /// Present (any value) on the "Re-arm 24 h" button's own form: keep the schedule,
    /// set a fresh expiry 24 h from now.
    #[serde(default)]
    rearm: Option<String>,
    /// `none` | `at` | `in`.
    #[serde(default)]
    expiry_mode: Option<String>,
    /// `datetime-local` value, read as UTC: `YYYY-MM-DDTHH:MM[:SS]`.
    #[serde(default)]
    expires_at: Option<String>,
    /// Hours from now, `1..=MAX_EXPIRES_IN_HOURS`.
    #[serde(default)]
    expires_in_hours: Option<String>,
    /// Checkbox: a weekly schedule applies.
    #[serde(default)]
    schedule: Option<String>,
    #[serde(default)]
    day0: Option<String>,
    #[serde(default)]
    day1: Option<String>,
    #[serde(default)]
    day2: Option<String>,
    #[serde(default)]
    day3: Option<String>,
    #[serde(default)]
    day4: Option<String>,
    #[serde(default)]
    day5: Option<String>,
    #[serde(default)]
    day6: Option<String>,
    /// `HH:MM` in the schedule's local time.
    #[serde(default)]
    start: Option<String>,
    /// `HH:MM`; `24:00` allowed for end of day.
    #[serde(default)]
    end: Option<String>,
    /// Minutes east of UTC, as the `<select>` posts it.
    #[serde(default)]
    tz_offset: Option<String>,
}

impl AccessForm {
    fn days(&self) -> Vec<u8> {
        [&self.day0, &self.day1, &self.day2, &self.day3, &self.day4, &self.day5, &self.day6]
            .iter()
            .enumerate()
            .filter_map(|(i, d)| d.as_ref().map(|_| i as u8))
            .collect()
    }
}

/// `HH:MM` -> minutes after midnight (`24:00` -> 1440, for an end time).
fn parse_hhmm(s: &str) -> Option<u16> {
    let (h, m) = s.trim().split_once(':')?;
    let h: u16 = h.parse().ok()?;
    let m: u16 = m.parse().ok()?;
    if m >= 60 || h > 24 || (h == 24 && m != 0) {
        return None;
    }
    Some(h * 60 + m)
}

/// A `datetime-local` value (`YYYY-MM-DDTHH:MM`, optional `:SS`, `T` or space), read
/// as UTC, to Unix seconds. `None` for anything malformed or an impossible civil date.
fn parse_datetime_local_utc(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, time) = s.split_once('T').or_else(|| s.split_once(' '))?;
    let mut d = date.split('-');
    let year: i64 = d.next()?.parse().ok()?;
    let month: u32 = d.next()?.parse().ok()?;
    let day: u32 = d.next()?.parse().ok()?;
    if d.next().is_some() || !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return None;
    }
    let mut t = time.split(':');
    let hour: i64 = t.next()?.parse().ok()?;
    let minute: i64 = t.next()?.parse().ok()?;
    let second: i64 = match t.next() {
        Some(sec) => sec.parse().ok()?,
        None => 0,
    };
    if t.next().is_some() || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Unix seconds -> the `datetime-local` value that pre-fills the form (`YYYY-MM-DDTHH:MM`).
fn datetime_local_value(secs: i64) -> String {
    format_utc_ymd_hm(secs).replacen(' ', "T", 1)
}

/// The pure form -> policy translation (`Err` = the `400` text). An unrestricted result
/// (no expiry, no schedule) is a valid answer and means "clear".
pub(super) fn policy_from_form(form: &AccessForm, now: i64) -> Result<AccessPolicy, String> {
    let expires_at = match form.expiry_mode.as_deref().map(str::trim) {
        None | Some("") | Some("none") => None,
        Some("at") => {
            let raw = form.expires_at.as_deref().unwrap_or("").trim();
            if raw.is_empty() {
                return Err("expiry: pick a date and time, or choose \"no expiry\"".to_string());
            }
            let at = parse_datetime_local_utc(raw)
                .ok_or_else(|| "expiry: not a valid date and time (expected YYYY-MM-DDTHH:MM, UTC)".to_string())?;
            if at <= now {
                return Err("expiry must be in the future".to_string());
            }
            Some(at)
        }
        Some("in") => {
            let hours: i64 = form
                .expires_in_hours
                .as_deref()
                .unwrap_or("")
                .trim()
                .parse()
                .map_err(|_| "expiry: \"in N hours\" needs a whole number of hours".to_string())?;
            if !(1..=MAX_EXPIRES_IN_HOURS).contains(&hours) {
                return Err(format!("expiry: hours must be between 1 and {MAX_EXPIRES_IN_HOURS}"));
            }
            Some(now + hours * 3_600)
        }
        Some(other) => return Err(format!("expiry: unknown mode {other:?}")),
    };
    let schedule = if form.schedule.is_some() {
        let days = form.days();
        if days.is_empty() {
            return Err("schedule: pick at least one day, or untick the schedule".to_string());
        }
        let start = parse_hhmm(form.start.as_deref().unwrap_or(""))
            .ok_or_else(|| "schedule: start must be a time like 09:00".to_string())?;
        let end = parse_hhmm(form.end.as_deref().unwrap_or(""))
            .ok_or_else(|| "schedule: end must be a time like 17:00 (24:00 for end of day)".to_string())?;
        if start >= MINUTES_PER_DAY {
            return Err("schedule: start must be before 24:00".to_string());
        }
        // The form models a same-day window only; a slot that wraps past midnight is
        // expressible in the shared type but not from these two time inputs.
        if end <= start {
            return Err("schedule: end must be after start".to_string());
        }
        let tz_offset_minutes: i32 = form
            .tz_offset
            .as_deref()
            .unwrap_or("0")
            .trim()
            .parse()
            .map_err(|_| "schedule: timezone offset must be a number of minutes".to_string())?;
        let schedule = WeeklySchedule {
            tz_offset_minutes,
            slots: days.into_iter().map(|day| Slot { day, start_minute: start, end_minute: end }).collect(),
        };
        schedule.validate().map_err(|e| format!("schedule: {e}"))?;
        Some(schedule)
    } else {
        None
    };
    let policy = AccessPolicy { expires_at, schedule };
    policy.validate().map_err(|e| e.to_string())?;
    Ok(policy)
}

/// `POST /portal/tunnels/:id/access`: save the form (or, with `rearm`, keep the
/// schedule and set a fresh 24 h expiry). Owner-scoped through the store -- an unknown
/// or foreign id is a `404`, never a `403` ("existence leaks nothing", the posture of
/// every other owner-scoped tunnel action). `400` with a plain-text reason when the
/// form does not describe a valid window. A form that describes no restriction at
/// all clears the policy instead of storing an empty one.
async fn set_access(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<AccessForm>,
) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    let now = now_secs();
    let policy = if form.rearm.is_some() {
        let existing = match st.tunnels.access_policy(&subject, &id) {
            Ok(p) => p,
            Err(e) => return internal_error("access/rearm", e).into_response(),
        };
        AccessPolicy { expires_at: Some(now + REARM_SECS), schedule: existing.and_then(|p| p.schedule) }
    } else {
        match policy_from_form(&form, now) {
            Ok(p) => p,
            Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
        }
    };
    if policy.is_unrestricted() {
        return clear_for(&st, &subject, &id).await;
    }
    match st.tunnels.set_access_policy(&subject, &id, &policy, now) {
        Ok(true) => {}
        Ok(false) => return (StatusCode::NOT_FOUND, "unknown tunnel").into_response(),
        Err(e) => return internal_error("access/set", e).into_response(),
    }
    let json = serde_json::to_string(&policy).unwrap_or_default();
    if let Some(audit) = &st.audit {
        let _ = audit.record(&subject, AUDIT_SET, Some(&id), Some(&json));
    }
    push_for_tunnel(&st, &subject, &id, Some(&policy)).await;
    Redirect::to("/portal/tunnels").into_response()
}

/// `POST /portal/tunnels/:id/access/clear`: back to unrestricted. Same owner scoping
/// and `404` posture as [`set_access`]; idempotent.
async fn clear_access(State(st): State<ApiState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    clear_for(&st, &subject, &id).await
}

async fn clear_for(st: &ApiState, subject: &str, id: &str) -> Response {
    match st.tunnels.clear_access_policy(subject, id) {
        Ok(true) => {}
        Ok(false) => return (StatusCode::NOT_FOUND, "unknown tunnel").into_response(),
        Err(e) => return internal_error("access/clear", e).into_response(),
    }
    if let Some(audit) = &st.audit {
        let _ = audit.record(subject, AUDIT_CLEARED, Some(id), None);
    }
    push_for_tunnel(st, subject, id, None).await;
    Redirect::to("/portal/tunnels").into_response()
}

/// Resolve the owner's tunnel to its routing token and push `policy` to the edge.
async fn push_for_tunnel(st: &ApiState, subject: &str, id: &str, policy: Option<&AccessPolicy>) {
    match st.tunnels.routing_token(subject, id) {
        Ok(Some(token)) => push_access_policy(st, &token, policy).await,
        Ok(None) => {}
        Err(e) => eprintln!(
            "ct-cp: access window for tunnel {id}: routing token lookup failed ({e}) -- edge not updated (#779)"
        ),
    }
}

/// Hand one tunnel's access window (or its removal, `None`) to the edge's admin
/// listener -- the same push shape as `authorize_hostname`'s authorize-host call
/// (shared admin secret, routing token in `x-ct-routing-token`, never the URL), and
/// the same best-effort contract: logged, never fails the caller. The edge evaluates
/// the policy locally from then on; a push that fails leaves the edge on whatever it
/// last had until the next push or its next boot-time rehydration.
pub(super) async fn push_access_policy(st: &ApiState, routing_token: &str, policy: Option<&AccessPolicy>) {
    let Some(edge) = &st.edge_admin else {
        eprintln!(
            "ct-cp: access-window push SKIPPED -- edge admin API not configured \
             (set CT_CP_EDGE_ADMIN_URL + CT_CP_EDGE_ADMIN_TOKEN); the edge will not enforce it (#779)"
        );
        return;
    };
    let endpoint = format!("{}/internal/tunnel/access-policy", edge.url.trim_end_matches('/'));
    let what = if policy.is_some() { "set" } else { "clear" };
    match edge_admin_http_client()
        .post(&endpoint)
        .header("x-ct-admin-token", edge.token.as_ref())
        .header("x-ct-routing-token", routing_token)
        .json(&policy)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => eprintln!("ct-cp: access-window {what} pushed to the edge (#779)"),
        Ok(r) => eprintln!("ct-cp: access-window {what} push returned {} from the edge (#779)", r.status()),
        Err(e) => eprintln!("ct-cp: access-window {what} push to the edge failed: {e} (#779)"),
    }
}

/// Called from `authorize_hostname` right after a successful authorize-host: if the
/// tunnel has a window on file, send it along so the edge never serves a freshly
/// authorized hostname without its policy. Nothing on file = nothing to push (the
/// edge's default for a token it has no policy for is unrestricted).
pub(super) async fn push_current_access_policy(st: &ApiState, routing_token: &str) {
    match st.tunnels.access_policy_for_token(routing_token) {
        Ok(Some(p)) => push_access_policy(st, routing_token, Some(&p)).await,
        Ok(None) => {}
        Err(e) => eprintln!("ct-cp: access policy lookup for a fresh authorization failed: {e} (#779)"),
    }
}

/// The one-line state a reader wants first, plus whether the "Re-arm" button applies.
fn state_line(policy: Option<&AccessPolicy>, now: i64) -> (String, bool) {
    let Some(p) = policy else {
        return ("Open · no restriction".to_string(), false);
    };
    let until = |at: i64| format!("in {} ({} UTC)", human_duration((at - now).max(0) as u64), format_utc_ymd_hm(at));
    if p.is_expired(now) {
        let at = p.expires_at.unwrap_or(now);
        return (format!("Closed · expired at {} UTC", format_utc_ymd_hm(at)), true);
    }
    let next = p.next_change(now);
    let line = match (p.is_open(now), next) {
        (true, Some(at)) if Some(at) == p.expires_at => format!("Open · expires {}", until(at)),
        (true, Some(at)) => format!("Open · closes {}", until(at)),
        (true, None) => "Open".to_string(),
        (false, Some(at)) => format!("Closed · opens {}", until(at)),
        (false, None) => "Closed · no reopening scheduled".to_string(),
    };
    (line, false)
}

/// The `<select name="tz_offset">` choices: whole hours from UTC-12 to UTC+14 plus the
/// two common half-hour zones, labeled the way a settings page usually does.
fn tz_options(selected: i32) -> String {
    let mut offsets: Vec<i32> = (-12..=14).map(|h| h * 60).collect();
    offsets.extend([330, 570]);
    offsets.sort_unstable();
    offsets
        .into_iter()
        .map(|m| {
            let sign = if m < 0 { '-' } else { '+' };
            let label = format!("UTC{sign}{:02}:{:02}", m.abs() / 60, m.abs() % 60);
            let sel = if m == selected { " selected" } else { "" };
            format!(r#"<option value="{m}"{sel}>{label}</option>"#)
        })
        .collect()
}

/// The card block, with the wall clock read here so `tunnels_html` stays pure.
pub(super) fn card_block_now(escaped_id: &str, policy: Option<&AccessPolicy>) -> String {
    card_block(escaped_id, policy, now_secs())
}

/// The "Access window" block of one tunnel card: state line, the edit form (pre-filled
/// from the current policy), Clear, and -- once expired -- "Re-arm 24 h". `escaped_id`
/// is the tunnel id as `tunnels_html` already escaped it; every other value is a
/// number or a string this module formatted itself.
pub(super) fn card_block(escaped_id: &str, policy: Option<&AccessPolicy>, now: i64) -> String {
    let id = escaped_id;
    let (state, expired) = state_line(policy, now);
    let rearm = if expired {
        format!(
            r#" <form class="inline" method="post" action="/portal/tunnels/{id}/access"><input type="hidden" name="rearm" value="1"><button type="submit" class="btn">Re-arm 24 h</button></form>"#
        )
    } else {
        String::new()
    };
    let expires_at = policy.and_then(|p| p.expires_at);
    let (mode_none, mode_at) = if expires_at.is_some() { ("", " checked") } else { (" checked", "") };
    let at_value = expires_at.map(datetime_local_value).unwrap_or_default();
    let schedule = policy.and_then(|p| p.schedule.as_ref());
    let schedule_checked = if schedule.is_some() { " checked" } else { "" };
    let (start, end) = schedule
        .and_then(|s| s.slots.first())
        .map(|s| (s.start_minute, s.end_minute))
        .unwrap_or((9 * 60, 17 * 60));
    let hhmm = |m: u16| format!("{:02}:{:02}", m / 60, m % 60);
    let days: String = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let checked = match schedule {
                Some(s) => s.slots.iter().any(|slot| usize::from(slot.day) == i),
                None => i < 5,
            };
            let checked = if checked { " checked" } else { "" };
            format!(r#"<label><input type="checkbox" name="day{i}" value="on"{checked}> {label}</label> "#)
        })
        .collect();
    let tz = tz_options(schedule.map(|s| s.tz_offset_minutes).unwrap_or(0));
    format!(
        r#"<div class="row access-window"><span class="k">Access window:</span> <span class="v">{state}</span>{rearm}</div>
<details class="access-window"><summary class="row"><span class="k">Edit access window</span></summary>
<form method="post" action="/portal/tunnels/{id}/access">
 <fieldset><legend>Expiry (UTC)</legend>
  <label><input type="radio" name="expiry_mode" value="none"{mode_none}> No expiry</label>
  <label><input type="radio" name="expiry_mode" value="at"{mode_at}> At <input type="datetime-local" name="expires_at" value="{at_value}"> UTC</label>
  <label><input type="radio" name="expiry_mode" value="in"> In <input type="number" name="expires_in_hours" min="1" max="{max_hours}" value="24" size="5"> hours</label>
 </fieldset>
 <fieldset><legend>Weekly schedule</legend>
  <label><input type="checkbox" name="schedule" value="on"{schedule_checked}> Only during these hours</label>
  <div class="days">{days}</div>
  <label>From <input type="time" name="start" value="{start}"></label> <label>to <input type="time" name="end" value="{end}"></label>
  <label>Timezone <select name="tz_offset">{tz}</select></label>
 </fieldset>
 <button type="submit" class="sec">Save</button>
</form>
<form class="inline" method="post" action="/portal/tunnels/{id}/access/clear"><button type="submit" class="sec">Clear</button></form>
<span class="help">Outside the window the edge answers visitors with a 503 page; the agent stays connected.</span>
</details>"#,
        max_hours = MAX_EXPIRES_IN_HOURS,
        start = hhmm(start),
        end = hhmm(end),
    )
}

#[cfg(test)]
mod tests {
    use super::super::{
        portal_api_router_with_verifier, SqliteBootstrap, SqliteEnrollment, SqliteLedger, SqliteTunnelStore,
    };
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    const KEY: &[u8] = b"portal-access-test-key";

    fn session(subject: &str) -> String {
        format!("ct_portal_session={}", crate::portal::sign_session_for_test(KEY, subject))
    }

    /// The portal router with an in-memory tunnel store, an audit log, and (optionally)
    /// an edge admin endpoint -- the three things these routes touch.
    fn app(
        edge_admin: Option<(String, String)>,
    ) -> (Router, Arc<SqliteTunnelStore>, Arc<crate::audit_log::SqliteAuditLog>) {
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let audit = Arc::new(crate::audit_log::SqliteAuditLog::open_in_memory().unwrap());
        let edge_mesh = crate::edge_mesh::EdgeMeshHandle::new(
            Arc::new(crate::edge_mesh::SqliteEdgeMesh::open_in_memory().unwrap()),
            Arc::from("test-edge"),
        );
        let router = portal_api_router_with_verifier(
            KEY,
            Arc::new(SqliteLedger::open_in_memory().unwrap()),
            tunnels.clone(),
            Arc::new(SqliteEnrollment::open_in_memory().unwrap()),
            Arc::new(SqliteBootstrap::open_in_memory().unwrap()),
            "https://portal.example",
            edge_admin,
            None,
            None,
            None,
            edge_mesh,
            None,
            None,
            Some(audit.clone()),
            None,
            Arc::new(crate::storage::SqliteChannelStore::open_in_memory().unwrap()),
        );
        (router, tunnels, audit)
    }

    async fn post_form(app: &Router, path: &str, subject: &str, form: &str) -> axum::response::Response {
        app.clone()
            .oneshot(
                Request::post(path)
                    .header("cookie", session(subject))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn body_text(resp: axum::response::Response) -> String {
        String::from_utf8(to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap()
    }

    /// One recorded push: `(routing token header, JSON body)`.
    type Pushes = Arc<Mutex<Vec<(String, serde_json::Value)>>>;

    /// A mock edge admin listener recording every access-policy push (and asserting the
    /// admin token), plus a tunnel-status route so the tunnels page can render.
    async fn mock_edge() -> (String, Pushes) {
        use axum::routing::get;
        let pushes: Pushes = Arc::new(Mutex::new(Vec::new()));
        let recorded = pushes.clone();
        let router = Router::new()
            .route(
                "/internal/tunnel/access-policy",
                axum::routing::post(move |headers: HeaderMap, axum::Json(body): axum::Json<serde_json::Value>| {
                    let recorded = recorded.clone();
                    async move {
                        assert_eq!(
                            headers.get("x-ct-admin-token").and_then(|v| v.to_str().ok()),
                            Some("edge-secret"),
                            "the push authenticates like every other edge-admin call"
                        );
                        let token =
                            headers.get("x-ct-routing-token").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                        recorded.lock().unwrap().push((token, body));
                        StatusCode::OK
                    }
                }),
            )
            .route("/admin/tunnel-status/:token", get(|| async { axum::Json(serde_json::json!({"connected": false})) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (format!("http://{addr}"), pushes)
    }

    fn utc(year: i64, month: u32, day: u32, hour: i64, minute: i64) -> i64 {
        days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60
    }

    #[test]
    fn form_parsing_covers_expiry_modes_schedule_and_rejections() {
        let now = utc(2026, 9, 7, 12, 0);
        // Nothing selected: unrestricted (= clear).
        assert!(policy_from_form(&AccessForm::default(), now).unwrap().is_unrestricted());
        // "at": read as UTC, must be in the future.
        let f = AccessForm { expiry_mode: Some("at".into()), expires_at: Some("2026-09-11T00:00".into()), ..Default::default() };
        assert_eq!(policy_from_form(&f, now).unwrap().expires_at, Some(utc(2026, 9, 11, 0, 0)));
        let f = AccessForm { expiry_mode: Some("at".into()), expires_at: Some("2026-09-07T11:59".into()), ..Default::default() };
        assert!(policy_from_form(&f, now).unwrap_err().contains("future"));
        let f = AccessForm { expiry_mode: Some("at".into()), expires_at: Some("2026-02-30T10:00".into()), ..Default::default() };
        assert!(policy_from_form(&f, now).unwrap_err().contains("not a valid"), "Feb 30");
        let f = AccessForm { expiry_mode: Some("at".into()), expires_at: Some("".into()), ..Default::default() };
        assert!(policy_from_form(&f, now).is_err(), "mode 'at' with no value");
        // "in": whole hours, bounded.
        let f = AccessForm { expiry_mode: Some("in".into()), expires_in_hours: Some("24".into()), ..Default::default() };
        assert_eq!(policy_from_form(&f, now).unwrap().expires_at, Some(now + 24 * 3_600));
        let f = AccessForm { expiry_mode: Some("in".into()), expires_in_hours: Some("0".into()), ..Default::default() };
        assert!(policy_from_form(&f, now).is_err());
        let f = AccessForm { expiry_mode: Some("in".into()), expires_in_hours: Some("1.5".into()), ..Default::default() };
        assert!(policy_from_form(&f, now).is_err());
        // Schedule: days + hours + offset become one slot per day.
        let f = AccessForm {
            schedule: Some("on".into()),
            day0: Some("on".into()),
            day2: Some("on".into()),
            start: Some("09:00".into()),
            end: Some("17:30".into()),
            tz_offset: Some("120".into()),
            ..Default::default()
        };
        let p = policy_from_form(&f, now).unwrap();
        let s = p.schedule.unwrap();
        assert_eq!(s.tz_offset_minutes, 120);
        assert_eq!(s.slots, vec![Slot { day: 0, start_minute: 540, end_minute: 1050 }, Slot { day: 2, start_minute: 540, end_minute: 1050 }]);
        // end <= start -> 400.
        let f = AccessForm { end: Some("09:00".into()), ..f };
        assert!(policy_from_form(&f, now).unwrap_err().contains("end must be after start"));
        let f = AccessForm { end: Some("08:00".into()), ..f };
        assert!(policy_from_form(&f, now).unwrap_err().contains("end must be after start"));
        // 24:00 is a valid end of day; no days is a 400; a bad offset is a 400.
        let f = AccessForm { end: Some("24:00".into()), ..f };
        assert_eq!(policy_from_form(&f, now).unwrap().schedule.unwrap().slots[0].end_minute, 1440);
        let f = AccessForm { day0: None, day2: None, ..f };
        assert!(policy_from_form(&f, now).unwrap_err().contains("at least one day"));
        let f = AccessForm { day0: Some("on".into()), tz_offset: Some("900".into()), ..f };
        assert!(policy_from_form(&f, now).unwrap_err().contains("timezone"));
        let f = AccessForm { tz_offset: Some("abc".into()), ..f };
        assert!(policy_from_form(&f, now).is_err());
        let f = AccessForm { tz_offset: Some("0".into()), start: Some("9am".into()), ..f };
        assert!(policy_from_form(&f, now).unwrap_err().contains("start"));
    }

    #[test]
    fn datetime_local_parsing_and_prefill_round_trip() {
        assert_eq!(parse_datetime_local_utc("2026-09-07T00:00"), Some(1_788_739_200));
        assert_eq!(parse_datetime_local_utc("2026-09-07 00:00:30"), Some(1_788_739_230));
        assert_eq!(parse_datetime_local_utc("2024-02-29T23:59"), Some(utc(2024, 2, 29, 23, 59)), "leap day");
        assert_eq!(parse_datetime_local_utc("2023-02-29T00:00"), None, "not a leap year");
        assert_eq!(parse_datetime_local_utc("2026-13-01T00:00"), None);
        assert_eq!(parse_datetime_local_utc("2026-09-07T24:00"), None);
        assert_eq!(parse_datetime_local_utc("2026-09-07"), None);
        assert_eq!(parse_datetime_local_utc("garbage"), None);
        assert_eq!(datetime_local_value(1_788_739_200), "2026-09-07T00:00");
        assert_eq!(parse_hhmm("24:00"), Some(1440));
        assert_eq!(parse_hhmm("24:01"), None);
        assert_eq!(parse_hhmm("7:05"), Some(425));
        assert_eq!(parse_hhmm("07:60"), None);
    }

    #[test]
    fn state_line_names_open_closed_expired_and_countdowns() {
        let now = utc(2026, 9, 7, 12, 0);
        assert_eq!(state_line(None, now), ("Open · no restriction".to_string(), false));
        let expiring = AccessPolicy { expires_at: Some(now + 2 * 3_600), schedule: None };
        let (line, rearm) = state_line(Some(&expiring), now);
        assert_eq!(line, "Open · expires in 2 h 0 m (2026-09-07 14:00 UTC)");
        assert!(!rearm);
        let expired = AccessPolicy { expires_at: Some(now - 60), schedule: None };
        let (line, rearm) = state_line(Some(&expired), now);
        assert_eq!(line, "Closed · expired at 2026-09-07 11:59 UTC");
        assert!(rearm, "an expired policy offers Re-arm");
        // Mon 09-17 UTC: at noon open until 17:00; at 18:00 closed until next Monday.
        let sched = AccessPolicy {
            expires_at: None,
            schedule: Some(WeeklySchedule { tz_offset_minutes: 0, slots: vec![Slot { day: 0, start_minute: 540, end_minute: 1020 }] }),
        };
        assert_eq!(state_line(Some(&sched), now).0, "Open · closes in 5 h 0 m (2026-09-07 17:00 UTC)");
        assert_eq!(state_line(Some(&sched), now + 6 * 3_600).0, "Closed · opens in 6 d 15 h (2026-09-14 09:00 UTC)");
        let never = AccessPolicy { expires_at: None, schedule: Some(WeeklySchedule { tz_offset_minutes: 0, slots: vec![] }) };
        assert_eq!(state_line(Some(&never), now).0, "Closed · no reopening scheduled");
    }

    #[test]
    fn card_block_prefills_the_form_from_the_current_policy_and_offers_rearm_when_expired() {
        let now = utc(2026, 9, 7, 12, 0);
        let html = card_block("t-1", None, now);
        assert!(html.contains(r#"action="/portal/tunnels/t-1/access""#));
        assert!(html.contains(r#"action="/portal/tunnels/t-1/access/clear""#));
        assert!(html.contains(r#"value="none" checked"#), "no expiry selected: {html}");
        assert!(!html.contains("Re-arm 24 h"));
        assert!(html.contains(r#"name="day0" value="on" checked"#) && html.contains(r#"name="day5" value="on"> Sat"#), "weekdays pre-ticked by default");
        assert!(html.contains(r#"<option value="0" selected>UTC+00:00</option>"#));
        assert!(html.contains(r#"<option value="330">UTC+05:30</option>"#));

        let p = AccessPolicy {
            expires_at: Some(utc(2026, 9, 11, 8, 30)),
            schedule: Some(WeeklySchedule { tz_offset_minutes: -300, slots: vec![Slot { day: 2, start_minute: 600, end_minute: 1080 }] }),
        };
        let html = card_block("t-1", Some(&p), now);
        assert!(html.contains(r#"value="at" checked"#));
        assert!(html.contains(r#"name="expires_at" value="2026-09-11T08:30""#));
        assert!(html.contains(r#"name="schedule" value="on" checked"#));
        assert!(html.contains(r#"name="day2" value="on" checked"#) && html.contains(r#"name="day0" value="on"> Mon"#));
        assert!(html.contains(r#"name="start" value="10:00""#) && html.contains(r#"name="end" value="18:00""#));
        assert!(html.contains(r#"<option value="-300" selected>UTC-05:00</option>"#));
        assert!(html.contains("Closed · opens in"), "Monday noon is outside a Wednesday slot: {html}");

        let expired = AccessPolicy { expires_at: Some(now - 1), schedule: None };
        let html = card_block("t-1", Some(&expired), now);
        assert!(html.contains("Re-arm 24 h") && html.contains(r#"name="rearm""#), "{html}");
    }

    #[tokio::test]
    async fn set_and_clear_routes_are_owner_scoped_validate_audit_and_push_to_the_edge() {
        let (edge_url, pushes) = mock_edge().await;
        let (app, tunnels, audit) = app(Some((edge_url, "edge-secret".to_string())));
        let t = tunnels.create("alice", "shop", Some("shop.example.com")).unwrap().created().unwrap();
        let path = format!("/portal/tunnels/{}/access", t.id);

        // No session -> the portal login, nothing stored.
        let anon = app
            .clone()
            .oneshot(
                Request::post(&path)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("expiry_mode=in&expires_in_hours=1"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(anon.status(), StatusCode::SEE_OTHER);
        assert_eq!(anon.headers().get("location").unwrap(), "/portal");

        // end <= start -> 400 with the reason, nothing stored, nothing pushed.
        let bad = post_form(&app, &path, "alice", "schedule=on&day0=on&start=17%3A00&end=09%3A00").await;
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(bad).await.contains("end must be after start"));
        assert_eq!(tunnels.access_policy("alice", &t.id).unwrap(), None);
        assert!(pushes.lock().unwrap().is_empty());

        // A stranger's set is a 404 (never a 403), nothing stored.
        assert_eq!(post_form(&app, &path, "mallory", "expiry_mode=in&expires_in_hours=2").await.status(), StatusCode::NOT_FOUND);
        assert_eq!(tunnels.access_policy("alice", &t.id).unwrap(), None);
        assert_eq!(post_form(&app, "/portal/tunnels/no-such-id/access", "alice", "expiry_mode=in&expires_in_hours=2").await.status(), StatusCode::NOT_FOUND);

        // The owner: stored, audited, pushed with the tunnel's routing token.
        let before = now_secs();
        let ok = post_form(&app, &path, "alice", "expiry_mode=in&expires_in_hours=2&schedule=on&day0=on&day4=on&start=09%3A00&end=17%3A00&tz_offset=60").await;
        assert_eq!(ok.status(), StatusCode::SEE_OTHER);
        assert_eq!(ok.headers().get("location").unwrap(), "/portal/tunnels");
        let stored = tunnels.access_policy("alice", &t.id).unwrap().expect("stored");
        let expires_at = stored.expires_at.expect("expiry");
        assert!((before + 2 * 3_600..=before + 2 * 3_600 + 5).contains(&expires_at));
        let sched = stored.schedule.as_ref().unwrap();
        assert_eq!(sched.tz_offset_minutes, 60);
        assert_eq!(sched.slots.iter().map(|s| s.day).collect::<Vec<_>>(), vec![0, 4]);
        let entries = audit.recent(10).unwrap();
        assert_eq!(entries[0].action, AUDIT_SET);
        assert_eq!(entries[0].actor_email, "alice");
        assert_eq!(entries[0].target.as_deref(), Some(t.id.as_str()));
        assert!(entries[0].detail.as_deref().unwrap().contains(r#""tz_offset_minutes":60"#), "detail is the policy JSON");
        {
            let p = pushes.lock().unwrap();
            assert_eq!(p.len(), 1, "one push per change");
            assert_eq!(p[0].0, t.routing_token, "routing token rides in the header");
            assert_eq!(p[0].1["expires_at"], expires_at);
            assert_eq!(p[0].1["schedule"]["slots"][1]["day"], 4);
        }

        // The tunnels page shows the state and pre-fills the form.
        let page = app
            .clone()
            .oneshot(Request::get("/portal/tunnels").header("cookie", session("alice")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(page.status(), StatusCode::OK);
        let html = body_text(page).await;
        assert!(html.contains("Access window:"), "{html}");
        assert!(html.contains(r#"name="schedule" value="on" checked"#), "{html}");
        assert!(html.contains(r#"<option value="60" selected>UTC+01:00</option>"#), "{html}");

        // A stranger's clear is a 404 and leaves it; the owner's clear removes, audits, pushes null.
        assert_eq!(post_form(&app, &format!("{path}/clear"), "mallory", "").await.status(), StatusCode::NOT_FOUND);
        assert!(tunnels.access_policy("alice", &t.id).unwrap().is_some());
        let cleared = post_form(&app, &format!("{path}/clear"), "alice", "").await;
        assert_eq!(cleared.status(), StatusCode::SEE_OTHER);
        assert_eq!(tunnels.access_policy("alice", &t.id).unwrap(), None);
        assert_eq!(audit.recent(10).unwrap()[0].action, AUDIT_CLEARED);
        {
            let p = pushes.lock().unwrap();
            assert_eq!(p.len(), 2);
            assert_eq!(p[1].0, t.routing_token);
            assert!(p[1].1.is_null(), "clear pushes null: {}", p[1].1);
        }

        // A form describing no restriction at all is a clear, not an empty policy row.
        assert_eq!(post_form(&app, &path, "alice", "expiry_mode=none").await.status(), StatusCode::SEE_OTHER);
        assert_eq!(tunnels.access_policy("alice", &t.id).unwrap(), None);
        assert!(pushes.lock().unwrap()[2].1.is_null());
    }

    #[tokio::test]
    async fn rearm_keeps_the_schedule_and_sets_a_fresh_24h_expiry() {
        let (app, tunnels, _audit) = app(None); // no edge admin: the push is skipped, the route still works
        let t = tunnels.create("alice", "shop", Some("shop.example.com")).unwrap().created().unwrap();
        let schedule = WeeklySchedule { tz_offset_minutes: 0, slots: vec![Slot { day: 0, start_minute: 0, end_minute: 1440 }] };
        let expired = AccessPolicy { expires_at: Some(1), schedule: Some(schedule.clone()) };
        assert!(tunnels.set_access_policy("alice", &t.id, &expired, 1).unwrap());

        let path = format!("/portal/tunnels/{}/access", t.id);
        assert_eq!(post_form(&app, &path, "mallory", "rearm=1").await.status(), StatusCode::NOT_FOUND);
        assert_eq!(tunnels.access_policy("alice", &t.id).unwrap().unwrap().expires_at, Some(1), "untouched");

        let before = now_secs();
        assert_eq!(post_form(&app, &path, "alice", "rearm=1").await.status(), StatusCode::SEE_OTHER);
        let p = tunnels.access_policy("alice", &t.id).unwrap().unwrap();
        let e = p.expires_at.unwrap();
        assert!((before + REARM_SECS..=before + REARM_SECS + 5).contains(&e), "24 h from now");
        assert_eq!(p.schedule, Some(schedule), "the schedule survives a re-arm");
        assert!(!p.is_expired(before + 60), "no longer expired");
    }
}
