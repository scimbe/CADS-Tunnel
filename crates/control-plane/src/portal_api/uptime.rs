//! #778 / #783: the per-tunnel "Uptime & usage" page with its opt-in public uptime
//! badge, and the account-level usage page + CSV export -- all fed by the edge's
//! session history (`edge_tunnel_history`, #776/#784).
//!
//! A child module of `portal_api` (rather than a sibling crate module) so it can use
//! that module's private state and helpers -- `ApiState`, `edge_tunnel_history`, the
//! `human_*` formatters, `page` -- without widening any of their visibility. Everything
//! here is registered through [`routes`], merged into the portal API router at one
//! call site, so the parent's own route table stays untouched.

use super::*;
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE};

/// Sessions asked of the edge per tunnel for the uptime page and the usage page -- the
/// edge route's own cap (`crates/edge/src/admin.rs`). The 30-day aggregation in
/// [`usage_from_history`] is computed over these newest-first rows, so a tunnel that
/// flapped more than 200 times in 30 days under-counts its oldest sessions; the page
/// says "up to 200" next to the table for that reason.
pub(super) const UPTIME_HISTORY_SESSIONS: usize = 200;

/// Sessions asked of the edge for the PUBLIC badge: the badge only renders the edge's
/// own 7-day uptime figure (in the payload regardless of `limit`), never a session, and
/// it is an unauthenticated, cacheable route -- so it asks for the cheapest possible
/// answer rather than 200 rows per hit.
const BADGE_HISTORY_SESSIONS: usize = 1;

const DAY_SECS: i64 = 86_400;
const WINDOW_30D_SECS: i64 = 30 * DAY_SECS;

/// #783: a tunnel's last-30-days usage, aggregated from its edge history by
/// [`usage_from_history`].
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(super) struct UsageSummary {
    /// Sessions that overlap the 30-day window (see [`usage_from_history`]).
    pub(super) sessions_30d: u64,
    /// Relay-plane bytes of those sessions, whole sessions (not clipped to the window).
    pub(super) bytes_in_30d: u64,
    pub(super) bytes_out_30d: u64,
    /// The edge's own 30-day uptime percentage, passed through (0..=100).
    pub(super) uptime_d30: f64,
    /// Longest stretch inside the window with no session open, in seconds; 0 when the
    /// tunnel was never observed down inside the window (or has no history at all).
    pub(super) longest_outage_secs_30d: u64,
}

/// #783: aggregate an edge history into its last-30-days [`UsageSummary`], `now` being
/// unix seconds. Pure; the window is `[now - 30 d, now]`.
///
/// Simplifications, deliberately (the edge's rows are per session, not per second):
/// * a session COUNTS when it overlaps the window at all (its end -- or `now`, for a
///   still-open one -- is at or after the window start), and then its bytes count in
///   FULL, even for the part that lies before the window; bytes are per session on the
///   edge, so clipping them proportionally would only invent precision;
/// * the longest outage is the largest gap between "the latest end of any session seen
///   so far" and the next session's start (so two overlapping legs -- a QUIC and a
///   TCP-fallback session open at once -- never produce a phantom gap), clipped to the
///   window, plus the tail from the last closed session's end to `now` when nothing is
///   open; a gap BEFORE the oldest known session is not an outage (no data, not
///   downtime);
/// * the 30-day uptime is the edge's own figure, not recomputed here.
pub(super) fn usage_from_history(h: &EdgeTunnelHistory, now: i64) -> UsageSummary {
    let window_start = now.saturating_sub(WINDOW_30D_SECS);
    let mut summary = UsageSummary {
        uptime_d30: h.uptime.d30,
        ..Default::default()
    };
    // Oldest first, whatever order the edge sent them in.
    let mut sessions: Vec<&EdgeSessionRow> = h.sessions.iter().collect();
    sessions.sort_by_key(|s| s.connected_at);
    let mut covered_until: Option<i64> = None;
    for s in sessions {
        let end = s.disconnected_at.unwrap_or(now);
        if end >= window_start {
            summary.sessions_30d += 1;
            summary.bytes_in_30d = summary.bytes_in_30d.saturating_add(s.bytes_in);
            summary.bytes_out_30d = summary.bytes_out_30d.saturating_add(s.bytes_out);
        }
        if let Some(prev_end) = covered_until {
            let gap = gap_secs(prev_end, s.connected_at, window_start, now);
            summary.longest_outage_secs_30d = summary.longest_outage_secs_30d.max(gap);
        }
        covered_until = Some(covered_until.map_or(end, |c| c.max(end)));
    }
    // The tail: from the last end to now. Zero whenever a session is still open, since
    // that session's `end` is `now` itself.
    if let Some(prev_end) = covered_until {
        let gap = gap_secs(prev_end, now, window_start, now);
        summary.longest_outage_secs_30d = summary.longest_outage_secs_30d.max(gap);
    }
    summary
}

/// The part of `[from, to]` that lies inside `[window_start, now]`, in seconds; 0 when
/// empty or inverted.
fn gap_secs(from: i64, to: i64, window_start: i64, now: i64) -> u64 {
    let start = from.max(window_start);
    let end = to.min(now);
    u64::try_from(end.saturating_sub(start)).unwrap_or(0)
}

/// #778: the public badge as a shields-style flat SVG -- left label `uptime 7d`, right
/// value `98.4 %` coloured green (>= 99), yellow (>= 95) or red, or a grey `n/a` when
/// the edge had no history. Carries NOTHING else: no hostname, id, token or timestamp
/// (the `<title>` repeats the visible text for screen readers, that is all).
pub(super) fn badge_svg(uptime_7d: Option<f64>) -> String {
    const LABEL: &str = "uptime 7d";
    let (value, colour) = match uptime_7d {
        Some(p) if p.is_finite() => {
            let p = p.clamp(0.0, 100.0);
            let colour = if p >= 99.0 {
                "#4c1"
            } else if p >= 95.0 {
                "#dfb317"
            } else {
                "#e05d44"
            };
            (human_pct(p), colour)
        }
        _ => ("n/a".to_string(), "#9f9f9f"),
    };
    // ~7 px per glyph at Verdana 11 px, plus 5 px of padding each side -- the same
    // rough metric shields.io's flat style uses, precise enough for a two-word badge.
    let text_width = |s: &str| u32::try_from(s.chars().count()).unwrap_or(0) * 7 + 10;
    let label_w = text_width(LABEL);
    let value_w = text_width(&value);
    let total_w = label_w + value_w;
    let label_x = f64::from(label_w) / 2.0;
    let value_x = f64::from(label_w) + f64::from(value_w) / 2.0;
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20" role="img" aria-label="{LABEL}: {value}"><title>{LABEL}: {value}</title><linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><clipPath id="r"><rect width="{total_w}" height="20" rx="3" fill="#fff"/></clipPath><g clip-path="url(#r)"><rect width="{label_w}" height="20" fill="#555"/><rect x="{label_w}" width="{value_w}" height="20" fill="{colour}"/><rect width="{total_w}" height="20" fill="url(#s)"/></g><g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11"><text x="{label_x:.1}" y="15" fill="#010101" fill-opacity=".3">{LABEL}</text><text x="{label_x:.1}" y="14">{LABEL}</text><text x="{value_x:.1}" y="15" fill="#010101" fill-opacity=".3">{value}</text><text x="{value_x:.1}" y="14">{value}</text></g></svg>"##
    )
}

/// The routes this module owns; merged into the portal API router by its builder.
/// `/portal/*` routes are session-scoped like every other portal route; `/badge/:file`
/// is deliberately public (#778: the whole point of a badge is a README can embed it).
pub(super) fn routes() -> Router<ApiState> {
    Router::new()
        .route("/portal/tunnels/:id/uptime", get(tunnel_uptime_page))
        .route("/portal/tunnels/:id/badge/enable", post(enable_tunnel_badge))
        .route("/portal/tunnels/:id/badge/disable", post(disable_tunnel_badge))
        .route("/badge/:file", get(public_badge_svg))
        .route("/portal/usage", get(usage_page))
        .route("/portal/usage.csv", get(usage_csv))
}

use ct_common::time::now_secs_i64 as now_secs;

/// Best-effort audit row for a badge change, when the deployment has an audit log --
/// same posture as `create_tunnel`'s `tunnel_enrolled` row (actor = the session's
/// subject, target = the tunnel id; never the public id, which is a capability).
fn audit_badge(st: &ApiState, subject: &str, tunnel_id: &str, action: &str) {
    if let Some(audit) = &st.audit {
        let _ = audit.record(subject, action, Some(tunnel_id), None);
    }
}

/// `GET /portal/tunnels/:id/uptime` (#778): owner-scoped -- an unknown or foreign id
/// is a 404, never a 403 ("existence leaks nothing", same as every other owner-scoped
/// tunnel route). Fail-open on the edge: no history renders an explanation, not
/// zeros.
async fn tunnel_uptime_page(State(st): State<ApiState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let Some(claims) = session_claims_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    let tunnel = match st.tunnels.owned_tunnel(&claims.subject, &id) {
        Ok(Some(t)) => t,
        Ok(None) => return (StatusCode::NOT_FOUND, "unknown tunnel").into_response(),
        Err(e) => return internal_error("tunnel_uptime_page/owned_tunnel", e).into_response(),
    };
    // Best-effort like every other per-page lookup: a store error here just renders
    // the badge as "off" rather than failing the whole page.
    let badge = st.tunnels.badge_public_id(&claims.subject, &tunnel.id).unwrap_or(None);
    let history = edge_tunnel_history(&st, &tunnel.routing_token, UPTIME_HISTORY_SESSIONS).await;
    let html = tunnel_uptime_html(
        &tunnel,
        history.as_ref(),
        badge.as_deref(),
        &st.portal_base,
        now_secs(),
        claims.email.as_deref(),
    );
    Html(html).into_response()
}

/// `POST /portal/tunnels/:id/badge/enable` (#778): owner-scoped, idempotent (see
/// `SqliteTunnelStore::enable_badge`), back to the uptime page. Audited when the
/// deployment has an audit log, same best-effort posture as `create_tunnel`'s row.
async fn enable_tunnel_badge(State(st): State<ApiState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    match st.tunnels.enable_badge(&subject, &id) {
        Ok(Some(_)) => {
            audit_badge(&st, &subject, &id, "tunnel_badge_enabled");
            // `id` is a real, owned tunnel id here (hex), so it is safe in a Location.
            Redirect::to(&format!("/portal/tunnels/{id}/uptime")).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "unknown tunnel").into_response(),
        Err(e) => internal_error("enable_tunnel_badge", e).into_response(),
    }
}

/// `POST /portal/tunnels/:id/badge/disable` (#778): owner-scoped; the old public id
/// 404s from the next request on. Disabling an already-disabled badge is a no-op
/// redirect, not an error.
async fn disable_tunnel_badge(State(st): State<ApiState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    match st.tunnels.owns(&subject, &id) {
        Ok(true) => {}
        Ok(false) => return (StatusCode::NOT_FOUND, "unknown tunnel").into_response(),
        Err(e) => return internal_error("disable_tunnel_badge/owns", e).into_response(),
    }
    match st.tunnels.disable_badge(&subject, &id) {
        Ok(removed) => {
            if removed {
                audit_badge(&st, &subject, &id, "tunnel_badge_disabled");
            }
            Redirect::to(&format!("/portal/tunnels/{id}/uptime")).into_response()
        }
        Err(e) => internal_error("disable_tunnel_badge", e).into_response(),
    }
}

/// `GET /badge/:public_id.svg` (#778), no auth: 404 for anything but an enabled badge's
/// exact `<64 hex>.svg`; otherwise the tunnel's routing token is resolved SERVER-SIDE
/// (badge -> owner + tunnel id -> owner-scoped token, so a revoked tunnel's badge dies
/// with it) and the edge's 7-day uptime rendered. Cacheable for 5 min: the figure moves
/// slowly and this is the one route on the portal a README can hammer.
async fn public_badge_svg(State(st): State<ApiState>, Path(file): Path<String>) -> Response {
    let public_id = match file.strip_suffix(".svg") {
        Some(p) if p.len() == 64 && p.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) => p,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let (subject, tunnel_id) = match st.tunnels.badge_lookup(public_id) {
        Ok(Some(pair)) => pair,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return internal_error("public_badge_svg/badge_lookup", e).into_response(),
    };
    let routing_token = match st.tunnels.routing_token(&subject, &tunnel_id) {
        Ok(Some(t)) => t,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return internal_error("public_badge_svg/routing_token", e).into_response(),
    };
    let history = edge_tunnel_history(&st, &routing_token, BADGE_HISTORY_SESSIONS).await;
    let svg = badge_svg(history.map(|h| h.uptime.d7));
    ([(CONTENT_TYPE, "image/svg+xml"), (CACHE_CONTROL, "public, max-age=300")], svg).into_response()
}

/// `GET /portal/usage` (#783): one row per OWNED tunnel (shared-with-me tunnels are
/// the owner's usage, not this account's) with its last-30-days numbers, plus totals.
async fn usage_page(State(st): State<ApiState>, headers: HeaderMap) -> Response {
    let Some(claims) = session_claims_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    let rows = match usage_rows_for(&st, &claims.subject).await {
        Ok(rows) => rows,
        Err(resp) => return resp,
    };
    Html(usage_html(&rows, claims.email.as_deref())).into_response()
}

/// `GET /portal/usage.csv` (#783): the same rows as [`usage_page`] as RFC 4180 CSV --
/// raw numbers (bytes, not `1.2 KB`), a header row, no totals row, and never a token.
async fn usage_csv(State(st): State<ApiState>, headers: HeaderMap) -> Response {
    let Some(subject) = session_subject_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    let rows = match usage_rows_for(&st, &subject).await {
        Ok(rows) => rows,
        Err(resp) => return resp,
    };
    (
        [
            (CONTENT_TYPE, "text/csv; charset=utf-8"),
            (CONTENT_DISPOSITION, "attachment; filename=\"cads-tunnel-usage.csv\""),
        ],
        usage_csv_text(&rows),
    )
        .into_response()
}

/// One usage row: the tunnel and its 30-day summary -- `None` when the edge had no
/// history for it (fail-open per tunnel: the row still lists, reading `n/a`).
type UsageRow = (SubjectTunnel, Option<UsageSummary>);

/// Every owned tunnel's usage row, the edge history fetches all in flight at once
/// (`join_all`), one bounded call per tunnel -- same shape as the tunnels page's own
/// status/history scrape.
async fn usage_rows_for(st: &ApiState, subject: &str) -> Result<Vec<UsageRow>, Response> {
    let tunnels = st
        .tunnels
        .list_for_subject(subject)
        .map_err(|e| internal_error("usage/list_for_subject", e).into_response())?;
    let histories = futures::future::join_all(
        tunnels
            .iter()
            .map(|t| edge_tunnel_history(st, &t.routing_token, UPTIME_HISTORY_SESSIONS)),
    )
    .await;
    let now = now_secs();
    Ok(tunnels
        .into_iter()
        .zip(histories)
        .map(|(t, h)| {
            let summary = h.map(|h| usage_from_history(&h, now));
            (t, summary)
        })
        .collect())
}

/// The uptime page body. Every tunnel- or edge-supplied string passes through
/// [`escape`]; the badge URL is built from `portal_base` (operator config) and the
/// stored hex id, escaped all the same.
fn tunnel_uptime_html(
    t: &SubjectTunnel,
    history: Option<&EdgeTunnelHistory>,
    badge_public_id: Option<&str>,
    portal_base: &str,
    now: i64,
    email: Option<&str>,
) -> String {
    let id = escape(&t.id);
    let name = escape(&t.name);
    let host = t
        .hostname
        .as_deref()
        .map(|h| format!(r#"<p class="help">Hostname: <code>{}</code></p>"#, escape(h)))
        .unwrap_or_default();
    let stats = match history {
        Some(h) => {
            let u = usage_from_history(h, now);
            let outage = if u.longest_outage_secs_30d == 0 {
                "none observed".to_string()
            } else {
                human_duration(u.longest_outage_secs_30d)
            };
            format!(
                r#"<div class="row"><span class="k">Uptime 24 h / 7 d / 30 d</span><span class="v">{h24} / {d7} / {d30}</span></div>
<div class="row"><span class="k">Longest outage (30 d)</span><span class="v">{outage}</span></div>
<div class="row"><span class="k">Sessions (30 d)</span><span class="v">{sessions}</span></div>
<div class="row"><span class="k" title="Edge-measured relay-plane bytes only -- a direct P2P leg's traffic isn't counted here.">Bytes in / out (30 d)</span><span class="v">{bytes_in} / {bytes_out}</span></div>
<h2>Sessions (newest first, up to {limit})</h2>
{table}"#,
                h24 = human_pct(h.uptime.h24),
                d7 = human_pct(h.uptime.d7),
                d30 = human_pct(h.uptime.d30),
                sessions = u.sessions_30d,
                bytes_in = human_bytes(u.bytes_in_30d),
                bytes_out = human_bytes(u.bytes_out_30d),
                limit = UPTIME_HISTORY_SESSIONS,
                table = tunnel_history_sessions_html(h),
            )
        }
        None => r#"<p class="help">The edge has no connection history for this tunnel yet -- history is disabled on the edge, the edge could not be reached, or the tunnel has never connected.</p>"#.to_string(),
    };
    let badge = match badge_public_id {
        Some(pid) => {
            let url = escape(&format!("{}/badge/{}.svg", portal_base.trim_end_matches('/'), pid));
            let markdown = format!("![uptime]({url})");
            format!(
                r#"<p class="help">Enabled. Anyone with this URL sees a 7-day uptime percentage and nothing else -- no hostname, tunnel id or traffic. Disabling makes the URL stop working immediately; re-enabling later mints a new one.</p>
<p><img src="{url}" alt="uptime badge" height="20"></p>
<div class="row"><span class="k">Badge URL</span><span class="v"><code>{url}</code> <button class="copy-btn" type="button" onclick="copyText(this,'{url}')">Copy</button></span></div>
<div class="row"><span class="k">Markdown</span><span class="v"><code>{markdown}</code> <button class="copy-btn" type="button" onclick="copyText(this,'{markdown}')">Copy</button></span></div>
<form class="inline" method="post" action="/portal/tunnels/{id}/badge/disable"><button class="btn danger" type="submit">Disable badge</button></form>"#
            )
        }
        None => format!(
            r#"<p class="help">Off. Enabling mints an unguessable public URL that renders this tunnel's 7-day uptime as an SVG badge, for a README or status page. It carries no hostname, tunnel id or traffic data, and can be disabled here at any time.</p>
<form class="inline" method="post" action="/portal/tunnels/{id}/badge/enable"><button class="btn" type="submit">Enable badge</button></form>"#
        ),
    };
    let body = format!(
        r#"<h1>Uptime &amp; usage · {name}</h1>
{host}
<p><a class="btn sec" href="/portal/tunnels">Back to Tunnels</a> <a class="btn sec" href="/portal/usage">Usage of all tunnels</a></p>
<h2>Last 30 days</h2>
{stats}
<h2>Public status badge</h2>
{badge}
<h2>Signed receipts</h2>
<p class="help">The edge records every session start and end for this tunnel, plus an hourly byte snapshot while it is connected, as a hash-chained receipt signed with the edge's own receipts key. The download is JSON lines: a header with the edge's public key, then one receipt per line. Verify it offline with <code>verify_receipts &lt;file&gt;</code> (crates/agent-tools) -- no trust in this portal required. A receipt proves the edge attested these metadata events in this order; it never contains payload, hostnames or addresses, and its timestamps are the edge's own clock.</p>
<p><a class="btn sec" href="/portal/tunnels/{id}/receipts.jsonl">Download receipts</a></p>"#
    );
    page("uptime", &body, email)
}

/// The usage page body: the table plus a totals row, or a one-line explanation when
/// the account owns no tunnel yet.
fn usage_html(rows: &[UsageRow], email: Option<&str>) -> String {
    let table = if rows.is_empty() {
        r#"<p class="help">No tunnels yet -- usage appears here once you own one.</p>"#.to_string()
    } else {
        let mut sessions_total: u64 = 0;
        let mut bytes_in_total: u64 = 0;
        let mut bytes_out_total: u64 = 0;
        let body = rows
            .iter()
            .map(|(t, summary)| {
                let host = t
                    .hostname
                    .as_deref()
                    .map(|h| format!(" · <code>{}</code>", escape(h)))
                    .unwrap_or_default();
                let cells = match summary {
                    Some(u) => {
                        sessions_total = sessions_total.saturating_add(u.sessions_30d);
                        bytes_in_total = bytes_in_total.saturating_add(u.bytes_in_30d);
                        bytes_out_total = bytes_out_total.saturating_add(u.bytes_out_30d);
                        format!(
                            "<td>{}</td><td>{}</td><td>{}</td><td>{}</td>",
                            human_pct(u.uptime_d30),
                            u.sessions_30d,
                            human_bytes(u.bytes_in_30d),
                            human_bytes(u.bytes_out_30d),
                        )
                    }
                    None => "<td>n/a</td><td>n/a</td><td>n/a</td><td>n/a</td>".to_string(),
                };
                format!(
                    r#"<tr><td><a href="/portal/tunnels/{id}/uptime">{name}</a>{host}</td>{cells}</tr>"#,
                    id = escape(&t.id),
                    name = escape(&t.name),
                )
            })
            .collect::<String>();
        format!(
            r#"<table class="history"><thead><tr><th>Tunnel</th><th>Uptime 30 d</th><th>Sessions 30 d</th><th>Bytes in</th><th>Bytes out</th></tr></thead>
<tbody>{body}<tr class="total"><td><strong>Total</strong> ({count} tunnels)</td><td>&ndash;</td><td>{sessions_total}</td><td>{bytes_in}</td><td>{bytes_out}</td></tr></tbody></table>"#,
            count = rows.len(),
            bytes_in = human_bytes(bytes_in_total),
            bytes_out = human_bytes(bytes_out_total),
        )
    };
    let body = format!(
        r#"<h1>Usage</h1>
<p class="help">Last 30 days per tunnel you own, as recorded by the edge: relay-plane bytes only (a direct P2P leg's traffic isn't counted), sessions that overlap the window with their full byte counts. A tunnel the edge has no history for reads <code>n/a</code>. Each tunnel's own page has the session list and the public badge.</p>
<p><a class="btn sec" href="/portal/usage.csv">Download CSV</a></p>
{table}"#
    );
    page("usage", &body, email)
}

/// RFC 4180 CSV of the usage rows: header, one line per tunnel, CRLF line ends, string
/// fields quoted (a tunnel name may contain a comma or a quote). Numbers raw: uptime
/// as `97.1`, bytes as integers; `n/a` rows leave the four number fields empty.
fn usage_csv_text(rows: &[UsageRow]) -> String {
    let mut out = String::from("tunnel,hostname,uptime_30d_pct,sessions_30d,bytes_in_30d,bytes_out_30d\r\n");
    for (t, summary) in rows {
        out.push_str(&csv_field(&t.name));
        out.push(',');
        out.push_str(&csv_field(t.hostname.as_deref().unwrap_or("")));
        out.push(',');
        match summary {
            Some(u) => {
                let pct = if u.uptime_d30.is_finite() { u.uptime_d30.clamp(0.0, 100.0) } else { 0.0 };
                out.push_str(&format!("{pct:.1},{},{},{}", u.sessions_30d, u.bytes_in_30d, u.bytes_out_30d));
            }
            None => out.push_str(",,,"),
        }
        out.push_str("\r\n");
    }
    out
}

/// One quoted CSV field: wrapped in `"`, inner `"` doubled, CR/LF dropped (a name
/// cannot legitimately contain them, and a stray one must not split a record).
fn csv_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\"\""),
            '\r' | '\n' => {}
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn closed(connected_at: i64, disconnected_at: i64, bytes_in: u64, bytes_out: u64) -> EdgeSessionRow {
        EdgeSessionRow {
            transport: "quic".to_string(),
            connected_at,
            disconnected_at: Some(disconnected_at),
            reason: Some("registration-closed".to_string()),
            bytes_in,
            bytes_out,
        }
    }

    fn open(connected_at: i64, bytes_in: u64, bytes_out: u64) -> EdgeSessionRow {
        EdgeSessionRow {
            transport: "quic".to_string(),
            connected_at,
            disconnected_at: None,
            reason: None,
            bytes_in,
            bytes_out,
        }
    }

    fn history(open_flag: bool, d30: f64, sessions: Vec<EdgeSessionRow>) -> EdgeTunnelHistory {
        EdgeTunnelHistory {
            open: open_flag,
            uptime: EdgeUptime { h24: 100.0, d7: 98.4, d30 },
            sessions,
        }
    }

    #[test]
    fn usage_from_history_of_an_empty_history_is_all_zero_but_the_edge_uptime_783() {
        let u = usage_from_history(&history(false, 97.1, vec![]), NOW);
        assert_eq!(
            u,
            UsageSummary {
                sessions_30d: 0,
                bytes_in_30d: 0,
                bytes_out_30d: 0,
                uptime_d30: 97.1,
                longest_outage_secs_30d: 0,
            }
        );
    }

    #[test]
    fn usage_from_history_counts_one_open_session_with_no_outage_783() {
        let u = usage_from_history(&history(true, 100.0, vec![open(NOW - 3_600, 1234, 5678)]), NOW);
        assert_eq!(u.sessions_30d, 1);
        assert_eq!(u.bytes_in_30d, 1234);
        assert_eq!(u.bytes_out_30d, 5678);
        assert_eq!(u.longest_outage_secs_30d, 0, "an open session runs to now: no tail gap");
    }

    #[test]
    fn usage_from_history_finds_the_longest_outage_between_two_sessions_783() {
        // Newest first, as the edge sends them: a 30 min hole between the closed
        // session's end and the open one's start.
        let h = history(
            true,
            97.1,
            vec![open(NOW - 3_600, 1234, 5678), closed(NOW - 7_200, NOW - 5_400, 10, 20)],
        );
        let u = usage_from_history(&h, NOW);
        assert_eq!(u.sessions_30d, 2);
        assert_eq!(u.bytes_in_30d, 1244);
        assert_eq!(u.bytes_out_30d, 5698);
        assert_eq!(u.longest_outage_secs_30d, 1_800);
    }

    #[test]
    fn usage_from_history_runs_the_tail_outage_to_now_when_nothing_is_open_783() {
        let h = history(false, 50.0, vec![closed(NOW - 10_000, NOW - 9_000, 1, 1), closed(NOW - 8_000, NOW - 7_500, 1, 1)]);
        let u = usage_from_history(&h, NOW);
        assert_eq!(u.longest_outage_secs_30d, 7_500, "the tail (7 500 s) beats the 1 000 s hole between the two");
        assert_eq!(u.sessions_30d, 2);
    }

    #[test]
    fn usage_from_history_never_reports_a_phantom_gap_between_overlapping_legs_783() {
        // A TCP-fallback leg opened while the QUIC one was still up, then outlived it.
        let h = history(
            false,
            100.0,
            vec![closed(NOW - 6_000, NOW - 4_000, 1, 1), closed(NOW - 5_000, NOW - 3_000, 1, 1)],
        );
        let u = usage_from_history(&h, NOW);
        assert_eq!(u.longest_outage_secs_30d, 3_000, "only the tail after the LATER end counts, no gap inside the overlap");
    }

    #[test]
    fn usage_from_history_clips_to_the_30_day_window_and_counts_straddlers_in_full_783() {
        let day = 86_400;
        let h = history(
            true,
            99.0,
            vec![
                // Ended long before the window: not counted, but it anchors the next gap.
                closed(NOW - 60 * day, NOW - 50 * day, 1_000, 1_000),
                // Straddles the window start: counted, bytes in full.
                closed(NOW - 31 * day, NOW - 29 * day, 500, 700),
                open(NOW - 10 * day, 5, 5),
            ],
        );
        let u = usage_from_history(&h, NOW);
        assert_eq!(u.sessions_30d, 2, "the pre-window session is out, the straddler and the open one are in");
        assert_eq!(u.bytes_in_30d, 505);
        assert_eq!(u.bytes_out_30d, 705);
        // The 20-day hole (-50 d .. -31 d) lies entirely before the window; the only
        // in-window outage is -29 d .. -10 d = 19 days.
        assert_eq!(u.longest_outage_secs_30d, 19 * day as u64);
    }

    #[test]
    fn badge_svg_colours_by_threshold_and_carries_only_the_label_and_value_778() {
        let green = badge_svg(Some(99.0));
        assert!(green.contains("#4c1"), "{green}");
        assert!(green.contains(">uptime 7d<"), "{green}");
        assert!(green.contains(">99 %<"), "{green}");
        assert!(green.contains(r#"<title>uptime 7d: 99 %</title>"#), "{green}");
        assert!(green.starts_with("<svg xmlns=\"http://www.w3.org/2000/svg\""), "{green}");

        let yellow = badge_svg(Some(98.4));
        assert!(yellow.contains("#dfb317"), "{yellow}");
        assert!(yellow.contains(">98.4 %<"), "{yellow}");
        assert!(!yellow.contains("#4c1"));

        let red = badge_svg(Some(94.99));
        assert!(red.contains("#e05d44"), "{red}");

        let na = badge_svg(None);
        assert!(na.contains("#9f9f9f"), "{na}");
        assert!(na.contains(">n/a<"), "{na}");
        assert_eq!(badge_svg(Some(f64::NAN)), na, "a non-finite figure reads as no data, never NaN");
        assert!(badge_svg(Some(140.0)).contains(">100 %<"), "clamped like the page's own percentage");
    }

    #[test]
    fn usage_csv_text_quotes_strings_and_leaves_no_history_rows_empty_783() {
        let t = |name: &str, host: Option<&str>| SubjectTunnel {
            id: "t1".to_string(),
            name: name.to_string(),
            hostname: host.map(str::to_string),
            created_at: 0,
            routing_token: "deadbeef".repeat(8),
        };
        let rows: Vec<UsageRow> = vec![
            (
                t("my \"site\", prod", Some("site.example")),
                Some(UsageSummary {
                    sessions_30d: 2,
                    bytes_in_30d: 1244,
                    bytes_out_30d: 5698,
                    uptime_d30: 97.1,
                    longest_outage_secs_30d: 1_800,
                }),
            ),
            (t("mesh-only\nx", None), None),
        ];
        let csv = usage_csv_text(&rows);
        let lines: Vec<&str> = csv.split("\r\n").collect();
        assert_eq!(lines[0], "tunnel,hostname,uptime_30d_pct,sessions_30d,bytes_in_30d,bytes_out_30d");
        assert_eq!(lines[1], r#""my ""site"", prod","site.example",97.1,2,1244,5698"#);
        assert_eq!(lines[2], r#""mesh-onlyx","",,,,"#, "no history: the number fields are empty, the newline dropped");
        assert_eq!(lines[3], "", "CRLF-terminated last record");
        assert!(!csv.contains("deadbeef"), "never a token");
    }

    #[test]
    fn usage_html_totals_the_rows_and_links_each_tunnel_to_its_uptime_page_783() {
        let t = |id: &str, name: &str| SubjectTunnel {
            id: id.to_string(),
            name: name.to_string(),
            hostname: Some(format!("{id}.example")),
            created_at: 0,
            routing_token: "ab".repeat(32),
        };
        let some = |sessions: u64, bytes: u64| {
            Some(UsageSummary {
                sessions_30d: sessions,
                bytes_in_30d: bytes,
                bytes_out_30d: bytes * 2,
                uptime_d30: 97.1,
                longest_outage_secs_30d: 0,
            })
        };
        let rows: Vec<UsageRow> = vec![(t("t1", "one"), some(2, 1024)), (t("t2", "<two>"), None), (t("t3", "three"), some(3, 1024))];
        let html = usage_html(&rows, None);
        assert!(html.contains(r#"<a href="/portal/tunnels/t1/uptime">one</a> · <code>t1.example</code>"#), "{html}");
        assert!(html.contains("&lt;two&gt;"), "escaped name: {html}");
        assert!(html.contains("<td>n/a</td><td>n/a</td><td>n/a</td><td>n/a</td>"), "{html}");
        assert!(html.contains("<strong>Total</strong> (3 tunnels)</td><td>&ndash;</td><td>5</td><td>2.0 KB</td><td>4.0 KB</td>"), "{html}");
        assert!(html.contains(r#"href="/portal/usage.csv""#), "{html}");
        assert!(!html.contains(&"ab".repeat(32)), "never a token");

        let empty = usage_html(&[], None);
        assert!(empty.contains("No tunnels yet"), "{empty}");
        assert!(!empty.contains("<table"), "{empty}");
    }
}
