//! Edge admin API (#27 RB4) — an authenticated `POST /admin/revoke/:token` the
//! control plane calls when a customer revokes a tunnel. The edge then tears the
//! tunnel down and blocks its re-registration (see [`EdgeState::revoke_token`]).
//!
//! This is the HTTP counterpart of the QUIC `'R'` op (RB3b); the thin,
//! HTTP-based control plane calls it with `reqwest` rather than opening a QUIC
//! client. It is served on its own listener (`CT_EDGE_ADMIN_LISTEN`) so an
//! operator can bind it to a private interface, and every request must carry the
//! shared admin secret (`x-ct-admin-token`), checked in constant time.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use quinn::Connection;
use serde::Serialize;

use crate::state::EdgeState;
use ct_common::RoutingToken;

/// Build the admin router (#27 revoke, #23 BP4b authorize-host, #153 host-auth dump,
/// monitoring-feature v1 tunnel-status, ADR-0025 Decision 6 bulk tunnel-status).
pub fn admin_router(state: Arc<EdgeState<Connection>>) -> Router {
    Router::new()
        .route("/admin/revoke/:token", post(revoke))
        .route("/admin/authorize-host/:token/:host", post(authorize_host))
        // #666: the routing token is a bearer credential -- carrying it in the URL path
        // means it lands in every proxy/LB/access log between the control plane and this
        // edge. This `:host`-only route (token via the `x-ct-routing-token` header
        // instead) is the fix, mirroring the CP-side #666/#671 fix already applied to
        // `acme_broker.rs`'s agent-facing routes. The original `:token/:host` route above
        // stays mounted, unchanged, for back-compat during a mixed CP/edge-version
        // rollout. Both forward to the same inner logic -- only how the token is
        // extracted differs.
        .route("/admin/authorize-host/:host", post(authorize_host_via_header))
        .route("/admin/host-auth-dump", get(host_auth_dump))
        .route("/admin/tunnel-status/:token", get(tunnel_status))
        // Static route, same path prefix as the `:token` one above -- axum/matchit
        // prefers an exact literal match over a same-position dynamic segment, so
        // this never collides with a (63-hex-char-short, in any case) real token.
        .route("/admin/tunnel-status/bulk", post(tunnel_status_bulk))
        // #763: read-only channel presence for the portal's Agent-bridges card. Served
        // on THIS (admin-token-gated, private-interface) listener -- the path keeps the
        // `/internal/channel/...` prefix the control plane's own edge<->CP channel
        // routes use, since the CP is its only caller. The `:channel_hex` list form
        // comes first: the portal's stored bridge grant binds the portal's OWN holder,
        // so the serving sidecar's holder is not derivable from it and the card asks
        // "who ELSE was here?" instead (see `channel_broker::ChannelPresence::holders_of`).
        .route("/internal/channel/presence/:channel_hex", get(channel_presence_list))
        .route("/internal/channel/presence/:channel_hex/:holder_hex", get(channel_presence_one))
        // #776: read-only per-tunnel session history for the portal's "Connection history"
        // card -- same listener, gate, and `/internal/...` naming as the #763 presence
        // routes above, for the same reason (the CP is its only caller).
        .route("/internal/tunnel/history/:token_hex", get(tunnel_history))
        // #782: signed forensic receipts -- the edge's receipts public key and a token's
        // receipt chain page, for the control plane's `receipts.jsonl` export. Same
        // listener, gate and `/internal/...` naming as the history route above.
        .route("/internal/receipts/pubkey", get(receipts_pubkey))
        .route("/internal/tunnel/receipts/:token_hex", get(tunnel_receipts))
        // #779: the control plane pushes a tunnel's access window here on every change
        // (and alongside a fresh hostname authorization); boot-time state comes from the
        // rehydrate replay instead. Routing token via the `x-ct-routing-token` header,
        // never the path (#666) -- same posture as the `:host`-only authorize-host route.
        .route("/internal/tunnel/access-policy", post(set_access_policy))
        .with_state(state)
}

/// Constant-time check of the `x-ct-admin-token` header against the shared secret.
fn admin_authed(state: &EdgeState<Connection>, headers: &HeaderMap) -> bool {
    headers
        .get("x-ct-admin-token")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_token_hex)
        .is_some_and(|a| state.admin_revoke_ok(&a))
}

/// #666: header carrying the routing token for the `:host`-only `authorize-host` route
/// form, so it never appears in a URL path/log. Distinct from `x-ct-admin-token` (the
/// shared edge-admin secret, already header-borne and unaffected by this fix) and from
/// `acme_broker.rs`'s `x-ct-agent-token` (same idea, different hop: that one is CP-facing
/// agent traffic, this one is CP-to-edge admin traffic).
const ROUTING_TOKEN_HEADER: &str = "x-ct-routing-token";

fn routing_token_from_header(headers: &HeaderMap) -> Option<String> {
    headers.get(ROUTING_TOKEN_HEADER).and_then(|v| v.to_str().ok()).map(str::to_string).filter(|s| !s.is_empty())
}

/// Serve the admin API on `listen` until the process ends.
pub async fn serve_admin(
    state: Arc<EdgeState<Connection>>,
    listen: SocketAddr,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, admin_router(state))
        .await
        .map_err(std::io::Error::other)
}

async fn revoke(
    State(state): State<Arc<EdgeState<Connection>>>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> StatusCode {
    if !admin_authed(&state, &headers) {
        return StatusCode::UNAUTHORIZED;
    }
    match parse_token_hex(&token) {
        Some(t) => {
            state.revoke_token(&RoutingToken(t));
            StatusCode::OK
        }
        None => StatusCode::BAD_REQUEST,
    }
}

#[derive(serde::Deserialize, Default)]
struct ChannelTierQuery {
    /// Rot/Gelb/Grün **channel** tier (#233) — which TLS termination channel
    /// serves this host (shared wildcard cert vs. the customer's own). Named
    /// `channel_tier` specifically to stay distinct from the unrelated
    /// user-facing *feature* tier (Standard/paid, see `portal_api.rs`). Absent
    /// (the default for every existing caller — nothing before this feature
    /// ever sent it) means "not Gelb", i.e. ordinary SNI-passthrough: fully
    /// backward-compatible, no existing authorize-host call can accidentally
    /// start terminating TLS for a host the operator didn't explicitly mark.
    #[serde(default)]
    channel_tier: Option<String>,
}

/// `POST /admin/authorize-host/:token/:host[?channel_tier=gelb]` (#23 BP4b,
/// #233): the control plane authorizes `host` to be bound by `token` (called
/// when a customer sets a hostname on a tunnel they own), and separately
/// records whether `host` is currently in the Gelb channel tier (served via
/// the shared front-door wildcard cert) — `?channel_tier=gelb` sets it, any
/// other value or its absence clears it (e.g. the control plane re-pushes
/// with no `channel_tier` once a hostname reaches Grün, reverting it to
/// ordinary passthrough so the browser sees the origin's own newly-issued
/// certificate). Authenticated by the shared admin secret.
async fn authorize_host(
    State(state): State<Arc<EdgeState<Connection>>>,
    headers: HeaderMap,
    Path((token, host)): Path<(String, String)>,
    Query(q): Query<ChannelTierQuery>,
) -> StatusCode {
    if !admin_authed(&state, &headers) {
        return StatusCode::UNAUTHORIZED;
    }
    authorize_host_inner(state, token, host, q).await
}

/// #666: same as [`authorize_host`], routing token via the `x-ct-routing-token` header
/// instead of the URL path — the CP→edge internal hop's half of the #666 fix (the
/// agent-facing CP routes were already fixed via `x-ct-agent-token`).
async fn authorize_host_via_header(
    State(state): State<Arc<EdgeState<Connection>>>,
    headers: HeaderMap,
    Path(host): Path<String>,
    Query(q): Query<ChannelTierQuery>,
) -> StatusCode {
    if !admin_authed(&state, &headers) {
        return StatusCode::UNAUTHORIZED;
    }
    let Some(token) = routing_token_from_header(&headers) else {
        return StatusCode::BAD_REQUEST;
    };
    authorize_host_inner(state, token, host, q).await
}

async fn authorize_host_inner(state: Arc<EdgeState<Connection>>, token: String, host: String, q: ChannelTierQuery) -> StatusCode {
    let host = host.trim();
    match parse_token_hex(&token) {
        Some(t) if !host.is_empty() => {
            // #504/#513: this route is the edge-side WRITE PRIMITIVE — the CP's own
            // machinery (the /registry/authorize-host proxy, the Gelb/ACME
            // re-authorize loop) calls it too, so the edge CANNOT tell a legitimate
            // CP-driven write from a human bypassing the CP (a per-use warning here
            // fired on every portal re-push — reverted same day). The guarantees
            // live one layer up: only the CP path persists ownership for
            // rehydration and runs the #504 portal-conflict check. Humans: use the
            // CP proxy, never this route directly (runbook rule 4, #502).
            state.authorize_host(host, RoutingToken(t));
            state.set_cert_tier(host, q.channel_tier.as_deref() == Some("gelb"));
            StatusCode::OK
        }
        _ => StatusCode::BAD_REQUEST,
    }
}

#[derive(Serialize, serde::Deserialize)]
struct HostAuthEntry {
    hostname: String,
    token: String,
}

/// `GET /admin/host-auth-dump` (#153): a **read-only** dump of every currently
/// authorized (hostname, token) pair on this edge — this deployment's own
/// live state, the only place it exists (the control plane's host-authorize
/// proxy is a pure pass-through; it never persisted what it forwarded). Exists
/// to safely backfill a durable control-plane-side ownership registry BEFORE
/// this edge is ever restarted (a restart wipes `host_auth`, which is exactly
/// the bug the registry fixes) — read this first, seed the registry, then it's
/// safe to redeploy. Authenticated the same way as every other admin route.
async fn host_auth_dump(
    State(state): State<Arc<EdgeState<Connection>>>,
    headers: HeaderMap,
) -> Result<Json<Vec<HostAuthEntry>>, StatusCode> {
    if !admin_authed(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let entries = state
        .dump_host_auth()
        .unwrap_or_default()
        .into_iter()
        .map(|(hostname, token)| HostAuthEntry {
            hostname,
            token: token.0.iter().map(|b| format!("{b:02x}")).collect(),
        })
        .collect();
    Ok(Json(entries))
}

#[derive(Serialize, serde::Deserialize)]
struct TunnelStatusResp {
    /// #544: true when the tunnel can be served over **either** transport. It used to
    /// mean "has a QUIC registration", which reported a fallback-served tunnel as
    /// disconnected while it was actively relaying -- the customer's portal said their
    /// agent was down, and an operator could not tell that apart from a real outage.
    connected: bool,
    /// QUIC registrations only, unchanged in meaning (#8 counts redundant agents here).
    registrations: usize,
    /// #544: TLS-TCP fallback registrations parked for this token. Reported BESIDE
    /// `registrations` rather than folded into it: the two transports fail differently
    /// and the operator response differs, so collapsing them would trade one ambiguity
    /// for another.
    fallback_parked: usize,
    /// Cumulative bytes received from / sent to this tunnel's clients since
    /// this Edge process started (monitoring-feature byte counters,
    /// 2026-08-01) -- `0` for a tunnel that has never relayed anything.
    bytes_received: u64,
    bytes_sent: u64,
    /// ADR-0025 Decision 3: whether an Agent currently has a direct/P2P
    /// listener advertised for this tunnel (`EdgeState::direct_endpoint`).
    /// This is an AVAILABILITY signal, not a claim that traffic is actually
    /// flowing over that path -- the edge structurally cannot see direct-path
    /// bytes (they bypass it entirely), so the admin console must never
    /// present this as a byte count it doesn't have. See the ADR's own
    /// wording; the honest framing in the admin UI itself is a later phase.
    direct: bool,
    /// ADR-0025 Decision 6: Unix seconds the tunnel's CURRENT unbroken
    /// connection streak started -- `None` while disconnected (the admin
    /// console's "uptime" column is `now - this`, only ever shown while
    /// `connected` is true).
    connected_since: Option<u64>,
    /// ADR-0025 Decision 6: Unix seconds of the most recent activity (a
    /// registration or a relay) for this tunnel -- `None` if it has never
    /// been seen at all. Unlike `connected_since`, this survives a
    /// disconnect, which is the entire point of a "last seen" column.
    last_seen: Option<u64>,
}

/// Shared by [`tunnel_status`] (single-token) and [`tunnel_status_bulk`]
/// (ADR-0025 Decision 6) so the two can never answer differently for the same
/// token -- one real read of [`EdgeState`], not two independently-maintained
/// call sites.
fn tunnel_status_of(state: &EdgeState<Connection>, token: &RoutingToken) -> TunnelStatusResp {
    let registrations = state.registration_count(token);
    let fallback_parked = state.tcp_parked_for(token);
    let (bytes_received, bytes_sent) = state.tunnel_bytes(token);
    let (connected_since, last_seen) = state.connection_timing(token);
    TunnelStatusResp {
        connected: registrations > 0 || fallback_parked > 0,
        registrations,
        fallback_parked,
        bytes_received,
        bytes_sent,
        direct: state.direct_endpoint(token).is_some(),
        connected_since,
        last_seen,
    }
}

/// `GET /admin/tunnel-status/:token` (monitoring feature v1, operator decision
/// 2026-08-01): whether `token` currently has a live Agent registration, how
/// many (redundant Agents, #8, count separately), and its cumulative relay
/// byte counts. Read-only, admin-token-gated like every other route here.
/// This is deliberately a per-tunnel query, not a bulk dump -- the control
/// plane calls it once per tunnel it's rendering (owner-scoped in the portal;
/// the operator may query any token directly for cross-tenant visibility,
/// per the same admin-token trust already granted by every other route on
/// this router). ADR-0016 still applies: this reveals only connection
/// liveness and byte volume, never payload or per-connection detail. For
/// rendering many tunnels at once (the admin console's own dashboard), see
/// [`tunnel_status_bulk`] -- one HTTP round trip instead of N.
async fn tunnel_status(
    State(state): State<Arc<EdgeState<Connection>>>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Result<Json<TunnelStatusResp>, StatusCode> {
    if !admin_authed(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let Some(t) = parse_token_hex(&token) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    Ok(Json(tunnel_status_of(&state, &RoutingToken(t))))
}

#[derive(serde::Deserialize)]
struct BulkTunnelStatusReq {
    tokens: Vec<String>,
}

#[derive(Serialize, serde::Deserialize)]
struct BulkTunnelStatusEntry {
    /// The exact hex string the caller sent for this entry (not re-derived),
    /// so the control plane can match it back to its own `routing_token`
    /// strings by plain equality without needing this endpoint to normalize
    /// case.
    token: String,
    #[serde(flatten)]
    status: TunnelStatusResp,
}

/// `POST /admin/tunnel-status/bulk {"tokens": [...]}` (ADR-0025 Decision 6):
/// the admin console's live tunnel/topology dashboard needs every known
/// tunnel's status in one round trip -- the control plane's `GET
/// /admin-ui/tunnels` is the only caller. Same admin-token gate and the same
/// read-only, liveness-and-byte-volume-only disclosure as the single-token
/// route above (ADR-0016); a malformed entry in `tokens` is silently skipped
/// rather than failing the whole batch -- the entire reason to batch this
/// call is so one bad/stale entry can't cost every other tunnel's row.
async fn tunnel_status_bulk(
    State(state): State<Arc<EdgeState<Connection>>>,
    headers: HeaderMap,
    Json(req): Json<BulkTunnelStatusReq>,
) -> Result<Json<Vec<BulkTunnelStatusEntry>>, StatusCode> {
    if !admin_authed(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let out = req
        .tokens
        .into_iter()
        .filter_map(|hex| {
            let t = parse_token_hex(&hex)?;
            let status = tunnel_status_of(&state, &RoutingToken(t));
            Some(BulkTunnelStatusEntry { token: hex, status })
        })
        .collect();
    Ok(Json(out))
}

/// `GET /internal/channel/presence/:channel_hex/:holder_hex` (#763): when `holder` was
/// last admitted (parked or paired) on `channel`, on any channel transport. Read-only
/// and admin-token-gated like every other route here; reveals only "seen / how long
/// ago" for a `(channel, holder)` the caller already names, never members' material
/// or payload (ADR-0016 posture). Response: `{"seen":true,"parked_now":bool,
/// "last_seen_secs_ago":n}` or `{"seen":false}` -- `parked_now` is the
/// [`crate::channel_broker::PRESENCE_SERVING_WINDOW_SECS`] window ("parked now or
/// within the last 60 s"), derived from the last admission rather than a live scan of
/// each transport's pairer (see `ChannelPresence`'s own doc for why that is the
/// faithful answer for a re-parking sidecar).
async fn channel_presence_one(
    State(state): State<Arc<EdgeState<Connection>>>,
    headers: HeaderMap,
    Path((channel_hex, holder_hex)): Path<(String, String)>,
) -> Result<Json<ChannelPresenceResp>, StatusCode> {
    if !admin_authed(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let (Some(channel), Some(holder)) = (parse_token_hex(&channel_hex), parse_token_hex(&holder_hex)) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let now = crate::channel_broker::presence_unix_now();
    let ago = crate::channel_broker::channel_presence_last_seen(&ct_common::channel::ChannelId(channel), &holder, now);
    Ok(Json(ChannelPresenceResp::from_last_seen(ago)))
}

/// `GET /internal/channel/presence/:channel_hex` (#763): every holder admitted on
/// `channel` within the presence window, most recent first -- the form the portal
/// actually uses (its own bridge holder is excluded CP-side). Same gate and the same
/// disclosure bound as [`channel_presence_one`]: holder pubkeys are public identities
/// the caller (the CP) already holds in its own channel roster.
async fn channel_presence_list(
    State(state): State<Arc<EdgeState<Connection>>>,
    headers: HeaderMap,
    Path(channel_hex): Path<String>,
) -> Result<Json<ChannelPresenceListResp>, StatusCode> {
    if !admin_authed(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let Some(channel) = parse_token_hex(&channel_hex) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let now = crate::channel_broker::presence_unix_now();
    let holders = crate::channel_broker::channel_presence_holders(&ct_common::channel::ChannelId(channel), now)
        .into_iter()
        .map(|(holder, ago)| ChannelPresenceHolder {
            holder: holder.iter().map(|b| format!("{b:02x}")).collect(),
            parked_now: crate::channel_broker::presence_is_serving(ago),
            last_seen_secs_ago: ago,
        })
        .collect();
    Ok(Json(ChannelPresenceListResp { holders }))
}

/// #763: one `(channel, holder)`'s presence. The two optional fields are omitted (not
/// `null`) when unseen, so the unseen shape is exactly `{"seen":false}`.
#[derive(Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
struct ChannelPresenceResp {
    seen: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parked_now: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_seen_secs_ago: Option<u64>,
}

impl ChannelPresenceResp {
    fn from_last_seen(ago: Option<u64>) -> Self {
        match ago {
            Some(ago) => Self {
                seen: true,
                parked_now: Some(crate::channel_broker::presence_is_serving(ago)),
                last_seen_secs_ago: Some(ago),
            },
            None => Self { seen: false, parked_now: None, last_seen_secs_ago: None },
        }
    }
}

/// #763: one row of [`ChannelPresenceListResp`].
#[derive(Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
struct ChannelPresenceHolder {
    /// The holder's ed25519 pubkey, lowercase hex.
    holder: String,
    parked_now: bool,
    last_seen_secs_ago: u64,
}

/// #763: the `:channel_hex` list form's body.
#[derive(Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
struct ChannelPresenceListResp {
    holders: Vec<ChannelPresenceHolder>,
}

#[derive(serde::Deserialize, Default)]
struct TunnelHistoryQuery {
    /// How many sessions to return, newest first. Absent -> [`HISTORY_DEFAULT_LIMIT`];
    /// clamped to `1..=`[`HISTORY_MAX_LIMIT`].
    #[serde(default)]
    limit: Option<usize>,
}

const HISTORY_DEFAULT_LIMIT: usize = 20;
const HISTORY_MAX_LIMIT: usize = 200;

/// #776: the body of [`tunnel_history`].
#[derive(Serialize, serde::Deserialize, Debug)]
struct TunnelHistoryResp {
    /// Whether the token has an open session row right now (a live streak).
    open: bool,
    /// Uptime over the trailing 24 h / 7 d / 30 d, `0.0..=100.0` each.
    uptime: crate::tunnel_history::UptimeSummary,
    /// The most recent sessions, newest first (the open one, if any, leads).
    sessions: Vec<crate::tunnel_history::SessionRow>,
}

/// `GET /internal/tunnel/history/:token_hex?limit=N` (#776): the token's recent session
/// rows and its uptime over the trailing 24 h / 7 d / 30 d, from the durable
/// `tunnel_sessions` store (`tunnel_history.rs`). Read-only and admin-token-gated like
/// every other route here; `404` when the history store is disabled
/// (`CT_EDGE_TUNNEL_HISTORY=off`, or it failed to open even in memory) so the CP can
/// fail open exactly as it does for presence (#763). What is disclosed is METADATA ONLY
/// for a token the caller already names: per session the transport, start/end Unix
/// seconds, the disconnect reason, and byte volume in each direction -- never a
/// hostname, source IP, request path, or payload (ADR-0016 posture). Response:
/// `{"open":bool,"uptime":{"h24":f,"d7":f,"d30":f},"sessions":[{"transport":"quic",
/// "connected_at":n,"disconnected_at":n|null,"reason":"..."|null,"bytes_in":n,
/// "bytes_out":n},...]}`. `limit` defaults to 20, capped at 200.
async fn tunnel_history(
    State(state): State<Arc<EdgeState<Connection>>>,
    headers: HeaderMap,
    Path(token_hex): Path<String>,
    Query(q): Query<TunnelHistoryQuery>,
) -> Result<Json<TunnelHistoryResp>, StatusCode> {
    if !admin_authed(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let Some(t) = parse_token_hex(&token_hex) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let Some(history) = state.tunnel_history() else {
        return Err(StatusCode::NOT_FOUND);
    };
    let limit = q.limit.filter(|&l| l > 0).unwrap_or(HISTORY_DEFAULT_LIMIT).min(HISTORY_MAX_LIMIT);
    // Re-derive the lowercase hex from the parsed bytes: the store is keyed by the exact
    // string `EdgeState` writes, and the caller's segment may be upper-case.
    let hex = crate::tunnel_history::routing_token_hex(&RoutingToken(t));
    let now = crate::tunnel_history::now_secs();
    let store_error = |e: rusqlite::Error| {
        eprintln!("ct-edge: tunnel history read failed: {e} (#776)");
        StatusCode::INTERNAL_SERVER_ERROR
    };
    let open = history.open_session_exists(&hex).map_err(store_error)?;
    let uptime = history.uptime_summary(&hex, now).map_err(store_error)?;
    let sessions = history.sessions_for(&hex, limit).map_err(store_error)?;
    Ok(Json(TunnelHistoryResp { open, uptime, sessions }))
}

/// #782: the body of [`receipts_pubkey`].
#[derive(Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
struct ReceiptsPubkeyResp {
    /// Always `"ed25519"`.
    alg: String,
    /// 64 lowercase hex chars.
    pubkey: String,
    edge_id: String,
}

/// `GET /internal/receipts/pubkey` (#782): the public half of this edge's dedicated
/// receipts signing key (`edge-receipts-key.bin`, never the CA key) and the `edge_id`
/// every receipt carries -- what an offline verifier checks a chain against. Admin-token
/// gated like every other route here (the key is public, but the listener is private
/// and nothing on it is unauthenticated); `404` when receipts are disabled
/// (`CT_EDGE_RECEIPTS=off`, or no history store at all).
async fn receipts_pubkey(
    State(state): State<Arc<EdgeState<Connection>>>,
    headers: HeaderMap,
) -> Result<Json<ReceiptsPubkeyResp>, StatusCode> {
    if !admin_authed(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let Some(history) = state.tunnel_history() else {
        return Err(StatusCode::NOT_FOUND);
    };
    let (Some(pubkey), Some(edge_id)) = (history.receipts_pubkey_hex(), history.receipts_edge_id()) else {
        return Err(StatusCode::NOT_FOUND);
    };
    Ok(Json(ReceiptsPubkeyResp { alg: "ed25519".into(), pubkey, edge_id: edge_id.to_string() }))
}

#[derive(serde::Deserialize, Default)]
struct TunnelReceiptsQuery {
    /// Return receipts with `seq` strictly greater than this (a cursor: the last seq the
    /// caller already holds). Absent -> from the oldest retained.
    #[serde(default)]
    since: Option<u64>,
    /// Page size, clamped to `1..=`[`crate::tunnel_history::RECEIPTS_MAX_LIMIT`];
    /// absent -> [`RECEIPTS_DEFAULT_LIMIT`].
    #[serde(default)]
    limit: Option<usize>,
}

const RECEIPTS_DEFAULT_LIMIT: usize = 200;

/// #782: the body of [`tunnel_receipts`].
#[derive(Serialize, serde::Deserialize, Debug)]
struct TunnelReceiptsResp {
    /// The key the chain verifies under (same as [`receipts_pubkey`]'s).
    pubkey: String,
    edge_id: String,
    /// Ascending by `seq`; empty for a token with no retained receipts.
    receipts: Vec<ct_common::receipt::Receipt>,
}

/// `GET /internal/tunnel/receipts/:token_hex?since=<seq>&limit=<n>` (#782): the token's
/// signed receipts, ascending, strictly after `since`, at most `limit` (default 200,
/// cap 1000) -- the page the control plane streams out as `receipts.jsonl`. Admin-token
/// gated; `400` malformed hex; `404` when receipts are disabled so the CP can say so
/// rather than export an empty file. What is disclosed is exactly what the receipts
/// carry (see `ct_common::receipt`): metadata events for a token the caller already
/// names, with the token itself present only as its SHA-256.
async fn tunnel_receipts(
    State(state): State<Arc<EdgeState<Connection>>>,
    headers: HeaderMap,
    Path(token_hex): Path<String>,
    Query(q): Query<TunnelReceiptsQuery>,
) -> Result<Json<TunnelReceiptsResp>, StatusCode> {
    if !admin_authed(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let Some(t) = parse_token_hex(&token_hex) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let Some(history) = state.tunnel_history() else {
        return Err(StatusCode::NOT_FOUND);
    };
    let (Some(pubkey), Some(edge_id)) = (history.receipts_pubkey_hex(), history.receipts_edge_id()) else {
        return Err(StatusCode::NOT_FOUND);
    };
    let limit = q
        .limit
        .filter(|&l| l > 0)
        .unwrap_or(RECEIPTS_DEFAULT_LIMIT)
        .min(crate::tunnel_history::RECEIPTS_MAX_LIMIT);
    let token_hash = ct_common::receipt::routing_token_hash(&t);
    let receipts = history.receipts_for(&token_hash, q.since.unwrap_or(0), limit).map_err(|e| {
        eprintln!("ct-edge: receipts read failed: {e} (#782)");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json(TunnelReceiptsResp { pubkey, edge_id: edge_id.to_string(), receipts }))
}

/// `POST /internal/tunnel/access-policy` (#779): the control plane's push of one
/// tunnel's access window. Admin-token-gated like every other route here; the routing
/// token rides in `x-ct-routing-token` (#666: a bearer credential never goes in a URL
/// path). Body: the `ct_common::access_window::AccessPolicy` JSON, or `null` to clear.
/// The edge stores it and evaluates it locally at the front door from then on -- this
/// route is the only write path besides the boot-time rehydrate replay. `400` on a
/// missing/malformed token header; the JSON extractor answers a malformed body itself.
async fn set_access_policy(
    State(state): State<Arc<EdgeState<Connection>>>,
    headers: HeaderMap,
    Json(policy): Json<Option<ct_common::access_window::AccessPolicy>>,
) -> StatusCode {
    if !admin_authed(&state, &headers) {
        return StatusCode::UNAUTHORIZED;
    }
    let Some(t) = routing_token_from_header(&headers).as_deref().and_then(parse_token_hex) else {
        return StatusCode::BAD_REQUEST;
    };
    if let Some(p) = &policy {
        if let Err(why) = p.validate() {
            eprintln!("ct-edge: access-policy push rejected: {why} (#779)");
            return StatusCode::BAD_REQUEST;
        }
    }
    let restricted = policy.as_ref().is_some_and(|p| !p.is_unrestricted());
    state.set_access_policy(RoutingToken(t), policy);
    eprintln!(
        "ct-edge: access window {} for token {}..{} (#779)",
        if restricted { "set" } else { "cleared" },
        hex_prefix(&t),
        hex_suffix(&t),
    );
    StatusCode::OK
}

/// #779: first / last two bytes of a routing token as hex, for a log line that names
/// the tunnel without printing the whole bearer credential.
fn hex_prefix(t: &[u8; 32]) -> String {
    t[..2].iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_suffix(t: &[u8; 32]) -> String {
    t[30..].iter().map(|b| format!("{b:02x}")).collect()
}

/// A 64-hex routing token from a path segment (surrounding whitespace ignored), or `None`.
fn parse_token_hex(s: &str) -> Option<[u8; 32]> {
    ct_common::hex::decode_32(s.trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::RelayKind;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn revoke_endpoint_authenticates_then_revokes() {
        let state = Arc::new(EdgeState::<Connection>::new());
        let secret = [0x22u8; 32];
        state.set_admin_token(secret);
        let secret_hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        let target = "aa".repeat(32);
        let target_token = RoutingToken([0xaa; 32]);

        let post = |auth: Option<String>, tok: &str| {
            let app = admin_router(state.clone());
            let mut req = Request::post(format!("/admin/revoke/{tok}"));
            if let Some(a) = auth {
                req = req.header("x-ct-admin-token", a);
            }
            app.oneshot(req.body(Body::empty()).unwrap())
        };

        // No / wrong admin token -> 401, nothing revoked.
        assert_eq!(post(None, &target).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        let wrong: String = [0x00u8; 32].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(post(Some(wrong), &target).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        assert!(!state.is_revoked(&target_token), "not revoked without valid auth");

        // Correct admin token -> 200 and the token is revoked.
        assert_eq!(
            post(Some(secret_hex.clone()), &target).await.unwrap().status(),
            StatusCode::OK
        );
        assert!(state.is_revoked(&target_token), "token revoked");

        // Malformed token with valid auth -> 400.
        assert_eq!(
            post(Some(secret_hex), "not-hex").await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn authorize_host_endpoint_authenticates_then_authorizes() {
        let state = Arc::new(EdgeState::<Connection>::new());
        let secret = [0x33u8; 32];
        state.set_admin_token(secret);
        state.require_host_auth(); // #23 BP4b: nothing binds until authorized
        let secret_hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        let tok = "cc".repeat(32);
        let tok_token = RoutingToken([0xcc; 32]);

        let post = |auth: Option<String>| {
            let app = admin_router(state.clone());
            let mut req = Request::post(format!("/admin/authorize-host/{tok}/help.bunsenbrenner.org"));
            if let Some(a) = auth {
                req = req.header("x-ct-admin-token", a);
            }
            app.oneshot(req.body(Body::empty()).unwrap())
        };

        // Wrong auth -> 401, nothing authorized.
        assert_eq!(post(None).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        assert!(!state.host_bind_allowed("help.bunsenbrenner.org", &tok_token));

        // Correct auth -> 200, the (host, token) pair is now bind-allowed.
        assert_eq!(post(Some(secret_hex)).await.unwrap().status(), StatusCode::OK);
        assert!(state.host_bind_allowed("help.bunsenbrenner.org", &tok_token));
        assert!(!state.host_bind_allowed("evil.example", &tok_token), "only the authorized host");
    }

    /// #666: the routing token must be acceptable via the `x-ct-routing-token` header on
    /// the `:host`-only route, not just the URL path -- this is the whole point of the
    /// fix (URL paths land in access logs, a header carrying the same bearer credential
    /// does not). Admin auth (`x-ct-admin-token`) is still required exactly as before;
    /// a missing/empty routing-token header must be refused distinctly (400) from a
    /// missing/wrong admin token (401).
    #[tokio::test]
    async fn authorize_host_accepts_the_routing_token_via_header_not_just_url_path_666() {
        let state = Arc::new(EdgeState::<Connection>::new());
        let secret = [0x66u8; 32];
        state.set_admin_token(secret);
        state.require_host_auth();
        let secret_hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        let tok = "dd".repeat(32);
        let tok_token = RoutingToken([0xdd; 32]);

        let post = |admin_auth: Option<&str>, routing_token: Option<&str>| {
            let app = admin_router(state.clone());
            let mut req = Request::post("/admin/authorize-host/help2.bunsenbrenner.org");
            if let Some(a) = admin_auth {
                req = req.header("x-ct-admin-token", a);
            }
            if let Some(t) = routing_token {
                req = req.header(ROUTING_TOKEN_HEADER, t);
            }
            app.oneshot(req.body(Body::empty()).unwrap())
        };

        // No admin auth at all -> 401, regardless of routing-token header.
        assert_eq!(post(None, Some(&tok)).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        assert!(!state.host_bind_allowed("help2.bunsenbrenner.org", &tok_token));

        // Correct admin auth, but no routing-token header -> 400, not treated as
        // "no owner" and not silently ignored.
        assert_eq!(post(Some(&secret_hex), None).await.unwrap().status(), StatusCode::BAD_REQUEST);
        assert!(!state.host_bind_allowed("help2.bunsenbrenner.org", &tok_token));

        // Correct admin auth + routing token via header -> 200, host now bind-allowed --
        // matches the path-form route's own outcome exactly.
        assert_eq!(post(Some(&secret_hex), Some(&tok)).await.unwrap().status(), StatusCode::OK);
        assert!(state.host_bind_allowed("help2.bunsenbrenner.org", &tok_token));
    }

    #[tokio::test]
    async fn authorize_host_sets_and_clears_the_gelb_cert_tier_via_the_query_param() {
        // #233: `?channel_tier=gelb` marks a host Gelb; a later call with no
        // `channel_tier` (the control plane's own push once a hostname
        // reaches Grün) clears it back to ordinary passthrough. No existing
        // caller ever sends this param, so its absence must be
        // indistinguishable from today.
        let state = Arc::new(EdgeState::<Connection>::new());
        let secret = [0x55u8; 32];
        state.set_admin_token(secret);
        let secret_hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        let tok = "dd".repeat(32);

        let post = |path: String| {
            let app = admin_router(state.clone());
            app.oneshot(
                Request::post(path)
                    .header("x-ct-admin-token", secret_hex.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
        };

        assert!(!state.is_gelb("gelb.bunsenbrenner.org"), "never marked -> not gelb");

        assert_eq!(
            post(format!("/admin/authorize-host/{tok}/gelb.bunsenbrenner.org?channel_tier=gelb")).await.unwrap().status(),
            StatusCode::OK
        );
        assert!(state.is_gelb("gelb.bunsenbrenner.org"));

        // No `channel_tier` param at all -> today's exact shape, and clears a previous Gelb mark.
        assert_eq!(
            post(format!("/admin/authorize-host/{tok}/gelb.bunsenbrenner.org")).await.unwrap().status(),
            StatusCode::OK
        );
        assert!(!state.is_gelb("gelb.bunsenbrenner.org"), "re-authorized with no tier -> reverted to passthrough");
    }

    #[tokio::test]
    async fn host_auth_dump_is_admin_gated_and_reports_current_authorizations() {
        // #153: the safe-backfill read path -- must require the admin token (it's
        // a live inventory of every hostname this edge currently serves) and must
        // report exactly what's actually authorized, in the hex form the control
        // plane's ownership registry stores.
        let state = Arc::new(EdgeState::<Connection>::new());
        let secret = [0x44u8; 32];
        state.set_admin_token(secret);
        state.require_host_auth();
        state.authorize_host("help.bunsenbrenner.org", RoutingToken([0xaa; 32]));
        state.authorize_host("flappy-demo.bunsenbrenner.org", RoutingToken([0xbb; 32]));
        let secret_hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();

        let get = |auth: Option<String>| {
            let app = admin_router(state.clone());
            let mut req = Request::get("/admin/host-auth-dump");
            if let Some(a) = auth {
                req = req.header("x-ct-admin-token", a);
            }
            app.oneshot(req.body(Body::empty()).unwrap())
        };

        assert_eq!(get(None).await.unwrap().status(), StatusCode::UNAUTHORIZED, "no admin token -> 401");

        let resp = get(Some(secret_hex)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let entries: Vec<HostAuthEntry> = serde_json::from_slice(&body).unwrap();
        let mut pairs: Vec<(String, String)> = entries.into_iter().map(|e| (e.hostname, e.token)).collect();
        pairs.sort();
        assert_eq!(
            pairs,
            vec![
                ("flappy-demo.bunsenbrenner.org".to_string(), "bb".repeat(32)),
                ("help.bunsenbrenner.org".to_string(), "aa".repeat(32)),
            ]
        );
    }

    #[tokio::test]
    async fn tunnel_status_is_admin_gated_and_reports_live_registration_count() {
        // Monitoring feature v1 (2026-08-01): the per-tunnel "connected or not" query --
        // must require the admin token, and must report the live registration count
        // (0 for never-registered/unknown). The boolean/count logic itself
        // (registered -> connected, redundant agents -> count > 1, evicted -> not
        // connected) is proven directly against EdgeState in state.rs's own
        // `tunnel_status_reflects_registration_count` test (generic over the handle
        // type, no real quinn::Connection needed); this test covers the HTTP/auth
        // layer this endpoint hardcodes EdgeState<Connection> for.
        let state = Arc::new(EdgeState::<Connection>::new());
        let secret = [0x66u8; 32];
        state.set_admin_token(secret);
        let secret_hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        let tok_hex = "cc".repeat(32);

        let get = |auth: Option<String>, path: String| {
            let app = admin_router(state.clone());
            let mut req = Request::get(path);
            if let Some(a) = auth {
                req = req.header("x-ct-admin-token", a);
            }
            app.oneshot(req.body(Body::empty()).unwrap())
        };

        assert_eq!(
            get(None, format!("/admin/tunnel-status/{tok_hex}")).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "no admin token -> 401"
        );

        // Never registered -> connected=false, registrations=0.
        let resp = get(Some(secret_hex.clone()), format!("/admin/tunnel-status/{tok_hex}")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let status: TunnelStatusResp = serde_json::from_slice(&body).unwrap();
        assert!(!status.connected);
        assert_eq!(status.registrations, 0);
        assert_eq!(status.bytes_received, 0, "never relayed anything -> 0");
        assert_eq!(status.bytes_sent, 0);

        // A relay against this token shows up in the byte counters (the
        // registration/connected-ness fields are unaffected by relay activity
        // alone -- `note_relay` never registers/deregisters an agent).
        let t = RoutingToken(parse_token_hex(&tok_hex).unwrap());
        state.note_relay(&t, 300, 120, RelayKind::DataPlane);
        let resp = get(Some(secret_hex.clone()), format!("/admin/tunnel-status/{tok_hex}")).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let status: TunnelStatusResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(status.bytes_received, 300, "client->agent direction");
        assert_eq!(status.bytes_sent, 120, "agent->client direction");

        // #544, the case this endpoint used to get wrong: an agent that reaches the edge
        // over the TLS-TCP fallback parks instead of registering over QUIC. Before this
        // fix `connected` was `registrations > 0`, so such a tunnel reported disconnected
        // while it was actively relaying -- the customer's portal (which deserialises this
        // very field) told them their agent was down, and an operator could not tell it
        // apart from a real outage. Observed live on 2026-08-17 with kali.bunsenbrenner.org,
        // which answered real HTTP while this endpoint said connected=false.
        let _park = state.park_tcp_agent(t.clone());
        let resp = get(Some(secret_hex.clone()), format!("/admin/tunnel-status/{tok_hex}")).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let status: TunnelStatusResp = serde_json::from_slice(&body).unwrap();
        assert!(status.connected, "a fallback-served tunnel is connected");
        assert_eq!(status.fallback_parked, 1, "and the transport is visible, not merged away");
        assert_eq!(
            status.registrations, 0,
            "`registrations` keeps its QUIC-only meaning -- the two transports are reported \
             beside each other because they fail differently"
        );

        // Malformed token hex -> 400, not a panic.
        assert_eq!(
            get(Some(secret_hex), "/admin/tunnel-status/not-hex".to_string()).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn channel_presence_is_admin_gated_and_reports_unknown_as_not_seen_763() {
        // #763: the presence read the portal's Agent-bridges card renders "Sidecar:
        // serving / not connected" from. Must require the admin token (401 without it),
        // answer an unknown (channel, holder) with exactly `{"seen":false}` (no `null`
        // fields for the CP to trip over), 400 malformed hex instead of panicking, and
        // -- once the broker has admitted that holder -- report it seen, parked now, and
        // fresh. The map's own ageing/bounding is proven against `ChannelPresence`
        // directly in channel_broker.rs; this covers the HTTP/auth layer.
        use ct_common::channel::ChannelId;

        let state = Arc::new(EdgeState::<Connection>::new());
        let secret = [0x77u8; 32];
        state.set_admin_token(secret);
        let secret_hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        // Unique to this test: the presence map is process-wide.
        let channel = [0x76u8; 32];
        let channel_hex = "76".repeat(32);
        let holder = [0x75u8; 32];
        let holder_hex = "75".repeat(32);

        let get = |auth: Option<String>, path: String| {
            let app = admin_router(state.clone());
            let mut req = Request::get(path);
            if let Some(a) = auth {
                req = req.header("x-ct-admin-token", a);
            }
            app.oneshot(req.body(Body::empty()).unwrap())
        };
        let one = format!("/internal/channel/presence/{channel_hex}/{holder_hex}");
        let list = format!("/internal/channel/presence/{channel_hex}");

        // No admin token -> 401 on both forms, nothing disclosed.
        assert_eq!(get(None, one.clone()).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        assert_eq!(get(None, list.clone()).await.unwrap().status(), StatusCode::UNAUTHORIZED);

        // Never admitted -> seen:false, and the list form is empty.
        let resp = get(Some(secret_hex.clone()), one.clone()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), r#"{"seen":false}"#, "the unseen shape is exactly this");
        let resp = get(Some(secret_hex.clone()), list.clone()).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: ChannelPresenceListResp = serde_json::from_slice(&body).unwrap();
        assert!(parsed.holders.is_empty());

        // The broker admits this holder (what both live offer sites do) -> seen, parked now.
        crate::channel_broker::note_channel_presence(
            ChannelId(channel),
            holder,
            crate::channel_broker::presence_unix_now(),
        );
        let resp = get(Some(secret_hex.clone()), one.clone()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: ChannelPresenceResp = serde_json::from_slice(&body).unwrap();
        assert!(parsed.seen);
        assert_eq!(parsed.parked_now, Some(true));
        assert!(parsed.last_seen_secs_ago.unwrap() <= 2, "just admitted -> fresh: {parsed:?}");
        let resp = get(Some(secret_hex.clone()), list.clone()).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: ChannelPresenceListResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.holders.len(), 1);
        assert_eq!(parsed.holders[0].holder, holder_hex);
        assert!(parsed.holders[0].parked_now);

        // Malformed hex -> 400, not a panic (either segment).
        assert_eq!(
            get(Some(secret_hex.clone()), format!("/internal/channel/presence/not-hex/{holder_hex}")).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            get(Some(secret_hex), format!("/internal/channel/presence/{channel_hex}/not-hex")).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn tunnel_history_is_admin_gated_and_reports_sessions_and_uptime_776() {
        // #776: the read the portal's "Connection history" card renders from. Must
        // require the admin token (401), 400 malformed hex, 404 while the store is
        // disabled (so the CP fails open like presence), and -- with one closed and one
        // open session -- return the documented JSON shape, newest first, with the
        // uptime computed from the rows. The store's own math is proven in
        // tunnel_history.rs and the lifecycle wiring in state.rs; this covers the HTTP
        // layer.
        use crate::tunnel_history::{SqliteTunnelHistory, TRANSPORT_QUIC};

        let state = Arc::new(EdgeState::<Connection>::new());
        let secret = [0x78u8; 32];
        state.set_admin_token(secret);
        let secret_hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        let tok_hex = "7a".repeat(32);
        let tok = RoutingToken([0x7a; 32]);

        let get = |auth: Option<String>, path: String| {
            let app = admin_router(state.clone());
            let mut req = Request::get(path);
            if let Some(a) = auth {
                req = req.header("x-ct-admin-token", a);
            }
            app.oneshot(req.body(Body::empty()).unwrap())
        };
        let path = format!("/internal/tunnel/history/{tok_hex}");

        // No admin token -> 401 (before any "is the store even on" answer leaks).
        assert_eq!(get(None, path.clone()).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        // Store not configured -> 404, the CP's fail-open signal.
        assert_eq!(get(Some(secret_hex.clone()), path.clone()).await.unwrap().status(), StatusCode::NOT_FOUND);

        let history = Arc::new(SqliteTunnelHistory::open_in_memory().unwrap());
        state.set_tunnel_history(history.clone());
        let now = crate::tunnel_history::now_secs();
        // One CLOSED 12 h session inside the last 24 h, written directly to the store...
        let hex = crate::tunnel_history::routing_token_hex(&tok);
        history.open_session(&hex, TRANSPORT_QUIC, now - 18 * 3600).unwrap();
        history.add_session_bytes(&hex, 500, 200, now - 12 * 3600).unwrap();
        history.close_session(&hex, now - 6 * 3600, "removed").unwrap();
        // ...and one OPEN session via the real registration path (a fallback park needs
        // no quinn handle, unlike `register`).
        let _park = state.park_tcp_agent(tok.clone());

        let resp = get(Some(secret_hex.clone()), format!("{path}?limit=10")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: TunnelHistoryResp = serde_json::from_slice(&body).unwrap();
        assert!(parsed.open, "the park opened a live session");
        assert_eq!(parsed.sessions.len(), 2);
        assert_eq!(parsed.sessions[0].transport, "tcp-fallback", "newest (open) first");
        assert_eq!(parsed.sessions[0].disconnected_at, None);
        assert_eq!(parsed.sessions[0].reason, None);
        assert_eq!(parsed.sessions[1].transport, "quic");
        assert_eq!(parsed.sessions[1].disconnected_at, Some(now - 6 * 3600));
        assert_eq!(parsed.sessions[1].reason.as_deref(), Some("removed"));
        assert_eq!((parsed.sessions[1].bytes_in, parsed.sessions[1].bytes_out), (500, 200));
        // 12 h closed + a just-opened live session (a few seconds at most) over 24 h.
        assert!(parsed.uptime.h24 >= 50.0 && parsed.uptime.h24 < 50.1, "{:?}", parsed.uptime);
        assert!(parsed.uptime.d7 > 0.0 && parsed.uptime.d30 > 0.0);

        // The raw JSON carries exactly the documented keys.
        let raw: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let mut keys: Vec<&str> = raw.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["open", "sessions", "uptime"]);
        let mut ukeys: Vec<&str> = raw["uptime"].as_object().unwrap().keys().map(String::as_str).collect();
        ukeys.sort_unstable();
        assert_eq!(ukeys, ["d30", "d7", "h24"]);
        let mut skeys: Vec<&str> = raw["sessions"][0].as_object().unwrap().keys().map(String::as_str).collect();
        skeys.sort_unstable();
        assert_eq!(skeys, ["bytes_in", "bytes_out", "connected_at", "disconnected_at", "reason", "transport"]);

        // `limit` is honoured (and an upper-case token segment resolves the same rows).
        let resp = get(Some(secret_hex.clone()), format!("/internal/tunnel/history/{}?limit=1", tok_hex.to_uppercase()))
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: TunnelHistoryResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.sessions.len(), 1);

        // An unknown token is an empty, zero-uptime answer, not an error.
        let resp = get(Some(secret_hex.clone()), format!("/internal/tunnel/history/{}", "7b".repeat(32))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: TunnelHistoryResp = serde_json::from_slice(&body).unwrap();
        assert!(!parsed.open && parsed.sessions.is_empty());
        assert_eq!((parsed.uptime.h24, parsed.uptime.d7, parsed.uptime.d30), (0.0, 0.0, 0.0));

        // Malformed hex -> 400, not a panic.
        assert_eq!(
            get(Some(secret_hex), "/internal/tunnel/history/not-hex".to_string()).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn receipts_routes_are_admin_gated_404_when_disabled_and_paginate_with_since_782() {
        // #782: the two reads the control plane's receipts export is built from. Both must
        // require the admin token (401), answer 404 while no signer is installed (history
        // off, or CT_EDGE_RECEIPTS=off) so the CP reports "unavailable" instead of
        // exporting an empty file, and -- with a signer -- publish the key and page the
        // token's chain ascending with an exclusive `since` cursor. The chain's own
        // construction is proven in tunnel_history.rs; this covers the HTTP layer.
        use crate::tunnel_history::{SqliteTunnelHistory, TRANSPORT_QUIC};
        use ct_common::receipt::{self, ReceiptSigner};

        let state = Arc::new(EdgeState::<Connection>::new());
        let secret = [0x82u8; 32];
        state.set_admin_token(secret);
        let secret_hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        let tok_hex = "7c".repeat(32);
        let tok = RoutingToken([0x7c; 32]);

        let get = |auth: Option<String>, path: String| {
            let app = admin_router(state.clone());
            let mut req = Request::get(path);
            if let Some(a) = auth {
                req = req.header("x-ct-admin-token", a);
            }
            app.oneshot(req.body(Body::empty()).unwrap())
        };
        let pubkey_path = "/internal/receipts/pubkey".to_string();
        let path = format!("/internal/tunnel/receipts/{tok_hex}");

        // No admin token -> 401 on both.
        assert_eq!(get(None, pubkey_path.clone()).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        assert_eq!(get(None, path.clone()).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        // No history store at all -> 404 on both.
        assert_eq!(get(Some(secret_hex.clone()), pubkey_path.clone()).await.unwrap().status(), StatusCode::NOT_FOUND);
        assert_eq!(get(Some(secret_hex.clone()), path.clone()).await.unwrap().status(), StatusCode::NOT_FOUND);

        // A history store WITHOUT a signer (CT_EDGE_RECEIPTS=off) -> still 404 on both,
        // while the history route itself keeps working.
        state.set_tunnel_history(Arc::new(SqliteTunnelHistory::open_in_memory().unwrap()));
        assert_eq!(get(Some(secret_hex.clone()), pubkey_path.clone()).await.unwrap().status(), StatusCode::NOT_FOUND);
        assert_eq!(get(Some(secret_hex.clone()), path.clone()).await.unwrap().status(), StatusCode::NOT_FOUND);
        assert_eq!(
            get(Some(secret_hex.clone()), format!("/internal/tunnel/history/{tok_hex}")).await.unwrap().status(),
            StatusCode::OK
        );

        // With a signer: the pubkey route publishes the key + edge id...
        let signer = ReceiptSigner::from_seed(&[0x82u8; 32], "edge-82");
        let expected_pubkey = signer.pubkey_hex();
        let history = Arc::new(SqliteTunnelHistory::open_in_memory().unwrap().with_receipts(signer).unwrap());
        state.set_tunnel_history(history.clone());
        let resp = get(Some(secret_hex.clone()), pubkey_path.clone()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: ReceiptsPubkeyResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            parsed,
            ReceiptsPubkeyResp { alg: "ed25519".into(), pubkey: expected_pubkey.clone(), edge_id: "edge-82".into() }
        );

        // ...and the receipts route pages the token's chain. Three sessions via the
        // store (six receipts), then one live open via the registration path.
        let hex = crate::tunnel_history::routing_token_hex(&tok);
        for i in 0..3 {
            history.open_session(&hex, TRANSPORT_QUIC, 1_000 + i * 100).unwrap();
            history.close_session(&hex, 1_050 + i * 100, "removed").unwrap();
        }
        let _park = state.park_tcp_agent(tok.clone());

        let resp = get(Some(secret_hex.clone()), path.clone()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: TunnelReceiptsResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.pubkey, expected_pubkey);
        assert_eq!(parsed.edge_id, "edge-82");
        assert_eq!(parsed.receipts.iter().map(|r| r.seq).collect::<Vec<_>>(), (1..=7).collect::<Vec<_>>());
        assert_eq!(parsed.receipts[6].kind, receipt::KIND_SESSION_OPEN, "the live park's open receipt");
        assert_eq!(parsed.receipts[6].payload["transport"], "tcp-fallback");
        assert!(!body.windows(64).any(|w| w == tok_hex.as_bytes()), "the raw routing token never appears");
        assert_eq!(parsed.receipts[0].routing_token_hash, receipt::routing_token_hash(&tok.0));
        let key = receipt::pubkey_from_hex(&parsed.pubkey).unwrap();
        receipt::verify_chain(&parsed.receipts, &key).expect("the served page verifies under the served key");
        // The raw JSON carries exactly the documented top-level keys and receipt keys.
        let raw: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let mut keys: Vec<&str> = raw.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["edge_id", "pubkey", "receipts"]);
        let mut rkeys: Vec<&str> = raw["receipts"][0].as_object().unwrap().keys().map(String::as_str).collect();
        rkeys.sort_unstable();
        assert_eq!(
            rkeys,
            ["edge_id", "hash", "kind", "payload", "prev_hash", "routing_token_hash", "seq", "sig", "ts"]
        );

        // `since` is an exclusive cursor and `limit` a page size (upper-case hex resolves too).
        let upper = format!("/internal/tunnel/receipts/{}?since=2&limit=3", tok_hex.to_uppercase());
        let resp = get(Some(secret_hex.clone()), upper).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: TunnelReceiptsResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.receipts.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![3, 4, 5]);
        let resp = get(Some(secret_hex.clone()), format!("{path}?since=7")).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: TunnelReceiptsResp = serde_json::from_slice(&body).unwrap();
        assert!(parsed.receipts.is_empty(), "past the head -> empty page, not an error");

        // An unknown token is an empty page; malformed hex -> 400.
        let unknown = format!("/internal/tunnel/receipts/{}", "7d".repeat(32));
        let resp = get(Some(secret_hex.clone()), unknown).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: TunnelReceiptsResp = serde_json::from_slice(&body).unwrap();
        assert!(parsed.receipts.is_empty());
        assert_eq!(
            get(Some(secret_hex), "/internal/tunnel/receipts/not-hex".to_string()).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }

    /// Same bug class as ct-agent#36: a 64-BYTE string containing a multi-byte UTF-8
    /// char (`U+FFFD` is 3 bytes) passes the `s.len() != 64` guard, then the old
    /// `&s[i*2..i*2+2]` string-slicing panicked the moment an `i*2` offset fell inside
    /// that char instead of on a boundary. `\u{FFFD}` (3 bytes) + 61 ASCII hex digits =
    /// 64 bytes / 62 chars -- reproduces the exact construction from the fixed function's
    /// doc comment.
    #[test]
    fn parse_token_hex_rejects_rather_than_panics_on_a_multi_byte_char_at_a_bad_offset() {
        let s: String = "\u{FFFD}".to_string() + &"a".repeat(61);
        assert_eq!(s.len(), 64, "byte-length guard alone would let this through");
        assert_eq!(parse_token_hex(&s), None);
    }

    #[tokio::test]
    async fn revoke_rejects_rather_than_panics_on_a_malformed_multi_byte_token_path_segment() {
        // The `x-ct-admin-token` HEADER path is NOT vulnerable to this: HeaderValue::to_str()
        // rejects any non-ASCII byte before parse_token_hex ever runs, confirmed separately
        // (an earlier draft of this test wrongly assumed the opposite). The real trigger is
        // the `:token` URL segment, which axum's `Path<String>` percent-decodes into a plain
        // String with no such restriction -- and is reachable only by a caller who already
        // passes the admin-secret check (this test authenticates first).
        let state = Arc::new(EdgeState::<Connection>::new());
        let secret = [0x22u8; 32];
        state.set_admin_token(secret);
        let secret_hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        // Percent-encoded U+FFFD (3 bytes: %EF%BF%BD) + 61 ASCII 'a's decodes to a 64-byte,
        // 62-char token -- passes `s.len() != 64`, then panics the old string-slicing code.
        let bad_token = format!("%EF%BF%BD{}", "a".repeat(61));

        let app = admin_router(state);
        let req = Request::post(format!("/admin/revoke/{bad_token}"))
            .header("x-ct-admin-token", secret_hex)
            .body(Body::empty())
            .unwrap();
        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn access_policy_push_is_admin_gated_stores_validates_and_clears_779() {
        use ct_common::access_window::AccessPolicy;
        let state = Arc::new(EdgeState::<Connection>::new());
        let secret = [0x79u8; 32];
        state.set_admin_token(secret);
        let secret_hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        let tok_hex = "ab".repeat(32);
        let token = RoutingToken([0xab; 32]);

        let post = |auth: Option<String>, tok: Option<String>, body: &'static str| {
            let app = admin_router(state.clone());
            let mut req = Request::post("/internal/tunnel/access-policy").header("content-type", "application/json");
            if let Some(a) = auth {
                req = req.header("x-ct-admin-token", a);
            }
            if let Some(t) = tok {
                req = req.header("x-ct-routing-token", t);
            }
            app.oneshot(req.body(Body::from(body)).unwrap())
        };
        let expiring = r#"{"expires_at":100}"#;

        // Wrong/missing admin auth -> 401, nothing stored.
        assert_eq!(post(None, Some(tok_hex.clone()), expiring).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        assert!(state.access_policy(&token).is_none());
        // Missing / malformed routing token -> 400.
        assert_eq!(post(Some(secret_hex.clone()), None, expiring).await.unwrap().status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            post(Some(secret_hex.clone()), Some("zz".repeat(32)), expiring).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
        // A policy that fails validation (day 9) -> 400, nothing stored.
        assert_eq!(
            post(
                Some(secret_hex.clone()),
                Some(tok_hex.clone()),
                r#"{"schedule":{"tz_offset_minutes":0,"slots":[{"day":9,"start_minute":0,"end_minute":60}]}}"#,
            )
            .await
            .unwrap()
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert!(state.access_policy(&token).is_none());

        // A valid push lands in the map and is evaluated locally from then on.
        let ok = post(Some(secret_hex.clone()), Some(tok_hex.clone()), expiring).await.unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        assert_eq!(state.access_policy(&token), Some(AccessPolicy { expires_at: Some(100), schedule: None }));
        assert!(state.access_window_open(&token, 99));
        assert!(!state.access_window_open(&token, 100));

        // `null` clears it.
        let cleared = post(Some(secret_hex.clone()), Some(tok_hex.clone()), "null").await.unwrap();
        assert_eq!(cleared.status(), StatusCode::OK);
        assert!(state.access_policy(&token).is_none());
        assert!(state.access_window_open(&token, 100));

        // Revoke clears a pushed policy too (the same admin listener's revoke route).
        let again = post(Some(secret_hex.clone()), Some(tok_hex.clone()), expiring).await.unwrap();
        assert_eq!(again.status(), StatusCode::OK);
        let revoke = admin_router(state.clone())
            .oneshot(
                Request::post(format!("/admin/revoke/{tok_hex}"))
                    .header("x-ct-admin-token", secret_hex.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoke.status(), StatusCode::OK);
        assert!(state.access_policy(&token).is_none(), "revoke must drop the policy with the token");
    }
}
