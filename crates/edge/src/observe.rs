//! Edge observability endpoint (#10, ADR-0016).
//!
//! Serves the Edge's data-plane gauges over HTTP in the Prometheus text
//! exposition format so a scraper can read `GET /metrics`. The Edge is
//! provider-blind, so this exposes **only metadata/counters** — how many tunnels
//! and Agent registrations the Edge is serving — never any payload.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use quinn::Connection;

use crate::state::{ConnectionCap, EdgeState};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Render the Edge's live gauges in the Prometheus text exposition format.
/// Generic over the handle type so it is unit-testable without live QUIC
/// connections (O1: live gauges; cumulative counters land in O2).
///
/// `ws_channel_cap` is the video-conferencing feature's browser WebSocket channel
/// listener's connection cap (`None` when that listener/cap is disabled) -- unlike
/// every gauge above, which reads from `EdgeState`, this reads directly from the
/// `ConnectionCap` itself (ws_channel.rs has no `EdgeState` of its own; wiring one in
/// just for this would be a much larger, unrelated change for one metric).
pub fn render_edge_metrics<H: Clone>(state: &EdgeState<H>, ws_channel_cap: Option<&ConnectionCap>) -> String {
    let mut out = format!(
        "# HELP ct_edge_active_tunnels Distinct routing tokens with at least one live agent.\n\
         # TYPE ct_edge_active_tunnels gauge\n\
         ct_edge_active_tunnels {tunnels}\n\
         # HELP ct_edge_active_agents Total live agent registrations (redundant agents counted).\n\
         # TYPE ct_edge_active_agents gauge\n\
         ct_edge_active_agents {agents}\n\
         # HELP ct_edge_registrations_total Agent registrations accepted since start.\n\
         # TYPE ct_edge_registrations_total counter\n\
         ct_edge_registrations_total {registrations}\n\
         # HELP ct_edge_relays_total Client relays served since start.\n\
         # TYPE ct_edge_relays_total counter\n\
         ct_edge_relays_total {relays}\n\
         # HELP ct_edge_relay_bytes_total Bytes relayed (both directions) since start.\n\
         # TYPE ct_edge_relay_bytes_total counter\n\
         ct_edge_relay_bytes_total {relay_bytes}\n\
         # HELP ct_edge_relay_bytes_kind_total Relayed bytes split by plane (#517 V1: the\n\
         # traffic-offload measurement base -- browser = SNI/Gelb browser traffic to a QUIC\n\
         # agent, dataplane = QUIC client relays, tcp_fallback = every relay with a TLS-TCP\n\
         # fallback leg, agent-side (a parked fallback agent, #534) or client-side (the :4433\n\
         # 'C'/'M' roles); the three sum to ct_edge_relay_bytes_total).\n\
         # TYPE ct_edge_relay_bytes_kind_total counter\n\
         ct_edge_relay_bytes_kind_total{{kind=\"browser\"}} {relay_bytes_browser}\n\
         ct_edge_relay_bytes_kind_total{{kind=\"dataplane\"}} {relay_bytes_dataplane}\n\
         ct_edge_relay_bytes_kind_total{{kind=\"tcp_fallback\"}} {relay_bytes_tcp_fallback}\n\
         # HELP ct_edge_channel_relay_bytes_total Bytes relayed through CHANNEL splices\n\
         # (both directions, both completer families) since start -- previously not\n\
         # counted anywhere (#517 V1).\n\
         # TYPE ct_edge_channel_relay_bytes_total counter\n\
         ct_edge_channel_relay_bytes_total {channel_relay_bytes}\n\
         # HELP ct_edge_channel_splices_total Completed channel relay splices since start.\n\
         # TYPE ct_edge_channel_splices_total counter\n\
         ct_edge_channel_splices_total {channel_splices}\n\
         # HELP ct_edge_channel_park_reaped_total Channel-pairer parks reaped past their TTL\n\
         # with no partner since start (#530) -- the channel plane's counterpart to\n\
         # ct_edge_tcp_fallback_reaped_total. Counts EVERY reap (including ones whose log\n\
         # line the bounded reap logging suppresses); a steady rate is the designed\n\
         # serve-loop re-park cycle (ct-agent#21), a sustained CHANGE in the rate is the\n\
         # regression signal.\n\
         # TYPE ct_edge_channel_park_reaped_total counter\n\
         ct_edge_channel_park_reaped_total {channel_park_reaped}\n\
         # HELP ct_edge_front_door_client_aborts_total :443 front-door connections that ended\n\
         # in a BENIGN client abort (ECONNRESET, EPIPE, or a peer that dropped the connection\n\
         # without sending TLS close_notify) since start (#533) -- normal client behavior, not\n\
         # an edge fault: a 2026-08-16 load test produced 158 of these from 340 SUCCESSFUL\n\
         # requests. Counts EVERY such abort, including the ones whose log line the bounded\n\
         # front-door abort logging suppresses, so the rate stays fully visible while the log\n\
         # keeps only a bounded sample. Errors that are NOT provably benign are never counted\n\
         # here and are still logged line by line (#127).\n\
         # TYPE ct_edge_front_door_client_aborts_total counter\n\
         ct_edge_front_door_client_aborts_total {front_door_client_aborts}\n\
         # HELP ct_edge_failovers_total Relays that failed over to a non-primary agent.\n\
         # TYPE ct_edge_failovers_total counter\n\
         ct_edge_failovers_total {failovers}\n\
         # HELP ct_edge_tcp_fallback_parked TLS-TCP fallback registrations parked right now \
         (the fallback counterpart to ct_edge_active_tunnels).\n\
         # TYPE ct_edge_tcp_fallback_parked gauge\n\
         ct_edge_tcp_fallback_parked {tcp_parked}\n\
         # HELP ct_edge_tcp_fallback_parks_total TLS-TCP fallback parks since start; its RATE is \
         the fallback pool's churn rate (each park is one agent-side connection joining the pool).\n\
         # TYPE ct_edge_tcp_fallback_parks_total counter\n\
         ct_edge_tcp_fallback_parks_total {tcp_parks}\n\
         # HELP ct_edge_tcp_fallback_reaped_total Dead TLS-TCP fallback parks reaped by the\n\
         # periodic sweep since start (#522). Its RATE is the park-orphan rate; a sustained\n\
         # rise is the regression signal that agents are abandoning parks faster than usual.\n\
         # TYPE ct_edge_tcp_fallback_reaped_total counter\n\
         ct_edge_tcp_fallback_reaped_total {tcp_reaped}\n\
         # HELP ct_edge_tcp_fallback_deliveries_total TLS-TCP fallback parks consumed by a client.\n\
         # TYPE ct_edge_tcp_fallback_deliveries_total counter\n\
         ct_edge_tcp_fallback_deliveries_total {tcp_deliveries}\n",
        tunnels = state.active_tunnels(),
        agents = state.total_registrations(),
        registrations = state.registrations_total(),
        relays = state.relays_total(),
        relay_bytes = state.relay_bytes_total(),
        relay_bytes_browser = state.relay_bytes_by_kind().0,
        relay_bytes_dataplane = state.relay_bytes_by_kind().1,
        relay_bytes_tcp_fallback = state.relay_bytes_by_kind().2,
        channel_relay_bytes = crate::channel_broker::channel_relay_totals().0,
        channel_splices = crate::channel_broker::channel_relay_totals().1,
        channel_park_reaped = crate::channel_broker::channel_park_reaped_total(),
        front_door_client_aborts = crate::serve::front_door_client_aborts_total(),
        failovers = state.failovers_total(),
        tcp_parked = state.tcp_parked(),
        tcp_parks = state.tcp_parks_total(),
        tcp_reaped = state.tcp_reaped_total(),
        tcp_deliveries = state.tcp_deliveries_total(),
    );
    // #497 slice 2: broker-loop liveness. Raw unix seconds (0 = loop never started); a
    // scraper alerts on staleness -- with the loops' own 10s idle tick, a value older than
    // ~30s means the accept loop is wedged, not idle (the 2026-08-13 outage class, invisible
    // to the process-level healthcheck).
    out.push_str(&format!(
        "# HELP ct_edge_channel_broker_loop_last_seen_seconds Unix time of each QUIC broker \
         accept loop's last iteration (idle ticks included); 0 = never started. Staleness \
         beyond ~30s means the loop is wedged.\n\
         # TYPE ct_edge_channel_broker_loop_last_seen_seconds gauge\n\
         ct_edge_channel_broker_loop_last_seen_seconds{{loop=\"relay\"}} {relay}\n\
         ct_edge_channel_broker_loop_last_seen_seconds{{loop=\"rendezvous\"}} {rendezvous}\n",
        relay = state.relay_broker_heartbeat().last_seen(),
        rendezvous = state.rendezvous_broker_heartbeat().last_seen(),
    ));
    if let Some(cap) = ws_channel_cap {
        out.push_str(&format!(
            "# HELP ct_edge_ws_channel_connections Browser WebSocket Agent-Fabric channel \
             connections currently admitted (video-conferencing feature).\n\
             # TYPE ct_edge_ws_channel_connections gauge\n\
             ct_edge_ws_channel_connections {in_use}\n\
             # HELP ct_edge_ws_channel_connections_max The configured cap (CT_EDGE_MAX_WS_CHANNEL_CONNECTIONS).\n\
             # TYPE ct_edge_ws_channel_connections_max gauge\n\
             ct_edge_ws_channel_connections_max {max}\n\
             # HELP ct_edge_ws_channel_shed_total WS channel connections shed since start (cap was full).\n\
             # TYPE ct_edge_ws_channel_shed_total counter\n\
             ct_edge_ws_channel_shed_total {shed}\n",
            in_use = cap.in_use(),
            max = cap.max(),
            shed = cap.shed_total(),
        ));
    }
    out
}

/// #498: how stale a broker-loop heartbeat may be before `/healthz` reports the loop as
/// wedged. The loops beat every iteration INCLUDING their 10s idle tick, so 60s (6 missed
/// ticks) is far above scheduler jitter and far below the latency at which an operator (or
/// a dependent's `service_healthy` condition) needs the truth.
pub const BROKER_HEALTH_MAX_AGE_SECS: u64 = 60;

/// #498: pure health classifier over the two QUIC broker-loop heartbeats. `Ok(())` when every
/// loop that has EVER beaten (`last_seen > 0`) beat within `max_age` of `now`; `Err` names
/// each stale loop and its age. A never-started loop (`last_seen == 0`) is deliberately NOT a
/// failure: the relay loop legitimately refuses to start on an address collision (the #103
/// guard), and boot is the container healthcheck's `start_period`. Documented trade-off: a
/// loop that wedges before its very first beat is invisible here -- the observed outage class
/// (2026-08-13) is a long-running loop wedging later, and the first beat lands within one
/// idle tick of spawn. Pure -- the caller supplies `now` -- so tests need no clock.
pub fn broker_loops_health(
    relay_last_seen: u64,
    rendezvous_last_seen: u64,
    now: u64,
    max_age_secs: u64,
) -> Result<(), String> {
    let mut stale = Vec::new();
    for (name, last) in [("relay", relay_last_seen), ("rendezvous", rendezvous_last_seen)] {
        if last > 0 && now.saturating_sub(last) > max_age_secs {
            stale.push(format!("{name} (last beat {}s ago)", now.saturating_sub(last)));
        }
    }
    if stale.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "wedged channel broker loop(s): {} -- the accept loop stopped iterating (idle \
             ticks included), so channel joins on that transport stall (#498)",
            stale.join(", ")
        ))
    }
}

/// Build the metrics router: `GET /metrics` renders the current gauges; `GET /healthz` (#498)
/// answers 200 only while the broker accept loops are provably iterating -- the container
/// healthcheck's probe target, so "healthy" means "can admit channel joins", not merely "the
/// metrics HTTP server responds".
pub fn metrics_router(state: Arc<EdgeState<Connection>>, ws_channel_cap: Option<ConnectionCap>) -> Router {
    Router::new()
        .route("/metrics", get(render))
        .route("/healthz", get(healthz))
        .with_state((state, ws_channel_cap))
}

async fn render(State((state, ws_channel_cap)): State<(Arc<EdgeState<Connection>>, Option<ConnectionCap>)>) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4")],
        render_edge_metrics(&*state, ws_channel_cap.as_ref()),
    )
}

async fn healthz(State((state, _)): State<(Arc<EdgeState<Connection>>, Option<ConnectionCap>)>) -> impl IntoResponse {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match broker_loops_health(
        state.relay_broker_heartbeat().last_seen(),
        state.rendezvous_broker_heartbeat().last_seen(),
        now,
        BROKER_HEALTH_MAX_AGE_SECS,
    ) {
        Ok(()) => (axum::http::StatusCode::OK, "ok\n".to_string()),
        Err(why) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, format!("{why}\n")),
    }
}

/// Bind `listen` and serve the Edge metrics endpoint until the process exits.
pub async fn serve_metrics(
    listen: SocketAddr,
    state: Arc<EdgeState<Connection>>,
    ws_channel_cap: Option<ConnectionCap>,
) -> Result<(), BoxError> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, metrics_router(state, ws_channel_cap)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::RelayKind;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use ct_common::RoutingToken;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn token(b: u8) -> RoutingToken {
        RoutingToken([b; 32])
    }

    #[test]
    fn gauges_reflect_registered_agents() {
        // Two agents on token A (redundant, #8) + one on token B → 2 tunnels,
        // 3 registrations. Generic over the handle so no live QUIC is needed.
        let state: EdgeState<u32> = EdgeState::new();
        state.register(token(1), 10);
        state.register(token(1), 11);
        state.register(token(2), 20);
        let body = render_edge_metrics(&state, None);
        assert!(body.contains("ct_edge_active_tunnels 2"), "{body}");
        assert!(body.contains("ct_edge_active_agents 3"), "{body}");
    }

    #[test]
    fn cumulative_counters_render_after_activity() {
        // #10 O2: registrations count every registration; relays/bytes/failovers
        // reflect data-plane activity.
        let state: EdgeState<u32> = EdgeState::new();
        state.register(token(1), 10);
        state.register(token(1), 11); // redundant → 2 registrations
        state.note_relay(&token(1), 100, 50, RelayKind::DataPlane);
        state.note_failover();
        // #517 V1: the per-plane split renders alongside the historical total.
        state.note_relay(&token(1), 7, 3, RelayKind::Browser);
        state.note_relay(&token(1), 1, 1, RelayKind::TcpFallback);
        let body = render_edge_metrics(&state, None);
        assert!(body.contains("ct_edge_registrations_total 2"), "{body}");
        assert!(body.contains("ct_edge_relays_total 3"), "{body}");
        assert!(body.contains("ct_edge_relay_bytes_total 162"), "{body}");
        assert!(body.contains("ct_edge_failovers_total 1"), "{body}");
        assert!(body.contains(r#"ct_edge_relay_bytes_kind_total{kind="browser"} 10"#), "{body}");
        assert!(body.contains(r#"ct_edge_relay_bytes_kind_total{kind="dataplane"} 150"#), "{body}");
        assert!(body.contains(r#"ct_edge_relay_bytes_kind_total{kind="tcp_fallback"} 2"#), "{body}");
        assert!(body.contains("ct_edge_channel_relay_bytes_total"), "{body}");
        assert!(body.contains("ct_edge_channel_splices_total"), "{body}");
        // #530: the channel-pairer reap counter renders (value is a process-wide
        // static shared with other tests, so assert presence, not a number).
        assert!(body.contains("ct_edge_channel_park_reaped_total"), "{body}");
        // #533: same for the front-door benign client-abort counter.
        assert!(body.contains("ct_edge_front_door_client_aborts_total"), "{body}");
    }

    #[tokio::test]
    async fn metrics_endpoint_serves_prometheus() {
        let state = Arc::new(EdgeState::<Connection>::new());
        let app = metrics_router(state, None);
        let resp = app
            .oneshot(Request::builder().uri("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "text/plain; version=0.0.4"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("ct_edge_active_tunnels 0"), "empty edge → 0 tunnels: {text}");
        assert!(text.contains("ct_edge_active_agents 0"));
        assert!(!text.contains("ct_edge_ws_channel_"), "no ws_channel_cap -> no ws-channel gauges at all: {text}");
    }

    #[test]
    fn broker_loops_health_classifies_fresh_stale_and_never_started_498() {
        // Fresh beats within the window -> healthy.
        assert!(broker_loops_health(1_000, 1_005, 1_030, 60).is_ok());
        // Exactly at the boundary is still healthy; one past it is not.
        assert!(broker_loops_health(940, 1_000, 1_000, 60).is_ok());
        let why = broker_loops_health(939, 1_000, 1_000, 60).expect_err("61s old = wedged");
        assert!(why.contains("relay") && why.contains("61s"), "names the stale loop and age: {why}");
        assert!(!why.contains("rendezvous ("), "the fresh loop is not named: {why}");
        // Both stale -> both named.
        let why = broker_loops_health(100, 200, 1_000, 60).expect_err("both wedged");
        assert!(why.contains("relay") && why.contains("rendezvous"), "{why}");
        // Never-started (0) is NOT a failure -- the relay loop legitimately refuses to start
        // on a #103 address collision, and boot is covered by the healthcheck start_period.
        assert!(broker_loops_health(0, 1_000, 1_030, 60).is_ok());
        assert!(broker_loops_health(0, 0, 1_030, 60).is_ok());
    }

    #[tokio::test]
    async fn healthz_endpoint_reports_200_fresh_and_503_wedged_498() {
        // Router-level: a fresh heartbeat answers 200 "ok"; a stale one flips the SAME
        // endpoint to 503 with a body naming the wedged loop -- the exact signal the
        // container healthcheck consumes (#498).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let state = Arc::new(EdgeState::<Connection>::new());
        state.relay_broker_heartbeat().beat(now);
        state.rendezvous_broker_heartbeat().beat(now);
        let resp = metrics_router(state.clone(), None)
            .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        state.relay_broker_heartbeat().beat(now - BROKER_HEALTH_MAX_AGE_SECS - 120);
        let resp = metrics_router(state, None)
            .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("relay") && text.contains("#498"), "names the wedged loop: {text}");
    }

    #[test]
    fn ws_channel_gauges_reflect_the_caps_real_state_when_present() {
        // Video-conferencing feature: the cap's own in_use()/max()/shed_total() feed
        // these gauges directly, so this is a real (not merely "does it render")
        // check -- admit 2 of a 3-slot cap, force one shed, and confirm the exact
        // numbers show up.
        let state: EdgeState<u32> = EdgeState::new();
        let cap = ConnectionCap::new(3);
        let _p1 = cap.try_admit().expect("slot 1");
        let _p2 = cap.try_admit().expect("slot 2");
        cap.note_shed();
        let body = render_edge_metrics(&state, Some(&cap));
        assert!(body.contains("ct_edge_ws_channel_connections 2"), "{body}");
        assert!(body.contains("ct_edge_ws_channel_connections_max 3"), "{body}");
        assert!(body.contains("ct_edge_ws_channel_shed_total 1"), "{body}");
    }
}
