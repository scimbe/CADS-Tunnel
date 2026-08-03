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
         # HELP ct_edge_failovers_total Relays that failed over to a non-primary agent.\n\
         # TYPE ct_edge_failovers_total counter\n\
         ct_edge_failovers_total {failovers}\n",
        tunnels = state.active_tunnels(),
        agents = state.total_registrations(),
        registrations = state.registrations_total(),
        relays = state.relays_total(),
        relay_bytes = state.relay_bytes_total(),
        failovers = state.failovers_total(),
    );
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

/// Build the metrics router: `GET /metrics` renders the current gauges.
pub fn metrics_router(state: Arc<EdgeState<Connection>>, ws_channel_cap: Option<ConnectionCap>) -> Router {
    Router::new()
        .route("/metrics", get(render))
        .with_state((state, ws_channel_cap))
}

async fn render(State((state, ws_channel_cap)): State<(Arc<EdgeState<Connection>>, Option<ConnectionCap>)>) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4")],
        render_edge_metrics(&*state, ws_channel_cap.as_ref()),
    )
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
        state.note_relay(&token(1), 100, 50);
        state.note_failover();
        let body = render_edge_metrics(&state, None);
        assert!(body.contains("ct_edge_registrations_total 2"), "{body}");
        assert!(body.contains("ct_edge_relays_total 1"), "{body}");
        assert!(body.contains("ct_edge_relay_bytes_total 150"), "{body}");
        assert!(body.contains("ct_edge_failovers_total 1"), "{body}");
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
