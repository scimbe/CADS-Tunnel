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
         # HELP ct_edge_channel_rendezvous_pairs_total Completed rendezvous pairings since \
start -- the edge handed both sides the other's endpoint and left the data path (#517 V1). \
Read WITH _splices_total: pairs>0 and splices==0 means the channel plane offloaded \
completely, while both at 0 means nothing was measured, not that offload succeeded.\n\
         # TYPE ct_edge_channel_rendezvous_pairs_total counter\n\
         ct_edge_channel_rendezvous_pairs_total {channel_pairs}\n\
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
        channel_pairs = crate::channel_broker::channel_rendezvous_pairs_total(),
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
    // #546: does a member's ADVERTISED endpoint match the source address the edge actually
    // observed? Counting only -- nothing is refused on this basis. `cross_family` is broken
    // out because a dual-stack member legitimately advertises the other family, and folding
    // it into `mismatch` would bury the signal in a legitimate case.
    {
        let (m, cf, mm, na, un) = crate::channel_broker::endpoint_attestation_totals();
        out.push_str(&format!(
            "# HELP ct_edge_channel_endpoint_attestation_total Channel joins by how the \
advertised endpoint relates to the edge-observed source address (#546). `mismatch` is the \
one enforcement refuses: observed on a GLOBAL address, advertised a different one of the \
same family. `unobservable` is a member the edge saw on a private address, where equality is \
structurally impossible -- kept separate so `mismatch` answers the enforcement question on \
its own. `cross_family` is ordinary dual-stack.\n\
         # TYPE ct_edge_channel_endpoint_attestation_total counter\n\
         ct_edge_channel_endpoint_attestation_total{{result=\"matches\"}} {m}\n\
         ct_edge_channel_endpoint_attestation_total{{result=\"cross_family\"}} {cf}\n\
         ct_edge_channel_endpoint_attestation_total{{result=\"mismatch\"}} {mm}\n\
         ct_edge_channel_endpoint_attestation_total{{result=\"no_address\"}} {na}\n\
         ct_edge_channel_endpoint_attestation_total{{result=\"unobservable\"}} {un}\n",
        ));
    }
    // #539: the companion gauge, without which the one above is ambiguous at 0 -- a loop the
    // edge never meant to run and one that was meant to run and never came up both read as 0.
    // Alert on `expected_since > 0 AND last_seen == 0` for longer than a boot; that is a loop
    // that failed to bind, and it is invisible in the last_seen gauge alone.
    out.push_str(&format!(
        "# HELP ct_edge_channel_broker_loop_expected_since_seconds Unix time at which the edge \
         decided to run each QUIC broker accept loop; 0 = deliberately not run (e.g. the #103 \
         address-collision guard). Paired with _last_seen_seconds: expected but never seen = \
         the loop failed to come up.\n\
         # TYPE ct_edge_channel_broker_loop_expected_since_seconds gauge\n\
         ct_edge_channel_broker_loop_expected_since_seconds{{loop=\"relay\"}} {relay}\n\
         ct_edge_channel_broker_loop_expected_since_seconds{{loop=\"rendezvous\"}} {rendezvous}\n",
        relay = state.relay_broker_heartbeat().expected_since(),
        rendezvous = state.rendezvous_broker_heartbeat().expected_since(),
    ));
    // #551: the per-IP join-refusal penalty (#414/#542/#547) had no surface at all. Both
    // numbers are needed and they answer different questions: `sheds_total` says whether
    // the penalty has ever done anything, `tracked_ips` says whether it still CAN.
    let penalty = state.join_refusal_penalty();
    out.push_str(&format!(
        "# HELP ct_edge_channel_join_penalty_sheds_total Channel-join connections shed \
         pre-handshake because their source IP exhausted its definitive-refusal budget.\n\
         # TYPE ct_edge_channel_join_penalty_sheds_total counter\n\
         ct_edge_channel_join_penalty_sheds_total {sheds}\n\
         # HELP ct_edge_channel_join_penalty_tracked_ips Distinct source IPs currently \
         tracked by the penalty. Read this against ..._max: the table evicts oldest-first \
         at the bound, so a value AT the bound means entries are being pushed out before \
         they can reach the per-IP budget and the penalty is degraded -- which is what a \
         refusal storm spread across many sources looks like. A high value is not \
         reassurance.\n\
         # TYPE ct_edge_channel_join_penalty_tracked_ips gauge\n\
         ct_edge_channel_join_penalty_tracked_ips {tracked}\n\
         # HELP ct_edge_channel_join_penalty_tracked_ips_max Capacity of that table, so a \
         scraper can alert on the ratio instead of a hard-coded bound.\n\
         # TYPE ct_edge_channel_join_penalty_tracked_ips_max gauge\n\
         ct_edge_channel_join_penalty_tracked_ips_max {tracked_max}\n",
        sheds = penalty.shed_total(),
        tracked = penalty.tracked_ips(),
        tracked_max = penalty.max_tracked_ips(),
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

/// One broker accept loop as health sees it: whether the edge meant to run it
/// ([`BrokerHeartbeat::expected_since`]) and when it last iterated
/// ([`BrokerHeartbeat::last_seen`]). Both are needed -- see [`broker_loops_health`].
pub struct BrokerLoopStatus {
    pub name: &'static str,
    pub last_seen: u64,
    pub expected_since: u64,
}

impl BrokerLoopStatus {
    pub fn of(name: &'static str, hb: &crate::state::BrokerHeartbeat) -> Self {
        Self { name, last_seen: hb.last_seen(), expected_since: hb.expected_since() }
    }
}

/// #498/#539: pure health classifier over the QUIC broker accept loops. Each loop is in
/// exactly one of three states, and the point of this function is that the third is not
/// silently folded into the first:
///
/// - **not expected** (`expected_since == 0`) -- the edge deliberately does not run it. The
///   relay loop legitimately refuses to start on an address collision (the #103 guard); that
///   is a configuration decision, not a fault, so it is healthy.
/// - **expected but never seen** (`expected_since > 0, last_seen == 0`) -- the edge meant to
///   run it and it never iterated. #539: this used to be healthy, because it was
///   indistinguishable from the case above. A failure to bind the relay listener lands here,
///   reaches only an `eprintln!`, and left `/healthz` answering 200 forever while agents that
///   are BOTH behind NAT -- the ones with no other path -- could not pair at all. Now it goes
///   stale `max_age` after the intent was declared, which also covers boot: the first beat
///   falls within one idle tick of spawn, well inside the window.
/// - **beating** (`last_seen > 0`) -- stale once the last beat is older than `max_age`.
///
/// `Err` names every unhealthy loop and says which of the two ways it is unhealthy, since the
/// operator response differs (a wedged loop is a restart; one that never came up is a port or
/// certificate problem at boot). Pure -- the caller supplies `now` -- so tests need no clock.
pub fn broker_loops_health(
    loops: &[BrokerLoopStatus],
    now: u64,
    max_age_secs: u64,
) -> Result<(), String> {
    let mut bad = Vec::new();
    for l in loops {
        if l.last_seen > 0 {
            let age = now.saturating_sub(l.last_seen);
            if age > max_age_secs {
                bad.push(format!("{} (wedged, last beat {age}s ago)", l.name));
            }
        } else if l.expected_since > 0 {
            let age = now.saturating_sub(l.expected_since);
            if age > max_age_secs {
                bad.push(format!("{} (never started, expected {age}s ago)", l.name));
            }
        }
    }
    if bad.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "channel broker loop(s) not serving: {} -- the accept loop is not iterating (idle \
             ticks included), so channel joins on that transport stall (#498/#539)",
            bad.join(", ")
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
    // #553: the TCP accept loops are checked by the SAME classifier as the QUIC brokers.
    // Kept as one list on purpose -- two parallel health paths drift, and the listener that
    // carries every public hostname is precisely the one that must not be the exception.
    let listeners = state.listener_heartbeats();
    let mut loops = vec![
        BrokerLoopStatus::of("relay", &state.relay_broker_heartbeat()),
        BrokerLoopStatus::of("rendezvous", &state.rendezvous_broker_heartbeat()),
    ];
    loops.extend(listeners.iter().map(|(label, hb)| BrokerLoopStatus::of(label, hb)));
    match broker_loops_health(&loops, now, BROKER_HEALTH_MAX_AGE_SECS) {
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

    /// Test helper: a loop that is running and last beat at `last_seen`.
    fn beating(name: &'static str, last_seen: u64) -> BrokerLoopStatus {
        BrokerLoopStatus { name, last_seen, expected_since: last_seen.saturating_sub(1) }
    }
    /// Test helper: a loop the edge deliberately does not run (#103 guard).
    fn not_expected(name: &'static str) -> BrokerLoopStatus {
        BrokerLoopStatus { name, last_seen: 0, expected_since: 0 }
    }
    /// Test helper: a loop the edge meant to run that has never iterated (#539).
    fn expected_but_silent(name: &'static str, since: u64) -> BrokerLoopStatus {
        BrokerLoopStatus { name, last_seen: 0, expected_since: since }
    }

    #[test]
    fn broker_loops_health_classifies_fresh_stale_and_never_started_498() {
        // Fresh beats within the window -> healthy.
        assert!(broker_loops_health(&[beating("relay", 1_000), beating("rendezvous", 1_005)], 1_030, 60).is_ok());
        // Exactly at the boundary is still healthy; one past it is not.
        assert!(broker_loops_health(&[beating("relay", 940), beating("rendezvous", 1_000)], 1_000, 60).is_ok());
        let why = broker_loops_health(&[beating("relay", 939), beating("rendezvous", 1_000)], 1_000, 60)
            .expect_err("61s old = wedged");
        assert!(why.contains("relay") && why.contains("61s"), "names the stale loop and age: {why}");
        assert!(!why.contains("rendezvous ("), "the fresh loop is not named: {why}");
        // Both stale -> both named.
        let why = broker_loops_health(&[beating("relay", 100), beating("rendezvous", 200)], 1_000, 60)
            .expect_err("both wedged");
        assert!(why.contains("relay") && why.contains("rendezvous"), "{why}");
        // A loop the edge never meant to run stays healthy -- the #103 address-collision
        // guard is a configuration decision, not a fault.
        assert!(broker_loops_health(&[not_expected("relay"), beating("rendezvous", 1_000)], 1_030, 60).is_ok());
        assert!(broker_loops_health(&[not_expected("relay"), not_expected("rendezvous")], 1_030, 60).is_ok());
    }

    #[test]
    fn broker_loop_expected_but_never_started_is_unhealthy_539() {
        // THE #539 CASE, and the one the old classifier could not see: the edge decided to
        // run the relay, the listener failed to bind (only an `eprintln!` says so), and the
        // loop never beat. Previously indistinguishable from "deliberately not run", so
        // /healthz answered 200 forever while both-NAT'd peers could not pair at all.
        let why = broker_loops_health(
            &[expected_but_silent("relay", 1_000), beating("rendezvous", 1_100)],
            1_100,
            60,
        )
        .expect_err("expected for 100s without a single beat is not healthy");
        assert!(why.contains("relay") && why.contains("never started"), "{why}");
        assert!(
            !why.contains("wedged"),
            "a loop that never came up is not a wedged loop -- the operator response differs \
             (port/certificate at boot vs. restart): {why}"
        );

        // Boot is not a false alarm: within the window, an expected-but-not-yet-beating loop
        // is healthy. This is what makes the check safe to arm without racing `start_period`.
        assert!(
            broker_loops_health(&[expected_but_silent("relay", 1_000)], 1_030, 60).is_ok(),
            "30s after the intent, the first beat may still be pending"
        );
        assert!(
            broker_loops_health(&[expected_but_silent("relay", 1_000)], 1_060, 60).is_ok(),
            "the boundary itself is still healthy, matching the beating case"
        );

        // The intent clock must not be restartable, or a loop that keeps re-declaring itself
        // would never age out.
        let hb = crate::state::BrokerHeartbeat::new();
        assert_eq!(hb.expected_since(), 0, "a fresh heartbeat expects nothing");
        hb.expect_start(1_000);
        hb.expect_start(9_000);
        assert_eq!(hb.expected_since(), 1_000, "first declaration wins");
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

    #[tokio::test]
    async fn healthz_reports_503_when_an_expected_loop_never_started_539() {
        // End to end through the real router, because the point of #539 is what the CONTAINER
        // healthcheck sees. A guard that has never been made to fire is a claim, not a guard.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let state = Arc::new(EdgeState::<Connection>::new());
        state.rendezvous_broker_heartbeat().beat(now);

        // Relay untouched: never expected, never beat -- a deliberate no-relay edge is healthy.
        let resp = metrics_router(state.clone(), None)
            .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "a deliberately unstarted relay is not a fault");

        // Now the edge declares it MEANT to run the relay, long enough ago that a first beat
        // was due -- the bind-failure signature. Same state, opposite verdict.
        state
            .relay_broker_heartbeat()
            .expect_start(now - BROKER_HEALTH_MAX_AGE_SECS - 120);
        let resp = metrics_router(state.clone(), None)
            .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("relay") && text.contains("never started"), "{text}");

        // And the metrics side carries the same distinction, so monitoring is not left with
        // the ambiguous 0 that made this invisible in the first place.
        let metrics = render_edge_metrics(&*state, None);
        let declared = now - BROKER_HEALTH_MAX_AGE_SECS - 120;
        assert!(
            metrics.contains(&format!(
                "ct_edge_channel_broker_loop_expected_since_seconds{{loop=\"relay\"}} {declared}"
            )),
            "the relay's declared intent must be exposed, not just consulted: {metrics}"
        );
        assert!(
            metrics.contains("ct_edge_channel_broker_loop_last_seen_seconds{loop=\"relay\"} 0"),
            "and it is the PAIR that identifies a failed start -- intent set, no beat: {metrics}"
        );
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

    /// #553: a dead TCP accept loop must flip `/healthz`, not just the QUIC brokers.
    ///
    /// The gap this closes: both broker heartbeats fresh, `:443` gone. Every public
    /// hostname is dark, and before this the endpoint answered 200 — so the container
    /// healthcheck stayed green and `restart: unless-stopped` never fired.
    #[tokio::test]
    async fn healthz_reports_503_when_a_registered_tcp_listener_goes_stale_553() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let state = Arc::new(EdgeState::<Connection>::new());
        state.relay_broker_heartbeat().beat(now);
        state.rendezvous_broker_heartbeat().beat(now);

        // The front door is registered and beating: healthy.
        let fd = state.expect_listener(":443 front door", now);
        fd.beat(now);
        let resp = metrics_router(state.clone(), None)
            .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "brokers and listener all fresh");

        // Its task dies. The BROKERS ARE STILL FINE -- that is the whole point, and the
        // reason checking only them was not enough.
        fd.beat(now - BROKER_HEALTH_MAX_AGE_SECS - 120);
        let resp = metrics_router(state.clone(), None)
            .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a dead :443 accept loop must not be reported as healthy just because the \
             QUIC brokers are alive"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains(":443 front door"),
            "the response must NAME the dead loop -- an operator cannot act on a bare 503: {body}"
        );
    }

    /// #553: a listener declared expected that never starts must also fail, not pass as
    /// "this edge simply does not run one" (#539's distinction, applied to listeners).
    #[tokio::test]
    async fn healthz_reports_503_for_a_registered_listener_that_never_started_553() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let state = Arc::new(EdgeState::<Connection>::new());
        state.relay_broker_heartbeat().beat(now);
        state.rendezvous_broker_heartbeat().beat(now);

        // Configured long enough ago to be past the grace window, and it never beat once —
        // a bind failure looks exactly like this.
        let _ = state.expect_listener("TCP fallback", now - BROKER_HEALTH_MAX_AGE_SECS - 120);
        let resp = metrics_router(state.clone(), None)
            .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        // ...and an edge that never registered one at all stays healthy: not running a
        // listener is a configuration choice, not a fault.
        let bare = Arc::new(EdgeState::<Connection>::new());
        bare.relay_broker_heartbeat().beat(now);
        bare.rendezvous_broker_heartbeat().beat(now);
        let resp = metrics_router(bare, None)
            .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "an unregistered listener must not be confused with a broken one"
        );
    }

    /// #551: the join-penalty numbers must track the penalty's REAL state, not just render.
    #[test]
    fn join_penalty_metrics_reflect_real_sheds_and_tracked_ips_551() {
        let state: EdgeState<u32> = EdgeState::new();
        let penalty = state.join_refusal_penalty();

        // Nothing has happened yet: both numbers present and zero. The zero matters -- an
        // absent metric and a quiet penalty must not look the same to a scraper.
        let body = render_edge_metrics(&state, None);
        assert!(body.contains("ct_edge_channel_join_penalty_sheds_total 0"), "{body}");
        assert!(body.contains("ct_edge_channel_join_penalty_tracked_ips 0"), "{body}");
        assert!(
            body.contains(&format!(
                "ct_edge_channel_join_penalty_tracked_ips_max {}",
                penalty.max_tracked_ips()
            )),
            "the bound must be exported so the gauge can be read as a ratio: {body}"
        );

        penalty.note_shed();
        penalty.note_shed();
        penalty.note_shed();
        for ip in ["203.0.113.1", "203.0.113.2"] {
            let _ = penalty.note_definitive_refusal(ip.parse().unwrap(), 60);
        }

        let body = render_edge_metrics(&state, None);
        assert!(body.contains("ct_edge_channel_join_penalty_sheds_total 3"), "{body}");
        assert!(
            body.contains("ct_edge_channel_join_penalty_tracked_ips 2"),
            "two distinct sources refused, so two are tracked: {body}"
        );
    }
}
