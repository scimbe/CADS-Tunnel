//! #781: the fleet view -- `GET /portal/fleet`, one table over every tunnel the caller
//! owns: online state, transport + 7-day uptime, bridge mode + sidecar presence, the
//! agent version and readiness flags from the last successful bridge probe, and a
//! version-drift hint across the fleet.
//!
//! Nothing here dials an agent on page load. Online/transport/uptime/presence come from
//! the edge's existing fail-open routes -- the same three bounded lookups the tunnels
//! page (#776) and the Agent-bridges page (#763) already make, all in one `join_all`
//! -- and the version/readiness columns come from the `bridge_probe_cache` table, which
//! `dial_bridge_tool` fills on every successful `bridge/status` / `bridge/config` call.
//! The edge does NOT learn the agent's version from the registration frame (the frame
//! carries no version field -- a planned protocol addition), so an agent that was never
//! probed reads "unknown", not "offline".
//!
//! Every rendered value that originates outside this process (tunnel names, hostnames,
//! edge-supplied transport strings, cached agent output) goes through [`escape`].

use super::*;
use crate::storage::BridgeProbe;

/// The fleet routes, merged onto the base portal-API router by `portal_api_router_with_verifier`.
pub(super) fn routes() -> Router<ApiState> {
    Router::new().route("/portal/fleet", get(fleet_page))
}

pub(super) use ct_common::time::now_secs_i64 as unix_now;

/// Sessions asked from the edge per tunnel: the newest one alone supplies the transport
/// column, and the uptime windows ride along regardless of the limit.
const FLEET_HISTORY_SESSIONS: usize = 1;

/// One row of the fleet table, with everything already fetched.
struct FleetRow {
    tunnel: SubjectTunnel,
    status: Option<EdgeTunnelStatus>,
    history: Option<EdgeTunnelHistory>,
    bridge_mode: String,
    has_grant: bool,
    presence: Option<BridgePresence>,
    probe: Option<BridgeProbe>,
}

/// `GET /portal/fleet` (session required): every tunnel the caller OWNS (shared-with
/// tunnels are not the caller's fleet), with three concurrent, fail-open edge lookups
/// per tunnel at most -- status, history (uptime + newest session's transport), and,
/// only for a bridge with a stored grant, the channel's sidecar presence.
async fn fleet_page(State(st): State<ApiState>, headers: HeaderMap) -> Response {
    let Some(claims) = session_claims_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    let subject = claims.subject;
    let tunnels = match st.tunnels.list_for_subject(&subject) {
        Ok(t) => t,
        Err(e) => return internal_error("fleet_page/list", e).into_response(),
    };
    let ids: Vec<&str> = tunnels.iter().map(|t| t.id.as_str()).collect();
    let modes = st.tunnels.rest_bridge_mode_batch(&subject, &ids).unwrap_or_default();
    // Per-row like `rest_bridges_page`'s grant lookup: the row count is bounded by the
    // account's tunnel quota, never large enough for N+1 to matter here.
    let grants: Vec<Option<String>> =
        tunnels.iter().map(|t| st.tunnels.bridge_grant(&subject, &t.id).unwrap_or(None)).collect();
    let probes: Vec<Option<BridgeProbe>> =
        tunnels.iter().map(|t| st.tunnels.bridge_probe(&subject, &t.id).unwrap_or(None)).collect();
    let st_ref = &st;
    let lookups = futures::future::join_all(tunnels.iter().zip(&grants).map(|(t, grant)| async move {
        futures::future::join3(
            edge_tunnel_status(st_ref, &t.routing_token),
            edge_tunnel_history(st_ref, &t.routing_token, FLEET_HISTORY_SESSIONS),
            async move {
                match grant {
                    Some(g) => edge_bridge_presence(st_ref, g).await,
                    None => None,
                }
            },
        )
        .await
    }))
    .await;
    let rows: Vec<FleetRow> = tunnels
        .into_iter()
        .zip(grants)
        .zip(probes)
        .zip(lookups)
        .map(|(((tunnel, grant), probe), (status, history, presence))| FleetRow {
            bridge_mode: modes.get(&tunnel.id).cloned().unwrap_or_else(|| "off".to_string()),
            has_grant: grant.is_some(),
            tunnel,
            status,
            history,
            presence,
            probe,
        })
        .collect();
    Html(fleet_html(&rows, unix_now(), claims.email.as_deref())).into_response()
}

/// A readiness-gap chip: the customer `page()` stylesheet has no chip rule, so the
/// style is inline, borrowing the danger button's palette.
const FLEET_CHIP_STYLE: &str = "display:inline-block;padding:.05rem .45rem;margin:.1rem .25rem .1rem 0;\
border:1px solid #6e2530;border-radius:99px;background:#3d1418;color:#ff9a9a;font-size:.75rem;white-space:nowrap";

/// The whole fleet page.
fn fleet_html(rows: &[FleetRow], now: i64, email: Option<&str>) -> String {
    let online = rows.iter().filter(|r| r.status.is_some_and(|s| s.connected)).count();
    let served = rows.iter().filter(|r| r.presence.is_some_and(|p| p.serving)).count();
    let with_gaps = rows
        .iter()
        .filter(|r| {
            let readiness = r.probe.as_ref().and_then(|p| p.readiness.as_ref());
            readiness.is_some_and(|rd| !readiness_gaps(rd).is_empty())
        })
        .count();
    let mut versions: Vec<&str> = rows.iter().filter_map(|r| r.probe.as_ref()?.agent_version.as_deref()).collect();
    versions.sort_unstable();
    versions.dedup();
    let drift = if versions.len() > 1 {
        format!(
            r#"<p class="warn">Version drift: {} -- more than one agent version is in use across the fleet.
Probe each agent after updating it so this line reflects the current state.</p>"#,
            versions.iter().map(|v| format!("<code>{}</code>", escape(v))).collect::<Vec<_>>().join(", ")
        )
    } else {
        String::new()
    };
    let summary = format!(
        "<p><strong>{}</strong> tunnels · <strong>{online}</strong> online · \
         <strong>{served}</strong> bridges served · <strong>{with_gaps}</strong> with readiness gaps</p>",
        rows.len()
    );
    let table = if rows.is_empty() {
        r#"<p class="help">No tunnels yet -- create one from <a href="/portal/tunnels">Tunnels</a>.</p>"#.to_string()
    } else {
        let cells: Vec<Vec<String>> = rows.iter().map(|r| fleet_row_cells(r, now)).collect();
        bridge_table_html(
            &["Name", "Online", "Transport / uptime 7 d", "Bridge", "Agent version", "Readiness", "Actions"],
            &cells,
        )
    };
    let body = format!(
        r#"<h1>Fleet</h1>
<p class="help">One line per tunnel you own. Online, transport and uptime come from the edge. Agent version and
readiness come from the last successful bridge probe (a <code>bridge/status</code> or <code>bridge/config</code>
call from the <a href="/portal/agent-bridges">Agent bridges</a> page, or "Probe now" here): the edge does not learn
the agent's version from its registration (a planned protocol addition), so an agent that was never probed reads
"unknown" rather than "offline". Nothing on this page dials an agent on load.</p>
{summary}
{drift}
{table}"#
    );
    page("Fleet", &body, email)
}

/// One row's seven cells, every value escaped.
fn fleet_row_cells(r: &FleetRow, now: i64) -> Vec<String> {
    let id = escape(&r.tunnel.id);
    let name = format!(
        "<strong>{}</strong><br><code>{}</code>",
        escape(&r.tunnel.name),
        r.tunnel.hostname.as_deref().map(escape).unwrap_or_else(|| "no hostname yet".to_string())
    );
    let online = match r.status {
        Some(EdgeTunnelStatus { connected: true, .. }) => r#"<span class="status-dot live"></span>Online"#,
        Some(EdgeTunnelStatus { connected: false, .. }) => r#"<span class="status-dot off"></span>Offline"#,
        None => r#"<span class="status-dot off"></span>n/a"#,
    }
    .to_string();
    let transport = match &r.history {
        Some(h) => format!(
            r#"{}<br><span class="help">7 d: {}</span>"#,
            h.sessions.first().map(|s| escape(&s.transport)).unwrap_or_else(|| "no sessions".to_string()),
            human_pct(h.uptime.d7)
        ),
        None => "n/a".to_string(),
    };
    let bridge = if r.bridge_mode == "off" {
        "off".to_string()
    } else {
        let sidecar = match (r.has_grant, r.presence) {
            (false, _) => "no grant".to_string(),
            (true, Some(BridgePresence { serving: true, last_seen_secs_ago })) => format!(
                r#"<span class="status-dot live"></span>serving{}"#,
                last_seen_secs_ago.map(|s| format!(" (seen {s} s ago)")).unwrap_or_default()
            ),
            (true, Some(BridgePresence { serving: false, .. })) => {
                r#"<span class="status-dot off"></span>not connected"#.to_string()
            }
            (true, None) => "presence unknown".to_string(),
        };
        format!("{} · {sidecar}", escape(&r.bridge_mode))
    };
    let version = r
        .probe
        .as_ref()
        .and_then(|p| p.agent_version.as_deref())
        .map(|v| format!("<code>{}</code>", escape(v)))
        .unwrap_or_else(|| "unknown".to_string());
    let readiness = match &r.probe {
        None => "not probed".to_string(),
        Some(probe) => {
            let flags = match &probe.readiness {
                None => "not probed".to_string(),
                Some(rd) => {
                    let gaps = readiness_gaps(rd);
                    if gaps.is_empty() {
                        "all ok".to_string()
                    } else {
                        gaps.iter()
                            .map(|g| format!(r#"<span style="{FLEET_CHIP_STYLE}">{}</span>"#, escape(g)))
                            .collect::<String>()
                    }
                }
            };
            format!(r#"{flags}<br><span class="help">probed {}</span>"#, probe_age(now, probe.probed_at))
        }
    };
    let probe_form = if r.has_grant {
        format!(
            r#" <form class="inline" method="post" action="/portal/tunnels/{id}/agent-bridge/call">
 <input type="hidden" name="tool" value="bridge/config">
 <input type="hidden" name="arguments" value="{{}}">
 <button type="submit" class="btn sec">Probe now</button>
</form>"#
        )
    } else {
        String::new()
    };
    let card = r#"<a class="btn sec" href="/portal/tunnels">Card</a>"#;
    let uptime = format!(r#"<a class="btn sec" href="/portal/tunnels/{id}/uptime">Uptime</a>"#);
    let actions = format!("{card} {uptime}{probe_form}");
    vec![name, online, transport, bridge, version, readiness, actions]
}

/// The readiness flags reported as NOT ready, as short chip labels, in the cache's own
/// (sorted) key order. Empty means "nothing reported as missing".
fn readiness_gaps(readiness: &serde_json::Value) -> Vec<String> {
    readiness
        .as_object()
        .map(|obj| obj.iter().filter_map(|(k, v)| readiness_gap_label(k, v)).collect::<Vec<String>>())
        .unwrap_or_default()
}

/// The chip label for one cached readiness flag when it signals a gap, `None` when it
/// doesn't. `*_configured`/`*_available`/`oidc_credential` are gaps when `false`/`"none"`;
/// `*_disabled` is a gap when `true`; `role` is informational only. Known keys get the
/// wording `bridge_config_hint_html` explains in full; unknown keys of the same shape get
/// a generic label derived from the key (escaped by the caller -- the key is agent-supplied).
fn readiness_gap_label(key: &str, value: &serde_json::Value) -> Option<String> {
    if key == "role" {
        return None;
    }
    let off = matches!(value, serde_json::Value::Bool(false)) || value.as_str() == Some("none");
    let on = matches!(value, serde_json::Value::Bool(true));
    let is_gap = if key.ends_with("_disabled") { on } else { off };
    if !is_gap {
        return None;
    }
    let named = match key {
        "manifest_registry_configured" => "no registry",
        "cp_url_configured" => "no cp url",
        "channel_id_configured" => "no channel id",
        "oidc_credential" => "no login",
        "manifest_trust_allowlist_configured" => "no trust list",
        "manifest_work_dir_configured" => "no work dir",
        "docker_available" => "no docker",
        "manifest_install_disabled" => "installs disabled",
        _ => "",
    };
    if !named.is_empty() {
        return Some(named.to_string());
    }
    if let Some(stem) = key.strip_suffix("_configured").or_else(|| key.strip_suffix("_available")) {
        return Some(format!("no {}", stem.replace('_', " ")));
    }
    key.strip_suffix("_disabled").map(|stem| format!("{} disabled", stem.replace('_', " ")))
}

/// A probe's age in the coarse unit a fleet reader wants: `just now`, `12 m ago`,
/// `3 h ago`, `2 d ago`. A cache row from the future (clock skew) reads `just now`.
fn probe_age(now: i64, probed_at: i64) -> String {
    let secs = (now - probed_at).max(0);
    if secs < 60 {
        "just now".to_string()
    } else if secs < 3_600 {
        format!("{} m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{} h ago", secs / 3_600)
    } else {
        format!("{} d ago", secs / 86_400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portal::sign_session_for_test;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use std::collections::HashSet;
    use tower::ServiceExt;

    const KEY: &[u8] = b"fleet-test-key";

    /// The parent module's test fixtures (`test_app_with_bridge_and_edge`, `get`,
    /// `bridge_grant_hex`) are private to its own `tests` module, so this child module
    /// carries its own, deliberately identical copies rather than widening theirs.
    fn app_with_edge(edge_url: Option<String>) -> (Router, Arc<SqliteTunnelStore>, ed25519_dalek::SigningKey) {
        let holder = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let app = portal_api_router_with_verifier(
            KEY,
            Arc::new(SqliteLedger::open_in_memory().unwrap()),
            tunnels.clone(),
            Arc::new(SqliteEnrollment::open_in_memory().unwrap()),
            Arc::new(SqliteBootstrap::open_in_memory().unwrap()),
            "https://portal.example",
            edge_url.map(|u| (u, "edge-secret".to_string())),
            None,
            None,
            None,
            EdgeMeshHandle::new(
                Arc::new(crate::edge_mesh::SqliteEdgeMesh::open_in_memory().unwrap()),
                Arc::from("test-edge"),
            ),
            None,
            None,
            None,
            Some((holder.clone(), [0x22u8; 32], "127.0.0.1:1".parse().unwrap(), "127.0.0.1:2".parse().unwrap())),
            Arc::new(crate::storage::SqliteChannelStore::open_in_memory().unwrap()),
        );
        (app, tunnels, holder)
    }

    /// A well-formed grant hex for `channel` bound to `holder_pub` (junk signature --
    /// the presence lookup only decodes it for the channel id, it never verifies it).
    fn grant_hex(channel: [u8; 32], holder_pub: [u8; 32]) -> String {
        let grant = ct_common::channel::SignedChannelGrant {
            grant: ct_common::channel::ChannelGrant {
                channel: ct_common::channel::ChannelId(channel),
                holder: holder_pub,
                direction: ct_common::channel::Direction::Initiate,
                rights: ct_common::channel::Rights::ReadWrite,
                delegable: false,
                expires_at: u64::MAX,
            },
            signature: [0u8; 64],
        };
        hex_encode(&grant.encode())
    }

    async fn get(app: &Router, path: &str, subject: Option<&str>) -> (StatusCode, String) {
        let mut req = Request::get(path);
        if let Some(s) = subject {
            req = req.header("cookie", format!("ct_portal_session={}", sign_session_for_test(KEY, s)));
        }
        let resp = app.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
        let status = resp.status();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    type OfflineTokens = Arc<std::sync::Mutex<HashSet<String>>>;

    /// A mock edge for the fleet page: `/admin/tunnel-status/:token` is connected unless
    /// the token is in `offline`; `/internal/tunnel/history/:token` answers a quic session
    /// with 98.4 % 7-day uptime for online tokens and 404s for offline ones; the presence
    /// route reports a serving sidecar (a holder other than this deployment's own).
    async fn mock_edge(offline: OfflineTokens) -> String {
        let own_holder_hex =
            hex_encode(&ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]).verifying_key().to_bytes());
        let status_offline = offline.clone();
        let history_offline = offline;
        let mock = Router::new()
            .route(
                "/admin/tunnel-status/:token",
                axum::routing::get(move |axum::extract::Path(token): axum::extract::Path<String>| {
                    let offline = status_offline.clone();
                    async move {
                        let connected = !offline.lock().unwrap().contains(&token);
                        Json(serde_json::json!({ "connected": connected, "bytes_received": 0, "bytes_sent": 0 }))
                    }
                }),
            )
            .route(
                "/internal/tunnel/history/:token",
                axum::routing::get(move |axum::extract::Path(token): axum::extract::Path<String>| {
                    let offline = history_offline.clone();
                    async move {
                        if offline.lock().unwrap().contains(&token) {
                            return StatusCode::NOT_FOUND.into_response();
                        }
                        Json(serde_json::json!({
                            "open": true,
                            "uptime": { "h24": 100.0, "d7": 98.4, "d30": 97.1 },
                            "sessions": [
                                { "transport": "quic", "connected_at": 1_757_100_000, "disconnected_at": null,
                                  "reason": null, "bytes_in": 1, "bytes_out": 2 }
                            ]
                        }))
                        .into_response()
                    }
                }),
            )
            .route(
                "/internal/channel/presence/:channel_hex",
                axum::routing::get(move |axum::extract::Path(_channel_hex): axum::extract::Path<String>| {
                    let own = own_holder_hex.clone();
                    async move {
                        Json(serde_json::json!({ "holders": [
                            { "holder": own, "parked_now": true, "last_seen_secs_ago": 3 },
                            { "holder": "ab".repeat(32), "parked_now": true, "last_seen_secs_ago": 12 }
                        ] }))
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn fleet_page_redirects_to_the_portal_shell_without_a_session_781() {
        let (app, _tunnels, _holder) = app_with_edge(None);
        let (status, _) = get(&app, "/portal/fleet", None).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn fleet_page_shows_online_uptime_and_a_served_bridge_and_na_for_an_offline_tunnel_781() {
        let offline: OfflineTokens = Arc::new(std::sync::Mutex::new(HashSet::new()));
        let edge_url = mock_edge(offline.clone()).await;
        let (app, tunnels, holder) = app_with_edge(Some(edge_url));
        let web = tunnels.create("alice", "web", Some("web-1234.example")).unwrap().created().expect("hostname free");
        tunnels.set_rest_bridge_mode("alice", &web.id, "permanent").unwrap();
        let grant = grant_hex([0x63u8; 32], holder.verifying_key().to_bytes());
        assert!(tunnels.set_bridge_grant("alice", &web.id, &grant).unwrap());
        let lab = tunnels.create("alice", "lab", None).unwrap().created().expect("hostname free");
        offline.lock().unwrap().insert(lab.routing_token.clone());

        let (status, html) = get(&app, "/portal/fleet", Some("alice")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            html.contains("<strong>2</strong> tunnels · <strong>1</strong> online · <strong>1</strong> bridges served"),
            "{html}"
        );
        // The online bridge row: status, transport + 7-day uptime, mode + sidecar, a Probe form.
        assert!(html.contains(r#"<span class="status-dot live"></span>Online"#), "{html}");
        assert!(html.contains(r#"quic<br><span class="help">7 d: 98.4 %</span>"#), "{html}");
        assert!(html.contains(r#"permanent · <span class="status-dot live"></span>serving (seen 12 s ago)"#), "{html}");
        assert!(html.contains(&format!(r#"action="/portal/tunnels/{}/agent-bridge/call""#, web.id)), "{html}");
        assert!(html.contains(r#"<input type="hidden" name="tool" value="bridge/config">"#), "{html}");
        assert_eq!(html.matches(">Probe now</button>").count(), 1, "only the bridge with a grant gets a Probe form");
        assert!(html.contains(&format!(r#"href="/portal/tunnels/{}/uptime""#, web.id)), "{html}");
        assert!(html.contains(&format!(r#"href="/portal/tunnels/{}/uptime""#, lab.id)), "{html}");
        // The offline row: no history from the edge reads n/a, its bridge is off.
        assert!(html.contains(r#"<span class="status-dot off"></span>Offline"#), "{html}");
        assert!(html.contains("<td style=\"") && html.contains(">n/a</td>"), "{html}");
        assert!(html.contains("<code>web-1234.example</code>") && html.contains("no hostname yet"), "{html}");
        // Never probed: version unknown, readiness not probed.
        assert!(html.contains(">unknown</td>"), "{html}");
        assert!(html.contains(">not probed</td>"), "{html}");
        assert!(!html.contains("Version drift"), "one (unknown) version is no drift");
        for t in [&web, &lab] {
            assert!(!html.contains(&t.routing_token), "the raw routing token is never rendered");
        }
        assert!(html.contains(r#"<a href="/portal/fleet">Fleet</a>"#), "the nav carries the new link");
    }

    #[tokio::test]
    async fn fleet_page_renders_readiness_chips_from_the_cache_and_not_probed_without_it_781() {
        let (app, tunnels, _holder) = app_with_edge(None);
        let now = unix_now();
        let probed = tunnels.create("alice", "probed", None).unwrap().created().expect("hostname free");
        let config = serde_json::json!({
            "role": "serve",
            "cp_url_configured": true,
            "oidc_credential": "none",
            "manifest_registry_configured": false,
            "docker_available": false,
            "manifest_install_disabled": false
        });
        assert!(tunnels.record_bridge_probe("alice", &probed.id, "bridge/config", &config, now - 3 * 3_600).unwrap());
        let fine = tunnels.create("alice", "fine", None).unwrap().created().expect("hostname free");
        let all_on =
            serde_json::json!({ "cp_url_configured": true, "oidc_credential": "present", "docker_available": true });
        assert!(tunnels.record_bridge_probe("alice", &fine.id, "bridge/config", &all_on, now).unwrap());
        let _fresh = tunnels.create("alice", "fresh", None).unwrap().created().expect("hostname free");

        let (status, html) = get(&app, "/portal/fleet", Some("alice")).await;
        assert_eq!(status, StatusCode::OK);
        for chip in ["no registry", "no login", "no docker"] {
            assert!(html.contains(&format!(r#"">{chip}</span>"#)), "chip {chip}: {html}");
        }
        assert!(!html.contains("no cp url"), "a true flag is not a gap");
        assert!(!html.contains("installs disabled"), "a false *_disabled flag is not a gap");
        assert!(html.contains(r#"<span class="help">probed 3 h ago</span>"#), "{html}");
        assert!(html.contains(r#"all ok<br><span class="help">probed just now</span>"#), "{html}");
        assert!(html.contains(">not probed</td>"), "the unprobed tunnel: {html}");
        assert!(html.contains("<strong>1</strong> with readiness gaps"), "{html}");
        // No edge configured: the edge-sourced columns fail open.
        assert!(html.contains(r#"<span class="status-dot off"></span>n/a"#), "{html}");
        assert_eq!(html.matches(">Probe now</button>").count(), 0, "no grant anywhere, no Probe form");
    }

    #[tokio::test]
    async fn fleet_page_hints_version_drift_only_across_distinct_cached_versions_781() {
        let (app, tunnels, _holder) = app_with_edge(None);
        let a = tunnels.create("alice", "a", None).unwrap().created().expect("hostname free");
        let b = tunnels.create("alice", "b", None).unwrap().created().expect("hostname free");
        let c = tunnels.create("alice", "c", None).unwrap().created().expect("hostname free");
        let v26 = serde_json::json!({ "version": "0.7.26" });
        assert!(tunnels.record_bridge_probe("alice", &a.id, "bridge/status", &v26, 1_000).unwrap());
        assert!(tunnels.record_bridge_probe("alice", &b.id, "bridge/status", &v26, 1_000).unwrap());
        let v25 = serde_json::json!({ "version": "0.7.25 <b>x</b>" });
        assert!(tunnels.record_bridge_probe("alice", &c.id, "bridge/status", &v25, 1_000).unwrap());

        let (status, html) = get(&app, "/portal/fleet", Some("alice")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            html.contains("Version drift: <code>0.7.25 &lt;b&gt;x&lt;/b&gt;</code>, <code>0.7.26</code>"),
            "distinct versions, sorted: {html}"
        );
        assert!(!html.contains("<b>x</b>"), "a cached agent string is escaped wherever it lands: {html}");
        assert_eq!(html.matches("<code>0.7.26</code>").count(), 3, "two rows plus the drift line: {html}");

        // Same version everywhere: no drift line.
        assert!(tunnels.record_bridge_probe("alice", &c.id, "bridge/status", &v26, 2_000).unwrap());
        let (_, html) = get(&app, "/portal/fleet", Some("alice")).await;
        assert!(!html.contains("Version drift"), "{html}");
    }

    #[tokio::test]
    async fn fleet_page_lists_only_the_callers_own_tunnels_781() {
        let (app, tunnels, _holder) = app_with_edge(None);
        tunnels.create("alice", "mine", None).unwrap().created().expect("hostname free");
        let bobs = tunnels.create("bob", "theirs", None).unwrap().created().expect("hostname free");
        tunnels.grant("bob", &bobs.id, "alice").unwrap();

        let (status, html) = get(&app, "/portal/fleet", Some("alice")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("<strong>mine</strong>"), "{html}");
        assert!(!html.contains("<strong>theirs</strong>"), "a merely shared tunnel is not alice's fleet: {html}");
        assert!(html.contains("<strong>1</strong> tunnels"), "{html}");
    }

    #[test]
    fn readiness_gap_labels_follow_the_flag_shape_781() {
        use serde_json::json;
        assert_eq!(readiness_gap_label("manifest_registry_configured", &json!(false)).as_deref(), Some("no registry"));
        assert_eq!(readiness_gap_label("manifest_registry_configured", &json!(true)), None);
        assert_eq!(readiness_gap_label("oidc_credential", &json!("none")).as_deref(), Some("no login"));
        assert_eq!(readiness_gap_label("oidc_credential", &json!("present")), None);
        assert_eq!(
            readiness_gap_label("manifest_install_disabled", &json!(true)).as_deref(),
            Some("installs disabled")
        );
        assert_eq!(readiness_gap_label("manifest_install_disabled", &json!(false)), None);
        assert_eq!(readiness_gap_label("role", &json!("none")), None, "role is informational");
        assert_eq!(readiness_gap_label("gpu_available", &json!(false)).as_deref(), Some("no gpu"));
        assert_eq!(
            readiness_gap_label("remote_shell_disabled", &json!(true)).as_deref(),
            Some("remote shell disabled")
        );
        assert_eq!(readiness_gap_label("some_path", &json!(false)), None, "keys outside the allowed shapes never chip");
        assert_eq!(
            readiness_gaps(&json!({ "b_configured": false, "a_available": false, "c_configured": true })),
            vec!["no a".to_string(), "no b".to_string()],
            "sorted key order, gaps only"
        );
    }

    #[test]
    fn probe_age_uses_the_coarse_units_a_fleet_reader_wants_781() {
        assert_eq!(probe_age(1_000, 1_000), "just now");
        assert_eq!(probe_age(1_000, 1_030), "just now", "a future timestamp never goes negative");
        assert_eq!(probe_age(1_000, 1_000 - 12 * 60), "12 m ago");
        assert_eq!(probe_age(1_000_000, 1_000_000 - 3 * 3_600 - 59), "3 h ago");
        assert_eq!(probe_age(1_000_000, 1_000_000 - 2 * 86_400 - 5 * 3_600), "2 d ago");
    }
}
