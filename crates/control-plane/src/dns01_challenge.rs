//! ACME DNS-01 challenge-publish endpoint (ADR-0003 follow-up): the operator's
//! actual "assist" in agent-held-certificate issuance. An agent proves it owns
//! a hostname by presenting the routing token this deployment already recorded
//! as bound to it ([`crate::edge_mesh::SqliteEdgeMesh::token_owns_hostname`]) —
//! reusing the ownership registry rather than a separate credential — and the
//! control plane publishes/clears the `_acme-challenge` TXT record on its
//! behalf via the operator's own DNS provider. The zone-wide DNS credential
//! (`DESEC_TOKEN`) never leaves the control plane; the agent never sees it,
//! and this endpoint can only ever touch `_acme-challenge.<hostname-it-owns>`,
//! never any other record.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use ct_dns::provider::Dns01Provider;
use serde::Deserialize;

use crate::edge_mesh::SqliteEdgeMesh;
use crate::storage::SqliteTunnelStore;

#[derive(Clone)]
struct Dns01State {
    edge_mesh: Arc<SqliteEdgeMesh>,
    provider: Arc<Dns01Provider>,
    /// The admission broker's ledger (#233 follow-up): [`publish`] refuses to
    /// place a challenge record for a hostname the broker hasn't currently
    /// admitted, even for its legitimate owner. Without this, a customer
    /// could bypass `ct-agent`'s admission poll entirely — run their own
    /// ACME client, hit this endpoint directly with their own (genuinely
    /// valid) routing token, and obtain a real certificate outside the
    /// queue, whenever they like, consuming the operator's shared per-CA
    /// rate-limit budget unpaced.
    tunnels: Arc<SqliteTunnelStore>,
    /// #301: coalesces concurrent [`publish`] calls for the same record/value into
    /// one shared deSEC convergence poll instead of each independently hammering
    /// all 12 unicast nodes.
    convergence: Arc<ct_dns::convergence::ConvergenceCoalescer>,
}

/// Build the DNS-01 challenge router. `None` when no DNS-01 backend is
/// configured (nothing to proxy to) — mirrors every other optional-config
/// router in this crate (e.g. [`crate::service::edge_authorize_host_router`]).
pub fn dns01_challenge_router(
    edge_mesh: Arc<SqliteEdgeMesh>,
    tunnels: Arc<SqliteTunnelStore>,
    provider: Option<Dns01Provider>,
) -> Router {
    match provider {
        Some(provider) => Router::new()
            .route("/agent/dns01-challenge", post(publish))
            .route("/agent/dns01-challenge/clear", post(clear))
            .with_state(Dns01State {
                edge_mesh,
                provider: Arc::new(provider),
                tunnels,
                convergence: Arc::new(ct_dns::convergence::ConvergenceCoalescer::new()),
            }),
        None => Router::new(),
    }
}

#[derive(Deserialize)]
struct ChallengeReq {
    /// The tunnel's routing token, hex — proof of ownership (#153: checked
    /// against the same registry every hostname authorization already feeds).
    token: String,
    hostname: String,
    /// The DNS-01 TXT value to publish. Absent/ignored for the clear route.
    #[serde(default)]
    value: String,
}

/// The record name a DNS-01 TXT challenge is published at (RFC 8555 §8.4).
/// Trivial and duplicated (not shared via a cross-crate import) rather than
/// restructured across the agent/control-plane boundary for one format!— see
/// `ct-agent`'s `acme::dns01_record_name`, which this must always match.
fn dns01_record_name(hostname: &str) -> String {
    format!("_acme-challenge.{}", hostname.trim_end_matches('.'))
}

async fn authorize(state: &Dns01State, token: &str, hostname: &str) -> Result<(), (StatusCode, String)> {
    // #286: `mesh_ownership` is best-effort bookkeeping (`EdgeMeshHandle::forget`
    // swallows a DELETE failure on revoke), so a stale row there must never be
    // sufficient on its own; also require the DURABLE `subject_tunnels` record to
    // currently agree this token owns this hostname. A revoked tunnel's row is gone
    // (transactional delete, #327), so this closes the gap regardless of whether the
    // best-effort mesh_ownership cleanup succeeded -- otherwise a former agent could
    // still obtain a real certificate for a hostname its customer no longer controls.
    let mesh_owns = state
        .edge_mesh
        .token_owns_hostname(token, hostname)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let durable_owns = state
        .tunnels
        .routing_token_for_hostname(hostname)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .as_deref()
        == Some(token);
    if mesh_owns && durable_owns {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "this token is not the recorded owner of this hostname".to_string()))
    }
}

async fn publish(
    State(state): State<Dns01State>,
    Json(req): Json<ChallengeReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    authorize(&state, &req.token, &req.hostname).await?;
    // #233: ownership alone is not enough -- the admission broker must have
    // actually admitted this hostname (an open claim offer, or already
    // permanently `gruen`) before its challenge record gets published at
    // all. This is what makes the queue/pacing actually binding rather than
    // advisory: the only way to get Let's Encrypt (or any CA) to see a valid
    // `_acme-challenge` record for this hostname is through this endpoint,
    // and this endpoint now refuses outside an admitted window.
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    match state.tunnels.cert_admission_for_hostname(&req.hostname) {
        Ok(Some(admission)) if admission.may_issue_now(now) => {}
        Ok(Some(admission)) => {
            return Err((
                StatusCode::TOO_EARLY,
                format!("{} is not currently admitted to issue (status={})", req.hostname, admission.status),
            ))
        }
        Ok(None) => return Err((StatusCode::NOT_FOUND, "no tunnel with this hostname".to_string())),
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
    let record_name = dns01_record_name(&req.hostname);
    state.provider.set_txt(&record_name, &req.value).await.map_err(|e| (StatusCode::BAD_GATEWAY, e))?;

    // deSEC-specific (#229): `set_txt` returning success only means deSEC's
    // API accepted the write, not that its anycast fleet serves it yet --
    // measured up to 152s to fully converge, and the single nearest node
    // behind ns1.desec.io/ns2.desec.org can each individually claim success
    // while a third of the fleet (reachable by Let's Encrypt's own remote
    // validation perspectives) still does not have the record. Wait here,
    // on the control plane, so the agent needs no DNS capability of its own
    // (this is also what makes the check work on a host with outbound
    // UDP/53 blocked entirely, unlike doing this client-side) and so a 200
    // response means what it says: this is actually live.
    if let Dns01Provider::Desec(client) = state.provider.as_ref() {
        use ct_dns::convergence::{Convergence, DEFAULT_TIMEOUT, DESEC_NODES};
        // #301: coalesced by (zone, record, value) -- a burst of concurrent publishes
        // for the exact same record+value share one poll instead of each hammering
        // all 12 deSEC nodes independently.
        let key = format!("{}/{}/{}", client.domain(), record_name, req.value);
        match state
            .convergence
            .wait_for_convergence(&key, DESEC_NODES, client.domain(), &record_name, &req.value, DEFAULT_TIMEOUT)
            .await
        {
            Convergence::Converged { .. } => {}
            // We could not reach any node ourselves -- a fact about the
            // control plane's own network, not about deSEC. The write did
            // succeed per deSEC's own API; don't fail an otherwise-good
            // publish over our own inability to double-check it.
            Convergence::NoNodesReachable => {
                eprintln!("ct-cp: dns01-challenge: could not reach any deSEC node to confirm convergence for {record_name}; proceeding anyway");
            }
            Convergence::TimedOut { lagging } => {
                return Err((
                    StatusCode::GATEWAY_TIMEOUT,
                    format!(
                        "published, but not yet converged across all deSEC nodes after {DEFAULT_TIMEOUT:?} -- still lagging: {}",
                        lagging.join(", ")
                    ),
                ));
            }
            // #265: distinct from TimedOut -- this control plane, not deSEC, is the
            // bottleneck (too many distinct hostnames publishing concurrently). The
            // TXT write above already succeeded; the agent's ACME client should
            // retry the publish shortly rather than treat this as a permanent failure.
            Convergence::Saturated => {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("published, but too many concurrent DNS-01 convergence checks in flight for {record_name} -- retry shortly"),
                ));
            }
        }
    }
    Ok(StatusCode::OK)
}

async fn clear(
    State(state): State<Dns01State>,
    Json(req): Json<ChallengeReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    authorize(&state, &req.token, &req.hostname).await?;
    state
        .provider
        .clear_txt(&dns01_record_name(&req.hostname))
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use crate::storage::SubjectTunnel;
    use ct_dns::store::AcmeDnsStore;
    use tower::ServiceExt;

    fn store() -> Arc<SqliteEdgeMesh> {
        Arc::new(SqliteEdgeMesh::open_in_memory().unwrap())
    }

    fn tunnels() -> Arc<SqliteTunnelStore> {
        Arc::new(SqliteTunnelStore::open_in_memory().unwrap())
    }

    /// Create a tunnel row for `hostname` and admit it straight to `gruen` --
    /// the shortest path to "the admission broker says yes" for tests whose
    /// point is ownership authorization, not admission status itself. Returns
    /// the full tunnel record (#286: `authorize` now also requires the
    /// durable routing token to match, not just mesh_ownership's record; some
    /// tests also need `.id` to revoke it).
    fn admit(tunnels: &SqliteTunnelStore, hostname: &str) -> SubjectTunnel {
        let t = tunnels.create("subject", hostname, Some(hostname)).unwrap();
        tunnels.enter_gelb_queue(hostname, 0).unwrap();
        tunnels.offer_claim(hostname, "letsencrypt", 0, 1).unwrap();
        tunnels.record_issuance_complete(hostname, "example.com", 0).unwrap();
        t
    }

    #[tokio::test]
    async fn publish_and_clear_require_the_owning_token_and_touch_only_that_hostname() {
        let edge_mesh = store();
        let tunnels = tunnels();
        let app_tunnel = admit(&tunnels, "app.example.com");
        let other_tunnel = admit(&tunnels, "other.example.com");
        let app_token = app_tunnel.routing_token.clone();
        let other_token = other_tunnel.routing_token.clone();
        edge_mesh.record_ownership(&app_token, Some("app.example.com"), "edge-1", 0).unwrap();
        edge_mesh.record_ownership(&other_token, Some("other.example.com"), "edge-1", 0).unwrap();
        let dns_store = Arc::new(AcmeDnsStore::new());
        let app = dns01_challenge_router(
            edge_mesh,
            tunnels,
            Some(Dns01Provider::SelfHosted(dns_store.clone())),
        );

        let post = |path: &str, body: serde_json::Value| {
            app.clone().oneshot(
                Request::post(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
        };

        // The owning token publishes successfully.
        let resp = post(
            "/agent/dns01-challenge",
            serde_json::json!({"token": app_token, "hostname": "app.example.com", "value": "tok-123"}),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(dns_store.txt("_acme-challenge.app.example.com"), vec!["tok-123".to_string()]);

        // A DIFFERENT owned hostname's token cannot touch this one.
        let resp = post(
            "/agent/dns01-challenge",
            serde_json::json!({"token": other_token, "hostname": "app.example.com", "value": "evil"}),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            dns_store.txt("_acme-challenge.app.example.com"),
            vec!["tok-123".to_string()],
            "the forbidden request never touched the record"
        );

        // An unknown token is refused too.
        let resp = post(
            "/agent/dns01-challenge",
            serde_json::json!({"token": "unknown", "hostname": "app.example.com", "value": "x"}),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // The owning token clears its own record.
        let resp = post(
            "/agent/dns01-challenge/clear",
            serde_json::json!({"token": app_token, "hostname": "app.example.com"}),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(dns_store.txt("_acme-challenge.app.example.com").is_empty());
    }

    #[tokio::test]
    async fn publish_is_refused_once_mesh_ownership_is_stale_relative_to_the_durable_tunnel_286() {
        // #286: mesh_ownership is best-effort (a revoke's forget() can fail and
        // leave a stale row). Proves the actual bug this closes for the DNS-01
        // publish endpoint specifically: a stale mesh_ownership row alone must
        // never be enough to publish a real ACME challenge record -- the
        // durable subject_tunnels record has to agree too.
        let edge_mesh = store();
        let tunnels = tunnels();
        let t = admit(&tunnels, "app.example.com");
        edge_mesh.record_ownership(&t.routing_token, Some("app.example.com"), "edge-1", 0).unwrap();
        // Revoke at the durable layer without touching mesh_ownership.
        tunnels.revoke("subject", &t.id, 1_000).unwrap();

        let dns_store = Arc::new(AcmeDnsStore::new());
        let app = dns01_challenge_router(edge_mesh, tunnels, Some(Dns01Provider::SelfHosted(dns_store.clone())));
        let resp = app
            .oneshot(
                Request::post("/agent/dns01-challenge")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"token": t.routing_token, "hostname": "app.example.com", "value": "v"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "revoked at the durable layer -> refused despite the stale mesh row");
        assert!(dns_store.txt("_acme-challenge.app.example.com").is_empty(), "no challenge record ever published");
    }

    #[tokio::test]
    async fn router_is_absent_with_no_provider_configured() {
        let app = dns01_challenge_router(store(), tunnels(), None);
        let resp = app
            .oneshot(
                Request::post("/agent/dns01-challenge")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"token": "x", "hostname": "y", "value": "z"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "no route mounted when nothing is configured");
        let _ = to_bytes(resp.into_body(), usize::MAX).await;
    }

    #[tokio::test]
    async fn publish_refuses_a_legitimately_owned_hostname_that_isnt_admitted_yet() {
        // #233: proves the fix for "a customer runs their own ACME client
        // straight against this endpoint, bypassing ct-agent's admission poll
        // entirely" -- ownership alone (a real, correctly-recorded token) must
        // NOT be enough once the broker exists; the hostname must actually be
        // in an admitted window (or already gruen).
        let edge_mesh = store();
        let tunnels = tunnels();
        let t = tunnels.create("subject", "app.example.com", Some("app.example.com")).unwrap();
        edge_mesh.record_ownership(&t.routing_token, Some("app.example.com"), "edge-1", 0).unwrap();
        // Deliberately left `rot` -- never entered the Gelb queue, never offered.
        let dns_store = Arc::new(AcmeDnsStore::new());
        let app =
            dns01_challenge_router(edge_mesh, tunnels, Some(Dns01Provider::SelfHosted(dns_store.clone())));

        let resp = app
            .oneshot(
                Request::post("/agent/dns01-challenge")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"token": t.routing_token, "hostname": "app.example.com", "value": "v"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_EARLY, "owning the hostname is not enough without admission");
        assert!(
            dns_store.txt("_acme-challenge.app.example.com").is_empty(),
            "the challenge record must never be published for a not-yet-admitted hostname"
        );
    }
}
