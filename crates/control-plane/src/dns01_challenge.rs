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

#[derive(Clone)]
struct Dns01State {
    edge_mesh: Arc<SqliteEdgeMesh>,
    provider: Arc<Dns01Provider>,
}

/// Build the DNS-01 challenge router. `None` when no DNS-01 backend is
/// configured (nothing to proxy to) — mirrors every other optional-config
/// router in this crate (e.g. [`crate::service::edge_authorize_host_router`]).
pub fn dns01_challenge_router(edge_mesh: Arc<SqliteEdgeMesh>, provider: Option<Dns01Provider>) -> Router {
    match provider {
        Some(provider) => Router::new()
            .route("/agent/dns01-challenge", post(publish))
            .route("/agent/dns01-challenge/clear", post(clear))
            .with_state(Dns01State { edge_mesh, provider: Arc::new(provider) }),
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
    let owns = state
        .edge_mesh
        .token_owns_hostname(token, hostname)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if owns {
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
        use ct_dns::convergence::{wait_for_convergence, Convergence, DEFAULT_TIMEOUT, DESEC_NODES};
        match wait_for_convergence(DESEC_NODES, client.domain(), &record_name, &req.value, DEFAULT_TIMEOUT).await {
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
    use ct_dns::store::AcmeDnsStore;
    use tower::ServiceExt;

    fn store() -> Arc<SqliteEdgeMesh> {
        Arc::new(SqliteEdgeMesh::open_in_memory().unwrap())
    }

    #[tokio::test]
    async fn publish_and_clear_require_the_owning_token_and_touch_only_that_hostname() {
        let edge_mesh = store();
        edge_mesh.record_ownership("deadbeef", Some("app.example.com"), "edge-1", 0).unwrap();
        edge_mesh.record_ownership("cafef00d", Some("other.example.com"), "edge-1", 0).unwrap();
        let dns_store = Arc::new(AcmeDnsStore::new());
        let app = dns01_challenge_router(
            edge_mesh,
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
            serde_json::json!({"token": "deadbeef", "hostname": "app.example.com", "value": "tok-123"}),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(dns_store.txt("_acme-challenge.app.example.com"), vec!["tok-123".to_string()]);

        // A DIFFERENT owned hostname's token cannot touch this one.
        let resp = post(
            "/agent/dns01-challenge",
            serde_json::json!({"token": "cafef00d", "hostname": "app.example.com", "value": "evil"}),
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
            serde_json::json!({"token": "deadbeef", "hostname": "app.example.com"}),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(dns_store.txt("_acme-challenge.app.example.com").is_empty());
    }

    #[tokio::test]
    async fn router_is_absent_with_no_provider_configured() {
        let app = dns01_challenge_router(store(), None);
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
}
