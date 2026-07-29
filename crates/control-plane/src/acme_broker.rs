//! Rot/Gelb/Grün certificate-tier admission broker (#233): the control-plane
//! half of moving thousands of new customers/day past Let's Encrypt's
//! 50-certificates-per-registered-domain-per-7-days ceiling without ever
//! sharing an agent's TLS private key.
//!
//! `ct-agent` cannot become a thin ACME client driven by this crate — Cargo
//! forbids the cycle (`ct-agent` already depends on `ct-control-plane`). So
//! this module is deliberately **not** an ACME client: it is an admission
//! gate, a CA-assignment ledger, and a self-throttled rate-limit budget
//! tracker. `ct-agent`'s own `acme_client`/`acme_orchestrate` keep driving
//! the real ACME wire protocol exactly as before; they just poll
//! [`admission`] first and report back via [`issuance_complete`].
//!
//! Every hostname starts **Rot** (created, not yet reachable), is promoted to
//! **Gelb** once it is live via the shared edge wildcard certificate (see the
//! `ct-edge` Gelb-termination path), and finally reaches **Grün** once its own
//! individually-issued, agent-held-key certificate exists. A Gelb hostname
//! sits in a FIFO queue; [`run_admission_loop`] periodically offers the
//! front-of-queue hostnames a 48h claim window against whichever CA in
//! [`ct_common::acme_ca::active_rotation`] currently has the most headroom —
//! a CA assignment, once offered, is **permanent** ([`SqliteTunnelStore::offer_claim`]/
//! [`SqliteTunnelStore::record_issuance_complete`] both refuse to rewrite an
//! already-set `assigned_ca`): every renewal reuses the same CA forever.
//!
//! Ownership is gated exactly like [`crate::dns01_challenge`]: an agent
//! proves it owns a hostname via the same routing token
//! [`crate::edge_mesh::SqliteEdgeMesh::token_owns_hostname`] already checks.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::edge_mesh::SqliteEdgeMesh;
use crate::storage::SqliteTunnelStore;

/// How long a front-of-queue claim offer stays open before lapsing.
const CLAIM_WINDOW_SECS: i64 = 48 * 3600;
/// The rate-limit ledger's rolling window — matches Let's Encrypt's own
/// "per 7 days" framing; every CA in the rotation is budgeted against the
/// same window for simplicity, even where a CA's real limit isn't weekly.
const BUDGET_WINDOW_SECS: i64 = 7 * 24 * 3600;

#[derive(Clone)]
struct AcmeBrokerState {
    edge_mesh: Arc<SqliteEdgeMesh>,
    tunnels: Arc<SqliteTunnelStore>,
    /// The edge admin API's (url, token) — same pair
    /// [`crate::portal_api`]'s `authorize_hostname` already uses — needed
    /// here so [`issuance_complete`] can revert a hostname's channel tier back
    /// to ordinary passthrough (`?channel_tier` absent) the moment it reaches
    /// Grün. `None` when unconfigured: the channel-tier push is then simply
    /// skipped (logged), matching this crate's "absent unless configured" style.
    edge_admin: Option<(String, String)>,
}

/// Build the admission-broker router. Always mounted (unlike
/// [`crate::dns01_challenge`], this needs no DNS backend) — the background
/// [`run_admission_loop`] is what's opt-in, via `CT_CP_ACME_BROKER_ENABLED`,
/// so a deployment that hasn't turned the feature on simply never promotes
/// anything past Rot and these endpoints stay quiet.
pub fn acme_broker_router(
    edge_mesh: Arc<SqliteEdgeMesh>,
    tunnels: Arc<SqliteTunnelStore>,
    edge_admin: Option<(String, String)>,
) -> Router {
    Router::new()
        .route("/agent/acme-admission/:token/:hostname", get(admission))
        .route("/agent/acme-issuance-complete/:token/:hostname", post(issuance_complete))
        .with_state(AcmeBrokerState { edge_mesh, tunnels, edge_admin })
}

/// Push this hostname's current **channel** tier to the edge (#233) — which
/// TLS termination channel serves it (shared wildcard cert vs. its own).
/// Named `channel_tier`/`push_channel_tier` specifically to stay distinct
/// from the unrelated user-facing *feature* tier (Standard/paid, see
/// `portal_api.rs`). The SAME `POST
/// /admin/authorize-host/:token/:host[?channel_tier=gelb]` call
/// `portal_api::authorize_hostname` already makes, just re-issued whenever
/// the channel tier itself changes rather than only at tunnel creation.
/// `gelb=true` on the Rot->Gelb transition (so the edge starts terminating
/// with the shared wildcard cert); `gelb=false` once a hostname reaches Grün
/// (so the edge reverts to ordinary passthrough and the browser sees the
/// origin's own, now-issued certificate). Best-effort and logged, never fails
/// the caller — exactly [`crate::portal_api::authorize_hostname`]'s own
/// posture, since the hostname's DB state is already correct either way.
async fn push_channel_tier(
    edge_admin: &Option<(String, String)>,
    tunnels: &SqliteTunnelStore,
    hostname: &str,
    gelb: bool,
) {
    let Some((url, token)) = edge_admin else {
        eprintln!(
            "ct-cp: acme_broker: channel-tier push SKIPPED for {hostname} (gelb={gelb}) — edge admin API not \
             configured (set CT_CP_EDGE_ADMIN_URL + CT_CP_EDGE_ADMIN_TOKEN)"
        );
        return;
    };
    let routing_token = match tunnels.routing_token_for_hostname(hostname) {
        Ok(Some(t)) => t,
        Ok(None) => {
            eprintln!("ct-cp: acme_broker: channel-tier push for {hostname} skipped — no routing token on record");
            return;
        }
        Err(e) => {
            eprintln!("ct-cp: acme_broker: channel-tier push for {hostname} failed to look up routing token: {e}");
            return;
        }
    };
    let endpoint = format!(
        "{}/admin/authorize-host/{routing_token}/{hostname}{}",
        url.trim_end_matches('/'),
        if gelb { "?channel_tier=gelb" } else { "" }
    );
    match crate::portal_api::edge_admin_http_client()
        .post(&endpoint)
        .header("x-ct-admin-token", token.as_str())
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => {
            eprintln!("ct-cp: acme_broker: channel-tier push for {hostname} (gelb={gelb}) succeeded")
        }
        Ok(r) => eprintln!("ct-cp: acme_broker: channel-tier push for {hostname} returned {}", r.status()),
        Err(e) => eprintln!("ct-cp: acme_broker: channel-tier push for {hostname} failed: {e}"),
    }
}

async fn authorize(state: &AcmeBrokerState, token: &str, hostname: &str) -> Result<(), (StatusCode, String)> {
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

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct AssignedCaResponse {
    name: String,
    directory_url: String,
    requires_eab: bool,
    eab_kid: Option<String>,
    eab_hmac_key_b64url: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct AdmissionResponse {
    status: String,
    may_issue_now: bool,
    assigned_ca: Option<AssignedCaResponse>,
    claim_deadline: Option<i64>,
}

async fn admission(
    State(state): State<AcmeBrokerState>,
    Path((token, hostname)): Path<(String, String)>,
) -> Result<Json<AdmissionResponse>, (StatusCode, String)> {
    authorize(&state, &token, &hostname).await?;
    let admission = state
        .tunnels
        .cert_admission_for_hostname(&hostname)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "no tunnel with this hostname".to_string()))?;

    let may_issue_now = admission.may_issue_now(now_secs());
    let assigned_ca = if may_issue_now { admission.assigned_ca.as_deref().and_then(ca_response_for) } else { None };

    Ok(Json(AdmissionResponse { status: admission.status, may_issue_now, assigned_ca, claim_deadline: admission.claim_deadline }))
}

async fn issuance_complete(
    State(state): State<AcmeBrokerState>,
    Path((token, hostname)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    authorize(&state, &token, &hostname).await?;
    let domain = registered_domain(&hostname);
    state
        .tunnels
        .record_issuance_complete(&hostname, &domain, now_secs())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Now that this hostname has its own real certificate, revert the edge to
    // ordinary passthrough -- otherwise it would stay stuck terminating with
    // the shared wildcard cert forever, the browser never seeing the
    // origin's own newly-issued one.
    push_channel_tier(&state.edge_admin, &state.tunnels, &hostname, false).await;
    Ok(StatusCode::OK)
}

fn ca_response_for(name: &str) -> Option<AssignedCaResponse> {
    let profile = ct_common::acme_ca::all_known().into_iter().find(|c| c.name == name)?;
    let (eab_kid, eab_hmac_key_b64url) = eab_for_ca(name);
    Some(AssignedCaResponse {
        name: profile.name.to_string(),
        directory_url: profile.directory_url.to_string(),
        requires_eab: profile.requires_eab,
        eab_kid,
        eab_hmac_key_b64url,
    })
}

/// Operator-configured EAB credentials for CAs that require them — one fixed
/// pair per CA (not per customer), same trust tier as a `directory_url`
/// itself. Absent (both `None`) for Let's Encrypt and for any CA this
/// deployment hasn't been given credentials for yet.
fn eab_for_ca(name: &str) -> (Option<String>, Option<String>) {
    eab_for_ca_with(name, |k| std::env::var(k).ok())
}

/// Testable core of [`eab_for_ca`] behind an injectable lookup, matching this
/// crate's `from_env_with` convention elsewhere -- avoids mutating real
/// process env vars (flaky under parallel test execution) just to prove
/// [`pick_ca`]'s EAB-credential gate.
fn eab_for_ca_with(name: &str, get: impl Fn(&str) -> Option<String>) -> (Option<String>, Option<String>) {
    let (kid_var, hmac_var) = match name {
        "zerossl" => ("CT_CP_ACME_EAB_ZEROSSL_KID", "CT_CP_ACME_EAB_ZEROSSL_HMAC"),
        "google-trust-services" => ("CT_CP_ACME_EAB_GTS_KID", "CT_CP_ACME_EAB_GTS_HMAC"),
        "ssl.com" => ("CT_CP_ACME_EAB_SSLCOM_KID", "CT_CP_ACME_EAB_SSLCOM_HMAC"),
        _ => return (None, None),
    };
    let get = |k: &str| get(k).filter(|s| !s.is_empty());
    (get(kid_var), get(hmac_var))
}

/// The registered domain (eTLD+1) a hostname falls under, used to key the
/// rate-limit ledger. Duplicated rather than shared across a crate boundary
/// on purpose (mirrors `dns01_challenge.rs`'s `dns01_record_name`) — this
/// fleet only ever mints single-level subdomains of its own configured
/// zone(s), so "everything but the leftmost label, unless there IS no
/// leftmost label to strip" is exact today; a multi-zone future would make
/// this a config lookup instead.
fn registered_domain(hostname: &str) -> String {
    let labels: Vec<&str> = hostname.split('.').collect();
    if labels.len() <= 2 {
        hostname.to_string()
    } else {
        labels[1..].join(".")
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Phase-1 conservative budget per CA per [`BUDGET_WINDOW_SECS`] — deliberately
/// **below** each CA's real documented (or, for GTS, assumed) limit. This
/// buffer is the actual "work against throttling/limits" mechanism: the
/// broker never lets its own bookkeeping get close enough to a real 429 to
/// risk one. ZeroSSL's real limit is "free, unlimited"; its budget here
/// exists only as a runaway-bug circuit breaker, not a real constraint.
fn budget_for(ca_name: &str) -> i64 {
    match ca_name {
        "letsencrypt" => 40,
        "zerossl" => 200,
        "google-trust-services" => 40,
        _ => 0,
    }
}

/// Pick the CA with the greatest remaining headroom for `domain` right now,
/// or `None` if every CA in the active rotation is at or over its budget --
/// or, just as importantly, has no CA left that could actually complete an
/// order. Least-utilized-first rather than a fixed round-robin counter or
/// fixed weights: GTS's real free-tier cap is unverified (see
/// `ct_common::acme_ca`'s own doc comments), so hardcoding a weight for an
/// unverified limit would be worse than adapting to actual usage.
///
/// A CA that `requires_eab` but has no EAB credentials configured for this
/// deployment (`eab_for_ca` returns `(None, None)`) is skipped entirely, not
/// merely deprioritized (found live, #229): `assigned_ca` is permanent once
/// offered (never rewritten), so assigning a CA this deployment can't
/// actually authenticate to would permanently strand that hostname at
/// Gelb -- ZeroSSL's real free-tier budget (200/7d) so outweighs Let's
/// Encrypt's (40/7d) that it would win this pick almost every time an
/// operator forgot to configure its EAB credentials, silently breaking
/// Gelb->Grün for nearly every future admission, not just the one that
/// happened to surface it.
fn pick_ca(tunnels: &SqliteTunnelStore, domain: &str, now: i64) -> rusqlite::Result<Option<&'static str>> {
    pick_ca_with(tunnels, domain, now, eab_for_ca)
}

/// Testable core of [`pick_ca`] behind an injectable EAB lookup (same
/// rationale as [`eab_for_ca_with`]).
fn pick_ca_with(
    tunnels: &SqliteTunnelStore,
    domain: &str,
    now: i64,
    eab_lookup: impl Fn(&str) -> (Option<String>, Option<String>),
) -> rusqlite::Result<Option<&'static str>> {
    let since = now - BUDGET_WINDOW_SECS;
    let mut best: Option<(&'static str, i64)> = None;
    for ca in ct_common::acme_ca::active_rotation() {
        if ca.requires_eab {
            let (kid, hmac) = eab_lookup(ca.name);
            if kid.is_none() || hmac.is_none() {
                continue;
            }
        }
        let budget = budget_for(ca.name);
        let (used, reserved) = tunnels.ca_budget_usage(ca.name, domain, since)?;
        let headroom = budget - used - reserved;
        if headroom > 0 && best.is_none_or(|(_, best_headroom)| headroom > best_headroom) {
            best = Some((ca.name, headroom));
        }
    }
    Ok(best.map(|(name, _)| name))
}

/// One admission-loop tick: Rot→Gelb safety net (pushing the Gelb tier to the
/// edge as each hostname is promoted), claim-deadline lapses, then offer CA
/// assignments to as much of the Gelb queue as current budget allows
/// (stopping, not erroring, the moment no CA has headroom — the rest of the
/// queue simply waits for the next tick).
async fn sweep_once(
    tunnels: &SqliteTunnelStore,
    edge_mesh: &SqliteEdgeMesh,
    edge_admin: &Option<(String, String)>,
) -> rusqlite::Result<()> {
    let now = now_secs();

    // 1. Rot -> Gelb safety net: `portal_api::authorize_hostname` already
    // pushes channel_tier=gelb synchronously on the happy path; this catches the
    // cases where that push failed or raced (edge admin unset, transient
    // error), and is also simply where a fresh admission-loop tick learns
    // about newly-reachable hostnames at all.
    for hostname in tunnels.rot_hostnames()? {
        if edge_mesh.lookup_by_host(&hostname)?.is_some() && tunnels.enter_gelb_queue(&hostname, now)? {
            push_channel_tier(edge_admin, tunnels, &hostname, true).await;
        }
    }

    // 2. Re-affirm channel_tier=gelb for every currently-Gelb hostname (#229
    // follow-up): the edge's `gelb_hosts` is in-memory-only with no
    // rehydration on restart, so any edge restart silently reverts these
    // hosts to plain SNI passthrough -- which forwards raw TLS bytes to a
    // Gelb-tier's plain-HTTP origin, producing handshake failures downstream.
    // Re-pushing every tick is a cheap, idempotent no-op on the edge in the
    // steady state and self-heals within one tick of any restart.
    for hostname in tunnels.gelb_hostnames()? {
        push_channel_tier(edge_admin, tunnels, &hostname, true).await;
    }

    // 3. Lapse expired claims -- must run before the admission sweep below so
    // a just-lapsed hostname's freed budget can be reused the same tick.
    tunnels.lapse_expired_claims(now)?;

    // 4. Admit as much of the FIFO queue as current CA headroom allows.
    for hostname in tunnels.gelb_queue_fifo()? {
        let domain = registered_domain(&hostname);
        match pick_ca(tunnels, &domain, now)? {
            Some(ca) => {
                tunnels.offer_claim(&hostname, ca, now, now + CLAIM_WINDOW_SECS)?;
            }
            None => break,
        }
    }
    Ok(())
}

/// Run [`sweep_once`] forever on `tick`, opt-in via `CT_CP_ACME_BROKER_ENABLED`
/// at the call site (this function itself has no such gate — the caller
/// decides whether to spawn it at all, matching this crate's "absent unless
/// configured" convention). Best-effort: a sweep error is logged, not fatal,
/// so a transient DB hiccup never kills the loop. `edge_admin` is the same
/// (url, token) pair the router's channel-tier-push uses — passed here too so the
/// Rot->Gelb transition can push `channel_tier=gelb` the moment it happens, not only
/// on the next tunnel-creation-time push.
pub async fn run_admission_loop(
    tunnels: Arc<SqliteTunnelStore>,
    edge_mesh: Arc<SqliteEdgeMesh>,
    edge_admin: Option<(String, String)>,
    tick: Duration,
) -> ! {
    loop {
        if let Err(e) = sweep_once(&tunnels, &edge_mesh, &edge_admin).await {
            eprintln!("ct-cp: acme_broker: sweep failed: {e}");
        }
        tokio::time::sleep(tick).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use std::sync::Mutex;
    use tower::ServiceExt;

    fn stores() -> (Arc<SqliteEdgeMesh>, Arc<SqliteTunnelStore>) {
        (Arc::new(SqliteEdgeMesh::open_in_memory().unwrap()), Arc::new(SqliteTunnelStore::open_in_memory().unwrap()))
    }

    #[tokio::test]
    async fn admission_requires_the_owning_token_and_reports_rot_by_default() {
        let (edge_mesh, tunnels) = stores();
        tunnels.create("alice", "web", Some("app.example.com")).unwrap();
        edge_mesh.record_ownership("deadbeef", Some("app.example.com"), "edge-1", 0).unwrap();
        let app = acme_broker_router(edge_mesh, tunnels, None);

        let resp = app
            .clone()
            .oneshot(Request::get("/agent/acme-admission/deadbeef/app.example.com").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: AdmissionResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.status, "rot");
        assert!(!parsed.may_issue_now);
        assert_eq!(parsed.assigned_ca, None);

        // The wrong token is refused, same as dns01_challenge's authorization.
        let resp = app
            .oneshot(Request::get("/agent/acme-admission/wrong-token/app.example.com").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admission_reports_may_issue_now_only_within_an_open_offer_or_once_gruen() {
        let (edge_mesh, tunnels) = stores();
        tunnels.create("alice", "web", Some("app.example.com")).unwrap();
        edge_mesh.record_ownership("deadbeef", Some("app.example.com"), "edge-1", 0).unwrap();
        tunnels.enter_gelb_queue("app.example.com", 100).unwrap();

        let far_future = now_secs() + 100;
        tunnels.offer_claim("app.example.com", "letsencrypt", 100, far_future).unwrap();
        let app = acme_broker_router(edge_mesh.clone(), tunnels.clone(), None);
        let resp = app
            .oneshot(Request::get("/agent/acme-admission/deadbeef/app.example.com").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: AdmissionResponse = serde_json::from_slice(&body).unwrap();
        assert!(parsed.may_issue_now, "an open, unexpired offer allows issuance");
        assert_eq!(parsed.assigned_ca.as_ref().unwrap().name, "letsencrypt");
        assert_eq!(parsed.claim_deadline, Some(far_future));

        // A completed issuance flips to gruen and keeps may_issue_now true forever after.
        let app = acme_broker_router(edge_mesh, tunnels.clone(), None);
        let resp = app
            .clone()
            .oneshot(
                Request::post("/agent/acme-issuance-complete/deadbeef/app.example.com").body(Body::empty()).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = app
            .oneshot(Request::get("/agent/acme-admission/deadbeef/app.example.com").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: AdmissionResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.status, "gruen");
        assert!(parsed.may_issue_now, "gruen always may_issue_now -- renewals forever");
        assert_eq!(parsed.assigned_ca.as_ref().unwrap().name, "letsencrypt", "same CA, never re-rolled");
    }

    #[test]
    fn registered_domain_strips_exactly_the_leftmost_label() {
        assert_eq!(registered_domain("customer1.bunsenbrenner.org"), "bunsenbrenner.org");
        assert_eq!(registered_domain("bunsenbrenner.org"), "bunsenbrenner.org", "no leftmost label to strip");
    }

    /// An EAB lookup standing in for "every CA has its credentials
    /// configured" -- the tests that exercise budget-based selection care
    /// about that logic specifically, not the EAB gate (covered separately
    /// below), so they inject this rather than depend on real process env vars.
    fn all_eab_configured(_name: &str) -> (Option<String>, Option<String>) {
        (Some("kid".to_string()), Some("hmac".to_string()))
    }

    #[test]
    fn pick_ca_favors_the_least_utilized_ca_and_returns_none_when_all_are_exhausted() {
        let tunnels = SqliteTunnelStore::open_in_memory().unwrap();
        tunnels.create("alice", "a", Some("a.example.com")).unwrap();
        tunnels.create("alice", "b", Some("b.example.com")).unwrap();
        tunnels.enter_gelb_queue("a.example.com", 1).unwrap();
        tunnels.enter_gelb_queue("b.example.com", 2).unwrap();
        // Burn most of Let's Encrypt's budget (40) so ZeroSSL/GTS look relatively fresher.
        for i in 0..35 {
            let host = format!("burn{i}.example.com");
            tunnels.create("alice", &host, Some(&host)).unwrap();
            tunnels.enter_gelb_queue(&host, 3).unwrap();
            tunnels.offer_claim(&host, "letsencrypt", 3, 999_999_999).unwrap();
            tunnels.record_issuance_complete(&host, "example.com", 3).unwrap();
        }

        let picked = pick_ca_with(&tunnels, "example.com", 100, all_eab_configured).unwrap();
        assert_ne!(picked, Some("letsencrypt"), "letsencrypt is down to 5 headroom, others have their full budget");

        // Exhaust every CA's budget entirely -- no CA should be pickable.
        let tunnels2 = SqliteTunnelStore::open_in_memory().unwrap();
        for ca in ["letsencrypt", "zerossl", "google-trust-services"] {
            let budget = budget_for(ca);
            for i in 0..budget {
                let host = format!("{ca}-{i}.example.com");
                tunnels2.create("alice", &host, Some(&host)).unwrap();
                tunnels2.enter_gelb_queue(&host, 1).unwrap();
                tunnels2.offer_claim(&host, ca, 1, 999_999_999).unwrap();
                tunnels2.record_issuance_complete(&host, "example.com", 1).unwrap();
            }
        }
        assert_eq!(
            pick_ca_with(&tunnels2, "example.com", 100, all_eab_configured).unwrap(),
            None,
            "every CA exhausted -- nothing pickable"
        );
    }

    #[test]
    fn pick_ca_never_assigns_a_ca_that_requires_eab_but_has_no_credentials_configured() {
        // #229: assigned_ca is permanent once offered (never rewritten), so
        // picking a CA this deployment can't actually authenticate to would
        // permanently strand that hostname at Gelb. ZeroSSL's budget (200/7d)
        // dwarfs Let's Encrypt's (40/7d), so with no EAB lookup at all it
        // would otherwise win every single time.
        let tunnels = SqliteTunnelStore::open_in_memory().unwrap();
        let none_configured = |_: &str| (None, None);
        let picked = pick_ca_with(&tunnels, "example.com", 100, none_configured).unwrap();
        assert_eq!(
            picked,
            Some("letsencrypt"),
            "letsencrypt needs no EAB and has full budget -- the only CA that's actually usable"
        );

        // Once ZeroSSL's credentials ARE configured, it wins back on budget headroom.
        let with_zerossl = |name: &str| {
            if name == "zerossl" {
                (Some("kid".to_string()), Some("hmac".to_string()))
            } else {
                (None, None)
            }
        };
        assert_eq!(pick_ca_with(&tunnels, "example.com", 100, with_zerossl).unwrap(), Some("zerossl"));
    }

    #[tokio::test]
    async fn sweep_once_promotes_rot_to_gelb_lapses_offers_and_admits_the_queue() {
        let edge_mesh = SqliteEdgeMesh::open_in_memory().unwrap();
        let tunnels = SqliteTunnelStore::open_in_memory().unwrap();
        tunnels.create("alice", "web", Some("app.example.com")).unwrap();
        // Not yet edge-authorized -> stays rot through a sweep. No edge_admin
        // configured (None) -- proves the sweep still runs to completion and
        // simply skips (logs) the channel-tier push, rather than failing the tick.
        sweep_once(&tunnels, &edge_mesh, &None).await.unwrap();
        assert_eq!(tunnels.cert_admission_for_hostname("app.example.com").unwrap().unwrap().status, "rot");

        // Edge authorization lands -> the safety net promotes it, and the
        // admission step immediately offers it a CA (budget is wide open).
        // `lookup_by_host` joins against `mesh_edges`, so the edge itself
        // must have a heartbeat row too, not just the ownership record.
        edge_mesh.heartbeat("edge-1", "127.0.0.1:1234", 0).unwrap();
        edge_mesh.record_ownership("tok1", Some("app.example.com"), "edge-1", 0).unwrap();
        sweep_once(&tunnels, &edge_mesh, &None).await.unwrap();
        let a = tunnels.cert_admission_for_hostname("app.example.com").unwrap().unwrap();
        assert_eq!(a.status, "gelb");
        assert_eq!(a.claim_state, "offered");
        assert!(a.assigned_ca.is_some());
    }

    /// A minimal mock edge admin API recording every `authorize-host` call it
    /// receives (path, including query string, plus the admin-token header).
    async fn spawn_mock_edge_admin() -> (String, Arc<Mutex<Vec<(String, Option<String>)>>>) {
        use axum::extract::{OriginalUri, State as AxState};
        let calls: Arc<Mutex<Vec<(String, Option<String>)>>> = Arc::new(Mutex::new(Vec::new()));
        async fn authorize_host(
            AxState(calls): AxState<Arc<Mutex<Vec<(String, Option<String>)>>>>,
            OriginalUri(uri): OriginalUri,
            headers: axum::http::HeaderMap,
        ) -> StatusCode {
            let token_hdr = headers.get("x-ct-admin-token").and_then(|v| v.to_str().ok()).map(str::to_string);
            calls.lock().unwrap().push((uri.to_string(), token_hdr));
            StatusCode::OK
        }
        let app = Router::new()
            .route("/admin/authorize-host/:token/:host", axum::routing::post(authorize_host))
            .with_state(calls.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), calls)
    }

    #[tokio::test]
    async fn sweep_pushes_tier_gelb_to_the_edge_and_issuance_complete_reverts_it() {
        // #233: the end-to-end wiring -- a Rot->Gelb promotion must reach the
        // edge's real authorize-host endpoint with `?channel_tier=gelb`, and
        // completing an issuance must push again with NO tier (reverting to
        // ordinary passthrough), using the tunnel's actual routing token.
        let (edge_url, calls) = spawn_mock_edge_admin().await;
        let edge_admin = Some((edge_url, "sekret".to_string()));

        let edge_mesh = Arc::new(SqliteEdgeMesh::open_in_memory().unwrap());
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "web", Some("app.example.com")).unwrap();
        edge_mesh.heartbeat("edge-1", "127.0.0.1:1234", 0).unwrap();
        edge_mesh.record_ownership(&t.routing_token, Some("app.example.com"), "edge-1", 0).unwrap();

        sweep_once(&tunnels, &edge_mesh, &edge_admin).await.unwrap();
        {
            let seen = calls.lock().unwrap();
            // One push from the Rot->Gelb promotion itself, one from the
            // same-tick Gelb re-affirm pass (#229 follow-up) -- both `channel_tier=gelb`
            // for the same host, since the re-affirm pass sees the row it just promoted.
            assert_eq!(seen.len(), 2, "promotion push + same-tick re-affirm push");
            for call in seen.iter() {
                assert!(
                    call.0.contains(&format!("/admin/authorize-host/{}/app.example.com", t.routing_token))
                        && call.0.contains("channel_tier=gelb"),
                    "{}",
                    call.0
                );
                assert_eq!(call.1.as_deref(), Some("sekret"));
            }
        }

        // Complete the issuance (front-of-queue offer already exists after the sweep).
        let app = acme_broker_router(edge_mesh.clone(), tunnels.clone(), edge_admin.clone());
        let resp = app
            .oneshot(
                Request::post(format!("/agent/acme-issuance-complete/{}/app.example.com", t.routing_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let seen = calls.lock().unwrap();
        assert_eq!(seen.len(), 3, "issuance-complete pushes a third, reverting channel-tier update");
        assert!(!seen[2].0.contains("channel_tier="), "no channel_tier param -> revert to ordinary passthrough: {}", seen[2].0);
    }

    #[tokio::test]
    async fn sweep_re_affirms_tier_gelb_on_every_tick_even_with_no_new_transition() {
        // #229 follow-up: the edge's `gelb_hosts` is in-memory-only and has no
        // rehydration on restart -- any edge restart silently reverts a
        // still-Gelb hostname to ordinary SNI passthrough. Proves the sweep
        // re-pushes channel_tier=gelb on a LATER tick too, not only at the moment of
        // the Rot->Gelb transition, so an edge restart self-heals within one
        // tick no matter when it happens.
        let (edge_url, calls) = spawn_mock_edge_admin().await;
        let edge_admin = Some((edge_url, "sekret".to_string()));

        let edge_mesh = Arc::new(SqliteEdgeMesh::open_in_memory().unwrap());
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "web", Some("app.example.com")).unwrap();
        edge_mesh.heartbeat("edge-1", "127.0.0.1:1234", 0).unwrap();
        edge_mesh.record_ownership(&t.routing_token, Some("app.example.com"), "edge-1", 0).unwrap();

        sweep_once(&tunnels, &edge_mesh, &edge_admin).await.unwrap();
        let after_first_tick = calls.lock().unwrap().len();
        assert!(after_first_tick >= 1, "at least the promotion push happened");

        // Simulate an edge restart wiping `gelb_hosts` -- nothing in this
        // store changes, there is no new Rot->Gelb transition to trigger.
        sweep_once(&tunnels, &edge_mesh, &edge_admin).await.unwrap();
        let after_second_tick = calls.lock().unwrap().len();
        assert!(
            after_second_tick > after_first_tick,
            "a second tick with no new transition must still re-push channel_tier=gelb for the still-Gelb hostname"
        );
        let seen = calls.lock().unwrap();
        assert!(seen.last().unwrap().0.contains("channel_tier=gelb"));
    }
}
