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
/// Returns whether the push actually reached the edge and succeeded (#264) -- the
/// caller uses this to decide whether a Gruen revert is confirmed or needs a retry
/// (see [`SqliteTunnelStore::pending_revert_hostnames`]); a Gelb-tier push has no
/// such follow-up today (the sweep already unconditionally re-affirms every row in
/// [`SqliteTunnelStore::gelb_hostnames`] every tick regardless of this return value).
async fn push_channel_tier(
    edge_admin: &Option<(String, String)>,
    tunnels: &SqliteTunnelStore,
    hostname: &str,
    gelb: bool,
) -> bool {
    let Some((url, token)) = edge_admin else {
        eprintln!(
            "ct-cp: acme_broker: channel-tier push SKIPPED for {hostname} (gelb={gelb}) — edge admin API not \
             configured (set CT_CP_EDGE_ADMIN_URL + CT_CP_EDGE_ADMIN_TOKEN)"
        );
        return false;
    };
    let routing_token = match tunnels.routing_token_for_hostname(hostname) {
        Ok(Some(t)) => t,
        Ok(None) => {
            eprintln!("ct-cp: acme_broker: channel-tier push for {hostname} skipped — no routing token on record");
            return false;
        }
        Err(e) => {
            eprintln!("ct-cp: acme_broker: channel-tier push for {hostname} failed to look up routing token: {e}");
            return false;
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
            eprintln!("ct-cp: acme_broker: channel-tier push for {hostname} (gelb={gelb}) succeeded");
            true
        }
        Ok(r) => {
            eprintln!("ct-cp: acme_broker: channel-tier push for {hostname} returned {}", r.status());
            false
        }
        Err(e) => {
            eprintln!("ct-cp: acme_broker: channel-tier push for {hostname} failed: {e}");
            false
        }
    }
}

async fn authorize(state: &AcmeBrokerState, token: &str, hostname: &str) -> Result<(), (StatusCode, String)> {
    // #286: `mesh_ownership` is best-effort bookkeeping (`EdgeMeshHandle::forget`
    // swallows a DELETE failure on revoke — see its own doc comment), so a stale row
    // there must never be sufficient on its own; also require the DURABLE
    // `subject_tunnels` record to currently agree this token owns this hostname. A
    // revoked tunnel's row is gone (transactional delete, #327), so this closes the
    // gap regardless of whether the best-effort mesh_ownership cleanup succeeded.
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

/// #263: this response carries EAB secrets (`assigned_ca.eab_hmac_key_b64url`) once
/// `may_issue_now` is true. The endpoint stays GET (auth lives in the path, and
/// `ct-agent`'s ACME flow already calls it that way — changing the method is a
/// breaking wire change this fix doesn't need to make), but every response is marked
/// `no-store` so a shared/intermediary cache in front of the control plane (CDN,
/// reverse proxy) never persists a secret-bearing body, even one whose auth the cache
/// can't see (it's in the path, not a header it necessarily keys on).
const NO_STORE: (axum::http::HeaderName, &str) = (axum::http::header::CACHE_CONTROL, "no-store");

async fn admission(
    State(state): State<AcmeBrokerState>,
    Path((token, hostname)): Path<(String, String)>,
) -> Result<([(axum::http::HeaderName, &'static str); 1], Json<AdmissionResponse>), (StatusCode, String)> {
    authorize(&state, &token, &hostname).await?;
    let admission = state
        .tunnels
        .cert_admission_for_hostname(&hostname)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "no tunnel with this hostname".to_string()))?;

    let may_issue_now = admission.may_issue_now(now_secs());
    let assigned_ca = if may_issue_now { admission.assigned_ca.as_deref().and_then(ca_response_for) } else { None };

    Ok((
        [NO_STORE],
        Json(AdmissionResponse { status: admission.status, may_issue_now, assigned_ca, claim_deadline: admission.claim_deadline }),
    ))
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
    // origin's own newly-issued one. #264: `record_issuance_complete` already
    // marked this hostname `pending_revert`; only clear that flag if the push
    // actually landed -- a failure here is now retried by the sweep instead of
    // silently forgotten (the DB said Gruen, the edge kept believing Gelb).
    if push_channel_tier(&state.edge_admin, &state.tunnels, &hostname, false).await {
        if let Err(e) = state.tunnels.clear_pending_revert(&hostname) {
            eprintln!("ct-cp: acme_broker: failed to clear pending_revert for {hostname}: {e}");
        }
    }
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

/// Promote one hostname from Rot to Gelb right now, if it's ready (the edge
/// already knows it owns this hostname). Called synchronously from
/// [`crate::portal_api::authorize_hostname`] right after a successful edge
/// authorize, so a freshly-created tunnel reaches Gelb immediately instead of
/// waiting for the next [`run_admission_loop`] tick (up to
/// `CT_CP_ACME_BROKER_TICK_SECS`, default 60s) — found live (#233 follow-up):
/// despite this module's own doc comments long claiming `authorize_hostname`
/// "already pushes channel_tier=gelb synchronously on the happy path", no call
/// site ever actually did that; every fresh tunnel silently sat in Rot for a
/// full tick no matter how fast the edge-authorize itself was. `sweep_once`'s
/// Rot→Gelb step remains as the safety net (edge admin unset, a transient
/// error here, or a restart missing this synchronous path) — not the primary
/// mechanism it was always meant to be.
pub(crate) async fn try_promote_rot_to_gelb(
    tunnels: &SqliteTunnelStore,
    edge_mesh: &crate::edge_mesh::EdgeMeshHandle,
    edge_admin: &Option<(String, String)>,
    hostname: &str,
) {
    let now = now_secs();
    match edge_mesh.lookup_by_host(hostname).map(|owned| owned.is_some()) {
        Ok(true) => match tunnels.enter_gelb_queue(hostname, now) {
            Ok(true) => {
                push_channel_tier(edge_admin, tunnels, hostname, true).await;
            }
            Ok(false) => {} // already past Rot (e.g. a retry) -- nothing to do
            Err(e) => eprintln!("ct-cp: acme_broker: enter_gelb_queue for {hostname} failed: {e}"),
        },
        Ok(false) => {} // edge doesn't know this hostname yet -- the sweep will catch it
        Err(e) => eprintln!("ct-cp: acme_broker: edge_mesh lookup for {hostname} failed: {e}"),
    }
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

    // 1. Rot -> Gelb safety net: `portal_api::authorize_hostname` calls
    // `try_promote_rot_to_gelb` synchronously on the happy path; this catches
    // the cases where that call failed or raced (edge admin unset, transient
    // error), and is also where a fresh admission-loop tick learns about any
    // hostname the synchronous path missed.
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

    // 2b. Retry the Gelb->Gruen revert push for any hostname it didn't confirm land
    // on yet (#264): unlike step 2 above, this is bounded and self-terminating --
    // once the push succeeds, `clear_pending_revert` removes the hostname from
    // `pending_revert_hostnames` for good, so this never grows into an ever-larger
    // per-tick re-push of every Gruen hostname a deployment has ever issued.
    for hostname in tunnels.pending_revert_hostnames()? {
        if push_channel_tier(edge_admin, tunnels, &hostname, false).await {
            tunnels.clear_pending_revert(&hostname)?;
        }
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
        let t = tunnels.create("alice", "web", Some("app.example.com")).unwrap();
        edge_mesh.record_ownership(&t.routing_token, Some("app.example.com"), "edge-1", 0).unwrap();
        let app = acme_broker_router(edge_mesh, tunnels, None);
        let path = format!("/agent/acme-admission/{}/app.example.com", t.routing_token);

        let resp = app.clone().oneshot(Request::get(&path).body(Body::empty()).unwrap()).await.unwrap();
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
    async fn admission_response_is_marked_no_store_263() {
        // #263: this response can carry EAB secrets once may_issue_now is true --
        // every response (secrets present or not) must tell a shared/intermediary
        // cache never to persist it.
        let (edge_mesh, tunnels) = stores();
        let t = tunnels.create("alice", "web", Some("app.example.com")).unwrap();
        edge_mesh.record_ownership(&t.routing_token, Some("app.example.com"), "edge-1", 0).unwrap();
        let app = acme_broker_router(edge_mesh, tunnels, None);
        let path = format!("/agent/acme-admission/{}/app.example.com", t.routing_token);

        let resp = app.oneshot(Request::get(&path).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(axum::http::header::CACHE_CONTROL).unwrap(), "no-store");
    }

    #[tokio::test]
    async fn admission_is_refused_once_mesh_ownership_is_stale_relative_to_the_durable_tunnel_286() {
        // #286: `mesh_ownership` is best-effort (a revoke's forget() can fail and
        // leave a stale row). Proves the actual bug this closes: even when
        // mesh_ownership still (incorrectly) claims a token owns a hostname, the
        // durable subject_tunnels record must ALSO agree, or admission is refused.
        let (edge_mesh, tunnels) = stores();
        let t = tunnels.create("alice", "web", Some("app.example.com")).unwrap();
        edge_mesh.record_ownership(&t.routing_token, Some("app.example.com"), "edge-1", 0).unwrap();
        // Revoke the tunnel at the durable layer WITHOUT touching mesh_ownership --
        // simulating exactly the failure mode #286 describes (forget()'s DELETE
        // silently failed and left the stale row behind).
        tunnels.revoke("alice", &t.id, 1_000).unwrap();
        assert!(
            edge_mesh.token_owns_hostname(&t.routing_token, "app.example.com").unwrap(),
            "sanity: the stale mesh_ownership row is still there"
        );

        let app = acme_broker_router(edge_mesh, tunnels, None);
        let path = format!("/agent/acme-admission/{}/app.example.com", t.routing_token);
        let resp = app.oneshot(Request::get(&path).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "a revoked tunnel must not admit even with a stale mesh_ownership row"
        );
    }

    #[tokio::test]
    async fn admission_reports_may_issue_now_only_within_an_open_offer_or_once_gruen() {
        let (edge_mesh, tunnels) = stores();
        let t = tunnels.create("alice", "web", Some("app.example.com")).unwrap();
        edge_mesh.record_ownership(&t.routing_token, Some("app.example.com"), "edge-1", 0).unwrap();
        tunnels.enter_gelb_queue("app.example.com", 100).unwrap();
        let admission_path = format!("/agent/acme-admission/{}/app.example.com", t.routing_token);
        let issuance_complete_path = format!("/agent/acme-issuance-complete/{}/app.example.com", t.routing_token);

        let far_future = now_secs() + 100;
        tunnels.offer_claim("app.example.com", "letsencrypt", 100, far_future).unwrap();
        let app = acme_broker_router(edge_mesh.clone(), tunnels.clone(), None);
        let resp = app.oneshot(Request::get(&admission_path).body(Body::empty()).unwrap()).await.unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: AdmissionResponse = serde_json::from_slice(&body).unwrap();
        assert!(parsed.may_issue_now, "an open, unexpired offer allows issuance");
        assert_eq!(parsed.assigned_ca.as_ref().unwrap().name, "letsencrypt");
        assert_eq!(parsed.claim_deadline, Some(far_future));

        // A completed issuance flips to gruen and keeps may_issue_now true forever after.
        let app = acme_broker_router(edge_mesh, tunnels.clone(), None);
        let resp = app
            .clone()
            .oneshot(Request::post(&issuance_complete_path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = app.oneshot(Request::get(&admission_path).body(Body::empty()).unwrap()).await.unwrap();
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
        edge_mesh.heartbeat("edge-1", "127.0.0.1:1234", now_secs()).unwrap();
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
        edge_mesh.heartbeat("edge-1", "127.0.0.1:1234", now_secs()).unwrap();
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

    /// Like [`spawn_mock_edge_admin`], but every call fails (500) while `failing` is
    /// true -- lets a test force `push_channel_tier` to report failure on demand.
    async fn spawn_mock_edge_admin_with_failure_toggle(
    ) -> (String, Arc<Mutex<Vec<(String, Option<String>)>>>, Arc<std::sync::atomic::AtomicBool>) {
        use axum::extract::{OriginalUri, State as AxState};
        let calls: Arc<Mutex<Vec<(String, Option<String>)>>> = Arc::new(Mutex::new(Vec::new()));
        let failing = Arc::new(std::sync::atomic::AtomicBool::new(false));
        async fn authorize_host(
            AxState((calls, failing)): AxState<(Arc<Mutex<Vec<(String, Option<String>)>>>, Arc<std::sync::atomic::AtomicBool>)>,
            OriginalUri(uri): OriginalUri,
            headers: axum::http::HeaderMap,
        ) -> StatusCode {
            let token_hdr = headers.get("x-ct-admin-token").and_then(|v| v.to_str().ok()).map(str::to_string);
            calls.lock().unwrap().push((uri.to_string(), token_hdr));
            if failing.load(std::sync::atomic::Ordering::SeqCst) {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::OK
            }
        }
        let app = Router::new()
            .route("/admin/authorize-host/:token/:host", axum::routing::post(authorize_host))
            .with_state((calls.clone(), failing.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), calls, failing)
    }

    #[tokio::test]
    async fn a_failed_revert_push_is_retried_by_the_sweep_until_it_lands_264() {
        // #264: issuance_complete's revert push is best-effort -- a failure used to
        // just get logged and forgotten, leaving the DB Gruen while the edge kept
        // believing Gelb (terminating with the shared wildcard cert) forever. Prove
        // the sweep now retries it, and stops retrying once it actually lands.
        let (edge_url, calls, failing) = spawn_mock_edge_admin_with_failure_toggle().await;
        let edge_admin = Some((edge_url, "sekret".to_string()));

        let edge_mesh = Arc::new(SqliteEdgeMesh::open_in_memory().unwrap());
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let t = tunnels.create("alice", "web", Some("app.example.com")).unwrap();
        edge_mesh.heartbeat("edge-1", "127.0.0.1:1234", now_secs()).unwrap();
        edge_mesh.record_ownership(&t.routing_token, Some("app.example.com"), "edge-1", 0).unwrap();
        sweep_once(&tunnels, &edge_mesh, &edge_admin).await.unwrap(); // Rot -> Gelb

        // Make the edge fail every push, then complete the issuance -- the revert
        // push fails, but the endpoint still reports success to the caller
        // (best-effort, unchanged), and the hostname is now Gruen + pending_revert.
        failing.store(true, std::sync::atomic::Ordering::SeqCst);
        let app = acme_broker_router(edge_mesh.clone(), tunnels.clone(), edge_admin.clone());
        let resp = app
            .oneshot(
                Request::post(format!("/agent/acme-issuance-complete/{}/app.example.com", t.routing_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "issuance-complete still succeeds even though the revert push failed");
        assert_eq!(
            tunnels.pending_revert_hostnames().unwrap(),
            vec!["app.example.com".to_string()],
            "the failed revert is tracked as pending"
        );

        // Still failing: a sweep retries it, but it's still pending.
        let calls_before = calls.lock().unwrap().len();
        sweep_once(&tunnels, &edge_mesh, &edge_admin).await.unwrap();
        assert!(calls.lock().unwrap().len() > calls_before, "the sweep retried the revert push");
        assert_eq!(tunnels.pending_revert_hostnames().unwrap(), vec!["app.example.com".to_string()], "still pending -- still failing");

        // The edge recovers: the next sweep's retry lands, and the flag clears.
        failing.store(false, std::sync::atomic::Ordering::SeqCst);
        sweep_once(&tunnels, &edge_mesh, &edge_admin).await.unwrap();
        assert!(tunnels.pending_revert_hostnames().unwrap().is_empty(), "cleared once the retry actually succeeds");

        // And it STAYS cleared -- a further sweep doesn't re-push a confirmed revert
        // (bounded/self-terminating, unlike the unconditional Gelb re-affirm above).
        let calls_before = calls.lock().unwrap().len();
        sweep_once(&tunnels, &edge_mesh, &edge_admin).await.unwrap();
        let revert_calls_since: usize =
            calls.lock().unwrap()[calls_before..].iter().filter(|(uri, _)| !uri.contains("channel_tier=")).count();
        assert_eq!(revert_calls_since, 0, "a confirmed revert is never re-pushed");
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
        edge_mesh.heartbeat("edge-1", "127.0.0.1:1234", now_secs()).unwrap();
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
