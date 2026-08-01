//! Multi-edge preparation (ADR-0021): a durable registry of which edge
//! instance currently serves which routing token / hostname, so the system
//! can add edge hosts without the tunnel-routing state living only in one
//! process's memory.
//!
//! Today there is exactly one edge, and this registry is a no-op fast path
//! (every tunnel is "assigned" to that one edge, every lookup resolves
//! locally). The value delivered *now*, with zero new infrastructure:
//!
//! - **Fixes the restart-wipes-host-auth bug.** `crates/edge/src/state.rs`'s
//!   `host_auth` map is purely in-process memory with no persistence — every
//!   edge container recreation silently drops every hostname authorization
//!   (this caused a real production outage this session, #214). Because the
//!   control plane already originates every hostname authorization (it mints
//!   the token and pushes `authorize-host` to the edge), it can durably
//!   record that fact here and hand it back to the edge on boot to replay.
//! - **Lays the real groundwork for horizontal scale.** Once a second edge
//!   exists, [`assign_edge`] starts round-robining new tunnels across every
//!   edge that's heartbeated recently, and any edge can look up which peer
//!   holds a token/hostname it doesn't have locally via `GET
//!   /internal/edges/lookup`.
//!
//! The edge-to-edge byte-relay itself (ADR-0021 Part 1) IS built on top of
//! that lookup — `crate::edge`'s `relay_via_peer_edge`/the `'M'`-framed
//! relay role in `serve.rs` — but stays off by default
//! (`CT_EDGE_MESH_RELAY_ENABLED`) until an operator actually runs a second
//! edge; with exactly one edge every local route always hits, so the relay
//! path is a no-op either way.

use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::storage::{open_tuned, sqlite_store_ctors};
use ct_common::sync::MutexExt;

/// #285: liveness window for [`SqliteEdgeMesh::lookup_by_token`]/[`SqliteEdgeMesh::lookup_by_host`]
/// -- an edge that hasn't heartbeated within this many seconds is treated as dead for ownership
/// resolution, even if its `mesh_edges` row hasn't been pruned yet. The edge heartbeats every 30s
/// (`crates/edge/src/serve.rs`); 4x that tolerates a couple of missed beats from transient network
/// blips (matching this file's existing "generous, not aggressive" cutoff philosophy — see
/// [`SqliteEdgeMesh::prune_stale_edges`]'s own doc comment) without treating a briefly-jittery-but-
/// alive edge as gone.
const OWNERSHIP_LIVENESS_SECS: i64 = 120;

/// SQLite-backed registry: which edge last heartbeated with which peer
/// address, and which edge owns which routing token / hostname.
pub struct SqliteEdgeMesh {
    conn: Mutex<Connection>,
}

sqlite_store_ctors!(SqliteEdgeMesh);

impl SqliteEdgeMesh {
    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS mesh_edges (
                 id         TEXT PRIMARY KEY,
                 peer_addr  TEXT NOT NULL,
                 last_seen  INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS mesh_ownership (
                 token       TEXT PRIMARY KEY,
                 hostname    TEXT,
                 edge_id     TEXT NOT NULL,
                 updated_at  INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_mesh_ownership_hostname
                 ON mesh_ownership (hostname);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// An edge announces itself: `id` reachable at `peer_addr` (the address a
    /// *peer* edge would use for mesh-relay, not the public listener).
    /// Upserts so repeated heartbeats just bump `last_seen`.
    pub fn heartbeat(&self, id: &str, peer_addr: &str, now: i64) -> rusqlite::Result<()> {
        self.conn.lock_safe().execute(
            "INSERT INTO mesh_edges (id, peer_addr, last_seen) VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET peer_addr = excluded.peer_addr, last_seen = excluded.last_seen",
            params![id, peer_addr, now],
        )?;
        Ok(())
    }

    /// Delete `mesh_edges` rows that haven't heartbeated since `since` (#290
    /// housekeeping); returns the count removed. A permanently decommissioned
    /// edge's row otherwise lives forever — `live_edges`/`assign_edge` already
    /// filter it out of the *active* pool by `last_seen`, but it still bloats
    /// the table and every future full scan. Safe to call periodically with a
    /// generous cutoff (comfortably past any real edge's longest expected
    /// downtime, e.g. a redeploy window) — an edge that heartbeats again after
    /// being pruned just re-inserts on its next call, same as a brand-new one.
    pub fn prune_stale_edges(&self, since: i64) -> rusqlite::Result<usize> {
        self.conn.lock_safe().execute("DELETE FROM mesh_edges WHERE last_seen < ?1", params![since])
    }

    /// Edges that have heartbeated at or after `since` (a Unix-seconds
    /// cutoff) — the pool [`assign_edge`] balances across.
    fn live_edges(&self, since: i64) -> rusqlite::Result<Vec<String>> {
        let conn = self.conn.lock_safe();
        let mut stmt = conn.prepare("SELECT id FROM mesh_edges WHERE last_seen >= ?1 ORDER BY id")?;
        let rows = stmt
            .query_map(params![since], |r| r.get::<_, String>(0))?
            .collect();
        rows
    }

    /// Pick which edge a *new* tunnel should be assigned to: the least-loaded
    /// (fewest existing ownership rows) among edges that heartbeated since
    /// `live_since`, or `default_id` when none have (today's single-edge
    /// reality, or a fresh deployment before any heartbeat has landed).
    pub fn assign_edge(&self, default_id: &str, live_since: i64) -> rusqlite::Result<String> {
        let live = self.live_edges(live_since)?;
        if live.is_empty() {
            return Ok(default_id.to_string());
        }
        let conn = self.conn.lock_safe();
        let mut best = live[0].clone();
        let mut best_count = i64::MAX;
        for id in &live {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM mesh_ownership WHERE edge_id = ?1",
                params![id],
                |r| r.get(0),
            )?;
            if count < best_count {
                best_count = count;
                best = id.clone();
            }
        }
        Ok(best)
    }

    /// Record that `edge_id` now owns `token` (and `hostname`, if this
    /// tunnel has a Browser-Plane binding). Upserts — a tunnel re-authorized
    /// or reassigned just overwrites its previous row.
    pub fn record_ownership(
        &self,
        token: &str,
        hostname: Option<&str>,
        edge_id: &str,
        now: i64,
    ) -> rusqlite::Result<()> {
        self.conn.lock_safe().execute(
            "INSERT INTO mesh_ownership (token, hostname, edge_id, updated_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(token) DO UPDATE SET
                 hostname = excluded.hostname, edge_id = excluded.edge_id, updated_at = excluded.updated_at",
            params![token, hostname, edge_id, now],
        )?;
        Ok(())
    }

    /// Which edge (id, peer_addr) owns `token`, if any. #285: the owning edge must have
    /// heartbeated within [`OWNERSHIP_LIVENESS_SECS`] -- an edge that died (or was
    /// decommissioned) without its stale `mesh_edges` row being pruned yet must not keep
    /// resolving as a live owner, or mesh-relay/promotion traffic black-holes against its
    /// dead `peer_addr` until someone notices and prunes manually.
    pub fn lookup_by_token(&self, token: &str) -> rusqlite::Result<Option<(String, String)>> {
        self.conn
            .lock_safe()
            .query_row(
                "SELECT e.id, e.peer_addr FROM mesh_ownership o
                 JOIN mesh_edges e ON e.id = o.edge_id
                 WHERE o.token = ?1 AND e.last_seen >= ?2",
                params![token, now_secs() - OWNERSHIP_LIVENESS_SECS],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
    }

    /// Whether `token` is the recorded owner of exactly `hostname` — the
    /// authorization check the ACME DNS-01 endpoint gates on (#153 follow-up):
    /// an agent proves it may claim `_acme-challenge.<hostname>` by presenting
    /// the routing token this registry already knows is bound to that
    /// hostname, so no separate credential/allowlist is needed.
    pub fn token_owns_hostname(&self, token: &str, hostname: &str) -> rusqlite::Result<bool> {
        self.conn
            .lock_safe()
            .query_row(
                "SELECT 1 FROM mesh_ownership WHERE token = ?1 AND hostname = ?2",
                params![token, hostname],
                |_| Ok(()),
            )
            .optional()
            .map(|r| r.is_some())
    }

    /// Which edge (id, peer_addr) owns `hostname`, if any. #285: same liveness gate as
    /// [`Self::lookup_by_token`] -- see its doc comment.
    pub fn lookup_by_host(&self, hostname: &str) -> rusqlite::Result<Option<(String, String)>> {
        self.conn
            .lock_safe()
            .query_row(
                "SELECT e.id, e.peer_addr FROM mesh_ownership o
                 JOIN mesh_edges e ON e.id = o.edge_id
                 WHERE o.hostname = ?1 AND e.last_seen >= ?2",
                params![hostname, now_secs() - OWNERSHIP_LIVENESS_SECS],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
    }

    /// Every (token, hostname) pair currently assigned to `edge_id` — what a
    /// booting edge replays into its local `host_auth`/`hosts` maps so a
    /// restart no longer silently forgets every authorization.
    pub fn owned_by(&self, edge_id: &str) -> rusqlite::Result<Vec<(String, Option<String>)>> {
        let conn = self.conn.lock_safe();
        let mut stmt = conn.prepare("SELECT token, hostname FROM mesh_ownership WHERE edge_id = ?1")?;
        let rows = stmt
            .query_map(params![edge_id], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect();
        rows
    }

    /// Forget `token`'s ownership record — a tunnel revoke/delete, so a stale row
    /// doesn't keep claiming an edge still owns a token nobody authorized anymore.
    pub fn remove_ownership(&self, token: &str) -> rusqlite::Result<()> {
        self.conn
            .lock_safe()
            .execute("DELETE FROM mesh_ownership WHERE token = ?1", params![token])?;
        Ok(())
    }
}

/// Shared handle the two ownership-recording hook points use (portal_api.rs's tunnel
/// creation flow, service.rs's `/registry/authorize-host` proxy) to record which edge
/// now owns a freshly-authorized (token, hostname) pair. Best-effort: a registry write
/// failure is logged, never surfaces to the caller — the tunnel/authorization itself
/// already succeeded and must not fail because of this bookkeeping.
#[derive(Clone)]
pub struct EdgeMeshHandle {
    store: Arc<SqliteEdgeMesh>,
    local_edge_id: Arc<str>,
}

impl EdgeMeshHandle {
    pub fn new(store: Arc<SqliteEdgeMesh>, local_edge_id: Arc<str>) -> Self {
        Self { store, local_edge_id }
    }

    /// Record that this deployment's local edge now owns `token` (and `host`, if any).
    pub fn record(&self, token: &str, host: Option<&str>) {
        if let Err(e) = self.store.record_ownership(token, host, &self.local_edge_id, now_secs()) {
            eprintln!("ct-cp: edge_mesh record_ownership failed: {e}");
        }
    }

    /// Forget `token`'s ownership record (a tunnel revoke/delete).
    pub fn forget(&self, token: &str) {
        if let Err(e) = self.store.remove_ownership(token) {
            eprintln!("ct-cp: edge_mesh remove_ownership failed: {e}");
        }
    }

    /// Look up which edge (if any) owns `host`, straight through to the
    /// underlying registry -- used by the Rot->Gelb synchronous promotion
    /// (`acme_broker::try_promote_rot_to_gelb`) to confirm the edge already
    /// knows about a hostname before promoting it.
    pub fn lookup_by_host(&self, host: &str) -> rusqlite::Result<Option<(String, String)>> {
        self.store.lookup_by_host(host)
    }
}

#[derive(Deserialize)]
struct HeartbeatBody {
    id: String,
    peer_addr: String,
}

#[derive(Deserialize)]
struct LookupQuery {
    token: Option<String>,
    host: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct OwnerResp {
    edge_id: String,
    peer_addr: String,
}

#[derive(Serialize, Deserialize)]
struct OwnedPair {
    token: String,
    hostname: Option<String>,
}

#[derive(Clone)]
struct MeshState {
    store: Arc<SqliteEdgeMesh>,
    admin_token: Option<[u8; 32]>,
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

async fn heartbeat(
    State(st): State<MeshState>,
    headers: HeaderMap,
    Json(body): Json<HeartbeatBody>,
) -> Result<StatusCode, (StatusCode, String)> {
    crate::service::require_admin(&headers, &st.admin_token, "edge heartbeat requires the admin token")?;
    st.store
        .heartbeat(&body.id, &body.peer_addr, now_secs())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

async fn lookup(
    State(st): State<MeshState>,
    headers: HeaderMap,
    Query(q): Query<LookupQuery>,
) -> Result<Json<OwnerResp>, (StatusCode, String)> {
    crate::service::require_admin(&headers, &st.admin_token, "mesh lookup requires the admin token")?;
    let found = if let Some(t) = q.token.as_deref() {
        st.store.lookup_by_token(t)
    } else if let Some(h) = q.host.as_deref() {
        st.store.lookup_by_host(h)
    } else {
        return Err((StatusCode::BAD_REQUEST, "token or host required".to_string()));
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    match found {
        Some((edge_id, peer_addr)) => Ok(Json(OwnerResp { edge_id, peer_addr })),
        None => Err((StatusCode::NOT_FOUND, "no owner recorded".to_string())),
    }
}

async fn rehydrate(
    State(st): State<MeshState>,
    headers: HeaderMap,
    Path(edge_id): Path<String>,
) -> Result<Json<Vec<OwnedPair>>, (StatusCode, String)> {
    crate::service::require_admin(&headers, &st.admin_token, "rehydration requires the admin token")?;
    let pairs = st
        .store
        .owned_by(&edge_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .into_iter()
        .map(|(token, hostname)| OwnedPair { token, hostname })
        .collect();
    Ok(Json(pairs))
}

/// Build the edge-mesh router: `POST /internal/edges/heartbeat`,
/// `GET /internal/edges/lookup?token=|host=`, `GET /internal/edges/rehydrate/:edge_id`.
/// Gated by the same shared admin token as every other admin-facing writer
/// here (`#186`'s one extract-and-compare) — `None` disables the gate (dev/test).
pub fn edge_mesh_router(store: Arc<SqliteEdgeMesh>, admin_token: Option<[u8; 32]>) -> Router {
    Router::new()
        .route("/internal/edges/heartbeat", post(heartbeat))
        .route("/internal/edges/lookup", get(lookup))
        .route("/internal/edges/rehydrate/:edge_id", get(rehydrate))
        .with_state(MeshState { store, admin_token })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    fn store() -> Arc<SqliteEdgeMesh> {
        Arc::new(SqliteEdgeMesh::open_in_memory().unwrap())
    }

    #[test]
    fn assign_edge_defaults_when_nothing_has_heartbeated() {
        let s = store();
        assert_eq!(s.assign_edge("edge-1", now_secs() - 60).unwrap(), "edge-1");
    }

    #[test]
    fn assign_edge_balances_across_live_edges_by_current_load() {
        let s = store();
        let now = now_secs();
        s.heartbeat("edge-1", "10.0.0.1:4437", now).unwrap();
        s.heartbeat("edge-2", "10.0.0.2:4437", now).unwrap();
        // edge-1 already has 3 tunnels, edge-2 has 0 -> new ones go to edge-2.
        for i in 0..3 {
            s.record_ownership(&format!("tok{i}"), None, "edge-1", now).unwrap();
        }
        assert_eq!(s.assign_edge("edge-1", now - 60).unwrap(), "edge-2");
    }

    #[test]
    fn assign_edge_ignores_stale_edges() {
        let s = store();
        let now = now_secs();
        s.heartbeat("edge-1", "10.0.0.1:4437", now - 600).unwrap(); // stale
        assert_eq!(s.assign_edge("edge-1", now - 60).unwrap(), "edge-1", "falls back to default, not the stale edge");
    }

    #[test]
    fn prune_stale_edges_removes_only_rows_older_than_the_cutoff_290() {
        let s = store();
        let now = now_secs();
        s.heartbeat("edge-live", "10.0.0.1:4437", now).unwrap();
        s.heartbeat("edge-decommissioned", "10.0.0.2:4437", now - 1_000).unwrap();

        assert_eq!(s.prune_stale_edges(now - 500).unwrap(), 1, "exactly the decommissioned row is pruned");
        assert_eq!(s.live_edges(now - 60).unwrap(), vec!["edge-live".to_string()], "the live edge survives");

        // A pruned edge that heartbeats again just re-inserts, same as brand-new.
        s.heartbeat("edge-decommissioned", "10.0.0.2:4438", now).unwrap();
        assert_eq!(
            s.live_edges(now - 60).unwrap(),
            vec!["edge-decommissioned".to_string(), "edge-live".to_string()]
        );

        // A second prune with the same cutoff finds nothing new to remove.
        assert_eq!(s.prune_stale_edges(now - 500).unwrap(), 0);
    }

    #[test]
    fn record_and_lookup_ownership_by_token_and_host() {
        let s = store();
        let now = now_secs();
        s.heartbeat("edge-1", "10.0.0.1:4437", now).unwrap();
        s.record_ownership("deadbeef", Some("app.example.com"), "edge-1", now).unwrap();

        let by_token = s.lookup_by_token("deadbeef").unwrap().expect("found by token");
        assert_eq!(by_token, ("edge-1".to_string(), "10.0.0.1:4437".to_string()));

        let by_host = s.lookup_by_host("app.example.com").unwrap().expect("found by host");
        assert_eq!(by_host, ("edge-1".to_string(), "10.0.0.1:4437".to_string()));

        assert!(s.lookup_by_token("unknown").unwrap().is_none());
        assert!(s.lookup_by_host("unknown.example.com").unwrap().is_none());
    }

    #[test]
    fn lookup_by_token_and_host_stop_resolving_a_dead_edges_stale_ownership_row_285() {
        let s = store();
        let now = now_secs();
        s.heartbeat("edge-1", "10.0.0.1:4437", now).unwrap();
        s.record_ownership("deadbeef", Some("app.example.com"), "edge-1", now).unwrap();

        // Fresh heartbeat -> still resolves normally.
        assert!(s.lookup_by_token("deadbeef").unwrap().is_some());
        assert!(s.lookup_by_host("app.example.com").unwrap().is_some());

        // edge-1 dies without its mesh_edges row being pruned: its last heartbeat ages
        // past OWNERSHIP_LIVENESS_SECS, but mesh_ownership still points at it.
        s.heartbeat("edge-1", "10.0.0.1:4437", now - OWNERSHIP_LIVENESS_SECS - 1).unwrap();

        assert!(
            s.lookup_by_token("deadbeef").unwrap().is_none(),
            "a dead edge's stale ownership row must not keep resolving as a live owner"
        );
        assert!(
            s.lookup_by_host("app.example.com").unwrap().is_none(),
            "same liveness gate applies to host lookups"
        );

        // Once edge-1 heartbeats again (comes back, or a replacement reuses its id), the
        // same ownership row resolves again -- this isn't a permanent black hole.
        s.heartbeat("edge-1", "10.0.0.1:4437", now).unwrap();
        assert!(s.lookup_by_token("deadbeef").unwrap().is_some());
    }

    #[test]
    fn token_owns_hostname_matches_only_the_exact_recorded_pair() {
        let s = store();
        let now = now_secs();
        s.record_ownership("deadbeef", Some("app.example.com"), "edge-1", now).unwrap();
        s.record_ownership("cafef00d", Some("other.example.com"), "edge-1", now).unwrap();

        assert!(s.token_owns_hostname("deadbeef", "app.example.com").unwrap());
        assert!(!s.token_owns_hostname("deadbeef", "other.example.com").unwrap(), "wrong hostname for this token");
        assert!(!s.token_owns_hostname("cafef00d", "app.example.com").unwrap(), "wrong token for this hostname");
        assert!(!s.token_owns_hostname("unknown", "app.example.com").unwrap(), "unknown token");
    }

    #[test]
    fn record_ownership_is_idempotent_reassignment() {
        // A tunnel re-authorized (or moved to a different edge) just overwrites
        // its row rather than erroring or duplicating.
        let s = store();
        let now = now_secs();
        s.heartbeat("edge-1", "10.0.0.1:4437", now).unwrap();
        s.heartbeat("edge-2", "10.0.0.2:4437", now).unwrap();
        s.record_ownership("tok", Some("app.example.com"), "edge-1", now).unwrap();
        s.record_ownership("tok", Some("app.example.com"), "edge-2", now + 1).unwrap();
        let (edge_id, peer_addr) = s.lookup_by_token("tok").unwrap().unwrap();
        assert_eq!(edge_id, "edge-2");
        assert_eq!(peer_addr, "10.0.0.2:4437");
    }

    #[test]
    fn owned_by_lists_exactly_that_edges_pairs_for_rehydration() {
        let s = store();
        let now = now_secs();
        s.record_ownership("tok-a", Some("a.example.com"), "edge-1", now).unwrap();
        s.record_ownership("tok-b", None, "edge-1", now).unwrap();
        s.record_ownership("tok-c", Some("c.example.com"), "edge-2", now).unwrap();

        let mut owned = s.owned_by("edge-1").unwrap();
        owned.sort();
        assert_eq!(
            owned,
            vec![
                ("tok-a".to_string(), Some("a.example.com".to_string())),
                ("tok-b".to_string(), None),
            ]
        );
        assert_eq!(s.owned_by("edge-2").unwrap(), vec![("tok-c".to_string(), Some("c.example.com".to_string()))]);
        assert!(s.owned_by("edge-3-never-seen").unwrap().is_empty());
    }

    #[test]
    fn remove_ownership_drops_the_row_and_is_a_no_op_on_an_unknown_token() {
        let s = store();
        let now = now_secs();
        s.heartbeat("edge-1", "10.0.0.1:4437", now).unwrap();
        s.record_ownership("tok", Some("app.example.com"), "edge-1", now).unwrap();
        assert!(s.lookup_by_token("tok").unwrap().is_some());
        s.remove_ownership("tok").unwrap();
        assert!(s.lookup_by_token("tok").unwrap().is_none(), "removed");
        s.remove_ownership("never-existed").unwrap(); // no-op, not an error
    }

    #[test]
    fn edge_mesh_handle_records_under_its_configured_local_edge_id_and_forgets_on_revoke() {
        let s = store();
        s.heartbeat("primary", "10.0.0.1:4437", now_secs()).unwrap();
        let handle = EdgeMeshHandle::new(s.clone(), Arc::from("primary"));

        handle.record("tok-a", Some("a.example.com"));
        let (edge_id, _) = s.lookup_by_token("tok-a").unwrap().expect("recorded under the local edge id");
        assert_eq!(edge_id, "primary");
        assert_eq!(
            s.lookup_by_host("a.example.com").unwrap().map(|(id, _)| id),
            Some("primary".to_string()),
            "hostname lookup resolves too"
        );

        // A token authorized with no hostname (Mesh-Plane only) records fine with hostname = None.
        handle.record("tok-b", None);
        assert!(s.lookup_by_token("tok-b").unwrap().is_some());

        handle.forget("tok-a");
        assert!(s.lookup_by_token("tok-a").unwrap().is_none(), "forgotten on revoke");
        assert!(s.lookup_by_token("tok-b").unwrap().is_some(), "unrelated token untouched");
    }

    fn test_router(admin_token: Option<[u8; 32]>) -> (Router, Arc<SqliteEdgeMesh>) {
        let store = store();
        (edge_mesh_router(store.clone(), admin_token), store)
    }

    fn hex32(b: &[u8; 32]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[tokio::test]
    async fn heartbeat_endpoint_requires_the_admin_token_when_configured() {
        let (app, _store) = test_router(Some([7u8; 32]));
        let resp = app
            .oneshot(
                Request::post("/internal/edges/heartbeat")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"id":"edge-1","peer_addr":"10.0.0.1:4437"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "no token presented -> refused");
    }

    #[tokio::test]
    async fn heartbeat_endpoint_records_a_live_edge() {
        let (app, store) = test_router(Some([7u8; 32]));
        let resp = app
            .oneshot(
                Request::post("/internal/edges/heartbeat")
                    .header("content-type", "application/json")
                    .header("x-ct-admin-token", hex32(&[7u8; 32]))
                    .body(Body::from(r#"{"id":"edge-1","peer_addr":"10.0.0.1:4437"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(store.live_edges(now_secs() - 5).unwrap(), vec!["edge-1".to_string()]);
    }

    #[tokio::test]
    async fn lookup_endpoint_returns_404_for_an_unknown_token_and_200_for_a_known_one() {
        let (app, store) = test_router(None);
        store.record_ownership("deadbeef", None, "edge-1", now_secs()).unwrap();
        store.heartbeat("edge-1", "10.0.0.1:4437", now_secs()).unwrap();

        let resp = app
            .clone()
            .oneshot(Request::get("/internal/edges/lookup?token=deadbeef").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let owner: OwnerResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(owner.edge_id, "edge-1");
        assert_eq!(owner.peer_addr, "10.0.0.1:4437");

        let miss = app
            .oneshot(Request::get("/internal/edges/lookup?token=unknown").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(miss.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn rehydrate_endpoint_returns_exactly_that_edges_pairs() {
        let (app, store) = test_router(None);
        store.record_ownership("tok-a", Some("a.example.com"), "edge-1", now_secs()).unwrap();
        store.record_ownership("tok-b", Some("b.example.com"), "edge-2", now_secs()).unwrap();

        let resp = app
            .oneshot(Request::get("/internal/edges/rehydrate/edge-1").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let pairs: Vec<OwnedPair> = serde_json::from_slice(&body).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].token, "tok-a");
        assert_eq!(pairs[0].hostname.as_deref(), Some("a.example.com"));
    }
}
