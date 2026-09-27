//! Retention (#775 item 2): `SqliteEnrollment::prune_redeemed_join_tokens`,
//! `SqliteEnrollment::prune_batch_issuance`, `SqliteBootstrap::prune`, and
//! `SqliteEdgeMesh::prune_stale_edges` each already existed with a real, tested
//! implementation -- but nothing ever called them outside their own tests. Every one
//! of those tables grows forever in a real long-running deployment. This module wires
//! them into an hourly background sweep, spawned from `main.rs` the same way #777's
//! `alerts::run_alert_loop` already is (same `shutdown_fired` watch channel, same
//! `tokio::time::interval` + `MissedTickBehavior::Skip` shape) so a SIGTERM stops this
//! loop too instead of leaving a sweep running past the shutdown grace period.
//!
//! Second increment: `acme_issuance_log` and `channel_claim_invites` age-out, an
//! opt-in `admin_audit_log` window, and a daily WAL checkpoint + `PRAGMA optimize`.
//! `token_issuances` is deliberately NOT pruned: each row is the record of a paid
//! Routing Token (account, price, time) and falls under bookkeeping retention.

use std::sync::Arc;
use std::time::Duration;

use rusqlite::Connection;

use crate::audit_log::SqliteAuditLog;
use crate::edge_mesh::SqliteEdgeMesh;
use crate::storage::{SqliteBootstrap, SqliteChannelStore, SqliteEnrollment, SqliteTunnelStore};

/// How often the sweep runs. None of the pruned rows are time-critical to remove
/// promptly -- worst case between ticks is a bounded amount of dead-row bloat -- so
/// this stays well below #777's per-minute alert loop's frequency.
const RETENTION_TICK: Duration = Duration::from_secs(3600);

/// Every this many ticks (daily at the hourly tick) the loop also truncates the WAL
/// and runs `PRAGMA optimize`.
const MAINTENANCE_EVERY_TICKS: u64 = 24;

/// `batch_issuance` rows older than this are pruned. Per
/// [`SqliteEnrollment::prune_batch_issuance`]'s own doc comment, this should
/// comfortably exceed any realistic retry window for the idempotency key it guards.
const BATCH_ISSUANCE_MAX_AGE_SECS: u64 = 24 * 3600;

/// `mesh_edges` rows not heartbeated since this far back are pruned. Deliberately far
/// wider than [`SqliteEdgeMesh`]'s own 120s liveness window used for *ownership
/// resolution* (`OWNERSHIP_LIVENESS_SECS`) -- that window decides whether a live edge
/// is preferred for new assignments; this one decides whether an edge is gone for
/// good. A week comfortably outlasts any real redeploy or maintenance window.
const EDGE_STALE_MAX_AGE_SECS: i64 = 7 * 24 * 3600;

/// `acme_issuance_log` rows older than this are pruned. Must stay wider than both
/// windows that read the table; the const assertion below enforces it.
const ACME_ISSUANCE_LOG_MAX_AGE_SECS: i64 = 30 * 24 * 3600;
const _: () = assert!(
    ACME_ISSUANCE_LOG_MAX_AGE_SECS > crate::acme_broker::BUDGET_WINDOW_SECS
        && ACME_ISSUANCE_LOG_MAX_AGE_SECS > crate::storage::MIN_ISSUANCE_LOG_INTERVAL_SECS
);

/// Claim invites consumed or expired longer ago than this are pruned. Until then a
/// reused link still answers "already used"/"expired" instead of "unknown".
const CLAIM_INVITE_GRACE_SECS: u64 = 30 * 24 * 3600;

/// Opt-in retention window for `admin_audit_log`, in days. Unset, empty, `0` or
/// unparsable means keep forever.
const ADMIN_AUDIT_RETENTION_ENV: &str = "CT_CP_ADMIN_AUDIT_RETENTION_DAYS";

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn parse_admin_audit_retention(raw: Option<&str>) -> Option<u64> {
    let days: u64 = raw?.trim().parse().ok()?;
    (days > 0).then(|| days.saturating_mul(24 * 3600))
}

/// What [`run_retention_loop`] needs from `main.rs`.
pub struct RetentionLoopConfig {
    /// The control-plane SQLite path; the loop opens its own handle on each of the
    /// stores it prunes, same as every other background loop shares that one file.
    pub db_path: String,
}

/// The stores one sweep touches.
pub(crate) struct RetentionStores {
    pub enrollment: SqliteEnrollment,
    pub bootstrap: SqliteBootstrap,
    pub edge_mesh: SqliteEdgeMesh,
    pub tunnels: SqliteTunnelStore,
    pub channels: SqliteChannelStore,
    pub audit_log: SqliteAuditLog,
    /// `None` keeps `admin_audit_log` forever.
    pub admin_audit_max_age_secs: Option<u64>,
}

impl RetentionStores {
    fn open(db_path: &str) -> Result<Self, String> {
        fn ctx<T>(what: &str, r: rusqlite::Result<T>) -> Result<T, String> {
            r.map_err(|e| format!("cannot open the {what} store: {e}"))
        }
        Ok(Self {
            enrollment: ctx("enrollment", SqliteEnrollment::open(db_path))?,
            bootstrap: ctx("bootstrap", SqliteBootstrap::open(db_path))?,
            edge_mesh: ctx("edge-mesh", SqliteEdgeMesh::open(db_path))?,
            tunnels: ctx("tunnel", SqliteTunnelStore::open(db_path))?,
            channels: ctx("channel", SqliteChannelStore::open(db_path))?,
            audit_log: ctx("admin audit log", SqliteAuditLog::open(db_path))?,
            admin_audit_max_age_secs: parse_admin_audit_retention(
                std::env::var(ADMIN_AUDIT_RETENTION_ENV).ok().as_deref(),
            ),
        })
    }

    #[cfg(test)]
    fn open_in_memory(admin_audit_max_age_secs: Option<u64>) -> Self {
        Self {
            enrollment: SqliteEnrollment::open_in_memory().unwrap(),
            bootstrap: SqliteBootstrap::open_in_memory().unwrap(),
            edge_mesh: SqliteEdgeMesh::open_in_memory().unwrap(),
            tunnels: SqliteTunnelStore::open_in_memory().unwrap(),
            channels: SqliteChannelStore::open_in_memory().unwrap(),
            audit_log: SqliteAuditLog::open_in_memory().unwrap(),
            admin_audit_max_age_secs,
        }
    }
}

/// Run the retention loop until `shutdown` turns `true` (or its sender goes away).
/// Spawned once from `main.rs`; every tick is [`tick`].
pub async fn run_retention_loop(cfg: RetentionLoopConfig, shutdown: tokio::sync::watch::Receiver<bool>) {
    let stores = match RetentionStores::open(&cfg.db_path) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("ct-cp: retention: {e}, retention disabled");
            return;
        }
    };
    match stores.admin_audit_max_age_secs {
        Some(secs) => eprintln!("ct-cp: retention: admin_audit_log window {} day(s)", secs / 86_400),
        None => eprintln!("ct-cp: retention: admin_audit_log kept forever ({ADMIN_AUDIT_RETENTION_ENV} unset)"),
    }
    run_retention_loop_with(stores, Some(cfg.db_path), shutdown, RETENTION_TICK).await;
}

/// [`run_retention_loop`] with injectable stores/period (tests). `MissedTickBehavior::
/// Skip`: a tick that overran does not burst-catch-up; it just waits for the next
/// period boundary -- matching [`crate::alerts::run_alert_loop_with`]'s own rationale.
pub(crate) async fn run_retention_loop_with(
    stores: Arc<RetentionStores>,
    db_path: Option<String>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    period: Duration,
) {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut ticks: u64 = 0;
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _ = interval.tick() => {
                tick(&stores, unix_now());
                ticks += 1;
                if ticks % MAINTENANCE_EVERY_TICKS == 0 {
                    if let Some(path) = &db_path {
                        maintain_db(path);
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() {
                    break;
                }
            }
        }
    }
    eprintln!("ct-cp: retention: loop stopped (shutdown)");
}

fn log_pruned(what: &str, r: rusqlite::Result<usize>) {
    match r {
        Ok(n) if n > 0 => eprintln!("ct-cp: retention: pruned {n} {what} row(s) (#775)"),
        Ok(_) => {}
        Err(e) => eprintln!("ct-cp: retention: pruning {what} failed: {e}"),
    }
}

/// One sweep pass: prunes each retention-managed table and logs how many rows each
/// removed (`#775` -- visibility into a sweep that otherwise runs silently forever).
fn tick(s: &RetentionStores, now: u64) {
    log_pruned("join_tokens", s.enrollment.prune_redeemed_join_tokens(now));
    log_pruned(
        "batch_issuance",
        s.enrollment.prune_batch_issuance(now, BATCH_ISSUANCE_MAX_AGE_SECS),
    );
    log_pruned("bootstrap_tokens", s.bootstrap.prune(now));
    let now_i = now as i64;
    log_pruned(
        "mesh_edges",
        s.edge_mesh.prune_stale_edges(now_i.saturating_sub(EDGE_STALE_MAX_AGE_SECS)),
    );
    log_pruned(
        "acme_issuance_log",
        s.tunnels
            .prune_acme_issuance_log(now_i.saturating_sub(ACME_ISSUANCE_LOG_MAX_AGE_SECS)),
    );
    log_pruned(
        "channel_claim_invites",
        s.channels.prune_claim_invites(now.saturating_sub(CLAIM_INVITE_GRACE_SECS)),
    );
    if let Some(max_age) = s.admin_audit_max_age_secs {
        log_pruned(
            "admin_audit_log",
            s.audit_log.prune_older_than(now.saturating_sub(max_age) as i64),
        );
    }
}

/// Daily housekeeping on its own short-lived connection: fold the WAL back into the
/// main file (so the `-wal` sidecar does not grow without bound under constant readers)
/// and let SQLite refresh its planner statistics.
fn maintain_db(path: &str) {
    let result = Connection::open(path).and_then(|conn| {
        conn.busy_timeout(Duration::from_secs(5))?;
        let (busy, log, checkpointed): (i64, i64, i64) =
            conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        conn.execute_batch("PRAGMA optimize;")?;
        Ok((busy, log, checkpointed))
    });
    match result {
        Ok((0, _, _)) => {}
        Ok((_, log, done)) => eprintln!(
            "ct-cp: retention: WAL checkpoint partially blocked by readers ({done}/{log} frames), retried tomorrow"
        ),
        Err(e) => eprintln!("ct-cp: retention: WAL checkpoint/optimize failed: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_prunes_all_four_dead_retention_tables_775() {
        use ct_common::{AgentId, TenantId};

        let s = RetentionStores::open_in_memory(None);
        let now = 1_000_000u64;

        // join_tokens: a redeemed row is prune-eligible regardless of age.
        let tenant = TenantId("t1".into());
        let token = s.enrollment.issue_join_token(&tenant, now).unwrap();
        s.enrollment.redeem(&token, &AgentId("a1".into()), [7u8; 32], now).unwrap();
        assert_eq!(s.enrollment.agent_count().unwrap(), 1, "redeeming still binds the agent");

        // batch_issuance: mint a batch at a `now` old enough to already be stale relative
        // to the sweep's `now` below.
        let stale_batch_now = now - BATCH_ISSUANCE_MAX_AGE_SECS - 10;
        s.enrollment
            .issue_join_tokens_idempotent(&tenant, 1, "stale-key", stale_batch_now)
            .unwrap();

        // bootstrap_tokens: mint one, then redeem it so it's prune-eligible.
        let bt = s.bootstrap.mint("secret", 60, now).unwrap();
        let _ = s.bootstrap.redeem(&bt, now);

        // mesh_edges: heartbeat once, far enough in the past to be stale at `now`.
        s.edge_mesh
            .heartbeat("edge-1", "1.2.3.4:1", None, (now as i64) - EDGE_STALE_MAX_AGE_SECS - 10)
            .unwrap();

        tick(&s, now);

        assert_eq!(s.enrollment.agent_count().unwrap(), 1, "prune never touches agent_bindings");
        // The DELETE affected join_tokens/batch_issuance/bootstrap_tokens/mesh_edges only;
        // re-running prune on the same state now removes nothing further (idempotent).
        assert_eq!(s.enrollment.prune_redeemed_join_tokens(now).unwrap(), 0);
        assert_eq!(s.enrollment.prune_batch_issuance(now, BATCH_ISSUANCE_MAX_AGE_SECS).unwrap(), 0);
        assert_eq!(s.bootstrap.prune(now).unwrap(), 0);
        let edge_cutoff = (now as i64).saturating_sub(EDGE_STALE_MAX_AGE_SECS);
        assert_eq!(s.edge_mesh.prune_stale_edges(edge_cutoff).unwrap(), 0);
    }

    #[test]
    fn acme_issuance_log_keeps_rows_inside_the_budget_window_775() {
        let s = RetentionStores::open_in_memory(None);
        let now: i64 = 100_000_000;
        s.tunnels.insert_acme_issuance_log_for_test("gts", "example.com", "old.example.com", now - ACME_ISSUANCE_LOG_MAX_AGE_SECS - 1);
        s.tunnels.insert_acme_issuance_log_for_test("gts", "example.com", "recent.example.com", now - crate::acme_broker::BUDGET_WINDOW_SECS + 60);

        tick(&s, now as u64);

        let (used, _) = s
            .tunnels
            .ca_budget_usage("gts", "example.com", now - crate::acme_broker::BUDGET_WINDOW_SECS)
            .unwrap();
        assert_eq!(used, 1, "the in-window issuance still counts against the CA budget");
        let (all, _) = s.tunnels.ca_budget_usage("gts", "example.com", 0).unwrap();
        assert_eq!(all, 1, "the row past the retention window is gone");
    }

    #[test]
    fn claim_invites_are_pruned_only_after_the_grace_period_775() {
        let s = RetentionStores::open_in_memory(None);
        let now: u64 = 100_000_000;
        s.channels.insert_claim_invite_for_test("long-expired", now - CLAIM_INVITE_GRACE_SECS - 1, None);
        s.channels.insert_claim_invite_for_test("just-expired", now - 60, None);
        s.channels.insert_claim_invite_for_test("long-consumed", now + 600, Some(now - CLAIM_INVITE_GRACE_SECS - 1));
        s.channels.insert_claim_invite_for_test("live", now + 600, None);

        tick(&s, now);

        use crate::storage::ClaimInviteLookup;
        let look = |t: &str| s.channels.claim_invite(t, now).unwrap();
        assert!(matches!(look("long-expired"), ClaimInviteLookup::Unknown));
        assert!(matches!(look("long-consumed"), ClaimInviteLookup::Unknown));
        assert!(matches!(look("just-expired"), ClaimInviteLookup::Expired), "grace period keeps the precise answer");
        assert!(matches!(look("live"), ClaimInviteLookup::Valid(_)));
    }

    #[test]
    fn admin_audit_log_is_kept_unless_a_window_is_configured_775() {
        let now = unix_now();
        let keep = RetentionStores::open_in_memory(None);
        keep.audit_log.record("ops@example.com", "grant_credit", None, None).unwrap();
        tick(&keep, now + 10 * 365 * 86_400);
        assert_eq!(keep.audit_log.recent(10).unwrap().len(), 1, "default keeps the log forever");

        let windowed = RetentionStores::open_in_memory(Some(86_400));
        windowed.audit_log.record("ops@example.com", "grant_credit", None, None).unwrap();
        tick(&windowed, now);
        assert_eq!(windowed.audit_log.recent(10).unwrap().len(), 1, "fresh entry survives");
        tick(&windowed, now + 2 * 86_400);
        assert!(windowed.audit_log.recent(10).unwrap().is_empty(), "entry past the window is pruned");
    }

    #[test]
    fn admin_audit_retention_env_parsing_775() {
        assert_eq!(parse_admin_audit_retention(None), None);
        assert_eq!(parse_admin_audit_retention(Some("")), None);
        assert_eq!(parse_admin_audit_retention(Some("0")), None);
        assert_eq!(parse_admin_audit_retention(Some("abc")), None);
        assert_eq!(parse_admin_audit_retention(Some(" 400 ")), Some(400 * 86_400));
    }

    #[test]
    fn maintain_db_checkpoints_a_file_backed_database_775() {
        let dir = std::env::temp_dir().join(format!("ct-cp-retention-{}-{}", std::process::id(), unix_now()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cp.db");
        let path = path.to_str().unwrap();
        let tunnels = SqliteTunnelStore::open(path).unwrap();
        tunnels.insert_acme_issuance_log_for_test("gts", "example.com", "h.example.com", 1);
        maintain_db(path);
        let wal = std::fs::metadata(format!("{path}-wal")).map(|m| m.len()).unwrap_or(0);
        assert_eq!(wal, 0, "TRUNCATE checkpoint empties the WAL sidecar");
        drop(tunnels);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn loop_stops_when_the_shutdown_signal_fires_775() {
        let stores = Arc::new(RetentionStores::open_in_memory(None));
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(run_retention_loop_with(stores, None, rx, Duration::from_millis(20)));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!handle.is_finished(), "runs until told to stop");
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("stops promptly")
            .unwrap();
    }
}
