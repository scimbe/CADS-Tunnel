//! Admin audit log (ADR-0025 Decision 6): an immutable record of every
//! privileged admin action — actor, action, target, and any extra detail —
//! matching this codebase's own established "operator must be able to see
//! everything" convention (#127-style loud logging) applied to the admin
//! surface itself. A privileged console with no record of who did what is a
//! real gap in a system whose whole premise is auditable trust.
//!
//! Self-contained (owns its own `admin_audit_log` table), the same shape as
//! `crates/edge/src/audit_log.rs`'s precedent for a narrow, single-purpose
//! audit store. Unlike that crate, this lives in the SAME crate as
//! `storage.rs`, so there is no cross-crate reason to duplicate its WAL/
//! busy-timeout tuning — [`record`](SqliteAuditLog::record) below reuses
//! `storage::open_tuned`/`sqlite_store_ctors!` directly.
//!
//! A logging failure must never block the actual admin action that triggered
//! it — same convention as `portal_api::authorize_hostname`'s edge-authorize
//! call (best-effort, loudly logged, never fails the caller's request).
//! [`SqliteAuditLog::record`] still returns a `Result` so a caller *can*
//! inspect it, but every call site should treat an `Err` as diagnostic only
//! (it is already `eprintln!`'d here) and never `?`-propagate it into failing
//! the privileged action itself.

use std::sync::Mutex;

use ct_common::sync::MutexExt;
use rusqlite::{params, Connection};

use crate::storage::{open_tuned, sqlite_store_ctors};

/// One row of `admin_audit_log`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLogEntry {
    pub id: i64,
    pub actor_email: String,
    pub action: String,
    pub target: Option<String>,
    pub detail: Option<String>,
    pub at: i64,
}

pub struct SqliteAuditLog {
    conn: Mutex<Connection>,
}

sqlite_store_ctors!(SqliteAuditLog);

impl SqliteAuditLog {
    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS admin_audit_log (
                 id          INTEGER PRIMARY KEY AUTOINCREMENT,
                 actor_email TEXT NOT NULL,
                 action      TEXT NOT NULL,
                 target      TEXT,
                 detail      TEXT,
                 at          INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_admin_audit_log_at ON admin_audit_log (at);
             CREATE INDEX IF NOT EXISTS idx_admin_audit_log_actor ON admin_audit_log (actor_email);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Record one privileged admin action. Every future privileged handler
    /// (credit grant, block/delete account, domain disable, admin add/remove,
    /// domain onboarding) calls this. Best-effort (see module doc): on a DB
    /// error this logs loudly to stderr and returns `Err`, but the caller must
    /// treat that as diagnostic only, never as a reason to undo or refuse the
    /// real action already performed.
    pub fn record(
        &self,
        actor_email: &str,
        action: &str,
        target: Option<&str>,
        detail: Option<&str>,
    ) -> rusqlite::Result<()> {
        let at = now_secs();
        let res = self.conn.lock_safe().execute(
            "INSERT INTO admin_audit_log (actor_email, action, target, detail, at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![actor_email.to_ascii_lowercase(), action, target, detail, at],
        );
        if let Err(e) = &res {
            eprintln!(
                "ct-cp: admin_audit_log record FAILED (actor={actor_email} action={action} \
                 target={target:?}): {e} -- the admin action itself was NOT blocked by this"
            );
        }
        res.map(|_| ())
    }

    /// The `limit` most recent entries, newest first — the admin-console UI's
    /// (later phase) data source.
    pub fn recent(&self, limit: u32) -> rusqlite::Result<Vec<AuditLogEntry>> {
        let conn = self.conn.lock_safe();
        let mut stmt = conn.prepare(
            "SELECT id, actor_email, action, target, detail, at
             FROM admin_audit_log ORDER BY at DESC, id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit], |r| {
                Ok(AuditLogEntry {
                    id: r.get(0)?,
                    actor_email: r.get(1)?,
                    action: r.get(2)?,
                    target: r.get(3)?,
                    detail: r.get(4)?,
                    at: r.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> SqliteAuditLog {
        SqliteAuditLog::open_in_memory().unwrap()
    }

    #[test]
    fn record_then_recent_round_trips_every_field() {
        let log = store();
        log.record("admin@example.com", "credit_grant", Some("acct-123"), Some("+500 credits"))
            .unwrap();
        let rows = log.recent(10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].actor_email, "admin@example.com");
        assert_eq!(rows[0].action, "credit_grant");
        assert_eq!(rows[0].target.as_deref(), Some("acct-123"));
        assert_eq!(rows[0].detail.as_deref(), Some("+500 credits"));
    }

    #[test]
    fn actor_email_is_stored_lowercased_matching_the_rest_of_this_crates_email_columns() {
        let log = store();
        log.record("Admin@Example.com", "domain_disable", Some("bunsenbrenner.org"), None)
            .unwrap();
        assert_eq!(log.recent(1).unwrap()[0].actor_email, "admin@example.com");
    }

    #[test]
    fn recent_returns_newest_first_and_respects_the_limit() {
        let log = store();
        for i in 0..5 {
            log.record("admin@example.com", "action", Some(&i.to_string()), None).unwrap();
        }
        let rows = log.recent(2).unwrap();
        assert_eq!(rows.len(), 2, "limit is honored");
        assert_eq!(rows[0].target.as_deref(), Some("4"), "newest first");
        assert_eq!(rows[1].target.as_deref(), Some("3"));
    }

    #[test]
    fn target_and_detail_are_optional() {
        let log = store();
        log.record("admin@example.com", "some_action", None, None).unwrap();
        let rows = log.recent(1).unwrap();
        assert_eq!(rows[0].target, None);
        assert_eq!(rows[0].detail, None);
    }
}
