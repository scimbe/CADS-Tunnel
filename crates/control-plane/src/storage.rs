//! SQLite-backed persistence (M18.1, productionization).
//!
//! Production requires durable state: the in-memory control-plane services lose
//! everything on restart. This module provides a SQLite-backed enrollment store
//! with the same semantics as [`crate::enrollment::Enrollment`], so it can
//! replace the in-memory version behind the HTTP layer. `rusqlite` with the
//! `bundled` SQLite (no system dependency) is called synchronously behind a
//! `Mutex`; the axum handlers already lock without holding the guard across an
//! `await`, so this fits the existing pattern.
//!
//! The store is deliberately backend-shaped (open / issue / redeem / binding) so
//! a Postgres backend for the hosted deployment can follow behind the same
//! surface.
//!
//! #344/#398: every `Sqlite*` store here still uses that single `Mutex<Connection>`
//! shape *except* [`SqliteTunnelStore`] (#344), [`SqliteAgentDirectory`],
//! [`SqlitePipelineRegistry`], [`SqliteChannelStore`] and [`SqliteTopologyStore`] (#398),
//! which also pool extra read-only connections via `r2d2`/`r2d2_sqlite` (see each store's own
//! struct doc for its specific read/write-contention reasoning). This is a deliberate,
//! per-store judgment call, not a uniform migration: #344 explicitly declined
//! [`SqliteEdgeMesh`] (its hot path is write-heavy, not read-heavy) rather than migrating it
//! just to hit a round number, and #398 re-verified that call plus made the same read/write
//! call-pattern judgment for every other store here. Migrated only where a real, hit,
//! read-heavy hot path justified it: `SqliteEnrollment`, `SqliteServiceAccountStore`,
//! `SqliteBootstrap`, `SqliteRegistry`, `SqliteLedger`, `SqliteNetworkStore` (all below) and
//! `SqliteEdgeMesh` (`edge_mesh.rs`) stay on the plain `Mutex<Connection>` shape -- see #398's
//! closing comment for the honest per-store reasoning on each.

use std::sync::Mutex;

use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};

use crate::accounts::{AccountId, LedgerError};
use crate::enrollment::{AgentPublicKey, EnrollError, JoinToken};
use crate::payment::{PaymentError, PaymentId};
use crate::registry::TunnelInfo;
use ct_common::channel::ChannelId;
use ct_common::{AgentId, RoutingToken, TenantId};
use ct_common::sync::MutexExt;

/// #407: `record_issuance_complete`'s minimum interval, per hostname, before it logs
/// another `acme_issuance_log` row — closes an unbounded-replay CA-budget amplifier (a
/// customer-controlled agent could otherwise flood the shared per-domain budget bucket by
/// re-POSTing "issuance complete" for its own already-gruen hostname). Real renewals are
/// ~60 days apart, so a 24h floor costs nothing legitimate.
const MIN_ISSUANCE_LOG_INTERVAL_SECS: i64 = 24 * 60 * 60;

/// Additive schema migration for in-place self-host upgrades (#44). SQLite's
/// `CREATE TABLE IF NOT EXISTS` never alters an existing table, so a column
/// introduced in a later commit is silently absent from a DB file created by an
/// older binary — the next write then fails with `no column named …` and 500s.
/// This ensures `table` has `column`, adding it via `ALTER TABLE … ADD COLUMN`
/// (which SQLite allows for a NOT NULL column only with a DEFAULT) when missing.
/// Idempotent: a no-op once the column exists, so it is safe on every startup.
///
/// `table`/`column`/`decl` are compile-time constants (never user input), so the
/// `format!` interpolation carries no injection surface.
pub(crate) fn ensure_column(conn: &Connection, table: &str, column: &str, decl: &str) -> rusqlite::Result<()> {
    let present = {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let cols: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<_>>()?;
        cols.iter().any(|c| c == column)
    };
    if !present {
        conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"))?;
    }
    Ok(())
}

/// Open a file-backed SQLite connection tuned for concurrent control-plane
/// writers (#110). Every control-plane store opens the **same** database file
/// through its own `Connection`, and SQLite's default rollback journal takes a
/// whole-file exclusive lock per write: a second connection touching the file
/// gets an immediate `SQLITE_BUSY` error instead of waiting. WAL lets readers
/// run alongside a single writer, and `busy_timeout` makes a contending writer
/// wait-and-retry (up to 5s) rather than failing outright. The `open_in_memory`
/// variants skip this — WAL and file locking are moot for a `:memory:` database.
pub(crate) fn open_tuned(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    tune_connection(&conn)?;
    // #608: `Connection::open` creates the file with the process's default umask
    // (typically 0644, world/group-readable) -- this file holds ledger balances,
    // payment/issuance records, and service-account data, none of which should be
    // readable by another local account on the host. Restricted AFTER
    // `tune_connection` engages WAL mode (not before): SQLite creates the
    // `-wal`/`-shm` sidecar files as part of that PRAGMA, so by this point all
    // three exist to restrict. Best-effort: a failure here doesn't fail `open` --
    // it only tightens a file that is otherwise already fully functional, never
    // blocks startup on it. Same gap+fix as `crates/edge/src/audit_log.rs`'s
    // `open_tuned` (this crate's own doc above notes the WAL tuning is duplicated
    // rather than shared between the two, same reasoning applies here).
    restrict_db_file_permissions(path);
    Ok(conn)
}

/// See [`open_tuned`]'s call site for why. `path`'s `-wal`/`-shm` sidecar files (WAL
/// mode) can hold the same data as the main file (recent, not-yet-checkpointed rows),
/// so all three need the same restriction, not just the main path.
#[cfg(unix)]
fn restrict_db_file_permissions(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    for candidate in [path.to_string(), format!("{path}-wal"), format!("{path}-shm")] {
        if std::path::Path::new(&candidate).exists() {
            let _ = std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600));
        }
    }
}

#[cfg(not(unix))]
fn restrict_db_file_permissions(_path: &str) {}

/// The WAL + busy_timeout tuning itself (#344), factored out of [`open_tuned`]
/// so [`SqliteTunnelStore::open`]'s pooled reader connections (via
/// `r2d2_sqlite::SqliteConnectionManager::with_init`) get the *identical*
/// tuning as the hand-opened `writer` connection above, from one source of
/// truth, instead of a second copy that could drift out of sync.
pub(crate) fn tune_connection(conn: &Connection) -> rusqlite::Result<()> {
    // `PRAGMA journal_mode` returns the resulting mode as a row, so it must be
    // set via `query_row` — `execute`/`pragma_update` reject row-returning
    // statements. The returned value is the mode SQLite actually applied.
    let _mode: String = conn.query_row("PRAGMA journal_mode=WAL;", [], |row| row.get(0))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(())
}

/// A connection for a READ-only [`SqliteTunnelStore`] method (#344; see that
/// struct's doc): either one checked out of its `readers` pool, or —
/// in-memory store / pool exhausted — its single `writer` connection locked
/// directly, same as before this migration. `Deref`s to [`Connection`] so
/// every read method's existing `conn.prepare(...)` / `conn.query_row(...)`
/// call sites work completely unchanged regardless of which variant it holds.
enum ReadConn<'a> {
    Pooled(r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>),
    Direct(std::sync::MutexGuard<'a, Connection>),
}

impl std::ops::Deref for ReadConn<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        match self {
            ReadConn::Pooled(c) => c,
            ReadConn::Direct(c) => c,
        }
    }
}

/// #192: the identical `open` / `open_in_memory` constructor pair that every `Sqlite*` store below
/// repeated verbatim (only each store's own `from_connection` schema differs). `open` uses the tuned
/// WAL connection ([`open_tuned`]); `open_in_memory` a `:memory:` one; both delegate to the store's
/// inherent `from_connection`. Invoked once per store (`sqlite_store_ctors!(SqliteX);`), collapsing 10
/// copy-pasted ctor pairs to one declaration each. `from_connection` (schema + any `ensure_column`
/// migrations) stays hand-written per store — that is the only part that legitimately differs.
macro_rules! sqlite_store_ctors {
    ($name:ident) => {
        impl $name {
            /// Open (creating if needed) a durable store at `path` on a tuned WAL connection.
            pub fn open(path: &str) -> rusqlite::Result<Self> {
                Self::from_connection(open_tuned(path)?)
            }
            /// Open an ephemeral in-memory store (for tests / stateless runs).
            pub fn open_in_memory() -> rusqlite::Result<Self> {
                Self::from_connection(Connection::open_in_memory()?)
            }
        }
    };
}
pub(crate) use sqlite_store_ctors;

/// Why a persisted redemption failed: an enrollment rule or the database.
#[derive(Debug)]
pub enum RedeemError {
    /// The redemption violated an enrollment rule (unknown / already-used token).
    Enroll(EnrollError),
    /// The underlying database operation failed.
    Db(rusqlite::Error),
}

impl std::fmt::Display for RedeemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RedeemError::Enroll(e) => write!(f, "{e}"),
            RedeemError::Db(e) => write!(f, "storage error: {e}"),
        }
    }
}

impl std::error::Error for RedeemError {}

impl From<rusqlite::Error> for RedeemError {
    fn from(e: rusqlite::Error) -> Self {
        RedeemError::Db(e)
    }
}

/// Why an idempotent batch issuance could not be served (#145 idem-conflict).
#[derive(Debug)]
pub enum IssueBatchError {
    /// A retry reused an `idempotency_key` that already names an operation with a
    /// **different** `tenant` or `count`. Rather than silently return the original
    /// (wrong) token set — which, since issuance is one global admin across tenants,
    /// could hand tenant-A's tokens back to a "tenant-B, same key" retry — we refuse.
    /// The caller surfaces this as `409 Conflict`, turning a client key-reuse bug
    /// into a loud error instead of a mis-provisioning footgun.
    Conflict,
    /// The underlying database operation failed.
    Db(rusqlite::Error),
}

impl std::fmt::Display for IssueBatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssueBatchError::Conflict => {
                write!(f, "idempotency_key reused with a different tenant or count")
            }
            IssueBatchError::Db(e) => write!(f, "storage error: {e}"),
        }
    }
}

impl std::error::Error for IssueBatchError {}

impl From<rusqlite::Error> for IssueBatchError {
    fn from(e: rusqlite::Error) -> Self {
        IssueBatchError::Db(e)
    }
}

/// SQLite-backed enrollment store (durable equivalent of [`crate::enrollment::Enrollment`]).
pub struct SqliteEnrollment {
    conn: Mutex<Connection>,
}

sqlite_store_ctors!(SqliteEnrollment);

/// #663: a join token's default lifetime from mint to redemption -- long enough
/// that an operator can generate an install link/QR and hand it to a new
/// device/person without a tight deadline, short enough that a token leaked
/// from a partial/failed install, a backup, or a log line stops being
/// exploitable for tenant-scoped rogue-agent enrollment after a bounded
/// window instead of forever. 7 days, matching common industry practice for
/// enrollment/invite links.
const JOIN_TOKEN_TTL_SECS: u64 = 7 * 24 * 3600;

impl SqliteEnrollment {
    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS join_tokens (
                 token    BLOB PRIMARY KEY,
                 tenant   TEXT NOT NULL,
                 redeemed INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS agent_bindings (
                 agent  TEXT PRIMARY KEY,
                 tenant TEXT NOT NULL,
                 pubkey BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS batch_issuance (
                 idem_key TEXT PRIMARY KEY,
                 tenant   TEXT NOT NULL,
                 tokens   BLOB NOT NULL
             );",
        )?;
        // #292: additive migration (same pattern as #44's `ensure_column`) so an
        // already-deployed store gains the timestamp `prune_batch_issuance` needs.
        // Pre-migration rows default to 0 -- deliberately never pruned by age (we
        // don't know their true age), so they don't vanish in one surprise sweep
        // right after an upgrade; only rows minted from here on age out normally.
        ensure_column(&conn, "batch_issuance", "created_at", "INTEGER NOT NULL DEFAULT 0")?;
        // #663: same additive-migration shape, same grandfather semantics --
        // `expires_at = 0` on an already-deployed row means "minted before this
        // fix existed", and is treated as never-expiring (`redeem`'s own check
        // skips 0 explicitly). This does NOT reopen the vulnerability for new
        // tokens: every `INSERT` from here on (issue_join_token[s][_idempotent])
        // always writes a real, positive `expires_at`. It only avoids silently
        // invalidating tokens an operator already handed out under the old
        // no-expiry contract, which would be a surprise breakage this migration
        // has no business causing.
        ensure_column(&conn, "join_tokens", "expires_at", "INTEGER NOT NULL DEFAULT 0")?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Issue a fresh single-use join token for `tenant`, persisting it. Expires
    /// [`JOIN_TOKEN_TTL_SECS`] after `now` (#663) -- an unredeemed token past
    /// that point is refused (and consumed) by [`Self::redeem`].
    pub fn issue_join_token(&self, tenant: &TenantId, now: u64) -> rusqlite::Result<JoinToken> {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let expires_at = now.saturating_add(JOIN_TOKEN_TTL_SECS);
        self.conn.lock_safe().execute(
            "INSERT INTO join_tokens (token, tenant, redeemed, expires_at) VALUES (?1, ?2, 0, ?3)",
            params![&bytes[..], tenant.0, expires_at as i64],
        )?;
        Ok(JoinToken(bytes))
    }

    /// Issue `count` fresh single-use join tokens for `tenant` in one call (#145 bulk provisioning):
    /// each is independently random + persisted + redeemable **exactly once**, so "provision N agents"
    /// becomes one mint instead of N.
    ///
    /// #465: previously N separate auto-committed statements (`(0..count).map(|_|
    /// self.issue_join_token(tenant))`) -- N lock round-trips and N separate disk
    /// commits for one logical bulk-provisioning operation. Now one transaction,
    /// mirroring `issue_join_tokens_idempotent`'s own mint-loop body (that sibling
    /// already documents at length why the crash-partway window matters). Unlike
    /// the idempotent version this has no operation-identity record to roll back
    /// to, so a mid-loop failure now aborts the whole batch (via the transaction's
    /// own drop-without-commit) rather than leaving a partial, silently-smaller
    /// set persisted for the caller to discover after the fact.
    pub fn issue_join_tokens(
        &self,
        tenant: &TenantId,
        count: usize,
        now: u64,
    ) -> rusqlite::Result<Vec<JoinToken>> {
        let expires_at = now.saturating_add(JOIN_TOKEN_TTL_SECS) as i64;
        let mut guard = self.conn.lock_safe();
        let tx = guard.transaction()?;
        let mut tokens = Vec::with_capacity(count);
        for _ in 0..count {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            tx.execute(
                "INSERT INTO join_tokens (token, tenant, redeemed, expires_at) VALUES (?1, ?2, 0, ?3)",
                params![&bytes[..], tenant.0, expires_at],
            )?;
            tokens.push(JoinToken(bytes));
        }
        tx.commit()?;
        Ok(tokens)
    }

    /// Issue `count` join tokens **idempotently** keyed by `idempotency_key` (#145, Marq's provisioning
    /// contract): the FIRST request with a given key mints + records its token set; any retry with the
    /// SAME key returns that exact set without minting again — so a network-retried batch provision
    /// can't create duplicate identities. The whole check-then-mint runs under one connection lock, so
    /// two concurrent requests with the same key can't both mint (the second sees the record).
    ///
    /// A retry must name the **same operation**: if the key already exists but was
    /// recorded for a different `tenant` or `count`, this returns
    /// [`IssueBatchError::Conflict`] instead of silently replaying the original set
    /// (the stored `tenant` and the recorded token count — `blob.len() / 32` — are the
    /// authoritative operation identity, so no extra column is needed).
    /// #289: the mint loop and the `batch_issuance` idempotency record now run
    /// in one transaction -- previously separate auto-committed statements, so
    /// a crash after minting but before the idem record committed left `count`
    /// live, durable, valid join tokens with no record of the operation. A
    /// retry with the same key then found nothing and minted a SECOND full
    /// set -- exactly the duplicate-identity outcome this idempotency key
    /// exists to prevent. Now either both land or neither does, so a retry
    /// after a crash always replays cleanly instead of re-minting.
    pub fn issue_join_tokens_idempotent(
        &self,
        tenant: &TenantId,
        count: usize,
        idempotency_key: &str,
        now: u64,
    ) -> Result<Vec<JoinToken>, IssueBatchError> {
        let mut guard = self.conn.lock_safe();
        let tx = guard.transaction()?;
        // Replay: return the previously-minted set for this key — but only if the retry
        // names the same operation. We fetch the stored `tenant` alongside the tokens so
        // a key reused with mismatched params fails loudly rather than mis-provisioning.
        let existing: Option<(String, Vec<u8>)> = tx
            .query_row(
                "SELECT tenant, tokens FROM batch_issuance WHERE idem_key = ?1",
                params![idempotency_key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((stored_tenant, blob)) = existing {
            if stored_tenant != tenant.0 || blob.len() != count * 32 {
                return Err(IssueBatchError::Conflict);
            }
            return Ok(blob
                .chunks_exact(32)
                .filter_map(|c| <[u8; 32]>::try_from(c).ok().map(JoinToken))
                .collect());
        }
        // First time: mint `count` tokens, persisting each join token + the idempotency record.
        // #663: same `now` this call already threads through for `batch_issuance.created_at`,
        // reused for `expires_at` too -- no new parameter needed.
        let expires_at = now.saturating_add(JOIN_TOKEN_TTL_SECS) as i64;
        let mut tokens = Vec::with_capacity(count);
        let mut blob = Vec::with_capacity(count * 32);
        for _ in 0..count {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            tx.execute(
                "INSERT INTO join_tokens (token, tenant, redeemed, expires_at) VALUES (?1, ?2, 0, ?3)",
                params![&bytes[..], tenant.0, expires_at],
            )?;
            blob.extend_from_slice(&bytes);
            tokens.push(JoinToken(bytes));
        }
        tx.execute(
            "INSERT INTO batch_issuance (idem_key, tenant, tokens, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![idempotency_key, tenant.0, blob, now as i64],
        )?;
        tx.commit()?;
        Ok(tokens)
    }

    /// Redeem a join token, binding `agent`'s public key to the token's tenant.
    /// Single-use: a second redemption of the same token is rejected, and the
    /// consumption is persisted so it survives a restart. #663: also refused
    /// (as [`EnrollError::Expired`]) once `now` is past the token's `expires_at`
    /// -- an `expires_at` of exactly 0 is a pre-migration legacy row (see
    /// [`Self::from_connection`]'s `ensure_column` call) and is never expired.
    /// An expired token is still consumed (mirrors [`SqliteBootstrap::redeem`]),
    /// so it can't be retried indefinitely either.
    ///
    /// #288: the consume (`UPDATE redeemed`) and the bind (`INSERT
    /// agent_bindings`) run in one transaction -- previously two separate
    /// auto-committed statements, so a crash between them left the token
    /// flagged redeemed with no binding row: a retry got `TokenAlreadyUsed`
    /// but the agent had no enrolled identity, permanently locked out without
    /// operator intervention. `confirm_payment` already wraps its own
    /// two-table update this way; this matches that precedent.
    pub fn redeem(
        &self,
        token: &JoinToken,
        agent: &AgentId,
        pubkey: AgentPublicKey,
        now: u64,
    ) -> Result<TenantId, RedeemError> {
        let mut guard = self.conn.lock_safe();
        let tx = guard.transaction()?;
        let row: Option<(String, i64, i64)> = tx
            .query_row(
                "SELECT tenant, redeemed, expires_at FROM join_tokens WHERE token = ?1",
                params![&token.0[..]],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let (tenant, redeemed, expires_at) = row.ok_or(RedeemError::Enroll(EnrollError::UnknownToken))?;
        if redeemed != 0 {
            return Err(RedeemError::Enroll(EnrollError::TokenAlreadyUsed));
        }
        tx.execute(
            "UPDATE join_tokens SET redeemed = 1 WHERE token = ?1",
            params![&token.0[..]],
        )?;
        if expires_at != 0 && (now as i64) > expires_at {
            tx.commit()?;
            return Err(RedeemError::Enroll(EnrollError::Expired));
        }
        tx.execute(
            "INSERT OR REPLACE INTO agent_bindings (agent, tenant, pubkey) VALUES (?1, ?2, ?3)",
            params![agent.0, tenant, &pubkey[..]],
        )?;
        tx.commit()?;
        Ok(TenantId(tenant))
    }

    /// Redeem a join token **only** if the caller proves possession of the private
    /// key for `pubkey` (#88 SEC88c): `proof` must be `pubkey`'s ed25519 signature
    /// over the join token (see [`crate::enrollment::verify_join_proof`]). The proof
    /// is checked *before* the token is consumed, so a bad proof burns nothing and
    /// returns [`EnrollError::BadProof`]; a valid proof falls through to the normal
    /// single-use [`Self::redeem`]. This closes the "redeem binds an unproven key"
    /// gap — a redemption can no longer bind a public key the caller doesn't control.
    pub fn redeem_with_proof(
        &self,
        token: &JoinToken,
        agent: &AgentId,
        pubkey: AgentPublicKey,
        proof: &[u8; 64],
        now: u64,
    ) -> Result<TenantId, RedeemError> {
        if !crate::enrollment::verify_join_proof(token, &pubkey, proof) {
            return Err(RedeemError::Enroll(EnrollError::BadProof));
        }
        self.redeem(token, agent, pubkey, now)
    }

    /// The binding recorded for `agent`, if enrolled.
    pub fn binding(
        &self,
        agent: &AgentId,
    ) -> rusqlite::Result<Option<(TenantId, AgentPublicKey)>> {
        self.conn
            .lock_safe()
            .query_row(
                "SELECT tenant, pubkey FROM agent_bindings WHERE agent = ?1",
                params![agent.0],
                |r| {
                    let tenant: String = r.get(0)?;
                    let pk: Vec<u8> = r.get(1)?;
                    // #466: was `key.copy_from_slice(&pk)`, which panics on anything but
                    // exactly 32 bytes -- every write path only ever inserts a well-formed
                    // key, but a corrupt/hand-edited/partially-restored DB (the exact
                    // scenario this codebase's migration machinery exists for) should get a
                    // clean error here, not a panic, matching the `try_from` pattern already
                    // used everywhere else in this file for this identical decode.
                    let key = <[u8; 32]>::try_from(pk.as_slice()).map_err(|_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Blob,
                            "agent_bindings.pubkey is not 32 bytes".into(),
                        )
                    })?;
                    Ok((TenantId(tenant), key))
                },
            )
            .optional()
    }

    /// Number of enrolled agents (bound public keys) — for the status view (F4.1).
    pub fn agent_count(&self) -> rusqlite::Result<i64> {
        self.conn
            .lock_safe()
            .query_row("SELECT COUNT(*) FROM agent_bindings", [], |r| r.get(0))
    }

    /// Delete already-redeemed join-token rows (#292 housekeeping) AND
    /// unredeemed rows past their `expires_at` (#663 -- an expired-but-never-
    /// redeemed token is exactly the "leaked, unbounded lifetime" case this
    /// column exists to close; there's no reason to keep it around once
    /// [`Self::redeem`] would refuse it anyway). `expires_at = 0` (a pre-
    /// migration legacy row) is never matched by the age check, same
    /// grandfather semantics as everywhere else this column is read. Returns
    /// the count removed. Safe to call periodically; live, unexpired,
    /// unredeemed tokens are never touched.
    pub fn prune_redeemed_join_tokens(&self, now: u64) -> rusqlite::Result<usize> {
        self.conn.lock_safe().execute(
            "DELETE FROM join_tokens WHERE redeemed != 0 OR (expires_at != 0 AND expires_at < ?1)",
            params![now as i64],
        )
    }

    /// Delete `batch_issuance` idempotency records older than `now - max_age_secs`
    /// (#292 housekeeping); returns the count removed. Rows from before the
    /// `created_at` column existed (`created_at = 0`) are never matched — their
    /// true age is unknown, so this only ages out records minted after the
    /// migration. `max_age_secs` should comfortably exceed any realistic retry
    /// window for the idempotency key it guards (a stale key past this point
    /// simply mints a fresh batch on the next reuse instead of replaying).
    pub fn prune_batch_issuance(&self, now: u64, max_age_secs: u64) -> rusqlite::Result<usize> {
        let cutoff = now.saturating_sub(max_age_secs) as i64;
        self.conn
            .lock_safe()
            .execute("DELETE FROM batch_issuance WHERE created_at != 0 AND created_at < ?1", params![cutoff])
    }
}

/// A real M2M credential a subject self-issued (real self-service feature,
/// 2026-08-04 -- account owners can create their own Keycloak service-account
/// clients, not just have core create one for them out-of-band). Keycloak's
/// own client object has no subject/owner concept at all -- this table is
/// what makes "this account's service accounts" a real, queryable thing.
/// Never stores the client secret: Keycloak itself is the source of truth for
/// that (fetch/rotate on demand), so a leaked DB row alone can't hand out a
/// live credential.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServiceAccountClient {
    pub client_id: String,
    pub name: String,
    pub created_at: i64,
}

/// SQLite-backed subject -> Keycloak-service-account-client ownership map.
pub struct SqliteServiceAccountStore {
    conn: Mutex<Connection>,
}

sqlite_store_ctors!(SqliteServiceAccountStore);

impl SqliteServiceAccountStore {
    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS service_account_clients (
                 client_id   TEXT PRIMARY KEY,
                 subject     TEXT NOT NULL,
                 internal_id TEXT NOT NULL,
                 name        TEXT NOT NULL,
                 created_at  INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_service_account_clients_subject
                 ON service_account_clients (subject);",
        )?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Record a freshly-created Keycloak client as owned by `subject`. Called
    /// only after the real Keycloak admin-API create call already succeeded --
    /// this is bookkeeping, never the thing that actually creates the client.
    pub fn record(&self, subject: &str, client_id: &str, internal_id: &str, name: &str, created_at: i64) -> rusqlite::Result<()> {
        self.conn.lock_safe().execute(
            "INSERT INTO service_account_clients (client_id, subject, internal_id, name, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![client_id, subject, internal_id, name, created_at],
        )?;
        Ok(())
    }

    /// Like [`Self::record`], but the owned-count check and the insert run
    /// under the SAME `conn` lock acquisition as one atomic unit -- same
    /// check-then-act race class `create_if_under_owned_limit` already closed
    /// for tunnels (#432). Found live during the TOCTOU consolidation sweep
    /// (2026-08-24): `service_account_create`'s handler used to read
    /// `existing_count` via a separate, earlier call to [`Self::list_for_subject`]
    /// -- with a real Keycloak admin-API round-trip in between the check and
    /// this insert, two concurrent requests from the same subject could both
    /// observe `existing_count < max` before either one's insert committed,
    /// exceeding `max`. Returns `Ok(false)` (no row inserted) when `subject`
    /// already owns `max` or more clients at the moment of the same lock
    /// acquisition that would perform the insert -- the caller is responsible
    /// for cleaning up the already-created (now unrecorded) Keycloak client in
    /// that case.
    pub fn record_if_under_limit(&self, subject: &str, client_id: &str, internal_id: &str, name: &str, created_at: i64, max: usize) -> rusqlite::Result<bool> {
        let conn = self.conn.lock_safe();
        let owned_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM service_account_clients WHERE subject = ?1",
            params![subject],
            |r| r.get(0),
        )?;
        if owned_count as usize >= max {
            return Ok(false);
        }
        conn.execute(
            "INSERT INTO service_account_clients (client_id, subject, internal_id, name, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![client_id, subject, internal_id, name, created_at],
        )?;
        Ok(true)
    }

    /// Every service-account client `subject` has self-issued, oldest first.
    /// Never carries a secret -- see the type's own doc comment.
    pub fn list_for_subject(&self, subject: &str) -> rusqlite::Result<Vec<ServiceAccountClient>> {
        let conn = self.conn.lock_safe();
        let mut stmt = conn.prepare(
            "SELECT client_id, name, created_at FROM service_account_clients WHERE subject = ?1 ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map(params![subject], |r| {
            Ok(ServiceAccountClient { client_id: r.get(0)?, name: r.get(1)?, created_at: r.get(2)? })
        })?;
        rows.collect()
    }

    /// The real Keycloak internal id for `client_id`, but ONLY if `subject`
    /// actually owns it -- the one lookup every rotate/revoke call must make
    /// first, so a caller can never act on a client they don't own even if
    /// they somehow already know its `client_id`.
    pub fn internal_id_for(&self, subject: &str, client_id: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .lock_safe()
            .query_row(
                "SELECT internal_id FROM service_account_clients WHERE subject = ?1 AND client_id = ?2",
                params![subject, client_id],
                |r| r.get(0),
            )
            .optional()
    }

    /// Drop the ownership record -- called only after the real Keycloak
    /// admin-API delete call already succeeded. `false` if `subject` didn't
    /// own `client_id` (nothing removed).
    pub fn remove(&self, subject: &str, client_id: &str) -> rusqlite::Result<bool> {
        let n = self
            .conn
            .lock_safe()
            .execute("DELETE FROM service_account_clients WHERE subject = ?1 AND client_id = ?2", params![subject, client_id])?;
        Ok(n > 0)
    }
}

#[cfg(test)]
mod service_account_store_tests {
    use super::*;

    #[test]
    fn record_then_list_returns_only_that_subjects_clients_oldest_first() {
        let store = SqliteServiceAccountStore::open_in_memory().unwrap();
        store.record("alice", "sa-1", "kc-internal-1", "CI bot", 100).unwrap();
        store.record("alice", "sa-2", "kc-internal-2", "Bridge", 200).unwrap();
        store.record("bob", "sa-3", "kc-internal-3", "Bob's thing", 150).unwrap();

        let alice_clients = store.list_for_subject("alice").unwrap();
        assert_eq!(alice_clients.len(), 2);
        assert_eq!(alice_clients[0].client_id, "sa-1");
        assert_eq!(alice_clients[1].client_id, "sa-2");
        assert_eq!(alice_clients[0].name, "CI bot");

        let bob_clients = store.list_for_subject("bob").unwrap();
        assert_eq!(bob_clients.len(), 1);
        assert_eq!(bob_clients[0].client_id, "sa-3");
    }

    #[test]
    fn internal_id_for_is_owner_scoped_not_just_client_id_scoped() {
        let store = SqliteServiceAccountStore::open_in_memory().unwrap();
        store.record("alice", "sa-1", "kc-internal-1", "CI bot", 100).unwrap();

        assert_eq!(store.internal_id_for("alice", "sa-1").unwrap(), Some("kc-internal-1".to_string()));
        assert_eq!(store.internal_id_for("mallory", "sa-1").unwrap(), None, "a non-owner must never resolve another subject's client");
        assert_eq!(store.internal_id_for("alice", "sa-does-not-exist").unwrap(), None);
    }

    #[test]
    fn record_if_under_limit_closes_the_toctou_race_the_handler_used_to_have() {
        // Real gap found live 2026-08-24: service_account_create used to check
        // existing_count via a separate, earlier list_for_subject().len() call,
        // then insert unconditionally after a real Keycloak network round-trip
        // in between -- two concurrent callers could both pass the check before
        // either inserted. This test proves the atomic replacement actually
        // enforces the cap: fill up to the limit, then confirm the next
        // attempt is rejected and performs NO insert (not just returns an
        // error after inserting anyway).
        let store = SqliteServiceAccountStore::open_in_memory().unwrap();
        assert!(store.record_if_under_limit("alice", "sa-1", "kc-1", "one", 100, 2).unwrap());
        assert!(store.record_if_under_limit("alice", "sa-2", "kc-2", "two", 200, 2).unwrap());
        assert!(
            !store.record_if_under_limit("alice", "sa-3", "kc-3", "three", 300, 2).unwrap(),
            "a third record at the cap of 2 must be rejected"
        );
        assert_eq!(store.list_for_subject("alice").unwrap().len(), 2, "the rejected attempt must not have inserted a row");
        // A different subject has their own independent limit.
        assert!(store.record_if_under_limit("bob", "sa-4", "kc-4", "bob's", 400, 2).unwrap());
    }

    #[test]
    fn remove_is_owner_scoped_and_reports_whether_anything_was_actually_removed() {
        let store = SqliteServiceAccountStore::open_in_memory().unwrap();
        store.record("alice", "sa-1", "kc-internal-1", "CI bot", 100).unwrap();

        assert!(!store.remove("mallory", "sa-1").unwrap(), "a non-owner's remove must be a real no-op, not silently succeed");
        assert_eq!(store.list_for_subject("alice").unwrap().len(), 1, "mallory's attempt must not have removed alice's row");

        assert!(store.remove("alice", "sa-1").unwrap());
        assert_eq!(store.list_for_subject("alice").unwrap().len(), 0);
        assert!(!store.remove("alice", "sa-1").unwrap(), "removing an already-gone row reports false, not an error");
    }

    #[test]
    fn service_account_client_never_serializes_a_secret_field() {
        // Real, not just a docstring claim: proves the JSON wire shape genuinely
        // has no place a secret could ever leak through this type.
        let c = ServiceAccountClient { client_id: "sa-1".to_string(), name: "CI bot".to_string(), created_at: 100 };
        let json = serde_json::to_value(&c).unwrap();
        let keys: std::collections::BTreeSet<&str> = json.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        assert_eq!(keys, ["client_id", "name", "created_at"].into_iter().collect());
    }
}

/// Why a bootstrap-token redemption failed (#90/#97 SEC90b).
#[derive(Debug)]
pub enum BootstrapError {
    /// No such bootstrap token (never minted, or already pruned).
    UnknownToken,
    /// The token was already redeemed (single-use).
    AlreadyUsed,
    /// The token's TTL has elapsed (`now` is past `expires_at`).
    Expired,
    /// A database error.
    Db(rusqlite::Error),
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootstrapError::UnknownToken => write!(f, "unknown bootstrap token"),
            BootstrapError::AlreadyUsed => write!(f, "bootstrap token already used"),
            BootstrapError::Expired => write!(f, "bootstrap token expired"),
            BootstrapError::Db(e) => write!(f, "database error: {e}"),
        }
    }
}

impl std::error::Error for BootstrapError {}

impl From<rusqlite::Error> for BootstrapError {
    fn from(e: rusqlite::Error) -> Self {
        BootstrapError::Db(e)
    }
}

/// SQLite-backed **bootstrap-token** store (#90/#97 SEC90b): the durable core of the
/// bootstrap-token exchange that lets the install/channel one-liners carry only a
/// **short-lived, single-use** opaque token instead of the real secrets (join /
/// routing tokens), which today are embedded in the shown command string and so land
/// in shell history and `ps`.
///
/// The flow this primitive underpins (HTTP route + installer rewrite are follow
/// packets): the CP [`mint`](Self::mint)s a bootstrap token bound to the real secret
/// bundle with a short TTL; the one-liner carries only that token; the agent redeems
/// it **server-side over TLS** ([`redeem`](Self::redeem)) to receive the real secret
/// in the response body. Because redemption is single-use and the TTL is short, a
/// bootstrap token leaked via shell history / `ps` is useless once redeemed or
/// expired — closing the secret-in-argv exposure without putting the real secret on
/// the command line.
///
/// Time is caller-supplied (`now`, unix seconds) for deterministic tests, mirroring
/// [`ct_common::replay::ReplayCache`] and the rate limiters. The `secret` payload is
/// opaque to the store (the follow packet decides its shape, e.g. a JSON bundle).
pub struct SqliteBootstrap {
    conn: Mutex<Connection>,
}

sqlite_store_ctors!(SqliteBootstrap);

impl SqliteBootstrap {
    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS bootstrap_tokens (
                 token      BLOB PRIMARY KEY,
                 secret     TEXT NOT NULL,
                 expires_at INTEGER NOT NULL,
                 redeemed   INTEGER NOT NULL DEFAULT 0
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Mint a fresh single-use bootstrap token that hands off `secret`, valid for
    /// `ttl_secs` from `now`. Returns the 32-byte token to embed in the one-liner.
    pub fn mint(&self, secret: &str, ttl_secs: u64, now: u64) -> rusqlite::Result<[u8; 32]> {
        let mut token = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut token);
        let expires_at = now.saturating_add(ttl_secs);
        self.conn.lock_safe().execute(
            "INSERT INTO bootstrap_tokens (token, secret, expires_at, redeemed) VALUES (?1, ?2, ?3, 0)",
            params![&token[..], secret, expires_at as i64],
        )?;
        Ok(token)
    }

    /// Redeem a bootstrap token, returning its secret **exactly once**. Fails with
    /// [`BootstrapError::UnknownToken`] if never minted, [`BootstrapError::Expired`]
    /// if `now` is past its TTL (an expired token is consumed so it can't be retried),
    /// or [`BootstrapError::AlreadyUsed`] on a second redemption. The consumption is
    /// persisted, so single-use survives a restart.
    pub fn redeem(&self, token: &[u8; 32], now: u64) -> Result<String, BootstrapError> {
        let conn = self.conn.lock_safe();
        let row: Option<(String, i64, i64)> = conn
            .query_row(
                "SELECT secret, expires_at, redeemed FROM bootstrap_tokens WHERE token = ?1",
                params![&token[..]],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let (secret, expires_at, redeemed) = row.ok_or(BootstrapError::UnknownToken)?;
        if redeemed != 0 {
            return Err(BootstrapError::AlreadyUsed);
        }
        // Consume the token regardless of freshness, so an expired token can't be
        // retried and a redeemed one is single-use.
        conn.execute(
            "UPDATE bootstrap_tokens SET redeemed = 1 WHERE token = ?1",
            params![&token[..]],
        )?;
        if (now as i64) > expires_at {
            return Err(BootstrapError::Expired);
        }
        Ok(secret)
    }

    /// Delete already-redeemed or expired rows (housekeeping); returns the count
    /// removed. Safe to call periodically — live, unredeemed, unexpired tokens stay.
    pub fn prune(&self, now: u64) -> rusqlite::Result<usize> {
        self.conn.lock_safe().execute(
            "DELETE FROM bootstrap_tokens WHERE redeemed != 0 OR expires_at < ?1",
            params![now as i64],
        )
    }
}

/// One entry in the **searchable agent directory** (#144 ②): an agent's holder key, the URL of
/// its published [`AgentCard`](ct_common::channel::AgentCard) well-known document, and the
/// self-asserted `role_tags` / `skill_ids` it wants to be discoverable by. The directory only
/// *points* at the verifiable card — a searcher fetches `card_url`
/// ([`/.well-known/agent-card.json`](ct_common::channel)) and re-checks the holder signature
/// itself; the registry is discovery, never trust (same discipline as the card's self-assertion).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AgentDirectoryEntry {
    /// Hex of the agent's 32-byte ed25519 holder public key (the identity).
    pub holder_pubkey: String,
    /// Where the holder-signed card is served.
    pub card_url: String,
    pub role_tags: Vec<String>,
    pub skill_ids: Vec<String>,
    pub registered_at: u64,
}

/// The registered domain (eTLD+1) a hostname falls under (#469). Duplicated rather
/// than shared across modules on purpose, mirroring `acme_broker::registered_domain`
/// (which mirrors `dns01_challenge::dns01_record_name`) — this fleet only ever mints
/// single-level subdomains of its own configured zone(s), so "everything but the
/// leftmost label, unless there is no leftmost label to strip" is exact today; a
/// multi-zone future would make this a config lookup instead.
fn registered_domain(hostname: &str) -> String {
    let labels: Vec<&str> = hostname.split('.').collect();
    if labels.len() <= 2 {
        hostname.to_string()
    } else {
        labels[1..].join(".")
    }
}

fn split_tokens(s: &str) -> Vec<String> {
    if s.is_empty() {
        Vec::new()
    } else {
        s.split('\n').map(str::to_string).collect()
    }
}

/// Escape a token for safe use inside a `LIKE ... ESCAPE '\'` pattern (backslash, then `%`/`_`,
/// the two characters `LIKE` itself treats as wildcards). `register`'s own newline check already
/// keeps tokens free of `\n`/`\r`, so this only has to defang `LIKE`'s own special characters —
/// otherwise a role/skill token containing e.g. `%` would silently widen the exact-token match
/// `search` promises (see its own doc comment) into a substring match.
fn like_escape_token(s: &str) -> String {
    s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

/// Why an agent-directory [`register`](SqliteAgentDirectory::register) was rejected.
#[derive(Debug)]
pub enum AgentDirectoryError {
    /// A `role_tag`/`skill_id` contained the record delimiter (a newline). The store joins tokens
    /// with `\n` and search splits on `\n`, so a token like `"source\nadmin"` would smuggle an
    /// extra searchable facet the agent never advertised — a token-injection. Reject at the door.
    InvalidToken(String),
    Db(rusqlite::Error),
}

impl std::fmt::Display for AgentDirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentDirectoryError::InvalidToken(t) => {
                write!(f, "role/skill token must not contain a newline: {t:?}")
            }
            AgentDirectoryError::Db(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for AgentDirectoryError {}
impl From<rusqlite::Error> for AgentDirectoryError {
    fn from(e: rusqlite::Error) -> Self {
        AgentDirectoryError::Db(e)
    }
}

/// SQLite-backed **searchable agent directory** (#144 ②): agents self-register their published
/// card URL + the roles/skills they advertise, and peers query `role`/`skill` to discover whom to
/// fetch + verify. Distinct from [`SqliteRegistry`] (tunnels). Can share the same DB file as the
/// other stores — it owns its `agent_cards` table + its own connection.
///
/// #398: this store follows the #344 hybrid pooled-reads-single-writer pattern (see
/// [`SqliteTunnelStore`]'s struct doc for the full read/write-contention reasoning). Its
/// [`search`](Self::search) backs the public `GET /registry/agents` discovery scan — genuinely
/// read-heavy, hit by every peer doing role/skill discovery — while [`register`](Self::register)
/// (self-(re)registration) is comparatively rare. Only [`register`] writes; [`search`] and
/// [`count`] are pooled.
pub struct SqliteAgentDirectory {
    /// The one connection [`Self::register`] uses, unchanged in shape from every other
    /// non-migrated store's `conn` field.
    writer: Mutex<Connection>,
    /// Extra read-only connections for [`Self::search`]/[`Self::count`] (see [`Self::read`]).
    /// `None` for an in-memory store (see [`SqliteTunnelStore::readers`]'s doc for why).
    readers: Option<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>,
}

impl SqliteAgentDirectory {
    /// Open (creating if needed) a durable store at `path`, plus a pool of extra read-only
    /// connections (#398; see the struct doc). Hand-written rather than [`sqlite_store_ctors!`]
    /// for the same reason as [`SqliteTunnelStore::open`]: `open` now does genuinely more than
    /// `open_in_memory` (builds the pool too).
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let mut store = Self::from_connection(open_tuned(path)?)?;
        let manager =
            r2d2_sqlite::SqliteConnectionManager::file(path).with_init(|c: &mut Connection| tune_connection(c));
        store.readers = Some(r2d2::Pool::builder().max_size(8).build_unchecked(manager));
        Ok(store)
    }

    /// Open an ephemeral in-memory store (tests / stateless runs). No reader pool (#398) —
    /// every method, read or write, goes through `writer`, exactly like before this migration.
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    /// A connection for a READ-only method (#398; same shape as [`SqliteTunnelStore::read`]).
    fn read(&self) -> ReadConn<'_> {
        match self.readers.as_ref().and_then(|pool| pool.get().ok()) {
            Some(pooled) => ReadConn::Pooled(pooled),
            None => ReadConn::Direct(self.writer.lock_safe()),
        }
    }

    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS agent_cards (
                 holder_pubkey TEXT PRIMARY KEY,
                 card_url      TEXT NOT NULL,
                 role_tags     TEXT NOT NULL,
                 skill_ids     TEXT NOT NULL,
                 registered_at INTEGER NOT NULL
             );",
        )?;
        Ok(Self {
            writer: Mutex::new(conn),
            readers: None,
        })
    }

    /// Self-register (or update) an agent's directory entry, keyed by its holder key — so an agent
    /// re-registering (new card URL, changed roles/skills) **upserts** rather than duplicating.
    /// `role_tags`/`skill_ids` are the self-asserted, searchable facets; `card_url` is where the
    /// signed card is fetched + verified.
    pub fn register(
        &self,
        holder_pubkey: &str,
        card_url: &str,
        role_tags: &[String],
        skill_ids: &[String],
        now: u64,
    ) -> Result<(), AgentDirectoryError> {
        // Token-injection defence (source's review finding): the facets are stored `\n`-joined and
        // searched by splitting on `\n`, so a token containing a newline (`"source\nadmin"`) would
        // smuggle an extra advertised facet. Reject any delimiter-bearing token at the door.
        for t in role_tags.iter().chain(skill_ids.iter()) {
            if t.contains('\n') || t.contains('\r') {
                return Err(AgentDirectoryError::InvalidToken(t.clone()));
            }
        }
        self.writer.lock_safe().execute(
            "INSERT OR REPLACE INTO agent_cards
                 (holder_pubkey, card_url, role_tags, skill_ids, registered_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                holder_pubkey,
                card_url,
                role_tags.join("\n"),
                skill_ids.join("\n"),
                now as i64
            ],
        )?;
        Ok(())
    }

    /// Search the directory: entries whose `role_tags` contain `role` (when given) AND whose
    /// `skill_ids` contain `skill` (when given), matched as **exact tokens** (not substrings, so
    /// `"admin"` never matches `"administrator"`). Both `None` → the whole directory. Sorted by
    /// holder key for a stable result.
    ///
    /// The exact-token match happens in the `WHERE` clause itself (#347): each stored column is
    /// wrapped in `char(10)` delimiters and matched against `%\n<escaped token>\n%`, so only rows
    /// that actually carry the token are pulled from SQLite and deserialized — a directory search
    /// no longer loads + token-splits every row just to discard most of them in Rust.
    pub fn search(
        &self,
        role: Option<&str>,
        skill: Option<&str>,
    ) -> rusqlite::Result<Vec<AgentDirectoryEntry>> {
        let conn = self.read();
        let mut sql = String::from(
            "SELECT holder_pubkey, card_url, role_tags, skill_ids, registered_at
             FROM agent_cards WHERE 1=1",
        );
        let mut binds: Vec<String> = Vec::new();
        if let Some(r) = role {
            sql.push_str(" AND (char(10) || role_tags || char(10)) LIKE ? ESCAPE '\\'");
            binds.push(format!("%\n{}\n%", like_escape_token(r)));
        }
        if let Some(s) = skill {
            sql.push_str(" AND (char(10) || skill_ids || char(10)) LIKE ? ESCAPE '\\'");
            binds.push(format!("%\n{}\n%", like_escape_token(s)));
        }
        sql.push_str(" ORDER BY holder_pubkey");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(binds.iter()), |r| {
                let role_tags: String = r.get(2)?;
                let skill_ids: String = r.get(3)?;
                Ok(AgentDirectoryEntry {
                    holder_pubkey: r.get(0)?,
                    card_url: r.get(1)?,
                    role_tags: split_tokens(&role_tags),
                    skill_ids: split_tokens(&skill_ids),
                    registered_at: r.get::<_, i64>(4)? as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Directory size without deserializing a single row (#347) — `status_handler`'s aggregate
    /// count only ever needed `COUNT(*)`, not every row's token-split facets.
    pub fn count(&self) -> rusqlite::Result<i64> {
        self.read()
            .query_row("SELECT COUNT(*) FROM agent_cards", [], |r| r.get(0))
    }
}

/// SQLite-backed **pipeline registry** (#174 B): where a designer *publishes* a workflow
/// [`PipelineSpec`](ct_common::pipeline::PipelineSpec) (#171/#172) so agents can discover it —
/// the pipeline analogue of the #144 agent directory. The spec is stored as its canonical JSON,
/// keyed by the spec's own `id`; publishing is owner-scoped so one designer can't overwrite
/// another's spec.
///
/// #398: hybrid pooled-reads-single-writer store (#344 pattern; see [`SqliteTunnelStore`]'s
/// struct doc). [`get`](Self::get)/[`list`](Self::list) back the public `GET /registry/pipelines`
/// + `GET /registry/pipelines/:id` discovery routes — genuinely read-heavy, hit by every agent
/// scanning for workflows to join — while [`publish`](Self::publish)/[`unpublish`](Self::unpublish)
/// (designer-initiated) are comparatively rare. Only `publish`/`unpublish` write; `get`/`list` are
/// pooled.
pub struct SqlitePipelineRegistry {
    /// The one connection [`Self::publish`]/[`Self::unpublish`] use, unchanged in shape from
    /// every other non-migrated store's `conn` field.
    writer: Mutex<Connection>,
    /// Extra read-only connections for [`Self::get`]/[`Self::list`] (see [`Self::read`]). `None`
    /// for an in-memory store (see [`SqliteTunnelStore::readers`]'s doc for why).
    readers: Option<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>,
}

impl SqlitePipelineRegistry {
    /// Open (creating if needed) a durable store at `path`, plus a pool of extra read-only
    /// connections (#398; see the struct doc).
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let mut store = Self::from_connection(open_tuned(path)?)?;
        let manager =
            r2d2_sqlite::SqliteConnectionManager::file(path).with_init(|c: &mut Connection| tune_connection(c));
        store.readers = Some(r2d2::Pool::builder().max_size(8).build_unchecked(manager));
        Ok(store)
    }

    /// Open an ephemeral in-memory store (tests / stateless runs). No reader pool (#398) —
    /// every method, read or write, goes through `writer`, exactly like before this migration.
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    /// A connection for a READ-only method (#398; same shape as [`SqliteTunnelStore::read`]).
    fn read(&self) -> ReadConn<'_> {
        match self.readers.as_ref().and_then(|pool| pool.get().ok()) {
            Some(pooled) => ReadConn::Pooled(pooled),
            None => ReadConn::Direct(self.writer.lock_safe()),
        }
    }

    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS pipelines (
                 id           TEXT PRIMARY KEY,
                 owner        TEXT NOT NULL,
                 spec_json    TEXT NOT NULL,
                 published_at INTEGER NOT NULL
             );",
        )?;
        Ok(Self { writer: Mutex::new(conn), readers: None })
    }

    /// Publish (upsert) a workflow pipeline spec, keyed by its `id`. Re-publishing the same id by
    /// the same `owner` updates it; a **different** owner cannot overwrite an existing spec
    /// (owner-scoped — returns `false` on the ownership clash, leaving the published spec intact).
    /// The spec is stored as its canonical JSON.
    pub fn publish(
        &self,
        owner: &str,
        spec: &ct_common::pipeline::PipelineSpec,
        now: u64,
    ) -> rusqlite::Result<bool> {
        let json = serde_json::to_string(spec)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let conn = self.writer.lock_safe();
        let existing_owner: Option<String> = conn
            .query_row("SELECT owner FROM pipelines WHERE id = ?1", params![spec.id], |r| r.get(0))
            .optional()?;
        if let Some(o) = existing_owner {
            if o != owner {
                return Ok(false);
            }
        }
        // #233: operator_pubkey_hex is Option<T> purely for backward compat with specs
        // published before the field existed -- a FRESH publish/re-publish has no such
        // excuse, since the designer always has their own pubkey to hand, and omitting
        // it silently breaks the "no prior relationship needed" registry-discovery
        // promise (role_channel_id returns None with no other signal). Making it a hard
        // requirement is a real API-contract change this crate shouldn't decide
        // unilaterally (a currently-passing publisher could start failing); this is the
        // safe middle ground -- purely a visibility signal, no behavior change for any
        // existing caller -- so an operator watching logs actually notices the gap
        // instead of it staying silent indefinitely, which is exactly how both real
        // demo pipelines ended up in this state for this long.
        if spec.operator_pubkey_hex.is_none() {
            eprintln!(
                "ct-cp: WARNING -- pipeline '{}' published with no operator_pubkey_hex (#233): \
                 registry-based channel discovery (GET /registry/pipelines/{}) won't work for \
                 this pipeline's roles until it republishes with one set",
                spec.id, spec.id
            );
        }
        conn.execute(
            "INSERT OR REPLACE INTO pipelines (id, owner, spec_json, published_at) VALUES (?1, ?2, ?3, ?4)",
            params![spec.id, owner, json, now as i64],
        )?;
        Ok(true)
    }

    /// Fetch a published pipeline spec by `id`, or `None` if unknown (or its stored JSON no longer
    /// parses — a forward-incompatible spec never crashes a reader).
    pub fn get(&self, id: &str) -> rusqlite::Result<Option<ct_common::pipeline::PipelineSpec>> {
        let json: Option<String> = self
            .read()
            .query_row("SELECT spec_json FROM pipelines WHERE id = ?1", params![id], |r| r.get(0))
            .optional()?;
        Ok(json.and_then(|j| serde_json::from_str(&j).ok()))
    }

    /// List every published pipeline as `(id, owner)`, sorted by id — the discovery surface a
    /// scanning agent reads to find workflows to join.
    pub fn list(&self) -> rusqlite::Result<Vec<(String, String)>> {
        let conn = self.read();
        let mut stmt = conn.prepare("SELECT id, owner FROM pipelines ORDER BY id")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Un-publish `id`, owner-scoped (account-deletion cascade's per-pipeline teardown).
    /// Returns whether a row was removed.
    pub fn unpublish(&self, owner: &str, id: &str) -> rusqlite::Result<bool> {
        let n = self.writer.lock_safe().execute(
            "DELETE FROM pipelines WHERE id = ?1 AND owner = ?2",
            params![id, owner],
        )?;
        Ok(n > 0)
    }
}

/// SQLite-backed tunnel registry (durable equivalent of
/// [`crate::registry::TunnelRegistry`]). Can share the same database file as
/// [`SqliteEnrollment`] — each store owns its tables and its own connection.
pub struct SqliteRegistry {
    conn: Mutex<Connection>,
}

sqlite_store_ctors!(SqliteRegistry);

impl SqliteRegistry {
    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS tunnels (
                 token  BLOB PRIMARY KEY,
                 tenant TEXT NOT NULL,
                 agent  TEXT NOT NULL
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Register (or replace) the tunnel served by `token`.
    pub fn register(&self, token: &RoutingToken, info: &TunnelInfo) -> rusqlite::Result<()> {
        self.conn.lock_safe().execute(
            "INSERT OR REPLACE INTO tunnels (token, tenant, agent) VALUES (?1, ?2, ?3)",
            params![&token.0[..], info.tenant.0, info.agent.0],
        )?;
        Ok(())
    }

    /// Resolve `token` to its tunnel, if registered (the Rendezvous lookup).
    pub fn lookup(&self, token: &RoutingToken) -> rusqlite::Result<Option<TunnelInfo>> {
        self.conn
            .lock_safe()
            .query_row(
                "SELECT tenant, agent FROM tunnels WHERE token = ?1",
                params![&token.0[..]],
                |r| {
                    Ok(TunnelInfo {
                        tenant: TenantId(r.get(0)?),
                        agent: AgentId(r.get(1)?),
                    })
                },
            )
            .optional()
    }

    /// Remove the tunnel for `token` (idempotent).
    pub fn unregister(&self, token: &RoutingToken) -> rusqlite::Result<()> {
        self.conn.lock_safe().execute(
            "DELETE FROM tunnels WHERE token = ?1",
            params![&token.0[..]],
        )?;
        Ok(())
    }

    /// Number of registered tunnels — for the status view (F4.1).
    pub fn tunnel_count(&self) -> rusqlite::Result<i64> {
        self.conn
            .lock_safe()
            .query_row("SELECT COUNT(*) FROM tunnels", [], |r| r.get(0))
    }
}

/// Why a persisted ledger operation failed: a ledger rule or the database.
#[derive(Debug)]
pub enum LedgerOpError {
    Ledger(LedgerError),
    Db(rusqlite::Error),
}

impl std::fmt::Display for LedgerOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LedgerOpError::Ledger(e) => write!(f, "{e}"),
            LedgerOpError::Db(e) => write!(f, "storage error: {e}"),
        }
    }
}
impl std::error::Error for LedgerOpError {}
impl From<rusqlite::Error> for LedgerOpError {
    fn from(e: rusqlite::Error) -> Self {
        LedgerOpError::Db(e)
    }
}

/// Why a persisted payment confirmation failed: a payment rule or the database.
#[derive(Debug)]
pub enum PaymentOpError {
    Payment(PaymentError),
    Db(rusqlite::Error),
}

impl std::fmt::Display for PaymentOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PaymentOpError::Payment(e) => write!(f, "{e}"),
            PaymentOpError::Db(e) => write!(f, "storage error: {e}"),
        }
    }
}
impl std::error::Error for PaymentOpError {}
impl From<rusqlite::Error> for PaymentOpError {
    fn from(e: rusqlite::Error) -> Self {
        PaymentOpError::Db(e)
    }
}

/// SQLite-backed prepaid-credit ledger + payment intake (durable equivalent of
/// [`crate::accounts::Ledger`] and [`crate::payment::PaymentIntake`]).
///
/// Balances are stored as SQLite `INTEGER` (i64); credit amounts far below
/// `i64::MAX` are the realistic case for a prepaid ledger. The confirm path runs
/// in a transaction so a crash cannot leave a payment confirmed without the
/// matching credit (or vice versa).
pub struct SqliteLedger {
    conn: Mutex<Connection>,
}

/// One row of [`SqliteLedger::list_accounts`] (ADR-0025 admin console).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSummaryRow {
    pub subject: String,
    pub account_hex: String,
    pub balance: u64,
    pub blocked: bool,
    pub max_tunnels: u32,
    pub max_channels: u32,
}

sqlite_store_ctors!(SqliteLedger);

impl SqliteLedger {
    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS accounts (
                 account BLOB PRIMARY KEY,
                 balance INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS payments (
                 payment   BLOB PRIMARY KEY,
                 account   BLOB NOT NULL,
                 credits   INTEGER NOT NULL,
                 confirmed INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS account_subjects (
                 subject TEXT PRIMARY KEY,
                 account BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS token_issuances (
                 idempotency_key BLOB PRIMARY KEY,
                 account         BLOB NOT NULL,
                 token           BLOB NOT NULL,
                 price           INTEGER NOT NULL,
                 issued_at       INTEGER NOT NULL
             );",
        )?;
        // #44: `payments.confirmed` was added after the table's first release;
        // ensure it exists on a pre-existing DB so a top-up write doesn't 500.
        ensure_column(&conn, "payments", "confirmed", "INTEGER NOT NULL DEFAULT 0")?;
        // Multi-tunnel entitlement follow-up (#214): every account defaults to the
        // Standard tier's own tunnel (1) -- an operator can raise this for a
        // SPECIFIC account (set_max_tunnels) to unlock self-service creation of
        // additional subdomains, instead of running admin_provision_tunnel by hand
        // for every one. DEFAULT 1 keeps every existing account's behavior
        // unchanged on a pre-existing DB.
        ensure_column(&conn, "accounts", "max_tunnels", "INTEGER NOT NULL DEFAULT 1")?;
        // #113-ui-limits: same idea for Agent-Fabric channels, which had NO cap at all
        // before this (unlike tunnels' max_tunnels) -- default 100 is generous enough
        // that no real Standard-tier account should ever hit it by accident, while
        // still bounding the previously-unbounded `channels` table an operator could
        // otherwise be flooded with. Raised per-account the same way as max_tunnels.
        ensure_column(&conn, "accounts", "max_channels", "INTEGER NOT NULL DEFAULT 100")?;
        // ADR-0025 (admin console): an admin-blocked account is refused at every
        // credit-gated admission point (`debit`/`debit_and_record_issuance`) and at
        // the self-service tunnel-creation gate (`portal_api::create_tunnel`) --
        // see [`Self::is_blocked`]'s doc for the "a flag nobody checks is worthless"
        // reasoning. DEFAULT 0 keeps every existing account unblocked on upgrade.
        ensure_column(&conn, "accounts", "blocked", "INTEGER NOT NULL DEFAULT 0")?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// The most tunnels `account` may own at once (default 1, the Standard
    /// tier) -- what [`Self::set_max_tunnels`] raises for a specific account.
    pub fn max_tunnels(&self, account: &AccountId) -> rusqlite::Result<u32> {
        self.conn
            .lock_safe()
            .query_row(
                "SELECT max_tunnels FROM accounts WHERE account = ?1",
                params![&account.0[..]],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map(|v| v.unwrap_or(1).max(0) as u32)
    }

    /// Raise (or lower) the tunnel-creation limit for one SPECIFIC account
    /// (#214) -- an operator-only action; `create_tunnel`'s own gate is the
    /// only thing that reads this. No-op (not an error) if `account` doesn't
    /// exist yet (a subject that has never logged in has no account row to
    /// update -- [`Self::account_for_subject`] creates one on first login).
    pub fn set_max_tunnels(&self, account: &AccountId, max: u32) -> rusqlite::Result<()> {
        self.conn.lock_safe().execute(
            "UPDATE accounts SET max_tunnels = ?1 WHERE account = ?2",
            params![max, &account.0[..]],
        )?;
        Ok(())
    }

    /// The most Agent-Fabric channels `account` may own at once (default 100, the
    /// Standard tier) -- what [`Self::set_max_channels`] raises for a specific
    /// account. Same shape as [`Self::max_tunnels`].
    pub fn max_channels(&self, account: &AccountId) -> rusqlite::Result<u32> {
        self.conn
            .lock_safe()
            .query_row(
                "SELECT max_channels FROM accounts WHERE account = ?1",
                params![&account.0[..]],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map(|v| v.unwrap_or(100).max(0) as u32)
    }

    /// Raise (or lower) the channel-registration limit for one SPECIFIC account --
    /// an operator-only action; `SqliteChannelStore::register_channel`'s own gate is
    /// the only thing that reads this. No-op (not an error) if `account` doesn't
    /// exist yet, same as [`Self::set_max_tunnels`].
    pub fn set_max_channels(&self, account: &AccountId, max: u32) -> rusqlite::Result<()> {
        self.conn.lock_safe().execute(
            "UPDATE accounts SET max_channels = ?1 WHERE account = ?2",
            params![max, &account.0[..]],
        )?;
        Ok(())
    }

    fn balance_of(conn: &Connection, id: &AccountId) -> rusqlite::Result<Option<i64>> {
        conn.query_row(
            "SELECT balance FROM accounts WHERE account = ?1",
            params![&id.0[..]],
            |r| r.get(0),
        )
        .optional()
    }

    /// `(balance, blocked)` in one row read -- used by [`Self::debit`] and
    /// [`Self::debit_and_record_issuance`] so the blocked check and the balance
    /// read are the same snapshot inside their transaction, not two separate
    /// queries that could observe an admin's concurrent block/unblock between them.
    fn balance_and_blocked_of(conn: &Connection, id: &AccountId) -> rusqlite::Result<Option<(i64, bool)>> {
        conn.query_row(
            "SELECT balance, blocked FROM accounts WHERE account = ?1",
            params![&id.0[..]],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)? != 0)),
        )
        .optional()
    }

    /// Whether `account` is admin-blocked (ADR-0025 Decision 6 / the admin
    /// console's block action). Checked by [`Self::debit`]/
    /// [`Self::debit_and_record_issuance`] (the credit-gated token-issuance
    /// admission path) and by `portal_api::create_tunnel` (the self-service
    /// tunnel-creation admission path) -- this codebase has an explicit standing
    /// lesson that a block flag nobody checks is worthless, so both real
    /// admission points enforce it, not just this accessor existing.
    pub fn is_blocked(&self, account: &AccountId) -> rusqlite::Result<bool> {
        self.conn
            .lock_safe()
            .query_row(
                "SELECT blocked FROM accounts WHERE account = ?1",
                params![&account.0[..]],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map(|v| v.unwrap_or(0) != 0)
    }

    /// Set (or clear) `account`'s blocked flag -- the admin console's block/
    /// unblock action. No-op (not an error) if `account` doesn't exist yet,
    /// matching [`Self::set_max_tunnels`]'s own convention.
    pub fn set_blocked(&self, account: &AccountId, blocked: bool) -> rusqlite::Result<()> {
        self.conn.lock_safe().execute(
            "UPDATE accounts SET blocked = ?1 WHERE account = ?2",
            params![blocked as i64, &account.0[..]],
        )?;
        Ok(())
    }

    /// Remove `subject`'s account row and its `account_subjects` mapping entirely
    /// -- the ledger half of an admin-triggered account deletion
    /// (`portal_api::admin_ui_delete_account`). Self-service account deletion
    /// deliberately does NOT do this (Keycloak still owns that caller's identity
    /// and a returning login would just re-create the account row); an admin
    /// deleting someone else's account has no such expectation, so this actually
    /// removes the row. No-op if `subject` has no account yet.
    pub fn delete_account_for_subject(&self, subject: &str) -> rusqlite::Result<()> {
        let mut guard = self.conn.lock_safe();
        let tx = guard.transaction()?;
        let account: Option<Vec<u8>> = tx
            .query_row(
                "SELECT account FROM account_subjects WHERE subject = ?1",
                params![subject],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(bytes) = account {
            tx.execute("DELETE FROM accounts WHERE account = ?1", params![&bytes[..]])?;
            tx.execute("DELETE FROM account_subjects WHERE subject = ?1", params![subject])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Every known subject's account state (ADR-0025 admin console, `GET
    /// /admin-ui/accounts`) -- subject, account id (hex), balance, blocked, and
    /// max_tunnels, one row per `account_subjects` entry. ADR-0012 deliberately
    /// keeps ordinary self-service code from ever enumerating other subjects'
    /// accounts; this is the narrow admin-only exception (mirrors admin_identity's
    /// own "narrow, explicit carve-out" framing), reachable only via the
    /// admin-session-gated `/admin-ui/*` surface, never a self-service route.
    pub fn list_accounts(&self) -> rusqlite::Result<Vec<AccountSummaryRow>> {
        let conn = self.conn.lock_safe();
        let mut stmt = conn.prepare(
            "SELECT s.subject, a.account, a.balance, a.blocked, a.max_tunnels, a.max_channels
             FROM account_subjects s JOIN accounts a ON a.account = s.account
             ORDER BY s.subject",
        )?;
        let rows = stmt
            .query_map([], |r| {
                let account: Vec<u8> = r.get(1)?;
                Ok(AccountSummaryRow {
                    subject: r.get(0)?,
                    account_hex: account.iter().map(|b| format!("{b:02x}")).collect(),
                    balance: r.get::<_, i64>(2)?.max(0) as u64,
                    blocked: r.get::<_, i64>(3)? != 0,
                    max_tunnels: r.get::<_, i64>(4)?.max(0) as u32,
                    max_channels: r.get::<_, i64>(5)?.max(0) as u32,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Open a fresh account with a zero balance; returns its id.
    pub fn open_account(&self) -> rusqlite::Result<AccountId> {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        self.conn.lock_safe().execute(
            "INSERT INTO accounts (account, balance) VALUES (?1, 0)",
            params![&bytes[..]],
        )?;
        Ok(AccountId(bytes))
    }

    /// Return the account bound to an OIDC `subject` (e.g. a Keycloak `sub`
    /// claim), creating it with a zero balance on first use (M19.1). Idempotent:
    /// the same subject always maps to the same account, so conventional
    /// authenticated users have one stable account. The lookup + creation run in
    /// a transaction so a subject can never end up with two accounts.
    pub fn account_for_subject(&self, subject: &str) -> Result<AccountId, LedgerOpError> {
        let mut guard = self.conn.lock_safe();
        let tx = guard.transaction()?;
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT account FROM account_subjects WHERE subject = ?1",
                params![subject],
                |r| r.get(0),
            )
            .optional()?;
        let account = if let Some(bytes) = existing {
            // #466: was `a.copy_from_slice(&bytes)`, which panics on anything but
            // exactly 32 bytes -- see the identical fix + reasoning on `binding` above.
            let a = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                LedgerOpError::Db(rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    "account_subjects.account is not 32 bytes".into(),
                ))
            })?;
            AccountId(a)
        } else {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            tx.execute(
                "INSERT INTO accounts (account, balance) VALUES (?1, 0)",
                params![&bytes[..]],
            )?;
            tx.execute(
                "INSERT INTO account_subjects (subject, account) VALUES (?1, ?2)",
                params![subject, &bytes[..]],
            )?;
            AccountId(bytes)
        };
        tx.commit()?;
        Ok(account)
    }

    /// Readiness probe: can this process actually read its database?
    ///
    /// #541: this used to run `SELECT 1`, which reads no page of the database file at all --
    /// no table, no schema, no disk. SQLite answers it from the expression itself, so it
    /// proved "a connection object exists", never "the database is usable", while `/readyz`
    /// advertised the latter. Demonstrated: with the file's header zeroed (the damage a
    /// failed restore or a bad disk leaves behind), a fresh connection opens fine -- SQLite
    /// opens lazily -- `SELECT 1` still returns Ok, and only a real table read fails with
    /// "file is not a database". The probe reported ready for a database nothing could be
    /// read from.
    ///
    /// Reading from a real table forces at least the schema page off the file, so a
    /// destroyed header, a missing schema and an unreadable file all surface. `LIMIT 1`
    /// keeps it constant-cost: this runs every 15s under the container healthcheck, and a
    /// `count(*)` would be linear in the number of accounts -- a probe that becomes a load
    /// source as the deployment grows.
    ///
    /// What it deliberately does NOT cover: **writability** (a read-only filesystem passes
    /// this), and the reachability of Keycloak. The latter is a decision, not an oversight --
    /// tying readiness to a downstream service turns that service's outage into this one's.
    pub fn ping(&self) -> rusqlite::Result<()> {
        self.conn
            .lock_safe()
            .query_row("SELECT 1 FROM accounts LIMIT 1", [], |_| Ok(()))
            .or_else(|e| match e {
                // An empty `accounts` table is a perfectly ready database -- the read
                // reached the file, which is the whole question. Only a real error is one.
                rusqlite::Error::QueryReturnedNoRows => Ok(()),
                other => Err(other),
            })
    }

    /// Number of open accounts — for the status view (F4.1).
    pub fn account_count(&self) -> rusqlite::Result<i64> {
        self.conn
            .lock_safe()
            .query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get(0))
    }

    /// Number of confirmed payments — for the status view (F4.1).
    pub fn confirmed_payment_count(&self) -> rusqlite::Result<i64> {
        self.conn
            .lock_safe()
            .query_row("SELECT COUNT(*) FROM payments WHERE confirmed = 1", [], |r| {
                r.get(0)
            })
    }

    /// Current balance, or [`LedgerError::UnknownAccount`].
    pub fn balance(&self, id: &AccountId) -> Result<u64, LedgerOpError> {
        let conn = self.conn.lock_safe();
        Self::balance_of(&conn, id)?
            .map(|b| b as u64)
            .ok_or(LedgerOpError::Ledger(LedgerError::UnknownAccount))
    }

    /// Add prepaid credit (saturating); returns the new balance.
    ///
    /// #442: reads then writes inside a transaction, matching
    /// [`Self::debit_and_record_issuance`]'s established shape -- a second
    /// control-plane process sharing this DB (the self-hostability goal this
    /// crate documents elsewhere) could otherwise interleave its own
    /// read-modify-write between this one's read and write, losing an update.
    /// The app-level `Mutex<Connection>` already excludes that within one
    /// process; this closes the same gap across processes.
    pub fn credit(&self, id: &AccountId, amount: u64) -> Result<u64, LedgerOpError> {
        // #604: same guard as `create_intent`'s own #83 check, mirrored here so this
        // function is self-defending regardless of caller -- see `LedgerError::
        // CreditAmountTooLarge`'s doc for why `amount as i64` below is unsafe unguarded.
        if amount > i64::MAX as u64 {
            return Err(LedgerOpError::Ledger(LedgerError::CreditAmountTooLarge { amount }));
        }
        let mut guard = self.conn.lock_safe();
        let tx = guard.transaction()?;
        let bal = Self::balance_of(&tx, id)?.ok_or(LedgerOpError::Ledger(LedgerError::UnknownAccount))?;
        let new = bal.saturating_add(amount as i64);
        tx.execute("UPDATE accounts SET balance = ?1 WHERE account = ?2", params![new, &id.0[..]])?;
        tx.commit()?;
        Ok(new as u64)
    }

    /// Spend credit; fails with [`LedgerError::InsufficientCredit`] and leaves
    /// the balance unchanged when the account cannot cover `amount`. #442: same
    /// transactional shape as [`Self::credit`] -- see its doc for why.
    pub fn debit(&self, id: &AccountId, amount: u64) -> Result<u64, LedgerOpError> {
        let mut guard = self.conn.lock_safe();
        let tx = guard.transaction()?;
        let (bal, blocked) =
            Self::balance_and_blocked_of(&tx, id)?.ok_or(LedgerOpError::Ledger(LedgerError::UnknownAccount))?;
        // ADR-0025: an admin-blocked account is refused here regardless of
        // balance -- checked before the balance comparison so a blocked-but-funded
        // account gets the same refusal as a blocked-and-broke one, not a
        // misleading InsufficientCredit.
        if blocked {
            return Err(LedgerOpError::Ledger(LedgerError::AccountBlocked));
        }
        let bal_u = bal as u64;
        if bal_u < amount {
            return Err(LedgerOpError::Ledger(LedgerError::InsufficientCredit {
                balance: bal_u,
                requested: amount,
            }));
        }
        let new = bal - amount as i64;
        tx.execute("UPDATE accounts SET balance = ?1 WHERE account = ?2", params![new, &id.0[..]])?;
        tx.commit()?;
        Ok(new as u64)
    }

    /// #272: look up a prior token issuance by its client-supplied idempotency key.
    /// A caller retrying a `/billing/issue` call after a lost response (crash, timeout,
    /// network drop) uses this to get back the SAME already-minted token instead of
    /// [`Self::debit_and_record_issuance`] debiting the account a second time for a
    /// token that was already paid for.
    ///
    /// #440: scoped to `id` -- `idempotency_key` is free-form client input with no
    /// global-uniqueness guarantee (a counter, a copied example value), so without
    /// this check one caller's key colliding with another's would hand back the
    /// OTHER account's already-minted Routing Token, un-debited. A key recorded
    /// under a different account is treated as "no issuance for THIS caller" (the
    /// insert path below then surfaces the real conflict).
    pub fn issuance_for_key(&self, id: &AccountId, idempotency_key: &[u8]) -> rusqlite::Result<Option<[u8; 32]>> {
        self.conn
            .lock_safe()
            .query_row(
                "SELECT token FROM token_issuances WHERE idempotency_key = ?1 AND account = ?2",
                params![idempotency_key, &id.0[..]],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()
            .and_then(|opt| {
                // #466: was `t.copy_from_slice(&bytes)`, which panics on anything but
                // exactly 32 bytes -- see the identical fix + reasoning on `binding` above.
                opt.map(|bytes| {
                    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Blob,
                            "token_issuances.token is not 32 bytes".into(),
                        )
                    })
                })
                .transpose()
            })
    }

    /// #272: debit `amount` from `id` and durably record the minted `token` against
    /// `idempotency_key` in ONE transaction, so a crash between the two can never
    /// happen -- the debit and the issuance record either both land or neither does.
    /// Pairs with [`Self::issuance_for_key`]: a caller checks that first, and only
    /// calls this when no prior issuance exists for the key.
    pub fn debit_and_record_issuance(
        &self,
        id: &AccountId,
        amount: u64,
        idempotency_key: &[u8],
        token: &[u8; 32],
        now: u64,
    ) -> Result<u64, LedgerOpError> {
        let mut guard = self.conn.lock_safe();
        let tx = guard.transaction()?;
        let (bal, blocked) =
            Self::balance_and_blocked_of(&tx, id)?.ok_or(LedgerOpError::Ledger(LedgerError::UnknownAccount))?;
        // ADR-0025: same "blocked wins over InsufficientCredit" ordering as `debit`.
        if blocked {
            return Err(LedgerOpError::Ledger(LedgerError::AccountBlocked));
        }
        let bal_u = bal as u64;
        if bal_u < amount {
            return Err(LedgerOpError::Ledger(LedgerError::InsufficientCredit {
                balance: bal_u,
                requested: amount,
            }));
        }
        let new = bal - amount as i64;
        tx.execute("UPDATE accounts SET balance = ?1 WHERE account = ?2", params![new, &id.0[..]])?;
        // #440: idempotency_key is still the table's sole PRIMARY KEY (not
        // (account, idempotency_key) -- that would need a full table rebuild,
        // SQLite has no in-place PK change). issuance_for_key already scopes its
        // lookup to this account, so by the time execution reaches here the
        // caller has confirmed THEIR account has no prior issuance for this key
        // -- a UNIQUE violation now means a DIFFERENT account already used this
        // exact key, a real (if now-caller-visible) conflict rather than a raw
        // DB error.
        tx.execute(
            "INSERT INTO token_issuances (idempotency_key, account, token, price, issued_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![idempotency_key, &id.0[..], &token[..], amount as i64, now as i64],
        )
        .map_err(|e| match &e {
            rusqlite::Error::SqliteFailure(err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                LedgerOpError::Ledger(LedgerError::IdempotencyKeyReused)
            }
            _ => LedgerOpError::Db(e),
        })?;
        tx.commit()?;
        Ok(new as u64)
    }

    /// Register a payment intent (top-up of `credits` against `account`);
    /// returns an opaque [`PaymentId`]. Unconfirmed until [`Self::confirm_payment`].
    pub fn create_intent(&self, account: &AccountId, credits: u64) -> rusqlite::Result<PaymentId> {
        // #83: SQLite INTEGER is i64. A `credits` above i64::MAX would wrap NEGATIVE
        // via `credits as i64`, and on confirmation add a negative amount and return
        // it `as u64` — turning a balance into ~u64::MAX. Reject the absurd value at
        // creation (a >9.2-quintillion top-up is never legitimate) so no negative
        // credits row can ever exist.
        if credits > i64::MAX as u64 {
            return Err(rusqlite::Error::ToSqlConversionFailure(
                format!("payment credits {credits} exceeds the maximum {}", i64::MAX).into(),
            ));
        }
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        self.conn.lock_safe().execute(
            "INSERT INTO payments (payment, account, credits, confirmed) VALUES (?1, ?2, ?3, 0)",
            params![&bytes[..], &account.0[..], credits as i64],
        )?;
        Ok(PaymentId(bytes))
    }

    /// Confirm a payment and credit the account, atomically. Idempotent: a
    /// second confirmation returns [`PaymentError::AlreadyConfirmed`] and does
    /// not credit again. Returns the new balance.
    pub fn confirm_payment(&self, payment: &PaymentId) -> Result<u64, PaymentOpError> {
        let mut guard = self.conn.lock_safe();
        let tx = guard.transaction()?;
        let row: Option<(Vec<u8>, i64, i64)> = tx
            .query_row(
                "SELECT account, credits, confirmed FROM payments WHERE payment = ?1",
                params![&payment.0[..]],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let (account, credits, confirmed) =
            row.ok_or(PaymentOpError::Payment(PaymentError::UnknownPayment))?;
        if confirmed != 0 {
            return Err(PaymentOpError::Payment(PaymentError::AlreadyConfirmed));
        }
        // #83 defence in depth: never credit a negative amount (create_intent now
        // prevents them, but a legacy/corrupt row must not corrupt a balance).
        if credits < 0 {
            return Err(PaymentOpError::Db(rusqlite::Error::IntegralValueOutOfRange(
                1, credits,
            )));
        }
        let bal: i64 = tx
            .query_row(
                "SELECT balance FROM accounts WHERE account = ?1",
                params![&account[..]],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(PaymentOpError::Payment(PaymentError::Ledger(
                LedgerError::UnknownAccount,
            )))?;
        let new_balance = bal.saturating_add(credits);
        tx.execute(
            "UPDATE accounts SET balance = ?1 WHERE account = ?2",
            params![new_balance, &account[..]],
        )?;
        tx.execute(
            "UPDATE payments SET confirmed = 1 WHERE payment = ?1",
            params![&payment.0[..]],
        )?;
        tx.commit()?;
        Ok(new_balance as u64)
    }
}

/// How a self-service tunnel create resolved (#432 atomic gate + the 15.08.
/// hostname-collision fix): the three answers need three different HTTP shapes
/// (created / quota exceeded / name already taken).
#[derive(Debug)]
pub enum CreateTunnelOutcome {
    Created(SubjectTunnel),
    OverLimit,
    HostnameTaken,
}

/// How [`SqliteChannelStore::register_channel_if_under_owned_limit`] resolved.
#[derive(Debug, PartialEq, Eq)]
pub enum RegisterChannelOutcome {
    Registered,
    OwnedByAnother,
    OverLimit,
}

impl CreateTunnelOutcome {
    /// The created tunnel, or `None` when the create was refused. Keeps call sites that
    /// legitimately expect success (tests with a known-free hostname) readable without
    /// re-matching the whole enum -- and, unlike a second "just insert it" constructor,
    /// leaves no path that can produce a duplicate (#545).
    pub fn created(self) -> Option<SubjectTunnel> {
        match self {
            Self::Created(t) => Some(t),
            _ => None,
        }
    }
}

/// One tunnel owned by a customer, as shown in the portal listing (#27). Holds
/// **no secret**: the routing token and capability are minted and shown once at
/// creation (a later sub-packet) and never persisted here, so listing a tunnel
/// can never leak credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectTunnel {
    /// Opaque per-tunnel id (not a secret) used to address it for revoke.
    pub id: String,
    /// Customer-chosen display name.
    pub name: String,
    /// Optional Browser-Plane hostname (#23) this tunnel serves.
    pub hostname: Option<String>,
    /// Unix seconds at creation.
    pub created_at: i64,
    /// Hex routing token the tunnel's agent registers under at the edge. Held
    /// **server-side only** — never rendered in a listing — so a revocation can
    /// invalidate the live registration (#27 RB1). It is a routing identifier,
    /// not the Noise capability (which is still never persisted).
    pub routing_token: String,
}

/// One row of `disabled_hostnames` (ADR-0025) -- the admin console's own
/// listing of what it has blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisabledHostnameRow {
    pub hostname: String,
    pub disabled_by: String,
    pub disabled_at: i64,
}

/// Rot/Gelb/Grün certificate-tier state for one hostname (#233 admission
/// queue broker). See [`SqliteTunnelStore::cert_admission_for_hostname`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertAdmission {
    /// `"rot"` (not yet reachable) | `"gelb"` (live via the shared wildcard
    /// cert, queued for its own) | `"gruen"` (own real cert issued).
    pub status: String,
    /// The CA (`ct_common::acme_ca::CaProfile::name`) this hostname's own
    /// certificate is/will be issued through. Set once, at first claim offer,
    /// and never rewritten afterward — every renewal reuses it.
    pub assigned_ca: Option<String>,
    /// `"none"` | `"offered"` (a 48h claim window is open) | `"lapsed"`
    /// (window expired unclaimed; awaiting an explicit customer re-request).
    pub claim_state: String,
    /// Unix seconds the current claim offer expires, if `claim_state=="offered"`.
    pub claim_deadline: Option<i64>,
    /// Position in the Gelb queue (0 = next), or `None` once a claim has been
    /// offered or the hostname is already `gruen`.
    pub queue_position: Option<i64>,
}

impl CertAdmission {
    /// Whether this hostname may have a real certificate issued for it right
    /// now: either it already has one (`gruen`, forever -- renewals must
    /// never be blocked by this), or it currently holds an unexpired claim
    /// offer. Shared by [`crate::acme_broker`]'s admission-poll response AND
    /// [`crate::dns01_challenge`]'s publish gate (#233 follow-up) — the
    /// SAME check must answer both "what does the agent's poll say" and "may
    /// the DNS-01 challenge actually be published", or a customer running
    /// their own ACME client directly against the publish endpoint (proven
    /// ownership of their own hostname, but bypassing `ct-agent`'s admission
    /// poll entirely) could issue a real certificate outside the queue,
    /// consuming the operator's shared rate-limit budget unpaced.
    pub fn may_issue_now(&self, now: i64) -> bool {
        self.status == "gruen" || (self.claim_state == "offered" && self.claim_deadline.is_some_and(|d| now < d))
    }
}

/// Why a tunnel-grant operation failed: the caller is not the tunnel's owner, or
/// the database errored (#29).
#[derive(Debug)]
pub enum GrantError {
    /// The caller does not own the tunnel (or it does not exist) — only the
    /// owner may manage its grants.
    NotOwner,
    /// The underlying database operation failed.
    Db(rusqlite::Error),
}

impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrantError::NotOwner => write!(f, "not the tunnel owner"),
            GrantError::Db(e) => write!(f, "storage error: {e}"),
        }
    }
}

impl std::error::Error for GrantError {}

impl From<rusqlite::Error> for GrantError {
    fn from(e: rusqlite::Error) -> Self {
        GrantError::Db(e)
    }
}

/// SQLite-backed per-subject tunnel store (#27): a customer creates, lists and
/// revokes their **own** tunnels. Every operation is scoped by `subject` (from
/// the verified token), so one customer can never see or revoke another's tunnel.
///
/// It also holds per-tunnel access **grants** (#29): the owner shares a tunnel
/// with other subjects, and [`is_authorized`](Self::is_authorized) answers
/// whether a subject may use it.
///
/// #344: this store is one of two (so far) with a connection **pool**
/// (`readers`) alongside its dedicated single writer connection, instead of
/// every operation sharing one `Mutex<Connection>` like the other Sqlite*
/// stores in this file still do. It was picked as the first slice because its
/// own hottest path (`/portal/tunnels` -> [`list_authorized_for_subject`] +
/// per-row [`cert_admission_for_hostname`], the finding's own cited example)
/// is genuinely read-heavy, and its WAL journal mode ([`open_tuned`]) already
/// supports concurrent readers at the SQLite engine level -- the old
/// `Mutex<Connection>` was the only thing serializing them anyway.
///
/// This store is **not** read-only, though (`create`/`revoke`/`grant`/the
/// Rot-Gelb-Grün admission-queue transitions all write), so pooling every
/// method would let previously-impossible concurrent writers race for
/// SQLite's single engine-level write lock, with only the 5s `busy_timeout`
/// standing between that race and a real `SQLITE_BUSY` surfacing to a caller
/// (see `open_tuned`'s doc: today the app-level `Mutex` makes that timeout
/// decorative, since this process never contends with itself). Rather than
/// prove that's safe under contention, every WRITE method keeps going through
/// `writer` -- the exact same single dedicated connection, same lock, same
/// full serialization as every other store's `conn` field today. Only the
/// READ-only methods (see [`Self::read`]) take a connection from `readers`
/// instead, so this migration changes nothing about write behavior and only
/// parallelizes what WAL already allowed to run concurrently at the engine
/// level. `r2d2`/`r2d2_sqlite` has no separate "pooled reads, one writer"
/// primitive -- `SqliteConnectionManager` just manages homogeneous pooled
/// connections -- so this hybrid is hand-rolled at the store level instead.
pub struct SqliteTunnelStore {
    /// The one connection every WRITE method uses, unchanged from before this
    /// migration (see the struct doc above for why writes stay serialized).
    writer: Mutex<Connection>,
    /// Extra read-only connections for every READ-only method (see
    /// [`Self::read`]). `None` for an in-memory store: a `:memory:` database is
    /// private to the `Connection` that opened it, so a second pooled
    /// connection would see an empty, disconnected database rather than a
    /// shared one (SQLite's shared-cache URI mode could fix this, but
    /// `open_in_memory` is test/stateless-run-only, so it isn't worth the
    /// complexity -- reads there just fall back to `writer`, exactly like
    /// before this migration).
    readers: Option<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>,
}

impl SqliteTunnelStore {
    /// Open (creating if needed) a durable store at `path` on a tuned WAL
    /// connection, plus a pool of extra read-only connections to the same file
    /// (#344; see the struct doc). Hand-written rather than
    /// [`sqlite_store_ctors!`] because that macro's `open`/`open_in_memory` pair
    /// is deliberately identical modulo `Connection::open` vs `open_in_memory`
    /// -- this store's `open` does genuinely more (builds the pool too), and
    /// its `open_in_memory` deliberately does NOT (see `readers`' doc), so the
    /// two are no longer simple twins of each other.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let mut store = Self::from_connection(open_tuned(path)?)?;
        // `build_unchecked`: connections are opened lazily on first checkout
        // rather than eagerly here, so a transient issue opening extra reader
        // connections can never fail store construction -- the eagerly-opened
        // `writer` connection above already proved `path` itself is openable.
        // Every pooled connection gets the identical WAL + busy_timeout tuning
        // as `writer` via `with_init` (`tune_connection`, factored out of
        // `open_tuned` so both share one source of truth for the tuning).
        let manager =
            r2d2_sqlite::SqliteConnectionManager::file(path).with_init(|c: &mut Connection| tune_connection(c));
        // #444: r2d2's documented default connection_timeout is 30s -- `read()`'s own
        // doc claims pool exhaustion "never a hard failure: a read simply degrades",
        // but without this override a burst past max_size(8) parks the calling tokio
        // worker thread for up to 30s BEFORE that degradation even begins, strictly
        // worse than the pre-pool behavior this was meant to improve on. 50ms is
        // "try briefly, then degrade" -- long enough to ride out a genuine transient
        // burst, short enough that the promised fallback actually happens promptly.
        store.readers = Some(
            r2d2::Pool::builder()
                .max_size(8)
                .connection_timeout(std::time::Duration::from_millis(50))
                .build_unchecked(manager),
        );
        Ok(store)
    }

    /// Open an ephemeral in-memory store (for tests / stateless runs). No
    /// reader pool (#344; see the struct doc) -- every method, read or write,
    /// goes through `writer`, exactly like before this migration.
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    /// A connection for a READ-only method (#344). Prefers a pooled reader
    /// connection when one exists (a file-backed store, concurrent with other
    /// readers at the SQLite/WAL engine level); falls back to `writer` for an
    /// in-memory store (no pool -- see `readers`' doc) or if the pool is
    /// transiently exhausted/unavailable (never a hard failure: a read simply
    /// degrades to the same serialized-but-correct path every method used
    /// before this migration, rather than surfacing a pool error to the
    /// caller).
    fn read(&self) -> ReadConn<'_> {
        match self.readers.as_ref().and_then(|pool| pool.get().ok()) {
            Some(pooled) => ReadConn::Pooled(pooled),
            None => ReadConn::Direct(self.writer.lock_safe()),
        }
    }

    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS subject_tunnels (
                 id            TEXT PRIMARY KEY,
                 subject       TEXT NOT NULL,
                 name          TEXT NOT NULL,
                 hostname      TEXT,
                 created_at    INTEGER NOT NULL,
                 routing_token TEXT NOT NULL DEFAULT ''
             );
             CREATE INDEX IF NOT EXISTS idx_subject_tunnels_subject
                 ON subject_tunnels (subject);
             CREATE TABLE IF NOT EXISTS tunnel_grants (
                 tunnel_id TEXT NOT NULL,
                 grantee   TEXT NOT NULL,
                 PRIMARY KEY (tunnel_id, grantee)
             );
             -- #463: PRIMARY KEY (tunnel_id, grantee) only helps queries constraining
             -- the leading column; every /portal/tunnels page load filters on grantee
             -- alone.
             CREATE INDEX IF NOT EXISTS idx_tunnel_grants_grantee
                 ON tunnel_grants (grantee);",
        )?;
        // #44: subject_tunnels gained `hostname` (#23) and `routing_token` (#27)
        // after its first release; add them to any pre-existing DB so schema-adding
        // upgrades don't 500 on a persistent self-host volume.
        ensure_column(&conn, "subject_tunnels", "hostname", "TEXT")?;
        ensure_column(
            &conn,
            "subject_tunnels",
            "routing_token",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        // #233: Rot/Gelb/Grün certificate-tier state (the admission-queue
        // broker). `status` starts `'rot'` for every existing row on upgrade --
        // correct, since a pre-existing hostname already has its own real cert
        // (today's only path); the one-time backfill to `'gruen'` for already-
        // live hostnames is a deliberate manual operator step (see the plan),
        // not automated here, so it is never silently assumed.
        ensure_column(&conn, "subject_tunnels", "status", "TEXT NOT NULL DEFAULT 'rot'")?;
        ensure_column(&conn, "subject_tunnels", "assigned_ca", "TEXT")?;
        ensure_column(&conn, "subject_tunnels", "queued_at", "INTEGER")?;
        ensure_column(&conn, "subject_tunnels", "claim_state", "TEXT NOT NULL DEFAULT 'none'")?;
        ensure_column(&conn, "subject_tunnels", "claim_offered_at", "INTEGER")?;
        ensure_column(&conn, "subject_tunnels", "claim_deadline", "INTEGER")?;
        // #264: set alongside the Gruen transition, cleared once the edge confirms
        // (or is believed to confirm) the channel_tier=gelb=false revert push --
        // see record_issuance_complete / pending_revert_hostnames / clear_pending_revert.
        ensure_column(&conn, "subject_tunnels", "pending_revert", "INTEGER NOT NULL DEFAULT 0")?;
        // Browser-Plane login gate (#382-follow): off by default for every existing
        // tunnel on upgrade -- enabling it is always an explicit owner action
        // (`set_require_login`), never silently turned on by this migration.
        ensure_column(&conn, "subject_tunnels", "require_login", "INTEGER NOT NULL DEFAULT 0")?;
        // #501: self-service complement to the strict allow-list -- when set (and
        // require_login is on), ANY successfully authenticated account passes the gate;
        // the allow-list is ignored while this is on. Off by default for every existing
        // tunnel on upgrade, same explicit-owner-action-only posture as require_login.
        ensure_column(&conn, "subject_tunnels", "allow_any_login", "INTEGER NOT NULL DEFAULT 0")?;
        // #517 V3 (traffic offload, slice 2): direct-serving state per tunnel.
        // `direct_endpoint` is the agent-advertised "ip:port" a reachable Green-tier
        // agent serves browsers on directly; `direct_enabled` is the OWNER's opt-in
        // switch (off by default -- direct serving is never turned on silently);
        // `direct_advertised` + `direct_failures` are the live probe state the
        // `direct_serving::fold_probe` hysteresis machine drives, persisted so a CP
        // restart resumes mid-hysteresis instead of re-flapping a live DNS record;
        // `direct_probed_at` is the last probe's unix seconds. All off/NULL/0 by
        // default for every existing tunnel on upgrade.
        ensure_column(&conn, "subject_tunnels", "direct_endpoint", "TEXT")?;
        ensure_column(&conn, "subject_tunnels", "direct_enabled", "INTEGER NOT NULL DEFAULT 0")?;
        ensure_column(&conn, "subject_tunnels", "direct_advertised", "INTEGER NOT NULL DEFAULT 0")?;
        ensure_column(&conn, "subject_tunnels", "direct_failures", "INTEGER NOT NULL DEFAULT 0")?;
        ensure_column(&conn, "subject_tunnels", "direct_probed_at", "INTEGER")?;
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_subject_tunnels_status_queued
                 ON subject_tunnels (status, queued_at);
             -- #291: routing_token_for_hostname/cert_admission_for_hostname both query
             -- by hostname, but no index covered it -- a full-table scan per lookup,
             -- on the admission sweep's hot per-hostname poll path. Placed here (after
             -- the `hostname` ensure_column above) rather than alongside the table's own
             -- CREATE, so it's safe to add regardless of whether this DB predates #44's
             -- hostname column.
             CREATE INDEX IF NOT EXISTS idx_subject_tunnels_hostname
                 ON subject_tunnels (hostname);
             CREATE TABLE IF NOT EXISTS acme_issuance_log (
                 id        INTEGER PRIMARY KEY AUTOINCREMENT,
                 ca        TEXT NOT NULL,
                 domain    TEXT NOT NULL,
                 hostname  TEXT NOT NULL,
                 issued_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_acme_issuance_log_ca_domain_time
                 ON acme_issuance_log (ca, domain, issued_at);
             CREATE TABLE IF NOT EXISTS revoked_tokens (
                 token      TEXT PRIMARY KEY,
                 revoked_at INTEGER NOT NULL
             );
             -- Browser-Plane login gate (#382-follow): same shape as channel_allowlist,
             -- but hostname-keyed -- the gate-check endpoint (GET /gate/check) only ever
             -- knows the visitor's target hostname (from Caddy's forward_auth), never a
             -- tunnel id or its owner.
             CREATE TABLE IF NOT EXISTS tunnel_login_allowlist (
                 hostname  TEXT NOT NULL,
                 email     TEXT NOT NULL,
                 added_by  TEXT NOT NULL,
                 added_at  INTEGER NOT NULL,
                 PRIMARY KEY (hostname, email)
             );
             -- Self-service access requests (#382-follow, issue #18): lets a
             -- visitor who fails the login gate's allow-list check leave a real,
             -- durable request instead of hitting a dead end -- the tunnel owner
             -- reviews these from the same portal page that already manages the
             -- allow-list (login_gate_html). No new notification infrastructure:
             -- this crate has none (Keycloak's own SMTP config is a separate,
             -- account-verification-only concern), so the owner checks the
             -- portal, same as they already do for the allow-list itself.
             -- Idempotent per (hostname, email): resubmitting refreshes the
             -- note/timestamp instead of growing an unbounded duplicate queue.
             CREATE TABLE IF NOT EXISTS gate_access_requests (
                 hostname     TEXT NOT NULL,
                 email        TEXT NOT NULL,
                 note         TEXT NOT NULL DEFAULT '',
                 requested_at INTEGER NOT NULL,
                 PRIMARY KEY (hostname, email)
             );
             -- ADR-0025 (admin console): a hostname an admin has explicitly disabled.
             -- The enforcer lives in `portal_api::authorize_hostname` -- see
             -- `is_hostname_disabled`'s own doc for why the check belongs there rather
             -- than anywhere else (every path that would (re-)authorize a hostname at
             -- the edge funnels through that one function).
             CREATE TABLE IF NOT EXISTS disabled_hostnames (
                 hostname     TEXT PRIMARY KEY,
                 disabled_by  TEXT NOT NULL,
                 disabled_at  INTEGER NOT NULL
             );",
        )?;
        // #406: nothing previously enforced one-tunnel-per-hostname -- `idx_subject_tunnels_
        // hostname` above is a plain, non-unique index. Two reachable collisions: a raised
        // per-account tunnel limit lets `auto_hostname(zone, name, subject)` (deterministic
        // in (name, subject)) produce two rows with the same hostname, and
        // `admin_provision_tunnel` accepts an arbitrary hostname with no availability check
        // at all, so two DIFFERENT subjects can be provisioned the identical hostname --
        // every hostname-keyed lookup (`routing_token_for_hostname`, `cert_admission_for_
        // hostname`, `require_login_for_hostname`, ...) then silently reads whichever row
        // SQLite returns first, including leaking one subject's `require_login`/allow-list
        // state onto a DIFFERENT subject's hostname.
        //
        // A partial UNIQUE index (NULL hostnames -- Mesh-Plane-only tunnels -- excluded)
        // closes this at the DB layer, race-proof regardless of which code path inserts.
        // Migration safety: on a pre-existing, already-duplicated DB, creating a UNIQUE
        // index over duplicate values fails outright -- rather than let that crash boot
        // for every self-hosted deployment (some of which may already be in this state),
        // check for duplicates first and skip the index (loudly) if any exist, so a boot
        // never breaks in place. `create()`/callers already return normal `rusqlite::Error`
        // on any constraint failure, so no caller signature change is needed once the
        // index is live -- a would-be duplicate insert now fails cleanly instead of
        // silently succeeding.
        let dup_hostnames: Vec<String> = conn
            .prepare(
                "SELECT hostname FROM subject_tunnels
                 WHERE hostname IS NOT NULL
                 GROUP BY hostname HAVING COUNT(*) > 1",
            )?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if dup_hostnames.is_empty() {
            conn.execute_batch(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_subject_tunnels_hostname_unique
                     ON subject_tunnels (hostname) WHERE hostname IS NOT NULL;",
            )?;
        } else {
            eprintln!(
                "ct-cp: WARNING -- #406: {} hostname(s) already have duplicate subject_tunnels \
                 rows, skipping the new UNIQUE index this boot so it doesn't fail: {:?}. Every \
                 hostname-keyed lookup for these hostnames may still read the wrong row until \
                 the duplicates are resolved (keep one row, delete/rehome the other(s)) and the \
                 process is restarted so the index can be created.",
                dup_hostnames.len(),
                dup_hostnames
            );
        }
        Ok(Self {
            writer: Mutex::new(conn),
            readers: None,
        })
    }

    /// Create a tunnel owned by `subject`; returns its metadata. A fresh routing
    /// token is minted and persisted server-side so a revocation can later find
    /// and invalidate the tunnel's edge registration (#27 RB1). The `id` is a
    /// random hex string; `created_at` is the current Unix time.
    /// #545: answers a taken hostname with a typed [`CreateTunnelOutcome::HostnameTaken`]
    /// instead of letting the insert fail on the unique index.
    ///
    /// Duplicates were never possible: `idx_subject_tunnels_hostname_unique` (partial,
    /// `WHERE hostname IS NOT NULL`) enforces that in the schema and in the deployed
    /// database. What was wrong is only the ANSWER -- the operator path relied on the
    /// constraint error, which surfaced as `500 internal error`, the same poor diagnosis
    /// an operator reported for the self-service path on 15.08. and which was fixed there.
    /// The check here runs under the same writer lock as the insert, so its answer cannot
    /// race a concurrent create; the unique index remains the backstop underneath.
    pub fn create(
        &self,
        subject: &str,
        name: &str,
        hostname: Option<&str>,
    ) -> Result<CreateTunnelOutcome, rusqlite::Error> {
        let mut idb = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut idb);
        let id: String = idb.iter().map(|b| format!("{b:02x}")).collect();
        let mut tokb = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut tokb);
        let routing_token: String = tokb.iter().map(|b| format!("{b:02x}")).collect();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let conn = self.writer.lock_safe();
        if let Some(h) = hostname {
            let taken: bool = conn
                .query_row("SELECT 1 FROM subject_tunnels WHERE hostname = ?1", params![h], |_| Ok(()))
                .optional()?
                .is_some();
            if taken {
                return Ok(CreateTunnelOutcome::HostnameTaken);
            }
        }
        conn.execute(
            "INSERT INTO subject_tunnels (id, subject, name, hostname, created_at, routing_token)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, subject, name, hostname, created_at, routing_token],
        )?;
        Ok(CreateTunnelOutcome::Created(SubjectTunnel {
            id,
            name: name.to_string(),
            hostname: hostname.map(str::to_string),
            created_at,
            routing_token,
        }))
    }

    /// Like [`Self::create`], but the owned-tunnel-count check and the insert run
    /// under the SAME `writer` lock acquisition as one atomic unit (#432) —
    /// closing the check-then-act race where `create_tunnel`'s handler used to
    /// read `owned_count` via a separate, earlier call to
    /// [`Self::list_authorized_for_subject`] and only insert afterward: two
    /// concurrent requests could both observe `owned_count < max` before either
    /// one's insert committed. Returns `Ok(None)` (no row created) when `subject`
    /// already owns `max` or more tunnels at the moment of the same lock
    /// acquisition that performs the insert.
    pub fn create_if_under_owned_limit(
        &self,
        subject: &str,
        name: &str,
        hostname: Option<&str>,
        max: u32,
    ) -> rusqlite::Result<CreateTunnelOutcome> {
        let conn = self.writer.lock_safe();
        let owned_count: u32 = conn.query_row(
            "SELECT COUNT(*) FROM subject_tunnels WHERE subject = ?1",
            params![subject],
            |r| r.get(0),
        )?;
        if owned_count >= max {
            return Ok(CreateTunnelOutcome::OverLimit);
        }
        // Operator bug report (15.08.): re-creating a name whose derived hostname
        // already exists surfaced as a 500 "internal error" in the portal.
        // The constraint referred to is `idx_subject_tunnels_hostname_unique` (a partial
        // UNIQUE index, not a column constraint -- easy to miss when reading only the
        // table definition). This check exists to turn that error into a clean answer,
        // not to be the only thing preventing duplicates. auto_hostname is deterministic per
        // (name, account), so the same account re-using a name ALWAYS collides --
        // checked here under the same writer lock the insert runs under, so the
        // answer can't race a concurrent create.
        if let Some(h) = hostname {
            let taken: bool = conn
                .query_row("SELECT 1 FROM subject_tunnels WHERE hostname = ?1", params![h], |_| Ok(()))
                .optional()?
                .is_some();
            if taken {
                return Ok(CreateTunnelOutcome::HostnameTaken);
            }
        }
        let mut idb = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut idb);
        let id: String = idb.iter().map(|b| format!("{b:02x}")).collect();
        let mut tokb = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut tokb);
        let routing_token: String = tokb.iter().map(|b| format!("{b:02x}")).collect();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        conn.execute(
            "INSERT INTO subject_tunnels (id, subject, name, hostname, created_at, routing_token)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, subject, name, hostname, created_at, routing_token],
        )?;
        Ok(CreateTunnelOutcome::Created(SubjectTunnel {
            id,
            name: name.to_string(),
            hostname: hostname.map(str::to_string),
            created_at,
            routing_token,
        }))
    }

    /// List `subject`'s own tunnels, newest first.
    pub fn list_for_subject(&self, subject: &str) -> rusqlite::Result<Vec<SubjectTunnel>> {
        let conn = self.read();
        let mut stmt = conn.prepare(
            "SELECT id, name, hostname, created_at, routing_token FROM subject_tunnels
             WHERE subject = ?1 ORDER BY created_at DESC, id",
        )?;
        let rows = stmt.query_map(params![subject], |r| {
            Ok(SubjectTunnel {
                id: r.get(0)?,
                name: r.get(1)?,
                hostname: r.get(2)?,
                created_at: r.get(3)?,
                routing_token: r.get(4)?,
            })
        })?;
        rows.collect()
    }

    /// Every tunnel across every subject — the edge_mesh backfill's source of truth for
    /// portal-created tunnels (an admin/migration read, not subject-scoped like the rest
    /// of this store's API; deliberately doesn't leak into any customer-facing route).
    pub fn all(&self) -> rusqlite::Result<Vec<SubjectTunnel>> {
        let conn = self.read();
        let mut stmt =
            conn.prepare("SELECT id, name, hostname, created_at, routing_token FROM subject_tunnels ORDER BY id")?;
        let rows = stmt.query_map([], |r| {
            Ok(SubjectTunnel {
                id: r.get(0)?,
                name: r.get(1)?,
                hostname: r.get(2)?,
                created_at: r.get(3)?,
                routing_token: r.get(4)?,
            })
        })?;
        rows.collect()
    }

    /// Revoke a tunnel by id, but only if it belongs to `subject`. Returns the
    /// removed tunnel's **routing token** (so the caller can invalidate its edge
    /// registration — #27 RB3/RB4), or `None` when the id is unknown or owned by
    /// someone else (no cross-subject deletion). Also clears the tunnel's access
    /// grants (#29) so none are orphaned.
    ///
    /// #327: also records the token in the durable `revoked_tokens` table (same
    /// transaction). This is what closes #327's gap — the Edge's own in-memory
    /// revoked set doesn't survive a restart, so without a durable CP-side
    /// record for it to replay from at boot, a still-reconnecting Agent for an
    /// already-revoked tunnel would successfully re-register after any Edge
    /// restart. This table is the CP's half of that fix (see
    /// [`Self::list_revoked_tokens`]); the Edge's boot-time fetch is the other.
    pub fn revoke(&self, subject: &str, id: &str, now: u64) -> rusqlite::Result<Option<String>> {
        let mut guard = self.writer.lock_safe();
        let tx = guard.transaction()?;
        let token: Option<String> = tx
            .query_row(
                "SELECT routing_token FROM subject_tunnels WHERE id = ?1 AND subject = ?2",
                params![id, subject],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(tok) = &token {
            tx.execute(
                "DELETE FROM subject_tunnels WHERE id = ?1 AND subject = ?2",
                params![id, subject],
            )?;
            tx.execute("DELETE FROM tunnel_grants WHERE tunnel_id = ?1", params![id])?;
            tx.execute(
                "INSERT OR REPLACE INTO revoked_tokens (token, revoked_at) VALUES (?1, ?2)",
                params![tok, now as i64],
            )?;
        }
        tx.commit()?;
        Ok(token)
    }

    /// Every routing token ever revoked (#327): the durable record an Edge
    /// replays at boot so a restart can't silently undo a customer's revoke.
    /// Unbounded like the Edge's own in-memory set would be, but here that's
    /// fine — SQLite scales to this far past what an in-memory `HashSet` on a
    /// resource-capped Edge process should hold, and this table is exactly the
    /// kind of durable, queryable store the growth concern in #280 was about
    /// the Edge NOT having.
    pub fn list_revoked_tokens(&self) -> rusqlite::Result<Vec<String>> {
        let conn = self.read();
        let mut stmt = conn.prepare("SELECT token FROM revoked_tokens")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect()
    }

    /// Whether `subject` is the owner of `tunnel_id` (not merely a grantee).
    /// Used to gate agent onboarding — only the owner installs an agent for a
    /// tunnel (#28).
    pub fn owns(&self, subject: &str, tunnel_id: &str) -> rusqlite::Result<bool> {
        Ok(Self::owner_of(&self.read(), tunnel_id)?.as_deref() == Some(subject))
    }

    /// The Browser-Plane hostname of a tunnel the caller owns, if any (#38 DL2):
    /// used to clear the tunnel's DNS record on revoke. Owner-scoped.
    pub fn tunnel_hostname(&self, subject: &str, tunnel_id: &str) -> rusqlite::Result<Option<String>> {
        self.read()
            .query_row(
                "SELECT hostname FROM subject_tunnels WHERE id = ?1 AND subject = ?2",
                params![tunnel_id, subject],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()
            .map(Option::flatten)
    }

    /// The routing token of a tunnel the caller owns, or `None` if the id is
    /// unknown or owned by someone else (#27 RB2). Owner-scoped so a non-owner
    /// cannot read another customer's routing token.
    pub fn routing_token(&self, subject: &str, tunnel_id: &str) -> rusqlite::Result<Option<String>> {
        self.read()
            .query_row(
                "SELECT routing_token FROM subject_tunnels WHERE id = ?1 AND subject = ?2",
                params![tunnel_id, subject],
                |r| r.get(0),
            )
            .optional()
    }

    /// Enable/disable the Browser-Plane login gate for a tunnel the caller owns
    /// (#382-follow). `false` if the id is unknown or owned by someone else.
    pub fn set_require_login(&self, subject: &str, tunnel_id: &str, enabled: bool) -> rusqlite::Result<bool> {
        let n = self.writer.lock_safe().execute(
            "UPDATE subject_tunnels SET require_login = ?1 WHERE id = ?2 AND subject = ?3",
            params![enabled as i64, tunnel_id, subject],
        )?;
        Ok(n > 0)
    }

    /// Whether a tunnel the caller owns currently has the login gate enabled, or
    /// `None` if the id is unknown or owned by someone else. Owner-scoped, for
    /// rendering the portal checkbox's current state.
    pub fn require_login(&self, subject: &str, tunnel_id: &str) -> rusqlite::Result<Option<bool>> {
        self.read()
            .query_row(
                "SELECT require_login FROM subject_tunnels WHERE id = ?1 AND subject = ?2",
                params![tunnel_id, subject],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map(|v| v.map(|n| n != 0))
    }

    /// Whether the login gate is enabled for `hostname` (#382-follow). Unscoped
    /// by design: [`GET /gate/check`] only ever knows the visitor's target
    /// hostname (from Caddy's `forward_auth`), never a tunnel id or its owner --
    /// this is the one lookup the gate-check path needs, mirroring
    /// [`routing_token_for_hostname`](Self::routing_token_for_hostname)'s same
    /// hostname-only shape.
    /// #393: `hostname` here is caller-supplied (the gate derives it from
    /// `X-Forwarded-Host`/`?host=`), matched against whatever casing this
    /// tunnel's hostname happened to be stored with -- `COLLATE NOCASE`
    /// (DNS hostnames are case-insensitive, RFC 4343, the same reasoning
    /// `email`'s own `.to_ascii_lowercase()` normalization already applies
    /// elsewhere in this file) so a casing mismatch can never make this
    /// return a false `false` -- which `gate_check` reads as "gate not
    /// required", admitting the request with **no authentication at all**.
    pub fn require_login_for_hostname(&self, hostname: &str) -> rusqlite::Result<bool> {
        Ok(self
            .read()
            .query_row(
                "SELECT require_login FROM subject_tunnels WHERE hostname = ?1 COLLATE NOCASE",
                params![hostname],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .map(|n| n != 0)
            .unwrap_or(false))
    }

    /// ADR-0025 (admin console): mark `hostname` disabled -- the enforcer,
    /// [`Self::is_hostname_disabled`], is consulted by `portal_api::
    /// authorize_hostname` (every path that would (re-)authorize a hostname at
    /// the edge funnels through that one function), so once this returns, no
    /// future authorize-host push for `hostname` succeeds until
    /// [`Self::enable_hostname`] reverses it. Idempotent: disabling an
    /// already-disabled hostname just refreshes who/when.
    pub fn disable_hostname(&self, hostname: &str, disabled_by: &str, at: i64) -> rusqlite::Result<()> {
        self.writer.lock_safe().execute(
            "INSERT INTO disabled_hostnames (hostname, disabled_by, disabled_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(hostname) DO UPDATE SET disabled_by = excluded.disabled_by, disabled_at = excluded.disabled_at",
            params![hostname, disabled_by, at],
        )?;
        Ok(())
    }

    /// Reverse [`Self::disable_hostname`]. Returns whether a row was actually
    /// removed (`false` if `hostname` wasn't disabled). Deliberately does NOT
    /// re-push the edge authorize-host call itself -- disabling one revoked the
    /// tunnel's live routing-token registration (see the `/admin-ui/hostnames/
    /// :host/disable` handler), so simply lifting the block here only permits
    /// the NEXT ordinary authorize_hostname call (e.g. the owner recreating the
    /// tunnel) to succeed again.
    pub fn enable_hostname(&self, hostname: &str) -> rusqlite::Result<bool> {
        let n = self
            .writer
            .lock_safe()
            .execute("DELETE FROM disabled_hostnames WHERE hostname = ?1", params![hostname])?;
        Ok(n > 0)
    }

    /// Whether `hostname` is currently admin-disabled -- the one check
    /// [`crate::portal_api::authorize_hostname`] makes before ever pushing an
    /// authorize-host call to the edge (ADR-0025's "flag needs an enforcer"
    /// discipline, same shape as [`crate::accounts::AccountId`]'s block flag).
    pub fn is_hostname_disabled(&self, hostname: &str) -> rusqlite::Result<bool> {
        Ok(self
            .read()
            .query_row(
                "SELECT 1 FROM disabled_hostnames WHERE hostname = ?1",
                params![hostname],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Every disabled hostname, most-recently-disabled first -- the admin
    /// console's own visibility into what it has blocked.
    pub fn list_disabled_hostnames(&self) -> rusqlite::Result<Vec<DisabledHostnameRow>> {
        let conn = self.read();
        let mut stmt = conn.prepare(
            "SELECT hostname, disabled_by, disabled_at FROM disabled_hostnames ORDER BY disabled_at DESC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(DisabledHostnameRow {
                    hostname: r.get(0)?,
                    disabled_by: r.get(1)?,
                    disabled_at: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// #501: enable/disable the "any authenticated account may enter" mode for a
    /// tunnel the caller owns. Only meaningful while `require_login` is on; the
    /// allow-list is ignored while this is set. `false` if the id is unknown or
    /// owned by someone else.
    pub fn set_allow_any_login(&self, subject: &str, tunnel_id: &str, enabled: bool) -> rusqlite::Result<bool> {
        let n = self.writer.lock_safe().execute(
            "UPDATE subject_tunnels SET allow_any_login = ?1 WHERE id = ?2 AND subject = ?3",
            params![enabled as i64, tunnel_id, subject],
        )?;
        Ok(n > 0)
    }

    /// #517 V3: the OWNER opts a tunnel into (or out of) direct serving, supplying
    /// the endpoint (`ip:port`) their agent is reachable on. Owner-scoped (`false`
    /// if unknown/foreign). Enabling only ARMS the feature -- the direct DNS record
    /// is published later, and only after an external reachability probe actually
    /// succeeds (the `fold_probe` hysteresis, slice 3+). Disabling clears the probe
    /// state so a re-enable starts fresh.
    pub fn set_direct_serving(
        &self,
        subject: &str,
        tunnel_id: &str,
        enabled: bool,
        endpoint: Option<&str>,
    ) -> rusqlite::Result<bool> {
        let conn = self.writer.lock_safe();
        let n = if enabled {
            conn.execute(
                "UPDATE subject_tunnels SET direct_enabled = 1, direct_endpoint = ?1 \
                 WHERE id = ?2 AND subject = ?3",
                params![endpoint, tunnel_id, subject],
            )?
        } else {
            // Disabling resets the whole probe state -- a later re-enable must not
            // resume a stale hysteresis streak or a lingering advertised flag.
            conn.execute(
                "UPDATE subject_tunnels SET direct_enabled = 0, direct_advertised = 0, \
                 direct_failures = 0, direct_probed_at = NULL WHERE id = ?1 AND subject = ?2",
                params![tunnel_id, subject],
            )?
        };
        Ok(n > 0)
    }

    /// #517 V3: a tunnel's direct-serving config as the portal renders it --
    /// `(enabled, endpoint, advertised)`; `None` for an unknown/foreign tunnel.
    pub fn direct_serving(
        &self,
        subject: &str,
        tunnel_id: &str,
    ) -> rusqlite::Result<Option<(bool, Option<String>, bool)>> {
        self.read()
            .query_row(
                "SELECT direct_enabled, direct_endpoint, direct_advertised \
                 FROM subject_tunnels WHERE id = ?1 AND subject = ?2",
                params![tunnel_id, subject],
                |r| Ok((r.get::<_, i64>(0)? != 0, r.get::<_, Option<String>>(1)?, r.get::<_, i64>(2)? != 0)),
            )
            .optional()
    }

    /// #517 V3: every direct-serving-ENABLED tunnel with an endpoint, as
    /// `(tunnel_id, hostname, endpoint, DirectServingState)` -- the probe loop's
    /// work list. Not owner-scoped (this is the CP's own background sweep, not a
    /// user request). A row with no hostname is skipped (nothing to publish a
    /// record for).
    pub fn direct_serving_candidates(
        &self,
    ) -> rusqlite::Result<Vec<(String, String, String, crate::direct_serving::DirectServingState)>> {
        let conn = self.read();
        let mut stmt = conn.prepare(
            "SELECT id, hostname, direct_endpoint, direct_advertised, direct_failures \
             FROM subject_tunnels \
             WHERE direct_enabled = 1 AND direct_endpoint IS NOT NULL AND hostname IS NOT NULL",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                crate::direct_serving::DirectServingState {
                    advertised: r.get::<_, i64>(3)? != 0,
                    consecutive_failures: r.get::<_, i64>(4)? as u32,
                },
            ))
        })?;
        rows.collect()
    }

    /// #517 V3: persist the post-probe hysteresis state for one tunnel (the CP
    /// loop calls this after `fold_probe`), stamping the probe time. Not
    /// owner-scoped -- same background-sweep rationale as
    /// [`direct_serving_candidates`](Self::direct_serving_candidates).
    pub fn record_direct_probe(
        &self,
        tunnel_id: &str,
        state: crate::direct_serving::DirectServingState,
        now: u64,
    ) -> rusqlite::Result<()> {
        self.writer.lock_safe().execute(
            "UPDATE subject_tunnels SET direct_advertised = ?1, direct_failures = ?2, \
             direct_probed_at = ?3 WHERE id = ?4",
            params![state.advertised as i64, state.consecutive_failures as i64, now as i64, tunnel_id],
        )?;
        Ok(())
    }

    /// #501: whether "any authenticated account" mode is on for a tunnel the caller
    /// owns (`None` if unknown/foreign) -- for rendering the portal checkbox.
    pub fn allow_any_login(&self, subject: &str, tunnel_id: &str) -> rusqlite::Result<Option<bool>> {
        self.read()
            .query_row(
                "SELECT allow_any_login FROM subject_tunnels WHERE id = ?1 AND subject = ?2",
                params![tunnel_id, subject],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map(|v| v.map(|n| n != 0))
    }

    /// #501: the gate-path lookup, hostname-keyed like
    /// [`require_login_for_hostname`](Self::require_login_for_hostname) and with the
    /// same #393 `COLLATE NOCASE` reasoning. A false `false` here only ever makes the
    /// gate STRICTER (falls back to the allow-list), never more permissive.
    pub fn allow_any_login_for_hostname(&self, hostname: &str) -> rusqlite::Result<bool> {
        Ok(self
            .read()
            .query_row(
                "SELECT allow_any_login FROM subject_tunnels WHERE hostname = ?1 COLLATE NOCASE",
                params![hostname],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .map(|n| n != 0)
            .unwrap_or(false))
    }

    /// Add `email` to the login gate's allow-list for a tunnel the caller owns
    /// (#382-follow), keyed by the tunnel's current hostname. `false` if the id
    /// is unknown, owned by someone else, or has no hostname yet.
    pub fn login_allowlist_add(
        &self,
        subject: &str,
        tunnel_id: &str,
        email: &str,
        now: u64,
    ) -> rusqlite::Result<bool> {
        let conn = self.writer.lock_safe();
        let hostname: Option<String> = conn
            .query_row(
                "SELECT hostname FROM subject_tunnels WHERE id = ?1 AND subject = ?2",
                params![tunnel_id, subject],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let Some(hostname) = hostname else { return Ok(false) };
        conn.execute(
            "INSERT OR REPLACE INTO tunnel_login_allowlist (hostname, email, added_by, added_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params![hostname, email.to_ascii_lowercase(), subject, now as i64],
        )?;
        Ok(true)
    }

    /// Remove `email` from a tunnel's login-gate allow-list (#382-follow),
    /// owner-scoped like [`login_allowlist_add`](Self::login_allowlist_add).
    pub fn login_allowlist_remove(&self, subject: &str, tunnel_id: &str, email: &str) -> rusqlite::Result<bool> {
        let conn = self.writer.lock_safe();
        let hostname: Option<String> = conn
            .query_row(
                "SELECT hostname FROM subject_tunnels WHERE id = ?1 AND subject = ?2",
                params![tunnel_id, subject],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let Some(hostname) = hostname else { return Ok(false) };
        conn.execute(
            "DELETE FROM tunnel_login_allowlist WHERE hostname = ?1 AND email = ?2",
            params![hostname, email.to_ascii_lowercase()],
        )?;
        Ok(true)
    }

    /// List a tunnel's login-gate allow-listed emails (#382-follow), owner-scoped:
    /// `None` if the id is unknown, owned by someone else, or has no hostname yet.
    pub fn login_allowlist_list(&self, subject: &str, tunnel_id: &str) -> rusqlite::Result<Option<Vec<String>>> {
        let conn = self.read();
        let hostname: Option<String> = conn
            .query_row(
                "SELECT hostname FROM subject_tunnels WHERE id = ?1 AND subject = ?2",
                params![tunnel_id, subject],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let Some(hostname) = hostname else { return Ok(None) };
        let mut stmt =
            conn.prepare("SELECT email FROM tunnel_login_allowlist WHERE hostname = ?1 ORDER BY added_at ASC")?;
        let rows = stmt.query_map(params![hostname], |r| r.get::<_, String>(0))?;
        Ok(Some(rows.collect::<rusqlite::Result<Vec<_>>>()?))
    }

    /// Whether `email` is allow-listed for `hostname`'s login gate (#382-follow).
    /// Unscoped like [`require_login_for_hostname`](Self::require_login_for_hostname)
    /// -- the one check `GET /portal/callback` needs after a successful gate login.
    /// #393: same reasoning as [`require_login_for_hostname`](Self::require_login_for_hostname)
    /// -- `hostname` is caller-supplied, matched case-insensitively against
    /// whichever casing `login_allowlist_add` originally stored (it always
    /// mirrors `subject_tunnels.hostname`'s own casing at add-time, which may
    /// predate this fix).
    pub fn email_allowed_for_hostname(&self, hostname: &str, email: &str) -> rusqlite::Result<bool> {
        Ok(self
            .read()
            .query_row(
                "SELECT 1 FROM tunnel_login_allowlist WHERE hostname = ?1 COLLATE NOCASE AND email = ?2",
                params![hostname, email.to_ascii_lowercase()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Record a self-service access-request for a gated hostname (#382-follow,
    /// issue #18): a visitor who fails `GET /gate/callback`'s allow-list check
    /// otherwise had no real next step. Only accepted for a hostname that
    /// currently has the login gate enabled -- rejects everything else so this
    /// can't be used to leave requests against an arbitrary, non-gated
    /// hostname (or a typo'd/nonexistent one). Idempotent per (hostname,
    /// email): resubmitting refreshes the note/timestamp, never grows an
    /// unbounded duplicate queue.
    /// #431: bound on distinct pending access requests per hostname -- resubmits
    /// under the same email are idempotent and never count against this, only
    /// genuinely distinct emails do.
    const MAX_PENDING_ACCESS_REQUESTS_PER_HOSTNAME: i64 = 500;

    pub fn record_access_request(&self, hostname: &str, email: &str, note: &str, now: u64) -> rusqlite::Result<bool> {
        if !self.require_login_for_hostname(hostname)? {
            return Ok(false);
        }
        let conn = self.writer.lock_safe();
        conn.execute(
            "INSERT INTO gate_access_requests (hostname, email, note, requested_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(hostname, email) DO UPDATE SET note = excluded.note, requested_at = excluded.requested_at",
            params![hostname, email.to_ascii_lowercase(), note, now as i64],
        )?;
        conn.execute(
            "DELETE FROM gate_access_requests WHERE hostname = ?1 AND email NOT IN (
                 SELECT email FROM gate_access_requests WHERE hostname = ?1
                 ORDER BY requested_at DESC LIMIT ?2
             )",
            params![hostname, Self::MAX_PENDING_ACCESS_REQUESTS_PER_HOSTNAME],
        )?;
        Ok(true)
    }

    /// Pending self-service access requests for a tunnel the caller owns
    /// (#382-follow), owner-scoped like
    /// [`login_allowlist_list`](Self::login_allowlist_list): `None` if the id is
    /// unknown, owned by someone else, or has no hostname yet. Oldest first, so
    /// the owner reviews in the order requests actually arrived.
    pub fn pending_access_requests(&self, subject: &str, tunnel_id: &str) -> rusqlite::Result<Option<Vec<(String, String, i64)>>> {
        let conn = self.read();
        let hostname: Option<String> = conn
            .query_row(
                "SELECT hostname FROM subject_tunnels WHERE id = ?1 AND subject = ?2",
                params![tunnel_id, subject],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let Some(hostname) = hostname else { return Ok(None) };
        // #393: gate_access_requests rows were written under the GATE's own caller-
        // supplied hostname casing (record_access_request), which may not match
        // subject_tunnels' canonical casing fetched above -- COLLATE NOCASE so a
        // request never silently goes missing from the owner's own pending-requests
        // view over a casing mismatch.
        let mut stmt = conn.prepare(
            "SELECT email, note, requested_at FROM gate_access_requests WHERE hostname = ?1 COLLATE NOCASE ORDER BY requested_at ASC",
        )?;
        let rows = stmt.query_map(params![hostname], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?))
        })?;
        Ok(Some(rows.collect::<rusqlite::Result<Vec<_>>>()?))
    }

    /// #437: batched form of [`Self::require_login`] for the tunnels-page render
    /// loop -- one query for every row instead of one query per row. Keyed by
    /// tunnel id; a row with no entry means "off" (matching the original's
    /// `unwrap_or(false)` caller-side default).
    /// #501: returns `(require_login, allow_any_login)` per tunnel in one query --
    /// the tunnels-page render needs both checkboxes' state anyway.
    pub fn require_login_batch(
        &self,
        subject: &str,
        tunnel_ids: &[&str],
    ) -> rusqlite::Result<std::collections::HashMap<String, (bool, bool)>> {
        if tunnel_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let conn = self.read();
        let placeholders = std::iter::repeat("?").take(tunnel_ids.len()).collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT id, require_login, allow_any_login FROM subject_tunnels WHERE subject = ?1 AND id IN ({placeholders})"
        );
        let mut stmt = conn.prepare(&sql)?;
        let params_iter = std::iter::once(subject).chain(tunnel_ids.iter().copied());
        let rows = stmt.query_map(rusqlite::params_from_iter(params_iter), |r| {
            Ok((r.get::<_, String>(0)?, (r.get::<_, i64>(1)? != 0, r.get::<_, i64>(2)? != 0)))
        })?;
        rows.collect()
    }

    /// #437: batched form of [`Self::login_allowlist_list`] +
    /// [`Self::pending_access_requests`] together for the tunnels-page render loop
    /// -- both derive from the same owned-tunnel id->hostname mapping, so one pass
    /// resolves it and two `IN (...)` queries (instead of one query per tunnel per
    /// concern) fetch the allowlist and pending requests for every hostname at
    /// once. Keyed by tunnel id, matching the per-row lookup callers already do;
    /// a row with no entry means "no hostname yet" (same as the originals'
    /// `Option` return narrowing to empty-default at the call site).
    pub fn allowlist_and_pending_batch(
        &self,
        subject: &str,
        tunnel_ids: &[&str],
    ) -> rusqlite::Result<std::collections::HashMap<String, (Vec<String>, Vec<(String, String, i64)>)>> {
        if tunnel_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let conn = self.read();
        let placeholders = std::iter::repeat("?").take(tunnel_ids.len()).collect::<Vec<_>>().join(",");
        let id_hostname_sql =
            format!("SELECT id, hostname FROM subject_tunnels WHERE subject = ?1 AND id IN ({placeholders})");
        let mut stmt = conn.prepare(&id_hostname_sql)?;
        let params_iter = std::iter::once(subject).chain(tunnel_ids.iter().copied());
        let id_to_hostname: Vec<(String, Option<String>)> = stmt
            .query_map(rusqlite::params_from_iter(params_iter), |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let hostnames: Vec<&str> = id_to_hostname.iter().filter_map(|(_, h)| h.as_deref()).collect();
        let mut out = std::collections::HashMap::with_capacity(id_to_hostname.len());
        if hostnames.is_empty() {
            for (id, _) in id_to_hostname {
                out.insert(id, (Vec::new(), Vec::new()));
            }
            return Ok(out);
        }

        let host_placeholders = std::iter::repeat("?").take(hostnames.len()).collect::<Vec<_>>().join(",");
        let allow_sql = format!(
            "SELECT hostname, email FROM tunnel_login_allowlist WHERE hostname IN ({host_placeholders}) ORDER BY added_at ASC"
        );
        let mut allow_by_host: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
        {
            let mut stmt = conn.prepare(&allow_sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(hostnames.iter()), |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (hostname, email) = row?;
                allow_by_host.entry(hostname.to_ascii_lowercase()).or_default().push(email);
            }
        }

        let pending_sql = format!(
            "SELECT hostname, email, note, requested_at FROM gate_access_requests
             WHERE hostname IN ({host_placeholders}) COLLATE NOCASE ORDER BY requested_at ASC"
        );
        let mut pending_by_host: std::collections::HashMap<String, Vec<(String, String, i64)>> =
            std::collections::HashMap::new();
        {
            let mut stmt = conn.prepare(&pending_sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(hostnames.iter()), |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?))
            })?;
            for row in rows {
                let (hostname, email, note, requested_at) = row?;
                pending_by_host.entry(hostname.to_ascii_lowercase()).or_default().push((email, note, requested_at));
            }
        }

        for (id, hostname) in id_to_hostname {
            let key = hostname.map(|h| h.to_ascii_lowercase());
            let allow = key.as_ref().and_then(|k| allow_by_host.get(k)).cloned().unwrap_or_default();
            let pending = key.as_ref().and_then(|k| pending_by_host.get(k)).cloned().unwrap_or_default();
            out.insert(id, (allow, pending));
        }
        Ok(out)
    }

    /// Dismiss a pending access request (#382-follow), owner-scoped like
    /// [`pending_access_requests`](Self::pending_access_requests). Used both
    /// when the owner explicitly declines a request and, from
    /// `login_allowlist_add_route`, to clear a request once its email has
    /// actually been granted access so it doesn't linger as "pending" after
    /// being satisfied.
    pub fn dismiss_access_request(&self, subject: &str, tunnel_id: &str, email: &str) -> rusqlite::Result<bool> {
        let conn = self.writer.lock_safe();
        let hostname: Option<String> = conn
            .query_row(
                "SELECT hostname FROM subject_tunnels WHERE id = ?1 AND subject = ?2",
                params![tunnel_id, subject],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let Some(hostname) = hostname else { return Ok(false) };
        // #393: same reasoning as pending_access_requests just above.
        let n = conn.execute(
            "DELETE FROM gate_access_requests WHERE hostname = ?1 COLLATE NOCASE AND email = ?2",
            params![hostname, email.to_ascii_lowercase()],
        )?;
        Ok(n > 0)
    }

    /// The routing token of a tunnel `subject` is **authorized** to use — as its
    /// owner or via a grant (#29) — or `None` otherwise. This is what lets a
    /// grantee obtain the shared tunnel's install/connection material, giving a
    /// grant real effect rather than only bookkeeping.
    pub fn routing_token_if_authorized(
        &self,
        subject: &str,
        tunnel_id: &str,
    ) -> rusqlite::Result<Option<String>> {
        let conn = self.read();
        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT subject, routing_token FROM subject_tunnels WHERE id = ?1",
                params![tunnel_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((owner, token)) = row else {
            return Ok(None);
        };
        if owner == subject {
            return Ok(Some(token));
        }
        let granted = Self::has_grant(&conn, tunnel_id, subject)?.then_some(1i64);
        Ok(granted.map(|_| token))
    }

    /// The public hostname of a tunnel `subject` is **authorized** to use — same
    /// owner-or-grantee rule as [`Self::routing_token_if_authorized`] — or `None`
    /// if unauthorized, unknown, or the tunnel simply has no hostname assigned
    /// (a Mesh-Plane-only tunnel). Lets the install page hand the agent its own
    /// already-assigned hostname instead of the agent copying it by hand from
    /// the tunnels list.
    pub fn hostname_if_authorized(
        &self,
        subject: &str,
        tunnel_id: &str,
    ) -> rusqlite::Result<Option<String>> {
        let conn = self.read();
        let row: Option<(String, Option<String>)> = conn
            .query_row(
                "SELECT subject, hostname FROM subject_tunnels WHERE id = ?1",
                params![tunnel_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((owner, hostname)) = row else {
            return Ok(None);
        };
        if owner == subject {
            return Ok(hostname);
        }
        let granted = Self::has_grant(&conn, tunnel_id, subject)?.then_some(1i64);
        Ok(granted.and(hostname))
    }

    /// List every tunnel `subject` is authorized to use — the ones they own plus
    /// the ones shared with them (#29) — each flagged with whether they own it
    /// (owned tunnels get the management actions; shared ones are read-only).
    pub fn list_authorized_for_subject(
        &self,
        subject: &str,
    ) -> rusqlite::Result<Vec<(SubjectTunnel, bool)>> {
        let conn = self.read();
        let mut stmt = conn.prepare(
            "SELECT id, name, hostname, created_at, routing_token, subject = ?1
             FROM subject_tunnels
             WHERE subject = ?1
                OR id IN (SELECT tunnel_id FROM tunnel_grants WHERE grantee = ?1)
             ORDER BY created_at DESC, id",
        )?;
        let rows = stmt.query_map(params![subject], |r| {
            Ok((
                SubjectTunnel {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    hostname: r.get(2)?,
                    created_at: r.get(3)?,
                    routing_token: r.get(4)?,
                },
                r.get::<_, i64>(5)? != 0,
            ))
        })?;
        rows.collect()
    }

    /// The routing token bound to `hostname`, unscoped by subject (#233): the
    /// admission broker/loop operates on hostnames directly (it isn't acting
    /// on behalf of any particular logged-in customer), so it needs the
    /// token to push a channel-tier update to the edge the same way
    /// [`crate::portal_api`]'s `authorize_hostname` already does. Mirrors
    /// [`Self::all`]'s "admin/migration read, deliberately not customer-facing"
    /// precedent rather than reusing the owner-scoped lookups above.
    pub fn routing_token_for_hostname(&self, hostname: &str) -> rusqlite::Result<Option<String>> {
        self.read()
            .query_row(
                "SELECT routing_token FROM subject_tunnels WHERE hostname = ?1",
                params![hostname],
                |r| r.get(0),
            )
            .optional()
    }

    /// Rot/Gelb/Grün certificate-tier state for `hostname` (#233), or `None`
    /// if no tunnel has this hostname. `queue_position` counts only rows
    /// genuinely ahead in line (status='gelb', claim_state='none', earlier
    /// `queued_at`) and is `None` once a claim has been offered or the
    /// hostname is already `gruen` -- a queue position stops meaning anything
    /// the moment a hostname leaves the "waiting" sub-state.
    pub fn cert_admission_for_hostname(&self, hostname: &str) -> rusqlite::Result<Option<CertAdmission>> {
        let conn = self.read();
        let row: Option<(String, Option<String>, String, Option<i64>, Option<i64>)> = conn
            .query_row(
                "SELECT status, assigned_ca, claim_state, claim_deadline, queued_at
                 FROM subject_tunnels WHERE hostname = ?1",
                params![hostname],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        let Some((status, assigned_ca, claim_state, claim_deadline, queued_at)) = row else {
            return Ok(None);
        };
        let queue_position = if status == "gelb" && claim_state == "none" {
            match queued_at {
                Some(qa) => Some(conn.query_row(
                    "SELECT COUNT(*) FROM subject_tunnels
                     WHERE status = 'gelb' AND claim_state = 'none' AND queued_at < ?1",
                    params![qa],
                    |r| r.get(0),
                )?),
                None => None,
            }
        } else {
            None
        };
        Ok(Some(CertAdmission { status, assigned_ca, claim_state, claim_deadline, queue_position }))
    }

    /// Batched form of [`Self::cert_admission_for_hostname`] (#351): a page rendering N
    /// tunnel rows was calling the single-hostname lookup once per row (up to 2N queries
    /// once the `queue_position` sub-query is counted) -- N sequential round trips that
    /// grow with the number of tunnels a page shows, instead of one. Fetches every
    /// requested hostname's row in a single `WHERE hostname IN (...)`, and computes
    /// `queue_position` for the whole batch from one sorted list of queued timestamps
    /// (`partition_point` on a sorted-ascending list is the same count a per-row
    /// `COUNT(*) WHERE queued_at < ?` would produce) instead of one `COUNT(*)` per row.
    /// Two queries total, regardless of how many hostnames are asked for.
    pub fn cert_admission_for_hostnames(
        &self,
        hostnames: &[&str],
    ) -> rusqlite::Result<std::collections::HashMap<String, CertAdmission>> {
        if hostnames.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let conn = self.read();
        let placeholders = std::iter::repeat("?").take(hostnames.len()).collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT hostname, status, assigned_ca, claim_state, claim_deadline, queued_at
             FROM subject_tunnels WHERE hostname IN ({placeholders})"
        );
        let rows: Vec<(String, String, Option<String>, String, Option<i64>, Option<i64>)> = conn
            .prepare(&sql)?
            .query_map(rusqlite::params_from_iter(hostnames.iter()), |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut queued_ats: Vec<i64> = conn
            .prepare(
                "SELECT queued_at FROM subject_tunnels
                 WHERE status = 'gelb' AND claim_state = 'none' AND queued_at IS NOT NULL",
            )?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<i64>>>()?;
        queued_ats.sort_unstable();

        let mut out = std::collections::HashMap::with_capacity(rows.len());
        for (hostname, status, assigned_ca, claim_state, claim_deadline, queued_at) in rows {
            let queue_position = if status == "gelb" && claim_state == "none" {
                queued_at.map(|qa| queued_ats.partition_point(|&x| x < qa) as i64)
            } else {
                None
            };
            out.insert(
                hostname,
                CertAdmission { status, assigned_ca, claim_state, claim_deadline, queue_position },
            );
        }
        Ok(out)
    }

    /// Flip a hostname from Rot to Gelb, entering the admission queue for the
    /// first time (`queued_at = now`). No-op (`Ok(false)`) unless the
    /// hostname is currently `rot` -- callers must not clobber later state.
    pub fn enter_gelb_queue(&self, hostname: &str, now: i64) -> rusqlite::Result<bool> {
        let affected = self.writer.lock_safe().execute(
            "UPDATE subject_tunnels SET status = 'gelb', queued_at = ?2
             WHERE hostname = ?1 AND status = 'rot'",
            params![hostname, now],
        )?;
        Ok(affected > 0)
    }

    /// Every hostname still `rot` -- candidates for the admission loop's
    /// Rot->Gelb safety-net sweep. The caller cross-checks each against the
    /// edge_mesh/edge-authorization side effects that actually make a
    /// hostname reachable before calling [`Self::enter_gelb_queue`]; this
    /// store has no visibility into that, deliberately (edge_mesh is a
    /// separate database with a separate concern).
    pub fn rot_hostnames(&self) -> rusqlite::Result<Vec<String>> {
        let conn = self.read();
        let mut stmt =
            conn.prepare("SELECT hostname FROM subject_tunnels WHERE status = 'rot' AND hostname IS NOT NULL")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect()
    }

    /// Every hostname currently in the Gelb tier, any `claim_state` (#229
    /// follow-up: `EdgeState::gelb_hosts` is edge-local, in-memory, and has no
    /// rehydration on restart, unlike the host-authorization map -- an edge
    /// restart silently drops every host back to ordinary SNI passthrough,
    /// which forwards raw TLS bytes to a Gelb-tier's plain-HTTP origin. The
    /// admission sweep re-affirms `channel_tier=gelb` for every row here on each tick
    /// so that gap self-heals within one tick of any edge restart, current or
    /// future, without a new edge-side rehydration protocol.
    pub fn gelb_hostnames(&self) -> rusqlite::Result<Vec<String>> {
        let conn = self.read();
        let mut stmt =
            conn.prepare("SELECT hostname FROM subject_tunnels WHERE status = 'gelb' AND hostname IS NOT NULL")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect()
    }

    /// Hostnames queued (Gelb, unclaimed, unassigned) in strict FIFO order --
    /// the admission sweep's candidate list, oldest `queued_at` first.
    pub fn gelb_queue_fifo(&self) -> rusqlite::Result<Vec<String>> {
        let conn = self.read();
        let mut stmt = conn.prepare(
            "SELECT hostname FROM subject_tunnels
             WHERE status = 'gelb' AND claim_state = 'none' AND assigned_ca IS NULL
             ORDER BY queued_at ASC",
        )?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect()
    }

    /// Offer a claim slot: assign `ca` permanently (nothing else in this store
    /// ever rewrites `assigned_ca` once set -- enforced here by only applying
    /// to a row where it is still `NULL`), open the caller-supplied 48h
    /// window. Returns `false` if the hostname already had a CA assigned
    /// (already offered or already `gruen`) -- a race-safe no-op, not an error.
    pub fn offer_claim(&self, hostname: &str, ca: &str, now: i64, deadline: i64) -> rusqlite::Result<bool> {
        let affected = self.writer.lock_safe().execute(
            "UPDATE subject_tunnels
             SET assigned_ca = ?2, claim_state = 'offered', claim_offered_at = ?3, claim_deadline = ?4
             WHERE hostname = ?1 AND assigned_ca IS NULL",
            params![hostname, ca, now, deadline],
        )?;
        Ok(affected > 0)
    }

    /// Expire every offer whose deadline has passed: clears `assigned_ca` (an
    /// unclaimed offer never consumed real CA capacity, so it must not count
    /// against the "CA assignment is permanent" invariant, which only applies
    /// once a hostname actually completes an issuance) and marks the row
    /// `lapsed`, awaiting an explicit customer re-request. Returns the number
    /// of rows lapsed this sweep.
    pub fn lapse_expired_claims(&self, now: i64) -> rusqlite::Result<usize> {
        self.writer.lock_safe().execute(
            "UPDATE subject_tunnels
             SET claim_state = 'lapsed', assigned_ca = NULL, claim_offered_at = NULL, claim_deadline = NULL
             WHERE claim_state = 'offered' AND claim_deadline < ?1",
            params![now],
        )
    }

    /// Explicit customer re-request after a lapse (#233): back of the queue,
    /// fresh `queued_at`. Deliberately never preserves the old position --
    /// otherwise a customer who simply never claims could keep a permanent
    /// front-of-queue slot for free. No-op (`Ok(false)`) unless the hostname
    /// is both owned by `subject` and actually `lapsed` -- can't be used to
    /// jump a still-waiting, already-offered, or already-`gruen` hostname.
    pub fn reclaim_cert_slot(&self, subject: &str, hostname: &str, now: i64) -> rusqlite::Result<bool> {
        let affected = self.writer.lock_safe().execute(
            "UPDATE subject_tunnels
             SET claim_state = 'none', queued_at = ?3
             WHERE hostname = ?1 AND subject = ?2 AND claim_state = 'lapsed'",
            params![hostname, subject, now],
        )?;
        Ok(affected > 0)
    }

    /// Record a completed issuance (#233): flips the hostname to `gruen`
    /// permanently and appends one row to the rate-limit ledger, using
    /// whichever CA this store itself had assigned -- **never** trusting a
    /// CA name the caller (the agent) might supply, so a compromised or
    /// buggy agent cannot misattribute its issuance to a different CA's
    /// budget. Renewals call this again too; that is a harmless idempotent
    /// re-affirmation of `status`/claim fields plus one more (correct) ledger
    /// row, since a renewal *does* consume real CA capacity again. Returns
    /// the CA the ledger entry was recorded against, or `None` if this
    /// hostname somehow had no `assigned_ca` (defensive; should not happen
    /// for a hostname that reached `gelb`+`offered`).
    /// #293: the status flip and the ledger insert run in one transaction --
    /// previously two separate auto-committed statements, so a crash between
    /// them left a hostname permanently `gruen` with no matching
    /// `acme_issuance_log` row. That silently undercounted the CA's real
    /// usage in [`Self::ca_budget_usage`], letting the admission sweep
    /// over-issue against that CA's actual rate limit. Now either both land
    /// or neither does.
    /// #261: only actually flips a hostname to `gruen` if it was in a state where
    /// completing issuance makes sense -- already `gruen` (a renewal's harmless
    /// idempotent re-affirmation, per this fn's own doc above) or `gelb` with a
    /// live `offered` claim (a real admission window this hostname was actually
    /// given). Without this guard, `issuance_complete`'s only real authorization is
    /// "caller holds this hostname's routing token" -- the same token an agent
    /// uses for every other tunnel operation -- so a buggy or malicious agent
    /// could flip straight from `rot` (never even offered a CA) to `gruen`,
    /// which reverts the edge to origin-passthrough for a hostname with no real
    /// certificate: a self-inflicted TLS-handshake outage the DB would then
    /// falsely report as a successful issuance. Returns `Ok(None)` (no ledger
    /// row, no state change) when the precondition isn't met, distinct from the
    /// pre-existing `Ok(None)` for "no assigned_ca on an otherwise-valid row" --
    /// callers that need to tell those apart should check current state first,
    /// same as the guard here does.
    pub fn record_issuance_complete(
        &self,
        hostname: &str,
        domain: &str,
        now: i64,
    ) -> rusqlite::Result<Option<String>> {
        let mut guard = self.writer.lock_safe();
        let tx = guard.transaction()?;
        let ca: Option<String> = tx
            .query_row(
                "SELECT assigned_ca FROM subject_tunnels WHERE hostname = ?1",
                params![hostname],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let rows = tx.execute(
            "UPDATE subject_tunnels
             SET status = 'gruen', claim_state = 'none', claim_offered_at = NULL, claim_deadline = NULL,
                 pending_revert = 1
             WHERE hostname = ?1 AND (status = 'gruen' OR (status = 'gelb' AND claim_state = 'offered'))",
            params![hostname],
        )?;
        if rows == 0 {
            tx.commit()?;
            return Ok(None);
        }
        if let Some(ca) = &ca {
            // #407: this endpoint can't distinguish a genuine renewal from a replay/retry —
            // the caller is a customer-controlled agent, not the operator, and nothing
            // previously de-duplicated or rate-limited the ledger insert. Once a hostname is
            // gruen, this guard passes forever, so an unbounded flood of "complete" calls
            // for the SAME hostname could exhaust the whole registered domain's shared CA
            // budget bucket, locking out every other tenant for the rest of the window.
            // Real renewals are ~60 days apart, so a same-hostname floor of
            // MIN_ISSUANCE_LOG_INTERVAL_SECS costs nothing legitimate while bounding the
            // worst case to one ledger entry per hostname per floor window regardless of
            // how many times the endpoint is hit.
            let recent: Option<i64> = tx
                .query_row(
                    "SELECT issued_at FROM acme_issuance_log WHERE hostname = ?1 ORDER BY issued_at DESC LIMIT 1",
                    params![hostname],
                    |r| r.get(0),
                )
                .optional()?;
            let already_logged_recently =
                recent.is_some_and(|last| now.saturating_sub(last) < MIN_ISSUANCE_LOG_INTERVAL_SECS);
            if !already_logged_recently {
                tx.execute(
                    "INSERT INTO acme_issuance_log (ca, domain, hostname, issued_at) VALUES (?1, ?2, ?3, ?4)",
                    params![ca, domain, hostname, now],
                )?;
            }
        }
        tx.commit()?;
        Ok(ca)
    }

    /// Every Gruen hostname whose `channel_tier=gelb=false` revert push to the edge
    /// hasn't been confirmed successful yet (#264): `issuance_complete`'s push is
    /// best-effort, and a failure (network blip, edge 5xx) used to just get logged
    /// and forgotten -- the DB said Gruen while the edge kept terminating with the
    /// shared wildcard cert forever, since the sweep only ever re-affirmed Gelb
    /// hosts, never reconciled a stuck-Gelb-on-the-edge Gruen host. The admission
    /// sweep retries every row here each tick until [`Self::clear_pending_revert`]
    /// confirms one actually landed.
    pub fn pending_revert_hostnames(&self) -> rusqlite::Result<Vec<String>> {
        let conn = self.read();
        let mut stmt = conn.prepare(
            "SELECT hostname FROM subject_tunnels WHERE status = 'gruen' AND pending_revert = 1 AND hostname IS NOT NULL",
        )?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect()
    }

    /// Mark `hostname`'s edge revert push as confirmed (#264) -- called once
    /// [`crate::acme_broker::push_channel_tier`] reports success, so
    /// [`Self::pending_revert_hostnames`] stops retrying it.
    pub fn clear_pending_revert(&self, hostname: &str) -> rusqlite::Result<()> {
        self.writer
            .lock_safe()
            .execute("UPDATE subject_tunnels SET pending_revert = 0 WHERE hostname = ?1", params![hostname])?;
        Ok(())
    }

    /// How many certificates `ca` has issued for `domain` in the trailing
    /// window starting at `since` (completed issuances only, per
    /// [`Self::record_issuance_complete`]'s status as the sole ledger-write
    /// path), plus how many currently-`offered` reservations exist for that
    /// CA -- an offer is a real, if not-yet-consumed, claim on that CA's
    /// budget, and must count against headroom just as much as a completed
    /// issuance so the admission sweep never over-commits a CA's real limit.
    pub fn ca_budget_usage(&self, ca: &str, domain: &str, since: i64) -> rusqlite::Result<(i64, i64)> {
        let conn = self.read();
        let used: i64 = conn.query_row(
            "SELECT COUNT(*) FROM acme_issuance_log WHERE ca = ?1 AND domain = ?2 AND issued_at >= ?3",
            params![ca, domain, since],
            |r| r.get(0),
        )?;
        // #469: `used` is scoped by `domain`, but this was not -- both this function's
        // own doc and its caller treat the two halves as equally per-domain, so they
        // agreed by coincidence in a single-zone deployment. `subject_tunnels` has no
        // `domain` column to filter by directly (only `hostname`), so -- mirroring this
        // crate's own established pattern of a small pure helper duplicated per module
        // rather than shared across one (`acme_broker::registered_domain`,
        // `dns01_challenge::dns01_record_name`) -- fetch the hostnames of in-flight
        // offers and filter in application code, same idea as #405/#464's approach for
        // an unindexable predicate.
        let mut stmt = conn.prepare(
            "SELECT hostname FROM subject_tunnels WHERE assigned_ca = ?1 AND claim_state = 'offered'",
        )?;
        let reserved = stmt
            .query_map(params![ca], |r| r.get::<_, Option<String>>(0))?
            .filter_map(|h| h.ok().flatten())
            .filter(|h| registered_domain(h) == domain)
            .count() as i64;
        Ok((used, reserved))
    }

    /// The owner subject of a tunnel, or `None` if the id is unknown.
    fn owner_of(conn: &Connection, tunnel_id: &str) -> rusqlite::Result<Option<String>> {
        conn.query_row(
            "SELECT subject FROM subject_tunnels WHERE id = ?1",
            params![tunnel_id],
            |r| r.get(0),
        )
        .optional()
    }

    /// Grant `grantee` access to a tunnel the caller owns (#29). Idempotent —
    /// re-granting the same subject is a no-op. Fails with
    /// [`GrantError::NotOwner`] unless `owner` actually owns `tunnel_id`.
    pub fn grant(&self, owner: &str, tunnel_id: &str, grantee: &str) -> Result<(), GrantError> {
        let conn = self.writer.lock_safe();
        match Self::owner_of(&conn, tunnel_id)? {
            Some(s) if s == owner => {}
            _ => return Err(GrantError::NotOwner),
        }
        conn.execute(
            "INSERT OR IGNORE INTO tunnel_grants (tunnel_id, grantee) VALUES (?1, ?2)",
            params![tunnel_id, grantee],
        )?;
        Ok(())
    }

    /// Revoke a subject's grant on a tunnel the caller owns. Returns `true` if a
    /// grant was removed. Fails with [`GrantError::NotOwner`] for non-owners.
    pub fn revoke_grant(
        &self,
        owner: &str,
        tunnel_id: &str,
        grantee: &str,
    ) -> Result<bool, GrantError> {
        let conn = self.writer.lock_safe();
        match Self::owner_of(&conn, tunnel_id)? {
            Some(s) if s == owner => {}
            _ => return Err(GrantError::NotOwner),
        }
        let affected = conn.execute(
            "DELETE FROM tunnel_grants WHERE tunnel_id = ?1 AND grantee = ?2",
            params![tunnel_id, grantee],
        )?;
        Ok(affected > 0)
    }

    /// List the subjects granted access to a tunnel the caller owns, sorted.
    /// Fails with [`GrantError::NotOwner`] for non-owners (so a non-owner cannot
    /// even enumerate who a tunnel is shared with).
    pub fn list_grants(&self, owner: &str, tunnel_id: &str) -> Result<Vec<String>, GrantError> {
        let conn = self.read();
        match Self::owner_of(&conn, tunnel_id)? {
            Some(s) if s == owner => {}
            _ => return Err(GrantError::NotOwner),
        }
        let mut stmt = conn.prepare(
            "SELECT grantee FROM tunnel_grants WHERE tunnel_id = ?1 ORDER BY grantee",
        )?;
        let rows = stmt.query_map(params![tunnel_id], |r| r.get(0))?;
        rows.collect::<rusqlite::Result<Vec<String>>>().map_err(GrantError::Db)
    }

    /// Does `subject` hold a grant on `tunnel_id` (#578)?
    ///
    /// The owner-or-grantee rule existed as three byte-identical `SELECT 1 FROM
    /// tunnel_grants` copies plus a fourth, set-shaped one in
    /// [`Self::list_authorized_for_subject`]. Three of them are now this helper. The
    /// fourth cannot be (it filters a list rather than answering about one subject), so
    /// `every_tunnel_authorization_path_agrees_578` pins all four against each other --
    /// a rule spread across copies diverges silently, and the copy that reads like the
    /// canonical one ([`Self::is_authorized`]) is the one no production path calls.
    fn has_grant(
        conn: &rusqlite::Connection,
        tunnel_id: &str,
        subject: &str,
    ) -> rusqlite::Result<bool> {
        let row: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM tunnel_grants WHERE tunnel_id = ?1 AND grantee = ?2",
                params![tunnel_id, subject],
                |r| r.get(0),
            )
            .optional()?;
        Ok(row.is_some())
    }

    /// Whether `subject` may use `tunnel_id`: `true` if it is the owner or holds
    /// a grant (#29) — `false` for an unknown tunnel.
    ///
    /// **Not the live gate, despite reading like it (#578).** This said "the authorization
    /// gate for capability access to a shared tunnel" while having no production caller
    /// anywhere in the workspace; the paths that actually gate access are
    /// [`Self::routing_token_if_authorized`] and [`Self::hostname_if_authorized`], and
    /// [`Self::list_authorized_for_subject`] expresses the same rule set-shaped. Tightening
    /// the rule here alone would change nothing in production, which is exactly the mistake
    /// the old wording invited. `every_tunnel_authorization_path_agrees_578` holds all four
    /// to the same answer.
    pub fn is_authorized(&self, subject: &str, tunnel_id: &str) -> rusqlite::Result<bool> {
        let conn = self.read();
        if Self::owner_of(&conn, tunnel_id)?.as_deref() == Some(subject) {
            return Ok(true);
        }
        let granted = Self::has_grant(&conn, tunnel_id, subject)?.then_some(1i64);
        Ok(granted.is_some())
    }
}

/// Agent Fabric channel registry (ADR-0020, #72 AF2d). Under **agent-held** key
/// custody the operator agent holds its channel signing key and signs grants; the
/// control plane stores only the operator **public** key + membership, and hands
/// the edge the operator pubkey for a channel (the same role host-auth plays for
/// hostnames). Never stores a channel signing key. Owner-scoped: only the subject
/// that registered a channel may re-key it or manage its members.
///
/// #398: hybrid pooled-reads-single-writer store (#344 pattern; see [`SqliteTunnelStore`]'s
/// struct doc for the full read/write-contention reasoning). [`authorize_holder`]/
/// [`operator_pubkey`] back `POST /internal/channel/authorize` (already wrapped in its own
/// `spawn_blocking`, #140/#231, after a real lock-wait-stall incident under concurrent load) --
/// the per-connection channel-admission gate every Agent-Fabric WS/A2A join hits. Pooling this
/// store's reads attacks the root cause that earlier fix only mitigated (it moved the blocking
/// work off the async worker but didn't stop the store's own `Mutex<Connection>` from
/// serializing every concurrent admission check). Write volume (register/add/remove
/// member/consume invitation/challenge) is comparatively rare -- admin/redemption events, not
/// per-connection -- so every WRITE method still keeps going through `writer`, unchanged.
///
/// [`authorize_holder`]: Self::authorize_holder
/// [`operator_pubkey`]: Self::operator_pubkey
pub struct SqliteChannelStore {
    /// The one connection every WRITE method uses, unchanged in shape from every other
    /// non-migrated store's `conn` field (see the struct doc for why writes stay serialized).
    writer: Mutex<Connection>,
    /// Extra read-only connections for every READ-only method (see [`Self::read`]). `None` for
    /// an in-memory store (see [`SqliteTunnelStore::readers`]'s doc for why).
    readers: Option<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>,
}

/// #514: how a grant deposit attempt resolved -- the two refusals need different
/// HTTP answers (403 vs. 404), so a bare bool won't do.
#[derive(Debug, PartialEq, Eq)]
pub enum GrantDepositOutcome {
    Deposited,
    NotOwner,
    NotAMember,
}

/// Why a self-service claim did or did not land (#577).
///
/// Was a bare `bool` whose `false` the route reported as "this email is not allow-listed".
/// Once a second, unrelated refusal existed, that single word would have named the wrong
/// cause for it -- the caller would be told to ask for an invitation when the real answer is
/// that the holder belongs to someone else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// Membership written (first claim, or the same subject rotating its own key).
    Claimed,
    /// This email is not on the channel's allow-list (covers an unknown channel).
    NotAllowlisted,
    /// This `(channel, holder)` was already claimed by a DIFFERENT portal subject.
    HolderClaimedByAnother,
}

impl ClaimOutcome {
    /// True only for [`ClaimOutcome::Claimed`] -- for call sites that genuinely need the
    /// yes/no and have nothing to say about the reason.
    pub fn claimed(self) -> bool {
        matches!(self, ClaimOutcome::Claimed)
    }
}

impl SqliteChannelStore {
    /// Open (creating if needed) a durable store at `path`, plus a pool of extra read-only
    /// connections (#398; see the struct doc).
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let mut store = Self::from_connection(open_tuned(path)?)?;
        let manager =
            r2d2_sqlite::SqliteConnectionManager::file(path).with_init(|c: &mut Connection| tune_connection(c));
        store.readers = Some(r2d2::Pool::builder().max_size(8).build_unchecked(manager));
        Ok(store)
    }

    /// Open an ephemeral in-memory store (tests / stateless runs). No reader pool (#398) --
    /// every method, read or write, goes through `writer`, exactly like before this migration.
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    /// A connection for a READ-only method (#398; same shape as [`SqliteTunnelStore::read`]).
    fn read(&self) -> ReadConn<'_> {
        match self.readers.as_ref().and_then(|pool| pool.get().ok()) {
            Some(pooled) => ReadConn::Pooled(pooled),
            None => ReadConn::Direct(self.writer.lock_safe()),
        }
    }

    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS channels (
                 channel   BLOB PRIMARY KEY,
                 operator  BLOB NOT NULL,
                 owner     TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS channel_members (
                 channel BLOB NOT NULL,
                 holder  BLOB NOT NULL,
                 PRIMARY KEY (channel, holder)
             );
             CREATE TABLE IF NOT EXISTS consumed_invitations (
                 signature  BLOB PRIMARY KEY,
                 expires_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS channel_challenges (
                 nonce      BLOB PRIMARY KEY,
                 expires_at INTEGER NOT NULL
             );
             -- #462: consume_invitation/consume_challenge each prune with
             -- `WHERE expires_at <= ?1` on every call -- unindexed, that's a full
             -- table scan (plus a write lock) growing linearly with accumulated rows.
             CREATE INDEX IF NOT EXISTS idx_consumed_invitations_expires
                 ON consumed_invitations (expires_at);
             CREATE INDEX IF NOT EXISTS idx_channel_challenges_expires
                 ON channel_challenges (expires_at);",
        )?;
        // #72 AF4 (registry carries the key): each member's X25519 Noise static key,
        // which the peer pins for the direct-path Noise_IK handshake. Additive,
        // nullable migration so an already-deployed channel_members upgrades in place (#44).
        ensure_column(&conn, "channel_members", "noise_pubkey", "BLOB")?;
        // #101 SEC101b: the member's attestation over its Noise key (holder-signed),
        // stored so the edge can relay it and the peer can verify the key is genuine.
        ensure_column(&conn, "channel_members", "noise_attestation", "BLOB")?;
        // #248-follow: additive migration so an already-deployed channel store gains
        // the self-service allow-list table in place, same pattern as #44's `ensure_column`.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS channel_allowlist (
                 channel   BLOB NOT NULL,
                 email     TEXT NOT NULL,
                 added_by  TEXT NOT NULL,
                 added_at  INTEGER NOT NULL,
                 PRIMARY KEY (channel, email)
             );
             -- #463: PRIMARY KEY (channel, email) only helps queries constraining the
             -- leading column; several queries filter on email alone.
             CREATE INDEX IF NOT EXISTS idx_channel_allowlist_email
                 ON channel_allowlist (email);",
        )?;
        // Self-service discoverability follow-up (2026-08-01): an allow-listed
        // person previously had no way to find out *which* channel they'd been
        // granted access to short of being told the raw channel id out of band --
        // the exact gap that kept surfacing as a manual, repeated chat hand-off
        // for real participants. Recording when a claim actually landed lets
        // `channels_for_email` report status (pending / claimed) without needing
        // to guess a not-yet-known holder key. Additive, nullable -- #44 pattern.
        ensure_column(&conn, "channel_allowlist", "claimed_at", "INTEGER")?;
        // #514: persisted, re-fetchable grant delivery -- the structural fix for the
        // sort#26 class (a demo's one-shot in-memory delivery stranding a grant when a
        // redeploy raced the pickup). The channel OWNER (who alone holds the operator
        // private key -- this server never does, it only stores the already-signed
        // grant bytes) deposits a member's signed grant here; the member re-fetches it
        // through its portal session any number of times. A stored grant is useless
        // without the member's private holder key (#81 possession challenge), so this
        // adds no bearer surface.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS channel_grant_deposits (
                 channel      BLOB NOT NULL,
                 holder       BLOB NOT NULL,
                 grant_hex    TEXT NOT NULL,
                 deposited_at INTEGER NOT NULL,
                 PRIMARY KEY (channel, holder)
             );
             -- #514: which portal SUBJECT claimed which holder on which channel --
             -- written at self-service claim time, so a member's portal session can
             -- find its own holders (and their deposited grants) without ever
             -- retyping key material.
             CREATE TABLE IF NOT EXISTS channel_member_subjects (
                 channel    BLOB NOT NULL,
                 holder     BLOB NOT NULL,
                 subject    TEXT NOT NULL,
                 claimed_at INTEGER NOT NULL,
                 PRIMARY KEY (channel, holder)
             );
             CREATE INDEX IF NOT EXISTS idx_channel_member_subjects_subject
                 ON channel_member_subjects (subject);",
        )?;
        Ok(Self {
            writer: Mutex::new(conn),
            readers: None,
        })
    }

    /// Register `channel` operated by `owner`, storing its operator **public** key.
    /// Idempotent for the same owner (re-key allowed); returns `false` without any
    /// change when the channel already exists under a *different* owner.
    pub fn register_channel(
        &self,
        channel: &ChannelId,
        operator_pubkey: &[u8; 32],
        owner: &str,
    ) -> rusqlite::Result<bool> {
        let conn = self.writer.lock_safe();
        let existing: Option<String> = conn
            .query_row(
                "SELECT owner FROM channels WHERE channel = ?1",
                params![&channel.0[..]],
                |r| r.get(0),
            )
            .optional()?;
        if matches!(existing, Some(ref o) if o != owner) {
            return Ok(false);
        }
        conn.execute(
            "INSERT OR REPLACE INTO channels (channel, operator, owner) VALUES (?1, ?2, ?3)",
            params![&channel.0[..], &operator_pubkey[..], owner],
        )?;
        Ok(true)
    }

    /// Like [`Self::register_channel`], but additionally enforces a per-owner
    /// channel-count limit (#113-ui-limits -- channels had NO cap at all before
    /// this, unlike tunnels' `max_tunnels`/`create_if_under_owned_limit`). Deliberately
    /// a separate method rather than widening `register_channel`'s own signature:
    /// that function has 45+ existing call sites (mostly test fixtures seeding an
    /// owned channel, which don't want or need limit enforcement); only the two
    /// real user-facing creation paths (`POST /me/channels`, the portal's New
    /// Channel form) should ever call this one. The count check runs under the
    /// SAME writer lock as the insert (race-free, same reasoning as #432's tunnel
    /// fix), and — matching `register_channel`'s own idempotent-re-key behavior —
    /// re-registering a channel already owned by `owner` is never blocked by the
    /// limit, only genuinely NEW channels are.
    pub fn register_channel_if_under_owned_limit(
        &self,
        channel: &ChannelId,
        operator_pubkey: &[u8; 32],
        owner: &str,
        max: u32,
    ) -> rusqlite::Result<RegisterChannelOutcome> {
        let conn = self.writer.lock_safe();
        let existing: Option<String> = conn
            .query_row(
                "SELECT owner FROM channels WHERE channel = ?1",
                params![&channel.0[..]],
                |r| r.get(0),
            )
            .optional()?;
        if matches!(existing, Some(ref o) if o != owner) {
            return Ok(RegisterChannelOutcome::OwnedByAnother);
        }
        if existing.is_none() {
            let owned_count: u32 =
                conn.query_row("SELECT COUNT(*) FROM channels WHERE owner = ?1", params![owner], |r| r.get(0))?;
            if owned_count >= max {
                return Ok(RegisterChannelOutcome::OverLimit);
            }
        }
        conn.execute(
            "INSERT OR REPLACE INTO channels (channel, operator, owner) VALUES (?1, ?2, ?3)",
            params![&channel.0[..], &operator_pubkey[..], owner],
        )?;
        Ok(RegisterChannelOutcome::Registered)
    }

    /// The operator public key for `channel`, if registered (the edge's lookup).
    pub fn operator_pubkey(&self, channel: &ChannelId) -> rusqlite::Result<Option<[u8; 32]>> {
        let raw: Option<Vec<u8>> = self
            .read()
            .query_row(
                "SELECT operator FROM channels WHERE channel = ?1",
                params![&channel.0[..]],
                |r| r.get(0),
            )
            .optional()?;
        Ok(raw.and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok()))
    }

    /// The operator public key for `channel` **iff `holder` is a current member** —
    /// the exact shape the edge channel broker's `authorize` closure requires (#81
    /// SEC81c): membership and revocation fold into the key source, so a holder that
    /// was never added, or was removed, resolves to `None` and is refused at the gate
    /// with no key rotation or expiry-shortening. A single JOIN keeps membership and
    /// key lookup atomic (no torn read between an `is_member` and an `operator_pubkey`
    /// call). This is the production source for `accept_and_read_join`'s `authorize`.
    pub fn authorize_holder(
        &self,
        channel: &ChannelId,
        holder: &[u8; 32],
    ) -> rusqlite::Result<Option<[u8; 32]>> {
        let raw: Option<Vec<u8>> = self
            .read()
            .query_row(
                "SELECT c.operator FROM channels c \
                 JOIN channel_members m ON m.channel = c.channel \
                 WHERE c.channel = ?1 AND m.holder = ?2",
                params![&channel.0[..], &holder[..]],
                |r| r.get(0),
            )
            .optional()?;
        Ok(raw.and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok()))
    }

    /// Every channel `owner` registered, sorted (account-deletion cascade's discovery
    /// step — the reverse of [`channel_owner`](Self::channel_owner)).
    pub fn channels_owned_by(&self, owner: &str) -> rusqlite::Result<Vec<ChannelId>> {
        let conn = self.read();
        let mut stmt = conn.prepare("SELECT channel FROM channels WHERE owner = ?1 ORDER BY channel")?;
        let rows = stmt
            .query_map(params![owner], |r| r.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows
            .into_iter()
            .filter_map(|v| <[u8; 32]>::try_from(v.as_slice()).ok().map(ChannelId))
            .collect())
    }

    /// Delete `channel` entirely (owner-scoped): its registration, every member, and
    /// its allow-list — the account-deletion cascade's per-channel teardown. Returns
    /// `false` (no-op) if `owner` doesn't own `channel`.
    pub fn delete_channel(&self, owner: &str, channel: &ChannelId) -> rusqlite::Result<bool> {
        let conn = self.writer.lock_safe();
        let n = conn.execute(
            "DELETE FROM channels WHERE channel = ?1 AND owner = ?2",
            params![&channel.0[..], owner],
        )?;
        if n > 0 {
            conn.execute("DELETE FROM channel_members WHERE channel = ?1", params![&channel.0[..]])?;
            conn.execute("DELETE FROM channel_allowlist WHERE channel = ?1", params![&channel.0[..]])?;
        }
        Ok(n > 0)
    }

    /// Strip `email` from every channel's allow-list, regardless of owner
    /// (account-deletion cascade: a deleted account's e-mail shouldn't keep sitting
    /// on other owners' pending-invite lists). Returns rows removed.
    pub fn remove_allowlist_entries_for_email(&self, email: &str) -> rusqlite::Result<usize> {
        Ok(self.writer.lock_safe().execute(
            "DELETE FROM channel_allowlist WHERE email = ?1",
            params![email.to_ascii_lowercase()],
        )?)
    }

    /// The subject that owns `channel`, if registered.
    pub fn channel_owner(&self, channel: &ChannelId) -> rusqlite::Result<Option<String>> {
        self.read()
            .query_row(
                "SELECT owner FROM channels WHERE channel = ?1",
                params![&channel.0[..]],
                |r| r.get(0),
            )
            .optional()
    }

    /// Add `holder` as a member of `channel`, pinning its X25519 Noise static key
    /// (#72 AF4). Owner-scoped: succeeds (`true`) only when `owner` owns the channel.
    /// Idempotent, and re-adding an existing holder **updates** its recorded Noise
    /// key. Returns `false` if not the owner (or the channel is unknown).
    pub fn add_member(
        &self,
        channel: &ChannelId,
        owner: &str,
        holder: &[u8; 32],
        noise_pubkey: &[u8; 32],
        noise_attestation: &[u8; 64],
    ) -> rusqlite::Result<bool> {
        let conn = self.writer.lock_safe();
        let is_owner: bool = conn
            .query_row(
                "SELECT 1 FROM channels WHERE channel = ?1 AND owner = ?2",
                params![&channel.0[..], owner],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !is_owner {
            return Ok(false);
        }
        conn.execute(
            "INSERT OR REPLACE INTO channel_members (channel, holder, noise_pubkey, noise_attestation) \
             VALUES (?1, ?2, ?3, ?4)",
            params![&channel.0[..], &holder[..], &noise_pubkey[..], &noise_attestation[..]],
        )?;
        Ok(true)
    }

    /// Every member of `channel`, owner-scoped (only `owner` -- the channel's real
    /// owner -- can list its members; anyone else gets an empty list, same
    /// ownership-check shape as [`Self::add_member`]) -- `(holder, noise_pubkey)`,
    /// sorted by holder so the result is stable. The video-conferencing feature's
    /// missing piece: `/me/channels` itself (registration, membership) had no GET
    /// route at all before this -- an operator could register a channel + add
    /// members but never list what they'd already registered.
    pub fn members_of(&self, channel: &ChannelId, owner: &str) -> rusqlite::Result<Option<Vec<([u8; 32], Option<[u8; 32]>)>>> {
        let conn = self.read();
        let is_owner: bool = conn
            .query_row(
                "SELECT 1 FROM channels WHERE channel = ?1 AND owner = ?2",
                params![&channel.0[..], owner],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !is_owner {
            // `None` (not an empty `Some(vec![])`), matching `allowlist_list`'s own
            // convention: a non-owner gets a clear 403 at the HTTP layer, not a 200
            // with an empty list that reads the same as "no members yet" -- no
            // membership-existence leak either way, but a distinguishable, honest
            // response instead of two different truths looking identical.
            return Ok(None);
        }
        let mut stmt = conn.prepare(
            "SELECT holder, noise_pubkey FROM channel_members WHERE channel = ?1 ORDER BY holder",
        )?;
        let rows = stmt
            .query_map(params![&channel.0[..]], |r| {
                let holder: Vec<u8> = r.get(0)?;
                let noise: Option<Vec<u8>> = r.get(1)?;
                Ok((holder, noise))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Some(
            rows.into_iter()
                .filter_map(|(h, n)| {
                    let holder = <[u8; 32]>::try_from(h.as_slice()).ok()?;
                    let noise = n.and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());
                    Some((holder, noise))
                })
                .collect(),
        ))
    }

    /// Record a cross-user invitation redemption as **consumed** (#72 AF3 / #108),
    /// keyed by the invitation's 64-byte operator signature (unique per invitation — a
    /// replay carries the identical bytes). Returns `true` the **first** time an
    /// unexpired invitation is redeemed and `false` on any replay, so a redemption is
    /// genuinely single-use and a **revoked member cannot restore membership** by
    /// re-POSTing the same redemption. Mirrors `verify_fresh`/`ReplayCache` for grants
    /// (#88 SEC88b); the caller (redeem endpoint) checks proofs first, then consumes.
    /// Expired records are pruned on each call so the table stays bounded, and an
    /// already-expired invitation is never fresh (defensive — `verify_invitation`
    /// rejects it first anyway).
    pub fn consume_invitation(
        &self,
        signature: &[u8; 64],
        expires_at: u64,
        now: u64,
    ) -> rusqlite::Result<bool> {
        let conn = self.writer.lock_safe();
        conn.execute(
            "DELETE FROM consumed_invitations WHERE expires_at <= ?1",
            params![now as i64],
        )?;
        if now >= expires_at {
            return Ok(false);
        }
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO consumed_invitations (signature, expires_at) VALUES (?1, ?2)",
            params![&signature[..], expires_at as i64],
        )?;
        Ok(inserted > 0)
    }

    /// Issue a fresh, single-use redemption **challenge** nonce (#108 defense-in-depth),
    /// valid for `ttl_secs` from `now`. The invitee signs it into its redemption; the CP
    /// [`consume_challenge`](Self::consume_challenge)s it exactly once, so a captured
    /// redemption is non-replayable independent of the invitation single-use record.
    pub fn issue_challenge(&self, now: u64, ttl_secs: u64) -> rusqlite::Result<[u8; 32]> {
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let conn = self.writer.lock_safe();
        // #403: this endpoint is unauthenticated and only reached the `consume_challenge`
        // prune after a valid invitation later verifies -- an idle deployment (nobody
        // currently redeeming) never hit that path at all, so the table grew without
        // bound under any flood of just this call. Pruning here too, on every issue, means
        // it self-bounds regardless of redemption traffic (in addition to #403's
        // per-IP rate limit on this path -- defense in depth, not a replacement for it).
        conn.execute("DELETE FROM channel_challenges WHERE expires_at <= ?1", params![now as i64])?;
        conn.execute(
            "INSERT INTO channel_challenges (nonce, expires_at) VALUES (?1, ?2)",
            params![&nonce[..], now.saturating_add(ttl_secs) as i64],
        )?;
        Ok(nonce)
    }

    /// Consume a redemption challenge nonce: returns `true` iff it exists and is unexpired
    /// (then deletes it, so a replay of the same nonce fails), `false` otherwise. Prunes
    /// expired nonces so the table stays bounded.
    pub fn consume_challenge(&self, nonce: &[u8; 32], now: u64) -> rusqlite::Result<bool> {
        let conn = self.writer.lock_safe();
        conn.execute(
            "DELETE FROM channel_challenges WHERE expires_at <= ?1",
            params![now as i64],
        )?;
        let deleted = conn.execute(
            "DELETE FROM channel_challenges WHERE nonce = ?1",
            params![&nonce[..]],
        )?;
        Ok(deleted > 0)
    }

    /// The holder-signed attestation over `holder`'s Noise key on `channel` (#101), if
    /// recorded. The edge relays this to the peer, who verifies the Noise key is bound
    /// to the holder (`ct_common::channel::verify_member_noise_attestation`) before
    /// pinning it — so a DB-substituted key is rejected.
    pub fn member_noise_attestation(
        &self,
        channel: &ChannelId,
        holder: &[u8; 32],
    ) -> rusqlite::Result<Option<[u8; 64]>> {
        let raw: Option<Option<Vec<u8>>> = self
            .read()
            .query_row(
                "SELECT noise_attestation FROM channel_members WHERE channel = ?1 AND holder = ?2",
                params![&channel.0[..], &holder[..]],
                |r| r.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?;
        Ok(raw.flatten().and_then(|v| <[u8; 64]>::try_from(v.as_slice()).ok()))
    }

    /// The X25519 Noise static key `holder` pinned for `channel` (#72 AF4), if the
    /// holder is a current member and a key is recorded. A peer fetches this to pin
    /// the other side's static key for the direct-path Noise_IK handshake; a removed
    /// (revoked) member resolves to `None`, as does a member added before the key
    /// column existed.
    pub fn member_noise_key(
        &self,
        channel: &ChannelId,
        holder: &[u8; 32],
    ) -> rusqlite::Result<Option<[u8; 32]>> {
        let raw: Option<Option<Vec<u8>>> = self
            .read()
            .query_row(
                "SELECT noise_pubkey FROM channel_members WHERE channel = ?1 AND holder = ?2",
                params![&channel.0[..], &holder[..]],
                |r| r.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?;
        Ok(raw.flatten().and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok()))
    }

    /// Whether `holder` is a member of `channel`.
    pub fn is_member(&self, channel: &ChannelId, holder: &[u8; 32]) -> rusqlite::Result<bool> {
        Ok(self
            .read()
            .query_row(
                "SELECT 1 FROM channel_members WHERE channel = ?1 AND holder = ?2",
                params![&channel.0[..], &holder[..]],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Whether `holder` is a member of any channel visible to `subject` (#698 finding 5):
    /// a channel `subject` owns, or one they're allow-listed on by `subject_email`. Mirrors
    /// the exact "account related channels" relationship [`topology_edge_channel`] already
    /// checks for an edge's attached channel (owned-by OR allow-listed-on) — reused here
    /// rather than inventing a new notion of "related to the caller".
    ///
    /// Purely an informational signal, never an authorization gate: a topology can
    /// legitimately reference an agent that hasn't joined any channel yet, or one
    /// belonging to a collaborator's channel this caller can't see. This only tells the
    /// UI whether `holder` is something the caller can independently corroborate, so an
    /// obviously-fake or mistyped id doesn't render as silently identical to a real,
    /// working agent.
    pub fn holder_visible_to(
        &self,
        subject: &str,
        subject_email: Option<&str>,
        holder: &[u8; 32],
    ) -> rusqlite::Result<bool> {
        for channel in self.channels_owned_by(subject)? {
            if self.is_member(&channel, holder)? {
                return Ok(true);
            }
        }
        if let Some(email) = subject_email {
            for (channel, _) in self.channels_for_email(email)? {
                if self.is_member(&channel, holder)? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Remove `holder` from `channel`. Owner-scoped, idempotent; `false` if not the
    /// owner (or unknown channel).
    pub fn remove_member(
        &self,
        channel: &ChannelId,
        owner: &str,
        holder: &[u8; 32],
    ) -> rusqlite::Result<bool> {
        let mut guard = self.writer.lock_safe();
        let tx = guard.transaction()?;
        let is_owner: bool = tx
            .query_row(
                "SELECT 1 FROM channels WHERE channel = ?1 AND owner = ?2",
                params![&channel.0[..], owner],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !is_owner {
            return Ok(false); // tx rolls back on drop -- nothing was written
        }
        // Revocation must be COMPLETE, in one transaction. Deleting only the
        // `channel_members` row left the holder's deposited grant re-fetchable
        // (`channel_grant_deposits`) and its subject->holder claim link
        // (`channel_member_subjects`) intact -- so a revoked member could still pull
        // their grant from their portal session (`GET /portal/channels/:channel/grant`)
        // and, since the edge honours any validly-signed unexpired grant independent of
        // CP membership, keep joining. All three rows are keyed by (channel, holder), so
        // this removes exactly this holder and leaves any sibling holder the same subject
        // claimed on the same channel untouched.
        tx.execute(
            "DELETE FROM channel_members WHERE channel = ?1 AND holder = ?2",
            params![&channel.0[..], &holder[..]],
        )?;
        tx.execute(
            "DELETE FROM channel_grant_deposits WHERE channel = ?1 AND holder = ?2",
            params![&channel.0[..], &holder[..]],
        )?;
        tx.execute(
            "DELETE FROM channel_member_subjects WHERE channel = ?1 AND holder = ?2",
            params![&channel.0[..], &holder[..]],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Add `email` (case-insensitively) to `channel`'s self-service **allow-list**
    /// (#248-follow): any portal user who later logs in with a matching *verified*
    /// id_token email may claim their own membership on this channel without the
    /// owner manually exchanging holder keys over e.g. a GitHub issue. Owner-scoped
    /// like [`add_member`](Self::add_member); idempotent (re-adding just refreshes
    /// `added_at`). Returns `false` if `owner` doesn't own `channel`.
    pub fn allowlist_add(
        &self,
        channel: &ChannelId,
        owner: &str,
        email: &str,
        now: u64,
    ) -> rusqlite::Result<bool> {
        let conn = self.writer.lock_safe();
        let is_owner: bool = conn
            .query_row(
                "SELECT 1 FROM channels WHERE channel = ?1 AND owner = ?2",
                params![&channel.0[..], owner],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !is_owner {
            return Ok(false);
        }
        conn.execute(
            "INSERT OR REPLACE INTO channel_allowlist (channel, email, added_by, added_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params![&channel.0[..], email.to_ascii_lowercase(), owner, now as i64],
        )?;
        Ok(true)
    }

    /// Remove `email` from `channel`'s allow-list. Owner-scoped, idempotent; `false`
    /// if not the owner (or unknown channel). Does **not** revoke an already-claimed
    /// membership — that's still [`remove_member`](Self::remove_member); this only
    /// stops a *future* claim.
    pub fn allowlist_remove(&self, channel: &ChannelId, owner: &str, email: &str) -> rusqlite::Result<bool> {
        let conn = self.writer.lock_safe();
        let is_owner: bool = conn
            .query_row(
                "SELECT 1 FROM channels WHERE channel = ?1 AND owner = ?2",
                params![&channel.0[..], owner],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !is_owner {
            return Ok(false);
        }
        conn.execute(
            "DELETE FROM channel_allowlist WHERE channel = ?1 AND email = ?2",
            params![&channel.0[..], email.to_ascii_lowercase()],
        )?;
        Ok(true)
    }

    /// List `channel`'s allow-listed emails. Owner-scoped: `None` if `owner` doesn't
    /// own `channel` (or it's unknown), `Some(emails)` otherwise (empty when no
    /// entries).
    pub fn allowlist_list(&self, channel: &ChannelId, owner: &str) -> rusqlite::Result<Option<Vec<String>>> {
        let conn = self.read();
        let is_owner: bool = conn
            .query_row(
                "SELECT 1 FROM channels WHERE channel = ?1 AND owner = ?2",
                params![&channel.0[..], owner],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !is_owner {
            return Ok(None);
        }
        let mut stmt = conn.prepare(
            "SELECT email FROM channel_allowlist WHERE channel = ?1 ORDER BY added_at ASC",
        )?;
        let emails = stmt
            .query_map(params![&channel.0[..]], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Some(emails))
    }

    /// Whether `email` (case-insensitive) is allow-listed on `channel` — the gate the
    /// self-service **claim** endpoint checks against the caller's own *verified*
    /// session email. Deliberately **not** owner-scoped: the claimant isn't the owner.
    pub fn allowlist_contains(&self, channel: &ChannelId, email: &str) -> rusqlite::Result<bool> {
        Ok(self
            .read()
            .query_row(
                "SELECT 1 FROM channel_allowlist WHERE channel = ?1 AND email = ?2",
                params![&channel.0[..], email.to_ascii_lowercase()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Self-service claim (#248-follow): add `holder` as a member of `channel`,
    /// authorized not by an owner-signed request but by `email` being on the
    /// channel's own allow-list — the counterpart to
    /// [`add_member`](Self::add_member) for a caller who **isn't** the owner.
    /// Returns `false` (no write) when `email` isn't allow-listed for `channel`
    /// (covers an unknown channel too, since its allow-list is then empty).
    /// Idempotent, same as `add_member`: re-claiming refreshes the recorded Noise
    /// key. The allow-list check and the insert happen under the same lock, so a
    /// concurrent `allowlist_remove` can't race a claim into landing anyway.
    ///
    /// Also stamps `channel_allowlist.claimed_at` for this `(channel, email)` pair
    /// (`now`), so [`channels_for_email`](Self::channels_for_email) can report
    /// claim status without needing to already know the claimant's holder key.
    pub fn claim_via_allowlist(
        &self,
        channel: &ChannelId,
        email: &str,
        holder: &[u8; 32],
        noise_pubkey: &[u8; 32],
        noise_attestation: &[u8; 64],
        now: u64,
        subject: Option<&str>,
    ) -> rusqlite::Result<ClaimOutcome> {
        let conn = self.writer.lock_safe();
        let allowed: bool = conn
            .query_row(
                "SELECT 1 FROM channel_allowlist WHERE channel = ?1 AND email = ?2",
                params![&channel.0[..], email.to_ascii_lowercase()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !allowed {
            return Ok(ClaimOutcome::NotAllowlisted);
        }
        // #577: the allow-list authorizes an EMAIL; the row this writes is keyed on
        // `(channel, holder)`, and `holder` comes from the caller with nothing binding the
        // two. The attestation check upstream stops a FORGED key, not a REPLAYED one: every
        // member legitimately receives the other members' `(noise_pubkey, attestation)` from
        // the edge's authorize response, so one allow-listed member could re-submit another
        // member's older attested key and, through `INSERT OR REPLACE`, roll that member's
        // pinned key back to a value it had rotated away from. The same call also replaced
        // the `channel_member_subjects` row below, redirecting the victim's deposited-grant
        // pickup (`holders_for_subject`, subject-scoped) to the caller.
        //
        // So: a holder already claimed by a portal subject may only be re-claimed by THAT
        // subject. Rotation by the rightful member keeps working; taking over someone else's
        // holder does not. Deliberately narrow -- it refuses only when the store can name a
        // different owner, never on a first claim, so it cannot lock out a legitimate member
        // whose holder nobody has claimed.
        if let Some(subject) = subject {
            let owned_by_other: bool = conn
                .query_row(
                    "SELECT 1 FROM channel_member_subjects \
                     WHERE channel = ?1 AND holder = ?2 AND subject <> ?3",
                    params![&channel.0[..], &holder[..], subject],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if owned_by_other {
                return Ok(ClaimOutcome::HolderClaimedByAnother);
            }
        }
        conn.execute(
            "INSERT OR REPLACE INTO channel_members (channel, holder, noise_pubkey, noise_attestation) \
             VALUES (?1, ?2, ?3, ?4)",
            params![&channel.0[..], &holder[..], &noise_pubkey[..], &noise_attestation[..]],
        )?;
        conn.execute(
            "UPDATE channel_allowlist SET claimed_at = ?3 WHERE channel = ?1 AND email = ?2",
            params![&channel.0[..], email.to_ascii_lowercase(), now as i64],
        )?;
        // #514: remember which portal subject claimed this holder, so the member's
        // own session can later find its holders (and re-fetch deposited grants)
        // without retyping key material. `subject` is `None` for legacy callers
        // that have no session identity to record.
        if let Some(subject) = subject {
            conn.execute(
                "INSERT OR REPLACE INTO channel_member_subjects (channel, holder, subject, claimed_at) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![&channel.0[..], &holder[..], subject, now as i64],
            )?;
        }
        Ok(ClaimOutcome::Claimed)
    }

    /// Self-service discoverability (2026-08-01): every channel `email`
    /// (case-insensitive) is allow-listed for, most-recently-added first, with
    /// whether they've already claimed membership. This is the query behind the
    /// portal account page's "Your Channels" section — a logged-in, verified-
    /// email user's own view of what they've been invited to, with no need to be
    /// told a raw channel id out of band first. Deliberately **not** owner-scoped
    /// (same posture as [`allowlist_contains`](Self::allowlist_contains)/
    /// [`claim_via_allowlist`](Self::claim_via_allowlist) — the caller here is the
    /// invitee, not the owner) and deliberately scoped to exactly the caller's own
    /// verified email — never call this with an email the session doesn't own.
    /// #514: the channel OWNER deposits `holder`'s already-signed grant for later
    /// (re-)pickup through the member's portal session -- the persistent replacement
    /// for demo-side one-shot delivery (the sort#26 class). Owner-scoped like every
    /// membership mutation; the holder must already be a member (deposit-for-stranger
    /// is a 404-shaped refusal, not a silent insert). Idempotent upsert: re-depositing
    /// (e.g. after a grant rotation) replaces the stored bytes.
    pub fn deposit_grant(
        &self,
        channel: &ChannelId,
        owner: &str,
        holder: &[u8; 32],
        grant_hex: &str,
        now: u64,
    ) -> rusqlite::Result<GrantDepositOutcome> {
        let conn = self.writer.lock_safe();
        let owns: bool = conn
            .query_row(
                "SELECT 1 FROM channels WHERE channel = ?1 AND owner = ?2",
                params![&channel.0[..], owner],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !owns {
            return Ok(GrantDepositOutcome::NotOwner);
        }
        let member: bool = conn
            .query_row(
                "SELECT 1 FROM channel_members WHERE channel = ?1 AND holder = ?2",
                params![&channel.0[..], &holder[..]],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !member {
            return Ok(GrantDepositOutcome::NotAMember);
        }
        conn.execute(
            "INSERT OR REPLACE INTO channel_grant_deposits (channel, holder, grant_hex, deposited_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params![&channel.0[..], &holder[..], grant_hex, now as i64],
        )?;
        Ok(GrantDepositOutcome::Deposited)
    }

    /// #514: every (holder, deposited grant) pair on `channel` that `subject`'s own
    /// portal claims produced -- what the member-facing fetch surface serves. Holders
    /// the subject claimed but whose grant nobody deposited yet are returned with
    /// `None`, so the caller can render "waiting for your grant" instead of a bare 404.
    pub fn deposited_grants_for_subject(
        &self,
        channel: &ChannelId,
        subject: &str,
    ) -> rusqlite::Result<Vec<([u8; 32], Option<String>)>> {
        let conn = self.writer.lock_safe();
        let mut stmt = conn.prepare(
            "SELECT s.holder, d.grant_hex FROM channel_member_subjects s \
             LEFT JOIN channel_grant_deposits d ON d.channel = s.channel AND d.holder = s.holder \
             WHERE s.channel = ?1 AND s.subject = ?2 ORDER BY s.claimed_at",
        )?;
        let rows = stmt.query_map(params![&channel.0[..], subject], |row| {
            let h: Vec<u8> = row.get(0)?;
            let g: Option<String> = row.get(1)?;
            Ok((h, g))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (h, g) = r?;
            let mut holder = [0u8; 32];
            if h.len() == 32 {
                holder.copy_from_slice(&h);
                out.push((holder, g));
            }
        }
        Ok(out)
    }

    pub fn channels_for_email(&self, email: &str) -> rusqlite::Result<Vec<(ChannelId, Option<u64>)>> {
        let conn = self.read();
        let mut stmt = conn.prepare(
            "SELECT channel, claimed_at FROM channel_allowlist WHERE email = ?1 ORDER BY added_at DESC",
        )?;
        let rows = stmt
            .query_map(params![email.to_ascii_lowercase()], |r| {
                let channel: Vec<u8> = r.get(0)?;
                let claimed_at: Option<i64> = r.get(1)?;
                Ok((channel, claimed_at))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows
            .into_iter()
            .filter_map(|(channel, claimed_at)| {
                let channel: [u8; 32] = channel.try_into().ok()?;
                Some((ChannelId(channel), claimed_at.map(|v| v as u64)))
            })
            .collect())
    }
}

/// SQLite-backed store for declarative **networks** (#102): the durable desired-state
/// the SDN-style control plane reconciles the mesh toward. A [`ct_common::policy::Network`]
/// (agents + policy) is persisted as a JSON blob keyed by `(owner, id)`, so it is strictly
/// **owner-scoped** — a subject can only read or write networks it owns. The controller
/// loads a network, calls `desired_channels()` + `reconcile(...)`, and mints/revokes grants
/// (a later packet); this store is just the persistence.
pub struct SqliteNetworkStore {
    conn: Mutex<Connection>,
}

sqlite_store_ctors!(SqliteNetworkStore);

impl SqliteNetworkStore {
    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS networks (
                 owner TEXT NOT NULL,
                 id    TEXT NOT NULL,
                 json  TEXT NOT NULL,
                 PRIMARY KEY (owner, id)
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Persist (create or replace) `owner`'s network `id`. The `Network` is stored as
    /// JSON; a malformed serialization is a programming error, so it maps to a DB error.
    pub fn put(
        &self,
        owner: &str,
        id: &str,
        network: &ct_common::policy::Network,
    ) -> rusqlite::Result<()> {
        let json = serde_json::to_string(network)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        self.conn.lock_safe().execute(
            "INSERT OR REPLACE INTO networks (owner, id, json) VALUES (?1, ?2, ?3)",
            params![owner, id, json],
        )?;
        Ok(())
    }

    /// Load `owner`'s network `id`, or `None` if they own no such network (so another
    /// subject's network id is invisible — owner isolation). A stored blob that no longer
    /// deserializes, OR that fails [`ct_common::policy::Network::validate`] (#478), is treated
    /// as absent rather than erroring the caller.
    ///
    /// `validate()` is opt-in and today only ever invoked by the authenticated `PUT` handler
    /// (`network_put`, `service.rs`) before a `put()` here — nothing enforces it at the storage
    /// layer itself, so a row written before the validator existed, or by any future write path
    /// that forgets to call it, would otherwise deserialize straight back out with no
    /// revalidation. `min_latency_overlay`/`Network::explain` degrade silently on an
    /// invalid/partitioned network rather than erroring, which is exactly the failure mode the
    /// validator exists to prevent — so re-check it here too, on every read, closing that gap
    /// for every current AND future caller of `get()` in one place.
    pub fn get(&self, owner: &str, id: &str) -> rusqlite::Result<Option<ct_common::policy::Network>> {
        let json: Option<String> = self
            .conn
            .lock_safe()
            .query_row(
                "SELECT json FROM networks WHERE owner = ?1 AND id = ?2",
                params![owner, id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(json
            .and_then(|j| serde_json::from_str::<ct_common::policy::Network>(&j).ok())
            .filter(|network| network.validate().is_ok()))
    }

    /// Delete `owner`'s network `id`; returns whether a row was removed.
    pub fn delete(&self, owner: &str, id: &str) -> rusqlite::Result<bool> {
        let n = self.conn.lock_safe().execute(
            "DELETE FROM networks WHERE owner = ?1 AND id = ?2",
            params![owner, id],
        )?;
        Ok(n > 0)
    }

    /// The ids of every network `owner` owns (sorted), for a listing view.
    pub fn list(&self, owner: &str) -> rusqlite::Result<Vec<String>> {
        let conn = self.conn.lock_safe();
        let mut stmt = conn.prepare("SELECT id FROM networks WHERE owner = ?1 ORDER BY id")?;
        let ids = stmt
            .query_map(params![owner], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(ids)
    }
}

/// Why a durable topology-assignment operation failed: either an assignment-rule
/// violation ([`crate::topology::AssignError`]) or the database.
#[derive(Debug)]
pub enum TopologyError {
    /// The transition violated the exclusivity / ownership rules.
    Assign(crate::topology::AssignError),
    /// A database error.
    Db(rusqlite::Error),
}

impl std::fmt::Display for TopologyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TopologyError::Assign(e) => write!(f, "{e}"),
            TopologyError::Db(e) => write!(f, "database error: {e}"),
        }
    }
}

impl std::error::Error for TopologyError {}

impl From<rusqlite::Error> for TopologyError {
    fn from(e: rusqlite::Error) -> Self {
        TopologyError::Db(e)
    }
}

impl From<crate::topology::AssignError> for TopologyError {
    fn from(e: crate::topology::AssignError) -> Self {
        TopologyError::Assign(e)
    }
}

/// SQLite-backed store for the Topology Editor's **exclusive agent-to-topology
/// assignment** (#107): the durable equivalent of [`crate::topology::AgentAssignment`],
/// so the exclusivity constraint (*an agent belongs to at most one topology; sharing can
/// only be revoked, not reassigned*) holds across restarts. One row per agent records its
/// owner and, if shared, the single topology it belongs to; the pure state machine
/// enforces every transition. (The `Topology` entity + edge-list are follow packets; this
/// is the membership core.)
/// #398: hybrid pooled-reads-single-writer store (#344 pattern; see [`SqliteTunnelStore`]'s
/// struct doc for the full read/write-contention reasoning). [`topology_authorizes`] is the
/// fallback branch of the same `/internal/channel/authorize` hot path [`SqliteChannelStore`]'s
/// own struct doc describes (a JOIN across `topology_edges`/`topologies`, previously a full
/// table scan per #464), and [`topology_by_uuid`] + [`agents_in`]/[`edges`] back the public
/// `GET /net/:uuid` live-status page — pure sequential reads on every load. Many other methods
/// here do an internal read-check-then-write under one held lock (e.g. `can_collaborate`/
/// `owns_topology` gating `add_edge_collab`) and stay on `writer` as a single unit — only
/// methods that are genuinely READ-ONLY end to end move to the pool.
///
/// [`topology_authorizes`]: Self::topology_authorizes
/// [`topology_by_uuid`]: Self::topology_by_uuid
/// [`agents_in`]: Self::agents_in
/// [`edges`]: Self::edges
pub struct SqliteTopologyStore {
    /// The one connection every WRITE method uses, unchanged in shape from every other
    /// non-migrated store's `conn` field (see the struct doc for why writes stay serialized).
    writer: Mutex<Connection>,
    /// Extra read-only connections for every READ-only method (see [`Self::read`]). `None` for
    /// an in-memory store (see [`SqliteTunnelStore::readers`]'s doc for why).
    readers: Option<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>,
}

/// Decode a topology node id — a 32-byte agent holder key as 64 hex chars (#107-enforce unified
/// identity) — into raw bytes, or `None` if it is not exactly 64 valid hex characters (so a
/// non-holder-key label is skipped by [`SqliteTopologyStore::authorized_channels`] rather than
/// naming a bogus channel).
fn topo_node_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

impl SqliteTopologyStore {
    /// Open (creating if needed) a durable store at `path`, plus a pool of extra read-only
    /// connections (#398; see the struct doc).
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let mut store = Self::from_connection(open_tuned(path)?)?;
        let manager =
            r2d2_sqlite::SqliteConnectionManager::file(path).with_init(|c: &mut Connection| tune_connection(c));
        store.readers = Some(r2d2::Pool::builder().max_size(8).build_unchecked(manager));
        Ok(store)
    }

    /// Open an ephemeral in-memory store (tests / stateless runs). No reader pool (#398) --
    /// every method, read or write, goes through `writer`, exactly like before this migration.
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    /// A connection for a READ-only method (#398; same shape as [`SqliteTunnelStore::read`]).
    fn read(&self) -> ReadConn<'_> {
        match self.readers.as_ref().and_then(|pool| pool.get().ok()) {
            Some(pooled) => ReadConn::Pooled(pooled),
            None => ReadConn::Direct(self.writer.lock_safe()),
        }
    }

    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS topology_agents (
                 agent    TEXT PRIMARY KEY,
                 owner    TEXT NOT NULL,
                 topology TEXT
             );
             -- #463: `agent` is the primary key, but queries filter by `topology`,
             -- which has no index of its own.
             CREATE INDEX IF NOT EXISTS idx_topology_agents_topology
                 ON topology_agents (topology);
             CREATE TABLE IF NOT EXISTS topologies (
                 id       TEXT PRIMARY KEY,
                 owner    TEXT NOT NULL,
                 net_uuid TEXT NOT NULL UNIQUE
             );
             CREATE TABLE IF NOT EXISTS topology_edges (
                 topology TEXT NOT NULL,
                 a        TEXT NOT NULL,
                 b        TEXT NOT NULL,
                 PRIMARY KEY (topology, a, b)
             );
             -- #464: topology_authorizes runs on every channel admission, scanning
             -- every edge across every topology -- these make the two rewritten
             -- index-seekable branches below actually seekable.
             CREATE INDEX IF NOT EXISTS idx_topology_edges_a ON topology_edges (a);
             CREATE INDEX IF NOT EXISTS idx_topology_edges_b ON topology_edges (b);
             -- #107-complex: a topology is shared with another Keycloak account by e-mail
             -- (mirrors channel_allowlist's shape/semantics) -- the default stays owner-only
             -- (no rows here), sharing is a strictly additive grant. A shared subject may view
             -- the topology and wire in their OWN agents/edges (collaborative composition, the
             -- use case topology.rs's original module doc already anticipated: 'their own, or
             -- ones shared to them') but never the owner-only governance actions (delete,
             -- operator-bind, manage the share list itself).
             CREATE TABLE IF NOT EXISTS topology_shares (
                 topology  TEXT NOT NULL,
                 email     TEXT NOT NULL,
                 added_by  TEXT NOT NULL,
                 added_at  INTEGER NOT NULL,
                 PRIMARY KEY (topology, email)
             );
             -- #463: PRIMARY KEY (topology, email) only helps queries constraining the
             -- leading column; several queries filter on email alone.
             CREATE INDEX IF NOT EXISTS idx_topology_shares_email
                 ON topology_shares (email);",
        )?;
        // #107-ui-mode: the per-topology overlay mode (a RoutingApproach token) the owner
        // chooses — direct (`baseline`, the default) vs complex-adaptive (`smart-route`/
        // `shortcut`). Additive (#44): a pre-existing self-host DB gains the column with the
        // safe direct default, so older topologies keep working unchanged.
        ensure_column(&conn, "topologies", "overlay_mode", "TEXT NOT NULL DEFAULT 'baseline'")?;
        // #107-enforce: the topology's bound operator public key — the ed25519 identity its overlay
        // links derive channels under (`channel_id_for_link` is operator-bound). Nullable + additive
        // (#44): a legacy topology has no operator bound (enforcement simply doesn't apply to it yet),
        // and self-host DBs upgrade in place. Self-contained on the topology so enforcement needs no
        // fragile cross-store join to discover whose operator authority governs the overlay.
        ensure_column(&conn, "topologies", "operator_pubkey", "BLOB")?;
        // #107-complex: an agent's node KIND in the topology graph -- 'peer' (default, a
        // regular channel member) or 'super-peer' (a byte-transparent UDP relay other LAN
        // members route through, ct-agent's `channel super-peer` subcommand). Purely a
        // rendering/informational hint at this layer -- the graph's actual admission
        // semantics (authorized_channels/topology_authorizes) are unchanged by it; a
        // super-peer node is still just an agent id in the edge graph. Additive (#44).
        ensure_column(&conn, "topology_agents", "kind", "TEXT NOT NULL DEFAULT 'peer'")?;
        // #698 finding 6: an optional, owner-set human-readable alias for the agent --
        // every node otherwise rendered the same truncated `a1a1a1a1…`-style holder-key
        // prefix, which becomes impossible to tell apart once several agents share a
        // near-identical real-key prefix. Nullable + additive (#44); agent-scoped (not
        // topology-scoped) like `kind`, so it survives a revoke/reassign cycle the same
        // way -- `persist`'s `ON CONFLICT` update deliberately never touches this column.
        ensure_column(&conn, "topology_agents", "label", "TEXT")?;
        // #107-complex: an edge may explicitly name a REAL, separately-registered channel
        // (from SqliteChannelStore) it carries, instead of only ever relying on the
        // implicit, derived channel_id_for_link(a, b). Nullable + additive (#44): most
        // edges never set this, and derivation is unaffected either way -- this is purely
        // link-info display + an explicit association a collaborator can attach, not a new
        // authorization path (authorized_channels/topology_authorizes still only ever
        // consult the derived id, so an explicit channel_id here cannot be used to smuggle
        // admission for a channel the drawn edge doesn't actually imply).
        ensure_column(&conn, "topology_edges", "channel_id", "BLOB")?;
        // #405: one-time migration for rows written before add_edge/remove_edge/*_collab/
        // set_edge_channel normalized case (this same change). Pre-existing rows may have
        // the caller's original, possibly-mixed-case spelling, and topology_authorizes'
        // own `lower(e.a)`/`lower(e.b)` check silently masked that until now.
        //
        // Two differently-cased rows for the SAME logical edge (e.g. ('A','b') and
        // ('a','B')) would both lowercase to the same (topology, a, b) triple, colliding
        // on `PRIMARY KEY (topology, a, b)` — a plain `UPDATE ... SET a=lower(a),
        // b=lower(b)` would abort partway through on that collision. Dedupe defensively
        // first (keep the row with a non-NULL channel_id if the group has one, otherwise
        // any row — losing a purely-cosmetic duplicate is fine; losing which channel_id
        // was attached is not) via a fresh temp table, then replace the row set atomically.
        conn.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS topology_edges_405_dedup AS
                 SELECT topology, lower(a) AS a, lower(b) AS b,
                        MAX(channel_id) AS channel_id
                 FROM topology_edges
                 GROUP BY topology, lower(a), lower(b);
             DELETE FROM topology_edges;
             INSERT INTO topology_edges (topology, a, b, channel_id)
                 SELECT topology, a, b, channel_id FROM topology_edges_405_dedup;
             DROP TABLE topology_edges_405_dedup;",
        )?;
        Ok(Self {
            writer: Mutex::new(conn),
            readers: None,
        })
    }

    /// Set a topology's **overlay mode** (#107-ui-mode) — the owner's choice of *direct*
    /// (`RoutingApproach::Baseline`) vs *complex-adaptive* (`SmartRoute`/`Shortcut`). Owner-
    /// scoped: returns `false` (no-op) if `id` doesn't exist or isn't owned by `owner`, so a
    /// subject can never retune a topology it doesn't own. The canonical token is stored.
    pub fn set_overlay_mode(
        &self,
        owner: &str,
        id: &str,
        mode: ct_common::overlay::RoutingApproach,
    ) -> rusqlite::Result<bool> {
        let n = self.writer.lock_safe().execute(
            "UPDATE topologies SET overlay_mode = ?3 WHERE id = ?1 AND owner = ?2",
            params![id, owner, mode.as_str()],
        )?;
        Ok(n == 1)
    }

    /// A topology's overlay mode (#107-ui-mode), or `None` if the topology doesn't exist. A
    /// legacy/unrecognized stored value degrades to `RoutingApproach::Baseline` (direct) — a
    /// stored mode never makes the read fail.
    pub fn overlay_mode(
        &self,
        id: &str,
    ) -> rusqlite::Result<Option<ct_common::overlay::RoutingApproach>> {
        let raw: Option<String> = self
            .read()
            .query_row(
                "SELECT overlay_mode FROM topologies WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(raw.map(|s| {
            ct_common::overlay::RoutingApproach::parse(&s)
                .unwrap_or(ct_common::overlay::RoutingApproach::Baseline)
        }))
    }

    /// Bind a topology's **operator public key** (#107-enforce): the ed25519 operator identity its
    /// overlay links derive channels under. Self-contained on the topology so enforcement needs no
    /// fragile cross-store join — the overlay itself declares whose operator authority governs it.
    ///
    /// **Two independent checks, both required (#107-enforce ii-a):**
    /// * **owner-scoping** — returns `false` (no-op) if `id` doesn't exist or isn't owned by
    ///   `owner`, so a subject can never rebind a topology it doesn't own.
    /// * **proof-of-possession** — `proof` must be the operator's ed25519 signature over
    ///   [`topology_operator_binding_bytes`](ct_common::channel::topology_operator_binding_bytes);
    ///   a binding whose proof doesn't verify under `operator_pubkey` is rejected (`false`).
    ///   Because `operator_pubkey` is public, without this anyone could bind a *victim's* operator
    ///   key to their own topology and (once enforcement consults it) mint admission to the
    ///   victim's channels. Owner-scoping proves *topology* control; this proves *operator-secret*
    ///   possession.
    ///
    /// Idempotent (a valid re-bind overwrites).
    pub fn set_operator(
        &self,
        owner: &str,
        id: &str,
        operator_pubkey: &[u8; 32],
        proof: &[u8; 64],
    ) -> rusqlite::Result<bool> {
        if !ct_common::channel::verify_topology_operator_binding(id, operator_pubkey, proof) {
            return Ok(false);
        }
        let n = self.writer.lock_safe().execute(
            "UPDATE topologies SET operator_pubkey = ?3 WHERE id = ?1 AND owner = ?2",
            params![id, owner, &operator_pubkey[..]],
        )?;
        Ok(n == 1)
    }

    /// A topology's bound operator public key (#107-enforce), or `None` if the topology doesn't
    /// exist or has no operator bound yet (a legacy/unenforced topology). A stored value of the
    /// wrong length degrades to `None` rather than failing the read.
    pub fn operator(&self, id: &str) -> rusqlite::Result<Option<[u8; 32]>> {
        let raw: Option<Option<Vec<u8>>> = self
            .read()
            .query_row(
                "SELECT operator_pubkey FROM topologies WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(raw.flatten().and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()))
    }

    /// Create a topology `id` owned by `owner`, addressed by the unique `net_uuid`.
    /// Returns `false` (no-op) if the `id` is already taken or the `net_uuid` collides —
    /// so ids and subdomains stay unique.
    pub fn create_topology(&self, owner: &str, id: &str, net_uuid: &str) -> rusqlite::Result<bool> {
        let conn = self.writer.lock_safe();
        let clash: bool = conn
            .query_row(
                "SELECT 1 FROM topologies WHERE id = ?1 OR net_uuid = ?2",
                params![id, net_uuid],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if clash {
            return Ok(false);
        }
        conn.execute(
            "INSERT INTO topologies (id, owner, net_uuid) VALUES (?1, ?2, ?3)",
            params![id, owner, net_uuid],
        )?;
        Ok(true)
    }

    fn row_to_topology(id: String, owner: String, net_uuid: String) -> crate::topology::Topology {
        crate::topology::Topology { id, owner, net_uuid }
    }

    /// The topology with `id`, if it exists.
    pub fn topology(&self, id: &str) -> rusqlite::Result<Option<crate::topology::Topology>> {
        self.read()
            .query_row(
                "SELECT id, owner, net_uuid FROM topologies WHERE id = ?1",
                params![id],
                |r| Ok(Self::row_to_topology(r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
    }

    /// Resolve a topology by its `net_uuid` — the lookup the `<net_uuid>.<zone>`
    /// live-status subdomain uses (UUID-only access for now, #107).
    pub fn topology_by_uuid(&self, net_uuid: &str) -> rusqlite::Result<Option<crate::topology::Topology>> {
        self.read()
            .query_row(
                "SELECT id, owner, net_uuid FROM topologies WHERE net_uuid = ?1",
                params![net_uuid],
                |r| Ok(Self::row_to_topology(r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
    }

    /// Every topology `owner` owns (by id, sorted).
    pub fn list_topologies(&self, owner: &str) -> rusqlite::Result<Vec<crate::topology::Topology>> {
        let conn = self.read();
        let mut stmt = conn
            .prepare("SELECT id, owner, net_uuid FROM topologies WHERE owner = ?1 ORDER BY id")?;
        let rows = stmt
            .query_map(params![owner], |r| {
                Ok(Self::row_to_topology(r.get(0)?, r.get(1)?, r.get(2)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Delete `owner`'s topology `id` (owner-scoped); returns whether a row was removed.
    /// A non-owner's delete is a no-op (`false`), so one subject can't drop another's.
    pub fn delete_topology(&self, owner: &str, id: &str) -> rusqlite::Result<bool> {
        let mut guard = self.writer.lock_safe();
        let tx = guard.transaction()?;
        let removed = Self::delete_topology_tx(&tx, owner, id)?;
        tx.commit()?;
        Ok(removed)
    }

    /// The body of [`Self::delete_topology`], factored out so
    /// [`Self::delete_all_owned_by`] (#443) can run it for every owned topology
    /// inside ONE transaction/lock instead of one per id -- see that method's doc.
    fn delete_topology_tx(tx: &rusqlite::Transaction<'_>, owner: &str, id: &str) -> rusqlite::Result<bool> {
        let n = tx.execute(
            "DELETE FROM topologies WHERE id = ?1 AND owner = ?2",
            params![id, owner],
        )?;
        if n > 0 {
            // The topology row is gone -- also drop what only made sense while it
            // existed (its wiring and its share list), and release any agent still
            // assigned into it back to "unassigned" rather than leaving it pointed at
            // a dangling topology id (previously left orphaned -- account-deletion
            // cascade work surfaced this as a real, if mostly harmless, leak).
            tx.execute("DELETE FROM topology_edges WHERE topology = ?1", params![id])?;
            tx.execute("DELETE FROM topology_shares WHERE topology = ?1", params![id])?;
            tx.execute(
                "UPDATE topology_agents SET topology = NULL WHERE topology = ?1",
                params![id],
            )?;
        }
        Ok(n > 0)
    }

    /// Every owned topology, agent, edge and share for `owner`, gone (account-deletion
    /// cascade). Reuses [`delete_topology_tx`](Self::delete_topology_tx) per id so the
    /// same cascade rules apply; also drops the owner's now-ownerless
    /// `topology_agents` rows (agents it registered but never assigned) and strips it
    /// as a collaborator from anyone else's share list. Returns the number of owned
    /// topologies removed.
    ///
    /// #443: the whole cascade -- id lookup, every per-topology delete, and the two
    /// final cleanup statements -- runs inside ONE transaction/lock, not one
    /// transaction per topology plus separate un-transacted cleanup. A DB error
    /// partway through previously left an arbitrary prefix of the account's
    /// topologies deleted with no record of how far it got (a retry wasn't
    /// equivalent to a clean run), and released the lock between steps, letting a
    /// concurrent `create_topology` by the same owner slip a row in mid-cascade that
    /// then survived the "delete all" that raced it. Now either the whole cascade
    /// lands or none of it does, and no concurrent writer can observe or create a
    /// half-deleted state.
    pub fn delete_all_owned_by(&self, owner: &str) -> rusqlite::Result<usize> {
        let mut guard = self.writer.lock_safe();
        let tx = guard.transaction()?;
        let ids: Vec<String> = {
            let mut stmt = tx.prepare("SELECT id FROM topologies WHERE owner = ?1")?;
            let rows = stmt
                .query_map(params![owner], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        let mut removed = 0usize;
        for id in &ids {
            if Self::delete_topology_tx(&tx, owner, id)? {
                removed += 1;
            }
        }
        tx.execute("DELETE FROM topology_agents WHERE owner = ?1", params![owner])?;
        tx.execute("DELETE FROM topology_shares WHERE added_by = ?1", params![owner])?;
        tx.commit()?;
        Ok(removed)
    }

    /// Strip `email` as a collaborator from every topology it's been shared into,
    /// regardless of owner (account-deletion cascade: a deleted account should stop
    /// showing up in other people's "shared with" lists too). Returns rows removed.
    pub fn remove_shares_by_email(&self, email: &str) -> rusqlite::Result<usize> {
        Ok(self.writer.lock_safe().execute(
            "DELETE FROM topology_shares WHERE email = ?1",
            params![email.to_ascii_lowercase()],
        )?)
    }

    /// Whether `owner` owns topology `id` (the edit-authorization check).
    fn owns_topology(conn: &Connection, owner: &str, topology: &str) -> rusqlite::Result<bool> {
        Ok(conn
            .query_row(
                "SELECT 1 FROM topologies WHERE id = ?1 AND owner = ?2",
                params![topology, owner],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Wire an **undirected edge** `a—b` into `owner`'s topology (who connects to whom,
    /// #107). Owner-scoped (only the topology owner may edit its wiring) and idempotent;
    /// the pair is canonicalized (`a—b` == `b—a`), so an edge is stored once. Returns
    /// `false` (no-op) if the caller doesn't own the topology, the edge is a self-loop
    /// (`a == b`), or it already exists.
    pub fn add_edge(&self, owner: &str, topology: &str, a: &str, b: &str) -> rusqlite::Result<bool> {
        // #405: node ids are hex-encoded holder keys (case-insensitive), but ordering
        // canonicalization below was case-SENSITIVE byte comparison over the caller's raw
        // spelling — topology_authorizes' own `lower(e.a)`/`lower(e.b)` check assumes
        // case doesn't matter, so lowercasing here first is what actually makes that true.
        let a = a.to_ascii_lowercase();
        let b = b.to_ascii_lowercase();
        if a == b {
            return Ok(false);
        }
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        let conn = self.writer.lock_safe();
        if !Self::owns_topology(&conn, owner, topology)? {
            return Ok(false);
        }
        let n = conn.execute(
            "INSERT OR IGNORE INTO topology_edges (topology, a, b) VALUES (?1, ?2, ?3)",
            params![topology, a, b],
        )?;
        Ok(n > 0)
    }

    /// Remove the undirected edge `a—b` from `owner`'s topology (owner-scoped, canonical).
    /// Returns whether a row was removed.
    pub fn remove_edge(&self, owner: &str, topology: &str, a: &str, b: &str) -> rusqlite::Result<bool> {
        // #405: see add_edge's comment — must lowercase identically, or a remove using
        // different casing than the original add silently deletes nothing while
        // topology_authorizes' lower()-based check keeps authorizing the surviving row.
        let a = a.to_ascii_lowercase();
        let b = b.to_ascii_lowercase();
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        let conn = self.writer.lock_safe();
        if !Self::owns_topology(&conn, owner, topology)? {
            return Ok(false);
        }
        let n = conn.execute(
            "DELETE FROM topology_edges WHERE topology = ?1 AND a = ?2 AND b = ?3",
            params![topology, a, b],
        )?;
        Ok(n > 0)
    }

    /// The undirected edges wired into `topology`, each canonical `(a, b)` with `a <= b`,
    /// sorted. This is the topology's adjacency the optimizer / renderer consume.
    pub fn edges(&self, topology: &str) -> rusqlite::Result<Vec<(String, String)>> {
        let conn = self.read();
        let mut stmt = conn.prepare(
            "SELECT a, b FROM topology_edges WHERE topology = ?1 ORDER BY a, b",
        )?;
        let edges = stmt
            .query_map(params![topology], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(edges)
    }

    /// The set of channels this topology's declared edges **authorize** on the wire (#107-enforce,
    /// maintainer 2026-07-24 "most robust"): fold the edges through
    /// [`channel_id_for_link`](ct_common::channel::channel_id_for_link) and return the `ChannelId`s
    /// the drawn graph sanctions. Under the **unified identity model** a topology node id *is* the
    /// agent's 32-byte holder key (hex) — the same identity `channel_members` and `channel_id_for_link`
    /// use — so there is no node-id↔holder mapping to drift out of sync. The admission gate consults
    /// this so a member is admissible to a channel **iff** the declared topology contains the link
    /// that names it (removing an edge stops authorizing its channel, no per-channel bookkeeping). An
    /// edge whose endpoint is not a valid 64-hex holder key is skipped — it cannot name a real
    /// channel. `operator_pubkey` is the channel operator's key (from the channels table);
    /// `channel_id_for_link` is operator-bound, so channels stay isolated across operators.
    pub fn authorized_channels(
        &self,
        topology: &str,
        operator_pubkey: &[u8; 32],
    ) -> rusqlite::Result<std::collections::HashSet<ChannelId>> {
        let links: Vec<([u8; 32], [u8; 32])> = self
            .edges(topology)?
            .iter()
            .filter_map(|(a, b)| Some((topo_node_hex32(a)?, topo_node_hex32(b)?)))
            .collect();
        Ok(ct_common::channel::authorized_channels(operator_pubkey, &links))
    }

    /// Reverse-lookup for the admission gate (#107-enforce ii-b): does **any** topology authorize
    /// `holder` on `channel`? Returns the authorizing topology's bound operator key iff some
    /// topology with a **bound (authenticated, ii-a) operator** has a declared edge `(holder, other)`
    /// whose [`channel_id_for_link`](ct_common::channel::channel_id_for_link) is exactly `channel` —
    /// i.e. the drawn overlay contains the link that names this channel and `holder` is one of its
    /// endpoints. This is the query that lets a declared edge **govern the wire**: the gate consults
    /// it *additively* alongside channel-members. Only operator-bound topologies participate (an
    /// unbound/legacy topology authorizes nothing), and the operator binding is proof-of-possession
    /// gated, so a topology cannot claim an operator key it doesn't hold.
    pub fn topology_authorizes(
        &self,
        channel: &ChannelId,
        holder: &[u8; 32],
    ) -> rusqlite::Result<Option<[u8; 32]>> {
        // #464: `holder_hex` is already lowercase (`format!("{b:02x}")` always emits
        // lowercase), and `add_edge`/`remove_edge` (#405) already lowercase every
        // stored endpoint on write -- so this no longer needs `lower()` on read to
        // match case-insensitively, which is what let this become a full scan of
        // every edge across every topology in the first place (an `OR` spanning two
        // different columns, one of them wrapped in a function, is unindexable no
        // matter what index exists). Rewritten as a `UNION ALL` of two
        // index-seekable branches instead -- see idx_topology_edges_a/_b above. `a`
        // and `b` can never be equal for a stored edge (add_edge refuses that), so
        // a real edge matches at most one branch: no risk of double-counting a row.
        let holder_hex: String = holder.iter().map(|b| format!("{b:02x}")).collect();
        let conn = self.read();
        let mut stmt = conn.prepare(
            "SELECT t.operator_pubkey, e.a, e.b \
             FROM topology_edges e JOIN topologies t ON t.id = e.topology \
             WHERE t.operator_pubkey IS NOT NULL AND e.a = ?1 \
             UNION ALL \
             SELECT t.operator_pubkey, e.a, e.b \
             FROM topology_edges e JOIN topologies t ON t.id = e.topology \
             WHERE t.operator_pubkey IS NOT NULL AND e.b = ?1",
        )?;
        let rows = stmt.query_map(params![holder_hex], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
        })?;
        for row in rows {
            let (op_raw, a, b) = row?;
            let op = match <[u8; 32]>::try_from(op_raw.as_slice()) {
                Ok(op) => op,
                Err(_) => continue,
            };
            // The peer endpoint is whichever side of the edge isn't this holder.
            let other_hex = if a.eq_ignore_ascii_case(&holder_hex) { &b } else { &a };
            let other = match topo_node_hex32(other_hex) {
                Some(o) => o,
                None => continue,
            };
            if ct_common::channel::channel_id_for_link(&op, holder, &other) == *channel {
                return Ok(Some(op));
            }
        }
        Ok(None)
    }

    /// Load the current assignment for `agent`, reconstructed from its row.
    fn load(conn: &Connection, agent: &str) -> rusqlite::Result<Option<crate::topology::AgentAssignment>> {
        let row: Option<(String, Option<String>)> = conn
            .query_row(
                "SELECT owner, topology FROM topology_agents WHERE agent = ?1",
                params![agent],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row.map(|(owner, topology)| {
            let mut a = crate::topology::AgentAssignment::new(owner.clone());
            if let Some(t) = topology {
                // Reconstruction: the owner (re)assigns itself, which always succeeds.
                let _ = a.assign(&owner, t);
            }
            a
        }))
    }

    fn persist(conn: &Connection, agent: &str, a: &crate::topology::AgentAssignment) -> rusqlite::Result<()> {
        // #107-complex: ON CONFLICT DO UPDATE (not a blind INSERT OR REPLACE) so a
        // previously-set `kind` (super-peer, set via `set_agent_kind`) survives every later
        // assign/revoke cycle -- REPLACE would silently reset it to the column default on
        // the agent's next reassignment.
        conn.execute(
            "INSERT INTO topology_agents (agent, owner, topology, kind) VALUES (?1, ?2, ?3, 'peer')
             ON CONFLICT(agent) DO UPDATE SET owner = excluded.owner, topology = excluded.topology",
            params![agent, a.owner(), a.topology()],
        )?;
        Ok(())
    }

    /// Set `agent`'s node **kind** in the topology graph (#107-complex): `"peer"` (default)
    /// or `"super-peer"`. Scoped to the agent's own registered owner (`by`) -- the same
    /// authority that controls its assignment -- so a topology collaborator can mark their
    /// OWN agent as a super-peer, never someone else's. `false` (no-op) if `agent` has never
    /// been touched (no row to update) or `by` isn't its owner. Rejects an unrecognized kind
    /// token outright (`Err`), same "never store garbage" posture as `RoutingApproach::parse`.
    pub fn set_agent_kind(&self, by: &str, agent: &str, kind: &str) -> Result<bool, String> {
        if kind != "peer" && kind != "super-peer" {
            return Err(format!("unrecognized agent kind {kind:?} (expected \"peer\" or \"super-peer\")"));
        }
        let n = self
            .writer
            .lock_safe()
            .execute(
                "UPDATE topology_agents SET kind = ?3 WHERE agent = ?1 AND owner = ?2",
                params![agent, by, kind],
            )
            .map_err(|e| e.to_string())?;
        Ok(n > 0)
    }

    /// Set (or, with `label: None`/empty-after-trim, clear) `agent`'s human-readable
    /// **alias** in the topology graph (#698 finding 6). Scoped to the agent's own
    /// registered owner (`by`) -- the exact same authority [`set_agent_kind`] already
    /// enforces, never the topology owner's authority: a collaborator may alias their
    /// OWN agent, not someone else's. `false` (no-op) if `agent` has never been touched
    /// (no row to update) or `by` isn't its owner. Capped at 40 chars so a node card
    /// (fixed-width in the SVG layout) never has to truncate an alias mid-render the
    /// way the old bare-key label did.
    pub fn set_agent_label(&self, by: &str, agent: &str, label: Option<&str>) -> Result<bool, String> {
        let trimmed = label.map(str::trim).filter(|s| !s.is_empty());
        if let Some(l) = trimmed {
            if l.chars().count() > 40 {
                return Err("label must be 40 characters or fewer".to_string());
            }
        }
        let n = self
            .writer
            .lock_safe()
            .execute(
                "UPDATE topology_agents SET label = ?3 WHERE agent = ?1 AND owner = ?2",
                params![agent, by, trimmed],
            )
            .map_err(|e| e.to_string())?;
        Ok(n > 0)
    }

    /// The current assignment for `agent`, if it has ever been touched.
    pub fn assignment(&self, agent: &str) -> rusqlite::Result<Option<crate::topology::AgentAssignment>> {
        Self::load(&self.read(), agent)
    }

    /// Share `agent` into `topology` on behalf of `by`. First touch registers the agent
    /// as owned by `by`; thereafter only the owner may assign, and only when unassigned
    /// (exclusivity — [`crate::topology::AssignError::AlreadyAssigned`] otherwise). The
    /// transition is enforced by the pure state machine and persisted.
    pub fn assign(&self, by: &str, agent: &str, topology: &str) -> Result<(), TopologyError> {
        let conn = self.writer.lock_safe();
        let mut a = Self::load(&conn, agent)?.unwrap_or_else(|| crate::topology::AgentAssignment::new(by));
        a.assign(by, topology)?;
        Self::persist(&conn, agent, &a)?;
        Ok(())
    }

    /// End `agent`'s current sharing (the owner reclaims, or the current topology
    /// releases), returning it to its owner's control. Persisted so exclusivity survives
    /// a restart. [`crate::topology::AssignError::NotAssigned`] if it is not in a topology.
    pub fn revoke(&self, by: &str, agent: &str) -> Result<(), TopologyError> {
        let conn = self.writer.lock_safe();
        let mut a = Self::load(&conn, agent)?.ok_or(crate::topology::AssignError::NotAssigned)?;
        a.revoke(by)?;
        Self::persist(&conn, agent, &a)?;
        Ok(())
    }

    /// The agents currently assigned to `topology` (sorted).
    pub fn agents_in(&self, topology: &str) -> rusqlite::Result<Vec<String>> {
        let conn = self.read();
        let mut stmt =
            conn.prepare("SELECT agent FROM topology_agents WHERE topology = ?1 ORDER BY agent")?;
        let agents = stmt
            .query_map(params![topology], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(agents)
    }

    /// Like [`agents_in`](Self::agents_in), but pairs each agent with its node **kind**
    /// (`"peer"`/`"super-peer"`, #107-complex) and its optional owner-set **label**
    /// (`#698` finding 6) — what the editor's richer node rendering needs; `agents_in`
    /// stays as-is for the (kind/label-indifferent) optimizer/authorization call sites.
    pub fn agents_with_kind(&self, topology: &str) -> rusqlite::Result<Vec<(String, String, Option<String>)>> {
        let conn = self.read();
        let mut stmt = conn
            .prepare("SELECT agent, kind, label FROM topology_agents WHERE topology = ?1 ORDER BY agent")?;
        let agents = stmt
            .query_map(params![topology], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(agents)
    }

    /// Like [`edges`](Self::edges), but includes each edge's explicitly-attached **channel
    /// id**, if any (#107-complex link info). `None` means the edge relies purely on the
    /// implicit, derived `channel_id_for_link` (the common case).
    pub fn edges_with_channel(&self, topology: &str) -> rusqlite::Result<Vec<(String, String, Option<[u8; 32]>)>> {
        let conn = self.read();
        let mut stmt = conn.prepare(
            "SELECT a, b, channel_id FROM topology_edges WHERE topology = ?1 ORDER BY a, b",
        )?;
        let edges = stmt
            .query_map(params![topology], |r| {
                let a: String = r.get(0)?;
                let b: String = r.get(1)?;
                let raw: Option<Vec<u8>> = r.get(2)?;
                Ok((a, b, raw))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(edges
            .into_iter()
            .map(|(a, b, raw)| {
                let channel_id = raw.and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());
                (a, b, channel_id)
            })
            .collect())
    }

    /// Whether `subject` may perform a **collaborative edit** (assign an agent, wire/unwire
    /// an edge, attach a channel to an edge) on `topology` (#107-complex): the topology's
    /// owner, OR a subject whose verified session e-mail is on the topology's share list.
    /// Owner-only governance actions (delete, operator-bind, managing the share list itself)
    /// deliberately do NOT use this — they stay `owns_topology`-only.
    fn can_collaborate(conn: &Connection, subject: &str, subject_email: Option<&str>, topology: &str) -> rusqlite::Result<bool> {
        if Self::owns_topology(conn, subject, topology)? {
            return Ok(true);
        }
        let Some(email) = subject_email else { return Ok(false) };
        Ok(conn
            .query_row(
                "SELECT 1 FROM topology_shares WHERE topology = ?1 AND email = ?2",
                params![topology, email.to_ascii_lowercase()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Wire an edge on behalf of a topology **owner or collaborator** (#107-complex) — like
    /// [`add_edge`](Self::add_edge), but the access check is `can_collaborate` (owner OR
    /// shared-by-email) instead of owner-only, and the two endpoints' assignment-into-THIS-
    /// topology is not otherwise re-verified here (matches `add_edge`'s existing contract:
    /// it wires whatever ids are given, real enforcement of "does this edge authorize a real
    /// channel" lives entirely in `authorized_channels`/`topology_authorizes`).
    pub fn add_edge_collab(
        &self,
        subject: &str,
        subject_email: Option<&str>,
        topology: &str,
        a: &str,
        b: &str,
    ) -> rusqlite::Result<bool> {
        // #405: see add_edge's comment — same case-normalization requirement.
        let a = a.to_ascii_lowercase();
        let b = b.to_ascii_lowercase();
        if a == b {
            return Ok(false);
        }
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        let conn = self.writer.lock_safe();
        if !Self::can_collaborate(&conn, subject, subject_email, topology)? {
            return Ok(false);
        }
        let n = conn.execute(
            "INSERT OR IGNORE INTO topology_edges (topology, a, b) VALUES (?1, ?2, ?3)",
            params![topology, a, b],
        )?;
        Ok(n > 0)
    }

    /// Remove an edge on behalf of a topology **owner or collaborator** (#107-complex) — the
    /// `add_edge_collab` counterpart to [`remove_edge`](Self::remove_edge).
    pub fn remove_edge_collab(
        &self,
        subject: &str,
        subject_email: Option<&str>,
        topology: &str,
        a: &str,
        b: &str,
    ) -> rusqlite::Result<bool> {
        // #405: see add_edge's comment — same case-normalization requirement.
        let a = a.to_ascii_lowercase();
        let b = b.to_ascii_lowercase();
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        let conn = self.writer.lock_safe();
        if !Self::can_collaborate(&conn, subject, subject_email, topology)? {
            return Ok(false);
        }
        let n = conn.execute(
            "DELETE FROM topology_edges WHERE topology = ?1 AND a = ?2 AND b = ?3",
            params![topology, a, b],
        )?;
        Ok(n > 0)
    }

    /// Attach (`Some`) or clear (`None`) an edge's explicit **channel id** (#107-complex link
    /// info) — owner-or-collaborator scoped like `add_edge_collab`. Does not validate that
    /// `channel_id` is a real, existing channel or that the caller owns/is a member of it —
    /// that validation belongs to the HTTP layer (service.rs), which has `SqliteChannelStore`
    /// in scope; this method's job is purely "is the caller allowed to edit this topology's
    /// edges." Purely informational either way (see the `channel_id` column's own doc
    /// comment) — never a new authorization path.
    pub fn set_edge_channel(
        &self,
        subject: &str,
        subject_email: Option<&str>,
        topology: &str,
        a: &str,
        b: &str,
        channel_id: Option<[u8; 32]>,
    ) -> rusqlite::Result<bool> {
        // #405: see add_edge's comment — same case-normalization requirement.
        let a = a.to_ascii_lowercase();
        let b = b.to_ascii_lowercase();
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        let conn = self.writer.lock_safe();
        if !Self::can_collaborate(&conn, subject, subject_email, topology)? {
            return Ok(false);
        }
        let n = conn.execute(
            "UPDATE topology_edges SET channel_id = ?4 WHERE topology = ?1 AND a = ?2 AND b = ?3",
            params![topology, a, b, channel_id.map(|c| c.to_vec())],
        )?;
        Ok(n > 0)
    }

    /// Whether `topology` is shared with `email` (#107-complex) — the raw existence check a
    /// non-owner subject's OWN view-access check needs; unlike `shares_for` this is NOT
    /// owner-scoped (the caller here is the invitee checking their own access, not the
    /// owner browsing their share list).
    pub fn is_shared_with(&self, topology: &str, email: &str) -> rusqlite::Result<bool> {
        let conn = self.read();
        Ok(conn
            .query_row(
                "SELECT 1 FROM topology_shares WHERE topology = ?1 AND email = ?2",
                params![topology, email.to_ascii_lowercase()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Share `topology` with `email` (#107-complex) — owner-scoped, idempotent, case-
    /// insensitive e-mail (matches `channel_allowlist`'s convention). `false` (no-op) if the
    /// caller doesn't own `topology`.
    pub fn share_add(&self, owner: &str, topology: &str, email: &str, now: i64) -> rusqlite::Result<bool> {
        let conn = self.writer.lock_safe();
        if !Self::owns_topology(&conn, owner, topology)? {
            return Ok(false);
        }
        conn.execute(
            "INSERT OR IGNORE INTO topology_shares (topology, email, added_by, added_at) VALUES (?1, ?2, ?3, ?4)",
            params![topology, email.to_ascii_lowercase(), owner, now],
        )?;
        Ok(true)
    }

    /// De-list `email` from `topology`'s share list (#107-complex) — owner-scoped. Returns
    /// whether a row was actually removed.
    pub fn share_remove(&self, owner: &str, topology: &str, email: &str) -> rusqlite::Result<bool> {
        let conn = self.writer.lock_safe();
        if !Self::owns_topology(&conn, owner, topology)? {
            return Ok(false);
        }
        let n = conn.execute(
            "DELETE FROM topology_shares WHERE topology = ?1 AND email = ?2",
            params![topology, email.to_ascii_lowercase()],
        )?;
        Ok(n > 0)
    }

    /// The e-mails `topology` is currently shared with (#107-complex) — owner-scoped
    /// (empty for a non-owner, never another owner's share list).
    pub fn shares_for(&self, owner: &str, topology: &str) -> rusqlite::Result<Vec<String>> {
        let conn = self.read();
        if !Self::owns_topology(&conn, owner, topology)? {
            return Ok(Vec::new());
        }
        let mut stmt = conn.prepare(
            "SELECT email FROM topology_shares WHERE topology = ?1 ORDER BY email",
        )?;
        let emails = stmt
            .query_map(params![topology], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(emails)
    }

    /// Every topology shared with `email` (#107-complex) — deliberately NOT owner-scoped
    /// (keyed on the INVITEE's own verified e-mail), the "topologies shared with me" portal
    /// view's data source, mirroring `SqliteChannelStore::channels_for_email`.
    pub fn topologies_shared_with_email(&self, email: &str) -> rusqlite::Result<Vec<crate::topology::Topology>> {
        let conn = self.read();
        let mut stmt = conn.prepare(
            "SELECT t.id, t.owner, t.net_uuid FROM topologies t
             JOIN topology_shares s ON s.topology = t.id
             WHERE s.email = ?1 ORDER BY t.id",
        )?;
        let rows = stmt
            .query_map(params![email.to_ascii_lowercase()], |r| {
                Ok(Self::row_to_topology(r.get(0)?, r.get(1)?, r.get(2)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

/// Bare CRUD on the `admins` table (ADR-0025 Decision 1/2): who may reach the
/// admin console at all, kept entirely separate from the pseudonymous
/// `AccountId`/ledger schema above -- a real Google email, not an opaque
/// account. This store has NO policy (who may add/remove whom, the
/// super-admin's un-removability) -- that lives in `admin_identity::AdminIdentity`,
/// which wraps this store. `email` is stored lowercased, matching every other
/// email column in this file (e.g. `tunnel_login_allowlist`).
pub struct SqliteAdminStore {
    conn: Mutex<Connection>,
}

sqlite_store_ctors!(SqliteAdminStore);

impl SqliteAdminStore {
    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS admins (
                 email    TEXT PRIMARY KEY,
                 added_by TEXT,
                 added_at INTEGER NOT NULL
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Whether `email` (any casing) has a row in `admins`.
    pub fn is_admin(&self, email: &str) -> rusqlite::Result<bool> {
        Ok(self
            .conn
            .lock_safe()
            .query_row(
                "SELECT 1 FROM admins WHERE email = ?1",
                params![email.to_ascii_lowercase()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Insert `email` as an admin if not already present (idempotent). `added_by`
    /// is the acting admin's email -- `None` only for the startup seed of the
    /// super-admin itself, which has no human actor.
    pub fn add_admin_row(&self, email: &str, added_by: Option<&str>, added_at: i64) -> rusqlite::Result<()> {
        self.conn.lock_safe().execute(
            "INSERT OR IGNORE INTO admins (email, added_by, added_at) VALUES (?1, ?2, ?3)",
            params![
                email.to_ascii_lowercase(),
                added_by.map(|s| s.to_ascii_lowercase()),
                added_at
            ],
        )?;
        Ok(())
    }

    /// Remove `email`'s admin row, if present. Returns whether a row was actually
    /// removed. No policy enforced here -- see the struct doc.
    pub fn remove_admin_row(&self, email: &str) -> rusqlite::Result<bool> {
        let n = self.conn.lock_safe().execute(
            "DELETE FROM admins WHERE email = ?1",
            params![email.to_ascii_lowercase()],
        )?;
        Ok(n > 0)
    }

    /// Every admin row, most-recently-added first -- for the admin-management UI
    /// (later phase).
    pub fn list_admins(&self) -> rusqlite::Result<Vec<AdminRow>> {
        let conn = self.conn.lock_safe();
        let mut stmt = conn.prepare("SELECT email, added_by, added_at FROM admins ORDER BY added_at DESC")?;
        let rows = stmt
            .query_map([], |r| {
                Ok(AdminRow {
                    email: r.get(0)?,
                    added_by: r.get(1)?,
                    added_at: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

/// One row of the `admins` table (ADR-0025) -- for the admin-management UI's listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRow {
    pub email: String,
    pub added_by: Option<String>,
    pub added_at: i64,
}

/// Bare CRUD on `managed_domains` + `managed_domain_hostnames` (ADR-0025
/// Decision 4: multi-domain onboarding). No policy here (mirrors
/// [`SqliteAdminStore`]'s own split) -- `domain_admin`'s handlers own the real
/// DNS/cert side effects and decide what `status` means; this store just
/// persists whatever they decide.
///
/// `managed_domains` is the onboarded-zone registry (`POST /admin-ui/domains`);
/// `managed_domain_hostnames` records every subdomain cert issued under one of
/// those zones (`POST /admin-ui/domains/:zone/hostnames`) so the cert-expiry
/// dashboard (`GET /admin-ui/certs`) knows which per-domain cert files exist
/// without scanning the filesystem.
pub struct SqliteManagedDomains {
    conn: Mutex<Connection>,
}

sqlite_store_ctors!(SqliteManagedDomains);

impl SqliteManagedDomains {
    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS managed_domains (
                 zone     TEXT PRIMARY KEY,
                 added_by TEXT,
                 added_at INTEGER NOT NULL,
                 status   TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS managed_domain_hostnames (
                 hostname  TEXT PRIMARY KEY,
                 zone      TEXT NOT NULL,
                 cert_dir  TEXT NOT NULL,
                 issued_by TEXT,
                 issued_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_managed_domain_hostnames_zone
                 ON managed_domain_hostnames (zone);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Register `zone` as managed. Returns `false` (no-op) if `zone` is already
    /// present -- the caller (`domain_admin::register_domain`) treats that as
    /// "already onboarded", not an error, since the real work (DNS records) is
    /// idempotent too.
    pub fn add_zone(&self, zone: &str, added_by: &str, added_at: i64, status: &str) -> rusqlite::Result<bool> {
        let n = self.conn.lock_safe().execute(
            "INSERT OR IGNORE INTO managed_domains (zone, added_by, added_at, status) VALUES (?1, ?2, ?3, ?4)",
            params![zone, added_by, added_at, status],
        )?;
        Ok(n > 0)
    }

    pub fn zone(&self, zone: &str) -> rusqlite::Result<Option<ManagedDomainRow>> {
        self.conn
            .lock_safe()
            .query_row(
                "SELECT zone, added_by, added_at, status FROM managed_domains WHERE zone = ?1",
                params![zone],
                |r| {
                    Ok(ManagedDomainRow {
                        zone: r.get(0)?,
                        added_by: r.get(1)?,
                        added_at: r.get(2)?,
                        status: r.get(3)?,
                    })
                },
            )
            .optional()
    }

    /// Every managed domain, most-recently-added first.
    pub fn list_zones(&self) -> rusqlite::Result<Vec<ManagedDomainRow>> {
        let conn = self.conn.lock_safe();
        let mut stmt =
            conn.prepare("SELECT zone, added_by, added_at, status FROM managed_domains ORDER BY added_at DESC")?;
        let rows = stmt
            .query_map([], |r| {
                Ok(ManagedDomainRow {
                    zone: r.get(0)?,
                    added_by: r.get(1)?,
                    added_at: r.get(2)?,
                    status: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Record a subdomain cert issued under a managed zone (idempotent upsert --
    /// a re-issued cert just refreshes `issued_at`/`issued_by`/`cert_dir`).
    pub fn record_hostname_cert(
        &self,
        hostname: &str,
        zone: &str,
        cert_dir: &str,
        issued_by: &str,
        issued_at: i64,
    ) -> rusqlite::Result<()> {
        self.conn.lock_safe().execute(
            "INSERT INTO managed_domain_hostnames (hostname, zone, cert_dir, issued_by, issued_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(hostname) DO UPDATE SET
                 cert_dir = excluded.cert_dir, issued_by = excluded.issued_by, issued_at = excluded.issued_at",
            params![hostname, zone, cert_dir, issued_by, issued_at],
        )?;
        Ok(())
    }

    /// Every subdomain cert issued under any managed zone -- the cert-expiry
    /// dashboard's source of which per-domain cert files to check.
    pub fn list_hostname_certs(&self) -> rusqlite::Result<Vec<ManagedDomainHostnameRow>> {
        let conn = self.conn.lock_safe();
        let mut stmt = conn.prepare(
            "SELECT hostname, zone, cert_dir, issued_by, issued_at FROM managed_domain_hostnames ORDER BY hostname",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(ManagedDomainHostnameRow {
                    hostname: r.get(0)?,
                    zone: r.get(1)?,
                    cert_dir: r.get(2)?,
                    issued_by: r.get(3)?,
                    issued_at: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

/// One row of `managed_domains` (ADR-0025 Decision 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedDomainRow {
    pub zone: String,
    pub added_by: Option<String>,
    pub added_at: i64,
    pub status: String,
}

/// One row of `managed_domain_hostnames` (ADR-0025 Decision 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedDomainHostnameRow {
    pub hostname: String,
    pub zone: String,
    pub cert_dir: String,
    pub issued_by: Option<String>,
    pub issued_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_sqlite_store_constructs_via_the_shared_ctor_macro() {
        // #192 (frozen): sqlite_store_ctors! generates open/open_in_memory for the stores below
        // that still use it, each delegating to its own from_connection. The regression the macro
        // could introduce is "a store no longer opens / its schema isn't applied", so construct
        // every one — a failure here (a store dropped from the macro, a broken from_connection)
        // fails loudly, not silently at boot.
        //
        // #344/#398: SqliteTunnelStore, SqliteAgentDirectory, SqlitePipelineRegistry,
        // SqliteChannelStore and SqliteTopologyStore are the five exceptions — each has its own
        // hand-written open/open_in_memory (see each struct's own doc) instead of the macro,
        // because their `open` also builds a reader connection pool that the macro's shared shape
        // has no parameter for. Every one's `open_in_memory` still exists with the identical
        // signature, so each belongs in this same "every store constructs" regression net
        // regardless of which ctor wrote it.
        SqliteEnrollment::open_in_memory().unwrap();
        SqliteBootstrap::open_in_memory().unwrap();
        SqliteAgentDirectory::open_in_memory().unwrap();
        SqlitePipelineRegistry::open_in_memory().unwrap();
        SqliteRegistry::open_in_memory().unwrap();
        SqliteLedger::open_in_memory().unwrap();
        SqliteTunnelStore::open_in_memory().unwrap();
        SqliteChannelStore::open_in_memory().unwrap();
        SqliteNetworkStore::open_in_memory().unwrap();
        SqliteTopologyStore::open_in_memory().unwrap();
    }

    #[test]
    fn pipeline_registry_publishes_and_discovers_specs_owner_scoped() {
        // #174 B (frozen): a designer publishes a workflow PipelineSpec so agents can discover it —
        // owner-scoped (a stranger can't overwrite), round-trips through JSON, unknown id → None.
        use ct_common::channel::ServiceType;
        use ct_common::pipeline::{PipelineSpec, RequiredRole, SelectionPolicy};
        let reg = SqlitePipelineRegistry::open_in_memory().unwrap();
        let spec = PipelineSpec {
            id: "flappy".into(),
            roles: vec![
                RequiredRole { service: ServiceType::TextGeneration, units: 1, tag: "physics".into(), selection_policy: None },
                RequiredRole { service: ServiceType::TextGeneration, units: 1, tag: "art".into(), selection_policy: None },
            ],
            operator_pubkey_hex: None, selection_policy: SelectionPolicy::LowestFloor,
        };
        assert!(reg.publish("alice", &spec, 100).unwrap(), "owner publishes");
        assert_eq!(reg.get("flappy").unwrap(), Some(spec.clone()), "published spec round-trips");
        assert_eq!(reg.get("nope").unwrap(), None, "unknown id → None");
        assert_eq!(reg.list().unwrap(), vec![("flappy".to_string(), "alice".to_string())], "discoverable in the list");

        // Owner-scoped: a different owner cannot overwrite the published spec.
        let hijack = PipelineSpec { id: "flappy".into(), roles: vec![], operator_pubkey_hex: None, selection_policy: SelectionPolicy::LowestFloor };
        assert!(!reg.publish("mallory", &hijack, 200).unwrap(), "non-owner cannot overwrite");
        assert_eq!(reg.get("flappy").unwrap().unwrap().roles.len(), 2, "spec unchanged after hijack attempt");

        // The owner re-publishing updates it.
        let updated = PipelineSpec {
            id: "flappy".into(),
            roles: vec![RequiredRole { service: ServiceType::SafetyCheck, units: 1, tag: "guard".into(), selection_policy: None }],
            operator_pubkey_hex: None, selection_policy: SelectionPolicy::LowestFloor,
        };
        assert!(reg.publish("alice", &updated, 300).unwrap(), "owner re-publish");
        assert_eq!(reg.get("flappy").unwrap().unwrap().roles.len(), 1, "owner re-publish updates the spec");

        // Account-deletion cascade: owner-scoped unpublish.
        assert!(!reg.unpublish("mallory", "flappy").unwrap(), "non-owner unpublish -> no-op");
        assert!(reg.unpublish("alice", "flappy").unwrap());
        assert_eq!(reg.get("flappy").unwrap(), None);
    }

    #[test]
    fn pipeline_registry_pooled_lists_run_concurrently_while_unpooled_serializes_398() {
        // #398: same proof shape as #344's cda587a test -- `list` (the `GET
        // /registry/pipelines` discovery surface) now takes a connection from `readers`
        // instead of `writer`, so N concurrent slow lists should overlap instead of
        // queuing. File-backed `open()` store (pooled) vs. in-memory (`readers: None`,
        // falls back to `writer`) proves the speedup is attributable to the pool.
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        const N: usize = 8;
        const SLEEP: Duration = Duration::from_millis(100);

        fn run_n_concurrent_slow_reads(reg: &Arc<SqlitePipelineRegistry>, n: usize) -> Duration {
            let started = Instant::now();
            let handles: Vec<_> = (0..n)
                .map(|_| {
                    let reg = Arc::clone(reg);
                    std::thread::spawn(move || {
                        let _conn = reg.read();
                        std::thread::sleep(SLEEP);
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap();
            }
            started.elapsed()
        }

        let path = temp_db_path();
        let pooled = Arc::new(SqlitePipelineRegistry::open(&path).unwrap());
        let pooled_elapsed = run_n_concurrent_slow_reads(&pooled, N);

        let unpooled = Arc::new(SqlitePipelineRegistry::open_in_memory().unwrap());
        let unpooled_elapsed = run_n_concurrent_slow_reads(&unpooled, N);

        assert!(
            pooled_elapsed < SLEEP * 3,
            "pooled reads should run concurrently (~1x SLEEP), not serialize: {pooled_elapsed:?} for \
             {N} reads of {SLEEP:?} each"
        );
        assert!(
            unpooled_elapsed >= SLEEP * (N as u32) / 2,
            "unpooled (in-memory) reads should still serialize through the writer mutex \
             (~{N}x SLEEP): got only {unpooled_elapsed:?} for {N} reads of {SLEEP:?} each"
        );

        drop(pooled);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    #[test]
    fn pipeline_registry_concurrent_publishes_and_lists_all_succeed_398() {
        // #398: real concurrent `list`/`get` reads (the pool) mixed with a real concurrent
        // `publish` write workload -- distinct ids per writer, so no ownership clash --
        // asserting neither errors and the durable end state has exactly the specs every
        // writer thread published.
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        const WRITERS: usize = 4;
        const PUBLISHES_PER_WRITER: usize = 25;
        const READERS: usize = 4;

        let path = temp_db_path();
        let reg = Arc::new(SqlitePipelineRegistry::open(&path).unwrap());
        let stop = Arc::new(AtomicBool::new(false));

        let reader_handles: Vec<_> = (0..READERS)
            .map(|_| {
                let reg = Arc::clone(&reg);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let mut reads = 0u32;
                    while !stop.load(Ordering::Relaxed) {
                        reg.list().expect("a concurrent list must not error while publishes are landing");
                        reads += 1;
                    }
                    reads
                })
            })
            .collect();

        let writer_handles: Vec<_> = (0..WRITERS)
            .map(|w| {
                let reg = Arc::clone(&reg);
                std::thread::spawn(move || {
                    for i in 0..PUBLISHES_PER_WRITER {
                        let spec = ct_common::pipeline::PipelineSpec {
                            id: format!("writer-{w}-pipeline-{i}"),
                            roles: vec![],
                            operator_pubkey_hex: None,
                            selection_policy: ct_common::pipeline::SelectionPolicy::LowestFloor,
                        };
                        assert!(
                            reg.publish(&format!("writer-{w}"), &spec, 100)
                                .expect("a concurrent publish must succeed within the 5s busy_timeout"),
                            "distinct ids per writer never clash on ownership"
                        );
                    }
                })
            })
            .collect();

        for h in writer_handles {
            h.join().unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        let total_reads: u32 = reader_handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert!(total_reads > 0, "readers actually ran concurrently with the writers, not sequentially after");

        assert_eq!(
            reg.list().unwrap().len(),
            WRITERS * PUBLISHES_PER_WRITER,
            "every concurrent publish() across every writer thread landed exactly once"
        );

        drop(reg);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    #[test]
    fn topology_authorized_channels_fold_edges_through_link_derivation() {
        // #107-enforce (frozen): a topology's authorized channel set = its declared edges folded
        // through channel_id_for_link. Under the unified identity model (maintainer 2026-07-24
        // "most robust") a node id IS the agent's 32-byte holder key (hex), so an edge names
        // exactly its derived channel; an undeclared pair is absent (membership ≠ authorization);
        // a non-holder-key label is skipped; and it is operator-bound + empty for unknown topos.
        let store = SqliteTopologyStore::open_in_memory().unwrap();
        let owner = "alice";
        store.create_topology(owner, "t1", "uuid1").unwrap();

        let op = [0x11u8; 32];
        let a = [0xaau8; 32];
        let b = [0xbbu8; 32];
        let c = [0xccu8; 32];
        let hx = |k: &[u8; 32]| k.iter().map(|x| format!("{x:02x}")).collect::<String>();

        // Declared graph: a—b and b—c (holder-hex node ids). Plus a bogus non-hex edge that the
        // derivation must skip (it cannot name a real channel).
        store.add_edge(owner, "t1", &hx(&a), &hx(&b)).unwrap();
        store.add_edge(owner, "t1", &hx(&b), &hx(&c)).unwrap();
        store.add_edge(owner, "t1", "not-a-holder-key", &hx(&a)).unwrap();

        let authorized = store.authorized_channels("t1", &op).unwrap();
        let ab = ct_common::channel::channel_id_for_link(&op, &a, &b);
        let bc = ct_common::channel::channel_id_for_link(&op, &b, &c);
        assert_eq!(authorized.len(), 2, "exactly the two valid declared links (bogus edge skipped)");
        assert!(authorized.contains(&ab) && authorized.contains(&bc), "both declared links present");

        // An undeclared pair a—c is NOT authorized even though both are members of the graph.
        assert!(
            !authorized.contains(&ct_common::channel::channel_id_for_link(&op, &a, &c)),
            "undeclared a—c refused (membership is not authorization)"
        );

        // Operator-bound: another operator's identically-shaped topology authorizes other channels.
        let authorized2 = store.authorized_channels("t1", &[0x22u8; 32]).unwrap();
        assert!(!authorized2.contains(&ab), "operator-bound: op2 does not authorize op1's channel");

        // An unknown / empty topology authorizes nothing.
        assert!(store.authorized_channels("nope", &op).unwrap().is_empty(), "unknown topology → empty");
    }

    #[test]
    fn topology_operator_binding_is_owner_scoped_authenticated_and_drives_authorized_channels() {
        // #107-enforce ii-a (frozen): a topology carries its OWN operator pubkey, bound only with
        // BOTH (owner-scoping) AND (operator proof-of-possession) — closing the admission bypass
        // where a public operator key could be bound to an attacker's topology. operator() reads it
        // back; unbound/unknown → None; and the bound operator is the identity authorized_channels
        // derives under.
        use ed25519_dalek::{Signer, SigningKey};
        let store = SqliteTopologyStore::open_in_memory().unwrap();
        store.create_topology("alice", "t1", "uuid1").unwrap();

        let op_sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let op = op_sk.verifying_key().to_bytes();
        // The operator's proof-of-possession for binding its key to topology "t1".
        let proof = op_sk
            .sign(&ct_common::channel::topology_operator_binding_bytes("t1", &op))
            .to_bytes();

        // Unbound initially; unknown topology → None.
        assert_eq!(store.operator("t1").unwrap(), None, "no operator bound yet");
        assert_eq!(store.operator("nope").unwrap(), None, "unknown topology → None");

        // A valid proof but WRONG owner is rejected (owner-scoping), binding stays absent.
        assert!(!store.set_operator("mallory", "t1", &op, &proof).unwrap(), "non-owner cannot bind");
        assert_eq!(store.operator("t1").unwrap(), None, "unauthorized owner left it unbound");

        // The owner WITHOUT a valid proof is rejected (proof-of-possession) — this is the bypass
        // guard: a forged proof (attacker key signing op's binding) cannot bind op's key.
        let attacker = SigningKey::from_bytes(&[0x99u8; 32]);
        let forged = attacker
            .sign(&ct_common::channel::topology_operator_binding_bytes("t1", &op))
            .to_bytes();
        assert!(!store.set_operator("alice", "t1", &op, &forged).unwrap(), "forged proof rejected (no bypass)");
        assert_eq!(store.operator("t1").unwrap(), None, "forged proof left it unbound");

        // Owner + valid proof binds; reads back.
        assert!(store.set_operator("alice", "t1", &op, &proof).unwrap(), "owner + valid proof binds");
        assert_eq!(store.operator("t1").unwrap(), Some(op), "operator reads back");

        // The bound operator is the identity the topology's authorized channels derive under.
        let a = [0xaau8; 32];
        let b = [0xbbu8; 32];
        let hx = |k: &[u8; 32]| k.iter().map(|x| format!("{x:02x}")).collect::<String>();
        store.add_edge("alice", "t1", &hx(&a), &hx(&b)).unwrap();
        let bound = store.operator("t1").unwrap().unwrap();
        assert!(
            store
                .authorized_channels("t1", &bound)
                .unwrap()
                .contains(&ct_common::channel::channel_id_for_link(&op, &a, &b)),
            "authorized channels derive under the bound operator key"
        );

        // A valid re-bind (to another proven operator key) overwrites (idempotent setter).
        let op2_sk = SigningKey::from_bytes(&[0x55u8; 32]);
        let op2 = op2_sk.verifying_key().to_bytes();
        let proof2 = op2_sk
            .sign(&ct_common::channel::topology_operator_binding_bytes("t1", &op2))
            .to_bytes();
        assert!(store.set_operator("alice", "t1", &op2, &proof2).unwrap(), "owner re-binds with proof");
        assert_eq!(store.operator("t1").unwrap(), Some(op2), "re-bind overwrites");
    }

    #[test]
    fn topology_authorizes_a_holder_only_on_a_declared_edges_channel() {
        // #107-enforce ii-b (frozen): the admission reverse-lookup. A holder is authorized on a
        // channel iff an OPERATOR-BOUND topology declares the edge that names it. An undeclared
        // channel, a stranger holder, or an UNBOUND topology all authorize nothing.
        use ed25519_dalek::{Signer, SigningKey};
        let store = SqliteTopologyStore::open_in_memory().unwrap();
        store.create_topology("alice", "t1", "uuid1").unwrap();

        let op_sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let op = op_sk.verifying_key().to_bytes();
        let a = [0xaau8; 32];
        let b = [0xbbu8; 32];
        let c = [0xccu8; 32];
        let hx = |k: &[u8; 32]| k.iter().map(|x| format!("{x:02x}")).collect::<String>();
        store.add_edge("alice", "t1", &hx(&a), &hx(&b)).unwrap();

        let chan_ab = ct_common::channel::channel_id_for_link(&op, &a, &b);
        let chan_ac = ct_common::channel::channel_id_for_link(&op, &a, &c);

        // BEFORE the operator is bound, the topology authorizes nothing (unbound ⇒ no enforcement).
        assert_eq!(store.topology_authorizes(&chan_ab, &a).unwrap(), None, "unbound topology authorizes nothing");

        // Bind the operator (authenticated, ii-a).
        let proof = op_sk
            .sign(&ct_common::channel::topology_operator_binding_bytes("t1", &op))
            .to_bytes();
        assert!(store.set_operator("alice", "t1", &op, &proof).unwrap());

        // Now the declared edge a—b authorizes BOTH its endpoints on its channel, and returns the op.
        assert_eq!(store.topology_authorizes(&chan_ab, &a).unwrap(), Some(op), "declared endpoint a authorized");
        assert_eq!(store.topology_authorizes(&chan_ab, &b).unwrap(), Some(op), "declared endpoint b authorized");

        // A holder NOT on the channel's naming edge is refused, even on a real channel.
        assert_eq!(store.topology_authorizes(&chan_ab, &c).unwrap(), None, "c is not an endpoint of a—b");
        // An undeclared channel (a—c edge was never drawn) is refused for a real member.
        assert_eq!(store.topology_authorizes(&chan_ac, &a).unwrap(), None, "a—c channel is not declared");
    }

    #[test]
    fn topology_pooled_authorizes_run_concurrently_while_unpooled_serializes_398() {
        // #398: same proof shape as #344's cda587a test -- `topology_authorizes` (the
        // `/internal/channel/authorize` admission fallback's per-connection hot path) now
        // takes a connection from `readers` instead of `writer`, so N concurrent slow
        // lookups should overlap instead of queuing. File-backed `open()` store (pooled) vs.
        // in-memory (`readers: None`, falls back to `writer`) proves the speedup is
        // attributable to the pool.
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        const N: usize = 8;
        const SLEEP: Duration = Duration::from_millis(100);

        fn run_n_concurrent_slow_reads(store: &Arc<SqliteTopologyStore>, n: usize) -> Duration {
            let started = Instant::now();
            let handles: Vec<_> = (0..n)
                .map(|_| {
                    let store = Arc::clone(store);
                    std::thread::spawn(move || {
                        let _conn = store.read();
                        std::thread::sleep(SLEEP);
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap();
            }
            started.elapsed()
        }

        let path = temp_db_path();
        let pooled = Arc::new(SqliteTopologyStore::open(&path).unwrap());
        let pooled_elapsed = run_n_concurrent_slow_reads(&pooled, N);

        let unpooled = Arc::new(SqliteTopologyStore::open_in_memory().unwrap());
        let unpooled_elapsed = run_n_concurrent_slow_reads(&unpooled, N);

        assert!(
            pooled_elapsed < SLEEP * 3,
            "pooled reads should run concurrently (~1x SLEEP), not serialize: {pooled_elapsed:?} for \
             {N} reads of {SLEEP:?} each"
        );
        assert!(
            unpooled_elapsed >= SLEEP * (N as u32) / 2,
            "unpooled (in-memory) reads should still serialize through the writer mutex \
             (~{N}x SLEEP): got only {unpooled_elapsed:?} for {N} reads of {SLEEP:?} each"
        );

        drop(pooled);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    #[test]
    fn topology_concurrent_edge_writes_and_authorizes_reads_all_succeed_398() {
        // #398: real concurrent `topology_authorizes` reads (the pool) mixed with a real
        // concurrent `add_edge` write workload against distinct topologies (so no ownership
        // clash), asserting neither errors and every concurrently-added edge is durably
        // present at the end.
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        const WRITERS: usize = 4;
        const EDGES_PER_WRITER: usize = 20;
        const READERS: usize = 4;

        let path = temp_db_path();
        let store = Arc::new(SqliteTopologyStore::open(&path).unwrap());
        // One shared topology every writer wires distinct node pairs into, and every reader
        // polls with `topology_authorizes` -- a channel that's never actually declared, so
        // every read is a real miss lookup exercised against a live, growing edge table.
        store.create_topology("owner-0", "shared", "uuid-shared").unwrap();
        let never_declared = ChannelId([0x77u8; 32]);
        let probe_holder = [0x01u8; 32];
        let stop = Arc::new(AtomicBool::new(false));

        let reader_handles: Vec<_> = (0..READERS)
            .map(|_| {
                let store = Arc::clone(&store);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let mut reads = 0u32;
                    while !stop.load(Ordering::Relaxed) {
                        store
                            .topology_authorizes(&never_declared, &probe_holder)
                            .expect("a concurrent topology_authorizes must not error while edges are landing");
                        reads += 1;
                    }
                    reads
                })
            })
            .collect();

        let writer_handles: Vec<_> = (0..WRITERS)
            .map(|w| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    for i in 0..EDGES_PER_WRITER {
                        let a = format!("{:064x}", w * 1000 + i * 2);
                        let b = format!("{:064x}", w * 1000 + i * 2 + 1);
                        assert!(
                            store
                                .add_edge("owner-0", "shared", &a, &b)
                                .expect("a concurrent add_edge must succeed within the 5s busy_timeout"),
                            "distinct node pairs per writer never clash"
                        );
                    }
                })
            })
            .collect();

        for h in writer_handles {
            h.join().unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        let total_reads: u32 = reader_handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert!(total_reads > 0, "readers actually ran concurrently with the writers, not sequentially after");

        assert_eq!(
            store.edges("shared").unwrap().len(),
            WRITERS * EDGES_PER_WRITER,
            "every concurrent add_edge() across every writer thread landed exactly once"
        );

        drop(store);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    fn tenant() -> TenantId {
        TenantId("tenant-1".into())
    }

    #[test]
    fn network_store_is_owner_scoped_and_round_trips() {
        // #102: a declarative Network persists per (owner, id) and is strictly
        // owner-scoped — another subject can't see it.
        use ct_common::policy::{Agent, AllowRule, Levels, Network, Policy, Selector};

        let store = SqliteNetworkStore::open_in_memory().unwrap();
        let net = Network {
            agents: vec![
                Agent::new("dev-1", "dev", "internal"),
                Agent::new("ops-1", "ops", "internal"),
            ],
            policy: Policy {
                levels: Levels::new(["public", "internal", "secret"]),
                rules: vec![AllowRule { from: Selector::group("dev"), to: Selector::group("ops") }],
                mac_flow_control: true,
            },
        };

        // Put + get round-trips the whole Network for its owner.
        store.put("alice", "corp", &net).unwrap();
        assert_eq!(store.get("alice", "corp").unwrap().as_ref(), Some(&net), "round-trips for the owner");

        // Owner isolation: another subject sees nothing under the same id.
        assert_eq!(store.get("mallory", "corp").unwrap(), None, "not visible to another owner");
        assert_eq!(store.get("alice", "other").unwrap(), None, "unknown id -> None");

        // List is owner-scoped; put replaces in place.
        store.put("alice", "team", &Network::default()).unwrap();
        assert_eq!(store.list("alice").unwrap(), vec!["corp".to_string(), "team".to_string()]);
        assert_eq!(store.list("mallory").unwrap(), Vec::<String>::new());

        // Delete removes only that owner's row.
        assert!(store.delete("alice", "corp").unwrap());
        assert!(!store.delete("alice", "corp").unwrap(), "already gone");
        assert_eq!(store.list("alice").unwrap(), vec!["team".to_string()]);
    }

    #[test]
    fn network_store_get_revalidates_on_read_and_hides_an_invalid_stored_network_478() {
        // #478: `Network::validate()` is opt-in -- `SqliteNetworkStore::put` itself does not
        // enforce it (only the authenticated REST `PUT` handler does, one call site). A row
        // written before the validator existed, by a migration, or by any future write path
        // that forgets to call `validate()`, must not be handed back to a caller unrevalidated
        // -- `get()` has to close that gap itself, on every read, not rely on every writer
        // getting it right.
        use ct_common::policy::{Agent, Network, Policy};

        let store = SqliteNetworkStore::open_in_memory().unwrap();
        let invalid = Network {
            agents: vec![
                Agent::new("worker", "dev", "internal"),
                Agent::new("worker", "dev", "internal"), // typo'd duplicate id
            ],
            policy: Policy::default(),
        };
        assert!(invalid.validate().is_err(), "sanity: this Network really is invalid");

        // put() has no validation of its own -- simulates a write path that forgot to call
        // Network::validate() (or a row that predates the validator).
        store.put("alice", "corp", &invalid).unwrap();

        assert_eq!(
            store.get("alice", "corp").unwrap(),
            None,
            "get() must revalidate on read and refuse to hand back an invalid stored network, \
             exactly as it already does for a blob that fails to deserialize at all"
        );

        // A subsequent valid write for the same (owner, id) is visible again -- the read-path
        // check only ever suppresses invalid rows, it doesn't wedge the slot.
        let valid = Network {
            agents: vec![Agent::new("worker", "dev", "internal")],
            policy: Policy::default(),
        };
        store.put("alice", "corp", &valid).unwrap();
        assert_eq!(store.get("alice", "corp").unwrap(), Some(valid), "a valid overwrite is visible again");
    }

    #[test]
    fn topology_store_enforces_exclusivity_across_a_restart() {
        use crate::topology::AssignError;

        let path = temp_db_path();
        {
            let store = SqliteTopologyStore::open(&path).unwrap();
            // Alice shares her agent into net-1 (first touch registers her as owner).
            store.assign("alice", "agent-1", "net-1").unwrap();
            assert_eq!(store.assignment("agent-1").unwrap().unwrap().topology(), Some("net-1"));

            // Exclusivity: it can't join a second topology while assigned.
            assert!(matches!(
                store.assign("alice", "agent-1", "net-2"),
                Err(TopologyError::Assign(AssignError::AlreadyAssigned { .. }))
            ));
            // Owner-scoped: another subject can neither reassign nor revoke it.
            assert!(matches!(
                store.assign("mallory", "agent-1", "net-2"),
                Err(TopologyError::Assign(AssignError::NotAuthorized))
            ));
            assert!(matches!(
                store.revoke("mallory", "agent-1"),
                Err(TopologyError::Assign(AssignError::NotAuthorized))
            ));
            // A second agent joins net-1 too.
            store.assign("alice", "agent-2", "net-1").unwrap();
            assert_eq!(store.agents_in("net-1").unwrap(), vec!["agent-1", "agent-2"]);
        }

        // Reopen on the same file: the exclusivity state persisted.
        {
            let store = SqliteTopologyStore::open(&path).unwrap();
            assert_eq!(store.assignment("agent-1").unwrap().unwrap().topology(), Some("net-1"));
            // Still exclusive after restart.
            assert!(matches!(
                store.assign("alice", "agent-1", "net-2"),
                Err(TopologyError::Assign(AssignError::AlreadyAssigned { .. }))
            ));

            // Revoke returns control to the owner; only then can it be reassigned.
            store.revoke("net-1", "agent-1").unwrap(); // the topology releases it
            assert!(!store.assignment("agent-1").unwrap().unwrap().is_assigned());
            store.assign("alice", "agent-1", "net-2").unwrap();
            assert_eq!(store.assignment("agent-1").unwrap().unwrap().topology(), Some("net-2"));

            // Revoking an unassigned agent errors.
            store.revoke("alice", "agent-2").unwrap();
            assert!(matches!(
                store.revoke("alice", "agent-2"),
                Err(TopologyError::Assign(AssignError::NotAssigned))
            ));
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn set_agent_label_is_owner_scoped_trims_clears_and_caps_length_698() {
        // #698 finding 6: an owner-set alias, same authority shape as set_agent_kind.
        let store = SqliteTopologyStore::open_in_memory().unwrap();
        store.assign("alice", "agent-1", "net-1").unwrap();

        // A stranger (not the agent's owner) cannot label it.
        assert!(!store.set_agent_label("mallory", "agent-1", Some("mine now")).unwrap());
        assert_eq!(store.agents_with_kind("net-1").unwrap()[0].2, None, "rejected label leaves it unset");

        // The owner can set a label; leading/trailing whitespace is trimmed.
        assert!(store.set_agent_label("alice", "agent-1", Some("  kali-desktop-2  ")).unwrap());
        assert_eq!(store.agents_with_kind("net-1").unwrap()[0].2.as_deref(), Some("kali-desktop-2"));

        // An all-whitespace (or empty) label clears it, same as `None`.
        assert!(store.set_agent_label("alice", "agent-1", Some("   ")).unwrap());
        assert_eq!(store.agents_with_kind("net-1").unwrap()[0].2, None, "whitespace-only label clears");
        assert!(store.set_agent_label("alice", "agent-1", Some("re-set")).unwrap());
        assert!(store.set_agent_label("alice", "agent-1", None).unwrap());
        assert_eq!(store.agents_with_kind("net-1").unwrap()[0].2, None, "None clears an existing label");

        // Over the length cap is rejected outright (no silent truncation).
        let too_long = "x".repeat(41);
        assert!(store.set_agent_label("alice", "agent-1", Some(&too_long)).is_err());
        assert!(store.set_agent_label("alice", "agent-1", Some(&"x".repeat(40))).unwrap(), "exactly 40 is fine");

        // An agent that has never been touched has no row to update: no-op, not an error.
        assert!(!store.set_agent_label("alice", "never-touched", Some("x")).unwrap());

        // A label survives a revoke/reassign cycle -- agent-scoped like `kind`, not
        // topology-scoped (persist()'s ON CONFLICT never touches this column).
        store.revoke("alice", "agent-1").unwrap();
        store.assign("alice", "agent-1", "net-2").unwrap();
        assert_eq!(store.agents_with_kind("net-2").unwrap()[0].2.as_deref(), Some(&"x".repeat(40)[..]));
    }

    #[test]
    fn topology_entity_has_unique_id_and_net_uuid_and_is_owner_scoped() {
        // #107: a Topology is a named container keyed by a unique net_uuid (its
        // live-status subdomain); ids + uuids are unique, delete is owner-scoped.
        let store = SqliteTopologyStore::open_in_memory().unwrap();

        assert!(store.create_topology("alice", "corp", "uuid-abc").unwrap(), "first create");
        assert!(!store.create_topology("alice", "corp", "uuid-xyz").unwrap(), "dup id -> no-op");
        assert!(!store.create_topology("bob", "team", "uuid-abc").unwrap(), "dup net_uuid -> no-op");
        assert!(store.create_topology("bob", "team", "uuid-xyz").unwrap(), "distinct id + uuid ok");

        // Lookup by id and by net_uuid (the subdomain resolver).
        let t = store.topology("corp").unwrap().unwrap();
        assert_eq!((t.owner.as_str(), t.net_uuid.as_str()), ("alice", "uuid-abc"));
        assert_eq!(store.topology_by_uuid("uuid-abc").unwrap().unwrap().id, "corp");
        assert!(store.topology_by_uuid("nope").unwrap().is_none());

        // Listing is owner-scoped.
        assert_eq!(
            store.list_topologies("alice").unwrap().iter().map(|t| t.id.clone()).collect::<Vec<_>>(),
            vec!["corp".to_string()]
        );

        // Delete is owner-scoped.
        assert!(!store.delete_topology("bob", "corp").unwrap(), "non-owner delete -> no-op");
        assert!(store.topology("corp").unwrap().is_some(), "still there");
        assert!(store.delete_topology("alice", "corp").unwrap(), "owner deletes");
        assert!(store.topology("corp").unwrap().is_none());
    }

    #[test]
    fn delete_topology_cascades_edges_shares_and_releases_assigned_agents_account_overhaul() {
        // Account-deletion cascade work surfaced this: `delete_topology` used to
        // only drop the `topologies` row itself, leaving `topology_edges` /
        // `topology_shares` orphaned and an assigned agent permanently pointed at
        // a now-nonexistent topology id. Real cascade required.
        let store = SqliteTopologyStore::open_in_memory().unwrap();
        store.create_topology("alice", "t1", "u1").unwrap();
        store.add_edge("alice", "t1", "a", "b").unwrap();
        store.share_add("alice", "t1", "carol@example.com", 100).unwrap();
        store.assign("alice", "agent-x", "t1").unwrap();
        assert_eq!(store.assignment("agent-x").unwrap().unwrap().topology(), Some("t1"));

        assert!(store.delete_topology("alice", "t1").unwrap());

        assert!(store.edges("t1").unwrap().is_empty(), "edges gone with the topology");
        assert!(store.shares_for("alice", "t1").unwrap().is_empty(), "shares gone (owner check also fails post-delete, both == empty)");
        assert!(
            !store.assignment("agent-x").unwrap().unwrap().is_assigned(),
            "the agent is released back to unassigned, not left pointed at a dead topology"
        );
    }

    #[test]
    fn delete_all_owned_by_and_remove_shares_by_email_drive_the_account_deletion_cascade() {
        let store = SqliteTopologyStore::open_in_memory().unwrap();
        store.create_topology("alice", "t1", "u1").unwrap();
        store.create_topology("alice", "t2", "u2").unwrap();
        store.create_topology("dave", "dt", "u3").unwrap();
        store.share_add("dave", "dt", "alice@example.com", 100).unwrap();
        store.share_add("alice", "t1", "carol@example.com", 100).unwrap();

        let removed = store.delete_all_owned_by("alice").unwrap();
        assert_eq!(removed, 2, "both of alice's topologies removed");
        assert!(store.list_topologies("alice").unwrap().is_empty());
        assert!(store.topology("dt").unwrap().is_some(), "dave's topology is untouched");

        // alice is still listed as a collaborator on dave's topology until the
        // email-scoped cleanup runs (the account-deletion route's second step).
        assert!(store.is_shared_with("dt", "alice@example.com").unwrap());
        let stripped = store.remove_shares_by_email("alice@example.com").unwrap();
        assert_eq!(stripped, 1);
        assert!(!store.is_shared_with("dt", "alice@example.com").unwrap());
    }

    #[test]
    fn topology_edge_list_is_undirected_owner_scoped_and_deduped() {
        // #107: the who-connects-to-whom wiring — undirected + canonical, owner-scoped.
        let store = SqliteTopologyStore::open_in_memory().unwrap();
        store.create_topology("alice", "t1", "u1").unwrap();

        // Wire b—a; it is stored canonically as (a, b).
        assert!(store.add_edge("alice", "t1", "b", "a").unwrap(), "edge added");
        assert_eq!(store.edges("t1").unwrap(), vec![("a".into(), "b".into())]);
        // Undirected + idempotent: the reverse / same edge is a no-op.
        assert!(!store.add_edge("alice", "t1", "a", "b").unwrap(), "dup edge -> no-op");
        // Self-loop rejected.
        assert!(!store.add_edge("alice", "t1", "x", "x").unwrap(), "self-loop -> no-op");
        // Owner-scoped: a non-owner can't wire the topology.
        assert!(!store.add_edge("mallory", "t1", "c", "d").unwrap(), "non-owner -> no-op");
        assert_eq!(store.edges("t1").unwrap(), vec![("a".into(), "b".into())], "unchanged");

        // A second edge; the adjacency is sorted.
        assert!(store.add_edge("alice", "t1", "c", "a").unwrap());
        assert_eq!(
            store.edges("t1").unwrap(),
            vec![("a".into(), "b".into()), ("a".into(), "c".into())]
        );

        // Remove is canonical + owner-scoped.
        assert!(!store.remove_edge("mallory", "t1", "b", "a").unwrap(), "non-owner remove -> no-op");
        assert!(store.remove_edge("alice", "t1", "b", "a").unwrap(), "owner removes b—a");
        assert!(!store.remove_edge("alice", "t1", "a", "b").unwrap(), "already gone");
        assert_eq!(store.edges("t1").unwrap(), vec![("a".into(), "c".into())]);
    }

    #[test]
    fn edges_are_case_normalized_so_a_differently_cased_remove_actually_removes_405() {
        // #405: node ids are case-insensitive hex holder keys. Wiring with one casing then
        // removing with another must actually delete the row — otherwise topology_authorizes'
        // own lower()-based check keeps authorizing a channel the UI showed as removed.
        let store = SqliteTopologyStore::open_in_memory().unwrap();
        store.create_topology("alice", "t1", "u1").unwrap();

        assert!(store.add_edge("alice", "t1", "AABB", "ccdd").unwrap());
        assert_eq!(store.edges("t1").unwrap(), vec![("aabb".into(), "ccdd".into())], "stored lowercased");

        // Removing with yet another casing combination must find and delete the same row.
        assert!(
            store.remove_edge("alice", "t1", "aabb", "CCDD").unwrap(),
            "differently-cased remove must still match the lowercased stored row"
        );
        assert!(store.edges("t1").unwrap().is_empty());

        // Adding the same logical edge under two different raw casings is a single edge,
        // not two — case-insensitive dedup, matching the ordinary same-case dedup above.
        assert!(store.add_edge("alice", "t1", "ABCD", "1234").unwrap());
        assert!(!store.add_edge("alice", "t1", "abcd", "1234").unwrap(), "same edge, different case -> no-op");
        assert!(!store.add_edge("alice", "t1", "1234", "ABCD").unwrap(), "same edge, reversed + different case -> no-op");
        assert_eq!(store.edges("t1").unwrap(), vec![("1234".into(), "abcd".into())]);
    }

    #[test]
    fn opening_a_db_with_pre_existing_mixed_case_and_colliding_edges_migrates_cleanly_405() {
        // #405: a self-host DB written before this fix may have mixed-case rows, including
        // two differently-cased rows for the SAME logical edge (which would collide on the
        // PRIMARY KEY once both are lowercased) — the boot-time migration must dedupe
        // safely rather than fail to open or silently drop a channel_id.
        let path = temp_db_path();
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE topologies (id TEXT PRIMARY KEY, owner TEXT NOT NULL, net_uuid TEXT NOT NULL UNIQUE);
                 CREATE TABLE topology_edges (
                     topology TEXT NOT NULL, a TEXT NOT NULL, b TEXT NOT NULL,
                     PRIMARY KEY (topology, a, b)
                 );
                 INSERT INTO topologies VALUES ('t1', 'alice', 'net-uuid-1');
                 -- Two rows that collide once lowercased: ('AA','bb') and ('aa','BB').
                 INSERT INTO topology_edges VALUES ('t1', 'AA', 'bb');
                 INSERT INTO topology_edges VALUES ('t1', 'aa', 'BB');
                 -- An unrelated, already-lowercase row must survive untouched.
                 INSERT INTO topology_edges VALUES ('t1', 'cc', 'dd');",
            )
            .unwrap();
        }
        // Opening (running the migration) must succeed, not error or panic on the collision.
        let store = SqliteTopologyStore::open(&path).unwrap();
        let edges = store.edges("t1").unwrap();
        assert_eq!(edges.len(), 2, "the two colliding rows deduped to one, plus the untouched one");
        assert!(edges.contains(&("aa".into(), "bb".into())), "the colliding pair survived, lowercased");
        assert!(edges.contains(&("cc".into(), "dd".into())), "the untouched row survived, unchanged");
        // The store is otherwise fully functional post-migration.
        assert!(store.add_edge("alice", "t1", "EE", "ff").unwrap());
        assert!(edges.len() < store.edges("t1").unwrap().len());
    }

    #[test]
    fn topology_overlay_mode_persists_owner_scoped_and_defaults_to_direct() {
        // #107-ui-mode: the owner picks direct (baseline) vs complex-adaptive (smart-route).
        use ct_common::overlay::RoutingApproach;
        let store = SqliteTopologyStore::open_in_memory().unwrap();
        store.create_topology("alice", "t1", "u1").unwrap();

        // Default is the safe direct mode (the additive column's DEFAULT 'baseline').
        assert_eq!(store.overlay_mode("t1").unwrap(), Some(RoutingApproach::Baseline));
        // A topology that doesn't exist -> None.
        assert_eq!(store.overlay_mode("ghost").unwrap(), None);

        // The owner switches to a complex-adaptive mode; it persists.
        assert!(store.set_overlay_mode("alice", "t1", RoutingApproach::SmartRoute).unwrap());
        assert_eq!(store.overlay_mode("t1").unwrap(), Some(RoutingApproach::SmartRoute));

        // Owner-scoped: a non-owner can't retune it (no-op, value unchanged).
        assert!(!store.set_overlay_mode("mallory", "t1", RoutingApproach::Baseline).unwrap());
        assert_eq!(store.overlay_mode("t1").unwrap(), Some(RoutingApproach::SmartRoute), "unchanged");
        // Setting the mode of a non-existent topology is a no-op.
        assert!(!store.set_overlay_mode("alice", "ghost", RoutingApproach::Shortcut).unwrap());

        // A legacy/garbage stored value degrades to Baseline (direct) — never a read error.
        store
            .writer
            .lock_safe()
            .execute("UPDATE topologies SET overlay_mode = 'legacy-nonsense' WHERE id = 't1'", [])
            .unwrap();
        assert_eq!(store.overlay_mode("t1").unwrap(), Some(RoutingApproach::Baseline), "unknown -> direct");
    }

    #[test]
    fn channel_challenge_is_single_use_and_expires() {
        // #108: a redemption challenge nonce is fresh once, then consumed; expiry rejects.
        let store = SqliteChannelStore::open_in_memory().unwrap();
        let n = store.issue_challenge(1_000, 120).unwrap();
        assert!(store.consume_challenge(&n, 1_050).unwrap(), "fresh within TTL");
        assert!(!store.consume_challenge(&n, 1_060).unwrap(), "same nonce again -> false (single-use)");
        // An unknown nonce is never fresh.
        assert!(!store.consume_challenge(&[0x9au8; 32], 1_000).unwrap());
        // An expired nonce is rejected (and pruned).
        let m = store.issue_challenge(1_000, 60).unwrap();
        assert!(!store.consume_challenge(&m, 1_061).unwrap(), "past TTL -> false");
    }

    #[test]
    fn issue_challenge_prunes_expired_rows_so_a_flood_of_this_endpoint_alone_self_bounds_403() {
        // #403: consume_challenge's own prune is only reached after a valid invitation
        // later verifies -- an idle deployment (nobody currently redeeming) never hit
        // that path, so a bare flood of just issue_challenge grew the table without
        // bound. issue_challenge now prunes too, so it self-bounds on its own.
        let store = SqliteChannelStore::open_in_memory().unwrap();
        let count = |s: &SqliteChannelStore| -> i64 {
            s.writer
                .lock_safe()
                .query_row("SELECT COUNT(*) FROM channel_challenges", [], |r| r.get(0))
                .unwrap()
        };
        // 50 short-TTL nonces, all now expired.
        for _ in 0..50 {
            store.issue_challenge(1_000, 10).unwrap();
        }
        assert_eq!(count(&store), 50, "all 50 tracked before any prune-triggering call");
        // A single later issue_challenge call, well past every prior nonce's expiry,
        // must sweep all of them -- not just the caller's own new row.
        let fresh = store.issue_challenge(1_000_000, 60).unwrap();
        assert_eq!(count(&store), 1, "the 50 expired rows were pruned; only the fresh one remains");
        assert!(store.consume_challenge(&fresh, 1_000_010).unwrap(), "the fresh nonce is still valid");
    }

    #[test]
    fn consume_invitation_is_single_use_and_prunes_expired() {
        // #108: an invitation redemption is recorded consumed by its signature; a replay
        // is rejected, a distinct invitation is independent, an expired one is never fresh.
        let store = SqliteChannelStore::open_in_memory().unwrap();
        let sig = [0x11u8; 64];
        assert!(store.consume_invitation(&sig, 1_000, 100).unwrap(), "first redeem is fresh");
        assert!(!store.consume_invitation(&sig, 1_000, 200).unwrap(), "replay rejected");
        // A distinct invitation (its own signature) is independently fresh.
        assert!(store.consume_invitation(&[0x22u8; 64], 1_000, 200).unwrap());
        // An already-expired invitation is never fresh (defensive; verify_invitation
        // rejects an expired one first anyway).
        assert!(!store.consume_invitation(&[0x33u8; 64], 1_000, 1_000).unwrap(), "expired -> not fresh");
        // A still-unexpired consumed record stays consumed across a later call.
        assert!(store.consume_invitation(&[0x44u8; 64], 5_000, 2_000).unwrap());
        assert!(!store.consume_invitation(&[0x44u8; 64], 5_000, 2_001).unwrap(), "still consumed before expiry");
    }

    #[test]
    fn bootstrap_token_redeems_once_within_ttl_then_is_dead() {
        // #90/#97 SEC90b: a bootstrap token hands off the real secret exactly once,
        // within a short TTL — so a copy left in shell history / `ps` is useless once
        // redeemed or expired. Time is caller-supplied for determinism.
        let store = SqliteBootstrap::open_in_memory().unwrap();
        let now = 1_000_000u64;
        let ttl = 300u64; // 5 minutes

        // Mint → redeem within the TTL returns the exact secret.
        let tok = store.mint("join=aa;routing=bb", ttl, now).unwrap();
        assert_eq!(store.redeem(&tok, now + 10).unwrap(), "join=aa;routing=bb");

        // Single-use: a second redemption fails (and does not re-hand-off the secret).
        assert!(
            matches!(store.redeem(&tok, now + 11), Err(BootstrapError::AlreadyUsed)),
            "second redemption must fail single-use"
        );

        // A never-minted token is unknown.
        assert!(matches!(
            store.redeem(&[0x42u8; 32], now),
            Err(BootstrapError::UnknownToken)
        ));

        // Expiry: a token redeemed past its TTL fails Expired and is consumed, so it
        // can't be retried (a later in-window `now` still fails — here AlreadyUsed).
        let expiring = store.mint("secret", ttl, now).unwrap();
        assert!(matches!(
            store.redeem(&expiring, now + ttl + 1),
            Err(BootstrapError::Expired)
        ));
        assert!(matches!(
            store.redeem(&expiring, now + 1),
            Err(BootstrapError::AlreadyUsed)
        ));

        // Prune drops the consumed rows; a fresh live token survives.
        let live = store.mint("still-good", ttl, now).unwrap();
        assert!(store.prune(now + 1).unwrap() >= 1, "consumed/expired rows pruned");
        assert_eq!(store.redeem(&live, now + 2).unwrap(), "still-good", "live token survives prune");
    }

    /// A unique temp DB path (no wall-clock / process helpers needed).
    fn temp_db_path() -> String {
        let mut b = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut b);
        let name: String = b.iter().map(|x| format!("{x:02x}")).collect();
        std::env::temp_dir()
            .join(format!("ct_enroll_{name}.db"))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn open_tunes_the_connection_for_wal_and_busy_timeout() {
        // #110: every file-backed store `open()` routes through `open_tuned`,
        // which must leave the connection in WAL mode with a non-zero
        // `busy_timeout` so concurrent control-plane writers queue instead of
        // getting an immediate `SQLITE_BUSY`. Deterministic: assert the pragmas
        // the fix sets, rather than racing two writers.
        let path = temp_db_path();
        let store = SqliteEnrollment::open(&path).expect("open a file-backed store");

        let conn = store.conn.lock().unwrap();
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode;", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode.to_lowercase(), "wal", "journal_mode is WAL");
        let busy_timeout: i64 = conn
            .query_row("PRAGMA busy_timeout;", [], |row| row.get(0))
            .unwrap();
        assert!(busy_timeout > 0, "busy_timeout is set (got {busy_timeout})");
        drop(conn);
        drop(store);

        // Clean up the DB plus the WAL/SHM sidecars WAL mode creates.
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    #[cfg(unix)]
    #[test]
    fn open_restricts_the_file_and_its_wal_shm_sidecars_to_owner_only() {
        // This DB file holds ledger balances, payment/issuance records, and
        // service-account data -- `Connection::open`'s default umask-based mode
        // (typically 0644) would let any other local account on the host read it
        // directly, bypassing the control plane entirely.
        use std::os::unix::fs::PermissionsExt;
        let path = temp_db_path();
        let store = SqliteBootstrap::open(&path).expect("open a file-backed store");
        // Force a write so a real transaction has actually touched the WAL, not
        // just the initial schema-creation one from `open`/`from_connection`.
        let _ = store.mint("perm-test-secret", 3600u64, 1u64).unwrap();

        let mode = |p: &str| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600, "main db file must be owner-only, not the umask default");
        for suffix in ["-wal", "-shm"] {
            let sidecar = format!("{path}{suffix}");
            if std::path::Path::new(&sidecar).exists() {
                assert_eq!(mode(&sidecar), 0o600, "{sidecar} must be owner-only too -- it can hold the same data");
            }
        }

        drop(store);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    #[test]
    fn pooled_reads_run_concurrently_while_the_same_pattern_serializes_without_a_pool_344() {
        // #344: the actual performance claim -- a file-backed `open()` store's READ-only
        // methods (`Self::read`) take a connection from `readers` instead of the single
        // `writer` `Mutex<Connection>` every other store still uses, so N concurrent slow
        // reads should overlap instead of queuing one after another. Matching this repo's
        // own house style for proving a performance claim empirically (#341,
        // crates/edge/src/serve.rs): real concurrent threads, a real elapsed-time
        // measurement, and a generous-but-real threshold -- not a micro-benchmark
        // assertion. Proven two ways in one test, same workload, only the store shape
        // differs: a file-backed pooled store (fast, ~1 SLEEP) vs. an in-memory store
        // (`readers: None`, per its own struct doc) that still serializes every read
        // through `writer` exactly like before this migration (~N * SLEEP) -- so the
        // speedup is demonstrably attributable to the pool, not some other test artifact.
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        const N: usize = 8;
        const SLEEP: Duration = Duration::from_millis(100);

        fn run_n_concurrent_slow_reads(store: &Arc<SqliteTunnelStore>, n: usize) -> Duration {
            let started = Instant::now();
            let handles: Vec<_> = (0..n)
                .map(|_| {
                    let store = Arc::clone(store);
                    std::thread::spawn(move || {
                        // Hold a real connection from `Self::read` for the sleep duration --
                        // simulates a slow query without needing one, and exercises the exact
                        // guard (`ReadConn`) every read method above actually uses.
                        let _conn = store.read();
                        std::thread::sleep(SLEEP);
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap();
            }
            started.elapsed()
        }

        // File-backed: `open()` builds the reader pool (max_size 8, matching N here) --
        // all N reads should be able to check out their own connection and overlap.
        let path = temp_db_path();
        let pooled = Arc::new(SqliteTunnelStore::open(&path).unwrap());
        let pooled_elapsed = run_n_concurrent_slow_reads(&pooled, N);

        // In-memory: no pool, so every `read()` falls back to locking `writer` directly --
        // the same single-`Mutex<Connection>` serialization #344's finding describes.
        let unpooled = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let unpooled_elapsed = run_n_concurrent_slow_reads(&unpooled, N);

        assert!(
            pooled_elapsed < SLEEP * 3,
            "pooled reads should run concurrently (~1x SLEEP), not serialize: {pooled_elapsed:?} for \
             {N} reads of {SLEEP:?} each"
        );
        assert!(
            unpooled_elapsed >= SLEEP * (N as u32) / 2,
            "unpooled (in-memory) reads should still serialize through the writer mutex \
             (~{N}x SLEEP): got only {unpooled_elapsed:?} for {N} reads of {SLEEP:?} each"
        );

        drop(pooled);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    #[test]
    fn concurrent_readers_and_writers_all_succeed_under_the_pool_within_busy_timeout_344() {
        // #344: the correctness question the migration's own struct doc raises -- pooling
        // reads means pooled reader connections now run against the SAME on-disk file WHILE
        // `writer` is actively landing writes, a genuinely new interleaving that didn't exist
        // when one Mutex<Connection> serialized everything in-process. WRITE methods
        // (`create`) still all funnel through the single `writer` connection (unchanged from
        // before this migration), so they can never race EACH OTHER for SQLite's one
        // engine-level write lock -- what this test actually exercises is real concurrent
        // readers (the pool) mixed with a real concurrent write workload, asserting both that
        // no operation ever errors (would surface as a real SQLITE_BUSY past the 5s
        // busy_timeout) and that the durable end state has exactly the rows every writer
        // thread actually wrote -- not just "it didn't panic once".
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        const WRITERS: usize = 4;
        const CREATES_PER_WRITER: usize = 25;
        const READERS: usize = 4;

        let path = temp_db_path();
        let store = Arc::new(SqliteTunnelStore::open(&path).unwrap());
        let stop = Arc::new(AtomicBool::new(false));

        // Readers hammer the hot path #344's own finding cites (`list_authorized_for_subject`,
        // the `/portal/tunnels` handler's own call) via the pool, for the whole test.
        let reader_handles: Vec<_> = (0..READERS)
            .map(|_| {
                let store = Arc::clone(&store);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let mut reads = 0u32;
                    while !stop.load(Ordering::Relaxed) {
                        store
                            .list_authorized_for_subject("writer-0")
                            .expect("a concurrent read must not error while writes are landing");
                        reads += 1;
                    }
                    reads
                })
            })
            .collect();

        // Writers concurrently create real rows through `writer` -- the exact same
        // serialization every other store's Mutex<Connection> already provides today, now
        // proven under real concurrent callers plus a concurrent read workload on top.
        let writer_handles: Vec<_> = (0..WRITERS)
            .map(|w| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    for i in 0..CREATES_PER_WRITER {
                        store
                            .create(&format!("writer-{w}"), &format!("t{i}"), None)
                            .expect("a concurrent create must succeed within the 5s busy_timeout");
                    }
                })
            })
            .collect();

        for h in writer_handles {
            h.join().unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        let total_reads: u32 = reader_handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert!(total_reads > 0, "readers actually ran concurrently with the writers, not sequentially after");

        // Durable end state: every create() from every writer thread landed exactly once --
        // no write silently lost to a race, no duplicate, under real concurrent access.
        assert_eq!(
            store.all().unwrap().len(),
            WRITERS * CREATES_PER_WRITER,
            "every concurrent create() across every writer thread landed exactly once"
        );

        drop(store);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    /// Operator bug report (15.08.): re-creating a name whose deterministic
    /// hostname already exists surfaced as a 500 "internal error" (UNIQUE
    /// constraint) instead of a clean answer. The create gate now answers with
    /// three distinct shapes: Created / OverLimit / HostnameTaken.
    /// #517 V3 slice 2: direct-serving is owner-opt-in, its probe state persists
    /// across the fold_probe hysteresis, and disabling wipes it clean.
    #[test]
    fn direct_serving_opt_in_and_probe_state_roundtrip_517() {
        use crate::direct_serving::{fold_probe, DirectServingState};
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        let t = match store
            .create_if_under_owned_limit("subj-d", "svc", Some("svc-x.example"), 2)
            .unwrap()
        {
            CreateTunnelOutcome::Created(t) => t,
            other => panic!("create: {other:?}"),
        };

        // Off by default; a foreign subject can't read or toggle it.
        assert_eq!(store.direct_serving("subj-d", &t.id).unwrap(), Some((false, None, false)));
        assert_eq!(store.direct_serving("someone-else", &t.id).unwrap(), None);
        assert!(!store.set_direct_serving("someone-else", &t.id, true, Some("1.2.3.4:443")).unwrap());

        // Owner opts in with an endpoint -> armed but not yet advertised, and it
        // shows up as a probe candidate.
        assert!(store.set_direct_serving("subj-d", &t.id, true, Some("1.2.3.4:443")).unwrap());
        assert_eq!(
            store.direct_serving("subj-d", &t.id).unwrap(),
            Some((true, Some("1.2.3.4:443".to_string()), false))
        );
        let cands = store.direct_serving_candidates().unwrap();
        assert_eq!(cands.len(), 1);
        let (tid, host, ep, state) = &cands[0];
        assert_eq!((tid.as_str(), host.as_str(), ep.as_str()), (t.id.as_str(), "svc-x.example", "1.2.3.4:443"));

        // Drive fold_probe and persist: first success publishes, and it survives a reload.
        let (state, action) = fold_probe(*state, true);
        assert_eq!(action, crate::direct_serving::DirectServingAction::Publish);
        store.record_direct_probe(&t.id, state, 1_000).unwrap();
        assert_eq!(
            store.direct_serving("subj-d", &t.id).unwrap(),
            Some((true, Some("1.2.3.4:443".to_string()), true)),
            "advertised state persisted"
        );
        // A single failure holds; the persisted failure streak carries.
        let reloaded = store.direct_serving_candidates().unwrap()[0].3;
        assert_eq!(reloaded, DirectServingState { advertised: true, consecutive_failures: 0 });
        let (state, _) = fold_probe(reloaded, false);
        store.record_direct_probe(&t.id, state, 1_030).unwrap();
        assert_eq!(store.direct_serving_candidates().unwrap()[0].3.consecutive_failures, 1);

        // Disable wipes the probe state (and drops it from the candidate list).
        assert!(store.set_direct_serving("subj-d", &t.id, false, None).unwrap());
        assert_eq!(store.direct_serving("subj-d", &t.id).unwrap(), Some((false, Some("1.2.3.4:443".to_string()), false)));
        assert!(store.direct_serving_candidates().unwrap().is_empty(), "disabled tunnels aren't probed");
    }

    #[test]
    fn create_gate_distinguishes_quota_from_hostname_collision() {
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        let t = match store.create_if_under_owned_limit("subj-a", "app", Some("app-x.example"), 2).unwrap() {
            CreateTunnelOutcome::Created(t) => t,
            other => panic!("first create must succeed, got {other:?}"),
        };
        assert_eq!(t.hostname.as_deref(), Some("app-x.example"));
        // Same derived hostname again (same account re-typing the same name):
        // a clean HostnameTaken, NOT a rusqlite UNIQUE error.
        assert!(matches!(
            store.create_if_under_owned_limit("subj-a", "app", Some("app-x.example"), 2).unwrap(),
            CreateTunnelOutcome::HostnameTaken
        ));
        // Different hostname still fits under the limit...
        assert!(matches!(
            store.create_if_under_owned_limit("subj-a", "app2", Some("app2-x.example"), 2).unwrap(),
            CreateTunnelOutcome::Created(_)
        ));
        // ...and the quota answer stays distinct from the collision answer.
        assert!(matches!(
            store.create_if_under_owned_limit("subj-a", "app3", Some("app3-x.example"), 2).unwrap(),
            CreateTunnelOutcome::OverLimit
        ));
    }

    #[test]
    fn subject_tunnel_store_is_self_scoped_for_create_list_revoke() {
        // #27 PP1: a customer creates, lists and revokes only their OWN tunnels.
        let store = SqliteTunnelStore::open_in_memory().unwrap();

        let a1 = store.create("alice", "web", Some("app.example")).unwrap().created().expect("hostname is free in this test");
        let _a2 = store.create("alice", "ssh", None).unwrap().created().expect("hostname is free in this test");
        let b1 = store.create("bob", "db", None).unwrap().created().expect("hostname is free in this test");

        // Listing is scoped to the subject — alice sees her two, bob sees his one.
        let alice = store.list_for_subject("alice").unwrap();
        assert_eq!(alice.len(), 2, "alice sees only her own tunnels");
        assert!(alice.iter().any(|t| t.name == "web" && t.hostname.as_deref() == Some("app.example")));
        assert_eq!(store.list_for_subject("bob").unwrap().len(), 1);

        // Cross-subject revoke is refused: bob cannot delete alice's tunnel.
        assert!(store.revoke("bob", &a1.id, 1_000).unwrap().is_none(), "no cross-subject revoke");
        assert_eq!(store.list_for_subject("alice").unwrap().len(), 2, "alice's tunnel survives");

        // Owner revoke removes exactly that tunnel and returns its routing token.
        assert_eq!(store.revoke("alice", &a1.id, 1_000).unwrap(), Some(a1.routing_token.clone()));
        let alice = store.list_for_subject("alice").unwrap();
        assert_eq!(alice.len(), 1);
        assert!(alice.iter().all(|t| t.id != a1.id));

        // Revoking an unknown id is a no-op false; bob's tunnel is untouched.
        assert!(store.revoke("alice", "deadbeef", 1_000).unwrap().is_none());
        assert_eq!(store.list_for_subject("bob").unwrap(), vec![b1]);
    }

    #[test]
    fn hostname_is_unique_across_subjects_and_within_one_subjects_own_tunnels_406() {
        // #406: nothing previously enforced one-tunnel-per-hostname -- two different
        // subjects (the cross-tenant case admin_provision_tunnel could hit) or the same
        // subject twice (the auto_hostname collision case) could both claim the same
        // hostname, and every hostname-keyed lookup would then silently read whichever
        // row SQLite happened to return first.
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        store.create("alice", "web", Some("shared.example")).unwrap().created().expect("hostname is free in this test");

        // Cross-subject collision: bob claiming alice's exact hostname must fail, not
        // silently create a second row for the same hostname.
        // #545: the refusal is now a TYPED answer rather than the unique index's error.
        // The property this test guards is unchanged -- no second row for one hostname --
        // but the caller can tell a collision from a database fault, which is what let the
        // operator path answer 500 for a perfectly ordinary conflict.
        assert!(
            matches!(
                store.create("bob", "other", Some("shared.example")),
                Ok(CreateTunnelOutcome::HostnameTaken)
            ),
            "a second subject claiming an already-owned hostname must be rejected"
        );
        // Same-subject collision (the auto_hostname(name, subject) determinism case).
        assert!(
            matches!(
                store.create("alice", "web-again", Some("shared.example")),
                Ok(CreateTunnelOutcome::HostnameTaken)
            ),
            "the SAME subject claiming a hostname they already own a row for must also be rejected"
        );
        // Only the original row exists — no partial/duplicate state from the failed inserts.
        assert_eq!(store.list_for_subject("alice").unwrap().len(), 1);
        assert_eq!(store.list_for_subject("bob").unwrap().len(), 0);

        // Mesh-Plane-only tunnels (no hostname at all) are unaffected — the index is
        // partial (`WHERE hostname IS NOT NULL`), so multiple NULLs are never a conflict.
        store.create("alice", "ssh-1", None).unwrap().created().expect("hostname is free in this test");
        store.create("alice", "ssh-2", None).unwrap().created().expect("hostname is free in this test");
        assert_eq!(store.list_for_subject("alice").unwrap().len(), 3, "two NULL-hostname tunnels + the original");

        // A different hostname is, of course, completely unaffected.
        store.create("bob", "own", Some("bob-owns-this.example")).unwrap().created().expect("hostname is free in this test");
        assert_eq!(store.list_for_subject("bob").unwrap().len(), 1);
    }

    #[test]
    fn opening_a_db_with_pre_existing_duplicate_hostnames_never_fails_to_boot_406() {
        // #406: a self-host DB that already has duplicate hostname rows (from before this
        // fix existed) must not crash on open when the new UNIQUE index can't be created
        // over already-duplicated data — the fix must degrade to "index skipped, loudly
        // logged" rather than making an existing, already-broken deployment worse by
        // refusing to boot at all.
        let path = temp_db_path();
        {
            // Seed pre-existing duplicate rows directly, bypassing create()'s own (not yet
            // existing at this raw-SQL point) protection — simulates a genuinely
            // already-duplicated legacy DB.
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE subject_tunnels (
                     id TEXT PRIMARY KEY, subject TEXT NOT NULL, name TEXT NOT NULL,
                     hostname TEXT, created_at INTEGER NOT NULL,
                     routing_token TEXT NOT NULL DEFAULT ''
                 );
                 INSERT INTO subject_tunnels VALUES ('id1','alice','web','dup.example',1,'');
                 INSERT INTO subject_tunnels VALUES ('id2','bob','other','dup.example',2,'');",
            )
            .unwrap();
        }
        // Opening (running every migration, including this one) must succeed, not error.
        let store = SqliteTunnelStore::open(&path).unwrap();
        // Both pre-existing duplicate rows are still there (nothing was destructively
        // resolved automatically — that decision needs an operator, not this migration).
        assert_eq!(store.list_for_subject("alice").unwrap().len(), 1);
        assert_eq!(store.list_for_subject("bob").unwrap().len(), 1);
        // The store is otherwise fully functional — a fresh, non-conflicting hostname
        // still works normally.
        assert!(store.create("carol", "fresh", Some("fresh.example")).is_ok());
    }

    #[test]
    fn reopening_an_older_db_migrates_missing_columns_instead_of_500ing() {
        // #44: a self-host DB created by an OLDER binary has subject_tunnels
        // WITHOUT the later-added `hostname` (#23) / `routing_token` (#27) columns.
        // CREATE TABLE IF NOT EXISTS won't touch it, so pre-fix the first create()
        // hit "no column named routing_token" and 500'd. Reproduce that exact
        // starting state, then prove open() migrates it and create()/list() work.
        let path = temp_db_path();

        // Old-schema DB: subject_tunnels as it existed before #23/#27.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE subject_tunnels (
                     id         TEXT PRIMARY KEY,
                     subject    TEXT NOT NULL,
                     name       TEXT NOT NULL,
                     created_at INTEGER NOT NULL
                 );",
            )
            .unwrap();
        }

        // Reopen with the current binary — from_connection runs the migration.
        let store = SqliteTunnelStore::open(&path).unwrap();
        let created = store
            .create("alice", "web", Some("app.example"))
            .expect("create must not 500 on a migrated older DB")
            .created()
            .expect("hostname is free in this test");
        assert_eq!(created.routing_token.len(), 64, "routing_token column present + minted");
        let listed = store.list_for_subject("alice").unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].hostname.as_deref(), Some("app.example"), "hostname column present");

        // Idempotent: a second open over the now-migrated DB is a clean no-op.
        let store2 = SqliteTunnelStore::open(&path).unwrap();
        assert_eq!(store2.list_for_subject("alice").unwrap().len(), 1);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn each_tunnel_binds_a_persistent_routing_token_returned_on_revoke() {
        // #27 RB1: creation mints a distinct 32-byte (64-hex) routing token that
        // persists (survives a re-read) and is returned when the tunnel is revoked
        // — the linkage a later cycle uses to invalidate the edge registration.
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        let a = store.create("alice", "web", None).unwrap().created().expect("hostname is free in this test");
        let b = store.create("alice", "ssh", None).unwrap().created().expect("hostname is free in this test");
        assert_eq!(a.routing_token.len(), 64, "32-byte hex routing token");
        assert_ne!(a.routing_token, b.routing_token, "distinct per tunnel");

        // The token persists (list re-reads it from the row).
        let listed = store.list_for_subject("alice").unwrap();
        assert!(listed.iter().any(|t| t.routing_token == a.routing_token));

        // Revoke returns exactly that token so the caller can act on it.
        assert_eq!(store.revoke("alice", &a.id, 1_000).unwrap(), Some(a.routing_token));
        // A second revoke of the same id yields nothing.
        assert_eq!(store.revoke("alice", &a.id, 1_000).unwrap(), None);
    }

    #[test]
    fn revoke_durably_records_the_token_for_edge_boot_replay_327() {
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        assert_eq!(store.list_revoked_tokens().unwrap(), Vec::<String>::new(), "nothing revoked yet");

        let a = store.create("alice", "web", None).unwrap().created().expect("hostname is free in this test");
        let b = store.create("alice", "api", None).unwrap().created().expect("hostname is free in this test");
        assert_eq!(store.revoke("alice", &a.id, 1_000).unwrap(), Some(a.routing_token.clone()));

        let revoked = store.list_revoked_tokens().unwrap();
        assert_eq!(revoked, vec![a.routing_token.clone()], "exactly the revoked tunnel's token, durably");

        // A second, distinct revoke accumulates rather than replacing.
        store.revoke("alice", &b.id, 2_000).unwrap();
        let mut revoked = store.list_revoked_tokens().unwrap();
        revoked.sort();
        let mut expected = vec![a.routing_token, b.routing_token];
        expected.sort();
        assert_eq!(revoked, expected, "both revocations persist");

        // A no-op revoke (unknown id) records nothing new.
        assert!(store.revoke("alice", "deadbeef", 3_000).unwrap().is_none());
        assert_eq!(store.list_revoked_tokens().unwrap().len(), 2, "a failed revoke records nothing");
    }

    #[test]
    fn routing_token_for_hostname_is_unscoped_and_none_for_unknown_hosts() {
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        let t = store.create("alice", "web", Some("app.example")).unwrap().created().expect("hostname is free in this test");
        assert_eq!(store.routing_token_for_hostname("app.example").unwrap(), Some(t.routing_token));
        assert_eq!(store.routing_token_for_hostname("no-such-host").unwrap(), None);
    }

    #[test]
    fn a_fresh_tunnel_starts_rot_with_no_admission_state() {
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        store.create("alice", "web", Some("app.example")).unwrap().created().expect("hostname is free in this test");
        let a = store.cert_admission_for_hostname("app.example").unwrap().unwrap();
        assert_eq!(a.status, "rot");
        assert_eq!(a.assigned_ca, None);
        assert_eq!(a.claim_state, "none");
        assert_eq!(a.claim_deadline, None);
        assert_eq!(a.queue_position, None, "not queued yet -- no position at all, not zero");
        assert_eq!(store.cert_admission_for_hostname("no-such-host").unwrap(), None);
    }

    #[test]
    fn entering_the_gelb_queue_is_fifo_and_wont_clobber_a_hostname_thats_moved_on() {
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        store.create("alice", "a", Some("a.example")).unwrap().created().expect("hostname is free in this test");
        store.create("alice", "b", Some("b.example")).unwrap().created().expect("hostname is free in this test");
        store.create("alice", "c", Some("c.example")).unwrap().created().expect("hostname is free in this test");

        assert!(store.enter_gelb_queue("a.example", 100).unwrap());
        assert!(store.enter_gelb_queue("b.example", 200).unwrap());
        assert!(store.enter_gelb_queue("c.example", 300).unwrap());
        // Re-entering an already-gelb hostname is a no-op, not a queue-jump.
        assert!(!store.enter_gelb_queue("a.example", 999).unwrap());

        assert_eq!(store.gelb_queue_fifo().unwrap(), vec!["a.example", "b.example", "c.example"]);
        assert_eq!(store.cert_admission_for_hostname("a.example").unwrap().unwrap().queue_position, Some(0));
        assert_eq!(store.cert_admission_for_hostname("b.example").unwrap().unwrap().queue_position, Some(1));
        assert_eq!(store.cert_admission_for_hostname("c.example").unwrap().unwrap().queue_position, Some(2));
    }

    #[test]
    fn cert_admission_for_hostnames_batches_exactly_what_the_per_row_lookup_would_return_351() {
        // #351: the real claim is "one batched call returns the SAME data N per-row calls
        // would have" -- not just "the batched call doesn't crash". Mixes a gruen hostname
        // (no queue_position), a not-yet-gelb host, an unknown hostname (must be absent
        // from the map, not present with a default), and three gelb-queued hosts with a
        // TIE in queued_at (b and c) to prove the batched queue_position math (a sorted
        // Vec + partition_point) reproduces the per-row `COUNT(*) WHERE queued_at < ?`
        // semantics exactly, ties included, not just for the easy strictly-increasing case.
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        store.create("alice", "a", Some("a.example")).unwrap().created().expect("hostname is free in this test");
        store.create("alice", "b", Some("b.example")).unwrap().created().expect("hostname is free in this test");
        store.create("alice", "c", Some("c.example")).unwrap().created().expect("hostname is free in this test");
        store.create("alice", "d", Some("d.example")).unwrap().created().expect("hostname is free in this test");
        store.enter_gelb_queue("a.example", 100).unwrap();
        store.enter_gelb_queue("b.example", 200).unwrap();
        store.enter_gelb_queue("c.example", 200).unwrap(); // tie with b
        // d.example stays "rot" (never entered the queue).

        let hostnames = ["a.example", "b.example", "c.example", "d.example", "no-such-host"];
        let batched = store.cert_admission_for_hostnames(&hostnames).unwrap();

        assert_eq!(batched.len(), 4, "the unknown hostname must be absent, not present with a default");
        assert!(!batched.contains_key("no-such-host"));

        for h in ["a.example", "b.example", "c.example", "d.example"] {
            let per_row = store.cert_admission_for_hostname(h).unwrap().unwrap();
            assert_eq!(
                batched.get(h).cloned(),
                Some(per_row),
                "batched result for {h} must exactly match the single-hostname lookup, ties included"
            );
        }
        // Spell out the tie result explicitly too, not just "matches the other method":
        // b and c share queued_at=200, so both must see exactly 1 hostname (a) ahead of
        // them, and neither counts the other despite the tie.
        assert_eq!(batched["a.example"].queue_position, Some(0));
        assert_eq!(batched["b.example"].queue_position, Some(1));
        assert_eq!(batched["c.example"].queue_position, Some(1));
        assert_eq!(batched["d.example"].queue_position, None, "not gelb -- no queue position");
    }

    #[test]
    fn offering_a_claim_assigns_a_ca_permanently_and_leaves_the_queue() {
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        store.create("alice", "a", Some("a.example")).unwrap().created().expect("hostname is free in this test");
        store.enter_gelb_queue("a.example", 100).unwrap();

        assert!(store.offer_claim("a.example", "letsencrypt", 500, 500 + 48 * 3600).unwrap());
        // A second offer attempt is a no-op -- assigned_ca is already set.
        assert!(!store.offer_claim("a.example", "zerossl", 600, 999).unwrap());

        let a = store.cert_admission_for_hostname("a.example").unwrap().unwrap();
        assert_eq!(a.status, "gelb");
        assert_eq!(a.assigned_ca.as_deref(), Some("letsencrypt"), "the FIRST offer wins, never overwritten");
        assert_eq!(a.claim_state, "offered");
        assert_eq!(a.claim_deadline, Some(500 + 48 * 3600));
        assert_eq!(a.queue_position, None, "no longer meaningfully 'in the queue' once offered");
        assert!(store.gelb_queue_fifo().unwrap().is_empty(), "offered hostnames leave the FIFO candidate list");
    }

    #[test]
    fn an_expired_unclaimed_offer_lapses_and_frees_its_ca_assignment() {
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        store.create("alice", "a", Some("a.example")).unwrap().created().expect("hostname is free in this test");
        store.enter_gelb_queue("a.example", 100).unwrap();
        store.offer_claim("a.example", "letsencrypt", 500, 1000).unwrap();

        assert_eq!(store.lapse_expired_claims(999).unwrap(), 0, "deadline not yet passed");
        assert_eq!(store.lapse_expired_claims(1001).unwrap(), 1);

        let a = store.cert_admission_for_hostname("a.example").unwrap().unwrap();
        assert_eq!(a.status, "gelb", "still gelb -- a lapse is not a demotion to rot");
        assert_eq!(a.claim_state, "lapsed");
        assert_eq!(a.assigned_ca, None, "an unclaimed offer never consumed real CA capacity");
    }

    #[test]
    fn reclaiming_a_lapsed_slot_goes_to_the_back_of_the_queue_not_its_old_position() {
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        store.create("alice", "a", Some("a.example")).unwrap().created().expect("hostname is free in this test");
        store.create("alice", "b", Some("b.example")).unwrap().created().expect("hostname is free in this test");
        store.enter_gelb_queue("a.example", 100).unwrap();
        store.enter_gelb_queue("b.example", 200).unwrap();
        store.offer_claim("a.example", "letsencrypt", 300, 400).unwrap();
        store.lapse_expired_claims(500).unwrap();

        // Wrong subject / not actually lapsed -> no-op.
        assert!(!store.reclaim_cert_slot("bob", "a.example", 600).unwrap());
        assert!(!store.reclaim_cert_slot("alice", "b.example", 600).unwrap(), "b never lapsed");

        assert!(store.reclaim_cert_slot("alice", "a.example", 600).unwrap());
        // b was already queued (queued_at=200) and never lapsed; a re-enters
        // fresh at queued_at=600 -- so b is now ahead, not a.
        assert_eq!(store.gelb_queue_fifo().unwrap(), vec!["b.example", "a.example"]);
    }

    #[test]
    fn a_completed_issuance_uses_the_stores_own_assigned_ca_not_a_caller_supplied_one() {
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        store.create("alice", "a", Some("a.example")).unwrap().created().expect("hostname is free in this test");
        store.enter_gelb_queue("a.example", 100).unwrap();
        store.offer_claim("a.example", "google-trust-services", 200, 999_999).unwrap();

        let recorded_ca = store.record_issuance_complete("a.example", "example.com", 300).unwrap();
        assert_eq!(recorded_ca.as_deref(), Some("google-trust-services"));

        let a = store.cert_admission_for_hostname("a.example").unwrap().unwrap();
        assert_eq!(a.status, "gruen");
        assert_eq!(a.claim_state, "none");
        assert_eq!(a.claim_deadline, None);
        assert_eq!(a.assigned_ca.as_deref(), Some("google-trust-services"), "permanent, unchanged by completion");

        let (used, reserved) = store.ca_budget_usage("google-trust-services", "example.com", 0).unwrap();
        assert_eq!(used, 1);
        assert_eq!(reserved, 0, "no longer 'offered' once complete -- doesn't double-count");

        // A genuine renewal, temporally distant (past #407's anti-flood floor,
        // MIN_ISSUANCE_LOG_INTERVAL_SECS = 24h -- real renewals are ~60 days apart),
        // still adds a second, correct ledger row -- renewals really do consume CA
        // capacity again. A call within the floor window (not this one) is the
        // replay/flood case #407 exists to suppress -- see the dedicated test below.
        store.record_issuance_complete("a.example", "example.com", 300 + 25 * 60 * 60).unwrap();
        let (used_after_renewal, _) = store.ca_budget_usage("google-trust-services", "example.com", 0).unwrap();
        assert_eq!(used_after_renewal, 2);
    }

    #[test]
    fn record_issuance_complete_does_not_double_log_within_the_anti_flood_floor_407() {
        // #407: this endpoint can't tell a genuine renewal apart from a replay/retry --
        // the caller is a customer-controlled agent, not the operator. Once a hostname is
        // gruen, a repeat call still passes the UPDATE's WHERE clause (status = 'gruen'),
        // so without a floor an unbounded flood of "complete" calls for the SAME hostname
        // could exhaust the whole domain's shared CA budget bucket and lock out every
        // other tenant. Real proof: many repeat calls, all within
        // MIN_ISSUANCE_LOG_INTERVAL_SECS (24h) of the first, must log exactly once.
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        store.create("alice", "a", Some("a.example")).unwrap().created().expect("hostname is free in this test");
        store.enter_gelb_queue("a.example", 100).unwrap();
        store.offer_claim("a.example", "google-trust-services", 200, 999_999).unwrap();

        store.record_issuance_complete("a.example", "example.com", 300).unwrap();
        for i in 0..50 {
            // Every call lands well inside the 24h floor from the first (max offset here
            // is 50 * 60s = 50 minutes), simulating a flood/replay, not real renewals.
            store.record_issuance_complete("a.example", "example.com", 300 + i * 60).unwrap();
        }
        let (used, _) = store.ca_budget_usage("google-trust-services", "example.com", 0).unwrap();
        assert_eq!(used, 1, "50 repeat calls within the floor must log exactly once, not 51 times");

        // A different hostname's own flood is tracked independently -- the floor is
        // per-hostname, not a single global gate that would starve unrelated tenants.
        store.create("bob", "b", Some("b.example")).unwrap().created().expect("hostname is free in this test");
        store.enter_gelb_queue("b.example", 100).unwrap();
        store.offer_claim("b.example", "google-trust-services", 200, 999_999).unwrap();
        store.record_issuance_complete("b.example", "example.com", 300).unwrap();
        let (used_both, _) = store.ca_budget_usage("google-trust-services", "example.com", 0).unwrap();
        assert_eq!(used_both, 2, "an unrelated hostname's own completion is unaffected");
    }

    #[test]
    fn ca_budget_usage_counts_offered_reservations_as_real_headroom_consumption() {
        // #469: `reserved` is now scoped through `registered_domain(hostname)`, so the
        // hostnames here must actually resolve to the "example.com" domain being
        // queried -- the original "a.example"/"b.example" placeholders (a synthetic
        // single-label pseudo-TLD, not `example.com`) predate that scoping and never
        // exercised it; `registered_domain` would strip them to bare "a.example"/
        // "b.example", not "example.com", so the pre-fix accidental scope-free `reserved`
        // count happened to still match this test's own assertions by coincidence.
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        store.create("alice", "a", Some("a.example.com")).unwrap().created().expect("hostname is free in this test");
        store.create("alice", "b", Some("b.example.com")).unwrap().created().expect("hostname is free in this test");
        store.enter_gelb_queue("a.example.com", 100).unwrap();
        store.enter_gelb_queue("b.example.com", 200).unwrap();
        store.offer_claim("a.example.com", "zerossl", 300, 999_999).unwrap();
        store.record_issuance_complete("a.example.com", "example.com", 400).unwrap();
        store.offer_claim("b.example.com", "zerossl", 500, 999_999).unwrap();

        let (used, reserved) = store.ca_budget_usage("zerossl", "example.com", 0).unwrap();
        assert_eq!(used, 1, "a.example.com's completed issuance");
        assert_eq!(reserved, 1, "b.example.com's still-open offer, not yet completed");
    }

    #[test]
    fn ca_budget_usage_reserved_is_scoped_per_domain_469() {
        // #469: before this fix, `reserved` counted every in-flight offer for the CA
        // across ALL domains, unscoped -- so a second zone's open offers would silently
        // consume the FIRST zone's budget headroom. Real proof: an open offer under
        // "other-zone.org" must not count toward "example.com"'s reserved figure.
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        store.create("alice", "a", Some("a.example.com")).unwrap().created().expect("hostname is free in this test");
        store.create("bob", "z", Some("z.other-zone.org")).unwrap().created().expect("hostname is free in this test");
        store.enter_gelb_queue("a.example.com", 100).unwrap();
        store.enter_gelb_queue("z.other-zone.org", 200).unwrap();
        store.offer_claim("a.example.com", "zerossl", 300, 999_999).unwrap();
        store.offer_claim("z.other-zone.org", "zerossl", 300, 999_999).unwrap();

        let (used_a, reserved_a) = store.ca_budget_usage("zerossl", "example.com", 0).unwrap();
        assert_eq!(used_a, 0);
        assert_eq!(reserved_a, 1, "only example.com's own open offer counts");

        let (used_z, reserved_z) = store.ca_budget_usage("zerossl", "other-zone.org", 0).unwrap();
        assert_eq!(used_z, 0);
        assert_eq!(reserved_z, 1, "the other zone's own open offer, independently scoped");
    }

    #[test]
    fn may_issue_now_is_true_only_within_an_open_offer_or_once_permanently_gruen() {
        let rot = CertAdmission { status: "rot".into(), assigned_ca: None, claim_state: "none".into(), claim_deadline: None, queue_position: None };
        assert!(!rot.may_issue_now(1000));

        let gelb_queued = CertAdmission { status: "gelb".into(), assigned_ca: None, claim_state: "none".into(), claim_deadline: None, queue_position: Some(3) };
        assert!(!gelb_queued.may_issue_now(1000));

        let offered = CertAdmission {
            status: "gelb".into(),
            assigned_ca: Some("letsencrypt".into()),
            claim_state: "offered".into(),
            claim_deadline: Some(2000),
            queue_position: None,
        };
        assert!(offered.may_issue_now(1000), "within the open window");
        assert!(!offered.may_issue_now(2000), "deadline itself is not still open");
        assert!(!offered.may_issue_now(2001), "past the deadline");

        let lapsed = CertAdmission { status: "gelb".into(), assigned_ca: None, claim_state: "lapsed".into(), claim_deadline: None, queue_position: None };
        assert!(!lapsed.may_issue_now(1000));

        let gruen = CertAdmission {
            status: "gruen".into(),
            assigned_ca: Some("zerossl".into()),
            claim_state: "none".into(),
            claim_deadline: None,
            queue_position: None,
        };
        assert!(gruen.may_issue_now(1000), "gruen always may-issue -- renewals must never block");
        assert!(gruen.may_issue_now(i64::MAX), "forever, regardless of how much later");
    }

    #[test]
    fn granted_tunnels_are_visible_and_authorized_to_the_grantee() {
        // #29 fix: a grant gives real effect — the grantee sees the tunnel and can
        // obtain its routing token; a non-grantee gets neither.
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        let t = store.create("alice", "web", None).unwrap().created().expect("hostname is free in this test");
        store.grant("alice", &t.id, "bob").unwrap();

        // Grantee: authorized for the token, and sees it flagged not-owned.
        assert_eq!(
            store.routing_token_if_authorized("bob", &t.id).unwrap(),
            Some(t.routing_token.clone())
        );
        let bob_list = store.list_authorized_for_subject("bob").unwrap();
        assert_eq!(bob_list.len(), 1);
        assert_eq!(bob_list[0].0.id, t.id);
        assert!(!bob_list[0].1, "shared tunnel is not owned by the grantee");

        // Owner: authorized + flagged owned.
        let alice_list = store.list_authorized_for_subject("alice").unwrap();
        assert_eq!(alice_list.len(), 1);
        assert!(alice_list[0].1, "owner flagged as owner");

        // A non-grantee: neither authorized nor able to see it.
        assert_eq!(store.routing_token_if_authorized("carol", &t.id).unwrap(), None);
        assert!(store.list_authorized_for_subject("carol").unwrap().is_empty());
    }

    /// #578: all four expressions of "owner or grantee" answer the same question.
    ///
    /// The rule lived as three byte-identical `SELECT 1 FROM tunnel_grants` copies plus a
    /// set-shaped fourth in `list_authorized_for_subject`. Three are now one helper; the
    /// fourth cannot be, because it filters a list. That leaves a real divergence risk, and
    /// it points the wrong way: `is_authorized` carries the doc comment calling it *the*
    /// authorization gate and has **no production caller at all** — the live gates are
    /// `routing_token_if_authorized` and `hostname_if_authorized`. Someone tightening the
    /// rule would naturally edit the canonical-looking one and change nothing.
    ///
    /// So the matrix is asserted across all four at once, including after a revoke.
    #[test]
    fn every_tunnel_authorization_path_agrees_578() {
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        let t = store
            // A hostname is REQUIRED for this fixture: `hostname_if_authorized` returns
            // `None` both for "not authorized" and for "authorized but no hostname
            // assigned". Without one, that path would report `false` for the owner too and
            // the matrix would compare two different questions.
            .create("alice", "web", Some("share-578.example.org"))
            .unwrap()
            .created()
            .expect("hostname is free in this test");
        store.grant("alice", &t.id, "bob").unwrap();

        // (subject, expected) — carol never appears in any grant.
        let check = |store: &SqliteTunnelStore, subject: &str, expected: bool| {
            assert_eq!(
                store.is_authorized(subject, &t.id).unwrap(),
                expected,
                "is_authorized({subject})"
            );
            assert_eq!(
                store.routing_token_if_authorized(subject, &t.id).unwrap().is_some(),
                expected,
                "routing_token_if_authorized({subject}) -- a LIVE gate"
            );
            assert_eq!(
                store.hostname_if_authorized(subject, &t.id).unwrap().is_some(),
                expected,
                "hostname_if_authorized({subject}) -- the other LIVE gate; this tunnel has a \
                 hostname, so `None` here can only mean 'not authorized'"
            );
            assert_eq!(
                store
                    .list_authorized_for_subject(subject)
                    .unwrap()
                    .iter()
                    .any(|(st, _)| st.id == t.id),
                expected,
                "list_authorized_for_subject({subject}) -- the set-shaped fourth copy"
            );
        };

        check(&store, "alice", true); // owner
        check(&store, "bob", true); // grantee
        check(&store, "carol", false); // stranger

        store.revoke_grant("alice", &t.id, "bob").unwrap();
        check(&store, "bob", false); // revoked -- every path must forget together
        check(&store, "alice", true); // and the owner is untouched by a revoke
    }

    #[test]
    fn tunnel_grants_are_owner_managed_and_gate_authorization() {
        // #29 PP1: only the owner manages grants; is_authorized = owner or grantee.
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        let t = store.create("alice", "web", None).unwrap().created().expect("hostname is free in this test");

        // Owner is authorized; strangers are not.
        assert!(store.is_authorized("alice", &t.id).unwrap(), "owner authorized");
        assert!(!store.is_authorized("bob", &t.id).unwrap());
        assert!(!store.is_authorized("bob", "no-such-tunnel").unwrap());

        // Only the owner may grant — bob (a stranger) cannot.
        assert!(matches!(
            store.grant("bob", &t.id, "carol"),
            Err(GrantError::NotOwner)
        ));
        assert!(matches!(
            store.list_grants("bob", &t.id),
            Err(GrantError::NotOwner),
        ), "non-owner cannot even enumerate grants");
        // The third sibling: `revoke_grant` had the same `owner_of` prologue as the two
        // above and no test asserting it. The three prologues are near-identical, which is
        // exactly the shape that invites being factored out -- and if this one lost its
        // check, the whole suite would still have gone green while any logged-in subject
        // could strip another owner's grantee of access to a shared tunnel. The property is
        // cheap to state and was the only one of the trio left standing on prose alone.
        store.grant("alice", &t.id, "dave").unwrap();
        assert!(matches!(
            store.revoke_grant("bob", &t.id, "dave"),
            Err(GrantError::NotOwner),
        ), "a non-owner must not be able to revoke someone else's grantee");
        assert!(
            store.is_authorized("dave", &t.id).unwrap(),
            "and the refused revoke must not have taken effect anyway"
        );
        assert!(store.revoke_grant("alice", &t.id, "dave").unwrap(), "the owner still can");

        // Owner grants bob -> bob becomes authorized; carol still is not.
        store.grant("alice", &t.id, "bob").unwrap();
        store.grant("alice", &t.id, "bob").unwrap(); // idempotent
        assert!(store.is_authorized("bob", &t.id).unwrap());
        assert!(!store.is_authorized("carol", &t.id).unwrap());
        assert_eq!(store.list_grants("alice", &t.id).unwrap(), vec!["bob".to_string()]);

        // Owner revokes bob's grant -> no longer authorized.
        assert!(store.revoke_grant("alice", &t.id, "bob").unwrap());
        assert!(!store.is_authorized("bob", &t.id).unwrap());
        assert!(!store.revoke_grant("alice", &t.id, "bob").unwrap(), "second revoke is a no-op");

        // Revoking the tunnel clears its grants (no orphans).
        store.grant("alice", &t.id, "bob").unwrap();
        assert!(store.revoke("alice", &t.id, 1_000).unwrap().is_some());
        assert!(!store.is_authorized("bob", &t.id).unwrap(), "grant gone with the tunnel");
        assert!(!store.is_authorized("alice", &t.id).unwrap(), "owner gone with the tunnel");
    }

    #[test]
    fn issue_then_redeem_binds_public_key() {
        let store = SqliteEnrollment::open_in_memory().unwrap();
        let token = store.issue_join_token(&tenant(), 1_000).unwrap();
        let agent = AgentId("agent-1".into());
        let pubkey = [7u8; 32];

        let bound = store.redeem(&token, &agent, pubkey, 1_000).unwrap();
        assert_eq!(bound, tenant());
        assert_eq!(store.binding(&agent).unwrap(), Some((tenant(), pubkey)));
    }

    #[test]
    fn join_token_is_single_use() {
        let store = SqliteEnrollment::open_in_memory().unwrap();
        let token = store.issue_join_token(&tenant(), 1_000).unwrap();
        store.redeem(&token, &AgentId("a1".into()), [1u8; 32], 1_000).unwrap();
        let second = store.redeem(&token, &AgentId("a2".into()), [2u8; 32], 1_000);
        assert!(
            matches!(second, Err(RedeemError::Enroll(EnrollError::TokenAlreadyUsed))),
            "second redemption rejected"
        );
    }

    /// #663: a leaked-but-unredeemed join token must stop being exploitable
    /// once it's past its TTL, not stay valid forever. Minted at `now = 1_000`
    /// with the default `JOIN_TOKEN_TTL_SECS` (7 days) means `expires_at =
    /// 1_000 + 604_800`; redeeming one second past that must be refused.
    #[test]
    fn redeem_refuses_a_join_token_past_its_expiry() {
        let store = SqliteEnrollment::open_in_memory().unwrap();
        let token = store.issue_join_token(&tenant(), 1_000).unwrap();
        let past_expiry = 1_000 + JOIN_TOKEN_TTL_SECS + 1;
        let result = store.redeem(&token, &AgentId("a".into()), [1u8; 32], past_expiry);
        assert!(
            matches!(result, Err(RedeemError::Enroll(EnrollError::Expired))),
            "an expired join token must be refused: {result:?}"
        );
        assert!(
            store.binding(&AgentId("a".into())).unwrap().is_none(),
            "an expired redemption must not bind the agent"
        );
    }

    /// The flip side of the expiry check: still comfortably inside the TTL
    /// window, redemption proceeds exactly as before this fix.
    #[test]
    fn redeem_succeeds_for_a_join_token_still_within_its_ttl() {
        let store = SqliteEnrollment::open_in_memory().unwrap();
        let token = store.issue_join_token(&tenant(), 1_000).unwrap();
        let still_valid = 1_000 + JOIN_TOKEN_TTL_SECS - 1;
        let bound = store.redeem(&token, &AgentId("a".into()), [1u8; 32], still_valid).unwrap();
        assert_eq!(bound, tenant());
    }

    /// #663: an expired token is CONSUMED, not left redeemable on retry --
    /// mirrors `SqliteBootstrap::redeem`'s "consume regardless of freshness"
    /// behavior. Without this, an attacker holding an expired-but-unconsumed
    /// token could keep retrying until an operator's clock/TTL assumption
    /// somehow worked in their favor; with it, one redemption attempt (expired
    /// or not) permanently burns the token.
    #[test]
    fn an_expired_join_token_is_consumed_not_left_retryable() {
        let store = SqliteEnrollment::open_in_memory().unwrap();
        let token = store.issue_join_token(&tenant(), 1_000).unwrap();
        let past_expiry = 1_000 + JOIN_TOKEN_TTL_SECS + 1;
        assert!(matches!(
            store.redeem(&token, &AgentId("a".into()), [1u8; 32], past_expiry),
            Err(RedeemError::Enroll(EnrollError::Expired))
        ));
        // A second attempt, even well within what would have been the TTL from
        // this exact `now`, sees the token already consumed -- not "expired"
        // again, "already used".
        assert!(matches!(
            store.redeem(&token, &AgentId("b".into()), [2u8; 32], past_expiry),
            Err(RedeemError::Enroll(EnrollError::TokenAlreadyUsed))
        ));
    }

    /// #663: a pre-migration row (`expires_at = 0`, the `ensure_column`
    /// default) must be grandfathered -- never treated as expired, regardless
    /// of how far `now` has moved on. Simulated directly via the raw table
    /// (an `INSERT` with no `expires_at` column, hitting the schema default)
    /// since every real `issue_join_token*` call always writes a real,
    /// positive value from here on.
    #[test]
    fn a_pre_migration_join_token_with_no_expiry_never_expires() {
        let store = SqliteEnrollment::open_in_memory().unwrap();
        {
            let conn = store.conn.lock_safe();
            conn.execute(
                "INSERT INTO join_tokens (token, tenant, redeemed) VALUES (?1, ?2, 0)",
                params![&[9u8; 32][..], tenant().0],
            )
            .unwrap();
        }
        let far_future = 1_000 + JOIN_TOKEN_TTL_SECS * 100;
        let bound = store
            .redeem(&JoinToken([9u8; 32]), &AgentId("legacy".into()), [1u8; 32], far_future)
            .unwrap();
        assert_eq!(bound, tenant(), "a legacy expires_at=0 row is never expired");
    }

    /// #663: `prune_redeemed_join_tokens` now also removes unredeemed rows
    /// past their expiry, not just already-redeemed ones (#292's original
    /// scope) -- an expired-but-never-redeemed token is exactly the "leaked,
    /// unbounded lifetime" case this whole column exists to close, so
    /// housekeeping should be able to clear it out too.
    #[test]
    fn prune_redeemed_join_tokens_also_removes_unredeemed_expired_rows_663() {
        let store = SqliteEnrollment::open_in_memory().unwrap();
        let expired = store.issue_join_token(&tenant(), 1_000).unwrap();
        // Minted much later, so its own `expires_at` lands well after the
        // `past_expiry` moment used below to prune -- the two tokens must
        // land on opposite sides of that line, not share the same expiry.
        let live = store.issue_join_token(&tenant(), 600_000).unwrap();
        let past_expiry = 1_000 + JOIN_TOKEN_TTL_SECS + 1;
        assert_eq!(
            store.prune_redeemed_join_tokens(past_expiry).unwrap(),
            1,
            "exactly the expired, still-unredeemed row is pruned"
        );
        assert!(
            matches!(
                store.redeem(&expired, &AgentId("a".into()), [1u8; 32], past_expiry),
                Err(RedeemError::Enroll(EnrollError::UnknownToken))
            ),
            "the pruned row is gone entirely, not just marked expired"
        );
        assert!(
            store.redeem(&live, &AgentId("b".into()), [2u8; 32], 1_000).is_ok(),
            "an unexpired token survives the same prune call"
        );
    }

    #[test]
    fn issue_join_tokens_mints_distinct_independently_redeemable_tokens() {
        // #145 bulk provisioning (frozen): a batch mint yields N DISTINCT tokens, each redeemable
        // exactly once and independent of the others — "provision N agents" in one call.
        let store = SqliteEnrollment::open_in_memory().unwrap();
        let tokens = store.issue_join_tokens(&tenant(), 5, 1_000).unwrap();
        assert_eq!(tokens.len(), 5, "five tokens minted");

        // All distinct.
        let mut seen = std::collections::HashSet::new();
        for t in &tokens {
            assert!(seen.insert(t.0), "each batch token is distinct");
        }

        // Each is a real, independently single-use token: redeem #0, its replay fails, #1 still works.
        assert!(store.redeem(&tokens[0], &AgentId("a0".into()), [10u8; 32], 1_000).is_ok(), "first token redeems");
        assert!(
            matches!(
                store.redeem(&tokens[0], &AgentId("a0b".into()), [11u8; 32], 1_000),
                Err(RedeemError::Enroll(EnrollError::TokenAlreadyUsed))
            ),
            "a batch token is single-use like any other"
        );
        assert!(
            store.redeem(&tokens[1], &AgentId("a1".into()), [12u8; 32], 1_000).is_ok(),
            "a different batch token is unaffected — independent tokens"
        );

        // count = 0 yields no tokens (caller/REST layer decides whether that's an error).
        assert!(store.issue_join_tokens(&tenant(), 0, 1_000).unwrap().is_empty(), "zero count mints nothing");
    }

    #[test]
    fn issue_join_tokens_idempotent_replays_the_same_set_without_reminting() {
        // #145 (Marq): a retried batch mint with the same idempotency key returns the SAME tokens and
        // does NOT mint new ones — so a network blip can't create duplicate identities.
        let store = SqliteEnrollment::open_in_memory().unwrap();

        let first = store.issue_join_tokens_idempotent(&tenant(), 3, "req-abc", 1_000).unwrap();
        assert_eq!(first.len(), 3);

        // Replay with the same key → the exact same tokens, no new mint.
        let replay = store.issue_join_tokens_idempotent(&tenant(), 3, "req-abc", 1_000).unwrap();
        assert_eq!(replay, first, "same idempotency key returns the same token set");

        // A DIFFERENT key mints a fresh, distinct set.
        let other = store.issue_join_tokens_idempotent(&tenant(), 3, "req-xyz", 1_000).unwrap();
        assert!(other.iter().all(|t| !first.contains(t)), "a different key mints distinct tokens");

        // The idempotently-minted tokens are real, single-use join tokens.
        assert!(store.redeem(&first[0], &AgentId("a".into()), [1u8; 32], 1_000).is_ok(), "an idempotent token redeems");
        // Replaying the key again AFTER one was redeemed still returns the same set (idempotency is
        // about issuance, not redemption state).
        let replay2 = store.issue_join_tokens_idempotent(&tenant(), 3, "req-abc", 1_000).unwrap();
        assert_eq!(replay2, first, "replay is stable regardless of downstream redemption");
    }

    #[test]
    fn issue_join_tokens_idempotent_rejects_key_reuse_with_mismatched_params() {
        // #145 idem-conflict: an idempotency key names ONE operation. Reusing it with a different
        // `count` or `tenant` must fail loudly (Conflict) instead of silently returning the original
        // set — otherwise a client key-reuse bug could hand tenant-A's tokens to a tenant-B retry.
        let store = SqliteEnrollment::open_in_memory().unwrap();
        let first = store.issue_join_tokens_idempotent(&tenant(), 3, "req-1", 1_000).unwrap();
        assert_eq!(first.len(), 3);

        // Same key, DIFFERENT count → Conflict, and nothing is re-minted.
        let mismatch_count = store.issue_join_tokens_idempotent(&tenant(), 5, "req-1", 1_000);
        assert!(
            matches!(mismatch_count, Err(IssueBatchError::Conflict)),
            "reusing a key with a different count is a Conflict"
        );

        // Same key, DIFFERENT tenant → Conflict (won't leak tenant()'s tokens to another tenant).
        let mismatch_tenant =
            store.issue_join_tokens_idempotent(&TenantId("other-tenant".into()), 3, "req-1", 1_000);
        assert!(
            matches!(mismatch_tenant, Err(IssueBatchError::Conflict)),
            "reusing a key with a different tenant is a Conflict"
        );

        // The original operation still replays cleanly — a rejected mismatch changed nothing.
        let replay = store.issue_join_tokens_idempotent(&tenant(), 3, "req-1", 1_000).unwrap();
        assert_eq!(replay, first, "the matching retry still returns the original set after conflicts");
    }

    #[test]
    fn prune_redeemed_join_tokens_removes_only_redeemed_rows_292() {
        let store = SqliteEnrollment::open_in_memory().unwrap();
        let live = store.issue_join_token(&tenant(), 1_000).unwrap();
        let redeemed = store.issue_join_token(&tenant(), 1_000).unwrap();
        store.redeem(&redeemed, &AgentId("a".into()), [1u8; 32], 1_000).unwrap();

        assert_eq!(store.prune_redeemed_join_tokens(1_000).unwrap(), 1, "exactly the redeemed row is pruned");
        // A second prune immediately after finds nothing new to remove.
        assert_eq!(store.prune_redeemed_join_tokens(1_000).unwrap(), 0);
        // Pruning the redeemed row never touched the live, unredeemed one.
        assert!(store.redeem(&live, &AgentId("b".into()), [2u8; 32], 1_000).is_ok(), "the live token still redeems");
    }

    #[test]
    fn prune_batch_issuance_ages_out_old_records_but_spares_recent_and_legacy_292() {
        let store = SqliteEnrollment::open_in_memory().unwrap();
        // An "old" record (created_at = 1_000) and a "recent" one (created_at = 9_000).
        store.issue_join_tokens_idempotent(&tenant(), 1, "old-key", 1_000).unwrap();
        store.issue_join_tokens_idempotent(&tenant(), 1, "recent-key", 9_000).unwrap();

        // now=10_000, max_age=5_000 -> cutoff=5_000: "old-key" (1_000) ages out, "recent-key" (9_000) doesn't.
        assert_eq!(store.prune_batch_issuance(10_000, 5_000).unwrap(), 1);
        // The pruned key's *next* use mints fresh (no longer replays the original set) --
        // proven indirectly: re-issuing under the same key with a mismatched count would
        // otherwise Conflict against the old record, but here it succeeds as a fresh mint.
        let after_prune = store.issue_join_tokens_idempotent(&tenant(), 2, "old-key", 10_000);
        assert!(after_prune.is_ok(), "a pruned idempotency key is gone, so reuse mints fresh instead of conflicting");

        // A legacy row (created_at defaults to 0 pre-migration) is never matched, however old.
        store
            .conn
            .lock_safe()
            .execute(
                "INSERT INTO batch_issuance (idem_key, tenant, tokens, created_at) VALUES ('legacy', 'x', X'00', 0)",
                [],
            )
            .unwrap();
        assert_eq!(store.prune_batch_issuance(u64::MAX, 0).unwrap(), 0, "created_at=0 legacy rows are never pruned");
    }

    #[test]
    fn unknown_token_is_rejected() {
        let store = SqliteEnrollment::open_in_memory().unwrap();
        let result = store.redeem(&JoinToken([0u8; 32]), &AgentId("a1".into()), [3u8; 32], 1_000);
        assert!(matches!(
            result,
            Err(RedeemError::Enroll(EnrollError::UnknownToken))
        ));
    }

    #[test]
    fn redeem_with_proof_requires_possession_of_the_bound_key() {
        // #88 SEC88c: a redemption must prove it holds the private key for the
        // public key it binds. A valid signature over the join token binds; a
        // proof made with a different key (i.e. binding a key the caller doesn't
        // control) is rejected with BadProof and does NOT consume the token.
        use ed25519_dalek::{Signer, SigningKey};

        let store = SqliteEnrollment::open_in_memory().unwrap();
        let token = store.issue_join_token(&tenant(), 1_000).unwrap();
        let agent = AgentId("agent-1".into());

        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pubkey = sk.verifying_key().to_bytes();
        let wrong = SigningKey::from_bytes(&[43u8; 32]);

        // Proof signed by the wrong key -> BadProof, token untouched.
        let forged = wrong.sign(&token.0).to_bytes();
        assert!(
            matches!(
                store.redeem_with_proof(&token, &agent, pubkey, &forged, 1_000),
                Err(RedeemError::Enroll(EnrollError::BadProof))
            ),
            "a proof that doesn't match the bound key is rejected"
        );
        assert!(store.binding(&agent).unwrap().is_none(), "nothing bound on a bad proof");

        // Genuine proof by the bound key -> binds, and the token is now single-use.
        let proof = sk.sign(&token.0).to_bytes();
        assert_eq!(store.redeem_with_proof(&token, &agent, pubkey, &proof, 1_000).unwrap(), tenant());
        assert_eq!(store.binding(&agent).unwrap(), Some((tenant(), pubkey)));
        assert!(
            matches!(
                store.redeem_with_proof(&token, &agent, pubkey, &proof, 1_000),
                Err(RedeemError::Enroll(EnrollError::TokenAlreadyUsed))
            ),
            "the token is consumed after a successful proven redemption"
        );
    }

    /// The production requirement: state survives a restart. Issue + redeem
    /// against a file-backed store, drop it (simulating a shutdown), reopen the
    /// same file, and confirm the binding persisted and the token stays consumed.
    #[test]
    fn state_survives_reopen() {
        let path = temp_db_path();
        let agent = AgentId("agent-persist".into());
        let token;
        {
            let store = SqliteEnrollment::open(&path).unwrap();
            token = store.issue_join_token(&tenant(), 1_000).unwrap();
            store.redeem(&token, &agent, [9u8; 32], 1_000).unwrap();
        } // store dropped -> connection closed

        let reopened = SqliteEnrollment::open(&path).unwrap();
        assert_eq!(
            reopened.binding(&agent).unwrap(),
            Some((tenant(), [9u8; 32])),
            "binding persisted across reopen"
        );
        let replay = reopened.redeem(&token, &AgentId("other".into()), [1u8; 32], 1_000);
        assert!(
            matches!(replay, Err(RedeemError::Enroll(EnrollError::TokenAlreadyUsed))),
            "token stays consumed across reopen"
        );

        let _ = std::fs::remove_file(&path);
    }

    fn info() -> TunnelInfo {
        TunnelInfo {
            tenant: TenantId("t".into()),
            agent: AgentId("a".into()),
        }
    }

    #[test]
    fn register_then_lookup() {
        let reg = SqliteRegistry::open_in_memory().unwrap();
        let token = RoutingToken([0x5a; 32]);
        reg.register(&token, &info()).unwrap();
        assert_eq!(reg.lookup(&token).unwrap(), Some(info()));
        assert_eq!(reg.lookup(&RoutingToken([0x11; 32])).unwrap(), None, "unknown token");
    }

    #[test]
    fn unregister_removes_and_reregister_overwrites() {
        let reg = SqliteRegistry::open_in_memory().unwrap();
        let token = RoutingToken([0x5a; 32]);
        reg.register(&token, &info()).unwrap();
        reg.unregister(&token).unwrap();
        assert_eq!(reg.lookup(&token).unwrap(), None);
        reg.unregister(&token).unwrap(); // idempotent

        reg.register(&token, &info()).unwrap();
        let other = TunnelInfo {
            tenant: TenantId("t2".into()),
            agent: AgentId("a2".into()),
        };
        reg.register(&token, &other).unwrap();
        assert_eq!(reg.lookup(&token).unwrap(), Some(other), "re-register overwrites");
    }

    #[test]
    fn registry_state_survives_reopen() {
        let path = temp_db_path();
        let token = RoutingToken([0x7c; 32]);
        {
            let reg = SqliteRegistry::open(&path).unwrap();
            reg.register(&token, &info()).unwrap();
        }
        let reopened = SqliteRegistry::open(&path).unwrap();
        assert_eq!(
            reopened.lookup(&token).unwrap(),
            Some(info()),
            "registration persisted across reopen"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ledger_open_credit_debit() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let acct = ledger.open_account().unwrap();
        assert_eq!(ledger.balance(&acct).unwrap(), 0, "new account starts empty");
        assert_eq!(ledger.credit(&acct, 100).unwrap(), 100);
        assert_eq!(ledger.credit(&acct, 50).unwrap(), 150, "top-ups accumulate");
        assert_eq!(ledger.debit(&acct, 30).unwrap(), 120);
        assert_eq!(ledger.balance(&acct).unwrap(), 120);
    }

    #[test]
    fn debit_beyond_balance_is_refused_without_mutation() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let acct = ledger.open_account().unwrap();
        ledger.credit(&acct, 10).unwrap();
        let refused = ledger.debit(&acct, 25);
        assert!(matches!(
            refused,
            Err(LedgerOpError::Ledger(LedgerError::InsufficientCredit { balance: 10, requested: 25 }))
        ));
        assert_eq!(ledger.balance(&acct).unwrap(), 10, "balance intact");
    }

    /// ADR-0025 (admin console): fail-first proof that `debit` — the credit-gated
    /// token-issuance admission path (`billing.rs`'s own doc: "the economic gate on
    /// tunnel creation") — actually refuses a blocked account, and does so BEFORE
    /// the balance check (a funded-but-blocked account gets `AccountBlocked`, not a
    /// misleading `InsufficientCredit`), with no mutation on refusal.
    #[test]
    fn debit_refuses_a_blocked_account_regardless_of_balance() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let acct = ledger.open_account().unwrap();
        ledger.credit(&acct, 100).unwrap();
        ledger.set_blocked(&acct, true).unwrap();
        assert!(
            matches!(ledger.debit(&acct, 1), Err(LedgerOpError::Ledger(LedgerError::AccountBlocked))),
            "a blocked account's debit must be refused even though it can afford it"
        );
        assert_eq!(ledger.balance(&acct).unwrap(), 100, "the refused debit left the balance intact");
    }

    /// Same admission gate, the idempotency-key-carrying sibling call site
    /// (`debit_and_record_issuance`, used by every issuance call that supplies a
    /// retry key).
    #[test]
    fn debit_and_record_issuance_refuses_a_blocked_account() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let acct = ledger.open_account().unwrap();
        ledger.credit(&acct, 100).unwrap();
        ledger.set_blocked(&acct, true).unwrap();
        let err = ledger.debit_and_record_issuance(&acct, 1, &[0x22u8; 32], &[0x33u8; 32], 1_000);
        assert!(matches!(err, Err(LedgerOpError::Ledger(LedgerError::AccountBlocked))));
        assert_eq!(ledger.issuance_for_key(&acct, &[0x22u8; 32]).unwrap(), None, "no issuance was recorded");
    }

    #[test]
    fn unblocking_an_account_restores_its_debit_capability() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let acct = ledger.open_account().unwrap();
        ledger.credit(&acct, 10).unwrap();
        ledger.set_blocked(&acct, true).unwrap();
        assert!(ledger.debit(&acct, 1).is_err(), "blocked: refused");
        ledger.set_blocked(&acct, false).unwrap();
        assert_eq!(ledger.debit(&acct, 1).unwrap(), 9, "unblocked: same ledger, now succeeds");
    }

    #[test]
    fn is_blocked_defaults_false_for_a_never_blocked_account() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let acct = ledger.open_account().unwrap();
        assert!(!ledger.is_blocked(&acct).unwrap());
    }

    /// ADR-0025 admin console: `GET /admin-ui/accounts`'s data source must
    /// actually reflect every OTHER admin action's real effect (credit,
    /// block, max-tunnels), not a stale/derived snapshot -- proven by mutating
    /// via the same real methods those admin routes call, then reading back
    /// through `list_accounts` alone.
    #[test]
    fn list_accounts_reports_every_subjects_real_balance_block_and_quota_state() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let alice = ledger.account_for_subject("kc-alice").unwrap();
        let bob = ledger.account_for_subject("kc-bob").unwrap();
        ledger.credit(&alice, 500).unwrap();
        ledger.set_max_tunnels(&alice, 5).unwrap();
        ledger.set_blocked(&bob, true).unwrap();

        let rows = ledger.list_accounts().unwrap();
        assert_eq!(rows.len(), 2, "both subjects that have ever logged in appear");

        let alice_row = rows.iter().find(|r| r.subject == "kc-alice").expect("alice present");
        assert_eq!(alice_row.balance, 500);
        assert_eq!(alice_row.max_tunnels, 5);
        assert!(!alice_row.blocked);
        assert_eq!(alice_row.account_hex.len(), 64, "32-byte account id, hex-encoded");

        let bob_row = rows.iter().find(|r| r.subject == "kc-bob").expect("bob present");
        assert!(bob_row.blocked);
        assert_eq!(bob_row.balance, 0);
        assert_ne!(alice_row.account_hex, bob_row.account_hex, "distinct accounts, distinct ids");
    }

    #[test]
    fn list_accounts_is_empty_when_no_subject_has_ever_logged_in() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        assert!(ledger.list_accounts().unwrap().is_empty());
    }

    /// The ledger half of an admin-triggered account deletion
    /// (`portal_api::admin_ui_delete_account`): the account row and its subject
    /// mapping are both actually gone, not merely zeroed -- proven by
    /// `account_for_subject` minting a FRESH (different) account id afterward,
    /// which only happens when no `account_subjects` row remains.
    #[test]
    fn delete_account_for_subject_removes_the_row_so_a_later_login_gets_a_fresh_account() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let original = ledger.account_for_subject("kc-gone").unwrap();
        ledger.credit(&original, 42).unwrap();

        ledger.delete_account_for_subject("kc-gone").unwrap();

        let recreated = ledger.account_for_subject("kc-gone").unwrap();
        assert_ne!(recreated.0, original.0, "a fresh account id was minted -- the old row is really gone");
        assert_eq!(ledger.balance(&recreated).unwrap(), 0, "the fresh account starts at zero, not the old balance");
    }

    #[test]
    fn delete_account_for_subject_is_a_no_op_for_a_subject_with_no_account() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        assert!(ledger.delete_account_for_subject("kc-never-logged-in").is_ok());
    }

    #[test]
    fn debit_and_record_issuance_is_replayed_from_the_idempotency_key_without_a_second_debit_272() {
        // #272: a caller retrying after a lost response (the debit committed, but the
        // token never reached them) must get back the SAME token, not be charged again.
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let acct = ledger.open_account().unwrap();
        ledger.credit(&acct, 10).unwrap();
        let key = [0x11u8; 32];
        let token = [0xAAu8; 32];

        assert_eq!(ledger.issuance_for_key(&acct, &key).unwrap(), None, "nothing recorded yet");
        let bal = ledger.debit_and_record_issuance(&acct, 3, &key, &token, 1_000).unwrap();
        assert_eq!(bal, 7, "debited once");
        assert_eq!(ledger.balance(&acct).unwrap(), 7);

        // The "retry": same key looked up first, exactly what the HTTP handler does.
        assert_eq!(ledger.issuance_for_key(&acct, &key).unwrap(), Some(token), "the same token comes back");
        assert_eq!(ledger.balance(&acct).unwrap(), 7, "looking it up never debits");

        // A genuinely NEW purchase (different key) still debits normally.
        let key2 = [0x22u8; 32];
        let token2 = [0xBBu8; 32];
        ledger.debit_and_record_issuance(&acct, 2, &key2, &token2, 1_001).unwrap();
        assert_eq!(ledger.balance(&acct).unwrap(), 5, "a different key debits again");
        assert_eq!(ledger.issuance_for_key(&acct, &key2).unwrap(), Some(token2));
    }

    #[test]
    fn issuance_for_key_is_scoped_per_account_and_a_cross_account_reuse_is_refused_440() {
        // #440: idempotency_key is free-form client input with no global-uniqueness
        // guarantee -- account B must never get back account A's token for a key
        // collision, and the insert path must refuse rather than silently letting
        // B's own (later) call land under a foreign key.
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let acct_a = ledger.open_account().unwrap();
        let acct_b = ledger.open_account().unwrap();
        ledger.credit(&acct_a, 10).unwrap();
        ledger.credit(&acct_b, 10).unwrap();
        let key = [0x99u8; 32];
        let token_a = [0xAAu8; 32];

        ledger.debit_and_record_issuance(&acct_a, 3, &key, &token_a, 1_000).unwrap();

        // B's lookup under the SAME key must find nothing -- not A's token.
        assert_eq!(
            ledger.issuance_for_key(&acct_b, &key).unwrap(),
            None,
            "B must never see A's issuance for a colliding key"
        );
        assert_eq!(ledger.balance(&acct_b).unwrap(), 10, "B untouched by A's issuance");

        // B then tries to record its own issuance under the same (globally-unique) key
        // -- refused with a distinct error, not silently overwriting A's row or
        // debiting B for nothing.
        let token_b = [0xBBu8; 32];
        let result = ledger.debit_and_record_issuance(&acct_b, 4, &key, &token_b, 1_001);
        assert!(
            matches!(result, Err(LedgerOpError::Ledger(LedgerError::IdempotencyKeyReused))),
            "got {result:?}"
        );
        assert_eq!(ledger.balance(&acct_b).unwrap(), 10, "refused issuance must not debit B");

        // A's own original issuance is untouched throughout.
        assert_eq!(ledger.issuance_for_key(&acct_a, &key).unwrap(), Some(token_a));
        assert_eq!(ledger.balance(&acct_a).unwrap(), 7);
    }

    #[test]
    fn debit_and_record_issuance_leaves_no_issuance_row_on_insufficient_credit_272() {
        // The debit and the issuance record are one transaction -- a refused debit must
        // not leave a dangling issuance row a later retry could incorrectly match.
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let acct = ledger.open_account().unwrap();
        ledger.credit(&acct, 1).unwrap();
        let key = [0x33u8; 32];
        let token = [0xCCu8; 32];

        let refused = ledger.debit_and_record_issuance(&acct, 5, &key, &token, 2_000);
        assert!(matches!(
            refused,
            Err(LedgerOpError::Ledger(LedgerError::InsufficientCredit { balance: 1, requested: 5 }))
        ));
        assert_eq!(ledger.balance(&acct).unwrap(), 1, "balance untouched");
        assert_eq!(ledger.issuance_for_key(&acct, &key).unwrap(), None, "no issuance recorded for the refused debit");
    }

    #[test]
    fn unknown_account_errors() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let ghost = AccountId([9u8; 32]);
        assert!(matches!(
            ledger.balance(&ghost),
            Err(LedgerOpError::Ledger(LedgerError::UnknownAccount))
        ));
        assert!(matches!(
            ledger.debit(&ghost, 1),
            Err(LedgerOpError::Ledger(LedgerError::UnknownAccount))
        ));
    }

    #[test]
    fn payment_confirmation_is_idempotent() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let acct = ledger.open_account().unwrap();
        let payment = ledger.create_intent(&acct, 100).unwrap();

        assert_eq!(ledger.confirm_payment(&payment).unwrap(), 100);
        assert!(
            matches!(
                ledger.confirm_payment(&payment),
                Err(PaymentOpError::Payment(PaymentError::AlreadyConfirmed))
            ),
            "second confirmation rejected"
        );
        assert_eq!(ledger.balance(&acct).unwrap(), 100, "credited exactly once");
    }

    #[test]
    fn create_intent_rejects_credits_above_i64_max() {
        // #83: a credits value above i64::MAX would wrap negative in SQLite and, on
        // confirmation, corrupt the balance (e.g. 0 -> ~u64::MAX). Reject at creation.
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let acct = ledger.open_account().unwrap();

        assert!(
            ledger.create_intent(&acct, u64::MAX).is_err(),
            "an over-i64::MAX top-up is rejected, not stored as a negative credits row"
        );
        assert!(
            ledger.create_intent(&acct, (i64::MAX as u64) + 1).is_err(),
            "just above i64::MAX is rejected"
        );
        assert_eq!(ledger.balance(&acct).unwrap(), 0, "no intent created, balance untouched");

        // The boundary value i64::MAX is accepted and confirms to the exact amount —
        // no wrap, no corruption.
        let big = ledger.create_intent(&acct, i64::MAX as u64).unwrap();
        assert_eq!(
            ledger.confirm_payment(&big).unwrap(),
            i64::MAX as u64,
            "the maximum valid top-up credits the exact amount"
        );
        assert_eq!(ledger.balance(&acct).unwrap(), i64::MAX as u64);
    }

    #[test]
    fn credit_rejects_amount_above_i64_max_604() {
        // #604: `credit()` had no guard of its own -- only `create_intent` (the one
        // production entry point) had the #83 check. A direct `credit()` call with an
        // over-i64::MAX amount used to wrap NEGATIVE and silently DECREASE the balance
        // instead of erroring.
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let acct = ledger.open_account().unwrap();
        ledger.credit(&acct, 100).unwrap();

        assert!(
            matches!(
                ledger.credit(&acct, u64::MAX),
                Err(LedgerOpError::Ledger(LedgerError::CreditAmountTooLarge { amount: u64::MAX }))
            ),
            "an over-i64::MAX credit is rejected with the typed error, not silently wrapped"
        );
        assert_eq!(ledger.balance(&acct).unwrap(), 100, "the balance must be untouched, not decreased");

        assert!(ledger.credit(&acct, (i64::MAX as u64) + 1).is_err(), "just above i64::MAX is rejected");
        assert_eq!(ledger.balance(&acct).unwrap(), 100);

        // The boundary value i64::MAX is still accepted (matches create_intent's own
        // boundary, and doesn't overflow the saturating_add against a small existing balance).
        assert_eq!(ledger.credit(&acct, i64::MAX as u64).unwrap(), i64::MAX as u64);
    }

    /// Production requirement: billing state survives a restart. Open + credit +
    /// confirm against a file-backed ledger, drop it, reopen, and confirm the
    /// balance persisted and the payment stays confirmed (no double-credit).
    #[test]
    fn ledger_state_survives_reopen() {
        let path = temp_db_path();
        let acct;
        let payment;
        {
            let ledger = SqliteLedger::open(&path).unwrap();
            acct = ledger.open_account().unwrap();
            ledger.credit(&acct, 5).unwrap();
            payment = ledger.create_intent(&acct, 3).unwrap();
            ledger.confirm_payment(&payment).unwrap(); // balance -> 8
        }
        let reopened = SqliteLedger::open(&path).unwrap();
        assert_eq!(reopened.balance(&acct).unwrap(), 8, "balance persisted across reopen");
        assert!(
            matches!(
                reopened.confirm_payment(&payment),
                Err(PaymentOpError::Payment(PaymentError::AlreadyConfirmed))
            ),
            "payment stays confirmed across reopen (no double-credit)"
        );
        assert_eq!(reopened.balance(&acct).unwrap(), 8, "no double-credit after reopen");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn account_for_subject_is_idempotent() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let a1 = ledger.account_for_subject("keycloak-sub-1").unwrap();
        let a2 = ledger.account_for_subject("keycloak-sub-1").unwrap();
        assert_eq!(a1, a2, "same subject maps to the same account");
        let b = ledger.account_for_subject("keycloak-sub-2").unwrap();
        assert_ne!(a1, b, "distinct subjects get distinct accounts");
        // The bound account is a real, usable account.
        ledger.credit(&a1, 10).unwrap();
        assert_eq!(ledger.balance(&a1).unwrap(), 10);
    }

    #[test]
    fn max_tunnels_defaults_to_one_and_is_raised_per_account_only() {
        // #214 multi-tunnel entitlement: every account starts at the Standard
        // tier's default of 1 (unchanged behavior for everyone who never gets
        // raised); raising it targets ONLY the specified account -- a sibling
        // account's own limit is untouched.
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let a1 = ledger.account_for_subject("remote-maintainer").unwrap();
        let a2 = ledger.account_for_subject("someone-else").unwrap();
        assert_eq!(ledger.max_tunnels(&a1).unwrap(), 1, "default is 1, the Standard tier");
        assert_eq!(ledger.max_tunnels(&a2).unwrap(), 1);

        ledger.set_max_tunnels(&a1, 5).unwrap();
        assert_eq!(ledger.max_tunnels(&a1).unwrap(), 5, "raised for the specified account");
        assert_eq!(ledger.max_tunnels(&a2).unwrap(), 1, "a different account's limit is untouched");
    }

    #[test]
    fn max_channels_defaults_to_100_and_is_raised_per_account_only() {
        // #113-ui-limits: same shape as max_tunnels, but channels had NO cap at
        // all before this -- default 100 (not 1) since the Standard tier's own
        // channel entitlement is meant to be generous, unlike the single-tunnel
        // default.
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let a1 = ledger.account_for_subject("remote-maintainer").unwrap();
        let a2 = ledger.account_for_subject("someone-else").unwrap();
        assert_eq!(ledger.max_channels(&a1).unwrap(), 100, "default is 100, the Standard tier");
        assert_eq!(ledger.max_channels(&a2).unwrap(), 100);

        ledger.set_max_channels(&a1, 5).unwrap();
        assert_eq!(ledger.max_channels(&a1).unwrap(), 5, "raised (or lowered) for the specified account");
        assert_eq!(ledger.max_channels(&a2).unwrap(), 100, "a different account's limit is untouched");
    }

    #[test]
    fn subject_account_survives_reopen() {
        let path = temp_db_path();
        let acct;
        {
            let ledger = SqliteLedger::open(&path).unwrap();
            acct = ledger.account_for_subject("sub-persist").unwrap();
            ledger.credit(&acct, 7).unwrap();
        }
        let reopened = SqliteLedger::open(&path).unwrap();
        assert_eq!(
            reopened.account_for_subject("sub-persist").unwrap(),
            acct,
            "subject maps to the same account after reopen"
        );
        assert_eq!(reopened.balance(&acct).unwrap(), 7);
        let _ = std::fs::remove_file(&path);
    }

    // --- #72 AF2d: agent-held channel registry ---

    #[test]
    fn channel_register_lookup_and_owner_scoped_membership() {
        let s = SqliteChannelStore::open_in_memory().unwrap();
        let ch = ChannelId([0x11; 32]);
        let op = [0x22u8; 32];
        let member = [0x33u8; 32];

        // Alice registers a channel with its operator PUBLIC key; the edge lookup
        // resolves it, and the owner is recorded.
        assert!(s.register_channel(&ch, &op, "alice").unwrap());
        assert_eq!(s.operator_pubkey(&ch).unwrap(), Some(op));
        assert_eq!(s.channel_owner(&ch).unwrap(), Some("alice".to_string()));
        assert_eq!(s.operator_pubkey(&ChannelId([0x99; 32])).unwrap(), None);

        // Non-owner cannot re-key the channel or manage its members.
        assert!(!s.register_channel(&ch, &[0xAAu8; 32], "mallory").unwrap());
        assert_eq!(s.operator_pubkey(&ch).unwrap(), Some(op), "operator key unchanged");
        assert!(!s.add_member(&ch, "mallory", &member, &[0xd4u8; 32], &[0u8; 64]).unwrap());
        assert!(!s.is_member(&ch, &member).unwrap());

        // Owner adds a member (idempotent), then removes it (idempotent).
        assert!(s.add_member(&ch, "alice", &member, &[0xd4u8; 32], &[0u8; 64]).unwrap());
        assert!(s.add_member(&ch, "alice", &member, &[0xd4u8; 32], &[0u8; 64]).unwrap(), "add is idempotent");
        assert!(s.is_member(&ch, &member).unwrap());
        assert!(s.remove_member(&ch, "alice", &member).unwrap());
        assert!(s.remove_member(&ch, "alice", &member).unwrap(), "remove is idempotent");
        assert!(!s.is_member(&ch, &member).unwrap());

        // Owner may re-key their own channel (agent rotates its operator key).
        assert!(s.register_channel(&ch, &[0x44u8; 32], "alice").unwrap());
        assert_eq!(s.operator_pubkey(&ch).unwrap(), Some([0x44u8; 32]));
    }

    #[test]
    fn register_channel_if_under_owned_limit_enforces_the_cap_atomically_and_never_blocks_a_re_key() {
        // #113-ui-limits: channels had no cap at all before this. Three things this
        // must get right: (1) the Nth-plus-1 NEW channel is refused once `owner`
        // already owns `max`, (2) re-registering (re-keying) a channel the SAME
        // owner already owns is NEVER blocked by the limit -- only genuinely new
        // channels count against it, matching register_channel's own idempotent-
        // re-key behavior, (3) a different owner's count is untouched.
        let s = SqliteChannelStore::open_in_memory().unwrap();
        let op = [0x77u8; 32];

        // Fill alice up to a limit of 2.
        let ch1 = ChannelId([0x01; 32]);
        let ch2 = ChannelId([0x02; 32]);
        assert_eq!(
            s.register_channel_if_under_owned_limit(&ch1, &op, "alice", 2).unwrap(),
            RegisterChannelOutcome::Registered
        );
        assert_eq!(
            s.register_channel_if_under_owned_limit(&ch2, &op, "alice", 2).unwrap(),
            RegisterChannelOutcome::Registered
        );

        // A third NEW channel is refused -- alice already owns 2, the limit.
        let ch3 = ChannelId([0x03; 32]);
        assert_eq!(
            s.register_channel_if_under_owned_limit(&ch3, &op, "alice", 2).unwrap(),
            RegisterChannelOutcome::OverLimit
        );
        assert_eq!(s.operator_pubkey(&ch3).unwrap(), None, "refused, never created");

        // Re-registering (re-keying) an ALREADY-OWNED channel is never blocked by
        // the limit, even though alice is already at the cap.
        let new_op = [0x88u8; 32];
        assert_eq!(
            s.register_channel_if_under_owned_limit(&ch1, &new_op, "alice", 2).unwrap(),
            RegisterChannelOutcome::Registered,
            "re-keying an owned channel is not a NEW channel, so the limit doesn't apply"
        );
        assert_eq!(s.operator_pubkey(&ch1).unwrap(), Some(new_op));

        // Owned-by-another still refused the same way as plain register_channel,
        // regardless of the (irrelevant, since it's refused first) limit.
        assert_eq!(
            s.register_channel_if_under_owned_limit(&ch1, &op, "mallory", 100).unwrap(),
            RegisterChannelOutcome::OwnedByAnother
        );

        // A different owner's own count is untouched by alice's limit/usage.
        let ch4 = ChannelId([0x04; 32]);
        assert_eq!(
            s.register_channel_if_under_owned_limit(&ch4, &op, "carol", 1).unwrap(),
            RegisterChannelOutcome::Registered
        );
    }

    #[test]
    fn holder_visible_to_checks_owned_and_allowlisted_channels_not_just_any_membership_698() {
        // #698 finding 5: "flag an id that isn't a channel member visible to the caller" --
        // reuses the exact owned-OR-allowlisted "account related" relationship
        // topology_edge_channel already established, applied to a holder key instead of a
        // channel id. A holder being a member of SOME channel isn't enough on its own if
        // the caller has no relationship to that channel at all.
        let s = SqliteChannelStore::open_in_memory().unwrap();
        let owned = ChannelId([0xa1; 32]);
        let allowlisted = ChannelId([0xb2; 32]);
        let unrelated = ChannelId([0xc3; 32]);
        assert!(s.register_channel(&owned, &[0x11u8; 32], "alice").unwrap());
        assert!(s.register_channel(&allowlisted, &[0x22u8; 32], "carol").unwrap());
        assert!(s.register_channel(&unrelated, &[0x33u8; 32], "carol").unwrap());
        assert!(s.allowlist_add(&allowlisted, "carol", "alice@example.test", 1_000).unwrap());

        let on_owned = [0xd1u8; 32];
        let on_allowlisted = [0xd2u8; 32];
        let on_unrelated = [0xd3u8; 32];
        let nowhere = [0xd4u8; 32];
        assert!(s.add_member(&owned, "alice", &on_owned, &[0u8; 32], &[0u8; 64]).unwrap());
        assert!(s.add_member(&allowlisted, "carol", &on_allowlisted, &[0u8; 32], &[0u8; 64]).unwrap());
        assert!(s.add_member(&unrelated, "carol", &on_unrelated, &[0u8; 32], &[0u8; 64]).unwrap());

        // A member of a channel alice owns: visible.
        assert!(s.holder_visible_to("alice", Some("alice@example.test"), &on_owned).unwrap());
        // A member of a channel alice is only allow-listed (not owner) on: visible too.
        assert!(s.holder_visible_to("alice", Some("alice@example.test"), &on_allowlisted).unwrap());
        // A member of a channel alice has NO relationship to at all: not visible, even
        // though it's a perfectly real member of a perfectly real channel.
        assert!(!s.holder_visible_to("alice", Some("alice@example.test"), &on_unrelated).unwrap());
        // A holder that isn't a member of anything: not visible.
        assert!(!s.holder_visible_to("alice", Some("alice@example.test"), &nowhere).unwrap());
        // No verified e-mail (e.g. a bearer-token caller): only the owned-channel check
        // runs, allow-listed relationships are unreachable without it.
        assert!(s.holder_visible_to("alice", None, &on_owned).unwrap());
        assert!(!s.holder_visible_to("alice", None, &on_allowlisted).unwrap());
    }

    #[test]
    fn channels_owned_by_and_delete_channel_and_remove_allowlist_entries_for_email_drive_account_deletion() {
        let s = SqliteChannelStore::open_in_memory().unwrap();
        let mine = ChannelId([0x11; 32]);
        let other = ChannelId([0x22; 32]);
        let op = [0x22u8; 32];
        let holder = [0x33u8; 32];
        assert!(s.register_channel(&mine, &op, "alice").unwrap());
        assert!(s.register_channel(&other, &op, "bob").unwrap());
        s.add_member(&mine, "alice", &holder, &[0u8; 32], &[0u8; 64]).unwrap();
        s.allowlist_add(&mine, "alice", "carol@example.com", 100).unwrap();
        s.allowlist_add(&other, "bob", "alice@example.com", 100).unwrap();

        assert_eq!(s.channels_owned_by("alice").unwrap(), vec![mine]);

        assert!(!s.delete_channel("mallory", &mine).unwrap(), "non-owner delete -> no-op");
        assert!(s.delete_channel("alice", &mine).unwrap());
        assert_eq!(s.channel_owner(&mine).unwrap(), None, "channel gone");
        assert!(!s.is_member(&mine, &holder).unwrap(), "members gone with it");
        assert_eq!(s.allowlist_list(&mine, "alice").unwrap(), None, "channel unknown post-delete");

        // bob's channel is untouched by alice's deletion, but her e-mail is still
        // sitting on its allow-list until the email-scoped cleanup runs.
        assert!(s.allowlist_contains(&other, "alice@example.com").unwrap());
        let stripped = s.remove_allowlist_entries_for_email("alice@example.com").unwrap();
        assert_eq!(stripped, 1);
        assert!(!s.allowlist_contains(&other, "alice@example.com").unwrap());
        assert_eq!(s.channel_owner(&other).unwrap(), Some("bob".to_string()), "bob's channel itself is untouched");
    }

    /// #514: grant deposit is owner- and member-scoped, idempotent, and the member's
    /// SUBJECT (recorded at claim time) can re-fetch it any number of times -- the
    /// storage half of the persistent grant-delivery flow that replaces demo-side
    /// one-shot delivery (the sort#26 class).
    #[test]
    fn grant_deposit_is_scoped_and_refetchable_by_the_claiming_subject_514() {
        let s = SqliteChannelStore::open_in_memory().unwrap();
        let ch = ChannelId([0x77u8; 32]);
        let holder = [0xabu8; 32];
        assert!(s.register_channel(&ch, &[0x11u8; 32], "alice").unwrap());
        assert!(s.allowlist_add(&ch, "alice", "nat@example.com", 1_000).unwrap());

        // Deposit before membership: refused as NotAMember (a deposit-for-stranger
        // must not sit undetected); non-owner deposit: refused as NotOwner.
        assert_eq!(
            s.deposit_grant(&ch, "alice", &holder, "aa", 1_500).unwrap(),
            GrantDepositOutcome::NotAMember
        );
        assert!(s
            .claim_via_allowlist(&ch, "nat@example.com", &holder, &[0xcdu8; 32], &[0u8; 64], 2_000, Some("subj-nat"))
            .unwrap().claimed());
        assert_eq!(
            s.deposit_grant(&ch, "mallory", &holder, "aa", 2_100).unwrap(),
            GrantDepositOutcome::NotOwner
        );

        // Before any deposit the claimed identity is visible with grant: None -- the
        // "waiting for your grant" state.
        assert_eq!(s.deposited_grants_for_subject(&ch, "subj-nat").unwrap(), vec![(holder, None)]);

        assert_eq!(
            s.deposit_grant(&ch, "alice", &holder, "deadbeef01", 2_200).unwrap(),
            GrantDepositOutcome::Deposited
        );
        assert_eq!(
            s.deposited_grants_for_subject(&ch, "subj-nat").unwrap(),
            vec![(holder, Some("deadbeef01".to_string()))],
            "the claiming subject re-fetches the deposited grant"
        );
        // Re-deposit replaces (grant rotation), other subjects see nothing.
        assert_eq!(
            s.deposit_grant(&ch, "alice", &holder, "deadbeef02", 2_300).unwrap(),
            GrantDepositOutcome::Deposited
        );
        assert_eq!(
            s.deposited_grants_for_subject(&ch, "subj-nat").unwrap(),
            vec![(holder, Some("deadbeef02".to_string()))]
        );
        assert!(s.deposited_grants_for_subject(&ch, "subj-other").unwrap().is_empty());
    }

    /// Removing a member is a COMPLETE revocation: it pulls the membership row AND the
    /// holder's deposited grant AND its subject->holder claim link, so a revoked member
    /// can no longer re-fetch its grant. A sibling holder the SAME subject claimed on the
    /// SAME channel (the real two-identity case: an account that re-claimed with a fresh
    /// persistent browser identity) must survive untouched.
    /// #577: an allow-listed member cannot take over ANOTHER member's holder.
    ///
    /// The attack this refuses, reproduced end to end below: the allow-list authorizes an
    /// *email*, but the row written is keyed on `(channel, holder)` and `holder` arrives from
    /// the caller. The upstream attestation check stops a forged key, not a replayed one --
    /// and every member legitimately receives the other members' `(noise_pubkey,
    /// attestation)` from the edge's authorize response. So Mallory, who is on the same
    /// allow-list, could re-submit Alice's earlier attested key and `INSERT OR REPLACE`
    /// Alice's pinned key back to a value Alice had rotated away from; the same write also
    /// replaced the subject link, redirecting Alice's deposited grant to Mallory.
    ///
    /// Both halves are asserted, because closing only the key half would leave the grant
    /// redirect standing and the test would still look green.
    #[test]
    fn an_allow_listed_member_cannot_take_over_another_members_holder_577() {
        let s = SqliteChannelStore::open_in_memory().unwrap();
        let ch = ChannelId([0xa7u8; 32]);
        let alice = [0x01u8; 32];
        let old_key = [0xc0u8; 32]; // what Alice rotated away from -- assume it leaked
        let new_key = [0xc9u8; 32]; // Alice's current key
        assert!(s.register_channel(&ch, &[0x11u8; 32], "owner").unwrap());
        assert!(s.allowlist_add(&ch, "owner", "alice@example.com", 1_000).unwrap());
        assert!(s.allowlist_add(&ch, "owner", "mallory@example.com", 1_000).unwrap());

        assert!(s
            .claim_via_allowlist(&ch, "alice@example.com", &alice, &old_key, &[0u8; 64], 2_000, Some("subj-alice"))
            .unwrap()
            .claimed());
        assert!(
            s.claim_via_allowlist(&ch, "alice@example.com", &alice, &new_key, &[0u8; 64], 2_100, Some("subj-alice"))
                .unwrap()
                .claimed(),
            "Alice rotating her own key must keep working -- the guard binds the holder to a \
             subject, it does not freeze the key"
        );

        // Mallory is genuinely allow-listed, so this is NOT a membership refusal.
        assert_eq!(
            s.claim_via_allowlist(&ch, "mallory@example.com", &alice, &old_key, &[0u8; 64], 2_200, Some("subj-mallory"))
                .unwrap(),
            ClaimOutcome::HolderClaimedByAnother,
            "an allow-listed stranger must not be able to re-pin another member's key"
        );

        assert_eq!(
            s.member_noise_key(&ch, &alice).unwrap(),
            Some(new_key),
            "Alice's pinned key must still be the one she rotated TO -- a successful rollback \
             here is what would let a leaked static key complete handshakes as Alice"
        );
        assert!(
            s.deposited_grants_for_subject(&ch, "subj-mallory").unwrap().is_empty(),
            "and the subject link must not have moved: it is what scopes deposited-grant \
             pickup, so taking it over redirects the victim's own grant"
        );
    }

    #[test]
    fn remove_member_is_a_complete_revocation_and_spares_siblings() {
        let s = SqliteChannelStore::open_in_memory().unwrap();
        let ch = ChannelId([0xe2u8; 32]);
        let stale = [0x8au8; 32]; // the redacted first identity
        let good = [0xdeu8; 32]; // the persistent re-claim, same subject
        assert!(s.register_channel(&ch, &[0x11u8; 32], "owner").unwrap());
        assert!(s.allowlist_add(&ch, "owner", "tester@example.com", 1_000).unwrap());
        // One subject claims BOTH holders on this channel.
        assert!(s
            .claim_via_allowlist(&ch, "tester@example.com", &stale, &[0xc1u8; 32], &[0u8; 64], 2_000, Some("subj-t"))
            .unwrap().claimed());
        assert!(s
            .claim_via_allowlist(&ch, "tester@example.com", &good, &[0xc2u8; 32], &[0u8; 64], 2_100, Some("subj-t"))
            .unwrap().claimed());
        assert_eq!(s.deposit_grant(&ch, "owner", &stale, "aaaa", 2_200).unwrap(), GrantDepositOutcome::Deposited);
        assert_eq!(s.deposit_grant(&ch, "owner", &good, "bbbb", 2_300).unwrap(), GrantDepositOutcome::Deposited);
        // Both fetchable before revocation.
        let mut before = s.deposited_grants_for_subject(&ch, "subj-t").unwrap();
        before.sort();
        // sorted ascending by holder bytes: stale (0x8a) precedes good (0xde)
        assert_eq!(before, vec![(stale, Some("aaaa".to_string())), (good, Some("bbbb".to_string()))]);

        // Non-owner cannot revoke (and writes nothing).
        assert!(!s.remove_member(&ch, "mallory", &stale).unwrap());
        assert_eq!(s.deposited_grants_for_subject(&ch, "subj-t").unwrap().len(), 2, "a rejected revoke is a no-op");

        // Owner revokes the stale identity: membership, deposit, AND subject link all gone.
        assert!(s.remove_member(&ch, "owner", &stale).unwrap());
        assert!(!s.is_member(&ch, &stale).unwrap());
        // The revoked holder can no longer re-fetch its grant; the sibling survives whole.
        assert_eq!(
            s.deposited_grants_for_subject(&ch, "subj-t").unwrap(),
            vec![(good, Some("bbbb".to_string()))],
            "revoked holder's deposit + subject link are gone; the sibling identity is untouched"
        );
        assert!(s.is_member(&ch, &good).unwrap(), "the sibling holder is still a member");
    }

    #[test]
    fn allowlist_is_owner_scoped_case_insensitive_and_claim_adds_the_member_248() {
        let s = SqliteChannelStore::open_in_memory().unwrap();
        let ch = ChannelId([0x55; 32]);
        let op = [0x22u8; 32];
        let holder = [0x66u8; 32];
        let noise = [0x77u8; 32];
        let attest = [0x88u8; 64];
        assert!(s.register_channel(&ch, &op, "alice").unwrap());

        // Non-owner can't manage the allow-list.
        assert!(!s.allowlist_add(&ch, "mallory", "nat@example.com", 1_000).unwrap());
        assert_eq!(s.allowlist_list(&ch, "mallory").unwrap(), None, "mallory isn't the owner");

        // Owner adds an email (idempotent), case-insensitively stored/matched.
        assert!(s.allowlist_add(&ch, "alice", "Nat@Example.com", 1_000).unwrap());
        assert!(s.allowlist_add(&ch, "alice", "nat@example.com", 2_000).unwrap(), "re-add is idempotent");
        assert_eq!(s.allowlist_list(&ch, "alice").unwrap(), Some(vec!["nat@example.com".to_string()]));
        assert!(s.allowlist_contains(&ch, "NAT@EXAMPLE.COM").unwrap(), "lookup is case-insensitive too");
        assert!(!s.allowlist_contains(&ch, "someone-else@example.com").unwrap());

        // An email NOT on the allow-list can't claim.
        assert!(!s.claim_via_allowlist(&ch, "stranger@example.com", &holder, &noise, &attest, 3_000, None).unwrap().claimed());
        assert!(!s.is_member(&ch, &holder).unwrap());

        // The allow-listed email claims successfully (owner never involved in this call).
        assert!(s.claim_via_allowlist(&ch, "nat@example.com", &holder, &noise, &attest, 3_000, None).unwrap().claimed());
        assert!(s.is_member(&ch, &holder).unwrap());

        // Owner removes the email; a FUTURE claim by a new holder is refused, but the
        // already-claimed membership above is untouched (allow-list ≠ membership).
        assert!(!s.allowlist_remove(&ch, "mallory", "nat@example.com").unwrap(), "non-owner can't remove");
        assert!(s.allowlist_remove(&ch, "alice", "nat@example.com").unwrap());
        assert!(s.allowlist_remove(&ch, "alice", "nat@example.com").unwrap(), "remove is idempotent");
        assert_eq!(s.allowlist_list(&ch, "alice").unwrap(), Some(vec![]));
        assert!(s.is_member(&ch, &holder).unwrap(), "de-listing doesn't revoke an existing member");
        let another_holder = [0x99u8; 32];
        assert!(!s.claim_via_allowlist(&ch, "nat@example.com", &another_holder, &noise, &attest, 4_000, None).unwrap().claimed());

        // An unknown channel's allow-list is always empty -> claim always false.
        let unknown = ChannelId([0xAB; 32]);
        assert!(!s.claim_via_allowlist(&unknown, "nat@example.com", &holder, &noise, &attest, 4_000, None).unwrap().claimed());
    }

    #[test]
    fn channels_for_email_reports_claim_status_and_stays_self_scoped() {
        // Self-service discoverability (2026-08-01): the query behind the portal
        // account page's "Your Channels" section. An allow-listed-but-not-yet-
        // claimed entry shows claimed_at = None; a claim stamps it; a different
        // email (or channel) is never conflated with this one.
        let s = SqliteChannelStore::open_in_memory().unwrap();
        let ch_a = ChannelId([0x11; 32]);
        let ch_b = ChannelId([0x22; 32]);
        let op = [0x55u8; 32];
        let holder = [0x66u8; 32];
        let noise = [0x77u8; 32];
        let attest = [0x88u8; 64];
        assert!(s.register_channel(&ch_a, &op, "alice").unwrap());
        assert!(s.register_channel(&ch_b, &op, "alice").unwrap());

        // Nothing yet -> empty.
        assert_eq!(s.channels_for_email("nat@example.com").unwrap(), vec![]);

        // Allow-listed on both channels, claimed on neither yet.
        assert!(s.allowlist_add(&ch_a, "alice", "nat@example.com", 1_000).unwrap());
        assert!(s.allowlist_add(&ch_b, "alice", "Nat@Example.com", 1_100).unwrap());
        let listed = s.channels_for_email("NAT@EXAMPLE.COM").unwrap();
        assert_eq!(listed.len(), 2, "case-insensitive lookup, both channels");
        assert!(listed.iter().all(|(_, claimed_at)| claimed_at.is_none()));

        // Claim on ch_a only -> that one shows claimed_at, ch_b still pending.
        assert!(s.claim_via_allowlist(&ch_a, "nat@example.com", &holder, &noise, &attest, 5_000, None).unwrap().claimed());
        let listed = s.channels_for_email("nat@example.com").unwrap();
        let a_status = listed.iter().find(|(c, _)| *c == ch_a).unwrap().1;
        let b_status = listed.iter().find(|(c, _)| *c == ch_b).unwrap().1;
        assert_eq!(a_status, Some(5_000), "ch_a claim stamped");
        assert_eq!(b_status, None, "ch_b still pending");

        // A different email sees nothing -- self-scoped, no cross-user leakage.
        assert_eq!(s.channels_for_email("someone-else@example.com").unwrap(), vec![]);
    }

    #[test]
    fn channel_authorize_holder_yields_operator_key_only_for_members() {
        // #81 SEC81c: the broker's `authorize(channel, holder)` production source.
        // Returns the operator key iff the holder is a current member — folding the
        // gap-2 membership/revocation check into the key lookup so a stolen/forged
        // grant for a non-member (or a removed member) is refused at the edge gate.
        let s = SqliteChannelStore::open_in_memory().unwrap();
        let ch = ChannelId([0xC0; 32]);
        let op = [0xEEu8; 32];
        let member = [0x33u8; 32];
        let stranger = [0x44u8; 32];

        // Unknown channel -> None (even for any holder).
        assert_eq!(s.authorize_holder(&ch, &member).unwrap(), None);

        // Registered channel, but holder not yet a member -> None (no key leaked).
        assert!(s.register_channel(&ch, &op, "alice").unwrap());
        assert_eq!(s.authorize_holder(&ch, &member).unwrap(), None, "non-member gets no key");

        // Member -> the operator key; a different holder still gets None.
        assert!(s.add_member(&ch, "alice", &member, &[0xd4u8; 32], &[0u8; 64]).unwrap());
        assert_eq!(s.authorize_holder(&ch, &member).unwrap(), Some(op), "member resolves the key");
        assert_eq!(s.authorize_holder(&ch, &stranger).unwrap(), None);

        // Revocation: removing the member immediately denies the key at the gate.
        assert!(s.remove_member(&ch, "alice", &member).unwrap());
        assert_eq!(s.authorize_holder(&ch, &member).unwrap(), None, "revoked member refused");

        // Re-key tracks through: a re-added member resolves the NEW operator key.
        assert!(s.add_member(&ch, "alice", &member, &[0xd4u8; 32], &[0u8; 64]).unwrap());
        assert!(s.register_channel(&ch, &[0x55u8; 32], "alice").unwrap());
        assert_eq!(s.authorize_holder(&ch, &member).unwrap(), Some([0x55u8; 32]));
    }

    #[test]
    fn channel_pooled_authorize_holder_runs_concurrently_while_unpooled_serializes_398() {
        // #398: same proof shape as #344's cda587a test -- `authorize_holder` (the
        // production source for `/internal/channel/authorize`'s per-connection admission
        // gate, already wrapped in its own spawn_blocking after the #140/#231 lock-wait-
        // stall incident) now takes a connection from `readers` instead of `writer`, so N
        // concurrent slow lookups should overlap instead of queuing. File-backed `open()`
        // store (pooled) vs. in-memory (`readers: None`, falls back to `writer`) proves the
        // speedup is attributable to the pool.
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        const N: usize = 8;
        const SLEEP: Duration = Duration::from_millis(100);

        fn run_n_concurrent_slow_reads(store: &Arc<SqliteChannelStore>, n: usize) -> Duration {
            let started = Instant::now();
            let handles: Vec<_> = (0..n)
                .map(|_| {
                    let store = Arc::clone(store);
                    std::thread::spawn(move || {
                        let _conn = store.read();
                        std::thread::sleep(SLEEP);
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap();
            }
            started.elapsed()
        }

        let path = temp_db_path();
        let pooled = Arc::new(SqliteChannelStore::open(&path).unwrap());
        let pooled_elapsed = run_n_concurrent_slow_reads(&pooled, N);

        let unpooled = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let unpooled_elapsed = run_n_concurrent_slow_reads(&unpooled, N);

        assert!(
            pooled_elapsed < SLEEP * 3,
            "pooled reads should run concurrently (~1x SLEEP), not serialize: {pooled_elapsed:?} for \
             {N} reads of {SLEEP:?} each"
        );
        assert!(
            unpooled_elapsed >= SLEEP * (N as u32) / 2,
            "unpooled (in-memory) reads should still serialize through the writer mutex \
             (~{N}x SLEEP): got only {unpooled_elapsed:?} for {N} reads of {SLEEP:?} each"
        );

        drop(pooled);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    #[test]
    fn channel_concurrent_member_adds_and_authorize_reads_all_succeed_398() {
        // #398: real concurrent `authorize_holder` reads (the pool) mixed with a real
        // concurrent `add_member` write workload on one shared, already-registered channel
        // (distinct holder keys per writer thread, so no row clash), asserting neither
        // errors and every concurrently-added member is durably present at the end.
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        const WRITERS: usize = 4;
        const MEMBERS_PER_WRITER: usize = 25;
        const READERS: usize = 4;

        let path = temp_db_path();
        let store = Arc::new(SqliteChannelStore::open(&path).unwrap());
        let ch = ChannelId([0x9au8; 32]);
        let op = [0x1cu8; 32];
        store.register_channel(&ch, &op, "owner-0").unwrap();
        let stop = Arc::new(AtomicBool::new(false));

        let reader_handles: Vec<_> = (0..READERS)
            .map(|_| {
                let store = Arc::clone(&store);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let mut reads = 0u32;
                    let probe = [0x00u8; 32];
                    while !stop.load(Ordering::Relaxed) {
                        store
                            .authorize_holder(&ch, &probe)
                            .expect("a concurrent authorize_holder must not error while members are landing");
                        reads += 1;
                    }
                    reads
                })
            })
            .collect();

        let writer_handles: Vec<_> = (0..WRITERS)
            .map(|w| {
                let store = Arc::clone(&store);
                let ch = ch;
                std::thread::spawn(move || {
                    for i in 0..MEMBERS_PER_WRITER {
                        let mut holder = [0u8; 32];
                        holder[0] = w as u8;
                        holder[1..5].copy_from_slice(&(i as u32).to_be_bytes());
                        assert!(
                            store
                                .add_member(&ch, "owner-0", &holder, &[0xd4u8; 32], &[0u8; 64])
                                .expect("a concurrent add_member must succeed within the 5s busy_timeout"),
                            "the shared channel stays owned by owner-0 throughout"
                        );
                    }
                })
            })
            .collect();

        for h in writer_handles {
            h.join().unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        let total_reads: u32 = reader_handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert!(total_reads > 0, "readers actually ran concurrently with the writers, not sequentially after");

        assert_eq!(
            store.members_of(&ch, "owner-0").unwrap().unwrap().len(),
            WRITERS * MEMBERS_PER_WRITER,
            "every concurrent add_member() across every writer thread landed exactly once"
        );

        drop(store);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    #[test]
    fn channel_member_noise_key_round_trips_and_reflects_revocation() {
        // #72 AF4: the registry carries each member's X25519 Noise static key so a
        // peer can pin it for the direct-path handshake. It is set on add, updated on
        // re-add, and gone after revocation.
        let s = SqliteChannelStore::open_in_memory().unwrap();
        let ch = ChannelId([0xC7; 32]);
        let member = [0x33u8; 32];
        let k1 = [0xa1u8; 32];
        let k2 = [0xb2u8; 32];

        assert!(s.register_channel(&ch, &[0xEEu8; 32], "alice").unwrap());
        assert_eq!(s.member_noise_key(&ch, &member).unwrap(), None, "non-member has no key");
        assert!(s.add_member(&ch, "alice", &member, &k1, &[0u8; 64]).unwrap());
        assert_eq!(s.member_noise_key(&ch, &member).unwrap(), Some(k1), "key round-trips");
        // Re-adding the same member updates the pinned key.
        assert!(s.add_member(&ch, "alice", &member, &k2, &[0u8; 64]).unwrap());
        assert_eq!(s.member_noise_key(&ch, &member).unwrap(), Some(k2), "re-add updates the key");
        // Revocation removes the member and its key.
        assert!(s.remove_member(&ch, "alice", &member).unwrap());
        assert_eq!(s.member_noise_key(&ch, &member).unwrap(), None, "revoked member: no key");
        assert!(!s.is_member(&ch, &member).unwrap());
    }

    #[test]
    fn channel_registry_survives_reopen() {
        let path = temp_db_path();
        let ch = ChannelId([0x55; 32]);
        let op = [0x66u8; 32];
        let member = [0x77u8; 32];
        {
            let s = SqliteChannelStore::open(&path).unwrap();
            assert!(s.register_channel(&ch, &op, "alice").unwrap());
            assert!(s.add_member(&ch, "alice", &member, &[0xd4u8; 32], &[0u8; 64]).unwrap());
        }
        let reopened = SqliteChannelStore::open(&path).unwrap();
        assert_eq!(reopened.operator_pubkey(&ch).unwrap(), Some(op), "operator key persists");
        assert!(reopened.is_member(&ch, &member).unwrap(), "membership persists");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn agent_directory_upserts_and_searches_by_exact_role_and_skill() {
        // #144 ②: agents self-register their card URL + advertised roles/skills; peers search by
        // role/skill to discover whom to fetch + verify. Re-registering upserts; matching is by
        // EXACT token (not substring); role+skill compose (AND).
        let dir = SqliteAgentDirectory::open_in_memory().unwrap();
        dir.register("aa", "https://source-1.agents.z/.well-known/agent-card.json",
            &["source".to_string()], &["transfer".to_string()], 100).unwrap();
        dir.register("bb", "https://sink-1.agents.z/.well-known/agent-card.json",
            &["sink".to_string(), "reviewer".to_string()], &["verify".to_string()], 100).unwrap();

        assert_eq!(dir.search(None, None).unwrap().len(), 2, "no filter -> whole directory");

        let sources = dir.search(Some("source"), None).unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].holder_pubkey, "aa");
        assert_eq!(sources[0].role_tags, vec!["source".to_string()]);
        assert_eq!(sources[0].card_url, "https://source-1.agents.z/.well-known/agent-card.json");

        assert_eq!(dir.search(None, Some("verify")).unwrap()[0].holder_pubkey, "bb", "by skill");
        assert!(dir.search(Some("sourc"), None).unwrap().is_empty(), "exact token, not substring");
        assert!(dir.search(Some("source"), Some("verify")).unwrap().is_empty(), "role AND skill");
        assert_eq!(dir.search(Some("source"), Some("transfer")).unwrap().len(), 1, "role AND skill match");

        // Re-register aa: new URL + an added role — upsert, not a duplicate.
        dir.register("aa", "https://new.z/.well-known/agent-card.json",
            &["source".to_string(), "coordinator".to_string()], &["transfer".to_string()], 200).unwrap();
        assert_eq!(dir.search(None, None).unwrap().len(), 2, "re-register upserts (no dupe)");
        let updated = dir.search(Some("coordinator"), None).unwrap();
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0].card_url, "https://new.z/.well-known/agent-card.json", "URL updated");
        assert_eq!(updated[0].registered_at, 200, "timestamp updated");

        // Token-injection is rejected at the door (source's review finding): a newline in a facet
        // would smuggle an extra advertised role, and the row must NOT be written.
        let injected = dir.register(
            "cc", "https://x/.well-known/agent-card.json",
            &["source\nadmin".to_string()], &[], 100,
        );
        assert!(matches!(injected, Err(AgentDirectoryError::InvalidToken(_))), "newline token rejected");
        assert!(dir.search(Some("admin"), None).unwrap().is_empty(), "the injected facet never landed");
        assert!(dir.search(None, None).unwrap().iter().all(|e| e.holder_pubkey != "cc"), "no partial row for the rejected register");
    }

    #[test]
    fn agent_directory_search_filters_in_sql_and_escapes_like_wildcards_347() {
        // #347: search's WHERE clause matches role_tags/skill_ids via LIKE, so a token containing
        // LIKE's own wildcard characters (`%`, `_`) must still be matched EXACTLY -- not widened
        // into a substring/wildcard match -- or the exact-token guarantee this store's own doc
        // comment promises would quietly break for any agent that self-asserts such a token.
        let dir = SqliteAgentDirectory::open_in_memory().unwrap();
        dir.register("aa", "https://a.z/.well-known/agent-card.json",
            &["role%wild".to_string()], &["skill_under".to_string()], 100).unwrap();
        dir.register("bb", "https://b.z/.well-known/agent-card.json",
            &["roleXwild".to_string()], &["skillAunder".to_string()], 100).unwrap();

        // A literal "%" in the stored token must not act as a SQL wildcard: searching for the
        // exact literal token matches only "aa", never "bb" (which would match if % were live).
        let by_percent = dir.search(Some("role%wild"), None).unwrap();
        assert_eq!(by_percent.len(), 1, "% in a token must be matched literally, not as a wildcard");
        assert_eq!(by_percent[0].holder_pubkey, "aa");

        let by_underscore = dir.search(None, Some("skill_under")).unwrap();
        assert_eq!(by_underscore.len(), 1, "_ in a token must be matched literally, not as a wildcard");
        assert_eq!(by_underscore[0].holder_pubkey, "aa");

        // The unrelated entries never match a pattern-shaped query for the other holder's token.
        assert!(dir.search(Some("roleXwild"), None).unwrap().iter().all(|e| e.holder_pubkey == "bb"));

        assert_eq!(dir.count().unwrap(), 2, "count() matches the real row count");
    }

    #[test]
    fn agent_directory_pooled_searches_run_concurrently_while_unpooled_serializes_398() {
        // #398: same proof shape as #344's cda587a test for SqliteTunnelStore -- `search`
        // (the `GET /registry/agents` discovery scan) now takes a connection from `readers`
        // via `Self::read` instead of the single `writer` `Mutex<Connection>` every
        // non-migrated store still uses, so N concurrent slow searches should overlap
        // instead of queuing. Proven two ways in one test, identical workload: a file-backed
        // `open()` store (pooled, ~1x SLEEP) vs. an in-memory store (`readers: None`, per its
        // own struct doc -- falls back to `writer`) that still serializes every search
        // (~N x SLEEP) -- so the speedup is attributable to the pool, not test noise.
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        const N: usize = 8;
        const SLEEP: Duration = Duration::from_millis(100);

        fn run_n_concurrent_slow_reads(dir: &Arc<SqliteAgentDirectory>, n: usize) -> Duration {
            let started = Instant::now();
            let handles: Vec<_> = (0..n)
                .map(|_| {
                    let dir = Arc::clone(dir);
                    std::thread::spawn(move || {
                        // Hold a real connection from `Self::read` for the sleep duration --
                        // exercises the exact guard `search`/`count` actually use.
                        let _conn = dir.read();
                        std::thread::sleep(SLEEP);
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap();
            }
            started.elapsed()
        }

        let path = temp_db_path();
        let pooled = Arc::new(SqliteAgentDirectory::open(&path).unwrap());
        let pooled_elapsed = run_n_concurrent_slow_reads(&pooled, N);

        let unpooled = Arc::new(SqliteAgentDirectory::open_in_memory().unwrap());
        let unpooled_elapsed = run_n_concurrent_slow_reads(&unpooled, N);

        assert!(
            pooled_elapsed < SLEEP * 3,
            "pooled reads should run concurrently (~1x SLEEP), not serialize: {pooled_elapsed:?} for \
             {N} reads of {SLEEP:?} each"
        );
        assert!(
            unpooled_elapsed >= SLEEP * (N as u32) / 2,
            "unpooled (in-memory) reads should still serialize through the writer mutex \
             (~{N}x SLEEP): got only {unpooled_elapsed:?} for {N} reads of {SLEEP:?} each"
        );

        drop(pooled);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    #[test]
    fn agent_directory_concurrent_registers_and_searches_all_succeed_398() {
        // #398: the correctness question the migration raises -- pooled reader connections
        // now run against the SAME on-disk file WHILE `writer` is actively landing
        // `register` writes. `register` still funnels through the single `writer`
        // connection unchanged, so concurrent registers can never race EACH OTHER; what
        // this test exercises is real concurrent `search` reads (the pool) mixed with a
        // real concurrent `register` write workload, asserting neither errors and the
        // durable end state has exactly the rows every writer thread registered.
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        const WRITERS: usize = 4;
        const REGISTERS_PER_WRITER: usize = 25;
        const READERS: usize = 4;

        let path = temp_db_path();
        let dir = Arc::new(SqliteAgentDirectory::open(&path).unwrap());
        let stop = Arc::new(AtomicBool::new(false));

        let reader_handles: Vec<_> = (0..READERS)
            .map(|_| {
                let dir = Arc::clone(&dir);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let mut reads = 0u32;
                    while !stop.load(Ordering::Relaxed) {
                        dir.search(None, None)
                            .expect("a concurrent search must not error while registers are landing");
                        reads += 1;
                    }
                    reads
                })
            })
            .collect();

        let writer_handles: Vec<_> = (0..WRITERS)
            .map(|w| {
                let dir = Arc::clone(&dir);
                std::thread::spawn(move || {
                    for i in 0..REGISTERS_PER_WRITER {
                        dir.register(
                            &format!("writer-{w}-agent-{i}"),
                            "https://example.invalid/.well-known/agent-card.json",
                            &["peer".to_string()],
                            &[],
                            100,
                        )
                        .expect("a concurrent register must succeed within the 5s busy_timeout");
                    }
                })
            })
            .collect();

        for h in writer_handles {
            h.join().unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        let total_reads: u32 = reader_handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert!(total_reads > 0, "readers actually ran concurrently with the writers, not sequentially after");

        assert_eq!(
            dir.search(None, None).unwrap().len(),
            WRITERS * REGISTERS_PER_WRITER,
            "every concurrent register() across every writer thread landed exactly once"
        );

        drop(dir);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    #[test]
    fn ping_fails_when_the_database_can_no_longer_be_read_541() {
        // The readiness probe claims "the database is reachable". #541: `SELECT 1` cannot
        // test that -- it reads no page of the file, so it is answered from the expression
        // itself and stays Ok no matter what happened to the data.
        //
        // Scope, established by experiment rather than assumed: a file corrupted *before
        // startup* is already caught, because `open` applies the schema and fails outright
        // ("file is not a database"), so the process never comes up. What no amount of
        // startup checking covers is a database that stops being readable **while the
        // process runs** -- an I/O error on read, or the store being replaced or emptied
        // underneath a live connection, as a botched restore or a remounted volume does.
        // That is what this test models, and it is the case the old probe reported ready for.
        let path = std::env::temp_dir()
            .join(format!("ct-cp-ping-{}.db", std::process::id()))
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_file(&path);

        let ledger = SqliteLedger::open(&path).expect("a fresh ledger opens");
        ledger
            .ping()
            .expect("an intact but empty ledger is ready -- no rows is not a failure");

        // Pull the ledger's own table out from under the live connection.
        {
            let other = rusqlite::Connection::open(&path).expect("second connection");
            other
                .execute("DROP TABLE accounts", [])
                .expect("drop the table this process needs");
        }

        let err = ledger
            .ping()
            .expect_err("a ledger whose accounts table is gone must not report ready");
        assert!(
            err.to_string().contains("no such table"),
            "the failure names what is actually missing: {err}"
        );

        drop(ledger);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    // ===== ADR-0025: disabled_hostnames (SqliteTunnelStore) =====

    /// Fail-first proof: an ordinary hostname must NOT read as disabled --
    /// otherwise every other assertion in this group would pass vacuously.
    #[test]
    fn a_hostname_nobody_ever_disabled_is_not_disabled() {
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        assert!(!store.is_hostname_disabled("never-touched.example").unwrap());
    }

    #[test]
    fn disable_hostname_is_visible_via_is_hostname_disabled_and_reversible_via_enable() {
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        store.disable_hostname("evil.example", "admin@example.com", 1000).unwrap();
        assert!(store.is_hostname_disabled("evil.example").unwrap());

        let removed = store.enable_hostname("evil.example").unwrap();
        assert!(removed, "enable_hostname must report the row it just removed");
        assert!(!store.is_hostname_disabled("evil.example").unwrap());
    }

    #[test]
    fn enable_hostname_on_a_never_disabled_host_is_a_harmless_no_op() {
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        assert!(!store.enable_hostname("never-disabled.example").unwrap());
    }

    #[test]
    fn disable_hostname_is_idempotent_and_refreshes_who_and_when() {
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        store.disable_hostname("host.example", "first-admin@example.com", 100).unwrap();
        store.disable_hostname("host.example", "second-admin@example.com", 200).unwrap();
        let rows = store.list_disabled_hostnames().unwrap();
        assert_eq!(rows.len(), 1, "re-disabling must not duplicate the row");
        assert_eq!(rows[0].disabled_by, "second-admin@example.com");
        assert_eq!(rows[0].disabled_at, 200);
    }

    #[test]
    fn list_disabled_hostnames_is_newest_first() {
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        store.disable_hostname("a.example", "admin@example.com", 100).unwrap();
        store.disable_hostname("b.example", "admin@example.com", 200).unwrap();
        let rows = store.list_disabled_hostnames().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].hostname, "b.example", "newest first");
        assert_eq!(rows[1].hostname, "a.example");
    }

    // ===== ADR-0025: SqliteManagedDomains =====

    #[test]
    fn add_zone_then_zone_round_trips_and_a_second_add_is_a_no_op() {
        let store = SqliteManagedDomains::open_in_memory().unwrap();
        assert!(store.add_zone("example.org", "admin@example.com", 1000, "active").unwrap());
        // Re-adding the same zone must not error or overwrite -- "already onboarded".
        assert!(!store.add_zone("example.org", "someone-else@example.com", 2000, "active").unwrap());

        let row = store.zone("example.org").unwrap().expect("zone exists");
        assert_eq!(row.added_by.as_deref(), Some("admin@example.com"), "the FIRST add wins");
        assert_eq!(row.added_at, 1000);
        assert_eq!(row.status, "active");
    }

    #[test]
    fn zone_is_none_for_a_never_registered_domain() {
        let store = SqliteManagedDomains::open_in_memory().unwrap();
        assert_eq!(store.zone("never-onboarded.example").unwrap(), None);
    }

    #[test]
    fn list_zones_is_newest_first() {
        let store = SqliteManagedDomains::open_in_memory().unwrap();
        store.add_zone("a.example", "admin@example.com", 100, "active").unwrap();
        store.add_zone("b.example", "admin@example.com", 200, "active").unwrap();
        let rows = store.list_zones().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].zone, "b.example");
        assert_eq!(rows[1].zone, "a.example");
    }

    #[test]
    fn record_hostname_cert_round_trips_and_upserts_on_reissue() {
        let store = SqliteManagedDomains::open_in_memory().unwrap();
        store
            .record_hostname_cert("app.example.org", "example.org", "/certs/managed/app.example.org", "admin@example.com", 1000)
            .unwrap();
        let rows = store.list_hostname_certs().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].zone, "example.org");
        assert_eq!(rows[0].cert_dir, "/certs/managed/app.example.org");

        // Re-issuance (e.g. renewal) upserts, not duplicates.
        store
            .record_hostname_cert("app.example.org", "example.org", "/certs/managed/app.example.org", "admin@example.com", 2000)
            .unwrap();
        let rows = store.list_hostname_certs().unwrap();
        assert_eq!(rows.len(), 1, "re-issuing the same hostname's cert must not duplicate the row");
        assert_eq!(rows[0].issued_at, 2000);
    }
}
