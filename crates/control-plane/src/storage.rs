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
    // `PRAGMA journal_mode` returns the resulting mode as a row, so it must be
    // set via `query_row` — `execute`/`pragma_update` reject row-returning
    // statements. The returned value is the mode SQLite actually applied.
    let _mode: String = conn.query_row("PRAGMA journal_mode=WAL;", [], |row| row.get(0))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(conn)
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
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Issue a fresh single-use join token for `tenant`, persisting it.
    pub fn issue_join_token(&self, tenant: &TenantId) -> rusqlite::Result<JoinToken> {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        self.conn.lock_safe().execute(
            "INSERT INTO join_tokens (token, tenant, redeemed) VALUES (?1, ?2, 0)",
            params![&bytes[..], tenant.0],
        )?;
        Ok(JoinToken(bytes))
    }

    /// Issue `count` fresh single-use join tokens for `tenant` in one call (#145 bulk provisioning):
    /// each is independently random + persisted + redeemable **exactly once**, so "provision N agents"
    /// becomes one mint instead of N. On any failure the partial tokens already persisted stay valid
    /// (each is standalone); the caller sees the error and can retry for the remainder.
    pub fn issue_join_tokens(
        &self,
        tenant: &TenantId,
        count: usize,
    ) -> rusqlite::Result<Vec<JoinToken>> {
        (0..count).map(|_| self.issue_join_token(tenant)).collect()
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
        let mut tokens = Vec::with_capacity(count);
        let mut blob = Vec::with_capacity(count * 32);
        for _ in 0..count {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            tx.execute(
                "INSERT INTO join_tokens (token, tenant, redeemed) VALUES (?1, ?2, 0)",
                params![&bytes[..], tenant.0],
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
    /// consumption is persisted so it survives a restart.
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
    ) -> Result<TenantId, RedeemError> {
        let mut guard = self.conn.lock_safe();
        let tx = guard.transaction()?;
        let row: Option<(String, i64)> = tx
            .query_row(
                "SELECT tenant, redeemed FROM join_tokens WHERE token = ?1",
                params![&token.0[..]],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (tenant, redeemed) = row.ok_or(RedeemError::Enroll(EnrollError::UnknownToken))?;
        if redeemed != 0 {
            return Err(RedeemError::Enroll(EnrollError::TokenAlreadyUsed));
        }
        tx.execute(
            "UPDATE join_tokens SET redeemed = 1 WHERE token = ?1",
            params![&token.0[..]],
        )?;
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
    ) -> Result<TenantId, RedeemError> {
        if !crate::enrollment::verify_join_proof(token, &pubkey, proof) {
            return Err(RedeemError::Enroll(EnrollError::BadProof));
        }
        self.redeem(token, agent, pubkey)
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
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&pk);
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

    /// Delete already-redeemed join-token rows (#292 housekeeping); returns the
    /// count removed. Unlike [`SqliteBootstrap::prune`] this needs no age check at
    /// all — `redeem` already enforces single-use via the `redeemed` flag, so a
    /// redeemed row can never be validly reused regardless of how old it is. Safe
    /// to call periodically; live, unredeemed tokens are never touched.
    pub fn prune_redeemed_join_tokens(&self) -> rusqlite::Result<usize> {
        self.conn.lock_safe().execute("DELETE FROM join_tokens WHERE redeemed != 0", [])
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

fn split_tokens(s: &str) -> Vec<String> {
    if s.is_empty() {
        Vec::new()
    } else {
        s.split('\n').map(str::to_string).collect()
    }
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
pub struct SqliteAgentDirectory {
    conn: Mutex<Connection>,
}

sqlite_store_ctors!(SqliteAgentDirectory);

impl SqliteAgentDirectory {
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
            conn: Mutex::new(conn),
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
        self.conn.lock_safe().execute(
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
    pub fn search(
        &self,
        role: Option<&str>,
        skill: Option<&str>,
    ) -> rusqlite::Result<Vec<AgentDirectoryEntry>> {
        let conn = self.conn.lock_safe();
        let mut stmt = conn.prepare(
            "SELECT holder_pubkey, card_url, role_tags, skill_ids, registered_at
             FROM agent_cards ORDER BY holder_pubkey",
        )?;
        let all = stmt
            .query_map([], |r| {
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
        Ok(all
            .into_iter()
            .filter(|e| {
                role.is_none_or(|r| e.role_tags.iter().any(|t| t == r))
                    && skill.is_none_or(|s| e.skill_ids.iter().any(|t| t == s))
            })
            .collect())
    }
}

/// SQLite-backed **pipeline registry** (#174 B): where a designer *publishes* a workflow
/// [`PipelineSpec`](ct_common::pipeline::PipelineSpec) (#171/#172) so agents can discover it —
/// the pipeline analogue of the #144 agent directory. The spec is stored as its canonical JSON,
/// keyed by the spec's own `id`; publishing is owner-scoped so one designer can't overwrite
/// another's spec.
pub struct SqlitePipelineRegistry {
    conn: Mutex<Connection>,
}

sqlite_store_ctors!(SqlitePipelineRegistry);

impl SqlitePipelineRegistry {
    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS pipelines (
                 id           TEXT PRIMARY KEY,
                 owner        TEXT NOT NULL,
                 spec_json    TEXT NOT NULL,
                 published_at INTEGER NOT NULL
             );",
        )?;
        Ok(Self { conn: Mutex::new(conn) })
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
        let conn = self.conn.lock_safe();
        let existing_owner: Option<String> = conn
            .query_row("SELECT owner FROM pipelines WHERE id = ?1", params![spec.id], |r| r.get(0))
            .optional()?;
        if let Some(o) = existing_owner {
            if o != owner {
                return Ok(false);
            }
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
            .conn
            .lock_safe()
            .query_row("SELECT spec_json FROM pipelines WHERE id = ?1", params![id], |r| r.get(0))
            .optional()?;
        Ok(json.and_then(|j| serde_json::from_str(&j).ok()))
    }

    /// List every published pipeline as `(id, owner)`, sorted by id — the discovery surface a
    /// scanning agent reads to find workflows to join.
    pub fn list(&self) -> rusqlite::Result<Vec<(String, String)>> {
        let conn = self.conn.lock_safe();
        let mut stmt = conn.prepare("SELECT id, owner FROM pipelines ORDER BY id")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Un-publish `id`, owner-scoped (account-deletion cascade's per-pipeline teardown).
    /// Returns whether a row was removed.
    pub fn unpublish(&self, owner: &str, id: &str) -> rusqlite::Result<bool> {
        let n = self.conn.lock_safe().execute(
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
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn balance_of(conn: &Connection, id: &AccountId) -> rusqlite::Result<Option<i64>> {
        conn.query_row(
            "SELECT balance FROM accounts WHERE account = ?1",
            params![&id.0[..]],
            |r| r.get(0),
        )
        .optional()
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
            let mut a = [0u8; 32];
            a.copy_from_slice(&bytes);
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

    /// Cheap liveness check that the database is reachable (readiness probe).
    pub fn ping(&self) -> rusqlite::Result<()> {
        self.conn
            .lock_safe()
            .query_row("SELECT 1", [], |_| Ok(()))
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
    pub fn credit(&self, id: &AccountId, amount: u64) -> Result<u64, LedgerOpError> {
        let conn = self.conn.lock_safe();
        let bal = Self::balance_of(&conn, id)?
            .ok_or(LedgerOpError::Ledger(LedgerError::UnknownAccount))?;
        let new = bal.saturating_add(amount as i64);
        conn.execute(
            "UPDATE accounts SET balance = ?1 WHERE account = ?2",
            params![new, &id.0[..]],
        )?;
        Ok(new as u64)
    }

    /// Spend credit; fails with [`LedgerError::InsufficientCredit`] and leaves
    /// the balance unchanged when the account cannot cover `amount`.
    pub fn debit(&self, id: &AccountId, amount: u64) -> Result<u64, LedgerOpError> {
        let conn = self.conn.lock_safe();
        let bal = Self::balance_of(&conn, id)?
            .ok_or(LedgerOpError::Ledger(LedgerError::UnknownAccount))?;
        let bal_u = bal as u64;
        if bal_u < amount {
            return Err(LedgerOpError::Ledger(LedgerError::InsufficientCredit {
                balance: bal_u,
                requested: amount,
            }));
        }
        let new = bal - amount as i64;
        conn.execute(
            "UPDATE accounts SET balance = ?1 WHERE account = ?2",
            params![new, &id.0[..]],
        )?;
        Ok(new as u64)
    }

    /// #272: look up a prior token issuance by its client-supplied idempotency key.
    /// A caller retrying a `/billing/issue` call after a lost response (crash, timeout,
    /// network drop) uses this to get back the SAME already-minted token instead of
    /// [`Self::debit_and_record_issuance`] debiting the account a second time for a
    /// token that was already paid for.
    pub fn issuance_for_key(&self, idempotency_key: &[u8]) -> rusqlite::Result<Option<[u8; 32]>> {
        self.conn
            .lock_safe()
            .query_row(
                "SELECT token FROM token_issuances WHERE idempotency_key = ?1",
                params![idempotency_key],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map(|opt| {
                opt.map(|bytes| {
                    let mut t = [0u8; 32];
                    t.copy_from_slice(&bytes);
                    t
                })
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
        let bal = tx
            .query_row("SELECT balance FROM accounts WHERE account = ?1", params![&id.0[..]], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?
            .ok_or(LedgerOpError::Ledger(LedgerError::UnknownAccount))?;
        let bal_u = bal as u64;
        if bal_u < amount {
            return Err(LedgerOpError::Ledger(LedgerError::InsufficientCredit {
                balance: bal_u,
                requested: amount,
            }));
        }
        let new = bal - amount as i64;
        tx.execute("UPDATE accounts SET balance = ?1 WHERE account = ?2", params![new, &id.0[..]])?;
        tx.execute(
            "INSERT INTO token_issuances (idempotency_key, account, token, price, issued_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![idempotency_key, &id.0[..], &token[..], amount as i64, now as i64],
        )?;
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
pub struct SqliteTunnelStore {
    conn: Mutex<Connection>,
}

sqlite_store_ctors!(SqliteTunnelStore);

impl SqliteTunnelStore {
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
             );",
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
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create a tunnel owned by `subject`; returns its metadata. A fresh routing
    /// token is minted and persisted server-side so a revocation can later find
    /// and invalidate the tunnel's edge registration (#27 RB1). The `id` is a
    /// random hex string; `created_at` is the current Unix time.
    pub fn create(
        &self,
        subject: &str,
        name: &str,
        hostname: Option<&str>,
    ) -> rusqlite::Result<SubjectTunnel> {
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
        self.conn.lock_safe().execute(
            "INSERT INTO subject_tunnels (id, subject, name, hostname, created_at, routing_token)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, subject, name, hostname, created_at, routing_token],
        )?;
        Ok(SubjectTunnel {
            id,
            name: name.to_string(),
            hostname: hostname.map(str::to_string),
            created_at,
            routing_token,
        })
    }

    /// List `subject`'s own tunnels, newest first.
    pub fn list_for_subject(&self, subject: &str) -> rusqlite::Result<Vec<SubjectTunnel>> {
        let conn = self.conn.lock_safe();
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
        let conn = self.conn.lock_safe();
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
        let mut guard = self.conn.lock_safe();
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
        let conn = self.conn.lock_safe();
        let mut stmt = conn.prepare("SELECT token FROM revoked_tokens")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect()
    }

    /// Whether `subject` is the owner of `tunnel_id` (not merely a grantee).
    /// Used to gate agent onboarding — only the owner installs an agent for a
    /// tunnel (#28).
    pub fn owns(&self, subject: &str, tunnel_id: &str) -> rusqlite::Result<bool> {
        Ok(Self::owner_of(&self.conn.lock_safe(), tunnel_id)?.as_deref() == Some(subject))
    }

    /// The Browser-Plane hostname of a tunnel the caller owns, if any (#38 DL2):
    /// used to clear the tunnel's DNS record on revoke. Owner-scoped.
    pub fn tunnel_hostname(&self, subject: &str, tunnel_id: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .lock_safe()
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
        self.conn
            .lock_safe()
            .query_row(
                "SELECT routing_token FROM subject_tunnels WHERE id = ?1 AND subject = ?2",
                params![tunnel_id, subject],
                |r| r.get(0),
            )
            .optional()
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
        let conn = self.conn.lock_safe();
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
        let granted: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM tunnel_grants WHERE tunnel_id = ?1 AND grantee = ?2",
                params![tunnel_id, subject],
                |r| r.get(0),
            )
            .optional()?;
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
        let conn = self.conn.lock_safe();
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
        let granted: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM tunnel_grants WHERE tunnel_id = ?1 AND grantee = ?2",
                params![tunnel_id, subject],
                |r| r.get(0),
            )
            .optional()?;
        Ok(granted.and(hostname))
    }

    /// List every tunnel `subject` is authorized to use — the ones they own plus
    /// the ones shared with them (#29) — each flagged with whether they own it
    /// (owned tunnels get the management actions; shared ones are read-only).
    pub fn list_authorized_for_subject(
        &self,
        subject: &str,
    ) -> rusqlite::Result<Vec<(SubjectTunnel, bool)>> {
        let conn = self.conn.lock_safe();
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
        self.conn
            .lock_safe()
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
        let conn = self.conn.lock_safe();
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

    /// Flip a hostname from Rot to Gelb, entering the admission queue for the
    /// first time (`queued_at = now`). No-op (`Ok(false)`) unless the
    /// hostname is currently `rot` -- callers must not clobber later state.
    pub fn enter_gelb_queue(&self, hostname: &str, now: i64) -> rusqlite::Result<bool> {
        let affected = self.conn.lock_safe().execute(
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
        let conn = self.conn.lock_safe();
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
        let conn = self.conn.lock_safe();
        let mut stmt =
            conn.prepare("SELECT hostname FROM subject_tunnels WHERE status = 'gelb' AND hostname IS NOT NULL")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect()
    }

    /// Hostnames queued (Gelb, unclaimed, unassigned) in strict FIFO order --
    /// the admission sweep's candidate list, oldest `queued_at` first.
    pub fn gelb_queue_fifo(&self) -> rusqlite::Result<Vec<String>> {
        let conn = self.conn.lock_safe();
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
        let affected = self.conn.lock_safe().execute(
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
        self.conn.lock_safe().execute(
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
        let affected = self.conn.lock_safe().execute(
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
        let mut guard = self.conn.lock_safe();
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
            tx.execute(
                "INSERT INTO acme_issuance_log (ca, domain, hostname, issued_at) VALUES (?1, ?2, ?3, ?4)",
                params![ca, domain, hostname, now],
            )?;
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
        let conn = self.conn.lock_safe();
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
        self.conn
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
        let conn = self.conn.lock_safe();
        let used: i64 = conn.query_row(
            "SELECT COUNT(*) FROM acme_issuance_log WHERE ca = ?1 AND domain = ?2 AND issued_at >= ?3",
            params![ca, domain, since],
            |r| r.get(0),
        )?;
        let reserved: i64 = conn.query_row(
            "SELECT COUNT(*) FROM subject_tunnels WHERE assigned_ca = ?1 AND claim_state = 'offered'",
            params![ca],
            |r| r.get(0),
        )?;
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
        let conn = self.conn.lock_safe();
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
        let conn = self.conn.lock_safe();
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
        let conn = self.conn.lock_safe();
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

    /// Whether `subject` may use `tunnel_id`: `true` if it is the owner or holds
    /// a grant (#29). This is the authorization gate for capability access to a
    /// shared tunnel — `false` for an unknown tunnel.
    pub fn is_authorized(&self, subject: &str, tunnel_id: &str) -> rusqlite::Result<bool> {
        let conn = self.conn.lock_safe();
        if Self::owner_of(&conn, tunnel_id)?.as_deref() == Some(subject) {
            return Ok(true);
        }
        let granted: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM tunnel_grants WHERE tunnel_id = ?1 AND grantee = ?2",
                params![tunnel_id, subject],
                |r| r.get(0),
            )
            .optional()?;
        Ok(granted.is_some())
    }
}

/// Agent Fabric channel registry (ADR-0020, #72 AF2d). Under **agent-held** key
/// custody the operator agent holds its channel signing key and signs grants; the
/// control plane stores only the operator **public** key + membership, and hands
/// the edge the operator pubkey for a channel (the same role host-auth plays for
/// hostnames). Never stores a channel signing key. Owner-scoped: only the subject
/// that registered a channel may re-key it or manage its members.
pub struct SqliteChannelStore {
    conn: Mutex<Connection>,
}

sqlite_store_ctors!(SqliteChannelStore);

impl SqliteChannelStore {
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
             );",
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
             );",
        )?;
        // Self-service discoverability follow-up (2026-08-01): an allow-listed
        // person previously had no way to find out *which* channel they'd been
        // granted access to short of being told the raw channel id out of band --
        // the exact gap that kept surfacing as a manual, repeated chat hand-off
        // for real participants. Recording when a claim actually landed lets
        // `channels_for_email` report status (pending / claimed) without needing
        // to guess a not-yet-known holder key. Additive, nullable -- #44 pattern.
        ensure_column(&conn, "channel_allowlist", "claimed_at", "INTEGER")?;
        Ok(Self {
            conn: Mutex::new(conn),
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
        let conn = self.conn.lock_safe();
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

    /// The operator public key for `channel`, if registered (the edge's lookup).
    pub fn operator_pubkey(&self, channel: &ChannelId) -> rusqlite::Result<Option<[u8; 32]>> {
        let raw: Option<Vec<u8>> = self
            .conn
            .lock_safe()
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
            .conn
            .lock_safe()
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
        let conn = self.conn.lock_safe();
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
        let conn = self.conn.lock_safe();
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
        Ok(self.conn.lock_safe().execute(
            "DELETE FROM channel_allowlist WHERE email = ?1",
            params![email.to_ascii_lowercase()],
        )?)
    }

    /// The subject that owns `channel`, if registered.
    pub fn channel_owner(&self, channel: &ChannelId) -> rusqlite::Result<Option<String>> {
        self.conn
            .lock_safe()
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
        let conn = self.conn.lock_safe();
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
        let conn = self.conn.lock_safe();
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
        let conn = self.conn.lock_safe();
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
        self.conn.lock_safe().execute(
            "INSERT INTO channel_challenges (nonce, expires_at) VALUES (?1, ?2)",
            params![&nonce[..], now.saturating_add(ttl_secs) as i64],
        )?;
        Ok(nonce)
    }

    /// Consume a redemption challenge nonce: returns `true` iff it exists and is unexpired
    /// (then deletes it, so a replay of the same nonce fails), `false` otherwise. Prunes
    /// expired nonces so the table stays bounded.
    pub fn consume_challenge(&self, nonce: &[u8; 32], now: u64) -> rusqlite::Result<bool> {
        let conn = self.conn.lock_safe();
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
            .conn
            .lock_safe()
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
            .conn
            .lock_safe()
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
            .conn
            .lock_safe()
            .query_row(
                "SELECT 1 FROM channel_members WHERE channel = ?1 AND holder = ?2",
                params![&channel.0[..], &holder[..]],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Remove `holder` from `channel`. Owner-scoped, idempotent; `false` if not the
    /// owner (or unknown channel).
    pub fn remove_member(
        &self,
        channel: &ChannelId,
        owner: &str,
        holder: &[u8; 32],
    ) -> rusqlite::Result<bool> {
        let conn = self.conn.lock_safe();
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
            "DELETE FROM channel_members WHERE channel = ?1 AND holder = ?2",
            params![&channel.0[..], &holder[..]],
        )?;
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
        let conn = self.conn.lock_safe();
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
        let conn = self.conn.lock_safe();
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
        let conn = self.conn.lock_safe();
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
            .conn
            .lock_safe()
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
    ) -> rusqlite::Result<bool> {
        let conn = self.conn.lock_safe();
        let allowed: bool = conn
            .query_row(
                "SELECT 1 FROM channel_allowlist WHERE channel = ?1 AND email = ?2",
                params![&channel.0[..], email.to_ascii_lowercase()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !allowed {
            return Ok(false);
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
        Ok(true)
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
    pub fn channels_for_email(&self, email: &str) -> rusqlite::Result<Vec<(ChannelId, Option<u64>)>> {
        let conn = self.conn.lock_safe();
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
    /// deserializes is treated as absent rather than erroring the caller.
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
        Ok(json.and_then(|j| serde_json::from_str(&j).ok()))
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
pub struct SqliteTopologyStore {
    conn: Mutex<Connection>,
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

sqlite_store_ctors!(SqliteTopologyStore);

impl SqliteTopologyStore {
    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS topology_agents (
                 agent    TEXT PRIMARY KEY,
                 owner    TEXT NOT NULL,
                 topology TEXT
             );
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
             );",
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
        // #107-complex: an edge may explicitly name a REAL, separately-registered channel
        // (from SqliteChannelStore) it carries, instead of only ever relying on the
        // implicit, derived channel_id_for_link(a, b). Nullable + additive (#44): most
        // edges never set this, and derivation is unaffected either way -- this is purely
        // link-info display + an explicit association a collaborator can attach, not a new
        // authorization path (authorized_channels/topology_authorizes still only ever
        // consult the derived id, so an explicit channel_id here cannot be used to smuggle
        // admission for a channel the drawn edge doesn't actually imply).
        ensure_column(&conn, "topology_edges", "channel_id", "BLOB")?;
        Ok(Self {
            conn: Mutex::new(conn),
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
        let n = self.conn.lock_safe().execute(
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
            .conn
            .lock_safe()
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
        let n = self.conn.lock_safe().execute(
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
            .conn
            .lock_safe()
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
        let conn = self.conn.lock_safe();
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
        self.conn
            .lock_safe()
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
        self.conn
            .lock_safe()
            .query_row(
                "SELECT id, owner, net_uuid FROM topologies WHERE net_uuid = ?1",
                params![net_uuid],
                |r| Ok(Self::row_to_topology(r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
    }

    /// Every topology `owner` owns (by id, sorted).
    pub fn list_topologies(&self, owner: &str) -> rusqlite::Result<Vec<crate::topology::Topology>> {
        let conn = self.conn.lock_safe();
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
        let conn = self.conn.lock_safe();
        let n = conn.execute(
            "DELETE FROM topologies WHERE id = ?1 AND owner = ?2",
            params![id, owner],
        )?;
        if n > 0 {
            // The topology row is gone -- also drop what only made sense while it
            // existed (its wiring and its share list), and release any agent still
            // assigned into it back to "unassigned" rather than leaving it pointed at
            // a dangling topology id (previously left orphaned -- account-deletion
            // cascade work surfaced this as a real, if mostly harmless, leak).
            conn.execute("DELETE FROM topology_edges WHERE topology = ?1", params![id])?;
            conn.execute("DELETE FROM topology_shares WHERE topology = ?1", params![id])?;
            conn.execute(
                "UPDATE topology_agents SET topology = NULL WHERE topology = ?1",
                params![id],
            )?;
        }
        Ok(n > 0)
    }

    /// Every owned topology, agent, edge and share for `owner`, gone (account-deletion
    /// cascade). Reuses [`delete_topology`](Self::delete_topology) per id so the same
    /// cascade rules apply; also drops the owner's now-ownerless
    /// `topology_agents` rows (agents it registered but never assigned) and strips it
    /// as a collaborator from anyone else's share list. Returns the number of owned
    /// topologies removed.
    pub fn delete_all_owned_by(&self, owner: &str) -> rusqlite::Result<usize> {
        let ids: Vec<String> = {
            let conn = self.conn.lock_safe();
            let mut stmt = conn.prepare("SELECT id FROM topologies WHERE owner = ?1")?;
            let rows = stmt
                .query_map(params![owner], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        let mut removed = 0usize;
        for id in &ids {
            if self.delete_topology(owner, id)? {
                removed += 1;
            }
        }
        let conn = self.conn.lock_safe();
        conn.execute("DELETE FROM topology_agents WHERE owner = ?1", params![owner])?;
        conn.execute("DELETE FROM topology_shares WHERE added_by = ?1", params![owner])?;
        Ok(removed)
    }

    /// Strip `email` as a collaborator from every topology it's been shared into,
    /// regardless of owner (account-deletion cascade: a deleted account should stop
    /// showing up in other people's "shared with" lists too). Returns rows removed.
    pub fn remove_shares_by_email(&self, email: &str) -> rusqlite::Result<usize> {
        Ok(self.conn.lock_safe().execute(
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
        if a == b {
            return Ok(false);
        }
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        let conn = self.conn.lock_safe();
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
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        let conn = self.conn.lock_safe();
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
        let conn = self.conn.lock_safe();
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
        let holder_hex: String = holder.iter().map(|b| format!("{b:02x}")).collect();
        let conn = self.conn.lock_safe();
        let mut stmt = conn.prepare(
            "SELECT t.operator_pubkey, e.a, e.b \
             FROM topology_edges e JOIN topologies t ON t.id = e.topology \
             WHERE t.operator_pubkey IS NOT NULL AND (lower(e.a) = ?1 OR lower(e.b) = ?1)",
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
            .conn
            .lock_safe()
            .execute(
                "UPDATE topology_agents SET kind = ?3 WHERE agent = ?1 AND owner = ?2",
                params![agent, by, kind],
            )
            .map_err(|e| e.to_string())?;
        Ok(n > 0)
    }

    /// The current assignment for `agent`, if it has ever been touched.
    pub fn assignment(&self, agent: &str) -> rusqlite::Result<Option<crate::topology::AgentAssignment>> {
        Self::load(&self.conn.lock_safe(), agent)
    }

    /// Share `agent` into `topology` on behalf of `by`. First touch registers the agent
    /// as owned by `by`; thereafter only the owner may assign, and only when unassigned
    /// (exclusivity — [`crate::topology::AssignError::AlreadyAssigned`] otherwise). The
    /// transition is enforced by the pure state machine and persisted.
    pub fn assign(&self, by: &str, agent: &str, topology: &str) -> Result<(), TopologyError> {
        let conn = self.conn.lock_safe();
        let mut a = Self::load(&conn, agent)?.unwrap_or_else(|| crate::topology::AgentAssignment::new(by));
        a.assign(by, topology)?;
        Self::persist(&conn, agent, &a)?;
        Ok(())
    }

    /// End `agent`'s current sharing (the owner reclaims, or the current topology
    /// releases), returning it to its owner's control. Persisted so exclusivity survives
    /// a restart. [`crate::topology::AssignError::NotAssigned`] if it is not in a topology.
    pub fn revoke(&self, by: &str, agent: &str) -> Result<(), TopologyError> {
        let conn = self.conn.lock_safe();
        let mut a = Self::load(&conn, agent)?.ok_or(crate::topology::AssignError::NotAssigned)?;
        a.revoke(by)?;
        Self::persist(&conn, agent, &a)?;
        Ok(())
    }

    /// The agents currently assigned to `topology` (sorted).
    pub fn agents_in(&self, topology: &str) -> rusqlite::Result<Vec<String>> {
        let conn = self.conn.lock_safe();
        let mut stmt =
            conn.prepare("SELECT agent FROM topology_agents WHERE topology = ?1 ORDER BY agent")?;
        let agents = stmt
            .query_map(params![topology], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(agents)
    }

    /// Like [`agents_in`](Self::agents_in), but pairs each agent with its node **kind**
    /// (`"peer"`/`"super-peer"`, #107-complex) — what the editor's richer node rendering
    /// needs; `agents_in` stays as-is for the (kind-indifferent) optimizer/authorization
    /// call sites.
    pub fn agents_with_kind(&self, topology: &str) -> rusqlite::Result<Vec<(String, String)>> {
        let conn = self.conn.lock_safe();
        let mut stmt = conn
            .prepare("SELECT agent, kind FROM topology_agents WHERE topology = ?1 ORDER BY agent")?;
        let agents = stmt
            .query_map(params![topology], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(agents)
    }

    /// Like [`edges`](Self::edges), but includes each edge's explicitly-attached **channel
    /// id**, if any (#107-complex link info). `None` means the edge relies purely on the
    /// implicit, derived `channel_id_for_link` (the common case).
    pub fn edges_with_channel(&self, topology: &str) -> rusqlite::Result<Vec<(String, String, Option<[u8; 32]>)>> {
        let conn = self.conn.lock_safe();
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
        if a == b {
            return Ok(false);
        }
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        let conn = self.conn.lock_safe();
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
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        let conn = self.conn.lock_safe();
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
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        let conn = self.conn.lock_safe();
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
        let conn = self.conn.lock_safe();
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
        let conn = self.conn.lock_safe();
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
        let conn = self.conn.lock_safe();
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
        let conn = self.conn.lock_safe();
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
        let conn = self.conn.lock_safe();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_sqlite_store_constructs_via_the_shared_ctor_macro() {
        // #192 (frozen): sqlite_store_ctors! generates open/open_in_memory for all 10 stores, each
        // delegating to its own from_connection. The regression the macro could introduce is "a store
        // no longer opens / its schema isn't applied", so construct every one — a failure here (a
        // store dropped from the macro, a broken from_connection) fails loudly, not silently at boot.
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
            .conn
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

    #[test]
    fn subject_tunnel_store_is_self_scoped_for_create_list_revoke() {
        // #27 PP1: a customer creates, lists and revokes only their OWN tunnels.
        let store = SqliteTunnelStore::open_in_memory().unwrap();

        let a1 = store.create("alice", "web", Some("app.example")).unwrap();
        let _a2 = store.create("alice", "ssh", None).unwrap();
        let b1 = store.create("bob", "db", None).unwrap();

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
            .expect("create must not 500 on a migrated older DB");
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
        let a = store.create("alice", "web", None).unwrap();
        let b = store.create("alice", "ssh", None).unwrap();
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

        let a = store.create("alice", "web", None).unwrap();
        let b = store.create("alice", "api", None).unwrap();
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
        let t = store.create("alice", "web", Some("app.example")).unwrap();
        assert_eq!(store.routing_token_for_hostname("app.example").unwrap(), Some(t.routing_token));
        assert_eq!(store.routing_token_for_hostname("no-such-host").unwrap(), None);
    }

    #[test]
    fn a_fresh_tunnel_starts_rot_with_no_admission_state() {
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        store.create("alice", "web", Some("app.example")).unwrap();
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
        store.create("alice", "a", Some("a.example")).unwrap();
        store.create("alice", "b", Some("b.example")).unwrap();
        store.create("alice", "c", Some("c.example")).unwrap();

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
    fn offering_a_claim_assigns_a_ca_permanently_and_leaves_the_queue() {
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        store.create("alice", "a", Some("a.example")).unwrap();
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
        store.create("alice", "a", Some("a.example")).unwrap();
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
        store.create("alice", "a", Some("a.example")).unwrap();
        store.create("alice", "b", Some("b.example")).unwrap();
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
        store.create("alice", "a", Some("a.example")).unwrap();
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

        // A renewal (calling this again) is a harmless idempotent re-affirmation
        // that still adds a second, correct ledger row -- renewals really do
        // consume CA capacity again.
        store.record_issuance_complete("a.example", "example.com", 400).unwrap();
        let (used_after_renewal, _) = store.ca_budget_usage("google-trust-services", "example.com", 0).unwrap();
        assert_eq!(used_after_renewal, 2);
    }

    #[test]
    fn ca_budget_usage_counts_offered_reservations_as_real_headroom_consumption() {
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        store.create("alice", "a", Some("a.example")).unwrap();
        store.create("alice", "b", Some("b.example")).unwrap();
        store.enter_gelb_queue("a.example", 100).unwrap();
        store.enter_gelb_queue("b.example", 200).unwrap();
        store.offer_claim("a.example", "zerossl", 300, 999_999).unwrap();
        store.record_issuance_complete("a.example", "example.com", 400).unwrap();
        store.offer_claim("b.example", "zerossl", 500, 999_999).unwrap();

        let (used, reserved) = store.ca_budget_usage("zerossl", "example.com", 0).unwrap();
        assert_eq!(used, 1, "a.example's completed issuance");
        assert_eq!(reserved, 1, "b.example's still-open offer, not yet completed");
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
        let t = store.create("alice", "web", None).unwrap();
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

    #[test]
    fn tunnel_grants_are_owner_managed_and_gate_authorization() {
        // #29 PP1: only the owner manages grants; is_authorized = owner or grantee.
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        let t = store.create("alice", "web", None).unwrap();

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
        let token = store.issue_join_token(&tenant()).unwrap();
        let agent = AgentId("agent-1".into());
        let pubkey = [7u8; 32];

        let bound = store.redeem(&token, &agent, pubkey).unwrap();
        assert_eq!(bound, tenant());
        assert_eq!(store.binding(&agent).unwrap(), Some((tenant(), pubkey)));
    }

    #[test]
    fn join_token_is_single_use() {
        let store = SqliteEnrollment::open_in_memory().unwrap();
        let token = store.issue_join_token(&tenant()).unwrap();
        store.redeem(&token, &AgentId("a1".into()), [1u8; 32]).unwrap();
        let second = store.redeem(&token, &AgentId("a2".into()), [2u8; 32]);
        assert!(
            matches!(second, Err(RedeemError::Enroll(EnrollError::TokenAlreadyUsed))),
            "second redemption rejected"
        );
    }

    #[test]
    fn issue_join_tokens_mints_distinct_independently_redeemable_tokens() {
        // #145 bulk provisioning (frozen): a batch mint yields N DISTINCT tokens, each redeemable
        // exactly once and independent of the others — "provision N agents" in one call.
        let store = SqliteEnrollment::open_in_memory().unwrap();
        let tokens = store.issue_join_tokens(&tenant(), 5).unwrap();
        assert_eq!(tokens.len(), 5, "five tokens minted");

        // All distinct.
        let mut seen = std::collections::HashSet::new();
        for t in &tokens {
            assert!(seen.insert(t.0), "each batch token is distinct");
        }

        // Each is a real, independently single-use token: redeem #0, its replay fails, #1 still works.
        assert!(store.redeem(&tokens[0], &AgentId("a0".into()), [10u8; 32]).is_ok(), "first token redeems");
        assert!(
            matches!(
                store.redeem(&tokens[0], &AgentId("a0b".into()), [11u8; 32]),
                Err(RedeemError::Enroll(EnrollError::TokenAlreadyUsed))
            ),
            "a batch token is single-use like any other"
        );
        assert!(
            store.redeem(&tokens[1], &AgentId("a1".into()), [12u8; 32]).is_ok(),
            "a different batch token is unaffected — independent tokens"
        );

        // count = 0 yields no tokens (caller/REST layer decides whether that's an error).
        assert!(store.issue_join_tokens(&tenant(), 0).unwrap().is_empty(), "zero count mints nothing");
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
        assert!(store.redeem(&first[0], &AgentId("a".into()), [1u8; 32]).is_ok(), "an idempotent token redeems");
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
        let live = store.issue_join_token(&tenant()).unwrap();
        let redeemed = store.issue_join_token(&tenant()).unwrap();
        store.redeem(&redeemed, &AgentId("a".into()), [1u8; 32]).unwrap();

        assert_eq!(store.prune_redeemed_join_tokens().unwrap(), 1, "exactly the redeemed row is pruned");
        // A second prune immediately after finds nothing new to remove.
        assert_eq!(store.prune_redeemed_join_tokens().unwrap(), 0);
        // Pruning the redeemed row never touched the live, unredeemed one.
        assert!(store.redeem(&live, &AgentId("b".into()), [2u8; 32]).is_ok(), "the live token still redeems");
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
        let result = store.redeem(&JoinToken([0u8; 32]), &AgentId("a1".into()), [3u8; 32]);
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
        let token = store.issue_join_token(&tenant()).unwrap();
        let agent = AgentId("agent-1".into());

        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pubkey = sk.verifying_key().to_bytes();
        let wrong = SigningKey::from_bytes(&[43u8; 32]);

        // Proof signed by the wrong key -> BadProof, token untouched.
        let forged = wrong.sign(&token.0).to_bytes();
        assert!(
            matches!(
                store.redeem_with_proof(&token, &agent, pubkey, &forged),
                Err(RedeemError::Enroll(EnrollError::BadProof))
            ),
            "a proof that doesn't match the bound key is rejected"
        );
        assert!(store.binding(&agent).unwrap().is_none(), "nothing bound on a bad proof");

        // Genuine proof by the bound key -> binds, and the token is now single-use.
        let proof = sk.sign(&token.0).to_bytes();
        assert_eq!(store.redeem_with_proof(&token, &agent, pubkey, &proof).unwrap(), tenant());
        assert_eq!(store.binding(&agent).unwrap(), Some((tenant(), pubkey)));
        assert!(
            matches!(
                store.redeem_with_proof(&token, &agent, pubkey, &proof),
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
            token = store.issue_join_token(&tenant()).unwrap();
            store.redeem(&token, &agent, [9u8; 32]).unwrap();
        } // store dropped -> connection closed

        let reopened = SqliteEnrollment::open(&path).unwrap();
        assert_eq!(
            reopened.binding(&agent).unwrap(),
            Some((tenant(), [9u8; 32])),
            "binding persisted across reopen"
        );
        let replay = reopened.redeem(&token, &AgentId("other".into()), [1u8; 32]);
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

    #[test]
    fn debit_and_record_issuance_is_replayed_from_the_idempotency_key_without_a_second_debit_272() {
        // #272: a caller retrying after a lost response (the debit committed, but the
        // token never reached them) must get back the SAME token, not be charged again.
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let acct = ledger.open_account().unwrap();
        ledger.credit(&acct, 10).unwrap();
        let key = [0x11u8; 32];
        let token = [0xAAu8; 32];

        assert_eq!(ledger.issuance_for_key(&key).unwrap(), None, "nothing recorded yet");
        let bal = ledger.debit_and_record_issuance(&acct, 3, &key, &token, 1_000).unwrap();
        assert_eq!(bal, 7, "debited once");
        assert_eq!(ledger.balance(&acct).unwrap(), 7);

        // The "retry": same key looked up first, exactly what the HTTP handler does.
        assert_eq!(ledger.issuance_for_key(&key).unwrap(), Some(token), "the same token comes back");
        assert_eq!(ledger.balance(&acct).unwrap(), 7, "looking it up never debits");

        // A genuinely NEW purchase (different key) still debits normally.
        let key2 = [0x22u8; 32];
        let token2 = [0xBBu8; 32];
        ledger.debit_and_record_issuance(&acct, 2, &key2, &token2, 1_001).unwrap();
        assert_eq!(ledger.balance(&acct).unwrap(), 5, "a different key debits again");
        assert_eq!(ledger.issuance_for_key(&key2).unwrap(), Some(token2));
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
        assert_eq!(ledger.issuance_for_key(&key).unwrap(), None, "no issuance recorded for the refused debit");
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
        assert!(!s.claim_via_allowlist(&ch, "stranger@example.com", &holder, &noise, &attest, 3_000).unwrap());
        assert!(!s.is_member(&ch, &holder).unwrap());

        // The allow-listed email claims successfully (owner never involved in this call).
        assert!(s.claim_via_allowlist(&ch, "nat@example.com", &holder, &noise, &attest, 3_000).unwrap());
        assert!(s.is_member(&ch, &holder).unwrap());

        // Owner removes the email; a FUTURE claim by a new holder is refused, but the
        // already-claimed membership above is untouched (allow-list ≠ membership).
        assert!(!s.allowlist_remove(&ch, "mallory", "nat@example.com").unwrap(), "non-owner can't remove");
        assert!(s.allowlist_remove(&ch, "alice", "nat@example.com").unwrap());
        assert!(s.allowlist_remove(&ch, "alice", "nat@example.com").unwrap(), "remove is idempotent");
        assert_eq!(s.allowlist_list(&ch, "alice").unwrap(), Some(vec![]));
        assert!(s.is_member(&ch, &holder).unwrap(), "de-listing doesn't revoke an existing member");
        let another_holder = [0x99u8; 32];
        assert!(!s.claim_via_allowlist(&ch, "nat@example.com", &another_holder, &noise, &attest, 4_000).unwrap());

        // An unknown channel's allow-list is always empty -> claim always false.
        let unknown = ChannelId([0xAB; 32]);
        assert!(!s.claim_via_allowlist(&unknown, "nat@example.com", &holder, &noise, &attest, 4_000).unwrap());
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
        assert!(s.claim_via_allowlist(&ch_a, "nat@example.com", &holder, &noise, &attest, 5_000).unwrap());
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
}
