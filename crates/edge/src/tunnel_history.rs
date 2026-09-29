//! #776: durable per-tunnel session history -- the foundation for owner-facing
//! uptime, usage, receipts, and alerts.
//!
//! [`EdgeState`](crate::state::EdgeState) keeps `tunnel_bytes`/`connected_since`/
//! `last_seen` in memory only: every redeploy wiped them, and the maps grew by one entry
//! per token ever seen with no eviction. This module adds the missing persistence: one
//! `tunnel_sessions` row per unbroken connection streak (opened by the first
//! registration on either transport, closed by the teardown paths), with the byte
//! counters flushed into the open row periodically and on close. The in-memory maps stay
//! the hot-path counters they are today -- `note_relay` never touches SQLite -- and the
//! flush task in [`run_tunnel_history_flush_loop`] is what finally lets them evict tokens
//! with no live session.
//!
//! Disclosure bound (ADR-0016 posture, same as the presence routes of #763): a session row
//! is METADATA ONLY -- routing token, transport, timestamps, a disconnect reason, and byte
//! volume. Never a hostname, source IP, request path, or any payload. The routing token is
//! stored as the same lowercase hex the admin API already uses for it.
//!
//! A separate DB file from `audit_log.rs`'s `conn_audit` (#603): that store is a host-only
//! evidentiary record with its own legal-floor retention argument; this one is served
//! over the admin listener to the control plane, so mixing the two in one file would blur
//! which access posture applies to which table. Same SQLite shape as `audit_log.rs`
//! (`open`/`open_in_memory`, a plain `Mutex<Connection>`, WAL + busy_timeout, owner-only
//! file mode), duplicated rather than shared for the same reason that file gives.
//!
//! Enabled by DEFAULT (unlike the audit log): the default path is `tunnel-history.sqlite`
//! beside the persisted CA key (`edge-ca-key.pem`, the edge's one durable volume);
//! `CT_EDGE_TUNNEL_HISTORY_PATH` overrides it and `CT_EDGE_TUNNEL_HISTORY=off` disables
//! it. A path that cannot be opened falls back to an in-memory store with a loud warning
//! -- the feature keeps working for the process lifetime, it just isn't durable.
//!
//! #782: the same store also holds the edge's **signed forensic receipts** -- a
//! `tunnel_receipts` table appended to, under the same connection lock, whenever a
//! session row is opened or closed and, hourly, when an open session's byte counters
//! moved. Each receipt is hash-chained to the previous one and ed25519-signed with the
//! edge's dedicated receipts key ([`crate::receipts`]); the chain head (last seq + hash)
//! lives in `tunnel_receipts_head` so retention pruning of old receipts never resets the
//! sequence. What a receipt proves, its exact JSON shape and the canonical form the
//! hash covers are documented once, on `ct_common::receipt`. Receipts are metadata only,
//! like the session rows they attest, and carry the routing token only as a SHA-256.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ct_common::receipt::{self, Receipt, ReceiptSigner};
use ct_common::sync::MutexExt;
use ct_common::RoutingToken;
use rusqlite::{params, Connection, OptionalExtension};

use crate::sqlite_util::open_tuned;
use serde::{Deserialize, Serialize};

use crate::shutdown::ShutdownSignal;
use crate::state::EdgeState;

/// Transport label recorded for a session opened by a QUIC registration.
pub const TRANSPORT_QUIC: &str = "quic";
/// Transport label recorded for a session opened by a TLS-TCP fallback park.
pub const TRANSPORT_TCP_FALLBACK: &str = "tcp-fallback";

/// Default file name, placed beside the persisted CA key.
pub const DEFAULT_FILE_NAME: &str = "tunnel-history.sqlite";
/// `CT_EDGE_TUNNEL_IDLE_EVICT_SECS` default: a token with no live registration and no
/// activity for a day is dropped from the in-memory maps (its history is on disk).
pub const DEFAULT_IDLE_EVICT_SECS: u64 = 24 * 60 * 60;
/// `CT_EDGE_TUNNEL_HISTORY_RETENTION_SECS` default: closed sessions are kept 90 days --
/// the longest window the owner-facing uptime summary reports is 30 days, and a
/// quarter's worth of receipts is the longest lookback the feature program names.
pub const DEFAULT_RETENTION_SECS: i64 = 90 * 24 * 60 * 60;
/// How often the flush loop writes byte deltas and runs the in-memory eviction.
const FLUSH_INTERVAL_SECS: u64 = 60;
/// Retention prune cadence, in flush ticks (60 x 60 s = hourly).
const PRUNE_EVERY_TICKS: u64 = 60;

const WINDOW_24H: i64 = 24 * 60 * 60;
const WINDOW_7D: i64 = 7 * WINDOW_24H;
const WINDOW_30D: i64 = 30 * WINDOW_24H;

/// One `tunnel_sessions` row as disclosed over the admin API. `bytes_in` is the
/// client->agent direction, `bytes_out` agent->client -- the same split as
/// `EdgeState::tunnel_bytes` / the tunnel-status route's `bytes_received`/`bytes_sent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRow {
    pub transport: String,
    pub connected_at: i64,
    pub disconnected_at: Option<i64>,
    pub reason: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Uptime percentages (`0.0..=100.0`) over the trailing 24 h / 7 d / 30 d, computed from
/// how much of each window the token's sessions cover (see [`uptime_percent`]).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct UptimeSummary {
    pub h24: f64,
    pub d7: f64,
    pub d30: f64,
}

/// #782: the admin route's page cap for `receipts_for`.
pub const RECEIPTS_MAX_LIMIT: usize = 1000;

/// SQLite-backed per-tunnel session history. See the module doc for scope/rationale.
pub struct SqliteTunnelHistory {
    conn: Mutex<Connection>,
    /// #782: receipt signing state; `None` when receipts are disabled (no signer was
    /// installed via [`with_receipts`](Self::with_receipts)). Its own mutexes are only
    /// ever taken while the `conn` guard is held (lock order: `conn`, then these), so
    /// emission is serialized with the row write it attests and seqs never interleave.
    receipts: Option<ReceiptEmitter>,
}

/// #782: the signer plus the in-memory chain head and the per-session byte high-water
/// marks the hourly snapshot compares against.
struct ReceiptEmitter {
    signer: ReceiptSigner,
    /// `(last seq, last hash hex)`; `(0, GENESIS_PREV_HASH)` before the first receipt.
    head: Mutex<(u64, String)>,
    /// Open session row id -> the `(bytes_in, bytes_out)` the last `bytes` receipt
    /// carried, so a snapshot is only emitted when the counters actually moved. Entries
    /// are dropped on close; a restart starts empty (every open row is closed at boot
    /// anyway, see [`close_stale_open_sessions`](SqliteTunnelHistory::close_stale_open_sessions)).
    snapshots: Mutex<HashMap<i64, (u64, u64)>>,
}

impl SqliteTunnelHistory {
    /// Open (creating if needed) a durable store at `path` on a tuned WAL connection.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        Self::from_connection(open_tuned(path)?)
    }

    /// Open an ephemeral in-memory store (tests, and the fallback when the configured
    /// path is not writable -- see [`open_with_fallback`]).
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS tunnel_sessions (
                 id              INTEGER PRIMARY KEY,
                 routing_token   TEXT NOT NULL,
                 transport       TEXT NOT NULL,
                 connected_at    INTEGER NOT NULL,
                 disconnected_at INTEGER,
                 reason          TEXT,
                 bytes_in        INTEGER NOT NULL DEFAULT 0,
                 bytes_out       INTEGER NOT NULL DEFAULT 0,
                 last_flush      INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_tunnel_sessions_token_connected
                 ON tunnel_sessions (routing_token, connected_at);
             CREATE INDEX IF NOT EXISTS idx_tunnel_sessions_disconnected
                 ON tunnel_sessions (disconnected_at);
             CREATE TABLE IF NOT EXISTS tunnel_receipts (
                 seq                INTEGER PRIMARY KEY,
                 prev_hash          TEXT NOT NULL,
                 ts                 INTEGER NOT NULL,
                 edge_id            TEXT NOT NULL,
                 kind               TEXT NOT NULL,
                 routing_token_hash TEXT NOT NULL,
                 payload            TEXT NOT NULL,
                 hash               TEXT NOT NULL,
                 sig                TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_tunnel_receipts_token_seq
                 ON tunnel_receipts (routing_token_hash, seq);
             CREATE INDEX IF NOT EXISTS idx_tunnel_receipts_ts
                 ON tunnel_receipts (ts);
             CREATE TABLE IF NOT EXISTS tunnel_receipts_head (
                 id        INTEGER PRIMARY KEY CHECK (id = 1),
                 last_seq  INTEGER NOT NULL,
                 last_hash TEXT NOT NULL
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
            receipts: None,
        })
    }

    /// #782: install the receipts signer, resuming the chain from the persisted head
    /// (`tunnel_receipts_head`; genesis when the table is empty). Every open/close from
    /// here on appends a signed receipt. Consumes and returns `self` so the store cannot
    /// be shared before its chain state is loaded.
    pub fn with_receipts(mut self, signer: ReceiptSigner) -> rusqlite::Result<Self> {
        self.install_receipts(signer)?;
        Ok(self)
    }

    /// [`with_receipts`](Self::with_receipts) in place: on `Err` the store is unchanged
    /// (no signer installed), so the caller can keep using it without receipts.
    pub fn install_receipts(&mut self, signer: ReceiptSigner) -> rusqlite::Result<()> {
        let head: Option<(i64, String)> = self
            .conn
            .lock_safe()
            .query_row("SELECT last_seq, last_hash FROM tunnel_receipts_head WHERE id = 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        let head = match head {
            Some((seq, hash)) => (seq.max(0) as u64, hash),
            None => (0, receipt::GENESIS_PREV_HASH.to_string()),
        };
        self.receipts = Some(ReceiptEmitter {
            signer,
            head: Mutex::new(head),
            snapshots: Mutex::new(HashMap::new()),
        });
        Ok(())
    }

    /// #782: whether a signer is installed (the admin routes answer 404 otherwise).
    pub fn receipts_enabled(&self) -> bool {
        self.receipts.is_some()
    }

    /// #782: the receipts public key (64 hex) when signing is enabled.
    pub fn receipts_pubkey_hex(&self) -> Option<String> {
        self.receipts.as_ref().map(|r| r.signer.pubkey_hex())
    }

    /// #782: the `edge_id` every receipt carries, when signing is enabled.
    pub fn receipts_edge_id(&self) -> Option<&str> {
        self.receipts.as_ref().map(|r| r.signer.edge_id())
    }

    /// #782: the chain head `(last seq, last hash)` -- `(0, genesis)` before the first
    /// receipt; `None` when signing is disabled.
    pub fn receipts_head(&self) -> Option<(u64, String)> {
        let _conn = self.conn.lock_safe();
        self.receipts.as_ref().map(|r| r.head.lock_safe().clone())
    }

    /// #782: append one signed receipt for `token_hex` (the caller holds the `conn`
    /// guard; the receipt row and the head update commit in one transaction so a crash
    /// between them cannot fork the chain). No-op when signing is disabled. A store
    /// error here is returned to the caller, which logs it and keeps the session row --
    /// a missed receipt is visible later as a seq gap, a lost session row is not.
    fn emit(
        &self,
        conn: &Connection,
        ts: i64,
        kind: &str,
        token_hex: &str,
        payload: serde_json::Value,
    ) -> rusqlite::Result<()> {
        let Some(em) = &self.receipts else {
            return Ok(());
        };
        let token_hash = routing_token_hash_of_hex(token_hex);
        let mut head = em.head.lock_safe();
        let seq = head.0 + 1;
        let r = em.signer.sign(seq, &head.1, ts, kind, &token_hash, payload);
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO tunnel_receipts (seq, prev_hash, ts, edge_id, kind, routing_token_hash, payload, hash, sig)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                clamp_i64(r.seq),
                r.prev_hash,
                r.ts,
                r.edge_id,
                r.kind,
                r.routing_token_hash,
                receipt::canonical_json(&r.payload),
                r.hash,
                r.sig,
            ],
        )?;
        tx.execute(
            "INSERT INTO tunnel_receipts_head (id, last_seq, last_hash) VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET last_seq = excluded.last_seq, last_hash = excluded.last_hash",
            params![clamp_i64(r.seq), r.hash],
        )?;
        tx.commit()?;
        *head = (r.seq, r.hash);
        Ok(())
    }

    /// #782: receipts for the token whose SHA-256 is `token_hash`, ascending by `seq`,
    /// strictly after `since_seq` (`0` = from the oldest retained), at most `limit`
    /// (capped at [`RECEIPTS_MAX_LIMIT`]). Empty for an unknown token or when signing
    /// is disabled.
    pub fn receipts_for(&self, token_hash: &str, since_seq: u64, limit: usize) -> rusqlite::Result<Vec<Receipt>> {
        if self.receipts.is_none() {
            return Ok(Vec::new());
        }
        let conn = self.conn.lock_safe();
        let mut stmt = conn.prepare(
            "SELECT seq, prev_hash, ts, edge_id, kind, routing_token_hash, payload, hash, sig
             FROM tunnel_receipts WHERE routing_token_hash = ?1 AND seq > ?2
             ORDER BY seq ASC LIMIT ?3",
        )?;
        let limit = clamp_i64(limit.clamp(1, RECEIPTS_MAX_LIMIT) as u64);
        let rows = stmt.query_map(params![token_hash, clamp_i64(since_seq), limit], |r| {
            let payload_text: String = r.get(6)?;
            let payload = serde_json::from_str(&payload_text).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(e))
            })?;
            Ok(Receipt {
                seq: r.get::<_, i64>(0)?.max(0) as u64,
                prev_hash: r.get(1)?,
                ts: r.get(2)?,
                edge_id: r.get(3)?,
                kind: r.get(4)?,
                routing_token_hash: r.get(5)?,
                payload,
                hash: r.get(7)?,
                sig: r.get(8)?,
            })
        })?;
        rows.collect()
    }

    /// #782: the hourly `bytes` snapshot -- one receipt per OPEN session whose
    /// `(bytes_in, bytes_out)` moved since its last snapshot (or since it opened),
    /// carrying the cumulative counters. Called from the flush loop AFTER the byte
    /// deltas were written into the rows, so the receipt attests what the row says.
    /// Returns how many were emitted; `0` when signing is disabled.
    pub fn emit_bytes_snapshots(&self, now: i64) -> rusqlite::Result<usize> {
        let Some(em) = &self.receipts else {
            return Ok(0);
        };
        let conn = self.conn.lock_safe();
        let open: Vec<(i64, String, i64, u64, u64)> = {
            let mut stmt = conn.prepare(
                "SELECT id, routing_token, connected_at, bytes_in, bytes_out FROM tunnel_sessions
                 WHERE disconnected_at IS NULL ORDER BY id",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get::<_, i64>(3)?.max(0) as u64,
                    r.get::<_, i64>(4)?.max(0) as u64,
                ))
            })?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let mut emitted = 0usize;
        for (id, token_hex, connected_at, bytes_in, bytes_out) in open {
            let last = em.snapshots.lock_safe().get(&id).copied().unwrap_or((0, 0));
            if last == (bytes_in, bytes_out) {
                continue;
            }
            self.emit(
                &conn,
                now,
                receipt::KIND_BYTES,
                &token_hex,
                serde_json::json!({ "bytes_in": bytes_in, "bytes_out": bytes_out, "connected_at": connected_at }),
            )?;
            em.snapshots.lock_safe().insert(id, (bytes_in, bytes_out));
            emitted += 1;
        }
        Ok(emitted)
    }

    /// #782: delete receipts with `ts` before `cutoff` (the same window as the session
    /// rows). The chain head is untouched, so the next receipt still continues the
    /// sequence; an export after pruning simply starts mid-chain (its verifier accepts
    /// that -- see `ct_common::receipt`). Returns the count removed.
    pub fn prune_receipts_older_than(&self, cutoff: i64) -> rusqlite::Result<usize> {
        self.conn.lock_safe().execute("DELETE FROM tunnel_receipts WHERE ts < ?1", params![cutoff])
    }

    /// #782: forget a closed session's snapshot high-water mark.
    fn forget_snapshot(&self, id: i64) {
        if let Some(em) = &self.receipts {
            em.snapshots.lock_safe().remove(&id);
        }
    }

    /// Open a session for `token_hex` at `now` and return its row id. **One open session
    /// per token at a time**: if an open row already exists it is returned instead of
    /// opening a second, with its `transport` updated to the caller's (a tunnel can move
    /// between QUIC and the TCP fallback mid-streak; the row records the latest).
    pub fn open_session(&self, token_hex: &str, transport: &str, now: i64) -> rusqlite::Result<i64> {
        let conn = self.conn.lock_safe();
        let existing: Option<(i64, String)> = conn
            .query_row(
                "SELECT id, transport FROM tunnel_sessions
                 WHERE routing_token = ?1 AND disconnected_at IS NULL ORDER BY id DESC LIMIT 1",
                params![token_hex],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((id, current)) = existing {
            // Only touch the row when the transport actually changed: a re-parking
            // TCP-fallback pool calls this on every park, so the common case is a
            // single indexed SELECT with no write.
            if current != transport {
                conn.execute(
                    "UPDATE tunnel_sessions SET transport = ?1 WHERE id = ?2",
                    params![transport, id],
                )?;
            }
            return Ok(id);
        }
        conn.execute(
            "INSERT INTO tunnel_sessions (routing_token, transport, connected_at, last_flush)
             VALUES (?1, ?2, ?3, ?3)",
            params![token_hex, transport, now],
        )?;
        let id = conn.last_insert_rowid();
        // #782: attest the new streak. Only here, not on the reuse path above: a
        // re-park or transport switch is not a new session.
        self.emit(
            &conn,
            now,
            receipt::KIND_SESSION_OPEN,
            token_hex,
            serde_json::json!({ "connected_at": now, "transport": transport }),
        )?;
        Ok(id)
    }

    /// Close the open session for `token_hex` (if any) at `now` with `reason`. Returns
    /// whether a row was actually closed -- `false` when none was open, which is a normal
    /// outcome for a teardown of a token that never opened one.
    ///
    /// #782: every row closed here gets a `session_close` receipt carrying the row's
    /// final counters (the caller flushes the last byte delta first -- see
    /// `EdgeState::close_tunnel_session`), so the receipt and the row agree.
    pub fn close_session(&self, token_hex: &str, now: i64, reason: &str) -> rusqlite::Result<bool> {
        let conn = self.conn.lock_safe();
        let open = open_rows(&conn, Some(token_hex))?;
        if open.is_empty() {
            return Ok(false);
        }
        conn.execute(
            "UPDATE tunnel_sessions SET disconnected_at = ?1, reason = ?2, last_flush = ?1
             WHERE routing_token = ?3 AND disconnected_at IS NULL",
            params![now, reason, token_hex],
        )?;
        for row in open {
            self.emit_close(&conn, &row, now, reason)?;
        }
        Ok(true)
    }

    /// #782: the `session_close` receipt for one just-closed row.
    fn emit_close(&self, conn: &Connection, row: &OpenRow, now: i64, reason: &str) -> rusqlite::Result<()> {
        self.emit(
            conn,
            now,
            receipt::KIND_SESSION_CLOSE,
            &row.token_hex,
            serde_json::json!({
                "bytes_in": row.bytes_in,
                "bytes_out": row.bytes_out,
                "connected_at": row.connected_at,
                "disconnected_at": now,
                "reason": reason,
            }),
        )?;
        self.forget_snapshot(row.id);
        Ok(())
    }

    /// Add byte deltas to the open session for `token_hex`. No-op (returns `false`) when
    /// none is open -- bytes relayed while no session is open belong to no row.
    pub fn add_session_bytes(
        &self,
        token_hex: &str,
        delta_in: u64,
        delta_out: u64,
        now: i64,
    ) -> rusqlite::Result<bool> {
        let n = self.conn.lock_safe().execute(
            "UPDATE tunnel_sessions
             SET bytes_in = bytes_in + ?1, bytes_out = bytes_out + ?2, last_flush = ?3
             WHERE routing_token = ?4 AND disconnected_at IS NULL",
            params![clamp_i64(delta_in), clamp_i64(delta_out), now, token_hex],
        )?;
        Ok(n > 0)
    }

    /// The most recent `limit` sessions for `token_hex`, newest first (open one, if any,
    /// first of all since it is the latest by `connected_at`).
    pub fn sessions_for(&self, token_hex: &str, limit: usize) -> rusqlite::Result<Vec<SessionRow>> {
        let conn = self.conn.lock_safe();
        let mut stmt = conn.prepare(
            "SELECT transport, connected_at, disconnected_at, reason, bytes_in, bytes_out
             FROM tunnel_sessions WHERE routing_token = ?1
             ORDER BY connected_at DESC, id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![token_hex, clamp_i64(limit as u64)], |r| {
            Ok(SessionRow {
                transport: r.get(0)?,
                connected_at: r.get(1)?,
                disconnected_at: r.get(2)?,
                reason: r.get(3)?,
                bytes_in: r.get::<_, i64>(4)?.max(0) as u64,
                bytes_out: r.get::<_, i64>(5)?.max(0) as u64,
            })
        })?;
        rows.collect()
    }

    /// Uptime over the trailing 24 h / 7 d / 30 d ending at `now`, from every session that
    /// overlaps the 30-day window (an open session counts up to `now`). Computed in Rust
    /// over at most 30 days of rows -- see [`uptime_percent`] for the math.
    pub fn uptime_summary(&self, token_hex: &str, now: i64) -> rusqlite::Result<UptimeSummary> {
        let conn = self.conn.lock_safe();
        let mut stmt = conn.prepare(
            "SELECT connected_at, disconnected_at FROM tunnel_sessions
             WHERE routing_token = ?1 AND (disconnected_at IS NULL OR disconnected_at >= ?2)",
        )?;
        let spans: Vec<(i64, Option<i64>)> = stmt
            .query_map(params![token_hex, now - WINDOW_30D], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(UptimeSummary {
            h24: uptime_percent(&spans, now, WINDOW_24H),
            d7: uptime_percent(&spans, now, WINDOW_7D),
            d30: uptime_percent(&spans, now, WINDOW_30D),
        })
    }

    /// Delete CLOSED sessions that ended before `cutoff`; open rows are never pruned
    /// (a still-connected tunnel's streak start must survive however old it is). Returns
    /// the count removed.
    pub fn prune_closed_older_than(&self, cutoff: i64) -> rusqlite::Result<usize> {
        self.conn.lock_safe().execute(
            "DELETE FROM tunnel_sessions WHERE disconnected_at IS NOT NULL AND disconnected_at < ?1",
            params![cutoff],
        )
    }

    /// Whether `token_hex` currently has an open session row.
    pub fn open_session_exists(&self, token_hex: &str) -> rusqlite::Result<bool> {
        let id: Option<i64> = self
            .conn
            .lock_safe()
            .query_row(
                "SELECT id FROM tunnel_sessions WHERE routing_token = ?1 AND disconnected_at IS NULL LIMIT 1",
                params![token_hex],
                |r| r.get(0),
            )
            .optional()?;
        Ok(id.is_some())
    }

    /// Boot-time repair: close EVERY open row at `now` with `reason`. A row left open by
    /// the previous process (crash, redeploy -- nothing runs the close paths then) would
    /// otherwise be adopted by [`open_session`](Self::open_session)'s one-open-row rule on
    /// the token's next registration, and the whole restart gap would count as uptime.
    /// Returns how many rows were closed. #782: each gets a `session_close` receipt too
    /// (reason `"edge-restart"`), so the chain records the gap rather than a session
    /// that silently never ended.
    pub fn close_stale_open_sessions(&self, now: i64, reason: &str) -> rusqlite::Result<usize> {
        let conn = self.conn.lock_safe();
        let open = open_rows(&conn, None)?;
        let n = conn.execute(
            "UPDATE tunnel_sessions SET disconnected_at = ?1, reason = ?2, last_flush = ?1
             WHERE disconnected_at IS NULL",
            params![now, reason],
        )?;
        for row in &open {
            self.emit_close(&conn, row, now, reason)?;
        }
        Ok(n)
    }

    #[cfg(test)]
    fn row_count(&self) -> rusqlite::Result<i64> {
        self.conn
            .lock_safe()
            .query_row("SELECT COUNT(*) FROM tunnel_sessions", [], |r| r.get(0))
    }
}

/// #782: what a close receipt needs from the row it closes.
struct OpenRow {
    id: i64,
    token_hex: String,
    connected_at: i64,
    bytes_in: u64,
    bytes_out: u64,
}

/// Every open session row, for one token or (`None`) all of them, oldest first.
fn open_rows(conn: &Connection, token_hex: Option<&str>) -> rusqlite::Result<Vec<OpenRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, routing_token, connected_at, bytes_in, bytes_out FROM tunnel_sessions
         WHERE disconnected_at IS NULL AND (?1 IS NULL OR routing_token = ?1) ORDER BY id",
    )?;
    let rows = stmt.query_map(params![token_hex], |r| {
        Ok(OpenRow {
            id: r.get(0)?,
            token_hex: r.get(1)?,
            connected_at: r.get(2)?,
            bytes_in: r.get::<_, i64>(3)?.max(0) as u64,
            bytes_out: r.get::<_, i64>(4)?.max(0) as u64,
        })
    })?;
    rows.collect()
}

/// #782: `ct_common::receipt::routing_token_hash` over the token the store is keyed by.
/// The store's key is always the lowercase hex `routing_token_hex` produces, so the
/// decode cannot fail for anything the edge wrote itself; a foreign string (a test
/// passing junk) hashes its own bytes rather than aborting the write.
fn routing_token_hash_of_hex(token_hex: &str) -> String {
    match receipt::hex_decode(token_hex) {
        Some(bytes) => receipt::routing_token_hash(&bytes),
        None => receipt::routing_token_hash(token_hex.as_bytes()),
    }
}

/// Percentage (`0.0..=100.0`) of the `window`-second interval ending at `now` that the
/// given `(connected_at, disconnected_at)` spans cover. An open span (`None`) runs to
/// `now`; a span entirely before the window contributes nothing; a span straddling the
/// window's start counts only its overlap. Spans are assumed non-overlapping (the
/// one-open-session-per-token invariant), and the result is clamped regardless.
pub fn uptime_percent(spans: &[(i64, Option<i64>)], now: i64, window: i64) -> f64 {
    if window <= 0 {
        return 0.0;
    }
    let window_start = now - window;
    let mut covered: i64 = 0;
    for &(start, end) in spans {
        let end = end.unwrap_or(now).min(now);
        let overlap = end - start.max(window_start);
        if overlap > 0 {
            covered = covered.saturating_add(overlap);
        }
    }
    let pct = covered as f64 / window as f64 * 100.0;
    pct.clamp(0.0, 100.0)
}

/// Lowercase hex of a routing token -- the key `tunnel_sessions.routing_token` uses, the
/// same encoding `admin.rs`'s routes and `serve::hex_of_bytes` produce.
pub(crate) fn routing_token_hex(token: &RoutingToken) -> String {
    ct_common::hex::encode(&token.0)
}

fn clamp_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Resolve where the history lives from `CT_EDGE_TUNNEL_HISTORY` (`off`/`0`/`false`
/// disables -> `None`), `CT_EDGE_TUNNEL_HISTORY_PATH` (a non-empty value wins), and
/// otherwise [`DEFAULT_FILE_NAME`] in the directory of `ca_key_path` (`edge-ca-key.pem`,
/// the edge's one durable volume). Compose's `"${VAR:-}"` convention hands an unset var
/// to the process as `Some("")`, so empty is treated as absent (same as #603's
/// `audit_log_path_from`).
pub fn resolve_history_path(toggle: Option<&str>, path: Option<&str>, ca_key_path: &str) -> Option<String> {
    if let Some(v) = toggle.map(str::trim) {
        if v == "0" || v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("false") {
            return None;
        }
    }
    if let Some(p) = path.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(p.to_string());
    }
    let ca = std::path::Path::new(ca_key_path);
    Some(match ca.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(DEFAULT_FILE_NAME).to_string_lossy().into_owned(),
        _ => DEFAULT_FILE_NAME.to_string(),
    })
}

/// `CT_EDGE_TUNNEL_IDLE_EVICT_SECS`, defaulting to [`DEFAULT_IDLE_EVICT_SECS`] for
/// unset/empty/non-positive input.
pub fn idle_evict_secs_from(v: Option<&str>) -> u64 {
    v.and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&s| s > 0)
        .unwrap_or(DEFAULT_IDLE_EVICT_SECS)
}

/// `CT_EDGE_TUNNEL_HISTORY_RETENTION_SECS`, defaulting to [`DEFAULT_RETENTION_SECS`] for
/// unset/empty/non-positive input.
pub fn retention_secs_from(v: Option<&str>) -> i64 {
    v.and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|&s| s > 0)
        .unwrap_or(DEFAULT_RETENTION_SECS)
}

/// Open the durable store at `path`, falling back to an in-memory store (with a loud
/// warning: the history then survives only until the next restart) when the file cannot
/// be opened -- a read-only or missing directory is a deployment mistake, not a reason to
/// lose the feature entirely or refuse tunnel service. `None` only if even the in-memory
/// store fails to initialise. The returned flag is `true` for the durable store.
pub fn open_with_fallback(path: &str) -> Option<(SqliteTunnelHistory, bool)> {
    match SqliteTunnelHistory::open(path) {
        Ok(h) => Some((h, true)),
        Err(e) => {
            eprintln!(
                "ct-edge: WARNING — tunnel session history at {path} failed to open ({e}); \
                 falling back to an IN-MEMORY store: session history and uptime will NOT \
                 survive a restart. Fix the volume or set CT_EDGE_TUNNEL_HISTORY_PATH (#776)"
            );
            match SqliteTunnelHistory::open_in_memory() {
                Ok(h) => Some((h, false)),
                Err(e) => {
                    eprintln!("ct-edge: WARNING — in-memory tunnel session history failed too ({e}); disabled (#776)");
                    None
                }
            }
        }
    }
}

/// Current wall-clock time in Unix seconds, `0` on a clock error (the codebase's
/// `SystemTime::now()` convention, e.g. `audit_log.rs::now_secs`).
pub(crate) fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// #776: the periodic flush + eviction task, spawned from `serve::run_edge` next to the
/// audit retention loop. Every 60 s it (a) writes each token's byte delta since the last
/// flush into its open session row, and (b) evicts from the in-memory maps every token
/// with no live registration whose last activity is older than `idle_evict_secs` (both
/// via [`EdgeState::flush_tunnel_history`]); once an hour it also prunes closed sessions
/// older than `retention_secs`, emits the `bytes` receipt snapshot for open sessions
/// whose counters moved (#782), and prunes receipts on the same window. Raced against
/// `shutdown` like `run_audit_retention_loop`.
/// The final byte flush of a session happens on the close paths themselves, not here, so
/// nothing relayed in the last minute of a session is lost to shutdown timing.
pub async fn run_tunnel_history_flush_loop<H: Clone + Send + Sync + 'static>(
    state: Arc<EdgeState<H>>,
    history: Arc<SqliteTunnelHistory>,
    idle_evict_secs: u64,
    retention_secs: i64,
    shutdown: ShutdownSignal,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(FLUSH_INTERVAL_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut ticks: u64 = 0;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tick.tick() => {
                let now = now_secs();
                let (flushed, evicted) = state.flush_tunnel_history(now.max(0) as u64, idle_evict_secs);
                if evicted > 0 {
                    eprintln!(
                        "ct-edge: tunnel history flushed {flushed} token(s), evicted {evicted} idle token(s) \
                         from the in-memory maps (#776)"
                    );
                }
                if ticks % PRUNE_EVERY_TICKS == 0 {
                    let cutoff = now.saturating_sub(retention_secs);
                    match history.prune_closed_older_than(cutoff) {
                        Ok(n) if n > 0 => eprintln!(
                            "ct-edge: tunnel-history retention pruned {n} closed session(s) older than {retention_secs}s (#776)"
                        ),
                        Ok(_) => {}
                        Err(e) => eprintln!("ct-edge: tunnel-history retention sweep failed: {e} (#776)"),
                    }
                    if history.receipts_enabled() {
                        if let Err(e) = history.emit_bytes_snapshots(now) {
                            eprintln!("ct-edge: receipts: hourly bytes snapshot failed: {e} (#782)");
                        }
                        match history.prune_receipts_older_than(cutoff) {
                            Ok(n) if n > 0 => eprintln!("ct-edge: receipts: retention pruned {n} receipt(s) (#782)"),
                            Ok(_) => {}
                            Err(e) => eprintln!("ct-edge: receipts: retention sweep failed: {e} (#782)"),
                        }
                    }
                }
                ticks = ticks.wrapping_add(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> SqliteTunnelHistory {
        SqliteTunnelHistory::open_in_memory().unwrap()
    }

    fn hex(b: u8) -> String {
        format!("{b:02x}").repeat(32)
    }

    /// Mirrors `audit_log.rs`'s `temp_db_path` test helper.
    fn temp_db_path() -> String {
        use rand::RngCore;
        let mut b = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut b);
        let name: String = b.iter().map(|x| format!("{x:02x}")).collect();
        std::env::temp_dir().join(format!("ct_tunnel_history_{name}.db")).to_string_lossy().into_owned()
    }

    #[test]
    fn open_then_close_records_one_session_with_reason_and_timestamps() {
        let s = store();
        let t = hex(0x01);
        let id = s.open_session(&t, TRANSPORT_QUIC, 1_000).unwrap();
        assert!(id > 0);
        assert!(s.open_session_exists(&t).unwrap());
        assert!(s.close_session(&t, 1_500, "removed").unwrap(), "an open row was closed");
        assert!(!s.open_session_exists(&t).unwrap());
        assert_eq!(
            s.sessions_for(&t, 10).unwrap(),
            vec![SessionRow {
                transport: TRANSPORT_QUIC.into(),
                connected_at: 1_000,
                disconnected_at: Some(1_500),
                reason: Some("removed".into()),
                bytes_in: 0,
                bytes_out: 0,
            }]
        );
        // Closing again finds nothing open -- a normal teardown-of-nothing outcome.
        assert!(!s.close_session(&t, 1_600, "removed").unwrap());
    }

    #[test]
    fn one_open_session_per_token_and_transport_follows_the_latest_registration() {
        let s = store();
        let t = hex(0x02);
        let first = s.open_session(&t, TRANSPORT_QUIC, 100).unwrap();
        // A second registration while the first is still open (a redundant agent, a
        // fallback park) must NOT start a second streak -- same row, transport updated.
        let again = s.open_session(&t, TRANSPORT_TCP_FALLBACK, 200).unwrap();
        assert_eq!(first, again, "the open row is reused");
        assert_eq!(s.row_count().unwrap(), 1);
        let rows = s.sessions_for(&t, 10).unwrap();
        assert_eq!(rows[0].transport, TRANSPORT_TCP_FALLBACK);
        assert_eq!(rows[0].connected_at, 100, "the streak start is the FIRST registration's");

        // Once closed, the next open is a genuinely new session.
        s.close_session(&t, 300, "removed").unwrap();
        let third = s.open_session(&t, TRANSPORT_QUIC, 400).unwrap();
        assert_ne!(third, first);
        assert_eq!(s.row_count().unwrap(), 2);

        // A different token is independent.
        let other = hex(0x03);
        assert_ne!(s.open_session(&other, TRANSPORT_QUIC, 400).unwrap(), third);
        assert_eq!(s.row_count().unwrap(), 3);
    }

    #[test]
    fn add_session_bytes_accumulates_into_the_open_row_and_is_a_noop_without_one() {
        let s = store();
        let t = hex(0x04);
        assert!(!s.add_session_bytes(&t, 10, 20, 50).unwrap(), "no open session -> no-op");
        assert_eq!(s.row_count().unwrap(), 0, "and no row is fabricated");

        s.open_session(&t, TRANSPORT_QUIC, 100).unwrap();
        assert!(s.add_session_bytes(&t, 100, 40, 160).unwrap());
        assert!(s.add_session_bytes(&t, 25, 5, 220).unwrap());
        s.close_session(&t, 300, "removed").unwrap();
        let row = &s.sessions_for(&t, 1).unwrap()[0];
        assert_eq!((row.bytes_in, row.bytes_out), (125, 45), "deltas accumulate");

        // Bytes after the close belong to no session.
        assert!(!s.add_session_bytes(&t, 1, 1, 400).unwrap());
        let row = &s.sessions_for(&t, 1).unwrap()[0];
        assert_eq!((row.bytes_in, row.bytes_out), (125, 45));
    }

    #[test]
    fn sessions_for_is_newest_first_and_honours_the_limit() {
        let s = store();
        let t = hex(0x05);
        for (start, end) in [(100, 200), (300, 400), (500, 600)] {
            s.open_session(&t, TRANSPORT_QUIC, start).unwrap();
            s.close_session(&t, end, "registration-closed").unwrap();
        }
        s.open_session(&t, TRANSPORT_TCP_FALLBACK, 700).unwrap(); // still open
        let rows = s.sessions_for(&t, 10).unwrap();
        let starts: Vec<i64> = rows.iter().map(|r| r.connected_at).collect();
        assert_eq!(starts, vec![700, 500, 300, 100]);
        assert_eq!(rows[0].disconnected_at, None, "the open one leads");
        assert_eq!(s.sessions_for(&t, 2).unwrap().len(), 2);
        assert!(s.sessions_for(&hex(0x06), 10).unwrap().is_empty(), "unknown token -> empty, not an error");
    }

    #[test]
    fn uptime_percent_math() {
        let now = 1_000_000;
        let day = WINDOW_24H;
        // A 12 h session fully inside the last 24 h -> 50 %.
        assert_eq!(uptime_percent(&[(now - 18 * 3600, Some(now - 6 * 3600))], now, day), 50.0);
        // An OPEN session counts up to `now`: opened 6 h ago -> 25 %.
        assert_eq!(uptime_percent(&[(now - 6 * 3600, None)], now, day), 25.0);
        // A session entirely before the window contributes nothing.
        assert_eq!(uptime_percent(&[(now - 3 * day, Some(now - 2 * day))], now, day), 0.0);
        // A session straddling the window start counts only its overlap: ended 18 h ago,
        // started long before -> 6 h of the 24 h window -> 25 %.
        assert_eq!(uptime_percent(&[(now - 3 * day, Some(now - 18 * 3600))], now, day), 25.0);
        // Several sessions add up; a session covering the whole window is 100 %, and the
        // result never exceeds it even if spans overlap.
        assert_eq!(
            uptime_percent(&[(now - 24 * 3600, Some(now - 12 * 3600)), (now - 12 * 3600, None)], now, day),
            100.0
        );
        assert_eq!(uptime_percent(&[(now - 2 * day, None), (now - day, None)], now, day), 100.0);
        // No sessions -> 0 %; a degenerate window -> 0 %, not a division by zero.
        assert_eq!(uptime_percent(&[], now, day), 0.0);
        assert_eq!(uptime_percent(&[(now - 10, None)], now, 0), 0.0);
        // A disconnected_at in the future (clock skew) is capped at `now`.
        assert_eq!(uptime_percent(&[(now - 12 * 3600, Some(now + 3600))], now, day), 50.0);
    }

    #[test]
    fn uptime_summary_reads_the_three_windows_from_the_rows() {
        let s = store();
        let t = hex(0x07);
        let now: i64 = 2_000_000_000;
        // 12 h, closed, inside the last 24 h.
        s.open_session(&t, TRANSPORT_QUIC, now - 18 * 3600).unwrap();
        s.close_session(&t, now - 6 * 3600, "removed").unwrap();
        // A 3-day session that ended 2 days ago: inside 7 d and 30 d, outside 24 h.
        s.open_session(&t, TRANSPORT_QUIC, now - 5 * WINDOW_24H).unwrap();
        s.close_session(&t, now - 2 * WINDOW_24H, "removed").unwrap();
        // A session that ended 40 days ago: outside every window, not even fetched.
        s.open_session(&t, TRANSPORT_QUIC, now - 45 * WINDOW_24H).unwrap();
        s.close_session(&t, now - 40 * WINDOW_24H, "removed").unwrap();

        let u = s.uptime_summary(&t, now).unwrap();
        assert_eq!(u.h24, 50.0);
        let expect_7d = (12.0 * 3600.0 + 3.0 * WINDOW_24H as f64) / WINDOW_7D as f64 * 100.0;
        assert!((u.d7 - expect_7d).abs() < 1e-9, "{} vs {expect_7d}", u.d7);
        let expect_30d = (12.0 * 3600.0 + 3.0 * WINDOW_24H as f64) / WINDOW_30D as f64 * 100.0;
        assert!((u.d30 - expect_30d).abs() < 1e-9, "{} vs {expect_30d}", u.d30);

        // An unknown token is 0/0/0, not an error.
        let z = s.uptime_summary(&hex(0x08), now).unwrap();
        assert_eq!((z.h24, z.d7, z.d30), (0.0, 0.0, 0.0));
    }

    #[test]
    fn prune_removes_only_closed_rows_older_than_the_cutoff_and_keeps_open_ones() {
        let s = store();
        let old = hex(0x09);
        s.open_session(&old, TRANSPORT_QUIC, 100).unwrap();
        s.close_session(&old, 200, "removed").unwrap();
        let recent = hex(0x0a);
        s.open_session(&recent, TRANSPORT_QUIC, 900).unwrap();
        s.close_session(&recent, 950, "removed").unwrap();
        let ancient_but_open = hex(0x0b);
        s.open_session(&ancient_but_open, TRANSPORT_QUIC, 1).unwrap();

        assert_eq!(s.prune_closed_older_than(500).unwrap(), 1, "exactly the old closed row");
        assert_eq!(s.row_count().unwrap(), 2);
        assert!(s.open_session_exists(&ancient_but_open).unwrap(), "an open row is never pruned");
        assert_eq!(s.sessions_for(&recent, 1).unwrap().len(), 1);
        assert_eq!(s.prune_closed_older_than(500).unwrap(), 0, "idempotent");
    }

    #[test]
    fn close_stale_open_sessions_closes_every_open_row_for_a_restart() {
        let s = store();
        s.open_session(&hex(0x0c), TRANSPORT_QUIC, 100).unwrap();
        s.open_session(&hex(0x0d), TRANSPORT_TCP_FALLBACK, 150).unwrap();
        s.open_session(&hex(0x0e), TRANSPORT_QUIC, 50).unwrap();
        s.close_session(&hex(0x0e), 80, "removed").unwrap();
        assert_eq!(s.close_stale_open_sessions(500, "edge-restart").unwrap(), 2);
        assert!(!s.open_session_exists(&hex(0x0c)).unwrap());
        let row = &s.sessions_for(&hex(0x0d), 1).unwrap()[0];
        assert_eq!((row.disconnected_at, row.reason.as_deref()), (Some(500), Some("edge-restart")));
        // The already-closed row keeps its own reason.
        let row = &s.sessions_for(&hex(0x0e), 1).unwrap()[0];
        assert_eq!((row.disconnected_at, row.reason.as_deref()), (Some(80), Some("removed")));
        // And the next registration after the restart starts a NEW session.
        let id = s.open_session(&hex(0x0c), TRANSPORT_QUIC, 600).unwrap();
        assert_eq!(s.sessions_for(&hex(0x0c), 10).unwrap().len(), 2);
        assert!(id > 0);
    }

    #[test]
    fn resolve_history_path_toggle_override_and_default_beside_the_ca_key() {
        let ca = "/shared/edge-ca-key.pem";
        assert_eq!(resolve_history_path(None, None, ca), Some("/shared/tunnel-history.sqlite".into()));
        assert_eq!(resolve_history_path(Some(""), Some(""), ca), Some("/shared/tunnel-history.sqlite".into()));
        assert_eq!(resolve_history_path(Some("on"), None, ca), Some("/shared/tunnel-history.sqlite".into()));
        assert_eq!(resolve_history_path(None, Some(" /data/h.sqlite "), ca), Some("/data/h.sqlite".into()));
        for off in ["off", "OFF", "0", "false"] {
            assert_eq!(resolve_history_path(Some(off), Some("/data/h.sqlite"), ca), None, "{off}");
        }
        // A bare cert file name (no directory) -> a bare default file name.
        assert_eq!(resolve_history_path(None, None, "edge-ca-key.pem"), Some(DEFAULT_FILE_NAME.into()));
    }

    #[test]
    fn env_seconds_parsers_default_on_unset_empty_or_nonpositive() {
        assert_eq!(idle_evict_secs_from(None), DEFAULT_IDLE_EVICT_SECS);
        assert_eq!(idle_evict_secs_from(Some("")), DEFAULT_IDLE_EVICT_SECS);
        assert_eq!(idle_evict_secs_from(Some("0")), DEFAULT_IDLE_EVICT_SECS);
        assert_eq!(idle_evict_secs_from(Some("x")), DEFAULT_IDLE_EVICT_SECS);
        assert_eq!(idle_evict_secs_from(Some(" 3600 ")), 3_600);
        assert_eq!(retention_secs_from(None), DEFAULT_RETENTION_SECS);
        assert_eq!(retention_secs_from(Some("-1")), DEFAULT_RETENTION_SECS);
        assert_eq!(retention_secs_from(Some("86400")), 86_400);
    }

    #[test]
    fn routing_token_hex_is_lowercase_64_chars() {
        let h = routing_token_hex(&RoutingToken([0xab; 32]));
        assert_eq!(h, "ab".repeat(32));
    }

    #[cfg(unix)]
    #[test]
    fn open_restricts_the_file_and_its_wal_shm_sidecars_to_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_db_path();
        let s = SqliteTunnelHistory::open(&path).unwrap();
        s.open_session(&hex(0x0f), TRANSPORT_QUIC, 1).unwrap();
        let mode = |p: &str| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600, "main db file must be owner-only");
        for suffix in ["-wal", "-shm"] {
            let sidecar = format!("{path}{suffix}");
            if std::path::Path::new(&sidecar).exists() {
                assert_eq!(mode(&sidecar), 0o600, "{sidecar} must be owner-only too");
            }
        }
        drop(s);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    #[test]
    fn open_with_fallback_degrades_to_in_memory_when_the_path_is_unusable() {
        let (h, durable) = open_with_fallback("/nonexistent-dir-776/sub/tunnel-history.sqlite").expect("in-memory fallback");
        assert!(!durable);
        h.open_session(&hex(0x10), TRANSPORT_QUIC, 1).unwrap();
        assert!(h.open_session_exists(&hex(0x10)).unwrap());
    }

    // ----- #782 receipts -----

    fn signer() -> ReceiptSigner {
        ReceiptSigner::from_seed(&[0x51u8; 32], "edge-test")
    }

    fn receipts_store() -> SqliteTunnelHistory {
        store().with_receipts(signer()).unwrap()
    }

    fn token_hash(b: u8) -> String {
        receipt::routing_token_hash(&[b; 32])
    }

    #[test]
    fn open_and_close_emit_linked_signed_receipts_that_verify_782() {
        let s = receipts_store();
        assert!(s.receipts_enabled());
        assert_eq!(s.receipts_head(), Some((0, receipt::GENESIS_PREV_HASH.to_string())));
        assert_eq!(s.receipts_pubkey_hex().as_deref(), Some(signer().pubkey_hex().as_str()));
        assert_eq!(s.receipts_edge_id(), Some("edge-test"));

        let t = hex(0x21);
        s.open_session(&t, TRANSPORT_QUIC, 1_000).unwrap();
        // A re-park / transport switch reuses the row and emits NOTHING.
        s.open_session(&t, TRANSPORT_TCP_FALLBACK, 1_100).unwrap();
        s.add_session_bytes(&t, 300, 40, 1_200).unwrap();
        s.close_session(&t, 1_500, "removed").unwrap();
        // Closing nothing emits nothing.
        assert!(!s.close_session(&t, 1_600, "removed").unwrap());

        let rs = s.receipts_for(&token_hash(0x21), 0, 100).unwrap();
        assert_eq!(rs.len(), 2, "one open, one close: {rs:?}");
        assert_eq!((rs[0].seq, rs[0].kind.as_str()), (1, receipt::KIND_SESSION_OPEN));
        assert_eq!(rs[0].prev_hash, receipt::GENESIS_PREV_HASH);
        assert_eq!(rs[0].payload, serde_json::json!({ "connected_at": 1_000, "transport": "quic" }));
        assert_eq!((rs[1].seq, rs[1].kind.as_str()), (2, receipt::KIND_SESSION_CLOSE));
        assert_eq!(rs[1].prev_hash, rs[0].hash, "chained");
        assert_eq!(
            rs[1].payload,
            serde_json::json!({
                "bytes_in": 300, "bytes_out": 40, "connected_at": 1_000, "disconnected_at": 1_500, "reason": "removed"
            })
        );
        assert_eq!(rs[1].ts, 1_500);
        assert_eq!(rs[1].edge_id, "edge-test");
        assert!(!rs.iter().any(|r| r.routing_token_hash == t), "the token itself never appears");
        let summary = receipt::verify_chain(&rs, &signer().pubkey_bytes()).expect("the store's chain verifies");
        assert_eq!((summary.sessions_opened, summary.sessions_closed, summary.bytes_in), (1, 1, 300));
        assert_eq!(s.receipts_head(), Some((2, rs[1].hash.clone())));

        // Another token's receipts continue the SAME per-edge chain but are listed apart.
        let other = hex(0x22);
        s.open_session(&other, TRANSPORT_QUIC, 2_000).unwrap();
        let rs_other = s.receipts_for(&token_hash(0x22), 0, 100).unwrap();
        assert_eq!(rs_other.len(), 1);
        assert_eq!(rs_other[0].seq, 3);
        assert_eq!(rs_other[0].prev_hash, rs[1].hash, "one chain per edge, across tokens");
        assert_eq!(s.receipts_for(&token_hash(0x21), 0, 100).unwrap().len(), 2, "unchanged");
        assert!(s.receipts_for(&token_hash(0x23), 0, 100).unwrap().is_empty(), "unknown token -> empty");
    }

    #[test]
    fn receipts_for_paginates_ascending_with_since_and_limit_782() {
        let s = receipts_store();
        let t = hex(0x24);
        for i in 0..5 {
            s.open_session(&t, TRANSPORT_QUIC, 100 * i).unwrap();
            s.close_session(&t, 100 * i + 50, "removed").unwrap();
        }
        let all = s.receipts_for(&token_hash(0x24), 0, 1000).unwrap();
        let seqs: Vec<u64> = all.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, (1..=10).collect::<Vec<_>>());
        let page = s.receipts_for(&token_hash(0x24), 0, 3).unwrap();
        assert_eq!(page.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2, 3]);
        let next = s.receipts_for(&token_hash(0x24), 3, 3).unwrap();
        assert_eq!(next.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![4, 5, 6], "`since` is exclusive");
        assert!(s.receipts_for(&token_hash(0x24), 10, 3).unwrap().is_empty());
        // A page verifies on its own (mid-chain start is accepted).
        receipt::verify_chain(&next, &signer().pubkey_bytes()).unwrap();
        // limit 0 is treated as 1, and the cap holds.
        assert_eq!(s.receipts_for(&token_hash(0x24), 0, 0).unwrap().len(), 1);
        assert_eq!(s.receipts_for(&token_hash(0x24), 0, usize::MAX).unwrap().len(), 10);
    }

    #[test]
    fn hourly_bytes_snapshot_is_emitted_only_for_open_sessions_whose_counters_moved_782() {
        let s = receipts_store();
        let a = hex(0x25);
        let b = hex(0x26);
        s.open_session(&a, TRANSPORT_QUIC, 100).unwrap();
        s.open_session(&b, TRANSPORT_QUIC, 100).unwrap();
        // Nothing relayed yet -> nothing to attest.
        assert_eq!(s.emit_bytes_snapshots(3_700).unwrap(), 0);
        s.add_session_bytes(&a, 10, 20, 200).unwrap();
        assert_eq!(s.emit_bytes_snapshots(3_800).unwrap(), 1, "only `a` moved");
        assert_eq!(s.emit_bytes_snapshots(3_900).unwrap(), 0, "unchanged -> no duplicate");
        s.add_session_bytes(&a, 1, 0, 4_000).unwrap();
        s.add_session_bytes(&b, 0, 5, 4_000).unwrap();
        assert_eq!(s.emit_bytes_snapshots(7_400).unwrap(), 2);
        let ra = s.receipts_for(&token_hash(0x25), 0, 100).unwrap();
        let kinds: Vec<&str> = ra.iter().map(|r| r.kind.as_str()).collect();
        assert_eq!(kinds, vec![receipt::KIND_SESSION_OPEN, receipt::KIND_BYTES, receipt::KIND_BYTES]);
        assert_eq!(ra[1].payload, serde_json::json!({ "bytes_in": 10, "bytes_out": 20, "connected_at": 100 }));
        assert_eq!(ra[2].payload, serde_json::json!({ "bytes_in": 11, "bytes_out": 20, "connected_at": 100 }));
        // A closed session is never snapshotted again, and its close carries the totals.
        s.close_session(&a, 8_000, "removed").unwrap();
        s.add_session_bytes(&a, 100, 100, 8_100).unwrap(); // no open row -> dropped
        assert_eq!(s.emit_bytes_snapshots(11_000).unwrap(), 0);
        let ra = s.receipts_for(&token_hash(0x25), 0, 100).unwrap();
        assert_eq!(ra.last().unwrap().kind, receipt::KIND_SESSION_CLOSE);
        assert_eq!(ra.last().unwrap().payload["bytes_in"], 11);
        // The whole per-edge chain (both tokens interleaved) still verifies.
        let mut all = s.receipts_for(&token_hash(0x25), 0, 100).unwrap();
        all.extend(s.receipts_for(&token_hash(0x26), 0, 100).unwrap());
        all.sort_by_key(|r| r.seq);
        receipt::verify_chain(&all, &signer().pubkey_bytes()).unwrap();
    }

    #[test]
    fn chain_head_survives_a_restart_and_retention_pruning_782() {
        let path = temp_db_path();
        let last_hash = {
            let s = SqliteTunnelHistory::open(&path).unwrap().with_receipts(signer()).unwrap();
            let t = hex(0x27);
            s.open_session(&t, TRANSPORT_QUIC, 1_000).unwrap();
            s.add_session_bytes(&t, 7, 8, 1_100).unwrap();
            // Left OPEN, as a crash would.
            s.receipts_head().unwrap().1
        };
        let s = SqliteTunnelHistory::open(&path).unwrap().with_receipts(signer()).unwrap();
        assert_eq!(s.receipts_head(), Some((1, last_hash.clone())), "head reloaded from the table");
        // Boot repair closes the stale row WITH a receipt naming the restart.
        assert_eq!(s.close_stale_open_sessions(5_000, "edge-restart").unwrap(), 1);
        let rs = s.receipts_for(&token_hash(0x27), 0, 100).unwrap();
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[1].seq, 2, "continues the sequence");
        assert_eq!(rs[1].prev_hash, last_hash);
        assert_eq!(rs[1].payload["reason"], "edge-restart");
        assert_eq!(rs[1].payload["bytes_in"].as_u64(), Some(7));
        assert_eq!(rs[1].payload["disconnected_at"].as_i64(), Some(5_000));
        receipt::verify_chain(&rs, &signer().pubkey_bytes()).unwrap();

        // Retention drops old receipts but not the head: the next seq is still 3, and the
        // survivor's prev_hash points at a pruned receipt (a mid-chain export).
        assert_eq!(s.prune_receipts_older_than(2_000).unwrap(), 1, "the ts=1000 open receipt");
        assert_eq!(s.prune_receipts_older_than(2_000).unwrap(), 0, "idempotent");
        s.open_session(&hex(0x27), TRANSPORT_QUIC, 6_000).unwrap();
        let rs = s.receipts_for(&token_hash(0x27), 0, 100).unwrap();
        assert_eq!(rs.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![2, 3]);
        let summary = receipt::verify_chain(&rs, &signer().pubkey_bytes()).unwrap();
        assert!(!summary.from_genesis);
        assert_eq!(summary.first_prev_hash.as_deref(), Some(last_hash.as_str()));
        // A different key cannot resume THIS chain's verification.
        let other = ReceiptSigner::from_seed(&[0x52u8; 32], "edge-test");
        assert!(receipt::verify_chain(&rs, &other.pubkey_bytes()).is_err());
        drop(s);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    #[test]
    fn a_store_without_a_signer_records_sessions_but_no_receipts_782() {
        let s = store();
        assert!(!s.receipts_enabled());
        assert_eq!(s.receipts_pubkey_hex(), None);
        assert_eq!(s.receipts_head(), None);
        let t = hex(0x28);
        s.open_session(&t, TRANSPORT_QUIC, 1).unwrap();
        s.close_session(&t, 2, "removed").unwrap();
        assert_eq!(s.emit_bytes_snapshots(3).unwrap(), 0);
        assert!(s.receipts_for(&token_hash(0x28), 0, 100).unwrap().is_empty());
        assert_eq!(s.sessions_for(&t, 10).unwrap().len(), 1, "the session row is still there");
        assert_eq!(s.prune_receipts_older_than(i64::MAX).unwrap(), 0);
    }

    #[tokio::test]
    async fn flush_loop_stops_on_shutdown() {
        let state: Arc<EdgeState<u32>> = Arc::new(EdgeState::new());
        let history = Arc::new(store());
        state.set_tunnel_history(history.clone());
        let (ctl, signal) = crate::shutdown::ShutdownController::new();
        let handle = tokio::spawn(run_tunnel_history_flush_loop(
            state,
            history,
            DEFAULT_IDLE_EVICT_SECS,
            DEFAULT_RETENTION_SECS,
            signal,
        ));
        ctl.trigger();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("flush loop must stop promptly on shutdown")
            .unwrap();
    }
}
