//! Durable, minimal audit log of accepted connections' source IP addresses (#603),
//! for the operator's own evidentiary defense -- proving to law enforcement/abuse
//! investigators that a real client, not the relay's own IP, originated a given
//! relayed session. This is NOT `X-Forwarded-For` to origin servers: most hostnames
//! run in Grün mode (customer's own TLS cert, pure SNI passthrough), where the edge
//! never parses HTTP and structurally cannot inject a header without breaking
//! passthrough; the operator's actual need is a durable record on THIS side, not a
//! header forwarded to the other side.
//!
//! Deliberately "thin metadata" per ADR-0011 (Lawful-Floor-only enforcement) and
//! ADR-0022 (the hosted default's actual identifiability posture): timestamp, source
//! IP, transport, and the routing token or channel+holder already used elsewhere for
//! authorization -- nothing richer (no request paths, headers, or user-agent). Access
//! is host-only (`sqlite3` directly on the box) by design, not a new HTTP endpoint --
//! see the design writeup for why a standing network-reachable admin surface for this
//! data would be inconsistent with ADR-0011's "narrow legal orders only" posture.
//!
//! `crates/edge` has no other disk persistence today -- [`EdgeState`](crate::state::EdgeState)
//! and the channel pairer are pure in-memory, lost on restart. This is the first
//! persistence layer in this process. The SQLite shape (`open`/`open_in_memory`, a
//! plain `Mutex<Connection>` for a write-heavy/rarely-read store) mirrors
//! `crates/control-plane/src/storage.rs`'s established convention (e.g.
//! `SqliteEdgeMesh`); `open_tuned`/the WAL+busy_timeout tuning is duplicated here
//! rather than shared, since edge and control-plane are separate processes with no
//! shared DB file today.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ct_common::sync::MutexExt;
use rusqlite::{params, Connection};

use crate::shutdown::ShutdownSignal;

/// Which accept path recorded a given row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnTransport {
    /// `:443` front door, SNI-passthrough or the EdgeRelay arm.
    FrontDoorTls,
    /// `:4433` TLS-over-TCP fallback.
    TcpFallback,
    /// QUIC, role `'A'` -- an agent registering itself.
    QuicRelayAgent,
    /// QUIC, role `'C'` -- a client/browser rendezvous.
    QuicRelayClient,
    /// The Agent-Fabric channel broker (`:4435`/`:4436`), a member admitted to a
    /// channel (post-handshake, grant verified -- not the pre-handshake raw accept).
    QuicChannel,
}

impl ConnTransport {
    fn as_str(self) -> &'static str {
        match self {
            ConnTransport::FrontDoorTls => "front_door_tls",
            ConnTransport::TcpFallback => "tcp_fallback",
            ConnTransport::QuicRelayAgent => "quic_relay_agent",
            ConnTransport::QuicRelayClient => "quic_relay_client",
            ConnTransport::QuicChannel => "quic_channel",
        }
    }
}

/// SQLite-backed record of which source IP was observed on which accepted
/// connection. See the module doc for scope/rationale.
pub struct SqliteAuditLog {
    conn: Mutex<Connection>,
}

impl SqliteAuditLog {
    /// Open (creating if needed) a durable store at `path` on a tuned WAL connection.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        Self::from_connection(open_tuned(path)?)
    }

    /// Open an ephemeral in-memory store (for tests).
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS conn_audit (
                 id            INTEGER PRIMARY KEY AUTOINCREMENT,
                 ts            INTEGER NOT NULL,
                 transport     TEXT NOT NULL,
                 source_ip     TEXT NOT NULL,
                 routing_token TEXT,
                 channel_id    TEXT,
                 holder_key    TEXT
             );
             CREATE INDEX IF NOT EXISTS idx_conn_audit_ts ON conn_audit (ts);
             CREATE INDEX IF NOT EXISTS idx_conn_audit_token ON conn_audit (routing_token);
             CREATE INDEX IF NOT EXISTS idx_conn_audit_channel ON conn_audit (channel_id);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Record one accepted connection. `token`/`channel`/`holder` are already
    /// hex-encoded by the caller (every call site already has a hex helper for these
    /// -- see `serve::hex_of_bytes` -- so this store stays decoupled from
    /// `ct_common`'s grant/token types).
    pub fn record(
        &self,
        transport: ConnTransport,
        ip: IpAddr,
        now: i64,
        token: Option<&str>,
        channel: Option<&str>,
        holder: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.conn.lock_safe().execute(
            "INSERT INTO conn_audit (ts, transport, source_ip, routing_token, channel_id, holder_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![now, transport.as_str(), ip.to_string(), token, channel, holder],
        )?;
        Ok(())
    }

    /// Delete rows older than `cutoff` (unix seconds); returns the count removed.
    pub fn prune_older_than(&self, cutoff: i64) -> rusqlite::Result<usize> {
        self.conn
            .lock_safe()
            .execute("DELETE FROM conn_audit WHERE ts < ?1", params![cutoff])
    }

    #[cfg(test)]
    fn row_count(&self) -> rusqlite::Result<i64> {
        self.conn
            .lock_safe()
            .query_row("SELECT COUNT(*) FROM conn_audit", [], |r| r.get(0))
    }
}

/// Same WAL + busy_timeout tuning as `crates/control-plane/src/storage.rs`'s
/// `open_tuned`/`tune_connection`, duplicated rather than shared across the crate
/// boundary (see the module doc).
fn open_tuned(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    let _mode: String = conn.query_row("PRAGMA journal_mode=WAL;", [], |row| row.get(0))?;
    conn.busy_timeout(Duration::from_secs(5))?;
    // #608: the module doc's "Access is host-only (`sqlite3` directly on the box) by
    // design" claim is only true if the FILE actually enforces that -- `Connection::
    // open` creates it with the process's default umask (typically 0644, world-
    // readable), which any other local account on the host could then read directly,
    // bypassing every access control this module otherwise relies on. Restricted
    // AFTER entering WAL mode (not before): SQLite creates the `-wal`/`-shm` sidecar
    // files as part of the PRAGMA above, so by this point all three exist to restrict.
    // Best-effort: a failure here doesn't fail `open` -- it only tightens a file that
    // is otherwise already fully functional, never blocks startup on it.
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

/// #603: periodic retention sweep, deleting `conn_audit` rows older than
/// `window_secs`. No scheduled prune/retention job exists anywhere else in this
/// codebase's production code today (the one prune function that does,
/// `SqliteEdgeMesh::prune_stale_edges`, is dead code, called only from its own
/// test) -- this is genuinely new infrastructure, though its shape (interval ticker
/// + delete, raced against shutdown) matches the reap loops already spawned in
/// `serve::run_edge`.
pub async fn run_audit_retention_loop(
    log: Arc<SqliteAuditLog>,
    window_secs: i64,
    shutdown: ShutdownSignal,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tick.tick() => {
                let cutoff = now_secs().saturating_sub(window_secs);
                match log.prune_older_than(cutoff) {
                    Ok(n) if n > 0 => eprintln!("ct-edge: audit-log retention pruned {n} row(s) older than {window_secs}s (#603)"),
                    Ok(_) => {}
                    Err(e) => eprintln!("ct-edge: audit-log retention sweep failed: {e} (#603)"),
                }
            }
        }
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
    use std::net::{IpAddr, Ipv4Addr};

    fn store() -> SqliteAuditLog {
        SqliteAuditLog::open_in_memory().unwrap()
    }

    /// A unique temp DB path (no wall-clock / process helpers needed) -- mirrors
    /// `crates/control-plane/src/storage.rs`'s own `temp_db_path` test helper.
    fn temp_db_path() -> String {
        use rand::RngCore;
        let mut b = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut b);
        let name: String = b.iter().map(|x| format!("{x:02x}")).collect();
        std::env::temp_dir().join(format!("ct_audit_log_{name}.db")).to_string_lossy().into_owned()
    }

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn record_persists_a_row_with_all_fields() {
        let s = store();
        s.record(
            ConnTransport::QuicChannel,
            ip(203, 0, 113, 7),
            1_000,
            None,
            Some("aa".repeat(32).as_str()),
            Some("bb".repeat(32).as_str()),
        )
        .unwrap();
        assert_eq!(s.row_count().unwrap(), 1);
    }

    #[test]
    fn record_allows_absent_token_and_channel_fields() {
        // Front-door/TCP-fallback rows carry a routing token; channel-plane rows
        // carry channel+holder instead -- both are legitimately partial.
        let s = store();
        s.record(ConnTransport::TcpFallback, ip(198, 51, 100, 1), 1_000, Some("cc".repeat(32).as_str()), None, None)
            .unwrap();
        assert_eq!(s.row_count().unwrap(), 1);
    }

    #[test]
    fn prune_older_than_removes_only_rows_before_the_cutoff() {
        let s = store();
        s.record(ConnTransport::FrontDoorTls, ip(10, 0, 0, 1), 500, Some("old".into()), None, None).unwrap();
        s.record(ConnTransport::FrontDoorTls, ip(10, 0, 0, 2), 1_500, Some("new".into()), None, None).unwrap();

        assert_eq!(s.prune_older_than(1_000).unwrap(), 1, "exactly the older row is pruned");
        assert_eq!(s.row_count().unwrap(), 1);

        // A second prune with the same cutoff finds nothing new to remove.
        assert_eq!(s.prune_older_than(1_000).unwrap(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn open_restricts_the_file_and_its_wal_shm_sidecars_to_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_db_path();
        let s = SqliteAuditLog::open(&path).unwrap();
        // Force a write so the row actually lands (and, on some SQLite builds, so the
        // -wal file is guaranteed to exist, not just the -shm memory-mapped index).
        s.record(ConnTransport::FrontDoorTls, ip(203, 0, 113, 1), 1, None, None, None).unwrap();

        let mode = |p: &str| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600, "main db file must be owner-only, not the umask default");
        for suffix in ["-wal", "-shm"] {
            let sidecar = format!("{path}{suffix}");
            if std::path::Path::new(&sidecar).exists() {
                assert_eq!(mode(&sidecar), 0o600, "{sidecar} must be owner-only too -- it can hold the same data");
            }
        }

        drop(s);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    #[tokio::test]
    async fn retention_loop_prunes_on_tick_and_stops_on_shutdown() {
        let log = Arc::new(store());
        log.record(ConnTransport::QuicChannel, ip(203, 0, 113, 9), now_secs() - 10, None, Some("dd".repeat(32).as_str()), Some("ee".repeat(32).as_str()))
            .unwrap();
        assert_eq!(log.row_count().unwrap(), 1);

        let (ctl, signal) = crate::shutdown::ShutdownController::new();
        let handle = tokio::spawn(run_audit_retention_loop(log.clone(), 5, signal));
        // Row is 10s old with a 5s retention window -- the loop's first tick (an hour
        // away in real time) would eventually prune it, but this test only needs to
        // prove shutdown stops the loop promptly, not wait out a real hourly tick.
        ctl.trigger();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("retention loop must stop promptly on shutdown")
            .unwrap();
    }
}
