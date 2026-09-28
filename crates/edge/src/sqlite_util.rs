//! SQLite connection setup shared by the edge's durable stores (`audit_log`,
//! `tunnel_history`): separate files with separate access postures, one tuning.

use std::time::Duration;

use rusqlite::Connection;

/// Open `path` in WAL mode with a 5s busy timeout, then restrict the database file
/// and its `-wal`/`-shm` sidecars to the owner (#603/#608).
pub(crate) fn open_tuned(path: &str) -> rusqlite::Result<Connection> {
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
