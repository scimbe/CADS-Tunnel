//! SQLite connection setup shared by the edge's durable stores (`audit_log`,
//! `tunnel_history`): separate files with separate access postures, one tuning.

use std::time::Duration;

use rusqlite::Connection;

/// Open `path` in WAL mode with a 5s busy timeout, then restrict the database file
/// and its `-wal`/`-shm` sidecars to the owner (#603/#608).
pub(crate) fn open_tuned(path: &str) -> rusqlite::Result<Connection> {
    // #1014: pre-create the file at 0600 (unix) BEFORE `Connection::open` ever gets a
    // chance to create it with the process's default umask (typically 0644,
    // world-readable). Without this, there is a window between file creation and
    // the post-WAL chmod below during which the file is world-readable, and a local
    // process that opens it in that window keeps a readable descriptor to it even
    // after the chmod. Only applies on first creation -- if the file already exists
    // (a normal restart), this does not touch its current contents or mode; the
    // chmod below still re-secures an old file left world-readable by a pre-#1014
    // run.
    precreate_owner_only(path);
    let conn = Connection::open(path)?;
    let _mode: String = conn.query_row("PRAGMA journal_mode=WAL;", [], |row| row.get(0))?;
    conn.busy_timeout(Duration::from_secs(5))?;
    // #608: the module doc's "Access is host-only (`sqlite3` directly on the box) by
    // design" claim is only true if the FILE actually enforces that. Restricted
    // AFTER entering WAL mode (not before): SQLite creates the `-wal`/`-shm` sidecar
    // files as part of the PRAGMA above, so by this point all three exist to restrict.
    // Best-effort: a failure here doesn't fail `open` -- it only tightens a file that
    // is otherwise already fully functional, never blocks startup on it. It is,
    // however, logged (#1014): a store that stays world-readable because chmod keeps
    // failing was previously never reported to the operator at all.
    restrict_db_file_permissions(path);
    Ok(conn)
}

/// Create `path` with mode 0600 if it does not exist yet, so `Connection::open`
/// right after never gets to create it with the process umask instead. A no-op if
/// the file is already there (does not truncate, does not change its current mode).
#[cfg(unix)]
fn precreate_owner_only(path: &str) {
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::OpenOptions::new().write(true).create(true).mode(0o600).open(path);
}

#[cfg(not(unix))]
fn precreate_owner_only(_path: &str) {}

/// See [`open_tuned`]'s call site for why. `path`'s `-wal`/`-shm` sidecar files (WAL
/// mode) can hold the same data as the main file (recent, not-yet-checkpointed rows),
/// so all three need the same restriction, not just the main path.
#[cfg(unix)]
fn restrict_db_file_permissions(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    for candidate in [path.to_string(), format!("{path}-wal"), format!("{path}-shm")] {
        if std::path::Path::new(&candidate).exists() {
            if let Err(e) = std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600)) {
                eprintln!("ct-edge: failed to restrict {candidate} to owner-only: {e}");
            }
        }
    }
}

#[cfg(not(unix))]
fn restrict_db_file_permissions(_path: &str) {}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(path: &str) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn open_tuned_creates_the_db_file_owner_only_from_the_start() {
        let dir = std::env::temp_dir().join(format!("ct-edge-sqlite-util-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.db").to_string_lossy().into_owned();

        let conn = open_tuned(&path).unwrap();
        assert_eq!(mode_of(&path), 0o600, "main db file must be owner-only, not left at the process umask");
        for sidecar in [format!("{path}-wal"), format!("{path}-shm")] {
            if std::path::Path::new(&sidecar).exists() {
                assert_eq!(mode_of(&sidecar), 0o600, "{sidecar} must be owner-only too");
            }
        }
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn precreate_owner_only_does_not_touch_an_existing_file() {
        let dir = std::env::temp_dir().join(format!("ct-edge-sqlite-util-existing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("already-there.db").to_string_lossy().into_owned();
        std::fs::write(&path, b"pre-existing contents").unwrap();

        precreate_owner_only(&path);

        assert_eq!(std::fs::read(&path).unwrap(), b"pre-existing contents", "must not truncate an existing file");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
