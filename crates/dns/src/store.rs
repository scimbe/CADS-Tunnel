//! ACME challenge record store (#31 FD4 / #23 BP4c).
//!
//! Maps a challenge name (`_acme-challenge.<host>`, lowercased) to its TXT
//! value(s). The localhost HTTP API mutates it (a later sub-packet); the DNS
//! responder reads it. Poison-safe locking so one panicked writer can't wedge
//! cert issuance.
//!
//! #302: in-memory only by default ([`AcmeDnsStore::new`]) -- a record published
//! but not yet observed by Let's Encrypt's multi-perspective validation is gone if
//! the process (or host) restarts in that window, and LE sees NXDOMAIN instead of
//! the record it already confirmed converged. [`AcmeDnsStore::open`] adds optional
//! crash-safe flat-file persistence (write-through on every mutation, reloaded at
//! startup) for the self-hosted `ct-dns` deployment path, without pulling in a
//! database dependency this otherwise deliberately dependency-free store doesn't
//! need for anything else.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

/// Thread-safe store of challenge name -> TXT values, with optional crash-safe
/// persistence to a flat file (#302).
#[derive(Default)]
pub struct AcmeDnsStore {
    txt: Mutex<HashMap<String, Vec<String>>>,
    persist_path: Option<PathBuf>,
}

impl AcmeDnsStore {
    /// In-memory only -- lost on restart. Fine for tests and for a deployment where
    /// challenge records are short-lived enough that a restart mid-issuance is an
    /// acceptable (if not ideal) failure the ACME client will simply retry.
    pub fn new() -> Self {
        Self::default()
    }

    /// #302: load any existing state from `path` (absent/empty file -> starts
    /// empty, not an error -- there's nothing to recover on first boot), then
    /// persist every subsequent mutation back to it. Returns an error only for a
    /// genuinely broken path (e.g. the parent directory doesn't exist) or corrupt
    /// existing content -- never partial/torn data, since writes are atomic
    /// (write to a temp file in the same directory, then rename, so a crash
    /// mid-write leaves either the old complete file or the new one, never a mix).
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let txt = match std::fs::read(&path) {
            Ok(bytes) if bytes.is_empty() => HashMap::new(),
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("corrupt ACME DNS store at {}: {e}", path.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e),
        };
        let store = Self { txt: Mutex::new(txt), persist_path: Some(path) };
        // Prove the path is actually writable now, at startup, rather than silently
        // discovering it on the first real publish deep into an issuance attempt.
        store.persist()?;
        Ok(store)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<String>>> {
        self.txt.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Write the full current state to `persist_path`, if set. Atomic: write to a
    /// sibling temp file, `fsync` it, then rename over the real path -- an OS-level
    /// atomic replace, so a crash mid-write can never leave a torn/partial file.
    fn persist(&self) -> std::io::Result<()> {
        let Some(path) = &self.persist_path else { return Ok(()) };
        let json = serde_json::to_vec(&*self.lock())?;
        let tmp_path = path.with_extension("tmp");
        let mut tmp = std::fs::File::create(&tmp_path)?;
        tmp.write_all(&json)?;
        tmp.sync_all()?;
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Publish a TXT value for `name` (ACME may need two challenges live at once,
    /// so values accumulate). Names are matched case-insensitively.
    pub fn add_txt(&self, name: &str, value: &str) {
        self.lock()
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(value.to_string());
        // Fail-soft: the in-memory map (already updated above) stays authoritative
        // for this process's lifetime regardless of persist() succeeding -- a
        // transient write failure (e.g. disk full) must not block issuance, only
        // risk this particular restart's recovery. Surfaced so an operator sees it.
        if let Err(e) = self.persist() {
            eprintln!("ct-dns: WARNING -- failed to persist ACME challenge store: {e}");
        }
    }

    /// Replace all TXT values for `name` with a single value.
    pub fn set_txt(&self, name: &str, value: &str) {
        self.lock()
            .insert(name.to_ascii_lowercase(), vec![value.to_string()]);
        // Fail-soft: the in-memory map (already updated above) stays authoritative
        // for this process's lifetime regardless of persist() succeeding -- a
        // transient write failure (e.g. disk full) must not block issuance, only
        // risk this particular restart's recovery. Surfaced so an operator sees it.
        if let Err(e) = self.persist() {
            eprintln!("ct-dns: WARNING -- failed to persist ACME challenge store: {e}");
        }
    }

    /// Remove all TXT values for `name` (challenge cleanup).
    pub fn clear(&self, name: &str) {
        self.lock().remove(&name.to_ascii_lowercase());
        // Fail-soft: the in-memory map (already updated above) stays authoritative
        // for this process's lifetime regardless of persist() succeeding -- a
        // transient write failure (e.g. disk full) must not block issuance, only
        // risk this particular restart's recovery. Surfaced so an operator sees it.
        if let Err(e) = self.persist() {
            eprintln!("ct-dns: WARNING -- failed to persist ACME challenge store: {e}");
        }
    }

    /// The TXT values currently published for `name` (empty if none).
    pub fn txt(&self, name: &str) -> Vec<String> {
        self.lock()
            .get(&name.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_publishes_accumulates_and_clears_case_insensitively() {
        let s = AcmeDnsStore::new();
        assert!(s.txt("_acme-challenge.host.test").is_empty());

        // add accumulates (two live challenges); lookup is case-insensitive.
        s.add_txt("_acme-challenge.Host.Test", "tok-a");
        s.add_txt("_acme-challenge.host.test", "tok-b");
        assert_eq!(
            s.txt("_ACME-CHALLENGE.HOST.TEST"),
            vec!["tok-a".to_string(), "tok-b".to_string()]
        );

        // set replaces; clear removes.
        s.set_txt("_acme-challenge.host.test", "only");
        assert_eq!(s.txt("_acme-challenge.host.test"), vec!["only".to_string()]);
        s.clear("_acme-challenge.host.test");
        assert!(s.txt("_acme-challenge.host.test").is_empty());
    }

    /// A path under the OS temp dir, unique enough for concurrent test runs not to
    /// collide (no external crate needed for this -- matches this crate's otherwise
    /// dependency-light test style).
    fn temp_store_path(label: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("ct-dns-store-test-{label}-{unique}.json"))
    }

    #[test]
    fn open_persists_across_a_restart_302() {
        // #302: exactly the scenario this closes -- publish, then simulate a
        // restart (drop the store, open a fresh one on the same path) and confirm
        // the record survived, instead of the fresh store starting empty.
        let path = temp_store_path("restart");
        {
            let s = AcmeDnsStore::open(&path).unwrap();
            s.set_txt("_acme-challenge.host.test", "survives-restart");
        } // dropped -- simulates the process exiting

        let reopened = AcmeDnsStore::open(&path).unwrap();
        assert_eq!(reopened.txt("_acme-challenge.host.test"), vec!["survives-restart".to_string()]);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn open_on_a_missing_file_starts_empty_not_as_an_error_302() {
        // First boot: nothing to recover yet -- must not be treated as corruption.
        let path = temp_store_path("first-boot");
        let s = AcmeDnsStore::open(&path).unwrap();
        assert!(s.txt("_acme-challenge.host.test").is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn open_persists_add_and_clear_not_just_set_302() {
        let path = temp_store_path("mutations");
        {
            let s = AcmeDnsStore::open(&path).unwrap();
            s.add_txt("_acme-challenge.a.test", "tok-1");
            s.add_txt("_acme-challenge.a.test", "tok-2");
            s.set_txt("_acme-challenge.b.test", "only");
            s.clear("_acme-challenge.b.test");
        }

        let reopened = AcmeDnsStore::open(&path).unwrap();
        assert_eq!(
            reopened.txt("_acme-challenge.a.test"),
            vec!["tok-1".to_string(), "tok-2".to_string()],
            "add_txt's accumulation survives a restart"
        );
        assert!(reopened.txt("_acme-challenge.b.test").is_empty(), "clear's removal survives a restart too");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn open_rejects_genuinely_corrupt_content_rather_than_silently_discarding_it_302() {
        // Corrupt (not just missing) content must be a loud error, not quietly
        // treated as "nothing to recover" -- that would mask real data loss.
        let path = temp_store_path("corrupt");
        std::fs::write(&path, b"not valid json at all").unwrap();
        let result = AcmeDnsStore::open(&path);
        assert!(result.is_err(), "corrupt existing content must fail open(), not silently start empty");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn no_persist_path_behaves_exactly_like_new_302() {
        // AcmeDnsStore::new() (no persistence) must be completely unaffected by this
        // feature -- no file ever touched, no behavior change.
        let s = AcmeDnsStore::new();
        s.set_txt("_acme-challenge.host.test", "in-memory-only");
        assert_eq!(s.txt("_acme-challenge.host.test"), vec!["in-memory-only".to_string()]);
    }
}
