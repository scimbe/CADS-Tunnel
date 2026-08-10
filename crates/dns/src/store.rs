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
use std::sync::{PoisonError, RwLock};

/// Thread-safe store of challenge name -> TXT values, with optional crash-safe
/// persistence to a flat file (#302).
///
/// #356: `RwLock`, not `Mutex` -- `txt()` (the real DNS hot path, called once per
/// incoming query) only ever needs a shared read; `add_txt`/`set_txt`/`clear`
/// (ACME publish/cleanup, orders of magnitude rarer) need exclusive write access.
/// A `Mutex` made every read exclusive too, serializing concurrent queries behind
/// each other for no reason -- a burst of resolver retries/parallel TCP queries
/// all wait on the same lock even though none of them are mutating anything.
#[derive(Default)]
pub struct AcmeDnsStore {
    txt: RwLock<HashMap<String, Vec<String>>>,
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
        let store = Self { txt: RwLock::new(txt), persist_path: Some(path) };
        // Prove the path is actually writable now, at startup, rather than silently
        // discovering it on the first real publish deep into an issuance attempt.
        store.persist()?;
        Ok(store)
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, Vec<String>>> {
        self.txt.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, Vec<String>>> {
        self.txt.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// #356 (test-only instrumentation): the whole point of an `RwLock` over a
    /// `Mutex` is that multiple readers can hold it at once, which isn't
    /// otherwise observable through `txt()`'s public API alone (it acquires and
    /// releases its guard within one call). Exposes a way to hold a read guard
    /// open so a test can prove a SECOND concurrent read still succeeds.
    #[cfg(test)]
    pub(crate) fn hold_read_lock_for_test(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, Vec<String>>> {
        self.read()
    }

    /// Write the full current state to `persist_path`, if set. Atomic: write to a
    /// sibling temp file, `fsync` it, then rename over the real path -- an OS-level
    /// atomic replace, so a crash mid-write can never leave a torn/partial file.
    fn persist(&self) -> std::io::Result<()> {
        let Some(path) = &self.persist_path else { return Ok(()) };
        let json = serde_json::to_vec(&*self.read())?;
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
        self.write()
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
        self.write()
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
        self.write().remove(&name.to_ascii_lowercase());
        // Fail-soft: the in-memory map (already updated above) stays authoritative
        // for this process's lifetime regardless of persist() succeeding -- a
        // transient write failure (e.g. disk full) must not block issuance, only
        // risk this particular restart's recovery. Surfaced so an operator sees it.
        if let Err(e) = self.persist() {
            eprintln!("ct-dns: WARNING -- failed to persist ACME challenge store: {e}");
        }
    }

    /// The TXT values currently published for `name` (empty if none).
    ///
    /// #352: the DNS responder's real caller ([`crate::server`]) already lowercases
    /// `name` itself (`message::parse_query`), so under a validation storm (multiple
    /// Let's Encrypt perspectives, retries, local convergence polls) this is the hot
    /// path -- allocating a fresh lowercased `String` on every single query just to
    /// build a lookup key identical to the input contributes nothing. Only allocate
    /// when `name` genuinely isn't already lowercase (any other caller, e.g. the admin
    /// API's tests, still gets the same case-insensitive lookup this store's own
    /// contract promises -- this is purely an allocation-avoidance fast path, not a
    /// narrowed contract).
    ///
    /// #356: takes only a shared read lock (RwLock), not an exclusive one -- many
    /// concurrent queries can read at once, and only ever contend with the rare
    /// ACME publish/cleanup write, not with each other.
    pub fn txt(&self, name: &str) -> Vec<String> {
        let guard = self.read();
        if name.bytes().any(|b| b.is_ascii_uppercase()) {
            guard.get(&name.to_ascii_lowercase()).cloned().unwrap_or_default()
        } else {
            guard.get(name).cloned().unwrap_or_default()
        }
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

    #[test]
    fn concurrent_reads_do_not_serialize_behind_each_other_356() {
        // #356: the real point of RwLock over Mutex -- multiple readers can hold
        // the lock at the same time, so a burst of concurrent queries never waits
        // on another query that's ALSO just reading. Hold a read guard open on
        // this thread, then have a second thread call the real, public txt()
        // concurrently: with a Mutex-backed store, that second read would block
        // until this thread's guard drops (deadlocking this test, since the guard
        // is held for the test's own duration); with RwLock it must succeed
        // promptly.
        let s = std::sync::Arc::new(AcmeDnsStore::new());
        s.add_txt("_acme-challenge.host.test", "tok");

        let guard = s.hold_read_lock_for_test();

        let (tx, rx) = std::sync::mpsc::channel();
        let s2 = s.clone();
        std::thread::spawn(move || {
            tx.send(s2.txt("_acme-challenge.host.test")).unwrap();
        });

        let result = rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect(
                "a second concurrent read must complete while another read guard is \
                 still held -- a Mutex-backed store would have blocked here",
            );
        assert_eq!(result, vec!["tok".to_string()]);
        drop(guard);
    }

    #[test]
    fn txt_returns_the_same_result_via_its_allocation_free_fast_path_as_its_lowercasing_fallback_352() {
        // #352: txt() now takes two different code paths depending on whether `name`
        // is already lowercase (the real DNS hot path never allocates a key) or not
        // (any other caller still gets a correctly lowercased lookup). Prove both
        // paths agree on the SAME stored record -- not just that each looks
        // individually plausible -- across the already-lowercase case, an
        // all-uppercase case, and a mixed-case case.
        let s = AcmeDnsStore::new();
        s.add_txt("_acme-challenge.host.test", "tok");

        let already_lowercase = s.txt("_acme-challenge.host.test");
        let all_uppercase = s.txt("_ACME-CHALLENGE.HOST.TEST");
        let mixed_case = s.txt("_Acme-Challenge.Host.Test");

        assert_eq!(already_lowercase, vec!["tok".to_string()]);
        assert_eq!(already_lowercase, all_uppercase, "fast path and fallback path must agree");
        assert_eq!(already_lowercase, mixed_case, "fast path and fallback path must agree");
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
