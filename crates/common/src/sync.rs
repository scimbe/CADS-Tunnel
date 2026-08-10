//! Poison-resilient locking (#24).
//!
//! `std::sync::Mutex` poisons **permanently** if a thread panics while holding
//! the lock: every later `lock().unwrap()` then panics too, so a single
//! panic in one critical section takes a whole subsystem down (the Edge routing
//! registry, or a control-plane store) until the process restarts — a narrow bug
//! becomes an indefinite outage. For shared state, availability matters more than
//! refusing to touch possibly-torn state (ADR-0018): recover the guard instead of
//! cascading the failure. Use for SHARED state (registries, stores, limiters); a
//! recovered map/connection is at worst slightly inconsistent, which is
//! preferable to 500ing every request forever. Do NOT use it to paper over a
//! torn invariant that must fail closed.

use std::sync::{Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Extension adding a poison-recovering lock to [`std::sync::Mutex`].
pub trait MutexExt<T: ?Sized> {
    /// Lock, recovering the guard if the mutex was poisoned by a panic in a
    /// previous critical section (instead of panicking again).
    fn lock_safe(&self) -> MutexGuard<'_, T>;
}

impl<T: ?Sized> MutexExt<T> for Mutex<T> {
    fn lock_safe(&self) -> MutexGuard<'_, T> {
        self.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Extension adding poison-recovering locks to [`std::sync::RwLock`], the
/// same rationale as [`MutexExt`] (#24 / ADR-0018) applied to a read/write
/// lock: for shared state where availability matters more than refusing to
/// touch possibly-torn state, recover a poisoned guard instead of cascading
/// the failure to every later caller. Use for a field that's read far more
/// often than it's written (#362) -- a field written as often as it's read
/// gets no real benefit from `RwLock` over `Mutex` and should stay a
/// [`MutexExt`] field.
pub trait RwLockExt<T: ?Sized> {
    /// Take a read lock, recovering the guard if the lock was poisoned by a
    /// panic in a previous critical section (instead of panicking again).
    fn read_safe(&self) -> RwLockReadGuard<'_, T>;
    /// Take a write lock, recovering the guard if the lock was poisoned by a
    /// panic in a previous critical section (instead of panicking again).
    fn write_safe(&self) -> RwLockWriteGuard<'_, T>;
}

impl<T: ?Sized> RwLockExt<T> for RwLock<T> {
    fn read_safe(&self) -> RwLockReadGuard<'_, T> {
        self.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write_safe(&self) -> RwLockWriteGuard<'_, T> {
        self.write().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn lock_safe_recovers_a_poisoned_mutex() {
        let m = Arc::new(Mutex::new(0u32));
        let m2 = Arc::clone(&m);
        // Poison the mutex: panic while holding the lock, mid-update.
        let _ = std::thread::spawn(move || {
            let mut g = m2.lock().unwrap();
            *g = 1;
            panic!("poison the lock");
        })
        .join();
        assert!(m.lock().is_err(), "std lock() sees the mutex as poisoned");
        // lock_safe still yields a usable guard (the last write survived).
        let g = m.lock_safe();
        assert_eq!(*g, 1, "recovered the guard instead of panicking");
    }

    #[test]
    fn read_safe_and_write_safe_recover_a_poisoned_rwlock() {
        let l = Arc::new(RwLock::new(0u32));
        let l2 = Arc::clone(&l);
        // Poison the lock: panic while holding the WRITE guard, mid-update --
        // a write-guard panic is what actually poisons a RwLock (a read-guard
        // panic does not, since std never lets a reader mutate).
        let _ = std::thread::spawn(move || {
            let mut g = l2.write().unwrap();
            *g = 1;
            panic!("poison the lock");
        })
        .join();
        assert!(l.read().is_err(), "std read() sees the lock as poisoned");
        assert!(l.write().is_err(), "std write() sees the lock as poisoned");
        // Both recovering accessors still yield a usable guard (the last
        // write survived).
        assert_eq!(*l.read_safe(), 1, "read_safe recovered instead of panicking");
        *l.write_safe() = 2;
        assert_eq!(*l.read_safe(), 2, "write_safe recovered and the new write stuck");
    }
}
