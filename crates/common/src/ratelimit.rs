//! Per-token rate limiting (ADR-0018).
//!
//! A fixed-window counter caps rendezvous attempts per Routing Token, layered
//! on top of the PoW gate. Time is caller-supplied (a window index) so this
//! stays deterministic and wall-clock-free.

use crate::RoutingToken;
use std::collections::HashMap;
use std::hash::Hash;

/// Fixed-window rate limiter keyed by an arbitrary key `K` (a Routing Token, an
/// account subject, …). Time is caller-supplied (a window index) so this stays
/// deterministic and wall-clock-free; the caller buckets wall-clock into windows.
pub struct KeyedRateLimiter<K> {
    max_per_window: u32,
    /// key -> (current window, count in that window)
    counters: HashMap<K, (u64, u32)>,
    /// #195: the most recent window we pruned at — so past-window entries get evicted on each window
    /// transition instead of accumulating one dead entry per key ever seen (unbounded growth).
    last_swept_window: u64,
}

impl<K: Eq + Hash + Clone> KeyedRateLimiter<K> {
    pub fn new(max_per_window: u32) -> Self {
        Self {
            max_per_window,
            counters: HashMap::new(),
            last_swept_window: 0,
        }
    }

    /// Record an attempt for `key` in `window`; returns whether it is allowed
    /// (strictly under the per-window limit). A new window resets the count.
    pub fn allow(&mut self, key: &K, window: u64) -> bool {
        // #195: bound memory. Windows are wall-clock buckets that only advance, so an entry from a
        // strictly-past window is dead (its count would reset on next use anyway) — on each window
        // transition, prune every entry older than `window`. Amortized O(1) per call: at most one
        // full sweep per window, O(1) within a window. Guarded on `window > last_swept_window` so an
        // out-of-order/backward window never wrongly evicts current entries.
        if window > self.last_swept_window {
            self.counters.retain(|_, (w, _)| *w >= window);
            self.last_swept_window = window;
        }
        let entry = self.counters.entry(key.clone()).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        if entry.1 >= self.max_per_window {
            return false;
        }
        entry.1 += 1;
        true
    }

    /// The number of keys currently tracked (bounded by the keys seen in the current window after a
    /// sweep). Exposed so callers/tests can observe that memory stays bounded (#195).
    pub fn tracked_keys(&self) -> usize {
        self.counters.len()
    }
}

/// Per-Routing-Token fixed-window limiter (ADR-0018): rendezvous-attempt cap
/// layered on the PoW gate.
pub type RateLimiter = KeyedRateLimiter<RoutingToken>;

#[cfg(test)]
mod tests {
    use super::*;

    fn token(b: u8) -> RoutingToken {
        RoutingToken([b; 32])
    }

    #[test]
    fn allows_up_to_limit_then_rejects() {
        let mut rl = RateLimiter::new(3);
        let t = token(1);
        assert!(rl.allow(&t, 0));
        assert!(rl.allow(&t, 0));
        assert!(rl.allow(&t, 0));
        assert!(!rl.allow(&t, 0), "the 4th attempt in the window is rejected");
    }

    #[test]
    fn resets_on_new_window() {
        let mut rl = RateLimiter::new(1);
        let t = token(1);
        assert!(rl.allow(&t, 0));
        assert!(!rl.allow(&t, 0));
        assert!(rl.allow(&t, 1), "a new window resets the counter");
    }

    #[test]
    fn tokens_are_independent() {
        let mut rl = RateLimiter::new(1);
        assert!(rl.allow(&token(1), 0));
        assert!(rl.allow(&token(2), 0), "a different token has its own budget");
        assert!(!rl.allow(&token(1), 0));
    }

    #[test]
    fn keyed_limiter_works_for_string_subjects() {
        // The generalized limiter caps per arbitrary key (e.g. an account
        // subject), independently per key, resetting each window.
        let mut rl: KeyedRateLimiter<String> = KeyedRateLimiter::new(2);
        let a = "user-a".to_string();
        let b = "user-b".to_string();
        assert!(rl.allow(&a, 0));
        assert!(rl.allow(&a, 0));
        assert!(!rl.allow(&a, 0), "user-a is capped at 2 per window");
        assert!(rl.allow(&b, 0), "user-b has an independent budget");
        assert!(rl.allow(&a, 1), "a new window resets user-a");
    }

    #[test]
    fn evicts_past_window_entries_so_memory_stays_bounded() {
        // #195 (frozen): one entry per distinct key in a window is fine, but they must NOT accumulate
        // forever across windows. After the window advances, stale keys are pruned.
        let mut rl: KeyedRateLimiter<u64> = KeyedRateLimiter::new(5);
        for k in 0..1000u64 {
            rl.allow(&k, 0);
        }
        assert_eq!(rl.tracked_keys(), 1000, "all keys tracked within their window");
        // One call in the next window sweeps the 1000 stale entries; only the current key remains.
        rl.allow(&42, 1);
        assert_eq!(rl.tracked_keys(), 1, "past-window entries evicted on the window transition");
        // Limiting still works after eviction.
        let mut rl2: KeyedRateLimiter<u64> = KeyedRateLimiter::new(2);
        assert!(rl2.allow(&7, 0) && rl2.allow(&7, 0) && !rl2.allow(&7, 0));
        assert!(rl2.allow(&7, 5), "a much later window resets the key");
        assert_eq!(rl2.tracked_keys(), 1);
    }
}
