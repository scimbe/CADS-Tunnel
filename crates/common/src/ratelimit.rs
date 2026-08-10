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

    #[test]
    fn with_max_tracked_keys_never_exceeds_the_cap_in_a_single_all_time_window_414() {
        // #414: `window_secs == 0` callers always pass `window = 0` forever, so the
        // window-transition sweep above never fires -- this is the actual bug scenario.
        // Without a capacity bound, every one of these 10,000 distinct keys would
        // accumulate forever.
        let mut rl: KeyedRateLimiter<u64> = KeyedRateLimiter::with_max_tracked_keys(5, 100);
        for k in 0..10_000u64 {
            rl.allow(&k, 0);
            assert!(rl.tracked_keys() <= 100, "never exceeds the configured cap, key {k}");
        }
        assert_eq!(rl.tracked_keys(), 100, "settles at exactly the cap, not below it");
    }

    #[test]
    fn with_max_tracked_keys_evicts_oldest_first_and_keeps_limiting_correctly_414() {
        let mut rl: KeyedRateLimiter<u64> = KeyedRateLimiter::with_max_tracked_keys(2, 3);
        assert!(rl.allow(&1, 0) && rl.allow(&1, 0) && !rl.allow(&1, 0), "key 1 hits its own per-window cap");
        assert!(rl.allow(&2, 0));
        assert!(rl.allow(&3, 0));
        assert_eq!(rl.tracked_keys(), 3, "at capacity, not yet evicting");

        // A 4th distinct key evicts the oldest (key 1) to make room.
        assert!(rl.allow(&4, 0));
        assert_eq!(rl.tracked_keys(), 3, "still at the cap, not over it");

        // Key 1 was evicted -- it gets a FRESH budget on next use (its old count is gone),
        // proving eviction actually happened rather than just refusing new keys outright.
        assert!(rl.allow(&1, 0), "evicted key 1 starts over with a clean budget");
        assert!(rl.allow(&1, 0));
        assert!(!rl.allow(&1, 0), "and is still correctly capped going forward");
    }

    #[test]
    fn with_max_tracked_keys_reusing_an_existing_key_does_not_evict_414() {
        // Re-using an already-tracked key must not count as "a new key" for eviction
        // purposes, and must not itself get evicted just for being used again.
        let mut rl: KeyedRateLimiter<u64> = KeyedRateLimiter::with_max_tracked_keys(10, 2);
        assert!(rl.allow(&1, 0));
        assert!(rl.allow(&2, 0));
        for _ in 0..5 {
            assert!(rl.allow(&1, 0), "repeatedly using key 1 must not evict it or anything else");
        }
        assert_eq!(rl.tracked_keys(), 2, "still exactly the two real keys, no phantom growth");
    }
}
