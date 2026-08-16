//! Bounded, windowed log throttling (#530, generalized in #533).
//!
//! The shape both known noise sites in this crate need: a repeating operator-facing
//! line whose FIRST occurrence per identity per time window carries full diagnostic
//! value, while the repeats only need to be *counted* — and where the identity space
//! is (or could be made) attacker-influenced, so the state that remembers "seen this
//! one already" must be hard-bounded.
//!
//! Introduced for the channel-pairer reap line (#530: a serve loop parks by design
//! forever, is reaped + re-parks every park-TTL cycle, and repeated the identical
//! line ~10k/day from 4 pairs). Generalized here for the `:443` front-door benign
//! client-abort line (#533: 340 successful load-test requests produced 158 identical
//! "front-door connection error" lines and drowned the 2 real signals in the same
//! window) rather than copied — the two differ only in the KEY they aggregate on
//! (`(channel_hex, holder_hex)` vs the abort class), so [`WindowLogThrottle`] is
//! generic over that key and both sites share one tested core.
//!
//! Pure in the `broker_loops_health`/`note_sibling_sightings` style: the caller
//! injects `now`, so tests need no clock, and the caller decides what (if anything)
//! to actually print. This module never logs.

use std::collections::HashMap;
use std::hash::Hash;

use ct_common::channel::UnixSeconds;

/// #530: what the caller should do with one occurrence's full log line.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum LogDecision {
    /// First occurrence of this key in the current window — log the full line
    /// (diagnostic value unchanged from before the throttle existed).
    LogFull,
    /// A repeat (or a key beyond the tracking cap) — say nothing now; it is
    /// aggregated into the window summary.
    Suppress,
}

/// #530: one summary window's aggregate, returned by
/// [`WindowLogThrottle::window_summary`] for the caller to speak as ONE line.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct WindowSummary<K> {
    /// Every occurrence noted in the window (full-logged + suppressed + untracked).
    pub total: u64,
    /// Distinct keys tracked in the window (≤ the cap).
    pub distinct_keys: usize,
    /// Occurrences of keys beyond the tracking cap (identity dropped, count kept).
    pub untracked: u64,
    /// The busiest tracked keys, `(key, count)`, descending by count, at most the
    /// `top_n` the throttle was built with.
    pub top: Vec<(K, u64)>,
}

/// #530/#533: pure, memory-bounded decision core for a repeating log line.
///
/// Keeps the first occurrence of each key fully logged, aggregates repeats, and hands
/// the caller one [`WindowSummary`] per elapsed window. Memory is bounded two ways: at
/// most `max_tracked` keys are ever held, and the whole map resets on every window
/// rollover — an attacker cycling many distinct identities can neither grow this map
/// nor mint unbounded full log lines.
///
/// The caller drives the clock, so *when* a rollover is noticed is the caller's
/// choice: a periodic reaper checks on every tick (#530), an event-driven site checks
/// on every occurrence (#533, where a quiet edge simply carries the last window until
/// the next occurrence — the accompanying counter metric, not the log, is the complete
/// record).
pub(crate) struct WindowLogThrottle<K> {
    window_secs: u64,
    max_tracked: usize,
    top_n: usize,
    /// Unix time the current window opened; 0 = no window open (opens lazily on the
    /// first occurrence, so an idle edge carries no state and emits no summaries).
    window_start: UnixSeconds,
    /// key -> occurrences of that key in this window.
    keys: HashMap<K, u64>,
    total: u64,
    suppressed: u64,
    untracked: u64,
}

impl<K: Clone + Eq + Hash + Ord> WindowLogThrottle<K> {
    pub(crate) fn new(window_secs: u64, max_tracked: usize, top_n: usize) -> Self {
        Self {
            window_secs,
            max_tracked,
            top_n,
            window_start: 0,
            keys: HashMap::new(),
            total: 0,
            suppressed: 0,
            untracked: 0,
        }
    }

    /// Note one occurrence of `key` at `now` and decide its log fate.
    pub(crate) fn note(&mut self, now: UnixSeconds, key: K) -> LogDecision {
        if self.window_start == 0 {
            self.window_start = now;
        }
        self.total = self.total.saturating_add(1);
        if let Some(count) = self.keys.get_mut(&key) {
            *count = count.saturating_add(1);
            self.suppressed = self.suppressed.saturating_add(1);
            return LogDecision::Suppress;
        }
        if self.keys.len() >= self.max_tracked {
            self.untracked = self.untracked.saturating_add(1);
            self.suppressed = self.suppressed.saturating_add(1);
            return LogDecision::Suppress;
        }
        self.keys.insert(key, 1);
        LogDecision::LogFull
    }

    /// Roll the window over once `window_secs` have passed since it opened: returns
    /// the aggregate to log — `Some` only when at least one occurrence was SUPPRESSED
    /// (a window where every key occurred exactly once was already fully logged line
    /// by line; a summary would add nothing) — and resets ALL state either way (the
    /// reset IS the eviction: together with the cap it bounds the map). `None` while
    /// the window is still open or was never opened.
    pub(crate) fn window_summary(&mut self, now: UnixSeconds) -> Option<WindowSummary<K>> {
        if self.window_start == 0 || now.saturating_sub(self.window_start) < self.window_secs {
            return None;
        }
        let summary = if self.suppressed > 0 {
            let mut top: Vec<(K, u64)> = self.keys.iter().map(|(k, n)| (k.clone(), *n)).collect();
            // Count descending; the key's own order as a deterministic tie-break.
            top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            top.truncate(self.top_n);
            Some(WindowSummary {
                total: self.total,
                distinct_keys: self.keys.len(),
                untracked: self.untracked,
                top,
            })
        } else {
            None
        };
        self.window_start = 0;
        self.keys.clear();
        self.total = 0;
        self.suppressed = 0;
        self.untracked = 0;
        summary
    }

    /// How many keys the current window tracks — the cap's observable effect, for the
    /// tests that pin that the map itself never grows past `max_tracked`. Test-only:
    /// production never needs to look inside, and an always-compiled accessor nobody
    /// calls would trip the crate's `-D warnings` gate.
    #[cfg(test)]
    pub(crate) fn tracked_len(&self) -> usize {
        self.keys.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #533: the generic core behaves identically for a small, closed key space (the
    /// front door's abort classes are `Copy` enum values, not owned string pairs) —
    /// first occurrence per key logs in full, repeats aggregate.
    #[test]
    fn window_throttle_first_occurrence_logs_full_and_repeats_are_suppressed_533() {
        let mut t: WindowLogThrottle<&'static str> = WindowLogThrottle::new(600, 8, 3);
        assert_eq!(t.note(100, "reset"), LogDecision::LogFull, "first of its key");
        assert_eq!(t.note(101, "reset"), LogDecision::Suppress, "repeat of the same key");
        assert_eq!(t.note(102, "close-notify"), LogDecision::LogFull, "a different key is its own first");
        assert_eq!(t.window_summary(699), None, "window still open -> no summary");
    }

    /// The window's aggregate names the busiest keys and counts everything, including
    /// the occurrences that were suppressed.
    #[test]
    fn window_throttle_summary_carries_counts_and_top_keys_533() {
        let mut t: WindowLogThrottle<&'static str> = WindowLogThrottle::new(600, 8, 2);
        for _ in 0..143 {
            t.note(100, "reset");
        }
        for _ in 0..15 {
            t.note(100, "close-notify");
        }
        t.note(100, "broken-pipe");
        let s = t.window_summary(700).expect("window elapsed with repeats -> summary");
        assert_eq!(s.total, 159, "every occurrence counted");
        assert_eq!(s.distinct_keys, 3);
        assert_eq!(s.untracked, 0);
        assert_eq!(s.top.len(), 2, "top list honours the configured top_n");
        assert_eq!(s.top[0], ("reset", 143), "busiest key first");
        assert_eq!(s.top[1], ("close-notify", 15));
        // The reset IS the eviction: the next window starts clean.
        assert_eq!(t.note(710, "reset"), LogDecision::LogFull, "after the reset the key logs full again");
        assert_eq!(t.tracked_len(), 1);
    }

    /// A window in which every key occurred exactly once was already fully logged line
    /// by line — no summary, but the state still resets.
    #[test]
    fn window_throttle_without_repeats_emits_no_summary_but_still_resets_533() {
        let mut t: WindowLogThrottle<&'static str> = WindowLogThrottle::new(600, 8, 3);
        t.note(100, "reset");
        assert_eq!(t.window_summary(700), None, "no repeats -> no summary line");
        assert_eq!(t.note(701, "reset"), LogDecision::LogFull, "state was still reset");
    }

    /// The cap is the anti-flood property: beyond it, occurrences are counted WITHOUT
    /// identity and never mint a full line, and the map never grows past the cap.
    #[test]
    fn window_throttle_caps_tracked_keys_and_counts_the_overflow_533() {
        let mut t: WindowLogThrottle<&'static str> = WindowLogThrottle::new(600, 2, 3);
        assert_eq!(t.note(100, "a"), LogDecision::LogFull);
        assert_eq!(t.note(101, "b"), LogDecision::LogFull);
        assert_eq!(t.note(102, "c"), LogDecision::Suppress, "beyond the cap -> no full line");
        assert_eq!(t.note(103, "d"), LogDecision::Suppress);
        assert_eq!(t.tracked_len(), 2, "the map never exceeds the cap");
        let s = t.window_summary(700).expect("summary");
        assert_eq!(s.total, 4, "every occurrence counted, tracked or not");
        assert_eq!(s.distinct_keys, 2);
        assert_eq!(s.untracked, 2, "overflow occurrences are counted without identity");
    }
}
