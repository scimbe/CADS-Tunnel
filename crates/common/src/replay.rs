//! Replay cache for single-presentation trust primitives (#88 SEC88a).
//!
//! `SignedCredential` and `ChannelGrant` are signature + expiry only, so a captured
//! token is replayable until it expires. A [`ReplayCache`] records an identifier for
//! each accepted token until that token's own expiry and rejects any later
//! presentation of the same identifier — turning "valid until expiry, any number of
//! times" into "valid once". The identifier is caller-chosen and opaque: the token's
//! 64-byte signature works (a replay carries the identical signature) as does an
//! explicit nonce.
//!
//! Time is caller-supplied (the same wall-clock seconds the verifiers already take as
//! `now`) so this stays deterministic and testable, mirroring [`crate::ratelimit`].
//! Entries whose expiry has passed are evicted on access, so the cache never has to
//! retain more than the set of currently-unexpired tokens.

use std::collections::HashMap;

/// #363: how often [`check_and_record`](ReplayCache::check_and_record) pays for a
/// full [`evict_expired`](ReplayCache::evict_expired) sweep, instead of on every
/// single call. Mirrors [`crate::ratelimit::KeyedRateLimiter::allow`]'s own
/// `last_swept_window` amortization (#195) for the identical reason: this is a
/// hot verify-path primitive (`credential`/`channel`'s own `verify_fresh`), and an
/// O(n) `HashMap::retain()` scan on every lookup — including every cache HIT —
/// degrades what should be an O(1) check to O(n) under load with many concurrent
/// valid tokens. Unlike the rate limiter's discrete window boundaries, this
/// cache's time has no natural "next window" to gate on (real wall-clock seconds,
/// ticking on essentially every call), so a fixed interval is used instead.
const EVICT_INTERVAL_SECS: u64 = 5;

/// A bounded-lifetime set of seen token identifiers. Each identifier is remembered
/// only until its token's `expires_at`, after which the token would be rejected on
/// expiry anyway and the entry is dropped.
#[derive(Default)]
pub struct ReplayCache {
    /// identifier bytes -> the token's `expires_at` (caller time units, e.g. seconds)
    seen: HashMap<Vec<u8>, u64>,
    /// #363: wall-clock time of the last full [`evict_expired`](Self::evict_expired)
    /// sweep. `0` (the `Default` value) triggers a sweep on the first call in real
    /// production usage, since a real Unix timestamp is always far more than
    /// [`EVICT_INTERVAL_SECS`] past `0` -- not a universal guarantee for any `now`
    /// (a test using small values, e.g. `now=1`, can and does exercise the "not
    /// enough time has passed yet" path even on a brand-new cache).
    last_evict_at: u64,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `id` (valid until `expires_at`) as seen at time `now`, returning
    /// whether it is **fresh** — `true` the first time an unexpired `id` is
    /// presented, `false` if the same `id` was already recorded and has not yet
    /// expired (a replay). An `id` whose `expires_at <= now` is treated as already
    /// invalid: it is not admitted as fresh and not stored (the caller's expiry
    /// check rejects it regardless).
    ///
    /// #363: the fast path no longer pays for a full map scan on every call — it
    /// looks up only the specific `id` being checked (real O(1)), so an
    /// already-expired entry under a DIFFERENT id (still present because its own
    /// full sweep hasn't run yet) can never cause a false replay: it's simply
    /// invisible to a lookup for a different id, and if that same id resurfaces,
    /// `self.seen.get(id)` seeing its expired entry and `insert` overwriting it
    /// behaves identically to the old evict-then-contains_key-then-insert
    /// sequence. The full sweep (bounding total memory across every id, not just
    /// the one being looked up right now) still runs, just at most once per
    /// [`EVICT_INTERVAL_SECS`] instead of every call — see its own doc comment.
    pub fn check_and_record(&mut self, id: &[u8], expires_at: u64, now: u64) -> bool {
        if now.saturating_sub(self.last_evict_at) >= EVICT_INTERVAL_SECS {
            self.evict_expired(now);
            self.last_evict_at = now;
        }
        // An already-expired token is never fresh and never stored — expiry alone
        // rejects it, and storing it would only add an entry we'd evict next sweep.
        if expires_at <= now {
            return false;
        }
        if let Some(&existing_expiry) = self.seen.get(id) {
            if existing_expiry > now {
                return false; // a live, unexpired replay
            }
            // Present but already expired (the periodic sweep hasn't reached it
            // yet) -- exactly as invisible to this check as if it were absent.
        }
        self.seen.insert(id.to_vec(), expires_at);
        true
    }

    /// Drop every entry whose token has expired at `now` (`expires_at <= now`).
    fn evict_expired(&mut self, now: u64) {
        self.seen.retain(|_, &mut expires_at| expires_at > now);
    }

    /// Number of currently-retained (unexpired-as-of-last-access) identifiers.
    /// Exposed for tests/observability; not part of the trust decision.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXP: u64 = 100;

    #[test]
    fn first_presentation_is_fresh_and_a_replay_is_rejected() {
        let mut c = ReplayCache::new();
        let sig = [7u8; 64];
        assert!(c.check_and_record(&sig, EXP, 10), "first presentation is fresh");
        assert!(!c.check_and_record(&sig, EXP, 20), "the same id again is a replay");
        assert!(!c.check_and_record(&sig, EXP, 99), "still a replay right up to expiry");
    }

    #[test]
    fn distinct_ids_are_independent() {
        let mut c = ReplayCache::new();
        assert!(c.check_and_record(&[1u8; 64], EXP, 10));
        assert!(c.check_and_record(&[2u8; 64], EXP, 10), "a different id is its own token");
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn an_already_expired_token_is_not_fresh_and_not_stored() {
        let mut c = ReplayCache::new();
        // expires_at == now and < now are both already invalid.
        assert!(!c.check_and_record(&[3u8; 64], 50, 50), "expires_at == now is not fresh");
        assert!(!c.check_and_record(&[4u8; 64], 40, 50), "expires_at < now is not fresh");
        assert!(c.is_empty(), "expired tokens are never retained");
    }

    #[test]
    fn entries_are_evicted_after_expiry_bounding_the_cache() {
        let mut c = ReplayCache::new();
        let sig = [9u8; 64];
        assert!(c.check_and_record(&sig, EXP, 10), "fresh before expiry");
        assert_eq!(c.len(), 1);
        // A later access past this token's expiry evicts it, so the map doesn't grow
        // without bound — and the id could even be admitted again as a brand-new
        // token (it would only reach here if it also passed a fresh expiry check).
        assert!(
            c.check_and_record(&[0u8; 64], 300, EXP + 1),
            "an access after expiry admits a new token"
        );
        assert_eq!(c.len(), 1, "the expired entry was evicted, not accumulated");
    }

    #[test]
    fn full_sweep_is_amortized_but_a_lookup_still_treats_its_own_expired_entry_as_gone_363() {
        let mut c = ReplayCache::new();
        // t=1: `last_evict_at` starts at 0 (`Default`); 1 - 0 = 1 < EVICT_INTERVAL_SECS
        // (5), so even this very first call doesn't sweep yet -- deliberately
        // exercising the "not enough real time has passed" path, not the
        // "brand new cache" path a real Unix timestamp would always take.
        assert!(c.check_and_record(&[1u8; 64], 3, 1), "id_a fresh, expires at t=3");
        assert_eq!(c.len(), 1);

        // t=4: id_a (expiry 3) is now logically expired, but only 4s have passed
        // since `last_evict_at` (still 0) -- still under EVICT_INTERVAL_SECS, so
        // the periodic full sweep is deliberately skipped again, and id_a's stale
        // entry is still physically present. This is the real, documented
        // relaxation #363 makes: the cache no longer guarantees "never holds more
        // than the currently-unexpired set" at every instant, only that a LOOKUP
        // always behaves as if it did.
        assert!(c.check_and_record(&[2u8; 64], 1000, 4), "id_b fresh, unrelated to id_a");
        assert_eq!(c.len(), 2, "id_a's stale entry is still physically present -- sweep hasn't run");

        // The real correctness property: even though id_a's own entry is still
        // sitting in the map, presenting id_a AGAIN at t=4 must NOT be treated as
        // a replay of a live token -- its own expiry (3) is in the past relative
        // to now (4), so the fast per-id lookup path must see it as gone, exactly
        // as if the full sweep had already run.
        assert!(
            c.check_and_record(&[1u8; 64], 1000, 4),
            "id_a's own expired entry never causes a false replay before the next sweep"
        );

        // t=6: 6s have now passed since `last_evict_at` (still 0) -- >= 5, so the
        // deferred full sweep finally runs. Note id_a was just re-inserted with
        // expiry=1000 at t=4 above, so it correctly survives this sweep; only a
        // genuinely stale entry with no matching lookup in between would ever be
        // reclaimed by it.
        assert!(c.check_and_record(&[3u8; 64], 1000, 6), "id_c fresh, triggers the deferred sweep");
        assert_eq!(c.len(), 3, "id_a (re-inserted), id_b, and id_c all still genuinely unexpired at t=6");
    }
}
