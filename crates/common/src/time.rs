//! Wall-clock Unix time, shared by every crate in the workspace.
//!
//! A clock set before 1970 yields `0` rather than a panic: every caller uses this for
//! TTLs, timestamps and retention cut-offs, where a zero "now" fails safe (tokens look
//! expired, nothing looks old enough to purge early).

/// Seconds since the Unix epoch, `0` on a clock error.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// [`now_secs`] as `i64`, for SQLite columns and signed arithmetic.
pub fn now_secs_i64() -> i64 {
    i64::try_from(now_secs()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    #[test]
    fn is_after_2020_and_consistent() {
        let a = super::now_secs();
        assert!(a > 1_577_836_800, "a real clock, not the 0 fallback");
        assert!(super::now_secs_i64() >= a as i64);
    }
}
