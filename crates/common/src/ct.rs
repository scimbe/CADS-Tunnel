//! Constant-time comparison for secrets (MACs, admin tokens), shared by every crate in
//! the workspace so the construction lives in one place.

/// Whether `a == b`, without an early exit on the first differing byte. The length
/// check does short-circuit: the lengths of the values compared here (MAC tags, fixed
/// tokens) are not secret, only their content is.
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    // Keep the optimizer from turning the fold back into a short-circuiting compare.
    std::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::eq;

    #[test]
    fn compares_content_and_length() {
        assert!(eq(b"", b""));
        assert!(eq(b"abc", b"abc"));
        assert!(!eq(b"abc", b"abd"));
        assert!(!eq(b"abc", b"ab"), "a prefix is not equal");
        assert!(!eq(&[0u8; 32], &[1u8; 32]));
    }
}
