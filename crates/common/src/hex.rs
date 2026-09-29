//! Lowercase hex encoding and strict decoding, shared by every crate in the workspace.
//!
//! Decoding accepts only an even number of ASCII hex digits (either case). That rules
//! out what `u8::from_str_radix` alone lets through (a leading `+`, as in `"+f"`), and
//! it never slices a string at a non-ASCII boundary, so it cannot panic on any input.

/// Lowercase hex of `bytes`.
pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    out
}

/// Decode hex of any even length, or `None`.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let digits = s.as_bytes();
    if digits.len() % 2 != 0 {
        return None;
    }
    digits.chunks_exact(2).map(|pair| Some(nibble(pair[0])? << 4 | nibble(pair[1])?)).collect()
}

/// Decode exactly `2 * N` hex digits into `[u8; N]`, or `None`.
pub fn decode_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N {
        return None;
    }
    decode(s)?.try_into().ok()
}

/// Decode exactly 64 hex digits (a 32-byte key, token or id), or `None`.
pub fn decode_32(s: &str) -> Option<[u8; 32]> {
    decode_array(s)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_byte() {
        let all: Vec<u8> = (0..=255).collect();
        let s = encode(&all);
        assert_eq!(s.len(), 512);
        assert_eq!(&s[..6], "000102");
        assert_eq!(&s[s.len() - 4..], "feff");
        assert_eq!(decode(&s).unwrap(), all);
        assert_eq!(decode(&s.to_uppercase()).unwrap(), all, "either case decodes");
    }

    #[test]
    fn rejects_what_from_str_radix_would_accept_or_panic_on() {
        assert_eq!(decode("+f"), None, "a sign is not a hex digit");
        assert_eq!(decode("-1"), None);
        assert_eq!(decode("abc"), None, "odd length");
        assert_eq!(decode("zz"), None);
        assert_eq!(decode("ä0"), None, "multi-byte UTF-8 is rejected, not sliced mid-char");
        assert_eq!(decode("é"), None);
        assert_eq!(decode(""), Some(vec![]));
    }

    #[test]
    fn fixed_width_decoding_checks_length() {
        let key = [0xabu8; 32];
        assert_eq!(decode_32(&encode(&key)), Some(key));
        assert_eq!(decode_32(&"ab".repeat(31)), None);
        assert_eq!(decode_32(&"ab".repeat(33)), None);
        assert_eq!(decode_array::<2>("0aff"), Some([0x0a, 0xff]));
        assert_eq!(decode_32(&format!("+f{}", "ab".repeat(31))), None);
    }
}
