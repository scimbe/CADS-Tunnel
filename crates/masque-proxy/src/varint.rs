//! QUIC variable-length integer encoding (RFC 9000 section 16), used by both the
//! Capsule Protocol (RFC 9297) and the UDP Proxying HTTP Datagram payload (RFC 9298)
//! for their Type/Length/Context-ID fields.
//!
//! Proven end-to-end in ct-agent's `spike-masque-h2/` (ADR-0024 M1) before this crate
//! existed; this is the production copy that crate's spike deliberately never wired
//! into anything real.

/// Encodes `v` as a QUIC varint, appending it to `out`. Panics if `v` exceeds the
/// 62-bit range the encoding can represent -- every value this crate ever encodes
/// (capsule type 0x00, small lengths, context ID 0) is far below that ceiling.
pub fn encode(v: u64, out: &mut Vec<u8>) {
    if v < (1 << 6) {
        out.push(v as u8);
    } else if v < (1 << 14) {
        let b = (v as u16) | 0x4000;
        out.extend_from_slice(&b.to_be_bytes());
    } else if v < (1 << 30) {
        let b = (v as u32) | 0x8000_0000;
        out.extend_from_slice(&b.to_be_bytes());
    } else if v < (1 << 62) {
        let b = v | 0xC000_0000_0000_0000;
        out.extend_from_slice(&b.to_be_bytes());
    } else {
        panic!("varint value {v} exceeds the 62-bit QUIC varint range");
    }
}

/// Decodes one QUIC varint from the front of `buf`, returning `(value, bytes_consumed)`.
/// `None` if `buf` doesn't contain enough bytes for the length the first byte's
/// 2-bit prefix declares -- the caller should buffer more input and retry.
pub fn decode(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mask = first & 0x3f;
    let mut v = mask as u64;
    for &b in &buf[1..len] {
        v = (v << 8) | b as u64;
    }
    Some((v, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_values_at_each_length_boundary() {
        for v in [0u64, 1, 63, 64, 16383, 16384, 1_073_741_823, 1_073_741_824] {
            let mut buf = Vec::new();
            encode(v, &mut buf);
            let (decoded, consumed) = decode(&buf).expect("decodes what we just encoded");
            assert_eq!(decoded, v, "value round-trips");
            assert_eq!(consumed, buf.len(), "consumes exactly what was encoded");
        }
    }

    #[test]
    fn decode_returns_none_on_truncated_input() {
        let mut buf = Vec::new();
        encode(16384, &mut buf); // a 4-byte encoding
        assert!(decode(&buf[..2]).is_none(), "truncated multi-byte varint must not decode");
    }
}
