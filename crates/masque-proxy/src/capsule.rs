//! RFC 9297 Capsule Protocol framing, specialized to the one capsule type this
//! proxy needs: the DATAGRAM (0x00) capsule (RFC 9297 section 5.2) used to carry
//! an HTTP Datagram over a transport with no native unreliable-datagram frame --
//! exactly HTTP/2's situation, unlike HTTP/3's native QUIC DATAGRAM frame.
//!
//! Wire format (RFC 9297 section 3.2):
//!   Capsule { Capsule Type (i), Capsule Length (i), Capsule Value (..) }
//! For DATAGRAM, Capsule Type = 0x00 and Capsule Value = the HTTP Datagram payload
//! (here: an RFC 9298 UDP Proxying payload, see [`udp_datagram_payload`]).
//!
//! Proven end-to-end in ct-agent's `spike-masque-h2/` (ADR-0024 M1) before this crate
//! existed. Production hardening added here that the spike didn't need: a bound on
//! the declared capsule length, so a peer can't claim an enormous `Capsule Length`
//! and force this proxy to buffer without limit waiting for bytes that may never
//! arrive (this codebase's established missing-bound family -- see CADS-Tunnel#593
//! and friends for the same class of fix elsewhere).

use crate::varint;

const DATAGRAM_CAPSULE_TYPE: u64 = 0x00;

/// RFC 9298 section 6: "endpoints MUST NOT send HTTP Datagrams with a UDP Proxying
/// Payload field longer than 65527 using Context ID zero" -- the largest a real UDP
/// payload can legitimately be. A declared capsule Length far beyond
/// [`MAX_CAPSULE_VALUE_LEN`] (Length + the small Context-ID prefix) is therefore
/// never a valid DATAGRAM capsule, only ever a malicious or buggy peer -- reject it
/// outright rather than buffering toward it.
const MAX_CAPSULE_VALUE_LEN: u64 = 65_527 + 8; // + generous headroom for the Context ID varint

/// Encodes one DATAGRAM capsule wrapping `payload` (an already-encoded HTTP Datagram
/// payload, e.g. from [`udp_datagram_payload::encode`]).
pub fn encode_datagram(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    varint::encode(DATAGRAM_CAPSULE_TYPE, &mut out);
    varint::encode(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}

/// Decodes one capsule from the front of `buf`. Returns `(capsule_type, value, bytes_consumed)`,
/// or `Ok(None)` if `buf` doesn't yet contain a complete capsule (the caller should buffer
/// more bytes from the stream and retry). `Err` only for a declared length so large it can
/// never be a legitimate DATAGRAM capsule (see [`MAX_CAPSULE_VALUE_LEN`]) -- the caller should
/// treat this as a protocol violation and tear the stream down, not keep buffering.
pub fn decode(buf: &[u8]) -> Result<Option<(u64, &[u8], usize)>, &'static str> {
    let Some((cap_type, type_len)) = varint::decode(buf) else {
        return Ok(None);
    };
    let Some((len, len_len)) = varint::decode(&buf[type_len..]) else {
        return Ok(None);
    };
    if len > MAX_CAPSULE_VALUE_LEN {
        return Err("capsule Length exceeds the maximum a legitimate UDP-proxying DATAGRAM capsule can carry");
    }
    let header_len = type_len + len_len;
    let total = header_len + len as usize;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some((cap_type, &buf[header_len..total], total)))
}

/// RFC 9298's UDP Proxying HTTP Datagram payload: `Context ID (i) | UDP Proxying Payload (..)`.
/// This proxy only ever uses Context ID 0 (an unmodified raw UDP payload -- RFC 9298
/// section 5's "Context ID zero" case; non-zero Context IDs are for future datagram
/// formats this proxy has no need to support, since it only ever tunnels one fixed
/// destination's raw UDP traffic, never a negotiated compression context).
pub mod udp_datagram_payload {
    use crate::varint;

    const CONTEXT_ID_RAW_UDP: u64 = 0;

    pub fn encode(udp_payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        varint::encode(CONTEXT_ID_RAW_UDP, &mut out);
        out.extend_from_slice(udp_payload);
        out
    }

    /// Decodes a full (already capsule-unwrapped) datagram payload, returning the raw
    /// UDP bytes if the Context ID is the raw-UDP one this proxy supports.
    pub fn decode(buf: &[u8]) -> Option<&[u8]> {
        let (context_id, consumed) = varint::decode(buf)?;
        if context_id != CONTEXT_ID_RAW_UDP {
            return None; // unsupported -- see module doc
        }
        Some(&buf[consumed..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_udp_packet_round_trips_through_capsule_and_datagram_framing() {
        let udp_payload = b"hello over connect-udp";
        let datagram_payload = udp_datagram_payload::encode(udp_payload);
        let capsule = encode_datagram(&datagram_payload);

        let (cap_type, value, consumed) = decode(&capsule).unwrap().expect("decodes the capsule we just built");
        assert_eq!(cap_type, DATAGRAM_CAPSULE_TYPE);
        assert_eq!(consumed, capsule.len(), "consumes the whole (single) capsule, no trailing bytes");

        let decoded_udp = udp_datagram_payload::decode(value).expect("context ID 0 -- raw UDP payload");
        assert_eq!(decoded_udp, udp_payload, "the original UDP bytes survive the round trip unchanged");
    }

    #[test]
    fn decode_returns_ok_none_for_a_capsule_still_arriving_across_stream_reads() {
        let full = encode_datagram(&udp_datagram_payload::encode(b"a longer payload than one byte"));
        assert_eq!(
            decode(&full[..full.len() - 1]).unwrap(),
            None,
            "one byte short of complete must not decode, and must not be an error"
        );
    }

    #[test]
    fn decode_rejects_a_declared_length_too_large_to_ever_be_a_legitimate_datagram() {
        // A peer claiming a multi-gigabyte capsule value must be refused immediately,
        // not buffered toward indefinitely -- this is exactly the unbounded-growth
        // shape this codebase treats as a real finding elsewhere (missing-bound family).
        let mut malicious = Vec::new();
        varint::encode(0x00, &mut malicious); // DATAGRAM capsule type
        varint::encode(10_000_000_000, &mut malicious); // an absurd declared length
        malicious.extend_from_slice(b"only a few real bytes follow");

        let err = decode(&malicious).unwrap_err();
        assert!(err.contains("exceeds"), "rejects rather than buffers toward an absurd declared length: {err}");
    }

    #[test]
    fn decode_accepts_a_declared_length_at_the_real_rfc9298_maximum() {
        // The largest a genuinely legitimate UDP payload can be (RFC 9298 section 6) must
        // NOT be rejected by the same guard that catches the malicious case above.
        let max_udp_payload = vec![0xABu8; 65_527];
        let datagram_payload = udp_datagram_payload::encode(&max_udp_payload);
        let capsule = encode_datagram(&datagram_payload);
        let (_, value, _) = decode(&capsule).unwrap().expect("a legitimate max-size capsule must decode");
        assert_eq!(udp_datagram_payload::decode(value).unwrap(), &max_udp_payload[..]);
    }
}
