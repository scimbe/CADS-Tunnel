//! Domain-separated signing-preimage builder (#184).
//!
//! Every signed primitive in the plane — settlement `Transfer`/`Hold`/`Vote`/`LeaderAttestation`,
//! channel `SignedChannelGrant`/`MembershipStaple`/`BillingCommitment`/`SettleReceipt`/`AgentCard`,
//! marketplace `CapacityOffer`/`CapacityBid`/`CapacityMatch`/`UsageReceipt`, … — signs a
//! **domain-separated, injective preimage**: `DOMAIN ‖ fields…`. Correctness rests on two properties:
//!
//! 1. **Domain separation** — the leading `DOMAIN` tag means a signature over one object type can
//!    never be replayed as a signature over another (a grant preimage can't be reinterpreted as a
//!    vote preimage).
//! 2. **Injectivity** — two *distinct* logical inputs must never serialize to the *same* bytes, or
//!    one signature authenticates both (ambiguity → forgery). For fixed-width fields this is automatic;
//!    for **variable-length** fields it requires a length prefix, and forgetting one on a single field
//!    silently breaks it (e.g. `"ab"‖"c"` and `"a"‖"bc"` collide without prefixes).
//!
//! These preimages were hand-rolled ~14 times, with the variable-length encoding written ≥3 different
//! ways — precisely where a missed length-prefix could slip in. [`Preimage`] centralises the discipline:
//! the domain seeds it, fixed fields append verbatim, and [`Preimage::var_bytes`] is the ONE place a
//! variable-length field is length-prefixed — so injectivity is enforced *by construction*, not by a
//! per-function convention. It is byte-for-byte compatible with the hand-rolled preimages it replaces
//! (a golden-vector test pins each), so switching to it changes no signature on the wire.

/// A domain-separated signing preimage under construction. Build with [`Preimage::new`], append fields
/// in canonical order, then [`Preimage::finish`] for the `Vec<u8>` the signer hashes/signs. The
/// builder is move-based (each method takes `self`) so a preimage reads as one linear chain that
/// mirrors the field order of the object being signed.
pub struct Preimage {
    buf: Vec<u8>,
}

impl Preimage {
    /// Seed a preimage with its `domain` separator (always first, always present).
    pub fn new(domain: &[u8]) -> Self {
        let mut buf = Vec::new();
        buf.extend_from_slice(domain);
        Self { buf }
    }

    /// Append a **fixed-width** field verbatim: a 32-byte key/account, a hash, or any blob whose length
    /// is fixed by the schema (so it needs no length prefix to stay injective).
    pub fn fixed(mut self, bytes: &[u8]) -> Self {
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Append a `u64` little-endian (amounts, nonces, terms, expiries, timestamps).
    pub fn u64(mut self, v: u64) -> Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Append a `u32` little-endian (an explicit count/height a caller writes as a fixed field).
    pub fn u32(mut self, v: u32) -> Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Append a single enum-tag byte — a discriminant that distinguishes variants occupying one field
    /// slot (e.g. a capacity kind). Fixed width (1 byte), so it needs no length prefix.
    pub fn tag(mut self, t: u8) -> Self {
        self.buf.push(t);
        self
    }

    /// Append a **variable-length** field, length-prefixed as `u32-LE length ‖ bytes`. This is the ONE
    /// place variable-length encoding lives, so no builder can forget the prefix and let two distinct
    /// inputs collide. (A field longer than `u32::MAX` bytes is not representable — none of the signed
    /// primitives carry one; the length is truncated by the `as u32` cast, matching the hand-rolled
    /// encoders this replaces, which used the same cast.)
    pub fn var_bytes(mut self, bytes: &[u8]) -> Self {
        self.buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Finish and return the preimage bytes.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_comes_first_and_fixed_fields_append_verbatim() {
        let out = Preimage::new(b"dom").fixed(&[0xAA; 4]).u64(0x0102030405060708).finish();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"dom");
        expected.extend_from_slice(&[0xAA; 4]);
        expected.extend_from_slice(&0x0102030405060708u64.to_le_bytes());
        assert_eq!(out, expected);
    }

    #[test]
    fn var_bytes_length_prefixes_so_the_encoding_is_injective() {
        // The classic collision a missing length-prefix allows: "ab"‖"c" vs "a"‖"bc". With var_bytes
        // (u32-LE len ‖ bytes) they MUST differ — that is the injective discipline this enforces.
        let a = Preimage::new(b"d").var_bytes(b"ab").var_bytes(b"c").finish();
        let b = Preimage::new(b"d").var_bytes(b"a").var_bytes(b"bc").finish();
        assert_ne!(a, b, "length-prefixing keeps distinct splits distinct");
        // exact shape: len(2)‖"ab"‖len(1)‖"c"
        let mut expected = Vec::new();
        expected.extend_from_slice(b"d");
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.extend_from_slice(b"ab");
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(b"c");
        assert_eq!(a, expected);
    }

    #[test]
    fn tag_and_u32_are_single_and_four_byte_fields() {
        let out = Preimage::new(b"").tag(0x07).u32(0x11223344).finish();
        assert_eq!(out, vec![0x07, 0x44, 0x33, 0x22, 0x11]);
    }
}
