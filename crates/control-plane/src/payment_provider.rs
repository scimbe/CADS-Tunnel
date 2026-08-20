//! Payment-provider webhook verification (M24.1).
//!
//! Real payment confirmation must originate from the payment provider, not from
//! a client that could simply call an endpoint to top itself up (the M18 stub).
//! Providers sign each webhook: Stripe-style, an HMAC-SHA256 over
//! `"<timestamp>.<body>"` with a shared webhook secret, delivered in a signature
//! header. This verifier authenticates that signature (constant-time) and
//! enforces a timestamp tolerance against replay, so only a genuine, fresh
//! provider event can drive a credit.
//!
//! The verifier is pure and clock-injected (`now` is a parameter), mirroring the
//! OIDC verifier (M19.2), so it is fully deterministic under test.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Why a webhook was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum WebhookError {
    /// The signature header was not valid hex.
    BadSignatureFormat,
    /// The HMAC did not match — forged or tampered event.
    SignatureMismatch,
    /// The event timestamp is outside the accepted window — likely a replay.
    StaleTimestamp,
}

impl std::fmt::Display for WebhookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebhookError::BadSignatureFormat => write!(f, "malformed webhook signature"),
            WebhookError::SignatureMismatch => write!(f, "webhook signature mismatch"),
            WebhookError::StaleTimestamp => write!(f, "webhook timestamp outside tolerance"),
        }
    }
}

impl std::error::Error for WebhookError {}

/// Verifies signed payment-provider webhooks against a shared secret.
pub struct WebhookVerifier {
    secret: Vec<u8>,
    tolerance_secs: u64,
}

impl WebhookVerifier {
    /// Bind the verifier to the provider's webhook signing secret and the
    /// maximum accepted age (either direction) of an event timestamp.
    pub fn new(secret: impl Into<Vec<u8>>, tolerance_secs: u64) -> Self {
        Self {
            secret: secret.into(),
            tolerance_secs,
        }
    }

    /// The signed message is the timestamp and body joined by a dot, exactly as
    /// the provider signs it.
    fn mac(&self, timestamp: u64, body: &[u8]) -> HmacSha256 {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts a key of any length");
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);
        mac
    }

    /// Verify a signed webhook. `timestamp` and `signature_hex` come from the
    /// provider's signature header, `body` is the raw request body, and `now` is
    /// the current unix time. Returns `Ok(())` only when the HMAC matches and the
    /// timestamp is within tolerance.
    pub fn verify(
        &self,
        timestamp: u64,
        body: &[u8],
        signature_hex: &str,
        now: u64,
    ) -> Result<(), WebhookError> {
        if now.abs_diff(timestamp) > self.tolerance_secs {
            return Err(WebhookError::StaleTimestamp);
        }
        let sig = hex_decode(signature_hex).ok_or(WebhookError::BadSignatureFormat)?;
        // Constant-time comparison via the MAC's own verifier.
        self.mac(timestamp, body)
            .verify_slice(&sig)
            .map_err(|_| WebhookError::SignatureMismatch)
    }

    /// Produce the hex signature for `timestamp.body`. This is the provider side
    /// of the scheme; exposed so tests and tooling can generate valid events.
    pub fn sign(&self, timestamp: u64, body: &[u8]) -> String {
        hex_encode(&self.mac(timestamp, body).finalize().into_bytes())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// #606: `s.len() % 2 == 0` is a BYTE-length check, not a char-boundary guard -- a
/// string with a multi-byte UTF-8 char can still have even byte length while a
/// `s[i*2..i*2+2]` slice lands mid-character and panics (e.g. `"a\u{e9}a"` is 4
/// bytes/even but the 'é' straddles the first slice boundary). Guarding on
/// `is_ascii()` too closes it -- same fix already applied to this exact
/// same-shaped function, `service::hex_decode` (#401). `signature_hex` here comes
/// from the `x-ct-webhook-signature` header; not reachable today (`HeaderValue::
/// to_str()` already rejects non-ASCII before this runs, same as #595/#606's other
/// header-sourced sites), fixed anyway for consistency and defense-in-depth.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"whsec_test_secret";
    const BODY: &[u8] = br#"{"intent":"pi_123","status":"succeeded","credits":10}"#;

    #[test]
    fn hex_decode_rejects_rather_than_panics_on_a_multi_byte_char_606() {
        // U+FFFD (3 bytes) + 1 ASCII byte = 4 bytes total (even -- passes the
        // `len() % 2` guard alone), but the char straddles the first 2-byte slice.
        let s = "\u{FFFD}a";
        assert_eq!(s.len() % 2, 0, "even-byte-length guard alone would let this through");
        assert_eq!(hex_decode(s), None);
    }

    #[test]
    fn valid_signature_within_tolerance_is_accepted() {
        let v = WebhookVerifier::new(SECRET, 300);
        let ts = 1_000_000u64;
        let sig = v.sign(ts, BODY);
        assert_eq!(v.verify(ts, BODY, &sig, ts + 5), Ok(()));
    }

    #[test]
    fn tampered_body_is_rejected() {
        let v = WebhookVerifier::new(SECRET, 300);
        let ts = 1_000_000u64;
        let sig = v.sign(ts, BODY);
        let forged = br#"{"intent":"pi_123","status":"succeeded","credits":9999}"#;
        assert_eq!(
            v.verify(ts, forged, &sig, ts),
            Err(WebhookError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let signer = WebhookVerifier::new(SECRET, 300);
        let ts = 1_000_000u64;
        let sig = signer.sign(ts, BODY);
        let attacker = WebhookVerifier::new(b"whsec_wrong".to_vec(), 300);
        assert_eq!(
            attacker.verify(ts, BODY, &sig, ts),
            Err(WebhookError::SignatureMismatch)
        );
    }

    #[test]
    fn stale_timestamp_is_rejected() {
        let v = WebhookVerifier::new(SECRET, 300);
        let ts = 1_000_000u64;
        let sig = v.sign(ts, BODY);
        // 10 minutes later, tolerance is 5 minutes.
        assert_eq!(
            v.verify(ts, BODY, &sig, ts + 600),
            Err(WebhookError::StaleTimestamp)
        );
    }

    #[test]
    fn malformed_signature_hex_is_rejected() {
        let v = WebhookVerifier::new(SECRET, 300);
        let ts = 1_000_000u64;
        assert_eq!(
            v.verify(ts, BODY, "not-hex!!", ts),
            Err(WebhookError::BadSignatureFormat)
        );
    }
}
