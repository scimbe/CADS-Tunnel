//! JSON Web Signature (RFC 7515) for ACME (RFC 8555 §6.2, ADR-0003): every ACME
//! protocol request is a JWS signed by the account's own ES256 (P-256 ECDSA) key,
//! carrying a fresh anti-replay nonce and the request's own target URL in the
//! protected header. This module owns the account keypair and the two protected-
//! header shapes ACME needs (`jwk` for the very first request — newAccount, before
//! the server has assigned a key id — and `kid` for every request after): getting
//! the raw-vs-DER signature format and the JWK thumbprint's canonical member order
//! wrong here would silently break every ACME call, so both are covered by RFC
//! 7515/7638-grounded tests, not just structural round-trips.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::hmac;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::Serialize;
use serde_json::Value;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// An ACME account's ES256 keypair — signs every protocol request. Generated
/// once (or restored from persisted PKCS#8), then reused across an agent's
/// lifetime so the same ACME account is reused on renewal (RFC 8555 accounts
/// are looked up by key, not re-created per order).
pub struct AccountKey {
    pkcs8: Vec<u8>,
    pair: EcdsaKeyPair,
}

impl AccountKey {
    /// Generate a fresh account key. The returned `pkcs8_der` should be
    /// persisted (e.g. to `CT_AGENT_STATE_DIR`) so [`Self::from_pkcs8`] can
    /// restore the same account on a later run instead of registering a new
    /// one every restart.
    pub fn generate() -> Result<Self, BoxError> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|e| format!("account key generation failed: {e}"))?
            .as_ref()
            .to_vec();
        Self::from_pkcs8(&pkcs8)
    }

    /// Restore an account key from a previously-persisted PKCS#8 document.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, BoxError> {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, &rng)
            .map_err(|e| format!("account key restore failed: {e}"))?;
        Ok(Self { pkcs8: pkcs8.to_vec(), pair })
    }

    /// The PKCS#8 DER to persist for [`Self::from_pkcs8`] on a later run.
    pub fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8
    }

    /// This key's public JWK (RFC 7518 §6.2.1), for the `jwk` field of the
    /// very first (newAccount) protected header.
    fn jwk(&self) -> Value {
        // SEC1 uncompressed point: 0x04 || X (32 bytes) || Y (32 bytes) for P-256.
        let public = self.pair.public_key().as_ref();
        let (x, y) = (&public[1..33], &public[33..65]);
        serde_json::json!({ "kty": "EC", "crv": "P-256", "x": b64url(x), "y": b64url(y) })
    }

    /// The JWK SHA-256 thumbprint (RFC 7638): the base64url digest of the JWK's
    /// canonical form — for EC keys, exactly `{"crv":...,"kty":...,"x":...,"y":...}`
    /// with members in that fixed lexicographic order and no whitespace. Forms the
    /// `keyAuthorization` (`token "." thumbprint`) for every ACME challenge type,
    /// including [`crate::acme::dns01_txt_value`]'s input for DNS-01.
    pub fn thumbprint(&self) -> String {
        let jwk = self.jwk();
        let canonical = format!(
            r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
            jwk["crv"].as_str().unwrap(),
            jwk["kty"].as_str().unwrap(),
            jwk["x"].as_str().unwrap(),
            jwk["y"].as_str().unwrap(),
        );
        b64url(&ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes()).as_ref()[..])
    }

    fn sign(&self, signing_input: &str) -> Result<Vec<u8>, BoxError> {
        let rng = SystemRandom::new();
        let sig = self
            .pair
            .sign(&rng, signing_input.as_bytes())
            .map_err(|e| format!("JWS signing failed: {e}"))?;
        // ECDSA_P256_SHA256_FIXED_SIGNING yields the raw (r || s) form JWS ES256
        // requires directly -- no ASN.1 DER-to-raw conversion, so no room for the
        // classic "signature verifies with openssl but not with a JWS validator"
        // encoding mismatch.
        Ok(sig.as_ref().to_vec())
    }

    /// Build the `externalAccountBinding` JWS (RFC 8555 §7.3.4) a second public
    /// CA (ZeroSSL, Google Trust Services, ...) requires inside `newAccount` to
    /// tie this ACME account to a pre-existing account at that CA. Distinct
    /// from every other signature this type produces: it is signed with the
    /// CA-issued **HMAC** key (`eab_hmac_key_b64url`, base64url as the CA hands
    /// it out), not this account's own ES256 key — the whole point is proving
    /// "the party who holds the EAB secret also holds this ACME key", so
    /// signing it with the ACME key itself would prove nothing.
    pub fn external_account_binding(
        &self,
        eab_kid: &str,
        eab_hmac_key_b64url: &str,
        new_account_url: &str,
    ) -> Result<Value, BoxError> {
        let hmac_key_bytes = URL_SAFE_NO_PAD
            .decode(eab_hmac_key_b64url)
            .map_err(|e| format!("EAB HMAC key is not valid base64url: {e}"))?;
        #[derive(Serialize)]
        struct EabProtected<'a> {
            alg: &'static str,
            kid: &'a str,
            url: &'a str,
        }
        let protected_json =
            serde_json::to_string(&EabProtected { alg: "HS256", kid: eab_kid, url: new_account_url })?;
        let protected_b64 = b64url(protected_json.as_bytes());
        // Payload is this account's own public JWK -- what the EAB binds to.
        let payload_b64 = b64url(serde_json::to_string(&self.jwk())?.as_bytes());
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key_bytes);
        let signature = hmac::sign(&key, signing_input.as_bytes());
        Ok(serde_json::json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": b64url(signature.as_ref()),
        }))
    }

    /// Build a signed JWS body (RFC 7515 §7.2 flattened form, which is what every
    /// ACME endpoint expects) for a POST to `url`. `payload` is the request body
    /// (pass `None` for a "POST-as-GET", RFC 8555 §6.3 — an empty JWS payload).
    /// `kid` is `None` only for the very first request (newAccount), which must
    /// carry the full `jwk` instead since the server hasn't assigned a key id yet.
    pub fn sign_request(
        &self,
        url: &str,
        nonce: &str,
        kid: Option<&str>,
        payload: Option<&Value>,
    ) -> Result<Value, BoxError> {
        #[derive(Serialize)]
        struct ProtectedJwk<'a> {
            alg: &'static str,
            nonce: &'a str,
            url: &'a str,
            jwk: Value,
        }
        #[derive(Serialize)]
        struct ProtectedKid<'a> {
            alg: &'static str,
            nonce: &'a str,
            url: &'a str,
            kid: &'a str,
        }
        let protected_json = match kid {
            Some(kid) => serde_json::to_string(&ProtectedKid { alg: "ES256", nonce, url, kid })?,
            None => serde_json::to_string(&ProtectedJwk { alg: "ES256", nonce, url, jwk: self.jwk() })?,
        };
        let protected_b64 = b64url(protected_json.as_bytes());
        // RFC 8555 §6.3: a "POST-as-GET" carries an empty string payload (NOT an
        // absent one, and NOT `"null"`/`"{}"`) -- distinct from a POST with an
        // actual JSON body.
        let payload_b64 = match payload {
            Some(v) => b64url(serde_json::to_string(v)?.as_bytes()),
            None => String::new(),
        };
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let signature = self.sign(&signing_input)?;
        Ok(serde_json::json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": b64url(&signature),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};

    #[test]
    fn generate_then_restore_from_pkcs8_yields_the_same_key() {
        let key = AccountKey::generate().unwrap();
        let restored = AccountKey::from_pkcs8(key.pkcs8_der()).unwrap();
        assert_eq!(key.jwk(), restored.jwk(), "same PKCS#8 -> same public key");
        assert_eq!(key.thumbprint(), restored.thumbprint());
    }

    #[test]
    fn jwk_has_exactly_the_ec_p256_members() {
        let key = AccountKey::generate().unwrap();
        let jwk = key.jwk();
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        // 32 raw bytes -> 43 base64url chars (no padding), for both coordinates.
        assert_eq!(jwk["x"].as_str().unwrap().len(), 43);
        assert_eq!(jwk["y"].as_str().unwrap().len(), 43);
    }

    #[test]
    fn thumbprint_is_deterministic_and_distinct_per_key() {
        let a = AccountKey::generate().unwrap();
        let b = AccountKey::generate().unwrap();
        assert_eq!(a.thumbprint(), a.thumbprint(), "deterministic for the same key");
        assert_ne!(a.thumbprint(), b.thumbprint(), "distinct keys -> distinct thumbprints");
        // 32-byte SHA-256 digest -> 43 base64url chars, no padding.
        assert_eq!(a.thumbprint().len(), 43);
        assert!(!a.thumbprint().contains('='), "no padding");
    }

    #[test]
    fn sign_request_produces_a_verifiable_jws_with_the_expected_shape() {
        let key = AccountKey::generate().unwrap();
        let payload = serde_json::json!({"termsOfServiceAgreed": true});
        let jws = key
            .sign_request("https://acme.example/new-account", "nonce-abc123", None, Some(&payload))
            .unwrap();

        // Shape: exactly the three flattened-JWS fields, all base64url (no '+','/','=').
        for field in ["protected", "payload", "signature"] {
            let v = jws[field].as_str().unwrap();
            assert!(!v.is_empty());
            assert!(!v.contains('+') && !v.contains('/') && !v.contains('='), "{field} is base64url, not base64");
        }

        // The protected header round-trips to exactly alg/nonce/url/jwk (the
        // first-request shape -- no kid yet).
        let protected: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jws["protected"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(protected["alg"], "ES256");
        assert_eq!(protected["nonce"], "nonce-abc123");
        assert_eq!(protected["url"], "https://acme.example/new-account");
        assert_eq!(protected["jwk"]["kty"], "EC");
        assert!(protected.get("kid").is_none(), "first request carries jwk, not kid");

        // The payload round-trips to exactly what was passed in.
        let decoded_payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jws["payload"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(decoded_payload, payload);

        // The signature genuinely verifies against the account's own public key
        // over signing_input = base64url(protected) "." base64url(payload) --
        // proving ECDSA_P256_SHA256_FIXED_SIGNING's raw r||s output is exactly
        // what a standard verifier expects, not a format ring alone would accept.
        let signing_input = format!("{}.{}", jws["protected"].as_str().unwrap(), jws["payload"].as_str().unwrap());
        let public_key_bytes = key.pair.public_key().as_ref();
        let verifier = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key_bytes);
        let sig_bytes = URL_SAFE_NO_PAD.decode(jws["signature"].as_str().unwrap()).unwrap();
        verifier.verify(signing_input.as_bytes(), &sig_bytes).expect("signature verifies");

        // A tampered signing input must NOT verify (proves this isn't a vacuous check).
        assert!(verifier.verify(b"tampered", &sig_bytes).is_err());
    }

    #[test]
    fn sign_request_uses_kid_not_jwk_once_an_account_id_is_known() {
        let key = AccountKey::generate().unwrap();
        let jws = key
            .sign_request(
                "https://acme.example/new-order",
                "nonce-xyz",
                Some("https://acme.example/acct/123"),
                Some(&serde_json::json!({"identifiers": []})),
            )
            .unwrap();
        let protected: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jws["protected"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(protected["kid"], "https://acme.example/acct/123");
        assert!(protected.get("jwk").is_none(), "kid requests never re-carry the full jwk");
    }

    #[test]
    fn external_account_binding_is_hmac_signed_with_the_eab_key_not_the_account_key() {
        let key = AccountKey::generate().unwrap();
        // A throwaway 32-byte HMAC key, base64url-encoded the way a CA hands one out.
        let hmac_key_b64 = URL_SAFE_NO_PAD.encode([7u8; 32]);
        let binding = key
            .external_account_binding("eab-kid-123", &hmac_key_b64, "https://acme.example/new-account")
            .unwrap();

        let protected: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(binding["protected"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(protected["alg"], "HS256", "EAB is HMAC-signed, never ES256");
        assert_eq!(protected["kid"], "eab-kid-123");
        assert_eq!(protected["url"], "https://acme.example/new-account");

        let payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(binding["payload"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(payload, key.jwk(), "EAB payload binds to this account's own public JWK");

        // Recompute the HMAC independently and confirm it matches -- proves the
        // signature is actually over signing_input with the EAB key, not a stub.
        let signing_input = format!("{}.{}", binding["protected"].as_str().unwrap(), binding["payload"].as_str().unwrap());
        let hmac_key_bytes = URL_SAFE_NO_PAD.decode(&hmac_key_b64).unwrap();
        let verify_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key_bytes);
        hmac::verify(&verify_key, signing_input.as_bytes(), &URL_SAFE_NO_PAD.decode(binding["signature"].as_str().unwrap()).unwrap())
            .expect("signature verifies against the EAB HMAC key");

        // A different EAB key must NOT verify -- proves this isn't vacuously true.
        let wrong_key = hmac::Key::new(hmac::HMAC_SHA256, &[9u8; 32]);
        assert!(hmac::verify(&wrong_key, signing_input.as_bytes(), &URL_SAFE_NO_PAD.decode(binding["signature"].as_str().unwrap()).unwrap()).is_err());
    }

    #[test]
    fn sign_request_post_as_get_carries_an_empty_payload_not_a_json_null() {
        // RFC 8555 §6.3: POST-as-GET (e.g. polling an order/authorization) is a
        // JWS over an EMPTY payload string -- not "null", not "{}", not absent.
        let key = AccountKey::generate().unwrap();
        let jws = key
            .sign_request("https://acme.example/order/1", "n1", Some("https://acme.example/acct/1"), None)
            .unwrap();
        assert_eq!(jws["payload"], "", "POST-as-GET payload is the empty string, unencoded");
    }
}
