//! OIDC bearer-token verification (M19.2, Keycloak).
//!
//! A client authenticates to the control plane with a Keycloak-issued JWT
//! access token in the `Authorization: Bearer` header. This module validates the
//! token (signature, expiry, issuer) and returns its `sub` claim, which is
//! mapped to an account via [`crate::storage::SqliteLedger::account_for_subject`]
//! (M19.1). The tunnel data path is unaffected and stays end-to-end encrypted.
//!
//! Production uses RS256 with the realm's RSA public key
//! ([`OidcVerifier::from_rsa_pem`]); a symmetric HS256 constructor
//! ([`OidcVerifier::from_hs_secret`]) is available for local/dev and drives the
//! tests, since the validation and claim-extraction logic is identical across
//! algorithms.

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

/// Why token verification failed (invalid signature, expired, wrong issuer, …).
#[derive(Debug)]
pub struct OidcError(String);

impl std::fmt::Display for OidcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "oidc verification failed: {}", self.0)
    }
}
impl std::error::Error for OidcError {}
impl From<jsonwebtoken::errors::Error> for OidcError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        OidcError(e.to_string())
    }
}

/// The subset of claims the control plane needs. `exp` is validated by the
/// library; `iss` is checked against the configured issuer; `sub` is returned.
#[derive(Deserialize)]
struct Claims {
    sub: String,
    #[allow(dead_code)]
    exp: usize,
    #[allow(dead_code)]
    iss: String,
    /// The client the token was issued to (Keycloak sets it on access tokens).
    #[serde(default)]
    azp: Option<String>,
    /// String or array; only read by the per-client audience rules.
    #[serde(default)]
    aud: Option<serde_json::Value>,
}

impl Claims {
    fn aud_contains(&self, want: &str) -> bool {
        match &self.aud {
            Some(serde_json::Value::String(a)) => a == want,
            Some(serde_json::Value::Array(v)) => v.iter().any(|a| a.as_str() == Some(want)),
            _ => false,
        }
    }
}

/// Default per-client audience rules (`CT_OIDC_CLIENT_AUD`): the mobile app's token must name this service.
/// The app gets one access token per resource server (scope `ct-api` here, `mdi-api` for the My Daily Idea
/// wrapper), so a token leaked at one service cannot be replayed at the other (RFC 9700 §2.3).
pub const DEFAULT_CLIENT_AUD: &str = "cads-mobile=ct-api";

/// Parses `client=audience[,client=audience...]`; `off` (or empty) means no rules. Malformed entries are an error,
/// so a typo cannot silently switch enforcement off.
pub fn parse_client_aud(spec: &str) -> Result<Vec<(String, String)>, OidcError> {
    let spec = spec.trim();
    if spec.is_empty() || spec.eq_ignore_ascii_case("off") {
        return Ok(Vec::new());
    }
    spec.split(',')
        .map(|e| {
            let (c, a) = e.split_once('=').ok_or_else(|| OidcError(format!("CT_OIDC_CLIENT_AUD entry without '=': {e}")))?;
            let (c, a) = (c.trim(), a.trim());
            if c.is_empty() || a.is_empty() {
                return Err(OidcError(format!("CT_OIDC_CLIENT_AUD entry incomplete: {e}")));
            }
            Ok((c.to_string(), a.to_string()))
        })
        .collect()
}

/// Verifies bearer tokens against a fixed key + expected issuer.
pub struct OidcVerifier {
    key: DecodingKey,
    validation: Validation,
    /// `(azp, audience)`: a token issued to `azp` must carry `audience` in `aud`.
    client_aud: Vec<(String, String)>,
}

impl OidcVerifier {
    fn build(key: DecodingKey, alg: Algorithm, issuer: &str) -> Self {
        let mut validation = Validation::new(alg);
        validation.set_issuer(&[issuer]);
        validation.validate_exp = true;
        // Keycloak access-token audiences vary by client; the account binding
        // relies on `sub` + `iss`, so audience is not required here.
        validation.validate_aud = false;
        Self { key, validation, client_aud: Vec::new() }
    }

    /// Build a verifier for RS256 tokens from the realm's RSA **public** key
    /// (PEM) and the expected issuer (the realm URL). This is the Keycloak path.
    pub fn from_rsa_pem(pem: &[u8], issuer: &str) -> Result<Self, OidcError> {
        let key = DecodingKey::from_rsa_pem(pem).map_err(OidcError::from)?;
        Ok(Self::build(key, Algorithm::RS256, issuer))
    }

    /// Build a verifier straight from a JWK's RSA components — the base64url
    /// modulus `n` and exponent `e` a Keycloak realm advertises at its JWKS
    /// endpoint (#42 KC2). Lets the control plane fetch the signing key from the
    /// realm rather than requiring a hand-exported PEM file, and skips the
    /// PEM roundtrip. Pair with [`jwks_signing_key`] to pull `(n, e)` from a JWKS.
    pub fn from_rsa_components(n: &str, e: &str, issuer: &str) -> Result<Self, OidcError> {
        let key = DecodingKey::from_rsa_components(n, e).map_err(OidcError::from)?;
        Ok(Self::build(key, Algorithm::RS256, issuer))
    }

    /// Build a verifier for HS256 tokens from a shared secret and expected
    /// issuer. For local/dev and tests; production uses [`Self::from_rsa_pem`].
    pub fn from_hs_secret(secret: &[u8], issuer: &str) -> Self {
        Self::build(DecodingKey::from_secret(secret), Algorithm::HS256, issuer)
    }

    /// Require the token's `aud` to contain `audience` (#82 SEC82b). Keycloak
    /// access-token audiences vary by client, so audience is **not** validated by
    /// default (see [`Self::build`]); an operator who knows their realm's
    /// access-token `aud` shape opts in with a field-checked value (env
    /// `CT_OIDC_ACCESS_AUD`). Once required, a token whose `aud` omits `audience`
    /// — or carries no `aud` at all — is rejected, closing the "bearer-token
    /// audience not validated" gap without a blind flip that would break realms
    /// whose access tokens don't carry the portal's audience.
    #[must_use]
    pub fn require_audience(mut self, audience: &str) -> Self {
        self.validation.set_audience(&[audience]);
        self.validation.validate_aud = true;
        // `validate_aud` alone only rejects a *mismatched* `aud`; a token carrying
        // no `aud` at all still passes. Requiring the claim's presence closes that
        // hole so an audience-less bearer token can't slip through enforcement.
        self.validation.set_required_spec_claims(&["exp", "aud"]);
        self
    }

    /// Per-client audience rules (env `CT_OIDC_CLIENT_AUD`, default [`DEFAULT_CLIENT_AUD`]): a token whose
    /// `azp` names a listed client must carry that client's audience for this service. Tokens of other
    /// clients are unaffected (their audience shape is the operator's `CT_OIDC_ACCESS_AUD` decision).
    #[must_use]
    pub fn require_client_audiences(mut self, rules: Vec<(String, String)>) -> Self {
        self.client_aud = rules;
        self
    }

    /// Verify `token` and return its subject (`sub`). Fails on a bad signature,
    /// an expired token, a mismatched issuer, or a per-client audience rule.
    pub fn subject(&self, token: &str) -> Result<String, OidcError> {
        let data = decode::<Claims>(token, &self.key, &self.validation)?;
        if let Some(azp) = data.claims.azp.as_deref() {
            for (client, aud) in &self.client_aud {
                if client == azp && !data.claims.aud_contains(aud) {
                    return Err(OidcError(format!("token of client {azp} lacks audience {aud}")));
                }
            }
        }
        Ok(data.claims.sub)
    }
}

/// A hot-swappable holder for the `/me/*` OIDC verifier (#328). Two problems this
/// closes together:
///
/// - **Self-healing**: before this, a boot-time JWKS fetch failure (a transient
///   Keycloak/network blip) disabled `/me/*` for the process's *entire remaining
///   lifetime* — nothing short of an operator noticing and restarting the process
///   brought it back. Recurred live twice in one session. A background task can
///   now keep retrying after boot and [`Self::set`] the verifier the moment a
///   fetch finally succeeds, with zero restart.
/// - **Observability**: the `/me/*` routers used to be conditionally *mounted*
///   at boot depending on verifier availability, so an unavailable verifier meant
///   an indistinguishable `404` (route not found) rather than an honest `503`
///   (route exists, temporarily can't authenticate you). Routers now mount
///   unconditionally against a handle and check readiness per-request.
///
/// `Clone` is cheap (one `Arc`) — every authenticated router/state holds its own
/// clone of the same underlying cell, so [`Self::set`] from the background
/// refresh task is visible to every route immediately.
#[derive(Clone)]
pub struct OidcVerifierHandle(std::sync::Arc<std::sync::RwLock<Option<std::sync::Arc<OidcVerifier>>>>);

impl OidcVerifierHandle {
    pub fn new(initial: Option<std::sync::Arc<OidcVerifier>>) -> Self {
        Self(std::sync::Arc::new(std::sync::RwLock::new(initial)))
    }

    /// A handle with no verifier yet — the state every `/me/*` route was
    /// permanently stuck in before #328 when the boot-time fetch failed;
    /// now just the starting state a background retry can heal from.
    pub fn empty() -> Self {
        Self::new(None)
    }

    /// Install a freshly-fetched verifier, replacing whatever (if anything) was
    /// there before. Called once by the boot sequence on success, and again by
    /// the background retry task the first time a delayed fetch succeeds.
    pub fn set(&self, verifier: std::sync::Arc<OidcVerifier>) {
        let mut guard = self.0.write().unwrap_or_else(|e| e.into_inner());
        *guard = Some(verifier);
    }

    /// The current verifier, if one has been installed yet.
    pub fn get(&self) -> Option<std::sync::Arc<OidcVerifier>> {
        self.0.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Whether a verifier is currently installed — what `/status`'s
    /// `oidc_enabled` field reports live (#328).
    pub fn is_ready(&self) -> bool {
        self.get().is_some()
    }
}

impl From<Option<std::sync::Arc<OidcVerifier>>> for OidcVerifierHandle {
    fn from(initial: Option<std::sync::Arc<OidcVerifier>>) -> Self {
        Self::new(initial)
    }
}

/// The JWKS (signing-key) endpoint of a Keycloak realm whose issuer is `issuer`
/// (#42 KC2): `<issuer>/protocol/openid-connect/certs`. A trailing slash on the
/// issuer is tolerated so it composes with `CT_OIDC_ISSUER` either way.
pub fn jwks_uri_for(issuer: &str) -> String {
    format!("{}/protocol/openid-connect/certs", issuer.trim_end_matches('/'))
}

/// Build an RS256 verifier by fetching the realm's JWKS at startup (#42 KC2-c).
/// `fetch` resolves the JWKS document for a URL — the live path uses reqwest, and
/// tests inject a canned document, so this stays hermetic. Returns `None` when the
/// fetch yields nothing or the document carries no RS256 signing key, which the
/// caller treats as "SSO key unavailable" (endpoints stay disabled, no panic).
pub async fn verifier_from_jwks<F, Fut>(issuer: &str, fetch: F) -> Option<OidcVerifier>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Option<serde_json::Value>>,
{
    let jwks = fetch(jwks_uri_for(issuer)).await?;
    let (n, e) = jwks_signing_key(&jwks)?;
    OidcVerifier::from_rsa_components(&n, &e, issuer).ok()
}

/// Like [`verifier_from_jwks`], but retries the fetch+select step on a short backoff
/// instead of giving up after one attempt (#271). The one-shot version means any
/// transient blip at boot — the realm still warming up, a rotated key not yet
/// propagated, a momentary network hiccup — permanently disables `/me/*` for the
/// process's entire lifetime, indistinguishable from the realm genuinely having no
/// usable key. `fetch` must be reusable (`Fn`, not `FnOnce`) so it can be called once
/// per attempt; `sleep` is injected so tests exercise every retry without waiting on
/// real backoff delays. `delays_ms[0]` is normally `0` (try immediately first).
pub async fn verifier_from_jwks_with_retry<F, Fut, S, SFut>(
    issuer: &str,
    fetch: F,
    delays_ms: &[u64],
    sleep: S,
) -> Option<OidcVerifier>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Option<serde_json::Value>>,
    S: Fn(u64) -> SFut,
    SFut: std::future::Future<Output = ()>,
{
    for &delay in delays_ms {
        if delay > 0 {
            sleep(delay).await;
        }
        if let Some(v) = verifier_from_jwks(issuer, |url| fetch(url)).await {
            return Some(v);
        }
    }
    None
}

/// Select the RS256 **signing** key from a parsed JWKS document and return its
/// base64url `(n, e)` components for [`OidcVerifier::from_rsa_components`] (#42
/// KC2). Picks the first key with `kty=RSA` that is usable for signature
/// verification — `use` is `sig` or absent, `alg` is `RS256` or absent — so EC
/// keys and encryption keys in the same document are skipped. Returns `None` when
/// the document exposes no such key (nothing is trusted by default).
pub fn jwks_signing_key(jwks: &serde_json::Value) -> Option<(String, String)> {
    jwks.get("keys")?.as_array()?.iter().find_map(|k| {
        if k.get("kty").and_then(|v| v.as_str()) != Some("RSA") {
            return None;
        }
        if matches!(k.get("use").and_then(|v| v.as_str()), Some(u) if u != "sig") {
            return None;
        }
        if matches!(k.get("alg").and_then(|v| v.as_str()), Some(a) if a != "RS256") {
            return None;
        }
        let n = k.get("n")?.as_str()?.to_string();
        let e = k.get("e")?.as_str()?.to_string();
        Some((n, e))
    })
}

/// The `kid` (key id) from a JWT header, if present (#82). Lets a verifier pick the
/// exact JWKS key that signed a token under key rotation.
pub fn token_kid(token: &str) -> Option<String> {
    jsonwebtoken::decode_header(token).ok()?.kid
}

/// Like [`jwks_signing_key`] but selects the RS256 signing key whose `kid` matches
/// `kid` (#82). Correct under key rotation — a realm that keeps an old key in its
/// JWKS must verify a token against the exact key that signed it (the token
/// header's `kid`), not just the first usable key. Returns `None` if no usable
/// RSA/RS256 key carries that `kid`.
pub fn jwks_signing_key_for_kid(jwks: &serde_json::Value, kid: &str) -> Option<(String, String)> {
    jwks.get("keys")?.as_array()?.iter().find_map(|k| {
        if k.get("kid").and_then(|v| v.as_str()) != Some(kid) {
            return None;
        }
        if k.get("kty").and_then(|v| v.as_str()) != Some("RSA") {
            return None;
        }
        if matches!(k.get("use").and_then(|v| v.as_str()), Some(u) if u != "sig") {
            return None;
        }
        if matches!(k.get("alg").and_then(|v| v.as_str()), Some(a) if a != "RS256") {
            return None;
        }
        let n = k.get("n")?.as_str()?.to_string();
        let e = k.get("e")?.as_str()?.to_string();
        Some((n, e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};

    const SECRET: &[u8] = b"test-realm-secret";
    const ISSUER: &str = "https://keycloak.example/realms/CADS-Tunnel";

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn oidc_verifier_handle_starts_empty_and_becomes_ready_once_set() {
        let handle = OidcVerifierHandle::empty();
        assert!(!handle.is_ready(), "no verifier installed yet");
        assert!(handle.get().is_none());

        let v = std::sync::Arc::new(OidcVerifier::from_hs_secret(SECRET, ISSUER));
        handle.set(v);
        assert!(handle.is_ready(), "#328: set() must flip readiness for a background self-heal to be observable");
        assert!(handle.get().is_some());
    }

    #[test]
    fn oidc_verifier_handle_clones_share_the_same_underlying_cell() {
        let handle = OidcVerifierHandle::empty();
        let clone = handle.clone();
        assert!(!clone.is_ready());

        // A route's own clone (taken at router-construction time) must observe a
        // later set() from the background retry task -- that's the whole point.
        handle.set(std::sync::Arc::new(OidcVerifier::from_hs_secret(SECRET, ISSUER)));
        assert!(clone.is_ready(), "#328: a pre-existing clone must see a later set() through the shared cell");
    }

    fn make_token(secret: &[u8], sub: &str, iss: &str, exp: u64) -> String {
        let claims = serde_json::json!({ "sub": sub, "iss": iss, "exp": exp });
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    fn make_token_with_aud(secret: &[u8], sub: &str, iss: &str, exp: u64, aud: &str) -> String {
        let claims = serde_json::json!({ "sub": sub, "iss": iss, "exp": exp, "aud": aud });
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    #[test]
    fn required_audience_gates_bearer_tokens() {
        // #82 SEC82b: with an audience required, only a token whose `aud` contains
        // it is accepted; a mismatched or absent `aud` is rejected — while the
        // default verifier (no audience required) still ignores `aud` entirely, so
        // enabling enforcement never silently breaks the pre-#82b behavior.
        let matching = make_token_with_aud(SECRET, "user-42", ISSUER, now() + 3600, "ct-portal");
        let wrong = make_token_with_aud(SECRET, "user-42", ISSUER, now() + 3600, "some-other-client");
        let no_aud = make_token(SECRET, "user-42", ISSUER, now() + 3600);

        let enforced = OidcVerifier::from_hs_secret(SECRET, ISSUER).require_audience("ct-portal");
        assert_eq!(enforced.subject(&matching).unwrap(), "user-42", "matching aud accepted");
        assert!(enforced.subject(&wrong).is_err(), "mismatched aud rejected");
        assert!(enforced.subject(&no_aud).is_err(), "missing aud rejected when required");

        // Default (audience not required) — pre-#82b behavior is preserved.
        let default = OidcVerifier::from_hs_secret(SECRET, ISSUER);
        assert_eq!(default.subject(&wrong).unwrap(), "user-42", "aud ignored by default");
        assert_eq!(default.subject(&no_aud).unwrap(), "user-42", "no aud is fine by default");
    }

    fn make_token_claims(secret: &[u8], claims: serde_json::Value) -> String {
        encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(secret)).unwrap()
    }

    #[test]
    fn client_audience_rules_keep_per_resource_tokens_apart() {
        // RFC 9700 §2.3: the app's token for the My Daily Idea wrapper (aud mydailyidea-api) must not work here,
        // the token for this service (aud ct-api) must; other clients are not affected by the rule.
        let rules = parse_client_aud(DEFAULT_CLIENT_AUD).unwrap();
        let v = OidcVerifier::from_hs_secret(SECRET, ISSUER).require_client_audiences(rules);
        let tok = |azp: &str, aud: serde_json::Value| {
            make_token_claims(SECRET, serde_json::json!({ "sub": "u1", "iss": ISSUER, "exp": now() + 3600, "azp": azp, "aud": aud }))
        };
        assert_eq!(v.subject(&tok("cads-mobile", serde_json::json!("ct-api"))).unwrap(), "u1");
        assert_eq!(v.subject(&tok("cads-mobile", serde_json::json!(["account", "ct-api"]))).unwrap(), "u1");
        assert!(v.subject(&tok("cads-mobile", serde_json::json!("mydailyidea-api"))).is_err(), "wrapper token refused here");
        assert!(v.subject(&tok("cads-mobile", serde_json::json!(["account"]))).is_err());
        let no_aud = make_token_claims(SECRET, serde_json::json!({ "sub": "u1", "iss": ISSUER, "exp": now() + 3600, "azp": "cads-mobile" }));
        assert!(v.subject(&no_aud).is_err(), "no aud at all refused for the listed client");
        assert_eq!(v.subject(&tok("ct-agent-cli", serde_json::json!("account"))).unwrap(), "u1", "other clients unaffected");
        assert_eq!(v.subject(&make_token(SECRET, "u2", ISSUER, now() + 3600)).unwrap(), "u2", "no azp: rule does not apply");
    }

    #[test]
    fn client_audience_spec_parsing() {
        assert_eq!(parse_client_aud("cads-mobile=ct-api").unwrap(), vec![("cads-mobile".into(), "ct-api".into())]);
        assert_eq!(parse_client_aud(" a=x , b=y ").unwrap().len(), 2);
        assert!(parse_client_aud("off").unwrap().is_empty());
        assert!(parse_client_aud("").unwrap().is_empty());
        assert!(parse_client_aud("cads-mobile").is_err(), "typo does not switch enforcement off");
        assert!(parse_client_aud("=x").is_err());
        assert!(parse_client_aud("a=").is_err());
    }

    #[test]
    fn valid_token_yields_subject() {
        let v = OidcVerifier::from_hs_secret(SECRET, ISSUER);
        let token = make_token(SECRET, "user-42", ISSUER, now() + 3600);
        assert_eq!(v.subject(&token).unwrap(), "user-42");
    }

    #[test]
    fn expired_token_is_rejected() {
        // Well beyond jsonwebtoken's default 60s exp leeway.
        let v = OidcVerifier::from_hs_secret(SECRET, ISSUER);
        let token = make_token(SECRET, "user-42", ISSUER, now() - 3600);
        assert!(v.subject(&token).is_err(), "expired token rejected");
    }

    #[test]
    fn wrong_issuer_is_rejected() {
        let v = OidcVerifier::from_hs_secret(SECRET, ISSUER);
        let token = make_token(SECRET, "user-42", "https://evil.example/realms/x", now() + 3600);
        assert!(v.subject(&token).is_err(), "mismatched issuer rejected");
    }

    #[test]
    fn bad_signature_is_rejected() {
        let v = OidcVerifier::from_hs_secret(SECRET, ISSUER);
        let token = make_token(b"other-secret", "user-42", ISSUER, now() + 3600);
        assert!(v.subject(&token).is_err(), "token signed with the wrong key rejected");
    }

    // #21 WC3: cover the RS256/Keycloak production constructor (from_rsa_pem) and
    // the OidcError Display — the HS256 tests above already exercise the shared
    // verification logic in subject(). A PUBLIC key is safe to embed (the
    // secret-guard only flags PRIVATE keys); it verifies key parsing, not signing.
    const RSA_PUBLIC_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoPFTleJfOSawf6FySZR1
9ysb7sezGSmNWL4K79aioS06m1/ymzDnXpt5gWcQzLGfP9yydIgbOP6tp2IYBpXb
yKdI5/CLdOV0g7TLSwUtAGAXH+Pl+QvyOL+oTAl2vqKczQ3nwhjDABey0eyBdshh
8DbP9jx72Seq7u9PWz0fk68wxd+QVW5qfcCVJYaCyS2o1OFzF5U1RE2cmQvVs03I
SXkvNCOPHmkffFR4TPb4k9UM1yS+gT1lSm8vTewgKNzLS3mDhsxYq2+bRhtshOEg
Zeq0yWDrACqZViurIS/kcGLrXHcMKGElE6LSdfm+QBzTuwPVpVa8IoKdh4ng5QVx
ZQIDAQAB
-----END PUBLIC KEY-----"#;

    #[test]
    fn from_rsa_pem_builds_a_verifier_from_a_public_key() {
        let v = OidcVerifier::from_rsa_pem(RSA_PUBLIC_PEM.as_bytes(), ISSUER);
        assert!(v.is_ok(), "a valid RSA public key builds an RS256 verifier");
    }

    #[test]
    fn from_rsa_pem_rejects_malformed_pem() {
        let err = OidcVerifier::from_rsa_pem(b"-----BEGIN PUBLIC KEY-----\nnope\n", ISSUER)
            .err()
            .expect("malformed PEM must error");
        assert!(err.to_string().contains("oidc verification failed"), "{err}");
    }

    #[test]
    fn oidc_error_displays_a_reason() {
        let v = OidcVerifier::from_hs_secret(SECRET, ISSUER);
        let token = make_token(b"wrong-key", "user-42", ISSUER, now() + 3600);
        let err = v.subject(&token).expect_err("bad signature errors");
        assert!(
            format!("{err}").starts_with("oidc verification failed:"),
            "Display renders the reason"
        );
    }

    #[test]
    fn jwks_uri_is_derived_from_the_issuer() {
        // #42 KC2: with or without a trailing slash on the issuer.
        assert_eq!(
            jwks_uri_for("https://kc.example/realms/ct-demo"),
            "https://kc.example/realms/ct-demo/protocol/openid-connect/certs"
        );
        assert_eq!(
            jwks_uri_for("https://kc.example/realms/ct-demo/"),
            "https://kc.example/realms/ct-demo/protocol/openid-connect/certs"
        );
    }

    #[test]
    fn jwks_signing_key_selects_the_rs256_sig_key_among_decoys() {
        // #42 KC2: a realm JWKS carries several keys — an EC key, an RSA
        // *encryption* key, and the RSA *signing* key. Only the last is the token
        // verification key; the selector must skip the others.
        let jwks = serde_json::json!({
            "keys": [
                { "kty": "EC", "use": "sig", "crv": "P-256", "x": "aa", "y": "bb" },
                { "kty": "RSA", "use": "enc", "alg": "RSA-OAEP", "n": "ENC-N", "e": "AQAB" },
                { "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1", "n": "SIG-N", "e": "AQAB" }
            ]
        });
        assert_eq!(
            jwks_signing_key(&jwks),
            Some(("SIG-N".to_string(), "AQAB".to_string())),
            "picks the RSA RS256 sig key, not the EC or the RSA enc key"
        );

        // A key with `use`/`alg` absent still qualifies (Keycloak omits them on
        // some realms) as long as it is RSA.
        let bare = serde_json::json!({ "keys": [ { "kty": "RSA", "n": "BARE-N", "e": "AQAB" } ] });
        assert_eq!(jwks_signing_key(&bare), Some(("BARE-N".into(), "AQAB".into())));

        // No RSA signing key -> nothing trusted.
        let none = serde_json::json!({
            "keys": [ { "kty": "EC", "use": "sig", "crv": "P-256", "x": "a", "y": "b" } ]
        });
        assert_eq!(jwks_signing_key(&none), None);
        assert_eq!(jwks_signing_key(&serde_json::json!({})), None, "no keys array -> None");
    }

    #[test]
    fn from_rsa_components_rejects_malformed_components() {
        // Invalid base64url components must surface as an error, not a panic — the
        // startup path treats that as "SSO key unavailable".
        let err = OidcVerifier::from_rsa_components("!!not-base64!!", "AQAB", ISSUER);
        assert!(err.is_err(), "garbage modulus is rejected");
    }

    /// Generate a throwaway RSA key AT RUNTIME (never committed — secret-guard
    /// forbids a private key in the tree), returning its base64url JWK components
    /// `(n, e)` and an RS256 token for `sub` signed by the private half.
    fn rsa_jwk_and_token(sub: &str) -> (String, String, String) {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use rsa::pkcs8::{EncodePrivateKey, LineEnding};
        use rsa::traits::PublicKeyParts;
        use rsa::{RsaPrivateKey, RsaPublicKey};

        let mut rng = rand::rngs::OsRng;
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
        let public = RsaPublicKey::from(&private);
        let n = URL_SAFE_NO_PAD.encode(public.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public.e().to_bytes_be());
        let pem = private.to_pkcs8_pem(LineEnding::LF).expect("pkcs8 pem");
        let claims = serde_json::json!({ "sub": sub, "iss": ISSUER, "exp": now() + 3600 });
        let token = encode(
            &Header::new(Algorithm::RS256),
            &claims,
            &EncodingKey::from_rsa_pem(pem.as_bytes()).expect("signing key"),
        )
        .expect("sign RS256");
        (n, e, token)
    }

    #[test]
    fn from_rsa_components_verifies_a_token_signed_by_the_matching_key() {
        // #42 KC2-b: the end-to-end JWKS -> verifier chain from raw components.
        let (n, e, token) = rsa_jwk_and_token("user-99");
        let v = OidcVerifier::from_rsa_components(&n, &e, ISSUER).expect("verifier from components");
        assert_eq!(v.subject(&token).unwrap(), "user-99", "token verifies via JWKS components");

        // A DIFFERENT key's components must reject the token — proving it checks the
        // signature, not merely that the components parse.
        let (on, oe, _) = rsa_jwk_and_token("someone-else");
        let v2 = OidcVerifier::from_rsa_components(&on, &oe, ISSUER).unwrap();
        assert!(v2.subject(&token).is_err(), "a non-matching key rejects the token");
    }

    #[test]
    fn jwks_signing_key_for_kid_selects_by_key_id() {
        // #82: with several signing keys in the JWKS (a rotation window), select the
        // one whose kid matches — not merely the first usable key.
        let jwks = serde_json::json!({"keys": [
            {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "old", "n": "N_OLD", "e": "AQAB"},
            {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "new", "n": "N_NEW", "e": "AQAB"}
        ]});
        assert_eq!(jwks_signing_key_for_kid(&jwks, "new"), Some(("N_NEW".into(), "AQAB".into())));
        assert_eq!(jwks_signing_key_for_kid(&jwks, "old"), Some(("N_OLD".into(), "AQAB".into())));
        assert_eq!(jwks_signing_key_for_kid(&jwks, "absent"), None, "unknown kid -> None");
        // token_kid pulls the kid from a token header.
        let token = encode(
            &{ let mut h = Header::new(Algorithm::HS256); h.kid = Some("new".into()); h },
            &serde_json::json!({"sub": "u", "iss": ISSUER, "exp": now() + 60}),
            &EncodingKey::from_secret(SECRET),
        )
        .unwrap();
        assert_eq!(token_kid(&token).as_deref(), Some("new"));
    }

    #[tokio::test]
    async fn verifier_from_jwks_fetches_selects_and_verifies() {
        // #42 KC2-c: the startup path — fetch the JWKS (injected here), select the
        // RS256 signing key, build the verifier, and verify a real token end-to-end.
        let (n, e, token) = rsa_jwk_and_token("user-77");
        let jwks = serde_json::json!({
            "keys": [
                { "kty": "EC", "use": "sig", "crv": "P-256", "x": "a", "y": "b" },
                { "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1", "n": n, "e": e }
            ]
        });

        let v = verifier_from_jwks(ISSUER, |url| {
            assert!(url.ends_with("/protocol/openid-connect/certs"), "fetches the certs endpoint");
            async move { Some(jwks) }
        })
        .await
        .expect("verifier built from the fetched JWKS");
        assert_eq!(v.subject(&token).unwrap(), "user-77", "fetched key verifies the token");

        // A failed fetch -> None (endpoints stay disabled, no panic).
        assert!(
            verifier_from_jwks(ISSUER, |_url| async { None }).await.is_none(),
            "no JWKS -> no verifier"
        );
        // A JWKS with no RSA signing key -> None.
        let ec_only = serde_json::json!({ "keys": [ { "kty": "EC", "use": "sig" } ] });
        assert!(
            verifier_from_jwks(ISSUER, |_url| async move { Some(ec_only) }).await.is_none(),
            "no RS256 key -> no verifier"
        );
    }

    #[tokio::test]
    async fn verifier_from_jwks_with_retry_recovers_from_transient_failures() {
        // #271: a JWKS fetch that fails the first two attempts (transport error, or a
        // realm that hasn't published its RS256 key yet) and succeeds on the third
        // still yields a working verifier — the one-shot version would give up forever.
        let (n, e, token) = rsa_jwk_and_token("user-271");
        let jwks = serde_json::json!({
            "keys": [{ "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1", "n": n, "e": e }]
        });
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let sleeps = std::sync::atomic::AtomicUsize::new(0);

        let v = verifier_from_jwks_with_retry(
            ISSUER,
            |_url| {
                let n = attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let jwks = jwks.clone();
                async move { if n < 2 { None } else { Some(jwks) } }
            },
            &[0, 10, 10, 10],
            |_ms| {
                sleeps.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async {}
            },
        )
        .await
        .expect("verifier eventually built after transient failures");

        assert_eq!(v.subject(&token).unwrap(), "user-271");
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 3, "third attempt succeeded");
        assert_eq!(sleeps.load(std::sync::atomic::Ordering::SeqCst), 2, "slept before attempts 2 and 3, not before the first");
    }

    #[tokio::test]
    async fn verifier_from_jwks_with_retry_gives_up_after_the_last_delay() {
        // A realm that genuinely never has a usable key still returns None -- this is
        // resilience against transient failures, not an infinite/unbounded retry.
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let result = verifier_from_jwks_with_retry(
            ISSUER,
            |_url| {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async { None }
            },
            &[0, 10, 10],
            |_ms| async {},
        )
        .await;
        assert!(result.is_none());
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 3, "tried exactly len(delays_ms) times");
    }
}
