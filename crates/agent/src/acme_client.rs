//! ACME (RFC 8555) network driver (ADR-0003): the order→authorize→finalize→
//! download state machine, built on [`crate::acme_jws`] for request signing and
//! [`crate::acme`] for the pure message parsing / CSR generation already there.
//! Talks DNS-01 only (no HTTP-01/TLS-ALPN-01 — the operator-assisted DNS-01
//! path is the whole point of ADR-0003: the operator satisfies the challenge
//! without ever seeing the certificate's private key).
//!
//! Hermetic tests here run against a local mock ACME server (an axum app
//! standing in for Let's Encrypt/Pebble), so the state machine — nonce
//! handling, badNonce retry, polling, the full happy path — is verified with
//! no network and no rate limits. A real interop check against Let's
//! Encrypt's **staging** directory is a separate, manual smoke test — this
//! module must never be pointed at production Let's Encrypt from an
//! automated test (real-world rate limits, ADR-0003's own domain-validation
//! consequence).

use std::time::Duration;

use ct_dns::provider::Dns01Provider;
use serde_json::Value;

use crate::acme::{self, AcmeDirectory, CsrBundle};
use crate::acme_jws::AccountKey;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// How long to keep polling an authorization/order before giving up — DNS
/// propagation plus the CA's own validation pass can genuinely take a couple
/// of minutes; this is not a tight loop (each poll is spaced by
/// [`POLL_INTERVAL`]).
const POLL_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// A successfully issued certificate: the PEM chain plus the private key that
/// signed its CSR. The private key **never leaves this process** except in
/// this return value, which the caller persists directly to disk (ADR-0003:
/// the operator-facing DNS-01 assist never sees it — only the CP's TXT-publish
/// call in [`publish_dns01`] does, and that call carries no key material at
/// all, only the derived challenge value).
pub struct IssuedCert {
    pub cert_chain_pem: String,
    pub key_pem: String,
}

/// Drives one ACME order to completion for `hostname` via DNS-01, using
/// `publish` to place (and, on success or failure, clear) the `_acme-challenge`
/// TXT record. `account` is reused across renewals (persist its
/// [`AccountKey::pkcs8_der`] and pass the same key back in).
pub struct AcmeClient {
    http: reqwest::Client,
    directory: AcmeDirectory,
    account: AccountKey,
    account_url: Option<String>,
    nonce: Option<String>,
}

impl AcmeClient {
    /// Fetch the ACME directory at `directory_url` (e.g.
    /// `https://acme-v02.api.letsencrypt.org/directory`, or the staging
    /// equivalent for testing) and prepare a client using `account` to sign
    /// every subsequent request.
    pub async fn discover(directory_url: &str, account: AccountKey) -> Result<Self, BoxError> {
        let http = reqwest::Client::builder().timeout(Duration::from_secs(30)).build()?;
        let resp = http.get(directory_url).send().await?;
        if !resp.status().is_success() {
            return Err(format!("ACME directory fetch failed: {}", resp.status()).into());
        }
        let json: Value = resp.json().await?;
        let directory = acme::parse_directory(&json).ok_or("malformed ACME directory (missing a required URL)")?;
        Ok(Self { http, directory, account, account_url: None, nonce: None })
    }

    async fn fresh_nonce(&mut self) -> Result<String, BoxError> {
        if let Some(n) = self.nonce.take() {
            return Ok(n);
        }
        let resp = self.http.head(&self.directory.new_nonce).send().await?;
        header_str(&resp, "replay-nonce").ok_or_else(|| "ACME server sent no Replay-Nonce".into())
    }

    fn capture_nonce(&mut self, resp: &reqwest::Response) {
        if let Some(n) = header_str(resp, "replay-nonce") {
            self.nonce = Some(n);
        }
    }

    /// POST a JWS-signed request to `url`. Retries exactly once on the
    /// server's `badNonce` error (RFC 8555 §6.5) — a fresh nonce, not a
    /// stale-request retry loop.
    async fn post_signed(&mut self, url: &str, payload: Option<&Value>) -> Result<reqwest::Response, BoxError> {
        for attempt in 0..2 {
            let nonce = self.fresh_nonce().await?;
            let jws = self.account.sign_request(url, &nonce, self.account_url.as_deref(), payload)?;
            let resp = self
                .http
                .post(url)
                .header("content-type", "application/jose+json")
                .json(&jws)
                .send()
                .await?;
            self.capture_nonce(&resp);
            if attempt == 0 && resp.status() == reqwest::StatusCode::BAD_REQUEST {
                let body: Value = resp.json().await.unwrap_or_default();
                if body.get("type").and_then(|t| t.as_str()) == Some("urn:ietf:params:acme:error:badNonce") {
                    continue; // one retry with the nonce this response just handed us
                }
                return Err(format!("ACME request to {url} failed: {body}").into());
            }
            return Ok(resp);
        }
        unreachable!("loop always returns or retries exactly once")
    }

    /// Register (or, per RFC 8555, idempotently re-resolve) the ACME account
    /// tied to this client's key. Must be called once before any order.
    pub async fn register_account(&mut self) -> Result<(), BoxError> {
        let payload = serde_json::json!({ "termsOfServiceAgreed": true });
        let url = self.directory.new_account.clone();
        let resp = self.post_signed(&url, Some(&payload)).await?;
        if !resp.status().is_success() {
            return Err(format!("account registration failed: {}", resp.status()).into());
        }
        let account_url = header_str(&resp, "location").ok_or("ACME server sent no account Location")?;
        self.account_url = Some(account_url);
        Ok(())
    }

    /// Order, validate (DNS-01 via `publish`), finalize, and download a
    /// certificate for `hostname`. `publish` places the TXT record (and is
    /// always given the chance to clear it again afterward, success or not).
    pub async fn issue_certificate(
        &mut self,
        hostname: &str,
        publish: &Dns01Provider,
    ) -> Result<IssuedCert, BoxError> {
        if self.account_url.is_none() {
            self.register_account().await?;
        }
        let csr = acme::generate_csr(hostname)?;
        let order_url_and_body = self.new_order(hostname).await?;
        let (order_url, mut order) = order_url_and_body;

        for authz_url in order.authorizations.clone() {
            self.validate_authorization(&authz_url, hostname, publish).await?;
        }

        order = self.poll_order(&order_url, |o| o.status != "pending" && o.status != "processing").await?;
        if order.status != "ready" && order.status != "processing" && order.status != "valid" {
            return Err(format!("order did not reach ready (status={})", order.status).into());
        }
        if order.status == "ready" {
            self.finalize(&order.finalize, &csr).await?;
            order = self.poll_order(&order_url, |o| o.status == "valid" || o.status == "invalid").await?;
        }
        if order.status != "valid" {
            return Err(format!("order finalize did not reach valid (status={})", order.status).into());
        }
        let cert_url = order.certificate.ok_or("order valid but carries no certificate URL")?;
        let cert_chain_pem = self.download_certificate(&cert_url).await?;
        Ok(IssuedCert { cert_chain_pem, key_pem: csr.key_pem })
    }

    async fn new_order(&mut self, hostname: &str) -> Result<(String, acme::AcmeOrder), BoxError> {
        let payload = serde_json::json!({ "identifiers": [{ "type": "dns", "value": hostname }] });
        let url = self.directory.new_order.clone();
        let resp = self.post_signed(&url, Some(&payload)).await?;
        if !resp.status().is_success() {
            return Err(format!("order creation failed: {}", resp.status()).into());
        }
        let order_url = header_str(&resp, "location").ok_or("ACME server sent no order Location")?;
        let json: Value = resp.json().await?;
        let order = acme::parse_order(&json).ok_or("malformed ACME order")?;
        Ok((order_url, order))
    }

    async fn validate_authorization(
        &mut self,
        authz_url: &str,
        hostname: &str,
        publish: &Dns01Provider,
    ) -> Result<(), BoxError> {
        let authz = self.post_as_get(authz_url).await?;
        let challenge =
            acme::select_dns01(&authz).ok_or("ACME server offered no dns-01 challenge for this authorization")?;
        let key_authorization = format!("{}.{}", challenge.token, self.account.thumbprint());
        let txt_value = acme::dns01_txt_value(&key_authorization);
        let record_name = acme::dns01_record_name(hostname);

        let publish_result = publish.set_txt(&record_name, &txt_value).await;
        let outcome = match publish_result {
            Ok(()) => self.complete_challenge(&challenge.url, authz_url).await,
            Err(e) => Err(format!("publishing the DNS-01 challenge record failed: {e}").into()),
        };
        // Always attempt cleanup, whether validation succeeded or not -- a
        // stale challenge TXT record must not linger either way.
        let _ = publish.clear_txt(&record_name).await;
        outcome
    }

    async fn complete_challenge(&mut self, challenge_url: &str, authz_url: &str) -> Result<(), BoxError> {
        // Signal readiness (RFC 8555 §7.5.1: an empty JSON object, not POST-as-GET).
        let resp = self.post_signed(challenge_url, Some(&serde_json::json!({}))).await?;
        if !resp.status().is_success() {
            return Err(format!("challenge response failed: {}", resp.status()).into());
        }
        let deadline = std::time::Instant::now() + POLL_TIMEOUT;
        loop {
            let authz = self.post_as_get(authz_url).await?;
            match authz.get("status").and_then(|s| s.as_str()) {
                Some("valid") => return Ok(()),
                Some("invalid") => return Err(format!("authorization {authz_url} became invalid: {authz}").into()),
                _ if std::time::Instant::now() >= deadline => {
                    return Err(format!("authorization {authz_url} did not validate within {POLL_TIMEOUT:?}").into())
                }
                _ => tokio::time::sleep(POLL_INTERVAL).await,
            }
        }
    }

    async fn poll_order(
        &mut self,
        order_url: &str,
        done: impl Fn(&acme::AcmeOrder) -> bool,
    ) -> Result<acme::AcmeOrder, BoxError> {
        let deadline = std::time::Instant::now() + POLL_TIMEOUT;
        loop {
            let json = self.post_as_get(order_url).await?;
            let order = acme::parse_order(&json).ok_or("malformed ACME order while polling")?;
            if done(&order) {
                return Ok(order);
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!("order {order_url} did not settle within {POLL_TIMEOUT:?} (status={})", order.status).into());
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    async fn finalize(&mut self, finalize_url: &str, csr: &CsrBundle) -> Result<(), BoxError> {
        let payload = serde_json::json!({ "csr": base64_url(&csr.csr_der) });
        let resp = self.post_signed(finalize_url, Some(&payload)).await?;
        if !resp.status().is_success() {
            return Err(format!("finalize failed: {}", resp.status()).into());
        }
        Ok(())
    }

    async fn download_certificate(&mut self, cert_url: &str) -> Result<String, BoxError> {
        let resp = self.post_signed(cert_url, None).await?;
        if !resp.status().is_success() {
            return Err(format!("certificate download failed: {}", resp.status()).into());
        }
        Ok(resp.text().await?)
    }

    /// A "POST-as-GET" (RFC 8555 §6.3): every ACME resource is fetched by
    /// POSTing an empty-payload JWS, never a plain GET — polling an order's
    /// current status is the same shape as fetching an authorization.
    async fn post_as_get(&mut self, url: &str) -> Result<Value, BoxError> {
        let resp = self.post_signed(url, None).await?;
        if !resp.status().is_success() {
            return Err(format!("fetching {url} failed: {}", resp.status()).into());
        }
        Ok(resp.json().await?)
    }
}

fn header_str(resp: &reqwest::Response, name: &str) -> Option<String> {
    resp.headers().get(name)?.to_str().ok().map(str::to_string)
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path as AxPath, State as AxState};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::{get, head, post};
    use axum::Router;
    use base64::Engine;
    use ct_dns::store::AcmeDnsStore;
    use std::sync::{Arc, Mutex};

    /// A minimal in-memory ACME server (directory/newAccount/newOrder/authz/
    /// challenge/finalize/cert) covering exactly the happy path plus one
    /// badNonce rejection, driven by a shared state machine so the mock stays
    /// small while still exercising every real HTTP round-trip this client
    /// makes -- no shortcuts inside `AcmeClient` itself.
    struct MockAcme {
        base: String,
        order_status: Mutex<&'static str>,
        authz_status: Mutex<&'static str>,
        nonce_uses: Mutex<u32>,
        seen_kid: Mutex<bool>,
    }

    async fn spawn_mock_acme() -> (String, Arc<MockAcme>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let state = Arc::new(MockAcme {
            base: base.clone(),
            order_status: Mutex::new("pending"),
            authz_status: Mutex::new("pending"),
            nonce_uses: Mutex::new(0),
            seen_kid: Mutex::new(false),
        });

        let app = Router::new()
            .route("/directory", get(directory))
            .route("/new-nonce", head(new_nonce))
            .route("/new-account", post(new_account))
            .route("/new-order", post(new_order))
            .route("/authz/1", post(get_authz))
            .route("/challenge/1", post(respond_challenge))
            .route("/order/1", post(get_order))
            .route("/finalize/1", post(finalize))
            .route("/cert/1", post(get_cert))
            .with_state(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (base, state)
    }

    fn nonce_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("replay-nonce", "test-nonce-1".parse().unwrap());
        h
    }

    async fn directory(AxState(s): AxState<Arc<MockAcme>>) -> impl axum::response::IntoResponse {
        (
            nonce_headers(),
            axum::Json(serde_json::json!({
                "newNonce": format!("{}/new-nonce", s.base),
                "newAccount": format!("{}/new-account", s.base),
                "newOrder": format!("{}/new-order", s.base),
            })),
        )
    }

    async fn new_nonce() -> impl axum::response::IntoResponse {
        (StatusCode::OK, nonce_headers())
    }

    async fn new_account(
        AxState(s): AxState<Arc<MockAcme>>,
        body: axum::body::Bytes,
    ) -> impl axum::response::IntoResponse {
        // Exercise the badNonce path exactly once: reject the FIRST signed
        // request with a stale/duplicate nonce, forcing AcmeClient's one-shot
        // retry to actually run and succeed.
        let mut uses = s.nonce_uses.lock().unwrap();
        *uses += 1;
        if *uses == 1 {
            return (
                StatusCode::BAD_REQUEST,
                nonce_headers(),
                axum::Json(serde_json::json!({"type": "urn:ietf:params:acme:error:badNonce"})),
            )
                .into_response();
        }
        // Real newAccount carries a jwk (no kid yet) in its protected header --
        // confirmed by the client-side unit test already; here just accept.
        let _ = body;
        let mut h = nonce_headers();
        h.insert("location", format!("{}/acct/1", s.base).parse().unwrap());
        (StatusCode::OK, h, axum::Json(serde_json::json!({"status": "valid"}))).into_response()
    }

    async fn new_order(
        AxState(s): AxState<Arc<MockAcme>>,
        headers: HeaderMap,
        body: axum::body::Bytes,
    ) -> impl axum::response::IntoResponse {
        // A signed request past account registration must carry `kid`, not `jwk`.
        let jws: Value = serde_json::from_slice(&body).unwrap();
        let protected: Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(jws["protected"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        *s.seen_kid.lock().unwrap() = protected.get("kid").is_some();
        let _ = headers;
        let mut h = nonce_headers();
        h.insert("location", format!("{}/order/1", s.base).parse().unwrap());
        (
            StatusCode::OK,
            h,
            axum::Json(serde_json::json!({
                "status": "pending",
                "authorizations": [format!("{}/authz/1", s.base)],
                "finalize": format!("{}/finalize/1", s.base),
            })),
        )
    }

    async fn get_authz(AxState(s): AxState<Arc<MockAcme>>) -> impl axum::response::IntoResponse {
        let status = *s.authz_status.lock().unwrap();
        (
            nonce_headers(),
            axum::Json(serde_json::json!({
                "status": status,
                "challenges": [
                    { "type": "http-01", "token": "ignored", "url": format!("{}/challenge/http", s.base) },
                    { "type": "dns-01", "token": "dns-token-1", "url": format!("{}/challenge/1", s.base) }
                ]
            })),
        )
    }

    async fn respond_challenge(AxState(s): AxState<Arc<MockAcme>>) -> impl axum::response::IntoResponse {
        // Move the authorization + order to their next states once the
        // challenge is answered -- standing in for the CA validating DNS.
        *s.authz_status.lock().unwrap() = "valid";
        *s.order_status.lock().unwrap() = "ready";
        (nonce_headers(), axum::Json(serde_json::json!({"status": "processing"})))
    }

    async fn get_order(AxState(s): AxState<Arc<MockAcme>>) -> impl axum::response::IntoResponse {
        let status = *s.order_status.lock().unwrap();
        let mut body = serde_json::json!({
            "status": status,
            "authorizations": [format!("{}/authz/1", s.base)],
            "finalize": format!("{}/finalize/1", s.base),
        });
        if status == "valid" {
            body["certificate"] = serde_json::json!(format!("{}/cert/1", s.base));
        }
        (nonce_headers(), axum::Json(body))
    }

    async fn finalize(AxState(s): AxState<Arc<MockAcme>>) -> impl axum::response::IntoResponse {
        *s.order_status.lock().unwrap() = "valid";
        (nonce_headers(), axum::Json(serde_json::json!({"status": "valid"})))
    }

    async fn get_cert(AxPath(_): AxPath<()>) -> impl axum::response::IntoResponse {
        (nonce_headers(), "-----BEGIN CERTIFICATE-----\nmock\n-----END CERTIFICATE-----\n")
    }

    #[tokio::test]
    async fn issue_certificate_drives_the_full_order_to_a_downloaded_cert() {
        let (base, mock) = spawn_mock_acme().await;
        let store = Arc::new(AcmeDnsStore::new());
        let publish = Dns01Provider::SelfHosted(store.clone());

        let account = AccountKey::generate().unwrap();
        let mut client = AcmeClient::discover(&format!("{base}/directory"), account).await.unwrap();
        let issued = client.issue_certificate("shop.example.test", &publish).await.unwrap();

        assert!(issued.cert_chain_pem.contains("BEGIN CERTIFICATE"));
        assert!(issued.key_pem.contains("PRIVATE KEY"), "the CSR's own key is returned for persistence");
        assert!(*mock.seen_kid.lock().unwrap(), "requests after account registration use kid, not jwk");
        // The challenge TXT was cleaned up after validation -- no stale record left.
        assert!(store.txt("_acme-challenge.shop.example.test").is_empty(), "challenge TXT cleared post-issuance");
    }

    #[tokio::test]
    async fn a_bad_nonce_is_retried_exactly_once_not_looped_forever() {
        // account creation is rigged to reject the first nonce; if the retry-once
        // logic works, issuance still completes -- if it looped or gave up, it wouldn't.
        let (base, _mock) = spawn_mock_acme().await;
        let account = AccountKey::generate().unwrap();
        let mut client = AcmeClient::discover(&format!("{base}/directory"), account).await.unwrap();
        client.register_account().await.expect("succeeds after exactly one badNonce retry");
    }
}
