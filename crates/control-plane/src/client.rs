//! HTTP client for the running control-plane service (M13.4a).
//!
//! The service exposes enrollment + registry/rendezvous over JSON (see
//! [`crate::http`]). This client lets an Agent enroll and register its tunnel,
//! and a Client resolve a routing token, against a *running* control plane —
//! the piece that turns the in-memory library into a hosted service (ADR-0017).
//! Plaintext HTTP only; this client's own traffic (enrollment, registry,
//! rendezvous) carries no payload and no trust material. That's narrower than
//! "the control plane holds no trust material" — it doesn't hold Agent/CA
//! private keys, but does hold operator secrets where configured (the
//! credential-issuer signing key, per-CA EAB credentials, DNS-provider
//! tokens) on other endpoints this client doesn't call (#266).

use serde::Deserialize;

use ct_common::{AgentId, RoutingToken, TenantId};

/// A thin HTTP client bound to one control-plane base URL (e.g.
/// `http://control-plane:8090`).
pub struct ControlPlaneClient {
    base: String,
    http: reqwest::Client,
    /// Optional shared admin token (hex) presented as `x-ct-admin-token` on the
    /// machine/operator writer routes the durable CP gates (#87 SEC87b-auth):
    /// `/enroll/issue`, `/registry/register`, `/accounts/open`, `/payment/intent`,
    /// `/billing/issue`. `None` → no header (dev/back-compat, ungated CP).
    admin_token: Option<String>,
}

/// Errors talking to the control-plane service.
#[derive(Debug)]
pub enum CpError {
    /// Transport-level failure (connect, timeout, body).
    Http(reqwest::Error),
    /// The service answered with a non-success status.
    Status(reqwest::StatusCode),
    /// #747: a non-success status whose plain-text body is worth showing the user
    /// verbatim (today only [`ControlPlaneClient::register_channel`]'s `409`, whose
    /// body tells the operator how to opt in to a re-key). A separate variant rather
    /// than widening [`CpError::Status`] so every existing `Status(_)` match keeps
    /// working; use [`CpError::status`] to inspect either uniformly.
    StatusWithBody(reqwest::StatusCode, String),
    /// A field could not be decoded (e.g. a token that is not 32 hex bytes).
    Malformed,
}

impl CpError {
    /// The HTTP status behind a [`CpError::Status`] or [`CpError::StatusWithBody`].
    pub fn status(&self) -> Option<reqwest::StatusCode> {
        match self {
            CpError::Status(s) | CpError::StatusWithBody(s, _) => Some(*s),
            CpError::Http(_) | CpError::Malformed => None,
        }
    }
}

impl std::fmt::Display for CpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CpError::Http(e) => write!(f, "control-plane request failed: {e}"),
            CpError::Status(s) => write!(f, "control-plane returned status {s}"),
            CpError::StatusWithBody(s, body) if body.trim().is_empty() => {
                write!(f, "control-plane returned status {s}")
            }
            CpError::StatusWithBody(s, body) => write!(f, "control-plane returned status {s}: {}", body.trim()),
            CpError::Malformed => write!(f, "control-plane returned a malformed field"),
        }
    }
}

impl std::error::Error for CpError {}

impl From<reqwest::Error> for CpError {
    fn from(e: reqwest::Error) -> Self {
        CpError::Http(e)
    }
}

type CpResult<T> = Result<T, CpError>;

/// #408: the same `OnceLock`-cached-client-with-timeout shape this codebase already
/// established twice (`main.rs::jwks_fetch_client` for #295, `portal_api.rs::
/// edge_admin_http_client`) -- a bare `reqwest::Client::new()` has no request or connect
/// timeout, so every method on [`ControlPlaneClient`] could block indefinitely against a
/// control plane that accepts the TCP connection and never answers. Bites hardest on the
/// payment path: `buy_token_idempotent` exists precisely so a retry after a lost response
/// is safe, but with no timeout the caller never reaches the retry in the first place.
fn control_plane_http_client() -> reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .connect_timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new())
        })
        .clone()
}

impl ControlPlaneClient {
    /// Bind the client to a base URL. A trailing slash is trimmed.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base: base_url.into().trim_end_matches('/').to_string(),
            http: control_plane_http_client(),
            admin_token: None,
        }
    }

    /// Present `token_hex` as the `x-ct-admin-token` on the gated writer routes
    /// (#87 SEC87b-auth), so this client can drive them against a CP that has the
    /// shared admin token configured (e.g. an operator selftest). Ungated routes
    /// are unaffected.
    pub fn with_admin_token(mut self, token_hex: impl Into<String>) -> Self {
        self.admin_token = Some(token_hex.into());
        self
    }

    /// Attach the admin token header to a request builder when one is configured.
    fn admin(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.admin_token {
            Some(tok) => rb.header("x-ct-admin-token", tok),
            None => rb,
        }
    }

    /// `POST /enroll/issue` — mint a single-use join token for a tenant.
    pub async fn issue_join_token(&self, tenant: &TenantId) -> CpResult<[u8; 32]> {
        let resp = self
            .admin(self.http.post(format!("{}/enroll/issue", self.base)))
            .json(&serde_json::json!({ "tenant": tenant.0 }))
            .send()
            .await?;
        let resp = ok(resp)?;
        let body: TokenBody = resp.json().await?;
        hex_decode_32(&body.token).ok_or(CpError::Malformed)
    }

    /// `POST /enroll/redeem` — redeem a join token, binding this Agent's public
    /// key to the tenant. `proof` is the Agent's ed25519 signature over the join
    /// token (#88 SEC88c), proving it holds the private key for `pubkey`; the
    /// durable control plane rejects a redemption whose proof doesn't match.
    /// Returns the bound tenant.
    pub async fn redeem(
        &self,
        join_token: &[u8; 32],
        agent: &AgentId,
        pubkey: &[u8; 32],
        proof: &[u8; 64],
    ) -> CpResult<TenantId> {
        let resp = self
            .http
            .post(format!("{}/enroll/redeem", self.base))
            .json(&serde_json::json!({
                "token": hex_encode(join_token),
                "agent": agent.0,
                "pubkey": hex_encode(pubkey),
                "proof": hex_encode(proof),
            }))
            .send()
            .await?;
        let resp = ok(resp)?;
        let body: TenantBody = resp.json().await?;
        Ok(TenantId(body.tenant))
    }

    /// `POST /me/signup` (anti-abuse repeat-signup mitigation) — `ct-agent signup`'s
    /// own entry point: self-service tunnel creation via the Bearer-JWT `ct-agent
    /// login`'s device-code flow already obtains, instead of a portal session
    /// cookie. `device_fingerprint` is `sha256(machine_id || "\0" || os_username)`
    /// (see `ct_agent::signup` for exactly what feeds it); `None` skips the
    /// control-plane's repeat-account cap entirely (fail-open, matches every other
    /// caller of the underlying account-creation path). Returns the routing token
    /// so the caller can start serving immediately with no manual copy-paste.
    pub async fn signup(
        &self,
        name: &str,
        bearer_token: &str,
        device_fingerprint: Option<&str>,
    ) -> CpResult<SignupResult> {
        let resp = self
            .http
            .post(format!("{}/me/signup", self.base))
            .header("authorization", format!("Bearer {bearer_token}"))
            .json(&serde_json::json!({
                "name": name,
                "device_fingerprint": device_fingerprint,
            }))
            .send()
            .await?;
        let resp = ok(resp)?;
        let body: SignupResponseBody = resp.json().await?;
        Ok(SignupResult { routing_token: body.routing_token, hostname: body.hostname })
    }

    /// `GET /pki/ca` — fetch the edge CA root DER the control plane publishes
    /// (#11), so a cross-host Agent/Client can obtain the trust root over HTTP
    /// instead of copying it out of band. Public key material only.
    pub async fn fetch_edge_cert(&self) -> CpResult<Vec<u8>> {
        let resp = self.http.get(format!("{}/pki/ca", self.base)).send().await?;
        let resp = ok(resp)?;
        Ok(resp.bytes().await?.to_vec())
    }

    /// `POST /registry/register` — register a tunnel's routing token.
    pub async fn register(
        &self,
        token: &RoutingToken,
        tenant: &TenantId,
        agent: &AgentId,
    ) -> CpResult<()> {
        let resp = self
            .admin(self.http.post(format!("{}/registry/register", self.base)))
            .json(&serde_json::json!({
                "token": hex_encode(&token.0),
                "tenant": tenant.0,
                "agent": agent.0,
            }))
            .send()
            .await?;
        ok(resp)?;
        Ok(())
    }

    /// `GET /registry/resolve/:token` — the Rendezvous lookup. Returns the
    /// `(tenant, agent)` bound to the routing token, or [`CpError::Status`]
    /// (404) if unknown.
    pub async fn resolve(&self, token: &RoutingToken) -> CpResult<(TenantId, AgentId)> {
        let resp = self
            .http
            .get(format!("{}/registry/resolve/{}", self.base, hex_encode(&token.0)))
            .send()
            .await?;
        let resp = ok(resp)?;
        let body: ResolveBody = resp.json().await?;
        Ok((TenantId(body.tenant), AgentId(body.agent)))
    }

    /// `POST /accounts/open` — open a fresh pseudonymous account (M15.4b).
    pub async fn open_account(&self) -> CpResult<[u8; 32]> {
        let resp = self
            .admin(self.http.post(format!("{}/accounts/open", self.base)))
            .send()
            .await?;
        let resp = ok(resp)?;
        let body: AccountBody = resp.json().await?;
        hex_decode_32(&body.account).ok_or(CpError::Malformed)
    }

    /// `POST /payment/intent` — register a prepaid top-up intent; returns the
    /// opaque payment id to confirm.
    pub async fn create_payment_intent(&self, account: &[u8; 32], credits: u64) -> CpResult<[u8; 32]> {
        let resp = self
            .admin(self.http.post(format!("{}/payment/intent", self.base)))
            .json(&serde_json::json!({ "account": hex_encode(account), "credits": credits }))
            .send()
            .await?;
        let resp = ok(resp)?;
        let body: PaymentBody = resp.json().await?;
        hex_decode_32(&body.payment).ok_or(CpError::Malformed)
    }

    /// `POST /payment/confirm` — confirm a payment; returns the new balance.
    pub async fn confirm_payment(&self, payment: &[u8; 32]) -> CpResult<u64> {
        let resp = self
            .http
            .post(format!("{}/payment/confirm", self.base))
            .json(&serde_json::json!({ "payment": hex_encode(payment) }))
            .send()
            .await?;
        let resp = ok(resp)?;
        let body: BalanceBody = resp.json().await?;
        Ok(body.balance)
    }

    /// `POST /billing/issue` — buy a routing token, charging `price` credits to
    /// the account. A [`CpError::Status`] (402) means insufficient credit.
    ///
    /// No idempotency protection (#272): a lost response after a successful debit means
    /// the account was charged with no recoverable token, and a caller-initiated retry
    /// debits again. Prefer [`Self::buy_token_idempotent`] for any caller that might retry.
    pub async fn buy_token(&self, account: &[u8; 32], price: u64) -> CpResult<RoutingToken> {
        let resp = self
            .admin(self.http.post(format!("{}/billing/issue", self.base)))
            .json(&serde_json::json!({ "account": hex_encode(account), "price": price }))
            .send()
            .await?;
        let resp = ok(resp)?;
        let body: TokenBody = resp.json().await?;
        Ok(RoutingToken(hex_decode_32(&body.token).ok_or(CpError::Malformed)?))
    }

    /// [`Self::buy_token`] with a caller-supplied idempotency key (#272, 64-hex, like every
    /// other token in this API): retrying this exact call with the SAME key after a lost
    /// response (crash, timeout, network drop) returns the same already-minted token
    /// instead of debiting the account a second time. Generate a fresh random key per
    /// logical purchase attempt (not per HTTP call) and reuse it across retries of that
    /// same attempt.
    pub async fn buy_token_idempotent(
        &self,
        account: &[u8; 32],
        price: u64,
        idempotency_key: &[u8; 32],
    ) -> CpResult<RoutingToken> {
        let resp = self
            .admin(self.http.post(format!("{}/billing/issue", self.base)))
            .json(&serde_json::json!({
                "account": hex_encode(account),
                "price": price,
                "idempotency_key": hex_encode(idempotency_key),
            }))
            .send()
            .await?;
        let resp = ok(resp)?;
        let body: TokenBody = resp.json().await?;
        Ok(RoutingToken(hex_decode_32(&body.token).ok_or(CpError::Malformed)?))
    }

    /// `POST /me/channels` — register a channel authority (#117 operator-register).
    /// Binds `channel_hex` (64-hex channel id) to `operator_pubkey_hex` (64-hex operator
    /// ed25519 public key) under the caller's OIDC subject (owner = the bearer token's
    /// subject), so the edge accepts the member grants that operator later signs — the
    /// last control-plane round-trip for an end-to-end self-service Agent-Fabric channel.
    /// Presents the OIDC token as `Authorization: Bearer`; the channel router is
    /// owner-scoped. Non-success answers come back as [`CpError::StatusWithBody`]
    /// carrying the service's plain-text reason: (403) the channel already belongs
    /// to a different subject, (401) the token was missing/invalid, and (#747) (409)
    /// the channel is already registered by this subject with a DIFFERENT operator
    /// key -- re-registering the same key is an idempotent 200, but a rotation must
    /// be opted into with `confirm_rekey = true` (which only adds the field to the
    /// wire request when set, so older control planes see the old shape). The 409
    /// body says exactly that, so callers should print it verbatim.
    pub async fn register_channel(
        &self,
        channel_hex: &str,
        operator_pubkey_hex: &str,
        bearer_token: &str,
        confirm_rekey: bool,
    ) -> CpResult<()> {
        let mut body = serde_json::json!({
            "channel": channel_hex,
            "operator_pubkey": operator_pubkey_hex,
        });
        if confirm_rekey {
            body["confirm_rekey"] = serde_json::Value::Bool(true);
        }
        let resp = self
            .http
            .post(format!("{}/me/channels", self.base))
            .header("authorization", format!("Bearer {bearer_token}"))
            .json(&body)
            .send()
            .await?;
        ok_with_body(resp).await?;
        Ok(())
    }

    /// `POST /me/channels/:channel/allowlist` (#248-follow) — allow-list `email` for
    /// self-service claiming on `channel` (owner-scoped: `bearer_token`'s subject must
    /// own it). Lets an operator manage the channel's allow-list from `ct-agent`
    /// instead of only the portal web UI.
    pub async fn channel_allowlist_add(&self, channel_hex: &str, email: &str, bearer_token: &str) -> CpResult<()> {
        let resp = self
            .http
            .post(format!("{}/me/channels/{channel_hex}/allowlist", self.base))
            .header("authorization", format!("Bearer {bearer_token}"))
            .json(&serde_json::json!({ "email": email }))
            .send()
            .await?;
        ok(resp)?;
        Ok(())
    }

    /// `POST /me/channels/:channel/allowlist/:email/remove` (#248-follow) — de-list
    /// `email` (owner-scoped). Only stops a *future* claim; an already-claimed member
    /// keeps their grant.
    pub async fn channel_allowlist_remove(&self, channel_hex: &str, email: &str, bearer_token: &str) -> CpResult<()> {
        let resp = self
            .http
            .post(format!(
                "{}/me/channels/{channel_hex}/allowlist/{}/remove",
                self.base,
                urlencode_path_segment(email),
            ))
            .header("authorization", format!("Bearer {bearer_token}"))
            .send()
            .await?;
        ok(resp)?;
        Ok(())
    }

    /// `GET /me/channels/:channel/allowlist` (#248-follow) — list allow-listed emails
    /// (owner-scoped).
    pub async fn channel_allowlist_list(&self, channel_hex: &str, bearer_token: &str) -> CpResult<Vec<String>> {
        let resp = self
            .http
            .get(format!("{}/me/channels/{channel_hex}/allowlist", self.base))
            .header("authorization", format!("Bearer {bearer_token}"))
            .send()
            .await?;
        let resp = ok(resp)?;
        let body: AllowlistBody = resp.json().await?;
        Ok(body.emails)
    }

    /// `POST /registry/agents` (#144 ②, #214 follow-up: automatic discoverability) — self-register
    /// (upsert) a published `card_url` + advertised facets, gated by the shared admin token (see
    /// [`Self::with_admin_token`]) rather than an OIDC bearer, since an autonomous agent has no
    /// interactive login path (#161). `card_url` must be `https://` — the CP rejects anything else.
    pub async fn register_agent(
        &self,
        holder_pubkey_hex: &str,
        card_url: &str,
        role_tags: &[String],
        skill_ids: &[String],
    ) -> CpResult<()> {
        let resp = self
            .admin(self.http.post(format!("{}/registry/agents", self.base)))
            .json(&serde_json::json!({
                "holder_pubkey": holder_pubkey_hex,
                "card_url": card_url,
                "role_tags": role_tags,
                "skill_ids": skill_ids,
            }))
            .send()
            .await?;
        ok(resp)?;
        Ok(())
    }
}

/// Map a non-success status to [`CpError::Status`].
fn ok(resp: reqwest::Response) -> CpResult<reqwest::Response> {
    let status = resp.status();
    if status.is_success() {
        Ok(resp)
    } else {
        Err(CpError::Status(status))
    }
}

/// #747: like [`ok`], but a non-success status carries the response text as
/// [`CpError::StatusWithBody`] so an actionable plain-text reason (the channel
/// router's `409` re-key hint) reaches the user instead of a bare status line.
/// An unreadable body degrades to an empty string, never to a transport error.
async fn ok_with_body(resp: reqwest::Response) -> CpResult<reqwest::Response> {
    let status = resp.status();
    if status.is_success() {
        Ok(resp)
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(CpError::StatusWithBody(status, body))
    }
}

/// Percent-encode one URL path segment (RFC 3986 unreserved chars pass through
/// unescaped, everything else — including `@` and `.`'s surrounding bytes when
/// they're not ASCII-alnum/`-`/`_`/`.`/`~` — is escaped). Just enough for an email
/// address in a path segment (`channel_allowlist_remove`); not a general URL encoder.
fn urlencode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[derive(Deserialize)]
struct AllowlistBody {
    emails: Vec<String>,
}

#[derive(Deserialize)]
struct TokenBody {
    token: String,
}
#[derive(Deserialize)]
struct SignupResponseBody {
    routing_token: String,
    hostname: Option<String>,
}
/// [`ControlPlaneClient::signup`]'s success result: the new (or existing, on a
/// re-run) tunnel's routing token and, when DNS is configured on this deployment,
/// its auto-assigned hostname.
#[derive(Debug, Clone)]
pub struct SignupResult {
    pub routing_token: String,
    pub hostname: Option<String>,
}
#[derive(Deserialize)]
struct TenantBody {
    tenant: String,
}
#[derive(Deserialize)]
struct AccountBody {
    account: String,
}
#[derive(Deserialize)]
struct PaymentBody {
    payment: String,
}
#[derive(Deserialize)]
struct BalanceBody {
    balance: u64,
}
#[derive(Deserialize)]
struct ResolveBody {
    tenant: String,
    agent: String,
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// #606: `s.len()` is BYTE length -- a multi-byte UTF-8 char in `s` can pass this guard
/// while a raw `&s[2*i..2*i+2]` slice would land mid-character and panic. Chunk the bytes
/// instead of slicing the `str`.
fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrollment::Enrollment;
    use crate::http::{control_plane_router, BillingState};

    #[test]
    fn hex_decode_32_rejects_rather_than_panics_on_a_multi_byte_char_606() {
        let s: String = "\u{FFFD}".to_string() + &"a".repeat(61);
        assert_eq!(s.len(), 64, "byte-length guard alone would let this through");
        assert_eq!(hex_decode_32(&s), None);
    }
    use crate::registry::TunnelRegistry;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn a_hung_control_plane_times_out_instead_of_blocking_forever_408() {
        // #408: a bare `reqwest::Client::new()` has no request/connect timeout -- prove
        // the real property, not just that the builder call compiles. A real listener
        // that accepts the TCP connection but never writes a response is exactly the
        // "control plane accepts the connection and never answers" scenario the issue
        // describes; the request-level timeout (10s) must fire well before any real
        // hang, not the connect-level one (this is a live loopback accept, not an
        // unroutable address).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            // Hold the connection open forever -- never read the request or write a
            // response. The client's request timeout is the only thing that can end this.
            std::future::pending::<()>().await;
        });

        let client = ControlPlaneClient::new(format!("http://{addr}"));
        let started = std::time::Instant::now();
        let result = client.resolve(&RoutingToken([0x11u8; 32])).await;
        let elapsed = started.elapsed();

        assert!(result.is_err(), "a hung control plane must surface as an error, not hang forever");
        assert!(
            elapsed < std::time::Duration::from_secs(15),
            "must time out around the configured 10s request timeout, not hang indefinitely (took {elapsed:?})"
        );
    }

    /// Spawn the full control-plane router on an ephemeral port; returns its base URL.
    async fn spawn_service() -> String {
        let enr = Arc::new(Mutex::new(Enrollment::new()));
        let reg = Arc::new(Mutex::new(TunnelRegistry::new()));
        let bill = Arc::new(Mutex::new(BillingState::default()));
        let app = control_plane_router(enr, reg, bill);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    /// Full E2E against a *running* service over a real TCP socket: an Agent
    /// enrolls (issue → redeem) and registers its tunnel, then a Client
    /// resolves the routing token — the hosted-control-plane flow (M13.4).
    #[tokio::test]
    async fn client_drives_live_control_plane_service() {
        // Spin up the real service on an ephemeral port.
        let enr = Arc::new(Mutex::new(Enrollment::new()));
        let reg = Arc::new(Mutex::new(TunnelRegistry::new()));
        let app = control_plane_router(enr, reg, Arc::new(Mutex::new(BillingState::default())));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // The listener is already bound, so connections queue even before serve
        // starts accepting — no startup race for the client below.
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let cp = ControlPlaneClient::new(format!("http://{addr}"));
        let agent = AgentId("agent-x".to_string());

        // Agent enrolls: issue a join token, then redeem it to bind the tenant.
        let join = cp
            .issue_join_token(&TenantId("tenant-x".to_string()))
            .await
            .unwrap();
        let tenant = cp.redeem(&join, &agent, &[7u8; 32], &[0u8; 64]).await.unwrap();
        assert_eq!(tenant.0, "tenant-x", "redeem binds the issuing tenant");

        // Agent registers its tunnel's routing token.
        let token = RoutingToken([0x5a; 32]);
        cp.register(&token, &tenant, &agent).await.unwrap();

        // Client resolves it via Rendezvous.
        let (t, a) = cp.resolve(&token).await.unwrap();
        assert_eq!(
            (t.0.as_str(), a.0.as_str()),
            ("tenant-x", "agent-x"),
            "resolve returns the registered binding"
        );

        // An unregistered token → 404 error, not a panic.
        let unknown = cp.resolve(&RoutingToken([0x11; 32])).await;
        assert!(matches!(unknown, Err(CpError::Status(_))), "unknown token errors");
    }

    #[tokio::test]
    async fn redeem_reuse_surfaces_a_status_error() {
        let enr = Arc::new(Mutex::new(Enrollment::new()));
        let reg = Arc::new(Mutex::new(TunnelRegistry::new()));
        let app = control_plane_router(enr, reg, Arc::new(Mutex::new(BillingState::default())));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let cp = ControlPlaneClient::new(format!("http://{addr}"));
        let agent = AgentId("a".to_string());
        let join = cp.issue_join_token(&TenantId("t".to_string())).await.unwrap();

        cp.redeem(&join, &agent, &[1u8; 32], &[0u8; 64]).await.unwrap();
        // Single-use: the second redemption is rejected (409) as a Status error.
        let second = cp.redeem(&join, &agent, &[1u8; 32], &[0u8; 64]).await;
        assert!(matches!(second, Err(CpError::Status(_))), "join token is single-use");
    }

    #[tokio::test]
    async fn fetch_edge_cert_downloads_the_published_root() {
        // #11 C2: the client fetches the edge CA root the CP publishes at /pki/ca.
        let der: &[u8] = b"\x30\x82\x01\x0a-fetched-ca-root";
        let path = std::env::temp_dir().join(format!("ct-cpc-ca-{}.der", std::process::id()));
        std::fs::write(&path, der).unwrap();
        let app = crate::service::pki_router(path.to_string_lossy().into_owned());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let cp = ControlPlaneClient::new(format!("http://{addr}"));
        let got = cp.fetch_edge_cert().await.unwrap();
        assert_eq!(got, der, "fetches the exact published CA root DER");

        let _ = std::fs::remove_file(&path);
    }

    /// The full M15 billing flow over a real socket: open account → a broke
    /// account is denied a token (402) → top up (intent + confirm) → buy a token.
    #[tokio::test]
    async fn client_drives_account_topup_and_gated_issuance() {
        let cp = ControlPlaneClient::new(spawn_service().await);

        let account = cp.open_account().await.unwrap();

        // Broke: buying a token is refused with a status error (402).
        let broke = cp.buy_token(&account, 1).await;
        assert!(matches!(broke, Err(CpError::Status(_))), "zero-balance issuance denied");

        // Top up 3 credits via an intent + confirmation.
        let payment = cp.create_payment_intent(&account, 3).await.unwrap();
        let balance = cp.confirm_payment(&payment).await.unwrap();
        assert_eq!(balance, 3, "confirmed payment credited the account");

        // Now issuance succeeds and returns a routing token.
        let token = cp.buy_token(&account, 1).await.unwrap();
        assert_ne!(token.0, [0u8; 32], "a real routing token was issued");

        // Confirming the same payment again is rejected (idempotent, 409).
        let replay = cp.confirm_payment(&payment).await;
        assert!(matches!(replay, Err(CpError::Status(_))), "confirmation is single-use");
    }

    /// #117-operator-register (frozen): the full client-over-HTTP round-trip against the
    /// real authenticated channel router. `ControlPlaneClient::register_channel` with a
    /// valid OIDC bearer registers the operator's channel authority (owner = the token
    /// subject), and the durable store then resolves that operator key — the last CP
    /// round-trip that makes an Agent-Fabric channel end-to-end self-service. An owner
    /// mismatch (a second subject re-keying) surfaces as a Status(403), and a missing
    /// token as a Status(401).
    #[tokio::test]
    async fn client_registers_a_channel_against_the_authed_service() {
        use crate::oidc::{OidcVerifier, OidcVerifierHandle};
        use crate::service::authed_channel_router;
        use crate::storage::{SqliteChannelStore, SqliteLedger};
        use ct_common::channel::ChannelId;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};

        let secret = b"realm-secret";
        let issuer = "https://kc/realms/ct";
        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let verifier = Arc::new(OidcVerifier::from_hs_secret(secret, issuer));
        let probe = channels.clone();
        let app = authed_channel_router(
            channels,
            OidcVerifierHandle::new(Some(verifier)),
            Arc::from(b"test-session-key".as_slice()),
            Arc::new(SqliteLedger::open_in_memory().unwrap()),
            None,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let jwt_for = |sub: &str| {
            let claims = serde_json::json!({ "sub": sub, "iss": issuer, "exp": now + 3600 });
            encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(secret)).unwrap()
        };

        let cp = ControlPlaneClient::new(format!("http://{addr}"));
        let channel_hex = "a1".repeat(32);
        let operator_hex = "b2".repeat(32);
        let chan = ChannelId(hex_decode_32(&channel_hex).unwrap());

        // Alice registers her channel authority via the client → 200, and the store
        // resolves the operator key she bound (drives the edge's grant verification).
        cp.register_channel(&channel_hex, &operator_hex, &jwt_for("alice"), false)
            .await
            .unwrap();
        assert_eq!(
            probe.operator_pubkey(&chan).unwrap(),
            Some(hex_decode_32(&operator_hex).unwrap()),
            "the registered operator authority round-trips through the store"
        );

        // A different subject cannot re-key alice's channel → the client surfaces 403.
        let mallory = cp
            .register_channel(&channel_hex, &"ff".repeat(32), &jwt_for("mallory"), false)
            .await;
        assert_eq!(
            mallory.as_ref().err().and_then(CpError::status),
            Some(reqwest::StatusCode::FORBIDDEN),
            "non-owner re-key is a 403 status error"
        );
        assert_eq!(
            probe.operator_pubkey(&chan).unwrap(),
            Some(hex_decode_32(&operator_hex).unwrap()),
            "the refused re-key left the operator key unchanged"
        );

        // A missing/invalid bearer token → the client surfaces a 401 status error.
        let no_auth = cp.register_channel(&channel_hex, &operator_hex, "", false).await;
        assert_eq!(
            no_auth.as_ref().err().and_then(CpError::status),
            Some(reqwest::StatusCode::UNAUTHORIZED),
            "a missing token is a 401 status error"
        );
    }

    /// #747: re-registering a channel the caller already owns with a DIFFERENT
    /// operator key is refused with 409, and the client hands the caller the
    /// service's plain-text reason (the `confirm_rekey` hint) rather than a bare
    /// status -- `ct-agent channel register` prints `Display` via `?`, so that is
    /// the only way the operator ever learns how to opt in. With `confirm_rekey`
    /// the same call rotates the key; a same-key re-run stays an idempotent Ok.
    #[tokio::test]
    async fn client_surfaces_the_409_body_for_an_operator_mismatch_747() {
        use crate::oidc::{OidcVerifier, OidcVerifierHandle};
        use crate::service::authed_channel_router;
        use crate::storage::{SqliteChannelStore, SqliteLedger};
        use ct_common::channel::ChannelId;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};

        let secret = b"realm-secret";
        let issuer = "https://kc/realms/ct";
        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let verifier = Arc::new(OidcVerifier::from_hs_secret(secret, issuer));
        let probe = channels.clone();
        let app = authed_channel_router(
            channels,
            OidcVerifierHandle::new(Some(verifier)),
            Arc::from(b"test-session-key".as_slice()),
            Arc::new(SqliteLedger::open_in_memory().unwrap()),
            None,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let claims = serde_json::json!({ "sub": "alice", "iss": issuer, "exp": now + 3600 });
        let alice = encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(secret)).unwrap();

        let cp = ControlPlaneClient::new(format!("http://{addr}"));
        let channel_hex = "a1".repeat(32);
        let op1 = "b2".repeat(32);
        let op2 = "c3".repeat(32);
        let chan = ChannelId(hex_decode_32(&channel_hex).unwrap());

        cp.register_channel(&channel_hex, &op1, &alice, false).await.unwrap();
        cp.register_channel(&channel_hex, &op1, &alice, false)
            .await
            .expect("a same-key re-run is idempotent");

        let refused = cp.register_channel(&channel_hex, &op2, &alice, false).await;
        let err = refused.expect_err("a different operator without confirm_rekey is refused");
        assert_eq!(err.status(), Some(reqwest::StatusCode::CONFLICT));
        match &err {
            CpError::StatusWithBody(_, body) => {
                assert!(body.contains("different operator_pubkey"), "body explains the mismatch: {body}");
                assert!(body.contains("\"confirm_rekey\": true"), "body tells the caller how to opt in: {body}");
            }
            other => panic!("expected StatusWithBody, got {other:?}"),
        }
        let shown = err.to_string();
        assert!(shown.contains("409"), "Display carries the status: {shown}");
        assert!(shown.contains("confirm_rekey"), "Display carries the hint verbatim: {shown}");
        assert_eq!(
            probe.operator_pubkey(&chan).unwrap(),
            Some(hex_decode_32(&op1).unwrap()),
            "the refused re-key wrote nothing"
        );

        cp.register_channel(&channel_hex, &op2, &alice, true)
            .await
            .expect("confirm_rekey rotates the operator");
        assert_eq!(probe.operator_pubkey(&chan).unwrap(), Some(hex_decode_32(&op2).unwrap()));
    }

    /// #214 follow-up (automatic agent-directory registration): `ControlPlaneClient::register_agent`
    /// with the admin token round-trips against the real `agent_directory_router` — makes
    /// `ct-agent channel agent-card` able to publish discoverability as one step instead of a
    /// separate manual `POST /registry/agents` the docs used to just describe.
    #[tokio::test]
    async fn client_registers_an_agent_against_the_directory_service() {
        use crate::service::agent_directory_router;
        use crate::storage::SqliteAgentDirectory;

        let admin = [0x42u8; 32];
        let admin_hex: String = admin.iter().map(|b| format!("{b:02x}")).collect();
        let directory = Arc::new(SqliteAgentDirectory::open_in_memory().unwrap());
        let app = agent_directory_router(directory.clone(), Some(admin));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let cp = ControlPlaneClient::new(format!("http://{addr}")).with_admin_token(admin_hex);
        let holder_hex = "ab".repeat(32);
        let roles = vec!["physics".to_string()];
        let skills = vec!["game-mechanics".to_string()];
        cp.register_agent(&holder_hex, "https://you.example/.well-known/agent-card.json", &roles, &skills)
            .await
            .unwrap();

        let found = directory.search(Some("physics"), None).unwrap();
        assert_eq!(found.len(), 1, "the registration round-trips into the searchable directory");
        assert_eq!(found[0].holder_pubkey, holder_hex);
        assert_eq!(found[0].card_url, "https://you.example/.well-known/agent-card.json");

        // A non-https card_url is rejected (SSRF defence-in-depth) → the client surfaces 400.
        let bad_url = cp.register_agent(&holder_hex, "http://not-https.example/card.json", &roles, &skills).await;
        assert!(matches!(bad_url, Err(CpError::Status(_))), "non-https card_url is a Status error (400)");

        // Missing/wrong admin token → the client surfaces 401.
        let no_admin = ControlPlaneClient::new(format!("http://{addr}"));
        let unauth = no_admin
            .register_agent(&holder_hex, "https://you.example/.well-known/agent-card.json", &roles, &skills)
            .await;
        assert!(matches!(unauth, Err(CpError::Status(_))), "missing admin token is a Status error (401)");
    }
}
