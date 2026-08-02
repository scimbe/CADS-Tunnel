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
    /// A field could not be decoded (e.g. a token that is not 32 hex bytes).
    Malformed,
}

impl std::fmt::Display for CpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CpError::Http(e) => write!(f, "control-plane request failed: {e}"),
            CpError::Status(s) => write!(f, "control-plane returned status {s}"),
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

impl ControlPlaneClient {
    /// Bind the client to a base URL. A trailing slash is trimmed.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
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
    /// owner-scoped, so a [`CpError::Status`] (403) means the channel already belongs to a
    /// different subject, and (401) means the token was missing/invalid.
    pub async fn register_channel(
        &self,
        channel_hex: &str,
        operator_pubkey_hex: &str,
        bearer_token: &str,
    ) -> CpResult<()> {
        let resp = self
            .http
            .post(format!("{}/me/channels", self.base))
            .header("authorization", format!("Bearer {bearer_token}"))
            .json(&serde_json::json!({
                "channel": channel_hex,
                "operator_pubkey": operator_pubkey_hex,
            }))
            .send()
            .await?;
        ok(resp)?;
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

fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrollment::Enrollment;
    use crate::http::{control_plane_router, BillingState};
    use crate::registry::TunnelRegistry;
    use std::sync::{Arc, Mutex};

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
        use crate::storage::SqliteChannelStore;
        use ct_common::channel::ChannelId;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};

        let secret = b"realm-secret";
        let issuer = "https://kc/realms/ct";
        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let verifier = Arc::new(OidcVerifier::from_hs_secret(secret, issuer));
        let probe = channels.clone();
        let app = authed_channel_router(channels, OidcVerifierHandle::new(Some(verifier)));
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
        cp.register_channel(&channel_hex, &operator_hex, &jwt_for("alice"))
            .await
            .unwrap();
        assert_eq!(
            probe.operator_pubkey(&chan).unwrap(),
            Some(hex_decode_32(&operator_hex).unwrap()),
            "the registered operator authority round-trips through the store"
        );

        // A different subject cannot re-key alice's channel → the client surfaces 403.
        let mallory = cp
            .register_channel(&channel_hex, &"ff".repeat(32), &jwt_for("mallory"))
            .await;
        assert!(matches!(mallory, Err(CpError::Status(_))), "non-owner re-key is a Status error (403)");
        assert_eq!(
            probe.operator_pubkey(&chan).unwrap(),
            Some(hex_decode_32(&operator_hex).unwrap()),
            "the refused re-key left the operator key unchanged"
        );

        // A missing/invalid bearer token → the client surfaces a Status error (401).
        let no_auth = cp.register_channel(&channel_hex, &operator_hex, "").await;
        assert!(matches!(no_auth, Err(CpError::Status(_))), "a missing token is a Status error (401)");
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
