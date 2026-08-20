//! Keycloak Admin REST API client (#382-follow: Browser-Plane login gate).
//!
//! The gate's email allow-list needs a real Keycloak account to exist for every
//! allow-listed email -- an email with no account can't complete the OIDC login
//! the gate requires. `ensure_user` provisions one on demand (idempotent: a
//! pre-existing account for that email is left untouched, matching this realm's
//! own `IGNORE_EXISTING` import convention elsewhere).
//!
//! Auth follows the exact pattern `scripts/apply-realm-theme.sh` already uses in
//! production: an admin-cli password-grant token against the `master` realm, then
//! bearer-authenticated calls against `/admin/realms/:realm/*`. No new auth
//! mechanism invented -- this is the first Rust-side caller of that same,
//! already-proven path.

use serde::{Deserialize, Serialize};
use serde_json::json;

/// Configuration to reach Keycloak's Admin REST API, read from env at startup
/// (`KEYCLOAK_PUBLIC_URL`, `KC_ADMIN_USER`, `KC_ADMIN_PASSWORD`, `CT_OIDC_REALM`
/// -- the same variable names `apply-realm-theme.sh` already reads from
/// `docker/deploy/.env`, so no new operator-facing config surface).
#[derive(Clone)]
pub struct KeycloakAdminConfig {
    pub base_url: String,
    pub realm: String,
    pub admin_user: String,
    pub admin_password: String,
}

/// Realm used when `CT_OIDC_REALM` is unset -- the realm this project's own
/// deploy manifests ship.
const DEFAULT_REALM: &str = "ct-demo";

impl KeycloakAdminConfig {
    pub fn from_env() -> Option<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let nonempty = |k: &str| get(k).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        Some(Self {
            base_url: nonempty("KEYCLOAK_PUBLIC_URL")?,
            realm: nonempty("CT_OIDC_REALM").unwrap_or_else(|| DEFAULT_REALM.to_string()),
            admin_user: nonempty("KC_ADMIN_USER")?,
            admin_password: nonempty("KC_ADMIN_PASSWORD")?,
        })
    }
}

#[derive(Debug)]
pub enum KcError {
    Http(String),
    Auth,
}

impl std::fmt::Display for KcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KcError::Http(e) => write!(f, "keycloak admin API error: {e}"),
            KcError::Auth => write!(f, "keycloak admin authentication failed"),
        }
    }
}

impl std::error::Error for KcError {}

/// Outcome of [`ensure_user`]: whether an account already existed, and (only when
/// freshly created) the one-time temporary password the tunnel owner must relay
/// to the invitee out of band -- this realm has no outbound-email mechanism
/// wired up (see `portal.rs`'s `require_verified_email` doc comment for the same
/// gap), so returning it here in the API response is the only way it ever
/// reaches anyone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnsureUserResult {
    pub already_existed: bool,
    pub temporary_password: Option<String>,
}

async fn admin_token(client: &reqwest::Client, cfg: &KeycloakAdminConfig) -> Result<(String, u64), KcError> {
    #[derive(Deserialize)]
    struct TokenResp {
        access_token: String,
        #[serde(default)]
        expires_in: u64,
    }
    let resp = client
        .post(format!(
            "{}/realms/master/protocol/openid-connect/token",
            cfg.base_url.trim_end_matches('/')
        ))
        .form(&[
            ("username", cfg.admin_user.as_str()),
            ("password", cfg.admin_password.as_str()),
            ("grant_type", "password"),
            ("client_id", "admin-cli"),
        ])
        .send()
        .await
        .map_err(|e| KcError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(KcError::Auth);
    }
    resp.json::<TokenResp>()
        .await
        .map(|t| (t.access_token, t.expires_in))
        .map_err(|e| KcError::Http(e.to_string()))
}

/// #434: was a fresh `master`-realm password grant (a real bcrypt verification,
/// ~50-100ms) on EVERY admin operation, minting a new Keycloak session each
/// time -- so even the cheapest op (`ensure_user` on an already-existing
/// account) paid two round trips, one pure auth overhead. Cached process-wide
/// (one Keycloak admin config per process, matching this module's own
/// `KeycloakAdminConfig::from_env()` singleton convention), refreshed when the
/// token's real `expires_in` TTL is within `EXPIRY_MARGIN` of expiring.
struct CachedToken {
    token: String,
    expires_at: std::time::Instant,
}

static TOKEN_CACHE: std::sync::RwLock<Option<CachedToken>> = std::sync::RwLock::new(None);
/// Refresh this far ahead of the token's real expiry -- covers request latency
/// and clock skew without over-fetching.
const EXPIRY_MARGIN: std::time::Duration = std::time::Duration::from_secs(30);

/// A cached admin token, refreshing it (and every other in-flight caller's view
/// of it) if it's missing, expired, or `force_refresh` is set -- the single
/// retry path uses `force_refresh` to cover a token invalidated early (e.g. an
/// out-of-band Keycloak session revoke) without waiting out its normal TTL.
async fn cached_admin_token(client: &reqwest::Client, cfg: &KeycloakAdminConfig, force_refresh: bool) -> Result<String, KcError> {
    if !force_refresh {
        if let Some(cached) = TOKEN_CACHE.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
            if cached.expires_at > std::time::Instant::now() {
                return Ok(cached.token.clone());
            }
        }
    }
    let (token, expires_in) = admin_token(client, cfg).await?;
    let ttl = std::time::Duration::from_secs(expires_in).saturating_sub(EXPIRY_MARGIN);
    let expires_at = std::time::Instant::now() + ttl;
    *TOKEN_CACHE.write().unwrap_or_else(|e| e.into_inner()) = Some(CachedToken { token: token.clone(), expires_at });
    Ok(token)
}

/// Random temporary password: 24 bytes of CSPRNG output, base64url-encoded --
/// long and high-entropy enough that "shared once out of band, must be changed
/// on first login" is a reasonable bridge until a real invite-email flow exists.
fn random_temp_password() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base64_url_no_pad(&buf)
}

fn base64_url_no_pad(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Ensure a Keycloak account exists for `email` in the configured realm --
/// idempotent (an existing account is left completely untouched, no password
/// reset). A freshly created account is `enabled`, carries the given email as
/// both `username` and `email`, and requires `UPDATE_PASSWORD` on first login
/// (so the temporary password below is single-use in practice, not a standing
/// credential).
pub async fn ensure_user(
    client: &reqwest::Client,
    cfg: &KeycloakAdminConfig,
    email: &str,
) -> Result<EnsureUserResult, KcError> {
    let mut token = cached_admin_token(client, cfg, false).await?;
    let realm_url = format!("{}/admin/realms/{}", cfg.base_url.trim_end_matches('/'), cfg.realm);

    let mut existing = client
        .get(format!("{realm_url}/users"))
        .bearer_auth(&token)
        .query(&[("email", email), ("exact", "true")])
        .send()
        .await
        .map_err(|e| KcError::Http(e.to_string()))?;
    // #434: single retry with a force-refreshed token -- covers a cached token
    // invalidated early (e.g. an out-of-band Keycloak session revoke), not just
    // the normal TTL-expiry path `cached_admin_token` already handles.
    if existing.status() == reqwest::StatusCode::UNAUTHORIZED {
        token = cached_admin_token(client, cfg, true).await?;
        existing = client
            .get(format!("{realm_url}/users"))
            .bearer_auth(&token)
            .query(&[("email", email), ("exact", "true")])
            .send()
            .await
            .map_err(|e| KcError::Http(e.to_string()))?;
    }
    if !existing.status().is_success() {
        return Err(KcError::Http(format!("GET users?email= returned {}", existing.status())));
    }
    let found: Vec<serde_json::Value> = existing.json().await.map_err(|e| KcError::Http(e.to_string()))?;
    if !found.is_empty() {
        return Ok(EnsureUserResult {
            already_existed: true,
            temporary_password: None,
        });
    }

    let create = client
        .post(format!("{realm_url}/users"))
        .bearer_auth(&token)
        .json(&json!({
            "username": email,
            "email": email,
            "enabled": true,
            "emailVerified": false,
            "requiredActions": ["UPDATE_PASSWORD"],
        }))
        .send()
        .await
        .map_err(|e| KcError::Http(e.to_string()))?;
    if !create.status().is_success() {
        return Err(KcError::Http(format!("POST users returned {}", create.status())));
    }
    // Keycloak's user-create response carries the new id only in `Location`, not
    // the body -- the documented shape of this endpoint, not an oversight here.
    let location = create
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| KcError::Http("user create response had no Location header".to_string()))?;
    let user_id = location
        .rsplit('/')
        .next()
        .ok_or_else(|| KcError::Http("could not parse user id from Location header".to_string()))?;

    let temp_password = random_temp_password();
    let set_pw = client
        .put(format!("{realm_url}/users/{user_id}/reset-password"))
        .bearer_auth(&token)
        .json(&json!({
            "type": "password",
            "value": temp_password,
            "temporary": true,
        }))
        .send()
        .await
        .map_err(|e| KcError::Http(e.to_string()))?;
    if !set_pw.status().is_success() {
        return Err(KcError::Http(format!("reset-password returned {}", set_pw.status())));
    }

    Ok(EnsureUserResult {
        already_existed: false,
        temporary_password: Some(temp_password),
    })
}

/// A freshly-created service-account client's real Keycloak internal id + its
/// one-time-visible secret (real self-service M2M credentials, 2026-08-04).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedClient {
    pub internal_id: String,
    pub secret: String,
}

#[derive(Deserialize)]
struct ClientSecretResp {
    value: String,
}

async fn fetch_client_secret(client: &reqwest::Client, token: &str, realm_url: &str, internal_id: &str) -> Result<String, KcError> {
    let resp = client
        .get(format!("{realm_url}/clients/{internal_id}/client-secret"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| KcError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(KcError::Http(format!("GET client-secret returned {}", resp.status())));
    }
    resp.json::<ClientSecretResp>().await.map(|s| s.value).map_err(|e| KcError::Http(e.to_string()))
}

/// Create a real, confidential, service-account-only Keycloak client (pure
/// client_credentials M2M -- no browser flows: standardFlow/directAccessGrants
/// both off) and return its internal id + the secret Keycloak minted for it.
/// `client_id` is trusted as already-validated/unique by the caller (the
/// portal route generates it server-side -- see `portal_api.rs` -- rather
/// than accepting arbitrary user input here), matching `ensure_user`'s own
/// division of validation (caller) vs. API mechanics (this module).
pub async fn create_service_account_client(
    client: &reqwest::Client,
    cfg: &KeycloakAdminConfig,
    client_id: &str,
    name: &str,
) -> Result<CreatedClient, KcError> {
    let mut token = cached_admin_token(client, cfg, false).await?;
    let realm_url = format!("{}/admin/realms/{}", cfg.base_url.trim_end_matches('/'), cfg.realm);

    let new_client_body = json!({
        "clientId": client_id,
        "name": name,
        "protocol": "openid-connect",
        "enabled": true,
        "publicClient": false,
        "standardFlowEnabled": false,
        "directAccessGrantsEnabled": false,
        "serviceAccountsEnabled": true,
        "authorizationServicesEnabled": false,
        "clientAuthenticatorType": "client-secret",
    });
    let mut create = client
        .post(format!("{realm_url}/clients"))
        .bearer_auth(&token)
        .json(&new_client_body)
        .send()
        .await
        .map_err(|e| KcError::Http(e.to_string()))?;
    // #434: single retry with a force-refreshed token, same reasoning as ensure_user.
    if create.status() == reqwest::StatusCode::UNAUTHORIZED {
        token = cached_admin_token(client, cfg, true).await?;
        create = client
            .post(format!("{realm_url}/clients"))
            .bearer_auth(&token)
            .json(&new_client_body)
            .send()
            .await
            .map_err(|e| KcError::Http(e.to_string()))?;
    }
    if !create.status().is_success() {
        return Err(KcError::Http(format!("POST clients returned {}", create.status())));
    }
    // Same shape as ensure_user's create response: the new id only ever comes
    // back in Location, never the body.
    let location = create
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| KcError::Http("client create response had no Location header".to_string()))?;
    let internal_id = location
        .rsplit('/')
        .next()
        .ok_or_else(|| KcError::Http("could not parse client internal id from Location header".to_string()))?
        .to_string();

    let secret = fetch_client_secret(client, &token, &realm_url, &internal_id).await?;
    Ok(CreatedClient { internal_id, secret })
}

/// Regenerate `internal_id`'s client secret and return the new value -- the
/// old secret stops working immediately (Keycloak's own regenerate semantics).
/// Ownership must already be verified by the caller (`SqliteServiceAccountStore
/// ::internal_id_for`) before this is ever called with a real internal id.
pub async fn rotate_client_secret(client: &reqwest::Client, cfg: &KeycloakAdminConfig, internal_id: &str) -> Result<String, KcError> {
    let mut token = cached_admin_token(client, cfg, false).await?;
    let realm_url = format!("{}/admin/realms/{}", cfg.base_url.trim_end_matches('/'), cfg.realm);
    let mut resp = client
        .post(format!("{realm_url}/clients/{internal_id}/client-secret"))
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| KcError::Http(e.to_string()))?;
    // #434: single retry with a force-refreshed token, same reasoning as ensure_user.
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        token = cached_admin_token(client, cfg, true).await?;
        resp = client
            .post(format!("{realm_url}/clients/{internal_id}/client-secret"))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| KcError::Http(e.to_string()))?;
    }
    if !resp.status().is_success() {
        return Err(KcError::Http(format!("POST client-secret (rotate) returned {}", resp.status())));
    }
    resp.json::<ClientSecretResp>().await.map(|s| s.value).map_err(|e| KcError::Http(e.to_string()))
}

/// Delete `internal_id` from Keycloak entirely -- the client stops
/// authenticating immediately. Ownership must already be verified by the
/// caller, same as [`rotate_client_secret`].
pub async fn delete_client(client: &reqwest::Client, cfg: &KeycloakAdminConfig, internal_id: &str) -> Result<(), KcError> {
    let mut token = cached_admin_token(client, cfg, false).await?;
    let realm_url = format!("{}/admin/realms/{}", cfg.base_url.trim_end_matches('/'), cfg.realm);
    let mut resp = client
        .delete(format!("{realm_url}/clients/{internal_id}"))
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| KcError::Http(e.to_string()))?;
    // #434: single retry with a force-refreshed token, same reasoning as ensure_user.
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        token = cached_admin_token(client, cfg, true).await?;
        resp = client
            .delete(format!("{realm_url}/clients/{internal_id}"))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| KcError::Http(e.to_string()))?;
    }
    if !resp.status().is_success() {
        return Err(KcError::Http(format!("DELETE client returned {}", resp.status())));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// #535 / #536: startup diagnosis for the two security promises this control
// plane makes but does not itself enforce -- Keycloak does.
//
// #535, the verified-email gate: `CT_GATE_REQUIRE_VERIFIED_EMAIL=1` (see
// `gate.rs`) only lets an allow-list hit through when the ID token carries
// `email_verified: true`. That is a security property exactly when the realm
// *enforces* the confirmation. On 2026-08-16 it did not: the realm carried
// `verifyEmail=true`, but the required-action provider `VERIFY_EMAIL` was never
// registered, so the flag was inert -- accounts could be created AND used
// without ever confirming an address, and nothing said a word. The gate rejected
// a `false` and believed a `true`; neither path can notice that nobody ever
// redeems the promise.
//
// #536, the one-time password: `ensure_user` above provisions accounts with
// `"temporary": true`, i.e. "the invitee must change this at first login". Same
// class of bug, same realm, found the same week: Keycloak can only force that
// change when the required-action provider `UPDATE_PASSWORD` is registered and
// enabled, and it was not -- six accounts carried the action in their
// `requiredActions` while nothing ever executed it, so the "one-time" password
// was in fact permanent.
//
// The two are deliberately kept as *separate statements* (see `EnforcementScope`
// and the two accessors on `RealmEnforcement`): they are switched on by different
// configuration and can fail independently. What they share is the data -- both
// read the realm's required-action list, which is fetched exactly once.
//
// This is pure diagnosis: nothing below is read at request time, and neither the
// auth nor the provisioning path is changed. It cannot abort startup either -- a
// deployment whose IdP is secured differently (social login with `trustEmail`,
// say) must keep running.
// ---------------------------------------------------------------------------

/// The one field of Keycloak's (very large) `RealmRepresentation` this check
/// cares about; every other field is ignored by serde.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RealmEmailPolicy {
    #[serde(rename = "verifyEmail", default)]
    pub verify_email: bool,
}

/// One entry of `GET /admin/realms/{realm}/authentication/required-actions`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RequiredActionProvider {
    #[serde(default)]
    pub alias: String,
    #[serde(rename = "providerId", default)]
    pub provider_id: String,
    #[serde(default)]
    pub enabled: bool,
}

/// One entry of `GET /admin/realms/{realm}/identity-provider/instances`.
#[derive(Debug, Clone, Deserialize)]
pub struct IdentityProviderInstance {
    #[serde(default)]
    pub alias: String,
    /// Defaults to `true` when absent: this feeds an *informational* listing, and
    /// an IdP wrongly omitted from it would be the silent direction again.
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(rename = "trustEmail", default)]
    pub trust_email: bool,
}

fn default_true() -> bool {
    true
}

/// Keycloak's built-in required action that actually sends the confirmation mail
/// and blocks the login until it is answered. Its *registration* -- not the realm
/// flag -- is what makes `verifyEmail=true` do anything.
const VERIFY_EMAIL_ACTION: &str = "VERIFY_EMAIL";

/// Keycloak's built-in required action that actually forces the password change
/// at the next login. Its *registration* -- not `"temporary": true` on the
/// reset-password call -- is what makes a one-time password one-time (#536).
const UPDATE_PASSWORD_ACTION: &str = "UPDATE_PASSWORD";

/// How one required-action provider stands in the realm. Shared by both checks:
/// the two promises differ, the way Keycloak (fails to) back them does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredActionState {
    /// Registered in the realm and enabled -- the promise has an enforcer behind it.
    Registered,
    /// Registered but switched off: same practical effect as missing.
    Disabled,
    /// Not registered at all -- the 2026-08-16 shape, for both actions.
    Missing,
}

/// What the realm actually enforces, derived from the three admin-API reads. One
/// snapshot; the two *independent* statements (#535, #536) are read off it by the
/// two accessors below, never merged into a single "all good".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealmEnforcement {
    pub realm_verify_email: bool,
    pub verify_email_action: RequiredActionState,
    /// Whether the realm can execute the `UPDATE_PASSWORD` action that
    /// `ensure_user`'s `"temporary": true` asks for (#536).
    pub update_password_action: RequiredActionState,
    /// Aliases of *enabled* identity providers that vouch for the address
    /// themselves (`trustEmail: true`); logins through them never see the realm's
    /// own confirmation step.
    pub trust_email_idps: Vec<String>,
}

impl RealmEnforcement {
    /// #535: both halves in place -- the realm asks for a confirmation *and*
    /// something registered actually asks for it.
    pub fn verified_email_is_enforced(&self) -> bool {
        self.realm_verify_email && self.verify_email_action == RequiredActionState::Registered
    }

    /// #536: a provisioned `"temporary": true` password really has to be changed.
    /// Deliberately independent of [`Self::verified_email_is_enforced`]: the realm
    /// flag and the email gate have no bearing on whether Keycloak can run
    /// `UPDATE_PASSWORD`.
    pub fn temporary_password_is_enforced(&self) -> bool {
        self.update_password_action == RequiredActionState::Registered
    }
}

/// Which of the two statements this run is entitled to make. They are switched on
/// by *different* configuration and neither implies the other: the verified-email
/// gate by `CT_GATE_REQUIRE_VERIFIED_EMAIL`, the one-time-password enforcement by
/// the mere existence of Keycloak admin credentials -- that is exactly what makes
/// `ensure_user` able to create accounts (`service.rs` builds the provisioning
/// router from the same `KeycloakAdminConfig::from_env()`). A control plane can
/// provision accounts with the gate off, and can run the gate on a realm it may
/// not provision into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnforcementScope {
    /// `CT_GATE_REQUIRE_VERIFIED_EMAIL` is on, so #535's statement is relevant.
    pub verified_email_gate: bool,
    /// Admin credentials exist, so `ensure_user` can hand out one-time passwords
    /// and #536's statement is relevant.
    pub user_provisioning: bool,
}

/// Pure classification over the parsed admin-API structures -- no HTTP, so the
/// judgement itself is testable without a server.
pub fn classify_realm_enforcement(
    realm: &RealmEmailPolicy,
    actions: &[RequiredActionProvider],
    idps: &[IdentityProviderInstance],
) -> RealmEnforcement {
    // Both actions are read out of the *same* list: Keycloak returns every
    // required-action provider of the realm from one endpoint, so #536 costs no
    // additional round trip on top of #535's.
    let state_of = |name: &str| match actions
        .iter()
        .find(|a: &&RequiredActionProvider| a.alias == name || a.provider_id == name)
    {
        None => RequiredActionState::Missing,
        Some(a) if a.enabled => RequiredActionState::Registered,
        Some(_) => RequiredActionState::Disabled,
    };
    RealmEnforcement {
        realm_verify_email: realm.verify_email,
        verify_email_action: state_of(VERIFY_EMAIL_ACTION),
        update_password_action: state_of(UPDATE_PASSWORD_ACTION),
        trust_email_idps: idps
            .iter()
            .filter(|i| i.enabled && i.trust_email)
            .map(|i| i.alias.clone())
            .collect(),
    }
}

/// The outcome of the startup check. `NotChecked` is deliberately its own state
/// rather than a defaulted-to-fine `Checked`: a check that could not run must not
/// read like one that passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RealmEnforcementCheck {
    Checked(RealmEnforcement),
    NotChecked(String),
}

impl RealmEnforcementCheck {
    /// The exact stderr lines this check emits, in order (`ct-cp:` prefix, matching
    /// the control plane's other startup/operational messages). Kept separate from
    /// the printing so the wording itself is under test.
    ///
    /// `scope` decides which of the two statements are made at all; a statement
    /// that is out of scope stays silent, and one that is in scope always says
    /// something -- pass, fail, or "could not check".
    pub fn report_lines(&self, realm: &str, scope: EnforcementScope) -> Vec<String> {
        let enforcement = match self {
            RealmEnforcementCheck::NotChecked(why) => {
                let mut lines = Vec::new();
                if scope.verified_email_gate {
                    lines.push(format!(
                        "ct-cp: WARNING -- #535: CT_GATE_REQUIRE_VERIFIED_EMAIL is on, but whether realm \
                         '{realm}' really enforces email confirmation could not be checked: {why}. This is \
                         NOT an all-clear -- confirm by hand that Realm settings -> Login -> Verify email is \
                         On AND that Authentication -> Required actions lists {VERIFY_EMAIL_ACTION} as enabled."
                    ));
                }
                if scope.user_provisioning {
                    lines.push(format!(
                        "ct-cp: WARNING -- #536: this control plane can provision Keycloak accounts with \
                         one-time passwords, but whether realm '{realm}' really forces the change could not \
                         be checked: {why}. This is NOT an all-clear -- confirm by hand that Authentication \
                         -> Required actions lists {UPDATE_PASSWORD_ACTION} as enabled."
                    ));
                }
                return lines;
            }
            RealmEnforcementCheck::Checked(e) => e,
        };

        let mut lines = Vec::new();
        if scope.verified_email_gate {
            lines.extend(enforcement.verified_email_lines(realm));
        }
        if scope.user_provisioning {
            lines.extend(enforcement.temporary_password_lines(realm));
        }
        lines
    }
}

impl RealmEnforcement {
    /// #535's statement, and nothing else: it names only the part that is actually
    /// missing, so a healthy half is never blamed for a broken one.
    fn verified_email_lines(&self, realm: &str) -> Vec<String> {
        let mut lines = Vec::new();
        if !self.realm_verify_email {
            lines.push(format!(
                "ct-cp: WARNING -- #535: CT_GATE_REQUIRE_VERIFIED_EMAIL is on, but realm '{realm}' has \
                 verifyEmail=false -- Keycloak never asks anyone to confirm their address, so the gate \
                 checks a promise nobody redeems. Fix: Keycloak admin console -> Realm settings -> Login \
                 -> Verify email = On."
            ));
        }
        match self.verify_email_action {
            RequiredActionState::Missing => lines.push(format!(
                "ct-cp: WARNING -- #535: CT_GATE_REQUIRE_VERIFIED_EMAIL is on, but the required-action \
                 provider {VERIFY_EMAIL_ACTION} is NOT REGISTERED in realm '{realm}' -- the realm's \
                 verifyEmail flag is inert without it (this is exactly the 2026-08-16 incident: accounts \
                 were created AND used without ever confirming an address). Fix: Keycloak admin console \
                 -> Authentication -> Required actions -> register {VERIFY_EMAIL_ACTION}, then enable it."
            )),
            RequiredActionState::Disabled => lines.push(format!(
                "ct-cp: WARNING -- #535: CT_GATE_REQUIRE_VERIFIED_EMAIL is on, but the required-action \
                 provider {VERIFY_EMAIL_ACTION} is registered-but-DISABLED in realm '{realm}' -- a \
                 disabled action enforces exactly as much as a missing one, so the realm's verifyEmail \
                 flag is inert. Fix: Keycloak admin console -> Authentication -> Required actions -> set \
                 {VERIFY_EMAIL_ACTION} to Enabled."
            )),
            RequiredActionState::Registered => {}
        }
        if self.verified_email_is_enforced() {
            // Say so out loud even when everything is fine: silence is what the
            // 2026-08-16 realm produced too, and a log that only ever speaks up on
            // failure can't distinguish "checked and healthy" from "never checked".
            lines.push(format!(
                "ct-cp: #535: verified-email gate checked -- realm '{realm}' enforces it (verifyEmail=true, \
                 required action {VERIFY_EMAIL_ACTION} registered and enabled)."
            ));
        }
        if !self.trust_email_idps.is_empty() {
            lines.push(format!(
                "ct-cp: #535: realm '{realm}' has enabled identity provider(s) with trustEmail=true: {} -- \
                 logins through them are accepted as verified on the provider's word and deliberately skip \
                 the realm's own confirmation step. Legitimate, but 'verified email only' therefore covers \
                 more accounts than it reads.",
                self.trust_email_idps.join(", ")
            ));
        }
        lines
    }

    /// #536's statement, and nothing else: whether Keycloak can execute the
    /// `UPDATE_PASSWORD` action that `ensure_user`'s `"temporary": true` requests.
    /// It says nothing about the email confirmation -- the two conditions are
    /// unrelated, and a warning that dragged the other one in would misdirect the
    /// operator to a setting that is fine.
    fn temporary_password_lines(&self, realm: &str) -> Vec<String> {
        let mut lines = Vec::new();
        match self.update_password_action {
            RequiredActionState::Missing => lines.push(format!(
                "ct-cp: WARNING -- #536: this control plane can provision Keycloak accounts, but the \
                 required-action provider {UPDATE_PASSWORD_ACTION} is NOT REGISTERED in realm '{realm}' -- \
                 provisioning sets the account password with \"temporary\": true, which Keycloak cannot \
                 enforce without that provider, so every one-time password stays valid forever (this is the \
                 2026-08-16 shape: six accounts carried {UPDATE_PASSWORD_ACTION} in requiredActions and none \
                 was ever asked to change it). Fix: Keycloak admin console -> Authentication -> Required \
                 actions -> register {UPDATE_PASSWORD_ACTION}, then enable it."
            )),
            RequiredActionState::Disabled => lines.push(format!(
                "ct-cp: WARNING -- #536: this control plane can provision Keycloak accounts, but the \
                 required-action provider {UPDATE_PASSWORD_ACTION} is registered-but-DISABLED in realm \
                 '{realm}' -- a disabled action enforces exactly as much as a missing one, so the one-time \
                 password handed to an invitee never has to be changed. Fix: Keycloak admin console -> \
                 Authentication -> Required actions -> set {UPDATE_PASSWORD_ACTION} to Enabled."
            )),
            RequiredActionState::Registered => lines.push(format!(
                "ct-cp: #536: one-time-password enforcement checked -- realm '{realm}' enforces it (required \
                 action {UPDATE_PASSWORD_ACTION} registered and enabled), so a provisioned temporary password \
                 must be changed at first login."
            )),
        }
        lines
    }
}

async fn admin_get_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    token: &str,
    url: &str,
) -> Result<T, KcError> {
    let resp = client
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| KcError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(KcError::Http(format!("GET {url} returned {}", resp.status())));
    }
    resp.json::<T>().await.map_err(|e| KcError::Http(e.to_string()))
}

/// Read what the realm actually enforces over the Admin REST API (the same
/// credentials `ensure_user` already uses). Read-only: three GETs, no mutation of
/// any realm state -- unchanged by #536, because the required-action list it
/// already fetches carries *every* provider of the realm, `UPDATE_PASSWORD`
/// included. The second statement therefore costs no second round trip.
pub async fn check_realm_enforcement(client: &reqwest::Client, cfg: &KeycloakAdminConfig) -> RealmEnforcementCheck {
    match fetch_realm_enforcement(client, cfg).await {
        Ok(e) => RealmEnforcementCheck::Checked(e),
        Err(e) => RealmEnforcementCheck::NotChecked(e.to_string()),
    }
}

async fn fetch_realm_enforcement(
    client: &reqwest::Client,
    cfg: &KeycloakAdminConfig,
) -> Result<RealmEnforcement, KcError> {
    let token = cached_admin_token(client, cfg, false).await?;
    let realm_url = format!("{}/admin/realms/{}", cfg.base_url.trim_end_matches('/'), cfg.realm);
    let realm: RealmEmailPolicy = admin_get_json(client, &token, &realm_url).await?;
    let actions: Vec<RequiredActionProvider> =
        admin_get_json(client, &token, &format!("{realm_url}/authentication/required-actions")).await?;
    let idps: Vec<IdentityProviderInstance> =
        admin_get_json(client, &token, &format!("{realm_url}/identity-provider/instances")).await?;
    Ok(classify_realm_enforcement(&realm, &actions, &idps))
}

/// Bounded client for any admin-API call against Keycloak: a Keycloak that
/// accepts the connection but never answers must not keep the caller alive
/// forever (#295 saw exactly that shape block `main()` on the JWKS fetch;
/// #610 found the same gap on the live service-account create/rotate/delete
/// request handlers, which each built their own unbounded `Client::new()`
/// instead of reusing this). Same bounds as `main.rs`'s `jwks_fetch_client`.
pub(crate) fn bounded_admin_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Startup entry point (#535, #536), called once from `main()`: check whichever of
/// the two promises this deployment actually makes -- the verified-email gate when
/// `CT_GATE_REQUIRE_VERIFIED_EMAIL` is on, the one-time-password enforcement when
/// admin credentials make provisioning possible -- and report the outcome on
/// stderr. Never aborts, never panics, and touches no state anything reads at
/// runtime.
///
/// Runs in a background task rather than inline: the check costs a password-grant
/// (a real bcrypt verification server-side) plus three admin GETs, i.e. four
/// sequential round trips to Keycloak, and an unreachable or slow IdP would
/// otherwise push that latency straight into the control plane's time-to-serving.
/// A diagnosis must not be able to delay -- let alone block -- booting.
///
/// Must be called from inside a Tokio runtime (`main()` is `#[tokio::main]`).
pub fn spawn_startup_keycloak_enforcement_check() {
    let gate_on = crate::portal::is_truthy_env("CT_GATE_REQUIRE_VERIFIED_EMAIL");
    let Some(cfg) = KeycloakAdminConfig::from_env() else {
        // No admin credentials: provisioning cannot create an account at all, so
        // #536 has no promise to check here -- but #535's gate can still be on,
        // and then a check that cannot run is not a passing one.
        if !gate_on {
            return;
        }
        let realm = std::env::var("CT_OIDC_REALM")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_REALM.to_string());
        let check = RealmEnforcementCheck::NotChecked(
            "no Keycloak admin configuration (KEYCLOAK_PUBLIC_URL / KC_ADMIN_USER / KC_ADMIN_PASSWORD)"
                .to_string(),
        );
        let scope = EnforcementScope {
            verified_email_gate: true,
            user_provisioning: false,
        };
        for line in check.report_lines(&realm, scope) {
            eprintln!("{line}");
        }
        return;
    };
    // Admin credentials exist, so `ensure_user` can hand out one-time passwords:
    // #536 is in scope whatever the gate does.
    let scope = EnforcementScope {
        verified_email_gate: gate_on,
        user_provisioning: true,
    };
    tokio::spawn(async move {
        let client = bounded_admin_http_client();
        let check = check_realm_enforcement(&client, &cfg).await;
        for line in check.report_lines(&cfg.realm, scope) {
            eprintln!("{line}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_lookup_reads_the_same_env_var_names_apply_realm_theme_sh_uses() {
        let env = |k: &str| -> Option<String> {
            match k {
                "KEYCLOAK_PUBLIC_URL" => Some("https://kc.example".to_string()),
                "KC_ADMIN_USER" => Some("admin".to_string()),
                "KC_ADMIN_PASSWORD" => Some("s3cr3t".to_string()),
                _ => None,
            }
        };
        let cfg = KeycloakAdminConfig::from_lookup(env).unwrap();
        assert_eq!(cfg.base_url, "https://kc.example");
        assert_eq!(cfg.realm, "ct-demo", "defaults when CT_OIDC_REALM is unset");
        assert_eq!(cfg.admin_user, "admin");
        assert_eq!(cfg.admin_password, "s3cr3t");
    }

    #[test]
    fn config_from_lookup_is_none_when_any_required_var_is_missing() {
        assert!(KeycloakAdminConfig::from_lookup(|_| None).is_none());
        assert!(KeycloakAdminConfig::from_lookup(|k| (k == "KEYCLOAK_PUBLIC_URL").then(|| "x".to_string())).is_none());
    }

    /// `bounded_admin_http_client` is now the shared client for every live
    /// admin-API call site (the startup enforcement check, plus the
    /// service-account create/rotate/delete request handlers in
    /// `service.rs`, which each previously built their own unbounded
    /// `Client::new()`). Prove directly that it does not hang forever on a
    /// Keycloak that accepts the connection and never answers -- a stall,
    /// not a refusal (a refused connection already errors immediately and
    /// proves nothing about the timeout).
    #[tokio::test]
    async fn bounded_admin_http_client_does_not_hang_on_a_stalled_connection_forever() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if let Ok((socket, _)) = listener.accept().await {
                    std::mem::forget(socket);
                }
            }
        });

        let client = bounded_admin_http_client();
        // A generous outer bound, completely independent of the client's own
        // (much shorter) configured timeout: proves the request returns at
        // all, rather than hanging past its own budget.
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(20), client.get(format!("http://{addr}/")).send()).await;
        let err = outcome
            .expect("the request must return within a bounded time, not hang on a stalled connection forever")
            .expect_err("a connection that never answers must surface as a request error");
        assert!(err.is_timeout(), "expected a client-side timeout, got: {err}");
    }

    #[tokio::test]
    async fn ensure_user_reports_already_existed_without_creating_or_resetting_anything() {
        use axum::extract::{Query, State};
        use axum::routing::{get, post};
        use axum::{Json, Router};
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let create_calls = Arc::new(AtomicUsize::new(0));
        let reset_calls = Arc::new(AtomicUsize::new(0));

        #[derive(Clone)]
        struct St {
            create_calls: Arc<AtomicUsize>,
            reset_calls: Arc<AtomicUsize>,
        }

        async fn token() -> Json<serde_json::Value> {
            Json(json!({ "access_token": "test-admin-token" }))
        }
        async fn users(Query(q): Query<HashMap<String, String>>) -> Json<serde_json::Value> {
            if q.get("email").map(String::as_str) == Some("existing@example.com") {
                Json(json!([{ "id": "already-there" }]))
            } else {
                Json(json!([]))
            }
        }
        async fn create_user(State(st): State<St>) -> axum::response::Response {
            st.create_calls.fetch_add(1, Ordering::SeqCst);
            axum::response::IntoResponse::into_response((
                axum::http::StatusCode::CREATED,
                [(axum::http::header::LOCATION, "http://kc/admin/realms/ct-demo/users/new-id-123")],
            ))
        }
        async fn reset_password(State(st): State<St>) -> axum::http::StatusCode {
            st.reset_calls.fetch_add(1, Ordering::SeqCst);
            axum::http::StatusCode::NO_CONTENT
        }

        let st = St {
            create_calls: create_calls.clone(),
            reset_calls: reset_calls.clone(),
        };
        let app = Router::new()
            .route("/realms/master/protocol/openid-connect/token", post(token))
            .route("/admin/realms/ct-demo/users", get(users).post(create_user))
            .route("/admin/realms/ct-demo/users/:id/reset-password", axum::routing::put(reset_password))
            .with_state(st);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let cfg = KeycloakAdminConfig {
            base_url: format!("http://{addr}"),
            realm: "ct-demo".to_string(),
            admin_user: "admin".to_string(),
            admin_password: "pw".to_string(),
        };
        let client = reqwest::Client::new();

        let existing = ensure_user(&client, &cfg, "existing@example.com").await.unwrap();
        assert!(existing.already_existed);
        assert_eq!(existing.temporary_password, None);
        assert_eq!(create_calls.load(Ordering::SeqCst), 0, "an existing account is never (re-)created");
        assert_eq!(reset_calls.load(Ordering::SeqCst), 0, "an existing account's password is never reset");

        let fresh = ensure_user(&client, &cfg, "brand-new@example.com").await.unwrap();
        assert!(!fresh.already_existed);
        assert!(fresh.temporary_password.is_some(), "a freshly created account gets a temp password");
        assert_eq!(create_calls.load(Ordering::SeqCst), 1);
        assert_eq!(reset_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn create_service_account_client_returns_the_real_internal_id_and_secret() {
        use axum::extract::{Path, State};
        use axum::routing::{delete, get, post};
        use axum::{Json, Router};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct St {
            secret_calls: Arc<AtomicUsize>,
            deleted: Arc<Mutex<Vec<String>>>,
        }

        async fn token() -> Json<serde_json::Value> {
            Json(json!({ "access_token": "test-admin-token" }))
        }
        async fn create_client() -> axum::response::Response {
            axum::response::IntoResponse::into_response((
                axum::http::StatusCode::CREATED,
                [(axum::http::header::LOCATION, "http://kc/admin/realms/ct-demo/clients/internal-abc-123")],
            ))
        }
        async fn client_secret(State(st): State<St>) -> Json<serde_json::Value> {
            let n = st.secret_calls.fetch_add(1, Ordering::SeqCst);
            Json(json!({ "type": "secret", "value": format!("secret-v{n}") }))
        }
        async fn delete_client_route(State(st): State<St>, Path(id): Path<String>) -> axum::http::StatusCode {
            st.deleted.lock().unwrap().push(id);
            axum::http::StatusCode::NO_CONTENT
        }

        let secret_calls = Arc::new(AtomicUsize::new(0));
        let deleted = Arc::new(Mutex::new(Vec::new()));
        let st = St { secret_calls: secret_calls.clone(), deleted: deleted.clone() };
        let app = Router::new()
            .route("/realms/master/protocol/openid-connect/token", post(token))
            .route("/admin/realms/ct-demo/clients", post(create_client))
            .route("/admin/realms/ct-demo/clients/:id/client-secret", get(client_secret).post(client_secret))
            .route("/admin/realms/ct-demo/clients/:id", delete(delete_client_route))
            .with_state(st);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let cfg = KeycloakAdminConfig {
            base_url: format!("http://{addr}"),
            realm: "ct-demo".to_string(),
            admin_user: "admin".to_string(),
            admin_password: "pw".to_string(),
        };
        let client = reqwest::Client::new();

        let created = create_service_account_client(&client, &cfg, "sa-test123", "Test bot").await.unwrap();
        assert_eq!(created.internal_id, "internal-abc-123", "the internal id must come from the real Location header");
        assert_eq!(created.secret, "secret-v0");

        let rotated = rotate_client_secret(&client, &cfg, &created.internal_id).await.unwrap();
        assert_eq!(rotated, "secret-v1", "rotate must return a genuinely different value than the original create");
        assert_ne!(rotated, created.secret);

        delete_client(&client, &cfg, &created.internal_id).await.unwrap();
        assert_eq!(deleted.lock().unwrap().as_slice(), ["internal-abc-123"], "delete must target the real internal id, not the client_id");
    }

    #[tokio::test]
    async fn create_service_account_client_surfaces_a_real_keycloak_failure_honestly() {
        use axum::routing::post;
        use axum::{Json, Router};

        async fn token() -> Json<serde_json::Value> {
            Json(json!({ "access_token": "test-admin-token" }))
        }
        async fn create_client_conflict() -> axum::http::StatusCode {
            axum::http::StatusCode::CONFLICT
        }

        let app = Router::new()
            .route("/realms/master/protocol/openid-connect/token", post(token))
            .route("/admin/realms/ct-demo/clients", post(create_client_conflict));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let cfg = KeycloakAdminConfig {
            base_url: format!("http://{addr}"),
            realm: "ct-demo".to_string(),
            admin_user: "admin".to_string(),
            admin_password: "pw".to_string(),
        };
        let client = reqwest::Client::new();

        let err = create_service_account_client(&client, &cfg, "sa-dup", "Test bot").await.unwrap_err();
        assert!(err.to_string().contains("409") || err.to_string().to_lowercase().contains("conflict"), "a real 409 must surface as a real error, not a fabricated success: {err}");
    }

    // --- #535 / #536: Keycloak-enforcement startup diagnosis -------------------

    /// Only the verified-email gate is on: a deployment that authenticates against
    /// a realm it cannot provision into.
    const GATE_ONLY: EnforcementScope = EnforcementScope {
        verified_email_gate: true,
        user_provisioning: false,
    };
    /// Only provisioning is possible: admin credentials, gate off.
    const PROVISIONING_ONLY: EnforcementScope = EnforcementScope {
        verified_email_gate: false,
        user_provisioning: true,
    };
    /// The production shape since #527: gate on *and* admin credentials present.
    const BOTH: EnforcementScope = EnforcementScope {
        verified_email_gate: true,
        user_provisioning: true,
    };

    fn action(alias: &str, enabled: bool) -> RequiredActionProvider {
        RequiredActionProvider {
            alias: alias.to_string(),
            provider_id: alias.to_string(),
            enabled,
        }
    }

    fn idp(alias: &str, enabled: bool, trust_email: bool) -> IdentityProviderInstance {
        IdentityProviderInstance {
            alias: alias.to_string(),
            enabled,
            trust_email,
        }
    }

    fn warnings(lines: &[String]) -> Vec<&String> {
        lines.iter().filter(|l| l.contains("WARNING")).collect()
    }

    #[test]
    fn an_enforcing_realm_is_confirmed_out_loud_and_warns_about_nothing() {
        let e = classify_realm_enforcement(
            &RealmEmailPolicy { verify_email: true },
            &[action("UPDATE_PASSWORD", true), action(VERIFY_EMAIL_ACTION, true)],
            &[idp("google", false, true)], // disabled IdP: not part of what is live
        );
        assert!(e.verified_email_is_enforced());
        assert!(e.trust_email_idps.is_empty(), "a disabled IdP must not be listed as active");

        let lines = RealmEnforcementCheck::Checked(e).report_lines("ct-demo", GATE_ONLY);
        assert!(warnings(&lines).is_empty(), "a healthy realm must not warn: {lines:?}");
        assert_eq!(lines.len(), 1, "exactly one confirmation line, so the log proves the check ran: {lines:?}");
        assert!(lines[0].contains("ct-demo") && lines[0].contains("verifyEmail=true"));
    }

    #[test]
    fn a_realm_flag_that_is_off_is_named_as_the_missing_part() {
        let e = classify_realm_enforcement(
            &RealmEmailPolicy { verify_email: false },
            &[action(VERIFY_EMAIL_ACTION, true)],
            &[],
        );
        assert!(!e.verified_email_is_enforced());
        let lines = RealmEnforcementCheck::Checked(e).report_lines("ct-demo", GATE_ONLY);
        let w = warnings(&lines);
        assert_eq!(w.len(), 1, "only the part that is actually broken is reported: {lines:?}");
        assert!(w[0].contains("verifyEmail=false"), "names the realm flag: {}", w[0]);
        assert!(w[0].contains("Realm settings -> Login"), "says where to fix it: {}", w[0]);
        assert!(
            !w[0].contains("NOT REGISTERED"),
            "must not blame the required action, which is fine here: {}",
            w[0]
        );
        assert!(
            !lines.iter().any(|l| l.contains("verified-email gate checked")),
            "no confirmation line when the realm does not enforce: {lines:?}"
        );
    }

    #[test]
    fn an_unregistered_verify_email_action_is_named_as_the_missing_part_the_2026_08_16_shape() {
        // The real incident: the realm flag WAS set, and it did nothing because the
        // provider behind it was never registered.
        let e = classify_realm_enforcement(
            &RealmEmailPolicy { verify_email: true },
            &[action("UPDATE_PASSWORD", true), action("CONFIGURE_TOTP", true)],
            &[],
        );
        assert_eq!(e.verify_email_action, RequiredActionState::Missing);
        assert!(!e.verified_email_is_enforced(), "verifyEmail=true alone is not enforcement");

        let lines = RealmEnforcementCheck::Checked(e).report_lines("ct-demo", GATE_ONLY);
        let w = warnings(&lines);
        assert_eq!(w.len(), 1, "{lines:?}");
        assert!(w[0].contains("VERIFY_EMAIL") && w[0].contains("NOT REGISTERED"), "{}", w[0]);
        assert!(w[0].contains("Authentication -> Required actions"), "says where to fix it: {}", w[0]);
        assert!(!w[0].contains("verifyEmail=false"), "must not blame the realm flag, which is set: {}", w[0]);
    }

    #[test]
    fn a_registered_but_disabled_verify_email_action_is_reported_as_no_enforcement() {
        let e = classify_realm_enforcement(
            &RealmEmailPolicy { verify_email: true },
            &[action(VERIFY_EMAIL_ACTION, false)],
            &[],
        );
        assert_eq!(e.verify_email_action, RequiredActionState::Disabled);
        assert!(!e.verified_email_is_enforced(), "a disabled action enforces exactly as much as a missing one");
        let lines = RealmEnforcementCheck::Checked(e).report_lines("ct-demo", GATE_ONLY);
        let w = warnings(&lines);
        assert_eq!(w.len(), 1, "{lines:?}");
        assert!(w[0].contains("DISABLED"), "{}", w[0]);
    }

    #[test]
    fn trust_email_identity_providers_are_enumerated_alongside_a_healthy_realm() {
        let e = classify_realm_enforcement(
            &RealmEmailPolicy { verify_email: true },
            &[action(VERIFY_EMAIL_ACTION, true)],
            &[
                idp("google", true, true),
                idp("github", true, true),
                idp("gitlab", true, true),
                idp("saml-corp", true, false), // no trustEmail: nothing to report
            ],
        );
        assert_eq!(e.trust_email_idps, ["google", "github", "gitlab"]);
        let lines = RealmEnforcementCheck::Checked(e).report_lines("ct-demo", GATE_ONLY);
        assert!(warnings(&lines).is_empty(), "trustEmail is legitimate, not a warning: {lines:?}");
        let listing = lines
            .iter()
            .find(|l| l.contains("trustEmail=true"))
            .unwrap_or_else(|| panic!("the trustEmail IdPs must be reported: {lines:?}"));
        assert!(listing.contains("google, github, gitlab"), "{listing}");
        assert!(!listing.contains("saml-corp"), "an IdP without trustEmail must not be listed: {listing}");
    }

    #[test]
    fn a_check_that_could_not_run_never_reads_like_a_passing_one() {
        let lines = RealmEnforcementCheck::NotChecked("connection refused".to_string()).report_lines("ct-demo", GATE_ONLY);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("could not be checked"), "{}", lines[0]);
        assert!(lines[0].contains("connection refused"), "the real cause must survive: {}", lines[0]);
        assert!(lines[0].contains("NOT an all-clear"), "{}", lines[0]);
        assert!(
            !lines[0].contains("verified-email gate checked"),
            "must never emit the confirmation wording: {}",
            lines[0]
        );
    }

    // --- #536: the one-time password's enforcer ------------------------------

    #[test]
    fn a_registered_update_password_action_is_confirmed_out_loud() {
        let e = classify_realm_enforcement(
            &RealmEmailPolicy { verify_email: false },
            &[action(UPDATE_PASSWORD_ACTION, true)],
            &[],
        );
        assert!(e.temporary_password_is_enforced());
        let lines = RealmEnforcementCheck::Checked(e).report_lines("ct-demo", PROVISIONING_ONLY);
        assert!(warnings(&lines).is_empty(), "a healthy realm must not warn: {lines:?}");
        assert_eq!(lines.len(), 1, "exactly one confirmation line, so the log proves the check ran: {lines:?}");
        assert!(
            lines[0].contains("ct-demo") && lines[0].contains(UPDATE_PASSWORD_ACTION),
            "{}",
            lines[0]
        );
    }

    #[test]
    fn an_unregistered_update_password_action_is_named_as_the_missing_enforcer_the_2026_08_16_shape() {
        // The real incident: provisioning asked for `"temporary": true` and six
        // accounts carried the action, but nothing in the realm could run it.
        let e = classify_realm_enforcement(
            &RealmEmailPolicy { verify_email: true },
            &[action(VERIFY_EMAIL_ACTION, true), action("CONFIGURE_TOTP", true)],
            &[],
        );
        assert_eq!(e.update_password_action, RequiredActionState::Missing);
        assert!(!e.temporary_password_is_enforced());

        let lines = RealmEnforcementCheck::Checked(e).report_lines("ct-demo", PROVISIONING_ONLY);
        let w = warnings(&lines);
        assert_eq!(w.len(), 1, "{lines:?}");
        assert!(w[0].contains(UPDATE_PASSWORD_ACTION) && w[0].contains("NOT REGISTERED"), "{}", w[0]);
        assert!(w[0].contains("Authentication -> Required actions"), "says where to fix it: {}", w[0]);
        assert!(
            w[0].contains("temporary") && w[0].contains("forever"),
            "names the consequence -- the one-time password is not one-time: {}",
            w[0]
        );
    }

    #[test]
    fn a_registered_but_disabled_update_password_action_is_reported_as_no_enforcement() {
        let e = classify_realm_enforcement(
            &RealmEmailPolicy { verify_email: true },
            &[action(UPDATE_PASSWORD_ACTION, false)],
            &[],
        );
        assert_eq!(e.update_password_action, RequiredActionState::Disabled);
        assert!(
            !e.temporary_password_is_enforced(),
            "a disabled action enforces exactly as much as a missing one"
        );
        let lines = RealmEnforcementCheck::Checked(e).report_lines("ct-demo", PROVISIONING_ONLY);
        let w = warnings(&lines);
        assert_eq!(w.len(), 1, "{lines:?}");
        assert!(w[0].contains("DISABLED") && w[0].contains(UPDATE_PASSWORD_ACTION), "{}", w[0]);
        assert!(
            !lines.iter().any(|l| l.contains("one-time-password enforcement checked")),
            "no confirmation line when the action cannot run: {lines:?}"
        );
    }

    #[test]
    fn an_unrunnable_check_never_reads_like_an_enforced_one_time_password() {
        let check = RealmEnforcementCheck::NotChecked("connection refused".to_string());

        let lines = check.report_lines("ct-demo", PROVISIONING_ONLY);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("#536") && lines[0].contains("could not"), "{}", lines[0]);
        assert!(lines[0].contains("connection refused"), "the real cause must survive: {}", lines[0]);
        assert!(lines[0].contains("NOT an all-clear"), "{}", lines[0]);
        assert!(
            !lines[0].contains("one-time-password enforcement checked"),
            "must never emit the confirmation wording: {}",
            lines[0]
        );

        // Both statements in scope: an unreachable admin API leaves BOTH unproven,
        // and each says so for itself.
        let both = check.report_lines("ct-demo", BOTH);
        assert_eq!(both.len(), 2, "{both:?}");
        assert!(both.iter().all(|l| l.contains("WARNING") && l.contains("NOT an all-clear")), "{both:?}");
        assert!(both[0].contains("#535") && both[1].contains("#536"), "{both:?}");
    }

    /// The point of #536 next to #535: the two conditions are unrelated, so a
    /// report about one must never blame -- or vouch for -- the other.
    #[test]
    fn the_verified_email_and_one_time_password_statements_are_independent() {
        // (a) Email confirmation fully in order, the one-time password unenforced.
        let e = classify_realm_enforcement(
            &RealmEmailPolicy { verify_email: true },
            &[action(VERIFY_EMAIL_ACTION, true)],
            &[],
        );
        assert!(e.verified_email_is_enforced() && !e.temporary_password_is_enforced());
        let lines = RealmEnforcementCheck::Checked(e).report_lines("ct-demo", BOTH);
        let w = warnings(&lines);
        assert_eq!(w.len(), 1, "only the broken statement warns: {lines:?}");
        assert!(w[0].contains(UPDATE_PASSWORD_ACTION), "{}", w[0]);
        assert!(
            !w[0].contains(VERIFY_EMAIL_ACTION) && !w[0].contains("verifyEmail"),
            "must not drag in the email confirmation, which is intact: {}",
            w[0]
        );
        assert!(
            lines.iter().any(|l| l.contains("verified-email gate checked")),
            "the intact statement is still confirmed: {lines:?}"
        );

        // (b) The mirror image: one-time password enforced, email confirmation
        // inert -- the 2026-08-16 realm as it would have looked with only #536 fixed.
        let e = classify_realm_enforcement(
            &RealmEmailPolicy { verify_email: true },
            &[action(UPDATE_PASSWORD_ACTION, true)],
            &[],
        );
        let lines = RealmEnforcementCheck::Checked(e).report_lines("ct-demo", BOTH);
        let w = warnings(&lines);
        assert_eq!(w.len(), 1, "{lines:?}");
        assert!(w[0].contains(VERIFY_EMAIL_ACTION) && w[0].contains("NOT REGISTERED"), "{}", w[0]);
        assert!(
            !w[0].contains(UPDATE_PASSWORD_ACTION),
            "must not blame the password action, which is fine here: {}",
            w[0]
        );
        assert!(
            lines.iter().any(|l| l.contains("one-time-password enforcement checked")),
            "{lines:?}"
        );

        // (c) Scope, not health, decides who speaks: with the gate off, a realm
        // that enforces no email confirmation at all is simply not this check's
        // business, while the provisioning statement still gets made.
        let e = classify_realm_enforcement(
            &RealmEmailPolicy { verify_email: false },
            &[action(UPDATE_PASSWORD_ACTION, true), action(VERIFY_EMAIL_ACTION, true)],
            &[],
        );
        let lines = RealmEnforcementCheck::Checked(e.clone()).report_lines("ct-demo", PROVISIONING_ONLY);
        assert!(!lines.iter().any(|l| l.contains("#535")), "gate off: no verified-email verdict: {lines:?}");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("#536"), "{}", lines[0]);

        // ... and symmetrically, a control plane that cannot provision says
        // nothing about a password enforcement it never relies on.
        let lines = RealmEnforcementCheck::Checked(e).report_lines("ct-demo", GATE_ONLY);
        assert!(!lines.iter().any(|l| l.contains("#536")), "no provisioning: no #536 verdict: {lines:?}");
        assert_eq!(warnings(&lines).len(), 1, "only the realm flag, which the gate does depend on: {lines:?}");
    }

    /// Both statements come out of the single required-actions read #535 already
    /// did -- proven by counting the requests the check actually makes, not by
    /// reading the code.
    #[tokio::test]
    async fn both_statements_are_read_off_one_required_actions_request() {
        use axum::extract::State;
        use axum::routing::{get, post};
        use axum::{Json, Router};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        type Hits = Arc<AtomicUsize>;

        async fn token() -> Json<serde_json::Value> {
            Json(json!({ "access_token": "test-admin-token" }))
        }
        async fn realm() -> Json<serde_json::Value> {
            Json(json!({ "realm": "ct-demo", "verifyEmail": true }))
        }
        async fn required_actions(State(hits): State<Hits>) -> Json<serde_json::Value> {
            hits.fetch_add(1, Ordering::SeqCst);
            // One list, both providers -- exactly what Keycloak returns.
            Json(json!([
                { "alias": "VERIFY_EMAIL", "providerId": "VERIFY_EMAIL", "enabled": true },
                { "alias": "UPDATE_PASSWORD", "providerId": "UPDATE_PASSWORD", "enabled": true },
            ]))
        }
        async fn idps() -> Json<serde_json::Value> {
            Json(json!([]))
        }

        let hits: Hits = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/realms/master/protocol/openid-connect/token", post(token))
            .route("/admin/realms/ct-demo", get(realm))
            .route("/admin/realms/ct-demo/authentication/required-actions", get(required_actions))
            .route("/admin/realms/ct-demo/identity-provider/instances", get(idps))
            .with_state(hits.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let cfg = KeycloakAdminConfig {
            base_url: format!("http://{addr}"),
            realm: "ct-demo".to_string(),
            admin_user: "admin".to_string(),
            admin_password: "pw".to_string(),
        };
        let check = check_realm_enforcement(&reqwest::Client::new(), &cfg).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "the second statement must not cost a second round trip"
        );
        let lines = check.report_lines(&cfg.realm, BOTH);
        assert!(warnings(&lines).is_empty(), "{lines:?}");
        assert_eq!(lines.len(), 2, "one confirmation per statement: {lines:?}");
        assert!(lines[0].contains("#535") && lines[1].contains("#536"), "{lines:?}");
    }

    /// The wire half: real Keycloak field names (`verifyEmail`, `providerId`,
    /// `trustEmail`) parsed off a mock admin API, so the classification above is
    /// fed by the shapes Keycloak actually returns.
    #[tokio::test]
    async fn check_realm_enforcement_reads_the_real_admin_api_shapes() {
        use axum::routing::{get, post};
        use axum::{Json, Router};

        async fn token() -> Json<serde_json::Value> {
            Json(json!({ "access_token": "test-admin-token" }))
        }
        async fn realm() -> Json<serde_json::Value> {
            // A trimmed but realistically-shaped RealmRepresentation: the check must
            // pick its one field out of a document full of unrelated ones.
            Json(json!({
                "id": "ct-demo",
                "realm": "ct-demo",
                "enabled": true,
                "registrationAllowed": true,
                "verifyEmail": true,
                "resetPasswordAllowed": true,
            }))
        }
        async fn required_actions() -> Json<serde_json::Value> {
            Json(json!([
                { "alias": "CONFIGURE_TOTP", "name": "Configure OTP", "providerId": "CONFIGURE_TOTP", "enabled": true, "defaultAction": false, "priority": 10 },
                { "alias": "VERIFY_EMAIL", "name": "Verify Email", "providerId": "VERIFY_EMAIL", "enabled": true, "defaultAction": false, "priority": 50 },
            ]))
        }
        async fn idps() -> Json<serde_json::Value> {
            Json(json!([
                { "alias": "google", "providerId": "google", "enabled": true, "trustEmail": true },
                { "alias": "saml-corp", "providerId": "saml", "enabled": true, "trustEmail": false },
            ]))
        }

        let app = Router::new()
            .route("/realms/master/protocol/openid-connect/token", post(token))
            .route("/admin/realms/ct-demo", get(realm))
            .route("/admin/realms/ct-demo/authentication/required-actions", get(required_actions))
            .route("/admin/realms/ct-demo/identity-provider/instances", get(idps));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let cfg = KeycloakAdminConfig {
            base_url: format!("http://{addr}"),
            realm: "ct-demo".to_string(),
            admin_user: "admin".to_string(),
            admin_password: "pw".to_string(),
        };
        let check = check_realm_enforcement(&reqwest::Client::new(), &cfg).await;
        assert_eq!(
            check,
            RealmEnforcementCheck::Checked(RealmEnforcement {
                realm_verify_email: true,
                verify_email_action: RequiredActionState::Registered,
                // This mock realm registers no UPDATE_PASSWORD -- read off the very
                // same list, without a fourth request.
                update_password_action: RequiredActionState::Missing,
                trust_email_idps: vec!["google".to_string()],
            })
        );
        let lines = check.report_lines(&cfg.realm, GATE_ONLY);
        assert!(warnings(&lines).is_empty(), "{lines:?}");
        assert_eq!(lines.len(), 2, "confirmation + the trustEmail listing: {lines:?}");
    }

    /// The realm on 2026-08-16, end to end over HTTP: `verifyEmail=true` with no
    /// `VERIFY_EMAIL` provider anywhere in the required-actions list.
    #[tokio::test]
    async fn check_realm_enforcement_catches_the_inert_realm_flag_over_http() {
        use axum::routing::{get, post};
        use axum::{Json, Router};

        async fn token() -> Json<serde_json::Value> {
            Json(json!({ "access_token": "test-admin-token" }))
        }
        async fn realm() -> Json<serde_json::Value> {
            Json(json!({ "realm": "ct-demo", "verifyEmail": true }))
        }
        async fn required_actions() -> Json<serde_json::Value> {
            Json(json!([
                { "alias": "UPDATE_PASSWORD", "providerId": "UPDATE_PASSWORD", "enabled": true },
            ]))
        }
        async fn idps() -> Json<serde_json::Value> {
            Json(json!([]))
        }

        let app = Router::new()
            .route("/realms/master/protocol/openid-connect/token", post(token))
            .route("/admin/realms/ct-demo", get(realm))
            .route("/admin/realms/ct-demo/authentication/required-actions", get(required_actions))
            .route("/admin/realms/ct-demo/identity-provider/instances", get(idps));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let cfg = KeycloakAdminConfig {
            base_url: format!("http://{addr}"),
            realm: "ct-demo".to_string(),
            admin_user: "admin".to_string(),
            admin_password: "pw".to_string(),
        };
        let lines = check_realm_enforcement(&reqwest::Client::new(), &cfg)
            .await
            .report_lines(&cfg.realm, GATE_ONLY);
        let w = warnings(&lines);
        assert_eq!(w.len(), 1, "{lines:?}");
        assert!(w[0].contains("VERIFY_EMAIL") && w[0].contains("NOT REGISTERED"), "{}", w[0]);
    }

    #[tokio::test]
    async fn an_unreachable_or_forbidden_admin_api_reports_not_checked_not_all_clear() {
        use axum::routing::{get, post};
        use axum::{Json, Router};

        // (a) Admin API answers, but the account may not read the realm (403).
        async fn token() -> Json<serde_json::Value> {
            Json(json!({ "access_token": "test-admin-token" }))
        }
        async fn forbidden() -> axum::http::StatusCode {
            axum::http::StatusCode::FORBIDDEN
        }
        let app = Router::new()
            .route("/realms/master/protocol/openid-connect/token", post(token))
            .route("/admin/realms/ct-demo", get(forbidden));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let cfg = KeycloakAdminConfig {
            base_url: format!("http://{addr}"),
            realm: "ct-demo".to_string(),
            admin_user: "admin".to_string(),
            admin_password: "pw".to_string(),
        };
        let check = check_realm_enforcement(&reqwest::Client::new(), &cfg).await;
        match &check {
            RealmEnforcementCheck::NotChecked(why) => assert!(why.contains("403"), "the real status must survive: {why}"),
            other => panic!("a 403 must not be classified as an enforcement verdict: {other:?}"),
        }
        let lines = check.report_lines(&cfg.realm, GATE_ONLY);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("could not be checked") && lines[0].contains("NOT an all-clear"), "{}", lines[0]);

        // (b) Nothing listening at all: bind, learn the port, then drop the listener.
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        let cfg = KeycloakAdminConfig {
            base_url: format!("http://{dead_addr}"),
            realm: "ct-demo".to_string(),
            admin_user: "admin".to_string(),
            admin_password: "pw".to_string(),
        };
        let lines = check_realm_enforcement(&reqwest::Client::new(), &cfg)
            .await
            .report_lines(&cfg.realm, GATE_ONLY);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("could not be checked"), "{}", lines[0]);
        assert!(
            !lines[0].contains("verified-email gate checked"),
            "an unreachable Keycloak must never produce the confirmation line: {}",
            lines[0]
        );
    }
}
