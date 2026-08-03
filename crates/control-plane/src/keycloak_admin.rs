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

impl KeycloakAdminConfig {
    pub fn from_env() -> Option<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let nonempty = |k: &str| get(k).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        Some(Self {
            base_url: nonempty("KEYCLOAK_PUBLIC_URL")?,
            realm: nonempty("CT_OIDC_REALM").unwrap_or_else(|| "ct-demo".to_string()),
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

async fn admin_token(client: &reqwest::Client, cfg: &KeycloakAdminConfig) -> Result<String, KcError> {
    #[derive(Deserialize)]
    struct TokenResp {
        access_token: String,
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
        .map(|t| t.access_token)
        .map_err(|e| KcError::Http(e.to_string()))
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
    let token = admin_token(client, cfg).await?;
    let realm_url = format!("{}/admin/realms/{}", cfg.base_url.trim_end_matches('/'), cfg.realm);

    let existing = client
        .get(format!("{realm_url}/users"))
        .bearer_auth(&token)
        .query(&[("email", email), ("exact", "true")])
        .send()
        .await
        .map_err(|e| KcError::Http(e.to_string()))?;
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
}
