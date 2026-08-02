//! CADS Tunnel Control-Plane service (M13.3, durable since M18.4d).
//!
//! Serves the enrollment + registry/rendezvous + billing HTTP API over TCP,
//! backed by a durable SQLite database so state survives a restart. Thin and
//! stateless-of-secrets (ADR-0017): holds no Agent private key or payload.
//!
//! Configuration: `CT_CONTROL_PLANE_LISTEN` (default `0.0.0.0:8090`),
//! `CT_CONTROL_PLANE_DB` (default `control-plane.db`),
//! `CT_PAYMENT_WEBHOOK_SECRET` (the payment provider's webhook signing secret;
//! if unset, a random secret is used so the webhook accepts nothing — payment is
//! effectively disabled until a real secret is configured), `CT_PORTAL_SESSION_KEY`
//! (#294: the portal session cookie's HMAC key — a **distinct** secret from the
//! webhook one, since that one is shared with an external payment provider; if
//! unset, a random key is used, so sessions just don't survive a restart until
//! it's set), and `CT_OIDC_ISSUER` + `CT_OIDC_PUBKEY_PATH` (the Keycloak realm
//! issuer and a PEM file with the realm's RSA public key; when both are set the
//! authenticated `/me/*` endpoints are mounted, otherwise they are absent).

use std::net::SocketAddr;
use std::sync::Arc;

use ct_control_plane::oidc::{verifier_from_jwks, verifier_from_jwks_with_retry, OidcVerifier, OidcVerifierHandle};
use ct_control_plane::service::persistent_control_plane_router;

/// Fetch a realm JWKS document over HTTP(S) for the startup verifier (#42 KC2-c).
/// Best-effort: any transport/status/parse failure yields `None`, so a missing or
/// not-yet-ready IdP leaves the /me/* endpoints disabled rather than aborting boot.
///
/// #295: a bare `reqwest::Client::new()` has no timeout, so a hanging IdP (or a
/// MITM on an `http://` `CT_OIDC_ISSUER` that accepts the connection but never
/// answers) blocked `main()` forever — the control plane never finished booting
/// and never started serving anything, not even the unauthenticated routes. The
/// portal's own OIDC back-channel already guards this (#96, `oidc_http_client`),
/// but that's a private helper of the `portal` module, unreachable from this bin
/// crate; this mirrors its bound (10s total + 5s connect) rather than sharing it.
/// A timeout here just becomes another `None` — fail-fast into "/me/* disabled",
/// never a hang.
fn jwks_fetch_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

async fn fetch_jwks(url: String) -> Option<serde_json::Value> {
    let resp = jwks_fetch_client().get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        eprintln!("ct-control-plane: JWKS fetch {url} -> HTTP {}", resp.status());
        return None;
    }
    resp.json::<serde_json::Value>().await.ok()
}

/// #82 SEC82b: apply the opt-in bearer-token audience requirement, if configured.
fn apply_access_aud(v: OidcVerifier, access_aud: Option<&str>) -> Arc<OidcVerifier> {
    match access_aud {
        Some(aud) => Arc::new(v.require_audience(aud)),
        None => Arc::new(v),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listen: SocketAddr = std::env::var("CT_CONTROL_PLANE_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:8090".to_string())
        .parse()?;
    let db = std::env::var("CT_CONTROL_PLANE_DB").unwrap_or_else(|_| "control-plane.db".to_string());

    // The webhook signing secret must match the payment provider's. If it is
    // unconfigured, fall back to an unguessable random secret so no attacker can
    // forge a "payment succeeded" event — payment is simply inert until set.
    let webhook_secret = match std::env::var("CT_PAYMENT_WEBHOOK_SECRET") {
        Ok(s) if !s.is_empty() => s.into_bytes(),
        _ => {
            eprintln!(
                "ct-control-plane: CT_PAYMENT_WEBHOOK_SECRET unset — payment webhook disabled"
            );
            let mut buf = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
            buf.to_vec()
        }
    };

    // Mount the authenticated /me/* endpoints when OIDC is configured. Preferred
    // (#42 KC2-c): CT_OIDC_ISSUER alone — the realm's RS256 signing key is fetched
    // from its JWKS (<issuer>/protocol/openid-connect/certs) at startup, no manual
    // key export. CT_OIDC_PUBKEY_PATH remains an explicit offline override (the
    // realm's RSA public key in PEM), taking precedence when set.
    // #328: track the issuer separately so a JWKS-path failure (the only retryable
    // case — a bad/missing CT_OIDC_PUBKEY_PATH aborts boot outright via `?` above,
    // and an unset CT_OIDC_ISSUER has nothing to retry) can be picked up by a
    // background self-heal task below, instead of permanently disabling `/me/*`
    // for the rest of this process's life. Recurred live twice in one session
    // before this fix (a transient Keycloak/network blip at exactly boot time).
    let mut retry_issuer: Option<String> = None;
    let oidc = match std::env::var("CT_OIDC_ISSUER") {
        Ok(issuer) if !issuer.is_empty() => match std::env::var("CT_OIDC_PUBKEY_PATH") {
            Ok(path) if !path.is_empty() => {
                let pem = std::fs::read(&path)?;
                let verifier = OidcVerifier::from_rsa_pem(&pem, &issuer)
                    .map_err(|e| format!("invalid OIDC realm key at {path}: {e}"))?;
                eprintln!("ct-control-plane: OIDC enabled (issuer={issuer}, key=PEM {path})");
                Some(verifier)
            }
            // #271: retry with a short backoff instead of one shot — a realm still
            // warming up, a rotated key not yet propagated, or a momentary network
            // blip at exactly this moment must not permanently disable /me/* for the
            // rest of this process's life. ~15.5s worst case across 6 attempts.
            _ => match verifier_from_jwks_with_retry(
                &issuer,
                fetch_jwks,
                &[0, 500, 1000, 2000, 4000, 8000],
                |ms| tokio::time::sleep(std::time::Duration::from_millis(ms)),
            )
            .await
            {
                Some(v) => {
                    eprintln!("ct-control-plane: OIDC enabled (issuer={issuer}, key=JWKS)");
                    Some(v)
                }
                None => {
                    eprintln!(
                        "ct-control-plane: CT_OIDC_ISSUER set but the realm JWKS had no usable RS256 key after retrying — /me/* disabled; retrying in the background (#328)"
                    );
                    retry_issuer = Some(issuer);
                    None
                }
            },
        },
        _ => {
            eprintln!("ct-control-plane: CT_OIDC_ISSUER unset — /me/* endpoints disabled");
            None
        }
    };
    // #82 SEC82b: opt-in bearer-token audience enforcement for /me/*. Keycloak
    // access-token audiences vary by client, so this stays off unless the operator
    // supplies their realm's field-checked access-token `aud` via CT_OIDC_ACCESS_AUD.
    // Read once and reused by both the boot-time verifier below and #328's
    // background retry task, so a self-healed verifier enforces the exact same
    // audience requirement a boot-time success would have.
    let access_aud = std::env::var("CT_OIDC_ACCESS_AUD").ok().filter(|s| !s.is_empty());
    if let Some(aud) = &access_aud {
        eprintln!("ct-control-plane: /me/* access-token audience enforced (aud={aud})");
    }
    let oidc_handle = OidcVerifierHandle::new(oidc.map(|v| apply_access_aud(v, access_aud.as_deref())));

    // #328: self-heal a failed boot-time JWKS fetch instead of leaving /me/*
    // permanently disabled. Long, fixed-cadence retries (not the boot path's short
    // backoff) so a genuinely down/misconfigured realm isn't hammered, while a
    // transient blip that outlasts the ~15.5s boot window still recovers within a
    // couple of minutes -- no operator noticing and restarting the process needed.
    // `/status`'s `oidc_enabled` field (already shipped) reflects this handle live,
    // so recovery is observable the moment it happens, not just in process logs.
    if let Some(issuer) = retry_issuer {
        let handle = oidc_handle.clone();
        let access_aud = access_aud.clone();
        tokio::spawn(async move {
            let mut delay = std::time::Duration::from_secs(30);
            const MAX_DELAY: std::time::Duration = std::time::Duration::from_secs(300);
            loop {
                tokio::time::sleep(delay).await;
                match verifier_from_jwks(&issuer, fetch_jwks).await {
                    Some(v) => {
                        eprintln!(
                            "ct-control-plane: OIDC self-healed (issuer={issuer}, key=JWKS) — /me/* now available (#328)"
                        );
                        handle.set(apply_access_aud(v, access_aud.as_deref()));
                        return;
                    }
                    None => {
                        eprintln!(
                            "ct-control-plane: OIDC background retry failed (issuer={issuer}) — retrying in {}s (#328)",
                            delay.as_secs()
                        );
                        delay = std::cmp::min(delay * 2, MAX_DELAY);
                    }
                }
            }
        });
    }

    // #68: the customer-facing install one-liner (/portal/tunnels/{id}/install)
    // embeds this base URL. If it's unset it silently falls back to
    // https://localhost — useless for a real customer — so warn loudly at startup.
    if std::env::var("CT_PORTAL_BASE_URL").map(|s| s.is_empty()).unwrap_or(true) {
        eprintln!(
            "ct-control-plane: CT_PORTAL_BASE_URL unset — customer install one-liners will point at https://localhost; set it to your public portal URL (e.g. https://<zone>)"
        );
    }

    // #294: the portal session cookie's HMAC key MUST NOT be the payment webhook
    // secret — that secret is shared by definition with an external payment
    // provider, so reusing it as a session-signing key let anyone who learns it
    // forge a `ct_portal_session` for any subject (SESSION_CTX is a public label,
    // not a secret). A dedicated CT_PORTAL_SESSION_KEY; unset falls back to an
    // unguessable random key (same pattern as the webhook secret above) — the
    // portal simply forces a fresh login after every restart until it's set,
    // never a shared/guessable key.
    let session_key = match std::env::var("CT_PORTAL_SESSION_KEY") {
        Ok(s) if !s.is_empty() => s.into_bytes(),
        _ => {
            eprintln!(
                "ct-control-plane: CT_PORTAL_SESSION_KEY unset — using a random key \
                 (portal sessions won't survive a restart until it's set)"
            );
            let mut buf = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
            buf.to_vec()
        }
    };

    let app = persistent_control_plane_router(&db, &webhook_secret, &session_key, oidc_handle)?;

    let listener = tokio::net::TcpListener::bind(listen).await?;
    eprintln!("ct-control-plane: listening on {listen}, db={db}");
    // Serve with connection info so the per-IP unauthenticated-writer rate limit
    // (#87 SEC87b-rl) can key on the client address.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
