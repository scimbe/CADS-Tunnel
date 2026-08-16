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
    // #430: tracked whenever JWKS mode is in play (not just on a failed boot fetch,
    // unlike the old `retry_issuer` this replaces) -- a realm's signing key can
    // rotate at any time after a *successful* boot too, so the background task
    // below must keep running in the healthy case as well, not just self-heal a
    // bad boot.
    let mut jwks_issuer: Option<String> = None;
    let mut jwks_boot_failed = false;
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
            _ => {
                jwks_issuer = Some(issuer.clone());
                match verifier_from_jwks_with_retry(
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
                        jwks_boot_failed = true;
                        None
                    }
                }
            }
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

    // #328/#430: self-heals a failed boot-time JWKS fetch (permanently disabled
    // /me/* used to need an operator restart to recover) AND periodically re-fetches
    // once healthy, so a realm signing-key rotation -- a routine Keycloak operation
    // -- doesn't turn into an outage for the rest of this process's life either. The
    // old version returned after its first success, which self-healed a bad boot but
    // never refreshed again in the (far more common) case where boot succeeded in
    // the first place. Runs whenever JWKS mode is configured, boot success or not.
    // `/status`'s `oidc_enabled` field (already shipped) reflects this handle live,
    // so a self-heal is observable the moment it happens, not just in process logs.
    if let Some(issuer) = jwks_issuer {
        let handle = oidc_handle.clone();
        let access_aud = access_aud.clone();
        tokio::spawn(async move {
            const PERIODIC_REFRESH: std::time::Duration = std::time::Duration::from_secs(600);
            const MAX_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(300);
            // A failed boot starts retrying soon (self-heal); a healthy boot already
            // has a fresh verifier, so its first re-fetch waits the full period.
            let mut delay = if jwks_boot_failed {
                std::time::Duration::from_secs(30)
            } else {
                PERIODIC_REFRESH
            };
            loop {
                tokio::time::sleep(delay).await;
                match verifier_from_jwks(&issuer, fetch_jwks).await {
                    Some(v) => {
                        eprintln!(
                            "ct-control-plane: OIDC verifier refreshed (issuer={issuer}, key=JWKS) — /me/* available (#328/#430)"
                        );
                        handle.set(apply_access_aud(v, access_aud.as_deref()));
                        delay = PERIODIC_REFRESH;
                    }
                    None => {
                        eprintln!(
                            "ct-control-plane: OIDC background refresh failed (issuer={issuer}) — retrying in {}s (#328/#430)",
                            delay.as_secs()
                        );
                        delay = std::cmp::min(delay * 2, MAX_RETRY_DELAY);
                    }
                }
            }
        });
    }

    // #535 / #536: check that Keycloak actually enforces the two promises this
    // process makes but cannot keep itself. #535: if the Browser-Plane gate
    // requires a verified email, the realm must really ask for the confirmation
    // instead of the gate trusting the claim blind. #536: if this control plane
    // can provision accounts, the `"temporary": true` password it hands out must
    // really have to be changed. On 2026-08-16 neither held -- both required-action
    // providers (`VERIFY_EMAIL`, `UPDATE_PASSWORD`) were unregistered, so the realm
    // flag was inert and one-time passwords were permanent, and nothing in the
    // system said a word. Pure diagnosis on stderr -- it never blocks or aborts
    // boot, and runs in the background so an unreachable Keycloak can't push four
    // admin round trips into this process's time-to-serving.
    ct_control_plane::keycloak_admin::spawn_startup_keycloak_enforcement_check();

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
    //
    // #400 (follow-up to #350/#376): #350 wired `.with_graceful_shutdown` but left the
    // drain UNBOUNDED -- "bounded by axum's own default per-connection idle limits and
    // server operators' own pod termination grace period", i.e. not actually bounded by
    // this process at all. `shutdown_fired` is a second, independently-observable copy of
    // the same shutdown event (the `shutdown_signal()` future itself can only be awaited
    // once, by `with_graceful_shutdown`) so `serve_with_bounded_grace` can start its own
    // grace clock at the exact moment shutdown was requested, not at process start.
    let (shutdown_tx, shutdown_fired) = tokio::sync::watch::channel(false);
    let with_shutdown = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });
    // axum 0.7's `Serve`/`WithGracefulShutdown` only implement `IntoFuture`, not `Future`
    // directly (their `IntoFuture::IntoFuture` associated type is a crate-private,
    // unnameable wrapper) -- so a raw value can't be passed generically as `impl Future`
    // without first driving it through a real `.await` point. Wrapping it in this async
    // block does exactly that: the block itself is a genuine, nameable-as-`impl Future` type.
    let serve_fut = async move { with_shutdown.await };
    serve_with_bounded_grace(serve_fut, shutdown_fired, shutdown_grace()).await?;
    Ok(())
}

/// #350: without this, a SIGTERM (a k8s rollout/restart is the real-world trigger) makes
/// `axum::serve` abort immediately -- dropping every in-flight request, including ones
/// that already kicked off a side effect elsewhere (an OIDC token exchange already sent
/// to the IdP, an edge revoke already in flight after the DB row is gone, a payment
/// webhook that already credited the ledger but hasn't finished responding). Waiting on
/// this future before `axum::serve` returns makes it drain in-flight connections instead
/// of cutting them off. #400: the wait is now explicitly bounded by
/// `serve_with_bounded_grace`, not left to axum's own defaults / the operator's own pod
/// termination grace period.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        let Ok(mut sig) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        else {
            std::future::pending::<()>().await;
            unreachable!();
        };
        sig.recv().await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    eprintln!("ct-control-plane: shutdown signal received, draining in-flight requests");
}

/// Default bound (#400) on how long the drain in `serve_with_bounded_grace` is given
/// once shutdown is requested before it forces an exit regardless of what's still in
/// flight. 30s: generous for a real in-flight request (even one with a side-channel HTTP
/// call to an IdP/payment provider) to finish, short enough to stay under common
/// container/pod termination grace periods (e.g. Kubernetes' 30s default
/// `terminationGracePeriodSeconds`) so this process exits on its own rather than being
/// SIGKILLed by the orchestrator.
const DEFAULT_SHUTDOWN_GRACE_SECS: u64 = 30;

/// Resolve `CT_CP_SHUTDOWN_GRACE_SECS` (#400): unset or unparseable falls back to
/// [`DEFAULT_SHUTDOWN_GRACE_SECS`] (fail-safe -- a typo must not silently produce an
/// unbounded or zero-length drain).
fn shutdown_grace() -> std::time::Duration {
    let secs = match std::env::var("CT_CP_SHUTDOWN_GRACE_SECS") {
        Err(_) => DEFAULT_SHUTDOWN_GRACE_SECS,
        Ok(s) => match s.trim().parse::<u64>() {
            Ok(n) => n,
            Err(_) => {
                eprintln!(
                    "ct-control-plane: invalid CT_CP_SHUTDOWN_GRACE_SECS '{s}' -- using default {DEFAULT_SHUTDOWN_GRACE_SECS}s"
                );
                DEFAULT_SHUTDOWN_GRACE_SECS
            }
        },
    };
    std::time::Duration::from_secs(secs)
}

/// Drives `serve_fut` (an already-constructed `axum::serve(...).with_graceful_shutdown(..)`,
/// or anything with the same `Future<Output = io::Result<()>>` shape) to completion, but
/// never waits more than `grace` PAST THE MOMENT shutdown was actually requested (observed
/// via `shutdown_fired`, a `watch` receiver that turns `true` at the exact instant the
/// signal future given to `with_graceful_shutdown` resolves) -- #400's bounded half of
/// #350's graceful-shutdown wiring, so a request that never finishes (a hung downstream
/// call, a slow/stalled client) can't hang shutdown forever. Before shutdown is requested,
/// the grace timer has not started, so normal request-serving is never itself bounded by
/// `grace`. Returns whichever of "served/drained cleanly" or "grace elapsed" happens
/// first; the caller (`main`) returning either way lets the process exit, which force-closes
/// anything `serve_fut` hadn't finished draining.
async fn serve_with_bounded_grace<F>(
    serve_fut: F,
    mut shutdown_fired: tokio::sync::watch::Receiver<bool>,
    grace: std::time::Duration,
) -> std::io::Result<()>
where
    F: std::future::Future<Output = std::io::Result<()>>,
{
    tokio::pin!(serve_fut);
    tokio::select! {
        biased;
        res = &mut serve_fut => res,
        _ = async {
            if !*shutdown_fired.borrow() {
                let _ = shutdown_fired.changed().await;
            }
            tokio::time::sleep(grace).await;
        } => {
            eprintln!(
                "ct-control-plane: shutdown grace period ({}s) elapsed with requests still in \
                 flight -- forcing exit (#400, CT_CP_SHUTDOWN_GRACE_SECS)",
                grace.as_secs()
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn graceful_shutdown_lets_an_in_flight_request_finish_instead_of_dropping_it_350() {
        // #350: the real property this fix buys -- a shutdown signal that arrives WHILE a
        // request is in flight (an OIDC callback mid-token-exchange, an edge-revoke mid-
        // delete_tunnel) must not cut that request off; the server must finish serving it
        // before it actually stops. This proves the exact axum `.with_graceful_shutdown`
        // wiring `shutdown_signal()` feeds into. It does NOT test OS-signal delivery itself
        // (sending a real SIGTERM/SIGINT to the test process would risk killing the test
        // binary, not something to do in a hermetic unit test) -- the signal SOURCE is
        // swapped for a manually-triggerable oneshot here; everything downstream of it is
        // the real axum shutdown path `main()` actually runs.
        use axum::routing::get;
        use axum::Router;

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        let app = Router::new().route(
            "/slow",
            get(|| async {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                "ok"
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });

        // Start the slow request, then -- while it's still sleeping -- fire the shutdown
        // signal. Without with_graceful_shutdown wired up there is no such hook to test at
        // all; this proves the wired-up hook actually lets the in-flight request finish
        // rather than being cut off the instant shutdown is requested.
        let url = format!("http://{addr}/slow");
        let req = tokio::spawn(async move { reqwest::get(&url).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        tx.send(()).unwrap();

        let resp = req.await.unwrap().unwrap();
        assert_eq!(
            resp.status(),
            200,
            "an in-flight request must complete, not be dropped, when shutdown fires mid-request"
        );
        assert_eq!(resp.text().await.unwrap(), "ok");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn serve_with_bounded_grace_lets_a_request_finish_within_the_grace_window_400() {
        // #400 property (b): a request that completes WITHIN the grace window must be
        // served normally -- the bounded wrapper must not cut it short just because a
        // grace bound exists at all.
        use axum::routing::get;
        use axum::Router;

        let app = Router::new().route(
            "/slow",
            get(|| async {
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                "ok"
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (shutdown_tx, shutdown_fired) = tokio::sync::watch::channel(false);
        let (sig_tx, sig_rx) = tokio::sync::oneshot::channel::<()>();
        let with_shutdown = axum::serve(listener, app).with_graceful_shutdown(async move {
            let _ = sig_rx.await;
            let _ = shutdown_tx.send(true);
        });
        // See main()'s own comment: `WithGracefulShutdown` only implements `IntoFuture`,
        // not `Future` -- wrap it in an async block so it can be passed generically.
        let serve_fut = async move { with_shutdown.await };

        // Generous grace -- well longer than the 150ms the request actually takes, so a
        // pass here proves the request wasn't force-closed, not just that the grace window
        // happened to outlast it by luck.
        let server = tokio::spawn(super::serve_with_bounded_grace(
            serve_fut,
            shutdown_fired,
            std::time::Duration::from_secs(5),
        ));

        let url = format!("http://{addr}/slow");
        let req = tokio::spawn(async move { reqwest::get(&url).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        sig_tx.send(()).unwrap();

        let resp = req.await.unwrap().unwrap();
        assert_eq!(
            resp.status(),
            200,
            "a request finishing within the grace window must be served normally, not force-closed"
        );
        assert_eq!(resp.text().await.unwrap(), "ok");

        // serve_with_bounded_grace itself must return promptly once drained -- not wait out
        // the whole (generous) grace window it was given.
        tokio::time::timeout(std::time::Duration::from_secs(1), server)
            .await
            .expect("returns promptly once the drain is actually complete")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn serve_with_bounded_grace_forces_exit_when_a_request_outlives_the_grace_window_400() {
        // #400 property (c): a request that does NOT finish within the grace window must
        // not hang shutdown forever -- serve_with_bounded_grace must return once the grace
        // bound elapses, regardless of what's still in flight, so the caller (main) can
        // proceed to exit and force-close it.
        use axum::routing::get;
        use axum::Router;

        let app = Router::new().route(
            "/hangs",
            get(|| async {
                // Far longer than the grace window below -- this handler is never allowed
                // to finish naturally within the test's bound.
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                "ok"
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (shutdown_tx, shutdown_fired) = tokio::sync::watch::channel(false);
        let (sig_tx, sig_rx) = tokio::sync::oneshot::channel::<()>();
        let with_shutdown = axum::serve(listener, app).with_graceful_shutdown(async move {
            let _ = sig_rx.await;
            let _ = shutdown_tx.send(true);
        });
        // See main()'s own comment: `WithGracefulShutdown` only implements `IntoFuture`,
        // not `Future` -- wrap it in an async block so it can be passed generically.
        let serve_fut = async move { with_shutdown.await };

        let grace = std::time::Duration::from_millis(150);
        let server = tokio::spawn(super::serve_with_bounded_grace(serve_fut, shutdown_fired, grace));

        let url = format!("http://{addr}/hangs");
        let _req = tokio::spawn(async move { reqwest::get(&url).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let start = tokio::time::Instant::now();
        sig_tx.send(()).unwrap();

        // Must return close to `grace` after the signal fires -- NOT after the request's
        // own 10s duration. The 2s bound below is generous slack above `grace` (150ms)
        // while staying far short of the 10s the stuck request would otherwise force.
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .expect("serve_with_bounded_grace must return within a bounded time, not hang on the stuck request")
            .unwrap()
            .unwrap();
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "must not wait anywhere near the stuck request's own duration: {:?}",
            start.elapsed()
        );
    }
}
