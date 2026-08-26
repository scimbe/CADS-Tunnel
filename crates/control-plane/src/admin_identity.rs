//! Admin identity (ADR-0025 "Admin Console — Traffic Monitor, Multi-Admin,
//! Multi-Domain Management", Decision 1/2): a narrow, explicit carve-out on top
//! of this system's otherwise-pseudonymous account model (ADR-0012). Binding
//! admin privilege to a real Google email mirrors the precedent `gate.rs`
//! already sets for individual tunnels' optional email-gated access — it is
//! not a signal to weaken the pseudonymous model for ordinary users.
//!
//! `CT_ADMIN_SUPER_EMAIL` names a startup-configured invariant, not just the
//! first row in the `admins` table: it can never be removed, and it is the
//! ONLY account allowed to add or remove *other* admin rows (enforced here in
//! code, not merely by which routes a caller can reach — see [`AdminIdentity::
//! remove_admin`]'s defense-in-depth check).
//!
//! Required, fail-closed at process startup (mirrors the posture the operator
//! asked for `CT_ADMIN_SUPER_EMAIL` to have, matching `CT_EDGE_ADMIN_TOKEN`'s
//! spirit as "no admin surface without an explicit operator secret/identity
//! configured"): [`super_admin_email_from_env`] returns `Err` when unset or
//! empty, and `main.rs` propagates that `Err` out of `main()` so the process
//! never starts serving anything without a super-admin configured, rather than
//! silently booting with an admin console nobody can reach or — worse — one
//! reachable by nobody being asserted.

use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::http::StatusCode;
use std::sync::Arc;

use crate::storage::SqliteAdminStore;

/// Read `CT_ADMIN_SUPER_EMAIL` once at startup. Required: unset or all-whitespace
/// is an `Err`, not a fallback — an admin console with no super-admin configured
/// must not come up at all (fail-closed, same posture requested for every other
/// required operator secret in this codebase, e.g. `CT_EDGE_ADMIN_TOKEN`).
/// Normalizes to lowercase (matches [`AdminIdentity`]'s comparisons and every
/// other email column in this crate — see `storage.rs`'s `to_ascii_lowercase()`
/// convention).
pub fn super_admin_email_from_env() -> Result<String, String> {
    match std::env::var("CT_ADMIN_SUPER_EMAIL") {
        Ok(s) if !s.trim().is_empty() => Ok(s.trim().to_ascii_lowercase()),
        _ => Err(
            "CT_ADMIN_SUPER_EMAIL is required (fail-closed) -- the control plane refuses to \
             start without a configured super-admin email (ADR-0025 Decision 2)"
                .to_string(),
        ),
    }
}

/// Errors from [`AdminIdentity::add_admin`]/[`AdminIdentity::remove_admin`].
#[derive(Debug)]
pub enum AdminError {
    /// Only the super-admin may add or remove admin rows at all (ADR-0025
    /// Decision 2) — `actor_email` was not `CT_ADMIN_SUPER_EMAIL`.
    NotSuperAdmin,
    /// The super-admin's own row can never be removed, regardless of who is
    /// asking — including the super-admin itself (ADR-0025 Decision 2, defense
    /// in depth: enforced here even though only the super-admin's own session
    /// can reach this call at all).
    CannotRemoveSuperAdmin,
    Db(rusqlite::Error),
}

impl std::fmt::Display for AdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminError::NotSuperAdmin => write!(f, "only the super-admin may add or remove admins"),
            AdminError::CannotRemoveSuperAdmin => write!(f, "the super-admin account can never be removed"),
            AdminError::Db(e) => write!(f, "storage error: {e}"),
        }
    }
}
impl std::error::Error for AdminError {}
impl From<rusqlite::Error> for AdminError {
    fn from(e: rusqlite::Error) -> Self {
        AdminError::Db(e)
    }
}

/// Admin identity/authorization on top of [`SqliteAdminStore`]'s bare CRUD:
/// who the super-admin is (from startup config) and the add/remove policy
/// around it. One instance is constructed at boot and shared (behind an
/// `Arc`) by every admin-ui route this and later phases add.
#[derive(Clone)]
pub struct AdminIdentity {
    store: Arc<SqliteAdminStore>,
    /// Always lowercased at construction (see [`super_admin_email_from_env`]).
    super_admin_email: Arc<str>,
}

impl AdminIdentity {
    pub fn new(store: Arc<SqliteAdminStore>, super_admin_email: impl AsRef<str>) -> Self {
        Self {
            store,
            super_admin_email: Arc::from(super_admin_email.as_ref().to_ascii_lowercase()),
        }
    }

    /// Whether `email` is the one startup-configured super-admin. Plain
    /// (non-constant-time) comparison is deliberate: unlike a bearer-token
    /// check (`ct_token_eq`'s reason to exist), an email address is not a
    /// secret an attacker is trying to *guess* character-by-character via a
    /// timing side channel — it's a known, often-public identity string
    /// compared for equality, the same posture every hostname/email
    /// allow-list comparison elsewhere in this crate already takes.
    pub fn is_super_admin(&self, email: &str) -> bool {
        email.eq_ignore_ascii_case(&self.super_admin_email)
    }

    /// Whether `email` has a row in the `admins` table. A storage error is
    /// treated as "not an admin" (fail-closed: a DB hiccup must never
    /// accidentally grant admin access), matching this crate's own posture
    /// elsewhere of degrading a lookup failure toward the safer answer rather
    /// than propagating a 500 into an authorization decision.
    pub fn is_admin(&self, email: &str) -> bool {
        self.store.is_admin(email).unwrap_or(false)
    }

    /// Idempotently ensure the super-admin has a row in `admins`. Called once
    /// at every startup (`main.rs`) — `added_by` is `None` (the super-admin's
    /// seed row has no human actor; it is a startup invariant asserted by
    /// configuration, not something anyone with admin access added), and
    /// `added_at` is "now" the FIRST time this runs (subsequent boots are a
    /// no-op via `INSERT OR IGNORE`, so the original seed time is preserved).
    pub fn ensure_super_admin_seeded(&self) -> rusqlite::Result<()> {
        self.store.add_admin_row(&self.super_admin_email, None, now_secs())
    }

    /// Add `new_admin_email` as an admin. Only the super-admin may call this
    /// (ADR-0025 Decision 2) — `actor_email` is the CURRENT session's verified
    /// email, resolved by the caller (e.g. [`admin_session_from_headers`])
    /// before this is reached; this function re-checks it itself rather than
    /// trusting the caller, so it is safe to call from anywhere, not just a
    /// route that has already gated on `is_super_admin`.
    pub fn add_admin(&self, actor_email: &str, new_admin_email: &str) -> Result<(), AdminError> {
        if !self.is_super_admin(actor_email) {
            return Err(AdminError::NotSuperAdmin);
        }
        self.store
            .add_admin_row(new_admin_email, Some(actor_email), now_secs())?;
        Ok(())
    }

    /// Remove `target_email`'s admin row. Only the super-admin may call this,
    /// AND the super-admin's own row is refused regardless of who is asking —
    /// including the super-admin acting on itself. The second check is
    /// deliberately unconditional (not `else`-chained under "actor is super-
    /// admin"): a future caller of this function that skips the `is_super_admin`
    /// gate above (a bug, a new call site) still cannot delete the super-admin's
    /// row, which is the actual invariant ADR-0025 Decision 2 asks for ("enforced
    /// in code, not just by who's allowed to call it").
    pub fn remove_admin(&self, actor_email: &str, target_email: &str) -> Result<(), AdminError> {
        if !self.is_super_admin(actor_email) {
            return Err(AdminError::NotSuperAdmin);
        }
        if self.is_super_admin(target_email) {
            return Err(AdminError::CannotRemoveSuperAdmin);
        }
        self.store.remove_admin_row(target_email)?;
        Ok(())
    }

    /// Every admin row (later-phase admin-management UI).
    pub fn list_admins(&self) -> rusqlite::Result<Vec<crate::storage::AdminRow>> {
        self.store.list_admins()
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The current request's resolved admin identity — what every future admin-ui
/// route (later phases) needs to both authorize the request and know whether
/// the extra super-admin-only actions (add/remove admin) are available to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminSession {
    pub email: String,
    pub is_super_admin: bool,
}

/// Resolve the current request's admin session, mirroring `portal_api::
/// account_for_session`'s shape (a plain function over `&HeaderMap`, not an
/// axum `FromRequestParts` extractor — this codebase doesn't use those; every
/// existing authed handler calls a resolver function like this one first) and
/// `gate.rs`'s "verified email" precedent: the session cookie's verified email
/// (only ever present when the IdP asserted `email_verified` at login — see
/// `portal.rs`'s callback) checked against the `admins` table.
///
/// `401 Unauthorized` when there is no valid session, or the session has no
/// verified email at all (an unverified identity can never be an admin —
/// there is nothing here for `CT_GATE_REQUIRE_VERIFIED_EMAIL`-style opt-out,
/// the admin surface always requires it). `403 Forbidden` when the session is
/// valid and verified but the email isn't in the `admins` table. Every future
/// admin-ui route calls this first, the same way every existing `/portal/*`
/// handler calls `account_for_session`.
///
/// **Open item for whoever wires up `/admin-ui/*` (ADR-0025 Decision 5
/// addendum, 2026-08-25):** this reads the `ct_portal_session` cookie, which
/// `portal.rs` mints host-only (no `Domain=`). Decision 5 serves the admin
/// console from its own distinct hostname (`CT_EDGE_ADMIN_UI_HOST`), so that
/// cookie — as configured today — never actually reaches it; a real admin
/// visiting `admin.<zone>` still gets `401`. See the ADR addendum for the two
/// options (widen Portal's cookie vs. give admin-ui its own `gate.rs`-shaped
/// login+session) — this function's own logic is correct either way, only
/// which cookie mints the session it reads is still open.
pub fn admin_session_from_headers(
    session_key: &[u8],
    admin: &AdminIdentity,
    headers: &HeaderMap,
) -> Result<AdminSession, Response> {
    let claims = crate::portal::session_claims_for(session_key, headers)
        .ok_or_else(|| StatusCode::UNAUTHORIZED.into_response())?;
    let Some(email) = claims.email else {
        return Err(StatusCode::UNAUTHORIZED.into_response());
    };
    if !admin.is_admin(&email) {
        return Err(StatusCode::FORBIDDEN.into_response());
    }
    let is_super_admin = admin.is_super_admin(&email);
    Ok(AdminSession { email, is_super_admin })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portal::sign_session_with_email_for_test;
    use crate::storage::SqliteAdminStore;

    const KEY: &[u8] = b"test-admin-session-key";
    const SUPER: &str = "scimbe@gmail.com";

    fn identity() -> AdminIdentity {
        let store = Arc::new(SqliteAdminStore::open_in_memory().unwrap());
        AdminIdentity::new(store, SUPER)
    }

    fn seeded_identity() -> AdminIdentity {
        let id = identity();
        id.ensure_super_admin_seeded().unwrap();
        id
    }

    // --- fail-first proof: env var is genuinely required ---------------------

    #[test]
    fn super_admin_email_from_env_fails_closed_when_unset() {
        // Isolated by construction: this reads the real process environment, so
        // this test only asserts the *shape* of the guard (unset => Err), not a
        // specific process-wide state -- the crate never calls std::env::set_var
        // for this key outside of a test explicitly opting in, and no other test
        // in this module sets it.
        if std::env::var("CT_ADMIN_SUPER_EMAIL").is_ok() {
            // Some other process-level state already set it (shouldn't happen in
            // this crate's own test suite) -- skip rather than give a false pass.
            return;
        }
        assert!(
            super_admin_email_from_env().is_err(),
            "CT_ADMIN_SUPER_EMAIL unset must fail closed, not silently default"
        );
    }

    // --- is_super_admin / is_admin --------------------------------------------

    #[test]
    fn is_super_admin_matches_case_insensitively_but_rejects_other_emails() {
        let id = identity();
        assert!(id.is_super_admin("scimbe@gmail.com"));
        assert!(id.is_super_admin("SciMBE@Gmail.com"));
        assert!(!id.is_super_admin("attacker@example.com"));
        assert!(!id.is_super_admin("scimbe@gmail.com.evil.example"));
    }

    #[test]
    fn ensure_super_admin_seeded_is_idempotent_and_makes_the_super_admin_an_admin() {
        let id = identity();
        assert!(!id.is_admin(SUPER), "not seeded yet");
        id.ensure_super_admin_seeded().unwrap();
        assert!(id.is_admin(SUPER));
        // Second boot: must not error or duplicate.
        id.ensure_super_admin_seeded().unwrap();
        assert_eq!(id.list_admins().unwrap().len(), 1, "seeding twice must not duplicate the row");
    }

    // --- add_admin / remove_admin authorization -------------------------------

    #[test]
    fn add_admin_by_the_super_admin_succeeds_and_the_new_admin_is_not_itself_super() {
        let id = seeded_identity();
        id.add_admin(SUPER, "second@example.com").unwrap();
        assert!(id.is_admin("second@example.com"));
        assert!(!id.is_super_admin("second@example.com"));
    }

    #[test]
    fn add_admin_refuses_a_non_super_admin_actor() {
        let id = seeded_identity();
        id.add_admin(SUPER, "second@example.com").unwrap();
        let err = id.add_admin("second@example.com", "third@example.com");
        assert!(matches!(err, Err(AdminError::NotSuperAdmin)));
        assert!(!id.is_admin("third@example.com"), "the refused add must not have happened");
    }

    #[test]
    fn remove_admin_by_the_super_admin_removes_a_regular_admin() {
        let id = seeded_identity();
        id.add_admin(SUPER, "second@example.com").unwrap();
        id.remove_admin(SUPER, "second@example.com").unwrap();
        assert!(!id.is_admin("second@example.com"));
    }

    #[test]
    fn remove_admin_refuses_a_non_super_admin_actor_even_targeting_someone_else() {
        let id = seeded_identity();
        id.add_admin(SUPER, "second@example.com").unwrap();
        id.add_admin(SUPER, "third@example.com").unwrap();
        let err = id.remove_admin("second@example.com", "third@example.com");
        assert!(matches!(err, Err(AdminError::NotSuperAdmin)));
        assert!(id.is_admin("third@example.com"), "the refused remove must not have happened");
    }

    /// Fail-first proof (ADR-0025 Decision 2's hard rule): even the super-admin's
    /// OWN session, acting on ITSELF, must be refused. This is the specific
    /// property "enforced in code, not just by who's allowed to call it" protects
    /// against -- without the second `is_super_admin(target_email)` check inside
    /// `remove_admin` (independent of the actor check just above it), a caller
    /// that IS legitimately the super-admin would otherwise be able to delete its
    /// own row and lock the deployment out of admin management entirely.
    #[test]
    fn remove_admin_refuses_even_the_super_admins_own_session_removing_itself() {
        let id = seeded_identity();
        let err = id.remove_admin(SUPER, SUPER);
        assert!(
            matches!(err, Err(AdminError::CannotRemoveSuperAdmin)),
            "got {err:?}"
        );
        assert!(id.is_admin(SUPER), "the super-admin row must still be present");
    }

    // --- admin_session_from_headers --------------------------------------------

    fn cookie(subject: &str, email: &str) -> String {
        format!("ct_portal_session={}", sign_session_with_email_for_test(KEY, subject, email))
    }

    fn headers_with_cookie(value: String) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(axum::http::header::COOKIE, value.parse().unwrap());
        h
    }

    #[test]
    fn admin_session_from_headers_is_unauthorized_with_no_session_at_all() {
        let id = seeded_identity();
        let resp = admin_session_from_headers(KEY, &id, &HeaderMap::new());
        assert_eq!(resp.unwrap_err().status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn admin_session_from_headers_is_unauthorized_when_the_session_has_no_verified_email() {
        let id = seeded_identity();
        // `sign_session_for_test` (no email) mirrors a session minted before this
        // IdP ever asserted `email_verified` -- see portal.rs's callback.
        let tok = crate::portal::sign_session_for_test(KEY, "some-subject");
        let headers = headers_with_cookie(format!("ct_portal_session={tok}"));
        let resp = admin_session_from_headers(KEY, &id, &headers);
        assert_eq!(resp.unwrap_err().status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn admin_session_from_headers_is_forbidden_for_a_verified_but_non_admin_email() {
        let id = seeded_identity();
        let headers = headers_with_cookie(cookie("someone", "not-an-admin@example.com"));
        let resp = admin_session_from_headers(KEY, &id, &headers);
        assert_eq!(resp.unwrap_err().status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn admin_session_from_headers_admits_the_seeded_super_admin_and_flags_it_as_super() {
        let id = seeded_identity();
        let headers = headers_with_cookie(cookie("super-subject", SUPER));
        let session = admin_session_from_headers(KEY, &id, &headers).unwrap();
        assert_eq!(session.email, SUPER);
        assert!(session.is_super_admin);
    }

    #[test]
    fn admin_session_from_headers_admits_a_regular_admin_but_does_not_flag_it_as_super() {
        let id = seeded_identity();
        id.add_admin(SUPER, "second@example.com").unwrap();
        let headers = headers_with_cookie(cookie("second-subject", "second@example.com"));
        let session = admin_session_from_headers(KEY, &id, &headers).unwrap();
        assert_eq!(session.email, "second@example.com");
        assert!(!session.is_super_admin);
    }
}
