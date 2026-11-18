//! Edge-side lookup of per-grant revocations (control-plane `channel_grant_revocations`).
//!
//! Admission asks it once per join; the live-splice sweep asks it for every digest that
//! currently carries bytes. Two directions, two defaults:
//!
//! * admission is **fail-closed**: a control plane that cannot be read refuses the join;
//! * a splice already carrying bytes is **fail-static**: only an authoritative "revoked"
//!   cuts it, exactly like the membership sweep (`channel_broker::sweep_live_splice_memberships`).
//!
//! A control plane without the endpoint (404/405) means "no revocation list": the edge then
//! behaves as before this feature, holder-level revocation through membership still works.
//! Nothing is installed in tests unless a test installs a source, and with no source
//! installed every question is answered "not revoked".

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use ct_common::channel::ChannelId;
use serde::{Deserialize, Serialize};

/// Why a lookup produced no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationLookupError {
    /// The control plane predates the endpoint (404/405): there is no revocation list.
    Unsupported,
    /// Transport failure, bad token or malformed reply: the state could not be read.
    Unreadable,
}

pub type RevocationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<[u8; 32]>, RevocationLookupError>> + Send + 'a>>;

/// Where revocations come from. Production: [`CpRevocationSource`].
pub trait RevocationSource: Send + Sync {
    /// Which of `digests` are revoked on `channel`.
    fn revoked_among<'a>(&'a self, channel: ChannelId, digests: Vec<[u8; 32]>) -> RevocationFuture<'a>;
}

static SOURCE: RwLock<Option<Arc<dyn RevocationSource>>> = RwLock::new(None);

/// Install the process-wide source (first production call wins; tests may replace it).
pub fn install(source: Arc<dyn RevocationSource>) {
    if let Ok(mut g) = SOURCE.write() {
        *g = Some(source);
    }
}

/// Install the control-plane backed source once. Idempotent: later calls are ignored.
pub fn install_control_plane(cp_base: &str, admin_token: &[u8; 32]) {
    let already = SOURCE.read().map(|g| g.is_some()).unwrap_or(true);
    if !already {
        install(Arc::new(CpRevocationSource::new(cp_base, admin_token)));
    }
}

fn current() -> Option<Arc<dyn RevocationSource>> {
    SOURCE.read().ok().and_then(|g| g.clone())
}

/// Admission verdict for one presented grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionVerdict {
    Allowed,
    Revoked,
    /// The list could not be read: refuse (fail-closed).
    Unreadable,
}

/// Admission check: is the grant with `digest` on `channel` revoked?
pub async fn admission_verdict(channel: &ChannelId, digest: [u8; 32]) -> AdmissionVerdict {
    let Some(src) = current() else { return AdmissionVerdict::Allowed };
    match src.revoked_among(*channel, vec![digest]).await {
        Ok(v) if v.contains(&digest) => AdmissionVerdict::Revoked,
        Ok(_) | Err(RevocationLookupError::Unsupported) => AdmissionVerdict::Allowed,
        Err(RevocationLookupError::Unreadable) => AdmissionVerdict::Unreadable,
    }
}

/// Sweep check: the revoked subset of `digests`, or empty when nothing is known
/// (fail-static: an unreadable list never cuts a running splice).
pub async fn revoked_for_sweep(channel: &ChannelId, digests: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    let Some(src) = current() else { return Vec::new() };
    src.revoked_among(*channel, digests).await.unwrap_or_default()
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Deserialize))]
struct RevokedReq {
    channel: String,
    digests: Vec<String>,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(Serialize))]
struct RevokedResp {
    revoked: Vec<String>,
}

/// How long answers are reused. A "revoked" answer is final until the grant expires, so it
/// is kept for the whole bound; a "not revoked" answer only briefly, so a fresh revocation
/// reaches admission within seconds.
const NOT_REVOKED_TTL: Duration = Duration::from_secs(5);
const UNSUPPORTED_TTL: Duration = Duration::from_secs(300);
const MAX_CACHED: usize = 4096;

/// Queries `POST /internal/channel/grant-revoked` on the control plane.
pub struct CpRevocationSource {
    client: reqwest::Client,
    url: String,
    admin_token_hex: String,
    cache: Mutex<HashMap<(ChannelId, [u8; 32]), (bool, Instant)>>,
    unsupported_until: Mutex<Option<Instant>>,
    /// #974: whether this endpoint has EVER returned a successful reply in this
    /// process. Once true, a later 404/405 is a fact about THIS request/connection
    /// (a reverse proxy during a CP restart, a misrouted request, a rollback to an
    /// older build) -- not proof the endpoint was never implemented -- so it maps
    /// to [`RevocationLookupError::Unreadable`] (fail-closed) instead of
    /// [`RevocationLookupError::Unsupported`] (fail-open). `Unsupported` is only
    /// ever latched while this is still false.
    ever_succeeded: std::sync::atomic::AtomicBool,
}

impl CpRevocationSource {
    pub fn new(cp_base: &str, admin_token: &[u8; 32]) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .pool_max_idle_per_host(0)
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            url: format!("{}/internal/channel/grant-revoked", cp_base.trim_end_matches('/')),
            admin_token_hex: ct_common::hex::encode(admin_token),
            cache: Mutex::new(HashMap::new()),
            unsupported_until: Mutex::new(None),
            ever_succeeded: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn cached(&self, channel: ChannelId, d: &[u8; 32]) -> Option<bool> {
        let c = self.cache.lock().ok()?;
        let (revoked, at) = c.get(&(channel, *d))?;
        (*revoked || at.elapsed() < NOT_REVOKED_TTL).then_some(*revoked)
    }

    async fn ask(&self, channel: ChannelId, digests: Vec<[u8; 32]>) -> Result<Vec<[u8; 32]>, RevocationLookupError> {
        // #974: consult the cache FIRST, regardless of the unsupported latch below --
        // a digest this edge already knows is revoked must stay revoked even while
        // the latch is active, which `admission_verdict` maps to Allowed. Before this
        // fix, the latch was checked first and short-circuited the whole call,
        // reporting an already-known-revoked digest as Unsupported too.
        let mut revoked = Vec::new();
        let mut unknown = Vec::new();
        for d in digests {
            match self.cached(channel, &d) {
                Some(true) => revoked.push(d),
                Some(false) => {}
                None => unknown.push(d),
            }
        }
        if unknown.is_empty() {
            return Ok(revoked);
        }
        if self
            .unsupported_until
            .lock()
            .ok()
            .and_then(|u| *u)
            .is_some_and(|t| Instant::now() < t)
        {
            return Err(RevocationLookupError::Unsupported);
        }
        let resp = self
            .client
            .post(&self.url)
            .header("x-ct-admin-token", &self.admin_token_hex)
            .json(&RevokedReq {
                channel: ct_common::hex::encode(&channel.0),
                digests: unknown.iter().map(|d| ct_common::hex::encode(d)).collect(),
            })
            .send()
            .await
            .map_err(|e| {
                eprintln!("ct-edge: grant-revocation lookup UNREADABLE [transport]: {e}");
                RevocationLookupError::Unreadable
            })?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::METHOD_NOT_ALLOWED {
            // #974: once this endpoint has ever answered successfully in this
            // process, a 404/405 now is a fact about this one request (proxy
            // hiccup during a CP restart, a misrouted request, a rollback) --
            // not evidence the endpoint was never implemented. Fail closed
            // instead of latching fail-open for the next 300s.
            if self.ever_succeeded.load(std::sync::atomic::Ordering::SeqCst) {
                eprintln!(
                    "ct-edge: grant-revocation lookup UNREADABLE [status={status}, endpoint has \
                     answered successfully before -- not treating this as unsupported]"
                );
                return Err(RevocationLookupError::Unreadable);
            }
            if let Ok(mut u) = self.unsupported_until.lock() {
                *u = Some(Instant::now() + UNSUPPORTED_TTL);
            }
            return Err(RevocationLookupError::Unsupported);
        }
        if !status.is_success() {
            eprintln!("ct-edge: grant-revocation lookup UNREADABLE [status={status}]");
            return Err(RevocationLookupError::Unreadable);
        }
        let body: RevokedResp = resp.json().await.map_err(|_| RevocationLookupError::Unreadable)?;
        self.ever_succeeded.store(true, std::sync::atomic::Ordering::SeqCst);
        let got: Vec<[u8; 32]> = body
            .revoked
            .iter()
            .map(|h| decode32(h))
            .collect::<Option<Vec<_>>>()
            .ok_or(RevocationLookupError::Unreadable)?;
        if let Ok(mut c) = self.cache.lock() {
            if c.len() >= MAX_CACHED {
                c.retain(|_, (r, at)| *r || at.elapsed() < NOT_REVOKED_TTL);
                if c.len() >= MAX_CACHED {
                    c.clear();
                }
            }
            for d in &unknown {
                c.insert((channel, *d), (got.contains(d), Instant::now()));
            }
        }
        revoked.extend(got.into_iter().filter(|d| unknown.contains(d)));
        Ok(revoked)
    }
}

fn decode32(s: &str) -> Option<[u8; 32]> {
    ct_common::hex::decode_32(s)
}

impl RevocationSource for CpRevocationSource {
    fn revoked_among<'a>(&'a self, channel: ChannelId, digests: Vec<[u8; 32]>) -> RevocationFuture<'a> {
        Box::pin(self.ask(channel, digests))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::routing::post;
    use axum::{Json, Router};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Clone)]
    struct MockCp {
        answer_404: Arc<AtomicBool>,
        calls: Arc<AtomicUsize>,
        revoked_hex: Arc<Mutex<Vec<String>>>,
    }

    async fn mock_grant_revoked(State(st): State<MockCp>, Json(req): Json<RevokedReq>) -> axum::response::Response {
        st.calls.fetch_add(1, Ordering::SeqCst);
        if st.answer_404.load(Ordering::SeqCst) {
            return axum::http::StatusCode::NOT_FOUND.into_response();
        }
        let revoked_hex = st.revoked_hex.lock().unwrap().clone();
        let revoked: Vec<String> = req.digests.into_iter().filter(|d| revoked_hex.contains(d)).collect();
        Json(RevokedResp { revoked }).into_response()
    }

    use axum::response::IntoResponse;

    async fn spawn_mock(st: MockCp) -> String {
        let app = Router::new().route("/internal/channel/grant-revoked", post(mock_grant_revoked)).with_state(st);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn a_cached_revoked_digest_stays_revoked_while_the_endpoint_is_unsupported_974() {
        // #974: the latch used to be checked BEFORE the cache, so a digest this
        // edge already proved revoked was reported as Unsupported (-> Allowed by
        // admission_verdict) for the rest of the 300s latch window. admission
        // only ever asks ONE digest at a time, so this reproduces its exact shape.
        let st = MockCp {
            answer_404: Arc::new(AtomicBool::new(false)),
            calls: Arc::new(AtomicUsize::new(0)),
            revoked_hex: Arc::new(Mutex::new(Vec::new())),
        };
        let base = spawn_mock(st.clone()).await;
        let source = CpRevocationSource::new(&base, &[0x11u8; 32]);
        let channel = ChannelId([0xAAu8; 32]);
        let digest = [0x22u8; 32];
        *st.revoked_hex.lock().unwrap() = vec![ct_common::hex::encode(&digest)];

        // First ask: real success, caches the digest as revoked.
        assert_eq!(source.ask(channel, vec![digest]).await, Ok(vec![digest]));
        assert_eq!(st.calls.load(Ordering::SeqCst), 1);

        // Endpoint now starts 404ing (simulating it becoming unsupported) --
        // irrelevant, since the cached revoked verdict must answer without even
        // reaching the mock.
        st.answer_404.store(true, Ordering::SeqCst);
        assert_eq!(
            source.ask(channel, vec![digest]).await,
            Ok(vec![digest]),
            "an already-cached-revoked digest must stay revoked regardless of the unsupported latch"
        );
        assert_eq!(st.calls.load(Ordering::SeqCst), 1, "the cache hit must not even reach the mock");
    }

    #[tokio::test]
    async fn a_404_after_a_prior_success_is_unreadable_not_unsupported_974() {
        // #974: once the endpoint has answered successfully at least once in this
        // process, a later 404/405 is a fact about THIS request (CP restart,
        // misrouted request, rollback), not proof the endpoint was never
        // implemented -- it must fail CLOSED (Unreadable), not fail open
        // (Unsupported, which admission_verdict maps to Allowed).
        let st = MockCp {
            answer_404: Arc::new(AtomicBool::new(false)),
            calls: Arc::new(AtomicUsize::new(0)),
            revoked_hex: Arc::new(Mutex::new(Vec::new())),
        };
        let base = spawn_mock(st.clone()).await;
        let source = CpRevocationSource::new(&base, &[0x11u8; 32]);
        let channel = ChannelId([0xBBu8; 32]);

        // A real success, on some OTHER digest, proves the endpoint is implemented.
        assert_eq!(source.ask(channel, vec![[0x33u8; 32]]).await, Ok(vec![]));

        // Now it starts 404ing for a genuinely never-before-seen digest.
        st.answer_404.store(true, Ordering::SeqCst);
        assert_eq!(
            source.ask(channel, vec![[0x44u8; 32]]).await,
            Err(RevocationLookupError::Unreadable),
            "a 404 after a prior success must be Unreadable (fail-closed), not Unsupported (fail-open)"
        );
    }

    #[tokio::test]
    async fn a_404_with_no_prior_success_is_still_unsupported_974() {
        // The original #517-style behavior must be unchanged for a genuinely old
        // control plane that has NEVER answered this endpoint successfully.
        let st = MockCp {
            answer_404: Arc::new(AtomicBool::new(true)),
            calls: Arc::new(AtomicUsize::new(0)),
            revoked_hex: Arc::new(Mutex::new(Vec::new())),
        };
        let base = spawn_mock(st.clone()).await;
        let source = CpRevocationSource::new(&base, &[0x11u8; 32]);
        let channel = ChannelId([0xCCu8; 32]);
        assert_eq!(source.ask(channel, vec![[0x55u8; 32]]).await, Err(RevocationLookupError::Unsupported));
    }

    /// A reply whose JSON parses but whose `revoked` entries are not valid 64-digit
    /// hex -- the shape #1012 describes.
    async fn mock_malformed_revoked() -> Json<serde_json::Value> {
        Json(serde_json::json!({ "revoked": ["not-hex-at-all"] }))
    }

    #[tokio::test]
    async fn a_reply_with_unparsable_hex_in_revoked_is_unreadable_not_not_revoked() {
        // Exercises CpRevocationSource directly (not through the process-wide `install`/
        // `current` statics) so this test cannot leak a source into unrelated tests
        // sharing the same test binary -- see #1042 on why that global is test-hostile.
        let app = Router::new().route("/internal/channel/grant-revoked", post(mock_malformed_revoked));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let source = CpRevocationSource::new(&format!("http://{addr}"), &[0u8; 32]);
        let channel = ChannelId([0x11u8; 32]);
        let digest = [0x22u8; 32];

        let err = source
            .revoked_among(channel, vec![digest])
            .await
            .expect_err("a malformed revoked entry must not be silently treated as an empty, valid answer");
        assert_eq!(err, RevocationLookupError::Unreadable);
    }
}
