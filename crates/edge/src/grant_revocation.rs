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
struct RevokedReq {
    channel: String,
    digests: Vec<String>,
}

#[derive(Deserialize)]
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
        }
    }

    fn cached(&self, channel: ChannelId, d: &[u8; 32]) -> Option<bool> {
        let c = self.cache.lock().ok()?;
        let (revoked, at) = c.get(&(channel, *d))?;
        (*revoked || at.elapsed() < NOT_REVOKED_TTL).then_some(*revoked)
    }

    async fn ask(&self, channel: ChannelId, digests: Vec<[u8; 32]>) -> Result<Vec<[u8; 32]>, RevocationLookupError> {
        if self
            .unsupported_until
            .lock()
            .ok()
            .and_then(|u| *u)
            .is_some_and(|t| Instant::now() < t)
        {
            return Err(RevocationLookupError::Unsupported);
        }
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
        let got: Vec<[u8; 32]> = body.revoked.iter().filter_map(|h| decode32(h)).collect();
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
