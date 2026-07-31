//! Agent Fabric — edge-side channel-authorize resolver (#81 SEC81c-c c-ii).
//!
//! The live broker's admission gate needs `authorize(channel, holder) ->
//! Option<operator_pubkey>` — the operator key iff the holder is a current member — but
//! the channel registry lives in the control plane. This queries the CP's
//! `POST /internal/channel/authorize` (c-i), presenting the shared edge↔CP admin token,
//! and maps the response to `Option<[u8; 32]>`.
//!
//! It is **fail-closed on authoritative refusals**: a clean 404 (genuinely not a
//! member) or 401 (bad admin token) resolves to `None` and evicts any cached entry —
//! the CP has spoken, and it said no. It is **fail-*static* on transport-class
//! failures** (#231): a timeout, connection error, or malformed 2xx body falls back to
//! the last successful resolution for this `(channel, holder)`, if one is still within
//! [`CACHE_TTL`] — a CP blip mid-restart no longer refuses *every* presenting grant
//! plane-wide just because one lookup couldn't complete, which is what made a single
//! brief CP hiccup indistinguishable from "you were never a member" (#231: "any CP
//! blip refuses the whole plane"). A holder with no prior successful resolution still
//! fails closed on a transport error, exactly as before — this only lets an
//! *already-attested* membership ride out a brief CP restart, it never invents one.
//! `CACHE_TTL` is deliberately short (seconds) to bound how long a revoked member
//! could still ride a stale cache entry after a well-timed CP blip.

use ct_common::channel::ChannelId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Hard bound on a single edge→CP authorize round-trip. Without it, `reqwest::Client::new()` has NO
/// request timeout, so a CP that accepts the TCP connection but never responds hangs `authorize().await`
/// **indefinitely** — and because authorize sits inline in the broker's admission gate
/// (`read_channel_join_on_stream`), every channel's admission then parks with no reply. From the
/// acceptor that surfaces as "admission exchange stalled (#140)" (a hang), NOT "refused" (a clean `NO`),
/// and post-#203 each new connection spawns another admit task that hangs the same way. This bound turns
/// an unresponsive CP into a fast, fail-closed refusal (the `send()` errors → `None` → `NO`) instead of
/// an unbounded stall — surfaced live on #207. 10s is generous for a same-cluster internal call while
/// still bounding the hang.
const DEFAULT_AUTHORIZE_TIMEOUT: Duration = Duration::from_secs(10);

fn hex(bytes: &[u8]) -> String {
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
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn hex_decode_64(s: &str) -> Option<[u8; 64]> {
    if s.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[derive(Serialize)]
struct AuthorizeReq {
    channel: String,
    holder: String,
}

#[derive(Deserialize)]
struct AuthorizeResp {
    operator_pubkey: String,
    #[serde(default)]
    noise_pubkey: Option<String>,
    #[serde(default)]
    noise_attestation: Option<String>,
}

/// A resolved channel membership: the operator key (verifies the grant), the member's
/// attested Noise static key, and the holder-signed attestation over it (#72 AF4 /
/// #100 / #101) — the broker relays the key + attestation to the paired peer so an A2A
/// initiator can verify the key is genuinely the holder's before pinning it.
#[derive(Clone)]
pub struct MemberResolution {
    pub operator_pubkey: [u8; 32],
    pub noise_pubkey: Option<[u8; 32]>,
    pub noise_attestation: Option<[u8; 64]>,
}

/// How long a successful resolution stays usable as a fail-*static* fallback after a
/// later transport-class failure for the same `(channel, holder)` (#231). Deliberately
/// short: it only needs to bridge a brief CP restart, and it bounds how long a member
/// revoked mid-outage could still ride the stale entry.
const CACHE_TTL: Duration = Duration::from_secs(30);

type CacheKey = (ChannelId, [u8; 32]);

/// Resolves channel-join authorization by querying the control plane's c-i endpoint.
#[derive(Clone)]
pub struct ChannelAuthorizer {
    client: reqwest::Client,
    url: String,
    admin_token_hex: String,
    cache: Arc<Mutex<HashMap<CacheKey, (MemberResolution, Instant)>>>,
    cache_ttl: Duration,
}

/// How the CP responded, coarsened to the three cases [`ChannelAuthorizer::resolve`]
/// treats differently: an authoritative refusal, an authoritative grant, or something
/// that isn't really an answer at all (transport error, timeout, malformed body, a
/// non-404/401 error status) — see the module doc comment for why those three cases
/// aren't all "None".
enum Outcome {
    Authorized(MemberResolution),
    Refused,
    Unresolved,
}

impl ChannelAuthorizer {
    /// `cp_base` is the control-plane base URL (e.g. `http://control-plane:8090`);
    /// `admin_token` is the shared edge↔CP admin secret the CP verifies. The authorize round-trip is
    /// bounded by [`DEFAULT_AUTHORIZE_TIMEOUT`] so an unresponsive CP fails closed fast instead of
    /// hanging the admission gate (#207).
    pub fn new(cp_base: &str, admin_token: &[u8; 32]) -> Self {
        Self::with_timeout(cp_base, admin_token, DEFAULT_AUTHORIZE_TIMEOUT)
    }

    /// Like [`new`](Self::new) but with an explicit per-request `timeout` on the authorize round-trip.
    /// A CP that never responds makes `send()` error at `timeout`, which resolves fail-closed to `None`
    /// (a refusal) — never an unbounded hang.
    pub fn with_timeout(cp_base: &str, admin_token: &[u8; 32], timeout: Duration) -> Self {
        Self::with_timeout_and_cache_ttl(cp_base, admin_token, timeout, CACHE_TTL)
    }

    /// Like [`with_timeout`](Self::with_timeout) but with an explicit fail-static cache
    /// TTL (#231) — exposed mainly so tests can use a short TTL instead of waiting out
    /// the real [`CACHE_TTL`].
    pub fn with_timeout_and_cache_ttl(
        cp_base: &str,
        admin_token: &[u8; 32],
        timeout: Duration,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(timeout)
                // #231: no idle-connection reuse. This call is low-frequency (once per
                // channel join) and latency-insensitive relative to a fresh TCP
                // handshake on a same-cluster hop, so pooling buys little — and a
                // pooled connection surviving a CP restart in a half-dead state (sent,
                // but never gets a reply until OS-level TCP timeouts kick in, well
                // past DEFAULT_AUTHORIZE_TIMEOUT's per-request bound in the worst case)
                // is exactly the kind of "not really unresolved, but not really
                // resolved either" state this whole fix is trying to eliminate. A
                // fresh connection per call fails fast and predictably instead.
                .pool_max_idle_per_host(0)
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            url: format!(
                "{}/internal/channel/authorize",
                cp_base.trim_end_matches('/')
            ),
            admin_token_hex: hex(admin_token),
            cache: Arc::new(Mutex::new(HashMap::new())),
            cache_ttl,
        }
    }

    /// The operator public key iff `holder` is a current member of `channel`, else
    /// `None` (fail-closed on an authoritative non-member/bad-token refusal; see
    /// [`Self::resolve`] for the fail-*static* behavior on transport-class failures).
    /// This is the broker's grant-verification gate; [`Self::resolve`] additionally
    /// carries the member's Noise key.
    pub async fn authorize(&self, channel: &ChannelId, holder: &[u8; 32]) -> Option<[u8; 32]> {
        self.resolve(channel, holder).await.map(|m| m.operator_pubkey)
    }

    async fn query(&self, channel: &ChannelId, holder: &[u8; 32]) -> Outcome {
        let resp = match self
            .client
            .post(&self.url)
            .header("x-ct-admin-token", &self.admin_token_hex)
            .json(&AuthorizeReq {
                channel: hex(&channel.0),
                holder: hex(holder),
            })
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return Outcome::Unresolved, // timeout / connection error
        };
        // A clean, authoritative "no" from the CP — it definitely resolved the
        // request, and definitely said this holder isn't (or can't be proven to be) a
        // member. Anything else non-success is an infrastructure problem, not an
        // answer, and falls through to Unresolved below.
        if resp.status() == reqwest::StatusCode::NOT_FOUND || resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Outcome::Refused;
        }
        if !resp.status().is_success() {
            return Outcome::Unresolved;
        }
        let Ok(body) = resp.json::<AuthorizeResp>().await else {
            return Outcome::Unresolved; // 2xx with an unparseable body — CP-side bug, not a refusal
        };
        let Some(operator_pubkey) = hex_decode_32(&body.operator_pubkey) else {
            return Outcome::Unresolved;
        };
        Outcome::Authorized(MemberResolution {
            operator_pubkey,
            noise_pubkey: body.noise_pubkey.as_deref().and_then(hex_decode_32),
            noise_attestation: body.noise_attestation.as_deref().and_then(hex_decode_64),
        })
    }

    /// Resolve the full membership — operator key plus the member's attested Noise
    /// key (when the registry has one) — iff `holder` is a current member (#72 AF4 /
    /// #100).
    ///
    /// Fail-closed on an authoritative refusal (CP 404/401): returns `None` and evicts
    /// any cached entry for this `(channel, holder)`, so a revoked member can't keep
    /// riding a stale positive result. Fail-*static* on a transport-class failure
    /// (#231) — timeout, connection error, malformed body, or any other non-success
    /// status: falls back to the last successful resolution for this `(channel,
    /// holder)` if it's still within [`CACHE_TTL`], rather than refusing a
    /// currently-legitimate member just because one lookup couldn't complete. A holder
    /// with no prior successful resolution still fails closed on a transport failure —
    /// this never admits anyone the CP hasn't actually vouched for at some point.
    pub async fn resolve(&self, channel: &ChannelId, holder: &[u8; 32]) -> Option<MemberResolution> {
        let key: CacheKey = (*channel, *holder);
        match self.query(channel, holder).await {
            Outcome::Authorized(m) => {
                if let Ok(mut cache) = self.cache.lock() {
                    cache.insert(key, (m.clone(), Instant::now()));
                }
                Some(m)
            }
            Outcome::Refused => {
                if let Ok(mut cache) = self.cache.lock() {
                    cache.remove(&key);
                }
                None
            }
            Outcome::Unresolved => self
                .cache
                .lock()
                .ok()
                .and_then(|cache| cache.get(&key).cloned())
                .filter(|(_, at)| at.elapsed() < self.cache_ttl)
                .map(|(m, _)| m),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::Value;

    // A minimal stand-in for the CP's c-i endpoint: requires the admin token, returns
    // the operator key for the one known member, 404 otherwise.
    async fn mock_authorize(
        headers: axum::http::HeaderMap,
        Json(body): Json<Value>,
    ) -> Result<Json<Value>, axum::http::StatusCode> {
        if headers.get("x-ct-admin-token").and_then(|v| v.to_str().ok()) != Some(&hex(&[0x7au8; 32]))
        {
            return Err(axum::http::StatusCode::UNAUTHORIZED);
        }
        let holder = body.get("holder").and_then(|v| v.as_str()).unwrap_or("");
        if holder == hex(&[0x33u8; 32]) {
            Ok(Json(serde_json::json!({
                "operator_pubkey": hex(&[0xEEu8; 32]),
                "noise_pubkey": hex(&[0x55u8; 32]),
                "noise_attestation": hex(&[0x66u8; 64]),
            })))
        } else {
            Err(axum::http::StatusCode::NOT_FOUND)
        }
    }

    async fn spawn_mock_cp() -> String {
        let (_handle, base) = spawn_abortable_mock_cp().await;
        base
    }

    /// Like [`spawn_mock_cp`] but returns the server task's `JoinHandle` too, so a test
    /// can `.abort()` it mid-test to simulate the CP actually going away (connection
    /// refused on the next call) rather than just pointing at a URL nothing ever
    /// listened on.
    async fn spawn_abortable_mock_cp() -> (tokio::task::JoinHandle<()>, String) {
        let app = Router::new().route("/internal/channel/authorize", post(mock_authorize));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (handle, format!("http://{addr}"))
    }

    #[tokio::test]
    async fn resolver_returns_operator_key_only_for_a_member_with_the_admin_token() {
        let base = spawn_mock_cp().await;
        let channel = ChannelId([0xC5u8; 32]);

        // Correct token + member -> the operator key.
        let good = ChannelAuthorizer::new(&base, &[0x7au8; 32]);
        assert_eq!(
            good.authorize(&channel, &[0x33u8; 32]).await,
            Some([0xEEu8; 32]),
            "member resolves the operator key"
        );
        // Correct token, non-member -> None (fail-closed on 404).
        assert_eq!(good.authorize(&channel, &[0x44u8; 32]).await, None, "non-member denied");
        // Wrong admin token -> None (fail-closed on 401).
        let bad = ChannelAuthorizer::new(&base, &[0u8; 32]);
        assert_eq!(bad.authorize(&channel, &[0x33u8; 32]).await, None, "bad token denied");
        // Unreachable CP -> None (fail-closed on transport error).
        let down = ChannelAuthorizer::new("http://127.0.0.1:1", &[0x7au8; 32]);
        assert_eq!(down.authorize(&channel, &[0x33u8; 32]).await, None, "unreachable CP denied");
    }

    #[tokio::test]
    async fn resolve_carries_the_members_attested_noise_key() {
        // #72 AF4 / #100: resolve() returns the operator key AND the member's Noise
        // key, so the broker can relay the peer key without the operator pasting it.
        let base = spawn_mock_cp().await;
        let channel = ChannelId([0xC5u8; 32]);
        let good = ChannelAuthorizer::new(&base, &[0x7au8; 32]);

        let m = good.resolve(&channel, &[0x33u8; 32]).await.expect("member resolves");
        assert_eq!(m.operator_pubkey, [0xEEu8; 32], "operator key");
        assert_eq!(m.noise_pubkey, Some([0x55u8; 32]), "attested Noise key delivered");
        assert_eq!(m.noise_attestation, Some([0x66u8; 64]), "the holder attestation is delivered too (#101)");
        // A non-member still resolves to None (fail-closed).
        assert!(good.resolve(&channel, &[0x44u8; 32]).await.is_none(), "non-member denied");
    }

    #[tokio::test]
    async fn a_transport_failure_falls_back_to_the_last_successful_resolution_231() {
        // #231: the actual bug this fix addresses. A member resolves successfully once
        // (populating the cache), the CP then genuinely goes away (connection refused,
        // not just "never contacted"), and a re-resolve for the SAME (channel, holder)
        // must fail-*static* to the cached membership rather than refuse it.
        let (handle, base) = spawn_abortable_mock_cp().await;
        let channel = ChannelId([0xC5u8; 32]);
        let auth = ChannelAuthorizer::with_timeout_and_cache_ttl(
            &base,
            &[0x7au8; 32],
            Duration::from_secs(2),
            Duration::from_secs(30),
        );

        let first = auth.resolve(&channel, &[0x33u8; 32]).await.expect("first resolve succeeds");
        assert_eq!(first.operator_pubkey, [0xEEu8; 32]);

        handle.abort(); // the CP is now genuinely unreachable, not just never-contacted
        // Give the abort a moment to actually close the listening socket.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let second = auth
            .resolve(&channel, &[0x33u8; 32])
            .await
            .expect("a transport failure falls back to the cached membership, not None");
        assert_eq!(second.operator_pubkey, [0xEEu8; 32], "cached resolution is unchanged");

        // A DIFFERENT holder with no prior successful resolution still fails closed —
        // the cache never invents a membership the CP hasn't actually vouched for.
        assert!(
            auth.resolve(&channel, &[0x99u8; 32]).await.is_none(),
            "a holder never successfully resolved still fails closed on a transport error"
        );
    }

    #[tokio::test]
    async fn an_authoritative_refusal_evicts_the_cache_even_after_a_prior_success() {
        // #231: fail-static must never survive a CLEAN refusal. A member resolves once
        // (cached), is then revoked (the CP now genuinely says 404 for them), and the
        // very next resolve must return None and drop the cache entry — a later
        // transport failure must NOT resurrect the revoked membership from the cache.
        let member_still_valid = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let flag = member_still_valid.clone();
        async fn revocable_authorize(
            axum::extract::State(flag): axum::extract::State<Arc<std::sync::atomic::AtomicBool>>,
            headers: axum::http::HeaderMap,
            Json(body): Json<Value>,
        ) -> Result<Json<Value>, axum::http::StatusCode> {
            if headers.get("x-ct-admin-token").and_then(|v| v.to_str().ok()) != Some(&hex(&[0x7au8; 32])) {
                return Err(axum::http::StatusCode::UNAUTHORIZED);
            }
            let holder = body.get("holder").and_then(|v| v.as_str()).unwrap_or("");
            if holder == hex(&[0x33u8; 32]) && flag.load(std::sync::atomic::Ordering::SeqCst) {
                Ok(Json(serde_json::json!({"operator_pubkey": hex(&[0xEEu8; 32])})))
            } else {
                Err(axum::http::StatusCode::NOT_FOUND)
            }
        }
        let app = Router::new()
            .route("/internal/channel/authorize", post(revocable_authorize))
            .with_state(flag);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let channel = ChannelId([0xC5u8; 32]);
        let auth = ChannelAuthorizer::with_timeout_and_cache_ttl(
            &format!("http://{addr}"),
            &[0x7au8; 32],
            Duration::from_secs(2),
            Duration::from_secs(30),
        );

        assert!(auth.resolve(&channel, &[0x33u8; 32]).await.is_some(), "member resolves once (cached)");
        member_still_valid.store(false, std::sync::atomic::Ordering::SeqCst); // the CP now genuinely revokes them
        assert!(
            auth.resolve(&channel, &[0x33u8; 32]).await.is_none(),
            "a clean revocation (404) is never overridden by the cache"
        );

        // The critical property: the cache entry was actually EVICTED, not just
        // shadowed for this one call — kill the CP entirely (transport failure) and
        // re-resolve through the SAME `auth` (same cache). If eviction didn't really
        // happen, this would wrongly fall back to the pre-revocation cached Some(...).
        server.abort();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            auth.resolve(&channel, &[0x33u8; 32]).await.is_none(),
            "the evicted key must fail closed on transport error too, not resurrect the pre-revocation cache entry"
        );
    }

    #[tokio::test]
    async fn a_cached_resolution_expires_after_its_ttl() {
        // #231: the fail-static fallback is time-bounded, not permanent — bounds how
        // long a member revoked mid-outage could still ride a stale cache entry.
        let (handle, base) = spawn_abortable_mock_cp().await;
        let channel = ChannelId([0xC5u8; 32]);
        let auth = ChannelAuthorizer::with_timeout_and_cache_ttl(
            &base,
            &[0x7au8; 32],
            Duration::from_secs(2),
            Duration::from_millis(50), // short TTL so the test doesn't need to wait 30s
        );
        assert!(auth.resolve(&channel, &[0x33u8; 32]).await.is_some(), "seeds the cache");
        handle.abort();
        tokio::time::sleep(Duration::from_millis(150)).await; // outlive the 50ms TTL
        assert!(
            auth.resolve(&channel, &[0x33u8; 32]).await.is_none(),
            "an expired cache entry no longer fail-statics a transport failure"
        );
    }

    // A CP that accepts the connection but NEVER responds — the live #207 failure mode (unresponsive,
    // not rejecting): the request hangs until the client's own timeout fires.
    async fn hang_forever(_headers: axum::http::HeaderMap, Json(_body): Json<Value>) -> Json<Value> {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        Json(serde_json::json!({}))
    }

    async fn spawn_hanging_cp() -> String {
        let app = Router::new().route("/internal/channel/authorize", post(hang_forever));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn an_unresponsive_cp_fails_closed_within_the_timeout_not_hangs() {
        // #207 (frozen): a CP that accepts the TCP connection but never replies must resolve to `None`
        // (a fail-closed refusal) bounded by the authorize timeout — NOT hang the admission gate
        // indefinitely (which surfaced as the plane-wide "admission exchange stalled (#140)" flood).
        let base = spawn_hanging_cp().await;
        let channel = ChannelId([0xC5u8; 32]);
        let auth = ChannelAuthorizer::with_timeout(&base, &[0x7au8; 32], Duration::from_millis(200));

        // The whole call must complete well under the mock's 3600s sleep — a generous 5s test bound
        // proves it's the client timeout ending it, not a hang. Result is None (fail-closed).
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            auth.authorize(&channel, &[0x33u8; 32]),
        )
        .await
        .expect("authorize must return within the bound, not hang on an unresponsive CP");
        assert_eq!(result, None, "an unresponsive CP fails closed to a refusal, not a hang");
    }
}
