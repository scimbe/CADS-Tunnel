//! Agent Fabric — edge-side channel-authorize resolver (#81 SEC81c-c c-ii).
//!
//! The live broker's admission gate needs `authorize(channel, holder) ->
//! Option<operator_pubkey>` — the operator key iff the holder is a current member — but
//! the channel registry lives in the control plane. This queries the CP's
//! `POST /internal/channel/authorize` (c-i), presenting the shared edge↔CP admin token,
//! and maps the response to `Option<[u8; 32]>`. It is **fail-closed**: any non-member
//! (404), bad token (401), or transport/parse error resolves to `None`, so an
//! unresolvable authorization denies admission at the gate rather than opening it.

use ct_common::channel::ChannelId;
use serde::{Deserialize, Serialize};
use std::time::Duration;

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
pub struct MemberResolution {
    pub operator_pubkey: [u8; 32],
    pub noise_pubkey: Option<[u8; 32]>,
    pub noise_attestation: Option<[u8; 64]>,
}

/// Resolves channel-join authorization by querying the control plane's c-i endpoint.
#[derive(Clone)]
pub struct ChannelAuthorizer {
    client: reqwest::Client,
    url: String,
    admin_token_hex: String,
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
        Self {
            client: reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            url: format!(
                "{}/internal/channel/authorize",
                cp_base.trim_end_matches('/')
            ),
            admin_token_hex: hex(admin_token),
        }
    }

    /// The operator public key iff `holder` is a current member of `channel`, else
    /// `None` (fail-closed on non-member / bad token / transport error). This is the
    /// broker's grant-verification gate; [`Self::resolve`] additionally carries the
    /// member's Noise key.
    pub async fn authorize(&self, channel: &ChannelId, holder: &[u8; 32]) -> Option<[u8; 32]> {
        self.resolve(channel, holder).await.map(|m| m.operator_pubkey)
    }

    /// Resolve the full membership — operator key plus the member's attested Noise
    /// key (when the registry has one) — iff `holder` is a current member (#72 AF4 /
    /// #100). Same fail-closed contract as [`Self::authorize`].
    pub async fn resolve(&self, channel: &ChannelId, holder: &[u8; 32]) -> Option<MemberResolution> {
        let resp = self
            .client
            .post(&self.url)
            .header("x-ct-admin-token", &self.admin_token_hex)
            .json(&AuthorizeReq {
                channel: hex(&channel.0),
                holder: hex(holder),
            })
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body: AuthorizeResp = resp.json().await.ok()?;
        Some(MemberResolution {
            operator_pubkey: hex_decode_32(&body.operator_pubkey)?,
            noise_pubkey: body.noise_pubkey.as_deref().and_then(hex_decode_32),
            noise_attestation: body.noise_attestation.as_deref().and_then(hex_decode_64),
        })
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
        let app = Router::new().route("/internal/channel/authorize", post(mock_authorize));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
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
