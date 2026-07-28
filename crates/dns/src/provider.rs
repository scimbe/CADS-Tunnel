//! DNS-01 provider abstraction (#31 AD5): publish/clear `_acme-challenge` TXT
//! records for an ACME client, over one of three interchangeable backends —
//!
//! - [`Dns01Provider::SelfHosted`]: the in-process `ct-dns` store (AD1–AD3), for a
//!   fully self-contained deployment;
//! - [`Dns01Provider::Desec`]: **deSEC** (<https://desec.io>), a free managed DNS
//!   with a REST API — the alternative when you'd rather not run your own `:53`.
//!   **Operator-side only** (holds the zone-wide token);
//! - [`Dns01Provider::RemoteAgent`] (ADR-0003 follow-up): the variant an
//!   **agent** actually uses — proves hostname ownership to the control
//!   plane's `/agent/dns01-challenge` endpoint with its own routing token, so
//!   the zone-wide DNS credential never leaves the operator's control plane.
//!
//! All three stay available; the operator selects a server-side one (see
//! `docs/dns01-desec.md` and the `.env`), agents always use `RemoteAgent`. The
//! deSEC token is read from the environment at startup and never logged.

use std::sync::Arc;

use crate::store::AcmeDnsStore;

/// A configured DNS-01 backend the ACME client drives via `set_txt`/`clear_txt`.
pub enum Dns01Provider {
    /// Self-hosted `ct-dns` store (in-process).
    SelfHosted(Arc<AcmeDnsStore>),
    /// deSEC managed DNS via its REST API — **operator-side only**: this
    /// variant holds the zone-wide `DESEC_TOKEN` and must never be
    /// constructed on an agent (see [`Dns01Provider::RemoteAgent`], the
    /// variant an agent actually uses).
    Desec(DesecClient),
    /// An **agent-side** client (ADR-0003 follow-up): proves hostname
    /// ownership to the control plane's `/agent/dns01-challenge` endpoint via
    /// its own routing token, so the zone-wide DNS credential never leaves
    /// the operator's control plane.
    RemoteAgent(RemoteAgentDns01Client),
}

impl Dns01Provider {
    /// Publish (replace) the TXT value for an `_acme-challenge` name.
    pub async fn set_txt(&self, name: &str, value: &str) -> Result<(), String> {
        match self {
            Dns01Provider::SelfHosted(store) => {
                store.set_txt(name, value);
                Ok(())
            }
            Dns01Provider::Desec(client) => client.set_txt(name, value).await,
            Dns01Provider::RemoteAgent(client) => client.publish(name, value).await,
        }
    }

    /// Remove the challenge TXT (cleanup hook).
    pub async fn clear_txt(&self, name: &str) -> Result<(), String> {
        match self {
            Dns01Provider::SelfHosted(store) => {
                store.clear(name);
                Ok(())
            }
            Dns01Provider::Desec(client) => client.clear_txt(name).await,
            Dns01Provider::RemoteAgent(client) => client.clear(name).await,
        }
    }
}

/// Agent-side DNS-01 client (ADR-0003 follow-up): calls the control plane's
/// `/agent/dns01-challenge` endpoint, proving ownership of the hostname with
/// the tunnel's own routing token (hex) rather than any DNS credential — the
/// control plane is the only thing that ever touches the real zone.
#[derive(Clone)]
pub struct RemoteAgentDns01Client {
    cp_url: String,
    routing_token: String,
    http: reqwest::Client,
}

impl RemoteAgentDns01Client {
    /// `cp_url` is the control-plane base URL; `routing_token` is this
    /// tunnel's own routing token, hex — the same one already bound to the
    /// hostname via host-authorization, so the control plane's ownership
    /// check (`edge_mesh::token_owns_hostname`) accepts it.
    pub fn new(cp_url: impl Into<String>, routing_token: impl Into<String>) -> Self {
        Self { cp_url: cp_url.into(), routing_token: routing_token.into(), http: reqwest::Client::new() }
    }

    /// Recover the bare hostname from a full `_acme-challenge.<hostname>`
    /// record name — the wire shape [`Dns01Provider::set_txt`]/`clear_txt`
    /// share with the other backends carries the full name, but the control
    /// plane's endpoint takes (and re-derives the record name from) the bare
    /// hostname, so it can never be tricked into writing an arbitrary name.
    fn hostname_of(name: &str) -> &str {
        name.strip_prefix("_acme-challenge.").unwrap_or(name)
    }

    async fn publish(&self, name: &str, value: &str) -> Result<(), String> {
        self.call("/agent/dns01-challenge", Self::hostname_of(name), Some(value)).await
    }

    async fn clear(&self, name: &str) -> Result<(), String> {
        self.call("/agent/dns01-challenge/clear", Self::hostname_of(name), None).await
    }

    async fn call(&self, path: &str, hostname: &str, value: Option<&str>) -> Result<(), String> {
        let url = format!("{}{path}", self.cp_url.trim_end_matches('/'));
        let mut body = serde_json::json!({ "token": self.routing_token, "hostname": hostname });
        if let Some(v) = value {
            body["value"] = serde_json::json!(v);
        }
        let resp = self.http.post(&url).json(&body).send().await.map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("control plane returned {} for {path}", resp.status()))
        }
    }
}

/// deSEC (<https://desec.io>) DNS-01 client. Configured from the environment (a
/// `.env` the operator supplies): `DESEC_TOKEN` (API token), `DESEC_DOMAIN` (the
/// zone managed at deSEC), optional `DESEC_API_BASE` (default
/// `https://desec.io/api/v1`). The token is held in memory and never logged.
#[derive(Clone)]
pub struct DesecClient {
    token: String,
    domain: String,
    base: String,
    http: reqwest::Client,
}

impl DesecClient {
    /// Build from process environment, or `None` if `DESEC_TOKEN`/`DESEC_DOMAIN`
    /// are not both set.
    pub fn from_env() -> Option<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Testable core of [`from_env`].
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let nonempty = |k: &str| get(k).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let token = nonempty("DESEC_TOKEN")?;
        let domain = nonempty("DESEC_DOMAIN")?;
        let base =
            nonempty("DESEC_API_BASE").unwrap_or_else(|| "https://desec.io/api/v1".to_string());
        Some(Self {
            token,
            domain,
            base,
            http: reqwest::Client::new(),
        })
    }

    /// The zone this client manages (`DESEC_DOMAIN`) — e.g. so a caller can build
    /// a fully-qualified hostname under it without re-reading the environment.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Upsert the TXT record via a bulk PATCH (leaves other records untouched);
    /// deSEC requires TXT values wrapped in double quotes.
    pub async fn set_txt(&self, name: &str, value: &str) -> Result<(), String> {
        self.patch_rrset(name, "TXT", vec![format!("\"{value}\"")]).await
    }

    /// Clear the challenge TXT — an empty `records` list removes the RRset.
    pub async fn clear_txt(&self, name: &str) -> Result<(), String> {
        self.patch_rrset(name, "TXT", Vec::new()).await
    }

    /// Publish an `A` record for a public agent hostname (#38 DL1): `host` must be
    /// under the configured zone. Used to make a tunnel's hostname resolvable to
    /// the edge automatically on bind.
    pub async fn set_a(&self, host: &str, ip: &str) -> Result<(), String> {
        self.guard_under_zone(host)?;
        self.patch_rrset(host, "A", vec![ip.to_string()]).await
    }

    /// Delete the `A` record for `host` (#38 DL1) — an empty `records` list
    /// removes the RRset, so a revoked tunnel leaves no orphaned DNS.
    pub async fn clear_a(&self, host: &str) -> Result<(), String> {
        self.guard_under_zone(host)?;
        self.patch_rrset(host, "A", Vec::new()).await
    }

    /// Refuse to touch a name that is not the zone or a subdomain of it — an
    /// agent may only claim a hostname under the operator's configured zone.
    fn guard_under_zone(&self, host: &str) -> Result<(), String> {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        let d = self.domain.trim_end_matches('.').to_ascii_lowercase();
        if h == d || h.ends_with(&format!(".{d}")) {
            Ok(())
        } else {
            Err(format!("{host} is not under the configured zone {}", self.domain))
        }
    }

    async fn patch_rrset(&self, name: &str, rtype: &str, records: Vec<String>) -> Result<(), String> {
        // Bulk PATCH is an upsert of the listed RRsets only (min TTL 3600).
        let body = serde_json::json!([{
            "subname": subname_of(name, &self.domain),
            "type": rtype,
            "ttl": 3600,
            "records": records,
        }]);
        let url = format!(
            "{}/domains/{}/rrsets/",
            self.base.trim_end_matches('/'),
            self.domain
        );
        let resp = self
            .http
            .patch(&url)
            .header("Authorization", format!("Token {}", self.token))
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("deSEC returned {} for {name}", resp.status()))
        }
    }
}

/// Derive the deSEC `subname` for a full record name under `domain`
/// (`_acme-challenge.app.example.org` under `example.org` -> `_acme-challenge.app`;
/// a name equal to the domain -> ""). ACME challenge names are always a subname,
/// never the bare apex.
pub fn subname_of(name: &str, domain: &str) -> String {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    if name == domain {
        return String::new();
    }
    name.strip_suffix(&format!(".{domain}"))
        .map(str::to_string)
        .unwrap_or(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::patch;
    use axum::Router;
    use std::sync::Mutex;

    #[test]
    fn subname_is_derived_relative_to_the_zone() {
        assert_eq!(
            subname_of("_acme-challenge.bunsenbrenner.org", "bunsenbrenner.org"),
            "_acme-challenge"
        );
        assert_eq!(
            subname_of("_acme-challenge.app1.Bunsenbrenner.ORG", "bunsenbrenner.org"),
            "_acme-challenge.app1"
        );
        assert_eq!(subname_of("bunsenbrenner.org", "bunsenbrenner.org"), "");
    }

    #[test]
    fn desec_from_lookup_needs_token_and_domain() {
        let ok = DesecClient::from_lookup(|k| match k {
            "DESEC_TOKEN" => Some("t".into()),
            "DESEC_DOMAIN" => Some("z.org".into()),
            _ => None,
        });
        assert!(ok.is_some());
        assert_eq!(ok.unwrap().base, "https://desec.io/api/v1", "default base");
        assert!(DesecClient::from_lookup(|k| (k == "DESEC_TOKEN").then(|| "t".into())).is_none());
    }

    #[tokio::test]
    async fn desec_set_and_clear_hit_the_bulk_rrset_endpoint_with_auth() {
        // Mock deSEC: capture (path, auth header, body) of the PATCH.
        type Captured = Arc<Mutex<Option<(String, String, String)>>>;
        let captured: Captured = Arc::new(Mutex::new(None));
        let app = Router::new()
            .route(
                "/domains/:domain/rrsets/",
                patch(
                    |State(cap): State<Captured>, headers: HeaderMap, uri: axum::http::Uri, body: String| async move {
                        let auth = headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        *cap.lock().unwrap() = Some((uri.path().to_string(), auth, body));
                        StatusCode::OK
                    },
                ),
            )
            .with_state(captured.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = DesecClient::from_lookup(|k| match k {
            "DESEC_TOKEN" => Some("secret-token".into()),
            "DESEC_DOMAIN" => Some("bunsenbrenner.org".into()),
            "DESEC_API_BASE" => Some(format!("http://{addr}")),
            _ => None,
        })
        .unwrap();

        // set_txt publishes the quoted value at the right RRset endpoint with auth.
        client.set_txt("_acme-challenge.bunsenbrenner.org", "tok-123").await.unwrap();
        let (path, auth, body) = captured.lock().unwrap().clone().expect("deSEC called");
        assert_eq!(path, "/domains/bunsenbrenner.org/rrsets/");
        assert_eq!(auth, "Token secret-token", "bearer via Token scheme");
        assert!(body.contains("_acme-challenge"), "carries the subname");
        assert!(body.contains("tok-123"), "carries the (quoted) TXT value");
        assert!(body.contains("TXT"));

        // clear_txt sends an empty records list (deletes the RRset).
        client.clear_txt("_acme-challenge.bunsenbrenner.org").await.unwrap();
        let (_p, _a, body) = captured.lock().unwrap().clone().unwrap();
        assert!(body.contains("\"records\":[]"), "empty records clears it");
    }

    #[tokio::test]
    async fn desec_set_and_clear_a_records_and_guard_the_zone() {
        // #38 DL1: A-record CRUD for a host under the zone; refuse hosts outside it.
        type Captured = Arc<Mutex<Option<(String, String, String)>>>;
        let captured: Captured = Arc::new(Mutex::new(None));
        let app = Router::new()
            .route(
                "/domains/:domain/rrsets/",
                patch(
                    |State(cap): State<Captured>, uri: axum::http::Uri, body: String| async move {
                        *cap.lock().unwrap() = Some((uri.path().to_string(), String::new(), body));
                        StatusCode::OK
                    },
                ),
            )
            .with_state(captured.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = DesecClient::from_lookup(|k| match k {
            "DESEC_TOKEN" => Some("t".into()),
            "DESEC_DOMAIN" => Some("bunsenbrenner.org".into()),
            "DESEC_API_BASE" => Some(format!("http://{addr}")),
            _ => None,
        })
        .unwrap();

        // set_a publishes the A record for the subname with the IP.
        client.set_a("help.bunsenbrenner.org", "45.133.9.145").await.unwrap();
        let (path, _a, body) = captured.lock().unwrap().clone().unwrap();
        assert_eq!(path, "/domains/bunsenbrenner.org/rrsets/");
        assert!(body.contains("\"subname\":\"help\"") && body.contains("\"type\":\"A\""));
        assert!(body.contains("45.133.9.145"));

        // clear_a sends an empty records list.
        client.clear_a("help.bunsenbrenner.org").await.unwrap();
        assert!(captured.lock().unwrap().clone().unwrap().2.contains("\"records\":[]"));

        // A host outside the configured zone is refused before any request.
        assert!(client.set_a("evil.example", "1.2.3.4").await.is_err());
    }

    #[tokio::test]
    async fn remote_agent_client_posts_the_token_hostname_and_value_never_a_dns_credential() {
        // ADR-0003 follow-up: the agent-side variant carries only its routing
        // token + hostname (+ value on publish) -- never DESEC_TOKEN or any
        // other zone-wide credential, and it recovers the bare hostname from
        // the full "_acme-challenge.<host>" record name the Dns01Provider
        // interface hands it.
        type Captured = Arc<Mutex<Option<(String, String)>>>;
        let captured: Captured = Arc::new(Mutex::new(None));
        let app = Router::new()
            .route(
                "/agent/dns01-challenge",
                axum::routing::post(
                    |State(cap): State<Captured>, body: String| async move {
                        *cap.lock().unwrap() = Some(("publish".to_string(), body));
                        StatusCode::OK
                    },
                ),
            )
            .route(
                "/agent/dns01-challenge/clear",
                axum::routing::post(
                    |State(cap): State<Captured>, body: String| async move {
                        *cap.lock().unwrap() = Some(("clear".to_string(), body));
                        StatusCode::OK
                    },
                ),
            )
            .with_state(captured.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = RemoteAgentDns01Client::new(format!("http://{addr}"), "deadbeef");
        let provider = Dns01Provider::RemoteAgent(client);

        provider.set_txt("_acme-challenge.app.example.com", "tok-123").await.unwrap();
        let (route, body) = captured.lock().unwrap().clone().unwrap();
        assert_eq!(route, "publish");
        assert!(body.contains("\"token\":\"deadbeef\""));
        assert!(body.contains("\"hostname\":\"app.example.com\""), "bare hostname, not the full record name");
        assert!(body.contains("\"value\":\"tok-123\""));
        assert!(!body.contains("DESEC"), "no DNS credential is ever carried");

        provider.clear_txt("_acme-challenge.app.example.com").await.unwrap();
        let (route, body) = captured.lock().unwrap().clone().unwrap();
        assert_eq!(route, "clear");
        assert!(body.contains("\"hostname\":\"app.example.com\""));
        assert!(!body.contains("\"value\""), "clear carries no value field");
    }
}
