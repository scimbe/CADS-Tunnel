//! ACME orchestration (ADR-0003): ties [`crate::acme_jws`]/[`crate::acme_client`]
//! together into what `ct-agent certificate` actually runs — obtain a cert if
//! none exists yet, renew it once it's getting old, and write the result where
//! the origin's own webserver (Caddy, already used by every real deployment —
//! see `docs/ops/runbook.md`) already expects a static `fullchain.pem`/
//! `privkey.pem` pair. Deliberately does **not** add TLS termination to
//! `ct-agent` itself: today's Browser-Plane mode is pure SNI passthrough,
//! and the origin already knows how to load cert files from disk — this
//! automates *writing* those files, it doesn't change who reads them.
//!
//! Renewal uses file age, not certificate parsing: Let's Encrypt issues
//! 90-day certificates, and renewing once the file is more than
//! [`RENEW_AFTER_DAYS`] old (the same ~30-day-before-expiry convention every
//! mainstream ACME client defaults to) needs no X.509 parsing at all — one
//! less place for a subtle bug to hide in security-sensitive code.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use ct_dns::provider::{Dns01Provider, RemoteAgentDns01Client};
use serde::Deserialize;

use crate::acme_client::AcmeClient;
use crate::acme_jws::AccountKey;
use crate::dns01_authoritative::AuthoritativeChecker;
use crate::dns01_propagation::{self, PropagationWaiter};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Renew once the existing cert file is older than this many days (90-day
/// Let's Encrypt certs, renewing with ~30 days of margin left).
const RENEW_AFTER_DAYS: u64 = 60;

/// How often [`run_renewal_loop`] re-checks whether renewal is due. Cheap (a
/// file-mtime check), so this can be frequent without hammering anything —
/// the ACME server itself is only ever contacted when renewal is actually due.
const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// How often to poll the admission broker (#233) while a hostname hasn't
/// reached `gruen` yet — the 48h claim window needs a much tighter loop than
/// a settled renewal cadence does. Once `gruen`, [`CHECK_INTERVAL`] takes
/// back over.
const ADMISSION_POLL_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// The CA a control-plane admission broker has assigned a hostname to, as
/// returned by `GET /agent/acme-admission/:token/:hostname`. Mirrors
/// `ct-control-plane`'s `acme_broker::AssignedCaResponse` (duplicated rather
/// than shared across the crate boundary, same precedent as
/// `dns01_challenge.rs`'s `dns01_record_name`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
struct AdmissionCa {
    #[allow(dead_code)]
    name: String,
    directory_url: String,
    requires_eab: bool,
    eab_kid: Option<String>,
    eab_hmac_key_b64url: Option<String>,
}

/// Response shape of `GET /agent/acme-admission/:token/:hostname`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
struct Admission {
    status: String,
    may_issue_now: bool,
    assigned_ca: Option<AdmissionCa>,
}

/// Poll the control-plane's admission broker (#233) for `hostname`. Returns
/// `None` on ANY failure — network error, non-2xx, unparseable body — which
/// is exactly what an older control-plane without this endpoint yet (a 404)
/// or one with the broker feature disabled looks like from here. This is a
/// deliberate backward-compatibility choice: [`obtain_or_renew`] treats `None`
/// as "no admission gate configured, proceed exactly as before this feature
/// existed" rather than blocking issuance on a control-plane that doesn't
/// speak this protocol yet.
async fn poll_admission(http: &reqwest::Client, cp_url: &str, token: &str, hostname: &str) -> Option<Admission> {
    let url = format!("{}/agent/acme-admission/{token}/{hostname}", cp_url.trim_end_matches('/'));
    let resp = http.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<Admission>().await.ok()
}

/// Tell the admission broker an issuance just completed, so it can flip this
/// hostname to `gruen` and record the CA it used against the rate-limit
/// ledger. Best-effort: if this fails, the cert is already safely on disk
/// (the whole point is never blocking on this), and the broker's own
/// `record_issuance_complete` is naturally idempotent — a later successful
/// call (e.g. after a renewal) still records correctly.
async fn notify_issuance_complete(http: &reqwest::Client, cp_url: &str, token: &str, hostname: &str) {
    let url = format!("{}/agent/acme-issuance-complete/{token}/{hostname}", cp_url.trim_end_matches('/'));
    if let Err(e) = http.post(&url).send().await {
        eprintln!("ct-agent: acme-issuance-complete callback failed (non-fatal, cert is already written): {e}");
    }
}

/// Everything one issuance/renewal run needs.
#[derive(Debug)]
pub struct AcmeCertConfig {
    /// Control-plane base URL (proves hostname ownership via `routing_token`).
    pub cp_url: String,
    /// This tunnel's own routing token, hex — never a DNS credential.
    pub routing_token: String,
    /// The hostname to request a certificate for.
    pub hostname: String,
    /// Where to write `fullchain.pem`/`privkey.pem` (created if missing).
    pub cert_out_dir: PathBuf,
    /// Where to persist the ACME account key (PKCS#8 DER) so renewals reuse
    /// the same account instead of registering a new one every run.
    pub account_key_path: PathBuf,
    /// DNS-over-HTTPS resolvers used to confirm the `_acme-challenge` TXT
    /// record is publicly visible before validation is triggered (see
    /// `crate::dns01_propagation`) -- more than one independent resolver
    /// operator, so a single resolver's stale negative cache (from an
    /// earlier attempt at the same hostname) can't block a retry. Reachable
    /// over 443 even when outbound UDP/53 is blocked.
    pub dns01_resolver_urls: Vec<String>,
    /// How long to wait for that TXT record to become publicly resolvable
    /// before giving up (deSEC and similar managed DNS backends replicate to
    /// public nameservers with a short but nonzero delay).
    pub dns01_propagation_timeout: Duration,
    /// How long to wait after publishing before the FIRST public-resolver
    /// lookup. Too low re-poisons the resolver cache with an NXDOMAIN that
    /// outlives the whole timeout (the #229 root cause); too high only costs
    /// issuance time. `None` uses the measured-safe default.
    pub dns01_initial_delay: Option<Duration>,
    /// Verify the challenge record against the zone's own authoritative
    /// nameservers (what Let's Encrypt actually queries, #229) rather than
    /// only public resolvers. Default `true`; set `false` only where direct
    /// DNS to those servers is impossible, or in hermetic tests whose mock
    /// hostname has no real zone.
    pub dns01_use_authoritative: bool,
    /// How many complete ACME orders to attempt when DNS-01 keeps losing the
    /// propagation race (#229). `None` uses the built-in default; keep it low
    /// -- every attempt is a real order against the CA's failed-validation
    /// rate limit.
    pub dns01_attempts: Option<u32>,
}

impl AcmeCertConfig {
    /// Read from the environment: `CT_AGENT_CP_URL`, `CT_AGENT_TOKEN`,
    /// `CT_AGENT_HOSTNAME` (all required), `CT_ACME_CERT_OUT_DIR` (default
    /// `/shared/acme-cert`), `CT_ACME_ACCOUNT_KEY_PATH` (default
    /// `<cert_out_dir>/acme-account-key.der`), `CT_ACME_DNS01_RESOLVER_URLS`
    /// (comma-separated, defaults to two independent public DoH resolvers),
    /// `CT_ACME_DNS01_PROPAGATION_TIMEOUT_SECS` (default 180),
    /// `CT_ACME_DNS01_ATTEMPTS` (default 3 -- whole-order retries on the
    /// propagation race; every attempt costs a real CA order),
    /// `CT_ACME_DNS01_INITIAL_DELAY_SECS` (default 75 -- see
    /// `dns01_propagation::DEFAULT_INITIAL_DELAY`; lowering it risks
    /// re-poisoning the resolver cache). The ACME directory URL and any EAB
    /// credentials are no longer configured here at all (#233): the
    /// admission broker at `cp_url` is the sole source of both, for every
    /// issuance and every renewal alike -- there is no locally-configured
    /// fallback.
    pub fn from_env() -> Result<Self, String> {
        Self::from_env_with(|k| std::env::var(k).ok())
    }

    pub(crate) fn from_env_with(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let cp_url = get("CT_AGENT_CP_URL").filter(|s| !s.is_empty()).ok_or("CT_AGENT_CP_URL is required")?;
        let routing_token =
            get("CT_AGENT_TOKEN").filter(|s| !s.is_empty()).ok_or("CT_AGENT_TOKEN is required")?;
        let hostname =
            get("CT_AGENT_HOSTNAME").filter(|s| !s.is_empty()).ok_or("CT_AGENT_HOSTNAME is required")?;
        let cert_out_dir = PathBuf::from(
            get("CT_ACME_CERT_OUT_DIR").filter(|s| !s.is_empty()).unwrap_or_else(|| "/shared/acme-cert".to_string()),
        );
        let account_key_path = get("CT_ACME_ACCOUNT_KEY_PATH")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| cert_out_dir.join("acme-account-key.der"));
        let dns01_resolver_urls = get("CT_ACME_DNS01_RESOLVER_URLS")
            .filter(|s| !s.is_empty())
            .map(|s| s.split(',').map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).collect())
            .unwrap_or_else(|| dns01_propagation::DEFAULT_RESOLVER_URLS.iter().map(|s| s.to_string()).collect());
        let dns01_initial_delay = get("CT_ACME_DNS01_INITIAL_DELAY_SECS")
            .filter(|s| !s.is_empty())
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs);
        let dns01_propagation_timeout = get("CT_ACME_DNS01_PROPAGATION_TIMEOUT_SECS")
            .filter(|s| !s.is_empty())
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(dns01_propagation::DEFAULT_TIMEOUT);
        Ok(Self {
            cp_url,
            routing_token,
            hostname,
            cert_out_dir,
            account_key_path,
            dns01_resolver_urls,
            dns01_propagation_timeout,
            dns01_initial_delay,
            dns01_attempts: get("CT_ACME_DNS01_ATTEMPTS")
                .filter(|v| !v.is_empty())
                .and_then(|v| v.parse::<u32>().ok()),
            dns01_use_authoritative: get("CT_ACME_DNS01_AUTHORITATIVE")
                .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no"))
                .unwrap_or(true),
        })
    }

    fn cert_path(&self) -> PathBuf {
        self.cert_out_dir.join("fullchain.pem")
    }
    fn key_path(&self) -> PathBuf {
        self.cert_out_dir.join("privkey.pem")
    }
}

/// Whether the cert at `path` is missing or old enough to renew.
fn needs_renewal(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return true; // no cert yet
    };
    let Ok(modified) = meta.modified() else {
        return true; // can't tell how old it is -- renew to be safe
    };
    let age = SystemTime::now().duration_since(modified).unwrap_or(Duration::MAX);
    age >= Duration::from_secs(RENEW_AFTER_DAYS * 24 * 60 * 60)
}

fn load_or_generate_account_key(path: &Path) -> Result<AccountKey, BoxError> {
    if let Ok(der) = std::fs::read(path) {
        if let Ok(key) = AccountKey::from_pkcs8(&der) {
            return Ok(key);
        }
        eprintln!("ct-agent: acme account key at {} unreadable, generating a fresh one", path.display());
    }
    let key = AccountKey::generate()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, key.pkcs8_der())?;
    Ok(key)
}

/// Obtain a certificate if none exists yet, or renew it if the existing one
/// is old enough ([`RENEW_AFTER_DAYS`]). No-op (returns `Ok(false)`) when a
/// recent enough cert is already on disk **or** when the admission broker
/// (#233) says this hostname isn't eligible to issue yet (still `rot`, or
/// `gelb` waiting for its turn in the queue) — the caller should simply try
/// again later, exactly like today's "cert is still fresh" no-op.
///
/// The admission broker is a **hard requirement**, not an optional
/// enhancement with a fallback: no legacy/mixed-version compatibility path is
/// maintained here. If it doesn't answer, that is a real failure to surface,
/// not something to silently work around by falling back to a locally
/// configured directory/EAB — the broker is what decides which CA a
/// hostname's own certificate ever comes from, and that decision must never
/// be second-guessed client-side.
pub async fn obtain_or_renew(config: &AcmeCertConfig) -> Result<bool, BoxError> {
    if !needs_renewal(&config.cert_path()) {
        return Ok(false);
    }
    let http = reqwest::Client::builder().timeout(Duration::from_secs(10)).build()?;
    let admission = poll_admission(&http, &config.cp_url, &config.routing_token, &config.hostname)
        .await
        .ok_or("admission broker did not respond -- cannot determine whether this hostname may issue yet")?;
    if !admission.may_issue_now {
        eprintln!(
            "ct-agent: {} not yet eligible to issue (status={}); waiting on the admission broker",
            config.hostname, admission.status
        );
        return Ok(false);
    }
    let ca = admission
        .assigned_ca
        .as_ref()
        .ok_or("admission broker says this hostname may issue now, but assigned it no CA")?;
    let directory_url = ca.directory_url.clone();
    let eab = if ca.requires_eab { ca.eab_kid.clone().zip(ca.eab_hmac_key_b64url.clone()) } else { None };

    std::fs::create_dir_all(&config.cert_out_dir)?;
    let account = load_or_generate_account_key(&config.account_key_path)?;
    let mut client = AcmeClient::discover(&directory_url, account).await?;
    if let Some((kid, hmac_key)) = eab {
        client = client.with_eab(kid, hmac_key);
    }
    let publish = Dns01Provider::RemoteAgent(RemoteAgentDns01Client::new(
        config.cp_url.clone(),
        config.routing_token.clone(),
    ));
    let mut propagation =
        PropagationWaiter::new(config.dns01_resolver_urls.clone(), config.dns01_propagation_timeout);
    if let Some(delay) = config.dns01_initial_delay {
        propagation = propagation.with_initial_delay(delay);
    }
    // The authoritative check is the one that matches how Let's Encrypt
    // actually validates (#229). If this host genuinely cannot query the
    // authoritative servers (outbound 53 blocked), fall back to the weaker
    // public-resolver check rather than refusing to issue at all.
    let authoritative = if config.dns01_use_authoritative {
        match AuthoritativeChecker::from_system() {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("ct-agent: authoritative DNS check unavailable ({e}); falling back to public resolvers");
                None
            }
        }
    } else {
        None
    };
    let issued = match config.dns01_attempts {
        Some(n) => {
            client
                .issue_certificate_with_attempts(&config.hostname, &publish, Some(&propagation), authoritative.as_ref(), n)
                .await?
        }
        None => {
            client.issue_certificate(&config.hostname, &publish, Some(&propagation), authoritative.as_ref()).await?
        }
    };

    // Write key before cert (an origin polling for the cert file should never
    // see a cert with no matching key on disk yet).
    write_private(&config.key_path(), issued.key_pem.as_bytes())?;
    std::fs::write(config.cert_path(), issued.cert_chain_pem.as_bytes())?;
    eprintln!(
        "ct-agent: obtained a certificate for {} ({} -> {})",
        config.hostname,
        directory_url,
        config.cert_out_dir.display()
    );
    // Tell the admission broker (#233) so it can flip this hostname to
    // `gruen` and log the completed issuance against the CA it assigned.
    notify_issuance_complete(&http, &config.cp_url, &config.routing_token, &config.hostname).await;
    Ok(true)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    std::fs::write(path, bytes)
}
#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

/// Run [`obtain_or_renew`] once immediately, then keep checking forever — the
/// entry point `ct-agent certificate` runs. A failed attempt is logged, not
/// fatal: the next tick tries again, the same resilience posture as every
/// other long-running `ct-agent` subcommand.
///
/// Sleep interval is dynamic (#233): [`CHECK_INTERVAL`] (6h) once a cert is
/// issued or no admission broker is configured, but [`ADMISSION_POLL_INTERVAL`]
/// (15min) whenever this hostname is known to still be waiting (`rot`/`gelb`)
/// — a 48h claim window needs a much tighter loop than a settled renewal
/// cadence to actually be responsive.
pub async fn run_renewal_loop(config: AcmeCertConfig) -> ! {
    loop {
        let sleep_for = match obtain_or_renew(&config).await {
            Ok(true) => CHECK_INTERVAL,
            Ok(false) => {
                eprintln!("ct-agent: existing certificate for {} is still fresh, or not yet admitted", config.hostname);
                admission_poll_interval(&config).await
            }
            Err(e) => {
                eprintln!("ct-agent: certificate obtain/renew failed: {e}");
                CHECK_INTERVAL
            }
        };
        tokio::time::sleep(sleep_for).await;
    }
}

/// Which interval [`run_renewal_loop`] should sleep for next: a fresh,
/// independent admission poll purely to read `status` (separate from
/// [`obtain_or_renew`]'s own poll, which is already done by the time this
/// runs) — cheap (one HTTP GET, at most every 15 minutes), and keeps this
/// concern decoupled from `obtain_or_renew`'s `Result<bool, _>` return shape
/// rather than growing that into a richer type every existing test asserts
/// against as a plain bool.
async fn admission_poll_interval(config: &AcmeCertConfig) -> Duration {
    let Ok(http) = reqwest::Client::builder().timeout(Duration::from_secs(10)).build() else {
        return CHECK_INTERVAL;
    };
    match poll_admission(&http, &config.cp_url, &config.routing_token, &config.hostname).await {
        Some(a) if a.status != "gruen" => ADMISSION_POLL_INTERVAL,
        _ => CHECK_INTERVAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Json as AxJson, State as AxState};
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::{get, head, post};
    use axum::Router;
    use serde_json::Value;
    use std::sync::{Arc, Mutex};

    fn env_lookup(present: Vec<(&str, &str)>) -> impl Fn(&str) -> Option<String> {
        let map: std::collections::HashMap<String, String> =
            present.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| map.get(k).cloned()
    }

    #[test]
    fn from_env_requires_the_three_agent_specific_vars_and_defaults_the_rest() {
        for missing in ["CT_AGENT_CP_URL", "CT_AGENT_TOKEN", "CT_AGENT_HOSTNAME"] {
            let mut vars = vec![
                ("CT_AGENT_CP_URL", "https://cp.example"),
                ("CT_AGENT_TOKEN", "deadbeef"),
                ("CT_AGENT_HOSTNAME", "app.example.com"),
            ];
            vars.retain(|(k, _)| *k != missing);
            let err = AcmeCertConfig::from_env_with(env_lookup(vars)).unwrap_err();
            assert!(err.contains(missing), "{err}");
        }

        let cfg = AcmeCertConfig::from_env_with(env_lookup(vec![
            ("CT_AGENT_CP_URL", "https://cp.example"),
            ("CT_AGENT_TOKEN", "deadbeef"),
            ("CT_AGENT_HOSTNAME", "app.example.com"),
        ]))
        .unwrap();
        assert_eq!(cfg.cert_out_dir, PathBuf::from("/shared/acme-cert"));
        assert_eq!(cfg.account_key_path, PathBuf::from("/shared/acme-cert/acme-account-key.der"));
        assert_eq!(
            cfg.dns01_resolver_urls,
            dns01_propagation::DEFAULT_RESOLVER_URLS.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );
        assert_eq!(cfg.dns01_propagation_timeout, dns01_propagation::DEFAULT_TIMEOUT);
    }

    #[test]
    fn from_env_honors_explicit_overrides() {
        let env = |k: &str| match k {
            "CT_AGENT_CP_URL" => Some("https://cp.example".to_string()),
            "CT_AGENT_TOKEN" => Some("deadbeef".to_string()),
            "CT_AGENT_HOSTNAME" => Some("app.example.com".to_string()),
            "CT_ACME_CERT_OUT_DIR" => Some("/tmp/my-certs".to_string()),
            "CT_ACME_ACCOUNT_KEY_PATH" => Some("/tmp/my-account.der".to_string()),
            "CT_ACME_DNS01_RESOLVER_URLS" => Some("https://dns.google/resolve, https://dns.quad9.net/dns-query".to_string()),
            "CT_ACME_DNS01_PROPAGATION_TIMEOUT_SECS" => Some("30".to_string()),
            _ => None,
        };
        let cfg = AcmeCertConfig::from_env_with(env).unwrap();
        assert_eq!(cfg.cert_out_dir, PathBuf::from("/tmp/my-certs"));
        assert_eq!(cfg.account_key_path, PathBuf::from("/tmp/my-account.der"));
        assert_eq!(
            cfg.dns01_resolver_urls,
            vec!["https://dns.google/resolve".to_string(), "https://dns.quad9.net/dns-query".to_string()]
        );
        assert_eq!(cfg.dns01_propagation_timeout, Duration::from_secs(30));
    }

    #[test]
    fn needs_renewal_is_true_for_a_missing_file_and_false_for_a_fresh_one() {
        let dir = std::env::temp_dir().join(format!("ct-acme-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fullchain.pem");

        assert!(needs_renewal(&path), "no file yet -> needs issuance");

        std::fs::write(&path, "cert").unwrap();
        assert!(!needs_renewal(&path), "freshly written -> not due for renewal");

        // Backdate the file past the renewal window.
        let old = SystemTime::now() - Duration::from_secs((RENEW_AFTER_DAYS + 1) * 24 * 60 * 60);
        let f = std::fs::File::open(&path).unwrap();
        f.set_modified(old).unwrap();
        assert!(needs_renewal(&path), "older than the renewal window -> due");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- End-to-end: obtain_or_renew against a mock ACME + mock control plane ---

    /// The admission broker's answer a mock control plane hands back. Default
    /// (see `spawn_mock_with_doh_delay` below) is "go ahead now, using this
    /// same mock's own ACME directory" -- exactly what every pre-#233 test in
    /// this module needs, since the admission broker is now a hard
    /// requirement for `obtain_or_renew` with no fallback. Tests that need to
    /// exercise the broker's OTHER behaviors (not yet eligible, a different
    /// assigned CA) overwrite this mutex before calling `obtain_or_renew`.
    #[derive(Clone)]
    struct MockAdmission {
        status: &'static str,
        may_issue_now: bool,
        assigned_ca: Option<MockAssignedCa>,
    }
    #[derive(Clone)]
    struct MockAssignedCa {
        directory_url: String,
        requires_eab: bool,
        eab_kid: Option<String>,
        eab_hmac_key_b64url: Option<String>,
    }

    struct MockAll {
        base: String,
        order_status: Mutex<&'static str>,
        dns01_hits: Mutex<Vec<Value>>,
        cp_publish_ok: bool,
        doh_hits: Mutex<u32>,
        doh_answers_after: u32,
        admission: Mutex<MockAdmission>,
        issuance_complete_hits: Mutex<u32>,
    }

    async fn spawn_mock(cp_publish_ok: bool) -> (String, Arc<MockAll>) {
        spawn_mock_with_doh_delay(cp_publish_ok, 0).await
    }

    async fn spawn_mock_with_doh_delay(cp_publish_ok: bool, doh_answers_after: u32) -> (String, Arc<MockAll>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let state = Arc::new(MockAll {
            base: base.clone(),
            order_status: Mutex::new("pending"),
            dns01_hits: Mutex::new(Vec::new()),
            cp_publish_ok,
            doh_hits: Mutex::new(0),
            doh_answers_after,
            admission: Mutex::new(MockAdmission {
                status: "gelb",
                may_issue_now: true,
                assigned_ca: Some(MockAssignedCa {
                    directory_url: format!("http://{addr}/directory"),
                    requires_eab: false,
                    eab_kid: None,
                    eab_hmac_key_b64url: None,
                }),
            }),
            issuance_complete_hits: Mutex::new(0),
        });

        fn nonce() -> HeaderMap {
            let mut h = HeaderMap::new();
            h.insert("replay-nonce", "n1".parse().unwrap());
            h
        }

        async fn directory(AxState(s): AxState<Arc<MockAll>>) -> impl axum::response::IntoResponse {
            (
                nonce(),
                AxJson(serde_json::json!({
                    "newNonce": format!("{}/new-nonce", s.base),
                    "newAccount": format!("{}/new-account", s.base),
                    "newOrder": format!("{}/new-order", s.base),
                })),
            )
        }
        async fn new_nonce() -> impl axum::response::IntoResponse {
            (StatusCode::OK, nonce())
        }
        async fn new_account(AxState(s): AxState<Arc<MockAll>>) -> impl axum::response::IntoResponse {
            let mut h = nonce();
            h.insert("location", format!("{}/acct/1", s.base).parse().unwrap());
            (StatusCode::OK, h, AxJson(serde_json::json!({"status": "valid"})))
        }
        async fn new_order(AxState(s): AxState<Arc<MockAll>>) -> impl axum::response::IntoResponse {
            let mut h = nonce();
            h.insert("location", format!("{}/order/1", s.base).parse().unwrap());
            (
                StatusCode::OK,
                h,
                AxJson(serde_json::json!({
                    "status": "pending",
                    "authorizations": [format!("{}/authz/1", s.base)],
                    "finalize": format!("{}/finalize/1", s.base),
                })),
            )
        }
        async fn get_authz(AxState(s): AxState<Arc<MockAll>>) -> impl axum::response::IntoResponse {
            (
                nonce(),
                AxJson(serde_json::json!({
                    "status": if *s.order_status.lock().unwrap() == "pending" { "pending" } else { "valid" },
                    "challenges": [{ "type": "dns-01", "token": "dtok", "url": format!("{}/challenge/1", s.base) }]
                })),
            )
        }
        async fn respond_challenge(AxState(s): AxState<Arc<MockAll>>) -> impl axum::response::IntoResponse {
            *s.order_status.lock().unwrap() = "ready";
            (nonce(), AxJson(serde_json::json!({"status": "processing"})))
        }
        async fn get_order(AxState(s): AxState<Arc<MockAll>>) -> impl axum::response::IntoResponse {
            let status = *s.order_status.lock().unwrap();
            let mut body = serde_json::json!({
                "status": status,
                "authorizations": [format!("{}/authz/1", s.base)],
                "finalize": format!("{}/finalize/1", s.base),
            });
            if status == "valid" {
                body["certificate"] = serde_json::json!(format!("{}/cert/1", s.base));
            }
            (nonce(), AxJson(body))
        }
        async fn finalize(AxState(s): AxState<Arc<MockAll>>) -> impl axum::response::IntoResponse {
            *s.order_status.lock().unwrap() = "valid";
            (nonce(), AxJson(serde_json::json!({"status": "valid"})))
        }
        async fn get_cert() -> impl axum::response::IntoResponse {
            (nonce(), "-----BEGIN CERTIFICATE-----\nmock\n-----END CERTIFICATE-----\n")
        }
        async fn dns01_publish(
            AxState(s): AxState<Arc<MockAll>>,
            AxJson(body): AxJson<Value>,
        ) -> StatusCode {
            s.dns01_hits.lock().unwrap().push(body);
            if s.cp_publish_ok {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            }
        }
        async fn dns01_clear() -> StatusCode {
            StatusCode::OK
        }
        async fn acme_admission(AxState(s): AxState<Arc<MockAll>>) -> impl axum::response::IntoResponse {
            let a = s.admission.lock().unwrap().clone();
            let body = serde_json::json!({
                "status": a.status,
                "may_issue_now": a.may_issue_now,
                "assigned_ca": a.assigned_ca.map(|ca| serde_json::json!({
                    "name": "mock-ca",
                    "directory_url": ca.directory_url,
                    "requires_eab": ca.requires_eab,
                    "eab_kid": ca.eab_kid,
                    "eab_hmac_key_b64url": ca.eab_hmac_key_b64url,
                })),
            });
            (StatusCode::OK, AxJson(body))
        }
        async fn acme_issuance_complete(AxState(s): AxState<Arc<MockAll>>) -> StatusCode {
            *s.issuance_complete_hits.lock().unwrap() += 1;
            StatusCode::OK
        }
        // Stands in for a public DoH resolver: immediately echoes back whatever
        // value the last dns01_publish call recorded, so the propagation check
        // in obtain_or_renew sees the record as already visible -- no real
        // network, no arbitrary sleep needed to keep this test fast.
        async fn doh(AxState(s): AxState<Arc<MockAll>>) -> AxJson<Value> {
            let n = {
                let mut hits = s.doh_hits.lock().unwrap();
                let seen = *hits;
                *hits += 1;
                seen
            };
            if n < s.doh_answers_after {
                return AxJson(serde_json::json!({"Status": 0, "Answer": []}));
            }
            let value = s.dns01_hits.lock().unwrap().last().and_then(|h| h["value"].as_str().map(str::to_string));
            match value {
                Some(v) => AxJson(serde_json::json!({"Status": 0, "Answer": [{"data": format!("\"{v}\"")}]})),
                None => AxJson(serde_json::json!({"Status": 0, "Answer": []})),
            }
        }

        let app = Router::new()
            .route("/directory", get(directory))
            .route("/new-nonce", head(new_nonce))
            .route("/new-account", post(new_account))
            .route("/new-order", post(new_order))
            .route("/authz/1", post(get_authz))
            .route("/challenge/1", post(respond_challenge))
            .route("/order/1", post(get_order))
            .route("/finalize/1", post(finalize))
            .route("/cert/1", post(get_cert))
            .route("/agent/dns01-challenge", post(dns01_publish))
            .route("/agent/dns01-challenge/clear", post(dns01_clear))
            .route("/agent/acme-admission/:token/:hostname", get(acme_admission))
            .route("/agent/acme-issuance-complete/:token/:hostname", post(acme_issuance_complete))
            .route("/doh", get(doh))
            .with_state(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (base, state)
    }

    #[tokio::test]
    async fn obtain_or_renew_writes_key_then_cert_and_is_a_no_op_on_the_next_call() {
        let (base, mock) = spawn_mock(true).await;
        let dir = std::env::temp_dir().join(format!("ct-acme-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let config = AcmeCertConfig {
            cp_url: base.clone(),
            routing_token: "deadbeef".to_string(),
            hostname: "app.example.com".to_string(),
            cert_out_dir: dir.clone(),
            account_key_path: dir.join("account.der"),
            dns01_resolver_urls: vec![format!("{base}/doh")],
            dns01_propagation_timeout: Duration::from_secs(5),
            dns01_initial_delay: Some(Duration::ZERO),
            dns01_use_authoritative: false,
            dns01_attempts: Some(1),
        };

        let did_issue = obtain_or_renew(&config).await.unwrap();
        assert!(did_issue, "no cert existed yet -> issued one");
        assert!(std::fs::read_to_string(config.cert_path()).unwrap().contains("BEGIN CERTIFICATE"));
        assert!(std::fs::read_to_string(config.key_path()).unwrap().contains("PRIVATE KEY"));
        assert!(std::fs::metadata(&config.account_key_path).is_ok(), "account key persisted for reuse");

        // The DNS-01 publish call the mock control plane received carries the
        // routing token + bare hostname -- proving the RemoteAgent wiring
        // (not a direct DesecClient) is what obtain_or_renew actually uses.
        let hits = mock.dns01_hits.lock().unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0]["token"], "deadbeef");
        assert_eq!(hits[0]["hostname"], "app.example.com");
        drop(hits);

        // A second call with the just-written (fresh) cert is a no-op --
        // proving the file-age renewal check actually gates re-issuance.
        let did_issue_again = obtain_or_renew(&config).await.unwrap();
        assert!(!did_issue_again, "a fresh cert must not trigger a redundant issuance");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn obtain_or_renew_surfaces_a_forbidden_dns01_publish_as_an_error_not_a_silent_no_op() {
        let (base, _mock) = spawn_mock(false).await;
        let dir = std::env::temp_dir().join(format!("ct-acme-e2e-forbidden-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = AcmeCertConfig {
            cp_url: base.clone(),
            routing_token: "not-the-owner".to_string(),
            hostname: "app.example.com".to_string(),
            cert_out_dir: dir.clone(),
            account_key_path: dir.join("account.der"),
            dns01_resolver_urls: vec![format!("{base}/doh")],
            dns01_propagation_timeout: Duration::from_secs(5),
            dns01_initial_delay: Some(Duration::ZERO),
            dns01_use_authoritative: false,
            dns01_attempts: Some(1),
        };
        let err = obtain_or_renew(&config).await.unwrap_err();
        assert!(err.to_string().contains("publishing"), "{err}");
        assert!(!config.cert_path().exists(), "no cert file written on a failed issuance");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- Reproduces #229: publish succeeding must not be treated as "the CA
    // can already see it" -- these two pin down the actual reported failure
    // shape (NXDOMAIN at validation time despite a successful publish call).

    #[tokio::test]
    async fn obtain_or_renew_waits_out_a_delayed_dns01_propagation_then_succeeds() {
        // The mock's own DoH-lookalike withholds the TXT answer for the first
        // lookup, simulating deSEC not having replicated the record to public
        // nameservers yet -- issuance must still complete once it appears.
        let (base, mock) = spawn_mock_with_doh_delay(true, 1).await;
        let dir = std::env::temp_dir().join(format!("ct-acme-e2e-delayed-doh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = AcmeCertConfig {
            cp_url: base.clone(),
            routing_token: "deadbeef".to_string(),
            hostname: "app.example.com".to_string(),
            cert_out_dir: dir.clone(),
            account_key_path: dir.join("account.der"),
            dns01_resolver_urls: vec![format!("{base}/doh")],
            dns01_propagation_timeout: Duration::from_secs(10),
            dns01_initial_delay: Some(Duration::ZERO),
            dns01_use_authoritative: false,
            dns01_attempts: Some(1),
        };

        let did_issue = obtain_or_renew(&config).await.unwrap();
        assert!(did_issue);
        assert!(std::fs::read_to_string(config.cert_path()).unwrap().contains("BEGIN CERTIFICATE"));
        assert!(*mock.doh_hits.lock().unwrap() >= 2, "retried the DoH lookup at least once before succeeding");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn obtain_or_renew_fails_clearly_instead_of_racing_the_ca_when_dns01_never_becomes_visible() {
        // The publish call to the control plane succeeds (unlike the
        // already-covered forbidden-token case above), but the record never
        // becomes publicly visible -- must fail with a clear propagation
        // error and never reach/trigger the ACME server's own validation,
        // not the confusing "authorization became invalid: NXDOMAIN" shape
        // an agent would otherwise see straight from Let's Encrypt.
        let (base, _mock) = spawn_mock_with_doh_delay(true, u32::MAX).await;
        let dir = std::env::temp_dir().join(format!("ct-acme-e2e-stuck-doh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = AcmeCertConfig {
            cp_url: base.clone(),
            routing_token: "deadbeef".to_string(),
            hostname: "app.example.com".to_string(),
            cert_out_dir: dir.clone(),
            account_key_path: dir.join("account.der"),
            dns01_resolver_urls: vec![format!("{base}/doh")],
            dns01_propagation_timeout: Duration::from_millis(200),
            dns01_initial_delay: Some(Duration::ZERO),
            dns01_use_authoritative: false,
            dns01_attempts: Some(1),
        };

        let err = obtain_or_renew(&config).await.unwrap_err();
        assert!(err.to_string().contains("DNS-01 propagation check failed"), "{err}");
        assert!(!config.cert_path().exists(), "no cert file written when propagation never confirms");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- #233: the admission broker is a hard requirement, not an optional
    // enhancement with a legacy fallback -- these pin that down directly.

    #[tokio::test]
    async fn obtain_or_renew_skips_issuance_when_the_admission_broker_says_not_yet() {
        let (base, mock) = spawn_mock(true).await;
        *mock.admission.lock().unwrap() = MockAdmission { status: "gelb", may_issue_now: false, assigned_ca: None };
        let dir = std::env::temp_dir().join(format!("ct-acme-e2e-not-admitted-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = AcmeCertConfig {
            cp_url: base.clone(),
            routing_token: "deadbeef".to_string(),
            hostname: "app.example.com".to_string(),
            cert_out_dir: dir.clone(),
            account_key_path: dir.join("account.der"),
            dns01_resolver_urls: vec![format!("{base}/doh")],
            dns01_propagation_timeout: Duration::from_secs(5),
            dns01_initial_delay: Some(Duration::ZERO),
            dns01_use_authoritative: false,
            dns01_attempts: Some(1),
        };

        let did_issue = obtain_or_renew(&config).await.unwrap();
        assert!(!did_issue, "admission broker says not yet eligible -> quiet no-op, not an error");
        assert!(!config.cert_path().exists());
        assert!(mock.dns01_hits.lock().unwrap().is_empty(), "never even attempted a DNS-01 publish");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn obtain_or_renew_requires_the_admission_broker_to_answer_at_all() {
        // No mock server, no admission endpoint to reach -- this must be a
        // hard failure (no fallback to some locally-assumed directory).
        let dir = std::env::temp_dir().join(format!("ct-acme-e2e-no-broker-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = AcmeCertConfig {
            cp_url: "http://127.0.0.1:1".to_string(),
            routing_token: "deadbeef".to_string(),
            hostname: "app.example.com".to_string(),
            cert_out_dir: dir.clone(),
            account_key_path: dir.join("account.der"),
            dns01_resolver_urls: vec![],
            dns01_propagation_timeout: Duration::from_secs(5),
            dns01_initial_delay: Some(Duration::ZERO),
            dns01_use_authoritative: false,
            dns01_attempts: Some(1),
        };
        let err = obtain_or_renew(&config).await.unwrap_err();
        assert!(err.to_string().contains("admission broker did not respond"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn obtain_or_renew_uses_the_admission_brokers_assigned_ca_authoritatively() {
        let (base, mock) = spawn_mock(true).await;
        // Point this hostname at a SECOND mock ACME server via the admission
        // response -- proving the broker's assignment is what actually gets
        // used, not just a same-server coincidence.
        let (base2, _mock2) = spawn_mock(true).await;
        *mock.admission.lock().unwrap() = MockAdmission {
            status: "gelb",
            may_issue_now: true,
            assigned_ca: Some(MockAssignedCa {
                directory_url: format!("{base2}/directory"),
                requires_eab: false,
                eab_kid: None,
                eab_hmac_key_b64url: None,
            }),
        };
        let dir = std::env::temp_dir().join(format!("ct-acme-e2e-assigned-ca-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = AcmeCertConfig {
            cp_url: base.clone(),
            routing_token: "deadbeef".to_string(),
            hostname: "app.example.com".to_string(),
            cert_out_dir: dir.clone(),
            account_key_path: dir.join("account.der"),
            dns01_resolver_urls: vec![format!("{base}/doh")],
            dns01_propagation_timeout: Duration::from_secs(5),
            dns01_initial_delay: Some(Duration::ZERO),
            dns01_use_authoritative: false,
            dns01_attempts: Some(1),
        };

        let did_issue = obtain_or_renew(&config).await.unwrap();
        assert!(did_issue, "succeeded via the admission broker's assigned directory (a different mock server)");
        assert_eq!(*mock.issuance_complete_hits.lock().unwrap(), 1, "completion callback fired exactly once");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
