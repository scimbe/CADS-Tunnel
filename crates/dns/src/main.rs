//! `ct-dns` daemon + `selftest` (#31).
//!
//! Default: authoritative DNS-01 responder — serves `_acme-challenge` TXT over
//! public UDP+TCP `:53`, with a loopback-only mutation API the co-located ACME
//! client drives. Config:
//! - `CT_DNS_LISTEN`     — DNS listener (default `0.0.0.0:53`; needs privilege).
//! - `CT_DNS_API_LISTEN` — mutation API (default `127.0.0.1:8053`; keep loopback).
//! - `CT_DNS_API_TOKEN`  — optional `x-ct-dns-token` shared secret.
//! - `CT_DNS_STORE_PATH` — optional path to persist published challenge records
//!   (#302) so a restart mid-issuance doesn't lose a record Let's Encrypt's
//!   multi-perspective validation hasn't seen yet. Unset -> in-memory only,
//!   same as before.
//!
//! `ct-dns selftest`: validate a deSEC token + zone end to end — publish a TXT via
//! the deSEC API, query the authoritative nameserver directly (bypassing global
//! propagation), then clean up. Run it on a host that can reach `:53` outbound.

use std::net::SocketAddr;
use std::sync::Arc;

use ct_dns::store::AcmeDnsStore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().nth(1).as_deref() == Some("selftest") {
        return run_selftest().await;
    }
    run_daemon().await
}

async fn run_daemon() -> Result<(), Box<dyn std::error::Error>> {
    let dns_listen: SocketAddr = std::env::var("CT_DNS_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:53".to_string())
        .parse()?;
    let api_listen: SocketAddr = std::env::var("CT_DNS_API_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8053".to_string())
        .parse()?;
    let token = std::env::var("CT_DNS_API_TOKEN").ok().filter(|s| !s.is_empty());

    if !api_listen.ip().is_loopback() {
        eprintln!("ct-dns: WARNING — API listener {api_listen} is not loopback; the mutation API should stay private");
    }
    eprintln!(
        "ct-dns: authoritative DNS on {dns_listen} (udp+tcp), mutation API on {api_listen}{}",
        if token.is_some() { " (token required)" } else { "" }
    );

    let store = match std::env::var("CT_DNS_STORE_PATH").ok().filter(|s| !s.is_empty()) {
        Some(path) => {
            let store = AcmeDnsStore::open(&path)?;
            eprintln!("ct-dns: challenge store persisted to {path} (#302)");
            Arc::new(store)
        }
        None => Arc::new(AcmeDnsStore::new()),
    };
    tokio::try_join!(
        ct_dns::server::serve_udp(store.clone(), dns_listen),
        ct_dns::server::serve_tcp(store.clone(), dns_listen),
        ct_dns::api::serve_api(store.clone(), token, api_listen),
    )?;
    Ok(())
}

/// Publish a unique TXT via deSEC, confirm it resolves at the authoritative NS,
/// then clean up. Exits non-zero if the record never appears.
async fn run_selftest() -> Result<(), Box<dyn std::error::Error>> {
    use ct_dns::provider::DesecClient;

    let client = DesecClient::from_env()
        .ok_or("selftest: set DESEC_TOKEN and DESEC_DOMAIN (see docs/dns01-desec.md)")?;
    let domain = std::env::var("DESEC_DOMAIN")?;
    // Which authoritative NS to query (deSEC's primary by default).
    let ns = std::env::var("DESEC_SELFTEST_NS").unwrap_or_else(|_| "ns1.desec.io:53".to_string());
    let name = format!("_acme-challenge.{domain}");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let value = format!("ct-dns-selftest-{nanos}");

    eprintln!("selftest: publishing TXT {name} via deSEC ...");
    client
        .set_txt(&name, &value)
        .await
        .map_err(|e| format!("deSEC publish failed: {e}"))?;

    eprintln!("selftest: querying {ns} for {name} (up to ~30s while deSEC serves it) ...");
    let mut seen = false;
    for attempt in 1..=15 {
        match ct_dns::client::query_txt(&ns, &name).await {
            Ok(vals) if vals.iter().any(|v| v == &value) => {
                seen = true;
                break;
            }
            Ok(_) => {}
            Err(e) => eprintln!("selftest: query attempt {attempt} error: {e}"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    eprintln!("selftest: cleaning up TXT {name} ...");
    let _ = client.clear_txt(&name).await;

    if seen {
        println!("SELFTEST OK — deSEC token + zone work: TXT published and resolved at {ns}");
        Ok(())
    } else {
        Err(format!(
            "SELFTEST FAILED — TXT not visible at {ns} within timeout. Check: token scope, \
             DESEC_DOMAIN={domain}, and that {ns} is reachable on :53 from here."
        )
        .into())
    }
}
