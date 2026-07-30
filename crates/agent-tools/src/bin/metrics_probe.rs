//! Metrics scrape probe (M14.2b).
//!
//! Scrapes an Agent's `/metrics` endpoint and succeeds once it observes tunnel
//! activity (`ct_tunnels_opened_total >= 1`). Used in the compose smoke: the
//! Client drives one tunnel, then this probe confirms the Agent's counters
//! moved. Raw HTTP/1.0 over TCP so it needs no HTTP-client dependency.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let addr =
        std::env::var("CT_AGENT_METRICS_ADDR").unwrap_or_else(|_| "127.0.0.1:9100".to_string());
    const WANT: &str = "ct_tunnels_opened_total";

    // Poll for up to ~30s: the endpoint may need a moment to bind, and the
    // tunnel that moves the counter may still be completing.
    for _ in 0..60 {
        if let Ok(body) = scrape(&addr).await {
            if let Some(opened) = counter_value(&body, WANT) {
                if opened >= 1 {
                    let bytes = counter_value(&body, "ct_bytes_to_origin_total").unwrap_or(0);
                    println!(
                        "metrics probe OK: {WANT}={opened} ct_bytes_to_origin_total={bytes} via {addr}"
                    );
                    return Ok(());
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Err(format!("metrics probe timed out waiting for {WANT} >= 1 at {addr}").into())
}

/// One raw HTTP/1.0 `GET /metrics`, returning the full response text.
async fn scrape(addr: &str) -> Result<String, BoxError> {
    let mut sock = TcpStream::connect(addr).await?;
    sock.write_all(b"GET /metrics HTTP/1.0\r\nHost: metrics\r\n\r\n").await?;
    let mut resp = String::new();
    sock.read_to_string(&mut resp).await?;
    Ok(resp)
}

/// Parse the value of the Prometheus counter `name` from the exposition text.
fn counter_value(body: &str, name: &str) -> Option<u64> {
    for line in body.lines() {
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix(name) {
            // Exact series match: the name is followed by whitespace then the value.
            if let Ok(v) = rest.trim().parse::<u64>() {
                return Some(v);
            }
        }
    }
    None
}
