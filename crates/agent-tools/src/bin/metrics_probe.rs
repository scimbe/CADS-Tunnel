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

/// #303: bound on connect + each read of a scrape -- without this, a metrics endpoint
/// that accepts the TCP connection but never writes anything (e.g. an Agent wedged
/// mid-bind, observed live in the compose smoke) hangs `read_to_string` forever, so
/// the 60x500ms poll loop never iterates and the smoke test hangs instead of
/// reporting a timeout.
const SCRAPE_TIMEOUT: Duration = Duration::from_secs(3);

/// #303: cap on the total scraped response size -- `read_to_string` was unbounded, so
/// a misbehaving endpoint streaming an arbitrarily large body would grow `resp` without
/// limit. A real Prometheus exposition for this probe's use is a handful of counters,
/// nowhere near this.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// One raw HTTP/1.0 `GET /metrics`, returning the full response text.
async fn scrape(addr: &str) -> Result<String, BoxError> {
    scrape_with_timeout(addr, SCRAPE_TIMEOUT).await
}

/// [`scrape`] with an injectable timeout (#303) so a test can prove it fires without
/// waiting out the real default.
async fn scrape_with_timeout(addr: &str, timeout: Duration) -> Result<String, BoxError> {
    let mut sock = tokio::time::timeout(timeout, TcpStream::connect(addr)).await??;
    tokio::time::timeout(timeout, sock.write_all(b"GET /metrics HTTP/1.0\r\nHost: metrics\r\n\r\n")).await??;
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        // Timeout resets on every successful partial read, so a slow-but-genuinely-
        // progressing response isn't unfairly punished -- only a true stall (no bytes
        // at all within `timeout`) fails the scrape.
        let n = tokio::time::timeout(timeout, sock.read(&mut buf)).await??;
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&buf[..n]);
        if resp.len() > MAX_RESPONSE_BYTES {
            return Err(format!("metrics response exceeded the {MAX_RESPONSE_BYTES}-byte cap").into());
        }
    }
    Ok(String::from_utf8_lossy(&resp).into_owned())
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn scrape_returns_the_full_body_from_a_well_behaved_endpoint() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 256];
            let _ = sock.read(&mut req).await;
            sock.write_all(b"ct_tunnels_opened_total 1\n").await.unwrap();
            sock.shutdown().await.unwrap();
        });

        let body = scrape_with_timeout(&addr.to_string(), Duration::from_secs(5)).await.unwrap();
        assert_eq!(counter_value(&body, "ct_tunnels_opened_total"), Some(1));
    }

    #[tokio::test]
    async fn scrape_times_out_against_an_endpoint_that_accepts_but_never_writes_303() {
        // #303: exactly the live-observed failure -- the port is open, the connection
        // is accepted, but the peer never sends a byte (an Agent wedged mid-bind).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _held = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            // Never read/write/close -- just hold the connection open and silent.
            std::future::pending::<()>().await;
            drop(sock);
        });

        let start = tokio::time::Instant::now();
        let result = scrape_with_timeout(&addr.to_string(), Duration::from_millis(200)).await;
        let elapsed = start.elapsed();

        assert!(result.is_err(), "a stalled endpoint must fail the scrape, not hang forever");
        assert!(elapsed < Duration::from_secs(2), "must fail promptly on the injected short timeout, elapsed {elapsed:?}");
    }

    #[tokio::test]
    async fn scrape_rejects_a_response_over_the_size_cap_303() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 256];
            let _ = sock.read(&mut req).await;
            // Stream well past the cap in one write.
            let oversized = vec![b'x'; MAX_RESPONSE_BYTES + 1024];
            let _ = sock.write_all(&oversized).await;
            let _ = sock.shutdown().await;
        });

        let result = scrape_with_timeout(&addr.to_string(), Duration::from_secs(5)).await;
        assert!(result.is_err(), "an oversized response must be rejected, not buffered without limit");
    }
}
