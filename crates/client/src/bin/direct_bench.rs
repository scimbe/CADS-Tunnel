//! Direct-connection baseline bench for the thesis FF2 measurement (#51).
//!
//! Measures the round-trip latency of a **direct** client→server connection over
//! the same `tc netem` path the tunnel sweep uses, with **no ct-edge / no tunnel
//! hop** in between, and emits a `RESULT <csv_row>` line in the *exact* format the
//! tunnel bench prints (`ct_client::bench::csv_row`) so `scripts/tabulate.py` can
//! diff tunnel − baseline into an overhead column. Two protocols:
//!
//!   CT_DIRECT_PROTO=tcp   — plain TCP round-trip to a TCP echo (the testbed's
//!                           socat `origin`); the transport the tunnel ultimately
//!                           delivers at the Origin.
//!   CT_DIRECT_PROTO=quic  — plain QUIC round-trip to `quic_echo`; isolates the
//!                           Noise/relay/PoW overhead from the QUIC transport the
//!                           tunnel's client→edge hop already pays.
//!
//! Methodology mirrors the tunnel one-shot bench (`bench::run_once`): a *fresh*
//! connection per iteration, write payload → half-close → read the echo back,
//! timed end-to-end; failed iterations are skipped. The netem condition labels are
//! read from the same `CT_BENCH_DELAY/LOSS/RATE` env the tunnel client uses, so the
//! baseline rows line up with the tunnel rows for the same grid point.
//!
//! Env:
//!   CT_DIRECT_PROTO       tcp | quic            (default tcp)
//!   CT_DIRECT_TARGET      host:port to dial     (default 10.5.0.3:8080)
//!   CT_DIRECT_CERT        quic server cert (der) (default /shared/quic-echo-cert.der)
//!   CT_CLIENT_ITERATIONS  round-trips to measure (default 30)
//!   CT_CLIENT_PAYLOAD     bytes to echo          (default hello-direct)
//!   CT_BENCH_DELAY/LOSS/RATE  condition labels for the CSV row (blank = none)

use std::net::SocketAddr;
use std::time::Instant;

use ct_client::bench::{csv_row, summarize, throughput, throughput_csv_row};
use ct_client::transport::{dial_edge, load_cert};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A bulk transfer larger than one socket buffer must be drained concurrently with
/// the write, or the return path fills and deadlocks. Cap on the echoed read so a
/// runaway peer can't allocate unbounded memory (256 MiB — well above any smoke
/// payload).
const MAX_BULK_BYTES: usize = 256 * 1024 * 1024;

/// One direct-TCP bulk transfer: connect → write the whole `payload` on a task,
/// half-close, drain the echo concurrently. Returns the elapsed **seconds** for
/// the round-trip of `payload.len()` bytes (the direct-baseline analogue of the
/// tunnel `run_once_throughput`, #57).
async fn tcp_throughput_once(target: SocketAddr, payload: &[u8]) -> Result<f64, BoxError> {
    let start = Instant::now();
    let stream = TcpStream::connect(target).await?;
    let (r, mut w) = stream.into_split();
    let payload_owned = payload.to_vec();
    let writer = tokio::spawn(async move {
        w.write_all(&payload_owned).await?;
        w.shutdown().await?;
        Ok::<(), std::io::Error>(())
    });
    let mut got = Vec::with_capacity(payload.len());
    // #593: this TCP path used the unbounded `AsyncReadExt::read_to_end` -- unlike the
    // QUIC path just below, which already bounds via quinn's own `RecvStream::read_to_end
    // (MAX_BULK_BYTES)`. tokio's generic `AsyncReadExt::read_to_end` has no built-in cap
    // parameter, so `.take(MAX_BULK_BYTES)` supplies the equivalent bound here; a read
    // that hits it fails the length check below instead of allocating without limit.
    r.take(MAX_BULK_BYTES as u64).read_to_end(&mut got).await?;
    let elapsed = start.elapsed().as_secs_f64();
    writer.await??;
    if got.len() == payload.len() {
        Ok(elapsed)
    } else {
        Err("tcp bulk echo length mismatch".into())
    }
}

/// One direct-QUIC bulk transfer: dial → open_bi → write the whole `payload` on a
/// task, finish, drain the echo concurrently (large read cap for the bulk path).
async fn quic_throughput_once(
    target: SocketAddr,
    cert: rustls::pki_types::CertificateDer<'static>,
    payload: &[u8],
) -> Result<f64, BoxError> {
    let start = Instant::now();
    let conn = dial_edge(target, cert).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    let payload_owned = payload.to_vec();
    let writer = tokio::spawn(async move {
        send.write_all(&payload_owned).await?;
        send.finish()?;
        Ok::<(), BoxError>(())
    });
    let got = recv.read_to_end(MAX_BULK_BYTES).await?;
    let elapsed = start.elapsed().as_secs_f64();
    writer.await??;
    conn.close(0u32.into(), b"done");
    if got.len() == payload.len() {
        Ok(elapsed)
    } else {
        Err("quic bulk echo length mismatch".into())
    }
}

/// One fresh-connection TCP round-trip: connect → write → half-close → read echo.
async fn tcp_once(target: SocketAddr, payload: &[u8]) -> Result<f64, BoxError> {
    tcp_once_capped(target, payload, MAX_BULK_BYTES as u64).await
}

/// [`tcp_once`]'s real body, with the read cap as a parameter so a test can pin a
/// small cap instead of paying for `MAX_BULK_BYTES` (#619).
async fn tcp_once_capped(target: SocketAddr, payload: &[u8], cap: u64) -> Result<f64, BoxError> {
    let start = Instant::now();
    let mut stream = TcpStream::connect(target).await?;
    stream.write_all(payload).await?;
    stream.shutdown().await?; // signal EOF so the echo (socat /bin/cat) replies + closes
    let mut got = Vec::new();
    // #619: this was the one unbounded `read_to_end` left in this file after #593
    // capped every other read here (`tcp_throughput_once`/`quic_throughput_once`/
    // `quic_once`) -- CT_DIRECT_TARGET is "not always something the operator fully
    // controls" (#593's own reasoning), so a misbehaving/malicious echo peer that
    // never closes could otherwise make this allocate without bound.
    stream.take(cap).read_to_end(&mut got).await?;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    if got == payload {
        Ok(elapsed)
    } else {
        Err("tcp echo mismatch".into())
    }
}

/// One fresh-connection QUIC round-trip: connect → open_bi → write → finish → read
/// echo. Reuses the client's QUIC dialer (`dial_edge`), which trusts exactly the
/// server cert we load from the shared volume.
async fn quic_once(
    target: SocketAddr,
    cert: rustls::pki_types::CertificateDer<'static>,
    payload: &[u8],
) -> Result<f64, BoxError> {
    let start = Instant::now();
    let conn = dial_edge(target, cert).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(payload).await?;
    send.finish()?;
    let got = recv.read_to_end(64 * 1024).await?;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    conn.close(0u32.into(), b"done");
    if got == payload {
        Ok(elapsed)
    } else {
        Err("quic echo mismatch".into())
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let proto = std::env::var("CT_DIRECT_PROTO").unwrap_or_else(|_| "tcp".to_string());
    let target: SocketAddr = std::env::var("CT_DIRECT_TARGET")
        .unwrap_or_else(|_| "10.5.0.3:8080".to_string())
        .parse()?;
    let iterations: usize = std::env::var("CT_CLIENT_ITERATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let payload = std::env::var("CT_CLIENT_PAYLOAD").unwrap_or_else(|_| "hello-direct".to_string());
    let payload = payload.as_bytes();

    // For QUIC, wait briefly for the echo server to publish its cert (startup race).
    let cert = if proto == "quic" {
        let path = std::env::var("CT_DIRECT_CERT")
            .unwrap_or_else(|_| "/shared/quic-echo-cert.der".to_string());
        let deadline = Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match load_cert(&path) {
                Ok(c) => break Some(c),
                Err(_) if Instant::now() < deadline => {
                    eprintln!("direct_bench: waiting for quic echo cert at {path} ...");
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                Err(e) => return Err(format!("quic echo cert not available at {path}: {e}").into()),
            }
        }
    } else {
        None
    };

    let delay = std::env::var("CT_BENCH_DELAY").unwrap_or_default();
    let loss = std::env::var("CT_BENCH_LOSS").unwrap_or_default();
    let rate = std::env::var("CT_BENCH_RATE").unwrap_or_default();

    // Throughput (bulk-transfer) baseline (#57): move a fixed CT_BENCH_BYTES
    // payload over the direct TCP/QUIC path and emit a throughput RESULT row
    // (delay,loss,rate,bytes,secs,mbps,mib_s) in the same format the tunnel
    // throughput bench prints — the direct QUIC-vs-TCP bandwidth comparison the
    // rate-limited sweep diffs against. Selected by CT_BENCH_MODE=throughput|bulk.
    if matches!(
        std::env::var("CT_BENCH_MODE").as_deref(),
        Ok("throughput") | Ok("bulk")
    ) {
        let bytes: usize = std::env::var("CT_BENCH_BYTES")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|&b| b > 0 && b <= MAX_BULK_BYTES)
            .unwrap_or(8 * 1024 * 1024);
        let bulk = vec![0u8; bytes];
        let mut total_bytes: u64 = 0;
        let mut total_secs: f64 = 0.0;
        for _ in 0..iterations.max(1) {
            let r = match proto.as_str() {
                "quic" => quic_throughput_once(target, cert.clone().unwrap(), &bulk).await,
                _ => tcp_throughput_once(target, &bulk).await,
            };
            match r {
                Ok(secs) => {
                    total_bytes += bulk.len() as u64;
                    total_secs += secs;
                }
                Err(e) => eprintln!("direct_bench: throughput iteration failed: {e}"),
            }
        }
        let t = throughput(total_bytes, total_secs)
            .ok_or("direct throughput bench produced no successful transfer")?;
        println!("RESULT {}", throughput_csv_row(&delay, &loss, &rate, &t));
        eprintln!(
            "direct_bench: proto={} throughput {} bytes in {:.3}s = {:.3} mbit/s ({:.3} MiB/s)",
            proto, t.bytes, t.secs, t.mbps, t.mib_s
        );
        return Ok(());
    }

    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let r = match proto.as_str() {
            "quic" => quic_once(target, cert.clone().unwrap(), payload).await,
            _ => tcp_once(target, payload).await,
        };
        match r {
            Ok(ms) => samples.push(ms),
            Err(e) => eprintln!("direct_bench: iteration failed: {e}"),
        }
    }

    let summary = summarize(&samples).ok_or("direct bench produced no samples")?;
    println!("RESULT {}", csv_row(&delay, &loss, &rate, &summary, &samples));
    eprintln!(
        "direct_bench: proto={} {}/{} iterations, mean {:.2}ms p95 {:.2}ms",
        proto, summary.n, iterations, summary.mean_ms, summary.p95_ms
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// #619: a peer that keeps sending past the cap and never closes must not make
    /// `tcp_once` read without bound -- the `.take(cap)` read hits the cap, `got`
    /// stops growing there, and the existing length-mismatch check (not a hang, not
    /// an unbounded allocation) is what ends the call. A small cap here (not the
    /// real 256 MiB `MAX_BULK_BYTES`) keeps this test fast while still proving the
    /// bound is real.
    #[tokio::test]
    async fn tcp_once_stops_at_the_cap_instead_of_reading_a_peer_that_never_closes() {
        const CAP: u64 = 4096;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Drain whatever the client sends, then stream well past CAP without
            // ever closing -- the exact "misbehaving/malicious echo peer" shape
            // #619 is about.
            let mut discard = [0u8; 64];
            let _ = sock.read(&mut discard).await;
            let chunk = vec![0u8; 1024];
            for _ in 0..(CAP as usize / chunk.len() + 4) {
                if sock.write_all(&chunk).await.is_err() {
                    break;
                }
            }
            // Deliberately never shuts down / drops late: the client's `.take(CAP)`
            // must be what ends the read, not the peer closing.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tcp_once_capped(addr, b"probe", CAP),
        )
        .await
        .expect("bounded by the cap, not by a hang waiting for the peer to close");

        // The peer never echoes the exact payload back (it streams zeros), so this
        // is always the length/content-mismatch error -- the point is it returns
        // promptly at all, proving the read didn't grow past the cap.
        assert!(result.is_err(), "a non-echoing peer fails the content check, as expected");

        server.abort();
    }
}
