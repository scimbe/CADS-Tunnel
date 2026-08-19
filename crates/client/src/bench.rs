//! Performance bench harness (M6.1a).
//!
//! Summary statistics over latency samples (pure, tested here), plus — in M6.1b —
//! a runner that measures tunnel round-trip latency under `tc netem` conditions
//! for the evaluation (M6).

use std::net::SocketAddr;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::transport::{
    client_tunnel_noise, client_tunnel_stream, dial_edge, udp_selftest,
    DEFAULT_STREAM_SETUP_DEADLINE,
};
use ct_common::Capability;
use rustls::pki_types::CertificateDer;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Cap on an echoed bulk read so a misbehaving Agent/Origin (this bench dials whatever
/// `client_tunnel_stream`'s Capability points at, which for #322-style pipeline onboarding
/// or an operator benchmarking a third party is not always something the operator fully
/// controls) can't make the client allocate unbounded memory or hang forever draining a
/// peer that never closes. `tokio::io::AsyncReadExt::read_to_end` has no built-in bound
/// (unlike quinn's `RecvStream::read_to_end(max_size)`, used by the sibling
/// `direct_bench.rs`'s QUIC path) -- `.take(MAX_BULK_BYTES)` supplies one here. 256 MiB,
/// matching `direct_bench.rs`'s own constant: well above any smoke payload, and a read
/// that hits this cap fails the existing length/content check below rather than silently
/// succeeding on truncated data.
const MAX_BULK_BYTES: u64 = 256 * 1024 * 1024;

/// CSV header for a sweep result file. The M16 statistical columns
/// (`stddev_ms`, `ci95_ms`, `p99_ms`) are appended after the original M6 columns
/// so existing readers that index the first nine columns keep working. The
/// trailing `samples_ms` column (#52) carries the raw per-iteration latencies
/// (space-separated) so a bootstrap-percentile CI can be computed downstream on
/// the right-skewed loss distributions; it is appended last for the same reason.
pub const CSV_HEADER: &str =
    "delay,loss,rate,n,mean_ms,min_ms,max_ms,p50_ms,p95_ms,stddev_ms,ci95_ms,p99_ms,samples_ms";

/// Summary statistics over a set of latency samples (milliseconds).
#[derive(Debug, Clone, PartialEq)]
pub struct Summary {
    pub n: usize,
    pub mean_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    /// Sample standard deviation (n−1 denominator); 0 for n < 2.
    pub stddev_ms: f64,
    /// Half-width of the 95% confidence interval for the mean
    /// (1.96·stddev/√n); 0 for n < 2.
    pub ci95_ms: f64,
    /// 99th percentile (nearest-rank) — the tail the study reports.
    pub p99_ms: f64,
}

/// Summarize latency `samples` (ms). Returns `None` for an empty set. Percentiles
/// use nearest-rank on the sorted samples; the spread is reported as the sample
/// standard deviation and a 95% confidence interval for the mean (M16 — results
/// must be statistically defensible, not single-point).
pub fn summarize(samples: &[f64]) -> Option<Summary> {
    if samples.is_empty() {
        return None;
    }
    let n = samples.len();
    let mean_ms = samples.iter().sum::<f64>() / n as f64;

    // Sample variance (n−1); undefined for a single sample → treat spread as 0.
    let (stddev_ms, ci95_ms) = if n >= 2 {
        let variance = samples
            .iter()
            .map(|x| {
                let d = x - mean_ms;
                d * d
            })
            .sum::<f64>()
            / (n as f64 - 1.0);
        let stddev = variance.sqrt();
        (stddev, 1.96 * stddev / (n as f64).sqrt())
    } else {
        (0.0, 0.0)
    };

    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let percentile = |p: f64| -> f64 {
        let idx = ((p / 100.0) * (n as f64 - 1.0)).round() as usize;
        sorted[idx]
    };

    Some(Summary {
        n,
        mean_ms,
        min_ms: sorted[0],
        max_ms: sorted[n - 1],
        p50_ms: percentile(50.0),
        p95_ms: percentile(95.0),
        stddev_ms,
        ci95_ms,
        p99_ms: percentile(99.0),
    })
}

/// One fresh-connection Noise round-trip: dial → `client_tunnel_noise` → verify
/// echo, returning the elapsed time in milliseconds (M8.4c-ii).
async fn run_once(
    edge_addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
) -> Result<f64, BoxError> {
    let start = Instant::now();
    let conn = dial_edge(edge_addr, edge_cert).await?;
    let response = client_tunnel_noise(&conn, &cap.token, cap, client_private, payload).await?;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    conn.close(0u32.into(), b"done");
    if response == payload {
        Ok(elapsed)
    } else {
        Err("bench response mismatch".into())
    }
}

/// Run `iterations` fresh-connection Noise round-trips, returning per-iteration
/// latency in milliseconds. Failed iterations are skipped.
pub async fn run_bench(
    edge_addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
    iterations: usize,
) -> Vec<f64> {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        if let Ok(ms) = run_once(edge_addr, edge_cert.clone(), cap, client_private, payload).await {
            samples.push(ms);
        }
    }
    samples
}

/// One streaming round-trip (M16.2b): dial → `client_tunnel_stream` bridging a
/// local duplex to the Origin over the Noise session; write `payload`, signal
/// EOF, read the echo back. Returns the elapsed time in milliseconds. This
/// measures the full-duplex streaming path (M9) rather than the one-shot path.
async fn run_once_stream(
    edge_addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
) -> Result<f64, BoxError> {
    let start = Instant::now();
    let conn = dial_edge(edge_addr, edge_cert).await?;
    let (app_local, app_remote) = tokio::io::duplex(64 * 1024);

    let token = cap.token.clone();
    let cap_c = cap.clone();
    let client_private = *client_private;
    let tunnel =
        tokio::spawn(
            async move {
                client_tunnel_stream(
                    &conn,
                    &token,
                    &cap_c,
                    &client_private,
                    app_local,
                    DEFAULT_STREAM_SETUP_DEADLINE,
                )
                .await
            },
        );

    // Drive the local app end: send the payload, half-close so the pump sees
    // EOF, then read the echoed bytes back.
    let (r, mut w) = tokio::io::split(app_remote);
    w.write_all(payload).await?;
    w.shutdown().await?;
    let mut got = Vec::new();
    r.take(MAX_BULK_BYTES).read_to_end(&mut got).await?;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;

    let _ = tunnel.await;
    if got == payload {
        Ok(elapsed)
    } else {
        Err("stream bench response mismatch".into())
    }
}

/// Run `iterations` streaming round-trips, returning per-iteration latency in
/// milliseconds. Failed iterations are skipped. The stream analogue of
/// [`run_bench`] for the mode comparison (M16.2b).
pub async fn run_bench_stream(
    edge_addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
    iterations: usize,
) -> Vec<f64> {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        if let Ok(ms) =
            run_once_stream(edge_addr, edge_cert.clone(), cap, client_private, payload).await
        {
            samples.push(ms);
        }
    }
    samples
}

/// One UDP round-trip (M16.2c): dial → `udp_selftest` sends one datagram through
/// the tunnel to the UDP Origin and awaits its echo. Returns the elapsed time in
/// milliseconds. Measures the datagram path (M10).
async fn run_once_udp(
    edge_addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
) -> Result<f64, BoxError> {
    let start = Instant::now();
    let conn = dial_edge(edge_addr, edge_cert).await?;
    let response = udp_selftest(&conn, &cap.token, cap, client_private, payload).await?;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    conn.close(0u32.into(), b"done");
    if response == payload {
        Ok(elapsed)
    } else {
        Err("udp bench response mismatch".into())
    }
}

/// Run `iterations` UDP round-trips, returning per-iteration latency in
/// milliseconds. Failed iterations are skipped. The datagram analogue of
/// [`run_bench`] for the mode comparison (M16.2c).
pub async fn run_bench_udp(
    edge_addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
    iterations: usize,
) -> Vec<f64> {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        if let Ok(ms) =
            run_once_udp(edge_addr, edge_cert.clone(), cap, client_private, payload).await
        {
            samples.push(ms);
        }
    }
    samples
}

/// One bulk transfer over the streaming tunnel (#76 OV2, #57): dial →
/// `client_tunnel_stream` bridging a local duplex to the Origin, write the whole
/// `payload`, half-close so the echo Origin drains it, and read every echoed byte
/// back — timed end-to-end. Returns the elapsed wall-clock **seconds** for the
/// round-trip of `payload.len()` application bytes. The throughput analogue of
/// [`run_once_stream`]: for the overlay-under-rate-limit dimension the metric is
/// bytes/second, not RTT.
///
/// The write side runs on its own task so the echo can be drained concurrently: a
/// bulk payload larger than the socket buffers would otherwise deadlock (the
/// return path fills before the reader starts).
async fn run_once_throughput(
    edge_addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
) -> Result<f64, BoxError> {
    let start = Instant::now();
    let conn = dial_edge(edge_addr, edge_cert).await?;
    let (app_local, app_remote) = tokio::io::duplex(256 * 1024);

    let token = cap.token.clone();
    let cap_c = cap.clone();
    let client_private = *client_private;
    let tunnel =
        tokio::spawn(
            async move {
                client_tunnel_stream(
                    &conn,
                    &token,
                    &cap_c,
                    &client_private,
                    app_local,
                    DEFAULT_STREAM_SETUP_DEADLINE,
                )
                .await
            },
        );

    let (r, mut w) = tokio::io::split(app_remote);
    let payload_owned = payload.to_vec();
    let writer = tokio::spawn(async move {
        w.write_all(&payload_owned).await?;
        w.shutdown().await?;
        Ok::<(), std::io::Error>(())
    });

    let mut got = Vec::with_capacity(payload.len());
    r.take(MAX_BULK_BYTES).read_to_end(&mut got).await?;
    let elapsed = start.elapsed().as_secs_f64();

    writer.await??;
    let _ = tunnel.await;
    if got.len() == payload.len() && got == payload {
        Ok(elapsed)
    } else {
        Err("throughput bench response mismatch".into())
    }
}

/// Run `iterations` bulk transfers of `payload` over the streaming tunnel and
/// return the aggregate [`Throughput`] over the total bytes moved and total
/// wall-clock elapsed (a sustained-transfer estimate; failed iterations are
/// skipped). `None` when no transfer succeeds. The `bytes` reported are the
/// one-way application payload summed across successful iterations; the elapsed
/// time is the full echo round-trip, so the rate is an echo-goodput figure the
/// evaluation interprets against the netem rate cap (#57).
pub async fn run_bench_throughput(
    edge_addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    cap: &Capability,
    client_private: &[u8; 32],
    payload: &[u8],
    iterations: usize,
) -> Option<Throughput> {
    let mut total_bytes: u64 = 0;
    let mut total_secs: f64 = 0.0;
    for _ in 0..iterations {
        if let Ok(secs) =
            run_once_throughput(edge_addr, edge_cert.clone(), cap, client_private, payload).await
        {
            total_bytes += payload.len() as u64;
            total_secs += secs;
        }
    }
    throughput(total_bytes, total_secs)
}

/// Format a CSV row for a netem condition and its latency [`Summary`]. Column
/// order matches [`CSV_HEADER`]: the M16 stats are appended after `p95_ms`, and
/// the raw per-iteration `samples` (#52) form the trailing `samples_ms` field —
/// space-separated (so the field stays comma-free) at the same 3-decimal
/// precision as the summary. Emitting the raw samples lets the thesis tooling
/// compute a bootstrap-percentile CI, which is valid on the right-skewed loss
/// distributions where the symmetric normal CI is not.
pub fn csv_row(delay: &str, loss: &str, rate: &str, s: &Summary, samples: &[f64]) -> String {
    let samples_field = samples
        .iter()
        .map(|v| format!("{v:.3}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{},{},{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{}",
        delay,
        loss,
        rate,
        s.n,
        s.mean_ms,
        s.min_ms,
        s.max_ms,
        s.p50_ms,
        s.p95_ms,
        s.stddev_ms,
        s.ci95_ms,
        s.p99_ms,
        samples_field
    )
}

/// Bulk-transfer throughput over a sustained transfer (#76 OV1). Latency (RTT) is
/// the wrong lens for overlay-under-load behaviour; the topology study needs
/// bytes/second. This is the pure measurement primitive the bulk-transfer run mode
/// (OV2) emits — kept unit-testable and network-free, alongside [`Summary`].
#[derive(Debug, Clone, PartialEq)]
pub struct Throughput {
    /// Total application bytes transferred.
    pub bytes: u64,
    /// Wall-clock seconds the transfer took.
    pub secs: f64,
    /// Throughput in megabits per second (bytes·8 / secs / 1e6).
    pub mbps: f64,
    /// Throughput in mebibytes per second (bytes / secs / 2^20).
    pub mib_s: f64,
}

/// Compute [`Throughput`] for `bytes` transferred in `secs`. Returns `None` for a
/// non-positive duration (no meaningful rate).
pub fn throughput(bytes: u64, secs: f64) -> Option<Throughput> {
    if secs <= 0.0 {
        return None;
    }
    Some(Throughput {
        bytes,
        secs,
        mbps: (bytes as f64) * 8.0 / secs / 1_000_000.0,
        mib_s: (bytes as f64) / secs / (1024.0 * 1024.0),
    })
}

/// CSV columns for a bulk-transfer sample under a netem condition (#76 OV1).
pub const THROUGHPUT_CSV_HEADER: &str = "delay,loss,rate,bytes,secs,mbps,mib_s";

/// Format a CSV row for a netem condition and its [`Throughput`], columns per
/// [`THROUGHPUT_CSV_HEADER`].
pub fn throughput_csv_row(delay: &str, loss: &str, rate: &str, t: &Throughput) -> String {
    format!(
        "{},{},{},{},{:.3},{:.3},{:.3}",
        delay, loss, rate, t.bytes, t.secs, t.mbps, t.mib_s
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_known_samples() {
        let s = summarize(&[10.0, 20.0, 30.0, 40.0, 50.0]).unwrap();
        assert_eq!(s.n, 5);
        assert_eq!(s.mean_ms, 30.0);
        assert_eq!(s.min_ms, 10.0);
        assert_eq!(s.max_ms, 50.0);
        assert_eq!(s.p50_ms, 30.0);
        assert_eq!(s.p95_ms, 50.0);
        assert_eq!(s.p99_ms, 50.0);
        // Sample stddev = sqrt(1000/4) = sqrt(250) ≈ 15.811; CI95 = 1.96·σ/√5.
        assert!((s.stddev_ms - 250.0_f64.sqrt()).abs() < 1e-9, "sample stddev");
        assert!((s.ci95_ms - 1.96 * 250.0_f64.sqrt() / 5.0_f64.sqrt()).abs() < 1e-9, "95% CI");
    }

    #[test]
    fn single_sample_has_zero_spread() {
        let s = summarize(&[42.0]).unwrap();
        assert_eq!(s.n, 1);
        assert_eq!(s.mean_ms, 42.0);
        assert_eq!(s.p99_ms, 42.0);
        assert_eq!(s.stddev_ms, 0.0, "no spread from one sample");
        assert_eq!(s.ci95_ms, 0.0, "no CI from one sample");
    }

    #[test]
    fn unsorted_input_is_handled() {
        let s = summarize(&[50.0, 10.0, 30.0]).unwrap();
        assert_eq!(s.min_ms, 10.0);
        assert_eq!(s.max_ms, 50.0);
        assert_eq!(s.p50_ms, 30.0);
    }

    #[test]
    fn empty_is_none() {
        assert!(summarize(&[]).is_none());
    }

    #[test]
    fn throughput_computes_mbps_and_mibps() {
        // 10 MB in 2 s = 40 Mbit/s; ~4.768 MiB/s.
        let t = throughput(10_000_000, 2.0).expect("positive duration");
        assert_eq!(t.bytes, 10_000_000);
        assert!((t.mbps - 40.0).abs() < 1e-6, "40 Mbit/s, got {}", t.mbps);
        assert!((t.mib_s - 4.76837).abs() < 1e-3, "~4.768 MiB/s, got {}", t.mib_s);
        // Non-positive duration has no meaningful rate.
        assert!(throughput(1, 0.0).is_none());
        assert!(throughput(1, -1.0).is_none());
    }

    #[test]
    fn throughput_csv_row_formats() {
        let t = throughput(5_000_000, 1.0).unwrap();
        let row = throughput_csv_row("30ms", "1%", "10mbit", &t);
        assert_eq!(row, "30ms,1%,10mbit,5000000,1.000,40.000,4.768");
        assert_eq!(
            THROUGHPUT_CSV_HEADER.split(',').count(),
            row.split(',').count(),
            "header and row column counts match"
        );
    }

    #[test]
    fn csv_row_formats() {
        let s = Summary {
            n: 5,
            mean_ms: 30.0,
            min_ms: 10.0,
            max_ms: 50.0,
            p50_ms: 30.0,
            p95_ms: 50.0,
            stddev_ms: 1.5,
            ci95_ms: 2.5,
            p99_ms: 50.0,
        };
        assert_eq!(
            csv_row("30ms", "1%", "10mbit", &s, &[10.0, 20.0, 30.0, 40.0, 50.0]),
            "30ms,1%,10mbit,5,30.000,10.000,50.000,30.000,50.000,1.500,2.500,50.000,\
             10.000 20.000 30.000 40.000 50.000"
        );
        // Header and row column counts still agree with the trailing samples field.
        assert_eq!(
            CSV_HEADER.split(',').count(),
            csv_row("30ms", "1%", "10mbit", &s, &[10.0, 20.0, 30.0, 40.0, 50.0])
                .split(',')
                .count(),
            "header and row column counts match"
        );
    }

    #[tokio::test]
    async fn run_bench_measures_iterations() {
        use ct_agent::serve::serve_noise_bridge;
        use ct_common::noise::generate_static_keypair;
        use ct_common::pow::Challenge;
        use ct_common::{OriginIdentity, RoutingToken};
        use ct_edge::serve::serve_connection;
        use ct_edge::state::EdgeState;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use quinn::Connection;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let token = RoutingToken([6u8; 32]);
        let challenge = Challenge {
            nonce: [0x44; 16],
            difficulty: 6,
        };
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();

        // Multi-accept TCP echo Origin (one connection per bench iteration).
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = origin_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let _ = sock.read_to_end(&mut buf).await;
                    let _ = sock.write_all(&buf).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: addr.to_string(),
        };

        // Edge: serve every incoming connection.
        let state_e = state.clone();
        let chal_e = challenge.clone();
        let edge = tokio::spawn(async move {
            while let Some(inc) = server.accept().await {
                let state = state_e.clone();
                let chal = chal_e.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = inc.await {
                        let _ = serve_connection(&conn, &state, &chal).await;
                        conn.closed().await;
                    }
                });
            }
        });

        // Agent: register, then serve every relayed stream as the Noise responder.
        let agent_ep = build_client_endpoint(cert.clone()).expect("agent ep");
        let agent_conn = agent_ep
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("agent conn");
        let (mut rs, mut rr) = agent_conn.open_bi().await.unwrap();
        rs.write_all(b"A").await.unwrap();
        rs.write_all(&token.0).await.unwrap();
        rs.finish().unwrap();
        assert_eq!(rr.read_to_end(8).await.unwrap(), b"OK");
        let origin_priv = origin_kp.private;
        let agent_task = tokio::spawn(async move {
            while let Ok((mut s, mut r)) = agent_conn.accept_bi().await {
                let priv_ = origin_priv;
                tokio::spawn(async move {
                    let _ = serve_noise_bridge(&mut s, &mut r, origin_addr, &priv_).await;
                });
            }
        });

        let samples = run_bench(addr, cert, &cap, &client_kp.private, b"ping", 3).await;
        assert_eq!(samples.len(), 3, "three successful Noise round-trips measured");
        assert!(summarize(&samples).is_some());

        agent_task.abort();
        edge.abort();
        origin.abort();
    }

    #[tokio::test]
    async fn run_bench_stream_measures_iterations() {
        // The streaming-mode bench (M16.2b): agent serves the full-duplex
        // serve_noise_stream path and run_bench_stream measures round-trips.
        use ct_agent::serve::serve_noise_stream;
        use ct_common::metrics::TunnelMetrics;
        use ct_common::noise::generate_static_keypair;
        use ct_common::pow::Challenge;
        use ct_common::{OriginIdentity, RoutingToken};
        use ct_edge::serve::serve_connection;
        use ct_edge::state::EdgeState;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use quinn::Connection;
        use std::sync::Arc;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let token = RoutingToken([7u8; 32]);
        let challenge = Challenge {
            nonce: [0x33; 16],
            difficulty: 6,
        };
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();

        // Multi-accept streaming echo Origin (one connection per iteration).
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = origin_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (mut r, mut w) = sock.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                    let _ = w.shutdown().await;
                });
            }
        });

        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: addr.to_string(),
        };

        let state_e = state.clone();
        let chal_e = challenge.clone();
        let edge = tokio::spawn(async move {
            while let Some(inc) = server.accept().await {
                let state = state_e.clone();
                let chal = chal_e.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = inc.await {
                        let _ = serve_connection(&conn, &state, &chal).await;
                        conn.closed().await;
                    }
                });
            }
        });

        let agent_ep = build_client_endpoint(cert.clone()).expect("agent ep");
        let agent_conn = agent_ep
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("agent conn");
        let (mut rs, mut rr) = agent_conn.open_bi().await.unwrap();
        rs.write_all(b"A").await.unwrap();
        rs.write_all(&token.0).await.unwrap();
        rs.finish().unwrap();
        assert_eq!(rr.read_to_end(8).await.unwrap(), b"OK");
        let origin_priv = origin_kp.private;
        let metrics = Arc::new(TunnelMetrics::new());
        let agent_task = tokio::spawn(async move {
            while let Ok((s, r)) = agent_conn.accept_bi().await {
                let priv_ = origin_priv;
                let m = Arc::clone(&metrics);
                tokio::spawn(async move {
                    let _ = serve_noise_stream(s, r, origin_addr, &[priv_], m).await;
                });
            }
        });

        let samples = run_bench_stream(addr, cert, &cap, &client_kp.private, b"ping-stream", 3).await;
        assert_eq!(samples.len(), 3, "three streaming round-trips measured");
        assert!(summarize(&samples).is_some());

        agent_task.abort();
        edge.abort();
        origin.abort();
    }

    #[tokio::test]
    async fn run_bench_throughput_measures_transfer() {
        // The throughput-mode bench (#57): the agent serves the streaming
        // serve_noise_stream path and run_bench_throughput moves a bulk payload
        // (larger than one socket buffer, to exercise the concurrent drain) over
        // the tunnel, returning a Throughput over the bytes actually transferred.
        use ct_agent::serve::serve_noise_stream;
        use ct_common::metrics::TunnelMetrics;
        use ct_common::noise::generate_static_keypair;
        use ct_common::pow::Challenge;
        use ct_common::{OriginIdentity, RoutingToken};
        use ct_edge::serve::serve_connection;
        use ct_edge::state::EdgeState;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use quinn::Connection;
        use std::sync::Arc;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let token = RoutingToken([9u8; 32]);
        let challenge = Challenge {
            nonce: [0x11; 16],
            difficulty: 6,
        };
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();

        // Multi-accept streaming echo Origin (one connection per iteration).
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = origin_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (mut r, mut w) = sock.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                    let _ = w.shutdown().await;
                });
            }
        });

        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: addr.to_string(),
        };

        let state_e = state.clone();
        let chal_e = challenge.clone();
        let edge = tokio::spawn(async move {
            while let Some(inc) = server.accept().await {
                let state = state_e.clone();
                let chal = chal_e.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = inc.await {
                        let _ = serve_connection(&conn, &state, &chal).await;
                        conn.closed().await;
                    }
                });
            }
        });

        let agent_ep = build_client_endpoint(cert.clone()).expect("agent ep");
        let agent_conn = agent_ep
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("agent conn");
        let (mut rs, mut rr) = agent_conn.open_bi().await.unwrap();
        rs.write_all(b"A").await.unwrap();
        rs.write_all(&token.0).await.unwrap();
        rs.finish().unwrap();
        assert_eq!(rr.read_to_end(8).await.unwrap(), b"OK");
        let origin_priv = origin_kp.private;
        let metrics = Arc::new(TunnelMetrics::new());
        let agent_task = tokio::spawn(async move {
            while let Ok((s, r)) = agent_conn.accept_bi().await {
                let priv_ = origin_priv;
                let m = Arc::clone(&metrics);
                tokio::spawn(async move {
                    let _ = serve_noise_stream(s, r, origin_addr, &[priv_], m).await;
                });
            }
        });

        // 256 KiB per transfer × 2 iterations = 512 KiB aggregated.
        let payload = vec![0x5au8; 256 * 1024];
        let t = run_bench_throughput(addr, cert, &cap, &client_kp.private, &payload, 2)
            .await
            .expect("bulk transfer produced a throughput");
        assert_eq!(t.bytes, 2 * 256 * 1024, "aggregate bytes over 2 transfers");
        assert!(t.secs > 0.0, "positive elapsed time");
        assert!(t.mbps > 0.0 && t.mib_s > 0.0, "positive throughput");

        agent_task.abort();
        edge.abort();
        origin.abort();
    }

    #[tokio::test]
    async fn run_bench_udp_measures_iterations() {
        // The UDP-mode bench (M16.2c): agent serves serve_noise_udp and
        // run_bench_udp measures datagram round-trips through a UDP echo origin.
        use ct_agent::serve::serve_noise_udp;
        use ct_common::noise::generate_static_keypair;
        use ct_common::pow::Challenge;
        use ct_common::{OriginIdentity, RoutingToken};
        use ct_edge::serve::serve_connection;
        use ct_edge::state::EdgeState;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use quinn::Connection;
        use std::sync::Arc;
        use tokio::net::UdpSocket;

        let token = RoutingToken([8u8; 32]);
        let challenge = Challenge {
            nonce: [0x22; 16],
            difficulty: 6,
        };
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();

        // UDP echo Origin: reply each datagram back to its sender from the bound
        // port (which is what the agent's connected socket expects).
        let origin_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_sock.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let Ok((n, peer)) = origin_sock.recv_from(&mut buf).await else {
                    break;
                };
                let _ = origin_sock.send_to(&buf[..n], peer).await;
            }
        });

        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: addr.to_string(),
        };

        let state_e = state.clone();
        let chal_e = challenge.clone();
        let edge = tokio::spawn(async move {
            while let Some(inc) = server.accept().await {
                let state = state_e.clone();
                let chal = chal_e.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = inc.await {
                        let _ = serve_connection(&conn, &state, &chal).await;
                        conn.closed().await;
                    }
                });
            }
        });

        let agent_ep = build_client_endpoint(cert.clone()).expect("agent ep");
        let agent_conn = agent_ep
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("agent conn");
        let (mut rs, mut rr) = agent_conn.open_bi().await.unwrap();
        rs.write_all(b"A").await.unwrap();
        rs.write_all(&token.0).await.unwrap();
        rs.finish().unwrap();
        assert_eq!(rr.read_to_end(8).await.unwrap(), b"OK");
        let origin_priv = origin_kp.private;
        let agent_task = tokio::spawn(async move {
            while let Ok((s, r)) = agent_conn.accept_bi().await {
                let priv_ = origin_priv;
                tokio::spawn(async move {
                    let _ = serve_noise_udp(s, r, origin_addr, &[priv_]).await;
                });
            }
        });

        let samples = run_bench_udp(addr, cert, &cap, &client_kp.private, b"ping-udp", 3).await;
        assert_eq!(samples.len(), 3, "three UDP round-trips measured");
        assert!(summarize(&samples).is_some());

        agent_task.abort();
        edge.abort();
        origin.abort();
    }

    #[tokio::test]
    async fn bounded_read_stops_a_runaway_peer_instead_of_hanging_forever_593() {
        // #593: proves the exact mechanism run_once_stream/run_once_throughput now rely
        // on (`.take(cap).read_to_end()`), isolated from the real edge/Noise harness. A
        // peer that keeps writing and never closes -- the "old code" failure mode -- must
        // not hang or grow the read buffer without bound: a bare `read_to_end(&mut got)`
        // against this same writer would never return (it only completes on EOF, which
        // this writer deliberately never sends), so this test would time out under the
        // pre-#593 code instead of completing.
        let (local, mut remote) = tokio::io::duplex(4096);
        let (r, _w) = tokio::io::split(local);
        const SMALL_CAP: u64 = 1024;
        let writer = tokio::spawn(async move {
            // Write well past the cap, then keep the connection open (no shutdown) --
            // exactly the "runaway/never-closes" peer shape the cap defends against.
            let chunk = vec![0xABu8; 256];
            for _ in 0..(SMALL_CAP as usize / chunk.len() + 4) {
                if remote.write_all(&chunk).await.is_err() {
                    return;
                }
            }
            // Deliberately never shutdown -- a bare read_to_end would block forever here.
            std::future::pending::<()>().await;
        });

        let mut got = Vec::new();
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(2), r.take(SMALL_CAP).read_to_end(&mut got))
                .await;

        writer.abort();
        assert!(result.is_ok(), "a capped read must return once the cap is hit, not hang");
        assert!(result.unwrap().is_ok(), "reaching the cap is Ok, not an error");
        assert_eq!(got.len(), SMALL_CAP as usize, "growth stops exactly at the cap");
    }
}
