//! CADS Tunnel Client tool (M6.1c).
//!
//! Waits for the Edge cert and the Agent's Capability, then either tunnels a
//! single payload (verifying the round-trip) or, when `CT_CLIENT_ITERATIONS>1`,
//! runs the latency bench and prints a labeled `RESULT` CSV row for the sweep.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ct_client::bench::{
    csv_row, run_bench, run_bench_stream, run_bench_throughput, run_bench_udp, summarize,
    throughput_csv_row,
};
use ct_client::config::ClientConfig;
use ct_client::ladder::{
    connect_via_ladder, filtered_ladder, network_signature, LadderCache, Rung,
};
use ct_client::transport::{
    client_forward, client_tunnel_auto, client_tunnel_noise_tcp_timed, client_tunnel_noise_timed,
    dial_edge_timed, dial_rung, load_cert, new_client_endpoint, udp_selftest, EdgeConn,
    DEFAULT_STREAM_SETUP_DEADLINE,
};
use ct_common::noise::generate_static_keypair;
use ct_common::Capability;

/// The transport family label for a landed rung — kept coarse ("quic"/"tcp") so
/// existing smoke greps (`via=quic` / `via=tcp`) still match across the :443 rungs.
fn via_label(rung: Rung) -> &'static str {
    match rung {
        Rung::Quic(_) => "quic",
        Rung::TlsTcp(_) => "tcp",
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = ClientConfig::from_env();
    let payload = std::env::var("CT_CLIENT_PAYLOAD").unwrap_or_else(|_| "hello-tunnel".to_string());
    let iterations: usize = std::env::var("CT_CLIENT_ITERATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    // Wait for the Edge cert. Cross-host, fetch the published root once with
    // `curl http://<cp>:8090/pki/ca -o edge-cert.der` (#11) and point
    // CT_CLIENT_EDGE_CERT at it; the lean client stays HTTP-client-free.
    let edge_cert_wait_secs = std::env::var("CT_CLIENT_EDGE_CERT_WAIT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(30);
    let edge_cert_deadline = Instant::now() + Duration::from_secs(edge_cert_wait_secs);
    let edge_cert = loop {
        match load_cert(&config.edge_cert_file) {
            Ok(cert) => break cert,
            Err(_) => {
                if Instant::now() >= edge_cert_deadline {
                    return Err(format!(
                        "ct-client: edge cert not available within {edge_cert_wait_secs}s at {}",
                        config.edge_cert_file
                    )
                    .into());
                }
                eprintln!("ct-client: waiting for edge cert ...");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };

    // Wait for the Agent's Capability.
    let cap_wait_secs = std::env::var("CT_CLIENT_CAPABILITY_WAIT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60);
    let cap_deadline = Instant::now() + Duration::from_secs(cap_wait_secs);
    let cap = loop {
        match std::fs::read(&config.capability_file)
            .ok()
            .and_then(|b| Capability::decode(&b).ok())
        {
            Some(cap) => break cap,
            None => {
                if Instant::now() >= cap_deadline {
                    return Err(format!(
                        "ct-client: capability not available within {cap_wait_secs}s at {}",
                        config.capability_file
                    )
                    .into());
                }
                eprintln!("ct-client: waiting for capability ...");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };

    let edge_addr: SocketAddr = cap.edge_addr.parse()?;

    // The Client's ephemeral Noise static key (its static key is not pinned by
    // the Origin in Noise_IK, so a fresh one per run is fine).
    let client_kp = generate_static_keypair();

    // UDP mode: send one datagram through the tunnel to a UDP Origin and verify
    // the echo (the Agent must run with CT_AGENT_ORIGIN_PROTO=udp).
    if std::env::var("CT_CLIENT_MODE").as_deref() == Ok("udp") {
        // #284: udp mode also dials the Edge directly, bypassing dial_rung's
        // per-rung timeout -- a blackholed/stalled Edge IP hung this forever.
        let conn = dial_edge_timed(edge_addr, edge_cert, Duration::from_secs(3)).await?;
        let echo = udp_selftest(
            &conn,
            &cap.token,
            &cap,
            &client_kp.private,
            payload.as_bytes(),
        )
        .await?;
        println!(
            "ct-client: udp sent {:?}, received {:?}",
            payload,
            String::from_utf8_lossy(&echo)
        );
        return if echo == payload.as_bytes() {
            eprintln!("ct-client: UDP tunnel round-trip OK");
            Ok(())
        } else {
            Err("udp echo mismatch".into())
        };
    }

    // P2P mode: auto-discover the Agent's direct endpoint and use the direct
    // path, falling back to the Edge relay. Retries briefly to win the startup
    // race where the Agent hasn't advertised its listener yet.
    if std::env::var("CT_CLIENT_MODE").as_deref() == Ok("p2p") {
        let mut result = (false, Vec::new());
        for attempt in 0..5u32 {
            // #284: p2p mode dials the Edge directly, bypassing dial_rung's
            // per-rung timeout (the Ladder machinery is forward-mode-only) --
            // a blackholed/stalled Edge IP hung this indefinitely and the
            // 5-attempt retry loop below never advanced. Bound it to the same
            // 3s budget the tunnel attempt right below already uses.
            let conn = dial_edge_timed(edge_addr, edge_cert.clone(), Duration::from_secs(3)).await?;
            let (used_direct, resp) = client_tunnel_auto(
                &conn,
                &cap.token,
                &cap,
                &client_kp.private,
                payload.as_bytes(),
                Duration::from_secs(3),
            )
            .await?;
            conn.close(0u32.into(), b"done");
            if resp != payload.as_bytes() {
                return Err("p2p echo mismatch".into());
            }
            result = (used_direct, resp);
            if used_direct || attempt == 4 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let (used_direct, resp) = result;
        println!(
            "ct-client: p2p sent {:?}, received {:?} (direct={used_direct})",
            payload,
            String::from_utf8_lossy(&resp)
        );
        eprintln!("ct-client: P2P tunnel round-trip OK (direct={used_direct})");
        return Ok(());
    }

    // Forward mode (#22 HW2a): bind a local TCP port and bridge each connection
    // through the tunnel to the Origin, so any TCP/TLS app (curl, a browser) can
    // ride it — e.g. `CT_CLIENT_MODE=forward CT_CLIENT_LISTEN=127.0.0.1:8443`
    // then `curl --cacert origin-ca.pem https://127.0.0.1:8443/`. Runs until
    // stopped. TLS terminates at the Origin; the Edge stays provider-blind.
    if std::env::var("CT_CLIENT_MODE").as_deref() == Ok("forward") {
        let listen: SocketAddr = std::env::var("CT_CLIENT_LISTEN")
            .map_err(|_| "CT_CLIENT_LISTEN is required for forward mode (e.g. 127.0.0.1:8443)")?
            .parse()
            .map_err(|e| format!("invalid CT_CLIENT_LISTEN: {e}"))?;
        let listener = tokio::net::TcpListener::bind(listen).await?;
        eprintln!(
            "ct-client: forwarding {} -> tunnel -> origin (stop with Ctrl-C)",
            listener.local_addr()?
        );
        return client_forward(
            listener,
            edge_addr,
            edge_cert,
            cap.token.clone(),
            cap,
            client_kp.private,
            DEFAULT_STREAM_SETUP_DEADLINE,
        )
        .await;
    }

    // Throughput (bulk-transfer) bench mode (#57): move a fixed CT_BENCH_BYTES
    // payload over the streaming tunnel and emit a throughput RESULT row
    // (delay,loss,rate,bytes,secs,mbps,mib_s) — the bandwidth dimension under the
    // netem rate cap (CT_NETEM_RATE), distinct from the latency modes that report
    // RTT. CT_BENCH_BYTES sizes the payload (default 8 MiB); CT_CLIENT_ITERATIONS
    // (>=1) aggregates that many transfers into a sustained-throughput estimate.
    if matches!(
        std::env::var("CT_BENCH_MODE").as_deref(),
        Ok("throughput") | Ok("bulk")
    ) {
        let bytes: usize = std::env::var("CT_BENCH_BYTES")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|&b| b > 0)
            .unwrap_or(8 * 1024 * 1024);
        let bulk = vec![0u8; bytes];
        let t = run_bench_throughput(
            edge_addr,
            edge_cert,
            &cap,
            &client_kp.private,
            &bulk,
            iterations.max(1),
        )
        .await
        .ok_or("throughput bench produced no successful transfer")?;
        let delay = std::env::var("CT_BENCH_DELAY").unwrap_or_default();
        let loss = std::env::var("CT_BENCH_LOSS").unwrap_or_default();
        let rate = std::env::var("CT_BENCH_RATE").unwrap_or_default();
        println!("RESULT {}", throughput_csv_row(&delay, &loss, &rate, &t));
        eprintln!(
            "ct-client: throughput {} bytes in {:.3}s = {:.3} mbit/s ({:.3} MiB/s)",
            t.bytes, t.secs, t.mbps, t.mib_s
        );
        return Ok(());
    }

    // Bench mode: run N round-trips and emit a labeled CSV row. CT_BENCH_MODE
    // selects the measured path — "stream" for the full-duplex streaming path,
    // otherwise the one-shot path (M16.2b).
    if iterations > 1 {
        let bench_mode = std::env::var("CT_BENCH_MODE").unwrap_or_default();
        let samples = match bench_mode.as_str() {
            "stream" => {
                run_bench_stream(
                    edge_addr,
                    edge_cert,
                    &cap,
                    &client_kp.private,
                    payload.as_bytes(),
                    iterations,
                )
                .await
            }
            "udp" => {
                run_bench_udp(
                    edge_addr,
                    edge_cert,
                    &cap,
                    &client_kp.private,
                    payload.as_bytes(),
                    iterations,
                )
                .await
            }
            _ => {
                run_bench(
                    edge_addr,
                    edge_cert,
                    &cap,
                    &client_kp.private,
                    payload.as_bytes(),
                    iterations,
                )
                .await
            }
        };
        let summary = summarize(&samples).ok_or("bench produced no samples")?;
        let delay = std::env::var("CT_BENCH_DELAY").unwrap_or_default();
        let loss = std::env::var("CT_BENCH_LOSS").unwrap_or_default();
        let rate = std::env::var("CT_BENCH_RATE").unwrap_or_default();
        println!("RESULT {}", csv_row(&delay, &loss, &rate, &summary, &samples));
        eprintln!(
            "ct-client: bench {}/{} iterations, mean {:.2}ms p95 {:.2}ms",
            summary.n, iterations, summary.mean_ms, summary.p95_ms
        );
        return Ok(());
    }

    // Single-tunnel mode (#31 FD3-c): walk the transport fallback ladder
    // (QUIC:<edge_port> → TLS-TCP:<edge_port> → QUIC:443 → TLS-TCP:443), landing on
    // the first reachable rung and remembering it per network — so a :443-only
    // restrictive network reaches the FD2 front door without re-paying a timeout on
    // every blocked rung. CT_CLIENT_FORCE_TCP keeps only the TLS-TCP rungs.
    // #74: the primary rungs use the port from the capability's edge_addr, so an
    // edge on a non-4433 port (e.g. the self-host stack on :4434) is reachable.
    let force_tcp = std::env::var("CT_CLIENT_FORCE_TCP").is_ok();
    let edge_port = edge_addr.port();
    let ladder = filtered_ladder(force_tcp, edge_port);
    let netsig = network_signature().await;
    let per_rung = Duration::from_secs(2);
    let edge_ip = edge_addr.ip();
    let mut cache = LadderCache::new();
    let cert_for_dial = edge_cert.clone();
    // #368: one shared QUIC endpoint for every Quic rung this ladder attempt
    // races (#367 can genuinely dial more than one concurrently) instead of
    // each rung binding its own throwaway UDP socket.
    let quic_endpoint = new_client_endpoint()?;
    let picked = connect_via_ladder(&mut cache, &netsig, &ladder, |rung| {
        let cert = cert_for_dial.clone();
        let quic_endpoint = &quic_endpoint;
        async move { dial_rung(rung, edge_ip, cert, quic_endpoint, per_rung).await }
    })
    .await
    .ok_or_else(|| format!("ct-client: no edge rung reachable (tried the :{edge_port}/:443 ladder)"))?;
    // Overall deadline for the tunnel operation once the edge connection is up,
    // so the client never hangs when the edge accepts the connection but cannot
    // relay (issue #2 — e.g. no agent registered for the token). Configurable via
    // CT_CLIENT_TUNNEL_TIMEOUT_SECS (default 10s).
    let tunnel_timeout = Duration::from_secs(
        std::env::var("CT_CLIENT_TUNNEL_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10),
    );
    // Report the transport family ("quic"/"tcp") as before, so existing smoke
    // greps (via=quic / via=tcp) keep working across the new :443 rungs.
    let (response, via) = match picked {
        (rung, EdgeConn::Quic(conn)) => {
            let r = client_tunnel_noise_timed(
                &conn,
                &cap.token,
                &cap,
                &client_kp.private,
                payload.as_bytes(),
                tunnel_timeout,
            )
            .await?;
            (r, via_label(rung))
        }
        (rung, EdgeConn::Tcp(tls)) => {
            let r = client_tunnel_noise_tcp_timed(
                tls,
                &cap.token,
                &cap,
                &client_kp.private,
                payload.as_bytes(),
                tunnel_timeout,
            )
            .await?;
            (r, via_label(rung))
        }
    };
    println!(
        "ct-client: sent {:?}, received {:?} (via={via})",
        payload,
        String::from_utf8_lossy(&response)
    );
    if response == payload.as_bytes() {
        eprintln!("ct-client: tunnel round-trip OK (via={via})");
        Ok(())
    } else {
        Err("tunnel response mismatch".into())
    }
}
