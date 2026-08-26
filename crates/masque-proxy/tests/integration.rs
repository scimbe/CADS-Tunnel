//! End-to-end proof this crate actually does what ADR-0024 M2 asks for: a real
//! `masque_proxy::run` instance, fronting a real UDP socket standing in for "the
//! edge's own QUIC listener", driven by a real h2 client speaking Extended CONNECT
//! (RFC 9220) + RFC 9297/9298 capsule-framed datagrams -- the same protocol layer
//! ct-agent's spike-masque-h2/ (M1) proved feasible, now exercised against the actual
//! production proxy rather than a throwaway client+server pair.

use bytes::Bytes;
use h2::ext::Protocol;
use http::{Method, Request};
use masque_proxy::{capsule, Config};
use std::time::Duration;
use tokio::net::UdpSocket;

fn hex_token(t: &[u8; 32]) -> String {
    t.iter().map(|b| format!("{b:02x}")).collect()
}

/// Binds a UDP socket that echoes every datagram it receives back to its sender --
/// stands in for "the edge's QUIC listener" (this proxy's single hard-restricted
/// target) without needing a real QUIC endpoint in this test.
async fn spawn_udp_echo_target() -> std::net::SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_527];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else { break };
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn a_udp_datagram_round_trips_through_the_real_proxy_to_the_configured_target() {
    let target = spawn_udp_echo_target().await;
    let token = [0x42u8; 32];
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        target,
        max_concurrent_tunnels: 4,
        idle_timeout: Duration::from_secs(5),
        shared_token: token,
    };
    // `run()` binds its own listener; grab the real (OS-assigned) address by binding
    // ourselves first and handing it the same address run() will then re-bind to
    // would race -- instead, bind here and pass the bound listener's address through
    // a fixed loopback port 0, then poll until the proxy is actually accepting.
    let listen_probe = std::net::TcpListener::bind(config.listen).unwrap();
    let proxy_addr = listen_probe.local_addr().unwrap();
    drop(listen_probe); // release the port; run() rebinds it -- see the retry loop below for the inherent race this accepts

    let mut config = config;
    config.listen = proxy_addr;
    tokio::spawn(masque_proxy::run(config));

    // The proxy needs a moment to actually bind after the probe above released the
    // port -- bounded retry rather than a fixed sleep, matching this codebase's own
    // "don't guess a delay" convention.
    let client_io = 'connect: {
        for _ in 0..50 {
            if let Ok(io) = tokio::net::TcpStream::connect(proxy_addr).await {
                break 'connect io;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("masque-proxy never started accepting on {proxy_addr}");
    };

    let (send_request, connection) = h2::client::handshake(client_io).await.unwrap();
    tokio::spawn(connection);

    let mut send_request = send_request.ready().await.unwrap();
    for _ in 0..50 {
        if send_request.is_extended_connect_protocol_enabled() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(send_request.is_extended_connect_protocol_enabled());

    let path = format!("/.well-known/masque/udp/{}/{}/", target.ip(), target.port());
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://{proxy_addr}{path}"))
        .header("x-ct-masque-token", hex_token(&token))
        .body(())
        .unwrap();
    request.extensions_mut().insert(Protocol::from_static("connect-udp"));

    let (response_fut, mut client_send) = send_request.send_request(request, false).unwrap();

    let udp_payload = b"a datagram tunneled to the configured target and back";
    let framed = capsule::encode_datagram(&capsule::udp_datagram_payload::encode(udp_payload));
    client_send.send_data(Bytes::from(framed), false).unwrap();

    let response = response_fut.await.unwrap();
    assert_eq!(response.status(), 200, "the proxy accepted the CONNECT-UDP request for its configured target");

    let mut body = response.into_body();
    let mut buf = Vec::new();
    let echoed = loop {
        let chunk = body.data().await.unwrap().unwrap();
        body.flow_control().release_capacity(chunk.len()).unwrap();
        buf.extend_from_slice(&chunk);
        if let Ok(Some((cap_type, value, _))) = capsule::decode(&buf) {
            assert_eq!(cap_type, 0x00);
            break capsule::udp_datagram_payload::decode(value).unwrap().to_vec();
        }
    };

    assert_eq!(
        echoed, udp_payload,
        "ADR-0024 M2 PROVEN: a datagram sent through a real masque-proxy instance reached the real UDP \
         target (echoed back by it) and the echo made it back through the proxy to the client, byte-for-byte"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_for_any_target_other_than_the_configured_one_gets_refused() {
    // The security-critical property (#559, ADR-0024 Decision 5): this proxy is not
    // a general relay. A request naming a DIFFERENT host/port than the one configured
    // target must be refused, not silently proxied somewhere else.
    let target = spawn_udp_echo_target().await;
    let attacker_chosen_target: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap(); // not `target`

    let listen_probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = listen_probe.local_addr().unwrap();
    drop(listen_probe);

    let token = [0x77u8; 32];
    let config = Config {
        listen: proxy_addr,
        target,
        max_concurrent_tunnels: 4,
        idle_timeout: Duration::from_secs(5),
        shared_token: token,
    };
    tokio::spawn(masque_proxy::run(config));

    let client_io = 'connect: {
        for _ in 0..50 {
            if let Ok(io) = tokio::net::TcpStream::connect(proxy_addr).await {
                break 'connect io;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("masque-proxy never started accepting on {proxy_addr}");
    };

    let (send_request, connection) = h2::client::handshake(client_io).await.unwrap();
    tokio::spawn(connection);

    let mut send_request = send_request.ready().await.unwrap();
    for _ in 0..50 {
        if send_request.is_extended_connect_protocol_enabled() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let path = format!("/.well-known/masque/udp/{}/{}/", attacker_chosen_target.ip(), attacker_chosen_target.port());
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://{proxy_addr}{path}"))
        .header("x-ct-masque-token", hex_token(&token))
        .body(())
        .unwrap();
    request.extensions_mut().insert(Protocol::from_static("connect-udp"));

    let (response_fut, _client_send) = send_request.send_request(request, true).unwrap();

    // A refused stream surfaces as an h2-level error to the response future (RST_STREAM),
    // never a 200 -- either outcome proves the request did NOT succeed as a tunnel.
    match response_fut.await {
        Ok(response) => panic!(
            "a request for an unconfigured target must never succeed -- got status {} instead of a refusal",
            response.status()
        ),
        Err(_) => {} // expected: the stream was reset
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_response_arrives_even_when_the_client_sends_no_data_first() {
    // ADR-0024 M4 regression test for the real bug found live against the deployed
    // proxy: `serve_connection` used to await `handle_request` INLINE instead of
    // spawning it, so nothing kept driving the h2 Connection's I/O while
    // `handle_request` was off doing its own thing -- the 200 response `handle_
    // request` had already queued via `send_response` sat buffered and unflushed
    // until the whole tunnel ended (see lib.rs's own doc comment on this fix for
    // the full mechanism). The OTHER round-trip test above never caught this: it
    // sends a DATA frame immediately after the request, and servicing that
    // incoming frame incidentally drove the connection enough to flush the
    // response too. A real ct-agent client (ADR-0024 M3's own dial sequence)
    // waits for the response BEFORE sending anything -- this test does the same.
    let target = spawn_udp_echo_target().await;
    let token = [0x55u8; 32];
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        target,
        max_concurrent_tunnels: 4,
        idle_timeout: Duration::from_secs(5),
        shared_token: token,
    };
    let listen_probe = std::net::TcpListener::bind(config.listen).unwrap();
    let proxy_addr = listen_probe.local_addr().unwrap();
    drop(listen_probe);

    let mut config = config;
    config.listen = proxy_addr;
    tokio::spawn(masque_proxy::run(config));

    let client_io = 'connect: {
        for _ in 0..50 {
            if let Ok(io) = tokio::net::TcpStream::connect(proxy_addr).await {
                break 'connect io;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("masque-proxy never started accepting on {proxy_addr}");
    };

    let (send_request, connection) = h2::client::handshake(client_io).await.unwrap();
    tokio::spawn(connection);

    let mut send_request = send_request.ready().await.unwrap();
    for _ in 0..50 {
        if send_request.is_extended_connect_protocol_enabled() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(send_request.is_extended_connect_protocol_enabled());

    let path = format!("/.well-known/masque/udp/{}/{}/", target.ip(), target.port());
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://{proxy_addr}{path}"))
        .header("x-ct-masque-token", hex_token(&token))
        .body(())
        .unwrap();
    request.extensions_mut().insert(Protocol::from_static("connect-udp"));

    // No client_send.send_data(...) here -- the whole point of this test.
    let (response_fut, _client_send) = send_request.send_request(request, false).unwrap();

    let response = tokio::time::timeout(Duration::from_secs(3), response_fut)
        .await
        .expect("the response must arrive well within 3s -- it must not depend on the client sending data first")
        .unwrap();
    assert_eq!(response.status(), 200, "the proxy accepted the CONNECT-UDP request for its configured target");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_with_no_or_wrong_token_gets_refused_even_for_the_correct_target() {
    // The complementary security property to the target-restriction test above: an
    // anonymous caller with no ct-agent credential at all -- just a bare TLS+h2
    // handshake to the public front door -- must not be able to open a tunnel merely
    // by getting the target right. See lib.rs's crate doc for why target-restriction
    // alone isn't enough here (the target is the edge's own internal QUIC listener).
    let target = spawn_udp_echo_target().await;
    let real_token = [0x11u8; 32];
    let wrong_token = [0x22u8; 32];

    let listen_probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = listen_probe.local_addr().unwrap();
    drop(listen_probe);

    let config = Config {
        listen: proxy_addr,
        target,
        max_concurrent_tunnels: 4,
        idle_timeout: Duration::from_secs(5),
        shared_token: real_token,
    };
    tokio::spawn(masque_proxy::run(config));

    let path = format!("/.well-known/masque/udp/{}/{}/", target.ip(), target.port());

    // Try three ways to get in without the real token: wrong token, no header at
    // all, and a header that isn't valid hex -- all three must be refused
    // identically to a wrong-target request (RST_STREAM, never a 200).
    for header in [Some(hex_token(&wrong_token)), None, Some("not-hex".to_string())] {
        let client_io = 'connect: {
            for _ in 0..50 {
                if let Ok(io) = tokio::net::TcpStream::connect(proxy_addr).await {
                    break 'connect io;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("masque-proxy never started accepting on {proxy_addr}");
        };
        let (send_request, connection) = h2::client::handshake(client_io).await.unwrap();
        tokio::spawn(connection);
        let mut send_request = send_request.ready().await.unwrap();
        for _ in 0..50 {
            if send_request.is_extended_connect_protocol_enabled() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let mut builder = Request::builder().method(Method::CONNECT).uri(format!("https://{proxy_addr}{path}"));
        if let Some(h) = &header {
            builder = builder.header("x-ct-masque-token", h);
        }
        let mut request = builder.body(()).unwrap();
        request.extensions_mut().insert(Protocol::from_static("connect-udp"));

        let (response_fut, _client_send) = send_request.send_request(request, true).unwrap();
        match response_fut.await {
            Ok(response) => panic!(
                "a request with header {header:?} must never succeed -- got status {} instead of a refusal",
                response.status()
            ),
            Err(_) => {} // expected: the stream was reset
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unauthenticated_stalled_connections_do_not_starve_a_legitimate_tunnel() {
    // #662(A): an unauthenticated caller that opens a TCP connection and never sends
    // the h2 preface used to pin an admission permit for the connection's entire
    // (unbounded) lifetime -- enough such connections (max_concurrent_tunnels worth)
    // permanently exhausted the semaphore, refusing every legitimate agent forever.
    // Regression: with max_concurrent_tunnels stalled attacker connections already
    // open and held (never handshaking), a legitimate authenticated tunnel must
    // still succeed -- admission is now checked per authenticated TUNNEL, not per
    // raw TCP connection, so the stalled connections never touch the semaphore.
    let target = spawn_udp_echo_target().await;
    let token = [0x99u8; 32];
    let max_concurrent_tunnels = 2;

    let listen_probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = listen_probe.local_addr().unwrap();
    drop(listen_probe);

    let config = Config {
        listen: proxy_addr,
        target,
        max_concurrent_tunnels,
        idle_timeout: Duration::from_secs(5),
        shared_token: token,
    };
    tokio::spawn(masque_proxy::run(config));

    // Open exactly `max_concurrent_tunnels` attacker connections and hold them open
    // without ever sending a single byte -- if admission were still pinned at raw
    // TCP-accept time (the pre-fix behavior), this alone exhausts the semaphore.
    let mut stalled_attackers = Vec::new();
    for _ in 0..max_concurrent_tunnels {
        let io = 'connect: {
            for _ in 0..50 {
                if let Ok(io) = tokio::net::TcpStream::connect(proxy_addr).await {
                    break 'connect io;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("masque-proxy never started accepting on {proxy_addr}");
        };
        stalled_attackers.push(io); // kept alive (not dropped) for the rest of the test
    }

    // A legitimate, fully-authenticated caller must still get through.
    let client_io = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let (send_request, connection) = h2::client::handshake(client_io).await.unwrap();
    tokio::spawn(connection);

    let mut send_request = send_request.ready().await.unwrap();
    for _ in 0..50 {
        if send_request.is_extended_connect_protocol_enabled() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(send_request.is_extended_connect_protocol_enabled());

    let path = format!("/.well-known/masque/udp/{}/{}/", target.ip(), target.port());
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://{proxy_addr}{path}"))
        .header("x-ct-masque-token", hex_token(&token))
        .body(())
        .unwrap();
    request.extensions_mut().insert(Protocol::from_static("connect-udp"));

    let (response_fut, _client_send) = send_request.send_request(request, true).unwrap();

    let response = tokio::time::timeout(Duration::from_secs(2), response_fut)
        .await
        .expect(
            "a legitimate authenticated tunnel must succeed promptly even while \
             max_concurrent_tunnels unauthenticated connections are stalled pre-handshake",
        )
        .unwrap();
    assert_eq!(response.status(), 200, "the legitimate tunnel must be admitted, not refused for lack of a free permit");

    drop(stalled_attackers); // keep them alive up to this point, not before
}
